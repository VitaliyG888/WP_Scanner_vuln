#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Rule definitions for the WordPress static vulnerability scanner.

A *rule* describes one way user controlled input reaches a dangerous sink.
The scanner resolves taint at function scope: a sink only fires when a user
input source ($_GET, $_POST, ...) is also present in the same function and no
sanitizer is used. That keeps the signal high and the false positive rate low.

Rule keys
---------
id           stable identifier (tests assert on it)
category     vulnerability class
title        human readable name
severity     critical | high | medium | low | info
cwe          CWE identifier
scope        'function' -> body + taint check, 'line' -> regex over the file
sink_re      regex (case-insensitive) matching the dangerous call
needs_source True when a user input source must appear in the same scope
sanitizer_re regex that, if found in the same scope, suppresses the finding
message      short explanation
"""

# Taint origins: unvalidated user controlled input.
SOURCES_RE = r"\$_(GET|POST|REQUEST|COOKIE|FILES)\b"

# WordPress nonce / capability helpers used as generic mitigations.
AUTH_RE = (
    r"(check_admin_referer|check_ajax_referer|wp_verify_nonce|"
    r"current_user_can|is_user_logged_in)"
)

RULES = [
    # ---------------------------------------------------------------- RCE
    {
        "id": "rce-command-injection",
        "category": "rce",
        "title": "Command injection",
        "severity": "critical",
        "cwe": "CWE-78",
        "scope": "function",
        "sink_re": r"\b(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(",
        "needs_source": True,
        "sanitizer_re": r"\bescapeshell(arg|cmd)\b",
        "message": "Unvalidated request data reaches a command execution function.",
    },
    {
        "id": "rce-code-eval",
        "category": "rce",
        "title": "Code execution via eval/assert/create_function",
        "severity": "critical",
        "cwe": "CWE-95",
        "scope": "function",
        "sink_re": r"\b(eval|assert|create_function)\s*\(",
        "needs_source": True,
        "sanitizer_re": None,
        "message": "Request data is evaluated as PHP code.",
    },
    {
        "id": "rce-callback-injection",
        "category": "rce",
        "title": "Dynamic callback invocation",
        "severity": "high",
        "cwe": "CWE-94",
        "scope": "function",
        "sink_re": r"\b(call_user_func|call_user_func_array)\s*\(",
        "needs_source": True,
        "sanitizer_re": None,
        "message": "A user controlled value is used as a PHP callback.",
    },
    # --------------------------------------------------------------- SQLi
    {
        "id": "sqli-wpdb-interpolation",
        "category": "sqli",
        "title": "SQL injection (unprepared $wpdb query)",
        "severity": "critical",
        "cwe": "CWE-89",
        "scope": "function",
        "sink_re": r"\$wpdb->(query|get_results|get_row|get_var|get_col)\s*\(",
        "needs_source": True,
        "sanitizer_re": r"(\$wpdb->prepare|esc_sql|prepare\s*\()",
        "message": "Request data is interpolated into SQL without $wpdb->prepare().",
    },
    {
        "id": "sqli-raw-driver",
        "category": "sqli",
        "title": "SQL injection (raw driver call)",
        "severity": "high",
        "cwe": "CWE-89",
        "scope": "function",
        "sink_re": r"\b(mysqli?_query|pg_query|sqlite_query)\s*\(",
        "needs_source": True,
        "sanitizer_re": r"(mysqli_real_escape_string|pg_escape_string)",
        "message": "Request data reaches a raw SQL driver call.",
    },
]
RULES.extend([
    # ------------------------------------------------------------ file IO
    {
        "id": "lfi-arbitrary-file-read",
        "category": "lfi",
        "title": "Local file inclusion / arbitrary file read",
        "severity": "high",
        "cwe": "CWE-98",
        "scope": "function",
        "sink_re": (
            r"\b(readfile|include|include_once|require|require_once|fopen|"
            r"show_source|highlight_file)\s*\("
        ),
        "needs_source": True,
        "sanitizer_re": r"\b(basename|realpath|wp_normalize_path)\s*\(",
        "message": "Request data is used to build a file path that is read or included.",
    },
    {
        "id": "upload-unrestricted",
        "category": "file_upload",
        "title": "Unrestricted file upload",
        "severity": "critical",
        "cwe": "CWE-434",
        "scope": "function",
        "sink_re": r"\b(move_uploaded_file|file_put_contents)\s*\(",
        "needs_source": True,
        "sanitizer_re": r"(wp_handle_upload|wp_check_filetype|sanitize_file_name)",
        "message": "Uploaded data is stored on disk without extension/type validation.",
    },
    # ------------------------------------------------------------- XSS/out
    {
        "id": "xss-unescaped-output",
        "category": "xss",
        "title": "Reflected XSS (unescaped output)",
        "severity": "medium",
        "cwe": "CWE-79",
        "scope": "function",
        "sink_re": r"\b(echo|print|printf|print_r|var_dump)\b",
        "needs_source": True,
        "direct_only": True,
        "sanitizer_re": (
            r"\b(esc_html|esc_attr|esc_url|esc_js|wp_kses|wp_kses_post|"
            r"sanitize_text_field|intval|absint)\b"
        ),
        "message": "Request data is printed to the page without escaping.",
    },
    {
        "id": "redirect-open",
        "category": "open_redirect",
        "title": "Open redirect",
        "severity": "medium",
        "cwe": "CWE-601",
        "scope": "function",
        "sink_re": r"header\s*\(\s*['\"]Location\s*:",
        "needs_source": True,
        "sanitizer_re": r"(wp_safe_redirect|esc_url_raw|wp_validate_redirect)",
        "message": "The redirect target is taken from request data.",
    },
    # ------------------------------------------------------ deserialization
    {
        "id": "deserialization-untrusted",
        "category": "deserialization",
        "title": "Insecure deserialization",
        "severity": "high",
        "cwe": "CWE-502",
        "scope": "function",
        "sink_re": r"\b(unserialize|maybe_unserialize)\s*\(",
        "needs_source": True,
        "sanitizer_re": None,
        "message": "Untrusted data is passed to unserialize().",
    },
    # ---------------------------------------------------------------- SSRF
    {
        "id": "ssrf-user-url",
        "category": "ssrf",
        "title": "Server-side request forgery",
        "severity": "medium",
        "cwe": "CWE-918",
        "scope": "function",
        "sink_re": (
            r"\b(wp_remote_get|wp_remote_post|wp_remote_request|curl_exec|"
            r"file_get_contents|get_headers)\s*\("
        ),
        "needs_source": True,
        "sanitizer_re": r"(wp_http_validate_url|esc_url_raw)",
        "message": "A user controlled URL is requested by the server.",
    },
    # -------------------------------------------------------- weak crypto
    {
        "id": "weak-password-hash",
        "category": "weak_hash",
        "title": "Weak password hashing (MD5/SHA1)",
        "severity": "medium",
        "cwe": "CWE-916",
        "scope": "function",
        "sink_re": r"\b(md5|sha1)\s*\(",
        "needs_source": False,
        "sanitizer_re": r"wp_hash_password",
        "message": "Use wp_hash_password() (bcrypt) instead of md5/sha1.",
    },
])

# File level (line scope) rules - hardcoded secrets.
SECRET_RULES = [
    {
        "id": "secret-api-key",
        "category": "hardcoded_secret",
        "title": "Hardcoded API key / token",
        "severity": "high",
        "cwe": "CWE-798",
        "pattern": (
            r"(api[_-]?key|secret|token|access[_-]?key)\s*['\"]?\s*[,=:]\s*"
            r"['\"][A-Za-z0-9_\-]{12,}['\"]"
        ),
    },
    {
        "id": "secret-db-credentials",
        "category": "hardcoded_secret",
        "title": "Hardcoded database credentials",
        "severity": "high",
        "cwe": "CWE-798",
        "pattern": r"\$(db_?(pass|password|user|pwd)|[A-Za-z0-9_]*password)\s*=\s*['\"][^'\"]{6,}['\"]",
    },
    {
        "id": "secret-wp-config",
        "category": "hardcoded_secret",
        "title": "Hardcoded WordPress secret / auth key",
        "severity": "high",
        "cwe": "CWE-798",
        "pattern": r"define\s*\(\s*['\"](AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY|DB_PASSWORD)['\"]\s*,",
    },
]

# WordPress hooks that expose a handler to unauthenticated visitors.
UNAUTH_ACTION_RE = (
    r"add_action\s*\(\s*['\"]wp_ajax_nopriv_([A-Za-z0-9_\-]+)['\"]\s*,\s*"
    r"['\"]?([A-Za-z0-9_]+)['\"]?"
)

