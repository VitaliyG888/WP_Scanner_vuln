#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Static WordPress vulnerability scanner (taint aware).

Unlike a plain "dangerous function" grep this scanner:
  * splits every PHP file into functions and resolves taint at function scope,
    so a sink only fires when request data ($_GET/$_POST/...) also flows into it;
  * suppresses findings when the matching WordPress sanitizer/validator is used
    (esc_html, intval, $wpdb->prepare, wp_handle_upload, wp_safe_redirect ...);
  * flags unauthenticated admin-ajax handlers (wp_ajax_nopriv_*) that perform
    sensitive operations without a nonce / capability check;
  * maps every finding to a CWE id and a severity.

Usage:
    python wp_vuln_scanner.py --path ./wp-content/plugins
    python wp_vuln_scanner.py --path ./downloaded_plugins --out report
    python wp_vuln_scanner.py --url https://example.com/wp-content/plugins/
"""

import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from wp_scan_rules import (  # noqa: E402
    RULES, SECRET_RULES, SOURCES_RE, AUTH_RE, UNAUTH_ACTION_RE,
)
from wp_report import summarize, to_json, render_html  # noqa: E402

DEFAULT_PATH = os.getcwd()
SENSITIVE_CATEGORIES = {"rce", "sqli", "lfi", "file_upload", "deserialization"}

FUNC_RE = re.compile(
    r"function\s+([A-Za-z0-9_]+)\s*\([^)]*\)\s*(?::\s*[\\A-Za-z0-9_|?]+\s*)?\{",
    re.IGNORECASE,
)


def find_php_functions(content):
    """Return [{'name','body','offset'}] using simple brace matching."""
    funcs = []
    for match in FUNC_RE.finditer(content):
        start = match.end()          # index just after the opening '{'
        depth = 1
        i = start
        while i < len(content) and depth:
            ch = content[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            i += 1
        funcs.append({
            "name": match.group(1),
            "body": content[start:i],
            "offset": start,
        })
    return funcs


def line_of(content, idx):
    return content.count("\n", 0, idx) + 1


def snippet_line(content, idx):
    start = content.rfind("\n", 0, idx) + 1
    end = content.find("\n", idx)
    if end == -1:
        end = len(content)
    return content[start:end].strip()[:200]


ASSIGN_RE = re.compile(
    r"\$([A-Za-z_][A-Za-z0-9_]*)\s*(?:\.=|\+=|=)\s*([^;]+);",
    re.IGNORECASE,
)


def tainted_vars(body):
    """Collect variables assigned (directly or transitively) from request data."""
    tainted = set()
    changed = True
    while changed:
        changed = False
        for match in ASSIGN_RE.finditer(body):
            var, rhs = match.group(1), match.group(2)
            if var in tainted or rhs.lstrip().startswith("="):
                continue
            if re.search(SOURCES_RE, rhs, re.IGNORECASE) or any(
                re.search(r"\$" + re.escape(t) + r"\b", rhs) for t in tainted
            ):
                tainted.add(var)
                changed = True
    for match in re.finditer(
        r"foreach\s*\(\s*\$_(" + "GET|POST|REQUEST|COOKIE|FILES" + r")\b[^)]*as\s*\$"
        r"([A-Za-z_][A-Za-z0-9_]*)",
        body,
        re.IGNORECASE,
    ):
        tainted.add(match.group(2))
    return tainted


def call_span(body, idx):
    """Text from the start of the statement up to the end of the call at idx.

    Scanning to the closing parenthesis (instead of the first ``;``) makes the
    taint check robust against semicolons that live inside string literals,
    e.g. system( 'id; ' . $cmd );
    """
    start = max(body.rfind(";", 0, idx), body.rfind("{", 0, idx),
                body.rfind("}", 0, idx)) + 1
    open_paren = body.find("(", idx)
    if open_paren != -1 and (
        open_paren - idx > 60
        or re.search(r"[;}\n'\"]", body[idx:open_paren])
    ):
        # The parenthesis belongs to a different statement (e.g. an echo
        # followed by a call on the next line) - ignore it.
        open_paren = -1
    if open_paren == -1:
        end = body.find("\n", idx)
        return body[start:len(body) if end == -1 else end]
    depth = 0
    i = open_paren
    while i < len(body):
        if body[i] == "(":
            depth += 1
        elif body[i] == ")":
            depth -= 1
            if depth == 0:
                break
        i += 1
    return body[start:i + 1]


def strip_nested(span):
    """Drop the contents of parenthesised sub-expressions from ``span``.

    Used by output rules so that only *direct* operands count as taint:
    echo 'id=' . $rows;          -> tainted (direct)
    echo 'rows=' . count( $rows ); -> not tainted (nested in a call)
    """
    out = []
    depth = 0
    for ch in span:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif depth == 0:
            out.append(ch)
    return "".join(out)


def statement_is_tainted(body, idx, tainted, direct_only=False):
    """True when the call at ``idx`` carries request data."""
    span = call_span(body, idx)
    if direct_only:
        span = strip_nested(span)
    if re.search(SOURCES_RE, span, re.IGNORECASE):
        return True
    return any(re.search(r"\$" + re.escape(t) + r"\b", span) for t in tainted)


def function_hits(body, offset):
    """Return [(rule, absolute_index)] for every sink that actually fires.

    The same sanitizer/taint logic is reused for the unauthenticated action
    check, so a handler that uses $wpdb->prepare() is not reported as sensitive.
    """
    hits = []
    tainted = tainted_vars(body)
    for rule in RULES:
        if rule.get("sanitizer_re") and re.search(rule["sanitizer_re"], body, re.IGNORECASE):
            continue
        for match in re.finditer(rule["sink_re"], body, re.IGNORECASE):
            if rule["needs_source"] and not statement_is_tainted(
                body, match.start(), tainted, rule.get("direct_only", False)
            ):
                continue
            hits.append((rule, offset + match.start()))
    return hits


def _finding(rule, rel_path, line, snippet):
    return {
        "id": rule["id"],
        "title": rule["title"],
        "category": rule["category"],
        "severity": rule["severity"],
        "cwe": rule.get("cwe", ""),
        "file": rel_path,
        "line": line,
        "snippet": snippet,
        "message": rule.get("message", ""),
    }


def scan_file(path, rel_path):
    """Scan a single PHP file and return a list of findings."""
    findings = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
    except OSError:
        return findings

    funcs = find_php_functions(content)
    func_by_name = {f["name"]: f for f in funcs}

    # ---- function scope taint rules -------------------------------------
    for func in funcs:
        for rule, abs_idx in function_hits(func["body"], func["offset"]):
            findings.append(_finding(rule, rel_path,
                                     line_of(content, abs_idx),
                                     snippet_line(content, abs_idx)))

    # ---- unauthenticated admin-ajax handlers ----------------------------
    for match in re.finditer(UNAUTH_ACTION_RE, content, re.IGNORECASE):
        action, handler = match.group(1), match.group(2)
        func = func_by_name.get(handler)
        if not func:
            continue
        body = func["body"]
        sensitive = any(
            rule["category"] in SENSITIVE_CATEGORIES
            for rule, _idx in function_hits(body, func["offset"])
        )
        if sensitive and not re.search(AUTH_RE, body, re.IGNORECASE):
            line = line_of(content, match.start())
            findings.append({
                "id": "unauth-ajax-action",
                "title": "Unauthenticated admin-ajax action",
                "category": "unauth_action",
                "severity": "high",
                "cwe": "CWE-862",
                "file": rel_path,
                "line": line,
                "snippet": snippet_line(content, match.start()),
                "message": ("wp_ajax_nopriv_{} -> {}() performs a sensitive "
                            "operation with no nonce/capability check.".format(action, handler)),
            })

    # ---- file level secrets ---------------------------------------------
    for rule in SECRET_RULES:
        for match in re.finditer(rule["pattern"], content, re.IGNORECASE):
            findings.append({
                "id": rule["id"],
                "title": rule["title"],
                "category": rule["category"],
                "severity": rule["severity"],
                "cwe": rule.get("cwe", ""),
                "file": rel_path,
                "line": line_of(content, match.start()),
                "snippet": snippet_line(content, match.start()),
                "message": "Secret material is hardcoded in the source tree.",
            })

    return findings



def scan_path(root, min_severity="info"):
    """Recursively scan a directory (or a single file) for PHP issues."""
    from wp_report import severity_rank
    findings = []
    files = []
    if os.path.isfile(root):
        files.append(root)
        base = os.path.dirname(os.path.abspath(root))
    else:
        base = os.path.abspath(root)
        for dirpath, _dirs, filenames in os.walk(root):
            for name in filenames:
                if name.lower().endswith((".php", ".phtml", ".inc")):
                    files.append(os.path.join(dirpath, name))

    threshold = severity_rank(min_severity)
    seen = set()
    for path in files:
        rel = os.path.relpath(path, base).replace("\\", "/")
        for finding in scan_file(path, rel):
            key = (finding["id"], finding["file"], finding["line"])
            if key in seen:
                continue
            seen.add(key)
            if severity_rank(finding["severity"]) >= threshold:
                findings.append(finding)

    findings.sort(key=lambda f: (-severity_rank(f["severity"]), f["file"], f["line"]))
    return {
        "target": base.replace("\\", "/"),
        "files_scanned": len(files),
        "findings": findings,
        "summary": summarize(findings),
    }


def download_remote_plugins(url, dest):
    """Best effort mirror of a web exposed plugins directory."""
    import requests
    headers = {"User-Agent": "Mozilla/5.0 (compatible; WP-Vuln-Scanner)"}
    from urllib.parse import urljoin
    pending = [url]
    seen = set()
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        try:
            resp = requests.get(current, timeout=15, headers=headers)
        except Exception as exc:  # noqa: BLE001
            print("[!] {}: {}".format(current, exc))
            continue
        if resp.status_code != 200:
            continue
        local = os.path.join(dest, *current[len(url):].split("/")).rstrip("\\/")
        if current.endswith("/"):
            os.makedirs(local or dest, exist_ok=True)
            for href in re.findall(r'href="([^"]+)"', resp.text):
                if href.startswith(("?", "/", "http", "mailto:")):
                    continue
                pending.append(urljoin(current, href))
        else:
            os.makedirs(os.path.dirname(local) or dest, exist_ok=True)
            with open(local, "wb") as fh:
                fh.write(resp.content)
            print("[+] {}".format(local))
    return dest


def main(argv=None):
    parser = argparse.ArgumentParser(description="Static WordPress vulnerability scanner")
    parser.add_argument("--path", default=DEFAULT_PATH,
                        help="local file/directory to scan (default: current directory)")
    parser.add_argument("--url", help="remote /wp-content/plugins/ URL to mirror and scan")
    parser.add_argument("--out", default="vulnerable_functions_report",
                        help="output file prefix (writes .json and .html)")
    parser.add_argument("--min-severity", default="info",
                        choices=["critical", "high", "medium", "low", "info"])
    args = parser.parse_args(argv)

    target = args.path
    if args.url:
        target = os.path.join("downloaded_plugins")
        print("[*] Mirroring {}".format(args.url))
        download_remote_plugins(args.url, target)

    print("[*] Scanning {}".format(target))
    result = scan_path(target, args.min_severity)
    result["summary"] = summarize(result["findings"])

    json_path = args.out + ".json"
    html_path = args.out + ".html"
    to_json(result, json_path)
    render_html(result, html_path, title="Static WordPress Scan")

    counts = result["summary"]["by_severity"]
    print("[+] Files scanned : {}".format(result["files_scanned"]))
    print("[+] Findings      : {}".format(result["summary"]["total"]))
    print("      critical={critical} high={high} medium={medium} low={low}".format(**counts))
    print("[+] JSON report   : {}".format(json_path))
    print("[+] HTML report   : {}".format(html_path))
    return result


if __name__ == "__main__":
    main()

