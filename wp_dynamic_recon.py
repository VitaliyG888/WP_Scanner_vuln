#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Passive / light recon checks for the dynamic WordPress scanner."""

import json
import re

from wp_dynamic_common import result, token

README_VER = re.compile(r"Version\s+([0-9]+\.[0-9.]+)", re.IGNORECASE)
GENERATOR = re.compile(
    r'name=["\']generator["\']\s+content=["\']([^"\']+)["\']', re.IGNORECASE
)

SENSITIVE = [
    ("/.git/config", "high", "CWE-538", r"\[core\]", "Exposed Git repository metadata"),
    ("/.env", "high", "CWE-538", r"(?m)^[A-Z0-9_]{2,}\s*=",
     "Exposed .env configuration file"),
    ("/wp-config.php.bak", "high", "CWE-538", r"define\s*\(",
     "WordPress config backup"),
    ("/wp-config.php~", "high", "CWE-538", r"define\s*\(",
     "WordPress config backup"),
    ("/wp-config.php.old", "high", "CWE-538", r"define\s*\(",
     "WordPress config backup"),
    ("/wp-content/debug.log", "high", "CWE-532", r"PHP (Fatal|Warning|Notice|Parse)",
     "Exposed debug log"),
    ("/readme.html", "info", "CWE-200", r"WordPress", "WordPress readme (version leak)"),
    ("/license.txt", "info", "CWE-200", r"WordPress", "WordPress license file"),
]


def check_fingerprint(target):
    """Identify the WordPress version and server technology."""
    try:
        resp = target.get("/")
    except Exception as exc:  # noqa: BLE001
        return [result("fingerprint", "Fingerprint", "info", "", False, str(exc))]
    version = None
    match = GENERATOR.search(resp.text)
    if match:
        version = match.group(1)
    else:
        try:
            readme = target.get("/readme.html")
            match = README_VER.search(readme.text)
            if match:
                version = "WordPress {}".format(match.group(1))
        except Exception:  # noqa: BLE001
            pass
    evidence = "generator={}".format(version) if version else "no version marker"
    powered = resp.headers.get("X-Powered-By", "")
    return [result("fingerprint", "Technology fingerprint", "info", "CWE-200",
                   False, "{} | X-Powered-By: {}".format(evidence, powered or "-"),
                   url=target.url("/"))]


def check_security_headers(target):
    """Report missing hardening headers."""
    required = ["X-Frame-Options", "Content-Security-Policy",
                "Strict-Transport-Security", "X-Content-Type-Options",
                "Referrer-Policy"]
    try:
        resp = target.get("/")
    except Exception as exc:  # noqa: BLE001
        return [result("security-headers", "Security headers", "info", "", False, str(exc))]
    missing = [h for h in required if h not in resp.headers]
    return [result("security-headers", "Missing security headers", "low", "CWE-693",
                   len(missing) >= 3, "missing: {}".format(", ".join(missing) or "none"),
                   url=target.url("/"))]


def check_cookie_flags(target):
    """Session cookies - informational."""
    try:
        resp = target.get("/wp-login.php")
    except Exception as exc:  # noqa: BLE001
        return [result("cookie-flags", "Cookie flags", "info", "", False, str(exc))]
    cookies = resp.raw.headers.getlist("Set-Cookie") \
        if hasattr(resp.raw, "headers") else []
    weak = [c for c in cookies if "httponly" not in c.lower()]
    return [result("cookie-flags", "Session cookie without HttpOnly", "info", "CWE-1004",
                   False, "set-cookie={} weak={}".format(len(cookies), len(weak)),
                   url=target.url("/wp-login.php"))]


def check_sensitive_files(target):
    """Probe for exposed backup / metadata files.

    Two traps are avoided here:

    * redirects are not followed (a site that is not installed yet answers 302
      to /wp-admin/install.php for *any* path, which would make every probe look
      like HTTP 200);
    * a canary path is fetched first, so that a soft-404 page (some hosts answer
      200 with the home page) cannot satisfy a signature either.
    """
    canary = ""
    try:
        probe = target.get("/" + token("CANARY"), allow_redirects=False)
        if probe.status_code == 200:
            canary = probe.text[:5000]
    except Exception:  # noqa: BLE001
        pass

    out = []
    for path, severity, cwe, signature, title in SENSITIVE:
        try:
            resp = target.get(path, allow_redirects=False)
        except Exception:  # noqa: BLE001
            continue
        if resp.status_code != 200:
            continue
        body = resp.text[:5000]
        if canary and body.strip() == canary.strip():
            continue  # soft 404 / catch-all page
        if not re.search(signature, body, re.IGNORECASE | re.MULTILINE):
            continue
        out.append(result(
            "sensitive-file", title, severity, cwe, severity != "info",
            "HTTP 200 ({} bytes)".format(len(resp.content)),
            url=target.url(path),
            detail="first bytes: {}".format(body.strip()[:120].replace("\n", " ")),
        ))
    return out


def check_directory_listing(target):
    """Highlight directories that the web server currently indexes."""
    out = []
    for path in ["/wp-content/plugins/", "/wp-content/uploads/", "/wp-content/themes/"]:
        try:
            resp = target.get(path)
        except Exception:  # noqa: BLE001
            continue
        if resp.status_code == 200 and "Index of /" in resp.text:
            out.append(result("directory-listing", "Directory listing enabled", "low",
                              "CWE-548", True, "index page returned for {}".format(path),
                              url=target.url(path)))
    return out


def check_xmlrpc(target):
    """XML-RPC enabled? Lists the exposed methods."""
    payload = ('<?xml version="1.0"?><methodCall><methodName>system.listMethods'
               '</methodName><params></params></methodCall>')
    try:
        resp = target.post("/xmlrpc.php", data=payload,
                           headers={"Content-Type": "text/xml"})
    except Exception as exc:  # noqa: BLE001
        return [result("xmlrpc", "XML-RPC", "info", "", False, str(exc))]
    if resp.status_code != 200 or "methodResponse" not in resp.text:
        return [result("xmlrpc", "XML-RPC disabled", "info", "", False,
                       "HTTP {}".format(resp.status_code), url=target.url("/xmlrpc.php"))]
    methods = re.findall(r"<string>([^<]+)</string>", resp.text)
    risky = [m for m in methods if m in
             ("pingback.ping", "wp.getUsersBlogs", "system.multicall", "wp.getUsers")]
    return [result("xmlrpc", "XML-RPC enabled with risky methods", "medium", "CWE-306",
                   bool(risky),
                   "methods={} risky={}".format(len(methods), ",".join(risky)),
                   url=target.url("/xmlrpc.php"))]


def check_user_enumeration(target):
    """Enumerate users through the REST API and the author archive."""
    out = []
    try:
        resp = target.get("/wp-json/wp/v2/users")
        if resp.status_code == 200:
            try:
                users = resp.json()
            except json.JSONDecodeError:
                users = []
            slugs = [u.get("slug") for u in users
                     if isinstance(u, dict) and u.get("slug")]
            if slugs:
                out.append(result("user-enum-rest", "User enumeration via REST API",
                                  "medium", "CWE-200", True,
                                  "users: {}".format(", ".join(slugs[:5])),
                                  url=target.url("/wp-json/wp/v2/users")))
    except Exception:  # noqa: BLE001
        pass
    try:
        resp = target.get("/?author=1", allow_redirects=True)
        final = getattr(resp, "url", "")
        if "/author/" in final or re.search(r"author-[a-z0-9_-]+", resp.text, re.IGNORECASE):
            out.append(result("user-enum-author", "User enumeration via author archive",
                              "medium", "CWE-200", True,
                              "resolved to {}".format(final),
                              url=target.url("/?author=1")))
    except Exception:  # noqa: BLE001
        pass
    if not out:
        out.append(result("user-enum", "User enumeration", "info", "CWE-200", False,
                          "no author/REST user leak found"))
    return out


RECON_CHECKS = [
    ("fingerprint", check_fingerprint),
    ("security-headers", check_security_headers),
    ("cookie-flags", check_cookie_flags),
    ("sensitive-files", check_sensitive_files),
    ("directory-listing", check_directory_listing),
    ("xmlrpc", check_xmlrpc),
    ("user-enum", check_user_enumeration),
]

