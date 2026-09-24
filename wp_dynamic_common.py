#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Shared helpers for the dynamic (black box) WordPress scanner."""

import uuid

import requests

DEFAULT_UA = "Mozilla/5.0 (compatible; WP-Vuln-Scanner/2.0; +https://localhost)"


class Target(object):
    """Thin wrapper around a requests session bound to one target host."""

    def __init__(self, base_url, timeout=15, user_agent=DEFAULT_UA):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent})

    def url(self, path):
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return "{}/{}".format(self.base_url, path.lstrip("/"))

    def get(self, path, **kwargs):
        return self.session.get(self.url(path), timeout=self.timeout, **kwargs)

    def post(self, path, **kwargs):
        return self.session.post(self.url(path), timeout=self.timeout, **kwargs)

    def head(self, path, **kwargs):
        kwargs.setdefault("allow_redirects", False)
        return self.session.head(self.url(path), timeout=self.timeout, **kwargs)


def token(prefix="VSCAN"):
    """Return a unique, highly unlikely to occur naturally marker string."""
    return "{}{}".format(prefix, uuid.uuid4().hex[:10].upper())


def result(check_id, title, severity, cwe, vulnerable, evidence="",
           url="", detail=""):
    return {
        "id": check_id,
        "title": title,
        "severity": severity,
        "cwe": cwe,
        "vulnerable": bool(vulnerable),
        "evidence": (evidence or "")[:400],
        "url": url,
        "detail": detail,
    }


def safe(fn, *args, **kwargs):
    """Run a callable, returning (result, error)."""
    try:
        return fn(*args, **kwargs), None
    except Exception as exc:  # noqa: BLE001
        return None, str(exc)
