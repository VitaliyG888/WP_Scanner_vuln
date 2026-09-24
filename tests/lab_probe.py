#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Print the raw response of every lab endpoint (debugging helper).

Usage:
    python tests/lab_probe.py --url http://localhost:8080
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wp_dynamic_common import Target, token  # noqa: E402
from wp_dynamic_checks import (  # noqa: E402
    CMD_MARKER_PAYLOADS, SQLI_SLEEP_PAYLOADS,
)

AJAX = "/wp-admin/admin-ajax.php"

PROBES = []
for _template in CMD_MARKER_PAYLOADS:
    PROBES.append(("rce {!r}".format(_template), "GET", "vulnlab_exec", "cmd",
                   _template.format(m=token("PROBE"))))
PROBES.append(("sqli-baseline", "GET", "vulnlab_search", "u", "1"))
for _template in SQLI_SLEEP_PAYLOADS:
    PROBES.append(("sqli {!r}".format(_template.strip()[:22]), "GET",
                   "vulnlab_search", "u", _template.format(n=4)))
PROBES += [
    ("lfi", "GET", "vulnlab_read", "file", "/etc/passwd"),
    ("xss", "GET", "vulnlab_xss", "msg", '"><svg/onload=PROBE>'),
    ("redirect", "GET", "vulnlab_redirect", "url", "https://example.org/PROBE"),
    ("deserialization", "POST", "vulnlab_unpack", "data",
     'O:8:"stdClass":1:{s:1:"a";s:1:"b";}'),
]


def main(argv=None):
    parser = argparse.ArgumentParser(description="Probe the lab endpoints directly")
    parser.add_argument("--url", default="http://localhost:8080")
    args = parser.parse_args(argv)
    target = Target(args.url, timeout=25)

    for name, method, action, param, value in PROBES:
        payload = {"action": action, param: value}
        try:
            if method == "POST":
                resp = target.post(AJAX, data=payload, allow_redirects=False)
            else:
                resp = target.get(AJAX, params=payload, allow_redirects=False)
        except Exception as exc:  # noqa: BLE001
            print("{:<18} EXCEPTION {}".format(name, exc))
            continue
        body = resp.text.replace("\n", " ")[:220]
        location = resp.headers.get("Location", "")
        print("{:<18} HTTP {:<4} {!r}".format(name, resp.status_code, body))
        if location:
            print("{:<18} Location: {}".format("", location))
    return 0


if __name__ == "__main__":
    sys.exit(main())
