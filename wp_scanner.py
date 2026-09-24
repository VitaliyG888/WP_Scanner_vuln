#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unified WordPress vulnerability scanner (static source analysis + dynamic).

Examples:
    python wp_scanner.py --mode static --path env/vulnerable-plugin
    python wp_scanner.py --mode dynamic --url http://localhost:8080
    python wp_scanner.py --mode all --path env/vulnerable-plugin --url http://localhost:8080
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from wp_vuln_scanner import scan_path, DEFAULT_PATH  # noqa: E402
from wp_exploit_framework import run_all  # noqa: E402
from wp_report import summarize, to_json, render_html, severity_rank  # noqa: E402

SEVERITIES = ["critical", "high", "medium", "low", "info"]


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="WordPress vulnerability scanner (static + dynamic)")
    parser.add_argument("--mode", default="all", choices=["static", "dynamic", "all"])
    parser.add_argument("--path", default=None,
                        help="local directory/file for static analysis")
    parser.add_argument("--url", default=None, help="target URL for dynamic analysis")
    parser.add_argument("--out", default="wp_scan_report", help="output file prefix")
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--min-severity", default="info", choices=SEVERITIES)
    parser.add_argument("--only", nargs="*", default=None,
                        help="dynamic: run only checks containing these tokens")
    parser.add_argument("--no-active", action="store_true",
                        help="dynamic: skip intrusive exploitation checks")
    parser.add_argument("--fail-on", default="none", choices=SEVERITIES + ["none"])
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    findings = []
    meta = {}

    if args.mode in ("static", "all"):
        path = args.path or DEFAULT_PATH
        static = scan_path(path, args.min_severity)
        for finding in static["findings"]:
            finding["source"] = "static"
            finding["location"] = "{}:{}".format(finding.get("file", ""),
                                                 finding.get("line", ""))
        findings += static["findings"]
        meta["static"] = {"target": static["target"],
                          "files_scanned": static["files_scanned"]}
        print("[static] {} file(s) scanned -> {} finding(s)".format(
            static["files_scanned"], len(static["findings"])))

    if args.mode in ("dynamic", "all") and args.url:
        dynamic = run_all(args.url, timeout=args.timeout, only=args.only,
                          no_active=args.no_active, verbose=not args.quiet)
        for finding in dynamic["findings"]:
            finding["source"] = "dynamic"
            finding["location"] = finding.get("file", "")
        findings += dynamic["findings"]
        meta["dynamic"] = {"target": dynamic["target"]}
        print("[dynamic] {} -> {} finding(s)".format(
            dynamic["target"], len(dynamic["findings"])))
    elif args.mode == "dynamic" and not args.url:
        parser.error("--url is required in dynamic mode")

    threshold = severity_rank(args.min_severity)
    findings = [f for f in findings if severity_rank(f["severity"]) >= threshold]
    findings.sort(key=lambda f: (-severity_rank(f["severity"]),
                                 str(f.get("source", "")),
                                 str(f.get("location", ""))))

    result = {
        "target": args.url or (args.path or DEFAULT_PATH),
        "mode": args.mode,
        "meta": meta,
        "findings": findings,
        "summary": summarize(findings),
    }

    json_path = args.out + ".json"
    html_path = args.out + ".html"
    to_json(result, json_path)
    render_html(result, html_path, title="WordPress Scan Report")

    counts = result["summary"]["by_severity"]
    print("[+] Total findings: {} (critical={critical} high={high} medium={medium} low={low})"
          .format(result["summary"]["total"], **counts))
    print("[+] JSON: {}".format(json_path))
    print("[+] HTML: {}".format(html_path))

    if args.fail_on != "none":
        fail_rank = severity_rank(args.fail_on)
        if any(severity_rank(f["severity"]) >= fail_rank for f in findings):
            print("[!] findings at or above '{}' detected".format(args.fail_on))
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
