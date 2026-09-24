#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Automated validation of the WordPress scanner against the Docker lab.

Static phase
    verifies that every vulnerability planted in
    env/vulnerable-plugin/vuln-core.php is detected, and that the properly
    sanitised env/clean-sample produces zero findings (precision baseline).
Dynamic phase
    runs against the live lab (docker compose up) and requires hard evidence
    (executed marker, measured delay, leaked file, reflected payload) for every
    exploitable class.

Usage:
    python tests/run_tests.py --url http://localhost:8080
    python tests/run_tests.py --static-only
"""

import argparse
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import requests  # noqa: E402

from wp_vuln_scanner import scan_path  # noqa: E402
from wp_exploit_framework import run_all  # noqa: E402


def load_ground_truth():
    path = os.path.join(ROOT, "env", "ground-truth.json")
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def wait_for(url, timeout=240, interval=3):
    """Poll the target until WordPress answers *and is installed*.

    A freshly started container answers HTTP 200 on /wp-login.php but redirects
    every request to /wp-admin/install.php, which would turn the whole dynamic
    phase into false negatives. The probe therefore also asserts that /wp-admin/
    does not point at install.php (the check is neutral: no exploit payload is
    sent before the dynamic phase starts).
    """
    deadline = time.monotonic() + timeout
    base = url.rstrip("/")
    while time.monotonic() < deadline:
        try:
            resp = requests.get(base + "/wp-login.php", timeout=10,
                                allow_redirects=False)
            if resp.status_code < 500:
                admin = requests.get(base + "/wp-admin/", timeout=10,
                                     allow_redirects=False)
                location = admin.headers.get("Location", "")
                if admin.status_code in (301, 302, 303, 307, 308) \
                        and "install.php" in location:
                    print("[.] {} is up but WordPress is not installed yet "
                          "(run: docker compose run --rm installer)".format(url))
                else:
                    print("[.] target {} is up and installed (HTTP {})".format(
                        url, resp.status_code))
                    return True
        except Exception:  # noqa: BLE001
            pass
        print("[.] waiting for {} ...".format(url))
        time.sleep(interval)
    return False


class Checks(object):
    """Tiny assertion recorder with PASS/FAIL output."""

    def __init__(self):
        self.passed = 0
        self.failed = 0

    def ok(self, name, detail=""):
        self.passed += 1
        print("  PASS  {:<42} {}".format(name, detail))

    def fail(self, name, detail=""):
        self.failed += 1
        print("  FAIL  {:<42} {}".format(name, detail))

    def require(self, name, condition, detail=""):
        if condition:
            self.ok(name, detail)
        else:
            self.fail(name, detail)
        return bool(condition)


def phase_static(gt, checks):
    """Static analysis must find every planted vulnerability class."""
    print("\n== Phase 1: static analysis (known vulnerabilities) ==")
    result = scan_path(os.path.join(ROOT, gt["plugin"]))
    found_ids = {f["id"] for f in result["findings"]}
    found_cats = {f["category"] for f in result["findings"]}
    print("  detected ids: {}".format(", ".join(sorted(found_ids))))

    for group in gt["static_expected_any_of"]:
        matched = [i for i in group if i in found_ids]
        checks.require("static:" + "|".join(group), bool(matched),
                       "matched {}".format(matched or "-"))
    for category in gt["static_expected_categories"]:
        checks.require("category:" + category, category in found_cats)
    checks.require("static:min-findings",
                   len(result["findings"]) >= gt["static_min_findings"],
                   "{} findings (>= {})".format(len(result["findings"]),
                                                gt["static_min_findings"]))
    return result


def phase_precision(gt, checks):
    """Properly sanitised code must not produce findings (false positives)."""
    print("\n== Phase 2: precision baseline (sanitised code) ==")
    sample = os.path.join(ROOT, gt["clean_sample"]["path"])
    result = scan_path(sample)
    expected = gt["clean_sample"]["expected_findings"]
    checks.require("precision:no-false-positives",
                   len(result["findings"]) == expected,
                   "{} findings on safe code".format(len(result["findings"])))
    for finding in result["findings"]:
        print("    unexpected: {} @ {}:{}".format(
            finding["id"], finding["file"], finding["line"]))
    return result


def phase_dynamic(url, gt, checks):
    """Exploitation phase: require hard evidence for each vuln class."""
    print("\n== Phase 3: dynamic analysis (live lab) ==")
    result = run_all(url, timeout=20, verbose=True)
    vulnerable = {r["id"] for r in result["results"] if r["vulnerable"]}
    print("  confirmed: {}".format(", ".join(sorted(vulnerable)) or "-"))

    for group in gt["dynamic_required_any_of"]:
        matched = [i for i in group if i in vulnerable]
        checks.require("dynamic:" + "|".join(group), bool(matched),
                       "matched {}".format(matched or "-"))
    for group in gt["dynamic_optional_any_of"]:
        matched = [i for i in group if i in vulnerable]
        print("  note  {:<42} {}".format("dynamic(optional):" + "|".join(group),
                                         matched or "not triggered"))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="Validate the WP scanner against the lab")
    parser.add_argument("--url", default=os.environ.get("TARGET_URL", "http://localhost:8080"))
    parser.add_argument("--wait", action="store_true",
                        help="wait until the target answers before scanning")
    parser.add_argument("--wait-timeout", type=int, default=300)
    parser.add_argument("--static-only", action="store_true")
    parser.add_argument("--mock", action="store_true",
                        help="run the dynamic phase against the built-in mock "
                             "target (no Docker required)")
    parser.add_argument("--json", default=os.path.join(ROOT, "tests", "results.json"))
    args = parser.parse_args(argv)

    ground_truth = load_ground_truth()
    checks = Checks()
    report = {}

    report["static"] = phase_static(ground_truth, checks)
    report["precision"] = phase_precision(ground_truth, checks)

    mock = None
    if not args.static_only and args.mock:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from mock_wp_server import start as start_mock
        mock, args.url = start_mock()
        print("[.] mock WordPress target started at {}".format(args.url))

    if args.static_only:
        print("\n[!] dynamic phase skipped (--static-only)")
    elif args.wait and not wait_for(args.url, args.wait_timeout):
        checks.fail("dynamic:target-reachable", "no answer from {}".format(args.url))
    else:
        report["dynamic"] = phase_dynamic(args.url, ground_truth, checks)

    if mock is not None:
        mock.shutdown()

    with open(args.json, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False, default=str)

    total = checks.passed + checks.failed
    print("\n== Summary ==")
    print("  passed: {} / {}".format(checks.passed, total))
    print("  failed: {}".format(checks.failed))
    print("  details written to {}".format(args.json))
    return 1 if checks.failed else 0


if __name__ == "__main__":
    sys.exit(main())

