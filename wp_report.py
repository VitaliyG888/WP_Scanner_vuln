#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Shared helpers for the WordPress scanner: severity model and rendering."""

import html
import json
import os

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

SEVERITY_COLOR = {
    "critical": "#b30000",
    "high": "#e65c00",
    "medium": "#c9a100",
    "low": "#3d7ea6",
    "info": "#6c757d",
}


def severity_rank(sev):
    """Return a sortable rank for a severity label (unknown -> 0)."""
    return SEVERITY_ORDER.get(sev, 0)


def summarize(findings):
    """Aggregate findings into a {severity: count} dict plus totals."""
    by_severity = {k: 0 for k in SEVERITY_ORDER}
    for f in findings:
        by_severity[f.get("severity", "info")] = by_severity.get(f.get("severity", "info"), 0) + 1
    return {
        "total": len(findings),
        "by_severity": by_severity,
    }


def _ensure_parent(output_file):
    """Create the directory of an output file when it does not exist yet."""
    parent = os.path.dirname(os.path.abspath(output_file))
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)
    return output_file


def to_json(results, output_file):
    _ensure_parent(output_file)
    with open(output_file, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2, ensure_ascii=False, default=str)
    return output_file


def render_html(results, output_file, title="WordPress Vulnerability Report"):
    """Render a self contained HTML report from a scanner result dict."""
    findings = results.get("findings", [])
    findings = sorted(findings, key=lambda f: severity_rank(f.get("severity")), reverse=True)
    summary = results.get("summary", summarize(findings))

    rows = []
    for f in findings:
        sev = f.get("severity", "info")
        colour = SEVERITY_COLOR.get(sev, "#6c757d")
        location = f.get("file", "")
        if f.get("line"):
            location = "{}:{}".format(location, f["line"])
        rows.append(
            "<tr>"
            "<td><span class='sev' style='background:{}'>{}</span></td>"
            "<td><b>{}</b><br><small>{}</small></td>"
            "<td><code>{}</code></td>"
            "<td><code>{}</code></td>"
            "<td><code>{}</code></td>"
            "<td class='msg'>{}</td>"
            "</tr>".format(
                colour,
                html.escape(sev),
                html.escape(f.get("title", f.get("id", ""))),
                html.escape(f.get("id", "")),
                html.escape(f.get("category", "")),
                html.escape(location or "-"),
                html.escape(f.get("cwe", "") or ""),
                html.escape((f.get("snippet", "") or "").strip()[:180]),
            )
        )

    counts = " ".join(
        "<span class='sev' style='background:{}'>{}: {}</span>".format(
            SEVERITY_COLOR.get(k, "#6c757d"), html.escape(k), v
        )
        for k, v in summary.get("by_severity", {}).items()
        if v
    )

    doc = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>{title}</title>
<style>
 body{{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1b1b1b}}
 h1{{margin:0 0 4px}} .meta{{color:#666;margin-bottom:12px}}
 table{{border-collapse:collapse;width:100%;font-size:13px}}
 th,td{{border:1px solid #ddd;padding:6px 8px;vertical-align:top;text-align:left}}
 th{{background:#f4f4f4}} tr:nth-child(even){{background:#fafafa}}
 code{{font-family:Consolas,monospace;font-size:12px}}
 .sev{{display:inline-block;color:#fff;border-radius:3px;padding:1px 7px;font-size:11px;font-weight:600}}
 .msg{{max-width:340px}}
</style></head><body>
<h1>{title}</h1>
<div class="meta">Target: <b>{target}</b> &middot; findings: <b>{total}</b></div>
<div class="meta">{counts}</div>
<table><thead><tr>
<th>Severity</th><th>Finding</th><th>Category</th><th>Location</th><th>CWE</th><th>Details</th>
</tr></thead><tbody>
{rows}
</tbody></table></body></html>""".format(
        title=html.escape(title),
        target=html.escape(str(results.get("target", "-"))),
        total=summary.get("total", len(findings)),
        counts=counts,
        rows="\n".join(rows) or "<tr><td colspan='6'>No findings</td></tr>",
    )

    _ensure_parent(output_file)
    with open(output_file, "w", encoding="utf-8") as fh:
        fh.write(doc)
    return output_file
