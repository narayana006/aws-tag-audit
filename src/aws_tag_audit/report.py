"""Render audit results as a table, JSON or CSV."""

from __future__ import annotations

import csv
import io
import json

from .audit import AuditResult, Finding

GROUPS = ("service", "account", "owner", "resource_type", "region")
FIELDS = list(Finding.__dataclass_fields__)


def _table(rows: list[list[str]], headers: list[str]) -> str:
    widths = [len(h) for h in headers]
    for row in rows:
        widths = [max(w, len(c)) for w, c in zip(widths, row)]
    lines = ["  ".join(h.ljust(w) for h, w in zip(headers, widths)).rstrip()]
    lines.append("  ".join("-" * w for w in widths))
    for row in rows:
        lines.append("  ".join(c.ljust(w) for c, w in zip(row, widths)).rstrip())
    return "\n".join(lines)


def _short_arn(arn: str, limit: int = 72) -> str:
    return arn if len(arn) <= limit else "..." + arn[-(limit - 3):]


def render_table(result: AuditResult, group_by: str = "service") -> str:
    out = [
        f"Checked {result.checked} resources: {result.compliant} compliant, "
        f"{result.noncompliant} non-compliant"
        + (f" ({result.skipped} skipped by policy)" if result.skipped else "")
    ]
    if not result.findings:
        return out[0] + "\n"
    problems = {p: 0 for p in ("missing", "empty", "invalid", "key-case")}
    for f in result.findings:
        problems[f.problem] += 1
    out.append("Findings: " + ", ".join(f"{n} {p}" for p, n in problems.items() if n))
    out.append("")
    counts = result.counts(group_by)
    rows = [[g, str(n)] for g, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))]
    out.append(_table(rows, [group_by.upper().replace("_", " "), "NON-COMPLIANT"]))
    out.append("")
    rows = [
        [_short_arn(f.arn), f.key, f.problem, f.value, f.detail]
        for f in sorted(result.findings, key=lambda f: (getattr(f, group_by), f.arn, f.key))
    ]
    out.append(_table(rows, ["RESOURCE", "TAG", "PROBLEM", "VALUE", "DETAIL"]))
    return "\n".join(out) + "\n"


def render_json(result: AuditResult, group_by: str = "service") -> str:
    doc = {
        "summary": {
            "checked": result.checked,
            "compliant": result.compliant,
            "non_compliant": result.noncompliant,
            "skipped": result.skipped,
            "findings": len(result.findings),
            f"non_compliant_by_{group_by}": dict(sorted(result.counts(group_by).items())),
        },
        "findings": [f.to_dict() for f in result.findings],
    }
    return json.dumps(doc, indent=2) + "\n"


def render_csv(result: AuditResult, group_by: str = "service") -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=FIELDS, lineterminator="\n")
    writer.writeheader()
    for f in result.findings:
        writer.writerow(f.to_dict())
    return buf.getvalue()


RENDERERS = {"table": render_table, "json": render_json, "csv": render_csv}
