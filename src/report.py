"""
report.py — Report generation for DevSec Vault.
Supports JSON, SARIF (GitHub Code Scanning compatible), and text summary.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanner import ScanResult


def _utcnow() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


# ─────────────────────────────────────────────────────────────
# JSON REPORT
# ─────────────────────────────────────────────────────────────


def build_json_report(results: list["ScanResult"], version: str = "2.0.0") -> dict:
    total_findings = sum(len(r.findings) for r in results)
    severity_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in results:
        for f in r.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    return {
        "schema": "devsec-vault-report",
        "version": version,
        "generated_at": _utcnow(),
        "summary": {
            "total_targets": len(results),
            "total_findings": total_findings,
            "clean_targets": sum(1 for r in results if r.clean),
            "severity_breakdown": severity_counts,
        },
        "results": [r.as_dict() for r in results],
    }


def write_json_report(
    results: list["ScanResult"], output_path: Path | None = None
) -> str:
    report = build_json_report(results)
    payload = json.dumps(report, indent=2)
    if output_path:
        output_path.write_text(payload, encoding="utf-8")
    return payload


# ─────────────────────────────────────────────────────────────
# SARIF REPORT  (GitHub Code Scanning format)
# ─────────────────────────────────────────────────────────────

_SARIF_SEVERITY_MAP = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}


def build_sarif_report(results: list["ScanResult"]) -> dict:
    from patterns import RAW_PATTERNS

    rules = []
    for rule_id, (_, severity, desc) in RAW_PATTERNS.items():
        rules.append(
            {
                "id": rule_id,
                "name": rule_id.replace("_", " ").title(),
                "shortDescription": {"text": desc},
                "defaultConfiguration": {
                    "level": _SARIF_SEVERITY_MAP.get(severity, "warning"),
                },
                "helpUri": "https://github.com/your-org/devsec-vault",
            }
        )

    sarif_results = []
    for r in results:
        for f in r.findings:
            sarif_results.append(
                {
                    "ruleId": f.rule,
                    "level": _SARIF_SEVERITY_MAP.get(f.severity, "warning"),
                    "message": {
                        "text": f"{f.description} — masked value: {f.masked_value}",
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": r.target.lstrip("/"),
                                    "uriBaseId": "%SRCROOT%",
                                },
                                "region": {"startLine": max(1, f.line_number)},
                            }
                        }
                    ],
                    "fingerprints": {"devsecVaultV1": f.fingerprint},
                    "properties": {
                        "severity": f.severity,
                        "source": f.source,
                        "commit": f.commit,
                    },
                }
            )

    return {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "DevSec Vault",
                        "informationUri": "https://github.com/your-org/devsec-vault",
                        "version": "2.0.0",
                        "rules": rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }


def write_sarif_report(
    results: list["ScanResult"], output_path: Path | None = None
) -> str:
    report = build_sarif_report(results)
    payload = json.dumps(report, indent=2)
    if output_path:
        output_path.write_text(payload, encoding="utf-8")
    return payload


# ─────────────────────────────────────────────────────────────
# METRICS  (machine-readable counters for dashboards)
# ─────────────────────────────────────────────────────────────


def build_metrics(results: list["ScanResult"]) -> dict:
    """Return flat key:value metrics suitable for Prometheus / badge display."""
    total = sum(len(r.findings) for r in results)
    by_source: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    by_rule: dict[str, int] = {}

    for r in results:
        for f in r.findings:
            by_source[f.source] = by_source.get(f.source, 0) + 1
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
            by_rule[f.rule] = by_rule.get(f.rule, 0) + 1

    return {
        "total_findings": total,
        "by_source": by_source,
        "by_severity": by_severity,
        "by_rule": by_rule,
        "targets_scanned": len(results),
        "clean_targets": sum(1 for r in results if r.clean),
    }
