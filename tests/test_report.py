"""tests/test_report.py — Unit tests for report generation."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from report import build_json_report, build_metrics, build_sarif_report
from scanner import Finding, ScanResult


def _make_result(target: str = "src/test.py") -> ScanResult:
    r = ScanResult(target=target)
    r.findings = [
        Finding(
            rule="AWS_ACCESS_KEY_ID",
            severity="CRITICAL",
            description="AWS Access Key ID",
            line_number=3,
            masked_value="AKIA****MPLE",
            fingerprint="deadbeef12345678",
            source="file",
            commit="",
        )
    ]
    return r


def test_json_report_structure():
    results = [_make_result()]
    report = build_json_report(results)
    assert report["schema"] == "devsec-vault-report"
    assert report["summary"]["total_findings"] == 1
    assert report["summary"]["severity_breakdown"]["CRITICAL"] == 1
    assert len(report["results"]) == 1


def test_sarif_report_structure():
    results = [_make_result()]
    sarif = build_sarif_report(results)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    assert len(sarif["runs"][0]["results"]) == 1
    assert sarif["runs"][0]["results"][0]["ruleId"] == "AWS_ACCESS_KEY_ID"


def test_metrics_structure():
    results = [_make_result()]
    m = build_metrics(results)
    assert m["total_findings"] == 1
    assert m["by_severity"]["CRITICAL"] == 1
    assert m["by_rule"]["AWS_ACCESS_KEY_ID"] == 1
    assert m["clean_targets"] == 0


def test_clean_result_metrics():
    r = ScanResult(target="clean.py")
    m = build_metrics([r])
    assert m["total_findings"] == 0
    assert m["clean_targets"] == 1
