"""
baseline.py — Allowlist / baseline management for DevSec Vault.

A baseline is a JSON file that stores fingerprints of known / accepted findings.
Any finding whose fingerprint is in the baseline is silently suppressed.
This mirrors how detect-secrets handles its .secrets.baseline file.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanner import Finding, ScanResult

DEFAULT_BASELINE_PATH = Path(".devsec-baseline.json")


def load_baseline(path: Path = DEFAULT_BASELINE_PATH) -> set[str]:
    """Return set of fingerprint strings from an existing baseline file."""
    if not path.exists():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return set(data.get("allowlist", []))
    except (json.JSONDecodeError, OSError):
        return set()


def save_baseline(
    results: list["ScanResult"],
    path: Path = DEFAULT_BASELINE_PATH,
) -> None:
    """
    Write all current findings as the new baseline (i.e., mark them all as allowed).
    Use this to initialise a fresh baseline or after reviewing and accepting findings.
    """
    all_fps: list[str] = []
    entries: list[dict] = []
    for r in results:
        for f in r.findings:
            if f.fingerprint not in all_fps:
                all_fps.append(f.fingerprint)
                entries.append(
                    {
                        "fingerprint": f.fingerprint,
                        "rule": f.rule,
                        "description": f.description,
                        "target": r.target,
                        "line": f.line_number,
                        "masked_value": f.masked_value,
                    }
                )
    data = {
        "schema": "devsec-vault-baseline",
        "version": "1",
        "allowlist": all_fps,
        "entries": entries,
    }
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def diff_baseline(
    old_fps: set[str],
    results: list["ScanResult"],
) -> tuple[list["Finding"], list[str]]:
    """
    Compare a previous baseline against new scan results.
    Returns:
      new_findings  — findings not in the old baseline (regressions)
      resolved_fps  — fingerprints in old baseline that no longer appear (fixed)
    """
    current_fps: set[str] = set()
    all_findings: list["Finding"] = []
    for r in results:
        for f in r.findings:
            current_fps.add(f.fingerprint)
            all_findings.append(f)

    new_findings = [f for f in all_findings if f.fingerprint not in old_fps]
    resolved_fps = list(old_fps - current_fps)
    return new_findings, resolved_fps
