"""
scanner.py — Core scanning engine for DevSec Vault.

Supports:
  - File/directory scanning
  - Git staged diff scanning
  - Git history scanning (all commits, all branches)
  - Entropy-based high-entropy string detection
  - Allowlist / baseline suppression
"""

from __future__ import annotations

import hashlib
import math
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Generator

from patterns import PATTERNS, SEVERITY_ORDER

# ─────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────

SKIP_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".ico",
        ".svg",
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".zip",
        ".tar",
        ".gz",
        ".bz2",
        ".xz",
        ".7z",
        ".pyc",
        ".pyo",
        ".bin",
        ".dat",
        ".db",
        ".pdf",
        ".docx",
        ".xlsx",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".mp3",
        ".mp4",
        ".avi",
        ".mov",
    }
)

SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        "__pycache__",
        "node_modules",
        ".venv",
        "venv",
        ".env",
        "dist",
        "build",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
    }
)

ENTROPY_THRESHOLD = 4.2  # Shannon entropy; strings above this are suspicious
ENTROPY_MIN_LENGTH = 20  # minimum chars to run entropy check on

# Characters typical for base64 / hex secrets


# ─────────────────────────────────────────────────────────────
# DATA MODEL
# ─────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    description: str
    line_number: int
    masked_value: str
    fingerprint: str  # SHA-256 of rule + raw_value for baseline suppression
    source: str = "file"  # "file" | "staged" | "history"
    commit: str = ""  # populated when source == "history"

    def as_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "description": self.description,
            "line_number": self.line_number,
            "masked_value": self.masked_value,
            "fingerprint": self.fingerprint,
            "source": self.source,
            "commit": self.commit,
        }


@dataclass
class ScanResult:
    target: str
    findings: list[Finding] = field(default_factory=list)
    error: str = ""

    @property
    def clean(self) -> bool:
        return len(self.findings) == 0 and not self.error

    def sorted_findings(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.line_number),
        )

    def as_dict(self) -> dict:
        return {
            "target": self.target,
            "clean": self.clean,
            "error": self.error,
            "findings": [f.as_dict() for f in self.sorted_findings()],
        }


# ─────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────


def _mask(value: str) -> str:
    """Show first 4 and last 4 chars; mask the rest."""
    if len(value) <= 8:
        return "****"
    return value[:4] + ("*" * min(len(value) - 8, 12)) + value[-4:]


def _fingerprint(rule: str, raw_value: str) -> str:
    digest = hashlib.sha256(f"{rule}:{raw_value}".encode()).hexdigest()
    return digest[:16]


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _high_entropy_tokens(line: str) -> Generator[str, None, None]:
    """Yield tokens in a line that look like high-entropy secrets."""
    import re

    # look for long alphanum/base64-ish tokens not preceded by common words
    for token in re.findall(r"[A-Za-z0-9+/=\-_]{%d,}" % ENTROPY_MIN_LENGTH, line):
        # skip if most chars are plain alpha (likely a long word / variable)
        alpha_ratio = sum(c.isalpha() for c in token) / len(token)
        if alpha_ratio > 0.85:
            continue
        if _shannon_entropy(token) >= ENTROPY_THRESHOLD:
            yield token


def _is_skippable_path(path: Path) -> bool:
    if path.suffix.lower() in SKIP_EXTENSIONS:
        return True
    for part in path.parts:
        if part in SKIP_DIRS:
            return True
    return False


# ─────────────────────────────────────────────────────────────
# CORE SCAN FUNCTIONS
# ─────────────────────────────────────────────────────────────


def scan_lines(
    lines: list[str],
    source: str = "file",
    commit: str = "",
    allowlist: set[str] | None = None,
) -> list[Finding]:
    """
    Scan a list of text lines for secrets.
    Returns a deduplicated list of Finding objects.
    """
    findings: list[Finding] = []
    seen_fingerprints: set[str] = set()
    allowlist = allowlist or set()

    for line_num, line in enumerate(lines, start=1):
        # ── Pattern-based detection ──────────────────────────
        for rule, (regex, severity, desc) in PATTERNS.items():
            for m in regex.finditer(line):
                raw = m.group()
                fp = _fingerprint(rule, raw)
                if fp in allowlist or fp in seen_fingerprints:
                    continue
                seen_fingerprints.add(fp)
                findings.append(
                    Finding(
                        rule=rule,
                        severity=severity,
                        description=desc,
                        line_number=line_num,
                        masked_value=_mask(raw),
                        fingerprint=fp,
                        source=source,
                        commit=commit,
                    )
                )

        # ── Entropy-based detection ──────────────────────────
        for token in _high_entropy_tokens(line):
            fp = _fingerprint("HIGH_ENTROPY", token)
            if fp in allowlist or fp in seen_fingerprints:
                continue
            seen_fingerprints.add(fp)
            findings.append(
                Finding(
                    rule="HIGH_ENTROPY",
                    severity="HIGH",
                    description=f"High-entropy token (entropy={_shannon_entropy(token):.2f})",
                    line_number=line_num,
                    masked_value=_mask(token),
                    fingerprint=fp,
                    source=source,
                    commit=commit,
                )
            )

    return findings


def scan_content(
    content: str,
    source: str = "file",
    commit: str = "",
    allowlist: set[str] | None = None,
) -> list[Finding]:
    return scan_lines(
        content.splitlines(), source=source, commit=commit, allowlist=allowlist
    )


def scan_file(
    file_path: Path,
    allowlist: set[str] | None = None,
) -> ScanResult:
    result = ScanResult(target=str(file_path))
    if _is_skippable_path(file_path):
        return result
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        result.findings = scan_content(content, source="file", allowlist=allowlist)
    except OSError as exc:
        result.error = str(exc)
    return result


def scan_directory(
    directory: Path,
    allowlist: set[str] | None = None,
    max_file_size_kb: int = 500,
) -> list[ScanResult]:
    results: list[ScanResult] = []
    for root, dirs, files in os.walk(directory):
        root_path = Path(root)
        # Prune skippable dirs in-place so os.walk won't recurse into them
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for fname in files:
            fpath = root_path / fname
            if _is_skippable_path(fpath):
                continue
            if fpath.stat().st_size > max_file_size_kb * 1024:
                continue
            results.append(scan_file(fpath, allowlist=allowlist))
    return results


# ─────────────────────────────────────────────────────────────
# GIT-AWARE SCANNING
# ─────────────────────────────────────────────────────────────


def _run_git(args: list[str], cwd: str | Path) -> str:
    """Run a git command and return stdout, or raise RuntimeError."""
    try:
        proc = subprocess.run(
            ["git"] + args,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=120,
        )
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.strip())
        return proc.stdout
    except FileNotFoundError:
        raise RuntimeError("git not found in PATH")


def scan_staged(
    repo_root: Path,
    allowlist: set[str] | None = None,
) -> ScanResult:
    """Scan git staged (index) diff for secrets."""
    result = ScanResult(target="<staged changes>")
    try:
        diff = _run_git(["diff", "--cached", "--unified=0"], cwd=repo_root)
        lines = [
            line[1:]
            for line in diff.splitlines()
            if line.startswith("+") and not line.startswith("+++")
        ]
        result.findings = scan_lines(lines, source="staged", allowlist=allowlist)
    except RuntimeError as exc:
        result.error = str(exc)
    return result


def scan_git_history(
    repo_root: Path,
    allowlist: set[str] | None = None,
    max_commits: int = 500,
) -> list[ScanResult]:
    """Scan all reachable commits for secrets introduced in diffs."""
    results: list[ScanResult] = []

    try:
        log_output = _run_git(
            ["log", "--all", "--format=%H", f"--max-count={max_commits}"],
            cwd=repo_root,
        )
    except RuntimeError as exc:
        results.append(ScanResult(target="<git history>", error=str(exc)))
        return results

    commits = [c.strip() for c in log_output.splitlines() if c.strip()]

    for sha in commits:
        try:
            diff = _run_git(
                ["show", "--unified=0", "--format=", sha],
                cwd=repo_root,
            )
        except RuntimeError:
            continue

        added_lines = [
            line[1:]
            for line in diff.splitlines()
            if line.startswith("+") and not line.startswith("+++")
        ]
        if not added_lines:
            continue

        findings = scan_lines(
            added_lines, source="history", commit=sha[:12], allowlist=allowlist
        )
        if findings:
            r = ScanResult(target=f"commit:{sha[:12]}")
            r.findings = findings
            results.append(r)

    return results
