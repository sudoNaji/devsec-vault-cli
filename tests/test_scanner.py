"""
tests/test_scanner.py — Unit tests for DevSec Vault scanning engine.
Run with: pytest tests/ -v
"""

import sys
from pathlib import Path

# Ensure src/ is importable
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from scanner import _mask, _shannon_entropy, scan_content, scan_lines

# ─────────────────────────────────────────────────────────────
# Entropy helpers
# ─────────────────────────────────────────────────────────────


def test_entropy_empty_string():
    assert _shannon_entropy("") == 0.0


def test_entropy_uniform_string():
    # All same character — minimum entropy
    assert _shannon_entropy("aaaaaaaaaa") < 0.1


def test_entropy_random_string():
    # High-entropy token should score > 4
    assert _shannon_entropy("wJalrXUtnFEMI/K7MDENG/bPxRfiCY") > 4.0


# ─────────────────────────────────────────────────────────────
# Masking
# ─────────────────────────────────────────────────────────────


def test_mask_short_value():
    assert _mask("abc") == "****"


def test_mask_long_value():
    result = _mask("AKIAIOSFODNN7EXAMPLE")
    assert result.startswith("AKIA")
    assert result.endswith("MPLE")
    assert "****" in result or "**" in result


# ─────────────────────────────────────────────────────────────
# AWS Key Detection
# ─────────────────────────────────────────────────────────────


def test_detect_aws_access_key():
    findings = scan_content("export AWS_KEY=AKIAIOSFODNN7EXAMPLE")
    rules = [f.rule for f in findings]
    assert "AWS_ACCESS_KEY_ID" in rules


def test_no_false_positive_short_akia():
    # AKIA followed by only 4 chars — too short
    findings = scan_content("AKIA1234")
    assert not any(f.rule == "AWS_ACCESS_KEY_ID" for f in findings)


# ─────────────────────────────────────────────────────────────
# GitHub Token Detection
# ─────────────────────────────────────────────────────────────


def test_detect_github_personal_token():
    token = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456"
    findings = scan_content(f"GITHUB_TOKEN={token}")
    rules = [f.rule for f in findings]
    assert "GITHUB_PERSONAL_TOKEN" in rules


def test_detect_github_oauth_token():
    token = "gho_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456"
    findings = scan_content(f"token={token}")
    rules = [f.rule for f in findings]
    assert "GITHUB_OAUTH_TOKEN" in rules


# ─────────────────────────────────────────────────────────────
# Stripe Key Detection
# ─────────────────────────────────────────────────────────────


def test_detect_stripe_secret_key():
    findings = scan_content("STRIPE_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc")
    rules = [f.rule for f in findings]
    assert "STRIPE_SECRET_KEY" in rules


def test_detect_stripe_test_key():
    findings = scan_content("STRIPE_KEY=sk_test_4eC39HqLyjWDarjtT1zdp7dc")
    rules = [f.rule for f in findings]
    assert "STRIPE_SECRET_KEY" in rules


# ─────────────────────────────────────────────────────────────
# Private Key Detection
# ─────────────────────────────────────────────────────────────


def test_detect_rsa_private_key():
    content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA..."
    findings = scan_content(content)
    rules = [f.rule for f in findings]
    assert "RSA_PRIVATE_KEY" in rules


def test_detect_openssh_private_key():
    content = "-----BEGIN OPENSSH PRIVATE KEY-----"
    findings = scan_content(content)
    rules = [f.rule for f in findings]
    assert "OPENSSH_PRIVATE_KEY" in rules


# ─────────────────────────────────────────────────────────────
# Database Connection String
# ─────────────────────────────────────────────────────────────


def test_detect_postgres_dsn():
    dsn = "postgres://admin:secretpassword@db.prod.example.com:5432/mydb"
    findings = scan_content(dsn)
    rules = [f.rule for f in findings]
    assert "DB_CONN_STRING" in rules


def test_no_false_positive_postgres_no_credentials():
    # No password in the DSN
    findings = scan_content("postgresql://localhost/mydb")
    assert not any(f.rule == "DB_CONN_STRING" for f in findings)


# ─────────────────────────────────────────────────────────────
# Slack Token Detection
# ─────────────────────────────────────────────────────────────


def test_detect_slack_token():
    findings = scan_content("SLACK_TOKEN=xoxb-17653672481-19874698323-pdFZKVeTuq8429b")
    rules = [f.rule for f in findings]
    assert "SLACK_TOKEN" in rules


# ─────────────────────────────────────────────────────────────
# JWT Detection
# ─────────────────────────────────────────────────────────────


def test_detect_jwt():
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    findings = scan_content(jwt)
    rules = [f.rule for f in findings]
    assert "JWT_TOKEN" in rules


# ─────────────────────────────────────────────────────────────
# Baseline / Allowlist suppression
# ─────────────────────────────────────────────────────────────


def test_allowlist_suppresses_finding():
    content = "AWS_KEY=AKIAIOSFODNN7EXAMPLE"
    findings_before = scan_content(content)
    assert findings_before  # should find something

    fps = {f.fingerprint for f in findings_before}
    findings_after = scan_content(content, allowlist=fps)
    # All findings should be suppressed
    assert len(findings_after) == 0


# ─────────────────────────────────────────────────────────────
# Source tagging
# ─────────────────────────────────────────────────────────────


def test_source_tag_propagated():
    findings = scan_content("ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456", source="staged")
    assert all(f.source == "staged" for f in findings)


def test_commit_tag_propagated():
    findings = scan_content(
        "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456", source="history", commit="abc123def456"
    )
    assert all(f.commit == "abc123def456" for f in findings)


# ─────────────────────────────────────────────────────────────
# Multi-line / multi-secret content
# ─────────────────────────────────────────────────────────────


def test_multiple_secrets_same_file():
    content = "\n".join(
        [
            "AWS_KEY=AKIAIOSFODNN7EXAMPLE",
            "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456",
            "STRIPE=sk_live_4eC39HqLyjWDarjtT1zdp7dc",
        ]
    )
    findings = scan_content(content)
    rules = {f.rule for f in findings}
    assert "AWS_ACCESS_KEY_ID" in rules
    assert "GITHUB_PERSONAL_TOKEN" in rules
    assert "STRIPE_SECRET_KEY" in rules


def test_deduplication_same_secret_two_lines():
    line = "TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456"
    content = f"{line}\n{line}"  # same secret repeated
    findings = scan_content(content)
    # fingerprint-based dedup — should only appear once
    gh_findings = [f for f in findings if f.rule == "GITHUB_PERSONAL_TOKEN"]
    assert len(gh_findings) == 1
