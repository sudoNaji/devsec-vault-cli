"""
patterns.py — Secret detection patterns for DevSec Vault.
Covers AWS, GitHub, Stripe, Slack, GCP, Azure, private keys,
generic high-entropy tokens, database DSNs, and more.
"""

import re

# ─────────────────────────────────────────────
# COMPILED PATTERN REGISTRY
# Each entry: (compiled_regex, severity, description)
# severity: CRITICAL | HIGH | MEDIUM | LOW
# ─────────────────────────────────────────────

RAW_PATTERNS: dict[str, tuple[str, str, str]] = {
    # ── Cloud Provider Keys ──────────────────────────────────────────────
    "AWS_ACCESS_KEY_ID": (
        r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])",
        "CRITICAL",
        "AWS Access Key ID",
    ),
    "AWS_SECRET_KEY": (
        r"(?i)aws[_\-\s]{0,5}secret[_\-\s]{0,5}(access[_\-\s]{0,5})?key[\s:=\"'`]{1,5}[A-Za-z0-9+/]{40}",
        "CRITICAL",
        "AWS Secret Access Key",
    ),
    "GCP_API_KEY": (
        r"AIza[0-9A-Za-z\-_]{35}",
        "HIGH",
        "Google Cloud API Key",
    ),
    "GCP_SERVICE_ACCOUNT": (
        r'"type"\s*:\s*"service_account"',
        "HIGH",
        "GCP Service Account JSON",
    ),
    "AZURE_CLIENT_SECRET": (
        r"(?i)azure[_\-\s]{0,5}(client[_\-\s]{0,5})?secret[\s:=\"'`]{1,5}[A-Za-z0-9\-._~]{32,}",
        "CRITICAL",
        "Azure Client Secret",
    ),
    # ── Source Control / CI Tokens ────────────────────────────────────────
    "GITHUB_PERSONAL_TOKEN": (
        r"ghp_[A-Za-z0-9]{32,}",
        "CRITICAL",
        "GitHub Personal Access Token",
    ),
    "GITHUB_OAUTH_TOKEN": (
        r"gho_[A-Za-z0-9]{32,}",
        "HIGH",
        "GitHub OAuth Token",
    ),
    "GITHUB_APP_TOKEN": (
        r"(ghs|ghu)_[A-Za-z0-9]{32,}",
        "HIGH",
        "GitHub App/User Token",
    ),
    "GITLAB_TOKEN": (
        r"glpat-[A-Za-z0-9\-]{20}",
        "HIGH",
        "GitLab Personal Access Token",
    ),
    # ── Payment / Financial ───────────────────────────────────────────────
    "STRIPE_SECRET_KEY": (
        r"sk_(live|test)_[0-9a-zA-Z]{24}",
        "CRITICAL",
        "Stripe Secret Key",
    ),
    "STRIPE_PUBLISHABLE_KEY": (
        r"pk_(live|test)_[0-9a-zA-Z]{24}",
        "MEDIUM",
        "Stripe Publishable Key",
    ),
    # ── Messaging / Collab ────────────────────────────────────────────────
    "SLACK_TOKEN": (
        r"xox[baprs]-[A-Za-z0-9-]{10,48}",
        "HIGH",
        "Slack API Token",
    ),
    "SLACK_WEBHOOK": (
        r"https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[A-Za-z0-9]{24}",
        "HIGH",
        "Slack Incoming Webhook",
    ),
    "DISCORD_WEBHOOK": (
        r"https://discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_\-]{60,68}",
        "MEDIUM",
        "Discord Webhook URL",
    ),
    # ── Private Keys ──────────────────────────────────────────────────────
    "RSA_PRIVATE_KEY": (
        r"-----BEGIN RSA PRIVATE KEY-----",  # pragma: allowlist secret
        "CRITICAL",
        "RSA Private Key",
    ),
    "OPENSSH_PRIVATE_KEY": (
        r"-----BEGIN OPENSSH PRIVATE KEY-----",  # pragma: allowlist secret
        "CRITICAL",
        "OpenSSH Private Key",
    ),
    "EC_PRIVATE_KEY": (
        r"-----BEGIN EC PRIVATE KEY-----",  # pragma: allowlist secret
        "CRITICAL",
        "EC Private Key",
    ),
    "PGP_PRIVATE_KEY": (
        r"-----BEGIN PGP PRIVATE KEY BLOCK-----",  # pragma: allowlist secret
        "CRITICAL",
        "PGP Private Key Block",
    ),
    # ── Database Connection Strings ───────────────────────────────────────
    "DB_CONN_STRING": (
        r"(?i)(postgres|mysql|mongodb|redis|mssql|sqlite)://[^:@\s\"']+:[^@\s\"']+@[^\s\"']+",
        "CRITICAL",
        "Database Connection String with credentials",
    ),
    # ── Generic High-Entropy / Password Patterns ──────────────────────────
    "GENERIC_SECRET": (
        r"""(?ix)
        (?:secret|password|passwd|api[_\-]?key|api[_\-]?token|auth[_\-]?token|access[_\-]?token)
        [\s:=\"'`]{1,5}
        (?![\s\"'`<>\{\}])
        [A-Za-z0-9+/\-_!@#$%^&*]{16,}
        """,
        "HIGH",
        "Generic Secret / Password Assignment",
    ),
    "JWT_TOKEN": (
        r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
        "HIGH",
        "JSON Web Token (JWT)",
    ),
    "BEARER_TOKEN": (
        r"""(?ix)
        Authorization:\s*Bearer\s+
        (?![\{\$<])
        [A-Za-z0-9\-_\.]{20,}
        """,
        "HIGH",
        "Authorization Bearer Token",
    ),
    # ── NPM / Package Manager ─────────────────────────────────────────────
    "NPM_TOKEN": (
        r"npm_[A-Za-z0-9]{36}",
        "HIGH",
        "NPM Publish Token",
    ),
    "PYPI_TOKEN": (
        r"pypi-[A-Za-z0-9\-_]{50,}",
        "HIGH",
        "PyPI API Token",
    ),
    # ── Email / SMTP ──────────────────────────────────────────────────────
    "SENDGRID_KEY": (
        r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}",
        "HIGH",
        "SendGrid API Key",
    ),
    "MAILGUN_KEY": (
        r"key-[A-Za-z0-9]{32}",
        "HIGH",
        "Mailgun API Key",
    ),
}


def _compile() -> dict[str, tuple[re.Pattern, str, str]]:
    compiled = {}
    for name, (pattern, severity, desc) in RAW_PATTERNS.items():
        try:
            compiled[name] = (re.compile(pattern, re.MULTILINE), severity, desc)
        except re.error as exc:
            # Never let a bad pattern crash the whole tool
            import sys

            print(f"[WARN] Pattern '{name}' failed to compile: {exc}", file=sys.stderr)
    return compiled


PATTERNS: dict[str, tuple[re.Pattern, str, str]] = _compile()

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
