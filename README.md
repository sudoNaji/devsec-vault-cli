# DevSec Vault

> **A layered, production-grade secret-detection pipeline for Python projects.**
> Local pre-commit gates · Push protection · Git history scanning · GitHub Actions CI · SARIF reporting · Supply-chain provenance.

---

## Why DevSec Vault?

Secret leaks are the #1 cause of cloud breaches. DevSec Vault implements a **defence-in-depth** pipeline that catches secrets at every stage of the development lifecycle — before they're committed, before they're pushed, and retroactively in repository history.

---

## Detection Layers

```
Developer workstation
│
├── [Layer 1] pre-commit hook  ──── devsec-vault staged
│     └── Blocks commit if staged diff contains a secret
│
├── [Layer 2] detect-secrets   ──── baseline-driven allowlist
│     └── Catches additional patterns not in our regex set
│
▼
Git push
│
├── [Layer 3] GitHub Push Protection
│     └── Server-side block for 200+ known token types
│
├── [Layer 4] GitHub Secret Scanning
│     └── Full-history scan across all branches
│
▼
Pull Request / CI (GitHub Actions)
│
├── [Layer 5] devsec-vault scan  ── file + directory scan, SARIF upload
├── [Layer 6] devsec-vault history ─ full commit history scan
├── [Layer 7] CodeQL              ── static analysis (security-and-quality)
└── [Layer 8] pip-audit           ── dependency CVE check
│
▼
Release
│
└── [Layer 9] Artifact Attestation + OpenSSF Scorecard
```

---

## Quick Start

```bash
# Clone
git clone https://github.com/your-org/devsec-vault
cd devsec-vault

# Install
pip install click rich

# Install pre-commit hooks
pip install pre-commit
pre-commit install

# Run a scan
python src/cli.py scan src/

# Scan git history
python src/cli.py history --max-commits 200

# Scan staged changes
python src/cli.py staged
```

---

## CLI Reference

### `scan` — Scan files or directories

```bash
python src/cli.py scan [OPTIONS] TARGETS...

Options:
  --format [text|json|sarif]    Output format (default: text)
  --output PATH                 Write report to file
  --baseline PATH               Allowlist baseline file
  --min-severity LEVEL          CRITICAL|HIGH|MEDIUM|LOW (default: LOW)
  --fail-on [any|high|critical|never]  Exit-1 threshold (default: any)
  --no-entropy                  Disable entropy heuristic
  --max-file-size KB            Skip files larger than N KB (default: 500)
```

### `staged` — Pre-commit gate

```bash
python src/cli.py staged [--repo PATH] [--format text|json|sarif]
```
Returns exit code 1 and blocks the commit if secrets are found in the staged diff.

### `history` — Full git history scan

```bash
python src/cli.py history [--max-commits 500] [--format sarif] [--output history.sarif]
```
Inspects every commit reachable from all branches.

### `baseline` — Allowlist management

```bash
# Generate baseline from current findings (mark all as accepted)
python src/cli.py baseline generate src/ --output .devsec-baseline.json

# Show what's new vs baseline (regressions)
python src/cli.py baseline diff src/

# View baseline contents
python src/cli.py baseline show
```

### `report` — Re-render saved report

```bash
python src/cli.py report report.json --format sarif --output results.sarif
python src/cli.py report report.json --format metrics
```

### `info` — Show loaded detection rules

```bash
python src/cli.py info
```

---

## Detection Coverage

| Rule | Severity | What it catches |
|------|----------|-----------------|
| `AWS_ACCESS_KEY_ID` | CRITICAL | `AKIA...` AWS access keys |
| `AWS_SECRET_KEY` | CRITICAL | AWS secret access keys |
| `GITHUB_PERSONAL_TOKEN` | CRITICAL | `ghp_...` PATs |
| `GITHUB_OAUTH_TOKEN` | HIGH | `gho_...` OAuth tokens |
| `GITHUB_APP_TOKEN` | HIGH | `ghs_/ghu_` app tokens |
| `STRIPE_SECRET_KEY` | CRITICAL | `sk_live_/sk_test_` |
| `RSA_PRIVATE_KEY` | CRITICAL | PEM private key headers |
| `OPENSSH_PRIVATE_KEY` | CRITICAL | OpenSSH private keys |
| `DB_CONN_STRING` | CRITICAL | `postgres://user:pass@host/db` |
| `GCP_API_KEY` | HIGH | `AIza...` Google API keys |
| `AZURE_CLIENT_SECRET` | CRITICAL | Azure client secrets |
| `SLACK_TOKEN` | HIGH | `xoxb-/xoxp-` tokens |
| `JWT_TOKEN` | HIGH | `eyJ...` JWTs |
| `HIGH_ENTROPY` | HIGH | Shannon entropy ≥ 4.2 heuristic |
| … +10 more | MEDIUM–HIGH | Stripe pub, Discord, NPM, PyPI… |

---

## Branch Protection Policy

`main` is protected by:
- ✅ Required pull request (1 approving review)
- ✅ Required status checks: `test`, `secret-scan`, `codeql`
- ✅ Signed commits (GPG/SSH) — unsigned commits are rejected
- ✅ No force pushes · no deletions · linear history
- ✅ Administrators included

See [`policies/branch-protection.md`](policies/branch-protection.md) for the full ruleset JSON.

---

## Attack Demo

### Blocked commit (local)

```
$ echo 'AWS_KEY=AKIAIOSFODNN7EXAMPLE' >> src/config.py
$ git add src/config.py && git commit -m "test"

DevSec Vault — staged secret scan.......................Failed
- hook id: devsec-vault-staged
- exit code: 1

 Severity  Rule              Line  Masked Value
 CRITICAL  AWS_ACCESS_KEY_ID    1  AKIA****MPLE

✗ Secret(s) detected in staged changes — commit blocked.
```

### Blocked push (GitHub Push Protection)

```
remote: error: GH013: Repository rule violations found for refs/heads/main.
remote: - Push cannot contain secrets
remote:   —— Amazon AWS Access Key ID ——
remote:      locations: src/config.py:1
remote:
To https://github.com/your-org/devsec-vault
 ! [remote rejected] feature/add-config -> main (push declined due to repository rule violations)
```

---

## Threat Model

See [`policies/threat-model.md`](policies/threat-model.md) for the full threat model covering assets, threat actors, and mitigations.

---

## Metrics

Track security posture over time:

```bash
python src/cli.py report report.json --format metrics
```

```json
{
  "total_findings": 0,
  "by_source": {},
  "by_severity": {},
  "clean_targets": 42,
  "targets_scanned": 42
}
```

| Metric | Target |
|--------|--------|
| Secrets caught locally (pre-commit) | All |
| Secrets blocked by push protection | 0 reach remote |
| Dependency CVEs unfixed | 0 CRITICAL, <5 HIGH |
| Commits unsigned | 0 on `main` |
| CodeQL alerts open | 0 CRITICAL/HIGH |

---

## Supply-Chain Security

- **Artifact attestations** generated on every release (build provenance via SLSA)
- **OpenSSF Scorecard** badge in repo — measures branch protection, signed releases, token permissions
- **OIDC** used for any cloud deployments — no long-lived credentials stored in GitHub Secrets

---

## Running Tests

```bash
pytest tests/ -v
```

---

## License

MIT
