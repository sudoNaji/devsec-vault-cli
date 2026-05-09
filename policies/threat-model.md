# Threat Model — DevSec Vault

## Assets
- Source code and configuration files in the repository
- Secrets / credentials used by the application (API keys, DB passwords, tokens)
- CI/CD pipeline integrity
- Contributor identity (commit authorship)
- Released build artifacts

## Threat Actors
| Actor | Likelihood | Impact |
|-------|-----------|--------|
| Developer accidentally commits a secret | High | Critical |
| Insider threat pushes malicious code | Low | Critical |
| Supply-chain attack via compromised dependency | Medium | High |
| Attacker reads public repo history for leaked credentials | High | Critical |
| CI/CD pipeline compromise via long-lived secrets | Medium | Critical |

## Attack Surface & Mitigations

### 1. Secret Leak — Local
**Threat:** Developer hard-codes API key in source file.
**Mitigations:**
- pre-commit hook (`devsec-vault staged`) blocks commit if secret detected
- detect-secrets baseline prevents accidental baseline suppression
- Developer education / `.env` patterns enforced by `.gitignore`

### 2. Secret Leak — Push
**Threat:** Secret bypasses local hooks and is pushed.
**Mitigations:**
- GitHub secret scanning (all branches, all history)
- GitHub push protection blocks the push for known token patterns
- `devsec-vault history` scans full git history in CI

### 3. Secret Leak — History
**Threat:** Old commits in repository contain secrets.
**Mitigations:**
- Weekly scheduled `devsec-vault history` CI scan
- SARIF results uploaded to GitHub Security tab
- Rotation SOP triggered on any CRITICAL finding

### 4. Unauthorized Code Merge
**Threat:** Attacker or bad actor merges code without review.
**Mitigations:**
- Branch protection: 1 required approving review on `main`
- Signed commits required (GPG/SSH) — authorship verified
- No force pushes; linear history enforced

### 5. Supply-Chain / Dependency Attack
**Threat:** Compromised package introduces malicious code.
**Mitigations:**
- `pip-audit` in CI detects CVEs in direct and transitive dependencies
- Dependabot alerts enabled on GitHub
- Pinned dependency versions in `requirements.txt`
- Artifact attestations provide build provenance for released packages

### 6. CI/CD Secret Exposure
**Threat:** Long-lived cloud credentials stored as repository secrets.
**Mitigations:**
- OIDC used for cloud authentication (no stored credentials)
- GitHub Actions secrets scoped to minimum required permissions
- Audit log monitored for unexpected secret access

## Residual Risk
- High-entropy entropy heuristic may miss non-standard secret formats
- History scan only covers up to `--max-commits` commits; very old history needs manual review
- Signed commits verify authorship but not the content quality of the change

## Detection → Remediation SOP
1. Finding detected → GitHub Security alert raised
2. On-call engineer notified (Slack + email via GitHub notifications)
3. Affected credential rotated within **2 hours** for CRITICAL, **24 hours** for HIGH
4. Git history rewritten or repo archived if unrotatable
5. Post-incident review within 5 business days
