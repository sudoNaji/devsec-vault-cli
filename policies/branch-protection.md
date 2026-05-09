# Branch Protection Policy — DevSec Vault

## Protected Branches

### `main`

| Rule | Setting |
|------|---------|
| Require pull request before merging | ✅ Enabled |
| Required approving reviews | 1 |
| Dismiss stale reviews on new push | ✅ Enabled |
| Require review from code owners | ✅ Enabled (CODEOWNERS file) |
| Require status checks to pass | ✅ Enabled |
| Required status checks | `test`, `secret-scan`, `codeql`, `dependency-audit` |
| Require branches to be up to date | ✅ Enabled |
| Require signed commits | ✅ Enabled (GPG / SSH signing) |
| Require linear history | ✅ Enabled (no merge commits) |
| Include administrators | ✅ Enabled |
| Allow force pushes | ❌ Disabled |
| Allow deletions | ❌ Disabled |

### `develop`

| Rule | Setting |
|------|---------|
| Require pull request before merging | ✅ Enabled |
| Required approving reviews | 1 |
| Require status checks | `test`, `secret-scan` |
| Require signed commits | ✅ Enabled |

## Ruleset Configuration (GitHub Rulesets API)

```json
{
  "name": "main-protection",
  "target": "branch",
  "enforcement": "active",
  "conditions": {
    "ref_name": {
      "include": ["refs/heads/main"],
      "exclude": []
    }
  },
  "rules": [
    { "type": "required_signatures" },
    { "type": "pull_request", "parameters": { "required_approving_review_count": 1, "dismiss_stale_reviews_on_push": true } },
    { "type": "required_status_checks", "parameters": { "required_status_checks": [{ "context": "test" }, { "context": "secret-scan" }, { "context": "codeql" }], "strict_required_status_checks_policy": true } },
    { "type": "non_fast_forward" }
  ]
}
```

## Commit Signing Setup

All commits to protected branches must be GPG or SSH signed.

```bash
# GPG signing (recommended)
git config --global user.signingkey YOUR_GPG_KEY_ID
git config --global commit.gpgsign true

# SSH signing (GitHub supports this natively)
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true
```
