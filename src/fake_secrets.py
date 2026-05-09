"""
fake_secrets.py — Demo file with synthetic secrets for attack demo / testing.

WARNING: These are FAKE credentials used purely for scanner validation.
They match real patterns but will fail any actual authentication.
"""

# Fake AWS credentials — will be caught by scanner
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Fake GitHub token
GITHUB_TOKEN = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"

# Fake Stripe key
STRIPE_SECRET = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"

# Fake private key header
FAKE_KEY_HEADER = "-----BEGIN RSA PRIVATE KEY-----"

# Fake DB connection string
DATABASE_URL = "postgres://admin:supersecretpassword123@db.example.com:5432/production"

# Fake Slack token
SLACK_API_TOKEN = "xoxb-17653672481-19874698323-pdFZKVeTuq8429b"

# Fake JWT
JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
