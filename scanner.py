# DevSec Vault - Secrets Scanner
import re, sys

PATTERNS = {
    "AWS Key":     r"AKIA[0-9A-Z]{16}",
    "Generic Token": r"[a-zA-Z0-9_\-]{32,45}",
    "Password":    r"password\s*=\s*['\"].+['\"]", # pragma: allowlist secret
}
PATTERNS["GitHub Token"] = r"ghp_[a-zA-Z0-9]{36}"
PATTERNS["Slack Token"]  = r"xox[baprs]-[0-9A-Za-z\-]{10,48}"

def scan_file(filepath):
    with open(filepath) as f:
        content = f.read()
    for name, pattern in PATTERNS.items():
        if re.search(pattern, content):
            print(f"[!] Found {name} in {filepath}")

if __name__ == "__main__":
    scan_file(sys.argv[1])
