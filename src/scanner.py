import re
from patterns import PATTERNS

def scan_content(content):
    findings = []

    for name, pattern in PATTERNS.items():
        if re.search(pattern, content):
            findings.append(name)

    return findings