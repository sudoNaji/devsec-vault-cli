import argparse
import os
import json
from scanner import scan_content


# ----------------------------
# CONFIG (real-world hygiene)
# ----------------------------
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif",
    ".exe", ".dll", ".so",
    ".zip", ".tar", ".gz",
    ".pyc", ".bin"
}

SKIP_DIRS = {
    ".git", "__pycache__", "node_modules", ".venv", "venv"
}


# ----------------------------
# FILE SAFETY CHECKS
# ----------------------------
def is_valid_file(path):
    return not any(path.endswith(ext) for ext in SKIP_EXTENSIONS)


def should_skip_dir(path):
    return any(skip in path.split(os.sep) for skip in SKIP_DIRS)


# ----------------------------
# CORE SCANNING LOGIC
# ----------------------------
def scan_file(file_path):
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        return scan_content(content)

    except Exception:
        return []


def scan_path(path):
    results = {}

    if os.path.isfile(path):
        results[path] = scan_file(path)
        return results

    for root, dirs, files in os.walk(path):

        # skip dangerous / irrelevant directories
        if should_skip_dir(root):
            continue

        for file in files:
            full_path = os.path.join(root, file)

            if not is_valid_file(full_path):
                continue

            results[full_path] = scan_file(full_path)

    return results


# ----------------------------
# OUTPUT FORMAT HANDLING
# ----------------------------
def print_text(results):
    for file, findings in results.items():
        print(f"\nFile: {file}")

        if findings:
            for item in findings:
                print(f"  [!] {item}")
        else:
            print("  Clean")


def print_json(results):
    print(json.dumps(results, indent=2))


# ----------------------------
# CLI ENTRY POINT
# ----------------------------
def main():
    parser = argparse.ArgumentParser(description="DevSec Vault CLI Scanner")

    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format"
    )

    args = parser.parse_args()

    results = scan_path(args.path)

    if args.format == "json":
        print_json(results)
    else:
        print_text(results)


if __name__ == "__main__":
    main()