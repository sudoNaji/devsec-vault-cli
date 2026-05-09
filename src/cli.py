import sys
from scanner import scan_content

def main(file_path):
    with open(file_path, "r") as f:
        content = f.read()

    results = scan_content(content)

    if results:
        print("Secrets detected:")
        for r in results:
            print("-", r)
    else:
        print("No secrets found")

if __name__ == "__main__":
    main(sys.argv[1])