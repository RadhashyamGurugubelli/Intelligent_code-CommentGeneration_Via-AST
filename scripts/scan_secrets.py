"""Release packaging secret scanner for AST Studio.

Scans the project tree for leaked secrets, API keys, credentials, and .env files.
Exits with 0 if clean, or 1 if any unmasked secret is detected.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# Add project root to sys.path
root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir))

from backend.security_secrets import detect_secrets


IGNORED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".gemini",
    "build",
    "dist",
    "tests",
    "samples",
}

SCANNED_EXTENSIONS = {
    ".py",
    ".js",
    ".html",
    ".css",
    ".json",
    ".yml",
    ".yaml",
    ".md",
    ".sh",
    ".bat",
    ".env",
    ".env.example",
}


def scan_repository(base_path: Path, allow_local_env: bool = False) -> list[dict]:
    all_findings = []
    for root, dirs, files in os.walk(base_path):
        # Prune ignored directories
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS and not any(part in IGNORED_DIRS for part in Path(root, d).parts)]

        for file_name in files:
            file_path = Path(root) / file_name
            ext = file_path.suffix.lower()

            # Ignore internal detector definition itself
            if file_name == "security_secrets.py":
                continue

            if file_name.lower().startswith(".env") and file_name != ".env.example":
                if allow_local_env:
                    continue
                all_findings.append({
                    "secret_type": "env_file",
                    "description": "Environment Configuration File",
                    "severity": "CRITICAL",
                    "file": str(file_path.relative_to(base_path)),
                    "line": 1,
                    "masked_value": "[ENVIRONMENT_FILE_CONTAINER]",
                    "line_snippet": file_name,
                })
                continue

            if ext not in SCANNED_EXTENSIONS and not file_name.startswith(".env"):
                continue

            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            findings = detect_secrets(content, filename=str(file_path.relative_to(base_path)))
            # If in .env.example, only flag real keys, not placeholders like "your_api_key_here"
            if file_name == ".env.example":
                findings = [
                    f for f in findings
                    if not any(placeholder in f.get("line_snippet", "").lower() for placeholder in ("your_", "test", "example", "<", "placeholder"))
                ]
            all_findings.extend(findings)

    return all_findings


def main() -> int:
    parser = argparse.ArgumentParser(description="AST Studio Release Packaging Secret Scanner")
    parser.add_argument("--path", type=str, default=str(root_dir), help="Directory to scan")
    parser.add_argument(
        "--allow-local-env",
        action="store_true",
        help="Ignore local untracked .env file when checking development workspace",
    )
    args = parser.parse_args()

    target_dir = Path(args.path).resolve()
    print(f"[*] Running Release Packaging Secret Scanner on {target_dir}...")
    findings = scan_repository(target_dir, allow_local_env=args.allow_local_env)
    if not findings:
        print("[+] Secret Scan Passed: No unmasked secrets or environment file leaks found.")
        return 0

    print(f"[!] FAILED: {len(findings)} potential secret(s) or leak(s) identified:\n")
    for f in findings:
        print(f"  - [{f['severity']}] {f['description']} in {f['file']}:{f['line']}")
        print(f"    Snippet: {f.get('line_snippet', '')}")
    return 1

    print(f"[!] FAILED: {len(findings)} potential secret(s) or leak(s) identified:\n")
    for f in findings:
        print(f"  - [{f['severity']}] {f['description']} in {f['file']}:{f['line']}")
        print(f"    Snippet: {f.get('line_snippet', '')}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
