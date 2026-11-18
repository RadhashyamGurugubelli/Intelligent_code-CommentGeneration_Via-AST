"""Repeatable Academic Submission Packager for AST Studio.

Uses an explicit allow-list of source code, configuration examples, assets, and tests.
Excludes all .env files, private keys, local SQLite databases, .git, __pycache__,
and development artifacts.
Produces a verified, clean ZIP archive in dist/ ready for academic evaluation.
"""

from __future__ import annotations

import os
import shutil
import sys
import zipfile
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from backend.security_secrets import detect_secrets


ALLOWLIST_DIRS = [
    "backend",
    "frontend",
    "tests",
    "scripts",
]

ALLOWLIST_FILES = [
    "run.py",
    "requirements.txt",
    "pyproject.toml",
    "README.md",
    ".env.example",
    ".gitignore",
    "gunicorn_conf.py",
]

FORBIDDEN_DIR_NAMES = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".venv",
    "venv",
    "env",
    "backups",
    "uploads",
    "workspaces",
    "temp",
    "dist",
    "build",
    ".gemini",
}

FORBIDDEN_EXTENSIONS = {
    ".pyc",
    ".pyo",
    ".pyd",
    ".sqlite",
    ".sqlite3",
    ".db",
    ".coverage",
}

FORBIDDEN_EXACT_FILES = {
    ".env",
    ".env.local",
    ".env.production",
    ".env.staging",
    "ast_studio.db",
    "ast_studio_dev.db",
    "ast_studio_prod.db",
    "ast_studio_test.db",
}


def create_clean_submission_package(output_zip: Path | None = None) -> Path:
    """Bundle only allowed, sanitized project files into a submission ZIP archive."""
    dist_dir = PROJECT_ROOT / "dist"
    dist_dir.mkdir(parents=True, exist_ok=True)

    if output_zip is None:
        output_zip = dist_dir / "AST_Studio_Academic_Submission.zip"

    # Temporary staging directory
    staging_dir = dist_dir / "_staging_package"
    if staging_dir.exists():
        shutil.rmtree(staging_dir)
    staging_dir.mkdir(parents=True, exist_ok=True)

    copied_files_count = 0
    total_bytes = 0

    print("=" * 60)
    print("AST Studio · Academic Submission Packager")
    print("=" * 60)

    # 1. Copy Allowlisted Root Files
    for file_name in ALLOWLIST_FILES:
        src = PROJECT_ROOT / file_name
        if src.is_file():
            dest = staging_dir / file_name
            shutil.copy2(src, dest)
            copied_files_count += 1
            total_bytes += src.stat().st_size
            print(f" [COPY FILE] {file_name}")

    # 2. Copy Allowlisted Directories with Strict Filtering
    for dir_name in ALLOWLIST_DIRS:
        src_dir = PROJECT_ROOT / dir_name
        if not src_dir.is_dir():
            continue

        for root, dirs, files in os.walk(src_dir):
            # Prune forbidden directories in-place
            dirs[:] = [
                d for d in dirs
                if d not in FORBIDDEN_DIR_NAMES
                and not d.endswith(".egg-info")
            ]

            rel_root = Path(root).relative_to(PROJECT_ROOT)
            dest_dir = staging_dir / rel_root
            dest_dir.mkdir(parents=True, exist_ok=True)

            for file_name in files:
                file_path = Path(root) / file_name
                ext = file_path.suffix.lower()

                # Filter out forbidden files & extensions
                if file_name in FORBIDDEN_EXACT_FILES:
                    print(f" [EXCLUDE FORBIDDEN FILE] {file_path}")
                    continue
                if ext in FORBIDDEN_EXTENSIONS:
                    continue
                if file_name.startswith(".coverage."):
                    continue

                dest_file = dest_dir / file_name
                shutil.copy2(file_path, dest_file)
                copied_files_count += 1
                total_bytes += file_path.stat().st_size

        print(f" [COPY DIR]  {dir_name}/")

    print("-" * 60)
    print(f"Staged {copied_files_count} clean files ({total_bytes / (1024 * 1024):.2f} MB)")

    # 3. Scan Staged Files for Secrets
    print("\nScanning staged submission package for leaked credentials...")
    secret_findings = []
    test_fixture_findings = []

    for root, _, files in os.walk(staging_dir):
        for file_name in files:
            file_path = Path(root) / file_name
            ext = file_path.suffix.lower()
            rel_path = file_path.relative_to(staging_dir)
            is_test_file = rel_path.parts and rel_path.parts[0] == "tests"

            if ext in {".py", ".js", ".html", ".css", ".json", ".md", ".yml", ".yaml", ".env.example"}:
                try:
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                    findings = detect_secrets(content, filename=str(rel_path))
                    if findings:
                        if is_test_file:
                            test_fixture_findings.extend(findings)
                        else:
                            secret_findings.extend(findings)
                except Exception as exc:
                    print(f"Warning: could not read {file_path}: {exc}")

    if test_fixture_findings:
        print(f" [INFO] Allowed {len(test_fixture_findings)} deliberate security test vectors/fixtures under tests/")

    if secret_findings:
        print("\n[CRITICAL ERROR] Leaked credentials detected in source/configuration files!")
        for f in secret_findings:
            print(f" - {f.get('file', 'unknown')}: {f.get('secret_type')} (line {f.get('line')}) | {f.get('line_snippet')}")
        shutil.rmtree(staging_dir)
        sys.exit(1)
    else:
        print(" [PASSED] Zero leaked credentials found in production codebase. Staged files are clean.")

    # 4. Generate Clean ZIP Archive
    print(f"\nCompressing into {output_zip.name}...")
    if output_zip.exists():
        output_zip.unlink()

    with zipfile.ZipFile(output_zip, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zipf:
        for root, _, files in os.walk(staging_dir):
            for file_name in files:
                abs_path = Path(root) / file_name
                arc_name = abs_path.relative_to(staging_dir)
                zipf.write(abs_path, arc_name)

    # Clean up staging directory
    shutil.rmtree(staging_dir)

    # 5. Verify ZIP Contents
    print("\nVerifying archive integrity and absence of forbidden artifacts...")
    with zipfile.ZipFile(output_zip, "r") as zipf:
        namelist = zipf.namelist()
        for name in namelist:
            # Integrity checks
            for forbidden in FORBIDDEN_EXACT_FILES:
                if name == forbidden or name.endswith("/" + forbidden):
                    raise RuntimeError(f"Archive verification failed: found forbidden file '{name}'")
            for forbidden_dir in FORBIDDEN_DIR_NAMES:
                if name.startswith(forbidden_dir + "/") or f"/{forbidden_dir}/" in name:
                    raise RuntimeError(f"Archive verification failed: found forbidden dir '{name}'")
            for ext in FORBIDDEN_EXTENSIONS:
                if name.endswith(ext):
                    raise RuntimeError(f"Archive verification failed: found forbidden ext '{name}'")

    zip_size_mb = output_zip.stat().st_size / (1024 * 1024)
    print(" [PASSED] Archive verification successful.")
    print("=" * 60)
    print("SUCCESS: Created Academic Submission Archive:")
    print(f"Location: {output_zip}")
    print(f"Archive Size: {zip_size_mb:.2f} MB")
    print(f"Files bundled: {len(namelist)}")
    print("=" * 60)
    return output_zip


if __name__ == "__main__":
    create_clean_submission_package()
