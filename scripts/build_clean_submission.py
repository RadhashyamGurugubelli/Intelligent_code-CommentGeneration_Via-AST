"""Academic submission packager that packages strictly from git ls-files.

Ensures zero untracked, ignored, temporary, or sensitive files are packaged.
Forbids .env, .venv, instance/, backups/, dist/, .coverage, __pycache__, etc.
Produces dist/AST_Studio_Submission.zip ready for evaluation.
"""

from __future__ import annotations

import os
import subprocess
import sys
import zipfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from backend.security_secrets import detect_secrets

FORBIDDEN_EXACT_NAMES = {
    ".env",
    ".env.local",
    ".env.production",
    ".env.staging",
    ".coverage",
}

FORBIDDEN_DIR_PARTS = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "venv",
    "env",
    "instance",
    "backups",
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
}


def get_git_tracked_files(root: Path) -> list[str]:
    """Retrieve list of tracked files using `git ls-files`."""
    try:
        proc = subprocess.run(
            ["git", "ls-files"],
            cwd=str(root),
            capture_output=True,
            text=True,
            check=True,
        )
        files = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        return files
    except Exception as exc:
        raise RuntimeError(f"Failed to run 'git ls-files': {exc}") from exc


def is_forbidden(rel_path_str: str) -> bool:
    """Check if a relative file path matches forbidden names, dirs, or extensions."""
    path = Path(rel_path_str)
    # Check exact filename (allow .env.example)
    if path.name == ".env.example":
        return False
    if path.name in FORBIDDEN_EXACT_NAMES or path.name.startswith(".env"):
        return True
    if path.name.startswith(".coverage"):
        return True
    # Check extension
    if path.suffix.lower() in FORBIDDEN_EXTENSIONS:
        return True
    # Check directory parts
    for part in path.parts[:-1]:
        if part in FORBIDDEN_DIR_PARTS or part == ".env" or part.startswith(".venv"):
            return True
    return False


def build_clean_submission(output_zip: Path | None = None) -> Path:
    """Build a clean submission ZIP strictly from git-tracked files."""
    dist_dir = PROJECT_ROOT / "dist"
    dist_dir.mkdir(parents=True, exist_ok=True)

    if output_zip is None:
        output_zip = dist_dir / "AST_Studio_Submission.zip"

    print("=" * 60)
    print("AST Studio · Clean Submission Packager (git ls-files)")
    print("=" * 60)

    tracked_files = get_git_tracked_files(PROJECT_ROOT)
    print(f"Discovered {len(tracked_files)} tracked files via git ls-files.")

    files_to_pack = []
    for rel_path in tracked_files:
        if is_forbidden(rel_path):
            print(f" [EXCLUDE FORBIDDEN] {rel_path}")
            continue
        full_path = PROJECT_ROOT / rel_path
        if not full_path.is_file():
            print(f" [SKIP MISSING] {rel_path}")
            continue
        files_to_pack.append((full_path, rel_path))

    print(f"Selected {len(files_to_pack)} verified files to bundle.")

    # Scan for secrets in candidate files (excluding deliberate test vectors and sample examples)
    print("\nScanning selected files for potential secret leaks...")
    secret_findings = []
    for full_path, rel_path in files_to_pack:
        ext = full_path.suffix.lower()
        if ext in {".py", ".js", ".html", ".css", ".json", ".md", ".yml", ".yaml", ".example"}:
            try:
                content = full_path.read_text(encoding="utf-8", errors="ignore")
                findings = detect_secrets(content, filename=rel_path)
                if findings:
                    norm_p = rel_path.replace("\\", "/")
                    if norm_p.startswith("tests/") or norm_p.startswith("sample example/"):
                        # Deliberate test vectors / security benchmarks
                        pass
                    else:
                        secret_findings.extend(findings)
            except Exception as e:
                print(f" [WARN] Failed to read {rel_path}: {e}")

    if secret_findings:
        print("\n[CRITICAL ERROR] Leaked credentials detected in submission files!")
        for f in secret_findings:
            print(f" - {f.get('file')}: {f.get('secret_type')} (line {f.get('line')})")
        raise RuntimeError("Credential leak check failed.")

    print(" [PASSED] Secret scan clean.")

    # Write ZIP
    print(f"\nCompressing into {output_zip.name}...")
    if output_zip.exists():
        output_zip.unlink()

    with zipfile.ZipFile(output_zip, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zipf:
        for full_path, rel_path in files_to_pack:
            # Normalize path delimiters in zip to '/'
            norm_rel_path = rel_path.replace("\\", "/")
            zipf.write(full_path, norm_rel_path)

    # Verification of the resulting ZIP
    print("\nVerifying archive contents...")
    with zipfile.ZipFile(output_zip, "r") as zipf:
        names = zipf.namelist()
        for name in names:
            if is_forbidden(name):
                raise RuntimeError(f"Archive verification failed: found forbidden entry '{name}'")

    size_mb = output_zip.stat().st_size / (1024 * 1024)
    print(f" [PASSED] Archive verified: {len(names)} files, {size_mb:.2f} MB")
    print("=" * 60)
    print(f"Created: {output_zip}")
    print("=" * 60)
    return output_zip


if __name__ == "__main__":
    build_clean_submission()
