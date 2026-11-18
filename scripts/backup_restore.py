"""Production Backup, Integrity Verification, and Disaster Recovery Script.

Provides automated, compressed, checksummed backups and atomic restore drills
for AST Studio SQLite database files and project workspace repositories.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tarfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BACKUP_DIR = PROJECT_ROOT / "backups"
DEFAULT_INSTANCE_DIR = PROJECT_ROOT / "instance"


def compute_sha256(file_path: Path) -> str:
    """Compute the SHA-256 hash of a file."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def create_backup(
    source_dir: Path = DEFAULT_INSTANCE_DIR,
    backup_dir: Path = DEFAULT_BACKUP_DIR,
    tag: Optional[str] = None,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Create a gzip-compressed tarball backup with SHA-256 integrity digest."""
    if not source_dir.exists():
        raise FileNotFoundError(f"Source directory '{source_dir}' does not exist.")

    backup_dir.mkdir(parents=True, exist_ok=True)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    suffix = f"_{tag}" if tag else ""
    archive_name = f"ast_studio_backup_{timestamp}{suffix}.tar.gz"
    archive_path = backup_dir / archive_name
    checksum_path = backup_dir / f"{archive_name}.sha256"

    items_to_backup = [p for p in source_dir.glob("*") if p.is_file() or p.is_dir()]
    if dry_run:
        return {
            "status": "dry_run",
            "archive_path": str(archive_path),
            "items_count": len(items_to_backup),
            "files": [p.name for p in items_to_backup],
        }

    with tarfile.open(archive_path, "w:gz") as tar:
        for item in items_to_backup:
            tar.add(item, arcname=item.name)

    sha256_digest = compute_sha256(archive_path)
    with open(checksum_path, "w", encoding="utf-8") as f:
        f.write(f"{sha256_digest}  {archive_name}\n")

    return {
        "status": "success",
        "archive_path": str(archive_path),
        "checksum_path": str(checksum_path),
        "sha256": sha256_digest,
        "size_bytes": archive_path.stat().st_size,
        "items_count": len(items_to_backup),
    }


def verify_backup(archive_path: Path) -> Dict[str, Any]:
    """Verify archive integrity and SHA-256 checksum against accompanying .sha256 file."""
    if not archive_path.exists():
        raise FileNotFoundError(f"Archive '{archive_path}' does not exist.")

    checksum_path = archive_path.parent / f"{archive_path.name}.sha256"
    actual_hash = compute_sha256(archive_path)

    expected_hash = None
    checksum_valid = None
    if checksum_path.exists():
        line = checksum_path.read_text(encoding="utf-8").strip()
        expected_hash = line.split()[0]
        checksum_valid = actual_hash == expected_hash

    # Test tar archive readability
    tar_valid = True
    member_count = 0
    members = []
    try:
        with tarfile.open(archive_path, "r:gz") as tar:
            for member in tar.getmembers():
                member_count += 1
                members.append(member.name)
    except Exception as exc:
        tar_valid = False
        members.append(f"Tar error: {exc}")

    is_ok = tar_valid and (checksum_valid is True or checksum_valid is None)
    return {
        "valid": is_ok,
        "actual_sha256": actual_hash,
        "expected_sha256": expected_hash,
        "checksum_matches": checksum_valid,
        "tar_structure_valid": tar_valid,
        "member_count": member_count,
        "members": members,
    }


def restore_backup(
    archive_path: Path,
    target_dir: Path = DEFAULT_INSTANCE_DIR,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Safely restore a backup into the target directory with checksum check."""
    verification = verify_backup(archive_path)
    if not verification["valid"]:
        raise ValueError(f"Backup verification failed: {verification}")

    if dry_run:
        return {
            "status": "dry_run",
            "target_dir": str(target_dir),
            "members": verification["members"],
        }

    target_dir.mkdir(parents=True, exist_ok=True)

    # Perform safe extraction, guarding against zip-slip/path traversal
    with tarfile.open(archive_path, "r:gz") as tar:
        for member in tar.getmembers():
            resolved_path = (target_dir / member.name).resolve()
            if not resolved_path.is_relative_to(target_dir.resolve()):
                raise ValueError(f"Security error: path traversal detected in archive member {member.name}")
        tar.extractall(path=target_dir)

    return {
        "status": "restored",
        "target_dir": str(target_dir),
        "members_restored": verification["member_count"],
    }


def list_backups(backup_dir: Path = DEFAULT_BACKUP_DIR) -> List[Dict[str, Any]]:
    """List all available backups in the backup directory."""
    if not backup_dir.exists():
        return []
    archives = sorted(backup_dir.glob("*.tar.gz"), key=lambda p: p.stat().st_mtime, reverse=True)
    results = []
    for archive in archives:
        checksum_path = backup_dir / f"{archive.name}.sha256"
        results.append({
            "name": archive.name,
            "path": str(archive),
            "size_bytes": archive.stat().st_size,
            "created_at": archive.stat().st_mtime,
            "has_checksum": checksum_path.exists(),
        })
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="AST Studio Backup & Recovery Tool")
    parser.add_argument("--backup", action="store_true", help="Create a new backup")
    parser.add_argument("--restore", type=str, help="Restore from archive path")
    parser.add_argument("--verify", type=str, help="Verify an archive path")
    parser.add_argument("--list", action="store_true", help="List backups")
    parser.add_argument("--source", type=str, default=str(DEFAULT_INSTANCE_DIR), help="Source directory")
    parser.add_argument("--target", type=str, default=str(DEFAULT_INSTANCE_DIR), help="Target restore directory")
    parser.add_argument("--dir", type=str, default=str(DEFAULT_BACKUP_DIR), help="Backup directory")
    parser.add_argument("--tag", type=str, help="Optional backup tag")
    parser.add_argument("--dry-run", action="store_true", help="Perform a dry run without modifications")

    args = parser.parse_args()

    if args.backup:
        res = create_backup(Path(args.source), Path(args.dir), args.tag, args.dry_run)
        print(json.dumps(res, indent=2))
        return 0
    elif args.verify:
        res = verify_backup(Path(args.verify))
        print(json.dumps(res, indent=2))
        return 0 if res["valid"] else 1
    elif args.restore:
        res = restore_backup(Path(args.restore), Path(args.target), args.dry_run)
        print(json.dumps(res, indent=2))
        return 0
    elif args.list:
        res = list_backups(Path(args.dir))
        print(json.dumps(res, indent=2))
        return 0
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
