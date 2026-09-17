"""Operator commands for schema setup, workers, retention, and restore drills."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import psycopg
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .team_store import TeamConfig, TeamStore, verify_team_export
from .team_worker import run_one


BACKUP_AAD = b"osint-toolbox-team-backup/1"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _subprocess_env(database_url: str) -> dict[str, str]:
    # Do not send the object key or IdP settings to pg_dump/pg_restore.
    return {"PATH": os.environ.get("PATH", ""), "PGDATABASE": database_url}


def _crypt_file(source: Path, destination: Path, key: bytes, decrypt: bool) -> None:
    if decrypt:
        with source.open("rb") as input_file:
            if input_file.read(4) != b"OTB1":
                raise ValueError("Unknown encrypted backup format")
            nonce = input_file.read(12)
            input_file.seek(-16, os.SEEK_END)
            tag = input_file.read(16)
            remaining = source.stat().st_size - 32
            input_file.seek(16)
            cryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
            cryptor.authenticate_additional_data(BACKUP_AAD)
            with destination.open("wb") as output:
                while remaining:
                    chunk = input_file.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise ValueError("Truncated encrypted backup")
                    output.write(cryptor.update(chunk))
                    remaining -= len(chunk)
                output.write(cryptor.finalize())
    else:
        nonce = os.urandom(12)
        cryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
        cryptor.authenticate_additional_data(BACKUP_AAD)
        with source.open("rb") as input_file, destination.open("xb") as output:
            output.write(b"OTB1" + nonce)
            for chunk in iter(lambda: input_file.read(1024 * 1024), b""):
                output.write(cryptor.update(chunk))
            output.write(cryptor.finalize())
            output.write(cryptor.tag)


def backup(store: TeamStore, output: Path) -> Path:
    """Encrypted pg_dump + ciphertext object snapshot; pause API/worker first."""
    if output.exists():
        raise ValueError("Backup destination already exists")
    ok, issues = store.verify_audit()
    if not ok:
        raise ValueError("Audit chain failed before backup: " + "; ".join(issues))
    pg_dump = shutil.which("pg_dump")
    if not pg_dump:
        raise ValueError("pg_dump is required for team backups")
    with tempfile.TemporaryDirectory(prefix="osint-team-backup-") as directory:
        root = Path(directory)
        dump = root / "database.dump"
        result = subprocess.run([pg_dump, "--format=custom", "--file", str(dump)],
                                env=_subprocess_env(store.config.database_url), capture_output=True, text=True)
        if result.returncode:
            raise ValueError("pg_dump failed: " + result.stderr[-1000:])
        files = {"database.dump": dump}
        for path in store.objects.root.rglob("*.enc"):
            if path.is_symlink():
                raise ValueError("Backup refuses symlinked objects")
            relative = path.relative_to(store.objects.root)
            if len(relative.parts) != 2:
                raise ValueError("Unexpected object storage path")
            files[f"objects/{relative.as_posix()}"] = path
        manifest = {"format": "osint-toolbox.team-backup/1",
                    "files": [{"path": name, "size_bytes": path.stat().st_size, "sha256": _sha256(path)}
                              for name, path in sorted(files.items())]}
        archive_path = root / "backup.zip"
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("MANIFEST.json", json.dumps(manifest, sort_keys=True))
            for name, path in sorted(files.items()):
                archive.write(path, arcname=name)
        output.parent.mkdir(parents=True, exist_ok=True)
        try:
            _crypt_file(archive_path, output, store.config.object_key, False)
        except BaseException:
            output.unlink(missing_ok=True)
            raise
    return output


def _verified_backup(backup_file: Path, key: bytes, directory: Path) -> tuple[Path, list[Path]]:
    archive_path = directory / "decrypted.zip"
    _crypt_file(backup_file, archive_path, key, True)
    with zipfile.ZipFile(archive_path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ValueError("Duplicate backup members")
        manifest = json.loads(archive.read("MANIFEST.json"))
        if manifest.get("format") != "osint-toolbox.team-backup/1":
            raise ValueError("Unknown backup manifest")
        expected = {row["path"]: row for row in manifest["files"]}
        if set(expected) | {"MANIFEST.json"} != set(names):
            raise ValueError("Backup manifest file list mismatch")
        extracted: list[Path] = []
        for name, row in expected.items():
            parts = Path(name).parts
            if name.startswith("/") or ".." in parts or (name != "database.dump" and
                (len(parts) != 3 or parts[0] != "objects")):
                raise ValueError("Unsafe backup member path")
            target = directory / name
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(name) as source, target.open("wb") as destination:
                shutil.copyfileobj(source, destination)
            if target.stat().st_size != row["size_bytes"] or _sha256(target) != row["sha256"]:
                raise ValueError(f"Backup checksum mismatch: {name}")
            extracted.append(target)
    return directory / "database.dump", extracted


def verify_backup(backup_file: Path, key: bytes) -> None:
    with tempfile.TemporaryDirectory(prefix="osint-team-verify-") as directory:
        _verified_backup(backup_file, key, Path(directory))


def restore_drill(store: TeamStore, backup_file: Path, target_database_url: str,
                  target_object_root: Path) -> dict[str, int]:
    """Restore only into an empty, separate database and object directory."""
    if target_database_url == store.config.database_url:
        raise ValueError("Restore drill target must not be the source database")
    if target_object_root.exists() and any(target_object_root.iterdir()):
        raise ValueError("Restore drill object directory must be empty")
    with psycopg.connect(target_database_url) as conn:
        existing = conn.execute("SELECT count(*) FROM pg_tables WHERE schemaname=current_schema()").fetchone()[0]
        if existing:
            raise ValueError("Restore drill database schema must be empty")
    pg_restore = shutil.which("pg_restore")
    if not pg_restore:
        raise ValueError("pg_restore is required for restore drills")
    with tempfile.TemporaryDirectory(prefix="osint-team-drill-") as directory:
        dump, extracted = _verified_backup(backup_file, store.config.object_key, Path(directory))
        result = subprocess.run([pg_restore, "--no-owner", "--no-privileges", "--exit-on-error", str(dump)],
                                env=_subprocess_env(target_database_url), capture_output=True, text=True)
        if result.returncode:
            raise ValueError("pg_restore failed: " + result.stderr[-1000:])
        target_object_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        for path in extracted:
            if path == dump:
                continue
            destination = target_object_root / path.relative_to(Path(directory) / "objects")
            destination.parent.mkdir(mode=0o700, exist_ok=True)
            shutil.copy2(path, destination)
    restored = TeamStore(replace(store.config, database_url=target_database_url, object_root=target_object_root))
    ok, issues = restored.verify_audit()
    if not ok:
        raise ValueError("Restored audit chain failed: " + "; ".join(issues))
    checked = 0
    with restored.connect() as conn:
        objects = conn.execute("SELECT * FROM team_objects WHERE deleted_at IS NULL ORDER BY object_id").fetchall()
        cases = conn.execute("SELECT case_id,owner_sub FROM team_cases WHERE deleted_at IS NULL").fetchall()
    for row in objects:
        restored.objects.read(row["case_id"], row["object_id"], row["sha256"])
        checked += 1
    for row in cases:
        export = restored.export_case(row["case_id"], row["owner_sub"])
        valid, problems = verify_team_export(export)
        if not valid:
            raise ValueError("Restored case export failed: " + "; ".join(problems))
    return {"cases": len(cases), "objects": checked}


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="osint-team")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init-db")
    sub.add_parser("verify-audit")
    sub.add_parser("worker-once")
    sub.add_parser("retention-once")
    make = sub.add_parser("backup")
    make.add_argument("output", type=Path)
    verify = sub.add_parser("verify-backup")
    verify.add_argument("backup_file", type=Path)
    drill = sub.add_parser("restore-drill")
    drill.add_argument("backup_file", type=Path)
    drill.add_argument("--target-database-url", required=True)
    drill.add_argument("--target-object-root", required=True, type=Path)
    args = parser.parse_args(argv)
    store = TeamStore(TeamConfig.from_env())
    if args.command == "init-db":
        store.init_schema()
        print("Team schema ready")
    elif args.command == "verify-audit":
        ok, issues = store.verify_audit()
        if not ok:
            raise SystemExit("; ".join(issues))
        print("Team audit chain valid")
    elif args.command == "worker-once":
        print(run_one(store) or "No approved job")
    elif args.command == "retention-once":
        print(json.dumps({"deleted_case_ids": store.retention_sweep(store.config.worker_subject)}))
    elif args.command == "backup":
        print(backup(store, args.output))
    elif args.command == "verify-backup":
        verify_backup(args.backup_file, store.config.object_key)
        print("Encrypted backup verified")
    elif args.command == "restore-drill":
        print(json.dumps(restore_drill(store, args.backup_file, args.target_database_url,
                                       args.target_object_root)))


if __name__ == "__main__":
    main()
