"""Offline operator commands, supervised worker and verifiable encrypted backups."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import zipfile
from dataclasses import replace
from pathlib import Path

import psycopg
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict

from .team_service import TeamService
from .team_store import MAINTENANCE_LOCK, TeamConfig, TeamStore, _private_directory, verify_team_export
from .team_worker import run_one
from .util import fsync_directory

BACKUP_AAD = b"osint-toolbox-team-backup/1"
MAX_BACKUP_BYTES = 10 * 1024 * 1024 * 1024


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _subprocess_env(database_url: str) -> dict[str, str]:
    """Parse URI or keyword conninfo; never mistake the entire DSN for a db name."""
    names = {"host": "PGHOST", "hostaddr": "PGHOSTADDR", "port": "PGPORT", "dbname": "PGDATABASE",
             "user": "PGUSER", "password": "PGPASSWORD", "passfile": "PGPASSFILE",
             "service": "PGSERVICE", "options": "PGOPTIONS", "sslmode": "PGSSLMODE",
             "sslcert": "PGSSLCERT", "sslkey": "PGSSLKEY", "sslrootcert": "PGSSLROOTCERT",
             "sslcrl": "PGSSLCRL", "sslcrldir": "PGSSLCRLDIR", "sslpassword": "PGSSLPASSWORD",
             "connect_timeout": "PGCONNECT_TIMEOUT", "application_name": "PGAPPNAME",
             "target_session_attrs": "PGTARGETSESSIONATTRS", "channel_binding": "PGCHANNELBINDING",
             "sslnegotiation": "PGSSLNEGOTIATION", "gssencmode": "PGGSSENCMODE",
             "require_auth": "PGREQUIREAUTH"}
    values = conninfo_to_dict(database_url)
    if set(values) - set(names):
        raise ValueError("Unsupported libpq backup option; use a supported explicit connection configuration")
    result = {"PATH": os.environ.get("PATH", os.defpath), "PGCONNECT_TIMEOUT": "5"}
    result.update({names[k]: v for k, v in values.items()})
    return result


def _run_postgres(command: list[str], database_url: str) -> None:
    try:
        result = subprocess.run(command, env=_subprocess_env(database_url), capture_output=True, timeout=900)
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError("PostgreSQL backup/restore command could not complete") from None
    if result.returncode:
        # stderr may contain passwords, conninfo, database names or server data.
        raise ValueError(f"{Path(command[0]).name} failed (exit {result.returncode}); check database connectivity and privileges")


def _crypt_file(source: Path, destination: Path, key: bytes, decrypt: bool) -> None:
    size = source.stat().st_size
    if size > MAX_BACKUP_BYTES or (decrypt and size < 32):
        raise ValueError("Invalid backup size")
    with source.open("rb") as input_file:
        if decrypt:
            if input_file.read(4) != b"OTB1":
                raise ValueError("Unknown encrypted backup format")
            nonce = input_file.read(12)
            input_file.seek(-16, os.SEEK_END)
            cryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, input_file.read(16))).decryptor()
            remaining = size - 32
            input_file.seek(16)
        else:
            nonce = os.urandom(12)
            cryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
            remaining = size
        cryptor.authenticate_additional_data(BACKUP_AAD)
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as output:
                if not decrypt:
                    output.write(b"OTB1" + nonce)
                while remaining:
                    chunk = input_file.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise ValueError("Truncated encrypted backup")
                    output.write(cryptor.update(chunk))
                    remaining -= len(chunk)
                output.write(cryptor.finalize())
                if not decrypt:
                    output.write(cryptor.tag)
                output.flush()
                os.fsync(output.fileno())
            fsync_directory(destination.parent)
        except BaseException:
            destination.unlink(missing_ok=True)
            raise


def backup(store: TeamStore, output: Path) -> Path:
    """Take a coordinated schema/object snapshot while application writes are frozen."""
    if output.exists() or output.is_symlink():
        raise ValueError("Backup destination already exists")
    pg_dump = shutil.which("pg_dump")
    if not pg_dump:
        raise ValueError("pg_dump is required")
    with store.maintenance() as conn, tempfile.TemporaryDirectory(prefix="osint-team-backup-") as directory:
        for verify in (store.verify_audit, store.verify_storage):
            valid, _ = verify()
            if not valid:
                raise ValueError("Integrity verification failed before backup")
        root = Path(directory)
        schema = conn.execute("SELECT current_schema() AS name").fetchone()["name"]
        if not schema or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", schema):
            raise ValueError("Backup requires a simple, dedicated application schema")
        dump = root / "database.dump"
        _run_postgres([pg_dump, "--no-password", "--format=custom", "--no-owner", "--no-acl",
                       "--schema=" + schema, "--file=" + str(dump)], store.config.database_url)
        files = {"database.dump": dump}
        rows = conn.execute("SELECT case_id,object_id FROM team_objects WHERE deleted_at IS NULL").fetchall()
        for row in rows:
            path = store.objects.path(row["case_id"], row["object_id"])
            files["objects/" + path.relative_to(store.objects.root).as_posix()] = path
        if sum(p.stat().st_size for p in files.values()) > MAX_BACKUP_BYTES:
            raise ValueError("Backup exceeds the supported 10 GiB snapshot limit")
        manifest = {"format": "osint-toolbox.team-backup/1", "schema": schema,
                    "files": [{"path": n, "size_bytes": p.stat().st_size, "sha256": _sha256(p)}
                              for n, p in sorted(files.items())]}
        archive_path = root / "backup.zip"
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("MANIFEST.json", json.dumps(manifest, sort_keys=True))
            for name, path in sorted(files.items()):
                archive.write(path, arcname=name)
        output.parent.mkdir(parents=True, exist_ok=True)
        _crypt_file(archive_path, output, store.config.backup_key or store.config.object_key, False)
    return output


def _verified_backup(backup_file: Path, key: bytes, directory: Path) -> tuple[Path, list[Path], str]:
    archive_path = directory / "decrypted.zip"
    _crypt_file(backup_file, archive_path, key, True)
    with zipfile.ZipFile(archive_path) as archive:
        entries = archive.infolist()
        names = [entry.filename for entry in entries]
        if (len(names) != len(set(names)) or len(names) > 100002
                or sum(e.file_size for e in entries) > MAX_BACKUP_BYTES):
            raise ValueError("Backup exceeds verification limits or contains duplicate members")
        if archive.getinfo("MANIFEST.json").file_size > 16 * 1024 * 1024:
            raise ValueError("Backup manifest too large")
        manifest = json.loads(archive.read("MANIFEST.json"))
        if manifest.get("format") != "osint-toolbox.team-backup/1":
            raise ValueError("Unknown backup manifest")
        schema = manifest.get("schema", "")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", schema):
            raise ValueError("Backup schema is missing or invalid")
        expected = {row["path"]: row for row in manifest["files"]}
        if (len(expected) != len(manifest["files"]) or "database.dump" not in expected
                or set(expected) | {"MANIFEST.json"} != set(names)):
            raise ValueError("Backup manifest file list mismatch")
        extracted = []
        for name, row in expected.items():
            if name != "database.dump" and not re.fullmatch(r"objects/TC-[0-9a-f]{32}/OBJ-[0-9a-f]{32}\.enc", name):
                raise ValueError("Unsafe backup member path")
            if archive.getinfo(name).file_size != row["size_bytes"]:
                raise ValueError("Backup size mismatch")
            target = directory / name
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with archive.open(name) as source, os.fdopen(descriptor, "wb") as destination:
                shutil.copyfileobj(source, destination, length=1024 * 1024)
            if _sha256(target) != row["sha256"]:
                raise ValueError("Backup checksum mismatch")
            extracted.append(target)
    return directory / "database.dump", extracted, schema


def verify_backup(backup_file: Path, key: bytes) -> None:
    with tempfile.TemporaryDirectory(prefix="osint-team-verify-") as directory:
        _verified_backup(backup_file, key, Path(directory))


def _database_identity(conn: psycopg.Connection) -> tuple:
    row = conn.execute("""SELECT current_database(), inet_server_addr()::text, inet_server_port(),
        pg_postmaster_start_time(), (SELECT oid FROM pg_database WHERE datname=current_database())""").fetchone()
    return tuple(row.values()) if isinstance(row, dict) else tuple(row)


def restore_drill(store: TeamStore, backup_file: Path, target_database_url: str,
                  target_object_root: Path) -> dict[str, int]:
    """Restore a trusted backup only into an empty, genuinely separate database."""
    target_root = target_object_root.absolute()
    source_root = store.objects.root
    resolved = target_root.resolve()
    if resolved == source_root or source_root in resolved.parents or resolved in source_root.parents:
        raise ValueError("Restore object directory must be separate from source storage")
    if target_root.exists() and any(target_root.iterdir()):
        raise ValueError("Restore object directory must be empty")
    pg_restore = shutil.which("pg_restore")
    if not pg_restore:
        raise ValueError("pg_restore is required")
    with store.connect() as source_conn, psycopg.connect(target_database_url) as target_conn:
        if _database_identity(source_conn) == _database_identity(target_conn):
            raise ValueError("Restore target must be a different database, not a different connection string")
        target_conn.execute("SET lock_timeout='10s'")
        target_conn.execute("SELECT pg_advisory_xact_lock(%s)", (MAINTENANCE_LOCK,))
        existing = target_conn.execute("""SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname!='information_schema'""").fetchone()[0]
        namespaces = target_conn.execute("""SELECT count(*) FROM pg_namespace
            WHERE nspname NOT LIKE 'pg_%' AND nspname NOT IN ('public','information_schema')""").fetchone()[0]
        functions = target_conn.execute("""SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
            WHERE n.nspname='public'""").fetchone()[0]
        if existing or namespaces or functions:
            raise ValueError("Restore target database must be empty")
        with tempfile.TemporaryDirectory(prefix="osint-team-drill-") as directory:
            root = Path(directory)
            dump, extracted, schema = _verified_backup(backup_file, store.config.backup_key or store.config.object_key, root)
            env = _subprocess_env(target_database_url)
            database = env.get("PGDATABASE") or target_conn.info.dbname
            _run_postgres([pg_restore, "--no-password", "--dbname=" + database, "--no-owner", "--no-privileges",
                           "--exit-on-error", "--single-transaction", str(dump)], target_database_url)
            _private_directory(target_root)
            for path in extracted:
                if path == dump:
                    continue
                destination = target_root / path.relative_to(root / "objects")
                _private_directory(destination.parent)
                descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with path.open("rb") as source, os.fdopen(descriptor, "wb") as output:
                    shutil.copyfileobj(source, output)
                    output.flush()
                    os.fsync(output.fileno())
                fsync_directory(destination.parent)
    # The dump preserves the source schema, regardless of the target connection's search_path.
    from psycopg.conninfo import make_conninfo
    restored_dsn = make_conninfo(target_database_url, options=f"-c search_path={schema}")
    restored = TeamStore(replace(store.config, database_url=restored_dsn, object_root=target_root))
    service = TeamService(restored)
    for verify in (restored.verify_audit, restored.verify_storage):
        if not verify()[0]:
            raise ValueError("Restored integrity verification failed")
    checked = 0
    with restored.connect() as conn:
        objects = conn.execute("SELECT * FROM team_objects WHERE deleted_at IS NULL ORDER BY object_id").fetchall()
        cases = conn.execute("SELECT case_id,owner_sub FROM team_cases WHERE deleted_at IS NULL").fetchall()
    for row in objects:
        restored.objects.read(row["case_id"], row["object_id"], row["sha256"])
        checked += 1
    for row in cases:
        if not verify_team_export(service.export_case(row["case_id"], row["owner_sub"]))[0]:
            raise ValueError("Restored case export failed")
    return {"cases": len(cases), "objects": checked}


def grant_runtime(store: TeamStore, role: str) -> None:
    """Run as schema owner; runtime cannot alter schema or mutate the audit log."""
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,62}", role):
        raise ValueError("Invalid runtime role")
    with store.maintenance() as conn:
        schema = conn.execute("SELECT current_schema() AS name").fetchone()["name"]
        who = conn.execute("SELECT rolname,rolsuper FROM pg_roles WHERE rolname=%s", (role,)).fetchone()
        owner = conn.execute("SELECT current_user AS name").fetchone()["name"]
        if not who or who["rolsuper"] or role == owner:
            raise ValueError("Runtime role must exist and must not be the migration owner or a superuser")
        conn.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(sql.Identifier(schema), sql.Identifier(role)))
        for permission, object_type in (("SELECT,INSERT,UPDATE,DELETE", "TABLES"), ("USAGE,SELECT", "SEQUENCES")):
            conn.execute(sql.SQL("GRANT " + permission + " ON ALL " + object_type + " IN SCHEMA {} TO {}")
                         .format(sql.Identifier(schema), sql.Identifier(role)))
        for table, permissions in (("team_audit", "UPDATE,DELETE,TRUNCATE"), ("team_schema_version", "INSERT,UPDATE,DELETE,TRUNCATE")):
            conn.execute(sql.SQL("REVOKE " + permissions + " ON {}.{} FROM {}")
                         .format(sql.Identifier(schema), sql.Identifier(table), sql.Identifier(role)))


def worker_loop(store: TeamStore, poll_seconds: float = 2.0) -> None:
    if not 0.1 <= poll_seconds <= 60:
        raise ValueError("poll-seconds must be 0.1–60")
    TeamService(store).ready()
    stop = threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: stop.set())
    while not stop.is_set():
        job_id = run_one(store)
        if job_id:
            print(json.dumps({"event": "worker.finished", "job_id": job_id}), flush=True)
        else:
            stop.wait(poll_seconds)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="osint-team")
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("init-db", "verify-audit", "verify-storage", "worker-once", "retention-once", "check"):
        sub.add_parser(command)
    worker = sub.add_parser("worker")
    worker.add_argument("--poll-seconds", type=float, default=2)
    grant = sub.add_parser("grant-runtime")
    grant.add_argument("--role", required=True)
    make = sub.add_parser("backup")
    make.add_argument("output", type=Path)
    verify = sub.add_parser("verify-backup")
    verify.add_argument("backup_file", type=Path)
    drill = sub.add_parser("restore-drill")
    drill.add_argument("backup_file", type=Path)
    drill.add_argument("--target-database-env", default="OSINT_TEAM_RESTORE_DATABASE_URL")
    drill.add_argument("--target-object-root", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        store = TeamStore(TeamConfig.from_env())
        service = TeamService(store)
        if args.command == "init-db":
            store.init_schema()
            print("Team schema ready")
        elif args.command in {"verify-audit", "verify-storage"}:
            verify = store.verify_audit if args.command == "verify-audit" else store.verify_storage
            with store.maintenance():
                ok, issues = verify()
            if not ok:
                raise ValueError("; ".join(issues))
            print("PASS")
        elif args.command == "check":
            print(json.dumps(service.ready()))
        elif args.command == "grant-runtime":
            grant_runtime(store, args.role)
            print("Runtime grants applied")
        elif args.command == "worker":
            worker_loop(store, args.poll_seconds)
        elif args.command == "worker-once":
            print(run_one(store) or "No approved job")
        elif args.command == "retention-once":
            print(json.dumps({"deleted_case_ids": service.retention_sweep(store.config.worker_subject)}))
        elif args.command == "backup":
            print(backup(store, args.output))
        elif args.command == "verify-backup":
            verify_backup(args.backup_file, store.config.backup_key or store.config.object_key)
            print("Encrypted backup verified")
        elif args.command == "restore-drill":
            from .team_store import _secret
            target = _secret(args.target_database_env)
            if not target:
                raise ValueError("Restore target database environment variable is missing")
            print(json.dumps(restore_drill(store, args.backup_file, target, args.target_object_root)))
    except Exception as exc:
        # No traceback/DSN/credential values in routine operator output.
        raise SystemExit(f"Team operation failed ({type(exc).__name__}); see the operator runbook") from None


if __name__ == "__main__":
    main()
