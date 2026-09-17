"""Privileged persistence primitives; user-facing operations live in TeamService.

Never expose SQL or object-store methods directly to clients.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import stat
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator
from uuid import uuid4

import psycopg
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from psycopg.rows import dict_row

from .util import canonical_json, fsync_directory

MAX_OBJECT_BYTES = 20 * 1024 * 1024
MAX_EXPORT_BYTES = 100 * 1024 * 1024
ROLE_RANK = {"viewer": 1, "analyst": 2, "reviewer": 3, "owner": 4, "admin": 5}
CASE_ID = re.compile(r"^TC-[0-9a-f]{32}$")
OBJECT_ID = re.compile(r"^OBJ-[0-9a-f]{32}$")
MAINTENANCE_LOCK = 809499102
SCHEMA_VERSION = 2


def _id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex}"


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _secret(name: str) -> str:
    """Support mounted secrets without putting their values in configuration files."""
    value, filename = os.environ.get(name), os.environ.get(name + "_FILE")
    if value and filename:
        raise ValueError(f"Set only {name} or {name}_FILE")
    if filename:
        path = Path(filename)
        if path.is_symlink() or path.stat().st_size > 16384:
            raise ValueError(f"Invalid {name}_FILE")
        value = path.read_text(encoding="utf-8").strip()
    return value or ""


@dataclass(frozen=True)
class TeamConfig:
    database_url: str = field(repr=False)
    object_root: Path
    object_key: bytes = field(repr=False)
    issuer: str
    audience: str
    jwks_url: str
    admin_subjects: frozenset[str]
    worker_subject: str
    backup_key: bytes | None = field(default=None, repr=False)
    max_case_bytes: int = 512 * 1024 * 1024
    max_case_objects: int = 1000
    max_pending_jobs: int = 100

    def __post_init__(self) -> None:
        if len(self.object_key) != 32 or (self.backup_key is not None and len(self.backup_key) != 32):
            raise ValueError("Encryption keys must contain 32 bytes")
        if not self.worker_subject or self.worker_subject in self.admin_subjects:
            raise ValueError("Worker identity must be separate from administrators")
        if min(self.max_case_bytes, self.max_case_objects, self.max_pending_jobs) < 1:
            raise ValueError("Team quotas must be positive")

    @classmethod
    def from_env(cls) -> TeamConfig:
        database_url, encoded_key = _secret("OSINT_TEAM_DATABASE_URL"), _secret("OSINT_TEAM_OBJECT_KEY")
        required = ("OSINT_TEAM_OBJECT_ROOT", "OSINT_TEAM_OIDC_ISSUER",
                    "OSINT_TEAM_OIDC_AUDIENCE", "OSINT_TEAM_OIDC_JWKS_URL")
        if not database_url or not encoded_key or any(not os.environ.get(name) for name in required):
            raise ValueError("Missing team configuration; see docs/TEAM_SERVICE.md")
        try:
            key = base64.b64decode(encoded_key, validate=True)
            backup = _secret("OSINT_TEAM_BACKUP_KEY")
            backup_key = base64.b64decode(backup, validate=True) if backup else None
        except ValueError:
            raise ValueError("Team encryption keys must be base64 encoded") from None
        return cls(database_url, Path(os.environ["OSINT_TEAM_OBJECT_ROOT"]), key,
                   os.environ["OSINT_TEAM_OIDC_ISSUER"], os.environ["OSINT_TEAM_OIDC_AUDIENCE"],
                   os.environ["OSINT_TEAM_OIDC_JWKS_URL"],
                   frozenset(x.strip() for x in os.environ.get("OSINT_TEAM_ADMIN_SUBS", "").split(",") if x.strip()),
                   os.environ.get("OSINT_TEAM_WORKER_SUB", "service:worker"), backup_key)


def _private_directory(path: Path) -> None:
    # Check before resolve(), including ancestors: resolving first hides symlinks.
    for component in [path, *path.parents]:
        if component.is_symlink() and str(component) not in {"/tmp", "/var"}:
            raise ValueError("Symlinked object directory is refused")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == "posix" and (path.stat().st_uid != os.getuid() or stat.S_IMODE(path.stat().st_mode) & 0o077):
        raise ValueError("Object directories must be service-owned and mode 0700")


class EncryptedObjects:
    def __init__(self, root: Path, key: bytes) -> None:
        if not root.is_absolute() or root == Path(root.anchor):
            raise ValueError("Object root must be a dedicated absolute directory")
        _private_directory(root)
        self.root = root.resolve()
        self.aead = AESGCM(key)

    def path(self, case_id: str, object_id: str) -> Path:
        if not CASE_ID.fullmatch(case_id) or not OBJECT_ID.fullmatch(object_id):
            raise ValueError("Invalid team case or object identifier")
        directory = self.root / case_id
        if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
            raise ValueError("Unsafe case object directory")
        path = directory / f"{object_id}.enc"
        if path.is_symlink():
            raise ValueError("Symlinked object is refused")
        return path

    def write(self, case_id: str, data: bytes) -> tuple[str, str]:
        if len(data) > MAX_OBJECT_BYTES:
            raise ValueError("Object exceeds the 20 MiB limit")
        object_id, digest, nonce = _id("OBJ"), hashlib.sha256(data).hexdigest(), os.urandom(12)
        encrypted = b"OST1" + nonce + self.aead.encrypt(nonce, data, f"{case_id}|{object_id}|{digest}".encode())
        path = self.path(case_id, object_id)
        _private_directory(path.parent)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(encrypted)
                handle.flush()
                os.fsync(handle.fileno())
            fsync_directory(path.parent)
        except BaseException:
            path.unlink(missing_ok=True)
            raise
        return object_id, digest

    def read(self, case_id: str, object_id: str, expected_sha256: str) -> bytes:
        path = self.path(case_id, object_id)
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as handle:
            blob = handle.read(MAX_OBJECT_BYTES + 33)
        if not 32 <= len(blob) <= MAX_OBJECT_BYTES + 32 or blob[:4] != b"OST1":
            raise ValueError("Invalid encrypted object format or size")
        try:
            data = self.aead.decrypt(blob[4:16], blob[16:], f"{case_id}|{object_id}|{expected_sha256}".encode())
        except InvalidTag:
            raise ValueError("Object authentication failed") from None
        if hashlib.sha256(data).hexdigest() != expected_sha256:
            raise ValueError("Object plaintext checksum mismatch")
        return data

    def delete(self, case_id: str, object_id: str) -> None:
        path = self.path(case_id, object_id)
        path.unlink(missing_ok=True)
        fsync_directory(path.parent)


@dataclass
class Transaction:
    connection: psycopg.Connection
    created_objects: list[tuple[str, str]] = field(default_factory=list)

    def execute(self, *args: Any, **kwargs: Any) -> Any:
        return self.connection.execute(*args, **kwargs)


class TeamStore:
    def __init__(self, config: TeamConfig) -> None:
        self.config = config
        self.objects = EncryptedObjects(config.object_root, config.object_key)

    def connect(self) -> psycopg.Connection:
        conn = psycopg.connect(self.config.database_url, row_factory=dict_row, connect_timeout=5)
        conn.execute("SET TIME ZONE 'UTC'")
        conn.execute("SET statement_timeout='30s'")
        conn.execute("SET lock_timeout='10s'")
        conn.commit()
        return conn

    @contextmanager
    def transaction(self, case_id: str | None = None) -> Iterator[Transaction]:
        created: list[tuple[str, str]] = []
        try:
            with self.connect() as conn:
                conn.execute("SELECT pg_advisory_xact_lock_shared(%s)", (MAINTENANCE_LOCK,))
                if case_id is not None:
                    if not CASE_ID.fullmatch(case_id):
                        raise LookupError("Case not found")
                    conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 17))", (case_id,))
                yield Transaction(conn, created)
        except BaseException:
            # Process death can still leave an orphan; verify-storage detects it.
            for case, object_id in created:
                self.objects.delete(case, object_id)
            raise

    @contextmanager
    def maintenance(self) -> Iterator[psycopg.Connection]:
        """Freeze application transactions during the database/object snapshot."""
        with self.connect() as conn:
            conn.execute("SET statement_timeout='30min'")
            conn.execute("SET lock_timeout='60s'")
            conn.execute("SELECT pg_advisory_xact_lock(%s)", (MAINTENANCE_LOCK,))
            yield conn

    def init_schema(self) -> None:
        with self.maintenance() as conn:
            conn.execute(Path(__file__).with_name("team_schema.sql").read_text(encoding="utf-8"), prepare=False)

    def audit(self, conn: Any, case_id: str | None, actor: str, action: str,
              resource_id: str = "", details: dict[str, Any] | None = None) -> None:
        if not actor:
            raise ValueError("Audit actor is required")
        conn.execute("SELECT pg_advisory_xact_lock(809499101)")
        last = conn.execute("SELECT event_sha256 FROM team_audit ORDER BY event_id DESC LIMIT 1").fetchone()
        previous = last["event_sha256"] if last else "0" * 64
        payload = {"case_id": case_id, "actor_sub": actor, "action": action, "resource_id": resource_id,
                   "details": details or {}, "created_at": _utc(), "previous_sha256": previous}
        digest = hashlib.sha256(canonical_json(payload).encode()).hexdigest()
        conn.execute("""INSERT INTO team_audit
            (case_id,actor_sub,action,resource_id,details,created_at,previous_sha256,event_sha256)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
            (case_id, actor, action, resource_id, json.dumps(details or {}), payload["created_at"], previous, digest))

    def verify_audit(self) -> tuple[bool, list[str]]:
        issues, previous = [], "0" * 64
        with self.connect() as conn:
            with conn.cursor(name="audit_verify") as cursor:
                cursor.execute("SELECT * FROM team_audit ORDER BY event_id")
                for row in cursor:
                    payload = {k: row[k] for k in ("case_id", "actor_sub", "action", "resource_id", "details",
                                                   "created_at", "previous_sha256")}
                    if row["previous_sha256"] != previous or row["event_sha256"] != hashlib.sha256(canonical_json(payload).encode()).hexdigest():
                        issues.append(f"Audit chain mismatch at event {row['event_id']}")
                    previous = row["event_sha256"]
        return not issues, issues

    def verify_storage(self) -> tuple[bool, list[str]]:
        issues, expected = [], set()
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM team_objects WHERE deleted_at IS NULL").fetchall()
            tombstones = conn.execute("SELECT object_id,case_id FROM team_objects WHERE deleted_at IS NOT NULL").fetchall()
        for row in rows:
            expected.add(self.objects.path(row["case_id"], row["object_id"]))
            try:
                data = self.objects.read(row["case_id"], row["object_id"], row["sha256"])
                if len(data) != row["size_bytes"]:
                    raise ValueError("Object size mismatch")
            except (OSError, ValueError):
                issues.append(f"Invalid or missing object {row['object_id']}")
        expected.update(self.objects.path(r["case_id"], r["object_id"]) for r in tombstones)
        for directory in self.objects.root.iterdir():
            if directory.is_symlink() or not directory.is_dir():
                issues.append("Unexpected entry in object root")
                continue
            for path in directory.iterdir():
                if path.is_symlink() or path not in expected:
                    issues.append(f"Unregistered or unsafe object: {directory.name}/{path.name}")
        return not issues, issues


def verify_team_export(content: bytes) -> tuple[bool, list[str]]:
    issues: list[str] = []
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            entries = archive.infolist()
            names = [entry.filename for entry in entries]
            if len(entries) > 1002 or sum(e.file_size for e in entries) > MAX_EXPORT_BYTES + 4 * 1024 * 1024:
                raise ValueError("Export exceeds verification limits")
            if len(names) != len(set(names)):
                raise ValueError("Duplicate archive members")
            manifest = json.loads(archive.read("MANIFEST.json"))
            if manifest.get("format") != "osint-toolbox.team-export/1":
                raise ValueError("Unknown export format")
            expected = {row["path"]: row for row in manifest["files"]}
            if len(expected) != len(manifest["files"]) or set(names) != set(expected) | {"MANIFEST.json"}:
                raise ValueError("Manifest file list mismatch")
            for name, row in expected.items():
                if name != "case.json" and not re.fullmatch(r"objects/OBJ-[0-9a-f]{32}", name):
                    raise ValueError("Unsafe export path")
                data = archive.read(name)
                if len(data) != row["size_bytes"] or hashlib.sha256(data).hexdigest() != row["sha256"]:
                    issues.append(f"Export checksum mismatch: {name}")
    except (OSError, KeyError, ValueError, TypeError, AttributeError, RuntimeError, zipfile.BadZipFile):
        issues.append("Export could not be verified")
    return not issues, issues
