"""PostgreSQL team state and AES-GCM encrypted local object storage.

This module is an optional service layer; the single-user evidence CLI remains
usable without any team dependencies or configuration.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import zipfile
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import psycopg
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from psycopg.rows import dict_row

from .util import canonical_json


MAX_OBJECT_BYTES = 20 * 1024 * 1024
ROLE_RANK = {"viewer": 1, "analyst": 2, "reviewer": 3, "owner": 4, "admin": 5}
CASE_ID = re.compile(r"^TC-[0-9a-f]{32}$")
OBJECT_ID = re.compile(r"^OBJ-[0-9a-f]{32}$")


def _id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex}"


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class TeamConfig:
    database_url: str
    object_root: Path
    object_key: bytes
    issuer: str
    audience: str
    jwks_url: str
    admin_subjects: frozenset[str]
    worker_subject: str

    @classmethod
    def from_env(cls) -> "TeamConfig":
        required = ("OSINT_TEAM_DATABASE_URL", "OSINT_TEAM_OBJECT_ROOT", "OSINT_TEAM_OBJECT_KEY",
                    "OSINT_TEAM_OIDC_ISSUER", "OSINT_TEAM_OIDC_AUDIENCE", "OSINT_TEAM_OIDC_JWKS_URL")
        missing = [name for name in required if not os.environ.get(name)]
        if missing:
            raise ValueError("Missing team configuration: " + ", ".join(missing))
        try:
            key = base64.b64decode(os.environ["OSINT_TEAM_OBJECT_KEY"], validate=True)
        except ValueError as exc:
            raise ValueError("OSINT_TEAM_OBJECT_KEY must be base64-encoded") from exc
        if len(key) != 32:
            raise ValueError("OSINT_TEAM_OBJECT_KEY must decode to 32 bytes")
        return cls(
            os.environ["OSINT_TEAM_DATABASE_URL"], Path(os.environ["OSINT_TEAM_OBJECT_ROOT"]).resolve(), key,
            os.environ["OSINT_TEAM_OIDC_ISSUER"], os.environ["OSINT_TEAM_OIDC_AUDIENCE"],
            os.environ["OSINT_TEAM_OIDC_JWKS_URL"],
            frozenset(x.strip() for x in os.environ.get("OSINT_TEAM_ADMIN_SUBS", "").split(",") if x.strip()),
            os.environ.get("OSINT_TEAM_WORKER_SUB", "service:worker"),
        )


class EncryptedObjects:
    def __init__(self, root: Path, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("Object encryption requires a 256-bit key")
        self.root = root.resolve()
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.root.is_symlink():
            raise ValueError("Object root may not be a symlink")
        self.aead = AESGCM(key)

    def path(self, case_id: str, object_id: str) -> Path:
        if not CASE_ID.fullmatch(case_id) or not OBJECT_ID.fullmatch(object_id):
            raise ValueError("Invalid team case or object identifier")
        return self.root / case_id / f"{object_id}.enc"

    def write(self, case_id: str, data: bytes) -> tuple[str, str]:
        if len(data) > MAX_OBJECT_BYTES:
            raise ValueError("Object exceeds the 20 MiB limit")
        object_id = _id("OBJ")
        digest = hashlib.sha256(data).hexdigest()
        nonce = os.urandom(12)
        aad = f"{case_id}|{object_id}|{digest}".encode()
        encrypted = b"OST1" + nonce + self.aead.encrypt(nonce, data, aad)
        path = self.path(case_id, object_id)
        path.parent.mkdir(mode=0o700, exist_ok=True)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(encrypted)
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException:
            path.unlink(missing_ok=True)
            raise
        return object_id, digest

    def read(self, case_id: str, object_id: str, expected_sha256: str) -> bytes:
        path = self.path(case_id, object_id)
        if path.is_symlink():
            raise ValueError("Symlinked object is refused")
        blob = path.read_bytes()
        if len(blob) < 32 or blob[:4] != b"OST1":
            raise ValueError("Invalid encrypted object format")
        nonce = blob[4:16]
        data = self.aead.decrypt(nonce, blob[16:], f"{case_id}|{object_id}|{expected_sha256}".encode())
        if hashlib.sha256(data).hexdigest() != expected_sha256:
            raise ValueError("Object plaintext checksum mismatch")
        return data

    def delete(self, case_id: str, object_id: str) -> None:
        path = self.path(case_id, object_id)
        if path.is_symlink():
            raise ValueError("Symlinked object is refused")
        path.unlink(missing_ok=True)


class TeamStore:
    def __init__(self, config: TeamConfig) -> None:
        self.config = config
        self.objects = EncryptedObjects(config.object_root, config.object_key)

    def connect(self) -> psycopg.Connection:
        return psycopg.connect(self.config.database_url, row_factory=dict_row, connect_timeout=5)

    def init_schema(self) -> None:
        schema = Path(__file__).with_name("team_schema.sql").read_text(encoding="utf-8")
        with self.connect() as conn:
            conn.execute(schema, prepare=False)

    def audit(self, conn: psycopg.Connection, case_id: str | None, actor: str,
              action: str, resource_id: str = "", details: dict[str, Any] | None = None) -> None:
        if not actor:
            raise ValueError("Audit actor is required")
        conn.execute("SELECT pg_advisory_xact_lock(809499101)")
        last = conn.execute("SELECT event_sha256 FROM team_audit ORDER BY event_id DESC LIMIT 1").fetchone()
        previous = last["event_sha256"] if last else "0" * 64
        payload = {"case_id": case_id, "actor_sub": actor, "action": action,
                   "resource_id": resource_id, "details": details or {}, "created_at": _utc(),
                   "previous_sha256": previous}
        digest = hashlib.sha256(canonical_json(payload).encode()).hexdigest()
        conn.execute("""INSERT INTO team_audit
            (case_id,actor_sub,action,resource_id,details,created_at,previous_sha256,event_sha256)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
            (case_id, actor, action, resource_id, json.dumps(details or {}), payload["created_at"], previous, digest))

    def verify_audit(self) -> tuple[bool, list[str]]:
        issues: list[str] = []
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM team_audit ORDER BY event_id").fetchall()
        previous = "0" * 64
        for row in rows:
            payload = {key: row[key] for key in
                       ("case_id", "actor_sub", "action", "resource_id", "details", "created_at", "previous_sha256")}
            digest = hashlib.sha256(canonical_json(payload).encode()).hexdigest()
            if row["previous_sha256"] != previous or row["event_sha256"] != digest:
                issues.append(f"Audit chain mismatch at event {row['event_id']}")
            previous = row["event_sha256"]
        return not issues, issues

    def case(self, conn: psycopg.Connection, case_id: str) -> dict[str, Any]:
        if not CASE_ID.fullmatch(case_id):
            raise LookupError("Case not found")
        row = conn.execute("SELECT * FROM team_cases WHERE case_id=%s AND deleted_at IS NULL", (case_id,)).fetchone()
        if not row:
            raise LookupError("Case not found")
        return row

    def role(self, conn: psycopg.Connection, case_id: str, actor: str) -> str:
        self.case(conn, case_id)
        if actor in self.config.admin_subjects:
            return "admin"
        row = conn.execute("SELECT role FROM team_members WHERE case_id=%s AND subject=%s", (case_id, actor)).fetchone()
        if not row:
            raise PermissionError("Case access denied")
        return row["role"]

    def require(self, conn: psycopg.Connection, case_id: str, actor: str, minimum: str) -> str:
        role = self.role(conn, case_id, actor)
        if ROLE_RANK[role] < ROLE_RANK[minimum]:
            raise PermissionError("Case permission denied")
        return role

    def create_case(self, actor: str, fields: dict[str, Any]) -> dict[str, Any]:
        until = date.fromisoformat(fields["retention_until"])
        if until <= datetime.now(timezone.utc).date():
            raise ValueError("Retention date must be in the future")
        case_id = _id("TC")
        with self.connect() as conn:
            row = conn.execute("""INSERT INTO team_cases
                (case_id,title,purpose,authority,target_type,target,sensitivity,retention_until,owner_sub)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *""",
                (case_id, fields["title"], fields["purpose"], fields["authority"], fields["target_type"],
                 fields["target"], fields["sensitivity"], until, actor)).fetchone()
            conn.execute("INSERT INTO team_members (case_id,subject,role,granted_by) VALUES (%s,%s,'owner',%s)",
                         (case_id, actor, actor))
            self.audit(conn, case_id, actor, "case.created", case_id)
        return row

    def list_cases(self, actor: str) -> list[dict[str, Any]]:
        with self.connect() as conn:
            if actor in self.config.admin_subjects:
                return conn.execute("SELECT * FROM team_cases WHERE deleted_at IS NULL ORDER BY created_at DESC").fetchall()
            return conn.execute("""SELECT c.* FROM team_cases c JOIN team_members m USING(case_id)
                WHERE m.subject=%s AND c.deleted_at IS NULL ORDER BY c.created_at DESC""", (actor,)).fetchall()

    def grant(self, case_id: str, actor: str, subject: str, role: str) -> None:
        if role not in ROLE_RANK or role == "admin":
            raise ValueError("Invalid case role")
        with self.connect() as conn:
            self.require(conn, case_id, actor, "owner")
            if subject == self.case(conn, case_id)["owner_sub"] and role != "owner":
                raise ValueError("Original case owner cannot be downgraded")
            conn.execute("""INSERT INTO team_members (case_id,subject,role,granted_by)
                VALUES (%s,%s,%s,%s) ON CONFLICT(case_id,subject)
                DO UPDATE SET role=EXCLUDED.role,granted_by=EXCLUDED.granted_by,granted_at=now()""",
                (case_id, subject, role, actor))
            self.audit(conn, case_id, actor, "member.granted", subject, {"role": role})

    def _object_row(self, conn: psycopg.Connection, case_id: str, object_id: str) -> dict[str, Any]:
        row = conn.execute("""SELECT * FROM team_objects
            WHERE case_id=%s AND object_id=%s AND deleted_at IS NULL""", (case_id, object_id)).fetchone()
        if not row:
            raise LookupError("Object not found")
        return row

    def put_object(self, case_id: str, actor: str, data: bytes, filename: str,
                   content_type: str, kind: str = "artifact") -> dict[str, Any]:
        if kind not in {"artifact", "job-result", "report"}:
            raise ValueError("Invalid object kind")
        with self.connect() as conn:
            if kind == "artifact":
                self.require(conn, case_id, actor, "analyst")
            else:
                self.case(conn, case_id)
        object_id, digest = self.objects.write(case_id, data)
        try:
            with self.connect() as conn:
                row = conn.execute("""INSERT INTO team_objects
                    (object_id,case_id,kind,filename,content_type,sha256,size_bytes,created_by)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *""",
                    (object_id, case_id, kind, filename[:200], content_type[:100], digest, len(data), actor)).fetchone()
                self.audit(conn, case_id, actor, "object.created", object_id,
                           {"kind": kind, "sha256": digest, "size_bytes": len(data)})
        except BaseException:
            self.objects.delete(case_id, object_id)
            raise
        return row

    def read_object(self, case_id: str, object_id: str) -> tuple[dict[str, Any], bytes]:
        with self.connect() as conn:
            row = self._object_row(conn, case_id, object_id)
        return row, self.objects.read(case_id, object_id, row["sha256"])

    def add_annotation(self, case_id: str, actor: str, body: str) -> dict[str, Any]:
        with self.connect() as conn:
            self.require(conn, case_id, actor, "analyst")
            row = conn.execute("""INSERT INTO team_annotations (annotation_id,case_id,body,author_sub)
                VALUES (%s,%s,%s,%s) RETURNING *""", (_id("ANN"), case_id, body, actor)).fetchone()
            self.audit(conn, case_id, actor, "annotation.created", row["annotation_id"])
        return row

    def add_work(self, case_id: str, actor: str, title: str) -> dict[str, Any]:
        with self.connect() as conn:
            self.require(conn, case_id, actor, "analyst")
            row = conn.execute("""INSERT INTO team_work_items
                (work_id,case_id,title,status,created_by,updated_by)
                VALUES (%s,%s,%s,'open',%s,%s) RETURNING *""",
                (_id("WRK"), case_id, title, actor, actor)).fetchone()
            self.audit(conn, case_id, actor, "work.created", row["work_id"])
        return row

    def assign_work(self, case_id: str, work_id: str, actor: str, assignee: str, status: str) -> dict[str, Any]:
        if status not in {"open", "in-review", "resolved"}:
            raise ValueError("Invalid work status")
        with self.connect() as conn:
            self.require(conn, case_id, actor, "reviewer")
            self.role(conn, case_id, assignee)
            row = conn.execute("""UPDATE team_work_items SET assigned_to=%s,status=%s,
                updated_by=%s,updated_at=now() WHERE case_id=%s AND work_id=%s RETURNING *""",
                (assignee, status, actor, case_id, work_id)).fetchone()
            if not row:
                raise LookupError("Work item not found")
            self.audit(conn, case_id, actor, "work.assigned", work_id,
                       {"assignee": assignee, "status": status})
        return row

    def request_job(self, case_id: str, actor: str, kind: str, provider: str | None,
                    target: str | None, source_object_id: str | None,
                    options: dict[str, str]) -> dict[str, Any]:
        with self.connect() as conn:
            self.require(conn, case_id, actor, "analyst")
            if kind == "media":
                if not source_object_id:
                    raise ValueError("Media job requires source_object_id")
                self._object_row(conn, case_id, source_object_id)
            row = conn.execute("""INSERT INTO team_jobs
                (job_id,case_id,kind,provider,target,source_object_id,options,status,requested_by)
                VALUES (%s,%s,%s,%s,%s,%s,%s,'pending',%s) RETURNING *""",
                (_id("JOB"), case_id, kind, provider, target, source_object_id,
                 json.dumps(options), actor)).fetchone()
            self.audit(conn, case_id, actor, "job.requested", row["job_id"], {"kind": kind, "provider": provider})
        return row

    def review_job(self, case_id: str, job_id: str, actor: str, approve: bool, reason: str) -> dict[str, Any]:
        with self.connect() as conn:
            self.require(conn, case_id, actor, "reviewer")
            job = conn.execute("SELECT * FROM team_jobs WHERE case_id=%s AND job_id=%s FOR UPDATE",
                               (case_id, job_id)).fetchone()
            if not job or job["status"] != "pending":
                raise LookupError("Pending job not found")
            if actor == job["requested_by"]:
                raise PermissionError("Requester cannot review their own job")
            row = conn.execute("""UPDATE team_jobs SET status=%s,reviewed_by=%s,review_reason=%s,
                updated_at=now() WHERE job_id=%s RETURNING *""",
                ("approved" if approve else "rejected", actor, reason, job_id)).fetchone()
            self.audit(conn, case_id, actor, "job.approved" if approve else "job.rejected", job_id)
        return row

    def add_report(self, case_id: str, actor: str, markdown: str) -> dict[str, Any]:
        obj = self.put_object(case_id, actor, markdown.encode(), "report.md", "text/markdown", "report")
        with self.connect() as conn:
            self.require(conn, case_id, actor, "analyst")
            conn.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (case_id,))
            version = conn.execute("SELECT COALESCE(max(version),0)+1 AS next FROM team_reports WHERE case_id=%s",
                                   (case_id,)).fetchone()["next"]
            row = conn.execute("""INSERT INTO team_reports
                (report_id,case_id,version,object_id,status,created_by)
                VALUES (%s,%s,%s,%s,'draft',%s) RETURNING *""",
                (_id("RPT"), case_id, version, obj["object_id"], actor)).fetchone()
            self.audit(conn, case_id, actor, "report.version-created", row["report_id"], {"version": version})
        return row

    def review_report(self, case_id: str, report_id: str, actor: str,
                      approve: bool, reason: str) -> dict[str, Any]:
        with self.connect() as conn:
            self.require(conn, case_id, actor, "reviewer")
            report = conn.execute("SELECT * FROM team_reports WHERE case_id=%s AND report_id=%s FOR UPDATE",
                                  (case_id, report_id)).fetchone()
            if not report or report["status"] != "draft":
                raise LookupError("Draft report not found")
            if actor == report["created_by"]:
                raise PermissionError("Author cannot review their own report")
            row = conn.execute("""UPDATE team_reports SET status=%s,reviewed_by=%s,
                review_reason=%s,reviewed_at=now() WHERE report_id=%s RETURNING *""",
                ("approved" if approve else "rejected", actor, reason, report_id)).fetchone()
            self.audit(conn, case_id, actor, "report.approved" if approve else "report.rejected", report_id)
        return row

    def set_hold(self, case_id: str, actor: str, active: bool, reason: str, authority: str) -> dict[str, Any]:
        with self.connect() as conn:
            self.require(conn, case_id, actor, "owner")
            previous = self.case(conn, case_id)
            if previous["legal_hold"] == active:
                raise ValueError("Legal hold is already in the requested state")
            row = conn.execute("""UPDATE team_cases SET legal_hold=%s,hold_reason=%s,
                hold_authority=%s WHERE case_id=%s RETURNING *""",
                (active, reason, authority, case_id)).fetchone()
            self.audit(conn, case_id, actor, "hold.placed" if active else "hold.released", case_id,
                       {"reason": reason})
        return row

    def retention_sweep(self, actor: str) -> list[str]:
        """Idempotent deletion of expired, non-held case content and PII metadata."""
        deleted: list[str] = []
        with self.connect() as conn:
            cases = conn.execute("""SELECT case_id FROM team_cases WHERE deleted_at IS NULL
                AND legal_hold=false AND retention_until < CURRENT_DATE ORDER BY case_id""").fetchall()
        for item in cases:
            case_id = item["case_id"]
            with self.connect() as conn:
                conn.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (case_id,))
                current = self.case(conn, case_id)
                if current["legal_hold"] or current["retention_until"] >= datetime.now(timezone.utc).date():
                    continue
                rows = conn.execute("SELECT object_id FROM team_objects WHERE case_id=%s AND deleted_at IS NULL",
                                    (case_id,)).fetchall()
                for row in rows:
                    self.objects.delete(case_id, row["object_id"])
                    conn.execute("UPDATE team_objects SET deleted_at=now() WHERE object_id=%s", (row["object_id"],))
                conn.execute("""UPDATE team_cases SET title='[DELETED]',purpose='[DELETED]',
                    authority='[DELETED]',target='[DELETED]',hold_reason='',hold_authority='',
                    deleted_at=now() WHERE case_id=%s""", (case_id,))
                conn.execute("DELETE FROM team_annotations WHERE case_id=%s", (case_id,))
                conn.execute("UPDATE team_work_items SET title='[DELETED]' WHERE case_id=%s", (case_id,))
                conn.execute("UPDATE team_jobs SET target=NULL,options='{}'::jsonb,error='' WHERE case_id=%s", (case_id,))
                self.audit(conn, case_id, actor, "case.retention-deleted", case_id,
                           {"object_count": len(rows)})
                deleted.append(case_id)
        return deleted

    def export_case(self, case_id: str, actor: str) -> bytes:
        """Build a bounded, owner-only plaintext interchange ZIP with checksums."""
        with self.connect() as conn:
            self.require(conn, case_id, actor, "owner")
            case = self.case(conn, case_id)
            objects = conn.execute("""SELECT * FROM team_objects WHERE case_id=%s
                AND deleted_at IS NULL ORDER BY object_id""", (case_id,)).fetchall()
            reports = conn.execute("SELECT * FROM team_reports WHERE case_id=%s ORDER BY version",
                                   (case_id,)).fetchall()
            annotations = conn.execute("SELECT * FROM team_annotations WHERE case_id=%s ORDER BY created_at",
                                       (case_id,)).fetchall()
        if len(objects) > 1000 or sum(row["size_bytes"] for row in objects) > 100 * 1024 * 1024:
            raise ValueError("Case export exceeds the 100 MiB/1,000-object safety limit")
        metadata = {"case": case, "objects": objects, "reports": reports, "annotations": annotations}
        files: dict[str, bytes] = {"case.json": json.dumps(metadata, default=str, sort_keys=True).encode()}
        for row in objects:
            files[f"objects/{row['object_id']}"] = self.objects.read(case_id, row["object_id"], row["sha256"])
        manifest = {"format": "osint-toolbox.team-export/1", "case_id": case_id,
                    "files": [{"path": name, "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)}
                              for name, data in sorted(files.items())]}
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("MANIFEST.json", json.dumps(manifest, sort_keys=True))
            for name, data in sorted(files.items()):
                archive.writestr(name, data)
        with self.connect() as conn:
            self.audit(conn, case_id, actor, "case.exported", case_id,
                       {"sha256": hashlib.sha256(output.getvalue()).hexdigest()})
        return output.getvalue()


def verify_team_export(content: bytes) -> tuple[bool, list[str]]:
    issues: list[str] = []
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            names = archive.namelist()
            if len(names) != len(set(names)):
                issues.append("Duplicate archive members")
            manifest = json.loads(archive.read("MANIFEST.json"))
            if manifest.get("format") != "osint-toolbox.team-export/1":
                issues.append("Unknown export format")
            expected = {row["path"]: row for row in manifest["files"]}
            if set(names) != set(expected) | {"MANIFEST.json"}:
                issues.append("Manifest file list mismatch")
            for name, row in expected.items():
                if name.startswith("/") or ".." in Path(name).parts or name not in names:
                    issues.append(f"Unsafe or missing export path: {name}")
                    continue
                data = archive.read(name)
                if len(data) != row["size_bytes"] or hashlib.sha256(data).hexdigest() != row["sha256"]:
                    issues.append(f"Export checksum mismatch: {name}")
    except (OSError, KeyError, ValueError, zipfile.BadZipFile, json.JSONDecodeError) as exc:
        issues.append(f"Export could not be verified: {exc}")
    return not issues, issues
