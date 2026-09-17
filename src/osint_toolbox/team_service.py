"""Transport-independent team application service.

HTTP, workers and operator commands share these policies. Callers supply an
identity authenticated by their transport; request payloads must never set it.
TeamStore is privileged infrastructure, not an alternate application API.
"""
from __future__ import annotations

import hashlib
import io
import json
import re
import zipfile
from contextlib import contextmanager
from datetime import date
from typing import Any, Iterator

from psycopg import sql

from . import __version__
from .application import TEAM_ANALYZERS, TEAM_PROVIDERS, execute_collection, validate_collection
from .team_models import (AssignmentInput, CaseInput, DecisionInput, HoldInput, JobInput,
                          MemberInput, NoteInput, ReasonInput, ReportInput, RetentionInput, WorkInput)
from .team_store import (CASE_ID, MAX_EXPORT_BYTES, MAX_OBJECT_BYTES, ROLE_RANK, SCHEMA_VERSION,
                         TeamStore, Transaction, _id, _utc)
from .util import canonical_json, safe_filename


class ConflictError(ValueError):
    """A valid request conflicts with current state; maps to HTTP 409."""


class QuotaError(ValueError):
    """A configured storage or queue bound was reached; maps to HTTP 429."""


def _subject(actor: str) -> str:
    if not isinstance(actor, str) or not actor.strip() or len(actor) > 200 or any(ord(c) < 32 for c in actor):
        raise PermissionError("Invalid authenticated identity")
    return actor


def _page(limit: int, offset: int) -> tuple[int, int]:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
        raise ValueError("limit must be 1–500")
    if isinstance(offset, bool) or not isinstance(offset, int) or not 0 <= offset <= 100000:
        raise ValueError("offset must be 0–100000")
    return limit, offset


def _public_job(row: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in row.items() if k not in {"lease_token", "request_sha256", "idempotency_key"}}


class TeamService:
    def __init__(self, store: TeamStore) -> None:
        self.store, self.config = store, store.config

    def _case(self, tx: Transaction, case_id: str) -> dict[str, Any]:
        row = tx.execute("SELECT * FROM team_cases WHERE case_id=%s AND deleted_at IS NULL", (case_id,)).fetchone()
        if not row:
            raise LookupError("Case not found")
        return row

    def _role(self, tx: Transaction, case_id: str, actor: str) -> str:
        _subject(actor)
        if actor == self.config.worker_subject:
            raise PermissionError("Worker identity cannot act as a case user")
        if actor in self.config.admin_subjects:
            return "admin"
        row = tx.execute("SELECT role FROM team_members WHERE case_id=%s AND subject=%s", (case_id, actor)).fetchone()
        if not row:
            raise PermissionError("Case access denied")
        return row["role"]

    def _require(self, tx: Transaction, case_id: str, actor: str, minimum: str) -> str:
        role = self._role(tx, case_id, actor)
        if ROLE_RANK[role] < ROLE_RANK[minimum]:
            raise PermissionError("Case permission denied")
        return role

    def _mutable(self, tx: Transaction, case: dict[str, Any]) -> None:
        today = tx.execute("SELECT CURRENT_DATE AS today").fetchone()["today"]
        if case["retention_until"] <= today:
            raise ConflictError("Case retention expired; new content and collection are blocked")

    @contextmanager
    def _scope(self, case_id: str, actor: str, minimum: str, action: str,
               write: bool = False) -> Iterator[Transaction]:
        _subject(actor)
        try:
            with self.store.transaction(case_id) as tx:
                case = self._case(tx, case_id)
                self._require(tx, case_id, actor, minimum)
                if write:
                    self._mutable(tx, case)
                yield tx
                self.store.audit(tx, case_id, actor, action, case_id)
        except (PermissionError, LookupError, ValueError):
            with self.store.transaction() as tx:
                self.store.audit(tx, case_id if CASE_ID.fullmatch(case_id) else None, actor,
                                 "service.denied", "", {"operation": action})
            raise

    def _admin(self, actor: str) -> None:
        if _subject(actor) not in self.config.admin_subjects:
            raise PermissionError("Administrator role required")

    def _operator(self, actor: str) -> None:
        if _subject(actor) not in self.config.admin_subjects | {self.config.worker_subject}:
            raise PermissionError("Operator identity required")

    def ready(self) -> dict[str, str]:
        with self.store.connect() as conn:
            row = conn.execute("SELECT version FROM team_schema_version WHERE singleton=true").fetchone()
            if not row or row["version"] != SCHEMA_VERSION:
                raise ConflictError("Team schema migration required")
        return {"status": "ready"}

    def create_case(self, actor: str, fields: dict[str, Any]) -> dict[str, Any]:
        self._admin(actor)
        fields = CaseInput.model_validate(fields).model_dump()
        until = date.fromisoformat(fields["retention_until"])
        case_id = _id("TC")
        with self.store.transaction(case_id) as tx:
            if until <= tx.execute("SELECT CURRENT_DATE AS today").fetchone()["today"]:
                raise ValueError("Retention date must be in the future")
            row = tx.execute("""INSERT INTO team_cases
                (case_id,title,purpose,authority,target_type,target,sensitivity,retention_until,owner_sub)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *""",
                (case_id, fields["title"], fields["purpose"], fields["authority"], fields["target_type"],
                 fields["target"], fields["sensitivity"], until, actor)).fetchone()
            tx.execute("INSERT INTO team_members (case_id,subject,role,granted_by) VALUES (%s,%s,'owner',%s)",
                       (case_id, actor, actor))
            self.store.audit(tx, case_id, actor, "case.created", case_id)
            return row

    def list_cases(self, actor: str, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        _subject(actor)
        _page(limit, offset)
        with self.store.transaction() as tx:
            if actor in self.config.admin_subjects:
                rows = tx.execute("""SELECT * FROM team_cases WHERE deleted_at IS NULL
                    ORDER BY created_at DESC,case_id LIMIT %s OFFSET %s""", (limit, offset)).fetchall()
            else:
                rows = tx.execute("""SELECT c.* FROM team_cases c JOIN team_members m USING(case_id)
                    WHERE m.subject=%s AND c.deleted_at IS NULL
                    ORDER BY c.created_at DESC,c.case_id LIMIT %s OFFSET %s""", (actor, limit, offset)).fetchall()
            self.store.audit(tx, None, actor, "cases.read")
            return rows

    def get_case(self, case_id: str, actor: str) -> dict[str, Any]:
        with self._scope(case_id, actor, "viewer", "case.read") as tx:
            return self._case(tx, case_id)

    def authorize_upload(self, case_id: str, actor: str) -> None:
        with self._scope(case_id, actor, "analyst", "object.upload-authorized", write=True):
            pass

    def grant(self, case_id: str, actor: str, subject: str, role: str) -> None:
        item = MemberInput(subject=subject, role=role)
        _subject(item.subject)
        if item.subject == self.config.worker_subject:
            raise ValueError("Worker cannot be granted user permissions")
        with self._scope(case_id, actor, "owner", "member.changed") as tx:
            if item.subject == self._case(tx, case_id)["owner_sub"] and item.role != "owner":
                raise ValueError("Original owner cannot be downgraded")
            tx.execute("""INSERT INTO team_members (case_id,subject,role,granted_by)
                VALUES (%s,%s,%s,%s) ON CONFLICT(case_id,subject)
                DO UPDATE SET role=EXCLUDED.role,granted_by=EXCLUDED.granted_by,granted_at=now()""",
                (case_id, item.subject, item.role, actor))
            self.store.audit(tx, case_id, actor, "member.granted", item.subject, {"role": item.role})

    def revoke(self, case_id: str, actor: str, subject: str) -> None:
        _subject(subject)
        with self._scope(case_id, actor, "owner", "member.revoked") as tx:
            if subject == self._case(tx, case_id)["owner_sub"]:
                raise ValueError("Original owner cannot be removed")
            tx.execute("DELETE FROM team_members WHERE case_id=%s AND subject=%s", (case_id, subject))
            self.store.audit(tx, case_id, actor, "member.removed", subject)

    def _object_row(self, tx: Transaction, case_id: str, object_id: str) -> dict[str, Any]:
        row = tx.execute("""SELECT * FROM team_objects WHERE case_id=%s
            AND object_id=%s AND deleted_at IS NULL""", (case_id, object_id)).fetchone()
        if not row:
            raise LookupError("Object not found")
        return row

    def _put_object(self, tx: Transaction, case_id: str, actor: str, data: bytes,
                    filename: str, content_type: str, kind: str) -> dict[str, Any]:
        if not isinstance(data, bytes) or len(data) > MAX_OBJECT_BYTES:
            raise ValueError("Object must be bytes and no larger than 20 MiB")
        usage = tx.execute("""SELECT count(*) AS n,COALESCE(sum(size_bytes),0) AS bytes
            FROM team_objects WHERE case_id=%s AND deleted_at IS NULL""", (case_id,)).fetchone()
        if usage["n"] >= self.config.max_case_objects or usage["bytes"] + len(data) > self.config.max_case_bytes:
            raise QuotaError("Case storage quota reached")
        if not re.fullmatch(r"[A-Za-z0-9.+-]+/[A-Za-z0-9.+-]+", content_type):
            content_type = "application/octet-stream"
        object_id, digest = self.store.objects.write(case_id, data)
        tx.created_objects.append((case_id, object_id))
        row = tx.execute("""INSERT INTO team_objects
            (object_id,case_id,kind,filename,content_type,sha256,size_bytes,created_by)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *""",
            (object_id, case_id, kind, safe_filename(filename)[:200], content_type, digest, len(data), actor)).fetchone()
        self.store.audit(tx, case_id, actor, "object.created", object_id,
                         {"kind": kind, "sha256": digest, "size_bytes": len(data)})
        return row

    def put_object(self, case_id: str, actor: str, data: bytes, filename: str,
                   content_type: str) -> dict[str, Any]:
        with self._scope(case_id, actor, "analyst", "artifact.added", write=True) as tx:
            return self._put_object(tx, case_id, actor, data, filename, content_type, "artifact")

    def read_object(self, case_id: str, actor: str, object_id: str) -> tuple[dict[str, Any], bytes]:
        with self._scope(case_id, actor, "analyst", "object.read") as tx:
            row = self._object_row(tx, case_id, object_id)
            return row, self.store.objects.read(case_id, object_id, row["sha256"])

    def list_records(self, case_id: str, actor: str, kind: str,
                     limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        tables = {"annotations": ("team_annotations", "annotation_id", "viewer"),
                  "work": ("team_work_items", "work_id", "viewer"),
                  "objects": ("team_objects", "object_id", "analyst"),
                  "jobs": ("team_jobs", "job_id", "analyst"),
                  "audit": ("team_audit", "event_id", "reviewer")}
        if kind not in tables:
            raise ValueError("Unknown record collection")
        _page(limit, offset)
        table, identifier, role = tables[kind]
        with self._scope(case_id, actor, role, kind + ".read") as tx:
            rows = tx.execute(sql.SQL("SELECT * FROM {} WHERE case_id=%s ORDER BY {} DESC LIMIT %s OFFSET %s")
                              .format(sql.Identifier(table), sql.Identifier(identifier)),
                              (case_id, limit, offset)).fetchall()
            return [_public_job(r) for r in rows] if kind == "jobs" else rows

    def add_annotation(self, case_id: str, actor: str, body: str) -> dict[str, Any]:
        item = NoteInput(body=body)
        with self._scope(case_id, actor, "analyst", "annotation.created", write=True) as tx:
            return tx.execute("""INSERT INTO team_annotations (annotation_id,case_id,body,author_sub)
                VALUES (%s,%s,%s,%s) RETURNING *""", (_id("ANN"), case_id, item.body, actor)).fetchone()

    def add_work(self, case_id: str, actor: str, title: str) -> dict[str, Any]:
        item = WorkInput(title=title)
        with self._scope(case_id, actor, "analyst", "work.created", write=True) as tx:
            return tx.execute("""INSERT INTO team_work_items (work_id,case_id,title,status,created_by,updated_by)
                VALUES (%s,%s,%s,'open',%s,%s) RETURNING *""", (_id("WRK"), case_id, item.title, actor, actor)).fetchone()

    def assign_work(self, case_id: str, work_id: str, actor: str, assignee: str, status: str) -> dict[str, Any]:
        item = AssignmentInput(assignee=assignee, status=status)
        with self._scope(case_id, actor, "reviewer", "work.assigned", write=True) as tx:
            self._require(tx, case_id, item.assignee, "analyst")
            row = tx.execute("""UPDATE team_work_items SET assigned_to=%s,status=%s,updated_by=%s,updated_at=now()
                WHERE case_id=%s AND work_id=%s RETURNING *""", (item.assignee, item.status, actor, case_id, work_id)).fetchone()
            if not row:
                raise LookupError("Work item not found")
            return row

    def review_queue(self, case_id: str, actor: str, limit: int = 100, offset: int = 0) -> dict[str, Any]:
        _page(limit, offset)
        with self._scope(case_id, actor, "reviewer", "review-queue.read") as tx:
            result = {}
            for name, table, state, key in (("jobs", "team_jobs", "pending", "job_id"),
                                             ("reports", "team_reports", "draft", "report_id"),
                                             ("work", "team_work_items", "in-review", "work_id")):
                rows = tx.execute(sql.SQL("""SELECT * FROM {} WHERE case_id=%s AND status=%s
                    ORDER BY created_at,{} LIMIT %s OFFSET %s""").format(sql.Identifier(table), sql.Identifier(key)),
                    (case_id, state, limit, offset)).fetchall()
                result[name] = [_public_job(r) for r in rows] if name == "jobs" else rows
            return result

    def _validate_job(self, tx: Transaction, case: dict[str, Any], item: JobInput) -> None:
        self._mutable(tx, case)
        if item.kind == "provider":
            if item.provider not in TEAM_PROVIDERS or not item.disclosure_confirmed or item.source_object_id:
                raise ValueError("Only allowlisted passive providers with disclosure confirmation are enabled")
            if item.target != case["target"]:
                raise ValueError("Provider target must exactly match the authorized case target")
            validate_collection(item.provider, item.target, item.options)
        else:
            if item.provider not in TEAM_ANALYZERS or item.options or item.target or not item.source_object_id:
                raise ValueError("Only bounded ffprobe/ExifTool jobs with a case artifact are enabled")
            source = self._object_row(tx, case["case_id"], item.source_object_id)
            if source["kind"] != "artifact":
                raise ValueError("Media jobs require an original artifact")

    def request_job(self, case_id: str, actor: str, fields: dict[str, Any],
                    idempotency_key: str | None = None) -> dict[str, Any]:
        item = JobInput.model_validate(fields)
        if idempotency_key is not None and not re.fullmatch(r"[A-Za-z0-9_.:-]{8,128}", idempotency_key):
            raise ValueError("Idempotency-Key must contain 8–128 safe characters")
        digest = hashlib.sha256(canonical_json(item.model_dump()).encode()).hexdigest()
        with self._scope(case_id, actor, "analyst", "job.requested", write=True) as tx:
            self._validate_job(tx, self._case(tx, case_id), item)
            if idempotency_key:
                previous = tx.execute("""SELECT * FROM team_jobs WHERE case_id=%s AND requested_by=%s
                    AND idempotency_key=%s""", (case_id, actor, idempotency_key)).fetchone()
                if previous:
                    if previous["request_sha256"] != digest:
                        raise ConflictError("Idempotency-Key was already used for a different request")
                    return _public_job(previous)
            count = tx.execute("""SELECT count(*) AS n FROM team_jobs WHERE case_id=%s
                AND status IN ('pending','approved','running')""", (case_id,)).fetchone()["n"]
            if count >= self.config.max_pending_jobs:
                raise QuotaError("Case pending-job quota reached")
            row = tx.execute("""INSERT INTO team_jobs
                (job_id,case_id,kind,provider,target,source_object_id,options,status,requested_by,
                 disclosure_confirmed,idempotency_key,request_sha256)
                VALUES (%s,%s,%s,%s,%s,%s,%s,'pending',%s,%s,%s,%s) RETURNING *""",
                (_id("JOB"), case_id, item.kind, item.provider, item.target, item.source_object_id,
                 json.dumps(item.options), actor, item.disclosure_confirmed, idempotency_key, digest)).fetchone()
            return _public_job(row)

    def _job(self, tx: Transaction, case_id: str, job_id: str) -> dict[str, Any]:
        row = tx.execute("SELECT * FROM team_jobs WHERE case_id=%s AND job_id=%s FOR UPDATE", (case_id, job_id)).fetchone()
        if not row:
            raise LookupError("Job not found")
        return row

    def get_job(self, case_id: str, actor: str, job_id: str) -> dict[str, Any]:
        with self._scope(case_id, actor, "analyst", "job.read") as tx:
            return _public_job(self._job(tx, case_id, job_id))

    def review_job(self, case_id: str, job_id: str, actor: str, approve: bool, reason: str) -> dict[str, Any]:
        item = DecisionInput(approve=approve, reason=reason)
        with self._scope(case_id, actor, "reviewer", "job.reviewed", write=True) as tx:
            job = self._job(tx, case_id, job_id)
            if job["status"] != "pending":
                raise ConflictError("Job is not pending review")
            if actor == job["requested_by"]:
                raise PermissionError("Requester cannot review their own job")
            self._require(tx, case_id, job["requested_by"], "analyst")
            self._validate_job(tx, self._case(tx, case_id), JobInput.model_validate(
                {k: job[k] for k in JobInput.model_fields}))
            row = tx.execute("""UPDATE team_jobs SET status=%s,reviewed_by=%s,review_reason=%s,
                updated_at=now() WHERE job_id=%s RETURNING *""",
                ("approved" if item.approve else "rejected", actor, item.reason, job_id)).fetchone()
            self.store.audit(tx, case_id, actor, "job.approved" if approve else "job.rejected", job_id)
            return _public_job(row)

    def cancel_job(self, case_id: str, actor: str, job_id: str, reason: str) -> dict[str, Any]:
        item = ReasonInput(reason=reason)
        with self._scope(case_id, actor, "analyst", "job.cancelled") as tx:
            job = self._job(tx, case_id, job_id)
            if actor != job["requested_by"]:
                self._require(tx, case_id, actor, "reviewer")
            if job["status"] not in {"pending", "approved", "running"}:
                raise ConflictError("Job is already terminal")
            row = tx.execute("""UPDATE team_jobs SET status='cancelled',lease_token=NULL,
                lease_expires_at=NULL,error='Cancelled by authorized user',review_reason=%s,updated_at=now()
                WHERE job_id=%s RETURNING *""", (item.reason, job_id)).fetchone()
            return _public_job(row)

    def retry_job(self, case_id: str, actor: str, job_id: str, reason: str) -> dict[str, Any]:
        ReasonInput(reason=reason)
        with self._scope(case_id, actor, "analyst", "job.retry-requested", write=True) as tx:
            job = self._job(tx, case_id, job_id)
            if actor != job["requested_by"]:
                raise PermissionError("Only the requester may request a retry")
            if job["status"] != "failed" or job["attempts"] >= 3:
                raise ConflictError("Retry requires a failed job with fewer than three attempts")
            row = tx.execute("""UPDATE team_jobs SET status='pending',reviewed_by=NULL,review_reason='',
                error='',lease_token=NULL,lease_expires_at=NULL,updated_at=now()
                WHERE job_id=%s RETURNING *""", (job_id,)).fetchone()
            return _public_job(row)

    def add_report(self, case_id: str, actor: str, markdown: str) -> dict[str, Any]:
        item = ReportInput(markdown=markdown)
        with self._scope(case_id, actor, "analyst", "report.version-created", write=True) as tx:
            # Authorization, object registration and report version are one unit.
            obj = self._put_object(tx, case_id, actor, item.markdown.encode(), "report.md", "text/markdown", "report")
            version = tx.execute("SELECT COALESCE(max(version),0)+1 AS n FROM team_reports WHERE case_id=%s",
                                 (case_id,)).fetchone()["n"]
            return tx.execute("""INSERT INTO team_reports (report_id,case_id,version,object_id,status,created_by)
                VALUES (%s,%s,%s,%s,'draft',%s) RETURNING *""",
                (_id("RPT"), case_id, version, obj["object_id"], actor)).fetchone()

    def review_report(self, case_id: str, report_id: str, actor: str,
                      approve: bool, reason: str) -> dict[str, Any]:
        item = DecisionInput(approve=approve, reason=reason)
        with self._scope(case_id, actor, "reviewer", "report.reviewed") as tx:
            report = tx.execute("SELECT * FROM team_reports WHERE case_id=%s AND report_id=%s FOR UPDATE",
                                (case_id, report_id)).fetchone()
            if not report:
                raise LookupError("Report not found")
            if report["status"] != "draft":
                raise ConflictError("Report is no longer a draft")
            if actor == report["created_by"]:
                raise PermissionError("Author cannot review their own report")
            row = tx.execute("""UPDATE team_reports SET status=%s,reviewed_by=%s,review_reason=%s,reviewed_at=now()
                WHERE report_id=%s RETURNING *""",
                ("approved" if item.approve else "rejected", actor, item.reason, report_id)).fetchone()
            self.store.audit(tx, case_id, actor, "report.approved" if approve else "report.rejected", report_id)
            return row

    def read_report(self, case_id: str, actor: str, report_id: str) -> bytes:
        with self._scope(case_id, actor, "viewer", "report.read") as tx:
            report = tx.execute("SELECT * FROM team_reports WHERE case_id=%s AND report_id=%s",
                                (case_id, report_id)).fetchone()
            if not report or (self._role(tx, case_id, actor) == "viewer" and report["status"] != "approved"):
                raise LookupError("Report not found")
            obj = self._object_row(tx, case_id, report["object_id"])
            return self.store.objects.read(case_id, obj["object_id"], obj["sha256"])

    def set_hold(self, case_id: str, actor: str, active: bool, reason: str, authority: str) -> dict[str, Any]:
        item = HoldInput(active=active, reason=reason, authority=authority)
        with self._scope(case_id, actor, "owner", "hold.changed") as tx:
            if self._case(tx, case_id)["legal_hold"] == item.active:
                raise ConflictError("Legal hold is already in the requested state")
            row = tx.execute("""UPDATE team_cases SET legal_hold=%s,hold_reason=%s,hold_authority=%s
                WHERE case_id=%s RETURNING *""", (item.active, item.reason, item.authority, case_id)).fetchone()
            self.store.audit(tx, case_id, actor, "hold.placed" if item.active else "hold.released", case_id,
                             {"reason_sha256": hashlib.sha256(item.reason.encode()).hexdigest()})
            return row

    def set_retention(self, case_id: str, actor: str, retention_until: str, reason: str) -> dict[str, Any]:
        item = RetentionInput(retention_until=retention_until, reason=reason)
        until = date.fromisoformat(item.retention_until)
        with self._scope(case_id, actor, "owner", "retention.changed") as tx:
            case = self._case(tx, case_id)
            if case["legal_hold"]:
                raise ConflictError("Retention is frozen by legal hold")
            if until <= tx.execute("SELECT CURRENT_DATE AS today").fetchone()["today"]:
                raise ValueError("New retention date must be in the future")
            return tx.execute("UPDATE team_cases SET retention_until=%s WHERE case_id=%s RETURNING *",
                              (until, case_id)).fetchone()

    def retention_sweep(self, actor: str) -> list[str]:
        """Tombstone first; purge in a second, restartable transaction."""
        self._operator(actor)
        with self.store.connect() as conn:
            rows = conn.execute("""SELECT case_id FROM team_cases WHERE
                (deleted_at IS NULL AND legal_hold=false AND retention_until<=CURRENT_DATE)
                OR (deleted_at IS NOT NULL AND purged_at IS NULL) ORDER BY case_id""").fetchall()
        deleted = []
        for item in rows:
            case_id = item["case_id"]
            with self.store.transaction(case_id) as tx:
                case = tx.execute("SELECT * FROM team_cases WHERE case_id=%s FOR UPDATE", (case_id,)).fetchone()
                today = tx.execute("SELECT CURRENT_DATE AS today").fetchone()["today"]
                if case["legal_hold"] or (case["deleted_at"] is None and case["retention_until"] > today):
                    continue
                if case["deleted_at"] is None:
                    tx.execute("""UPDATE team_cases SET title='[DELETED]',purpose='[DELETED]',authority='[DELETED]',
                        target='[DELETED]',hold_reason='',hold_authority='',deleted_at=now() WHERE case_id=%s""", (case_id,))
                    tx.execute("""UPDATE team_objects SET deleted_at=now(),filename='[DELETED]'
                        WHERE case_id=%s AND deleted_at IS NULL""", (case_id,))
                    tx.execute("DELETE FROM team_annotations WHERE case_id=%s", (case_id,))
                    tx.execute("DELETE FROM team_members WHERE case_id=%s", (case_id,))
                    tx.execute("UPDATE team_work_items SET title='[DELETED]' WHERE case_id=%s", (case_id,))
                    tx.execute("""UPDATE team_jobs SET target=NULL,options='{}'::jsonb,error='',review_reason='',
                        idempotency_key=NULL,lease_token=NULL,lease_expires_at=NULL,
                        status=CASE WHEN status IN ('pending','approved','running') THEN 'cancelled' ELSE status END
                        WHERE case_id=%s""", (case_id,))
                    tx.execute("UPDATE team_reports SET review_reason='' WHERE case_id=%s", (case_id,))
                    self.store.audit(tx, case_id, actor, "case.retention-tombstoned", case_id)
            with self.store.transaction(case_id) as tx:
                rows = tx.execute("SELECT object_id FROM team_objects WHERE case_id=%s", (case_id,)).fetchall()
                for row in rows:
                    self.store.objects.delete(case_id, row["object_id"])
                tx.execute("UPDATE team_cases SET purged_at=now() WHERE case_id=%s", (case_id,))
                self.store.audit(tx, case_id, actor, "case.retention-deleted", case_id, {"object_count": len(rows)})
            deleted.append(case_id)
        return deleted

    def export_case(self, case_id: str, actor: str) -> bytes:
        with self._scope(case_id, actor, "owner", "case.exported") as tx:
            objects = tx.execute("SELECT * FROM team_objects WHERE case_id=%s AND deleted_at IS NULL ORDER BY object_id",
                                 (case_id,)).fetchall()
            if len(objects) > 1000 or sum(r["size_bytes"] for r in objects) > MAX_EXPORT_BYTES:
                raise ValueError("Case export exceeds 100 MiB/1,000 objects")
            metadata = {"case": self._case(tx, case_id), "objects": objects}
            for table in ("reports", "annotations", "work_items", "members", "jobs", "audit"):
                rows = tx.execute(sql.SQL("SELECT * FROM {} WHERE case_id=%s").format(sql.Identifier("team_" + table)),
                                  (case_id,)).fetchall()
                metadata[table] = [_public_job(r) for r in rows] if table == "jobs" else rows
            payload = json.dumps(metadata, default=str, sort_keys=True).encode()
            if len(payload) > 4 * 1024 * 1024:
                raise ValueError("Case export metadata exceeds 4 MiB")
            files = {"case.json": payload}
            for row in objects:
                files["objects/" + row["object_id"]] = self.store.objects.read(case_id, row["object_id"], row["sha256"])
            manifest = {"format": "osint-toolbox.team-export/1", "case_id": case_id,
                        "files": [{"path": n, "sha256": hashlib.sha256(b).hexdigest(), "size_bytes": len(b)}
                                  for n, b in sorted(files.items())]}
            output = io.BytesIO()
            with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("MANIFEST.json", json.dumps(manifest, sort_keys=True))
                for name, data in sorted(files.items()):
                    archive.writestr(name, data)
            return output.getvalue()

    def metrics(self, actor: str) -> dict[str, Any]:
        self._admin(actor)
        with self.store.transaction() as tx:
            states = tx.execute("SELECT status,count(*) AS n FROM team_jobs GROUP BY status").fetchall()
            self.store.audit(tx, None, actor, "metrics.read")
            return {"cases": tx.execute("SELECT count(*) AS n FROM team_cases WHERE deleted_at IS NULL").fetchone()["n"],
                    "jobs": {r["status"]: r["n"] for r in states},
                    "pending_purges": tx.execute("""SELECT count(*) AS n FROM team_cases
                        WHERE deleted_at IS NOT NULL AND purged_at IS NULL""").fetchone()["n"]}

    def claim_job(self) -> dict[str, Any] | None:
        # Read candidate IDs, then take case -> job locks in the same order as API operations.
        with self.store.connect() as conn:
            candidates = conn.execute("""SELECT case_id,job_id FROM team_jobs WHERE status='approved'
                OR (status='running' AND lease_expires_at<now()) ORDER BY created_at,job_id LIMIT 100""").fetchall()
        for candidate in candidates:
            with self.store.transaction(candidate["case_id"]) as tx:
                job = self._job(tx, candidate["case_id"], candidate["job_id"])
                if job["status"] == "running":
                    expired = tx.execute("SELECT %s::timestamptz < now() AS expired", (job["lease_expires_at"],)).fetchone()["expired"]
                    if expired:
                        tx.execute("""UPDATE team_jobs SET status='failed',error='Worker lease expired; review before retry',
                            lease_token=NULL,lease_expires_at=NULL,updated_at=now() WHERE job_id=%s""", (job["job_id"],))
                        self.store.audit(tx, job["case_id"], self.config.worker_subject, "job.lease-expired", job["job_id"])
                    continue
                if job["status"] != "approved":
                    continue
                try:
                    self._authorize_job(tx, job)
                except (ValueError, PermissionError, LookupError):
                    tx.execute("UPDATE team_jobs SET status='failed',error='Authorization no longer valid',updated_at=now() WHERE job_id=%s",
                               (job["job_id"],))
                    self.store.audit(tx, job["case_id"], self.config.worker_subject, "job.blocked", job["job_id"])
                    continue
                row = tx.execute("""UPDATE team_jobs SET status='running',lease_token=%s,
                    lease_expires_at=now()+interval '15 minutes',attempts=attempts+1,updated_at=now()
                    WHERE job_id=%s RETURNING *""", (_id("LEASE"), job["job_id"])).fetchone()
                self.store.audit(tx, job["case_id"], self.config.worker_subject, "job.started", job["job_id"])
                return row
        return None

    def _authorize_job(self, tx: Transaction, job: dict[str, Any]) -> None:
        case = self._case(tx, job["case_id"])
        if not job["reviewed_by"] or job["reviewed_by"] == job["requested_by"]:
            raise PermissionError("Independent review required")
        self._require(tx, job["case_id"], job["requested_by"], "analyst")
        self._require(tx, job["case_id"], job["reviewed_by"], "reviewer")
        self._validate_job(tx, case, JobInput.model_validate({k: job[k] for k in JobInput.model_fields}))

    def _lease(self, tx: Transaction, job: dict[str, Any]) -> dict[str, Any]:
        current = self._job(tx, job["case_id"], job["job_id"])
        if current["status"] != "running" or current["lease_token"] != job["lease_token"]:
            raise ConflictError("Job lease is no longer current")
        valid = tx.execute("SELECT %s::timestamptz > now() AS valid", (current["lease_expires_at"],)).fetchone()["valid"]
        if not valid:
            raise ConflictError("Job lease expired")
        self._authorize_job(tx, current)
        return current

    def prepare_job(self, job: dict[str, Any]) -> Any:
        def authorize() -> None:
            with self.store.transaction(job["case_id"]) as tx:
                self._lease(tx, job)
                self.store.audit(tx, job["case_id"], self.config.worker_subject, "job.execution-authorized", job["job_id"])
        if job["kind"] == "provider":
            return execute_collection(job["provider"], job["target"], job["options"], authorize=authorize)
        with self.store.transaction(job["case_id"]) as tx:
            self._lease(tx, job)
            obj = self._object_row(tx, job["case_id"], job["source_object_id"])
            return self.store.objects.read(job["case_id"], obj["object_id"], obj["sha256"])

    def finish_job(self, job: dict[str, Any], prepared: Any) -> None:
        with self.store.transaction(job["case_id"]) as tx:
            self._lease(tx, job)
            actor, case_id = self.config.worker_subject, job["case_id"]
            metadata = {"format": "osint-toolbox.collection-result/1", "job_id": job["job_id"],
                        "provider": job["provider"], "requested_by": job["requested_by"],
                        "reviewed_by": job["reviewed_by"], "collected_at_utc": _utc(), "toolbox_version": __version__}
            if job["kind"] == "provider":
                raw = self._put_object(tx, case_id, actor, prepared.raw_content, prepared.raw_name,
                                       prepared.content_type, "job-result")
                metadata.update({"target": job["target"], "request_url": prepared.request_url,
                                 "source_title": prepared.source_title, "source_notes": prepared.source_notes,
                                 "reliability": prepared.reliability, "credibility": prepared.credibility,
                                 "topic": prepared.topic, "records": prepared.records,
                                 "raw_object_id": raw["object_id"], "raw_sha256": raw["sha256"],
                                 "outcome": "results" if prepared.records else "zero-results"})
            else:
                metadata.update({"source_object_id": job["source_object_id"], "analysis": json.loads(prepared)})
            result = self._put_object(tx, case_id, actor, json.dumps(metadata, sort_keys=True).encode(),
                                      "job-result.json", "application/json", "job-result")
            tx.execute("""UPDATE team_jobs SET status='completed',result_object_id=%s,lease_token=NULL,
                lease_expires_at=NULL,updated_at=now() WHERE job_id=%s""", (result["object_id"], job["job_id"]))
            self.store.audit(tx, case_id, actor, "job.completed", job["job_id"], {"result_object_id": result["object_id"]})

    def fail_job(self, job: dict[str, Any], error_type: str) -> None:
        with self.store.transaction(job["case_id"]) as tx:
            row = tx.execute("""UPDATE team_jobs SET status='failed',error=%s,lease_token=NULL,
                lease_expires_at=NULL,updated_at=now() WHERE job_id=%s AND status='running'
                AND lease_token=%s RETURNING job_id""",
                ("Execution failed (" + re.sub(r"[^A-Za-z]", "", error_type)[:80] + "); review before retry",
                 job["job_id"], job["lease_token"])).fetchone()
            if row:
                self.store.audit(tx, job["case_id"], self.config.worker_subject, "job.failed", job["job_id"])
