"""Single-claim worker for reviewer-approved passive and local media jobs."""
from __future__ import annotations

import json
import os
import signal
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .providers import PREPARERS, _validate_collection_options
from .team_store import TeamStore


PASSIVE_PROVIDERS = frozenset({"rdap", "dns", "crtsh", "wayback", "commoncrawl"})


def _media_output(provider: str, data: bytes) -> bytes:
    if os.name != "posix":
        raise ValueError("Resource-controlled media jobs require a POSIX worker")
    import resource

    def limits() -> None:
        resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
        resource.setrlimit(resource.RLIMIT_AS, (1024 * 1024 * 1024, 1024 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_FSIZE, (2 * 1024 * 1024, 2 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))

    with tempfile.TemporaryDirectory(prefix="osint-media-") as directory:
        source = Path(directory) / "input.bin"
        descriptor = os.open(source, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
        args = (["ffprobe", "-v", "error", "-show_format", "-show_streams", "-of", "json", str(source)]
                if provider == "ffprobe" else
                ["exiftool", "-json", "-G1", "-a", "-u", str(source)])
        with (Path(directory) / "stdout").open("w+b") as stdout, (Path(directory) / "stderr").open("w+b") as stderr:
            process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                       cwd=directory, close_fds=True, start_new_session=True, preexec_fn=limits)
            try:
                process.wait(timeout=45)
            except subprocess.TimeoutExpired as exc:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                raise ValueError("Media analyzer exceeded the 45-second wall-clock limit") from exc
            stdout.seek(0)
            stderr.seek(0)
            output = stdout.read(2 * 1024 * 1024 + 1)
            error = stderr.read(1000).decode("utf-8", errors="replace")
            if len(output) > 2 * 1024 * 1024 or process.returncode:
                raise ValueError(f"Media analyzer failed or exceeded 2 MiB output: {error[:300]}")
            json.loads(output)
            return output


def run_one(store: TeamStore) -> str | None:
    """Atomically claim one approved job; record an encrypted result or failure."""
    actor = store.config.worker_subject
    with store.connect() as conn:
        expired = conn.execute("""UPDATE team_jobs SET status='failed',
            error='Worker lease expired',updated_at=now()
            WHERE status='running' AND updated_at < now()-interval '1 hour'
            RETURNING job_id,case_id""").fetchall()
        for row in expired:
            store.audit(conn, row["case_id"], actor, "job.lease-expired", row["job_id"])
        job = conn.execute("""SELECT j.* FROM team_jobs j JOIN team_cases c USING(case_id)
            WHERE j.status='approved' AND c.deleted_at IS NULL
            ORDER BY j.created_at,j.job_id FOR UPDATE OF j SKIP LOCKED LIMIT 1""").fetchone()
        if not job:
            return None
        conn.execute("UPDATE team_jobs SET status='running',updated_at=now() WHERE job_id=%s", (job["job_id"],))
        store.audit(conn, job["case_id"], actor, "job.started", job["job_id"])
    try:
        with store.connect() as conn:
            case = store.case(conn, job["case_id"])
            if case["retention_until"] <= datetime.now(timezone.utc).date():
                raise ValueError("Case retention expired; no new collection is permitted")
            if not job["reviewed_by"] or job["reviewed_by"] == job["requested_by"]:
                raise ValueError("Job lacks independent review")
        if job["kind"] == "provider":
            if job["provider"] not in PASSIVE_PROVIDERS or job["target"] != case["target"]:
                raise ValueError("Provider or target no longer matches approved scope")
            options = job["options"]
            _validate_collection_options(job["provider"], options)
            prepared = PREPARERS[job["provider"]](job["target"], options)
            raw = store.put_object(job["case_id"], actor, prepared.raw_content,
                                   prepared.raw_name, prepared.content_type, "job-result")
            result = {"provider": job["provider"], "target": job["target"],
                      "request_url": prepared.request_url, "source_title": prepared.source_title,
                      "records": prepared.records, "source_notes": prepared.source_notes,
                      "raw_object_id": raw["object_id"], "raw_sha256": raw["sha256"]}
            output = json.dumps(result, ensure_ascii=False, sort_keys=True).encode()
        elif job["kind"] == "media":
            if job["provider"] not in {"ffprobe", "exiftool"} or not job["source_object_id"]:
                raise ValueError("Media job is outside the allowlist")
            _, data = store.read_object(job["case_id"], job["source_object_id"])
            output = _media_output(job["provider"], data)
        else:
            raise ValueError("Unknown job kind")
        result_object = store.put_object(job["case_id"], actor, output, "job-result.json",
                                         "application/json", "job-result")
        with store.connect() as conn:
            conn.execute("""UPDATE team_jobs SET status='completed',result_object_id=%s,
                updated_at=now() WHERE job_id=%s""", (result_object["object_id"], job["job_id"]))
            store.audit(conn, job["case_id"], actor, "job.completed", job["job_id"],
                        {"result_object_id": result_object["object_id"]})
    except Exception as exc:
        with store.connect() as conn:
            conn.execute("UPDATE team_jobs SET status='failed',error=%s,updated_at=now() WHERE job_id=%s",
                         (str(exc)[:500], job["job_id"]))
            store.audit(conn, job["case_id"], actor, "job.failed", job["job_id"])
    return job["job_id"]
