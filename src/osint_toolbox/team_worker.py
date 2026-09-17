"""Single-claim worker for reviewer-approved passive and local media jobs."""
from __future__ import annotations

import json
import os
import signal
import subprocess
import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .team_service import TeamService
from .team_store import TeamStore


@contextmanager
def _deadline(seconds: int = 840):
    """A hard wall-clock bound below the lease; workers are dedicated POSIX processes."""
    if os.name != "posix" or threading.current_thread() is not threading.main_thread():
        raise ValueError("Team workers require a dedicated POSIX main process")
    previous = signal.getsignal(signal.SIGALRM)
    if signal.getitimer(signal.ITIMER_REAL)[0]:
        raise ValueError("Worker process already has an active deadline")

    def expired(*_):
        raise TimeoutError("Job exceeded its wall-clock deadline")

    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def _media_output(provider: str, data: bytes) -> bytes:
    if provider not in {"ffprobe", "exiftool"}:
        raise ValueError("Unknown media analyzer")
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
        args = (["ffprobe", "-protocol_whitelist", "file", "-format_whitelist",
                 "mov,mp4,m4a,3gp,3g2,mj2,matroska,webm,avi,wav,mp3,ogg,flac,png_pipe,jpeg_pipe",
                 "-v", "error", "-show_format", "-show_streams", "-of", "json", str(source)]
                if provider == "ffprobe" else
                ["exiftool", "-config", "", "-json", "-G1", "-a", "-u", str(source)])
        with (Path(directory) / "stdout").open("w+b") as stdout, (Path(directory) / "stderr").open("w+b") as stderr:
            process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                       cwd=directory, close_fds=True, start_new_session=True, preexec_fn=limits,
                                       env={"PATH": os.defpath + ":/opt/homebrew/bin", "LANG": "C"})
            try:
                process.wait(timeout=45)
            except subprocess.TimeoutExpired as exc:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                raise ValueError("Media analyzer exceeded the 45-second wall-clock limit") from exc
            stdout.seek(0)
            stderr.seek(0)
            output = stdout.read(2 * 1024 * 1024 + 1)
            if len(output) > 2 * 1024 * 1024 or process.returncode:
                raise ValueError("Media analyzer failed or exceeded 2 MiB output")
            json.loads(output)
            return output


def run_one(store: TeamStore) -> str | None:
    """Claim and execute one job through the same service used by the API."""
    service = TeamService(store)
    job = service.claim_job()
    if job is None:
        return None
    try:
        with _deadline():
            prepared = service.prepare_job(job)
            if job["kind"] == "media":
                prepared = _media_output(job["provider"], prepared)
            service.finish_job(job, prepared)
    except Exception as exc:
        # Provider errors can contain target URLs or response content. Persist only
        # a classification; operators correlate it with the job ID and audit trail.
        service.fail_job(job, type(exc).__name__)
    return job["job_id"]
