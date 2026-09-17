"""Authenticated FastAPI team service; run with uvicorn's --factory option."""
from __future__ import annotations

import json
from typing import Any, Literal
from urllib.parse import urlsplit

import jwt
import psycopg
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from .providers import PROVIDERS, _validate_collection_options
from .team_store import MAX_OBJECT_BYTES, TeamConfig, TeamStore


ALLOWED_TEAM_PROVIDERS = frozenset({"rdap", "dns", "crtsh", "wayback", "commoncrawl"})
AUTH = HTTPBearer(auto_error=False)


class TokenVerifier:
    def __init__(self, issuer: str, audience: str, jwks_url: str,
                 jwks_data: dict[str, Any] | None = None) -> None:
        first, second = urlsplit(issuer), urlsplit(jwks_url)
        if first.scheme != "https" or second.scheme != "https" or first.hostname != second.hostname:
            raise ValueError("OIDC issuer and JWKS URL must use HTTPS on the same host")
        if not audience:
            raise ValueError("OIDC API audience is required")
        self.issuer = issuer
        self.audience = audience
        self.local_keys = jwt.PyJWKSet.from_dict(jwks_data) if jwks_data is not None else None
        self.client = None if self.local_keys else jwt.PyJWKClient(jwks_url, timeout=5, cache_jwk_set=True)

    def verify(self, token: str) -> str:
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") != "RS256" or not header.get("kid"):
                raise jwt.InvalidTokenError("Unsupported token algorithm or key ID")
            if self.local_keys:
                key = next((entry.key for entry in self.local_keys.keys if entry.key_id == header["kid"]), None)
                if key is None:
                    raise jwt.InvalidTokenError("Unknown signing key")
            else:
                key = self.client.get_signing_key_from_jwt(token).key
            claims = jwt.decode(token, key, algorithms=["RS256"], issuer=self.issuer,
                                audience=self.audience, leeway=30,
                                options={"require": ["exp", "iat", "iss", "aud", "sub"]})
            subject = claims["sub"]
            if not isinstance(subject, str) or not subject.strip() or len(subject) > 200:
                raise jwt.InvalidTokenError("Invalid subject")
            return subject
        except (jwt.PyJWTError, ValueError, StopIteration) as exc:
            raise HTTPException(status_code=401, detail="Invalid access token") from exc


class CaseInput(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    purpose: str = Field(min_length=3, max_length=2000)
    authority: str = Field(min_length=3, max_length=2000)
    target_type: str = Field(min_length=2, max_length=40)
    target: str = Field(min_length=2, max_length=500)
    sensitivity: Literal["internal", "confidential", "restricted"] = "confidential"
    retention_until: str


class MemberInput(BaseModel):
    subject: str = Field(min_length=1, max_length=200)
    role: Literal["viewer", "analyst", "reviewer", "owner"]


class NoteInput(BaseModel):
    body: str = Field(min_length=1, max_length=4000)


class WorkInput(BaseModel):
    title: str = Field(min_length=1, max_length=300)


class AssignmentInput(BaseModel):
    assignee: str = Field(min_length=1, max_length=200)
    status: Literal["open", "in-review", "resolved"]


class JobInput(BaseModel):
    kind: Literal["provider", "media"]
    provider: str | None = None
    target: str | None = None
    source_object_id: str | None = None
    options: dict[str, str] = Field(default_factory=dict)
    disclosure_confirmed: bool = False


class DecisionInput(BaseModel):
    approve: bool
    reason: str = Field(min_length=3, max_length=1000)


class ReportInput(BaseModel):
    markdown: str = Field(min_length=1, max_length=200000)


class HoldInput(BaseModel):
    active: bool
    reason: str = Field(min_length=3, max_length=1000)
    authority: str = Field(min_length=3, max_length=1000)


def create_app(config: TeamConfig | None = None,
               jwks_data: dict[str, Any] | None = None) -> FastAPI:
    config = config or TeamConfig.from_env()
    store = TeamStore(config)
    verifier = TokenVerifier(config.issuer, config.audience, config.jwks_url, jwks_data)
    app = FastAPI(title="OSINT Toolbox Team API", version="1.0.0", docs_url=None, redoc_url=None)
    app.state.store = store

    def actor(request: Request, credentials: HTTPAuthorizationCredentials | None = Depends(AUTH)) -> str:
        if credentials is None or credentials.scheme.lower() != "bearer":
            raise HTTPException(status_code=401, detail="Bearer access token required")
        subject = verifier.verify(credentials.credentials)
        request.state.actor = subject
        return subject

    def access(case_id: str, subject: str, minimum: str = "viewer") -> str:
        with store.connect() as conn:
            return store.require(conn, case_id, subject, minimum)

    @app.exception_handler(LookupError)
    async def missing(_: Request, exc: LookupError) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=404)

    @app.exception_handler(PermissionError)
    async def forbidden(_: Request, exc: PermissionError) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=403)

    @app.exception_handler(ValueError)
    async def bad_request(_: Request, exc: ValueError) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=400)

    @app.middleware("http")
    async def audit_request(request: Request, call_next):
        response = await call_next(request)
        subject = getattr(request.state, "actor", None)
        if subject:
            # Audit *reads* and denials too. Never log raw query/body/token values.
            with store.connect() as conn:
                store.audit(conn, None, subject, "api.request", "",
                            {"method": request.method, "route": request.scope.get("route").path
                             if request.scope.get("route") else request.url.path,
                             "status": response.status_code})
        return response

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "alive"}

    @app.get("/readyz")
    def readyz() -> dict[str, str]:
        with store.connect() as conn:
            conn.execute("SELECT 1")
        return {"status": "ready"}

    @app.post("/cases", status_code=201)
    def create_case(payload: CaseInput, subject: str = Depends(actor)) -> dict[str, Any]:
        if subject not in config.admin_subjects:
            raise PermissionError("Only configured administrators can create cases")
        return store.create_case(subject, payload.model_dump())

    @app.get("/cases")
    def list_cases(subject: str = Depends(actor)) -> list[dict[str, Any]]:
        return store.list_cases(subject)

    @app.get("/cases/{case_id}")
    def get_case(case_id: str, subject: str = Depends(actor)) -> dict[str, Any]:
        access(case_id, subject)
        with store.connect() as conn:
            return store.case(conn, case_id)

    @app.put("/cases/{case_id}/members")
    def grant_member(case_id: str, payload: MemberInput,
                     subject: str = Depends(actor)) -> dict[str, str]:
        store.grant(case_id, subject, payload.subject, payload.role)
        return {"subject": payload.subject, "role": payload.role}

    @app.post("/cases/{case_id}/objects", status_code=201)
    async def upload(case_id: str, request: Request,
                     subject: str = Depends(actor)) -> dict[str, Any]:
        access(case_id, subject, "analyst")
        declared = request.headers.get("content-length")
        if declared and int(declared) > MAX_OBJECT_BYTES:
            raise HTTPException(413, "Object exceeds 20 MiB")
        chunks = []
        size = 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > MAX_OBJECT_BYTES:
                raise HTTPException(413, "Object exceeds 20 MiB")
            chunks.append(chunk)
        filename = request.headers.get("x-filename", "artifact.bin")
        return store.put_object(case_id, subject, b"".join(chunks), filename,
                                request.headers.get("content-type", "application/octet-stream"))

    @app.get("/cases/{case_id}/objects/{object_id}")
    def download(case_id: str, object_id: str,
                 subject: str = Depends(actor)) -> Response:
        access(case_id, subject, "analyst")
        row, data = store.read_object(case_id, object_id)
        return Response(data, media_type=row["content_type"],
                        headers={"X-Content-SHA256": row["sha256"], "Cache-Control": "no-store"})

    @app.post("/cases/{case_id}/annotations", status_code=201)
    def add_annotation(case_id: str, payload: NoteInput,
                       subject: str = Depends(actor)) -> dict[str, Any]:
        return store.add_annotation(case_id, subject, payload.body)

    @app.get("/cases/{case_id}/annotations")
    def annotations(case_id: str, subject: str = Depends(actor)) -> list[dict[str, Any]]:
        access(case_id, subject)
        with store.connect() as conn:
            return conn.execute("""SELECT * FROM team_annotations WHERE case_id=%s
                ORDER BY created_at DESC LIMIT 500""", (case_id,)).fetchall()

    @app.post("/cases/{case_id}/work", status_code=201)
    def add_work(case_id: str, payload: WorkInput,
                 subject: str = Depends(actor)) -> dict[str, Any]:
        return store.add_work(case_id, subject, payload.title)

    @app.put("/cases/{case_id}/work/{work_id}/assignment")
    def assign(case_id: str, work_id: str, payload: AssignmentInput,
               subject: str = Depends(actor)) -> dict[str, Any]:
        return store.assign_work(case_id, work_id, subject, payload.assignee, payload.status)

    @app.get("/cases/{case_id}/review-queue")
    def review_queue(case_id: str, subject: str = Depends(actor)) -> dict[str, Any]:
        access(case_id, subject, "reviewer")
        with store.connect() as conn:
            return {
                "jobs": conn.execute("SELECT * FROM team_jobs WHERE case_id=%s AND status='pending' ORDER BY created_at",
                                     (case_id,)).fetchall(),
                "reports": conn.execute("SELECT * FROM team_reports WHERE case_id=%s AND status='draft' ORDER BY version",
                                        (case_id,)).fetchall(),
                "work": conn.execute("SELECT * FROM team_work_items WHERE case_id=%s AND status='in-review' ORDER BY created_at",
                                     (case_id,)).fetchall(),
            }

    @app.post("/cases/{case_id}/jobs", status_code=201)
    def request_job(case_id: str, payload: JobInput,
                    subject: str = Depends(actor)) -> dict[str, Any]:
        access(case_id, subject, "analyst")
        if payload.kind == "provider":
            if payload.provider not in ALLOWED_TEAM_PROVIDERS or not payload.disclosure_confirmed:
                raise ValueError("Only allowlisted passive providers with explicit disclosure confirmation are enabled")
            with store.connect() as conn:
                case = store.case(conn, case_id)
            if payload.target != case["target"]:
                raise ValueError("Team provider target must exactly match the authorized case target")
            _validate_collection_options(payload.provider, payload.options)
            if PROVIDERS[payload.provider]["target_disclosure"] != "external":
                raise ValueError("Unexpected provider disclosure class")
        elif payload.kind == "media":
            if payload.provider not in {"ffprobe", "exiftool"} or payload.options:
                raise ValueError("Only bounded ffprobe and ExifTool media jobs are enabled")
        return store.request_job(case_id, subject, payload.kind, payload.provider,
                                 payload.target, payload.source_object_id, payload.options)

    @app.post("/cases/{case_id}/jobs/{job_id}/review")
    def review_job(case_id: str, job_id: str, payload: DecisionInput,
                   subject: str = Depends(actor)) -> dict[str, Any]:
        return store.review_job(case_id, job_id, subject, payload.approve, payload.reason)

    @app.post("/cases/{case_id}/reports", status_code=201)
    def add_report(case_id: str, payload: ReportInput,
                   subject: str = Depends(actor)) -> dict[str, Any]:
        return store.add_report(case_id, subject, payload.markdown)

    @app.post("/cases/{case_id}/reports/{report_id}/review")
    def review_report(case_id: str, report_id: str, payload: DecisionInput,
                      subject: str = Depends(actor)) -> dict[str, Any]:
        return store.review_report(case_id, report_id, subject, payload.approve, payload.reason)

    @app.get("/cases/{case_id}/reports/{report_id}")
    def get_report(case_id: str, report_id: str,
                   subject: str = Depends(actor)) -> Response:
        role = access(case_id, subject)
        with store.connect() as conn:
            report = conn.execute("SELECT * FROM team_reports WHERE case_id=%s AND report_id=%s",
                                  (case_id, report_id)).fetchone()
        if not report or (role == "viewer" and report["status"] != "approved"):
            raise LookupError("Report not found")
        _, data = store.read_object(case_id, report["object_id"])
        return Response(data, media_type="text/markdown", headers={"Cache-Control": "no-store"})

    @app.post("/cases/{case_id}/legal-hold")
    def legal_hold(case_id: str, payload: HoldInput,
                   subject: str = Depends(actor)) -> dict[str, Any]:
        return store.set_hold(case_id, subject, payload.active, payload.reason, payload.authority)

    @app.get("/cases/{case_id}/audit")
    def case_audit(case_id: str, subject: str = Depends(actor)) -> list[dict[str, Any]]:
        access(case_id, subject, "reviewer")
        with store.connect() as conn:
            return conn.execute("SELECT * FROM team_audit WHERE case_id=%s ORDER BY event_id DESC LIMIT 500",
                                (case_id,)).fetchall()

    @app.get("/cases/{case_id}/export")
    def case_export(case_id: str, subject: str = Depends(actor)) -> Response:
        content = store.export_case(case_id, subject)
        return Response(content, media_type="application/zip",
                        headers={"Cache-Control": "no-store", "Content-Disposition": "attachment; filename=case-export.zip"})

    @app.get("/metrics")
    def metrics(subject: str = Depends(actor)) -> dict[str, Any]:
        if subject not in config.admin_subjects:
            raise PermissionError("Metrics require administrator role")
        with store.connect() as conn:
            return {"cases": conn.execute("SELECT count(*) AS n FROM team_cases WHERE deleted_at IS NULL").fetchone()["n"],
                    "queued_jobs": conn.execute("SELECT count(*) AS n FROM team_jobs WHERE status='approved'").fetchone()["n"],
                    "failed_jobs": conn.execute("SELECT count(*) AS n FROM team_jobs WHERE status='failed'").fetchone()["n"]}

    return app
