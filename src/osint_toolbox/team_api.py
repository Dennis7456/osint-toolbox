"""HTTP transport only; TeamService owns application authorization and policy."""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any
from urllib.parse import urlsplit

import jwt
import psycopg
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import ValidationError
from starlette.concurrency import run_in_threadpool

from . import __version__
from .team_models import (AssignmentInput, CaseInput, DecisionInput, HoldInput, JobInput,
                          MemberInput, NoteInput, ReasonInput, ReportInput, RetentionInput, WorkInput)
from .team_service import ConflictError, QuotaError, TeamService
from .team_store import MAX_OBJECT_BYTES, TeamConfig, TeamStore

AUTH = HTTPBearer(auto_error=False)


class TokenVerifier:
    def __init__(self, issuer: str, audience: str, jwks_url: str,
                 jwks_data: dict[str, Any] | None = None) -> None:
        first, second = urlsplit(issuer), urlsplit(jwks_url)
        if (first.scheme != "https" or second.scheme != "https" or not first.hostname
                or first.hostname != second.hostname or first.port != second.port
                or first.username or second.username or first.fragment or second.fragment):
            raise ValueError("OIDC issuer and JWKS must use the same configured HTTPS origin")
        if not audience:
            raise ValueError("OIDC API audience is required")
        self.issuer, self.audience = issuer, audience
        self.local_keys = jwt.PyJWKSet.from_dict(jwks_data) if jwks_data is not None else None
        self.client = None if self.local_keys else jwt.PyJWKClient(jwks_url, timeout=5, cache_jwk_set=True)

    def verify(self, token: str) -> str:
        try:
            if len(token) > 16384:
                raise jwt.InvalidTokenError("Token too large")
            header = jwt.get_unverified_header(token)
            if header.get("alg") != "RS256" or not header.get("kid"):
                raise jwt.InvalidTokenError("Unsupported algorithm or key")
            if self.local_keys:
                key = next((entry.key for entry in self.local_keys.keys if entry.key_id == header["kid"]), None)
                if key is None:
                    raise jwt.InvalidTokenError("Unknown key")
            else:
                key = self.client.get_signing_key_from_jwt(token).key
            claims = jwt.decode(token, key, algorithms=["RS256"], issuer=self.issuer, audience=self.audience,
                                leeway=30, options={"require": ["exp", "iat", "iss", "aud", "sub"]})
            subject = claims["sub"]
            if not isinstance(subject, str) or not subject.strip() or len(subject) > 200 or any(ord(c) < 32 for c in subject):
                raise jwt.InvalidTokenError("Invalid subject")
            return subject
        except (jwt.PyJWTError, ValueError, StopIteration):
            raise HTTPException(status_code=401, detail="Invalid access token",
                                headers={"WWW-Authenticate": "Bearer"}) from None


class BodyTooLarge(Exception):
    pass


class RequestLimits:
    """Bound bytes before JSON parsing, including chunked requests."""
    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = dict(scope["headers"])
        maximum = MAX_OBJECT_BYTES if scope["path"].endswith("/objects") else 1024 * 1024
        try:
            declared = int(headers.get(b"content-length", b"0"))
            if declared < 0:
                raise ValueError
        except ValueError:
            await JSONResponse({"detail": "Invalid Content-Length"}, status_code=400)(scope, receive, send)
            return
        if declared > maximum:
            await JSONResponse({"detail": "Request body too large"}, status_code=413)(scope, receive, send)
            return
        consumed = 0

        async def bounded_receive():
            nonlocal consumed
            message = await receive()
            if message["type"] == "http.request":
                consumed += len(message.get("body", b""))
                if consumed > maximum:
                    raise BodyTooLarge()
            return message
        await self.app(scope, bounded_receive, send)


def create_app(config: TeamConfig | None = None, jwks_data: dict[str, Any] | None = None) -> FastAPI:
    config = config or TeamConfig.from_env()
    store = TeamStore(config)
    service = TeamService(store)
    verifier = TokenVerifier(config.issuer, config.audience, config.jwks_url, jwks_data)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await run_in_threadpool(service.ready)
        yield

    app = FastAPI(title="OSINT Toolbox Team API", version=__version__, docs_url=None,
                  redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.store, app.state.service = store, service
    app.add_middleware(RequestLimits)

    def actor(request: Request, credentials: HTTPAuthorizationCredentials | None = Depends(AUTH)) -> str:
        if credentials is None or credentials.scheme.lower() != "bearer":
            raise HTTPException(401, "Bearer access token required", headers={"WWW-Authenticate": "Bearer"})
        request.state.actor = verifier.verify(credentials.credentials)
        return request.state.actor

    @app.exception_handler(LookupError)
    async def missing(_: Request, exc: LookupError) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=404)

    @app.exception_handler(PermissionError)
    async def forbidden(_: Request, exc: PermissionError) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=403)

    @app.exception_handler(ConflictError)
    async def conflict(_: Request, exc: ConflictError) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=409)

    @app.exception_handler(QuotaError)
    async def quota(_: Request, exc: QuotaError) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=429, headers={"Retry-After": "60"})

    @app.exception_handler(ValueError)
    async def invalid(_: Request, exc: ValueError) -> JSONResponse:
        return JSONResponse({"detail": "Invalid application input"}, status_code=400)

    @app.exception_handler(ValidationError)
    @app.exception_handler(RequestValidationError)
    async def validation(_: Request, exc: Exception) -> JSONResponse:
        # Pydantic errors may contain entire submitted values, including secrets.
        return JSONResponse({"detail": "Invalid request fields"}, status_code=422)

    @app.exception_handler(BodyTooLarge)
    async def oversized(_: Request, exc: BodyTooLarge) -> JSONResponse:
        return JSONResponse({"detail": "Request body too large"}, status_code=413)

    @app.exception_handler(psycopg.Error)
    async def unavailable(_: Request, exc: psycopg.Error) -> JSONResponse:
        return JSONResponse({"detail": "Database unavailable or operation conflicted"}, status_code=503)

    def audit_request(subject: str, method: str, route: str, status: int) -> None:
        with store.transaction() as tx:
            store.audit(tx, None, subject, "api.request", "",
                        {"method": method, "route": route, "status": status})

    @app.middleware("http")
    async def audit_and_headers(request: Request, call_next):
        response = await call_next(request)
        route = request.scope.get("route")
        if request.url.path not in {"/healthz", "/readyz"}:
            # Unknown paths, query/body contents and tokens are never logged.
            try:
                await run_in_threadpool(audit_request, getattr(request.state, "actor", "unauthenticated"),
                                        request.method, route.path if route else "<unmatched>", response.status_code)
            except psycopg.Error:
                response = JSONResponse({"detail": "Audit storage unavailable"}, status_code=503)
        response.headers.update({"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
                                 "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
                                 "Referrer-Policy": "no-referrer"})
        return response

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "alive"}

    @app.get("/readyz")
    def readyz() -> dict[str, str]:
        return service.ready()

    @app.get("/openapi.json")
    def openapi(subject: str = Depends(actor)) -> dict[str, Any]:
        service._admin(subject)
        return app.openapi()

    @app.post("/cases", status_code=201)
    def create_case(payload: CaseInput, subject: str = Depends(actor)):
        return service.create_case(subject, payload.model_dump())

    @app.get("/cases")
    def list_cases(subject: str = Depends(actor), limit: int = Query(100, ge=1, le=500),
                   offset: int = Query(0, ge=0, le=100000)):
        return service.list_cases(subject, limit, offset)

    @app.get("/cases/{case_id}")
    def get_case(case_id: str, subject: str = Depends(actor)):
        return service.get_case(case_id, subject)

    @app.put("/cases/{case_id}/members")
    def grant(case_id: str, payload: MemberInput, subject: str = Depends(actor)):
        service.grant(case_id, subject, payload.subject, payload.role)
        return {"subject": payload.subject, "role": payload.role}

    @app.delete("/cases/{case_id}/members/{member_subject}", status_code=204)
    def revoke(case_id: str, member_subject: str, subject: str = Depends(actor)):
        service.revoke(case_id, subject, member_subject)
        return Response(status_code=204)

    @app.post("/cases/{case_id}/objects", status_code=201)
    async def upload(case_id: str, request: Request, subject: str = Depends(actor)):
        await run_in_threadpool(service.authorize_upload, case_id, subject)
        data = await request.body()
        return await run_in_threadpool(service.put_object, case_id, subject, data,
                                       request.headers.get("x-filename", "artifact.bin"),
                                       request.headers.get("content-type", "application/octet-stream").split(";")[0])

    @app.get("/cases/{case_id}/objects/{object_id}")
    def download(case_id: str, object_id: str, subject: str = Depends(actor)):
        row, data = service.read_object(case_id, subject, object_id)
        # Never execute an uploaded HTML/SVG/script in the API origin.
        return Response(data, media_type="application/octet-stream",
                        headers={"Content-Disposition": 'attachment; filename="artifact.bin"',
                                 "X-Content-SHA256": row["sha256"]})

    @app.post("/cases/{case_id}/annotations", status_code=201)
    def annotate(case_id: str, payload: NoteInput, subject: str = Depends(actor)):
        return service.add_annotation(case_id, subject, payload.body)

    @app.post("/cases/{case_id}/work", status_code=201)
    def add_work(case_id: str, payload: WorkInput, subject: str = Depends(actor)):
        return service.add_work(case_id, subject, payload.title)

    @app.put("/cases/{case_id}/work/{work_id}/assignment")
    def assign(case_id: str, work_id: str, payload: AssignmentInput, subject: str = Depends(actor)):
        return service.assign_work(case_id, work_id, subject, payload.assignee, payload.status)

    @app.get("/cases/{case_id}/review-queue")
    def review_queue(case_id: str, subject: str = Depends(actor),
                     limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0, le=100000)):
        return service.review_queue(case_id, subject, limit, offset)

    @app.post("/cases/{case_id}/jobs", status_code=201)
    def request_job(case_id: str, payload: JobInput, request: Request, subject: str = Depends(actor)):
        return service.request_job(case_id, subject, payload.model_dump(), request.headers.get("Idempotency-Key"))

    @app.get("/cases/{case_id}/jobs/{job_id}")
    def get_job(case_id: str, job_id: str, subject: str = Depends(actor)):
        return service.get_job(case_id, subject, job_id)

    @app.post("/cases/{case_id}/jobs/{job_id}/review")
    def review_job(case_id: str, job_id: str, payload: DecisionInput, subject: str = Depends(actor)):
        return service.review_job(case_id, job_id, subject, payload.approve, payload.reason)

    @app.post("/cases/{case_id}/jobs/{job_id}/cancel")
    def cancel_job(case_id: str, job_id: str, payload: ReasonInput, subject: str = Depends(actor)):
        return service.cancel_job(case_id, subject, job_id, payload.reason)

    @app.post("/cases/{case_id}/jobs/{job_id}/retry")
    def retry_job(case_id: str, job_id: str, payload: ReasonInput, subject: str = Depends(actor)):
        return service.retry_job(case_id, subject, job_id, payload.reason)

    @app.post("/cases/{case_id}/reports", status_code=201)
    def report(case_id: str, payload: ReportInput, subject: str = Depends(actor)):
        return service.add_report(case_id, subject, payload.markdown)

    @app.post("/cases/{case_id}/reports/{report_id}/review")
    def review_report(case_id: str, report_id: str, payload: DecisionInput, subject: str = Depends(actor)):
        return service.review_report(case_id, report_id, subject, payload.approve, payload.reason)

    @app.get("/cases/{case_id}/reports/{report_id}")
    def read_report(case_id: str, report_id: str, subject: str = Depends(actor)):
        return Response(service.read_report(case_id, subject, report_id), media_type="text/markdown",
                        headers={"Content-Disposition": 'attachment; filename="report.md"'})

    @app.post("/cases/{case_id}/legal-hold")
    def hold(case_id: str, payload: HoldInput, subject: str = Depends(actor)):
        return service.set_hold(case_id, subject, payload.active, payload.reason, payload.authority)

    @app.put("/cases/{case_id}/retention")
    def retention(case_id: str, payload: RetentionInput, subject: str = Depends(actor)):
        return service.set_retention(case_id, subject, payload.retention_until, payload.reason)

    @app.get("/cases/{case_id}/export")
    def export(case_id: str, subject: str = Depends(actor)):
        return Response(service.export_case(case_id, subject), media_type="application/zip",
                        headers={"Content-Disposition": 'attachment; filename="case-export.zip"'})

    @app.get("/metrics")
    def metrics(subject: str = Depends(actor)):
        return service.metrics(subject)

    # Registered last so concrete resource routes always take precedence.
    @app.get("/cases/{case_id}/{collection}")
    def records(case_id: str, collection: str, subject: str = Depends(actor),
                limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0, le=100000)):
        return service.list_records(case_id, subject, collection, limit, offset)

    return app
