"""Exact-target, ledger-backed approval gates for licensed providers."""
from __future__ import annotations

import ipaddress
import os
import re
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

from .case import _append_record, _known_ids, append_ledger, assert_case_mutable
from .locking import case_lock
from .util import canonical_json, ensure_case, new_id, read_json, read_jsonl, sha256_bytes, utc_now


POLICY_FILE = Path(__file__).parent / "data" / "provider_policies.json"
REGISTRY_FILE = Path(__file__).parent / "data" / "registries.json"


@lru_cache(maxsize=1)
def provider_profiles() -> dict[str, dict[str, Any]]:
    return read_json(POLICY_FILE)["profiles"]


def registry_profiles(jurisdiction: str = "") -> list[dict[str, Any]]:
    rows = read_json(REGISTRY_FILE)["registries"]
    return [row for row in rows if not jurisdiction or row["jurisdiction"] == jurisdiction.upper()]


def profile_digest(provider: str) -> str:
    return sha256_bytes(canonical_json(provider_profiles()[provider]).encode("utf-8"))


def normalized_target(provider: str, target: str) -> str:
    profile = provider_profiles()[provider]
    raw = target.strip()
    target_type = profile["target_type"]
    if target_type == "email":
        if not re.fullmatch(r"[^\s@/]+@[^\s@/]+\.[^\s@/]+", raw):
            raise ValueError("Provider target must be one email address")
        return raw.casefold()
    if target_type == "domain":
        label = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
        if len(raw) > 253 or not re.fullmatch(rf"{label}(?:\.{label})+", raw):
            raise ValueError("Provider target must be one domain")
        return raw.lower()
    if target_type == "ip":
        try:
            address = ipaddress.ip_address(raw)
        except ValueError as exc:
            raise ValueError("Provider target must be one IP address") from exc
        if not address.is_global:
            raise ValueError("Provider target must be a globally routable IP address")
        return address.compressed
    if target_type == "organization":
        if not 3 <= len(raw) <= 160 or any(ord(c) < 32 for c in raw):
            raise ValueError("Provider organization query must contain 3–160 printable characters")
        return " ".join(raw.split())
    raise ValueError(f"Provider target type is not supported by collection: {target_type}")


def _retention_ready(case_record: dict[str, Any], pii: bool) -> None:
    if not pii:
        return
    raw = case_record.get("retention_until", "")
    try:
        date = datetime.strptime(raw, "%Y-%m-%d").date()
    except ValueError as exc:
        raise ValueError("PII provider collection requires a future ISO retention date on the case") from exc
    if date <= datetime.now(timezone.utc).date():
        raise ValueError("PII provider collection requires a future ISO retention date on the case")


def approve_provider(
    case: str | Path, provider: str, target: str, basis: str, reason: str,
    reviewer: str, actor: str, expires_at: str, max_runs: int = 1,
    authority_artifact_id: str = "", terms_reviewed: bool = False,
    data_residency_accepted: bool = False, cost_acknowledged: bool = False,
    data_residency_note: str = "", cost_note: str = "",
) -> dict[str, Any]:
    profiles = provider_profiles()
    if provider not in profiles or profiles[provider]["mode"] != "api":
        raise ValueError("Provider has no enabled API adapter and cannot be approved for collection")
    profile = profiles[provider]
    case_dir = ensure_case(case)
    case_record = read_json(case_dir / "case.json")
    assert_case_mutable(case_dir)
    if not str(case_record.get("authority", "")).strip():
        raise ValueError("Case authority must be recorded before provider approval")
    _retention_ready(case_record, profile["pii"])
    selected = normalized_target(provider, target)
    if basis not in profile["allowed_basis"]:
        raise ValueError(f"Authorization basis for {provider} must be one of: {', '.join(profile['allowed_basis'])}")
    if not all((terms_reviewed, data_residency_accepted, cost_acknowledged)):
        raise ValueError("Approval requires explicit terms, data-residency, and cost acknowledgments")
    if not data_residency_note.strip() or not cost_note.strip():
        raise ValueError("Approval must record the reviewed data-residency and cost/credit terms")
    if not reason.strip() or not reviewer.strip() or not actor.strip() or reviewer.strip().casefold() == actor.strip().casefold():
        raise ValueError("Approval requires a reason and distinct, named reviewer and actor")
    if not 1 <= max_runs <= 100:
        raise ValueError("max_runs must be between 1 and 100")
    try:
        expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Approval expiry must be a timezone-aware ISO datetime") from exc
    if expiry.tzinfo is None:
        raise ValueError("Approval expiry must include a UTC offset or Z")
    now = datetime.now(timezone.utc)
    if not now < expiry.astimezone(timezone.utc) <= now + timedelta(days=90):
        raise ValueError("Approval must expire within 90 days and be in the future")
    if provider == "hibp-account" and basis == "self":
        if case_record.get("target_type") != "email" or case_record.get("target", "").strip().casefold() != selected:
            raise ValueError("Self HIBP search requires the case target to be the same email address")
    if basis in {"documented-consent", "organization-authorized", "asset-authorized"} and not authority_artifact_id:
        raise ValueError("This authorization basis requires a preserved authority artifact")
    if authority_artifact_id and authority_artifact_id not in _known_ids(case_dir, "artifacts.jsonl", "artifact_id"):
        raise ValueError("Unknown authority artifact ID")
    record = {
        "approval_id": new_id("APP"), "action": "approved", "provider": provider,
        "target": selected, "basis": basis, "authority_artifact_id": authority_artifact_id,
        "reviewer": reviewer.strip(), "actor": actor.strip(), "reason": reason.strip(),
        "terms_url": profile["terms_url"], "profile_sha256": profile_digest(provider),
        "data_residency_note": data_residency_note.strip(), "cost_note": cost_note.strip(),
        "expires_at_utc": expiry.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "max_runs": max_runs, "reverses_id": "", "created_at_utc": utc_now(),
    }
    return _append_record(case_dir, "provider_approvals.jsonl", "provider-approval.recorded", record, record["actor"])


def revoke_provider_approval(case: str | Path, approval_id: str, reason: str, actor: str = "operator") -> dict[str, Any]:
    case_dir = ensure_case(case)
    rows = read_jsonl(case_dir / "provider_approvals.jsonl")
    approved = next((r for r in rows if r["approval_id"] == approval_id and r["action"] == "approved"), None)
    if approved is None or any(r["action"] == "revoked" and r["reverses_id"] == approval_id for r in rows):
        raise ValueError("Approval is unknown or already revoked")
    if not reason.strip():
        raise ValueError("Revocation reason is required")
    record = {**approved, "approval_id": new_id("APP"), "action": "revoked", "reverses_id": approval_id,
              "reason": reason.strip(), "actor": actor.strip() or "operator", "created_at_utc": utc_now()}
    return _append_record(case_dir, "provider_approvals.jsonl", "provider-approval.recorded", record, record["actor"])


def reserve_approved_run(case: str | Path, provider: str, target: str, actor: str) -> str:
    """Reserve one run under a lock before any network request can occur."""
    case_dir = ensure_case(case)
    profile = provider_profiles().get(provider)
    if profile is None or profile["mode"] != "api":
        raise ValueError(f"No approved API policy profile exists for {provider}")
    selected = normalized_target(provider, target)
    with case_lock(case_dir):
        assert_case_mutable(case_dir)
        _retention_ready(read_json(case_dir / "case.json"), profile["pii"])
        key = os.environ.get(profile["credential_env"], "").strip()
        if not key or "\r" in key or "\n" in key:
            raise ValueError(f"{provider} requires a valid {profile['credential_env']} environment credential")
        if provider.startswith("hibp-") and not re.fullmatch(r"[a-fA-F0-9]{32}", key):
            raise ValueError("HIBP_API_KEY must be a 32-character hexadecimal subscription key")
        rows = read_jsonl(case_dir / "provider_approvals.jsonl")
        revoked = {r["reverses_id"] for r in rows if r["action"] == "revoked"}
        now = datetime.now(timezone.utc)
        candidates = [r for r in rows if r["action"] == "approved" and r["provider"] == provider and
                      r["target"] == selected and r["approval_id"] not in revoked and
                      r["profile_sha256"] == profile_digest(provider) and
                      datetime.fromisoformat(r["expires_at_utc"].replace("Z", "+00:00")) > now]
        if not candidates:
            raise ValueError("No current, exact-target approval matches this provider and policy profile")
        reservations = read_jsonl(case_dir / "ledger.jsonl")
        for approval in reversed(candidates):
            used = sum(entry.get("action") == "provider.approved-run-reserved" and
                       entry.get("payload", {}).get("approval_id") == approval["approval_id"] for entry in reservations)
            if used < approval["max_runs"]:
                append_ledger(case_dir, "provider.approved-run-reserved", {
                    "approval_id": approval["approval_id"], "provider": provider, "target": selected,
                    "reservation_id": new_id("RSV"), "reserved_at_utc": utc_now(),
                }, actor.strip() or "operator", _already_locked=True)
                return approval["approval_id"]
        raise ValueError("Approved run limit reached; obtain a new exact-target approval")
