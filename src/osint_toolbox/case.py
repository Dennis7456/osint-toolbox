from __future__ import annotations

import json
import mimetypes
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .locking import case_lock
from .schema_validation import validate_or_raise, validation_issues
from .transactions import (
    TRANSACTION_DIRECTORY,
    commit_transaction,
    orphan_payload_paths,
    pending_transaction_paths,
    recover_pending_transactions,
    transaction_id,
    transaction_payload_path,
)
from .util import (
    canonical_json,
    copy_file_atomic,
    ensure_case,
    new_id,
    read_json,
    read_jsonl,
    normalize_event_time,
    safe_filename,
    sha256_bytes,
    sha256_file,
    slugify,
    utc_now,
    write_bytes,
    write_json,
)


SCHEMA_VERSION = "1.4"
CONFIDENCE_VALUES = {"high", "medium", "low", "unknown"}
DATA_FILES = {
    "source.added": "sources.jsonl",
    "artifact.added": "artifacts.jsonl",
    "observation.added": "observations.jsonl",
    "entity.added": "entities.jsonl",
    "relationship.added": "relationships.jsonl",
    "event.added": "events.jsonl",
    "derivation.added": "derivations.jsonl",
    "claim.added": "claims.jsonl",
    "provider.run-recorded": "provider_runs.jsonl",
    "legal-hold.recorded": "legal_holds.jsonl",
    "resolution.recorded": "resolutions.jsonl",
    "worksheet.recorded": "worksheets.jsonl",
    "audit-review.recorded": "audit_reviews.jsonl",
    "provider-approval.recorded": "provider_approvals.jsonl",
}


def _state_hash(value: dict[str, Any]) -> str:
    return sha256_bytes(canonical_json(value).encode("utf-8"))


def _empty_legal_hold() -> dict[str, Any]:
    return {
        "active": False,
        "hold_id": "",
        "reason": "",
        "authority": "",
        "set_at_utc": "",
        "set_by": "",
        "released_at_utc": "",
        "released_by": "",
        "release_reason": "",
        "release_authority": "",
    }


def append_ledger(
    case_dir: Path,
    action: str,
    payload: dict[str, Any],
    actor: str,
    _already_locked: bool = False,
) -> dict[str, Any]:
    if not _already_locked:
        with case_lock(case_dir):
            return append_ledger(case_dir, action, payload, actor, _already_locked=True)
    entries = commit_transaction(
        case_dir,
        action,
        [],
        [{"action": action, "payload": payload, "actor": actor.strip() or "operator"}],
    )
    return entries[0]


def create_case(
    output: str | Path,
    title: str,
    purpose: str,
    authority: str,
    target_type: str,
    target: str,
    owner: str = "",
    sensitivity: str = "internal",
    retention_until: str = "",
    reviewers: list[str] | None = None,
    jurisdictions: list[str] | None = None,
    collection_tier: str = "passive-public",
) -> Path:
    if not all(value.strip() for value in (title, purpose, authority, target_type, target)):
        raise ValueError("title, purpose, authority, target type, and target are required")
    base = Path(output).expanduser().resolve()
    base.mkdir(parents=True, exist_ok=True)
    date = utc_now()[:10].replace("-", "")
    case_id = f"CASE-{date}-{slugify(title, 32).upper()}-{new_id('X').split('-')[1][:6]}"
    case_dir = base / case_id
    case_dir.mkdir()
    for directory in ("artifacts", "notes", "reports"):
        (case_dir / directory).mkdir()
    case_record = {
        "schema_version": SCHEMA_VERSION,
        "case_id": case_id,
        "title": title.strip(),
        "purpose": purpose.strip(),
        "authority": authority.strip(),
        "target_type": target_type.strip().lower(),
        "target": target.strip(),
        "owner": owner.strip(),
        "sensitivity": _require_enum(
            sensitivity, {"public", "internal", "confidential", "restricted"}, "Case sensitivity"
        ),
        "retention_until": retention_until.strip(),
        "reviewers": sorted(set(item.strip() for item in (reviewers or []) if item.strip())),
        "jurisdictions": sorted(set(item.strip() for item in (jurisdictions or []) if item.strip())),
        "collection_tier": _require_enum(
            collection_tier, {"manual-public", "passive-public", "approved-licensed"}, "Collection tier"
        ),
        "created_at_utc": utc_now(),
        "status": "open",
        "legal_hold": _empty_legal_hold(),
    }
    validate_or_raise("case", case_record, "Case metadata")
    commit_transaction(
        case_dir,
        "case.created",
        [
            *[
                {"type": "touch_file", "path": filename}
                for filename in sorted(set(DATA_FILES.values()))
            ],
            {"type": "json_create", "path": "case.json", "value": case_record},
        ],
        [{"action": "case.created", "payload": case_record, "actor": owner or "operator"}],
    )
    return case_dir


def update_case_status(
    case: str | Path,
    status: str,
    note: str,
    actor: str = "operator",
) -> dict[str, Any]:
    case_dir = ensure_case(case)
    with case_lock(case_dir):
        ok, issues = verify_case(case_dir)
        if not ok:
            raise ValueError("Case integrity must pass before a status change: " + "; ".join(issues))
        record = read_json(case_dir / "case.json")
        previous_status = record["status"]
        next_status = _require_enum(status, {"open", "review", "closed", "archived"}, "Case status")
        if previous_status == next_status:
            raise ValueError(f"Case status is already {next_status}")
        if not note.strip():
            raise ValueError("A status-change note is required")
        record["status"] = next_status
        record["updated_at_utc"] = utc_now()
        validate_or_raise("case", record, "Case metadata")
        commit_transaction(
            case_dir,
            "case.status-changed",
            [{
                "type": "json_replace",
                "path": "case.json",
                "expected_before_sha256": _state_hash(read_json(case_dir / "case.json")),
                "value": record,
            }],
            [{
                "action": "case.status-changed",
                "payload": {
                    "previous_status": previous_status,
                    "new_status": next_status,
                    "note": note.strip(),
                    "previous_case_sha256": _state_hash(read_json(case_dir / "case.json")),
                    "case": record,
                },
                "actor": actor.strip() or "operator",
            }],
        )
    return record


def _migrate_1_0_to_1_1(previous: dict[str, Any]) -> dict[str, Any]:
    migrated = dict(previous)
    migrated.update({
        "schema_version": "1.1",
        "sensitivity": "internal",
        "retention_until": "",
        "reviewers": [],
        "jurisdictions": [],
        "collection_tier": "passive-public",
        "updated_at_utc": utc_now(),
    })
    return migrated


def _migrate_1_1_to_1_2(previous: dict[str, Any]) -> dict[str, Any]:
    migrated = dict(previous)
    migrated.update({
        "schema_version": "1.2",
        "legal_hold": _empty_legal_hold(),
        "updated_at_utc": utc_now(),
    })
    return migrated


def _migrate_1_2_to_1_3(previous: dict[str, Any]) -> dict[str, Any]:
    migrated = dict(previous)
    migrated.update({"schema_version": "1.3", "updated_at_utc": utc_now()})
    return migrated


def _migrate_1_3_to_1_4(previous: dict[str, Any]) -> dict[str, Any]:
    migrated = dict(previous)
    migrated.update({"schema_version": "1.4", "updated_at_utc": utc_now()})
    return migrated


MIGRATIONS = {
    "1.0": ("1.1", _migrate_1_0_to_1_1),
    "1.1": ("1.2", _migrate_1_1_to_1_2),
    "1.2": ("1.3", _migrate_1_2_to_1_3),
    "1.3": ("1.4", _migrate_1_3_to_1_4),
}


def upgrade_case(case: str | Path, actor: str = "operator") -> tuple[dict[str, Any], bool]:
    case_dir = ensure_case(case)
    with case_lock(case_dir):
        previous = read_json(case_dir / "case.json")
        version = previous.get("schema_version")
        if version == SCHEMA_VERSION:
            return previous, False
        if version not in MIGRATIONS:
            raise ValueError(f"No migration is available from schema version: {version}")
        for filename in set(DATA_FILES.values()):
            (case_dir / filename).touch(exist_ok=True)
        _, issues = verify_case(case_dir)
        material_issues = [
            issue for issue in issues
            if not issue.startswith("Unsupported schema version:")
            and not issue.startswith("case.json JSON Schema validation")
        ]
        if material_issues:
            raise ValueError("Case integrity must pass before migration: " + "; ".join(material_issues))
        migrated = previous
        changed = False
        while migrated.get("schema_version") != SCHEMA_VERSION:
            from_version = str(migrated.get("schema_version"))
            migration = MIGRATIONS.get(from_version)
            if migration is None:
                raise ValueError(f"No migration is available from schema version: {from_version}")
            to_version, migrate = migration
            next_record = migrate(migrated)
            if to_version == SCHEMA_VERSION:
                validate_or_raise("case", next_record, "Migrated case metadata")
            previous_hash = _state_hash(migrated)
            commit_transaction(
                case_dir,
                f"case.migrated.{from_version}-to-{to_version}",
                [{
                    "type": "json_replace",
                    "path": "case.json",
                    "expected_before_sha256": previous_hash,
                    "value": next_record,
                }],
                [{
                    "action": "case.migrated",
                    "payload": {
                        "from_version": from_version,
                        "to_version": to_version,
                        "previous_case_sha256": previous_hash,
                        "case": next_record,
                    },
                    "actor": actor.strip() or "operator",
                }],
            )
            migrated = next_record
            changed = True
        return migrated, changed


def place_legal_hold(
    case: str | Path,
    reason: str,
    authority: str,
    actor: str = "operator",
) -> dict[str, Any]:
    case_dir = ensure_case(case)
    if not reason.strip() or not authority.strip():
        raise ValueError("Legal-hold reason and authority are required")
    with case_lock(case_dir):
        ok, issues = verify_case(case_dir)
        if not ok:
            raise ValueError("Case integrity must pass before placing a legal hold: " + "; ".join(issues))
        previous = read_json(case_dir / "case.json")
        if previous["legal_hold"]["active"]:
            raise ValueError(f"Legal hold is already active: {previous['legal_hold']['hold_id']}")
        timestamp = utc_now()
        hold_id = new_id("HLD")
        actor_name = actor.strip() or "operator"
        event = {
            "legal_hold_event_id": new_id("HLE"),
            "hold_id": hold_id,
            "action": "placed",
            "reason": reason.strip(),
            "authority": authority.strip(),
            "actor": actor_name,
            "created_at_utc": timestamp,
        }
        validate_or_raise("record", event, "Legal-hold event")
        updated = dict(previous)
        updated["legal_hold"] = {
            "active": True,
            "hold_id": hold_id,
            "reason": reason.strip(),
            "authority": authority.strip(),
            "set_at_utc": timestamp,
            "set_by": actor_name,
            "released_at_utc": "",
            "released_by": "",
            "release_reason": "",
            "release_authority": "",
        }
        updated["updated_at_utc"] = timestamp
        validate_or_raise("case", updated, "Case metadata")
        previous_hash = _state_hash(previous)
        commit_transaction(
            case_dir,
            "legal-hold.placed",
            [
                {"type": "jsonl_append", "path": "legal_holds.jsonl", "record": event},
                {
                    "type": "json_replace",
                    "path": "case.json",
                    "expected_before_sha256": previous_hash,
                    "value": updated,
                },
            ],
            [
                {"action": "legal-hold.recorded", "payload": event, "actor": actor_name},
                {
                    "action": "case.legal-hold-changed",
                    "payload": {
                        "previous_case_sha256": previous_hash,
                        "previous_active": False,
                        "new_active": True,
                        "hold_id": hold_id,
                        "case": updated,
                    },
                    "actor": actor_name,
                },
            ],
        )
        return updated["legal_hold"]


def release_legal_hold(
    case: str | Path,
    reason: str,
    authority: str,
    actor: str = "operator",
) -> dict[str, Any]:
    case_dir = ensure_case(case)
    if not reason.strip() or not authority.strip():
        raise ValueError("Legal-hold release reason and authority are required")
    with case_lock(case_dir):
        ok, issues = verify_case(case_dir)
        if not ok:
            raise ValueError("Case integrity must pass before releasing a legal hold: " + "; ".join(issues))
        previous = read_json(case_dir / "case.json")
        hold = previous["legal_hold"]
        if not hold["active"]:
            raise ValueError("Case has no active legal hold")
        timestamp = utc_now()
        actor_name = actor.strip() or "operator"
        event = {
            "legal_hold_event_id": new_id("HLE"),
            "hold_id": hold["hold_id"],
            "action": "released",
            "reason": reason.strip(),
            "authority": authority.strip(),
            "actor": actor_name,
            "created_at_utc": timestamp,
        }
        validate_or_raise("record", event, "Legal-hold event")
        updated = dict(previous)
        updated_hold = dict(hold)
        updated_hold.update({
            "active": False,
            "released_at_utc": timestamp,
            "released_by": actor_name,
            "release_reason": reason.strip(),
            "release_authority": authority.strip(),
        })
        updated["legal_hold"] = updated_hold
        updated["updated_at_utc"] = timestamp
        validate_or_raise("case", updated, "Case metadata")
        previous_hash = _state_hash(previous)
        commit_transaction(
            case_dir,
            "legal-hold.released",
            [
                {"type": "jsonl_append", "path": "legal_holds.jsonl", "record": event},
                {
                    "type": "json_replace",
                    "path": "case.json",
                    "expected_before_sha256": previous_hash,
                    "value": updated,
                },
            ],
            [
                {"action": "legal-hold.recorded", "payload": event, "actor": actor_name},
                {
                    "action": "case.legal-hold-changed",
                    "payload": {
                        "previous_case_sha256": previous_hash,
                        "previous_active": True,
                        "new_active": False,
                        "hold_id": hold["hold_id"],
                        "case": updated,
                    },
                    "actor": actor_name,
                },
            ],
        )
        return updated["legal_hold"]


def update_case_retention(
    case: str | Path,
    retention_until: str,
    note: str,
    actor: str = "operator",
) -> dict[str, Any]:
    case_dir = ensure_case(case)
    if not note.strip():
        raise ValueError("A retention-change note is required")
    with case_lock(case_dir):
        ok, issues = verify_case(case_dir)
        if not ok:
            raise ValueError("Case integrity must pass before changing retention: " + "; ".join(issues))
        previous = read_json(case_dir / "case.json")
        if previous["legal_hold"]["active"]:
            raise ValueError("Retention cannot be changed while a legal hold is active")
        next_value = retention_until.strip()
        if previous["retention_until"] == next_value:
            raise ValueError("Case retention is already set to that value")
        updated = dict(previous)
        updated["retention_until"] = next_value
        updated["updated_at_utc"] = utc_now()
        validate_or_raise("case", updated, "Case metadata")
        previous_hash = _state_hash(previous)
        commit_transaction(
            case_dir,
            "case.retention-changed",
            [{
                "type": "json_replace",
                "path": "case.json",
                "expected_before_sha256": previous_hash,
                "value": updated,
            }],
            [{
                "action": "case.retention-changed",
                "payload": {
                    "previous_retention_until": previous["retention_until"],
                    "new_retention_until": next_value,
                    "note": note.strip(),
                    "previous_case_sha256": previous_hash,
                    "case": updated,
                },
                "actor": actor.strip() or "operator",
            }],
        )
        return updated


def retention_status(case: str | Path) -> dict[str, Any]:
    case_dir = ensure_case(case)
    case_record = read_json(case_dir / "case.json")
    integrity_valid, integrity_issues = verify_case(case_dir)
    hold = case_record.get("legal_hold", _empty_legal_hold())
    retention_until = case_record.get("retention_until", "")
    if hold.get("active"):
        disposition = "held"
    elif not retention_until:
        disposition = "not-set"
    else:
        try:
            retention_date = datetime.strptime(retention_until, "%Y-%m-%d").date()
            disposition = "due" if retention_date <= datetime.now(timezone.utc).date() else "scheduled"
        except ValueError:
            disposition = "policy-label"
    return {
        "case_id": case_record["case_id"],
        "retention_until": retention_until,
        "legal_hold": hold,
        "disposition": disposition,
        "integrity_valid": integrity_valid,
        "integrity_issues": integrity_issues,
    }


def recover_case(case: str | Path, actor: str = "operator") -> dict[str, Any]:
    case_dir = Path(case).expanduser().resolve()
    if not case_dir.is_dir():
        raise ValueError(f"Not an OSINT Toolbox case directory: {case_dir}")
    with case_lock(case_dir):
        result = recover_pending_transactions(case_dir)
        if result["recovered_transaction_ids"] and (case_dir / "case.json").is_file():
            append_ledger(
                case_dir,
                "case.recovery-completed",
                {"recovered_transaction_ids": result["recovered_transaction_ids"]},
                actor.strip() or "operator",
                _already_locked=True,
            )
    if (case_dir / "case.json").is_file():
        result["integrity_valid"], result["integrity_issues"] = verify_case(case_dir)
    else:
        result["integrity_valid"] = False
        result["integrity_issues"] = ["case.json is still missing"]
    return result


def _known_ids(case_dir: Path, filename: str, field: str) -> set[str]:
    return {str(row[field]) for row in read_jsonl(case_dir / filename) if field in row}


def _require_ids(values: list[str], known: set[str], label: str, allow_empty: bool = False) -> None:
    if not values and not allow_empty:
        raise ValueError(f"At least one {label} is required")
    missing = sorted(set(values) - known)
    if missing:
        raise ValueError(f"Unknown {label}s: {', '.join(missing)}")


def _require_enum(value: str, allowed: set[str], label: str) -> str:
    normalized = value.strip().lower()
    if normalized not in allowed:
        raise ValueError(f"{label} must be one of: {', '.join(sorted(allowed))}")
    return normalized


def assert_case_mutable(case: str | Path) -> Path:
    case_dir = ensure_case(case)
    status = read_json(case_dir / "case.json").get("status")
    if status in {"closed", "archived"}:
        raise ValueError(f"Case is {status}; reopen it with set-status before adding records")
    return case_dir


def _append_record(
    case_dir: Path,
    filename: str,
    action: str,
    record: dict[str, Any],
    actor: str,
) -> dict[str, Any]:
    with case_lock(case_dir):
        assert_case_mutable(case_dir)
        validate_or_raise("case", read_json(case_dir / "case.json"), "Case metadata")
        validate_or_raise("record", record, f"{filename} record")
        commit_transaction(
            case_dir,
            action,
            [{"type": "jsonl_append", "path": filename, "record": record}],
            [{"action": action, "payload": record, "actor": actor.strip() or "operator"}],
        )
    return record


def add_source(
    case: str | Path,
    url: str,
    title: str,
    topic: str,
    reliability: str,
    credibility: str,
    notes: str = "",
    collector: str = "operator",
    accessed_at: str | None = None,
) -> dict[str, Any]:
    case_dir = ensure_case(case)
    if not url.startswith(("https://", "http://")):
        raise ValueError("Source URL must start with http:// or https://")
    if not title.strip() or not topic.strip():
        raise ValueError("Source title and topic are required")
    source = {
        "source_id": new_id("SRC"),
        "url": url,
        "title": title.strip(),
        "topic": topic.strip().lower(),
        "reliability": _require_enum(reliability, {"primary", "secondary", "unknown"}, "Source reliability"),
        "credibility": _require_enum(credibility, CONFIDENCE_VALUES, "Source credibility"),
        "notes": notes.strip(),
        "collector": collector.strip() or "operator",
        "accessed_at_utc": accessed_at or utc_now(),
    }
    return _append_record(case_dir, "sources.jsonl", "source.added", source, source["collector"])


def add_artifact_bytes(
    case: str | Path,
    content: bytes,
    original_name: str,
    source_url: str,
    topic: str,
    notes: str = "",
    collector: str = "operator",
    mime_type: str | None = None,
) -> dict[str, Any]:
    case_dir = ensure_case(case)
    artifact_id = new_id("ART")
    clean_name = safe_filename(original_name)
    destination = case_dir / "artifacts" / f"{artifact_id}-{clean_name}"
    txn_id = transaction_id()
    staged = transaction_payload_path(case_dir, txn_id)
    write_bytes(staged, content)
    record = {
        "artifact_id": artifact_id,
        "original_name": Path(original_name).name,
        "stored_path": destination.relative_to(case_dir).as_posix(),
        "sha256": sha256_bytes(content),
        "size_bytes": len(content),
        "mime_type": mime_type or mimetypes.guess_type(clean_name)[0] or "application/octet-stream",
        "source_url": source_url,
        "topic": topic.strip().lower(),
        "notes": notes.strip(),
        "collector": collector.strip() or "operator",
        "collected_at_utc": utc_now(),
    }
    try:
        with case_lock(case_dir):
            assert_case_mutable(case_dir)
            validate_or_raise("case", read_json(case_dir / "case.json"), "Case metadata")
            validate_or_raise("record", record, "Artifact record")
            commit_transaction(
                case_dir,
                "artifact.added",
                [
                    {
                        "type": "install_file",
                        "staged_path": staged.relative_to(case_dir).as_posix(),
                        "destination": destination.relative_to(case_dir).as_posix(),
                        "sha256": record["sha256"],
                        "size_bytes": record["size_bytes"],
                    },
                    {"type": "jsonl_append", "path": "artifacts.jsonl", "record": record},
                ],
                [{"action": "artifact.added", "payload": record, "actor": record["collector"]}],
                txn_id=txn_id,
            )
        return record
    except Exception:
        journal = case_dir / TRANSACTION_DIRECTORY / f"{txn_id}.json"
        if not journal.exists() and staged.exists():
            staged.unlink()
        raise


def add_artifact(
    case: str | Path,
    input_path: str | Path,
    source_url: str,
    topic: str,
    notes: str = "",
    collector: str = "operator",
) -> dict[str, Any]:
    case_dir = ensure_case(case)
    original = Path(input_path).expanduser().resolve()
    if not original.is_file():
        raise ValueError(f"Artifact is not a file: {original}")
    artifact_id = new_id("ART")
    destination = case_dir / "artifacts" / f"{artifact_id}-{safe_filename(original.name)}"
    txn_id = transaction_id()
    staged = transaction_payload_path(case_dir, txn_id)
    copy_file_atomic(original, staged)
    record = {
        "artifact_id": artifact_id,
        "original_name": original.name,
        "stored_path": destination.relative_to(case_dir).as_posix(),
        "sha256": sha256_file(staged),
        "size_bytes": staged.stat().st_size,
        "mime_type": mimetypes.guess_type(destination.name)[0] or "application/octet-stream",
        "source_url": source_url,
        "topic": topic.strip().lower(),
        "notes": notes.strip(),
        "collector": collector.strip() or "operator",
        "collected_at_utc": utc_now(),
    }
    try:
        with case_lock(case_dir):
            assert_case_mutable(case_dir)
            validate_or_raise("case", read_json(case_dir / "case.json"), "Case metadata")
            validate_or_raise("record", record, "Artifact record")
            commit_transaction(
                case_dir,
                "artifact.added",
                [
                    {
                        "type": "install_file",
                        "staged_path": staged.relative_to(case_dir).as_posix(),
                        "destination": destination.relative_to(case_dir).as_posix(),
                        "sha256": record["sha256"],
                        "size_bytes": record["size_bytes"],
                    },
                    {"type": "jsonl_append", "path": "artifacts.jsonl", "record": record},
                ],
                [{"action": "artifact.added", "payload": record, "actor": record["collector"]}],
                txn_id=txn_id,
            )
        return record
    except Exception:
        journal = case_dir / TRANSACTION_DIRECTORY / f"{txn_id}.json"
        if not journal.exists() and staged.exists():
            staged.unlink()
        raise


def add_observation(
    case: str | Path,
    source_id: str,
    kind: str,
    value: Any,
    query: str = "",
    observed_at: str = "",
    artifact_id: str = "",
    status: str = "observed",
    notes: str = "",
    collector: str = "operator",
) -> dict[str, Any]:
    case_dir = ensure_case(case)
    _require_ids([source_id], _known_ids(case_dir, "sources.jsonl", "source_id"), "source ID")
    if artifact_id:
        _require_ids([artifact_id], _known_ids(case_dir, "artifacts.jsonl", "artifact_id"), "artifact ID")
    record = {
        "observation_id": new_id("OBS"),
        "source_id": source_id,
        "kind": kind.strip().lower(),
        "value": value,
        "query": query,
        "observed_at": observed_at,
        "accessed_at_utc": utc_now(),
        "artifact_id": artifact_id,
        "status": _require_enum(
            status,
            {"observed", "unavailable", "conflicting", "retracted", "superseded", "candidate-unverified"},
            "Observation status",
        ),
        "notes": notes.strip(),
        "collector": collector.strip() or "operator",
    }
    if not record["kind"]:
        raise ValueError("Observation kind is required")
    return _append_record(case_dir, "observations.jsonl", "observation.added", record, record["collector"])


def add_entity(
    case: str | Path,
    entity_type: str,
    label: str,
    source_ids: list[str] | None = None,
    aliases: list[str] | None = None,
    attributes: dict[str, Any] | None = None,
    role: str = "candidate",
    confidence: str = "unknown",
    notes: str = "",
    analyst: str = "operator",
) -> dict[str, Any]:
    case_dir = ensure_case(case)
    source_ids = source_ids or []
    _require_ids(source_ids, _known_ids(case_dir, "sources.jsonl", "source_id"), "source ID", allow_empty=True)
    record = {
        "entity_id": new_id("ENT"),
        "entity_type": entity_type.strip().lower(),
        "label": label.strip(),
        "aliases": sorted(set(alias.strip() for alias in (aliases or []) if alias.strip())),
        "attributes": attributes or {},
        "role": _require_enum(role, {"seed", "candidate", "resolved"}, "Entity role"),
        "confidence": _require_enum(confidence, CONFIDENCE_VALUES, "Entity confidence"),
        "source_ids": source_ids,
        "notes": notes.strip(),
        "analyst": analyst.strip() or "operator",
        "created_at_utc": utc_now(),
    }
    if not record["entity_type"] or not record["label"]:
        raise ValueError("Entity type and label are required")
    return _append_record(case_dir, "entities.jsonl", "entity.added", record, record["analyst"])


def add_relationship(
    case: str | Path,
    from_entity_id: str,
    relationship_type: str,
    to_entity_id: str,
    source_ids: list[str],
    evidence_kind: str = "observed",
    confidence: str = "medium",
    observed_at: str = "",
    notes: str = "",
    analyst: str = "operator",
) -> dict[str, Any]:
    case_dir = ensure_case(case)
    entity_ids = _known_ids(case_dir, "entities.jsonl", "entity_id")
    _require_ids([from_entity_id, to_entity_id], entity_ids, "entity ID")
    _require_ids(source_ids, _known_ids(case_dir, "sources.jsonl", "source_id"), "source ID")
    evidence_kind = _require_enum(evidence_kind, {"observed", "inferred"}, "Evidence kind")
    record = {
        "relationship_id": new_id("REL"),
        "from_entity_id": from_entity_id,
        "relationship_type": relationship_type.strip().lower(),
        "to_entity_id": to_entity_id,
        "evidence_kind": evidence_kind,
        "confidence": _require_enum(confidence, CONFIDENCE_VALUES, "Relationship confidence"),
        "observed_at": observed_at,
        "source_ids": source_ids,
        "notes": notes.strip(),
        "analyst": analyst.strip() or "operator",
        "created_at_utc": utc_now(),
    }
    if not record["relationship_type"]:
        raise ValueError("Relationship type is required")
    return _append_record(case_dir, "relationships.jsonl", "relationship.added", record, record["analyst"])


def add_event(
    case: str | Path,
    label: str,
    event_type: str,
    start_at: str,
    source_ids: list[str],
    end_at: str = "",
    location_entity_id: str = "",
    confidence: str = "medium",
    notes: str = "",
    analyst: str = "operator",
) -> dict[str, Any]:
    case_dir = ensure_case(case)
    _require_ids(source_ids, _known_ids(case_dir, "sources.jsonl", "source_id"), "source ID")
    if location_entity_id:
        _require_ids([location_entity_id], _known_ids(case_dir, "entities.jsonl", "entity_id"), "entity ID")
    start_at_utc, start_precision = normalize_event_time(start_at, "Event start")
    end_at_utc = ""
    end_precision = ""
    if end_at.strip():
        end_at_utc, end_precision = normalize_event_time(end_at, "Event end")
        if start_precision == end_precision == "datetime" and end_at_utc < start_at_utc:
            raise ValueError("Event end cannot precede event start")
        if start_precision == end_precision == "date" and end_at_utc < start_at_utc:
            raise ValueError("Event end cannot precede event start")
    record = {
        "event_id": new_id("EVT"),
        "label": label.strip(),
        "event_type": event_type.strip().lower(),
        "start_at": start_at.strip(),
        "end_at": end_at.strip(),
        "start_at_utc": start_at_utc,
        "end_at_utc": end_at_utc,
        "start_precision": start_precision,
        "end_precision": end_precision,
        "location_entity_id": location_entity_id,
        "confidence": _require_enum(confidence, CONFIDENCE_VALUES, "Event confidence"),
        "source_ids": source_ids,
        "notes": notes.strip(),
        "analyst": analyst.strip() or "operator",
        "created_at_utc": utc_now(),
    }
    if not record["label"] or not record["event_type"] or not record["start_at"]:
        raise ValueError("Event label, type, and start time are required")
    return _append_record(case_dir, "events.jsonl", "event.added", record, record["analyst"])


def add_derivation(
    case: str | Path,
    parent_artifact_id: str,
    child_artifact_id: str,
    tool: str,
    version: str,
    command: list[str],
    notes: str = "",
    actor: str = "operator",
) -> dict[str, Any]:
    case_dir = ensure_case(case)
    artifact_ids = _known_ids(case_dir, "artifacts.jsonl", "artifact_id")
    _require_ids([parent_artifact_id, child_artifact_id], artifact_ids, "artifact ID")
    if parent_artifact_id == child_artifact_id:
        raise ValueError("Parent and child artifacts must differ")
    record = {
        "derivation_id": new_id("DRV"),
        "parent_artifact_id": parent_artifact_id,
        "child_artifact_id": child_artifact_id,
        "tool": tool.strip(),
        "version": version.strip(),
        "command": command,
        "notes": notes.strip(),
        "actor": actor.strip() or "operator",
        "created_at_utc": utc_now(),
    }
    if not record["tool"] or not record["command"]:
        raise ValueError("Derivation tool and command are required")
    return _append_record(case_dir, "derivations.jsonl", "derivation.added", record, record["actor"])


def add_provider_run(
    case: str | Path,
    provider: str,
    target: str,
    status: str,
    request_url: str,
    source_id: str = "",
    artifact_id: str = "",
    observation_count: int = 0,
    error: str = "",
    collector: str = "operator",
) -> dict[str, Any]:
    case_dir = ensure_case(case)
    record = {
        "provider_run_id": new_id("RUN"),
        "provider": provider,
        "target": target,
        "status": _require_enum(status, {"completed", "failed", "blocked"}, "Provider run status"),
        "request_url": request_url,
        "source_id": source_id,
        "artifact_id": artifact_id,
        "observation_count": observation_count,
        "error": error,
        "collector": collector.strip() or "operator",
        "completed_at_utc": utc_now(),
    }
    return _append_record(case_dir, "provider_runs.jsonl", "provider.run-recorded", record, record["collector"])


def add_claim(
    case: str | Path,
    statement: str,
    confidence: str,
    source_ids: list[str],
    status: str = "assessed",
    notes: str = "",
    analyst: str = "operator",
) -> dict[str, Any]:
    case_dir = ensure_case(case)
    _require_ids(source_ids, _known_ids(case_dir, "sources.jsonl", "source_id"), "source ID")
    if not statement.strip():
        raise ValueError("Claim statement is required")
    claim = {
        "claim_id": new_id("CLM"),
        "statement": statement.strip(),
        "confidence": _require_enum(confidence, {"high", "medium", "low"}, "Claim confidence"),
        "status": _require_enum(status, {"assessed", "tentative", "disputed", "retracted"}, "Claim status"),
        "source_ids": source_ids,
        "notes": notes.strip(),
        "analyst": analyst.strip() or "operator",
        "created_at_utc": utc_now(),
    }
    return _append_record(case_dir, "claims.jsonl", "claim.added", claim, claim["analyst"])


def _check_refs(
    rows: list[dict[str, Any]],
    row_id: str,
    field: str,
    known: set[str],
    label: str,
    issues: list[str],
) -> None:
    for row in rows:
        values = row.get(field, [])
        values = values if isinstance(values, list) else ([values] if values else [])
        missing = set(values) - known
        if missing:
            issues.append(
                f"{label} {row.get(row_id, '<missing ID>')} has missing {field}: {', '.join(sorted(missing))}"
            )


def verify_case(case: str | Path) -> tuple[bool, list[str]]:
    case_dir = ensure_case(case)
    issues: list[str] = []
    for filename in ["ledger.jsonl", *sorted(set(DATA_FILES.values()))]:
        if not (case_dir / filename).is_file():
            issues.append(f"Required case file is missing: {filename}")
    issues.extend(
        f"Pending crash-recovery transaction: {path.name}"
        for path in pending_transaction_paths(case_dir)
    )
    issues.extend(
        f"Unreferenced transaction payload requires manual review: {path.relative_to(case_dir).as_posix()}"
        for path in orphan_payload_paths(case_dir)
    )
    try:
        record = read_json(case_dir / "case.json")
        if record.get("schema_version") != SCHEMA_VERSION:
            issues.append(f"Unsupported schema version: {record.get('schema_version')}")
        for issue in validation_issues("case", record):
            issues.append(f"case.json JSON Schema validation failed: {issue}")
    except Exception as exc:
        issues.append(f"case.json could not be read: {exc}")

    previous_hash = None
    ledger_rows: list[dict[str, Any]] = []
    try:
        ledger_rows = read_jsonl(case_dir / "ledger.jsonl")
        for index, entry in enumerate(ledger_rows, 1):
            supplied_hash = entry.get("entry_sha256")
            base = dict(entry)
            base.pop("entry_sha256", None)
            calculated = sha256_bytes(canonical_json(base).encode("utf-8"))
            if entry.get("previous_entry_sha256") != previous_hash:
                issues.append(f"Ledger entry {index} has an invalid previous hash")
            if supplied_hash != calculated:
                issues.append(f"Ledger entry {index} content hash does not match")
            previous_hash = supplied_hash
    except Exception as exc:
        issues.append(f"ledger.jsonl could not be verified: {exc}")

    try:
        case_payloads = [entry.get("payload") for entry in ledger_rows if entry.get("action") == "case.created"]
        if len(case_payloads) != 1:
            issues.append("Ledger must contain exactly one case.created record")
        else:
            latest_case = case_payloads[0]
            for entry in ledger_rows:
                if entry.get("action") == "case.migrated":
                    payload = entry.get("payload", {})
                    expected_previous = sha256_bytes(canonical_json(latest_case).encode("utf-8"))
                    if payload.get("from_version") != latest_case.get("schema_version"):
                        issues.append(f"Case migration has an invalid source version: {entry.get('entry_id')}")
                    if payload.get("previous_case_sha256") != expected_previous:
                        issues.append(f"Case migration has an invalid previous-case hash: {entry.get('entry_id')}")
                    latest_case = payload.get("case", {})
                    if payload.get("to_version") != latest_case.get("schema_version"):
                        issues.append(f"Case migration has an invalid destination version: {entry.get('entry_id')}")
                elif entry.get("action") == "case.status-changed":
                    payload = entry.get("payload", {})
                    if payload.get("previous_status") != latest_case.get("status"):
                        issues.append(f"Case status transition has an invalid previous status: {entry.get('entry_id')}")
                    expected_previous = _state_hash(latest_case)
                    if payload.get("previous_case_sha256") not in {None, expected_previous}:
                        issues.append(f"Case status transition has an invalid previous-case hash: {entry.get('entry_id')}")
                    latest_case = payload.get("case", {})
                elif entry.get("action") == "case.retention-changed":
                    payload = entry.get("payload", {})
                    if payload.get("previous_retention_until") != latest_case.get("retention_until"):
                        issues.append(f"Case retention transition has an invalid previous value: {entry.get('entry_id')}")
                    if payload.get("previous_case_sha256") != _state_hash(latest_case):
                        issues.append(f"Case retention transition has an invalid previous-case hash: {entry.get('entry_id')}")
                    latest_case = payload.get("case", {})
                elif entry.get("action") == "case.legal-hold-changed":
                    payload = entry.get("payload", {})
                    previous_hold = latest_case.get("legal_hold", _empty_legal_hold())
                    if payload.get("previous_active") != previous_hold.get("active"):
                        issues.append(f"Legal-hold transition has an invalid previous state: {entry.get('entry_id')}")
                    if payload.get("previous_case_sha256") != _state_hash(latest_case):
                        issues.append(f"Legal-hold transition has an invalid previous-case hash: {entry.get('entry_id')}")
                    latest_case = payload.get("case", {})
            if canonical_json(latest_case) != canonical_json(read_json(case_dir / "case.json")):
                issues.append("case.json does not match its latest hash-chained state")
    except Exception as exc:
        issues.append(f"case.json could not be matched to the ledger: {exc}")

    for action, filename in DATA_FILES.items():
        try:
            ledger_payloads = Counter(
                canonical_json(entry["payload"]) for entry in ledger_rows if entry.get("action") == action
            )
            file_payloads = Counter(canonical_json(row) for row in read_jsonl(case_dir / filename))
            if ledger_payloads != file_payloads:
                issues.append(f"{filename} does not match the hash-chained ledger")
        except Exception as exc:
            issues.append(f"{filename} could not be matched to the ledger: {exc}")

    datasets: dict[str, list[dict[str, Any]]] = {}
    primary_ids = {
        "sources.jsonl": "source_id", "artifacts.jsonl": "artifact_id", "observations.jsonl": "observation_id",
        "entities.jsonl": "entity_id", "relationships.jsonl": "relationship_id", "events.jsonl": "event_id",
        "derivations.jsonl": "derivation_id", "claims.jsonl": "claim_id", "provider_runs.jsonl": "provider_run_id",
        "legal_holds.jsonl": "legal_hold_event_id",
        "resolutions.jsonl": "resolution_id", "worksheets.jsonl": "worksheet_id",
        "audit_reviews.jsonl": "review_id",
        "provider_approvals.jsonl": "approval_id",
    }
    for filename in set(DATA_FILES.values()):
        try:
            rows = read_jsonl(case_dir / filename)
            datasets[filename] = rows
            for index, row in enumerate(rows, 1):
                for issue in validation_issues("record", row):
                    issues.append(f"{filename}:{index} JSON Schema validation failed: {issue}")
            key = primary_ids[filename]
            ids = [row.get(key) for row in rows]
            if any(not value for value in ids):
                issues.append(f"{filename} contains a record without {key}")
            if len(ids) != len(set(ids)):
                issues.append(f"{filename} contains duplicate {key} values")
        except Exception as exc:
            issues.append(f"{filename} could not be read: {exc}")

    artifacts = datasets.get("artifacts.jsonl", [])
    registered_artifact_paths: set[Path] = set()
    for artifact in artifacts:
        try:
            path = (case_dir / artifact["stored_path"]).resolve()
            if case_dir not in path.parents:
                issues.append(f"Artifact path escapes the case: {artifact['artifact_id']}")
            elif not path.is_file():
                issues.append(f"Artifact is missing: {artifact['artifact_id']}")
            else:
                registered_artifact_paths.add(path)
                if path.stat().st_size != artifact.get("size_bytes"):
                    issues.append(f"Artifact size mismatch: {artifact['artifact_id']}")
                if sha256_file(path) != artifact.get("sha256"):
                    issues.append(f"Artifact hash mismatch: {artifact['artifact_id']}")
        except Exception as exc:
            issues.append(f"Artifact {artifact.get('artifact_id', '<missing ID>')} could not be verified: {exc}")
    for path in sorted((case_dir / "artifacts").rglob("*")):
        if path.is_file() and path.resolve() not in registered_artifact_paths:
            issues.append(f"Artifact file is not registered: {path.relative_to(case_dir).as_posix()}")

    source_ids = {row.get("source_id") for row in datasets.get("sources.jsonl", [])}
    artifact_ids = {row.get("artifact_id") for row in artifacts}
    entity_ids = {row.get("entity_id") for row in datasets.get("entities.jsonl", [])}
    _check_refs(datasets.get("claims.jsonl", []), "claim_id", "source_ids", source_ids, "Claim", issues)
    _check_refs(datasets.get("observations.jsonl", []), "observation_id", "source_id", source_ids, "Observation", issues)
    _check_refs(datasets.get("observations.jsonl", []), "observation_id", "artifact_id", artifact_ids, "Observation", issues)
    _check_refs(datasets.get("entities.jsonl", []), "entity_id", "source_ids", source_ids, "Entity", issues)
    _check_refs(datasets.get("relationships.jsonl", []), "relationship_id", "source_ids", source_ids, "Relationship", issues)
    _check_refs(datasets.get("relationships.jsonl", []), "relationship_id", "from_entity_id", entity_ids, "Relationship", issues)
    _check_refs(datasets.get("relationships.jsonl", []), "relationship_id", "to_entity_id", entity_ids, "Relationship", issues)
    _check_refs(datasets.get("events.jsonl", []), "event_id", "source_ids", source_ids, "Event", issues)
    _check_refs(datasets.get("events.jsonl", []), "event_id", "location_entity_id", entity_ids, "Event", issues)
    _check_refs(datasets.get("derivations.jsonl", []), "derivation_id", "parent_artifact_id", artifact_ids, "Derivation", issues)
    _check_refs(datasets.get("derivations.jsonl", []), "derivation_id", "child_artifact_id", artifact_ids, "Derivation", issues)
    _check_refs(datasets.get("provider_runs.jsonl", []), "provider_run_id", "source_id", source_ids, "Provider run", issues)
    _check_refs(datasets.get("provider_runs.jsonl", []), "provider_run_id", "artifact_id", artifact_ids, "Provider run", issues)
    for row in datasets.get("resolutions.jsonl", []):
        _check_refs([row], "resolution_id", "entity_ids", entity_ids, "Resolution", issues)
        _check_refs([row], "resolution_id", "source_ids", source_ids, "Resolution", issues)
        for feature in row.get("features", []):
            _check_refs([feature | {"resolution_id": row.get("resolution_id")}], "resolution_id", "source_ids", source_ids, "Resolution feature", issues)
    seen_merges: dict[str, dict[str, Any]] = {}
    undone: set[str] = set()
    for row in datasets.get("resolutions.jsonl", []):
        if row.get("action") == "merge":
            seen_merges[row["resolution_id"]] = row
        elif row.get("action") == "split":
            target = row.get("reverses_id", "")
            if target not in seen_merges or target in undone or row.get("entity_ids") != seen_merges.get(target, {}).get("entity_ids"):
                issues.append(f"Resolution {row.get('resolution_id')} does not reverse an active matching merge")
            undone.add(target)
    for row in datasets.get("worksheets.jsonl", []):
        _check_refs([row], "worksheet_id", "source_ids", source_ids, "Worksheet", issues)
        _check_refs([row], "worksheet_id", "artifact_ids", artifact_ids, "Worksheet", issues)
        for feature in [*row.get("clues", []), *row.get("leads", [])]:
            _check_refs([feature | {"worksheet_id": row.get("worksheet_id")}], "worksheet_id", "source_ids", source_ids, "Worksheet feature", issues)
        for candidate in row.get("candidates", []):
            _check_refs([candidate | {"worksheet_id": row.get("worksheet_id")}], "worksheet_id", "source_ids", source_ids, "Location candidate", issues)
            _check_refs([candidate | {"worksheet_id": row.get("worksheet_id")}], "worksheet_id", "map_artifact_ids", artifact_ids, "Map snapshot", issues)
            for feature in [*candidate.get("matched_features", []), *candidate.get("mismatched_features", [])]:
                _check_refs([feature | {"worksheet_id": row.get("worksheet_id")}], "worksheet_id", "source_ids", source_ids, "Location feature", issues)
    for row in datasets.get("audit_reviews.jsonl", []):
        expected = sha256_bytes(canonical_json({"category": row.get("category"), "record_ids": sorted(row.get("record_ids", []))}).encode("utf-8"))
        if row.get("fingerprint") != expected:
            issues.append(f"Audit review {row.get('review_id')} has an invalid finding fingerprint")
    approvals_by_id: dict[str, dict[str, Any]] = {}
    revoked: set[str] = set()
    for row in datasets.get("provider_approvals.jsonl", []):
        if row.get("action") == "approved":
            approvals_by_id[row["approval_id"]] = row
        elif row.get("action") == "revoked":
            target = row.get("reverses_id", "")
            if target not in approvals_by_id or target in revoked:
                issues.append(f"Provider approval {row.get('approval_id')} does not revoke an active approval")
            elif (row.get("provider"), row.get("target")) != (approvals_by_id[target].get("provider"), approvals_by_id[target].get("target")):
                issues.append(f"Provider approval {row.get('approval_id')} revokes a different provider/target")
            revoked.add(target)
        reference = row.get("authority_artifact_id", "")
        if reference and reference not in artifact_ids:
            issues.append(f"Provider approval {row.get('approval_id')} refers to a missing authority artifact")

    active_hold_id = ""
    latest_hold_event: dict[str, Any] | None = None
    for event in datasets.get("legal_holds.jsonl", []):
        if event.get("action") == "placed":
            if active_hold_id:
                issues.append(f"Legal hold placed while another hold was active: {event.get('legal_hold_event_id')}")
            active_hold_id = str(event.get("hold_id", ""))
            latest_hold_event = event
        elif event.get("action") == "released":
            if not active_hold_id or event.get("hold_id") != active_hold_id:
                issues.append(f"Legal-hold release does not match an active hold: {event.get('legal_hold_event_id')}")
            active_hold_id = ""
            latest_hold_event = event
    try:
        current_hold = read_json(case_dir / "case.json").get("legal_hold", _empty_legal_hold())
        if bool(active_hold_id) != current_hold.get("active"):
            issues.append("case.json legal-hold state does not match legal_holds.jsonl")
        if active_hold_id and current_hold.get("hold_id") != active_hold_id:
            issues.append("case.json active hold ID does not match legal_holds.jsonl")
        if latest_hold_event and current_hold.get("hold_id") != latest_hold_event.get("hold_id"):
            issues.append("case.json latest hold ID does not match legal_holds.jsonl")
    except Exception:
        pass
    return not issues, issues


def escape_table(value: Any) -> str:
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value or "").replace("|", "\\|").replace("\n", " ")


def render_report(case: str | Path, output: str | Path | None = None) -> Path:
    case_dir = ensure_case(case)
    case_record = read_json(case_dir / "case.json")
    sources = read_jsonl(case_dir / "sources.jsonl")
    claims = read_jsonl(case_dir / "claims.jsonl")
    artifacts = read_jsonl(case_dir / "artifacts.jsonl")
    observations = read_jsonl(case_dir / "observations.jsonl")
    entities = read_jsonl(case_dir / "entities.jsonl")
    relationships = read_jsonl(case_dir / "relationships.jsonl")
    events = read_jsonl(case_dir / "events.jsonl")
    ok, issues = verify_case(case_dir)
    source_by_id = {source["source_id"]: source for source in sources}
    entity_by_id = {entity["entity_id"]: entity for entity in entities}
    lines = [
        f"# {case_record['title']}", "", f"- Case ID: `{case_record['case_id']}`",
        f"- Target type: {case_record['target_type']}", f"- Target: {case_record['target']}",
        f"- Purpose: {case_record['purpose']}", f"- Authority: {case_record['authority']}",
        f"- Status: {case_record['status']}", f"- Sensitivity: {case_record.get('sensitivity', 'not recorded')}",
        f"- Collection tier: {case_record.get('collection_tier', 'not recorded')}",
        f"- Jurisdictions: {', '.join(case_record.get('jurisdictions', [])) or 'not recorded'}",
        f"- Retention until: {case_record.get('retention_until') or 'not recorded'}",
        f"- Legal hold: {'ACTIVE — ' + case_record['legal_hold']['hold_id'] if case_record.get('legal_hold', {}).get('active') else 'not active'}",
        f"- Reviewers: {', '.join(case_record.get('reviewers', [])) or 'not assigned'}",
        f"- Created: {case_record['created_at_utc']}", f"- Integrity check: {'PASS' if ok else 'FAIL'}", "",
        "## Executive summary", "",
        "_Complete after analysis. Distinguish observations, assessed claims, and unknowns._", "",
        "## Assessed claims", "",
    ]
    if not claims:
        lines.append("_No assessed claims recorded._")
    for claim in claims:
        lines.extend([
            f"### {claim['claim_id']} — {claim['confidence'].title()} confidence", "", claim["statement"], "",
            f"Status: {claim['status']}", "", "Sources:", "",
        ])
        for source_id in claim["source_ids"]:
            source = source_by_id.get(source_id, {})
            lines.append(f"- `{source_id}` — [{source.get('title', 'missing source')}]({source.get('url', '')})")
        if claim.get("notes"):
            lines.extend(["", f"Analyst note: {claim['notes']}"])
        lines.append("")

    lines.extend(["## Observation register", "", "| ID | Kind | Status | Observed | Source | Value |", "|---|---|---|---|---|---|"])
    for row in observations:
        lines.append(
            f"| {row['observation_id']} | {escape_table(row['kind'])} | {escape_table(row['status'])} | "
            f"{escape_table(row['observed_at'])} | {row['source_id']} | {escape_table(row['value'])} |"
        )

    lines.extend(["", "## Entity and relationship register", "", "| ID | Type | Label | Confidence | Sources |", "|---|---|---|---|---|"])
    for row in entities:
        lines.append(
            f"| {row['entity_id']} | {escape_table(row['entity_type'])} | {escape_table(row['label'])} | "
            f"{escape_table(row['confidence'])} | {escape_table(', '.join(row['source_ids']))} |"
        )
    lines.extend(["", "| Relationship | From | Type | To | Evidence | Confidence |", "|---|---|---|---|---|---|"])
    for row in relationships:
        start = entity_by_id.get(row["from_entity_id"], {}).get("label", row["from_entity_id"])
        end = entity_by_id.get(row["to_entity_id"], {}).get("label", row["to_entity_id"])
        lines.append(
            f"| {row['relationship_id']} | {escape_table(start)} | {escape_table(row['relationship_type'])} | "
            f"{escape_table(end)} | {row['evidence_kind']} | {row['confidence']} |"
        )

    lines.extend(["", "## Timeline", "", "| ID | Start | End | Type | Event | Confidence |", "|---|---|---|---|---|---|"])
    for row in sorted(events, key=lambda item: item.get("start_at_utc", item.get("start_at", ""))):
        lines.append(
            f"| {row['event_id']} | {escape_table(row.get('start_at_utc', row['start_at']))} | "
            f"{escape_table(row.get('end_at_utc', row['end_at']))} | "
            f"{escape_table(row['event_type'])} | {escape_table(row['label'])} | {row['confidence']} |"
        )

    lines.extend(["", "## Source register", "", "| ID | Topic | Reliability | Credibility | Accessed (UTC) | Source |", "|---|---|---|---|---|---|"])
    for source in sources:
        lines.append(
            "| {source_id} | {topic} | {reliability} | {credibility} | {accessed} | [{title}]({url}) |".format(
                source_id=escape_table(source["source_id"]), topic=escape_table(source["topic"]),
                reliability=escape_table(source["reliability"]), credibility=escape_table(source["credibility"]),
                accessed=escape_table(source["accessed_at_utc"]), title=escape_table(source["title"]), url=source["url"],
            )
        )
    lines.extend(["", "## Artifact register", "", "| ID | File | Type | Bytes | SHA-256 | Source |", "|---|---|---|---:|---|---|"])
    for artifact in artifacts:
        lines.append(
            f"| {artifact['artifact_id']} | `{escape_table(artifact['stored_path'])}` | {escape_table(artifact['mime_type'])} | "
            f"{artifact['size_bytes']} | `{artifact['sha256']}` | {escape_table(artifact['source_url'])} |"
        )
    lines.extend(["", "## Limitations and unresolved questions", ""])
    if issues:
        lines.extend(f"- Integrity issue: {issue}" for issue in issues)
    else:
        lines.append("- Add collection gaps, source limitations, and alternative explanations here.")
    lines.extend([
        "", "## Method", "",
        "Collection was limited to the authority and purpose stated above. Observations preserve what a source "
        "showed; claims are separate assessments. Every relationship states whether it was observed or inferred. "
        "Artifact hashes and the case ledger were verified when this report was generated.", "",
    ])
    destination = Path(output).expanduser().resolve() if output else case_dir / "reports" / "report.md"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("\n".join(lines), encoding="utf-8")
    append_ledger(case_dir, "report.rendered", {"path": str(destination)}, "system")
    return destination
