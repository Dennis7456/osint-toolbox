from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .util import (
    append_jsonl,
    canonical_json,
    fsync_directory,
    new_id,
    read_json,
    read_jsonl,
    sha256_bytes,
    sha256_file,
    utc_now,
    write_json,
)


JOURNAL_FORMAT = "osint-toolbox.transaction/1"
TRANSACTION_DIRECTORY = ".transactions"
JSONL_FILES = {
    "sources.jsonl", "artifacts.jsonl", "observations.jsonl", "entities.jsonl",
    "relationships.jsonl", "events.jsonl", "derivations.jsonl", "claims.jsonl",
    "provider_runs.jsonl", "legal_holds.jsonl", "resolutions.jsonl", "worksheets.jsonl", "audit_reviews.jsonl",
    "provider_approvals.jsonl",
}
RECORD_ID_FIELDS = (
    "entry_id", "legal_hold_event_id", "provider_run_id", "observation_id",
    "relationship_id", "derivation_id", "event_id", "entity_id", "claim_id",
    "artifact_id", "source_id",
    "resolution_id", "worksheet_id", "review_id",
    "approval_id",
)


def pending_transaction_paths(case_dir: Path) -> list[Path]:
    directory = case_dir / TRANSACTION_DIRECTORY
    if not directory.is_dir():
        return []
    return sorted(directory.glob("*.json"))


def orphan_payload_paths(case_dir: Path) -> list[Path]:
    directory = case_dir / TRANSACTION_DIRECTORY
    if not directory.is_dir():
        return []
    referenced: set[str] = set()
    for journal_path in pending_transaction_paths(case_dir):
        try:
            journal = read_json(journal_path)
        except Exception:
            continue
        for operation in journal.get("operations", []):
            if operation.get("type") == "install_file":
                referenced.add(str(operation.get("staged_path", "")))
    return sorted(
        path for path in directory.glob("*.payload")
        if path.relative_to(case_dir).as_posix() not in referenced
    )


def transaction_id() -> str:
    return new_id("TXN")


def transaction_payload_path(case_dir: Path, txn_id: str) -> Path:
    directory = case_dir / TRANSACTION_DIRECTORY
    directory.mkdir(parents=True, exist_ok=True)
    return directory / f"{txn_id}.payload"


def _safe_case_path(case_dir: Path, relative: str) -> Path:
    relative_path = Path(relative)
    if not relative or relative_path.is_absolute() or ".." in relative_path.parts:
        raise ValueError(f"Unsafe transaction path: {relative!r}")
    path = (case_dir / relative).resolve()
    if case_dir.resolve() not in path.parents:
        raise ValueError(f"Transaction path escapes the case: {relative}")
    return path


def _ledger_entries(
    case_dir: Path,
    txn_id: str,
    events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    rows = read_jsonl(case_dir / "ledger.jsonl")
    previous_hash = rows[-1]["entry_sha256"] if rows else None
    entries: list[dict[str, Any]] = []
    for event in events:
        entry: dict[str, Any] = {
            "entry_id": new_id("LED"),
            "timestamp_utc": utc_now(),
            "actor": event["actor"],
            "action": event["action"],
            "payload": event["payload"],
            "transaction_id": txn_id,
            "previous_entry_sha256": previous_hash,
        }
        entry["entry_sha256"] = sha256_bytes(canonical_json(entry).encode("utf-8"))
        entries.append(entry)
        previous_hash = entry["entry_sha256"]
    return entries


def _append_idempotent(path: Path, record: dict[str, Any]) -> None:
    expected = canonical_json(record)
    try:
        rows = read_jsonl(path)
    except Exception:
        raw = path.read_bytes() if path.exists() else b""
        final_newline = raw.rfind(b"\n")
        complete = raw[: final_newline + 1]
        tail = raw[final_newline + 1 :]
        expected_bytes = (expected + "\n").encode("utf-8")
        if tail and expected_bytes.startswith(tail):
            with path.open("r+b") as handle:
                handle.truncate(len(complete))
                handle.flush()
                os.fsync(handle.fileno())
            rows = read_jsonl(path)
        else:
            raise ValueError(f"Cannot recover an unrelated partial JSONL line in {path.name}")
    serialized = {canonical_json(row) for row in rows}
    if expected in serialized:
        if path.stat().st_size and not path.read_bytes().endswith(b"\n"):
            with path.open("ab") as handle:
                handle.write(b"\n")
                handle.flush()
                os.fsync(handle.fileno())
        return
    identifier_field = next((field for field in RECORD_ID_FIELDS if field in record), None)
    if identifier_field and any(row.get(identifier_field) == record[identifier_field] for row in rows):
        raise ValueError(f"Cannot recover {path.name}: {identifier_field} conflicts with the journal")
    append_jsonl(path, record)


def _apply_operation(case_dir: Path, operation: dict[str, Any]) -> None:
    operation_type = operation.get("type")
    if operation_type == "touch_file":
        relative_path = operation.get("path")
        if relative_path not in JSONL_FILES:
            raise ValueError(f"A transaction may not initialize {relative_path}")
        path = _safe_case_path(case_dir, relative_path)
        existed = path.exists()
        path.touch(exist_ok=True)
        if not existed:
            fsync_directory(path.parent)
        return
    if operation_type in {"jsonl_append", "ledger_append"}:
        relative_path = operation.get("path")
        if operation_type == "ledger_append" and relative_path != "ledger.jsonl":
            raise ValueError("A ledger transaction may only append to ledger.jsonl")
        if operation_type == "jsonl_append" and relative_path not in JSONL_FILES:
            raise ValueError(f"A data transaction may not append to {relative_path}")
        path = _safe_case_path(case_dir, operation["path"])
        path.parent.mkdir(parents=True, exist_ok=True)
        existed = path.exists()
        path.touch(exist_ok=True)
        if not existed:
            fsync_directory(path.parent)
        _append_idempotent(path, operation["record"])
        return
    if operation_type == "json_replace":
        if operation.get("path") != "case.json":
            raise ValueError("A JSON replacement transaction may only update case.json")
        path = _safe_case_path(case_dir, operation["path"])
        current = read_json(path)
        current_hash = sha256_bytes(canonical_json(current).encode("utf-8"))
        after = operation["value"]
        after_hash = sha256_bytes(canonical_json(after).encode("utf-8"))
        if current_hash == after_hash:
            return
        if current_hash != operation["expected_before_sha256"]:
            raise ValueError(f"Cannot recover {operation['path']}: current content conflicts with the journal")
        write_json(path, after)
        return
    if operation_type == "json_create":
        if operation.get("path") != "case.json":
            raise ValueError("A JSON creation transaction may only create case.json")
        path = _safe_case_path(case_dir, operation["path"])
        value = operation["value"]
        if path.exists():
            current = read_json(path)
            if canonical_json(current) != canonical_json(value):
                raise ValueError(f"Cannot recover {operation['path']}: existing content conflicts with the journal")
            return
        write_json(path, value)
        return
    if operation_type == "install_file":
        staged_relative = Path(str(operation.get("staged_path", "")))
        destination_relative = Path(str(operation.get("destination", "")))
        if not staged_relative.parts or staged_relative.parts[0] != TRANSACTION_DIRECTORY or staged_relative.suffix != ".payload":
            raise ValueError("A staged payload must be inside the transaction directory")
        if not destination_relative.parts or destination_relative.parts[0] != "artifacts":
            raise ValueError("A transaction payload may only be installed in artifacts")
        staged = _safe_case_path(case_dir, operation["staged_path"])
        destination = _safe_case_path(case_dir, operation["destination"])
        if destination.is_file():
            if destination.stat().st_size != operation["size_bytes"] or sha256_file(destination) != operation["sha256"]:
                raise ValueError(f"Cannot recover {operation['destination']}: destination content conflicts with the journal")
            if staged.exists():
                staged.unlink()
            return
        if not staged.is_file():
            raise ValueError(f"Cannot recover {operation['destination']}: staged payload is missing")
        if staged.stat().st_size != operation["size_bytes"] or sha256_file(staged) != operation["sha256"]:
            raise ValueError(f"Cannot recover {operation['destination']}: staged payload hash does not match")
        destination.parent.mkdir(parents=True, exist_ok=True)
        os.replace(staged, destination)
        fsync_directory(destination.parent)
        return
    raise ValueError(f"Unknown transaction operation: {operation_type}")


def commit_transaction(
    case_dir: Path,
    operation_name: str,
    operations: list[dict[str, Any]],
    ledger_events: list[dict[str, Any]],
    txn_id: str | None = None,
) -> list[dict[str, Any]]:
    existing = pending_transaction_paths(case_dir)
    if existing:
        raise ValueError("Case has a pending transaction; run recover-case before making changes")
    txn_id = txn_id or transaction_id()
    entries = _ledger_entries(case_dir, txn_id, ledger_events)
    journal = {
        "journal_format": JOURNAL_FORMAT,
        "transaction_id": txn_id,
        "operation": operation_name,
        "created_at_utc": utc_now(),
        "operations": operations + [
            {"type": "ledger_append", "path": "ledger.jsonl", "record": entry}
            for entry in entries
        ],
    }
    journal["journal_sha256"] = sha256_bytes(canonical_json(journal).encode("utf-8"))
    directory = case_dir / TRANSACTION_DIRECTORY
    directory.mkdir(parents=True, exist_ok=True)
    journal_path = directory / f"{txn_id}.json"
    write_json(journal_path, journal)
    for operation in journal["operations"]:
        _apply_operation(case_dir, operation)
    journal_path.unlink()
    fsync_directory(directory)
    try:
        directory.rmdir()
    except OSError:
        pass
    return entries


def recover_pending_transactions(case_dir: Path) -> dict[str, Any]:
    recovered: list[str] = []
    pending = pending_transaction_paths(case_dir)
    if len(pending) > 1:
        raise ValueError("Multiple pending transactions require manual review")
    for journal_path in pending:
        journal = read_json(journal_path)
        if journal.get("journal_format") != JOURNAL_FORMAT:
            raise ValueError(f"Unsupported transaction journal: {journal_path.name}")
        supplied_hash = journal.get("journal_sha256")
        unhashed = dict(journal)
        unhashed.pop("journal_sha256", None)
        if supplied_hash != sha256_bytes(canonical_json(unhashed).encode("utf-8")):
            raise ValueError(f"Transaction journal hash does not match: {journal_path.name}")
        if journal.get("transaction_id") != journal_path.stem:
            raise ValueError(f"Transaction ID does not match journal filename: {journal_path.name}")
        operations = journal.get("operations")
        if not isinstance(operations, list) or not operations:
            raise ValueError(f"Transaction journal has no operations: {journal_path.name}")
        for operation in operations:
            _apply_operation(case_dir, operation)
        recovered.append(journal["transaction_id"])
        journal_path.unlink()
        fsync_directory(journal_path.parent)
    directory = case_dir / TRANSACTION_DIRECTORY
    try:
        directory.rmdir()
    except OSError:
        pass
    return {
        "recovered_transaction_ids": recovered,
        "orphan_payloads": [path.relative_to(case_dir).as_posix() for path in orphan_payload_paths(case_dir)],
    }
