from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .case import _append_record, append_ledger, verify_case
from .util import canonical_json, ensure_case, new_id, read_json, read_jsonl, sha256_bytes, utc_now, write_json


def _finding(
    findings: list[dict[str, Any]],
    severity: str,
    category: str,
    message: str,
    record_ids: list[str],
) -> None:
    fingerprint = sha256_bytes(canonical_json({"category": category, "record_ids": sorted(record_ids)}).encode("utf-8"))
    findings.append({
        "finding_id": f"AUD-{len(findings) + 1:04d}",
        "fingerprint": fingerprint,
        "severity": severity,
        "category": category,
        "message": message,
        "record_ids": record_ids,
    })


def audit_case(
    case: str | Path,
    stale_days: int = 365,
    output: str | Path | None = None,
) -> tuple[Path, dict[str, Any]]:
    if not 1 <= stale_days <= 36500:
        raise ValueError("stale_days must be between 1 and 36500")
    case_dir = ensure_case(case)
    findings: list[dict[str, Any]] = []
    integrity_ok, integrity_issues = verify_case(case_dir)
    for issue in integrity_issues:
        _finding(findings, "high", "integrity", issue, [])

    sources = read_jsonl(case_dir / "sources.jsonl")
    observations = read_jsonl(case_dir / "observations.jsonl")
    entities = read_jsonl(case_dir / "entities.jsonl")
    relationships = read_jsonl(case_dir / "relationships.jsonl")
    claims = read_jsonl(case_dir / "claims.jsonl")
    artifacts = read_jsonl(case_dir / "artifacts.jsonl")
    derivations = read_jsonl(case_dir / "derivations.jsonl")
    provider_runs = read_jsonl(case_dir / "provider_runs.jsonl")

    entity_groups: dict[tuple[str, str], list[str]] = defaultdict(list)
    for entity in entities:
        key = (entity.get("entity_type", "").casefold(), " ".join(entity.get("label", "").casefold().split()))
        entity_groups[key].append(entity.get("entity_id", ""))
    for (entity_type, label), ids in entity_groups.items():
        if label and len(ids) > 1:
            _finding(
                findings, "medium", "duplicate-entity-candidate",
                f"{len(ids)} {entity_type} entities share the normalized label {label!r}; review before merging.", ids,
            )
    for entity in entities:
        if not entity.get("source_ids"):
            _finding(findings, "high", "missing-entity-source", "Entity has no traceable source IDs; exclude it from graph and workbench exports.", [entity.get("entity_id", "")])

    observation_groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for observation in observations:
        if observation.get("status") in {"observed", "conflicting"}:
            observation_groups[(observation.get("kind", ""), observation.get("query", ""))].append(observation)
    for (kind, query), rows in observation_groups.items():
        values = {canonical_json(row.get("value")) for row in rows}
        source_count = len({row.get("source_id") for row in rows})
        if len(values) > 1 and source_count > 1:
            _finding(
                findings, "medium", "conflicting-observations",
                f"Different values were recorded for {kind!r} and query {query!r} across {source_count} sources.",
                [row.get("observation_id", "") for row in rows],
            )
    repeated_observations: dict[tuple[str, str, str, str], list[str]] = defaultdict(list)
    for observation in observations:
        key = (
            observation.get("source_id", ""), observation.get("kind", ""), observation.get("query", ""),
            canonical_json(observation.get("value")),
        )
        repeated_observations[key].append(observation.get("observation_id", ""))
    for ids in repeated_observations.values():
        if len(ids) > 1:
            _finding(findings, "low", "duplicate-observation-candidate", "Several observations repeat the same source, kind, query and value; review access times and status before treating them as distinct.", ids)

    now = datetime.now(timezone.utc)
    for source in sources:
        value = source.get("accessed_at_utc", "")
        try:
            accessed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            age = (now - accessed.astimezone(timezone.utc)).days
            if age > stale_days:
                _finding(
                    findings, "low", "stale-source",
                    f"Source was accessed {age} days ago; confirm it still supports current-use claims.",
                    [source.get("source_id", "")],
                )
        except (ValueError, AttributeError):
            _finding(findings, "medium", "invalid-source-time", f"Invalid source access time: {value!r}.", [source.get("source_id", "")])

    observation_sources = {row.get("source_id") for row in observations}
    for claim in claims:
        unobserved = sorted(set(claim.get("source_ids", [])) - observation_sources)
        if unobserved:
            _finding(
                findings, "low", "claim-observation-gap",
                "Claim cites source records without normalized observations; verify the reasoning remains reproducible.",
                [claim.get("claim_id", ""), *unobserved],
            )
        cited_observations = [row for row in observations if row.get("source_id") in claim.get("source_ids", [])]
        if cited_observations and all(row.get("status") in {"retracted", "superseded", "unavailable"} for row in cited_observations):
            _finding(findings, "medium", "claim-retracted-evidence", "Every normalized observation from cited sources is unavailable, superseded, or retracted.", [claim.get("claim_id", ""), *claim.get("source_ids", [])])

    linked_artifacts = {row.get("artifact_id") for row in observations if row.get("artifact_id")}
    for worksheet in read_jsonl(case_dir / "worksheets.jsonl"):
        linked_artifacts.update(worksheet.get("artifact_ids", []))
    for row in derivations:
        linked_artifacts.update({row.get("parent_artifact_id"), row.get("child_artifact_id")})
    for artifact in artifacts:
        if artifact.get("artifact_id") not in linked_artifacts:
            _finding(
                findings, "low", "orphan-artifact",
                "Artifact is preserved but not linked to an observation or derivation.",
                [artifact.get("artifact_id", "")],
            )

    source_groups: dict[str, list[str]] = defaultdict(list)
    for source in sources:
        source_groups[source.get("url", "").strip().casefold()].append(source.get("source_id", ""))
    for url, ids in source_groups.items():
        if url and len(ids) > 1:
            _finding(findings, "low", "duplicate-source-candidate", f"{len(ids)} source records share the same URL; compare capture times and content.", ids)

    for relationship in relationships:
        if relationship.get("evidence_kind") == "inferred" and relationship.get("confidence") == "high":
            _finding(
                findings, "medium", "high-confidence-inference",
                "High-confidence inferred relationship requires explicit alternative testing and reviewer attention.",
                [relationship.get("relationship_id", "")],
            )

    latest_provider_status: dict[str, dict[str, Any]] = {}
    for run in provider_runs:
        latest_provider_status[run.get("provider", "unknown")] = run
    for provider, run in latest_provider_status.items():
        if run.get("status") != "completed":
            _finding(
                findings, "low", "provider-not-completed",
                f"Latest {provider} run ended with status {run.get('status')}; do not interpret it as a zero result.",
                [run.get("provider_run_id", "")],
            )

    reviews = {row["fingerprint"]: row for row in read_jsonl(case_dir / "audit_reviews.jsonl")}
    for item in findings:
        review = reviews.get(item["fingerprint"])
        item["review"] = review
        item["suppressed"] = bool(review and review["disposition"] in {"false-positive", "resolved"}) and item["category"] != "integrity"
    severity_counts = Counter(item["severity"] for item in findings if not item["suppressed"])
    audit = {
        "audit_format": "osint-toolbox.quality-audit/1",
        "generated_at_utc": utc_now(),
        "case_id": read_json(case_dir / "case.json")["case_id"],
        "parameters": {"stale_days": stale_days},
        "integrity_valid_at_start": integrity_ok,
        "summary": {
            "finding_count": len(findings),
            "open_count": sum(not item["suppressed"] for item in findings),
            "suppressed_count": sum(item["suppressed"] for item in findings),
            "high": severity_counts["high"],
            "medium": severity_counts["medium"],
            "low": severity_counts["low"],
        },
        "findings": findings,
        "warning": "Audit findings are review prompts, not factual conclusions or automatic corrections.",
    }
    destination = Path(output).expanduser().resolve() if output else case_dir / "reports" / "quality-audit.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    write_json(destination, audit)
    append_ledger(
        case_dir, "audit.rendered",
        {"path": str(destination), "finding_count": len(findings), "integrity_valid_at_start": integrity_ok}, "system",
    )
    return destination, audit


def review_finding(
    case: str | Path, fingerprint: str, disposition: str, reason: str, reviewer: str = "operator",
    stale_days: int = 365,
) -> dict[str, Any]:
    if disposition not in {"accepted", "deferred", "false-positive", "resolved", "reopened"}:
        raise ValueError("Unknown review disposition")
    if not reason.strip() or not reviewer.strip():
        raise ValueError("Review reason and reviewer are required")
    case_dir = ensure_case(case)
    _, current = audit_case(case_dir, stale_days=stale_days)
    finding = next((item for item in current["findings"] if item["fingerprint"] == fingerprint), None)
    if finding is None:
        raise ValueError("Finding fingerprint is not present in the current audit; rerun audit with matching --stale-days")
    if finding["category"] == "integrity" and disposition in {"false-positive", "resolved"}:
        raise ValueError("Integrity failures cannot be suppressed")
    row = {
        "review_id": new_id("REV"), "fingerprint": fingerprint, "category": finding["category"],
        "record_ids": finding["record_ids"], "disposition": disposition, "reason": reason.strip(),
        "reviewer": reviewer.strip(), "created_at_utc": utc_now(),
    }
    return _append_record(case_dir, "audit_reviews.jsonl", "audit-review.recorded", row, row["reviewer"])
