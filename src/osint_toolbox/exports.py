from __future__ import annotations

import csv
import json
import zipfile
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

from .case import DATA_FILES, append_ledger, verify_case
from .transactions import TRANSACTION_DIRECTORY
from .util import ensure_case, read_json, read_jsonl, sha256_bytes, sha256_file, utc_now, write_json
from .workbench import active_resolution_groups
from .policy import provider_profiles


EXPORT_TABLES = sorted(set(DATA_FILES.values()))


def _snapshot(case_dir: Path) -> dict[str, Any]:
    ok, issues = verify_case(case_dir)
    ledger = read_jsonl(case_dir / "ledger.jsonl")
    return {
        "export_format": "osint-toolbox.case-export/1",
        "exported_at_utc": utc_now(),
        "case": read_json(case_dir / "case.json"),
        "integrity": {"valid": ok, "issues": issues, "ledger_head_sha256": ledger[-1]["entry_sha256"] if ledger else None},
        "datasets": {Path(name).stem: read_jsonl(case_dir / name) for name in EXPORT_TABLES},
    }


def export_json(case: str | Path, output: str | Path | None = None) -> Path:
    case_dir = ensure_case(case)
    destination = Path(output).expanduser().resolve() if output else case_dir / "reports" / "case-export.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    write_json(destination, _snapshot(case_dir))
    append_ledger(case_dir, "export.created", {"format": "json", "path": str(destination)}, "system")
    return destination


def export_redacted_json(
    case: str | Path,
    policy_path: str | Path,
    output: str | Path | None = None,
) -> Path:
    case_dir = ensure_case(case)
    snapshot, policy_hash = build_redacted_snapshot(case_dir, policy_path)
    destination = Path(output).expanduser().resolve() if output else case_dir / "reports" / "case-export-redacted.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    write_json(destination, snapshot)
    append_ledger(
        case_dir, "export.created",
        {"format": "redacted-json", "path": str(destination), "policy_sha256": policy_hash}, "system",
    )
    return destination


def build_redacted_snapshot(case: str | Path, policy_path: str | Path) -> tuple[dict[str, Any], str]:
    case_dir = ensure_case(case)
    policy_file = Path(policy_path).expanduser().resolve()
    try:
        policy = read_json(policy_file)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Redaction policy could not be read: {exc}") from exc
    if not isinstance(policy, dict):
        raise ValueError("Redaction policy must be a JSON object")
    snapshot = _snapshot(case_dir)
    datasets = snapshot["datasets"]
    case_fields = policy.get("mask_case_fields", [])
    redact_fields = policy.get("mask_dataset_fields", {})
    exclusions = policy.get("exclude_record_ids", {})
    if not isinstance(case_fields, list) or not isinstance(redact_fields, dict) or not isinstance(exclusions, dict):
        raise ValueError("Invalid redaction policy field types")
    pii_providers = {name for name, profile in provider_profiles().items() if profile["pii"]}
    sensitive_runs = [row for row in read_jsonl(case_dir / "provider_runs.jsonl") if row.get("provider") in pii_providers]
    sensitive_approvals = [row for row in read_jsonl(case_dir / "provider_approvals.jsonl") if row.get("provider") in pii_providers]
    reference_fields = {"source_id", "source_ids", "artifact_id", "artifact_ids", "entity_id", "entity_ids", "from_entity_id", "to_entity_id", "parent_artifact_id", "child_artifact_id"}
    if (sensitive_runs or sensitive_approvals) and any(reference_fields & set(fields) for fields in redact_fields.values() if isinstance(fields, list)):
        raise ValueError("Redaction of provenance IDs would prevent safe licensed-data minimization; exclude records instead")
    for field in case_fields:
        if field in snapshot["case"]:
            snapshot["case"][field] = "[REDACTED]"
    for dataset, fields in redact_fields.items():
        if dataset not in datasets or not isinstance(fields, list):
            raise ValueError(f"Invalid dataset or field list in redaction policy: {dataset}")
        for row in datasets[dataset]:
            for field in fields:
                if field in row:
                    row[field] = "[REDACTED]"
    primary_ids = {
        "sources": "source_id", "artifacts": "artifact_id", "observations": "observation_id",
        "entities": "entity_id", "relationships": "relationship_id", "events": "event_id",
        "derivations": "derivation_id", "claims": "claim_id", "provider_runs": "provider_run_id",
        "legal_holds": "legal_hold_event_id",
        "resolutions": "resolution_id", "worksheets": "worksheet_id", "audit_reviews": "review_id",
        "provider_approvals": "approval_id",
    }
    for dataset, record_ids in exclusions.items():
        if dataset not in datasets or dataset not in primary_ids or not isinstance(record_ids, list):
            raise ValueError(f"Invalid dataset or ID list in redaction policy: {dataset}")
        excluded = set(record_ids)
        key = primary_ids[dataset]
        datasets[dataset] = [row for row in datasets[dataset] if row.get(key) not in excluded]
    if sensitive_runs or sensitive_approvals:
        snapshot["case"]["target"] = "[REDACTED]"
        hidden_source_ids = {row.get("source_id") for row in sensitive_runs if row.get("source_id")}
        hidden_artifact_ids = {row.get("artifact_id") for row in sensitive_runs if row.get("artifact_id")}
        hidden_artifact_ids.update(row["authority_artifact_id"] for row in sensitive_approvals
                                   if row.get("authority_artifact_id"))
        hidden_entities = {row["entity_id"] for row in datasets.get("entities", [])
                           if set(row.get("source_ids", [])) & hidden_source_ids}
        for name, predicate in {
            "sources": lambda r: r.get("source_id") in hidden_source_ids,
            "artifacts": lambda r: r.get("artifact_id") in hidden_artifact_ids,
            "observations": lambda r: r.get("source_id") in hidden_source_ids or r.get("artifact_id") in hidden_artifact_ids,
            "claims": lambda r: bool(set(r.get("source_ids", [])) & hidden_source_ids),
            "entities": lambda r: r.get("entity_id") in hidden_entities,
            "relationships": lambda r: bool(set(r.get("source_ids", [])) & hidden_source_ids) or r.get("from_entity_id") in hidden_entities or r.get("to_entity_id") in hidden_entities,
            "events": lambda r: bool(set(r.get("source_ids", [])) & hidden_source_ids) or r.get("location_entity_id") in hidden_entities,
            "derivations": lambda r: r.get("parent_artifact_id") in hidden_artifact_ids or r.get("child_artifact_id") in hidden_artifact_ids,
            "resolutions": lambda r: bool(set(r.get("source_ids", [])) & hidden_source_ids) or bool(set(r.get("entity_ids", [])) & hidden_entities),
            "worksheets": lambda r: bool(set(r.get("source_ids", [])) & hidden_source_ids) or bool(set(r.get("artifact_ids", [])) & hidden_artifact_ids),
            "provider_runs": lambda r: r.get("provider") in pii_providers,
            "provider_approvals": lambda r: r.get("provider") in pii_providers,
            "audit_reviews": lambda r: True,
        }.items():
            kept = []
            for row in datasets.get(name, []):
                if not predicate(row):
                    kept.append(row)
            if name in datasets:
                datasets[name] = kept
        snapshot["licensed_data_minimization"] = {
            "excluded_provider_ids": sorted({row["provider"] for row in [*sensitive_runs, *sensitive_approvals]}),
            "warning": "Licensed PII provider records and linked material were excluded; check free-text narrative before sharing.",
        }
    policy_hash = sha256_file(policy_file)
    snapshot["redaction"] = {
        "is_redacted_derivative": True,
        "policy_sha256": policy_hash,
        "warning": "This minimized view is not a complete evidence package. Verify claims against the controlled original case.",
    }
    return snapshot, policy_hash


def _csv_value(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    if value is None:
        return ""
    return str(value)


def export_csv(case: str | Path, output: str | Path | None = None) -> Path:
    case_dir = ensure_case(case)
    destination = Path(output).expanduser().resolve() if output else case_dir / "reports" / "csv-export"
    destination.mkdir(parents=True, exist_ok=True)
    for filename in EXPORT_TABLES:
        rows = read_jsonl(case_dir / filename)
        fieldnames = sorted({key for row in rows for key in row})
        output_file = destination / f"{Path(filename).stem}.csv"
        with output_file.open("w", encoding="utf-8", newline="") as handle:
            if fieldnames:
                writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
                writer.writeheader()
                for row in rows:
                    writer.writerow({key: _csv_cell(row.get(key)) for key in fieldnames})
            else:
                handle.write("")
    append_ledger(case_dir, "export.created", {"format": "csv", "path": str(destination)}, "system")
    return destination


def export_graphml(case: str | Path, output: str | Path | None = None) -> Path:
    case_dir = ensure_case(case)
    entities, relationships = _traceable_graph(case_dir)
    destination = Path(output).expanduser().resolve() if output else case_dir / "reports" / "case-graph.graphml"
    destination.parent.mkdir(parents=True, exist_ok=True)
    namespace = "http://graphml.graphdrawing.org/xmlns"
    ET.register_namespace("", namespace)
    root = ET.Element(f"{{{namespace}}}graphml")
    keys = {
        "label": ("node", "string"), "entity_type": ("node", "string"), "role": ("node", "string"),
        "confidence": ("all", "string"), "relationship_type": ("edge", "string"),
        "evidence_kind": ("edge", "string"), "source_ids": ("all", "string"), "observed_at": ("edge", "string"),
        "resolution_group": ("node", "string"),
    }
    for key_id, (scope, attr_type) in keys.items():
        ET.SubElement(root, f"{{{namespace}}}key", id=key_id, **{"for": scope, "attr.name": key_id, "attr.type": attr_type})
    graph = ET.SubElement(root, f"{{{namespace}}}graph", id="case", edgedefault="directed")
    group_by_id = {identifier: group[0] for group in active_resolution_groups(entities, read_jsonl(case_dir / "resolutions.jsonl")) for identifier in group}
    for entity in entities:
        node = ET.SubElement(graph, f"{{{namespace}}}node", id=entity["entity_id"])
        values = {
            "label": entity["label"], "entity_type": entity["entity_type"], "role": entity["role"],
            "confidence": entity["confidence"], "source_ids": ",".join(entity["source_ids"]),
            "resolution_group": group_by_id[entity["entity_id"]],
        }
        for key, value in values.items():
            ET.SubElement(node, f"{{{namespace}}}data", key=key).text = value
    for relationship in relationships:
        edge = ET.SubElement(
            graph, f"{{{namespace}}}edge", id=relationship["relationship_id"],
            source=relationship["from_entity_id"], target=relationship["to_entity_id"],
        )
        values = {
            "relationship_type": relationship["relationship_type"], "evidence_kind": relationship["evidence_kind"],
            "confidence": relationship["confidence"], "source_ids": ",".join(relationship["source_ids"]),
            "observed_at": relationship["observed_at"],
        }
        for key, value in values.items():
            ET.SubElement(edge, f"{{{namespace}}}data", key=key).text = value
    tree = ET.ElementTree(root)
    ET.indent(tree, space="  ")
    tree.write(destination, encoding="utf-8", xml_declaration=True)
    append_ledger(case_dir, "export.created", {"format": "graphml", "path": str(destination)}, "system")
    return destination


def _traceable_graph(case_dir: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    ok, issues = verify_case(case_dir)
    if not ok:
        raise ValueError("Case integrity must pass before graph export: " + "; ".join(issues))
    entities = read_jsonl(case_dir / "entities.jsonl")
    relationships = read_jsonl(case_dir / "relationships.jsonl")
    unsourced = [row["entity_id"] for row in entities if not row["source_ids"]]
    unsourced += [row["relationship_id"] for row in relationships if not row["source_ids"]]
    if unsourced:
        raise ValueError("Graph nodes/edges require source IDs: " + ", ".join(unsourced))
    return entities, relationships


def _csv_cell(value: Any) -> str:
    raw = _csv_value(value)
    return "'" + raw if raw.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")) else raw


def export_maltego(case: str | Path, output: str | Path | None = None) -> Path:
    """Export separate entity/link tables for explicit manual column mapping in Maltego."""
    case_dir = ensure_case(case)
    entities, relationships = _traceable_graph(case_dir)
    destination = Path(output).expanduser().resolve() if output else case_dir / "reports" / "maltego-export"
    destination.mkdir(parents=True, exist_ok=True)
    by_id = {row["entity_id"]: row for row in entities}
    groups = active_resolution_groups(entities, read_jsonl(case_dir / "resolutions.jsonl"))
    group_by_id = {identifier: group[0] for group in groups for identifier in group}
    entity_rows = [{
        "entity_id": e["entity_id"], "label": e["label"], "entity_type": e["entity_type"],
        "role": e["role"], "confidence": e["confidence"], "source_ids": e["source_ids"],
        "resolution_group": group_by_id[e["entity_id"]],
    } for e in entities]
    link_rows = [{
        "relationship_id": r["relationship_id"], "from_entity_id": r["from_entity_id"],
        "from_label": by_id[r["from_entity_id"]]["label"], "from_type": by_id[r["from_entity_id"]]["entity_type"],
        "to_entity_id": r["to_entity_id"], "to_label": by_id[r["to_entity_id"]]["label"],
        "to_type": by_id[r["to_entity_id"]]["entity_type"], "relationship_type": r["relationship_type"],
        "evidence_kind": r["evidence_kind"], "confidence": r["confidence"], "source_ids": r["source_ids"],
    } for r in relationships]
    for name, fields, rows in (
        ("entities.csv", ["entity_id", "label", "entity_type", "role", "confidence", "source_ids", "resolution_group"], entity_rows),
        ("links.csv", ["relationship_id", "from_entity_id", "from_label", "from_type", "to_entity_id", "to_label", "to_type", "relationship_type", "evidence_kind", "confidence", "source_ids"], link_rows),
    ):
        with (destination / name).open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            for row in rows:
                writer.writerow({field: _csv_cell(row[field]) for field in fields})
    write_json(destination / "graph.json", {"entities": entity_rows, "links": link_rows, "resolution_groups": groups})
    append_ledger(case_dir, "export.created", {"format": "maltego", "path": str(destination)}, "system")
    return destination


def _case_files(case_dir: Path, excluded: Path) -> list[Path]:
    files: list[Path] = []
    for path in case_dir.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"Case bundles do not include symbolic links: {path}")
        relative = path.relative_to(case_dir)
        if (
            path.is_file()
            and path.name != ".case.lock"
            and TRANSACTION_DIRECTORY not in relative.parts
            and path.resolve() != excluded.resolve()
        ):
            files.append(path)
    return sorted(files, key=lambda item: item.relative_to(case_dir).as_posix())


def create_bundle(case: str | Path, output: str | Path | None = None) -> tuple[Path, str]:
    case_dir = ensure_case(case)
    ok, issues = verify_case(case_dir)
    if not ok:
        raise ValueError("Case integrity check failed; correct it before bundling: " + "; ".join(issues))
    case_record = read_json(case_dir / "case.json")
    destination = Path(output).expanduser().resolve() if output else case_dir / "reports" / f"{case_record['case_id']}.zip"
    destination.parent.mkdir(parents=True, exist_ok=True)
    files = _case_files(case_dir, destination)
    ledger = read_jsonl(case_dir / "ledger.jsonl")
    manifest = {
        "manifest_format": "osint-toolbox.bundle-manifest/1",
        "created_at_utc": utc_now(),
        "case_id": case_record["case_id"],
        "schema_version": case_record["schema_version"],
        "ledger_head_sha256": ledger[-1]["entry_sha256"] if ledger else None,
        "files": [
            {"path": path.relative_to(case_dir).as_posix(), "size_bytes": path.stat().st_size, "sha256": sha256_file(path)}
            for path in files
        ],
    }
    manifest_bytes = (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        archive.writestr("MANIFEST.json", manifest_bytes)
        for path in files:
            archive.write(path, arcname=path.relative_to(case_dir).as_posix())
    bundle_hash = sha256_file(destination)
    append_ledger(
        case_dir, "bundle.created",
        {"path": str(destination), "sha256": bundle_hash, "manifest_sha256": sha256_bytes(manifest_bytes)}, "system",
    )
    return destination, bundle_hash


def verify_bundle(bundle: str | Path) -> tuple[bool, list[str]]:
    path = Path(bundle).expanduser().resolve()
    issues: list[str] = []
    try:
        with zipfile.ZipFile(path, "r") as archive:
            names = archive.namelist()
            if len(names) != len(set(names)):
                issues.append("Bundle contains duplicate member names")
            if "MANIFEST.json" not in names:
                return False, ["Bundle has no MANIFEST.json"]
            manifest = json.loads(archive.read("MANIFEST.json"))
            expected = {row["path"]: row for row in manifest.get("files", [])}
            actual = set(names) - {"MANIFEST.json"}
            if set(expected) != actual:
                issues.append("Bundle file list does not match the manifest")
            for name, row in expected.items():
                normalized_name = name.replace("\\", "/")
                if normalized_name.startswith("/") or ".." in Path(normalized_name).parts:
                    issues.append(f"Unsafe bundle path: {name}")
                    continue
                if name not in actual:
                    continue
                content = archive.read(name)
                if len(content) != row.get("size_bytes"):
                    issues.append(f"Size mismatch: {name}")
                if sha256_bytes(content) != row.get("sha256"):
                    issues.append(f"Hash mismatch: {name}")
    except (OSError, zipfile.BadZipFile, json.JSONDecodeError, KeyError, TypeError) as exc:
        issues.append(f"Bundle could not be verified: {exc}")
    return not issues, issues
