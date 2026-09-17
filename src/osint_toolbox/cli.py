from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .analyzers import ANALYZERS, analyze_artifact
from .audit import audit_case, review_finding
from .case import (
    add_artifact,
    add_claim,
    add_derivation,
    add_entity,
    add_event,
    add_observation,
    add_relationship,
    add_source,
    create_case,
    place_legal_hold,
    recover_case,
    release_legal_hold,
    render_report,
    retention_status,
    update_case_retention,
    update_case_status,
    upgrade_case,
    verify_case,
)
from .catalog import find_tools, load_workflows
from .doctor import render_system_check, system_check
from .exports import create_bundle, export_csv, export_graphml, export_json, export_maltego, export_redacted_json, verify_bundle
from .pdf_reports import render_pdf_report
from .policy import approve_provider, provider_profiles, registry_profiles, revoke_provider_approval
from .providers import PROVIDERS, collect_provider, probe_provider, save_provider_probe
from .queries import ENGINE_URLS, build_query, list_recipes
from .signing import sign_bundle_manifest, verify_bundle_signature
from .util import ensure_case, parse_key_values, read_json, utc_now
from .workbench import record_resolution, record_worksheet, render_workbench


TARGET_TYPES = ["person", "organization", "domain", "username", "email", "media", "location", "social", "event"]
CONFIDENCE = ["high", "medium", "low", "unknown"]


def write_plan(case_path: str) -> Path:
    case_dir = ensure_case(case_path)
    case_record = read_json(case_dir / "case.json")
    workflows = load_workflows()["workflows"]
    workflow = workflows.get(case_record["target_type"])
    if not workflow:
        raise ValueError(f"No workflow for target type: {case_record['target_type']}")
    lines = [
        f"# Investigation plan — {case_record['title']}", "", f"- Case ID: `{case_record['case_id']}`",
        f"- Target: {case_record['target']}", f"- Purpose: {case_record['purpose']}",
        f"- Authority: {case_record['authority']}", f"- Generated: {utc_now()}", "",
        "## Collection questions", "",
    ]
    lines.extend(f"- [ ] {item}" for item in workflow["questions"])
    lines.extend(["", "## Collection sequence", ""])
    for index, step in enumerate(workflow["steps"], 1):
        lines.append(f"{index}. {step}")
    lines.extend(["", "## Stop conditions", ""])
    lines.extend(f"- {item}" for item in workflow["stop_conditions"])
    lines.extend([
        "", "## Review gates", "",
        "- [ ] Every material observation has a logged source and access time.",
        "- [ ] Identity matches are corroborated; same-name or same-username matches are not treated as proof.",
        "- [ ] Sensitive personal data is necessary, proportionate, and handled under the documented authority.",
        "- [ ] Alternative explanations and collection gaps are recorded.",
        "- [ ] Artifacts and the hash-chained ledger pass `osint-toolbox verify`.", "",
    ])
    destination = case_dir / "investigation-plan.md"
    destination.write_text("\n".join(lines), encoding="utf-8")
    return destination


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="osint-toolbox", description="Evidence-first OSINT case workbench")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor_parser = subparsers.add_parser("doctor", help="Check local capabilities without network requests")
    doctor_parser.add_argument("--json", action="store_true")

    init_parser = subparsers.add_parser("init-case", help="Create a scoped case directory")
    init_parser.add_argument("--title", required=True)
    init_parser.add_argument("--purpose", required=True)
    init_parser.add_argument("--authority", required=True)
    init_parser.add_argument("--target-type", required=True, choices=TARGET_TYPES)
    init_parser.add_argument("--target", required=True)
    init_parser.add_argument("--owner", default="")
    init_parser.add_argument("--sensitivity", choices=["public", "internal", "confidential", "restricted"], default="internal")
    init_parser.add_argument("--retention-until", default="", help="ISO date or policy label")
    init_parser.add_argument("--reviewer", action="append", default=[])
    init_parser.add_argument("--jurisdiction", action="append", default=[])
    init_parser.add_argument("--collection-tier", choices=["manual-public", "passive-public", "approved-licensed"], default="passive-public")
    init_parser.add_argument("--output", default="cases")

    status_parser = subparsers.add_parser("set-status", help="Record an auditable case-status transition")
    status_parser.add_argument("case")
    status_parser.add_argument("status", choices=["open", "review", "closed", "archived"])
    status_parser.add_argument("--note", required=True)
    status_parser.add_argument("--actor", default="operator")

    upgrade_parser = subparsers.add_parser("upgrade-case", help="Migrate a supported older case schema in place")
    upgrade_parser.add_argument("case")
    upgrade_parser.add_argument("--actor", default="operator")

    hold_parser = subparsers.add_parser("place-legal-hold", help="Place an auditable preservation hold")
    hold_parser.add_argument("case")
    hold_parser.add_argument("--reason", required=True)
    hold_parser.add_argument("--authority", required=True)
    hold_parser.add_argument("--actor", default="operator")

    release_hold_parser = subparsers.add_parser("release-legal-hold", help="Release an active preservation hold")
    release_hold_parser.add_argument("case")
    release_hold_parser.add_argument("--reason", required=True)
    release_hold_parser.add_argument("--authority", required=True)
    release_hold_parser.add_argument("--actor", default="operator")

    hold_status_parser = subparsers.add_parser("legal-hold-status", help="Show hold and retention disposition")
    hold_status_parser.add_argument("case")

    retention_parser = subparsers.add_parser("set-retention", help="Record an auditable retention change")
    retention_parser.add_argument("case")
    retention_parser.add_argument("retention_until", help="ISO date, policy label, or empty string to clear")
    retention_parser.add_argument("--note", required=True)
    retention_parser.add_argument("--actor", default="operator")

    recover_parser = subparsers.add_parser("recover-case", help="Complete interrupted journaled case writes")
    recover_parser.add_argument("case")
    recover_parser.add_argument("--actor", default="operator")

    plan_parser = subparsers.add_parser("plan", help="Generate a target-specific collection plan")
    plan_parser.add_argument("case")

    catalog_parser = subparsers.add_parser("catalog", help="List curated tools")
    catalog_parser.add_argument("--topic")
    catalog_parser.add_argument("--search")

    recipes_parser = subparsers.add_parser("list-recipes", help="List safe search-query recipes")
    recipes_parser.add_argument("--topic")

    query_parser = subparsers.add_parser("query", help="Generate a search URL without making a request")
    query_parser.add_argument("recipe_id")
    query_parser.add_argument("--param", action="append", default=[])
    query_parser.add_argument("--engine", choices=sorted(ENGINE_URLS), default="google")

    source_parser = subparsers.add_parser("add-source", help="Log a public source")
    source_parser.add_argument("case")
    source_parser.add_argument("--url", required=True)
    source_parser.add_argument("--title", required=True)
    source_parser.add_argument("--topic", required=True)
    source_parser.add_argument("--reliability", choices=["primary", "secondary", "unknown"], required=True)
    source_parser.add_argument("--credibility", choices=CONFIDENCE, required=True)
    source_parser.add_argument("--notes", default="")
    source_parser.add_argument("--collector", default="operator")
    source_parser.add_argument("--accessed-at")

    artifact_parser = subparsers.add_parser("add-artifact", help="Copy and hash an artifact into a case")
    artifact_parser.add_argument("case")
    artifact_parser.add_argument("input_path")
    artifact_parser.add_argument("--source-url", required=True)
    artifact_parser.add_argument("--topic", required=True)
    artifact_parser.add_argument("--notes", default="")
    artifact_parser.add_argument("--collector", default="operator")

    observation_parser = subparsers.add_parser("add-observation", help="Record a direct source observation")
    observation_parser.add_argument("case")
    observation_parser.add_argument("--source-id", required=True)
    observation_parser.add_argument("--kind", required=True)
    observation_parser.add_argument("--value", required=True)
    observation_parser.add_argument("--json-value", action="store_true", help="Parse --value as JSON")
    observation_parser.add_argument("--query", default="")
    observation_parser.add_argument("--observed-at", default="")
    observation_parser.add_argument("--artifact-id", default="")
    observation_parser.add_argument("--status", default="observed")
    observation_parser.add_argument("--notes", default="")
    observation_parser.add_argument("--collector", default="operator")

    entity_parser = subparsers.add_parser("add-entity", help="Record a seed, candidate, or resolved entity")
    entity_parser.add_argument("case")
    entity_parser.add_argument("--type", required=True)
    entity_parser.add_argument("--label", required=True)
    entity_parser.add_argument("--source-id", action="append", default=[])
    entity_parser.add_argument("--alias", action="append", default=[])
    entity_parser.add_argument("--attribute", action="append", default=[])
    entity_parser.add_argument("--role", choices=["seed", "candidate", "resolved"], default="candidate")
    entity_parser.add_argument("--confidence", choices=CONFIDENCE, default="unknown")
    entity_parser.add_argument("--notes", default="")
    entity_parser.add_argument("--analyst", default="operator")

    relationship_parser = subparsers.add_parser("add-relationship", help="Record a typed, sourced entity relationship")
    relationship_parser.add_argument("case")
    relationship_parser.add_argument("--from-entity-id", required=True)
    relationship_parser.add_argument("--type", required=True)
    relationship_parser.add_argument("--to-entity-id", required=True)
    relationship_parser.add_argument("--source-id", action="append", required=True)
    relationship_parser.add_argument("--evidence-kind", choices=["observed", "inferred"], default="observed")
    relationship_parser.add_argument("--confidence", choices=CONFIDENCE, default="medium")
    relationship_parser.add_argument("--observed-at", default="")
    relationship_parser.add_argument("--notes", default="")
    relationship_parser.add_argument("--analyst", default="operator")

    event_parser = subparsers.add_parser("add-event", help="Add a sourced timeline event")
    event_parser.add_argument("case")
    event_parser.add_argument("--label", required=True)
    event_parser.add_argument("--type", required=True)
    event_parser.add_argument("--start-at", required=True)
    event_parser.add_argument("--end-at", default="")
    event_parser.add_argument("--location-entity-id", default="")
    event_parser.add_argument("--source-id", action="append", required=True)
    event_parser.add_argument("--confidence", choices=CONFIDENCE, default="medium")
    event_parser.add_argument("--notes", default="")
    event_parser.add_argument("--analyst", default="operator")

    derivation_parser = subparsers.add_parser("add-derivation", help="Link a derivative artifact to its parent and tool")
    derivation_parser.add_argument("case")
    derivation_parser.add_argument("--parent-artifact-id", required=True)
    derivation_parser.add_argument("--child-artifact-id", required=True)
    derivation_parser.add_argument("--tool", required=True)
    derivation_parser.add_argument("--version", default="unknown")
    derivation_parser.add_argument("--command-part", action="append", required=True)
    derivation_parser.add_argument("--notes", default="")
    derivation_parser.add_argument("--actor", default="operator")

    claim_parser = subparsers.add_parser("add-claim", help="Record a source-backed analytic claim")
    claim_parser.add_argument("case")
    claim_parser.add_argument("--statement", required=True)
    claim_parser.add_argument("--confidence", choices=CONFIDENCE[:-1], required=True)
    claim_parser.add_argument("--source-id", action="append", required=True)
    claim_parser.add_argument("--status", choices=["assessed", "tentative", "disputed", "retracted"], default="assessed")
    claim_parser.add_argument("--notes", default="")
    claim_parser.add_argument("--analyst", default="operator")

    subparsers.add_parser("providers", help="List passive and governed licensed-provider adapters")
    policy_parser = subparsers.add_parser("provider-policy", help="Show licensed-provider policy metadata")
    policy_parser.add_argument("provider", nargs="?", choices=sorted(provider_profiles()))
    registry_parser = subparsers.add_parser("registries", help="List official registry profiles by jurisdiction")
    registry_parser.add_argument("--jurisdiction", choices=["KE", "UK", "US", "GLOBAL"])

    approve_parser = subparsers.add_parser("approve-provider", help="Record exact-target, time-limited provider approval")
    approve_parser.add_argument("case")
    approve_parser.add_argument("provider", choices=sorted(p for p, x in provider_profiles().items() if x["mode"] == "api"))
    approve_parser.add_argument("--target", required=True)
    approve_parser.add_argument("--basis", required=True)
    approve_parser.add_argument("--reason", required=True)
    approve_parser.add_argument("--reviewer", required=True)
    approve_parser.add_argument("--actor", required=True)
    approve_parser.add_argument("--expires-at", required=True, help="Timezone-aware ISO timestamp, no more than 90 days away")
    approve_parser.add_argument("--max-runs", type=int, default=1)
    approve_parser.add_argument("--authority-artifact-id", default="")
    approve_parser.add_argument("--terms-reviewed", action="store_true")
    approve_parser.add_argument("--data-residency-accepted", action="store_true")
    approve_parser.add_argument("--cost-acknowledged", action="store_true")
    approve_parser.add_argument("--data-residency-note", required=True)
    approve_parser.add_argument("--cost-note", required=True)

    revoke_parser = subparsers.add_parser("revoke-provider-approval", help="Revoke an active provider approval")
    revoke_parser.add_argument("case")
    revoke_parser.add_argument("approval_id")
    revoke_parser.add_argument("--reason", required=True)
    revoke_parser.add_argument("--actor", default="operator")
    collect_parser = subparsers.add_parser("collect", help="Explicitly run one passive provider and preserve its response")
    collect_parser.add_argument("case")
    collect_parser.add_argument("provider", choices=sorted(PROVIDERS))
    collect_parser.add_argument("--target", help="Defaults to the case target")
    collect_parser.add_argument("--option", action="append", default=[], help="Provider key=value option")
    collect_parser.add_argument("--collector", default="operator")
    collect_parser.add_argument("--execute", action="store_true", help="Required acknowledgment that a network request will run")
    collect_parser.add_argument(
        "--confirm-external-disclosure",
        action="store_true",
        help="Confirm that case sensitivity and authority permit sending the target/query to external services",
    )

    health_parser = subparsers.add_parser("provider-health", help="Probe one provider using a reserved test target")
    health_parser.add_argument("provider", choices=[*sorted(PROVIDERS), "all"])
    health_parser.add_argument("--option", action="append", default=[])
    health_parser.add_argument("--output", default="provider-status.json")
    health_parser.add_argument("--execute", action="store_true", help="Required acknowledgment that a network request will run")

    subparsers.add_parser("analyzers", help="List supported local analyzers")
    analyze_parser = subparsers.add_parser("analyze", help="Run a local analyzer and log a derivation")
    analyze_parser.add_argument("case")
    analyze_parser.add_argument("artifact_id")
    analyze_parser.add_argument("analyzer", choices=sorted(ANALYZERS))
    analyze_parser.add_argument("--actor", default="operator")

    verify_parser = subparsers.add_parser("verify", help="Verify the ledger, artifacts, and references")
    verify_parser.add_argument("case")

    report_parser = subparsers.add_parser("report", help="Render a Markdown case report")
    report_parser.add_argument("case")
    report_parser.add_argument("--output")

    pdf_report_parser = subparsers.add_parser("report-pdf", help="Render a reproducible PDF case report")
    pdf_report_parser.add_argument("case")
    pdf_report_parser.add_argument("--output")

    redacted_pdf_parser = subparsers.add_parser(
        "redact-pdf", help="Render a PDF from a policy-minimized case snapshot"
    )
    redacted_pdf_parser.add_argument("case")
    redacted_pdf_parser.add_argument("policy")
    redacted_pdf_parser.add_argument("--output")

    audit_parser = subparsers.add_parser("audit", help="Run non-destructive case quality checks")
    audit_parser.add_argument("case")
    audit_parser.add_argument("--stale-days", type=int, default=365)
    audit_parser.add_argument("--output")

    review_parser = subparsers.add_parser("review-finding", help="Append a disposition for a current audit finding")
    review_parser.add_argument("case")
    review_parser.add_argument("fingerprint")
    review_parser.add_argument("disposition", choices=["accepted", "deferred", "false-positive", "resolved", "reopened"])
    review_parser.add_argument("--reason", required=True)
    review_parser.add_argument("--reviewer", default="operator")
    review_parser.add_argument("--stale-days", type=int, default=365)

    resolution_parser = subparsers.add_parser("resolve-entities", help="Record an evidence-backed merge or reverse an active merge")
    resolution_parser.add_argument("case")
    resolution_parser.add_argument("action", choices=["merge", "split"])
    resolution_parser.add_argument("entity_id", nargs=2)
    resolution_parser.add_argument("--source-id", action="append", required=True)
    resolution_parser.add_argument("--feature", action="append", default=[], help="JSON object with description and source_ids; required for merge")
    resolution_parser.add_argument("--reverses-id", default="", help="Active merge ID, required for split")
    resolution_parser.add_argument("--reason", required=True)
    resolution_parser.add_argument("--analyst", default="operator")

    worksheet_parser = subparsers.add_parser("record-worksheet", help="Validate and preserve a geolocation or media worksheet JSON")
    worksheet_parser.add_argument("case")
    worksheet_parser.add_argument("input_path")
    worksheet_parser.add_argument("--analyst", default="operator")

    view_parser = subparsers.add_parser("workbench", help="Render a self-contained offline timeline and entity review page")
    view_parser.add_argument("case")
    view_parser.add_argument("--output")

    export_parser = subparsers.add_parser("export", help="Export normalized case data")
    export_parser.add_argument("case")
    export_parser.add_argument("format", choices=["json", "csv", "graphml", "maltego"])
    export_parser.add_argument("--output")

    redact_parser = subparsers.add_parser("redact", help="Create a minimized JSON view using an explicit policy")
    redact_parser.add_argument("case")
    redact_parser.add_argument("policy")
    redact_parser.add_argument("--output")

    bundle_parser = subparsers.add_parser("bundle", help="Create a portable ZIP with a SHA-256 manifest")
    bundle_parser.add_argument("case")
    bundle_parser.add_argument("--output")

    verify_bundle_parser = subparsers.add_parser("verify-bundle", help="Verify every file against a bundle manifest")
    verify_bundle_parser.add_argument("bundle")

    sign_bundle_parser = subparsers.add_parser("sign-bundle", help="Create detached Ed25519 signature metadata for a bundle manifest")
    sign_bundle_parser.add_argument("bundle")
    sign_bundle_parser.add_argument("private_key")
    sign_bundle_parser.add_argument("--output")

    verify_signature_parser = subparsers.add_parser("verify-signature", help="Verify a bundle and detached Ed25519 manifest signature")
    verify_signature_parser.add_argument("bundle")
    verify_signature_parser.add_argument("signature")
    verify_signature_parser.add_argument("public_key")
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "doctor":
            check = system_check()
            print(json.dumps(check, indent=2) if args.json else render_system_check(check))
        elif args.command == "init-case":
            print(create_case(
                args.output, args.title, args.purpose, args.authority, args.target_type, args.target, args.owner,
                args.sensitivity, args.retention_until, args.reviewer, args.jurisdiction, args.collection_tier,
            ))
        elif args.command == "set-status":
            row = update_case_status(args.case, args.status, args.note, args.actor)
            print(row["status"])
        elif args.command == "upgrade-case":
            row, changed = upgrade_case(args.case, args.actor)
            print(f"{row['schema_version']} {'migrated' if changed else 'already-current'}")
        elif args.command == "place-legal-hold":
            hold = place_legal_hold(args.case, args.reason, args.authority, args.actor)
            print(f"{hold['hold_id']} active")
        elif args.command == "release-legal-hold":
            hold = release_legal_hold(args.case, args.reason, args.authority, args.actor)
            print(f"{hold['hold_id']} released")
        elif args.command == "legal-hold-status":
            print(json.dumps(retention_status(args.case), indent=2))
        elif args.command == "set-retention":
            row = update_case_retention(args.case, args.retention_until, args.note, args.actor)
            print(row["retention_until"] or "cleared")
        elif args.command == "recover-case":
            result = recover_case(args.case, args.actor)
            print(json.dumps(result, indent=2))
            if not result["integrity_valid"]:
                raise SystemExit(1)
        elif args.command == "plan":
            print(write_plan(args.case))
        elif args.command == "catalog":
            tools = find_tools(args.topic, args.search)
            for tool in tools:
                print(f"{tool['id']:<28} {tool['recommendation']:<12} {tool['name']} — {tool['role']}")
            print(f"\n{len(tools)} tool(s)")
        elif args.command == "list-recipes":
            recipes = list_recipes()
            if args.topic:
                recipes = [recipe for recipe in recipes if args.topic.lower() in [x.lower() for x in recipe["topics"]]]
            for recipe in recipes:
                print(f"{recipe['id']:<30} {recipe['description']}")
        elif args.command == "query":
            query, url = build_query(args.recipe_id, parse_key_values(args.param), args.engine)
            print(f"Query: {query}\nURL:   {url}")
        elif args.command == "add-source":
            row = add_source(args.case, args.url, args.title, args.topic, args.reliability, args.credibility, args.notes, args.collector, args.accessed_at)
            print(row["source_id"])
        elif args.command == "add-artifact":
            row = add_artifact(args.case, args.input_path, args.source_url, args.topic, args.notes, args.collector)
            print(f"{row['artifact_id']} {row['sha256']}")
        elif args.command == "add-observation":
            value = json.loads(args.value) if args.json_value else args.value
            row = add_observation(args.case, args.source_id, args.kind, value, args.query, args.observed_at, args.artifact_id, args.status, args.notes, args.collector)
            print(row["observation_id"])
        elif args.command == "add-entity":
            row = add_entity(args.case, args.type, args.label, args.source_id, args.alias, parse_key_values(args.attribute), args.role, args.confidence, args.notes, args.analyst)
            print(row["entity_id"])
        elif args.command == "add-relationship":
            row = add_relationship(args.case, args.from_entity_id, args.type, args.to_entity_id, args.source_id, args.evidence_kind, args.confidence, args.observed_at, args.notes, args.analyst)
            print(row["relationship_id"])
        elif args.command == "add-event":
            row = add_event(args.case, args.label, args.type, args.start_at, args.source_id, args.end_at, args.location_entity_id, args.confidence, args.notes, args.analyst)
            print(row["event_id"])
        elif args.command == "add-derivation":
            row = add_derivation(args.case, args.parent_artifact_id, args.child_artifact_id, args.tool, args.version, args.command_part, args.notes, args.actor)
            print(row["derivation_id"])
        elif args.command == "add-claim":
            row = add_claim(args.case, args.statement, args.confidence, args.source_id, args.status, args.notes, args.analyst)
            print(row["claim_id"])
        elif args.command == "providers":
            for provider_id, provider in PROVIDERS.items():
                print(
                    f"{provider_id:<16} {provider['mode']:<22} disclosure={provider['target_disclosure']:<8} "
                    f"{provider['name']} — {provider['notes']}"
                )
        elif args.command == "provider-policy":
            profiles = provider_profiles()
            print(json.dumps({args.provider: profiles[args.provider]} if args.provider else profiles, indent=2))
        elif args.command == "registries":
            print(json.dumps(registry_profiles(args.jurisdiction or ""), indent=2))
        elif args.command == "approve-provider":
            row = approve_provider(
                args.case, args.provider, args.target, args.basis, args.reason, args.reviewer,
                args.actor, args.expires_at, args.max_runs, args.authority_artifact_id,
                args.terms_reviewed, args.data_residency_accepted, args.cost_acknowledged,
                args.data_residency_note, args.cost_note,
            )
            print(row["approval_id"])
        elif args.command == "revoke-provider-approval":
            row = revoke_provider_approval(args.case, args.approval_id, args.reason, args.actor)
            print(row["approval_id"])
        elif args.command == "collect":
            if not args.execute:
                raise ValueError("Collection is opt-in: review the target/options and add --execute to make the network request")
            target = args.target or read_json(ensure_case(args.case) / "case.json")["target"]
            result = collect_provider(
                args.case,
                args.provider,
                target,
                parse_key_values(args.option),
                args.collector,
                args.confirm_external_disclosure,
            )
            print(
                f"{result['run']['provider_run_id']} source={result['source']['source_id']} "
                f"artifact={result['artifact']['artifact_id']} observations={len(result['observations'])}"
            )
        elif args.command == "provider-health":
            if not args.execute:
                raise ValueError("Provider health checks are opt-in; add --execute to make the network request")
            provider_ids = sorted(PROVIDERS) if args.provider == "all" else [args.provider]
            options = parse_key_values(args.option)
            results = [probe_provider(provider_id, options) for provider_id in provider_ids]
            destination = Path(args.output)
            for result in results:
                destination = save_provider_probe(result, destination)
            print(json.dumps(results[0] if len(results) == 1 else results, indent=2))
            print(destination)
        elif args.command == "analyzers":
            for analyzer_id, analyzer in ANALYZERS.items():
                print(f"{analyzer_id:<12} {analyzer['description']}")
        elif args.command == "analyze":
            result = analyze_artifact(args.case, args.artifact_id, args.analyzer, args.actor)
            print(f"{result['artifact']['artifact_id']} {result['derivation']['derivation_id']}")
        elif args.command == "verify":
            ok, issues = verify_case(args.case)
            if ok:
                print("PASS")
            else:
                print("FAIL")
                for issue in issues:
                    print(f"- {issue}")
                raise SystemExit(1)
        elif args.command == "report":
            print(render_report(args.case, args.output))
        elif args.command == "report-pdf":
            path, digest = render_pdf_report(args.case, args.output)
            print(f"{path} {digest}")
        elif args.command == "redact-pdf":
            path, digest = render_pdf_report(args.case, args.output, args.policy)
            print(f"{path} {digest}")
        elif args.command == "audit":
            path, audit = audit_case(args.case, args.stale_days, args.output)
            summary = audit["summary"]
            print(f"{path}\nfindings={summary['finding_count']} high={summary['high']} medium={summary['medium']} low={summary['low']}")
        elif args.command == "review-finding":
            row = review_finding(args.case, args.fingerprint, args.disposition, args.reason, args.reviewer, args.stale_days)
            print(row["review_id"])
        elif args.command == "resolve-entities":
            row = record_resolution(args.case, args.action, args.entity_id, [json.loads(item) for item in args.feature], args.source_id, args.reason, args.reverses_id, args.analyst)
            print(row["resolution_id"])
        elif args.command == "record-worksheet":
            row = record_worksheet(args.case, read_json(Path(args.input_path).expanduser()), args.analyst)
            print(row["worksheet_id"])
        elif args.command == "workbench":
            print(render_workbench(args.case, args.output))
        elif args.command == "export":
            exporters = {"json": export_json, "csv": export_csv, "graphml": export_graphml, "maltego": export_maltego}
            print(exporters[args.format](args.case, args.output))
        elif args.command == "redact":
            print(export_redacted_json(args.case, args.policy, args.output))
        elif args.command == "bundle":
            path, digest = create_bundle(args.case, args.output)
            print(f"{path}\nsha256 {digest}")
        elif args.command == "verify-bundle":
            ok, issues = verify_bundle(args.bundle)
            if ok:
                print("PASS")
            else:
                print("FAIL")
                for issue in issues:
                    print(f"- {issue}")
                raise SystemExit(1)
        elif args.command == "sign-bundle":
            path, metadata = sign_bundle_manifest(args.bundle, args.private_key, args.output)
            print(f"{path} manifest={metadata['manifest_sha256']} key={metadata['public_key_der_sha256']}")
        elif args.command == "verify-signature":
            ok, issues = verify_bundle_signature(args.bundle, args.signature, args.public_key)
            if ok:
                print("PASS")
            else:
                print("FAIL")
                for issue in issues:
                    print(f"- {issue}")
                raise SystemExit(1)
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
