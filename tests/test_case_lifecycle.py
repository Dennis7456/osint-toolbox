from __future__ import annotations

import tempfile
import shutil
import subprocess
import unittest
import json
import zipfile
from importlib.util import find_spec
from pathlib import Path
from unittest.mock import patch

from osint_toolbox.case import (
    add_artifact,
    add_claim,
    add_derivation,
    add_entity,
    add_event,
    add_observation,
    add_relationship,
    add_source,
    append_ledger,
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
from osint_toolbox.cli import write_plan
from osint_toolbox.audit import audit_case
from osint_toolbox.exports import create_bundle, export_csv, export_graphml, export_json, export_redacted_json, verify_bundle
from osint_toolbox.queries import build_query
from osint_toolbox.pdf_reports import render_pdf_report
from osint_toolbox.signing import sign_bundle_manifest, verify_bundle_signature
from osint_toolbox.util import read_json, read_jsonl, write_json
from osint_toolbox import transactions
from osint_toolbox.locking import _lock_windows, _unlock_windows
from osint_toolbox.doctor import _distributed_asset_available


class CaseLifecycleTest(unittest.TestCase):
    def test_doctor_finds_data_files_under_environment_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            expected = root / "share" / "osint-toolbox" / "schemas" / "example.schema.json"
            expected.parent.mkdir(parents=True)
            expected.write_text("{}\n", encoding="utf-8")
            with patch("osint_toolbox.doctor.sysconfig.get_path", return_value=str(root)):
                self.assertTrue(
                    _distributed_asset_available(
                        "schemas/example.schema.json",
                        project_root=root / "missing-source-tree",
                    )
                )

    def test_end_to_end_case(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case_dir = create_case(
                root,
                "Example review",
                "Test the case lifecycle",
                "Unit-test authorization",
                "organization",
                "Example Organization",
                "test-analyst",
            )
            plan = write_plan(str(case_dir))
            self.assertTrue(plan.is_file())

            source = add_source(
                case_dir,
                "https://example.org/about",
                "Example source",
                "organization",
                "primary",
                "high",
            )
            sample = root / "sample.txt"
            sample.write_text("preserved content\n", encoding="utf-8")
            artifact = add_artifact(case_dir, sample, source["url"], "evidence")
            self.assertEqual(len(artifact["sha256"]), 64)

            observation = add_observation(
                case_dir,
                source["source_id"],
                "domain.control-statement",
                {"domain": "example.org", "organization": "Example Organization"},
                artifact_id=artifact["artifact_id"],
            )
            self.assertTrue(observation["observation_id"].startswith("OBS-"))
            organization = add_entity(
                case_dir, "organization", "Example Organization", [source["source_id"]], role="resolved", confidence="high"
            )
            domain = add_entity(
                case_dir, "domain", "example.org", [source["source_id"]], role="resolved", confidence="high"
            )
            relationship = add_relationship(
                case_dir, organization["entity_id"], "controls", domain["entity_id"], [source["source_id"]]
            )
            self.assertEqual(relationship["evidence_kind"], "observed")
            event = add_event(
                case_dir, "Source accessed", "collection", "2026-09-14T15:00:00+03:00", [source["source_id"]]
            )
            self.assertTrue(event["event_id"].startswith("EVT-"))
            self.assertEqual(event["start_at_utc"], "2026-09-14T12:00:00Z")

            derivative_file = root / "metadata.json"
            derivative_file.write_text('{"FileType": "TXT"}\n', encoding="utf-8")
            derivative = add_artifact(case_dir, derivative_file, source["url"], "derived-metadata")
            derivation = add_derivation(
                case_dir, artifact["artifact_id"], derivative["artifact_id"], "test-analyzer", "1.0", ["test-analyzer", "sample.txt"]
            )
            self.assertTrue(derivation["derivation_id"].startswith("DRV-"))

            claim = add_claim(
                case_dir,
                "Example Organization controls example.org.",
                "medium",
                [source["source_id"]],
            )
            self.assertTrue(claim["claim_id"].startswith("CLM-"))

            ok, issues = verify_case(case_dir)
            self.assertTrue(ok, issues)

            updated = update_case_status(case_dir, "review", "Ready for independent review", "test-analyst")
            self.assertEqual(updated["status"], "review")
            ok, issues = verify_case(case_dir)
            self.assertTrue(ok, issues)
            report = render_report(case_dir)
            self.assertIn(source["source_id"], report.read_text(encoding="utf-8"))

            json_export = export_json(case_dir)
            csv_export = export_csv(case_dir)
            graph_export = export_graphml(case_dir)
            self.assertTrue(json_export.is_file())
            self.assertTrue((csv_export / "observations.csv").is_file())
            graph_text = graph_export.read_text(encoding="utf-8")
            self.assertIn(organization["entity_id"], graph_text)
            self.assertIn(relationship["relationship_id"], graph_text)

            policy = root / "redaction.json"
            policy.write_text(
                '{"mask_case_fields":["target"],"mask_dataset_fields":{"entities":["attributes"]},'
                '"exclude_record_ids":{"observations":["' + observation["observation_id"] + '"]}}',
                encoding="utf-8",
            )
            redacted = export_redacted_json(case_dir, policy)
            redacted_data = redacted.read_text(encoding="utf-8")
            self.assertIn('"target": "[REDACTED]"', redacted_data)
            self.assertNotIn(observation["observation_id"], redacted_data)

            bundle, digest = create_bundle(case_dir)
            self.assertEqual(len(digest), 64)
            bundle_ok, bundle_issues = verify_bundle(bundle)
            self.assertTrue(bundle_ok, bundle_issues)

            ok, issues = verify_case(case_dir)
            self.assertTrue(ok, issues)

    def test_artifact_tampering_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case_dir = create_case(root, "Tamper test", "Test", "Test", "media", "sample")
            sample = root / "sample.txt"
            sample.write_text("original", encoding="utf-8")
            artifact = add_artifact(case_dir, sample, "https://example.org/file", "media")
            (case_dir / artifact["stored_path"]).write_text("changed", encoding="utf-8")
            ok, issues = verify_case(case_dir)
            self.assertFalse(ok)
            self.assertTrue(any("hash mismatch" in issue for issue in issues))

    def test_ledger_content_tampering_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case_dir = create_case(temporary, "Ledger test", "Test", "Test", "domain", "example.org")
            add_source(case_dir, "https://example.org", "Example", "domain", "primary", "high")
            ledger_path = case_dir / "ledger.jsonl"
            ledger_path.write_text(
                ledger_path.read_text(encoding="utf-8").replace("Example", "Altered", 1),
                encoding="utf-8",
            )
            ok, issues = verify_case(case_dir)
            self.assertFalse(ok)
            self.assertTrue(any("content hash does not match" in issue for issue in issues))

    def test_changed_bundle_manifest_record_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case_dir = create_case(root, "Bundle tamper", "Test", "Test", "domain", "example.org")
            add_source(case_dir, "https://example.org", "Example", "domain", "primary", "high")
            bundle, _ = create_bundle(case_dir)
            changed_bundle = root / "changed.zip"
            with zipfile.ZipFile(bundle, "r") as source_archive:
                members = {name: source_archive.read(name) for name in source_archive.namelist()}
            manifest = json.loads(members["MANIFEST.json"])
            manifest["files"][0]["sha256"] = "0" * 64
            members["MANIFEST.json"] = (json.dumps(manifest, indent=2) + "\n").encode("utf-8")
            with zipfile.ZipFile(changed_bundle, "w") as changed_archive:
                for name, content in members.items():
                    changed_archive.writestr(name, content)
            ok, issues = verify_bundle(changed_bundle)
            self.assertFalse(ok)
            self.assertTrue(any("Hash mismatch" in issue for issue in issues))

    @unittest.skipUnless(shutil.which("openssl") is not None, "OpenSSL is not installed")
    def test_bundle_manifest_ed25519_signature(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case_dir = create_case(root, "Signed bundle", "Test", "Test", "domain", "example.org")
            add_source(case_dir, "https://example.org", "Example", "domain", "primary", "high")
            bundle, _ = create_bundle(case_dir)
            private_key = root / "signing-private.pem"
            public_key = root / "signing-public.pem"
            openssl = shutil.which("openssl") or "openssl"
            subprocess.run(
                [openssl, "genpkey", "-algorithm", "ED25519", "-out", str(private_key)],
                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            subprocess.run(
                [openssl, "pkey", "-in", str(private_key), "-pubout", "-out", str(public_key)],
                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            signature_path, metadata = sign_bundle_manifest(bundle, private_key)
            self.assertEqual(metadata["algorithm"], "Ed25519")
            self.assertEqual(len(metadata["public_key_der_sha256"]), 64)
            valid, issues = verify_bundle_signature(bundle, signature_path, public_key)
            self.assertTrue(valid, issues)

            changed = read_json(signature_path)
            changed["signature"] = "AAAA"
            write_json(signature_path, changed)
            valid, issues = verify_bundle_signature(bundle, signature_path, public_key)
            self.assertFalse(valid)
            self.assertIn("Ed25519 signature verification failed", issues)

    @unittest.skipUnless(find_spec("reportlab") is not None, "ReportLab optional dependency is not installed")
    def test_pdf_report_is_reproducible_and_supports_policy_redaction(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case_dir = create_case(
                root, "PDF report", "Test deterministic rendering", "Unit-test authority",
                "organization", "Sensitive Example", "test-analyst",
            )
            source = add_source(case_dir, "https://example.org", "Example", "organization", "primary", "high")
            add_claim(case_dir, "Sensitive Example controls example.org.", "medium", [source["source_id"]])
            place_legal_hold(case_dir, "Preserve report materials", "Unit-test authority", "test-analyst")
            first_path, first_digest = render_pdf_report(case_dir)
            first_bytes = first_path.read_bytes()
            second_path, second_digest = render_pdf_report(case_dir)
            self.assertEqual(first_digest, second_digest)
            self.assertEqual(first_bytes, second_path.read_bytes())
            self.assertTrue(first_bytes.startswith(b"%PDF-"))

            policy = root / "pdf-redaction.json"
            policy.write_text(
                '{"mask_case_fields":["target","authority","legal_hold"],'
                '"mask_dataset_fields":{"claims":["statement"]},"exclude_record_ids":{}}',
                encoding="utf-8",
            )
            redacted_path, redacted_digest = render_pdf_report(case_dir, policy_path=policy)
            self.assertTrue(redacted_path.name.endswith("redacted.pdf"))
            self.assertEqual(len(redacted_digest), 64)
            self.assertTrue(redacted_path.read_bytes().startswith(b"%PDF-"))
            if find_spec("pypdf") is not None:
                from pypdf import PdfReader

                extracted = "\n".join(page.extract_text() or "" for page in PdfReader(redacted_path).pages)
                self.assertNotIn("Sensitive Example", extracted)
                self.assertNotIn("Unit-test authority", extracted)
                self.assertIn("[REDACTED]", extracted)
            actions = [row["action"] for row in read_jsonl(case_dir / "ledger.jsonl")]
            self.assertEqual(actions.count("report.rendered"), 3)
            ok, issues = verify_case(case_dir)
            self.assertTrue(ok, issues)

    def test_query_builder_encodes_values(self) -> None:
        query, url = build_query(
            "web.name-context",
            {"name": "Jane Example", "context": "Nairobi"},
            "google",
        )
        self.assertEqual(query, '"Jane Example" "Nairobi"')
        self.assertIn("Jane+Example", url)

    def test_broken_relationship_reference_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case_dir = create_case(temporary, "Reference test", "Test", "Test", "domain", "example.org")
            source = add_source(case_dir, "https://example.org", "Example", "domain", "primary", "high")
            first = add_entity(case_dir, "domain", "example.org", [source["source_id"]])
            second = add_entity(case_dir, "organization", "Example", [source["source_id"]])
            add_relationship(case_dir, first["entity_id"], "registered-to", second["entity_id"], [source["source_id"]])
            relationship_file = case_dir / "relationships.jsonl"
            relationship_file.write_text(
                relationship_file.read_text(encoding="utf-8").replace(second["entity_id"], "ENT-MISSING"),
                encoding="utf-8",
            )
            ok, issues = verify_case(case_dir)
            self.assertFalse(ok)
            self.assertTrue(any("relationships.jsonl does not match" in issue for issue in issues))

    def test_closed_case_rejects_new_records(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case_dir = create_case(temporary, "Closure test", "Test", "Test", "domain", "example.org")
            update_case_status(case_dir, "closed", "Work complete")
            with self.assertRaisesRegex(ValueError, "Case is closed"):
                add_source(case_dir, "https://example.org", "Example", "domain", "primary", "high")
            ok, issues = verify_case(case_dir)
            self.assertTrue(ok, issues)

    def test_legal_hold_freezes_retention_and_preserves_release_history(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case_dir = create_case(
                temporary, "Hold test", "Preservation test", "Case authority", "domain", "example.org",
                retention_until="2027-01-01",
            )
            placed = place_legal_hold(case_dir, "Preserve responsive material", "Counsel instruction", "custodian")
            self.assertTrue(placed["active"])
            self.assertTrue(placed["hold_id"].startswith("HLD-"))
            self.assertEqual(retention_status(case_dir)["disposition"], "held")
            with self.assertRaisesRegex(ValueError, "legal hold is active"):
                update_case_retention(case_dir, "2026-01-01", "Shorten retention", "custodian")

            released = release_legal_hold(case_dir, "Matter concluded", "Counsel instruction", "custodian")
            self.assertFalse(released["active"])
            updated = update_case_retention(case_dir, "2030-01-01", "Approved extension", "custodian")
            self.assertEqual(updated["retention_until"], "2030-01-01")
            events = read_jsonl(case_dir / "legal_holds.jsonl")
            self.assertEqual([event["action"] for event in events], ["placed", "released"])
            self.assertEqual(events[0]["hold_id"], events[1]["hold_id"])
            ok, issues = verify_case(case_dir)
            self.assertTrue(ok, issues)

    def test_runtime_json_schema_rejects_invalid_record_before_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case_dir = create_case(temporary, "Schema test", "Test", "Test", "domain", "example.org")
            with self.assertRaisesRegex(ValueError, "JSON Schema validation"):
                add_source(
                    case_dir, "https://example.org", "Example", "domain", "primary", "high",
                    accessed_at="not-a-date",
                )
            self.assertEqual(read_jsonl(case_dir / "sources.jsonl"), [])
            self.assertEqual(len(read_jsonl(case_dir / "ledger.jsonl")), 1)
            ok, issues = verify_case(case_dir)
            self.assertTrue(ok, issues)

    def test_interrupted_jsonl_write_is_recovered_idempotently(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case_dir = create_case(temporary, "Recovery test", "Test", "Test", "domain", "example.org")
            original_apply = transactions._apply_operation
            calls = 0

            def interrupt_before_ledger(case_path, operation):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("simulated crash")
                return original_apply(case_path, operation)

            with patch("osint_toolbox.transactions._apply_operation", side_effect=interrupt_before_ledger):
                with self.assertRaisesRegex(OSError, "simulated crash"):
                    add_source(case_dir, "https://example.org", "Example", "domain", "primary", "high")

            ok, issues = verify_case(case_dir)
            self.assertFalse(ok)
            self.assertTrue(any("Pending crash-recovery transaction" in issue for issue in issues))
            result = recover_case(case_dir, "recovery-operator")
            self.assertEqual(len(result["recovered_transaction_ids"]), 1)
            self.assertTrue(result["integrity_valid"], result["integrity_issues"])
            self.assertEqual(len(read_jsonl(case_dir / "sources.jsonl")), 1)
            actions = [entry["action"] for entry in read_jsonl(case_dir / "ledger.jsonl")]
            self.assertEqual(actions.count("source.added"), 1)
            self.assertEqual(actions.count("case.recovery-completed"), 1)

    def test_windows_lock_backend_locks_one_initialized_byte(self) -> None:
        class FakeMsvcrt:
            LK_LOCK = 1
            LK_UNLCK = 2

            def __init__(self) -> None:
                self.calls = []

            def locking(self, descriptor, mode, size) -> None:
                self.calls.append((descriptor, mode, size))

        with tempfile.TemporaryFile() as handle:
            backend = FakeMsvcrt()
            _lock_windows(handle, backend)
            _unlock_windows(handle, backend)
            self.assertEqual(handle.seek(0, 2), 1)
            self.assertEqual([call[1:] for call in backend.calls], [(backend.LK_LOCK, 1), (backend.LK_UNLCK, 1)])

    def test_schema_1_0_case_migrates_without_losing_history(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case_dir = Path(temporary) / "CASE-LEGACY"
            case_dir.mkdir()
            for directory in ("artifacts", "notes", "reports"):
                (case_dir / directory).mkdir()
            for filename in ("sources.jsonl", "claims.jsonl", "artifacts.jsonl", "ledger.jsonl"):
                (case_dir / filename).touch()
            legacy = {
                "schema_version": "1.0",
                "case_id": "CASE-LEGACY",
                "title": "Legacy case",
                "purpose": "Migration test",
                "authority": "Test authority",
                "target_type": "domain",
                "target": "example.org",
                "owner": "test",
                "created_at_utc": "2026-09-14T00:00:00Z",
                "status": "open",
            }
            write_json(case_dir / "case.json", legacy)
            original_entry = append_ledger(case_dir, "case.created", legacy, "test")
            migrated, changed = upgrade_case(case_dir, "test")
            self.assertTrue(changed)
            self.assertEqual(migrated["schema_version"], "1.4")
            self.assertTrue((case_dir / "observations.jsonl").is_file())
            self.assertTrue((case_dir / "legal_holds.jsonl").is_file())
            self.assertEqual(read_json(case_dir / "case.json")["collection_tier"], "passive-public")
            self.assertFalse(read_json(case_dir / "case.json")["legal_hold"]["active"])
            self.assertEqual(original_entry["entry_sha256"], read_jsonl(case_dir / "ledger.jsonl")[0]["entry_sha256"])
            self.assertEqual(
                [entry["payload"]["to_version"] for entry in read_jsonl(case_dir / "ledger.jsonl") if entry["action"] == "case.migrated"],
                ["1.1", "1.2", "1.3", "1.4"],
            )
            ok, issues = verify_case(case_dir)
            self.assertTrue(ok, issues)

    def test_schema_1_1_case_uses_registered_forward_migration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case_dir = create_case(temporary, "Migration registry", "Test", "Test", "domain", "example.org")
            current = read_json(case_dir / "case.json")
            current["schema_version"] = "1.1"
            current.pop("legal_hold")
            write_json(case_dir / "case.json", current)
            ledger = read_jsonl(case_dir / "ledger.jsonl")
            ledger[0]["payload"] = current
            ledger[0].pop("transaction_id", None)
            ledger[0].pop("entry_sha256")
            from osint_toolbox.util import canonical_json, sha256_bytes

            ledger[0]["entry_sha256"] = sha256_bytes(canonical_json(ledger[0]).encode("utf-8"))
            (case_dir / "ledger.jsonl").write_text(canonical_json(ledger[0]) + "\n", encoding="utf-8")
            migrated, changed = upgrade_case(case_dir, "migrator")
            self.assertTrue(changed)
            self.assertEqual(migrated["schema_version"], "1.4")
            ok, issues = verify_case(case_dir)
            self.assertTrue(ok, issues)

    def test_quality_audit_finds_duplicate_entities_and_observation_gap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case_dir = create_case(temporary, "Audit test", "Test", "Test", "organization", "Example")
            source = add_source(
                case_dir, "https://example.org", "Old source", "organization", "primary", "high",
                accessed_at="2020-01-01T00:00:00Z",
            )
            first = add_entity(case_dir, "organization", "Example Inc", [source["source_id"]])
            second = add_entity(case_dir, "organization", " example   inc ", [source["source_id"]])
            add_claim(case_dir, "Example claim", "low", [source["source_id"]])
            _, audit = audit_case(case_dir, stale_days=30)
            categories = {finding["category"] for finding in audit["findings"]}
            self.assertIn("duplicate-entity-candidate", categories)
            self.assertIn("claim-observation-gap", categories)
            self.assertIn("stale-source", categories)
            self.assertIn(first["entity_id"], str(audit))
            self.assertIn(second["entity_id"], str(audit))
            ok, issues = verify_case(case_dir)
            self.assertTrue(ok, issues)


if __name__ == "__main__":
    unittest.main()
