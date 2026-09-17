from __future__ import annotations

import csv
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from xml.etree import ElementTree as ET

from osint_toolbox.audit import audit_case, review_finding
from osint_toolbox.case import add_artifact, add_entity, add_event, add_relationship, add_source, create_case, upgrade_case, verify_case
from osint_toolbox.cli import main
from osint_toolbox.exports import export_csv, export_graphml, export_maltego
from osint_toolbox.util import read_json, read_jsonl, write_json
from osint_toolbox.workbench import active_resolution_groups, record_resolution, record_worksheet, render_workbench


class WorkbenchTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.case = create_case(self.root, "Review <script>alert(1)</script>", "Test", "Authorized test", "media", "test")
        self.source = add_source(self.case, "https://example.org/one", "Primary page", "media", "primary", "high")
        self.sid = self.source["source_id"]

    def test_merge_split_source_trace_and_graph_truth(self) -> None:
        first = add_entity(self.case, "organization", "Example", [self.sid])
        second = add_entity(self.case, "organization", "example", [self.sid])
        first_id, second_id = first["entity_id"], second["entity_id"]
        with self.assertRaises(ValueError):
            record_resolution(self.case, "merge", [first_id, second_id], [], [self.sid], "Unproven")
        with self.assertRaises(ValueError):
            record_resolution(self.case, "merge", [first_id, second_id], [{"description": "name", "source_ids": ["SRC-UNKNOWN"]}], [self.sid], "Unproven")
        feature = {"description": "Shared verified registration", "source_ids": [self.sid]}
        merge = record_resolution(self.case, "merge", [first_id, second_id], [feature], [self.sid], "Corroborated registration")
        self.assertEqual(len([g for g in active_resolution_groups(read_jsonl(self.case / "entities.jsonl"), read_jsonl(self.case / "resolutions.jsonl")) if len(g) == 2]), 1)
        relationship = add_relationship(self.case, first_id, "same-region", second_id, [self.sid], evidence_kind="inferred")
        event = add_event(self.case, "Public notice", "publication", "2026-09-17", [self.sid])
        graph = export_graphml(self.case)
        tree = ET.parse(graph)
        ns = {"g": "http://graphml.graphdrawing.org/xmlns"}
        edge = tree.find(".//g:edge", ns)
        self.assertEqual(edge.attrib["id"], relationship["relationship_id"])
        edge_data = {d.attrib["key"]: d.text for d in edge.findall("g:data", ns)}
        self.assertEqual(edge_data["evidence_kind"], "inferred")
        self.assertEqual(edge_data["source_ids"], self.sid)
        self.assertTrue(all(node.find("g:data[@key='source_ids']", ns).text == self.sid for node in tree.findall(".//g:node", ns)))
        maltego = export_maltego(self.case)
        with (maltego / "links.csv").open(newline="", encoding="utf-8") as handle:
            self.assertEqual(next(csv.DictReader(handle))["evidence_kind"], "inferred")
        self.assertEqual(read_json(maltego / "graph.json")["links"][0]["source_ids"], [self.sid])
        view = render_workbench(self.case)
        html = view.read_text(encoding="utf-8")
        self.assertIn(event["event_id"], html)
        self.assertIn("\\u003cscript\\u003e", html)
        self.assertNotIn("<script>alert(1)</script>", html)
        record_resolution(self.case, "split", [first_id, second_id], [], [self.sid], "Independent review disputes match", merge["resolution_id"])
        self.assertEqual(len(active_resolution_groups(read_jsonl(self.case / "entities.jsonl"), read_jsonl(self.case / "resolutions.jsonl"))), 2)
        self.assertEqual(len(read_jsonl(self.case / "entities.jsonl")), 2)
        with self.assertRaises(ValueError):
            record_resolution(self.case, "split", [first_id, second_id], [], [self.sid], "Duplicate reversal", merge["resolution_id"])
        self.assertTrue(verify_case(self.case)[0])

    def test_worksheets_media_and_map_snapshot_refs(self) -> None:
        image = self.root / "image.png"
        image.write_bytes(b"image bytes")
        subject = add_artifact(self.case, image, self.source["url"], "media")
        snapshot = add_artifact(self.case, image, self.source["url"], "maps")
        clue = {"description": "Road sign", "source_ids": [self.sid]}
        geo = {
            "kind": "geolocation", "title": "Candidate site", "subject_artifact_id": subject["artifact_id"],
            "source_ids": [self.sid], "artifact_ids": [subject["artifact_id"], snapshot["artifact_id"]],
            "clues": [clue], "candidates": [{"label": "Nairobi?", "source_ids": [self.sid], "matched_features": [clue], "mismatched_features": [clue], "map_artifact_ids": [snapshot["artifact_id"]]}],
            "leads": [], "assessment": "Unconfirmed",
        }
        row = record_worksheet(self.case, geo)
        self.assertEqual(row["kind"], "geolocation")
        invalid = json.loads(json.dumps(geo))
        invalid["candidates"][0]["map_artifact_ids"] = ["ART-MISSING"]
        with self.assertRaises(ValueError):
            record_worksheet(self.case, invalid)
        media = {
            "kind": "media-provenance", "title": "First-appearance review", "subject_artifact_id": subject["artifact_id"],
            "source_ids": [self.sid], "artifact_ids": [subject["artifact_id"]], "clues": [], "candidates": [],
            "leads": [{"lead_kind": "reverse-search", "description": "Similar image", "url": self.source["url"], "observed_at": "2026-09-17", "source_ids": [self.sid], "notes": "Not confirmed"}, {"lead_kind": "earliest-appearance", "description": "Earliest seen", "url": self.source["url"], "observed_at": "2025-01-01", "source_ids": [self.sid], "notes": "Archive lead"}], "assessment": "Original unknown",
        }
        record_worksheet(self.case, media)
        self.assertIn(snapshot["artifact_id"], render_workbench(self.case).read_text(encoding="utf-8"))
        self.assertTrue(verify_case(self.case)[0])

    def test_audit_dispositions_are_append_only_and_integrity_not_suppressed(self) -> None:
        add_entity(self.case, "organization", "Repeated", [self.sid])
        add_entity(self.case, "organization", "repeated", [self.sid])
        _, audit = audit_case(self.case)
        found = next(x for x in audit["findings"] if x["category"] == "duplicate-entity-candidate")
        review_finding(self.case, found["fingerprint"], "false-positive", "Independent branches", "reviewer")
        _, later = audit_case(self.case)
        reviewed = next(x for x in later["findings"] if x["fingerprint"] == found["fingerprint"])
        self.assertTrue(reviewed["suppressed"])
        self.assertEqual(reviewed["review"]["reason"], "Independent branches")
        self.assertEqual(later["summary"]["suppressed_count"], 1)
        review_finding(self.case, found["fingerprint"], "reopened", "New evidence", "reviewer")
        self.assertFalse(next(x for x in audit_case(self.case)[1]["findings"] if x["fingerprint"] == found["fingerprint"])["suppressed"])
        self.assertEqual(len(read_jsonl(self.case / "audit_reviews.jsonl")), 2)
        self.assertTrue(verify_case(self.case)[0])

    def test_unsourced_legacy_entity_is_not_silently_exported(self) -> None:
        add_entity(self.case, "person", "Unknown", [])
        self.assertTrue(verify_case(self.case)[0])
        with self.assertRaisesRegex(ValueError, "source IDs"):
            export_graphml(self.case)
        with self.assertRaisesRegex(ValueError, "Untraceable"):
            render_workbench(self.case)
        self.assertIn("missing-entity-source", [x["category"] for x in audit_case(self.case)[1]["findings"]])

    def test_csv_free_text_is_not_executable_spreadsheet_formula(self) -> None:
        add_entity(self.case, "organization", "=1+1", [self.sid])
        path = export_csv(self.case)
        with (path / "entities.csv").open(newline="", encoding="utf-8") as handle:
            self.assertEqual(next(csv.DictReader(handle))["label"], "'=1+1")
        maltego = export_maltego(self.case)
        with (maltego / "entities.csv").open(newline="", encoding="utf-8") as handle:
            self.assertEqual(next(csv.DictReader(handle))["label"], "'=1+1")
        self.assertEqual(read_json(maltego / "graph.json")["entities"][0]["label"], "=1+1")

    def test_phase3_cli_commands_and_invalid_feature_gate(self) -> None:
        first = add_entity(self.case, "organization", "First", [self.sid])
        second = add_entity(self.case, "organization", "Second", [self.sid])
        base = [str(self.case), "merge", first["entity_id"], second["entity_id"], "--source-id", self.sid, "--reason", "Independent evidence"]
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as err:
                main(["resolve-entities", *base])
        self.assertEqual(err.exception.code, 2)
        feature = json.dumps({"description": "Matching official registry", "source_ids": [self.sid]})
        with contextlib.redirect_stdout(io.StringIO()) as out:
            main(["resolve-entities", *base, "--feature", feature])
        merge_id = out.getvalue().strip()
        self.assertTrue(merge_id.startswith("RES-"))
        with contextlib.redirect_stdout(io.StringIO()):
            main(["workbench", str(self.case)])
            main(["export", str(self.case), "maltego"])
        self.assertTrue((self.case / "reports" / "workbench.html").exists())
        with contextlib.redirect_stdout(io.StringIO()):
            main(["resolve-entities", str(self.case), "split", first["entity_id"], second["entity_id"], "--source-id", self.sid, "--reason", "Other evidence", "--reverses-id", merge_id])
        self.assertTrue(verify_case(self.case)[0])

    def test_forward_migration_from_1_2_adds_analysis_datasets(self) -> None:
        from osint_toolbox.util import canonical_json, sha256_bytes
        legacy = create_case(self.root, "Legacy 1.2", "Test", "Test", "domain", "example.org")
        old = read_json(legacy / "case.json")
        old["schema_version"] = "1.2"
        write_json(legacy / "case.json", old)
        row = read_jsonl(legacy / "ledger.jsonl")[0]
        row["payload"] = old
        row.pop("entry_sha256")
        row["entry_sha256"] = sha256_bytes(canonical_json(row).encode("utf-8"))
        (legacy / "ledger.jsonl").write_text(canonical_json(row) + "\n", encoding="utf-8")
        upgraded, changed = upgrade_case(legacy)
        self.assertTrue(changed)
        self.assertEqual(upgraded["schema_version"], "1.4")
        self.assertTrue((legacy / "worksheets.jsonl").exists())
        self.assertTrue(verify_case(legacy)[0])


if __name__ == "__main__":
    unittest.main()
