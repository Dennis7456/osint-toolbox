from __future__ import annotations

import json
import os
import subprocess
import unittest
import tempfile
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from unittest.mock import Mock, patch

from osint_toolbox.case import create_case, verify_case
from osint_toolbox.policy import approve_provider
from osint_toolbox.cli import main
from osint_toolbox.providers import (
    FetchResult,
    PREPARERS,
    PROVIDERS,
    PreparedCollection,
    build_whatsmyname_queue,
    parse_commoncrawl,
    parse_crtsh,
    parse_dns,
    parse_rdap,
    parse_securitytrails_history,
    parse_searxng,
    parse_sherlock_csv,
    parse_wayback_rows,
    probe_provider,
    _retry_delay,
    select_rdap_base,
    collect_provider,
)
from osint_toolbox.util import read_jsonl


class ProviderParserTest(unittest.TestCase):
    def test_wayback_rows_normalize(self) -> None:
        payload = [
            ["timestamp", "original", "mimetype", "statuscode", "digest", "length"],
            ["20200102030405", "https://example.org/", "text/html", "200", "ABC", "42"],
        ]
        records = parse_wayback_rows(payload, 10)
        self.assertEqual(records[0]["kind"], "archive.capture")
        self.assertEqual(records[0]["value"]["original"], "https://example.org/")

    def test_rdap_bootstrap_and_record_normalize(self) -> None:
        bootstrap = {"services": [[ ["com", "net"], ["https://rdap.example/"] ]]}
        self.assertEqual(select_rdap_base(bootstrap, "example.com"), "https://rdap.example/")
        records = parse_rdap({
            "ldhName": "EXAMPLE.COM",
            "status": ["active"],
            "events": [{"eventAction": "registration", "eventDate": "2000-01-01T00:00:00Z"}],
            "nameservers": [{"ldhName": "NS1.EXAMPLE.COM"}],
        })
        self.assertEqual({record["kind"] for record in records}, {"domain.name", "domain.status", "domain.event", "domain.nameserver"})

    def test_crtsh_and_searxng_normalize(self) -> None:
        certificates = parse_crtsh([{"id": 1, "name_value": "example.org\nwww.example.org", "entry_timestamp": "2024-01-01"}], 10)
        self.assertEqual(certificates[0]["value"]["dns_names"], ["example.org", "www.example.org"])
        results = parse_searxng({"results": [{"url": "https://example.org", "title": "Example", "engine": "test"}]}, 10)
        self.assertEqual(results[0]["value"]["engine"], "test")

    def test_commoncrawl_ndjson_and_dns_normalize(self) -> None:
        content = (
            b'{"url":"https://example.org/","timestamp":"20250101000000","status":"200",'
            b'"digest":"ABC","filename":"crawl.warc.gz"}\n'
        )
        crawl = parse_commoncrawl(content, 10)
        self.assertEqual(crawl[0]["kind"], "web-crawl.index-entry")
        self.assertEqual(crawl[0]["value"]["digest"], "ABC")
        dns = parse_dns({
            "Status": 0,
            "AD": True,
            "Answer": [{"name": "example.org.", "type": 1, "TTL": 300, "data": "192.0.2.1"}],
        })
        self.assertEqual(dns[0]["kind"], "dns.response-status")
        self.assertEqual(dns[1]["value"]["type_name"], "A")

    def test_securitytrails_history_normalizes_and_distinguishes_errors(self) -> None:
        records = parse_securitytrails_history({
            "records": [{
                "first_seen": "2024-01-01",
                "last_seen": "2024-06-30",
                "organizations": ["Example Network"],
                "values": [{"ip": "192.0.2.10"}],
            }],
        }, "a", 10)
        self.assertEqual(records[0]["kind"], "dns.history")
        self.assertEqual(records[0]["value"]["record_type"], "A")
        self.assertEqual(records[0]["value"]["values"], [{"ip": "192.0.2.10"}])
        self.assertEqual(records[0]["observed_at"], "2024-06-30")
        self.assertEqual(parse_securitytrails_history({"records": []}, "A", 10), [])
        with self.assertRaisesRegex(ValueError, "quota exceeded"):
            parse_securitytrails_history({"message": "quota exceeded"}, "A", 10)

    def test_securitytrails_collection_uses_header_without_secret_leakage(self) -> None:
        payload = {
            "records": [{
                "first_seen": "2024-01-01",
                "last_seen": "2024-01-02",
                "organizations": [],
                "values": [{"ip": "192.0.2.10"}],
            }],
        }
        content = json.dumps(payload).encode("utf-8")
        final_url = "https://api.securitytrails.com/v1/history/example.org/dns/a?page=1"
        fetch_result = FetchResult(final_url, final_url, content, "application/json")
        with tempfile.TemporaryDirectory() as temporary:
            case_dir = create_case(temporary, "Historical DNS", "Test", "Test", "domain", "example.org", retention_until="2099-01-01")
            authority_file = Path(temporary) / "authorization.txt"
            authority_file.write_text("Test authorization", encoding="utf-8")
            from osint_toolbox.case import add_artifact
            authority_id = add_artifact(case_dir, authority_file, "https://example.org/authorization", "authority")["artifact_id"]
            from datetime import datetime, timedelta, timezone
            approve_provider(case_dir, "securitytrails", "example.org", "asset-authorized", "Approved test",
                             "reviewer", "collector", (datetime.now(timezone.utc) + timedelta(days=7)).isoformat(),
                             authority_artifact_id=authority_id, terms_reviewed=True,
                             data_residency_accepted=True, cost_acknowledged=True,
                             data_residency_note="Reviewed account contract", cost_note="One test query")
            with patch.dict(os.environ, {"SECURITYTRAILS_API_KEY": "test-secret"}):
                with patch("osint_toolbox.providers._fetch", return_value=fetch_result) as fetch:
                    result = collect_provider(
                        case_dir,
                        "securitytrails",
                        "example.org",
                        {"record_type": "A"},
                        confirm_external_disclosure=True,
                    )
            request_url = fetch.call_args.args[0]
            self.assertNotIn("test-secret", request_url)
            self.assertEqual(fetch.call_args.kwargs["headers"], {"APIKEY": "test-secret"})
            self.assertNotIn("test-secret", json.dumps(result))
            self.assertEqual(len(result["observations"]), 1)
            ok, issues = verify_case(case_dir)
            self.assertTrue(ok, issues)

    def test_whatsmyname_is_manual_queue_only(self) -> None:
        payload = {
            "sites": [
                {"name": "Example", "uri_pretty": "https://example.org/", "uri_check": "https://example.org/{account}", "cat": "social", "known": "known"},
                {"name": "Invalid", "uri_check": "https://invalid.example/{account}", "cat": "social", "valid": False},
            ]
        }
        queue = build_whatsmyname_queue(payload, "jane/example", 10)
        self.assertEqual(len(queue), 1)
        self.assertEqual(queue[0]["status"], "candidate-unverified")
        self.assertIn("jane%2Fexample", queue[0]["value"]["profile_url"])
        self.assertIn("No request was made", queue[0]["notes"])

    def test_sherlock_csv_preserves_claimed_available_and_blocked_outcomes(self) -> None:
        content = (
            b"username,name,url_main,url_user,exists,http_status,response_time_s\n"
            b"analyst,GitHub,https://github.com,https://github.com/analyst,Claimed,200,0.2\n"
            b"analyst,Reddit,https://reddit.com,https://reddit.com/user/analyst,Available,404,0.1\n"
            b"analyst,Example,https://example.org,https://example.org/analyst,WAF,403,0.3\n"
        )
        records = parse_sherlock_csv(content, 10)
        self.assertEqual(len(records), 3)
        self.assertEqual(records[0]["kind"], "username.profile-candidate")
        self.assertEqual(records[0]["status"], "candidate-unverified")
        self.assertEqual(records[1]["value"]["outcome"], "Available")
        self.assertEqual(records[1]["status"], "unavailable")
        self.assertIn("inconclusive", records[2]["notes"])

    def test_sherlock_requires_allowlist_and_preserves_scoped_csv(self) -> None:
        csv_output = (
            "username,name,url_main,url_user,exists,http_status,response_time_s\n"
            "analyst,GitHub,https://github.com,https://github.com/analyst,Claimed,200,0.2\n"
            "analyst,Reddit,https://reddit.com,https://reddit.com/user/analyst,Available,404,0.1\n"
        ).encode("utf-8")
        commands: list[list[str]] = []

        def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[bytes]:
            commands.append(command)
            if "--version" in command:
                return subprocess.CompletedProcess(command, 0, b"Sherlock v0.16.0\n", b"")
            folder = Path(command[command.index("--folderoutput") + 1])
            (folder / "analyst.csv").write_bytes(csv_output)
            return subprocess.CompletedProcess(command, 0, b"", b"")

        with tempfile.TemporaryDirectory() as temporary:
            case_dir = create_case(temporary, "Scoped username", "Test", "Test", "username", "analyst")
            with self.assertRaisesRegex(ValueError, "broad all-site runs are disabled"):
                collect_provider(case_dir, "sherlock", "analyst", {}, confirm_external_disclosure=True)
            with patch("osint_toolbox.providers.shutil.which", return_value="/opt/tools/sherlock"):
                with patch("osint_toolbox.providers.subprocess.run", side_effect=fake_run):
                    result = collect_provider(
                        case_dir,
                        "sherlock",
                        "analyst",
                        {"sites": "GitHub,Reddit", "timeout": "5", "max_runtime": "30"},
                        confirm_external_disclosure=True,
                    )
            run_command = commands[1]
            self.assertIn("--print-all", run_command)
            self.assertEqual(run_command.count("--site"), 2)
            self.assertNotIn("--browse", run_command)
            self.assertEqual(len(result["observations"]), 2)
            self.assertEqual(result["observations"][0]["status"], "candidate-unverified")
            self.assertEqual(result["observations"][1]["value"]["outcome"], "Available")
            self.assertIn("explicit site allowlist: GitHub, Reddit", result["source"]["notes"])
            runs = read_jsonl(case_dir / "provider_runs.jsonl")
            self.assertEqual([run["status"] for run in runs], ["failed", "completed"])
            ok, issues = verify_case(case_dir)
            self.assertTrue(ok, issues)

    def test_failed_validation_is_audited_without_network(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case_dir = create_case(temporary, "Provider failure", "Test", "Test", "domain", "example.org")
            with self.assertRaisesRegex(ValueError, "Expected a domain"):
                collect_provider(case_dir, "rdap", "invalid", confirm_external_disclosure=True)
            runs = read_jsonl(case_dir / "provider_runs.jsonl")
            self.assertEqual(runs[0]["status"], "failed")
            ok, issues = verify_case(case_dir)
            self.assertTrue(ok, issues)

    def test_cli_requires_explicit_network_acknowledgment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case_dir = create_case(temporary, "Opt in", "Test", "Test", "domain", "example.org")
            with redirect_stderr(StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    main(["collect", str(case_dir), "rdap", "--target", "example.org"])
            self.assertEqual(raised.exception.code, 2)
            self.assertEqual(read_jsonl(case_dir / "provider_runs.jsonl"), [])

    def test_cli_execute_still_requires_disclosure_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case_dir = create_case(temporary, "Two gates", "Test", "Test", "domain", "example.org")
            preparer = Mock()
            with patch.dict(PREPARERS, {"rdap": preparer}):
                with redirect_stderr(StringIO()):
                    with self.assertRaises(SystemExit) as raised:
                        main(["collect", str(case_dir), "rdap", "--target", "example.org", "--execute"])
            self.assertEqual(raised.exception.code, 2)
            preparer.assert_not_called()
            self.assertEqual(read_jsonl(case_dir / "provider_runs.jsonl")[0]["status"], "blocked")

    def test_external_target_disclosure_is_blocked_and_audited_without_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case_dir = create_case(
                temporary,
                "Disclosure gate",
                "Test",
                "Test",
                "domain",
                "example.org",
                sensitivity="confidential",
            )
            with patch.dict(PREPARERS, {"rdap": Mock()}):
                with self.assertRaisesRegex(ValueError, "confirm-external-disclosure"):
                    collect_provider(case_dir, "rdap", "example.org")
                PREPARERS["rdap"].assert_not_called()
            runs = read_jsonl(case_dir / "provider_runs.jsonl")
            self.assertEqual(len(runs), 1)
            self.assertEqual(runs[0]["status"], "blocked")
            self.assertIn("confidential", runs[0]["error"])
            ok, issues = verify_case(case_dir)
            self.assertTrue(ok, issues)

    def test_confirmed_disclosure_is_hash_chained_and_linked_to_source(self) -> None:
        prepared = PreparedCollection(
            "rdap",
            "https://rdap.example/domain/example.org",
            "Example RDAP",
            "domain",
            "primary",
            "high",
            "rdap-example.json",
            b'{"ldhName":"EXAMPLE.ORG"}',
            "application/json",
            [{"kind": "domain.name", "value": "EXAMPLE.ORG", "status": "observed"}],
            "Authoritative test response.",
        )
        with tempfile.TemporaryDirectory() as temporary:
            case_dir = create_case(
                temporary,
                "Confirmed disclosure",
                "Test",
                "Test",
                "domain",
                "example.org",
                sensitivity="restricted",
            )
            with patch.dict(PREPARERS, {"rdap": Mock(return_value=prepared)}):
                result = collect_provider(
                    case_dir,
                    "rdap",
                    "example.org",
                    collector="reviewed-analyst",
                    confirm_external_disclosure=True,
                )
            confirmation_entries = [
                row for row in read_jsonl(case_dir / "ledger.jsonl")
                if row["action"] == "provider.external-disclosure-confirmed"
            ]
            self.assertEqual(len(confirmation_entries), 1)
            confirmation = confirmation_entries[0]["payload"]
            self.assertEqual(confirmation["case_sensitivity"], "restricted")
            self.assertEqual(confirmation_entries[0]["actor"], "reviewed-analyst")
            self.assertIn(confirmation["confirmation_id"], result["source"]["notes"])
            self.assertEqual(result["run"]["status"], "completed")
            ok, issues = verify_case(case_dir)
            self.assertTrue(ok, issues)

    def test_zero_results_failure_and_block_are_distinct(self) -> None:
        empty = PreparedCollection(
            "rdap",
            "https://rdap.example/domain/example.org",
            "Empty RDAP",
            "domain",
            "primary",
            "high",
            "rdap-empty.json",
            b"{}",
            "application/json",
            [],
        )
        with tempfile.TemporaryDirectory() as temporary:
            case_dir = create_case(temporary, "Outcome semantics", "Test", "Test", "domain", "example.org")
            with patch.dict(PREPARERS, {"rdap": Mock(return_value=empty)}):
                completed = collect_provider(
                    case_dir, "rdap", "example.org", confirm_external_disclosure=True
                )
            self.assertEqual(completed["run"]["status"], "completed")
            self.assertEqual(completed["run"]["observation_count"], 0)

            with patch.dict(PREPARERS, {"rdap": Mock(side_effect=ValueError("provider unavailable"))}):
                with self.assertRaisesRegex(ValueError, "provider unavailable"):
                    collect_provider(case_dir, "rdap", "example.org", confirm_external_disclosure=True)
            with self.assertRaisesRegex(ValueError, "confirm-external-disclosure"):
                collect_provider(case_dir, "rdap", "example.org")
            statuses = [row["status"] for row in read_jsonl(case_dir / "provider_runs.jsonl")]
            self.assertEqual(statuses, ["completed", "failed", "blocked"])

    def test_dataset_only_queue_does_not_require_target_disclosure_confirmation(self) -> None:
        prepared = PreparedCollection(
            "whatsmyname",
            "https://example.test/wmn-data.json",
            "WhatsMyName test dataset",
            "username",
            "secondary",
            "medium",
            "wmn-data.json",
            b'{"sites":[]}',
            "application/json",
            [],
            "No profile service received the username.",
        )
        with tempfile.TemporaryDirectory() as temporary:
            case_dir = create_case(temporary, "Dataset only", "Test", "Test", "username", "analyst")
            with patch.dict(PREPARERS, {"whatsmyname": Mock(return_value=prepared)}):
                result = collect_provider(case_dir, "whatsmyname", "analyst")
            self.assertEqual(result["run"]["status"], "completed")
            actions = [row["action"] for row in read_jsonl(case_dir / "ledger.jsonl")]
            self.assertNotIn("provider.external-disclosure-confirmed", actions)

    def test_provider_metadata_and_unknown_options_are_strict(self) -> None:
        self.assertEqual(set(PROVIDERS), set(PREPARERS))
        for metadata in PROVIDERS.values():
            self.assertIn(metadata["target_disclosure"], {"external", "none"})
            self.assertIsInstance(metadata["options"], tuple)
        with tempfile.TemporaryDirectory() as temporary:
            case_dir = create_case(temporary, "Strict options", "Test", "Test", "domain", "example.org")
            with patch.dict(PREPARERS, {"rdap": Mock()}):
                with self.assertRaisesRegex(ValueError, "Unsupported rdap provider option"):
                    collect_provider(
                        case_dir,
                        "rdap",
                        "example.org",
                        {"timout": "10"},
                        confirm_external_disclosure=True,
                    )
                PREPARERS["rdap"].assert_not_called()
            self.assertEqual(read_jsonl(case_dir / "provider_runs.jsonl")[0]["status"], "failed")

    def test_retry_after_is_bounded(self) -> None:
        self.assertEqual(_retry_delay({"Retry-After": "3"}, 0), 3.0)
        self.assertEqual(_retry_delay({"Retry-After": "999"}, 0), 10.0)
        self.assertEqual(_retry_delay({}, 2), 4.0)

    def test_unconfigured_searxng_probe_does_not_use_network(self) -> None:
        result = probe_provider("searxng", {})
        self.assertEqual(result["status"], "unconfigured")
        self.assertEqual(result["response_bytes"], 0)

    def test_unconfigured_securitytrails_probe_does_not_use_network(self) -> None:
        with patch.dict(os.environ, {"SECURITYTRAILS_API_KEY": ""}):
            with patch("osint_toolbox.providers._fetch") as fetch:
                result = probe_provider("securitytrails", {})
        fetch.assert_not_called()
        self.assertEqual(result["status"], "unconfigured")
        self.assertEqual(result["response_bytes"], 0)

    def test_unconfigured_sherlock_probe_does_not_run_subprocess(self) -> None:
        with patch("osint_toolbox.providers.shutil.which", return_value=None):
            with patch("osint_toolbox.providers.subprocess.run") as process:
                result = probe_provider("sherlock", {})
        process.assert_not_called()
        self.assertEqual(result["status"], "unconfigured")


if __name__ == "__main__":
    unittest.main()
