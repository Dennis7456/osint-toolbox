from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from io import StringIO
from importlib.util import find_spec
from pathlib import Path
from urllib.request import Request
from unittest.mock import patch

from osint_toolbox.case import add_artifact, add_claim, create_case, verify_case
from osint_toolbox.cli import main
from osint_toolbox.exports import build_redacted_snapshot
from osint_toolbox.pdf_reports import render_pdf_report
from osint_toolbox.policy import approve_provider, provider_profiles, registry_profiles, revoke_provider_approval
from osint_toolbox.providers import FetchResult, _SameOriginRedirect, _fetch, collect_provider, probe_provider
from osint_toolbox.util import read_jsonl


class LicensedProviderTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.expiry = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()

    def case(self, target_type: str, target: str, retention: str = "2099-01-01") -> Path:
        return create_case(self.root, "Licensed review", "Authorized test", "Written test authorization", target_type, target,
                           owner="collector", retention_until=retention)

    def authority_artifact(self, case: Path) -> str:
        original = self.root / "authorization.txt"
        original.write_text("Written test authorization", encoding="utf-8")
        return add_artifact(case, original, "https://example.org/authorization", "authority")["artifact_id"]

    def approve(self, case: Path, provider: str, target: str, basis: str, artifact: str = "", max_runs: int = 1):
        return approve_provider(case, provider, target, basis, "Reviewed purpose, terms and cost", "reviewer", "collector",
                                self.expiry, max_runs, artifact, True, True, True,
                                "Provider jurisdiction reviewed", "One query within account credits")

    def test_hibp_account_fails_closed_and_404_is_zero_not_failure(self) -> None:
        email = "me@example.org"
        case = self.case("email", email)
        with patch("osint_toolbox.providers._fetch") as fetch:
            with self.assertRaisesRegex(ValueError, "approval|credential"):
                collect_provider(case, "hibp-account", email, confirm_external_disclosure=True)
            fetch.assert_not_called()
        with self.assertRaisesRegex(ValueError, "acknowledgment"):
            approve_provider(case, "hibp-account", email, "self", "Reason", "reviewer", "collector", self.expiry)
        approval = self.approve(case, "hibp-account", email, "self")
        self.assertEqual(approval["provider"], "hibp-account")
        with patch("osint_toolbox.providers._fetch") as fetch:
            with self.assertRaisesRegex(ValueError, "HIBP_API_KEY"):
                collect_provider(case, "hibp-account", email, confirm_external_disclosure=True)
            fetch.assert_not_called()
        with patch.dict(os.environ, {"HIBP_API_KEY": "wrong-format"}):
            with patch("osint_toolbox.providers._fetch") as fetch:
                with self.assertRaisesRegex(ValueError, "32-character"):
                    collect_provider(case, "hibp-account", email, confirm_external_disclosure=True)
                fetch.assert_not_called()
        self.assertFalse(any(row["action"] == "provider.approved-run-reserved" for row in read_jsonl(case / "ledger.jsonl")))
        with patch.dict(os.environ, {"HIBP_API_KEY": "a" * 32}):
            with patch("osint_toolbox.providers._fetch") as fetch:
                with self.assertRaisesRegex(ValueError, "confirm-external-disclosure"):
                    collect_provider(case, "hibp-account", email)
                fetch.assert_not_called()
            with patch("osint_toolbox.providers._fetch", return_value=FetchResult(
                "https://haveibeenpwned.com/api/v3/breachedAccount/me%40example.org",
                "https://haveibeenpwned.com/api/v3/breachedAccount/me%40example.org", b"", "application/json", 404,
            )) as fetch:
                result = collect_provider(case, "hibp-account", email, confirm_external_disclosure=True)
                self.assertEqual(result["run"]["status"], "completed")
                self.assertEqual(result["observations"], [])
                self.assertEqual(fetch.call_args.kwargs["headers"], {"hibp-api-key": "a" * 32})
                self.assertEqual(fetch.call_args.kwargs["allow_statuses"], {404})
            with patch("osint_toolbox.providers._fetch") as fetch:
                with self.assertRaisesRegex(ValueError, "run limit"):
                    collect_provider(case, "hibp-account", email, confirm_external_disclosure=True)
                fetch.assert_not_called()
        ledger = (case / "ledger.jsonl").read_text(encoding="utf-8")
        self.assertNotIn("a" * 32, ledger)
        self.assertEqual(sum(row["action"] == "provider.approved-run-reserved" for row in read_jsonl(case / "ledger.jsonl")), 1)
        self.assertTrue(verify_case(case)[0])

    def test_hibp_verified_domain_checked_before_breach_query(self) -> None:
        case = self.case("domain", "example.org")
        self.approve(case, "hibp-domain", "example.org", "verified-domain")
        with patch.dict(os.environ, {"HIBP_API_KEY": "b" * 32}):
            with patch("osint_toolbox.providers._fetch", return_value=FetchResult(
                "https://haveibeenpwned.com/api/v3/subscribedDomains",
                "https://haveibeenpwned.com/api/v3/subscribedDomains", b"[]", "application/json",
            )) as fetch:
                with self.assertRaisesRegex(ValueError, "not verified"):
                    collect_provider(case, "hibp-domain", "example.org", confirm_external_disclosure=True)
                self.assertEqual(fetch.call_count, 1)
            self.approve(case, "hibp-domain", "example.org", "verified-domain")
            responses = [
                FetchResult("https://haveibeenpwned.com/api/v3/subscribedDomains",
                            "https://haveibeenpwned.com/api/v3/subscribedDomains",
                            b'[{"DomainName":"example.org"}]', "application/json"),
                FetchResult("https://haveibeenpwned.com/api/v3/breachedDomain/example.org",
                            "https://haveibeenpwned.com/api/v3/breachedDomain/example.org",
                            b'{"alias":["ExampleBreach"]}', "application/json"),
            ]
            with patch("osint_toolbox.providers._fetch", side_effect=responses) as fetch:
                result = collect_provider(case, "hibp-domain", "example.org", confirm_external_disclosure=True)
                self.assertEqual(fetch.call_count, 2)
                self.assertEqual(result["observations"][0]["kind"], "breach.domain-alias")
                self.assertEqual(result["observations"][0]["value"]["alias"], "alias")
        self.assertTrue(verify_case(case)[0])

    def test_consent_artifact_retention_revocation_and_exact_target(self) -> None:
        case = self.case("email", "other@example.org", retention="")
        artifact = self.authority_artifact(case)
        with self.assertRaisesRegex(ValueError, "retention"):
            self.approve(case, "hibp-account", "person@example.org", "documented-consent", artifact)
        case = self.case("email", "other2@example.org")
        artifact = self.authority_artifact(case)
        with self.assertRaisesRegex(ValueError, "authority artifact"):
            self.approve(case, "hibp-account", "person@example.org", "documented-consent")
        with self.assertRaisesRegex(ValueError, "same email"):
            self.approve(case, "hibp-account", "person@example.org", "self")
        approval = self.approve(case, "hibp-account", "person@example.org", "documented-consent", artifact)
        revoke_provider_approval(case, approval["approval_id"], "Consent withdrawn")
        with patch.dict(os.environ, {"HIBP_API_KEY": "c" * 32}):
            with patch("osint_toolbox.providers._fetch") as fetch:
                with self.assertRaisesRegex(ValueError, "No current"):
                    collect_provider(case, "hibp-account", "person@example.org", confirm_external_disclosure=True)
                fetch.assert_not_called()
        self.assertTrue(verify_case(case)[0])

    def test_changed_policy_or_expired_approval_blocks_before_network(self) -> None:
        case = self.case("email", "me@example.org")
        self.approve(case, "hibp-account", "me@example.org", "self")

        class FutureDatetime(datetime):
            @classmethod
            def now(cls, tz=None):
                return datetime.now(tz) + timedelta(days=10)

        with patch.dict(os.environ, {"HIBP_API_KEY": "e" * 32}):
            with patch("osint_toolbox.policy.profile_digest", return_value="0" * 64):
                with patch("osint_toolbox.providers._fetch") as fetch:
                    with self.assertRaisesRegex(ValueError, "No current"):
                        collect_provider(case, "hibp-account", "me@example.org", confirm_external_disclosure=True)
                    fetch.assert_not_called()
            with patch("osint_toolbox.policy.datetime", FutureDatetime):
                with patch("osint_toolbox.providers._fetch") as fetch:
                    with self.assertRaisesRegex(ValueError, "No current"):
                        collect_provider(case, "hibp-account", "me@example.org", confirm_external_disclosure=True)
                    fetch.assert_not_called()
        self.assertTrue(verify_case(case)[0])

    def test_hunter_censys_and_companies_house_normalize_without_key_leaks(self) -> None:
        cases = [
            ("hunter-domain", "domain", "example.org", "organization-authorized", "HUNTER_API_KEY", "test-hunter-key",
             {"data": {"emails": [{"value": "a@example.org", "confidence": 70, "sources": []}]}}, "email.professional-candidate"),
            ("censys-host", "domain", "8.8.8.8", "asset-authorized", "CENSYS_PAT", "test-censys-token",
             {"result": {"resource": {"ip": "8.8.8.8", "last_updated_at": "2026-01-01T00:00:00Z", "services": [{"port": 443, "transport_protocol": "TCP"}]}}}, "host.indexed-services"),
            ("companies-house", "organization", "Example Ltd", "business-research", "COMPANIES_HOUSE_API_KEY", "test-ch-key",
             {"items": [{"company_number": "12345678", "title": "Example Ltd", "company_status": "active"}]}, "registry.company-candidate"),
        ]
        for provider, target_type, target, basis, env_name, key, payload, kind in cases:
            with self.subTest(provider=provider):
                case = self.case(target_type, target)
                artifact = self.authority_artifact(case) if basis != "business-research" else ""
                self.approve(case, provider, target, basis, artifact)
                url = "https://example.org/response"
                fetched = FetchResult(url, url, json.dumps(payload).encode("utf-8"), "application/json")
                with patch.dict(os.environ, {env_name: key}):
                    with patch("osint_toolbox.providers._fetch", return_value=fetched) as fetch:
                        result = collect_provider(case, provider, target, confirm_external_disclosure=True)
                        self.assertEqual(result["observations"][0]["kind"], kind)
                        self.assertNotIn(key, fetch.call_args.args[0])
                        self.assertNotIn(key, (case / "ledger.jsonl").read_text(encoding="utf-8"))
                self.assertTrue(verify_case(case)[0])

    def test_redacted_derivative_omits_licensed_pii_and_linked_claim(self) -> None:
        email = "me@example.org"
        case = self.case("email", email)
        self.approve(case, "hibp-account", email, "self")
        url = "https://haveibeenpwned.com/api/v3/breachedAccount/me%40example.org"
        fetched = FetchResult(url, url, b'[{"Name":"ExampleBreach"}]', "application/json")
        with patch.dict(os.environ, {"HIBP_API_KEY": "d" * 32}):
            with patch("osint_toolbox.providers._fetch", return_value=fetched):
                result = collect_provider(case, "hibp-account", email, confirm_external_disclosure=True)
        add_claim(case, "This personal email appears in ExampleBreach", "low", [result["source"]["source_id"]])
        policy_path = Path(__file__).parents[1] / "templates" / "redaction-policy.json"
        snapshot, _ = build_redacted_snapshot(case, policy_path)
        rendered = json.dumps(snapshot)
        self.assertNotIn(email, rendered)
        self.assertNotIn("ExampleBreach", rendered)
        self.assertEqual(snapshot["case"]["target"], "[REDACTED]")
        self.assertEqual(snapshot["datasets"]["provider_approvals"], [])
        self.assertEqual(snapshot["datasets"]["claims"], [])
        self.assertIn("hibp-account", snapshot["licensed_data_minimization"]["excluded_provider_ids"])
        self.assertTrue(verify_case(case)[0])

    def test_redacted_derivative_omits_sensitive_authority_artifact(self) -> None:
        case = self.case("domain", "example.org")
        artifact = self.authority_artifact(case)
        self.approve(case, "hunter-domain", "example.org", "organization-authorized", artifact)
        policy_path = Path(__file__).parents[1] / "templates" / "redaction-policy.json"
        snapshot, _ = build_redacted_snapshot(case, policy_path)
        self.assertEqual(snapshot["datasets"]["artifacts"], [])
        self.assertEqual(snapshot["datasets"]["provider_approvals"], [])

    @unittest.skipUnless(find_spec("reportlab") is not None and shutil.which("pdftotext") is not None,
                         "ReportLab and pdftotext are needed for PDF content inspection")
    def test_redacted_pdf_does_not_render_licensed_pii(self) -> None:
        email = "me@example.org"
        case = self.case("email", email)
        self.approve(case, "hibp-account", email, "self")
        url = "https://haveibeenpwned.com/api/v3/breachedAccount/me%40example.org"
        with patch.dict(os.environ, {"HIBP_API_KEY": "f" * 32}):
            with patch("osint_toolbox.providers._fetch", return_value=FetchResult(
                url, url, b'[{"Name":"ExampleBreach"}]', "application/json")):
                collect_provider(case, "hibp-account", email, confirm_external_disclosure=True)
        policy_path = Path(__file__).parents[1] / "templates" / "redaction-policy.json"
        pdf_path, _ = render_pdf_report(case, policy_path=policy_path)
        rendered = subprocess.run(["pdftotext", str(pdf_path), "-"], check=True,
                                  capture_output=True, text=True).stdout
        self.assertNotIn(email, rendered)
        self.assertNotIn("ExampleBreach", rendered)
        self.assertTrue(verify_case(case)[0])

    def test_credentialed_requests_refuse_insecure_or_cross_origin_redirects(self) -> None:
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            _fetch("http://example.org/", headers={"Authorization": "Bearer secret"})
        request = Request("https://api.example.org/lookup")
        with self.assertRaisesRegex(ValueError, "another origin"):
            _SameOriginRedirect("api.example.org").redirect_request(
                request, None, 302, "Found", {}, "https://other.example.org/lookup")

    def test_phase4_cli_catalog_and_approval(self) -> None:
        case = self.case("email", "me@example.org")
        with redirect_stdout(StringIO()) as out:
            main(["provider-policy", "hibp-account"])
        self.assertIn("allowed_basis", out.getvalue())
        with redirect_stdout(StringIO()) as out:
            main(["registries", "--jurisdiction", "KE"])
        self.assertIn("ke-nck-license", out.getvalue())
        with redirect_stdout(StringIO()) as out:
            main(["approve-provider", str(case), "hibp-account", "--target", "me@example.org",
                  "--basis", "self", "--reason", "Authorized self-check", "--reviewer", "reviewer",
                  "--actor", "collector", "--expires-at", self.expiry, "--terms-reviewed",
                  "--data-residency-accepted", "--cost-acknowledged",
                  "--data-residency-note", "Reviewed provider jurisdiction",
                  "--cost-note", "One subscription query"])
        approval_id = out.getvalue().strip()
        self.assertTrue(approval_id.startswith("APP-"))
        with redirect_stdout(StringIO()):
            main(["revoke-provider-approval", str(case), approval_id, "--reason", "Review ended"])
        self.assertTrue(verify_case(case)[0])

    def test_registry_profiles_and_no_network_health(self) -> None:
        ids = {r["id"] for r in registry_profiles("KE")}
        self.assertIn("ke-nck-license", ids)
        self.assertIn("ke-brs-official-search", ids)
        self.assertEqual(provider_profiles()["shodan"]["mode"], "manual")
        with patch("osint_toolbox.providers._fetch") as fetch:
            self.assertEqual(probe_provider("hibp-account")["status"], "unconfigured")
            fetch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
