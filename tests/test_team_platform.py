from __future__ import annotations

import base64
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

try:
    import jwt
    import psycopg
    from cryptography.hazmat.primitives.asymmetric import rsa
    from fastapi.testclient import TestClient
    from psycopg import sql
    from psycopg.conninfo import make_conninfo
    from osint_toolbox.providers import PreparedCollection
    from osint_toolbox.team_api import create_app
    from osint_toolbox.team_ops import backup, restore_drill, verify_backup
    from osint_toolbox.team_store import TeamConfig, TeamStore, verify_team_export
    from osint_toolbox.team_worker import run_one
    TEAM_DEPS = True
except ImportError:
    TEAM_DEPS = False


@unittest.skipUnless(TEAM_DEPS and os.environ.get("OSINT_TEAM_TEST_DATABASE_URL"),
                     "Team dependencies and a disposable PostgreSQL test URL are required")
class TeamPlatformTest(unittest.TestCase):
    def setUp(self) -> None:
        self.base_url = os.environ["OSINT_TEAM_TEST_DATABASE_URL"]
        self.schema = "osint_test_" + uuid4().hex[:12]
        with psycopg.connect(self.base_url) as conn:
            conn.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(self.schema)))
        self.dsn = make_conninfo(self.base_url, options=f"-c search_path={self.schema}")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.drop_schema)
        self.config = TeamConfig(
            self.dsn, Path(self.tmp.name) / "objects", os.urandom(32),
            "https://idp.example.test/", "osint-api", "https://idp.example.test/jwks.json",
            frozenset({"admin"}), "service:test-worker",
        )
        self.store = TeamStore(self.config)
        self.store.init_schema()
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.private_key.public_key()))
        jwk["kid"] = "test-key"
        self.client = TestClient(create_app(self.config, {"keys": [jwk]}))
        self.addCleanup(self.client.close)

    def drop_schema(self) -> None:
        with psycopg.connect(self.base_url) as conn:
            conn.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(self.schema)))

    def auth(self, subject: str) -> dict[str, str]:
        now = datetime.now(timezone.utc)
        token = jwt.encode({"iss": self.config.issuer, "aud": self.config.audience,
                            "sub": subject, "iat": now, "exp": now + timedelta(minutes=10)},
                           self.private_key, algorithm="RS256", headers={"kid": "test-key"})
        return {"Authorization": "Bearer " + token}

    def create_case(self) -> str:
        response = self.client.post("/cases", headers=self.auth("admin"), json={
            "title": "Test case", "purpose": "Authorized testing", "authority": "Written mandate",
            "target_type": "domain", "target": "example.org", "sensitivity": "confidential",
            "retention_until": "2099-01-01"})
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()["case_id"]

    def member(self, case_id: str, subject: str, role: str) -> None:
        response = self.client.put(f"/cases/{case_id}/members", headers=self.auth("admin"),
                                   json={"subject": subject, "role": role})
        self.assertEqual(response.status_code, 200, response.text)

    def test_auth_rbac_reports_jobs_objects_and_audit(self) -> None:
        case_id = self.create_case()
        for subject, role in (("analyst", "analyst"), ("reviewer", "reviewer"), ("viewer", "viewer")):
            self.member(case_id, subject, role)
        self.assertEqual(self.client.get(f"/cases/{case_id}").status_code, 401)
        self.assertEqual(self.client.get(f"/cases/{case_id}", headers=self.auth("outsider")).status_code, 403)
        self.assertEqual(self.client.get(f"/cases/{case_id}", headers=self.auth("viewer")).status_code, 200)
        self.assertEqual(self.client.post(f"/cases/{case_id}/objects", headers=self.auth("viewer"),
                                          content=b"secret").status_code, 403)

        uploaded = self.client.post(f"/cases/{case_id}/objects", headers=self.auth("analyst"),
                                    content=b"sensitive evidence")
        self.assertEqual(uploaded.status_code, 201, uploaded.text)
        object_id = uploaded.json()["object_id"]
        self.assertNotIn(b"sensitive evidence", self.store.objects.path(case_id, object_id).read_bytes())
        self.assertEqual(self.client.get(f"/cases/{case_id}/objects/{object_id}",
                                         headers=self.auth("viewer")).status_code, 403)
        self.assertEqual(self.client.get(f"/cases/{case_id}/objects/{object_id}",
                                         headers=self.auth("analyst")).content, b"sensitive evidence")
        self.assertEqual(self.client.get(f"/cases/{case_id}/objects/{object_id}",
                                         headers=self.auth("outsider")).status_code, 403)

        report = self.client.post(f"/cases/{case_id}/reports", headers=self.auth("analyst"),
                                  json={"markdown": "# Controlled report"})
        self.assertEqual(report.status_code, 201, report.text)
        report_id = report.json()["report_id"]
        self.assertEqual(report.json()["version"], 1)
        self.assertEqual(self.client.get(f"/cases/{case_id}/reports/{report_id}",
                                         headers=self.auth("viewer")).status_code, 404)
        self.assertEqual(self.client.post(f"/cases/{case_id}/reports/{report_id}/review",
                                          headers=self.auth("analyst"),
                                          json={"approve": True, "reason": "Self approval"}).status_code, 403)
        self.assertEqual(self.client.post(f"/cases/{case_id}/reports/{report_id}/review",
                                          headers=self.auth("reviewer"),
                                          json={"approve": True, "reason": "Evidence checked"}).status_code, 200)
        self.assertIn("Controlled report", self.client.get(f"/cases/{case_id}/reports/{report_id}",
                                                           headers=self.auth("viewer")).text)

        job = self.client.post(f"/cases/{case_id}/jobs", headers=self.auth("analyst"), json={
            "kind": "provider", "provider": "rdap", "target": "example.org",
            "disclosure_confirmed": True, "options": {}})
        self.assertEqual(job.status_code, 201, job.text)
        job_id = job.json()["job_id"]
        self.assertEqual(self.client.post(f"/cases/{case_id}/jobs/{job_id}/review",
                                          headers=self.auth("analyst"),
                                          json={"approve": True, "reason": "Self review"}).status_code, 403)
        self.assertEqual(self.client.post(f"/cases/{case_id}/jobs/{job_id}/review",
                                          headers=self.auth("reviewer"),
                                          json={"approve": True, "reason": "Passive authorized query"}).status_code, 200)
        prepared = PreparedCollection("rdap", "https://rdap.example/domain/example.org", "RDAP test",
                                      "domain", "primary", "high", "rdap.json", b'{"ldhName":"example.org"}',
                                      "application/json", [{"kind": "domain.name", "value": "example.org"}])
        with patch("osint_toolbox.team_worker.PREPARERS", {"rdap": lambda target, options: prepared}):
            self.assertEqual(run_one(self.store), job_id)
        with self.store.connect() as conn:
            result = conn.execute("SELECT * FROM team_jobs WHERE job_id=%s", (job_id,)).fetchone()
        self.assertEqual(result["status"], "completed")
        self.assertTrue(result["result_object_id"])
        valid, issues = self.store.verify_audit()
        self.assertTrue(valid, issues)
        with self.store.connect() as conn:
            with self.assertRaises(psycopg.Error):
                conn.execute("DELETE FROM team_audit")
        exported = self.client.get(f"/cases/{case_id}/export", headers=self.auth("admin"))
        self.assertEqual(exported.status_code, 200, exported.text[:300])
        self.assertTrue(verify_team_export(exported.content)[0])
        self.assertEqual(self.client.get(f"/cases/{case_id}/export", headers=self.auth("viewer")).status_code, 403)

    def test_hold_retention_and_denied_unsafe_job(self) -> None:
        case_id = self.create_case()
        self.member(case_id, "analyst", "analyst")
        self.assertEqual(self.client.post(f"/cases/{case_id}/jobs", headers=self.auth("analyst"),
                                          json={"kind": "provider", "provider": "hibp-account",
                                                "target": "example.org", "disclosure_confirmed": True}).status_code, 400)
        self.assertEqual(self.client.post(f"/cases/{case_id}/jobs", headers=self.auth("analyst"),
                                          json={"kind": "provider", "provider": "rdap",
                                                "target": "other.org", "disclosure_confirmed": True}).status_code, 400)
        uploaded = self.client.post(f"/cases/{case_id}/objects", headers=self.auth("analyst"), content=b"expire me")
        self.assertEqual(uploaded.status_code, 201)
        object_id = uploaded.json()["object_id"]
        self.assertEqual(self.client.post(f"/cases/{case_id}/legal-hold", headers=self.auth("admin"),
                                          json={"active": True, "reason": "Preserve", "authority": "Counsel"}).status_code, 200)
        with self.store.connect() as conn:
            conn.execute("UPDATE team_cases SET retention_until=CURRENT_DATE-1 WHERE case_id=%s", (case_id,))
        self.assertEqual(self.store.retention_sweep("service:retention"), [])
        self.assertTrue(self.store.objects.path(case_id, object_id).exists())
        self.assertEqual(self.client.post(f"/cases/{case_id}/legal-hold", headers=self.auth("admin"),
                                          json={"active": False, "reason": "Released", "authority": "Counsel"}).status_code, 200)
        self.assertEqual(self.store.retention_sweep("service:retention"), [case_id])
        self.assertFalse(self.store.objects.path(case_id, object_id).exists())
        self.assertEqual(self.client.get(f"/cases/{case_id}", headers=self.auth("admin")).status_code, 404)
        self.assertTrue(self.store.verify_audit()[0])

    def test_encrypted_backup_verification(self) -> None:
        case_id = self.create_case()
        self.client.post(f"/cases/{case_id}/objects", headers=self.auth("admin"), content=b"backup evidence")
        output = Path(self.tmp.name) / "backup.otb"
        backup(self.store, output)
        verify_backup(output, self.config.object_key)
        self.assertNotIn(b"backup evidence", output.read_bytes())
        damaged = Path(self.tmp.name) / "damaged.otb"
        blob = bytearray(output.read_bytes())
        blob[-20] ^= 1
        damaged.write_bytes(blob)
        with self.assertRaises(Exception):
            verify_backup(damaged, self.config.object_key)


if __name__ == "__main__":
    unittest.main()
