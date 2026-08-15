import copy
import unittest
from tenant_app.api import request_export
from tenant_app.audit import AuditLog
from tenant_app.auth import PermissionCache, authorize
from tenant_app.errors import AuthorizationError, IntegrityError
from tenant_app.jobs import run_export_job
from tenant_app.signing import EnvelopeSigner
from tenant_app.storage import ExportStorage

NOW = 1800000000
KEY = b"local-benchmark-signing-key-32bytes"


def user(user_id, tenant, role="analyst"):
    return {"user_id": user_id, "home_tenant": tenant, "account_type": "user", "tenant_roles": {tenant: [role]}}


def support(user_id="support-1"):
    return {"user_id": user_id, "home_tenant": "support", "account_type": "support", "tenant_roles": {}}


def grant(signer, support_user, tenant, scopes, expires=NOW + 300, grant_id="g-1"):
    return signer.sign({"kind": "support_grant", "grant_id": grant_id, "support_user_id": support_user, "tenant_id": tenant, "scopes": scopes, "expires_at": expires})


class SecurityRegressionTests(unittest.TestCase):
    def setUp(self):
        self.signer = EnvelopeSigner(KEY)
        self.cache = PermissionCache()
        self.audit = AuditLog()
        self.storage = ExportStorage()
        self.datasets = {"tenant-a": [{"id": 1}], "tenant-b": [{"id": 2}]}

    def test_legitimate_own_tenant_export(self):
        principal = user("alice", "tenant-a")
        job = request_export(principal, {"tenant_id": "tenant-a", "request_id": "r1", "export_id": "e1"}, self.cache, self.signer, self.audit, now=NOW)
        result = run_export_job(job, self.signer, self.storage, self.datasets, self.audit, now=NOW)
        self.assertEqual(result["tenant_id"], "tenant-a")
        self.assertEqual(self.storage.download_export(principal, "tenant-a", "e1", self.cache, self.audit)["rows"], [{"id": 1}])

    def test_cross_tenant_api_request_is_denied(self):
        principal = user("alice", "tenant-a")
        with self.assertRaises(AuthorizationError):
            request_export(principal, {"tenant_id": "tenant-b", "request_id": "r2", "export_id": "e2"}, self.cache, self.signer, self.audit, now=NOW)

    def test_cache_decision_is_tenant_scoped(self):
        principal = user("alice", "tenant-a")
        self.assertTrue(authorize(principal, "tenant-a", "export:create", self.cache))
        self.assertFalse(authorize(principal, "tenant-b", "export:create", self.cache))

    def test_forged_worker_job_is_rejected(self):
        principal = user("alice", "tenant-a")
        job = request_export(principal, {"tenant_id": "tenant-a", "request_id": "r3", "export_id": "e3"}, self.cache, self.signer, self.audit, now=NOW)
        forged = copy.deepcopy(job)
        forged["tenant_id"] = "tenant-b"
        with self.assertRaises(IntegrityError):
            run_export_job(forged, self.signer, self.storage, self.datasets, self.audit, now=NOW)
        forged = copy.deepcopy(job)
        forged["export_id"] = "different-export"
        with self.assertRaises(IntegrityError):
            run_export_job(forged, self.signer, self.storage, self.datasets, self.audit, now=NOW)

    def test_storage_keys_and_reads_are_tenant_scoped(self):
        self.storage.put_export("tenant-a", "same", {"tenant_id": "tenant-a", "rows": [1]})
        self.storage.put_export("tenant-b", "same", {"tenant_id": "tenant-b", "rows": [2]})
        self.assertEqual(len(self.storage.object_keys()), 2)
        with self.assertRaises(AuthorizationError):
            self.storage.download_export(user("alice", "tenant-a"), "tenant-b", "same", self.cache, self.audit)

    def test_support_grant_is_exact_tenant(self):
        principal = support()
        g = grant(self.signer, "support-1", "tenant-b", ["export:create", "export:read"])
        job = request_export(principal, {"tenant_id": "tenant-b", "request_id": "r4", "export_id": "e4"}, self.cache, self.signer, self.audit, grant=g, now=NOW)
        run_export_job(job, self.signer, self.storage, self.datasets, self.audit, now=NOW)
        self.assertEqual(self.storage.download_export(principal, "tenant-b", "e4", self.cache, self.audit, grant=g, signer=self.signer, now=NOW)["rows"], [{"id": 2}])
        queued = request_export(principal, {"tenant_id": "tenant-b", "request_id": "r4-queued", "export_id": "e4-queued"}, self.cache, self.signer, self.audit, grant=g, now=NOW)
        revoked = {"g-1"}
        with self.assertRaises(IntegrityError):
            run_export_job(queued, self.signer, self.storage, self.datasets, self.audit, now=NOW, revoked_grant_ids=revoked)
        self.assertTrue(any(
            event.get("event") == "export_job_denied" and event.get("job_id") == queued.get("job_id")
            for event in self.audit.events
        ))
        with self.assertRaises(AuthorizationError):
            self.storage.download_export(principal, "tenant-b", "e4", self.cache, self.audit, grant=g, signer=self.signer, now=NOW, revoked_grant_ids=revoked)
        replacement = grant(self.signer, "support-1", "tenant-b", ["export:create", "export:read"], grant_id="g-2")
        regranted = request_export(principal, {"tenant_id": "tenant-b", "request_id": "r4-regranted", "export_id": "e4-regranted"}, self.cache, self.signer, self.audit, grant=replacement, now=NOW, revoked_grant_ids=revoked)
        run_export_job(regranted, self.signer, self.storage, self.datasets, self.audit, now=NOW, revoked_grant_ids=revoked)
        self.assertEqual(self.storage.download_export(principal, "tenant-b", "e4-regranted", self.cache, self.audit, grant=replacement, signer=self.signer, now=NOW, revoked_grant_ids=revoked)["rows"], [{"id": 2}])
        with self.assertRaises(AuthorizationError):
            self.storage.download_export(principal, "tenant-b", "e4", self.cache, self.audit, now=NOW)
        with self.assertRaises(AuthorizationError):
            request_export(principal, {"tenant_id": "tenant-a", "request_id": "r5", "export_id": "e5"}, self.cache, self.signer, self.audit, grant=g, now=NOW)
        self.assertTrue(any(event.get("event") == "export_read_denied" for event in self.audit.events))
        self.assertTrue(any(event.get("event") == "export_request_denied" for event in self.audit.events))

    def test_worker_rejects_completed_request_replay(self):
        principal = user("alice", "tenant-a")
        job = request_export(principal, {"tenant_id": "tenant-a", "request_id": "r-replay", "export_id": "e-replay"}, self.cache, self.signer, self.audit, now=NOW)
        run_export_job(job, self.signer, self.storage, self.datasets, self.audit, now=NOW)
        replay = copy.deepcopy(job)
        replay["job_id"] = "job-replay-mutated"
        with self.assertRaises(IntegrityError):
            run_export_job(replay, self.signer, self.storage, self.datasets, self.audit, now=NOW)
        self.assertTrue(any(
            event.get("event") == "export_job_denied" and event.get("job_id") == "job-replay-mutated"
            for event in self.audit.events
        ))

    def test_forged_delegation_fields_do_not_authorize_users(self):
        principal = user("mallory", "tenant-a")
        principal["delegated_tenant"] = "tenant-b"
        principal["delegated_scopes"] = ["export:create", "export:read"]
        principal["delegated_grant_id"] = "forged-grant"
        self.assertFalse(authorize(principal, "tenant-b", "export:create", self.cache))
        with self.assertRaises(AuthorizationError):
            request_export(principal, {"tenant_id": "tenant-b", "request_id": "r-forged-del", "export_id": "e-forged-del"}, self.cache, self.signer, self.audit, now=NOW)


if __name__ == "__main__":
    unittest.main()
