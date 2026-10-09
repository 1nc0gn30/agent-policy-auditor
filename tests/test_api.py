"""Integration tests for CockpitHandler HTTP REST API."""

import json
import threading
import time
import unittest
import urllib.request
from http.server import HTTPServer

from agent_policy_auditor.web_cockpit import CockpitHandler


class TestCockpitAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = 18106  # Use high ephemeral port for unit testing
        cls.server = HTTPServer(("127.0.0.1", cls.port), CockpitHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_api_stats(self):
        req = urllib.request.urlopen(f"http://127.0.0.1:{self.port}/api/stats")
        self.assertEqual(req.status, 200)
        data = json.loads(req.read().decode())
        self.assertIn("total_leases_granted", data)
        self.assertIn("uptime_seconds", data)

    def test_api_grant_and_verify_lease(self):
        # Grant Lease
        grant_body = json.dumps({
            "agent_id": "api_test_agent",
            "capability": "FS_READ",
            "target": "/tmp/*",
            "duration_sec": 60
        }).encode()
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/api/leases/grant",
            data=grant_body,
            headers={"Content-Type": "application/json"}
        )
        res = urllib.request.urlopen(req)
        self.assertEqual(res.status, 200)
        data = json.loads(res.read().decode())
        self.assertEqual(data["status"], "granted")
        lease_id = data["lease"]["lease_id"]

        # Verify Allowed Action
        verify_body = json.dumps({
            "lease_id": lease_id,
            "capability": "FS_READ",
            "target": "/tmp/test.txt"
        }).encode()
        req_v = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/api/leases/verify",
            data=verify_body,
            headers={"Content-Type": "application/json"}
        )
        res_v = urllib.request.urlopen(req_v)
        data_v = json.loads(res_v.read().decode())
        self.assertTrue(data_v["allowed"])

    def test_api_audit_manifest(self):
        manifest_body = json.dumps({
            "manifest": {
                "name": "test_mcp_server",
                "tools": [
                    {"name": "calculator", "description": "Add numbers"}
                ]
            }
        }).encode()
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/api/audit",
            data=manifest_body,
            headers={"Content-Type": "application/json"}
        )
        res = urllib.request.urlopen(req)
        self.assertEqual(res.status, 200)
        data = json.loads(res.read().decode())
        self.assertIn("security_score", data)
        self.assertIn("risk_level", data)


if __name__ == "__main__":
    unittest.main()
