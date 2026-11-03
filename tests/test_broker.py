"""Unit tests for PolicyBroker and Capability Leasing."""

import tempfile
import time
import unittest
from agent_policy_auditor.broker import PolicyBroker


class TestPolicyBroker(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = f"{self.temp_dir.name}/test_policy.db"
        self.broker = PolicyBroker(db_path=self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_grant_and_verify_valid_lease(self):
        lease = self.broker.grant_lease(
            agent_id="test_agent",
            capability="FS_READ",
            target="~/NullAITech/*",
            duration_sec=60.0
        )
        self.assertTrue(lease.is_valid())
        self.assertTrue(lease.lease_id.startswith("lease_"))

        # Verify allowed path
        allowed, reason = self.broker.verify_action(
            lease_id=lease.lease_id,
            capability="FS_READ",
            target="~/NullAITech/project"
        )
        self.assertTrue(allowed)
        self.assertIn("Authorized", reason)

    def test_verify_capability_mismatch(self):
        lease = self.broker.grant_lease(
            agent_id="test_agent",
            capability="FS_READ",
            target="*"
        )
        allowed, reason = self.broker.verify_action(
            lease_id=lease.lease_id,
            capability="FS_WRITE",
            target="~/file.txt"
        )
        self.assertFalse(allowed)
        self.assertIn("CapabilityMismatch", reason)

    def test_verify_target_mismatch(self):
        lease = self.broker.grant_lease(
            agent_id="test_agent",
            capability="NET_EGRESS",
            target="api.nullai.tech"
        )
        allowed, reason = self.broker.verify_action(
            lease_id=lease.lease_id,
            capability="NET_EGRESS",
            target="malicious-site.com"
        )
        self.assertFalse(allowed)
        self.assertIn("TargetNotPermitted", reason)

    def test_lease_revocation(self):
        lease = self.broker.grant_lease(
            agent_id="test_agent",
            capability="SHELL_EXEC",
            target="*"
        )
        self.broker.revoke_lease(lease.lease_id)
        allowed, reason = self.broker.verify_action(
            lease_id=lease.lease_id,
            capability="SHELL_EXEC",
            target="ls"
        )
        self.assertFalse(allowed)
        self.assertIn("LeaseRevoked", reason)

    def test_emergency_killswitch(self):
        self.broker.grant_lease("agent_x", "FS_READ", "*")
        self.broker.grant_lease("agent_x", "FS_WRITE", "*")
        self.broker.grant_lease("agent_y", "FS_READ", "*")

        revoked_count = self.broker.revoke_all_for_agent("agent_x")
        self.assertEqual(revoked_count, 2)

        active = self.broker.get_active_leases()
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0]["agent_id"], "agent_y")

    def test_budget_quota_enforcement(self):
        lease = self.broker.grant_lease(
            agent_id="finance_agent",
            capability="TOKEN_BUDGET",
            target="openai",
            max_budget_usd=0.05
        )
        # Action within budget
        allowed, _ = self.broker.verify_action(lease.lease_id, "TOKEN_BUDGET", "openai", cost_usd=0.02)
        self.assertTrue(allowed)

        # Action exceeding remaining budget
        allowed, reason = self.broker.verify_action(lease.lease_id, "TOKEN_BUDGET", "openai", cost_usd=0.04)
        self.assertFalse(allowed)
        self.assertIn("BudgetExceeded", reason)


if __name__ == "__main__":
    unittest.main()
