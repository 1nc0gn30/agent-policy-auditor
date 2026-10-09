"""Unit tests for ManifestAuditor security evaluations."""

import unittest
from agent_policy_auditor.auditor import ManifestAuditor


class TestManifestAuditor(unittest.TestCase):
    def setUp(self):
        self.auditor = ManifestAuditor()

    def test_clean_manifest_scores_safe(self):
        clean_manifest = {
            "name": "safe_calculator_agent",
            "tools": [
                {
                    "name": "add_numbers",
                    "description": "Adds two numbers",
                    "parameters": {"type": "object", "properties": {"a": {"type": "number"}, "b": {"type": "number"}}}
                }
            ]
        }
        report = self.auditor.audit_manifest(clean_manifest)
        self.assertEqual(report.security_score, 100)
        self.assertEqual(report.risk_level, "SAFE")
        self.assertEqual(report.total_findings, 0)

    def test_detects_unsandboxed_shell(self):
        risky_manifest = {
            "name": "unconstrained_terminal_agent",
            "tools": [
                {
                    "name": "run_bash_command",
                    "description": "Executes shell commands directly on host",
                    "parameters": {"type": "object", "properties": {"cmd": {"type": "string"}}}
                }
            ]
        }
        report = self.auditor.audit_manifest(risky_manifest)
        self.assertLess(report.security_score, 100)
        rule_ids = [f.rule_id for f in report.findings]
        self.assertIn("EXEC-002-UNSANDBOXED-SHELL", rule_ids)

    def test_detects_hardcoded_secrets(self):
        secret_manifest = {
            "name": "leaky_agent",
            "system_prompt": "You are connected with API key sk-abcdef12345678901234567890 to authenticate."
        }
        report = self.auditor.audit_manifest(secret_manifest)
        rule_ids = [f.rule_id for f in report.findings]
        self.assertIn("SEC-001-HARDCODED-SECRET", rule_ids)
        self.assertEqual(report.risk_level, "CRITICAL")

    def test_detects_destructive_commands(self):
        prompt_with_rm = "Please run rm -rf /var/log to clear disk space."
        report = self.auditor.audit_manifest(prompt_with_rm)
        rule_ids = [f.rule_id for f in report.findings]
        self.assertIn("DEST-004-IRREVERSIBLE-ACTION", rule_ids)


if __name__ == "__main__":
    unittest.main()
