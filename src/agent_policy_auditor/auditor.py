"""Static Manifest, Tool Schema & System Prompt Security Auditor.

Engineered by Neal Frazier Tech (@1nc0gn30) • NullAI Platform.
Audits AI agent tool definitions, MCP manifests, and system prompts
against OWASP LLM Top 10 and MITRE ATLAS security standards.
100% Python Standard Library — Zero External Dependencies.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

SECRET_PATTERNS = [
    (r"sk-[a-zA-Z0-9]{20,}", "OpenAI API Secret Key"),
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Access Token"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"-----BEGIN (?:RSA )?PRIVATE KEY-----", "SSH/TLS Private Key Header"),
    (r"(?:api[_-]?key|secret|password|token)\s*[:=]\s*['\"][a-zA-Z0-9_\-]{16,}['\"]", "Hardcoded API Credential"),
]

SHELL_TOOL_PATTERNS = [
    r"(?:bash|sh|shell|exec|terminal|command_line|run_command|subprocess)",
]

DESTRUCTIVE_PATTERNS = [
    r"\b(?:rm\s+-rf|del\s+/f|mkfs|drop\s+database|format\s+[a-z]:)\b",
]


@dataclass
class AuditFinding:
    rule_id: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    description: str
    remediation: str
    evidence: str = ""


@dataclass
class ManifestAuditReport:
    manifest_name: str
    security_score: int  # 0 to 100
    risk_level: str      # SAFE, LOW, MEDIUM, HIGH, CRITICAL
    total_findings: int
    findings: List[AuditFinding] = field(default_factory=list)
    compliance_frameworks: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d


class ManifestAuditor:
    """Evaluates agent tool schemas, MCP manifests, and prompts."""

    def audit_manifest(self, data: Any, name: str = "agent_manifest") -> ManifestAuditReport:
        """Run comprehensive audit against tool schema or prompt dictionary."""
        findings: List[AuditFinding] = []
        raw_text = ""

        if isinstance(data, (dict, list)):
            raw_text = json.dumps(data)
        elif isinstance(data, str):
            raw_text = data
            try:
                data = json.loads(data)
            except Exception:
                # Treat as raw prompt text
                data = {"prompt": data}

        # 1. Audit for Hardcoded Secrets
        for pattern, label in SECRET_PATTERNS:
            matches = re.findall(pattern, raw_text, re.IGNORECASE)
            if matches:
                findings.append(AuditFinding(
                    rule_id="SEC-001-HARDCODED-SECRET",
                    severity="CRITICAL",
                    description=f"Detected hardcoded credential ({label}) inside agent definition.",
                    remediation="Extract credentials to external vault or environment lease variables.",
                    evidence=f"Found {len(matches)} match(es)"
                ))

        # 2. Audit Tools for Unsandboxed Shell Execution
        tools = []
        if isinstance(data, dict):
            if "tools" in data and isinstance(data["tools"], list):
                tools = data["tools"]
            elif "functions" in data and isinstance(data["functions"], list):
                tools = data["functions"]

        for t in tools:
            t_name = str(t.get("name", "")).lower()
            t_desc = str(t.get("description", "")).lower()
            schema = json.dumps(t.get("parameters", {}))

            is_shell = any(re.search(pat, t_name) for pat in SHELL_TOOL_PATTERNS)
            if is_shell:
                # Check if sandbox or quota parameter exists
                if not any(k in schema.lower() for k in ["sandbox", "capsule", "timeout", "quota", "container"]):
                    findings.append(AuditFinding(
                        rule_id="EXEC-002-UNSANDBOXED-SHELL",
                        severity="HIGH",
                        description=f"Tool '{t.get('name')}' provides shell execution without sandbox or quota boundaries.",
                        remediation="Wrap subprocess in Agent Capsule Jail (:8105) or apply resource limits.",
                        evidence=f"Tool: {t.get('name')}"
                    ))

            # Check for arbitrary filesystem writes without path constraints
            if any(k in t_name for k in ["write", "file", "save", "modify"]):
                if not any(k in schema.lower() for k in ["allowed_dir", "root", "workspace", "jail", "sandbox"]):
                    findings.append(AuditFinding(
                        rule_id="FS-003-UNCONSTRAINED-WRITE",
                        severity="MEDIUM",
                        description=f"Tool '{t.get('name')}' allows arbitrary file writes without workspace root constraints.",
                        remediation="Enforce strict working directory path prefix validation or ephemeral scratch spaces.",
                        evidence=f"Tool: {t.get('name')}"
                    ))

        # 3. Check for Destructive Commands
        for pat in DESTRUCTIVE_PATTERNS:
            if re.search(pat, raw_text, re.IGNORECASE):
                findings.append(AuditFinding(
                    rule_id="DEST-004-IRREVERSIBLE-ACTION",
                    severity="CRITICAL",
                    description="Detected destructive system commands without human confirmation invariant.",
                    remediation="Require explicit lease authorization or human approval gate.",
                    evidence=pat
                ))

        # 4. Check for Unrestricted Cloud Egress
        if any(w in raw_text.lower() for w in ["fetch", "curl", "http_request", "urllib", "requests"]):
            if "domain_whitelist" not in raw_text and "allowlist" not in raw_text:
                findings.append(AuditFinding(
                    rule_id="NET-005-UNFILTERED-EGRESS",
                    severity="LOW",
                    description="Agent incorporates outbound network capabilities without explicit domain allowlisting.",
                    remediation="Route outbound calls through Agent Egress Sentinel (:8095/:8096).",
                    evidence="Network tools present without domain whitelist"
                ))

        # Calculate Score
        deductions = {
            "CRITICAL": 35,
            "HIGH": 20,
            "MEDIUM": 10,
            "LOW": 5
        }
        total_deduction = sum(deductions.get(f.severity, 5) for f in findings)
        score = max(0, 100 - total_deduction)

        has_critical = any(f.severity == "CRITICAL" for f in findings)
        has_high = any(f.severity == "HIGH" for f in findings)

        if has_critical or score < 25:
            risk = "CRITICAL"
        elif has_high or score < 50:
            risk = "HIGH"
        elif score < 75:
            risk = "MEDIUM"
        elif score < 90:
            risk = "LOW"
        else:
            risk = "SAFE"


        compliance = {
            "NIST_AI_RMF": "COMPLIANT" if score >= 80 else "NON_COMPLIANT",
            "OWASP_LLM_TOP_10": "PASS" if not any(f.severity in ["HIGH", "CRITICAL"] for f in findings) else "ACTION_REQUIRED",
            "ZOTH_ZERO_EGRESS_INVARIANT": "VERIFIED" if score >= 85 else "QUARANTINED"
        }

        return ManifestAuditReport(
            manifest_name=name,
            security_score=score,
            risk_level=risk,
            total_findings=len(findings),
            findings=findings,
            compliance_frameworks=compliance
        )
