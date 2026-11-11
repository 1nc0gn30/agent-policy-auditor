"""CLI Entrypoint for Agent Policy Auditor.

Engineered by 1nc0gn30 (@1nc0gn30) • NullAI Platform.
100% Python Standard Library — Zero External Dependencies.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
import time
import urllib.request
from pathlib import Path
from typing import List, Optional

from agent_policy_auditor.auditor import ManifestAuditor
from agent_policy_auditor.broker import PolicyBroker
from agent_policy_auditor.web_cockpit import serve


def _default_bind_host() -> str:
    """Bind address: localhost unless explicitly opted in via $ZOTH_BIND_HOST or
    $HOST (IP literal only; zsh sets HOST to the hostname) or --host."""
    for var in ("ZOTH_BIND_HOST", "HOST"):
        val = os.environ.get(var, "").strip()
        if val == "localhost":
            return "127.0.0.1"
        if val:
            try:
                ipaddress.ip_address(val)
                return val
            except ValueError:
                pass
    return "127.0.0.1"


def _emit_status(host: str, port: int, as_json: bool) -> None:
    stats = None
    active = []
    online = False
    try:
        with urllib.request.urlopen(f"http://{host}:{port}/api/stats", timeout=2.0) as resp:
            stats = json.loads(resp.read().decode("utf-8"))
            online = True
        with urllib.request.urlopen(f"http://{host}:{port}/api/leases", timeout=2.0) as resp:
            active = json.loads(resp.read().decode("utf-8")).get("leases", [])
    except Exception:
        broker = PolicyBroker()
        stats = broker.get_stats()
        active = broker.get_active_leases()

    if as_json:
        print(json.dumps({
            "service": "agent-policy-auditor",
            "version": "2.5.0",
            "online": online,
            "host": host,
            "port": port,
            "stats": stats,
            "active_leases": active,
        }, indent=2))
        return

    print("\n" + "=" * 60)
    print("  AGENT POLICY AUDITOR & LEASE BROKER — STATUS")
    print("=" * 60)
    print(f"  • Daemon Endpoint:      http://{host}:{port} ({'ONLINE' if online else 'LOCAL BROKER'})")
    print(f"  • Total Leases Granted: {stats['total_leases_granted']}")
    print(f"  • Active Leases:        {stats['active_leases_count']}")
    print(f"  • Revoked Leases:       {stats['revoked_leases_count']}")
    print(f"  • Violations Blocked:   {stats['violations_blocked']}")
    print(f"  • Budget Allocated:     ${stats['total_budget_allocated_usd']:.2f}")
    print("-" * 60)
    if active:
        print("  ACTIVE LEASES:")
        for l in active:
            print(f"    [{l['lease_id']}] Agent: {l['agent_id']} | Cap: {l['capability']} | Target: {l['target']} | TTL: {l['ttl_seconds']:.1f}s")
    else:
        print("  No active leases currently in effect.")
    print("=" * 60 + "\n")


def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(
        prog="agent-policy",
        description="Agent Policy Auditor & Capability Leaser (Port 8106)"
    )
    parser.add_argument("-v", "--version", action="version", version="agent-policy-auditor 2.5.0")
    parser.add_argument("--status", action="store_true", help="Display active leases and broker telemetry")
    parser.add_argument("--json", action="store_true", help="Emit structured JSON output")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Daemon host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8106, help="Daemon port (default: 8106)")

    subparsers = parser.add_subparsers(dest="subcommand", help="Subcommand to run")

    # Serve Command
    serve_parser = subparsers.add_parser("serve", help="Launch the Cockpit REST API and web UI")
    serve_parser.add_argument("--port", type=int, default=8106, help="Port to bind (default: 8106)")
    serve_parser.add_argument("--host", type=str, default=_default_bind_host(), help="Host interface (default: 127.0.0.1 or $ZOTH_BIND_HOST)")

    # Status Command
    status_parser = subparsers.add_parser("status", help="Display active leases and broker telemetry")
    status_parser.add_argument("--host", type=str, default="127.0.0.1", help="Daemon host (default: 127.0.0.1)")
    status_parser.add_argument("--port", type=int, default=8106, help="Daemon port (default: 8106)")
    status_parser.add_argument("--json", action="store_true", help="Emit structured JSON output")

    # Lease Commands
    lease_parser = subparsers.add_parser("lease", help="Manage capability leases")
    lease_sub = lease_parser.add_subparsers(dest="lease_action")

    grant_parser = lease_sub.add_parser("grant", help="Issue a new capability lease")
    grant_parser.add_argument("--agent", type=str, required=True, help="Agent identifier")
    grant_parser.add_argument("--cap", type=str, required=True, help="Capability type (FS_READ, FS_WRITE, NET_EGRESS, SHELL_EXEC)")
    grant_parser.add_argument("--target", type=str, default="*", help="Target glob or domain")
    grant_parser.add_argument("--duration", type=float, default=300.0, help="Duration in seconds (default: 300)")
    grant_parser.add_argument("--budget", type=float, default=0.0, help="Max USD budget quota (default: 0.0)")

    verify_parser = lease_sub.add_parser("verify", help="Verify an action against a lease")
    verify_parser.add_argument("--lease", type=str, required=True, help="Lease ID")
    verify_parser.add_argument("--cap", type=str, required=True, help="Capability type to verify")
    verify_parser.add_argument("--target", type=str, required=True, help="Target path/domain to verify")
    verify_parser.add_argument("--cost", type=float, default=0.0, help="Action USD cost")

    revoke_parser = lease_sub.add_parser("revoke", help="Revoke a lease")
    revoke_parser.add_argument("--lease", type=str, required=True, help="Lease ID to revoke")

    # Audit Command
    audit_parser = subparsers.add_parser("audit", help="Audit an agent manifest or tool schema")
    audit_parser.add_argument("--file", type=str, required=True, help="Path to JSON manifest or prompt file")
    audit_parser.add_argument("--json", action="store_true", help="Emit audit report as JSON")

    args = parser.parse_args(argv)

    if getattr(args, "status", False) or (getattr(args, "json", False) and not args.subcommand):
        _emit_status(args.host, args.port, as_json=bool(getattr(args, "json", False)))
        return

    if args.subcommand == "serve":
        serve(port=args.port, host=args.host)
        return

    if args.subcommand == "status":
        _emit_status(args.host, args.port, as_json=bool(getattr(args, "json", False)))
        return

    if args.subcommand == "lease":
        broker = PolicyBroker()
        if args.lease_action == "grant":
            lease = broker.grant_lease(
                agent_id=args.agent,
                capability=args.cap,
                target=args.target,
                duration_sec=args.duration,
                max_budget_usd=args.budget
            )
            print(f"✓ Granted Lease: {lease.lease_id}")
            print(f"  Agent:      {lease.agent_id}")
            print(f"  Capability: {lease.capability}")
            print(f"  Target:     {lease.target}")
            print(f"  Expires:    {time.ctime(lease.expires_at)} ({lease.duration_sec:.0f}s)")
            return

        if args.lease_action == "verify":
            allowed, reason = broker.verify_action(
                lease_id=args.lease,
                capability=args.cap,
                target=args.target,
                cost_usd=args.cost
            )
            print(f"Result: {'✓ AUTHORIZED' if allowed else '✗ DENIED'}")
            print(f"Reason: {reason}")
            sys.exit(0 if allowed else 1)

        if args.lease_action == "revoke":
            success = broker.revoke_lease(args.lease)
            if success:
                print(f"✓ Revoked Lease: {args.lease}")
            else:
                print(f"✗ Lease not found: {args.lease}")
                sys.exit(1)
            return

    if args.subcommand == "audit":
        p = Path(args.file)
        if not p.is_file():
            print(f"Error: File not found: {args.file}")
            sys.exit(1)
        raw = p.read_text(encoding="utf-8")
        auditor = ManifestAuditor()
        report = auditor.audit_manifest(raw, name=p.name)
        if getattr(args, "json", False):
            print(json.dumps(report.to_dict(), indent=2))
            return
        print("\n" + "=" * 60)
        print(f"  MANIFEST AUDIT REPORT: {report.manifest_name}")
        print("=" * 60)
        print(f"  • Security Score: {report.security_score}/100 [{report.risk_level}]")
        print(f"  • Total Findings: {report.total_findings}")
        print("-" * 60)
        for f in report.findings:
            print(f"  [{f.severity}] {f.rule_id}: {f.description}")
            print(f"     Remediation: {f.remediation}")
        print("-" * 60)
        print(f"  Compliance: {json.dumps(report.compliance_frameworks, indent=4)}")
        print("=" * 60 + "\n")
        return

    parser.print_help()


if __name__ == "__main__":
    main()
