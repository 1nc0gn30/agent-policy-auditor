# Agent Policy Auditor & Capability Leaser

![Agent Policy Auditor Hero Banner](assets/hero-banner.svg)

**Agent Policy Auditor** (`agent-policy-auditor`) is a zero-dependency Python 3.10+ capability lease broker, action verifier, static manifest security auditor, and web workstation (`127.0.0.1:8106`) for AI agents. Instead of granting static, unbounded permissions, it issues cryptographic time-bound and budget-bounded leases (`FS_READ`, `FS_WRITE`, `NET_EGRESS`, `SHELL_EXEC`) and audits MCP/agent tool manifests against OWASP LLM Top 10 and NIST AI RMF controls.

- **Zoth Studio v2 Dossier**: [https://zoth.nullai.tech/tools/agent-policy-auditor](https://zoth.nullai.tech/tools/agent-policy-auditor)
- **Repository**: [https://github.com/1nc0gn30/agent-policy-auditor](https://github.com/1nc0gn30/agent-policy-auditor)
- **Default Loopback Endpoint**: `http://127.0.0.1:8106`

---

## Overview

- **Time-Bound Capability Broker (`PolicyBroker`)**: Issues leases scoped to an `agent_id`, capability (`FS_READ`, `FS_WRITE`, `NET_EGRESS`, `SHELL_EXEC`), path/domain glob `target`, `duration_sec` TTL, and optional `max_budget_usd` ceiling.
- **Runtime Action Verification**: Evaluates candidate tool actions (`verify_action`) against lease expiration, capability match, glob scope, revocation state, and remaining USD quota, incrementing violation counters on unauthorized attempts.
- **Emergency Kill Switch**: Supports single-lease revocation (`/api/leases/revoke`) and full per-agent revocation (`/api/leases/revoke_all`), emitting audit telemetry to Flight Recorder (`127.0.0.1:8104/api/ingest`) when online.
- **Static Manifest Auditor (`ManifestAuditor`)**: Scans JSON tool schemas, MCP server manifests, and system prompts for unrestricted shell execution, wildcard filesystem/network grants, credential exposure, and prompt-injection surfaces, producing a `0–100` security score and compliance mapping.

---

## Architecture

```text
Agent Runtime / MCP Host
   │
   ├──► PolicyBroker (grant / verify / revoke / revoke_all)
   │       └── TTL + Glob Target + USD Quota Enforcement
   │
   ├──► ManifestAuditor (static schema & prompt rule engine)
   │       └── Security Score (0-100) + OWASP LLM / NIST AI RMF Mapping
   │
   └──► Web Cockpit & REST API (127.0.0.1:8106) ──► Flight Recorder (:8104)
```

---

## Quickstart

```bash
git clone https://github.com/1nc0gn30/agent-policy-auditor.git
cd agent-policy-auditor
python3 -m pip install -e .

# Start the REST API & Web Cockpit on 127.0.0.1:8106
agent-policy serve --host 127.0.0.1 --port 8106
```

Or launch via Python module / npm scripts:

```bash
PYTHONPATH=src python3 -m agent_policy_auditor.cli serve --port 8106
# or:
npm run serve
```

Open `http://127.0.0.1:8106` in your browser.

---

## CLI & ZothOS v3.4.0 Integration

On ZothOS v3.4.0, both `agent-policy` and `./bin/agent-policy` (plus `./bin/agent-policy-auditor-tui`) provide CLI lease management and manifest auditing:

```bash
# Inspect daemon status and active leases
agent-policy --status
agent-policy --json
agent-policy status --port 8106 --json

# Grant a 300-second filesystem read lease with a $1.50 budget ceiling
agent-policy lease grant --agent researcher_01 --cap FS_READ --target "/tmp/workspace/*" --duration 300 --budget 1.50

# Verify an action against an active lease (exits 0 if authorized, 1 if denied)
agent-policy lease verify --lease <lease_id> --cap FS_READ --target "/tmp/workspace/notes.md" --cost 0.05

# Revoke a lease
agent-policy lease revoke --lease <lease_id>

# Audit a JSON tool manifest or system prompt
agent-policy audit --file path/to/manifest.json --json
```

---

## REST API Reference

Mutating `POST` routes enforce local-origin CSRF validation (`127.0.0.1`, `localhost`, `[::1]`, or local CLI requests without an `Origin` header).

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/` | Web policy auditor & lease cockpit (`public/index.html`) |
| `GET` | `/health`, `/api/health` | Service health check (`status: "ok"`, `port: 8106`) |
| `GET` | `/api/stats` | Broker counters (`total_leases_granted`, `active_leases_count`, `violations_blocked`, `uptime_seconds`) |
| `GET` | `/api/leases` | Active capability leases with remaining TTL |
| `POST` | `/api/leases/grant` | Grant lease (`{"agent_id", "capability", "target", "duration_sec", "budget_usd"}`) |
| `POST` | `/api/leases/verify` | Verify action (`{"lease_id", "capability", "target", "cost_usd"}`) |
| `POST` | `/api/leases/revoke` | Revoke single lease (`{"lease_id": "..."}`) |
| `POST` | `/api/leases/revoke_all` | Revoke all active leases for an agent (`{"agent_id": "..."}`) |
| `POST` | `/api/audit` | Audit a manifest/schema (`{"name": "tool.json", "manifest": {...}}`) |

---

## Testing & Verification

```bash
PYTHONPATH=src python3 -m pytest -q
./bin/agent-policy --help
./bin/agent-policy --json
```

---

## Support & License

100% free and open-source software under the MIT License.

- Optional support: [Buy Us a Coffee via Stripe](https://buy.stripe.com/3cIfZg27PdKo2D64Ocfw40X)
- Engineered by **1nc0gn30** (`@1nc0gn30`, [https://1nc0gn30.si](https://1nc0gn30.si)) • **NullAI** ([https://nullai.tech](https://nullai.tech))
