"""HTTP Server & REST Cockpit for Agent Policy Auditor (Port 8106).

Engineered by Neal Frazier Tech (@1nc0gn30) • NullAI Platform.
100% Python Standard Library — Zero External Pip Dependencies.
"""

from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict, Optional

from agent_policy_auditor.auditor import ManifestAuditor
from agent_policy_auditor.broker import PolicyBroker


def _safe_rel(raw: str) -> str:
    """Request path -> safe relative path inside a static dir; '' (index) if it
    tries to climb out with '..' or is absolute. Raw request paths are not normalised."""
    from urllib.parse import unquote
    rel = unquote(str(raw or "")).replace("\\", "/").lstrip("/")
    parts = [p for p in rel.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts) or ":" in (parts[0] if parts else ""):
        return ""
    return "/".join(parts)


def _is_local_origin(origin) -> bool:
    """Browser Origin check. No Origin header = non-browser client (CLI/agent): allowed.
    Otherwise only http(s)://localhost / 127.0.0.1 / [::1] pages may call this API, so a
    random website can't drive the local server from the user's browser (CSRF)."""
    if not origin:
        return True
    from urllib.parse import urlparse
    try:
        u = urlparse(origin)
    except ValueError:
        return False
    return u.scheme in ("http", "https") and u.hostname in ("localhost", "127.0.0.1", "::1")


def _cors_origin(handler) -> str:
    origin = handler.headers.get("Origin")
    return origin if origin and _is_local_origin(origin) else "http://127.0.0.1"


STATIC_DIR = Path(__file__).resolve().parent.parent.parent / "public"


class CockpitHandler(BaseHTTPRequestHandler):
    broker = PolicyBroker()
    auditor = ManifestAuditor()
    start_time = time.time()

    def log_message(self, format: str, *args: Any) -> None:
        pass  # Suppress default noisy console logs

    def _send_json(self, data: Any, status: int = 200) -> None:
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", _cors_origin(self))
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", _cors_origin(self))
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_GET(self) -> None:
        url = urllib.parse.urlparse(self.path)
        path = url.path

        if path == "/api/stats":
            stats = self.broker.get_stats()
            stats["uptime_seconds"] = round(time.time() - self.start_time, 1)
            self._send_json(stats)
            return

        if path == "/api/leases":
            leases = self.broker.get_active_leases()
            self._send_json({"leases": leases, "count": len(leases)})
            return

        if path in ["/api/health", "/health"]:
            self._send_json({"status": "ok", "service": "agent-policy-auditor", "port": 8106})
            return

        # Serve Static Files
        clean_path = _safe_rel(path)
        if not clean_path:
            clean_path = "index.html"
        target_file = (STATIC_DIR / clean_path).resolve()

        if not target_file.is_relative_to(STATIC_DIR.resolve()):
            self.send_error(403, "Forbidden")
            return

        if target_file.is_file():
            mime = "text/html"
            if target_file.suffix == ".json":
                mime = "application/json"
            elif target_file.suffix == ".css":
                mime = "text/css"
            elif target_file.suffix == ".js":
                mime = "application/javascript"
            elif target_file.suffix == ".png":
                mime = "image/png"
            elif target_file.suffix == ".svg":
                mime = "image/svg+xml"
            elif target_file.suffix in [".txt", ".xml"]:
                mime = "text/plain"

            content = target_file.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", f"{mime}; charset=utf-8" if "text" in mime or "json" in mime else mime)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return

        # Fallback to index.html for SPA behavior
        index_file = STATIC_DIR / "index.html"
        if index_file.is_file():
            content = index_file.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return

        self.send_error(404, "File Not Found")

    def do_POST(self) -> None:
        if not _is_local_origin(self.headers.get("Origin")):
            _body = b'{"error": "cross-origin request blocked"}'
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(_body)))
            self.end_headers()
            self.wfile.write(_body)
            return
        url = urllib.parse.urlparse(self.path)
        path = url.path
        length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(length) if length > 0 else b"{}"

        try:
            body = json.loads(raw_body.decode("utf-8")) if raw_body else {}
        except Exception:
            body = {}

        if path == "/api/leases/grant":
            agent_id = body.get("agent_id", "default_agent")
            capability = body.get("capability", "FS_READ")
            target = body.get("target", "*")
            duration_sec = float(body.get("duration_sec", 300.0))
            budget_usd = float(body.get("budget_usd", 0.0))

            lease = self.broker.grant_lease(
                agent_id=agent_id,
                capability=capability,
                target=target,
                duration_sec=duration_sec,
                max_budget_usd=budget_usd
            )
            self._notify_flight_recorder("LEASE_GRANTED", f"Granted {capability} to {agent_id} for target {target}")
            self._send_json({"status": "granted", "lease": lease.to_dict()})
            return

        if path == "/api/leases/verify":
            lease_id = body.get("lease_id", "")
            capability = body.get("capability", "")
            target = body.get("target", "")
            cost_usd = float(body.get("cost_usd", 0.0))

            allowed, reason = self.broker.verify_action(
                lease_id=lease_id,
                capability=capability,
                target=target,
                cost_usd=cost_usd
            )
            if not allowed:
                self._notify_flight_recorder("LEASE_VIOLATION", f"Blocked unauthorized {capability} on {target}: {reason}")

            self._send_json({"allowed": allowed, "reason": reason})
            return

        if path == "/api/leases/revoke":
            lease_id = body.get("lease_id", "")
            success = self.broker.revoke_lease(lease_id)
            self._notify_flight_recorder("LEASE_REVOKED", f"Revoked lease {lease_id}")
            self._send_json({"revoked": success, "lease_id": lease_id})
            return

        if path == "/api/leases/revoke_all":
            agent_id = body.get("agent_id", "")
            count = self.broker.revoke_all_for_agent(agent_id)
            self._notify_flight_recorder("EMERGENCY_KILLSWITCH", f"Revoked all {count} leases for agent {agent_id}")
            self._send_json({"revoked_count": count, "agent_id": agent_id})
            return

        if path == "/api/audit":
            manifest = body.get("manifest", body)
            name = body.get("name", "agent_manifest")
            report = self.auditor.audit_manifest(manifest, name=name)
            self._send_json(report.to_dict())
            return

        self.send_error(404, "Endpoint Not Found")

    def _notify_flight_recorder(self, event_type: str, message: str) -> None:
        """Forward policy events into Agent Flight Recorder on port 8104."""
        try:
            payload = json.dumps({
                "source": "agent-policy-auditor",
                "type": event_type,
                "message": message,
                "timestamp_ms": int(time.time() * 1000)
            }).encode("utf-8")
            req = urllib.request.Request(
                "http://127.0.0.1:8104/api/ingest",
                data=payload,
                headers={"Content-Type": "application/json"}
            )
            urllib.request.urlopen(req, timeout=0.5)
        except Exception:
            pass


def serve(port: int = 8106, host: str = "127.0.0.1") -> None:
    server = HTTPServer((host, port), CockpitHandler)
    print(f"⚡ [AGENT POLICY AUDITOR] Cockpit & Lease Broker running on http://127.0.0.1:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Agent Policy Auditor...")
        server.server_close()
