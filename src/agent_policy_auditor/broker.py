"""Autonomous Policy Broker and Time-Bound Capability Leaser.

Engineered by Neal Frazier Tech (@1nc0gn30) • NullAI Platform.
Provides HMAC-SHA256 signed capability leases with automatic TTL expiry,
path glob matching, and emergency kill-switches.
100% Python Standard Library — Zero External Dependencies.
"""

from __future__ import annotations

import fnmatch
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SECRET_KEY = os.environ.get("AGENT_POLICY_SECRET", secrets.token_hex(32))


@dataclass
class CapabilityLease:
    lease_id: str
    agent_id: str
    capability: str  # FS_READ, FS_WRITE, NET_EGRESS, SHELL_EXEC, TOKEN_BUDGET
    target: str      # Path glob, domain, command pattern, etc.
    granted_at: float
    expires_at: float
    duration_sec: float
    max_budget_usd: float = 0.0
    used_budget_usd: float = 0.0
    active: bool = True
    revoked: bool = False
    signature: str = ""

    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    def is_valid(self) -> bool:
        return self.active and not self.revoked and not self.is_expired()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class PolicyBroker:
    """Manages agent capability leases and enforces security policies."""

    def __init__(self, db_path: Optional[str] = None):
        self._lock = threading.RLock()
        self.db_path = db_path or os.environ.get(
            "AGENT_POLICY_DB",
            str(Path.home() / ".local" / "share" / "zoth" / "policy_leases.db")
        )
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self.leases: Dict[str, CapabilityLease] = {}
        self.violations_blocked: int = 0
        self.total_leases_granted: int = 0
        self._init_db()
        self._load_from_db()

    def _init_db(self) -> None:
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS leases (
                    lease_id TEXT PRIMARY KEY,
                    agent_id TEXT,
                    capability TEXT,
                    target TEXT,
                    granted_at REAL,
                    expires_at REAL,
                    duration_sec REAL,
                    max_budget_usd REAL,
                    used_budget_usd REAL,
                    active INTEGER,
                    revoked INTEGER,
                    signature TEXT
                )
            """)
            conn.commit()
            conn.close()

    def _load_from_db(self) -> None:
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute("SELECT lease_id, agent_id, capability, target, granted_at, expires_at, duration_sec, max_budget_usd, used_budget_usd, active, revoked, signature FROM leases")
            rows = cur.fetchall()
            for r in rows:
                lease = CapabilityLease(
                    lease_id=r[0],
                    agent_id=r[1],
                    capability=r[2],
                    target=r[3],
                    granted_at=r[4],
                    expires_at=r[5],
                    duration_sec=r[6],
                    max_budget_usd=r[7],
                    used_budget_usd=r[8],
                    active=bool(r[9]),
                    revoked=bool(r[10]),
                    signature=r[11]
                )
                self.leases[lease.lease_id] = lease
            conn.close()
            self.total_leases_granted = len(self.leases)

    def _generate_signature(self, lease_id: str, agent_id: str, capability: str, target: str, expires_at: float) -> str:
        payload = f"{lease_id}:{agent_id}:{capability}:{target}:{expires_at:.4f}".encode("utf-8")
        return hmac.new(SECRET_KEY.encode("utf-8"), payload, hashlib.sha256).hexdigest()

    def grant_lease(
        self,
        agent_id: str,
        capability: str,
        target: str,
        duration_sec: float = 300.0,
        max_budget_usd: float = 0.0
    ) -> CapabilityLease:
        """Issue a time-bound, signed capability lease to an agent."""
        with self._lock:
            lease_id = f"lease_{secrets.token_hex(6)}"
            now = time.time()
            expires_at = now + duration_sec
            sig = self._generate_signature(lease_id, agent_id, capability, target, expires_at)

            lease = CapabilityLease(
                lease_id=lease_id,
                agent_id=agent_id,
                capability=capability.upper(),
                target=target,
                granted_at=now,
                expires_at=expires_at,
                duration_sec=duration_sec,
                max_budget_usd=max_budget_usd,
                used_budget_usd=0.0,
                active=True,
                revoked=False,
                signature=sig
            )

            self.leases[lease_id] = lease
            self.total_leases_granted += 1

            # Persist to SQLite
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute("""
                INSERT OR REPLACE INTO leases VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                lease.lease_id, lease.agent_id, lease.capability, lease.target,
                lease.granted_at, lease.expires_at, lease.duration_sec,
                lease.max_budget_usd, lease.used_budget_usd,
                int(lease.active), int(lease.revoked), lease.signature
            ))
            conn.commit()
            conn.close()

            return lease

    def verify_action(
        self,
        lease_id: str,
        capability: str,
        target: str,
        cost_usd: float = 0.0
    ) -> Tuple[bool, str]:
        """Verify whether an action is authorized under an active lease."""
        with self._lock:
            lease = self.leases.get(lease_id)
            if not lease:
                self.violations_blocked += 1
                return False, "LeaseNotFound: No capability lease registered with this ID"

            if lease.revoked:
                self.violations_blocked += 1
                return False, "LeaseRevoked: Capability lease was explicitly revoked by security operator"

            if lease.is_expired():
                lease.active = False
                self.violations_blocked += 1
                return False, f"LeaseExpired: Capability lease expired {time.time() - lease.expires_at:.1f}s ago"

            # Verify cryptographic signature
            expected_sig = self._generate_signature(
                lease.lease_id, lease.agent_id, lease.capability, lease.target, lease.expires_at
            )
            if not hmac.compare_digest(lease.signature, expected_sig):
                self.violations_blocked += 1
                return False, "TamperedSignature: Lease signature verification failed"

            # Verify capability type
            if lease.capability != capability.upper():
                self.violations_blocked += 1
                return False, f"CapabilityMismatch: Required {capability.upper()}, lease only grants {lease.capability}"

            # Verify target match (supports glob matching)
            target_clean = str(target).strip()
            lease_target = str(lease.target).strip()

            matched = False
            if lease_target == "*" or lease_target == target_clean:
                matched = True
            elif fnmatch.fnmatch(target_clean, lease_target):
                matched = True

            if not matched:
                self.violations_blocked += 1
                return False, f"TargetNotPermitted: Action target '{target_clean}' does not match lease pattern '{lease_target}'"

            # Check budget quota if applicable
            if lease.max_budget_usd > 0.0:
                if lease.used_budget_usd + cost_usd > lease.max_budget_usd:
                    self.violations_blocked += 1
                    return False, f"BudgetExceeded: Lease budget ${lease.max_budget_usd:.4f} exceeded (used: ${lease.used_budget_usd:.4f}, requested: ${cost_usd:.4f})"
                lease.used_budget_usd += cost_usd

            return True, "Authorized: Action matches active capability lease"

    def revoke_lease(self, lease_id: str) -> bool:
        """Revoke a specific lease immediately."""
        with self._lock:
            lease = self.leases.get(lease_id)
            if not lease:
                return False
            lease.active = False
            lease.revoked = True

            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute("UPDATE leases SET active = 0, revoked = 1 WHERE lease_id = ?", (lease_id,))
            conn.commit()
            conn.close()
            return True

    def revoke_all_for_agent(self, agent_id: str) -> int:
        """Emergency Kill-Switch: Revoke all active leases for an agent."""
        count = 0
        with self._lock:
            for l in self.leases.values():
                if l.agent_id == agent_id and l.active:
                    l.active = False
                    l.revoked = True
                    count += 1
            if count > 0:
                conn = sqlite3.connect(self.db_path)
                cur = conn.cursor()
                cur.execute("UPDATE leases SET active = 0, revoked = 1 WHERE agent_id = ?", (agent_id,))
                conn.commit()
                conn.close()
        return count

    def get_active_leases(self) -> List[Dict[str, Any]]:
        """Return all valid, non-expired leases."""
        with self._lock:
            valid = []
            now = time.time()
            for l in self.leases.values():
                if l.is_valid():
                    d = l.to_dict()
                    d["ttl_seconds"] = max(0.0, l.expires_at - now)
                    valid.append(d)
            return sorted(valid, key=lambda x: x["ttl_seconds"])

    def get_stats(self) -> Dict[str, Any]:
        """Return operational telemetry."""
        with self._lock:
            active_count = sum(1 for l in self.leases.values() if l.is_valid())
            revoked_count = sum(1 for l in self.leases.values() if l.revoked)
            total_budget = sum(l.max_budget_usd for l in self.leases.values())
            used_budget = sum(l.used_budget_usd for l in self.leases.values())

            return {
                "total_leases_granted": self.total_leases_granted,
                "active_leases_count": active_count,
                "revoked_leases_count": revoked_count,
                "violations_blocked": self.violations_blocked,
                "total_budget_allocated_usd": round(total_budget, 4),
                "total_budget_consumed_usd": round(used_budget, 4),
            }
