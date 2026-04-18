# Copyright (c) 2026 Kantoshi Miyamura
#
# AxiomMind Safe Integration — Immutable Audit Log
#
# All decisions recorded with HMAC-SHA256 signature.
# Tampering detected via signature verification.
# Append-only: entries never deleted.

import asyncio
import hashlib
import hmac
import json
import logging
import time
from typing import List, Optional, Dict, Any
import aiosqlite

from .models import (
    AuditEntry, AuditEventType, ActionProposal, PolicyDecisionResult,
    ExecutionResult
)

_log = logging.getLogger(__name__)


class AuditLog:
    """
    Tamper-evident audit log with HMAC-SHA256 signatures.

    Every action proposal, policy decision, and execution is recorded.
    Signatures prevent tampering; signature verification on read detects it.
    """

    def __init__(self, db_path: str, secret_key: str):
        """
        Initialize audit log.

        Args:
            db_path: Path to SQLite database
            secret_key: Secret key for HMAC signature (>32 bytes)
        """
        self.db_path = db_path
        self.secret_key = secret_key.encode() if isinstance(secret_key, str) else secret_key
        self.db: Optional[aiosqlite.Connection] = None

        if len(self.secret_key) < 32:
            _log.warning(
                "AUDIT: secret_key is weak (%d bytes), use >= 32 bytes",
                len(self.secret_key)
            )

    async def initialize(self):
        """Initialize database schema."""
        self.db = await aiosqlite.connect(self.db_path)

        # Create audit table
        await self.db.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY,
                timestamp REAL NOT NULL,
                event_type TEXT NOT NULL,
                actor TEXT NOT NULL,
                action_type TEXT,
                reason TEXT,
                proposal_id TEXT,
                policy_decision_id TEXT,
                execution_id TEXT,
                details TEXT,
                signature TEXT NOT NULL,
                created_at REAL DEFAULT CURRENT_TIMESTAMP
            )
        """)

        await self.db.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp
            ON audit_log(timestamp DESC)
        """)

        await self.db.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_event_type
            ON audit_log(event_type)
        """)

        await self.db.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_actor
            ON audit_log(actor)
        """)

        await self.db.commit()
        _log.info("Audit log initialized: %s", self.db_path)

    async def close(self):
        """Close database connection."""
        if self.db:
            await self.db.close()

    # ─────────────────────────────────────────────────────────────────────────
    # Signature / Verification
    # ─────────────────────────────────────────────────────────────────────────

    def _compute_signature(self, entry_dict: Dict[str, Any]) -> str:
        """
        Compute HMAC-SHA256 signature for audit entry.

        Signature computed over all fields except signature itself.
        """
        # Remove signature from dict if present
        entry_copy = {k: v for k, v in entry_dict.items() if k != "signature"}

        # Sort keys for deterministic ordering
        message = json.dumps(entry_copy, sort_keys=True, default=str)
        message_bytes = message.encode("utf-8")

        sig = hmac.new(self.secret_key, message_bytes, hashlib.sha256).hexdigest()
        return sig

    def _verify_signature(self, entry_dict: Dict[str, Any]) -> bool:
        """
        Verify HMAC-SHA256 signature of audit entry.

        Returns:
            True if signature valid, False if tampered
        """
        stored_sig = entry_dict.get("signature", "")
        if not stored_sig:
            _log.warning("AUDIT TAMPER: missing signature")
            return False

        expected_sig = self._compute_signature(entry_dict)

        if not hmac.compare_digest(stored_sig, expected_sig):
            _log.error(
                "AUDIT TAMPER DETECTED: signature mismatch for entry %s",
                entry_dict.get("id", "unknown")
            )
            return False

        return True

    # ─────────────────────────────────────────────────────────────────────────
    # Logging Methods
    # ─────────────────────────────────────────────────────────────────────────

    async def log_anomaly_detected(
        self,
        anomaly_type: str,
        severity: str,
        details: Dict[str, Any],
    ) -> AuditEntry:
        """
        Log anomaly detection.

        Called when mind-core detects an issue.
        """
        entry = AuditEntry(
            event_type=AuditEventType.ANOMALY_DETECTED,
            actor="mind-core",
            reason=f"Anomaly detected: {anomaly_type}",
            details={
                "anomaly_type": anomaly_type,
                "severity": severity,
                **details,
            },
        )
        await self._store_entry(entry)
        return entry

    async def log_action_proposed(
        self,
        proposal: ActionProposal,
    ) -> AuditEntry:
        """
        Log action proposal.

        Called when mind-core generates a proposal.
        """
        entry = AuditEntry(
            event_type=AuditEventType.ACTION_PROPOSED,
            actor="mind-core",
            action_type=proposal.action_type,
            reason=proposal.reason,
            proposal_id=proposal.id,
            details={
                "proposal_id": proposal.id,
                "action_type": proposal.action_type.value,
                "severity": proposal.severity,
                "details": proposal.details,
            },
        )
        await self._store_entry(entry)
        return entry

    async def log_action_approved(
        self,
        proposal: ActionProposal,
        policy_result: PolicyDecisionResult,
    ) -> AuditEntry:
        """
        Log policy approval.

        Called when mind-policy approves an action.
        """
        entry = AuditEntry(
            event_type=AuditEventType.ACTION_APPROVED,
            actor="mind-policy",
            action_type=proposal.action_type,
            reason=policy_result.reason,
            proposal_id=proposal.id,
            policy_decision_id=policy_result.id,
            details={
                "proposal_id": proposal.id,
                "policy_decision_id": policy_result.id,
                "checks": policy_result.checks,
                "latency_ms": policy_result.latency_ms,
            },
        )
        await self._store_entry(entry)
        return entry

    async def log_action_rejected(
        self,
        proposal: ActionProposal,
        reason: str,
    ) -> AuditEntry:
        """
        Log policy rejection.

        Called when mind-policy rejects an action.
        """
        entry = AuditEntry(
            event_type=AuditEventType.ACTION_REJECTED,
            actor="mind-policy",
            action_type=proposal.action_type,
            reason=reason,
            proposal_id=proposal.id,
            details={
                "proposal_id": proposal.id,
                "rejection_reason": reason,
            },
        )
        await self._store_entry(entry)
        return entry

    async def log_action_executed(
        self,
        proposal: ActionProposal,
        execution_result: ExecutionResult,
    ) -> AuditEntry:
        """
        Log successful execution.

        Called when mind-executor successfully runs action.
        """
        entry = AuditEntry(
            event_type=AuditEventType.ACTION_EXECUTED,
            actor="mind-executor",
            action_type=proposal.action_type,
            reason=f"Executed: {proposal.action_type}",
            proposal_id=proposal.id,
            execution_id=execution_result.id,
            details={
                "proposal_id": proposal.id,
                "execution_id": execution_result.id,
                "success": execution_result.success,
                "return_code": execution_result.return_code,
                "duration_seconds": execution_result.duration_seconds,
                "stdout_lines": len(execution_result.stdout.split("\n")),
                "has_stderr": bool(execution_result.stderr),
            },
        )
        await self._store_entry(entry)
        return entry

    async def log_action_failed(
        self,
        proposal: ActionProposal,
        error_type: str,
        error_msg: str,
    ) -> AuditEntry:
        """
        Log execution failure.

        Called when mind-executor fails to run action.
        """
        entry = AuditEntry(
            event_type=AuditEventType.ACTION_FAILED,
            actor="mind-executor",
            action_type=proposal.action_type,
            reason=error_msg,
            proposal_id=proposal.id,
            details={
                "proposal_id": proposal.id,
                "error_type": error_type,
                "error_message": error_msg,
            },
        )
        await self._store_entry(entry)
        return entry

    async def log_tamper_detected(
        self,
        entry_id: str,
        reason: str,
    ) -> AuditEntry:
        """
        Log tamper detection.

        Called when signature verification fails.
        """
        entry = AuditEntry(
            event_type=AuditEventType.AUDIT_TAMPER_DETECTED,
            actor="audit-system",
            reason=f"Tamper detected: {reason}",
            details={
                "tampered_entry_id": entry_id,
                "detection_reason": reason,
            },
        )
        await self._store_entry(entry)
        return entry

    # ─────────────────────────────────────────────────────────────────────────
    # Storage & Retrieval
    # ─────────────────────────────────────────────────────────────────────────

    async def _store_entry(self, entry: AuditEntry) -> bool:
        """
        Store audit entry to database with signature.

        Returns:
            True if stored successfully
        """
        if not self.db:
            _log.error("Audit log not initialized")
            return False

        # Convert entry to dict
        entry_dict = {
            "id": entry.id,
            "timestamp": entry.timestamp,
            "event_type": entry.event_type.value,
            "actor": entry.actor,
            "action_type": entry.action_type.value if entry.action_type else None,
            "reason": entry.reason,
            "proposal_id": entry.proposal_id,
            "policy_decision_id": entry.policy_decision_id,
            "execution_id": entry.execution_id,
            "details": json.dumps(entry.details),
        }

        # Compute and add signature
        signature = self._compute_signature(entry_dict)
        entry_dict["signature"] = signature

        try:
            await self.db.execute(
                """
                INSERT INTO audit_log
                (id, timestamp, event_type, actor, action_type, reason,
                 proposal_id, policy_decision_id, execution_id, details, signature)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry_dict["id"],
                    entry_dict["timestamp"],
                    entry_dict["event_type"],
                    entry_dict["actor"],
                    entry_dict["action_type"],
                    entry_dict["reason"],
                    entry_dict["proposal_id"],
                    entry_dict["policy_decision_id"],
                    entry_dict["execution_id"],
                    entry_dict["details"],
                    entry_dict["signature"],
                ),
            )
            await self.db.commit()
            return True

        except Exception as exc:
            _log.exception("Failed to store audit entry: %s", exc)
            return False

    async def get_entries(
        self,
        limit: int = 100,
        offset: int = 0,
        event_type: Optional[AuditEventType] = None,
    ) -> List[Dict[str, Any]]:
        """
        Retrieve audit entries with signature verification.

        Returns:
            List of entries (with tamper detection applied)
        """
        if not self.db:
            return []

        query = "SELECT * FROM audit_log ORDER BY timestamp DESC"
        params: List[Any] = []

        if event_type:
            query += " WHERE event_type = ?"
            params.append(event_type.value)

        query += f" LIMIT {limit} OFFSET {offset}"

        entries = []
        async with self.db.execute(query, params) as cur:
            rows = await cur.fetchall()
            for row in rows:
                entry_dict = dict(row)

                # Verify signature
                if not self._verify_signature(entry_dict):
                    await self.log_tamper_detected(
                        entry_dict["id"],
                        "signature verification failed"
                    )
                    continue  # Skip tampered entry

                entries.append(entry_dict)

        return entries

    async def get_stats(self) -> Dict[str, Any]:
        """
        Get audit log statistics.

        Returns:
            Count of entries by type, total entries, etc.
        """
        if not self.db:
            return {}

        stats = {"total_entries": 0}

        async with self.db.execute(
            "SELECT COUNT(*) as count FROM audit_log"
        ) as cur:
            row = await cur.fetchone()
            stats["total_entries"] = row[0] if row else 0

        # Count by event type
        async with self.db.execute(
            "SELECT event_type, COUNT(*) as count FROM audit_log GROUP BY event_type"
        ) as cur:
            rows = await cur.fetchall()
            stats["by_event_type"] = {row[0]: row[1] for row in rows}

        # Count by actor
        async with self.db.execute(
            "SELECT actor, COUNT(*) as count FROM audit_log GROUP BY actor"
        ) as cur:
            rows = await cur.fetchall()
            stats["by_actor"] = {row[0]: row[1] for row in rows}

        return stats
