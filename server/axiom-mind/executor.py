# Copyright (c) 2026 Kantoshi Miyamura
#
# AxiomMind Safe Integration — Safe Executor
#
# Executes ONLY whitelisted actions.
# NO command generation from untrusted input.
# Every execution logged to immutable audit trail.

import asyncio
import logging
import time
from typing import List, Optional, Dict, Any

from .models import (
    ActionProposal, ActionType, PolicyDecisionResult, ExecutionResult,
    PolicyDecision, ExecutorConfig
)

_log = logging.getLogger(__name__)


class SecurityError(Exception):
    """Raised when executor detects security violation."""
    pass


class SafeExecutor:
    """
    Safely executes whitelisted actions only.

    Key invariants:
    1. ONLY hardcoded commands in WHITELIST can execute
    2. Policy approval REQUIRED before execution
    3. 30-second timeout per command
    4. All executions logged to audit trail
    5. Return code + output captured for verification
    """

    # ─────────────────────────────────────────────────────────────────────────
    # WHITELIST OF ALLOWED COMMANDS
    # ─────────────────────────────────────────────────────────────────────────
    # NO command generation, NO interpolation, NO user input in commands.
    # These are the ONLY commands that can execute.
    # ─────────────────────────────────────────────────────────────────────────

    WHITELIST: Dict[ActionType, List[str]] = {
        # Restart blockchain node via systemd
        ActionType.RESTART_NODE: [
            "systemctl", "restart", "axiom-node"
        ],

        # Reload nginx configuration (graceful restart)
        ActionType.RELOAD_NGINX: [
            "systemctl", "reload", "nginx"
        ],

        # Restart axiom-web service via PM2
        ActionType.RESTART_WEB: [
            "pm2", "restart", "axiom-web"
        ],

        # Cleanup journald logs (size limit)
        ActionType.CLEANUP_LOGS: [
            "journalctl", "--vacuum-size=100M"
        ],

        # Log advisory (no actual execution, just log)
        ActionType.LOG_ADVISORY: [
            "echo", "AxiomMind advisory logged"
        ],
    }

    def __init__(self, config: ExecutorConfig = None, audit_logger=None):
        """
        Initialize safe executor.

        Args:
            config: Executor configuration
            audit_logger: Audit log interface (called for every action)
        """
        self.config = config or ExecutorConfig()
        self.audit_logger = audit_logger
        self._execution_count = 0

        _log.info(
            "SafeExecutor initialized: enabled=%s, require_approval=%s, timeout=%ds",
            self.config.enable_execution,
            self.config.require_policy_approval,
            self.config.command_timeout_seconds,
        )

    async def execute(
        self,
        proposal: ActionProposal,
        policy_result: PolicyDecisionResult,
    ) -> ExecutionResult:
        """
        Execute action only if policy approves.

        Args:
            proposal: Action proposal from mind-core
            policy_result: Decision from mind-policy

        Returns:
            ExecutionResult with success/failure + output

        Raises:
            SecurityError: If action not whitelisted or policy not approved
        """
        result = ExecutionResult(
            proposal_id=proposal.id,
            action_type=proposal.action_type,
        )

        # ─────────────────────────────────────────────────────────────────────
        # Check 1: Is action whitelisted?
        # ─────────────────────────────────────────────────────────────────────
        if proposal.action_type not in self.WHITELIST:
            error = f"Action not whitelisted: {proposal.action_type}"
            _log.error("SECURITY: %s", error)
            result.error = error
            result.success = False

            if self.audit_logger:
                await self.audit_logger.log_action_failed(
                    proposal, "action_not_whitelisted", error
                )

            raise SecurityError(error)

        # ─────────────────────────────────────────────────────────────────────
        # Check 2: Does policy approve?
        # ─────────────────────────────────────────────────────────────────────
        if self.config.require_policy_approval:
            if policy_result.decision != PolicyDecision.APPROVE:
                error = f"Policy rejected action: {policy_result.reason}"
                _log.warning("Policy rejection: %s", error)
                result.error = error
                result.success = False

                if self.audit_logger:
                    await self.audit_logger.log_action_rejected(
                        proposal, policy_result.reason
                    )

                return result  # Not a security error, just rejected

        # ─────────────────────────────────────────────────────────────────────
        # Check 3: Get hardcoded command (no generation!)
        # ─────────────────────────────────────────────────────────────────────
        cmd = self.WHITELIST[proposal.action_type]
        _log.info(
            "Executor: about to run %s (whitelist verified)",
            " ".join(cmd)
        )

        # ─────────────────────────────────────────────────────────────────────
        # Execute (or skip if disabled)
        # ─────────────────────────────────────────────────────────────────────
        start_time = time.time()

        if not self.config.enable_execution:
            # DRY RUN MODE: skip actual execution
            _log.info("DRY RUN: would execute %s", " ".join(cmd))
            result.success = True
            result.stdout = "[DRY RUN - not executed]"
            result.duration_seconds = 0.0
        else:
            try:
                result_tuple = await self._run_command_with_timeout(
                    cmd, timeout=self.config.command_timeout_seconds
                )
                result.success = result_tuple[0]
                result.return_code = result_tuple[1]
                result.stdout = result_tuple[2]
                result.stderr = result_tuple[3]
                result.error = result_tuple[4]

            except Exception as exc:
                _log.exception("Executor error: %s", exc)
                result.success = False
                result.error = str(exc)

        result.duration_seconds = time.time() - start_time

        # ─────────────────────────────────────────────────────────────────────
        # Log to audit trail
        # ─────────────────────────────────────────────────────────────────────
        if self.audit_logger:
            if result.success:
                await self.audit_logger.log_action_executed(proposal, result)
            else:
                await self.audit_logger.log_action_failed(
                    proposal, "execution_error", result.error or "unknown error"
                )

        self._execution_count += 1

        _log.info(
            "Executor: action %s completed in %.2fs: success=%s return_code=%d",
            proposal.action_type, result.duration_seconds,
            result.success, result.return_code
        )

        return result

    async def _run_command_with_timeout(
        self,
        cmd: List[str],
        timeout: int = 30,
    ) -> tuple[bool, int, str, str, Optional[str]]:
        """
        Run command with timeout.

        Returns:
            (success, return_code, stdout, stderr, error)
            - success: True if return_code == 0
            - error: None if success, error string otherwise
        """
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                await asyncio.wait_for(proc.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                _log.warning("Command timeout: %s (killed)", " ".join(cmd))
                proc.kill()
                await proc.wait()
                return (
                    False, -1, "", "",
                    f"Command timeout after {timeout}s"
                )

            # Get output
            stdout_bytes = proc.stdout.read() if proc.stdout else b""
            stderr_bytes = proc.stderr.read() if proc.stderr else b""
            await asyncio.gather(
                proc.stdout.read() if proc.stdout else asyncio.sleep(0),
                proc.stderr.read() if proc.stderr else asyncio.sleep(0),
            )

            stdout = stdout_bytes.decode("utf-8", errors="replace") if proc.stdout else ""
            stderr = stderr_bytes.decode("utf-8", errors="replace") if proc.stderr else ""

            # Communicate to get output properly
            stdout, stderr = await proc.communicate()
            stdout = stdout.decode("utf-8", errors="replace") if stdout else ""
            stderr = stderr.decode("utf-8", errors="replace") if stderr else ""

            success = proc.returncode == 0
            error = None if success else f"Command failed with code {proc.returncode}"

            return (success, proc.returncode, stdout, stderr, error)

        except Exception as exc:
            _log.exception("Exception running command: %s", exc)
            return (False, -1, "", "", str(exc))

    # ─────────────────────────────────────────────────────────────────────────
    # Monitoring
    # ─────────────────────────────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        """
        Get executor statistics.

        Used for monitoring + debugging.
        """
        return {
            "enabled": self.config.enable_execution,
            "require_policy_approval": self.config.require_policy_approval,
            "command_timeout_seconds": self.config.command_timeout_seconds,
            "execution_count": self._execution_count,
            "whitelist_size": len(self.WHITELIST),
            "allowed_actions": [a.value for a in self.WHITELIST.keys()],
        }
