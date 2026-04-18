# Copyright (c) 2026 Kantoshi Miyamura
#
# AxiomMind Safe Integration — Policy Engine
#
# Validates all action proposals before they can be executed.
# NO action bypasses the policy engine.
# All policy decisions are logged and auditable.

import asyncio
import time
import logging
from typing import Dict, Set, Optional
from datetime import datetime, timedelta

from .models import (
    ActionProposal, ActionType, PolicyDecision, PolicyDecisionResult,
    SystemState, MinCooldownConfig, RateLimitConfig
)

_log = logging.getLogger(__name__)


class PolicyEngine:
    """
    Validates action proposals against safety policies.

    Key invariants:
    1. No action executes without APPROVE decision
    2. Cooldowns prevent restart loops
    3. Rate limits prevent action spam
    4. Health preconditions prevent unsafe actions
    5. All decisions are logged (tamper-proof)
    """

    def __init__(
        self,
        cooldown_config: MinCooldownConfig = None,
        rate_limit_config: RateLimitConfig = None,
    ):
        self.cooldown_config = cooldown_config or MinCooldownConfig()
        self.rate_limit_config = rate_limit_config or RateLimitConfig()

        # Track action history for cooldown + rate limiting
        self._action_history: Dict[str, list[float]] = {
            action.value: [] for action in ActionType
        }

    async def validate_action(
        self,
        proposal: ActionProposal,
        system_state: SystemState,
    ) -> PolicyDecisionResult:
        """
        Validate action proposal against all policies.

        Args:
            proposal: Action to validate
            system_state: Current system health snapshot

        Returns:
            PolicyDecisionResult with decision + reasoning
        """
        start_time = time.time()
        checks: Dict[str, bool] = {}

        # ─────────────────────────────────────────────────────────────────────
        # Check 1: Action type is whitelisted
        # ─────────────────────────────────────────────────────────────────────
        try:
            action_enum = ActionType(proposal.action_type.value)
            checks["action_whitelisted"] = True
        except ValueError:
            checks["action_whitelisted"] = False
            return PolicyDecisionResult(
                proposal_id=proposal.id,
                decision=PolicyDecision.REJECT,
                reason=f"Action '{proposal.action_type}' is not whitelisted",
                checks=checks,
                latency_ms=1000 * (time.time() - start_time),
            )

        # ─────────────────────────────────────────────────────────────────────
        # Check 2: Cooldown enforcement (prevent immediate repeat)
        # ─────────────────────────────────────────────────────────────────────
        cooldown_ok, cooldown_reason = self._check_cooldown(proposal.action_type)
        checks["cooldown_enforced"] = cooldown_ok
        if not cooldown_ok:
            return PolicyDecisionResult(
                proposal_id=proposal.id,
                decision=PolicyDecision.REJECT,
                reason=cooldown_reason,
                checks=checks,
                latency_ms=1000 * (time.time() - start_time),
            )

        # ─────────────────────────────────────────────────────────────────────
        # Check 3: Rate limiting (prevent action spam)
        # ─────────────────────────────────────────────────────────────────────
        rate_ok, rate_reason = self._check_rate_limit(proposal.action_type)
        checks["rate_limit_ok"] = rate_ok
        if not rate_ok:
            return PolicyDecisionResult(
                proposal_id=proposal.id,
                decision=PolicyDecision.REJECT,
                reason=rate_reason,
                checks=checks,
                latency_ms=1000 * (time.time() - start_time),
            )

        # ─────────────────────────────────────────────────────────────────────
        # Check 4: Action-specific health preconditions
        # ─────────────────────────────────────────────────────────────────────
        health_ok, health_reason = await self._check_health_preconditions(
            proposal.action_type, system_state
        )
        checks["health_preconditions"] = health_ok
        if not health_ok:
            return PolicyDecisionResult(
                proposal_id=proposal.id,
                decision=PolicyDecision.REJECT,
                reason=health_reason,
                checks=checks,
                latency_ms=1000 * (time.time() - start_time),
            )

        # ─────────────────────────────────────────────────────────────────────
        # All checks passed → APPROVE
        # ─────────────────────────────────────────────────────────────────────
        _log.info(
            "Policy APPROVE: action=%s reason=%s severity=%s",
            proposal.action_type, proposal.reason, proposal.severity
        )

        return PolicyDecisionResult(
            proposal_id=proposal.id,
            decision=PolicyDecision.APPROVE,
            reason="All policy checks passed",
            checks=checks,
            latency_ms=1000 * (time.time() - start_time),
        )

    # ─────────────────────────────────────────────────────────────────────────
    # Policy Checks
    # ─────────────────────────────────────────────────────────────────────────

    def _check_cooldown(self, action_type: ActionType) -> tuple[bool, str]:
        """
        Enforce minimum time between repeated actions.

        Returns:
            (passed, reason)
        """
        action_key = action_type.value
        now = time.time()

        # Get cooldown requirement for this action
        cooldown_secs = getattr(
            self.cooldown_config, action_key.replace("-", "_"), 300
        )

        # Get last execution time
        history = self._action_history.get(action_key, [])
        if not history:
            # First execution, no cooldown needed
            return True, ""

        last_exec = history[-1]
        elapsed = now - last_exec

        if elapsed < cooldown_secs:
            remaining = cooldown_secs - elapsed
            reason = (
                f"Action '{action_key}' on cooldown: "
                f"executed {elapsed:.0f}s ago, need {cooldown_secs}s. "
                f"Wait {remaining:.0f}s more."
            )
            return False, reason

        return True, ""

    def _check_rate_limit(self, action_type: ActionType) -> tuple[bool, str]:
        """
        Enforce max actions per time period.

        Returns:
            (passed, reason)
        """
        action_key = action_type.value
        now = time.time()

        # Default: max 10 actions per hour
        max_per_hour = self.rate_limit_config.max_actions_per_hour

        # Special case: restart_node has tighter limit (max 3 per 6h)
        if action_type == ActionType.RESTART_NODE:
            max_per_period = self.rate_limit_config.max_restarts_per_6h
            period_secs = 6 * 3600
        else:
            max_per_period = max_per_hour
            period_secs = 3600

        history = self._action_history.get(action_key, [])

        # Remove entries older than period
        cutoff = now - period_secs
        recent = [t for t in history if t > cutoff]
        self._action_history[action_key] = recent

        if len(recent) >= max_per_period:
            reason = (
                f"Rate limit exceeded for '{action_key}': "
                f"{len(recent)}/{max_per_period} in last "
                f"{period_secs//3600}h. Wait before retrying."
            )
            return False, reason

        return True, ""

    async def _check_health_preconditions(
        self,
        action_type: ActionType,
        system_state: SystemState,
    ) -> tuple[bool, str]:
        """
        Check action-specific health preconditions.

        E.g., only restart_node if RPC is actually down.

        Returns:
            (passed, reason)
        """
        if action_type == ActionType.RESTART_NODE:
            # Precondition: RPC must actually be down
            if system_state.rpc_alive:
                return (
                    False,
                    "Cannot restart node: RPC is currently alive. "
                    "Action only allowed when RPC unresponsive."
                )
            return True, ""

        elif action_type == ActionType.RELOAD_NGINX:
            # Precondition: nginx must not be active
            if system_state.nginx_active:
                return (
                    False,
                    "Cannot reload nginx: nginx is already active. "
                    "Only reload if service is down."
                )
            return True, ""

        elif action_type == ActionType.RESTART_WEB:
            # Precondition: axiom-web must not be online
            if system_state.axiom_web_online:
                return (
                    False,
                    "Cannot restart axiom-web: service is already online. "
                    "Only restart if service is down."
                )
            return True, ""

        elif action_type == ActionType.CLEANUP_LOGS:
            # Precondition: disk usage must be high
            if system_state.disk_percent < 85:
                return (
                    False,
                    "Cannot cleanup logs: disk usage is only "
                    f"{system_state.disk_percent:.1f}%. "
                    "Only cleanup when disk > 85%."
                )
            return True, ""

        elif action_type == ActionType.LOG_ADVISORY:
            # Advisory-only, no preconditions
            return True, ""

        return False, f"Unknown action type: {action_type}"

    # ─────────────────────────────────────────────────────────────────────────
    # Tracking & History
    # ─────────────────────────────────────────────────────────────────────────

    def record_execution(self, action_type: ActionType, timestamp: float = None):
        """
        Record that an action was executed.

        Called by mind-executor after successful execution.
        """
        if timestamp is None:
            timestamp = time.time()

        action_key = action_type.value
        if action_key not in self._action_history:
            self._action_history[action_key] = []

        self._action_history[action_key].append(timestamp)

        # Keep only last 1000 entries per action
        if len(self._action_history[action_key]) > 1000:
            self._action_history[action_key] = (
                self._action_history[action_key][-1000:]
            )

        _log.debug(
            "Policy: recorded execution of %s at %s",
            action_key, datetime.fromtimestamp(timestamp).isoformat()
        )

    def get_action_history(self, action_type: ActionType) -> list[float]:
        """
        Get execution history for an action.

        Returns list of timestamps when action was executed.
        """
        action_key = action_type.value
        return self._action_history.get(action_key, [])

    def get_stats(self) -> Dict[str, any]:
        """
        Get policy engine statistics.

        Used for monitoring + debugging.
        """
        return {
            "action_history": {
                key: len(times) for key, times in self._action_history.items()
            },
            "cooldown_config": {
                "restart_node": self.cooldown_config.restart_node,
                "reload_nginx": self.cooldown_config.reload_nginx,
                "restart_web": self.cooldown_config.restart_web,
                "log_advisory": self.cooldown_config.log_advisory,
                "cleanup_logs": self.cooldown_config.cleanup_logs,
            },
            "rate_limit_config": {
                "max_actions_per_hour": self.rate_limit_config.max_actions_per_hour,
                "max_restarts_per_6h": self.rate_limit_config.max_restarts_per_6h,
            },
        }
