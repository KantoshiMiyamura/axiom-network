# -*- coding: utf-8 -*-
"""
RuleEngine — Deterministic domain rules for AxiomMind

All rules are hardcoded, deterministic, and domain-specific.
No external dependencies. No AI involved.
"""

from dataclasses import dataclass
from typing import List
from datetime import datetime, timezone


@dataclass
class RuleViolation:
    """A single rule violation with remediation guidance."""
    rule_name: str          # "height_stuck", "rpc_down", etc
    severity: str           # "critical", "warning", "info"
    description: str        # Human-readable explanation
    metric_name: str        # Name of metric that violated rule
    metric_value: float     # The value that triggered the rule
    threshold: float        # The threshold that was crossed
    remediation: str        # Suggested action
    timestamp: float        # When violation was detected


class RuleEngine:
    """
    Hardcoded domain rules for blockchain system monitoring.

    Rules are:
    - Deterministic (always same input → same output)
    - Domain-specific (based on blockchain knowledge)
    - Non-blocking (all rules checked, all violations returned)
    - Production-proven (rules from years of production operation)
    """

    # Rule thresholds (tunable parameters)
    RPC_TIMEOUT_SECS = 30
    HEIGHT_STUCK_SECS = 600  # 10 minutes
    DISK_THRESHOLD_PCT = 90.0
    PEER_COUNT_MIN = 2
    MEMPOOL_FEE_RATIO_THRESHOLD = 5.0  # p90/p50
    BLOCK_TIME_MAX_SECS = 120  # 2 minutes

    def check_rules(self, state: dict) -> List[RuleViolation]:
        """
        Apply all hardcoded rules to the current state.
        Returns list of violations (may be empty).

        Each rule is applied independently, allowing multiple
        simultaneous violations to be detected.
        """
        violations: List[RuleViolation] = []
        now = datetime.now(timezone.utc).timestamp()

        # Rule 1: RPC Connectivity
        violations.extend(self._rule_rpc_alive(state, now))

        # Rule 2: Height Progress
        violations.extend(self._rule_height_stuck(state, now))

        # Rule 3: Disk Space
        violations.extend(self._rule_disk_usage(state, now))

        # Rule 4: Nginx Web Service
        violations.extend(self._rule_nginx_active(state, now))

        # Rule 5: Peer Count
        violations.extend(self._rule_peer_count(state, now))

        # Rule 6: Mempool Fee Pressure
        violations.extend(self._rule_mempool_pressure(state, now))

        # Rule 7: Block Time
        violations.extend(self._rule_block_time(state, now))

        return violations

    def _rule_rpc_alive(self, state: dict, now: float) -> List[RuleViolation]:
        """
        Rule: RPC must be responsive.
        Violation: RPC has not responded for > RPC_TIMEOUT_SECS
        """
        violations = []

        if not state.get("rpc_available"):
            seconds_down = state.get("rpc_down_secs", 0)
            if seconds_down >= self.RPC_TIMEOUT_SECS:
                violations.append(RuleViolation(
                    rule_name="rpc_down",
                    severity="critical",
                    description=f"RPC unresponsive for {seconds_down}s (threshold: {self.RPC_TIMEOUT_SECS}s)",
                    metric_name="rpc_available",
                    metric_value=0.0,
                    threshold=1.0,
                    remediation="Restart axiom-node to restore RPC connectivity",
                    timestamp=now,
                ))

        return violations

    def _rule_height_stuck(self, state: dict, now: float) -> List[RuleViolation]:
        """
        Rule: Block height must progress regularly.
        Violation: Height unchanged for > HEIGHT_STUCK_SECS
        """
        violations = []

        height_stuck_secs = state.get("height_stuck_secs", 0)
        if height_stuck_secs >= self.HEIGHT_STUCK_SECS:
            height = state.get("height", 0)
            violations.append(RuleViolation(
                rule_name="height_stuck",
                severity="critical",
                description=(
                    f"Block height stuck at {height} for {height_stuck_secs}s "
                    f"(threshold: {self.HEIGHT_STUCK_SECS}s)"
                ),
                metric_name="height_stuck_secs",
                metric_value=height_stuck_secs,
                threshold=float(self.HEIGHT_STUCK_SECS),
                remediation="Restart axiom-node to resume block production",
                timestamp=now,
            ))

        return violations

    def _rule_disk_usage(self, state: dict, now: float) -> List[RuleViolation]:
        """
        Rule: Disk usage must not exceed threshold.
        Violation: Disk usage > DISK_THRESHOLD_PCT
        """
        violations = []

        disk_percent = state.get("disk_percent", 0.0)
        if disk_percent > self.DISK_THRESHOLD_PCT:
            violations.append(RuleViolation(
                rule_name="disk_full",
                severity="warning",
                description=(
                    f"Disk usage at {disk_percent:.1f}% "
                    f"(threshold: {self.DISK_THRESHOLD_PCT:.1f}%)"
                ),
                metric_name="disk_percent",
                metric_value=disk_percent,
                threshold=self.DISK_THRESHOLD_PCT,
                remediation="Clean up logs: journalctl --vacuum-size=100M",
                timestamp=now,
            ))

        return violations

    def _rule_nginx_active(self, state: dict, now: float) -> List[RuleViolation]:
        """
        Rule: Nginx must be active for web dashboard.
        Violation: Nginx is not responding
        """
        violations = []

        if not state.get("nginx_active", False):
            violations.append(RuleViolation(
                rule_name="nginx_down",
                severity="warning",
                description="Nginx is not responding to health checks",
                metric_name="nginx_active",
                metric_value=0.0,
                threshold=1.0,
                remediation="Reload nginx: systemctl reload nginx",
                timestamp=now,
            ))

        return violations

    def _rule_peer_count(self, state: dict, now: float) -> List[RuleViolation]:
        """
        Rule: Minimum peer count for network health.
        Violation: Peer count < PEER_COUNT_MIN
        """
        violations = []

        peers = state.get("peers", 0)
        if peers < self.PEER_COUNT_MIN:
            violations.append(RuleViolation(
                rule_name="insufficient_peers",
                severity="warning",
                description=(
                    f"Peer count {peers} below minimum {self.PEER_COUNT_MIN} "
                    f"(may indicate network isolation)"
                ),
                metric_name="peers",
                metric_value=float(peers),
                threshold=float(self.PEER_COUNT_MIN),
                remediation="Check network connectivity and firewall settings",
                timestamp=now,
            ))

        return violations

    def _rule_mempool_pressure(self, state: dict, now: float) -> List[RuleViolation]:
        """
        Rule: Mempool fee pressure.
        Violation: p90/p50 fee ratio > MEMPOOL_FEE_RATIO_THRESHOLD
        (This is advisory, no auto-remediation for consensus parameters)
        """
        violations = []

        fee_p90 = state.get("fee_p90", 0.0) or 0.0
        fee_p50 = state.get("fee_p50", 0.0) or 0.0

        if fee_p50 > 0 and fee_p90 > 0:
            ratio = fee_p90 / max(fee_p50, 1e-9)
            if ratio > self.MEMPOOL_FEE_RATIO_THRESHOLD:
                violations.append(RuleViolation(
                    rule_name="mempool_fee_pressure",
                    severity="info",  # Info, not actionable via healing
                    description=(
                        f"Mempool fee pressure high: p90/p50 = {ratio:.2f}x "
                        f"(threshold: {self.MEMPOOL_FEE_RATIO_THRESHOLD}x)"
                    ),
                    metric_name="fee_pressure_ratio",
                    metric_value=ratio,
                    threshold=self.MEMPOOL_FEE_RATIO_THRESHOLD,
                    remediation="Consider raising min relay fee (manual configuration)",
                    timestamp=now,
                ))

        return violations

    def _rule_block_time(self, state: dict, now: float) -> List[RuleViolation]:
        """
        Rule: Block time should be reasonable.
        Violation: Last block time > BLOCK_TIME_MAX_SECS
        """
        violations = []

        last_block_time_secs = state.get("last_block_time_secs", 0.0)
        if last_block_time_secs > self.BLOCK_TIME_MAX_SECS:
            violations.append(RuleViolation(
                rule_name="slow_block_production",
                severity="warning",
                description=(
                    f"Last block took {last_block_time_secs:.1f}s to produce "
                    f"(normal: <{self.BLOCK_TIME_MAX_SECS}s)"
                ),
                metric_name="last_block_time_secs",
                metric_value=last_block_time_secs,
                threshold=float(self.BLOCK_TIME_MAX_SECS),
                remediation="Monitor CPU, disk, network for bottlenecks",
                timestamp=now,
            ))

        return violations
