# -*- coding: utf-8 -*-
"""
CorrelationEngine — Multi-signal pattern detection for AxiomMind

Looks for patterns and correlations across multiple anomalies
to identify root causes and compound threats.

No external dependencies. Heuristic-based. Fast.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List

from axiom_mind.anomaly_engine import Anomaly
from axiom_mind.rule_engine import RuleViolation


@dataclass
class Correlation:
    """A detected pattern/correlation across multiple signals."""
    pattern_name: str           # "network_degradation", "fee_pressure", etc
    confidence: float           # 0.0-1.0 confidence in pattern
    contributing_metrics: List[str]  # Which metrics support this
    contributing_rules: List[str]    # Which rule violations support
    description: str            # Pattern description
    recommended_action: str     # Suggested remediation
    severity: str               # "critical", "warning", "info"
    timestamp: float            # When pattern was detected


class CorrelationEngine:
    """
    Detect multi-signal patterns and correlations.

    Patterns:
    1. Network Degradation: block_time UP + peer_count DOWN + mempool_size UP
    2. Fee Pressure: fee_rate UP + mempool_size UP
    3. Storage Bottleneck: disk_percent UP + mempool_size DOWN
    4. RPC Failure Cascade: rpc_down → height_stuck → block_time anomalies
    5. System Overload: all metrics anomalous simultaneously
    """

    def __init__(self):
        pass

    def correlate(
        self,
        state: dict,
        violations: List[RuleViolation],
        anomalies: List[Anomaly],
    ) -> List[Correlation]:
        """
        Detect patterns across violations and anomalies.

        Returns list of correlations (may be empty).
        """
        correlations: List[Correlation] = []
        now = datetime.now(timezone.utc).timestamp()

        # Extract which metrics and rules are problematic
        anomalous_metrics = {a.metric for a in anomalies}
        violation_rules = {v.rule_name for v in violations}

        # Pattern 1: Network Degradation
        if self._detect_network_degradation(anomalies, anomalous_metrics):
            correlations.append(Correlation(
                pattern_name="network_degradation",
                confidence=0.92,
                contributing_metrics=["block_time", "peer_count", "mempool_size"],
                contributing_rules=["insufficient_peers"],
                description=(
                    "Multiple network-related anomalies detected: "
                    "slow block production, fewer peers, growing mempool. "
                    "Indicates network congestion or partial isolation."
                ),
                recommended_action="Check network connectivity and peer connections",
                severity="warning",
                timestamp=now,
            ))

        # Pattern 2: Fee Pressure
        if self._detect_fee_pressure(anomalies, anomalous_metrics, state):
            correlations.append(Correlation(
                pattern_name="fee_pressure",
                confidence=0.88,
                contributing_metrics=["fee_rate", "mempool_size"],
                contributing_rules=["mempool_fee_pressure"],
                description=(
                    "Fee rate and mempool size both elevated. "
                    "Indicates sustained demand exceeding capacity."
                ),
                recommended_action="Monitor mempool, consider fee settings",
                severity="info",
                timestamp=now,
            ))

        # Pattern 3: Storage Bottleneck
        if self._detect_storage_bottleneck(state, violations, anomalies):
            correlations.append(Correlation(
                pattern_name="storage_bottleneck",
                confidence=0.85,
                contributing_metrics=["disk_percent"],
                contributing_rules=["disk_full"],
                description=(
                    "High disk usage while mempool shrinking. "
                    "Indicates disk I/O becoming a bottleneck."
                ),
                recommended_action="Clean up old logs and temporary files",
                severity="warning",
                timestamp=now,
            ))

        # Pattern 4: RPC Failure Cascade
        if self._detect_rpc_cascade(violations, anomalies):
            correlations.append(Correlation(
                pattern_name="rpc_failure_cascade",
                confidence=0.95,
                contributing_metrics=["block_time"],
                contributing_rules=["rpc_down", "height_stuck"],
                description=(
                    "RPC is down AND height is stuck. "
                    "RPC failure is preventing block production monitoring."
                ),
                recommended_action="Restart axiom-node to restore RPC and block production",
                severity="critical",
                timestamp=now,
            ))

        # Pattern 5: System Overload
        if self._detect_system_overload(violations, anomalies):
            correlations.append(Correlation(
                pattern_name="system_overload",
                confidence=0.90,
                contributing_metrics=list(anomalous_metrics),
                contributing_rules=list(violation_rules),
                description=(
                    "Multiple simultaneous anomalies and violations. "
                    "System is under severe stress or experiencing cascading failures."
                ),
                recommended_action="Perform comprehensive system health check and restart services as needed",
                severity="critical",
                timestamp=now,
            ))

        return correlations

    def _detect_network_degradation(
        self,
        anomalies: List[Anomaly],
        anomalous_metrics: set,
    ) -> bool:
        """
        Network Degradation Pattern:
        - block_time is HIGH (slow production)
        - peer_count is LOW (fewer connections)
        - mempool_size is HIGH (transactions backing up)
        """
        has_slow_blocks = any(a.metric == "block_time" and a.z_score > 1.5 for a in anomalies)
        has_few_peers = any(a.metric == "peer_count" and a.z_score < -1.5 for a in anomalies)
        has_mempool_growth = any(a.metric == "mempool_size" and a.z_score > 1.5 for a in anomalies)

        # Need at least 2 of 3 to be confident
        matches = sum([has_slow_blocks, has_few_peers, has_mempool_growth])
        return matches >= 2

    def _detect_fee_pressure(
        self,
        anomalies: List[Anomaly],
        anomalous_metrics: set,
        state: dict,
    ) -> bool:
        """
        Fee Pressure Pattern:
        - fee_rate is HIGH (expensive to transact)
        - mempool_size is HIGH (many pending transactions)
        """
        has_high_fees = any(a.metric == "fee_rate" and a.z_score > 1.5 for a in anomalies)
        has_mempool_growth = any(a.metric == "mempool_size" and a.z_score > 1.5 for a in anomalies)

        # Both needed for fee pressure pattern
        return has_high_fees and has_mempool_growth

    def _detect_storage_bottleneck(
        self,
        state: dict,
        violations: List[RuleViolation],
        anomalies: List[Anomaly],
    ) -> bool:
        """
        Storage Bottleneck Pattern:
        - disk_percent is HIGH (running out of space)
        - mempool_size is LOW (transaction processing slowing down)
        """
        has_full_disk = any(v.rule_name == "disk_full" for v in violations)
        has_slow_mempool = any(
            a.metric == "mempool_size" and a.z_score < -1.5 for a in anomalies
        )

        # Both needed to be confident
        return has_full_disk and has_slow_mempool

    def _detect_rpc_cascade(
        self,
        violations: List[RuleViolation],
        anomalies: List[Anomaly],
    ) -> bool:
        """
        RPC Failure Cascade Pattern:
        - rpc_down (direct failure)
        - height_stuck (consequence of RPC being down)
        """
        has_rpc_down = any(v.rule_name == "rpc_down" for v in violations)
        has_height_stuck = any(v.rule_name == "height_stuck" for v in violations)

        # Both needed for cascade
        return has_rpc_down and has_height_stuck

    def _detect_system_overload(
        self,
        violations: List[RuleViolation],
        anomalies: List[Anomaly],
    ) -> bool:
        """
        System Overload Pattern:
        - 3+ critical violations, OR
        - 3+ critical/warning anomalies, OR
        - Multiple different types of issues
        """
        critical_violations = [v for v in violations if v.severity == "critical"]
        critical_anomalies = [a for a in anomalies if a.severity == "critical"]
        warning_anomalies = [a for a in anomalies if a.severity == "warning"]

        # Overload = many simultaneous issues
        total_issues = len(critical_violations) + len(critical_anomalies) + len(warning_anomalies)
        return total_issues >= 3
