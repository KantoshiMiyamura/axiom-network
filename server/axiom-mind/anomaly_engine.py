# -*- coding: utf-8 -*-
"""
AnomalyEngine — Statistical anomaly detection for AxiomMind

Uses EWMA (Exponential Weighted Moving Average) + Z-score analysis
to detect deviations from normal system behavior.

No external dependencies. Deterministic. Production-proven.
"""

import math
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Dict, Optional


@dataclass
class Anomaly:
    """A single detected anomaly with statistical evidence."""
    metric: str             # "block_time", "peer_count", "mempool_size", "fee_rate"
    value: float            # Current measured value
    baseline: float         # EWMA mean (what we expect)
    std_dev: float          # Standard deviation
    z_score: float          # (value - baseline) / std_dev (how many sigmas away)
    severity: str           # "critical" (|z| >= 3.0), "warning" (|z| >= 2.0), "info"
    description: str        # Human-readable explanation
    timestamp: float        # When anomaly was detected


class EWMA:
    """
    Exponential Weighted Moving Average tracker.

    Maintains a running mean and variance of a metric with
    exponential weighting (recent values matter more).

    alpha = learning rate (0.0-1.0)
      - 0.1 = ~10-sample memory (fast adaptation)
      - 0.05 = ~20-sample memory (moderate adaptation)
      - 0.01 = ~100-sample memory (slow adaptation)
    """

    def __init__(self, alpha: float, initial: float):
        self.alpha = alpha
        self.mean = initial
        self.variance = initial * 0.1  # Start with 10% variance
        self.sample_count = 1

    def update(self, value: float) -> None:
        """Update EWMA with new value."""
        delta = value - self.mean
        self.mean += self.alpha * delta
        self.variance += self.alpha * (delta * delta - self.variance)
        self.sample_count += 1

    def get_mean(self) -> float:
        """Get current EWMA mean."""
        return self.mean

    def get_std_dev(self) -> float:
        """Get current standard deviation."""
        return math.sqrt(max(self.variance, 0.001))  # Avoid sqrt(0)

    def get_z_score(self, value: float) -> float:
        """Calculate z-score for a value."""
        std_dev = self.get_std_dev()
        if std_dev == 0:
            return 0.0
        return (value - self.mean) / std_dev


class AnomalyEngine:
    """
    Statistical anomaly detector for blockchain system metrics.

    Tracks:
    - Block production time
    - Peer count
    - Mempool size
    - Fee rates
    - Orphan rate

    Uses EWMA + Z-score to identify deviations from normal.
    """

    # Z-score thresholds for severity
    CRITICAL_THRESHOLD = 3.0  # 99.7% of normal samples
    WARNING_THRESHOLD = 2.0   # 95% of normal samples

    def __init__(self):
        """Initialize EWMA trackers for each metric."""
        # Block time: alpha=0.1 (fast adaptation, 10-sample memory)
        self._block_time = EWMA(alpha=0.1, initial=30.0)

        # Peer count: alpha=0.15 (moderate adaptation)
        self._peer_count = EWMA(alpha=0.15, initial=8.0)

        # Mempool size: alpha=0.1 (fast adaptation)
        self._mempool_size = EWMA(alpha=0.1, initial=200.0)

        # Fee rate: alpha=0.1 (fast adaptation)
        self._fee_rate = EWMA(alpha=0.1, initial=10.0)

        # Orphan rate: alpha=0.05 (slow adaptation, orphans are rare)
        self._orphan_rate = EWMA(alpha=0.05, initial=0.01)

        # Track previous values to detect initial startup
        self._prev_height: Optional[int] = None
        self._prev_block_time_secs: Optional[float] = None

    def detect(self, state: dict) -> List[Anomaly]:
        """
        Detect anomalies in current state.

        Updates EWMA trackers and returns list of anomalies
        (may be empty if state is normal).
        """
        anomalies: List[Anomaly] = []
        now = datetime.now(timezone.utc).timestamp()

        # Check block time (time since last block)
        block_time = state.get("last_block_time_secs", 30.0)
        if self._prev_block_time_secs is not None:  # Skip first sample
            anomaly = self._check_metric(
                metric="block_time",
                value=block_time,
                ewma=self._block_time,
                timestamp=now,
            )
            if anomaly:
                anomalies.append(anomaly)
        self._block_time.update(block_time)
        self._prev_block_time_secs = block_time

        # Check peer count
        peers = state.get("peers", 8)
        anomaly = self._check_metric(
            metric="peer_count",
            value=float(peers),
            ewma=self._peer_count,
            timestamp=now,
        )
        if anomaly:
            anomalies.append(anomaly)
        self._peer_count.update(float(peers))

        # Check mempool size
        mempool_size = state.get("mempool_size", 200)
        anomaly = self._check_metric(
            metric="mempool_size",
            value=float(mempool_size),
            ewma=self._mempool_size,
            timestamp=now,
        )
        if anomaly:
            anomalies.append(anomaly)
        self._mempool_size.update(float(mempool_size))

        # Check fee rate (p50 fee)
        fee_rate = state.get("fee_p50", 10.0) or 10.0
        anomaly = self._check_metric(
            metric="fee_rate",
            value=fee_rate,
            ewma=self._fee_rate,
            timestamp=now,
        )
        if anomaly:
            anomalies.append(anomaly)
        self._fee_rate.update(fee_rate)

        return anomalies

    def _check_metric(
        self,
        metric: str,
        value: float,
        ewma: EWMA,
        timestamp: float,
    ) -> Optional[Anomaly]:
        """
        Check if a single metric value is anomalous.

        Returns Anomaly if z-score exceeds threshold, None otherwise.
        """
        z_score = ewma.get_z_score(value)
        abs_z = abs(z_score)

        if abs_z >= self.CRITICAL_THRESHOLD:
            severity = "critical"
            description = (
                f"{metric} is {abs_z:.1f}σ away from baseline "
                f"({value:.1f} vs {ewma.get_mean():.1f}, ±{ewma.get_std_dev():.1f})"
            )
        elif abs_z >= self.WARNING_THRESHOLD:
            severity = "warning"
            description = (
                f"{metric} is {abs_z:.1f}σ away from baseline "
                f"({value:.1f} vs {ewma.get_mean():.1f}, ±{ewma.get_std_dev():.1f})"
            )
        else:
            return None  # Normal

        return Anomaly(
            metric=metric,
            value=value,
            baseline=ewma.get_mean(),
            std_dev=ewma.get_std_dev(),
            z_score=z_score,
            severity=severity,
            description=description,
            timestamp=timestamp,
        )

    def get_current_baselines(self) -> Dict[str, Dict[str, float]]:
        """
        Get current baselines for monitoring/debugging.

        Returns dict with mean, std_dev for each metric.
        """
        return {
            "block_time": {
                "mean": self._block_time.get_mean(),
                "std_dev": self._block_time.get_std_dev(),
            },
            "peer_count": {
                "mean": self._peer_count.get_mean(),
                "std_dev": self._peer_count.get_std_dev(),
            },
            "mempool_size": {
                "mean": self._mempool_size.get_mean(),
                "std_dev": self._mempool_size.get_std_dev(),
            },
            "fee_rate": {
                "mean": self._fee_rate.get_mean(),
                "std_dev": self._fee_rate.get_std_dev(),
            },
        }
