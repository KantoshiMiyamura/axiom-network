# -*- coding: utf-8 -*-
"""
RiskScoring — Composite risk assessment for AxiomMind

Combines rule violations, anomalies, and correlations into
a single risk score (0.0-1.0) with prioritized recommendations.

No external dependencies. Deterministic. Fast.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List

from axiom_mind.anomaly_engine import Anomaly
from axiom_mind.rule_engine import RuleViolation
from axiom_mind.correlation_engine import Correlation


@dataclass
class SystemRiskScore:
    """Composite risk assessment."""
    overall_risk: float         # 0.0 (safe) to 1.0 (critical)
    rule_risk: float            # 0.0-1.0 risk from rule violations
    anomaly_risk: float         # 0.0-1.0 risk from anomalies
    correlation_risk: float     # 0.0-1.0 risk from correlations
    top_threats: List[str] = field(default_factory=list)  # Top 3 issues
    recommendations: List[str] = field(default_factory=list)  # Ranked actions
    ai_mode: str = "local_only"             # "local_only", "hybrid"
    local_confidence: float = 0.95           # 0.8-1.0
    timestamp: float = 0.0


class RiskScoring:
    """
    Calculate composite risk scores from multiple signal types.

    Weighting:
    - Critical rule violations: 50 points each
    - Critical anomalies: 30 points each
    - Warning violations/anomalies: 10 points each
    - Info violations/anomalies: 3 points each
    - High-confidence correlations: 20 points each

    Max points: 100 (normalized to 0.0-1.0)
    """

    MAX_POINTS = 100.0

    def score(
        self,
        violations: List[RuleViolation],
        anomalies: List[Anomaly],
        correlations: List[Correlation],
        ai_mode: str = "local_only",
    ) -> SystemRiskScore:
        """
        Calculate composite risk score and recommendations.

        Returns SystemRiskScore with overall_risk (0.0-1.0) and
        ranked recommendations.
        """
        now = datetime.now(timezone.utc).timestamp()

        # Score each component
        rule_risk, rule_points = self._score_violations(violations)
        anomaly_risk, anomaly_points = self._score_anomalies(anomalies)
        correlation_risk, correlation_points = self._score_correlations(correlations)

        # Weighted total
        total_points = (rule_points + anomaly_points + correlation_points)
        overall_risk = min(1.0, total_points / self.MAX_POINTS)

        # Top threats (across all sources)
        threats = self._identify_top_threats(violations, anomalies, correlations)

        # Recommendations (ranked by priority)
        recommendations = self._generate_recommendations(
            violations, anomalies, correlations
        )

        return SystemRiskScore(
            overall_risk=overall_risk,
            rule_risk=rule_risk,
            anomaly_risk=anomaly_risk,
            correlation_risk=correlation_risk,
            top_threats=threats[:3],  # Top 3
            recommendations=recommendations[:5],  # Top 5 recommendations
            ai_mode=ai_mode,
            local_confidence=0.95,  # Local analysis is highly reliable
            timestamp=now,
        )

    def _score_violations(self, violations: List[RuleViolation]) -> tuple:
        """
        Score rule violations.

        Returns (risk_score, points)
        """
        if not violations:
            return 0.0, 0.0

        points = 0.0
        for v in violations:
            if v.severity == "critical":
                points += 50.0
            elif v.severity == "warning":
                points += 10.0
            elif v.severity == "info":
                points += 3.0

        risk = min(1.0, points / 100.0)
        return risk, points

    def _score_anomalies(self, anomalies: List[Anomaly]) -> tuple:
        """
        Score detected anomalies.

        Returns (risk_score, points)
        """
        if not anomalies:
            return 0.0, 0.0

        points = 0.0
        for a in anomalies:
            if a.severity == "critical":
                points += 30.0
            elif a.severity == "warning":
                points += 10.0
            elif a.severity == "info":
                points += 3.0

        risk = min(1.0, points / 100.0)
        return risk, points

    def _score_correlations(self, correlations: List[Correlation]) -> tuple:
        """
        Score detected correlations/patterns.

        Returns (risk_score, points)
        """
        if not correlations:
            return 0.0, 0.0

        points = 0.0
        for c in correlations:
            # Points based on confidence and severity
            confidence_boost = c.confidence  # 0.8-1.0
            if c.severity == "critical":
                points += 25.0 * confidence_boost
            elif c.severity == "warning":
                points += 15.0 * confidence_boost
            else:
                points += 5.0 * confidence_boost

        risk = min(1.0, points / 100.0)
        return risk, points

    def _identify_top_threats(
        self,
        violations: List[RuleViolation],
        anomalies: List[Anomaly],
        correlations: List[Correlation],
    ) -> List[str]:
        """
        Identify top threats across all sources.

        Returns list of threat descriptions, ranked by severity.
        """
        threats: List[tuple] = []  # (severity_order, description)

        # Add violations as threats
        for v in violations:
            severity_order = {"critical": 0, "warning": 1, "info": 2}.get(v.severity, 3)
            threats.append((severity_order, f"{v.rule_name}: {v.description}"))

        # Add critical anomalies as threats
        for a in anomalies:
            if a.severity in ["critical", "warning"]:
                severity_order = {"critical": 0, "warning": 1}.get(a.severity, 2)
                threats.append((severity_order, f"{a.metric}: {a.description}"))

        # Add correlations as threats
        for c in correlations:
            severity_order = {"critical": 0, "warning": 1, "info": 2}.get(c.severity, 3)
            threats.append((severity_order, f"{c.pattern_name}: {c.description}"))

        # Sort by severity, return descriptions only
        threats.sort(key=lambda x: x[0])
        return [desc for _, desc in threats]

    def _generate_recommendations(
        self,
        violations: List[RuleViolation],
        anomalies: List[Anomaly],
        correlations: List[Correlation],
    ) -> List[str]:
        """
        Generate ranked recommendations for remediation.

        Returns list of recommended actions, highest priority first.
        """
        recommendations: List[tuple] = []  # (priority_order, action)

        # Recommendations from violations (highest priority)
        for v in violations:
            if v.severity == "critical":
                # Critical violations get priority 0
                recommendations.append((0, v.remediation))
            elif v.severity == "warning":
                # Warning violations get priority 1
                recommendations.append((1, v.remediation))

        # Recommendations from correlations (high priority if critical)
        for c in correlations:
            if c.severity == "critical":
                recommendations.append((0.5, c.recommended_action))
            elif c.severity == "warning":
                recommendations.append((1.5, c.recommended_action))

        # Recommendations from anomalies (lower priority, supplementary)
        for a in anomalies:
            if a.severity == "critical":
                # Suggest monitoring anomalous metric
                recommendations.append((2, f"Monitor {a.metric} closely"))

        # Remove duplicates, preserving order
        seen = set()
        deduped = []
        for priority, rec in sorted(recommendations, key=lambda x: x[0]):
            if rec not in seen:
                seen.add(rec)
                deduped.append(rec)

        return deduped

    def get_risk_level_name(self, risk_score: float) -> str:
        """
        Get human-readable risk level.

        risk_score: 0.0-1.0
        """
        if risk_score < 0.2:
            return "SAFE"
        elif risk_score < 0.4:
            return "LOW"
        elif risk_score < 0.6:
            return "MODERATE"
        elif risk_score < 0.8:
            return "HIGH"
        else:
            return "CRITICAL"
