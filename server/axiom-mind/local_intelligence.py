# -*- coding: utf-8 -*-
"""
LocalIntelligence — Coordinator for all local intelligence modules

Combines:
- RuleEngine (deterministic rules)
- AnomalyEngine (statistical detection)
- CorrelationEngine (pattern matching)
- RiskScoring (composite assessment)

This is the PRIMARY source of all system insights.
Used by SafeSelfHealer to make healing decisions.
Completely offline, no external dependencies.
"""

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List

from axiom_mind.rule_engine import RuleEngine, RuleViolation
from axiom_mind.anomaly_engine import AnomalyEngine, Anomaly
from axiom_mind.correlation_engine import CorrelationEngine, Correlation
from axiom_mind.risk_scoring import RiskScoring, SystemRiskScore


@dataclass
class AnalysisResult:
    """Result of local intelligence analysis."""
    rule_violations: List[RuleViolation] = field(default_factory=list)
    anomalies: List[Anomaly] = field(default_factory=list)
    correlations: List[Correlation] = field(default_factory=list)
    risk_score: SystemRiskScore = field(default_factory=SystemRiskScore)
    analysis_timestamp: float = 0.0
    analysis_ms: float = 0.0  # How long analysis took
    ai_mode: str = "local_only"


class LocalIntelligence:
    """
    Local intelligence coordinator.

    Runs all offline modules and produces a unified analysis result.
    Used by:
    - SafeSelfHealer (for healing decisions)
    - Dashboard (for display)
    - Logs (for audit trail)

    Zero external dependencies.
    Latency: <50ms typical (completely local, no I/O)
    """

    def __init__(self, ai_mode: str = "local_only"):
        """Initialize all local intelligence modules."""
        self.ai_mode = ai_mode
        self.rule_engine = RuleEngine()
        self.anomaly_engine = AnomalyEngine()
        self.correlation_engine = CorrelationEngine()
        self.risk_scoring = RiskScoring()

    async def analyze(self, state: dict) -> AnalysisResult:
        """
        Run complete local intelligence analysis.

        Process:
        1. Rule violations (deterministic checks)
        2. Anomaly detection (statistical analysis)
        3. Correlation analysis (pattern matching)
        4. Risk scoring (composite assessment)

        Returns AnalysisResult with all insights.
        Latency: <50ms, completely local.
        """
        start_ms = time.time() * 1000.0
        now = datetime.now(timezone.utc).timestamp()

        # Step 1: Check hardcoded rules
        violations = self.rule_engine.check_rules(state)

        # Step 2: Detect anomalies (updates EWMA baselines)
        anomalies = self.anomaly_engine.detect(state)

        # Step 3: Find correlations across signals
        correlations = self.correlation_engine.correlate(state, violations, anomalies)

        # Step 4: Calculate composite risk score
        risk_score = self.risk_scoring.score(
            violations=violations,
            anomalies=anomalies,
            correlations=correlations,
            ai_mode=self.ai_mode,
        )

        # Calculate analysis latency
        end_ms = time.time() * 1000.0
        analysis_ms = end_ms - start_ms

        return AnalysisResult(
            rule_violations=violations,
            anomalies=anomalies,
            correlations=correlations,
            risk_score=risk_score,
            analysis_timestamp=now,
            analysis_ms=analysis_ms,
            ai_mode=self.ai_mode,
        )

    def get_summary(self, result: AnalysisResult) -> dict:
        """
        Get human-readable summary of analysis result.

        Used for dashboard, logs, and CLI output.
        """
        return {
            "ai_mode": self.ai_mode,
            "analysis_ms": result.analysis_ms,
            "risk_level": self.risk_scoring.get_risk_level_name(result.risk_score.overall_risk),
            "overall_risk": round(result.risk_score.overall_risk, 2),
            "rule_risk": round(result.risk_score.rule_risk, 2),
            "anomaly_risk": round(result.risk_score.anomaly_risk, 2),
            "correlation_risk": round(result.risk_score.correlation_risk, 2),
            "violations_count": len(result.rule_violations),
            "critical_violations": len([v for v in result.rule_violations if v.severity == "critical"]),
            "anomalies_count": len(result.anomalies),
            "critical_anomalies": len([a for a in result.anomalies if a.severity == "critical"]),
            "correlations_count": len(result.correlations),
            "critical_correlations": len([c for c in result.correlations if c.severity == "critical"]),
            "top_threats": result.risk_score.top_threats,
            "recommendations": result.risk_score.recommendations,
            "local_confidence": result.risk_score.local_confidence,
        }

    def get_details(self, result: AnalysisResult) -> dict:
        """
        Get detailed analysis results for API and dashboard.

        Includes all violations, anomalies, correlations.
        """
        return {
            "ai_mode": self.ai_mode,
            "analysis_ms": result.analysis_ms,
            "timestamp": result.analysis_timestamp,
            "risk_score": {
                "overall": result.risk_score.overall_risk,
                "from_rules": result.risk_score.rule_risk,
                "from_anomalies": result.risk_score.anomaly_risk,
                "from_correlations": result.risk_score.correlation_risk,
                "local_confidence": result.risk_score.local_confidence,
            },
            "rule_violations": [
                {
                    "rule": v.rule_name,
                    "severity": v.severity,
                    "description": v.description,
                    "metric": v.metric_name,
                    "value": v.metric_value,
                    "threshold": v.threshold,
                    "remediation": v.remediation,
                }
                for v in result.rule_violations
            ],
            "anomalies": [
                {
                    "metric": a.metric,
                    "value": a.value,
                    "baseline": a.baseline,
                    "z_score": round(a.z_score, 2),
                    "severity": a.severity,
                    "description": a.description,
                }
                for a in result.anomalies
            ],
            "correlations": [
                {
                    "pattern": c.pattern_name,
                    "confidence": round(c.confidence, 2),
                    "contributing_metrics": c.contributing_metrics,
                    "contributing_rules": c.contributing_rules,
                    "severity": c.severity,
                    "description": c.description,
                    "recommended_action": c.recommended_action,
                }
                for c in result.correlations
            ],
            "anomaly_baselines": self.anomaly_engine.get_current_baselines(),
            "top_threats": result.risk_score.top_threats,
            "recommendations": result.risk_score.recommendations,
        }
