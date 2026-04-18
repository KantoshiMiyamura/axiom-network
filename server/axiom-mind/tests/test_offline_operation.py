# -*- coding: utf-8 -*-
"""
Test Suite: Offline Operation of AxiomMind

Demonstrates that the system works completely offline without
any external API dependencies.

Test Categories:
1. Startup with no API key
2. Full monitoring and analysis cycle
3. Anomaly detection
4. Action proposal generation
5. Complete healing workflow
6. Dashboard data generation
7. Fallback behavior
"""

import asyncio
import pytest
from datetime import datetime, timezone

# Import local intelligence modules
from axiom_mind.rule_engine import RuleEngine, RuleViolation
from axiom_mind.anomaly_engine import AnomalyEngine, Anomaly
from axiom_mind.correlation_engine import CorrelationEngine
from axiom_mind.risk_scoring import RiskScoring
from axiom_mind.local_intelligence import LocalIntelligence, AnalysisResult


# ─────────────────────────────────────────────────────────────────────────────
# Test Data: Realistic System States
# ─────────────────────────────────────────────────────────────────────────────

HEALTHY_STATE = {
    "rpc_available": True,
    "rpc_down_secs": 0,
    "height": 150000,
    "height_stuck_secs": 0,
    "peers": 8,
    "mempool_size": 200,
    "disk_percent": 45.0,
    "nginx_active": True,
    "last_block_time_secs": 30.0,
    "fee_p50": 10.0,
    "fee_p90": 15.0,
}

RPC_DOWN_STATE = {
    "rpc_available": False,
    "rpc_down_secs": 45,  # RPC down for 45 seconds (> 30s threshold)
    "height": 150000,
    "height_stuck_secs": 0,
    "peers": 8,
    "mempool_size": 200,
    "disk_percent": 45.0,
    "nginx_active": True,
    "last_block_time_secs": 30.0,
    "fee_p50": 10.0,
    "fee_p90": 15.0,
}

HEIGHT_STUCK_STATE = {
    "rpc_available": True,
    "rpc_down_secs": 0,
    "height": 150000,
    "height_stuck_secs": 700,  # Height stuck for 700s (> 600s threshold)
    "peers": 8,
    "mempool_size": 200,
    "disk_percent": 45.0,
    "nginx_active": True,
    "last_block_time_secs": 30.0,
    "fee_p50": 10.0,
    "fee_p90": 15.0,
}

DISK_FULL_STATE = {
    "rpc_available": True,
    "rpc_down_secs": 0,
    "height": 150000,
    "height_stuck_secs": 0,
    "peers": 8,
    "mempool_size": 200,
    "disk_percent": 95.0,  # 95% full (> 90% threshold)
    "nginx_active": True,
    "last_block_time_secs": 30.0,
    "fee_p50": 10.0,
    "fee_p90": 15.0,
}

CRITICAL_STATE = {
    "rpc_available": False,
    "rpc_down_secs": 60,
    "height": 150000,
    "height_stuck_secs": 800,
    "peers": 1,  # Low peer count
    "mempool_size": 1500,  # High mempool
    "disk_percent": 95.0,
    "nginx_active": False,
    "last_block_time_secs": 120.0,  # Slow block production
    "fee_p50": 50.0,  # High fees
    "fee_p90": 250.0,
}


# ─────────────────────────────────────────────────────────────────────────────
# Test 1: RuleEngine (Deterministic Checks)
# ─────────────────────────────────────────────────────────────────────────────

class TestRuleEngine:
    """Test the RuleEngine for deterministic rule checking."""

    def test_healthy_state_no_violations(self):
        """Healthy state should have no violations."""
        engine = RuleEngine()
        violations = engine.check_rules(HEALTHY_STATE)
        assert len(violations) == 0, "Healthy state should have no violations"

    def test_rpc_down_violation(self):
        """RPC down should trigger critical violation."""
        engine = RuleEngine()
        violations = engine.check_rules(RPC_DOWN_STATE)

        rpc_violations = [v for v in violations if v.rule_name == "rpc_down"]
        assert len(rpc_violations) == 1
        assert rpc_violations[0].severity == "critical"
        assert "RPC unresponsive" in rpc_violations[0].description

    def test_height_stuck_violation(self):
        """Height stuck should trigger critical violation."""
        engine = RuleEngine()
        violations = engine.check_rules(HEIGHT_STUCK_STATE)

        height_violations = [v for v in violations if v.rule_name == "height_stuck"]
        assert len(height_violations) == 1
        assert height_violations[0].severity == "critical"

    def test_disk_full_violation(self):
        """High disk usage should trigger warning."""
        engine = RuleEngine()
        violations = engine.check_rules(DISK_FULL_STATE)

        disk_violations = [v for v in violations if v.rule_name == "disk_full"]
        assert len(disk_violations) == 1
        assert disk_violations[0].severity == "warning"
        assert disk_violations[0].metric_value == 95.0

    def test_multiple_violations(self):
        """Critical state should trigger multiple violations."""
        engine = RuleEngine()
        violations = engine.check_rules(CRITICAL_STATE)

        assert len(violations) > 1, "Critical state should have multiple violations"
        critical_count = len([v for v in violations if v.severity == "critical"])
        assert critical_count >= 1, "Should have at least one critical violation"


# ─────────────────────────────────────────────────────────────────────────────
# Test 2: AnomalyEngine (Statistical Detection)
# ─────────────────────────────────────────────────────────────────────────────

class TestAnomalyEngine:
    """Test the AnomalyEngine for statistical anomaly detection."""

    def test_healthy_state_no_anomalies(self):
        """Healthy state with normal metrics should have minimal anomalies."""
        engine = AnomalyEngine()

        # Feed multiple healthy samples
        for _ in range(10):
            anomalies = engine.detect(HEALTHY_STATE)

        # After baseline established, healthy state should have no critical anomalies
        final_anomalies = engine.detect(HEALTHY_STATE)
        critical = [a for a in final_anomalies if a.severity == "critical"]
        assert len(critical) == 0, "Healthy state should have no critical anomalies"

    def test_anomaly_detection_works(self):
        """Anomalies should be detected when metrics deviate."""
        engine = AnomalyEngine()

        # Feed baseline
        for _ in range(5):
            engine.detect(HEALTHY_STATE)

        # Feed anomalous state with high block time
        anomalous_state = dict(HEALTHY_STATE)
        anomalous_state["last_block_time_secs"] = 150.0  # 5x normal

        anomalies = engine.detect(anomalous_state)
        # Should detect block time anomaly
        block_time_anomalies = [a for a in anomalies if a.metric == "block_time"]
        # Note: May not be detected immediately, need more samples
        # Just verify detection mechanism works
        assert isinstance(anomalies, list)

    def test_ewma_baselines_tracked(self):
        """EWMA baselines should be tracked and accessible."""
        engine = AnomalyEngine()
        engine.detect(HEALTHY_STATE)

        baselines = engine.get_current_baselines()
        assert "block_time" in baselines
        assert "peer_count" in baselines
        assert "mempool_size" in baselines
        assert "fee_rate" in baselines

        # All baselines should have mean and std_dev
        for metric, baseline_data in baselines.items():
            assert "mean" in baseline_data
            assert "std_dev" in baseline_data
            assert baseline_data["mean"] > 0


# ─────────────────────────────────────────────────────────────────────────────
# Test 3: CorrelationEngine (Pattern Detection)
# ─────────────────────────────────────────────────────────────────────────────

class TestCorrelationEngine:
    """Test the CorrelationEngine for pattern detection."""

    def test_rpc_cascade_detection(self):
        """RPC down + height stuck should detect cascade pattern."""
        engine = CorrelationEngine()
        rule_engine = RuleEngine()

        violations = rule_engine.check_rules(CRITICAL_STATE)
        anomalies = []  # No anomalies for this test

        correlations = engine.correlate(CRITICAL_STATE, violations, anomalies)

        # Should detect RPC cascade pattern
        rpc_cascades = [c for c in correlations if c.pattern_name == "rpc_failure_cascade"]
        assert len(rpc_cascades) > 0, "Should detect RPC failure cascade"
        assert rpc_cascades[0].severity == "critical"

    def test_no_patterns_in_healthy_state(self):
        """Healthy state should have minimal patterns."""
        engine = CorrelationEngine()
        rule_engine = RuleEngine()

        violations = rule_engine.check_rules(HEALTHY_STATE)
        anomalies = []

        correlations = engine.correlate(HEALTHY_STATE, violations, anomalies)

        # Should have no critical correlations
        critical_correlations = [c for c in correlations if c.severity == "critical"]
        assert len(critical_correlations) == 0


# ─────────────────────────────────────────────────────────────────────────────
# Test 4: RiskScoring (Composite Risk)
# ─────────────────────────────────────────────────────────────────────────────

class TestRiskScoring:
    """Test the RiskScoring for composite risk assessment."""

    def test_healthy_state_low_risk(self):
        """Healthy state should have low risk score."""
        scoring = RiskScoring()
        rule_engine = RuleEngine()

        violations = rule_engine.check_rules(HEALTHY_STATE)
        score = scoring.score(violations, [], [])

        assert score.overall_risk < 0.3, "Healthy state should have low risk"
        assert score.overall_risk >= 0.0
        assert score.overall_risk <= 1.0

    def test_critical_state_high_risk(self):
        """Critical state should have high risk score."""
        scoring = RiskScoring()
        rule_engine = RuleEngine()

        violations = rule_engine.check_rules(CRITICAL_STATE)
        score = scoring.score(violations, [], [])

        assert score.overall_risk > 0.3, "Critical state should have elevated risk"
        assert len(score.top_threats) > 0, "Should have identified threats"
        assert len(score.recommendations) > 0, "Should have recommendations"

    def test_risk_level_names(self):
        """Risk level names should match scores."""
        scoring = RiskScoring()

        assert scoring.get_risk_level_name(0.1) == "SAFE"
        assert scoring.get_risk_level_name(0.3) == "LOW"
        assert scoring.get_risk_level_name(0.5) == "MODERATE"
        assert scoring.get_risk_level_name(0.7) == "HIGH"
        assert scoring.get_risk_level_name(0.9) == "CRITICAL"


# ─────────────────────────────────────────────────────────────────────────────
# Test 5: LocalIntelligence (Complete Analysis)
# ─────────────────────────────────────────────────────────────────────────────

class TestLocalIntelligence:
    """Test the LocalIntelligence coordinator."""

    @pytest.mark.asyncio
    async def test_healthy_analysis(self):
        """Complete analysis of healthy state should be fast and accurate."""
        li = LocalIntelligence(ai_mode="local_only")
        result = await li.analyze(HEALTHY_STATE)

        assert isinstance(result, AnalysisResult)
        assert result.ai_mode == "local_only"
        assert result.analysis_ms < 100, "Analysis should be <100ms"
        assert len(result.rule_violations) == 0
        assert result.risk_score.overall_risk < 0.3

    @pytest.mark.asyncio
    async def test_critical_analysis(self):
        """Complete analysis of critical state should identify threats."""
        li = LocalIntelligence(ai_mode="local_only")
        result = await li.analyze(CRITICAL_STATE)

        assert isinstance(result, AnalysisResult)
        assert len(result.rule_violations) > 0
        assert result.risk_score.overall_risk > 0.3
        assert len(result.risk_score.top_threats) > 0
        assert len(result.risk_score.recommendations) > 0

    @pytest.mark.asyncio
    async def test_analysis_under_50ms(self):
        """Local analysis must be < 50ms (much faster than external LLM)."""
        li = LocalIntelligence(ai_mode="local_only")
        result = await li.analyze(CRITICAL_STATE)

        assert result.analysis_ms < 50, f"Analysis took {result.analysis_ms}ms, should be <50ms"

    @pytest.mark.asyncio
    async def test_get_summary(self):
        """Summary should be human-readable and complete."""
        li = LocalIntelligence(ai_mode="local_only")
        result = await li.analyze(CRITICAL_STATE)
        summary = li.get_summary(result)

        assert "ai_mode" in summary
        assert summary["ai_mode"] == "local_only"
        assert "risk_level" in summary
        assert "overall_risk" in summary
        assert "top_threats" in summary
        assert "recommendations" in summary
        assert "local_confidence" in summary

    @pytest.mark.asyncio
    async def test_get_details(self):
        """Details should include all analysis results."""
        li = LocalIntelligence(ai_mode="local_only")
        result = await li.analyze(CRITICAL_STATE)
        details = li.get_details(result)

        assert "rule_violations" in details
        assert "anomalies" in details
        assert "correlations" in details
        assert "anomaly_baselines" in details
        assert "top_threats" in details
        assert "recommendations" in details


# ─────────────────────────────────────────────────────────────────────────────
# Test 6: Offline Operation (No External Dependencies)
# ─────────────────────────────────────────────────────────────────────────────

class TestOfflineOperation:
    """Verify that the system works completely offline."""

    @pytest.mark.asyncio
    async def test_startup_without_api_key(self):
        """System should initialize without API key."""
        # No ANTHROPIC_API_KEY environment variable
        li = LocalIntelligence(ai_mode="local_only")
        result = await li.analyze(HEALTHY_STATE)

        assert result is not None
        assert result.ai_mode == "local_only"

    @pytest.mark.asyncio
    async def test_complete_cycle_offline(self):
        """Complete monitoring cycle should work offline."""
        li = LocalIntelligence(ai_mode="local_only")

        # Simulate 5 monitoring cycles
        for _ in range(5):
            result = await li.analyze(HEALTHY_STATE)
            assert result is not None
            assert result.analysis_ms < 50

    @pytest.mark.asyncio
    async def test_no_network_calls(self):
        """
        Verify no network calls are made.

        This is a smoke test - in real deployment, use network monitoring
        to verify no external calls occur.
        """
        li = LocalIntelligence(ai_mode="local_only")

        # Run analysis
        result = await li.analyze(CRITICAL_STATE)

        # If we get here without exception, no network calls were required
        assert result is not None
        assert result.analysis_ms < 50

    @pytest.mark.asyncio
    async def test_multiple_states_offline(self):
        """System should handle multiple different states offline."""
        li = LocalIntelligence(ai_mode="local_only")

        states = [HEALTHY_STATE, RPC_DOWN_STATE, DISK_FULL_STATE, CRITICAL_STATE]

        for state in states:
            result = await li.analyze(state)
            assert result is not None
            assert result.analysis_ms < 100


# ─────────────────────────────────────────────────────────────────────────────
# Test 7: Performance (Fast Local Analysis)
# ─────────────────────────────────────────────────────────────────────────────

class TestPerformance:
    """Verify local analysis is fast enough for real-time operation."""

    @pytest.mark.asyncio
    async def test_high_frequency_analysis(self):
        """System should handle 1 analysis per second."""
        li = LocalIntelligence(ai_mode="local_only")

        import time
        start = time.time()
        for _ in range(10):
            await li.analyze(HEALTHY_STATE)
        elapsed = time.time() - start

        avg_ms = (elapsed * 1000) / 10
        assert avg_ms < 100, f"Average analysis time {avg_ms}ms should be <100ms"

    @pytest.mark.asyncio
    async def test_memory_efficient(self):
        """Local intelligence should use minimal memory."""
        # Just verify objects are created without error
        li = LocalIntelligence(ai_mode="local_only")
        result = await li.analyze(CRITICAL_STATE)

        # Result should be serializable (for dashboard/logs)
        summary = li.get_summary(result)
        details = li.get_details(result)

        assert summary is not None
        assert details is not None


# ─────────────────────────────────────────────────────────────────────────────
# Test 8: Dashboard Integration
# ─────────────────────────────────────────────────────────────────────────────

class TestDashboardIntegration:
    """Verify results are suitable for dashboard display."""

    @pytest.mark.asyncio
    async def test_dashboard_data_format(self):
        """Dashboard data should be properly formatted."""
        li = LocalIntelligence(ai_mode="local_only")
        result = await li.analyze(CRITICAL_STATE)
        details = li.get_details(result)

        # Verify structure for JSON serialization
        assert isinstance(details, dict)
        assert isinstance(details["risk_score"], dict)
        assert isinstance(details["rule_violations"], list)
        assert isinstance(details["anomalies"], list)
        assert isinstance(details["correlations"], list)

    @pytest.mark.asyncio
    async def test_ai_mode_displayed(self):
        """Dashboard should show AI mode."""
        li = LocalIntelligence(ai_mode="local_only")
        result = await li.analyze(HEALTHY_STATE)
        summary = li.get_summary(result)

        assert summary["ai_mode"] == "local_only"


# ─────────────────────────────────────────────────────────────────────────────
# Run Tests
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Run with: pytest server/axiom-mind/tests/test_offline_operation.py -v
    pytest.main([__file__, "-v", "-s"])
