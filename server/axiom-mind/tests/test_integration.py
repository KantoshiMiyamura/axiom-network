# Copyright (c) 2026 Kantoshi Miyamura
#
# AxiomMind Safe Integration — End-to-End Integration Tests
#
# Tests the complete flow: proposal → policy validation → execution → audit

import pytest
import asyncio
import tempfile
import os
from pathlib import Path

from axiom_mind import (
    ActionType, ActionProposal, PolicyEngine, SafeExecutor,
    AuditLog, SystemState, ExecutorConfig, PolicyDecision,
    MinCooldownConfig, RateLimitConfig
)


class TestFullActionFlow:
    """Test complete action proposal → validation → execution → audit flow."""

    @pytest.mark.asyncio
    async def test_rpc_down_proposal_flow(self):
        """Full flow: RPC down → proposal → policy → executor → audit."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Setup
            audit = AuditLog(
                os.path.join(tmpdir, "audit.db"),
                "secret_key_at_least_32_bytes_long_"
            )
            await audit.initialize()

            policy = PolicyEngine()
            executor = SafeExecutor(
                config=ExecutorConfig(
                    enable_execution=False,  # DRY RUN
                    require_policy_approval=True,
                ),
                audit_logger=audit,
            )

            # Scenario: RPC is down
            state = SystemState(
                rpc_alive=False,  # ← Key condition
                best_height=1000,
                peer_count=5,
            )

            # Step 1: Proposal generated (by mind-core)
            proposal = ActionProposal(
                action_type=ActionType.RESTART_NODE,
                reason="RPC unresponsive for 30s",
                severity="critical",
            )
            await audit.log_action_proposed(proposal)

            # Step 2: Policy validates
            policy_result = await policy.validate_action(proposal, state)
            assert policy_result.decision == PolicyDecision.APPROVE
            await audit.log_action_approved(proposal, policy_result)

            # Step 3: Executor runs
            execution_result = await executor.execute(proposal, policy_result)
            assert execution_result.success is True  # DRY RUN
            assert "DRY RUN" in execution_result.stdout

            # Step 4: Verify audit trail
            entries = await audit.get_entries(limit=100)
            assert len(entries) >= 3  # proposed, approved, executed

            event_types = [e["event_type"] for e in entries]
            assert "action_proposed" in event_types
            assert "action_approved" in event_types
            assert "action_executed" in event_types

            await audit.close()

    @pytest.mark.asyncio
    async def test_policy_rejection_flow(self):
        """Policy rejection is logged and execution prevented."""
        with tempfile.TemporaryDirectory() as tmpdir:
            audit = AuditLog(
                os.path.join(tmpdir, "audit.db"),
                "secret_key_at_least_32_bytes_long_"
            )
            await audit.initialize()

            policy = PolicyEngine()
            executor = SafeExecutor(
                config=ExecutorConfig(enable_execution=False),
                audit_logger=audit,
            )

            # Scenario: RPC is actually UP (shouldn't restart)
            state = SystemState(
                rpc_alive=True,  # ← Violates precondition
            )

            proposal = ActionProposal(
                action_type=ActionType.RESTART_NODE,
                reason="Trying to restart even though RPC is up",
            )
            await audit.log_action_proposed(proposal)

            # Policy should REJECT
            policy_result = await policy.validate_action(proposal, state)
            assert policy_result.decision == PolicyDecision.REJECT
            assert "health_preconditions" in policy_result.checks
            assert policy_result.checks["health_preconditions"] is False

            await audit.log_action_rejected(proposal, policy_result.reason)

            # Executor should refuse (even if enabled)
            executor.config.enable_execution = True
            result = await executor.execute(proposal, policy_result)
            assert result.success is False  # Rejected by policy

            # Verify audit trail shows rejection
            entries = await audit.get_entries(limit=100)
            event_types = [e["event_type"] for e in entries]
            assert "action_rejected" in event_types

            await audit.close()

    @pytest.mark.asyncio
    async def test_cooldown_prevents_repeated_action(self):
        """Cooldown enforcement prevents restart loops."""
        with tempfile.TemporaryDirectory() as tmpdir:
            audit = AuditLog(
                os.path.join(tmpdir, "audit.db"),
                "secret_key_at_least_32_bytes_long_"
            )
            await audit.initialize()

            # Very short cooldown for testing
            cooldown = MinCooldownConfig(restart_node=1)  # 1 second
            policy = PolicyEngine(cooldown_config=cooldown)
            executor = SafeExecutor(
                config=ExecutorConfig(enable_execution=False),
                audit_logger=audit,
            )

            state = SystemState(rpc_alive=False)

            # First restart
            proposal1 = ActionProposal(action_type=ActionType.RESTART_NODE)
            result1 = await policy.validate_action(proposal1, state)
            assert result1.decision == PolicyDecision.APPROVE

            policy.record_execution(ActionType.RESTART_NODE)

            # Immediate second restart should fail
            proposal2 = ActionProposal(action_type=ActionType.RESTART_NODE)
            result2 = await policy.validate_action(proposal2, state)
            assert result2.decision == PolicyDecision.REJECT
            assert "cooldown" in result2.reason.lower()

            # Wait for cooldown
            await asyncio.sleep(1.1)

            # Third restart after cooldown should succeed
            proposal3 = ActionProposal(action_type=ActionType.RESTART_NODE)
            result3 = await policy.validate_action(proposal3, state)
            assert result3.decision == PolicyDecision.APPROVE

            await audit.close()

    @pytest.mark.asyncio
    async def test_rate_limit_prevents_spam(self):
        """Rate limiting prevents action spam."""
        with tempfile.TemporaryDirectory() as tmpdir:
            audit = AuditLog(
                os.path.join(tmpdir, "audit.db"),
                "secret_key_at_least_32_bytes_long_"
            )
            await audit.initialize()

            rate_limit = RateLimitConfig(max_actions_per_hour=2)
            policy = PolicyEngine(rate_limit_config=rate_limit)

            state = SystemState()

            # Action 1: Should approve
            p1 = ActionProposal(action_type=ActionType.LOG_ADVISORY)
            r1 = await policy.validate_action(p1, state)
            assert r1.decision == PolicyDecision.APPROVE
            policy.record_execution(ActionType.LOG_ADVISORY)

            # Action 2: Should approve
            p2 = ActionProposal(action_type=ActionType.LOG_ADVISORY)
            r2 = await policy.validate_action(p2, state)
            assert r2.decision == PolicyDecision.APPROVE
            policy.record_execution(ActionType.LOG_ADVISORY)

            # Action 3: Should be rate-limited
            p3 = ActionProposal(action_type=ActionType.LOG_ADVISORY)
            r3 = await policy.validate_action(p3, state)
            assert r3.decision == PolicyDecision.REJECT
            assert "rate limit" in r3.reason.lower()

            await audit.close()


class TestAuditTrail:
    """Test audit trail completeness and integrity."""

    @pytest.mark.asyncio
    async def test_all_decisions_logged(self):
        """Every decision is logged to audit trail."""
        with tempfile.TemporaryDirectory() as tmpdir:
            audit = AuditLog(
                os.path.join(tmpdir, "audit.db"),
                "secret_key_at_least_32_bytes_long_"
            )
            await audit.initialize()

            proposal = ActionProposal(action_type=ActionType.LOG_ADVISORY)

            # Log proposal
            entry1 = await audit.log_action_proposed(proposal)
            assert entry1.id is not None

            # Log approval
            from axiom_mind import PolicyDecisionResult
            policy_result = PolicyDecisionResult(
                proposal_id=proposal.id,
                decision=PolicyDecision.APPROVE,
            )
            entry2 = await audit.log_action_approved(proposal, policy_result)
            assert entry2.id is not None

            # Log execution
            from axiom_mind import ExecutionResult
            exec_result = ExecutionResult(
                proposal_id=proposal.id,
                action_type=ActionType.LOG_ADVISORY,
                success=True,
            )
            entry3 = await audit.log_action_executed(proposal, exec_result)
            assert entry3.id is not None

            # Verify all entries are in database
            entries = await audit.get_entries(limit=100)
            assert len(entries) == 3

            # Verify signatures
            for entry in entries:
                assert audit._verify_signature(entry) is True

            await audit.close()

    @pytest.mark.asyncio
    async def test_audit_entries_immutable(self):
        """Audit entries cannot be easily modified."""
        with tempfile.TemporaryDirectory() as tmpdir:
            audit = AuditLog(
                os.path.join(tmpdir, "audit.db"),
                "secret_key_at_least_32_bytes_long_"
            )
            await audit.initialize()

            proposal = ActionProposal(action_type=ActionType.RESTART_NODE)
            await audit.log_action_proposed(proposal)

            # Retrieve entry
            entries = await audit.get_entries(limit=1)
            entry = entries[0]
            original_sig = entry["signature"]

            # Attempt to tamper: change the reason
            entry["reason"] = "TAMPERED REASON"

            # Signature should no longer match
            new_sig = audit._compute_signature(entry)
            assert new_sig != original_sig

            # Verification should fail
            assert audit._verify_signature(entry) is False

            await audit.close()


class TestNoConsensusInterference:
    """Verify AxiomMind cannot interfere with consensus."""

    @pytest.mark.asyncio
    async def test_action_proposals_have_no_consensus_impact(self):
        """ActionProposals have no methods that affect consensus."""
        proposal = ActionProposal(
            action_type=ActionType.RESTART_NODE,
            reason="Test",
        )

        # Check that proposal has no way to:
        # - Validate a block
        # - Create a transaction
        # - Modify chain state
        # - Access private keys

        restricted_methods = [
            "validate_block",
            "validate_transaction",
            "create_block",
            "sign_transaction",
            "modify_consensus",
            "get_private_key",
            "access_wallet",
        ]

        for method in restricted_methods:
            assert not hasattr(proposal, method), (
                f"Proposal should not have {method}"
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
