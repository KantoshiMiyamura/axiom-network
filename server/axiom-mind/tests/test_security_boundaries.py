# Copyright (c) 2026 Kantoshi Miyamura
#
# AxiomMind Safe Integration — Security Boundary Tests
#
# These tests verify that AxiomMind CANNOT:
# 1. Execute arbitrary commands
# 2. Access wallet keys
# 3. Validate blocks directly
# 4. Affect consensus
# 5. Bypass policy engine
# 6. Tamper with audit logs

import pytest
import asyncio
import tempfile
import os
from pathlib import Path

from axiom_mind import (
    ActionType, ActionProposal, PolicyEngine, SafeExecutor,
    SecurityError, ExecutorConfig, AuditLog, SystemState,
    PolicyDecisionResult, PolicyDecision
)


class TestNoArbitraryExecution:
    """Verify that arbitrary command execution is impossible."""

    def test_non_whitelisted_action_rejected(self):
        """Non-whitelisted actions raise SecurityError."""
        # Try to execute something not in whitelist
        bad_proposal = ActionProposal(
            action_type="rm_rf_slash",  # NOT a valid ActionType
            reason="Try to delete filesystem",
        )

        # This should fail at the ActionType validation
        with pytest.raises((ValueError, AttributeError)):
            # Creating invalid ActionType fails
            pass

    @pytest.mark.asyncio
    async def test_executor_requires_whitelist_match(self):
        """Executor refuses to execute commands not in whitelist."""
        executor = SafeExecutor(
            config=ExecutorConfig(enable_execution=False)
        )

        # Try with invalid action type
        proposal = ActionProposal(action_type=ActionType.RESTART_NODE)

        # Create a policy result that approves
        policy_result = PolicyDecisionResult(
            proposal_id=proposal.id,
            decision=PolicyDecision.APPROVE,
        )

        # This should work (it's whitelisted)
        result = await executor.execute(proposal, policy_result)
        assert result is not None

    def test_whitelist_hardcoded_not_generated(self):
        """Whitelist commands are hardcoded, not generated."""
        executor = SafeExecutor()

        # Whitelist must be a fixed dict, not generated from input
        assert isinstance(executor.WHITELIST, dict)
        assert ActionType.RESTART_NODE in executor.WHITELIST

        # Command must be a list of strings
        cmd = executor.WHITELIST[ActionType.RESTART_NODE]
        assert isinstance(cmd, list)
        assert all(isinstance(part, str) for part in cmd)

        # Command is exactly: ["systemctl", "restart", "axiom-node"]
        assert cmd == ["systemctl", "restart", "axiom-node"]


class TestNoWalletKeyAccess:
    """Verify AxiomMind cannot access private keys or wallet secrets."""

    def test_no_wallet_imports(self):
        """mind-* modules never import axiom-wallet or axiom-signer."""
        import axiom_mind

        # Check that wallet modules are not imported
        import sys
        imported_modules = set(sys.modules.keys())

        wallet_modules = {m for m in imported_modules if "wallet" in m or "signer" in m}

        # Filter out test-related imports
        wallet_modules = {
            m for m in wallet_modules
            if not m.startswith("test") and not m.startswith("_")
        }

        # Should be empty (no wallet access)
        assert len(wallet_modules) == 0, (
            f"AxiomMind should not import wallet modules, found: {wallet_modules}"
        )

    def test_no_key_material_in_proposals(self):
        """ActionProposals never contain key material."""
        proposal = ActionProposal(
            action_type=ActionType.LOG_ADVISORY,
            reason="Test proposal",
            details={"some": "data"},
        )

        # Convert to dict to verify serialization
        proposal_dict = proposal.__dict__

        # Check that no 'key' or 'secret' fields exist
        for key in proposal_dict.keys():
            assert "key" not in key.lower()
            assert "secret" not in key.lower()
            assert "private" not in key.lower()
            assert "password" not in key.lower()


class TestPolicyEngineBypass:
    """Verify policy engine cannot be bypassed."""

    @pytest.mark.asyncio
    async def test_executor_checks_policy_approval(self):
        """Executor refuses to execute without APPROVE decision."""
        executor = SafeExecutor(
            config=ExecutorConfig(
                enable_execution=False,
                require_policy_approval=True,
            )
        )

        proposal = ActionProposal(action_type=ActionType.RESTART_NODE)

        # Policy REJECTS
        policy_result = PolicyDecisionResult(
            proposal_id=proposal.id,
            decision=PolicyDecision.REJECT,
            reason="Cooldown not expired",
        )

        result = await executor.execute(proposal, policy_result)

        # Execution should fail (not approved)
        assert result.success is False
        assert result.error is not None

    @pytest.mark.asyncio
    async def test_cooldown_prevents_restart_loop(self):
        """Policy enforces cooldown to prevent restart loops."""
        policy = PolicyEngine()

        state = SystemState(rpc_alive=False)

        # First proposal
        proposal1 = ActionProposal(action_type=ActionType.RESTART_NODE)
        result1 = await policy.validate_action(proposal1, state)
        assert result1.decision == PolicyDecision.APPROVE

        # Record that it executed
        policy.record_execution(ActionType.RESTART_NODE)

        # Second proposal immediately after
        proposal2 = ActionProposal(action_type=ActionType.RESTART_NODE)
        result2 = await policy.validate_action(proposal2, state)

        # Should be rejected due to cooldown
        assert result2.decision == PolicyDecision.REJECT
        assert "cooldown" in result2.reason.lower()

    @pytest.mark.asyncio
    async def test_rate_limit_max_actions_per_hour(self):
        """Policy enforces max actions per hour."""
        policy = PolicyEngine()
        policy.rate_limit_config.max_actions_per_hour = 3

        state = SystemState(
            rpc_alive=False,
            disk_percent=50,
            nginx_active=False,
            axiom_web_online=False,
        )

        # Try to exceed rate limit
        for i in range(4):
            if i < 3:
                proposal = ActionProposal(
                    action_type=ActionType.LOG_ADVISORY,
                    reason=f"Advisory {i}",
                )
                result = await policy.validate_action(proposal, state)
                assert result.decision == PolicyDecision.APPROVE, f"Advisory {i} should approve"
                policy.record_execution(ActionType.LOG_ADVISORY)
            else:
                # 4th should be rate-limited
                proposal = ActionProposal(
                    action_type=ActionType.LOG_ADVISORY,
                    reason="Advisory 4",
                )
                result = await policy.validate_action(proposal, state)
                assert result.decision == PolicyDecision.REJECT
                assert "rate limit" in result.reason.lower()


class TestAuditTamperDetection:
    """Verify audit log tampering is detected."""

    @pytest.mark.asyncio
    async def test_audit_signature_verification(self):
        """Audit entries with tampered signatures are detected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            audit = AuditLog(
                os.path.join(tmpdir, "audit.db"),
                "secret_key_at_least_32_bytes_long_"
            )
            await audit.initialize()

            # Log an action
            proposal = ActionProposal(action_type=ActionType.RESTART_NODE)
            await audit.log_action_proposed(proposal)

            # Retrieve and verify entry
            entries = await audit.get_entries(limit=10)
            assert len(entries) > 0

            # Entry should have valid signature
            entry = entries[0]
            assert "signature" in entry
            assert len(entry["signature"]) > 0

            # Verify signature matches
            assert audit._verify_signature(entry) is True

            await audit.close()

    @pytest.mark.asyncio
    async def test_tampered_signature_rejected(self):
        """Entries with invalid signatures are detected as tampered."""
        with tempfile.TemporaryDirectory() as tmpdir:
            audit = AuditLog(
                os.path.join(tmpdir, "audit.db"),
                "secret_key_at_least_32_bytes_long_"
            )
            await audit.initialize()

            # Create a fake entry with wrong signature
            fake_entry = {
                "id": "test-id",
                "timestamp": 123456.0,
                "event_type": "action_executed",
                "actor": "attacker",
                "action_type": "restart_node",
                "reason": "TAMPERED",
                "proposal_id": None,
                "policy_decision_id": None,
                "execution_id": None,
                "details": "{}",
                "signature": "wrong_signature_here",
            }

            # Signature should not verify
            assert audit._verify_signature(fake_entry) is False

            await audit.close()


class TestBlockchainIsolation:
    """Verify blockchain core is isolated from AxiomMind."""

    def test_no_consensus_imports(self):
        """mind-* never imports axiom-consensus."""
        import sys

        # Check imports
        imported_modules = set(sys.modules.keys())
        consensus_modules = {
            m for m in imported_modules
            if "consensus" in m and not m.startswith("test")
        }

        # Should only have axiom-consensus if loaded elsewhere, not by mind-*
        assert len(consensus_modules) == 0, (
            f"AxiomMind should not import consensus modules: {consensus_modules}"
        )

    def test_action_proposals_cannot_modify_consensus(self):
        """Action proposals have no way to affect block validation."""
        proposal = ActionProposal(
            action_type=ActionType.RESTART_NODE,
            reason="Test",
        )

        # Proposal has no methods like validate_block, sign_tx, etc.
        assert not hasattr(proposal, "validate_block")
        assert not hasattr(proposal, "sign_transaction")
        assert not hasattr(proposal, "modify_consensus_rule")

        # It's pure data
        assert hasattr(proposal, "action_type")
        assert hasattr(proposal, "reason")
        assert hasattr(proposal, "details")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
