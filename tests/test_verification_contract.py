"""Tests for the Unified Verification Contract and schema_version 1 compliance.

Validates that:
- The contract strictly enforces schema_version 1 with all 6 checks.
- Missing keys are treated as 'not_run', NEVER implicitly passed.
- Overall status is derived dynamically from required check statuses.
- Static-only mode sets verification_level to 'static_only'.
- Behavioral tests passing upgrades verification_level to 'full'.
- Legacy migration mapper handles partial, legacy, and empty payloads without guessing.
"""

from __future__ import annotations

import unittest
from backend.agentic.verification_contract import (
    SCHEMA_VERSION,
    build_unified_audit,
    create_failed_audit,
    create_not_run_audit,
    migrate_legacy_audit,
)


class VerificationContractTests(unittest.TestCase):
    """Test suite for the unified verification schema and producers."""

    def test_build_unified_audit_all_pass_static_only(self):
        """Verify clean static run yields 'passed' status and 'static_only' level."""
        audit = build_unified_audit(
            integrity_result={"syntax_valid": True, "definitions_preserved": True},
            security_findings=[],
            security_regressions=[],
            type_errors=[],
            behavioral_results=None,
            is_approved=True,
            code_changed=False,
        )
        self.assertEqual(audit["schema_version"], SCHEMA_VERSION)
        self.assertEqual(audit["status"], "passed")
        self.assertEqual(audit["verification_level"], "static_only")
        self.assertTrue(audit["passed"])
        self.assertEqual(audit["checks"]["syntax"]["status"], "passed")
        self.assertEqual(audit["checks"]["definitions"]["status"], "passed")
        self.assertEqual(audit["checks"]["security"]["status"], "passed")
        self.assertEqual(audit["checks"]["types"]["status"], "passed")
        self.assertEqual(audit["checks"]["behavior"]["status"], "not_run")
        self.assertEqual(audit["checks"]["approval"]["status"], "passed")
        self.assertEqual(len(audit["failures"]), 0)

    def test_build_unified_audit_all_pass_with_behavioral_sandbox(self):
        """Verify passing sandbox behavioral tests elevates level to 'full'."""
        audit = build_unified_audit(
            integrity_result={"syntax_valid": True, "definitions_preserved": True},
            security_findings=[],
            security_regressions=[],
            type_errors=[],
            behavioral_results={"behavioral_tests_run": True, "behavioral_tests_passed": True},
            is_approved=True,
            code_changed=True,
        )
        self.assertEqual(audit["status"], "passed")
        self.assertEqual(audit["verification_level"], "full")
        self.assertEqual(audit["checks"]["behavior"]["status"], "passed")
        self.assertEqual(audit["checks"]["approval"]["status"], "passed")

    def test_build_unified_audit_security_finding_causes_failure(self):
        """Verify unresolved security findings fail the security check and overall status."""
        audit = build_unified_audit(
            integrity_result={"syntax_valid": True, "definitions_preserved": True},
            security_findings=[{"cwe": "CWE-89", "name": "SQL Injection"}],
            security_regressions=[],
            type_errors=[],
        )
        self.assertEqual(audit["status"], "failed")
        self.assertFalse(audit["passed"])
        self.assertEqual(audit["checks"]["security"]["status"], "failed")
        self.assertTrue(any("SECURITY" in f for f in audit["failures"]))

    def test_build_unified_audit_syntax_failure_causes_failure(self):
        """Verify syntax invalidity fails syntax check and overall status."""
        audit = build_unified_audit(
            integrity_result={"syntax_valid": False, "error": "SyntaxError on line 4"},
            security_findings=[],
            security_regressions=[],
            type_errors=[],
        )
        self.assertEqual(audit["status"], "failed")
        self.assertFalse(audit["passed"])
        self.assertEqual(audit["checks"]["syntax"]["status"], "failed")

    def test_build_unified_audit_behavioral_failure_causes_failure(self):
        """Verify failed sandbox assertions fail behavior check and overall status."""
        audit = build_unified_audit(
            integrity_result={"syntax_valid": True, "definitions_preserved": True},
            security_findings=[],
            security_regressions=[],
            type_errors=[],
            behavioral_results={"behavioral_tests_run": True, "behavioral_tests_passed": False, "error": "AssertionError"},
        )
        self.assertEqual(audit["status"], "failed")
        self.assertFalse(audit["passed"])
        self.assertEqual(audit["checks"]["behavior"]["status"], "failed")

    def test_build_unified_audit_missing_syntax_is_not_run_and_fails_pass_requirement(self):
        """Missing syntax validation is 'not_run' and prevents audit from passing."""
        audit = build_unified_audit(
            integrity_result={},  # Missing syntax_valid and definitions_preserved
            security_findings=[],
            type_errors=[],
        )
        self.assertEqual(audit["checks"]["syntax"]["status"], "not_run")
        self.assertEqual(audit["checks"]["definitions"]["status"], "not_run")
        # Since required checks are not_run, overall status must NOT be passed
        self.assertEqual(audit["status"], "not_run")
        self.assertFalse(audit["passed"])

    def test_create_not_run_audit_schema(self):
        """Verify create_not_run_audit outputs valid schema with all checks not_run."""
        audit = create_not_run_audit("Session cancelled before execution.")
        self.assertEqual(audit["schema_version"], SCHEMA_VERSION)
        self.assertEqual(audit["status"], "not_run")
        self.assertFalse(audit["passed"])
        for check in audit["checks"].values():
            self.assertEqual(check["status"], "not_run")

    def test_create_failed_audit_schema(self):
        """Verify create_failed_audit outputs valid schema with failed status."""
        audit = create_failed_audit("Execution terminated with exception: Timeout")
        self.assertEqual(audit["schema_version"], SCHEMA_VERSION)
        self.assertEqual(audit["status"], "failed")
        self.assertFalse(audit["passed"])
        self.assertEqual(audit["checks"]["syntax"]["status"], "failed")
        self.assertIn("Timeout", audit["failures"][0])

    def test_migrate_legacy_audit_never_guesses_missing_keys_as_true(self):
        """Verify legacy payloads with missing keys do not assume value !== false is a pass."""
        legacy = {
            "passed": True,  # Legacy claim of pass
            "syntax_valid": True,
            # definitions_preserved is missing!
            # security_checks_passed is missing!
        }
        migrated = migrate_legacy_audit(legacy)
        self.assertEqual(migrated["schema_version"], SCHEMA_VERSION)
        self.assertEqual(migrated["checks"]["syntax"]["status"], "passed")
        self.assertEqual(migrated["checks"]["definitions"]["status"], "not_run")
        self.assertEqual(migrated["checks"]["security"]["status"], "not_run")
        # Crucial requirement: A missing check must prevent overall pass!
        self.assertEqual(migrated["status"], "not_run")
        self.assertFalse(migrated["passed"])

    def test_migrate_legacy_audit_empty_or_none(self):
        """Verify empty or None inputs safely produce a valid 'not_run' schema."""
        migrated_none = migrate_legacy_audit(None)
        self.assertEqual(migrated_none["status"], "not_run")
        self.assertEqual(migrated_none["schema_version"], SCHEMA_VERSION)

        migrated_empty = migrate_legacy_audit({})
        self.assertEqual(migrated_empty["status"], "not_run")
        self.assertEqual(migrated_empty["schema_version"], SCHEMA_VERSION)

    def test_producer_audit_agent_deterministic_turn(self):
        """Contract test: AuditAgent produces schema_version 1 audit."""
        from backend.agentic.agents.specialists import AuditAgent
        from backend.agentic.session import AgentSession
        from backend.agentic.tools import default_tool_registry

        agent = AuditAgent(tools=default_tool_registry)
        session = AgentSession(
            session_id="audit_agent_contract_test",
            original_code="def add(a, b):\n    return a + b\n",
            original_code_digest="digest_add",
            current_code="def add(a, b):\n    return a + b\n",
            task="Verify code integrity",
        )
        res = agent.deterministic_turn(session, sub_task="Perform final verification")
        self.assertEqual(res["status"], "completed")
        audit = session.final_audit
        self.assertIsNotNone(audit)
        self.assertEqual(audit["schema_version"], SCHEMA_VERSION)
        self.assertIn(audit["status"], {"passed", "failed", "not_run"})
        self.assertIn("checks", audit)
        self.assertIn("syntax", audit["checks"])
        self.assertIn("definitions", audit["checks"])
        self.assertIn("security", audit["checks"])
        self.assertIn("types", audit["checks"])
        self.assertIn("behavior", audit["checks"])
        self.assertIn("approval", audit["checks"])

    def test_producer_supervisor_audit_from_observations(self):
        """Contract test: Supervisor _audit_from_observations produces schema_version 1."""
        from backend.agentic.session import AgentSession
        from backend.agentic.supervisor import SupervisorAgent
        from backend.agentic.tools import default_tool_registry

        supervisor = SupervisorAgent(tools=default_tool_registry)
        session = AgentSession(
            session_id="sup_obs_contract_test",
            original_code="def compute():\n    return 42\n",
            original_code_digest="digest_compute",
            current_code="def compute():\n    return 42\n",
            task="Analyze AST only",
        )
        audit = supervisor._audit_from_observations(session, task_id="test_audit_obs")
        self.assertEqual(audit["schema_version"], SCHEMA_VERSION)
        self.assertEqual(session.final_audit, audit)
        self.assertIn(audit["status"], {"passed", "failed", "not_run"})
        self.assertIn("checks", audit)

    def test_producer_supervisor_run_full_lifecycle(self):
        """Contract test: Supervisor.run produces schema_version 1 in final_payload."""
        from backend.agentic.session import AgentSession
        from backend.agentic.supervisor import SupervisorAgent
        from backend.agentic.tools import default_tool_registry

        supervisor = SupervisorAgent(tools=default_tool_registry)
        session = AgentSession(
            session_id="sup_run_contract_test",
            original_code="def multiply(x, y):\n    return x * y\n",
            original_code_digest="digest_mult",
            current_code="def multiply(x, y):\n    return x * y\n",
            task="Analyze Python AST structure and call graph",
        )
        payload = supervisor.run(session)
        self.assertEqual(payload["status"], "completed")
        self.assertIn("final_audit", payload)
        self.assertEqual(payload["final_audit"]["schema_version"], SCHEMA_VERSION)
        self.assertIn(payload["audit_status"], {"passed", "failed", "not_run"})

    def test_producer_runtime_execution_failure(self):
        """Contract test: AgentRuntime sets failed schema_version 1 audit on exception."""
        from unittest.mock import patch
        from backend.agentic.runtime import AgentRuntime
        from backend.agentic.session import SessionManager

        runtime = AgentRuntime(session_manager=SessionManager(), model_client=None)
        session = runtime.start_session("def broken():\n    pass\n", "Trigger failure")
        with patch.object(runtime.supervisor, "run", side_effect=RuntimeError("Simulated failure")):
            err_payload = runtime.execute_session(session.session_id)
        self.assertEqual(err_payload["status"], "failed")
        self.assertEqual(err_payload["audit_status"], "failed")
        self.assertEqual(err_payload["final_audit"]["schema_version"], SCHEMA_VERSION)
        self.assertEqual(session.final_audit["status"], "failed")

    def test_producer_runtime_cancellation(self):
        """Contract test: AgentRuntime sets not_run schema_version 1 audit on cancellation."""
        from backend.agentic.runtime import AgentRuntime
        from backend.agentic.session import SessionManager

        runtime = AgentRuntime(session_manager=SessionManager(), model_client=None)
        session = runtime.start_session("def cancel_me():\n    pass\n", "Cancel test")
        session.status = "awaiting_approval"
        cancel_res = runtime.cancel_session(session.session_id)
        self.assertEqual(cancel_res["status"], "cancelled")
        self.assertEqual(cancel_res["final_audit"]["schema_version"], SCHEMA_VERSION)
        self.assertEqual(cancel_res["final_audit"]["status"], "not_run")
        self.assertEqual(session.final_audit["status"], "not_run")

    def test_producer_session_manager_serialization_deserialization(self):
        """Contract test: SessionManager serializes and deserializes schema_version 1 audit."""
        from backend.agentic.session import AgentSession, SessionManager

        mgr = SessionManager()
        session = AgentSession(
            session_id="session_persistence_contract_test",
            original_code="x = 1\n",
            original_code_digest="digest_x",
            current_code="x = 1\n",
            task="Persist audit",
            final_audit={
                "schema_version": 1,
                "status": "passed",
                "verification_level": "static_only",
                "checks": {
                    "syntax": {"status": "passed", "evidence": "Valid", "details": "ok"},
                    "definitions": {"status": "passed", "evidence": "Preserved", "details": "ok"},
                    "security": {"status": "passed", "evidence": "Clean", "details": "ok"},
                    "types": {"status": "passed", "evidence": "Clean", "details": "ok"},
                    "behavior": {"status": "not_run", "evidence": "Skipped", "details": "ok"},
                    "approval": {"status": "passed", "evidence": "No change", "details": "ok"},
                },
                "summary": "Summary",
                "failures": [],
                "warnings": [],
            },
        )
        s_dict = session.to_dict()
        self.assertEqual(s_dict["final_audit"]["schema_version"], 1)
        self.assertEqual(s_dict["audit_status"], "passed")
        self.assertTrue(s_dict["audit_passed"])

        restored = mgr._deserialize_session(s_dict)
        self.assertEqual(restored.final_audit["schema_version"], 1)
        self.assertEqual(restored.final_audit["status"], "passed")


if __name__ == "__main__":
    unittest.main()
