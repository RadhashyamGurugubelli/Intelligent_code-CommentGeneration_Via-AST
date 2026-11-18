"""Unit tests for typed WorkflowIntent, deterministic policy table, and DAG validation.

Tests exact selected agent IDs, DAG ordering, safety constraints, and regression cases.
"""

from __future__ import annotations

import unittest

from backend.agentic.intent import (
    POLICY_TABLE,
    WorkflowIntent,
    build_deterministic_plan,
    classify_intent,
    validate_dag,
    validate_model_plan,
)


class WorkflowPlanningAndIntentTests(unittest.TestCase):
    """Regression test suite for NEXUS task planning and agent selection."""

    def test_regression_case_1_ast_structure_and_call_graph_selects_atlas_only(self):
        """'Analyze Python AST structure and call graph' selects ATLAS only."""
        task = "Analyze Python AST structure and call graph"
        intent = classify_intent(task)
        self.assertEqual(intent, WorkflowIntent.ARCHITECTURE_ANALYSIS)

        plan = build_deterministic_plan(intent, task)
        agent_keys = [step["agent_key"] for step in plan]
        self.assertEqual(agent_keys, ["architect"])

        profile = POLICY_TABLE[intent]
        self.assertTrue(profile.read_only)
        self.assertFalse(profile.requires_approval)
        self.assertFalse(profile.verification_required)
        self.assertIn("architect", profile.agent_reasons)
        self.assertEqual(plan[0]["dependencies"], [])

    def test_regression_case_2_security_scan_only_selects_sentinel_only(self):
        """'Scan for security vulnerabilities only' selects SENTINEL only and never REMEDY."""
        task = "Scan for security vulnerabilities only"
        intent = classify_intent(task)
        self.assertEqual(intent, WorkflowIntent.SECURITY_SCAN)

        plan = build_deterministic_plan(intent, task)
        agent_keys = [step["agent_key"] for step in plan]
        self.assertEqual(agent_keys, ["red_team"])
        self.assertNotIn("blue_team", agent_keys)
        self.assertNotIn("audit", agent_keys)

        profile = POLICY_TABLE[intent]
        self.assertTrue(profile.read_only)
        self.assertFalse(profile.requires_approval)
        self.assertFalse(profile.verification_required)
        self.assertEqual(plan[0]["dependencies"], [])

    def test_regression_case_3_fix_security_findings_selects_sentinel_remedy_verity(self):
        """'Fix the security findings' selects SENTINEL → REMEDY → VERITY."""
        task = "Fix the security findings"
        intent = classify_intent(task)
        self.assertEqual(intent, WorkflowIntent.SECURITY_REMEDIATION)

        plan = build_deterministic_plan(intent, task)
        agent_keys = [step["agent_key"] for step in plan]
        self.assertEqual(agent_keys, ["red_team", "blue_team", "audit"])

        # Check DAG order: red_team -> blue_team -> audit
        red_task = next(t for t in plan if t["agent_key"] == "red_team")
        blue_task = next(t for t in plan if t["agent_key"] == "blue_team")
        audit_task = next(t for t in plan if t["agent_key"] == "audit")

        self.assertEqual(red_task["dependencies"], [])
        self.assertEqual(blue_task["dependencies"], ["red_team"])
        self.assertEqual(audit_task["dependencies"], ["blue_team"])

        profile = POLICY_TABLE[intent]
        self.assertFalse(profile.read_only)
        self.assertTrue(profile.requires_approval)
        self.assertTrue(profile.verification_required)

    def test_regression_case_4_generate_docstrings_selects_scribe_with_context_and_verifies(self):
        """'Generate docstrings' selects SCRIBE and only the context dependency it needs, then verifies."""
        task = "Generate docstrings"
        intent = classify_intent(task)
        self.assertEqual(intent, WorkflowIntent.DOCUMENTATION)

        plan = build_deterministic_plan(intent, task)
        agent_keys = [step["agent_key"] for step in plan]
        self.assertEqual(agent_keys, ["architect", "docstring", "audit"])
        self.assertNotIn("red_team", agent_keys)
        self.assertNotIn("optimizer", agent_keys)
        self.assertNotIn("blue_team", agent_keys)

        # Check DAG order: architect -> docstring -> audit
        arch_task = next(t for t in plan if t["agent_key"] == "architect")
        doc_task = next(t for t in plan if t["agent_key"] == "docstring")
        audit_task = next(t for t in plan if t["agent_key"] == "audit")

        self.assertEqual(arch_task["dependencies"], [])
        self.assertEqual(doc_task["dependencies"], ["architect"])
        self.assertEqual(audit_task["dependencies"], ["docstring"])

    def test_regression_case_5_optimize_this_function_selects_context_then_forge_then_verity(self):
        """'Optimize this function' selects required architecture context then FORGE then VERITY."""
        task = "Optimize this function"
        intent = classify_intent(task)
        self.assertEqual(intent, WorkflowIntent.OPTIMIZATION)

        plan = build_deterministic_plan(intent, task)
        agent_keys = [step["agent_key"] for step in plan]
        self.assertEqual(agent_keys, ["architect", "optimizer", "audit"])

        # FORGE must depend on architect and cannot start before its required context
        arch_task = next(t for t in plan if t["agent_key"] == "architect")
        opt_task = next(t for t in plan if t["agent_key"] == "optimizer")
        audit_task = next(t for t in plan if t["agent_key"] == "audit")

        self.assertEqual(arch_task["dependencies"], [])
        self.assertEqual(opt_task["dependencies"], ["architect"])
        self.assertFalse(opt_task.get("parallel", False))  # Cannot run parallel with architect
        self.assertEqual(audit_task["dependencies"], ["optimizer"])

    def test_regression_case_6_run_complete_project_review_selects_full_review(self):
        """'Run a complete project review' selects the full-review profile with approvals & DAG."""
        task = "Run a complete project review"
        intent = classify_intent(task)
        self.assertEqual(intent, WorkflowIntent.FULL_REVIEW)

        plan = build_deterministic_plan(intent, task)
        agent_keys = [step["agent_key"] for step in plan]
        self.assertEqual(
            agent_keys,
            ["architect", "optimizer", "red_team", "blue_team", "docstring", "audit"],
        )

        profile = POLICY_TABLE[intent]
        self.assertFalse(profile.read_only)
        self.assertTrue(profile.requires_approval)
        self.assertTrue(profile.verification_required)

        # Optimizer must depend on architect
        opt_task = next(t for t in plan if t["agent_key"] == "optimizer")
        self.assertIn("architect", opt_task["dependencies"])

        # Blue team must depend on red team
        blue_task = next(t for t in plan if t["agent_key"] == "blue_team")
        self.assertIn("red_team", blue_task["dependencies"])

    def test_regression_case_7_vague_or_empty_task_requires_user_to_choose(self):
        """A vague/empty task asks the user to choose a task rather than silently launching full review."""
        vague_inputs = ["", "   ", "help", "run", "do it", "start", "go"]
        for task in vague_inputs:
            with self.assertRaises(ValueError) as ctx:
                classify_intent(task)
            self.assertIn("specify an engineering task", str(ctx.exception).lower())

    def test_word_boundaries_prevent_accidental_intent_match(self):
        """Verify that words like 'all' inside 'call graph' do not trigger full review."""
        task = "Analyze call graph and callback handlers"
        intent = classify_intent(task)
        self.assertEqual(intent, WorkflowIntent.ARCHITECTURE_ANALYSIS)
        self.assertNotEqual(intent, WorkflowIntent.FULL_REVIEW)

    def test_dag_cycle_detection(self):
        """Verify that validate_dag rejects circular dependencies."""
        invalid_plan = [
            {"task_id": "architect", "dependencies": ["optimizer"]},
            {"task_id": "optimizer", "dependencies": ["architect"]},
        ]
        with self.assertRaises(ValueError) as ctx:
            validate_dag(invalid_plan)
        self.assertIn("cycle detected", str(ctx.exception).lower())

    def test_optimizer_missing_architect_dependency_is_rejected(self):
        """Verify that validate_dag rejects optimizer if architect is present but not in dependencies."""
        invalid_plan = [
            {"task_id": "architect", "dependencies": []},
            {"task_id": "optimizer", "dependencies": []},  # Missing architect dependency
        ]
        with self.assertRaises(ValueError) as ctx:
            validate_dag(invalid_plan)
        self.assertIn("consumes architecture_findings and must declare 'architect'", str(ctx.exception))

    def test_model_plan_cannot_add_unapproved_agents(self):
        """Verify that validate_model_plan rejects attempts by model to add agents outside profile."""
        profile = POLICY_TABLE[WorkflowIntent.ARCHITECTURE_ANALYSIS]
        model_output = {
            "tasks": [
                {"task_id": "architect", "dependencies": []},
                {"task_id": "blue_team", "dependencies": []},  # Not allowed in architecture_analysis!
            ]
        }
        validated = validate_model_plan(model_output, profile)
        self.assertIsNone(validated)

    def test_model_plan_rejects_unknown_tools(self):
        """Verify that validate_model_plan sanitizes or rejects unknown tools."""
        profile = POLICY_TABLE[WorkflowIntent.ARCHITECTURE_ANALYSIS]
        model_output = {
            "tasks": [
                {"task_id": "architect", "required_tools": ["malicious_shell_tool"], "dependencies": []},
            ]
        }
        validated = validate_model_plan(model_output, profile)
        self.assertIsNotNone(validated)
        # Verify malicious_shell_tool was replaced with standard allowlisted tools
        self.assertNotIn("malicious_shell_tool", validated[0]["required_tools"])
        self.assertIn("inspect_ast_structure", validated[0]["required_tools"])


if __name__ == "__main__":
    unittest.main()
