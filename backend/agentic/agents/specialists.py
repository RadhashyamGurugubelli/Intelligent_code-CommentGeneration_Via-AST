"""Specialized sub-agent personas for the Agentic AI Layer."""

from __future__ import annotations

from typing import Any, Dict

from backend.agentic.agents.base_agent import BaseAgent
from backend.agentic.session import AgentSession
from backend.agentic.tools.registry import ToolRegistry


class ArchitectAgent(BaseAgent):
    """Specialist sub-agent for AST structural analysis, modular design, and complexity reduction."""

    def __init__(self, tools: ToolRegistry, model_client: Any = None) -> None:
        super().__init__(
            name="ArchitectAgent",
            role_description="Analyzes AST topology, cyclomatic complexity, and structural cohesion.",
            system_prompt=(
                "Your objective is to inspect the code's abstract syntax tree, calculate cyclomatic complexity, "
                "identify deeply nested branches, and propose clean architectural decompositions."
            ),
            tools=tools,
            model_client=model_client,
        )

    def deterministic_turn(self, session: AgentSession, sub_task: str) -> Dict[str, Any]:
        tool_res = self.tools.execute("inspect_ast_structure", {}, context=session)
        type_res = self.tools.execute("infer_type_errors", {}, context=session)
        summary = (
            f"Analyzed AST structure: {tool_res.get('result', {}).get('function_count', 0)} function(s), "
            f"File CC={tool_res.get('result', {}).get('file_cyclomatic_complexity', 1)}. "
            f"Found {type_res.get('result', {}).get('error_count', 0)} definite type error(s)."
        )
        session.record_step(
            agent=self.name,
            thought="Inspected AST structure and type inference.",
            action="finish",
            observation={"ast": tool_res, "types": type_res},
            duration_ms=1.5,
        )
        return {
            "agent": self.name,
            "status": "completed",
            "action": "finish",
            "thought": "Completed structural assessment.",
            "summary": summary,
        }


class OptimizerAgent(BaseAgent):
    """Specialist sub-agent for algorithmic complexity and performance speedups."""

    def __init__(self, tools: ToolRegistry, model_client: Any = None) -> None:
        super().__init__(
            name="OptimizerAgent",
            role_description="Detects algorithmic bottlenecks and synthesizes speedup optimizations.",
            system_prompt=(
                "Your objective is to analyze Python code for algorithmic bottlenecks (e.g. quadratic loops, "
                "eager generator allocations, redundant lookups) and synthesize optimizations."
            ),
            tools=tools,
            model_client=model_client,
        )

    def deterministic_turn(self, session: AgentSession, sub_task: str) -> Dict[str, Any]:
        detect_res = self.tools.execute("detect_optimization_targets", {}, context=session)
        opps = detect_res.get("result", {}).get("opportunities_count", 0)
        summary = f"Detected {opps} algorithmic optimization opportunity(ies)."

        if opps > 0:
            session.create_checkpoint("Pre-optimization snapshot")
            opt_res = self.tools.execute("synthesize_optimization", {}, context=session)
            if opt_res.get("status") == "success" and opt_res.get("result", {}).get("optimized"):
                session.update_code(opt_res["result"]["optimized_code"])
                summary += f" Applied optimizations: {opt_res['result'].get('complexity_before')} -> {opt_res['result'].get('complexity_after')}."

        session.record_step(
            agent=self.name,
            thought="Executed performance optimization scan.",
            action="finish",
            observation={"detection": detect_res},
            duration_ms=2.0,
        )
        return {
            "agent": self.name,
            "status": "completed",
            "action": "finish",
            "thought": "Completed performance optimization turn.",
            "summary": summary,
        }


class RedTeamAgent(BaseAgent):
    """Specialist sub-agent for static security vulnerability probing across 7 CWE vectors."""

    def __init__(self, tools: ToolRegistry, model_client: Any = None) -> None:
        super().__init__(
            name="RedTeamAgent",
            role_description="Probes AST for static vulnerability sinks without code execution.",
            system_prompt=(
                "Your objective is to inspect Python code for security flaws (SQL injection, command injection, "
                "path traversal, deserialization, SSRF, XXE, ReDoS) and identify unmitigated sinks."
            ),
            tools=tools,
            model_client=model_client,
        )

    def deterministic_turn(self, session: AgentSession, sub_task: str) -> Dict[str, Any]:
        probe_res = self.tools.execute("probe_security_vulnerabilities", {}, context=session)
        res_data = probe_res.get("result", {})
        vuln_count = res_data.get("vulnerabilities_detected", 0)
        resilience = res_data.get("resilience_score", 100)

        summary = (
            f"Red Team audit completed. Found {vuln_count} vulnerability finding(s). "
            f"Static resilience score: {resilience}/100."
        )
        session.record_step(
            agent=self.name,
            thought="Completed static vulnerability probing.",
            action="finish",
            observation=probe_res,
            duration_ms=2.5,
        )
        return {
            "agent": self.name,
            "status": "completed",
            "action": "finish",
            "thought": "Identified security threat landscape.",
            "summary": summary,
            "vulnerabilities": res_data.get("scenarios", []),
        }


class BlueTeamAgent(BaseAgent):
    """Specialist sub-agent for defensive remediation and security patching."""

    def __init__(self, tools: ToolRegistry, model_client: Any = None) -> None:
        super().__init__(
            name="BlueTeamAgent",
            role_description="Synthesizes defensive security patches and parameterized sanitizations.",
            system_prompt=(
                "Your objective is to remediate reported security vulnerabilities by replacing dynamic "
                "queries with parameterized placeholders, disabling entity resolution, or adding boundary guards."
            ),
            tools=tools,
            model_client=model_client,
        )

    def deterministic_turn(self, session: AgentSession, sub_task: str) -> Dict[str, Any]:
        session.create_checkpoint("Pre-remediation snapshot")
        patch_res = self.tools.execute("synthesize_defensive_patch", {}, context=session)
        res_data = patch_res.get("result", {})

        if res_data.get("fixed"):
            session.update_code(res_data["fixed_code"])
            summary = (
                f"Remediated {res_data.get('neutralized_count', 0)} vulnerability finding(s). "
                f"Defensive controls: {', '.join(res_data.get('defensive_controls', []))}."
            )
        else:
            summary = "No unmitigated vulnerabilities required defensive patching."

        session.record_step(
            agent=self.name,
            thought="Synthesized defensive security hardening.",
            action="finish",
            observation=patch_res,
            duration_ms=3.0,
        )
        return {
            "agent": self.name,
            "status": "completed",
            "action": "finish",
            "thought": "Completed defensive patch synthesis.",
            "summary": summary,
        }


class DocstringAgent(BaseAgent):
    """Specialist sub-agent for AST docstrings and semantic specifications."""

    def __init__(self, tools: ToolRegistry, model_client: Any = None) -> None:
        super().__init__(
            name="DocstringAgent",
            role_description="Synthesizes accurate docstrings grounded in AST semantics.",
            system_prompt=(
                "Your objective is to produce substantive function docstrings detailing parameters, "
                "returns, exceptions, and intermediate operational logic grounded in AST facts."
            ),
            tools=tools,
            model_client=model_client,
        )

    def deterministic_turn(self, session: AgentSession, sub_task: str) -> Dict[str, Any]:
        semantics_res = self.tools.execute("explain_ast_semantics", {}, context=session)
        total_expl = semantics_res.get("result", {}).get("total_explanations", 0)
        summary = f"Generated {total_expl} AST-grounded semantic explanations and docstrings."

        session.record_step(
            agent=self.name,
            thought="Generated AST semantic explanations.",
            action="finish",
            observation=semantics_res,
            duration_ms=1.5,
        )
        return {
            "agent": self.name,
            "status": "completed",
            "action": "finish",
            "thought": "Completed documentation synthesis.",
            "summary": summary,
        }


class AuditAgent(BaseAgent):
    """Specialist sub-agent for AST non-regression audit and score delta calculation."""

    def __init__(self, tools: ToolRegistry, model_client: Any = None) -> None:
        super().__init__(
            name="AuditAgent",
            role_description="Verifies syntax, symbol preservation, and calculates quality deltas.",
            system_prompt=(
                "Your objective is to perform the final non-regression audit. Verify that syntax is valid, "
                "all definitions are preserved, and calculate the overall health improvements."
            ),
            tools=tools,
            model_client=model_client,
        )

    def deterministic_turn(self, session: AgentSession, sub_task: str) -> Dict[str, Any]:
        val_res = self.tools.execute(
            "verify_code_integrity",
            {"original_code": session.original_code, "candidate_code": session.current_code},
            context=session,
        )
        diff_res = self.tools.execute(
            "compute_unified_diff",
            {"original_code": session.original_code, "candidate_code": session.current_code},
            context=session,
        )
        passed = val_res.get("result", {}).get("all_passed", False)
        summary = (
            f"Audit verification: {'PASSED' if passed else 'FAILED'}. "
            f"Definitions preserved: {val_res.get('result', {}).get('definitions_preserved')}, "
            f"Diff: +{diff_res.get('result', {}).get('added_lines', 0)} / -{diff_res.get('result', {}).get('removed_lines', 0)} lines."
        )

        session.record_step(
            agent=self.name,
            thought="Completed final integrity audit.",
            action="finish",
            observation={"integrity": val_res, "diff": diff_res},
            duration_ms=1.0,
        )
        return {
            "agent": self.name,
            "status": "completed",
            "action": "finish",
            "thought": "Integrity audit finished.",
            "summary": summary,
            "passed": passed,
            "diff": diff_res.get("result", {}).get("diff", ""),
        }
