"""Supervisor & Meta-Planner Agent coordinating the sub-agent swarm."""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Optional

from backend.agentic.agents.specialists import (
    ArchitectAgent,
    AuditAgent,
    BlueTeamAgent,
    DocstringAgent,
    OptimizerAgent,
    RedTeamAgent,
)
from backend.agentic.session import AgentSession
from backend.agentic.tools.registry import ToolRegistry
from backend.model_provider import MODEL_NAME

logger = logging.getLogger(__name__)


class SupervisorAgent:
    """Meta-Planner that decomposes tasks and orchestrates specialized sub-agents."""

    def __init__(
        self,
        tools: ToolRegistry,
        model_client: Any = None,
        model_name: str = MODEL_NAME,
        event_callback: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    ) -> None:
        self.tools = tools
        self.model_client = model_client
        self.model_name = model_name
        self.emit_event = event_callback or (lambda event, payload: None)

        # Initialize sub-agent swarm
        self.swarm = {
            "architect": ArchitectAgent(tools, model_client),
            "optimizer": OptimizerAgent(tools, model_client),
            "red_team": RedTeamAgent(tools, model_client),
            "blue_team": BlueTeamAgent(tools, model_client),
            "docstring": DocstringAgent(tools, model_client),
            "audit": AuditAgent(tools, model_client),
        }

    def generate_plan(self, session: AgentSession) -> List[Dict[str, Any]]:
        """Decompose developer task into an ordered sequence of sub-tasks."""
        task_lower = session.task.lower()

        # Dynamic task composition based on user intent
        plan = []
        plan.append({
            "stage": 1,
            "agent_key": "architect",
            "name": "AST Structural & Complexity Audit",
            "description": "Inspect abstract syntax tree, calculate cyclomatic complexity, and detect type errors.",
            "status": "pending",
        })

        if any(k in task_lower for k in ("optimi", "speed", "perf", "fast", "complex", "all", "improve")):
            plan.append({
                "stage": len(plan) + 1,
                "agent_key": "optimizer",
                "name": "Algorithmic Complexity & Speedup Optimization",
                "description": "Detect quadratic loops or redundant lookups and apply performance improvements.",
                "status": "pending",
            })

        if any(k in task_lower for k in ("sec", "vuln", "attack", "cwe", "red", "threat", "all", "audit", "harden")):
            plan.append({
                "stage": len(plan) + 1,
                "agent_key": "red_team",
                "name": "Red Team Static Vulnerability Probing",
                "description": "Probe source code statically for 7 CWE vulnerability classes.",
                "status": "pending",
            })

        if any(k in task_lower for k in ("fix", "patch", "blue", "remediat", "harden", "sec", "all")):
            plan.append({
                "stage": len(plan) + 1,
                "agent_key": "blue_team",
                "name": "Blue Team Defensive Remediation",
                "description": "Synthesize defensive sanitization and parameterized queries.",
                "status": "pending",
            })

        if any(k in task_lower for k in ("doc", "comment", "spec", "explain", "all")):
            plan.append({
                "stage": len(plan) + 1,
                "agent_key": "docstring",
                "name": "AST Semantic Docstrings & Explanations",
                "description": "Generate grounded docstring specifications and behavior summaries.",
                "status": "pending",
            })

        plan.append({
            "stage": len(plan) + 1,
            "agent_key": "audit",
            "name": "Integrity, Non-Regression & Quality Audit",
            "description": "Verify Python AST syntax, definition symbol preservation, and compute unified diff.",
            "status": "pending",
        })

        session.plan = plan
        return plan

    def run(self, session: AgentSession) -> Dict[str, Any]:
        """Execute the coordinated multi-agent workflow to completion."""
        session.set_status("planning")
        plan = self.generate_plan(session)
        self.emit_event("plan_created", {"session_id": session.session_id, "plan": plan})

        results = []
        for step_info in session.plan:
            agent_key = step_info["agent_key"]
            agent = self.swarm.get(agent_key)
            if not agent:
                continue

            session.set_status("running_subagent")
            step_info["status"] = "in_progress"
            self.emit_event(
                "subagent_started",
                {
                    "session_id": session.session_id,
                    "stage": step_info["stage"],
                    "agent": agent.name,
                    "task": step_info["name"],
                },
            )

            # Execute turn
            turn_result = agent.execute_turn(session, sub_task=step_info["description"])
            step_info["status"] = turn_result.get("status", "completed")
            step_info["summary"] = turn_result.get("summary", "")
            results.append(turn_result)

            self.emit_event(
                "subagent_completed",
                {
                    "session_id": session.session_id,
                    "stage": step_info["stage"],
                    "agent": agent.name,
                    "summary": turn_result.get("summary"),
                },
            )

        session.set_status("completed")
        diff_res = self.tools.execute(
            "compute_unified_diff",
            {"original_code": session.original_code, "candidate_code": session.current_code},
            context=session,
        )

        final_payload = {
            "status": "completed",
            "session_id": session.session_id,
            "original_code": session.original_code,
            "final_code": session.current_code,
            "code_changed": session.current_code.strip() != session.original_code.strip(),
            "diff": diff_res.get("result", {}).get("diff", ""),
            "plan": session.plan,
            "trajectory_steps": len(session.trajectory),
            "checkpoints": len(session.checkpoints),
            "results": results,
        }
        self.emit_event("workflow_completed", final_payload)
        return final_payload
