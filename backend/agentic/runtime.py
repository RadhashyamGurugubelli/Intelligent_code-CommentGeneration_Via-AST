"""Agent Runtime managing state machine lifecycles and supervisor execution."""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, Optional

from backend.agentic.session import AgentSession, SessionManager, default_session_manager
from backend.agentic.supervisor import SupervisorAgent
from backend.agentic.tools import create_standard_tool_registry
from backend.agentic.tools.registry import ToolRegistry
from backend.attack_guard import detect_attack
from backend.validator import validate_code

logger = logging.getLogger(__name__)


class AgentRuntime:
    """Core runtime engine for stateful agentic workflows."""

    def __init__(
        self,
        tools: Optional[ToolRegistry] = None,
        session_manager: Optional[SessionManager] = None,
        model_client: Any = None,
        event_callback: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    ) -> None:
        self.tools = tools or create_standard_tool_registry()
        self.session_manager = session_manager or default_session_manager
        self.model_client = model_client
        self.event_callback = event_callback or (lambda event, payload: None)
        self.supervisor = SupervisorAgent(
            tools=self.tools,
            model_client=self.model_client,
            event_callback=self.event_callback,
        )

    def start_session(
        self,
        source_code: str,
        task: str = "",
        session_id: Optional[str] = None,
        auto_approve: bool = True,
    ) -> AgentSession:
        """Initialize a new session with preflight syntax and attack checks."""
        # 1. Syntax Validation
        valid = validate_code(source_code)
        if valid is not True:
            raise ValueError(f"Initial source code fails Python syntax validation: {valid}")

        # 2. Attack Guardrail Pre-scan:
        # Scan prompt task for adversarial prompt injection / policy bypass
        if task:
            prompt_detection = detect_attack(task, content_type="prompt")
            if prompt_detection["detected"]:
                raise PermissionError(
                    f"Agent session blocked by security layer: {', '.join(prompt_detection.get('categories', []))}"
                )

        # Scan source code for embedded prompt injection or credential/data exfiltration
        source_prompt_scan = detect_attack(source_code, content_type="prompt")
        source_code_scan = detect_attack(source_code, content_type="code")
        adversarial_categories = {
            "policy_bypass",
            "safety_control_bypass",
            "credential_exfiltration",
            "private_data_exfiltration",
            "jailbreak_attempt",
            "sensitive_data_transfer",
        }
        detected_categories = [
            cat
            for cat in (source_prompt_scan.get("categories", []) + source_code_scan.get("categories", []))
            if cat in adversarial_categories
        ]
        if detected_categories:
            unique_cats = list(dict.fromkeys(detected_categories))
            raise PermissionError(
                f"Agent session blocked by security layer: {', '.join(unique_cats)}"
            )

        # 3. Create or reuse Session
        if session_id:
            existing = self.session_manager.get_session(session_id)
            if existing:
                existing.task = task or existing.task
                existing.update_code(source_code)
                return existing

        session = self.session_manager.create_session(code=source_code, task=task)
        session.is_approved = auto_approve
        self.event_callback("session_created", {"session_id": session.session_id, "task": session.task})
        return session

    def execute_session(self, session_id: str) -> Dict[str, Any]:
        """Run the supervisor workflow for a given session."""
        session = self.session_manager.get_session(session_id)
        if not session:
            raise KeyError(f"Session '{session_id}' not found.")

        try:
            return self.supervisor.run(session)
        except Exception as exc:
            logger.exception("Agent runtime execution failed for session %s", session_id)
            session.set_status("failed")
            error_payload = {
                "status": "failed",
                "session_id": session_id,
                "error": str(exc),
                "error_type": type(exc).__name__,
            }
            self.event_callback("session_failed", error_payload)
            return error_payload

    def handle_user_action(
        self,
        session_id: str,
        action: str,
        feedback: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Process Human-in-the-Loop decision on pending approval."""
        session = self.session_manager.get_session(session_id)
        if not session:
            raise KeyError(f"Session '{session_id}' not found.")

        if action.lower() == "approve":
            session.is_approved = True
            session.pending_approval = None
            session.record_step(
                agent="HumanSupervisor",
                thought="User approved pending action.",
                action="human_approval",
                observation={"decision": "approved", "feedback": feedback},
            )
            self.event_callback("action_approved", {"session_id": session_id})
            return {"status": "resumed", "session_id": session_id, "decision": "approved"}

        if action.lower() == "reject":
            session.is_approved = False
            # Rollback to latest checkpoint if available
            if session.checkpoints:
                latest_chk = session.checkpoints[-1]
                session.rollback_to(latest_chk.id)
            session.pending_approval = None
            session.record_step(
                agent="HumanSupervisor",
                thought="User rejected pending action; restored previous checkpoint.",
                action="human_rejection",
                observation={"decision": "rejected", "feedback": feedback},
            )
            self.event_callback("action_rejected", {"session_id": session_id})
            return {"status": "rolled_back", "session_id": session_id, "decision": "rejected"}

        return {"status": "ignored", "session_id": session_id, "error": f"Unknown action '{action}'"}
