"""Flask routes and streaming endpoints for the Agentic AI Layer."""

from __future__ import annotations

import logging
import threading
from typing import Any

from flask import Blueprint, Response, current_app, jsonify, request

from backend.agentic.events import default_broadcaster
from backend.agentic.runtime import AgentRuntime
from backend.agentic.session import default_session_manager
from backend.agentic.tools import create_standard_tool_registry
from backend.model_provider import create_model_client
from backend.request_utils import extract_code as _extract_code
from backend.request_utils import request_data as _parse_request_data

logger = logging.getLogger(__name__)

agentic_routes = Blueprint("agentic", __name__)

# Shared runtime instance hooked to broadcaster
_tool_registry = create_standard_tool_registry()
_runtime = AgentRuntime(
    tools=_tool_registry,
    session_manager=default_session_manager,
    model_client=create_model_client(),
    event_callback=default_broadcaster.emit,
)


def _request_data():
    return _parse_request_data(request)


@agentic_routes.route("/agentic/tools", methods=["GET"])
def list_agentic_tools_route():
    """Return allowlisted tools and their standard schemas."""
    return jsonify({
        "status": "success",
        "count": len(_tool_registry.list_tools()),
        "tools": [
            {
                "name": t.name,
                "description": t.description,
                "is_read_only": t.is_read_only,
                "requires_approval": t.requires_approval,
                "schema": t.parameters_schema,
            }
            for t in _tool_registry.list_tools()
        ],
    })


@agentic_routes.route("/agentic/run", methods=["POST"])
def run_agentic_workflow_route():
    """Start an autonomous agentic workflow with optional background streaming."""
    data = _request_data()
    code = _extract_code(data)
    task = str(data.get("task", "")).strip()
    is_async = bool(data.get("async", True))

    if code is None:
        return jsonify({"error": "Code must be a string"}), 400
    if not code.strip():
        return jsonify({"error": "No code provided"}), 400
    if len(code) > current_app.config.get("MAX_SOURCE_LENGTH", 50000):
        return jsonify({"error": "Payload Too Large"}), 413
    if len(task) > 4000:
        return jsonify({"error": "Task is too long"}), 413

    auto_approve = bool(data.get("auto_approve", True))
    try:
        session = _runtime.start_session(source_code=code, task=task, auto_approve=auto_approve)
    except ValueError as exc:
        return jsonify({"error": str(exc), "syntax_error": True}), 400
    except PermissionError as exc:
        return jsonify({"error": str(exc), "security_blocked": True}), 422
    except Exception as exc:
        logger.exception("Failed to initialize agent session")
        return jsonify({"error": f"Failed to initialize session: {exc}"}), 500

    if is_async:
        # Launch background execution worker
        worker = threading.Thread(
            target=_runtime.execute_session,
            args=(session.session_id,),
            daemon=True,
        )
        worker.start()
        return jsonify({
            "status": "accepted",
            "session_id": session.session_id,
            "stream_url": f"/agentic/stream/{session.session_id}",
            "task": session.task,
        }), 202

    # Synchronous execution mode
    result = _runtime.execute_session(session.session_id)
    return jsonify(result)


@agentic_routes.route("/agentic/stream/<session_id>", methods=["GET"])
def stream_agentic_workflow_route(session_id: str):
    """Server-Sent Events endpoint streaming real-time thoughts and tool execution frames."""
    session = default_session_manager.get_session(session_id)
    if not session:
        return jsonify({"error": f"Session '{session_id}' not found."}), 404

    stream_generator = default_broadcaster.generate_sse_stream(session_id)
    response = Response(stream_generator, mimetype="text/event-stream")
    response.headers["Cache-Control"] = "no-cache, no-transform"
    response.headers["X-Accel-Buffering"] = "no"
    response.headers["Connection"] = "keep-alive"
    return response


@agentic_routes.route("/agentic/session/<session_id>", methods=["GET"])
def get_agentic_session_route(session_id: str):
    """Fetch current state, trajectory, and diff for a session."""
    session = default_session_manager.get_session(session_id)
    if not session:
        return jsonify({"error": f"Session '{session_id}' not found."}), 404
    return jsonify(session.to_dict())


@agentic_routes.route("/agentic/action", methods=["POST"])
def user_action_agentic_route():
    """Handle Human-in-the-Loop decision for pending approval."""
    data = _request_data()
    session_id = data.get("session_id")
    action = data.get("action", "")
    feedback = data.get("feedback")

    if not session_id or not isinstance(session_id, str):
        return jsonify({"error": "Missing valid session_id."}), 400
    if not action or action.lower() not in ("approve", "reject"):
        return jsonify({"error": "Action must be 'approve' or 'reject'."}), 400

    result = _runtime.handle_user_action(session_id, action, feedback)
    return jsonify(result)
