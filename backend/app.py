"""Flask routes for Intelligent Code Comment Generation via AST."""

import difflib
import logging
import os
import secrets
from io import BytesIO

from flask import Blueprint, Flask, current_app, jsonify, request, send_file, send_from_directory

from .agent import AgentRunError, run_agent
from .agentic.routes import agentic_routes
from .multi_agent_orchestrator import run_multi_agent_workflow
from .professor_student_engine import ProfessorStudentOrchestrator
from .optimization_agent import optimize_code
from .security_attack_agent import simulate_attacks
from .security_fixing_agent import fix_attack_vulnerabilities
from .assistant import (
    AssistantModelError,
    UnsafeAISuggestionError,
    build_assistant_response,
    build_live_ai_suggestion,
)
from .attack_guard import detect_attack, evaluate_attack_suite
from .code_analysis import (
    CC_THRESHOLD,
    CommentGenerationError,
    _build_prompt_payload,
    analyze_code,
    build_smart_ast_explanations,
    client,
    validate_code,
)
from .code_improver import _definition_names, _warnings_for, improve_code_quality
from .config import AppConfig
from .editor_assist import editor_assist
from .model_provider import (
    MODEL_NAME,
    get_current_settings,
    provider_display_name,
    provider_ready,
    test_provider_connectivity,
    update_provider_settings,
)
from .pipeline import run_pipeline
from .provider_errors import classify_provider_error
from .request_utils import (
    cursor_to_offset as _cursor_to_offset,
)
from .request_utils import (
    extract_code as _extract_code,
)
from .request_utils import (
    request_data as _parse_request_data,
)
from .request_utils import (
    to_utf16_offset as _to_utf16_offset,
)
from .request_utils import (
    undefined_name_findings as _undefined_name_findings,
)
from .request_utils import (
    valid_cursor as _valid_cursor,
)
from .rules import build_review_score, summarize_quality
from .validator import check_undefined_names, format_name_errors, format_python_error
from .visualise import graphviz_available, open_ast_pdf

FRONTEND_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "frontend")
)

main_routes = Blueprint("main", __name__)
security_routes = Blueprint("security", __name__)
agent_routes = Blueprint("agent", __name__)
analysis_routes = Blueprint("analysis", __name__)
editor_routes = Blueprint("editor", __name__)
assistant_routes = Blueprint("assistant", __name__)
artifact_routes = Blueprint("artifacts", __name__)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def _log_blocked_attack(endpoint, detection):
    logger.warning(
        "Blocked AI security attack endpoint=%s categories=%s risk_score=%s",
        endpoint,
        ",".join(detection["categories"]),
        detection["risk_score"],
    )


def _scan_assistant_input(prompt, code):
    prompt_result = detect_attack(prompt)
    source_result = detect_attack(code, content_type="code")
    categories = list(
        dict.fromkeys(prompt_result["categories"] + source_result["categories"])
    )
    risk_score = max(prompt_result["risk_score"], source_result["risk_score"])
    return {
        "detected": bool(categories),
        "decision": "block" if categories else "allow",
        "risk_score": risk_score,
        "severity": (
            prompt_result["severity"]
            if prompt_result["risk_score"] >= source_result["risk_score"]
            else source_result["severity"]
        ),
        "categories": categories,
        "reasons": list(
            dict.fromkeys(prompt_result["reasons"] + source_result["reasons"])
        ),
        "detection_latency_ms": round(
            prompt_result["detection_latency_ms"]
            + source_result["detection_latency_ms"],
            3,
        ),
    }



def _provider_error_response(error):
    classified = classify_provider_error(error, provider_display_name())
    if classified is None:
        return None
    payload, status = classified
    return jsonify(payload), status

def _request_data():
    return _parse_request_data(request)


def _api_key_required():
    if not current_app.config.get("REQUIRE_API_KEY", False):
        return False
    expected = (current_app.config.get("API_KEY") or "").strip()
    if not expected:
        return True
    authorization = request.headers.get("Authorization", "")
    if authorization.lower().startswith("bearer "):
        provided = authorization.split(None, 1)[1].strip()
    else:
        provided = request.headers.get("X-API-Key", "").strip()
    return not provided or not secrets.compare_digest(provided, expected)


def _enforce_model_api_key():
    if request.method == "OPTIONS":
        return None
    protected_paths = {
        "/api/settings",
        "/api/test-provider",
        "/generate",
        "/assist/ai",
        "/assistant",
        "/assistant/improve",
        "/agent/run",
        "/agent/optimize",
        "/agent/simulate-attacks",
        "/agent/fix-attacks",
        "/agent/multi-agent-workflow",
        "/agent/professor-student",
        "/agentic/run",
        "/open_ast_pdf",
        "/download_ast_pdf",
    }
    if request.path not in protected_paths:
        return None
    if current_app.config.get("REQUIRE_API_KEY", False) and not (
        current_app.config.get("API_KEY") or ""
    ).strip():
        logger.error(
            "API key authentication is enabled, but no API_KEY is configured."
        )
        return jsonify(
            {
                "error": "API key authentication is enabled, but API_KEY is not configured on the server."
            }
        ), 503
    if _api_key_required():
        return jsonify(
            {
                "error": "Authentication required. Provide Authorization: Bearer <API_KEY> or X-API-Key."
            }
        ), 401
    return None


def _syntax_finding(source_code, severity):
    try:
        compile(source_code, "<editor-suggestion>", "exec")
    except SyntaxError as exc:
        return {
            "rule_id": "SYNTAX001",
            "severity": severity,
            "message": f"Python syntax is incomplete: {exc.msg}",
            "line": exc.lineno or 0,
            "column": exc.offset or 0,
        }
    return None


def after_request(response):
    logger.info(f"{request.method} {request.path} - {response.status_code}")
    origin = request.headers.get("Origin")
    allowed_origins = current_app.config["CORS_ORIGINS"]
    if origin:
        if "*" in allowed_origins:
            logger.warning(
                "Wildcard CORS origin is disabled for safety; use an explicit allowlist."
            )
            allowed_origins = ()
        if origin in allowed_origins:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Headers"] = (
                "Content-Type,Authorization,X-API-Key"
            )
            response.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
            response.headers.add("Vary", "Origin")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault(
        "Permissions-Policy", "geolocation=(), microphone=(), camera=()"
    )
    return response


def request_entity_too_large(error):
    return jsonify({"error": "Payload Too Large"}), error.code or 413


@main_routes.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@main_routes.route("/health", methods=["GET"])
def health():
    ai_available = provider_ready(client)
    return jsonify(
        {
            "status": "ok",
            "name": "Intelligent Code Comment Generation via AST",
            "version": "2.0",
            "ai_available": ai_available,
            "ai_provider": provider_display_name(),
            "ai_model": MODEL_NAME,
            "ast_pdf_available": graphviz_available(),
            "modules": [
                "assistant",
                "agent",
                "agentic",
                "attack_guard",
                "optimization_agent",
                "security_attack_agent",
                "security_fixing_agent",
                "multi_agent_orchestrator",
                "multi_agents",
                "ast_analyzer",
                "code_improver",
                "code_analysis",
                "config",
                "editor_assist",
                "models",
                "model_provider",
                "pipeline",
                "prompt_builder",
                "provider_errors",
                "request_utils",
                "rules",
                "type_analyzer",
                "validator",
                "visualise",
            ],
        }
    )


@main_routes.route("/api/settings", methods=["GET"])
def get_settings_route():
    """Get active provider and docstring preferences."""
    return jsonify(get_current_settings())


@main_routes.route("/api/settings", methods=["POST"])
def update_settings_route():
    """Update runtime provider, key, model, or docstring style."""
    data = _request_data()
    updated = update_provider_settings(
        provider=data.get("provider"),
        api_key=data.get("api_key"),
        model=data.get("model"),
        base_url=data.get("base_url"),
        docstring_style=data.get("docstring_style"),
    )
    return jsonify(updated)


@main_routes.route("/api/test-provider", methods=["POST"])
def test_provider_route():
    """Test live connectivity to a model provider."""
    data = _request_data()
    provider = data.get("provider") or AppConfig.AI_PROVIDER
    api_key = data.get("api_key")
    model = data.get("model")
    base_url = data.get("base_url")
    result = test_provider_connectivity(
        provider=provider,
        api_key=api_key,
        model=model,
        base_url=base_url,
    )
    return jsonify(result)


@security_routes.route("/security/evaluate", methods=["GET"])
def security_evaluate_route():
    """Run the deterministic, labeled attack simulation suite."""
    return jsonify(evaluate_attack_suite())


@security_routes.route("/security/simulate-custom-attack", methods=["POST"])
def security_simulate_custom_attack_route():
    """Simulate a targeted custom or preset attack payload against code or guardrails."""
    data = _request_data()
    payload = str(data.get("payload", "")).strip()
    attack_type = str(data.get("attack_type", "custom")).strip().lower()
    code = _extract_code(data) or ""

    if len(code) > current_app.config.get("MAX_SOURCE_LENGTH", 50000):
        return jsonify({"error": "Payload Too Large"}), 413
    if len(payload) > 4000:
        return jsonify({"error": "Payload is too long"}), 413

    if code:
        valid = validate_code(code)
        if valid is not True:
            formatted = format_python_error(code)
            return jsonify({
                "error": f"Syntax error in your code: {valid}",
                "interpreter_output": formatted,
            }), 400

    prompt_scan = detect_attack(payload, content_type="prompt") if payload else {"detected": False, "categories": [], "reasons": [], "detection_latency_ms": 0.5}
    code_scan = detect_attack(code, content_type="code") if code else {"detected": False, "categories": [], "reasons": []}

    ast_findings = []
    if code:
        try:
            sim_res = simulate_attacks(code)
            ast_findings = sim_res.get("attack_scenarios", [])
        except Exception:
            pass

    matched_scenario = None
    for sc in ast_findings:
        cat = sc.get("category", "").lower()
        if (
            ("sql" in attack_type and ("sql" in cat or "89" in sc.get("cwe", "").lower()))
            or (("cmd" in attack_type or "command" in attack_type or "code" in attack_type) and ("command" in cat or "code" in cat or "78" in sc.get("cwe", "").lower() or "94" in sc.get("cwe", "").lower()))
            or (("traversal" in attack_type or "path" in attack_type) and ("path" in cat or "traversal" in cat or "22" in sc.get("cwe", "").lower()))
            or (("pickle" in attack_type or "deserial" in attack_type) and ("deserial" in cat or "502" in sc.get("cwe", "").lower()))
            or (("ssrf" in attack_type or "request" in attack_type) and ("ssrf" in cat or "918" in sc.get("cwe", "").lower()))
            or (("redos" in attack_type or "regex" in attack_type) and ("redos" in cat or "1333" in sc.get("cwe", "").lower() or "dos" in cat))
            or (("xxe" in attack_type or "xml" in attack_type) and ("xml" in cat or "xxe" in cat or "611" in sc.get("cwe", "").lower()))
            or (("hash" in attack_type or "crypto" in attack_type or "md5" in attack_type) and ("crypt" in cat or "hash" in cat or "327" in sc.get("cwe", "").lower()))
            or (("temp" in attack_type or "mktemp" in attack_type) and ("temp" in cat or "377" in sc.get("cwe", "").lower()))
            or (("debug" in attack_type) and ("debug" in cat or "disclosure" in cat or "215" in sc.get("cwe", "").lower()))
            or (("ssl" in attack_type or "tls" in attack_type) and ("transport" in cat or "ssl" in cat or "295" in sc.get("cwe", "").lower()))
            or (("secret" in attack_type or "token" in attack_type or "credential" in attack_type) and ("secret" in cat or "credential" in cat or "798" in sc.get("cwe", "").lower()))
        ):
            matched_scenario = sc
            break

    if not matched_scenario and ast_findings:
        matched_scenario = ast_findings[0]

    detected = prompt_scan["detected"] or code_scan["detected"] or (matched_scenario is not None)

    if matched_scenario:
        cwe = matched_scenario.get("cwe", "CWE-20: Improper Input Validation")
        cvss = 9.8 if matched_scenario.get("severity") == "critical" else 7.5
        target_line = matched_scenario.get("target_line", 1)
        vuln_code = matched_scenario.get("vulnerable_code", "")
        mitigation = matched_scenario.get("mitigation", "Implement strict input sanitization and parameterized queries.")
        trace = (
            f"Static Red Team Analysis identified vulnerable sink at line {target_line}: '{vuln_code}'. "
            f"Payload '{payload}' targets this vulnerability pattern. {matched_scenario.get('simulation_trace', '')}"
        )
    elif prompt_scan["detected"]:
        cwe = "CWE-77: Command / Prompt Injection"
        cvss = 8.5
        target_line = 0
        vuln_code = "AI Prompt Interface"
        mitigation = "Deterministic Guardrails blocked adversarial tokens before model execution."
        trace = f"Guardrail Alert: {', '.join(prompt_scan.get('reasons', []))}. Payload attempted prompt injection / policy bypass."
    else:
        is_sqli = any(kw in payload.upper() for kw in ("' OR", "UNION SELECT", "DROP TABLE", "--"))
        is_cmdi = any(kw in payload for kw in (";", "|", "&&", "`", "$("))
        is_redos = "(" in payload and "+" in payload and "*" in payload
        is_xxe = "<!ENTITY" in payload.upper() or "<!DOCTYPE" in payload.upper()
        is_ssrf = any(marker in payload.lower() for marker in ("169.254.169.254", "metadata", "localhost", "127.0.0.1"))
        if is_sqli:
            cwe = "CWE-89: SQL Injection"
            cvss = 8.8
            mitigation = "Use parameterized SQL queries with bind variables (? or %s)."
            trace = f"SQL Injection signature detected in payload '{payload}'. In an unescaped query, this alters SQL syntax logic."
            detected = True
        elif is_cmdi:
            cwe = "CWE-78: OS Command Injection"
            cvss = 9.8
            mitigation = "Avoid shell=True and pass argument lists to subprocess.run."
            trace = f"Shell command metacharacter detected in payload '{payload}'. This triggers arbitrary shell execution."
            detected = True
        elif is_redos:
            cwe = "CWE-1333: Inefficient Regular Expression Complexity (ReDoS)"
            cvss = 7.5
            mitigation = "Simplify regex quantifier nesting and use linear-time regex engines."
            trace = f"Exponential backtracking regex bomb detected '{payload}'. Catastrophic backtracking can freeze CPU worker threads."
            detected = True
        elif is_xxe:
            cwe = "CWE-611: XML External Entity Reference (XXE)"
            cvss = 8.6
            mitigation = "Disable DTD processing and external entity resolution via defusedxml."
            trace = f"XML External Entity (XXE) injection payload detected '{payload}'. Unrestricted parser entity resolution can leak files or access internal networks."
            detected = True
        elif is_ssrf:
            cwe = "CWE-918: Server-Side Request Forgery (SSRF)"
            cvss = 8.6
            mitigation = "Validate destination IP/hostname against private subnet allowlists and block cloud metadata IP (169.254.169.254)."
            trace = f"Cloud metadata / internal network SSRF target detected '{payload}'. Unsanitized fetches can leak IAM instance credentials."
            detected = True
        else:
            cwe = "CWE-20: Improper Input Validation" 
            cvss = 5.3
            mitigation = "Enforce allowlists and schema validation on all untrusted inputs."
            trace = f"Custom payload '{payload}' tested against AST model. No immediate critical exploit path detected in active source."

    return jsonify({
        "status": "success",
        "payload": payload,
        "attack_type": attack_type,
        "detected": detected,
        "blocked_by_guard": prompt_scan["detected"],
        "exploit_successful": matched_scenario is not None,
        "severity": "critical" if cvss >= 9.0 else "high" if cvss >= 7.0 else "medium",
        "risk_score": int(cvss * 10),
        "cvss": cvss,
        "cwe": cwe,
        "target_line": target_line if matched_scenario else 0,
        "vulnerable_code": vuln_code if matched_scenario else "",
        "exploit_trace": trace,
        "mitigation": mitigation,
        "latency_ms": prompt_scan.get("detection_latency_ms", 1.2),
    })


@agent_routes.route("/agent/run", methods=["POST"])
def agent_run_route():
    data = _request_data()
    code = _extract_code(data)
    task = data.get("task", "")
    if code is None:
        return jsonify({"error": "Code must be a string"}), 400
    if not code.strip():
        return jsonify({"error": "No code provided"}), 400
    if len(code) > current_app.config["MAX_SOURCE_LENGTH"]:
        return jsonify({"error": "Payload Too Large"}), 413
    if not isinstance(task, str):
        return jsonify({"error": "Task must be a string"}), 400
    if len(task) > 4000:
        return jsonify({"error": "Task is too long"}), 413

    attack_detection = _scan_assistant_input(task, code)
    if attack_detection["detected"]:
        _log_blocked_attack("/agent/run", attack_detection)
        return jsonify(
            {
                "error": "Agent run blocked by the security layer.",
                "security_blocked": True,
                "attack_detection": attack_detection,
            }
        ), 422

    valid = validate_code(code)
    if valid is not True:
        formatted = format_python_error(code)
        return jsonify(
            {
                "error": f"Syntax error in your code: {valid}",
                "interpreter_output": formatted,
            }
        ), 400
    if client is None:
        return jsonify(
            {
                "error": "The AI agent requires a configured model. Set API_KEY and restart the server."
            }
        ), 503

    try:
        analysis = analyze_code(code)
        analysis["warnings"].extend(
            _undefined_name_findings(check_undefined_names(code))
        )
        return jsonify(run_agent(code, task, analysis, client))
    except AgentRunError as exc:
        logger.warning("AI agent run rejected (%s)", type(exc).__name__)
        return jsonify({"error": str(exc), "agent_status": "failed"}), 502
    except Exception as exc:
        logger.exception("AI agent run failed")
        provider_error = _provider_error_response(exc)
        if provider_error:
            return provider_error
        return jsonify({"error": "AI agent run failed", "agent_status": "failed"}), 502


@agent_routes.route("/agent/optimize", methods=["POST"])
def agent_optimize_route():
    data = _request_data()
    code = _extract_code(data)
    if code is None:
        return jsonify({"error": "Code must be a string"}), 400
    if not code.strip():
        return jsonify({"error": "No code provided"}), 400
    if len(code) > current_app.config["MAX_SOURCE_LENGTH"]:
        return jsonify({"error": "Payload Too Large"}), 413

    valid = validate_code(code)
    if valid is not True:
        formatted = format_python_error(code)
        return jsonify(
            {
                "error": f"Syntax error in your code: {valid}",
                "interpreter_output": formatted,
            }
        ), 400

    try:
        return jsonify(optimize_code(code, model_client=client))
    except Exception as exc:
        logger.exception("Code optimization agent failed")
        return jsonify({"error": f"Code optimization agent failed: {exc}", "status": "failed"}), 500


@agent_routes.route("/agent/simulate-attacks", methods=["POST"])
def agent_simulate_attacks_route():
    data = _request_data()
    code = _extract_code(data)
    if code is None:
        return jsonify({"error": "Code must be a string"}), 400
    if not code.strip():
        return jsonify({"error": "No code provided"}), 400
    if len(code) > current_app.config["MAX_SOURCE_LENGTH"]:
        return jsonify({"error": "Payload Too Large"}), 413

    valid = validate_code(code)
    if valid is not True:
        formatted = format_python_error(code)
        return jsonify(
            {
                "error": f"Syntax error in your code: {valid}",
                "interpreter_output": formatted,
            }
        ), 400

    try:
        return jsonify(simulate_attacks(code, model_client=client))
    except Exception as exc:
        logger.exception("Attack simulation agent failed")
        return jsonify({"error": f"Attack simulation agent failed: {exc}", "status": "failed"}), 500


@agent_routes.route("/agent/fix-attacks", methods=["POST"])
def agent_fix_attacks_route():
    data = _request_data()
    code = _extract_code(data)
    if code is None:
        return jsonify({"error": "Code must be a string"}), 400
    if not code.strip():
        return jsonify({"error": "No code provided"}), 400
    if len(code) > current_app.config["MAX_SOURCE_LENGTH"]:
        return jsonify({"error": "Payload Too Large"}), 413

    valid = validate_code(code)
    if valid is not True:
        formatted = format_python_error(code)
        return jsonify(
            {
                "error": f"Syntax error in your code: {valid}",
                "interpreter_output": formatted,
            }
        ), 400

    try:
        return jsonify(fix_attack_vulnerabilities(code, model_client=client))
    except Exception as exc:
        logger.exception("Attack fixing agent failed")
        return jsonify({"error": f"Attack fixing agent failed: {exc}", "status": "failed"}), 500


@agent_routes.route("/agent/multi-agent-workflow", methods=["POST"])
def agent_multi_agent_workflow_route():
    data = _request_data()
    code = _extract_code(data)
    if code is None:
        return jsonify({"error": "Code must be a string"}), 400
    if not code.strip():
        return jsonify({"error": "No code provided"}), 400
    if len(code) > current_app.config["MAX_SOURCE_LENGTH"]:
        return jsonify({"error": "Payload Too Large"}), 413

    valid = validate_code(code)
    if valid is not True:
        formatted = format_python_error(code)
        return jsonify(
            {
                "error": f"Syntax error in your code: {valid}",
                "interpreter_output": formatted,
            }
        ), 400

    try:
        return jsonify(run_multi_agent_workflow(code, model_client=client))
    except Exception as exc:
        logger.exception("Multi-agent workflow failed")
        return jsonify({"error": f"Multi-agent workflow failed: {exc}", "status": "failed"}), 500


@agent_routes.route("/agent/professor-student", methods=["POST"])
def agent_professor_student_route():
    data = _request_data()
    code = _extract_code(data)
    if code is None:
        return jsonify({"error": "Code must be a string"}), 400
    if not code.strip():
        return jsonify({"error": "No code provided"}), 400
    if len(code) > current_app.config["MAX_SOURCE_LENGTH"]:
        return jsonify({"error": "Payload Too Large"}), 413

    max_iterations = data.get("max_iterations", 5)
    try:
        max_iterations = int(max_iterations)
    except (ValueError, TypeError):
        max_iterations = 5

    try:
        orchestrator = ProfessorStudentOrchestrator(model_client=client, max_iterations=max_iterations)
        result = orchestrator.run(code)
        return jsonify(result)
    except Exception as exc:
        logger.exception("Professor-Student continuous review loop failed")
        return jsonify({"error": f"Professor-Student review failed: {exc}", "status": "failed"}), 500


@analysis_routes.route("/analyze", methods=["POST"])
def analyze_route():
    data = _request_data()
    code = _extract_code(data)
    if code is None:
        return jsonify({"error": "Code must be a string"}), 400
    if not code.strip():
        return jsonify({"error": "No code provided"}), 400
    if len(code) > current_app.config["MAX_SOURCE_LENGTH"]:
        return jsonify({"error": "Payload Too Large"}), 413

    valid = validate_code(code)
    if valid is not True:
        formatted = format_python_error(code)
        syntax_finding = {
            "rule_id": "SYNTAX001",
            "severity": "error",
            "message": f"Syntax error in your code: {valid}",
            "line": 1,
        }
        return jsonify(
            {
                "error": f"Syntax error in your code: {valid}",
                "interpreter_output": formatted,
                "warnings": [syntax_finding],
                "quality_score": 0,
                "quality_summary": summarize_quality([syntax_finding]),
                "review_score": build_review_score([syntax_finding]),
            }
        ), 400

    undefined = check_undefined_names(code)
    name_warnings = format_name_errors(undefined)
    name_findings = _undefined_name_findings(undefined)

    try:
        analysis = analyze_code(code)
        warnings = analysis["warnings"] + name_findings
        analysis["warnings"] = warnings
        quality_summary = summarize_quality(warnings)
        return jsonify(
            {
                "analysis": analysis,
                "warnings": warnings,
                "quality_summary": quality_summary,
                "quality_score": quality_summary["score"],
                "review_score": build_review_score(warnings),
                "execution_status": "not_executed",
                "name_errors": name_warnings,
                "name_findings": name_findings,
                "smart_explanations": build_smart_ast_explanations(code),
            }
        )
    except Exception as exc:
        logger.exception("Code analysis failed")
        provider_error = _provider_error_response(exc)
        if provider_error:
            return provider_error
        return jsonify({"error": "Code analysis failed"}), 500


@analysis_routes.route("/generate", methods=["POST"])
def generate():
    data = _request_data()
    code = _extract_code(data)
    if code is None:
        return jsonify({"error": "Code must be a string"}), 400
    if not code.strip():
        return jsonify({"error": "No code provided"}), 400
    if len(code) > current_app.config["MAX_SOURCE_LENGTH"]:
        return jsonify({"error": "Payload Too Large"}), 413

    valid = validate_code(code)
    if valid is not True:
        formatted = format_python_error(code)
        syntax_finding = {
            "rule_id": "SYNTAX001",
            "severity": "error",
            "message": f"Syntax error in your code: {valid}",
            "line": 1,
        }
        return jsonify(
            {
                "error": f"Syntax error in your code: {valid}",
                "interpreter_output": formatted,
                "warnings": [syntax_finding],
                "quality_score": 0,
                "quality_summary": summarize_quality([syntax_finding]),
                "review_score": build_review_score([syntax_finding]),
            }
        ), 400

    undefined = check_undefined_names(code)
    name_warnings = format_name_errors(undefined)
    name_findings = _undefined_name_findings(undefined)

    attack_detection = detect_attack(code, content_type="code")
    if attack_detection["detected"]:
        preflight = analyze_code(code)
        preflight_warnings = preflight["warnings"] + name_findings
        security_warnings = [
            warning
            for warning in preflight_warnings
            if warning["rule_id"].startswith("SEC")
        ]
        if not security_warnings:
            security_warnings = [
                {
                    "rule_id": "SEC006",
                    "severity": "error",
                    "message": "Adversarial instructions or sensitive-data transfer detected before AI generation.",
                    "line": 0,
                }
            ]
            preflight_warnings.extend(security_warnings)
        preflight["warnings"] = preflight_warnings
        _log_blocked_attack("/generate", attack_detection)
        q_summary = summarize_quality(preflight_warnings)
        return jsonify(
            {
                "error": "Security risks detected. Fix the findings before generating comments. Source code was not executed.",
                "security_blocked": True,
                "execution_status": "not_executed",
                "warnings": security_warnings,
                "quality_summary": q_summary,
                "quality_score": q_summary["score"],
                "review_score": build_review_score(preflight_warnings),
                "analysis": preflight,
                "attack_detection": attack_detection,
            }
        ), 409

    try:
        preflight = analyze_code(code)
        preflight_warnings = preflight["warnings"] + name_findings
        security_warnings = [
            warning
            for warning in preflight_warnings
            if warning["rule_id"].startswith("SEC")
        ]
        if security_warnings:
            preflight["warnings"] = preflight_warnings
            q_summary = summarize_quality(preflight_warnings)
            return jsonify(
                {
                    "error": "Security risks detected. Fix the findings before generating comments. Source code was not executed.",
                    "security_blocked": True,
                    "execution_status": "not_executed",
                    "warnings": security_warnings,
                    "quality_summary": q_summary,
                    "quality_score": q_summary["score"],
                    "review_score": build_review_score(preflight_warnings),
                    "analysis": preflight,
                }
            ), 409
        pipeline_result = run_pipeline(code, preflight)
    except CommentGenerationError as exc:
        logger.warning("Comment generation failed: %s", exc)
        provider_error = _provider_error_response(exc.__cause__)
        if provider_error:
            return provider_error
        return jsonify({"error": str(exc)}), 502
    except Exception as exc:
        logger.exception("Code generation pipeline failed")
        provider_error = _provider_error_response(exc)
        if provider_error:
            return provider_error
        return jsonify({"error": "Code generation pipeline failed"}), 500

    analysis = pipeline_result["analysis"]
    analysis["warnings"].extend(name_findings)
    quality_summary = summarize_quality(analysis["warnings"])
    review_score = build_review_score(analysis["warnings"])
    quality_score = quality_summary["score"]
    return jsonify(
        {
            "commented_code": pipeline_result["commented_code"],
            "execution_status": "not_executed",
            "analysis": analysis,
            "warnings": analysis["warnings"],
            "quality_summary": quality_summary,
            "cc_summary": {
                "file_cc": analysis["summary"]["file_cc"],
                "per_function": {
                    item["name"]: item["complexity"] for item in analysis["functions"]
                },
                "threshold": CC_THRESHOLD,
            },
            "validation": pipeline_result["validation"],
            "ai_status": pipeline_result["method"],
            "generation_notice": pipeline_result["generation_notice"],
            "smart_explanations": build_smart_ast_explanations(code),
            "prompt_payload": _build_prompt_payload(code, analysis),
            "quality_score": quality_score,
            "review_score": review_score,
            "name_errors": name_warnings,
        }
    )


@editor_routes.route("/assist", methods=["POST"])
def assist_route():
    data = _request_data()
    code = data.get("code", "")
    cursor = data.get("cursor", 0)
    if not isinstance(code, str):
        return jsonify({"error": "Code must be a string"}), 400
    if len(code) > current_app.config["MAX_SOURCE_LENGTH"]:
        return jsonify({"error": "Payload Too Large"}), 413
    if not _valid_cursor(cursor):
        return jsonify(
            {
                "error": "Cursor must be an integer offset or contain integer line and column values"
            }
        ), 400
    try:
        return jsonify(editor_assist(code, cursor))
    except Exception as exc:
        logger.exception("Editor assistance failed")
        provider_error = _provider_error_response(exc)
        if provider_error:
            return provider_error
        return jsonify({"error": "Editor assistance failed"}), 500


@editor_routes.route("/assist/ai", methods=["POST"])
def live_ai_assist_route():
    data = _request_data()
    code = _extract_code(data)
    cursor = data.get("cursor", 0)
    if code is None:
        return jsonify({"error": "Code must be a string"}), 400
    if not code.strip():
        return jsonify({"error": "No code provided"}), 400
    if len(code) > current_app.config["MAX_SOURCE_LENGTH"]:
        return jsonify({"error": "Payload Too Large"}), 413
    if not _valid_cursor(cursor):
        return jsonify(
            {
                "error": "Cursor must be an integer offset or contain integer line and column values"
            }
        ), 400
    attack_detection = detect_attack(code, content_type="code")
    if attack_detection["detected"]:
        _log_blocked_attack("/assist/ai", attack_detection)
        cursor_index = _cursor_to_offset(code, cursor)
        return jsonify(
            {
                "suggestion": "",
                "suggestion_type": "ai_completion",
                "source": "ai",
                "replacement_range": {
                    "start": _to_utf16_offset(code, cursor_index),
                    "end": _to_utf16_offset(code, cursor_index),
                },
                "cursor_offset": _to_utf16_offset(code, cursor_index),
                "explanation": "AI completion was blocked because the source contains adversarial instructions.",
                "validation_status": "rejected",
                "warnings": [
                    {
                        "rule_id": "SEC006",
                        "severity": "error",
                        "message": "Adversarial instructions in source were blocked before sending it to the AI model.",
                        "line": 0,
                    }
                ],
                "attack_detection": attack_detection,
            }
        )
    if client is None:
        return jsonify(
            {
                "error": "Live AI suggestions are unavailable. Configure API_KEY to enable them."
            }
        ), 503

    try:
        suggestion = build_live_ai_suggestion(code, cursor, client)
    except UnsafeAISuggestionError:
        logger.warning("Rejected unsafe or adversarial AI completion at /assist/ai")
        suggestion = ""
        cursor_index = _cursor_to_offset(code, cursor)
        warnings = [
            {
                "rule_id": "SEC001",
                "severity": "error",
                "message": "AI suggestion was rejected because it introduced unsafe execution logic or prompt-injection content.",
                "line": 0,
            }
        ]
        return jsonify(
            {
                "suggestion": suggestion,
                "suggestion_type": "ai_completion",
                "source": "ai",
                "replacement_range": {
                    "start": _to_utf16_offset(code, cursor_index),
                    "end": _to_utf16_offset(code, cursor_index),
                },
                "cursor_offset": _to_utf16_offset(code, cursor_index),
                "explanation": "AI-generated completion was rejected because it introduced unsafe logic.",
                "validation_status": "rejected",
                "warnings": warnings,
            }
        )
    except Exception as exc:
        logger.exception("Live AI completion request failed")
        provider_error = _provider_error_response(exc)
        if provider_error:
            return provider_error
        return jsonify(
            {
                "error": "The live AI provider request failed. Check the server log for its diagnostic."
            }
        ), 502
    try:
        cursor_index = _cursor_to_offset(code, cursor)
        candidate = code[:cursor_index] + suggestion + code[cursor_index:]
        original_syntax = _syntax_finding(code, "warning")
        candidate_syntax = _syntax_finding(candidate, "error")
        original_valid = original_syntax is None
        candidate_valid = candidate_syntax is None
        warnings = []
        validation_status = "needs_review"

        if not candidate_valid:
            warnings.append(candidate_syntax)
            if original_valid:
                validation_status = "rejected"
        elif not original_valid:
            warnings.append(original_syntax)
        elif original_valid:
            original_security = [
                warning
                for warning in analyze_code(code)["warnings"]
                if warning["rule_id"].startswith("SEC")
            ]
            candidate_security = [
                warning
                for warning in analyze_code(candidate)["warnings"]
                if warning["rule_id"].startswith("SEC")
            ]
            original_counts = {}
            for warning in original_security:
                key = warning["rule_id"], warning["message"]
                original_counts[key] = original_counts.get(key, 0) + 1
            remaining_original = original_counts.copy()
            added_security = []
            for warning in candidate_security:
                key = warning["rule_id"], warning["message"]
                if remaining_original.get(key, 0):
                    remaining_original[key] -= 1
                else:
                    added_security.append(warning)
            if added_security:
                warnings.extend(added_security)
                validation_status = "rejected"
            else:
                warnings.extend(original_security)
                validation_status = "needs_review" if original_security else "validated"
        if validation_status == "rejected":
            suggestion = ""
        return jsonify(
            {
                "suggestion": suggestion,
                "suggestion_type": "ai_completion",
                "source": "ai",
                "replacement_range": {
                    "start": _to_utf16_offset(code, cursor_index),
                    "end": _to_utf16_offset(code, cursor_index),
                },
                "cursor_offset": _to_utf16_offset(
                    candidate, cursor_index + len(suggestion)
                ),
                "explanation": (
                    "Suggestion rejected because it introduces invalid syntax or a new security finding."
                    if validation_status == "rejected"
                    else "AI-generated completion; review its behavior before accepting."
                ),
                "validation_status": validation_status,
                "warnings": warnings,
            }
        )
    except Exception as exc:
        logger.exception("Live AI completion validation failed")
        provider_error = _provider_error_response(exc)
        if provider_error:
            return provider_error
        return jsonify(
            {
                "error": "The AI completion could not be validated safely. Check the server log for its diagnostic."
            }
        ), 502


@assistant_routes.route("/assistant", methods=["POST"])
def assistant_route():
    data = _request_data()
    code = _extract_code(data)
    prompt = data.get("prompt", "") if isinstance(data, dict) else ""
    if code is None:
        return jsonify({"error": "Code must be a string"}), 400
    if not code.strip():
        return jsonify({"error": "No code provided"}), 400
    if len(code) > current_app.config["MAX_SOURCE_LENGTH"]:
        return jsonify({"error": "Payload Too Large"}), 413
    if not isinstance(prompt, str):
        return jsonify({"error": "Prompt must be a string"}), 400
    if len(prompt) > 4000:
        return jsonify({"error": "Prompt is too long"}), 413

    attack_detection = _scan_assistant_input(prompt, code)
    if attack_detection["detected"]:
        _log_blocked_attack("/assistant", attack_detection)
        return jsonify(
            {
                "error": "Request blocked by the Agentic AI security layer.",
                "security_blocked": True,
                "attack_detection": attack_detection,
            }
        ), 422

    valid = validate_code(code)
    if valid is not True:
        formatted = format_python_error(code)
        return jsonify(
            {
                "error": f"Syntax error in your code: {valid}",
                "interpreter_output": formatted,
            }
        ), 400

    try:
        analysis = analyze_code(code)
        name_findings = _undefined_name_findings(check_undefined_names(code))
        analysis["warnings"].extend(name_findings)
        assistant_warning = None
        try:
            assistant = build_assistant_response(analysis, prompt, client, code)
        except AssistantModelError as exc:
            if client is None:
                raise
            logger.warning(
                "AI assistant model response failed (%s); returning AST-grounded guidance.",
                type(exc).__name__,
            )
            assistant = build_assistant_response(analysis, prompt, None, code)
            assistant_warning = (
                "The configured AI provider could not provide a usable response; this uses "
                "AST-grounded guidance instead."
            )
        return jsonify(
            {
                "assistant_reply": assistant["message"],
                "assistant_type": assistant["type"],
                "assistant_source": assistant["source"],
                "assistant_warning": assistant_warning,
                "suggestions": assistant["suggestions"],
                "analysis_summary": assistant["summary"],
                "warnings": analysis.get("warnings", []),
            }
        )
    except Exception as exc:
        logger.exception("AI assistant request failed")
        provider_error = _provider_error_response(exc)
        if provider_error:
            return provider_error
        return jsonify({"error": "AI assistant request failed"}), 500


@assistant_routes.route("/assistant/improve", methods=["POST"])
def assistant_improve_route():
    data = _request_data()
    code = _extract_code(data)
    if code is None:
        return jsonify({"error": "Code must be a string"}), 400
    if not code.strip():
        return jsonify({"error": "No code provided"}), 400
    if len(code) > current_app.config["MAX_SOURCE_LENGTH"]:
        return jsonify({"error": "Payload Too Large"}), 413
    prompt_scan = detect_attack(code, content_type="prompt")
    code_scan = detect_attack(code, content_type="code")
    _adv_cats = {"policy_bypass", "safety_control_bypass", "credential_exfiltration", "private_data_exfiltration", "jailbreak_attempt", "sensitive_data_transfer"}
    _adv_detected = any(c in _adv_cats for c in (prompt_scan.get("categories", []) + code_scan.get("categories", [])))
    attack_detection = (prompt_scan if prompt_scan["detected"] else code_scan) if _adv_detected else {"detected": False, "categories": []}
    if attack_detection["detected"]:
        _log_blocked_attack("/assistant/improve", attack_detection)
        return jsonify(
            {
                "error": "AI improvement was blocked because the source contains adversarial instructions.",
                "security_blocked": True,
                "attack_detection": attack_detection,
            }
        ), 422

    valid = validate_code(code)
    if valid is not True:
        formatted = format_python_error(code)
        return jsonify(
            {
                "error": f"Syntax error in your code: {valid}",
                "interpreter_output": formatted,
            }
        ), 400
    if client is None:
        return jsonify(
            {
                "error": "AI code improvement is unavailable. Configure API_KEY to enable it."
            }
        ), 503

    try:
        result = improve_code_quality(code, client)
        return jsonify(result)
    except Exception as exc:
        logger.exception("AI code-quality improvement failed")
        provider_error = _provider_error_response(exc)
        if provider_error:
            return provider_error
        return jsonify({"error": "AI code-quality improvement failed"}), 502


@artifact_routes.route("/open_ast_pdf", methods=["POST"])
def open_ast_pdf_route():
    return _ast_pdf_response(as_attachment=False)


@artifact_routes.route("/download_ast_pdf", methods=["POST"])
def download_ast_pdf_route():
    return _ast_pdf_response(as_attachment=True)


def _ast_pdf_response(*, as_attachment):
    data = _request_data()
    code = _extract_code(data)
    if code is None:
        return jsonify({"error": "Code must be a string"}), 400
    if not code.strip():
        return jsonify({"error": "No code provided"}), 400
    if len(code) > current_app.config["MAX_SOURCE_LENGTH"]:
        return jsonify({"error": "Payload Too Large"}), 413
    valid = validate_code(code)
    if valid is not True:
        formatted = format_python_error(code)
        return jsonify(
            {
                "error": f"Syntax error in your code: {valid}",
                "interpreter_output": formatted,
            }
        ), 400
    try:
        pdf_data = open_ast_pdf(code)
        return send_file(
            BytesIO(pdf_data),
            mimetype="application/pdf",
            as_attachment=as_attachment,
            download_name="ast.pdf",
        )
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 503
    except Exception as exc:
        logger.exception("AST PDF rendering failed")
        provider_error = _provider_error_response(exc)
        if provider_error:
            return provider_error
        return jsonify({"error": "AST PDF rendering failed"}), 500


def create_app(config_overrides=None):
    """Build a Flask application with the API route groups and shared middleware."""
    flask_app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")
    flask_app.config.from_object(AppConfig)
    if config_overrides:
        flask_app.config.update(config_overrides)

    for blueprint in (
        main_routes,
        security_routes,
        agent_routes,
        analysis_routes,
        editor_routes,
        assistant_routes,
        artifact_routes,
        agentic_routes,
    ):
        flask_app.register_blueprint(blueprint)

    flask_app.before_request(_enforce_model_api_key)
    flask_app.after_request(after_request)
    flask_app.register_error_handler(413, request_entity_too_large)
    return flask_app


app = create_app()
