"""Tests for REMEDY and VERITY behaviour preservation, opt-in sandbox, and separated reports.

Hermetic tests: no real network, no DNS, isolated tmp_path workspace for sandbox tests.
"""

from __future__ import annotations

from backend.agentic.agents.specialists import AuditAgent
from backend.agentic.tools import create_standard_tool_registry
from backend.agentic.tools.verification_tools import verify_code_integrity_handler
from backend.agentic.verification_contract import (
    build_unified_audit,
    create_failed_audit,
    create_not_run_audit,
)
from backend.behavioral_verifier import check_remediation_behaviour_preservation
from backend.project.engineering_tools import EngineeringToolsRunner
from backend.project.workspace import ProjectWorkspace
from backend.security_fixing_agent import fix_attack_vulnerabilities


# =====================================================================
# 1. Behaviour-Preservation Checks for os.system -> subprocess.run
# =====================================================================


def test_behaviour_preservation_detects_check_true_exception_contract_change():
    """Replacing os.system with check=True raises CalledProcessError on error instead of returning exit code."""
    original = (
        "import os\n"
        "def execute(cmd):\n"
        "    return os.system(cmd)\n"
    )
    # Candidate with check=True changes exception contract
    candidate = (
        "import subprocess\n"
        "import shlex\n"
        "def execute(cmd):\n"
        "    return subprocess.run(shlex.split(cmd), shell=False, check=True).returncode\n"
    )

    result = check_remediation_behaviour_preservation(original, candidate)
    assert result["behaviour_change"] is True
    assert any("check=True" in w for w in result["warnings"])
    assert any("CalledProcessError" in w for w in result["warnings"])
    assert len(result["findings"]) >= 1
    assert result["findings"][0]["behaviour_change"] is True


def test_behaviour_preservation_detects_completed_process_return_contract_change():
    """Returning subprocess.run(...) directly returns CompletedProcess instead of int exit code."""
    original = (
        "import os\n"
        "def execute(cmd):\n"
        "    status = os.system(cmd)\n"
        "    return status\n"
    )
    # Candidate returns CompletedProcess instead of int
    candidate = (
        "import subprocess\n"
        "import shlex\n"
        "def execute(cmd):\n"
        "    status = subprocess.run(shlex.split(cmd), shell=False, check=False)\n"
        "    return status\n"
    )

    result = check_remediation_behaviour_preservation(original, candidate)
    assert result["behaviour_change"] is True
    assert any("returncode" in w for w in result["warnings"])
    assert any("CompletedProcess" in w for w in result["warnings"])


def test_behaviour_preservation_accepts_safe_check_false_with_returncode():
    """Remediation using check=False and .returncode preserves both return and exception contracts."""
    original = (
        "import os\n"
        "def execute(cmd):\n"
        "    return os.system(cmd)\n"
    )
    safe_candidate = (
        "import subprocess\n"
        "import shlex\n"
        "def execute(cmd):\n"
        "    return subprocess.run(shlex.split(cmd), shell=False, check=False).returncode\n"
    )

    result = check_remediation_behaviour_preservation(original, safe_candidate)
    assert result["behaviour_change"] is False
    assert len(result["warnings"]) == 0
    assert len(result["findings"]) == 0


def test_remedy_synthesizes_safe_subprocess_run_preserving_contract():
    """REMEDY must synthesize subprocess.run with check=False and .returncode."""
    vuln_code = (
        "import os\n"
        "def execute_user_command(user_input):\n"
        "    cmd = f'ping {user_input}'\n"
        "    return os.system(cmd)\n"
    )

    remedy_res = fix_attack_vulnerabilities(vuln_code)
    assert remedy_res["fixed"] is True
    fixed_code = remedy_res["fixed_code"]
    assert "subprocess.run(" in fixed_code
    assert "check=False" in fixed_code
    assert ".returncode" in fixed_code
    assert "os.system(" not in fixed_code

    preservation = check_remediation_behaviour_preservation(vuln_code, fixed_code)
    assert preservation["behaviour_change"] is False
    assert len(preservation["warnings"]) == 0


def test_verification_tools_handler_exposes_behaviour_preservation():
    """verify_code_integrity_handler returns behaviour_preservation, behaviour_change, and behaviour_warnings."""
    original = "import os\ndef f(x):\n    return os.system(x)\n"
    breaking_candidate = (
        "import subprocess, shlex\n"
        "def f(x):\n"
        "    return subprocess.run(shlex.split(x), shell=False, check=True).returncode\n"
    )

    res = verify_code_integrity_handler(
        {"original_code": original, "candidate_code": breaking_candidate, "allow_executable_changes": True},
        context=None,
    )
    assert "behaviour_preservation" in res
    assert res["behaviour_change"] is True
    assert len(res["behaviour_warnings"]) > 0


# =====================================================================
# 2. Opt-in Sandboxed Behavioural Test Runner for Project Workbench
# =====================================================================


def test_engineering_tools_runner_pytest_disabled_by_default(tmp_path):
    """By default (ALLOW_PROJECT_TEST_EXECUTION=false), pytest is NOT RUN with clear security notice."""
    ws = ProjectWorkspace(workspace_id="default_disabled", base_storage_dir=tmp_path)
    ws.write_file("test_sample.py", "def test_ok(): pass\n")
    runner = EngineeringToolsRunner(ws)

    # conftest automatically sets ALLOW_PROJECT_TEST_EXECUTION=false
    res = runner.run_pytest()
    assert res["tool"] == "pytest"
    assert res["status"] == "not_run_sandbox_unavailable"
    assert res["passed"] in (None, False)
    assert "NOT RUN: this environment has no OS-level sandbox" in res["message"]
    assert "ALLOW_PROJECT_TEST_EXECUTION=false" in res["reason"]


def test_engineering_tools_runner_pytest_opt_in_runs_in_disposable_temp_copy(tmp_path, monkeypatch):
    """When ALLOW_PROJECT_TEST_EXECUTION=true, pytest runs in a temp copy and passes."""
    monkeypatch.setenv("ALLOW_PROJECT_TEST_EXECUTION", "true")

    ws = ProjectWorkspace(workspace_id="opt_in_run", base_storage_dir=tmp_path)
    ws.write_file("test_sample.py", "def test_passes():\n    assert 2 + 2 == 4\n")
    runner = EngineeringToolsRunner(ws)

    res = runner.run_pytest(args=["test_sample.py"])
    assert res["tool"] == "pytest"
    assert res["status"] == "passed"
    assert res["passed"] is True
    assert res["exit_code"] == 0
    assert "1 passed" in res["stdout"]
    assert res["sandbox_isolated"] is True


def test_engineering_tools_runner_pytest_output_capping(tmp_path, monkeypatch):
    """Subprocess output is capped at 64KB to avoid memory exhaustion."""
    monkeypatch.setenv("ALLOW_PROJECT_TEST_EXECUTION", "true")

    ws = ProjectWorkspace(workspace_id="capped_output", base_storage_dir=tmp_path)
    # Write a test that prints a large amount of text
    ws.write_file(
        "test_big_output.py",
        "def test_large():\n"
        "    for _ in range(2000):\n"
        "        print('A' * 100)\n"
        "    assert True\n",
    )
    runner = EngineeringToolsRunner(ws)

    res = runner.run_pytest(args=["-s", "test_big_output.py"])
    assert res["passed"] is True
    assert len(res["stdout"]) <= 66000
    if len(res["stdout"]) >= 64000:
        assert "[Output truncated]" in res["stdout"]


# =====================================================================
# 3. VERITY Report Separation and Warning on Behaviour Change
# =====================================================================


def test_verity_audit_shows_warning_on_behaviour_change_not_silent_success():
    """VERITY must show a visible warning (not silent success) when candidate alters behaviour."""
    audit = build_unified_audit(
        integrity_result={
            "syntax_valid": True,
            "definitions_preserved": True,
            "structural_safety": {"is_safe": True},
            "executable_code_preserved": False,
            "behaviour_change": True,
            "behaviour_warnings": [
                "Remediation replaced os.system with subprocess.run(..., check=True), altering exception contract."
            ],
        },
        security_findings=[],
        security_regressions=[],
        type_errors=[],
        behavioral_results=None,
        is_approved=True,
        code_changed=True,
        security_checked=True,
        types_checked=True,
    )

    # Must contain warning about behaviour change
    assert audit["behaviour_change"] is True
    assert any("BEHAVIOUR:" in w for w in audit["warnings"])
    assert "WARNING: Behaviour contract altered" in audit["summary"]
    assert "WARNING: Behaviour contract alterations detected" in audit["report"]


def test_verity_report_clearly_separates_three_sections():
    """VERITY final report clearly separates: 1. Static checks passed, 2. Behavioural checks, 3. What was NOT verified."""
    audit = build_unified_audit(
        integrity_result={
            "syntax_valid": True,
            "definitions_preserved": True,
            "structural_safety": {"is_safe": True},
            "executable_code_preserved": True,
        },
        security_findings=[],
        security_regressions=[],
        type_errors=[],
        behavioral_results=None,
        is_approved=False,
        code_changed=False,
        security_checked=True,
        types_checked=True,
    )

    # Check top-level structured audit keys
    assert "static_checks" in audit
    assert "behavioral_checks" in audit
    assert "not_verified" in audit
    assert "report" in audit

    assert audit["static_checks"]["status"] == "passed"
    assert audit["static_checks"]["passed"] is True
    assert audit["behavioral_checks"]["status"] == "not_run"
    assert audit["behavioral_checks"]["run"] is False

    # Check what was not verified
    assert any("Runtime behavioural assertions" in item for item in audit["not_verified"])

    # Check report string has distinct numbered sections
    report = audit["report"]
    assert "1. STATIC CHECKS PASSED:" in report
    assert "2. BEHAVIOURAL CHECKS:" in report
    assert "3. WHAT WAS NOT VERIFIED:" in report
    assert "Status: NOT RUN" in report


def test_audit_agent_deterministic_turn_surfaces_behaviour_findings():
    """AuditAgent surfaces behaviour change in findings, warnings, and summary."""
    from backend.agentic.session import SessionManager

    session = SessionManager().create_session(
        code="import os\ndef f(x):\n    return os.system(x)\n",
        task="Audit candidate with behaviour-altering patch",
    )
    # Candidate alters exception contract
    session.current_code = (
        "import subprocess\n"
        "import shlex\n"
        "def f(x):\n"
        "    return subprocess.run(shlex.split(x), shell=False, check=True).returncode\n"
    )

    registry = create_standard_tool_registry()
    agent = AuditAgent(tools=registry)

    turn_res = agent.deterministic_turn(session, "run audit")
    audit = turn_res["audit"]

    # Verify behaviour warning is captured
    assert audit["behaviour_change"] is True
    assert any("BEHAVIOUR:" in w for w in audit["warnings"])
    assert any(f.get("category") == "behaviour_change" for f in turn_res["findings"])
    assert "WARNING: Behaviour contract altered" in turn_res["summary"]
    assert "1. STATIC CHECKS PASSED:" in audit["report"]
    assert "2. BEHAVIOURAL CHECKS:" in audit["report"]
    assert "3. WHAT WAS NOT VERIFIED:" in audit["report"]


def test_create_not_run_and_failed_audit_contain_separated_sections():
    """create_not_run_audit and create_failed_audit must also include static, behavioral, and not_verified sections."""
    not_run = create_not_run_audit("Skipped due to pipeline cancellation.")
    assert "static_checks" in not_run
    assert "behavioral_checks" in not_run
    assert "not_verified" in not_run
    assert "report" in not_run
    assert "1. STATIC CHECKS:" in not_run["report"]
    assert "2. BEHAVIOURAL CHECKS:" in not_run["report"]
    assert "3. WHAT WAS NOT VERIFIED:" in not_run["report"]

    failed = create_failed_audit("SyntaxError in input")
    assert "static_checks" in failed
    assert "behavioral_checks" in failed
    assert "not_verified" in failed
    assert "report" in failed
    assert "1. STATIC CHECKS:" in failed["report"]
    assert "2. BEHAVIOURAL CHECKS:" in failed["report"]
    assert "3. WHAT WAS NOT VERIFIED:" in failed["report"]
