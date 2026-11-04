"""Coordinate code optimization, static security analysis, remediation, and verification."""

import difflib
import logging
from typing import Any

from backend.code_improver import _definition_names, _warnings_for
from backend.optimization_agent import optimize_code
from backend.rules import summarize_quality
from backend.security_attack_agent import simulate_attacks
from backend.security_fixing_agent import fix_attack_vulnerabilities
from backend.validator import validate_code

logger = logging.getLogger(__name__)


def run_multi_agent_workflow(source_code: str, model_client: Any = None) -> dict[str, Any]:
    """Run optimization, static security checks, remediation, and verification."""
    valid = validate_code(source_code)
    if valid is not True:
        raise ValueError(f"Invalid Python source code: {valid}")

    initial_warnings = _warnings_for(source_code)
    initial_quality = summarize_quality(initial_warnings)
    initial_score = initial_quality["score"]

    timeline = []

    # -------------------------------------------------------------
    # STAGE 1: Code Optimization AI Agent
    # -------------------------------------------------------------
    opt_result = optimize_code(source_code, model_client=model_client)
    timeline.append({
        "stage": 1,
        "agent": "AI Code Optimization Agent",
        "action": "AST Performance & Algorithmic Complexity Analysis",
        "status": "completed",
        "details": (
            f"Complexity transition: {opt_result['complexity_before']} -> {opt_result['complexity_after']}. "
            f"Estimated speedup: {opt_result['estimated_speedup']}. "
            f"Found {opt_result['opportunities_found']} optimization opportunity(ies)."
        ),
        "code_modified": opt_result["optimized"],
    })

    # The code to carry into security evaluation is the optimized code (or original if no opt)
    working_code = opt_result["optimized_code"] if opt_result["optimized"] else source_code

    # -------------------------------------------------------------
    # STAGE 2: Static security assessment
    # -------------------------------------------------------------
    sim_result = simulate_attacks(working_code, model_client=model_client)
    timeline.append({
        "stage": 2,
        "agent": "Static Python Security Analyzer",
        "action": "AST-based security checks; source code is not executed",
        "status": "completed",
        "details": (
            f"Completed {sim_result['total_checks_run']} static checks. "
            f"Identified {sim_result['vulnerabilities_detected']} potential finding(s). "
            f"Static risk score: {sim_result['resilience_score']}/100."
        ),
        "vulnerabilities_found": sim_result["vulnerabilities_detected"],
    })

    # -------------------------------------------------------------
    # STAGE 3: Security Fixing & Remediation AI Agent (Blue Team)
    # -------------------------------------------------------------
    fix_result = fix_attack_vulnerabilities(
        working_code,
        attack_simulation=sim_result,
        model_client=model_client,
    )
    timeline.append({
        "stage": 3,
        "agent": "AI Security Fixing & Remediation Agent (Blue Team)",
        "action": "Defensive remediation of reported static findings",
        "status": "completed",
        "details": (
            f"Addressed {fix_result.get('neutralized_count', 0)} reported finding(s). "
            f"Applied defensive controls: {', '.join(fix_result.get('defensive_controls', [])) or 'None required'}. "
            f"Post-remediation static risk score: {fix_result.get('post_fix_resilience_score', 100)}/100."
        ),
        "code_modified": fix_result.get("fixed", False),
    })

    final_code = fix_result["fixed_code"] if fix_result["fixed"] else working_code

    # -------------------------------------------------------------
    # STAGE 4: Verification & Audit Agent
    # -------------------------------------------------------------
    final_warnings = _warnings_for(final_code)
    final_quality = summarize_quality(final_warnings)
    final_score = final_quality["score"]

    final_sim = simulate_attacks(final_code)
    is_resilient = final_sim["vulnerabilities_detected"] == 0
    syntax_is_valid = validate_code(final_code) is True
    defs_preserved = _definition_names(final_code) == _definition_names(source_code)
    all_passed = is_resilient and syntax_is_valid and defs_preserved

    verifier_result = {
        "agent": "verification_agent",
        "agent_name": "AI Verification & Synthesis Agent",
        "status": "completed",
        "action": "AST Integrity, Security Non-Regression & Quality Audit",
        "syntax_valid": syntax_is_valid,
        "definitions_preserved": defs_preserved,
        "all_checks_passed": all_passed,
        "initial_quality_score": initial_score,
        "final_quality_score": final_score,
        "quality_delta": final_score - initial_score,
        "initial_resilience_score": sim_result["resilience_score"],
        "final_resilience_score": final_sim["resilience_score"],
        "resilience_delta": final_sim["resilience_score"] - sim_result["resilience_score"],
        "audit_report": {
            "code_integrity_verified": defs_preserved and syntax_is_valid,
            "security_regressions": final_sim["vulnerabilities_detected"],
            "remaining_vulnerabilities": final_sim["vulnerabilities_detected"],
            "optimizations_retained": len(opt_result.get("optimizations_applied", [])),
            "findings_remediated": fix_result.get("neutralized_count", 0),
        },
    }

    timeline.append({
        "stage": 4,
        "agent": "AI Verification & Synthesis Agent",
        "action": "AST Integrity, Security Non-Regression & Quality Audit",
        "status": "completed",
        "details": (
            f"Final quality score: {initial_score}/100 -> {final_score}/100. "
            f"Final security resilience: {final_sim['resilience_score']}/100. "
            f"Syntax valid: {syntax_is_valid}, Definitions preserved: {defs_preserved}."
        ),
        "all_checks_passed": all_passed,
    })

    # Generate unified diff showing complete modifications made across pipeline
    diff_lines = list(difflib.unified_diff(
        source_code.splitlines(keepends=True),
        final_code.splitlines(keepends=True),
        fromfile="original.py",
        tofile="hardened_optimized.py",
        n=3,
    ))
    diff_text = "".join(diff_lines)

    benchmark_statistics = {
        "before": {
            "quality_score": initial_score,
            "resilience_score": sim_result["resilience_score"],
            "vulnerabilities": sim_result["vulnerabilities_detected"],
            "algorithmic_complexity": opt_result.get("complexity_before", "N/A"),
            "critical_risks": sim_result.get("risk_breakdown", {}).get("critical", 0),
            "high_risks": sim_result.get("risk_breakdown", {}).get("high", 0),
        },
        "after": {
            "quality_score": final_score,
            "resilience_score": final_sim["resilience_score"],
            "vulnerabilities": final_sim["vulnerabilities_detected"],
            "algorithmic_complexity": opt_result.get("complexity_after", "N/A"),
            "critical_risks": final_sim.get("risk_breakdown", {}).get("critical", 0),
            "high_risks": final_sim.get("risk_breakdown", {}).get("high", 0),
        },
        "improvements": {
            "quality_delta": final_score - initial_score,
            "resilience_delta": final_sim["resilience_score"] - sim_result["resilience_score"],
            "findings_remediated": fix_result.get("neutralized_count", 0),
            "speedup_factor": opt_result.get("estimated_speedup", "1.0x"),
        },
    }

    return {
        "workflow": "multi_agent_collaboration",
        "status": "completed",
        "initial_code": source_code,
        "optimized_code": opt_result["optimized_code"],
        "final_hardened_code": final_code,
        "code_changed": final_code.strip() != source_code.strip(),
        "diff": diff_text,
        "summary": {
            "initial_quality_score": initial_score,
            "final_quality_score": final_score,
            "initial_resilience_score": sim_result["resilience_score"],
            "final_resilience_score": final_sim["resilience_score"],
            "optimizations_applied": len(opt_result["optimizations_applied"]),
            "static_checks_run": sim_result["total_checks_run"],
            "findings_remediated": fix_result["neutralized_count"],
            "remaining_vulnerabilities": final_sim["vulnerabilities_detected"],
            "overall_health": (
                "No Static Findings (not a security certification)"
                if is_resilient
                else "Potential Findings Remain"
            ),
            "benchmark_statistics": benchmark_statistics,
        },
        "agents": {
            "optimizer": opt_result,
            "attack_simulator": sim_result,
            "security_fixer": fix_result,
            "verifier": verifier_result,
        },
        "timeline": timeline,
    }
