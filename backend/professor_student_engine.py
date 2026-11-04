"""Professor-Student Continuous Pedagogical Review & Remediation Loop."""

import difflib
import logging
from typing import Any, Dict, List, Optional

from backend.ast_analyzer import analyze_code
from backend.code_analysis import _fallback_comment_code
from backend.code_improver import _warnings_for, improve_code_quality
from backend.rules import summarize_quality
from backend.security_attack_agent import simulate_attacks
from backend.security_fixing_agent import fix_attack_vulnerabilities
from backend.validator import validate_code

logger = logging.getLogger(__name__)


class ProfessorStudentOrchestrator:
    """Orchestrates an iterative feedback loop between a Student generator and a Professor evaluator."""

    def __init__(self, model_client: Any = None, max_iterations: int = 5):
        self.model_client = model_client
        self.max_iterations = max(1, min(10, int(max_iterations or 5)))

    def _grade_from_score(self, score: int) -> str:
        if score >= 95:
            return "A+"
        if score >= 88:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 60:
            return "D"
        return "F"

    def professor_evaluate(self, code: str) -> Dict[str, Any]:
        """Strict pedagogical audit covering correctness, security, clarity, and style."""
        valid = validate_code(code)
        if valid is not True:
            return {
                "score": 0,
                "grade": "F",
                "critique": [f"Syntax Error: {valid}"],
                "passed": False,
                "security_findings": 1,
            }

        warnings = _warnings_for(code)
        quality = summarize_quality(warnings)
        base_score = quality["score"]

        # Run static security check
        sec_result = simulate_attacks(code, model_client=self.model_client)
        sec_findings = sec_result.get("vulnerabilities_detected", 0)

        # Inspect AST structure
        ast_data = analyze_code(code)
        functions_missing_docs = []
        for fn in ast_data.get("functions", []):
            if fn.get("complexity", 1) > 8:
                warnings.append({
                    "rule_id": "COMPLEX001",
                    "severity": "warning",
                    "message": f"High cyclomatic complexity in {fn.get('name')}() (CC={fn.get('complexity')})",
                })

        deductions = sec_findings * 25
        final_score = max(0, min(100, base_score - deductions))
        grade = self._grade_from_score(final_score)

        critiques = []
        if sec_findings > 0:
            critiques.append(
                f"Security Vulnerability: Identified {sec_findings} vulnerable sink(s). Neutralize immediately."
            )
        for w in warnings[:4]:
            critiques.append(f"{w.get('rule_id', 'Lint')}: {w.get('message')}")

        if not critiques and final_score >= 90:
            critiques.append("Exemplary code structure, clean docstrings, and robust security posture.")

        return {
            "score": final_score,
            "grade": grade,
            "critique": critiques,
            "passed": final_score >= 90 and sec_findings == 0,
            "security_findings": sec_findings,
            "warnings_count": len(warnings),
        }

    def student_revise(self, code: str, critique: List[str], iteration: int) -> str:
        """Student synthesizes improvements addressing the Professor's critique."""
        candidate = code

        # 1. Remediate security sinks if flagged
        if any("Security" in c for c in critique):
            fix_res = fix_attack_vulnerabilities(candidate, model_client=self.model_client)
            if fix_res.get("fixed") and fix_res.get("fixed_code"):
                candidate = fix_res["fixed_code"]

        # 2. Improve code quality / rules
        try:
            imp_res = improve_code_quality(candidate, model_client=self.model_client)
            if imp_res.get("improved") and imp_res.get("improved_code"):
                candidate = imp_res["improved_code"]
        except Exception as exc:
            logger.debug("Code improver step skipped: %s", exc)

        # 3. Add clean AST docstrings if lacking
        try:
            ast_info = analyze_code(candidate)
            doc_code = _fallback_comment_code(candidate, analysis=ast_info)
            if validate_code(doc_code) is True:
                candidate = doc_code
        except Exception:
            pass

        return candidate

    def run(self, source_code: str) -> Dict[str, Any]:
        """Execute the continuous feedback loop until approval or max_iterations reached."""
        valid = validate_code(source_code)
        if valid is not True:
            return {
                "status": "failed",
                "error": f"Initial code contains syntax errors: {valid}",
                "iterations": [],
            }

        history = []
        current_code = source_code

        for i in range(1, self.max_iterations + 1):
            eval_res = self.professor_evaluate(current_code)
            history.append({
                "iteration": i,
                "code": current_code,
                "score": eval_res["score"],
                "grade": eval_res["grade"],
                "passed": eval_res["passed"],
                "critique": eval_res["critique"],
            })

            if eval_res["passed"] or i >= self.max_iterations:
                break

            revised = self.student_revise(current_code, eval_res["critique"], i)
            if revised == current_code:
                # No further automated revision possible
                break
            current_code = revised

        final_eval = history[-1]
        diff = "\n".join(
            difflib.unified_diff(
                source_code.splitlines(),
                current_code.splitlines(),
                fromfile="Initial Submission",
                tofile="Professor Approved",
                lineterm="",
            )
        )

        return {
            "status": "completed",
            "iterations_count": len(history),
            "approved": final_eval["passed"],
            "initial_code": source_code,
            "final_code": current_code,
            "final_grade": final_eval["grade"],
            "final_score": final_eval["score"],
            "code_modified": current_code != source_code,
            "diff": diff,
            "iterations": history,
            "summary": (
                f"Professor evaluated submission over {len(history)} iteration(s): "
                f"Final Grade {final_eval['grade']} ({final_eval['score']}/100)."
            ),
        }
