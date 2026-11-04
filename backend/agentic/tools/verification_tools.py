"""Verification, diffing, and audit tool adapters for Agentic AI Layer."""

from __future__ import annotations

import difflib
from typing import Any, Dict

from backend.code_improver import _definition_names
from backend.rules import apply_rules, summarize_quality
from backend.validator import validate_code, validate_generated_code


def verify_code_integrity_handler(args: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Verify that a candidate code string compiles cleanly and preserves all function/class symbols."""
    original = args.get("original_code")
    candidate = args.get("candidate_code")

    if not original and context and hasattr(context, "original_code"):
        original = context.original_code
    if not candidate and context and hasattr(context, "current_code"):
        candidate = context.current_code

    if not candidate:
        raise ValueError("Missing candidate code for verification.")
    original = original or candidate

    syntax_valid = validate_code(candidate) is True
    defs_original = _definition_names(original)
    defs_candidate = _definition_names(candidate)
    defs_preserved = defs_original == defs_candidate

    gen_val = validate_generated_code(original, candidate)

    return {
        "syntax_valid": syntax_valid,
        "definitions_preserved": defs_preserved,
        "missing_definitions": list(set(defs_original) - set(defs_candidate)),
        "added_definitions": list(set(defs_candidate) - set(defs_original)),
        "executable_code_preserved": gen_val.get("is_valid", False),
        "all_passed": syntax_valid and defs_preserved,
    }


def compute_unified_diff_handler(args: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Compute unified diff between original code and candidate code."""
    original = args.get("original_code")
    candidate = args.get("candidate_code")

    if not original and context and hasattr(context, "original_code"):
        original = context.original_code
    if not candidate and context and hasattr(context, "current_code"):
        candidate = context.current_code

    original_lines = (original or "").splitlines(keepends=True)
    candidate_lines = (candidate or "").splitlines(keepends=True)

    diff = list(
        difflib.unified_diff(
            original_lines,
            candidate_lines,
            fromfile=args.get("from_file", "original.py"),
            tofile=args.get("to_file", "candidate.py"),
            n=args.get("context_lines", 3),
        )
    )
    diff_text = "".join(diff)
    return {
        "has_changes": bool(diff_text.strip()),
        "diff": diff_text,
        "added_lines": sum(1 for line in diff if line.startswith("+") and not line.startswith("+++")),
        "removed_lines": sum(1 for line in diff if line.startswith("-") and not line.startswith("---")),
    }
