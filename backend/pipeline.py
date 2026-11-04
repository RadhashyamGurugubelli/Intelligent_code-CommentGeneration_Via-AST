"""Orchestrates analysis, code generation, and scoring."""

from backend.ast_analyzer import analyze_code
from backend.code_analysis import generate_commented_code
from backend.model_provider import provider_display_name
from backend.rules import apply_rules, build_review_score, summarize_quality
from backend.validator import validate_generated_code


def run_pipeline(source_code: str, analysis: dict | None = None) -> dict:
    """Analyze source, generate comments, and score findings.

    Routes may pass an existing analysis when they have already performed
    preflight checks, avoiding a second AST walk for the same source.
    """
    if analysis is None:
        analysis = analyze_code(source_code)

    warnings = analysis.get("warnings")
    if warnings is None:
        warnings = apply_rules(analysis)
    analysis["warnings"] = warnings

    commented_code, method = generate_commented_code(source_code, analysis)
    validation = validate_generated_code(source_code, commented_code)
    if method == "ast" and analysis.get("type_errors"):
        generation_notice = (
            "Definite type errors were detected, so deterministic AST comments "
            "were used instead of AI-generated comments."
        )
    elif method == "ast":
        generation_notice = (
            "The AI provider was unavailable or returned unusable comments, "
            "so detailed deterministic AST comments were generated instead."
        )
        generation_notice += (
            " Check the API key and provider credits to restore AI-generated "
            "comments."
        )
    else:
        generation_notice = None

    quality_summary = summarize_quality(warnings)
    quality_score = quality_summary["score"]
    review_score = build_review_score(warnings)

    return {
        "commented_code": commented_code,
        "source": source_code,
        "quality_score": quality_score,
        "quality_summary": quality_summary,
        "review_score": review_score,
        "analysis": analysis,
        "validation": validation,
        "method": method,
        "generation_notice": generation_notice,
    }
