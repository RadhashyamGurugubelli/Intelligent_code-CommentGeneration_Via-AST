"""Pre-configured standard tool catalog for the Agentic AI Layer."""

from __future__ import annotations

from backend.agentic.tools.ast_tools import (
    explain_ast_semantics_handler,
    infer_type_errors_handler,
    inspect_ast_structure_handler,
    inspect_undefined_names_handler,
)
from backend.agentic.tools.optimization_tools import (
    detect_optimization_targets_handler,
    synthesize_optimization_handler,
)
from backend.agentic.tools.registry import ToolDefinition, ToolRegistry
from backend.agentic.tools.security_tools import (
    evaluate_attack_guardrail_handler,
    probe_security_vulnerabilities_handler,
    synthesize_defensive_patch_handler,
)
from backend.agentic.tools.verification_tools import (
    compute_unified_diff_handler,
    verify_code_integrity_handler,
)


def create_standard_tool_registry() -> ToolRegistry:
    """Build and return a ToolRegistry populated with all allowlisted AST tools."""
    registry = ToolRegistry()

    # 1. Structure & AST Inspection
    registry.register(
        ToolDefinition(
            name="inspect_ast_structure",
            description="Inspect AST structural breakdown: functions, classes, imports, call count, and cyclomatic complexity.",
            parameters_schema={
                "type": "object",
                "properties": {
                    "source_code": {
                        "type": "string",
                        "description": "Optional Python code override. If omitted, uses active code from context.",
                    }
                },
                "required": [],
            },
            handler=inspect_ast_structure_handler,
            is_read_only=True,
        )
    )

    # 2. Definite Type Inference
    registry.register(
        ToolDefinition(
            name="infer_type_errors",
            description="Statically detect definite type collisions (e.g. incompatible operations) without running code.",
            parameters_schema={
                "type": "object",
                "properties": {
                    "source_code": {
                        "type": "string",
                        "description": "Optional Python code override.",
                    }
                },
                "required": [],
            },
            handler=infer_type_errors_handler,
            is_read_only=True,
        )
    )

    # 3. AST Semantic Explanations
    registry.register(
        ToolDefinition(
            name="explain_ast_semantics",
            description="Generate deterministic, AST-grounded explanations of control flow, recursion, and key logic steps.",
            parameters_schema={
                "type": "object",
                "properties": {
                    "source_code": {
                        "type": "string",
                        "description": "Optional Python code override.",
                    }
                },
                "required": [],
            },
            handler=explain_ast_semantics_handler,
            is_read_only=True,
        )
    )

    # 4. Undefined Names
    registry.register(
        ToolDefinition(
            name="inspect_undefined_names",
            description="Check for undefined variables, missing imports, or unresolved function identifiers.",
            parameters_schema={
                "type": "object",
                "properties": {
                    "source_code": {
                        "type": "string",
                        "description": "Optional Python code override.",
                    }
                },
                "required": [],
            },
            handler=inspect_undefined_names_handler,
            is_read_only=True,
        )
    )

    # 5. Security Vulnerability Probing (Red Team)
    registry.register(
        ToolDefinition(
            name="probe_security_vulnerabilities",
            description="Audit source code statically for 7 CWE vulnerability classes (SQLi, command injection, path traversal, insecure deserialization, SSRF, XXE, ReDoS) without code execution.",
            parameters_schema={
                "type": "object",
                "properties": {
                    "source_code": {
                        "type": "string",
                        "description": "Optional Python code override.",
                    }
                },
                "required": [],
            },
            handler=probe_security_vulnerabilities_handler,
            is_read_only=True,
        )
    )

    # 6. Defensive Security Patching (Blue Team)
    registry.register(
        ToolDefinition(
            name="synthesize_defensive_patch",
            description="Synthesize defensive patches for reported security findings (e.g. parameterized queries, safe regex bounds). Requires approval before applying.",
            parameters_schema={
                "type": "object",
                "properties": {
                    "source_code": {
                        "type": "string",
                        "description": "Optional Python code override.",
                    }
                },
                "required": [],
            },
            handler=synthesize_defensive_patch_handler,
            is_read_only=False,
            requires_approval=True,
        )
    )

    # 7. Attack Guardrail Evaluation
    registry.register(
        ToolDefinition(
            name="evaluate_attack_guardrail",
            description="Evaluate prompt or source code against deterministic adversarial prompt-injection and data exfiltration guards.",
            parameters_schema={
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "description": "Prompt text or source code to evaluate.",
                    },
                    "content_type": {
                        "type": "string",
                        "description": "Either 'prompt' or 'code'.",
                    },
                },
                "required": [],
            },
            handler=evaluate_attack_guardrail_handler,
            is_read_only=True,
        )
    )

    # 8. Optimization Bottlenecks Detection
    registry.register(
        ToolDefinition(
            name="detect_optimization_targets",
            description="Detect algorithmic and memory optimization opportunities (quadratic loops, redundant dictionary lookups, eager comprehensions).",
            parameters_schema={
                "type": "object",
                "properties": {
                    "source_code": {
                        "type": "string",
                        "description": "Optional Python code override.",
                    }
                },
                "required": [],
            },
            handler=detect_optimization_targets_handler,
            is_read_only=True,
        )
    )

    # 9. Synthesize Optimizations
    registry.register(
        ToolDefinition(
            name="synthesize_optimization",
            description="Propose algorithmic complexity and speedup optimizations. Requires approval before applying.",
            parameters_schema={
                "type": "object",
                "properties": {
                    "source_code": {
                        "type": "string",
                        "description": "Optional Python code override.",
                    }
                },
                "required": [],
            },
            handler=synthesize_optimization_handler,
            is_read_only=False,
            requires_approval=True,
        )
    )

    # 10. Code Integrity Verification
    registry.register(
        ToolDefinition(
            name="verify_code_integrity",
            description="Verify Python AST validity, syntax correctness, and function/class definition preservation.",
            parameters_schema={
                "type": "object",
                "properties": {
                    "original_code": {
                        "type": "string",
                        "description": "Original Python source code.",
                    },
                    "candidate_code": {
                        "type": "string",
                        "description": "Modified candidate Python source code.",
                    },
                },
                "required": [],
            },
            handler=verify_code_integrity_handler,
            is_read_only=True,
        )
    )

    # 11. Compute Unified Diff
    registry.register(
        ToolDefinition(
            name="compute_unified_diff",
            description="Compute unified diff between original code and candidate code.",
            parameters_schema={
                "type": "object",
                "properties": {
                    "original_code": {
                        "type": "string",
                        "description": "Original Python code.",
                    },
                    "candidate_code": {
                        "type": "string",
                        "description": "Modified Python code.",
                    },
                },
                "required": [],
            },
            handler=compute_unified_diff_handler,
            is_read_only=True,
        )
    )

    return registry


__all__ = [
    "ToolDefinition",
    "ToolRegistry",
    "create_standard_tool_registry",
]
