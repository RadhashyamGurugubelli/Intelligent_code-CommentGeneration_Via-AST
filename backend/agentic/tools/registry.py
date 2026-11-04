"""Unified Tool Registry and standard schema definitions for Agentic AI Layer."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from time import perf_counter
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class ToolExecutionError(Exception):
    """Raised when an allowlisted tool fails during execution."""


@dataclass
class ToolDefinition:
    """Specification of an allowlisted, executable agent tool."""

    name: str
    description: str
    parameters_schema: Dict[str, Any]
    handler: Callable[[Dict[str, Any], Any], Dict[str, Any]]
    is_read_only: bool = True
    requires_approval: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_function_schema(self) -> Dict[str, Any]:
        """Convert into standard OpenAI/Copilot function-calling format."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters_schema,
            },
        }


class ToolRegistry:
    """Thread-safe registry of allowlisted agent tools."""

    def __init__(self) -> None:
        self._tools: Dict[str, ToolDefinition] = {}

    def register(self, tool: ToolDefinition) -> None:
        """Register a new tool definition."""
        if not tool.name or not isinstance(tool.name, str):
            raise ValueError("Tool name must be a non-empty string.")
        if not callable(tool.handler):
            raise ValueError(f"Tool handler for '{tool.name}' must be callable.")
        self._tools[tool.name] = tool
        logger.debug("Registered tool: %s (read_only=%s)", tool.name, tool.is_read_only)

    def get(self, name: str) -> Optional[ToolDefinition]:
        """Fetch a registered tool by identifier."""
        return self._tools.get(name)

    def list_tools(self) -> List[ToolDefinition]:
        """Return all registered tools."""
        return list(self._tools.values())

    def get_tool_schemas(self) -> List[Dict[str, Any]]:
        """Return all tool schemas in function-calling format."""
        return [t.to_function_schema() for t in self._tools.values()]

    def validate_arguments(self, tool: ToolDefinition, args: Dict[str, Any]) -> List[str]:
        """Validate input arguments against declared schema properties."""
        errors: List[str] = []
        schema = tool.parameters_schema or {}
        properties = schema.get("properties", {})
        required = schema.get("required", [])

        # Check required fields
        for req in required:
            if req not in args or args[req] is None:
                errors.append(f"Missing required parameter: '{req}'")

        # Basic type checking
        type_map = {
            "string": str,
            "integer": int,
            "number": (int, float),
            "boolean": bool,
            "array": list,
            "object": dict,
        }

        for param_name, param_val in args.items():
            if param_name in properties:
                expected_type_str = properties[param_name].get("type")
                if expected_type_str in type_map:
                    expected_type = type_map[expected_type_str]
                    if not isinstance(param_val, expected_type):
                        errors.append(
                            f"Parameter '{param_name}' expected type '{expected_type_str}', "
                            f"got '{type(param_val).__name__}'."
                        )
        return errors

    def execute(
        self,
        name: str,
        arguments: Optional[Dict[str, Any]] = None,
        context: Any = None,
    ) -> Dict[str, Any]:
        """Execute a registered tool within sandboxed error handling and latency tracking."""
        args = arguments or {}
        if name not in self._tools:
            return {
                "status": "error",
                "tool": name,
                "error": f"Tool '{name}' is not in the allowlisted registry.",
                "execution_time_ms": 0.0,
            }

        tool = self._tools[name]
        validation_errors = self.validate_arguments(tool, args)
        if validation_errors:
            return {
                "status": "error",
                "tool": name,
                "error": "Argument validation failed: " + "; ".join(validation_errors),
                "validation_errors": validation_errors,
                "execution_time_ms": 0.0,
            }

        # Check Human-in-the-Loop approval gate
        is_approved = getattr(context, "is_approved", False) if context else False
        if tool.requires_approval and not is_approved:
            return {
                "status": "pending_approval",
                "tool": name,
                "arguments": args,
                "message": f"Action '{name}' requires human approval before proceeding.",
                "execution_time_ms": 0.0,
            }

        started_at = perf_counter()
        try:
            result = tool.handler(args, context)
            latency_ms = round((perf_counter() - started_at) * 1000, 3)
            return {
                "status": "success",
                "tool": name,
                "result": result,
                "is_read_only": tool.is_read_only,
                "execution_time_ms": latency_ms,
            }
        except Exception as exc:
            latency_ms = round((perf_counter() - started_at) * 1000, 3)
            logger.exception("Execution of tool '%s' raised an exception: %s", name, exc)
            return {
                "status": "error",
                "tool": name,
                "error": str(exc),
                "error_type": type(exc).__name__,
                "execution_time_ms": latency_ms,
            }
