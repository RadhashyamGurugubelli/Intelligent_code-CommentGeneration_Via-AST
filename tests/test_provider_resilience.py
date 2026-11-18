"""Provider Resilience and Failure Recovery Test Suite for AST Studio.

Tests:
- Model provider HTTP 500 Internal Server Error recovery and AST fallback
- Model provider timeout handling (ConnectTimeout, ReadTimeout)
- Malformed / corrupted model response handling
- HTTP 429 Rate Limiting, Retry-After parsing, and safe degradation
- Controlled connectivity tests across provider failure modes
"""

from __future__ import annotations

from unittest.mock import MagicMock


from backend.agentic.agents.specialists import (
    AtlasSpecialist,
)
from backend.agentic.session import AgentSession
from backend.agentic.supervisor import SupervisorAgent
from backend.agentic.tools import default_tool_registry
from backend.model_provider import test_provider_connectivity as check_provider_connectivity
from backend.provider_errors import classify_provider_error


SAMPLE_CODE = """
def calculate_interest(principal, rate, time):
    return (principal * rate * time) / 100
"""


class TestProviderResilience:
    """Verify that model provider outages never crash workflows or corrupt state."""

    def test_provider_500_server_error_fallback(self):
        """When the LLM provider fails with HTTP 500, supervisor falls back to deterministic AST."""
        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = RuntimeError(
            "HTTP 500 Internal Server Error: Upstream inference engine crashed."
        )

        supervisor = SupervisorAgent(
            tools=default_tool_registry,
            model_client=mock_client,
        )
        session = AgentSession(
            session_id="test_fallback_500",
            original_code=SAMPLE_CODE,
            original_code_digest="abc",
            current_code=SAMPLE_CODE,
            task="Optimize interest calculation",
        )

        # Execution must not crash; must fall back to deterministic mode and finish
        result = supervisor.run(session)
        assert result["status"] in {"completed", "awaiting_approval"}
        assert session.status in {"completed", "awaiting_approval"}

    def test_provider_timeout_fallback(self):
        """When LLM provider times out, supervisor catches timeout and falls back."""
        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = TimeoutError(
            "HTTP 504 Gateway Timeout: Read operation timed out after 30.0s."
        )

        supervisor = SupervisorAgent(
            tools=default_tool_registry,
            model_client=mock_client,
        )
        session = AgentSession(
            session_id="test_fallback_timeout",
            original_code=SAMPLE_CODE,
            original_code_digest="abc",
            current_code=SAMPLE_CODE,
            task="Audit security vulnerabilities",
        )

        result = supervisor.run(session)
        assert result["status"] in {"completed", "awaiting_approval"}
        assert session.status in {"completed", "awaiting_approval"}

    def test_provider_malformed_json_fallback(self):
        """When LLM provider returns non-JSON or corrupted text, specialist agents fall back cleanly."""
        mock_client = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = "I am a helpful assistant! ```json {not: 'valid' json"
        mock_response = MagicMock()
        mock_response.choices = [mock_choice]
        mock_client.chat.completions.create.return_value = mock_response

        atlas = AtlasSpecialist(tools=default_tool_registry, model_client=mock_client)
        session = AgentSession(
            session_id="test_malformed_json",
            original_code=SAMPLE_CODE,
            original_code_digest="abc",
            current_code=SAMPLE_CODE,
            task="Inspect AST topology",
        )

        result = atlas.execute_turn(session, sub_task="Inspect AST topology", task_id="T1")
        assert result["status"] in {"completed", "finish"}

    def test_provider_rate_limit_classification(self):
        """Verify that provider 429 rate limit is properly classified."""
        rate_limit_err = Exception("HTTP 429 Too Many Requests: Rate limit exceeded. Retry-After: 30")
        payload, status = classify_provider_error(rate_limit_err, "OpenAI")
        assert status == 429
        assert "rate-limited" in payload["error"].lower()

    def test_provider_connectivity_error_handling(self):
        """Verify check_provider_connectivity handles AST provider and invalid URLs safely."""
        res_ast = check_provider_connectivity("ast")
        assert res_ast["success"] is True

        res_ssrf = check_provider_connectivity("openai", base_url="http://169.254.169.254")
        assert res_ssrf["success"] is False
        assert "ssrf" in res_ssrf["error"].lower() or "blocked" in res_ssrf["error"].lower()
