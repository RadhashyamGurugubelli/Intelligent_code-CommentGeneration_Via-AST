"""Tests for the Centralized Provider Adapter."""

from __future__ import annotations

from unittest.mock import MagicMock, patch
import pytest

from backend.agentic.provider_adapter import (
    ProviderAdapter,
    ProviderAdapterError,
    redact_secrets,
)
from backend.agentic.session import AgentSession


class TestRedactSecrets:
    def test_redact_bearer_tokens(self):
        raw = "Error 401: Invalid Bearer sk-ant-api03-abcdef1234567890xyz"
        redacted = redact_secrets(raw)
        assert "sk-ant" not in redacted
        assert "[REDACTED_SECRET]" in redacted

    def test_redact_api_key_query_or_kv(self):
        raw = "Failed with api_key='sk-proj-999888777666555' in url"
        redacted = redact_secrets(raw)
        assert "999888777" not in redacted
        assert "[REDACTED_SECRET]" in redacted

    def test_noop_on_normal_strings(self):
        text = "Provider request timed out after 30 seconds."
        assert redact_secrets(text) == text


class TestProviderAdapter:
    def test_provider_info_ast_provider(self):
        with patch("backend.agentic.provider_adapter.AppConfig.AI_PROVIDER", "ast"):
            adapter = ProviderAdapter(provider_id="ast")
            info = adapter.get_provider_info()
            assert info["id"] == "ast"
            assert info["ready"] is True
            assert info["model_execution_ready"] is False

    def test_provider_info_openai_ready(self):
        adapter = ProviderAdapter(provider_id="openai")
        mock_client = MagicMock()
        mock_client.chat = MagicMock()
        with patch.object(adapter, "is_provider_ready", return_value=True), \
             patch.object(adapter, "is_model_execution_ready", return_value=True):
            info = adapter.get_provider_info(mock_client)
            assert info["id"] == "openai"
            assert info["ready"] is True
            assert info["model_execution_ready"] is True

    def test_execute_completion_success_and_session_recording(self):
        adapter = ProviderAdapter(provider_id="openai")
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.choices = [MagicMock(message=MagicMock(content="Hello response"))]
        mock_client.chat.completions.create.return_value = mock_resp

        session = AgentSession(
            session_id="test_adapter_sess",
            original_code="x = 1",
            original_code_digest="abc",
            current_code="x = 1",
            task="test task",
        )
        assert session.metadata.get("model_call_count", 0) == 0

        resp = adapter.execute_completion(
            client=mock_client,
            messages=[{"role": "user", "content": "hi"}],
            session=session,
        )
        assert resp == mock_resp
        assert session.metadata.get("model_call_count") == 1
        mock_client.chat.completions.create.assert_called_once()

    def test_execute_completion_rate_limit_error(self):
        adapter = ProviderAdapter(provider_id="openai")
        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = RuntimeError(
            "HTTP 429 Too Many Requests: Rate limit exceeded with Bearer sk-secret12345678"
        )

        with pytest.raises(ProviderAdapterError) as exc_info:
            adapter.execute_completion(
                client=mock_client,
                messages=[{"role": "user", "content": "hi"}],
            )
        err = exc_info.value
        assert err.status_code == 429
        assert "rate-limited" in str(err).lower()
        assert "sk-secret" not in str(err)

    def test_execute_completion_auth_error_redaction(self):
        adapter = ProviderAdapter(provider_id="openai")
        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = RuntimeError(
            "401 Unauthorized: token sk-supersecret-token-value-12345 is invalid"
        )

        with pytest.raises(ProviderAdapterError) as exc_info:
            adapter.execute_completion(
                client=mock_client,
                messages=[{"role": "user", "content": "hi"}],
            )
        err = exc_info.value
        assert err.status_code == 502
        assert "supersecret" not in str(err)
        assert "rejected the configured token" in str(err)

    def test_as_chat_client_interface(self):
        adapter = ProviderAdapter(provider_id="openai")
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_client.chat.completions.create.return_value = mock_resp

        proxy = adapter.as_chat_client(mock_client)
        assert hasattr(proxy, "chat")
        assert hasattr(proxy.chat, "completions")
        assert hasattr(proxy.chat.completions, "create")

        res = proxy.chat.completions.create(messages=[{"role": "user", "content": "test"}])
        assert res == mock_resp
