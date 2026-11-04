"""Shared Hugging Face, local Ollama, and GitHub Copilot model configuration."""

import json
import logging
import os
import subprocess
from types import SimpleNamespace
from urllib import request as urllib_request
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import urlopen

from backend.config import AppConfig

try:
    from huggingface_hub import InferenceClient
except ImportError:  # pragma: no cover
    InferenceClient = None

logger = logging.getLogger(__name__)


def _get_active_model_name():
    p = AppConfig.AI_PROVIDER
    if p == "copilot":
        return AppConfig.COPILOT_MODEL
    if p == "openai":
        return AppConfig.OPENAI_MODEL
    if p == "gemini":
        return AppConfig.GEMINI_MODEL
    if p == "groq":
        return AppConfig.GROQ_MODEL
    if p == "anthropic":
        return AppConfig.ANTHROPIC_MODEL
    if p == "ollama":
        return AppConfig.OLLAMA_MODEL
    if p == "ast":
        return "Deterministic AST"
    return AppConfig.HF_MODEL


MODEL_NAME = _get_active_model_name()


class ModelRequestError(RuntimeError):
    def __init__(self, message, status_code=None):
        super().__init__(message)
        self.response = SimpleNamespace(status_code=status_code)


class CopilotRequestError(ModelRequestError):
    pass


class OpenAICompatibleCompletions:
    def __init__(self, api_key, base_url, model_name, custom_headers=None, timeout=120):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model_name = model_name
        self.custom_headers = custom_headers or {}
        self.timeout = timeout

    def create(self, **kwargs):
        if not self.api_key and "ollama" not in self.base_url:
            raise ModelRequestError("API key is not configured for this provider.", 401)

        payload = {
            "model": kwargs.get("model") or self.model_name,
            "messages": kwargs.get("messages", []),
            "temperature": kwargs.get("temperature", 0.1),
            "max_tokens": kwargs.get("max_tokens", 1500),
        }
        extra_body = kwargs.get("extra_body", {})
        if isinstance(extra_body, dict):
            payload.update(
                {
                    key: value
                    for key, value in extra_body.items()
                    if key != "chat_template_kwargs"
                }
            )

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        headers.update(self.custom_headers)

        endpoint = f"{self.base_url}/chat/completions"
        data = json.dumps(payload).encode("utf-8")
        req = urllib_request.Request(endpoint, data=data, headers=headers, method="POST")
        try:
            with urllib_request.urlopen(req, timeout=self.timeout) as response:
                body = response.read().decode("utf-8")
                result = json.loads(body)
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise ModelRequestError(
                f"Provider request failed: {detail or exc.reason}",
                getattr(exc, "code", None),
            ) from exc
        except (URLError, TimeoutError, ValueError) as exc:
            raise ModelRequestError(
                f"Provider request failed: {exc}",
                None,
            ) from exc

        choice = (result.get("choices") or [{}])[0]
        message = choice.get("message") or {}
        content = message.get("content") or ""
        if isinstance(content, list):
            parts = []
            for part in content:
                if isinstance(part, dict):
                    text = part.get("text") or part.get("content") or ""
                    if isinstance(text, str):
                        parts.append(text)
                elif isinstance(part, str):
                    parts.append(part)
            content = "".join(parts)
        if not isinstance(content, str):
            content = str(content)
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=content))]
        )


class CopilotCompletions(OpenAICompatibleCompletions):
    def __init__(self, api_key, base_url, model_name):
        super().__init__(
            api_key=api_key,
            base_url=base_url,
            model_name=model_name,
            custom_headers={
                "Editor-Version": "vscode/1.0",
                "Copilot-Integration-Id": "vscode-chat",
            },
            timeout=180,
        )


class AnthropicCompletions:
    def __init__(self, api_key, base_url, model_name, timeout=120):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model_name = model_name
        self.timeout = timeout

    def create(self, **kwargs):
        if not self.api_key:
            raise ModelRequestError("Anthropic API key is not configured.", 401)

        messages = kwargs.get("messages", [])
        system_content = ""
        user_messages = []
        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            if role == "system":
                system_content = content
            else:
                user_messages.append({"role": role, "content": content})

        payload = {
            "model": kwargs.get("model") or self.model_name,
            "messages": user_messages or [{"role": "user", "content": "Hello"}],
            "max_tokens": kwargs.get("max_tokens", 1500),
            "temperature": kwargs.get("temperature", 0.1),
        }
        if system_content:
            payload["system"] = system_content

        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
            "accept": "application/json",
        }
        endpoint = f"{self.base_url}/messages"
        data = json.dumps(payload).encode("utf-8")
        req = urllib_request.Request(endpoint, data=data, headers=headers, method="POST")
        try:
            with urllib_request.urlopen(req, timeout=self.timeout) as response:
                body = response.read().decode("utf-8")
                result = json.loads(body)
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise ModelRequestError(
                f"Anthropic request failed: {detail or exc.reason}",
                getattr(exc, "code", None),
            ) from exc
        except (URLError, TimeoutError, ValueError) as exc:
            raise ModelRequestError(
                f"Anthropic request failed: {exc}",
                None,
            ) from exc

        content_parts = result.get("content", [])
        text_parts = [p.get("text", "") for p in content_parts if isinstance(p, dict)]
        content = "".join(text_parts)
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=content))]
        )


class CopilotClient:
    def __init__(self, api_key, base_url, model_name):
        self.chat = SimpleNamespace(
            completions=CopilotCompletions(api_key, base_url, model_name)
        )


class UniversalClient:
    def __init__(self, completions_obj):
        self.chat = SimpleNamespace(completions=completions_obj)


def _resolve_copilot_token():
    token = AppConfig.API_KEY.strip() if AppConfig.API_KEY else ""
    if token:
        return token
    for cmd in (("gh", "auth", "token"), ("github-copilot-cli", "auth", "token")):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        except FileNotFoundError:
            continue
        if result.returncode == 0:
            token = result.stdout.strip()
            if token:
                return token
    return ""


def create_model_client(provider_override=None, api_key_override=None, model_override=None):
    """Create the configured provider client."""
    provider = (provider_override or AppConfig.AI_PROVIDER).strip().lower()
    api_key = api_key_override or AppConfig.API_KEY

    if provider == "ast":
        return None

    if provider == "copilot":
        token = api_key_override or _resolve_copilot_token()
        if not token:
            return None
        return CopilotClient(
            api_key=token,
            base_url=AppConfig.COPILOT_BASE_URL,
            model_name=model_override or AppConfig.COPILOT_MODEL,
        )

    if provider == "openai":
        key = api_key or AppConfig.OPENAI_API_KEY
        if not key:
            return None
        return UniversalClient(
            OpenAICompatibleCompletions(
                api_key=key,
                base_url=AppConfig.OPENAI_BASE_URL,
                model_name=model_override or AppConfig.OPENAI_MODEL,
            )
        )

    if provider == "gemini":
        key = api_key or AppConfig.GEMINI_API_KEY
        if not key:
            return None
        return UniversalClient(
            OpenAICompatibleCompletions(
                api_key=key,
                base_url=AppConfig.GEMINI_BASE_URL,
                model_name=model_override or AppConfig.GEMINI_MODEL,
            )
        )

    if provider == "groq":
        key = api_key or AppConfig.GROQ_API_KEY
        if not key:
            return None
        return UniversalClient(
            OpenAICompatibleCompletions(
                api_key=key,
                base_url=AppConfig.GROQ_BASE_URL,
                model_name=model_override or AppConfig.GROQ_MODEL,
            )
        )

    if provider == "anthropic":
        key = api_key or AppConfig.ANTHROPIC_API_KEY
        if not key:
            return None
        return UniversalClient(
            AnthropicCompletions(
                api_key=key,
                base_url=AppConfig.ANTHROPIC_BASE_URL,
                model_name=model_override or AppConfig.ANTHROPIC_MODEL,
            )
        )

    if provider == "ollama":
        return UniversalClient(
            OpenAICompatibleCompletions(
                api_key="ollama",
                base_url=AppConfig.OLLAMA_BASE_URL,
                model_name=model_override or AppConfig.OLLAMA_MODEL,
                timeout=AppConfig.OLLAMA_TIMEOUT,
            )
        )

    # Hugging Face default
    if InferenceClient is None:
        return None
    if not api_key:
        return None
    return InferenceClient(api_key=api_key)


def provider_ready(client):
    """Check provider reachability and model availability for UI health."""
    if AppConfig.AI_PROVIDER == "ast":
        return True
    if client is None:
        return False
    if AppConfig.AI_PROVIDER in {"copilot", "openai", "gemini", "groq", "anthropic"}:
        return bool(AppConfig.API_KEY)
    if AppConfig.AI_PROVIDER != "ollama":
        return True

    parsed_url = urlsplit(AppConfig.OLLAMA_BASE_URL)
    path = parsed_url.path.rstrip("/")
    if path.endswith("/v1"):
        path = path[:-3]
    tags_url = urlunsplit(
        (parsed_url.scheme, parsed_url.netloc, f"{path}/api/tags", "", "")
    )
    try:
        with urlopen(tags_url, timeout=1.5) as response:
            models = json.load(response).get("models", [])
    except (OSError, URLError, TimeoutError, ValueError) as exc:
        logger.info("Local Ollama is not ready (%s).", type(exc).__name__)
        return False

    return any(
        isinstance(model, dict)
        and model.get("name") == AppConfig.OLLAMA_MODEL
        for model in models
    )


def provider_display_name(provider=None):
    """Return a user-facing name for the configured AI provider."""
    p = (provider or AppConfig.AI_PROVIDER).strip().lower()
    names = {
        "openai": "OpenAI",
        "gemini": "Google Gemini",
        "groq": "Groq Cloud",
        "anthropic": "Anthropic Claude",
        "copilot": "GitHub Copilot",
        "ollama": "Local Ollama",
        "huggingface": "Hugging Face",
        "ast": "Deterministic AST Engine",
    }
    return names.get(p, p.capitalize())


def test_provider_connectivity(provider, api_key=None, model=None, base_url=None):
    """Live verification of provider API credentials and latency."""
    import time

    started = time.perf_counter()
    p = provider.strip().lower()
    if p == "ast":
        return {
            "success": True,
            "latency_ms": 0.5,
            "provider": "Deterministic AST Engine",
            "model": "Zero-Cloud Offline AST",
        }

    temp_client = create_model_client(
        provider_override=p,
        api_key_override=api_key,
        model_override=model,
    )
    if not temp_client:
        return {
            "success": False,
            "error": f"API key is missing or could not initialize client for {p}.",
        }

    try:
        if hasattr(temp_client, "chat"):
            target_model = model or _get_active_model_name()
            resp = temp_client.chat.completions.create(
                model=target_model,
                messages=[{"role": "user", "content": "Respond with 'OK'"}],
                max_tokens=10,
                temperature=0.0,
            )
            content = resp.choices[0].message.content or ""
        elif hasattr(temp_client, "text_generation"):
            content = temp_client.text_generation("Respond with 'OK'", max_new_tokens=5)
        else:
            content = "OK"

        elapsed = round((time.perf_counter() - started) * 1000, 1)
        return {
            "success": True,
            "latency_ms": elapsed,
            "provider": provider_display_name(p),
            "model": model or _get_active_model_name(),
            "sample_response": content.strip()[:60],
        }
    except Exception as exc:
        return {
            "success": False,
            "error": str(exc),
            "provider": provider_display_name(p),
        }


def get_current_settings():
    """Retrieve full runtime provider and docstring settings."""
    from backend.config import SUPPORTED_PROVIDERS

    p = AppConfig.AI_PROVIDER
    has_key = bool(
        AppConfig.API_KEY
        or (p == "openai" and AppConfig.OPENAI_API_KEY)
        or (p == "gemini" and AppConfig.GEMINI_API_KEY)
        or (p == "groq" and AppConfig.GROQ_API_KEY)
        or (p == "anthropic" and AppConfig.ANTHROPIC_API_KEY)
        or (p in {"ast", "ollama"})
    )
    return {
        "provider": p,
        "provider_display": provider_display_name(p),
        "model": _get_active_model_name(),
        "docstring_style": AppConfig.DOCSTRING_STYLE,
        "supported_providers": sorted(list(SUPPORTED_PROVIDERS)),
        "supported_styles": ["google", "sphinx", "numpy", "standard"],
        "has_api_key": has_key,
        "ai_ready": provider_ready(None if p == "ast" else create_model_client()),
    }


def update_provider_settings(
    provider=None,
    api_key=None,
    model=None,
    base_url=None,
    docstring_style=None,
):
    """Dynamically update runtime provider settings."""
    global MODEL_NAME
    from backend.config import SUPPORTED_PROVIDERS

    if provider:
        p = str(provider).strip().lower()
        if p in SUPPORTED_PROVIDERS:
            AppConfig.AI_PROVIDER = p

    active_p = AppConfig.AI_PROVIDER

    if api_key is not None:
        key_str = str(api_key).strip()
        AppConfig.API_KEY = key_str
        if active_p == "openai":
            AppConfig.OPENAI_API_KEY = key_str
        elif active_p == "gemini":
            AppConfig.GEMINI_API_KEY = key_str
        elif active_p == "groq":
            AppConfig.GROQ_API_KEY = key_str
        elif active_p == "anthropic":
            AppConfig.ANTHROPIC_API_KEY = key_str

    if model:
        m_str = str(model).strip()
        if active_p == "openai":
            AppConfig.OPENAI_MODEL = m_str
        elif active_p == "gemini":
            AppConfig.GEMINI_MODEL = m_str
        elif active_p == "groq":
            AppConfig.GROQ_MODEL = m_str
        elif active_p == "anthropic":
            AppConfig.ANTHROPIC_MODEL = m_str
        elif active_p == "ollama":
            AppConfig.OLLAMA_MODEL = m_str
        elif active_p == "copilot":
            AppConfig.COPILOT_MODEL = m_str
        elif active_p == "huggingface":
            AppConfig.HF_MODEL = m_str

    if base_url:
        b_str = str(base_url).strip()
        if active_p == "ollama":
            AppConfig.OLLAMA_BASE_URL = b_str
        elif active_p == "openai":
            AppConfig.OPENAI_BASE_URL = b_str
        elif active_p == "gemini":
            AppConfig.GEMINI_BASE_URL = b_str
        elif active_p == "groq":
            AppConfig.GROQ_BASE_URL = b_str
        elif active_p == "anthropic":
            AppConfig.ANTHROPIC_BASE_URL = b_str
        elif active_p == "copilot":
            AppConfig.COPILOT_BASE_URL = b_str

    if docstring_style:
        style_str = str(docstring_style).strip().lower()
        if style_str in {"google", "sphinx", "numpy", "standard"}:
            AppConfig.DOCSTRING_STYLE = style_str

    MODEL_NAME = _get_active_model_name()

    try:
        import backend.code_analysis as ca

        ca.client = create_model_client()
        ca.MODEL_NAME = MODEL_NAME
    except Exception as exc:
        logger.warning("Could not refresh ca.client: %s", exc)

    return get_current_settings()


