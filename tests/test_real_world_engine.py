"""Tests for real-world scenarios, settings APIs, multi-provider engine, and structured docstring styles."""

import json
import unittest
from io import BytesIO
from unittest.mock import patch

import backend.app as app_module
import backend.code_analysis as code_analysis_module
import backend.model_provider as model_provider
from backend.agentic.routes import _runtime
from backend.app import app
from backend.config import AppConfig
from backend.code_analysis import _fallback_comment_code
from backend.validator import validate_code


class RealWorldEngineTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        self.original_provider = AppConfig.AI_PROVIDER
        self.original_style = AppConfig.DOCSTRING_STYLE
        self.settings_changed = False

    def tearDown(self):
        if self.settings_changed:
            model_provider.update_provider_settings(
                provider=self.original_provider,
                docstring_style=self.original_style,
            )

    def test_settings_api_get(self):
        """GET /api/settings returns engine provider, model, and docstring configuration."""
        response = self.client.get("/api/settings")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("provider", data)
        self.assertIn("supported_providers", data)
        self.assertIn("openai", data["supported_providers"])
        self.assertIn("gemini", data["supported_providers"])
        self.assertIn("groq", data["supported_providers"])
        self.assertIn("anthropic", data["supported_providers"])
        self.assertIn("ast", data["supported_providers"])
        self.assertIn("supported_styles", data)
        self.assertIn("google", data["supported_styles"])
        self.assertIn("sphinx", data["supported_styles"])
        self.assertIn("numpy", data["supported_styles"])
        self.assertIn("base_url", data)
        self.assertIn("supports_base_url", data)
        self.assertIn("provider_status", data)
        self.assertIn(
            data["provider_status"],
            {
                "AST MODE",
                "NOT CONFIGURED",
                "CONFIGURED / NOT TESTED",
                "CONNECTED",
                "FAILED",
            },
        )
        self.assertNotIn("api_key", data)

    def test_settings_api_update(self):
        """POST /api/settings dynamically updates provider and docstring preferences."""
        self.settings_changed = True
        payload = {
            "provider": "ast",
            "docstring_style": "sphinx",
        }
        response = self.client.post("/api/settings", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["provider"], "ast")
        self.assertEqual(data["docstring_style"], "sphinx")
        self.assertEqual(AppConfig.DOCSTRING_STYLE, "sphinx")
        self.assertIsNone(code_analysis_module.client)
        self.assertIsNone(app_module.client)
        self.assertIsNone(_runtime.model_client)
        self.assertTrue(
            all(agent.model_client is None for agent in _runtime.supervisor.swarm.values())
        )

    def test_test_provider_api_ast(self):
        """POST /api/test-provider tests connectivity for offline AST engine."""
        payload = {"provider": "ast"}
        response = self.client.post("/api/test-provider", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data.get("success"))
        self.assertIn("latency_ms", data)
        self.assertIn("Deterministic AST", data.get("provider"))

    def test_test_provider_uses_submitted_custom_base_url(self):
        response_body = json.dumps(
            {"choices": [{"message": {"content": "OK"}}]}
        ).encode("utf-8")
        with patch.object(
            model_provider.urllib_request,
            "urlopen",
            return_value=BytesIO(response_body),
        ) as urlopen:
            response = self.client.post(
                "/api/test-provider",
                json={
                    "provider": "openai",
                    "api_key": "test-token",
                    "model": "test-model",
                    "base_url": "https://proxy.example/v1",
                },
            )

        result = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertTrue(result["success"])
        request = urlopen.call_args.args[0]
        self.assertEqual(
            request.full_url,
            "https://proxy.example/v1/chat/completions",
        )
        self.assertEqual(request.get_header("Authorization"), "Bearer test-token")

    def test_provider_status_changes_only_after_a_live_request(self):
        response = type("CompletionResponse", (), {
            "choices": [type("Choice", (), {
                "message": type("Message", (), {"content": "OK"})()
            })()]
        })()
        client = type("ProviderClient", (), {
            "chat": type("Chat", (), {
                "completions": type("Completions", (), {
                    "create": staticmethod(lambda **kwargs: response)
                })()
            })()
        })()

        with (
            patch.object(AppConfig, "AI_PROVIDER", "openai"),
            patch.object(AppConfig, "OPENAI_API_KEY", "configured-test-key"),
            patch.object(AppConfig, "API_KEY_PROVIDER", "openai"),
            patch.object(AppConfig, "OPENAI_MODEL", "status-test-model"),
            patch.object(model_provider, "_LAST_PROVIDER_TEST", None),
        ):
            settings = model_provider.get_current_settings()
            self.assertEqual(settings["provider_status"], "CONFIGURED / NOT TESTED")
            with patch.object(model_provider, "create_model_client", return_value=client):
                result = model_provider.test_provider_connectivity("openai")

            self.assertTrue(result["success"])
            self.assertEqual(result["provider_status"], "CONNECTED")
            self.assertEqual(
                model_provider.get_current_settings()["provider_status"],
                "CONNECTED",
            )

    def test_provider_test_errors_are_safe_and_status_is_failed(self):
        client = type("ProviderClient", (), {
            "chat": type("Chat", (), {
                "completions": type("Completions", (), {
                    "create": staticmethod(
                        lambda **kwargs: (_ for _ in ()).throw(
                            RuntimeError("401 rejected token sk-private-test-secret")
                        )
                    )
                })()
            })()
        })()

        with (
            patch.object(AppConfig, "AI_PROVIDER", "openai"),
            patch.object(AppConfig, "OPENAI_API_KEY", "configured-test-key"),
            patch.object(AppConfig, "API_KEY_PROVIDER", "openai"),
            patch.object(AppConfig, "OPENAI_MODEL", "status-test-model"),
            patch.object(model_provider, "_LAST_PROVIDER_TEST", None),
            patch.object(model_provider, "create_model_client", return_value=client),
        ):
            result = model_provider.test_provider_connectivity("openai")

            self.assertFalse(result["success"])
            self.assertEqual(result["provider_status"], "FAILED")
            self.assertNotIn("sk-private-test-secret", result["error"])
            self.assertIn("rejected the configured token", result["error"])
            self.assertEqual(
                model_provider.get_current_settings()["provider_status"],
                "FAILED",
            )

    def test_provider_credentials_are_not_reused_for_another_provider(self):
        with (
            patch.object(AppConfig, "AI_PROVIDER", "huggingface"),
            patch.object(AppConfig, "API_KEY", "copilot-test-token"),
            patch.object(AppConfig, "API_KEY_PROVIDER", "copilot"),
            patch.object(AppConfig, "HF_TOKEN", ""),
            patch.object(AppConfig, "OPENAI_API_KEY", "openai-test-token"),
            patch.object(AppConfig, "GITHUB_TOKEN", "copilot-test-token"),
            patch.object(model_provider, "InferenceClient") as inference_client,
        ):
            self.assertIsNone(
                model_provider.create_model_client(provider_override="huggingface")
            )
            inference_client.assert_not_called()

        with (
            patch.object(AppConfig, "AI_PROVIDER", "huggingface"),
            patch.object(AppConfig, "API_KEY", "huggingface-test-token"),
            patch.object(AppConfig, "API_KEY_PROVIDER", "huggingface"),
            patch.object(AppConfig, "COPILOT_TOKEN", ""),
            patch.object(AppConfig, "GITHUB_TOKEN", "copilot-test-token"),
            patch.object(AppConfig, "GH_TOKEN", ""),
            patch.object(model_provider, "_resolve_github_token") as resolve_token,
        ):
            copilot_client = model_provider.create_model_client(
                provider_override="copilot"
            )

        if copilot_client is None:
            self.fail("Copilot credentials did not create a client.")
        self.assertEqual(
            getattr(getattr(copilot_client, "chat").completions, "api_key"),
            "copilot-test-token",
        )
        resolve_token.assert_not_called()

    def test_settings_reject_invalid_provider_and_base_url(self):
        invalid_provider = self.client.post(
            "/api/settings",
            json={"provider": "not-a-supported-provider"},
        )
        invalid_url = self.client.post(
            "/api/test-provider",
            json={"provider": "openai", "base_url": "file://local/path"},
        )
        self.assertEqual(invalid_provider.status_code, 400)
        self.assertEqual(invalid_url.status_code, 400)

    def test_multi_style_docstring_google(self):
        """Google-style docstrings format Args, Returns, and Raises."""
        source = (
            "def calculate_tax(amount: float, rate: float = 0.05) -> float:\n"
            "    if amount < 0:\n"
            "        raise ValueError('Amount must be positive')\n"
            "    return amount * rate\n"
        )
        commented = _fallback_comment_code(source, docstring_style="google")
        self.assertIn("Args:", commented)
        self.assertIn("amount (float):", commented)
        self.assertIn("rate (float, optional):", commented)
        self.assertIn("Returns:", commented)
        self.assertIn("float:", commented)
        self.assertIn("Raises:", commented)
        self.assertIn("ValueError:", commented)
        # Verify valid Python syntax
        self.assertTrue(validate_code(commented))

    def test_multi_style_docstring_sphinx(self):
        """Sphinx-style docstrings format :param, :type, :returns:, :rtype, and :raises."""
        source = (
            "def calculate_tax(amount: float, rate: float = 0.05) -> float:\n"
            "    if amount < 0:\n"
            "        raise ValueError('Amount must be positive')\n"
            "    return amount * rate\n"
        )
        commented = _fallback_comment_code(source, docstring_style="sphinx")
        self.assertIn(":param amount:", commented)
        self.assertIn(":type amount: float", commented)
        self.assertIn(":returns:", commented)
        self.assertIn(":rtype: float", commented)
        self.assertIn(":raises ValueError:", commented)
        self.assertTrue(validate_code(commented))

    def test_multi_style_docstring_numpy(self):
        """NumPy-style docstrings format Parameters, Returns, and Raises sections with underline."""
        source = (
            "def calculate_tax(amount: float, rate: float = 0.05) -> float:\n"
            "    if amount < 0:\n"
            "        raise ValueError('Amount must be positive')\n"
            "    return amount * rate\n"
        )
        commented = _fallback_comment_code(source, docstring_style="numpy")
        self.assertIn("Parameters", commented)
        self.assertIn("----------", commented)
        self.assertIn("amount : float", commented)
        self.assertIn("Returns", commented)
        self.assertIn("-------", commented)
        self.assertIn("Raises", commented)
        self.assertIn("------", commented)
        self.assertIn("ValueError", commented)
        self.assertTrue(validate_code(commented))

    def test_explicit_docstring_style_overrides_legacy_positional_style(self):
        source = "def calculate_tax(amount: float) -> float:\n    return amount\n"
        commented = _fallback_comment_code(
            source,
            "google",
            docstring_style="numpy",
        )
        self.assertIn("Parameters", commented)
        self.assertNotIn("Args:", commented)

    def test_real_world_fastapi_ecommerce_pipeline(self):
        """Real-world scenario 1: FastAPI order calculation pipeline runs through /generate cleanly."""
        code = (
            "from typing import List\n\n"
            "class OrderItem:\n"
            "    def __init__(self, sku: str, quantity: int, unit_price: float):\n"
            "        if quantity <= 0:\n"
            "            raise ValueError('Quantity must be positive')\n"
            "        self.sku = sku\n"
            "        self.quantity = quantity\n"
            "        self.unit_price = unit_price\n\n"
            "def calculate_order_total(items: List[OrderItem], discount_rate: float = 0.0) -> float:\n"
            "    if not items:\n"
            "        raise ValueError('Cannot calculate total for empty order')\n"
            "    subtotal = sum(i.quantity * i.unit_price for i in items)\n"
            "    discount = subtotal * discount_rate\n"
            "    tax = (subtotal - discount) * 0.0825\n"
            "    return round((subtotal - discount) + tax, 2)\n"
        )
        response = self.client.post("/generate", json={"code": code})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("commented_code", data)
        self.assertTrue(data["validation"]["is_valid"])
        self.assertTrue(validate_code(data["commented_code"]))

    def test_real_world_ml_feature_pipeline(self):
        """Real-world scenario 2: Statistical feature normalization with outlier clipping."""
        code = (
            "import math\n"
            "from typing import List, Tuple\n\n"
            "def compute_z_score_normalization(values: List[float], clip_outliers: bool = True) -> Tuple[List[float], float, float]:\n"
            "    if not values:\n"
            "        raise ValueError('Feature list cannot be empty')\n"
            "    n = len(values)\n"
            "    mean_val = sum(values) / n\n"
            "    variance = sum((x - mean_val) ** 2 for x in values) / (n - 1 if n > 1 else 1)\n"
            "    std_dev = math.sqrt(variance)\n"
            "    if std_dev == 0.0:\n"
            "        return [0.0] * n, round(mean_val, 4), 0.0\n"
            "    normalized = []\n"
            "    for x in values:\n"
            "        z = (x - mean_val) / std_dev\n"
            "        if clip_outliers:\n"
            "            z = max(-3.0, min(3.0, z))\n"
            "        normalized.append(round(z, 4))\n"
            "    return normalized, round(mean_val, 4), round(std_dev, 4)\n"
        )
        response = self.client.post("/generate", json={"code": code})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data["validation"]["is_valid"])
        self.assertTrue(validate_code(data["commented_code"]))

    def test_real_world_concurrent_lru_cache(self):
        """Real-world scenario 3: Thread-safe concurrent LRU Cache with locks and TTL eviction."""
        code = (
            "import time\n"
            "from collections import OrderedDict\n"
            "from threading import RLock\n"
            "from typing import Any, Optional\n\n"
            "class ConcurrentLruCache:\n"
            "    def __init__(self, capacity: int = 128, default_ttl_seconds: float = 300.0):\n"
            "        if capacity <= 0:\n"
            "            raise ValueError('Capacity must be positive')\n"
            "        self.capacity = capacity\n"
            "        self.default_ttl = default_ttl_seconds\n"
            "        self._lock = RLock()\n"
            "        self._store = OrderedDict()\n\n"
            "    def get(self, key: str) -> Optional[Any]:\n"
            "        with self._lock:\n"
            "            if key not in self._store:\n"
            "                return None\n"
            "            val, expiry = self._store[key]\n"
            "            if time.time() > expiry:\n"
            "                del self._store[key]\n"
            "                return None\n"
            "            self._store.move_to_end(key)\n"
            "            return val\n\n"
            "    def put(self, key: str, value: Any, ttl: Optional[float] = None) -> None:\n"
            "        ttl_seconds = ttl if ttl is not None else self.default_ttl\n"
            "        expiry = time.time() + ttl_seconds\n"
            "        with self._lock:\n"
            "            if key in self._store:\n"
            "                self._store.move_to_end(key)\n"
            "            self._store[key] = (value, expiry)\n"
            "            while len(self._store) > self.capacity:\n"
            "                self._store.popitem(last=False)\n"
        )
        response = self.client.post("/generate", json={"code": code})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data["validation"]["is_valid"])
        self.assertTrue(validate_code(data["commented_code"]))

    def test_health_endpoint_reports_professor_student_module(self):
        """GET /health must list the professor_student_engine in active modules."""
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("modules", data)
        self.assertIn("professor_student_engine", data["modules"])

    def test_generate_endpoint_accepts_docstring_style_override(self):
        """POST /generate accepts an explicit docstring_style override."""
        code = (
            "def calculate_tax(amount: float) -> float:\n"
            "    return amount * 0.05\n"
        )
        with patch("backend.code_analysis.client", None):
            # 1. Test Sphinx style
            resp_sphinx = self.client.post(
                "/generate",
                json={"code": code, "docstring_style": "sphinx"},
            )
            self.assertEqual(resp_sphinx.status_code, 200)
            data_sphinx = resp_sphinx.get_json()
            self.assertIn(":param amount:", data_sphinx["commented_code"])
            self.assertIn(":returns:", data_sphinx["commented_code"])

            # 2. Test NumPy style
            resp_numpy = self.client.post(
                "/generate",
                json={"code": code, "docstring_style": "numpy"},
            )
            self.assertEqual(resp_numpy.status_code, 200)
            data_numpy = resp_numpy.get_json()
            self.assertIn("Parameters", data_numpy["commented_code"])
            self.assertIn("Returns", data_numpy["commented_code"])

            # 3. Test invalid style rejection
            resp_invalid = self.client.post(
                "/generate",
                json={"code": code, "docstring_style": "invalid_style"},
            )
            self.assertEqual(resp_invalid.status_code, 400)
            self.assertIn("Unsupported docstring style", resp_invalid.get_json()["error"])

    def test_type_analyzer_handles_optional_and_union_annotations(self):
        """Type analyzer conservatively resolves Optional[T], T | None, and List[T]."""
        from backend.type_analyzer import find_definite_type_errors

        # Optional[int] + str mismatch
        opt_code = (
            "from typing import Optional\n"
            "def add_tax(base: Optional[int]):\n"
            "    return base + 'invalid'\n"
        )
        findings_opt = find_definite_type_errors(opt_code)
        self.assertTrue(len(findings_opt) >= 1)
        self.assertEqual(findings_opt[0]["left_type"], "int")
        self.assertEqual(findings_opt[0]["right_type"], "str")

        # int | None + str mismatch
        union_code = (
            "def add_rate(rate: int | None):\n"
            "    return rate + 'invalid'\n"
        )
        findings_union = find_definite_type_errors(union_code)
        self.assertTrue(len(findings_union) >= 1)
        self.assertEqual(findings_union[0]["left_type"], "int")
        self.assertEqual(findings_union[0]["right_type"], "str")

        # List[str] + int mismatch
        list_code = (
            "from typing import List\n"
            "def summarize(tags: List[str]):\n"
            "    return tags + 42\n"
        )
        findings_list = find_definite_type_errors(list_code)
        self.assertTrue(len(findings_list) >= 1)
        self.assertEqual(findings_list[0]["left_type"], "list")
        self.assertEqual(findings_list[0]["right_type"], "int")

    def test_type_analyzer_handles_qualified_and_aliased_typing_annotations(self):
        from backend.type_analyzer import find_definite_type_errors

        code = (
            "import typing as t\n"
            "from typing import List as StringList\n\n"
            "def add_tax(base: t.Optional[int]):\n"
            "    return base + 'invalid'\n\n"
            "def summarize(tags: StringList[str]):\n"
            "    return tags + 42\n"
        )

        findings = find_definite_type_errors(code)

        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]["left_type"], "int")
        self.assertEqual(findings[1]["left_type"], "list")

    def test_redos_detection_with_import_alias(self):
        """Security scanner detects ReDoS patterns even with renamed or aliased re imports."""
        from backend.security_attack_agent import simulate_attacks

        code = (
            "from re import compile as my_compile\n"
            "vuln_pattern = my_compile(r'^(a+)+$')\n"
        )
        sim = simulate_attacks(code)
        self.assertTrue(sim["vulnerabilities_detected"] >= 1)
        redos_scenarios = [s for s in sim["attack_scenarios"] if "CWE-1333" in s["cwe"]]
        self.assertTrue(len(redos_scenarios) >= 1)

    def test_professor_student_optimizes_quadratic_sort_complexity(self):
        """Professor-Student student revision invokes optimizer when high complexity is flagged."""
        from backend.professor_student_engine import ProfessorStudentOrchestrator

        bubble_sort_code = (
            "def bubble_sort(arr):\n"
            "    n = len(arr)\n"
            "    for i in range(n):\n"
            "        for j in range(0, n - i - 1):\n"
            "            if arr[j] > arr[j + 1]:\n"
            "                arr[j], arr[j + 1] = arr[j + 1], arr[j]\n"
            "    return arr\n"
        )
        orchestrator = ProfessorStudentOrchestrator(max_iterations=3)
        res = orchestrator.run(bubble_sort_code)
        self.assertEqual(res["status"], "completed")
        self.assertTrue(res["code_modified"])
        self.assertIn("sorted", res["final_code"])
        self.assertTrue(validate_code(res["final_code"]))


if __name__ == "__main__":
    unittest.main()
