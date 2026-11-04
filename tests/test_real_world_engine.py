"""Tests for real-world scenarios, settings APIs, multi-provider engine, and structured docstring styles."""

import unittest
from backend.app import app
from backend.config import AppConfig
from backend.code_analysis import _fallback_comment_code, analyze_code
from backend.validator import validate_code, validate_generated_code


class RealWorldEngineTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        self.original_provider = AppConfig.AI_PROVIDER
        self.original_style = AppConfig.DOCSTRING_STYLE

    def tearDown(self):
        AppConfig.AI_PROVIDER = self.original_provider
        AppConfig.DOCSTRING_STYLE = self.original_style

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

    def test_settings_api_update(self):
        """POST /api/settings dynamically updates provider and docstring preferences."""
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

    def test_test_provider_api_ast(self):
        """POST /api/test-provider tests connectivity for offline AST engine."""
        payload = {"provider": "ast"}
        response = self.client.post("/api/test-provider", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data.get("success"))
        self.assertIn("latency_ms", data)
        self.assertIn("Deterministic AST", data.get("provider"))

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


if __name__ == "__main__":
    unittest.main()
