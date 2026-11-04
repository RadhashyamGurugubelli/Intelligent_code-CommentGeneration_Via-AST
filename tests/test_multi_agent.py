import json
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import backend.app as app_module
from backend.multi_agent_orchestrator import run_multi_agent_workflow
from backend.optimization_agent import detect_optimization_opportunities, optimize_code
from backend.security_attack_agent import simulate_attacks
from backend.security_fixing_agent import fix_attack_vulnerabilities


class MultiAgentTests(unittest.TestCase):
    def setUp(self):
        self.client = app_module.app.test_client()

    # -------------------------------------------------------------
    # OPTIMIZATION AGENT TESTS
    # -------------------------------------------------------------
    def test_optimization_agent_detects_quadratic_sort(self):
        source = (
            "def bubble_sort(items):\n"
            "    arr = list(items)\n"
            "    n = len(arr)\n"
            "    for i in range(n):\n"
            "        for j in range(i + 1, n):\n"
            "            if arr[j] < arr[i]:\n"
            "                arr[i], arr[j] = arr[j], arr[i]\n"
            "    return arr\n"
        )
        opps = detect_optimization_opportunities(source)
        self.assertTrue(any(o["type"] == "algorithmic_sorting" for o in opps))

        result = optimize_code(source)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["complexity_before"], "O(n^2)")
        self.assertTrue(result["optimized"])
        self.assertIn("sorted", result["optimized_code"])
        self.assertTrue(result["verification"]["syntax_valid"])
        self.assertTrue(result["verification"]["definitions_preserved"])

    def test_optimization_agent_detects_eager_list_comp_in_sum(self):
        source = (
            "def calculate_total(items):\n"
            "    return sum([item['price'] for item in items if item['active']])\n"
        )
        opps = detect_optimization_opportunities(source)
        self.assertTrue(any(o["type"] == "generator_expression" for o in opps))

        result = optimize_code(source)
        self.assertTrue(result["optimized"])
        self.assertIn("sum(", result["optimized_code"])
        # Should not have [item inside sum([
        self.assertNotIn("sum([", result["optimized_code"])
        self.assertTrue(result["verification"]["syntax_valid"])

    def test_optimization_agent_detects_redundant_dict_keys(self):
        source = (
            "def iterate_records(data):\n"
            "    for key in data.keys():\n"
            "        print(key)\n"
        )
        opps = detect_optimization_opportunities(source)
        self.assertTrue(any(o["type"] == "redundant_dict_keys" for o in opps))

        result = optimize_code(source)
        self.assertTrue(result["optimized"])
        self.assertIn("for key in data:", result["optimized_code"])

    def test_optimization_agent_with_ai_model(self):
        source = "def add(a, b):\n    return a + b\n"
        candidate = "def add(a, b):\n    return a + b\n"

        fake_model = SimpleNamespace(
            chat=SimpleNamespace(
                completions=SimpleNamespace(
                    create=MagicMock(
                        return_value=SimpleNamespace(
                            choices=[
                                SimpleNamespace(
                                    message=SimpleNamespace(content=candidate)
                                )
                            ]
                        )
                    )
                )
            )
        )
        result = optimize_code(source, model_client=fake_model)
        self.assertEqual(result["status"], "completed")
        self.assertTrue(result["verification"]["syntax_valid"])

    # -------------------------------------------------------------
    # SECURITY ATTACK SIMULATION AGENT (RED TEAM) TESTS
    # -------------------------------------------------------------
    def test_attack_simulation_detects_sql_injection(self):
        source = (
            "import sqlite3\n"
            "def get_user(user_id):\n"
            "    conn = sqlite3.connect('users.db')\n"
            "    cursor = conn.cursor()\n"
            "    query = f\"SELECT * FROM users WHERE id = {user_id}\"\n"
            "    cursor.execute(query)\n"
            "    return cursor.fetchone()\n"
        )
        sim = simulate_attacks(source)
        self.assertEqual(sim["status"], "completed")
        self.assertTrue(sim["is_vulnerable"])
        self.assertGreater(sim["vulnerabilities_detected"], 0)
        self.assertTrue(any("CWE-89" in s["cwe"] for s in sim["attack_scenarios"]))
        self.assertTrue(
            all(
                "not executed" in s["attack_payload"]
                for s in sim["attack_scenarios"]
            )
        )
        self.assertEqual(sim["execution_status"], "not_executed")
        self.assertLess(sim["resilience_score"], 100)

    def test_attack_simulation_detects_command_injection(self):
        source = (
            "import os\n"
            "def run_command(cmd):\n"
            "    return os.system(cmd)\n"
        )
        sim = simulate_attacks(source)
        self.assertTrue(sim["is_vulnerable"])
        self.assertTrue(any("CWE-78" in s["cwe"] for s in sim["attack_scenarios"]))
        self.assertGreater(sim["risk_breakdown"]["critical"], 0)

    def test_attack_simulation_detects_eval_execution(self):
        source = (
            "def eval_expression(expr):\n"
            "    return eval(expr)\n"
        )
        sim = simulate_attacks(source)
        self.assertTrue(sim["is_vulnerable"])
        self.assertTrue(any("CWE-94" in s["cwe"] or "CWE-78" in s["cwe"] for s in sim["attack_scenarios"]))

    def test_attack_simulation_detects_hardcoded_secrets(self):
        source = (
            "API_TOKEN = 'secret-token-xyz-12345'\n"
            "def fetch():\n"
            "    return API_TOKEN\n"
        )
        sim = simulate_attacks(source)
        self.assertTrue(sim["is_vulnerable"])
        self.assertTrue(any("CWE-522" in s["cwe"] or "CWE-798" in s["cwe"] for s in sim["attack_scenarios"]))

    def test_attack_simulation_hardened_code(self):
        safe_source = (
            "def add(a, b):\n"
            "    return a + b\n"
        )
        sim = simulate_attacks(safe_source)
        self.assertEqual(sim["vulnerabilities_detected"], 0)
        self.assertFalse(sim["is_vulnerable"])
        self.assertEqual(sim["resilience_score"], 100)
        self.assertIn("not a security certification", sim["defense_verdict"])

    # -------------------------------------------------------------
    # SECURITY FIXING AGENT (BLUE TEAM) TESTS
    # -------------------------------------------------------------
    def test_security_fixing_agent_remediates_sql_injection(self):
        source = (
            "import sqlite3\n"
            "def get_user(user_id):\n"
            "    conn = sqlite3.connect('users.db')\n"
            "    cursor = conn.cursor()\n"
            "    query = f\"SELECT * FROM users WHERE id = {user_id}\"\n"
            "    cursor.execute(query)\n"
            "    return cursor.fetchone()\n"
        )
        fixed = fix_attack_vulnerabilities(source)
        self.assertEqual(fixed["status"], "completed")
        self.assertTrue(fixed["fixed"])
        self.assertIn("?", fixed["fixed_code"])
        self.assertIn("(user_id,)", fixed["fixed_code"])
        self.assertTrue(fixed["verification"]["syntax_valid"])
        self.assertTrue(fixed["verification"]["definitions_preserved"])
        self.assertTrue(fixed["verification"]["all_attacks_neutralized"])
        self.assertEqual(fixed["post_fix_resilience_score"], 100)
        self.assertGreater(fixed["neutralized_count"], 0)

    def test_security_fixing_agent_remediates_eval(self):
        source = (
            "def parse_payload(payload):\n"
            "    return eval(payload)\n"
        )
        fixed = fix_attack_vulnerabilities(source)
        self.assertTrue(fixed["fixed"])
        self.assertIn("ast.literal_eval", fixed["fixed_code"])
        self.assertTrue(fixed["verification"]["syntax_valid"])
        self.assertTrue(fixed["verification"]["all_attacks_neutralized"])

    def test_security_fixing_agent_remediates_command_injection(self):
        source = (
            "import os\n"
            "def run_command(cmd):\n"
            "    return os.system(cmd)\n"
        )
        fixed = fix_attack_vulnerabilities(source)
        self.assertTrue(fixed["fixed"])
        self.assertIn("subprocess.run", fixed["fixed_code"])
        self.assertTrue(fixed["verification"]["syntax_valid"])

    def test_security_fixing_agent_remediates_secrets(self):
        source = (
            "API_TOKEN = 'sample-secret-token'\n"
            "def get_key():\n"
            "    return API_TOKEN\n"
        )
        fixed = fix_attack_vulnerabilities(source)
        self.assertTrue(fixed["fixed"])
        self.assertIn("os.getenv", fixed["fixed_code"])
        self.assertTrue(fixed["verification"]["syntax_valid"])

    def test_security_fixing_agent_on_safe_code(self):
        source = "def multiply(x, y):\n    return x * y\n"
        fixed = fix_attack_vulnerabilities(source)
        self.assertEqual(fixed["status"], "already_secure")
        self.assertFalse(fixed["fixed"])
        self.assertEqual(fixed["post_fix_resilience_score"], 100)

    def test_security_fixing_agent_remediates_path_traversal(self):
        source = (
            "import os\n"
            "def read_file(name):\n"
            "    path = os.path.join('/safe/dir', name)\n"
            "    with open(path, 'r') as f:\n"
            "        return f.read()\n"
        )
        fixed = fix_attack_vulnerabilities(source)
        self.assertTrue(fixed["fixed"])
        self.assertIn("os.path.basename", fixed["fixed_code"])
        self.assertEqual(fixed["post_fix_resilience_score"], 100)

    def test_security_fixing_agent_remediates_ssl_verification(self):
        source = (
            "import requests\n"
            "def fetch(url):\n"
            "    return requests.get(url, verify=False)\n"
        )
        fixed = fix_attack_vulnerabilities(source)
        self.assertTrue(fixed["fixed"])
        self.assertIn("verify=True", fixed["fixed_code"])
        self.assertEqual(fixed["post_fix_resilience_score"], 100)

    def test_optimization_agent_sort_complexity_transition(self):
        source = (
            "def bubble_sort(arr):\n"
            "    for i in range(len(arr)):\n"
            "        for j in range(len(arr) - 1):\n"
            "            if arr[j] > arr[j + 1]:\n"
            "                arr[j], arr[j + 1] = arr[j + 1], arr[j]\n"
            "    return arr\n"
        )
        opt = optimize_code(source)
        self.assertTrue(opt["optimized"])
        self.assertEqual(opt["complexity_before"], "O(n^2)")
        self.assertEqual(opt["complexity_after"], "O(n log n)")


    # -------------------------------------------------------------
    # MULTI-AGENT COLLABORATIVE ORCHESTRATOR TESTS
    # -------------------------------------------------------------
    def test_multi_agent_workflow_full_pipeline(self):
        # Code containing both optimization opportunities and security vulnerabilities
        source = (
            "import sqlite3\n\n"
            "def query_users(user_id):\n"
            "    conn = sqlite3.connect('app.db')\n"
            "    cursor = conn.cursor()\n"
            "    query = f\"SELECT * FROM users WHERE id = {user_id}\"\n"
            "    cursor.execute(query)\n"
            "    return cursor.fetchall()\n"
        )
        result = run_multi_agent_workflow(source)
        self.assertEqual(result["workflow"], "multi_agent_collaboration")
        self.assertEqual(result["status"], "completed")
        self.assertEqual(len(result["timeline"]), 4)
        self.assertTrue(result["code_changed"])
        self.assertEqual(result["summary"]["final_resilience_score"], 100)
        self.assertEqual(result["summary"]["remaining_vulnerabilities"], 0)
        self.assertIn("optimizer", result["agents"])
        self.assertIn("attack_simulator", result["agents"])
        self.assertIn("security_fixer", result["agents"])

    # -------------------------------------------------------------
    # HTTP ENDPOINT INTEGRATION TESTS
    # -------------------------------------------------------------
    def test_api_agent_optimize_endpoint(self):
        source = (
            "def total(items):\n"
            "    return sum([x for x in items])\n"
        )
        response = self.client.post("/agent/optimize", json={"code": source})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["agent"], "code_optimizer")
        self.assertTrue(
            "sum(x for x in items)" in data["optimized_code"]
            or "sum((x for x in items))" in data["optimized_code"]
        )

    def test_api_agent_simulate_attacks_endpoint(self):
        source = (
            "import sqlite3\n"
            "def get_item(item_id):\n"
            "    query = f\"SELECT * FROM items WHERE id = {item_id}\"\n"
            "    cursor.execute(query)\n"
        )
        response = self.client.post("/agent/simulate-attacks", json={"code": source})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["agent"], "security_attack_simulation")
        self.assertTrue(data["is_vulnerable"])
        self.assertGreater(len(data["attack_scenarios"]), 0)

    def test_api_agent_fix_attacks_endpoint(self):
        source = (
            "import sqlite3\n"
            "def get_user(user_id):\n"
            "    conn = sqlite3.connect('users.db')\n"
            "    cursor = conn.cursor()\n"
            "    query = f\"SELECT * FROM users WHERE id = {user_id}\"\n"
            "    cursor.execute(query)\n"
            "    return cursor.fetchone()\n"
        )
        response = self.client.post("/agent/fix-attacks", json={"code": source})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["agent"], "security_fixing_agent")
        self.assertTrue(data["fixed"])
        self.assertEqual(data["post_fix_resilience_score"], 100)

    def test_api_agent_multi_agent_workflow_endpoint(self):
        source = (
            "import sqlite3\n"
            "def get_user(user_id):\n"
            "    conn = sqlite3.connect('users.db')\n"
            "    cursor = conn.cursor()\n"
            "    query = f\"SELECT * FROM users WHERE id = {user_id}\"\n"
            "    cursor.execute(query)\n"
            "    return cursor.fetchone()\n"
        )
        response = self.client.post("/agent/multi-agent-workflow", json={"code": source})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["workflow"], "multi_agent_collaboration")
        self.assertEqual(data["status"], "completed")
        self.assertEqual(len(data["timeline"]), 4)

    def test_api_health_includes_new_agent_modules(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        modules = response.get_json()["modules"]
        self.assertIn("optimization_agent", modules)
        self.assertIn("security_attack_agent", modules)
        self.assertIn("security_fixing_agent", modules)
        self.assertIn("multi_agent_orchestrator", modules)


if __name__ == "__main__":
    unittest.main()
