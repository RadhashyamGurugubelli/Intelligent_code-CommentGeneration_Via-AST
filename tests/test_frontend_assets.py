import unittest
from backend.app import app


class FrontendAssetIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_index_html_loads_successfully(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        content = response.data.decode("utf-8")
        self.assertIn("<title>AST Studio", content)
        self.assertIn("id=\"code-editor\"", content)
        self.assertIn("id=\"btn-multi-agent-team\"", content)
        self.assertIn("id=\"confusion-matrix-container\"", content)
        self.assertIn("id=\"btn-simulate-custom-attack\"", content)
        self.assertIn("AST Insights", content)
        self.assertIn("id=\"explanations-content\"", content)
        self.assertIn("id=\"btn-open-file\"", content)
        self.assertIn("id=\"btn-sandbox-open-file\"", content)
        self.assertIn("id=\"sandbox-source-status\"", content)
        self.assertIn("id=\"btn-sec-simulate-code\"", content)
        self.assertIn("id=\"btn-banner-simulate\"", content)
        self.assertIn("id=\"sec-active-code-section\"", content)
        self.assertNotIn("data-tab=\"tab-explanations\"", content)
        self.assertNotIn("data-tab=\"tab-agentic\"", content)
        self.assertIn("AI Multi-Agents & Swarm", content)
        self.assertIn("id=\"btn-run-agentic\"", content)
        self.assertIn("id=\"agentic-stream-console\"", content)
        self.assertIn("id=\"agentic-result-box\"", content)
        self.assertNotIn("GitHub Copilot AI + AST", content)
        self.assertNotIn(">Attack Guard Active", content)
        self.assertNotIn(">Multi-Agent Ready", content)

    def test_unsafe_formatter_is_disabled_without_changing_nested_python(self):
        index = self.client.get("/").data.decode("utf-8")
        script = self.client.get("/script.js").data.decode("utf-8")
        self.assertRegex(
            index,
            r'<button[^>]*id="btn-format"[^>]*disabled[^>]*>',
        )
        self.assertIn(
            "Formatting is unavailable because automatic re-indentation can change Python code behavior.",
            index,
        )
        self.assertNotIn("function formatCode()", script)
        self.assertNotIn("btn-format').addEventListener", script)

        source = (
            "def f(flag):\n"
            "    if flag:\n"
            "        return 1\n"
            "    return 0\n"
        )
        namespace = {}
        exec(compile(source, "<nested-branch-regression>", "exec"), namespace)
        self.assertEqual(namespace["f"](False), 0)
        self.assertEqual(namespace["f"](True), 1)

    def test_styles_css_loads_successfully(self):
        response = self.client.get("/styles.css")
        self.assertEqual(response.status_code, 200)
        content = response.data.decode("utf-8")
        self.assertIn("--bg-canvas: #0a0d14", content)
        self.assertIn("--accent-cyan: #38bdf8", content)
        self.assertIn(".matrix-container", content)

    def test_settings_modal_uses_fixed_centered_overlay_and_dialog_card(self):
        index = self.client.get("/").data.decode("utf-8")
        styles = self.client.get("/styles.css").data.decode("utf-8")
        self.assertRegex(
            index,
            r'<div id="settings-modal" class="settings-modal-overlay"',
        )
        self.assertRegex(
            styles,
            r"(?s)\.settings-modal-overlay\s*\{[^}]*"
            r"position:\s*fixed;[^}]*inset:\s*0;[^}]*"
            r"align-items:\s*center;[^}]*justify-content:\s*center;",
        )
        self.assertRegex(
            styles,
            r"(?s)\.settings-modal-card\s*\{[^}]*"
            r"max-height:\s*88vh;[^}]*display:\s*flex;[^}]*"
            r"flex-direction:\s*column;",
        )

    def test_editor_overlay_supports_horizontal_overflow_sync(self):
        styles = self.client.get("/styles.css").data.decode("utf-8")
        script = self.client.get("/script.js").data.decode("utf-8")
        self.assertRegex(
            styles,
            r"(?s)\.editor-highlight\s*\{[^}]*overflow:\s*hidden",
        )
        self.assertRegex(
            styles,
            r"(?s)\.editor-highlight\s+code\s*\{[^}]*"
            r"width:\s*max-content;[^}]*min-width:\s*100%;",
        )
        self.assertIn("white-space: pre;", styles)
        self.assertIn("editorHighlight.scrollLeft = editor.scrollLeft;", script)

    def test_script_js_loads_successfully(self):
        response = self.client.get("/script.js")
        self.assertEqual(response.status_code, 200)
        content = response.data.decode("utf-8")
        self.assertIn("runMultiAgentTeam", content)
        self.assertIn("simulateCustomAttack", content)
        self.assertIn("filterBenchmarkTable", content)
        self.assertIn("runSecurityLabCodeSimulation", content)
        self.assertNotIn("ai-mode-badge", content)

    def test_analyze_returns_ast_explanations(self):
        response = self.client.post(
            "/analyze",
            json={"code": "def choose(value):\n    if value:\n        return 1\n    return 0\n"},
        )
        self.assertEqual(response.status_code, 200)
        explanations = response.get_json()["smart_explanations"]
        self.assertTrue(any(item["kind"] == "function" for item in explanations))
        self.assertTrue(any(item["kind"] == "branch" for item in explanations))

    def test_custom_attack_simulation_sqli(self):
        payload = {
            "payload": "' OR '1'='1' --",
            "attack_type": "sqli",
            "code": "def get_user(uid):\n    query = f'SELECT * FROM users WHERE id = {uid}'\n    cursor.execute(query)\n"
        }
        response = self.client.post("/security/simulate-custom-attack", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "success")
        self.assertTrue(data["detected"])
        self.assertIn("SQL", data["cwe"])
        self.assertGreaterEqual(data["risk_score"], 80)

    def test_custom_attack_simulation_command_injection(self):
        payload = {
            "payload": "; cat /etc/passwd #",
            "attack_type": "cmdi",
            "code": "import os\ndef ping(host):\n    os.system(f'ping -c 1 {host}')\n"
        }
        response = self.client.post("/security/simulate-custom-attack", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "success")
        self.assertTrue(data["detected"])
        self.assertIn("Command", data["cwe"])

    def test_custom_attack_simulation_benign(self):
        payload = {
            "payload": "user123",
            "attack_type": "custom",
            "code": "def add(a, b):\n    return a + b\n"
        }
        response = self.client.post("/security/simulate-custom-attack", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "success")
        self.assertFalse(data["exploit_successful"])


    def test_threat_remediation_modal_elements_present(self):
        index = self.client.get("/").data.decode("utf-8")
        styles = self.client.get("/styles.css").data.decode("utf-8")
        script = self.client.get("/script.js").data.decode("utf-8")
        self.assertIn('id="security-threat-modal"', index)
        self.assertIn('id="btn-threat-modal-autofix"', index)
        self.assertIn('id="btn-threat-modal-dismiss"', index)
        self.assertIn('.threat-modal-overlay', styles)
        self.assertIn('showThreatRemediationModal', script)
        self.assertIn('applyAutoFixFromModal', script)

    def test_security_lab_offers_remediation_after_reviewing_attack_risks(self):
        script = self.client.get("/script.js").data.decode("utf-8")
        self.assertIn('id="btn-sec-proceed-remediation"', script)
        self.assertIn("<strong>Attack type:</strong>", script)
        self.assertIn("Attack risk score:", script)
        self.assertIn("risk indicator, not a calibrated probability", script)
        self.assertIn("Would you like to apply an automatic fix or keep the code unchanged?", script)
        simulation_flow = script.split("async function runSecurityLabCodeSimulation()", 1)[1].split(
            "\nasync function evaluateSecurity(", 1
        )[0]
        self.assertLess(
            simulation_flow.index("proceedRemediationBtn.addEventListener"),
            simulation_flow.index("showThreatRemediationModal({"),
        )

    def test_tabs_bar_vertical_clipping_fix_present(self):
        styles = self.client.get("/styles.css").data.decode("utf-8")
        self.assertIn('flex: 0 0 48px !important;', styles)
        self.assertIn('min-height: 48px;', styles)

    def test_ghost_text_alignment_and_font_style_normal(self):
        styles = self.client.get("/styles.css").data.decode("utf-8")
        script = self.client.get("/script.js").data.decode("utf-8")
        self.assertIn('font-style: normal;', styles)
        self.assertIn('clearGhostText', script)


    def test_assistant_prompt_auto_fix_and_keydown_wired(self):
        script = self.client.get("/script.js").data.decode("utf-8")
        self.assertIn("assistantPrompt.addEventListener('keydown'", script)
        self.assertIn("btn-revert-agent-run", script)
        self.assertIn("btn-revert-quality-candidate", script)
        self.assertIn("data-preset", script)

    def test_agent_run_extract_and_synthesize_candidate(self):
        from backend.agent import extract_or_synthesize_candidate, extract_python_code
        reply = "Here is the fix:\n```python\ndef safe(x):\n    return x\n```\nDone."
        code = extract_python_code(reply)
        self.assertEqual(code, "def safe(x):\n    return x")

        vulnerable = "def run(cmd):\n    import os\n    os.system(cmd)\n"
        candidate = extract_or_synthesize_candidate(vulnerable, "fix security vulnerabilities")
        self.assertIsNotNone(candidate)
        self.assertNotEqual(candidate, vulnerable)


if __name__ == "__main__":
    unittest.main()
