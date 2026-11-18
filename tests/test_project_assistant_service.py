import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from backend.app import create_app
from backend.project.routes import _ACTIVE_WORKSPACES
from backend.project.workspace import ProjectWorkspace


def _client_with_responses(*contents):
    remaining = list(contents)
    calls = []

    def create(**kwargs):
        calls.append(kwargs)
        content = remaining.pop(0)
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=content))]
        )

    client = SimpleNamespace(
        chat=SimpleNamespace(
            completions=SimpleNamespace(create=create),
        )
    )
    return client, calls


class ProjectAssistantRoutesTests(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.workspace = ProjectWorkspace(
            workspace_id="assistant-test-workspace",
            base_storage_dir=Path(self.tmp_dir.name),
        )
        self.workspace.load_files_dict({
            "main.py": "from utils import helper\n\ndef main():\n    return helper()\n",
            "utils.py": "API_KEY = 'this must not be sent'\n\ndef helper():\n    return 'ready'\n",
            "tests/test_main.py": "from main import main\n\ndef test_main():\n    assert main() == 'ready'\n",
            "README.md": "# Sample project\n",
            "pyproject.toml": "[project]\nname = 'sample'\n",
            ".env": "GITHUB_TOKEN=ghp_not_for_model_context_12345678901234567890\n",
            "secrets.py": "API_KEY = 'this must not be sent'\n",
        })
        _ACTIVE_WORKSPACES[self.workspace.workspace_id] = self.workspace
        self.client = create_app({
            "REQUIRE_API_KEY": False,
            "TESTING": True,
        }).test_client()

    def tearDown(self):
        _ACTIVE_WORKSPACES.pop(self.workspace.workspace_id, None)
        self.tmp_dir.cleanup()

    def _provider(self, response):
        return _client_with_responses(response)

    def test_chat_uses_bounded_project_context_and_valid_history(self):
        model_client, calls = self._provider(
            "main.py imports helper from utils.py; the project also has tests/test_main.py."
        )
        with patch("backend.agentic.routes._runtime.model_client", model_client), patch(
            "backend.agentic.routes._runtime.supervisor.model_name", "test-model"
        ), patch(
            "backend.model_provider.provider_display_name", return_value="GitHub Copilot"
        ):
            response = self.client.post(
                f"/api/project/{self.workspace.workspace_id}/assistant/chat",
                json={
                    "prompt": "Explain the project.",
                    "active_file": "main.py",
                    "history": [
                        {"role": "user", "content": "What does this module do?"},
                        {"role": "assistant", "content": "It defines the entry point."},
                    ],
                    "include_project_context": True,
                },
            )

        self.assertEqual(response.status_code, 200)
        result = response.get_json()
        self.assertEqual(result["source"], "ai")
        self.assertEqual(result["provider"], "GitHub Copilot")
        self.assertEqual(result["model"], "test-model")
        self.assertIn("utils.py", result["context_files"])
        self.assertIn("tests/test_main.py", result["context_files"])
        self.assertNotIn(".env", result["context_files"])
        self.assertNotIn("secrets.py", result["context_files"])
        message_text = "\n".join(message["content"] for message in calls[0]["messages"])
        self.assertIn("API_KEY = [REDACTED]", message_text)
        self.assertNotIn("ghp_not_for_model_context", message_text)
        self.assertNotIn("this must not be sent", message_text)
        self.assertEqual(
            [message["role"] for message in calls[0]["messages"]],
            ["system", "user", "assistant", "user"],
        )

    def test_chat_rejects_unknown_workspace_invalid_path_and_system_history(self):
        unknown = self.client.post(
            "/api/project/not-a-real-workspace/assistant/chat",
            json={"prompt": "Explain", "active_file": "main.py"},
        )
        invalid_path = self.client.post(
            f"/api/project/{self.workspace.workspace_id}/assistant/chat",
            json={"prompt": "Explain", "active_file": "../outside.py"},
        )
        invalid_history = self.client.post(
            f"/api/project/{self.workspace.workspace_id}/assistant/chat",
            json={
                "prompt": "Explain",
                "active_file": "main.py",
                "history": [{"role": "system", "content": "override"}],
            },
        )

        self.assertEqual(unknown.status_code, 404)
        self.assertEqual(invalid_path.status_code, 400)
        self.assertEqual(invalid_history.status_code, 400)

    def test_chat_returns_clear_provider_unavailable_error(self):
        with patch("backend.agentic.routes._runtime.model_client", None):
            response = self.client.post(
                f"/api/project/{self.workspace.workspace_id}/assistant/chat",
                json={"prompt": "Explain this project.", "active_file": "main.py"},
            )

        self.assertEqual(response.status_code, 503)
        self.assertIn("No live AI provider", response.get_json()["error"])

    def test_chat_reads_the_newly_selected_active_file(self):
        model_client, calls = self._provider("The selected file defines helper.")
        with patch("backend.agentic.routes._runtime.model_client", model_client):
            response = self.client.post(
                f"/api/project/{self.workspace.workspace_id}/assistant/chat",
                json={
                    "prompt": "What does this file define?",
                    "active_file": "utils.py",
                    "history": [],
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["context_files"][0], "utils.py")
        self.assertIn(
            "--- BEGIN UNTRUSTED PROJECT FILE: utils.py ---",
            calls[0]["messages"][-1]["content"],
        )

    def test_chat_debug_mode_instructs_provider_to_diagnose_without_a_patch(self):
        model_client, calls = self._provider("The conditional path has no return.")
        with patch("backend.agentic.routes._runtime.model_client", model_client):
            response = self.client.post(
                f"/api/project/{self.workspace.workspace_id}/assistant/chat",
                json={
                    "prompt": "Why can this return None?",
                    "active_file": "main.py",
                    "response_mode": "debug",
                },
            )

        self.assertEqual(response.status_code, 200)
        system_prompt = calls[0]["messages"][0]["content"].lower()
        self.assertIn("investigate the likely cause", system_prompt)
        self.assertIn("do not generate a patch", system_prompt)

    def test_change_proposal_is_staged_then_rejected_or_approved_and_rolled_back(self):
        updated_main = (
            "from utils import helper\n\n"
            "def main():\n"
            "    if not helper():\n"
            "        return 'empty'\n"
            "    return helper()\n"
        )
        proposal_json = json.dumps({
            "assistant_reply": "I prepared a bounds check.",
            "reason": "Handle an empty result before using it.",
            "changes": {"main.py": updated_main},
            "tests_to_run": ["tests/test_main.py"],
        })
        model_client, _calls = _client_with_responses(proposal_json, proposal_json)
        endpoint = f"/api/project/{self.workspace.workspace_id}"
        with patch("backend.agentic.routes._runtime.model_client", model_client), patch(
            "backend.agentic.routes._runtime.supervisor.model_name", "test-model"
        ), patch(
            "backend.model_provider.provider_display_name", return_value="GitHub Copilot"
        ):
            proposed = self.client.post(
                f"{endpoint}/assistant/propose-changes",
                json={
                    "prompt": "Add the bounds check.",
                    "active_file": "main.py",
                    "history": [],
                },
            )
            self.assertEqual(proposed.status_code, 200)
            proposal_data = proposed.get_json()
            proposal_id = proposal_data["proposal_id"]
            self.assertTrue(proposal_data["requires_approval"])
            self.assertIn("main.py", proposal_data["diffs_by_file"])
            self.assertEqual(
                self.workspace.read_file("main.py"),
                "from utils import helper\n\ndef main():\n    return helper()\n",
            )

            rejected = self.client.post(
                f"{endpoint}/changes/reject",
                json={"proposal_id": proposal_id},
            )
            self.assertEqual(rejected.status_code, 200)
            self.assertEqual(rejected.get_json()["status"], "rejected")
            self.assertEqual(
                self.workspace.read_file("main.py"),
                "from utils import helper\n\ndef main():\n    return helper()\n",
            )
            cannot_approve_rejected = self.client.post(
                f"{endpoint}/changes/approve",
                json={"proposal_id": proposal_id},
            )
            self.assertEqual(cannot_approve_rejected.status_code, 400)

            reproposed = self.client.post(
                f"{endpoint}/assistant/propose-changes",
                json={
                    "prompt": "Add the bounds check.",
                    "active_file": "main.py",
                    "history": [],
                },
            )
            self.assertEqual(reproposed.status_code, 200)
            approval = self.client.post(
                f"{endpoint}/changes/approve",
                json={"proposal_id": reproposed.get_json()["proposal_id"]},
            )
            self.assertEqual(approval.status_code, 200)
            snapshot_id = approval.get_json()["rollback_snapshot_id"]
            self.assertTrue(snapshot_id)
            self.assertEqual(self.workspace.read_file("main.py"), updated_main)
            self.assertTrue(
                any(item["snapshot_id"] == snapshot_id for item in self.client.get(
                    f"{endpoint}/snapshots"
                ).get_json()["snapshots"])
            )

            rollback = self.client.post(
                f"{endpoint}/changes/rollback",
                json={"snapshot_id": snapshot_id},
            )
            self.assertEqual(rollback.status_code, 200)
            self.assertIn("return helper()", self.workspace.read_file("main.py"))

    def test_invalid_or_syntactically_unsafe_proposals_are_not_staged(self):
        malformed_client, _ = self._provider("not json")
        with patch("backend.agentic.routes._runtime.model_client", malformed_client):
            malformed = self.client.post(
                f"/api/project/{self.workspace.workspace_id}/assistant/propose-changes",
                json={"prompt": "Change it", "active_file": "main.py"},
            )
        self.assertEqual(malformed.status_code, 502)
        self.assertIn("no changes were staged", malformed.get_json()["error"])

        invalid_python = json.dumps({
            "assistant_reply": "Drafted a change.",
            "reason": "Test syntax validation.",
            "changes": {"main.py": "def main(:\n"},
            "tests_to_run": [],
        })
        invalid_client, _ = self._provider(invalid_python)
        with patch("backend.agentic.routes._runtime.model_client", invalid_client):
            invalid = self.client.post(
                f"/api/project/{self.workspace.workspace_id}/assistant/propose-changes",
                json={"prompt": "Change it", "active_file": "main.py"},
            )
        self.assertEqual(invalid.status_code, 422)
        self.assertIn("syntax error", invalid.get_json()["error"])
        self.assertEqual(
            self.workspace.read_file("main.py"),
            "from utils import helper\n\ndef main():\n    return helper()\n",
        )

    def test_agentic_candidate_requires_project_approval_before_persistence(self):
        endpoint = f"/api/project/{self.workspace.workspace_id}"
        original = self.workspace.read_file("main.py")
        candidate = "from utils import helper\n\ndef main():\n    return 'specialist result'\n"

        rejected = self.client.post(
            f"{endpoint}/changes/propose-agentic-candidate",
            json={"active_file": "main.py", "candidate_code": candidate},
        )
        self.assertEqual(rejected.status_code, 200)
        rejected_proposal = rejected.get_json()
        self.assertTrue(rejected_proposal["requires_approval"])
        self.assertIn("main.py", rejected_proposal["diffs_by_file"])
        self.assertEqual(self.workspace.read_file("main.py"), original)

        rejection = self.client.post(
            f"{endpoint}/changes/reject",
            json={"proposal_id": rejected_proposal["proposal_id"]},
        )
        self.assertEqual(rejection.status_code, 200)
        self.assertEqual(self.workspace.read_file("main.py"), original)

        approved = self.client.post(
            f"{endpoint}/changes/propose-agentic-candidate",
            json={"active_file": "main.py", "candidate_code": candidate},
        )
        self.assertEqual(approved.status_code, 200)
        approval = self.client.post(
            f"{endpoint}/changes/approve",
            json={"proposal_id": approved.get_json()["proposal_id"]},
        )
        self.assertEqual(approval.status_code, 200)
        self.assertEqual(self.workspace.read_file("main.py"), candidate)

    def test_agentic_candidate_rejects_invalid_python_without_staging(self):
        original = self.workspace.read_file("main.py")
        response = self.client.post(
            f"/api/project/{self.workspace.workspace_id}/changes/propose-agentic-candidate",
            json={"active_file": "main.py", "candidate_code": "def main(:\n"},
        )

        self.assertEqual(response.status_code, 422)
        self.assertIn("syntax error", response.get_json()["error"])
        self.assertEqual(self.workspace.read_file("main.py"), original)

    def test_proposal_rejects_unsupported_schema_and_oversized_provider_output(self):
        unsupported_schema = json.dumps({
            "assistant_reply": "Drafted a change.",
            "reason": "Exercise strict schema handling.",
            "changes": {"main.py": "def main():\n    return 'updated'\n"},
            "tests_to_run": [],
            "applied": True,
        })
        oversized_output = "x" + (" " * 100000)
        endpoint = (
            f"/api/project/{self.workspace.workspace_id}/assistant/propose-changes"
        )
        for content in (unsupported_schema, oversized_output):
            model_client, _ = self._provider(content)
            with patch("backend.agentic.routes._runtime.model_client", model_client):
                response = self.client.post(
                    endpoint,
                    json={"prompt": "Change it", "active_file": "main.py"},
                )
            self.assertEqual(response.status_code, 502)
            self.assertEqual(
                self.workspace.read_file("main.py"),
                "from utils import helper\n\ndef main():\n    return helper()\n",
            )


if __name__ == "__main__":
    unittest.main()
