"""Rigorous security regression suite for NEXUS session security and approval boundaries."""

import hashlib
import unittest
from pathlib import Path

from backend.app import app
from backend.agentic.session import (
    default_session_manager,
    default_sse_ticket_store,
)


from backend.security_rate_limit import default_rate_limiter


class NexusSessionSecurityHardeningTests(unittest.TestCase):
    """Test suite proving session ownership, ticket consumption, and approval boundaries."""

    def setUp(self):
        default_rate_limiter.reset()
        self.client = app.test_client()
        self.sample_code = "def add(a, b):\n    return a + b\n"

    def tearDown(self):
        default_rate_limiter.reset()

    def _start_async_session(self, **kwargs):
        payload = {
            "code": self.sample_code,
            "task": "Analyze security and performance.",
            "async": True,
            "execution_mode": "deterministic",
            **kwargs,
        }
        resp = self.client.post("/agentic/run", json=payload)
        self.assertEqual(resp.status_code, 202)
        data = resp.get_json()
        session_id = data["session_id"]
        owner_token = data["owner_token"]
        return session_id, owner_token, resp

    def test_unauthenticated_requests_denied(self):
        """Unauthenticated requests without owner credentials must receive 401 across all routes."""
        session_id, owner_token, _ = self._start_async_session()
        unauth_client = app.test_client()

        # 1. GET session without credentials
        resp_get = unauth_client.get(f"/agentic/session/{session_id}")
        self.assertEqual(resp_get.status_code, 401)
        self.assertIn("Authentication required", resp_get.get_json().get("error", ""))

        # 2. GET stream without ticket or credentials
        resp_stream = unauth_client.get(f"/agentic/stream/{session_id}")
        self.assertEqual(resp_stream.status_code, 401)

        # 3. POST cancel without credentials
        resp_cancel = unauth_client.post(f"/agentic/cancel/{session_id}")
        self.assertEqual(resp_cancel.status_code, 401)

        # 4. POST ticket generation without credentials
        resp_ticket = unauth_client.post(f"/agentic/session/{session_id}/ticket")
        self.assertEqual(resp_ticket.status_code, 401)

        # 5. POST action without credentials
        resp_action = unauth_client.post(
            "/agentic/action",
            json={"session_id": session_id, "action": "approve"},
        )
        self.assertEqual(resp_action.status_code, 401)

    def test_invalid_token_denied_with_403(self):
        """Requests with an invalid or fabricated session token must be rejected with 403 Forbidden."""
        session_id, owner_token, _ = self._start_async_session()
        unauth_client = app.test_client()
        bad_headers = {"X-Session-Token": "fabricated_bad_token_12345"}

        resp_get = unauth_client.get(f"/agentic/session/{session_id}", headers=bad_headers)
        self.assertEqual(resp_get.status_code, 403)
        self.assertIn("invalid session token", resp_get.get_json().get("error", "").lower())

        resp_cancel = unauth_client.post(f"/agentic/cancel/{session_id}", headers=bad_headers)
        self.assertEqual(resp_cancel.status_code, 403)

        resp_ticket = unauth_client.post(f"/agentic/session/{session_id}/ticket", headers=bad_headers)
        self.assertEqual(resp_ticket.status_code, 403)

    def test_cross_session_token_reuse_denied(self):
        """An owner token valid for Session A must be rejected with 403 when used against Session B."""
        session_a, token_a, _ = self._start_async_session()
        session_b, token_b, _ = self._start_async_session()
        self.assertNotEqual(session_a, session_b)
        self.assertNotEqual(token_a, token_b)

        client_b = app.test_client()
        # Attempt to access Session B using Session A's valid token
        resp = client_b.get(
            f"/agentic/session/{session_b}",
            headers={"X-Session-Token": token_a},
        )
        self.assertEqual(resp.status_code, 403)
        self.assertIn("invalid session token", resp.get_json().get("error", "").lower())

    def test_owner_token_omitted_from_to_dict_and_get_response(self):
        """AgentSession.to_dict() and GET responses must NEVER serialize or expose owner_token."""
        session_id, owner_token, _ = self._start_async_session()
        session = default_session_manager.get_session(session_id)
        self.assertIsNotNone(session)

        # 1. Model to_dict() must not contain owner_token by default
        public_dict = session.to_dict()
        self.assertNotIn("owner_token", public_dict)

        # 2. Persistence to_dict(include_owner_token=True) must preserve it
        internal_dict = session.to_dict(include_owner_token=True)
        self.assertIn("owner_token", internal_dict)
        self.assertEqual(internal_dict["owner_token"], owner_token)

        # 3. GET /agentic/session/<id> must not contain owner_token
        auth_client = app.test_client()
        resp = auth_client.get(
            f"/agentic/session/{session_id}",
            headers={"X-Session-Token": owner_token},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertNotIn("owner_token", data)

    def test_strict_json_boolean_validation(self):
        """String booleans such as 'false' or numbers must be rejected with 400 Bad Request."""
        invalid_auto_approves = ["false", "true", "0", "1", 0, 1, "yes", None]
        for val in invalid_auto_approves:
            resp = self.client.post(
                "/agentic/run",
                json={
                    "code": self.sample_code,
                    "task": "Test boolean validation",
                    "auto_approve": val,
                },
            )
            self.assertEqual(
                resp.status_code,
                400,
                f"Expected 400 for auto_approve={val!r}, got {resp.status_code}",
            )
            self.assertIn("must be a valid JSON boolean", resp.get_json().get("error", ""))

        auto_approve = self.client.post(
            "/agentic/run",
            json={
                "code": self.sample_code,
                "task": "Fix a source issue",
                "auto_approve": True,
            },
        )
        self.assertEqual(auto_approve.status_code, 400)
        self.assertIn("explicit operator approval", auto_approve.get_json()["error"])

        invalid_asyncs = ["false", "true", "0", 1, "no"]
        for val in invalid_asyncs:
            resp = self.client.post(
                "/agentic/run",
                json={
                    "code": self.sample_code,
                    "task": "Test async boolean validation",
                    "async": val,
                },
            )
            self.assertEqual(
                resp.status_code,
                400,
                f"Expected 400 for async={val!r}, got {resp.status_code}",
            )
            self.assertIn("must be a valid JSON boolean", resp.get_json().get("error", ""))

    def test_sse_single_use_ticket_flow(self):
        """SSE tickets must be single-use: valid on first connection, rejected upon replay."""
        session_id, owner_token, _ = self._start_async_session()
        client = app.test_client()

        # Generate ticket
        ticket_resp = client.post(
            f"/agentic/session/{session_id}/ticket",
            headers={"X-Session-Token": owner_token},
        )
        self.assertEqual(ticket_resp.status_code, 200)
        ticket = ticket_resp.get_json()["ticket"]
        self.assertTrue(ticket.startswith("sse_"))

        # Connect with ticket -> 200 OK
        stream_client1 = app.test_client()
        resp1 = stream_client1.get(f"/agentic/stream/{session_id}?ticket={ticket}")
        self.assertEqual(resp1.status_code, 200)

        # Replay same ticket -> 403 Forbidden (burned upon consumption)
        stream_client2 = app.test_client()
        resp2 = stream_client2.get(f"/agentic/stream/{session_id}?ticket={ticket}")
        self.assertEqual(resp2.status_code, 403)
        self.assertEqual(resp2.get_json().get("status"), "invalid_ticket")

    def test_expired_sse_ticket_denied(self):
        """Expired SSE tickets must be rejected with 403 Forbidden (status: expired_ticket)."""
        session_id, owner_token, _ = self._start_async_session()
        # Manually create an expired ticket in the store
        expired_ticket = default_sse_ticket_store.create_ticket(
            session_id=session_id,
            owner_token=owner_token,
            ttl_seconds=-5.0,  # Expired 5 seconds ago
        )
        client = app.test_client()
        resp = client.get(f"/agentic/stream/{session_id}?ticket={expired_ticket}")
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.get_json().get("status"), "expired_ticket")

    def test_durable_token_query_parameters_disallowed(self):
        """Durable tokens in query parameters (?token=...) must be rejected to prevent log leakage."""
        session_id, owner_token, _ = self._start_async_session()
        client = app.test_client()

        # Query param ?token= on stream route -> 403 query_token_disallowed
        resp_stream = client.get(f"/agentic/stream/{session_id}?token={owner_token}")
        self.assertEqual(resp_stream.status_code, 403)
        self.assertEqual(resp_stream.get_json().get("status"), "query_token_disallowed")

        # Query param ?token= on session route -> 403 or 401
        resp_sess = client.get(f"/agentic/session/{session_id}?token={owner_token}")
        self.assertIn(resp_sess.status_code, (401, 403))

    def test_cookie_authentication_flow(self):
        """Clients receiving the HttpOnly session cookie on /agentic/run must be authorized automatically."""
        # 1. Run session; client receives Set-Cookie: ast_session_<id>
        session_id, owner_token, run_resp = self._start_async_session()
        cookie_header = run_resp.headers.get("Set-Cookie", "")
        self.assertIn(f"ast_session_{session_id}=", cookie_header)
        self.assertIn("HttpOnly", cookie_header)
        self.assertIn("SameSite=Lax", cookie_header)

        # 2. Same client queries session without X-Session-Token header -> 200 OK (via cookie)
        resp = self.client.get(f"/agentic/session/{session_id}")
        self.assertEqual(resp.status_code, 200)

    def test_approval_digest_binding_and_tamper_evidence(self):
        """Approval decisions must record who approved what, when, and for which candidate digest."""
        session_id, owner_token, _ = self._start_async_session(auto_approve=False)
        session = default_session_manager.get_session(session_id)
        self.assertIsNotNone(session)

        # Simulate pending approval with candidate code digest
        candidate_code = "def add(a, b):\n    '''Add two numbers.'''\n    return a + b\n"
        correct_digest = hashlib.sha256(candidate_code.encode("utf-8")).hexdigest()
        tampered_digest = hashlib.sha256(b"tampered code").hexdigest()

        session.status = "awaiting_approval"
        session.pending_approval = {
            "task_id": "task_remedy_1",
            "tool": "synthesize_defensive_patch",
            "candidate_digest": correct_digest,
            "permission_required": "apply_candidate",
        }

        auth_client = app.test_client()

        # 1. Reject approval when client submits mismatched digest (tamper-evident)
        resp_tampered = auth_client.post(
            "/agentic/action",
            headers={"X-Session-Token": owner_token, "X-Approver-Id": "lead-architect"},
            json={
                "session_id": session_id,
                "action": "approve",
                "candidate_digest": tampered_digest,
                "feedback": "Approved modification",
            },
        )
        self.assertEqual(resp_tampered.status_code, 400)
        self.assertIn("Candidate digest mismatch", resp_tampered.get_json().get("error", ""))

        # 2. Accept approval when digest matches
        resp_valid = auth_client.post(
            "/agentic/action",
            headers={"X-Session-Token": owner_token, "X-Approver-Id": "lead-architect"},
            json={
                "session_id": session_id,
                "action": "approve",
                "candidate_digest": correct_digest,
                "feedback": "Approved modification",
            },
        )
        self.assertEqual(resp_valid.status_code, 200)
        self.assertEqual(resp_valid.get_json().get("status"), "resumed")

        # 3. Verify approval history trail
        self.assertTrue(len(session.approval_history) >= 1)
        record = session.approval_history[-1]
        self.assertEqual(record["approver"], "lead-architect")
        self.assertEqual(record["candidate_digest"], correct_digest)
        self.assertEqual(record["action"], "approve")
        self.assertTrue(record["timestamp"])

    def test_packaging_exclusions_present_in_gitignore_and_manifest(self):
        """Sensitive directories and files (.env, SQLite databases, backups, build caches) must be excluded."""
        root_dir = Path(__file__).resolve().parent.parent
        gitignore_path = root_dir / ".gitignore"
        manifest_path = root_dir / "MANIFEST.in"

        self.assertTrue(gitignore_path.exists())
        gitignore_text = gitignore_path.read_text(encoding="utf-8")
        self.assertIn(".env*", gitignore_text)
        self.assertIn("backups/", gitignore_text)
        self.assertIn("instance/", gitignore_text)
        self.assertIn("*.sqlite*", gitignore_text)
        self.assertIn("*.db", gitignore_text)

        self.assertTrue(manifest_path.exists())
        manifest_text = manifest_path.read_text(encoding="utf-8")
        self.assertIn("exclude .env*", manifest_text)
        self.assertIn("recursive-exclude backups *", manifest_text)
        self.assertIn("recursive-exclude instance *", manifest_text)
        self.assertIn("recursive-exclude * *.sqlite*", manifest_text)
        self.assertIn("recursive-exclude * *.db", manifest_text)


if __name__ == "__main__":
    unittest.main()
