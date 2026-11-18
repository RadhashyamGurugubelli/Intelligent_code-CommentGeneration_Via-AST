"""Unit and contract tests for Session Repository, Schema Migrations, and Typed Schemas."""

from __future__ import annotations

from contextlib import closing
import sqlite3
import tempfile
import unittest
from pathlib import Path

from backend.agentic.repository import (
    InMemorySessionRepository,
    SQLiteSessionRepository,
)
from backend.agentic.schemas import (
    PlanPreviewRequest,
    SSEEventEnvelope,
    SSETicketResponse,
    SchemaValidationError,
    UserActionRequest,
    WorkflowRunRequest,
)
from backend.agentic.session import AgentSession, SessionManager


class TestTypedSchemas(unittest.TestCase):
    """Test suite verifying typed request and response schemas and error validation."""

    def test_workflow_run_request_valid(self):
        req = WorkflowRunRequest.from_dict({
            "code": "def hello(): pass",
            "task": "Scan for vulnerabilities",
            "auto_approve": False,
            "async": True,
            "execution_mode": "deterministic",
            "max_review_cycles": 3,
        })
        self.assertEqual(req.code, "def hello(): pass")
        self.assertEqual(req.task, "Scan for vulnerabilities")
        self.assertFalse(req.auto_approve)
        self.assertTrue(req.async_run)
        self.assertEqual(req.execution_mode, "deterministic")
        self.assertEqual(req.max_review_cycles, 3)

    def test_workflow_run_request_strict_boolean_rejection(self):
        with self.assertRaises(SchemaValidationError) as ctx:
            WorkflowRunRequest.from_dict({
                "code": "def hello(): pass",
                "auto_approve": "false",
            })
        self.assertIn("valid JSON boolean", str(ctx.exception))

        with self.assertRaises(SchemaValidationError) as ctx:
            WorkflowRunRequest.from_dict({
                "code": "def hello(): pass",
                "async": "0",
            })
        self.assertIn("valid JSON boolean", str(ctx.exception))

    def test_workflow_run_request_empty_or_oversized_code(self):
        with self.assertRaises(SchemaValidationError) as ctx:
            WorkflowRunRequest.from_dict({"code": ""})
        self.assertEqual(ctx.exception.status_code, 400)

        with self.assertRaises(SchemaValidationError) as ctx:
            WorkflowRunRequest.from_dict({"code": "x" * 60000}, max_source_length=50000)
        self.assertEqual(ctx.exception.status_code, 413)

    def test_user_action_request_validation(self):
        # Valid approve
        req = UserActionRequest.from_dict({
            "session_id": "test-session-12345678",
            "action": "APPROVE",
            "feedback": "Looks good",
        })
        self.assertEqual(req.action, "approve")
        self.assertEqual(req.feedback, "Looks good")

        # Invalid action
        with self.assertRaises(SchemaValidationError) as ctx:
            UserActionRequest.from_dict({
                "session_id": "test-session-12345678",
                "action": "delete_all",
            })
        self.assertEqual(ctx.exception.status_code, 400)

        # Invalid session_id
        with self.assertRaises(SchemaValidationError) as ctx:
            UserActionRequest.from_dict({
                "session_id": "bad;id",
                "action": "approve",
            })
        self.assertEqual(ctx.exception.status_code, 400)

    def test_plan_preview_and_ticket_schemas(self):
        prev = PlanPreviewRequest.from_dict({"task": "Optimize loop"})
        self.assertEqual(prev.task, "Optimize loop")

        ticket_resp = SSETicketResponse(
            status="success",
            ticket="sse_abc123",
            session_id="session-12345678",
            expires_in=60,
        )
        data = ticket_resp.to_dict()
        self.assertEqual(data["ticket"], "sse_abc123")
        self.assertEqual(data["expires_in"], 60)

    def test_sse_event_envelope(self):
        env = SSEEventEnvelope(
            event="task_assigned",
            session_id="session-12345678",
            agent="ATLAS",
            status="running",
            data={"task": "inspect_ast"},
            event_id=42,
        )
        wire = env.to_payload()
        self.assertEqual(wire["event_id"], 42)
        self.assertEqual(wire["agent"], "ATLAS")
        self.assertEqual(wire["task"], "inspect_ast")


class TestSessionRepositories(unittest.TestCase):
    """Test suite covering InMemory and SQLite session repository implementations."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_sessions.sqlite3"

    def tearDown(self):
        try:
            self.temp_dir.cleanup()
        except (PermissionError, OSError):
            pass

    def _create_sample_session(self, session_id="test_sess_001"):
        return AgentSession(
            session_id=session_id,
            original_code="def calc(): return 42\n",
            original_code_digest="abc123digest",
            current_code="def calc(): return 42\n",
            task="Audit code calculation",
            status="running",
        )

    def test_in_memory_repository_lifecycle(self):
        repo = InMemorySessionRepository()
        session = self._create_sample_session("mem_001")

        repo.save(session)
        loaded = repo.get("mem_001")
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.task, "Audit code calculation")

        all_sess = repo.list_all()
        self.assertEqual(len(all_sess), 1)

        stats = repo.runtime_statistics()
        self.assertEqual(stats["active_executions"], 1)

        self.assertTrue(repo.delete("mem_001"))
        self.assertIsNone(repo.get("mem_001"))

    def test_sqlite_repository_migration_and_persistence(self):
        repo = SQLiteSessionRepository(self.db_path)
        session = self._create_sample_session("sqlite_001")

        repo.save(session)
        loaded = repo.get("sqlite_001")
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.session_id, "sqlite_001")
        self.assertEqual(loaded.original_code, "def calc(): return 42\n")

        # Verify schema_migrations table exists and has versions applied
        with closing(sqlite3.connect(str(self.db_path))) as conn:
            cur = conn.execute("SELECT MAX(version) FROM schema_migrations")
            ver = cur.fetchone()[0]
            self.assertGreaterEqual(ver, 1)

            # Verify columns
            cur = conn.execute("PRAGMA table_info(agent_sessions)")
            col_names = [r[1] for r in cur.fetchall()]
            self.assertIn("session_id", col_names)
            self.assertIn("updated_at", col_names)
            self.assertIn("payload", col_names)

    def test_session_manager_custom_repository_injection(self):
        mem_repo = InMemorySessionRepository()
        mgr = SessionManager(repository=mem_repo)

        sess = mgr.create_session("def square(x): return x * x", task="Square number")
        self.assertIn(sess.session_id, mgr._sessions)

        # Verify it was stored in custom repository
        self.assertIsNotNone(mem_repo.get(sess.session_id))

        # Delete session through manager
        mgr.delete_session(sess.session_id)
        self.assertIsNone(mem_repo.get(sess.session_id))
        self.assertNotIn(sess.session_id, mgr._sessions)


if __name__ == "__main__":
    unittest.main()
