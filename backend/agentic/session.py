"""Thread-safe session state and context persistence for Agentic AI Layer."""

from __future__ import annotations

import hashlib
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Checkpoint:
    """Snapshot of source code and audit metrics at a specific step."""

    id: str
    step: int
    label: str
    code: str
    code_digest: str
    created_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TrajectoryStep:
    """Audit record of a single agent deliberation or tool execution turn."""

    step: int
    agent: str
    thought: str
    action: str
    tool: Optional[str] = None
    tool_arguments: Optional[Dict[str, Any]] = None
    observation: Optional[Dict[str, Any]] = None
    duration_ms: float = 0.0
    timestamp: float = field(default_factory=time.time)


@dataclass
class AgentSession:
    """Persistent working state for an autonomous agent execution workflow."""

    session_id: str
    original_code: str
    original_code_digest: str
    current_code: str
    task: str
    status: str = "idle"
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    plan: List[Dict[str, Any]] = field(default_factory=list)
    trajectory: List[TrajectoryStep] = field(default_factory=list)
    checkpoints: List[Checkpoint] = field(default_factory=list)
    pending_approval: Optional[Dict[str, Any]] = None
    is_approved: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def record_step(
        self,
        agent: str,
        thought: str,
        action: str,
        tool: Optional[str] = None,
        tool_arguments: Optional[Dict[str, Any]] = None,
        observation: Optional[Dict[str, Any]] = None,
        duration_ms: float = 0.0,
    ) -> TrajectoryStep:
        """Append an audited step to episodic trajectory memory."""
        with self._lock:
            step_num = len(self.trajectory) + 1
            step = TrajectoryStep(
                step=step_num,
                agent=agent,
                thought=thought,
                action=action,
                tool=tool,
                tool_arguments=tool_arguments,
                observation=observation,
                duration_ms=round(duration_ms, 3),
            )
            self.trajectory.append(step)
            self.updated_at = time.time()
            return step

    def create_checkpoint(self, label: str, metadata: Optional[Dict[str, Any]] = None) -> Checkpoint:
        """Create a safe snapshot of current code before applying modifications."""
        with self._lock:
            chk_id = f"chk_{len(self.checkpoints) + 1}_{uuid.uuid4().hex[:6]}"
            digest = hashlib.sha256(self.current_code.encode("utf-8")).hexdigest()
            checkpoint = Checkpoint(
                id=chk_id,
                step=len(self.trajectory),
                label=label,
                code=self.current_code,
                code_digest=digest,
                metadata=metadata or {},
            )
            self.checkpoints.append(checkpoint)
            self.updated_at = time.time()
            return checkpoint

    def rollback_to(self, checkpoint_id: str) -> bool:
        """Restore working code to a previous checkpoint."""
        with self._lock:
            for chk in reversed(self.checkpoints):
                if chk.id == checkpoint_id:
                    self.current_code = chk.code
                    self.updated_at = time.time()
                    return True
            return False

    def update_code(self, new_code: str) -> None:
        """Update working code with thread-safe timestamp tracking."""
        with self._lock:
            self.current_code = new_code
            self.updated_at = time.time()

    def set_status(self, status: str) -> None:
        """Update session state machine status."""
        with self._lock:
            self.status = status
            self.updated_at = time.time()

    def to_dict(self) -> Dict[str, Any]:
        """Serialize session state into a JSON-compatible dictionary."""
        with self._lock:
            return {
                "session_id": self.session_id,
                "status": self.status,
                "task": self.task,
                "created_at": self.created_at,
                "updated_at": self.updated_at,
                "original_code_digest": self.original_code_digest,
                "code_changed": self.current_code.strip() != self.original_code.strip(),
                "plan": self.plan,
                "trajectory": [asdict(t) for t in self.trajectory],
                "checkpoints": [asdict(c) for c in self.checkpoints],
                "pending_approval": self.pending_approval,
                "metadata": self.metadata,
            }


class SessionManager:
    """Thread-safe manager for concurrent active agent sessions."""

    def __init__(self, default_ttl_seconds: int = 1800) -> None:
        self._sessions: Dict[str, AgentSession] = {}
        self._lock = threading.Lock()
        self.default_ttl = default_ttl_seconds
        self._last_reap = time.time()

    def _maybe_cleanup(self) -> None:
        """Opportunistically reap expired sessions if interval elapsed."""
        now = time.time()
        if now - self._last_reap >= 60.0:
            self._last_reap = now
            self.cleanup_expired()

    def create_session(self, code: str, task: str = "") -> AgentSession:
        """Create and register a new stateful AgentSession."""
        self._maybe_cleanup()
        session_id = str(uuid.uuid4())
        digest = hashlib.sha256(code.encode("utf-8")).hexdigest()
        session = AgentSession(
            session_id=session_id,
            original_code=code,
            original_code_digest=digest,
            current_code=code,
            task=task or "Analyze and improve code quality and security.",
        )
        with self._lock:
            self._sessions[session_id] = session
        return session

    def get_session(self, session_id: str) -> Optional[AgentSession]:
        """Fetch session by ID."""
        self._maybe_cleanup()
        with self._lock:
            return self._sessions.get(session_id)

    def delete_session(self, session_id: str) -> bool:
        """Remove a session from registry."""
        with self._lock:
            if session_id in self._sessions:
                del self._sessions[session_id]
                return True
            return False

    def cleanup_expired(self, ttl_seconds: Optional[int] = None) -> int:
        """Prune inactive sessions past their expiration TTL."""
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl
        now = time.time()
        to_delete = []
        with self._lock:
            for sid, sess in self._sessions.items():
                if now - sess.updated_at > ttl:
                    to_delete.append(sid)
            for sid in to_delete:
                del self._sessions[sid]
        return len(to_delete)


# Global default session manager
default_session_manager = SessionManager()
