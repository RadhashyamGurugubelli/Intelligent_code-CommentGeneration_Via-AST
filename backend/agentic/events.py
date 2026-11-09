"""Server-Sent Events (SSE) broadcaster and pub/sub event bus."""

from __future__ import annotations

import collections
import json
import logging
import queue
import threading
import time
from typing import Any, Dict, Generator, Optional

logger = logging.getLogger(__name__)


class EventBroadcaster:
    """Thread-safe event pub/sub bus for SSE streaming with event replay buffer."""

    def __init__(self, history_limit: int = 100) -> None:
        self._queues: Dict[str, list[queue.Queue]] = {}
        self._history: Dict[str, collections.deque] = {}
        self._history_limit = history_limit
        self._lock = threading.Lock()

    def subscribe(self, session_id: str) -> queue.Queue:
        """Subscribe a new SSE listener queue to session events and replay history."""
        q: queue.Queue = queue.Queue(maxsize=300)
        with self._lock:
            if session_id not in self._queues:
                self._queues[session_id] = []
            self._queues[session_id].append(q)

            # Replay historical frames so late-connecting clients never miss frames
            historical_frames = list(self._history.get(session_id, []))
            for frame in historical_frames:
                try:
                    q.put_nowait(frame)
                except queue.Full:
                    break
        return q

    def unsubscribe(self, session_id: str, q: queue.Queue) -> None:
        """Remove an SSE listener queue."""
        with self._lock:
            if session_id in self._queues:
                try:
                    self._queues[session_id].remove(q)
                except ValueError:
                    pass
                if not self._queues[session_id]:
                    del self._queues[session_id]

    def emit(self, event: str, payload: Dict[str, Any]) -> None:
        """Publish an event frame to all listeners and record in replay history."""
        session_id = payload.get("session_id")
        if not session_id:
            return

        frame = {
            "event": event,
            "data": payload,
            "timestamp": time.time(),
        }

        with self._lock:
            if session_id not in self._history:
                self._history[session_id] = collections.deque(maxlen=self._history_limit)
            self._history[session_id].append(frame)
            listeners = list(self._queues.get(session_id, []))

        for q in listeners:
            try:
                q.put_nowait(frame)
            except queue.Full:
                logger.warning("Listener queue full for session %s, dropping frame %s", session_id, event)

    def clear_session(self, session_id: str) -> None:
        """Prune queues and history for expired session."""
        with self._lock:
            self._queues.pop(session_id, None)
            self._history.pop(session_id, None)

    def generate_sse_stream(
        self,
        session_id: str,
        timeout_seconds: float = 300.0,
    ) -> Generator[str, None, None]:
        """Yield formatted SSE text frames for Flask Response generator."""
        listener = self.subscribe(session_id)
        start_time = time.time()
        last_ping = time.time()
        try:
            # Initial connection acknowledgement
            yield f"event: connected\ndata: {json.dumps({'session_id': session_id})}\n\n"

            while time.time() - start_time < timeout_seconds:
                try:
                    frame = listener.get(timeout=1.0)
                    event_type = frame["event"]
                    data_json = json.dumps(frame["data"])
                    yield f"event: {event_type}\ndata: {data_json}\n\n"

                    # If workflow completed or failed, close stream
                    if event_type in ("workflow_completed", "session_failed"):
                        break
                except queue.Empty:
                    # Send periodic keepalive heartbeat every 15 seconds
                    now = time.time()
                    if now - last_ping >= 15.0:
                        yield ": ping\n\n"
                        last_ping = now
        finally:
            self.unsubscribe(session_id, listener)


default_broadcaster = EventBroadcaster()
