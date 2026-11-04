"""Server-Sent Events (SSE) broadcaster and pub/sub event bus."""

from __future__ import annotations

import json
import logging
import queue
import threading
import time
from typing import Any, Dict, Generator, Optional

logger = logging.getLogger(__name__)


class EventBroadcaster:
    """Thread-safe event pub/sub bus for SSE streaming."""

    def __init__(self) -> None:
        self._queues: Dict[str, list[queue.Queue]] = {}
        self._lock = threading.Lock()

    def subscribe(self, session_id: str) -> queue.Queue:
        """Subscribe a new SSE listener queue to session events."""
        q: queue.Queue = queue.Queue(maxsize=200)
        with self._lock:
            if session_id not in self._queues:
                self._queues[session_id] = []
            self._queues[session_id].append(q)
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
        """Publish an event frame to all listeners for the given session."""
        session_id = payload.get("session_id")
        if not session_id:
            return

        with self._lock:
            listeners = list(self._queues.get(session_id, []))

        frame = {
            "event": event,
            "data": payload,
            "timestamp": time.time(),
        }

        for q in listeners:
            try:
                q.put_nowait(frame)
            except queue.Full:
                logger.warning("Listener queue full for session %s, dropping frame %s", session_id, event)

    def generate_sse_stream(
        self,
        session_id: str,
        timeout_seconds: float = 60.0,
    ) -> Generator[str, None, None]:
        """Yield formatted SSE text frames for Flask Response generator."""
        listener = self.subscribe(session_id)
        start_time = time.time()
        try:
            # Initial connection acknowledgement
            yield f"event: connected\ndata: {json.dumps({'session_id': session_id})}\n\n"

            while time.time() - start_time < timeout_seconds:
                try:
                    frame = listener.get(timeout=2.0)
                    event_type = frame["event"]
                    data_json = json.dumps(frame["data"])
                    yield f"event: {event_type}\ndata: {data_json}\n\n"

                    # If workflow completed or failed, close stream
                    if event_type in ("workflow_completed", "session_failed"):
                        break
                except queue.Empty:
                    # Ping / keepalive frame
                    yield ": ping\n\n"
        finally:
            self.unsubscribe(session_id, listener)


default_broadcaster = EventBroadcaster()
