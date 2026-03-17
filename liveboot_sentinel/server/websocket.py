"""
websocket.py - WebSocket connection manager for real-time alert broadcasting.
Manages connected dashboard clients and broadcasts alert events.
"""

import json
import logging
from typing import Optional

from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)

# Maximum concurrent WebSocket connections (DoS mitigation)
MAX_CONNECTIONS = 50


class ConnectionManager:
    """
    Manages active WebSocket connections and broadcasts messages.
    Thread-safe for async use within a single event loop.
    """

    def __init__(self):
        self._active: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> bool:
        """
        Accept a new WebSocket connection.

        Returns:
            True if connection accepted, False if limit reached.
        """
        if len(self._active) >= MAX_CONNECTIONS:
            logger.warning(
                "WebSocket connection limit (%d) reached — rejecting new connection",
                MAX_CONNECTIONS
            )
            await websocket.close(code=1008, reason="Connection limit reached")
            return False

        await websocket.accept()
        self._active.append(websocket)
        logger.info("WebSocket client connected — total: %d", len(self._active))
        return True

    def disconnect(self, websocket: WebSocket) -> None:
        """Remove a WebSocket connection from the active list."""
        try:
            self._active.remove(websocket)
            logger.info("WebSocket client disconnected — total: %d", len(self._active))
        except ValueError:
            pass  # Already removed

    async def broadcast(self, payload: dict) -> int:
        """
        Broadcast a JSON payload to all connected clients.
        Removes disconnected clients automatically.

        Args:
            payload: Dict to serialize and broadcast.

        Returns:
            Number of clients successfully messaged.
        """
        if not self._active:
            return 0

        # Serialize once
        try:
            message = json.dumps(payload)
        except (TypeError, ValueError) as e:
            logger.error("Cannot serialize WebSocket broadcast payload: %s", str(e)[:200])
            return 0

        disconnected = []
        success_count = 0

        for ws in list(self._active):
            try:
                await ws.send_text(message)
                success_count += 1
            except (WebSocketDisconnect, RuntimeError):
                disconnected.append(ws)
            except Exception as e:
                logger.warning("WebSocket send error: %s", str(e)[:100])
                disconnected.append(ws)

        # Clean up dead connections
        for ws in disconnected:
            self.disconnect(ws)

        if disconnected:
            logger.debug("Removed %d stale WebSocket connections", len(disconnected))

        return success_count

    async def send_alert_event(self, alert_data: dict) -> None:
        """
        Send a structured alert event to all dashboard clients.
        """
        payload = {
            "type": "alert",
            "data": alert_data,
        }
        count = await self.broadcast(payload)
        logger.debug("Alert broadcast to %d WebSocket clients", count)

    async def send_stats_event(self, stats: dict) -> None:
        """Send a stats update event to all dashboard clients."""
        payload = {
            "type": "stats",
            "data": stats,
        }
        await self.broadcast(payload)

    @property
    def connection_count(self) -> int:
        return len(self._active)


# Singleton manager instance
manager = ConnectionManager()
