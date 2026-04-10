"""Standalone WebSocket listener for remote sensor connections.

Runs independently of the FastAPI web server so sensors can connect
in console, live, and web modes.
"""
from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

log = logging.getLogger(__name__)

_server_task: asyncio.Task | None = None
_ws_server = None


async def start_sensor_listener(
    app,
    host: str = "0.0.0.0",
    port: int = 8443,
) -> None:
    """Start the WebSocket sensor listener in the background.

    Args:
        app: LeethaApp instance (needs _remote_sensor_manager, packet_queue,
             capture_engine, config.data_dir).
        host: Bind address.
        port: Bind port.
    """
    global _server_task, _ws_server

    if _server_task and not _server_task.done():
        log.debug("sensor listener already running")
        return

    try:
        import websockets
        from websockets.asyncio.server import serve
    except ImportError:
        log.warning("websockets not installed — remote sensor listener disabled")
        return

    manager = app._remote_sensor_manager
    ca_dir = Path(app.config.data_dir) / "ca"

    async def handle_sensor(websocket):
        from scapy.layers.l2 import Ether

        # Extract sensor name from query params
        path = websocket.request.path if hasattr(websocket, 'request') else ""
        params = {}
        if "?" in path:
            query = path.split("?", 1)[1]
            for part in query.split("&"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    params[k] = v

        sensor_name = params.get("name")
        if not sensor_name:
            await websocket.close(1008, "Sensor name required")
            return

        if manager.is_revoked(sensor_name, ca_dir):
            await websocket.close(1008, "Certificate revoked")
            return

        try:
            session = manager.register(sensor_name, str(websocket.remote_address[0]))
        except ValueError:
            await websocket.close(1008, "Sensor already connected")
            return

        log.info("remote sensor connected: %s from %s", sensor_name, websocket.remote_address[0])

        try:
            async for message in websocket:
                # Text messages = control/discovery (JSON)
                if isinstance(message, str):
                    try:
                        payload = json.loads(message)
                        if payload.get("type") == "discovery":
                            ifaces = payload.get("interfaces", [])
                            session.set_discovered_interfaces(ifaces)
                            log.info(
                                "sensor %s reported %d interfaces",
                                sensor_name, len(ifaces),
                            )
                    except Exception:
                        pass
                    continue

                # Binary messages = packet frames
                frames = session.feed(message)
                for frame in frames:
                    try:
                        pkt = Ether(frame.packet)
                        iface_label = f"remote:{sensor_name}"
                        result = app.capture_engine._classify(pkt, iface_label)
                        if result is not None:
                            result.interface = iface_label
                            app.packet_queue.put_nowait(result)
                    except Exception:
                        pass
        except Exception:
            pass
        finally:
            manager.unregister(sensor_name)
            log.info("remote sensor disconnected: %s", sensor_name)

    async def _run_server():
        global _ws_server
        try:
            _ws_server = await serve(
                handle_sensor,
                host,
                port,
                logger=log,
            )
            log.info("sensor listener started on %s:%d", host, port)
            await _ws_server.serve_forever()
        except OSError as e:
            if "Address already in use" in str(e):
                log.info("sensor listener port %d in use (web server likely running) — skipping", port)
            else:
                log.warning("sensor listener failed: %s", e)
        except Exception as e:
            log.warning("sensor listener error: %s", e)

    _server_task = asyncio.create_task(_run_server())


async def stop_sensor_listener() -> None:
    """Stop the sensor listener."""
    global _server_task, _ws_server
    if _ws_server:
        _ws_server.close()
        _ws_server = None
    if _server_task and not _server_task.done():
        _server_task.cancel()
        try:
            await _server_task
        except asyncio.CancelledError:
            pass
        _server_task = None
