"""
WebSocket endpoints for real-time streaming:
  /ws/analysis/{analysis_id}   — static analysis progress
  /ws/logcat/{session_id}      — logcat lines
  /ws/proxy/{session_id}       — captured proxy flows
  /ws/frida/{session_id}       — Frida events
"""
import asyncio
import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

ws_router = APIRouter()


async def _ws_send_loop(ws: WebSocket, queue: asyncio.Queue) -> None:
    """Pull from queue and send JSON to the WebSocket until disconnected."""
    try:
        while True:
            try:
                msg = await asyncio.wait_for(queue.get(), timeout=30)
                await ws.send_text(json.dumps(msg, default=str))
            except asyncio.TimeoutError:
                # Send ping to keep connection alive
                await ws.send_text(json.dumps({"type": "ping"}))
    except (WebSocketDisconnect, Exception):
        pass


# --- Analysis progress ---

@ws_router.websocket("/analysis/{analysis_id}")
async def ws_analysis_progress(ws: WebSocket, analysis_id: int):
    await ws.accept()
    from api.analysis import get_progress_queue
    queue = get_progress_queue(analysis_id)
    if queue is None:
        await ws.send_text(json.dumps({"type": "error", "message": "No active analysis"}))
        await ws.close()
        return
    await _ws_send_loop(ws, queue)


# --- Logcat (Android) ---

@ws_router.websocket("/logcat/{session_id}")
async def ws_logcat(ws: WebSocket, session_id: int):
    await ws.accept()
    from core.logcat_streamer import logcat_streamer
    queue = logcat_streamer.subscribe(session_id)
    try:
        await _ws_send_loop(ws, queue)
    finally:
        logcat_streamer.unsubscribe(session_id, queue)


# --- Syslog (iOS) ---

@ws_router.websocket("/syslog/{session_id}")
async def ws_syslog(ws: WebSocket, session_id: int):
    await ws.accept()
    from core.ios_syslog_streamer import ios_syslog_streamer
    queue = ios_syslog_streamer.subscribe(session_id)
    try:
        await _ws_send_loop(ws, queue)
    finally:
        ios_syslog_streamer.unsubscribe(session_id, queue)


# --- Proxy flows ---

@ws_router.websocket("/proxy/{session_id}")
async def ws_proxy(ws: WebSocket, session_id: int):
    await ws.accept()
    from api.router import get_proxy_manager
    pm = get_proxy_manager()
    queue = pm.subscribe(session_id)
    try:
        await _ws_send_loop(ws, queue)
    finally:
        pm.unsubscribe(session_id, queue)


# --- Frida events ---

@ws_router.websocket("/frida/{session_id}")
async def ws_frida(ws: WebSocket, session_id: int):
    await ws.accept()
    from api.router import get_frida_manager
    fm = get_frida_manager()
    queue = fm.subscribe(session_id)
    try:
        await _ws_send_loop(ws, queue)
    finally:
        fm.unsubscribe(session_id, queue)


# --- Brute-force job progress ---

@ws_router.websocket("/brute-force/{job_id}")
async def ws_brute_force(ws: WebSocket, job_id: int):
    await ws.accept()
    from api.brute_force import get_bf_queue
    queue = None
    for _ in range(20):
        queue = get_bf_queue(job_id)
        if queue:
            break
        await asyncio.sleep(0.25)
    if queue is None:
        await ws.send_text(json.dumps({"type": "error", "message": "No active brute-force job"}))
        await ws.close()
        return
    await _ws_send_loop(ws, queue)


# --- Fuzzing job progress ---

@ws_router.websocket("/fuzzing/{job_id}")
async def ws_fuzzing(ws: WebSocket, job_id: int):
    await ws.accept()
    from api.fuzzing import get_fuzz_queue
    queue = None
    for _ in range(20):
        queue = get_fuzz_queue(job_id)
        if queue:
            break
        await asyncio.sleep(0.25)
    if queue is None:
        await ws.send_text(json.dumps({"type": "error", "message": "No active fuzz job"}))
        await ws.close()
        return
    await _ws_send_loop(ws, queue)


# --- JWT brute-force progress ---

@ws_router.websocket("/jwt/{test_id}")
async def ws_jwt_brute(ws: WebSocket, test_id: int):
    await ws.accept()
    from api.jwt_test import get_brute_queue
    # Poll until the queue is registered (background task may start slightly after WS connects)
    queue = None
    for _ in range(20):
        queue = get_brute_queue(test_id)
        if queue:
            break
        await asyncio.sleep(0.25)
    if queue is None:
        await ws.send_text(json.dumps({"type": "error", "message": "No active brute-force for this test"}))
        await ws.close()
        return
    await _ws_send_loop(ws, queue)


# --- API test progress ---

@ws_router.websocket("/api-testing/{test_id}")
async def ws_api_test(ws: WebSocket, test_id: int):
    await ws.accept()
    from core.api_test_engine import get_test_queue
    queue = None
    for _ in range(20):
        queue = get_test_queue(test_id)
        if queue:
            break
        await asyncio.sleep(0.25)
    if queue is None:
        await ws.send_text(json.dumps({"type": "error", "message": "No active test"}))
        await ws.close()
        return
    await _ws_send_loop(ws, queue)


# --- OWASP scan progress ---

@ws_router.websocket("/owasp/{scan_id}")
async def ws_owasp_progress(ws: WebSocket, scan_id: int):
    await ws.accept()
    from core.owasp_scanner import get_progress_queue
    queue = get_progress_queue(scan_id)
    if queue is None:
        await ws.send_text(json.dumps({"type": "error", "message": "No active scan"}))
        await ws.close()
        return
    await _ws_send_loop(ws, queue)
