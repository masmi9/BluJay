import io
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models.session import DynamicSession, ProxyFlow
from schemas.proxy import FlowsResponse, ProxyFlowDetail, ProxyFlowOut, ProxyStartRequest, ReplayResult, RepeaterRequest, RepeaterResult

router = APIRouter()

# ── Cert LAN server ──────────────────────────────────────────────────────────
_cert_server: HTTPServer | None = None
_cert_server_lock = threading.Lock()


def _make_cert_handler(cert_path):
    class CertHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            try:
                data = cert_path.read_bytes()
            except Exception:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            # iOS requires this exact content-type to trigger the install prompt
            self.send_header("Content-Type", "application/x-x509-ca-cert")
            self.send_header("Content-Disposition", 'attachment; filename="mitmproxy-ca-cert.pem"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass  # suppress stdout noise

    return CertHandler


@router.post("/start")
async def start_proxy(body: ProxyStartRequest, db: AsyncSession = Depends(get_db)):
    from api.router import get_proxy_manager
    pm = get_proxy_manager()

    # session_id=0 means standalone mode — no DynamicSession required
    if body.session_id == 0:
        await pm.start(0, body.port)
        return {"status": "started", "port": body.port, "standalone": True}

    result = await db.execute(select(DynamicSession).where(DynamicSession.id == body.session_id))
    sess = result.scalar_one_or_none()
    if not sess:
        raise HTTPException(404, "Session not found")

    await pm.start(body.session_id, body.port)
    sess.proxy_port = body.port
    await db.commit()
    return {"status": "started", "port": body.port}


@router.post("/stop/{session_id}")
async def stop_proxy(session_id: int):
    from api.router import get_proxy_manager
    pm = get_proxy_manager()
    await pm.stop(session_id)
    return {"status": "stopped"}


@router.get("/flows", response_model=FlowsResponse)
async def get_flows(
    session_id: int = Query(...),
    skip: int = 0,
    limit: int = 100,
    method: str | None = None,
    host: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    q = select(ProxyFlow).where(ProxyFlow.session_id == session_id)
    if method:
        q = q.where(ProxyFlow.method == method.upper())
    if host:
        q = q.where(ProxyFlow.host.contains(host))

    count_q = select(func.count()).select_from(q.subquery())
    total = (await db.execute(count_q)).scalar_one()
    items = (await db.execute(q.order_by(ProxyFlow.timestamp.desc()).offset(skip).limit(limit))).scalars().all()
    return {"total": total, "items": items}


@router.get("/flows/{flow_id}", response_model=ProxyFlowDetail)
async def get_flow(flow_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ProxyFlow).where(ProxyFlow.id == flow_id))
    flow = result.scalar_one_or_none()
    if not flow:
        raise HTTPException(404, "Flow not found")
    return flow


@router.post("/flows/{flow_id}/replay", response_model=ReplayResult)
async def replay_flow(flow_id: str, db: AsyncSession = Depends(get_db)):
    import httpx, json

    result = await db.execute(select(ProxyFlow).where(ProxyFlow.id == flow_id))
    flow = result.scalar_one_or_none()
    if not flow:
        raise HTTPException(404, "Flow not found")

    headers = json.loads(flow.request_headers or "{}")
    # Remove hop-by-hop headers
    for h in ("host", "content-length", "transfer-encoding", "connection"):
        headers.pop(h, None)

    async with httpx.AsyncClient(verify=False, timeout=30) as client:
        resp = await client.request(
            method=flow.method,
            url=flow.url,
            headers=headers,
            content=flow.request_body or b"",
        )
    return ReplayResult(
        status_code=resp.status_code,
        headers=dict(resp.headers),
        body=resp.text[:50000],
    )


@router.delete("/flows")
async def clear_flows(session_id: int = Query(...), db: AsyncSession = Depends(get_db)):
    from sqlalchemy import delete
    await db.execute(delete(ProxyFlow).where(ProxyFlow.session_id == session_id))
    await db.commit()
    return {"status": "cleared"}


@router.get("/cert")
async def get_cert():
    from api.router import get_proxy_manager
    pm = get_proxy_manager()
    cert_path = pm.get_cert_path()
    if not cert_path.exists():
        raise HTTPException(404, "Certificate not yet generated — start the proxy first")
    return FileResponse(str(cert_path), filename="mitmproxy-ca-cert.pem", media_type="application/x-pem-file")


class ConfigureDeviceRequest(BaseModel):
    serial: str
    host: str = "127.0.0.1"
    port: int = 8080
    push_cert: bool = True


@router.post("/configure-device")
async def configure_device(body: ConfigureDeviceRequest):
    """
    Sets the Wi-Fi proxy on the connected device via ADB and optionally pushes
    the mitmproxy CA cert to /sdcard/Download/ so the user can install it.
    """
    from core import adb_manager
    from api.router import get_proxy_manager

    # Set proxy on device
    proxy_ok = await adb_manager.set_proxy(body.serial, body.host, body.port)
    if not proxy_ok:
        raise HTTPException(500, "adb set proxy failed — is the device connected?")

    cert_result: dict | None = None
    if body.push_cert:
        pm = get_proxy_manager()
        cert_path = pm.get_cert_path()
        if cert_path.exists():
            cert_result = await adb_manager.push_cert(body.serial, cert_path)
        else:
            cert_result = {"pushed": False, "remote_path": None,
                           "note": "Start the proxy first to generate the cert"}

    return {
        "proxy_set": proxy_ok,
        "host": body.host,
        "port": body.port,
        "cert": cert_result,
        "install_hint": (
            "To trust the cert: Settings → Security → Install certificate → CA certificate → "
            "open mitmproxy-ca-cert.pem from Downloads"
        ),
    }


@router.post("/cert-server/start")
async def start_cert_server(port: int = 8888):
    """Start a LAN-accessible HTTP server that serves the mitmproxy CA cert on 0.0.0.0:{port}."""
    global _cert_server
    from api.router import get_proxy_manager
    pm = get_proxy_manager()
    cert_path = pm.get_cert_path()
    if not cert_path.exists():
        raise HTTPException(404, "Cert not found — start the proxy first to generate it")

    with _cert_server_lock:
        if _cert_server:
            _cert_server.shutdown()
            _cert_server = None

        handler = _make_cert_handler(cert_path)
        try:
            server = HTTPServer(("0.0.0.0", port), handler)
        except OSError as e:
            raise HTTPException(400, f"Cannot bind to port {port}: {e}")

        t = threading.Thread(target=server.serve_forever, daemon=True, name="cert-server")
        t.start()
        _cert_server = server

    return {"port": port, "running": True}


@router.post("/cert-server/stop")
async def stop_cert_server():
    global _cert_server
    with _cert_server_lock:
        if _cert_server:
            _cert_server.shutdown()
            _cert_server = None
    return {"running": False}


@router.get("/cert-server/status")
async def cert_server_status():
    return {"running": _cert_server is not None}


@router.get("/cert-qr")
async def cert_qr(url: str):
    """Generate a QR code PNG for the given cert URL so the iPhone can scan it."""
    try:
        import qrcode
        import qrcode.image.svg
        qr = qrcode.QRCode(box_size=6, border=2)
        qr.add_data(url)
        qr.make(fit=True)
        img = qr.make_image(fill_color="white", back_color="#18181b")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return Response(content=buf.getvalue(), media_type="image/png")
    except Exception as e:
        raise HTTPException(500, f"QR generation failed: {e}")


@router.get("/local-ip")
async def get_local_ip():
    """Returns the machine's LAN IPs so the frontend can show iOS setup instructions.
    Returns all candidate IPs so the user can pick the right one if auto-detection
    selects a VPN/Tailscale address instead of the Wi-Fi interface."""
    import socket

    candidates: list[str] = []

    # Method 1: enumerate all addresses for this hostname
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            addr = info[4][0]
            if addr not in candidates:
                candidates.append(addr)
    except Exception:
        pass

    # Method 2: UDP trick — reveals the default-route interface
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            addr = s.getsockname()[0]
            if addr not in candidates:
                candidates.append(addr)
    except Exception:
        pass

    # Remove loopback
    candidates = [ip for ip in candidates if not ip.startswith("127.")]

    # Score: prefer 192.168.x.x > 10.x.x.x > 172.16-31.x.x > everything else
    def _score(ip: str) -> int:
        if ip.startswith("192.168."):
            return 0
        if ip.startswith("10."):
            return 1
        if ip.startswith("172."):
            return 2
        return 10  # VPN / Tailscale (100.x.x.x) last

    candidates.sort(key=_score)
    local_ip = candidates[0] if candidates else "127.0.0.1"
    return {"local_ip": local_ip, "all_ips": candidates}


@router.post("/repeater", response_model=RepeaterResult)
async def repeater_send(body: RepeaterRequest):
    """Send an arbitrary HTTP request and return the response — powers the Repeater tab."""
    import httpx, time

    # Strip hop-by-hop headers that break direct httpx requests
    headers = {
        k: v for k, v in body.headers.items()
        if k.lower() not in ("host", "content-length", "transfer-encoding", "connection")
    }

    start = time.monotonic()
    async with httpx.AsyncClient(verify=False, timeout=30) as client:
        resp = await client.request(
            method=body.method.upper(),
            url=body.url,
            headers=headers,
            content=body.body.encode() if body.body else b"",
        )
    duration_ms = (time.monotonic() - start) * 1000

    return RepeaterResult(
        status_code=resp.status_code,
        headers=dict(resp.headers),
        body=resp.text[:100_000],
        duration_ms=round(duration_ms, 1),
    )


@router.post("/unconfigure-device")
async def unconfigure_device(serial: str):
    """Clears the device proxy setting."""
    from core import adb_manager
    ok = await adb_manager.clear_proxy(serial)
    return {"proxy_cleared": ok}

