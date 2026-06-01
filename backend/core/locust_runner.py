"""
Locust performance test runner — spawns Docker locust containers on demand.

Scenario map:
  multi_user    → multi_user_session.py  — independent sessions per user
  oauth         → oauth_flow.py          — OAuth2 token acquisition + refresh
  jwt           → jwt_rotation.py        — JWT rotation under concurrent load
  websocket/ws  → websocket_load.py      — WebSocket connection load
  api_sequence  → api_sequence.py        — chained CRUD API sequence (default)

Script is piped via stdin using a sh wrapper so no volume mounts are needed.
Results stream via asyncio.Queue to the WebSocket endpoint using the same
event shapes as the k6 runner:
  {"type": "start",    "job_id": ..., "script": ...}
  {"type": "progress", "output": <text line>}
  {"type": "metric",   "data": {...}}
  {"type": "done",     "job_id": ..., "exit_code": 0}
  {"type": "error",    "message": ...}
"""
import asyncio
import os
import re
import shutil
from pathlib import Path
from urllib.parse import urlparse

import structlog

logger = structlog.get_logger()

LOCUST_SCRIPTS_DIR = Path(__file__).parent.parent / "data" / "locust_scripts"
LOCUST_IMAGE = os.getenv("LOCUST_DOCKER_IMAGE", "locustio/locust:latest")

_SCRIPT_MAP = {
    "multi_user":   "multi_user_session.py",
    "session":      "multi_user_session.py",
    "oauth":        "oauth_flow.py",
    "token":        "oauth_flow.py",
    "jwt":          "jwt_rotation.py",
    "rotation":     "jwt_rotation.py",
    "websocket":    "websocket_load.py",
    "ws":           "websocket_load.py",
    "api_sequence": "api_sequence.py",
    "sequence":     "api_sequence.py",
    "chain":        "api_sequence.py",
    "crud":         "api_sequence.py",
}

# Matches Locust's stats table rows in headless output:
# GET /path   100  0(0.00%) | 123  45  456  120 | 3.3  0.00
_STATS_RE = re.compile(
    r"^\s*\S+\s+"                  # method
    r"(/\S*)\s+"                   # path
    r"(\d+)\s+"                    # # reqs
    r"(\d+)\s*\([\d.]+%\)\s*\|"   # # fails
    r"\s*([\d.]+)\s+"              # avg ms
    r"([\d.]+)\s+"                 # min ms
    r"([\d.]+)\s+"                 # max ms
    r"([\d.]+)\s*\|"               # median ms
    r"\s*([\d.]+)"                 # req/s
)


def _resolve_script(scenario: str) -> Path:
    key = scenario.lower().replace(" ", "_").replace("-", "_")
    for fragment, script in _SCRIPT_MAP.items():
        if fragment in key:
            return LOCUST_SCRIPTS_DIR / script
    return LOCUST_SCRIPTS_DIR / "api_sequence.py"


def _base_url(target_url: str) -> str:
    p = urlparse(target_url)
    if p.netloc:
        return f"{p.scheme}://{p.netloc}"
    return target_url


async def run_locust(
    job_id: str,
    target_url: str,
    scenario: str,
    queue: asyncio.Queue,
    users: int = 10,
    spawn_rate: float = 2.0,
    run_time: str = "30s",
    extra_env: dict[str, str] | None = None,
) -> None:
    if not shutil.which("docker"):
        await queue.put({"type": "error", "message": "docker not found on PATH"})
        return

    script_path = _resolve_script(scenario)
    if not script_path.exists():
        await queue.put({"type": "error", "message": f"Locust script not found: {script_path.name}"})
        return

    script_content = script_path.read_text()
    host = _base_url(target_url)

    env_args: list[str] = [
        "-e", f"TARGET_URL={target_url}",
        "-e", f"USERS={users}",
        "-e", f"SPAWN_RATE={spawn_rate}",
        "-e", f"RUN_TIME={run_time}",
    ]
    for k, v in (extra_env or {}).items():
        env_args += ["-e", f"{k}={v}"]

    # websocket_load.py needs websocket-client; install it quietly first
    pip_step = "pip install websocket-client -q 2>/dev/null; " if "websocket" in script_path.name else ""

    shell_cmd = (
        f"{pip_step}"
        "cat > /tmp/locustfile.py && "
        f"locust -f /tmp/locustfile.py --headless "
        f"-u {users} -r {spawn_rate} -t {run_time} "
        f"--host {host}"
    )

    cmd = [
        "docker", "run", "--rm", "-i",
        *env_args,
        LOCUST_IMAGE,
        "/bin/sh", "-c", shell_cmd,
    ]

    await queue.put({"type": "start", "job_id": job_id, "script": script_path.name})
    logger.info("locust starting", job_id=job_id, script=script_path.name, target=target_url)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        assert proc.stdin is not None
        proc.stdin.write(script_content.encode())
        proc.stdin.close()

        async def _stream(source) -> None:
            async for line in source:
                text = line.decode(errors="replace").rstrip()
                if not text:
                    continue
                m = _STATS_RE.match(text)
                if m:
                    await queue.put({
                        "type": "metric",
                        "data": {
                            "metric": "locust_stats",
                            "path":      m.group(1),
                            "reqs":      int(m.group(2)),
                            "fails":     int(m.group(3)),
                            "avg_ms":    float(m.group(4)),
                            "min_ms":    float(m.group(5)),
                            "max_ms":    float(m.group(6)),
                            "median_ms": float(m.group(7)),
                            "rps":       float(m.group(8)),
                        },
                    })
                else:
                    await queue.put({"type": "progress", "output": text})

        await asyncio.gather(_stream(proc.stdout), _stream(proc.stderr))
        exit_code = await proc.wait()

        await queue.put({"type": "done", "job_id": job_id, "exit_code": exit_code})
        logger.info("locust finished", job_id=job_id, exit_code=exit_code)

    except Exception as exc:
        await queue.put({"type": "error", "message": str(exc)})
        logger.error("locust runner error", job_id=job_id, error=str(exc))
