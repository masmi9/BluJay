"""
Performance test runner — spawns Docker k6 containers on demand.

Finding-triggered test matrix:
  race_condition  → concurrent load — state mutation under pressure
  auth_endpoint   → brute-force rate limit — lockout threshold detection
  idor_found      → enumeration load — ID range sweep at scale
  api_endpoint    → spike test — DoS viability assessment
  slow_response   → stress test — timing-based vulnerability confirmation

Results stream via asyncio.Queue to the WebSocket endpoint.
"""
import asyncio
import json
import os
import shutil
from pathlib import Path

import structlog

logger = structlog.get_logger()

K6_SCRIPTS_DIR = Path(__file__).parent.parent / "data" / "k6_scripts"

# Maps finding type keyword → script filename
_SCRIPT_MAP = {
    "race_condition": "race_condition.js",
    "race":           "race_condition.js",
    "auth_endpoint":  "auth_brute.js",
    "auth":           "auth_brute.js",
    "brute":          "auth_brute.js",
    "idor_found":     "idor_enum.js",
    "idor":           "idor_enum.js",
    "api_endpoint":   "spike_test.js",
    "spike":          "spike_test.js",
    "dos":            "spike_test.js",
    "slow_response":  "stress_test.js",
    "slow":           "stress_test.js",
    "stress":         "stress_test.js",
}

K6_IMAGE = os.getenv("K6_DOCKER_IMAGE", "grafana/k6:latest")


def _resolve_script(finding_type: str) -> Path:
    key = finding_type.lower().replace(" ", "_").replace("-", "_")
    for fragment, script in _SCRIPT_MAP.items():
        if fragment in key:
            return K6_SCRIPTS_DIR / script
    # Default to spike test
    return K6_SCRIPTS_DIR / "spike_test.js"


async def run_k6(
    job_id: str,
    target_url: str,
    finding_type: str,
    queue: asyncio.Queue,
    vus: int = 10,
    duration: str = "30s",
    extra_env: dict[str, str] | None = None,
) -> None:
    """
    Spawn a Docker k6 container, pipe the script via stdin, and emit
    progress events to *queue*.

    Event shapes emitted:
      {"type": "start",    "job_id": ..., "script": ...}
      {"type": "progress", "output": <k6 stdout line>}
      {"type": "metric",   "data": <parsed k6 JSON metric>}  (when --out json used)
      {"type": "done",     "job_id": ..., "exit_code": 0}
      {"type": "error",    "message": ...}
    """
    if not shutil.which("docker"):
        await queue.put({"type": "error", "message": "docker not found on PATH"})
        return

    script_path = _resolve_script(finding_type)
    if not script_path.exists():
        await queue.put({"type": "error", "message": f"k6 script not found: {script_path.name}"})
        return

    script_content = script_path.read_text()

    env_args: list[str] = [
        "-e", f"TARGET_URL={target_url}",
        "-e", f"VUS={vus}",
        "-e", f"DURATION={duration}",
    ]
    for k, v in (extra_env or {}).items():
        env_args += ["-e", f"{k}={v}"]

    cmd = [
        "docker", "run", "--rm", "-i",
        *env_args,
        K6_IMAGE,
        "run", "--out", "json=/dev/stderr", "-",
    ]

    await queue.put({"type": "start", "job_id": job_id, "script": script_path.name})
    logger.info("k6 starting", job_id=job_id, script=script_path.name, target=target_url)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # Write script to stdin then close it
        assert proc.stdin is not None
        proc.stdin.write(script_content.encode())
        proc.stdin.close()

        # Stream stdout (human-readable k6 output) and stderr (JSON metrics) concurrently
        async def _read_stdout() -> None:
            assert proc.stdout is not None
            async for line in proc.stdout:
                text = line.decode(errors="replace").rstrip()
                if text:
                    await queue.put({"type": "progress", "output": text})

        async def _read_stderr() -> None:
            assert proc.stderr is not None
            async for line in proc.stderr:
                text = line.decode(errors="replace").rstrip()
                if not text:
                    continue
                # k6 --out json emits NDJSON metric lines to stderr
                try:
                    metric = json.loads(text)
                    await queue.put({"type": "metric", "data": metric})
                except json.JSONDecodeError:
                    # Not JSON — k6 status line, pass through as progress
                    await queue.put({"type": "progress", "output": text})

        await asyncio.gather(_read_stdout(), _read_stderr())
        exit_code = await proc.wait()

        await queue.put({"type": "done", "job_id": job_id, "exit_code": exit_code})
        logger.info("k6 finished", job_id=job_id, exit_code=exit_code)

    except Exception as exc:
        await queue.put({"type": "error", "message": str(exc)})
        logger.error("k6 runner error", job_id=job_id, error=str(exc))
