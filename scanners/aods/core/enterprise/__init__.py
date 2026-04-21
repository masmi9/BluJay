"""
AODS Enterprise Module
======================

Enterprise integration components:
- rbac_manager: Role-based access control
- batch_cli: Batch analysis operations (data classes)
- Batch integration functions: execute_batch_analysis, create_batch_config, load_targets_from_file
"""

import json
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)


def load_targets_from_file(path: str) -> List[str]:
    """Load batch targets from a text file (one path per line).

    Lines starting with '#' are comments. Blank lines are skipped.
    Returns list of APK/target path strings.
    """
    targets = []
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Batch targets file not found: {path}")

    for line in file_path.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        targets.append(stripped)

    if not targets:
        raise ValueError(f"No targets found in {path}")

    logger.info("Loaded batch targets", count=len(targets), source=str(path))
    return targets


def create_batch_config(
    operation: str = "security_analysis",
    targets: list | None = None,
    output_dir: str = "./batch_results",
    enable_parallel_processing: bool = False,
    max_concurrent_analyses: int = 4,
    timeout_minutes: int = 60,
    enable_ml_enhancement: bool = True,
    report_formats: list | None = None,
) -> Dict[str, Any]:
    """Create a batch configuration dictionary.

    Returns a plain dict consumed by execute_batch_analysis().
    """
    return {
        "operation": operation,
        "targets": targets or [],
        "output_dir": output_dir,
        "enable_parallel": enable_parallel_processing,
        "max_concurrent": max_concurrent_analyses,
        "timeout_minutes": timeout_minutes,
        "enable_ml": enable_ml_enhancement,
        "report_formats": report_formats or ["json", "html"],
    }


def _run_single_target(
    target: Dict[str, Any],
    config: Dict[str, Any],
    index: int,
    total: int,
) -> Dict[str, Any]:
    """Run AODS scan on a single batch target via subprocess."""
    target_path = target.get("path", "")
    target_id = target.get("id", f"target_{index}")
    output_dir = Path(config.get("output_dir", "./batch_results")).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    result: Dict[str, Any] = {
        "target_id": target_id,
        "target_path": target_path,
        "success": False,
        "start_time": datetime.now().isoformat(),
        "end_time": None,
        "report_path": None,
        "error": None,
        "findings_count": 0,
    }

    # Sanitize target_id to prevent path traversal in report directory
    safe_id = target_id.replace("..", "").replace("/", "_").replace("\\", "_")
    if not safe_id:
        safe_id = f"target_{index}"

    # Validate target exists
    apk_path = Path(target_path).resolve()
    if not apk_path.exists():
        result["error"] = f"Target not found: {target_path}"
        result["end_time"] = datetime.now().isoformat()
        logger.warning("Batch target not found", target_id=target_id, path=target_path)
        return result

    # Build report dir and verify it stays under output_dir
    report_dir = (output_dir / safe_id).resolve()
    try:
        report_dir.relative_to(output_dir)
    except ValueError:
        result["error"] = "target_id path traversal not allowed"
        result["end_time"] = datetime.now().isoformat()
        logger.warning("Batch target_id path traversal", target_id=target_id)
        return result
    report_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        sys.executable,
        "dyna.py",
        "--apk", str(apk_path),
        "--mode", "safe",
        "--output-dir", str(report_dir),
        "--formats", "json",
    ]

    # ML toggle
    if not config.get("enable_ml", True):
        cmd.append("--disable-ml")

    # Additional report formats
    formats = config.get("report_formats", ["json"])
    if "html" in formats and "html" not in cmd:
        cmd.extend(["--formats", "json", "html"])

    timeout_secs = config.get("timeout_minutes", 60) * 60

    logger.info(
        "Starting batch target",
        target_id=target_id,
        index=index + 1,
        total=total,
        path=target_path,
    )

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_secs,
            cwd=str(Path(__file__).parent.parent.parent),  # repo root
        )

        result["end_time"] = datetime.now().isoformat()

        if proc.returncode == 0:
            result["success"] = True
            # Try to find generated report
            json_reports = list(report_dir.glob("*.json"))
            if json_reports:
                result["report_path"] = str(json_reports[0])
                # Extract findings count from report
                try:
                    report_data = json.loads(json_reports[0].read_text())
                    findings = report_data.get("findings", report_data.get("vulnerabilities", []))
                    result["findings_count"] = len(findings) if isinstance(findings, list) else 0
                except Exception:
                    pass
            logger.info("Batch target completed", target_id=target_id, findings=result["findings_count"])
        else:
            result["error"] = proc.stderr[:500] if proc.stderr else f"Exit code {proc.returncode}"
            logger.warning("Batch target failed", target_id=target_id, exit_code=proc.returncode)

    except subprocess.TimeoutExpired:
        result["error"] = f"Timeout after {config.get('timeout_minutes', 60)} minutes"
        result["end_time"] = datetime.now().isoformat()
        logger.warning("Batch target timed out", target_id=target_id)
    except Exception as e:
        result["error"] = str(e)
        result["end_time"] = datetime.now().isoformat()
        logger.error("Batch target exception", target_id=target_id, error=str(e))

    return result


def execute_batch_analysis(
    config: Dict[str, Any],
    targets: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Execute batch analysis across multiple targets.

    Args:
        config: Batch configuration dict from create_batch_config().
        targets: List of target dicts with at least {"id": ..., "path": ...}.

    Returns:
        Dict with keys: success, targets_processed, targets_total,
        reports_generated, results, errors, elapsed_seconds.
    """
    start_time = time.monotonic()
    total = len(targets)

    batch_result: Dict[str, Any] = {
        "success": False,
        "targets_processed": 0,
        "targets_total": total,
        "reports_generated": [],
        "results": [],
        "errors": [],
        "elapsed_seconds": 0,
    }

    if not targets:
        batch_result["success"] = True
        batch_result["error"] = "No targets to process"
        return batch_result

    output_dir = Path(config.get("output_dir", "./batch_results"))
    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Starting batch analysis", targets=total, parallel=config.get("enable_parallel", False))

    use_parallel = config.get("enable_parallel", False)
    max_workers = min(config.get("max_concurrent", 4), total)

    if use_parallel and total > 1:
        # Parallel execution
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(_run_single_target, target, config, i, total): i
                for i, target in enumerate(targets)
            }
            for future in as_completed(futures):
                try:
                    result = future.result()
                    batch_result["results"].append(result)
                    if result["success"]:
                        batch_result["targets_processed"] += 1
                        if result.get("report_path"):
                            batch_result["reports_generated"].append(result["report_path"])
                    else:
                        batch_result["errors"].append(
                            f"{result['target_id']}: {result.get('error', 'unknown')}"
                        )
                except Exception as e:
                    batch_result["errors"].append(str(e))
    else:
        # Sequential execution
        for i, target in enumerate(targets):
            result = _run_single_target(target, config, i, total)
            batch_result["results"].append(result)
            if result["success"]:
                batch_result["targets_processed"] += 1
                if result.get("report_path"):
                    batch_result["reports_generated"].append(result["report_path"])
            else:
                batch_result["errors"].append(
                    f"{result['target_id']}: {result.get('error', 'unknown')}"
                )

    batch_result["elapsed_seconds"] = round(time.monotonic() - start_time, 2)
    batch_result["success"] = batch_result["targets_processed"] > 0

    # Write summary report
    summary_path = output_dir / "batch_summary.json"
    try:
        summary_path.write_text(json.dumps(batch_result, indent=2, default=str))
        batch_result["reports_generated"].append(str(summary_path))
        logger.info("Batch summary written", path=str(summary_path))
    except Exception as e:
        logger.warning("Failed to write batch summary", error=str(e))

    logger.info(
        "Batch analysis complete",
        processed=batch_result["targets_processed"],
        total=total,
        elapsed=batch_result["elapsed_seconds"],
    )

    return batch_result
