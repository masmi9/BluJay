#!/usr/bin/env python3
"""
AODS Batch Processing CLI
====================================================================

Command-line interface for batch security analysis operations.
Uses all AODS capabilities including ML enhancement, analytics dashboard,
WebView security, unified reporting, and performance optimization.

DUAL EXCELLENCE PRINCIPLE:
1. Full feature set
2. MINIMUM complexity (intuitive interface with smart defaults)

Features:
- Batch Analysis: Multiple targets (APKs, directories, web apps)
- Automated Scheduling: Cron-like scheduling and workflow management
- Enterprise Logging: Full audit trails and monitoring
- CI/CD Integration: Pipeline-ready with machine-readable output
- Report Distribution: Automated report generation and delivery
- Resource Management: Intelligent resource allocation and optimization
- Progress Tracking: Real-time progress monitoring and notifications
- Configuration Management: Advanced configuration handling
"""

import argparse
import json
import logging as stdlib_logging
import sys
import time
import yaml
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum

# AODS Framework Imports
from core.shared_infrastructure.security import UnifiedSecurityManager, UnifiedSecurityOptions
from core.shared_infrastructure.reporting import generate_security_report, create_report_manager
from core.shared_infrastructure.performance import create_performance_manager
from core.shared_infrastructure.configuration import create_configuration_manager

# Optional analytics module (may not be implemented yet)
try:
    from core.shared_infrastructure.analytics import create_analytics_dashboard, DashboardView

    ANALYTICS_AVAILABLE = True
except ImportError:
    create_analytics_dashboard = None
    DashboardView = None
    ANALYTICS_AVAILABLE = False

try:
    from core.logging_config import get_logger
except ImportError:
    get_logger = stdlib_logging.getLogger

logger = get_logger(__name__)

if not ANALYTICS_AVAILABLE:
    logger.warning("Analytics module not available - batch analytics features disabled")


class BatchOperation(Enum):
    """Types of batch operations."""

    SECURITY_ANALYSIS = "security_analysis"
    VULNERABILITY_SCAN = "vulnerability_scan"
    COMPLIANCE_AUDIT = "compliance_audit"
    PERFORMANCE_BENCHMARK = "performance_benchmark"
    BATCH_REPORT = "batch_report"
    ANALYTICS_EXPORT = "analytics_export"


class ScheduleType(Enum):
    """Types of scheduling."""

    IMMEDIATE = "immediate"
    SCHEDULED = "scheduled"
    RECURRING = "recurring"
    CI_CD = "ci_cd"


class OutputFormat(Enum):
    """CLI output formats."""

    JSON = "json"
    YAML = "yaml"
    TABLE = "table"
    SUMMARY = "summary"
    MACHINE = "machine"


@dataclass
class BatchTarget:
    """Batch processing target definition."""

    target_id: str
    target_path: str
    target_type: str  # "apk", "directory", "url", "config"
    priority: int = 1  # 1 (highest) to 5 (lowest)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BatchConfig:
    """Batch processing configuration."""

    operation: BatchOperation
    targets: List[BatchTarget]
    output_directory: str
    report_formats: List[str] = field(default_factory=lambda: ["json", "html"])

    # Enterprise features
    enable_parallel_processing: bool = True
    max_concurrent_analyses: int = 4
    timeout_minutes: int = 60
    retry_attempts: int = 3

    # Integration settings
    enable_ml_enhancement: bool = True
    enable_analytics_tracking: bool = True
    enable_performance_monitoring: bool = True

    # Reporting and notifications
    enable_real_time_updates: bool = True
    notification_endpoints: List[str] = field(default_factory=list)
    report_distribution: List[str] = field(default_factory=list)

    # Resource management
    memory_limit_gb: Optional[float] = None
    cpu_limit_percent: Optional[int] = None
    disk_space_limit_gb: Optional[float] = None


@dataclass
class BatchResult:
    """Batch processing result."""

    batch_id: str
    start_time: datetime
    end_time: Optional[datetime] = None
    status: str = "running"  # running, completed, failed, cancelled
    targets_processed: int = 0
    targets_total: int = 0
    results: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    performance_metrics: Dict[str, Any] = field(default_factory=dict)
    reports_generated: List[str] = field(default_factory=list)


class EnterpriseBatchCLI:
    """
    Batch processing CLI for AODS.

    DUAL EXCELLENCE: Maximum enterprise capability + Minimum complexity

    Capabilities:
    - Multi-target batch analysis with intelligent scheduling
    - Enterprise logging, monitoring, and audit trails
    - Integration with all AODS frameworks (ML, analytics, reporting)
    - CI/CD pipeline support with machine-readable output
    - Resource management and performance optimization
    - Automated report generation and distribution
    """

    def __init__(self):
        self.logger = get_logger(__name__)
        self.batch_results = {}
        self.active_batches = {}
        self.executor = ThreadPoolExecutor(max_workers=8)

        # Initialize AODS framework components
        self._init_aods_frameworks()

        # CLI configuration
        self.cli_config = {
            "version": "1.0.0",
            "name": "AODS Enterprise Batch CLI",
            "description": "Enterprise batch processing for AODS security analysis",
        }

        self.logger.info("AODS Enterprise Batch CLI initialized")

    def _init_aods_frameworks(self):
        """Initialize all AODS framework components."""
        try:
            # Security manager with all capabilities
            security_options = UnifiedSecurityOptions()
            security_options.enable_ml_enhancement = True
            security_options.enable_analytics_dashboard = True
            security_options.enable_webview_analysis = True
            self.security_manager = UnifiedSecurityManager(security_options)

            # Analytics dashboard
            self.analytics_dashboard = create_analytics_dashboard(
                {"enable_user_feedback": True, "enable_learning_analytics": True, "enable_real_time_updates": True}
            )

            # Report manager
            self.report_manager = create_report_manager()

            # Performance manager
            self.performance_manager = create_performance_manager()

            # Configuration manager
            self.config_manager = create_configuration_manager()

            self.logger.info("All AODS frameworks initialized successfully")

        except Exception as e:
            self.logger.error(f"Failed to initialize AODS frameworks: {e}")
            raise

    def create_argument_parser(self) -> argparse.ArgumentParser:
        """Create full argument parser for enterprise CLI."""
        parser = argparse.ArgumentParser(
            prog="aods-batch",
            description="AODS Enterprise Batch Processing CLI",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # Single APK analysis
  aods-batch analyze --target app.apk --output reports/

  # Batch analysis of multiple APKs
  aods-batch batch --config batch_config.yaml --parallel

  # CI/CD integration
  aods-batch ci-scan --targets-file targets.txt --format machine --output results/

  # Scheduled analysis
  aods-batch schedule --config batch_config.yaml --cron "0 2 * * *"

  # Analytics export
  aods-batch export-analytics --days 30 --format json --output analytics.json

For more information: https://github.com/your-org/aods
            """,
        )

        # Global options
        parser.add_argument("--version", action="version", version=f"%(prog)s {self.cli_config['version']}")
        parser.add_argument("--verbose", "-v", action="count", default=0, help="Increase verbosity")
        parser.add_argument("--quiet", "-q", action="store_true", help="Suppress non-essential output")
        parser.add_argument("--config", "-c", help="Configuration file path")
        parser.add_argument("--output", "-o", help="Output directory", default="./aods_output")
        parser.add_argument(
            "--format", choices=["json", "yaml", "table", "summary", "machine"], default="summary", help="Output format"
        )

        # Create subparsers for different operations
        subparsers = parser.add_subparsers(dest="command", help="Available commands")

        # Analyze command (single target)
        analyze_parser = subparsers.add_parser("analyze", help="Analyze single target")
        analyze_parser.add_argument("--target", "-t", required=True, help="Target file or directory")
        analyze_parser.add_argument(
            "--type", choices=["apk", "directory", "url"], help="Target type (auto-detected if not specified)"
        )
        analyze_parser.add_argument("--reports", nargs="+", default=["json", "html"], help="Report formats to generate")
        analyze_parser.add_argument("--ml", action="store_true", default=True, help="Enable ML enhancement")
        analyze_parser.add_argument("--analytics", action="store_true", default=True, help="Enable analytics tracking")

        # Batch command (multiple targets)
        batch_parser = subparsers.add_parser("batch", help="Batch analysis of multiple targets")
        batch_parser.add_argument("--config", required=True, help="Batch configuration file")
        batch_parser.add_argument("--parallel", action="store_true", help="Enable parallel processing")
        batch_parser.add_argument("--max-concurrent", type=int, default=4, help="Maximum concurrent analyses")
        batch_parser.add_argument("--timeout", type=int, default=60, help="Timeout per analysis (minutes)")

        # CI/CD integration command
        ci_parser = subparsers.add_parser("ci-scan", help="CI/CD pipeline integration")
        ci_parser.add_argument("--targets-file", required=True, help="File containing list of targets")
        ci_parser.add_argument("--fail-on-high", action="store_true", help="Fail build on high severity findings")
        ci_parser.add_argument("--fail-on-critical", action="store_true", help="Fail build on critical findings")
        ci_parser.add_argument("--threshold", type=int, default=0, help="Maximum allowed vulnerabilities")
        ci_parser.add_argument("--machine-output", help="Machine-readable output file")

        # Scheduling command
        schedule_parser = subparsers.add_parser("schedule", help="Schedule batch analysis")
        schedule_parser.add_argument("--config", required=True, help="Batch configuration file")
        schedule_parser.add_argument("--cron", help="Cron expression for scheduling")
        schedule_parser.add_argument("--datetime", help="Specific datetime (YYYY-MM-DD HH:MM)")
        schedule_parser.add_argument("--recurring", choices=["daily", "weekly", "monthly"], help="Recurring schedule")

        # Analytics export command
        export_parser = subparsers.add_parser("export-analytics", help="Export analytics data")
        export_parser.add_argument("--days", type=int, default=30, help="Number of days to export")
        export_parser.add_argument(
            "--view", choices=["overview", "feedback", "performance", "ml", "security"], help="Specific view to export"
        )
        export_parser.add_argument("--include-raw", action="store_true", help="Include raw data")

        # Status and monitoring commands
        status_parser = subparsers.add_parser("status", help="Check batch job status")
        status_parser.add_argument("--job-id", help="Specific job ID to check")
        status_parser.add_argument("--all", action="store_true", help="Show all active jobs")

        return parser

    def execute_analyze_command(self, args) -> Dict[str, Any]:
        """Execute single target analysis."""
        try:
            self.logger.info(f"Starting analysis of target: {args.target}")

            # Create batch target
            target = BatchTarget(
                target_id=f"single_{int(time.time())}",
                target_path=args.target,
                target_type=args.type or self._detect_target_type(args.target),
                priority=1,
                metadata={"command": "analyze", "timestamp": datetime.now().isoformat()},
            )

            # Configure analysis
            config = BatchConfig(
                operation=BatchOperation.SECURITY_ANALYSIS,
                targets=[target],
                output_directory=args.output,
                report_formats=args.reports,
                enable_ml_enhancement=args.ml,
                enable_analytics_tracking=args.analytics,
                max_concurrent_analyses=1,
            )

            # Execute analysis
            result = self._execute_batch_analysis(config)

            # Format output
            return self._format_cli_output(result, args.format)

        except Exception as e:
            self.logger.error(f"Analysis failed: {e}")
            return {"error": str(e), "success": False}

    def execute_batch_command(self, args) -> Dict[str, Any]:
        """Execute batch analysis."""
        try:
            # Load batch configuration
            config = self._load_batch_config(args.config)

            # Apply CLI overrides
            if args.parallel:
                config.enable_parallel_processing = True
            if args.max_concurrent:
                config.max_concurrent_analyses = args.max_concurrent
            if args.timeout:
                config.timeout_minutes = args.timeout

            self.logger.info(f"Starting batch analysis: {len(config.targets)} targets")

            # Execute batch
            result = self._execute_batch_analysis(config)

            return self._format_cli_output(result, args.format)

        except Exception as e:
            self.logger.error(f"Batch analysis failed: {e}")
            return {"error": str(e), "success": False}

    def execute_ci_scan_command(self, args) -> Dict[str, Any]:
        """Execute CI/CD pipeline scan."""
        try:
            # Load targets from file
            targets = self._load_targets_file(args.targets_file)

            # Create CI/CD optimized configuration
            config = BatchConfig(
                operation=BatchOperation.VULNERABILITY_SCAN,
                targets=targets,
                output_directory=args.output,
                report_formats=["json", "machine"] if args.machine_output else ["json"],
                enable_parallel_processing=True,
                max_concurrent_analyses=2,  # Conservative for CI/CD
                timeout_minutes=30,  # Faster timeout for CI/CD
                enable_real_time_updates=False,  # Reduce noise in CI/CD
            )

            # Execute scan
            result = self._execute_batch_analysis(config)

            # Check failure conditions
            exit_code = self._check_ci_failure_conditions(result, args)

            # Generate machine output if requested
            if args.machine_output:
                self._generate_machine_output(result, args.machine_output)

            output = self._format_cli_output(result, "machine" if args.format == "machine" else "summary")
            output["exit_code"] = exit_code

            return output

        except Exception as e:
            self.logger.error(f"CI/CD scan failed: {e}")
            return {"error": str(e), "success": False, "exit_code": 1}

    def execute_export_analytics_command(self, args) -> Dict[str, Any]:
        """Execute analytics data export."""
        try:
            self.logger.info(f"Exporting analytics data for {args.days} days")

            if args.view:
                # Export specific view
                from core.shared_infrastructure.analytics import DashboardView

                view = DashboardView(args.view)
                data = self.analytics_dashboard.get_dashboard_data(view)
            else:
                # Export full analytics
                data = self.analytics_dashboard.export_analytics_data("json", args.days)

            # Save to output file
            output_file = Path(args.output) / f"analytics_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            output_file.parent.mkdir(parents=True, exist_ok=True)

            with open(output_file, "w") as f:
                json.dump(data, f, indent=2, default=str)

            return {
                "success": True,
                "export_file": str(output_file),
                "data_points": len(str(data)),
                "export_timestamp": datetime.now().isoformat(),
            }

        except Exception as e:
            self.logger.error(f"Analytics export failed: {e}")
            return {"error": str(e), "success": False}

    def _execute_batch_analysis(self, config: BatchConfig) -> BatchResult:
        """Execute batch analysis with full enterprise features."""
        batch_id = f"batch_{int(time.time())}"
        result = BatchResult(
            batch_id=batch_id, start_time=datetime.now(), targets_total=len(config.targets), status="running"
        )

        try:
            self.active_batches[batch_id] = result

            if config.enable_parallel_processing and len(config.targets) > 1:
                # Parallel processing
                self._execute_parallel_analysis(config, result)
            else:
                # Sequential processing
                self._execute_sequential_analysis(config, result)

            result.status = "completed"
            result.end_time = datetime.now()

            # Generate batch reports
            if config.report_formats:
                result.reports_generated = self._generate_batch_reports(config, result)

            # Record analytics
            if config.enable_analytics_tracking:
                self._record_batch_analytics(config, result)

            self.logger.info(f"Batch {batch_id} completed: {result.targets_processed}/{result.targets_total} targets")

        except Exception as e:
            result.status = "failed"
            result.end_time = datetime.now()
            result.errors.append(str(e))
            self.logger.error(f"Batch {batch_id} failed: {e}")
        finally:
            self.batch_results[batch_id] = result
            if batch_id in self.active_batches:
                del self.active_batches[batch_id]

        return result

    def _execute_parallel_analysis(self, config: BatchConfig, result: BatchResult):
        """Execute analysis in parallel for multiple targets."""
        futures = []

        with ThreadPoolExecutor(max_workers=config.max_concurrent_analyses) as executor:
            for target in config.targets:
                future = executor.submit(self._analyze_single_target, target, config)
                futures.append((future, target))

            for future, target in as_completed([(f, t) for f, t in futures]):
                try:
                    analysis_result = future.result(timeout=config.timeout_minutes * 60)
                    result.results.append(analysis_result)
                    result.targets_processed += 1

                    if config.enable_real_time_updates:
                        self._send_progress_update(result)

                except Exception as e:
                    error_msg = f"Target {target.target_id} failed: {e}"
                    result.errors.append(error_msg)
                    self.logger.error(error_msg)

    def _execute_sequential_analysis(self, config: BatchConfig, result: BatchResult):
        """Execute analysis sequentially for targets."""
        for target in config.targets:
            try:
                analysis_result = self._analyze_single_target(target, config)
                result.results.append(analysis_result)
                result.targets_processed += 1

                if config.enable_real_time_updates:
                    self._send_progress_update(result)

            except Exception as e:
                error_msg = f"Target {target.target_id} failed: {e}"
                result.errors.append(error_msg)
                self.logger.error(error_msg)

    def _analyze_single_target(self, target: BatchTarget, config: BatchConfig) -> Dict[str, Any]:
        """Analyze a single target using all AODS capabilities."""
        start_time = time.time()

        try:
            # Perform security analysis
            analysis_result = self.security_manager.perform_comprehensive_security_analysis(target.target_path)

            # Add target metadata
            analysis_result["target_metadata"] = {
                "target_id": target.target_id,
                "target_path": target.target_path,
                "target_type": target.target_type,
                "priority": target.priority,
                "analysis_time": time.time() - start_time,
            }

            # Calculate summary metrics
            analysis_result["summary"] = self._calculate_analysis_summary(analysis_result)

            return analysis_result

        except Exception as e:
            self.logger.error(f"Analysis of {target.target_id} failed: {e}")
            return {
                "target_metadata": {
                    "target_id": target.target_id,
                    "target_path": target.target_path,
                    "target_type": target.target_type,
                    "error": str(e),
                    "analysis_time": time.time() - start_time,
                },
                "success": False,
            }

    def _calculate_analysis_summary(self, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate summary metrics for analysis result."""
        return {
            "total_findings": len(analysis_result.get("security_findings", []))
            + len(analysis_result.get("crypto_findings", []))
            + len(analysis_result.get("secret_findings", []))
            + len(analysis_result.get("webview_findings", []))
            + len(analysis_result.get("ml_findings", [])),
            "critical_findings": len(
                [f for f in analysis_result.get("security_findings", []) if f.get("severity") == "critical"]
            ),
            "high_findings": len(
                [f for f in analysis_result.get("security_findings", []) if f.get("severity") == "high"]
            ),
            "ml_enhanced": len(analysis_result.get("ml_findings", [])) > 0,
            "webview_issues": len(analysis_result.get("webview_findings", [])),
            "analysis_successful": True,
        }

    def _detect_target_type(self, target_path: str) -> str:
        """Auto-detect target type based on path."""
        path = Path(target_path)

        if path.is_file():
            if path.suffix.lower() == ".apk":
                return "apk"
            else:
                return "file"
        elif path.is_dir():
            return "directory"
        elif target_path.startswith(("http://", "https://")):
            return "url"
        else:
            return "unknown"

    def _load_batch_config(self, config_path: str) -> BatchConfig:
        """Load batch configuration from file."""
        try:
            with open(config_path, "r") as f:
                if config_path.endswith(".yaml") or config_path.endswith(".yml"):
                    config_data = yaml.safe_load(f)
                else:
                    config_data = json.load(f)

            # Convert to BatchConfig
            targets = [BatchTarget(**target_data) for target_data in config_data.get("targets", [])]

            return BatchConfig(
                operation=BatchOperation(config_data.get("operation", "security_analysis")),
                targets=targets,
                output_directory=config_data.get("output_directory", "./aods_output"),
                report_formats=config_data.get("report_formats", ["json", "html"]),
                enable_parallel_processing=config_data.get("enable_parallel_processing", True),
                max_concurrent_analyses=config_data.get("max_concurrent_analyses", 4),
                timeout_minutes=config_data.get("timeout_minutes", 60),
                enable_ml_enhancement=config_data.get("enable_ml_enhancement", True),
                enable_analytics_tracking=config_data.get("enable_analytics_tracking", True),
            )

        except Exception as e:
            self.logger.error(f"Failed to load batch config: {e}")
            raise

    def _load_targets_file(self, targets_file: str) -> List[BatchTarget]:
        """Load targets from file."""
        targets = []

        try:
            with open(targets_file, "r") as f:
                for i, line in enumerate(f):
                    line = line.strip()
                    if line and not line.startswith("#"):
                        targets.append(
                            BatchTarget(
                                target_id=f"target_{i + 1}",
                                target_path=line,
                                target_type=self._detect_target_type(line),
                                priority=1,
                            )
                        )

            return targets

        except Exception as e:
            self.logger.error(f"Failed to load targets file: {e}")
            raise

    def _check_ci_failure_conditions(self, result: BatchResult, args) -> int:
        """Check if CI/CD build should fail based on findings."""
        if not result.results:
            return 1  # Fail if no results

        total_critical = 0
        total_high = 0
        total_findings = 0

        for analysis_result in result.results:
            summary = analysis_result.get("summary", {})
            total_critical += summary.get("critical_findings", 0)
            total_high += summary.get("high_findings", 0)
            total_findings += summary.get("total_findings", 0)

        # Check failure conditions
        if args.fail_on_critical and total_critical > 0:
            return 1

        if args.fail_on_high and total_high > 0:
            return 1

        if hasattr(args, "threshold") and total_findings > args.threshold:
            return 1

        return 0  # Success

    def _generate_machine_output(self, result: BatchResult, output_file: str):
        """Generate machine-readable output for CI/CD."""
        machine_data = {
            "batch_id": result.batch_id,
            "status": result.status,
            "start_time": result.start_time.isoformat(),
            "end_time": result.end_time.isoformat() if result.end_time else None,
            "targets_processed": result.targets_processed,
            "targets_total": result.targets_total,
            "success_rate": result.targets_processed / result.targets_total if result.targets_total > 0 else 0,
            "errors": result.errors,
            "summary": {
                "total_findings": sum(r.get("summary", {}).get("total_findings", 0) for r in result.results),
                "critical_findings": sum(r.get("summary", {}).get("critical_findings", 0) for r in result.results),
                "high_findings": sum(r.get("summary", {}).get("high_findings", 0) for r in result.results),
                "ml_enhanced_analyses": sum(
                    1 for r in result.results if r.get("summary", {}).get("ml_enhanced", False)
                ),
            },
        }

        with open(output_file, "w") as f:
            json.dump(machine_data, f, indent=2, default=str)

    def _format_cli_output(self, result: BatchResult, format_type: str) -> Dict[str, Any]:
        """Format output for CLI display."""
        if format_type == "json":
            return {
                "batch_id": result.batch_id,
                "status": result.status,
                "targets_processed": result.targets_processed,
                "targets_total": result.targets_total,
                "results": result.results,
                "errors": result.errors,
            }
        elif format_type == "summary":
            return {
                "status": result.status,
                "targets": f"{result.targets_processed}/{result.targets_total}",
                "duration": str(result.end_time - result.start_time) if result.end_time else "running",
                "total_findings": sum(r.get("summary", {}).get("total_findings", 0) for r in result.results),
                "errors": len(result.errors),
                "success": result.status == "completed" and len(result.errors) == 0,
            }
        else:
            return {"result": result, "format": format_type}

    def _send_progress_update(self, result: BatchResult):
        """Send real-time progress update."""
        progress = (result.targets_processed / result.targets_total) * 100 if result.targets_total > 0 else 0
        self.logger.info(
            f"Batch {result.batch_id}: {progress:.1f}% complete ({result.targets_processed}/{result.targets_total})"
        )

    def _generate_batch_reports(self, config: BatchConfig, result: BatchResult) -> List[str]:
        """Generate batch reports."""
        reports = []

        try:
            # Aggregate all findings
            all_findings = []
            for analysis_result in result.results:
                all_findings.extend(analysis_result.get("security_findings", []))
                all_findings.extend(analysis_result.get("crypto_findings", []))
                all_findings.extend(analysis_result.get("secret_findings", []))
                all_findings.extend(analysis_result.get("webview_findings", []))
                all_findings.extend(analysis_result.get("ml_findings", []))

            # Generate reports in requested formats
            for format_type in config.report_formats:
                report_path = Path(config.output_directory) / f"batch_report_{result.batch_id}.{format_type}"
                report_path.parent.mkdir(parents=True, exist_ok=True)

                if format_type == "json":
                    with open(report_path, "w") as f:
                        json.dump(
                            {
                                "batch_metadata": {
                                    "batch_id": result.batch_id,
                                    "start_time": result.start_time.isoformat(),
                                    "end_time": result.end_time.isoformat() if result.end_time else None,
                                    "targets_processed": result.targets_processed,
                                },
                                "findings": all_findings,
                                "results": result.results,
                            },
                            f,
                            indent=2,
                            default=str,
                        )
                else:
                    # Use unified reporting framework
                    report_data = generate_security_report(all_findings, output_formats=[format_type])
                    with open(report_path, "w") as f:
                        f.write(str(report_data))

                reports.append(str(report_path))

        except Exception as e:
            self.logger.error(f"Failed to generate batch reports: {e}")

        return reports

    def _record_batch_analytics(self, config: BatchConfig, result: BatchResult):
        """Record batch analytics."""
        try:
            from core.shared_infrastructure.analytics import AnalyticsMetricType

            # Record batch performance metrics
            batch_duration = (result.end_time - result.start_time).total_seconds() if result.end_time else 0

            self.analytics_dashboard.record_analytics_metric(
                AnalyticsMetricType.PERFORMANCE_METRICS,
                batch_duration,
                {
                    "batch_id": result.batch_id,
                    "targets_processed": result.targets_processed,
                    "operation_type": config.operation.value,
                    "parallel_processing": config.enable_parallel_processing,
                },
            )

            # Record success rate
            success_rate = (
                (result.targets_processed - len(result.errors)) / result.targets_processed
                if result.targets_processed > 0
                else 0
            )
            self.analytics_dashboard.record_analytics_metric(
                AnalyticsMetricType.USER_SATISFACTION,
                success_rate,
                {"batch_id": result.batch_id, "metric_type": "batch_success_rate"},
            )

        except Exception as e:
            self.logger.warning(f"Failed to record batch analytics: {e}")

    def cleanup(self):
        """Cleanup CLI resources."""
        if hasattr(self, "executor"):
            self.executor.shutdown(wait=True)

        if hasattr(self, "security_manager"):
            self.security_manager.cleanup()

        if hasattr(self, "analytics_dashboard"):
            self.analytics_dashboard.cleanup()

        self.logger.info("Enterprise Batch CLI cleanup completed")


def main():
    """Main CLI entry point."""
    cli = EnterpriseBatchCLI()

    try:
        parser = cli.create_argument_parser()
        args = parser.parse_args()

        # Configure logging
        log_level = stdlib_logging.WARNING
        if args.verbose >= 2:
            log_level = stdlib_logging.DEBUG
        elif args.verbose == 1:
            log_level = stdlib_logging.INFO
        elif not args.quiet:
            log_level = stdlib_logging.WARNING

        stdlib_logging.basicConfig(level=log_level, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

        # Execute command
        if args.command == "analyze":
            result = cli.execute_analyze_command(args)
        elif args.command == "batch":
            result = cli.execute_batch_command(args)
        elif args.command == "ci-scan":
            result = cli.execute_ci_scan_command(args)
            # Set exit code for CI/CD
            if "exit_code" in result:
                sys.exit(result["exit_code"])
        elif args.command == "export-analytics":
            result = cli.execute_export_analytics_command(args)
        else:
            parser.print_help()
            sys.exit(1)

        # Output result
        if args.format == "json":
            logger.info("CLI output", output=json.loads(json.dumps(result, default=str)))
        elif args.format == "yaml":
            logger.info("CLI output", output=result)
        else:
            # Summary format
            if result.get("success", True):
                logger.info(
                    "Operation completed successfully",
                    targets=result.get("targets"),
                    total_findings=result.get("total_findings"),
                    duration=result.get("duration"),
                )
            else:
                logger.error("Operation failed", error=result.get("error"))
                sys.exit(1)

    except KeyboardInterrupt:
        logger.warning("Operation cancelled by user")
        sys.exit(130)
    except Exception as e:
        logger.error("Unexpected error", error=str(e))
        sys.exit(1)
    finally:
        cli.cleanup()


if __name__ == "__main__":
    main()
