#!/usr/bin/env python3
"""
AODS Enterprise ML Monitoring Dashboard - Stage 6.1.2
=====================================================

Real-time performance monitoring and drift detection for enterprise ML system.
Tracks precision, false positive rates, model drift, and enterprise KPIs.

ENTERPRISE MONITORING FEATURES:
- Real-time precision/FP rate tracking vs targets
- Model performance degradation alerts
- Drift detection with statistical significance testing
- Enterprise KPI dashboard with historical trends
- Automated performance reporting
- Health check integration for production deployment
"""

import logging
import json
import time
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field, asdict
from collections import deque
import warnings

# Data analysis and visualization
try:
    import numpy as np

    ANALYTICS_AVAILABLE = True
except ImportError:
    ANALYTICS_AVAILABLE = False
    warnings.warn("Advanced analytics libraries not available")

# Web dashboard (optional)
try:
    from flask import Flask, render_template_string, jsonify

    WEB_AVAILABLE = True
except ImportError:
    WEB_AVAILABLE = False
    warnings.warn("Web dashboard libraries not available")

logger = logging.getLogger(__name__)


@dataclass
class MonitoringMetrics:
    """Monitoring metrics for enterprise ML system."""

    # Core performance metrics
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    accuracy: float = 0.0
    false_positive_rate: float = 0.0

    # Enterprise targets tracking
    precision_vs_target: float = 0.0  # (actual - target) / target
    fp_rate_vs_target: float = 0.0  # (actual - target) / target
    target_achievement_score: float = 0.0  # Overall target achievement

    # Processing metrics
    throughput_per_minute: float = 0.0
    avg_processing_time_ms: float = 0.0
    error_rate: float = 0.0

    # Model health metrics
    confidence_distribution: List[float] = field(default_factory=list)
    drift_score: float = 0.0
    calibration_quality: float = 0.0

    # Temporal tracking
    timestamp: datetime = field(default_factory=datetime.now)
    samples_in_window: int = 0


@dataclass
class AlertConfig:
    """Alert configuration for monitoring system."""

    precision_threshold: float = 0.95
    fp_rate_threshold: float = 0.05
    drift_threshold: float = 0.1
    error_rate_threshold: float = 0.02
    throughput_threshold: float = 60.0  # per minute
    alert_cooldown_minutes: int = 30


class EnterpriseMLMonitoringDashboard:
    """
    Enterprise ML monitoring dashboard with real-time performance tracking,
    drift detection, and automated alerting capabilities.
    """

    def __init__(self, config: Dict[str, Any]):
        """Initialize enterprise monitoring dashboard."""

        self.config = config
        self.monitoring_config = config.get("monitoring", {})
        self.logger = logging.getLogger(__name__)

        # Monitoring configuration
        self.window_size = self.monitoring_config.get("window_size", 1000)
        self.retention_days = self.monitoring_config.get("retention_days", 90)
        self.dashboard_enabled = self.monitoring_config.get("dashboard_enabled", True)

        # Alert configuration
        self.alert_config = AlertConfig(
            precision_threshold=self.monitoring_config.get("precision_target", 0.95),
            fp_rate_threshold=self.monitoring_config.get("fp_rate_target", 0.05),
            drift_threshold=self.monitoring_config.get("drift_threshold", 0.1),
            error_rate_threshold=self.monitoring_config.get("error_rate_threshold", 0.02),
            alert_cooldown_minutes=self.monitoring_config.get("alert_cooldown", 30),
        )

        # Data storage
        self.metrics_history = deque(maxlen=self.window_size)
        self.performance_samples = deque(maxlen=self.window_size)
        self.alert_history = []

        # Real-time tracking
        self.current_metrics = MonitoringMetrics()
        self.baseline_metrics = None
        self.last_alert_time = {}
        self.monitoring_lock = threading.Lock()

        # Storage paths
        self.storage_dir = Path(config.get("storage_dir", "data/monitoring"))
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        # Initialize components
        self._initialize_monitoring()
        self._load_historical_data()

        # Start web dashboard if enabled
        if self.dashboard_enabled and WEB_AVAILABLE:
            self._initialize_web_dashboard()

        self.logger.info("Enterprise ML Monitoring Dashboard initialized")

    def _initialize_monitoring(self):
        """Initialize monitoring components."""

        # Metrics collection
        self.metrics_log_path = self.storage_dir / "metrics_history.jsonl"
        self.alerts_log_path = self.storage_dir / "alerts_history.jsonl"

        # Performance tracking
        self.sample_timestamps = deque(maxlen=self.window_size)
        self.processing_times = deque(maxlen=self.window_size)
        self.confidence_scores = deque(maxlen=self.window_size)
        self.error_counts = deque(maxlen=100)  # Track recent errors

        self.logger.info("Monitoring components initialized")

    def _load_historical_data(self):
        """Load historical monitoring data."""

        try:
            if self.metrics_log_path.exists():
                with open(self.metrics_log_path, "r") as f:
                    for line in f:
                        try:
                            data = json.loads(line.strip())
                            timestamp = datetime.fromisoformat(data["timestamp"])

                            # Only load recent data
                            if datetime.now() - timestamp <= timedelta(days=self.retention_days):
                                metrics = MonitoringMetrics(
                                    precision=data.get("precision", 0.0),
                                    recall=data.get("recall", 0.0),
                                    f1_score=data.get("f1_score", 0.0),
                                    accuracy=data.get("accuracy", 0.0),
                                    false_positive_rate=data.get("false_positive_rate", 0.0),
                                    throughput_per_minute=data.get("throughput_per_minute", 0.0),
                                    drift_score=data.get("drift_score", 0.0),
                                    timestamp=timestamp,
                                )
                                self.metrics_history.append(metrics)

                        except (json.JSONDecodeError, KeyError, ValueError) as e:
                            self.logger.debug(f"Failed to parse historical data line: {e}")

                self.logger.info(f"Loaded {len(self.metrics_history)} historical metric records")

        except Exception as e:
            self.logger.warning(f"Failed to load historical data: {e}")

    def update_performance_metrics(
        self, prediction_result: Dict[str, Any], ground_truth: Optional[bool] = None, processing_time_ms: float = 0.0
    ):
        """Update monitoring metrics with new prediction result."""

        with self.monitoring_lock:
            try:
                current_time = datetime.now()

                # Track timing and throughput
                self.sample_timestamps.append(current_time)
                self.processing_times.append(processing_time_ms)

                # Track confidence distribution
                confidence = prediction_result.get("confidence_score", 0.5)
                self.confidence_scores.append(confidence)

                # Track performance if ground truth available
                if ground_truth is not None:
                    predicted = not prediction_result.get("is_false_positive", False)
                    self.performance_samples.append(
                        {
                            "predicted": predicted,
                            "actual": ground_truth,
                            "confidence": confidence,
                            "timestamp": current_time,
                        }
                    )

                # Update real-time metrics
                self._update_realtime_metrics()

                # Check for alerts
                self._check_performance_alerts()

                # Log metrics periodically
                if len(self.sample_timestamps) % 100 == 0:
                    self._log_current_metrics()

            except Exception as e:
                self.logger.error(f"Failed to update performance metrics: {e}")
                self.error_counts.append(current_time)

    def _update_realtime_metrics(self):
        """Update real-time performance metrics."""

        try:
            current_time = datetime.now()

            # Calculate throughput (samples per minute)
            recent_timestamps = [ts for ts in self.sample_timestamps if current_time - ts <= timedelta(minutes=1)]
            self.current_metrics.throughput_per_minute = len(recent_timestamps)

            # Calculate average processing time
            if self.processing_times:
                self.current_metrics.avg_processing_time_ms = np.mean(list(self.processing_times))

            # Calculate error rate
            recent_errors = [ts for ts in self.error_counts if current_time - ts <= timedelta(minutes=10)]
            total_recent_samples = len(
                [ts for ts in self.sample_timestamps if current_time - ts <= timedelta(minutes=10)]
            )

            if total_recent_samples > 0:
                self.current_metrics.error_rate = len(recent_errors) / total_recent_samples

            # Update confidence distribution
            self.current_metrics.confidence_distribution = list(self.confidence_scores)[-50:]

            # Calculate performance metrics if we have ground truth samples
            if len(self.performance_samples) >= 10:
                self._calculate_performance_metrics()

            # Calculate drift score
            self._calculate_drift_score()

            self.current_metrics.timestamp = current_time
            self.current_metrics.samples_in_window = len(self.sample_timestamps)

        except Exception as e:
            self.logger.error(f"Failed to update real-time metrics: {e}")

    def _calculate_performance_metrics(self):
        """Calculate precision, recall, and other performance metrics."""

        if not ANALYTICS_AVAILABLE:
            return

        try:
            # Get recent samples for evaluation
            recent_samples = list(self.performance_samples)[-100:]  # Last 100 samples

            if len(recent_samples) < 10:
                return

            # Extract predictions and ground truth
            predictions = [sample["predicted"] for sample in recent_samples]
            actual = [sample["actual"] for sample in recent_samples]

            # Calculate confusion matrix components
            tp = sum(1 for p, a in zip(predictions, actual) if p and a)
            tn = sum(1 for p, a in zip(predictions, actual) if not p and not a)
            fp = sum(1 for p, a in zip(predictions, actual) if p and not a)
            fn = sum(1 for p, a in zip(predictions, actual) if not p and a)

            # Calculate metrics
            if tp + fp > 0:
                self.current_metrics.precision = tp / (tp + fp)

            if tp + fn > 0:
                self.current_metrics.recall = tp / (tp + fn)

            if tp + tn + fp + fn > 0:
                self.current_metrics.accuracy = (tp + tn) / (tp + tn + fp + fn)

            if fp + tn > 0:
                self.current_metrics.false_positive_rate = fp / (fp + tn)

            # Calculate F1 score
            if self.current_metrics.precision + self.current_metrics.recall > 0:
                self.current_metrics.f1_score = (
                    2
                    * self.current_metrics.precision
                    * self.current_metrics.recall
                    / (self.current_metrics.precision + self.current_metrics.recall)
                )

            # Calculate target achievement metrics
            self.current_metrics.precision_vs_target = (
                self.current_metrics.precision - self.alert_config.precision_threshold
            ) / self.alert_config.precision_threshold

            self.current_metrics.fp_rate_vs_target = (
                self.current_metrics.false_positive_rate - self.alert_config.fp_rate_threshold
            ) / self.alert_config.fp_rate_threshold

            # Overall target achievement score
            precision_achievement = min(1.0, self.current_metrics.precision / self.alert_config.precision_threshold)
            fp_achievement = min(
                1.0, self.alert_config.fp_rate_threshold / max(0.001, self.current_metrics.false_positive_rate)
            )
            self.current_metrics.target_achievement_score = (precision_achievement + fp_achievement) / 2

        except Exception as e:
            self.logger.error(f"Failed to calculate performance metrics: {e}")

    def _calculate_drift_score(self):
        """Calculate model drift score using statistical methods."""

        if not ANALYTICS_AVAILABLE or len(self.confidence_scores) < 50:
            return

        try:
            # Compare recent confidence distribution to baseline
            recent_confidences = list(self.confidence_scores)[-50:]

            if self.baseline_metrics is None:
                # Establish baseline from first 100 samples
                if len(self.confidence_scores) >= 100:
                    baseline_confidences = list(self.confidence_scores)[:50]
                    self.baseline_metrics = {
                        "confidence_mean": np.mean(baseline_confidences),
                        "confidence_std": np.std(baseline_confidences),
                    }
                return

            # Calculate drift using statistical tests
            baseline_mean = self.baseline_metrics["confidence_mean"]
            recent_mean = np.mean(recent_confidences)

            # Simple drift score based on mean shift
            self.current_metrics.drift_score = abs(recent_mean - baseline_mean) / max(0.1, baseline_mean)

            # Calculate confidence calibration quality (simplified)
            confidence_std = np.std(recent_confidences)
            expected_std = 0.2  # Expected standard deviation for well-calibrated model
            self.current_metrics.calibration_quality = min(1.0, expected_std / max(0.05, confidence_std))

        except Exception as e:
            self.logger.error(f"Failed to calculate drift score: {e}")

    def _check_performance_alerts(self):
        """Check for performance degradation and trigger alerts."""

        current_time = datetime.now()
        cooldown = timedelta(minutes=self.alert_config.alert_cooldown_minutes)

        alerts_to_send = []

        # Precision alert
        if (
            self.current_metrics.precision > 0
            and self.current_metrics.precision < self.alert_config.precision_threshold
        ):

            last_alert = self.last_alert_time.get("precision", datetime.min)
            if current_time - last_alert > cooldown:
                alerts_to_send.append(
                    {
                        "type": "precision_degradation",
                        "severity": "HIGH",
                        "message": f"Precision {self.current_metrics.precision:.3f} below target {self.alert_config.precision_threshold:.3f}",  # noqa: E501
                        "current_value": self.current_metrics.precision,
                        "target_value": self.alert_config.precision_threshold,
                    }
                )
                self.last_alert_time["precision"] = current_time

        # False positive rate alert
        if (
            self.current_metrics.false_positive_rate > 0
            and self.current_metrics.false_positive_rate > self.alert_config.fp_rate_threshold
        ):

            last_alert = self.last_alert_time.get("fp_rate", datetime.min)
            if current_time - last_alert > cooldown:
                alerts_to_send.append(
                    {
                        "type": "fp_rate_degradation",
                        "severity": "HIGH",
                        "message": f"FP rate {self.current_metrics.false_positive_rate:.3f} above target {self.alert_config.fp_rate_threshold:.3f}",  # noqa: E501
                        "current_value": self.current_metrics.false_positive_rate,
                        "target_value": self.alert_config.fp_rate_threshold,
                    }
                )
                self.last_alert_time["fp_rate"] = current_time

        # Drift alert
        if self.current_metrics.drift_score > self.alert_config.drift_threshold:
            last_alert = self.last_alert_time.get("drift", datetime.min)
            if current_time - last_alert > cooldown:
                alerts_to_send.append(
                    {
                        "type": "model_drift",
                        "severity": "MEDIUM",
                        "message": f"Model drift detected: {self.current_metrics.drift_score:.3f} > {self.alert_config.drift_threshold:.3f}",  # noqa: E501
                        "current_value": self.current_metrics.drift_score,
                        "target_value": self.alert_config.drift_threshold,
                    }
                )
                self.last_alert_time["drift"] = current_time

        # Send alerts
        for alert in alerts_to_send:
            self._send_alert(alert)

    def _send_alert(self, alert: Dict[str, Any]):
        """Send performance alert."""

        try:
            alert["timestamp"] = datetime.now().isoformat()
            self.alert_history.append(alert)

            # Log alert
            self.logger.warning(f"PERFORMANCE ALERT [{alert['severity']}]: {alert['message']}")

            # Save alert to file
            with open(self.alerts_log_path, "a") as f:
                f.write(json.dumps(alert) + "\n")

        except Exception as e:
            self.logger.error(f"Failed to send alert: {e}")

    def _log_current_metrics(self):
        """Log current metrics to persistent storage."""

        try:
            metrics_data = asdict(self.current_metrics)
            metrics_data["timestamp"] = self.current_metrics.timestamp.isoformat()

            with open(self.metrics_log_path, "a") as f:
                f.write(json.dumps(metrics_data, default=str) + "\n")

        except Exception as e:
            self.logger.error(f"Failed to log metrics: {e}")

    def get_dashboard_data(self) -> Dict[str, Any]:
        """Get full dashboard data for monitoring UI."""

        with self.monitoring_lock:
            try:
                return {
                    "current_metrics": asdict(self.current_metrics),
                    "targets": {
                        "precision_target": self.alert_config.precision_threshold,
                        "fp_rate_target": self.alert_config.fp_rate_threshold,
                        "drift_threshold": self.alert_config.drift_threshold,
                    },
                    "performance_trend": [
                        {
                            "timestamp": m.timestamp.isoformat(),
                            "precision": m.precision,
                            "fp_rate": m.false_positive_rate,
                            "drift_score": m.drift_score,
                            "target_achievement": m.target_achievement_score,
                        }
                        for m in list(self.metrics_history)[-50:]  # Last 50 data points
                    ],
                    "recent_alerts": [alert for alert in self.alert_history[-10:]],  # Last 10 alerts
                    "system_health": {
                        "total_samples": len(self.sample_timestamps),
                        "error_rate": self.current_metrics.error_rate,
                        "avg_processing_time": self.current_metrics.avg_processing_time_ms,
                        "throughput": self.current_metrics.throughput_per_minute,
                    },
                }
            except Exception as e:
                self.logger.error(f"Failed to get dashboard data: {e}")
                return {"error": str(e)}

    def _initialize_web_dashboard(self):
        """Initialize web-based monitoring dashboard."""

        if not WEB_AVAILABLE:
            self.logger.warning("Web dashboard libraries not available")
            return

        try:
            self.flask_app = Flask(__name__)

            @self.flask_app.route("/dashboard")
            def dashboard():
                return render_template_string(self._get_dashboard_html())

            @self.flask_app.route("/api/metrics")
            def api_metrics():
                return jsonify(self.get_dashboard_data())

            @self.flask_app.route("/health")
            def health_check():
                return jsonify(
                    {
                        "status": "healthy",
                        "timestamp": datetime.now().isoformat(),
                        "metrics_available": len(self.metrics_history) > 0,
                    }
                )

            # Security configuration
            dashboard_host = self.monitoring_config.get("dashboard_host", "127.0.0.1")  # Localhost only by default
            dashboard_port = self.monitoring_config.get("dashboard_port", 8080)

            # Security warning for network binding
            if dashboard_host == "0.0.0.0":
                self.logger.warning("⚠️ SECURITY WARNING: Dashboard binding to all interfaces (0.0.0.0)")
                self.logger.warning("   This exposes the dashboard to network access - ensure proper security measures")

            # Start Flask in separate thread
            dashboard_thread = threading.Thread(
                target=lambda: self.flask_app.run(
                    host=dashboard_host,
                    port=dashboard_port,
                    debug=False,  # Always disable debug for security
                    use_reloader=False,  # Disable reloader for security
                ),
                daemon=True,
            )
            dashboard_thread.start()

            self.logger.info(f"🚀 Web dashboard started on http://{dashboard_host}:{dashboard_port}")
            if dashboard_host == "127.0.0.1":
                self.logger.info("🛡️ Dashboard secured: localhost-only access")
            else:
                self.logger.warning("⚠️ Dashboard exposed to network - ensure proper security")

        except Exception as e:
            self.logger.error(f"Failed to initialize web dashboard: {e}")

    def _get_dashboard_html(self) -> str:
        """Get HTML template for monitoring dashboard."""

        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>AODS Enterprise ML Monitoring Dashboard</title>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
                .metric-card { border: 1px solid #ddd; padding: 15px; border-radius: 5px; }
                .metric-value { font-size: 2em; font-weight: bold; }
                .target-met { color: green; }
                .target-missed { color: red; }
                .chart-container { height: 400px; margin: 20px 0; }
            </style>
        </head>
        <body>
            <h1>AODS Enterprise ML Monitoring Dashboard</h1>

            <div class="metrics-grid">
                <div class="metric-card">
                    <h3>Precision</h3>
                    <div class="metric-value" id="precision">Loading...</div>
                    <div>Target: ≥95%</div>
                </div>

                <div class="metric-card">
                    <h3>False Positive Rate</h3>
                    <div class="metric-value" id="fp-rate">Loading...</div>
                    <div>Target: ≤5%</div>
                </div>

                <div class="metric-card">
                    <h3>Model Drift Score</h3>
                    <div class="metric-value" id="drift-score">Loading...</div>
                    <div>Alert Threshold: 0.1</div>
                </div>

                <div class="metric-card">
                    <h3>Target Achievement</h3>
                    <div class="metric-value" id="achievement">Loading...</div>
                    <div>Overall Score</div>
                </div>
            </div>

            <div class="chart-container">
                <canvas id="performance-chart"></canvas>
            </div>

            <div class="chart-container">
                <canvas id="alerts-chart"></canvas>
            </div>

            <script>
                // Auto-refresh dashboard every 30 seconds
                setInterval(updateDashboard, 30000);
                updateDashboard();

                function updateDashboard() {
                    fetch('/api/metrics')
                        .then(response => response.json())
                        .then(data => {
                            updateMetrics(data.current_metrics);
                            updateCharts(data.performance_trend);
                        })
                        .catch(error => console.error('Error:', error));
                }

                function updateMetrics(metrics) {
                    document.getElementById('precision').textContent = (metrics.precision * 100).toFixed(1) + '%';
                    document.getElementById('fp-rate').textContent = (metrics.false_positive_rate * 100).toFixed(1) + '%';  # noqa: E501
                    document.getElementById('drift-score').textContent = metrics.drift_score.toFixed(3);
                    document.getElementById('achievement').textContent = (metrics.target_achievement_score * 100).toFixed(1) + '%';  # noqa: E501

                    // Color coding based on targets
                    document.getElementById('precision').className =
                        'metric-value ' + (metrics.precision >= 0.95 ? 'target-met' : 'target-missed');
                    document.getElementById('fp-rate').className =
                        'metric-value ' + (metrics.false_positive_rate <= 0.05 ? 'target-met' : 'target-missed');
                }

                function updateCharts(trend) {
                    // Implementation would include Chart.js charts for performance trends
                    console.log('Performance trend:', trend);
                }
            </script>
        </body>
        </html>
        """


# Enterprise monitoring integration function


def initialize_enterprise_monitoring(ml_reducer, config: Dict[str, Any]) -> EnterpriseMLMonitoringDashboard:
    """
    Initialize enterprise monitoring dashboard for ML false positive reducer.

    Args:
        ml_reducer: Enterprise ML false positive reducer instance
        config: Monitoring configuration

    Returns:
        Monitoring dashboard instance
    """

    # Create monitoring dashboard
    dashboard = EnterpriseMLMonitoringDashboard(config)

    # Integrate monitoring with ML reducer
    original_analyze = ml_reducer.analyze_for_false_positive

    def monitored_analyze(content, title="", vulnerability_info=None, context=None):
        """Monitored analysis with performance tracking."""

        start_time = time.time()
        result = original_analyze(content, title, vulnerability_info, context)
        processing_time = (time.time() - start_time) * 1000

        # Update monitoring metrics
        dashboard.update_performance_metrics(prediction_result=asdict(result), processing_time_ms=processing_time)

        return result

    # Replace analyze method with monitored version
    ml_reducer.analyze_for_false_positive = monitored_analyze
    ml_reducer.monitoring_dashboard = dashboard

    logger.info("Enterprise monitoring integrated with ML reducer")

    return dashboard
