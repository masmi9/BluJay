"""
core.cli.arg_parser - CLI argument parser for dyna.py (Track 46).

Contains ``create_argument_parser()`` which builds the argparse parser
for the AODS CLI.
"""

import argparse


def create_argument_parser():
    """Build and return the ArgumentParser for dyna.py CLI.

    Returns:
        argparse.ArgumentParser: Fully configured parser.
    """
    parser = argparse.ArgumentParser(
        description="AODS - Automated OWASP Dynamic Scan Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single APK Analysis with AUTO-DETECTION (NEW - Simplified!)
  python dyna.py --apk app.apk --mode deep

  # Manual package specification (backward compatible)
  python dyna.py --apk app.apk --pkg com.example.app --mode deep

  # Auto-detection with user confirmation
  python dyna.py --apk app.apk --confirm-pkg --mode deep

  # Disable auto-detection, force manual entry
  python dyna.py --apk app.apk --no-auto-pkg --mode deep

  # Vulnerable app mode (package auto-detected)
  python dyna.py --apk app.apk --vulnerable-app-mode
Environment Variables:
  AODS_ALLOW_VULNERABLE_APP_HEURISTICS=1
    Enable name-pattern heuristics from config/vulnerable_app_heuristics.yaml (default: 0/off)
  AODS_AI_FRIDA_ENABLE=1
    Enable rule-based Frida dynamic analysis suggestions
  AODS_AI_FRIDA_ML_ENABLE=1
    Enable ML-based Frida suggestions (requires model artifacts)
  AODS_AI_FRIDA_MIN_SCORE=0.6
    Minimum score threshold for ML suggestions
  AODS_REFERENCE_ONLY=1
    Emit reference-only reports to reduce artifact size in CI
  AODS_CANONICAL=1
    Use canonical modular execution paths

  # Static/Dynamic analysis only
  python dyna.py --apk app.apk --static-only
  python dyna.py --apk app.apk --dynamic-only

  # Enterprise Batch Processing with auto-detection
  python dyna.py --batch-targets config/ci_cd_targets.txt --batch-parallel

  # Batch processing with configuration
  python dyna.py --batch-config config/enterprise_batch_config.yaml

  # CI/CD Pipeline Integration
  python dyna.py --batch-targets targets.txt --ci-mode --fail-on-critical
        """,
    )

    # Primary arguments for single APK analysis
    parser.add_argument("--apk", help="Path to APK file to analyze")
    parser.add_argument("--pkg", help="Package name of the application (auto-detected if not provided)")

    # Scan mode argument (CRITICAL FIX)
    parser.add_argument(
        "--mode",
        choices=["safe", "deep", "agent"],
        default="safe",
        help="Scan mode: 'safe' (basic), 'deep' (full), 'agent' (AI-orchestrated) (default: safe)",
    )

    # Scan profile for performance optimization
    parser.add_argument(
        "--profile",
        choices=["lightning", "fast", "standard", "deep"],
        help="Scan profile for performance optimization: 'lightning' (~30s), 'fast' (~2-3min), 'standard' (~5-8min), 'deep' (~15+min). Auto-selected based on mode if not specified.",  # noqa: E501
    )

    # Testing mode for faster development iteration
    parser.add_argument(
        "--testing-mode",
        action="store_true",
        help="Enable testing mode: automatically uses lightning profile for faster development iteration (overrides --profile)",  # noqa: E501
    )

    # Report format arguments
    parser.add_argument(
        "--formats",
        nargs="+",
        choices=["txt", "json", "csv", "html", "all"],
        default=["json"],
        help="Report formats to generate (default: json)",
    )

    # Parallel execution arguments
    parser.add_argument("--parallel", action="store_true", help="Enable parallel plugin execution")

    parser.add_argument("--parallel-windows", action="store_true", help="Run analysis in separate windows")

    # Android 14 pattern control arguments
    parser.add_argument(
        "--disable-android14-webview-patterns",
        action="store_true",
        help="Disable Android 14 WebView security patterns (enabled by default)",
    )

    parser.add_argument(
        "--disable-android14-network-patterns",
        action="store_true",
        help="Disable Android 14 network security patterns (enabled by default)",
    )

    parser.add_argument(
        "--enable-android14-audit-patterns",
        action="store_true",
        help="Enable Android 14 data access auditing patterns (compliance features)",
    )
    # Crypto toggles (parity with YAML)
    parser.add_argument(
        "--enable-crypto-rng-patterns",
        action="store_true",
        help="Enable RNG-related crypto rules (e.g., Math.random, SHA1PRNG, constant seeds)",
    )
    parser.add_argument(
        "--enable-crypto-policy-patterns",
        action="store_true",
        help="Enable policy-oriented crypto rules (e.g., DSA/DH keygen heuristics)",
    )
    # GDPR/policy patterns toggle
    parser.add_argument(
        "--enable-gdpr-policy-patterns",
        action="store_true",
        help="Enable GDPR/data policy-oriented patterns gated by enable_gdpr_policy_patterns",
    )
    # HTTP allowlist mode and job constraints toggles
    parser.add_argument(
        "--http-mode",
        choices=["strict", "internal", "auto"],
        help="HTTP detection mode: strict (prod), internal (RFC1918 allowlist), or auto (selects based on environment)",
    )
    parser.add_argument(
        "--enable-job-constraints-patterns",
        action="store_true",
        help="Enable WorkManager/JobScheduler constraints patterns",
    )

    # ML filtering control arguments
    parser.add_argument(
        "--force-ml-filtering",
        action="store_true",
        help="Force ML false positive filtering even for vulnerable/training apps",
    )
    parser.add_argument(
        "--app-profile",
        choices=["production", "vulnerable", "qa_vulnerable"],
        help="Select app profile to drive ML defaults (production vs vulnerable)",
    )
    parser.add_argument(
        "--ml-fp-threshold", type=float, help="Override ML false-positive threshold for the selected profile (0..1)"
    )

    parser.add_argument("--optimized", action="store_true", help="Enable advanced optimized execution")

    parser.add_argument("--max-workers", type=int, help="Maximum number of worker processes")

    # Other options
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")

    parser.add_argument("--benchmark", action="store_true", help="Enable benchmarking mode")

    # PHASE 7: Architecture migration options
    parser.add_argument(
        "--canonical", action="store_true", help="Use canonical modular architecture (same as AODS_CANONICAL=1)"
    )

    # ML Configuration arguments (Basic ML controls available)
    parser.add_argument(
        "--disable-ml",
        action="store_true",
        help="Disable machine learning components (ML enabled by default with XGBoost, confidence analysis, and false positive reduction)",  # noqa: E501
    )

    parser.add_argument(
        "--disable-enhancements",
        action="store_true",
        help="Disable vulnerability enhancements (recommendations, ML analysis, smart filtering) for basic compatibility mode",  # noqa: E501
    )

    parser.add_argument(
        "--enable-malware-scan",
        action="store_true",
        help="Enable ML-based APK malware detection (analyzes structural features to detect malware without AV signatures)",  # noqa: E501
    )

    parser.add_argument(
        "--vulnerable-app-mode",
        action="store_true",
        help=(
            "Enable vulnerable app mode with relaxed detection settings for testing/training apps. "
            "To use name-pattern heuristics from config/vulnerable_app_heuristics.yaml, set "
            "AODS_ALLOW_VULNERABLE_APP_HEURISTICS=1 (default is off)."
        ),
    )

    # Scan type separation arguments for parallel execution
    parser.add_argument("--static-only", action="store_true", help="Run only static analysis (for parallel execution)")

    parser.add_argument(
        "--dynamic-only", action="store_true", help="Run only dynamic analysis (for parallel execution)"
    )

    parser.add_argument(
        "--disable-static-analysis", action="store_true", help="Disable static analysis (enable only dynamic analysis)"
    )

    parser.add_argument(
        "--disable-dynamic-analysis", action="store_true", help="Disable dynamic analysis (enable only static analysis)"
    )

    # Objection Integration arguments
    parser.add_argument(
        "--with-objection",
        action="store_true",
        help="Enable Objection integration for interactive testing and verification",
    )

    parser.add_argument(
        "--objection-mode",
        choices=["recon", "verify", "training", "dev"],
        help="Objection integration mode: 'recon' for reconnaissance, 'verify' for finding verification, 'training' for guided learning, 'dev' for development testing",  # noqa: E501
    )

    parser.add_argument(
        "--objection-timeout", type=int, default=300, help="Timeout for Objection operations in seconds (default: 300)"
    )

    parser.add_argument(
        "--export-objection-commands",
        action="store_true",
        help="Export Objection verification commands to file for manual execution",
    )

    parser.add_argument("--output", help="Output file path for results (default: auto-generated)")
    parser.add_argument(
        "--skip-if-report-exists", action="store_true", help="Skip scanning if --output exists and is non-empty"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Parse args, print planned actions, and exit without scanning"
    )

    parser.add_argument(
        "--parallel-scan",
        action="store_true",
        default=True,
        help="Use parallel scan manager to run static and dynamic scans in separate windows (DEFAULT)",
    )

    parser.add_argument(
        "--sequential",
        action="store_true",
        help="Run scans sequentially in single process (disables default parallel execution)",
    )

    # Cross-platform analysis arguments
    parser.add_argument(
        "--cross-platform",
        action="store_true",
        help="Enable cross-platform analysis (Flutter, React Native, Xamarin, PWA)",
    )

    parser.add_argument(
        "--frameworks",
        nargs="+",
        choices=["flutter", "react_native", "xamarin", "pwa", "all"],
        default=["all"],
        help="Specific frameworks to analyze (default: all)",
    )

    # Configuration and Enterprise Features
    parser.add_argument(
        "--config", help="Path to custom YAML configuration file (e.g., --config config/production_config.yaml)"
    )

    parser.add_argument(
        "--compliance",
        choices=["nist", "masvs", "owasp", "iso27001"],
        help="Enable compliance framework analysis (e.g., --compliance nist)",
    )

    parser.add_argument(
        "--environment",
        choices=["development", "staging", "production"],
        help="Select deployment environment configuration",
    )

    parser.add_argument(
        "--enterprise-optimization", action="store_true", help="Enable enterprise performance optimization features"
    )

    # Enterprise Batch Processing Features (PHASE 13)
    parser.add_argument(
        "--batch-targets", help="Path to file containing list of targets for batch processing (one per line)"
    )

    parser.add_argument("--batch-config", help="Path to YAML configuration file for batch processing settings")

    parser.add_argument(
        "--batch-parallel",
        action="store_true",
        help="Enable parallel processing for batch analysis (default: sequential)",
    )

    parser.add_argument(
        "--batch-max-concurrent",
        type=int,
        default=4,
        help="Maximum concurrent analyses for batch processing (default: 4)",
    )

    parser.add_argument(
        "--batch-timeout", type=int, default=60, help="Timeout per target in batch processing (minutes, default: 60)"
    )

    parser.add_argument(
        "--batch-output-dir", help="Output directory for batch processing results (default: ./batch_results)"
    )

    parser.add_argument(
        "--ci-mode", action="store_true", help="Enable CI/CD mode with machine-readable output and exit codes"
    )

    parser.add_argument(
        "--fail-on-critical",
        action="store_true",
        help="Exit with error code if critical vulnerabilities found (CI/CD mode)",
    )

    parser.add_argument(
        "--fail-on-high",
        action="store_true",
        help="Exit with error code if high severity vulnerabilities found (CI/CD mode)",
    )

    # Automatic Package Detection Features
    pkg_group = parser.add_argument_group("Package Detection Options")

    pkg_group.add_argument(
        "--auto-pkg", action="store_true", default=True, help="Enable automatic package name detection (default)"
    )

    pkg_group.add_argument(
        "--no-auto-pkg",
        action="store_false",
        dest="auto_pkg",
        help="Disable automatic package detection, require manual entry",
    )

    pkg_group.add_argument(
        "--confirm-pkg", action="store_true", help="Always ask for confirmation of auto-detected package names"
    )

    pkg_group.add_argument(
        "--pkg-confidence-threshold",
        type=float,
        default=0.8,
        metavar="0.0-1.0",
        help="Minimum confidence threshold for auto-detection (default: 0.8)",
    )

    # Interactive Features
    parser.add_argument("--dashboard", action="store_true", help="Launch interactive executive reporting dashboard")

    # Executive Dashboard Configuration
    parser.add_argument(
        "--executive-dashboard", action="store_true", help="Generate executive dashboard report (enabled by default)"
    )

    parser.add_argument("--no-executive-dashboard", action="store_true", help="Disable executive dashboard generation")

    parser.add_argument(
        "--executive-dashboard-out",
        type=str,
        metavar="DIR",
        help="Output directory for executive dashboard (default: same as report output)",
    )

    parser.add_argument("--feedback-server", action="store_true", help="Start web-based ML training feedback interface")

    parser.add_argument("--feedback-port", type=int, default=5000, help="Port for feedback server (default: 5000)")

    # Advanced ML Configuration
    parser.add_argument("--ml-confidence", type=float, help="Set ML model confidence threshold (0.0-1.0)")

    parser.add_argument("--ml-models-path", help="Path to custom ML models directory")

    # Progressive Analysis
    parser.add_argument(
        "--progressive-analysis", action="store_true", help="Enable progressive analysis for large APKs"
    )

    parser.add_argument(
        "--sample-rate", type=float, default=0.3, help="Sample rate for progressive analysis (0.1-1.0, default: 0.3)"
    )

    # Quality Assurance and Monitoring
    parser.add_argument("--qa-mode", action="store_true", help="Enable quality assurance and accuracy benchmarking")

    parser.add_argument("--enable-metrics", action="store_true", help="Enable Prometheus metrics collection")

    parser.add_argument("--metrics-port", type=int, default=9090, help="Port for metrics endpoint (default: 9090)")

    # Security Profiles
    parser.add_argument(
        "--security-profile",
        choices=["basic", "enhanced", "enterprise"],
        default="basic",
        help="Security profile for analysis (default: basic)",
    )

    # Deduplication Configuration Arguments
    dedup_group = parser.add_argument_group("Vulnerability Deduplication")

    dedup_group.add_argument(
        "--dedup-strategy",
        choices=["basic", "intelligent", "aggressive", "conservative"],
        default="aggressive",
        help="Deduplication strategy for vulnerability reporting (default: aggressive)",
    )

    dedup_group.add_argument(
        "--dedup-threshold",
        type=float,
        default=0.85,
        help="Similarity threshold for deduplication (0.0-1.0, default: 0.85)",
    )

    dedup_group.add_argument(
        "--preserve-evidence",
        action="store_true",
        default=True,
        help="Preserve evidence from merged duplicate vulnerabilities (default: enabled)",
    )

    dedup_group.add_argument(
        "--disable-deduplication",
        action="store_true",
        help="Disable vulnerability deduplication entirely (NOT RECOMMENDED for production)",
    )

    # Agent Intelligence System (Track 90) - optional AI-powered analysis
    agent_group = parser.add_argument_group("Agent Intelligence (optional)")
    agent_group.add_argument(
        "--agent",
        action="store_true",
        help="Enable AI agent analysis after scan completion (requires AODS_AGENT_ENABLED=1)",
    )
    agent_group.add_argument(
        "--agent-narrate",
        action="store_true",
        help="Run narration agent to summarize findings in natural language",
    )
    agent_group.add_argument(
        "--agent-verify",
        action="store_true",
        help="Run verification agent to confirm findings against source code",
    )
    agent_group.add_argument(
        "--agent-orchestrate",
        action="store_true",
        help="Run orchestration agent to select optimal plugins for this APK",
    )
    agent_group.add_argument(
        "--agent-triage",
        action="store_true",
        help="Run triage agent to classify findings as TP/FP and prioritize by exploitability",
    )
    agent_group.add_argument(
        "--agent-remediate",
        action="store_true",
        help="Run remediation agent to generate code patches for vulnerability findings",
    )
    agent_group.add_argument(
        "--agent-pipeline",
        action="store_true",
        help="Run agent pipeline (triage -> verify -> remediate -> narrate) sequentially",
    )
    agent_group.add_argument(
        "--agent-model",
        type=str,
        default=None,
        help="Override Claude model for agent tasks (e.g., claude-sonnet-4-6)",
    )

    return parser
