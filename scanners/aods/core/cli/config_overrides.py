"""
core.cli.config_overrides - Pattern config overrides and vulnerable app filter (Track 46).

Pure functions with no dyna.py state dependencies.
"""

from pathlib import Path

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)


def apply_pattern_configuration_overrides(args):
    """Apply command-line overrides to vulnerability pattern configuration.

    IMPORTANT: Overrides are written to a runtime config file in artifacts/,
    NOT to the repo config file. This prevents git pollution and ensures
    deterministic behavior across runs.
    """
    import yaml
    import os

    config_path = "config/vulnerability_patterns.yaml"
    if not os.path.exists(config_path):
        logger.warning("Configuration file not found", config_path=config_path)
        return

    try:
        # Read current configuration (base config from repo)
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)

        # Apply Android 14 pattern overrides
        if "android_14_pattern_control" not in config:
            config["android_14_pattern_control"] = {}

        if args.disable_android14_webview_patterns:
            config["android_14_pattern_control"]["enable_webview_hardening_patterns"] = False
            logger.info("Disabled Android 14 WebView security patterns")

        if args.disable_android14_network_patterns:
            config["android_14_pattern_control"]["enable_network_hardening_patterns"] = False
            logger.info("Disabled Android 14 network security patterns")

        if args.enable_android14_audit_patterns:
            config["android_14_pattern_control"]["enable_data_auditing_patterns"] = True
            logger.info("Enabled Android 14 data access auditing patterns")

        # Crypto pattern toggles (parity with CLI)
        if getattr(args, "enable_crypto_rng_patterns", False):
            config["android_14_pattern_control"]["enable_crypto_rng_patterns"] = True
            logger.info("Enabled crypto RNG patterns")
        if getattr(args, "enable_crypto_policy_patterns", False):
            config["android_14_pattern_control"]["enable_crypto_policy_patterns"] = True
            logger.info("Enabled crypto policy patterns")

        # GDPR policy patterns toggle
        if getattr(args, "enable_gdpr_policy_patterns", False):
            config["android_14_pattern_control"]["enable_gdpr_policy_patterns"] = True
            logger.info("Enabled GDPR/data policy patterns")

        # HTTP mode handling (env overrides CLI; CLI overrides YAML)
        http_mode = os.environ.get("AODS_HTTP_MODE") or getattr(args, "http_mode", None)
        if http_mode:
            if http_mode == "strict":
                config["android_14_pattern_control"]["enable_http_strict"] = True
                config["android_14_pattern_control"]["enable_http_rfc1918_allowed"] = False
                logger.info("HTTP mode set", mode="strict")
            elif http_mode == "internal":
                config["android_14_pattern_control"]["enable_http_strict"] = False
                config["android_14_pattern_control"]["enable_http_rfc1918_allowed"] = True
                logger.info("HTTP mode set", mode="internal", detail="RFC1918 allowlist")
            elif http_mode == "auto":
                is_internal = os.environ.get("AODS_BUILD_VARIANT", "").lower() in ("internal", "dev", "debug")
                if is_internal:
                    config["android_14_pattern_control"]["enable_http_strict"] = False
                    config["android_14_pattern_control"]["enable_http_rfc1918_allowed"] = True
                    logger.info("HTTP mode auto-resolved", resolved_mode="internal")
                else:
                    config["android_14_pattern_control"]["enable_http_strict"] = True
                    config["android_14_pattern_control"]["enable_http_rfc1918_allowed"] = False
                    logger.info("HTTP mode auto-resolved", resolved_mode="strict")

        # Work/Job constraints toggle
        if os.environ.get("AODS_ENABLE_JOB_CONSTRAINTS") == "1" or getattr(
            args, "enable_job_constraints_patterns", False
        ):
            config["android_14_pattern_control"]["enable_job_constraints_patterns"] = True
            logger.info("Enabled job/work constraints patterns")

        # Apply ML filtering overrides
        if "ml_filtering_control" not in config:
            config["ml_filtering_control"] = {}

        if args.force_ml_filtering:
            config["ml_filtering_control"]["force_ml_filtering_for_vulnerable_apps"] = True
            logger.info("Enabled ML filtering for vulnerable apps")

        # App profile selection (affects YAML defaults used by ML pipeline)
        if getattr(args, "app_profile", None):
            os.environ["AODS_APP_PROFILE"] = args.app_profile
            logger.info("App profile set", profile=args.app_profile)

        # Direct ML FP threshold override (env wins over YAML)
        if getattr(args, "ml_fp_threshold", None) is not None:
            profile = os.environ.get("AODS_APP_PROFILE", "production")
            try:
                thr_val = float(args.ml_fp_threshold)
                if profile in ("vulnerable", "qa_vulnerable"):
                    config["ml_filtering_control"]["vulnerable_app_ml_filtering_threshold"] = thr_val
                else:
                    config["ml_filtering_control"]["production_app_ml_filtering_threshold"] = thr_val
                os.environ["AODS_ML_FP_THRESHOLD"] = str(thr_val)
                logger.info("ML FP threshold set", threshold=thr_val, profile=profile, note="env overrides YAML")
            except Exception:
                logger.warning("Invalid value for --ml-fp-threshold; expected a float between 0 and 1")

        # Write runtime overrides to artifacts/ (NOT to repo config)
        # This prevents git pollution and ensures deterministic behavior
        runtime_config_dir = Path("artifacts/runtime_config")
        runtime_config_dir.mkdir(parents=True, exist_ok=True)
        runtime_config_path = runtime_config_dir / "vulnerability_patterns_runtime.yaml"

        with open(runtime_config_path, "w") as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)

        # Set env var so consumers (static_analyzer, etc.) pick up the runtime config
        # Consumers check AODS_VULN_PATTERNS_CONFIG first, then fall back to repo config
        os.environ["AODS_VULN_PATTERNS_CONFIG"] = str(runtime_config_path)

        logger.info("Runtime configuration saved", path=str(runtime_config_path))

    except Exception as e:
        logger.warning("Failed to apply configuration overrides", error=str(e))


def apply_vulnerable_app_filtering_if_needed(results, args):
    """Apply vulnerable app filtering to reduce false positives if needed"""
    try:
        if not args.vulnerable_app_mode:
            return results

        from core.vulnerable_app_coordinator import VulnerableAppCoordinator

        coordinator = VulnerableAppCoordinator()

        # Create app context
        app_context = {
            "package_name": getattr(args, "pkg", ""),
            "apk_path": getattr(args, "apk", ""),
            "force_vulnerable": args.vulnerable_app_mode,
        }

        # Apply filtering to findings
        if "findings" in results:
            original_count = len(results["findings"])
            results["findings"] = coordinator.apply_vulnerable_app_filtering(results["findings"], app_context)
            filtered_count = len(results["findings"])

            reduction_pct = (original_count - filtered_count) / original_count * 100 if original_count > 0 else 0.0
            logger.info(
                "Vulnerable app filtering applied",
                original_count=original_count,
                filtered_count=filtered_count,
                reduction_pct=round(reduction_pct, 1),
            )

            # Update counts
            results["findings_count"] = filtered_count

    except Exception as e:
        logger.warning("Vulnerable app filtering failed", error=str(e))

    return results
