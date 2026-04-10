#!/usr/bin/env python3
"""
AODS Package Name Detection - User Interaction Module
=====================================================

Provides user interaction functions for package name detection including
confirmation prompts, manual entry, and intelligent user experience flows.

Features:
- Interactive confirmation of auto-detected package names
- Manual package name entry with validation
- User-friendly feedback and error messages
- Support for batch processing and CI/CD modes
"""

import sys
from typing import Tuple
from core.utils.package_name_extractor import PackageExtractionResult

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)


def resolve_package_name(args, apk_path: str) -> Tuple[str, bool, float]:
    """
    Resolve package name with auto-detection and user interaction.

    This is the main function that coordinates package name resolution
    including auto-detection, user confirmation, and fallback mechanisms.

    Args:
        args: Parsed command line arguments
        apk_path: Path to APK file

    Returns:
        Tuple of (package_name, was_auto_detected, confidence)
    """
    from core.utils.package_name_extractor import PackageNameExtractor

    # If package name explicitly provided, use it
    if getattr(args, "pkg", None):
        logger.debug("Using explicitly provided package name")
        return args.pkg, False, 1.0

    # If auto-detection disabled, require manual input
    if not getattr(args, "auto_pkg", True):
        logger.debug("Auto-detection disabled, prompting for manual entry")
        return prompt_for_package_name(), False, 1.0

    # Auto-detect package name
    logger.debug(f"Starting auto-detection for APK: {apk_path}")
    extractor = PackageNameExtractor()
    result = extractor.extract_package_name(apk_path)

    if result.success:
        # Check if confirmation needed based on various criteria
        confidence_threshold = getattr(args, "pkg_confidence_threshold", 0.8)
        needs_confirmation = _should_confirm_package(args, result, confidence_threshold)

        if needs_confirmation:
            logger.debug("Package detection requires user confirmation")
            confirmed = confirm_package_name(result)
            if confirmed:
                return result.package_name, True, result.confidence
            else:
                logger.debug("User rejected auto-detected package, prompting for manual entry")
                return prompt_for_package_name(), False, 1.0
        else:
            # High confidence, use automatically
            logger.info(
                "Auto-detected package",
                package_name=result.package_name,
                method=result.method,
                confidence=f"{result.confidence:.0%}",
            )
            return result.package_name, True, result.confidence
    else:
        # Auto-detection failed
        logger.warning("Could not auto-detect package name", error=result.error)

        # In CI mode, this might be a fatal error
        if getattr(args, "ci_mode", False):
            logger.error(
                "CI mode: Package auto-detection failed, cannot proceed. Please provide package name explicitly with --pkg"  # noqa: E501
            )
            sys.exit(1)

        logger.info("Please provide package name manually")
        return prompt_for_package_name(), False, 1.0


def _should_confirm_package(args, result: PackageExtractionResult, confidence_threshold: float) -> bool:
    """
    Determine if user confirmation is needed for auto-detected package.

    Args:
        args: Command line arguments
        result: Package extraction result
        confidence_threshold: Minimum confidence for auto-acceptance

    Returns:
        True if confirmation is needed
    """
    # Always confirm if explicitly requested
    if getattr(args, "confirm_pkg", False):
        return True

    # Confirm if confidence is below threshold
    if result.confidence < confidence_threshold:
        return True

    # Confirm for low-reliability methods
    if result.method in ["filename_generation", "filename_guessing"]:
        return True

    # Don't confirm in CI/batch mode for high confidence results
    if getattr(args, "ci_mode", False) or getattr(args, "batch_targets", None):
        return False

    return False


def confirm_package_name(result: PackageExtractionResult) -> bool:
    """
    Interactive confirmation of auto-detected package name.

    Displays information about the detected package and
    asks the user for confirmation.

    Args:
        result: Package extraction result

    Returns:
        True if user confirms the package name
    """
    # Check for non-interactive mode
    import os

    if os.getenv("AODS_NON_INTERACTIVE", "0") == "1" or os.getenv("CI", "0") == "1":
        logger.info(
            "Auto-detected package information (Non-Interactive Mode)",
            package_name=result.package_name,
            app_name=result.app_name,
            method=result.method,
            confidence=f"{result.confidence:.1%}",
        )
        logger.info("Auto-accepting package in non-interactive mode")
        return True

    logger.info(
        "Auto-detected package information",
        package_name=result.package_name,
        app_name=result.app_name,
        version_name=result.version_name,
        version_code=result.version_code,
        target_sdk=result.target_sdk,
        method=result.method,
        confidence=f"{result.confidence:.1%}",
    )

    # Add context based on confidence level
    if result.confidence < 0.5:
        logger.warning("Low confidence detection - please verify carefully")
    elif result.confidence < 0.8:
        logger.warning("Medium confidence detection - please verify")

    # Add method-specific context
    if result.method == "filename_generation":
        logger.info("Generated from filename - may not be accurate")
    elif result.method == "filename_pattern_match":
        logger.info("Matched known app pattern - likely accurate")

    # Get user input with retry logic
    max_attempts = 3
    for attempt in range(max_attempts):
        try:
            response = input(f"Use package '{result.package_name}'? [Y/n]: ").strip().lower()

            if response in ["", "y", "yes"]:
                return True
            elif response in ["n", "no"]:
                return False
            else:
                logger.info("Please enter 'y' for yes or 'n' for no")
                continue

        except (KeyboardInterrupt, EOFError):
            logger.warning("Cancelled by user")
            return False

    # After max attempts, default to no
    logger.error("Too many invalid responses, defaulting to manual entry")
    return False


def prompt_for_package_name() -> str:
    """
    Prompt user to manually enter package name with validation.

    Provides helpful examples and validates the input format before
    accepting the package name.

    Returns:
        Valid package name entered by user
    """
    # Check for non-interactive mode
    import os

    if os.getenv("AODS_NON_INTERACTIVE", "0") == "1" or os.getenv("CI", "0") == "1":
        logger.error(
            "Manual package name entry required but non-interactive mode is enabled. Please provide package name via --pkg argument."  # noqa: E501
        )
        raise RuntimeError("Package name required but non-interactive mode is enabled. Use --pkg argument.")

    logger.info(
        "Manual package name entry required. Examples: com.example.app, com.company.appname, jakhar.aseem.diva. Package name must use dot notation."  # noqa: E501
    )

    max_attempts = 5
    for attempt in range(max_attempts):
        try:
            pkg = input("Enter package name: ").strip()

            if not pkg:
                logger.warning("Package name cannot be empty")
                continue

            # Validate package name format
            if _validate_manual_package_name(pkg):
                logger.info("Using package name", package_name=pkg)
                return pkg
            else:
                logger.warning(
                    "Please enter a valid package name with dot notation. Format: com.company.app (at least 2 parts separated by dots)"  # noqa: E501
                )
                continue

        except (KeyboardInterrupt, EOFError):
            logger.warning("Cancelled by user")
            sys.exit(1)

    # After max attempts, exit with error
    logger.error("Too many invalid attempts. Cannot proceed without valid package name.")
    sys.exit(1)


def _validate_manual_package_name(package_name: str) -> bool:
    """
    Validate manually entered package name format.

    Args:
        package_name: Package name to validate

    Returns:
        True if valid package name format
    """
    if not package_name or not isinstance(package_name, str):
        return False

    # Must contain at least one dot
    if "." not in package_name:
        return False

    # Split into parts and validate each
    parts = package_name.split(".")
    if len(parts) < 2:
        return False

    # Each part should be a valid identifier
    import re

    for part in parts:
        if not part:  # Empty part
            return False
        # Must start with letter, can contain letters, digits, underscores
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9_]*$", part):
            return False

    # Additional validation: reasonable length
    if len(package_name) > 100:
        return False

    return True


def show_package_detection_status(args) -> None:
    """
    Display current package detection configuration status.

    Args:
        args: Parsed command line arguments
    """
    from core.utils.package_name_extractor import check_aapt_availability

    # Show auto-detection status
    if getattr(args, "auto_pkg", True):
        aapt_available = check_aapt_availability()
        threshold = getattr(args, "pkg_confidence_threshold", 0.8)
        confirm_mode = "always_ask" if getattr(args, "confirm_pkg", False) else "auto_confirm_high_confidence"

        logger.info(
            "Package detection configuration",
            auto_detection="enabled",
            aapt_available=aapt_available,
            confidence_threshold=f"{threshold:.0%}",
            confirmation_mode=confirm_mode,
        )
    else:
        logger.info("Package detection configuration", auto_detection="disabled (manual entry required)")

    # Show CI mode status
    if getattr(args, "ci_mode", False):
        logger.info("CI/CD mode enabled (no interactive prompts)")


def handle_batch_package_detection(targets: list, args) -> list:
    """
    Handle package detection for batch processing.

    Args:
        targets: List of target configurations
        args: Command line arguments

    Returns:
        List of targets with package names resolved
    """
    from core.utils.package_name_extractor import PackageNameExtractor

    logger.info(f"Processing package detection for {len(targets)} targets")

    extractor = PackageNameExtractor()
    updated_targets = []

    for i, target in enumerate(targets):
        target_path = target.get("path") or target.get("target_path", "")

        # Only process APK files
        if not target_path.lower().endswith(".apk"):
            updated_targets.append(target)
            continue

        logger.info("Processing batch target", target_index=i + 1, total_targets=len(targets), target_path=target_path)

        # Check if package name already provided
        if target.get("package_name"):
            logger.info("Package name already provided", package_name=target["package_name"])
            updated_targets.append(target)
            continue

        # Auto-detect package name
        result = extractor.extract_package_name(target_path)

        if result.success:
            # For batch processing, use higher confidence threshold
            confidence_threshold = 0.9 if getattr(args, "ci_mode", False) else 0.8

            if result.confidence >= confidence_threshold:
                logger.info(
                    "Package auto-detected", package_name=result.package_name, confidence=f"{result.confidence:.0%}"
                )
                target["package_name"] = result.package_name
                target["auto_detected"] = True
                target["detection_confidence"] = result.confidence
            else:
                logger.info(
                    "Package detected with low confidence",
                    package_name=result.package_name,
                    confidence=f"{result.confidence:.0%}",
                )

                # In CI mode, use anyway with warning
                if getattr(args, "ci_mode", False):
                    logger.warning("CI mode: Using low confidence detection")
                    target["package_name"] = result.package_name
                    target["auto_detected"] = True
                    target["detection_confidence"] = result.confidence
                else:
                    # Interactive mode: ask for confirmation
                    if confirm_package_name(result):
                        target["package_name"] = result.package_name
                        target["auto_detected"] = True
                        target["detection_confidence"] = result.confidence
                    else:
                        # Skip this target or use manual entry
                        logger.warning("Skipping target due to rejected package detection")
                        continue
        else:
            logger.error("Auto-detection failed", error=result.error)

            # In CI mode, this might be fatal
            if getattr(args, "ci_mode", False):
                logger.info("CI mode: Skipping target")
                continue
            else:
                # Interactive mode: could prompt for manual entry
                logger.info("Manual entry would be required")
                continue

        updated_targets.append(target)

    return updated_targets
