"""
IOSPluginManager – discovers, selects, and executes IODS plugins.

Plugin discovery: scans plugins/ directory for v2_plugin.py files.
Profile-based selection:
  lightning : 8 plugins  (fast CI checks)
  fast      : 12 plugins
  standard  : 16 plugins (default)
  deep      : 20 plugins (all)
"""
from __future__ import annotations

import importlib.util
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeout
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Type

from core.logging_config import get_logger
from core.plugins.base_plugin_ios import (
    BasePluginIOS,
    PluginCapability,
    PluginPriority,
    PluginResult,
    PluginStatus,
)

logger = get_logger(__name__)

# Profile → included plugin names (in priority order)
PROFILE_PLUGINS: Dict[str, List[str]] = {
    "lightning": [
        "binary_security_analyzer",
        "ats_analyzer",
        "hardcoded_secrets_analyzer",
        "entitlements_analyzer",
        "code_signing_analyzer",
        "cryptography_analyzer",
        "network_security_analyzer",
        "logging_analyzer",
    ],
    "fast": [
        "binary_security_analyzer",
        "ats_analyzer",
        "hardcoded_secrets_analyzer",
        "entitlements_analyzer",
        "code_signing_analyzer",
        "cryptography_analyzer",
        "network_security_analyzer",
        "logging_analyzer",
        "keychain_analyzer",
        "data_storage_analyzer",
        "webview_analyzer",
        "privacy_analyzer",
    ],
    "standard": [
        "binary_security_analyzer",
        "ats_analyzer",
        "hardcoded_secrets_analyzer",
        "entitlements_analyzer",
        "code_signing_analyzer",
        "cryptography_analyzer",
        "network_security_analyzer",
        "logging_analyzer",
        "keychain_analyzer",
        "data_storage_analyzer",
        "webview_analyzer",
        "privacy_analyzer",
        "url_scheme_analyzer",
        "clipboard_analyzer",
        "cert_pinning_analyzer",
        "swift_objc_patterns_analyzer",
    ],
    "deep": [
        "binary_security_analyzer",
        "ats_analyzer",
        "hardcoded_secrets_analyzer",
        "entitlements_analyzer",
        "code_signing_analyzer",
        "cryptography_analyzer",
        "network_security_analyzer",
        "logging_analyzer",
        "keychain_analyzer",
        "data_storage_analyzer",
        "webview_analyzer",
        "privacy_analyzer",
        "url_scheme_analyzer",
        "clipboard_analyzer",
        "cert_pinning_analyzer",
        "swift_objc_patterns_analyzer",
        "jailbreak_detection_analyzer",
        "anti_debugging_analyzer",
        "third_party_library_analyzer",
        "dynamic_analysis_modules",
    ],
}

DYNAMIC_PLUGINS = {"dynamic_analysis_modules"}


class IOSPluginManager:
    """Discovers, loads, and executes iOS security analysis plugins."""

    def __init__(self, plugins_dir: str = "plugins", profile: str = "standard") -> None:
        self.plugins_dir = Path(plugins_dir)
        self.profile = profile
        self._registry: Dict[str, Type[BasePluginIOS]] = {}
        self._loaded = False

    def discover_plugins(self) -> None:
        """Scan plugins/ directory for v2_plugin.py files and register them."""
        if _not_exists := not self.plugins_dir.exists():
            logger.warning("Plugins directory not found", path=str(self.plugins_dir))
            return

        for plugin_dir in sorted(self.plugins_dir.iterdir()):
            if not plugin_dir.is_dir():
                continue
            v2_file = plugin_dir / "v2_plugin.py"
            if not v2_file.exists():
                continue
            plugin_name = plugin_dir.name
            try:
                cls = self._load_plugin_class(plugin_name, v2_file)
                if cls is not None:
                    self._registry[plugin_name] = cls
                    logger.debug("Registered plugin", name=plugin_name)
            except Exception as e:
                logger.warning("Failed to load plugin", name=plugin_name, error=str(e))

        self._loaded = True
        logger.info("Plugin discovery complete", count=len(self._registry), profile=self.profile)

    def _load_plugin_class(self, name: str, path: Path) -> Optional[Type[BasePluginIOS]]:
        """Dynamically load the plugin class from v2_plugin.py."""
        spec = importlib.util.spec_from_file_location(f"plugins.{name}.v2_plugin", path)
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        # Ensure plugins root is on path for relative imports
        plugins_root = str(self.plugins_dir.parent)
        if plugins_root not in sys.path:
            sys.path.insert(0, plugins_root)
        spec.loader.exec_module(module)

        # Find the BasePluginIOS subclass in the module
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            try:
                if (
                    isinstance(attr, type)
                    and issubclass(attr, BasePluginIOS)
                    and attr is not BasePluginIOS
                ):
                    return attr
            except TypeError:
                continue
        return None

    def get_selected_plugins(self, static_only: bool = False, dynamic_only: bool = False) -> List[str]:
        """Return plugin names for the current profile, filtered by mode."""
        selected = PROFILE_PLUGINS.get(self.profile, PROFILE_PLUGINS["standard"])
        if static_only:
            selected = [p for p in selected if p not in DYNAMIC_PLUGINS]
        elif dynamic_only:
            selected = [p for p in selected if p in DYNAMIC_PLUGINS]
        return selected

    def run_static_plugins(self, ipa_ctx, max_workers: int = 4) -> List[Dict[str, Any]]:
        """Run all static analysis plugins in parallel. Returns list of result dicts."""
        if not self._loaded:
            self.discover_plugins()
        selected = self.get_selected_plugins(static_only=True)
        return self._execute_plugins(selected, ipa_ctx, parallel=True, max_workers=max_workers)

    def run_dynamic_plugins(self, ipa_ctx) -> List[Dict[str, Any]]:
        """Run dynamic plugins sequentially (device state changes)."""
        if not self._loaded:
            self.discover_plugins()
        selected = self.get_selected_plugins(dynamic_only=True)
        return self._execute_plugins(selected, ipa_ctx, parallel=False)

    def _execute_plugins(
        self,
        plugin_names: List[str],
        ipa_ctx,
        parallel: bool = True,
        max_workers: int = 4,
    ) -> List[Dict[str, Any]]:
        results = []
        plugins_to_run: List[Tuple[str, BasePluginIOS]] = []

        for name in plugin_names:
            cls = self._registry.get(name)
            if cls is None:
                logger.debug("Plugin not registered, skipping", name=name)
                continue
            try:
                instance = cls()
                can_run, reason = instance.can_execute(ipa_ctx)
                if not can_run:
                    logger.info("Plugin skipped", name=name, reason=reason)
                    continue
                plugins_to_run.append((name, instance))
            except Exception as e:
                logger.warning("Plugin instantiation failed", name=name, error=str(e))

        if parallel and len(plugins_to_run) > 1:
            results = self._run_parallel(plugins_to_run, ipa_ctx, max_workers)
        else:
            results = self._run_sequential(plugins_to_run, ipa_ctx)

        return results

    def _run_parallel(
        self, plugins: List[Tuple[str, BasePluginIOS]], ipa_ctx, max_workers: int
    ) -> List[Dict[str, Any]]:
        results = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self._run_single, name, plugin, ipa_ctx): name
                for name, plugin in plugins
            }
            for future in as_completed(futures):
                name = futures[future]
                try:
                    result = future.result(timeout=300)
                    results.append(result)
                except FuturesTimeout:
                    logger.warning("Plugin timed out", name=name)
                    results.append({"plugin": name, "status": "timeout", "findings": []})
                except Exception as e:
                    logger.warning("Plugin execution error", name=name, error=str(e))
                    results.append({"plugin": name, "status": "error", "findings": []})
        return results

    def _run_sequential(
        self, plugins: List[Tuple[str, BasePluginIOS]], ipa_ctx
    ) -> List[Dict[str, Any]]:
        results = []
        for name, plugin in plugins:
            results.append(self._run_single(name, plugin, ipa_ctx))
        return results

    def _run_single(self, name: str, plugin: BasePluginIOS, ipa_ctx) -> Dict[str, Any]:
        start = time.time()
        try:
            plugin.setup(ipa_ctx)
            result: PluginResult = plugin.execute(ipa_ctx)
            plugin.cleanup(ipa_ctx)
            elapsed = time.time() - start
            logger.info(
                "Plugin complete",
                name=name,
                status=result.status.value,
                findings=len(result.findings),
                elapsed=f"{elapsed:.2f}s",
            )
            return {
                "plugin": name,
                "status": result.status.value,
                "execution_time": elapsed,
                "findings": [self._finding_to_dict(f) for f in result.findings],
                "warnings": result.warning_messages,
                "metadata": result.metadata,
            }
        except Exception as e:
            elapsed = time.time() - start
            logger.error("Plugin raised exception", name=name, error=str(e))
            return {
                "plugin": name,
                "status": "error",
                "execution_time": elapsed,
                "findings": [],
                "error": str(e),
            }

    @staticmethod
    def _finding_to_dict(finding) -> Dict[str, Any]:
        return {
            "finding_id": finding.finding_id,
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "file_path": finding.file_path,
            "line_number": finding.line_number,
            "code_snippet": finding.code_snippet,
            "vulnerability_type": finding.vulnerability_type,
            "cwe_id": finding.cwe_id,
            "owasp_category": finding.owasp_category,
            "masvs_control": finding.masvs_control,
            "evidence": finding.evidence,
            "remediation": finding.remediation,
            "references": finding.references,
        }
