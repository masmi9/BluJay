#!/usr/bin/env python3
"""
Unified Plugin Executor

Consolidates all plugin execution logic from different execution systems.
Eliminates duplication while providing consistent plugin execution behavior.
"""

import logging
import sys
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union

from rich.text import Text

# Migrated to canonical timeout system (Phase 7)
from core.timeout import (
    UnifiedTimeoutManager as TimeoutManager,
    TimeoutType,
    get_optimized_timeout_for_plugin,  # CONSOLIDATED: No more deferred imports
)

# Import plugin-specific timeout registry for optimized performance (2025-08-27)

logger = logging.getLogger(__name__)

# CONSOLIDATED: Deferred imports eliminated - using unified timeout system


def execute_static_scan(apk_path: str, package_name: str, mode: str, vulnerable_app_mode: bool, timeout: int = 1800):
    """Standalone static analysis execution function for process separation."""
    try:
        logger.info(f"🔍 Executing static analysis for {package_name}")

        # Import APK context and create minimal setup for plugin execution
        from core.apk_ctx import APKContext
        from core.plugins import create_plugin_manager

        # Create APK context for analysis
        apk_ctx = APKContext(apk_path_str=apk_path, package_name=package_name)
        apk_ctx.set_scan_mode(mode)
        apk_ctx.vulnerable_app_mode = vulnerable_app_mode

        # Create plugin manager with scan optimization
        plugin_manager = create_plugin_manager(
            scan_mode=mode,
            vulnerable_app_mode=vulnerable_app_mode,
            apk_path=apk_path,  # ENHANCED: Pass APK path for intelligent timeout calculation
        )

        logger.info(f"🔧 Running {len(plugin_manager.plugins)} static analysis plugins")

        # Execute all plugins
        plugin_results = plugin_manager.execute_all_plugins(apk_ctx)

        # Convert plugin results to structured format
        static_results = {
            "scan_type": "static",
            "package_name": package_name,
            "apk_path": apk_path,
            "plugin_results": plugin_results,
            "external_vulnerabilities": [],
            "vulnerabilities": [],
            "metadata": {
                "scan_duration": timeout,
                "analysis_type": "static",
                "plugins_executed": len(plugin_results),
                "findings_count": len(plugin_results),
            },
        }

        # Extract vulnerabilities from plugin results
        for plugin_name, (title, content) in plugin_results.items():
            # Create vulnerability entry for each plugin result
            vuln_entry = {
                "title": title,
                "description": str(content),
                "severity": "MEDIUM",  # Default severity
                "category": "STATIC_ANALYSIS",
                "plugin": plugin_name,
                "source": "static_scan",
            }
            static_results["external_vulnerabilities"].append(vuln_entry)

        logger.info(f"✅ Static analysis completed: {len(plugin_results)} plugins executed")
        return ("static_scan_completed", static_results)

    except Exception as e:
        logger.error(f"❌ Static analysis failed: {e}")
        return ("static_scan_failed", {"error": str(e)})


def execute_dynamic_scan(apk_path: str, package_name: str, mode: str, vulnerable_app_mode: bool, timeout: int = 1800):
    """Standalone dynamic analysis execution function for process separation."""
    try:
        logger.info(f"🔧 Executing dynamic analysis for {package_name}")

        # Import APK context and create minimal setup for plugin execution
        from core.apk_ctx import APKContext
        from core.plugins import create_plugin_manager

        # Create APK context for analysis
        apk_ctx = APKContext(apk_path_str=apk_path, package_name=package_name)
        apk_ctx.set_scan_mode(mode)
        apk_ctx.vulnerable_app_mode = vulnerable_app_mode

        # Create plugin manager with scan optimization
        plugin_manager = create_plugin_manager(
            scan_mode=mode,
            vulnerable_app_mode=vulnerable_app_mode,
            apk_path=apk_path,  # ENHANCED: Pass APK path for intelligent timeout calculation
        )

        logger.info(f"🔧 Running {len(plugin_manager.plugins)} dynamic analysis plugins")

        # Execute all plugins
        plugin_results = plugin_manager.execute_all_plugins(apk_ctx)

        # Convert plugin results to structured format
        dynamic_results = {
            "scan_type": "dynamic",
            "package_name": package_name,
            "apk_path": apk_path,
            "plugin_results": plugin_results,
            "external_vulnerabilities": [],
            "vulnerabilities": [],
            "metadata": {
                "scan_duration": timeout,
                "analysis_type": "dynamic",
                "plugins_executed": len(plugin_results),
                "findings_count": len(plugin_results),
            },
        }

        # ENHANCED: Extract structured vulnerabilities using new extractor
        try:
            from core.dynamic_vulnerability_extractor import DynamicVulnerabilityExtractor

            vulnerability_extractor = DynamicVulnerabilityExtractor()

            # Create structured scan results for the extractor
            structured_results = {
                "results": {
                    plugin_name: {"title": title, "result": content}
                    for plugin_name, (title, content) in plugin_results.items()
                }
            }

            # Extract structured vulnerabilities
            structured_vulnerabilities = vulnerability_extractor.extract_vulnerabilities_from_scan_results(
                structured_results, apk_ctx
            )

            logger.info(
                f"🔍 Extracted {len(structured_vulnerabilities)} structured vulnerabilities from dynamic analysis"
            )

            # Convert BaseVulnerability objects to dictionaries for JSON serialization
            for vuln in structured_vulnerabilities:
                vuln_dict = vuln.to_dict()
                dynamic_results["vulnerabilities"].append(vuln_dict)

            # Update metadata with structured vulnerability count
            dynamic_results["metadata"]["structured_vulnerabilities"] = len(structured_vulnerabilities)
            dynamic_results["metadata"]["findings_count"] = len(structured_vulnerabilities)

        except Exception as e:
            logger.warning(f"⚠️ Structured vulnerability extraction failed: {e}")
            logger.info("📄 Falling back to basic vulnerability extraction")

            # Fallback: Basic vulnerability extraction (original method)
            for plugin_name, (title, content) in plugin_results.items():
                # Create vulnerability entry for each plugin result
                vuln_entry = {
                    "title": title,
                    "description": str(content),
                    "severity": "HIGH",  # Dynamic analysis typically higher severity
                    "category": "DYNAMIC_ANALYSIS",
                    "plugin": plugin_name,
                    "source": "dynamic_scan",
                }
                dynamic_results["external_vulnerabilities"].append(vuln_entry)

        logger.info(f"✅ Dynamic analysis completed: {len(plugin_results)} plugins executed")
        return ("dynamic_scan_completed", dynamic_results)

    except Exception as e:
        logger.error(f"❌ Dynamic analysis failed: {e}")
        return ("dynamic_scan_failed", {"error": str(e)})


class PluginStatus(Enum):
    """Unified plugin status enumeration."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


@dataclass
class PluginExecutionResult:
    """
    Unified plugin execution result structure.

    Consolidates result formats from different execution systems.
    """

    plugin_name: str
    status: PluginStatus
    result: Optional[Tuple[str, Union[str, Text]]] = None
    error: Optional[str] = None
    execution_time: float = 0.0
    timeout_used: int = 0
    memory_used_mb: float = 0.0

    @property
    def success(self) -> bool:
        """Check if plugin execution was successful."""
        return self.status == PluginStatus.SUCCESS

    @property
    def failed(self) -> bool:
        """Check if plugin execution failed."""
        return self.status in [PluginStatus.FAILED, PluginStatus.TIMEOUT, PluginStatus.CANCELLED]


class PluginExecutor:
    """
    Unified plugin executor eliminating execution logic duplication.

    Consolidates plugin execution from:
    - ParallelAnalysisEngine._execute_plugin_safe()
    - RobustPluginExecutionManager._execute_plugin_robust()
    - UnifiedPluginExecutionManager._execute_plugin()
    - Individual plugin ThreadPoolExecutor implementations
    """

    def __init__(self, timeout_manager: Optional[TimeoutManager] = None):
        """Initialize unified plugin executor."""
        self.timeout_manager = timeout_manager or TimeoutManager()
        self.logger = logging.getLogger(__name__)
        self._current_scan_profile = None  # Current scan profile for timeout optimization

        # Execution statistics
        self._execution_stats = {
            "total_executions": 0,
            "successful_executions": 0,
            "failed_executions": 0,
            "timeout_executions": 0,
            "total_execution_time": 0.0,
        }

        self.logger.info("Unified plugin executor initialized")

    def execute_plugin(
        self, plugin: Any, apk_ctx: Any, timeout_seconds: Optional[int] = None, deep_mode: bool = True
    ) -> PluginExecutionResult:
        """
        Execute a single plugin with unified timeout and error handling.

        Args:
            plugin: Plugin object or function to execute
            apk_ctx: APK context for analysis
            timeout_seconds: Custom timeout override
            deep_mode: Whether to run in deep analysis mode

        Returns:
            PluginExecutionResult with execution details
        """
        plugin_name = self._get_plugin_name(plugin)

        # Determine timeout (using intelligent + profile-aware system - 2025-08-29)
        if timeout_seconds is None:
            # Store APK path for intelligent timeout calculation
            if hasattr(apk_ctx, "apk_path_str"):
                self._current_apk_path = apk_ctx.apk_path_str
            # Try to get scan profile from execution context
            scan_profile = (
                getattr(self, "_current_scan_profile", None) or getattr(apk_ctx, "scan_profile", None)
                if apk_ctx
                else None
            )
            timeout_seconds = self._get_plugin_timeout(plugin_name, scan_profile)

        # Create execution result
        result = PluginExecutionResult(
            plugin_name=plugin_name, status=PluginStatus.PENDING, timeout_used=timeout_seconds
        )

        # Track execution statistics
        self._execution_stats["total_executions"] += 1

        try:
            # Execute with timeout protection
            with self.timeout_manager.timeout_context(
                operation_name=f"plugin_{plugin_name}", timeout_seconds=timeout_seconds, timeout_type=TimeoutType.PLUGIN
            ) as timeout_ctx:

                result.status = PluginStatus.RUNNING
                start_time = time.time()

                # Execute the plugin function
                plugin_result = self._execute_plugin_function(plugin, apk_ctx, deep_mode)

                # Calculate execution time
                result.execution_time = time.time() - start_time

                # Process and validate result
                result.result = self._process_plugin_result(plugin_name, plugin_result)
                result.status = PluginStatus.SUCCESS

                self._execution_stats["successful_executions"] += 1
                self._execution_stats["total_execution_time"] += result.execution_time

                self.logger.debug(f"Plugin '{plugin_name}' executed successfully in {result.execution_time:.2f}s")

        except Exception as e:
            result.execution_time = time.time() - start_time if "start_time" in locals() else 0.0

            # Determine failure type
            if "timeout" in str(e).lower() or "TimeoutError" in str(type(e).__name__):
                result.status = PluginStatus.TIMEOUT
                result.error = f"Plugin execution timed out after {timeout_seconds}s"
                self._execution_stats["timeout_executions"] += 1
                self.logger.warning(f"Plugin '{plugin_name}' timed out after {timeout_seconds}s")
            else:
                result.status = PluginStatus.FAILED
                result.error = str(e)
                self._execution_stats["failed_executions"] += 1
                self.logger.error(f"Plugin '{plugin_name}' failed: {e}")

            # Create error result
            result.result = self._create_error_result(plugin_name, result.error)

        return result

    def _execute_plugin_function(self, plugin: Any, apk_ctx: Any, deep_mode: bool = False) -> Any:
        """
        Execute plugin function with unified handling.

        Supports both traditional plugin objects and ExecutionTask objects.
        """
        # Check if this is an ExecutionTask with a function payload
        if hasattr(plugin, "payload") and isinstance(plugin.payload, dict):
            payload = plugin.payload

            # Handle function_name for process separation (picklable)
            if "function_name" in payload:
                function_name = payload["function_name"]
                args = payload.get("args", ())
                kwargs = payload.get("kwargs", {})

                self.logger.debug(f"Executing ExecutionTask function by name: {function_name}")

                # Call the function by name from the global scan functions
                if function_name == "execute_static_scan":
                    return execute_static_scan(*args, **kwargs)
                elif function_name == "execute_dynamic_scan":
                    return execute_dynamic_scan(*args, **kwargs)
                else:
                    raise ValueError(f"Unknown function name: {function_name}")

            # Handle direct function references (for thread-based execution)
            elif "function" in payload:
                func = payload["function"]
                args = payload.get("args", ())
                kwargs = payload.get("kwargs", {})

                self.logger.debug(f"Executing ExecutionTask function: {func.__name__}")

                # Call the function with extracted arguments
                return func(*args, **kwargs)

        # NEW: Check if this is a PluginMetadata object - extract the module
        if hasattr(plugin, "module") and plugin.module is not None:
            self.logger.debug(f"Extracting module from PluginMetadata for {self._get_plugin_name(plugin)}")
            plugin = plugin.module

        # Handle PluginMetadata-like objects (dataclasses with file_path/module_name but no .module)
        # This is what CanonicalOrchestrator returns from UnifiedPluginManager.plugins.values()
        elif hasattr(plugin, "module_name") and hasattr(plugin, "file_path"):
            plugin_name = getattr(plugin, "name", str(plugin.module_name))
            self.logger.debug(f"Loading PluginMetadata object: {plugin_name}")
            try:
                # Try import by module_name first (preserves package semantics)
                import importlib

                loaded_module = importlib.import_module(plugin.module_name)
                plugin = self._extract_plugin_from_module(loaded_module, plugin_name)
            except ImportError as e:
                self.logger.debug(f"Module import failed for {plugin.module_name}: {e}, trying file path")
                try:
                    plugin = self._load_plugin_from_path(str(plugin.file_path), plugin_name)
                except Exception as e2:
                    self.logger.warning(f"Failed to load plugin {plugin_name}: {e2}")
                    return self._create_error_result(plugin_name, f"Failed to load plugin: {e2}")

        # Traditional plugin execution logic
        # Try different common plugin execution patterns

        plugin_name = self._get_plugin_name(plugin)
        self.logger.debug(f"Attempting to execute plugin {plugin_name}: type={type(plugin)}")

        # Handle dictionary plugins (common in unified plugin managers)
        if isinstance(plugin, dict):
            self.logger.debug(f"Plugin {plugin_name} is a dictionary, resolving to executable instance")

            # AODS unified plugin manager format - load from file_path
            if "file_path" in plugin and plugin["file_path"]:
                file_path = plugin["file_path"]
                self.logger.debug(f"Loading plugin module from file_path: {file_path}")
                try:
                    plugin = self._load_plugin_from_path(file_path, plugin_name)
                    self.logger.debug(f"Successfully loaded plugin {plugin_name} from {file_path}")
                except Exception as e:
                    self.logger.warning(f"Failed to load plugin {plugin_name} from {file_path}: {e}")
                    return self._create_error_result(plugin_name, f"Failed to load plugin from {file_path}: {e}")

            # Try to resolve from other common dictionary plugin formats
            elif "module" in plugin and plugin["module"] is not None:
                self.logger.debug(f"Resolving plugin from module: {plugin['module']}")
                plugin = plugin["module"]
            elif "instance" in plugin and plugin["instance"] is not None:
                self.logger.debug(f"Resolving plugin from instance: {plugin['instance']}")
                plugin = plugin["instance"]
            elif "class" in plugin and plugin["class"] is not None:
                self.logger.debug(f"Resolving plugin from class: {plugin['class']}")
                plugin_class = plugin["class"]
                if hasattr(plugin_class, "__call__") and not hasattr(plugin_class, "execute"):
                    try:
                        plugin = plugin_class()
                    except Exception as e:
                        self.logger.warning(f"Failed to instantiate plugin class {plugin_class}: {e}")
                        plugin = plugin_class
                else:
                    plugin = plugin_class
            elif "function" in plugin and plugin["function"] is not None:
                self.logger.debug(f"Resolving plugin from function: {plugin['function']}")
                plugin = plugin["function"]
            else:
                # Try to find any callable object in the dictionary
                callable_found = False
                for key, value in plugin.items():
                    if callable(value) and key not in ["__init__", "__new__"]:
                        self.logger.debug(f"Using callable {key} from plugin dictionary")
                        plugin = value
                        callable_found = True
                        break

                if not callable_found:
                    self.logger.warning(f"Dictionary plugin {plugin_name} has no executable component")
                    return self._create_error_result(
                        plugin_name,
                        f"Plugin dictionary missing file_path or executable component. Keys: {list(plugin.keys())}",
                    )

        # First check for object methods (traditional plugin objects)
        if hasattr(plugin, "execute") and callable(getattr(plugin, "execute")):
            self.logger.debug(f"Executing {plugin_name} via .execute() method")
            # Check execute() signature to determine correct arity
            # V2 plugins: execute(self, apk_ctx) - 2 params including self
            # Legacy plugins: execute(self, apk_ctx, deep_mode) - 3 params including self
            try:
                import inspect

                sig = inspect.signature(plugin.execute)
                param_count = len(sig.parameters)
                if param_count <= 1:
                    # execute(self) or execute() - call with just context
                    return plugin.execute(apk_ctx)
                elif param_count == 2:
                    # execute(self, apk_ctx) - v2 style
                    return plugin.execute(apk_ctx)
                else:
                    # execute(self, apk_ctx, deep_mode) or more - legacy style
                    return plugin.execute(apk_ctx, deep_mode)
            except (ValueError, TypeError) as e:
                self.logger.debug(
                    f"Could not inspect execute() signature for {plugin_name}: {e}, trying with deep_mode"
                )
                try:
                    return plugin.execute(apk_ctx, deep_mode)
                except TypeError:
                    return plugin.execute(apk_ctx)
        elif hasattr(plugin, "run") and callable(getattr(plugin, "run")):
            self.logger.debug(f"Executing {plugin_name} via .run() method")
            return plugin.run(apk_ctx)
        elif hasattr(plugin, "__call__"):
            return plugin(apk_ctx)
        elif hasattr(plugin, "run_function") and callable(getattr(plugin, "run_function")):
            return plugin.run_function(apk_ctx)

        # Check for module-level functions (when plugin is a module object)
        elif hasattr(plugin, "run_plugin") and callable(getattr(plugin, "run_plugin")):
            self.logger.debug(f"Executing module-level run_plugin function for {self._get_plugin_name(plugin)}")
            return plugin.run_plugin(apk_ctx)
        elif hasattr(plugin, "run") and callable(getattr(plugin, "run")):
            self.logger.debug(f"Executing module-level run function for {self._get_plugin_name(plugin)}")
            return plugin.run(apk_ctx)

        # If no standard execution method found, try to call it directly
        elif callable(plugin):
            return plugin(apk_ctx)
        else:
            # Enhanced error message with available attributes for debugging
            available_attrs = [
                attr for attr in dir(plugin) if not attr.startswith("_") and callable(getattr(plugin, attr, None))
            ]
            self.logger.debug(
                f"Plugin {self._get_plugin_name(plugin)} available callable attributes: {available_attrs}"
            )
            raise AttributeError(
                f"Plugin {self._get_plugin_name(plugin)} has no callable execution method. Available: {available_attrs[:5]}"  # noqa: E501
            )

    def _get_plugin_name(self, plugin: Any) -> str:
        """Extract plugin name from plugin object or dictionary representation."""

        # Handle dictionary plugin representations (common in unified plugin managers)
        if isinstance(plugin, dict):
            self.logger.debug(f"Processing dictionary plugin: keys={list(plugin.keys())}")
            # Check for common name keys in plugin dictionaries
            name_keys = ["name", "plugin_name", "module_name", "__name__", "id", "identifier", "class_name"]
            for key in name_keys:
                if key in plugin and isinstance(plugin[key], str):
                    return plugin[key]
            # If no standard name, try to extract from module info
            if "module" in plugin:
                module_name = str(plugin["module"])
                if "." in module_name:
                    return module_name.split(".")[-1]  # Get last part of module path
                return module_name
            # Look for any meaningful string identifier
            for key, value in plugin.items():
                if isinstance(value, str) and key not in ["error", "status", "result", "output"]:
                    # Use the key-value pair or just value if short
                    return value if len(value) < 50 else f"{key}_plugin"
            return "unknown_plugin_dict"

        # Check if this is an ExecutionTask
        if hasattr(plugin, "task_id"):
            return plugin.task_id
        elif hasattr(plugin, "task_type"):
            return f"ExecutionTask_{plugin.task_type}"

        # Try various attributes to get the name
        name_attrs = ["name", "plugin_name", "module_name", "__name__", "__class__.__name__"]

        for attr in name_attrs:
            if "." in attr:
                # Handle nested attributes like __class__.__name__
                obj = plugin
                for part in attr.split("."):
                    if hasattr(obj, part):
                        obj = getattr(obj, part)
                    else:
                        obj = None
                        break
                if obj and isinstance(obj, str):
                    return obj
            else:
                if hasattr(plugin, attr):
                    value = getattr(plugin, attr)
                    if isinstance(value, str):
                        return value

        # Fallback to string representation (but avoid generic 'dict')
        plugin_str = str(plugin)
        if plugin_str in ["<class 'dict'>", "dict"] or plugin_str.startswith("<class"):
            return f"unknown_plugin_{type(plugin).__name__}"
        return plugin_str

    def _load_plugin_from_path(self, file_path: str, plugin_name: str) -> Any:
        """Load plugin module from file path and return executable instance."""
        import importlib.util
        from pathlib import Path

        try:
            plugin_path = Path(file_path)

            # Validate plugin file exists
            if not plugin_path.exists():
                raise FileNotFoundError(f"Plugin file not found: {plugin_path}")

            # Handle directory plugins (with __init__.py)
            if plugin_path.is_dir():
                init_file = plugin_path / "__init__.py"
                if init_file.exists():
                    plugin_path = init_file
                else:
                    raise ImportError(f"Directory plugin {plugin_path} missing __init__.py")

            # Generate unique module name to avoid conflicts
            module_name = f"aods_plugin_{abs(hash(str(plugin_path)))}"

            # Load module spec
            spec = importlib.util.spec_from_file_location(module_name, plugin_path)
            if spec is None:
                raise ImportError(f"Could not create spec for plugin: {plugin_path}")

            # Create and execute module
            module = importlib.util.module_from_spec(spec)

            # Add to sys.modules to support relative imports within the plugin
            sys.modules[module_name] = module

            try:
                spec.loader.exec_module(module)
            except Exception as e:
                # Clean up sys.modules on failure
                if module_name in sys.modules:
                    del sys.modules[module_name]
                raise ImportError(f"Failed to execute plugin module {plugin_path}: {e}")

            # Look for executable plugin patterns in the loaded module
            plugin_instance = self._extract_plugin_from_module(module, plugin_name)

            return plugin_instance

        except Exception as e:
            self.logger.error(f"Failed to load plugin {plugin_name} from {file_path}: {e}")
            raise

    def _extract_plugin_from_module(self, module: Any, plugin_name: str) -> Any:
        """Extract executable plugin instance from loaded module."""

        # Pattern 0: V2 plugin factory - create_plugin() returns instance with execute()
        if hasattr(module, "create_plugin") and callable(getattr(module, "create_plugin")):
            try:
                instance = module.create_plugin()
                self.logger.debug(f"Created v2 plugin instance via create_plugin() for {plugin_name}")
                return instance
            except Exception as e:
                self.logger.warning(f"create_plugin() failed for {plugin_name}: {e}")
                # Fall through to other patterns

        # Pattern 1: Look for run_plugin function (common in AODS plugins)
        if hasattr(module, "run_plugin") and callable(getattr(module, "run_plugin")):
            self.logger.debug(f"Found run_plugin function in {plugin_name}")
            return module

        # Pattern 2: Look for plugin class (class ending with 'Plugin')
        plugin_classes = []
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if (
                isinstance(attr, type)
                and (attr_name.endswith("Plugin") or attr_name.endswith("Analyzer"))
                and attr_name != "Plugin"
            ):  # Exclude base Plugin class
                plugin_classes.append((attr_name, attr))

        if plugin_classes:
            # Prefer classes with execute/run/analyze methods
            for class_name, plugin_class in plugin_classes:
                if hasattr(plugin_class, "execute") or hasattr(plugin_class, "run") or hasattr(plugin_class, "analyze"):
                    try:
                        # Try to instantiate the plugin class
                        instance = plugin_class()
                        self.logger.debug(f"Instantiated plugin class {class_name} from {plugin_name}")
                        return instance
                    except Exception as e:
                        self.logger.warning(f"Failed to instantiate {class_name} from {plugin_name}: {e}")
                        # Return the class itself as fallback
                        return plugin_class

            # Fallback: use first plugin class
            class_name, plugin_class = plugin_classes[0]
            try:
                instance = plugin_class()
                return instance
            except Exception:
                return plugin_class

        # Pattern 3: Look for any callable that might be the plugin entry point
        for attr_name in ["main", "analyze", "execute", "run", "scan"]:
            if hasattr(module, attr_name) and callable(getattr(module, attr_name)):
                self.logger.debug(f"Found callable {attr_name} in {plugin_name}")
                return module

        # Fallback: return the module itself and let the execution logic handle it
        self.logger.debug(f"No specific plugin pattern found in {plugin_name}, returning module")
        return module

    # REMOVED: Duplicate _get_plugin_timeout method - using implementation at line 772

    def _process_plugin_result(self, plugin_name: str, raw_result: Any) -> Tuple[str, Union[str, Text]]:
        """
        Process and validate plugin result into consistent format.

        Consolidates result processing from different execution systems.
        """
        # Handle None results
        if raw_result is None:
            return (plugin_name, "No results found")

        # Handle tuple results (most common format)
        if isinstance(raw_result, tuple):
            if len(raw_result) == 2:
                title, content = raw_result
                return (str(title), content)
            elif len(raw_result) == 1:
                return (plugin_name, raw_result[0])
            else:
                # Handle unexpected tuple length
                return (plugin_name, str(raw_result))

        # Handle string results
        if isinstance(raw_result, str):
            return (plugin_name, raw_result)

        # Handle Rich Text results
        if hasattr(raw_result, "markup") or isinstance(raw_result, Text):
            return (plugin_name, raw_result)

        # Handle dict results (convert to readable format)
        if isinstance(raw_result, dict):
            if "title" in raw_result and "content" in raw_result:
                return (raw_result["title"], raw_result["content"])
            else:
                # Convert dict to readable string
                content = self._format_dict_result(raw_result)
                return (plugin_name, content)

        # Handle list results
        if isinstance(raw_result, list):
            if len(raw_result) == 0:
                return (plugin_name, "No findings detected")
            else:
                content = self._format_list_result(raw_result)
                return (plugin_name, content)

        # Fallback to string conversion
        return (plugin_name, str(raw_result))

    def _format_dict_result(self, result_dict: Dict[str, Any]) -> str:
        """Format dictionary result into readable string."""
        if not result_dict:
            return "No findings detected"

        lines = []
        for key, value in result_dict.items():
            if isinstance(value, (list, dict)):
                lines.append(f"{key}: {len(value) if isinstance(value, list) else 'complex object'}")
            else:
                lines.append(f"{key}: {value}")

        return "\n".join(lines)

    def _format_list_result(self, result_list: List[Any]) -> str:
        """Format list result into readable string."""
        if not result_list:
            return "No findings detected"

        # If list contains simple strings, join them
        if all(isinstance(item, str) for item in result_list):
            return "\n".join(result_list)

        # Otherwise, summarize the list
        return f"Found {len(result_list)} items: {', '.join(str(item)[:50] for item in result_list[:3])}{'...' if len(result_list) > 3 else ''}"  # noqa: E501

    def _create_error_result(self, plugin_name: str, error_message: str) -> Tuple[str, Text]:
        """Create formatted error result."""
        error_title = f"❌ {plugin_name}"
        error_content = Text(f"Error: {error_message}", style="red")
        return (error_title, error_content)

    def get_execution_statistics(self) -> Dict[str, Any]:
        """Get plugin execution statistics."""
        stats = self._execution_stats.copy()

        # Calculate derived statistics
        total = stats["total_executions"]
        if total > 0:
            stats["success_rate"] = stats["successful_executions"] / total
            stats["failure_rate"] = stats["failed_executions"] / total
            stats["timeout_rate"] = stats["timeout_executions"] / total
            stats["average_execution_time"] = (
                stats["total_execution_time"] / stats["successful_executions"]
                if stats["successful_executions"] > 0
                else 0.0
            )
        else:
            stats["success_rate"] = 0.0
            stats["failure_rate"] = 0.0
            stats["timeout_rate"] = 0.0
            stats["average_execution_time"] = 0.0

        return stats

    def _get_plugin_timeout(self, plugin_name: str, scan_profile: Optional[str] = None) -> int:
        """Get intelligently optimized timeout using EXISTING IntelligentTimeoutOptimizer + scan profile modifiers."""
        try:
            # INTEGRATION FIX: Use the existing sophisticated IntelligentTimeoutOptimizer first
            apk_path = getattr(self, "_current_apk_path", None)
            intelligent_timeout = get_optimized_timeout_for_plugin(plugin_name, apk_path or "")

            # Apply scan profile optimization ON TOP of intelligent timeout (not instead of)
            if scan_profile:
                final_timeout = self._apply_scan_profile_modifier(intelligent_timeout, scan_profile, plugin_name)
                self.logger.debug(
                    f"🧠 Plugin '{plugin_name}' timeout: {intelligent_timeout}s (intelligent) → {final_timeout}s (profile: {scan_profile})"  # noqa: E501
                )
                return final_timeout
            else:
                self.logger.debug(f"🧠 Plugin '{plugin_name}' timeout: {intelligent_timeout}s (intelligent)")
                return intelligent_timeout

        except Exception as e:
            # Fallback to unified timeout manager default
            try:
                default_timeout = self.timeout_manager.get_timeout_for_type(TimeoutType.PLUGIN)
            except Exception:
                # Final fallback with profile-specific defaults
                if scan_profile and scan_profile.lower() == "lightning":
                    default_timeout = 60  # Lightning profile: 60s max
                elif scan_profile and scan_profile.lower() == "fast":
                    default_timeout = 120  # Fast profile: 2 minutes max
                else:
                    default_timeout = 294  # Original default
            self.logger.warning(
                f"⚠️ Could not get intelligent timeout for '{plugin_name}': {e}. Using default: {default_timeout}s"
            )
            return default_timeout

    def _apply_scan_profile_modifier(self, base_timeout: int, scan_profile: str, plugin_name: str) -> int:
        """Apply scan profile modifier to intelligent base timeout."""
        profile_lower = scan_profile.lower()

        # Lightning profile: Reasonable optimization while respecting intelligent calculations
        if profile_lower == "lightning":
            # For very heavy plugins (base > 1200s), reasonable reduction
            if base_timeout > 1200:
                return max(300, min(600, int(base_timeout * 0.4)))  # 40% with reasonable floor/ceiling
            # For heavy plugins (base 600-1200s), moderate reduction
            elif base_timeout > 600:
                return max(240, min(480, int(base_timeout * 0.5)))  # 50% with floors/ceilings
            # For medium plugins (base 200-600s), light reduction
            elif base_timeout > 200:
                return max(120, min(300, int(base_timeout * 0.7)))  # 70% with floors/ceilings
            # For light plugins, minimal reduction
            else:
                return max(60, min(150, int(base_timeout * 0.85)))  # 85% with floors/ceilings

        # Fast profile: Moderate optimization
        elif profile_lower == "fast":
            return max(120, min(300, int(base_timeout * 0.75)))  # 75% with reasonable bounds

        # Standard profile: Light optimization
        elif profile_lower == "standard":
            return max(180, min(450, int(base_timeout * 0.85)))  # 85% with reasonable bounds

        # Deep profile: Use full intelligent timeout
        else:
            return base_timeout

    def set_scan_profile(self, scan_profile: str):
        """Set the current scan profile for timeout optimization."""
        self._current_scan_profile = scan_profile
        self.logger.debug(f"Plugin executor configured for scan profile: {scan_profile}")

    def reset_statistics(self):
        """Reset execution statistics."""
        self._execution_stats = {
            "total_executions": 0,
            "successful_executions": 0,
            "failed_executions": 0,
            "timeout_executions": 0,
            "total_execution_time": 0.0,
        }


def create_plugin_executor(timeout_manager: Optional[TimeoutManager] = None) -> PluginExecutor:
    """Factory function to create plugin executor."""
    return PluginExecutor(timeout_manager)
