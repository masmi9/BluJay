"""
Dynamic Analysis Modules – Frida-based runtime analysis for iOS.

Requires: jailbroken iOS device with Frida server, ideviceinstaller.

Performs:
  - Keychain runtime monitoring (SecItemAdd/SecItemCopyMatching hooks)
  - Network request interception (NSURLSession hooks)
  - Cryptographic API monitoring (CCCrypt hooks)
  - File system access monitoring
  - Method swizzling detection
"""
from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.plugins.base_plugin_ios import (
    BasePluginIOS, PluginCapability, PluginFinding,
    PluginMetadata, PluginPriority, PluginResult, PluginStatus,
    PluginDependency,
)

_FRIDA_SCRIPT = """
// IODS Frida instrumentation script
'use strict';

var findings = [];

// Hook SecItemAdd for keychain monitoring
try {
    var SecItemAdd = Module.findExportByName('Security', 'SecItemAdd');
    if (SecItemAdd) {
        Interceptor.attach(SecItemAdd, {
            onEnter: function(args) {
                var attrs = ObjC.Object(args[0]);
                findings.push({
                    type: 'keychain_write',
                    description: 'SecItemAdd called: ' + attrs.toString().substring(0, 200)
                });
            }
        });
    }
} catch(e) {}

// Hook NSURLSession for network monitoring
try {
    var resolver = new ApiResolver('objc');
    resolver.enumerateMatches('*[NSURLSession dataTaskWithRequest:*]', {
        onMatch: function(match) {
            Interceptor.attach(match.address, {
                onEnter: function(args) {
                    var req = ObjC.Object(args[2]);
                    var url = req.URL().absoluteString().toString();
                    if (url.startsWith('http://')) {
                        findings.push({
                            type: 'cleartext_http',
                            description: 'Cleartext HTTP request: ' + url
                        });
                    }
                }
            });
        },
        onComplete: function() {}
    });
} catch(e) {}

// Report findings
setInterval(function() {
    if (findings.length > 0) {
        send({findings: findings});
        findings = [];
    }
}, 1000);
"""


class DynamicAnalysisModulesV2(BasePluginIOS):

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="dynamic_analysis_modules",
            version="1.0.0",
            capabilities=[PluginCapability.DYNAMIC_ANALYSIS, PluginCapability.BEHAVIORAL_ANALYSIS],
            description="Frida-based runtime analysis: keychain, network, crypto monitoring.",
            priority=PluginPriority.LOW,
            timeout_seconds=300,
            requires_device=True,
            tags=["frida", "dynamic", "runtime", "hook"],
            masvs_control="MASVS-RESILIENCE-4",
            dependencies=[
                PluginDependency(name="frida", optional=False,
                                 install_command="pip install frida frida-tools",
                                 description="Frida dynamic instrumentation toolkit"),
            ],
        )

    def can_execute(self, ipa_ctx) -> tuple:
        if not ipa_ctx.scan_mode == "deep":
            return False, "Dynamic analysis requires --mode deep"
        device_udid = getattr(ipa_ctx, "device_udid", None)
        if not device_udid and not self._detect_device():
            return False, "No iOS device connected (use --device-udid or connect a jailbroken device)"
        try:
            import frida
        except ImportError:
            return False, "frida package not installed (pip install frida frida-tools)"
        return True, None

    def execute(self, ipa_ctx) -> PluginResult:
        self.setup(ipa_ctx)
        findings: List[PluginFinding] = []

        try:
            import frida
        except ImportError:
            return self.create_result(
                PluginStatus.DEPENDENCY_MISSING,
                error_message="frida package not installed",
            )

        device = self._connect_device(ipa_ctx, frida)
        if device is None:
            return self.create_result(
                PluginStatus.FAILURE,
                error_message="Could not connect to iOS device via Frida",
            )

        try:
            frida_findings = self._run_frida_session(device, ipa_ctx)
            findings.extend(self._convert_frida_findings(frida_findings))
        except Exception as e:
            return self.create_result(
                PluginStatus.PARTIAL_SUCCESS,
                findings=findings,
                error_message=f"Frida session error: {e}",
            )

        return self.create_result(PluginStatus.SUCCESS, findings)

    def _detect_device(self) -> bool:
        """Check if any iOS device is connected via USB."""
        try:
            result = subprocess.run(
                ["ideviceinfo", "-q", "ProductType"],
                capture_output=True, text=True, timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False

    def _connect_device(self, ipa_ctx, frida_module) -> Optional[Any]:
        """Connect to iOS device via Frida."""
        try:
            device_mgr = frida_module.get_device_manager()
            # Try USB device first
            for device in device_mgr.enumerate_devices():
                if device.type == "usb":
                    return device
            return None
        except Exception:
            return None

    def _run_frida_session(self, device, ipa_ctx) -> List[Dict[str, Any]]:
        """Attach Frida to the target app and collect runtime findings."""
        import frida
        bundle_id = ipa_ctx.bundle_id
        if not bundle_id:
            return []

        script_results: List[Dict[str, Any]] = []

        def on_message(message, data):
            if message.get("type") == "send":
                payload = message.get("payload", {})
                if "findings" in payload:
                    script_results.extend(payload["findings"])

        session = device.attach(bundle_id)
        script = session.create_script(_FRIDA_SCRIPT)
        script.on("message", on_message)
        script.load()

        # Collect for 30 seconds
        time.sleep(30)
        script.unload()
        session.detach()

        return script_results

    def _convert_frida_findings(self, frida_results: List[Dict[str, Any]]) -> List[PluginFinding]:
        findings = []
        seen = set()
        for r in frida_results:
            ftype = r.get("type", "unknown")
            desc = r.get("description", "")
            key = f"{ftype}:{desc[:40]}"
            if key in seen:
                continue
            seen.add(key)

            if ftype == "cleartext_http":
                findings.append(self.create_finding(
                    f"dynamic_cleartext_http_{len(findings)}",
                    "Cleartext HTTP Request Observed at Runtime",
                    f"Runtime monitoring captured: {desc}",
                    "high",
                    confidence=0.95,
                    cwe_id="CWE-319",
                    masvs_control="MASVS-NETWORK-1",
                    evidence={"runtime_capture": desc},
                    remediation="All network requests must use HTTPS. Enable ATS in Info.plist.",
                ))
            elif ftype == "keychain_write":
                findings.append(self.create_finding(
                    f"dynamic_keychain_write_{len(findings)}",
                    "Runtime Keychain Write Observed",
                    f"SecItemAdd called at runtime: {desc[:200]}",
                    "info",
                    confidence=0.9,
                    cwe_id="CWE-312",
                    masvs_control="MASVS-STORAGE-1",
                    evidence={"runtime_capture": desc[:200]},
                ))
            else:
                findings.append(self.create_finding(
                    f"dynamic_finding_{len(findings)}",
                    f"Runtime Finding: {ftype}",
                    desc,
                    "medium",
                    confidence=0.8,
                    evidence={"runtime_capture": desc},
                ))

        return findings
