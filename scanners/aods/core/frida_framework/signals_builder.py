from __future__ import annotations

import re
from pathlib import Path
from typing import Optional, List

from core.xml_safe import safe_parse

from .script_suggester import APKAnalysisSignals


def _find_decompiled_dir(package_hint: Optional[str] = None, sources_dir: Optional[Path] = None) -> Optional[Path]:
    """Best-effort discovery of a decompiled sources directory.

    Prefers explicit sources_dir if provided (from apk_ctx.decompiled_apk_dir).
    Falls back to workspace directory discovery.
    """
    if sources_dir and sources_dir.is_dir():
        return sources_dir

    project_root = Path.cwd()
    candidates = []

    # Search workspace dir
    ws = project_root / "workspace"
    if ws.exists():
        candidates.extend(sorted(ws.glob("*_decompiled"), key=lambda p: p.stat().st_mtime, reverse=True))

    # Search project root
    candidates.extend(sorted(project_root.glob("*_decompiled"), key=lambda p: p.stat().st_mtime, reverse=True))

    for c in candidates:
        if c.is_dir():
            return c
    return None


def build_apk_analysis_signals(package_name: Optional[str] = None, max_classes: int = 5000) -> APKAnalysisSignals:
    """Build minimal `APKAnalysisSignals` by scanning a decompiled directory.

    This is a lightweight heuristic builder to seed the rule-based suggester
    until a richer static signal pipeline is wired. It extracts class names
    from .java/.smali file paths and performs simple library hints.
    """
    signals = APKAnalysisSignals.minimal(package_name)
    decompiled_dir = _find_decompiled_dir(package_name)
    if not decompiled_dir:
        return signals

    classes: List[str] = []
    methods: List[str] = []

    # Precompiled regex for basic method extraction
    java_method_re = re.compile(
        r"^(?:\s*(?:public|private|protected|static|final|synchronized|native|abstract|strictfp)\s+)*"  # modifiers
        r"[\w\<\>\[\],\.?]+\s+"  # return type
        r"(?P<name>[A-Za-z_$][A-Za-z\d_$]*)\s*\("
    )
    smali_method_re = re.compile(r"^\s*\.method\s+.*\s(?P<name>[A-Za-z_$][A-Za-z\d_$]*)\(.*")
    # Collect class-like paths from Java and Smali files
    for ext in ("*.java", "*.smali"):
        for f in decompiled_dir.rglob(ext):
            try:
                rel = f.relative_to(decompiled_dir)
                parts = rel.with_suffix("").parts
                # Heuristic: treat path segments as package.class
                class_name = ".".join(parts)
                if class_name:
                    classes.append(class_name)
                # Extract method names with simple heuristics
                try:
                    with f.open("r", errors="replace") as fh:
                        for i, line in enumerate(fh):
                            if ext == "*.java":
                                m = java_method_re.match(line)
                                if m:
                                    method_name = m.group("name")
                                    if class_name and method_name:
                                        methods.append(f"{class_name}#{method_name}")
                            else:
                                m = smali_method_re.match(line)
                                if m:
                                    method_name = m.group("name")
                                    if class_name and method_name:
                                        methods.append(f"{class_name}#{method_name}")
                            # Cap to avoid heavy parsing
                            if len(methods) >= max_classes * 2:
                                break
                except Exception:
                    pass
                if len(classes) >= max_classes:
                    raise StopIteration
            except StopIteration:
                break
            except Exception:
                continue

    signals.classes = classes
    signals.methods = methods

    # Simple library fingerprints by path
    libs = {}
    lib_hints = {
        "okhttp3": "okhttp3",
        "retrofit2": "retrofit2",
        "bouncycastle": "bouncycastle",
        "conscrypt": "conscrypt",
    }
    for hint, name in lib_hints.items():
        if any(hint in c for c in classes):
            libs[name] = "unknown"
    signals.libraries = libs

    # Parse AndroidManifest.xml for permissions and features
    manifest = decompiled_dir / "AndroidManifest.xml"
    permissions: List[str] = []
    manifest_features = {}
    if manifest.exists():
        try:
            tree = safe_parse(str(manifest))
            root = tree.getroot()
            # Android namespace
            _ns = {"android": "http://schemas.android.com/apk/res/android"}  # noqa: F841
            for item in root.findall("uses-permission"):
                name = item.get("{http://schemas.android.com/apk/res/android}name")
                if name:
                    permissions.append(name)
            for item in root.findall("uses-feature"):
                name = item.get("{http://schemas.android.com/apk/res/android}name")
                if name:
                    manifest_features[name] = True
        except Exception:
            pass
    signals.permissions = permissions
    signals.manifest_features = manifest_features

    return signals
