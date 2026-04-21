from __future__ import annotations

import json
from typing import Dict, Any


def render_script_from_template(template_id: str, params: Dict[str, Any]) -> str:
    """Render a Frida script from a template identifier and parameters.

    NOTE: This is a lightweight fallback renderer. It prefers using the
    CustomScriptManager if available, otherwise emits a minimal Java.perform
    wrapper carrying template metadata. This keeps CI smoke tests deterministic
    and safe. A full integration can replace this with real template rendering.
    """
    try:
        # Optional integration with CustomScriptManager (if available)
        from plugins.frida_dynamic_analysis.custom_script_manager import (
            CustomScriptManager,
            CustomScriptProfile,
            CustomScriptSource,
        )

        csm = CustomScriptManager()
        profile = CustomScriptProfile(
            script_name=f"auto_{template_id}",
            source_type=CustomScriptSource.TEMPLATE_BASED,
            source_content=template_id,
            parameters=params,
        )
        content = csm.generate_custom_script_content(profile)
        if content and isinstance(content, str):
            return content
    except Exception:
        pass

    # Fallback minimal wrapper for smoke tests and safe default
    metadata = json.dumps({"template_id": template_id, "params": params}, ensure_ascii=False)
    return f"""
Java.perform(function() {{
  try {{
    console.log('[+] AODS rule-based script loaded');
    console.log('[+] Template: {template_id}');
    console.log('[+] Params: {metadata}');
  }} catch (e) {{}}
}});
"""
