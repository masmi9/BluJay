# Package for enhanced detection adapters and legacy module
from .v2_plugin import EnhancedDetectionV2, create_plugin

__all__ = ["EnhancedDetectionV2", "create_plugin", "run", "run_plugin"]


def run(apk_ctx):
    """Legacy plugin entry point - wraps v2 plugin."""
    try:
        from rich.text import Text

        plugin = create_plugin()
        result = plugin.execute(apk_ctx)

        if result.findings:
            output = Text(f"Enhanced Detection - {len(result.findings)} findings\n", style="bold blue")
            for finding in result.findings[:10]:
                output.append(f"• {finding.title}\n", style="yellow")
        else:
            output = Text("Enhanced Detection - Analysis complete\n", style="green")

        return "Enhanced Detection Plugin", output
    except Exception as e:
        from rich.text import Text

        return "Enhanced Detection Plugin", Text(f"Error: {e}", style="red")


def run_plugin(apk_ctx):
    """Alias for run()."""
    return run(apk_ctx)
