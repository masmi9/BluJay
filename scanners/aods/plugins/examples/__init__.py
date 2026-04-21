# Example plugins demonstrating AODS standardized plugin format

# BasePluginV2 interface
try:
    from .v2_plugin import ExamplesV2, create_plugin  # noqa: F401

    Plugin = ExamplesV2
except ImportError:
    pass
