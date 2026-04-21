"""
core.native_decompiler - Ghidra-based native binary decompilation.

Provides GhidraBridge for decompiling .so files to pseudo-C, enabling
ML-based vulnerability detection on native code. Falls back gracefully
when Ghidra is not installed.
"""
