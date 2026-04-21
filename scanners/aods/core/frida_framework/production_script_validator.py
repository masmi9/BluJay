from __future__ import annotations

from dataclasses import dataclass
from typing import List


@dataclass
class ValidationResult:
    valid: bool
    errors: List[str]


class ProductionScriptValidator:
    """Production-focused Frida script validator (lightweight scaffolding)."""

    FORBIDDEN_TOKENS = (
        "Java.openClassFile",
        "Module.load",
        "Process.spawn",
        "new File(",
        "FileInputStream",
        "Socket(",
        "URLConnection",
    )
    MAX_SIZE_BYTES = 50_000

    def validate_standard(self, script_content: str) -> ValidationResult:
        errors: List[str] = []
        if not isinstance(script_content, str) or not script_content.strip():
            errors.append("empty_script")
            return ValidationResult(False, errors)
        if len(script_content.encode("utf-8")) > self.MAX_SIZE_BYTES:
            errors.append("script_too_large")
        for token in self.FORBIDDEN_TOKENS:
            if token in script_content:
                errors.append(f"forbidden_token:{token}")
        # Basic sanity: require Java.perform wrapper
        if "Java.perform(function()" not in script_content:
            errors.append("missing_java_perform_wrapper")
        return ValidationResult(len(errors) == 0, errors)

    def validate_strict(self, script_content: str) -> ValidationResult:
        """Strict policy validation with additional checks."""
        result = self.validate_standard(script_content)
        errors = list(result.errors)
        # Additional strict checks (examples): limit number of hooks, deny eval/Function constructor
        if "eval(" in script_content or "Function(" in script_content:
            errors.append("forbidden_dynamic_code")
        # Rough hook count heuristic
        hook_count = script_content.count("Java.use(") + script_content.count("Interceptor.attach(")
        if hook_count > 50:
            errors.append("too_many_hooks")
        return ValidationResult(len(errors) == 0, errors)
