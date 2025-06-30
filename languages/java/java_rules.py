# Rule objects to sync with JavaParser visitor logic
import re

class JavaRule:
    def __init__(self, rule_id, desc, severity, pattern):
        self.rule_id = rule_id
        self.desc = desc
        self.severity = severity
        self.pattern = pattern  # regex pattern to match code strings

    def matches(self, node_str):
        return re.search(self.pattern, node_str)

def get_rules():
    return [
        JavaRule(
            rule_id="A03",
            desc="Potential command injection via Runtime.exec",
            severity="High",
            pattern=r"Runtime\.getRuntime\(\)\.exec"
        )
    ]
