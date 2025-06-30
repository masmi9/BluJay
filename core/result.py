from enum import Enum

class Severity(Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    INFO = "Informational"

class Result:
    def __init__(self, rule_id, desc, file, line, severity: Severity):
        self.rule_id = rule_id
        self.desc = desc
        self.file = file
        self.line = line
        self.severity = severity

    def to_dict(self):
        return {
            "rule_id": self.rule_id,
            "desc": self.desc,
            "file": self.file,
            "line": self.line,
            "severity": self.severity.value
        }
