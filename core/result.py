from enum import Enum

class Severity(Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    INFO = "Informational"
    FP = "False Positive"
    INTENTIONAL = "Intentional"

class Result:
    def __init__(self, rule_id, desc, file, line, severity: Severity, cvss_score=None, cvss_vector=None):
        self.rule_id = rule_id
        self.desc = desc
        self.file = file
        self.line = line
        self.severity = severity
        self.cvss_score = cvss_score
        self.cvss_vector = cvss_vector

    def to_dict(self):
        return {
            "Rule ID": self.rule_id,
            "Description": self.desc,
            "File": self.file,
            "Line": self.line,
            "Severity": self.severity.value,
            "CVSS Score": self.cvss_score,
            "CVSS Vector": self.cvss_vector
        }
