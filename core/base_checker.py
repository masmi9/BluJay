class BaseChecker:
    def __init__(self, rule_id, description, severity):
        self.rule_id = rule_id
        self.description = description
        self.severity = severity

    def match(self, node):
        raise NotImplementedError("Subclasses must implement match method")