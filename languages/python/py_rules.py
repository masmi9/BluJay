import ast

class Rule:
    def __init__(self, rule_id, desc, severity, pattern_func):
        self.rule_id = rule_id
        self.desc = desc
        self.severity = severity
        self.pattern_func = pattern_func

    def check(self, tree, file_path):
        results = []
        for node in ast.walk(tree):
            if self.pattern_func(node):
                results.append({
                    "rule_id": self.rule_id,
                    "desc": self.desc,
                    "file": file_path,
                    "line": getattr(node, 'lineno', 1),
                    "severity": self.severity
                })
        return results


def is_dangerous_eval(node):
    return isinstance(node, ast.Call) and getattr(node.func, 'id', '') == 'eval'


def get_rules():
    return [
        Rule("A03", "Use of eval() with potentially tainted input", "High", is_dangerous_eval)
    ]