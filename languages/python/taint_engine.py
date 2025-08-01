import ast
from core.result import Result, Severity

class TaintEngine(ast.NodeVisitor):
    def __init__(self):
        self.tainted_vars = set()
        self.findings = []
        self.sources = {"input", "request.args.get", "request.form.get", "sys.argv"}
        self.sinks = {"eval", "os.system", "subprocess.call", "open", "exec"}

    def get_func_name(self, node):
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return self.get_func_name(node.value) + "." + node.attr
        elif isinstance(node, ast.Call):
            return self.get_func_name(node.func)
        return ""

    def visit_Assign(self, node):
        # Example: user_input = input()
        if isinstance(node.value, ast.Call):
            func_name = self.get_func_name(node.value.func)
            if func_name in self.sources:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted_vars.add(target.id)
        self.generic_visit(node)

    def is_tainted_expr(self, node):
        if isinstance(node, ast.Name):
            return node.id in self.tainted_vars
        elif isinstance(node, ast.BinOp):
            return self.is_tainted_expr(node.left) or self.is_tainted_expr(node.right)
        elif isinstance(node, ast.Call):
            return any(self.is_tainted_expr(arg) for arg in node.args)
        elif isinstance(node, ast.Attribute):
            return self.is_tainted_expr(node.value)
        return False

    def visit_Call(self, node):
        func_name = self.get_func_name(node.func)
        if func_name in self.sinks:
            for arg in node.args:
                if self.is_tainted_expr(arg):
                    line = node.lineno
                    self.findings.append(Result(
                        rule_id="TA01",
                        desc=f"Tainted input reaches sink '{func_name}'",
                        file=self.file_path,
                        line=line,
                        severity=Severity.HIGH,
                        cvss_score=8.8,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                    ).to_dict())
        self.generic_visit(node)

    def run(self, tree):
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                child.parent = node
        self.visit(tree)
        return self.findings