import ast

class TaintEngine(ast.NodeVisitor):
    def __init__(self):
        self.tainted_vars = set()
        self.findings = []
        self.sources = {"input", "request.args.get"}
        self.sinks = {"eval", "os.system", "subprocess.call"}

    def visit_Call(self, node):
        func_name = getattr(node.func, 'id', None) or getattr(getattr(node.func, 'attr', None), 'id', None)
        if func_name in self.sources:
            if isinstance(node.parent, ast.Assign):
                self.tainted_vars.add(node.parent.targets[0].id)
        elif func_name in self.sinks:
            for arg in node.args:
                if isinstance(arg, ast.Name) and arg.id in self.tainted_vars:
                    self.findings.append((func_name, arg.lineno))
        self.generic_visit(node)

    def run(self, tree):
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                child.parent = node
        self.visit(tree)
        return self.findings