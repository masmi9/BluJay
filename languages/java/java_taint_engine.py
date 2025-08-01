import jpype
from core.result import Result, Severity

class JavaTaintEngine:
    def __init__(self, file_path):
        self.file_path = file_path
        self.tainted_vars = set()
        self.findings = []
        self.sources = {"getParameter", "getHeader", "getCookies"}
        self.sinks = {"Runtime.getRuntime().exec", "new URL", "FileOutputStream"}

    def run(self, root_node):
        Node = jpype.JClass("com.github.javaparser.ast.Node")

        all_nodes = root_node.findAll(Node)
        for node in all_nodes:
            code = str(node)

            # Track source → variable
            for source in self.sources:
                if f"{source}(" in code:
                    var = self.extract_assigned_var(code)
                    if var:
                        self.tainted_vars.add(var)

            # Check sink ← tainted var
            for sink in self.sinks:
                if sink in code:
                    for var in self.tainted_vars:
                        if var in code:
                            line = node.getRange().get().begin.line if node.getRange().isPresent() else 1
                            self.findings.append(Result(
                                rule_id="TA-J01",
                                desc=f"Tainted variable '{var}' reaches sink: {sink}",
                                file=self.file_path,
                                line=line,
                                severity=Severity.HIGH,
                                cvss_score=8.8,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                            ).to_dict())
        return self.findings

    def extract_assigned_var(self, code_line):
        # Very basic: look for "Type var = source(...);"
        import re
        match = re.search(r"\b(\w+)\s+(\w+)\s*=\s*.*?(getParameter|getHeader|getCookies)\s*\(", code_line)
        return match.group(2) if match else None