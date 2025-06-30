import jpype
import jpype.imports
import os
import re

# Start the JVM and use JavaParser to analyze Java source code
JAVAPARSER_JAR_PATH = os.path.join(os.path.dirname(__file__), 'javaparser-core-3.25.4.jar')
if not jpype.isJVMStarted():
    jpype.startJVM(classpath=[JAVAPARSER_JAR_PATH])

from com.github.javaparser import JavaParser
from com.github.javaparser.ast.visitor import VoidVisitorAdapter

class FindingVisitor(VoidVisitorAdapter):
    def __init__(self, file_path):
        super().__init__()
        self.file_path = file_path
        self.findings = []

    def visit(self, n, arg):
        super().visit(n, arg)
        # Example: look for Runtime.getRuntime().exec()
        code = str(n)
        if re.search(r"Runtime\.getRuntime\(\)\.exec", code):
            self.findings.append({
                "rule_id": "A03",
                "desc": "Potential command injection via Runtime.exec",
                "file": self.file_path,
                "line": getattr(n.getRange().orElse(None), 'begin', {}).line if n.getRange().isPresent() else 1,
                "severity": "High"
            })


def run_analysis(file_path):
    with open(file_path, 'r') as file:
        source_code = file.read()

    parse_result = JavaParser.parse(source_code)
    visitor = FindingVisitor(file_path)
    visitor.visit(parse_result, None)

    return visitor.findings