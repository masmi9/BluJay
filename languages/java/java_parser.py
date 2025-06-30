import jpype
import jpype.imports
import os
import re
from core.result import Result, Severity
from languages.java import java_rules

# Start JVM
JAVAPARSER_JAR_PATH = os.path.join(os.path.dirname(__file__), 'javaparser-core-3.25.4.jar')
if not jpype.isJVMStarted():
    jpype.startJVM(classpath=[JAVAPARSER_JAR_PATH])

from com.github.javaparser import JavaParser

def run_analysis(file_path):
    with open(file_path, 'r') as file:
        source_code = file.read()

    parse_result = JavaParser.parse(source_code)
    rules = java_rules.get_rules()
    findings = []

    # Traverse every node by converting to string and matching
    nodes = parse_result.findAll(jpype.JClass("com.github.javaparser.ast.Node"))
    for node in nodes:
        code = str(node)
        for rule in rules:
            if rule.matches(code):
                line = node.getRange().get().begin.line if node.getRange().isPresent() else 1
                findings.append(Result(
                    rule_id=rule.rule_id,
                    desc=rule.desc,
                    file=file_path,
                    line=line,
                    severity=Severity[rule.severity.upper()]
                ).to_dict())
    return findings
