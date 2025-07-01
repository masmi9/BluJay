import jpype
import jpype.imports
import os
import re
import urllib.request
from core.result import Result, Severity
from languages.java import java_rules

# Constants
JAR_NAME = 'javaparser-core-3.25.4.jar'
JAR_PATH = os.path.join(os.path.dirname(__file__), JAR_NAME)
JAR_URL = f'https://repo1.maven.org/maven2/com/github/javaparser/javaparser-core/3.25.4/{JAR_NAME}'

# Ensure the jar is downloaded
def ensure_jar():
    if not os.path.exists(JAR_PATH):
        print(f"[+] Downloading {JAR_NAME}...")
        urllib.request.urlretrieve(JAR_URL, JAR_PATH)
        print("[+] Download complete.")

# Run analysis on a Java file
def run_analysis(file_path):
    ensure_jar()

    if not jpype.isJVMStarted():
        jpype.startJVM(classpath=[JAR_PATH])

    # Import Java classes only after JVM is started
    from com.github.javaparser import JavaParser
    from java.io import File

    java_file = File(file_path)
    parse_result = JavaParser.parse(java_file)
    rules = java_rules.get_rules()
    findings = []

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
