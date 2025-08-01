import jpype
import jpype.imports
import os
import urllib.request
from core.result import Result, Severity
from languages.java import java_rules
from languages.java.java_taint_engine import JavaTaintEngine

# Constants
JAR_NAME = 'javaparser-core-3.25.4.jar'
JAR_PATH = os.path.join(os.path.dirname(__file__), JAR_NAME)
JAR_URL = f'https://repo1.maven.org/maven2/com/github/javaparser/javaparser-core/3.25.4/' + JAR_NAME

cvss_info = {
    "A01": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "A02": (7.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "A03": (9.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
    "A04": (6.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"),
    "A05": (6.0, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"),
    "A06": (8.2, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:H"),
    "A07": (7.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
    "A08": (8.8, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H"),
    "A09": (5.3, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L"),
    "A10": (9.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
}

# Ensure the jar is downloaded
def ensure_jar():
    if not os.path.exists(JAR_PATH):
        print(f"[+] Downloading {JAR_NAME}...")
        urllib.request.urlretrieve(JAR_URL, JAR_PATH)
        print("[+] Download complete.")

def get_java_classes():
    from com.github.javaparser import JavaParser
    from java.nio.file import Paths
    from java.nio.charset import StandardCharsets
    return JavaParser, Paths, StandardCharsets

# Run analysis on a Java file
def run_analysis(file_path):
    ensure_jar()
    print(f"[DEBUG] Starting JVM with: {JAR_PATH}")

    if not jpype.isJVMStarted():
        try:
            jpype.startJVM(classpath=[JAR_PATH])
        except Exception as e:
            print(f"[!] Failed to start JVM: {e}")
            return []

    JavaParser, Paths, StandardCharsets = get_java_classes()

    print(f"[BluJay DEBUG] Parsing: {file_path}")
    java_path = Paths.get(os.path.abspath(file_path))
    parser = JavaParser()
    parse_result = parser.parse(java_path, StandardCharsets.UTF_8)

    if not parse_result.isSuccessful() or not parse_result.getResult().isPresent():
        print(f"[!] Failed to parse: {file_path}")
        return []

    root_node = parse_result.getResult().get()
    nodes = root_node.findAll(jpype.JClass("com.github.javaparser.ast.Node"))

    findings = []

    # Tain analysis results
    findings.extend(JavaTaintEngine(file_path).run(root_node))

    # Run static rule-based matching
    for node in nodes:
        code = str(node)
        for rule in java_rules.get_rules():
            if rule.matches(code):
                line = node.getRange().get().begin.line if node.getRange().isPresent() else 1
                cvss_score, cvss_vector = cvss_info.get(rule.rule_id, (None, None))
                findings.append(Result(
                    rule_id=rule.rule_id,
                    desc=rule.desc,
                    file=file_path,
                    line=line,
                    severity=Severity[rule.severity.upper()],
                    cvss_score=cvss_score,
                    cvss_vector=cvss_vector
                ).to_dict())

    return findings
