import ast
from languages.python.taint_engine import TaintEngine


def run_analysis(file_path):
    with open(file_path, "r") as f:
        source_code = f.read()

    tree = ast.parse(source_code, filename=file_path)
    engine = TaintEngine()
    findings = engine.run(tree)

    results = []
    for func, lineno in findings:
        results.append({
            "rule_id": "A03",
            "desc": f"Tainted data passed to sensitive sink: {func}()",
            "file": file_path,
            "line": lineno,
            "severity": "High"
        })
    return results
