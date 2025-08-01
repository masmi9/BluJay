import ast
from languages.python.taint_engine import TaintEngine


def run_analysis(file_path):
    with open(file_path, "r") as f:
        source_code = f.read()

    tree = ast.parse(source_code, filename=file_path)
    engine = TaintEngine(file_path)
    findings = engine.run(tree)

    return findings