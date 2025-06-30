import os
from languages.python import py_parser

def test_eval_taint():
    file_path = os.path.join(os.path.dirname(__file__), "example_positive_eval.py")
    findings = py_parser.run_analysis(file_path)
    assert any("eval" in f["desc"] for f in findings)