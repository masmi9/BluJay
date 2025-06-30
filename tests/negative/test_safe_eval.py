import os
from languages.python import py_parser

def test_eval_safe():
    file_path = os.path.join(os.path.dirname(__file__), "example_negative_eval.py")
    findings = py_parser.run_analysis(file_path)
    assert not findings