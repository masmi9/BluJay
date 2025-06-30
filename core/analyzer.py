import os
from core.base_checker import BaseChecker
from languages.python import py_parser
from languages.java import java_parser  # Placeholder

class Analyzer:
    def __init__(self, language):
        self.language = language

    def run(self, input_path):
        all_results = []
        for root, _, files in os.walk(input_path):
            for file in files:
                if file.endswith(".py") and self.language == "python":
                    full_path = os.path.join(root, file)
                    results = py_parser.run_analysis(full_path)
                    all_results.extend(results)
                elif file.endswith(".java") and self.language == "java":
                    full_path = os.path.join(root, file)
                    results = java_parser.run_analysis(full_path)  # Placeholder
                    all_results.extend(results)
        return all_results