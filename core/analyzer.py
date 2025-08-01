import os
from core.base_checker import BaseChecker
from languages.python import py_parser
from languages.java.java_parser import run_analysis as run_java_analysis

class Analyzer:
    def __init__(self, language):
        self.language = language
        self.analyzers = {
            "python": py_parser.run_analysis,
            "java": run_java_analysis
        }
        self.extensions = {
            "python": ".py",
            "java": ".java"
        }

    def run(self, input_path):
        all_results = []
        analyzer_func = self.analyzers.get(self.language)
        file_ext = self.extensions.get(self.language)

        if not analyzer_func or not file_ext:
            raise ValueError(f"Unsupported language: {self.language}")
        
        for root, _, files in os.walk(input_path):
            for file in files:
                full_path = os.path.join(root, file)
                results = analyzer_func(full_path)
                all_results.extend(results)
        return all_results