import csv
import json

class Reporter:
    def __init__(self, output_file):
        self.output_file = output_file

    def generate(self, findings):
        if self.output_file.endswith(".csv"):
            with open(self.output_file, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Rule ID", "Description", "File", "Line", "Severity"])
                for f in findings:
                    writer.writerow([f.get("rule_id"), f.get("desc"), f.get("file"), f.get("line"), f.get("severity")])
        elif self.output_file.endswith(".json"):
            with open(self.output_file, "w") as f:
                json.dump(findings, f, indent=2)