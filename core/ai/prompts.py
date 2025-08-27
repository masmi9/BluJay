BASE_PROMPT = """You are validating a static analysis finding.

Project context:
- Language: {language}
- Frameworks/Libraries: {frameworks}

Finding:
- Rule: {rule_id} (CWE-{cwe_id})
- Location: {file}:{line}
- Severity: {severity}
- Message: {message}

Code Snippet (focus region):
