from core.ai.validator import AIValidator

def test_heuristics_true_positive():
    val = AIValidator(provider="dry_run")
    findings = [{
        "rule_id":"JAVA_SSRF", "cwe_id":918, "file":"src/Foo.java", "line":42,
        "severity":"High", "message":"User input to URL()", "code":"new URL(userInput)",
        "source":"userInput", "sink":"new URL()", "sanitizers":[], "taint_path":["userInput","URL()"]
    }]
    out = val.validate_findings(findings, language="java")
    assert out[0]["ai_validation"]["label"] == "true_positive"
