# languages/java/java_rules.py
# Rule objects to sync with JavaParser logic
import re

class JavaRule:
    def __init__(self, rule_id, desc, severity, pattern):
        self.rule_id = rule_id
        self.desc = desc
        self.severity = severity
        self.pattern = pattern  # regex pattern to match code strings

    def matches(self, node_str):
        return re.search(self.pattern, node_str)

def get_rules():
    return [
        JavaRule(
            rule_id="A01",
            desc="Potential broken access control: exposed endpoints or methods",
            severity="High",
            pattern=r"@PermitAll|@RolesAllowed"
        ),
        JavaRule(
            rule_id="A02",
            desc="Potential cryptographic failure: insecure cipher",
            severity="High",
            pattern=r"Cipher\.getInstance\("
        ),
        JavaRule(
            rule_id="A03",
            desc="Potential command injection via Runtime.exec",
            severity="High",
            pattern=r"Runtime\.getRuntime\(\).*?\.exec"
        ),
        JavaRule(
            rule_id="A04",
            desc="Potential insecure design: insecure default configuration",
            severity="Medium",
            pattern=r"@Configuration|@Bean"
        ),
        JavaRule(
            rule_id="A05",
            desc="Security misconfiguration: debug/logging enabled",
            severity="Medium",
            pattern=r"logger\.debug\(|System\.out\.print"
        ),
        JavaRule(
            rule_id="A06",
            desc="Use of vulnerable or outdated component",
            severity="Medium",
            pattern=r"import org\.apache\.struts|log4j"
        ),
        JavaRule(
            rule_id="A07",
            desc="Authentication weakness: hardcoded credentials",
            severity="High",
            pattern=r"password\s*=\s*\".*\""
        ),
        JavaRule(
            rule_id="A08",
            desc="Data integrity failure: insecure deserialization",
            severity="High",
            pattern=r"ObjectInputStream|readObject\("
        ),
        JavaRule(
            rule_id="A09",
            desc="Potential insecure reflection via Class.forName or newInstance",
            severity="Medium",
            pattern=r"Class\.forName\(|clazz\.newInstance\("
        ),
        JavaRule(
            rule_id="A10",
            desc="Potential SSRF via URL fetching with user-controlled input",
            severity="High",
            pattern=r"(HttpURLConnection|new URL\()"
        )
    ]
