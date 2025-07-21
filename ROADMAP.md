# BluJay SAST Tool - Product Vision

## ✨ Core Differentiators

* **Threat-Centric Detection**
* **Lightning-Fast Feedback**
* **Custom Rule Engine**
* **Mobile & Web App Coverage**
* **CI/CD Native**

## 🔧 Core Features

* Language Support: Java, Kotlin, XML, Python, JavaScript
* Rule System: YAML + Python, Regression Tests, Rule Marketplace
* Scan Modes: CLI, CI/CD, Live Mode (Future)
* Output: SARIF, JSON, CSV, HTML
* Developer UX: GitHub PRs, IDE Plugin, Auto-Fixes
* Risk Intelligence: Scoring, Compliance Tags, Threat Intel

## 🚀 Competitive Edge

See comparison matrix with Semgrep, SonarQube, Coverity, Veracode, Checkmarx

## 📊 Target Users

AppSec Engineers, Mobile Analysts, DevOps, Security Devs, Compliance Teams

## 🚀 Roadmap (Q3-Q4 2025)

* Web UI dashboard
* Frida/dynamic integration
* Rule suggestion engine
* AndroidManifest analyzer
* Dex reflection mapper

## 📅 Use Cases

* Reflection/WebView export scanning
* SSRF/URL fetchers
* eval/exec in web
* Crypto & file access abuse
* IOC enrichment

## 🌐 GitHub Snippet

```bash
pip install blujay-sast
blujay scan --input ./myapp --lang java --output results.json
```

---

# BluJay SAST Tool Development Checklist

## 🏋️ Product Planning

* [ ] Finalize BluJay's core vision and positioning
* [ ] Define supported languages (Java, Kotlin, Python, JS, XML)
* [ ] Create target threat models (e.g., OWASP, Mobile Top 10)
* [ ] Design CLI UX and integration flow

## 📁 Core Engine & Rule System

* [ ] Build modular static analysis engine (AST + regex)
* [ ] Implement YAML-based pattern rule engine
* [ ] Implement Python rule scripting for taint & symbolic logic
* [ ] Add rule validation + regression test runner
* [ ] Support rule metadata (severity, CWE, remediation)

## 📊 Language Support

* [ ] Java/Kotlin AST parser + symbol resolver
* [ ] XML manifest scanner with ICC detection
* [ ] Python + JS tokenizer/parser integration
* [ ] YAML/JSON config key extraction

## 🔧 CI/CD Integration

* [ ] GitHub Actions template
* [ ] GitLab CI pipeline support
* [ ] Jenkinsfile integration sample
* [ ] SARIF + JSON output formatting
* [ ] GitHub PR annotation support

## 🔎 Threat Detection Rulepacks

* [ ] SSRF, hardcoded fetcher detection
* [ ] Reflection + WebView exported misuse
* [ ] Command injection + insecure exec
* [ ] Weak crypto flagging (ECB, MD5, etc.)
* [ ] File/IPC access risks (tmp, sdcard, etc.)
* [ ] Frida hookable logic markers
* [ ] IOC pattern matching + enrichments

## 📊 UX & Reporting

* [ ] HTML report generator with filters
* [ ] CSV + SARIF export
* [ ] Add risk scoring per finding
* [ ] Build auto-remediation suggestions engine

## 🚀 Future Enhancements

* [ ] VSCode plugin (live rule hints)
* [ ] Web dashboard (team views)
* [ ] Threat badge + scoring dashboard
* [ ] Integration with VirusTotal, OTX, AbuseIPDB
* [ ] Frida-based dynamic context enrichment

---

**BluJay is not just another SAST tool. It is a security engineer’s co-pilot.**