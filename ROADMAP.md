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

### 🥇 Phase 1: CLI + Core Engine

* [ ] Design CLI UX and integration flow (crucial for early adopters, automation)
    - [x] Implement blucli.main with `argparse`-based interface
    - [x] Support `--input`, `--lang`, `--output` arguments
    - [] Add real-time logging and progress indicators
    - [] Add clear error messages and usage help
    - [] Include `--debug` and `--ruleset` flags for advanced usage
    - [] Provide example CLI usage in README.md
* [ ] Build modular static analysis engine (AST + regex)
    - [x] Java parser integrated with `javaparser-core`
    - [x] Java taint engine integrated
    - [x] Pattern-based rule matching system (regex)
    - [] Normalize and unify result output structure (CSV + JSON)
    - [] Modular architecture for multi-language plugin support
* [ ] Support rule metadata system (severity, CWE, remediation)
    - [x] Static pattern rules implemented in `java_rules.py`
    - [x] CVSS base score and OWASP Top 10 tagging
    - [] Add support for YAML-based rule definitions
    - [] Implement rule schema validation (e.g., `cerberus`, `jsonschema`)
    - [] Build regression test runner for rule validation
* [ ] Java/Kotlin AST parser + symbol resolver (language maturity for MVP)
    - [x] Java parsing and analysis via AST (JavaParser)
    - [] Kotlin support (AST or KotlinPoet/UAST Integration)
* [ ] Add rule validation + regression test runner
    - [] Add test cases to `tests/java/positive` and `negative/`
    - [] Create assertion-based unit tests for rule detections
    - [x] Set up CLI integration in `.github/workflows/ci.yml`
    - [] Auto-run test suite on PR/commit via GitHub Actions

### 🥈 Phase 2: Web Dashboard MVP

* [x] Web dashboard (team views) (essential for teams, PM visibility, triage)
* [ ] HTML report generator with filters
* [ ] Risk scoring per finding
* [ ] Threat badge + scoring dashboard


## Secondary: Ecosystem + Expansion

### 🥉 Phase 3: CI/CD and Format Support

* [ ] GitHub Actions template
* [ ] GitLab CI pipeline support
* [ ] Jenkinsfile integration sample
* [ ] SARIF + CSV + JSON output formatting
* [ ] GitHub PR annotation support

### 🔄 Phase 4: Rule & Language Expansion

* [ ] XML manifest scanner (ICC)
* [ ] Python/JS parser integration
* [ ] Rulepacks: SSRF, Reflection, Crypto, Frida markers, etc.
* [ ] Frida hookable logic markers
* [ ] IOC pattern matching + enrichments (VirusTotal, OTX, AbuselPDB)

## 🚀 Future Enhancements

* [ ] VSCode plugin (live rule hints)
* [ ] Auto-remediation engine
* [ ] Frida dynamic enrichment

---

**BluJay is not just another SAST tool. It is a security engineer’s co-pilot.**