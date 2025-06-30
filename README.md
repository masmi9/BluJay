# BluJay - Static Application Security Testing (SAST) Framework

**BluJay** is a high-accuracy, extensible SAST tool designed to analyze Java and Python source code and binaries without execution. It performs automated source code reviews using AST-based and taint-aware analysis to detect the most critical vulnerabilities — starting with the OWASP Top Ten.

BluJay is developer-friendly and CI/CD-ready, producing findings in `.csv`, `.json`, and professional pentest report formats.

## ✨ Features
- 🔍 Taint analysis engine for tracking untrusted input to dangerous sinks
- ⚙️ Language support: Java, Python (more coming soon)
- 📦 Binary support: `.jar`, `.pyc`, `.class` (bytecode-level parsing)
- 📊 Output formats: `.csv`, `.json`, `.docx` (pentest-ready)
- 🔁 CLI and CI/CD compatible
- 🧠 Extensible rules engine for OWASP Top Ten and custom checks

## 🚀 Getting Started
```bash
pip install -e .
blujay scan --input ./src --lang python --output ./report.csv
