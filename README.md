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
- 🤖 Optional **AI Validation Layer** to reduce false positives, prioritize real issues, and provide quick context
- ⚙️ Easy project-level configuration with `.blujay.yml`

## 🚀 Getting Started

```bash
pip install -e .
blujay scan --input ./src --lang python --output ./report.csv
```

## ⚙️ Configuration

You can customize BluJay using a `.blujay.yml` file at the root of your project:

```bash
ai:
    enabled: true
    provider: dry_run
    model: gpt-4o-mini
    threshold: 0.75
scan:
    max_findings: 2000
    languages: [java, python]
report:
    formats: [json, csv]
    output_dir: reports/
```

- Place `.blujay.yml` in your project root.
- CLI flags will override config file settings.
- This makes it simple to share consistent scan settings across your team.

## 🧠 AI Validation Layer

BluJay can optionally use AI to help filter and explain findings:
- Supports `openai`, `anthropic`, `ollama`, or a built-in `dry_run` heuristic mode
- Adds a confidence score and quick explanation to each finding
- Helps teams spend less time on false positives and more time fixing real issues
