import argparse
import sys, json
from colorama import Fore, init

from core.analyzer import Analyzer
from core.reporter import Reporter
from core.config import load_config
from core.ai.validator import AIValidator

def print_banner():
    init(autoreset=True)
    banner = f"""{Fore.BLUE}
    $$$$$$$\  $$\       $$\   $$\    $$$$$\  $$$$$$\  $$\     $$\ 
    $$  __$$\ $$ |      $$ |  $$ |   \__$$ |$$  __$$\ \$$\   $$  |
    $$ |  $$ |$$ |      $$ |  $$ |      $$ |$$ /  $$ | \$$\ $$  / 
    $$$$$$$\ |$$ |      $$ |  $$ |      $$ |$$$$$$$$ |  \$$$$  /  
    $$  __$$\ $$ |      $$ |  $$ |$$\   $$ |$$  __$$ |   \$$  /   
    $$ |  $$ |$$ |      $$ |  $$ |$$ |  $$ |$$ |  $$ |    $$ |    
    $$$$$$$  |$$$$$$$$\ \$$$$$$  |\$$$$$$  |$$ |  $$ |    $$ |    
    \_______/ \________| \______/  \______/ \__|  \__|    \__|

    Static Analysis | OWASP Top 10 | CVSS | Taint Tracking | Java & Python
"""
    print(banner)

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="BluJay - Static Analysis Tool")
    # scan args
    parser.add_argument("--input", required=True, help="Path to source code directory")
    parser.add_argument("--lang", choices=["python", "java"], required=True, help="Programming language")
    parser.add_argument("--output", required=True, help="Output report file path (.csv or .json)")
    parser.add_argument("--format", choices=["csv", "json"], default=None, help="Output report format")

    # AI args (flags override config)
    parser.add_argument("--ai-validate", action="store_true")
    parser.add_argument("--ai-provider", default="dry_run", choices=["dry_run", "openai", "anthropic", "ollama"], help="AI provider to use")
    parser.add_argument("--ai-model", default=None)
    parser.add_argument("--ai-threshold", type=float, default=0.65, help="Confidence threshold for AI validation")
    
    args = parser.parse_args()

    # load config (from .blujay.yml if exists)
    config = load_config()

    # Resolve report format: flag > config > infer from output file
    fmt = (
        args.format 
        or (config.get("report", {}).get("formats", [None])[0])   
        or (args.output.rsplit(".", 1)[-1] if "." in args.output else None) 
        or "json"
    )

    # Run analysis
    analyzer = Analyzer()    
    findings = Analyzer.analyze(input_path=args.input, language=args.lang)
    
    # Decide if AI should run (flag OR config)
    ai_config = config.get("ai", {}) or {}
    run_ai = args.ai_validate or ai_config.get("enabled", False)
    
    if run_ai:
        provider = args.ai_provider or ai_config.get("provider", "dry_run")
        model = args.ai_model or ai_config.get("model", "gpt-4o-mini")
        threshold = (
            args.ai_threshold
            if args.ai_threshold is not None
            else float(ai_config.get("threshold", 0.65))
        )
        validator = AIValidator(provider=provider, model=model, threshold=threshold)
        findings = validator.validate_findings(findings, language=args.lang)

    # Write report
    Reporter().write(findings, output_path=args.output, format=fmt)

if __name__ == "__main__":
    main()