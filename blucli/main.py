import argparse
from core.analyzer import Analyzer
from core.reporter import Reporter


def main():
    parser = argparse.ArgumentParser(description="BluJay - Static Analysis Tool")
    parser.add_argument("--input", required=True, help="Path to source code directory")
    parser.add_argument("--lang", choices=["python", "java"], required=True, help="Programming language")
    parser.add_argument("--output", required=True, help="Output report file path (.csv or .json)")
    args = parser.parse_args()

    analyzer = Analyzer(language=args.lang)
    results = analyzer.run(args.input)

    reporter = Reporter(output_file=args.output)
    reporter.generate(results)


if __name__ == "__main__":
    main()