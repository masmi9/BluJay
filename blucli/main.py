import argparse
from core.analyzer import Analyzer
from core.reporter import Reporter
from colorama import Fore, init

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