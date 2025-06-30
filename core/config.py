import json
import os

RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "rules")


def load_owasp_rules():
    owasp_path = os.path.join(RULES_DIR, "owasp_top10.json")
    with open(owasp_path, "r") as f:
        return json.load(f)


def get_taint_sources(lang):
    rules = load_owasp_rules()
    sources = set()
    for rule in rules.values():
        if "sources" in rule:
            sources.update(rule["sources"])
    return sources


def get_taint_sinks(lang):
    rules = load_owasp_rules()
    sinks = set()
    for rule in rules.values():
        if "sinks" in rule:
            sinks.update(rule["sinks"])
    return sinks