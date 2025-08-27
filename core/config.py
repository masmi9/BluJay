import json
import os, yaml

RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "rules")

def load_config():
    path = find_config_file()
    if not path:
        return {}
    with open(path, "r") as f:
        # Always return safe_load for security
        return yaml.safe_load(f) or {}
    

def find_config_file():
    cwd = os.getcwd()
    while True:
        candidate = os.path.join(cwd, ".blujay.yml")
        if os.path.isfile(candidate):
            return candidate
        parent = os.path.dirname(cwd)
        if parent == cwd: # reached root
            return None
        cwd = parent


def get_ai_config(cfg):
    ai = cfg.get("ai", {}) or {}
    return {
        "enabled": bool(ai.get("enabled", False)),
        "provider": str(ai.get("provider", "dry_run")),
        "model": str(ai.get("model", "gpt-4o-mini")),
        "threshold": float(ai.get("threshold", 0.65)),
    }


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