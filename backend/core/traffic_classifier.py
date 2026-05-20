"""Rule-based HTTP traffic type classifier.

Priority order: ai_llm → subsystem → mobile → web → unknown
"""
from __future__ import annotations

import json
import re

_LLM_HOSTS = {
    "api.openai.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "api.mistral.ai",
    "api.cohere.com",
    "api.together.xyz",
    "api.groq.com",
    "api.perplexity.ai",
    "api.deepinfra.com",
    "openrouter.ai",
    "inference.ai",
    "api.replicate.com",
    "api.huggingface.co",
    "router.huggingface.co",
}

_LLM_PATH_FRAGMENTS = (
    "/v1/chat/completions",
    "/v1/completions",
    "/v1/messages",
    "/api/chat",
    "/api/generate",
    "/api/embeddings",
    "/v1/embeddings",
)

_SUBSYSTEM_PORTS = {8000, 8080, 8443, 5000, 3000, 4000, 11434, 5173, 8888}

_MOBILE_UA_PATTERNS = re.compile(
    r"Dalvik|okhttp|CFNetwork|AlamofireSession|Volley|com\.android|retrofit|URLSession",
    re.IGNORECASE,
)

_BROWSER_UA_PATTERNS = re.compile(
    r"Mozilla|Chrome|Safari|Firefox|Edge|Opera|Chromium",
    re.IGNORECASE,
)

_INTERNAL_HOST_RE = re.compile(
    r"^(localhost|127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|.*\.local$|.*\.internal$)",
    re.IGNORECASE,
)


def _is_llm_host(host: str) -> bool:
    host_lower = host.lower().split(":")[0]  # strip port
    if host_lower in _LLM_HOSTS:
        return True
    # Ollama local server pattern
    if host_lower in ("localhost", "127.0.0.1", "0.0.0.0") and ":11434" in host:
        return True
    return False


def _has_llm_path(path: str) -> bool:
    path_lower = path.lower()
    return any(f in path_lower for f in _LLM_PATH_FRAGMENTS)


def _has_messages_body(request_body: str | None) -> bool:
    if not request_body:
        return False
    try:
        data = json.loads(request_body[:4096])
        return isinstance(data, dict) and "messages" in data and isinstance(data["messages"], list)
    except Exception:
        return False


def _is_subsystem(host: str, url: str | None) -> bool:
    host_no_port = host.split(":")[0]
    if _INTERNAL_HOST_RE.match(host_no_port):
        return True
    # Check if URL contains a subsystem port
    if url:
        for port in _SUBSYSTEM_PORTS:
            if f":{port}" in url or f":{port}/" in url:
                return True
    return False


def classify_flow(
    host: str,
    path: str,
    request_headers: dict,
    request_body: str | None,
    url: str | None = None,
) -> str:
    ua = ""
    accept = ""
    for k, v in request_headers.items():
        kl = k.lower()
        if kl == "user-agent":
            ua = str(v)
        elif kl == "accept":
            accept = str(v)

    # 1. AI/LLM — highest priority
    if _is_llm_host(host) or _has_llm_path(path) or _has_messages_body(request_body):
        return "ai_llm"

    # 2. Subsystem (internal services)
    if _is_subsystem(host, url):
        return "subsystem"

    # 3. Mobile — no browser UA, and (mobile UA present OR JSON/protobuf content without HTML accept)
    content_type_header = ""
    for k, v in request_headers.items():
        if k.lower() == "content-type":
            content_type_header = str(v).lower()
    is_mobile_ua = bool(_MOBILE_UA_PATTERNS.search(ua))
    is_browser_ua = bool(_BROWSER_UA_PATTERNS.search(ua))
    accepts_html = "text/html" in accept.lower()
    is_json_or_proto = "json" in content_type_header or "protobuf" in content_type_header or "grpc" in content_type_header

    if is_mobile_ua and not is_browser_ua:
        return "mobile"
    if not is_browser_ua and not accepts_html and is_json_or_proto:
        return "mobile"

    # 4. Web — HTML in accept or browser UA
    if accepts_html or "text/html" in content_type_header or is_browser_ua:
        return "web"

    return "unknown"
