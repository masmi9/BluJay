"""
GraphQL security testing — introspection, batching, field suggestions, injection.
"""
import json
import re

import httpx
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()


class GraphQLTestRequest(BaseModel):
    url: str
    headers: dict[str, str] = {}
    test_introspection: bool = True
    test_batching: bool = True
    test_field_suggestions: bool = True
    test_injection: bool = True
    test_auth_bypass: bool = True
    timeout: float = 15.0


_INTROSPECTION = {
    "query": """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        types { name kind fields { name type { name kind } } }
      }
    }"""
}

_BATCH_PAYLOAD = [
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
]

_FIELD_SUGGEST_QUERY = {"query": "{ users { passwordHash } }"}

_INJECTION_PAYLOADS = [
    {"query": '{ user(id: "1 OR 1=1") { id email } }'},
    {"query": '{ user(id: "1; DROP TABLE users--") { id } }'},
    {"query": '{ search(q: "<script>alert(1)</script>") { result } }'},
]

_ALIAS_OVERLOAD = {"query": " ".join([f'a{i}: __typename' for i in range(100)]).join(["{", "}"])}

_AUTH_BYPASS_MUTATIONS = [
    {"query": "mutation { createUser(role: \"admin\", email: \"pwn@test.com\", password: \"pwn\") { id } }"},
    {"query": "mutation { resetPassword(email: \"admin@app.com\") { token } }"},
]


async def _gql(client: httpx.AsyncClient, url: str, headers: dict, payload) -> dict:
    try:
        r = await client.post(url, json=payload, headers=headers)
        return {"status": r.status_code, "body": r.text[:2000], "error": None}
    except Exception as e:
        return {"status": None, "body": None, "error": str(e)}


def _has_data(body: str | None) -> bool:
    if not body:
        return False
    try:
        d = json.loads(body)
        return "data" in d and d["data"] is not None
    except Exception:
        return False


def _has_errors(body: str | None) -> bool:
    if not body:
        return False
    return '"errors"' in body


def _extract_types(body: str | None) -> list[str]:
    if not body:
        return []
    try:
        d = json.loads(body)
        types = d.get("data", {}).get("__schema", {}).get("types", [])
        return [t["name"] for t in types if t and not t["name"].startswith("__")]
    except Exception:
        return []


@router.post("/test")
async def test_graphql(req: GraphQLTestRequest):
    findings = []
    details: dict = {}

    async with httpx.AsyncClient(verify=False, timeout=req.timeout) as client:

        # Is this actually a GraphQL endpoint?
        probe = await _gql(client, req.url, req.headers, {"query": "{ __typename }"})
        if probe["error"] or not _has_data(probe["body"]):
            return {
                "url": req.url,
                "is_graphql": False,
                "findings": [],
                "details": {"probe": probe},
            }
        details["probe"] = probe

        # Introspection
        if req.test_introspection:
            r = await _gql(client, req.url, req.headers, _INTROSPECTION)
            types = _extract_types(r["body"])
            details["introspection"] = {"status": r["status"], "types": types[:40]}
            if types:
                findings.append({
                    "severity": "medium",
                    "title": "GraphQL introspection is enabled",
                    "detail": f"Schema exposed {len(types)} types: {', '.join(types[:10])}...",
                    "recommendation": "Disable introspection in production with `introspection: false`.",
                })

                sensitive_types = [t for t in types if any(
                    kw in t.lower() for kw in ("admin", "user", "password", "secret", "token", "auth", "internal")
                )]
                if sensitive_types:
                    findings.append({
                        "severity": "high",
                        "title": "Sensitive type names exposed via introspection",
                        "detail": f"Types: {', '.join(sensitive_types)}",
                    })

        # Batching
        if req.test_batching:
            r = await _gql(client, req.url, req.headers, _BATCH_PAYLOAD)
            details["batching"] = {"status": r["status"]}
            if r["status"] == 200 and _has_data(r["body"]):
                findings.append({
                    "severity": "medium",
                    "title": "GraphQL batching is enabled",
                    "detail": "Multiple queries accepted in a single request. Can be abused for brute-force / DoS.",
                    "recommendation": "Limit batch size or disable batching.",
                })

        # Alias overload (DoS)
        r_alias = await _gql(client, req.url, req.headers, _ALIAS_OVERLOAD)
        details["alias_overload"] = {"status": r_alias["status"]}
        if r_alias["status"] == 200 and _has_data(r_alias["body"]):
            findings.append({
                "severity": "medium",
                "title": "GraphQL alias overloading accepted (potential DoS)",
                "detail": "100-alias query executed without rejection. No query complexity limits detected.",
            })

        # Field suggestions (schema leakage via typos)
        if req.test_field_suggestions:
            r = await _gql(client, req.url, req.headers, _FIELD_SUGGEST_QUERY)
            body = r["body"] or ""
            if "Did you mean" in body or "suggestion" in body.lower():
                suggestions = re.findall(r'"Did you mean "([^"]+)"', body)
                findings.append({
                    "severity": "low",
                    "title": "GraphQL field suggestions leak schema information",
                    "detail": f"Typo queries return field suggestions: {suggestions[:5]}",
                    "recommendation": "Disable field suggestions in production.",
                })
            details["field_suggestions"] = {"body_snippet": body[:300]}

        # Injection
        if req.test_injection:
            injection_hits = []
            for p in _INJECTION_PAYLOADS:
                r = await _gql(client, req.url, req.headers, p)
                if _has_data(r["body"]) or (r["body"] and "error" not in r["body"].lower()):
                    injection_hits.append(p["query"][:80])
            if injection_hits:
                findings.append({
                    "severity": "high",
                    "title": "GraphQL injection payload returned data",
                    "detail": f"Payloads that returned data: {injection_hits}",
                })
            details["injection"] = {"hits": injection_hits}

        # Auth bypass mutations
        if req.test_auth_bypass:
            bypass_hits = []
            for p in _AUTH_BYPASS_MUTATIONS:
                r = await _gql(client, req.url, req.headers, p)
                if r["status"] == 200 and _has_data(r["body"]):
                    bypass_hits.append(p["query"][:80])
            if bypass_hits:
                findings.append({
                    "severity": "critical",
                    "title": "Unauthenticated mutation succeeded",
                    "detail": f"Mutations that returned data without auth: {bypass_hits}",
                })
            details["auth_bypass"] = {"hits": bypass_hits}

    return {
        "url": req.url,
        "is_graphql": True,
        "findings": findings,
        "finding_count": len(findings),
        "details": details,
    }
