from datetime import datetime
from pydantic import BaseModel

class JwtTestCreate(BaseModel):
    token: str
    session_id: int | None = None
    analysis_id: int | None = None
    wordlist: str | None = None  # path override; defaults to bundled jwt_secrets.txt

class JwtTestOut(BaseModel):
    id: int
    created_at: datetime
    session_id: int | None
    analysis_id: int | None
    raw_token: str
    decoded_header: str | None
    decoded_payload: str | None
    alg_none_token: str | None
    hmac_secret_found: str | None
    rs256_hs256_token: str | None
    kid_injection_payloads: str | None
    role_escalation_tokens: str | None
    notes: str | None

    model_config = {"from_attributes": True}


class JwtBruteForceResult(BaseModel):
    found: bool
    secret: str | None
    tested_count: int
    error: str | None = None

class JwtDecodeResult(BaseModel):
    header: dict
    payload: dict
    alg_none_token: str
    kid_tokens: list[str]
    role_tokens: list[str]
