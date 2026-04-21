from datetime import datetime

from pydantic import BaseModel, field_validator


class ProxyFlowOut(BaseModel):
    id: str
    session_id: int
    timestamp: datetime
    method: str
    url: str
    host: str
    path: str
    request_headers: str  # JSON string
    response_status: int | None
    response_headers: str | None  # JSON string
    tls: bool
    content_type: str | None
    duration_ms: float | None

    model_config = {"from_attributes": True}


class ProxyFlowDetail(ProxyFlowOut):
    request_body: str | None
    response_body: str | None

    @field_validator('request_body', 'response_body', mode='before')
    @classmethod
    def decode_body(cls, v: bytes | str | None) -> str | None:
        if isinstance(v, bytes):
            return v.decode('utf-8', errors='replace')
        return v


class FlowsResponse(BaseModel):
    total: int
    items: list[ProxyFlowOut]


class ProxyStartRequest(BaseModel):
    port: int = 8080
    session_id: int = 0  # 0 = standalone (no DynamicSession required)


class ReplayResult(BaseModel):
    status_code: int
    headers: dict
    body: str


class RepeaterRequest(BaseModel):
    method: str
    url: str
    headers: dict[str, str] = {}
    body: str = ""


class RepeaterResult(BaseModel):
    status_code: int
    headers: dict[str, str]
    body: str
    duration_ms: float
