from pydantic import BaseModel


class EntitlementInfo(BaseModel):
    key: str
    value: str
    risk_level: str   # critical | high | medium | low | info
    description: str


class IpaSummary(BaseModel):
    analysis_id: int
    bundle_id: str | None
    min_ios_version: str | None
    ats_config: dict
    entitlements: list[EntitlementInfo]
    platform: str
