from datetime import datetime

from pydantic import BaseModel


class AnalysisCreate(BaseModel):
    pass  # APK uploaded as multipart form, no JSON body needed


class AnalysisSummary(BaseModel):
    id: int
    created_at: datetime
    apk_filename: str
    apk_sha256: str
    package_name: str | None
    version_name: str | None
    version_code: int | None
    min_sdk: int | None
    target_sdk: int | None
    platform: str = "android"
    bundle_id: str | None = None
    min_ios_version: str | None = None
    status: str
    error_message: str | None

    model_config = {"from_attributes": True}


class AnalysisDetail(AnalysisSummary):
    decompile_path: str | None
    jadx_path: str | None


class StaticFindingOut(BaseModel):
    id: int
    analysis_id: int
    category: str
    severity: str
    title: str
    description: str
    file_path: str | None
    line_number: int | None
    evidence: str | None
    rule_id: str | None
    # Enriched fields — computed at query time, not stored in DB
    impact: str | None = None
    attack_path: str | None = None

    model_config = {"from_attributes": True}


class FindingsResponse(BaseModel):
    total: int
    items: list[StaticFindingOut]


class PermissionInfo(BaseModel):
    name: str
    short_name: str
    protection_level: str  # normal | dangerous | signature | signatureOrSystem
    description: str
    risk: str  # none | low | medium | high | critical


class ComponentInfo(BaseModel):
    name: str
    type: str  # activity | service | receiver | provider
    exported: bool
    permission: str | None
    intent_filters: list[dict]


class ParsedManifest(BaseModel):
    package_name: str
    version_name: str | None
    version_code: int | None
    min_sdk: int | None
    target_sdk: int | None
    debuggable: bool
    allow_backup: bool
    network_security_config: bool
    uses_cleartext_traffic: bool | None
    permissions: list[str]
    components: list[ComponentInfo]


class SourceEntry(BaseModel):
    path: str
    is_dir: bool
    size: int | None


class ProgressEvent(BaseModel):
    type: str = "progress"
    stage: str
    pct: int
    message: str
