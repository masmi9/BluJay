from pydantic import BaseModel


class WebViewFinding(BaseModel):
    rule_id: str
    severity: str
    title: str
    file: str
    line: int
    evidence: str


class WebViewFile(BaseModel):
    index: int
    source: str
    path: str
    size_bytes: int
    findings: list[WebViewFinding]
    bridge_methods: list[str]


class WebViewScanResult(BaseModel):
    analysis_id: int
    files_found: int
    findings_count: int
    files: list[WebViewFile]
