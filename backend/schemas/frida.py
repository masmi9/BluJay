from datetime import datetime

from pydantic import BaseModel


class FridaScriptInfo(BaseModel):
    name: str
    filename: str
    description: str
    hooks: list[str]


class FridaAttachRequest(BaseModel):
    device_serial: str
    package_name: str
    session_id: int  # DynamicSession id


class FridaLoadScriptRequest(BaseModel):
    builtin_name: str | None = None  # name from /frida/scripts list
    source: str | None = None        # raw JS — one of these must be set


class FridaScriptLoaded(BaseModel):
    script_id: str
    name: str


class FridaEventOut(BaseModel):
    id: int
    session_id: int
    timestamp: datetime
    event_type: str
    script_name: str | None
    payload: str  # JSON

    model_config = {"from_attributes": True}


class FridaEventsResponse(BaseModel):
    total: int
    items: list[FridaEventOut]
