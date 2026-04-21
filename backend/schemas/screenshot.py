from datetime import datetime

from pydantic import BaseModel


class CaptureRequest(BaseModel):
    serial: str
    session_id: int
    label: str = ""
    platform: str = "android"   # android | ios


class ScreenshotOut(BaseModel):
    id: int
    session_id: int
    captured_at: datetime
    label: str
    file_path: str
    thumbnail_b64: str

    model_config = {"from_attributes": True}
