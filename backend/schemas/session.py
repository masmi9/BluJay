from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class DynamicSessionCreate(BaseModel):
    analysis_id: Optional[int] = None
    device_serial: str        # ADB serial for Android; UDID for iOS
    package_name: str
    platform: str = "android"  # android | ios


class DynamicSessionOut(BaseModel):
    id: int
    analysis_id: Optional[int]
    created_at: datetime
    device_serial: str
    package_name: str
    platform: str
    status: str
    proxy_port: Optional[int]
    frida_attached: bool

    model_config = {"from_attributes": True}
