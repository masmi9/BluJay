from datetime import datetime

from pydantic import BaseModel


class DynamicSessionCreate(BaseModel):
    analysis_id: int
    device_serial: str
    package_name: str


class DynamicSessionOut(BaseModel):
    id: int
    analysis_id: int
    created_at: datetime
    device_serial: str
    package_name: str
    status: str
    proxy_port: int | None
    frida_attached: bool

    model_config = {"from_attributes": True}
