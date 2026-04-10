from pydantic import BaseModel


class DeviceInfo(BaseModel):
    serial: str
    state: str  # device | offline | unauthorized
    product: str | None
    model: str | None
    transport_id: str | None


class InstallResult(BaseModel):
    success: bool
    message: str


class LaunchRequest(BaseModel):
    package_name: str
    activity: str | None = None


class LogcatLine(BaseModel):
    ts: str
    level: str  # V D I W E F
    tag: str
    message: str
    pid: str | None = None
