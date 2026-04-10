from pydantic import BaseModel


class IosDeviceInfo(BaseModel):
    udid: str
    name: str | None
    model: str | None
    ios_version: str | None
    jailbroken: bool
