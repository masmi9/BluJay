"""
Async client for the MobSF REST API.
MobSF must be running separately (Docker recommended: https://github.com/MobSF/Mobile-Security-Framework-MobSF).
Default URL: http://localhost:8008  API key shown on MobSF home page.
"""
from pathlib import Path

import httpx


class MobSFClient:
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip("/")
        self._headers = {"Authorization": api_key}

    async def is_reachable(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=3) as client:
                r = await client.get(f"{self.base_url}/api/v1/scans", headers=self._headers)
                return r.status_code < 500
        except Exception:
            return False

    async def upload(self, apk_path: Path) -> dict:
        async with httpx.AsyncClient(timeout=60) as client:
            with open(apk_path, "rb") as f:
                r = await client.post(
                    f"{self.base_url}/api/v1/upload",
                    headers=self._headers,
                    files={"file": (apk_path.name, f, "application/octet-stream")},
                )
            r.raise_for_status()
            return r.json()

    async def scan(self, scan_type: str, file_name: str, scan_hash: str) -> dict:
        async with httpx.AsyncClient(timeout=120) as client:
            r = await client.post(
                f"{self.base_url}/api/v1/scan",
                headers=self._headers,
                data={"scan_type": scan_type, "file_name": file_name, "hash": scan_hash},
            )
            r.raise_for_status()
            return r.json()

    async def report_json(self, scan_hash: str) -> dict:
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.post(
                f"{self.base_url}/api/v1/report_json",
                headers=self._headers,
                data={"hash": scan_hash},
            )
            r.raise_for_status()
            return r.json()
