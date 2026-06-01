"""
Locust — OAuth2 Token Acquisition + Refresh Under Load
Scenario: every user independently acquires an access token via client_credentials,
uses it for API calls, and re-acquires when it ages past REFRESH_EVERY seconds.

Env vars:
  TARGET_URL       API endpoint to hit after token acquisition (required)
  TOKEN_ENDPOINT   OAuth token path (default /oauth/token)
  CLIENT_ID        OAuth client id (default test_client)
  CLIENT_SECRET    OAuth client secret (default test_secret)
  SCOPE            requested scope (default "read write")
  REFRESH_EVERY    seconds before proactive token refresh (default 60)
"""
import os
import time
from urllib.parse import urlparse

from locust import HttpUser, between, task

TARGET_URL     = os.getenv("TARGET_URL", "http://localhost:8000/api/resource")
TOKEN_ENDPOINT = os.getenv("TOKEN_ENDPOINT", "/oauth/token")
CLIENT_ID      = os.getenv("CLIENT_ID", "test_client")
CLIENT_SECRET  = os.getenv("CLIENT_SECRET", "test_secret")
SCOPE          = os.getenv("SCOPE", "read write")
REFRESH_EVERY  = int(os.getenv("REFRESH_EVERY", "60"))
TARGET_PATH    = urlparse(TARGET_URL).path or "/api/resource"


class OAuthUser(HttpUser):
    wait_time = between(1, 3)

    def on_start(self):
        self._acquire_token()
        self._token_at = time.monotonic()

    def _acquire_token(self):
        resp = self.client.post(
            TOKEN_ENDPOINT,
            data={
                "grant_type": "client_credentials",
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "scope": SCOPE,
            },
            name="[oauth] token",
        )
        if resp.status_code == 200:
            token = resp.json().get("access_token", "")
            self.client.headers["Authorization"] = f"Bearer {token}"

    def _maybe_refresh(self):
        if time.monotonic() - self._token_at > REFRESH_EVERY:
            self._acquire_token()
            self._token_at = time.monotonic()

    @task(5)
    def access_resource(self):
        self._maybe_refresh()
        self.client.get(TARGET_PATH)

    @task(1)
    def force_refresh(self):
        self._acquire_token()
        self._token_at = time.monotonic()
