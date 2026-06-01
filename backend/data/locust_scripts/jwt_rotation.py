"""
Locust — JWT Rotation Under Concurrent Load
Scenario: users log in, use their JWT for requests, and rotate via refresh
token on a timer. Confirms whether concurrent rotation causes race conditions,
double-spend on refresh tokens, or token invalidation edge cases.

Env vars:
  TARGET_URL          endpoint to stress after login (required)
  LOGIN_ENDPOINT      login path (default /api/auth/login)
  REFRESH_ENDPOINT    refresh path (default /api/auth/refresh)
  USERNAME            test account username (default test@example.com)
  PASSWORD            test account password (default password123)
  ROTATE_EVERY        seconds between forced JWT rotations (default 30)
"""
import os
import time
from urllib.parse import urlparse

from locust import HttpUser, between, task

TARGET_URL       = os.getenv("TARGET_URL", "http://localhost:8000/api/protected")
LOGIN_ENDPOINT   = os.getenv("LOGIN_ENDPOINT", "/api/auth/login")
REFRESH_ENDPOINT = os.getenv("REFRESH_ENDPOINT", "/api/auth/refresh")
USERNAME         = os.getenv("USERNAME", "test@example.com")
PASSWORD         = os.getenv("PASSWORD", "password123")
ROTATE_EVERY     = int(os.getenv("ROTATE_EVERY", "30"))
TARGET_PATH      = urlparse(TARGET_URL).path or "/api/protected"


class JwtUser(HttpUser):
    wait_time = between(0.5, 1.5)

    def on_start(self):
        self.jwt = None
        self.refresh_token = None
        self._issued_at = time.monotonic()
        self._login()

    def _login(self):
        resp = self.client.post(
            LOGIN_ENDPOINT,
            json={"username": USERNAME, "password": PASSWORD},
            name="[jwt] login",
        )
        if resp.status_code == 200:
            data = resp.json()
            self.jwt = data.get("access_token") or data.get("token")
            self.refresh_token = data.get("refresh_token")
            if self.jwt:
                self.client.headers["Authorization"] = f"Bearer {self.jwt}"
            self._issued_at = time.monotonic()

    def _rotate(self):
        if not self.refresh_token:
            self._login()
            return
        resp = self.client.post(
            REFRESH_ENDPOINT,
            json={"refresh_token": self.refresh_token},
            name="[jwt] rotate",
        )
        if resp.status_code == 200:
            data = resp.json()
            self.jwt = data.get("access_token", self.jwt)
            self.refresh_token = data.get("refresh_token", self.refresh_token)
            if self.jwt:
                self.client.headers["Authorization"] = f"Bearer {self.jwt}"
            self._issued_at = time.monotonic()
        else:
            # Refresh rejected — re-login to get fresh tokens
            self._login()

    def _maybe_rotate(self):
        if time.monotonic() - self._issued_at > ROTATE_EVERY:
            self._rotate()

    @task(4)
    def hit_protected(self):
        self._maybe_rotate()
        self.client.get(TARGET_PATH)

    @task(1)
    def force_rotate(self):
        self._rotate()
