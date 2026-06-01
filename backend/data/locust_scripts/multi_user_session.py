"""
Locust — Multi-User Session Load Test
Scenario: independent authenticated sessions per virtual user.
Each user logs in, acquires a session token, then makes authenticated requests.

Env vars (set by BluJay perf runner):
  TARGET_URL        full endpoint URL to stress (required)
  LOGIN_ENDPOINT    login path (default /api/auth/login)
  USERNAME_PREFIX   prefix for generated usernames (default "user")
  PASSWORD          shared password (default "password123")
  SESSION_COUNT     number of distinct user accounts to cycle (default 5)
"""
import os
from urllib.parse import urlparse

from locust import HttpUser, between, task

TARGET_URL    = os.getenv("TARGET_URL", "http://localhost:8000/api/test")
LOGIN_PATH    = os.getenv("LOGIN_ENDPOINT", "/api/auth/login")
USERNAME_PFX  = os.getenv("USERNAME_PREFIX", "user")
PASSWORD      = os.getenv("PASSWORD", "password123")
SESSION_COUNT = int(os.getenv("SESSION_COUNT", "5"))
TARGET_PATH   = urlparse(TARGET_URL).path or "/api/test"

_counter = 0


class SessionUser(HttpUser):
    wait_time = between(0.5, 2)

    def on_start(self):
        global _counter
        idx = _counter % SESSION_COUNT
        _counter += 1
        username = f"{USERNAME_PFX}{idx}"

        resp = self.client.post(
            LOGIN_PATH,
            json={"username": username, "password": PASSWORD},
            name="[auth] login",
        )
        if resp.status_code == 200:
            data = resp.json()
            token = data.get("access_token") or data.get("token") or ""
            if token:
                self.client.headers["Authorization"] = f"Bearer {token}"
            # also carry cookies automatically via self.client session
        # intentionally non-fatal — test proceeds even without valid creds
        # to measure how the API handles unauthenticated load

    @task(3)
    def read_resource(self):
        self.client.get(TARGET_PATH)

    @task(1)
    def write_resource(self):
        self.client.post(TARGET_PATH, json={"test": True, "source": "locust"})
