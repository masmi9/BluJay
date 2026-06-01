"""
Locust — Chained API Sequence (CRUD Flow)
Scenario: each virtual user executes a full create → read → update → delete
lifecycle. Tests stateful API workflows where later calls depend on prior
responses — a pattern k6 can't model cleanly without complex state sharing.

Env vars:
  TARGET_URL    base resource endpoint (required) e.g. http://host/api/items
  AUTH_TOKEN    Bearer token (optional)
  CREATE_BODY   JSON string for POST body (default {"name":"locust","value":"test"})
  ID_FIELD      key in the create response that holds the resource ID (default "id")
"""
import json
import os
from urllib.parse import urlparse

from locust import HttpUser, SequentialTaskSet, between, task

TARGET_URL  = os.getenv("TARGET_URL", "http://localhost:8000/api/items")
AUTH_TOKEN  = os.getenv("AUTH_TOKEN", "")
_raw_body   = os.getenv("CREATE_BODY", '{"name":"locust","value":"test"}')
ID_FIELD    = os.getenv("ID_FIELD", "id")
BASE_PATH   = urlparse(TARGET_URL).path or "/api/items"

try:
    CREATE_BODY = json.loads(_raw_body)
except Exception:
    CREATE_BODY = {"name": "locust", "value": "test"}


class CRUDSequence(SequentialTaskSet):
    def on_start(self):
        self.resource_id = None
        if AUTH_TOKEN:
            self.user.client.headers["Authorization"] = f"Bearer {AUTH_TOKEN}"

    @task
    def create(self):
        resp = self.client.post(BASE_PATH, json=CREATE_BODY, name=f"POST {BASE_PATH}")
        if resp.status_code in (200, 201):
            try:
                self.resource_id = resp.json().get(ID_FIELD)
            except Exception:
                self.resource_id = None

    @task
    def read(self):
        if self.resource_id is not None:
            self.client.get(f"{BASE_PATH}/{self.resource_id}", name=f"GET {BASE_PATH}/:id")
        else:
            self.client.get(BASE_PATH, name=f"GET {BASE_PATH}")

    @task
    def update(self):
        if self.resource_id is None:
            return
        updated = {**CREATE_BODY, "name": "locust_updated"}
        self.client.put(
            f"{BASE_PATH}/{self.resource_id}",
            json=updated,
            name=f"PUT {BASE_PATH}/:id",
        )

    @task
    def delete(self):
        if self.resource_id is None:
            return
        self.client.delete(
            f"{BASE_PATH}/{self.resource_id}",
            name=f"DELETE {BASE_PATH}/:id",
        )
        self.resource_id = None


class ApiSequenceUser(HttpUser):
    tasks = [CRUDSequence]
    wait_time = between(0.5, 2)

    def on_start(self):
        if AUTH_TOKEN:
            self.client.headers["Authorization"] = f"Bearer {AUTH_TOKEN}"
