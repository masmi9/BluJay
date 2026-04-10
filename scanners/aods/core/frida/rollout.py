#!/usr/bin/env python3
from __future__ import annotations

import os
from hashlib import blake2b


def _stable_float(seed: str, key: str) -> float:
    h = blake2b(f"{seed}:{key}".encode("utf-8"), digest_size=8).digest()
    # map 8 bytes to 0..1
    val = int.from_bytes(h, "big")
    return (val % (1 << 64)) / float(1 << 64)


def should_route_to_ml(percent: int | float, key: str) -> bool:
    try:
        p = float(percent)
    except Exception:
        p = 0.0
    p = max(0.0, min(100.0, p))
    seed = os.environ.get("AODS_FRIDA_PLANNER_SEED", "0")
    return _stable_float(str(seed), key) < (p / 100.0)
