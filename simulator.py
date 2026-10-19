"""Deterministic synthetic events for a repeatable hackathon demo."""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timezone

import detector
import policy

NORMAL = [
    ("example.com", 443, 2_400),
    ("api.github.com", 443, 8_200),
    ("pypi.org", 443, 1_200),
]
SUSPICIOUS = [
    ("203.0.113.50", 4444, 5_000_000),
    ("collector.exfil.example", 443, 1_800_000),
    ("api.github.com", 8080, 3_000),
]


def make_event(host: str, port: int, size: int, container: str = "attendance-api") -> dict:
    event = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "container": container,
        "dest_host": host,
        "dest_port": port,
        "protocol": "TCP",
        "bytes_out": size,
        "bytes_attempted": size,
        "source": "simulator",
        "outcome": "simulated",
    }
    event["action"] = policy.action_for(event)
    return event


def generate_normal(count: int = 5) -> list[dict]:
    events = [make_event(*random.choice(NORMAL)) for _ in range(max(1, min(count, 100)))]
    for event in events:
        detector.append_event(event)
    return events


def generate_suspicious() -> list[dict]:
    events = [make_event(*item) for item in SUSPICIOUS]
    for event in events:
        detector.append_event(event)
    return events
