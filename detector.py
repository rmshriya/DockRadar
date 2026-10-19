"""JSONL ingest and SQLite history for EgressEye."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import policy as policy_engine

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("EGRESSEYE_DATA_DIR", BASE_DIR / "data"))
EVENTS_FILE = DATA_DIR / "events.jsonl"
DB_FILE = DATA_DIR / "egresseye.db"
EVENT_LOCK = threading.Lock()

CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    container TEXT NOT NULL,
    dest_host TEXT NOT NULL,
    dest_port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    bytes_out INTEGER NOT NULL,
    bytes_attempted INTEGER NOT NULL,
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    reason TEXT NOT NULL,
    action TEXT NOT NULL,
    outcome TEXT NOT NULL,
    source TEXT NOT NULL
)
"""


@contextlib.contextmanager
def database():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_FILE, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute(CREATE_TABLE)
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def normalize_event(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    try:
        host = policy_engine.normalize_host(raw.get("dest_host"), allow_wildcard=False)
        port = int(raw.get("dest_port"))
        sent = int(raw.get("bytes_out", 0))
        attempted = int(raw.get("bytes_attempted", sent))
    except (TypeError, ValueError):
        return None
    if not (1 <= port <= 65535) or sent < 0 or attempted < sent:
        return None
    event_id = str(raw.get("id") or hashlib.sha256(json.dumps(raw, sort_keys=True).encode()).hexdigest())[:100]
    try:
        timestamp = str(raw.get("timestamp") or datetime.now(timezone.utc).isoformat(timespec="seconds"))[:64]
        # Validate but preserve the original timezone/format for display.
        datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return {
        "id": event_id,
        "timestamp": timestamp,
        "container": str(raw.get("container") or "unknown")[:120],
        "dest_host": host,
        "dest_port": port,
        "protocol": str(raw.get("protocol") or "TCP").upper()[:12],
        "bytes_out": sent,
        "bytes_attempted": attempted,
        "source": str(raw.get("source") or "proxy")[:30],
        "outcome": str(raw.get("outcome") or "observed")[:40],
        "action": str(raw.get("action") or "")[:12].upper(),
    }


def append_event(raw: dict[str, Any]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    event = dict(raw)
    event.setdefault("id", str(uuid.uuid4()))
    event.setdefault("timestamp", datetime.now(timezone.utc).isoformat(timespec="seconds"))
    with EVENT_LOCK, EVENTS_FILE.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(event, separators=(",", ":")) + "\n")


def process_events() -> dict[str, int]:
    if not EVENTS_FILE.exists():
        return {"new": 0, "malformed": 0}
    policy = policy_engine.load_policy()
    new = malformed = 0
    with database() as connection, EVENTS_FILE.open("r", encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            try:
                event = normalize_event(json.loads(line))
            except (json.JSONDecodeError, UnicodeDecodeError):
                event = None
            if event is None:
                malformed += 1
                continue
            result = policy_engine.classify_event(event, policy)
            action = event["action"] or (
                "BLOCK" if policy["mode"] == "block" and result["status"] == "ALERT" else "ALLOW"
            )
            cursor = connection.execute(
                """INSERT OR IGNORE INTO events
                (id,timestamp,container,dest_host,dest_port,protocol,bytes_out,bytes_attempted,
                 status,severity,reason,action,outcome,source)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (event["id"], event["timestamp"], event["container"], event["dest_host"],
                 event["dest_port"], event["protocol"], event["bytes_out"], event["bytes_attempted"],
                 result["status"], result["severity"], "; ".join(result["reasons"]), action,
                 event["outcome"], event["source"]),
            )
            new += cursor.rowcount
    return {"new": new, "malformed": malformed}


def reanalyze_all() -> None:
    policy = policy_engine.load_policy()
    with database() as connection:
        rows = connection.execute("SELECT * FROM events").fetchall()
        for row in rows:
            event = dict(row)
            result = policy_engine.classify_event(event, policy)
            connection.execute(
                "UPDATE events SET status=?,severity=?,reason=? WHERE id=?",
                (result["status"], result["severity"], "; ".join(result["reasons"]), event["id"]),
            )


def get_events(limit: int = 2000) -> list[dict[str, Any]]:
    with database() as connection:
        rows = connection.execute(
            "SELECT * FROM events ORDER BY timestamp DESC, rowid DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(row) for row in rows]


def clear_history() -> None:
    with database() as connection:
        connection.execute("DELETE FROM events")
    if EVENTS_FILE.exists():
        EVENTS_FILE.write_text("", encoding="utf-8")
