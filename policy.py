"""Validated egress policy and destination classification."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent
POLICY_FILE = Path(os.environ.get("EGRESSEYE_POLICY", BASE_DIR / "config" / "policy.json"))
DEFAULT_POLICY: dict[str, Any] = {
    "mode": "block",
    "max_bytes_out": 1_000_000,
    "destinations": [],
}
LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)
SEVERITY_RANK = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def normalize_host(value: Any, *, allow_wildcard: bool = True) -> str:
    """Return a lower-case ASCII hostname/IP or raise ValueError."""
    host = str(value or "").strip().rstrip(".").lower()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    wildcard = host.startswith("*.")
    if wildcard:
        if not allow_wildcard:
            raise ValueError("Wildcards are not valid for a destination event")
        host = host[2:]
    if not host or "*" in host or "/" in host or "@" in host:
        raise ValueError("Enter a hostname, IP address, or *.domain wildcard")
    try:
        normalized = ipaddress.ip_address(host).compressed
        if wildcard:
            raise ValueError("IP addresses cannot use a wildcard")
        return normalized
    except ValueError as exc:
        if "cannot use a wildcard" in str(exc):
            raise
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Hostname is not valid IDNA") from exc
    if len(ascii_host) > 253:
        raise ValueError("Hostname must be 253 characters or fewer")
    labels = ascii_host.split(".")
    if any(not LABEL_RE.fullmatch(label) for label in labels):
        raise ValueError("Hostname contains an invalid label")
    return f"*.{ascii_host}" if wildcard else ascii_host


def validate_policy(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError("Policy must be a JSON object")
    mode = raw.get("mode", "block")
    if mode not in {"block", "monitor"}:
        raise ValueError("Mode must be 'block' or 'monitor'")
    try:
        limit = int(raw.get("max_bytes_out", 1_000_000))
    except (TypeError, ValueError) as exc:
        raise ValueError("Outbound byte limit must be a whole number") from exc
    if limit < 0 or limit > 10**12:
        raise ValueError("Outbound byte limit must be between 0 and 1,000,000,000,000")

    entries = raw.get("destinations", [])
    if not isinstance(entries, list):
        raise ValueError("Destinations must be a list")
    destinations: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("Each destination must be an object")
        host = normalize_host(entry.get("host"))
        if host in seen:
            raise ValueError(f"Duplicate destination: {host}")
        seen.add(host)
        ports_raw = entry.get("ports", [])
        if not isinstance(ports_raw, list) or not ports_raw:
            raise ValueError(f"Add at least one allowed port for {host}")
        ports: set[int] = set()
        for item in ports_raw:
            if isinstance(item, bool):
                raise ValueError(f"Invalid port for {host}")
            try:
                port = int(item)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"Invalid port for {host}") from exc
            if not 1 <= port <= 65535:
                raise ValueError(f"Ports must be between 1 and 65535 for {host}")
            ports.add(port)
        destinations.append({
            "host": host,
            "ports": sorted(ports),
            "note": str(entry.get("note", "")).strip()[:200],
        })
    return {"mode": mode, "max_bytes_out": limit, "destinations": destinations}


def load_policy() -> dict[str, Any]:
    if not POLICY_FILE.exists():
        return validate_policy(DEFAULT_POLICY)
    try:
        return validate_policy(json.loads(POLICY_FILE.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise RuntimeError(f"Could not load egress policy at {POLICY_FILE}: {exc}") from exc


def save_policy(raw: Any) -> dict[str, Any]:
    policy = validate_policy(raw)
    POLICY_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix="policy-", suffix=".json", dir=POLICY_FILE.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(policy, stream, indent=2)
            stream.write("\n")
        os.replace(temporary, POLICY_FILE)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return policy


def destination_matches(host: str, rule_host: str) -> bool:
    if rule_host.startswith("*."):
        suffix = rule_host[1:]  # includes the leading dot
        return host.endswith(suffix) and host != rule_host[2:]
    return host == rule_host


def classify_event(event: dict[str, Any], policy: dict[str, Any] | None = None) -> dict[str, Any]:
    """Classify a destination and transfer size against the supplied policy."""
    policy = validate_policy(policy or load_policy())
    try:
        host = normalize_host(event.get("dest_host"), allow_wildcard=False)
        port = int(event.get("dest_port", 0))
        sent = max(0, int(event.get("bytes_attempted", event.get("bytes_out", 0))))
    except (TypeError, ValueError):
        return {"status": "ALERT", "severity": "HIGH", "reasons": ["Invalid destination event"]}
    if not 1 <= port <= 65535:
        return {"status": "ALERT", "severity": "HIGH", "reasons": ["Invalid destination port"]}

    matches = [d for d in policy["destinations"] if destination_matches(host, d["host"])]
    reasons: list[str] = []
    severity = "NONE"
    if not matches:
        reasons.append(f"Destination {host} is not on the approved list")
        try:
            ipaddress.ip_address(host)
            reasons.append("Destination is a raw IP address")
        except ValueError:
            pass
        severity = "HIGH"
    elif not any(port in d["ports"] for d in matches):
        reasons.append(f"Port {port} is not approved for {host}")
        severity = "MEDIUM"

    limit = policy["max_bytes_out"]
    if sent > limit:
        reasons.append(f"Outbound transfer attempted {sent:,} bytes (limit {limit:,})")
        next_level = {"NONE": "MEDIUM", "MEDIUM": "HIGH", "HIGH": "CRITICAL"}
        severity = next_level.get(severity, severity)
    return {"status": "ALERT" if reasons else "OK", "severity": severity, "reasons": reasons}


def action_for(event: dict[str, Any], policy: dict[str, Any] | None = None) -> str:
    policy = validate_policy(policy or load_policy())
    classification = classify_event(event, policy)
    return "BLOCK" if policy["mode"] == "block" and classification["status"] == "ALERT" else "ALLOW"
