"""Minimal workload with safe live allow/block probes routed through EgressEye."""

from __future__ import annotations

import os
import socket
import time

import requests
from flask import Flask, jsonify

app = Flask(__name__)
WORKLOAD_NAME = os.environ.get("WORKLOAD_NAME", "attendance-api")
ALLOWED_DEMO_URL = "https://example.com/"
BLOCKED_DEMO_URL = "https://collect.exfil.example/"


@app.get("/")
def home():
    return jsonify(
        service="EgressEye sample workload",
        workload=WORKLOAD_NAME,
        demos=["/demo/allowed", "/demo/blocked", "/health"],
        note="Outbound HTTP(S) requests use the EgressEye forward proxy.",
    )


@app.get("/health")
def health():
    return jsonify(status="ok", workload=WORKLOAD_NAME, container=socket.gethostname())


def probe(url: str, label: str):
    started = time.monotonic()
    try:
        response = requests.get(url, timeout=12, headers={"X-EgressEye-Workload": WORKLOAD_NAME})
        return jsonify(
            demo=label,
            result="completed",
            destination=url,
            upstream_status=response.status_code,
            elapsed_ms=round((time.monotonic() - started) * 1000),
        )
    except requests.RequestException as exc:
        # A deny is a successful security demonstration: the proxy rejected it.
        return jsonify(
            demo=label,
            result="request_rejected_or_unreachable",
            destination=url,
            detail=str(exc)[:240],
            elapsed_ms=round((time.monotonic() - started) * 1000),
        )


@app.get("/demo/allowed")
def allowed_demo():
    return probe(ALLOWED_DEMO_URL, "allowlisted HTTPS connectivity")


@app.get("/demo/blocked")
def blocked_demo():
    return probe(BLOCKED_DEMO_URL, "unapproved HTTPS destination")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True)
