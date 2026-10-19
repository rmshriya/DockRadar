"""Optional host-side container admission gate using Docker, Trivy and Cosign.

Run `python delivery_gate.py check IMAGE`. It writes a small JSON report into
data/ for the dashboard. Missing tooling fails closed and is shown as a reason.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent
CONFIG_DIR = BASE_DIR / "config"
DATA_DIR = Path(os.environ.get("EGRESSEYE_DATA_DIR", BASE_DIR / "data"))
POLICY_FILE = CONFIG_DIR / "delivery_policy.json"
TRUSTED_FILE = CONFIG_DIR / "trusted_digest.json"
PUBLIC_KEY = CONFIG_DIR / "cosign.pub"
REPORT_FILE = DATA_DIR / "delivery_report.json"


def run_command(args: list[str], timeout: int = 120) -> tuple[int, str, str]:
    try:
        process = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
        return process.returncode, process.stdout, process.stderr
    except FileNotFoundError:
        return 127, "", f"Required command not found: {args[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"Command timed out after {timeout} seconds: {args[0]}"


def get_digest(image: str) -> tuple[str | None, str]:
    code, _, error = run_command(["docker", "pull", image])
    if code:
        return None, error.strip()[-500:] or "Docker could not pull the image"
    code, output, error = run_command([
        "docker", "image", "inspect", "--format", "{{json .RepoDigests}}", image
    ])
    if code:
        return None, error.strip()[-500:] or "Docker could not inspect the pulled image"
    try:
        repo_digests = json.loads(output)
    except json.JSONDecodeError:
        return None, "Docker returned an unreadable RepoDigests value"
    repository = image.rsplit(":", 1)[0] if ":" in image.rsplit("/", 1)[-1] else image
    for value in repo_digests or []:
        if value.startswith(repository + "@sha256:"):
            return value.rsplit("@", 1)[1], ""
    return None, "The image has no registry digest; push it to a registry before checking delivery integrity"


def verify_signature(image: str) -> dict[str, Any]:
    if not PUBLIC_KEY.exists():
        return {"valid": False, "detail": "Missing config/cosign.pub"}
    code, _, error = run_command([
        "cosign", "verify", "--key", str(PUBLIC_KEY),
        "--insecure-ignore-tlog=true", image,
    ])
    if code == 0:
        return {"valid": True, "detail": "Signature verified against config/cosign.pub"}
    return {"valid": False, "detail": (error.strip().splitlines() or ["Signature verification failed"])[-1]}


def scan_image(image: str) -> dict[str, Any]:
    code, output, error = run_command([
        "trivy", "image", "--scanners", "vuln,secret", "--format", "json", image,
    ], timeout=300)
    if code:
        return {"ok": False, "error": error.strip()[-600:] or "Trivy scan failed", "counts": {}, "secrets": [], "top_vulns": []}
    try:
        report = json.loads(output)
    except json.JSONDecodeError:
        return {"ok": False, "error": "Trivy returned invalid JSON", "counts": {}, "secrets": [], "top_vulns": []}
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    secrets: list[dict[str, Any]] = []
    top_vulns: list[dict[str, Any]] = []
    for result in report.get("Results", []) or []:
        for vulnerability in result.get("Vulnerabilities", []) or []:
            severity = str(vulnerability.get("Severity", "UNKNOWN")).upper()
            counts[severity] = counts.get(severity, 0) + 1
            if severity in {"CRITICAL", "HIGH"}:
                top_vulns.append({
                    "CVE": vulnerability.get("VulnerabilityID", "unknown"),
                    "Package": vulnerability.get("PkgName", "unknown"),
                    "Installed": vulnerability.get("InstalledVersion", "unknown"),
                    "Fixed in": vulnerability.get("FixedVersion") or "—",
                    "Severity": severity,
                })
        for secret in result.get("Secrets", []) or []:
            secrets.append({
                "File": result.get("Target", "unknown"),
                "Rule": secret.get("RuleID", "unknown"),
                "Title": secret.get("Title", "Secret detected"),
                "Severity": secret.get("Severity", "UNKNOWN"),
            })
    return {"ok": True, "error": "", "counts": counts, "secrets": secrets, "top_vulns": top_vulns}


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def write_report(report: dict[str, Any]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_FILE.write_text(json.dumps(report, indent=2), encoding="utf-8")


def record_baseline(image: str) -> int:
    digest, error = get_digest(image)
    if not digest:
        print(f"BLOCKED: {error}")
        return 1
    signature = verify_signature(image)
    if not signature["valid"]:
        print(f"BLOCKED: refusing to trust an unsigned or unverifiable image: {signature['detail']}")
        return 1
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    TRUSTED_FILE.write_text(json.dumps({
        "image": image,
        "digest": digest,
        "recorded_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }, indent=2), encoding="utf-8")
    print(f"Trusted signed digest recorded: {digest}")
    return 0


def run_gate(image: str) -> dict[str, Any]:
    policy = load_json(POLICY_FILE, {
        "max_critical": 0, "max_high": 10, "max_secrets": 0,
        "require_valid_signature": True, "require_digest_match": True,
    })
    digest, digest_error = get_digest(image)
    scan = scan_image(image)
    signature = verify_signature(image)
    trusted = load_json(TRUSTED_FILE, {})
    trusted_digest = trusted.get("digest")
    digest_match = bool(digest and trusted_digest and digest == trusted_digest)
    reasons: list[str] = []
    if not digest:
        reasons.append(digest_error)
    if not scan["ok"]:
        reasons.append(f"Trivy scan unavailable or failed: {scan['error']}")
    else:
        counts = scan["counts"]
        if counts.get("CRITICAL", 0) > int(policy["max_critical"]):
            reasons.append(f"{counts['CRITICAL']} CRITICAL findings (limit {policy['max_critical']})")
        if counts.get("HIGH", 0) > int(policy["max_high"]):
            reasons.append(f"{counts['HIGH']} HIGH findings (limit {policy['max_high']})")
        if len(scan["secrets"]) > int(policy["max_secrets"]):
            reasons.append(f"{len(scan['secrets'])} secret finding(s) (limit {policy['max_secrets']})")
    if policy.get("require_valid_signature", True) and not signature["valid"]:
        reasons.append(f"Image signature is missing or invalid: {signature['detail']}")
    if policy.get("require_digest_match", True) and not digest_match:
        reasons.append("Image digest does not match the trusted signed baseline")
    decision = "APPROVED" if not reasons else "BLOCKED"
    report = {
        "image": image,
        "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "decision": decision,
        "reasons": reasons,
        "scan": scan,
        "signature": signature,
        "digest": {"trusted": trusted_digest, "current": digest, "match": digest_match},
        "policy": policy,
    }
    write_report(report)
    return report


def main(argv: list[str]) -> int:
    if len(argv) != 3 or argv[1] not in {"baseline", "check"}:
        print("Usage: python delivery_gate.py baseline|check IMAGE")
        return 2
    if argv[1] == "baseline":
        return record_baseline(argv[2])
    report = run_gate(argv[2])
    print(f"\nDELIVERY DECISION: {report['decision']}")
    for reason in report["reasons"]:
        print(f"  - {reason}")
    print(f"Report written to {REPORT_FILE}")
    return 0 if report["decision"] == "APPROVED" else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
