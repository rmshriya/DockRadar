"""A small policy-enforcing HTTP/HTTPS forward proxy for the demo workload.

HTTPS destinations are visible from CONNECT hostnames and ports. TLS payloads
remain encrypted; only byte counts and destination metadata are recorded.
"""

from __future__ import annotations

import select
import socket
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import detector
import policy

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 3128
CONNECT_TIMEOUT = 8
TUNNEL_IDLE_TIMEOUT = 20
MAX_HTTP_BODY = 2_000_000


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class EgressProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "EgressEyeGateway/1.0"
    sys_version = ""

    def log_message(self, fmt: str, *args) -> None:
        print(f"{self.log_date_time_string()} {self.client_address[0]} {fmt % args}", flush=True)

    def _workload(self) -> str:
        value = self.headers.get("X-EgressEye-Workload", "sample-app")
        return "".join(ch for ch in value[:120] if ch.isalnum() or ch in "._:-") or "unknown"

    def _classify(self, host: str, port: int, amount: int = 0) -> tuple[dict, dict]:
        current = policy.load_policy()
        verdict = policy.classify_event(
            {"dest_host": host, "dest_port": port, "bytes_attempted": amount}, current
        )
        blocked = current["mode"] == "block" and verdict["status"] == "ALERT"
        return current, {**verdict, "action": "BLOCK" if blocked else "ALLOW"}

    def _record(
        self,
        host: str,
        port: int,
        *,
        protocol: str,
        action: str,
        outcome: str,
        bytes_out: int = 0,
        bytes_attempted: int | None = None,
        reasons: list[str] | None = None,
    ) -> None:
        event = {
            "id": str(uuid.uuid4()),
            "timestamp": utc_now(),
            "container": self._workload(),
            "dest_host": host,
            "dest_port": port,
            "protocol": protocol,
            "bytes_out": max(0, bytes_out),
            "bytes_attempted": max(bytes_out, bytes_attempted if bytes_attempted is not None else bytes_out),
            "action": action,
            "outcome": outcome,
            "source": "proxy",
            "reason": "; ".join(reasons or []),
        }
        detector.append_event(event)

    def _respond(self, code: int, message: str) -> None:
        body = (message + "\n").encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass
        self.close_connection = True

    @staticmethod
    def _send_all(connection: socket.socket, payload: bytes) -> None:
        view = memoryview(payload)
        while view:
            _, writable, exceptional = select.select([], [connection], [connection], 10)
            if exceptional or not writable:
                raise TimeoutError("socket write timed out")
            written = connection.send(view)
            if written <= 0:
                raise ConnectionError("socket closed while forwarding")
            view = view[written:]

    def _deny(self, host: str, port: int, protocol: str, verdict: dict, amount: int = 0) -> None:
        self._record(
            host, port, protocol=protocol, action="BLOCK", outcome="policy_block",
            bytes_attempted=amount, reasons=verdict["reasons"],
        )
        reason = "; ".join(verdict["reasons"]) or "Denied by egress policy"
        self._respond(403, f"EgressEye blocked this destination: {reason}")

    @staticmethod
    def _authority(value: str, default_port: int) -> tuple[str, int]:
        parsed = urlsplit("//" + value.strip())
        host = parsed.hostname
        port = parsed.port or default_port
        if not host or not 1 <= port <= 65535:
            raise ValueError("Expected a valid host:port destination")
        return policy.normalize_host(host, allow_wildcard=False), port

    def do_CONNECT(self) -> None:
        try:
            host, port = self._authority(self.path, 443)
        except (ValueError, TypeError):
            self._respond(400, "Invalid CONNECT destination")
            return
        current, verdict = self._classify(host, port)
        if verdict["action"] == "BLOCK":
            self._deny(host, port, "HTTPS", verdict)
            return

        try:
            upstream = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
        except OSError as exc:
            self._record(host, port, protocol="HTTPS", action="ALLOW", outcome="connect_error")
            self._respond(502, f"Approved by policy, but the upstream connection failed: {exc.__class__.__name__}")
            return

        self.send_response(200, "Connection established")
        self.end_headers()
        attempted = sent = 0
        outcome = "connected"
        last_activity = time.monotonic()
        self.connection.setblocking(False)
        upstream.setblocking(False)
        try:
            while True:
                idle = time.monotonic() - last_activity
                if idle >= TUNNEL_IDLE_TIMEOUT:
                    outcome = "idle_timeout"
                    break
                readable, _, exceptional = select.select(
                    [self.connection, upstream], [], [self.connection, upstream],
                    max(0.1, TUNNEL_IDLE_TIMEOUT - idle),
                )
                if exceptional:
                    break
                for source in readable:
                    try:
                        chunk = source.recv(65536)
                    except OSError:
                        chunk = b""
                    if not chunk:
                        outcome = "connection_closed"
                        break
                    last_activity = time.monotonic()
                    if source is self.connection:
                        attempted += len(chunk)
                        next_verdict = policy.classify_event(
                            {"dest_host": host, "dest_port": port, "bytes_attempted": attempted}, current
                        )
                        if current["mode"] == "block" and next_verdict["severity"] in {"MEDIUM", "HIGH", "CRITICAL"}:
                            outcome = "byte_limit_block"
                            self.close_connection = True
                            self._record(
                                host, port, protocol="HTTPS", action="BLOCK", outcome=outcome,
                                bytes_out=sent, bytes_attempted=attempted, reasons=next_verdict["reasons"],
                            )
                            return
                        sent += len(chunk)
                        destination = upstream
                    else:
                        destination = self.connection
                    self._send_all(destination, chunk)
                else:
                    continue
                if outcome == "connection_closed":
                    break
        except (OSError, ValueError):
            outcome = "relay_error"
        finally:
            self.close_connection = True
            try:
                upstream.close()
            except OSError:
                pass
        self._record(
            host, port, protocol="HTTPS", action="ALLOW", outcome=outcome,
            bytes_out=sent, bytes_attempted=attempted,
        )

    def _handle_http(self) -> None:
        parsed = urlsplit(self.path)
        host = parsed.hostname or self.headers.get("Host", "").split(":", 1)[0]
        try:
            host = policy.normalize_host(host, allow_wildcard=False)
            port = parsed.port or (80 if parsed.scheme.lower() == "http" else 443)
        except (ValueError, TypeError):
            self._respond(400, "Invalid HTTP destination")
            return
        if parsed.scheme.lower() != "http":
            self._respond(400, "Use HTTPS CONNECT for TLS destinations")
            return
        transfer_encoding = self.headers.get("Transfer-Encoding", "").lower()
        if "chunked" in transfer_encoding:
            self._respond(501, "Chunked request bodies are not supported by this demo gateway")
            return
        try:
            body_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._respond(400, "Invalid Content-Length")
            return
        if body_length < 0 or body_length > MAX_HTTP_BODY:
            self._respond(413, "Request body exceeds the demo proxy limit")
            return
        body = self.rfile.read(body_length) if body_length else b""
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        headers = []
        for key, value in self.headers.items():
            if key.lower() in {"proxy-connection", "proxy-authorization", "connection", "content-length", "transfer-encoding"}:
                continue
            headers.append(f"{key}: {value}\r\n")
        headers.extend([f"Content-Length: {len(body)}\r\n", "Connection: close\r\n"])
        request_bytes = f"{self.command} {path} HTTP/1.1\r\n" + "".join(headers) + "\r\n"
        payload = request_bytes.encode("iso-8859-1") + body
        current, verdict = self._classify(host, port, len(payload))
        if verdict["action"] == "BLOCK":
            self._deny(host, port, "HTTP", verdict, len(payload))
            return
        try:
            upstream = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
            upstream.settimeout(CONNECT_TIMEOUT)
            upstream.sendall(payload)
            while True:
                chunk = upstream.recv(65536)
                if not chunk:
                    break
                self.connection.sendall(chunk)
        except OSError as exc:
            self._record(host, port, protocol="HTTP", action="ALLOW", outcome="connect_error", bytes_out=len(payload))
            if not self.wfile.closed:
                self._respond(502, f"Approved by policy, but the upstream connection failed: {exc.__class__.__name__}")
            return
        finally:
            try:
                upstream.close()
            except (OSError, UnboundLocalError):
                pass
        self._record(host, port, protocol="HTTP", action="ALLOW", outcome="connected", bytes_out=len(payload))
        self.close_connection = True

    do_GET = _handle_http
    do_POST = _handle_http
    do_PUT = _handle_http
    do_DELETE = _handle_http
    do_HEAD = _handle_http
    do_OPTIONS = _handle_http
    do_PATCH = _handle_http


class ReusableThreadingServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    detector.DATA_DIR.mkdir(parents=True, exist_ok=True)
    server = ReusableThreadingServer((LISTEN_HOST, LISTEN_PORT), EgressProxyHandler)
    print(f"EgressEye proxy listening on {LISTEN_HOST}:{LISTEN_PORT}", flush=True)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
