"""Minimal outbound-egress probe.

No Flask, no gunicorn, no requests, no third-party packages at all -
only Python's stdlib (http.server, socket, urllib) - specifically to
rule out anything about the seo-keyword-checker app stack, its
dependencies, or its base image as the cause of the ~15s outbound hang.

GET /            -> probes DEFAULT_TARGET
GET /?url=<url>  -> probes a different target
GET /healthz     -> plain 200, no outbound call (proves the container
                     itself is healthy independent of egress)

For each resolved IP of the target host, does a raw TCP connect (no TLS,
no HTTP) with its own timer, in addition to the full HTTPS fetch. If one
address family (typically IPv6) hangs for ~15s while the other connects
in milliseconds, that's the classic "IPv6 route advertised but egress
silently drops it" pattern, and it would point at the CaaS network path
itself rather than at anything in this Python process.
"""
import json
import socket
import time
import urllib.request
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DEFAULT_TARGET = "https://example.com"
CONNECT_TIMEOUT = 20  # generous on purpose - we want to see it hang and time it, not cut it off early


def probe_tcp_connect(family, sockaddr):
    t0 = time.perf_counter()
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(CONNECT_TIMEOUT)
    try:
        s.connect(sockaddr)
        elapsed = time.perf_counter() - t0
        return {"ok": True, "seconds": round(elapsed, 3)}
    except Exception as exc:
        elapsed = time.perf_counter() - t0
        return {"ok": False, "seconds": round(elapsed, 3), "error": f"{type(exc).__name__}: {exc}"}
    finally:
        s.close()


def probe(url):
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    result = {"target": url, "host": host, "port": port}

    # Stage 1: DNS resolution, isolated from any connection attempt.
    t0 = time.perf_counter()
    try:
        addrinfo = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        result["dns_seconds"] = round(time.perf_counter() - t0, 3)
    except Exception as exc:
        result["dns_seconds"] = round(time.perf_counter() - t0, 3)
        result["dns_error"] = f"{type(exc).__name__}: {exc}"
        return result

    # Dedup by (family, address) - getaddrinfo often repeats entries per socktype.
    seen = set()
    unique = []
    for family, _socktype, _proto, _canon, sockaddr in addrinfo:
        key = (family, sockaddr[0])
        if key not in seen:
            seen.add(key)
            unique.append((family, sockaddr))

    # Stage 2: raw TCP connect timing, per resolved address, so an IPv6-only
    # hang is visible even if the HTTP client would have quietly fallen back.
    result["resolved"] = []
    for family, sockaddr in unique:
        fam_name = "IPv6" if family == socket.AF_INET6 else ("IPv4" if family == socket.AF_INET else str(family))
        conn = probe_tcp_connect(family, sockaddr)
        result["resolved"].append({"family": fam_name, "address": sockaddr[0], "connect": conn})

    # Stage 3: the actual full HTTPS/HTTP fetch, as the real app does it.
    t1 = time.perf_counter()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "egress-probe/1.0"})
        with urllib.request.urlopen(req, timeout=CONNECT_TIMEOUT + 5) as resp:
            body_len = len(resp.read(2048))
            result["http_seconds"] = round(time.perf_counter() - t1, 3)
            result["http_status"] = resp.status
            result["bytes_read"] = body_len
    except Exception as exc:
        result["http_seconds"] = round(time.perf_counter() - t1, 3)
        result["http_error"] = f"{type(exc).__name__}: {exc}"

    return result


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path == "/healthz":
            self._send(200, b"ok", "text/plain")
            return

        qs = urllib.parse.parse_qs(parsed.query)
        target = qs.get("url", [DEFAULT_TARGET])[0]

        started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        result = probe(target)
        result["probe_started_utc"] = started

        body = ("<pre>" + json.dumps(result, indent=2) + "</pre>").encode("utf-8")
        self._send(200, body, "text/html; charset=utf-8")

    def _send(self, code, body, content_type):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass  # keep stdout quiet - the HTTP response itself is the output


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", 8080), Handler)
    server.serve_forever()
