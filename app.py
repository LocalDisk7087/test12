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
import sys
import time
import urllib.request
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DEFAULT_TARGET = "https://example.com"
CONNECT_TIMEOUT = 20  # generous on purpose - we want to see it hang and time it, not cut it off early


def log(msg):
    """Print immediately, flushed, so this survives in the container's stdout
    logs even if the platform's gateway kills the HTTP response before the
    request finishes (which is exactly the failure mode we're chasing)."""
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True, file=sys.stdout)


def read_resolv_conf():
    try:
        with open("/etc/resolv.conf") as f:
            content = f.read()
        nameservers = [line.split()[1] for line in content.splitlines()
                       if line.strip().startswith("nameserver")]
        return content, nameservers
    except Exception as exc:
        return f"<could not read: {exc}>", []


def probe_nameserver_reachability(nameservers):
    """Independent of DNS actually resolving anything: just check whether
    each configured nameserver accepts a TCP connection on port 53. If this
    also hangs/fails, the resolver is unreachable at the network level
    (routing/firewall). If this succeeds but DNS still fails, the resolver
    is reachable but not answering queries (a different, narrower bug)."""
    results = []
    for ns in nameservers:
        log(f"checking nameserver {ns}:53 reachability (TCP) ...")
        t0 = time.perf_counter()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        try:
            s.connect((ns, 53))
            elapsed = time.perf_counter() - t0
            log(f"  {ns}:53 TCP CONNECTED in {elapsed:.3f}s")
            results.append({"nameserver": ns, "tcp_53_ok": True, "seconds": round(elapsed, 3)})
        except Exception as exc:
            elapsed = time.perf_counter() - t0
            log(f"  {ns}:53 TCP FAILED after {elapsed:.3f}s: {type(exc).__name__}: {exc}")
            results.append({"nameserver": ns, "tcp_53_ok": False, "seconds": round(elapsed, 3),
                             "error": f"{type(exc).__name__}: {exc}"})
        finally:
            s.close()
    return results


def probe_tcp_connect(family, sockaddr):
    fam_name = "IPv6" if family == socket.AF_INET6 else ("IPv4" if family == socket.AF_INET else str(family))
    log(f"  connecting via {fam_name} to {sockaddr} ...")
    t0 = time.perf_counter()
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(CONNECT_TIMEOUT)
    try:
        s.connect(sockaddr)
        elapsed = time.perf_counter() - t0
        log(f"  {fam_name} {sockaddr} CONNECTED in {elapsed:.3f}s")
        return {"ok": True, "seconds": round(elapsed, 3)}
    except Exception as exc:
        elapsed = time.perf_counter() - t0
        log(f"  {fam_name} {sockaddr} FAILED after {elapsed:.3f}s: {type(exc).__name__}: {exc}")
        return {"ok": False, "seconds": round(elapsed, 3), "error": f"{type(exc).__name__}: {exc}"}
    finally:
        s.close()


def probe(url):
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    result = {"target": url, "host": host, "port": port}
    log(f"=== probe start: {url} ===")

    # Stage 0: what resolver is this container even configured to use,
    # and can we reach it at all at the TCP level (independent of whether
    # DNS queries actually get answered)?
    resolv_conf, nameservers = read_resolv_conf()
    log(f"/etc/resolv.conf:\n{resolv_conf}")
    result["resolv_conf"] = resolv_conf
    result["nameserver_reachability"] = probe_nameserver_reachability(nameservers)

    # Stage 1: DNS resolution, isolated from any connection attempt.
    log(f"resolving {host} ...")
    t0 = time.perf_counter()
    try:
        addrinfo = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        result["dns_seconds"] = round(time.perf_counter() - t0, 3)
        log(f"DNS resolved in {result['dns_seconds']}s")
    except Exception as exc:
        result["dns_seconds"] = round(time.perf_counter() - t0, 3)
        result["dns_error"] = f"{type(exc).__name__}: {exc}"
        log(f"DNS FAILED after {result['dns_seconds']}s: {result['dns_error']}")
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
    log("starting full HTTPS fetch (this is the stage that hung before) ...")
    t1 = time.perf_counter()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "egress-probe/1.0"})
        with urllib.request.urlopen(req, timeout=CONNECT_TIMEOUT + 5) as resp:
            body_len = len(resp.read(2048))
            result["http_seconds"] = round(time.perf_counter() - t1, 3)
            result["http_status"] = resp.status
            result["bytes_read"] = body_len
            log(f"HTTP fetch OK in {result['http_seconds']}s, status={resp.status}")
    except Exception as exc:
        result["http_seconds"] = round(time.perf_counter() - t1, 3)
        result["http_error"] = f"{type(exc).__name__}: {exc}"
        log(f"HTTP fetch FAILED after {result['http_seconds']}s: {result['http_error']}")

    log(f"=== probe done: {url} ===")
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
