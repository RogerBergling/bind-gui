#!/usr/bin/env python3
"""Start the real static server and verify HTTP behaviour and headers."""

from __future__ import annotations

import http.client
import json
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOST = "127.0.0.1"


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, 0))
        return int(sock.getsockname()[1])


def wait_for(port: int, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.25)
            try:
                sock.connect((HOST, port))
                return
            except OSError:
                time.sleep(0.1)
    raise RuntimeError(f"server did not start on {HOST}:{port}")


def fetch(port: int, path: str):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    return opener.open(f"http://{HOST}:{port}{path}", timeout=5)


def request_raw(port: int, path: str, method: str = "GET"):
    connection = http.client.HTTPConnection(HOST, port, timeout=5)
    connection.request(method, path, headers={"Host": HOST})
    response = connection.getresponse()
    body = response.read()
    headers = dict(response.getheaders())
    connection.close()
    return response.status, headers, body


def main() -> int:
    port = free_port()
    process = subprocess.Popen(
        [sys.executable, str(ROOT / "start.py"), "--host", HOST, "--port", str(port), "--no-browser"],
        cwd=str(ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    failures: list[str] = []
    try:
        wait_for(port)

        home = fetch(port, "/")
        body = home.read().decode("utf-8", "replace")
        headers = {key.lower(): value for key, value in home.headers.items()}
        if home.status != 200:
            failures.append(f"GET / returned {home.status}")
        for term in ["BIND Workbench", 'id="view"', "/assets/js/app.js"]:
            if term not in body:
                failures.append(f"GET / body is missing {term!r}")
        for header in ["content-security-policy", "referrer-policy", "x-frame-options", "x-content-type-options", "cross-origin-opener-policy", "cross-origin-resource-policy"]:
            if header not in headers:
                failures.append(f"GET / is missing {header}")
        csp = headers.get("content-security-policy", "")
        if "default-src 'self'" not in csp:
            failures.append("CSP does not default to self")
        if "https://cloudflare-dns.com" not in csp or "https://dns.google" not in csp:
            failures.append("CSP does not allow the curated DoH origins")
        if "unsafe-eval" in csp:
            failures.append("CSP allows unsafe-eval")
        if "frame-ancestors 'none'" not in csp:
            failures.append("CSP does not deny framing")
        if headers.get("cache-control") != "no-store, no-cache, must-revalidate, max-age=0":
            failures.append("Cache-Control is not no-store")
        if headers.get("x-frame-options") != "DENY":
            failures.append("X-Frame-Options is not DENY")
        if headers.get("x-content-type-options") != "nosniff":
            failures.append("X-Content-Type-Options is not nosniff")

        css = fetch(port, "/assets/css/app.css")
        if css.status != 200:
            failures.append(f"GET /assets/css/app.css returned {css.status}")
        if "text/css" not in css.headers.get("Content-Type", ""):
            failures.append("CSS content type is wrong")
        css.read()

        version = fetch(port, "/version.json")
        data = json.loads(version.read())
        if not isinstance(data, dict) or "version" not in data:
            failures.append("version.json is not a version object")

        license_response = fetch(port, "/LICENSE.txt")
        if license_response.status != 200:
            failures.append("LICENSE.txt was not served")
        license_response.read()

        head_status, head_headers, _ = request_raw(port, "/", "HEAD")
        if head_status != 200:
            failures.append(f"HEAD / returned {head_status}")
        if "content-security-policy" not in {key.lower() for key in head_headers}:
            failures.append("HEAD / lacks security headers")

        listing_status, _, listing_body = request_raw(port, "/assets/")
        if listing_status != 404:
            failures.append("Directory listing is not blocked")
        if b"app.css" in listing_body:
            failures.append("Directory listing exposed files")

        missing_status, _, _ = request_raw(port, "/does-not-exist.txt")
        if missing_status != 404:
            failures.append(f"Missing static file returned {missing_status}, expected 404")

        deep_status, _, deep_body = request_raw(port, "/some/hash/route")
        if deep_status != 200 or b"BIND Workbench" not in deep_body:
            failures.append("Extensionless deep link did not return the app shell")

        traversal_status, _, traversal_body = request_raw(port, "/..%2fstart.py")
        if b"#!/usr/bin/env python" in traversal_body:
            failures.append("Path traversal exposed start.py")
        if traversal_status == 200 and b"BIND Workbench" not in traversal_body:
            failures.append("Unexpected traversal response")
    finally:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()

    print("BIND Workbench HTTP smoke test")
    if failures:
        for failure in failures:
            print(f"  error: {failure}")
        return 1
    print("  headers, MIME types, routing and containment: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
