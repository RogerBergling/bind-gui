#!/usr/bin/env python3
"""Start the real static server and verify HTTP behaviour and headers."""

from __future__ import annotations

import http.client
import contextlib
import json
import os
import socket
import subprocess
import tempfile
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


def auth_request(port: int, path: str, method: str = "GET", headers: dict | None = None, data: bytes | None = None):
    request = urllib.request.Request(
        f"http://{HOST}:{port}{path}",
        data=data,
        method=method,
        headers=headers or {},
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        response = opener.open(request, timeout=5)
        return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers), error.read()


def run_auth_tests(failures: list[str]) -> None:
    port = free_port()
    password = "correct horse battery staple"
    upload_password = "different import password"
    env_handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False)
    env_handle.write(f"BIND_WORKBENCH_PASSWORD={password}\nBIND_WORKBENCH_UPLOAD_PASSWORD={upload_password}\nBIND_WORKBENCH_SESSION_HOURS=1\n")
    env_handle.close()
    env = {**os.environ, "BIND_WORKBENCH_ENV_FILE": env_handle.name}
    env.pop("BIND_WORKBENCH_PASSWORD", None)
    process = subprocess.Popen(
        [sys.executable, str(ROOT / "start.py"), "--host", HOST, "--port", str(port), "--no-browser"],
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        wait_for(port)
        status, headers, body = auth_request(port, "/")
        if status != 200 or b"Unlock the workbench" not in body:
            failures.append("Password gate did not serve the login page at /")
        if b'id="view"' in body:
            failures.append("Password gate served the app shell before login")
        if password.encode() in body:
            failures.append("Password leaked into the login page")

        status, _, body = auth_request(port, "/assets/js/app.js")
        if status != 401:
            failures.append(f"Unauthenticated app asset returned {status}, expected 401")
        status, _, _ = auth_request(port, "/assets/css/app.css")
        if status != 200:
            failures.append("Login stylesheet was not publicly accessible")
        status, _, _ = auth_request(port, "/login.js")
        if status != 200:
            failures.append("Login script was not publicly accessible")
        status, _, body = auth_request(port, "/api/auth-status")
        if status != 200 or b'"required":true' not in body or b'"authenticated":false' not in body:
            failures.append("auth-status did not report the unauthenticated gate")
        status, _, body = auth_request(port, "/api/upload-status")
        if status != 200 or b'"required":true' not in body or b'"separatePassword":true' not in body:
            failures.append("upload-status did not report the import gate")
        status, headers, body = auth_request(
            port,
            "/api/login",
            "POST",
            {"Content-Type": "application/json"},
            json.dumps({"password": "wrong"}).encode(),
        )
        if status != 401 or b"Invalid password" not in body:
            failures.append("Wrong password did not return a generic 401")
        if "Set-Cookie" in headers:
            failures.append("Wrong password returned a session cookie")

        status, headers, body = auth_request(
            port,
            "/api/login",
            "POST",
            {"Content-Type": "application/json"},
            json.dumps({"password": password}).encode(),
        )
        if status != 200:
            failures.append(f"Correct password returned {status}")
        cookie_header = headers.get("Set-Cookie", "")
        for marker in ["HttpOnly", "SameSite=Strict", "Path=/", "Max-Age="]:
            if marker not in cookie_header:
                failures.append(f"Session cookie lacks {marker}")
        cookie = cookie_header.split(";", 1)[0]
        if not cookie.startswith("bind_workbench_session="):
            failures.append("Session cookie has an unexpected name")

        status, _, body = auth_request(
            port,
            "/api/upload-auth",
            "POST",
            {"Cookie": cookie, "X-Bind-Upload-Password": "wrong"},
        )
        if status != 401 or b"Invalid import password" not in body:
            failures.append("Wrong import password did not return 401")
        status, _, body = auth_request(
            port,
            "/api/upload-auth",
            "POST",
            {"Cookie": cookie, "X-Bind-Upload-Password": upload_password},
        )
        if status != 200:
            failures.append("Correct import password was rejected")

        status, _, body = auth_request(port, "/api/auth-status", headers={"Cookie": cookie})
        if status != 200 or b'"authenticated":true' not in body:
            failures.append("auth-status did not report the authenticated session")
        status, _, body = auth_request(port, "/", headers={"Cookie": cookie})
        if status != 200 or b'id="view"' not in body:
            failures.append("Authenticated request did not serve the app shell")
        status, _, _ = auth_request(port, "/version.json", headers={"Cookie": cookie})
        if status != 200:
            failures.append("Authenticated version.json request failed")

        status, _, _ = auth_request(port, "/api/logout", "POST", headers={"Cookie": cookie})
        if status != 200:
            failures.append("Logout failed")
        status, _, body = auth_request(port, "/api/auth-status", headers={"Cookie": cookie})
        if b'"authenticated":false' not in body:
            failures.append("Logout did not invalidate the session")
    finally:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
        with contextlib.suppress(OSError):
            os.unlink(env_handle.name)


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

        run_auth_tests(failures)
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
    print("  headers, MIME types, routing, containment and password gate: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
