#!/usr/bin/env python3
"""BIND Workbench — hardened, zero-dependency static file server.

The application is a browser-only single-page app. This process never handles
configuration data and has no configuration write path: it serves files from
./public. The only non-static endpoints are the optional password-session
routes described below.

Optional password protection:
    BIND_WORKBENCH_PASSWORD=... python3 start.py
    BIND_WORKBENCH_UPLOAD_PASSWORD=... python3 start.py

When BIND_WORKBENCH_PASSWORD is set, the whole app is gated behind a login
page and an HttpOnly session cookie. BIND_WORKBENCH_UPLOAD_PASSWORD adds a
second server-verified prompt before configuration files are imported; if it
is empty it falls back to the app password. Both are checked server-side with
hmac.compare_digest and are never embedded in the frontend bundle.

    python3 start.py                  # pick a free port (8005-8025) and open a browser
    python3 start.py --no-browser     # serve only
    python3 start.py --port 8005      # preferred port
    python3 start.py --host 0.0.0.0   # expose on the LAN (review the security page first)
"""

from __future__ import annotations

import argparse
import contextlib
import functools
import hmac
import http.server
import json
import os
import secrets
import socket
import sys
import threading
import time
import urllib.parse
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WEB_ROOT = ROOT / "public"
WEB_ROOT_REAL = WEB_ROOT.resolve()
PORT_RANGE = range(8005, 8026)


def load_env_file(path: Path) -> None:
    """Load simple KEY=VALUE lines from .env without overriding real env vars."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not key or not key.replace("_", "").isalnum() or key[0].isdigit():
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        os.environ.setdefault(key, value)


def warn_insecure_env_file(path: Path) -> None:
    """Warn when a password-bearing .env is readable by group or others."""
    try:
        mode = path.stat().st_mode
    except OSError:
        return
    if mode & 0o077:
        print(
            f"Warning: {path} is readable by group or others (mode {mode & 0o777:o}). "
            f"Run: chmod 600 {path}",
            file=sys.stderr,
        )


ENV_FILE = Path(os.environ.get("BIND_WORKBENCH_ENV_FILE", str(ROOT / ".env"))).expanduser()
load_env_file(ENV_FILE)

PASSWORD_ENV = "BIND_WORKBENCH_PASSWORD"
UPLOAD_PASSWORD_ENV = "BIND_WORKBENCH_UPLOAD_PASSWORD"
SESSION_HOURS_ENV = "BIND_WORKBENCH_SESSION_HOURS"
AUTH_PASSWORD = os.environ.get(PASSWORD_ENV, "")
AUTH_ENABLED = bool(AUTH_PASSWORD)
UPLOAD_PASSWORD_OVERRIDE = os.environ.get(UPLOAD_PASSWORD_ENV, "")
UPLOAD_PASSWORD = UPLOAD_PASSWORD_OVERRIDE or AUTH_PASSWORD
UPLOAD_AUTH_ENABLED = bool(UPLOAD_PASSWORD)
SESSION_COOKIE = "bind_workbench_session"
try:
    _SESSION_HOURS = int(os.environ.get(SESSION_HOURS_ENV, "12") or "12")
except ValueError:
    _SESSION_HOURS = 12
SESSION_TTL_SECONDS = max(300, min(72 * 3600, _SESSION_HOURS * 3600))
LOGIN_PAGE = WEB_ROOT / "login.html"
LOGIN_ASSETS = {"/login", "/login.html", "/login.js", "/assets/css/app.css"}
LOGIN_BODY_LIMIT = 4096
LOGIN_FAILURE_LIMIT = 5
LOGIN_FAILURE_WINDOW = 60

SESSIONS: dict[str, float] = {}
SESSIONS_LOCK = threading.Lock()
LOGIN_FAILURES: dict[str, list[float]] = {}
UPLOAD_FAILURES: dict[str, list[float]] = {}
FAILURES_LOCK = threading.Lock()

NO_CACHE = "no-store, no-cache, must-revalidate, max-age=0"

# Keep these in sync with the headers documented on the in-app security page.
# The two DNS-over-HTTPS origins are the only permitted cross-origin requests.
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self' https://cloudflare-dns.com https://dns.google; "
        "object-src 'none'; "
        "worker-src 'none'; "
        "base-uri 'none'; "
        "frame-ancestors 'none'; "
        "form-action 'none'"
    ),
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "X-Permitted-Cross-Domain-Policies": "none",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


def _prune_sessions(now: float | None = None) -> None:
    current = time.time() if now is None else now
    with SESSIONS_LOCK:
        expired = [token for token, expiry in SESSIONS.items() if expiry <= current]
        for token in expired:
            SESSIONS.pop(token, None)


class Handler(http.server.SimpleHTTPRequestHandler):
    """Static handler with strict routing, containment and optional auth."""

    server_version = "BindWorkbench"
    sys_version = ""

    def version_string(self) -> str:
        """Do not advertise the Python runtime or stdlib server version."""
        return self.server_version

    extensions_map = {
        **http.server.SimpleHTTPRequestHandler.extensions_map,
        ".md": "text/markdown; charset=utf-8",
        ".js": "text/javascript; charset=utf-8",
        ".mjs": "text/javascript; charset=utf-8",
        ".css": "text/css; charset=utf-8",
        ".html": "text/html; charset=utf-8",
        ".json": "application/json; charset=utf-8",
        ".svg": "image/svg+xml",
        ".xml": "application/xml; charset=utf-8",
        ".txt": "text/plain; charset=utf-8",
        ".webmanifest": "application/manifest+json",
    }

    def end_headers(self) -> None:
        self.send_header("Cache-Control", NO_CACHE)
        for name, value in SECURITY_HEADERS.items():
            self.send_header(name, value)
        with contextlib.suppress(Exception):
            super().end_headers()

    def list_directory(self, path):  # noqa: N802 (stdlib naming)
        """Never expose directory indexes."""
        self.send_error(404, "Not found")
        return None

    @staticmethod
    def _safe_request_path(path: str) -> bool:
        """Reject control characters, including percent-encoded nulls."""
        try:
            decoded = urllib.parse.unquote(path, errors="replace")
        except (UnicodeError, ValueError):
            return False
        return not any(ord(char) < 0x20 or ord(char) == 0x7F for char in decoded)

    def _inside_web_root(self, path) -> bool:
        """True only when *path* resolves to the web root or a child of it."""
        try:
            resolved = Path(path).resolve()
        except (OSError, ValueError, UnicodeError):
            return False
        return resolved == WEB_ROOT_REAL or WEB_ROOT_REAL in resolved.parents

    def translate_path(self, path: str) -> str:  # noqa: N802 (stdlib naming)
        """Keep symlinks inside public/ instead of following them elsewhere."""
        if not self._safe_request_path(path):
            return str(WEB_ROOT_REAL / "__not_found__")
        try:
            translated = super().translate_path(path)
        except (OSError, ValueError, UnicodeError):
            return str(WEB_ROOT_REAL / "__not_found__")
        if not self._inside_web_root(translated):
            return str(WEB_ROOT_REAL / "__not_found__")
        return translated

    def send_head(self):
        """Re-check directory index files after symlink resolution."""
        path = self.translate_path(self.path)
        try:
            is_directory = Path(path).is_dir()
        except (OSError, ValueError, UnicodeError):
            is_directory = False
        if is_directory:
            for name in ("index.html", "index.htm"):
                index = Path(path) / name
                try:
                    exists = index.exists()
                except (OSError, ValueError, UnicodeError):
                    exists = False
                if exists and not self._inside_web_root(index):
                    self.send_error(404, "Not found")
                    return None
        return super().send_head()

    def _resolve_route(self) -> None:
        # Hash routing normally means every route is "/". Send extension-less
        # paths to the app shell so direct deep links still work.
        path = self.path.split("?", 1)[0].split("#", 1)[0]
        if not self._safe_request_path(path):
            return
        if path not in ("/", ""):
            try:
                candidate = (WEB_ROOT / path.lstrip("/")).resolve()
            except (OSError, ValueError, UnicodeError):
                return
            inside = candidate == WEB_ROOT_REAL or WEB_ROOT_REAL in candidate.parents
            if inside and not candidate.exists() and not Path(path).suffix:
                self.path = "/"

    # ------------------------------------------------------------------
    # Authentication primitives
    # ------------------------------------------------------------------

    def _path(self) -> str:
        return self.path.split("?", 1)[0].split("#", 1)[0]

    def _cookies(self) -> dict[str, str]:
        result: dict[str, str] = {}
        for part in (self.headers.get("Cookie") or "").split(";"):
            if "=" not in part:
                continue
            name, value = part.split("=", 1)
            result[name.strip()] = value.strip()
        return result

    def _session_token(self) -> str:
        return self._cookies().get(SESSION_COOKIE, "")

    def _authenticated(self) -> bool:
        if not AUTH_ENABLED:
            return True
        token = self._session_token()
        if not token:
            return False
        now = time.time()
        _prune_sessions(now)
        with SESSIONS_LOCK:
            expiry = SESSIONS.get(token)
            if expiry is None or expiry <= now:
                SESSIONS.pop(token, None)
                return False
            return True

    def _is_https(self) -> bool:
        return (self.headers.get("X-Forwarded-Proto") or "").lower() == "https"

    def _send_json(self, status: int, payload: dict, extra_headers: list[tuple[str, str]] | None = None) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for name, value in extra_headers or []:
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                self.wfile.write(body)

    def _serve_login(self) -> None:
        try:
            body = LOGIN_PAGE.read_bytes()
        except OSError:
            self.send_error(500, "Login page is missing")
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                self.wfile.write(body)

    def _redirect(self, location: str) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _auth_status(self) -> None:
        self._send_json(200, {"required": AUTH_ENABLED, "authenticated": self._authenticated()})

    def _client_ip(self) -> str:
        return str(self.client_address[0]) if self.client_address else "unknown"

    def _login_rate_limited(self) -> bool:
        ip = self._client_ip()
        now = time.time()
        with FAILURES_LOCK:
            failures = [stamp for stamp in LOGIN_FAILURES.get(ip, []) if now - stamp < LOGIN_FAILURE_WINDOW]
            LOGIN_FAILURES[ip] = failures
            return len(failures) >= LOGIN_FAILURE_LIMIT

    def _record_login_failure(self) -> None:
        ip = self._client_ip()
        now = time.time()
        with FAILURES_LOCK:
            failures = [stamp for stamp in LOGIN_FAILURES.get(ip, []) if now - stamp < LOGIN_FAILURE_WINDOW]
            failures.append(now)
            LOGIN_FAILURES[ip] = failures[-LOGIN_FAILURE_LIMIT:]

    def _clear_login_failures(self) -> None:
        with FAILURES_LOCK:
            LOGIN_FAILURES.pop(self._client_ip(), None)

    def _upload_status(self) -> None:
        self._send_json(200, {
            "required": UPLOAD_AUTH_ENABLED,
            "separatePassword": bool(UPLOAD_PASSWORD_OVERRIDE),
            "sessionProtected": AUTH_ENABLED,
        })

    def _upload_rate_limited(self) -> bool:
        ip = self._client_ip()
        now = time.time()
        with FAILURES_LOCK:
            failures = [stamp for stamp in UPLOAD_FAILURES.get(ip, []) if now - stamp < LOGIN_FAILURE_WINDOW]
            UPLOAD_FAILURES[ip] = failures
            return len(failures) >= LOGIN_FAILURE_LIMIT

    def _record_upload_failure(self) -> None:
        ip = self._client_ip()
        now = time.time()
        with FAILURES_LOCK:
            failures = [stamp for stamp in UPLOAD_FAILURES.get(ip, []) if now - stamp < LOGIN_FAILURE_WINDOW]
            failures.append(now)
            UPLOAD_FAILURES[ip] = failures[-LOGIN_FAILURE_LIMIT:]

    def _clear_upload_failures(self) -> None:
        with FAILURES_LOCK:
            UPLOAD_FAILURES.pop(self._client_ip(), None)

    def _handle_upload_auth(self) -> None:
        if AUTH_ENABLED and not self._authenticated():
            self._send_json(401, {"ok": False, "error": "Authentication required."})
            return
        if not UPLOAD_AUTH_ENABLED:
            self._send_json(200, {"ok": True})
            return
        if self._upload_rate_limited():
            self._send_json(429, {"ok": False, "error": "Too many attempts. Wait a minute and try again."})
            return
        provided = self.headers.get("X-Bind-Upload-Password", "")
        if not provided or not hmac.compare_digest(provided.encode("utf-8"), UPLOAD_PASSWORD.encode("utf-8")):
            self._record_upload_failure()
            self._send_json(401, {"ok": False, "error": "Invalid import password."})
            return
        self._clear_upload_failures()
        self._send_json(200, {"ok": True})

    def _handle_login(self) -> None:
        if not AUTH_ENABLED:
            self._send_json(200, {"ok": True})
            return
        if self._login_rate_limited():
            self._send_json(429, {"ok": False, "error": "Too many attempts. Wait a minute and try again."})
            return
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            length = 0
        if length <= 0 or length > LOGIN_BODY_LIMIT:
            self._record_login_failure()
            self._send_json(400, {"ok": False, "error": "Invalid login request."})
            return
        provided = ""
        try:
            raw = self.rfile.read(length)
            try:
                data = json.loads(raw.decode("utf-8"))
            except (UnicodeError, ValueError):
                data = None
            if isinstance(data, dict):
                provided = str(data.get("password") or "")
            else:
                try:
                    parsed = urllib.parse.parse_qs(raw.decode("utf-8", "replace"), max_num_fields=16)
                    provided = str((parsed.get("password") or [""])[0])
                except (UnicodeError, ValueError):
                    provided = ""
        except OSError:
            provided = ""
        if not hmac.compare_digest(provided.encode("utf-8"), AUTH_PASSWORD.encode("utf-8")):
            self._record_login_failure()
            self._send_json(401, {"ok": False, "error": "Invalid password."})
            return
        token = secrets.token_urlsafe(32)
        now = time.time()
        _prune_sessions(now)
        with SESSIONS_LOCK:
            SESSIONS[token] = now + SESSION_TTL_SECONDS
        self._clear_login_failures()
        self._send_json(200, {"ok": True}, [("Set-Cookie", self._cookie_header(token))])

    def _cookie_header(self, token: str) -> str:
        parts = [
            f"{SESSION_COOKIE}={token}",
            "HttpOnly",
            "SameSite=Strict",
            "Path=/",
            f"Max-Age={SESSION_TTL_SECONDS}",
        ]
        if self._is_https():
            parts.append("Secure")
        return "; ".join(parts)

    def _handle_logout(self) -> None:
        token = self._session_token()
        if token:
            with SESSIONS_LOCK:
                SESSIONS.pop(token, None)
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", "2")
        parts = [f"{SESSION_COOKIE}=", "HttpOnly", "SameSite=Strict", "Path=/", "Max-Age=0"]
        if self._is_https():
            parts.append("Secure")
        self.send_header("Set-Cookie", "; ".join(parts))
        self.end_headers()
        if self.command != "HEAD":
            with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                self.wfile.write(b"{}")

    # ------------------------------------------------------------------
    # HTTP methods
    # ------------------------------------------------------------------

    def _gate(self) -> bool:
        """Return True when the request may continue to the static handler."""
        path = self._path()
        if path == "/api/auth-status":
            self._auth_status()
            return False
        if path == "/api/upload-status":
            self._upload_status()
            return False
        if path in ("/login", "/login.html"):
            if AUTH_ENABLED:
                self._serve_login()
            else:
                self._redirect("/")
            return False
        if path == "/login.js" or path == "/assets/css/app.css":
            return True
        if AUTH_ENABLED and not self._authenticated():
            if path.startswith("/api/"):
                self._send_json(401, {"ok": False, "error": "Authentication required."})
            elif path in ("/", "") or not Path(path).suffix:
                self._serve_login()
            else:
                self._send_json(401, {"ok": False, "error": "Authentication required."})
            return False
        return True

    def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
        if not self._gate():
            return
        self._resolve_route()
        super().do_GET()

    def do_HEAD(self) -> None:  # noqa: N802 (stdlib naming)
        if not self._gate():
            return
        self._resolve_route()
        super().do_HEAD()

    def do_POST(self) -> None:  # noqa: N802 (stdlib naming)
        path = self._path()
        if path == "/api/login":
            self._handle_login()
            return
        if path == "/api/logout":
            self._handle_logout()
            return
        if path == "/api/upload-auth":
            self._handle_upload_auth()
            return
        self._send_json(404, {"ok": False, "error": "Not found."})

    def log_message(self, fmt: str, *args) -> None:
        message = fmt % args
        message = "".join(char if char.isprintable() else " " for char in message)
        if len(message) > 512:
            message = f"{message[:509]}..."
        sys.stderr.write("  %s\n" % message)


def port_available(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
        except OSError:
            return False
    return True


def choose_port(host: str, requested: int | None) -> int:
    if requested:
        if port_available(host, requested):
            return requested
        print(f"Port {requested} is busy; looking for a free port instead…")
    for port in PORT_RANGE:
        if port_available(host, port):
            return port
    raise SystemExit("No free port in 8005–8025. Pass --port with another number.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Serve the BIND Workbench.")
    parser.add_argument("--port", type=int, default=None, help="preferred port (default: first free 8005–8025)")
    parser.add_argument("--host", default="127.0.0.1", help="bind address (default: 127.0.0.1)")
    parser.add_argument("--no-browser", action="store_true", help="do not open a browser")
    args = parser.parse_args()

    warn_insecure_env_file(ENV_FILE)
    if not (WEB_ROOT / "index.html").exists() or not LOGIN_PAGE.exists():
        print(f"Could not find {WEB_ROOT / 'index.html'} or {LOGIN_PAGE}.", file=sys.stderr)
        return 1
    if AUTH_ENABLED and len(AUTH_PASSWORD) < 12:
        print("Warning: BIND_WORKBENCH_PASSWORD is shorter than 12 characters.", file=sys.stderr)

    port = choose_port(args.host, args.port)
    handler = functools.partial(Handler, directory=str(WEB_ROOT))
    try:
        server = http.server.ThreadingHTTPServer((args.host, port), handler)
    except OSError as exc:
        print(f"Could not start the server: {exc}", file=sys.stderr)
        return 1

    shown_host = "localhost" if args.host in ("127.0.0.1", "0.0.0.0") else args.host
    url = f"http://{shown_host}:{port}/"

    print()
    print("  BIND Workbench")
    print("  --------------")
    print(f"  Serving : {WEB_ROOT}")
    print(f"  Open    : {url}")
    print(f"  Env file: {ENV_FILE if ENV_FILE.exists() else 'not present (optional)'}")
    print(f"  Auth    : {'password required (BIND_WORKBENCH_PASSWORD set)' if AUTH_ENABLED else 'disabled (local/default)'}")
    print(f"  Upload  : {'password required' if UPLOAD_AUTH_ENABLED else 'no import password'}")
    print("  Privacy : configs stay in your browser; live DNS is opt-in")
    print("  Stop    : Ctrl+C")
    print()

    if not args.no_browser:
        timer = threading.Timer(0.7, lambda: webbrowser.open(url))
        timer.daemon = True
        timer.start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
