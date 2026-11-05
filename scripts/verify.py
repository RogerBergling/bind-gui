#!/usr/bin/env python3
"""Static repository verification for BIND Workbench.

This is intentionally dependency-free. It checks the things a browser smoke
test cannot: required files, import graph integrity, packaging metadata,
security-header consistency and documentation promises.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PUBLIC = ROOT / "public"
JS_ROOT = PUBLIC / "assets" / "js"

REQUIRED = [
    "README.md",
    "LICENSE",
    "Dockerfile",
    "compose.yaml",
    "package.json",
    ".dockerignore",
    ".editorconfig",
    ".env.example",
    "start.py",
    "public/index.html",
    "public/login.html",
    "public/login.js",
    "public/LICENSE.txt",
    "public/version.json",
    "public/assets/css/app.css",
    "public/assets/js/app.js",
    "scripts/verify.py",
    "scripts/smoke.py",
    "scripts/check-js.mjs",
    ".github/workflows/ci.yml",
    ".github/workflows/docker-publish.yml",
]

ERRORS: list[str] = []
WARNINGS: list[str] = []


def fail(message: str) -> None:
    ERRORS.append(message)


def warn(message: str) -> None:
    WARNINGS.append(message)


def read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        fail(f"{path.relative_to(ROOT)} is not valid UTF-8")
        return ""


def check_required() -> None:
    for relative in REQUIRED:
        path = ROOT / relative
        if not path.exists():
            fail(f"Missing required file: {relative}")
        elif path.is_file() and path.stat().st_size == 0:
            fail(f"Empty required file: {relative}")


def check_json() -> None:
    for relative in ["package.json", "public/version.json"]:
        path = ROOT / relative
        if not path.exists():
            continue
        try:
            data = json.loads(read(path))
        except json.JSONDecodeError as exc:
            fail(f"{relative} is not valid JSON: {exc}")
            continue
        if not isinstance(data, dict):
            fail(f"{relative} must contain a JSON object")
    package = json.loads(read(ROOT / "package.json")) if (ROOT / "package.json").exists() else {}
    version = json.loads(read(PUBLIC / "version.json")) if (PUBLIC / "version.json").exists() else {}
    if package.get("license") != "MIT":
        fail("package.json must declare the MIT license")
    if package.get("name") != "bind-workbench":
        fail("package.json name must be bind-workbench")
    if not re.match(r"^\d+\.\d+\.\d+", str(package.get("version", ""))):
        fail("package.json version must be semver-like")
    if version.get("version") not in (package.get("version"), "dev"):
        warn("public/version.json version is not the development placeholder")


def check_readme() -> None:
    text = read(ROOT / "README.md")
    required_sections = [
        "BIND Workbench",
        "Quick start",
        "What it does",
        "Import",
        "Compare",
        "Analyze",
        "DNSSEC",
        "Live DNS",
        "Security",
        "Development",
        "GHCR",
        "MIT",
        "Limitations",
        "Password protection",
    ]
    for section in required_sections:
        if section.lower() not in text.lower():
            fail(f"README.md is missing the “{section}” section or term")
    if "Describe how to install" in text:
        fail("README.md still contains the template placeholder")
    if len(text) < 5000:
        fail("README.md is suspiciously short for the documented feature set")


def check_html() -> None:
    html = read(PUBLIC / "index.html")
    required = [
        'id="view"',
        'id="theme-toggle"',
        "BIND Workbench",
        "assets/css/app.css",
        "assets/js/app.js",
        "Content-Security-Policy",
    ]
    for term in required:
        if term not in html:
            # CSP is set by the server, not the HTML; don't require it there.
            if term == "Content-Security-Policy":
                continue
            fail(f"public/index.html is missing {term!r}")
    if re.search(r"<script(?![^>]*\bsrc=)", html, re.IGNORECASE):
        fail("public/index.html contains an inline script; CSP forbids it")
    if re.search(r"<link[^>]+href=[\"']https?://", html, re.IGNORECASE):
        fail("public/index.html loads an external stylesheet or asset")
    if re.search(r"<script[^>]+src=[\"']https?://", html, re.IGNORECASE):
        fail("public/index.html loads an external script")
    if "fonts.googleapis" in html or "cdn.jsdelivr" in html or "unpkg.com" in html:
        fail("public/index.html references a third-party asset host")


def check_login_page() -> None:
    html = read(PUBLIC / "login.html")
    for term in ["Unlock the workbench", "login-password", "/login.js", "/assets/css/app.css"]:
        if term not in html:
            fail(f"public/login.html is missing {term!r}")
    if re.search(r"<script(?![^>]*\bsrc=)", html, re.IGNORECASE):
        fail("public/login.html contains an inline script")
    script = read(PUBLIC / "login.js")
    for term in ["/api/auth-status", "/api/login", "location.reload", "Invalid password"]:
        if term not in script:
            fail(f"public/login.js is missing {term!r}")
    if "BIND_WORKBENCH_PASSWORD" in script:
        fail("login.js must not contain the server password")


def check_start_py() -> None:
    text = read(ROOT / "start.py")
    for term in [
        "Content-Security-Policy",
        "connect-src 'self' https://cloudflare-dns.com https://dns.google;",
        "frame-ancestors 'none'",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "no-store",
        "do_GET",
        "do_HEAD",
        "list_directory",
        "--no-browser",
        "BIND_WORKBENCH_PASSWORD",
        "hmac.compare_digest",
        "HttpOnly",
        "SameSite=Strict",
        "/api/login",
        "/api/auth-status",
        "Set-Cookie",
    ]:
        if term not in text:
            fail(f"start.py is missing {term!r}")
    if "unsafe-eval" in text:
        fail("start.py CSP must not allow unsafe-eval")
    if "connect-src *" in text or "connect-src 'self' *" in text:
        fail("start.py CSP must not allow arbitrary outbound origins")
    if "BIND_WORKBENCH_PASSWORD" not in compose_for_check():
        fail("compose.yaml does not expose BIND_WORKBENCH_PASSWORD")


def compose_for_check() -> str:
    return read(ROOT / "compose.yaml")


def check_docker() -> None:
    dockerfile = read(ROOT / "Dockerfile")
    compose = read(ROOT / "compose.yaml")
    for term in ["USER 10001:10001", "HEALTHCHECK", "python:3.12-alpine", "COPY --chown=app:app public"]:
        if term not in dockerfile:
            fail(f"Dockerfile is missing {term!r}")
    if "ADD http" in dockerfile:
        fail("Dockerfile must not fetch remote artifacts with ADD")
    for term in ["read_only: true", "cap_drop:", "no-new-privileges:true", "8005:8005"]:
        if term not in compose:
            fail(f"compose.yaml is missing {term!r}")
    if "/var/run/docker.sock" in compose:
        fail("compose.yaml must not mount the Docker socket")


def check_workflows() -> None:
    ci = read(ROOT / ".github/workflows/ci.yml")
    publish = read(ROOT / ".github/workflows/docker-publish.yml")
    for term in ["node --test", "scripts/verify.py", "scripts/smoke.py", "docker/build-push-action"]:
        if term not in ci:
            fail(f"CI workflow is missing {term!r}")
    for term in ["packages: write", "ghcr.io", "linux/amd64,linux/arm64", "provenance: true", "sbom: true"]:
        if term not in publish:
            fail(f"Publish workflow is missing {term!r}")


def check_imports() -> None:
    import_re = re.compile(r"(?:from\s+|import\s*\()\s*['\"]([^'\"]+\.js)['\"]")
    for path in sorted(JS_ROOT.rglob("*.js")):
        text = read(path)
        for specifier in import_re.findall(text):
            if specifier.startswith(("http://", "https://")):
                fail(f"{path.relative_to(ROOT)} imports a remote module: {specifier}")
                continue
            if not specifier.startswith("."):
                continue
            target = (path.parent / specifier).resolve()
            if not target.exists():
                fail(f"Broken import in {path.relative_to(ROOT)}: {specifier}")
            elif not str(target).startswith(str(JS_ROOT.resolve())):
                fail(f"Import escapes the JS root in {path.relative_to(ROOT)}: {specifier}")
    # Every page module should exist and be imported by the router.
    app = read(JS_ROOT / "app.js")
    for page in ["home", "workbench", "analyze", "zones", "live", "compare", "history", "learn", "glossary", "reference", "security"]:
        if f"./pages/{page}.js" not in app:
            fail(f"app.js does not route to pages/{page}.js")
        if not (JS_ROOT / "pages" / f"{page}.js").exists():
            fail(f"Missing page module pages/{page}.js")


def check_assets() -> None:
    css = read(PUBLIC / "assets" / "css" / "app.css")
    for term in ["--bg", ".workbench-shell", ".diff", ".record-table", ".finding-card", ".chain-step", ".article-layout", "@media"]:
        if term not in css:
            fail(f"app.css is missing {term!r}")
    if "url(http" in css.replace(" ", ""):
        fail("app.css must not load remote assets")
    index = read(PUBLIC / "index.html")
    for href in re.findall(r'(?:href|src)=["\'](/[^"\']+)["\']', index):
        if href.startswith("//"):
            continue
        target = PUBLIC / href.lstrip("/")
        if not target.exists():
            fail(f"index.html references missing asset: {href}")
    # The favicon is a data URL; no external request.
    if "fonts.googleapis.com" in css:
        fail("app.css references Google Fonts")


def check_license() -> None:
    license_text = read(ROOT / "LICENSE")
    copy = read(PUBLIC / "LICENSE.txt")
    if "MIT License" not in license_text:
        fail("LICENSE is not an MIT license")
    if license_text != copy:
        fail("public/LICENSE.txt must match LICENSE")
    if "Copyright (c) 2026" not in license_text:
        warn("LICENSE does not contain the expected copyright year")


def check_docs_links() -> None:
    readme = read(ROOT / "README.md")
    files_in_readme = re.findall(r"\[[^\]]+\]\(([^)]+)\)", readme)
    for link in files_in_readme:
        if link.startswith(("http://", "https://", "#", "mailto:")):
            continue
        target = (ROOT / link.split("#", 1)[0]).resolve()
        if not target.exists():
            fail(f"README.md links to a missing local path: {link}")


def main() -> int:
    check_required()
    if ERRORS:
        # Continuing may produce noisy secondary errors, but the required-file
        # list is cheap and useful in one pass.
        pass
    check_json()
    check_readme()
    check_html()
    check_login_page()
    check_start_py()
    check_docker()
    check_workflows()
    check_imports()
    check_assets()
    check_license()
    check_docs_links()

    print("BIND Workbench repository verification")
    print(f"  JavaScript modules : {len(list(JS_ROOT.rglob('*.js')))}")
    print(f"  Errors             : {len(ERRORS)}")
    print(f"  Warnings           : {len(WARNINGS)}")
    for warning in WARNINGS:
        print(f"  warning: {warning}")
    for error in ERRORS:
        print(f"  error: {error}")
    if ERRORS:
        return 1
    print("  OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
