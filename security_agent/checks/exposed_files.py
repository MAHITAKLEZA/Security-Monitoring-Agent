"""Exposed sensitive files: .env, VCS metadata, backups, phpinfo, keys, directory listings, source maps.

Each probe is validated by content (not just HTTP 200) and compared with the site's soft-404 page
to avoid false positives from SPA/catch-all routing.
"""

import hashlib
import re
import secrets
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import requests

from ..models import Finding, Severity as S

NAME = "exposed_files"


def _rx(pattern):
    compiled = re.compile(pattern.encode(), re.I | re.M)
    return lambda body: bool(compiled.search(body))


def _magic(*signatures):
    return lambda body: any(body.startswith(sig) for sig in signatures)


_ENV = _rx(r"^\s*(export\s+)?[A-Z][A-Z0-9_]{2,}\s*=\s*\S")
_SQL = _rx(r"(CREATE TABLE|INSERT INTO|DROP TABLE|-- MySQL dump|PostgreSQL database dump)")
_ARCHIVE = _magic(b"PK\x03\x04", b"\x1f\x8b", b"7z\xbc\xaf\x27\x1c", b"Rar!", b"BZh")
_DIR_LISTING = _rx(r"<title>\s*Index of /")

# (path, severity, title, matcher, html_allowed)
PROBES = [
    ("/.env", S.CRITICAL, "Environment file (.env) exposed", _ENV, False),
    ("/.env.local", S.CRITICAL, "Environment file (.env.local) exposed", _ENV, False),
    ("/.env.production", S.CRITICAL, "Environment file (.env.production) exposed", _ENV, False),
    ("/.env.development", S.CRITICAL, "Environment file (.env.development) exposed", _ENV, False),
    ("/.env.backup", S.CRITICAL, "Environment backup file exposed", _ENV, False),
    ("/.git/HEAD", S.CRITICAL, "Git repository exposed (.git/HEAD)", _rx(r"^ref:\s*refs/|^[0-9a-f]{40}\s*$"), False),
    ("/.git/config", S.CRITICAL, "Git config exposed", _rx(r"\[core\]"), False),
    ("/.svn/entries", S.HIGH, "SVN metadata exposed", _rx(r"^\d+\s*$|svn:"), False),
    ("/.hg/hgrc", S.HIGH, "Mercurial metadata exposed", _rx(r"\[paths\]"), False),
    ("/.DS_Store", S.MEDIUM, ".DS_Store file exposed (directory structure leak)", _magic(b"\x00\x00\x00\x01Bud1"), False),
    ("/.htpasswd", S.CRITICAL, ".htpasswd credentials file exposed", _rx(r"^[^:\s]+:(\$apr1\$|\$2[aby]\$|\{SHA\}|[./0-9A-Za-z]{13}$)"), False),
    ("/.npmrc", S.HIGH, ".npmrc exposed", _rx(r"_authToken|registry="), False),
    ("/.aws/credentials", S.CRITICAL, "AWS credentials file exposed", _rx(r"aws_access_key_id"), False),
    ("/id_rsa", S.CRITICAL, "Private SSH key exposed", _rx(r"-----BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY"), False),
    ("/.ssh/id_rsa", S.CRITICAL, "Private SSH key exposed", _rx(r"-----BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY"), False),
    ("/.vscode/sftp.json", S.CRITICAL, "VS Code SFTP config (credentials) exposed", _rx(r"\"(password|host)\"\s*:"), False),
    ("/docker-compose.yml", S.HIGH, "docker-compose.yml exposed", _rx(r"^services:|^version:"), False),
    ("/Dockerfile", S.MEDIUM, "Dockerfile exposed", _rx(r"^FROM\s+\S+"), False),
    ("/package.json", S.LOW, "package.json exposed (dependency disclosure)", _rx(r"\"dependencies\"\s*:"), False),
    ("/composer.json", S.LOW, "composer.json exposed", _rx(r"\"require\"\s*:"), False),
    ("/web.config", S.HIGH, "web.config exposed", _rx(r"<configuration"), False),
    ("/wp-config.php.bak", S.CRITICAL, "WordPress config backup exposed", _rx(r"DB_PASSWORD"), False),
    ("/wp-config.php~", S.CRITICAL, "WordPress config backup exposed", _rx(r"DB_PASSWORD"), False),
    ("/config.php.bak", S.CRITICAL, "PHP config backup exposed", _rx(r"<\?php"), False),
    ("/backup.zip", S.CRITICAL, "Backup archive exposed", _ARCHIVE, False),
    ("/backup.tar.gz", S.CRITICAL, "Backup archive exposed", _ARCHIVE, False),
    ("/site.zip", S.CRITICAL, "Site archive exposed", _ARCHIVE, False),
    ("/www.zip", S.CRITICAL, "Site archive exposed", _ARCHIVE, False),
    ("/db.sql", S.CRITICAL, "Database dump exposed", _SQL, False),
    ("/dump.sql", S.CRITICAL, "Database dump exposed", _SQL, False),
    ("/database.sql", S.CRITICAL, "Database dump exposed", _SQL, False),
    ("/backup.sql", S.CRITICAL, "Database dump exposed", _SQL, False),
    ("/error.log", S.MEDIUM, "Error log exposed", _rx(r"(error|warn|exception|stack)"), False),
    ("/debug.log", S.MEDIUM, "Debug log exposed", _rx(r"(error|warn|exception|debug)"), False),
    ("/phpinfo.php", S.HIGH, "phpinfo() page exposed", _rx(r"phpinfo\(\)|PHP Version"), True),
    ("/info.php", S.HIGH, "phpinfo() page exposed", _rx(r"phpinfo\(\)|PHP Version"), True),
    ("/server-status", S.MEDIUM, "Apache server-status exposed", _rx(r"Apache Server Status"), True),
    ("/nginx_status", S.LOW, "nginx stub_status exposed", _rx(r"Active connections:"), False),
    ("/.next/BUILD_ID", S.MEDIUM, "Next.js build directory exposed", _rx(r"^[\w-]{6,}\s*$"), False),
    ("/uploads/", S.MEDIUM, "Directory listing enabled (/uploads/)", _DIR_LISTING, True),
    ("/backup/", S.HIGH, "Directory listing enabled (/backup/)", _DIR_LISTING, True),
    ("/static/", S.LOW, "Directory listing enabled (/static/)", _DIR_LISTING, True),
    ("/images/", S.LOW, "Directory listing enabled (/images/)", _DIR_LISTING, True),
    ("/_next/static/", S.LOW, "Directory listing enabled (/_next/static/)", _DIR_LISTING, True),
]


def _looks_like_html(body):
    head = body[:512].lstrip().lower()
    return head.startswith((b"<!doctype", b"<html", b"<head", b"<body")) or b"<html" in head


def _digest(body):
    return hashlib.sha256(body).hexdigest()


def _probe(ctx, path, matcher, html_ok, soft404):
    try:
        resp, body = ctx.fetch_limited(path)
    except requests.RequestException:
        return None
    if resp.status_code != 200 or not body or _digest(body) == soft404:
        return None
    if not html_ok and _looks_like_html(body):
        return None
    if matcher is not None and not matcher(body):
        return None
    return {"url": resp.url, "status": resp.status_code, "bytes_sampled": len(body),
            "content_type": resp.headers.get("Content-Type", "")}


def _source_maps(ctx, cfg):
    _, page = ctx.home
    scripts = [s["src"] for s in page.scripts if not ctx.is_external(s["src"])][: cfg.get("max_sourcemap_checks", 5)]
    exposed = []
    for src in scripts:
        map_url = src.split("?")[0] + ".map"
        try:
            resp, body = ctx.fetch_limited(map_url, max_bytes=4096)
        except requests.RequestException:
            continue
        if resp.status_code == 200 and (b'"mappings"' in body or b'"sources"' in body):
            exposed.append(urlparse(map_url).path)
    if not exposed:
        return []
    return [Finding(NAME, "JavaScript source maps are publicly accessible", S.MEDIUM,
                    f"{len(exposed)} of {len(scripts)} sampled bundles have downloadable .map files, "
                    "exposing original front-end source code.",
                    "Disable production source maps (Next.js: productionBrowserSourceMaps: false) or block *.map.",
                    {"source_maps": exposed})]


def run(ctx, cfg, state):
    try:
        _, sample = ctx.fetch_limited(f"/__secmon_{secrets.token_hex(6)}")
        soft404 = _digest(sample) if sample else None
    except requests.RequestException:
        soft404 = None

    probes = [(p, sev, title, m, html_ok) for p, sev, title, m, html_ok in PROBES]
    for extra in cfg.get("extra_paths") or []:
        pattern = extra.get("pattern")
        probes.append((extra["path"], S.parse(extra.get("severity", "MEDIUM")), f"Sensitive path exposed: {extra['path']}",
                       _rx(pattern) if pattern else None, bool(pattern)))

    findings = []
    with ThreadPoolExecutor(max_workers=cfg.get("max_workers", 4)) as pool:
        futures = [(p, pool.submit(_probe, ctx, p[0], p[3], p[4], soft404)) for p in probes]
        for (path, severity, title, _, _), future in futures:
            hit = future.result()
            if hit:
                findings.append(Finding(NAME, title, severity, f"{path} is publicly readable.",
                                        "Remove the file from the web root or deny access at the web server "
                                        "(e.g. nginx: location ~ /\\. { deny all; }). Rotate any exposed secrets.",
                                        hit))

    findings.extend(_source_maps(ctx, cfg))
    if not findings:
        findings.append(Finding(NAME, "No exposed sensitive files found", S.INFO,
                                f"{len(probes)} common sensitive paths checked."))
    return findings
