"""Inside scan over SSH/SFTP for sites that aren't WordPress (React, plain HTML, PHP, Laravel, Node...). Logs in with
a username and SSH key, walks the website folder read-only and reports what an outside scan can't see: web shells
and injected code in server files, cloaking rules in .htaccess, PHP in upload or media folders, secrets and backups
inside the web folder, files anyone on the server can change, and server-side code that appeared or changed since
the last scan.

The server's host key is pinned when the site is added: if it changes later, the scan stops and reports it (a moved
server, or someone in the middle). Findings are reported under the `malware` check as "Inside scan: ...", next to
the WordPress inside scan."""

import hashlib
import io
import re
import socket
import stat
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from jp_seo_agent.files import CODE_EXT, DISGUISED_EXT, HTACCESS_SIGS, MEDIA_EXT, PHP_OPEN_TAG, PHP_SIGS

from ..models import Finding, Severity as S
from .malware import PATTERNS as JS_SIGS
from .malware_inside import SVG_SCRIPT

TAG = "Inside scan"
TIMEOUT = 20
MAX_FILES = 20000
MAX_READS = 20000          # file contents read per scan (every file); any beyond this are read on the next scans
BINARY_HEAD_BYTES = 65536  # media, fonts, PDFs...: the start of the file is enough to spot a program or PHP inside
MAX_ARCHIVE_BYTES = 8_000_000
MAX_ARCHIVE_MEMBERS = 500
MAX_ARCHIVE_MEMBER_BYTES = 500_000
ARCHIVE = object()         # marker: a .zip, opened to look at what is inside
BINARY = object()          # marker: a binary file, only its first bytes are checked
MAX_READ_BYTES = 2_000_000
MAX_GENERIC_BYTES = 1_000_000   # files with no recognised type are read up to this size
GENERIC = object()         # marker: check a file of unknown type by its content
# Files that are binary by nature and not worth reading (a real program is caught by name or location instead)
BINARY_EXT = re.compile(r"\.(?:mp[34]|avi|mov|mkv|webm|wmv|flv|ogg|wav|flac|woff2?|ttf|otf|eot|pdf|zip|rar|7z|gz|tgz|"
                        r"tar|bz2|xz|iso|mo|psd|ai|docx?|xlsx?|pptx?|map|min\.css|css|lock|sqlite3?|db)$", re.I)
MAX_LOCATIONS = 20
SKIP_DIRS = {"node_modules", ".git", ".svn", ".hg", ".cache", "cache", ".npm", ".yarn"}
SERVER_CODE = re.compile(r"(?:\.(?:php\d?|phtml|phar|pht|phps|inc|cgi|pl|py|sh|asp|aspx|jsp)|^\.htaccess|"
                         r"^\.user\.ini|^php\.ini)$", re.I)
CONFIG_FILES = re.compile(r"^(?:\.htaccess|\.user\.ini|php\.ini)$", re.I)
WEB_CODE = re.compile(r"\.(?:m?js|cjs|html?)$", re.I)
UPLOAD_DIRS = {"uploads", "upload", "images", "image", "img", "media", "files", "static", "assets", "photos"}
PROGRAM_EXT = re.compile(r"\.(?:exe|dll|msi|bat|cmd|scr|vbs|hta|jar|elf|bin)$", re.I)
SENSITIVE = re.compile(r"(?:^\.env(?:\..+)?$|\.(?:sql|sql\.gz|bak|old|orig|swp|dump|tar|tar\.gz|tgz|zip|rar|7z|"
                       r"log|pem|key|p12|pfx)$|^id_(?:rsa|dsa|ecdsa|ed25519)$|^\.git$|^\.htpasswd$|"
                       r"^(?:wp-config|config|settings)\.php\..+$)", re.I)


class SSHError(Exception):
    """Couldn't connect, log in or open the website folder."""


class HostKeyChanged(SSHError):
    pass


def load_key(text):
    """A paramiko key from private key text (OpenSSH or PEM; Ed25519, ECDSA or RSA, without a passphrase)."""
    import paramiko
    for cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return cls.from_private_key(io.StringIO(text))
        except paramiko.PasswordRequiredException as exc:
            raise SSHError("This private key has a passphrase. Use a key without one (ssh-keygen ... -N \"\") or "
                           "let the dashboard generate the key.") from exc
        except (paramiko.SSHException, ValueError):
            continue
    raise SSHError("That doesn't look like a private key (it starts with -----BEGIN ... PRIVATE KEY-----).")


def generate_key(comment="kleza-security-agent"):
    """(private key in OpenSSH format, public key line) for a new Ed25519 key pair."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                                serialization.NoEncryption()).decode()
    public = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    return private, f"{public} {comment}"


def connect(host, port, username, key_text, pinned=None):
    """(transport, sftp, host key line). Refuses a server whose key doesn't match `pinned`."""
    try:
        import paramiko
    except ImportError as exc:
        raise SSHError("The SSH inside scan needs the paramiko package: pip install -r requirements.txt") from exc
    pkey = load_key(key_text)
    try:
        sock = socket.create_connection((host, int(port)), timeout=TIMEOUT)
    except OSError as exc:
        raise SSHError(f"Can't reach {host}:{port} ({exc.__class__.__name__}). Check the host, the port (often 22; "
                       "Hostinger uses 65002) and that SSH access is turned on in the hosting panel.") from exc
    transport = paramiko.Transport(sock)
    try:
        transport.banner_timeout = transport.auth_timeout = TIMEOUT
        transport.start_client(timeout=TIMEOUT)
        server_key = transport.get_remote_server_key()
        host_key = f"{server_key.get_name()} {server_key.get_base64()}"
        if pinned and pinned != host_key:
            raise HostKeyChanged(f"The server's SSH key changed (now {_fingerprint(server_key)}). If the site moved to "
                                 "a new server, remove the site and add it again; otherwise someone may be "
                                 "intercepting the connection.")
        try:
            transport.auth_publickey(username, pkey)
        except paramiko.AuthenticationException as exc:
            raise SSHError(f"The server refused the key for user '{username}'. Add the public key to the server "
                           "(cPanel: Security > SSH Access > Manage SSH Keys > Import, then Authorize) and check "
                           "the username.") from exc
        sftp = paramiko.SFTPClient.from_transport(transport)
        sftp.get_channel().settimeout(TIMEOUT * 3)
        return transport, sftp, host_key
    except SSHError:
        transport.close()
        raise
    except (paramiko.SSHException, OSError, EOFError) as exc:
        transport.close()
        raise SSHError(f"SSH connection to {host}:{port} failed: {exc.__class__.__name__}: {exc}"[:300]) from exc


def _fingerprint(key):
    import base64
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


PORTS = (22, 65002, 2222)    # the usual SSH ports: standard, Hostinger, some shared hosts
INDEX = re.compile(r"^index\.(?:html?|php)$", re.I)


def _folders(domain):
    """Where hosts usually keep a site's files, most specific first (relative paths start at the login folder)."""
    names = [domain] + ([domain[4:]] if domain.startswith("www.") else [f"www.{domain}"])
    out = []
    for d in names:
        out += [f"domains/{d}/public_html", f"{d}/public_html", f"public_html/{d}", d, f"/var/www/{d}/public_html",
                f"/var/www/{d}/html", f"/var/www/{d}/dist", f"/var/www/{d}/build", f"/var/www/{d}"]
    return out + ["public_html", "www", "htdocs", "httpdocs", "html", "/var/www/html", "/usr/share/nginx/html"]


def _find_root(sftp, domain):
    """The first usual website folder that holds an index file (or, failing that, the first one that exists)."""
    existing = None
    for path in _folders(domain):
        try:
            if not stat.S_ISDIR(sftp.stat(path).st_mode):
                continue
            names = sftp.listdir(path)
        except OSError:
            continue
        if any(INDEX.match(n) for n in names):
            return sftp.normalize(path)
        existing = existing or sftp.normalize(path)
    if existing:
        return existing
    raise SSHError("Logged in, but couldn't find the website folder. Open Advanced and enter it, e.g. "
                   "/home/<user>/public_html or /var/www/site.")


def probe(host, port, username, key_text, web_root=None, domain=""):
    """Test the login and the folder when a site is added: (host key line, port, absolute website folder).
    With no port, the usual SSH ports are tried; with no folder, the usual website folders are searched."""
    for i, p in enumerate([port] if port else PORTS):
        try:
            transport, sftp, host_key = connect(host, p, username, key_text)
            port = p
            break
        except SSHError as exc:   # only "can't reach" moves on to the next port
            if port or i == len(PORTS) - 1 or not str(exc).startswith("Can't reach"):
                if not port and str(exc).startswith("Can't reach"):
                    raise SSHError(f"Can't reach SSH on {host} (tried ports {', '.join(map(str, PORTS))}). Turn on "
                                   "SSH access in the hosting panel, or open Advanced and enter the server's SSH "
                                   "host and port (a site behind Cloudflare needs the server's own address).") from exc
                raise
    try:
        if not web_root:
            return host_key, port, _find_root(sftp, domain)
        try:
            root = sftp.normalize(web_root)
            if not stat.S_ISDIR(sftp.stat(root).st_mode):
                raise SSHError(f"{web_root} is a file, not a folder.")
            sftp.listdir(root)
        except OSError as exc:
            raise SSHError(f"Logged in, but can't open the website folder {web_root} ({exc}). Use the folder that "
                           "holds the site's files, e.g. /home/<user>/public_html or /var/www/site.") from exc
        return host_key, port, root
    finally:
        transport.close()


def _key_text(cfg):
    path = cfg.get("key_file")
    if not path:
        raise SSHError("No private key is set for this site (key_file).")
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise SSHError(f"Can't read the private key file {path}.") from exc


def _walk(sftp, root, notes):
    """{relative path: (size, mtime, mode)} of every regular file under root (symlinks are not followed)."""
    files, stack = {}, [""]
    while stack and len(files) < MAX_FILES:
        rel_dir = stack.pop()
        try:
            entries = sftp.listdir_attr(f"{root}/{rel_dir}" if rel_dir else root)
        except OSError:
            notes.append(f"can't list {rel_dir or '/'}")
            continue
        for e in entries:
            rel = f"{rel_dir}/{e.filename}" if rel_dir else e.filename
            mode = e.st_mode or 0
            if stat.S_ISDIR(mode):
                if e.filename in SKIP_DIRS:
                    if e.filename == ".git":
                        files[rel] = (0, int(e.st_mtime or 0), mode)   # reported as a sensitive item
                    continue
                stack.append(rel)
                if mode & 0o002:
                    files.setdefault(rel + "/", (0, int(e.st_mtime or 0), mode))
            elif stat.S_ISREG(mode):
                files[rel] = (int(e.st_size or 0), int(e.st_mtime or 0), mode)
    if len(files) >= MAX_FILES:
        notes.append(f"stopped at {MAX_FILES} files")
    return files


def _sigs(name):
    if CONFIG_FILES.match(name):
        return HTACCESS_SIGS
    if CODE_EXT.search(name):
        return PHP_SIGS
    if WEB_CODE.search(name):
        return [(n, rx, s.name) for n, rx, s in JS_SIGS]
    if name.lower().endswith(".svg"):
        return [("script inside an SVG image", SVG_SCRIPT, "HIGH")]
    if MEDIA_EXT.search(name):
        return [("PHP code hidden in an image", PHP_OPEN_TAG, "CRITICAL")]
    if name.lower().endswith(".zip"):
        return ARCHIVE
    if BINARY_EXT.search(name):
        return BINARY
    return GENERIC   # any other file (no extension, .txt, .ico, .json, .log, ...) is checked by its content


def _read_limit(sigs):
    return MAX_ARCHIVE_BYTES if sigs is ARCHIVE else BINARY_HEAD_BYTES if sigs is BINARY else \
        MAX_GENERIC_BYTES if sigs is GENERIC else MAX_READ_BYTES


def _archive_hits(data):
    """Open a zip and look at what is inside: server scripts, and malicious code in the small ones."""
    hits = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for info in zf.infolist()[:MAX_ARCHIVE_MEMBERS]:
                leaf = info.filename.rsplit("/", 1)[-1]
                if not SERVER_CODE.search(leaf) or info.is_dir():
                    continue
                hits.append(("server script inside a zip archive", S.MEDIUM, info.filename))
                if info.file_size <= MAX_ARCHIVE_MEMBER_BYTES and CODE_EXT.search(leaf):
                    text = zf.read(info).decode("utf-8", "ignore")
                    hits.extend((n, sev, f"{info.filename}: {snip}") for n, sev, snip in _scan_content(text, PHP_SIGS))
    except (zipfile.BadZipFile, NotImplementedError, RuntimeError, OSError):
        pass
    return hits


def _generic_hits(data, text):
    """Dangerous content in a file whose name doesn't say it is code: a compiled program, a script, or PHP."""
    hits = []
    if data.startswith((b"\x7fELF", b"MZ")):
        hits.append(("compiled program hidden in a non-program file", S.HIGH, repr(data[:12])))
    elif data.startswith(b"#!"):
        hits.append(("script (shebang) in an unexpected file", S.MEDIUM, text[:100].replace("\n", " ")))
    if PHP_OPEN_TAG.search(text):
        m = PHP_OPEN_TAG.search(text)
        hits.append(("PHP code inside a file that isn't a PHP file", S.HIGH,
                     text[max(m.start() - 40, 0):m.end() + 100].replace("\n", " ")))
        hits.extend(_scan_content(text, PHP_SIGS))
    return hits


def _scan_content(text, sigs):
    hits = []
    for name, regex, severity in sigs:
        m = regex.search(text)
        if m:
            start = max(m.start() - 60, 0)
            hits.append((name, S.parse(severity), text[start:m.end() + 60].replace("\n", " ")))
    return hits


def _finding(title, severity, items, detail, recommendation):
    locs = [{"location": p, "snippet": snip} for p, snip in items[:MAX_LOCATIONS]]
    more = f" (+{len(items) - MAX_LOCATIONS} more)" if len(items) > MAX_LOCATIONS else ""
    return Finding("malware", f"{TAG}: {title}", severity,
                   f"{detail}: " + ", ".join(p for p, _ in items[:MAX_LOCATIONS]) + more,
                   recommendation, {"locations": locs, "via": "ssh"})


def scan(sftp, root, state):
    findings, notes = [], []
    prev = state.get("files") if state.get("root") == root else None
    files = _walk(sftp, root, notes)
    old = prev or {}
    new_paths = [p for p in files if p not in old] if prev is not None else []
    changed = [p for p in files if p in old and tuple(old[p][:2]) != files[p][:2]]

    # Which contents to read: new and changed files first, then files never read before (spread over scans)
    hashes = {p: (old[p][2] if p in old and len(old[p]) > 2 and p not in changed else None) for p in files}
    size_cap = lambda sigs: {id(ARCHIVE): MAX_ARCHIVE_BYTES, id(GENERIC): MAX_GENERIC_BYTES,
                             id(BINARY): float("inf")}.get(id(sigs), MAX_READ_BYTES)
    readable = [p for p in files if not p.endswith("/") and files[p][0] <= size_cap(_sigs(p.rsplit("/", 1)[-1]))]
    # Images are read last on the first scan (there can be thousands), but an image that just appeared is read at once
    queue = [p for p in readable if p in new_paths or p in changed] + \
            [p for p in readable if p not in new_paths and p not in changed and hashes[p] is None
             and not MEDIA_EXT.search(p)] + \
            [p for p in readable if p not in new_paths and p not in changed and hashes[p] is None
             and MEDIA_EXT.search(p)]
    content_changed, hits = set(), {}
    for path in queue[:MAX_READS]:
        sigs = _sigs(path.rsplit("/", 1)[-1])
        limit = _read_limit(sigs)
        try:
            with sftp.open(f"{root}/{path}", "rb") as fh:
                fh.prefetch(min(files[path][0], limit))
                data = fh.read(limit)
        except OSError:
            continue
        digest = hashlib.sha256(data).hexdigest()
        if path in old and len(old[path]) > 2 and old[path][2] and old[path][2] != digest:
            content_changed.add(path)
        hashes[path] = digest
        text = data.decode("utf-8", "ignore")
        if sigs is ARCHIVE:
            found = _archive_hits(data)
        elif sigs in (GENERIC, BINARY):
            found = _generic_hits(data, text)
        else:
            found = _scan_content(text, sigs)
        for name, severity, snippet in found:
            hits.setdefault(name, []).append((path, snippet, severity))
    if len(queue) > MAX_READS:
        notes.append(f"{len(queue) - MAX_READS} file(s) left to read on the next scans")

    for name, items in sorted(hits.items(), key=lambda kv: -max(i[2] for i in kv[1])):
        findings.append(_finding(f"Suspicious code on the server ({name})", max(i[2] for i in items),
                                 [(p, s) for p, s, _ in items], "Found in",
                                 "Open these files on the server. If your team didn't write this code, treat the site "
                                 "as compromised: take a backup for evidence, restore the files from your clean "
                                 "source or build, then change the SSH, hosting and database passwords."))

    php_in_uploads = [p for p in files if SERVER_CODE.search(p.rsplit("/", 1)[-1]) and not CONFIG_FILES.match(
        p.rsplit("/", 1)[-1]) and UPLOAD_DIRS & {seg.lower() for seg in p.split("/")[:-1]}]
    if php_in_uploads:
        findings.append(_finding("Server-side script in an upload or media folder", S.HIGH,
                                 [(p, "") for p in php_in_uploads], "Found",
                                 "Upload, image and static folders should only hold files to download. A script there "
                                 "is how web shells usually hide: check it, remove it if your team didn't put it "
                                 "there, and stop scripts running in that folder."))

    in_uploads = lambda p: bool(UPLOAD_DIRS & {seg.lower() for seg in p.split("/")[:-1]})
    disguised = [p for p in files if DISGUISED_EXT.search(p.rsplit("/", 1)[-1])]
    if disguised:
        findings.append(_finding("Disguised script file (double extension)", S.HIGH, [(p, "") for p in disguised],
                                 "Found",
                                 "Names like shell.php.jpg slip past upload filters and run as PHP on servers that map "
                                 "any '.php.' name to the interpreter. Check them, delete the ones your team didn't "
                                 "create, and find out how they were uploaded."))
    programs = [p for p in files if in_uploads(p) and PROGRAM_EXT.search(p.rsplit("/", 1)[-1])]
    if programs:
        findings.append(_finding("Program or script in an upload or media folder", S.MEDIUM,
                                 [(p, "") for p in programs], "Found",
                                 "Attackers host malware among uploaded files. Open each one and delete it if your "
                                 "team didn't upload it."))

    sensitive = [p.rstrip("/") for p in files if SENSITIVE.search(p.rstrip("/").rsplit("/", 1)[-1])]
    if sensitive:
        findings.append(_finding("Secret or backup file inside the web folder", S.MEDIUM, [(p, "") for p in sensitive],
                                 "Found",
                                 "Move .env files, keys, database dumps, archives and logs out of the website folder "
                                 "(or delete them), and rotate any password or key they contain. Anything in the web "
                                 "folder may be downloadable."))

    writable = [p for p, (_, _, mode) in files.items() if mode & 0o002]
    if writable:
        findings.append(_finding("Files or folders anyone on the server can change", S.LOW,
                                 [(p, oct(files[p][2] & 0o777)) for p in writable], "World-writable",
                                 "Use 644 for files and 755 for folders (chmod), so other accounts on a shared server "
                                 "can't change them."))

    if prev is not None:
        new_code = [p for p in new_paths if SERVER_CODE.search(p.rsplit("/", 1)[-1])]
        if new_code:
            findings.append(_finding("New server-side code files since the last scan", S.HIGH,
                                     [(p, "") for p in new_code], "New",
                                     "If nobody on your team deployed these, check them now: a new PHP or other script "
                                     "file, or .htaccess, is the usual first sign of a break-in."))
        changed_code = [p for p in changed if SERVER_CODE.search(p.rsplit("/", 1)[-1])
                        and (p in content_changed or hashes.get(p) is None)]
        if changed_code:
            findings.append(_finding("Server-side code files changed since the last scan", S.MEDIUM,
                                     [(p, "") for p in changed_code], "Changed",
                                     "Confirm these changes came from your own deployment. If not, compare them with "
                                     "your source code and restore the clean version."))

    state.update(root=root, files={p: [s, m, hashes.get(p)] for p, (s, m, _) in files.items()},
                 scanned_at=datetime.now(timezone.utc).isoformat())
    summary = (f"{len(files)} files in {root}; {len(new_paths)} new, {len(changed)} changed, "
               f"{min(len(queue), MAX_READS)} read" + (f"; {'; '.join(notes)}" if notes else ""))
    if prev is None:
        findings.append(Finding("malware", f"{TAG}: Baseline recorded over SSH", S.INFO, summary,
                                "New and changed files are reported from the next scan."))
    else:
        findings.append(Finding("malware", f"{TAG}: scanned the server files over SSH", S.INFO, summary))
    return findings


def run(ctx, cfg, state):
    ssh = cfg.get("ssh") or {}
    if not ssh.get("host") or not cfg.get("inside_scan", True):
        return []
    try:
        transport, sftp, _ = connect(ssh["host"], ssh.get("port", 22), ssh.get("username", ""), _key_text(ssh),
                                     ssh.get("host_key"))
    except HostKeyChanged as exc:
        return [Finding("malware", f"{TAG}: SSH server key changed", S.HIGH, str(exc),
                        "Confirm with your host whether the server changed before trusting it again.")]
    except SSHError as exc:
        return [Finding("malware", f"{TAG}: could not log in over SSH", S.INFO, str(exc),
                        "Fix the SSH access, then scan again.")]
    try:
        return scan(sftp, sftp.normalize(ssh.get("web_root") or "."), state.setdefault("ssh_inside", {}))
    finally:
        transport.close()
