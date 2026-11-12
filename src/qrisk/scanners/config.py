"""Layer 5: configuration files.

Reads nginx, Apache httpd, OpenSSL (openssl.cnf) and OpenSSH (sshd_config /
ssh_config) files, and flags weak or quantum-vulnerable settings with the exact
file and line. Certificates, DH parameters and SSH host keys that a config
points to are inspected too, when they are readable.
"""

from __future__ import annotations

import glob
import re
import shlex
from dataclasses import dataclass, field, replace
from pathlib import Path

from ..models import Finding, Note, Rating
from ..rules import (
    TLS_GROUPS, Verdict, rate_bulk_cipher, rate_public_key, rate_ssh_cipher, rate_ssh_hostkey, rate_ssh_kex, rate_ssh_mac,
    rate_tls12_kex, rate_tls_version, NIST_NOW,
)
from .certs import scan_file

MAX_FILE_SIZE = 1_000_000
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__"}
CONFIG_NAMES = {"sshd_config", "ssh_config", "nginx.conf", "httpd.conf", "apache2.conf", "openssl.cnf", "ssl.conf"}
CONFIG_DIRS = {"sites-enabled", "sites-available", "conf.d", "conf-enabled", "sshd_config.d", "ssh_config.d"}

# How to fix things, in each server's own syntax.
FIX = {
    "nginx": {
        "protocols": "Set `ssl_protocols TLSv1.2 TLSv1.3;`",
        "groups": "Put the hybrid group first: `ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;` (OpenSSL 3.5+).",
        "ciphers": "Use a modern list, e.g. `ssl_ciphers ECDHE+AESGCM:ECDHE+CHACHA20;`",
    },
    "apache": {
        "protocols": "Set `SSLProtocol -all +TLSv1.2 +TLSv1.3`",
        "groups": "Add `SSLOpenSSLConfCmd Groups X25519MLKEM768:X25519:prime256v1` (OpenSSL 3.5+).",
        "ciphers": "Use a modern list, e.g. `SSLCipherSuite ECDHE+AESGCM:ECDHE+CHACHA20`",
    },
    "openssl": {
        "protocols": "Set `MinProtocol = TLSv1.2` in the system_default section.",
        "groups": "Set `Groups = X25519MLKEM768:X25519:prime256v1` (OpenSSL 3.5+).",
        "ciphers": "Use `CipherString = DEFAULT:@SECLEVEL=2` or higher.",
    },
}

_PROTOCOL_CODES = {"SSLV2": 0x0200, "SSLV3": 0x0300, "TLSV1": 0x0301, "TLSV1.0": 0x0301, "TLSV1.1": 0x0302,
                   "TLSV1.2": 0x0303, "TLSV1.3": 0x0304}
_GROUP_ALIASES = {"prime256v1": "secp256r1", "p-256": "secp256r1", "p-384": "secp384r1", "p-521": "secp521r1"}
_GROUPS_BY_NAME = {name.lower(): (code, v) for code, (name, v) in TLS_GROUPS.items()}

_WEAK_CIPHER_TOKENS = {
    "RC4": "RC4 has practical plaintext-recovery attacks.",
    "DES": "DES / 3DES use 56-bit keys or 64-bit blocks.",
    "3DES": "3DES has a 64-bit block size (Sweet32).",
    "MD5": "MD5-based suites are broken.",
    "NULL": "NULL ciphers send data unencrypted.",
    "ENULL": "NULL ciphers send data unencrypted.",
    "ANULL": "Anonymous suites have no server authentication.",
    "ADH": "Anonymous Diffie-Hellman has no server authentication.",
    "AECDH": "Anonymous ECDH has no server authentication.",
    "EXP": "Export-grade ciphers are deliberately weak.",
    "EXPORT": "Export-grade ciphers are deliberately weak.",
    "LOW": "LOW enables 64-bit and 56-bit ciphers.",
    "KRSA": "Static RSA key exchange has no forward secrecy.",
    "RSA": "In OpenSSL cipher strings `RSA` means static RSA key exchange (no forward secrecy).",
    "SSLV3": "Enables SSLv3-era cipher suites.",
}


@dataclass
class Directive:
    name: str
    args: list[str]
    line: int
    section: str = ""  # openssl [section], nginx "server example.com", Apache "VirtualHost *:443", SSH "Host x"


@dataclass
class _Ctx:
    kind: str  # nginx | apache | openssl | sshd
    path: Path
    rel: str
    target: str
    included: bool = False
    boundary: Path | None = None  # files outside this folder are not read (None = no limit)
    findings: list[Finding] = field(default_factory=list)
    notes: list[Note] = field(default_factory=list)

    def add(self, d: Directive, category: str, asset: str, v: Verdict, fix: str | None = None) -> None:
        rec = v.recommendation
        if fix and v.rating in (Rating.CRITICAL, Rating.QUANTUM_VULNERABLE):
            rec = fix
        self.findings.append(Finding(
            target=self.target, layer="config", category=category, asset=asset, rating=v.rating,
            reason=v.reason, recommendation=rec, nist=v.nist, algorithm=v.algo,
            location=f"{self.rel}:{d.line}",
            details={"file": self.rel, "line": d.line, "kind": self.kind,
                     "directive": f"{d.name} {' '.join(d.args)}".strip()[:200],
                     **({"context": d.section} if d.section else {})},
        ))

    def note(self, msg: str, level: str = "info", line: int | None = None) -> None:
        self.notes.append(Note(f"{self.rel}:{line}" if line else self.rel, msg, level))

    def allowed(self, p: Path) -> bool:
        return _inside(p, self.boundary)

    def fix(self, what: str) -> str | None:
        return FIX.get(self.kind, {}).get(what)


# --- parsing --------------------------------------------------------------------------

def _strip_comment(line: str) -> str:
    out, quote = [], None
    for ch in line:
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch == "#":
            break
        out.append(ch)
    return "".join(out)


def _split(text: str) -> list[str]:
    try:
        return shlex.split(text)
    except ValueError:
        return text.split()


def parse_nginx(text: str) -> list[Directive]:
    """nginx statements end with ';' and may span lines; '{' / '}' open and close blocks.

    Directives inside a ``server { }`` block get ``section = "server <server_name>"``.
    """
    out: list[Directive] = []
    stack: list[dict] = []  # open blocks: {"name", "line", "names", "dirs"}
    buf, start = "", 0

    def close(block: dict) -> None:
        if block["name"] == "server":
            label = "server " + (" ".join(block["names"]) or f"(line {block['line']})")
            for d in block["dirs"]:
                d.section = label

    for no, raw in enumerate(text.splitlines(), 1):
        for ch in _strip_comment(raw) + "\n":
            if not buf.strip():
                start = no
            if ch in ";{}":
                tokens = _split(buf)
                if ch == ";" and tokens:
                    d = Directive(tokens[0], tokens[1:], start)
                    out.append(d)
                    server = next((b for b in reversed(stack) if b["name"] == "server"), None)
                    if server is not None:
                        server["dirs"].append(d)
                        if d.name == "server_name":
                            server["names"] += [a for a in d.args if a != "_"]
                elif ch == "{":
                    stack.append({"name": tokens[0] if tokens else "", "line": start, "names": [], "dirs": []})
                elif ch == "}" and stack:
                    close(stack.pop())
                buf = ""
            else:
                buf += ch
    while stack:
        close(stack.pop())
    return out


def parse_lines(text: str, *, kind: str) -> list[Directive]:
    """Apache (`Name args`, `\\` continuation), OpenSSH (`Name value` / `Name=value`) and openssl.cnf (`key = value`)."""
    out: list[Directive] = []
    section, pending, start = "", "", 0
    blocks: list[str] = []  # Apache <VirtualHost ...> nesting
    for no, raw in enumerate(text.splitlines(), 1):
        line = _strip_comment(raw).rstrip()
        if kind == "apache" and line.endswith("\\"):
            if not pending:
                start = no
            pending += line[:-1] + " "
            continue
        if pending:
            line, no_used = pending + line, start
            pending = ""
        else:
            no_used = no
        s = line.strip()
        if not s:
            continue
        if kind == "openssl":
            m = re.match(r"\[\s*([^\]]+?)\s*\]$", s)
            if m:
                section = m.group(1)
                continue
            m = re.match(r"\.include\s*=?\s*(\S+)", s)
            if m:
                out.append(Directive(".include", [m.group(1)], no_used, section))
                continue
            if "=" in s:
                key, _, value = s.partition("=")
                out.append(Directive(key.strip(), [value.strip()], no_used, section))
            continue
        if kind == "apache" and s.startswith("</"):
            if blocks:
                blocks.pop()
            continue
        if kind == "apache" and s.startswith("<"):
            blocks.append(s.strip("<>").strip())
            continue
        if kind == "sshd":
            m = re.match(r"(\S+?)(?:\s*=\s*|\s+)(.*)$", s)
            if m:
                if m.group(1).lower() in ("host", "match"):
                    section = f"{m.group(1)} {m.group(2).strip()}"
                out.append(Directive(m.group(1), [m.group(2).strip()], no_used, section))
            continue
        tokens = _split(s)
        if tokens:
            vhost = next((b for b in reversed(blocks) if b.lower().startswith("virtualhost")), "")
            out.append(Directive(tokens[0], tokens[1:], no_used, vhost))
    return out


def detect_kind(path: Path, text: str) -> str | None:
    name = path.name.lower()
    if "ssh" in name or path.parent.name.lower().startswith("ssh") or \
            re.search(r"^\s*(KexAlgorithms|HostKeyAlgorithms|HostKey|PubkeyAcceptedAlgorithms)\b", text, re.M | re.I):
        return "sshd"
    if re.search(r"^\s*(SSLProtocol|SSLCipherSuite|SSLEngine|SSLCertificateFile|SSLOpenSSLConfCmd|<VirtualHost)\b",
                 text, re.M):
        return "apache"
    if re.search(r"^\s*(ssl_protocols|ssl_ciphers|ssl_certificate|ssl_ecdh_curve|server\s*\{|http\s*\{|listen\s)",
                 text, re.M):
        return "nginx"
    if path.suffix.lower() == ".cnf" or re.search(r"^\s*(openssl_conf|MinProtocol|CipherString|default_bits)\s*=",
                                                  text, re.M):
        return "openssl"
    return None


# --- shared checks ------------------------------------------------------------------

def _protocols(ctx: _Ctx, d: Directive, versions: list[str]) -> None:
    for name in versions:
        code = _PROTOCOL_CODES.get(name.upper())
        if code is None:
            continue
        if code == 0x0200:
            v = Verdict(Rating.CRITICAL, "SSL 2.0 is completely broken.", "", NIST_NOW)
        else:
            v = rate_tls_version(code)
        pretty = {0x0200: "SSL 2.0", 0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
                  0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}[code]
        ctx.add(d, "protocol", f"{pretty} enabled", v, ctx.fix("protocols"))


def _apache_protocols(args: list[str]) -> list[str]:
    """Resolve `SSLProtocol all -SSLv3 +TLSv1.3` into the enabled set."""
    all_ = ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
    enabled: list[str] = []
    for tok in args:
        op, name = (tok[0], tok[1:]) if tok[:1] in "+-" else ("+", tok)
        names = all_ if name.lower() == "all" else [name]
        for n in names:
            if op == "+" and n not in enabled:
                enabled.append(n)
            elif op == "-" and n in enabled:
                enabled.remove(n)
    return enabled


def _groups(ctx: _Ctx, d: Directive, value: str) -> None:
    names = [n for n in re.split(r"[:,\s]+", value) if n]
    if names == ["auto"]:
        ctx.note("Groups set to 'auto': OpenSSL picks its defaults (OpenSSL 3.5+ includes X25519MLKEM768).",
                 line=d.line)
        return
    pq = False
    for raw in names:
        name = _GROUP_ALIASES.get(raw.lower(), raw.lower()).lstrip("?*")
        if name not in _GROUPS_BY_NAME:
            continue
        _code, v = _GROUPS_BY_NAME[name]
        pq = pq or v.rating in (Rating.HYBRID, Rating.QUANTUM_SAFE)
        ctx.add(d, "key-exchange", f"{v.algo.name if v.algo else raw} (configured group)", v, ctx.fix("groups"))
    if not pq:
        ctx.note("No post-quantum key-exchange group configured. " + (ctx.fix("groups") or ""), "warning", d.line)


def _cipher_string(ctx: _Ctx, d: Directive, value: str) -> None:
    tokens = [t for t in re.split(r"[:,\s]+|(?=@)", value) if t]  # "DEFAULT@SECLEVEL=1" -> DEFAULT, @SECLEVEL=1
    excluded = {t[1:].upper() for t in tokens if t[:1] in "!-"}
    weak_found = False
    static_rsa: list[str] = []
    for tok in tokens:
        if tok[:1] in "!-":
            continue
        t = tok.lstrip("+")
        up = t.upper()
        m = re.match(r"@SECLEVEL=(\d)", up)
        if m:
            if int(m.group(1)) <= 1:
                ctx.add(d, "cipher", f"@SECLEVEL={m.group(1)}", Verdict(
                    Rating.CRITICAL, f"Security level {m.group(1)} allows 80-bit security (RSA-1024, SHA-1 signatures).",
                    "", NIST_NOW), ctx.fix("ciphers"))
                weak_found = True
            continue
        if up in _WEAK_CIPHER_TOKENS:
            ctx.add(d, "cipher", f"{t} in cipher list", Verdict(Rating.CRITICAL, _WEAK_CIPHER_TOKENS[up], "", NIST_NOW),
                    ctx.fix("ciphers"))
            weak_found = True
            continue
        if up == "ALL" and not ({"KRSA", "RSA"} & excluded):
            ctx.add(d, "cipher", "ALL in cipher list", Verdict(
                Rating.CRITICAL, "`ALL` enables legacy suites, including static-RSA key exchange.", "", NIST_NOW),
                ctx.fix("ciphers"))
            weak_found = True
            continue
        if up.startswith("TLS_"):  # TLS 1.3 suite names
            v = rate_bulk_cipher(up)
        elif "-" in up and re.search(r"AES|CHACHA|DES|RC4|CAMELLIA|SEED|IDEA|NULL", up):  # OpenSSL suite names
            if "CBC3" in up:
                up = up.replace("DES-CBC3", "3DES")
            v = rate_bulk_cipher(up)
            if not up.startswith(("ECDHE", "DHE", "EDH", "ECDH-", "TLS_")) and v.rating is not Rating.CRITICAL:
                static_rsa.append(t)
        else:
            continue
        if v.rating is Rating.CRITICAL:
            ctx.add(d, "cipher", t, v, ctx.fix("ciphers"))
            weak_found = True
    if static_rsa:
        v = rate_tls12_kex("RSA")
        ctx.add(d, "key-exchange", f"Static RSA suites ({', '.join(static_rsa[:3])}{'…' if len(static_rsa) > 3 else ''})",
                v, ctx.fix("ciphers"))
        weak_found = True
    if not weak_found:
        ctx.add(d, "cipher", "Cipher list", Verdict(
            Rating.QUANTUM_SAFE, "No weak or legacy cipher suites are enabled.", "No action needed.", None))


EXTERNAL_HINT = "outside the scanned folder, so not read (use --config-follow-external to allow)"


def _inside(p: Path, boundary: Path | None) -> bool:
    if boundary is None:
        return True
    try:
        p.resolve().relative_to(boundary.resolve())
        return True
    except (ValueError, OSError):
        return False


def _resolve_relative(base_file: Path, p: Path, boundary: Path | None) -> list[Path]:
    """Relative paths resolve against the server's prefix (e.g. /etc/nginx), usually the config
    file's folder or one of its parents (sites-enabled/ -> nginx/). Never climb out of the boundary."""
    parents = [base_file.parent, *base_file.parent.parents][:4]
    return [parent / p for parent in parents if _inside(parent, boundary)] or [base_file.parent / p]


def _referenced_file(ctx: _Ctx, d: Directive, raw: str, *, ssh_hostkey: bool = False) -> None:
    p = Path(raw)
    if not p.is_absolute():
        options = _resolve_relative(ctx.path, p, ctx.boundary)
        p = next((o for o in options if o.is_file()), options[0])
    if ssh_hostkey and Path(str(p) + ".pub").is_file():
        p = Path(str(p) + ".pub")
    if not ctx.allowed(p):
        ctx.note(f"Referenced file {raw} is {EXTERNAL_HINT}.", line=d.line)
        return
    try:
        if not p.is_file() or p.stat().st_size > MAX_FILE_SIZE:
            ctx.note(f"Referenced file not readable here: {raw}", line=d.line)
            return
        f, n = scan_file(p, target=ctx.target, location=p.as_posix())
    except Exception as exc:  # unreadable key, permission denied, ...
        ctx.note(f"Could not inspect {raw}: {exc}", line=d.line)
        return
    for finding in f:
        finding.details.setdefault("referenced_from", f"{ctx.rel}:{d.line}")
    ctx.findings += f
    ctx.notes += n


# --- per-server analysers -----------------------------------------------------------

def _analyse_tls_server(ctx: _Ctx, dirs: list[Directive]) -> None:
    """nginx and Apache share most logic; only directive names differ."""
    nginx = ctx.kind == "nginx"
    names = {d.name.lower() for d in dirs}
    uses_tls = False
    for d in dirs:
        n, args = d.name.lower(), d.args
        conf_cmd = (n == "ssl_conf_command" and nginx) or (n == "sslopensslconfcmd" and not nginx)
        if n in ("ssl_protocols",):
            _protocols(ctx, d, args)
        elif n == "sslprotocol":
            _protocols(ctx, d, _apache_protocols(args))
        elif n in ("ssl_ciphers", "sslciphersuite") and args:
            _cipher_string(ctx, d, args[-1])
        elif n == "ssl_ecdh_curve" and args:
            _groups(ctx, d, args[0])
        elif conf_cmd and len(args) >= 2 and args[0].lower() in ("groups", "curves"):
            _groups(ctx, d, args[1])
        elif conf_cmd and len(args) >= 2 and args[0].lower() == "minprotocol":
            _min_protocol(ctx, d, args[1])
        elif conf_cmd and len(args) >= 2 and args[0].lower() == "dhparameters":
            _referenced_file(ctx, d, args[1])
        elif n in ("ssl_certificate", "sslcertificatefile", "ssl_dhparam") and args:
            _referenced_file(ctx, d, args[0])
        elif (n == "listen" and any(a in ("ssl", "quic") for a in args)) or (n in ("ssl", "sslengine") and args[:1] == ["on"]):
            uses_tls = True
        if n.startswith("ssl"):
            uses_tls = True
    if uses_tls and not ctx.included:
        proto_directive = "ssl_protocols" if nginx else "sslprotocol"
        if proto_directive not in names:
            ctx.note("TLS is enabled but protocols are not set, so server defaults apply "
                     f"({'nginx ≥1.23.4: TLSv1.2 TLSv1.3' if nginx else 'Apache 2.4: all versions OpenSSL allows'}).")
        has_groups = "ssl_ecdh_curve" in names or any(
            d.args[:1] and d.args[0].lower() in ("groups", "curves") for d in dirs
            if d.name.lower() in ("ssl_conf_command", "sslopensslconfcmd"))
        if not has_groups:
            ctx.note("Key-exchange groups are not set, so OpenSSL defaults apply. OpenSSL 3.5+ offers X25519MLKEM768 "
                     "by default; older versions offer no post-quantum group.")


def _min_protocol(ctx: _Ctx, d: Directive, value: str) -> None:
    code = _PROTOCOL_CODES.get(value.upper().replace("DTLSV", "TLSV"))
    if code is None:
        return
    v = rate_tls_version(code) if code != 0x0200 else Verdict(Rating.CRITICAL, "SSL 2.0 is broken.", "", NIST_NOW)
    if code < 0x0303:
        v = replace(v, reason=f"Minimum protocol {value} allows obsolete versions. " + v.reason)
    ctx.add(d, "protocol", f"MinProtocol {value}", v, ctx.fix("protocols"))


def _analyse_openssl(ctx: _Ctx, dirs: list[Directive]) -> None:
    for d in dirs:
        key, value = d.name.lower(), (d.args[0] if d.args else "")
        if key == "minprotocol":
            _min_protocol(ctx, d, value)
        elif key == "cipherstring":
            _cipher_string(ctx, d, value)
        elif key == "ciphersuites":
            _cipher_string(ctx, d, value)
        elif key in ("groups", "curves"):
            _groups(ctx, d, value)
        elif key == "default_bits" and value.isdigit():
            v = rate_public_key("RSA", int(value))
            ctx.add(d, "public-key", f"default_bits = {value} (new RSA keys)", v,
                    "Set `default_bits = 3072` (or 4096) and plan migration to ML-DSA certificates." if
                    v.rating is not Rating.QUANTUM_SAFE else None)
        elif key == "default_md" and value.lower() in ("md5", "sha1", "md4"):
            ctx.add(d, "hash", f"default_md = {value}", Verdict(
                Rating.CRITICAL, f"{value.upper()} signatures have practical collision attacks.",
                "Set `default_md = sha256`.", NIST_NOW))


def _analyse_sshd(ctx: _Ctx, dirs: list[Directive]) -> None:
    names = {d.name.lower() for d in dirs}
    for d in dirs:
        key = d.name.lower()
        value = d.args[0] if d.args else ""
        if key == "protocol" and "1" in value.split(","):
            ctx.add(d, "protocol", "SSH protocol 1", Verdict(Rating.CRITICAL, "SSH-1 is broken.", "Remove `Protocol 1`.", NIST_NOW))
            continue
        if key == "hostkey":
            _referenced_file(ctx, d, value, ssh_hostkey=True)
            continue
        rater = {
            "kexalgorithms": ("key-exchange", rate_ssh_kex),
            "hostkeyalgorithms": ("host-key", rate_ssh_hostkey),
            "pubkeyacceptedalgorithms": ("host-key", rate_ssh_hostkey),
            "pubkeyacceptedkeytypes": ("host-key", rate_ssh_hostkey),
            "casignaturealgorithms": ("host-key", rate_ssh_hostkey),
            "ciphers": ("cipher", rate_ssh_cipher),
            "macs": ("mac", rate_ssh_mac),
        }.get(key)
        if not rater or not value or value.startswith("-"):
            continue  # "-alg" only removes algorithms from the defaults
        category, rate = rater
        if value[0] in "+^":
            ctx.note(f"{d.name} {value[0]}... modifies OpenSSH's built-in defaults; only the listed algorithms are rated.",
                     line=d.line)
        for alg in value.lstrip("+^").split(","):
            alg = alg.strip()
            if alg:
                ctx.add(d, category, alg, rate(alg))
    if "kexalgorithms" not in names and not ctx.included:
        ctx.note("KexAlgorithms is not set, so OpenSSH defaults apply: OpenSSH 9.0+ prefers sntrup761x25519-sha512, "
                 "10.0+ prefers mlkem768x25519-sha256. Older versions have no post-quantum key exchange.")


# --- entry point ------------------------------------------------------------------------

def _candidates(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    out = []
    for p in sorted(root.rglob("*")):
        if not p.is_file() or any(part in SKIP_DIRS for part in p.relative_to(root).parts):
            continue
        if p.suffix.lower() in (".conf", ".cnf") or p.name.lower() in CONFIG_NAMES or p.parent.name in CONFIG_DIRS:
            out.append(p)
    return out


_INCLUDE_DIRECTIVES = {"include", "includeoptional", ".include"}


def _includes(path: Path, dirs: list[Directive], boundary: Path | None = None) -> tuple[list[Path], list[tuple[int, str]]]:
    """Files named by include directives. Relative paths are tried against the file's folder and its
    parents, because nginx, Apache and OpenSSH resolve them against their own prefix (e.g. /etc/nginx)."""
    found: list[Path] = []
    skipped: list[tuple[int, str]] = []  # (line, pattern) of includes outside the boundary
    for d in dirs:
        if d.name.lower() not in _INCLUDE_DIRECTIVES or not d.args:
            continue
        for pattern in d.args[0].split() if d.name.lower() == "include" and len(d.args) == 1 else d.args[:1]:
            p = Path(pattern)
            if p.is_absolute():
                candidates = [p] if _inside(p, boundary) or boundary is None else []
                if not candidates:
                    skipped.append((d.line, pattern))
            else:
                candidates = _resolve_relative(path, p, boundary)
            for candidate in candidates:
                matches = sorted(Path(m) for m in glob.glob(str(candidate)) if Path(m).is_file())
                outside = [m for m in matches if not _inside(m, boundary)]  # e.g. a symlink leaving the folder
                if outside:
                    skipped.append((d.line, pattern))
                matches = [m for m in matches if _inside(m, boundary)]
                if matches:
                    found += matches
                    break
    return found, skipped


def scan_config(root: str | Path, *, follow_external: bool = False) -> tuple[list[Finding], list[Note]]:
    """Scan config files under ``root``.

    By default, includes and referenced files (certificates, DH params, host keys) are only read
    when they are inside the scanned folder: scanning a copy of someone's config must not pull
    the scanning machine's own /etc files into the report. ``follow_external=True`` lifts that.
    """
    root = Path(root)
    target = f"config:{root}"
    if not root.exists():
        return [], [Note(target, f"Path not found: {root}", "error")]
    findings: list[Finding] = []
    notes: list[Note] = []
    seen: dict[str, int] = {}
    # Work list of (file, kind inherited from the including file, included from).
    queue: list[tuple[Path, str | None, str | None]] = [(p, None, None) for p in _candidates(root)]
    visited: set[Path] = set()
    while queue:
        path, inherited, parent = queue.pop(0)
        if path.resolve() in visited:
            continue
        visited.add(path.resolve())
        boundary = None if follow_external else (root if root.is_dir() else root.parent)
        try:
            rel = path.as_posix() if root.is_file() else (root / path.relative_to(root)).as_posix()
        except ValueError:  # included from outside the scanned folder
            rel = path.as_posix()
        try:
            too_big = path.stat().st_size > MAX_FILE_SIZE
        except OSError as exc:  # broken symlink, permission denied, deleted while scanning...
            notes.append(Note(rel, f"Could not read: {exc}", "warning"))
            continue
        if too_big:
            notes.append(Note(rel, "Skipped: file larger than 1 MB.", "warning"))
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            notes.append(Note(rel, f"Could not read: {exc}", "warning"))
            continue
        kind = inherited or detect_kind(path, text)  # an included snippet has its parent's syntax
        if kind is None:
            continue
        seen[kind] = seen.get(kind, 0) + 1
        ctx = _Ctx(kind, path, rel, target, included=parent is not None, boundary=boundary)
        dirs = parse_nginx(text) if kind == "nginx" else parse_lines(text, kind=kind)
        if kind in ("nginx", "apache"):
            _analyse_tls_server(ctx, dirs)
        elif kind == "openssl":
            _analyse_openssl(ctx, dirs)
        else:
            _analyse_sshd(ctx, dirs)
        if parent:
            for f in ctx.findings:
                f.details["included_from"] = parent
        findings += ctx.findings
        notes += ctx.notes
        included, skipped = _includes(path, dirs, boundary)
        for line, pattern in skipped:
            notes.append(Note(f"{rel}:{line}", f"Include {pattern} is {EXTERNAL_HINT}.", "warning"))
        for inc in included:
            if inc.resolve() not in visited:
                queue.append((inc, kind, rel))
    summary = ", ".join(f"{n} {k}" for k, n in sorted(seen.items())) or "none"
    notes.append(Note(target, f"Config files recognised: {summary}.", "info" if seen else "warning"))
    return findings, notes
