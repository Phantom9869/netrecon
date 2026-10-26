"""
Exposed-path probe and light web technology fingerprinting.

The probe issues GET requests only. It will not follow a redirect off the
original host, caps same-host redirects at three, and reads at most 64 KiB
of each body. Response bytes are untrusted: they are decoded lossily, control
characters are stripped, and nothing from a response is evaluated or passed
to a shell.

A path is a hit only when its body matches a content check. A random-path
baseline catches soft 404s and SPA catch-all pages. Secret values from files
such as ``.env`` are never stored; key names may be reported with values
redacted. Paths discovered in robots.txt or a sitemap are listed as leads
and are not requested.

Use this only against hosts you are authorized to test.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import secrets
import threading
import urllib.parse
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

import requests

from ..models import WebExposureResult, WebFinding, WebLead, WebTechnology

USER_AGENT = "netrecon/1.0 (web exposure probe; authorized testing only)"
BODY_LIMIT = 64 * 1024
MAX_REDIRECTS = 3
MAX_WORKERS = 8
DEFAULT_TIMEOUT = 5.0
DEFAULT_THREADS = 4
DEFAULT_BUDGET = 48

_SEVERITIES = {"info", "low", "medium", "high"}
_SEV_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
_DROP_HEADERS = {
    "cookie", "set-cookie", "authorization", "proxy-authorization",
    "x-api-key", "x-auth-token",
}
_BIDI = {
    0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
    0x2066, 0x2067, 0x2068, 0x2069,
    0x200E, 0x200F, 0xFEFF,
}
_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_COOKIE_RE = re.compile(r"[A-Za-z0-9_!#$%&'*+.^`|~-]{1,64}")
_SAFE_KEY = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.\-]{0,80}$")
_LEAD_RE = re.compile(r"/[A-Za-z0-9._~%!$&+,;=@/\-]{0,159}")
_ENV_LINE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=")
_DEFINE = re.compile(r"""define\s*\(\s*['"]([A-Z0-9_]+)['"]""")
_SECTION = re.compile(
    r"""(?m)^\[([A-Za-z0-9_.\-]+)(?:\s+"([A-Za-z0-9_.\-/]+)")?\]"""
)
_EMBEDDED_CRED = re.compile(r"://[^/\s:]+:[^/\s@]+@")
_SENSITIVE = re.compile(
    r"(?i)(?:^|_)(?:pass(?:word)?|secret|token|api[-_]?key|private[-_]?key|"
    r"credential|database|aws[-_]?secret)(?:$|_)"
)
_GEN_1 = re.compile(
    r"""(?is)<meta[^>]*name\s*=\s*(['"])generator\1[^>]*content\s*=\s*"""
    r"""(['"])([^'"]{0,200})\2"""
)
_GEN_2 = re.compile(
    r"""(?is)<meta[^>]*content\s*=\s*(['"])([^'"]{0,200})\1[^>]*name\s*=\s*"""
    r"""(['"])generator\3"""
)
_SITEMAP_LOC = re.compile(r"(?i)<loc>\s*([^<\s]+)\s*</loc>")


@dataclass
class _Hit:
    severity: str
    reason: str
    leads: list[tuple[str, str]] = field(default_factory=list)


@dataclass(frozen=True)
class _Probe:
    path: str
    check: Callable[[bytes, str], _Hit | None]
    weak: bool = False


@dataclass
class _Fetched:
    url: str
    status: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    cookies: list[str] = field(default_factory=list)
    body: bytes = b""
    truncated: bool = False
    error: str = ""


@dataclass(frozen=True)
class _Baseline:
    status: int
    digest: str
    prefix: str
    length: int


class _Budget:
    def __init__(self, limit: int):
        self._limit = limit
        self._used = 0
        self._lock = threading.Lock()

    def take(self) -> bool:
        with self._lock:
            if self._used >= self._limit:
                return False
            self._used += 1
            return True


# ── Text hygiene ──────────────────────────────────────────────────────

def _sanitize_inline(value: str, limit: int) -> str:
    """Strip control and bidi characters. Response text is attacker-controlled."""
    if not value:
        return ""
    kept: list[str] = []
    for ch in value:
        code = ord(ch)
        if code < 32 or code == 127 or code in _BIDI or not ch.isprintable():
            continue
        kept.append(ch)
        if len(kept) >= limit:
            break
    return "".join(kept).strip()


def _decode_body(body: bytes) -> str:
    text = body.decode("utf-8", errors="replace")
    kept: list[str] = []
    for ch in text:
        code = ord(ch)
        if ch in "\n\t\r":
            kept.append(ch)
        elif code < 32 or code == 127 or code in _BIDI or not ch.isprintable():
            continue
        else:
            kept.append(ch)
    return "".join(kept)


def _looks_html(text: str) -> bool:
    sample = text.lstrip().lower()
    head = sample[:600]
    return (
        sample.startswith("<!doctype")
        or sample.startswith("<html")
        or "<head" in head
        or "<body" in head
    )


def _looks_not_found(text: str) -> bool:
    low = text.lower()
    if "<title>404" in low or "page not found" in low:
        return True
    return "404" in low and "not found" in low


def _has_password_input(text: str) -> bool:
    compact = re.sub(r"\s+", "", text.lower())
    return (
        'type="password"' in compact
        or "type='password'" in compact
        or "type=password" in compact
    )


def _loads_json(text: str):
    stripped = text.strip()
    if not stripped or stripped[0] not in "{[":
        return None
    try:
        return json.loads(stripped)
    except (json.JSONDecodeError, ValueError, UnicodeError):
        return None


def _collect_keys(obj, prefix: str = "", depth: int = 0, acc: list[str] | None = None) -> list[str]:
    """Key paths only. Values are never appended."""
    if acc is None:
        acc = []
    if depth > 5 or len(acc) >= 40:
        return acc
    if isinstance(obj, dict):
        for key, value in obj.items():
            if not isinstance(key, str) or not _SAFE_KEY.fullmatch(key):
                continue
            path = f"{prefix}.{key}" if prefix else key
            acc.append(path)
            if isinstance(value, (dict, list)):
                _collect_keys(value, path, depth + 1, acc)
            if len(acc) >= 40:
                break
    elif isinstance(obj, list):
        for item in obj[:10]:
            if isinstance(item, (dict, list)):
                _collect_keys(item, prefix, depth + 1, acc)
    return acc


def _is_sensitive(name: str) -> bool:
    leaf = name.rsplit(".", 1)[-1]
    return bool(_SENSITIVE.search(leaf) or _SENSITIVE.search(name))


def _clean_lead(value: str) -> str | None:
    cleaned = _sanitize_inline(value, 200)
    if not cleaned:
        return None
    cleaned = cleaned.split()[0].split("#", 1)[0].split("?", 1)[0]
    if not cleaned.startswith("/") or cleaned.startswith("//") or cleaned == "/":
        return None
    if not _LEAD_RE.fullmatch(cleaned):
        return None
    return cleaned


def _lead_from_url(loc: str, host: str) -> str | None:
    cleaned = _sanitize_inline(loc, 300)
    if not cleaned:
        return None
    parts = urllib.parse.urlsplit(cleaned)
    if parts.scheme in ("http", "https"):
        loc_host = (parts.hostname or "").rstrip(".").lower()
        try:
            if loc_host and not _is_ip(loc_host):
                loc_host = loc_host.encode("idna").decode("ascii")
        except UnicodeError:
            return None
        if loc_host and loc_host != host:
            return None
        return _clean_lead(parts.path or "")
    if cleaned.startswith("/"):
        return _clean_lead(cleaned)
    return None


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


# ── Target and URL safety ─────────────────────────────────────────────

def _canonical_host(host: str) -> str:
    host = host.strip().rstrip(".").lower()
    if not host or len(host) > 253:
        raise ValueError("invalid target host")
    if _is_ip(host):
        return host
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("invalid target host") from exc
    labels = host.split(".")
    if not labels or any(not _LABEL.fullmatch(label) for label in labels):
        raise ValueError("invalid target host")
    return host


def _format_host(host: str) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


def _format_netloc(scheme: str, host: str, port: int | None) -> str:
    shown = _format_host(host)
    if port and not ((scheme == "https" and port == 443) or (scheme == "http" and port == 80)):
        return f"{shown}:{port}"
    return shown


def normalize_target(target: str) -> tuple[str, str]:
    """Return ``(base_url, hostname)``. Only http and https are accepted."""
    raw = (target or "").strip()
    if not raw or len(raw) > 2048:
        raise ValueError("invalid target")
    if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in raw):
        raise ValueError("invalid target")
    if "\\" in raw or raw.startswith("//") or raw.startswith("/"):
        raise ValueError("invalid target")
    if "://" not in raw:
        raw = "https://" + raw
    parts = urllib.parse.urlsplit(raw)
    if parts.scheme not in ("http", "https"):
        raise ValueError("only http and https targets are supported")
    if parts.username or parts.password:
        raise ValueError("credentials in the target URL are not allowed")
    if not parts.hostname:
        raise ValueError("invalid target host")
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError("invalid target port") from exc
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("invalid target port")
    host = _canonical_host(parts.hostname)
    base = f"{parts.scheme}://{_format_netloc(parts.scheme, host, port)}"
    return base, host


def _classify_redirect(current: str, location: str, host: str) -> tuple[str, str | None]:
    if not location or not isinstance(location, str) or len(location) > 2048:
        return "bad-location", None
    if "\\" in location or any(ord(ch) < 32 or ord(ch) == 127 for ch in location):
        return "bad-location", None
    joined = urllib.parse.urljoin(current, location.strip())
    parts = urllib.parse.urlsplit(joined)
    if parts.username or parts.password:
        return "bad-location", None
    if parts.scheme not in ("http", "https"):
        return "bad-scheme", None
    loc_host = (parts.hostname or "").rstrip(".").lower()
    if not loc_host:
        return "bad-location", None
    try:
        loc_host = _canonical_host(loc_host)
    except ValueError:
        return "bad-location", None
    if loc_host != host:
        return "cross-host", None
    try:
        port = parts.port
    except ValueError:
        return "bad-location", None
    rebuilt = urllib.parse.urlunsplit((
        parts.scheme,
        _format_netloc(parts.scheme, loc_host, port),
        parts.path or "/",
        parts.query,
        "",
    ))
    return "ok", rebuilt


def _public_url(url: str) -> str:
    """Drop query and fragment so redirect tokens are not stored."""
    parts = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((
        parts.scheme,
        parts.netloc,
        parts.path or "/",
        "",
        "",
    ))


def _same_host(url: str, host: str) -> bool:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https") or parts.username or parts.password:
        return False
    loc_host = (parts.hostname or "").rstrip(".").lower()
    try:
        loc_host = _canonical_host(loc_host)
    except ValueError:
        return False
    return loc_host == host


# ── HTTP ──────────────────────────────────────────────────────────────

def _empty(url: str, error: str, status: int = 0) -> _Fetched:
    return _Fetched(url=url, status=status, error=error)


def _cookie_name(header_value: str) -> str | None:
    if not header_value:
        return None
    first = str(header_value).split(";", 1)[0]
    name, sep, _value = first.partition("=")
    if not sep:
        return None
    name = name.strip()
    if _COOKIE_RE.fullmatch(name):
        return name
    return None


def _cookie_names_from_response(response) -> list[str]:
    values: list[str] = []
    extra = getattr(response, "set_cookie_headers", None)
    if isinstance(extra, (list, tuple)):
        values.extend(str(item) for item in extra)
    raw = getattr(response, "raw", None)
    header_obj = getattr(raw, "headers", None) if raw is not None else None
    if header_obj is not None and hasattr(header_obj, "getlist"):
        try:
            values.extend(str(item) for item in header_obj.getlist("Set-Cookie"))
        except Exception:
            pass
    if not values:
        headers = getattr(response, "headers", {}) or {}
        try:
            single = headers.get("Set-Cookie")
        except Exception:
            single = None
        if not single:
            try:
                single = headers.get("set-cookie")
            except Exception:
                single = None
        if single:
            values.append(str(single))
    names: list[str] = []
    seen: set[str] = set()
    for value in values:
        name = _cookie_name(value)
        if name and name.lower() not in seen:
            seen.add(name.lower())
            names.append(name)
    return names


def _copy_headers(response) -> dict[str, str]:
    try:
        items = list(response.headers.items())
    except Exception:
        return {}
    copied: dict[str, str] = {}
    for key, value in items:
        if not isinstance(key, str):
            continue
        name = key.strip().lower()
        if not name or name in _DROP_HEADERS:
            continue
        if isinstance(value, (bytes, bytearray)):
            value = bytes(value).decode("latin-1", errors="replace")
        elif not isinstance(value, str):
            value = str(value)
        copied[name] = _sanitize_inline(value, 180)
        if len(copied) >= 40:
            break
    return copied


def _read_capped(response, limit: int = BODY_LIMIT) -> tuple[bytes, bool]:
    buf = bytearray()
    truncated = False
    try:
        chunks = response.iter_content(chunk_size=8192)
    except Exception:
        return b"", False
    try:
        for chunk in chunks:
            if not chunk:
                continue
            if isinstance(chunk, str):
                chunk = chunk.encode("utf-8", errors="replace")
            room = limit - len(buf)
            if room <= 0:
                truncated = True
                break
            if len(chunk) > room:
                buf.extend(chunk[:room])
                truncated = True
                break
            buf.extend(chunk)
    except requests.Timeout:
        raise
    except Exception:
        return bytes(buf), truncated
    return bytes(buf), truncated


def _http_get(url: str, timeout: float) -> _Fetched:
    """One GET. Redirects are not followed by the HTTP library."""
    session = requests.Session()
    response = None
    try:
        session.trust_env = False
        session.max_redirects = 0
        try:
            response = session.get(
                url,
                allow_redirects=False,
                stream=True,
                timeout=timeout,
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept": "*/*",
                    "Accept-Encoding": "identity",
                },
            )
        except requests.Timeout:
            return _empty(url, "timeout")
        except requests.RequestException:
            return _empty(url, "request failed")
        try:
            status = int(response.status_code)
        except (TypeError, ValueError):
            status = 0
        headers = _copy_headers(response)
        cookies = _cookie_names_from_response(response)
        if status in _REDIRECT_STATUSES:
            return _Fetched(
                url=url, status=status, headers=headers, cookies=cookies, body=b"",
            )
        try:
            body, truncated = _read_capped(response)
        except requests.Timeout:
            return _empty(url, "timeout", status=status)
        return _Fetched(
            url=url,
            status=status,
            headers=headers,
            cookies=cookies,
            body=body,
            truncated=truncated,
        )
    finally:
        if response is not None:
            try:
                response.close()
            except Exception:
                pass
        session.close()


def _fetch_chain(start_url: str, host: str, timeout: float, budget: _Budget) -> _Fetched:
    current = start_url
    seen: set[str] = set()
    redirects = 0
    while True:
        if current in seen:
            return _empty(start_url, "redirect loop")
        seen.add(current)
        if not budget.take():
            return _empty(start_url, "request budget exhausted")
        fetched = _http_get(current, timeout)
        if fetched.error:
            return fetched
        if fetched.status in _REDIRECT_STATUSES:
            if redirects >= MAX_REDIRECTS:
                return _Fetched(url=current, status=fetched.status, error="redirect limit")
            decision, nxt = _classify_redirect(
                current, fetched.headers.get("location", ""), host,
            )
            if decision != "ok" or not nxt:
                error = "refused cross-host redirect" if decision == "cross-host" else "refused redirect"
                return _Fetched(url=current, status=fetched.status, error=error)
            redirects += 1
            current = nxt
            continue
        if not _same_host(fetched.url, host):
            return _Fetched(url=current, status=fetched.status, error="refused cross-host redirect")
        return fetched


# ── Soft 404 ──────────────────────────────────────────────────────────

def _normalize_body(body: bytes, path: str) -> bytes:
    token = path.encode("ascii", errors="ignore")
    if token:
        body = body.replace(token, b"")
        quoted = urllib.parse.quote(path).encode("ascii", errors="ignore")
        if quoted and quoted != token:
            body = body.replace(quoted, b"")
    return body


def _baseline_from(body: bytes, status: int, path: str) -> _Baseline:
    norm = _normalize_body(body, path)
    return _Baseline(
        status=status,
        digest=hashlib.sha256(norm).hexdigest(),
        prefix=hashlib.sha256(norm[:256]).hexdigest(),
        length=len(norm),
    )


def _matches_baseline(body: bytes, status: int, path: str, baseline: _Baseline | None) -> bool:
    if baseline is None:
        return False
    norm = _normalize_body(body, path)
    if hashlib.sha256(norm).hexdigest() == baseline.digest:
        return True
    if status == baseline.status:
        delta = abs(len(norm) - baseline.length)
        prefix = hashlib.sha256(norm[:256]).hexdigest()
        if delta <= 32 and prefix == baseline.prefix:
            return True
    return False


# ── Content checks ────────────────────────────────────────────────────

def _check_git_head(body: bytes, text: str) -> _Hit | None:
    sample = text.lstrip("\ufeff \t\r\n")
    if not sample.startswith("ref:"):
        return None
    match = re.match(r"ref:\s*(refs/[A-Za-z0-9._/\-]{1,80})", sample)
    if match:
        ref = match.group(1)
        return _Hit("high", f"Git HEAD exposed ({ref})")
    return _Hit("high", "Git HEAD exposed (ref pointer)")


def _check_git_config(body: bytes, text: str) -> _Hit | None:
    if _looks_html(text):
        return None
    if "[core]" not in text and "repositoryformatversion" not in text:
        return None
    labels: list[str] = []
    for section, sub in _SECTION.findall(text):
        if not _SAFE_KEY.fullmatch(section):
            continue
        if sub and _SAFE_KEY.fullmatch(sub):
            labels.append(f"{section}.{sub}")
        else:
            labels.append(section)
        if len(labels) >= 8:
            break
    extra = f"; sections: {', '.join(labels)}" if labels else ""
    creds = " (embedded credentials redacted)" if _EMBEDDED_CRED.search(text) else ""
    return _Hit("high", f"Git config exposed{extra}{creds}")


def _env_key_ok(key: str) -> bool:
    return "_" in key or (len(key) >= 2 and key.isupper())


def _check_env(body: bytes, text: str) -> _Hit | None:
    if _looks_html(text):
        return None
    keys: list[str] = []
    interesting = 0
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        interesting += 1
        match = _ENV_LINE.match(stripped)
        if match:
            keys.append(match.group(1))
    if interesting == 0 or not keys:
        return None
    if len(keys) / interesting < 0.5:
        return None
    if len(keys) < 2 and not any(_env_key_ok(key) for key in keys):
        return None
    shown = ", ".join(keys[:12])
    more = f" (+{len(keys) - 12} more)" if len(keys) > 12 else ""
    return _Hit("high", f"Environment file exposed; keys: {shown}{more} (values redacted)")


def _check_svn(body: bytes, text: str) -> _Hit | None:
    low = text.lower()
    if "<wc-entries" in low:
        return _Hit("high", "SVN working copy entries exposed")
    lines = [line.strip() for line in text.splitlines() if line.strip()][:8]
    if lines and re.fullmatch(r"\d{1,2}", lines[0]) and any(line in {"dir", "file"} for line in lines[1:6]):
        return _Hit("high", "SVN working copy entries exposed")
    return None


def _check_ds_store(body: bytes, text: str) -> _Hit | None:
    if body.startswith(b"\x00\x00\x00\x01Bud1"):
        return _Hit("low", "macOS .DS_Store metadata exposed")
    return None


def _check_server_status(body: bytes, text: str) -> _Hit | None:
    low = text.lower()
    if "apache server status" in low or ("server version:" in low and "server built:" in low):
        return _Hit("medium", "Apache server-status page exposed (request list not stored)")
    return None


def _check_phpinfo(body: bytes, text: str) -> _Hit | None:
    low = text.lower()
    if "php version" in low and ("phpinfo()" in low or "zend engine" in low):
        return _Hit("high", "phpinfo() page exposed (body not stored)")
    return None


def _check_wp_config(body: bytes, text: str) -> _Hit | None:
    names = _DEFINE.findall(text)
    if not names:
        return None
    needed = {"DB_NAME", "DB_USER", "DB_PASSWORD", "DB_HOST", "AUTH_KEY", "SECURE_AUTH_KEY"}
    if not any(name in needed for name in names):
        return None
    uniq = list(dict.fromkeys(names))[:12]
    shown = ", ".join(uniq)
    return _Hit("high", f"WordPress config backup exposed; constants: {shown} (values redacted)")


def _check_zip(body: bytes, text: str) -> _Hit | None:
    if body.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return _Hit("high", "ZIP archive exposed (not extracted)")
    return None


def _check_config_json(body: bytes, text: str) -> _Hit | None:
    data = _loads_json(text)
    if not isinstance(data, dict) or not data:
        return None
    sensitive = [key for key in _collect_keys(data) if _is_sensitive(key)]
    if not sensitive:
        return None
    shown = ", ".join(dict.fromkeys(sensitive))
    if len(shown) > 180:
        shown = shown[:177] + "..."
    return _Hit("high", f"JSON config exposed; keys: {shown} (values redacted)")


def _check_actuator_env(body: bytes, text: str) -> _Hit | None:
    data = _loads_json(text)
    if not isinstance(data, dict):
        return None
    if "propertySources" not in data and "systemEnvironment" not in data:
        return None
    names: list[str] = []
    sources = data.get("propertySources")
    if isinstance(sources, list):
        for source in sources:
            if not isinstance(source, dict):
                continue
            props = source.get("properties")
            if not isinstance(props, dict):
                continue
            for key in props.keys():
                if isinstance(key, str) and _SAFE_KEY.fullmatch(key):
                    names.append(key)
                if len(names) >= 12:
                    break
    system_env = data.get("systemEnvironment")
    if isinstance(system_env, dict):
        for key in system_env.keys():
            if isinstance(key, str) and _SAFE_KEY.fullmatch(key):
                names.append(key)
            if len(names) >= 12:
                break
    uniq = list(dict.fromkeys(names))[:12]
    detail = f"; properties: {', '.join(uniq)}" if uniq else ""
    return _Hit("high", f"Spring actuator env exposed{detail} (values redacted)")


def _check_actuator_health(body: bytes, text: str) -> _Hit | None:
    data = _loads_json(text)
    if not isinstance(data, dict):
        return None
    status = data.get("status")
    if not isinstance(status, str):
        return None
    status_up = status.strip().upper()
    if status_up not in {"UP", "DOWN", "OUT_OF_SERVICE", "UNKNOWN"}:
        return None
    if not _SAFE_KEY.fullmatch(status_up):
        return None
    comps = data.get("components")
    if not isinstance(comps, dict):
        comps = data.get("details") if isinstance(data.get("details"), dict) else {}
    names = [
        key for key in comps.keys()
        if isinstance(key, str) and _SAFE_KEY.fullmatch(key)
    ][:8] if isinstance(comps, dict) else []
    if names:
        return _Hit(
            "low",
            f"Spring actuator health is {status_up}; components: {', '.join(names)} "
            "(details not stored)",
        )
    if isinstance(comps, dict) and comps:
        return _Hit("low", f"Spring actuator health is {status_up}; component details present (details not stored)")
    return _Hit("info", f"Spring actuator health is {status_up}")


def _check_openapi(body: bytes, text: str) -> _Hit | None:
    data = _loads_json(text)
    if not isinstance(data, dict):
        return None
    version = data.get("openapi", data.get("swagger"))
    if "openapi" not in data and "swagger" not in data:
        return None
    label = ""
    if isinstance(version, str) and re.fullmatch(r"[0-9.]{1,16}", version):
        label = f" ({version})"
    count = 0
    paths = data.get("paths")
    if isinstance(paths, dict):
        count = min(len(paths), 9999)
    suffix = f", {count} paths" if count else ""
    return _Hit("medium", f"OpenAPI document exposed{label}{suffix}")


def _check_security_txt(body: bytes, text: str) -> _Hit | None:
    if _looks_html(text):
        return None
    fields: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or ":" not in stripped:
            continue
        name = stripped.split(":", 1)[0].strip()
        if re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,30}", name):
            fields.append(name)
    lowered = [field_name.lower() for field_name in fields]
    if "contact" not in lowered:
        return None
    uniq: list[str] = []
    for field_name in fields:
        if field_name not in uniq:
            uniq.append(field_name)
        if len(uniq) >= 8:
            break
    return _Hit("info", f"security.txt published; fields: {', '.join(uniq)}")


def _directive_paths(text: str, field_name: str) -> list[str]:
    found: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        if key.strip().lower() != field_name:
            continue
        lead = _clean_lead(value.strip())
        if lead and lead not in found:
            found.append(lead)
        if len(found) >= 25:
            break
    return found


def _check_robots(body: bytes, text: str) -> _Hit | None:
    if _looks_html(text):
        return None
    has_agent = False
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        if key.strip().lower() == "user-agent" and value.strip():
            has_agent = True
            break
    if not has_agent:
        return None
    disallows = _directive_paths(text, "disallow")
    hit = _Hit(
        "info",
        f"robots.txt published; {len(disallows)} disallowed path(s) listed and not requested",
    )
    hit.leads = [("/robots.txt", path) for path in disallows]
    return hit


def _check_sitemap(body: bytes, text: str) -> _Hit | None:
    low = text.lower()
    if "<urlset" not in low and "<sitemapindex" not in low:
        return None
    return _Hit("info", "XML sitemap exposed")


def _finish_sitemap(hit: _Hit, text: str, host: str) -> _Hit:
    leads: list[str] = []
    for loc in _SITEMAP_LOC.findall(text):
        path = _lead_from_url(loc, host)
        if path and path not in leads:
            leads.append(path)
        if len(leads) >= 25:
            break
    hit.reason = f"XML sitemap exposed; {len(leads)} location(s) listed and not requested"
    hit.leads = [("/sitemap.xml", path) for path in leads]
    return hit


def _check_admin(body: bytes, text: str) -> _Hit | None:
    if _looks_not_found(text):
        return None
    low = text.lower()
    if not ("<html" in low or "<!doctype" in low or "<form" in low or "<input" in low):
        return None
    if _has_password_input(text) or "wp-login.php" in low or ("dashboard" in low and "logout" in low):
        return _Hit("medium", "Admin interface exposed")
    return None


def _check_login(body: bytes, text: str) -> _Hit | None:
    if _looks_not_found(text):
        return None
    low = text.lower()
    if not ("<html" in low or "<!doctype" in low or "<form" in low or "<input" in low):
        return None
    if _has_password_input(text):
        return _Hit("low", "Login form exposed")
    return None


PROBES: tuple[_Probe, ...] = (
    _Probe("/.git/HEAD", _check_git_head),
    _Probe("/.git/config", _check_git_config),
    _Probe("/.env", _check_env),
    _Probe("/.svn/entries", _check_svn),
    _Probe("/.DS_Store", _check_ds_store),
    _Probe("/server-status", _check_server_status),
    _Probe("/phpinfo.php", _check_phpinfo),
    _Probe("/wp-config.php.bak", _check_wp_config),
    _Probe("/backup.zip", _check_zip),
    _Probe("/config.json", _check_config_json),
    _Probe("/actuator/env", _check_actuator_env),
    _Probe("/actuator/health", _check_actuator_health),
    _Probe("/swagger.json", _check_openapi),
    _Probe("/openapi.json", _check_openapi),
    _Probe("/.well-known/security.txt", _check_security_txt, weak=True),
    _Probe("/robots.txt", _check_robots, weak=True),
    _Probe("/sitemap.xml", _check_sitemap, weak=True),
    _Probe("/admin", _check_admin, weak=True),
    _Probe("/login", _check_login, weak=True),
)
PROBE_PATHS: tuple[str, ...] = tuple(probe.path for probe in PROBES)


# ── Technology fingerprint ────────────────────────────────────────────

def _add(found: list[tuple[str, str]], name: str, evidence: str) -> None:
    evidence = _sanitize_inline(evidence, 160)
    if name and evidence:
        found.append((name, evidence))


def fingerprint(
    headers: dict[str, str] | None = None,
    cookies: list[str] | None = None,
    html: str = "",
) -> list[WebTechnology]:
    """Identify technologies from headers, cookie names, and HTML.

    Cookie values and other secret material are not retained. ``cookies``
    may be names or raw ``Set-Cookie`` strings; only the name is kept.
    """
    hdrs: dict[str, str] = {}
    for key, value in (headers or {}).items():
        if isinstance(key, str) and isinstance(value, str):
            hdrs[key.strip().lower()] = _sanitize_inline(value, 180)
    names: list[str] = []
    for cookie in cookies or []:
        if not isinstance(cookie, str):
            continue
        name = _cookie_name(cookie + "=") if "=" not in cookie else _cookie_name(cookie)
        if name is None and "=" not in cookie:
            name = cookie.strip() if _COOKIE_RE.fullmatch(cookie.strip()) else None
        if name and name not in names:
            names.append(name)
    page = html[:12000] if isinstance(html, str) else ""
    low_page = page.lower()
    found: list[tuple[str, str]] = []

    server = hdrs.get("server", "")
    server_low = server.lower()
    if "cloudflare" in server_low:
        _add(found, "Cloudflare", f"Server: {server}")
    if "cf-ray" in hdrs or "cf-cache-status" in hdrs:
        evidence = "cf-ray header" if "cf-ray" in hdrs else "cf-cache-status header"
        if "cf-ray" in hdrs and hdrs["cf-ray"]:
            evidence = f"cf-ray: {hdrs['cf-ray']}"
        _add(found, "Cloudflare", evidence)
    if "nginx" in server_low:
        _add(found, "nginx", f"Server: {server}")
    if "openresty" in server_low:
        _add(found, "OpenResty", f"Server: {server}")
    if "litespeed" in server_low:
        _add(found, "LiteSpeed", f"Server: {server}")
    if "caddy" in server_low:
        _add(found, "Caddy", f"Server: {server}")
    if "gunicorn" in server_low:
        _add(found, "Gunicorn", f"Server: {server}")
    if "microsoft-iis" in server_low or server_low.startswith("iis/"):
        _add(found, "Microsoft IIS", f"Server: {server}")
    if "coyote" in server_low or "tomcat" in server_low:
        _add(found, "Apache Tomcat", f"Server: {server}")
    elif re.search(r"(?i)(^|[\s/])apache([/\s]|$)", server):
        _add(found, "Apache", f"Server: {server}")

    powered = hdrs.get("x-powered-by", "")
    powered_low = powered.lower()
    if "express" in powered_low:
        _add(found, "Express", f"X-Powered-By: {powered}")
    if "php" in powered_low:
        _add(found, "PHP", f"X-Powered-By: {powered}")
    if "asp.net" in powered_low or "x-aspnet-version" in hdrs:
        evidence = f"X-Powered-By: {powered}" if powered else "X-AspNet-Version header"
        _add(found, "ASP.NET", evidence)
    if "next.js" in powered_low or "nextjs" in powered_low:
        _add(found, "Next.js", f"X-Powered-By: {powered}")
    if "spring" in powered_low:
        _add(found, "Spring", f"X-Powered-By: {powered}")
    if hdrs.get("x-application-context"):
        _add(found, "Spring", "X-Application-Context header")
    if hdrs.get("x-drupal-cache") or hdrs.get("x-drupal-dynamic-cache"):
        _add(found, "Drupal", "Drupal cache header")

    generator = hdrs.get("x-generator", "")
    meta = ""
    match = _GEN_1.search(page) or _GEN_2.search(page)
    if match:
        meta = match.group(3) if match.re is _GEN_1 else match.group(2)
    for candidate in (generator, meta):
        if not candidate:
            continue
        low = candidate.lower()
        label = f"meta generator: {candidate}" if candidate == meta else f"X-Generator: {candidate}"
        if "wordpress" in low:
            _add(found, "WordPress", label)
        if "drupal" in low:
            _add(found, "Drupal", label)
        if "django" in low:
            _add(found, "Django", label)
        if "laravel" in low:
            _add(found, "Laravel", label)
        if "next.js" in low or "nextjs" in low:
            _add(found, "Next.js", label)

    if "/wp-content/" in low_page or "/wp-includes/" in low_page:
        _add(found, "WordPress", "HTML references WordPress paths")
    if "drupal.settings" in low_page or "/sites/default/" in low_page or "drupal.js" in low_page:
        _add(found, "Drupal", "HTML references Drupal paths")
    if "csrfmiddlewaretoken" in low_page or "/static/admin/" in low_page:
        _add(found, "Django", "HTML references Django markers")
    if "/_next/static/" in low_page or "__next_data__" in low_page:
        _add(found, "Next.js", "HTML references Next.js paths")
    if "phpinfo()" in low_page and "php version" in low_page:
        _add(found, "PHP", "phpinfo() page")

    for name in names:
        low = name.lower()
        if low == "phpsessid":
            _add(found, "PHP", "cookie: PHPSESSID")
        elif low.startswith("wordpress_") or low.startswith("wp-settings") or low.startswith("wp-"):
            _add(found, "WordPress", f"cookie: {name}")
        elif low == "laravel_session" or low.startswith("laravel_"):
            _add(found, "Laravel", f"cookie: {name}")
        elif low == "jsessionid":
            _add(found, "Spring", "cookie: JSESSIONID")
        elif low == "connect.sid":
            _add(found, "Express", "cookie: connect.sid")
        elif low == "csrftoken":
            _add(found, "Django", "cookie: csrftoken")
        elif re.fullmatch(r"(?i)S?SESS[0-9a-f]{32}", name):
            _add(found, "Drupal", f"cookie: {name}")

    return _merge_technologies(found)


def _merge_technologies(pairs: list[tuple[str, str]] | list[WebTechnology]) -> list[WebTechnology]:
    order: list[str] = []
    evidence: dict[str, list[str]] = {}
    for item in pairs:
        if isinstance(item, WebTechnology):
            name, ev = item.name, item.evidence
        else:
            name, ev = item
        name = _sanitize_inline(name, 40)
        ev = _sanitize_inline(ev, 160)
        if not name or not ev:
            continue
        if name not in evidence:
            order.append(name)
            evidence[name] = []
        if ev not in evidence[name] and len(evidence[name]) < 3:
            evidence[name].append(ev)
    merged = [
        WebTechnology(name=name, evidence=" | ".join(evidence[name])[:180])
        for name in order
    ]
    merged.sort(key=lambda tech: tech.name.lower())
    return merged


def _html_for_fingerprint(headers: dict[str, str], body: bytes) -> str:
    if not body:
        return ""
    text = _decode_body(body[:12000])
    ctype = headers.get("content-type", "").lower()
    stripped = text.lstrip().lower()
    if "html" in ctype or "xml" in ctype or stripped.startswith("<!doctype") or stripped.startswith("<"):
        return text[:12000]
    return ""


# ── Scan ──────────────────────────────────────────────────────────────

def _outcome(
    probe: _Probe,
    fetched: _Fetched,
    baseline: _Baseline | None,
    host: str,
) -> tuple[WebFinding | None, list[WebLead], list[WebTechnology], str]:
    if fetched.error:
        return None, [], [], f"{probe.path}: {fetched.error}"
    html = _html_for_fingerprint(fetched.headers, fetched.body)
    techs = fingerprint(fetched.headers, fetched.cookies, html)
    if probe.weak and fetched.status >= 400:
        return None, [], techs, ""
    if not fetched.body or _matches_baseline(fetched.body, fetched.status, probe.path, baseline):
        return None, [], techs, ""
    text = _decode_body(fetched.body)
    try:
        hit = probe.check(fetched.body, text)
    except Exception:
        return None, [], techs, f"{probe.path}: probe failed"
    if hit is None:
        return None, [], techs, ""
    if probe.path == "/sitemap.xml":
        hit = _finish_sitemap(hit, text, host)
    if hit.severity not in _SEVERITIES:
        return None, [], techs, ""
    if not _same_host(fetched.url, host):
        return None, [], techs, f"{probe.path}: refused cross-host redirect"
    reason = _sanitize_inline(hit.reason, 300)
    if fetched.truncated:
        reason = _sanitize_inline(reason + " (response truncated at 64 KiB)", 300)
    finding = WebFinding(
        path=probe.path,
        url=_public_url(fetched.url),
        status=fetched.status,
        severity=hit.severity,
        reason=reason,
    )
    leads = [
        WebLead(source=source, path=path)
        for source, path in hit.leads
        if path
    ]
    return finding, leads, techs, ""


def _scan_probe(
    probe: _Probe,
    origin: str,
    host: str,
    timeout: float,
    budget: _Budget,
    baseline: _Baseline | None,
) -> tuple[WebFinding | None, list[WebLead], list[WebTechnology], str]:
    try:
        fetched = _fetch_chain(origin + probe.path, host, timeout, budget)
        return _outcome(probe, fetched, baseline, host)
    except Exception:
        return None, [], [], f"{probe.path}: probe failed"


def run(
    target: str,
    timeout: float = DEFAULT_TIMEOUT,
    threads: int = DEFAULT_THREADS,
    budget: int = DEFAULT_BUDGET,
) -> WebExposureResult:
    """Probe a fixed, small path list and fingerprint the HTTP service.

    ``timeout`` is the per-request connect/read timeout in seconds.
    ``threads`` is capped at a small pool. ``budget`` is the total number
    of GET requests, including the baseline, the homepage, and redirects.
    """
    origin, host = normalize_target(target)
    try:
        timeout_value = float(timeout)
        thread_count = int(threads)
        budget_limit = int(budget)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid web exposure options") from exc
    if timeout_value <= 0:
        raise ValueError("timeout must be positive")
    if thread_count < 1:
        raise ValueError("threads must be at least 1")
    if budget_limit < 1:
        raise ValueError("budget must be at least 1")
    timeout_value = min(timeout_value, 30.0)
    thread_count = min(thread_count, MAX_WORKERS, len(PROBES))
    limiter = _Budget(budget_limit)

    result = WebExposureResult(base_url=origin)
    token = secrets.token_hex(8)
    baseline_path = f"/.netrecon-baseline-{token}"
    baseline_fetch = _fetch_chain(origin + baseline_path, host, timeout_value, limiter)
    baseline: _Baseline | None = None
    tech_items: list[WebTechnology] = []
    if baseline_fetch.error:
        result.errors.append(f"baseline: {baseline_fetch.error}")
    else:
        baseline = _baseline_from(baseline_fetch.body, baseline_fetch.status, baseline_path)
        tech_items.extend(fingerprint(
            baseline_fetch.headers,
            baseline_fetch.cookies,
            _html_for_fingerprint(baseline_fetch.headers, baseline_fetch.body),
        ))

    home = _fetch_chain(origin + "/", host, timeout_value, limiter)
    if home.error:
        result.errors.append(f"homepage: {home.error}")
    else:
        tech_items.extend(fingerprint(
            home.headers,
            home.cookies,
            _html_for_fingerprint(home.headers, home.body),
        ))

    findings: list[WebFinding] = []
    leads: list[WebLead] = []
    workers = max(1, thread_count)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [
            pool.submit(_scan_probe, probe, origin, host, timeout_value, limiter, baseline)
            for probe in PROBES
        ]
        for future in as_completed(futures):
            try:
                finding, probe_leads, techs, error = future.result()
            except Exception:
                result.errors.append("probe failed")
                continue
            if finding is not None:
                findings.append(finding)
            leads.extend(probe_leads)
            tech_items.extend(techs)
            if error:
                result.errors.append(error)

    findings.sort(key=lambda item: (_SEV_RANK.get(item.severity, 9), item.path))
    dedup_leads: list[WebLead] = []
    seen_leads: set[tuple[str, str]] = set()
    for lead in leads:
        key = (lead.source, lead.path)
        if key in seen_leads:
            continue
        seen_leads.add(key)
        dedup_leads.append(lead)
    dedup_leads.sort(key=lambda lead: (lead.source, lead.path))

    dedup_errors: list[str] = []
    seen_errors: set[str] = set()
    for error in result.errors:
        if error not in seen_errors:
            seen_errors.add(error)
            dedup_errors.append(error)

    result.findings = findings
    result.leads = dedup_leads[:40]
    result.technologies = _merge_technologies(tech_items)
    result.errors = dedup_errors[:30]
    return result


def display(result: WebExposureResult) -> None:
    width = 60
    icons = {"high": "🔴", "medium": "🟠", "low": "🟡", "info": "•"}
    print(f"\n{'─' * width}")
    print(f"  WEB EXPOSURE  {result.base_url}")
    print(f"{'─' * width}")
    if not result.findings:
        print("  No exposed paths confirmed.")
    for finding in result.findings:
        icon = icons.get(finding.severity, "•")
        print(f"  {icon} {finding.severity:<6} {finding.status:<4} {finding.path}")
        print(f"    {finding.reason}")
        print(f"    {finding.url}")
    if result.technologies:
        print("\n  Technologies:")
        for tech in result.technologies:
            print(f"    {tech.name} — {tech.evidence}")
    if result.leads:
        print("\n  Leads (not requested):")
        for lead in result.leads[:12]:
            print(f"    {lead.source}  {lead.path}")
        if len(result.leads) > 12:
            print(f"    (+{len(result.leads) - 12} more)")
    if result.errors:
        print("\n  Notes:")
        for error in result.errors[:12]:
            print(f"    {error}")
    print(f"{'─' * width}\n")
