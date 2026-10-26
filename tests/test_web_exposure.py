"""Web exposure probe: content checks, soft 404s, and report output.

HTTP is mocked. Nothing in this module contacts the network.
"""
import json
import threading
import urllib.parse

import pytest
import requests

from netrecon.cli import build_parser
from netrecon.models import (
    DnsResult,
    HeaderResult,
    PortEntry,
    ReconReport,
    SslResult,
    WebExposureResult,
    WebFinding,
    WebLead,
    WebTechnology,
    WhoisResult,
)
from netrecon.modules import web_exposure
from netrecon.report import html_report, json_report


ENV_SECRET = "ENVSECRET_9f3a"
ENV_SECRET_2 = "ENVSECRET2_9f3a"
GIT_SECRET = "GITSECRET_9f3a"
SVN_SECRET = "SVNSECRET_9f3a"
WP_SECRET = "WPSECRET_9f3a"
WP_DB_SECRET = "WPDBSECRET_9f3a"
JSON_SECRET = "JSONSECRET_9f3a"
JSON_HOST = "db-host-secret.internal"
ACTUATOR_SECRET = "ACTUATORSECRET_9f3a"
HEALTH_SECRET = "HEALTHSECRET_9f3a"
MAIL_SECRET = "SECMAIL_9f3a@example.com"
ROBOT_SECRET = "ROBOTSECRET_9f3a"
SITEMAP_SECRET = "SITEMAPSECRET_9f3a"
COOKIE_SECRET = "COOKIESECRET_9f3a"
HEADER_SECRET = "HEADERSECRET_9f3a"
TITLE_SECRET = "TITLESECRET_9f3a"
QUERY_SECRET = "QUERYSECRET_9f3a"
EXC_SECRET = "EXCSECRET_9f3a"
LEAK_SECRET = "LEAKSECRET_9f3a"
REDIR_SECRET = "REDIRSECRET_9f3a"

SECRETS = [
    ENV_SECRET, ENV_SECRET_2, GIT_SECRET, SVN_SECRET, WP_SECRET, WP_DB_SECRET,
    JSON_SECRET, JSON_HOST, ACTUATOR_SECRET, HEALTH_SECRET, MAIL_SECRET,
    ROBOT_SECRET, SITEMAP_SECRET, COOKIE_SECRET, HEADER_SECRET, TITLE_SECRET,
    QUERY_SECRET, EXC_SECRET, LEAK_SECRET, REDIR_SECRET,
    "githost-secret.example", "svn-host-secret.example",
]

NOT_FOUND = (
    404,
    b"<html><title>404 Not Found</title><p>missing</p></html>",
    {"Content-Type": "text/html"},
)

GIT_CONFIG = (
    "[core]\n"
    "\trepositoryformatversion = 0\n"
    "[remote \"origin\"]\n"
    f"\turl = https://user:{GIT_SECRET}@githost-secret.example/org/app.git\n"
).encode()

ENV_BODY = f"DB_PASSWORD={ENV_SECRET}\nAPI_KEY={ENV_SECRET_2}\n".encode()

SVN_BODY = (
    "12\n"
    "dir\n"
    "2484\n"
    f"https://user:{SVN_SECRET}@svn-host-secret.example/repo\n"
).encode()

WP_BODY = (
    "<?php\n"
    f"define('DB_NAME', '{WP_DB_SECRET}');\n"
    f"define('DB_PASSWORD', '{WP_SECRET}');\n"
    "define('AUTH_KEY', 'auth-key-secret');\n"
).encode()

CONFIG_JSON = json.dumps({
    "database": {"host": JSON_HOST, "password": JSON_SECRET},
    "debug": False,
}).encode()

ACTUATOR_ENV = json.dumps({
    "propertySources": [{
        "name": "systemProperties",
        "properties": {"db.password": {"value": ACTUATOR_SECRET}},
    }],
}).encode()

ACTUATOR_HEALTH = json.dumps({
    "status": "UP",
    "components": {"db": {"status": "UP", "details": {"password": HEALTH_SECRET}}},
}).encode()

SWAGGER = json.dumps({
    "swagger": "2.0",
    "info": {"title": TITLE_SECRET},
    "paths": {"/v1/users": {}},
}).encode()

OPENAPI = json.dumps({
    "openapi": "3.0.1",
    "info": {"title": TITLE_SECRET},
    "paths": {"/v1/users": {}, "/v1/health": {}},
}).encode()

SECURITY_TXT = (
    f"Contact: mailto:{MAIL_SECRET}\n"
    "Expires: 2027-01-01T00:00:00Z\n"
    "Preferred-Languages: en\n"
).encode()

ROBOTS = (
    "User-agent: *\n"
    "Disallow: /secret-admin\n"
    f"Disallow: /backup.sql?token={ROBOT_SECRET}\n"
).encode()

SITEMAP = (
    "<?xml version=\"1.0\"?>\n"
    "<urlset>\n"
    f"  <url><loc>https://example.com/hidden-page?token={SITEMAP_SECRET}</loc></url>\n"
    "  <url><loc>https://evil.example/offhost-page</loc></url>\n"
    "</urlset>\n"
).encode()

ADMIN_HTML = b"<!doctype html><html><body><form><input type=\"password\"></form></body></html>"
LOGIN_HTML = b"<!doctype html><html><body><form action=\"/login\"><input type='password'></form></body></html>"
PHPINFO = (
    b"<!DOCTYPE html><html><head><title>phpinfo()</title></head>"
    b"<body><h1>PHP Version 8.2.0</h1></body></html>"
)
SERVER_STATUS = (
    b"<html><head><title>Apache Server Status</title></head>"
    b"<body><h1>Apache Server Status for example</h1></body></html>"
)
DS_STORE = b"\x00\x00\x00\x01Bud1" + b"\x00" * 16
ZIP_BYTES = b"PK\x03\x04" + b"\x00" * 32

HOME_HTML = (
    b"<!doctype html><html><head>"
    b"<meta name=\"generator\" content=\"WordPress 6.4.2\">"
    b"</head><body><script src=\"/wp-includes/js/wp-embed.min.js\"></script>"
    b"</body></html>"
)

POSITIVE = {
    "/.git/HEAD": (200, b"ref: refs/heads/main\n", {"Content-Type": "text/plain"}),
    "/.git/config": (200, GIT_CONFIG, {"Content-Type": "text/plain"}),
    "/.env": (200, ENV_BODY, {
        "Content-Type": "text/plain",
        "X-Env-Password": HEADER_SECRET,
    }),
    "/.svn/entries": (200, SVN_BODY, {"Content-Type": "text/plain"}),
    "/.DS_Store": (200, DS_STORE, {"Content-Type": "application/octet-stream"}),
    "/server-status": (200, SERVER_STATUS, {"Content-Type": "text/html"}),
    "/phpinfo.php": (200, PHPINFO, {"Content-Type": "text/html"}),
    "/wp-config.php.bak": (200, WP_BODY, {"Content-Type": "text/plain"}),
    "/backup.zip": (200, ZIP_BYTES, {"Content-Type": "application/zip"}),
    "/config.json": (200, CONFIG_JSON, {"Content-Type": "application/json"}),
    "/actuator/env": (200, ACTUATOR_ENV, {"Content-Type": "application/json"}),
    "/actuator/health": (200, ACTUATOR_HEALTH, {"Content-Type": "application/json"}),
    "/swagger.json": (200, SWAGGER, {"Content-Type": "application/json"}),
    "/openapi.json": (200, OPENAPI, {"Content-Type": "application/json"}),
    "/.well-known/security.txt": (200, SECURITY_TXT, {"Content-Type": "text/plain"}),
    "/robots.txt": (200, ROBOTS, {"Content-Type": "text/plain"}),
    "/sitemap.xml": (200, SITEMAP, {"Content-Type": "application/xml"}),
    "/admin": (200, ADMIN_HTML, {"Content-Type": "text/html"}),
    "/login": (200, LOGIN_HTML, {"Content-Type": "text/html"}),
}

REASON_BITS = {
    "/.git/HEAD": "refs/heads/main",
    "/.git/config": "credentials redacted",
    "/.env": "DB_PASSWORD",
    "/.svn/entries": "SVN",
    "/.DS_Store": ".DS_Store",
    "/server-status": "server-status",
    "/phpinfo.php": "phpinfo()",
    "/wp-config.php.bak": "DB_PASSWORD",
    "/backup.zip": "ZIP",
    "/config.json": "database.password",
    "/actuator/env": "db.password",
    "/actuator/health": "components: db",
    "/swagger.json": "2.0",
    "/openapi.json": "3.0.1",
    "/.well-known/security.txt": "Contact",
    "/robots.txt": "not requested",
    "/sitemap.xml": "not requested",
    "/admin": "Admin",
    "/login": "Login",
}

SEVERITY = {
    "/.git/HEAD": "high",
    "/.git/config": "high",
    "/.env": "high",
    "/.svn/entries": "high",
    "/.DS_Store": "low",
    "/server-status": "medium",
    "/phpinfo.php": "high",
    "/wp-config.php.bak": "high",
    "/backup.zip": "high",
    "/config.json": "high",
    "/actuator/env": "high",
    "/actuator/health": "low",
    "/swagger.json": "medium",
    "/openapi.json": "medium",
    "/.well-known/security.txt": "info",
    "/robots.txt": "info",
    "/sitemap.xml": "info",
    "/admin": "medium",
    "/login": "low",
}


class FakeResponse:
    def __init__(self, status, body, headers, url):
        self.status_code = status
        self.headers = dict(headers or {})
        self.url = url
        self._body = body if isinstance(body, bytes) else str(body).encode()
        self.raw = None

    def iter_content(self, chunk_size=8192):
        view = self._body
        for index in range(0, len(view), chunk_size):
            yield view[index:index + chunk_size]

    def close(self):
        return None


class Hub:
    def __init__(self, router):
        self.router = router
        self.calls = []
        self.kwargs = []
        self.lock = threading.Lock()


class FakeSession:
    def __init__(self, hub):
        self.hub = hub
        self.trust_env = True
        self.max_redirects = 30

    def close(self):
        return None

    def get(self, url, **kwargs):
        with self.hub.lock:
            self.hub.calls.append(url)
            self.hub.kwargs.append(kwargs)
        result = self.hub.router(url)
        if isinstance(result, BaseException):
            raise result
        status, body, headers = result
        return FakeResponse(status, body, headers, url)

    def post(self, *args, **kwargs):
        raise AssertionError("POST is not allowed")

    def put(self, *args, **kwargs):
        raise AssertionError("PUT is not allowed")

    def delete(self, *args, **kwargs):
        raise AssertionError("DELETE is not allowed")

    def request(self, method, url, **kwargs):
        if str(method).upper() != "GET":
            raise AssertionError(method)
        return self.get(url, **kwargs)


def install(monkeypatch, router):
    hub = Hub(router)
    monkeypatch.setattr(web_exposure.requests, "Session", lambda: FakeSession(hub))
    return hub


def assert_safe_requests(hub):
    assert hub.calls
    for kwargs in hub.kwargs:
        assert kwargs["allow_redirects"] is False
        assert kwargs["stream"] is True
        assert kwargs["headers"]["User-Agent"] == web_exposure.USER_AGENT
        assert kwargs["headers"]["Accept-Encoding"] == "identity"
        assert kwargs["timeout"] > 0


def call_paths(hub):
    return [urllib.parse.urlsplit(url).path for url in hub.calls]


def route_map(routes, home=None, fallback=NOT_FOUND):
    home_response = home or (
        200,
        b"<!doctype html><html><head><title>Home</title></head><body>ok</body></html>",
        {"Content-Type": "text/html", "Server": "nginx/1.25.3"},
    )

    def router(url):
        path = urllib.parse.urlsplit(url).path
        if path in routes:
            return routes[path]
        if path.startswith("/.netrecon-baseline-"):
            return fallback
        if path == "/":
            return home_response
        return fallback

    return router


def check(path, body):
    raw = body if isinstance(body, bytes) else body.encode()
    text = raw.decode("utf-8", errors="replace")
    for probe in web_exposure.PROBES:
        if probe.path == path:
            return probe.check(raw, text)
    raise AssertionError(path)


def render(result, tmp_path, capsys, target="example.com"):
    web_exposure.display(result)
    text = capsys.readouterr().out
    report = ReconReport(
        target=target,
        web_exposure=result,
        ports=[PortEntry(port=80, state="open", service="http", banner="banner-keep")],
    )
    report.summary()
    text += capsys.readouterr().out
    json_path = tmp_path / "report.json"
    html_path = tmp_path / "report.html"
    json_report.save(report, str(json_path))
    html_report.save(report, str(html_path))
    text += capsys.readouterr().out
    raw_json = json_path.read_text()
    raw_html = html_path.read_text()
    blob = text + raw_json + raw_html + repr(result)
    return blob, json.loads(raw_json), raw_html


def assert_redacted(blob):
    for secret in SECRETS:
        assert secret not in blob


# ── Path list and direct content checks ──────────────────────────────

def test_probe_list_covers_the_high_signal_paths():
    required = {
        "/.git/HEAD", "/.git/config", "/.env", "/.svn/entries", "/.DS_Store",
        "/server-status", "/phpinfo.php", "/wp-config.php.bak", "/backup.zip",
        "/config.json", "/actuator/env", "/actuator/health", "/swagger.json",
        "/openapi.json", "/.well-known/security.txt", "/robots.txt",
        "/sitemap.xml", "/admin", "/login",
    }
    assert required <= set(web_exposure.PROBE_PATHS)


@pytest.mark.parametrize("path", list(POSITIVE))
def test_each_path_matches_its_content(path):
    _status, body, _headers = POSITIVE[path]
    hit = check(path, body)
    if path == "/sitemap.xml":
        assert hit is not None
        hit = web_exposure._finish_sitemap(hit, body.decode(), "example.com")
    assert hit is not None
    assert hit.severity == SEVERITY[path]
    assert REASON_BITS[path] in hit.reason
    blob = hit.reason + " ".join(lead for _src, lead in hit.leads)
    assert_redacted(blob)


@pytest.mark.parametrize(
    "path,body",
    [
        ("/.git/HEAD", b"<html>ref: refs/heads/main later</html>"),
        ("/.git/HEAD", b"refs/heads/main\n"),
        ("/.git/config", b"this is not a git config\n"),
        ("/.env", b"<html><body>DB_PASSWORD=nope</body></html>"),
        ("/.env", b"A=1\n"),
        ("/.env", b"hello world\nnot assignments\n"),
        ("/.svn/entries", b"just a text file\n"),
        ("/.DS_Store", b"xxxxBud1 not at the start"),
        ("/server-status", b"<html><title>Apache</title></html>"),
        ("/phpinfo.php", b"<html><body>PHP Version 8 was released.</body></html>"),
        ("/wp-config.php.bak", b"<?php echo 'no defines';"),
        ("/backup.zip", b"PK not a real archive"),
        ("/config.json", b'{"message":"hello"}'),
        ("/actuator/env", b'{"status":"UP"}'),
        ("/actuator/health", b'{"status":"OK"}'),
        ("/swagger.json", b'{"info":{"title":"nope"}}'),
        ("/.well-known/security.txt", b"Hello: there\n"),
        ("/robots.txt", b"hello world\n"),
        ("/sitemap.xml", b"<html><body>no sitemap</body></html>"),
        ("/admin", b"<!doctype html><html><title>Admin</title></html>"),
        ("/login", b"<!doctype html><html><h1>Login</h1></html>"),
        ("/admin", b"<html><title>404 Not Found</title><input type=\"password\"></html>"),
        ("/login", b"<html>page not found <input type=\"password\"></html>"),
    ],
)
def test_lookalike_content_is_not_a_hit(path, body):
    assert check(path, body) is None


def test_git_head_does_not_echo_the_rest_of_the_file():
    hit = check("/.git/HEAD", b"ref: " + b"X" * 400)
    assert hit is not None
    assert "XXX" not in hit.reason
    assert hit.reason == "Git HEAD exposed (ref pointer)"


def test_env_accepts_two_lowercase_keys_without_values():
    hit = check("/.env", b"foo=super-secret\nbaz=other-secret\n")
    assert hit is not None
    assert "foo" in hit.reason and "baz" in hit.reason
    assert "super-secret" not in hit.reason
    assert "other-secret" not in hit.reason


def test_robots_and_sitemap_leads_drop_queries_and_off_host_urls():
    robots = check("/robots.txt", ROBOTS)
    assert [lead for _src, lead in robots.leads] == ["/secret-admin", "/backup.sql"]
    sitemap = check("/sitemap.xml", SITEMAP)
    sitemap = web_exposure._finish_sitemap(sitemap, SITEMAP.decode(), "example.com")
    assert [lead for _src, lead in sitemap.leads] == ["/hidden-page"]
    assert_redacted(sitemap.reason + robots.reason)


def test_svn_xml_entries_match_without_the_repository_url():
    body = (
        "<?xml version=\"1.0\"?>\n"
        f"<wc-entries xmlns=\"svn:\"><entry url=\"https://user:{SVN_SECRET}@svn-host-secret.example/repo\"/>"
        "</wc-entries>\n"
    )
    hit = check("/.svn/entries", body)
    assert hit is not None
    assert SVN_SECRET not in hit.reason
    assert "svn-host-secret" not in hit.reason


# ── Technology fingerprint ────────────────────────────────────────────

def test_fingerprint_headers_cookies_and_html_without_secret_values():
    wordpress = web_exposure.fingerprint(
        {"Server": "nginx/1.25.3", "CF-Ray": "abc123"},
        [f"laravel_session={COOKIE_SECRET}; Path=/; HttpOnly", "PHPSESSID"],
        "<html><meta name=\"generator\" content=\"WordPress 6.4.2\">"
        "<script src=\"/wp-includes/js/wp-embed.min.js\"></script></html>",
    )
    names = {tech.name for tech in wordpress}
    assert {"nginx", "Cloudflare", "WordPress", "Laravel", "PHP"} <= names
    blob = " ".join(tech.evidence for tech in wordpress)
    assert COOKIE_SECRET not in blob
    assert "laravel_session" in blob
    assert "WordPress 6.4.2" in blob

    express = web_exposure.fingerprint({"X-Powered-By": "Express"}, ["connect.sid"])
    assert {tech.name for tech in express} >= {"Express"}

    spring = web_exposure.fingerprint(
        {"X-Application-Context": "app:prod"},
        ["JSESSIONID"],
    )
    assert {tech.name for tech in spring} == {"Spring"}

    django = web_exposure.fingerprint(
        {},
        ["csrftoken"],
        f"<html><input name=\"csrfmiddlewaretoken\" value=\"{JSON_SECRET}\"></html>",
    )
    assert {tech.name for tech in django} == {"Django"}
    assert JSON_SECRET not in " ".join(tech.evidence for tech in django)

    drupal = web_exposure.fingerprint(
        {"X-Drupal-Cache": "HIT", "X-Generator": "Drupal 10"},
        ["SESS" + "ab" * 16],
    )
    assert "Drupal" in {tech.name for tech in drupal}

    apache = web_exposure.fingerprint({"Server": "Apache/2.4.51"})
    coyote = web_exposure.fingerprint({"Server": "Apache-Coyote/1.1"})
    assert {tech.name for tech in apache} == {"Apache"}
    assert {tech.name for tech in coyote} == {"Apache Tomcat"}

    iis = web_exposure.fingerprint(
        {"Server": "Microsoft-IIS/10.0", "X-AspNet-Version": "4.0.30319"},
    )
    assert {"Microsoft IIS", "ASP.NET"} <= {tech.name for tech in iis}

    nxt = web_exposure.fingerprint({}, [], "<html><script src=\"/_next/static/main.js\"></script></html>")
    assert {tech.name for tech in nxt} == {"Next.js"}

    messy = web_exposure.fingerprint({"Server": "nginx\x1b[31m/1.25.3\r\nX-Injected: 1"})
    evidence = messy[0].evidence
    assert "\x1b" not in evidence
    assert "\n" not in evidence
    assert "\r" not in evidence
    assert "nginx" in evidence


# ── End-to-end mocked HTTP ────────────────────────────────────────────

def test_run_confirms_every_path_and_redacts_secrets(monkeypatch, tmp_path, capsys):
    home = (
        200,
        HOME_HTML,
        {
            "Content-Type": "text/html",
            "Server": "nginx/1.25.3",
            "CF-Ray": "7f3a9-ORD",
            "Set-Cookie": f"laravel_session={COOKIE_SECRET}; Path=/; HttpOnly",
        },
    )
    hub = install(monkeypatch, route_map(POSITIVE, home=home))
    result = web_exposure.run("example.com", threads=1)
    assert_safe_requests(hub)
    assert result.base_url == "https://example.com"
    by_path = {finding.path: finding for finding in result.findings}
    assert set(by_path) == set(web_exposure.PROBE_PATHS)
    for path, finding in by_path.items():
        assert finding.severity == SEVERITY[path]
        assert finding.status == 200
        assert finding.url == "https://example.com" + path
        assert REASON_BITS[path] in finding.reason

    leads = {(lead.source, lead.path) for lead in result.leads}
    assert ("/robots.txt", "/secret-admin") in leads
    assert ("/robots.txt", "/backup.sql") in leads
    assert ("/sitemap.xml", "/hidden-page") in leads
    assert all("evil.example" not in lead.path for lead in result.leads)

    requested = set(call_paths(hub))
    assert set(web_exposure.PROBE_PATHS) <= requested
    assert "/" in requested
    assert any(path.startswith("/.netrecon-baseline-") for path in requested)
    assert "/secret-admin" not in requested
    assert "/backup.sql" not in requested
    assert "/hidden-page" not in requested
    assert not any("evil.example" in url for url in hub.calls)

    names = {tech.name for tech in result.technologies}
    assert {"nginx", "Cloudflare", "WordPress", "Laravel", "PHP"} <= names

    blob, data, raw_html = render(result, tmp_path, capsys)
    assert_redacted(blob)
    assert "values redacted" in blob
    assert data["web_exposure"]["findings"]
    assert "DB_PASSWORD" in raw_html
    assert ENV_SECRET not in raw_html


def test_parallel_run_matches_the_serial_findings(monkeypatch):
    hub = install(monkeypatch, route_map(POSITIVE, home=(200, HOME_HTML, {
        "Content-Type": "text/html",
        "Server": "nginx/1.25.3",
    })))
    result = web_exposure.run("Example.COM", threads=4)
    assert_safe_requests(hub)
    assert result.base_url == "https://example.com"
    assert {finding.path for finding in result.findings} == set(web_exposure.PROBE_PATHS)
    assert all(urllib.parse.urlsplit(url).scheme == "https" for url in hub.calls)


def test_soft_404_suppresses_catch_all_and_reflected_bodies(monkeypatch):
    shell = b"<!doctype html><html><body><input type=\"password\"><script>admin login</script></body></html>"

    def spa(url):
        return 200, shell, {"Content-Type": "text/html", "Server": "nginx"}

    hub = install(monkeypatch, spa)
    result = web_exposure.run("https://example.com", threads=1)
    assert result.findings == []
    assert {tech.name for tech in result.technologies} == {"nginx"}
    assert_safe_requests(hub)

    def reflected(url):
        path = urllib.parse.urlsplit(url).path
        body = b"ref: refs/heads/main\nPATH:" + path.encode()
        return 200, body, {"Content-Type": "text/plain"}

    install(monkeypatch, reflected)
    reflected_result = web_exposure.run("https://example.com", threads=1)
    assert reflected_result.findings == []

    def custom_404(url):
        path = urllib.parse.urlsplit(url).path
        body = f"<html><title>404 Not Found</title><p>Not Found {path}</p></html>".encode()
        return 200, body, {"Content-Type": "text/html"}

    install(monkeypatch, custom_404)
    missing = web_exposure.run("https://example.com", threads=1)
    assert missing.findings == []


def test_real_env_survives_a_reflected_404_baseline(monkeypatch):
    def router(url):
        path = urllib.parse.urlsplit(url).path
        if path == "/.env":
            return 200, ENV_BODY, {"Content-Type": "text/plain"}
        body = f"<html><title>404 Not Found</title><p>missing {path}</p></html>".encode()
        return 200, body, {"Content-Type": "text/html"}

    install(monkeypatch, router)
    result = web_exposure.run("https://example.com", threads=1)
    assert [finding.path for finding in result.findings] == ["/.env"]
    assert ENV_SECRET not in result.findings[0].reason
    assert "DB_PASSWORD" in result.findings[0].reason
    assert "API_KEY" in result.findings[0].reason


def test_weak_pages_need_a_successful_status(monkeypatch):
    form = (401, LOGIN_HTML, {"Content-Type": "text/html"})
    routes = {"/login": form, "/admin": form}
    install(monkeypatch, route_map(routes))
    denied = web_exposure.run("https://example.com", threads=1)
    assert denied.findings == []

    ok = (200, LOGIN_HTML, {"Content-Type": "text/html"})
    install(monkeypatch, route_map({"/login": ok, "/admin": ok}))
    allowed = web_exposure.run("https://example.com", threads=1)
    assert {finding.path for finding in allowed.findings} == {"/admin", "/login"}


def test_strong_signature_can_match_a_non_200_status(monkeypatch):
    install(monkeypatch, route_map({
        "/.git/HEAD": (500, b"ref: refs/heads/main\n", {"Content-Type": "text/plain"}),
    }))
    result = web_exposure.run("https://example.com", threads=1)
    assert [finding.path for finding in result.findings] == ["/.git/HEAD"]
    assert result.findings[0].status == 500


def test_body_cap_drops_bytes_past_64kib(monkeypatch, tmp_path, capsys):
    prefix = f"DB_PASSWORD={ENV_SECRET}\nAPI_KEY={ENV_SECRET_2}\n".encode()
    pad = b"A" * (web_exposure.BODY_LIMIT + 80)
    suffix = f"\nLEAKED_KEY={LEAK_SECRET}\n".encode()
    body = prefix + pad + suffix
    install(monkeypatch, route_map({
        "/.env": (200, body, {"Content-Type": "text/plain"}),
    }))
    result = web_exposure.run("https://example.com", threads=1)
    assert [finding.path for finding in result.findings] == ["/.env"]
    reason = result.findings[0].reason
    assert "DB_PASSWORD" in reason
    assert "LEAKED_KEY" not in reason
    assert "truncated" in reason
    blob, _data, _html = render(result, tmp_path, capsys)
    assert_redacted(blob)
    assert "LEAKED_KEY" not in blob


def test_timeout_and_request_errors_do_not_abort_or_leak(monkeypatch, tmp_path, capsys):
    def router(url):
        path = urllib.parse.urlsplit(url).path
        if path == "/.env":
            raise requests.Timeout(f"slow {EXC_SECRET}")
        if path == "/.svn/entries":
            raise requests.ConnectionError(f"dial {EXC_SECRET}")
        if path == "/.git/HEAD":
            return 200, b"ref: refs/heads/main\n", {"Content-Type": "text/plain"}
        return NOT_FOUND

    install(monkeypatch, router)
    result = web_exposure.run("https://example.com", threads=1)
    assert [finding.path for finding in result.findings] == ["/.git/HEAD"]
    assert any(error == "/.env: timeout" for error in result.errors)
    assert any(error == "/.svn/entries: request failed" for error in result.errors)
    blob, _data, _html = render(result, tmp_path, capsys)
    assert EXC_SECRET not in blob


def test_same_host_redirect_is_capped_and_query_is_not_stored(monkeypatch, tmp_path, capsys):
    def router(url):
        parts = urllib.parse.urlsplit(url)
        if parts.path == "/.git/HEAD":
            return 302, b"", {"Location": f"/hidden/HEAD?token={QUERY_SECRET}"}
        if parts.path == "/hidden/HEAD":
            return 200, b"ref: refs/heads/main\n", {"Content-Type": "text/plain"}
        return NOT_FOUND

    hub = install(monkeypatch, router)
    result = web_exposure.run("https://example.com", threads=1)
    assert result.findings[0].path == "/.git/HEAD"
    assert result.findings[0].url == "https://example.com/hidden/HEAD"
    assert result.findings[0].status == 200
    assert any(urllib.parse.urlsplit(url).path == "/hidden/HEAD" for url in hub.calls)
    blob, _data, _html = render(result, tmp_path, capsys)
    assert QUERY_SECRET not in blob


def test_fourth_redirect_is_not_followed(monkeypatch):
    chain = {"/.git/HEAD": "/a", "/a": "/b", "/b": "/c", "/c": "/d"}

    def router(url):
        path = urllib.parse.urlsplit(url).path
        if path in chain:
            return 302, b"", {"Location": chain[path]}
        if path == "/d":
            return 200, b"ref: refs/heads/main\n", {"Content-Type": "text/plain"}
        return NOT_FOUND

    hub = install(monkeypatch, router)
    result = web_exposure.run("https://example.com", threads=1)
    assert result.findings == []
    assert "/d" not in call_paths(hub)
    assert "/c" in call_paths(hub)
    assert any("redirect limit" in error for error in result.errors)


def test_three_same_host_redirects_reach_the_body(monkeypatch):
    chain = {"/.git/HEAD": "/a", "/a": "/b", "/b": "/c"}

    def router(url):
        path = urllib.parse.urlsplit(url).path
        if path in chain:
            return 302, b"", {"Location": chain[path]}
        if path == "/c":
            return 200, b"ref: refs/heads/main\n", {"Content-Type": "text/plain"}
        return NOT_FOUND

    hub = install(monkeypatch, router)
    result = web_exposure.run("https://example.com", threads=1)
    assert [finding.path for finding in result.findings] == ["/.git/HEAD"]
    assert result.findings[0].url == "https://example.com/c"
    assert "/c" in call_paths(hub)


@pytest.mark.parametrize(
    "location",
    [
        "https://evil.example/steal?x=REDIRSECRET_9f3a",
        "https://example.com.evil.com/.git/HEAD",
        "https://user:REDIRSECRET_9f3a@example.com/.git/HEAD",
        "ftp://example.com/file",
        "javascript:alert(1)",
        "//evil.example/steal",
    ],
)
def test_off_host_and_unsafe_redirects_are_refused(monkeypatch, location, tmp_path, capsys):
    def router(url):
        path = urllib.parse.urlsplit(url).path
        if path == "/.git/HEAD":
            return 302, b"ref: refs/heads/main\n", {"Location": location}
        if "evil" in urllib.parse.urlsplit(url).netloc or REDIR_SECRET in url:
            raise AssertionError(f"followed unsafe redirect to {url}")
        return NOT_FOUND

    hub = install(monkeypatch, router)
    result = web_exposure.run("https://example.com", threads=1)
    assert result.findings == []
    assert not any("evil.example" in url for url in hub.calls)
    assert not any(REDIR_SECRET in url for url in hub.calls)
    assert any("refused" in error for error in result.errors)
    blob, _data, _html = render(result, tmp_path, capsys)
    assert "evil.example" not in blob
    assert REDIR_SECRET not in blob


def test_request_budget_stops_further_gets(monkeypatch):
    hub = install(monkeypatch, route_map({}))
    result = web_exposure.run("https://example.com", threads=1, budget=3)
    assert len(hub.calls) == 3
    paths = call_paths(hub)
    assert paths[0].startswith("/.netrecon-baseline-")
    assert paths[1] == "/"
    assert paths[2] == "/.git/HEAD"
    assert result.findings == []
    assert any("budget" in error for error in result.errors)


def test_target_url_is_reduced_to_the_origin(monkeypatch):
    hub = install(monkeypatch, route_map({}))
    result = web_exposure.run("http://example.com/app/admin?q=1", threads=1, budget=3)
    assert result.base_url == "http://example.com"
    assert all(urllib.parse.urlsplit(url).netloc == "example.com" for url in hub.calls)
    assert all("/app/" not in url for url in hub.calls)


def test_ipv4_target_with_port_is_preserved(monkeypatch):
    hub = install(monkeypatch, route_map({}))
    result = web_exposure.run("http://127.0.0.1:8080", threads=1, budget=2)
    assert result.base_url == "http://127.0.0.1:8080"
    assert hub.calls
    assert all(url.startswith("http://127.0.0.1:8080/") for url in hub.calls)


@pytest.mark.parametrize(
    "target",
    [
        "",
        "ftp://example.com",
        "file:///etc/passwd",
        "gopher://example.com",
        "javascript:alert(1)",
        "http://user:pass@example.com",
        "https://user:pass@example.com/.env",
        "http://",
        "//example.com",
        "https://example.com/foo bar",
        "http://exa mple.com",
        "https://example.com\\@evil.com",
        "https://example.com:99999",
    ],
)
def test_invalid_targets_do_not_touch_the_network(monkeypatch, target):
    def boom():
        raise AssertionError("network used")

    monkeypatch.setattr(web_exposure.requests, "Session", boom)
    with pytest.raises(ValueError):
        web_exposure.run(target)


def test_non_positive_options_are_rejected_before_requests(monkeypatch):
    def boom():
        raise AssertionError("network used")

    monkeypatch.setattr(web_exposure.requests, "Session", boom)
    with pytest.raises(ValueError):
        web_exposure.run("example.com", timeout=0)
    with pytest.raises(ValueError):
        web_exposure.run("example.com", threads=0)
    with pytest.raises(ValueError):
        web_exposure.run("example.com", budget=0)


# ── Reports and CLI ───────────────────────────────────────────────────

def test_summary_lists_high_paths_and_technologies(capsys):
    report = ReconReport(
        target="example.com",
        web_exposure=WebExposureResult(
            base_url="https://example.com",
            findings=[
                WebFinding("/.env", "https://example.com/.env", 200, "high", "keys redacted"),
                WebFinding("/login", "https://example.com/login", 200, "low", "Login form exposed"),
            ],
            technologies=[WebTechnology("nginx", "Server: nginx")],
            leads=[WebLead("/robots.txt", "/secret-admin")],
        ),
    )
    report.summary()
    out = capsys.readouterr().out
    assert "2 finding(s), 1 high" in out
    assert "/.env" in out
    assert "nginx" in out
    assert "not requested" in out


def test_json_keeps_old_keys_and_html_escapes_web_fields(tmp_path):
    payload = '<script>alert(1)</script>'
    evidence = '<svg onload=alert(1)>'
    report = ReconReport(
        target="ex<ample>.com",
        ports=[
            PortEntry(
                port=22, state="open", service="ssh", banner=payload,
                product="OpenSSH", version="9.9", findings=["clear"],
            )
        ],
        web_exposure=WebExposureResult(
            base_url="https://ex<ample>.com",
            findings=[
                WebFinding(
                    "/<admin>",
                    "https://example.com/?q=<img src=x onerror=alert(1)>",
                    200,
                    "high",
                    payload,
                )
            ],
            technologies=[WebTechnology("WordPress", evidence)],
            leads=[WebLead("/robots.txt", "/<disallow>")],
            errors=["timed out <b>x</b>"],
        ),
    )
    json_path = tmp_path / "report.json"
    html_path = tmp_path / "report.html"
    json_report.save(report, str(json_path))
    html_report.save(report, str(html_path))
    data = json.loads(json_path.read_text())
    assert set(data) >= {
        "target", "scanned_at", "dns", "ssl", "headers", "whois",
        "subdomains", "ports", "errors", "web_exposure",
    }
    opened = data["ports"][0]
    assert opened["port"] == 22
    assert opened["state"] == "open"
    assert opened["service"] == "ssh"
    assert opened["banner"] == payload
    assert opened["product"] == "OpenSSH"
    assert opened["version"] == "9.9"
    assert opened["findings"] == ["clear"]
    finding = data["web_exposure"]["findings"][0]
    assert set(finding) == {"path", "url", "status", "severity", "reason"}
    assert finding["reason"] == payload
    assert data["web_exposure"]["technologies"][0]["evidence"] == evidence
    assert data["web_exposure"]["leads"][0]["path"] == "/<disallow>"

    text = html_path.read_text()
    assert "<script>" not in text
    assert "<img" not in text
    assert "<svg" not in text
    assert "<admin>" not in text
    assert "<disallow>" not in text
    assert "ex<ample>" not in text
    assert "<b>" not in text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text
    assert "&lt;svg onload=alert(1)&gt;" in text
    assert "&lt;img src=x onerror=alert(1)&gt;" in text
    assert "banner-keep" not in text
    assert payload not in text or "&lt;script&gt;" in text

    empty = ReconReport(target="example.com")
    empty_path = tmp_path / "empty.json"
    empty_html = tmp_path / "empty.html"
    json_report.save(empty, str(empty_path))
    html_report.save(empty, str(empty_html))
    assert json.loads(empty_path.read_text())["web_exposure"] is None
    assert "Web exposure" not in empty_html.read_text()


def test_generator_payload_is_escaped_in_html(monkeypatch, tmp_path):
    nasty = '<script>alert(1)</script> WordPress 6.4'
    home = (
        200,
        f'<!doctype html><html><meta name="generator" content="{nasty}"></html>'.encode(),
        {"Content-Type": "text/html", "Server": "nginx\x1b[31m"},
    )
    install(monkeypatch, route_map({}, home=home))
    result = web_exposure.run("https://example.com", threads=1, budget=2)
    evidence = " ".join(tech.evidence for tech in result.technologies)
    assert "\x1b" not in evidence
    assert "WordPress" in {tech.name for tech in result.technologies}
    html_path = tmp_path / "report.html"
    html_report.save(ReconReport(target="example.com", web_exposure=result), str(html_path))
    text = html_path.read_text()
    assert "<script>" not in text
    assert "&lt;script&gt;" in text


def _stub_scan_modules(monkeypatch, calls):
    from netrecon import cli

    monkeypatch.setattr(cli.dns_enum, "run", lambda *a, **k: calls.append("dns") or DnsResult())
    monkeypatch.setattr(cli.ssl_check, "run", lambda *a, **k: calls.append("ssl") or SslResult())
    monkeypatch.setattr(cli.headers, "run", lambda *a, **k: calls.append("headers") or HeaderResult())
    monkeypatch.setattr(cli.whois_lookup, "run", lambda *a, **k: calls.append("whois") or WhoisResult())
    monkeypatch.setattr(cli.subdomains, "run", lambda *a, **k: calls.append("subdomains") or {})
    monkeypatch.setattr(cli.port_scan, "run", lambda *a, **k: calls.append("ports") or [])
    monkeypatch.setattr(cli.web_exposure, "run", lambda *a, **k: calls.append("web") or WebExposureResult())


def test_scan_opt_out_and_web_selection(monkeypatch):
    calls = []
    _stub_scan_modules(monkeypatch, calls)
    parser = build_parser()

    def run(argv):
        calls.clear()
        args = parser.parse_args(argv)
        args.func(args)
        return list(calls)

    assert "web" not in run(["scan", "example.com", "--all", "--no-web-exposure"])
    assert "dns" in calls and "ports" in calls

    assert "web" not in run(["scan", "example.com", "--no-web-exposure"])
    assert "dns" in calls

    assert "web" in run(["scan", "example.com"])
    assert "web" in run(["scan", "example.com", "--all"])
    assert run(["scan", "example.com", "--dns"]) == ["dns"]
    assert run(["scan", "example.com", "--web-exposure"]) == ["web"]
    assert run(["scan", "example.com", "--web-exposure", "--no-web-exposure"]) == ["web"]
    assert run(["scan", "example.com", "--ports", "--no-banners"]) == ["ports"]


def test_web_subcommand_passes_timeout_and_threads(monkeypatch):
    from netrecon import cli

    captured = {}

    def fake_run(target, timeout=5, threads=4, budget=48):
        captured["target"] = target
        captured["timeout"] = timeout
        captured["threads"] = threads
        return WebExposureResult(base_url="https://example.com")

    monkeypatch.setattr(cli.web_exposure, "run", fake_run)
    monkeypatch.setattr(cli.web_exposure, "display", lambda result: None)
    args = build_parser().parse_args(["web", "example.com", "--timeout", "2.5", "--threads", "3"])
    args.func(args)
    assert captured == {"target": "example.com", "timeout": 2.5, "threads": 3}
