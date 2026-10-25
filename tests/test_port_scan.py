"""Port fingerprinting: banners, version heuristics, and report output.

Sockets are mocked. Nothing in this module dials the network.
"""
import errno
import json
import socket
import struct

import pytest

from netrecon.cli import build_parser
from netrecon.models import PortEntry, ReconReport
from netrecon.modules import port_scan
from netrecon.report import html_report, json_report


class ScriptedSocket:
    """Minimal socket double. A zero timeout means 'nothing buffered yet'."""

    def __init__(self, chunks, connect_code=0):
        self._chunks = list(chunks)
        self.connect_code = connect_code
        self.sent = []
        self.recv_calls = 0
        self.timeouts = []
        self._timeout = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def close(self):
        return None

    def settimeout(self, value):
        self._timeout = value
        self.timeouts.append(value)

    def gettimeout(self):
        return self._timeout

    def connect_ex(self, addr):
        return self.connect_code

    def sendall(self, data):
        self.sent.append(bytes(data))

    def recv(self, n):
        self.recv_calls += 1
        if self._timeout == 0:
            raise BlockingIOError(errno.EAGAIN, "would block")
        if not self._chunks:
            raise socket.timeout("timed out")
        item = self._chunks.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item[:n]


def install_socket(monkeypatch, chunks, connect_code=0):
    holder = {}

    def factory(family, sock_type):
        sock = ScriptedSocket(chunks, connect_code=connect_code)
        holder["sock"] = sock
        return sock

    monkeypatch.setattr(
        port_scan, "_resolve", lambda target: (socket.AF_INET, "203.0.113.10")
    )
    monkeypatch.setattr(port_scan.socket, "socket", factory)
    return holder


def scan(monkeypatch, chunks, port, connect_code=0, target="example.com", **kwargs):
    holder = install_socket(monkeypatch, chunks, connect_code=connect_code)
    results = port_scan.run(
        target,
        ports=kwargs.pop("ports", [port]),
        threads=1,
        timeout=kwargs.pop("timeout", 0.25),
        quiet=True,
        **kwargs,
    )
    return results, holder["sock"]


def mysql_greeting(version: str) -> bytes:
    payload = b"\x0a" + version.encode("ascii") + b"\x00" + b"\x00" * 4
    return struct.pack("<I", len(payload))[:3] + b"\x00" + payload


def mongo_version_blob(version: str) -> bytes:
    raw = version.encode("ascii")
    element = b"\x02version\x00" + struct.pack("<i", len(raw) + 1) + raw + b"\x00"
    element += b"\x10maxWireVersion\x00" + struct.pack("<i", 8)
    return element


def _heuristic(findings):
    return [note for note in findings if "heuristic" in note.lower()]


# ── Parsing ───────────────────────────────────────────────────────────

def test_parse_openssh_old_and_current():
    old = port_scan._fingerprint(b"SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8\r\n", 22)
    assert old.service == "ssh"
    assert old.product == "OpenSSH"
    assert old.version == "7.2p2"
    assert "OpenSSH_7.2p2" in old.banner
    assert any("7.2p2" in note and "not a CVE database" in note for note in old.findings)

    current = port_scan._fingerprint(b"SSH-2.0-OpenSSH_9.8p1\r\n", 22)
    assert current.version == "9.8p1"
    assert current.findings == []


def test_parse_dropbear_and_ssh1():
    old = port_scan._fingerprint(b"SSH-2.0-dropbear_2019.78\r\n", 22)
    assert old.product == "Dropbear"
    assert old.version == "2019.78"
    assert _heuristic(old.findings)

    current = port_scan._fingerprint(b"SSH-2.0-dropbear_2022.83\r\n", 22)
    assert current.findings == []

    legacy = port_scan._fingerprint(b"SSH-1.5-OpenSSH_1.2.3\r\n", 22)
    assert any("protocol 1" in note for note in legacy.findings)
    assert any("heuristic" in note for note in legacy.findings)


def test_parse_http_servers():
    nginx = port_scan._fingerprint(
        b"HTTP/1.1 200 OK\r\nServer: nginx/1.27.2\r\nContent-Length: 0\r\n\r\n",
        80,
    )
    assert nginx.service == "http"
    assert nginx.product == "nginx"
    assert nginx.version == "1.27.2"
    assert nginx.findings == []
    assert "Server: nginx/1.27.2" in nginx.banner

    old_nginx = port_scan._fingerprint(
        b"HTTP/1.0 200 OK\r\nServer: nginx/1.14.0\r\n\r\n", 8080,
    )
    assert old_nginx.service == "http"
    assert any("1.14.0" in note and "heuristic" in note for note in old_nginx.findings)

    apache = port_scan._fingerprint(
        b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)\r\n\r\n", 80,
    )
    assert apache.product == "Apache httpd"
    assert apache.version == "2.4.49"
    assert any("2.4.49" in note and "not a CVE database" in note for note in apache.findings)

    current_apache = port_scan._fingerprint(
        b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.62\r\n\r\n", 80,
    )
    assert current_apache.findings == []

    iis = port_scan._fingerprint(
        b"HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/8.5\r\n\r\n", 80,
    )
    assert iis.product == "Microsoft-IIS"
    assert iis.version == "8.5"
    assert _heuristic(iis.findings)


def test_parse_php_component_without_flagging_current_apache():
    ident = port_scan._fingerprint(
        b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.58\r\nX-Powered-By: PHP/7.4.3\r\n\r\n",
        80,
    )
    assert ident.version == "2.4.58"
    assert any("PHP" in note and "heuristic" in note for note in ident.findings)
    assert not any("Apache httpd before" in note for note in ident.findings)


def test_parse_tls_version_prefix():
    obsolete = port_scan._fingerprint(
        b"TLS:TLSv1.0\nHTTP/1.1 200 OK\r\nServer: nginx/1.25.0\r\n\r\n",
        443,
    )
    assert obsolete.service == "https"
    assert obsolete.version == "1.25.0"
    assert any("TLSv1.0" in note and "heuristic" in note for note in obsolete.findings)
    assert not any("nginx before" in note for note in obsolete.findings)

    modern = port_scan._fingerprint(
        b"TLS:TLSv1.2\nHTTP/1.1 200 OK\r\nServer: nginx/1.25.0\r\n\r\n",
        443,
    )
    assert modern.findings == []
    assert "TLS:TLSv1.2" in modern.banner


def test_parse_mail_ftp_and_telnet():
    exim = port_scan._fingerprint(b"220 mail.example.com ESMTP Exim 4.92\r\n", 25)
    assert exim.service == "smtp"
    assert exim.product == "Exim"
    assert exim.version == "4.92"
    assert _heuristic(exim.findings)

    postfix = port_scan._fingerprint(b"220 mail.example.com ESMTP Postfix\r\n", 25)
    assert postfix.product == "Postfix"
    assert postfix.version == ""
    assert postfix.findings == []

    vsftpd = port_scan._fingerprint(b"220 (vsFTPd 2.3.4)\r\n", 21)
    assert vsftpd.product == "vsftpd"
    assert vsftpd.version == "2.3.4"
    assert any("backdoor" in note for note in vsftpd.findings)
    assert any("not a CVE database" in note for note in vsftpd.findings)

    telnet = port_scan._fingerprint(b"\xff\xfd\x18\xff\xfd\x20login: \r\n", 23)
    assert telnet.service == "telnet"
    assert "login:" in telnet.banner
    assert "\xff" not in telnet.banner
    assert any("Telnet" in note for note in telnet.findings)


def test_parse_redis_elasticsearch_memcached_docker():
    redis = port_scan._fingerprint(
        b"$80\r\n# Server\r\nredis_version:5.0.7\r\nos:Linux\r\n", 6379,
    )
    assert redis.service == "redis"
    assert redis.version == "5.0.7"
    assert any("without authentication" in note for note in redis.findings)
    assert _heuristic(redis.findings)
    assert not any(note.startswith("Exposed Redis") for note in redis.findings)

    noauth = port_scan._fingerprint(b"-NOAUTH Authentication required.\r\n", 6379)
    assert noauth.version == ""
    assert any("AUTH is enabled" in note for note in noauth.findings)

    current_redis = port_scan._fingerprint(b"redis_version:7.2.4\r\n", 6379)
    assert not _heuristic(current_redis.findings)
    assert any("without authentication" in note for note in current_redis.findings)

    elastic = port_scan._fingerprint(
        b'HTTP/1.1 200 OK\r\n\r\n{"tagline":"You Know, for Search",'
        b'"version":{"number":"7.10.2"}}\r\n',
        9200,
    )
    assert elastic.service == "elasticsearch"
    assert elastic.product == "Elasticsearch"
    assert elastic.version == "7.10.2"
    assert any("without authentication" in note for note in elastic.findings)
    assert _heuristic(elastic.findings)

    current_elastic = port_scan._fingerprint(
        b'HTTP/1.1 200 OK\r\n\r\n{"tagline":"You Know, for Search",'
        b'"version":{"number":"8.11.3"}}\r\n',
        9200,
    )
    assert current_elastic.version == "8.11.3"
    assert not _heuristic(current_elastic.findings)

    cached = port_scan._fingerprint(b"VERSION 1.4.15\r\n", 11211)
    assert cached.product == "Memcached"
    assert cached.version == "1.4.15"
    assert any("without authentication" in note for note in cached.findings)

    docker = port_scan._fingerprint(
        b'HTTP/1.1 200 OK\r\n\r\n{"Version":"19.03.8","ApiVersion":"1.40"}\r\n',
        2375,
    )
    assert docker.service == "docker"
    assert docker.version == "19.03.8"
    assert any("without authentication" in note for note in docker.findings)
    assert _heuristic(docker.findings)

    current_docker = port_scan._fingerprint(
        b'HTTP/1.1 200 OK\r\n\r\n{"Version":"24.0.7","ApiVersion":"1.43"}\r\n',
        2375,
    )
    assert current_docker.version == "24.0.7"
    assert not _heuristic(current_docker.findings)


def test_parse_mysql_and_mariadb():
    mysql = port_scan._fingerprint(mysql_greeting("5.7.33"), 3306)
    assert mysql.product == "MySQL"
    assert mysql.version == "5.7.33"
    assert mysql.service == "mysql"
    assert _heuristic(mysql.findings)

    current = port_scan._fingerprint(mysql_greeting("8.0.36"), 3306)
    assert current.version == "8.0.36"
    assert not _heuristic(current.findings)
    assert any("Exposed MySQL" in note for note in current.findings)

    maria = port_scan._fingerprint(mysql_greeting("5.5.5-10.3.22-MariaDB"), 3306)
    assert maria.product == "MariaDB"
    assert maria.version == "10.3.22"
    assert maria.service == "mariadb"
    assert any("MariaDB" in note and "heuristic" in note for note in maria.findings)


def test_parse_mongodb_blob():
    ident = port_scan._fingerprint(mongo_version_blob("4.2.11"), 27017)
    assert ident.service == "mongodb"
    assert ident.product == "MongoDB"
    assert ident.version == "4.2.11"
    assert any("without authentication" in note for note in ident.findings)
    assert _heuristic(ident.findings)


def test_version_comparison_boundaries():
    assert port_scan._version_is_below("7.2p1", (8, 2))
    assert not port_scan._version_is_below("8.2p1", (8, 2))
    assert port_scan._version_is_below("8.1.9", (8, 2))
    assert not port_scan._version_is_below("1.22.0", (1, 22, 0))
    assert port_scan._version_is_below("1.21.6", (1, 22, 0))
    assert not port_scan._version_is_below("", (1, 0))
    assert port_scan._version_tuple("10.3.22-MariaDB")[:3] == (10, 3, 22)


def test_control_chars_and_oversized_banner_are_capped():
    raw = (
        b"\x00\x07\x1b[31mSSH-2.0-OpenSSH_9.1p1\x1b[0m\r\n"
        + "\u202e".encode()
        + b"A" * 20000
    )
    ident = port_scan._fingerprint(raw, 22)
    assert ident.product == "OpenSSH"
    assert ident.version == "9.1p1"
    assert "\x1b" not in ident.banner
    assert "\u202e" not in ident.banner
    assert "[31m" not in ident.banner
    assert len(ident.banner) <= port_scan.BANNER_MAX_LEN
    assert all(ch.isprintable() for ch in ident.banner)

    noise = port_scan._fingerprint(b"\x00\x01" + b"G" * 10000, 65535)
    assert noise.product == ""
    assert len(noise.banner) <= port_scan.BANNER_MAX_LEN
    assert all(ch.isprintable() for ch in noise.banner)
    assert "\x00" not in noise.banner


def test_http_host_header_rejects_injection():
    payload = port_scan._http_bytes("evil.com\r\nX-Evil: 1", "HEAD", "/")
    assert b"X-Evil" not in payload
    assert b"Host: localhost\r\n" in payload
    assert payload.startswith(b"HEAD / HTTP/1.0\r\n")


def test_mongo_probe_is_a_single_ismaster_message():
    probe = port_scan._mongo_hello()
    assert struct.unpack_from("<i", probe, 0)[0] == len(probe)
    assert struct.unpack_from("<i", probe, 12)[0] == 2013
    assert b"isMaster" in probe
    assert b"admin" in probe


# ── Scanner I/O ───────────────────────────────────────────────────────

def test_open_ssh_is_passive_and_http_is_probed(monkeypatch):
    results, sock = scan(monkeypatch, [b"SSH-2.0-OpenSSH_7.2p2\r\n"], 22)
    assert results[0].state == "open"
    assert results[0].product == "OpenSSH"
    assert sock.sent == []
    assert all(value is not None and value <= 0.25 for value in sock.timeouts)

    results, sock = scan(
        monkeypatch,
        [b"HTTP/1.1 200 OK\r\nServer: nginx/1.14.0\r\n\r\n"],
        80,
    )
    sent = b"".join(sock.sent)
    assert b"HEAD / HTTP/1.0\r\n" in sent
    assert b"Host: example.com\r\n" in sent
    assert results[0].version == "1.14.0"
    assert _heuristic(results[0].findings)


def test_banner_timeout_keeps_port_open(monkeypatch):
    results, sock = scan(monkeypatch, [], 80)
    assert results[0].state == "open"
    assert results[0].banner == ""
    assert results[0].version == ""
    assert any(b"HEAD / HTTP/1.0" in chunk for chunk in sock.sent)

    results, sock = scan(monkeypatch, [], 22)
    assert results[0].state == "open"
    assert results[0].service == "ssh"
    assert results[0].banner == ""
    assert sock.sent == []

    results, _sock = scan(monkeypatch, [socket.timeout("timed out")], 25)
    assert results[0].state == "open"
    assert results[0].banner == ""


def test_refused_and_filtered_skip_banners(monkeypatch):
    results, sock = scan(
        monkeypatch, [b"SSH-2.0-OpenSSH_9.9\r\n"], 22,
        connect_code=errno.ECONNREFUSED,
    )
    assert results[0].state == "closed"
    assert results[0].banner == ""
    assert sock.recv_calls == 0

    results, sock = scan(
        monkeypatch, [b"SSH-2.0-OpenSSH_9.9\r\n"], 22,
        connect_code=errno.ETIMEDOUT,
    )
    assert results[0].state == "filtered"
    assert sock.recv_calls == 0


def test_no_banners_skips_io_but_keeps_port_exposure(monkeypatch):
    results, sock = scan(
        monkeypatch, [b"SSH-2.0-OpenSSH_7.2p2\r\n"], 22, grab_banners=False,
    )
    assert results[0].banner == ""
    assert results[0].product == ""
    assert results[0].version == ""
    assert results[0].findings == []
    assert results[0].service == "ssh"
    assert sock.recv_calls == 0
    assert sock.sent == []

    results, sock = scan(
        monkeypatch, [b"redis_version:5.0.7\r\n"], 6379, grab_banners=False,
    )
    assert sock.recv_calls == 0
    assert results[0].version == ""
    assert any("Redis" in note for note in results[0].findings)


def test_service_probes_and_anonymous_ftp(monkeypatch):
    results, sock = scan(
        monkeypatch,
        [b"$40\r\nredis_version:5.0.7\r\n"],
        6379,
    )
    assert b"INFO\r\n" in b"".join(sock.sent)
    assert results[0].version == "5.0.7"

    results, sock = scan(monkeypatch, [b"VERSION 1.6.9\r\n"], 11211)
    assert b"version\r\n" in b"".join(sock.sent)
    assert results[0].version == "1.6.9"

    body = (
        b"HTTP/1.1 200 OK\r\n\r\n"
        b'{"tagline":"You Know, for Search","version":{"number":"7.10.2"}}\r\n'
    )
    results, sock = scan(monkeypatch, [body], 9200)
    assert b"GET / HTTP/1.0\r\n" in b"".join(sock.sent)
    assert results[0].version == "7.10.2"

    docker = (
        b"HTTP/1.1 200 OK\r\n\r\n"
        b'{"Version":"19.03.8","ApiVersion":"1.40"}\r\n'
    )
    results, sock = scan(monkeypatch, [docker], 2375)
    assert b"GET /version HTTP/1.0\r\n" in b"".join(sock.sent)
    assert results[0].product == "Docker"

    results, sock = scan(monkeypatch, [mongo_version_blob("4.2.11")], 27017)
    sent = b"".join(sock.sent)
    assert b"isMaster" in sent
    assert results[0].version == "4.2.11"

    results, sock = scan(monkeypatch, [mysql_greeting("5.7.31")], 3306)
    assert sock.sent == []
    assert results[0].product == "MySQL"
    assert results[0].version == "5.7.31"

    results, sock = scan(
        monkeypatch,
        [
            b"220 (vsFTPd 2.3.4)\r\n",
            b"331 Please specify the password.\r\n",
            b"230 Login successful.\r\n",
        ],
        21,
    )
    sent = b"".join(sock.sent)
    assert b"USER anonymous\r\n" in sent
    assert b"PASS anonymous@\r\n" in sent
    assert b"QUIT\r\n" in sent
    assert results[0].version == "2.3.4"
    assert any("Anonymous FTP login accepted" == note for note in results[0].findings)
    assert any("backdoor" in note for note in results[0].findings)

    results, sock = scan(
        monkeypatch,
        [b"220 ProFTPD 1.3.5 Server ready.\r\n", b"530 Not logged in.\r\n"],
        21,
    )
    sent = b"".join(sock.sent)
    assert b"USER anonymous\r\n" in sent
    assert b"PASS anonymous@" not in sent
    assert not any("Anonymous FTP" in note for note in results[0].findings)
    assert results[0].product == "ProFTPD"

    results, sock = scan(
        monkeypatch, [b"220 mail.example.com ESMTP Exim 4.92\r\n"], 25,
    )
    assert all(b"USER anonymous" not in chunk for chunk in sock.sent)
    assert results[0].product == "Exim"


def test_tls_probe_records_protocol_and_server(monkeypatch):
    seen = {}

    class FakeTLS:
        def __init__(self, sock, server_hostname=None):
            self._sock = sock
            self.server_hostname = server_hostname
            seen["sni"] = server_hostname

        def settimeout(self, value):
            self._sock.settimeout(value)

        def gettimeout(self):
            return self._sock.gettimeout()

        def version(self):
            return "TLSv1.0"

        def sendall(self, data):
            self._sock.sendall(data)

        def recv(self, n):
            return self._sock.recv(n)

        def close(self):
            return None

    class FakeContext:
        def __init__(self, *args, **kwargs):
            self.check_hostname = True
            self.verify_mode = None
            self.minimum_version = None

        def set_ciphers(self, spec):
            seen["ciphers"] = spec

        def wrap_socket(self, sock, server_hostname=None):
            return FakeTLS(sock, server_hostname)

    monkeypatch.setattr(port_scan.ssl, "SSLContext", FakeContext)
    results, sock = scan(
        monkeypatch,
        [b"HTTP/1.1 200 OK\r\nServer: nginx/1.14.0\r\n\r\n"],
        443,
    )
    assert seen["sni"] == "example.com"
    assert b"HEAD / HTTP/1.0\r\n" in b"".join(sock.sent)
    assert results[0].service == "https"
    assert results[0].version == "1.14.0"
    assert "TLS:TLSv1.0" in results[0].banner
    assert any("TLSv1.0" in note for note in results[0].findings)
    assert any("nginx" in note for note in results[0].findings)


def test_oversized_socket_banner_is_truncated(monkeypatch):
    blob = b"SSH-2.0-OpenSSH_8.9p1 " + (b"B" * 20000) + b"\r\n"
    results, _sock = scan(monkeypatch, [blob], 22)
    assert results[0].product == "OpenSSH"
    assert results[0].version.startswith("8.9")
    assert len(results[0].banner) <= port_scan.BANNER_MAX_LEN
    assert all(ch.isprintable() for ch in results[0].banner)


def test_garbage_socket_banner_cannot_inject_controls(monkeypatch):
    raw = b"\x00\x1b[31mhello\x1b[0m\r\n" + "\u202e".encode() + b"\x07" * 20
    results, _sock = scan(monkeypatch, [raw], 9)
    banner = results[0].banner
    assert results[0].state == "open"
    assert "hello" in banner
    assert "\x1b" not in banner
    assert "\u202e" not in banner
    assert "[31m" not in banner
    assert all(ch.isprintable() for ch in banner)


def test_injected_host_is_not_sent(monkeypatch):
    _results, sock = scan(
        monkeypatch,
        [b"HTTP/1.0 200 OK\r\n\r\n"],
        80,
        target="evil.com\r\nX-Evil: 1",
    )
    sent = b"".join(sock.sent)
    assert b"X-Evil" not in sent
    assert b"\r\nHost: localhost\r\n" in sent


# ── CLI, console, reports ─────────────────────────────────────────────

def test_top_ports_selection():
    assert port_scan.TOP_PORTS[:20] == port_scan.PROFILES["top20"]
    first = port_scan._select_ports(None, None, None, None, top_ports=40)
    assert first == port_scan.TOP_PORTS[:40]
    assert 6379 in first and 27017 in first and 2375 in first
    assert 11211 in port_scan.PROFILES["db"]
    assert 9042 in port_scan.PROFILES["db"]
    assert len(port_scan.TOP_PORTS) > 100

    with pytest.raises(ValueError):
        port_scan._select_ports(None, None, None, None, top_ports=0)
    with pytest.raises(ValueError):
        port_scan._select_ports(
            None, None, None, None, top_ports=len(port_scan.TOP_PORTS) + 1,
        )
    # An explicit profile still wins over top_ports.
    assert port_scan._select_ports("web", None, None, None, top_ports=10) == (
        port_scan.PROFILES["web"]
    )


def test_cli_no_banners_and_top_ports(monkeypatch):
    captured = {}

    def fake_run(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return []

    monkeypatch.setattr(port_scan, "run", fake_run)
    monkeypatch.setattr(port_scan, "display", lambda results: None)
    parser = build_parser()

    args = parser.parse_args(
        ["ports", "example.com", "--top-ports", "25", "--no-banners", "--timeout", "0.2"]
    )
    args.func(args)
    assert captured["kwargs"]["grab_banners"] is False
    assert captured["kwargs"]["top_ports"] == 25
    assert captured["kwargs"]["profile"] is None

    args = parser.parse_args(["ports", "example.com", "--ports", "22", "80"])
    args.func(args)
    assert captured["kwargs"]["grab_banners"] is True
    assert captured["kwargs"]["ports"] == [22, 80]

    with pytest.raises(SystemExit):
        parser.parse_args(
            ["ports", "example.com", "--top-ports", "10", "--profile", "web"]
        )


def test_scan_command_passes_opt_out(monkeypatch):
    captured = {}

    def fake_run(*args, **kwargs):
        captured["kwargs"] = kwargs
        return []

    monkeypatch.setattr(port_scan, "run", fake_run)
    parser = build_parser()
    args = parser.parse_args(
        ["scan", "example.com", "--ports", "--no-banners", "--top-ports", "15"]
    )
    args.func(args)
    assert captured["kwargs"]["grab_banners"] is False
    assert captured["kwargs"]["top_ports"] == 15
    assert captured["kwargs"]["profile"] is None


def test_display_and_summary_include_new_fields(capsys):
    port_scan.display([
        PortEntry(
            port=22, state="open", service="ssh", product="OpenSSH",
            version="7.2p2", banner="SSH-2.0-OpenSSH_7.2p2",
            findings=[
                "OpenSSH before 8.2 is outdated; found 7.2p2 "
                "(heuristic, not a CVE database)"
            ],
        )
    ])
    out = capsys.readouterr().out
    assert "VERSION" in out
    assert "OpenSSH/7.2p2" in out
    assert "not a CVE database" in out

    report = ReconReport(
        target="example.com",
        ports=[
            PortEntry(
                port=22, state="open", service="ssh", product="OpenSSH",
                version="7.2p2", findings=["old"],
            ),
            PortEntry(port=81, state="closed"),
        ],
    )
    report.summary()
    summary = capsys.readouterr().out
    assert "22 OpenSSH/7.2p2" in summary
    assert "Port flags : 1 with findings" in summary


def test_html_escapes_banner_product_version_and_findings(tmp_path):
    banner = '<script>alert("x")</script>'
    finding = '<img src=x onerror=alert(1)>'
    report = ReconReport(
        target="ex<ample>.com",
        ports=[
            PortEntry(
                port=80, state="open", service="http<svc>",
                banner=banner, product="<nginx>",
                version='1.0"><svg/onload=alert(1)>',
                findings=[finding],
            )
        ],
    )
    path = tmp_path / "report.html"
    html_report.save(report, str(path))
    text = path.read_text()
    assert "<script>" not in text
    assert "<img" not in text
    assert "<nginx>" not in text
    assert "<svg" not in text
    assert "<svc>" not in text
    assert "ex<ample>" not in text
    assert 'alert("x")' not in text
    assert "&lt;script&gt;" in text
    assert "&lt;img src=x onerror=alert(1)&gt;" in text
    assert "&lt;nginx&gt;" in text
    assert "not a CVE database" in text


def test_json_report_keeps_old_keys_and_adds_fingerprint(tmp_path):
    banner = '<script>alert(1)</script>'
    report = ReconReport(
        target="example.com",
        ports=[
            PortEntry(
                port=22, state="open", service="ssh", banner=banner,
                product="OpenSSH", version="9.9", findings=["clear"],
            ),
            PortEntry(port=23, state="closed"),
        ],
    )
    path = tmp_path / "report.json"
    json_report.save(report, str(path))
    data = json.loads(path.read_text())
    opened = data["ports"][0]
    assert opened["port"] == 22
    assert opened["state"] == "open"
    assert opened["service"] == "ssh"
    assert opened["banner"] == banner
    assert opened["product"] == "OpenSSH"
    assert opened["version"] == "9.9"
    assert opened["findings"] == ["clear"]
    closed = data["ports"][1]
    assert closed["service"] == ""
    assert closed["product"] == ""
    assert closed["version"] == ""
    assert closed["findings"] == []
