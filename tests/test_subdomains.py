"""Tests for subdomain discovery, crt.sh fetching, and report output."""
import io
import json
import tempfile
import threading
import unittest
from argparse import Namespace
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import MagicMock, patch

import requests

from netrecon.cli import cmd_scan
from netrecon.models import ReconReport, SubdomainEntry, SubdomainResult
from netrecon.modules import subdomains
from netrecon.report import html_report, json_report


SINK = ["203.0.113.9"]


class TestValidation(unittest.TestCase):
    def test_rejects_bad_targets_without_network(self):
        bad_targets = [
            "",
            "example",
            "http://example.com",
            "example.com/x",
            "example.com:443",
            "-bad.com",
            "bad-.com",
            "ex ample.com",
            "127.0.0.1",
            "example.com/../169.254.169.254",
            None,
        ]
        for target in bad_targets:
            with self.subTest(target=target):
                with patch.object(subdomains, "_fetch_crtsh",
                                  side_effect=AssertionError("network")), \
                     patch.object(subdomains, "_probe_wildcard",
                                  side_effect=AssertionError("dns")):
                    with self.assertRaises(ValueError):
                        subdomains.run(target, use_crtsh=True)

    def test_trailing_dot_and_case_are_normalized(self):
        seen = []

        def resolve_a(host, _resolver):
            seen.append(host)
            return None

        with patch.object(subdomains, "_resolve_a", side_effect=resolve_a), \
             patch.object(subdomains, "_resolve_cname", return_value=None), \
             patch.object(subdomains, "_fetch_crtsh", return_value=([], None)):
            wordlist = _write_wordlist("WWW\n")
            subdomains.run("Example.COM.", wordlist=wordlist, use_crtsh=True)

        self.assertIn("www.example.com", seen)

    def test_threads_and_timeout_rejected_before_network(self):
        with patch.object(subdomains, "_fetch_crtsh",
                          side_effect=AssertionError("network")), \
             patch.object(subdomains, "_load_wordlist",
                          side_effect=AssertionError("disk")):
            with self.assertRaises(ValueError):
                subdomains.run("example.com", threads=0)
            with self.assertRaises(ValueError):
                subdomains.run("example.com", timeout=0)
            with self.assertRaises(ValueError):
                subdomains.run("example.com", crtsh_timeout=0)

    def test_missing_wordlist_does_not_fetch(self):
        with patch.object(subdomains, "_fetch_crtsh",
                          side_effect=AssertionError("network")), \
             patch.object(subdomains, "_probe_wildcard",
                          side_effect=AssertionError("dns")):
            with self.assertRaises(FileNotFoundError):
                subdomains.run(
                    "example.com",
                    wordlist="/no/such/netrecon-wordlist",
                    use_crtsh=True,
                )

    def test_wordlist_skips_comments_dupes_and_invalid_labels(self):
        path = _write_wordlist(
            "# comment\n\nWWW\nbad_name!\nwww\n-bad\napi.dev\nok\n"
        )
        self.assertEqual(
            subdomains._load_wordlist(Path(path)),
            ["www", "api.dev", "ok"],
        )

    def test_default_wordlist_exists(self):
        self.assertTrue(subdomains.DEFAULT_WORDLIST.is_file())


class TestNameParsing(unittest.TestCase):
    def test_crtsh_rows_keep_only_real_subdomains(self):
        rows = [
            {
                "name_value": "www.example.com\n*.dev.example.com\n"
                              "example.com\nother.com\n<script>.example.com",
                "common_name": "api.example.com",
            },
            {"name_value": "*.example.com", "common_name": "WWW.Example.com."},
            {"name_value": None, "common_name": 12},
            "not-a-row",
            {"name_value": "foo.*.example.com"},
        ]
        self.assertEqual(
            subdomains._names_from_crtsh(rows, "example.com"),
            ["api.example.com", "dev.example.com", "www.example.com"],
        )

    def test_out_of_scope_suffix_is_rejected(self):
        self.assertIsNone(subdomains._host_under("example.com.evil.com", "example.com"))
        self.assertIsNone(subdomains._host_under("notexample.com", "example.com"))
        self.assertEqual(
            subdomains._host_under("*.api.example.com", "example.com"),
            "api.example.com",
        )


class TestTakeoverAndWildcard(unittest.TestCase):
    def test_takeover_matches_suffix_not_substring(self):
        hint = subdomains._takeover_hint("FOO.GITHUB.IO.")
        self.assertIn("GitHub Pages", hint)
        self.assertIn("foo.github.io", hint)
        self.assertIsNotNone(subdomains._takeover_hint("github.io"))
        self.assertIsNotNone(subdomains._takeover_hint("bucket.s3.amazonaws.com"))
        self.assertIsNone(subdomains._takeover_hint("notgithub.io"))
        self.assertIsNone(subdomains._takeover_hint("github.io.evil.example"))
        self.assertIsNone(subdomains._takeover_hint(None))
        self.assertIsNone(subdomains._takeover_hint(""))

    def test_wildcard_noise_keeps_distinct_cname(self):
        sink = {"203.0.113.5"}
        self.assertTrue(subdomains._is_wildcard_noise(
            ["203.0.113.5"], None, sink, set(),
        ))
        self.assertFalse(subdomains._is_wildcard_noise(
            ["192.0.2.9"], None, sink, set(),
        ))
        self.assertFalse(subdomains._is_wildcard_noise(
            ["203.0.113.5", "192.0.2.9"], None, sink, set(),
        ))
        self.assertFalse(subdomains._is_wildcard_noise(
            ["203.0.113.5"], "blog.github.io", sink, set(),
        ))
        self.assertTrue(subdomains._is_wildcard_noise(
            ["203.0.113.5"], "wild.example.net", sink, {"wild.example.net"},
        ))
        self.assertFalse(subdomains._is_wildcard_noise(
            ["203.0.113.5"], None, set(), set(),
        ))


class TestCrtshFetch(unittest.TestCase):
    def test_redirect_is_not_followed_and_body_is_not_read(self):
        resp = MagicMock()
        resp.status_code = 302
        resp.headers = {"Location": "http://169.254.169.254/latest/meta-data"}
        resp.iter_content.side_effect = AssertionError("body was read")

        with patch("netrecon.modules.subdomains.requests.get", return_value=resp) as get:
            names, err = subdomains._fetch_crtsh("example.com")

        self.assertEqual(names, [])
        self.assertEqual(err, "crt.sh redirected; refusing to follow")
        self.assertNotIn("169.254", err)
        self.assertEqual(get.call_count, 1)
        self.assertEqual(get.call_args.args[0], "https://crt.sh/")
        self.assertEqual(get.call_args.kwargs["params"]["q"], "%.example.com")
        self.assertFalse(get.call_args.kwargs["allow_redirects"])
        self.assertTrue(get.call_args.kwargs["stream"])
        self.assertEqual(
            get.call_args.kwargs["timeout"],
            (5.0, subdomains._CRTSH_TIMEOUT),
        )
        resp.iter_content.assert_not_called()
        resp.close.assert_called_once()

    def test_content_length_over_cap_skips_the_body(self):
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {"Content-Length": str(subdomains._CRTSH_MAX_BYTES + 1)}
        resp.iter_content.side_effect = AssertionError("body was read")

        with patch("netrecon.modules.subdomains.requests.get", return_value=resp):
            names, err = subdomains._fetch_crtsh("example.com")

        self.assertEqual(names, [])
        self.assertIn("exceeded", err)
        resp.iter_content.assert_not_called()
        resp.close.assert_called_once()

    def test_streamed_body_is_capped(self):
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {}
        resp.iter_content.return_value = [b"x" * 10, b"y" * 10]

        with patch("netrecon.modules.subdomains.requests.get", return_value=resp), \
             patch.object(subdomains, "_CRTSH_MAX_BYTES", 16):
            names, err = subdomains._fetch_crtsh("example.com")

        self.assertEqual(names, [])
        self.assertIn("exceeded", err)
        resp.close.assert_called_once()

    def test_timeout_and_connection_errors_are_contained(self):
        with patch("netrecon.modules.subdomains.requests.get",
                   side_effect=requests.Timeout("slow")):
            names, err = subdomains._fetch_crtsh("example.com")
        self.assertEqual(names, [])
        self.assertIn("timed out", err)

        boom = requests.ConnectionError("no route\nsecret-body")
        with patch("netrecon.modules.subdomains.requests.get", side_effect=boom):
            names, err = subdomains._fetch_crtsh("example.com")
        self.assertEqual(names, [])
        self.assertIn("request failed", err)
        self.assertNotIn("\n", err)
        self.assertNotIn("secret-body", err)

    def test_parses_json_names_from_a_capped_body(self):
        payload = json.dumps([
            {
                "name_value": "www.example.com\n*.dev.example.com\nexample.com",
                "common_name": "api.example.com",
            },
        ]).encode()
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {"Content-Length": str(len(payload))}
        resp.iter_content.return_value = [payload]

        with patch("netrecon.modules.subdomains.requests.get", return_value=resp):
            names, err = subdomains._fetch_crtsh("example.com")

        self.assertIsNone(err)
        self.assertEqual(names, ["api.example.com", "dev.example.com", "www.example.com"])
        resp.close.assert_called_once()

    def test_invalid_and_non_list_json(self):
        for body, needle in ((b"<html>", "invalid JSON"), (b'{"error": true}', "unexpected")):
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {}
            resp.iter_content.return_value = [body]
            with self.subTest(body=body):
                with patch("netrecon.modules.subdomains.requests.get", return_value=resp):
                    names, err = subdomains._fetch_crtsh("example.com")
            self.assertEqual(names, [])
            self.assertIn(needle, err)

    def test_http_error_status(self):
        resp = MagicMock()
        resp.status_code = 429
        resp.headers = {}
        with patch("netrecon.modules.subdomains.requests.get", return_value=resp):
            names, err = subdomains._fetch_crtsh("example.com")
        self.assertEqual(names, [])
        self.assertIn("429", err)
        resp.iter_content.assert_not_called()


class TestRun(unittest.TestCase):
    def test_wildcard_crtsh_and_dangling_cname(self):
        """Sink answers drop; a distinct CNAME and crt.sh-only names stay."""
        real = {
            "www.example.com": ["192.0.2.20"],
            "cdn.example.com": SINK,
        }
        no_a = {"blog.example.com", "decoy.example.com", "old.example.com"}
        cnames = {
            "blog.example.com": "blog.github.io",
            "decoy.example.com": "decoy.notgithub.io",
            "cdn.example.com": "cdn.example.net",
        }

        def resolve_a(host, _resolver):
            if host in no_a:
                return None
            return real.get(host, SINK)

        def resolve_cname(host, _resolver):
            return cnames.get(host)

        ct_names = [
            "www.example.com",
            "old.example.com",
            "blog.example.com",
            "not-a-name",
            "other.com",
        ]
        wordlist = _write_wordlist("www\nblog\ndecoy\nmail\ncdn\n")

        with patch.object(subdomains, "_resolve_a", side_effect=resolve_a), \
             patch.object(subdomains, "_resolve_cname", side_effect=resolve_cname), \
             patch.object(subdomains, "_fetch_crtsh", return_value=(ct_names, None)):
            result = subdomains.run(
                "Example.COM.",
                wordlist=wordlist,
                threads=4,
                use_crtsh=True,
            )

        by_host = {entry.host: entry for entry in result.entries}
        self.assertEqual(
            list(by_host),
            [
                "blog.example.com",
                "cdn.example.com",
                "decoy.example.com",
                "old.example.com",
                "www.example.com",
            ],
        )
        self.assertNotIn("mail.example.com", by_host)
        self.assertTrue(result.wildcard)
        self.assertEqual(result.wildcard_ips, SINK)
        self.assertIsNone(result.crtsh_error)

        self.assertEqual(by_host["www.example.com"].ips, ["192.0.2.20"])
        self.assertEqual(by_host["www.example.com"].source, "wordlist+crtsh")
        self.assertIsNone(by_host["www.example.com"].takeover)

        blog = by_host["blog.example.com"]
        self.assertEqual(blog.ips, [])
        self.assertEqual(blog.source, "wordlist+crtsh")
        self.assertIn("GitHub Pages", blog.takeover)
        self.assertIn("blog.github.io", blog.takeover)

        self.assertIsNone(by_host["decoy.example.com"].takeover)
        self.assertEqual(by_host["decoy.example.com"].source, "wordlist")
        self.assertEqual(by_host["cdn.example.com"].ips, SINK)
        self.assertEqual(by_host["cdn.example.com"].source, "wordlist")
        self.assertEqual(by_host["old.example.com"].ips, [])
        self.assertEqual(by_host["old.example.com"].source, "crtsh")

        subdomains.display(result)

    def test_crtsh_failure_keeps_wordlist_hits(self):
        def resolve_a(host, _resolver):
            if host == "www.example.com":
                return ["192.0.2.10"]
            return None

        wordlist = _write_wordlist("www\nmail\n")
        with patch.object(subdomains, "_resolve_a", side_effect=resolve_a), \
             patch.object(subdomains, "_resolve_cname", return_value=None), \
             patch.object(subdomains, "_fetch_crtsh",
                          return_value=([], "crt.sh request timed out")):
            result = subdomains.run("example.com", wordlist=wordlist, use_crtsh=True)

        self.assertEqual(result.crtsh_error, "crt.sh request timed out")
        self.assertFalse(result.wildcard)
        self.assertEqual([entry.host for entry in result.entries], ["www.example.com"])
        self.assertEqual(result.entries[0].source, "wordlist")

    def test_no_crtsh_does_not_fetch(self):
        wordlist = _write_wordlist("www\n")
        with patch.object(subdomains, "_resolve_a", return_value=None), \
             patch.object(subdomains, "_resolve_cname", return_value=None), \
             patch.object(subdomains, "_fetch_crtsh",
                          side_effect=AssertionError("network")):
            result = subdomains.run(
                "example.com", wordlist=wordlist, use_crtsh=False,
            )
        self.assertEqual(result.entries, [])
        self.assertIsNone(result.crtsh_error)

    def test_crtsh_name_cap_is_alphabetical_and_keeps_overlap(self):
        def resolve_a(_host, _resolver):
            return None

        wordlist = _write_wordlist("www\n")
        names = ["www.example.com", "b.example.com", "a.example.com"]
        with patch.object(subdomains, "_resolve_a", side_effect=resolve_a), \
             patch.object(subdomains, "_resolve_cname", return_value=None), \
             patch.object(subdomains, "_fetch_crtsh", return_value=(names, None)), \
             patch.object(subdomains, "_CRTSH_MAX_NAMES", 1):
            result = subdomains.run("example.com", wordlist=wordlist, use_crtsh=True)

        hosts = [entry.host for entry in result.entries]
        self.assertEqual(hosts, ["a.example.com", "www.example.com"])
        sources = {entry.host: entry.source for entry in result.entries}
        self.assertEqual(sources["www.example.com"], "wordlist+crtsh")
        self.assertEqual(sources["a.example.com"], "crtsh")
        self.assertTrue(result.notes)
        self.assertIn("first 1", result.notes[0])


class TestResolverIsolation(unittest.TestCase):
    def test_each_thread_gets_its_own_resolver(self):
        created = []

        class FakeResolver:
            def __init__(self):
                created.append(self)
                self.timeout = None
                self.lifetime = None

        subdomains._tls.resolver = None
        subdomains._tls.timeout = None
        try:
            with patch("netrecon.modules.subdomains.dns.resolver.Resolver", FakeResolver):
                main = subdomains._thread_resolver(2.0)
                again = subdomains._thread_resolver(2.0)
                self.assertIs(main, again)
                other = []

                def worker():
                    other.append(subdomains._thread_resolver(2.0))

                thread = threading.Thread(target=worker)
                thread.start()
                thread.join()
                self.assertIsNot(other[0], main)
                changed = subdomains._thread_resolver(9.0)
                self.assertIsNot(changed, main)
                self.assertEqual(len(created), 3)
        finally:
            subdomains._tls.resolver = None
            subdomains._tls.timeout = None


class TestReports(unittest.TestCase):
    def _result(self) -> SubdomainResult:
        return SubdomainResult(
            entries=[
                SubdomainEntry(
                    host="blog.example.com",
                    ips=["192.0.2.10"],
                    source="wordlist+crtsh",
                    takeover="<img src=x onerror=alert(1)>",
                ),
            ],
            wildcard=True,
            wildcard_ips=["203.0.113.9"],
            crtsh_error="crt.sh <script>alert(1)</script>",
            notes=["checked <b>names</b>"],
        )

    def test_json_report_includes_findings(self):
        report = ReconReport(target="example.com", subdomains=self._result())
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "out.json")
            json_report.save(report, path)
            data = json.loads(Path(path).read_text(encoding="utf-8"))

        block = data["subdomains"]
        self.assertTrue(block["wildcard"])
        self.assertEqual(block["wildcard_ips"], ["203.0.113.9"])
        self.assertEqual(block["entries"][0]["host"], "blog.example.com")
        self.assertEqual(block["entries"][0]["ips"], ["192.0.2.10"])
        self.assertEqual(block["entries"][0]["source"], "wordlist+crtsh")
        self.assertIn("<img", block["entries"][0]["takeover"])
        self.assertIn("<script>", block["crtsh_error"])

    def test_json_omits_subdomains_when_module_did_not_run(self):
        report = ReconReport(target="example.com")
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "out.json")
            json_report.save(report, path)
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        self.assertIsNone(data["subdomains"])

    def test_html_report_escapes_remote_text(self):
        report = ReconReport(target="example.com", subdomains=self._result())
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "out.html")
            html_report.save(report, path)
            text = Path(path).read_text(encoding="utf-8")

        self.assertNotIn("<script>", text)
        self.assertNotIn("<img", text)
        self.assertNotIn("<b>", text)
        self.assertIn("&lt;script&gt;", text)
        self.assertIn("&lt;img", text)
        self.assertIn("blog.example.com", text)
        self.assertIn("wordlist+crtsh", text)
        self.assertIn("Wildcard DNS", text)
        self.assertIn("192.0.2.10", text)

    def test_summary_mentions_wildcard_and_takeover(self):
        report = ReconReport(target="example.com", subdomains=self._result())
        buf = io.StringIO()
        with redirect_stdout(buf):
            report.summary()
        text = buf.getvalue()
        self.assertIn("Subdomains : 1 name", text)
        self.assertIn("1 resolving", text)
        self.assertIn("wildcard DNS", text)
        self.assertIn("1 takeover hint(s)", text)
        self.assertIn("crt.sh failed", text)

    def test_scan_stores_the_full_result(self):
        result = self._result()
        args = Namespace(
            target="example.com",
            all=False,
            dns=False,
            ssl=False,
            headers=False,
            whois=False,
            subdomains=True,
            ports=False,
            wordlist=None,
            threads=4,
            no_crtsh=True,
            profile="top20",
            timeout=1.0,
            output=None,
            format="json",
        )
        with tempfile.TemporaryDirectory() as tmp:
            args.output = str(Path(tmp) / "scan.json")
            with patch("netrecon.cli.subdomains.run", return_value=result) as run:
                cmd_scan(args)
            data = json.loads(Path(args.output).read_text(encoding="utf-8"))

        self.assertEqual(run.call_args.args[0], "example.com")
        self.assertFalse(run.call_args.kwargs["use_crtsh"])
        self.assertEqual(run.call_args.kwargs["threads"], 4)
        entry = data["subdomains"]["entries"][0]
        self.assertEqual(entry["host"], "blog.example.com")
        self.assertEqual(entry["ips"], ["192.0.2.10"])
        self.assertEqual(entry["source"], "wordlist+crtsh")
        self.assertTrue(entry["takeover"])
        self.assertTrue(data["subdomains"]["wildcard"])

    def test_cli_rejects_bad_input_without_a_traceback(self):
        from netrecon.cli import main

        cases = [
            ["netrecon", "subdomains", "127.0.0.1", "--no-crtsh"],
            ["netrecon", "subdomains", "example.com",
             "--wordlist", "/no/such/netrecon-wordlist", "--no-crtsh"],
        ]
        for argv in cases:
            stderr = io.StringIO()
            with self.subTest(argv=argv), \
                 patch("sys.argv", argv), \
                 redirect_stdout(io.StringIO()), \
                 redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as caught:
                    main()
            self.assertEqual(caught.exception.code, 1)
            self.assertIn("Error:", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())


def _write_wordlist(contents: str) -> str:
    handle = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8")
    handle.write(contents)
    handle.close()
    return handle.name


if __name__ == "__main__":
    unittest.main()
