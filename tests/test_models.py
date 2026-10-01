"""Tests for shared dataclasses in models.py."""
import unittest
from datetime import datetime
from netrecon.models import (
    DnsResult, SslResult, HeaderResult, WhoisResult,
    PortEntry, ReconReport,
)


class TestDnsResult(unittest.TestCase):
    def test_defaults(self):
        r = DnsResult()
        self.assertEqual(r.a, [])
        self.assertIsNone(r.spf)
        self.assertIsNone(r.dmarc)
        self.assertEqual(r.issues, [])


class TestSslResult(unittest.TestCase):
    def test_defaults(self):
        r = SslResult()
        self.assertFalse(r.valid)
        self.assertEqual(r.days_left, 0)
        self.assertEqual(r.san, [])


class TestHeaderResult(unittest.TestCase):
    def test_default_grade_f(self):
        r = HeaderResult()
        self.assertEqual(r.grade, "F")
        self.assertEqual(r.score, 0)


class TestWhoisResult(unittest.TestCase):
    def test_defaults(self):
        r = WhoisResult()
        self.assertIsNone(r.registrar)
        self.assertIsNone(r.days_until_expiry)
        self.assertEqual(r.nameservers, [])


class TestPortEntry(unittest.TestCase):
    def test_open_port(self):
        p = PortEntry(port=80, state="open", service="http", banner="nginx")
        self.assertEqual(p.state, "open")

    def test_closed_port(self):
        p = PortEntry(port=8080, state="closed")
        self.assertEqual(p.service, "")


class TestReconReport(unittest.TestCase):
    def test_open_ports_property(self):
        report = ReconReport(target="example.com")
        report.ports = [
            PortEntry(port=80,   state="open"),
            PortEntry(port=81,   state="closed"),
            PortEntry(port=443,  state="open"),
            PortEntry(port=8080, state="filtered"),
        ]
        self.assertEqual(len(report.open_ports), 2)
        self.assertEqual([p.port for p in report.open_ports], [80, 443])

    def test_open_ports_empty(self):
        report = ReconReport(target="example.com")
        self.assertEqual(report.open_ports, [])

    def test_errors_dict_default_empty(self):
        report = ReconReport(target="example.com")
        self.assertEqual(report.errors, {})

    def test_scanned_at_default_is_datetime(self):
        report = ReconReport(target="example.com")
        self.assertIsInstance(report.scanned_at, datetime)


if __name__ == "__main__":
    unittest.main()
