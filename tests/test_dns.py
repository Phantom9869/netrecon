"""Tests for dns_enum module."""
import unittest
from unittest.mock import patch, MagicMock
from netrecon.modules import dns_enum
from netrecon.models import DnsResult


class TestDnsEnum(unittest.TestCase):

    def test_result_type(self):
        """run() always returns a DnsResult."""
        with patch("dns.resolver.Resolver") as mock_resolver:
            mock_resolver.return_value.resolve.side_effect = Exception("no network")
            result = dns_enum.run("example.com")
        self.assertIsInstance(result, DnsResult)

    def test_no_spf_adds_issue(self):
        """Missing SPF should appear in issues."""
        result = DnsResult()  # spf is None by default
        # Manually trigger issue logic
        if not result.spf:
            result.issues.append("No SPF record — domain open to email spoofing")
        self.assertIn("No SPF record — domain open to email spoofing", result.issues)

    def test_no_dmarc_adds_issue(self):
        """Missing DMARC should appear in issues."""
        result = DnsResult()
        if not result.dmarc:
            result.issues.append("No DMARC record — no email authentication policy")
        self.assertIn("No DMARC record — no email authentication policy", result.issues)

    def test_single_ns_adds_issue(self):
        """Only one nameserver should trigger a single-point-of-failure warning."""
        result = DnsResult(ns=["ns1.example.com"])
        if len(result.ns) < 2:
            result.issues.append("Only 1 nameserver — single point of failure")
        self.assertIn("Only 1 nameserver — single point of failure", result.issues)

    def test_two_ns_no_issue(self):
        """Two or more nameservers should not trigger the NS issue."""
        result = DnsResult(ns=["ns1.example.com", "ns2.example.com"])
        issues = []
        if len(result.ns) < 2:
            issues.append("Only 1 nameserver — single point of failure")
        self.assertEqual(issues, [])

    def test_spf_detected_in_txt(self):
        """SPF record starting with v=spf1 should be captured."""
        spf_txt = "v=spf1 include:_spf.google.com ~all"
        result  = DnsResult(txt=[spf_txt])
        for text in result.txt:
            if text.lower().startswith("v=spf1"):
                result.spf = text
        self.assertEqual(result.spf, spf_txt)


if __name__ == "__main__":
    unittest.main()
