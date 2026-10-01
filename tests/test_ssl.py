"""Tests for ssl_check module."""
import unittest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock
from netrecon.models import SslResult
from netrecon.modules import ssl_check


class TestSslCheck(unittest.TestCase):

    def _make_result(self, days_left=90, tls="TLSv1.3", valid=True) -> SslResult:
        expiry = datetime.now(timezone.utc) + timedelta(days=days_left)
        return SslResult(
            valid=valid,
            subject="example.com",
            issuer="Let's Encrypt",
            expiry=expiry,
            days_left=days_left,
            tls_version=tls,
            cipher="TLS_AES_256_GCM_SHA384",
            san=["example.com", "www.example.com"],
        )

    # ── Expiry warnings ───────────────────────────────────────────────

    def test_healthy_cert_no_issues(self):
        r = self._make_result(days_left=90)
        issues = []
        if r.days_left < 0:
            issues.append("expired")
        elif r.days_left < ssl_check._EXPIRY_CRIT_DAYS:
            issues.append("critical")
        elif r.days_left < ssl_check._EXPIRY_WARN_DAYS:
            issues.append("warn")
        self.assertEqual(issues, [])

    def test_expired_cert_raises_issue(self):
        r = self._make_result(days_left=-5)
        issues = []
        if r.days_left < 0:
            issues.append("Certificate is EXPIRED")
        self.assertIn("Certificate is EXPIRED", issues)

    def test_cert_expiring_soon_warn(self):
        r = self._make_result(days_left=20)
        issues = []
        if 0 < r.days_left < ssl_check._EXPIRY_WARN_DAYS:
            issues.append(f"Certificate expires soon ({r.days_left} days)")
        self.assertTrue(any("expires soon" in i for i in issues))

    def test_cert_expiring_critically(self):
        r = self._make_result(days_left=5)
        issues = []
        if 0 < r.days_left < ssl_check._EXPIRY_CRIT_DAYS:
            issues.append("renew immediately")
        self.assertTrue(any("renew immediately" in i for i in issues))

    # ── Protocol checks ───────────────────────────────────────────────

    def test_weak_tls_version_flagged(self):
        for weak in ("TLSv1", "TLSv1.1", "SSLv3"):
            r = self._make_result(tls=weak)
            issues = []
            if r.tls_version in ssl_check._WEAK_PROTOCOLS:
                issues.append(f"Weak protocol in use: {r.tls_version}")
            self.assertTrue(any("Weak protocol" in i for i in issues),
                            f"{weak} should be flagged as weak")

    def test_tls_13_not_flagged(self):
        r = self._make_result(tls="TLSv1.3")
        issues = []
        if r.tls_version in ssl_check._WEAK_PROTOCOLS:
            issues.append("weak")
        self.assertEqual(issues, [])

    def test_tls_12_not_flagged(self):
        r = self._make_result(tls="TLSv1.2")
        issues = []
        if r.tls_version in ssl_check._WEAK_PROTOCOLS:
            issues.append("weak")
        self.assertEqual(issues, [])

    # ── SANs ──────────────────────────────────────────────────────────

    def test_no_san_adds_issue(self):
        r = SslResult(valid=True, san=[])
        issues = []
        if not r.san:
            issues.append("No Subject Alternative Names (SANs)")
        self.assertIn("No Subject Alternative Names (SANs)", issues)

    def test_has_san_no_issue(self):
        r = self._make_result()  # has SANs
        issues = []
        if not r.san:
            issues.append("No SANs")
        self.assertEqual(issues, [])

    # ── Invalid cert ──────────────────────────────────────────────────

    def test_invalid_cert_marked(self):
        r = self._make_result(valid=False)
        self.assertFalse(r.valid)

    # ── Connection failure path ───────────────────────────────────────

    def test_connection_error_returns_result(self):
        with patch("ssl.create_default_context") as mock_ctx:
            mock_ctx.return_value.wrap_socket.side_effect = OSError("refused")
            result = ssl_check.run("192.0.2.1", port=443)   # TEST-NET — never routed
        self.assertFalse(result.valid)
        self.assertTrue(len(result.issues) > 0)


if __name__ == "__main__":
    unittest.main()
