"""Tests for headers module."""
import unittest
from unittest.mock import patch, MagicMock
from netrecon.models import HeaderResult
from netrecon.modules import headers


class TestHeaderGrader(unittest.TestCase):

    # ── Grade thresholds ──────────────────────────────────────────────

    def test_grade_a_plus_perfect_score(self):
        grade = headers._grade(8, 8)
        self.assertEqual(grade, "A+")

    def test_grade_a(self):
        grade = headers._grade(7, 8)   # ~87%
        self.assertEqual(grade, "A")

    def test_grade_b(self):
        grade = headers._grade(6, 8)   # 75%
        self.assertEqual(grade, "B")

    def test_grade_c(self):
        grade = headers._grade(5, 8)   # 62%
        self.assertEqual(grade, "C")

    def test_grade_d(self):
        grade = headers._grade(3, 8)   # 37%
        self.assertEqual(grade, "D")

    def test_grade_f_low_score(self):
        grade = headers._grade(1, 8)   # 12%
        self.assertEqual(grade, "F")

    def test_grade_f_zero_score(self):
        grade = headers._grade(0, 8)
        self.assertEqual(grade, "F")

    def test_grade_zero_max_score(self):
        """Division by zero guard — max_score=0 should return F."""
        grade = headers._grade(0, 0)
        self.assertEqual(grade, "F")

    # ── Header detection ──────────────────────────────────────────────

    def _mock_response(self, header_dict: dict) -> MagicMock:
        mock_resp = MagicMock()
        mock_resp.headers = header_dict
        return mock_resp

    def test_all_headers_present_gives_high_grade(self):
        good_headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy":   "default-src 'self'",
            "X-Frame-Options":           "DENY",
            "X-Content-Type-Options":    "nosniff",
            "Referrer-Policy":           "no-referrer",
            "Permissions-Policy":        "geolocation=()",
        }
        with patch("requests.get", return_value=self._mock_response(good_headers)):
            result = headers.run("example.com")
        self.assertIn(result.grade[0], ("A",))
        self.assertEqual(result.missing, [])
        self.assertEqual(len(result.present), 6)

    def test_no_headers_gives_f(self):
        with patch("requests.get", return_value=self._mock_response({})):
            result = headers.run("example.com")
        self.assertEqual(result.grade, "F")
        self.assertEqual(result.score, 0)
        self.assertEqual(result.present, [])

    def test_hsts_without_max_age_not_counted(self):
        """HSTS value must contain max-age= to count."""
        bad_hsts = {"Strict-Transport-Security": "includeSubDomains"}
        with patch("requests.get", return_value=self._mock_response(bad_hsts)):
            result = headers.run("example.com")
        self.assertNotIn("Strict-Transport-Security", result.present)
        self.assertIn("Strict-Transport-Security", result.missing)

    def test_x_frame_options_must_be_deny_or_sameorigin(self):
        bad = {"X-Frame-Options": "ALLOWALL"}
        with patch("requests.get", return_value=self._mock_response(bad)):
            result = headers.run("example.com")
        self.assertNotIn("X-Frame-Options", result.present)

    def test_x_content_type_must_be_nosniff(self):
        bad = {"X-Content-Type-Options": "something-else"}
        with patch("requests.get", return_value=self._mock_response(bad)):
            result = headers.run("example.com")
        self.assertNotIn("X-Content-Type-Options", result.present)

    def test_server_header_recorded_in_details(self):
        resp_headers = {"Server": "Apache/2.4.51"}
        with patch("requests.get", return_value=self._mock_response(resp_headers)):
            result = headers.run("example.com")
        self.assertEqual(result.details.get("Server"), "Apache/2.4.51")

    # ── Network error path ────────────────────────────────────────────

    def test_request_exception_returns_f(self):
        import requests as req
        with patch("requests.get", side_effect=req.RequestException("timeout")):
            result = headers.run("example.com")
        self.assertEqual(result.grade, "F")
        self.assertEqual(result.score, 0)
        self.assertIn("error", result.details)

    # ── Result type ───────────────────────────────────────────────────

    def test_returns_header_result(self):
        with patch("requests.get", return_value=self._mock_response({})):
            result = headers.run("example.com")
        self.assertIsInstance(result, HeaderResult)

    def test_max_score_constant(self):
        """max_score should always match the number of weighted checks."""
        expected = sum(m["weight"] for m in headers.SECURITY_HEADERS.values())
        self.assertEqual(headers._MAX_SCORE, expected)


if __name__ == "__main__":
    unittest.main()
