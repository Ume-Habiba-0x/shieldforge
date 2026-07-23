"""Unit tests for modules/sqli.py"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from core.context import Config, Context
from core.models import Severity
from modules.sqli import SQLiScanner

PAYLOADS_FIXTURE = """
error|'
boolean_true|' OR 1=1--
boolean_false|' OR 1=2--
time|' AND SLEEP(5)--
time_control|' AND SLEEP(0)--
"""


@pytest.fixture()
def payloads_file(tmp_path: Path) -> Path:
    p = tmp_path / "payloads.txt"
    p.write_text(PAYLOADS_FIXTURE, encoding="utf-8")
    return p


def make_response(text: str, status_code: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.text = text
    resp.status_code = status_code
    return resp


def make_context(target_url: str) -> Context:
    return Context(config=Config(target_url=target_url))


class TestPayloadLoading:
    def test_loads_and_buckets_all_categories(self, payloads_file: Path) -> None:
        scanner = SQLiScanner(payloads_path=payloads_file)
        assert scanner._error_payloads == ["'"]
        assert scanner._true_payloads == ["' OR 1=1--"]
        assert scanner._false_payloads == ["' OR 1=2--"]
        assert scanner._time_payloads == ["' AND SLEEP(5)--"]
        assert scanner._time_control_payloads == ["' AND SLEEP(0)--"]

    def test_missing_file_does_not_crash(self, tmp_path: Path) -> None:
        missing = tmp_path / "does_not_exist.txt"
        scanner = SQLiScanner(payloads_path=missing)
        assert scanner._error_payloads == []


class TestContractCompliance:
    def test_name_and_description(self, payloads_file: Path) -> None:
        scanner = SQLiScanner(payloads_path=payloads_file)
        assert scanner.name == "sqli"
        assert isinstance(scanner.description, str)
        assert len(scanner.description) > 0

    def test_validate_fails_without_target(self, payloads_file: Path) -> None:
        scanner = SQLiScanner(payloads_path=payloads_file)
        context = make_context("")
        assert scanner.validate(context) is False

    def test_validate_passes_with_target(self, payloads_file: Path) -> None:
        scanner = SQLiScanner(payloads_path=payloads_file)
        context = make_context("http://example.com/?id=1")
        assert scanner.validate(context) is True

    def test_get_http_uses_context_attribute(self, payloads_file: Path) -> None:
        scanner = SQLiScanner(payloads_path=payloads_file)
        context = make_context("http://example.com/?id=1")
        sentinel = MagicMock()
        context.http_client = sentinel
        assert scanner._get_http(context) is sentinel

    def test_get_http_falls_back_when_missing(self, payloads_file: Path) -> None:
        from utils.http_client import HTTPClient

        scanner = SQLiScanner(payloads_path=payloads_file)
        context = make_context("http://example.com/?id=1")
        assert isinstance(scanner._get_http(context), HTTPClient)

    def test_get_logger_uses_shared_shieldforge_logger(self, payloads_file: Path) -> None:
        scanner = SQLiScanner(payloads_path=payloads_file)
        assert scanner._get_logger().name == "shieldforge"


class TestErrorSignatureMatching:
    def test_matches_mysql_error(self, payloads_file: Path) -> None:
        scanner = SQLiScanner(payloads_path=payloads_file)
        text = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server"
        assert scanner._match_error_signature(text) == "MySQL"

    def test_no_match_returns_none(self, payloads_file: Path) -> None:
        scanner = SQLiScanner(payloads_path=payloads_file)
        assert scanner._match_error_signature("<html>Welcome</html>") is None


class TestErrorBasedDetection:
    def test_detects_error_based_sqli(self, payloads_file: Path) -> None:
        scanner = SQLiScanner(payloads_path=payloads_file)
        http = MagicMock()
        http.get.return_value = make_response("SQL syntax error near MySQL server")
        logger = MagicMock()

        finding = scanner._error_based_test(http, "http://example.com/?id=1", "id", logger, baseline_status=200)

        assert finding is not None
        assert finding.severity == Severity.HIGH
        assert finding.evidence["database_fingerprint"] == "MySQL"

    def test_clean_response_returns_none(self, payloads_file: Path) -> None:
        scanner = SQLiScanner(payloads_path=payloads_file)
        http = MagicMock()
        http.get.return_value = make_response("<html>Normal page</html>")
        logger = MagicMock()

        finding = scanner._error_based_test(http, "http://example.com/?id=1", "id", logger, baseline_status=200)
        assert finding is None

    def test_generic_500_with_no_signature_still_flagged(self, payloads_file: Path) -> None:
        """Real-world case: app catches the DB exception and shows a bare
        'Internal Server Error' page with no vendor-specific text at all -
        the baseline(200) -> payload(500) status flip should still be caught."""
        scanner = SQLiScanner(payloads_path=payloads_file)
        http = MagicMock()
        http.get.return_value = make_response("<h4>Internal Server Error</h4>", status_code=500)
        logger = MagicMock()

        finding = scanner._error_based_test(http, "http://example.com/?id=1", "id", logger, baseline_status=200)

        assert finding is not None
        assert finding.evidence["database_fingerprint"] == "Unknown (generic error page, no leaked signature)"

    def test_cloudflare_525_not_flagged_as_sqli(self, payloads_file: Path) -> None:
        """Real-world case found via live testing: a raw quote in a URL can
        trip a 525 (Cloudflare SSL handshake failed) at the CDN/edge layer,
        with nothing to do with the origin app's SQL query. This must NOT be
        treated as evidence of SQLi - it's a network/proxy-layer status, not
        an application-level one."""
        scanner = SQLiScanner(payloads_path=payloads_file)
        http = MagicMock()
        http.get.return_value = make_response("<html>525 SSL handshake failed</html>", status_code=525)
        logger = MagicMock()

        finding = scanner._error_based_test(http, "http://example.com/?id=1", "id", logger, baseline_status=200)
        assert finding is None

    def test_real_application_502_still_flagged(self, payloads_file: Path) -> None:
        """Sanity check the exclusion is scoped correctly: a genuine
        application-level 502 (not in the 520-527 Cloudflare range) should
        still be caught by the generic fallback."""
        scanner = SQLiScanner(payloads_path=payloads_file)
        http = MagicMock()
        http.get.return_value = make_response("<html>Bad Gateway</html>", status_code=502)
        logger = MagicMock()

        finding = scanner._error_based_test(http, "http://example.com/?id=1", "id", logger, baseline_status=200)
        assert finding is not None
        assert finding.confidence == 0.75

    def test_baseline_already_500_does_not_false_positive(self, payloads_file: Path) -> None:
        """If the target already returns 500 for everything (broken page,
        unrelated to injection), a payload also returning 500 should not
        be flagged as a new finding."""
        scanner = SQLiScanner(payloads_path=payloads_file)
        http = MagicMock()
        http.get.return_value = make_response("<h4>Internal Server Error</h4>", status_code=500)
        logger = MagicMock()

        finding = scanner._error_based_test(http, "http://example.com/?id=1", "id", logger, baseline_status=500)
        assert finding is None

    def test_retry_exhausted_persistent_5xx_still_flagged(self, payloads_file: Path) -> None:
        """Real-world case discovered via live testing: HTTPClient's Retry
        adapter (status_forcelist=[500,502,503,504], raise_on_status=True)
        raises RetryError after exhausting retries on a persistent 5xx, so
        the response object never reaches our code at all - the scanner
        must treat retry-exhaustion itself as evidence, not just silently
        swallow it as an ordinary failed request."""
        import requests

        scanner = SQLiScanner(payloads_path=payloads_file)
        http = MagicMock()
        http.get.side_effect = requests.exceptions.RetryError("Max retries exceeded")
        logger = MagicMock()

        finding = scanner._error_based_test(http, "http://example.com/?id=1", "id", logger, baseline_status=200)

        assert finding is not None
        assert "persistent 5xx" in finding.evidence["database_fingerprint"]
        assert finding.confidence == 0.65

    def test_ordinary_connection_failure_not_flagged(self, payloads_file: Path) -> None:
        """A genuinely failed request (DNS, timeout, connection refused) is
        NOT the same as retry-exhaustion and must not be flagged."""
        import requests

        scanner = SQLiScanner(payloads_path=payloads_file)
        http = MagicMock()
        http.get.side_effect = requests.exceptions.ConnectionError("Connection refused")
        logger = MagicMock()

        finding = scanner._error_based_test(http, "http://example.com/?id=1", "id", logger, baseline_status=200)
        assert finding is None


class TestBooleanBasedDetection:
    def test_detects_boolean_based_sqli(self, payloads_file: Path) -> None:
        scanner = SQLiScanner(payloads_path=payloads_file)
        http = MagicMock()
        http.get.side_effect = [
            make_response("<html>" + "A" * 500 + "</html>"),
            make_response("<html>No results found</html>"),
        ]
        logger = MagicMock()

        finding = scanner._boolean_based_test(http, "http://example.com/?id=1", "id", logger)

        assert finding is not None
        assert finding.evidence["length_delta"] > 5

    def test_identical_responses_not_flagged(self, payloads_file: Path) -> None:
        scanner = SQLiScanner(payloads_path=payloads_file)
        http = MagicMock()
        http.get.side_effect = [make_response("same"), make_response("same")]
        logger = MagicMock()

        finding = scanner._boolean_based_test(http, "http://example.com/?id=1", "id", logger)
        assert finding is None


class TestTimeBasedDetection:
    def test_detects_time_based_sqli(self, payloads_file: Path) -> None:
        scanner = SQLiScanner(payloads_path=payloads_file)
        http = MagicMock()
        http.get.return_value = make_response("<html>ok</html>")
        logger = MagicMock()

        with patch("time.time", side_effect=[0.0, 0.2, 0.2, 5.4]):
            finding = scanner._time_based_test(http, "http://example.com/?id=1", "id", logger)

        assert finding is not None
        assert finding.evidence["technique"] == "time-based"
        assert finding.evidence["delay_delta_s"] >= 4.0

    def test_fast_responses_not_flagged(self, payloads_file: Path) -> None:
        scanner = SQLiScanner(payloads_path=payloads_file)
        http = MagicMock()
        http.get.return_value = make_response("<html>ok</html>")
        logger = MagicMock()

        with patch("time.time", side_effect=[0.0, 0.1, 0.1, 0.3]):
            finding = scanner._time_based_test(http, "http://example.com/?id=1", "id", logger)

        assert finding is None

    def test_noisy_control_is_skipped(self, payloads_file: Path) -> None:
        scanner = SQLiScanner(payloads_path=payloads_file)
        http = MagicMock()
        http.get.return_value = make_response("<html>ok</html>")
        logger = MagicMock()

        # Control itself takes 3.5s - too noisy to trust, should be skipped entirely.
        with patch("time.time", side_effect=[0.0, 3.5]):
            finding = scanner._time_based_test(http, "http://example.com/?id=1", "id", logger)

        assert finding is None


class TestFullScan:
    def test_scan_with_no_parameters(self, payloads_file: Path) -> None:
        scanner = SQLiScanner(payloads_path=payloads_file)
        context = make_context("http://example.com/page")
        result = scanner.scan(context)
        assert result.has_findings is False
        assert result.module_name == "sqli"

    def test_scan_reports_vulnerable_parameter(self, payloads_file: Path) -> None:
        scanner = SQLiScanner(payloads_path=payloads_file)
        context = make_context("http://example.com/?id=1")
        context.http_client = MagicMock()
        context.http_client.get.return_value = make_response("SQL syntax error near MySQL server")

        result = scanner.scan(context)

        assert result.has_findings is True
        assert result.findings[0].evidence["database_fingerprint"] == "MySQL"

    def test_run_wraps_scan_with_timing(self, payloads_file: Path) -> None:
        scanner = SQLiScanner(payloads_path=payloads_file)
        context = make_context("http://example.com/page")
        result = scanner.run(context)
        assert result.duration_ms >= 0
