"""
modules/sqli.py

SQL Injection Detection Module for ShieldForge.
Owned by: Member D (ITSOLERA Summer Internship)

Three detection tiers, run cheapest/most-confident first, stopping at the
first confirmed technique per parameter:

    1. Error-based  - inject syntax-breaking payloads, match DB error signatures
    2. Boolean-based - inject true/false condition pairs, diff the responses
    3. Time-based   - inject deliberate delay payloads, compare timing against
                       a same-shaped zero-delay control payload

This module never sends destructive payloads (no DROP/DELETE/UPDATE/INSERT).
Its job is to prove injection is possible, not to mutate target data.

Per core/engine.py: Engine sets `context.http_client = HTTPClient(...)` as a
plain attribute (not in context.data), and there is no logger on context at
all - engine.py calls `setup_logger("shieldforge")` once at import time, and
any later call to `setup_logger("shieldforge")` returns that same configured
logger by name. This module follows both conventions exactly.
"""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

from core.context import Context
from core.models import Finding, ScanResult, Severity
from modules.base import BaseScanner
from utils.http_client import HTTPClient
from utils.logger import setup_logger

DEFAULT_PAYLOADS_PATH = Path(__file__).resolve().parents[1] / "config" / "payloads" / "sqli_payloads.txt"

# Delay requested by time-based payloads (seconds). Payload file and this
# threshold must stay in sync - payloads ask for SLEEP(5)/WAITFOR DELAY 0:0:5.
TIME_DELAY_SECONDS = 5
# A measured delta below this (but above 0) is treated as network jitter,
# not a confirmed delay - keeps threshold safely under the requested delay.
TIME_DELTA_THRESHOLD = 4.0
# If the *control* payload itself takes this long, the network/target is too
# noisy to trust a timing comparison - skip rather than risk a false positive.
CONTROL_NOISE_CEILING = 3.0

# Cloudflare-specific edge/CDN status codes (520-527, e.g. 525 = SSL handshake
# failed between Cloudflare and the origin). These indicate a network/proxy
# layer problem, not an application-level SQL error - excluded from the
# generic 5xx fallback below to avoid false positives on Cloudflare-fronted
# targets where a raw quote in a URL trips edge/WAF behavior unrelated to SQL.
CLOUDFLARE_EDGE_CODES = range(520, 528)

SQL_ERROR_SIGNATURES: Dict[str, "re.Pattern[str]"] = {
    "MySQL": re.compile(
        r"SQL syntax.*MySQL|Warning.*mysql_|MySQLSyntaxErrorException|"
        r"valid MySQL result|check the manual that corresponds to your (MySQL|MariaDB) server",
        re.IGNORECASE,
    ),
    "PostgreSQL": re.compile(
        r"PostgreSQL.*ERROR|Warning.*\Wpg_|valid PostgreSQL result|Npgsql\.",
        re.IGNORECASE,
    ),
    "MSSQL": re.compile(
        r"Driver.* SQL[\-\_\ ]*Server|OLE DB.* SQL Server|"
        r"Unclosed quotation mark after the character string|Microsoft SQL Native Client error",
        re.IGNORECASE,
    ),
    "Oracle": re.compile(
        r"\bORA-[0-9]{4,5}\b|Oracle error|Oracle.*Driver|quoted string not properly terminated",
        re.IGNORECASE,
    ),
    "SQLite": re.compile(
        r"SQLite/JDBCDriver|SQLite\.Exception|System\.Data\.SQLite\.SQLiteException|"
        r"\[SQLITE_ERROR\]|near \".*\": syntax error",
        re.IGNORECASE,
    ),
    "Generic": re.compile(
        r"SQL syntax|syntax error|unclosed quotation mark|quoted string not properly terminated",
        re.IGNORECASE,
    ),
}


class SQLiScanner(BaseScanner):
    """Detects SQL injection points via error, boolean, and time-based techniques."""

    @property
    def name(self) -> str:
        return "sqli"

    @property
    def description(self) -> str:
        return "Detect SQL injection vulnerabilities via error, boolean, and time-based techniques"

    def __init__(self, payloads_path: Path | str | None = None) -> None:
        self._payloads_path = Path(payloads_path) if payloads_path else DEFAULT_PAYLOADS_PATH
        self._error_payloads: List[str] = []
        self._true_payloads: List[str] = []
        self._false_payloads: List[str] = []
        self._time_payloads: List[str] = []
        self._time_control_payloads: List[str] = []
        self._load_payloads()

    # ------------------------------------------------------------------ #
    # Context helpers
    # ------------------------------------------------------------------ #
    def _get_http(self, context: Context) -> HTTPClient:
        http = getattr(context, "http_client", None)
        if http is not None:
            return http  # type: ignore[no-any-return]  # dynamically-set attribute, untyped upstream
        logger = self._get_logger()
        logger.warning(
            "No http_client found on context - creating a fallback HTTPClient"
        )
        # HTTPClient's proxy param is typed `str` but Config.proxy is Optional[str];
        # HTTPClient itself handles None correctly at runtime (see utils/http_client.py).
        return HTTPClient(
            timeout=context.config.timeout,
            proxy=context.config.proxy,  # type: ignore[arg-type]
            user_agent=context.config.user_agent,
            verify_ssl=context.config.verify_ssl,
        )

    def _get_logger(self) -> Any:
        # engine.py calls setup_logger("shieldforge") once at import time;
        # calling it again with the same name returns that same configured
        # logger (setup_logger guards against re-adding handlers).
        return setup_logger("shieldforge")

    # ------------------------------------------------------------------ #
    # Payload loading
    # ------------------------------------------------------------------ #
    def _load_payloads(self) -> None:
        try:
            lines = self._payloads_path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return

        for raw_line in lines:
            line = raw_line.strip()
            if not line or line.startswith("#") or "|" not in line:
                continue
            category, _, payload = line.partition("|")
            category = category.strip()
            if category == "error":
                self._error_payloads.append(payload)
            elif category == "boolean_true":
                self._true_payloads.append(payload)
            elif category == "boolean_false":
                self._false_payloads.append(payload)
            elif category == "time":
                self._time_payloads.append(payload)
            elif category == "time_control":
                self._time_control_payloads.append(payload)

    # ------------------------------------------------------------------ #
    # URL helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _extract_parameters(url: str) -> Dict[str, List[str]]:
        return parse_qs(urlparse(url).query)

    @staticmethod
    def _build_url_with_param(url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        query_dict = parse_qs(parsed.query)
        query_dict[param] = [value]
        new_query = urlencode(query_dict, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _match_error_signature(self, response_text: str) -> Optional[str]:
        for db_name, pattern in SQL_ERROR_SIGNATURES.items():
            if pattern.search(response_text):
                return db_name
        return None

    def _safe_get(self, http: HTTPClient, url: str, logger: Any) -> Optional[requests.Response]:
        try:
            return http.get(url)  # type: ignore[no-any-return]  # HTTPClient.get is untyped upstream
        except requests.RequestException as exc:
            logger.debug("Request failed for %s: %s", url, exc)
            return None

    def _get_detecting_retry_exhaustion(
        self, http: HTTPClient, url: str, logger: Any
    ) -> Tuple[Optional[requests.Response], bool]:
        """
        Like _safe_get, but distinguishes two very different failure modes:

        - An ordinary failed request (DNS, timeout, connection refused) -> (None, False)
        - HTTPClient's Retry adapter exhausting retries on a persistent 5xx
          (status_forcelist=[500, 502, 503, 504], raise_on_status=True) -> (None, True)

        The second case matters a lot for error-based SQLi detection: a payload
        that reliably triggers a 500 IS the signal we're looking for, but the
        shared HTTPClient's retry policy converts that 500 into a raised
        RetryError before we ever see the status code. Treating retry
        exhaustion itself as evidence recovers that signal without needing to
        change the shared retry policy in utils/http_client.py.
        """
        try:
            return http.get(url), False
        except requests.exceptions.RetryError as exc:
            logger.debug("Retries exhausted for %s (likely persistent 5xx): %s", url, exc)
            return None, True
        except requests.RequestException as exc:
            logger.debug("Request failed for %s: %s", url, exc)
            return None, False

    def _safe_timed_get(
        self, http: HTTPClient, url: str, logger: Any
    ) -> Tuple[Optional[requests.Response], float]:
        start = time.time()
        try:
            response = http.get(url)
            return response, time.time() - start
        except requests.RequestException as exc:
            logger.debug("Timed request failed for %s: %s", url, exc)
            return None, time.time() - start

    # ------------------------------------------------------------------ #
    # Detection tiers
    # ------------------------------------------------------------------ #
    def _error_based_test(
        self, http: HTTPClient, url: str, param: str, logger: Any, baseline_status: int
    ) -> Optional[Finding]:
        for payload in self._error_payloads:
            test_url = self._build_url_with_param(url, param, payload)
            response, retry_exhausted = self._get_detecting_retry_exhaustion(http, test_url, logger)

            if retry_exhausted:
                # HTTPClient retried a persistent 5xx (500/502/503/504) three
                # times and gave up rather than returning it - that persistence
                # itself is strong evidence this payload broke a server-side
                # query, even though we never got to see the actual status text.
                return Finding(
                    module=self.name,
                    category="sql-injection",
                    title=f"Error-based SQL injection in parameter '{param}' (persistent server error)",
                    description=(
                        f"Injecting a syntax-breaking payload into '{param}' caused the "
                        "server to persistently return a 5xx error across multiple retries, "
                        "indicating the payload broke a server-side query. The shared "
                        "HTTPClient's retry policy retried this away rather than returning "
                        "it, so no response body/status could be inspected directly."
                    ),
                    severity=Severity.HIGH,
                    evidence={
                        "technique": "error-based",
                        "parameter": param,
                        "payload": payload,
                        "database_fingerprint": "Unknown (persistent 5xx, retried away by HTTPClient)",
                        "url": test_url,
                    },
                    remediation="Use parameterized queries or an ORM instead of building SQL from raw input.",
                    confidence=0.65,
                )

            if response is None:
                continue

            db_match = self._match_error_signature(response.text)
            if db_match:
                return Finding(
                    module=self.name,
                    category="sql-injection",
                    title=f"Error-based SQL injection in parameter '{param}'",
                    description=(
                        f"Injecting a syntax-breaking payload into '{param}' surfaced a "
                        f"{db_match} database error, indicating the parameter reaches a "
                        "SQL query without proper sanitization."
                    ),
                    severity=Severity.HIGH,
                    evidence={
                        "technique": "error-based",
                        "parameter": param,
                        "payload": payload,
                        "database_fingerprint": db_match,
                        "url": test_url,
                    },
                    remediation="Use parameterized queries or an ORM instead of building SQL from raw input.",
                    confidence=0.95,
                )

            # Fallback signal: many modern apps catch the DB exception and render
            # a generic error page with no vendor-specific text at all (e.g. a
            # bare "Internal Server Error"). A baseline-200 -> payload-5xx flip is
            # itself strong evidence the payload broke a server-side query, even
            # with zero leaked error text to fingerprint against.
            #
            # EXCLUDED: 520-527 are Cloudflare-specific edge/CDN codes (e.g. 525 =
            # SSL handshake failed between Cloudflare and the origin). These mean
            # something went wrong at the network/proxy layer, not inside the
            # application's SQL query - a raw quote in a URL can trip WAF/edge
            # behavior with nothing to do with the database. Counting these would
            # produce false positives on any Cloudflare-fronted site.
            if (
                baseline_status < 500
                and response.status_code >= 500
                and response.status_code not in CLOUDFLARE_EDGE_CODES
            ):
                return Finding(
                    module=self.name,
                    category="sql-injection",
                    title=f"Error-based SQL injection in parameter '{param}' (generic error page)",
                    description=(
                        f"Injecting a syntax-breaking payload into '{param}' changed the "
                        f"response from HTTP {baseline_status} to HTTP {response.status_code}. "
                        "No vendor-specific database error text was found in the response, "
                        "but the status code change itself indicates the payload broke a "
                        "server-side query - the application appears to catch the exception "
                        "and render a generic error page rather than leaking DB details."
                    ),
                    severity=Severity.HIGH,
                    evidence={
                        "technique": "error-based",
                        "parameter": param,
                        "payload": payload,
                        "database_fingerprint": "Unknown (generic error page, no leaked signature)",
                        "baseline_status": baseline_status,
                        "response_status": response.status_code,
                        "url": test_url,
                    },
                    remediation="Use parameterized queries or an ORM instead of building SQL from raw input.",
                    confidence=0.75,
                )
        return None

    def _boolean_based_test(
        self, http: HTTPClient, url: str, param: str, logger: Any
    ) -> Optional[Finding]:
        import difflib

        for true_payload, false_payload in zip(self._true_payloads, self._false_payloads):
            true_url = self._build_url_with_param(url, param, true_payload)
            false_url = self._build_url_with_param(url, param, false_payload)

            true_resp = self._safe_get(http, true_url, logger)
            false_resp = self._safe_get(http, false_url, logger)
            if true_resp is None or false_resp is None:
                continue
            if true_resp.status_code != 200 or false_resp.status_code != 200:
                continue

            similarity = difflib.SequenceMatcher(None, true_resp.text, false_resp.text).ratio()
            length_delta = abs(len(true_resp.text) - len(false_resp.text))

            if similarity < 0.95 and length_delta > 5:
                return Finding(
                    module=self.name,
                    category="sql-injection",
                    title=f"Boolean-based SQL injection in parameter '{param}'",
                    description=(
                        f"True/false condition payloads in '{param}' produced meaningfully "
                        "different responses, suggesting the parameter influences a SQL "
                        "WHERE clause even though no database error is shown."
                    ),
                    severity=Severity.HIGH,
                    evidence={
                        "technique": "boolean-based",
                        "parameter": param,
                        "true_payload": true_payload,
                        "false_payload": false_payload,
                        "similarity_ratio": round(similarity, 3),
                        "length_delta": length_delta,
                    },
                    remediation="Use parameterized queries or an ORM instead of building SQL from raw input.",
                    confidence=0.8,
                )
        return None

    def _time_based_test(
        self, http: HTTPClient, url: str, param: str, logger: Any
    ) -> Optional[Finding]:
        for time_payload, control_payload in zip(self._time_payloads, self._time_control_payloads):
            control_url = self._build_url_with_param(url, param, control_payload)
            control_resp, control_elapsed = self._safe_timed_get(http, control_url, logger)
            if control_resp is None:
                continue
            if control_elapsed > CONTROL_NOISE_CEILING:
                # Target/network too noisy to trust a timing comparison right now.
                logger.debug("Skipping time-based test on '%s' - control request too slow", param)
                continue

            test_url = self._build_url_with_param(url, param, time_payload)
            test_resp, test_elapsed = self._safe_timed_get(http, test_url, logger)
            if test_resp is None:
                continue

            delay_delta = test_elapsed - control_elapsed
            if delay_delta >= TIME_DELTA_THRESHOLD:
                return Finding(
                    module=self.name,
                    category="sql-injection",
                    title=f"Time-based blind SQL injection in parameter '{param}'",
                    description=(
                        f"A delay payload in '{param}' took {delay_delta:.1f}s longer than "
                        "an identically-shaped zero-delay control payload, suggesting the "
                        "database executed the injected delay function."
                    ),
                    severity=Severity.HIGH,
                    evidence={
                        "technique": "time-based",
                        "parameter": param,
                        "payload": time_payload,
                        "control_payload": control_payload,
                        "control_elapsed_s": round(control_elapsed, 2),
                        "test_elapsed_s": round(test_elapsed, 2),
                        "delay_delta_s": round(delay_delta, 2),
                    },
                    remediation="Use parameterized queries or an ORM instead of building SQL from raw input.",
                    confidence=0.7,
                )
        return None

    # ------------------------------------------------------------------ #
    # Main entry point
    # ------------------------------------------------------------------ #
    def scan(self, context: Context) -> ScanResult:
        target = context.config.target_url
        http = self._get_http(context)
        logger = self._get_logger()

        parameters = self._extract_parameters(target)
        if not parameters:
            logger.info("No query parameters found on %s - nothing to test", target)
            return self._create_result(findings=[], target=target)

        baseline_resp = self._safe_get(http, target, logger)
        baseline_status = baseline_resp.status_code if baseline_resp is not None else 200

        findings: List[Finding] = []

        for param in parameters:
            logger.info("Testing parameter '%s' on %s", param, target)

            hit = self._error_based_test(http, target, param, logger, baseline_status)
            if hit:
                findings.append(hit)
                logger.warning("Confirmed error-based SQLi on '%s'", param)
                continue

            hit = self._boolean_based_test(http, target, param, logger)
            if hit:
                findings.append(hit)
                logger.warning("Confirmed boolean-based SQLi on '%s'", param)
                continue

            hit = self._time_based_test(http, target, param, logger)
            if hit:
                findings.append(hit)
                logger.warning("Confirmed time-based SQLi on '%s'", param)

        return self._create_result(findings=findings, target=target)
