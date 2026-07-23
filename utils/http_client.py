import logging
import time
from typing import Optional
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from requests.exceptions import (
    ConnectionError,
    ProxyError,
    ReadTimeout,
    SSLError,
    TooManyRedirects,
)
from urllib3.util.retry import Retry

from utils.logger import setup_logger

logger = setup_logger("shieldforge.http")

MAX_RESPONSE_BYTES         = 10 * 1024 * 1024
RETRY_BACKOFF              = 1
DEFAULT_RETRY_TOTAL        = 3
DEFAULT_RETRY_STATUS_CODES = [429, 500, 502, 503, 504]


class HTTPClientError(Exception):
    """Raised when the HTTP client encounters a non-recoverable error."""


class HTTPClient:
    """Shared HTTP session for all scanner modules."""

    def __init__(
        self,
        timeout: int = 10,
        proxy: Optional[str] = None,
        user_agent: str = "ShieldForge/1.0",
        verify_ssl: bool = True,
        cookies: Optional[dict] = None,
        extra_headers: Optional[dict] = None,
        max_retries: int = DEFAULT_RETRY_TOTAL,
    ):
        """Initialise the shared HTTP session.

        Args:
            timeout:       Seconds to wait for a response.
            proxy:         Proxy URL e.g. http://127.0.0.1:8080.
            user_agent:    User-Agent header value.
            verify_ssl:    Whether to verify SSL certificates.
            cookies:       Cookies to attach to every request.
            extra_headers: Additional headers for every request.
            max_retries:   Retry attempts on transient failures.
        """
        self.timeout    = timeout
        self.verify_ssl = verify_ssl
        self.user_agent = user_agent
        self._proxies   = self._build_proxy_dict(proxy)
        self.session    = requests.Session()

        self.session.headers.update({
            "User-Agent":      self.user_agent,
            "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection":      "keep-alive",
        })

        if extra_headers:
            self.session.headers.update(extra_headers)

        if cookies:
            self.session.cookies.update(cookies)

        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=RETRY_BACKOFF,
            status_forcelist=DEFAULT_RETRY_STATUS_CODES,
            allowed_methods=["GET", "HEAD", "POST", "OPTIONS"],
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://",  adapter)
        self.session.mount("https://", adapter)

    def get(
        self,
        url: str,
        params: Optional[dict] = None,
        allow_redirects: bool = True,
        **kwargs,
    ) -> requests.Response:
        """Send an HTTP GET request.

        Args:
            url:             Target URL.
            params:          Query string parameters.
            allow_redirects: Follow redirects.

        Returns:
            requests.Response

        Raises:
            HTTPClientError: On any network failure.
        """
        return self._request(
            "GET", url,
            params=params,
            allow_redirects=allow_redirects,
            **kwargs,
        )

    def post(
        self,
        url: str,
        data: Optional[dict] = None,
        json: Optional[dict] = None,
        allow_redirects: bool = True,
        **kwargs,
    ) -> requests.Response:
        """Send an HTTP POST request.

        Args:
            url:             Target URL.
            data:            Form-encoded body.
            json:            JSON body.
            allow_redirects: Follow redirects.

        Returns:
            requests.Response

        Raises:
            HTTPClientError: On any network failure.
        """
        return self._request(
            "POST", url,
            data=data,
            json=json,
            allow_redirects=allow_redirects,
            **kwargs,
        )

    def head(
        self,
        url: str,
        allow_redirects: bool = True,
        **kwargs,
    ) -> requests.Response:
        """Send an HTTP HEAD request.

        Args:
            url:             Target URL.
            allow_redirects: Follow redirects.

        Returns:
            requests.Response

        Raises:
            HTTPClientError: On any network failure.
        """
        return self._request(
            "HEAD", url,
            allow_redirects=allow_redirects,
            **kwargs,
        )

    def options(self, url: str, **kwargs) -> requests.Response:
        """Send an HTTP OPTIONS request.

        Args:
            url: Target URL.

        Returns:
            requests.Response

        Raises:
            HTTPClientError: On any network failure.
        """
        return self._request("OPTIONS", url, **kwargs)

    def set_cookies(self, cookies: dict) -> None:
        """Update session cookies.

        Args:
            cookies: Cookie name to value mapping.
        """
        self.session.cookies.update(cookies)

    def set_headers(self, headers: dict) -> None:
        """Merge additional headers into the session.

        Args:
            headers: Header name to value mapping.
        """
        self.session.headers.update(headers)

    def get_cookies(self) -> dict:
        """Return current session cookies as a plain dict.

        Returns:
            Dict of cookie name to value.
        """
        return dict(self.session.cookies)

    def _request(self, method: str, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout",  self.timeout)
        kwargs.setdefault("proxies",  self._proxies)
        kwargs.setdefault("verify",   self.verify_ssl)

        start = time.monotonic()

        try:
            response   = self.session.request(method, url, **kwargs)
            elapsed_ms = int((time.monotonic() - start) * 1000)

            content_length = int(
                response.headers.get("Content-Length", 0) or 0
            )
            if content_length > MAX_RESPONSE_BYTES:
                logger.warning(
                    "Response from %s is very large (%d bytes)",
                    url,
                    content_length,
                )

            logger.debug(
                "%s %s → %d (%d ms)",
                method, url, response.status_code, elapsed_ms,
            )
            return response

        except ReadTimeout:
            msg = f"Request timed out after {self.timeout}s: {url}"
            logger.warning(msg)
            raise HTTPClientError(msg) from None

        except SSLError as exc:
            msg = f"SSL/TLS error for {url}: {exc}"
            logger.warning(msg)
            raise HTTPClientError(msg) from exc

        except ProxyError as exc:
            msg = f"Proxy error for {url}: {exc}"
            logger.warning(msg)
            raise HTTPClientError(msg) from exc

        except TooManyRedirects as exc:
            msg = f"Too many redirects for {url}: {exc}"
            logger.warning(msg)
            raise HTTPClientError(msg) from exc

        except ConnectionError as exc:
            msg = f"Connection failed for {url}: {exc}"
            logger.warning(msg)
            raise HTTPClientError(msg) from exc

        except Exception as exc:
            msg = f"Unexpected error for {url}: {exc}"
            logger.error(msg)
            raise HTTPClientError(msg) from exc

    @staticmethod
    def _build_proxy_dict(proxy: Optional[str]) -> Optional[dict]:
        if not proxy:
            return None
        parsed = urlparse(proxy)
        if parsed.scheme not in ("http", "https", "socks5", "socks4"):
            logger.warning(
                "Proxy scheme '%s' may not be supported.", parsed.scheme
            )
        return {"http": proxy, "https": proxy}