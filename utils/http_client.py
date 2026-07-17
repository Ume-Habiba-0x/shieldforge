"""ShieldForge — Shared HTTP client."""

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class HTTPClient:
    """Shared HTTP session with retries."""

    def __init__(self, timeout: int = 10, proxy: str = None,
                 user_agent: str = "ShieldForge/1.0",
                 verify_ssl: bool = True):
        self.timeout = timeout
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self.user_agent = user_agent
        self.verify_ssl = verify_ssl

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.user_agent})

        retry = Retry(total=3, backoff_factor=1,
                     status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def get(self, url: str, **kwargs):
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("proxies", self.proxy)
        kwargs.setdefault("verify", self.verify_ssl)
        return self.session.get(url, **kwargs)

    def post(self, url: str, **kwargs):
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("proxies", self.proxy)
        kwargs.setdefault("verify", self.verify_ssl)
        return self.session.post(url, **kwargs)

    def head(self, url: str, **kwargs):
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("proxies", self.proxy)
        kwargs.setdefault("verify", self.verify_ssl)
        return self.session.head(url, **kwargs)
