import ipaddress
import re
from typing import Optional
from urllib.parse import ParseResult, parse_qs, urlparse, urlunparse

from utils.logger import get_logger

logger = get_logger("shieldforge.validators")

ALLOWED_SCHEMES = {"http", "https"}

BLOCKED_HOSTS = {
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    "169.254.169.254",
    "metadata.google.internal",
}

MAX_URL_LENGTH = 2048

_DOMAIN_LABEL_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
)


def validate_url(url: str) -> Optional[str]:
    """Validate and normalise a URL string.

    Checks scheme, hostname, blocked hosts and private IPs.
    Adds http:// if no scheme is present.

    Args:
        url: Raw URL string.

    Returns:
        Normalised URL on success, None on failure.
    """
    if not url or not isinstance(url, str):
        logger.warning("validate_url: received empty or non-string input")
        return None

    url = url.strip()

    if len(url) > MAX_URL_LENGTH:
        logger.warning(
            "validate_url: URL exceeds %d characters", MAX_URL_LENGTH
        )
        return None

    if "://" in url:
        scheme = url.split("://")[0].lower()
        if scheme not in ALLOWED_SCHEMES:
            logger.warning(
                "validate_url: scheme '%s' is not allowed (use http or https)",
                scheme,
            )
            return None
        url = scheme + "://" + url.split("://", 1)[1]
    else:
        url = "http://" + url

    try:
        parsed = urlparse(url)
    except Exception as exc:
        logger.warning("validate_url: failed to parse URL: %s", exc)
        return None

    host = parsed.hostname or ""
    if not host:
        logger.warning("validate_url: no hostname found in '%s'", url)
        return None

    if "." not in host:
        logger.warning(
            "validate_url: host '%s' has no dot — not a valid domain", host
        )
        return None

    if host.lower() in BLOCKED_HOSTS:
        logger.warning(
            "validate_url: host '%s' is in the blocked list", host
        )
        return None

    if _is_private_ip(host):
        logger.warning(
            "validate_url: host '%s' is a private IP", host
        )
        return None

    return _normalise(parsed)


def is_valid_url(url: str) -> bool:
    """Return True if url passes validate_url().

    Args:
        url: Raw URL string.

    Returns:
        bool
    """
    return validate_url(url) is not None


def sanitize_url(url: str) -> str:
    """Remove query string and fragment from a URL.

    Args:
        url: Any URL string.

    Returns:
        URL without query or fragment.
    """
    try:
        parsed = urlparse(url)
        return urlunparse(ParseResult(
            scheme=parsed.scheme,
            netloc=parsed.netloc,
            path=parsed.path,
            params="",
            query="",
            fragment="",
        ))
    except Exception:
        return url


def extract_base_url(url: str) -> str:
    """Return scheme and host only, no path or query.

    Args:
        url: Any URL string.

    Returns:
        Base URL string e.g. https://example.com.
    """
    try:
        parsed = urlparse(url)
        return urlunparse(ParseResult(
            scheme=parsed.scheme,
            netloc=parsed.netloc,
            path="",
            params="",
            query="",
            fragment="",
        ))
    except Exception:
        return url


def is_same_origin(url_a: str, url_b: str) -> bool:
    """Return True if both URLs share scheme, host and port.

    Args:
        url_a: First URL.
        url_b: Second URL.

    Returns:
        bool
    """
    try:
        a = urlparse(url_a)
        b = urlparse(url_b)
        return (
            a.scheme.lower() == b.scheme.lower()
            and (a.hostname or "").lower() == (b.hostname or "").lower()
            and _effective_port(a) == _effective_port(b)
        )
    except Exception:
        return False


def extract_domain(url: str) -> str:
    """Return the hostname from a URL.

    Args:
        url: Any URL string.

    Returns:
        Hostname string or empty string.
    """
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def build_url(base: str, path: str) -> str:
    """Join a base URL and a path segment safely.

    Args:
        base: Base URL e.g. https://example.com.
        path: Path to append e.g. /robots.txt.

    Returns:
        Joined URL string.
    """
    base = base.rstrip("/")
    path = path if path.startswith("/") else "/" + path
    return base + path


def is_valid_domain(domain: str) -> bool:
    """Return True if domain looks like a valid hostname.

    Args:
        domain: Hostname without scheme or path.

    Returns:
        bool
    """
    if not domain or len(domain) > 253:
        return False
    domain = domain.rstrip(".")
    labels = domain.split(".")
    if len(labels) < 2:
        return False
    return all(_DOMAIN_LABEL_RE.match(label) for label in labels)


def has_query_params(url: str) -> bool:
    """Return True if the URL has a non-empty query string.

    Args:
        url: Any URL string.

    Returns:
        bool
    """
    try:
        return bool(urlparse(url).query)
    except Exception:
        return False


def extract_query_params(url: str) -> dict:
    """Parse query string into a dict.

    Args:
        url: Any URL string.

    Returns:
        Dict of parameter name to value.
    """
    try:
        raw    = urlparse(url).query
        parsed = parse_qs(raw, keep_blank_values=True)
        return {k: v[-1] for k, v in parsed.items()}
    except Exception:
        return {}


def _is_private_ip(host: str) -> bool:
    try:
        addr = ipaddress.ip_address(host)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def _effective_port(parsed: ParseResult) -> int:
    if parsed.port:
        return parsed.port
    return 443 if parsed.scheme == "https" else 80


def _normalise(parsed: ParseResult) -> str:
    normalised = ParseResult(
        scheme=parsed.scheme.lower(),
        netloc=parsed.netloc.lower(),
        path=parsed.path,
        params=parsed.params,
        query=parsed.query,
        fragment=parsed.fragment,
    )
    url = urlunparse(normalised)
    if url.endswith("/") and normalised.path == "/":
        url = url[:-1]
    return url