"""ShieldForge — Information Disclosure Scanner.

Detects exposed sensitive files (version control folders, environment
files, backups, server artifacts) and sensitive paths leaked through
robots.txt.
"""

import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from core.context import Context
from core.models import Finding, Severity, ScanResult
from modules.base import BaseScanner

logger = logging.getLogger(__name__)

# Marker used to probe the server's "not found" behaviour before trusting
# any 200 response. Some servers return HTTP 200 with an HTML error page
# for every path ("soft 404"), which would otherwise cause false positives.
_BASELINE_PATH = "/__shieldforge_baseline_check_8f2c1a__"

_WORDLIST_PATH = Path(__file__).resolve().parent.parent / "config" / "payloads" / "disclosure_payloads.txt"

# Fallback used if the wordlist file is missing/unreadable, and also acts
# as the source of truth for severity/description per path.
_SEVERITY_MAP: Dict[str, Tuple[Severity, str]] = {
    ".git/HEAD": (Severity.CRITICAL, "Exposed .git directory can leak full source history"),
    ".git/config": (Severity.CRITICAL, "Exposed .git config can leak source history and remotes"),
    ".git/index": (Severity.HIGH, "Exposed .git index can leak tracked file contents"),
    ".git/logs/HEAD": (Severity.HIGH, "Exposed .git logs can leak commit history"),
    ".svn/entries": (Severity.HIGH, "Exposed .svn metadata can leak source history"),
    ".hg/store/00manifest.i": (Severity.HIGH, "Exposed Mercurial store can leak source history"),
    ".env": (Severity.CRITICAL, "Exposed .env can leak credentials and API keys"),
    ".env.local": (Severity.CRITICAL, "Exposed .env.local can leak credentials and API keys"),
    ".env.production": (Severity.CRITICAL, "Exposed .env.production can leak production credentials"),
    ".env.backup": (Severity.CRITICAL, "Exposed .env backup can leak credentials"),
    "config.json": (Severity.HIGH, "Exposed config.json may leak internal configuration"),
    "secrets.yml": (Severity.CRITICAL, "Exposed secrets.yml can leak application secrets"),
    "credentials.json": (Severity.CRITICAL, "Exposed credentials.json can leak service credentials"),
    "id_rsa": (Severity.CRITICAL, "Exposed private SSH key allows server/account compromise"),
    "id_rsa.pub": (Severity.LOW, "Exposed public SSH key discloses key material"),
    "backup.zip": (Severity.HIGH, "Exposed backup archive may contain source and data"),
    "backup.sql": (Severity.CRITICAL, "Exposed SQL backup can leak entire database contents"),
    "backup.tar.gz": (Severity.HIGH, "Exposed backup archive may contain source and data"),
    "site.zip": (Severity.HIGH, "Exposed site archive may contain source and data"),
    "www.zip": (Severity.HIGH, "Exposed site archive may contain source and data"),
    "db.sql": (Severity.CRITICAL, "Exposed SQL dump can leak entire database contents"),
    "database.sql": (Severity.CRITICAL, "Exposed SQL dump can leak entire database contents"),
    "dump.sql": (Severity.CRITICAL, "Exposed SQL dump can leak entire database contents"),
    "config.php.bak": (Severity.HIGH, "Exposed config backup may leak credentials in source"),
    "config.old": (Severity.HIGH, "Exposed config backup may leak credentials in source"),
    "index.php.bak": (Severity.MEDIUM, "Exposed source backup may leak application logic"),
    "wp-config.php.bak": (Severity.CRITICAL, "Exposed WordPress config backup can leak DB credentials"),
    "wp-config.php.old": (Severity.CRITICAL, "Exposed WordPress config backup can leak DB credentials"),
    ".DS_Store": (Severity.LOW, "Exposed .DS_Store can leak directory/file structure"),
    "web.config": (Severity.MEDIUM, "Exposed web.config may leak server configuration"),
    ".htaccess": (Severity.MEDIUM, "Exposed .htaccess may leak server rules/configuration"),
    ".htpasswd": (Severity.CRITICAL, "Exposed .htpasswd can leak password hashes"),
    "phpinfo.php": (Severity.MEDIUM, "Exposed phpinfo() leaks detailed server/environment info"),
    "server-status": (Severity.MEDIUM, "Exposed Apache server-status leaks live request info"),
    "composer.lock": (Severity.LOW, "Exposed composer.lock discloses dependency versions"),
    "package-lock.json": (Severity.LOW, "Exposed package-lock.json discloses dependency versions"),
    "Dockerfile": (Severity.LOW, "Exposed Dockerfile discloses build/deploy internals"),
    "docker-compose.yml": (Severity.MEDIUM, "Exposed docker-compose.yml may leak service topology/secrets"),
    "error.log": (Severity.MEDIUM, "Exposed error log may leak paths, stack traces, or queries"),
    "debug.log": (Severity.MEDIUM, "Exposed debug log may leak internal application details"),
    "access.log": (Severity.LOW, "Exposed access log discloses request history"),
}

_DEFAULT_SEVERITY = (Severity.MEDIUM, "Sensitive file appears to be publicly accessible")

# Keywords that make a robots.txt Disallow entry worth flagging.
_ROBOTS_SENSITIVE_HINTS = (
    "admin", "backup", "config", "private", "secret", "internal",
    "db", "sql", ".git", ".env", "credentials", "staging", "dev",
)


class DisclosureScanner(BaseScanner):
    """Detect information disclosure: exposed files and leaked paths."""

    @property
    def name(self) -> str:
        return "disclosure"

    @property
    def description(self) -> str:
        return "Detect exposed sensitive files and information disclosure"

    def scan(self, context: Context) -> ScanResult:
        target = context.config.target_url.rstrip("/")
        findings: List[Finding] = []
        errors: List[str] = []

        try:
            baseline = self._get_baseline(context, target)
        except Exception as e:
            baseline = None
            logger.warning("Disclosure baseline probe failed: %s", e)

        try:
            findings.extend(self._check_robots(context, target))
        except Exception as e:
            errors.append(f"robots.txt check failed: {str(e)}")
            logger.error("Disclosure robots.txt check failed: %s", e)

        try:
            findings.extend(self._check_sensitive_paths(context, target, baseline))
        except Exception as e:
            errors.append(f"Sensitive path check failed: {str(e)}")
            logger.error("Disclosure sensitive path check failed: %s", e)

        return self._create_result(findings=findings, errors=errors, target=target)

    # -- helpers -----------------------------------------------------

    def _get_baseline(self, context: Context, target: str) -> Optional[dict]:
        """Probe a random, near-certainly-nonexistent path to learn how
        the server responds to 'not found' requests (status + body
        length), so real 200s can be told apart from soft-404 pages."""
        response = context.http_client.get(f"{target}{_BASELINE_PATH}")
        return {
            "status": response.status_code,
            "length": len(response.text or ""),
        }

    def _is_soft_404(self, response, baseline: Optional[dict]) -> bool:
        if baseline is None:
            return False
        if response.status_code != baseline["status"]:
            return False
        body_len = len(response.text or "")
        # Treat near-identical body length to the baseline as the same
        # generic error page rather than a distinct, real file.
        return abs(body_len - baseline["length"]) <= 25

    def _load_wordlist(self) -> List[str]:
        try:
            with open(_WORDLIST_PATH, "r") as f:
                paths = [
                    line.strip() for line in f
                    if line.strip() and not line.strip().startswith("#")
                ]
            if paths:
                return paths
        except OSError as e:
            logger.warning("Could not read disclosure wordlist, using defaults: %s", e)

        return list(_SEVERITY_MAP.keys())

    def _check_sensitive_paths(self, context: Context, target: str,
                              baseline: Optional[dict]) -> List[Finding]:
        findings: List[Finding] = []

        for path in self._load_wordlist():
            url = f"{target}/{path}"
            try:
                response = context.http_client.get(url)
            except Exception as e:
                logger.debug("Disclosure check skipped for %s: %s", path, e)
                continue

            if response.status_code != 200:
                continue
            if self._is_soft_404(response, baseline):
                continue

            severity, description = _SEVERITY_MAP.get(path, _DEFAULT_SEVERITY)
            findings.append(Finding(
                module=self.name,
                category="information_disclosure",
                title=f"Exposed file: {path}",
                description=description,
                severity=severity,
                evidence={
                    "path": path,
                    "url": url,
                    "status_code": response.status_code,
                    "content_length": len(response.text or ""),
                },
                remediation="Remove the file from the web root, restrict access, "
                            "or block it at the server/reverse-proxy level.",
                confidence=0.9,
            ))

        return findings

    def _check_robots(self, context: Context, target: str) -> List[Finding]:
        findings: List[Finding] = []
        response = context.http_client.get(f"{target}/robots.txt")

        if response.status_code != 200:
            return findings

        disallowed: List[str] = []
        for line in (response.text or "").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.lower().startswith("disallow:"):
                value = line.split(":", 1)[1].strip()
                if value:
                    disallowed.append(value)

        if not disallowed:
            return findings

        sensitive_hits = [
            path for path in disallowed
            if any(hint in path.lower() for hint in _ROBOTS_SENSITIVE_HINTS)
        ]

        if sensitive_hits:
            findings.append(Finding(
                module=self.name,
                category="information_disclosure",
                title="Sensitive paths disclosed via robots.txt",
                description=(
                    "robots.txt lists disallowed paths that hint at sensitive "
                    f"areas of the application: {', '.join(sensitive_hits)}"
                ),
                severity=Severity.LOW,
                evidence={"disallowed_paths": disallowed, "flagged_paths": sensitive_hits},
                remediation="Do not rely on robots.txt to hide sensitive paths; "
                            "enforce authentication/authorization instead.",
                confidence=0.7,
            ))

        return findings
