"""ShieldForge -- Authentication Assessment Scanner.

Covers the Module 2 checklist from the task brief and GitHub issue #3:
  - login form discovery
  - username enumeration (response-difference based)
  - session cookie flag analysis (Secure / HttpOnly / SameSite)
  - password policy indicators (client-side rules + on-page policy text)

This module only ever sends two extra requests per discovered login form
(one with a common username, one with a made-up probe username) using a
fixed, clearly-fake password. It never brute-forces or guesses real
credentials -- it only compares how the app responds.
"""

import logging
import re
from typing import List, Optional
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from core.context import Context
from core.models import Finding, Severity, ScanResult
from modules.base import BaseScanner

logger = logging.getLogger(__name__)

POLICY_HINT_RE = re.compile(
    r"(password must|at least\s*\d+\s*character|minimum\s*\d+\s*character|"
    r"must contain|must include|password.{0,25}(upper|lower|digit|number|special))",
    re.IGNORECASE,
)

# Fixed, obviously-fake probe values used only to diff two responses.
# Never a guessed or real credential, and only one extra request pair
# per login form (no brute forcing, no wordlists).
COMMON_USERNAME = "admin"
PROBE_USERNAME = "sf_probe_x7f21c9"
PROBE_PASSWORD = "Sf!Probe_9182x"


class AuthScanner(BaseScanner):
    """Assess authentication mechanisms on the target page."""

    @property
    def name(self) -> str:
        return "auth"

    @property
    def description(self) -> str:
        return "Assess authentication mechanisms (login forms, enumeration, cookies, policy)"

    def scan(self, context: Context) -> ScanResult:
        target = context.config.target_url
        findings: List[Finding] = []
        errors: List[str] = []

        try:
            response = context.http_client.get(target)
        except Exception as e:
            errors.append(f"Failed to fetch target: {e}")
            logger.error("Auth scan failed to fetch target: %s", e)
            return self._create_result(findings=findings, errors=errors, target=target)

        findings.extend(self._check_session_cookies(response))

        login_forms = self._discover_login_forms(response.text, target)

        if not login_forms:
            findings.append(Finding(
                module=self.name,
                category="info",
                title="No login form detected",
                description="No <form> containing a password field was found on the target page.",
                severity=Severity.INFO,
                evidence={"target": target},
                remediation="If the login page lives elsewhere, re-run with --target pointed at it directly.",
                confidence=0.6,
            ))
            return self._create_result(findings=findings, errors=errors, target=target)

        for form in login_forms:
            findings.extend(self._check_password_policy(form, response.text))

            try:
                enum_finding = self._test_username_enumeration(context, form)
                if enum_finding:
                    findings.append(enum_finding)
            except Exception as e:
                errors.append(f"Enumeration probe failed for {form['action_url']}: {e}")
                logger.warning("Enumeration probe failed: %s", e)

        return self._create_result(findings=findings, errors=errors, target=target)

    # ---------- discovery ----------

    def _discover_login_forms(self, html: str, target: str) -> List[dict]:
        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception as e:
            logger.warning("HTML parsing failed for %s: %s", target, e)
            return []

        login_forms = []
        for form_tag in soup.find_all("form"):
            inputs = form_tag.find_all("input")
            has_password = any((i.get("type") or "text").lower() == "password" for i in inputs)
            if not has_password:
                continue

            action = form_tag.get("action") or target
            login_forms.append({
                "action": action,
                "action_url": urljoin(target, action),
                "method": (form_tag.get("method") or "get").lower(),
                "inputs": inputs,
            })
        return login_forms

    # ---------- checks ----------

    def _check_password_policy(self, form: dict, html: str) -> List[Finding]:
        password_inputs = [i for i in form["inputs"] if (i.get("type") or "").lower() == "password"]
        has_client_side_rule = any(i.get("minlength") or i.get("pattern") for i in password_inputs)
        has_text_hint = bool(POLICY_HINT_RE.search(html))

        if has_client_side_rule or has_text_hint:
            return []

        return [Finding(
            module=self.name,
            category="weak_password_policy",
            title="No password policy indicators found",
            description=(
                "The login form has no client-side length/pattern constraints on its "
                "password field, and no policy text was found on the page. This isn't "
                "proof the server accepts weak passwords, but it's worth confirming manually."
            ),
            severity=Severity.MEDIUM,
            evidence={"action_url": form["action_url"]},
            remediation="Enforce and document a minimum password policy (length + complexity) server-side.",
            confidence=0.5,
        )]

    def _test_username_enumeration(self, context: Context, form: dict) -> Optional[Finding]:
        user_field = self._first_field_name(form["inputs"], ("text", "email"))
        pass_field = self._first_field_name(form["inputs"], ("password",))

        if not user_field or not pass_field:
            return None

        resp_common = self._submit(context, form, user_field, COMMON_USERNAME, pass_field, PROBE_PASSWORD)
        resp_probe = self._submit(context, form, user_field, PROBE_USERNAME, pass_field, PROBE_PASSWORD)

        status_differs = resp_common.status_code != resp_probe.status_code
        length_differs = abs(len(resp_common.text) - len(resp_probe.text)) > 20

        if not (status_differs or length_differs):
            return None

        return Finding(
            module=self.name,
            category="username_enumeration",
            title="Possible username enumeration",
            description=(
                "The login response differs between a common username ('admin') and a "
                "nonexistent probe username submitted with the same password. That "
                "difference can let an attacker enumerate valid accounts before "
                "attempting to guess passwords."
            ),
            severity=Severity.HIGH,
            evidence={
                "action_url": form["action_url"],
                "status_common_username": resp_common.status_code,
                "status_probe_username": resp_probe.status_code,
                "response_length_common": len(resp_common.text),
                "response_length_probe": len(resp_probe.text),
            },
            remediation="Return an identical, generic error for both unknown usernames and wrong passwords.",
            confidence=0.6,
        )

    def _check_session_cookies(self, response) -> List[Finding]:
        findings = []
        for cookie in getattr(response, "cookies", []) or []:
            rest = getattr(cookie, "_rest", {}) or {}
            rest_keys_upper = {str(k).upper() for k in rest.keys()}

            missing = []
            if not getattr(cookie, "secure", False):
                missing.append("Secure")
            if "HTTPONLY" not in rest_keys_upper:
                missing.append("HttpOnly")
            if "SAMESITE" not in rest_keys_upper:
                missing.append("SameSite")

            if missing:
                findings.append(Finding(
                    module=self.name,
                    category="session_cookie",
                    title=f"Cookie '{cookie.name}' missing {', '.join(missing)}",
                    description=f"The '{cookie.name}' cookie is missing recommended flag(s): {', '.join(missing)}.",
                    severity=Severity.MEDIUM if ("Secure" in missing or "HttpOnly" in missing) else Severity.LOW,
                    evidence={"cookie": cookie.name, "missing_flags": missing},
                    remediation="Set Secure, HttpOnly, and SameSite=Strict (or Lax) on session cookies.",
                    confidence=0.9,
                ))
        return findings

    # ---------- helpers ----------

    @staticmethod
    def _first_field_name(inputs, types) -> Optional[str]:
        for i in inputs:
            input_type = (i.get("type") or "text").lower()
            name = i.get("name")
            if input_type in types and name:
                return name
        return None

    @staticmethod
    def _submit(context: Context, form: dict, user_field: str, user_value: str,
                pass_field: str, pass_value: str):
        data = {user_field: user_value, pass_field: pass_value}
        if form["method"] == "post":
            return context.http_client.post(form["action_url"], data=data)
        return context.http_client.get(form["action_url"], params=data)
