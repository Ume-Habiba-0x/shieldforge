"""ShieldForge — XSS Scanner."""
import os
import logging
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup

from modules.base import BaseScanner
from core.models import Finding, Severity

logger = logging.getLogger(__name__)

class XSSScanner(BaseScanner):
    """Scanner module to detect Reflected Cross-Site Scripting (XSS) vulnerabilities."""

    @property
    def name(self) -> str:
        return "xss"

    @property
    def description(self) -> str:
        return "Scans HTML forms and URL parameters for raw reflection of payload values."

    def _load_payloads(self) -> list[str]:
        """Loads XSS payloads from the project's config directory securely."""
        payload_path = os.path.join("config", "payloads", "xss_payloads.txt")
        payloads = []
        
        if not os.path.exists(payload_path):
            logger.error(f"Payload file missing at {payload_path}. Proceeding with an empty list.")
            return payloads

        try:
            with open(payload_path, "r", encoding="utf-8") as f:
                for line in f:
                    cleaned = line.strip()
                    if cleaned and not cleaned.startswith("#"):
                        payloads.append(cleaned)
        except Exception as e:
            logger.error(f"Failed to read payload file {payload_path}: {e}")
            
        return payloads

    def scan(self, context) -> "ScanResult":
        """Main entry point invoked by core/engine.py."""
        target = context.config.target_url


        findings: list[Finding] = []
        errors: list[str] = []

        logger.info(f"Starting XSS scan against target: {target}")
        payloads = self._load_payloads()
        
        if not payloads:
            logger.warning("No XSS payloads loaded. Scan will yield no dynamic injection results.")
            return self._create_result(findings=findings, errors=errors, target=target)

        # 1. Fetch the initial page to extract forms
        try:
            response = context.http_client.get(target)
            if response and response.text:
                soup = BeautifulSoup(response.text, "lxml")
                forms = soup.find_all("form")
                
                # Process discovered HTML Forms
                for index, form in enumerate(forms, 1):
                    try:
                        self._scan_form(form, target, payloads, context, findings)
                    except Exception as e:
                        err_msg = f"Error scanning form #{index} on {target}: {e}"
                        logger.error(err_msg, exc_info=True)
                        errors.append(err_msg)
        except Exception as e:
            err_msg = f"Failed to fetch base URL {target} for form extraction: {e}"
            logger.error(err_msg, exc_info=True)
            errors.append(err_msg)

        # 2. Process query-string parameters from the target URL independently
        try:
            self._scan_url_parameters(target, payloads, context, findings)
        except Exception as e:
            err_msg = f"Error scanning URL parameters for {target}: {e}"
            logger.error(err_msg, exc_info=True)
            errors.append(err_msg)

        return self._create_result(
            findings=findings,
            errors=errors,
            target=target
        )

    def _scan_form(self, form, base_url: str, payloads: list[str], context, findings: list[Finding]) -> None:
        """Parses a specific HTML form structure and acts as the mutation injection engine."""
        action = form.attrs.get("action", "")
        method = form.attrs.get("method", "get").lower()
        target_url = urljoin(base_url, action)

        # Map out candidates within the form element tree
        input_names = []
        form_data = {}
        
        for input_tag in form.find_all(["input", "textarea"]):
            input_name = input_tag.attrs.get("name")
            if not input_name:
                continue
                
            input_type = input_tag.attrs.get("type", "text").lower()
            if input_type in ["text", "search", "textarea", "password", "email"]:
                input_names.append(input_name)
            else:
                # Retain defaults for hidden, submit, or structured keys
                form_data[input_name] = input_tag.attrs.get("value", "test")

        # Test payloads on candidates sequentially
        for field_name in input_names:
            for payload in payloads:
                current_payload_data = form_data.copy()
                current_payload_data[field_name] = payload

                try:
                    if method == "post":
                        resp = context.http_client.post(target_url, data=current_payload_data)
                    else:
                        resp = context.http_client.get(target_url, params=current_payload_data)

                    if resp and payload in resp.text:
                        findings.append(Finding(
                            module="xss",
                            category="Reflected Cross-Site Scripting (XSS)",
                            title=f"Reflected XSS via Form Input Parameter '{field_name}'",
                            description=f"The application reflects raw inputs provided through the form field '{field_name}' inside the endpoint context without proper contextual encoding.",
                            severity=Severity.HIGH,
                            evidence=f"Endpoint: {target_url} | Parameter: {field_name} | Payload: {payload}",
                            remediation="Implement strict context-aware HTML entity output encoding alongside strict server-side alphanumeric input parameter validation filters.",
                            confidence="High"
                        ))
                        break # Break payload loop for this field to prevent log flood if vulnerable
                except Exception as e:
                    logger.error(f"Network error during mutation check on form field '{field_name}': {e}")
                    raise

    def _scan_url_parameters(self, url: str, payloads: list[str], context, findings: list[Finding]) -> None:
        """Parses and checks native key-value attributes appended directly to the base URL string."""
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        
        if not params:
            return

        base_endpoint = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"

        for param_name in params.keys():
            for payload in payloads:
                # Re-construct parameters, swapping only the active target candidate with our test vector
                current_params = {k: v[0] for k, v in params.items()}
                current_params[param_name] = payload

                try:
                    resp = context.http_client.get(base_endpoint, params=current_params)
                    if resp and payload in resp.text:
                        findings.append(Finding(
                            module="xss",
                            category="Reflected Cross-Site Scripting (XSS)",
                            title=f"Reflected XSS via URL Parameter '{param_name}'",
                            description=f"The application dynamically outputs the HTTP request query parameter '{param_name}' directly into the DOM tree without prior cleansing routines.",
                            severity=Severity.HIGH,
                            evidence=f"Endpoint: {base_endpoint} | Parameter: {param_name} | Payload: {payload}",
                            remediation="Ensure all browser-bound variables pass through context-specific escaping filters (such as htmlspecialchars structures or strict framework template engines).",
                            confidence="High"
                        ))
                        break
                except Exception as e:
                    logger.error(f"Network error during mutation check on URL param '{param_name}': {e}")
                    raise
