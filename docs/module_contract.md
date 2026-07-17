
# Module Contract

Every scanner module MUST follow this contract.

## Input
- `context: Context` — shared state with target_url, http_client, config

## Output
- `ScanResult` containing module_name, findings, errors, duration_ms, target

## Rules
| Rule | Why |
|------|-----|
| Never print() — use logger | Centralized output |
| Never generate reports | Reports are separate layer |
| Never call other modules | Engine handles orchestration |
| Use context.http_client | Shared config, retries, proxy |
| Catch ALL exceptions | One crash kills nothing |
| Return empty findings if nothing found | "No vuln" is valid result |

## Finding Structure
```python
Finding(
    module="your_module_name",
    category="reflected_xss",
    title="Reflected XSS in login",
    description="Payload reflected without sanitization",
    severity=Severity.HIGH,
    evidence={"payload": "<script>alert(1)</script>", "param": "search"},
    remediation="Sanitize user input, use CSP, encode output",
    confidence=0.9
)
