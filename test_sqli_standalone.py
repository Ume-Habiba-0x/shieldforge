#!/usr/bin/env python3
"""
test_sqli_standalone.py

Run only the SQLi scanner directly, bypassing framework.py's Engine,
module discovery, and report generation entirely. Useful for fast
iteration while developing/debugging modules/sqli.py.

Usage:
    python3 test_sqli_standalone.py --target "http://host/page?id=1"
    python3 test_sqli_standalone.py --target "https://host/filter?category=Accessories" --timeout 15
"""

from __future__ import annotations

import argparse
import json
import sys

from core.context import Config, Context
from modules.sqli import SQLiScanner
from utils.http_client import HTTPClient


def main() -> int:
    parser = argparse.ArgumentParser(description="Standalone SQLiScanner test (no Engine required)")
    parser.add_argument("--target", required=True, help="Full target URL including query string")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--proxy", default=None, help="e.g. http://127.0.0.1:8080 to route through Burp")
    args = parser.parse_args()

    config = Config(target_url=args.target, timeout=args.timeout, proxy=args.proxy)
    context = Context(config=config)
    context.http_client = HTTPClient(timeout=args.timeout, proxy=args.proxy)

    scanner = SQLiScanner()

    # Debug line first - if any of these are 0, that's the whole story right
    # there and no amount of target-hunting will find anything.
    print(
        f"[debug] payload counts -> error={len(scanner._error_payloads)} "
        f"true={len(scanner._true_payloads)} false={len(scanner._false_payloads)} "
        f"time={len(scanner._time_payloads)} time_control={len(scanner._time_control_payloads)}\n"
    )

    result = scanner.run(context)

    print(f"Target:   {args.target}")
    print(f"Duration: {result.duration_ms}ms")
    print(f"Errors:   {result.errors}")
    print(f"Findings: {len(result.findings)}\n")

    for finding in result.findings:
        print(json.dumps(finding.to_dict(), indent=2))

    return 0


if __name__ == "__main__":
    sys.exit(main())
