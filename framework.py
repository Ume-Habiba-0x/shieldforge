#!/usr/bin/env python3
"""ShieldForge — Security Testing Framework
    Forging Secure Applications
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from core.context import Config
from core.engine import Engine
from reports.html_generator import HTMLReport
from reports.json_generator import JSONReport
from utils.logger import setup_logger

logger = setup_logger()

BANNER = r"""
    +============================================+
    |                                            |
    |       S H I E L D F O R G E                |
    |                                            |
    |       Security Testing Framework           |
    |                                            |
    |       Forging Secure Applications          |
    |                                            |
    |            Version 1.0.0                     |
    |                                            |
    +============================================+
"""


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="ShieldForge — Security Testing Framework"
    )
    parser.add_argument("--target", required=True, help="Target URL to scan")
    parser.add_argument("--module", default="all",
                       help="Comma-separated modules (default: all)")
    parser.add_argument("--output", choices=["text", "html", "json"],
                       default="text", help="Output format")
    parser.add_argument("--timeout", type=int, default=30,
                       help="Request timeout in seconds (default: 30)")
    parser.add_argument("--proxy", help="Proxy URL")
    parser.add_argument("--user-agent", default="ShieldForge/1.0",
                       help="Custom User-Agent")

    args = parser.parse_args()

    config = Config(
        target_url=args.target,
        timeout=args.timeout,
        proxy=args.proxy,
        user_agent=args.user_agent,
        output_format=args.output
    )

    if args.module == "all":
        module_names = None
    else:
        module_names = [m.strip() for m in args.module.split(",")]

    engine = Engine(config)
    engine.load_scanners(module_names)
    context = engine.run()

    if args.output == "html":
        report = HTMLReport().generate(context)
        output_file = "shieldforge_report.html"
    elif args.output == "json":
        report = JSONReport().generate(context)
        output_file = "shieldforge_report.json"
    else:
        report = generate_text_report(context)
        output_file = None

    if output_file:
        with open(output_file, "w") as f:
            f.write(report)
        print(f"\n[+] Report saved: {output_file}")
    else:
        print(report)

    summary = context.get_summary()
    print(f"\n[+] Scan complete: {summary['total_findings']} findings")
    print(f"[+] Severity breakdown: {summary['severity_breakdown']}")


def generate_text_report(context):
    """Clean ASCII terminal report."""
    R = "\033[91m"      # Red
    Y = "\033[93m"      # Yellow  
    G = "\033[92m"      # Green
    B = "\033[94m"      # Blue
    C = "\033[96m"      # Cyan
    W = "\033[97m"      # White
    DIM = "\033[90m"    # Gray
    RESET = "\033[0m"
    BOLD = "\033[1m"

    lines = [
        f"{C}+{'='*58}+{RESET}",
        f"{C}|{RESET}{' '*14}{BOLD}S H I E L D F O R G E{RESET}{' '*23}{C}|{RESET}",
        f"{C}|{RESET}{' '*16}{DIM}Security Testing Framework{RESET}{' '*18}{C}|{RESET}",
        f"{C}+{'='*58}+{RESET}",
        f"{C}|{RESET}  {BOLD}Target:{RESET} {W}{context.config.target_url}{RESET}{' '*30}{C}|{RESET}",
        f"{C}+{'='*58}+{RESET}",
        ""
    ]

    for result in context.scan_results:
        lines.append(f"{B}+-- {result.module_name.upper()} {'-'*50}{RESET}")
        
        if result.errors:
            lines.append(f"{R}|  [!] Errors: {', '.join(result.errors)}{RESET}")
        
        if not result.findings:
            lines.append(f"{G}|  [OK] No findings{RESET}")
        
        for f in result.findings:
            if f.severity.value in ["CRITICAL", "HIGH"]:
                color = R
                marker = "[!]"
            elif f.severity.value == "MEDIUM":
                color = Y
                marker = "[~]"
            else:
                color = G
                marker = "[i]"
            
            lines.append(f"{color}|  {marker} [{f.severity.value}] {f.title}{RESET}")
            lines.append(f"{DIM}|     {f.description}{RESET}")
            
            if f.remediation:
                lines.append(f"{B}|     Fix: {f.remediation}{RESET}")
            
            lines.append("")
        
        lines.append(f"{B}+{'-'*58}+{RESET}")
        lines.append("")

    # Summary
    summary = context.get_summary()
    total = summary['total_findings']
    
    lines.append(f"{C}+{'='*58}+{RESET}")
    lines.append(f"{C}|{RESET}{' '*18}{BOLD}SCAN SUMMARY{RESET}{' '*28}{C}|{RESET}")
    lines.append(f"{C}+{'='*58}+{RESET}")
    
    for sev, count in summary['severity_breakdown'].items():
        if count > 0:
            color = R if sev in ['CRITICAL', 'HIGH'] else Y if sev == 'MEDIUM' else G
            lines.append(f"{C}|{RESET}  {color}{sev:12s}: {count:3d}{RESET}{' '*38}{C}|{RESET}")
    
    lines.append(f"{C}|{RESET}  {'-'*54}  {C}|{RESET}")
    lines.append(f"{C}|{RESET}  {BOLD}TOTAL: {total} findings{RESET}{' '*36}{C}|{RESET}")
    lines.append(f"{C}+{'='*58}+{RESET}")
    lines.append(f"{DIM}ShieldForge v1.0.0 — Forging Secure Applications{RESET}")

    return "\n".join(lines)


if __name__ == "__main__":
    main()
