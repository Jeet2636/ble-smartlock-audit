"""
Command-line entry point for the attacker-side tool.

Usage:
    python cli.py scan                        # passively find nearby BLE devices
    python cli.py scan --filter VulnBLE        # only show devices whose name matches
    python cli.py enum <ADDRESS>                # connect + enumerate + classify
    python cli.py enum <ADDRESS> --out out.json # also save full JSON result
    python cli.py enum <ADDRESS> --html rep.html # write the HTML report somewhere else
"""
import argparse
import asyncio
import json

from . import scanner
from . import enumerate as enum_mod
from . import report as report_mod


def main() -> None:
    parser = argparse.ArgumentParser(description="BLE Security Assessment Framework")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Passively scan for nearby BLE devices")
    scan_p.add_argument("--duration", type=float, default=8.0, help="Scan time in seconds")
    scan_p.add_argument("--filter", type=str, default=None, help="Only show devices whose name contains this")

    enum_p = sub.add_parser("enum", help="Connect to a device and enumerate its GATT profile")
    enum_p.add_argument("address", help="BLE address of the target (from `scan` output)")
    enum_p.add_argument("--out", type=str, default=None, help="Write full JSON result to this file")
    enum_p.add_argument("--html", type=str, default="report.html",
                        help="Write the HTML report to this file (default: report.html)")
    enum_p.add_argument("--no-html", action="store_true", help="Skip the HTML report")

    args = parser.parse_args()

    if args.command == "scan":
        devices = asyncio.run(scanner.scan(duration=args.duration, name_filter=args.filter))
        scanner.print_devices(devices)

    elif args.command == "enum":
        result = asyncio.run(enum_mod.enumerate_device(args.address))
        enum_mod.print_summary(result)
        if args.out:
            with open(args.out, "w") as f:
                json.dump(result.to_dict(), f, indent=2)
            print(f"\nSaved full JSON result to {args.out}")
        if not args.no_html:
            with open(args.html, "w", encoding="utf-8") as f:
                f.write(report_mod.render_html(result))
            print(f"Generated HTML report to {args.html}")


if __name__ == "__main__":
    main()
