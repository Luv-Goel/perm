"""Perm CLI."""

import argparse
import sys
import os
from . import __version__
from .core import scan_path, find_suid_binaries, format_findings, generate_report


def main():
    parser = argparse.ArgumentParser(prog="perm", description="Security permissions auditor")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("scan", help="Scan directory for permission issues")
    p.add_argument("path", nargs="?", default=".", help="Directory to scan")
    p.add_argument("--report", metavar="FILE", help="Generate HTML report")

    p = sub.add_parser("suid", help="Find SUID binaries")
    p.add_argument("paths", nargs="*", default=None, help="Directories to search")

    args = parser.parse_args()

    if args.command == "scan":
        if not os.path.isdir(args.path):
            print(f"[ERR] Directory not found: {args.path}", file=sys.stderr)
            sys.exit(1)
        results = scan_path(args.path)
        print(format_findings(results))
        if args.report:
            path = generate_report(results, args.report)
            print(f"[OK] Report: {path}", file=sys.stderr)
        total = len(results["suid"]) + len(results["world_readable_sensitive"]) + len(results["world_writable"])
        if total:
            sys.exit(1)

    elif args.command == "suid":
        binaries = find_suid_binaries(args.paths)
        if binaries:
            print(f"  SUID binaries ({len(binaries)}):")
            for b in binaries:
                print(f"    {b['mode']}  {b['path']}")
        else:
            print("  No SUID binaries found.")


if __name__ == "__main__":
    main()
