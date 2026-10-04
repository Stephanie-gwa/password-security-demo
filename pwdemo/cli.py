"""
cli.py — command-line entry point.

    python -m pwdemo run                  # the full comparison demo
    python -m pwdemo run --output out.json
    python -m pwdemo list-scenarios

This CLI only ever operates on the synthetic passwords bundled in
synthetic_data.py — there is no flag anywhere here to point it at an
arbitrary password or hash. See README "Scope" for why.
"""
from __future__ import annotations
import argparse
import json
import sys

from .comparison import run_full_comparison
from .synthetic_data import TARGET_SCENARIOS

METHOD_LABELS = {
    "dictionary_unsalted": "Dictionary attack (unsalted)",
    "dictionary_salted": "Dictionary attack (salted PBKDF2)",
    "bruteforce_unsalted": "Brute-force search (unsalted)",
    "lookup_table": "Precomputed lookup table",
    "rainbow_table": "Rainbow chain table",
}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pwdemo",
        description="Educational demonstration of weak vs. modern password hashing. "
                     "Uses only synthetic passwords bundled with this project.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="Run the full comparison demo")
    run.add_argument("--output", "-o", default=None, help="Write full results as JSON to this file")
    run.add_argument("--quiet", "-q", action="store_true", help="Only print the summary table")

    sub.add_parser("list-scenarios", help="List the synthetic target scenarios this demo uses")

    return p


def cmd_run(args) -> int:
    if not args.quiet:
        print("Running the password hashing demonstration (synthetic passwords only)...\n")

    report = run_full_comparison()

    print(format_table(report))
    print()
    print(f"Lookup table:   {report.lookup_table_stats['entries']} entries, "
          f"built in {report.lookup_table_stats['build_seconds']*1000:.2f} ms")
    print(f"Rainbow table:  {report.rainbow_table_stats['stored_chains']} stored chains "
          f"(chain length {report.rainbow_table_stats['chain_length']}), theoretical coverage "
          f"{report.rainbow_table_stats['theoretical_coverage']:,} passwords, "
          f"built in {report.rainbow_table_stats['build_seconds']*1000:.2f} ms")
    print(f"\nTotal demo runtime: {report.total_seconds:.2f}s")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, indent=2)
        print(f"\nFull results written to {args.output}")

    return 0


def format_table(report) -> str:
    rows = report.results
    header = f"{'Scenario':<20} {'Hash scheme':<16} {'Method':<32} {'Found':<7} {'Time':>10}"
    lines = [header, "-" * len(header)]
    for r in rows:
        label = METHOD_LABELS.get(r["method"], r["method"])
        found = "yes" if r["found"] else "no"
        elapsed = r["elapsed_seconds"]
        time_str = f"{elapsed*1000:.3f} ms" if elapsed < 1 else f"{elapsed:.2f} s"
        lines.append(f"{r['scenario']:<20} {r['hash_scheme']:<16} {label:<32} {found:<7} {time_str:>10}")
    return "\n".join(lines)


def cmd_list_scenarios(_args) -> int:
    for name, info in TARGET_SCENARIOS.items():
        print(f"{name}: {info['explain']}")
    return 0


def main(argv: list = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "run":
        return cmd_run(args)
    if args.command == "list-scenarios":
        return cmd_list_scenarios(args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
