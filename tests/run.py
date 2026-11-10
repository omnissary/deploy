"""Select and run checks from the flake's test suite registry."""

import argparse
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent


def nix_output(*args):
    return subprocess.check_output(["nix", *args], cwd=ROOT, text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", default="fast", help="suite name, or all")
    parser.add_argument(
        "--system", help="Nix system to select (defaults to the current system)"
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="print enabled names as JSON without building",
    )
    parser.add_argument("names", nargs="*", default=["all"])
    args = parser.parse_args()

    try:
        system = args.system or nix_output(
            "eval", "--raw", "--impure", "--expr", "builtins.currentSystem"
        )
        suites = json.loads(nix_output("eval", "--json", f".#testSuites.{system}"))
        if args.suite == "all":
            available = sorted(name for names in suites.values() for name in names)
        elif args.suite in suites:
            available = suites[args.suite]
        else:
            parser.error(
                f"unknown suite {args.suite!r}, available suites: {', '.join(suites)}"
            )

        if args.names == ["all"]:
            names = available
        else:
            unknown = sorted(set(args.names) - set(available))
            if unknown:
                parser.error(
                    f"unknown or unavailable tests for {args.suite}: {', '.join(unknown)}"
                )
            names = args.names

        if args.list:
            print(json.dumps(names))
            return 0
        if not names:
            parser.error(f"no tests in suite {args.suite!r} are available on {system}")
        return subprocess.call(
            [
                "nix",
                "build",
                "--no-link",
                "--print-build-logs",
                *[f".#checks.{system}.{name}" for name in names],
            ],
            cwd=ROOT,
        )
    except subprocess.CalledProcessError as error:
        return error.returncode


if __name__ == "__main__":
    raise SystemExit(main())
