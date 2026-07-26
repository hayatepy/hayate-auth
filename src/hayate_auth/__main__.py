"""CLI (DESIGN §4): emit migration DDL; applying it stays the user's job.

python -m hayate_auth generate --dialect sqlite
python -m hayate_auth generate --dialect d1 | npx wrangler d1 execute DB --file=-
"""

from __future__ import annotations

import argparse
import sys

from .schema import DIALECTS, MIGRATIONS


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m hayate_auth")
    commands = parser.add_subparsers(dest="command", required=True)
    generate = commands.add_parser("generate", help="print the schema DDL")
    generate.add_argument("--dialect", choices=sorted(DIALECTS), default="sqlite")
    generate.add_argument(
        "--upgrade-from",
        choices=sorted(MIGRATIONS),
        help="emit only the explicit migration from this released version",
    )
    args = parser.parse_args(argv)

    ddl = (
        MIGRATIONS[args.upgrade_from][args.dialect]
        if args.upgrade_from is not None
        else DIALECTS[args.dialect]
    )
    print(ddl, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
