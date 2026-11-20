"""Command line interface: `uv run python -m app.cli <command>`.

Commands:
    export-openapi   writes the OpenAPI snapshot (openapi/v1.json); with --check
                     only compares and exits with 1 if the snapshot is outdated.

Later phases add: create-superadmin, sync-permissions, rotate-keys, verify-audit.
"""

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from app.settings import Settings

DEFAULT_OPENAPI_PATH = Path("openapi/v1.json")


def build_openapi_document() -> str:
    """Renders the OpenAPI schema deterministically (independent of the environment)."""
    from app.main import create_app

    settings = Settings(_env_file=None, app_env="test", log_level="WARNING")
    schema = create_app(settings).openapi()
    return json.dumps(schema, indent=2, ensure_ascii=False, sort_keys=False) + "\n"


def _export_openapi(args: argparse.Namespace) -> int:
    path: Path = args.output
    document = build_openapi_document()
    if args.check:
        current = path.read_text(encoding="utf-8") if path.exists() else ""
        if current != document:
            sys.stderr.write(
                f"OpenAPI snapshot {path} eskirgan. Yangilash: "
                "uv run python -m app.cli export-openapi\n"
            )
            return 1
        return 0
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(document, encoding="utf-8", newline="\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m app.cli", description="Admin BFF CLI")
    commands = parser.add_subparsers(dest="command", required=True)

    export = commands.add_parser("export-openapi", help="OpenAPI snapshot'ini yozish")
    export.add_argument("--output", type=Path, default=DEFAULT_OPENAPI_PATH)
    export.add_argument("--check", action="store_true", help="faqat solishtirish")
    export.set_defaults(handler=_export_openapi)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    exit_code: int = args.handler(args)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
