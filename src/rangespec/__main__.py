"""Allow ``python -m rangespec`` to use the installed CLI entry point."""

from rangespec.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
