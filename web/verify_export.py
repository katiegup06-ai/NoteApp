"""Verify a downloaded CSV: python verify_export.py CSV CHECKSUM."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from export_integrity import verify_bytes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check a CSV file against its SHA-256 checksum."
    )
    parser.add_argument("csv", type=Path, help="The original downloaded CSV file")
    parser.add_argument("checksum", type=Path, help="The downloaded .sha256 file")
    args = parser.parse_args(argv)
    try:
        data = args.csv.read_bytes()
        # Preserve line endings; the parser, not text-mode translation, validates
        # whether the checksum has one permitted final newline.
        with args.checksum.open("r", encoding="utf-8", newline="") as handle:
            checksum_text = handle.read()
        matches = verify_bytes(data, checksum_text, filename=args.csv.name)
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if not matches:
        print(f"FAIL: SHA-256 does not match {args.csv.name}.")
        return 1
    print(f"PASS: SHA-256 matches {args.csv.name}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
