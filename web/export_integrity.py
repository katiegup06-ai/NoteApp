"""SHA-256 checksums for the exact bytes of a CSV export.

The checksum detects a changed file. It is not a digital signature: someone
who can replace both the CSV and its checksum can create a matching pair.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import re
import zipfile


EXPORT_FILENAME = "grades.csv"
CHECKSUM_FILENAME = EXPORT_FILENAME + ".sha256"


def _validate_filename(filename: str) -> None:
    """Allow one portable filename, never an absolute path or directory path."""
    if (
        not isinstance(filename, str)
        or not filename
        or filename in (".", "..")
        or filename != filename.strip()
        or any(char in filename for char in "/\\:")
        or any(ord(char) < 32 or ord(char) == 127 for char in filename)
    ):
        raise ValueError("Checksum filename must be a simple filename without a path.")


def sha256_hex(data: bytes) -> str:
    """Return the lowercase SHA-256 digest of the original bytes."""
    return hashlib.sha256(data).hexdigest()


def make_checksum(data: bytes, filename: str = EXPORT_FILENAME) -> str:
    """Create one sha256sum-style record with a terminating newline."""
    _validate_filename(filename)
    return f"{sha256_hex(data)}  {filename}\n"


def parse_checksum(text: str, expected_filename: str = EXPORT_FILENAME) -> str:
    """Read exactly one SHA-256 record and return its lowercase digest.

    The record uses two spaces between the digest and the filename. An optional
    UTF-8 BOM and one trailing LF or CRLF are accepted. Other lines, path names,
    malformed hashes, and a filename different from expected_filename are errors.
    """
    _validate_filename(expected_filename)
    if not isinstance(text, str):
        raise ValueError("Checksum text must be a string.")
    if text.startswith("\ufeff"):
        text = text[1:]
    if text.endswith("\r\n"):
        text = text[:-2]
    elif text.endswith("\n"):
        text = text[:-1]
    match = re.fullmatch(r"([0-9A-Fa-f]{64})  ([^\r\n]+)", text)
    if match is None:
        raise ValueError("Expected exactly one SHA-256 checksum record.")
    digest, filename = match.groups()
    _validate_filename(filename)
    if filename != expected_filename:
        raise ValueError("Checksum filename does not match the CSV filename.")
    return digest.lower()


def verify_bytes(
    data: bytes, checksum_text: str, filename: str = EXPORT_FILENAME
) -> bool:
    """Return False for changed bytes; raise ValueError for invalid metadata."""
    expected = parse_checksum(checksum_text, expected_filename=filename)
    return hmac.compare_digest(sha256_hex(data), expected)


def make_export_bundle(data: bytes) -> bytes:
    """Put the same CSV byte snapshot and its checksum into one ZIP file."""
    checksum = make_checksum(data).encode("utf-8")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(EXPORT_FILENAME, data)
        archive.writestr(CHECKSUM_FILENAME, checksum)
    return buffer.getvalue()
