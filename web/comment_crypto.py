"""AES-GCM storage for NotesApp comments.

Stored format: gcm:v1: + Base64(nonce + ciphertext + authentication tag).
Existing plaintext comments must be migrated before using decrypt_comment.
"""

import base64
import binascii
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


PREFIX = "gcm:v1:"
KEY_ENV = "NOTESAPP_KEY_B64"


def load_key() -> bytes:
    """Read the same 256-bit key from configuration on every application start."""
    encoded = os.environ.get(KEY_ENV)
    if not encoded:
        raise RuntimeError(f"Set {KEY_ENV} before starting NotesApp")
    try:
        key = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise RuntimeError(f"{KEY_ENV} must contain valid Base64") from exc
    if len(key) != 32:
        raise RuntimeError(f"{KEY_ENV} must decode to exactly 32 bytes")
    return key


def _associated_data(note_id: int) -> bytes:
    """Bind the encrypted comment to its database record."""
    return f"notes:{int(note_id)}:comment:v1".encode("utf-8")


def encrypt_comment(comment: str | None, note_id: int, key: bytes) -> str | None:
    if comment is None:
        return None
    nonce = os.urandom(12)
    ciphertext_and_tag = AESGCM(key).encrypt(
        nonce, comment.encode("utf-8"), _associated_data(note_id)
    )
    packed = base64.b64encode(nonce + ciphertext_and_tag).decode("ascii")
    return PREFIX + packed


def decrypt_comment(value: str | None, note_id: int, key: bytes) -> str | None:
    if value is None:
        return None
    if not value.startswith(PREFIX):
        raise ValueError("Comment is not encrypted; migrate existing comments first")
    packed = base64.b64decode(value[len(PREFIX):], validate=True)
    if len(packed) < 28:
        raise ValueError("Encrypted comment is truncated")
    plaintext = AESGCM(key).decrypt(
        packed[:12], packed[12:], _associated_data(note_id)
    )
    return plaintext.decode("utf-8")
