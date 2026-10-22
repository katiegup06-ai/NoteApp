"""Session 03 lab: Caesar cracking, AES ECB/GCM image demo, and NotesApp GCM.

Requirements: python -m pip install cryptography pillow

Examples (run from the outputs folder):
  python lab_session03.py caesar-encrypt --text "Attack at dawn!" --key 7
  python lab_session03.py caesar-crack --text "Hkzhjr ha khdu!"
  python lab_session03.py image-demo
  python lab_session03.py image-demo --input photo.png --out-dir .
  python lab_session03.py notes-migrate notes.db
"""
from __future__ import annotations

import argparse
import base64
import os
import sqlite3
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from PIL import Image, ImageDraw

# Approximate frequencies of A..Z in ordinary English, as probabilities.
ENGLISH_FREQ = (
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228,
    0.02015, 0.06094, 0.06966, 0.00153, 0.00772, 0.04025,
    0.02406, 0.06749, 0.07507, 0.01929, 0.00095, 0.05987,
    0.06327, 0.09056, 0.02758, 0.00978, 0.02360, 0.00150,
    0.01974, 0.00074,
)


def caesar_encrypt(text: str, key: int) -> str:
    """Shift ASCII letters forward by key; leave punctuation and case intact."""
    key %= 26
    out = []
    for char in text:
        if "a" <= char <= "z":
            out.append(chr((ord(char) - ord("a") + key) % 26 + ord("a")))
        elif "A" <= char <= "Z":
            out.append(chr((ord(char) - ord("A") + key) % 26 + ord("A")))
        else:
            out.append(char)
    return "".join(out)


def caesar_decrypt(text: str, key: int) -> str:
    return caesar_encrypt(text, -key)


def chi_squared_english(text: str) -> float:
    """Lower is a better fit: sum((observed-expected)^2 / expected)."""
    counts = [0] * 26
    total = 0
    for char in text.lower():
        if "a" <= char <= "z":
            counts[ord(char) - ord("a")] += 1
            total += 1
    if total == 0:
        return float("inf")
    score = 0.0
    for observed, probability in zip(counts, ENGLISH_FREQ):
        expected = total * probability
        score += (observed - expected) ** 2 / expected
    return score


def caesar_crack(ciphertext: str) -> tuple[int, str, float]:
    """Try every possible encryption shift and return (key, plaintext, score)."""
    candidates = [
        (key, caesar_decrypt(ciphertext, key))
        for key in range(26)
    ]
    key, plaintext = min(candidates, key=lambda item: chi_squared_english(item[1]))
    return key, plaintext, chi_squared_english(plaintext)


def make_demo_image() -> Image.Image:
    """Create a flat-color teaching image so ECB's repeated blocks are visible."""
    image = Image.new("RGBA", (320, 240), (238, 238, 230, 255))
    draw = ImageDraw.Draw(image)
    draw.rectangle((0, 0, 319, 35), fill=(35, 115, 175, 255))
    draw.rectangle((0, 205, 319, 239), fill=(35, 145, 80, 255))
    # A simple high-contrast figure and repeated bars make repeated pixel blocks.
    draw.ellipse((115, 48, 205, 138), fill=(245, 175, 35, 255))
    draw.ellipse((138, 72, 148, 82), fill=(20, 20, 25, 255))
    draw.ellipse((172, 72, 182, 82), fill=(20, 20, 25, 255))
    draw.polygon([(150, 95), (170, 95), (160, 108)], fill=(220, 65, 45, 255))
    draw.rectangle((95, 138, 225, 207), fill=(25, 35, 50, 255))
    draw.rectangle((25, 55, 55, 180), fill=(210, 65, 55, 255))
    draw.rectangle((65, 55, 82, 180), fill=(245, 195, 50, 255))
    draw.rectangle((255, 55, 285, 180), fill=(210, 65, 55, 255))
    draw.rectangle((295, 55, 312, 180), fill=(245, 195, 50, 255))
    return image


def encrypt_image_demo(input_path: Optional[str], out_dir: str) -> tuple[Path, Path, Path]:
    """Encrypt RGBA pixels under ECB and GCM and save ciphertext-as-image views."""
    target = Path(out_dir)
    target.mkdir(parents=True, exist_ok=True)
    if input_path:
        with Image.open(input_path) as source:
            image = source.convert("RGBA")
    else:
        image = make_demo_image()
    # AES works on 16-byte blocks; RGBA rows are four bytes per pixel.
    # Pad the width to a multiple of four pixels so raw bytes align exactly.
    width, height = image.size
    aligned_width = (width + 3) // 4 * 4
    if aligned_width != width:
        aligned = Image.new("RGBA", (aligned_width, height), (0, 0, 0, 255))
        aligned.paste(image, (0, 0))
        image = aligned
    raw = image.tobytes()
    if len(raw) % 16:
        raise ValueError("Pixel bytes must be a multiple of AES's 16-byte block size")

    key = os.urandom(32)  # Demo key, deliberately not written to disk.
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    ecb_bytes = encryptor.update(raw) + encryptor.finalize()

    nonce = os.urandom(12)
    gcm_result = AESGCM(key).encrypt(nonce, raw, b"session03-image-demo")
    gcm_bytes = gcm_result[:-16]  # Remove tag only for the visual pixel rendering.
    # The GCM tag is required to decrypt/authenticate real data; this PNG is only a visualization.

    original_path = target / "plaintext.png"
    ecb_path = target / "ecb_encrypted.png"
    gcm_path = target / "gcm_encrypted.png"
    image.save(original_path)
    Image.frombytes("RGBA", image.size, ecb_bytes).save(ecb_path)
    Image.frombytes("RGBA", image.size, gcm_bytes).save(gcm_path)
    return original_path, ecb_path, gcm_path


# Part 3 helpers: SQLite schema assumed to be notes(id INTEGER PRIMARY KEY, comment TEXT).
GCM_PREFIX = "gcm:v1:"
GCM_KEY_ENV = "NOTESAPP_KEY_B64"


def load_notes_key() -> bytes:
    encoded = os.environ.get(GCM_KEY_ENV)
    if not encoded:
        raise RuntimeError(f"Set {GCM_KEY_ENV} to a base64-encoded 32-byte key first")
    try:
        key = base64.b64decode(encoded, validate=True)
    except Exception as exc:
        raise RuntimeError(f"{GCM_KEY_ENV} is not valid base64") from exc
    if len(key) != 32:
        raise RuntimeError(f"{GCM_KEY_ENV} must decode to exactly 32 bytes")
    return key


def encrypt_comment(comment: Optional[str], note_id: int, key: bytes) -> Optional[str]:
    if comment is None:
        return None
    nonce = os.urandom(12)
    aad = f"notes:{note_id}:comment:v1".encode()
    ciphertext_and_tag = AESGCM(key).encrypt(nonce, comment.encode("utf-8"), aad)
    return GCM_PREFIX + base64.b64encode(nonce + ciphertext_and_tag).decode("ascii")


def decrypt_comment(value: Optional[str], note_id: int, key: bytes) -> Optional[str]:
    if value is None:
        return None
    if not value.startswith(GCM_PREFIX):  # Lets a migration read plaintext rows.
        return value
    packed = base64.b64decode(value[len(GCM_PREFIX):], validate=True)
    if len(packed) < 12 + 16:
        raise ValueError("Stored GCM value is malformed")
    aad = f"notes:{note_id}:comment:v1".encode()
    return AESGCM(key).decrypt(packed[:12], packed[12:], aad).decode("utf-8")


def migrate_comments(db_path: str, key: bytes) -> int:
    changed = 0
    with sqlite3.connect(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        rows = db.execute("SELECT id, comment FROM notes WHERE comment IS NOT NULL").fetchall()
        for note_id, comment in rows:
            if not comment.startswith(GCM_PREFIX):
                db.execute("UPDATE notes SET comment = ? WHERE id = ?",
                           (encrypt_comment(comment, note_id, key), note_id))
                changed += 1
    return changed


def main() -> None:
    parser = argparse.ArgumentParser(description="Session 03 cryptography lab")
    commands = parser.add_subparsers(dest="command", required=True)

    enc = commands.add_parser("caesar-encrypt", help="Encrypt text with a Caesar shift")
    enc.add_argument("--text", required=True)
    enc.add_argument("--key", required=True, type=int)
    dec = commands.add_parser("caesar-decrypt", help="Decrypt text with a known shift")
    dec.add_argument("--text", required=True)
    dec.add_argument("--key", required=True, type=int)
    crack = commands.add_parser("caesar-crack", help="Crack a Caesar shift by chi-squared")
    crack.add_argument("--text", required=True)
    img = commands.add_parser("image-demo", help="Create ECB/GCM ciphertext image comparison")
    img.add_argument("--input", help="Optional input image; demo image is used if omitted")
    img.add_argument("--out-dir", default=".")
    migration = commands.add_parser("notes-migrate", help="Encrypt plaintext notes.comment values")
    migration.add_argument("database")

    args = parser.parse_args()
    if args.command == "caesar-encrypt":
        print(caesar_encrypt(args.text, args.key))
    elif args.command == "caesar-decrypt":
        print(caesar_decrypt(args.text, args.key))
    elif args.command == "caesar-crack":
        key, plaintext, score = caesar_crack(args.text)
        print(f"Recovered encryption shift: {key}\nChi-squared score: {score:.3f}\nPlaintext: {plaintext}")
    elif args.command == "image-demo":
        paths = encrypt_image_demo(args.input, args.out_dir)
        print("Created:")
        for path in paths:
            print(path.resolve())
        print("The random demo key and GCM nonce were kept only in memory.")
    elif args.command == "notes-migrate":
        count = migrate_comments(args.database, load_notes_key())
        print(f"Encrypted {count} comment(s).")


if __name__ == "__main__":
    main()
