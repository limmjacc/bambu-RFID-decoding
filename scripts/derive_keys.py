#!/usr/bin/env python3
"""Derive the 16 Mifare Classic sector A-keys for a Bambu Lab filament tag.

Bambu tags derive each sector key from the tag UID with HKDF-SHA256 (RFC 5869):
the UID is the input keying material, a fixed 16-byte constant is the salt, and
the context is b"RFID-A\\0". Sixteen 6-byte keys are produced, one per sector.
The B-keys are all zero. Parameters follow the community reverse-engineering
notes in https://github.com/Bambu-Research-Group/RFID-Tag-Guide; they have not
been validated against a physical tag in this repository, because the dumps in
dumps/ do not contain sector trailers.

Use this only on tags you own, to read them with a tool such as a Flipper Zero.

Usage:
    python3 scripts/derive_keys.py "95 DA B1 02"          # "sector: key" lines
    python3 scripts/derive_keys.py 95DAB102 --dict        # bare keys, Flipper user-dictionary format
"""
import argparse
import hashlib
import hmac
import sys

SALT = bytes.fromhex("9a759cf2c4f7caff222cb9769b41bc96")
CONTEXT = b"RFID-A\0"
KEY_LENGTH = 6
SECTOR_COUNT = 16


def hkdf_sha256(ikm, salt, info, length):
    """RFC 5869 HKDF with SHA-256: extract, then expand to `length` bytes."""
    if length > 255 * hashlib.sha256().digest_size:
        raise ValueError("requested length is too large for HKDF-SHA256")
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, block = b"", b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def parse_uid(text):
    """Parse a 4-byte UID from hex, tolerating spaces, colons and dashes."""
    cleaned = "".join(ch for ch in text if ch not in " :-")
    try:
        uid = bytes.fromhex(cleaned)
    except ValueError:
        raise ValueError(f"UID is not valid hex: {text!r}") from None
    if len(uid) != 4:
        raise ValueError(f"UID must be 4 bytes, got {len(uid)}")
    return uid


def derive_keys(uid):
    """Return the 16 sector A-keys (6 bytes each) for a 4-byte UID."""
    okm = hkdf_sha256(uid, SALT, CONTEXT, KEY_LENGTH * SECTOR_COUNT)
    return [okm[i : i + KEY_LENGTH] for i in range(0, len(okm), KEY_LENGTH)]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("uid", help="4-byte tag UID in hex, e.g. '95 DA B1 02'")
    parser.add_argument("--dict", action="store_true", help="print bare keys, one per line")
    args = parser.parse_args(argv)
    try:
        keys = derive_keys(parse_uid(args.uid))
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    for sector, key in enumerate(keys):
        print(key.hex().upper() if args.dict else f"{sector:2d}: {key.hex().upper()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
