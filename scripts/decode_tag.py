#!/usr/bin/env python3
"""Decode a Bambu Lab filament spool tag from a Flipper Zero .nfc dump.

Field layout follows the community reverse-engineering notes in
https://github.com/Bambu-Research-Group/RFID-Tag-Guide (BambuLabRfid.md).
It is not an official Bambu Lab specification. All integers are little endian.

Usage:
    python3 scripts/decode_tag.py dumps/pla-matte-black.nfc [--json] [--strict]
"""
import argparse
import json
import re
import struct
import sys

BLOCK_SIZE = 16
BLOCK_COUNT = 64
TRAILER_BLOCKS = tuple(range(3, BLOCK_COUNT, 4))
SIGNATURE_BLOCKS = (42, 44, 45, 46, 48, 49, 50, 52, 53, 54, 56, 57, 58, 60, 61, 62)
EXPECTED_ACCESS = bytes.fromhex("87878769")

_BLOCK_RE = re.compile(r"^Block\s+(\d+):\s*((?:[0-9A-Fa-f?]{2}\s*)+)")


class DumpError(ValueError):
    """Raised when the dump is malformed."""


def load_blocks(text):
    """Return {block_number: bytes-or-None}. A block with any '??' is None."""
    blocks = {}
    for lineno, line in enumerate(text.splitlines(), 1):
        match = _BLOCK_RE.match(line.split("#", 1)[0].strip())
        if not match:
            continue
        number = int(match.group(1))
        tokens = match.group(2).split()
        if len(tokens) != BLOCK_SIZE:
            raise DumpError(f"line {lineno}: block {number} has {len(tokens)} bytes, expected {BLOCK_SIZE}")
        blocks[number] = None if "??" in tokens else bytes(int(t, 16) for t in tokens)
    return blocks


def load_header(text):
    """Return the UID, ATQA and SAK lines from the tag header."""
    header = {}
    for key in ("UID", "ATQA", "SAK"):
        match = re.search(rf"^{key}:[ \t]*((?:[0-9A-Fa-f]{{2}}[ \t]*)+)", text, re.MULTILINE)
        if match:
            header[key] = bytes.fromhex(match.group(1).replace(" ", ""))
    return header


def _text(raw):
    return raw.split(b"\0", 1)[0].decode("ascii", errors="replace")


def decode(text):
    """Decode a dump into a dict of fields plus a list of consistency warnings."""
    blocks = load_blocks(text)
    header = load_header(text)
    warnings = []

    def get(n):
        data = blocks.get(n)
        if data is None:
            raise DumpError(f"block {n} is missing or unknown")
        return data

    b0, b1, b2, b4, b5, b6 = (get(n) for n in (0, 1, 2, 4, 5, 6))
    b8, b9, b10, b12, b13, b14, b16 = (get(n) for n in (8, 9, 10, 12, 13, 14, 16))

    uid = b0[:4]
    bcc = uid[0] ^ uid[1] ^ uid[2] ^ uid[3]
    if bcc != b0[4]:
        warnings.append(f"block 0 BCC is {b0[4]:02X}, expected {bcc:02X}")
    if "UID" in header and header["UID"] != uid:
        warnings.append("header UID does not match block 0")

    r, g, b, a = b5[0:4]
    drying_temp, drying_time, bed_type, bed_temp, hotend_max, hotend_min = struct.unpack_from("<6H", b6)
    production = _text(b12)

    # Block 16: format ID 2 means colour info follows. The second colour is
    # stored byte-reversed (ABGR), per upstream and confirmed on a dual-colour dump.
    format_id, color_count = struct.unpack_from("<2H", b16)
    colors = [bytes([r, g, b, a])]
    if format_id == 2 and color_count > 1:
        colors.append(b16[4:8][::-1])
    elif format_id == 2 and color_count != 1:
        warnings.append(f"block 16 colour count is {color_count}")

    for n in TRAILER_BLOCKS:
        trailer = blocks.get(n)
        if trailer is None:
            if n not in blocks:
                warnings.append(f"trailer block {n} is absent")
            continue
        if trailer[6:10] != EXPECTED_ACCESS:
            warnings.append(f"block {n} access bytes are {trailer[6:10].hex(' ').upper()}")
    signature = [blocks.get(n) for n in SIGNATURE_BLOCKS]
    if any(s is None for s in signature):
        warnings.append("signature region is incomplete")

    fields = {
        "uid": uid.hex(" ").upper(),
        "atqa": header.get("ATQA", b"").hex(" ").upper() or None,
        "sak": header.get("SAK", b"").hex(" ").upper() or None,
        "variant_id": _text(b1[0:8]),
        "material_id": _text(b1[8:16]),
        "filament_type": _text(b2),
        "detailed_filament_type": _text(b4),
        "color_rgba": [r, g, b, a],
        "color_hex": f"#{r:02X}{g:02X}{b:02X}{a:02X}",
        "colors_hex": ["#" + c.hex().upper() for c in colors],
        "spool_weight_g": struct.unpack_from("<H", b5, 4)[0],
        "filament_diameter_mm": round(struct.unpack_from("<f", b5, 8)[0], 3),
        "drying_temp_c": drying_temp,
        "drying_time_h": drying_time,
        "bed_temp_type": bed_type,
        "bed_temp_c": bed_temp,
        "hotend_max_c": hotend_max,
        "hotend_min_c": hotend_min,
        "xcam_info": b8[0:12].hex(" ").upper(),
        "nozzle_diameter_mm": round(struct.unpack_from("<f", b8, 12)[0], 3),
        "tray_uid": b9.hex().upper(),
        # Upstream labels this spool width (mm x 100). It varies implausibly
        # between spools in our dumps, so it is reported raw, not as millimetres.
        "block10_raw": struct.unpack_from("<H", b10, 4)[0],
        "production_datetime": production,
        "production_datetime_short": _text(b13),
        "filament_length_m": struct.unpack_from("<H", b14, 4)[0],
        "signature_bytes_present": sum(len(s) for s in signature if s),
    }
    return {"fields": fields, "warnings": warnings}


def format_report(result):
    f = result["fields"]
    rows = [
        ("UID", f["uid"]),
        ("Variant / material ID", f"{f['variant_id']} / {f['material_id']}"),
        ("Filament", f"{f['detailed_filament_type']} (base: {f['filament_type']})"),
        ("Color(s) (RGBA)", ", ".join(f["colors_hex"])),
        ("Spool weight", f"{f['spool_weight_g']} g"),
        ("Filament diameter", f"{f['filament_diameter_mm']} mm"),
        ("Filament length", f"{f['filament_length_m']} m"),
        ("Drying", f"{f['drying_temp_c']} C for {f['drying_time_h']} h"),
        ("Hotend range", f"{f['hotend_min_c']}-{f['hotend_max_c']} C"),
        ("Bed", f"type {f['bed_temp_type']}, {f['bed_temp_c']} C"),
        ("Nozzle diameter (block 8)", f"{f['nozzle_diameter_mm']} mm"),
        ("Block 10 value (raw)", f["block10_raw"]),
        ("Tray UID", f["tray_uid"]),
        ("Produced", f["production_datetime"]),
        ("Signature bytes in dump", f["signature_bytes_present"]),
    ]
    width = max(len(k) for k, _ in rows)
    lines = [f"{k.ljust(width)}  {v}" for k, v in rows]
    lines += [f"WARNING: {w}" for w in result["warnings"]]
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("dumps", nargs="+", help="path(s) to Flipper Zero .nfc file(s)")
    parser.add_argument("--json", action="store_true", help="emit JSON (a dict keyed by path) instead of a table")
    parser.add_argument("--strict", action="store_true", help="exit non-zero if any dump produces a warning")
    args = parser.parse_args(argv)

    results, status = {}, 0
    for path in args.dumps:
        try:
            with open(path, encoding="utf-8") as fh:
                results[path] = decode(fh.read())
        except (OSError, DumpError) as exc:
            print(f"error: {path}: {exc}", file=sys.stderr)
            status = 1
            continue
        if args.strict and results[path]["warnings"]:
            status = 1

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for path, result in results.items():
            if len(results) > 1:
                print(f"== {path}")
            print(format_report(result))
    return status


if __name__ == "__main__":
    sys.exit(main())
