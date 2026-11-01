#!/usr/bin/env python3
"""Rewrite a Flipper .nfc dump into the repository's canonical, annotated layout.

Every dump in dumps/ has the same structure: the Flipper header, section
banners, a comment on every header field and Block line, and a summary. The
comment wording follows the original hand-annotated pla-matte-black dump, with
values filled in from the dump's own decoded fields (see decode_tag.py). Block
data is never altered, and rerunning the script is a no-op.

All non-data text is written as '#' comments so the file stays loadable.

Usage:
    python3 scripts/annotate_dump.py dumps/pla-matte-red.nfc [more.nfc ...]
"""
import argparse
import calendar
import pathlib
import re
import sys

import decode_tag

COMMENT_COLUMN = 59  # longest data ends at column 57 ("Block NN: " + 47 chars)
BANNER = "#" * 40
DEVICE_TYPES = (
    "ISO14443-3A, ISO14443-3B, ISO14443-4A, ISO14443-4B, ISO15693-3, FeliCa, NTAG/Ultralight, "
    "Mifare Classic, Mifare Plus, Mifare DESFire, SLIX, ST25TB, NTAG4xx, Type 4 Tag, EMV"
)
UPPERCASE_WORDS = {"pla", "petg", "abs", "asa", "tpu", "pc", "pa", "pet"}

_BLOCK_LINE = re.compile(r"^Block\s+(\d+):\s*((?:[0-9A-Fa-f?]{2}\s*)+?)\s*(?:#.*)?$")


def hx(data):
    return data.hex(" ").upper()


def profile_name(stem):
    """'pla-matte-black' -> 'PLA Matte Black'."""
    return " ".join(w.upper() if w in UPPERCASE_WORDS else w.capitalize() for w in stem.split("-"))


def friendly_time(production):
    """'2025_04_25_16_57' -> ('April 25, 2025, at 4:57 PM', '2025-04-25 at 16:57 / 4:57pm')."""
    match = re.fullmatch(r"(\d{4})_(\d{2})_(\d{2})_(\d{2})_(\d{2})", production)
    if not match:
        return production, production
    year, month, day, hour, minute = (int(g) for g in match.groups())
    h12 = hour % 12 or 12
    suffix = "AM" if hour < 12 else "PM"
    long_form = f"{calendar.month_name[month]} {day}, {year}, at {h12}:{minute:02d} {suffix}"
    short_form = f"{year}-{month:02d}-{day:02d} at {hour:02d}:{minute:02d} / {h12}:{minute:02d}{suffix.lower()}"
    return long_form, short_form


def describe(number, data, f):
    """Return the comment text for one block. `data` is None for blocks with unknown bytes."""
    if number in decode_tag.TRAILER_BLOCKS:
        return (f"sector {number // 4} trailer: keys unknown (??), access bits 87 87 87 69, "
                "configures read/write permissions")
    if number in decode_tag.SIGNATURE_BLOCKS:
        start = decode_tag.SIGNATURE_BLOCKS.index(number) * 16
        return f"RSA-2048 signature, bytes {start}-{start + 15} of 256"

    long_time, _ = friendly_time(f["production_datetime"])
    short_time = data.split(b"\0", 1)[0].decode("ascii", "replace")
    r, g, b, a = f["color_rgba"]
    texts = {
        0: f"UID ({f['uid']}), BCC (check byte), SAK/ATQA and manufacturer data",
        1: (f"tray info index, variant ID \"{f['variant_id']}\" (bytes 0-7), material ID \"{f['material_id']}\" "
            "(bytes 8-15), internal Bambu IDs for this filament type"),
        2: f"Filament Type, {f['filament_type']}, base material",
        4: f"detailed filament Type, {f['detailed_filament_type']}",
        5: (f"color R={r} G={g} B={b} A={a} ({hx(data[0:4])}), spool weight {f['spool_weight_g']}g ({hx(data[4:6])}), "
            f"filament diameter {f['filament_diameter_mm']}mm ({hx(data[8:12])})"),
        6: (f"drying temp {f['drying_temp_c']}C ({hx(data[0:2])}), drying time {f['drying_time_h']}h ({hx(data[2:4])}), "
            f"bed temp type {f['bed_temp_type']} ({hx(data[4:6])}), bed temp {f['bed_temp_c']}C ({hx(data[6:8])}), "
            f"nozzle temp range {f['hotend_min_c']}C to {f['hotend_max_c']}C "
            f"(max {hx(data[8:10])}, min {hx(data[10:12])})"),
        8: (f"X-Cam Info, Binary, Internal AMS calibration data ({hx(data[0:12])}), "
            f"possible Nozzle Diameter {f['nozzle_diameter_mm']}mm ({hx(data[12:16])})"),
        9: "Tray UID/Serial, Binary, Likely a unique spool serial number or hash derived from UID",
        10: (f"uint16 LE at bytes 4-5 = {f['block10_raw']} ({hx(data[4:6])}), labelled spool width upstream "
             "but varies between spools, field partially unknown"),
        12: f"Production Date/Time, {f['production_datetime']}, Manufacturing timestamp: {long_time}",
        13: (f"Unknown (Batch/Expiry?), \"{short_time}\", Possibly a truncated date code, batch ID, or expiry "
             "snippet, format varies between spools"),
        14: f"filament length {f['filament_length_m']}m, uint16 LE at bytes 4-5 ({hx(data[4:6])}), meaning uncertain upstream",
        16: (f"format ID ({hx(data[0:2])}), color count ({hx(data[2:4])}), second color ({hx(data[4:8])}, "
             f"stored reversed), colors: {', '.join(f['colors_hex'])}"),
        17: "unknown, 01 00 seen only on dual-color spools",
        40: "signature region header, unknown, 01 00 on every dump",
    }
    if number in texts:
        return texts[number]
    if not any(data):
        return "unused, zero padding"
    return "unknown"


def summary(f, stem):
    kg = f["spool_weight_g"] / 1000
    kg_text = f"{kg:g} kg" if kg >= 1 else f"{f['spool_weight_g']} g"
    _, short_time = friendly_time(f["production_datetime"])
    return [
        (f"Filament Profile: {kg_text} spool of {profile_name(stem)}, {f['filament_diameter_mm']} mm diameter. "
         f"Dry at {f['drying_temp_c']}C for {f['drying_time_h']} hours"),
        (f"Print Config: Nozzle {f['hotend_min_c']}-{f['hotend_max_c']}C, bed type {f['bed_temp_type']} "
         f"(adjust in slicer). Produced on {short_time}"),
        "Full Dump: Sectors 0-3 hold ~80% of useful info; the rest is security/padding",
    ]


def load_tokens(text):
    """Return {block_number: [16 upper-case hex or '??' tokens]}."""
    tokens = {}
    for line in text.splitlines():
        match = _BLOCK_LINE.match(line)
        if match:
            tokens[int(match.group(1))] = [t.upper() for t in match.group(2).split()]
    return tokens


def _header_value(text, key, default):
    match = re.search(rf"^{re.escape(key)}:[ \t]*([^#\r\n]*?)[ \t]*(?:#.*)?$", text, re.MULTILINE)
    return match.group(1) if match else default


def annotate(text, stem="unknown"):
    """Return `text` rewritten into the canonical annotated layout."""
    device_type = _header_value(text, "Device type", "Mifare Classic")
    if device_type != "Mifare Classic":
        raise decode_tag.DumpError(f"unsupported device type {device_type!r}")
    header = decode_tag.load_header(text)
    for key in ("UID", "ATQA", "SAK"):
        if key not in header:
            raise decode_tag.DumpError(f"missing {key} line")
    tokens = load_tokens(text)
    missing = [n for n in range(decode_tag.BLOCK_COUNT) if n not in tokens]
    if missing:
        raise decode_tag.DumpError(f"missing blocks: {missing[:5]}")
    blocks = decode_tag.load_blocks(text)
    fields = decode_tag.decode(text)["fields"]

    def banner(title):
        return ["", BANNER, f"# {title}", BANNER, ""]

    out = ["Filetype: Flipper NFC device", "Version: 4"]
    out += banner("TAG Info")
    out += [
        f"# Device type can be {DEVICE_TYPES}",
        "Device type: Mifare Classic",
        "# UID is common for all formats",
        f"UID: {hx(header['UID'])}  # unique tag identifier, used as a base for key derivation in encrypted variants",
        "# ISO14443-3A specific data",
        f"ATQA: {hx(header['ATQA'])}  # answer to request, indicates Mifare Classic compatibility",
        f"SAK: {hx(header['SAK'])}  # select acknowledge (confirms 1K memory size)",
        "# Mifare Classic specific data",
        f"Mifare Classic type: {_header_value(text, 'Mifare Classic type', '1K')}  "
        "# 1024 bytes total (16 sectors x 64 bytes each)",
        f"Data format version: {_header_value(text, 'Data format version', '2')}",
    ]
    out += banner("DATA BLOCKS")
    out.append("# Mifare Classic blocks, '??' means unknown data")

    sections = {
        0: ["Sector 0-3", "Useful printer information"],
        16: ["Sector 4-9", "color info (blocks 16-17), otherwise unused zero padding, read/write permission blocks"],
        40: ["Sector 10-15", "RSA-2048 signature (256 bytes in 16 data blocks, after a header block)",
             "binary noise in the dump, cryptographic signature over the tag data",
             "also contains read/write permission blocks"],
    }
    for number in range(decode_tag.BLOCK_COUNT):
        if number in sections:
            out.append("")
            out += [f"# {line}" for line in sections[number]]
        body = f"Block {number}: {' '.join(tokens[number])}"
        out.append(f"{body.ljust(COMMENT_COLUMN)}# {describe(number, blocks[number], fields)}")
        if number in decode_tag.TRAILER_BLOCKS and number not in (15, 39, 63):
            out.append("")

    out += banner("SUMMARY")
    out.append("# Useful information and Filament Spool Summary")
    out += [f"# {line}" for line in summary(fields, stem)]
    return "\n".join(out) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("dumps", nargs="+", help="path(s) to Flipper Zero .nfc file(s), edited in place")
    args = parser.parse_args(argv)
    status = 0
    for path in map(pathlib.Path, args.dumps):
        try:
            path.write_text(annotate(path.read_text(encoding="utf-8"), path.stem), encoding="utf-8")
        except (OSError, decode_tag.DumpError) as exc:
            print(f"error: {path}: {exc}", file=sys.stderr)
            status = 1
    return status


if __name__ == "__main__":
    sys.exit(main())
