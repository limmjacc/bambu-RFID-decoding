# Bambu RFID Decoding

Tools and sample data for decoding the Mifare Classic 1K tags on Bambu Lab filament spools. The repository contains a decoder for Flipper Zero `.nfc` dumps, a sector-key derivation script, and a growing set of annotated dumps from real spools.

The tag layout comes from the community reverse-engineering notes in the [Bambu Research Group RFID-Tag-Guide](https://github.com/Bambu-Research-Group/RFID-Tag-Guide). It is not an official Bambu Lab specification. Treat all output as a starting point and verify it against the upstream guide.

## Repository layout

| Path | Contents |
| --- | --- |
| `dumps/` | Flipper `.nfc` dumps, named `<material>-<finish-or-type>-<color>.nfc` |
| `scripts/decode_tag.py` | Decodes one or more dumps into a table or JSON |
| `scripts/derive_keys.py` | Derives the 16 sector A-keys from a tag UID |
| `scripts/annotate_dump.py` | Adds a per-block explanatory comment to a dump, in place |
| `tests/` | Unit tests for both scripts and every dump |

## Usage

Python 3.9 or later. The scripts use only the standard library.

```
python3 scripts/decode_tag.py dumps/pla-matte-black.nfc        # table
python3 scripts/decode_tag.py dumps/*.nfc --json               # JSON for many dumps
python3 scripts/decode_tag.py dumps/*.nfc --strict             # exit 1 on any warning
python3 scripts/derive_keys.py "95 DA B1 02"                   # sector: key
python3 scripts/derive_keys.py 95DAB102 --dict                 # bare keys for a Flipper user dictionary
python3 scripts/annotate_dump.py dumps/new-dump.nfc            # add per-block comments
python3 -m unittest discover -s tests                          # run tests
```

The decoder also checks the block 0 check byte (BCC), the sector trailer access bytes, and the presence of the signature region. Any mismatch appears as a warning.

## Dumps

| File | Variant ID | Filament | Colors | Hotend °C | Drying | Length |
| --- | --- | --- | --- | --- | --- | --- |
| `pla-matte-black.nfc` | A01-K1 | PLA Matte | `#000000` | 190–230 | 55 °C, 8 h | 315 m |
| `pla-matte-blue.nfc` | A01-B3 | PLA Matte | `#0078BF` | 190–230 | 55 °C, 8 h | 315 m |
| `pla-matte-orange.nfc` | A01-A2 | PLA Matte | `#F99963` | 190–230 | 55 °C, 8 h | 315 m |
| `pla-matte-red.nfc` | A01-R1 | PLA Matte | `#DE4343` | 190–230 | 55 °C, 8 h | 315 m |
| `pla-galaxy-purple.nfc` | A15-B0 | PLA Galaxy | `#594177` | 190–230 | 55 °C, 6 h | 350 m |
| `pla-silk-dual-purple-green.nfc` | A05-T7 | PLA Silk | `#720062`, `#3A913F` | 210–230 | 55 °C, 8 h | 315 m |
| `petg-translucent-purple.nfc` | G01-P0 | PETG Translucent | `#D6ABFF` (alpha 80) | 230–260 | 65 °C, 8 h | 330 m |

All seven spools report 1000 g and 1.75 mm. Every dump has the same layout: the Flipper header, section banners, a comment on each header field and Block line, and a summary. The comment wording originates from the hand-annotated `pla-matte-black.nfc`. `scripts/annotate_dump.py` generates the files, fills in the per-spool values, and never alters block data. A test fails if any dump drifts from that layout.

The comments are inline, so confirm that your Flipper firmware accepts them before you load an annotated file back onto the device. If it does not, strip them with `sed 's/ *#.*//'`.

To add a dump, save the raw export under `dumps/` with a kebab-case name, run `scripts/annotate_dump.py` on it, and add an entry to `EXPECTED` in `tests/test_decode_tag.py`. The file name also supplies the profile name in the summary. Each dump contains the tag UID, tray UID and signature, so confirm you are comfortable publishing them first.

## Tag layout

Mifare Classic 1K: 16 sectors of 4 blocks, 16 bytes per block. Integers are little endian. Sector keys are derived from the UID, so trailers appear as `??` in dumps.

| Block | Bytes | Field |
| --- | --- | --- |
| 0 | 0–3, 4, 5–15 | UID, BCC check byte, SAK/ATQA and manufacturer data |
| 1 | 0–7, 8–15 | Variant ID (`A01-K1`), material ID (`GFA01`) |
| 2 | 0–15 | Filament type (`PLA`) |
| 4 | 0–15 | Detailed filament type (`PLA Matte`) |
| 5 | 0–3, 4–5, 8–11 | Color RGBA, spool weight (g, uint16), diameter (mm, float32) |
| 6 | 0–1, 2–3, 4–5, 6–7, 8–9, 10–11 | Drying °C, drying hours, bed temp type, bed temp °C, hotend max °C, hotend min °C |
| 8 | 0–11, 12–15 | X-cam info (opaque), nozzle diameter (mm, float32) |
| 9 | 0–15 | Tray UID |
| 10 | 4–5 | Unknown uint16 (see below) |
| 12 | 0–15 | Production time, `YYYY_MM_DD_HH_MM` |
| 13 | 0–15 | Short production time (meaning uncertain) |
| 14 | 4–5 | Filament length in metres |
| 16 | 0–1, 2–3, 4–7 | Format ID (`02 00` means color info), color count, second color stored byte-reversed (ABGR) |
| 42–62 | 16 data blocks | RSA-2048 signature (256 bytes) |

Every sector trailer carries the access bytes `87 87 87 69` and a zero B-key, as upstream documents for Bambu tags.

## Sector key derivation

Each sector A-key comes from HKDF-SHA256 ([RFC 5869](https://www.rfc-editor.org/rfc/rfc5869)): the UID is the input keying material, a fixed 16-byte constant is the salt, and the context is `RFID-A\0`. The script produces sixteen 6-byte keys. The HKDF implementation is verified against the RFC test vectors. The salt and context come from upstream's `deriveKeys.py`; this repository cannot confirm them against a physical tag, because none of the dumps contains sector trailers. Use the script only on tags you own.

## Findings and open questions

- **Block 10 is not a consistent spool width.** Upstream labels it spool width in hundredths of a millimetre. Across these seven dumps it decodes to 2.01, 6.66, 6.66, 11.49, 15.36, 15.36 and 66.25 mm, which no single spool geometry explains. Only the Galaxy dump matches upstream's example. The decoder reports the raw value.
- **Dual-color spools** set the Block 16 color count to 2 and store the second color byte-reversed. The `pla-silk-dual-purple-green` dump confirms this.
- **Bed temperature type** and the **X-cam info** bytes are undocumented upstream. Bed temperature reads zero on every dump here.
- **Signature coverage.** Upstream does not state the hashed byte range, padding scheme or public key. It reports that printers reject tags with an invalid signature. This repository has not tested that claim.
- **Block 13** (short production time) is marked uncertain upstream.

## Limitations

The layout is reverse-engineered and checked against seven tags only. Do not rely on decoded values for any safety-relevant or production decision without verifying them against the current upstream documentation.
