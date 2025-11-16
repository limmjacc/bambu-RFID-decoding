# Bambu PLA Matte Black - NFC Spool Profile

`Bambu_PLAMatte_Black.nfc` tag dump. This file extracts the human-readable metadata and key settings stored on the filament spool's NFC tag so you can quickly see recommended print settings, spool info, and security notes. Although this file is NFC data, it still classifies as RFID. All NFC devices are HF-RFID devices, but not all RFID devices are NFC devices.

---

**Quick Facts**

- **Filename:** `Bambu_PLAMatte_Black.nfc`
- **Device type:** Mifare Classic (ISO14443-3A)
- **UID (tag):** `95 DA B1 02`
- **Mifare Classic type:** 1K (1024 bytes, 16 sectors x 64 bytes)
- **Data format version:** 2
- **Profile:** PLA Matte Black, 1.75 mm, 1 kg spool
- **Production date:** 2025-04-25 16:57 (UTC/local as recorded)

---

## Overview

This dump contains the NFC data stored on a Bambu filament spool tag. Sectors 0–3 contain the bulk of the human-readable spool metadata (material, color, diameter, spool weight, recommended drying and temperature ranges). Later sectors are mainly padding, permission trailers, and a cryptographic signature block used by the printer ecosystem to validate the tag.

This tag is authentic Bambu structure. To clone or reuse on another spool, you'd need to replicate the UID, data, and signature which is currently impossible without hacking the printer firmware or using community tools. Empty sectors suggest a basic config; advanced tags might use more space.

The information below is extracted from the blocks in Sector 0–3 and the helpful summary lines included in the dump.

---

## Extracted Metadata

- **Material / Subtype:** PLA (Polylactic Acid) — Matte finish
- **Color:** Black (RGBA: 0, 0, 0, 255)
- **Diameter:** 1.75 mm (commonly encoded)
- **Spool weight:** 1000 g (1 kg)
- **Drying:** 55 °C for 8 hours
- **Nozzle temperature (recommended):** 190–230 °C
- **Bed type / bed temperature:** `bed type 0` (unspecified — adjust in slicer for your printer/bed surface)

Raw fields of note (decoded / interpreted):

- Block 0: material variant and printer/tray info
- Block 1: internal material ID (`GFA01...`) and Bambu material identifier
- Block 2: `PLA` as base material
- Block 4: `PLA Matte` string
- Block 5: color + spool weight + diameter encoded (R,G,B,A, weight uint16 LE, diameter float/encoded)
- Block 6: drying temp/time and nozzle temp range
- Block 12: production timestamp `2025_04_25_16_57`

---

## Useful Print Settings (summary)

- Material: PLA (matte)
- Diameter: 1.75 mm — verify your slicer matches this
- Nozzle: 190–230 °C — start near 200–205 °C and tune flow
- Bed: use recommended adhesion for PLA matte (blue tape/PET, glue stick, or light brim)
- Drying: 55 °C for 8 hours before printing if spool has been exposed to humidity
- Spool: 1 kg — update spool weight in inventory if you track remaining filament

---

## Security & Data Layout Notes

- Many trailer blocks show `access bits: 87 87 87 69` — these are access configuration bytes for each sector trailer.
- Sectors 10–15 appear to contain an RSA-2048 signature/hash used for validation; treat these blocks as cryptographic data (not human readable).
- Sectors beyond 3 are largely padding/permission blocks and cryptographic signature material. Sectors 0–3 hold ~80% of the useful spool info.

---

## Example Raw Snippets (from the dump)

```
UID: 95 DA B1 02

Block 4: 50 4C 41 20 4D 61 74 74 65 00 00 00 00 00 00 00  # "PLA Matte"
Block 5: 00 00 00 FF E8 03 00 00 00 00 E0 3F 00 00 00 00  # color black, weight 1000g, diameter 1.75mm
Block 6: 37 00 08 00 00 00 00 00 E6 00 BE 00 00 00 00 00  # drying 55C, 8h, nozzle 190-230C

Block 12: 32 30 32 35 5F 30 34 5F 32 35 5F 31 36 5F 35 37  # 2025_04_25_16_57
```

---