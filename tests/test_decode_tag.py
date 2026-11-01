import contextlib
import io
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import decode_tag  # noqa: E402

DUMPS = ROOT / "dumps"

# name: (UID, variant ID, detailed type, colours, hotend min-max, drying C/h, length m, produced)
EXPECTED = {
    "pla-matte-black": ("95 DA B1 02", "A01-K1", "PLA Matte", ["#000000FF"], (190, 230), (55, 8), 315, "2025_04_25_16_57"),
    "pla-matte-blue": ("BD 17 32 39", "A01-B3", "PLA Matte", ["#0078BFFF"], (190, 230), (55, 8), 315, "2025_09_16_16_50"),
    "pla-matte-orange": ("B5 86 1A 03", "A01-A2", "PLA Matte", ["#F99963FF"], (190, 230), (55, 8), 315, "2025_04_29_07_44"),
    "pla-matte-red": ("15 C4 C9 A3", "A01-R1", "PLA Matte", ["#DE4343FF"], (190, 230), (55, 8), 315, "2025_08_23_15_35"),
    "pla-galaxy-purple": ("B7 D9 92 2A", "A15-B0", "PLA Galaxy", ["#594177FF"], (190, 230), (55, 6), 350, "2025_06_24_07_44"),
    "pla-silk-dual-purple-green": ("CD CE 88 3A", "A05-T7", "PLA Silk", ["#720062FF", "#3A913FFF"], (210, 230), (55, 8), 315, "2025_09_16_15_02"),
    "petg-translucent-purple": ("A7 0F 48 7A", "G01-P0", "PETG Translucent", ["#D6ABFF80"], (230, 260), (65, 8), 330, "2025_08_07_19_17"),
}


def decode_dump(name):
    return decode_tag.decode((DUMPS / f"{name}.nfc").read_text(encoding="utf-8"))


class DumpTests(unittest.TestCase):
    def test_every_dump_has_an_expectation(self):
        self.assertEqual({p.stem for p in DUMPS.glob("*.nfc")}, set(EXPECTED))

    def test_decoded_fields(self):
        for name, (uid, variant, kind, colors, hotend, drying, length, produced) in EXPECTED.items():
            with self.subTest(dump=name):
                result = decode_dump(name)
                f = result["fields"]
                self.assertEqual(result["warnings"], [])
                self.assertEqual(f["uid"], uid)
                self.assertEqual(f["variant_id"], variant)
                self.assertEqual(f["detailed_filament_type"], kind)
                self.assertEqual(f["colors_hex"], colors)
                self.assertEqual((f["hotend_min_c"], f["hotend_max_c"]), hotend)
                self.assertEqual((f["drying_temp_c"], f["drying_time_h"]), drying)
                self.assertEqual(f["filament_length_m"], length)
                self.assertEqual(f["production_datetime"], produced)
                self.assertEqual(f["spool_weight_g"], 1000)
                self.assertEqual(f["filament_diameter_mm"], 1.75)
                self.assertEqual(f["signature_bytes_present"], 256)


class ParserTests(unittest.TestCase):
    def test_short_block_rejected(self):
        with self.assertRaises(decode_tag.DumpError):
            decode_tag.load_blocks("Block 59: ?? ?? ?? 87 87 87 69 ??")

    def test_unknown_block_is_none(self):
        blocks = decode_tag.load_blocks("Block 3: " + " ".join(["??"] * 16))
        self.assertIsNone(blocks[3])

    def test_bad_bcc_warns(self):
        text = (DUMPS / "pla-matte-red.nfc").read_text(encoding="utf-8")
        text = text.replace("Block 0: 15 C4 C9 A3 BB", "Block 0: 15 C4 C9 A3 00")
        self.assertTrue(any("BCC" in w for w in decode_tag.decode(text)["warnings"]))

    def test_strict_exit_code(self):
        paths = [str(p) for p in sorted(DUMPS.glob("*.nfc"))]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(decode_tag.main(paths + ["--strict"]), 0)


class AnnotateTests(unittest.TestCase):
    def test_annotation_preserves_data_and_is_idempotent(self):
        import annotate_dump

        text = (DUMPS / "pla-matte-red.nfc").read_text(encoding="utf-8")
        once = annotate_dump.annotate(text)
        self.assertEqual(annotate_dump.annotate(once), once)
        self.assertEqual(decode_tag.load_blocks(once), decode_tag.load_blocks(text))
        self.assertEqual(decode_tag.decode(once), decode_tag.decode(text))
        self.assertIn('variant ID "A01-R1"', once)

    def test_committed_dumps_are_annotated(self):
        import annotate_dump

        for path in DUMPS.glob("*.nfc"):
            with self.subTest(dump=path.stem):
                text = path.read_text(encoding="utf-8")
                self.assertEqual(annotate_dump.annotate(text, path.stem), text)

    def test_all_dumps_share_one_structure(self):
        def skeleton(path):
            # Line-by-line shape: the key before ':' for data lines, '#' for whole-line comments.
            return [
                "#" if line.startswith("#") else line.split(":")[0]
                for line in path.read_text(encoding="utf-8").splitlines()
            ]

        paths = sorted(DUMPS.glob("*.nfc"))
        reference = skeleton(paths[0])
        for path in paths[1:]:
            with self.subTest(dump=path.stem):
                self.assertEqual(skeleton(path), reference)


if __name__ == "__main__":
    unittest.main()
