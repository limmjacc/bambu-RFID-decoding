import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))

import derive_keys  # noqa: E402


class HkdfTests(unittest.TestCase):
    """RFC 5869 appendix A test vectors (SHA-256)."""

    def test_rfc5869_case_1(self):
        okm = derive_keys.hkdf_sha256(
            ikm=bytes.fromhex("0b" * 22),
            salt=bytes.fromhex("000102030405060708090a0b0c"),
            info=bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"),
            length=42,
        )
        self.assertEqual(
            okm.hex(),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        )

    def test_rfc5869_case_3_empty_salt_and_info(self):
        okm = derive_keys.hkdf_sha256(ikm=bytes.fromhex("0b" * 22), salt=b"", info=b"", length=42)
        self.assertEqual(
            okm.hex(),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        )


class DeriveKeysTests(unittest.TestCase):
    def test_shape(self):
        keys = derive_keys.derive_keys(bytes.fromhex("95DAB102"))
        self.assertEqual(len(keys), 16)
        self.assertTrue(all(len(k) == 6 for k in keys))
        self.assertEqual(len(set(keys)), 16)

    def test_deterministic_and_uid_dependent(self):
        a = derive_keys.derive_keys(bytes.fromhex("95DAB102"))
        self.assertEqual(a, derive_keys.derive_keys(bytes.fromhex("95DAB102")))
        self.assertNotEqual(a, derive_keys.derive_keys(bytes.fromhex("15C4C9A3")))

    def test_parse_uid_formats(self):
        for text in ("95 DA B1 02", "95:da:b1:02", "95DAB102"):
            self.assertEqual(derive_keys.parse_uid(text), bytes.fromhex("95DAB102"))

    def test_parse_uid_rejects_bad_input(self):
        for text in ("95 DA B1", "zz zz zz zz", "95 DA B1 02 03"):
            with self.assertRaises(ValueError):
                derive_keys.parse_uid(text)


if __name__ == "__main__":
    unittest.main()
