"""Target-bound static proof and corruption controls; no captured execution."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research/work-items/RE-001-node115-tokenid-tree-value"
spec = importlib.util.spec_from_file_location("tokenid_tree_value", PACKET / "verify_target.py")
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)

# (excerpt name, VA, size) for every byte range facts() pins.
SEMANTIC_RANGES = {
    "insert_dispatch": [(0x3f19f1c, 4), (0x3f19f20, 2), (0x3f19f22, 3),
                        (0x3f19f25, 4), (0x3f19f29, 4), (0x3f19f3c, 3),
                        (0x3f19f3f, 5), (0x3f19f44, 5), (0x3f19f5a, 4),
                        (0x3f19f5e, 4), (0x3f19f62, 4), (0x3f19f66, 4),
                        (0x3f19f6a, 5), (0x3f19f6f, 3), (0x3f19f72, 3),
                        (0x3f19f75, 3), (0x3f19f78, 5), (0x3f19f7d, 5),
                        (0x3f19f82, 2), (0x3f19f84, 3), (0x3f19f87, 4),
                        (0x3f19f8b, 5)],
    "tree_insert_entry_alloc": [(0x370690b, 3), (0x370690e, 3), (0x3706914, 5),
                                (0x3706919, 2), (0x370691b, 4), (0x3706930, 5),
                                (0x370694d, 3), (0x3706953, 5), (0x370696c, 3),
                                (0x370696f, 5), (0x3706974, 6), (0x370697f, 11),
                                (0x370698a, 9), (0x37069a0, 7), (0x37069a7, 4),
                                (0x37069ab, 2), (0x37069ad, 3), (0x37069b0, 7),
                                (0x37069b7, 2), (0x37069b9, 3), (0x37069bc, 5),
                                (0x37069c1, 4), (0x37069c5, 8), (0x37069cd, 2),
                                (0x37069cf, 5)],
    "recursive_entry_slot": [(0x34f9d71, 3), (0x34f9d74, 3), (0x34f9d77, 8),
                             (0x34f9d7f, 4), (0x34f9d83, 2), (0x34f9d85, 4),
                             (0x34f9d89, 4), (0x34f9d8d, 3), (0x34f9d90, 4),
                             (0x34f9d94, 3), (0x34f9d97, 3), (0x34f9d9a, 2),
                             (0x34f9d9c, 3), (0x34f9d9f, 4), (0x34f9da3, 5)],
    "recursive_value_store": [(0x34f9e43, 4), (0x34f9e47, 3), (0x34f9e54, 2),
                              (0x34f9e56, 8), (0x34f9e5e, 8)],
    "value_address": [(0x3f1a750, 3), (0x3f1a753, 3), (0x3f1a756, 2),
                      (0x3f1a758, 4), (0x3f1a75c, 4), (0x3f1a760, 6),
                      (0x3f1a767, 4), (0x3f1a76b, 4), (0x3f1a76f, 4),
                      (0x3f1a773, 2), (0x3f1a775, 4), (0x3f1a779, 3),
                      (0x3f1a77c, 2), (0x3f1a77e, 3), (0x3f1a781, 4),
                      (0x3f1a785, 4), (0x3f1a789, 3), (0x3f1a78c, 4),
                      (0x3f1a790, 4), (0x3f1a794, 4)],
    "lookup_vacant_id": [(0x3cd3d3f, 2), (0x3cd3d41, 3), (0x3cd3d44, 4),
                         (0x3cd3d48, 5), (0x3cd3d4d, 4), (0x3cd3d51, 5),
                         (0x3cd3d56, 5), (0x3cd3d5b, 6), (0x3cd3d61, 6),
                         (0x3cd3d67, 2), (0x3cd3d69, 3), (0x3cd3d6c, 4),
                         (0x3cd3d70, 4), (0x3cd3d74, 4), (0x3cd3d78, 3)],
    "lookup_convert_id": [(0x3cd3b94, 3), (0x3cd3b97, 6), (0x3cd3b9d, 4),
                          (0x3cd3ba1, 2), (0x3cd3ba3, 4), (0x3cd3ba7, 5),
                          (0x3cd3bac, 5), (0x3cd3bb1, 8), (0x3cd3bb9, 4),
                          (0x3cd3bbd, 5), (0x3cd3bc2, 3)],
}


class TreeValueProof(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pins = json.loads((PACKET / "discovery.json").read_text())
        cls.excerpts = {e["name"]: e for e in cls.pins["excerpts"]}

    def _excerpts_with(self, name, window):
        excerpts = json.loads(json.dumps(self.pins["excerpts"]))
        for e in excerpts:
            if e["name"] == name:
                e["raw_hex"] = window.hex()
        return excerpts

    def test_real_target_replay(self):
        result = helper.verify((ROOT / "artifacts/node/115/hl-node").read_bytes(),
                               self.pins)
        self.assertEqual(result["tree_value"], "incoming index at node+0xb8+slot*8")
        self.assertEqual(result["tree_key"], "16-byte id at node+slot*16")
        self.assertEqual(result["flat_value"], "incoming rdx at entry+0x10")

    def test_digest_rejects_before_native_tools(self):
        with self.assertRaisesRegex(ValueError, "target digest"):
            helper.verify(b"not the target", self.pins, True, Path("never-executed"))

    def test_fde_pin_corruption(self):
        pins = json.loads(json.dumps(self.pins))
        pins["fdes"]["tree_insert"]["fde_record_hex"] = (
            "00" + pins["fdes"]["tree_insert"]["fde_record_hex"][2:])
        with self.assertRaisesRegex(ValueError, "FDE record"):
            helper.verify((ROOT / "artifacts/node/115/hl-node").read_bytes(), pins)

    def test_each_semantic_instruction_byte_flip(self):
        # These controls call the small fragment decoder, not the digest-first CLI.
        checked = 0
        for name, ranges in SEMANTIC_RANGES.items():
            e = self.excerpts[name]
            window = bytearray(bytes.fromhex(e["raw_hex"]))
            base = int(e["start"], 16)
            for va, size in ranges:
                for i in range(va - base, va - base + size):
                    for bit in range(8):
                        corrupt = bytearray(window)
                        corrupt[i] ^= 1 << bit
                        with self.subTest(excerpt=name, offset=i, bit=bit):
                            with self.assertRaises(ValueError):
                                helper.facts(self._excerpts_with(name, corrupt))
                        checked += 1
        self.assertGreater(checked, 0)


if __name__ == "__main__":
    unittest.main()
