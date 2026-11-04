"""Static and synthetic controls for the node 115 address-set packet."""

import json
import itertools
import tempfile
import unittest
from pathlib import Path

from tools import re21_address_set115 as packet


class Overlay:
    """Change one byte as seen by a predicate without copying the ELF."""

    def __init__(self, image, address, xor=1):
        self.image = image
        self.address = address
        self.xor = xor

    def locate(self, *args, **kwargs):
        return self.image.locate(*args, **kwargs)

    def read(self, va, size):
        out = bytearray(self.image.read(va, size))
        if va <= self.address < va + size:
            out[self.address - va] ^= self.xor
        return bytes(out)


def limb_fold(a, b):
    """Independent 32-bit-limb multiplication oracle for fold64."""
    lo_mask = (1 << 32) - 1
    a0, a1 = a & lo_mask, a >> 32
    b0, b1 = b & lo_mask, b >> 32
    p0 = a0 * b0
    mid = (p0 >> 32) + a1 * b0 + a0 * b1
    low = ((mid & lo_mask) << 32) | (p0 & lo_mask)
    high = (a1 * b1 + (mid >> 32)) & packet.MASK
    return low ^ high


def hash_oracle(key, seed, secret):
    words = [int.from_bytes(key[:8], "little"), int.from_bytes(key[8:16], "little"),
             int.from_bytes(key[16:], "little")]
    first = limb_fold(words[0] ^ seed, words[1] ^ secret)
    return limb_fold(first ^ words[2], secret)


class AddressSetEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = packet.TARGET.read_bytes()
        packet.authenticate(cls.data)
        cls.image = packet.Image(cls.data)
        cls.tmp = tempfile.TemporaryDirectory()
        cls.out = Path(cls.tmp.name)
        cls.summary = packet.generate(cls.data, cls.out)
        cls.relocs = packet.collect_relocs(cls.image)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_generation_matches_packaged_evidence(self):
        expected = packet.ROOT / "research/work-items/RE-021-address-set-growth-115"
        names = {"constants.json", "edges.tsv", "exception-headers.json", "exception-sites.tsv",
                 "functions.json", "handoff.json", "relocations.tsv", "rip-references.tsv",
                 "summary.json", "windows.tsv"}
        self.assertEqual({p.name for p in self.out.iterdir()}, names)
        for name in sorted(names):
            with self.subTest(name=name):
                self.assertEqual((self.out / name).read_bytes(), (expected / name).read_bytes())

    def test_selection_and_real_fdes(self):
        self.assertEqual(self.summary["selected_fdes"], 8)
        self.assertEqual(self.summary["selected_fde_bytes"], 2974)
        self.assertEqual(self.summary["lsda_tables"], 2)
        self.assertEqual(self.summary["lsda_call_sites"], 8)
        rows = json.loads((self.out / "functions.json").read_text())
        self.assertEqual({int(r["start_va"], 16) for r in rows}, {r[0] for r in packet.FUNCTIONS})
        for row in rows:
            self.assertEqual(len(bytes.fromhex(row["body_bytes"])), row["size"])

    def test_changed_binary_hash_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            packet.authenticate(self.data[:-1] + bytes([self.data[-1] ^ 1]))

    def test_changed_historical_hash_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "node 94 SHA-256 mismatch"):
            packet.compare_legacy(b"altered historical capture", self.data)

    def test_non_file_backed_secret_is_not_readable(self):
        with self.assertRaises(ValueError):
            self.image.read(0x64FFE90, 1)
        section, _ = self.image.locate(0x64FFE90, 8, file_backed=False)
        self.assertEqual(section["type"], 8)

    def test_unknown_address_and_cross_section_read_are_rejected(self):
        with self.assertRaises(ValueError):
            self.image.read(0, 1)
        section = self.image.section(".text")
        with self.assertRaises(ValueError):
            self.image.read(section["address"] + section["size"] - 1, 2)
        with self.assertRaises(ValueError):
            self.image.read(-1, 1)
        with self.assertRaises(ValueError):
            self.image.read(section["address"], 0)

    def test_instruction_byte_corruption_fails_body_digest(self):
        start, _, digest = next(x for x in packet.FUNCTIONS if x[0] == 0x5C06630)
        body = next(r for r in json.loads((self.out / "functions.json").read_text())
                    if r["start_va"] == hex(start))
        end = int(body["end_va_exclusive"], 16)
        with self.assertRaisesRegex(ValueError, "body mismatch"):
            packet.check_body(Overlay(self.image, 0x5C06698), start, end, digest)

    def test_corrupt_branch_opcode_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "opcode mismatch"):
            packet.branch(Overlay(self.image, 0x5C06667), 0x5C06667, "e8")

    def test_corrupt_branch_displacement_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "target mismatch"):
            packet.branch(Overlay(self.image, 0x5C06668), 0x5C06667, "e8", 0x5C394A0)

    def test_unsupported_branch_encoding_is_rejected(self):
        with self.assertRaises(ValueError):
            packet.branch(self.image, 0x5C06667, "90")

    def test_corrupt_rip_opcode_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "RIP-relative opcode"):
            packet.rip(Overlay(self.image, 0x5C067A7), 0x5C067A7, "ff15")

    def test_bridge_reassembles_fourth_record(self):
        bridge = packet.collect_bridge(self.image, self.relocs)
        self.assertEqual(bridge["array_index"], 3)
        self.assertEqual(bridge["record_stride"], 56)
        self.assertEqual(bridge["copy_size"], 224)
        self.assertEqual(bridge["set_offset_in_registry"], 40)
        self.assertEqual(bridge["parent_growth_offset_in_set"], 16)
        self.assertEqual(bridge["parent_seed_offset_in_set"], 32)
        self.assertEqual(bridge["parent_growth_threshold"], 3)
        self.assertEqual(bridge["parent_reserve_additional"], 4)
        self.assertEqual(bridge["key_bytes"], "00" * 19 + "09")
        self.assertEqual(bridge["parent_reserve_slot"], "0x64ec338")
        self.assertNotEqual(bridge["record_tag"], bridge["skipped_tag"])

    def test_corrupt_bridge_instruction_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "predicate mismatch"):
            packet.collect_bridge(Overlay(self.image, 0x5C1894B), self.relocs)

    def test_corrupt_bridge_record_key_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "source record predicate"):
            packet.collect_bridge(Overlay(self.image, 0x64C0763), self.relocs)

    def test_selected_relocation_has_expected_addend(self):
        relocs = {row[0]: row for row in self.relocs}
        self.assertEqual(relocs[0x64EC338][3], 0x5C06B20)
        self.assertEqual(relocs[0x64C0748][3], 0x5C165B0)
        self.assertEqual(relocs[0x64DFA78][3], 0x64FFE90)
        self.assertEqual(relocs[0x64DF508][4], "memcpy")
        self.assertEqual(relocs[0x64DF568][4], "memmove")
        self.assertEqual(relocs[0x64DF750][4], "memset")

    def test_mutated_relocation_addend_is_rejected(self):
        data = bytearray(self.data)
        entry = next(row for row in self.relocs if row[0] == 0x64EC338)
        data[entry[5] + 16] ^= 1
        with self.assertRaisesRegex(ValueError, "relocation mismatch"):
            packet.collect_relocs(packet.Image(data))

    def test_duplicate_selected_relocation_is_rejected(self):
        data = bytearray(self.data)
        entry = next(row for row in self.relocs if row[0] == 0x64EC338)
        pos = entry[5]
        data[pos + 24:pos + 48] = data[pos:pos + 24]
        with self.assertRaisesRegex(ValueError, "duplicate selected relocation"):
            packet.collect_relocs(packet.Image(data))

    def test_mutated_dynamic_symbol_is_rejected(self):
        data = bytearray(self.data)
        strings = self.image.section(".dynstr")
        begin = strings["offset"]
        end = begin + strings["size"]
        at = data.find(b"memcpy\0", begin, end)
        self.assertGreaterEqual(at, begin)
        data[at] ^= 1
        with self.assertRaisesRegex(ValueError, "relocation mismatch"):
            packet.collect_relocs(packet.Image(data))

    def test_unwind_record_length_corruption_is_rejected(self):
        rows = json.loads((self.out / "functions.json").read_text())
        fde = int(rows[0]["fde_va"], 16)
        with self.assertRaises(ValueError):
            packet.record_bytes(Overlay(self.image, fde + 3), fde)

    def test_unwind_range_corruption_is_rejected(self):
        start, _, digest = packet.FUNCTIONS[0]
        with self.assertRaises(ValueError):
            packet.check_body(self.image, start, start, digest)
        with self.assertRaises(ValueError):
            packet.check_body(self.image, start, start + 1, digest)

    def test_lsda_header_corruption_is_rejected(self):
        headers = json.loads((self.out / "exception-headers.json").read_text())
        header = headers[0]
        data = bytearray(self.data)
        data[int(header["file_offset"], 16)] = 0
        fde = {"start": 0x5C05E70, "end": 0x5C060FE, "lsda": 0x3FD598}
        with self.assertRaisesRegex(ValueError, "LPStart"):
            packet.parse_lsda(packet.Image(data), fde)

    def test_lsda_wrong_fde_range_is_rejected(self):
        fde = {"start": 0x5C05E70, "end": 0x5C05E80, "lsda": 0x3FD598}
        with self.assertRaisesRegex(ValueError, "exceeds FDE"):
            packet.parse_lsda(self.image, fde)


class AddressSetModels(unittest.TestCase):
    def test_fold_matches_independent_limb_products(self):
        values = (0, 1, (1 << 32) - 1, 1 << 32, (1 << 63), packet.MASK,
                  0x0123456789ABCDEF, 0xFEDCBA9876543210)
        for a in values:
            for b in values:
                with self.subTest(a=a, b=b):
                    self.assertEqual(packet.fold(a, b), limb_fold(a, b))

    def test_hash_all_key_bits_and_seeds(self):
        for bit in range(160):
            key = (1 << bit).to_bytes(20, "little")
            for seed, secret in ((0, 0), (0, packet.MASK), (1, 0x123456789ABCDEF0),
                                 (packet.MASK, 0xFEDCBA9876543210)):
                self.assertEqual(packet.hash20(key, seed, secret), hash_oracle(key, seed, secret))

    def test_address09_tail_is_little_endian_09000000(self):
        key = bytes(19) + b"\x09"
        self.assertEqual(int.from_bytes(key[16:], "little"), 0x09000000)
        seed, secret = 0x123456789ABCDEF0, 0xFEDCBA9876543210
        expected = limb_fold(limb_fold(seed, secret) ^ 0x09000000, secret)
        self.assertEqual(packet.hash20(key, seed, secret), expected)

    def test_bad_hash_inputs_are_rejected(self):
        for key, seed, secret in ((b"", 0, 0), (bytes(21), 0, 0), (bytes(20), -1, 0),
                                  (bytes(20), 0, 1 << 64)):
            with self.subTest(key=key, seed=seed, secret=secret):
                with self.assertRaises(ValueError):
                    packet.hash20(key, seed, secret)

    def test_reservation_thresholds_and_overflow(self):
        self.assertEqual(packet.capacity(3), 3)
        self.assertEqual(packet.capacity(7), 7)
        self.assertEqual(packet.capacity(15), 14)
        self.assertEqual(packet.capacity(31), 28)
        self.assertEqual(packet.reserve_choice(15, 6, 1), "in_place")
        self.assertEqual(packet.reserve_choice(15, 7, 1), "new_table")
        self.assertEqual(packet.reserve_choice(15, 1, packet.MASK), "overflow")
        with self.assertRaises(ValueError):
            packet.reserve_choice(14, 0, 1)
        with self.assertRaises(ValueError):
            packet.reserve_choice(15, 15, 1)
        with self.assertRaises(ValueError):
            packet.capacity(packet.MASK)

    def test_four_record_preflight_budget_under_normal_returns(self):
        for initial in range(4, 21):
            for consumed in itertools.product((0, 1), repeat=4):
                growth = initial
                for take in consumed:
                    self.assertGreater(growth, 0)
                    growth -= take
                self.assertGreaterEqual(growth, 0)

    def test_preflight_rehash_or_growth_provides_four_slots(self):
        for buckets in (4, 8, 16, 32, 64, 128, 256, 512, 1024):
            mask = buckets - 1
            cap = packet.capacity(mask)
            for count in range(cap + 1):
                route = packet.reserve_choice(mask, count, 4)
                if route == "in_place":
                    resulting_capacity = cap
                else:
                    required = max(cap + 1, count + 4)
                    resulting_capacity = packet.capacity(packet.new_bucket_count(required) - 1)
                self.assertGreaterEqual(resulting_capacity - count, 4)

    def test_bucket_rounding_against_capacity_oracle(self):
        for needed in range(65536):
            bucket_count = 4
            while packet.capacity(bucket_count - 1) < needed:
                bucket_count *= 2
            self.assertEqual(packet.new_bucket_count(needed), bucket_count)
        with self.assertRaises(OverflowError):
            packet.new_bucket_count(1 << 61)

    def test_rehash_marks_all_control_bytes(self):
        for value in range(256):
            signed_value = value if value < 128 else value - 256
            reference = 255 if signed_value < 0 else 128
            self.assertEqual(packet.mark_rehash_control(value), reference)
        for value in (-1, 256):
            with self.assertRaises(ValueError):
                packet.mark_rehash_control(value)

    def test_duplicate_is_checked_before_empty_in_same_group(self):
        key = bytes(19) + b"\x09"
        controls = [255, 255, 5] + [255] * 13
        keys = [None, None, key] + [None] * 13
        result = packet.probe_insert(controls, keys, key, 5 << 57, 1)
        self.assertTrue(result["duplicate"])
        self.assertEqual(result["index"], 2)

    def test_all_160_key_bits_participate_in_equality(self):
        key = bytes(19) + b"\x09"
        for bit in range(160):
            other = bytearray(key)
            other[bit // 8] ^= 1 << (bit % 8)
            controls = [5] + [255] * 15
            keys = [bytes(other)] + [None] * 15
            result = packet.probe_insert(controls, keys, key, 5 << 57, 1)
            self.assertFalse(result["duplicate"])
            self.assertEqual(result["index"], 1)

    def test_deleted_bucket_reuse_does_not_consume_growth(self):
        key = bytes(19) + b"\x09"
        result = packet.probe_insert([128, 255] + [255] * 14, [None] * 16, key, 0, 3)
        self.assertFalse(result["duplicate"])
        self.assertEqual((result["index"], result["old_control"], result["growth"]), (0, 128, 3))

    def test_empty_bucket_consumes_one_growth(self):
        key = bytes(19) + b"\x09"
        result = packet.probe_insert([255] * 16, [None] * 16, key, 0, 3)
        self.assertEqual((result["index"], result["old_control"], result["growth"]), (0, 255, 2))

    def test_small_table_padding_falls_back_to_real_empty(self):
        key = bytes(19) + b"\x09"
        controls = [7, 255, 7, 7]
        keys = [bytes(20), None, bytes(20), bytes(20)]
        result = packet.probe_insert(controls, keys, key, (5 << 57) | 2, 1)
        self.assertEqual(result["index"], 1)

    def test_probe_crosses_group_before_empty(self):
        key = bytes(19) + b"\x09"
        controls = [1] * 16 + [255] * 16
        keys = [bytes(20)] * 16 + [None] * 16
        result = packet.probe_insert(controls, keys, key, 2 << 57, 1)
        self.assertEqual(result["index"], 16)

    def test_no_growth_does_not_enter_synthetic_probe(self):
        with self.assertRaises(ValueError):
            packet.probe_insert([255] * 16, [None] * 16, bytes(20), 0, 0)

    def test_invalid_probe_shapes_are_rejected(self):
        key = bytes(20)
        with self.assertRaises(ValueError):
            packet.probe_insert([255] * 3, [None] * 3, key, 0, 1)
        with self.assertRaises(ValueError):
            packet.probe_insert([255] * 16, [None] * 15, key, 0, 1)
        with self.assertRaises(ValueError):
            packet.probe_insert([1] * 16, [key] * 16, key, 0, 1)
        with self.assertRaises(ValueError):
            packet.probe_insert([129] + [255] * 15, [None] * 16, key, 0, 1)


if __name__ == "__main__":
    unittest.main()
