"""Static and corruption controls for the selected inspected-precompile path."""
import csv
import hashlib
import io
import json
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import inspected_precompile94 as subject


class Overlay:
    """Read-only, single-byte mutation over an authenticated image."""

    def __init__(self, image, position, xor=1):
        self.image = image
        self.secs = image.secs
        self.position = position
        self.xor = xor

    def read(self, va, size):
        out = bytearray(self.image.read(va, size))
        if va <= self.position < va + size:
            out[self.position - va] ^= self.xor
        return bytes(out)

    def s32(self, va):
        return struct.unpack("<i", self.read(va, 4))[0]

    def u64(self, va):
        return struct.unpack("<Q", self.read(va, 8))[0]

    def offset(self, va, size=1):
        return self.image.offset(va, size)

    def relative_relocations(self):
        return self.image.relative_relocations()


def rows(files, name):
    return list(csv.DictReader(io.StringIO(files[name].decode("ascii")), delimiter="\t"))


def probe_equal_20(left, right):
    """Synthetic model of the selected 16-lane comparison and four-byte AND."""
    if len(left) != 20 or len(right) != 20:
        raise ValueError("key must contain exactly 20 bytes")
    head = [a == b for a, b in zip(left[:16], right[:16])]
    tail = [a == b for a, b in zip(left[16:], right[16:])]
    return all(head[i] and (i >= 4 or tail[i]) for i in range(16))


def reserve_hint(remaining, count):
    """Synthetic model of the 64-bit LEA/shift/conditional move sequence."""
    limit = (1 << 64) - 1
    if not 0 <= remaining <= limit or not 0 <= count <= limit:
        raise ValueError("operands must be unsigned 64-bit values")
    return remaining if count == 0 else ((remaining + 1) & limit) >> 1


class InspectedPrecompileStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = subject.Image(subject.TARGET.read_bytes())
        cls.files = subject.collect(cls.image)
        cls.fdes = {int(r["start_va"], 16): r for r in rows(cls.files, "functions.tsv")}

    def test_target_digest_rejects_other_bytes(self):
        known = hashlib.sha256(b"abc").hexdigest()
        self.assertEqual(subject.checked_digest(b"abc", known), known)
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            subject.checked_digest(b"abd", known)
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            subject.Image(b"not an ELF")

    def test_selected_function_extents_are_fde_bound(self):
        self.assertEqual(len(self.fdes), 15)
        fde = self.fdes[0x37FFA30]
        self.assertEqual(int(fde["end_va"], 16), 0x37FFC4E)
        self.assertEqual(int(fde["bytes"]), 542)
        self.assertEqual(fde["sha256"], "f4e21417b75aa30929530ec2366df6c70a4d808ed7e54b3759efcb60fec6b464")
        self.assertEqual(self.fdes[0x37DC350]["sha256"],
                         "40068e10c426c5a5e1229194d30f858ffd55f54482256d9c0a774cc5477b4164")
        self.assertNotIn(0x32AE320, self.fdes)
        self.assertNotIn(0x3268CE0, self.fdes)
        self.assertNotIn(0x4E9D2A0, self.fdes)

    def test_file_offsets_and_elf_identity(self):
        self.assertEqual(self.image.offset(0x37FFA30, 1), 0x37FEA30)
        self.assertEqual(self.image.read(0x37FFA30, 1), b"\x55")
        for fde in self.fdes.values():
            start = int(fde["start_va"], 16)
            end = int(fde["end_va"], 16)
            self.assertLess(start, end)
            self.assertEqual(end - start, int(fde["bytes"]))
            self.assertEqual(hashlib.sha256(self.image.read(start, end - start)).hexdigest(), fde["sha256"])

    def test_corrupt_unwind_start_rejects_the_selected_fde(self):
        altered = bytearray(self.image.data)
        encoded_start = self.image.offset(0x11AE220 + 8, 4)
        altered[encoded_start] ^= 1
        fake = object.__new__(subject.Image)
        fake.data = bytes(altered)
        fake.secs = self.image.secs
        fake._relas = None
        with self.assertRaisesRegex(ValueError, "selected FDE"):
            subject.unwind_records(fake)

    def test_nobits_cross_section_and_outside_rejected(self):
        with self.assertRaises(ValueError):
            self.image.read(0x5788348, 8)
        text = next(s for s in self.image.secs if s["name"] == ".text")
        with self.assertRaises(ValueError):
            self.image.read(text["address"] + text["size"] - 1, 2)
        with self.assertRaises(ValueError):
            self.image.read(0, 0)
        with self.assertRaises(ValueError):
            self.image.read((1 << 64) - 1, 2)

    def test_ambiguous_and_non_file_sections_rejected(self):
        sec = {"type": 1, "flags": 2, "address": 16, "offset": 0, "size": 8}
        self.assertEqual(subject.file_offset([sec], 8, 18, 2), 2)
        with self.assertRaises(ValueError):
            subject.file_offset([sec, dict(sec)], 8, 18, 2)
        with self.assertRaises(ValueError):
            subject.file_offset([{**sec, "type": 8}], 8, 18, 2)
        with self.assertRaises(ValueError):
            subject.file_offset([{**sec, "flags": 0}], 8, 18, 2)
        with self.assertRaises(ValueError):
            subject.file_offset([sec], 3, 18, 2)

    def test_every_reviewed_window_rejects_changed_bytes(self):
        self.assertEqual(len(subject.PINS), 64)
        for name, va, expected in subject.PINS:
            with self.subTest(window=name):
                raw = bytes.fromhex(expected)
                self.assertEqual(subject.checked_bytes(self.image, va, raw), raw)
                for p in sorted({va, va + len(raw) // 2, va + len(raw) - 1}):
                    with self.assertRaises(ValueError):
                        subject.checked_bytes(Overlay(self.image, p), va, raw)

    def test_every_selected_control_displacement_is_required(self):
        self.assertEqual(len(subject.EDGES), 71)
        for name, va, target in subject.EDGES:
            with self.subTest(edge=name):
                decoded = subject.checked_control(self.image, va, target)
                length = len(bytes.fromhex(decoded["bytes"]))
                with self.assertRaises(ValueError):
                    subject.checked_control(Overlay(self.image, va + length - 1), va, target)

    def test_control_decoder_rejects_unsupported_shape(self):
        with self.assertRaises(ValueError):
            subject.decode_control(Overlay(self.image, 0x37DE295, xor=0xE8), 0x37DE295)
        with self.assertRaises(ValueError):
            subject.checked_control(self.image, 0x37DE295, 0x37FD851)

    def test_relocation_corruption_and_wrong_type(self):
        slot, target = 0x570A7D8, 0x37FFA30
        raw = struct.pack("<QQq", slot, 8, target)
        record = (8, target, 24, raw)
        self.assertEqual(subject.checked_relative(record, slot, target)["addend"], target)
        for offset in (0, 8, 16):
            corrupt = bytearray(raw)
            corrupt[offset] ^= 1
            with self.subTest(offset=offset):
                with self.assertRaises(ValueError):
                    subject.checked_relative((8, target, 24, bytes(corrupt)), slot, target)
        bad_info = (1 << 32) | 8
        with self.assertRaises(ValueError):
            subject.checked_relative((bad_info, target, 24, struct.pack("<QQq", slot, bad_info, target)), slot)
        with self.assertRaises(ValueError):
            subject.checked_relative(None, slot)
        with self.assertRaises(ValueError):
            subject.checked_relative(record, slot, target + 1)

    def test_copy_import_symbol_and_corruption(self):
        copy = subject.dynamic_import(self.image, 0x576DFE0, "memcpy")
        self.assertEqual(copy["symbol_index"], 6)
        self.assertEqual(copy["name"], "memcpy")
        self.assertEqual(copy["slot"], 0x576DFE0)
        for changed in (copy["name_va"], copy["symbol_va"] + 4, copy["slot"]):
            with self.subTest(changed=changed):
                with self.assertRaises(ValueError):
                    subject.dynamic_import(Overlay(self.image, changed), 0x576DFE0, "memcpy")
        for info, addend in ((6, 0), ((6 << 32) | 8, 0), ((6 << 32) | 6, 1)):
            raw = struct.pack("<QQq", 0x576DFE0, info, addend)
            with self.assertRaises(ValueError):
                subject.checked_global((info, addend, 0, raw), 0x576DFE0)

    def test_vtables_bind_distinct_stages(self):
        table = rows(self.files, "descriptors.tsv")
        methods = {(x["name"], x["method_offset"]): int(x["target_va"], 16) for x in table}
        self.assertEqual(methods[("private_provider", "0x28")], 0x3268CE0)
        self.assertEqual(methods[("inspection_callback", "0x28")], 0x37FFA30)
        self.assertEqual(methods[("inspection_callback", "0x18")], 0x37F3A00)
        self.assertEqual(methods[("revision12_inner_callback", "0x28")], 0x3287AD0)
        self.assertEqual(methods[("hook", "0x20")], 0x37E1590)
        self.assertEqual(methods[("hook", "0x18")], 0x37F3CA0)
        self.assertEqual(subject.relative(self.image, 0x5774020, 0x37DC350)["addend"], 0x37DC350)
        with self.assertRaises(ValueError):
            subject.relative(self.image, 0x5774020, 0x37DC351)

    def test_all_revision_bytes_and_canonical_boundaries(self):
        table = rows(self.files, "revision-cases.tsv")
        self.assertEqual(len(table), 256)
        expected = ([0, 0, 2, 2, 4, 5, 6, 8, 8, 9, 9, 11, 12, 12, 12, 15, 16, 17, 18, 19]
                    + [255] * 236)
        self.assertEqual([int(x["requested_byte"]) for x in table], list(range(256)))
        self.assertEqual([int(x["canonical_byte"]) for x in table], expected)
        for i in (12, 13, 14):
            self.assertEqual(int(table[i]["group4_va"], 16), 0x32CE340)
        self.assertNotEqual(int(table[11]["group4_va"], 16), 0x32CE340)
        self.assertEqual(int(table[20]["case_va"], 16), int(table[255]["case_va"], 16))

    def test_revision_table_corruption_rejected(self):
        owner = {"start": 0x37FD850, "end": int(self.fdes[0x37FD850]["end_va"], 16)}
        with self.assertRaises(ValueError):
            subject.revision_cases(Overlay(self.image, 0x59A880 + 4 * 12), owner)
        with self.assertRaises(ValueError):
            subject.revision_cases(Overlay(self.image, 0x37FD86F), owner)
        with self.assertRaises(ValueError):
            subject.revision_cases(Overlay(self.image, 0x37FD8FE), owner)

    def test_callback_pairs_and_allocation_failures(self):
        pairs = rows(self.files, "callback-pairs.tsv")
        failures = rows(self.files, "callback-allocation-failures.tsv")
        self.assertEqual(len(pairs), 11)
        self.assertEqual(len(failures), 11)
        self.assertEqual([int(p["output_vtable_offset"], 16) for p in pairs], list(range(8, 0xA9, 16)))
        self.assertEqual(pairs[2]["descriptor_va"], "0x56e7120")
        self.assertEqual(pairs[2]["method_plus_28_va"], "0x3287ad0")
        self.assertEqual({int(x["requested_bytes"]) for x in failures}, {16})
        self.assertEqual(len({x["null_target_va"] for x in failures}), 11)

    def test_callback_constructor_corruption_rejected(self):
        owner = {"start": 0x32CE340, "size": int(self.fdes[0x32CE340]["bytes"]),
                 "end": int(self.fdes[0x32CE340]["end_va"], 16)}
        for position in (0x32CE5FC, 0x32CE362):
            with self.subTest(position=position):
                with self.assertRaises(ValueError):
                    subject.callback_records(Overlay(self.image, position), owner)

    def test_wrapper_installation_is_distinct_from_inner_callback(self):
        table = rows(self.files, "installed-wrappers.tsv")
        self.assertEqual(len(table), 7)
        selected = next(x for x in table if x["handler_vtable_offset"] == "0x110")
        self.assertEqual(selected["handler_data_offset"], "0x108")
        self.assertEqual(selected["descriptor_va"], "0x570a7b0")
        self.assertEqual(selected["method_plus_28_va"], "0x37ffa30")
        owner = {"start": 0x37E1590, "end": int(self.fdes[0x37E1590]["end_va"], 16)}
        with self.assertRaises(ValueError):
            subject.installed_wrappers(Overlay(self.image, 0x37E192B), owner)

    def test_cross_function_layout_and_synthetic_address_fixture(self):
        layout = json.loads(self.files["layout.json"])
        builder, snap = layout["builder"], layout["snapshot"]
        self.assertEqual((builder["handler_factory_data_offset"], builder["handler_factory_vtable_offset"]),
                         (0x48, 0x50))
        self.assertEqual((builder["handler_callback_data_offset"], builder["handler_callback_vtable_offset"]),
                         (0x108, 0x110))
        self.assertEqual((builder["handler_result_data_offset"], builder["handler_result_vtable_offset"]),
                         (0xC8, 0xD0))
        self.assertEqual((builder["handler_post_data_offset"], builder["handler_post_vtable_offset"]),
                         (0xD8, 0xE0))
        self.assertEqual(builder["context_registry_offset"], 0xE8)
        self.assertEqual(builder["context_address_set_offset"], 0x80)
        self.assertEqual(layout["installer"], {
            "opcode_array_offset": 0x198, "opcode_stride": 16, "opcode_span": 4096,
            "opcode_pair_count": 256, "extra_opcode_first": 160,
            "extra_opcode_last": 164, "extra_opcode_count": 5})
        self.assertEqual((snap["frame_bytes"], snap["address_source_offset"], snap["address_length"]),
                         (160, 96, 20))
        fixture = bytes.fromhex("00" * 19 + "09")
        frame = bytearray(snap["frame_bytes"])
        first, last = snap["address_source_offset"], snap["address_last_word_offset"]
        frame[first:first + 20] = fixture
        address_copy = bytes(frame[first:first + 16] + frame[last:last + 4])
        self.assertEqual(address_copy, fixture)
        self.assertTrue(probe_equal_20(address_copy, fixture))
        for bit in range(160):
            altered = bytearray(fixture)
            altered[bit // 8] ^= 1 << (bit % 8)
            self.assertFalse(probe_equal_20(address_copy, bytes(altered)))
        with self.assertRaises(ValueError):
            probe_equal_20(fixture[:-1], fixture)

    def test_snapshot_copy_length_and_address_displacements_are_required(self):
        callback_table, _ = subject.callback_records(
            self.image, {"start": 0x32CE340, "size": int(self.fdes[0x32CE340]["bytes"]),
                         "end": int(self.fdes[0x32CE340]["end_va"], 16)})
        wrappers = subject.installed_wrappers(
            self.image, {"start": 0x37E1590, "end": int(self.fdes[0x37E1590]["end_va"], 16)})
        for position in (0x37FFAA7, 0x37FFA9C, 0x37FFB2D, 0x37DE9DC):
            with self.subTest(position=position):
                with self.assertRaises(ValueError):
                    subject.collect_layout(Overlay(self.image, position), callback_table, wrappers)

    def test_set_path_compares_all_twenty_bytes(self):
        windows = {x["name"]: x["bytes"] for x in rows(self.files, "semantic-windows.tsv")}
        probe = bytes.fromhex(windows["set_insert_probe"])
        self.assertIn(bytes.fromhex("f30f6f1e"), probe)  # first 16 bytes
        self.assertIn(bytes.fromhex("660f6e5e10"), probe)  # final four bytes
        self.assertIn(bytes.fromhex("81fdffff0000"), probe)  # all comparison lanes
        edges = {x["name"]: x for x in rows(self.files, "control-edges.tsv")}
        self.assertEqual(edges["set_existing_key"]["target_or_slot_va"], "0x379c367")
        self.assertEqual(edges["set_empty_growth_budget"]["target_or_slot_va"], "0x379c372")

    def test_result_four_packages_and_returns_through_selected_cleanup(self):
        edges = {x["name"]: x for x in rows(self.files, "control-edges.tsv")}
        self.assertEqual(edges["builder_callback_result_four"]["target_or_slot_va"], "0x37df09a")
        self.assertEqual(edges["builder_callback_four_common_handler"]["target_or_slot_va"], "0x37dea7d")
        self.assertEqual(edges["builder_post_callback_result_other"]["target_or_slot_va"], "0x37dec34")
        self.assertEqual(edges["builder_result_return"]["target_or_slot_va"], "0x37dee7a")
        windows = {x["name"]: x["bytes"] for x in rows(self.files, "semantic-windows.tsv")}
        self.assertEqual(windows["result_sentinel"], "49bc0200000000000080")
        self.assertTrue(windows["builder_epilogue"].endswith("c3"))

    def test_set_growth_guard_and_iterator_edges(self):
        layout = json.loads(self.files["layout.json"])["address_set"]
        self.assertEqual(layout, {"iterator_remaining_offset": 56, "key_width": 20,
                                  "set_count_offset": 24, "set_growth_offset": 16})
        edges = {x["name"]: x for x in rows(self.files, "control-edges.tsv")}
        self.assertEqual(edges["context_set_reserve"]["target_or_slot_va"], "0x36e35c6")
        self.assertEqual(edges["context_set_extend"]["target_or_slot_va"], "0x3be3e90")
        self.assertEqual(edges["context_set_insert"]["target_or_slot_va"], "0x379c1d0")
        maximum = (1 << 64) - 1
        for remaining, count, expected in ((0, 0, 0), (1, 1, 1), (2, 1, 1),
                                           (3, 1, 2), (maximum, 0, maximum), (maximum, 1, 0)):
            with self.subTest(remaining=remaining, count=count):
                self.assertEqual(reserve_hint(remaining, count), expected)
        for remaining, count in ((-1, 0), (1 << 64, 1), (0, -1)):
            with self.assertRaises(ValueError):
                reserve_hint(remaining, count)

    def test_lsda_records_bind_failure_landings(self):
        table = rows(self.files, "exception-sites.tsv")
        def find_site(site):
            return next(row for row in table
                        if int(row["start_va"], 16) <= site < int(row["end_va"], 16))
        self.assertEqual(find_site(0x37E1CF0)["landing_va"], "0x37e1e4a")
        self.assertEqual(find_site(0x37FFA94)["landing_va"], "0x37ffc13")
        self.assertEqual(find_site(0x37FFB48)["landing_va"], "0x37ffc00")
        self.assertEqual(find_site(0x37FFBF8)["landing_va"], "0x37ffc2c")
        self.assertEqual(find_site(0x37F3A0A)["landing_va"], "0x37f3a64")
        self.assertEqual(find_site(0x37F3A1A)["landing_va"], "0x37f3a42")
        self.assertEqual(len(table), 403)

    def test_lsda_parser_rejects_truncation_and_outside_landing(self):
        good = bytes.fromhex("ffff010401020300")
        decoded, header = subject.decode_lsda(good, 0, len(good), 100, 110)
        self.assertEqual((decoded[0]["start"], decoded[0]["end"], decoded[0]["landing"]), (101, 103, 103))
        self.assertEqual(header["callsite_encoding"], 1)
        for raw in (good[:-1], bytes.fromhex("ffff010401028000"),
                    bytes.fromhex("ffff010401020b00"), bytes.fromhex("feff010401020300"),
                    bytes.fromhex("ffff020401020300")):
            with self.subTest(raw=raw.hex()):
                with self.assertRaises(ValueError):
                    subject.decode_lsda(raw, 0, len(raw), 100, 110)

    def test_retained_generated_files_match_byte_for_byte(self):
        evidence = ROOT / "research/work-items/RE-021-inspected-precompile-path-94"
        self.assertEqual(len(self.files), 17)
        for name, expected in sorted(self.files.items()):
            with self.subTest(name=name):
                self.assertEqual((evidence / name).read_bytes(), expected)

    def test_summary_is_a_selected_corpus_not_a_gate(self):
        summary = json.loads(self.files["summary.json"])
        self.assertEqual(summary["target_sha256"], subject.TARGET_SHA256)
        self.assertEqual(summary["counts"]["selected_fde_bytes"], 31903)
        self.assertEqual(summary["counts"]["lsda_records_with_landing"], 337)
        self.assertIn("no execution", summary["limitations"])


if __name__ == "__main__":
    unittest.main()
