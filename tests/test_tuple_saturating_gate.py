"""Target-grounded static controls for the 0x4d8c270 RE-001 bind."""
import contextlib
import copy
import importlib.util
import json
import mmap
from pathlib import Path
import random
import re
import shutil
import struct
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("tuple_saturating_gate", ROOT / "tools/tuple_saturating_gate.py")
gate = importlib.util.module_from_spec(SPEC)
# dataclasses consults sys.modules when resolving annotations.
import sys
sys.modules[SPEC.name] = gate
SPEC.loader.exec_module(gate)


class TupleSaturatingGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.file = gate.BINARY.open("rb")
        # One private mapping. Controls dirty only the mutated pages, never
        # make full bytearray copies, and restore them before the next test.
        cls.data = mmap.mmap(cls.file.fileno(), 0, access=mmap.ACCESS_COPY)
        cls.image = gate.Image(cls.data)
        cls.generated = gate.outputs(cls.data)
        cls.record = json.loads(cls.generated["records.json"])
        cls.body = cls.image.read(gate.START, gate.END - gate.START)
        cls.insns = gate.check_body(cls.body)

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.file.close()

    @contextlib.contextmanager
    def mutation(self, offset, replacement):
        old = self.data[offset:offset + len(replacement)]
        try:
            self.data[offset:offset + len(replacement)] = replacement
            yield
        finally:
            self.data[offset:offset + len(replacement)] = old

    @contextlib.contextmanager
    def packet_copy(self):
        # Preserve the manifest's relative tool/test locations.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            packet = root / "research/work-items/packet"
            shutil.copytree(gate.PACKET, packet)
            for name in ("tools/tuple_saturating_gate.py", "tests/test_tuple_saturating_gate.py",
                         "tools/elf_index.py", "tools/fde_extents.py"):
                dest = root / name
                dest.parent.mkdir(exist_ok=True)
                shutil.copyfile(ROOT / name, dest)
            yield packet

    def rewrite_manifest(self, packet):
        (packet / "MANIFEST.sha256").write_bytes(gate.manifest_bytes(packet))

    def check_vector(self, left, right, current, base, limit, expected=None):
        args = (left, right, current, base, limit)
        al, expected_rax = gate.model(*args)
        rax, reads = gate.interpret(self.insns, gate.fields_for(*args))
        self.assertEqual(rax, expected_rax)
        self.assertEqual(rax & 0xff, al)
        if expected is not None:
            self.assertEqual(al, expected)
        return rax, reads

    def test_committed_packet_reproduces(self):
        gate.check_packet(gate.PACKET, self.generated)

    def test_byte_identical_second_generation(self):
        self.assertEqual(gate.outputs(self.data), self.generated)

    def test_readme_counts_equal_json_and_regeneration(self):
        text = (gate.PACKET / "README.md").read_text()
        self.assertIn(gate.metrics_table(self.record), text)
        self.assertEqual(text, gate.render_readme(self.record))
        rows = re.findall(r"^\| ([^|]+) \| (\d+) \|$", text, re.M)
        self.assertEqual(len(rows), len(self.record["counts"]))
        self.assertEqual([int(n) for _, n in rows], list(self.record["counts"][key] for key in
                         ("body_bytes", "padding_bytes", "instructions", "callees", "direct_calls",
                          "direct_jumps", "branches", "returns", "writes", "vectors")))

    def test_extent_cie_padding_and_complete_decode(self):
        f = self.record["function"]
        self.assertEqual((f["size"], f["padding_size"]), (104, 8))
        self.assertEqual(f["fde_section_offset"], "0x267a08")
        self.assertEqual(f["cie_section_offset"], "0x0")
        self.assertEqual(b"".join(i.raw for i in self.insns), self.body)
        gate.check_cfg(self.insns)
        self.assertEqual(self.record["callees"], [])

    def test_wrong_digest_fails_closed(self):
        with self.mutation(0, b"X"):
            with self.assertRaisesRegex(ValueError, "target SHA-256"):
                gate.outputs(self.data)

    def test_mutated_window_fails_even_without_whole_digest_check(self):
        raw = bytearray(self.body)
        raw[2] ^= 4  # Change a valid load's field offset.
        with self.assertRaisesRegex(ValueError, "body SHA-256"):
            gate.check_body(raw)

    def test_mutated_actual_window_rejected_by_collection(self):
        off = self.image.offset(gate.START, 1)
        with self.mutation(off, b"\xe8"), mock.patch.object(gate, "check_digest"):
            with self.assertRaisesRegex(ValueError, "body SHA-256"):
                gate.collect(self.data)

    def test_unknown_instruction_rejected(self):
        with self.assertRaisesRegex(ValueError, "unsupported instruction"):
            gate.decode(b"\x90", gate.START)

    def test_truncated_instruction_rejected(self):
        with self.assertRaisesRegex(ValueError, "truncated instruction"):
            gate.decode(b"\x48\x3d\x78", gate.START)

    def test_every_primary_instruction_rejects_partial_encoding(self):
        for insn in self.insns:
            for length in range(1, len(insn.raw)):
                with self.subTest(va=hex(insn.va), length=length), self.assertRaises(ValueError):
                    gate.decode(insn.raw[:length], insn.va)

    def test_branch_into_instruction_rejected(self):
        raw = bytearray(self.body)
        raw[0x11] += 1  # JNE now lands inside TEST AL,AL.
        with self.assertRaisesRegex(ValueError, "branch target"):
            gate.check_cfg(gate.decode(raw, gate.START))

    def test_shifted_fde_association_rejected(self):
        f = copy.deepcopy(self.record["function"])
        f["fde_section_offset"] = "0x267a09"
        with self.assertRaisesRegex(ValueError, "FDE association"):
            gate.check_primary_frame(f)

    def test_actual_fde_start_mutation_rejected(self):
        off = self.image.offset(int(self.record["function"]["fde_va"], 16), 12) + 8
        delta = struct.unpack_from("<i", self.data, off)[0]
        with self.mutation(off, struct.pack("<i", delta + 1)):
            with self.assertRaisesRegex(ValueError, "index/FDE mismatch"):
                gate.read_frames(self.image)

    def test_actual_fde_range_mutation_rejected(self):
        off = self.image.offset(int(self.record["function"]["fde_va"], 16), 16) + 12
        with self.mutation(off, struct.pack("<i", 103)), mock.patch.object(gate, "check_digest"):
            with self.assertRaisesRegex(ValueError, "FDE association"):
                gate.collect(self.data)

    def test_actual_cie_pointer_mutation_rejected(self):
        off = self.image.offset(int(self.record["function"]["fde_va"], 16), 8) + 4
        delta = struct.unpack_from("<I", self.data, off)[0]
        with self.mutation(off, struct.pack("<I", delta + 1)):
            with self.assertRaisesRegex(ValueError, "preceding CIE"):
                gate.read_frames(self.image)

    def test_actual_padding_mutation_rejected(self):
        off = self.image.offset(gate.END, 1)
        with self.mutation(off, b"\x90"), mock.patch.object(gate, "check_digest"):
            with self.assertRaisesRegex(ValueError, "padding"):
                gate.collect(self.data)

    def test_wrong_callee_target_rejected(self):
        site = gate.CALLER_SITES[0]
        raw = self.image.read(site, 5)
        gate.check_callsite(raw, site)
        wrong = b"\xe8" + struct.pack("<i", gate.START + 1 - site - 5)
        with self.assertRaisesRegex(ValueError, "wrong direct callee target"):
            gate.check_callsite(wrong, site)

    def test_full_text_scan_sees_removed_call(self):
        site = gate.CALLER_SITES[0]
        off = self.image.offset(site, 5)
        with self.mutation(off, b"\xe8" + struct.pack("<i", gate.START + 1 - site - 5)):
            rows = gate.scan_callers(self.image, gate.START)
        self.assertEqual(len(rows), 3)
        self.assertNotIn(hex(site), [r["site"] for r in rows])

    def test_full_text_scan_includes_e9_and_noninstruction_patterns(self):
        # An extra pattern in the INT3 gap must not be silently alignment-filtered.
        off = self.image.offset(gate.END, 5)
        raw = b"\xe9" + struct.pack("<i", gate.START - gate.END - 5)
        with self.mutation(off, raw):
            rows = gate.scan_callers(self.image, gate.START)
        self.assertIn(dict(site=hex(gate.END), kind="jump", target=hex(gate.START)), rows)

    def test_location_relocation_and_source_identity(self):
        loc = gate.location_record(self.image)
        self.assertEqual((loc["source_suffix"], loc["line"], loc["column"]), ("l1/src/books.rs", 14, 16))
        lea = gate.decode(self.image.read(0x4c19b52, 7), 0x4c19b52)[0]
        self.assertEqual(lea.args, ("rdx", 0x5742320))

    def test_wrong_location_relocation_rejected(self):
        off = int(self.record["first_party_context"]["relocation_file_offset"], 16) + 16
        addend = struct.unpack_from("<q", self.data, off)[0]
        with self.mutation(off, struct.pack("<q", addend + 1)):
            with self.assertRaisesRegex(ValueError, "wrong Location relocation"):
                gate.location_record(self.image)

    def test_boundary_vectors_match_decoded_instructions(self):
        for note, *values in gate.VECTORS:
            with self.subTest(note=note):
                self.check_vector(*values)

    def test_seeded_full_width_model_comparison(self):
        rng = random.Random(0x4d8c270)
        for index in range(2000):
            left = tuple(rng.getrandbits(32) for _ in range(3))
            right = list(left)
            if index % 4:
                right[index % 3] = rng.getrandbits(32)
            base = rng.choice((rng.getrandbits(64), gate.MASK64 - rng.randrange(10001)))
            current = rng.choice((rng.getrandbits(64), min(base + 5000, gate.MASK64)))
            limit = rng.choice((rng.getrandbits(64), current))
            self.check_vector(left, right, current, base, limit)

    def test_saturation_cutoff_and_unsigned_max(self):
        for base in (gate.MASK64 - 5001, gate.MASK64 - 5000, gate.MASK64 - 4999, gate.MASK64):
            threshold = min(base + 5000, gate.MASK64)
            for current in (threshold - 1, threshold):
                self.check_vector((0, 0, 0), (1, 0, 0), current, base, 0, int(current == threshold))

    def test_full_rax_is_not_canonical_al(self):
        rax, _ = self.check_vector((0x12345678, 0, 0), (0, 0, 0), 0, 0, 0, 2)
        self.assertEqual(rax, 0x12345602)
        rax, _ = self.check_vector((0, 0, 0), (1, 0, 0), 5000, 0, 0, 1)
        self.assertEqual(rax, 0x1301)

    def test_short_circuit_skips_unread_fields(self):
        # These mappings deliberately omit fields that must not be read.
        rax, reads = gate.interpret(self.insns, {0x60: 1, 0x4524: 0, 0x28: 0, 0x4408: 0})
        self.assertEqual(rax & 0xff, 2)
        self.assertEqual(reads, [0x60, 0x28, 0x4524, 0x4408])
        rax, reads = gate.interpret(self.insns, {0x60: 0, 0x4524: 1, 0x28: 5000, 0x10: 0})
        self.assertEqual(rax & 0xff, 1)
        self.assertEqual(reads, [0x60, 0x28, 0x4524, 0x10])

    def test_model_rejects_out_of_range_inputs(self):
        for left, current in (((1 << 32, 0, 0), 0), ((0, 0, 0), -1), ((0, 0, 0), 1 << 64)):
            with self.assertRaises(ValueError):
                gate.model(left, (0, 0, 0), current, 0, 0)

    def test_manifest_corruption_rejected(self):
        with self.packet_copy() as packet:
            (packet / "MANIFEST.sha256").write_text("0" * 64 + "  records.json\n")
            with self.assertRaisesRegex(ValueError, "manifest mismatch"):
                gate.check_packet(packet, self.generated)

    def test_unlisted_packet_file_rejected(self):
        with self.packet_copy() as packet:
            (packet / "unexpected.txt").write_text("extra")
            with self.assertRaisesRegex(ValueError, "whitelist"):
                gate.check_packet(packet, self.generated)

    def test_forged_semantic_records_rejected_after_rehash(self):
        mutations = (
            lambda r: r["callees"].append({"target": "0x4d8c2e0"}),
            lambda r: r["rule"].update(addend=4999),
            lambda r: r["counts"].update(direct_calls=0),
            lambda r: r["function"].update(fde_section_offset="0x267a09"),
            lambda r: r["incoming"].pop(),
        )
        with self.packet_copy() as packet:
            for change in mutations:
                r = copy.deepcopy(self.record)
                change(r)
                (packet / "records.json").write_text(json.dumps(r, indent=2, sort_keys=True) + "\n")
                self.rewrite_manifest(packet)
                with self.assertRaisesRegex(ValueError, "regeneration mismatch: records.json"):
                    gate.check_packet(packet, self.generated)

    def test_forged_readme_count_rejected_after_rehash(self):
        with self.packet_copy() as packet:
            text = (packet / "README.md").read_text().replace("| Direct e8 call patterns | 4 |", "| Direct e8 call patterns | 3 |")
            (packet / "README.md").write_text(text)
            self.rewrite_manifest(packet)
            with self.assertRaisesRegex(ValueError, "regeneration mismatch: README.md"):
                gate.check_packet(packet, self.generated)

    def test_committed_tool_has_no_disassembler_process_dependency(self):
        # Reject executable process-launch calls, not prose about disassembly.
        import ast
        for file in (ROOT / "tools/tuple_saturating_gate.py", gate.PACKET / "verify.py"):
            tree = ast.parse(file.read_text())
            imports = [n for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))]
            self.assertFalse(any(getattr(n, "module", "") in ("subprocess", "ctypes") or
                                 any(a.name in ("subprocess", "ctypes") for a in n.names) for n in imports))


if __name__ == "__main__":
    unittest.main()
