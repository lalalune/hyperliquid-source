"""Reconstruction and corruption controls for the node 115 Keccak-256 sponge and RIPEMD-160 compression packet."""

import hashlib
import json
import pathlib
import struct
import unittest

from tools import evm_keccak_ripemd_115 as t


class ModelOnlyTests(unittest.TestCase):
    """Properties of the reconstruction that need no binary at all."""

    RC = None

    @classmethod
    def setUpClass(cls):
        # the 24 standard Keccak round constants, written out independently of the captured table
        cls.RC = (0x1, 0x8082, 0x800000000000808A, 0x8000000080008000, 0x808B, 0x80000001, 0x8000000080008081,
                  0x8000000000008009, 0x8A, 0x88, 0x80008009, 0x8000000A, 0x8000808B, 0x800000000000008B,
                  0x8000000000008089, 0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x800A,
                  0x800000008000000A, 0x8000000080008081, 0x8000000000008080, 0x80000001, 0x8000000080008008)

    def test_sha3_256_agrees_with_the_standard_library(self):
        sv = t.SpongeVariant()
        for size in (0, 1, 55, 135, 136, 137, 300):
            data = bytes(range(size % 251)) * 2
            lanes, pos, rate, delim, flag = t.sponge_absorb((0,) * 25, 0, 136, 0x06, 0, data, self.RC, None, sv)
            out, _ = t.sponge_squeeze(lanes, pos, rate, delim, flag, 32, self.RC)
            self.assertEqual(out, hashlib.sha3_256(data).digest())

    def test_published_keccak256_vectors(self):
        for data, digest in t.KECCAK_VECTORS:
            self.assertEqual(t.keccak256_model(data, self.RC).hex(), digest)

    def test_chunked_absorb_equals_one_write(self):
        data = t.Stream(3).data(500)
        whole = t.keccak256_model(data, self.RC)
        for chunks in ([1, 499], [135, 365], [136, 364], [137, 363], [100, 100, 100, 200]):
            self.assertEqual(t.keccak256_model(data, self.RC, chunks=chunks), whole)

    def test_ripemd160_published_vectors_use_the_model(self):
        for data, digest in t.RIPEMD_VECTORS:
            self.assertEqual(t.ripemd160_digest(data, t.ripemd_compress).hex(), digest)

    def test_squeeze_does_not_change_its_input_and_reads_in_order(self):
        s = t.Stream(8)
        lanes = s.lanes()
        long_read, original = t.sponge_squeeze(lanes, 5, 136, 1, 0, 400, self.RC)
        short_read, _ = t.sponge_squeeze(lanes, 5, 136, 1, 0, 150, self.RC)
        self.assertEqual(original, (lanes, 5, 136, 1, 0))
        self.assertEqual(long_read[:150], short_read)

    def test_panic_conditions_follow_the_slice_checks(self):
        lanes = (0,) * 25
        with self.assertRaises(t.Panic):
            t.sponge_absorb(lanes, 150, 100, 1, 0, b"", self.RC)         # rate below position
        with self.assertRaises(t.Panic):
            t.sponge_absorb(lanes, 201, 250, 1, 0, b"", self.RC)         # position past the state
        t.sponge_absorb(lanes, 201, 250, 1, 1, b"", self.RC)             # the reset clears the position first
        with self.assertRaises(t.Panic):
            t.sponge_squeeze(lanes, 0, 0, 1, 0, 1, self.RC)              # rate zero cannot be padded
        with self.assertRaises(t.Panic):
            t.sponge_squeeze(lanes, 0, 201, 1, 0, 1, self.RC)            # padding byte past the state

    def test_stream_is_deterministic(self):
        self.assertEqual(t.Stream(1).data(16), t.Stream(1).data(16))
        self.assertNotEqual(t.Stream(1).data(16), t.Stream(2).data(16))

    def test_every_variant_knob_is_rejected_when_unknown(self):
        with self.assertRaises(KeyError):
            t.KeccakVariant(nonsense=1)
        with self.assertRaises(KeyError):
            t.RipemdVariant(nonsense=1)
        with self.assertRaises(KeyError):
            t.SpongeVariant(nonsense=1)


class BinaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = t.Binary()
        cls.rc = cls.binary.rc_table()
        cls.machine = t.make_machine(cls.binary)

    def test_function_extents_are_whole_unwind_intervals(self):
        for name, start, _ in t.FUNCTIONS:
            self.assertEqual(self.binary.extent(name)[0], start)
            self.assertEqual(self.binary.image.exact_fde(start)[1], self.binary.extent(name)[1])

    def test_round_constants_come_from_the_captured_table(self):
        self.assertEqual(len(self.rc), 24)
        self.assertEqual(self.rc[0], 1)
        self.assertEqual(self.rc[23], 0x8000000080008008)

    def test_f1600_matches_on_sampled_inputs(self):
        for index, lanes in enumerate(t.f1600_inputs(60)):
            got = t.emu_f1600(self.machine, lanes)
            self.assertIsNone(got.stop)
            self.assertEqual(got.value, t.keccak_f(lanes, self.rc), index)

    def test_ripemd_compress_matches_on_sampled_inputs(self):
        for index, (state, block) in enumerate(t.ripemd_inputs(60)):
            got = t.emu_ripemd(self.machine, state, block)
            self.assertEqual(got.value, t.ripemd_compress(state, block), index)

    def test_absorb_and_squeeze_match_including_stops(self):
        stops = 0
        for case in t.absorb_inputs(160):
            got = t.emu_absorb(self.machine, *case)
            want = t.expected_absorb(self.rc, case)
            self.assertEqual(got.key(), want.key())
            stops += bool(got.stop)
        for case in t.squeeze_inputs(120):
            got = t.emu_squeeze(self.machine, *case)
            want = t.expected_squeeze(self.rc, case)
            self.assertEqual(got.key(), want.key())
            stops += bool(got.stop)
        self.assertGreaterEqual(stops, 1)

    def test_whole_hash_flows_reproduce_published_digests(self):
        for data, digest in t.KECCAK_VECTORS:
            self.assertEqual(t.emu_keccak256(self.machine, data, [len(data)]).hex(), digest)
        for data, digest in t.RIPEMD_VECTORS[:5]:
            self.assertEqual(t.emu_ripemd160(self.machine, data).hex(), digest)

    def test_every_rotate_count_the_model_needs_is_present_in_the_decoded_bytes(self):
        report = t.constants_report(self.binary, self.rc)
        counts = report["rotate_immediates"]["ripemd160_compress"]
        for shift in set(t.S_LEFT + t.S_RIGHT):
            self.assertTrue(any(key.endswith(" %d" % shift) for key in counts), shift)
        self.assertTrue(all(report["ripemd_constants_found_as_instruction_immediates"].values()))


class NegativeControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = t.Binary()
        cls.rc = cls.binary.rc_table()
        cls.machine = t.make_machine(cls.binary)

    def test_a_wrong_round_constant_is_caught_by_one_case(self):
        lanes = t.Stream(1).lanes()
        wrong = t.swap_rc(self.rc, 5, self.rc[5] ^ 1)
        self.assertNotEqual(t.emu_f1600(self.machine, lanes).value, t.keccak_f(lanes, wrong))

    def test_a_flipped_rotate_immediate_in_the_target_is_caught(self):
        picks = [row for row in self.binary.rows["ripemd160_compress"] if row.op == "rol" and row.imm_at is not None and row.imm_size == 1]
        site = picks[3].va + picks[3].imm_at
        patched = t.make_machine(self.binary, patches={site: self.binary.image.blob[self.binary.image.offset(site)] ^ 1})
        state, block = next(iter(t.ripemd_inputs(30)))
        self.assertNotEqual(t.emu_ripemd(patched, state, block).value, t.ripemd_compress(state, block))

    def test_wrong_pad_offset_changes_the_digest(self):
        wrong = t.SpongeVariant(pad_at=-2)
        self.assertNotEqual(t.keccak256_model(b"abc", self.rc, sv=wrong).hex(), t.KECCAK_VECTORS[1][1])

    def test_out_of_range_inputs_stop_the_target(self):
        lanes = t.Stream(2).lanes()
        self.assertEqual(t.emu_absorb(self.machine, lanes, 201, 136, 1, 0, b"x").stop, "panic")
        self.assertEqual(t.emu_squeeze(self.machine, lanes, 0, 201, 1, 0, 4).stop, "panic")
        self.assertEqual(t.emu_squeeze(self.machine, lanes, 3, 0, 1, 0, 4).stop, "panic")

    def test_a_modified_binary_fails_the_digest_check(self):
        h = hashlib.sha256()
        blob = memoryview(self.binary.image.blob)
        h.update(blob[:10])
        h.update(bytes([blob[10] ^ 0xFF]))
        h.update(blob[11:])
        self.assertFalse(t.check_binary_digest(h.hexdigest()))
        with self.assertRaises(t.EvidenceError):
            t.load_image(pathlib.Path(__file__))

    def test_truncated_instruction_stream_is_refused(self):
        start = t.RIPEMD
        wide = [row for row in self.binary.rows["ripemd160_compress"] if row.size >= 3][20]
        with self.assertRaises(t.EvidenceError):
            t.decode_range(self.binary.image, start, wide.va + 1)


class PacketTests(unittest.TestCase):
    PACKET = t.ROOT / "research/work-items/evm-keccak-ripemd-hash-115"

    def test_committed_measure_matches_tsv_rows(self):
        self.assertTrue(self.PACKET.is_dir())
        measure = json.loads((self.PACKET / "measure.json").read_text())
        rows = (self.PACKET / "negative-controls.tsv").read_text().splitlines()[1:]
        self.assertEqual(measure["negative_controls"], len(rows))
        self.assertEqual(measure["negative_detected"], sum(r.split("\t")[2] == "yes" for r in rows))
        self.assertGreaterEqual(measure["cases"], 10000)


if __name__ == "__main__":
    unittest.main()
