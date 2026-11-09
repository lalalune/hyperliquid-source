import hashlib
import itertools
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re11_selfdestruct_keccak115 as t  # noqa: E402


class SelfdestructKeccak(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = t.Image(t.BINARY.read_bytes())
        for start in (t.SD_A, t.SD_B, t.KECCAK):
            t.KS[start] = t.consts_for(cls.image, start, "sd" if start in (t.SD_A, t.SD_B) else "kc")

    def cases(self, label, count):
        return [c for lb, c in itertools.islice((x for x in t.case_stream() if x[0] == label), count)]

    def run_all(self, label, count, mut=frozenset(), override=None):
        m = t.Machine(self.image, override)
        bad = 0
        for c in self.cases(label, count):
            try:
                _, _, _, ok = t.run_case(m, self.image, c, t.KS[c["copy"]], mut)
            except t.ToolError:  # a corrupted code byte may send the evaluator out of bounds: also a detection
                ok = False
            bad += not ok
        return bad

    def test_keccak_reconstruction_matches_known_vectors(self):
        self.assertEqual(t.keccak256(b""), t.EMPTY_KECCAK)
        self.assertEqual(t.keccak256(b"abc").hex(), "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")
        for n in (0, 1, 135, 136, 137, 272, 300):
            data = bytes(range(256)) * 2
            self.assertEqual(t.kc_hash(data[:n], frozenset(["pad06"])), hashlib.sha3_256(data[:n]).digest())

    def test_empty_hash_constants_in_the_binary(self):
        k = t.KS[t.SD_A]
        self.assertEqual(k["h_lo"] + k["h_hi"], t.EMPTY_KECCAK)
        self.assertEqual(t.KS[t.SD_B]["h_lo"], k["h_lo"])

    def test_wrong_binary_is_rejected(self):
        corrupt = bytearray(t.BINARY.read_bytes())
        corrupt[self.image.text["offset"] + 7] ^= 1
        with self.assertRaises(t.ToolError):
            t.Image(bytes(corrupt))
        with self.assertRaises(t.ToolError):
            self.image.code(self.image.text["address"] + self.image.text["size"] + 0x100, 4)

    def test_call_site_roles_are_read_from_code_bytes(self):
        for start in (t.SD_A, t.SD_B):
            roles = t.KS[start]["roles"]
            self.assertEqual(set(roles), {"load", "journal_grow", "list_grow", "transfer", "burn", "none", "ovf"})
            self.assertTrue(all(len(v) == 1 for v in roles.values()))
        self.assertNotEqual(t.KS[t.SD_A]["roles"]["load"], t.KS[t.SD_B]["roles"]["load"])
        self.assertEqual(set(t.KS[t.KECCAK]["roles"]), {"absorb", "memcpy", "memset", "squeeze", "resize", "ovf"})

    def test_beneficiary_word_decoding_round_trips(self):
        s = t.Stream("words")
        for _ in range(50):
            addr = t.rand_addr(s)
            self.assertEqual(t.frame_target(t.words_for(addr, s)), addr)

    def test_saturating_signed_add(self):
        self.assertEqual(t.satadd(1, 2), 3)
        self.assertEqual(t.satadd((1 << 63) - 1, 1), (1 << 63) - 1)
        self.assertEqual(t.satadd(1 << 63, t.M64), 1 << 63)
        self.assertEqual(t.satadd(t.M64, 1), 0)

    def test_hashbrown_fixture_probe(self):
        s = t.Stream("probe")
        addrs = [s.take(20) for _ in range(5)]
        ents = [(a, t.addr_hash(a, 7, 9), bytes(0x68)) for a in addrs]
        h = t.addr_hash(addrs[0], 7, 9)
        decoy = bytes([addrs[0][0] ^ 1]) + addrs[0][1:]
        mem, coff, slots = t.layout(16, ents, [], [(h & 15, h >> 57, decoy)])
        for a in addrs:
            end = t.find_slot(mem, coff, 16, t.addr_hash(a, 7, 9), a)
            self.assertEqual(end, coff - slots[a] * t.BUCKET)
        absent = s.take(20)
        self.assertIsNone(t.find_slot(mem, coff, 16, t.addr_hash(absent, 7, 9), absent))

    def test_selfdestruct_copies_match_the_model(self):
        self.assertEqual(self.run_all("sd-a", 250), 0)
        self.assertEqual(self.run_all("sd-b", 250), 0)

    def test_keccak_matches_the_model(self):
        self.assertEqual(self.run_all("kc", 250), 0)

    def test_every_branch_class_is_reached(self):
        m = t.Machine(self.image)
        seen = set()
        for c in self.cases("sd-a", 500):
            want, _, _, _ = t.run_case(m, self.image, c, t.KS[c["copy"]])
            seen.add(t.classify(c, want))
        for need in ("sd/ret-0x03/load+transfer", "sd/ret-0x03/burn+load", "sd/ret-0x20/load", "sd/ret-0x28/",
                     "sd/ret-0x2c/", "sd/panic-none/load"):
            self.assertIn(need, seen)

    def test_wrong_model_is_detected(self):
        for mut in ("carry_drop", "ignore_bit80", "no_cold", "fork_le3"):
            self.assertGreater(self.run_all("sd-a", 400, frozenset([mut])), 0, mut)
        for mut in ("pad06", "cost_floor", "swap_off_len"):
            self.assertGreater(self.run_all("kc", 400, frozenset([mut])), 0, mut)

    def test_corrupted_code_byte_is_detected(self):
        for start, mutants in ((t.SD_A, t.SD_BYTE_MUTANTS[:3]), (t.KECCAK, t.KC_BYTE_MUTANTS[:3])):
            label = "sd-a" if start == t.SD_A else "kc"
            for off, idx, old, new, _ in mutants:
                va = start + off + idx
                self.assertEqual(self.image.code(va, 1)[0], old)
                self.assertGreater(self.run_all(label, 400, override={va: new}), 0)

    def test_stub_event_mismatch_is_detected(self):
        m = t.Machine(self.image)
        c = self.cases("kc", 1)[0]
        want, got, sim, ok = t.run_case(m, self.image, c, t.KS[c["copy"]])
        self.assertTrue(ok)
        got["events"] = got["events"] + [("squeeze", 0, 0)]
        self.assertFalse(t.same(want, got, sim))


if __name__ == "__main__":
    unittest.main()
