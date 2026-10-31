"""Tests for tools/block_proposal_path.py. Expected numbers here are literals, not calls to the tool's rule list."""
import copy
import hashlib
import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import block_proposal_path as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-008-block-proposal-94"
Case = tool.Case
tx = tool.tx


class Shared:
    image = None
    harness = None
    full = None


def image_get():
    if Shared.image is None:
        Shared.image = tool.load_image()
        Shared.harness = tool.Harness(Shared.image)
    return Shared.image


def run(case):
    image_get()
    return Shared.harness.run(case)


def block_of(case):
    got = run(case)
    blocks = [item[1] for item in got["out"] if item[0] == "block"]
    return blocks[0] if blocks else None


def full():
    if Shared.full is None:
        Shared.full = tool.analyse(image_get())
    return Shared.full


def patched(image, va, value):
    other = copy.copy(image)
    blob = bytearray(image.blob)
    blob[image.offset(va)] = value
    other.blob = bytes(blob)
    return other


class Identity(unittest.TestCase):
    def test_wrong_digest_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_changed_byte_refused(self):
        blob = bytearray(tool.BINARY.read_bytes())
        blob[-1] ^= 1
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "copy"
            path.write_bytes(blob)
            with self.assertRaises(tool.EvidenceError):
                tool.load_image(path)

    def test_source_starts_no_program(self):
        text = (ROOT / "tools" / "block_proposal_path.py").read_text()
        for word in ("sub" + "process", "os.sys" + "tem", "pop" + "en("):
            self.assertNotIn(word, text)


class Gates(unittest.TestCase):
    def test_leader_sends_one_block(self):
        block = block_of(Case("t", txs=[tx(0x100)]))
        self.assertEqual(block["round"], 1000)
        self.assertEqual(block["hashes"], [0x100])
        self.assertEqual(block["proposer"], bytes(range(0x40, 0x54)))

    def test_not_leader(self):
        self.assertEqual(run(Case("t", leader="other", txs=[tx(0x100)]))["out"], [])
        self.assertEqual(run(Case("t", leader="error", txs=[tx(0x100)]))["out"], [])

    def test_one_proposal_per_round(self):
        self.assertIsNone(block_of(Case("t", last=1000, txs=[tx(0x100)])))
        self.assertIsNotNone(block_of(Case("t", last=999, txs=[tx(0x100)])))

    def test_round_past_execution_only_logs(self):
        got = run(Case("t", round=1001, last=1000, execution_bound=1000, high_qc=(1000, 0x7000), txs=[tx(0x100)]))
        self.assertEqual(len(got["logs"]), 1)
        self.assertEqual(got["logs"][0][1], b"Querying stakes for high round, is execution behind?")
        self.assertEqual(len(got["out"]), 1)

    def test_no_stake_entry_stops(self):
        for stake in ("none", "empty", "out"):
            self.assertEqual(run(Case("t", stake=stake, txs=[tx(0x100)]))["out"], [])


class Parent(unittest.TestCase):
    def test_state_qc_without_tc(self):
        self.assertEqual(block_of(Case("t", txs=[tx(0x100)]))["qc_round"], 999)

    def test_tc_highest_qc_wins_over_state_qc(self):
        block = block_of(Case("t", tc=[(995, 0x7001)], high_qc=(999, 0x7000), blocks=[(0x7001, 995, 0, (39999, 0))], txs=[tx(0x100)]))
        self.assertEqual((block["qc_round"], block["qc_hash"]), (995, 0x7001))

    def test_tc_tie_takes_the_last(self):
        block = block_of(Case("t", tc=[(997, 0x7000), (997, 0x7001), (997, 0x7002)], blocks=[(0x7002, 997, 0, (39999, 0))], txs=[tx(0x100)]))
        self.assertEqual(block["qc_hash"], 0x7002)

    def test_tc_moves_into_the_block(self):
        got = run(Case("t", tc=[(995, 0x7000)], txs=[tx(0x100)]))
        self.assertEqual(got["tc_word"], 1 << 63)
        self.assertEqual(got["out"][0][1]["tc"][0], 2)

    def test_missing_parent_keeps_mark_and_tc(self):
        got = run(Case("t", tc=[(995, 0x7000)], blocks=[(0x7100, 999, 0, (39999, 0))], txs=[tx(0x100)]))
        self.assertEqual(got["out"], [])
        self.assertEqual(got["last"], 1000)
        self.assertEqual(got["tc_word"], 2)

    def test_missing_ancestor_asks_with_one_and_five(self):
        got = run(Case("t", missing=0x7777, txs=[tx(0x100)]))
        self.assertEqual(got["asks"][0][1:], (0x7777, 1, 5, 0.0))
        self.assertEqual(got["out"][0][0], 0xA)
        self.assertEqual(run(Case("t", missing=0x7777, ask=2))["out"], [])


class Selection(unittest.TestCase):
    def test_ten_second_edge(self):
        self.assertEqual(block_of(Case("t", txs=[tx(0x100, 10000)]))["hashes"], [0x100])
        self.assertIsNone(block_of(Case("t", txs=[tx(0x100, 10001)])))

    def test_tag_flag_and_excluded(self):
        block = block_of(Case("t", txs=[tx(0x100, tag=(1 << 63) + 1), tx(0x101, used=1), tx(0x102), tx(0x103), tx(0x104, tag=1 << 63)], excluded=(0x102,)))
        self.assertEqual(block["hashes"], [0x103, 0x104])

    def test_oldest_first_then_key_order(self):
        block = block_of(Case("t", txs=[tx(0x100, 5), tx(0x101, 50), tx(0x102, 20), tx(0x103, 20)]))
        self.assertEqual(block["hashes"], [0x101, 0x102, 0x103, 0x100])

    def test_byte_cap_edges(self):
        self.assertEqual(len(block_of(Case("t", txs=[tx(0x100, 3, 3000000), tx(0x101, 2, 1000000)]))["hashes"]), 2)
        self.assertEqual(len(block_of(Case("t", txs=[tx(0x100, 3, 3000000), tx(0x101, 2, 1000001)]))["hashes"]), 1)

    def test_first_over_cap_kept(self):
        self.assertEqual(block_of(Case("t", txs=[tx(0x100, 3, 9000000), tx(0x101, 2, 1)]))["hashes"], [0x100])

    def test_no_skip_after_the_cap(self):
        self.assertEqual(block_of(Case("t", txs=[tx(0x100, 3, 3999999), tx(0x101, 2, 5), tx(0x102, 1, 1)]))["hashes"], [0x100])

    def test_hash_cap(self):
        self.assertEqual(len(block_of(Case("t", txs=[tx(0x100 + index, index % 7) for index in range(101)]))["hashes"]), 100)
        self.assertEqual(len(block_of(Case("t", txs=[tx(0x100 + index, index % 7) for index in range(99)]))["hashes"]), 99)

    def test_size_sum_panics(self):
        self.assertTrue(run(Case("t", txs=[tx(0x100, 3, 1 << 63), tx(0x101, 2, 1 << 63)]))["panicked"])

    def test_seen_map_has_no_effect(self):
        self.assertEqual(block_of(Case("t", txs=[tx(0x100)], seen=(0x100,)))["hashes"], [0x100])


class Empty(unittest.TestCase):
    def test_idle(self):
        got = run(Case("t"))
        self.assertEqual(got["out"], [])
        self.assertEqual(got["last"], 999)

    def test_force_flag(self):
        self.assertEqual(block_of(Case("t", force=1))["hashes"], [])

    def test_pending_needs_round_above_watermark(self):
        base = (0x7000, 999, 0, (39999, 0))
        self.assertIsNotNone(block_of(Case("t", blocks=[base, (0x7100, 901, 1, (39990, 0))])))
        self.assertIsNone(block_of(Case("t", blocks=[base, (0x7100, 900, 1, (39990, 0))])))
        self.assertIsNone(block_of(Case("t", blocks=[base, (0x7100, 950, 0, (39990, 0))])))


class Time(unittest.TestCase):
    def test_event_plus_50_ms(self):
        self.assertEqual(block_of(Case("t", txs=[tx(0x100)]))["time"][1:], (40000, 550000000))

    def test_parent_not_older_plus_1_ms(self):
        block = block_of(Case("t", blocks=[(0x7000, 999, 0, (40001, 7))], txs=[tx(0x100)]))
        self.assertEqual(block["time"][1:], (40001, 1000007))

    def test_same_millisecond_counts_as_not_older(self):
        block = block_of(Case("t", blocks=[(0x7000, 999, 0, (40000, 550999999))], txs=[tx(0x100)]))
        self.assertEqual(block["time"][1:], (40000, 551999999))


class Prune(unittest.TestCase):
    def test_off_unless_word_is_one(self):
        self.assertEqual(run(Case("t", prune=2, txs=[tx(0x100, bad=True)]))["verified"], [])

    def test_failed_tx_leaves(self):
        got = run(Case("t", prune=1, txs=[tx(0x100, bad=True), tx(0x101)]))
        self.assertEqual(got["removed"], 1)
        self.assertEqual(got["tx_count"], 1)
        self.assertEqual(got["out"][0][1]["hashes"], [0x101])

    def test_none_tag_is_not_verified_but_selected(self):
        got = run(Case("t", prune=1, txs=[tx(0x100, tag=1 << 63, bad=True), tx(0x101)]))
        self.assertEqual(got["verified"], [0x101])
        self.assertEqual(got["out"][0][1]["hashes"], [0x100, 0x101])


class Timers(unittest.TestCase):
    def test_durations(self):
        image = image_get()
        self.assertEqual(tool.duration_of(image, 0x3FD3333333333333), (0, 300000000))
        self.assertEqual(tool.duration_of(image, 0x3FB9999999999999), (0, 100000000))

    def test_second_constant_is_a_third_of_the_first(self):
        self.assertEqual(struct.pack("<d", 0.3 / 3), struct.pack("<Q", 0x3FB9999999999999))

    def test_duration_rule_has_teeth(self):
        self.assertNotEqual(tool.exact_duration(0x3FD0000000000000), (0, 300000000))


class Controls(unittest.TestCase):
    def assert_killed(self, va, offset, flip):
        image = image_get()
        at = image.offset(va + offset)
        harness = tool.Harness(image, {va + offset: image.blob[at] ^ flip})
        self.assertIsNotNone(tool.first_failure(harness, tool.named_cases()))

    def test_control_passes(self):
        image = image_get()
        self.assertIsNone(tool.first_failure(tool.Harness(image), tool.named_cases()))

    def test_byte_cap_mutant(self):
        self.assert_killed(0x44B5D16, 3, 2)

    def test_hash_cap_mutant(self):
        self.assert_killed(0x44B5CC8, 3, 1)

    def test_once_per_round_mutant(self):
        self.assert_killed(0x44B501A, 1, 1)

    def test_parent_lookup_mutant(self):
        self.assert_killed(0x44B5DF7, 1, 1)

    def test_rule_list_catches_a_wrong_block(self):
        case = Case("t", txs=[tx(0x100)])
        got = run(case)
        want = tool.spec_run(case)[1]
        self.assertTrue(tool.same(got, want))
        got["out"][0][1]["round"] += 1
        self.assertFalse(tool.same(got, want))

    def test_rule_list_catches_an_extra_write(self):
        case = Case("t", txs=[tx(0x100)])
        got = run(case)
        want = tool.spec_run(case)[1]
        got["changed"] = got["changed"] + [0x10]
        self.assertFalse(tool.same(got, want))


class Bytes(unittest.TestCase):
    def test_pins(self):
        image = image_get()
        self.assertGreater(tool.check_pins(image), 40)
        with self.assertRaises(tool.EvidenceError):
            tool.check_pins(patched(image, 0x44AE44D, 0x90))

    def test_trigger_sites(self):
        image = image_get()
        self.assertEqual(len(tool.scan_triggers(image)), 7)

    def test_trigger_site_loss_found(self):
        image = image_get()
        with self.assertRaises(tool.EvidenceError):
            tool.scan_triggers(patched(image, 0x44AE465, 0x90))

    def test_tables(self):
        image = image_get()
        self.assertEqual(len(tool.check_tables(image)), 4)
        with self.assertRaises(tool.EvidenceError):
            tool.check_tables(patched(image, 0x6F2A34 + 12, 0))

    def test_constants(self):
        image = image_get()
        with self.assertRaises(tool.EvidenceError):
            tool.check_constants(patched(image, 0x20A4C0, 0))

    def test_fields(self):
        image = image_get()
        self.assertEqual([len(row[2]) for row in tool.scan_fields(image)], [3, 4])

    def test_outside_address_refused(self):
        image = image_get()
        with self.assertRaises(tool.EvidenceError):
            image.fde(0x10)


class Packet(unittest.TestCase):
    def test_no_mutant_left_unexplained(self):
        rows = full()["mutations"]
        self.assertGreater(len(rows), 100)
        self.assertFalse([row for row in rows if row[3] == "survived" and row[4] == "UNEXPLAINED"])

    def test_committed_files_match(self):
        files = tool.render(full(), image_get())
        for name, text in files.items():
            self.assertEqual((FOLDER / name).read_text(encoding="ascii"), text, name)

    def test_manifest(self):
        lines = (FOLDER / "MANIFEST.sha256").read_text().splitlines()
        self.assertTrue(lines)
        for line in lines:
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)


if __name__ == "__main__":
    unittest.main()
