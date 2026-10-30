"""Pinned byte evidence and architectural controls for RE-006."""
import hashlib
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import order_book_lifecycle_94 as ob  # noqa: E402

PACKET = ROOT / "research/work-items/RE-006-price-level-lifecycle-94"
_DATA = None


def data():
    global _DATA
    if _DATA is None:
        _DATA = ob.TARGET.read_bytes()
    return _DATA


def locally_mutated(va):
    changed = bytearray(data())
    off = ob.file_mapping(changed, va)
    changed[off] ^= 1
    return bytes(changed)


def scan_mutated(buf):
    return ob.validate_controls(buf)


class PinnedEvidence(unittest.TestCase):
    def test_committed_evidence_recomputes(self):
        self.assertEqual((PACKET / "evidence.json").read_text(), ob.render(ob.scan(data())))

    def test_expected_fdes_and_edges(self):
        result = ob.scan(data())
        self.assertEqual(result["fde_count"], 121299)
        self.assertEqual([(x["start_va"], x["end_va"]) for x in result["functions"]],
                         [(hex(a), hex(b)) for _, a, b, _ in ob.FUNCTIONS])
        self.assertEqual([(x["site_va"], x["target_va"]) for x in result["call_edges"]],
                         [(hex(a), hex(b)) for a, b, _ in ob.CALL_EDGES])

    def test_all_source_locations_are_relocation_bound(self):
        got = ob.scan(data())["source_locations"]
        self.assertEqual(len(got), len(ob.LOCATIONS))
        self.assertEqual([x["line"] for x in got], [1048, 1286, 1294, 514, 517, 445, 768, 167, 79])


class AdversarialMutations(unittest.TestCase):
    def test_digest_gate_rejects_mutation(self):
        with self.assertRaisesRegex(ob.EvidenceError, "SHA-256"):
            ob.scan(locally_mutated(ob.ANCHORS[0][1]))

    def test_each_local_instruction_obligation_rejects_mutation(self):
        for label, start, _, _, _ in ob.ANCHORS:
            with self.subTest(label=label):
                with self.assertRaisesRegex(ob.EvidenceError, "bytes changed"):
                    scan_mutated(locally_mutated(start))

    def test_each_call_edge_rejects_retarget(self):
        for site, _, _ in ob.CALL_EDGES:
            with self.subTest(site=hex(site)):
                with self.assertRaisesRegex(ob.EvidenceError, "bytes changed|call at"):
                    scan_mutated(locally_mutated(site + 1))

    def test_each_location_rejects_line_mutation(self):
        for slot, _, _, _ in ob.LOCATIONS:
            with self.subTest(slot=hex(slot)):
                with self.assertRaisesRegex(ob.EvidenceError, "Location"):
                    scan_mutated(locally_mutated(slot + 16))


class ArchitecturalModel(unittest.TestCase):
    """Small state model for the exact writes, not target execution."""

    def setUp(self):
        self.slots = []
        self.free_head = 0
        self.live = 0
        self.total = 0
        self.levels = {}

    @staticmethod
    def side_key(side, price):
        return -price if side == 0 else price

    def insert(self, side, price, oid, size):
        key = self.free_head
        slot = {"live": True, "oid": oid, "size": size, "prev": None, "next": None}
        if key == len(self.slots):
            self.slots.append(slot)
            self.free_head = key + 1
        else:
            self.assertFalse(self.slots[key]["live"])
            self.free_head = self.slots[key]["free_next"]
            self.slots[key] = slot
        self.live = min((1 << 64) - 1, self.live + 1)
        self.total = min((1 << 64) - 1, self.total + size)
        level_key = (side, self.side_key(side, price))
        level = self.levels.setdefault(level_key, {"head": None, "tail": None})
        old_tail = level["tail"]
        if old_tail is not None:
            self.assertTrue(self.slots[old_tail]["live"])
            self.slots[old_tail]["next"] = key
            slot["prev"] = old_tail
        if level["head"] is None:
            level["head"] = key
        level["tail"] = key
        return key

    def remove(self, side, price, key):
        slot = self.slots[key]
        self.assertTrue(slot["live"])
        previous, following = slot["prev"], slot["next"]
        level_key = (side, self.side_key(side, price))
        level = self.levels[level_key]
        if previous is None:
            level["head"] = following
        else:
            self.assertTrue(self.slots[previous]["live"])
            self.slots[previous]["next"] = following
        if following is None:
            level["tail"] = previous
        else:
            self.assertTrue(self.slots[following]["live"])
            self.slots[following]["prev"] = previous
        if level["head"] is None and level["tail"] is None:
            del self.levels[level_key]
        old_free = self.free_head
        self.total = max(0, self.total - slot["size"])
        self.live = max(0, self.live - 1)
        self.slots[key] = {"live": False, "free_next": old_free}
        self.free_head = key

    def test_bid_and_ask_key_order(self):
        self.assertEqual(sorted(self.side_key(0, p) for p in [99, 101, 100]), [-101, -100, -99])
        self.assertEqual(sorted(self.side_key(1, p) for p in [99, 101, 100]), [99, 100, 101])

    def test_fifo_append_and_head_cancel(self):
        first = self.insert(0, 100, 7, 4)
        second = self.insert(0, 100, 8, 6)
        level = self.levels[(0, -100)]
        self.assertEqual((level["head"], level["tail"]), (first, second))
        self.assertEqual((self.slots[first]["prev"], self.slots[first]["next"]), (None, second))
        self.assertEqual((self.slots[second]["prev"], self.slots[second]["next"]), (first, None))
        self.remove(0, 100, first)
        self.assertEqual(self.levels[(0, -100)], {"head": second, "tail": second})
        self.assertIsNone(self.slots[second]["prev"])
        self.assertEqual(self.total, 6)

    def test_middle_and_tail_unlink(self):
        keys = [self.insert(1, 100, oid, 1) for oid in (1, 2, 3)]
        self.remove(1, 100, keys[1])
        self.assertEqual(self.slots[keys[0]]["next"], keys[2])
        self.assertEqual(self.slots[keys[2]]["prev"], keys[0])
        self.remove(1, 100, keys[2])
        self.assertEqual(self.levels[(1, 100)], {"head": keys[0], "tail": keys[0]})
        self.assertIsNone(self.slots[keys[0]]["next"])

    def test_delete_then_lifo_slot_reuse(self):
        first = self.insert(0, 10, 1, 5)
        self.remove(0, 10, first)
        self.assertEqual(self.free_head, first)
        reused = self.insert(0, 11, 2, 7)
        self.assertEqual(reused, first)
        self.assertEqual((self.live, self.total), (1, 7))

    def test_empty_level_removed(self):
        key = self.insert(1, 77, 1, 2)
        self.remove(1, 77, key)
        self.assertNotIn((1, 77), self.levels)

    def test_invalid_previous_neighbor_fails_before_writes(self):
        first = self.insert(0, 1, 1, 1)
        second = self.insert(0, 1, 2, 1)
        self.slots[first]["live"] = False
        before = dict(self.levels[(0, -1)])
        with self.assertRaises(AssertionError):
            self.remove(0, 1, second)
        self.assertEqual(self.levels[(0, -1)], before)

    def test_u64_accounting_boundaries(self):
        maximum = (1 << 64) - 1
        self.total = maximum - 1
        self.insert(0, 3, 1, 2)
        self.assertEqual(self.total, maximum)
        # The removal helper's observed subtract path floors an underflow at 0.
        self.total = 1
        self.slots[0]["size"] = 2
        self.remove(0, 3, 0)
        self.assertEqual(self.total, 0)


class Determinism(unittest.TestCase):
    def test_tool_output_is_hashseed_independent(self):
        outputs = set()
        for seed in ("0", "1", "4242"):
            env = dict(__import__("os").environ, PYTHONHASHSEED=seed)
            outputs.add(subprocess.run([sys.executable, "-I", "-B", str(ROOT / "tools/order_book_lifecycle_94.py")],
                                       cwd=ROOT, env=env, check=True, capture_output=True).stdout)
        self.assertEqual(len(outputs), 1)


if __name__ == "__main__":
    unittest.main()
