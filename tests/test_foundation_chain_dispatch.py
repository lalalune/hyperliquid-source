"""Tests for the node #94 wrapper-chain dispatch model (RE-001).

Target-grounded expectations: the walk, the four-skip limit, the
unconditional fifth call and the null-head return are read off the
verbatim excerpts in research/work-items/RE-001-chain-dispatch-94/.
Packet checks re-verify the evidence against the binary; corruption
controls prove the checks fail on tampered packets.
"""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from foundation_chain_dispatch import (
    SENTINEL_CELLS,
    ChainExhausted,
    Wrapper,
    current_head,
    resolve,
    resolve_chain,
)

PACKET = Path(__file__).resolve().parents[1] / "research" / "work-items" / "RE-001-chain-dispatch-94"
SENTINEL = object()


def chain(slots):
    """Build a wrapper chain from a list of slot values."""
    head = None
    for slot in reversed(slots):
        head = Wrapper(slot, head)
    return head


def outer_with(head):
    return {0x788: {0x6B0: head}}


def value_slot(value):
    return lambda node: value


class TestCurrentHead(unittest.TestCase):
    def test_head_and_null(self):
        node = Wrapper(value_slot(1))
        self.assertIs(current_head(outer_with(node)), node)
        self.assertIsNone(current_head(outer_with(None)))


class TestResolveChain(unittest.TestCase):
    def test_null_head_returns_not_found(self):
        self.assertEqual(resolve_chain(None, SENTINEL), (False, None))

    def test_first_node_dispatched(self):
        calls = []
        slot = lambda node: calls.append(node) or "first"
        head = Wrapper(slot)
        found, value = resolve_chain(head, SENTINEL)
        self.assertTrue(found)
        self.assertEqual(value, "first")
        self.assertIs(calls[0], head)

    def test_sentinel_skips_up_to_four(self):
        for skips in range(0, 5):
            slots = [SENTINEL] * skips + [value_slot("hit")]
            found, value = resolve_chain(chain(slots), SENTINEL)
            self.assertTrue(found, "skips=%d" % skips)
            self.assertEqual(value, "hit")

    def test_fifth_node_called_unconditionally(self):
        # Four sentinels, then a fifth node whose slot IS the
        # sentinel: the binary calls it without comparing.
        slots = [SENTINEL] * 4 + [value_slot("fifth")]
        found, value = resolve_chain(chain(slots), SENTINEL)
        self.assertTrue(found)
        self.assertEqual(value, "fifth")

    def test_chain_exhausted_raises(self):
        with self.assertRaises(ChainExhausted):
            resolve_chain(chain([SENTINEL, SENTINEL]), SENTINEL)

    def test_dispatch_receives_its_wrapper(self):
        seen = []
        head = Wrapper(lambda node: seen.append(node) or 7)
        resolve_chain(head, SENTINEL)
        self.assertIs(seen[0], head)


class TestResolveEndToEnd(unittest.TestCase):
    def test_all_three_getters_share_the_walk(self):
        for slot_offset in (0x70, 0x78, 0x98):
            head = chain([SENTINEL, value_slot("v-%#x" % slot_offset)])
            found, value = resolve(outer_with(head), slot_offset, SENTINEL)
            self.assertTrue(found)
            self.assertEqual(value, "v-%#x" % slot_offset)

    def test_sentinel_cells_are_distinct(self):
        self.assertEqual(len(set(SENTINEL_CELLS.values())), 3)

    def test_null_head_end_to_end(self):
        found, value = resolve(outer_with(None), 0x70, SENTINEL)
        self.assertEqual((found, value), (False, None))

    def test_unknown_slot_rejected(self):
        with self.assertRaises(ValueError):
            resolve(outer_with(None), 0x60, SENTINEL)


class TestPacket(unittest.TestCase):
    def test_verify_passes(self):
        result = subprocess.run(
            [sys.executable, str(PACKET / "verify.py")],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ALL CHECKS PASSED", result.stdout)

    def test_excerpts_regenerate(self):
        repo = Path(__file__).resolve().parents[1]
        result = subprocess.run(
            [sys.executable, str(PACKET / "export_excerpts.py"),
             "--out", tempfile.mkdtemp()],
            capture_output=True, text=True, cwd=str(repo))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_records_shape(self):
        records = json.loads((PACKET / "records.json").read_text())
        self.assertEqual(records["task"], "RE-001")
        self.assertEqual(len(records["functions"]), 4)
        self.assertEqual(len(records["getters"]), 3)
        self.assertEqual(records["plt"], [])
        # Semantic records only: no per-instruction mnemonic list.
        self.assertNotIn("instructions", records)
        self.assertNotIn("mnemonics", records)

    def test_corruption_controls(self):
        for mutate in ("records", "excerpt"):
            with tempfile.TemporaryDirectory() as tmp:
                copy = Path(tmp) / "packet"
                shutil.copytree(PACKET, copy)
                if mutate == "records":
                    path = copy / "records.json"
                    text = path.read_text().replace("0x514dfa0", "0x514dfa1", 1)
                    path.write_text(text)
                else:
                    path = copy / "getters.objdump.txt"
                    text = path.read_text().replace("514dfa0", "514dfa1", 1)
                    path.write_text(text)
                result = subprocess.run(
                    [sys.executable, str(copy / "verify.py"), "--binary",
                     str(Path(__file__).resolve().parents[1]
                         / "work" / "hl-node-94.bin")],
                    capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0,
                                    "tampered %s still verified" % mutate)


if __name__ == "__main__":
    unittest.main()
