import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import foundation_tree_insert_hint as tool  # noqa: E402

PACKET = ROOT / "research" / "work-items" / "RE-001-tree-insert-hint-94"
BIN = ROOT / "work" / "hl-node-94.bin"

# Balanced tree: keys 10, 20, 30, 40, 50, 60, 70.
SPEC = (40, (20, (10, None, None), (30, None, None)),
        (60, (50, None, None), (70, None, None)))
# Left-skewed tree: 30 -> 20 -> 10 (tests the leftmost arms).
SKEW = (30, (20, (10, None, None), None), None)


def tree_of(spec):
    return tool.Tree(tool.build(spec))


class TestHintPosition(unittest.TestCase):
    def test_empty_tree_hint_is_header(self):
        tree = tree_of(None)
        first, second = tool.get_insert_hint_unique_pos(tree, tree.header, 42)
        self.assertIsNone(first)
        self.assertIs(second, tree.header)

    def test_end_hint_above_rightmost(self):
        tree = tree_of(SPEC)
        first, second = tool.get_insert_hint_unique_pos(tree, tree.header, 80)
        self.assertIsNone(first)
        self.assertIs(second, tree.rightmost)
        self.assertEqual(second.key, 70)

    def test_end_hint_falls_to_walk(self):
        tree = tree_of(SPEC)
        first, second = tool.get_insert_hint_unique_pos(tree, tree.header, 30)
        self.assertIs(second, None)
        self.assertEqual(first.key, 30)
        first, second = tool.get_insert_hint_unique_pos(tree, tree.header, 35)
        self.assertIsNone(first)
        self.assertEqual(second.key, 30)

    def test_hint_hit(self):
        tree = tree_of(SPEC)
        hint = tool.find(tree, 40)
        first, second = tool.get_insert_hint_unique_pos(tree, hint, 40)
        self.assertIs(first, hint)
        self.assertIsNone(second)

    def test_hint_leftmost_below(self):
        tree = tree_of(SPEC)
        hint = tool.find(tree, 10)
        first, second = tool.get_insert_hint_unique_pos(tree, hint, 5)
        self.assertIs(first, hint)
        self.assertIs(second, hint)

    def test_predecessor_adjacent_no_right_child(self):
        tree = tree_of(SPEC)
        hint = tool.find(tree, 40)
        first, second = tool.get_insert_hint_unique_pos(tree, hint, 35)
        self.assertIsNone(first)
        self.assertEqual(second.key, 30)

    def test_predecessor_adjacent_right_child(self):
        tree = tree_of(SPEC)
        hint = tool.find(tree, 30)
        first, second = tool.get_insert_hint_unique_pos(tree, hint, 25)
        self.assertIs(first, hint)
        self.assertIs(second, hint)

    def test_predecessor_adjacency_failure_falls_back(self):
        tree = tree_of(SPEC)
        hint = tool.find(tree, 60)
        got = tool.get_insert_hint_unique_pos(tree, hint, 45)
        want = tool.get_insert_unique_pos(tree, 45)
        self.assertEqual(got, want)
        self.assertIsNone(got[0])
        self.assertEqual(got[1].key, 50)

    def test_hint_rightmost_above(self):
        tree = tree_of(SPEC)
        hint = tool.find(tree, 70)
        first, second = tool.get_insert_hint_unique_pos(tree, hint, 75)
        self.assertIsNone(first)
        self.assertIs(second, hint)

    def test_successor_adjacent_no_right_child(self):
        tree = tree_of(SPEC)
        hint = tool.find(tree, 30)
        first, second = tool.get_insert_hint_unique_pos(tree, hint, 35)
        self.assertIsNone(first)
        self.assertIs(second, hint)

    def test_successor_adjacent_right_child(self):
        tree = tree_of(SPEC)
        hint = tool.find(tree, 20)
        first, second = tool.get_insert_hint_unique_pos(tree, hint, 25)
        self.assertEqual(first.key, 30)
        self.assertIs(first, second)

    def test_successor_adjacency_failure_falls_back(self):
        tree = tree_of(SPEC)
        hint = tool.find(tree, 20)
        got = tool.get_insert_hint_unique_pos(tree, hint, 35)
        want = tool.get_insert_unique_pos(tree, 35)
        self.assertEqual(got, want)
        self.assertIsNone(got[0])
        self.assertEqual(got[1].key, 30)

    def test_walk_miss_left_with_predecessor_step(self):
        tree = tree_of(SPEC)
        first, second = tool.get_insert_hint_unique_pos(tree, tree.header, 25)
        self.assertIsNone(first)
        self.assertEqual(second.key, 30)

    def test_walk_hit_and_miss_right(self):
        tree = tree_of(SKEW)
        first, second = tool.get_insert_unique_pos(tree, 20)
        self.assertEqual(first.key, 20)
        self.assertIsNone(second)
        first, second = tool.get_insert_unique_pos(tree, 25)
        self.assertIsNone(first)
        self.assertEqual(second.key, 20)

    def test_signed_int32_edges(self):
        tree = tree_of((0, (-2147483648, None, None), (2147483647, None, None)))
        first, second = tool.get_insert_hint_unique_pos(tree, tree.header, -2147483648)
        self.assertEqual(first.key, -2147483648)
        self.assertIsNone(second)
        first, second = tool.get_insert_hint_unique_pos(
            tree, tool.find(tree, 2147483647), 2147483647)
        self.assertEqual(first.key, 2147483647)
        self.assertIsNone(second)
        first, second = tool.get_insert_hint_unique_pos(tree, tree.header, 2147483647)
        self.assertEqual(first.key, 2147483647)
        self.assertIsNone(second)

    def test_consumer_decisions(self):
        tree = tree_of(SPEC)
        kind, value = tool.consumer_decision(tree, tool.find(tree, 40), 40)
        self.assertEqual((kind, value.key), ("hit", 40))
        # (node, node) arm: first non-null forces insert_left True.
        kind, value = tool.consumer_decision(tree, tool.find(tree, 20), 25)
        self.assertEqual((kind, value), ("insert", True))
        # (0, parent) arm with key above the parent: insert_left False.
        kind, value = tool.consumer_decision(tree, tool.find(tree, 30), 35)
        self.assertEqual((kind, value), ("insert", False))
        # (0, successor) arm from the walk: key below the successor.
        kind, value = tool.consumer_decision(tree, tree.header, 25)
        self.assertEqual((kind, value), ("insert", True))
        # Empty tree: second is the header, so insert_left is True.
        empty = tree_of(None)
        kind, value = tool.consumer_decision(empty, empty.header, 7)
        self.assertEqual((kind, value), ("insert", True))

    def test_caller_bodies_agree_except_call_displacements(self):
        data = BIN.read_bytes()
        # .text: file offset = vaddr - 0x1000.
        c1 = data[0x514CA70 - 0x1000:0x514CB31 - 0x1000]
        c2 = data[0x514CB40 - 0x1000:0x514CC01 - 0x1000]
        self.assertEqual(len(c1), 193)
        self.assertEqual(len(c2), 193)
        masked1 = bytearray(c1)
        masked2 = bytearray(c2)
        for off in (0x18, 0x57, 0x72, 0x9B):
            self.assertEqual(c1[off], 0xE8)
            self.assertEqual(c2[off], 0xE8)
            masked1[off + 1:off + 5] = b"\x00\x00\x00\x00"
            masked2[off + 1:off + 5] = b"\x00\x00\x00\x00"
        self.assertEqual(bytes(masked1), bytes(masked2))

    def test_packet_verifies(self):
        result = subprocess.run(
            [sys.executable, str(PACKET / "verify.py")],
            capture_output=True, text=True, cwd=str(ROOT),
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ALL CHECKS PASSED", result.stdout)

    def test_excerpts_regenerate(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [sys.executable, str(PACKET / "export_excerpts.py"), "--out", tmp],
                capture_output=True, text=True, cwd=str(ROOT),
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for name in ("window.objdump.txt", "caller1.objdump.txt",
                         "caller2.objdump.txt", "plt.objdump.txt"):
                regenerated = Path(tmp, name).read_text()
                self.assertEqual(regenerated, (PACKET / name).read_text())

    def test_corruption_controls(self):
        env = dict(os.environ, HL_NODE94_BIN=str(BIN))
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "packet"
            shutil.copytree(PACKET, copy)
            # Tamper with a semantic record: verification must fail.
            records = copy / "records.json"
            text = records.read_text()
            tampered = text.replace("0x514c8f0", "0x514c8f1", 1)
            self.assertNotEqual(tampered, text)
            records.write_text(tampered)
            result = subprocess.run(
                [sys.executable, str(copy / "verify.py")],
                capture_output=True, text=True, cwd=str(ROOT), env=env,
            )
            self.assertNotEqual(result.returncode, 0)
            # Tamper with an excerpt instead: verification must also fail.
            shutil.rmtree(copy)
            shutil.copytree(PACKET, copy)
            window = copy / "window.objdump.txt"
            lines = window.read_text().splitlines()
            lines[1] = lines[1].replace("push", "po sh", 1) if "push" in lines[1] else lines[1] + " "
            window.write_text("\n".join(lines) + "\n")
            result = subprocess.run(
                [sys.executable, str(copy / "verify.py")],
                capture_output=True, text=True, cwd=str(ROOT), env=env,
            )
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
