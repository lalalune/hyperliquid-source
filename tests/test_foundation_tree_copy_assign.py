import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import foundation_tree_copy_assign as tool  # noqa: E402

PACKET = ROOT / "research" / "work-items" / "RE-001-tree-copy-assign-94"


def payload(key, value):
    """16 payload bytes: int32 key at +0x20, double value at +0x28."""
    return struct.pack("<i", key) + b"\x00\x00\x00\x00" + struct.pack("<d", value)


def key_of(node):
    return struct.unpack("<i", node.payload[:4])[0]


def value_of(node):
    return struct.unpack("<d", node.payload[8:16])[0]


def build(spec):
    """Build a tree from a nested (key, value, left, right) spec."""
    if spec is None:
        return None
    key, value, left, right = spec
    node = tool.Node(value=1, payload=payload(key, value))
    node.left = build(left)
    if node.left is not None:
        node.left.parent = node
    node.right = build(right)
    if node.right is not None:
        node.right.parent = node
    return node


def shape(node):
    if node is None:
        return None
    return (key_of(node), shape(node.left), shape(node.right))


SRC_SPEC = (10, 1.5, (5, 2.5, (3, 3.5, None, None), None), (15, 4.5, None, (20, 5.5, None, None)))


class CopyAssignTests(unittest.TestCase):
    def test_self_assign_is_noop(self):
        dest = tool.Container(build(SRC_SPEC))
        before = shape(dest.root)
        stats = tool.copy_assign(dest, dest)
        self.assertEqual(shape(dest.root), before)
        self.assertEqual((stats.allocations, stats.reuses, stats.destructions), (0, 0, 0))
        self.assertEqual(dest.count, 5)

    def test_empty_src_clears_dest(self):
        dest = tool.Container(build(SRC_SPEC))
        src = tool.Container(None)
        stats = tool.copy_assign(dest, src)
        self.assertIsNone(dest.root)
        self.assertEqual(dest.leftmost, tool.HEADER)
        self.assertEqual(dest.rightmost, tool.HEADER)
        self.assertEqual(dest.count, 0)
        self.assertEqual((stats.allocations, stats.reuses, stats.destructions), (0, 0, 5))

    def test_empty_dest_allocates_all(self):
        dest = tool.Container(None)
        src = tool.Container(build(SRC_SPEC))
        stats = tool.copy_assign(dest, src)
        self.assertEqual(shape(dest.root), shape(src.root))
        self.assertEqual((stats.allocations, stats.reuses, stats.destructions), (5, 0, 0))
        self.assertEqual(key_of(dest.leftmost), 3)
        self.assertEqual(key_of(dest.rightmost), 20)
        self.assertEqual(dest.count, 5)

    def test_smaller_src_reuses_and_destroys_leftover(self):
        dest = tool.Container(build(SRC_SPEC))
        src = tool.Container(build((7, 9.0, None, None)))
        stats = tool.copy_assign(dest, src)
        self.assertEqual(shape(dest.root), (7, None, None))
        self.assertEqual(value_of(dest.root), 9.0)
        self.assertEqual((stats.allocations, stats.reuses, stats.destructions), (0, 1, 4))
        self.assertEqual(dest.count, 1)

    def test_larger_src_reuses_all_then_allocates(self):
        dest = tool.Container(build((7, 9.0, None, None)))
        src = tool.Container(build(SRC_SPEC))
        stats = tool.copy_assign(dest, src)
        self.assertEqual(shape(dest.root), shape(src.root))
        self.assertEqual((stats.allocations, stats.reuses, stats.destructions), (4, 1, 0))
        self.assertEqual(dest.count, 5)

    def test_payload_bytes_preserved(self):
        dest = tool.Container(None)
        src = tool.Container(build(SRC_SPEC))
        tool.copy_assign(dest, src)
        for s_node, d_node in zip(tool.inorder(src.root), tool.inorder(dest.root)):
            self.assertEqual(d_node.payload, s_node.payload)
            self.assertEqual(d_node.value, s_node.value)

    def test_extremes_on_skewed_tree(self):
        # Left spine only: leftmost is the deepest node, rightmost the root.
        dest = tool.Container(None)
        src = tool.Container(build((30, 1.0, (20, 2.0, (10, 3.0, None, None), None), None)))
        tool.copy_assign(dest, src)
        self.assertEqual(key_of(dest.leftmost), 10)
        self.assertEqual(key_of(dest.rightmost), 30)
        self.assertEqual(dest.count, 3)

    def test_erase_count_matches_subtree_size(self):
        root = build(SRC_SPEC)
        self.assertEqual(tool.erase_count(root), 5)
        self.assertEqual(tool.erase_count(None), 0)

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
            for name in ("window.objdump.txt", "copy.objdump.txt", "erase.objdump.txt"):
                regenerated = Path(tmp, name).read_text()
                self.assertEqual(regenerated, (PACKET / name).read_text())

    def test_corruption_controls(self):
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "packet"
            shutil.copytree(PACKET, copy)
            # Tamper with a semantic record: verification must fail.
            records = copy / "records.json"
            text = records.read_text()
            tampered = text.replace("0x514c780", "0x514c781", 1)
            self.assertNotEqual(tampered, text)
            records.write_text(tampered)
            result = subprocess.run(
                [sys.executable, str(copy / "verify.py")],
                capture_output=True, text=True, cwd=str(ROOT),
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
                capture_output=True, text=True, cwd=str(ROOT),
            )
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
