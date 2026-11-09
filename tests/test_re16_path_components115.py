import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re16_path_components115 as T  # noqa: E402

CACHE = {}


def image():
    if "image" not in CACHE:
        CACHE["image"] = T.Image(T.BINARY.read_bytes())
    return CACHE["image"]


def case(entry, path, front=0, back=2, root=None, junk=bytes(0x28)):
    if root is None:
        root = int(path.startswith(b"/"))
    return (entry, path, front, back, root, junk, "test")


def check(c, mut=frozenset(), override=None):
    total, bad, rows = T.evaluate(image(), [c], override=override, mut=mut)
    return bad == 0


class ModelTests(unittest.TestCase):
    def test_include_cur_dir(self):
        self.assertTrue(T.include_cur_dir(b"."))
        self.assertTrue(T.include_cur_dir(b"./a"))
        self.assertFalse(T.include_cur_dir(b".."))
        self.assertFalse(T.include_cur_dir(b".a"))
        self.assertFalse(T.include_cur_dir(b""))

    def test_parse_pieces(self):
        self.assertEqual(T.parse_back(b"a/bc", 0, 0), (3, 9, 2, 2))
        self.assertEqual(T.parse_back(b"a/..", 0, 0), (3, 8, 2, 2))
        self.assertEqual(T.parse_back(b"a/.", 0, 0), (2, 0x0a, 2, 1))
        self.assertEqual(T.parse_back(b"a/", 0, 0), (1, 0x0a, 2, 0))
        self.assertEqual(T.parse_back(b"/a", 0, 1), (1, 9, 1, 1))

    def test_parse_panic_on_rooted_empty_slice(self):
        with self.assertRaises(T.Panic):
            T.parse_back(b"", 0, 1)

    def test_next_back_sequence(self):
        path, f, b, n, got = b"/a/./..", 0, 2, 7, []
        while True:
            res, n, f, b = T.next_back(path[:n], f, b, 1)
            if res is None:
                break
            got.append(res[0])
        self.assertEqual(got, [8, 9, 6])

    def test_as_path_trims(self):
        self.assertEqual(T.as_path(b"./a/./", 0, 2, 0), (0, 3))
        self.assertEqual(T.as_path(b"/a//", 0, 2, 1), (0, 2))
        self.assertEqual(T.as_path(b"./a/", 2, 2, 0), (2, 1))


class MachineTests(unittest.TestCase):
    def test_trio_agrees_on_samples(self):
        for p in (b"", b"/", b".", b"./", b"a", b"a/b", b"/a/../b/", b"//a", b"././/a/."):
            for entry in ("parse_back", "as_path", "next_back_drain"):
                self.assertTrue(check(case(entry, p)), (entry, p))

    def test_arbitrary_states_agree(self):
        for p in (b"", b"/a", b"a/.", b"..", b"./x"):
            for front in range(4):
                for back in range(4):
                    for root in (0, 1):
                        for entry in ("parse_back", "as_path", "next_back"):
                            self.assertTrue(check(case(entry, p, front, back, root)), (entry, p, front, back, root))

    def test_prefix_area_is_ignored(self):
        a = T.run(T.machine(image()), image(), T.NEXT_BACK, b"/a/b", 0, 2, 1, bytes(0x28))
        b = T.run(T.machine(image()), image(), T.NEXT_BACK, b"/a/b", 0, 2, 1, bytes([0x5a]) * 0x28)
        self.assertEqual(a[0]["out"][:0x18], b[0]["out"][:0x18])

    def test_unreachable_and_subtract_panics(self):
        sites = T.site_table(image())
        res, _ = T.run(T.machine(image()), image(), T.NEXT_BACK, b"a", 0, 0, 0, bytes(0x28))
        self.assertEqual(res["panic"], "unreachable")
        res, _ = T.run(T.machine(image()), image(), T.PARSE, b"", 0, 2, 1, bytes(0x28))
        self.assertEqual(res["regs"], (1, 0, 0, dict((n, l) for n, _, _, l in sites)["parse_start_gt_len"]))


class NegativeTests(unittest.TestCase):
    def test_model_mutants_are_caught(self):
        paths = (b"/a/./..", b"./a", b"a//b/.", b"..", b".", b"/")
        for name in T.MODEL_MUTANTS:
            caught = False
            for p in paths:
                for entry in ("parse_back", "as_path", "next_back_drain"):
                    if not check(case(entry, p), mut=frozenset([name])):
                        caught = True
            self.assertTrue(caught, name)

    def test_code_byte_flip_is_caught(self):
        self.assertEqual(image().code(0x5c8e803, 1)[0], 0x2f)
        self.assertFalse(check(case("parse_back", b"a/b"), override={0x5c8e803: 0x2e}))

    def test_corrupt_binary_and_range(self):
        data = bytearray(T.BINARY.read_bytes())
        data[image().text["offset"] + 5] ^= 1
        with self.assertRaises(T.ToolError):
            T.Image(bytes(data))
        with self.assertRaises(T.ToolError):
            image().code(image().text["address"] + image().text["size"] + 0x100, 4)

    def test_wrong_site_lea_is_rejected(self):
        saved = T.PANIC_SITES
        T.PANIC_SITES = ((0x5c8e7c5, "x", 0x5c8e7b6),)
        try:
            with self.assertRaises(T.ToolError):
                T.site_table(image())
        finally:
            T.PANIC_SITES = saved


if __name__ == "__main__":
    unittest.main()
