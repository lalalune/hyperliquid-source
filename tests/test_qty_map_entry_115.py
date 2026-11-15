"""Tests for tools/qty_map_entry_115.py: specification, memory builders, mutation sites and recorded results (no binary needed)."""

import json
import pathlib
import struct
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import qty_map_entry_115 as tool  # noqa: E402

WORK = ROOT / "research" / "work-items" / "RE-009-quantities-map-entry-115"


class FakeImage:
    """Minimal image: a code blob mapped at a base address, enough for the decoder and the interpreter."""

    def __init__(self, code, base=0x1000):
        self.blob = bytearray(code)
        self.base = base
        self.fde_ends = {base: base + len(code)}

    def offset(self, va):
        if not self.base <= va < self.base + len(self.blob):
            raise tool.EvidenceError("outside")
        return va - self.base


class Holder:
    def __init__(self):
        self.memory = tool.Memory(None)


def keys(count, seed=3, style="wide"):
    return tool.make_keys(tool.Lcg(seed), count, style)


class GeneratorTests(unittest.TestCase):
    def test_generator_is_deterministic_and_bounded(self):
        a, b = tool.Lcg(7), tool.Lcg(7)
        self.assertEqual([a.next() for _ in range(5)], [b.next() for _ in range(5)])
        self.assertTrue(all(0 <= tool.Lcg(9).below(5) < 5 for _ in range(20)))
        self.assertEqual(len(tool.Lcg(1).blob(33)), 33)

    def test_keys_are_sorted_distinct_twenty_bytes(self):
        for style in ("wide", "near", "mid", "high"):
            found = keys(30, style=style)
            self.assertEqual(found, sorted(set(found)))
            self.assertTrue(all(len(k) == 20 for k in found))
        self.assertEqual(len({k[:19] for k in keys(10, style="near")}), 1)
        self.assertTrue(all(k[4] & 0x80 for k in keys(10, style="high")))

    def test_digest_mismatch_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.verify_digest(b"not the node binary")
        self.assertEqual(tool.verify_digest(b"x", tool.hashlib.sha256(b"x").hexdigest()), tool.hashlib.sha256(b"x").hexdigest())


class SearchSpecTests(unittest.TestCase):
    def test_found_and_insertion_points_match_a_scan(self):
        rows = keys(12)
        for index, key in enumerate(rows):
            self.assertEqual(tool.spec_search(rows, key), (0, index))
        low, high = b"\x00" * 20, b"\xff" * 20
        self.assertEqual(tool.spec_search(rows, low), (1, 0))
        self.assertEqual(tool.spec_search(rows, high), (1, len(rows)))
        self.assertEqual(tool.spec_search([], low), (1, 0))
        for probe in keys(40, seed=11):
            result, index = tool.spec_search(rows, probe)
            self.assertEqual(index, sum(1 for k in rows if k < probe))
            self.assertEqual(result, 0 if probe in rows else 1)

    def test_wrong_specifications_disagree(self):
        rows = keys(9)
        self.assertNotEqual(tool.spec_search(rows, rows[3], "right"), tool.spec_search(rows, rows[3]))
        self.assertNotEqual(tool.spec_search(rows, rows[3], "next"), tool.spec_search(rows, rows[3]))

    def test_unsigned_byte_order(self):
        rows = [b"\x7f" + bytes(19), b"\x80" + bytes(19)]
        self.assertEqual(tool.spec_search(rows, b"\x80" + bytes(19)), (0, 1))


class TreeTests(unittest.TestCase):
    def walk(self, holder, node, height):
        mem = holder.memory
        length = struct.unpack("<H", mem.bytes_at(node + tool.PLEN_AT, 2))[0]
        self.assertLessEqual(length, tool.NODE_CAP)
        own = [bytes(mem.bytes_at(node + tool.KEYS_AT + 20 * i, 20)) for i in range(length)]
        if height == 0:
            return own
        out = []
        for i in range(length + 1):
            child = struct.unpack("<Q", mem.bytes_at(node + tool.EDGES_AT + 8 * i, 8))[0]
            out.extend(self.walk(holder, child, height - 1))
            if i < length:
                out.append(own[i])
        return out

    def test_node_images_hold_every_key_in_order_at_uniform_height(self):
        for count in (1, 11, 12, 32, 64, 130, 400):
            holder = Holder()
            rows = keys(count, seed=count)
            root, height, found, nodes = tool.build_tree(holder, tool.Lcg(count), rows, tool.NODE_AT)
            self.assertEqual(self.walk(holder, root, height), rows)
            self.assertEqual(set(found), set(rows))
            self.assertEqual(height == 0, count <= tool.NODE_CAP)

    def test_walk_reports_leaf_and_index(self):
        holder = Holder()
        rows = keys(64)
        root, height, found, nodes = tool.build_tree(holder, tool.Lcg(2), rows, tool.NODE_AT)
        for key in rows:
            node, h, index = found[key]
            self.assertEqual(tool.spec_tree_walk(nodes, root, height, key), ("occupied", "tree", node, h, index, tool.MAP_AT + 8))
        probe = b"\x00" * 20
        words = tool.spec_tree_walk(nodes, root, height, probe)
        self.assertEqual(words[:2], ("vacant", "tree"))
        self.assertEqual(words[5:], (0, 0))
        self.assertEqual(nodes[words[4]][1], [])


class EntrySpecTests(unittest.TestCase):
    def ring_case(self, count, present):
        live = keys(count + 1)
        query = live[count // 2] if present else live[-1]
        live = live if present else live[:-1]
        live = live[:count] if present else live
        holder = Holder()
        case = {"header": (count + 1, tool.RING_AT, 0, len(live)), "live": live, "query": query, "nodes": None, "staged": None, "staged_nodes": None}
        if not present and len(live) >= tool.PROMOTE_LEN:
            root, height, found, nodes = tool.build_tree(holder, tool.Lcg(5), live, tool.NODE_AT)
            case["staged"], case["staged_nodes"] = (root, height, len(live)), nodes
        return case

    def test_ring_thresholds(self):
        absent_63 = tool.spec_entry(self.ring_case(63, False))
        self.assertEqual(absent_63[0][:2], ("vacant", "ring"))
        self.assertEqual(absent_63[1][0], 64)
        promoted = tool.spec_entry(self.ring_case(64, False))
        self.assertEqual(promoted[0][:2], ("vacant", "tree"))
        self.assertEqual(promoted[1][0], tool.MIN)
        self.assertEqual(promoted[2], struct.pack("<QQQQ", 65, tool.RING_AT, 0, 64) + struct.pack("<QQQQ", 0, 8, 0, 0))
        present = tool.spec_entry(self.ring_case(80, True))
        self.assertEqual(present[0][:2], ("occupied", "ring"))

    def test_tree_thresholds(self):
        holder = Holder()
        for count, expected in ((31, "reached"), (32, "occupied"), (0, "reached")):
            live = keys(max(count, 1))[:count]
            root, height, found, nodes = tool.build_tree(holder, tool.Lcg(1), live, tool.NODE_AT) if live else (0, 0, {}, {})
            query = live[0] if live else b"\x01" * 20
            case = {"header": (tool.MIN, root, height, count), "live": live, "query": query, "nodes": nodes, "staged": None}
            if count == 0:
                case["header"] = (tool.MIN, root, height, 0)
            self.assertEqual(tool.spec_entry(case)[0][0], expected)
        null_root = {"header": (tool.MIN, 0, 0, 40), "live": [], "query": b"\x02" * 20, "nodes": {}, "staged": None}
        self.assertEqual(tool.spec_entry(null_root)[0], ("vacant", "tree", tool.MAP_AT + 8, b"\x02" * 20, 0, 0, tool.MIN))

    def test_wrong_specifications_are_caught(self):
        case = self.ring_case(64, False)
        right = tool.spec_entry(case)
        self.assertNotEqual(tool.spec_entry(case, "limit")[0], right[0])
        got = (right[0], right[1], right[2])
        self.assertTrue(tool.entry_matches(case, got))
        self.assertFalse(tool.entry_matches(case, got, "limit"))
        self.assertFalse(tool.entry_matches(case, (right[0], right[1], None)))
        self.assertFalse(tool.entry_matches(case, (right[0], (0, 0, 0, 0), right[2])))
        self.assertFalse(tool.entry_matches(case, (("occupied", "ring", 0, 0), right[1], right[2])))


class DebitSpecTests(unittest.TestCase):
    BOOK = {b"\x01" * 20: (50, 100), b"\x02" * 20: (200, 100)}

    def test_subtracts_and_clamps_the_limit(self):
        got = tool.spec_debit(self.BOOK, b"\x01" * 20, 30)
        self.assertEqual(got[b"\x01" * 20], (50, 70))
        got = tool.spec_debit(self.BOOK, b"\x02" * 20, 30)
        self.assertEqual(got[b"\x02" * 20], (70, 70))
        self.assertEqual(got[b"\x01" * 20], (50, 100))

    def test_underflow_panics_and_absent_key_changes_nothing(self):
        self.assertEqual(tool.spec_debit(self.BOOK, b"\x01" * 20, 101), "panic")
        self.assertEqual(tool.spec_debit(self.BOOK, b"\x01" * 20, 100)[b"\x01" * 20], (0, 0))
        self.assertEqual(tool.spec_debit(self.BOOK, b"\x09" * 20, 5), self.BOOK)

    def test_wrong_specifications_differ(self):
        key = b"\x02" * 20
        self.assertNotEqual(tool.spec_debit(self.BOOK, key, 30, "no_clamp"), tool.spec_debit(self.BOOK, key, 30))
        self.assertNotEqual(tool.spec_debit(self.BOOK, key, 101, "saturate"), tool.spec_debit(self.BOOK, key, 101))

    def test_debit_cases_cover_both_maps_and_panics(self):
        rng = tool.Lcg(4)
        cases = [tool.debit_case(rng) for _ in range(300)]
        self.assertEqual({c["shape"] for c in cases}, {"ring", "tree"})
        self.assertTrue(any(tool.spec_debit(c["book"], c["query"], c["amount"]) == "panic" for c in cases))
        self.assertTrue(any(c["query"] not in c["book"] and c["live"] for c in cases))
        self.assertTrue(all(c["query"] in c["book"] or c["query"] not in c["live"] for c in cases))

    def test_debit_tree_layout_keeps_values_before_keys(self):
        holder = Holder()
        rows = keys(30)
        root, height, found, nodes = tool.build_tree(holder, tool.Lcg(6), rows, tool.NODE_AT, tool.DEBIT_LAYOUT)
        node, h, index = found[rows[0]]
        length = struct.unpack("<H", holder.memory.bytes_at(node + 0x196, 2))[0]
        self.assertEqual(length, len(nodes[node][0]))
        self.assertEqual(bytes(holder.memory.bytes_at(node + 0xB8 + 20 * index, 20)), rows[0])

    def test_equivalence_classifier_needs_the_right_instruction(self):
        image = FakeImage(bytes([0x49, 0x83, 0xFF, 0x01, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x95, 0xC0, 0xC3]))
        rows = tool.decode_range(image, 0x1000, 0x100D)
        self.assertEqual(tool.classify_equivalent(rows[0], rows[1]), "short-circuit-one")
        self.assertEqual(tool.classify_equivalent(rows[1], rows[2]), "low-byte-overwrite")
        self.assertIsNone(tool.classify_equivalent(rows[2], rows[3]))
        self.assertIsNone(tool.classify_equivalent(rows[3], None))


class MutationTests(unittest.TestCase):
    # jne +2 ; mov eax,5 ; ret
    CODE = bytes([0x75, 0x02, 0xB8, 0x05, 0x00, 0x00, 0x00, 0xC3])

    def test_sites_invert_branch_and_flip_immediate(self):
        image = FakeImage(self.CODE)
        sites = tool.mutation_sites(image, 0x1000, 0x1008, {0x1000, 0x1002, 0x1007})
        kinds = {(va, kind): patch for va, kind, patch in sites}
        self.assertEqual(kinds[(0x1000, "invert-branch")], {0x1000: 0x74})
        self.assertEqual(kinds[(0x1002, "flip-immediate")], {0x1003: 0x04})

    def test_unexecuted_rows_are_not_mutated(self):
        sites = tool.mutation_sites(FakeImage(self.CODE), 0x1000, 0x1008, {0x1007})
        self.assertEqual(sites, [])

    def test_interpreter_runs_and_patches_change_the_result(self):
        image = FakeImage(bytes([0xB8, 0x05, 0x00, 0x00, 0x00, 0xC3]))
        machine = tool.Machine(image)
        self.assertEqual(machine.run(0x1000, {}) & 0xFFFFFFFF, 5)
        machine = tool.Machine(image, {0x1001: 0x06})
        self.assertEqual(machine.run(0x1000, {}) & 0xFFFFFFFF, 6)

    def test_memcmp_hook_is_unsigned_and_length_bound(self):
        image = FakeImage(bytes([0xC3]))
        machine = tool.Machine(image)
        a, b = tool.HEAP_BASE, tool.HEAP_BASE + 0x100
        machine.memory.put_bytes(a, b"\x80" + bytes(19))
        machine.memory.put_bytes(b, b"\x7f" + bytes(19))
        machine.regs[tool.RDI], machine.regs[tool.RSI], machine.regs[tool.RDX] = a, b, 20
        tool.memcmp_hook(machine)
        self.assertEqual(machine.regs[tool.RAX], 1)
        machine.memory.put_bytes(a, b"\x7f" + bytes(18) + b"\x01")
        machine.memory.put_bytes(b, b"\x7f" + bytes(19))
        machine.regs[tool.RDX] = 19
        tool.memcmp_hook(machine)
        self.assertEqual(machine.regs[tool.RAX], 0)
        machine.regs[tool.RDX] = 20
        tool.memcmp_hook(machine)
        self.assertEqual(machine.regs[tool.RAX], 1)


class RecordedResultTests(unittest.TestCase):
    def test_measure_is_consistent_with_controls(self):
        measure = json.loads((WORK / "measure.json").read_text())
        rows = (WORK / "controls.tsv").read_text().splitlines()[1:]
        self.assertEqual(len(rows), measure["negative_controls"])
        self.assertEqual(sum(1 for r in rows if r.endswith("\t1")), measure["negative_detected"])
        equivalent = (WORK / "equivalent-mutants.tsv").read_text().splitlines()[1:]
        self.assertEqual(len(equivalent), measure["equivalent"])
        self.assertEqual(measure["negative_detected"] + measure["equivalent"], measure["negative_controls"])
        self.assertGreater(measure["cases"], 0)

    def test_sources_hold_no_absolute_paths(self):
        banned = ["/" + d + "/" for d in ("home", "mnt", "srv", "root", "tmp", "opt", "var", "etc")]
        for path in (ROOT / "tools" / "qty_map_entry_115.py", pathlib.Path(__file__)):
            text = path.read_text()
            self.assertFalse([b for b in banned if b in text.replace('"' + b, "").replace("'" + b, "")], path.name)


if __name__ == "__main__":
    unittest.main()
