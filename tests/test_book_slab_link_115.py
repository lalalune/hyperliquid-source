import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))

import book_slab_link_115 as T  # noqa: E402

ENT = T.ENT
M64 = T.M64


def occ(prev=None, nxt=None, size=100, price=7, flag=0, key=0x55, aux=9):
    raw = bytearray(bytes([0x33]) * ENT)
    T.setq(raw, 0, 0 if prev is None else 1)
    T.setq(raw, 8, 0 if prev is None else prev)
    T.setq(raw, 0x10, 0 if nxt is None else 1)
    T.setq(raw, 0x18, 0 if nxt is None else nxt)
    T.setq(raw, 0xB0, price)
    raw[0xD8] = flag
    raw[0xD2] = 0x44
    raw[0xDC:0xE0] = aux.to_bytes(4, "little")
    T.setq(raw, 0xE0, size)
    T.setq(raw, 0xF0, key)
    return bytes(raw)


def vac(nxt):
    raw = bytearray(bytes([0x77]) * ENT)
    T.setq(raw, 0, 2)
    T.setq(raw, 8, nxt)
    return bytes(raw)


def level(head=None, tail=None, cursor=(0, 0), total=0, count=0):
    raw = bytearray(bytes([0x11]) * 0x80)
    T.setq(raw, 0, 0 if head is None else 1)
    T.setq(raw, 8, head or 0)
    T.setq(raw, 0x10, 0 if tail is None else 1)
    T.setq(raw, 0x18, tail or 0)
    T.setq(raw, 0x20, cursor[0])
    T.setq(raw, 0x28, cursor[1])
    T.setq(raw, 0x70, total)
    T.setq(raw, 0x78, count)
    return bytes(raw)


def dirty_tail():
    raw = bytearray(level(0, 1))
    T.setq(raw, 0x10, 1 | (1 << 32))
    return bytes(raw)


def world(jelem, ents, nxt=None, count=None, scap=None, jlen=1, jcap=None, total=1000, lvl=None, size=250, **extra):
    order = bytearray(bytes([0x22]) * ENT)
    T.setq(order, 0xE0, size)
    T.setq(order, 0xB0, 4242)
    T.setq(order, 0xF0, 0x1234)
    c = {"scap": len(ents) + 2 if scap is None else scap, "ents": list(ents), "count": len([e for e in ents if T.q(e, 0) != 2]) if count is None else count,
         "nxt": len(ents) if nxt is None else nxt, "jcap": jlen + 2 if jcap is None else jcap, "jents": [bytes([9]) * jelem] * jlen, "jelem": jelem,
         "T": total, "L": lvl if lvl is not None else level(), "O": bytes(order), "A": 0xABCDEF, "tag": 0, "idx": 0, "level": True}
    c.update(extra)
    return c


class Base(unittest.TestCase):
    def _setup(cls):
        cls.image = T.load_image_checked()
        for name, va, kind in T.COPIES:
            T.JELEM[name] = T.journal_elem(cls.image, va)
        cls.rigs = {name: T.Rig(cls.image, name, va, kind) for name, va, kind in T.COPIES}

    _setup = classmethod(_setup)
    setUpClass = classmethod(lambda cls: cls._setup())

    def both(self, name, c):
        kind = c.get("kind") or [k for n, v, k in T.COPIES if n == name][0]
        exp = T.expected(c, kind, name)
        rig = self.rigs[name]
        panic, ev, heap, ret = rig.run(c)
        self.assertEqual(panic, exp[0])
        self.assertEqual(ev, exp[1])
        real = T.real_snapshot(rig, heap, exp[4], c)
        self.assertEqual(real, exp[2])
        return panic, ev, heap, ret, rig

    def read(self, heap, rig):
        s_len = T.q(heap, T.OFF_S + 0x10)
        ptr = T.q(heap, T.OFF_S + 8) - T.H
        ents = [bytes(heap[ptr + i * ENT:ptr + (i + 1) * ENT]) for i in range(s_len)]
        return s_len, ents


INSERTS = ("insert-a1", "insert-b1", "insert-a2", "insert-b2")
UNLINKS = ("unlink-b", "unlink-a")


class Static(unittest.TestCase):
    def _setup(cls):
        cls.image = T.load_image_checked()

    _setup = classmethod(_setup)
    setUpClass = classmethod(lambda cls: cls._setup())

    def test_every_copy_starts_an_fde(self):
        for name, va, kind in T.COPIES:
            start, end = self.image.exact_fde(va)
            self.assertEqual(start, va)
            self.assertGreater(end - start, 400)
            with self.assertRaises(T.EvidenceError):
                self.image.exact_fde(va + 1)

    def test_journal_record_sizes(self):
        want = {"insert-a1": 0x2B8, "insert-b1": 0x2C8, "insert-a2": 0x2B8, "insert-b2": 0x2C8, "unlink-b": 0x2C8, "unlink-a": 0x2B8}
        for name, va, kind in T.COPIES:
            self.assertEqual(T.journal_elem(self.image, va), want[name])

    def test_digest_check_rejects_a_changed_binary(self):
        blob = bytearray(T.BINARY.read_bytes()[:4096])
        with self.assertRaises(T.EvidenceError):
            T.check_blob(bytes(blob))

    def test_call_sites(self):
        for name, va, kind in T.COPIES:
            sites = T.site_table(self.image, va)
            slots = [s[2] for s in sites if s[1] == "slot"]
            self.assertEqual(slots.count(T.REPORT_SLOT), 2 if kind == "insert" else 1)
            self.assertEqual(slots.count(T.PANIC_LOC_SLOT), 2 if kind == "insert" else 1)
            if kind == "unlink":
                self.assertIn(0x4DE02D0, [s[2] for s in sites if s[1] == "call"])
            for site in sites:
                if site[2] == T.REPORT_SLOT or (site[2] == T.PANIC_LOC_SLOT and kind == "insert"):
                    self.assertIsNotNone(site[3], "Location row for %#x" % site[0])
                    self.assertTrue(site[3][0].startswith("l1/"))


class InsertTests(Base):
    def test_append_to_an_empty_level(self):
        for name in INSERTS:
            c = world(T.JELEM[name], [], total=5)
            c.update(tag=0, idx=0)
            panic, ev, heap, ret, rig = self.both(name, c)
            self.assertIsNone(panic)
            self.assertEqual(ret, 0)
            s_len, ents = self.read(heap, rig)
            self.assertEqual(s_len, 1)
            self.assertEqual(T.q(heap, T.OFF_S + 0x18), 1)
            self.assertEqual(T.q(heap, T.OFF_S + 0x20), 1)
            self.assertEqual((T.q(ents[0], 0), T.q(ents[0], 0x10)), (0, 0))
            lv = bytes(heap[T.OFF_L:T.OFF_L + 0x80])
            self.assertEqual((T.q(lv, 0), T.q(lv, 8), T.q(lv, 0x10), T.q(lv, 0x18)), (1, 0, 1, 0))
            self.assertEqual((T.q(lv, 0x70), T.q(lv, 0x78)), (250, 1))
            self.assertEqual(T.q(heap, T.OFF_T), 255)
            self.assertNotIn("grow:slab", ev)

    def test_append_after_the_tail_updates_the_old_tail(self):
        for name in INSERTS:
            c = world(T.JELEM[name], [occ(None, 1), occ(0, None)], lvl=level(0, 1, total=300, count=2))
            c.update(tag=0, idx=0)
            panic, ev, heap, ret, rig = self.both(name, c)
            self.assertEqual(ret, 2)
            s_len, ents = self.read(heap, rig)
            self.assertEqual((T.q(ents[1], 0x10), T.q(ents[1], 0x18)), (1, 2))
            self.assertEqual((T.q(ents[2], 0), T.q(ents[2], 8), T.q(ents[2], 0x10)), (1, 1, 0))
            lv = bytes(heap[T.OFF_L:T.OFF_L + 0x80])
            self.assertEqual((T.q(lv, 0x10), T.q(lv, 0x18)), (1, 2))
            self.assertEqual((T.q(lv, 0x70), T.q(lv, 0x78)), (550, 3))

    def test_insert_before_a_slot(self):
        for name in INSERTS:
            c = world(T.JELEM[name], [occ(None, 1), occ(0, None)], lvl=level(0, 1, total=300, count=2))
            c.update(tag=1, idx=1)
            panic, ev, heap, ret, rig = self.both(name, c)
            s_len, ents = self.read(heap, rig)
            self.assertEqual((T.q(ents[2], 0), T.q(ents[2], 8), T.q(ents[2], 0x10), T.q(ents[2], 0x18)), (1, 0, 1, 1))
            self.assertEqual((T.q(ents[1], 0), T.q(ents[1], 8)), (1, 2))
            self.assertEqual((T.q(ents[0], 0x10), T.q(ents[0], 0x18)), (1, 2))
            lv = bytes(heap[T.OFF_L:T.OFF_L + 0x80])
            self.assertEqual((T.q(lv, 0), T.q(lv, 8)), (1, 0))

    def test_insert_before_the_head_moves_the_head(self):
        for name in INSERTS:
            c = world(T.JELEM[name], [occ(None, None)], lvl=level(0, 0, total=1, count=1))
            c.update(tag=1, idx=0)
            panic, ev, heap, ret, rig = self.both(name, c)
            lv = bytes(heap[T.OFF_L:T.OFF_L + 0x80])
            self.assertEqual((T.q(lv, 0), T.q(lv, 8)), (1, 1))
            self.assertEqual((T.q(lv, 0x10), T.q(lv, 0x18)), (1, 0))

    def test_vacant_slot_is_reused_and_free_list_advances(self):
        for name in INSERTS:
            c = world(T.JELEM[name], [occ(None, None), vac(3), occ(None, None), vac(4)], nxt=1, count=2)
            c.update(tag=0, idx=0, L=level(0, 2, total=1, count=2))
            panic, ev, heap, ret, rig = self.both(name, c)
            self.assertEqual(ret, 1)
            self.assertEqual(T.q(heap, T.OFF_S + 0x20), 3)
            self.assertEqual(T.q(heap, T.OFF_S + 0x10), 4)
            self.assertEqual(T.q(heap, T.OFF_S + 0x18), 3)

    def test_totals_saturate_and_report(self):
        for name in INSERTS:
            c = world(T.JELEM[name], [], total=M64 - 3, lvl=level(None, None, total=M64 - 1))
            c.update(tag=0, idx=0)
            panic, ev, heap, ret, rig = self.both(name, c)
            self.assertEqual(T.q(heap, T.OFF_T), M64)
            self.assertEqual(T.q(heap, T.OFF_L + 0x70), M64)
            self.assertEqual([e for e in ev if e.startswith("report")], ["report:total-add", "report:level-add"])

    def test_free_list_pointing_past_the_end_panics(self):
        for name in INSERTS:
            c = world(T.JELEM[name], [occ()], nxt=5)
            c.update(tag=0, idx=0)
            panic, ev, heap, ret, rig = self.both(name, c)
            self.assertEqual(panic, "fmt:slab-next-beyond-len")
            self.assertEqual(T.q(heap, T.OFF_S + 0x18), 2)

    def test_dirty_vacant_word_is_found_by_the_qword_test_and_caught_by_the_dword_test(self):
        for name in INSERTS:
            dirty = bytearray(occ())
            T.setq(dirty, 0, 2 | (1 << 32))
            c = world(T.JELEM[name], [bytes(dirty)])
            c.update(tag=1, idx=0)
            panic, ev, heap, ret, rig = self.both(name, c)
            self.assertEqual(panic, "loc:prev-slot-missing")

    def test_journal_record_fields(self):
        for name in INSERTS:
            c = world(T.JELEM[name], [occ(None, None, key=0x777)], jlen=0, jcap=0, lvl=level(0, 0))
            c.update(tag=1, idx=0)
            panic, ev, heap, ret, rig = self.both(name, c)
            self.assertIn("grow:journal", ev)
            at = T.q(heap, T.OFF_J + 8) - T.H
            rec = bytes(heap[at:at + rig.jelem])
            self.assertEqual((T.q(rec, 0), T.q(rec, 8), T.q(rec, 0x10), T.q(rec, 0x18)), (2, 1, 0x777, 250))
            self.assertEqual((T.q(rec, 0x20), T.q(rec, 0x28), T.q(rec, 0x30)), (4242, 0xABCDEF, 0x1234))
            self.assertEqual(T.q(heap, T.OFF_J + 0x10), 1)


class UnlinkTests(Base):
    def test_absent_slots_return_the_none_word(self):
        for name in UNLINKS:
            for ents, idx in (([], 0), ([vac(1)], 0), ([occ()], 5), ([occ()], M64)):
                c = world(T.JELEM[name], ents)
                c.update(idx=idx, kind="unlink")
                panic, ev, heap, ret, rig = self.both(name, c)
                self.assertEqual(T.q(heap, T.OFF_OUT), 2)
                self.assertEqual(T.q(heap, T.OFF_J + 0x10), 1)

    def test_only_entry_empties_the_level(self):
        for name in UNLINKS:
            c = world(T.JELEM[name], [occ(None, None, size=40)], total=100, lvl=level(0, 0, total=40, count=1))
            c.update(idx=0, kind="unlink")
            panic, ev, heap, ret, rig = self.both(name, c)
            self.assertEqual(heap[T.OFF_OUT + ENT], 1)
            lv = bytes(heap[T.OFF_L:T.OFF_L + 0x80])
            self.assertEqual((T.q(lv, 0), T.q(lv, 0x10), T.q(lv, 0x70), T.q(lv, 0x78)), (0, 0, 0, 0))
            self.assertEqual(T.q(heap, T.OFF_T), 60)
            s_len, ents = self.read(heap, rig)
            self.assertEqual((T.q(ents[0], 0), T.q(ents[0], 8)), (2, 1))
            self.assertEqual(T.q(heap, T.OFF_S + 0x20), 0)
            self.assertEqual(T.q(heap, T.OFF_S + 0x18), 0)
            self.assertEqual(T.q(bytes(heap[T.OFF_OUT:T.OFF_OUT + ENT]), 0xE0), 40)

    def test_middle_entry_relinks_both_neighbours(self):
        for name in UNLINKS:
            c = world(T.JELEM[name], [occ(None, 1), occ(0, 2), occ(1, None)], lvl=level(0, 2, total=900, count=3))
            c.update(idx=1, kind="unlink")
            panic, ev, heap, ret, rig = self.both(name, c)
            s_len, ents = self.read(heap, rig)
            self.assertEqual((T.q(ents[0], 0x10), T.q(ents[0], 0x18)), (1, 2))
            self.assertEqual((T.q(ents[2], 0), T.q(ents[2], 8)), (1, 0))
            self.assertEqual(heap[T.OFF_OUT + ENT], 0)

    def test_head_removal_moves_the_head_and_cursor_follows(self):
        for name in UNLINKS:
            c = world(T.JELEM[name], [occ(None, 1), occ(0, None)], lvl=level(0, 1, cursor=(1, 0), total=900, count=2))
            c.update(idx=0, kind="unlink")
            panic, ev, heap, ret, rig = self.both(name, c)
            lv = bytes(heap[T.OFF_L:T.OFF_L + 0x80])
            self.assertEqual((T.q(lv, 0), T.q(lv, 8)), (1, 1))
            self.assertEqual((T.q(lv, 0x20), T.q(lv, 0x28)), (1, 1))
            s_len, ents = self.read(heap, rig)
            self.assertEqual((T.q(ents[1], 0), T.q(ents[1], 8)), (0, 0))

    def test_tree_step_and_negative_key_and_null_level(self):
        for name in UNLINKS:
            c = world(T.JELEM[name], [occ(None, None, flag=1, aux=7, key=99)], lvl=level(0, 0, total=250, count=1))
            c.update(idx=0, kind="unlink")
            panic, ev, heap, ret, rig = self.both(name, c)
            self.assertEqual(ev, ["tree:%x:%x:%x" % (T.H + T.OFF_L + 0x50, 99, 7)])
            c = world(T.JELEM[name], [occ(None, None, price=(1 << 63) + 5)], lvl=level(0, 0))
            c.update(idx=0, kind="unlink")
            self.assertEqual(self.both(name, c)[0], "str:negative-key")
            c = world(T.JELEM[name], [occ(None, None, size=7)], total=3, lvl=level(0, 0, total=7, count=1))
            c.update(idx=0, kind="unlink", level=False)
            panic, ev, heap, ret, rig = self.both(name, c)
            self.assertEqual(ev, ["report:total-sub"])
            self.assertEqual(T.q(heap, T.OFF_T), 0)
            self.assertEqual(heap[T.OFF_OUT + ENT], 0)
            self.assertEqual(T.q(heap, T.OFF_L + 0x70), 7)

    def test_missing_neighbours_panic(self):
        for name in UNLINKS:
            c = world(T.JELEM[name], [occ(None, 3)], lvl=level(0, 0))
            c.update(idx=0, kind="unlink")
            self.assertEqual(self.both(name, c)[0], "loc:unlink-next-missing")
            c = world(T.JELEM[name], [occ(4, None)], lvl=level(0, 0))
            c.update(idx=0, kind="unlink")
            self.assertEqual(self.both(name, c)[0], "loc:unlink-prev-missing")


class Controls(Base):
    def test_each_flaw_is_visible_on_a_hand_world(self):
        probes = {
            "total-wraps": ("insert", world(T.JELEM["insert-a1"], [], total=M64), dict(tag=0, idx=0)),
            "kind-qword": ("insert", world(T.JELEM["insert-a1"], [occ(None, 1), occ(0, None)], lvl=dirty_tail()), dict(tag=0, idx=0)),
            "tag-any": ("insert", world(T.JELEM["insert-a1"], [occ(None, 1), occ(0, None)], lvl=level(0, 1)), dict(tag=3, idx=0)),
            "no-prev-link": ("insert", world(T.JELEM["insert-a1"], [occ(None, None)], lvl=level(0, 0)), dict(tag=0, idx=0)),
            "head-for-tail": ("insert", world(T.JELEM["insert-a1"], [], lvl=level()), dict(tag=0, idx=0)),
            "return-len": ("insert", world(T.JELEM["insert-a1"], []), dict(tag=0, idx=0)),
            "cursor-any-idx": ("unlink", world(T.JELEM["unlink-b"], [occ(None, 1), occ(0, None)], lvl=level(0, 1, cursor=(1, 5))), dict(idx=0)),
            "flag-plain": ("unlink", world(T.JELEM["unlink-b"], [occ()], lvl=level(0, 0)), dict(idx=0)),
            "tree-never": ("unlink", world(T.JELEM["unlink-b"], [occ(flag=1)], lvl=level(0, 0)), dict(idx=0)),
            "sum-wraps": ("unlink", world(T.JELEM["unlink-b"], [occ(size=50)], lvl=level(0, 0, total=10)), dict(idx=0)),
        }
        for flaw, (kind, c, extra) in probes.items():
            c.update(extra)
            c["kind"] = kind
            name = "insert-a1" if kind == "insert" else "unlink-b"
            good = T.expected(c, kind, name)
            bad = T.expected(c, kind, name, flaw)
            self.assertTrue(good[0] != bad[0] or good[1] != bad[1] or good[2] != bad[2] or good[3] != bad[3], flaw)

    def test_flaw_names_exist_in_the_reconstruction(self):
        source = pathlib.Path(T.__file__).read_text()
        for flaw in T.INSERT_FLAWS + T.UNLINK_FLAWS:
            self.assertGreaterEqual(source.count('"%s"' % flaw), 2, flaw)

    def test_flipped_found_branch_is_caught_on_real_bytes(self):
        name, va, kind = T.COPIES[0]
        c = world(T.JELEM[name], [occ(None, None)], lvl=level(0, 0))
        c.update(tag=1, idx=0)
        exp = T.expected(c, kind, name)
        caught = 0
        for label, mva, patch in T.mutant_list(self.image, va):
            if label != "jcc-flip":
                continue
            mut = T.Rig(self.image, name, va, kind, patch)
            try:
                got = mut.run(c)
            except (T.Halt, T.EvidenceError, T.Panicked):
                caught += 1
                continue
            snap = T.real_snapshot(mut, got[2], exp[4], c)
            if got[0] != exp[0] or got[1] != exp[1] or snap != exp[2]:
                caught += 1
        self.assertGreaterEqual(caught, 8)

    def test_out_of_range_address_is_refused(self):
        with self.assertRaises(T.EvidenceError):
            T.static_rows(self.image, 0x1)
        with self.assertRaises(T.EvidenceError):
            T.static_rows(self.image, T.COPIES[0][1] + 4)


class FullRun(unittest.TestCase):
    def test_small_replay_matches_and_is_deterministic(self):
        image = T.load_image_checked()
        first = T.run_all(image, 40, byte_controls=False)
        second = T.run_all(image, 40, byte_controls=False)
        self.assertEqual(first["digest"].hexdigest(), second["digest"].hexdigest())
        self.assertEqual(sum(c["mismatches"] for c in first["copies"]), 0)
        self.assertEqual(first["cases"], 240)

    def test_equivalence_proof_rejects_a_live_displacement(self):
        image = T.load_image_checked()
        name, va, kind = T.COPIES[2]
        rows = T.static_rows(image, va)[2]
        live = [r for r in rows if r.op == "lea"][-1]
        self.assertIsNone(T.equivalence_reason(image, va, "imm-bit0", live.va))


if __name__ == "__main__":
    unittest.main()
