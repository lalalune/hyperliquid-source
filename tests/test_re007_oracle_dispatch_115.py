"""Controls for the node #115 oracle update dispatch reconstruction (root 0x2753b90, body 0x2d35a80, drop glue)."""
import datetime
import json
from pathlib import Path
import random
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import re007_oracle_dispatch_115 as T  # noqa: E402

WORK = ROOT / "research" / "work-items" / "RE-007-oracle-update-dispatch-115"


def pack_date(year, month, day):
    ordinal = datetime.date(year, month, day).timetuple().tm_yday
    return (year << 13 | ordinal << 4 | 0xA) & T.M32


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = T.load_image()
        cls.rig = T.Rig(cls.image)


class BinaryIdentity(Base):
    def test_digest_is_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / "blob"
            fake.write_bytes(b"not the node binary")
            with self.assertRaises(T.EvidenceError):
                T.load_image(fake)

    def test_member_extents_come_from_the_bytes(self):
        sizes = {va: self.image.exact_fde(va)[1] - va for va in T.MEMBERS}
        self.assertEqual(sizes[0x2753B90], 820)
        self.assertEqual(sum(sizes.values()), 9233)

    def test_foreign_address_is_not_a_function_start(self):
        with self.assertRaises(T.EvidenceError):
            self.image.exact_fde(0x2753B91)

    def test_panic_literals_match_the_model_constants(self):
        rows = {(reg, target) for reg, _, target in T.panic_literals(self.image)}
        for pair in (T.PANIC_ROOT["dex"], T.PANIC_ROOT["book"]):
            self.assertIn(("rdi", pair[0]), rows)
            self.assertIn(("rcx", pair[1]), rows)
            self.assertIn(("r8", pair[2]), rows)

    def test_pins_are_found(self):
        for fn, name, pattern, matches, addresses, meaning in T.pin_rows(self.image):
            self.assertGreaterEqual(matches, 1, name)


class ModelsAgainstBytes(Base):
    def run_kind(self, kind, count):
        for index in range(count):
            ok, label, trace = T.CHECKS[kind](self.rig, T.case_rng(kind, index))
            self.assertTrue(ok, (kind, index, label))

    def test_root(self):
        self.run_kind("root", 300)

    def test_body(self):
        self.run_kind("body", 600)

    def test_small_drop(self):
        self.run_kind("small", 150)

    def test_event_vector_drop(self):
        self.run_kind("events", 150)

    def test_enum_drop(self):
        self.run_kind("enum", 500)

    def test_every_body_path_is_reached(self):
        seen = set()
        for index in range(1500):
            seen.add(T.check_body(self.rig, T.case_rng("body", index))[1])
        for path in ("classify-reject", "limit-reject", "validate-error", "apply-ok", "apply-days-fallback",
                     "apply-range-fallback", "event-queued", "event-queued-grow"):
            self.assertIn(path, seen)


class Arithmetic(unittest.TestCase):
    def test_millis_match_the_calendar(self):
        rnd = random.Random(5)
        for _ in range(400):
            year = rnd.randint(1970, 2100)
            month, day = rnd.randint(1, 12), rnd.randint(1, 28)
            secs, nanos = rnd.randint(0, 86399), rnd.randint(0, 999999999)
            expected = (int((datetime.datetime(year, month, day) - datetime.datetime(1970, 1, 1)).total_seconds()) + secs) * 1000 + nanos // 1000000
            self.assertEqual(T.days_millis(pack_date(year, month, day), secs, nanos), expected)

    def test_epoch_and_before_epoch(self):
        self.assertEqual(T.days_millis(pack_date(1970, 1, 1), 0, 0), 0)
        self.assertEqual(T.days_millis(pack_date(2000, 1, 1), 0, 0), 946684800000)
        self.assertEqual(T.days_millis(pack_date(1969, 12, 31), 10, 0), 0)  # negative values clamp to zero

    def test_wrong_epoch_constant_is_visible(self):
        date = pack_date(2024, 5, 6)
        self.assertNotEqual(T.days_millis(date, 0, 0, ("epoch",)), T.days_millis(date, 0, 0))

    def test_ring_descriptor_inline_mode(self):
        fx = T.Fixture()
        fx.q(T.STATE + 0x38, T.NICHE)
        fx.q(T.STATE + 0x40, 0)
        self.assertEqual(T.ring_descriptor(fx, T.STATE)[:3], [0, 0, 0])

    def test_enum_handler_table_decodes(self):
        tables = T.decode_tables(T.load_image())
        self.assertEqual(T.handler_for_tag(0x7E, tables), 0x42320FD)
        self.assertEqual(T.handler_for_tag(0x105, tables), 0x4232130)
        self.assertEqual(T.handler_for_tag(0x1FF, tables), 0x423228A)
        self.assertEqual(T.handler_for_tag(0x160, tables), "sub160")


class NegativeControls(Base):
    def test_model_mutants_are_caught(self):
        for kind, flag in (("root", "dex_div"), ("root", "asset_stride"), ("body", "wrap"), ("body", "limit_cmp"),
                           ("small", "second_niche_free"), ("events", "event_size"), ("enum", "scale16")):
            self.assertGreaterEqual(T.first_mismatch(kind, 800, (flag,), rig=self.rig), 0, flag)

    def test_corrupted_bytes_are_caught(self):
        start, data = T.fn_bytes(self.image, T.ROOT_FN)
        where = start + T.find_all(data, T.p32(0x510))[0]
        patched = {where: self.image.blob[self.image.offset(where)] ^ 1}
        self.assertGreaterEqual(T.first_mismatch("root", 300, patches=patched, image=self.image), 0)
        start, data = T.fn_bytes(self.image, T.BODY_FN)
        where = start + T.find_all(data, b"\x66\xc7\x03" + T.p16(0xD2))[0] + 3
        patched = {where: self.image.blob[self.image.offset(where)] ^ 1}
        self.assertGreaterEqual(T.first_mismatch("body", 600, patches=patched, image=self.image), 0)

    def test_unmutated_models_have_no_mismatch(self):
        for kind in ("root", "body", "small", "events", "enum"):
            self.assertEqual(T.first_mismatch(kind, 150, rig=self.rig), -1, kind)

    def test_out_of_range_asset_id_panics(self):
        fx, _ = T.root_fixture(random.Random(3))
        arg = bytearray(fx.get(T.ARG, 0x58))
        arg[0x38:0x40] = T.p64(10000 * 40)
        fx.put(T.ARG, bytes(arg))
        status, trace, info = T.model_root(fx)
        self.assertEqual(status, "panic:panic_msg")
        self.assertEqual(T.u64(arg, 0x38) // 10000, 40)


class Evidence(Base):
    def test_regeneration_matches_the_committed_files(self):
        measure = json.loads((WORK / "measure.json").read_text())
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "work"
            self.assertEqual(T.generate(out)["cases"], measure["cases"])
            for path in sorted(out.iterdir()):
                self.assertEqual(path.read_bytes(), (WORK / path.name).read_bytes(), path.name)
        self.assertEqual(measure["negative_detected"] + measure["equivalent"], measure["negative_controls"])
        self.assertGreaterEqual(measure["negative_controls"], 30)
        self.assertGreaterEqual(measure["cases"], 10000)


if __name__ == "__main__":
    unittest.main()
