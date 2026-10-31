import copy
import hashlib
import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import spot_sell_price_band as t  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-006-spot-sell-price-band-94"


def shared(cls):
    cls.image = t.load_image()
    cls.harness = t.Harness(cls.image)


class Base(unittest.TestCase):
    setUpClass = classmethod(shared)

    def band(self, **change):
        case = t.Case("test", "band", "", t.band_world(**change))
        self.assertEqual(t.compare_run(self.harness, case), "")
        out = self.harness.run(case)["out"]
        return {"tag": t.word(out, 0), "x": t.word(out, 8), "low": t.word(out, 0x10), "high": t.word(out, 0x18), "last": t.word(out, 0x20), "code": out[8]}

    def rows(self, **change):
        data = t.band_world()["rows"]
        data[t.BASE_TOKEN] = t.base_row(**change)
        return data

    def mutant(self, va, offset, value, case):
        machine = self.harness.machine
        machine.patches = {va + offset: value}
        machine.cache.pop(va, None)
        try:
            return t.compare_run(self.harness, case)
        finally:
            machine.patches = {}
            machine.cache.pop(va, None)


class Identity(Base):
    def test_wrong_digest_is_refused(self):
        with self.assertRaisesRegex(t.EvidenceError, "SHA-256 mismatch"):
            t.load_image(expected="0" * 64)

    def test_function_end_comes_from_the_fde(self):
        self.assertEqual(self.image.exact_fde(t.BAND), (0x37344A0, 0x3734BC3))

    def test_a_middle_address_is_not_a_function_start(self):
        with self.assertRaisesRegex(t.EvidenceError, "not an FDE start"):
            self.image.exact_fde(t.BAND + 1)

    def test_bss_has_no_file_bytes(self):
        bss = self.image.named[".bss"]
        with self.assertRaisesRegex(t.EvidenceError, "outside file-backed"):
            self.image.offset(bss["address"] + 8)

    def test_constants_and_bytes(self):
        self.assertEqual(len(t.read_constants(self.image)), len(t.CONSTANTS))
        self.assertEqual(len(t.read_host_bytes(self.image)), len(t.HOST_BYTES))

    def test_changed_constant_is_refused(self):
        other = copy.copy(self.image)
        blob = bytearray(self.image.blob)
        blob[self.image.offset(0x20AA58)] ^= 1
        other.blob = bytes(blob)
        with self.assertRaisesRegex(t.EvidenceError, "constant"):
            t.read_constants(other)

    def test_changed_byte_is_refused(self):
        other = copy.copy(self.image)
        blob = bytearray(self.image.blob)
        blob[self.image.offset(0x3734A2C) + 1] ^= 1
        other.blob = bytes(blob)
        with self.assertRaisesRegex(t.EvidenceError, "host bytes"):
            t.read_host_bytes(other)


class Prices(Base):
    def test_worked_example(self):
        found = self.band()
        self.assertEqual((found["tag"], found["low"], found["high"]), (1, 1400000010, 1960000100))

    def test_high_moves_up_from_an_exact_multiple(self):
        self.assertEqual(self.band(price=1000, ticks=(10, 10))["high"], 990)
        self.assertEqual(self.band(price=1000, ticks=(980, 10))["high"], 1960)

    def test_low_never_passes_high(self):
        found = self.band(rows=self.rows(b8=2 * t.UNIT))
        self.assertEqual(found["low"], found["high"])

    def test_curve(self):
        self.assertEqual(t.rate(10 ** 13), 25 * 10 ** 12)
        self.assertEqual(t.rate(t.KINK - 1), 74999999999999)
        self.assertEqual(t.rate(t.KINK), 83333333333333)
        self.assertEqual(t.rate(t.UNIT), t.UNIT)

    def test_kink_is_a_step(self):
        below = self.band(rows=self.rows(b8=t.KINK - 1), ticks=(1, 1))
        above = self.band(rows=self.rows(b8=t.KINK), ticks=(1, 1))
        self.assertGreater(above["low"], below["low"])

    def test_small_price_gives_word_one(self):
        self.assertEqual(self.band(rows=self.rows(b8=0), price=1, ticks=(1, 1))["low"], 2)

    def test_saturation(self):
        found = self.band(price=t.U64, ticks=(2 ** 63, 2 ** 63))
        self.assertEqual((found["low"], found["high"]), (t.U64, t.U64))


class Words(Base):
    def test_missing_rows_stop_with_nine(self):
        self.assertEqual((self.band(rows=None)["tag"], self.band(rows=None)["code"]), (3, 9))

    def test_inactive_base(self):
        self.assertEqual(self.band(rows=self.rows(active=0))["tag"], 2)

    def test_no_price(self):
        self.assertEqual(self.band(price=0)["tag"], 2)

    def test_missing_words(self):
        self.assertEqual(self.band(words=None)["tag"], 2)

    def test_debt_past_a_word_stops(self):
        data = t.band_world()["words"]
        data[t.QUOTE_TOKEN] = (t.U64, 2)
        rows = t.band_world()["rows"]
        rows[t.QUOTE_TOKEN] = t.quote_row(q58=t.UNIT + 1)
        found = self.band(words=data, rows=rows)
        self.assertEqual((found["tag"], found["code"]), (3, 3))

    def test_no_divisor_stops_with_six(self):
        found = self.band(rows=self.rows(b78=0))
        self.assertEqual((found["tag"], found["code"]), (3, 6))

    def test_first_scale_refusal(self):
        found = self.band(scale1=(0, 5))
        self.assertEqual((found["tag"], found["code"]), (3, 3))

    def test_second_scale_refusal_gives_tag_zero(self):
        found = self.band(scale2=(0, 77))
        self.assertEqual(found["tag"], 0)

    def test_last_is_capped_by_the_second_scale(self):
        self.assertEqual(self.band(scale2=(1, 3))["last"], 3)
        self.assertEqual(self.band(scale2=(1, 0))["last"], 0)

    def test_x_comes_from_the_rescale(self):
        self.assertEqual(self.band()["x"], 123456)

    def test_arguments_are_compared(self):
        wanted = t.spec_run(t.Case("c", "band", "", t.band_world()))
        found = self.harness.run(t.Case("c", "band", "", t.band_world(spot=8)))
        self.assertNotEqual(found["events"], wanted["events"])


class Controls(Base):
    def test_all_cases_match(self):
        for case in t.all_cases():
            self.assertEqual(t.compare_run(self.harness, case), "")

    def test_kink_constant(self):
        case = t.Case("c", "band", "", t.band_world(rows=self.rows(b8=t.KINK - 1), ticks=(1, 1), price=2 ** 53))
        self.assertTrue(self.mutant(0x373470B, 2, 0xFE, case))

    def test_mutation_targets_cover_the_function(self):
        rows = t.decode_range(self.image, *self.image.exact_fde(t.BAND))
        self.assertGreater(len(list(t.mutation_targets(self.image, rows))), 100)

    def test_call_sites(self):
        self.assertEqual(sorted(t.slot_sites(self.image, t.SLOT_QUOTE)), [0x26D23C4, 0x4C2158A, 0x4C21A7A])


class Packet(unittest.TestCase):
    def test_manifest(self):
        lines = (FOLDER / "MANIFEST.sha256").read_text().splitlines()
        names = sorted(path.name for path in FOLDER.iterdir() if path.name != "MANIFEST.sha256")
        self.assertEqual(sorted(line.split("  ")[1] for line in lines), names)
        for line in lines:
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_evidence_counts(self):
        doc = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(doc["mismatches"], 0)
        rows = (FOLDER / "mutations.tsv").read_text().splitlines()[1:]
        self.assertEqual(len(rows), sum(doc["mutations"].values()))
        for row in rows:
            fields = row.split("\t")
            if fields[3] != "killed":
                self.assertTrue(fields[5])


if __name__ == "__main__":
    unittest.main()
