"""Checks for the aligned quote token fee path of node #94."""

import hashlib
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import fees_aligned_quote as tool  # noqa: E402

PACKET = ROOT / "research" / "work-items" / "fees-aligned-quote-94"


class Base(unittest.TestCase):
    image = tool.load_image()
    harness = tool.Harness(image)
    cases = tool.all_cases()

    def pick(self, kind, label):
        return next(case for case in self.cases if case["kind"] == kind and case["label"] == label)

    def mutated(self, va, at, xor, case):
        machine = self.harness.machine
        base = self.image.offset(va)
        machine.patches = {va + at: self.image.blob[base + at] ^ xor}
        machine.cache.pop(va, None)
        try:
            return tool.compare_run(self.harness, case)
        finally:
            machine.patches = {}
            machine.cache.pop(va, None)


class Inputs(Base):
    def test_digest_is_checked(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_address_outside_the_file_fails(self):
        with self.assertRaises(tool.EvidenceError):
            self.image.offset(0x7FFFFFFFFFFF)

    def test_nobits_is_not_mapped(self):
        self.assertTrue(all(section["type"] != 8 for section in self.image.mapped))

    def test_function_bounds(self):
        for layout in tool.WRITERS:
            start, end = self.image.exact_fde(layout["entry"])
            self.assertEqual(end - start, tool.WRITER_SIZE)
        with self.assertRaises(tool.EvidenceError):
            self.image.exact_fde(tool.WRAPPER + 1)

    def test_decoder_stops_on_the_end(self):
        with self.assertRaises(tool.EvidenceError):
            tool.decode_range(self.image, tool.WRAPPER, tool.WRAPPER + 2)

    def test_pins_refuse_other_bytes(self):
        saved = tool.PINS
        tool.PINS = (("0x274dea5", "00000000", "bad"),)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.pin_rows(self.image)
        finally:
            tool.PINS = saved

    def test_status_texts(self):
        self.assertEqual(tool.status_text(self.image, tool.BAD_QUOTE), "Invalid quote token")
        self.assertEqual(tool.status_text(self.image, tool.DUPLICATE), "Duplicate aligned quote token deployer")
        with self.assertRaises(tool.EvidenceError):
            tool.status_text(self.image, tool.OK)

    def test_argument_form_refuses_an_unknown_site(self):
        with self.assertRaises(tool.EvidenceError):
            tool.argument_form(self.image, tool.WRAPPER)

    def test_callers(self):
        sites = tool.direct_callers(self.image, [layout["entry"] for layout in tool.WRITERS])
        self.assertEqual(len(sites), 9)
        forms = [tool.argument_form(self.image, site) for site, _ in sites]
        self.assertEqual(sorted(force for _, force in forms), [0] * 6 + [1] * 3)
        self.assertTrue(all(enable == "action +0x10" for enable, force in forms if force))


class Specification(Base):
    def spec(self, **fields):
        case = dict(token=1, enable=1, force=0, tokens=tool.TOKENS, status={1: 0}, aligned={}, dex=[(1, b"\x07"), (9, b"\x08")], gate=tool.OK)
        case.update(fields)
        return tool.writer_spec(case)

    def test_insert(self):
        want = self.spec()
        self.assertEqual(want["tag"], tool.OK)
        self.assertEqual(want["aligned"], {1: 1})
        self.assertEqual(want["dex"], [(1, b"\x01"), (9, b"\x08")])

    def test_inactive_peer_blocks(self):
        self.assertEqual(self.spec(aligned={2: 0})["tag"], tool.DUPLICATE)

    def test_other_owner_passes(self):
        self.assertEqual(self.spec(aligned={3: 1})["tag"], tool.OK)

    def test_reenable_needs_force(self):
        self.assertEqual(self.spec(aligned={1: 0})["tag"], tool.TEXT_STATUS)
        self.assertEqual(self.spec(aligned={1: 0}, force=1)["aligned"], {1: 1})

    def test_force_does_not_lift_the_status_test_on_enable(self):
        self.assertEqual(self.spec(status={1: 1}, force=1)["tag"], tool.BAD_QUOTE)

    def test_disable_rules(self):
        self.assertEqual(self.spec(enable=0, aligned={1: 1})["tag"], tool.TEXT_STATUS)
        self.assertEqual(self.spec(enable=0, aligned={1: 1}, force=1)["aligned"], {1: 0})
        self.assertEqual(self.spec(enable=0, status={}, aligned={})["tag"], tool.OK)

    def test_class(self):
        case = dict(quotes={20: 0}, outcome=True)
        self.assertEqual(tool.class_of(case, 20), 1)
        self.assertEqual(tool.class_of(case, 21), 2)
        self.assertEqual(tool.class_of(dict(case, outcome=False), 21), 0)

    def test_scales(self):
        fee = dict(first=(1e-3, -1e-4), second=(0.0, 0.0), two=0, discount=0.0)
        scales = (0.5, 2.0)
        self.assertEqual(tool.fee_spec(fee, 0, 1.0, True, 1, 0, 10 ** 6, scales)["gross"], 500)
        self.assertEqual(tool.fee_spec(fee, 0, 1.0, True, 0, 0, 10 ** 6, scales)["gross"], 1000)
        self.assertEqual(tool.fee_spec(fee, 0, 1.0, False, 1, 0, 10 ** 6, scales)["rebate"], 200)
        self.assertEqual(tool.fee_spec(fee, 0, 1.0, False, 0, 0, 10 ** 6, scales)["rebate"], 100)

    def test_class_two_drops_a_rebate(self):
        fee = dict(first=(1e-3, -1e-4), second=(0.0, 0.0), two=0, discount=0.0)
        self.assertEqual(tool.fee_spec(fee, 2, 0.25, False, 0, 0, 10 ** 6, (1.0, 1.0))["rebate"], 0)


class Bytes(Base):
    def test_all_kinds_match(self):
        for kind in tool.COMPARE:
            sample = [case for case in self.cases if case["kind"] == kind][::17]
            self.assertTrue(sample)
            for case in sample:
                self.assertEqual(tool.compare_run(self.harness, case), "", case["label"])

    def test_every_copy_writes_its_own_list(self):
        for layout in tool.WRITERS:
            case = self.pick("writer", "%s/none/active/e1/f0/d9" % layout["name"])
            self.assertEqual(tool.compare_run(self.harness, case), "")

    def test_wrong_dex_offset_fails(self):
        case = self.pick("writer", "first/none/active/e1/f0/d1")
        self.assertTrue(self.mutated(0x274DEA5, 3, 8, case))

    def test_flipped_status_branch_fails(self):
        case = self.pick("writer", "first/none/disabled/e1/f0/d6")
        self.assertTrue(self.mutated(0x274DC7E, 1, 1, case))

    def test_wrapper_class_flip_fails(self):
        case = self.pick("wrapper", "plain/3/0/1/0/0")
        self.assertTrue(self.mutated(0x372F0F0, 1, 2, case))

    def test_wrong_spec_is_seen(self):
        case = dict(self.pick("wrapper", "plain/2/0/1/0/0"), scales=(0.8, 1.5))
        good = tool.compare_run(self.harness, case)
        self.assertEqual(good, "")
        saved = tool.class_rate
        tool.class_rate = lambda *args: saved(*args) * 2
        try:
            self.assertTrue(tool.compare_run(self.harness, case))
        finally:
            tool.class_rate = saved

    def test_collector_sees_one_byte_of_the_owner(self):
        case = self.pick("collect", "one byte apart")
        self.assertEqual(tool.compare_run(self.harness, case), "")


class Packet(Base):
    def test_files_match_a_fresh_run(self):
        evidence = json.loads((PACKET / "evidence.json").read_text(encoding="utf-8"))
        fresh, _ = tool.analyse(self.image, full=False)
        self.assertEqual(fresh["mismatches"], 0)
        for key in ("functions", "writer_callers", "scale_readers", "keys", "status", "texts", "cases"):
            self.assertEqual(evidence[key], fresh[key], key)
        with tempfile.TemporaryDirectory() as folder:
            out = pathlib.Path(folder)
            tool.write_tsv(out / "pins.tsv", ("address", "bytes", "meaning"), tool.pin_rows(self.image))
            tool.write_tsv(out / "path-map.tsv", ("order", "stage", "address", "behaviour"), tool.path_rows())
            tool.write_tsv(out / "class-samples.tsv", ("case", "cross", "class", "aligned_byte", "gross", "rebate"), tool.class_samples(self.image))
            for name in ("pins.tsv", "path-map.tsv", "class-samples.tsv"):
                self.assertEqual((out / name).read_bytes(), (PACKET / name).read_bytes(), name)

    def test_survivors_have_reasons(self):
        rows = (PACKET / "mutations.tsv").read_text(encoding="utf-8").splitlines()[1:]
        evidence = json.loads((PACKET / "evidence.json").read_text(encoding="utf-8"))
        self.assertEqual(len(rows), sum(evidence["mutations"].values()))
        for row in rows:
            parts = row.split("\t")
            if parts[3] != "killed":
                self.assertTrue(parts[5] and parts[5] != "not classified", row)

    def test_manifest(self):
        for line in (PACKET / "MANIFEST.sha256").read_text(encoding="utf-8").splitlines():
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest, name)


if __name__ == "__main__":
    unittest.main()
