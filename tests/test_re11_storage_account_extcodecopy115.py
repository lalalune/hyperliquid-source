import hashlib
import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re11_storage_account_extcodecopy115 as t  # noqa: E402

PACKET = ROOT / "research" / "work-items" / "RE-011-storage-account-extcodecopy-115"


def sl_detected(image, cases, mut=frozenset(), override=None):
    _, bad, _ = t.sl_evaluate(image, override=override, mut=mut, stop_on_first=True, cases=cases)
    return bad > 0


def ar_detected(image, cases, mut=frozenset(), override=None):
    rows, _ = t.ar_evaluate(image, override=override, mut=mut, stop_on_first=True, cases=cases)
    return not rows[-1][3]


def tw_detected(image, cases, mut=frozenset(), override=None):
    _, bad, _ = t.tw_evaluate(image, override=override, mut=mut, stop_on_first=True, cases=cases)
    return bad > 0


class SharedImage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = t.load_image()

    def test_binary_digest(self):
        self.assertEqual(hashlib.sha256(t.BINARY.read_bytes()).hexdigest(), t.SHA256)

    def test_wrong_digest_rejected(self):
        data = bytearray(self.image.data)
        data[self.image.text["offset"] + 1] ^= 0x40
        with self.assertRaises(t.ToolError):
            t.Image(bytes(data))

    def test_code_outside_text_rejected(self):
        end = self.image.text["address"] + self.image.text["size"]
        with self.assertRaises(t.ToolError):
            self.image.code(end + 0x10, 4)
        with self.assertRaises(t.ToolError):
            self.image.code(end - 2, 4)

    def test_shared_seed_slot(self):
        # the SLOAD account map and the transient map hash with the same process seed slot
        self.assertEqual(t.SL_SEED_GOT, t.TW_SEED_GOT)
        sl_consts, _ = t.sl_static_evidence(self.image)
        tw_consts, _ = t.tw_static_evidence(self.image)
        self.assertEqual(sl_consts["hash_seed"]["target"], "0x64ffe90")
        self.assertFalse(sl_consts["hash_seed"]["target_section_has_file_bytes"])
        self.assertIn("0x64dfa78", json.dumps(tw_consts))

    def test_shared_address_hash_matches(self):
        # both families reconstruct the same folded 20-byte address hash
        for i in range(64):
            addr = bytes((i * 7 + k * 13) & 0xff for k in range(20))
            secret, seed = (i * 0x9e3779b97f4a7c15) & t.M64, (i * 0x632be59bd9b4e019 + 1) & t.M64
            self.assertEqual(t.sl_addr_hash(addr, secret, seed), t.tw_addr_hash(addr, secret, seed))


class Sload(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = t.load_image()
        cls.cases = t.sl_all_cases()

    def test_static_constants(self):
        consts, decoded = t.sl_static_evidence(self.image)
        calls = consts["load_calls"]
        self.assertEqual({v["target"] for v in calls["0x2993ff0"].values()}, {"0x4e33680"})
        self.assertEqual({v["target"] for v in calls["0x2993bd0"].values()}, {"0x433bcf0"})
        self.assertEqual(len(calls["0x2993ff0"]), 2)
        self.assertEqual(consts["functions"]["0x2993ff0"]["instructions"], 236)
        self.assertEqual(consts["functions"]["0x2993bd0"]["instructions"], 236)
        self.assertEqual(sorted(decoded), sorted(t.SL_FUNCS))

    def test_hash_example(self):
        addr = bytes(range(1, 21))
        a0 = int.from_bytes(addr[0:8], "little")
        a1 = int.from_bytes(addr[8:16], "little") ^ 1
        p = a0 * a1
        z = (p & t.M64) ^ int.from_bytes(addr[16:20], "little") ^ (p >> 64)
        self.assertEqual(t.sl_addr_hash(addr, 0, 1), z)

    def test_rejects_changed_check_byte(self):
        data = bytearray(self.image.data)
        sec = self.image.text
        data[0x2994370 - sec["address"] + sec["offset"]] = 0x37
        with self.assertRaises(t.ToolError):
            t.sl_static_evidence(t.Image(bytes(data), check=False))

    def test_outcome_families_present(self):
        rows, bad, _ = t.sl_evaluate(self.image, cases=self.cases[:800])
        self.assertEqual(bad, 0)
        seen = {"/".join(t.sl_outcome(c, got).split("/")[:3]) for _, c, _, got, _ in rows}
        for want in ("ok/berlin/cold", "ok/berlin/warm", "ok/pre-berlin/cold", "out-of-gas/berlin/cold",
                     "out-of-gas/berlin/absent", "out-of-gas/berlin/load-error", "miss-or-error/pre-berlin/absent",
                     "miss-or-error/pre-berlin/empty-map", "miss-or-error/pre-berlin/load-error", "underflow"):
            self.assertIn(want, seen)

    def test_model_mutants_detected(self):
        for name in t.SL_MODEL_MUTANTS:
            with self.subTest(name=name):
                self.assertTrue(sl_detected(self.image, self.cases, mut=frozenset([name])))

    def test_code_mutants_detected(self):
        for va, byte, _ in t.SL_BYTE_MUTANTS:
            with self.subTest(va=hex(va)):
                self.assertNotEqual(self.image.code(va, 1)[0], byte)
                self.assertTrue(sl_detected(self.image, self.cases, override={va: byte}))


class AccountRead(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = t.load_image()
        cls.cases = t.ar_all_cases()
        per = {}
        cls.subset = []
        for c in cls.cases:
            key = (c["op"], c["copy"])
            per[key] = per.get(key, 0) + 1
            if per[key] <= 120:
                cls.subset.append(c)

    def test_static_pins_and_tables(self):
        fdes, insns = t.ar_static_evidence(self.image)
        for key, va in t.AR_BODIES.items():
            self.assertIn(va, fdes)
            self.assertEqual(insns[key][0][0], va)
        self.assertEqual(t.ar_loader_tags(insns), {0: [0, 2], 1: [0, 2]})
        self.assertEqual(self.image.read(t.AR_EMPTY_LO, 16) + self.image.read(t.AR_EMPTY_HI, 16), t.AR_EMPTY_HASH)

    def test_keccak_reference(self):
        self.assertEqual(t.ar_keccak256(b"").hex(),
                         "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        self.assertEqual(t.ar_keccak256(b"abc").hex(),
                         "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")

    def test_subset_matches(self):
        rows, _ = t.ar_evaluate(self.image, cases=self.subset)
        self.assertEqual([r[0]["id"] for r in rows if not r[3]], [])
        kinds = {t.ar_outcome(r[0], r[1]).split("+")[0] for r in rows}
        for k in ("ok", "out-of-gas", "underflow", "not-activated", "overflow", "fatal", "error",
                  "panic:extcodesize-code-none", "ok cold=1 empty=1", "ok cold=0 empty=0"):
            self.assertIn(k, kinds)

    def test_model_mutants_detected(self):
        for mt in t.AR_MODEL_MUTANTS:
            with self.subTest(mt=mt):
                self.assertTrue(ar_detected(self.image, self.cases, mut=frozenset([mt])))

    def test_byte_mutants_detected(self):
        for va, value, label in t.AR_BYTE_MUTANTS:
            with self.subTest(label=label):
                self.assertTrue(ar_detected(self.image, self.cases, override={va: value}))

    def test_stub_contract_violation_fails(self):
        c = dict(next(x for x in self.cases if x["op"] == t.AR_BALANCE and x["len"] > 0))
        m = t.AR_CaseMachine(self.image)
        t.ar_install(m, self.image)
        m.case = c
        m.regs[6], m.regs[2], m.regs[8] = t.AR_HOST_AT + t.AR_H_JOURNAL + 8, t.AR_HOST_AT + t.AR_H_DB, 0
        with self.assertRaises(t.ToolError):
            t.ar_state_stub(t.AR_STATE_GOT[0])(m)

    def test_corrupted_pin_fails(self):
        data = bytearray(self.image.data)
        data[0x29906a6 - self.image.text["address"] + self.image.text["offset"]] ^= 1
        with self.assertRaises(t.ToolError):
            t.ar_static_evidence(t.Image(bytes(data), check=False))

    def test_corrupted_empty_hash_fails(self):
        data = bytearray(self.image.data)
        _, off = self.image.section_of(t.AR_EMPTY_HI + 3)
        data[off] ^= 0x40
        with self.assertRaises(t.ToolError):
            t.ar_static_evidence(t.Image(bytes(data), check=False))


class TransientWriter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = t.load_image()
        cls.cases = t.tw_all_cases()

    def test_static_evidence(self):
        consts, _ = t.tw_static_evidence(self.image)
        self.assertEqual(consts["tstore_call"]["target"], "0x2972390")
        self.assertEqual(consts["journal_record"]["bytes"], 0x58)
        self.assertEqual(len(consts["checked_bytes"]), len(t.TW_CHECKED))
        self.assertEqual(consts["functions"]["0x2972390"]["instructions"], 511)

    def test_outcome_families_present(self):
        rows, bad, _ = t.tw_evaluate(self.image, cases=self.cases[:1500])
        self.assertEqual(bad, 0)
        classes = {t.tw_outcome(c, want, got) for _, c, want, got, _ in rows}
        for need in ("remove/no-change", "remove/erase-empty+journal", "write/overwrite+no-journal",
                     "write/overwrite+grow+journal", "boundary-tls"):
            self.assertIn(need, classes)

    def test_model_mutants_detected(self):
        for name in t.TW_MODEL_MUTANTS:
            with self.subTest(name=name):
                self.assertTrue(tw_detected(self.image, self.cases, mut=frozenset([name])))

    def test_code_mutants_detected(self):
        for va, byte, _ in t.TW_BYTE_MUTANTS:
            with self.subTest(va=hex(va)):
                self.assertNotEqual(self.image.code(va, 1)[0], byte)
                self.assertTrue(tw_detected(self.image, self.cases, override={va: byte}))


class ExtCodeCopy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = t.load_image()
        cls.cases = t.ec_all_cases()
        per = {}
        cls.subset = []
        for c in cls.cases:
            per[c["copy"]] = per.get(c["copy"], 0) + 1
            if per[c["copy"]] <= 600:
                cls.subset.append(c)

    def test_static_pins_and_tables(self):
        fdes, insns, refs = t.ec_static_evidence(self.image)
        for copy, va in t.EC_BODIES.items():
            self.assertIn(va, fdes)
            self.assertEqual(insns[copy][0][0], va)
            self.assertIn(("direct", t.EC_LOADERS[copy]), refs[copy])
            self.assertNotIn(("direct", t.EC_LOADERS[1 - copy]), refs[copy])
        self.assertEqual(self.image.import_name(t.EC_MEMCPY_GOT), "memcpy")
        self.assertEqual(self.image.import_name(t.EC_MEMSET_GOT), "memset")

    def test_subset_matches(self):
        rows, _ = t.ec_evaluate(self.image, cases=self.subset)
        self.assertEqual([r[0]["id"] for r in rows if not r[3]], [])
        kinds = {t.ec_outcome(r[0], r[1]).split(" ")[0] for r in rows}
        for k in ("ok+copy+zero", "ok+zero", "ok+copy+zero+grow", "out-of-gas", "underflow", "invalid-operand",
                  "fatal", "panic:no-bytecode", "panic:length-range", "panic:zero-fill-bound"):
            self.assertIn(k, kinds)

    def test_model_reference_semantics(self):
        # Hand-built case: code 0..9, copy 6 bytes from code offset 7 into memory offset 3 -> 3 code bytes then zeros.
        c = dict(self.cases[0])
        c.update(len=4, stack={3: 0xabc, 2: 3, 1: 7, 0: 6}, cpw=3, gas=100, words=8, ctx=0, mlen=0x1000,
                 tag=0, bc=True, olen=10, plen=10, code=bytes(range(10)) + bytes(t.EC_CODE_SIZE - 10),
                 mem=b"\xff" * t.EC_MEM_SIZE, count=1, flag=0, grow_ret=0)
        want = t.ec_model(c)
        self.assertEqual(want["ret"], t.EC_R_OK)
        self.assertEqual(want["gas"], 97)
        self.assertEqual(bytes(want["mem"][:12]), b"\xff\xff\xff\x07\x08\x09\x00\x00\x00\xff\xff\xff")
        got = t.ec_run_case(t.EC_CaseMachine(self.image), c)
        self.assertTrue(t.ec_compare(c, want, got))

    def test_model_mutants_detected(self):
        for mt in t.EC_MODEL_MUTANTS:
            with self.subTest(mt=mt):
                rows, _ = t.ec_evaluate(self.image, mut=frozenset([mt]), stop_on_first=True, cases=self.cases)
                self.assertFalse(rows[-1][3], mt)

    def test_byte_mutants_detected(self):
        for va, value, label in t.EC_BYTE_MUTANTS:
            with self.subTest(label=label):
                try:
                    rows, _ = t.ec_evaluate(self.image, override={va: value}, stop_on_first=True, cases=self.cases)
                    self.assertFalse(rows[-1][3], label)
                except t.ToolError:
                    pass

    def test_stub_contract_violation_fails(self):
        m = t.EC_CaseMachine(self.image)
        t.ec_install(m, self.image)
        m.case = self.cases[0]
        m.regs[7], m.regs[6], m.regs[2], m.regs[8] = t.STACK_TOP - 0x200, t.EC_INTERP_AT + t.EC_I_WORDS, \
            t.EC_HOST_AT, 0
        with self.assertRaises(t.ToolError):
            t.ec_loader_stub(m)

    def test_corrupted_pin_fails(self):
        data = bytearray(self.image.data)
        off = 0x2990329 + 2 - self.image.text["address"] + self.image.text["offset"]  # copy 1 load_code byte
        data[off] ^= 1
        bad = t.Image(bytes(data), check=False)
        with self.assertRaises(t.ToolError):
            t.ec_static_evidence(bad)

    def test_corrupted_table_slot_fails(self):
        data = bytearray(self.image.data)
        rela = next(s for s in self.image.secs if s["name"] == ".rela.dyn")
        target = t.EC_OP_TABLES[1] + 8 * t.EC_EXTCODECOPY
        for pos in range(rela["offset"], rela["offset"] + rela["size"], 24):
            if int.from_bytes(data[pos:pos + 8], "little") == target:
                data[pos + 16] ^= 0x10
                break
        else:
            self.fail("no relocation for the table slot")
        bad = t.Image(bytes(data), check=False)
        with self.assertRaises(t.ToolError):
            t.ec_static_evidence(bad)

    def test_shared_tables_and_loaders(self):
        # EXTCODECOPY sits in the same two opcode tables and calls the same account loaders as the account reads
        self.assertEqual(t.EC_OP_TABLES, t.AR_OP_TABLES)
        self.assertEqual(t.EC_LOADERS, t.AR_LOADERS)
        self.assertEqual(t.EC_ARC_DROP_GOT, t.AR_ARC_DROP_GOT)
        for i in range(64):
            word = (i * 0x9e3779b97f4a7c15_632be59bd9b4e019_0123456789abcdef) % (1 << 256)
            self.assertEqual(t.ec_address_bytes(word, frozenset()), t.ar_address_bytes(word, frozenset()))

    def test_regenerates_family_outputs(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            t.ec_generate(tmp)
            tmp = pathlib.Path(tmp)
            for name in ("ec-constants.json", "ec-decoded-instructions.tsv", "ec-functions.tsv",
                         "ec-negative-controls.tsv", "ec-outcome-classes.tsv"):
                with self.subTest(name=name):
                    self.assertEqual((tmp / name).read_bytes(), (PACKET / name).read_bytes())
            full = (tmp / "ec-cases.tsv").read_bytes()
            summary = json.loads((PACKET / "summary.json").read_text())
            self.assertEqual(hashlib.sha256(full).hexdigest(), summary["families"]["ec"]["full_cases_tsv_sha256"])
            lines = full.decode().splitlines()
            sampled = lines[:1] + lines[1::t.SAMPLE_EVERY]
            self.assertEqual((PACKET / "ec-cases.tsv").read_text().splitlines(), sampled)


class Packet(unittest.TestCase):
    def test_manifest(self):
        names = set()
        for line in (PACKET / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ", 1)
            names.add(name)
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest, name)
        self.assertEqual(names, {p.name for p in PACKET.iterdir() if p.name != "MANIFEST.sha256"})

    def test_summary_and_sampled_rows(self):
        summary = json.loads((PACKET / "summary.json").read_text())
        self.assertEqual(summary["binary_sha256"], t.SHA256)
        self.assertEqual(summary["mismatches"], 0)
        self.assertEqual(summary["negative_controls"], summary["negative_controls_detected"])
        totals = {"sl": len(t.sl_all_cases()), "ar": len(t.ar_all_cases()), "tw": len(t.tw_all_cases()),
                  "ec": len(t.ec_all_cases())}
        self.assertEqual(summary["cases"], sum(totals.values()))
        for key, n in totals.items():
            fam = summary["families"][key]
            self.assertEqual(fam["cases"], n)
            rows = (PACKET / f"{key}-cases.tsv").read_text().splitlines()[1:]
            self.assertEqual(len(rows), (n + t.SAMPLE_EVERY - 1) // t.SAMPLE_EVERY)
            self.assertEqual(fam["sampled_rows_committed"], len(rows))
            self.assertTrue(all(r.rsplit("\t", 1)[-1] == "yes" for r in rows))

    def test_control_counter_rejects_a_miss(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            p = pathlib.Path(tmp) / "c.tsv"
            p.write_text("kind\tcontrol\tdetected\nmodel\ta\t1\nmodel\tb\t0\n")
            self.assertEqual(t.control_counts(p), (2, 1))


if __name__ == "__main__":
    unittest.main()
