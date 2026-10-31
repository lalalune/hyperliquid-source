"""RE-019: rmp/json loader packet, exact pins, seed determinism, negative controls and tamper tests."""
import hashlib
import importlib.util
import os
from pathlib import Path
import struct
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-019-rmp-json-loader-94"
sys.path.insert(0, str(ROOT / "tools"))
import rmp_json_loader as tool  # noqa: E402

OUTPUT_SHA256 = "58cf74dd36110d624b1df3422838f9f242c3ed14623a9b3bd44eb1e334ded75f"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


iv = load("re019_independent_verify", PACKET / "independent_verify.py")
DATA = bytearray(tool.TARGET.read_bytes()) if tool.TARGET.exists() else None
SEGS = tool.segments(bytes(DATA[:0x1000])) if DATA is not None else None


def off(va):
    for base, o, size in SEGS:
        if base <= va < base + size:
            return o + va - base
    raise KeyError(hex(va))


class Patched:
    def __init__(self, file_off, new):
        self.o, self.new = file_off, bytes(new)

    def __enter__(self):
        self.old = bytes(DATA[self.o:self.o + len(self.new)])
        DATA[self.o:self.o + len(self.new)] = self.new
        return DATA

    def __exit__(self, *exc):
        DATA[self.o:self.o + len(self.old)] = self.old


def flip(va, at=0):
    o = off(va) + at
    return Patched(o, [DATA[o] ^ 0x01])


def tool_rejects(data):
    try:
        return bool(tool.expectation_errors(tool.analyse(bytes(data), check_sha=False)))
    except (ValueError, KeyError, IndexError, struct.error):
        return True


@unittest.skipIf(DATA is None, "node #94 binary not present")
class RmpJsonLoaderTests(unittest.TestCase):
    def test_output_pin_and_expectations(self):
        r = tool.analyse(bytes(DATA))
        self.assertEqual(tool.expectation_errors(r), [])
        text = tool.render(r)
        self.assertEqual(hashlib.sha256(text.encode()).hexdigest(), OUTPUT_SHA256)
        self.assertEqual((PACKET / "rmp-json-loader.json").read_text(), text)

    def test_exact_counts(self):
        r = tool.analyse(bytes(DATA))
        self.assertEqual(len(r["callers"]), 3)
        self.assertEqual(len(tool.KEY_INSNS), 41)
        self.assertEqual(len(tool.CALLER_KEYS), 6)
        self.assertEqual(len(r["key_bytes"]), 47)
        self.assertEqual(len(r["labels"]), 5)
        self.assertEqual(len(r["locations"]), 2)
        self.assertEqual(r["extent_len"], 1744)
        self.assertEqual(r["ok_payload_len"], 0x1fc8)
        self.assertEqual(r["err_tag"], 2)
        self.assertEqual(r["path_abi"]["rsi"], "path pointer")
        self.assertEqual(r["tilde_expander"]["va"], "0x144a600")
        self.assertEqual(r["tilde_expander"]["cmpw_imm"], "0x2f7e")

    def test_seeds_and_optimize_byte_identical(self):
        outs = set()
        for seed, flags in (("0", []), ("7", []), ("99", []), ("0", ["-O"])):
            env = dict(os.environ, PYTHONHASHSEED=seed)
            outs.add(subprocess.run(
                [sys.executable, "-B", *flags, str(ROOT / "tools" / "rmp_json_loader.py")],
                env=env, check=True, capture_output=True).stdout)
        self.assertEqual(len(outs), 1)
        self.assertEqual(hashlib.sha256(outs.pop()).hexdigest(), OUTPUT_SHA256)

    def test_independent_verifier_passes(self):
        self.assertEqual(iv.check_keys(bytes(DATA)), [])
        self.assertEqual(iv.check_packet(), [])

    def test_independent_imports_nothing_from_tools(self):
        src = (PACKET / "independent_verify.py").read_text()
        self.assertNotIn("sys.path", src)
        for line in src.splitlines():
            if line.startswith(("import ", "from ")):
                self.assertIn(line.split()[1].split(".")[0],
                              {"hashlib", "pathlib", "struct", "bisect"}, line)

    def test_every_key_byte_flip_caught_by_independent(self):
        for va, hx in iv.KEYS:
            for i in range(len(hx) // 2):
                with self.subTest(va=hex(va), byte=i), flip(va, i) as d:
                    self.assertTrue(iv.check_keys(
                        bytes(d), check_sha=False, callers=False,
                        labels=False, locations=False, extent=False))

    def test_every_key_va_flip_rejected_by_tool(self):
        for va, _hx, role in tool.KEY_INSNS + tool.CALLER_KEYS:
            with self.subTest(va=hex(va), role=role), flip(va) as d:
                self.assertTrue(tool_rejects(d))

    def test_label_byte_flip_caught(self):
        with flip(0x1fd0ce) as d:
            self.assertTrue(tool_rejects(d))
            self.assertTrue(iv.check_keys(bytes(d), check_sha=False, callers=False,
                                          locations=False, extent=False))

    def test_caller_tampers(self):
        with flip(0x3273862 + 1) as d:
            self.assertTrue(tool_rejects(d))
            self.assertTrue(iv.check_callers(bytes(d)))
        # plant an extra e8 to FN in a nearby dead-ish zone
        site = 0x3273870
        disp = tool.FN - (site + 5)
        with Patched(off(site), b"\xe8" + struct.pack("<i", disp)) as d:
            self.assertTrue(tool_rejects(d))
            self.assertTrue(iv.check_callers(bytes(d)))
        self.assertEqual(iv.check_callers(bytes(DATA)), [])

    def test_negative_control_re016_slot(self):
        # 0x5773aa8 / 0x3751e80 are RE-016; this packet does not claim them
        r = tool.analyse(bytes(DATA))
        blob = tool.render(r)
        self.assertNotIn("0x5773aa8", blob)
        self.assertNotIn("0x3751e80", blob)
        self.assertEqual(r["function"], "0x3c155a0")

    def test_negative_control_re017_body(self):
        # 0x3273810 body / 0x3273920 materializer call are RE-017; we only cite the
        # caller site 0x3273862 and its FDE start
        r = tool.analyse(bytes(DATA))
        self.assertIn("0x3273862", r["callers"])
        self.assertEqual(r["caller_fdes"]["0x3273862"], "0x3273810")
        self.assertNotIn("0x3273920", r["key_bytes"])
        self.assertNotIn("0x3273920", tool.render(r))

    def test_sha_mismatch_rejected(self):
        with flip(0x3c155a0):
            with self.assertRaises(ValueError):
                tool.analyse(bytes(DATA))
            self.assertEqual(iv.check_keys(bytes(DATA)), ["binary sha256 mismatch"])

    def test_manifest_matches_files(self):
        for line in (PACKET / "MANIFEST.sha256").read_text().splitlines():
            h, name = line.split("  ", 1)
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), h, name)

    def test_readme_hashes_match_manifest(self):
        readme = (PACKET / "README.md").read_text()
        for line in (PACKET / "MANIFEST.sha256").read_text().splitlines():
            h, name = line.split("  ", 1)
            if name != "README.md":
                self.assertIn(h, readme, name)


if __name__ == "__main__":
    unittest.main()
