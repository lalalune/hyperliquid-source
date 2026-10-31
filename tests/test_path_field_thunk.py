"""RE-020: path-field + thunk packet, exact pins, seed determinism, negative controls and tamper tests."""
import hashlib
import importlib.util
import os
from pathlib import Path
import struct
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-020-path-field-thunk-94"
sys.path.insert(0, str(ROOT / "tools"))
import path_field_thunk as tool  # noqa: E402

OUTPUT_SHA256 = "6d3a09f4d8ab2e6061c6bfe3491ccec5fa43ad4f15439999e743557ab1c3ce15"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


iv = load("re020_independent_verify", PACKET / "independent_verify.py")
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
class PathFieldThunkTests(unittest.TestCase):
    def test_output_pin_and_expectations(self):
        r = tool.analyse(bytes(DATA))
        self.assertEqual(tool.expectation_errors(r), [])
        text = tool.render(r)
        self.assertEqual(hashlib.sha256(text.encode()).hexdigest(), OUTPUT_SHA256)
        self.assertEqual((PACKET / "path-field-thunk.json").read_text(), text)

    def test_exact_counts(self):
        r = tool.analyse(bytes(DATA))
        self.assertEqual(r["ff15_count"], 4)
        self.assertEqual(r["e8_direct_to_thunk_count"], 0)
        self.assertEqual(len(tool.KEY_INSNS), 26)
        self.assertEqual(r["key_insns"], 26)
        self.assertEqual(len(r["locations"]), 1)
        self.assertEqual(r["fde_a_extent_len"], 10208)
        self.assertEqual(r["fde_b_extent_len"], 192)
        self.assertEqual(r["got_slot"], "0x5773c70")
        self.assertEqual(r["got_addend"], "0x4546ba0")
        self.assertEqual(r["path_sources"]["0x22aec0f"]["path_ptr_source"], "[rbp+0xd0]")
        self.assertEqual(r["path_sources"]["0x22aee86"]["path_ptr_source"], "[rbp+0x140]")
        self.assertEqual(r["path_sources"]["0x22aef33"]["path_ptr_source"], "[rbp+0x220]")
        self.assertEqual(r["path_sources"]["0x22afc2c"]["path_ptr_source"], "r15")

    def test_seeds_and_optimize_byte_identical(self):
        outs = set()
        for seed, flags in (("0", []), ("7", []), ("99", []), ("0", ["-O"])):
            env = dict(os.environ, PYTHONHASHSEED=seed)
            outs.add(subprocess.run(
                [sys.executable, "-B", *flags, str(ROOT / "tools" / "path_field_thunk.py")],
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
                              {"hashlib", "pathlib", "struct"}, line)

    def test_every_key_byte_flip_caught_by_independent(self):
        for va, hx in iv.KEYS:
            for i in range(len(hx) // 2):
                with self.subTest(va=hex(va), byte=i), flip(va, i) as d:
                    self.assertTrue(iv.check_keys(
                        bytes(d), check_sha=False, census=False,
                        locations=False, extent=False))

    def test_every_key_va_flip_rejected_by_tool(self):
        for va, _hx, role in tool.KEY_INSNS:
            with self.subTest(va=hex(va), role=role), flip(va) as d:
                self.assertTrue(tool_rejects(d))

    def test_wrong_binary_sha_rejected(self):
        d = bytearray(DATA)
        d[0] ^= 1
        with self.assertRaises(ValueError):
            tool.analyse(bytes(d))

    def test_token_rule_clean(self):
        import re
        pat = re.compile(rb"\b(keys?|tokens?|secret|password)=")
        paths = list(PACKET.glob("*")) + [ROOT / "tools" / "path_field_thunk.py",
                                          ROOT / "tests" / "test_path_field_thunk.py"]
        for p in paths:
            if p.is_file():
                self.assertIsNone(pat.search(p.read_bytes()), p)


if __name__ == "__main__":
    unittest.main()
