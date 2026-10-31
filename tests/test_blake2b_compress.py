"""RE-021: Blake2b compress packet — exact pins, seed determinism, negative controls, tamper tests."""
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-021-blake2b-compress-94"
sys.path.insert(0, str(ROOT / "tools"))
import blake2b_compress as tool  # noqa: E402

# Full JSON pin (includes Unicorn behavioural proof fields).
OUTPUT_SHA256 = "dc2420392ce8f7ad5f63dbc313b8ddb8095143a91a25eef1e9a2a7663ad78f92"
# Static-only JSON pin (tools/blake2b_compress.py --no-emu): committed expected
# EIP-152 outputs without emulated_* fields. Unconditional across environments.
NO_EMU_OUTPUT_SHA256 = "bf027d6f03afb99a699b8a3def6ccecb026be95f6714d6e61c743ea52aed7ed6"

HAS_UNICORN = importlib.util.find_spec("unicorn") is not None


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


iv = load("re021_independent_verify", PACKET / "independent_verify.py")
DATA = bytearray(tool.TARGET.read_bytes()) if tool.TARGET.exists() else None
SEGS = tool.segments(bytes(DATA)) if DATA is not None else None


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
        r = tool.analyse(bytes(data), check_sha=False, run_emu=False)
        if any(not kb["match"] for kb in r["key_bytes"]):
            return True
        if tool.expectation_errors(r):
            return True
        if not HAS_UNICORN:
            return False
        r = tool.analyse(bytes(data), check_sha=False, run_emu=True)
        return bool(tool.expectation_errors(r))
    except Exception:
        return True


@unittest.skipIf(DATA is None, "node #94 binary not present")
class Blake2bCompressTests(unittest.TestCase):
    def test_static_output_pin_and_expectations(self):
        """Unconditional: static pins + committed --no-emu JSON hash."""
        r = tool.analyse(bytes(DATA), run_emu=False)
        self.assertEqual(tool.expectation_errors(r), [])
        text = tool.render(r)
        self.assertEqual(hashlib.sha256(text.encode()).hexdigest(), NO_EMU_OUTPUT_SHA256)
        # Committed packet JSON is the full (unicorn) pin; static expected
        # outputs inside it must still match the tool's EIP-152 table.
        import json
        disk = json.loads((PACKET / "blake2b-compress.json").read_text())
        for name, spec in tool.EIP152_VECTORS.items():
            self.assertEqual(
                disk["eip152_vectors"][name]["expected_output_hex"],
                spec["output_hex"],
                name,
            )
            self.assertEqual(
                r["eip152_vectors"][name]["expected_output_hex"],
                spec["output_hex"],
                name,
            )
        self.assertEqual(disk["key_insns_count"], 37)
        self.assertEqual(disk["carved_sha256"], tool.CARVED_SHA256)

    @unittest.skipUnless(HAS_UNICORN, "unicorn not installed; emulation tests skipped")
    def test_output_pin_and_expectations(self):
        r = tool.analyse(bytes(DATA))
        self.assertEqual(tool.expectation_errors(r), [])
        text = tool.render(r)
        self.assertEqual(hashlib.sha256(text.encode()).hexdigest(), OUTPUT_SHA256)
        self.assertEqual((PACKET / "blake2b-compress.json").read_text(), text)

    def test_exact_counts(self):
        r = tool.analyse(bytes(DATA), run_emu=False)
        self.assertEqual(r["key_insns_count"], 37)
        self.assertEqual(len(tool.KEY_INSNS), 37)
        self.assertEqual(r["carved_len"], 1932)
        self.assertEqual(r["carved_sha256"], tool.CARVED_SHA256)
        self.assertEqual(r["rol_counts"], {"0x20": 8, "0x28": 8, "0x30": 8, "1": 8})
        self.assertEqual(len(r["eip152_vectors"]), 4)
        self.assertEqual(r["eip152_vectors"]["vector_4_rounds0"]["rounds"], 0)
        self.assertEqual(r["eip152_vectors"]["vector_5_rounds12"]["rounds"], 12)
        self.assertEqual(
            r["eip152_vectors"]["vector_4_rounds0"]["expected_output_hex"],
            tool.EIP152_VECTORS["vector_4_rounds0"]["output_hex"],
        )
        self.assertEqual(
            r["eip152_vectors"]["vector_5_rounds12"]["expected_output_hex"],
            tool.EIP152_VECTORS["vector_5_rounds12"]["output_hex"],
        )
        self.assertEqual(r["behavioural_proof"], "unicorn_emulation_of_carved_function_bytes")
        self.assertEqual(r["hyperevm_precompile_wiring"]["status"], "statically_shown")
        self.assertTrue(r["hyperevm_precompile_wiring"]["address_0x09_match"])
        self.assertEqual(r["hyperevm_precompile_wiring"]["gas_per_round"], 1)
        self.assertEqual(r["hyperevm_precompile_wiring"]["input_len_imm"], "0xd5")
        self.assertIsNotNone(r["hyperevm_precompile_wiring"]["wrap_rela"])
        self.assertIsNotNone(r["hyperevm_precompile_wiring"]["f_rela"])
        self.assertEqual(r["location_path_len"], 102)
        self.assertTrue(r["location_path_match"])

    @unittest.skipUnless(HAS_UNICORN, "unicorn not installed; emulation tests skipped")
    def test_exact_counts_emu_byte_identical(self):
        r = tool.analyse(bytes(DATA), run_emu=True)
        self.assertTrue(r["eip152_vectors"]["vector_4_rounds0"]["byte_identical"])
        self.assertTrue(r["eip152_vectors"]["vector_5_rounds12"]["byte_identical"])

    def test_seeds_and_optimize_byte_identical_no_emu(self):
        """Unconditional seed/-O stability of the static (--no-emu) JSON."""
        outs = set()
        for seed, flags in (("0", []), ("7", []), ("99", []), ("0", ["-O"])):
            env = dict(os.environ, PYTHONHASHSEED=seed)
            outs.add(subprocess.run(
                [sys.executable, "-B", *flags, str(ROOT / "tools" / "blake2b_compress.py"),
                 "--no-emu"],
                env=env, check=True, capture_output=True).stdout)
        self.assertEqual(len(outs), 1)
        self.assertEqual(hashlib.sha256(outs.pop()).hexdigest(), NO_EMU_OUTPUT_SHA256)

    @unittest.skipUnless(HAS_UNICORN, "unicorn not installed; emulation tests skipped")
    def test_seeds_and_optimize_byte_identical(self):
        outs = set()
        for seed, flags in (("0", []), ("7", []), ("99", []), ("0", ["-O"])):
            env = dict(os.environ, PYTHONHASHSEED=seed)
            outs.add(subprocess.run(
                [sys.executable, "-B", *flags, str(ROOT / "tools" / "blake2b_compress.py")],
                env=env, check=True, capture_output=True).stdout)
        self.assertEqual(len(outs), 1)
        self.assertEqual(hashlib.sha256(outs.pop()).hexdigest(), OUTPUT_SHA256)

    def test_independent_verifier_passes(self):
        self.assertEqual(iv.check_keys(bytes(DATA)), [])
        self.assertEqual(iv.check_packet(), [])

    def test_negative_control_wrong_sha_rejected(self):
        bad = bytearray(DATA)
        bad[0] ^= 0x01
        with self.assertRaises(ValueError):
            tool.analyse(bytes(bad), check_sha=True, run_emu=False)

    def test_tamper_each_key_insn_fails(self):
        for va, hx, _note in tool.KEY_INSNS:
            with self.subTest(va=hex(va)):
                with flip(va):
                    self.assertTrue(tool_rejects(DATA), f"tamper at {hex(va)} should fail")

    def test_tamper_iv_immediate_fails_decode(self):
        with flip(0x4E9A8C8, at=2):
            self.assertTrue(tool_rejects(DATA))

    def test_tamper_sigma0_fails(self):
        with flip(tool.SIGMA_VA):
            self.assertTrue(tool_rejects(DATA))

    def test_tamper_carved_changes_sha(self):
        with flip(tool.FN, at=10):
            r = tool.analyse(bytes(DATA), check_sha=False, run_emu=False)
            self.assertNotEqual(r["carved_sha256"], tool.CARVED_SHA256)

    @unittest.skipUnless(HAS_UNICORN, "unicorn not installed; emulation tests skipped")
    def test_emu_tamper_iv_breaks_vector(self):
        with flip(0x4E9A8C8, at=4):
            r = tool.analyse(bytes(DATA), check_sha=False, run_emu=True)
            v = r["eip152_vectors"]["vector_5_rounds12"]
            self.assertFalse(v["byte_identical"])

    def test_tamper_wiring_len_check_fails(self):
        with flip(0x4E9D2AA):
            self.assertTrue(tool_rejects(DATA))

    def test_tamper_wiring_final_flag_fails(self):
        with flip(0x4E9D2F9):
            self.assertTrue(tool_rejects(DATA))

    def test_tamper_wiring_bswap_fails(self):
        with flip(0x4E9D2BA):
            self.assertTrue(tool_rejects(DATA))

    def test_tamper_wiring_call_fails(self):
        with flip(0x4E9D3BD):
            self.assertTrue(tool_rejects(DATA))

    def test_tamper_address_0x09_fails(self):
        with flip(tool.ADDR09_VA, at=19):
            self.assertTrue(tool_rejects(DATA))

    def test_token_rule_no_secret_equals(self):
        text = tool.render(tool.analyse(bytes(DATA), run_emu=False))
        for bad in ("keys=", "key=", "token=", "tokens=", "secret=", "password="):
            self.assertNotIn(bad, text)
        self.assertIn("key_insns_count", text)

    def test_no_abs_paths_in_tests_file(self):
        src = (ROOT / "tests" / "test_blake2b_compress.py").read_text()
        needle_home = "/" + "home/"
        needle_tmp = "/" + "tmp/"
        needle_ws = "/" + "workspace/"
        self.assertNotIn(needle_home, src)
        self.assertNotIn(needle_tmp, src)
        self.assertNotIn(needle_ws, src)

    def test_vector_output_pins(self):
        r = tool.analyse(bytes(DATA), run_emu=False)
        self.assertEqual(
            r["eip152_vectors"]["vector_4_rounds0"]["expected_output_hex"],
            tool.EIP152_VECTORS["vector_4_rounds0"]["output_hex"],
        )
        self.assertEqual(
            r["eip152_vectors"]["vector_5_rounds12"]["expected_output_hex"],
            tool.EIP152_VECTORS["vector_5_rounds12"]["output_hex"],
        )


if __name__ == "__main__":
    unittest.main()
