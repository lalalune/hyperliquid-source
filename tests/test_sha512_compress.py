"""RE-023: SHA-512 compress packet — exact pins, seed determinism, negative controls, tamper tests."""
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-023-sha512-compress-94"
sys.path.insert(0, str(ROOT / "tools"))
import sha512_compress as tool  # noqa: E402

OUTPUT_SHA256 = "8cb0c2e8bb4b4da347cf14b3142fcee8a2458275d9adc85550bf780da745e5e4"
NO_EMU_OUTPUT_SHA256 = "783b671d1ac2ba4497eb611fb4e7b5a576b11ce22619e18d96f35e313964a739"
HAS_UNICORN = importlib.util.find_spec("unicorn") is not None


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


iv = load("re023_independent_verify", PACKET / "independent_verify.py")
DATA = bytearray(tool.TARGET.read_bytes()) if tool.TARGET.exists() else None
SEGS = tool.segments(bytes(DATA)) if DATA is not None else None


def off(va):
    for base, o, filesz, _m in SEGS:
        if base <= va < base + filesz:
            return o + va - base
    raise KeyError(hex(va))


class Patched:
    def __init__(self, file_off, new):
        self.o, self.new = file_off, bytes(new)

    def __enter__(self):
        self.old = bytes(DATA[self.o : self.o + len(self.new)])
        DATA[self.o : self.o + len(self.new)] = self.new
        return DATA

    def __exit__(self, *exc):
        DATA[self.o : self.o + len(self.old)] = self.old


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
class Sha512CompressTests(unittest.TestCase):
    def test_static_output_pin_and_expectations(self):
        r = tool.analyse(bytes(DATA), run_emu=False)
        self.assertEqual(tool.expectation_errors(r), [])
        text = tool.render(r)
        self.assertEqual(hashlib.sha256(text.encode()).hexdigest(), NO_EMU_OUTPUT_SHA256)
        import json

        disk = json.loads((PACKET / "sha512-compress.json").read_text())
        self.assertEqual(disk["key_insns_count"], 15)
        self.assertEqual(disk["carved_sha256"], tool.CARVED_SHA256)
        self.assertEqual(disk["got_mov_caller_count"], 1)
        for name, spec in tool.VECTORS.items():
            self.assertEqual(
                disk["vectors"][name]["expected_digest_hex"],
                spec["digest_hex"],
                name,
            )

    @unittest.skipUnless(HAS_UNICORN, "unicorn not installed")
    def test_output_pin_and_expectations(self):
        r = tool.analyse(bytes(DATA), run_emu=True)
        self.assertEqual(tool.expectation_errors(r), [])
        text = tool.render(r)
        self.assertEqual(hashlib.sha256(text.encode()).hexdigest(), OUTPUT_SHA256)

    def test_seed_determinism_no_emu(self):
        digests = []
        for seed in ("0", "7", "99"):
            env = os.environ.copy()
            env["PYTHONHASHSEED"] = seed
            env["PYTHONPATH"] = str(ROOT / "tools") + os.pathsep + env.get("PYTHONPATH", "")
            out = subprocess.check_output(
                [sys.executable, "-B", str(ROOT / "tools" / "sha512_compress.py"), "--no-emu"],
                cwd=str(ROOT),
                env=env,
            )
            digests.append(hashlib.sha256(out).hexdigest())
        self.assertEqual(digests[0], digests[1])
        self.assertEqual(digests[1], digests[2])
        self.assertEqual(digests[0], NO_EMU_OUTPUT_SHA256)

    def test_optim_determinism_no_emu(self):
        env = os.environ.copy()
        env["PYTHONHASHSEED"] = "0"
        out = subprocess.check_output(
            [sys.executable, "-O", "-B", str(ROOT / "tools" / "sha512_compress.py"), "--no-emu"],
            cwd=str(ROOT),
            env=env,
        )
        self.assertEqual(hashlib.sha256(out).hexdigest(), NO_EMU_OUTPUT_SHA256)

    def test_independent_verify_imports(self):
        src = (PACKET / "independent_verify.py").read_text()
        self.assertNotIn("import unicorn", src)
        self.assertNotIn("sha512_compress", src)
        imports = [ln for ln in src.splitlines() if ln.startswith("import ") or ln.startswith("from ")]
        self.assertEqual(
            imports,
            [
                "import hashlib",
                "from pathlib import Path",
                "import struct",
            ],
        )

    def test_tamper_prologue_rejected(self):
        with flip(tool.FN):
            self.assertTrue(tool_rejects(DATA))

    def test_tamper_dispatcher_e9_rejected(self):
        with flip(tool.DISPATCHER_E9, at=1):
            self.assertTrue(tool_rejects(DATA))

    def test_tamper_caller_mov_rejected(self):
        with flip(tool.CALLER_MOV, at=3):
            self.assertTrue(tool_rejects(DATA))

    def test_negative_unpinned_byte_still_static_ok(self):
        # Mid-body byte not in KEY_INSNS: static pins still match.
        with flip(0x4EC4A60):
            r = tool.analyse(bytes(DATA), check_sha=False, run_emu=False)
            self.assertTrue(all(kb["match"] for kb in r["key_bytes"]))

    @unittest.skipUnless(HAS_UNICORN, "unicorn not installed")
    def test_emu_tamper_prologue_breaks_vector(self):
        with flip(tool.FN):
            r = tool.analyse(bytes(DATA), check_sha=False, run_emu=True)
            self.assertTrue(
                any(not v.get("emulated_match", True) for v in r["vectors"].values())
                or tool.expectation_errors(r)
            )

    @unittest.skipUnless(HAS_UNICORN, "unicorn not installed")
    def test_exact_counts_emu_byte_identical(self):
        r = tool.analyse(bytes(DATA), run_emu=True)
        self.assertEqual(r["got_mov_caller_count"], 1)
        self.assertEqual(r["key_insns_count"], 15)
        for v in r["vectors"].values():
            self.assertTrue(v["emulated_match"])


if __name__ == "__main__":
    unittest.main()
