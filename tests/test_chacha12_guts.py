"""RE-022: ChaCha12 guts packet — exact pins, seed determinism, negative controls, tamper tests."""
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-022-chacha12-guts-94"
sys.path.insert(0, str(ROOT / "tools"))
import chacha12_guts as tool  # noqa: E402

OUTPUT_SHA256 = "146a164a1fbc9be96ede3696385ee093560a303539b890fc68707f6770d9c3ab"
NO_EMU_OUTPUT_SHA256 = "d3d31f80bfbf74bc86c3fb528853e413e53548025288ca4c0335e07fa569d48b"
HAS_UNICORN = importlib.util.find_spec("unicorn") is not None


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


iv = load("re022_independent_verify", PACKET / "independent_verify.py")
DATA = bytearray(tool.TARGET.read_bytes()) if tool.TARGET.exists() else None
SEGS = tool.segments(bytes(DATA)) if DATA is not None else None


def off(va):
    for base, o, size, _m in SEGS:
        if base <= va < base + size:
            return o + va - base
    # filesz-based
    for base, o, filesz, _m in SEGS:
        if base <= va < base + filesz:
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
class ChaCha12GutsTests(unittest.TestCase):
    def test_static_output_pin_and_expectations(self):
        r = tool.analyse(bytes(DATA), run_emu=False)
        self.assertEqual(tool.expectation_errors(r), [])
        text = tool.render(r)
        self.assertEqual(hashlib.sha256(text.encode()).hexdigest(), NO_EMU_OUTPUT_SHA256)
        import json
        disk = json.loads((PACKET / "chacha12-guts.json").read_text())
        self.assertEqual(disk["key_insns_count"], 20)
        self.assertEqual(disk["carved_sha256"], tool.CARVED_SHA256)
        self.assertEqual(disk["got_caller_count"], 21)
        for name, spec in tool.VECTORS.items():
            self.assertEqual(
                disk["vectors"][name]["expected_output_hex"],
                spec["output_hex"],
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
                [sys.executable, "-B", str(ROOT / "tools" / "chacha12_guts.py"), "--no-emu"],
                cwd=str(ROOT), env=env,
            )
            digests.append(hashlib.sha256(out).hexdigest())
        self.assertEqual(digests[0], digests[1])
        self.assertEqual(digests[1], digests[2])
        self.assertEqual(digests[0], NO_EMU_OUTPUT_SHA256)

    def test_independent_verify_imports(self):
        src = (PACKET / "independent_verify.py").read_text()
        for banned in ("unicorn", "chacha12_guts", "import json", "import os"):
            # allow words in comments/strings carefully — require import line check
            pass
        self.assertNotIn("import unicorn", src)
        self.assertNotIn("chacha12_guts", src)
        # only hashlib pathlib struct
        imports = [ln for ln in src.splitlines() if ln.startswith("import ") or ln.startswith("from ")]
        self.assertEqual(imports, [
            "import hashlib",
            "from pathlib import Path",
            "import struct",
        ])

    def test_tamper_expand_rejected(self):
        with flip(tool.EXPAND_VA):
            self.assertTrue(tool_rejects(DATA))

    def test_tamper_prologue_rejected(self):
        with flip(tool.FN):
            self.assertTrue(tool_rejects(DATA))

    def test_tamper_caller_esi_rejected(self):
        with flip(0x13C9ECA, at=1):  # change imm 6
            self.assertTrue(tool_rejects(DATA))

    def test_negative_wrong_fn_va(self):
        # flipping a nearby unrelated byte outside pins should still pass static
        # (use a byte in the padding int3 after ret that is not in KEY_INSNS)
        # Actually int3 after ret is outside carved for key checks of pinned sites.
        # Flip a non-pinned byte inside function body that is not in KEY_INSNS list.
        # Use 0x4e13790 which is mid-setup but not pinned — static key_insns still match;
        # expectation_errors may still pass static. So this is a negative that tool does NOT reject.
        with flip(0x4E137A0):
            r = tool.analyse(bytes(DATA), check_sha=False, run_emu=False)
            # key_insns still match
            self.assertTrue(all(kb["match"] for kb in r["key_bytes"]))

    @unittest.skipUnless(HAS_UNICORN, "unicorn not installed")
    def test_emu_tamper_expand_breaks_vector(self):
        with flip(tool.EXPAND_VA):
            r = tool.analyse(bytes(DATA), check_sha=False, run_emu=True)
            self.assertTrue(any(not v.get("emulated_match", True) for v in r["vectors"].values())
                            or tool.expectation_errors(r))

    @unittest.skipUnless(HAS_UNICORN, "unicorn not installed")
    def test_exact_counts_emu_byte_identical(self):
        r = tool.analyse(bytes(DATA), run_emu=True)
        self.assertEqual(r["got_caller_count"], 21)
        self.assertEqual(r["key_insns_count"], 20)
        for v in r["vectors"].values():
            self.assertTrue(v["emulated_match"])
            self.assertEqual(v["counter_after"], 4)


if __name__ == "__main__":
    unittest.main()
