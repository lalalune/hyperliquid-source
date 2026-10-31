"""RE-024: RIPEMD-160 compress packet — exact pins, seed determinism, negative controls, tamper tests."""
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-024-ripemd160-compress-94"
sys.path.insert(0, str(ROOT / "tools"))
import ripemd160_compress as tool  # noqa: E402

OUTPUT_SHA256 = "6167af924de2bbdb68943119ea66c3866448fa024b20992a10cd9bdd7ecefb43"
NO_EMU_OUTPUT_SHA256 = "93cb5eefd852849a082765ffb6c87e7a192b07b073d3b33bf8f61affb2cf5ca4"
HAS_UNICORN = importlib.util.find_spec("unicorn") is not None


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


iv = load("re024_independent_verify", PACKET / "independent_verify.py")
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
class Ripemd160CompressTests(unittest.TestCase):
    def test_static_output_pin_and_expectations(self):
        r = tool.analyse(bytes(DATA), run_emu=False)
        self.assertEqual(tool.expectation_errors(r), [])
        text = tool.render(r)
        self.assertEqual(hashlib.sha256(text.encode()).hexdigest(), NO_EMU_OUTPUT_SHA256)
        import json

        disk = json.loads((PACKET / "ripemd160-compress.json").read_text())
        self.assertEqual(disk["key_insns_count"], 8)
        self.assertEqual(disk["carved_sha256"], tool.CARVED_SHA256)
        self.assertEqual(disk["got_mov_caller_count"], 1)
        self.assertEqual(disk["got_ff15_caller_count"], 1)
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
                [sys.executable, "-B", str(ROOT / "tools" / "ripemd160_compress.py"), "--no-emu"],
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
            [sys.executable, "-O", "-B", str(ROOT / "tools" / "ripemd160_compress.py"), "--no-emu"],
            cwd=str(ROOT),
            env=env,
        )
        self.assertEqual(hashlib.sha256(out).hexdigest(), NO_EMU_OUTPUT_SHA256)

    def test_independent_verify_imports(self):
        src = (PACKET / "independent_verify.py").read_text()
        self.assertNotIn("import unicorn", src)
        self.assertNotIn("ripemd160_compress", src)
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

    def test_tamper_finalize_mov_rejected(self):
        with flip(tool.FINALIZE_MOV, at=3):
            self.assertTrue(tool_rejects(DATA))

    def test_tamper_location_lea_rejected(self):
        with flip(tool.LOCATION_LEA, at=3):
            self.assertTrue(tool_rejects(DATA))

    def test_negative_unpinned_byte_still_static_ok(self):
        # Mid-body byte not in KEY_INSNS: static pins still match.
        with flip(0x4EA5610):
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
    def test_emu_tamper_mid_carve_breaks_digest(self):
        # Flip a mid-compress K-constant byte (not a KEY_INSN). Digest mismatch
        # or Unicorn fault both count as detected break.
        with flip(0x4ea603d):
            try:
                r = tool.analyse(bytes(DATA), check_sha=False, run_emu=True)
            except Exception:
                return
            self.assertTrue(
                any(not v.get("emulated_match", True) for v in r["vectors"].values())
            )

    @unittest.skipUnless(HAS_UNICORN, "unicorn not installed")
    def test_emu_mutated_state_and_block_mismatch(self):
        # Direct Unicorn: flip IV state byte / flip block byte → digest != KAT.
        segs = tool.segments(bytes(DATA))
        padded = bytes.fromhex(tool.VECTORS["abc"]["padded_hex"])
        expect = tool.VECTORS["abc"]["digest_hex"]
        good = tool.emulate_compress(bytes(DATA), segs, padded)
        self.assertEqual(good.hex(), expect)
        # Mutate block: XOR first padded byte after IV path — re-run with patched binary
        # is heavy; instead mutate via a local reimplementation of the call inputs.
        from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_PROT_ALL, UcError
        from unicorn.x86_const import UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RSP
        import struct as st

        def run(state0, block0):
            mu = Uc(UC_ARCH_X86, UC_MODE_64)
            page = 0x1000

            def map_span(va, size):
                start = va & ~(page - 1)
                end = (va + size + page - 1) & ~(page - 1)
                try:
                    mu.mem_map(start, end - start, UC_PROT_ALL)
                except UcError:
                    for p in range(start, end, page):
                        try:
                            mu.mem_map(p, page, UC_PROT_ALL)
                        except UcError:
                            pass

            for base, off, filesz, memsz in segs:
                map_span(base, memsz)
                blob = bytes(DATA)[off : off + filesz] + bytes(max(0, memsz - filesz))
                mu.mem_write(base, blob)
            STACK = 0x7FFF00000000
            map_span(STACK, 0x100000)
            SCRATCH = 0x70000000
            map_span(SCRATCH, 0x10000)
            STOP = 0x600000000
            map_span(STOP, 0x1000)
            mu.mem_write(STOP, b"\xf4")
            STATE = SCRATCH + 0x100
            BLOCK = SCRATCH + 0x200
            mu.mem_write(STATE, state0)
            mu.mem_write(BLOCK, block0)
            rsp = STACK + 0x100000 - 0x2000 - 8
            mu.mem_write(rsp, st.pack("<Q", STOP))
            mu.reg_write(UC_X86_REG_RSP, rsp)
            mu.reg_write(UC_X86_REG_RDI, STATE)
            mu.reg_write(UC_X86_REG_RSI, BLOCK)
            mu.emu_start(tool.FN, STOP, timeout=10_000_000, count=5_000_000)
            return bytes(mu.mem_read(STATE, 20))

        iv = bytearray(tool.RIPEMD160_IV_LE)
        blk = bytearray(padded[:64])
        bad_state = bytearray(iv)
        bad_state[0] ^= 0x01
        bad_block = bytearray(blk)
        bad_block[0] ^= 0x01
        self.assertNotEqual(run(bytes(bad_state), bytes(blk)).hex(), expect)
        self.assertNotEqual(run(bytes(iv), bytes(bad_block)).hex(), expect)

    @unittest.skipUnless(HAS_UNICORN, "unicorn not installed")
    def test_exact_counts_emu_byte_identical(self):
        r = tool.analyse(bytes(DATA), run_emu=True)
        self.assertEqual(r["got_mov_caller_count"], 1)
        self.assertEqual(r["got_ff15_caller_count"], 1)
        self.assertEqual(r["key_insns_count"], 8)
        for v in r["vectors"].values():
            self.assertTrue(v["emulated_match"])


if __name__ == "__main__":
    unittest.main()
