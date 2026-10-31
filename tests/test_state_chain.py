"""RE-016: state chain packet, exact pins, seed determinism and key-VA tamper tests."""
import hashlib
import importlib.util
import os
from pathlib import Path
import struct
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research' / 'work-items' / 'RE-016-state-chain-94'
sys.path.insert(0, str(ROOT / 'tools'))
import state_chain as tool  # noqa: E402

OUTPUT_SHA256 = '6e063821c3de3ad62dc45b0af1bc28ff7cdedaf048da0fbdd3cc5e51cabead75'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


iv = load('re016_independent_verify', PACKET / 'independent_verify.py')
DATA = bytearray(tool.TARGET.read_bytes()) if tool.TARGET.exists() else None
SEGS = tool.segments(bytes(DATA[:0x1000])) if DATA is not None else None


def off(va):
    for base, o, size in SEGS:
        if base <= va < base + size:
            return o + va - base
    raise KeyError(hex(va))


class Patched:
    """Overwrite bytes of the shared binary copy (file offset) for the duration of a block."""
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


def rela_off(slot):
    sec = tool.sections(bytes(DATA))['.rela.dyn']
    for o in range(sec['offset'], sec['offset'] + sec['size'], 24):
        if struct.unpack_from('<Q', DATA, o)[0] == slot:
            return o
    raise KeyError(hex(slot))


@unittest.skipIf(DATA is None, 'node #94 binary not present')
class StateChainTests(unittest.TestCase):
    def test_output_pin_and_expectations(self):
        r = tool.analyse(bytes(DATA))
        self.assertEqual(tool.expectation_errors(r), [])
        self.assertEqual(hashlib.sha256(tool.render(r).encode()).hexdigest(), OUTPUT_SHA256)
        self.assertEqual((PACKET / 'state-chain.json').read_text(), tool.render(r))

    def test_seeds_byte_identical(self):
        outs = set()
        for seed in ('0', '7', '99'):
            env = dict(os.environ, PYTHONHASHSEED=seed)
            outs.add(subprocess.run([sys.executable, '-B', str(ROOT / 'tools' / 'state_chain.py')],
                                    env=env, check=True, capture_output=True).stdout)
        self.assertEqual(len(outs), 1)
        self.assertEqual(hashlib.sha256(outs.pop()).hexdigest(), OUTPUT_SHA256)

    def test_independent_verifier_passes(self):
        self.assertEqual(iv.check_keys(bytes(DATA)), [])
        self.assertEqual(iv.check_packet(), [])

    def test_independent_imports_nothing_from_tools(self):
        src = (PACKET / 'independent_verify.py').read_text()
        self.assertNotIn('tools', ''.join(l for l in src.splitlines() if l.startswith(('import', 'from'))))
        self.assertNotIn('sys.path', src)

    def test_every_key_va_flip_is_caught_by_independent(self):
        for va, hx, role in iv.KEYS:
            for i in range(len(hx) // 2):
                with self.subTest(va=hex(va), byte=i), flip(va, i) as d:
                    self.assertTrue(iv.check_keys(bytes(d), check_sha=False), role)

    def test_chain_key_flips_rejected_by_tool(self):
        sites = [0x3752220, 0x3752221, 0x3270682, 0x3270684, 0x326e4bb, 0x326e4bc, 0x326e48b,
                 0x326e4a0, 0x326e4ac, 0x326e4e6, 0x326e4fa, 0x375220d + 4, 0x327066d + 4,
                 0x326e4b0 + 4, 0x375285e + 3, 0x375286d + 1, 0x3270756 + 1, 0x326e4dc + 1,
                 0x326e4e1 + 2, 0x327075b + 2, 0x3752865 + 4, 0x327074e + 4, 0x326e4d7 + 4,
                 0x3752287 + 3, 0x32706a5 + 3, 0x3751eb8 + 2, 0x32705ac + 2, 0x326e481 + 2]
        for va in sites:
            with self.subTest(va=hex(va)), flip(va) as d:
                self.assertTrue(tool_rejects(d))

    def test_branch_insertion_rejected(self):
        # replace the wrapper's 3-byte mov rax,rbx with je +1; nop: one branch where 0 are pinned
        with Patched(off(0x327079f), b'\x74\x01\x90') as d:
            self.assertTrue(tool_rejects(d))

    def test_reloc_tampers(self):
        for slot in (0x5773aa8, 0x5775580):
            o = rela_off(slot)
            for field, delta in (('type', 8), ('sym', 12), ('addend', 16)):
                with self.subTest(slot=hex(slot), field=field), Patched(o + delta, [DATA[o + delta] ^ 0x01]) as d:
                    self.assertTrue(tool_rejects(d))
                    self.assertTrue(iv.check_keys(bytes(d), check_sha=False))

    def test_duplicate_addend_rejected(self):
        o = rela_off(0x5773aa0)
        with Patched(o + 16, struct.pack('<q', 0x326e460)) as d:
            self.assertTrue(tool_rejects(d))
            self.assertTrue(iv.check_keys(bytes(d), check_sha=False))

    def test_caller_scan_pins(self):
        cs = tool.analyse(bytes(DATA))['caller_scan']
        self.assertEqual(cs['rel32_call_sites'], {'0x326e460': [], '0x3270570': ['0x3752220'], '0x3751e80': []})
        self.assertEqual(len(cs['ff15_slot_sites']['0x5773aa8']), 6)
        self.assertEqual(cs['ff15_slot_sites']['0x5775580'], ['0x3270682'])

    def test_caller_scan_tampers(self):
        # remove a known ff15 site, and plant a new rel32 call to each reloc-only function
        with flip(0x226685a + 2) as d:
            self.assertTrue(tool_rejects(d))
            self.assertTrue(iv.check_callers(bytes(d)))
        site = 0x3751e80 - 0x10
        for tgt in (0x3751e80, 0x326e460):
            new = b'\xe8' + struct.pack('<i', tgt - (site + 5))
            with self.subTest(tgt=hex(tgt)), Patched(off(site), new) as d:
                self.assertTrue(tool_rejects(d))
                self.assertTrue(iv.check_callers(bytes(d)))
        self.assertEqual(iv.check_callers(bytes(DATA)), [])

    def test_sha_mismatch_rejected(self):
        with flip(0x3751e80):
            with self.assertRaises(ValueError):
                tool.analyse(bytes(DATA))
            self.assertEqual(iv.check_keys(bytes(DATA)), ['binary sha256 mismatch'])

    def test_manifest_matches_files(self):
        for line in (PACKET / 'MANIFEST.sha256').read_text().splitlines():
            h, name = line.split('  ', 1)
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), h, name)

    def test_readme_hashes_match_manifest(self):
        readme = (PACKET / 'README.md').read_text()
        for line in (PACKET / 'MANIFEST.sha256').read_text().splitlines():
            h, name = line.split('  ', 1)
            if name != 'README.md':
                self.assertIn(h, readme, name)


if __name__ == '__main__':
    unittest.main()
