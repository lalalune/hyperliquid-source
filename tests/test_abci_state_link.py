"""RE-017: abci state link packet, exact pins, seed determinism, negative controls and tamper tests."""
import hashlib
import importlib.util
import os
from pathlib import Path
import struct
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research' / 'work-items' / 'RE-017-abci-state-link-94'
sys.path.insert(0, str(ROOT / 'tools'))
import abci_state_link as tool  # noqa: E402

OUTPUT_SHA256 = 'e8e24678b2e9aa32e93a08f5ab9e469b49b40742d2839affb1c9c2295ace4548'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


iv = load('re017_independent_verify', PACKET / 'independent_verify.py')
DATA = bytearray(tool.TARGET.read_bytes()) if tool.TARGET.exists() else None
SEGS = tool.segments(bytes(DATA[:0x1000])) if DATA is not None else None
SEC = tool.sections(bytes(DATA)) if DATA is not None else None


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


def rela_off(slot):
    s = SEC['.rela.dyn']
    for o in range(s['offset'], s['offset'] + s['size'], 24):
        if struct.unpack_from('<Q', DATA, o)[0] == slot:
            return o
    raise KeyError(hex(slot))


def tool_rejects(data):
    try:
        return bool(tool.expectation_errors(tool.analyse(bytes(data), check_sha=False)))
    except (ValueError, KeyError, IndexError, UnicodeDecodeError, struct.error):
        return True


@unittest.skipIf(DATA is None, 'node #94 binary not present')
class AbciStateLinkTests(unittest.TestCase):
    def test_output_pin_and_expectations(self):
        r = tool.analyse(bytes(DATA))
        self.assertEqual(tool.expectation_errors(r), [])
        text = tool.render(r)
        self.assertEqual(hashlib.sha256(text.encode()).hexdigest(), OUTPUT_SHA256)
        self.assertEqual((PACKET / 'abci-state-link.json').read_text(), text)

    def test_exact_counts(self):
        cs = tool.analyse(bytes(DATA))['caller_scan']
        self.assertEqual(cs['rel32_call_sites'], {'0x3273810': []})
        self.assertEqual(cs['ff15_slot_sites']['0x57755a8'], ['0x3272785'])
        self.assertEqual(len(cs['ff15_slot_sites']['0x5773aa8']), 6)
        self.assertEqual(len(tool.KEY_INSNS), 33)

    def test_seeds_and_optimize_byte_identical(self):
        outs = set()
        for seed, flags in (('0', []), ('7', []), ('99', []), ('0', ['-O'])):
            env = dict(os.environ, PYTHONHASHSEED=seed)
            outs.add(subprocess.run([sys.executable, '-B', *flags, str(ROOT / 'tools' / 'abci_state_link.py')],
                                    env=env, check=True, capture_output=True).stdout)
        self.assertEqual(len(outs), 1)
        self.assertEqual(hashlib.sha256(outs.pop()).hexdigest(), OUTPUT_SHA256)

    def test_independent_verifier_passes(self):
        self.assertEqual(iv.check_keys(bytes(DATA)), [])
        self.assertEqual(iv.check_packet(), [])

    def test_independent_imports_nothing_from_tools(self):
        src = (PACKET / 'independent_verify.py').read_text()
        self.assertNotIn('sys.path', src)
        for line in src.splitlines():
            if line.startswith(('import ', 'from ')):
                self.assertIn(line.split()[1].split('.')[0], {'hashlib', 'pathlib', 'struct'}, line)

    def test_every_key_byte_flip_caught_by_independent(self):
        for va, hx in iv.KEYS:
            for i in range(len(hx) // 2):
                with self.subTest(va=hex(va), byte=i), flip(va, i) as d:
                    self.assertTrue(iv.check_keys(bytes(d), check_sha=False, callers=False))

    def test_every_key_va_flip_rejected_by_tool(self):
        for va, _hx, role in tool.KEY_INSNS:
            with self.subTest(va=hex(va), role=role), flip(va) as d:
                self.assertTrue(tool_rejects(d))

    def test_extent_byte_outside_keys_caught(self):
        # 0x32738e0 movups xmm0,[rbx] is not a key instruction; only the extent hash pins it
        with flip(0x32738e0, 2) as d:
            self.assertTrue(tool_rejects(d))
            self.assertTrue(iv.check_keys(bytes(d), check_sha=False, callers=False))

    def test_reloc_tampers(self):
        o = rela_off(0x57755a8)
        for field, delta in (('type', 8), ('sym', 12), ('addend', 16)):
            with self.subTest(field=field), Patched(o + delta, [DATA[o + delta] ^ 0x01]) as d:
                self.assertTrue(tool_rejects(d))
                self.assertTrue(iv.check_keys(bytes(d), check_sha=False, callers=False))

    def test_duplicate_addend_rejected(self):
        o = rela_off(0x57755a0)
        with Patched(o + 16, struct.pack('<q', 0x3273810)) as d:
            self.assertTrue(tool_rejects(d))
            self.assertTrue(iv.check_keys(bytes(d), check_sha=False, callers=False))

    def test_location_tampers(self):
        for at in (8, 16, 20):  # length, line, column
            with self.subTest(at=at), flip(0x56dfbf8 + at) as d:
                self.assertTrue(tool_rejects(d))
                self.assertTrue(iv.check_keys(bytes(d), check_sha=False, callers=False))
        with flip(0x1dd8eb + 40) as d:  # one byte of the file name string
            self.assertTrue(tool_rejects(d))
            self.assertTrue(iv.check_keys(bytes(d), check_sha=False, callers=False))

    def test_caller_tampers(self):
        with flip(0x226685a + 2) as d:  # remove one ff15 site on 0x5773aa8
            self.assertTrue(tool_rejects(d))
            self.assertTrue(iv.check_callers(bytes(d)))
        site = 0x3273810 - 0x10  # plant a rel32 call to the reloc-only function
        with Patched(off(site), b'\xe8' + struct.pack('<i', 0x3273810 - (site + 5))) as d:
            self.assertTrue(tool_rejects(d))
            self.assertTrue(iv.check_callers(bytes(d)))
        self.assertEqual(iv.check_callers(bytes(DATA)), [])

    def test_negative_control_neighbour_slot(self):
        # 0x57755a0 is a neighbouring RELATIVE slot (0x32d62e0): not the claimed link
        r = tool.analyse(bytes(DATA))
        self.assertNotIn('0x57755a0', r['addend_carriers'])
        self.assertNotIn('0x57755a0', r['caller_scan']['ff15_slot_sites'])

    def test_sha_mismatch_rejected(self):
        with flip(0x3273810):
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
