"""RE-018: materializer call ABI packet, exact pins, seed determinism, negative controls and tamper tests."""
import hashlib
import importlib.util
import os
from pathlib import Path
import struct
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research' / 'work-items' / 'RE-018-materializer-call-abi-94'
sys.path.insert(0, str(ROOT / 'tools'))
import materializer_call_abi as tool  # noqa: E402

SLOT = 0x5773aa8
OUTPUT_SHA256 = '4789cdd0cb2dd7af93b0a20b50cd976da3b3fc18fe0307505d0b25a98c6f52f0'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


iv = load('re018_independent_verify', PACKET / 'independent_verify.py')
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


@unittest.skipIf(DATA is None, 'node #94 binary not present')
class MaterializerCallAbiTests(unittest.TestCase):
    def test_output_pin_and_expectations(self):
        r = tool.analyse(bytes(DATA))
        self.assertEqual(tool.expectation_errors(r), [])
        text = tool.render(r)
        self.assertEqual(hashlib.sha256(text.encode()).hexdigest(), OUTPUT_SHA256)
        self.assertEqual((PACKET / 'materializer-call-abi.json').read_text(), text)

    def test_exact_counts(self):
        r = tool.analyse(bytes(DATA))
        self.assertEqual(len(r['sites']), 5)
        self.assertEqual(len(r['caller_scan']['ff15_slot_sites']['0x5773aa8']), 6)
        self.assertEqual(len(tool.KEY_INSNS), 38)
        self.assertEqual(len(r['window_sha256']), 5)

    def test_seeds_and_optimize_byte_identical(self):
        outs = set()
        for seed, flags in (('0', []), ('7', []), ('99', []), ('0', ['-O'])):
            env = dict(os.environ, PYTHONHASHSEED=seed)
            outs.add(subprocess.run([sys.executable, '-B', *flags, str(ROOT / 'tools' / 'materializer_call_abi.py')],
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
                self.assertIn(line.split()[1].split('.')[0],
                              {'hashlib', 'pathlib', 'struct', 'bisect'}, line)

    def test_every_key_byte_flip_caught_by_independent(self):
        for va, hx in iv.KEYS:
            for i in range(len(hx) // 2):
                with self.subTest(va=hex(va), byte=i), flip(va, i) as d:
                    self.assertTrue(iv.check_keys(bytes(d), check_sha=False, callers=False, windows=False))

    def test_every_key_va_flip_rejected_by_tool(self):
        for va, _hx, role in tool.KEY_INSNS:
            with self.subTest(va=hex(va), role=role), flip(va) as d:
                self.assertTrue(tool_rejects(d))

    def test_window_byte_outside_keys_caught(self):
        # 0x2266820 is inside the [-0x40,+6) window of 0x226685a but not a key insn
        with flip(0x2266820) as d:
            self.assertTrue(tool_rejects(d))
            self.assertTrue(iv.check_keys(bytes(d), check_sha=False, callers=False))

    def test_caller_tampers(self):
        with flip(0x226685a + 2) as d:
            self.assertTrue(tool_rejects(d))
            self.assertTrue(iv.check_callers(bytes(d)))
        # plant an extra ff15 to the slot in a dead zone near 0x2266868
        site = 0x2266870
        disp = SLOT - (site + 6)
        with Patched(off(site), b'\xff\x15' + struct.pack('<i', disp)) as d:
            self.assertTrue(tool_rejects(d))
            self.assertTrue(iv.check_callers(bytes(d)))
        self.assertEqual(iv.check_callers(bytes(DATA)), [])

    def test_negative_control_re017_site(self):
        # 0x3273920 is the sixth ff15 site; this packet cites it but does not own its body
        r = tool.analyse(bytes(DATA))
        self.assertIn('0x3273920', r['caller_scan']['ff15_slot_sites']['0x5773aa8'])
        self.assertNotIn('0x3273920', r['sites'])
        self.assertNotIn('0x3273920', r['window_sha256'])

    def test_negative_control_neighbour_slot(self):
        # 0x5775580 is the RE-016 inner slot; not claimed here
        r = tool.analyse(bytes(DATA))
        self.assertNotIn('0x5775580', r['caller_scan']['ff15_slot_sites'])
        self.assertEqual(r['slot'], '0x5773aa8')

    def test_sha_mismatch_rejected(self):
        with flip(0x226685a):
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
