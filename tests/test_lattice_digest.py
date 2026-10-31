"""RE-009-D: lattice digest packet, exact pins and key-VA tamper tests."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research' / 'work-items' / 'RE-009-D-lattice-digest-94'
sys.path.insert(0, str(ROOT / 'tools'))
import lattice_digest as tool  # noqa: E402

OUTPUT_SHA256 = '53d36b84f3f5cca3821964e1670abdf38ff389d2b62a5b4e75d6f993f74860a0'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


iv = load('re009d_independent_verify', PACKET / 'independent_verify.py')
DATA = bytearray(tool.TARGET.read_bytes()) if tool.TARGET.exists() else None
SEGS = tool.segments(bytes(DATA[:0x1000])) if DATA is not None else None


def off(va):
    for base, o, size in SEGS:
        if base <= va < base + size:
            return o + va - base
    raise KeyError(hex(va))


class Patched:
    """Flip one byte of the shared binary copy for the duration of a block."""
    def __init__(self, va, value=None):
        self.o, self.value = off(va), value

    def __enter__(self):
        self.old = DATA[self.o]
        DATA[self.o] = self.old ^ 0x01 if self.value is None else self.value
        return DATA

    def __exit__(self, *exc):
        DATA[self.o] = self.old


def tool_rejects(data):
    try:
        return bool(tool.expectation_errors(tool.analyse(data, check_sha=False)))
    except (ValueError, KeyError, IndexError, TypeError, AttributeError, UnicodeDecodeError, struct_error()):
        return True


def struct_error():
    import struct
    return struct.error


@unittest.skipIf(DATA is None, 'node #94 binary not present')
class Packet(unittest.TestCase):
    def test_output_pinned_and_seed_independent(self):
        text = tool.render(tool.analyse(bytes(DATA)))
        self.assertEqual(hashlib.sha256(text.encode()).hexdigest(), OUTPUT_SHA256)
        self.assertEqual((PACKET / 'lattice-digest.json').read_text(), text)
        for seed in ('0', '7', '99'):
            out = subprocess.run([sys.executable, '-B', str(ROOT / 'tools' / 'lattice_digest.py')],
                                 capture_output=True, check=True, env={'PYTHONHASHSEED': seed}).stdout
            self.assertEqual(hashlib.sha256(out).hexdigest(), OUTPUT_SHA256)

    def test_expectations_exact(self):
        r = tool.analyse(bytes(DATA))
        self.assertEqual(tool.expectation_errors(r), [])
        d = r['digest_function']
        self.assertEqual([x['len'] for x in d['hasher_runs']], ['0x800'] * 3)
        self.assertEqual(len(d['unhashed_trailers']), 3)

    def test_independent_all_pass(self):
        rows = iv.check_keys(bytes(DATA))
        self.assertEqual(len(rows), 101)
        self.assertEqual({r[0] for r in rows}, {'PASS'})
        self.assertEqual(iv.check_packet(json.loads((PACKET / 'lattice-digest.json').read_text())), [])

    def test_missing_binary_inconclusive(self):
        self.assertEqual({r[0] for r in iv.check_keys(None)}, {'INCONCLUSIVE'})
        self.assertEqual({r[0] for r in iv.check_keys(b'not the binary')}, {'INCONCLUSIVE'})


@unittest.skipIf(DATA is None, 'node #94 binary not present')
class Tamper(unittest.TestCase):
    def test_every_key_va_flip_fails_independent(self):
        for va, hexs, role in iv.KEYS:
            with self.subTest(va=hex(va), role=role), Patched(va + len(hexs) // 2 - 1) as d:
                rows = {r[1]: r[0] for r in iv.check_keys(d, check_sha=False)}
                self.assertEqual(rows[va], 'FAIL')

    def test_key_va_flips_rejected_by_tool(self):
        # Last byte of each digest/caller/writer key instruction: displacement, immediate or rel32.
        for va, hexs, role in iv.KEYS:
            with self.subTest(va=hex(va), role=role), Patched(va + len(hexs) // 2 - 1) as d:
                self.assertTrue(tool_rejects(d), role)

    def test_semantic_tampers(self):
        cases = [
            (0x37e2700, 0x10, 'lane0 update len 0x800 -> 0x810 (would hash the trailer)'),
            (0x37e2912, 0x30, 'out+0x20 trailer store moved onto a digest field'),
            (0x20c020, 0x00, 'IV word 0'),
            (0x14fa049, 0x04, 'ROOT flag 8 -> 4'),
            (0x14f941c, 0x08, 'chunk size 0x400 -> 0x800'),
            (0x3269a2a, 0x00, 'writer copy length'),
            (0x201e66, ord('L'), 'writer path literal'),
            (0x326b009, 0x00, 'post A frame free size 0x18c8 -> 0x0000'),
            (0x32fc34d, 0x40, 'post B overwrite [rsp+0x20] disp 0x20 -> 0x40'),
        ]
        for va, val, why in cases:
            with self.subTest(why=why), Patched(va, val) as d:
                self.assertTrue(tool_rejects(d), why)

    def test_packet_claim_tamper_rejected(self):
        p = json.loads((PACKET / 'lattice-digest.json').read_text())
        p['digest_function']['output_fields'][2]['value'] = 'lane0 digest[0x20:0x30]'
        self.assertIn('output field map', iv.check_packet(p))
        p = json.loads((PACKET / 'lattice-digest.json').read_text())
        p['digest_function']['hasher_runs'][0]['len'] = '0x810'
        self.assertIn('update lengths', iv.check_packet(p))
        p = json.loads((PACKET / 'lattice-digest.json').read_text())
        p['callers'][1]['digest_before_writer'] = False
        self.assertIn('caller ordering / dataflow', iv.check_packet(p))
        p = json.loads((PACKET / 'lattice-digest.json').read_text())
        p['post_digest']['A']['digest_content_reads'] = 1
        self.assertTrue(any('post_digest A' in e for e in iv.check_packet(p)))
        p = json.loads((PACKET / 'lattice-digest.json').read_text())
        p['post_digest']['B']['claim'] = 'consumed by writer'
        self.assertTrue(any('post_digest B claim' in e for e in iv.check_packet(p)))


if __name__ == '__main__':
    unittest.main()
