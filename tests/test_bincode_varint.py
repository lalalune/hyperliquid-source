"""RE-005 tests: pinned output, tamper/mutation controls, determinism, toolchain cross-check."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import bincode_varint as bv  # noqa: E402

PACKET = ROOT / 'research/work-items/RE-005-bincode-varint'
OUTPUT_SHA256 = '7e7a06b035c5b223cfa4573b9f315e344db2207c88c967e8079b88a0093a7657'
_DATA = None


def data():
    global _DATA
    if _DATA is None:
        _DATA = bv.TARGET.read_bytes()
    return _DATA


def mutate(va, new):
    buf = bytearray(data())
    o = bv.va_to_off(bv.sections(data()), va)
    buf[o:o + len(new)] = new
    return bytes(buf)


def boundary_misses(sites):
    """Return each (va, func_start) whose va is not an instruction start in objdump's linear sweep."""
    misses = []
    for va, start in sites:
        out = subprocess.run(['objdump', '-d', '--no-show-raw-insn', f'--start-address={start:#x}',
                              f'--stop-address={va + 16:#x}', str(bv.TARGET)],
                             check=True, capture_output=True, text=True).stdout
        if not any(l.strip().startswith(f'{va:x}:') for l in out.splitlines()):
            misses.append(va)
    return misses


def scan_mutated(buf):
    return bv.scan(buf, expected_sha256=hashlib.sha256(buf).hexdigest())


class PinnedOutput(unittest.TestCase):
    def test_output_hash_is_pinned(self):
        self.assertEqual(hashlib.sha256(bv.render(bv.scan(data())).encode()).hexdigest(), OUTPUT_SHA256)

    def test_committed_json_matches_recomputation(self):
        self.assertEqual((PACKET / 'varint-sites.json').read_text(), bv.render(bv.scan(data())))

    def test_exact_counts(self):
        r = bv.scan(data())
        self.assertEqual([f['name'] for f in r['functions']], [
            'varint_encode_u32_vec', 'varint_size_u32', 'varint_encode_u64_vec', 'varint_size_u64',
            'varint_encode_u32_le_ptr', 'varint_encode_u64_vec_b', 'varint_size_u64_b'])
        self.assertEqual([f['direct_calls'] for f in r['functions']], [3, 2, 25, 25, 75, 86, 87])
        self.assertEqual({k: len(v) for k, v in r['text_idiom_sites'].items()}, {
            'cmp_r32_0xfb_then_cmp_0x10000': 3, 'cmp_r64_0xfb_then_cmp_0x10000': 4,
            'store_marker_0xfd_imm8': 2})
        self.assertEqual(r['fde_count'], 121299)
        self.assertEqual([(p['location'], p['path'], p['line'], p['column']) for p in r['panic_locations']], [
            ('0x56c2e78', '/home/ubuntu/hl/bincode-fork/src/enc/write.rs', 78, 9),
            ('0x56c2e78', '/home/ubuntu/hl/bincode-fork/src/enc/write.rs', 78, 9),
            ('0x5737ce8', '/home/ubuntu/hl/bincode-fork/src/enc/write.rs', 78, 9)])

    def test_stays_off_pr8_bridge_encoder(self):
        for f in bv.scan(data())['functions']:
            lo, hi = int(f['fde_start'], 16), int(f['fde_end'], 16)
            for bridge in (0x3c9a570, 0x58f650):
                self.assertFalse(lo <= bridge < hi)


class NegativeControls(unittest.TestCase):
    def test_corrupted_digest_rejected(self):
        buf = bytearray(data()); buf[-1] ^= 1
        with self.assertRaisesRegex(bv.EvidenceError, 'SHA-256'):
            bv.scan(bytes(buf))

    def test_truncated_input_rejected(self):
        with self.assertRaises((bv.EvidenceError, ValueError, struct_error())):
            bv.scan(data()[:len(data()) // 2])
        buf = data()[:len(data()) // 2]
        with self.assertRaises((bv.EvidenceError, ValueError, IndexError, struct_error())):
            scan_mutated(buf)

    def test_node_115_rejected(self):
        p = ROOT / 'artifacts/node/115/hl-node'
        with self.assertRaisesRegex(bv.EvidenceError, 'SHA-256'):
            bv.scan(p.read_bytes())

    def test_swapped_marker_immediates_rejected(self):
        # 0xfb <-> 0xfc marker stores in the u64 encoder.
        buf = mutate(0x27ab34b, bytes.fromhex('42c6040ffc'))
        with self.assertRaisesRegex(bv.EvidenceError, '0x27ab34b'):
            scan_mutated(buf)

    def test_swapped_threshold_immediate_rejected(self):
        buf = mutate(0x27ab0aa, bytes.fromhex('81f9fc000000'))
        with self.assertRaisesRegex(bv.EvidenceError, '0x27ab0aa'):
            scan_mutated(buf)

    def test_untampered_mutation_baseline_passes(self):
        buf = mutate(0x27ab0aa, bytes.fromhex('81f9fb000000'))  # identical bytes
        self.assertEqual(bv.render(scan_mutated(buf)), bv.render(bv.scan(data())))

    def test_wrong_fde_rejected(self):
        orig = bv.FUNCTIONS
        try:
            name, s, e, a, c = orig[0]
            bv.FUNCTIONS = ((name, s, e + 4, a, c),) + orig[1:]
            with self.assertRaisesRegex(bv.EvidenceError, 'FDE extent'):
                bv.scan(data())
        finally:
            bv.FUNCTIONS = orig

    def test_wrong_call_count_rejected(self):
        orig = bv.FUNCTIONS
        try:
            name, s, e, a, c = orig[1]
            bv.FUNCTIONS = (orig[0], (name, s, e, a, c + 1)) + orig[2:]
            with self.assertRaisesRegex(bv.EvidenceError, 'direct calls'):
                bv.scan(data())
        finally:
            bv.FUNCTIONS = orig

    def test_idiom_outside_pinned_functions_rejected(self):
        orig = bv.FUNCTIONS
        try:
            bv.FUNCTIONS = orig[:4]
            with self.assertRaisesRegex(bv.EvidenceError, 'outside every pinned function'):
                bv.scan(data())
        finally:
            bv.FUNCTIONS = orig


def struct_error():
    import struct
    return struct.error


class Determinism(unittest.TestCase):
    def test_hashseed_independent(self):
        outs = set()
        for seed in ('0', '1', '4242'):
            env = dict(os.environ, PYTHONHASHSEED=seed)
            outs.add(subprocess.run([sys.executable, '-I', '-B', str(ROOT / 'tools/bincode_varint.py')],
                                    env=env, check=True, capture_output=True).stdout)
        self.assertEqual(len(outs), 1)
        self.assertEqual(hashlib.sha256(outs.pop()).hexdigest(), OUTPUT_SHA256)


@unittest.skipUnless(shutil.which('readelf') and shutil.which('objdump'), 'binutils required')
class BinutilsCrossCheck(unittest.TestCase):
    def test_fde_extents_match_readelf(self):
        r = bv.scan(data())
        out = subprocess.run(['readelf', '--debug-dump=frames', str(bv.TARGET)], check=True,
                             capture_output=True, text=True).stdout
        for f in r['functions']:
            s, e = int(f['fde_start'], 16), int(f['fde_end'], 16)
            self.assertIn(f'pc={s:016x}..{e:016x}', out, f['name'])

    def test_anchor_bytes_match_objdump(self):
        for f in bv.scan(data())['functions']:
            for a in f['anchors']:
                va = int(a['va'], 16)
                n = len(a['bytes']) // 2
                out = subprocess.run(['objdump', '-d', f'--start-address={va:#x}',
                                      f'--stop-address={va + n:#x}', str(bv.TARGET)],
                                     check=True, capture_output=True, text=True).stdout
                line = [l for l in out.splitlines() if l.strip().startswith(f'{va:x}:')]
                self.assertEqual(len(line), 1, a['va'])
                self.assertEqual(line[0].split('\t')[1].replace(' ', ''), a['bytes'], a['va'])

    def idiom_sites(self):
        starts = sorted(bv.fde_extents(data(), bv.sections(data())))
        out = []
        for vas in bv.scan(data())['text_idiom_sites'].values():
            for v in vas:
                va = int(v, 16)
                out.append((va, max(s for s in starts if s <= va)))
        return out

    def test_idiom_vas_are_objdump_instruction_starts(self):
        self.assertEqual(boundary_misses(self.idiom_sites()), [])

    def test_off_by_one_idiom_va_rejected(self):
        sites = self.idiom_sites()
        i = [va for va, _ in sites].index(0x27ab30b)
        shifted = list(sites)
        shifted[i] = (sites[i][0] + 1, sites[i][1])
        self.assertEqual(boundary_misses(shifted), [0x27ab30c])



class SectionHeaderTests(unittest.TestCase):
    def test_sections_rejects_shstrndx_out_of_range(self):
        data = bytearray(128)
        data[:6] = b'\x7fELF\x02\x01'
        data[40:48] = (64).to_bytes(8, 'little')
        data[58:60] = (64).to_bytes(2, 'little')
        data[60:62] = (1).to_bytes(2, 'little')
        data[62:64] = (3).to_bytes(2, 'little')
        with self.assertRaises(bv.EvidenceError):
            bv.sections(bytes(data))


if __name__ == '__main__':
    unittest.main()
