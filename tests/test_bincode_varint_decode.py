"""RE-005 decode-side tests: pinned output, tamper controls, determinism, objdump cross-check."""
import hashlib
import os
from pathlib import Path
import struct
import subprocess
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from gnu_binutils import requires_gnu  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import bincode_varint as bv  # noqa: E402
import bincode_varint_decode as dv  # noqa: E402

PACKET = ROOT / 'research/work-items/RE-005-bincode-varint'
OUTPUT_SHA256 = '6da03736b718d6c7db769a0a1be7e9131a6229cea6b198dd85d535282be5a56f'
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
    return dv.scan(buf, expected_sha256=hashlib.sha256(buf).hexdigest())


class Pinned(unittest.TestCase):
    def test_output_hash(self):
        self.assertEqual(hashlib.sha256(bv.render(dv.scan(data())).encode()).hexdigest(), OUTPUT_SHA256)

    def test_committed_json(self):
        self.assertEqual((PACKET / 'decode-sites.json').read_text(), bv.render(dv.scan(data())))

    def test_exact_values(self):
        r = dv.scan(data())
        self.assertEqual([d['jump_targets_by_tag'] for d in r['decoders']], [
            {'0xfb': '0x466bd76', '0xfc': '0x466bd8e', '0xfd': '0x466bd82', '0xfe': '0x466bdc5'},
            {'0xfb': '0x2558f6d', '0xfc': '0x2558f86', '0xfd': '0x2558f7a', '0xfe': '0x25591a1'}])
        self.assertEqual((len(r['tag_dispatch_sites']), r['tag_dispatch_function_count']), (21, 16))
        self.assertEqual([(p['path'], p['line'], p['column']) for p in r['panic_locations']], [
            ('/home/ubuntu/hl/bincode-fork/src/de/decoder.rs', 93, 13),
            ('/home/ubuntu/hl/bincode-fork/src/de/impls.rs', 499, 20)])

    def test_off_pr8_bridge(self):
        for site in dv.scan(data())['tag_dispatch_sites']:
            self.assertNotIn(site['fde_start'], ('0x3c9a570', '0x58f650'))


class Negative(unittest.TestCase):
    def test_digest(self):
        buf = bytearray(data()); buf[0x100] ^= 1
        with self.assertRaisesRegex(bv.EvidenceError, 'SHA-256'):
            dv.scan(bytes(buf))

    def test_truncated(self):
        with self.assertRaises((bv.EvidenceError, ValueError, IndexError, struct.error)):
            scan_mutated(data()[:len(data()) // 2])

    def test_swapped_tag_threshold(self):
        with self.assertRaisesRegex(bv.EvidenceError, '0x466bd4a'):
            scan_mutated(mutate(0x466bd4a, bytes.fromhex('4881fafc000000')))

    def test_swapped_jump_table_entries(self):
        o = 0x6f6ea8  # .rodata: va == file offset
        e0, e1 = data()[o:o + 4], data()[o + 4:o + 8]
        buf = bytearray(data()); buf[o:o + 8] = e1 + e0
        with self.assertRaisesRegex(bv.EvidenceError, 'jump table'):
            scan_mutated(bytes(buf))

    def test_swapped_load_width(self):
        # make the 0xfb arm load a dword instead of a word
        with self.assertRaisesRegex(bv.EvidenceError, '0x466bd76'):
            scan_mutated(mutate(0x466bd76, bytes.fromhex('8b510190')))

    def test_extra_dispatch_site_rejected(self):
        # turn the encode-side store at 0x27ab0e8 area into a fake dispatch: closure must break
        with self.assertRaisesRegex(bv.EvidenceError, 'dispatch'):
            scan_mutated(mutate(0x27ab0a0, bytes.fromhex('81c005ffffff83f803')))

    def test_identity_baseline(self):
        buf = mutate(0x466bd4a, bytes.fromhex('4881fafb000000'))
        self.assertEqual(bv.render(scan_mutated(buf)), bv.render(dv.scan(data())))


class Determinism(unittest.TestCase):
    def test_hashseed(self):
        outs = {subprocess.run([sys.executable, '-I', '-B', str(ROOT / 'tools/bincode_varint_decode.py')],
                               env=dict(os.environ, PYTHONHASHSEED=s), check=True,
                               capture_output=True).stdout for s in ('0', '7', '4242')}
        self.assertEqual(len(outs), 1)
        self.assertEqual(hashlib.sha256(outs.pop()).hexdigest(), OUTPUT_SHA256)


class Binutils(unittest.TestCase):
    @requires_gnu('objdump', 'readelf')
    def test_fde_readelf(self):
        out = subprocess.run(['readelf', '--debug-dump=frames', str(bv.TARGET)], check=True,
                             capture_output=True, text=True).stdout
        for d in dv.scan(data())['decoders']:
            s, e = int(d['fde_start'], 16), int(d['fde_end'], 16)
            self.assertIn(f'pc={s:016x}..{e:016x}', out)

    @requires_gnu('objdump', 'readelf')
    def test_anchor_objdump(self):
        for d in dv.scan(data())['decoders']:
            for a in d['anchors']:
                va = int(a['va'], 16)
                out = subprocess.run(['objdump', '-d', f'--start-address={va:#x}',
                                      f'--stop-address={va + len(a["bytes"]) // 2:#x}', str(bv.TARGET)],
                                     check=True, capture_output=True, text=True).stdout
                line = [l for l in out.splitlines() if l.strip().startswith(f'{va:x}:')]
                self.assertEqual(len(line), 1, a['va'])
                self.assertEqual(line[0].split('\t')[1].replace(' ', ''), a['bytes'], a['va'])

    def sites(self):
        return [(int(s['va'], 16), int(s['fde_start'], 16)) for s in dv.scan(data())['tag_dispatch_sites']]

    @requires_gnu('objdump', 'readelf')
    def test_dispatch_vas_are_objdump_instruction_starts(self):
        self.assertEqual(boundary_misses(self.sites()), [])

    def test_rex_b_sites_start_at_prefix(self):
        rex = sorted(va for va, _ in self.sites() if data()[bv.va_to_off(bv.sections(data()), va)] == 0x41)
        self.assertEqual([f'{va:#x}' for va in rex], [
            '0x2558fe2', '0x2559079', '0x2561b18', '0x2973ac6', '0x2973bb6',
            '0x466d895', '0x466d9c5', '0x466db15'])

    @requires_gnu('objdump', 'readelf')
    def test_off_by_one_va_rejected(self):
        sites = self.sites()
        for i in (sites.index((0x2558fe2, 0x2558ee0)), sites.index((0x466bd5b, 0x466bd10))):
            shifted = list(sites)
            shifted[i] = (sites[i][0] + 1, sites[i][1])
            self.assertEqual(boundary_misses(shifted), [sites[i][0] + 1])


if __name__ == '__main__':
    unittest.main()
