"""Verification and adversarial negative controls for RE-002-node115-native-libs-wave3-tls-census."""
import hashlib
import importlib.util
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-002-node115-native-libs-wave3-tls-census'
sys.path.insert(0, str(ROOT / 'tools'))
import byte_progress  # noqa: E402
import verify_packets  # noqa: E402


def _load_census_mod():
    spec = importlib.util.spec_from_file_location('native_libs_wave3_tls_census_115', PACKET / 'census.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class NativeLibsWave3TlsCensus115Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_census_mod()
        cls.census = json.loads((PACKET / 'census.json').read_text())
        cls.bodies = (PACKET / 'bodies.bin').read_bytes()
        cls.licenses = json.loads((PACKET / 'licenses.json').read_text())
        cls.target_blob = (ROOT / cls.mod.TARGET).read_bytes()
        cls.text_sec = next(s for s in byte_progress.sections(cls.target_blob) if s['name'] == '.text')

    def _target_slice(self, rec):
        off = self.text_sec['offset'] + rec['start'] - self.text_sec['address']
        return self.target_blob[off:off + (rec['end'] - rec['start'])]

    def _source_slice(self, rec):
        n = rec['end'] - rec['start']
        return self.bodies[rec['source_offset']:rec['source_offset'] + n]

    def test_packet_verifies_against_node115_and_manifest(self):
        self.mod.verify()
        parsed = verify_packets.parse_manifest(PACKET / 'MANIFEST.sha256')
        self.assertGreaterEqual(len(parsed), 11)
        for digest, rel_path in parsed:
            actual = hashlib.sha256((PACKET / rel_path).read_bytes()).hexdigest()
            self.assertEqual(actual, digest, f'digest mismatch for {rel_path}')

    def test_strict_attribution_licenses_and_tls_relaxation_coverage(self):
        self.assertEqual(set(self.licenses.keys()), set(self.census['lock_packages'].keys()))
        for pkg, lic in self.licenses.items():
            for bad in self.mod.FORBIDDEN_LICENSE_TOKENS:
                self.assertNotIn(bad, lic, f'non-permissive license for {pkg}')

        self.assertEqual(set(self.census['summary'].keys()), {'librocksdb-sys', 'tikv-jemalloc-sys'})
        total_bytes = sum(r['end'] - r['start'] for r in self.census['records'])
        self.assertGreaterEqual(len(self.census['records']), 350)
        self.assertGreaterEqual(total_bytes, 730_000)

        sites = self.census['tls_relaxation_sites']
        self.assertGreater(sites.get('tlsgd-gd-le', 0), 1000)
        self.assertGreater(sites.get('tlsgd-gd-ie', 0), 100)
        self.assertGreater(sites.get('gottpoff-ie-le', 0), 100)

        for rec in self.census['records']:
            self.assertTrue(rec['native'])
            self.assertTrue(rec['fde_backed'])
            self.assertFalse(rec['assembly_object'])
            self.assertEqual(rec['dependency'], 'native-libraries')
            self.assertEqual(rec['component'], 'foundation')
            self.assertTrue(rec['id'].startswith(self.mod.WINDOW_PREFIX))
            self.assertTrue(any(r.get('relaxation') in byte_progress.TLS_RELAXATIONS for r in rec['relocations']))
            n = rec['end'] - rec['start']
            if rec['copy_count'] > 1:
                self.assertGreaterEqual(n, self.mod.MULTI_MIN_BYTES)
                self.assertGreaterEqual(rec['distinct_source_functions'], rec['copy_count'])
            else:
                self.assertGreaterEqual(n, self.mod.MIN_BYTES)

    def test_disjoint_from_byte_windows_and_wave2(self):
        registry = json.loads((ROOT / 'research/byte-windows.json').read_text())
        registered = [w for w in registry['windows'] if w['id'].startswith(self.mod.WINDOW_PREFIX)]
        w2 = json.loads((ROOT / 'research/work-items/RE-002-node115-native-libs-wave2-census/census.json').read_text())
        other = [
            (w['start'], w['end'])
            for w in registry['windows']
            if not w['id'].startswith(self.mod.WINDOW_PREFIX)
        ] + [(r['start'], r['end']) for r in w2['records']]
        other.sort()
        starts = [a for a, _ in other]
        for rec in self.census['records']:
            self.assertFalse(
                self.mod.overlaps_any(other, starts, rec['start'], rec['end']),
                f"overlap at {hex(rec['start'])}",
            )
        if registered:
            components = json.loads((ROOT / 'research/components.json').read_text())['components']
            coverage = byte_progress.load_coverage(ROOT, 'research/byte-windows.json', components)
            rows = [r for r in coverage['windows'] if r['id'].startswith(self.mod.WINDOW_PREFIX)]
            self.assertEqual(len(rows), len(self.census['records']))
            self.assertTrue(all(r['relocation_qualified'] for r in rows))
            self.assertTrue(all(r.get('dependency') == 'native-libraries' for r in rows))
            self.assertTrue(all(r['component'] == 'foundation' for r in rows))

    def test_negative_controls_on_real_tls_records(self):
        # 1. Real RocksDB TLSGD record: unmasked byte flip fails; untagged TLSGD, wrong TLSGD mode, and dropped PLT32 raise.
        tlsgd_rec = next(
            r for r in self.census['records']
            if any(rel.get('relaxation') == 'tlsgd-gd-le' for rel in r['relocations'])
        )
        src = self._source_slice(tlsgd_rec)
        tgt = self._target_slice(tlsgd_rec)
        rels = tlsgd_rec['relocations']
        self.assertTrue(byte_progress.compare(src, tgt, rels)['relocation_qualified'])

        # Flip an unmasked byte
        gd_site = next(rel for rel in rels if rel.get('relaxation') == 'tlsgd-gd-le')
        masked = set()
        for rel in rels:
            masked.update(range(rel['offset'], rel['offset'] + 4))
            if 'relaxation' in rel:
                rb = byte_progress.relaxation_bytes(src, tgt, rel['offset'], rel['kind'], rel['relaxation'])
                masked |= rb
        unmasked_idx = next(i for i in range(len(src)) if i not in masked)
        mut_tgt = bytearray(tgt)
        mut_tgt[unmasked_idx] ^= 0xff
        self.assertFalse(byte_progress.compare(src, bytes(mut_tgt), rels)['relocation_qualified'])

        # Drop relaxation tag on kind 19 -> ValueError
        untagged = [
            ({k: v for k, v in rel.items() if k != 'relaxation'} if rel is gd_site else rel)
            for rel in rels
        ]
        with self.assertRaises(ValueError):
            byte_progress.compare(src, tgt, untagged)

        # Swap tlsgd-gd-le -> tlsgd-gd-ie on real LE bytes -> ValueError
        wrong_mode = [
            ({**rel, 'relaxation': 'tlsgd-gd-ie'} if rel is gd_site else rel)
            for rel in rels
        ]
        with self.assertRaises(ValueError):
            byte_progress.compare(src, tgt, wrong_mode)

        # Drop paired PLT32 at offset + 8 -> ValueError
        no_pair = [rel for rel in rels if not (rel['kind'] == 4 and rel['offset'] == gd_site['offset'] + 8)]
        with self.assertRaises(ValueError):
            byte_progress.compare(src, tgt, no_pair)

        # 2. Real jemalloc GOTTPOFF record: register-mismatch tamper in ModRM raises ValueError.
        ie_rec = next(
            r for r in self.census['records']
            if any(rel.get('relaxation') == 'gottpoff-ie-le' for rel in r['relocations'])
        )
        ie_src = self._source_slice(ie_rec)
        ie_tgt = self._target_slice(ie_rec)
        ie_rels = ie_rec['relocations']
        self.assertTrue(byte_progress.compare(ie_src, ie_tgt, ie_rels)['relocation_qualified'])
        ie_site = next(rel for rel in ie_rels if rel.get('relaxation') == 'gottpoff-ie-le')
        bad_reg_tgt = bytearray(ie_tgt)
        bad_reg_tgt[ie_site['offset'] - 1] ^= 0x01  # mutate destination register bit in ModRM
        with self.assertRaises(ValueError):
            byte_progress.compare(ie_src, bytes(bad_reg_tgt), ie_rels)

    def test_tls_psabi_relaxations_require_exact_register_preserving_rewrite(self):
        # 1) R_X86_64_TLSGD (kind 19) GD->LE and GD->IE with paired PLT32 at offset+8
        gd_src = b'\x90\x66\x48\x8d\x3d\x00\x00\x00\x00\x66\x66\x48\xe8\x00\x00\x00\x00\xc3'
        le_tgt = b'\x90\x64\x48\x8b\x04\x25\x00\x00\x00\x00\x48\x8d\x80\x50\xef\xff\xff\xc3'
        ie_tgt = b'\x90\x64\x48\x8b\x04\x25\x00\x00\x00\x00\x48\x03\x05\xa5\x5f\x47\x00\xc3'
        gd_le_rels = [
            {'offset': 5, 'width': 4, 'kind': 19, 'addend': -4, 'relaxation': 'tlsgd-gd-le'},
            {'offset': 13, 'width': 4, 'kind': 4, 'addend': -4},
        ]
        gd_ie_rels = [
            {'offset': 5, 'width': 4, 'kind': 19, 'addend': -4, 'relaxation': 'tlsgd-gd-ie'},
            {'offset': 13, 'width': 4, 'kind': 4, 'addend': -4},
        ]
        res_le = byte_progress.compare(gd_src, le_tgt, gd_le_rels)
        self.assertTrue(res_le['relocation_qualified'])
        self.assertEqual(res_le['relocation_bytes'], 16)
        res_ie = byte_progress.compare(gd_src, ie_tgt, gd_ie_rels)
        self.assertTrue(res_ie['relocation_qualified'])
        self.assertEqual(res_ie['relocation_bytes'], 16)
        for s, t, rels in (
            (gd_src, le_tgt, [gd_le_rels[0]]),  # missing paired PLT32 at offset+8
            (gd_src, le_tgt, [{'offset': 5, 'width': 4, 'kind': 19, 'addend': -4}, gd_le_rels[1]]),  # untagged
            (gd_src, ie_tgt, gd_le_rels),  # GD->IE bytes tagged as GD->LE
            (gd_src, le_tgt, gd_ie_rels),  # GD->LE bytes tagged as GD->IE
            (gd_src, le_tgt[:11] + b'\x8d\x81' + le_tgt[13:], gd_le_rels),  # wrong target register %rcx
        ):
            with self.subTest(rels=rels), self.assertRaises(ValueError):
                byte_progress.compare(s, t, rels)
        self.assertFalse(byte_progress.compare(gd_src, b'\x91' + le_tgt[1:], gd_le_rels)['relocation_qualified'])

        # 2) R_X86_64_GOTTPOFF (kind 22) IE->LE: mov rax/r11 and add rdi -> lea rdi
        mov_rax_src = b'\x48\x8b\x05\x00\x00\x00\x00\x90'
        mov_rax_tgt = b'\x48\xc7\xc0\xf0\xff\xff\xff\x90'
        mov_r11_src = b'\x4c\x8b\x1d\x00\x00\x00\x00\x90'
        mov_r11_tgt = b'\x49\xc7\xc3\xf0\xff\xff\xff\x90'
        add_rdi_src = b'\x48\x03\x3d\x00\x00\x00\x00\x90'
        lea_rdi_tgt = b'\x48\x8d\xbf\xf0\xff\xff\xff\x90'
        ie_row = {'offset': 3, 'width': 4, 'kind': 22, 'addend': -4, 'relaxation': 'gottpoff-ie-le'}
        for s, t in ((mov_rax_src, mov_rax_tgt), (mov_r11_src, mov_r11_tgt), (add_rdi_src, lea_rdi_tgt)):
            r = byte_progress.compare(s, t, [ie_row])
            self.assertTrue(r['relocation_qualified'])
            self.assertEqual(r['relocation_bytes'], 7)
        for s, t, bad in (
            (mov_rax_src, mov_rax_tgt, {'offset': 3, 'width': 4, 'kind': 22, 'addend': -4}),  # untagged
            (mov_rax_src, b'\x48\xc7\xc1\xf0\xff\xff\xff\x90', ie_row),  # rax -> rcx register mismatch
            (mov_r11_src, b'\x48\xc7\xc3\xf0\xff\xff\xff\x90', ie_row),  # REX.B dropped (r11 -> rbx)
            (mov_rax_src, b'\x48\xc6\xc0\xf0\xff\xff\xff\x90', ie_row),  # invalid opcode 0xc6
            (add_rdi_src, b'\x48\x8d\xb8\xf0\xff\xff\xff\x90', ie_row),  # lea rdi,[rax+disp] register mismatch
            (mov_rax_src, mov_rax_tgt, {**ie_row, 'kind': 42}),          # wrong reloc kind
        ):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                byte_progress.compare(s, t, [bad])


if __name__ == '__main__':
    unittest.main()
