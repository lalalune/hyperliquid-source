"""Verification and adversarial negative controls for RE-002-node115-rust-vendor-wave5-census."""
import copy
import hashlib
import importlib.util
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-002-node115-rust-vendor-wave5-census'
sys.path.insert(0, str(ROOT / 'tools'))
import byte_progress  # noqa: E402
import verify_packets  # noqa: E402


def _load():
    spec = importlib.util.spec_from_file_location('rust_vendor_wave5_census_115', PACKET / 'census.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class RustVendorWave5Census115Tests(unittest.TestCase):
    def setUp(self):
        self.mod = _load()
        self.census = json.loads((PACKET / 'census.json').read_text())
        self.licenses = json.loads((PACKET / 'licenses.json').read_text())
        self.components = json.loads((ROOT / 'research/components.json').read_text())['components']

    def test_packet_verifies_and_manifest_sha256(self):
        self.mod.verify()
        entries = verify_packets.parse_manifest(PACKET / 'MANIFEST.sha256')
        self.assertGreaterEqual(len(entries), 23)
        for digest, rel in entries:
            path = PACKET / rel
            self.assertTrue(path.is_file(), f'missing manifest file {rel}')
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest, rel)

    def test_summary_attribution_and_permissive_licenses(self):
        sm = self.census['summary']
        self.assertEqual(sm['total_windows'], 292)
        self.assertEqual(sm['total_bytes'], 308000)
        self.assertEqual(sm['tls_relaxed_windows'], 14)
        self.assertEqual(sm['tls_relaxed_bytes'], 7832)
        self.assertEqual(sm['tls_relaxation_sites'], 19)
        self.assertEqual(sm['crates_matched'], 23)
        self.assertEqual(set(self.census['lock_packages']), set(self.licenses))
        for pkg, lic in self.licenses.items():
            self.assertTrue(self.mod.is_permissive_license(lic), f'non-permissive license {pkg}: {lic}')
        for rec in self.census['records']:
            self.assertFalse(rec['native'])
            self.assertIn(rec['dependency'], self.mod.ALLOWED_DEPS)

    def test_disjoint_from_registry_and_siblings_or_registered(self):
        bw = json.loads((ROOT / 'research/byte-windows.json').read_text())
        other = [
            (w['start'], w['end'])
            for w in bw['windows']
            if w['target'] == 'node115' and not w['id'].startswith(self.mod.WINDOW_PREFIX)
        ]
        other.extend(self.mod.collect_peer_intervals())
        merged, starts = self.mod._build_merged(other)
        for rec in self.census['records']:
            self.assertFalse(
                self.mod._overlaps(merged, starts, rec['start'], rec['end']),
                f"overlap at {hex(rec['start'])}",
            )
        reg_rows = [w for w in bw['windows'] if w['id'].startswith(self.mod.WINDOW_PREFIX)]
        if reg_rows:
            cov = byte_progress.load_coverage(ROOT, 'research/byte-windows.json', self.components)
            rows = [r for r in cov['windows'] if r['id'].startswith(self.mod.WINDOW_PREFIX)]
            self.assertEqual((len(rows), sum(r['bytes'] for r in rows)), (292, 308000))
            self.assertTrue(all('dependency' in r for r in rows))
            self.assertTrue(all(r['relocation_qualified'] for r in rows))

    def test_negative_controls_symbol_and_license_gates(self):
        self.assertIsNone(self.mod.extract_defining_crate_ident('_ZN4core3ptr13drop_in_place17h0000000000000000E'))
        self.assertIsNone(self.mod.extract_defining_crate_ident('_ZN23w5_cli_chrono_rayon_rdb4main17h0000000000000000E'))
        self.assertIsNone(self.mod.extract_defining_crate_ident('_ZN20w5_alloc_collections4main17h0000000000000000E'))
        self.assertIsNone(self.mod.extract_defining_crate_ident('_RNvCs1234_7___rustc18___rust_start_panic'))
        self.assertFalse(self.mod.is_permissive_license('GPL-3.0-only'))
        self.assertFalse(self.mod.is_permissive_license('AGPL-3.0-or-later'))
        self.assertFalse(self.mod.is_permissive_license('LGPL-2.1'))

    def test_negative_controls_unmasked_mutation_and_tls_relaxation_tamper(self):
        bodies = (PACKET / 'bodies.bin').read_bytes()
        data = (ROOT / self.mod.TARGET).read_bytes()
        text = next(s for s in self.mod.sections(data) if s['name'] == '.text')

        def target_slice(rec):
            off = text['offset'] + rec['start'] - text['address']
            return data[off:off + (rec['end'] - rec['start'])]

        # 1. Unmasked byte flip on the 23 KB clap FDE fails relocation_qualified
        plain = max((r for r in self.census['records'] if not r['tls_relaxed']), key=lambda r: r['end'] - r['start'])
        n = plain['end'] - plain['start']
        src = bodies[plain['source_offset']:plain['source_offset'] + n]
        tgt = target_slice(plain)
        masked = set()
        for rel in plain['relocations']:
            masked.update(range(rel['offset'], rel['offset'] + rel['width']))
        idx = next(k for k in range(n) if k not in masked)
        mut = bytearray(tgt)
        mut[idx] ^= 0xff
        self.assertFalse(byte_progress.compare(src, bytes(mut), plain['relocations'])['relocation_qualified'])

        # 2. GOTTPOFF (kind 22) tampering: missing relaxation, wrong mode, or wrong register must raise ValueError
        got_rec = next(
            r for r in self.census['records']
            if any(rel.get('relaxation') == 'gottpoff-ie-le' for rel in r['relocations'])
        )
        gn = got_rec['end'] - got_rec['start']
        gsrc = bodies[got_rec['source_offset']:got_rec['source_offset'] + gn]
        gtgt = target_slice(got_rec)
        self.assertTrue(byte_progress.compare(gsrc, gtgt, got_rec['relocations'])['relocation_qualified'])

        no_rel = copy.deepcopy(got_rec['relocations'])
        g_idx = next(i for i, rel in enumerate(no_rel) if rel.get('relaxation') == 'gottpoff-ie-le')
        del no_rel[g_idx]['relaxation']
        with self.assertRaises(ValueError):
            byte_progress.compare(gsrc, gtgt, no_rel)

        wrong_mode = copy.deepcopy(got_rec['relocations'])
        wrong_mode[g_idx]['relaxation'] = 'tlsgd-gd-le'
        with self.assertRaises(ValueError):
            byte_progress.compare(gsrc, gtgt, wrong_mode)

        bad_reg = bytearray(gtgt)
        goff = got_rec['relocations'][g_idx]['offset']
        bad_reg[goff - 1] ^= 0x01
        with self.assertRaises(ValueError):
            byte_progress.compare(gsrc, bytes(bad_reg), got_rec['relocations'])


if __name__ == '__main__':
    unittest.main()
