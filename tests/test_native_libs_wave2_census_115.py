"""Verification and adversarial negative controls for RE-002-node115-native-libs-wave2-census."""
import hashlib
import importlib.util
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-002-node115-native-libs-wave2-census'
sys.path.insert(0, str(ROOT / 'tools'))
import byte_progress  # noqa: E402
import verify_packets  # noqa: E402


def _load_census_mod():
    spec = importlib.util.spec_from_file_location('native_libs_wave2_census_115', PACKET / 'census.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class NativeLibsWave2Census115Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_census_mod()
        cls.census = json.loads((PACKET / 'census.json').read_text())
        cls.bodies = (PACKET / 'bodies.bin').read_bytes()
        cls.licenses = json.loads((PACKET / 'licenses.json').read_text())

    def test_packet_verifies_against_node115_and_manifest(self):
        self.mod.verify()
        manifest_path = PACKET / 'MANIFEST.sha256'
        parsed = verify_packets.parse_manifest(manifest_path)
        self.assertGreaterEqual(len(parsed), 30)
        for digest, rel_path in parsed:
            actual = hashlib.sha256((PACKET / rel_path).read_bytes()).hexdigest()
            self.assertEqual(actual, digest, f'digest mismatch for {rel_path}')

    def test_strict_attribution_permissive_licenses_and_expected_crates(self):
        self.assertEqual(set(self.licenses.keys()), set(self.census['lock_packages'].keys()))
        for pkg, lic in self.licenses.items():
            for bad in self.mod.FORBIDDEN_LICENSE_TOKENS:
                self.assertNotIn(bad, lic, f'non-permissive license for {pkg}')

        expected_crates = {
            'tikv-jemalloc-sys',
            'zstd-sys',
            'librocksdb-sys',
            'lz4-sys',
            'blake3',
            'blst',
            'secp256k1-sys',
            'sha3-asm',
        }
        self.assertEqual(set(self.census['summary'].keys()), expected_crates)

        total_bytes = sum(r['end'] - r['start'] for r in self.census['records'])
        self.assertGreaterEqual(len(self.census['records']), 1700)
        self.assertGreaterEqual(total_bytes, 1_250_000)

        asm_records = [r for r in self.census['records'] if r['assembly_object']]
        self.assertEqual(len(asm_records), 11)
        self.assertEqual(sum(r['end'] - r['start'] for r in asm_records), 60507)
        for rec in asm_records:
            self.assertEqual(rec['crate'], 'blake3')
            self.assertFalse(rec['fde_backed'])
            self.assertTrue(all(rel['kind'] == 2 for rel in rec['relocations']))

        for rec in self.census['records']:
            self.assertTrue(rec['native'])
            self.assertEqual(rec['dependency'], 'native-libraries')
            self.assertEqual(rec['component'], 'foundation')
            self.assertTrue(rec['id'].startswith(self.mod.WINDOW_PREFIX))
            n = rec['end'] - rec['start']
            if rec['copy_count'] > 1:
                self.assertGreaterEqual(n, self.mod.MULTI_MIN_BYTES)
                self.assertGreaterEqual(rec['distinct_source_functions'], rec['copy_count'])
            else:
                self.assertGreaterEqual(n, self.mod.MIN_BYTES)

    def test_byte_windows_registration_or_disjointness(self):
        registry = json.loads((ROOT / 'research/byte-windows.json').read_text())
        registered = [w for w in registry['windows'] if w['id'].startswith(self.mod.WINDOW_PREFIX)]
        other = [(w['start'], w['end']) for w in registry['windows'] if not w['id'].startswith(self.mod.WINDOW_PREFIX)]
        other.sort()
        starts = [a for a, _ in other]
        for rec in self.census['records']:
            self.assertFalse(
                self.mod.overlaps_any(other, starts, rec['start'], rec['end']),
                f"overlap with byte-windows.json at {hex(rec['start'])}",
            )
        if registered:
            components = json.loads((ROOT / 'research/components.json').read_text())['components']
            coverage = byte_progress.load_coverage(ROOT, 'research/byte-windows.json', components)
            rows = [r for r in coverage['windows'] if r['id'].startswith(self.mod.WINDOW_PREFIX)]
            self.assertEqual(len(rows), len(self.census['records']))
            self.assertTrue(all(r['relocation_qualified'] for r in rows))
            self.assertTrue(all(r.get('dependency') == 'native-libraries' for r in rows))
            self.assertTrue(all(r['component'] == 'foundation' for r in rows))

    def test_negative_controls_reject_mutation_relaxation_tls_and_overlap(self):
        # 1. Unmasked byte flip breaks qualification.
        rec0 = self.census['records'][0]
        n0 = rec0['end'] - rec0['start']
        src0 = self.bodies[rec0['source_offset']:rec0['source_offset'] + n0]
        masked = set()
        for rel in rec0['relocations']:
            masked.update(range(rel['offset'], rel['offset'] + rel['width']))
            if 'relaxation' in rel:
                masked.update(range(rel['offset'] - 2, rel['offset']))
        unmasked_idx = next(i for i in range(n0) if i not in masked)
        mutated = bytearray(src0)
        mutated[unmasked_idx] ^= 0xff
        res = byte_progress.compare(bytes(mutated), src0, [
            {k: v for k, v in r.items() if k != 'relaxation'} for r in rec0['relocations']
        ])
        self.assertFalse(res['relocation_qualified'])

        # 2. Corrupting a psABI GOTPCRELX relaxed opcode byte raises ValueError in byte_progress.compare.
        relaxed_rec = next(
            r for r in self.census['records']
            if any(rel.get('relaxation') == 'gotpcrelx-mov-lea' for rel in r['relocations'])
        )
        rn = relaxed_rec['end'] - relaxed_rec['start']
        rsrc = self.bodies[relaxed_rec['source_offset']:relaxed_rec['source_offset'] + rn]
        rel_site = next(rel for rel in relaxed_rec['relocations'] if rel.get('relaxation') == 'gotpcrelx-mov-lea')
        bad_tgt = bytearray(rsrc)
        bad_tgt[rel_site['offset'] - 2] = 0x8e  # invalid relaxation opcode (must be 0x8d)
        with self.assertRaises(ValueError):
            byte_progress.compare(rsrc, bytes(bad_tgt), [rel_site])

        # 3. Unsupported TLS relocation kinds (R_X86_64_TLSGD=19, R_X86_64_GOTTPOFF=22) are rejected.
        for tls_kind in (19, 22):
            with self.assertRaises(ValueError):
                byte_progress.compare(
                    src0,
                    src0,
                    [{'offset': 4, 'width': 4, 'kind': tls_kind, 'addend': -4}],
                )

        # 4. Overlap detector catches exact and partial overlaps and allows strictly adjacent spans.
        merged = [(0x63493c0, 0x6349400), (0x6349500, 0x6349600)]
        starts = [a for a, _ in merged]
        self.assertTrue(self.mod.overlaps_any(merged, starts, 0x63493c0, 0x6349400))
        self.assertTrue(self.mod.overlaps_any(merged, starts, 0x63493f0, 0x6349420))
        self.assertTrue(self.mod.overlaps_any(merged, starts, 0x63494e0, 0x6349510))
        self.assertFalse(self.mod.overlaps_any(merged, starts, 0x6349400, 0x6349500))


if __name__ == '__main__':
    unittest.main()
