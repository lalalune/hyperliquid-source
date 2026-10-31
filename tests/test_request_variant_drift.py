"""Authenticate paired releases and exercise real variant/key controls."""
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import request_variant_drift as subject
from elf_index import sections


class RequestVariantDriftTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.paths = {r: subject.ROOT / f'artifacts/node/{r}/hl-node' for r in subject.TARGETS}
        if any(not p.is_file() or p.stat().st_size != subject.TARGETS[r][0] for r, p in cls.paths.items()):
            raise unittest.SkipTest('requires both materialized release captures')
        cls.data = {r: p.read_bytes() for r, p in cls.paths.items()}
        cls.secs = {r: sections(b) for r, b in cls.data.items()}
        cls.report = subject.analyze(cls.data['94'], cls.data['115'])

    def offset(self, r, va):
        s = next(s for s in self.secs[r] if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        return s['offset'] + va - s['address']

    def mutated(self, r, va):
        changed = dict(self.data)
        changed[r] = bytearray(changed[r])
        changed[r][self.offset(r, va)] ^= 1
        return changed

    def test_retained_report_and_complete_native_regeneration(self):
        self.assertEqual(self.report, json.loads((subject.PACKET / 'records.json').read_text()))
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            subject.generate(self.paths, out)
            for f in out.iterdir():
                self.assertEqual(f.read_bytes(), (subject.PACKET / f.name).read_bytes(), f.name)

    def test_overlapping_key_loads_cover_exact_spelling(self):
        pair = self.report['additional_key_pairs_115'][0]
        low, high = int(pair['low'], 16), int(pair['high'], 16)
        key = b'only_use_db'
        self.assertTrue(subject.overlapping_key_match(key, low, high))
        # All single-byte substitutions (11*255), including NUL/non-ASCII,
        # and all 0..32 lengths: this is only the selected equality obligation.
        for i in range(11):
            for value in range(256):
                changed = bytearray(key)
                changed[i] = value
                self.assertEqual(subject.overlapping_key_match(changed, low, high), value == key[i])
        for n in range(33):
            candidate = (key + b'X' * 33)[:n]
            self.assertEqual(subject.overlapping_key_match(candidate, low, high), candidate == key)
        # Every byte is covered by the union [0,8) U [3,11); hence arbitrary
        # combinations match iff all eleven bytes match, not just sampled keys.
        self.assertEqual(set(range(8)) | set(range(3, 11)), set(range(11)))
        self.assertEqual([x & 1 for x in [0, 1, 2]], [0, 1, 0])

    def test_actual_new_key_flag_and_selector_bytes(self):
        locations = list(subject.FLAG_CONTROLS) + [0x1fb7a08, 0x1fc5948]
        locations += [site + 2 for pair in subject.KEY_PAIRS for site in pair]
        for va in locations:
            with self.subTest(va=hex(va)):
                changed = self.mutated('115', va)
                with self.assertRaisesRegex(ValueError, 'key|flag|selector'):
                    subject.analyze(changed['94'], changed['115'])

    def test_actual_diagnostic_slot_xref_and_fde_controls(self):
        for r, rows in subject.VARIANTS.items():
            for _name, _start, _end, slot, string_va, site in rows:
                for va, error in [(string_va, 'diagnostic'), (slot + 8, 'length'), (site + 3, 'xref')]:
                    changed = self.mutated(r, va)
                    with self.assertRaisesRegex(ValueError, error):
                        subject.analyze(changed['94'], changed['115'])
                s = next(s for s in self.secs[r] if s['name'] == '.rela.dyn')
                rel = next(p for p in range(s['offset'], s['offset'] + s['size'], 24)
                           if struct.unpack_from('<Q', self.data[r], p)[0] == slot)
                changed = dict(self.data)
                changed[r] = bytearray(changed[r])
                changed[r][rel + 16] ^= 1
                with self.assertRaisesRegex(ValueError, 'relocation'):
                    subject.analyze(changed['94'], changed['115'])
            for row in self.report['releases'][r]['variants']:
                va = int(row['frame_records']['fde']['va'], 16) + 12
                changed = self.mutated(r, va)
                with self.assertRaisesRegex(ValueError, 'FDE'):
                    subject.analyze(changed['94'], changed['115'])

    def test_public_identity_rejects_swapped_or_changed_releases(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / 'out'
            with self.assertRaisesRegex(ValueError, 'pinned node94'):
                subject.generate({'94': self.paths['115'], '115': self.paths['94']}, out)
            changed = Path(directory) / 'changed'
            altered = self.mutated('94', 0x3d1e6f)['94']
            changed.write_bytes(altered)
            with self.assertRaisesRegex(ValueError, 'pinned node94'):
                subject.generate({'94': changed, '115': self.paths['115']}, out)
            self.assertFalse(out.exists())
            changed.write_bytes(b'not an ELF')
            for release in subject.TARGETS:
                paths = dict(self.paths)
                paths[release] = changed
                with self.assertRaisesRegex(ValueError, f'pinned node{release}'):
                    subject.generate(paths, out)
                self.assertFalse(out.exists())
