"""Real capture/metadata/count-operand controls for action structure drift."""
import copy
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import action_field_drift as subject
from elf_index import sections


class ActionFieldDriftTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.spec = subject.specification()
        cls.paths = {r: subject.ROOT / f'artifacts/node/{r}/hl-node' for r in cls.spec}
        if any(not p.is_file() or p.stat().st_size != cls.spec[r]['bytes'] for r, p in cls.paths.items()):
            raise unittest.SkipTest('requires materialized paired release captures')
        cls.data = {r: p.read_bytes() for r, p in cls.paths.items()}
        cls.secs = {r: sections(raw) for r, raw in cls.data.items()}
        cls.report = json.loads((subject.PACKET / 'records.json').read_text())

    def offset(self, release, va):
        s = next(s for s in self.secs[release] if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        return s['offset'] + va - s['address']

    def changed(self, release, va):
        inputs = dict(self.data)
        inputs[release] = bytearray(inputs[release])
        inputs[release][self.offset(release, va)] ^= 1
        return inputs

    def test_retained_bindings_and_complete_native_regeneration(self):
        expected = copy.deepcopy(self.report)
        owners = [o for r in expected['releases'].values() for v in r['variants'].values() for o in v['owners']]
        self.assertEqual(len(owners), 20)
        self.assertEqual(sum(o.pop('decoded_instructions') for o in owners), 9869)
        self.assertEqual(sum(o['bytes'] for o in owners), 48878)
        self.assertEqual(subject.analyze(self.data), expected)
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            subject.generate(self.paths, out)
            for f in out.iterdir():
                self.assertEqual(f.read_bytes(), (subject.PACKET / f.name).read_bytes(), f.name)

    def test_each_named_action_diagnostic_count_is_bound_in_both_releases(self):
        for release, record in self.spec.items():
            for name, row in record['variants'].items():
                va = int(row['diagnostic_va'], 16) + row['text'].index('with ') + len('with ')
                with self.subTest(release=release, name=name):
                    with self.assertRaisesRegex(ValueError, 'diagnostic'):
                        subject.analyze(self.changed(release, va))

    def test_actual_new_field_name_and_count_call_operands(self):
        seen_tables = set()
        for name, row in self.spec['115']['variants'].items():
            for owner in row['owners']:
                c = owner['field_consumers'][0]
                # Actual immediate2 ->3 in each of ten owner functions,
                # not merely a synthetic report or global hash rejection.
                at = int(c['count_site'], 16) + len(bytes.fromhex(c['count_hex'])) - 4
                with self.subTest(name=name, owner=owner['start']):
                    with self.assertRaisesRegex(ValueError, 'instruction'):
                        subject.analyze(self.changed('115', at))
                if c['table'] in seen_tables:
                    continue
                seen_tables.add(c['table'])
                for entry in c['entries']:
                    with self.assertRaisesRegex(ValueError, 'field name'):
                        subject.analyze(self.changed('115', int(entry['string_va'], 16)))
                with self.assertRaisesRegex(ValueError, 'instruction'):
                    subject.analyze(self.changed('115', int(c['call_site'], 16) + 1))
        self.assertEqual(len(seen_tables), 4)

    def test_actual_field_relocations_leas_and_fde_extents(self):
        for release in ['94', '115']:
            row = self.spec[release]['variants']['CancelAction']
            sec = next(s for s in self.secs[release] if s['name'] == '.rela.dyn')
            offsets = {struct.unpack_from('<Q', self.data[release], p)[0]: p
                       for p in range(sec['offset'], sec['offset'] + sec['size'], 24)}
            slots = [int(row['slot'], 16)]
            if release == '115':
                slots += [int(e['slot'], 16) for e in row['owners'][0]['field_consumers'][0]['entries']]
            for slot in slots:
                inputs = dict(self.data)
                inputs[release] = bytearray(inputs[release])
                inputs[release][offsets[slot] + 16] ^= 1
                with self.assertRaisesRegex(ValueError, 'relocation'):
                    subject.analyze(inputs)
            for owner in row['owners']:
                with self.assertRaisesRegex(ValueError, 'LEA'):
                    subject.analyze(self.changed(release, int(owner['diagnostic_lea'], 16) + 3))
            owner = self.report['releases'][release]['variants']['CancelAction']['owners'][0]
            with self.assertRaisesRegex(ValueError, 'FDE'):
                subject.analyze(self.changed(release, int(owner['frame_records']['fde']['va'], 16) + 12))

    def test_public_identity_gate_precedes_output_for_wrong_and_changed_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            out = root / 'out'
            with self.assertRaisesRegex(ValueError, 'pinned node94'):
                subject.generate({'94': self.paths['115'], '115': self.paths['94']}, out)
            changed = root / 'changed'
            va = int(self.spec['115']['variants']['CancelAction']['diagnostic_va'], 16)
            changed.write_bytes(self.changed('115', va)['115'])
            with self.assertRaisesRegex(ValueError, 'pinned node115'):
                subject.generate({'94': self.paths['94'], '115': changed}, out)
            changed.write_bytes(b'not an ELF')
            with self.assertRaisesRegex(ValueError, 'pinned node115'):
                subject.generate({'94': self.paths['94'], '115': changed}, out)
            self.assertFalse(out.exists())
