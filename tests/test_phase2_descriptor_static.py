"""Native target evidence and phase-2 counterfactuals."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import phase2_descriptor_static as subject
from elf_index import sections


class Phase2DescriptorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not subject.TARGET.is_file() or subject.TARGET.stat().st_size != 105896032:
            raise unittest.SkipTest('materialized node115 required')
        cls.data = subject.TARGET.read_bytes()
        if hashlib.sha256(cls.data).hexdigest() != subject.SHA:
            raise ValueError('wrong node115 capture')
        cls.secs = sections(cls.data)
        cls.report = subject.analyze(cls.data)

    def offset(self, va):
        s = next(s for s in self.secs
                 if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        return s['offset'] + va - s['address']

    def mutate(self, va, value=None):
        b = bytearray(self.data)
        o = self.offset(va)
        b[o] = b[o] ^ 1 if value is None else value
        return b

    def test_analysis_shape(self):
        owners = {row['role'] for row in self.report['owners']}
        self.assertEqual(owners, {'large_consumer',
                                  'descriptor_stream_collect',
                                  'descriptor_record_bind'})
        self.assertEqual(self.report['target_sha256'], subject.SHA)
        self.assertEqual(
            self.report['slot_bindings']['descriptor_bind'],
            {'slot': '0x64e1458', 'type': 8,
             'type_name': 'R_X86_64_RELATIVE', 'addend': '0x47473c0'})
        self.assertEqual(
            self.report['slot_bindings']['isatty']['symbol'], 'isatty')
        self.assertEqual(
            self.report['phase2']['direct_calls']
            ['descriptor_stream_collect']['sites'],
            ['0x15a4626', '0x15a487d', '0x473a03b'])
        self.assertEqual(
            self.report['phase2']['direct_calls']
            ['descriptor_record_bind']['sites'], [])
        self.assertEqual(
            self.report['phase2']['direct_calls']
            ['descriptor_map_insert']['sites'], ['0x15a4ab4'])

    def test_branch_identity(self):
        identity = self.report['phase2']['consumer']['branch_identity']
        self.assertEqual(len(identity), 2)
        first, second = identity
        self.assertEqual(first['bytes'], 66)
        self.assertEqual(first['lea_targets_a'],
                         ['0x468adf', '0x468b0f'])
        self.assertEqual(first['lea_targets_a'], first['lea_targets_b'])
        self.assertEqual(first['call_target_a'], '0x474d890')
        self.assertEqual(first['call_target_a'], first['call_target_b'])
        self.assertEqual(second['bytes'], 130)
        self.assertEqual(second['string_load_targets'],
                         ['0x468aff', '0x468aef', '0x468adf'])
        record = self.report['phase2']['consumer']['descriptor_record']
        self.assertEqual(record['written_fields']['0x30'], '0x110001')
        self.assertEqual(record['unwritten_offset'], '0x28')
        self.assertEqual(record['format_string']['bytes'], 48)

    def test_models(self):
        self.assertEqual(subject.branch_for(subject.SENTINEL),
                         'sentinel_bind')
        self.assertEqual(subject.branch_for(subject.SENTINEL - 1),
                         'present_format')
        self.assertEqual(subject.branch_for(0), 'present_format')
        self.assertEqual(subject.collect_model(),
                         {'element_bytes': 0x58, 'initial_capacity': 4,
                          'initial_allocation': 0x160, 'terminal_tag': 5,
                          'empty_header': (0, 8, 0)})
        self.assertEqual(subject.collect_header(4, 0x1000, 3),
                         (4, 0x1000, 3))
        self.assertEqual(
            subject.second_record_fields((7, 0x2000, 5), 0x3000),
            (7, 0x2000, 5, 0x30, 0x3000, 0x30))
        self.assertEqual(subject.bind_path(1), 'slot_object')
        self.assertEqual(subject.bind_path(0), 'global_table')
        self.assertEqual(subject.bind_path(2), 'global_table')
        out = subject.bind_consumer_call_output(0xdead)
        self.assertEqual(out['word_0x10'], subject.BIND_TABLE_OBJECT)
        self.assertEqual(out['word_0x18'], 0xdead)
        self.assertEqual(out['word_0x20'], subject.RECORD_TAG_WORD)
        self.assertEqual(out['byte_0x28'], 1)
        self.assertEqual(subject.second_structure_payload('sentinel_bind'),
                         {'bytes': 0x30, 'tag': subject.PAYLOAD_TAG_SENTINEL})
        self.assertEqual(subject.second_structure_payload('present_format'),
                         {'bytes': 0x70, 'tag': subject.PAYLOAD_TAG_PRESENT})
        with self.assertRaises(ValueError):
            subject.second_structure_payload('other')

    def test_counterfactual_probe_compare(self):
        with self.assertRaisesRegex(ValueError, 'probe_compare pin changed'):
            subject.analyze(bytes(self.mutate(0x15a45e0)))

    def test_counterfactual_collect_tag(self):
        with self.assertRaisesRegex(ValueError, 'tag_check_state_1 pin changed'):
            subject.analyze(bytes(self.mutate(0x474d8b2)))

    def test_counterfactual_bind_path(self):
        with self.assertRaisesRegex(ValueError, 'path_byte pin changed'):
            subject.analyze(bytes(self.mutate(0x47473db)))

    def test_counterfactual_slot_binding(self):
        slot = subject.SLOT_BINDINGS['descriptor_bind'][0]
        sec = next(s for s in self.secs if s['name'] == '.rela.dyn')
        data = bytearray(self.data)
        for p in range(sec['offset'], sec['offset'] + sec['size'], 24):
            off, _, _ = struct.unpack_from('<QQq', data, p)
            if off == slot:
                data[p + 16] ^= 1
                break
        with self.assertRaisesRegex(ValueError, 'slot binding changed'):
            subject.analyze(bytes(data))

    def test_counterfactual_branch_build(self):
        # The branch-B tagword immediate is inside segment 1 but
        # is not a displacement field: streams must diverge.
        with self.assertRaisesRegex(ValueError,
                                    'branch build streams differ'):
            subject.analyze(bytes(self.mutate(0x15a4876)))

    def test_counterfactual_lea_target(self):
        # A displacement byte in the branch-A format-string lea:
        # the pin (which covers the full instruction) rejects it.
        with self.assertRaisesRegex(ValueError, 'build_a_lea_fmt pin changed'):
            subject.analyze(bytes(self.mutate(0x15a45ec)))

    def test_counterfactual_wrong_collect_start(self):
        with self.assertRaisesRegex(ValueError,
                                    'descriptor_stream_collect body changed'):
            subject.analyze(bytes(self.mutate(subject.COLLECT + 0x130)))

    def test_counterfactual_bind_globals(self):
        with self.assertRaisesRegex(ValueError,
                                    'bind global initial state changed'):
            subject.analyze(bytes(self.mutate(subject.BIND_CONFIG_BYTE)))

    def test_regeneration(self):
        packet = subject.PACKET
        self.assertTrue(packet.is_dir())
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / 'packet'
            subject.generate(subject.TARGET, out)
            for name in ('records.json', 'frames.txt'):
                self.assertEqual((out / name).read_bytes(),
                                 (packet / name).read_bytes())
            for path in packet.glob('*_objdump.txt'):
                self.assertEqual((out / path.name).read_bytes(),
                                 path.read_bytes())
        manifest = (packet / 'MANIFEST.sha256').read_text().splitlines()
        listed = set()
        for line in manifest:
            digest, name = line.split('  ', 1)
            listed.add(name)
            self.assertEqual(
                hashlib.sha256((packet / name).read_bytes()).hexdigest(),
                digest)
        on_disk = {p.name for p in packet.iterdir()
                   if p.is_file() and p.name != 'MANIFEST.sha256'}
        self.assertEqual(listed, on_disk)


if __name__ == '__main__':
    unittest.main()
