"""Static node94 CLI facts and corrupted evidence; no target execution (MIT)."""
import copy
import base64
import gzip
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'tools'))
import chain_cli_static as c

spec = importlib.util.spec_from_file_location('chain_cli_packet_verify', c.PACKET / 'verify.py')
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)


class TargetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = c.TARGET.read_bytes()
        cls.image = c.Image(cls.raw)
        with mock.patch('subprocess.run', side_effect=AssertionError('target execution forbidden')):
            cls.report = c.analyze(cls.raw)

    def mutated(self, va, replacement, reparse=False):
        off = self.image.offset(va, len(replacement))
        data = self.raw[:off] + replacement + self.raw[off + len(replacement):]
        if reparse:
            return c.Image(data)
        image = copy.copy(self.image)
        image.data = data
        return image

    def test_recorded_facts_equal(self):
        self.assertEqual(self.report, v.read_json(c.PACKET / 'records.json'))
        self.assertEqual((self.report['primary_bytes'], len(self.report['bodies']),
                          sum(x['instructions'] for x in self.report['bodies'])), (4476, 11, 1566))

    def test_wrong_identity_before_output_or_process(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'bad'
            path.write_bytes(b'not a target')
            output = Path(d) / 'output'
            with mock.patch('subprocess.run', side_effect=AssertionError('unexpected process')):
                with self.assertRaisesRegex(ValueError, 'identity'):
                    c.export(path, output)
            self.assertFalse(output.exists())

    def test_all_anchors_below_digest(self):
        for label, (va, raw) in c.ANCHORS.items():
            # Last byte avoids deliberately changing instruction lengths, so
            # the semantic guard, rather than whole-file identity, must fail.
            where = va + len(bytes.fromhex(raw)) - 1
            replacement = bytes([self.image.read(where, 1)[0] ^ 1])
            with self.subTest(label=label), self.assertRaises(ValueError):
                c.extract(self.mutated(where, replacement))

    def test_every_command_constant_below_digest(self):
        for name, _, _, chunks, _ in c.NAMES:
            va = chunks[0][3]
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'spelling|overlapping'):
                c.extract(self.mutated(va, bytes([self.image.read(va, 1)[0] ^ 1])))

    def test_simd_padding_is_required(self):
        for name, _, _, chunks, _ in c.NAMES:
            for _, width, kind, va in chunks:
                if kind == 'simd_tail':
                    with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'zero extension'):
                        c.extract(self.mutated(va + width, b'\x01'))

    def test_interval_comparison_has_no_unchecked_name_byte(self):
        # Independent interval union, not an x86 emulator or input replay.
        for row in self.report['commands']:
            intervals = [(x['input_offset'], x['input_offset'] + x['input_bytes'])
                         for x in row['comparison_chunks']]
            covered = {k for a, b in intervals for k in range(a, b)}
            self.assertEqual(covered, set(range(len(row['name']))))
            target = row['name'].encode()
            for k in range(len(target)):
                changed = target[:k] + bytes([target[k] ^ 1]) + target[k + 1:]
                self.assertFalse(all(changed[a:b] == target[a:b] for a, b in intervals))

    def test_length_table_corruption_valid_and_interior_targets(self):
        for target in (c.MISS, c.RANGES['commands'][0] + 1):
            with self.subTest(target=target), self.assertRaises(ValueError):
                c.extract(self.mutated(c.TABLE, struct.pack('<i', target - c.TABLE)))

    def test_fixed_tags_corruption(self):
        for name, va in c.TAG_WRITES.items():
            old = self.image.read(va + 3, 4)
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'first word'):
                c.extract(self.mutated(va + 3, struct.pack('<I', int.from_bytes(old, 'little') ^ 1)))

    def test_profile_presence_is_not_fixed_variant(self):
        row = next(x for x in self.report['commands'] if x['name'] == 'change-validator-profile')
        self.assertEqual(row['normal_first_qword_values'], [0, 1])
        values = {x for row in self.report['commands'] for x in row['normal_first_qword_values']}
        self.assertEqual(values, set(range(14)) | {15})

    def test_chain_names_and_program_literal_corruption(self):
        for va in [x[0] for x in c.CHAIN_NAMES] + [0x6f6141]:
            with self.subTest(va=hex(va)), self.assertRaisesRegex(ValueError, 'spelling|program name'):
                c.extract(self.mutated(va, b'?'))

    def test_every_distinct_option_literal_corruption(self):
        for va in {int(x['literal_va'], 16) for x in self.report['options']}:
            with self.subTest(va=hex(va)), self.assertRaisesRegex(ValueError, 'option spelling'):
                c.extract(self.mutated(va, b'?'))

    def test_relocation_target_and_kind_corruption(self):
        for slot in (0x5773918, 0x5776a78, 0x5776a80):
            row = self.image.relocations[slot]
            off = int(row['file_offset'], 16)
            for start, raw in ((off + 16, struct.pack('<q', row['addend'] + 1)),
                               (off + 8, struct.pack('<Q', 6))):
                data = self.raw[:start] + raw + self.raw[start + len(raw):]
                with self.subTest(slot=hex(slot), start=start), self.assertRaises(ValueError):
                    c.extract(c.Image(data))

    def test_duplicate_relocation_writer_rejected_both_orders(self):
        items = list(self.image.relocations.values())
        for source, destination in ((items[0], items[-1]), (items[-1], items[0])):
            off = int(source['file_offset'], 16)
            raw = struct.pack('<Q', int(destination['slot'], 16))
            data = self.raw[:off] + raw + self.raw[off + 8:]
            with self.assertRaisesRegex(ValueError, 'duplicate relocation'):
                c.Image(data)

    def test_fde_extent_change_rejected(self):
        owner = self.image.owner(c.RANGES['chain'][0])
        va = owner['fde'] + 12
        raw = struct.pack('<i', owner['end'] - owner['start'] - 1)
        with self.assertRaisesRegex(ValueError, 'FDE extent'):
            c.extract(self.mutated(va, raw, reparse=True))

    def test_cie_version_change_rejected(self):
        owner = self.image.owner(c.RANGES['chain'][0])
        with self.assertRaisesRegex(ValueError, 'CIE version'):
            self.mutated(owner['cie'] + 8, b'\x02', reparse=True)

    def test_source_location_change_visible_below_digest(self):
        location = self.report['source_locations'][0]
        va = int(location['record'], 16) + 16
        changed = c.extract(self.mutated(va, struct.pack('<I', location['line'] + 1)))
        self.assertNotEqual(changed, self.report)
        self.assertEqual(changed['source_locations'][0]['line'], location['line'] + 1)

    def test_all_retained_native_instruction_bytes_and_boundaries(self):
        self.assertEqual(v.verify_native(self.report, c.PACKET), 22)

    def test_native_gap_overlap_and_truncation_rejected(self):
        for text in ('1000: 90\n1002: c3\n', '1000: 90\n1000: c3\n', '1000: 90\n'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                c.native_bytes(text, 0x1000, 0x1002)

    def test_duplicate_json_key_rejected(self):
        with self.assertRaisesRegex(ValueError, 'duplicate JSON'):
            json.loads('{"x":1,"x":2}', object_pairs_hook=c.unique)

    def test_manifest_inventory_and_corruption(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / 'a').write_bytes(b'abc')
            rows = {'a': {'bytes': 3, 'sha256': c.digest(b'abc')}}
            v.verify_manifest(root, rows, {'a'})
            with self.assertRaisesRegex(ValueError, 'inventory'):
                v.verify_manifest(root, rows, {'a', 'b'})
            (root / 'a').write_bytes(b'abd')
            with self.assertRaisesRegex(ValueError, 'hash differs'):
                v.verify_manifest(root, rows, {'a'})

    def test_manifest_cannot_remove_required_evidence(self):
        self.assertTrue({'records.json', 'raw-streams.json.gz', 'CONTRACT.md',
                         'commands.gnu.txt', 'commands.llvm.txt'} <= v.PACKET_FILES)
        with self.assertRaisesRegex(ValueError, 'inventory'):
            v.verify_manifest(ROOT, {}, {'required'})
        with self.assertRaisesRegex(ValueError, 'unsafe'):
            v.verify_manifest(ROOT, {'../outside': {}}, {'../outside'})

    def test_packet_nested_file_and_empty_directory_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / 'manifest.json').write_text('{}')
            (root / 'a').write_bytes(b'abc')
            v.verify_packet_inventory(root, {'a'})
            (root / 'nested').mkdir()
            with self.assertRaisesRegex(ValueError, 'directory'):
                v.verify_packet_inventory(root, {'a'})
            (root / 'nested' / 'extra').write_bytes(b'extra')
            with self.assertRaises(ValueError):
                v.verify_packet_inventory(root, {'a'})

    def test_dangling_file_and_parent_symlinks_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / 'manifest.json').write_text('{}')
            (root / 'dangling').symlink_to(root / 'missing')
            with self.assertRaisesRegex(ValueError, 'symlink'):
                v.verify_packet_inventory(root, set())
            (root / 'dangling').unlink()
            (root / 'real').mkdir()
            (root / 'real' / 'a').write_bytes(b'abc')
            (root / 'linked').symlink_to(root / 'real', target_is_directory=True)
            row = {'linked/a': {'bytes': 3, 'sha256': c.digest(b'abc')}}
            with self.assertRaisesRegex(ValueError, 'symlink'):
                v.verify_manifest(root, row, set(row))

    def test_archive_bytes_and_duplicate_labels(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'streams.gz'
            row = {'label': 'stdout', 'bytes': 3, 'sha256': c.digest(b'abc'),
                   'base64': base64.b64encode(b'abc').decode()}
            def save(rows):
                path.write_bytes(gzip.compress(json.dumps({'schema': 1, 'streams': rows}).encode(), mtime=0))
            save([row])
            self.assertEqual(v.verify_archive(path), {'streams': 1, 'raw_bytes': 3})
            save([row, row])
            with self.assertRaisesRegex(ValueError, 'duplicate'):
                v.verify_archive(path)
            row['base64'] = base64.b64encode(b'abd').decode()
            save([row])
            with self.assertRaisesRegex(ValueError, 'differs'):
                v.verify_archive(path)


if __name__ == '__main__':
    unittest.main()
