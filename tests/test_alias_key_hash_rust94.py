"""Native original-key provenance and retained input-only authored Rust results."""
import base64
import importlib.util
import io
import json
from pathlib import Path
import shutil
import struct
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT/'research/work-items/RE-001-key-hash-rust-94'
SPEC = importlib.util.spec_from_file_location('alias_key_hash94', PACKET/'verify.py')
v = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(v)


class AliasKeyHashTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT/'artifacts/node/94/hl-node').read_bytes()
        cls.native = json.loads((PACKET/'native.json').read_text())
        cls.frozen = json.loads((PACKET/'frozen.json').read_text())
        cls.rows, cls.inputs, cls.expected = v.fixtures()

    def test_complete_native_wrappers_feed_finalizer_and_seed_slot(self):
        v.authenticate(self.data)
        self.assertEqual([f['bytes'] for f in self.native['functions']], [352, 363, 471])
        self.assertEqual(self.native['rows_each'], 324)
        self.assertEqual(self.native['identical_finalizer']['bytes'], 244)
        self.assertEqual(self.native['seed_provenance']['borrowed_seed_va'], '0x577ae58')
        self.assertTrue(self.native['seed_provenance']['same_address'])
        self.assertEqual(self.native['seed_slot_section']['raw_16'], '00'*16)
        self.assertEqual(self.native['owned_reads']['capacity_offset0'], 'not read')
        self.assertTrue(self.native['owned_reads']['no_associated_alias_read'])

    def test_pre_rust_freeze_and_actual_constructor_partition(self):
        plan = json.loads((PACKET/'PLAN.json').read_text())
        for old, current in [('FROZEN.json', 'frozen.json'), ('authenticated.json', 'native.json'), ('equations.py', 'equations.py')]:
            self.assertEqual(v.sha((PACKET/current).read_bytes()), plan['files'][old]['sha256'])
        self.assertFalse(plan['new_rust_written'])
        cases = self.frozen['cases']
        self.assertEqual(len(cases), 48)
        self.assertEqual(sum(r['length'] > 16 for r in cases), 30)
        self.assertEqual(sum(r['length'] <= 16 for r in cases), 18)
        for length in [16, 17, 255, 256, 257]:
            self.assertTrue(any(r['length'] == length for r in cases))
        for r in cases:
            keys = [int(x, 16) for x in r['keys_u64']]
            key = bytes.fromhex(r['input_hex'])
            h, states, final = v.eq.stream_key(keys, key)
            self.assertEqual(h, v.eq.bulk_payload(keys, key+b'\xff'))
            self.assertEqual(f'{h:016x}', r['borrowed_expected_H'])
            self.assertEqual(r['owned_expected_H'], r['borrowed_expected_H'])
            self.assertEqual(states, [r['after_original_key_feed'], r['after_ff_feed']])
            self.assertEqual(f'{final:016x}', r['final_word_u64'])

    def test_capacity_and_associated_value_controls_do_not_substitute_the_key(self):
        controls = self.frozen['capacity_ignored_controls']
        self.assertEqual(sum(len(r['capacity_u64_variants']) for r in controls), 144)
        for c, r in zip(controls, self.frozen['cases']):
            self.assertEqual(c['capacity_u64_variants'], [r['length'], r['length']+1, r['length']+16])
            self.assertEqual(c['borrowed_and_owned_expected_H_each_capacity'], r['owned_expected_H'])
        for r in self.frozen['substitution_controls']:
            h = r['correct_hash_original_key']
            self.assertEqual(len(r['associated_value_invariance_rows']), 3)
            for item in r['associated_value_invariance_rows']:
                self.assertEqual(item['expected_H'], h)
                self.assertEqual(len(bytes.fromhex(item['value_u128_le'])), 16)
            for field in ['wrong_key_alias_letters_hash', 'wrong_key_packed_carrier_hash', 'unstable_seed_flip_k0_hash',
                          'wrong_delimiter_fe_hash', 'wrong_copied_key_first_byte_hash']:
                self.assertNotEqual(r[field], h, field)
        for r in self.frozen['prior_fixed20_domain_controls']:
            self.assertNotEqual(r['prior_plain20_math_H'], r['variable_key20_plus_ff_H'])

    def test_identity_and_native_export_corruption_fail_closed(self):
        for changed in [self.data[:-1], b'x'+self.data[1:]]:
            with self.assertRaises(ValueError):
                v.authenticate(changed)
        with tempfile.TemporaryDirectory(prefix='alias-key-hash-') as directory:
            temporary = Path(directory)
            for name in ['native.json', 'frozen.json', 'equations.py', 'native-gnu.txt', 'native-llvm.txt']:
                shutil.copyfile(PACKET/name, temporary/name)
            listing = (temporary/'native-gnu.txt').read_text()
            row = next(s for s in listing.splitlines() if s.lstrip().startswith('13d38c0:'))
            for changed in [listing.replace(row, ''), listing.replace(row, row+'\n'+row), listing.replace('13d38c0:\t53', '13d38c0:\t90')]:
                (temporary/'native-gnu.txt').write_text(changed)
                with patch.object(v, 'HERE', temporary):
                    with self.assertRaises(ValueError):
                        v.authenticate(self.data)

    def test_input_contains_seeds_and_keys_without_expected_hashes(self):
        offset = 7
        for i, (_, keys, key, _) in enumerate(self.rows):
            identity, k0, k1, length = struct.unpack_from('<HQQI', self.inputs, offset)
            offset += 22
            self.assertEqual((identity, k0, k1, length), (i, *keys, len(key)))
            self.assertEqual(self.inputs[offset:offset+length], key)
            offset += length
        self.assertEqual(offset, len(self.inputs))
        driver = (PACKET/'input-only.rs').read_text()
        self.assertNotIn('include_', driver)
        self.assertNotIn('std::fs', driver)

    def test_raw_output_comparator_rejects_hash_and_framing_corruption(self):
        self.assertEqual(v.compare(self.expected, self.expected), [])
        changed = bytearray(self.expected)
        changed[9] ^= 1
        self.assertEqual(len(v.compare(changed, self.expected)), 1)
        changed[7] ^= 1
        with self.assertRaises(ValueError):
            v.compare(changed, self.expected)
        for changed in [self.expected[:-1], b'x'+self.expected[1:], self.expected+b'x']:
            with self.assertRaises(ValueError):
                v.compare(changed, self.expected)

    def test_current_source_receipt_and_all_compiled_semantic_controls(self):
        receipt = json.loads((PACKET/'comparison.json').read_text())
        self.assertEqual(receipt['source_input_pins'], v.source_pins())
        self.assertEqual(receipt['runner_sha256'], v.sha((PACKET/'verify.py').read_bytes()))
        self.assertFalse(receipt['captured_execution'])
        self.assertEqual(len(receipt['builds']), 16)
        bundle = json.loads((PACKET/'raw-streams.json').read_text())
        payload = base64.b64decode(bundle['payload_base64'], validate=True)
        self.assertEqual(len(payload), bundle['payload_bytes'])
        self.assertEqual(v.sha(payload), bundle['payload_sha256'])
        self.assertEqual(v.sha((PACKET/'comparison.json').read_bytes()), bundle['comparison_json_sha256'])
        with tarfile.open(fileobj=io.BytesIO(payload), mode='r:gz') as tar:
            members = tar.getmembers()
            self.assertTrue(all(m.isfile() and not m.name.startswith('/') and '..' not in Path(m.name).parts for m in members))
            self.assertEqual(len(members), len({m.name for m in members}))
            raw = {m.name: tar.extractfile(m).read() for m in members}
        self.assertEqual(set(raw), set(bundle['files']))
        allowed = {'snapshot/SNAPSHOT.json', 'snapshot/recipes.json', 'snapshot/inputs.bin', 'snapshot/expected.bin'}
        self.assertTrue(all(n in allowed or not n.startswith('snapshot/') and n.endswith(('.stdout', '.stderr', '.d', '/actual.bin')) for n in raw))
        self.assertFalse(any(n.endswith(('.rs', '.rlib', '.o', '.so')) for n in raw))
        for name, pin in bundle['files'].items():
            self.assertEqual((len(raw[name]), v.sha(raw[name])), (pin['bytes'], pin['sha256']))
        self.assertEqual(raw['snapshot/inputs.bin'], self.inputs)
        self.assertEqual(raw['snapshot/expected.bin'], self.expected)
        snapshot = json.loads(raw['snapshot/SNAPSHOT.json'])
        self.assertEqual(v.sha(raw['snapshot/SNAPSHOT.json']), receipt['snapshot_sha256'])
        self.assertEqual(snapshot, receipt['snapshot_files'])
        for name, pin in snapshot.items():
            if name in bundle['omitted_snapshot_files_bound_to_current_text']:
                content = (ROOT/bundle['omitted_snapshot_files_bound_to_current_text'][name]).read_bytes()
            else:
                content = raw['snapshot/'+name]
            self.assertEqual((len(content), v.sha(content)), (pin['bytes'], pin['sha256']))
        original = (ROOT/'src/node94-alias/src/lib.rs').read_text()
        recipes = {name: (old, new) for name, old, new in v.RECIPES}
        observed = set()
        for build in receipt['builds']:
            observed.add((build['variant'], build['opt']))
            source = original
            if build['variant'] != 'baseline':
                old, new = recipes[build['variant']]
                self.assertEqual(original.count(old), 1)
                source = original.replace(old, new)
            self.assertEqual(v.sha(source.encode()), build['source_sha256'])
            directory = f"{build['variant']}-opt{build['opt']}"
            actual = raw[directory+'/actual.bin']
            differences = v.compare(actual, self.expected)
            self.assertEqual(len(differences), build['different_cases'])
            self.assertEqual(bool(differences), build['variant'] != 'baseline')
            self.assertEqual(differences[0] if differences else None, build['first_witness'])
            self.assertEqual(v.sha(actual), build['stdout_sha256'])
            self.assertEqual(raw[directory+'/run.stderr'], b'')
            for i, command in enumerate(build['commands']):
                self.assertEqual(command['exit'], 0)
                for suffix in ['stdout', 'stderr']:
                    content = raw[directory+f'/compile-{i}.{suffix}']
                    self.assertEqual(content, b'')
                    self.assertEqual(v.sha(content), command[suffix+'_sha256'])
            for name, content in build['depinfo'].items():
                self.assertEqual(raw[directory+'/'+name], content.encode())
            if build['variant'] == 'baseline':
                self.assertEqual(len(build['framing_controls']), 4)
        self.assertEqual(observed, {(name, opt) for name in ['baseline', *recipes] for opt in [0, 3]})

    def test_packet_manifest(self):
        v.manifest_check()
