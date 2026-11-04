"""Static integrity and independent boundary witnesses; no captured execution."""
import importlib.util
import base64
import copy
import gzip
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
import tarfile
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import accept4_source115 as a
PACKET = ROOT / 'research/work-items/RE-012-accept4-source-115'
spec = importlib.util.spec_from_file_location('accept4_relation', PACKET / 'contract_relation.py')
relation = importlib.util.module_from_spec(spec); spec.loader.exec_module(relation)
spec = importlib.util.spec_from_file_location('accept4_verify', PACKET / 'verify.py')
verifier = importlib.util.module_from_spec(spec); spec.loader.exec_module(verifier)


class LicensedInputs(unittest.TestCase):
    def test_archive_hash_rejects_change(self):
        provenance = json.loads((PACKET / 'source-provenance.json').read_text())
        raw = bytearray((PACKET / 'licensed-build-inputs.json.gz').read_bytes()); raw[-1] ^= 1
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory); (path / 'licensed-build-inputs.json.gz').write_bytes(raw)
            with self.assertRaises(a.EvidenceError):
                verifier.licensed_build_inputs(provenance, path)

    def changed_crate_rejected(self, symlink=False):
        provenance = json.loads((PACKET / 'source-provenance.json').read_text())
        doc = json.loads(gzip.decompress((PACKET / 'licensed-build-inputs.json.gz').read_bytes()))
        entry = doc['entries']['downloads/mio-1.0.2.crate']
        source = io.BytesIO(base64.b64decode(entry['base64'])); dest = io.BytesIO(); changed = False
        with tarfile.open(fileobj=source, mode='r:gz') as original, tarfile.open(fileobj=dest, mode='w:gz') as replacement:
            for member in original.getmembers():
                item = copy.copy(member)
                raw = original.extractfile(member).read() if member.isfile() else None
                if raw and not changed:
                    if symlink:
                        item.type = tarfile.SYMTYPE; item.linkname = 'missing'; item.size = 0; raw = None
                    else:
                        raw = bytes([raw[0] ^ 1]) + raw[1:]
                    changed = True
                replacement.addfile(item, io.BytesIO(raw) if raw is not None else None)
        self.assertTrue(changed)
        raw = dest.getvalue(); entry.update(bytes=len(raw), sha256=a.sha(raw), base64=base64.b64encode(raw).decode())
        packed = gzip.compress(json.dumps(doc).encode(), mtime=0)
        provenance['licensed_inputs_archive'].update(bytes=len(packed), sha256=a.sha(packed))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory); (path / 'licensed-build-inputs.json.gz').write_bytes(packed)
            with self.assertRaises(a.EvidenceError):
                verifier.licensed_build_inputs(provenance, path)

    def test_source_change_below_archive_hash(self):
        self.changed_crate_rejected()

    def test_source_symlink_below_archive_hash(self):
        self.changed_crate_rejected(symlink=True)


class PacketInventory(unittest.TestCase):
    def fixture(self, root):
        packet = root / 'research/work-items/example'
        manifest = {}
        for name in ['comparison/body', 'overlap/record', 'static/record', 'verify.py']:
            path = packet / name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'fixture')
            manifest[path.relative_to(root).as_posix()] = a.sha(path.read_bytes())
        (packet / 'MANIFEST.sha256').write_text('fixture\n')
        for name in ['tools/accept4_source115.py', 'tests/test_accept4_source115.py']:
            path = root / name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'fixture'); manifest[name] = a.sha(path.read_bytes())
        return packet, manifest

    def check(self, mutate=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); packet, manifest = self.fixture(root)
            verifier.check_inventory(root, packet, manifest)
            if mutate:
                mutate(root, packet)
                with self.assertRaises(a.EvidenceError):
                    verifier.check_inventory(root, packet, manifest)

    def test_regular_closed_inventory(self):
        self.check()

    def test_nested_extra_file(self):
        self.check(lambda root, p: (p / 'static/extra').write_bytes(b'extra'))

    def test_extra_empty_directory(self):
        self.check(lambda root, p: (p / 'static/empty').mkdir())

    def test_dangling_symlink(self):
        self.check(lambda root, p: (p / 'dangling').symlink_to('missing'))

    def test_identical_file_symlink(self):
        def mutate(root, p):
            raw = (p / 'verify.py').read_bytes()
            (root / 'identical').write_bytes(raw)
            (p / 'verify.py').unlink(); (p / 'verify.py').symlink_to(root / 'identical')
        self.check(mutate)

    def test_parent_directory_symlink(self):
        def mutate(root, p):
            (p / 'comparison').rename(root / 'original-comparison')
            (p / 'comparison').symlink_to(root / 'original-comparison', target_is_directory=True)
        self.check(mutate)

    def test_external_file_symlink(self):
        def mutate(root, p):
            path = root / 'tools/accept4_source115.py'
            path.unlink(); path.symlink_to(p / 'verify.py')
        self.check(mutate)


class StaticBindings(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = (ROOT / 'artifacts/node/115/hl-node').read_bytes()
        cls.im = a.Image(cls.raw)
        cls.authority = json.loads((PACKET / 'static/records.json').read_text())

    def rejects(self, data):
        try:
            result = a.inspect(data, authenticate=False)
        except (ValueError, struct.error, UnicodeError, IndexError):
            return
        self.assertNotEqual(result, self.authority)

    def test_exact_complete_binding(self):
        self.assertEqual(a.inspect(self.raw), self.authority)
        self.assertEqual(sum(b['bytes'] for b in self.authority['bodies']), 18430)
        self.assertEqual(sum(b['instructions'] for b in self.authority['bodies']), 3671)
        self.assertEqual(len(self.authority['direct_calls']), 4)
        self.assertEqual(self.authority['would_block_errno'], [11])

    def test_scoped_instruction_controls_below_whole_digest(self):
        addresses = [0x475b05b, 0x475b063, 0x475b06f, 0x475b074, 0x475b07c,
                     0x475b083, 0x475b088, 0x475b091, 0x475b09b, 0x475b0a0,
                     0x475b0a5, 0x475b0ad, 0x475b0b5, 0x475b0cb, 0x475b0dc,
                     0x475b0e0, 0x475b0f8, 0x475b108, 0x475b116, 0x475b11a,
                     0x475b12c, 0x475b136, 0x475b142, 0x475b148]
        for stage in a.CALLER_STAGES:
            addresses += [stage['call'], stage['register_call'], stage['register_close']]
            if 'family_test' in stage:
                addresses += [stage['family_test'], stage['family_close']]
        for va in addresses:
            with self.subTest(va=hex(va)):
                changed = bytearray(self.raw); changed[self.im.offset(va)] ^= 1
                self.rejects(bytes(changed))

    def test_unwind_import_table_and_literal_controls(self):
        offsets = [self.im.offset(b['fde']['fde'] + 12) for b in self.authority['bodies']]
        offsets += [r['relocation']['file_offset'] + 16 for r in self.authority['imports']]
        offsets += [self.im.offset(va + 4 * (2 if count == 4 else 10)) for va, count in a.TABLES.items()]
        offsets += [self.im.offset(s['rejection_text']) for s in a.CALLER_STAGES if 'rejection_text' in s]
        for offset in offsets:
            with self.subTest(file_offset=offset):
                changed = bytearray(self.raw); changed[offset] ^= 1
                self.rejects(bytes(changed))
        with self.assertRaises(a.EvidenceError):
            a.inspect(self.raw[:-1])


class ContractWitnesses(unittest.TestCase):
    def setUp(self):
        self.initial = bytes(range(40))

    def call(self, result=7, storage=b'', **kwargs):
        return relation.helper(19, result, storage, self.initial, **kwargs)

    def test_errno_and_short_circuit(self):
        for ret in [-1, -2, -(1 << 31)]:
            for error in [0, 11, 20, 0x80000000, 0xffffffff]:
                result = self.call(ret, errno=error, output_address=0xfedcba9876543210)
                expected = bytearray(self.initial)
                expected[:4] = b'\x01\0\0\0'
                expected[8:16] = b'\x02\0\0\0' + error.to_bytes(4, 'little')
                self.assertEqual(result['output_hex'], expected.hex())
                self.assertEqual(result['sockaddr_reads'], [])
                self.assertEqual(result['events'], [['accept4', 19, 128, 0x80800], ['errno', error]])
                self.assertEqual(result['rax'], 0xfedcba9876543210)

    def test_ipv4_known_fields_and_unspecified_import_registers(self):
        storage = bytes.fromhex('02001234a1b2c3d4')
        result = self.call(0, storage)
        self.assertEqual(result['active'], {'fd': 0, 'family': 4, 'address': 'a1b2c3d4', 'port': 0x1234})
        self.assertEqual(result['output_hex'], '00000000000000000000a1b2c3d43412' + '??' * 20 + '02002627')
        self.assertEqual(result['sockaddr_reads'], [[0, 2], [4, 4], [2, 2]])
        self.assertEqual(result['events'], [['accept4', 19, 128, 0x80800]])
        values = (0x0807060504030201, 0x0c0b0a09, 0x100f0e0d, 0x14131211)
        observed = self.call(0, storage, volatile=values)
        self.assertEqual(observed['output_hex'][32:72], bytes(range(1, 21)).hex())
        self.assertEqual(observed['output_hex'][:32], result['output_hex'][:32])
        self.assertEqual(observed['output_hex'][72:], '02002627')

    def test_ipv6_distinct_port_flow_scope_and_read_footprint(self):
        storage = bytes.fromhex('0a00123411223344') + bytes(range(16)) + bytes.fromhex('55667788')
        result = self.call(0x7fffffff, storage, volatile=(0, 0, 0, 0))
        expected = bytearray(self.initial)
        expected[:4] = bytes(4); expected[4:8] = bytes.fromhex('ffffff7f')
        expected[8:12] = bytes.fromhex('01000000'); expected[12:28] = bytes(range(16))
        expected[28:36] = bytes.fromhex('1122334455667788'); expected[36:38] = bytes.fromhex('3412')
        self.assertEqual(result['output_hex'], expected.hex())
        self.assertEqual(result['active']['flowinfo'], 0x44332211)
        self.assertEqual(result['active']['scope_id'], 0x88776655)
        self.assertEqual(result['sockaddr_reads'], [[0, 2], [2, 2], [4, 4], [24, 4], [8, 4], [10, 2], [12, 8], [20, 4]])

    def test_full_family_width_and_unknown_error_publication(self):
        expected = bytearray(self.initial); expected[:4] = b'\x01\0\0\0'
        expected[8:16] = bytes.fromhex('0300000014000000')
        for family in range(65536):
            storage = family.to_bytes(2, 'little') + bytes(26)
            result = self.call(9, storage, errno=123, close_return=-1)
            if family in (2, 10):
                self.assertEqual(result['kind'], 'success')
            else:
                self.assertEqual(result['output_hex'], expected.hex())
                self.assertEqual(result['sockaddr_reads'], [[0, 2]])
                self.assertEqual(result['events'], [['accept4', 19, 128, 0x80800], ['close', 9, expected.hex()]])

    def test_socklen_is_not_a_validation_gate(self):
        for storage in [bytes.fromhex('0200ffff11223344'), bytes.fromhex('0a000001') + bytes(range(24)), b'\x01\0']:
            expected = self.call(storage=storage)
            for length in [0, 1, 2, 7, 8, 27, 28, 128, 0xffffffff]:
                self.assertEqual(self.call(storage=storage, returned_length=length), expected)
        with self.assertRaises(ValueError):
            self.call(storage=b'\x02\0')

    def test_four_caller_boundaries_and_actual_reload_values(self):
        for caller in range(4):
            for error in [0, 10, 11, 12, 20, 0x8000000b, 0xffffffff]:
                result = relation.caller_boundary(caller, 'os-error', errno=error)
                self.assertEqual(result, {'boundary': 'would-block' if error == 11 else 'other-error', 'events': []})
            self.assertEqual(relation.caller_boundary(caller, 'family-error')['events'], [])
            failed = relation.caller_boundary(caller, 'success', registration_tag=2, fd_after_registration=37)
            self.assertEqual(failed['events'], [['register', 3], ['close', 37]])
            for after in [-1, 0, 41]:
                result = relation.caller_boundary(caller, 'success', family=6, fd_after_cleanup=after)
                if caller == 3:
                    self.assertEqual(result, {'boundary': 'address-forwarded', 'events': [['register', 3]]})
                else:
                    events = [['register', 3], ['make-error', 'ip not v4'], ['cleanup']]
                    if after != -1:
                        events += [['close', after]]
                    events += [['drop']]
                    self.assertEqual(result, {'boundary': 'ipv6-rejected', 'events': events})


if __name__ == '__main__':
    unittest.main()
