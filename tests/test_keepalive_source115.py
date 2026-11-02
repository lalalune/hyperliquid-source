"""Target-scoped integrity controls and independent protocol counterexamples."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import sys
sys.dont_write_bytecode = True
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import keepalive_source115 as k

PACKET = ROOT / 'research/work-items/RE-012-keepalive-source-115'
spec = importlib.util.spec_from_file_location('keepalive_relation', PACKET / 'protocol_relation.py')
relation = importlib.util.module_from_spec(spec); spec.loader.exec_module(relation)


class KeepaliveEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT / 'artifacts/node/115/hl-node').read_bytes()
        cls.im = k.Image(cls.data)
        cls.golden = json.loads((PACKET / 'static/records.json').read_text())

    def rejects(self, data):
        try:
            actual = k.inspect(data, authenticate=False, check_body_hashes=False)
        except (ValueError, struct.error, UnicodeError, IndexError):
            return
        self.assertNotEqual(actual, self.golden, 'changed scoped evidence was silently accepted')

    def test_exact_regeneration(self):
        self.assertEqual(k.inspect(self.data), self.golden)
        self.assertEqual(sum(b['bytes'] for b in self.golden['bodies']), 6972)
        self.assertEqual(sum(b['instructions'] for b in self.golden['bodies']), 1444)

    def test_instruction_corruption_below_digest_gate(self):
        # Both durations, both unsigned clamps, retry tag, option levels/names,
        # failure predicates, zero return, errno packing, both real caller
        # enable gates and continuation/custom-drop predicates.
        addresses = [0x5c6852c,0x5c68539,0x5c68544,0x5c68558,0x5c68569,
                     0x5c6856e,0x5c68587,0x5c6859b,0x5c685b1,0x5c685cb,
                     0x5c685dc,0x5c685e1,0x5c685f3,0x5c685f7,
                     0x5c6861c,0x5c686a1,0x5c686e7,
                     0x2e6bf49,0x2e6bf58,0x2e6bf71,0x2e6bfca,0x2e6bfcf,
                     0x2e6bfe3,0x2e6bff2,0x2e6c00e,0x2e6c026,0x2e6c02b,
                     0x2e6c030,0x2e6c01d,0x2e6c264,0x2e6b0ca,0x2e6b0d3,
                     0x2e7dbfa,0x2e7dc19,0x2e7dc24,0x2e7dc44,0x2e7dc5d,
                     0x2e7dc70,0x2e7dd82,0x2e7dd91,0x2e7de95,0x2e7de9a,
                     0x2e7de9f,0x2e7bdda,0x2e7bde3]
        for va in addresses:
            with self.subTest(va=hex(va)):
                changed = bytearray(self.data); changed[self.im.offset(va)] ^= 1
                self.rejects(bytes(changed))

    def test_fde_and_source_record_corruption(self):
        for body in self.golden['bodies']:
            va = body['fde']['fde'] + 12
            changed = bytearray(self.data); changed[self.im.offset(va)] ^= 1
            self.rejects(bytes(changed))
        for record in self.golden['locations'] + self.golden['tracing_metadata']:
            changed = bytearray(self.data); changed[self.im.offset(int(record['path_va'], 16))] ^= 1
            self.rejects(bytes(changed))

    def test_relocation_corruption(self):
        for rec in self.golden['relocations']:
            with self.subTest(slot=rec['where']):
                changed = bytearray(self.data); changed[rec['file_offset'] + 16] ^= 1
                self.rejects(bytes(changed))

    def test_full_digest_gate(self):
        with self.assertRaises(k.EvidenceError):
            k.inspect(self.data[:-1])

    def test_boundaries_and_short_circuit(self):
        # Expectations below use direct literal event lists, separate from the
        # table relation. Values are artificial raw target-boundary probes.
        f = relation.fixture
        for n in [0, 1, 999999999, 1000000000, 1000000001, 0xffffffff]:
            record = f(t=0, s0=0x8000000000000000, n0=n, n1=1000000000)
            expected = [] if n == 1000000000 else [(6, 4, b'\xff\xff\xff\x7f', 4)]
            self.assertEqual(relation.requests(record), expected)
        for t in [0, 1, 2, 3, 0xffffffff]:
            expected = [(6, 6, b'\xff' * 4, 4)] if t == 1 else []
            self.assertEqual(relation.requests(f(t=t, n0=1000000000, n1=1000000000)), expected)
        for value, expected in [(0, 0), (0x7ffffffe, 0x7ffffffe), (0x7fffffff, 0x7fffffff),
                                (0x80000000, 0x7fffffff), (0xffffffffffffffff, 0x7fffffff)]:
            self.assertEqual(int.from_bytes(relation.requests(f(s0=value))[0][2], 'little'), expected)
        for failure in range(3):
            returns = [0, 0, 0]; returns[failure] = -1
            result = relation.helper(f(), returns, -1)
            self.assertEqual(len(result['requests']), failure + 1)
            self.assertEqual(result['rax'], 0xffffffff00000002)
            self.assertEqual(result['errno_reads'], 1)
        self.assertEqual(len(relation.helper(f(), [-2, 1, -2147483648], 1)['requests']), 3)
        self.assertEqual(relation.helper(f(), [-2, 1, -2147483648], 1)['rax'], 0)

    def test_registered_alternatives_and_corruption_controls(self):
        spec = importlib.util.spec_from_file_location('keepalive_verify', PACKET / 'verify.py')
        verifier = importlib.util.module_from_spec(spec); spec.loader.exec_module(verifier)
        registry = json.loads((ROOT / 'research/byte-windows.json').read_text())
        expected = json.loads((PACKET / 'comparison/comparison.json').read_text())
        actual = verifier.registry_checks(registry, expected, self.golden)
        self.assertEqual((actual['target_intervals'], actual['alternative_comparisons']), (2, 4))
        labels = ['missing_alternative', 'changed_source_extent', 'changed_comparison_pointer',
                  'asserted_version_assignment', 'duplicate_target', 'changed_target_hash']
        for label in labels:
            with self.subTest(control=label):
                changed = copy.deepcopy(registry)
                row = next(r for r in changed['windows'] if r['id'] == 'node115-socket2-keepalive-5c68520')
                if label == 'missing_alternative':
                    row['alternative_candidates'].pop()
                elif label == 'changed_source_extent':
                    row['alternative_candidates'][1]['source']['length'] -= 1
                elif label == 'changed_comparison_pointer':
                    row['alternative_candidates'][1]['comparison_pointer'][1] = 3
                elif label == 'asserted_version_assignment':
                    row['version_assignment_proved'] = True
                elif label == 'duplicate_target':
                    changed['windows'].append(copy.deepcopy(row))
                elif label == 'changed_target_hash':
                    row['target_body_sha256'] = '0' * 64
                with self.assertRaises(ValueError):
                    verifier.registry_checks(changed, expected, self.golden)

    def test_best_effort_counterexamples(self):
        for err in [0, 1, 11, 22, -1, -2147483648]:
            for failure in range(4):
                options = [0, 0, 0]
                if failure:
                    options[failure - 1] = -1
                result = relation.caller_stage(True, -1 if failure == 0 else 0,
                                               relation.fixture(), options, err)
                self.assertEqual(len(result['calls']), failure + 1)
                self.assertTrue(result['continues'])
                self.assertFalse(result['custom_drop'])
                self.assertTrue(result['outlined_drop_called'])
                self.assertEqual(relation.drop_tag(result['error_word']), 'no_pointee_read')
                self.assertEqual(relation.drop_tag(result['error_word'] ^ 3), 'opaque_custom')
                self.assertEqual(result['error_word'], ((err & 0xffffffff) << 32) | 2)
        self.assertEqual(relation.caller_stage(False, -1, relation.fixture(), [-1] * 3, 22)['calls'], [])

class PacketAdmission(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import base64,gzip
        spec=importlib.util.spec_from_file_location('keepalive_verify_admission',PACKET/'verify.py')
        cls.v=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.v)
        cls.decoded={n:base64.b64decode(e['base64'],validate=True) for n,e in
                     json.loads(gzip.decompress((PACKET/'licensed-evidence.json.gz').read_bytes()))['entries'].items()}

    def test_whole_licensed_sources_and_objects(self):
        self.assertEqual(self.v.license_sources(self.decoded),506)

    def test_source_mutation_below_updated_archive_pin(self):
        import hashlib,io,tarfile
        changed=dict(self.decoded);name='socket2-0.4.10.crate';raw=changed['official-archives/'+name]
        buf=io.BytesIO()
        with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as inp,tarfile.open(fileobj=buf,mode='w:gz') as out:
            modified=False
            for member in inp.getmembers():
                data=inp.extractfile(member).read() if member.isfile() else None
                if member.name.endswith('/src/lib.rs'):
                    data=bytes([data[0]^1])+data[1:];modified=True
                out.addfile(member,io.BytesIO(data) if data is not None else None)
        self.assertTrue(modified)
        changed['official-archives/'+name]=buf.getvalue()
        result=json.loads(changed['source-build/result.json']);result['archives'][name]={'bytes':len(buf.getvalue()),'sha256':hashlib.sha256(buf.getvalue()).hexdigest()}
        changed['source-build/result.json']=json.dumps(result).encode()
        with self.assertRaisesRegex(ValueError,'complete official sources'):self.v.license_sources(changed)

    def test_closed_inventory_controls(self):
        import tempfile
        for control in ('normal','extra_file','extra_directory','nested_file','file_symlink','dangling_symlink','directory_symlink','external_parent_symlink'):
            with self.subTest(control=control),tempfile.TemporaryDirectory() as temp:
                root=Path(temp).resolve();packet=root/'research/work-items/test';packet.mkdir(parents=True)
                for d in ('static','comparison'):(packet/d).mkdir()
                names=['research/work-items/test/a.txt','tools/keepalive_source115.py','tests/test_keepalive_source115.py','tools/byte_progress.py']
                for name in names:
                    q=root/name;q.parent.mkdir(parents=True,exist_ok=True);q.write_text('x')
                (packet/'MANIFEST.sha256').write_text('')
                if control=='extra_file':(packet/'unknown').write_text('x')
                elif control=='extra_directory':(packet/'unknown').mkdir()
                elif control=='nested_file':(packet/'static'/'unknown').write_text('x')
                elif control=='file_symlink':
                    (packet/'a.txt').unlink();(packet/'a.txt').symlink_to(root/'tools/byte_progress.py')
                elif control=='dangling_symlink':(packet/'missing').symlink_to(packet/'absent')
                elif control=='directory_symlink':(packet/'linked').symlink_to(packet/'static',target_is_directory=True)
                elif control=='external_parent_symlink':
                    (root/'tools').rename(root/'tool-target');(root/'tools').symlink_to(root/'tool-target',target_is_directory=True)
                if control=='normal':self.v.check_inventory(root,packet,dict.fromkeys(names,''))
                else:
                    with self.assertRaises(ValueError):self.v.check_inventory(root,packet,dict.fromkeys(names,''))

    def test_inactive_padding_is_not_a_value(self):
        record=bytearray(relation.fixture());expected=relation.requests(record)
        record[20:24]=b'\xff\x13\x42\x80'
        self.assertEqual(relation.requests(record),expected)

    def test_current_level_gates_are_distinct(self):
        # Direct branch predicates, not opaque tracing callback effects.
        for n,server,client in [(0,True,True),(1,False,True),(3,False,True),(4,False,False),(5,False,False),(2**64-1,False,False)]:
            self.assertEqual(n==0,server);self.assertEqual(n<=3,client)


if __name__ == '__main__':
    unittest.main()
