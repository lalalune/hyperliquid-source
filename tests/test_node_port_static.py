"""Controls for tools/node_port_static.py (node #94 net_utils NodePort port arithmetic)."""
import json
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import node_port_static as np_  # noqa: E402
from artifacts import check  # noqa: E402

BINARY = ROOT / np_.TARGET
PACKET = ROOT / 'research/work-items/transport-node-port-94/records.json'
CACHE = {}


def load():
    if not CACHE:
        identity = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                        if i['path'] == np_.TARGET)
        check(BINARY, identity)
        CACHE['data'] = BINARY.read_bytes()
        CACHE['img'] = np_.Image(CACHE['data'])
        CACHE['result'] = np_.analyse(CACHE['data'])
        CACHE['sha256'] = identity['sha256']
    return CACHE


@unittest.skipUnless(BINARY.exists(), 'pinned node #94 binary not present')
class Results(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = load()['result']

    def test_tables(self):
        self.assertEqual([t['va'] for t in self.result['tables']], ['0x3c4ce0', '0x3d8450', '0x6f16a2'])
        self.assertTrue(all(t['ports'] == [4001, 4002, 4003, 4004, 3998, 3999] for t in self.result['tables']))

    def test_sites(self):
        sites = self.result['sites']
        self.assertEqual(len(sites), 10)
        self.assertEqual(sorted(s['fde'] for s in sites if s['shape'] == 'table'), ['0x2037ac0', '0x22c54a0', '0x43831e0'])
        consts = {s['fde']: s['base_port'] for s in sites if s['shape'] != 'table'}
        self.assertEqual(consts, {'0x1fd4570': 4001, '0x2039060': 4002, '0x43848f0': 4004, '0x4387f40': 4002,
                                  '0x438ed70': None, '0x454c2b0': 4003, '0x47b4950': None})
        for s in sites:
            if s['shape'] == 'jump_table':
                self.assertEqual(s['port_by_discriminant'], [4001, 4002, 4003, 4004, 3998, 3999])
        for s in sites:
            self.assertEqual((s['mul_overflow']['line'], s['mul_overflow']['col']), (23, 63))
            self.assertEqual((s['add_overflow']['line'], s['add_overflow']['col']), (28, 14))
            self.assertEqual(s['mul_overflow']['message'], 'attempt to multiply with overflow')
            self.assertEqual(s['add_overflow']['message'], 'attempt to add with overflow')
            self.assertEqual(s['local_ip'], '127.0.0.1')

    def test_model(self):
        for r in self.result['model']['rows']:
            self.assertEqual((r['max_index_ok'], r['first_add_panic'], r['first_mul_panic']), (61, 62, 66))
            self.assertTrue(r['reference_agrees_on_success'] and r['reference_errors_where_binary_panics'])

    def test_packet_matches_regeneration(self):
        result = dict(load()['result'])
        result['target_sha256'] = load()['sha256']
        self.assertEqual(PACKET.read_text(), json.dumps(result, indent=2, sort_keys=True) + '\n')


@unittest.skipUnless(BINARY.exists(), 'pinned node #94 binary not present')
class CorruptionControls(unittest.TestCase):
    """Each control flips the bytes behind one claim; the analysis must refuse."""

    def mutated(self, va, new):
        c = load()
        data = bytearray(c['data'])
        off = c['img'].offset(va, len(new))
        data[off:off + len(new)] = new
        return bytes(data)

    def refuses(self, va, new, pattern):
        with self.assertRaisesRegex(np_.EvidenceError, pattern):
            np_.analyse(self.mutated(va, new))

    def test_stride(self):
        self.refuses(0x2039118 + 2, b'\xe9', 'site census changed')

    def test_mul_register_mismatch(self):
        self.refuses(0x1fd4e2a + 2, b'\xe2', 'is not mov r16,1000; mul r16')

    def test_bound_not_complement(self):
        self.refuses(0x1fd4e36 + 2, b'\x5f', 'is not 0xffff - 4001')

    def test_const_base(self):
        self.refuses(0x454c353 + 1, b'\xa4', 'is not 0xffff - 4004')

    def test_jump_table_arm_port(self):
        self.refuses(0x438f640 + 2, b'\x9d', 'jump-table ports')

    def test_jump_table_fallthrough_arm_port(self):
        self.refuses(0x47b4af4 + 2, b'\xa1', 'jump-table ports')

    def test_table_entry(self):
        self.refuses(0x3d8450 + 4, struct.pack('<H', 4013), 'port table census')

    def test_table_lea_retarget(self):
        self.refuses(0x2037d11 + 3, struct.pack('<i', struct.unpack('<i', load()['img'].read(0x2037d14, 4))[0] + 2),
                     'port table reference census|is not a port table')

    def test_local_ip(self):
        self.refuses(0x4383451 + 4, b'\x02', 'no unique local-IP build')

    def test_add_carry_check(self):
        self.refuses(0x22c5579 + 1, b'\x83', 'no unique local-IP build and checked u16 add')

    def test_mul_location_line(self):
        loc = 0x5719a08
        self.refuses(loc + 16, struct.pack('<I', 24), 'mul Location 0x5719a08 is line 24')

    def test_add_panic_slot_relocation(self):
        img = load()['img']
        rela = next(s for s in img.secs if s['name'] == '.rela.dyn')
        for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
            where, info, addend = struct.unpack_from('<QQq', img.data, pos)
            if where == 0x576e118:
                data = bytearray(img.data)
                data[pos + 16:pos + 24] = struct.pack('<q', 0x157b4a0)
                with self.assertRaisesRegex(np_.EvidenceError, 'message is not'):
                    np_.analyse(bytes(data))
                return
        self.fail('add panic slot relocation not found')

    def test_injected_mul_site(self):
        self.refuses(0x3723000, bytes.fromhex('66b9e80366f7e10f8000000000'), '0x3723000')

    def test_truncated_elf(self):
        with self.assertRaises(ValueError):
            np_.analyse(load()['data'][:4096])


class Model(unittest.TestCase):
    def test_thresholds_exhaustive(self):
        for base in np_.PORTS:
            for i in range(256):
                got = np_.local_port(base, i)
                if i <= 61:
                    self.assertEqual(got, base + 1000 * i)
                elif i <= 65:
                    self.assertEqual(got, 'panic: attempt to add with overflow')
                else:
                    self.assertEqual(got, 'panic: attempt to multiply with overflow')

    def test_reference_error_class_differs(self):
        self.assertEqual(np_.reference_port(4001, 62), 'Err(PortOverflow)')
        self.assertNotEqual(np_.local_port(4001, 62), np_.reference_port(4001, 62))


if __name__ == '__main__':
    unittest.main()
