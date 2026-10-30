"""Controls for tools/tcp_frame_write_static.py (node #94 net_utils TCP frame writes)."""
import json
import random
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import tcp_frame_write_static as tw  # noqa: E402
from artifacts import check  # noqa: E402

BINARY = ROOT / tw.TARGET
PACKET = ROOT / 'research/work-items/transport-tcp-frame-write-94/records.json'
CACHE = {}


def load():
    if not CACHE:
        identity = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                        if i['path'] == tw.TARGET)
        check(BINARY, identity)
        CACHE['data'] = BINARY.read_bytes()
        CACHE['img'] = tw.Image(CACHE['data'])
        CACHE['result'] = tw.analyse(CACHE['data'])
        CACHE['sha256'] = identity['sha256']
    return CACHE


@unittest.skipUnless(BINARY.exists(), 'pinned node #94 binary not present')
class Results(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = load()['result']

    def test_census(self):
        c = self.result['census']
        self.assertEqual(c['port_compares'], ['0x204b3b5', '0x43a1835', '0x4b375d5'])
        self.assertEqual(len(c['compress_u16_table']), 3)
        self.assertEqual(len(c['compress_u32_table']), 3)
        self.assertEqual(len(c['lz4_stats_record_owner_fdes']), 8)

    def test_writer_facts(self):
        for w in self.result['writers']:
            self.assertEqual(w['threshold']['raw_when'], 'len < 0x401')
            self.assertEqual(w['port']['ports'], [3998, 3999])
            self.assertEqual(w['capacity']['bytes'], '24 + len * 110 / 100')
            self.assertEqual((w['hash_table']['small']['bytes'], w['hash_table']['large']['bytes']), (0x2000, 0x4000))
            self.assertEqual(w['chunking']['chunk_bytes'], 4_000_000)
            self.assertEqual((w['timeout']['default_seconds'], w['timeout']['descriptor']), (20.0, 'tcp_chunk'))
        self.assertEqual([w['header']['flag_set']['register'] for w in self.result['writers']], ['r14', 'r14', 'r13'])

    def test_wrappers_pass_flag_zero(self):
        for w in self.result['wrappers']:
            self.assertEqual((w['arg0'], w['arg8_seconds'], w['chunk_timeout_selected']), (0, 60.0, 20.0))

    def test_inline_writer_flag_constant_zero(self):
        self.assertEqual((self.result['inline_pair']['flag'], self.result['inline_pair']['chunk_timeout_selected']), (0, 20.0))

    def test_direct_callers(self):
        rows = self.result['callers']
        self.assertEqual(len(rows) + len(self.result['wrappers']), 12)
        decoded = [r for r in rows if 'arg0' in r]
        self.assertEqual(len(decoded), 9)
        self.assertTrue(all(r['arg8_seconds'] == 60.0 for r in decoded))
        sixty = [(r['call'], r['owner_fde'], r['arg0']) for r in decoded if r['chunk_timeout_selected'] == 60.0]
        self.assertEqual(sixty, [('0x203b588', '0x203a190', 1)])
        self.assertEqual([r['call'] for r in rows if 'arg0' not in r], [hex(tw.INLINE_POLL_CALL)])
        labels = {r['call']: r['label'] for r in rows if 'label' in r}
        self.assertEqual(sorted(set(labels.values())),
                         ['abci_stream send tcp greeting', 'send gossip rpc request', 'write evm kv batch'])
        self.assertTrue(all(r['chunk_timeout_selected'] == 20.0 for r in rows if 'label' in r))
        self.assertNotIn('0x203b588', labels)

    def test_packet_matches_regeneration(self):
        expected = json.loads(PACKET.read_text())
        got = dict(self.result, target_sha256=load()['sha256'])
        self.assertEqual(json.loads(json.dumps(got, sort_keys=True)), expected)


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
        with self.assertRaisesRegex(tw.EvidenceError, pattern):
            tw.analyse(self.mutated(va, new))

    def test_threshold_immediate(self):
        self.refuses(0x43a181b + 3, b'\x02', 'threshold signature occurs 0')

    def test_port_immediate(self):
        self.refuses(0x4b375d5 + 1, b'\x9f', 'port-mask census')

    def test_capacity_multiplier(self):
        self.refuses(0x204b3d1 + 1, b'\x6f', 'capacity signature occurs 0')

    def test_prefix_store(self):
        self.refuses(0x4b37642, b'\x90\x90\x90', 'prefix signature occurs 0')

    def test_table_split_immediate(self):
        self.refuses(0x204b43a + 3, b'\xfe', 'table_split signature occurs 0')

    def test_small_table_size(self):
        self.refuses(0x43a18d2 + 2, b'\x10', 'table_small signature occurs 0')

    def test_compressed_flag_value(self):
        self.refuses(0x204b6b9 + 2, b'\x02', 'flag_compressed signature occurs 0')

    def test_flag_store_register(self):
        self.refuses(0x204b770 + 2, b'\x68', 'flag register r13')

    def test_bswap_removed(self):
        self.refuses(0x43a1bbf, b'\x90\x90\x90', 'be_length signature occurs 0')

    def test_chunk_size(self):
        self.refuses(0x4b379ba + 7, b'\x01', 'chunk_size signature occurs 0')

    def test_default_timeout_constant(self):
        va = 0x204bfa2
        disp = struct.unpack('<i', load()['img'].read(va + 4, 4))[0]
        self.refuses(va + 4, struct.pack('<i', disp + 8), 'default chunk timeout is')

    def test_timeout_seconds_field(self):
        self.refuses(0x204bf97 + 4, b'\x40', 'not loaded from flag field \\+ 8')

    def test_injected_port_compare(self):
        self.refuses(0x3723000, bytes.fromhex('3d9e0f0000'), 'port-mask census')

    def test_compressor_slot_relocation(self):
        img = load()['img']
        rela = next(s for s in img.secs if s['name'] == '.rela.dyn')
        for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
            where, info, addend = struct.unpack_from('<QQq', img.data, pos)
            if where == tw.SLOTS['compress_u16_table']:
                data = bytearray(img.data)
                data[pos + 16:pos + 24] = struct.pack('<q', addend + 16)
                with self.assertRaisesRegex(tw.EvidenceError, 'relocation changed'):
                    tw.analyse(bytes(data))
                return
        self.fail('compressor slot relocation not found')

    def test_wrapper_flag(self):
        self.refuses(0x204b244 + 4, b'\x01', 'wrapper tag')

    def test_inline_pair_flag(self):
        self.refuses(0x4b3759a, b'\xb0\x01', 'flag = 0')

    def test_caller_seconds_load_removed(self):
        self.refuses(0x203b54b, b'\x90' * 10, 'writer call 0x203b588: 0 movabs 60.0 loads')

    def test_caller_base_moved(self):
        self.refuses(0x203b57b + 3, b'\x10', 'writer call 0x203b588: no unique store')

    def test_injected_direct_call(self):
        va = 0x3723000
        rel = struct.pack('<i', tw.WRITERS[0] - (va + 5))
        self.refuses(va, b'\xe8' + rel, 'writer call 0x3723000')

    def test_caller_label_length(self):
        self.refuses(0x2039993 + 2, b'\x16', 'label length in r8d')

    def test_caller_flag_is_read_not_assumed(self):
        """Sensitivity: flipping one zero flag to 1 must move that call to the 60 s selection."""
        result = tw.analyse(self.mutated(0x203433f + 7, b'\x01'))
        selected = [r['call'] for r in result['callers'] if r.get('chunk_timeout_selected') == 60.0]
        self.assertEqual(selected, ['0x2034387', '0x203b588'])

    def test_truncated_elf(self):
        with self.assertRaises(ValueError):
            tw.analyse(load()['data'][:4096])


class Model(unittest.TestCase):
    def test_div100_sequence(self):
        rng = random.Random(94)
        values = [0, 1, 99, 100, 101, 399, 400, (1 << 64) // 110] + [rng.randrange(1 << 64) for _ in range(2000)]
        for x in values:
            self.assertEqual(tw.binary_div100(x), x // 100, x)

    def test_compression_predicate(self):
        self.assertFalse(tw.compresses(0x400, 4001))
        self.assertTrue(tw.compresses(0x401, 4001))
        self.assertFalse(tw.compresses(0x401, 3998))
        self.assertFalse(tw.compresses(0x401, 3999))
        self.assertTrue(tw.compresses(0x401, 3997))

    def test_header_prefix_and_chunks(self):
        self.assertEqual(tw.frame_header(0x01020304, True), bytes.fromhex('0102030401'))
        self.assertIsNone(tw.frame_header(1 << 32, False))
        self.assertEqual(tw.size_prefix((1 << 32) + 5), bytes.fromhex('05000000'))
        self.assertEqual(tw.reference_prefix((1 << 32) + 5), bytes.fromhex('ffffffff'))
        self.assertEqual(tw.chunks(tw.CHUNK + 1), [tw.CHUNK, 1])
        self.assertEqual(tw.model_summary()['prefix_differs'], 2)


if __name__ == '__main__':
    unittest.main()
