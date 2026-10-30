"""Controls for tools/tcp_frame_read_static.py (node #94 net_utils TCP frame reads)."""
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import tcp_frame_read_static as tfr  # noqa: E402
from artifacts import check  # noqa: E402

BINARY = ROOT / tfr.TARGET
PACKET = ROOT / 'research/work-items/transport-tcp-frame-read-94/records.json'
CACHE = {}


def load():
    if not CACHE:
        identity = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                        if i['path'] == tfr.TARGET)
        check(BINARY, identity)
        CACHE['data'] = BINARY.read_bytes()
        CACHE['img'] = tfr.Image(CACHE['data'])
        CACHE['result'] = tfr.analyse(CACHE['data'])
        CACHE['sha256'] = identity['sha256']
    return CACHE


@unittest.skipUnless(BINARY.exists(), 'pinned node #94 binary not present')
class Results(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        c = load()
        cls.result, cls.img = c['result'], c['img']

    def test_five_copies_and_census(self):
        self.assertEqual([c['fde'][0] for c in self.result['copies']],
                         ['0x2049950', '0x43a0260', '0x4b72900', '0x22615b0', '0x4744160'])
        census = self.result['census']
        for name in ('chunk_cap_sites', 'gate_compares', 'over_limit_desc', 'over_limit_len', 'progress_warn'):
            self.assertEqual(len(census[name]), 5, name)
        self.assertEqual(len(census['early_eof']), 7)
        self.assertEqual(len(census['read_rs_location_records']), 20)
        self.assertEqual(sorted({r['line'] for r in census['read_rs_location_records'].values()}), [19, 24, 35, 51])

    def test_header_layout_and_eof(self):
        for helper in self.result['header_helpers'].values():
            self.assertEqual((helper['buffer_len'], helper['length_dword_offset'], helper['flag_byte_offset']), (5, 0x50, 0x54))
        inline = [c['header'] for c in self.result['copies'] if 'bswap' in c['header']]
        self.assertEqual(len(inline), 3)
        for h in inline:
            self.assertEqual(int(h['flag_offset'], 16) - int(h['frame_offset'], 16), 4)
        for row in self.result['early_eof_sites']:
            self.assertEqual((row['kind_imm'], row['message_len'], row['callee']), (37, 9, '0x4edac60'))

    def test_limit_flag_chunk_and_timeouts(self):
        for c in self.result['copies']:
            self.assertTrue(all(l['accepted_target'] == c['flag_alloc']['flag_compare'] for l in c['limits']))
            self.assertEqual(c['flag_alloc']['predicate'], 'flag == 1')
            self.assertEqual(c['flag_alloc']['alloc_callee'], '0x54c0780')
            self.assertEqual(c['decompress']['callee'], '0x3d1abc0')
            self.assertEqual({k: (v['descriptor'], v['seconds']) for k, v in c['timeouts'].items()},
                             {'header': ('tcp_bytes', 40.0), 'chunk': ('tcp_read_exact', 20.0)})
            self.assertIn('35', c['read_rs_locations'])
            self.assertIn('51', c['read_rs_locations'])
        self.assertEqual(sum(len(c['limits']) for c in self.result['copies']), 6)

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
        with self.assertRaisesRegex(tfr.EvidenceError, pattern):
            tfr.analyse(self.mutated(va, new))

    def test_flag_immediate(self):
        self.refuses(0x4b73215 + 3, b'\x02', 'no cmp r8,1')

    def test_limit_branch_inverted(self):
        self.refuses(0x204a0b9 + 1, b'\x82', 'accepted length does not reach the flag test')

    def test_limit_compare_register(self):
        self.refuses(0x2263e9d + 2, b'\x6c', r'no cmp \[max_len\], r14')

    def test_chunk_cap_immediate(self):
        self.refuses(0x43a12ff + 2, b'\x01', 'min\\(remaining, 4_000_000\\)')

    def test_gate_branch_kind(self):
        self.refuses(0x474522a + 1, b'\x86', 'gate jb')

    def test_progress_rejoin(self):
        self.refuses(0x4b73a1b + 1, b'\x00\x00\x00\x00', 'does not rejoin the remaining check')

    def test_header_bswap(self):
        self.refuses(0x204873a, b'\x90\x90', 'u32 load, bswap, flag byte')

    def test_inline_flag_offset(self):
        self.refuses(0x4b731f5 + 4, b'\xa5', 'flag byte is not length dword \\+ 4')

    def test_eof_kind(self):
        self.refuses(0x2263e22 + 7 + 6, b'\x26', 'early-eof io::Error')

    def test_over_limit_lea_retarget(self):
        self.refuses(0x47471ef + 3, b'\x00', 'over_limit_desc')

    def test_decompress_slot(self):
        self.refuses(0x204aad2 + 2, b'\x40', 'slot')

    def test_injected_chunk_cap_outside_copies(self):
        self.refuses(0x3723000, tfr.CHUNK_CAP, 'chunk-cap census 6')

    def test_location_path(self):
        self.refuses(tfr.SOURCE_VA + 40, b'X', 'read.rs path literal changed')

    def test_truncated_elf(self):
        with self.assertRaises(ValueError):
            tfr.analyse(load()['data'][:4096])


class Model(unittest.TestCase):
    def test_admission_boundary(self):
        self.assertTrue(tfr.admitted(100, 100))
        self.assertFalse(tfr.admitted(101, 100))
        self.assertTrue(tfr.admitted(0, 0))
        self.assertFalse(tfr.admitted(1 << 32, 1 << 40))

    def test_only_flag_one_is_compressed(self):
        self.assertEqual([f for f in range(256) if tfr.compressed(f)], [1])

    def test_chunk_plans(self):
        self.assertEqual(tfr.chunk_plan(0), [])
        self.assertEqual(tfr.chunk_plan(5), [(5, False)])
        self.assertEqual(tfr.chunk_plan(tfr.CHUNK), [(tfr.CHUNK, True)])
        self.assertEqual(tfr.chunk_plan(tfr.CHUNK + 1), [(tfr.CHUNK, True), (1, True)])
        self.assertEqual(tfr.reference_plan(tfr.CHUNK + 1), [(tfr.CHUNK, True), (1, False)])

    def test_reference_differs_only_by_final_chunk_log(self):
        for n in tfr.MODEL_LENGTHS:
            ours, ref = tfr.chunk_plan(n), tfr.reference_plan(n)
            self.assertEqual([c for c, _ in ours], [c for c, _ in ref])
            self.assertEqual(ours[:-1], ref[:-1])
            if n >= tfr.CHUNK:
                self.assertEqual((ours[-1][1], ref[-1][1]), (True, False))


if __name__ == '__main__':
    unittest.main()
