"""Controls for tools/tcp_lz4_frame_static.py (node #94 TCP LZ4 frame payloads)."""
import json
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import tcp_lz4_frame_static as lz  # noqa: E402
from artifacts import check  # noqa: E402

BINARY = ROOT / lz.TARGET
PACKET = ROOT / 'research/work-items/transport-lz4-frame-94/records.json'
CACHE = {}


def load():
    if not CACHE:
        identity = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                        if i['path'] == lz.TARGET)
        check(BINARY, identity)
        CACHE['data'] = BINARY.read_bytes()
        CACHE['img'] = lz.Image(CACHE['data'])
        CACHE['result'] = lz.analyse(CACHE['data'])
        CACHE['sha256'] = identity['sha256']
    return CACHE


@unittest.skipUnless(BINARY.exists(), 'pinned node #94 binary not present')
class Results(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = load()['result']

    def test_binding_and_census(self):
        census = self.result['census']
        self.assertEqual(census['slot_calls'], ['0x204aad2', '0x2264edb', '0x43a13e2', '0x47470c9', '0x4b73a4d'])
        self.assertEqual(census['relocations_to_decompressor'], ['0x5773810'])
        self.assertEqual(self.result['decompressor']['fde'], ['0x3d1abc0', '0x3d1b62b'])
        self.assertEqual({r['path'].split('/')[0] for r in self.result['lz4_flex_locations'].values()}, {'0.11.6'})

    def test_prefix_limit_and_allocation(self):
        e = self.result['entry']
        self.assertEqual(e['short_input']['rejects_len_at_most'], 3)
        self.assertEqual(e['short_input']['error'], 'ExpectedAnotherByte')
        self.assertEqual((e['prefix']['width_bits'], e['prefix']['byte_order']), (32, 'little'))
        self.assertEqual(e['limit']['rejects'], 'max_len < uncompressed_size')
        self.assertTrue(e['limit']['equal_admitted'])
        self.assertEqual(e['allocation']['callee'], '0x54c0780')
        self.assertEqual([a['name'] for a in e['over_limit']['arguments_in_order']],
                         ['buf.len()', 'uncompressed_size', 'max_len'])
        self.assertFalse(self.result['ok']['length_equality_checked'])

    def test_error_tags_follow_declaration_order(self):
        self.assertEqual([(t['tag'], t['error']) for t in self.result['errors']['tags']],
                         list(enumerate(lz.DECOMPRESS_ERRORS)))
        self.assertEqual([r['location']['line'] for r in self.result['source_bindings']], [39, 190, 194, 196, 227])

    def test_every_caller_passes_admission_max_len(self):
        rows = self.result['callers']
        self.assertEqual(len(rows), 5)
        for r in rows:
            self.assertTrue(r['same_max_len_as_admission'])
        self.assertEqual(rows[-1]['base_link'], '0x4747039')

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
        with self.assertRaisesRegex(lz.EvidenceError, pattern):
            lz.analyse(self.mutated(va, new))

    def test_short_input_threshold(self):
        self.refuses(0x3d1abd9 + 3, b'\x04', 'input length compare with 3')

    def test_limit_branch_inverted(self):
        self.refuses(0x3d1abfb + 1, b'\x83', 'no jb at 0x3d1abfb')

    def test_limit_operands_swapped(self):
        self.refuses(0x3d1abf8 + 2, b'\xcb', r'cmp rcx\(max_len\)')

    def test_prefix_byte_swap_inserted(self):
        self.refuses(0x3d1abee, b'\x0f\xcb', 'little-endian u32 prefix load')

    def test_alloc_slot(self):
        self.refuses(0x3d1ac13 + 2, b'\x87', 'allocation slot changed|unrelocated slot')

    def test_offset_zero_tag(self):
        self.refuses(0x3d1b2ef + 2, b'\x05', 'error tag 3')

    def test_offset_out_of_bounds_branch(self):
        self.refuses(0x3d1ad58 + 1, b'\x83', 'no jb at 0x3d1ad58')

    def test_over_limit_argument_order(self):
        self.refuses(0x3d1b4fe + 4, b'\xa8', 'over-limit argument array')

    def test_over_limit_template(self):
        self.refuses(lz.TEMPLATES['over_limit'][0] + 5, b'X', 'template over_limit changed')

    def test_output_length_clamp(self):
        self.refuses(0x3d1b2d2 + 2, b'\x42', r'len = min')

    def test_caller_limit_displacement(self):
        self.refuses(0x2264ec4 + 4, b'\x30', 'not the admission max_len')

    def test_caller_flag_displacement(self):
        self.refuses(0x4b73a20 + 2, b'\x51', 'flag slot is not max_len')

    def test_inline_copy_base_link(self):
        self.refuses(0x4747039 + 2, b'\xce', 'admission base copied into call base')

    def test_injected_extra_slot_call(self):
        va = 0x3723000
        disp = lz.SLOT - (va + 6)
        self.refuses(va, b'\xff\x15' + struct.pack('<i', disp), 'decompressor slot call census')

    def test_lz4_version_in_location_path(self):
        self.refuses(0x1ed5fb + len(lz.LZ4_PATH) + 5, b'5', 'versions referenced|not an lz4_flex record')

    def test_truncated_elf(self):
        with self.assertRaises(ValueError):
            lz.analyse(load()['data'][:4096])


class Model(unittest.TestCase):
    def test_boundaries(self):
        self.assertEqual(lz.payload_outcome(3, 0, 16), 'ExpectedAnotherByte')
        self.assertEqual(lz.payload_outcome(4, 16, 16), 'decode')
        self.assertEqual(lz.payload_outcome(4, 17, 16), 'lz4 bytes over limit')

    def test_reference_predicates_agree(self):
        self.assertEqual(lz.model_summary()['predicate_disagreements'], 0)


if __name__ == '__main__':
    unittest.main()
