import tempfile
import unittest
from pathlib import Path

from tools import remaining_edges_static as packet


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / 'artifacts/node/115/hl-node'
PACKET_DIR = (ROOT / 'research/work-items/'
              'RE-006-node115-remaining-edges')


def _flip(data, offset):
    mutated = bytearray(data)
    mutated[offset] ^= 0xFF
    return bytes(mutated)


def _file_offset(data, va):
    """File offset of a virtual address, via the section table."""
    for sec in packet.sections(data):
        if sec['type'] != 8 and sec['address'] <= va \
                < sec['address'] + sec['size']:
            return sec['offset'] + (va - sec['address'])
    raise AssertionError(f'no section covers {va:#x}')


class RemainingEdgesPacketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = ARTIFACT.read_bytes()

    def test_generates_committed_packet_byte_for_byte(self):
        with tempfile.TemporaryDirectory() as tmp:
            packet.generate(self.data, tmp)
            generated = {p.name: p.read_bytes()
                         for p in Path(tmp).iterdir()}
        committed = {p.name: p.read_bytes()
                     for p in PACKET_DIR.iterdir()
                     if p.name != 'README.md'
                     and p.name != 'MANIFEST.sha256'}
        self.assertEqual(set(generated), set(committed))
        for name in generated:
            self.assertEqual(generated[name], committed[name], name)

    def test_counters_and_verdicts(self):
        with tempfile.TemporaryDirectory() as tmp:
            records = packet.generate(self.data, tmp)
        counters = records['counters']
        self.assertEqual(counters['bodies'], 30)
        self.assertEqual(counters['exported_bodies'], 21)
        self.assertEqual(counters['census_sites'], 89)
        self.assertEqual(counters['census_fdes'], 43)
        self.assertEqual(counters['branchless_sites'], 22)
        self.assertEqual(counters['flag_register_sites'], 1)
        self.assertEqual(counters['panic_raw_refs'], 11085)
        self.assertEqual(counters['panic_caller_fdes'], 6969)
        self.assertEqual(counters['panic_validated_small_sites'], 150)

        edge3 = records['edge3_branchless']
        e3c = edge3['counters']
        self.assertEqual(e3c['branch_handled_sites'], 67)
        self.assertEqual(e3c['subset_2608_rule'], 15)
        self.assertEqual(e3c['sign_test_first_use'], 16)
        self.assertEqual(e3c['flag_counts'],
                         {'0': 64, '1': 24, 'register': 1,
                          'unknown': 0})
        self.assertEqual(e3c['class_counts'], {
            'zeroed-dst': 12, 'rdx-self-zero': 4,
            'copy-zero-on-eq': 2, 'rdx-zero-on-eq': 3,
            'rax-zero-return': 1})
        for site in edge3['sites'].values():
            self.assertEqual(site['flag'], 0)
            self.assertIn('zero_row', site)

        edge4 = records['edge4_flag_site']
        self.assertEqual(edge4['site'], '0x3698891')
        self.assertEqual(edge4['r14_writes_in_window'],
                         ['0x3698770', '0x36987ac'])
        self.assertEqual(edge4['bindings']['rcx']['reg'], 'r14b')
        self.assertEqual(edge4['bindings']['rdx']['src'], '0x10(%rbp)')

        edge5 = records['edge5_panic_callee']
        census = edge5['caller_census']
        self.assertEqual(census['kinds'], {'call': 11085})
        self.assertEqual(census['validated_small_fdes'], 150)
        self.assertEqual(census['stub_shape_fdes'], ['0x1680c10'])
        self.assertEqual(census['rela_addends_for_fmt0'],
                         [['0x64df730', 8]])
        self.assertEqual(census['e8_direct_calls'],
                         {'0x1680e60': 0, '0x1680e80': 0})
        for body in edge5['chain'].values():
            self.assertEqual(body['rets'], [])
            self.assertEqual(body['byte_after'], 'cc')
        self.assertEqual(edge5['plt']['target_addend'], '0x16a0650')
        self.assertEqual(edge5['plt']['section'], '.plt')

    def test_wrong_artifact_rejected(self):
        with self.assertRaises(packet.PacketError):
            packet.analyze(b'\x00' * packet.NODE_SIZE)

    def test_mutation_panic_shim_row_rejected(self):
        offset = _file_offset(self.data, 0x1680E64)
        with self.assertRaises(packet.PacketError):
            packet.analyze(_flip(self.data, offset))

    def test_mutation_flag_write_row_rejected(self):
        offset = _file_offset(self.data, 0x3698770)
        with self.assertRaises(packet.PacketError):
            packet.analyze(_flip(self.data, offset))

    def test_mutation_branchless_cmov_row_rejected(self):
        offset = _file_offset(self.data, 0x2BFD1A9)
        with self.assertRaises(packet.PacketError):
            packet.analyze(_flip(self.data, offset))


if __name__ == '__main__':
    unittest.main()
