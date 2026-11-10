"""Node #115 slow abci step wrapper 0x59ec200. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import slow_abci_step_wrapper_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-slow-abci-step-wrapper-115/evidence.json'


class SlowAbciStepWrapperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_chain_and_callers(self):
        self.assertEqual(self.result['callers']['0x59ec200'], ['0x4fcae48'])
        self.assertEqual(self.result['callers']['0x5a04e40'], ['0x5618630'])
        self.assertIn('0x5a07ec0', self.result['inner_0x5a04e40']['step'])
        self.assertEqual(self.result['sha256'], packet.SHA256)
        self.assertFalse(self.result['gates_changed'])

    def test_freeze_changed_model(self):
        self.assertEqual(self.result['inner_0x5a04e40']['freeze_changed_samples'],
                         {'None -> None': 0, 'None -> Some(h)': 1, 'Some(h) -> None': 1,
                          'Some(h) -> Some(h)': 0, 'Some(h) -> Some(h2)': 1})

    def test_committed_packet_matches(self):
        self.assertEqual(packet.render(self.result), PACKET.read_bytes())
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(packet.main(['--out', tmp, '--check']), 0)

    def _patch(self, va, new):
        sec = next(s for s in sections(self.data)
                   if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        off = sec['offset'] + va - sec['address']
        broken = bytearray(self.data)
        broken[off:off + len(new)] = new
        return bytes(broken)

    def _rejects(self, data):
        with self.assertRaises(ValueError):
            packet.bind(data, self.fdes)

    def test_visor_gate_rejected(self):
        # cmp byte [rsp+0x3b8], 0 -> cmp byte [rsp+0x3b9], 0
        self._rejects(self._patch(0x59ec2c7 + 3, b'\xb9'))

    def test_freeze_equal_test_rejected(self):
        # jb 0x59ed3db -> jbe
        self._rejects(self._patch(0x59ec3a9 + 1, b'\x86'))

    def test_freeze_some_tag_rejected(self):
        # cmp dword [rax+0x10e8], 1 -> 2
        self._rejects(self._patch(0x59ec389 + 6, b'\x02'))

    def test_changed_setne_rejected(self):
        # setne dl -> sete dl
        self._rejects(self._patch(0x5a05ffa + 1, b'\x94'))

    def test_result_byte_offset_rejected(self):
        # mov [rax+0xf8], dl -> [rax+0xf9]
        self._rejects(self._patch(0x5a060d4 + 2, b'\xf9'))

    def test_step_call_rejected(self):
        # call 0x5a07ec0 -> call 0x5a07ec1
        self._rejects(self._patch(0x5a05fc9 + 1, b'\xf3'))

    def test_digest_mask_rejected(self):
        # cmp eax, 0xffff -> 0xfffe
        self._rejects(self._patch(0x5a05d23 + 1, b'\xfe'))

    def test_assert_string_rejected(self):
        # freeze_height >= -> freeze_height <=
        self._rejects(self._patch(0x929b14 + 32, b'<'))


if __name__ == '__main__':
    unittest.main()
