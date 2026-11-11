"""Node #115 shared value observer: who sets and who reads the x50 flag. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
import abci_step_observer_x50_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-abci-step-observer-x50-115/evidence.json'


class AbciStepObserverX50Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_closure_shape(self):
        closure = self.result['flag_clearing_closure']
        self.assertEqual(closure['vtable']['size'], 16)
        self.assertEqual(closure['vtable']['call_once'], '0x47832b0')
        self.assertEqual(closure['vtable']['call'], '0x4784980')
        self.assertEqual(closure['builder']['slot_calls'], ['0x567bbac'])
        self.assertEqual(self.result['sha256'], packet.SHA256)
        self.assertFalse(self.result['gates_changed'])

    def test_censuses(self):
        stores = self.result['flag_stores']
        self.assertEqual(len(stores['census']), 8)
        self.assertEqual(len(stores['value_1']), 5)
        self.assertEqual(self.result['flag_reads']['census'], ['0x15475b1', '0x15486e6'])
        names = [s['name_inferred'] for s in self.result['flag_setters']['sites']]
        self.assertEqual(names.count('profiled_mutex/{}/compute/{}'), 4)
        self.assertEqual(names.count('profiled_rw_lock/{}/{}'), 1)

    def test_committed_packet_matches(self):
        self.assertEqual(packet.render(self.result), PACKET.read_bytes())
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(packet.main(['--out', tmp, '--check']), 0)

    def _patch(self, va, new):
        broken = bytearray(self.data)
        off, old = packet.read_va(self.data, va, len(new))
        self.assertEqual(len(old), len(new))
        broken[off:off + len(new)] = new
        return bytes(broken)

    def _rejects(self, data):
        with self.assertRaises(ValueError):
            packet.bind(data, self.fdes)

    def test_closure_store_value_rejected(self):
        # call_once clears the flag: 0 -> 1
        self._rejects(self._patch(0x47832e9 + 7, b'\x01'))

    def test_closure_inner_slot_rejected(self):
        # call [rcx+0x28] -> call [rcx+0x20]
        self._rejects(self._patch(0x47849a5 + 2, b'\x20'))

    def test_vtable_call_slot_rejected(self):
        # vtable +0x28 relocation addend points one byte later (in the copied image only
        # the relocation table changes, so patch the RELA addend)
        relocs = packet.relocations(self.data)
        for sec in packet.sections(self.data):
            if sec['type'] != 4:
                continue
            for i in range(sec['size'] // 24):
                off = sec['offset'] + i * 24
                va, info, addend = struct.unpack_from('<QQq', self.data, off)
                if va == packet.VTABLE + 0x28:
                    broken = bytearray(self.data)
                    struct.pack_into('<q', broken, off + 16, addend + 1)
                    self._rejects(bytes(broken))
                    return
        self.fail(f'no relocation at vtable +0x28 among {len(relocs)}')

    def test_template_rejected(self):
        # profiled_mutex/ -> profiled_mutez/
        self._rejects(self._patch(packet.MUTEX_TEMPLATE + 14, b'z'))

    def test_xmm0_constant_rejected(self):
        self._rejects(self._patch(packet.ONE, struct.pack('<d', 2.0)))

    def test_multiply_factor_rejected(self):
        # mov ecx, 50 -> 51
        self._rejects(self._patch(0x15475ba + 1, b'\x33'))

    def test_record_offset_rejected(self):
        # mov [rsp+0x17c], r15b -> [rsp+0x17d]
        self._rejects(self._patch(0x1548873 + 4, b'\x7d'))

    def test_r15_clobber_rejected(self):
        # replace the movsd at 0x15487ff with mov r15, rax + padding
        self._rejects(self._patch(0x15487ff, bytes.fromhex('4989c7909090')))

    def _pad(self, size):
        pad = packet.OBSERVER_END
        _, run = packet.read_va(self.data, pad, size)
        if run != b'\xcc' * size:
            self.skipTest('no int3 padding after the observer FDE')
        return pad

    def test_extra_flag_read_rejected(self):
        # cmp byte [rbx+0x25c], 1 in the int3 padding
        self._rejects(self._patch(self._pad(7), bytes.fromhex('80bb5c02000001')))

    def test_extra_flag_store_rejected(self):
        # mov byte [r14+0x25c], 1 in the int3 padding
        self._rejects(self._patch(self._pad(8), bytes.fromhex('41c6865c02000001')))

    def test_extra_vtable_lea_rejected(self):
        pad = self._pad(7)
        disp = packet.VTABLE - (pad + 7)
        self._rejects(self._patch(pad, b'\x48\x8d\x05' + struct.pack('<i', disp)))


if __name__ == '__main__':
    unittest.main()
