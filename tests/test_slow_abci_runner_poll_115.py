"""Node #115 slow abci runner pair, driver thread and constant blocks. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import slow_abci_runner_poll_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-slow-abci-runner-poll-115/evidence.json'


class SlowAbciRunnerPollTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_censuses(self):
        self.assertEqual(self.result['slow_driver_start']['slot_0x64e7458_calls'], ['0x2aed2f5', '0x2cb8915'])
        self.assertEqual(self.result['runner_pair']['slot_0x64e7440_calls'], ['0x2aec3ef', '0x2cb7a0f'])
        self.assertEqual(self.result['constant_blocks']['imm32_525600_sites'],
                         ['0x434b990', '0x5649c52', '0x5649c92'])
        self.assertEqual(self.result['slow_driver_start']['vtable']['call'], '0x5a34440')
        self.assertEqual(self.result['sha256'], packet.SHA256)
        self.assertFalse(self.result['gates_changed'])

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

    def test_return_pair_rejected(self):
        # mov rdx, r15 -> mov rdx, r14 (slow Arc no longer returned)
        self._rejects(self._patch(0x5a6c681 + 2, b'\xf2'))

    def test_slow_arc_size_rejected(self):
        # mov edi, 0xb80 -> 0xb90
        self._rejects(self._patch(0x5a6c655 + 1, b'\x90'))

    def test_thread_name_rejected(self):
        # 'node slow abci_state driver' -> 'node fast ...'
        self._rejects(self._patch(0x93afe8 + 5, b'f'))

    def test_vtable_size_rejected(self):
        # vtable size 0xb8 -> 0xb0
        self._rejects(self._patch(0x64b8a08, b'\xb0'))

    def test_apply_block_flag_rejected(self):
        # mov edx, 1 -> mov edx, 0
        self._rejects(self._patch(0x5a34f08 + 1, b'\x00'))

    def test_pool_offset_rejected(self):
        # mov rsi, [rax+0xb58] -> [rax+0xb50]
        self._rejects(self._patch(0x5a34e26 + 3, b'\x50'))

    def test_constant_rejected(self):
        # [r14+0xb30] = 525600 -> 525601
        self._rejects(self._patch(0x5649c4b + 7, struct.pack('<I', 525601)))

    def test_lock_helper_string_rejected(self):
        # base/src/lock_id.rs -> base/src/lock_idDrs at the 0x4f19fa0 reference
        target = packet.rip_target(self.data, 0x4f1a239, b'\x48\x8d\x05', 7)
        self._rejects(self._patch(target + 16, b'D'))


if __name__ == '__main__':
    unittest.main()
