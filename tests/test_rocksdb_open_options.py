import contextlib
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import rocksdb_open_options as tool  # noqa: E402

PACKET = ROOT / 'research/work-items/RE-009-rocksdb-open-options-94'
SOURCE = ROOT / 'tools/rocksdb_open_options.py'


def setup_class(cls):
    cls.data = bytearray(tool.load())
    cls.img = tool.Image(cls.data)
    cls.index = tool.function_index(cls.data)
    cls.files = tool.build(bytes(cls.data))
    cls.report = json.loads(cls.files['open-options.json'])


class RocksDbOpenOptions(unittest.TestCase):
    setUpClass = classmethod(setup_class)

    def patched(self, va, new):
        """Corrupt bytes in place for one check, then restore them."""
        off = self.img.offset(va, len(new))
        old = bytes(self.data[off:off + len(new)])
        self.assertNotEqual(old, new)
        self.data[off:off + len(new)] = new
        try:
            yield
        finally:
            self.data[off:off + len(new)] = old

    patched = contextlib.contextmanager(patched)

    def flip(self, va):
        return bytes([self.img.read(va, 1)[0] ^ 1])

    def test_committed_files_match_regeneration(self):
        for name, text in self.files.items():
            self.assertEqual((PACKET / name).read_text(encoding='utf-8'), text)

    def test_manifest_lists_every_generated_file(self):
        rows = dict(reversed(line.split('  ')) for line in (PACKET / 'MANIFEST.sha256').read_text().splitlines())
        self.assertEqual(sorted(rows), sorted(p.name for p in PACKET.iterdir() if p.name != 'MANIFEST.sha256'))
        for name, digest in rows.items():
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest)

    def test_generation_is_repeatable(self):
        self.assertEqual(tool.build(bytes(self.data)), self.files)

    def test_tool_runs_no_external_program(self):
        source = SOURCE.read_text(encoding='utf-8')
        for word in ('subprocess', 'os.system', 'popen', 'objdump', 'readelf'):
            self.assertNotIn(word, source.replace('objdump/readelf', ''))

    def test_profiles(self):
        state, checkpoint = self.report['profiles']['state'], self.report['profiles']['checkpoint']
        self.assertEqual((state['default_cache_gib'], state['block_size']), (2, 0x4000))
        self.assertEqual((checkpoint['default_cache_gib'], checkpoint['block_size']), (16, 0x8000))
        self.assertEqual(state['write_buffer_size'], 0x8000000)
        self.assertEqual(checkpoint['write_buffer_size'], 0x8000000)
        self.assertEqual(state['create_if_missing_esi'], 1)
        self.assertEqual(checkpoint['create_if_missing_esi'], 1)

    def test_call_order_is_the_same_in_both_wrappers(self):
        orders = [[row['role'] for row in self.report['profiles'][name]['ffi_calls_in_address_order']]
                  for name in tool.WRAPPERS]
        self.assertEqual(orders[0], orders[1])
        self.assertEqual(orders[0][:len(tool.HOT_ORDER)], tool.HOT_ORDER)

    def test_no_unlisted_setter_between_create_and_open(self):
        allocator, arc_drop = '0x54c06b0', '0x4ea9d90'
        tail = ['set_block_size', 'options_create', 'set_create_if_missing', 'set_write_buffer_size', 'set_table_factory']
        head = ['block_options_create', 'lru_cache_create', allocator, 'set_block_cache', arc_drop]
        state = self.report['profiles']['state']
        checkpoint = self.report['profiles']['checkpoint']
        names = lambda profile: [row['role'] or row['target'] for row in profile['all_call_positions_create_to_open']]
        self.assertEqual(names(state), head + tail + ['0x3c98770'])
        self.assertEqual(names(checkpoint), head + tail + [arc_drop, '0x4b70480'])

    def test_slot_only_reach_of_tuning_setters(self):
        for role in ('set_block_size', 'set_write_buffer_size', 'set_table_factory', 'set_block_cache'):
            self.assertEqual(self.report['census']['sites_by_role'][role], 2, role)
        self.assertEqual(self.report['census']['options_create_owners'], 11)
        self.assertEqual(self.report['census']['owners_with_all_three_tuning_setters'], ['0x3421980', '0x42c70c0'])

    def test_field_fingerprints(self):
        defaults = self.report['constructor_defaults']
        self.assertEqual(defaults['block_options']['plus_0x60_default_i32'], 10)
        self.assertEqual(defaults['block_options']['plus_0x64_default_i32'], 16)
        self.assertEqual(defaults['options']['write_buffer_setter_offset_minus_base'], 0x218)
        self.assertEqual(defaults['options']['table_factory_setter_offset_minus_base'], 0x2b8)
        self.assertEqual(defaults['lru_cache']['pool_ratio_xmm0'], 0.5)

    def test_validators_and_gate(self):
        self.assertEqual(self.report['validators']['bundle_names'], ['Exchange', 'Rpc', 'EvmState'])
        self.assertEqual(self.report['validators']['state_forbids'], ['EvmState'])
        self.assertEqual(self.report['checkpoint_gate']['first_word_equals'], '0x8000000000000001')
        self.assertEqual(self.report['callers']['state']['skips_bundle_byte'], 3)

    def test_paths_have_no_build_prefix(self):
        for row in self.report['locations'].values():
            self.assertFalse(row['file'].startswith('/'), row)

    def test_capacity_edges(self):
        self.assertEqual(tool.cache_capacity(None, 2), 2 << 30)
        self.assertEqual(tool.cache_capacity(None, 16), 16 << 30)
        self.assertEqual(tool.cache_capacity(0, 2), 0)
        self.assertEqual(tool.cache_capacity((1 << 34) - 1, 2), ((1 << 34) - 1) << 30)
        self.assertEqual(tool.cache_capacity(1 << 34, 2), (1 << 64) - 1)
        self.assertLess(tool.cache_capacity((1 << 34) - 1, 2), 1 << 64)

    def test_digest_control(self):
        damaged = bytearray(self.data)
        damaged[0x1000] ^= 1
        with self.assertRaises(ValueError):
            tool.check_digest(damaged)

    def test_address_controls(self):
        bss = self.img.section('.bss')
        with self.assertRaises(ValueError):
            self.img.read(bss['address'], 1)
        with self.assertRaises(ValueError):
            self.img.read(1 << 40, 1)
        with self.assertRaises(ValueError):
            tool.extent(self.index, tool.WRAPPERS['state']['start'] + 1)

    def test_setter_body_controls(self):
        for role in tool.SETTER_BODIES:
            target = tool.FFI[role][1] + 4
            with self.patched(target, self.flip(target)):
                with self.assertRaises(ValueError):
                    tool.check_setters(self.img)

    def test_relocated_slot_control(self):
        slot = tool.FFI['set_block_size'][0]
        old = self.img.rel[slot]
        self.img.rel[slot] = old + 0x10
        try:
            with self.assertRaises(ValueError):
                tool.check_slots(self.img)
        finally:
            self.img.rel[slot] = old

    def test_write_buffer_offset_control(self):
        target = tool.FFI['set_write_buffer_size'][1] + 7
        with self.patched(target, b'\x05'):
            with self.assertRaises(ValueError):
                tool.check_setters(self.img)

    def test_block_size_receiver_control(self):
        site = int(self.report['profiles']['state']['ffi_calls_in_address_order'][3]['site'], 16)
        with self.patched(site - 9, b'\x90\x90\x90\x90'):
            with self.assertRaises(ValueError):
                tool.check_wrapper(self.img, self.index, 'state')

    def test_call_order_control(self):
        """Point the block size call at the write buffer slot: the role order must break."""
        site = int(self.report['profiles']['state']['ffi_calls_in_address_order'][3]['site'], 16)
        slot = tool.FFI['set_write_buffer_size'][0]
        disp = (slot - (site + 6)).to_bytes(4, 'little', signed=True)
        with self.patched(site + 2, disp):
            with self.assertRaises(ValueError):
                tool.check_wrapper(self.img, self.index, 'state')

    def test_cache_shift_control(self):
        start = tool.WRAPPERS['checkpoint']['start']
        blob = self.img.read(start, 0x200)
        pos = blob.index(bytes.fromhex('48c1e822'))
        with self.patched(start + pos + 3, b'\x23'):
            with self.assertRaises(ValueError):
                tool.check_wrapper(self.img, self.index, 'checkpoint')

    def test_saturation_arm_control(self):
        arm = int(self.report['profiles']['state']['saturation_arm'], 16)
        with self.patched(arm + 3, b'\x00'):
            with self.assertRaises(ValueError):
                tool.check_wrapper(self.img, self.index, 'state')

    def test_default_cache_is_read_from_bytes(self):
        start = tool.WRAPPERS['state']['start']
        blob = self.img.read(start, 0x200)
        pos = blob.index(bytes.fromhex('bf020000004 90f45fe'.replace(' ', '')))
        with self.patched(start + pos + 1, b'\x03'):
            changed = tool.check_wrapper(self.img, self.index, 'state')
        self.assertEqual(changed['default_cache_gib'], 3)

    def test_block_size_is_read_from_bytes(self):
        site = int(self.report['profiles']['checkpoint']['ffi_calls_in_address_order'][3]['site'], 16)
        with self.patched(site - 3, b'\x81'):
            changed = tool.check_wrapper(self.img, self.index, 'checkpoint')
        self.assertEqual(changed['block_size'], 0x8100)

    def test_constructor_default_control(self):
        start = 0x5313980
        blob = self.img.read(start, 0x200)
        pos = blob.index(bytes.fromhex('48c7831802000000000004'))
        with self.patched(start + pos + 10, b'\x08'):
            with self.assertRaises(ValueError):
                tool.check_defaults(self.img, self.index)

    def test_validator_control(self):
        start = tool.WRAPPERS['state']['validator']
        blob = self.img.read(start, 0x100)
        pos = blob.index(bytes.fromhex('c644240702'))
        with self.patched(start + pos + 4, b'\x01'):
            with self.assertRaises(ValueError):
                tool.check_validators(self.img, self.index)

    def test_checkpoint_gate_control(self):
        site = int(self.report['checkpoint_gate']['compare_site'], 16)
        with self.patched(site + 3, b'\x74'):
            with self.assertRaises(ValueError):
                tool.check_checkpoint_gate(self.img, self.index)

    def test_caller_skip_control(self):
        with self.patched(0x3be4b5b, b'\x04'):
            with self.assertRaises(ValueError):
                tool.check_callers(self.img)


if __name__ == '__main__':
    unittest.main()
