"""Actual visor byte/metadata controls for a conditional local-return proof."""
import hashlib
import json
import mmap
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import visor_allocator_cache as cache


class VisorAllocatorCacheTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.handle = cache.TARGET.open('rb')
        cls.data = mmap.mmap(cls.handle.fileno(), 0, access=mmap.ACCESS_READ)
        if len(cls.data) != cache.SIZE or hashlib.sha256(cls.data).hexdigest() != cache.SHA256:
            raise AssertionError('Genuine pinned captured visor is required')
        cls.record, cls.exports = cache.collect(cls.data)
        cls.image = cache.Image(cls.data)

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.handle.close()

    def change(self, offset, raw):
        altered = mmap.mmap(self.handle.fileno(), 0, access=mmap.ACCESS_COPY)
        self.addCleanup(altered.close)
        altered[offset:offset + len(raw)] = raw
        return altered

    def va_change(self, va, raw):
        return self.change(self.image.read(va, len(raw))[0], raw)

    def test_actual_extent_all_terminal_paths_and_return_word(self):
        r = self.record
        self.assertEqual((r['body']['va'], r['body']['end'], r['body']['bytes'], r['body']['sha256']),
                         ('0x70bf30', '0x70bff2', 194, cache.BODY_SHA256))
        self.assertEqual((r['body']['fde'], r['body']['cie'], r['body']['lsda']), ('0x25e494', '0x22a3a0', None))
        self.assertEqual(len(r['instructions']), 37)
        self.assertEqual((len(r['graph']['branches']), len(r['graph']['local_return_paths']),
                          len(r['graph']['open_tail_paths']), r['graph']['reachable_instruction_rows']), (6, 2, 3, 35))
        self.assertEqual(r['graph']['padding_rows'], ['0x70bfbf', '0x70bfc5'])
        self.assertTrue(all('0x70bf94' in p and '0x70bfbb' in p for p in r['graph']['local_return_paths']))
        self.assertEqual(self.image.read(0x70bf94, 3)[1], bytes.fromhex('488b32'))
        self.assertEqual(self.image.read(0x70bfbb, 4)[1], bytes.fromhex('4889f0c3'))
        self.assertFalse(r['slow_target']['native_decoded'])
        self.assertEqual(r['slow_target']['body_metadata']['bytes'], 7611)

    def test_fs_base_loaded_word_and_nobits_values_are_not_conflated(self):
        self.assertEqual(self.image.read(0x70bf79, 9)[1], bytes.fromhex('644c8b1c2500000000'))
        self.assertEqual(self.record['actual_terms']['header_bias'], -0xc80)
        self.assertIn('NOT assumed equal B', self.record['symbols']['T'])
        for table, va, size in zip(self.record['runtime_tables'], (0xa0c4c0, 0xa0c700), (513, 2048)):
            self.assertEqual((table['va'], table['envelope_bytes'], table['section']['type']), (hex(va), size, 8))
            self.assertFalse(table['file_backed'])
            self.assertFalse(table['initialized_values_observed'])
            with self.assertRaisesRegex(ValueError, 'NOBITS runtime state'):
                self.image.read(va, size)

    def test_request_rounding_and_counter_wrap_are_only_address_algebra(self):
        t = self.record['actual_terms']
        self.assertEqual((t['request_upper_inclusive'], t['round_addend'], t['index_shift']), (4096, 7, 3))
        for request in (0, 1, 7, 8, 9, 4095, 4096):
            index = (request + t['round_addend']) >> t['index_shift']
            self.assertEqual(index, (request + 7) // 8)
            self.assertLessEqual(index, 512)
        # A symbolic counterexample to an unproved no-overflow/cache-size invariant.
        used, unknown_size, limit = (1 << 64) - 1, 1, 1
        summed = (used + unknown_size) % (1 << 64)
        self.assertLess(summed, limit)
        self.assertIn('modulo2**64', self.record['symbols']['q'])
        self.assertIn('No initialized class map/size values', self.record['result_limits'][1])

    def test_ordered_writes_do_not_assume_independent_pre_entry_counter(self):
        a, b = self.record['ordered_writes']['fast A'], self.record['ordered_writes']['fast B']
        self.assertEqual([w['width'] for w in a], [8, 8, 8])
        self.assertEqual([w['width'] for w in b], [8, 2, 8, 8])
        self.assertEqual([w['site'] for w in b], ['0x70bfd1', '0x70bfd8', '0x70bfe0', '0x70bfe8'])
        self.assertIn('NOW', a[-1]['operation'])
        # Symbolic address identity, not a target execution or assertion of a real TLS ABI.
        B, class_byte = 1 << 48, 3
        T = B - 0x30 - 24 * class_byte
        H = T + 24 * class_byte - 0xc80
        self.assertNotEqual(T, B)
        self.assertEqual(H + 0x368, B - 0x948)
        self.assertIn('may alias one another', self.record['proof_domain'][3])

    def test_cached_zero_or_unaligned_word_has_no_local_rejection(self):
        rows = {r['va']: r for r in self.record['instructions']}
        # Actual return is a register move from the earlier load; no later branch tests RSI.
        self.assertEqual(rows[0x70bfbb]['hex'], '4889f0')
        comparisons = [r['assembly'] for r in rows.values() if r['assembly'].startswith(('cmp ', 'test '))]
        self.assertEqual(len(comparisons), 4)
        self.assertEqual([x.split(None, 1)[1].split(',', 1)[0] for x in comparisons], ['rdi', 'r10', 'dx', 'dx'])
        self.assertIn('not locally checked for null, alignment', self.record['result_limits'][0])
        # Cursor fallback tests its low16 bits after reading its cell, not the returned word.
        self.assertLess(0x70bf94, 0x70bf9b)
        self.assertIn('ALREADY occurred', self.record['guard_partition'][3]['prior_read'])

    def test_actual_guard_address_cursor_and_return_mutations_rejected(self):
        cases = {0x70bf3c: b'\x83', 0x70bf4b: b'\x0f', 0x70bf56: b'\x04',
                 0x70bf44: b'\x79', 0x70bf79: b'\x65', 0x70bf77: b'\x77',
                 0x70bf90: b'\x68', 0x70bf94: bytes.fromhex('488b30'),
                 0x70bf9a: b'\x10', 0x70bfa2: b'\x75', 0x70bfcb: b'\x70',
                 0x70bfdc: b'\x74', 0x70bfba: b'\x02', 0x70bfbb: bytes.fromhex('4889f8')}
        for va, raw in cases.items():
            with self.subTest(va=hex(va)), self.assertRaisesRegex(ValueError, 'block operands|Native rows|Native row'):
                cache.derive(self.va_change(va, raw))

    def test_actual_fde_nobits_binding_and_used_caller_controls(self):
        with self.assertRaisesRegex(ValueError, 'FDE differs'):
            cache.derive(self.va_change(0x25e494 + 12, struct.pack('<i', 193)))
        bss_index = next(i for i, s in enumerate(self.image.sections) if s['name'] == '.bss')
        shoff = struct.unpack_from('<Q', self.data, 40)[0]
        stride = struct.unpack_from('<H', self.data, 58)[0]
        with self.assertRaisesRegex(ValueError, 'NOBITS|Section outside file'):
            cache.derive(self.change(shoff + bss_index * stride + 4, struct.pack('<I', 1)))
        relocation = self.record['actual_collection_binding']
        with self.assertRaisesRegex(ValueError, 'allocation binding differs'):
            cache.derive(self.change(int(relocation['file_offset'], 16) + 16, struct.pack('<q', cache.START + 1)))
        with self.assertRaisesRegex(ValueError, 'collection size-argument/call'):
            cache.derive(self.va_change(0x61db18, b'\xf6'))

    def test_full_identity_refused_before_any_native_call(self):
        with mock.patch.object(cache.subprocess, 'check_output', side_effect=AssertionError('must not decode')):
            for wrong in (b'wrong target', self.va_change(cache.START, b'\x90')):
                with self.assertRaisesRegex(ValueError, 'visor identity differs'):
                    cache.collect(wrong)

    def test_real_private_native_mutation_and_source_symlink_replacement(self):
        real = subprocess.run
        seen = []
        def altered(argv, **kwargs):
            if argv[-1] != 'allocator.bin':
                return real(argv, **kwargs)
            p = Path(kwargs['cwd']) / 'allocator.bin'
            original = p.read_bytes()
            self.assertEqual((len(original), p.stat().st_mode & 0o777), (194, 0o400))
            p.chmod(0o600)
            changed = bytearray(original)
            changed[0x70bf4b - cache.START] = 15
            p.write_bytes(changed)
            result = real(argv, **kwargs)
            p.write_bytes(original)
            p.chmod(0o400)
            seen.append(p)
            return result
        with mock.patch.object(cache.subprocess, 'run', side_effect=altered):
            with self.assertRaisesRegex(ValueError, 'Native row bytes'):
                cache.collect(self.data)
        self.assertFalse(seen[0].exists())
        with tempfile.TemporaryDirectory(prefix='valloc-link-') as temporary:
            directory = Path(temporary)
            link, other, output = directory / 'input', directory / 'other', directory / 'out'
            link.symlink_to(cache.TARGET)
            other.write_bytes(b'changed private source path')
            def replace(argv, **kwargs):
                if argv[-1] == 'allocator.bin':
                    link.unlink()
                    link.symlink_to(other)
                return real(argv, **kwargs)
            with mock.patch.object(cache.subprocess, 'run', side_effect=replace):
                with self.assertRaisesRegex(ValueError, 'Source changed'):
                    cache.write_report(link, output)
            self.assertFalse(output.exists())
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), cache.SHA256)

    def test_repeat_packet_and_real_cli_prior_output_preservation(self):
        again, exports = cache.collect(self.data)
        self.assertEqual(again, self.record)
        self.assertEqual(exports, self.exports)
        packet = ROOT / 'research/work-items/RE-013-visor-allocator-cache'
        if (packet / 'record.json').exists():
            self.assertEqual(json.loads((packet / 'record.json').read_text()), again)
            self.assertEqual((packet / 'allocator.objdump.txt').read_bytes(), exports['allocator.objdump.txt'].encode())
        with tempfile.TemporaryDirectory(prefix='valloc-cli-') as temporary:
            output = Path(temporary) / 'report with spaces.json'
            command = [sys.executable, '-B', str(ROOT / 'tools/visor_allocator_cache.py'), '--output', str(output)]
            run = subprocess.run(command, capture_output=True, text=True, env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(json.loads(output.read_text()), self.record)
            prior = output.read_bytes()
            run = subprocess.run(command, capture_output=True, text=True, env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
            self.assertNotEqual(run.returncode, 0)
            self.assertEqual(prior, output.read_bytes())


if __name__ == '__main__':
    unittest.main()
