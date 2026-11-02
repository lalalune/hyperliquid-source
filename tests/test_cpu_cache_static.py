import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import cpu_cache_static as cpu


class CpuCacheEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = cpu.TARGET.read_bytes()
        cls.image = cpu.Image(cls.data)
        cls.frame_records = cpu.fde_extents(cls.data)

    def test_authentic_initializer_consumer_and_ceil_binding(self):
        result = cpu.analyze(self.data)
        self.assertEqual(result['relative_bindings']['0x57747c8'], '0x565f670')
        self.assertEqual(result['relative_bindings']['0x5747f88'], '0x4e04830')
        self.assertEqual(result['cache']['store_site'], '0x4e05daf')
        self.assertFalse(result['captured_binary_executed'])
        recorded = json.loads((cpu.PACKET / 'evidence/records.json').read_text())
        for a, b in zip(result['ranges'], recorded['ranges']):
            for key, value in a.items():
                self.assertEqual(value, b[key], key)

    def test_complete_native_decoders_agree_with_capture(self):
        for start, (end, _, _) in cpu.RANGES.items():
            body = self.image.read(start, end - start)
            exports = [cpu.decode_export((cpu.PACKET / 'evidence' / f'{start:x}.{kind}.txt').read_text(), start, end, body)
                       for kind in ['objdump', 'llvm']]
            self.assertEqual(exports[0], exports[1])

    def test_overlapping_fde_is_rejected_instead_of_counted_once(self):
        meta, frames, tail = self.frame_records
        original = next(f for f in frames if f['start'] == 0x4e04830)
        for additional in [dict(original), dict(original, start=original['start'] + 1)]:
            with patch.object(cpu, 'fde_extents', return_value=(meta, frames + [additional], tail)):
                with self.assertRaisesRegex(ValueError, 'overlapping or changed FDE'):
                    cpu.analyze(self.data, authenticate=False)

    def test_duplicate_relocation_slot_is_rejected(self):
        data = bytearray(self.data)
        section = self.image.section('.rela.dyn')
        struct.pack_into('<Q', data, section['offset'], 0x57747c8)
        with self.assertRaisesRegex(ValueError, 'duplicate RELA slot'):
            cpu.analyze(data, authenticate=False)

    def test_unexpected_relocation_cannot_rewrite_numeric_evidence(self):
        data = bytearray(self.data)
        section = self.image.section('.rela.dyn')
        struct.pack_into('<Q', data, section['offset'], 0x203e81)
        with self.assertRaisesRegex(ValueError, 'overlaps protected evidence'):
            cpu.analyze(data, authenticate=False)

    def test_changed_opcode_constant_literal_and_callback_are_rejected(self):
        cases = [(0x4e05daf + 3, 'RIP binding'), (0x203e80, 'constant/vtable'),
                 (0x715d0d, 'literal'), (0x4e0499d, 'whole function')]
        for address, error in cases:
            with self.subTest(address=hex(address)):
                data = bytearray(self.data)
                data[self.image.offset(address, 1)] ^= 1
                with self.assertRaisesRegex(ValueError, error):
                    cpu.analyze(data, authenticate=False)
        data = bytearray(self.data)
        section = self.image.section('.rela.dyn')
        offset = next(o for o in range(section['offset'], section['offset'] + section['size'], 24)
                      if struct.unpack_from('<Q', data, o)[0] == 0x5747f88)
        struct.pack_into('<q', data, offset + 16, 0x4e04831)
        with self.assertRaisesRegex(ValueError, 'RELATIVE binding'):
            cpu.analyze(data, authenticate=False)

    def test_wrong_snapshot_fails_before_any_export(self):
        with self.assertRaisesRegex(ValueError, 'wrong node94 input'):
            cpu.analyze(self.data[:-1])

    def test_nobits_section_alone_does_not_prove_loader_zero_fill(self):
        data = bytearray(self.data)
        offset = struct.unpack_from('<Q', data, 32)[0]
        stride, count = struct.unpack_from('<HH', data, 54)
        for index in range(count):
            row = offset + index * stride
            fields = struct.unpack_from('<IIQQQQQQ', data, row)
            if fields[0] == 1 and fields[3] <= 0x57883f8 < fields[3] + fields[6]:
                struct.pack_into('<Q', data, row + 32, 0x5788400 - fields[3])
        with self.assertRaisesRegex(ValueError, 'PT_LOAD zero-fill tail'):
            cpu.analyze(data, authenticate=False)

    def test_packet_inventory_rejects_extra_files_symlinks_and_duplicate_keys(self):
        spec = importlib.util.spec_from_file_location('cpu_packet_verifier', cpu.PACKET / 'verify.py')
        verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)
        with self.assertRaisesRegex(ValueError, 'duplicate JSON key'):
            json.loads('{"a": 1, "a": 2}', object_pairs_hook=verifier.unique_object)
        with tempfile.TemporaryDirectory(prefix='cpu-packet-control-') as directory:
            root = Path(directory)
            packet = root / 'packet'
            packet.mkdir()
            (packet / 'manifest.json').write_text('{"files": {}}')
            (packet / 'nested').mkdir()
            (packet / 'nested/manifest.json').write_text('{}')
            with self.assertRaisesRegex(ValueError, 'inventory changed'):
                verifier.check_inventory(packet, root)
            (packet / 'link').symlink_to(root / 'absent')
            with self.assertRaisesRegex(ValueError, 'symlink in packet'):
                verifier.check_inventory(packet, root)

    def test_rust_values_match_frozen_integer_only_oracle(self):
        try:
            rustc = subprocess.check_output(['rustup', 'which', '--toolchain', '1.94.1', 'rustc'], text=True, stderr=subprocess.DEVNULL).strip()
            cargo = subprocess.check_output(['rustup', 'which', '--toolchain', '1.94.1', 'cargo'], text=True, stderr=subprocess.DEVNULL).strip()
        except (FileNotFoundError, subprocess.CalledProcessError):
            self.skipTest('pinned Rust 1.94.1 toolchain unavailable')
        env = dict(os.environ, RUSTC=rustc, RUSTDOC=str(Path(rustc).with_name('rustdoc')),
                   PATH=str(Path(rustc).parent) + os.pathsep + os.environ.get('PATH', ''))
        rows = json.loads((cpu.PACKET / 'oracle/vectors.json').read_text())
        with tempfile.TemporaryDirectory(prefix='cpu-cache-rust-') as target:
            command = [cargo, 'build', '--release', '--locked', '--offline', '--manifest-path',
                       str(cpu.PACKET / 'rust/Cargo.toml'), '--target-dir', target]
            subprocess.run(command, env=env, check=True, capture_output=True, text=True)
            inputs = ''.join(f"{r['quota']} {r['period']} {r['logical']}\n" for r in rows)
            actual = subprocess.run([str(Path(target) / 'release/cpu-cache-vectors')], input=inputs,
                                    capture_output=True, text=True, check=True).stdout.splitlines()
        self.assertEqual(len(actual), len(rows))
        for ordinal, (line, row) in enumerate(zip(actual, rows)):
            expected = ' '.join(str(row[k]) if row[k] is not None else 'none'
                                for k in ['quota_bits', 'period_bits', 'ratio_bits', 'rounded_quota', 'store'])
            self.assertEqual(line, expected, f'pre-Rust frozen vector {ordinal}')


if __name__ == '__main__':
    unittest.main()
