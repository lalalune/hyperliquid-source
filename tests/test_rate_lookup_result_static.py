"""Real Node94 byte/relocation controls; local arithmetic is not binary execution."""
import hashlib
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT
import rate_lookup_result_static as collector
from rate_lookup_result_static import (CONTROLS, RELOCATIONS, TARGET, TARGET_BYTES, TARGET_SHA256,
                                       Image, branch_targets, controls, relocations, verify_listing)


class RateLookupResultTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT / TARGET).read_bytes()
        if len(cls.data) != TARGET_BYTES or hashlib.sha256(cls.data).hexdigest() != TARGET_SHA256:
            raise ValueError('Real Node94 identity mismatch')
        cls.image = Image(cls.data)

    def test_real_target_instruction_and_relocation_controls(self):
        controls(self.image)
        self.assertEqual(len(relocations(self.image)), 5)
        self.assertEqual(branch_targets(self.image), {
            'caller_to_lookup': '0x4956d50', 'opaque_helper': '0x4959020',
            'jno_target': '0x4956d78', 'callback_slot': '0x576efb0',
            'caller_data_address': '0x572e848'})

    def test_each_real_instruction_control_rejects_corruption(self):
        for va in CONTROLS:
            with self.subTest(va=hex(va)):
                changed = bytearray(self.data)
                offset, _ = self.image.read(va, 1)
                changed[offset] ^= 1
                with self.assertRaisesRegex(ValueError, 'instruction changed'):
                    controls(Image(changed))

    def test_each_real_relocation_rejects_retarget(self):
        for row in relocations(self.image):
            with self.subTest(slot=row['slot_va']):
                changed = bytearray(self.data)
                changed[int(row['record_file_offset'], 16) + 16] ^= 1
                with self.assertRaisesRegex(ValueError, 'relocation changed'):
                    relocations(Image(changed))

    def test_encoded_zero_minus_word_overflow_partition(self):
        self.assertEqual(self.image.read(0x4956d5a, 7)[1], bytes.fromhex('31c0483b077117'))
        maximum, sign = (1 << 64) - 1, 1 << 63
        # Architectural subtraction OF=((a^b)&(a^result)&sign)!=0, with a=0.
        # Signed negation has one unrepresentable input: -2**63.
        samples = [0, 1, 2, sign - 1, sign, sign + 1, maximum - 1, maximum]
        overflowing = [word for word in samples if (word & ((-word) & maximum) & sign) != 0]
        self.assertEqual(overflowing, [sign])

    def test_two_real_encoded_stride_and_base_operands(self):
        fast = self.image.read(0x4956d61, 12)[1]
        slow = self.image.read(0x4956e7a, 14)[1]
        self.assertEqual(fast[:4], bytes.fromhex('48694718'))
        self.assertEqual(slow[:5], bytes.fromhex('4869442468'))
        self.assertEqual(struct.unpack_from('<i', fast, 4)[0], 608)
        self.assertEqual(struct.unpack_from('<i', slow, 5)[0], 608)
        self.assertEqual(fast[8:], bytes.fromhex('48034708'))
        self.assertEqual(slow[9:], bytes.fromhex('4803442458'))
        # Independent multiply/add reduction examples, no memory dereference.
        modulus = 1 << 64
        for base, index, expected in [(0, 0, 0), (0x1000, 2, 0x14c0),
                                      (modulus - 1, 1, 607), (7, modulus - 1, modulus - 601)]:
            self.assertEqual((base + 608 * index) % modulus, expected)

    def test_listing_guard_rejects_truncation_address_and_byte_changes(self):
        start, end = 0x4714f49, 0x4714f4c
        exact = ' 4714f49:\t48 89 c7  \tmov %rax,%rdi\n'
        verify_listing(exact, self.image, start, end)
        for raw in ['', exact.replace('4714f49', '4714f4a'), exact.replace('c7', 'cf'),
                    ' 4714f49:\t48 89  \tmov\n']:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                verify_listing(raw, self.image, start, end)

    def test_real_cli_preserves_existing_empty_and_populated_output(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as temporary:
            output = Path(temporary) / 'retained'
            output.mkdir()
            for populated in (False, True):
                with self.subTest(populated=populated):
                    if populated:
                        (output / 'records.json').write_bytes(b'prior-evidence\r\n\x00')
                    before = {p.name: p.read_bytes() for p in output.iterdir()}
                    result = subprocess.run([sys.executable, '-B', str(ROOT / 'tools/rate_lookup_result_static.py'),
                                             '--binary', str(ROOT / TARGET), '--output', str(output)],
                                            capture_output=True, encoding='utf-8', check=False)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('Output already exists; preserve retained evidence', result.stderr)
                    self.assertEqual({p.name: p.read_bytes() for p in output.iterdir()}, before)

    def test_real_private_path_swap_cannot_publish_mixed_fde_metadata(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as temporary:
            supplied = Path(temporary) / 'supplied.elf'
            with supplied.open('xb') as target, (ROOT / TARGET).open('rb') as source:
                shutil.copyfileobj(source, target, length=1024 * 1024)
            supplied.chmod(0o600)
            output = Path(temporary) / 'output'
            field_offset, original = self.image.read(0x12aaa44, 4)
            self.assertEqual(original, bytes.fromhex('18ce2e00'))
            replacement = bytes.fromhex('2c955c00')  # Existing zR CIE instead of zPLR.
            real_native = collector.subprocess.check_output
            inputs, frame_lines = [], []
            replaced = False

            def native_reader(argv, **kwargs):
                nonlocal replaced
                if '--version' not in argv:
                    inputs.append(Path(argv[-1]))
                if argv[0] == 'readelf' and '-wf' in argv and not replaced:
                    native_path = Path(argv[-1])
                    if native_path != supplied:
                        self.assertEqual(stat.S_IMODE(native_path.stat().st_mode), 0o600)
                        self.assertEqual(stat.S_IMODE(native_path.parent.stat().st_mode), 0o700)
                        self.assertNotEqual((native_path.stat().st_dev, native_path.stat().st_ino),
                                            (supplied.stat().st_dev, supplied.stat().st_ino))
                        self.assertEqual(hashlib.sha256(native_path.read_bytes()).hexdigest(), TARGET_SHA256)
                    old_fd = os.open(supplied, os.O_RDONLY)
                    old_identity = os.fstat(old_fd)
                    supplied.unlink()
                    new_fd = os.open(supplied, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    new_identity = os.fstat(new_fd)
                    self.assertNotEqual((old_identity.st_dev, old_identity.st_ino),
                                        (new_identity.st_dev, new_identity.st_ino))
                    # Free the unlinked original before copying the replacement.
                    os.close(old_fd)
                    with os.fdopen(new_fd, 'wb') as target, (ROOT / TARGET).open('rb') as source:
                        shutil.copyfileobj(source, target, length=1024 * 1024)
                        target.seek(field_offset)
                        target.write(replacement)
                    replaced = True
                result = real_native(argv, **kwargs)  # Real GNU tools, no mocked output.
                if argv[0] == 'readelf' and '-wf' in argv:
                    frame_lines.extend(line for line in result.splitlines()
                                       if 'FDE' in line and 'pc=0000000004956d50..' in line)
                return result

            with mock.patch.object(collector.subprocess, 'check_output', side_effect=native_reader):
                with self.assertRaisesRegex(ValueError, 'Source changed during static collection'):
                    collector.generate(supplied, output)
            self.assertTrue(replaced)
            self.assertFalse(output.exists())
            self.assertTrue(inputs)
            self.assertTrue(all(path != supplied for path in inputs))
            self.assertEqual(len(set(inputs)), 1)
            self.assertEqual(len(frame_lines), 1)
            self.assertEqual(int(frame_lines[0].split('cie=')[1].split()[0], 16), 0x2dc714)

    def test_owned_snapshot_mutation_rejects_and_cleans_only_its_copy(self):
        seen = []
        with self.assertRaisesRegex(ValueError, 'Snapshot changed during static collection'):
            with collector.native_snapshot(b'private snapshot bytes') as snapshot:
                seen.append(snapshot)
                snapshot.write_bytes(b'changed snapshot bytes')
        self.assertFalse(seen[0].exists())
        self.assertFalse(seen[0].parent.exists())
        self.assertEqual(hashlib.sha256((ROOT / TARGET).read_bytes()).hexdigest(), TARGET_SHA256)

    def test_source_hardlink_metadata_is_allowed_but_bytes_are_bound(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as temporary:
            source = Path(temporary) / 'source'
            value = b'private metadata control'
            source.write_bytes(value)
            before = source.stat()
            expected = hashlib.sha256(value).hexdigest()
            os.link(source, Path(temporary) / 'alias')
            self.assertNotEqual(source.stat().st_ctime_ns, before.st_ctime_ns)
            self.assertTrue(collector.source_unchanged(source, before, expected))
            source.write_bytes(bytes([value[0] ^ 1]) + value[1:])
            os.utime(source, ns=(before.st_atime_ns, before.st_mtime_ns))
            self.assertFalse(collector.source_unchanged(source, before, expected))


if __name__ == '__main__':
    unittest.main()
