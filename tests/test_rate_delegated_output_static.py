"""Actual Node94 no-split operands/routes and real native input-binding controls."""
import copy
import hashlib
import json
import mmap
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import rate_delegated_output_static as target


class DelegatedOutputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = target.ROOT / target.TARGET
        cls.handle = cls.binary.open('rb')
        cls.data = mmap.mmap(cls.handle.fileno(), 0, access=mmap.ACCESS_READ)
        if len(cls.data) != target.SIZE or hashlib.sha256(cls.data).hexdigest() != target.SHA256:
            raise AssertionError('Genuine pinned Node94 input is required; no synthetic substitute')
        cls.temp = tempfile.TemporaryDirectory(prefix='nosplit-tests-')
        cls.directory = Path(cls.temp.name)
        cls.record = target.collect(cls.binary, cls.directory / 'normal')
        cls.text = (cls.directory / 'normal/helper.objdump.txt').read_text(encoding='utf-8')
        cls.image = target.Image(cls.data)
        cls.body = cls.image.read(target.START, target.END - target.START)[1]

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.handle.close()
        cls.temp.cleanup()

    def mutation(self, offset, replacement):
        changed = mmap.mmap(self.handle.fileno(), 0, access=mmap.ACCESS_COPY)
        self.addCleanup(changed.close)
        changed[offset:offset + len(replacement)] = replacement
        return changed

    def va_mutation(self, va, replacement):
        return self.mutation(self.image.read(va, len(replacement))[0], replacement)

    def test_actual_boundaries_operands_and_both_insertion_routes(self):
        r = self.record
        self.assertEqual(r['body'], {'start': '0x4258c00', 'end': '0x4259d02', 'bytes': 4354,
                                    'file_offset': '0x4257c00', 'sha256': target.BODY_SHA256})
        self.assertEqual(r['fde']['va'], '0x12295cc')
        self.assertEqual(struct.unpack_from('<i', bytes.fromhex(r['fde']['raw']), 12)[0], 4354)
        c = r['no_split_contract']
        self.assertEqual(c['count_load']['width_bits'], 16)
        self.assertEqual(c['count_bound']['unsigned_upper_exclusive'], 11)
        self.assertEqual(c['index_load']['width_bits'], 64)
        self.assertEqual((c['last_copy']['scale'], c['last_copy']['length']), (608, 608))
        self.assertEqual([o['offset'] for o in c['output']], [0, 8, 16])
        n = r['native']
        self.assertEqual(n['partition_routes'], ['0x4258ca0', '0x4258cf8'])
        self.assertEqual(n['both_routes_pass_common_sites_before_return'],
                         ['0x4258d86', '0x4258da0', '0x4258dd9', '0x4258ddc', '0x4258de0'])
        self.assertEqual(n['selected_only_terminal'], '0x4259a3e')
        self.assertEqual(n['selected_instruction_count'], 73)
        self.assertEqual(n['fallthrough_outside_full_extent'][0]['fallthrough'], '0x4259d02')

    def test_count_bound_does_not_impose_an_independent_index_bound(self):
        # Mathematical counterexample to an unproved invariant, not target execution.
        count, independent_index = 0, (1 << 64) - 1
        self.assertLess(count, 11)
        self.assertGreater(independent_index, 10)
        self.assertLessEqual((independent_index + 1) % (1 << 64), count)
        self.assertIn('Independent qword', self.record['no_split_contract']['index_domain'])
        self.assertIn('after the initial opaque import', self.record['no_split_contract']['conditions'][0])

    def test_direct_pointer_stores_need_the_explicit_all_write_frame_domain(self):
        # Symbolic address algebra on actual LEA/ADD operands; no target/CPU execution.
        self.assertEqual(self.image.read(0x4258c8c, 4)[1], bytes.fromhex('488d045b'))
        self.assertEqual(self.image.read(0x4258c90, 4)[1], bytes.fromhex('4d8d24c6'))
        scale = (1 + 2) * 8
        offset = struct.unpack('<I', self.image.read(0x4258c97, 4)[1])[0]
        self.assertEqual((scale, offset), (24, 0x1a28))
        modulus, sp, index = 1 << 64, 1 << 48, 0
        for count, protected_offset in ((0, 0x78), (1, 0x28)):
            base = (sp + protected_offset - scale * index - offset) % modulus
            derived_destination = (base + scale * index + offset) % modulus
            self.assertEqual(derived_destination, sp + protected_offset)
            self.assertLess(count, 11)
            self.assertEqual((index + 1) % modulus <= count, count == 1)
        # The direct stores can overwrite protected words even if imports preserve them.
        self.assertEqual(self.image.read(0x4258cb1, 5)[1], bytes.fromhex('410f110424'))
        self.assertEqual(self.image.read(0x4258d38, 5)[1], bytes.fromhex('410f110424'))
        domain = self.record['no_split_contract']['frame_proof_domain']
        self.assertEqual([r['offset'] for r in domain['protected_live_words']], [8, 16, 40, 120])
        self.assertEqual(domain['allocation_bytes'], 0xca8)
        self.assertIn('ALL memory effects', self.record['no_split_contract']['conditions'][2])
        self.assertIn('Unverified proof-domain assumption', domain['qualification'])

    def test_real_instruction_corruptions_break_pointer_bound_and_forwarding(self):
        mutations = {
            0x4258c4d: b'\xb6',  # u16 load -> byte load
            0x4258c56: b'\x0c',  # count threshold11 ->12
            0x4258c57: b'\x76',  # JB ->JBE
            0x4258c87: b'\x08',  # qword index source offset16 ->8
            0x4258d7f: b'\x5c',  # saved index reload operand
            0x4258d8c: b'\x61',  #608 ->609 last-copy scale
            0x4258d92: b'\xf6',  # base-add destination carrier
            0x4258d9c: b'\x61',  #608 ->609 length
            0x4258db3: b'\x03',  # local constant2 ->3
            0x4258ddc: b'\x49',  # output8 pointer carrier
            0x4258de2: b'\x68',  # output16 source RBX ->RBP
            0x495906a: b'\x40',  # caller R9 input+38 ->40 alias obligation
        }
        for va, replacement in mutations.items():
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError, 'Selected delegated'):
                    target.inspect_bytes(self.va_mutation(va, replacement))

    def test_actual_import_cfi_and_lsda_corruptions_are_rejected(self):
        for row in self.record['imports']:
            changed = self.mutation(int(row['file_offset'], 16) + 8, struct.pack('<Q', 8))
            with self.subTest(slot=row['slot']), self.assertRaisesRegex(ValueError, 'import relocation'):
                target.inspect_bytes(changed)
        changed = self.va_mutation(target.FDE + 12, struct.pack('<i', 4353))
        with self.assertRaisesRegex(ValueError, 'FDE changed'):
            target.inspect_bytes(changed)
        changed = self.va_mutation(target.FDE + 30, b'\x11')
        with self.assertRaisesRegex(ValueError, 'raw CFI'):
            target.inspect_bytes(changed)
        changed = self.va_mutation(target.LSDA, b'\xfe')
        with self.assertRaisesRegex(ValueError, 'LSDA encoding'):
            target.inspect_bytes(changed)
        changed = self.va_mutation(target.LSDA + 9, b'\x01')
        with self.assertRaisesRegex(ValueError, 'raw LSDA'):
            target.inspect_bytes(changed)

    def test_native_bytes_boundaries_and_common_route_cannot_be_faked(self):
        with self.assertRaisesRegex(ValueError, 'instruction bytes'):
            target.native_rows(self.text.replace('48 89 30', '48 89 31', 1), self.body)
        # A real branch retargeted one byte into the common block must not acquire an edge.
        old, new = 'e9 b3 00 00 00', 'e9 b4 00 00 00'
        self.assertIn(old, self.text)
        text = self.text.replace(old, new, 1).replace('jmp    0x4258d86', 'jmp    0x4258d87', 1)
        body = bytearray(self.body)
        at = 0x4258cce - target.START
        body[at:at + 5] = bytes.fromhex(new)
        with self.assertRaisesRegex(ValueError, 'admitted boundary'):
            target.native_rows(text, body)
        # A real boundary on the split path still cannot pass the selected local route proof.
        displacement = struct.pack('<i', 0x4259078 - (0x4258cce + 5))
        changed = bytes.fromhex('e9') + displacement
        body[at:at + 5] = changed
        text = self.text.replace(old, ' '.join(f'{v:02x}' for v in changed), 1).replace('jmp    0x4258d86', 'jmp    0x4259078', 1)
        with self.assertRaisesRegex(ValueError, 'escapes'):
            target.native_rows(text, body)

    def test_real_source_symlink_replacement_keeps_native_slice_and_refuses_output(self):
        with tempfile.TemporaryDirectory(prefix='nosplit-symlink-') as directory:
            root = Path(directory)
            source, other, output = root / 'source', root / 'other', root / 'out'
            source.symlink_to(self.binary)
            other.write_bytes(b'different private input')
            real = subprocess.check_output
            seen = []
            def observe(argv, **kwargs):
                if argv[0] == 'objdump' and '--version' not in argv:
                    path = Path(kwargs['cwd']) / argv[-1]
                    seen.append({'bytes': path.stat().st_size, 'sha256': target.digest(path),
                                 'file_mode': stat.S_IMODE(path.stat().st_mode),
                                 'directory_mode': stat.S_IMODE(path.parent.stat().st_mode),
                                 'path': path})
                    source.unlink()
                    source.symlink_to(other)
                return real(argv, **kwargs)
            with mock.patch.object(target.subprocess, 'check_output', side_effect=observe):
                with self.assertRaisesRegex(ValueError, 'Source changed'):
                    target.collect(source, output)
            self.assertEqual(len(seen), 1)
            self.assertEqual({k: seen[0][k] for k in ('bytes', 'sha256', 'file_mode', 'directory_mode')},
                             {'bytes': 4354, 'sha256': target.BODY_SHA256, 'file_mode': 0o600, 'directory_mode': 0o700})
            self.assertFalse(seen[0]['path'].exists())
            self.assertFalse(output.exists())
            self.assertEqual(target.digest(self.binary), target.SHA256)

    def test_owned_slice_mutation_is_detected_and_cleaned(self):
        path = None
        with self.assertRaisesRegex(ValueError, 'Owned native slice changed'):
            with target.private_slice(self.body) as path:
                self.assertEqual(path.stat().st_size, 4354)
                path.write_bytes(b'changed private slice')
        self.assertFalse(path.exists())

    def test_normal_repeat_packet_and_actual_cli_existing_output_preservation(self):
        again = self.directory / 'again'
        target.collect(self.binary, again)
        for name in ('helper.objdump.txt', 'instructions.json', 'records.json'):
            self.assertEqual((again / name).read_bytes(), (self.directory / 'normal' / name).read_bytes())
        packet = target.ROOT / 'research/work-items/RE-001-rate-delegated-output-94/observed'
        if packet.exists():
            self.assertEqual((packet / 'helper.objdump.txt').read_bytes(), (again / 'helper.objdump.txt').read_bytes())
            self.assertEqual((packet / 'instructions.json').read_bytes(), (again / 'instructions.json').read_bytes())
            expected, observed = json.loads((packet / 'records.json').read_text()), copy.deepcopy(self.record)
            expected['native'].pop('tool')
            observed['native'].pop('tool')
            self.assertEqual(expected, observed)
        with tempfile.TemporaryDirectory(prefix='nosplit-cli-') as directory:
            output = Path(directory) / 'existing'
            output.mkdir()
            for populated in (False, True):
                if populated:
                    (output / 'sentinel').write_bytes(b'preserve this exact content')
                before = {p.name: p.read_bytes() for p in output.iterdir()}
                run = subprocess.run([sys.executable, '-B', str(target.ROOT / 'tools/rate_delegated_output_static.py'),
                                      '--output', str(output)], capture_output=True, text=True,
                                     env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
                self.assertNotEqual(run.returncode, 0)
                self.assertIn('Output must be a new directory', run.stderr)
                self.assertEqual(before, {p.name: p.read_bytes() for p in output.iterdir()})

    def test_wrong_identity_fails_before_native_and_output(self):
        with tempfile.TemporaryDirectory(prefix='nosplit-identity-') as directory:
            binary, output = Path(directory) / 'wrong', Path(directory) / 'out'
            binary.write_bytes(b'not the captured binary')
            with mock.patch.object(target.subprocess, 'check_output') as native:
                with self.assertRaisesRegex(ValueError, 'Node94 identity mismatch'):
                    target.collect(binary, output)
                native.assert_not_called()
            self.assertFalse(output.exists())

    def test_split_copy_equation_both_return_tails_and_saved_triple(self):
        s = self.record['native']['split_output']
        self.assertEqual(s['first_insertion_copy']['va'], '0x4259022')
        self.assertEqual((s['first_insertion_copy']['scale'], s['first_insertion_copy']['length']), (608, 608))
        self.assertEqual(s['all_return_cutsets'], {
            'first_split_insertion_copy': ['0x4259022'],
            'output0_stores': ['0x4258dd9', '0x4259a18'],
            'output8_stores': ['0x4258ddc', '0x4259a20'],
            'output16_stores': ['0x4258de0', '0x4259a29']})
        self.assertEqual([(w['offset'], w['width'], w['reload']) for w in s['saved_tail']['words']],
                         [(144, 8, '0x4259a10'), (104, 8, '0x4259a1b'), (40, 8, '0x4259a24')])
        self.assertEqual(s['scope'], {'ordinary_reachable_instructions': 683, 'normal_return': '0x4259a3e',
                                     'explicit_memory_writes_full_context': 139,
                                     'explicit_memory_writes_on_split_normal_graph': 128})
        self.assertIn('not equated to initialcount', s['later_count'])
        self.assertEqual([p['pivot_register'] for p in s['initial_partition_before_allocation']], [4, 5, 5, 6])
        self.assertIn('not equated to entry values', s['limits'][0])
        # Symbolic address identity from actual tail-store/reload displacements, no CPU execution.
        store_offset = self.image.read(0x4259a23, 1)[1][0]
        reload_offset = self.image.read(0x4259a28, 1)[1][0]
        self.assertEqual((store_offset, reload_offset), (8, 0x28))
        sp = 1 << 48
        output_pointer = sp + reload_offset - store_offset
        self.assertEqual(output_pointer + store_offset, sp + reload_offset)
        self.assertIn('AND final output stores', s['proof_domain'][2])

    def decode_actual_private_mutation(self, va, raw):
        body = bytearray(self.body)
        body[va - target.START:va - target.START + len(raw)] = raw
        with target.private_slice(body) as path:
            text = subprocess.check_output(self.record['native']['argv'], cwd=path.parent,
                                           encoding='utf-8', env={**os.environ, 'LC_ALL': 'C'})
        return target.native_rows(text, body)

    def test_real_native_split_bypass_and_width_overlap_controls(self):
        # Actual5B jump altered to a valid output-tail entry bypasses first split copy/saves.
        va, destination = 0x4258c7f, 0x4259a0b
        raw = b'\xe9' + struct.pack('<i', destination - va - 5)
        with self.assertRaisesRegex(ValueError, 'copy/output cutset'):
            self.decode_actual_private_mutation(va, raw)
        # Actual INC SP60..68 changed to SP68..70 overlaps the protected middle word.
        with self.assertRaisesRegex(ValueError, 'overlaps the saved result'):
            self.decode_actual_private_mutation(0x4259531, bytes.fromhex('48ff442468'))
        # Equal-length actual scalar store atSP20 replaced by valid16B MOVUPS reaches liveSP28.
        with self.assertRaisesRegex(ValueError, 'overlaps the saved result'):
            self.decode_actual_private_mutation(0x4259858, bytes.fromhex('0f11442420'))

    def test_actual_split_copy_and_saved_output_operand_mutations(self):
        for va, replacement in {0x4259007: b'\x61', 0x425901e: b'\xbf',
                                0x425905d: b'\x60', 0x425907b: b'\x88',
                                0x4259089: b'\x20', 0x4259a17: b'\x88',
                                0x4259a28: b'\x20'}.items():
            with self.subTest(va=hex(va)), self.assertRaisesRegex(ValueError, 'Selected delegated'):
                target.inspect_bytes(self.va_mutation(va, replacement))


if __name__ == '__main__':
    unittest.main()
