"""Static byte/semantics controls for the complete node #115 decimal cursor leaf."""
from contextlib import contextmanager
import hashlib
import json
import mmap
from pathlib import Path
import re
import runpy
import shutil
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import node115_decimal_cursor as bind
from elf_index import sections


class DecimalCursorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.handle = bind.TARGET.open('rb')
        cls.data = mmap.mmap(cls.handle.fileno(), 0, access=mmap.ACCESS_COPY)
        cls.secs = sections(cls.data)
        cls.record = bind.analyze(cls.data)
        cls.body = bytes.fromhex(cls.record['window']['body_bytes'])
        cls.check_manifest = staticmethod(runpy.run_path(str(bind.PACKET / 'verify.py'))['check_manifest'])

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.handle.close()

    @contextmanager
    def patched(self, offset, replacement):
        original = self.data[offset:offset + len(replacement)]
        self.data[offset:offset + len(replacement)] = replacement
        try:
            yield
        finally:
            self.data[offset:offset + len(original)] = original

    def offset(self, va, size=1):
        return bind.mapping(self.secs, va, size)

    def test_byte_identical_regeneration(self):
        self.assertEqual(self.record, json.loads((bind.PACKET / 'records.json').read_text()))
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / 'packet'
            bind.generate(bind.TARGET, out)
            self.assertEqual({p.name for p in out.iterdir()}, {p.name for p in bind.PACKET.iterdir()})
            for path in out.iterdir():
                self.assertEqual(path.read_bytes(), (bind.PACKET / path.name).read_bytes(), path.name)
            self.check_manifest(out, ROOT)

    def test_readme_counts_match_json_and_evidence(self):
        readme = (bind.PACKET / 'README.md').read_text()
        record = json.loads((bind.PACKET / 'records.json').read_text())
        block = re.search(r'<!-- counts:start -->\n(.*?)\n<!-- counts:end -->', readme, re.S)
        self.assertIsNotNone(block)
        counts = dict((key, int(value)) for key, value in re.findall(r'^- (\w+): (\d+)$', block[1], re.M))
        self.assertEqual(counts, record['counts'])
        self.assertEqual(block[1], bind.count_lines(record))
        self.assertEqual(readme, bind.readme_text(record))
        ins, scan = record['instructions'], record['caller_scan']
        self.assertEqual(counts['body_bytes'], sum(len(bytes.fromhex(r['bytes'])) for r in ins))
        self.assertEqual(counts['body_bytes'], record['window']['end'] - record['window']['start'])
        self.assertEqual(counts['instructions'], len(ins))
        self.assertEqual(counts['callees'], len(record['callees']))
        self.assertEqual(counts['direct_call_sites'], sum(r['kind'] == 'call' for r in scan['sites']))
        self.assertEqual(counts['direct_caller_owners'], len(scan['owners']))
        self.assertEqual(counts['tail_jump_sites'], sum(r['kind'] == 'jmp' for r in scan['sites']))
        self.assertEqual(counts['conditional_branches'], sum(r['mnemonic'] in ('ja', 'jae') for r in ins))
        self.assertEqual(counts['returns'], sum(r['mnemonic'] == 'ret' for r in ins))
        self.assertEqual(counts['cursor_stores'], sum(r['mnemonic'] == 'mov' and 'base' in r['operands'][0] for r in ins))
        self.assertEqual(counts['frozen_vectors'], len(record['vectors']))
        self.assertEqual(counts['padding_bytes'], len(bytes.fromhex(record['window']['padding']['bytes'])))
        self.assertEqual(counts['text_bytes_scanned'], scan['end'] - scan['start'])
        self.assertEqual(counts['targeted_tests'], unittest.defaultTestLoader.loadTestsFromTestCase(type(self)).countTestCases())

    def test_complete_leaf_and_all_consumption_paths(self):
        rows, edges, _ = bind.validate_body(self.body)
        self.assertTrue(0x2800000 <= bind.START < 0x3c00000)
        self.assertFalse(0x5f00000 <= bind.START < 0x5f20000)
        self.assertEqual(rows[-1]['va'], bind.END - 1)
        self.assertFalse(any(r['mnemonic'] in ('call', 'jmp') for r in rows))
        graph = {r['va']: r['successors'] for r in edges}
        row_map = {r['va']: r for r in rows}
        paths, pending = [], [(bind.START, [])]
        while pending:
            va, path = pending.pop()
            path = path + [va]
            if not graph[va]:
                paths.append(path)
            else:
                pending.extend((dst, path) for dst in graph[va])
        # Exactly the logical outcomes: empty, invalid first, exhausted after
        # first, invalid second, exhausted after second, invalid third, success.
        outcomes = []
        for path in paths:
            instructions = [row_map[va] for va in path]
            stores = [r['va'] for r in instructions if r['mnemonic'] == 'mov' and 'base' in r['operands'][0]]
            self.assertEqual(stores, [0x2e564c9, 0x2e564e2, 0x2e564fe][:len(stores)])
            for row in instructions:
                if row['mnemonic'] == 'mov' and 'base' in row['operands'][0]:
                    self.assertEqual(row['operands'][0], {'base': 'rdi', 'index': None, 'scale': 1, 'disp': 16, 'width': 64})
            eax_writes = [r for r in instructions if r['operands'] and r['operands'][0].get('reg') == 'eax']
            final = eax_writes[-1]
            kind = 'success' if final['mnemonic'] == 'shl' else hex(final['operands'][1]['imm'])
            outcomes.append((kind, len(stores)))
        self.assertCountEqual(outcomes, [('0x30001', 0), ('0x30001', 1), ('0x30001', 2),
                                         ('0x30002', 1), ('0x30002', 2), ('0x30002', 3), ('success', 3)])

    def test_frozen_instruction_derived_vectors(self):
        for row in self.record['vectors']:
            with self.subTest(case=row['case']):
                self.assertEqual(bind.model(bytes.fromhex(row['buffer_hex']), row['cursor'], row['end']),
                                 (row['rax'], row['cursor_after']))

    def test_every_decimal_triple_and_leading_zero(self):
        params = self.record['parameters']
        for value in range(1000):
            digits = f'{value:03}'.encode('ascii')
            self.assertEqual(bind.instruction_value(digits, params), value << 16)
            self.assertEqual(bind.model(digits), (value << 16, 3))
        self.assertEqual(bind.model(b'000'), (0, 3))
        self.assertNotEqual(bind.model(b'000')[0], bind.model(b'')[0])

    def test_every_byte_at_each_position_and_early_error_consumption(self):
        params = self.record['parameters']
        for index in range(3):
            for byte in range(256):
                digits = bytearray(b'123')
                digits[index] = byte
                digits = bytes(digits)
                with self.subTest(index=index, byte=byte):
                    if 48 <= byte <= 57:
                        expected, after = int(digits.decode('ascii')) << 16, 3
                    else:
                        expected, after = 0x30002, index + 1
                    self.assertEqual(bind.model(digits), (expected, after))
                    self.assertEqual(bind.instruction_value(digits, params), expected)
                    # A rejected byte wins over exhaustion immediately after it.
                    if not 48 <= byte <= 57:
                        self.assertEqual(bind.model(digits, end=index + 1), (expected, after))

    def test_exhaustion_offsets_and_no_delimiter_read(self):
        for start in range(5):
            buffer = b'x' * start + b'987\x00garbage'
            for remaining in range(3):
                self.assertEqual(bind.model(buffer, start, start + remaining), (0x30001, start + remaining))
            self.assertEqual(bind.model(buffer, start), (987 << 16, start + 3))
        self.assertEqual(bind.model(b'', (1 << 64) - 1), (0x30001, (1 << 64) - 1))
        for args in ((b'1', -1, 1), (b'1', 0, 2), (b'1', 1 << 64, 1)):
            with self.assertRaises(ValueError):
                bind.model(*args)

    def test_real_arithmetic_and_admission_mutants_change_results(self):
        # These alter decoded operand-derived algebra before the whole-body check.
        mutants = [(0x2e56516, 10, b'123'),  # IMUL hundreds factor
                   (0x2e56522, 33, b'123'),  # middle ASCII compensation
                   (0x2e56530, 8, b'123'),  # packed result shift
                   (0x2e564d2, 10, b':23'),  # first inclusive digit maximum
                   (0x2e564ed, 10, b'1:3'),  # second inclusive maximum
                   (0x2e5650e, 11, b'12:')]  # third exclusive limit
        for site, replacement, digits in mutants:
            changed = bytearray(self.body)
            changed[site - bind.START] = replacement
            with self.subTest(site=site):
                extracted = bind.parameters(bind.decode(changed, bind.START))
                self.assertNotEqual(bind.instruction_value(digits, extracted),
                                    bind.instruction_value(digits, self.record['parameters']))
                with self.assertRaisesRegex(ValueError, 'instruction rule changed'):
                    bind.validate_body(changed)

    def test_every_body_byte_is_checked_below_digest_gate(self):
        for offset in range(len(self.body)):
            changed = bytearray(self.body)
            changed[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                bind.validate_body(changed)

    def test_decoder_is_operand_driven_and_strict(self):
        self.assertEqual(bind.decode(bytes.fromhex('488b5718'), 0)[0]['assembly'], 'mov rdx, qword [rdi+0x18]')
        self.assertEqual(bind.decode(bytes.fromhex('6bc00a'), 0)[0]['assembly'], 'imul eax, eax, 0xa')
        self.assertEqual(bind.decode(bytes.fromhex('73fe'), 0x100)[0]['operands'], [{'target': 0x100}])
        self.assertEqual(bind.decode(bytes.fromhex('6683f802'), 0)[0]['assembly'], 'cmp ax, 0x2')
        self.assertEqual(bind.decode(bytes.fromhex('400fb6ce'), 0)[0]['assembly'], 'movzx ecx, sil')
        for code in (b'\x0f\x0b', b'\x48', b'\x48\x8b', b'\x48\x8b\x84\x24',
                     b'\xe8\x00', b'\x66\x90', b'\x80\xc9\x01', b'\xf3\xc3', b'\x48\xc3',
                     b'\x0f\xb6\xe4', b'\x48\x8d\xc1'):
            with self.subTest(code=code.hex()), self.assertRaises(ValueError):
                bind.decode(code, bind.START)
        for length in range(len(self.body)):
            with self.subTest(length=length), self.assertRaises(ValueError):
                bind.validate_body(self.body[:length])

    def test_branch_and_store_operand_corruptions(self):
        for site in (0x2e564c1, 0x2e564cc, 0x2e564e5, 0x2e56501):
            changed = bytearray(self.body)
            changed[site - bind.START] += 1
            with self.subTest(site=site), self.assertRaises(ValueError):
                bind.validate_body(changed)

    def test_public_digest_rejects_wrong_capture_before_output(self):
        for data in (b'', b'wrong capture'):
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                bind.analyze(data)
        with self.patched(self.offset(bind.START), b'\x49'):
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                bind.analyze(self.data)
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'wrong.elf'
            binary.write_bytes(b'wrong binary')
            output = Path(directory) / 'must-not-exist'
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                bind.generate(binary, output)
            self.assertFalse(output.exists())

    def test_shifted_fde_and_extent_cie_and_padding_controls(self):
        for field in (8, 12):
            offset = self.offset(bind.FDE['fde'] + field, 4)
            value = struct.unpack_from('<i', self.data, offset)[0]
            with self.patched(offset, struct.pack('<i', value + 1)):
                with self.assertRaisesRegex(ValueError, 'FDE changed'):
                    bind.inspect_static(self.data)
        with self.patched(self.offset(bind.FDE['cie'] + 21), b'\x02'):
            with self.assertRaisesRegex(ValueError, 'frame bytes changed'):
                bind.inspect_static(self.data)
        with self.patched(self.offset(bind.END), b'\x90'):
            with self.assertRaisesRegex(ValueError, 'padding'):
                bind.inspect_static(self.data)

    def test_wrong_incoming_call_target_and_consumer_shift(self):
        # Empty callee set: mutate the actual incoming call target instead.
        offset = self.offset(bind.CALL_SITE + 1, 4)
        old = struct.unpack_from('<i', self.data, offset)[0]
        with self.patched(offset, struct.pack('<i', old + 1)):
            with self.assertRaisesRegex(ValueError, 'caller target changed'):
                bind.inspect_static(self.data)
        with self.patched(self.offset(0x2e57e9b), b'\x08'):
            with self.assertRaisesRegex(ValueError, 'caller argument/result context'):
                bind.inspect_static(self.data)

    def test_full_text_scan_includes_unaligned_hits_and_final_position(self):
        code = bytearray(b'\x90' * 25)
        section = {'offset': 3, 'address': 0x1000, 'size': 19}
        for offset, opcode in ((4, 0xe8), (17, 0xe9)):
            site = section['address'] + offset - section['offset']
            code[offset:offset + 5] = bytes([opcode]) + struct.pack('<i', 0x1100 - site - 5)
        rows = bind.scan_direct(code, section, 0x1100)
        self.assertEqual([(r['file_offset'], r['kind']) for r in rows], [(4, 'call'), (17, 'jmp')])
        self.assertEqual(bind.scan_direct(code, section, 0x1101), [])
        # Insert a synthetic reference inside the real post-body padding; the
        # scanner must retain it even though no instruction alignment is proved.
        offset = self.offset(bind.END, 5)
        with self.patched(offset, b'\xe9' + struct.pack('<i', bind.START - bind.END - 5)):
            text = next(s for s in self.secs if s['name'] == '.text')
            hits = bind.scan_direct(self.data, text, bind.START)
            self.assertEqual([r['site'] for r in hits], [bind.END, bind.CALL_SITE])

    def test_source_location_reference_path_metadata_and_relocation(self):
        rel = self.record['source_context']['relocation']['file_offset']
        offsets = (self.offset(bind.LOCATION_SITE + 3), self.offset(bind.LOCATION_VA + 8),
                   self.offset(bind.LOCATION_VA + 16), self.offset(bind.PATH_VA), rel + 8, rel + 16)
        for offset in offsets:
            with self.subTest(offset=offset), self.patched(offset, bytes([self.data[offset] ^ 1])):
                with self.assertRaisesRegex(ValueError, 'source'):
                    bind.inspect_static(self.data)

    def test_manifest_whitelist_and_corruption_controls(self):
        self.check_manifest(bind.PACKET, ROOT)
        for variant in ('extra-file', 'extra-entry', 'duplicate', 'missing', 'changed-file', 'symlink'):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as directory:
                packet = Path(directory) / 'packet'
                shutil.copytree(bind.PACKET, packet)
                manifest = packet / 'MANIFEST.sha256'
                original = manifest.read_text()
                if variant == 'extra-file':
                    (packet / 'stray.txt').write_text('untracked evidence')
                elif variant == 'extra-entry':
                    manifest.write_text(original + '0' * 64 + '  stray.txt\n')
                elif variant == 'duplicate':
                    manifest.write_text(original + original.splitlines()[0] + '\n')
                elif variant == 'missing':
                    manifest.write_text('\n'.join(original.splitlines()[1:]) + '\n')
                elif variant == 'symlink':
                    manifest.unlink()
                    manifest.symlink_to(bind.PACKET / 'MANIFEST.sha256')
                else:
                    (packet / 'records.json').write_text('{}\n')
                with self.assertRaises(ValueError):
                    self.check_manifest(packet, ROOT)

    def test_no_disassembler_or_process_dependency(self):
        # Inspect executable AST operations, not the explanatory docstrings.
        import ast
        files = [ROOT / 'tools/node115_decimal_cursor.py', ROOT / 'tests/test_node115_decimal_cursor.py',
                 bind.PACKET / 'verify.py']
        for path in files:
            tree = ast.parse(path.read_text())
            imports = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imports.extend(a.name for a in node.names)
                elif isinstance(node, ast.ImportFrom):
                    imports.append(node.module)
            self.assertFalse({'subprocess', 'os', 'ctypes', 'capstone', 'unicorn'} & set(imports))
        self.assertEqual(hashlib.sha256(self.body).hexdigest(), bind.BODY_SHA)


if __name__ == '__main__':
    unittest.main()
