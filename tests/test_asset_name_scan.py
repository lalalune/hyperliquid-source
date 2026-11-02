"""Static target-grounded controls for the complete asset-name scanning leaf."""
from contextlib import contextmanager
import copy
import json
import mmap
from pathlib import Path
import random
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import asset_name_scan as bind


class AssetNameScanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.generated = bind.payload()
        cls.records = json.loads(cls.generated['records.json'])
        with bind.BINARY.open('rb') as handle:
            with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
                image = bind.Image(data)
                cls.body = image.read(bind.START, bind.END - bind.START)
                cls.caller_bytes = image.read(bind.CALLSITE, 5)
                cls.text_offset = image.offset(bind.START, 1)
                cls.call_offset = image.offset(bind.CALLSITE, 5)
                cls.padding_offset = image.offset(bind.END, 1)
        cls.instructions = bind.check_leaf(cls.body)

    @contextmanager
    def mutated_image(self, offset, replacement):
        # One private mapping; only changed pages are copied, never the whole ELF.
        with bind.BINARY.open('rb') as handle:
            with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_COPY) as data:
                data[offset:offset + len(replacement)] = replacement
                yield data

    @contextmanager
    def packet_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            packet = Path(directory) / 'packet'
            packet.mkdir()
            for name in (*bind.LOCAL_FILES, 'MANIFEST.sha256'):
                shutil.copyfile(bind.PACKET / name, packet / name)
            yield packet

    def rewrite_manifest(self, packet):
        (packet / 'MANIFEST.sha256').write_text(bind.manifest_text(packet))

    def test_packet_verifies(self):
        self.assertEqual(bind.check_packet(), self.records)

    def test_regeneration_is_byte_identical(self):
        with tempfile.TemporaryDirectory() as directory:
            bind.generate(directory)
            for name in (*bind.LOCAL_FILES, 'MANIFEST.sha256'):
                self.assertEqual((Path(directory) / name).read_bytes(), (bind.PACKET / name).read_bytes(), name)

    def test_no_disassembler_or_external_process_dependency(self):
        with (patch.object(subprocess, 'run', side_effect=AssertionError('external process')),
             patch.object(subprocess, 'Popen', side_effect=AssertionError('external process')),
             patch.object(subprocess, 'check_output', side_effect=AssertionError('external process'))):
            self.assertEqual(bind.payload(), self.generated)

    def test_readme_counts_equal_json(self):
        readme = (bind.PACKET / 'README.md').read_text()
        table = readme.split('<!-- counts:start -->\n')[1].split('\n<!-- counts:end -->')[0]
        self.assertEqual(table, bind.counts_table(self.records))
        self.assertEqual(self.records['counts']['decoded_instructions'], len(self.instructions))
        self.assertEqual(self.records['counts']['vectors'], len(self.records['vectors']))
        self.assertEqual(self.records['counts']['body_bytes'], sum(len(i.raw) for i in self.instructions))
        self.assertEqual(self.records['counts']['callees'], len(self.records['function']['callees']))
        self.assertEqual(self.records['counts']['direct_e8_callers'], len(self.records['caller_census']['hits']))

    def test_recorded_vectors_have_independent_expected_rule(self):
        for vector in self.records['vectors']:
            with self.subTest(basis=vector['basis']):
                text = bytes.fromhex(vector['input_hex']).decode('utf-8')
                expected = (vector['expected_al'], vector['expected_cursor'])
                self.assertEqual(bind.scan_model(text, vector['initial_cursor']), expected)
                trace = bind.interpret(self.instructions, text.encode(), vector['initial_cursor'])
                self.assertEqual((trace['al'], trace['cursor']), expected)
                self.assertEqual(trace['writes'], vector['cursor_writes'])

    def test_exhaustive_ascii_predicate_and_stop_cursor(self):
        for cp in range(128):
            text = 'AZ09' + chr(cp) + 'A'
            expected = (0, 6) if 48 <= cp <= 57 or 65 <= cp <= 90 else (1, 5)
            with self.subTest(codepoint=cp):
                trace = bind.interpret(self.instructions, text.encode())
                self.assertEqual((trace['al'], trace['cursor']), expected)
                self.assertEqual(bind.scan_model(text), expected)

    def test_unicode_boundaries_are_consumed_and_rejected(self):
        for cp in (0x7f, 0x80, 0x7ff, 0x800, 0xd7ff, 0xe000, 0xffff, 0x10000, 0x10ffff):
            with self.subTest(codepoint=cp):
                raw = ('A' + chr(cp) + 'Z').encode()
                trace = bind.interpret(self.instructions, raw)
                self.assertEqual((trace['al'], trace['cursor']), (1, len(raw) - 1))
                self.assertEqual(trace['writes'], list(range(1, len(raw))))

    def test_deterministic_mixed_strings_agree_with_model(self):
        rng = random.Random(94)
        alphabet = 'AZM09_az\x00é€😀'
        for _ in range(150):
            text = ''.join(rng.choice(alphabet) for _ in range(rng.randrange(24)))
            boundary = len(text[:rng.randrange(len(text) + 1)].encode())
            actual = bind.interpret(self.instructions, text.encode(), boundary)
            self.assertEqual((actual['al'], actual['cursor']), bind.scan_model(text, boundary))

    def test_rejection_only_sets_al_not_full_rax(self):
        trace = bind.interpret(self.instructions, b'a')
        self.assertEqual(trace['al'], 1)
        self.assertEqual(trace['rax'], 0x100000001)
        self.assertNotEqual(trace['rax'], 1)
        self.assertEqual(bind.interpret(self.instructions, b'A')['rax'], 0)

    def test_empty_suffix_does_not_read_or_store(self):
        self.assertEqual(bind.interpret(self.instructions, b''), {'al': 0, 'rax': 0, 'cursor': 0, 'writes': []})
        self.assertEqual(bind.interpret(self.instructions, b'A', 1)['writes'], [])

    def test_malformed_overlong_encoding_is_not_validated(self):
        # c1 81 masks to U+0041, so the machine rule accepts it despite invalid UTF-8.
        trace = bind.interpret(self.instructions, b'\xc1\x81Z')
        self.assertEqual((trace['al'], trace['cursor']), (0, 3))
        with self.assertRaises(UnicodeDecodeError):
            b'\xc1\x81Z'.decode('utf-8')

    def test_malformed_sentinel_returns_false_before_end(self):
        # f4 90 80 80 assembles exactly 0x110000 at the decoded cmp immediate.
        trace = bind.interpret(self.instructions, b'\xf4\x90\x80\x80a')
        self.assertEqual((trace['al'], trace['cursor']), (0, 4))
        self.assertEqual(trace['writes'], [1, 2, 3, 4])

    def test_truncated_scalar_reports_analysis_memory_error(self):
        with self.assertRaisesRegex(ValueError, 'read outside supplied memory'):
            bind.interpret(self.instructions, b'\xf0')

    def test_every_window_byte_is_pinned(self):
        for index in range(len(self.body)):
            corrupt = bytearray(self.body)
            corrupt[index] ^= 1
            with self.subTest(offset=index), self.assertRaisesRegex(ValueError, 'body SHA-256'):
                bind.check_leaf(corrupt)

    def test_decoder_rejects_every_truncated_instruction(self):
        for instruction in self.instructions:
            for cut in range(1, len(instruction.raw)):
                with self.subTest(va=hex(instruction.va), cut=cut), self.assertRaises(ValueError):
                    bind.decode(instruction.raw[:cut], instruction.va)

    def test_decoder_rejects_unsupported_encoding(self):
        with self.assertRaisesRegex(ValueError, 'unsupported opcode'):
            bind.decode(b'\x90', bind.START)
        with self.assertRaisesRegex(ValueError, 'unsupported arithmetic group'):
            bind.decode(bytes.fromhex('83d001'), bind.START)

    def test_wrong_digest_cannot_be_overridden(self):
        with self.mutated_image(self.text_offset, b'\x90') as data:
            with self.assertRaisesRegex(ValueError, 'digest/size mismatch'):
                bind.authenticate(data)
        with self.assertRaisesRegex(ValueError, 'digest/size mismatch'):
            bind.authenticate(b'not the node')

    def test_shifted_fde_is_rejected_independently_of_digest(self):
        # PC-relative FDE start is at record+8, not the next unwind-index start.
        offset = int(self.records['function']['fde']['fde_file_offset'], 16) + 8
        with bind.BINARY.open('rb') as handle:
            handle.seek(offset)
            original = struct.unpack('<i', handle.read(4))[0]
        with self.mutated_image(offset, struct.pack('<i', original + 1)) as data:
            with self.assertRaisesRegex(ValueError, 'missing/ambiguous FDE start'):
                bind.analyze(bind.Image(data))

    def test_wrong_cie_is_rejected_independently_of_digest(self):
        offset = int(self.records['function']['fde']['fde_file_offset'], 16) + 4
        with self.mutated_image(offset, struct.pack('<I', 1)) as data:
            with self.assertRaisesRegex(ValueError, 'names no preceding CIE'):
                bind.Image(data)

    def test_wrong_callee_target_is_rejected(self):
        corrupt = bytearray(self.caller_bytes)
        struct.pack_into('<i', corrupt, 1, struct.unpack_from('<i', corrupt, 1)[0] + 1)
        self.assertEqual(bind.decode(corrupt, bind.CALLSITE)[0].args, (bind.START + 1,))
        with self.mutated_image(self.call_offset, corrupt) as data:
            with self.assertRaisesRegex(ValueError, 'direct caller census mismatch'):
                bind.analyze(bind.Image(data))

    def test_padding_mutation_is_rejected(self):
        with self.mutated_image(self.padding_offset, b'\x90') as data:
            with self.assertRaisesRegex(ValueError, 'padding mismatch'):
                bind.analyze(bind.Image(data))

    def test_location_relocation_mutation_is_rejected(self):
        offset = int(self.records['caller_context']['location']['relocation']['file_offset'], 16) + 16
        with self.mutated_image(offset, struct.pack('<q', bind.PATH_VA + 1)) as data:
            with self.assertRaisesRegex(ValueError, 'Location RELATIVE relocation mismatch'):
                bind.analyze(bind.Image(data))

    def test_semantic_record_mutation_survives_manifest_but_not_regeneration(self):
        with self.packet_copy() as packet:
            altered = copy.deepcopy(self.records)
            altered['rule']['accepted_scalar_intervals_inclusive'][0][0] -= 1
            (packet / 'records.json').write_text(json.dumps(altered, indent=2) + '\n')
            self.rewrite_manifest(packet)
            bind.check_manifest(packet)
            with self.assertRaisesRegex(ValueError, 'regenerated evidence differs: records.json'):
                bind.check_packet(packet)

    def test_recorded_digest_mutation_is_rejected(self):
        with self.packet_copy() as packet:
            records = copy.deepcopy(self.records)
            records['target']['sha256'] = '0' * 64
            (packet / 'records.json').write_text(json.dumps(records, indent=2) + '\n')
            self.rewrite_manifest(packet)
            with self.assertRaisesRegex(ValueError, 'regenerated evidence differs'):
                bind.check_packet(packet)

    def test_readme_count_mutation_is_rejected(self):
        with self.packet_copy() as packet:
            path = packet / 'README.md'
            path.write_text(path.read_text().replace('| body_bytes | 204 |', '| body_bytes | 205 |'))
            self.rewrite_manifest(packet)
            with self.assertRaisesRegex(ValueError, 'regenerated evidence differs: README.md'):
                bind.check_packet(packet)

    def test_instruction_walk_mutation_is_rejected(self):
        with self.packet_copy() as packet:
            path = packet / 'instructions.txt'
            path.write_text(path.read_text().replace('cmp esi, 0xffffffe6', 'cmp esi, 0xffffffe7'))
            self.rewrite_manifest(packet)
            with self.assertRaisesRegex(ValueError, 'regenerated evidence differs: instructions.txt'):
                bind.check_packet(packet)

    def test_manifest_rejects_duplicate_missing_traversal_and_hash(self):
        with self.packet_copy() as packet:
            path = packet / 'MANIFEST.sha256'
            good = path.read_text()
            variants = [good + good.splitlines()[0] + '\n',
                        '\n'.join(good.splitlines()[1:]) + '\n',
                        good + '0' * 64 + '  ../unapproved\n',
                        '0' * 64 + good[64:]]
            for bad in variants:
                with self.subTest(manifest=bad[:30]):
                    path.write_text(bad)
                    with self.assertRaisesRegex(ValueError, 'manifest'):
                        bind.check_manifest(packet)

    def test_manifest_rejects_symlink(self):
        with self.packet_copy() as packet:
            path = packet / 'instructions.txt'
            path.unlink()
            path.symlink_to(bind.PACKET / 'instructions.txt')
            with self.assertRaisesRegex(ValueError, 'symlink'):
                bind.check_manifest(packet)

    def test_novelty_checks_record_empty_results_and_input_snapshots(self):
        novelty = self.records['novelty']
        self.assertEqual(novelty['baseline'], bind.BASELINE)
        self.assertEqual({(c['term'], c['scope']) for c in novelty['checks']},
                         {(term, scope) for term in ('2786530', str(bind.START)) for scope in ('research', 'pr_titles')})
        for check in novelty['checks']:
            self.assertEqual((check['exit_code'], check['stdout'], check['stderr']), (1, '', ''))
        self.assertEqual({row['name'] for row in novelty['pr_lists']},
                         {'open_prs.txt', 'merged_prs.txt', 'closed_unmerged_prs.txt'})


if __name__ == '__main__':
    unittest.main()
