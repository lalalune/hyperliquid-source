"""Target-grounded and adversarial nv_stream evidence checks; stdlib only (MIT)."""
from contextlib import contextmanager
import copy
import hashlib
import importlib.util
import io
import json
import mmap
from pathlib import Path
import shutil
import struct
import tempfile
import unittest
from unittest import mock

from tools import nv_stream_inventory as n

PACKET = n.ROOT/'research/work-items/nv-stream-inventory-94'
spec = importlib.util.spec_from_file_location('nv_stream_verify', PACKET/'verify.py')
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)


class SmallImage:
    def __init__(self, raw, base=0x1000):
        self.raw, self.base = raw, base

    def read(self, va, size):
        off = va-self.base
        n.require(size > 0 and off >= 0 and off+size <= len(self.raw), 'synthetic read outside bytes')
        return self.raw[off:off+size]

    def evidence(self, va, size):
        return {'va': hex(va), 'file_offset': hex(va-self.base), 'section': 'synthetic',
                'bytes': self.read(va, size).hex()}


class DecoderTests(unittest.TestCase):
    def test_lea_all_registers_and_signed_displacement(self):
        for reg in range(16):
            for displacement in (-0x80000000, -7, 0, 0x7fffffff):
                raw = bytes((0x4c if reg >= 8 else 0x48, 0x8d, (reg%8)*8+5))+struct.pack('<i', displacement)
                self.assertEqual(n.decode_lea(raw, 0x100000000), (0x100000007+displacement, reg))

    def test_lea_rejects_shifted_wrong_modrm_and_width(self):
        for raw in (bytes.fromhex('8d0500000000'), bytes.fromhex('488d0400000000'),
                    bytes.fromhex('488d05000000'), bytes.fromhex('408d0500000000'),
                    bytes.fromhex('488d050000000000')):
            with self.subTest(raw=raw.hex()), self.assertRaises(n.EvidenceError): n.decode_lea(raw, 0x1000)

    def test_rel32_positive_negative_and_opcode(self):
        for op in (0xe8, 0xe9):
            for disp in (-2147483648, -5, 0, 2147483647):
                self.assertEqual(n.decode_rel32_transfer(bytes([op])+struct.pack('<i', disp), 0x100000000),
                                 0x100000005+disp)
        for raw in (b'\xe8\x00', b'\xeb\x00\x00\x00\x00', b'\xff\x00\x00\x00\x00'):
            with self.assertRaises(n.EvidenceError): n.decode_rel32_transfer(raw, 0)

    def test_boundary_decoder_modrm_sib_prefix_lengths(self):
        examples = ('48898c24c8000000', '48c744245819000000', '49c785100200000e000000',
                    '64488b1c2500000000', '6666662e0f1f840000000000', '488b0501000000',
                    'f0480fb10e', '0f8501000000', '41b812000000', '48b88877665544332211')
        for raw in examples:
            with self.subTest(raw=raw):
                decoded = n.decode_instruction(bytes.fromhex(raw))
                self.assertEqual(decoded['raw'].hex(), raw)

    def test_truncated_instructions_at_every_byte(self):
        for raw in ('488d0d69d215fe', '48c78424d00000001c000000', 'e8e932fcff',
                    '48898c24c8000000', '48b88877665544332211'):
            code = bytes.fromhex(raw)
            for end in range(len(code)):
                with self.subTest(raw=raw, end=end), self.assertRaises(n.EvidenceError):
                    n.decode_instruction(code[:end])

    def test_unknown_reserved_overlong_and_invalid_lock_fail(self):
        for raw in ('c5f877', '62f17c4858c0', 'ff38', 'c7c800000000', '488dc0',
                    'f0833801', 'f090', 'f2f390', '666601c0', '66'*14+'0f1f00'):
            with self.subTest(raw=raw), self.assertRaises(n.EvidenceError):
                n.decode_instruction(bytes.fromhex(raw))

    def test_embedded_lea_and_call_are_not_boundaries(self):
        for operand in (bytes.fromhex('488d050000000090'), bytes.fromhex('e801000000909090')):
            raw = b'\x48\xb8'+operand+b'\xc3'
            im = SmallImage(raw)
            insns = n.decode_fde(im, {'start': 0x1000, 'end': 0x1000+len(raw)})
            self.assertEqual([x['site'] for x in insns], [0x1000, 0x100a])
            with self.assertRaises(n.EvidenceError): n.verified_lea(im, insns, 0x1002, 0x1009)
            self.assertEqual(n.scoped_edges(im, {0x1000: insns}), [])

    def test_internal_branch_to_operand_rejected(self):
        im = SmallImage(bytes.fromhex('eb0148b80000000000000000c3'))
        with self.assertRaisesRegex(n.EvidenceError, 'inside an instruction'):
            n.decode_fde(im, {'start': 0x1000, 'end': 0x1000+len(im.raw)})

    def test_complete_fde_not_silently_truncated(self):
        im = SmallImage(bytes.fromhex('90488d05'))
        with self.assertRaises(n.EvidenceError):
            n.decode_fde(im, {'start': 0x1000, 'end': 0x1004})

    def test_register_immediate_values(self):
        self.assertEqual(n.decode_mov_immediate(bytes.fromhex('b912000000')), {'register': 1, 'value': 18, 'width': 32})
        self.assertEqual(n.decode_mov_immediate(bytes.fromhex('41b8ffffffff'))['register'], 8)
        self.assertEqual(n.decode_mov_immediate(bytes.fromhex('48c7c0ffffffff'))['value'], -1)

    def test_qword_store_and_pointer_register(self):
        memory, reg = n.decode_pointer_store(bytes.fromhex('4c89b310020000'))
        self.assertEqual((memory, reg), ({'base_register': 3, 'displacement': 528}, 14))
        x = n.decode_mov_immediate(bytes.fromhex('49c785100200000e000000'))
        self.assertEqual(x, {'memory': {'base_register': 13, 'displacement': 528}, 'value': 14, 'width': 64})
        x = n.decode_mov_immediate(bytes.fromhex('48c74424f8ffffffff'))
        self.assertEqual(x['memory']['displacement'], -8)
        self.assertEqual(x['value'], -1)

    def test_memory_decoders_reject_index_rip_width_and_extension(self):
        for raw in ('c744245819000000', '48c74c245819000000', '48c7050000000019000000',
                    '48c744645819000000', '48c74424581900000000'):
            with self.subTest(raw=raw), self.assertRaises(n.EvidenceError):
                n.decode_mov_immediate(bytes.fromhex(raw))
        for raw in ('48890d00000000', '4889446458', '4489442458'):
            with self.subTest(raw=raw), self.assertRaises(n.EvidenceError):
                n.decode_pointer_store(bytes.fromhex(raw))

    def test_counted_ascii_markers_and_prefix(self):
        raw = b'\xc0\x03pre\xc0\x08 message\xc0'
        im = SmallImage(raw)
        proof = n.counted_fragment(im, 0x1000, 0x1008, b'message')
        self.assertEqual(proof['length'], 8)
        self.assertEqual(len(proof['chunks']), 2)
        self.assertEqual(proof['pattern']['bytes'], raw.hex())

    def test_counted_fragment_never_crosses_zero_terminator(self):
        # Adjacent real templates can be separated by C0 00 C0. Zero ends
        # this bounded traversal, even when a later probe is a valid chunk.
        raw = b'\x03old\xc0\x00\xc0\x03new\xc0'
        with self.assertRaises(n.EvidenceError):
            n.counted_fragment(SmallImage(raw), 0x1000, 0x1008, b'new')

    def test_counted_fragment_corrupt_lengths_markers_and_ascii(self):
        for raw in (b'\x04abc\xc0', b'\x03abc\xc1', b'\x03a\x80c\xc0', b'\x00abc\xc0'):
            with self.subTest(raw=raw), self.assertRaises(n.EvidenceError):
                n.counted_fragment(SmallImage(raw), 0x1000, 0x1001, b'abc')


class TargetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.handle = (n.ROOT/n.TARGET).open('rb')
        cls.data = mmap.mmap(cls.handle.fileno(), 0, access=mmap.ACCESS_READ)
        # A build must remain entirely Python/static even with executables on PATH.
        with mock.patch('subprocess.Popen', side_effect=AssertionError('external process forbidden')), \
             mock.patch('socket.create_connection', side_effect=AssertionError('network forbidden')):
            cls.results = n.build(cls.data)
        cls.e = cls.results['inventory.json']
        cls.image = n.Image(cls.data)
        cls.relocations = n.relative_relocations(cls.image)
        cls.decoded = {int(f['start'], 16): [{'site': int(f['start'], 16)+int(row[0], 16),
                         'raw': bytes.fromhex(row[1]), 'kind': row[2]} for row in f['instructions']]
                       for f in cls.results['instructions.json']['fdes']}
        cls.diagnostics = {d['probe']: d for d in cls.e['diagnostics']}

    @classmethod
    def tearDownClass(cls):
        cls.data.close(); cls.handle.close()

    @contextmanager
    def mutated(self, va, replacement):
        _, off = self.image.mapping(va, len(replacement))
        with mmap.mmap(self.handle.fileno(), 0, access=mmap.ACCESS_COPY) as data:
            data[off:off+len(replacement)] = replacement
            yield data, n.Image(data)

    def test_exact_location_layout_and_edges(self):
        v.verify_facts(self.e)
        self.assertEqual(self.e['metrics']['locations'], 28)
        self.assertEqual(self.e['metrics']['scoped_fde_bytes'], 70375)
        self.assertEqual(self.e['metrics']['decoded_instructions'], 12350)

    def test_every_location_has_relocation_and_decoded_leas(self):
        for loc in self.e['locations']:
            slot = int(loc['va'], 16)
            self.assertEqual(loc['path'], 'node/src/nv_stream.rs')
            self.assertTrue(loc['lea_sites'])
            self.assertEqual(self.relocations[slot]['target'], int(loc['path_bytes']['va'], 16))
            self.assertEqual(loc['path_length'], len(n.PREFIX+n.SCOPE))
        for row in self.e['location_leas']:
            n.verified_lea(self.image, self.decoded[int(row['owner'], 16)],
                           int(row['instruction']['va'], 16), int(row['location'], 16))

    def test_wrong_digest_and_empty_input_rejected_before_parse(self):
        for raw in (b'', b'\x7fELF'+bytes(60)):
            with self.assertRaisesRegex(n.EvidenceError, 'SHA-256 mismatch'): n.build(raw)
        with self.mutated(0x569ed68+16, struct.pack('<I', 59)) as (data, _):
            with self.assertRaisesRegex(n.EvidenceError, 'SHA-256 mismatch'): n.build(data)

    def test_wrong_digest_cli_does_not_write_output(self):
        with tempfile.TemporaryDirectory() as temp:
            binary, out = Path(temp)/'wrong.bin', Path(temp)/'output'
            binary.write_bytes(b'incorrect captured target')
            with mock.patch('sys.argv', ['nv_stream_inventory.py', '--binary', str(binary), '--out', str(out)]), \
                 mock.patch('sys.stderr', new_callable=io.StringIO):
                with self.assertRaises(SystemExit) as error: n.main()
            self.assertEqual(error.exception.code, 1)
            self.assertFalse(out.exists())

    def test_location_pointer_length_line_column_corruption(self):
        for delta, replacement in ((0, struct.pack('<Q', 1)), (8, struct.pack('<Q', 1)),
                                   (16, struct.pack('<I', 0)), (20, struct.pack('<I', 0))):
            with self.subTest(delta=delta), self.mutated(0x569ed68+delta, replacement) as (_, image):
                with self.assertRaises(n.EvidenceError):
                    n.decode_location(image, 0x569ed68, self.relocations[0x569ed68])

    def test_wrong_exact_path_and_shifted_location_slot(self):
        path = self.relocations[0x569ed68]['target']
        with self.mutated(path+len(n.PREFIX), b'X') as (_, image):
            with self.assertRaises(n.EvidenceError): n.decode_location(image, 0x569ed68, self.relocations[0x569ed68])
        with self.assertRaises(n.EvidenceError): n.decode_location(self.image, 0x569ed69, self.relocations[0x569ed68])

    def test_relocation_symbol_and_shifted_addend(self):
        relocation = self.relocations[0x569ed68]
        with self.mutated(relocation['entry_va']+8, struct.pack('<Q', 0x100000008)) as (_, image):
            with self.assertRaises(n.EvidenceError): n.relative_relocations(image)
        changed = {**relocation, 'target': relocation['target']+1}
        with self.assertRaises(n.EvidenceError): n.decode_location(self.image, 0x569ed68, changed)

    def test_duplicate_relocation_slot_rejected(self):
        first, second = list(self.relocations.values())[:2]
        slot = struct.unpack('<Q', self.image.read(first['entry_va'], 8))[0]
        with self.mutated(second['entry_va'], struct.pack('<Q', slot)) as (_, image):
            with self.assertRaisesRegex(n.EvidenceError, 'duplicate relocation'): n.relative_relocations(image)

    def test_missing_required_section(self):
        shoff = struct.unpack_from('<Q', self.data, 40)[0]
        entsize, _, names_index = struct.unpack_from('<HHH', self.data, 58)
        names_off = struct.unpack_from('<Q', self.data, shoff+names_index*entsize+24)[0]
        for section in (b'.text\0', b'.rela.dyn\0', b'.eh_frame\0'):
            off = self.data.find(section, names_off)
            self.assertGreaterEqual(off, 0)
            with mmap.mmap(self.handle.fileno(), 0, access=mmap.ACCESS_COPY) as data:
                data[off+1:off+2] = b'X'
                with self.assertRaisesRegex(n.EvidenceError, 'missing section'): n.Image(data)

    def test_nonexecuting_text_section_rejected(self):
        shoff = struct.unpack_from('<Q', self.data, 40)[0]
        entsize = struct.unpack_from('<H', self.data, 58)[0]
        index = next(i for i, s in enumerate(self.image.sections) if s['name'] == '.text')
        off = shoff+index*entsize+8
        with mmap.mmap(self.handle.fileno(), 0, access=mmap.ACCESS_COPY) as data:
            flags = struct.unpack_from('<Q', data, off)[0]
            data[off:off+8] = struct.pack('<Q', flags & ~4)
            with self.assertRaisesRegex(n.EvidenceError, 'non-executable'): n.Image(data)

    def test_malformed_fde_range_and_unwind_pointer(self):
        record = self.e['fdes'][0]['fde_record']
        with self.mutated(int(record['va'], 16)+12, struct.pack('<i', -1)) as (_, image):
            with self.assertRaises(ValueError): n.Fdes(image)
        hdr = self.image.by_name['.eh_frame_hdr']['address']
        with self.mutated(hdr+4, bytes(4)) as (_, image):
            with self.assertRaises(ValueError): n.Fdes(image)

    def test_shifted_lea_and_changed_displacement_fail(self):
        insns = self.decoded[0x227a0e0]
        with self.assertRaises(n.EvidenceError): n.verified_lea(self.image, insns, 0x227b758, 0x569ed68)
        row = next(x for x in insns if x['site'] == 0x227b757)
        with self.mutated(row['site']+3, bytes(4)) as (_, image):
            with self.assertRaises(n.EvidenceError): n.verified_lea(image, insns, row['site'], 0x569ed68)

    def test_literal_pair_exact_length_and_adjacent_field(self):
        insns = self.decoded[0x227a0e0]
        i = next(i for i, x in enumerate(insns) if x['site'] == 0x227ac37)
        result = n.pointer_length_pair(self.image, insns, i, b'nv stream client block or tx')
        self.assertEqual(result['length'], 28)
        for delta in (-1, 1):
            changed = copy.deepcopy(insns[i:i+3])
            raw = bytearray(changed[2]['raw']); raw[-4:] = struct.pack('<i', 28+delta)
            changed[2]['raw'] = bytes(raw)
            with self.assertRaises(n.EvidenceError): n.pointer_length_pair(self.image, changed, 0, b'nv stream client block or tx')
        changed = copy.deepcopy(insns[i:i+3])
        raw = bytearray(changed[2]['raw']); raw[4:8] = struct.pack('<i', 0xd8)
        changed[2]['raw'] = bytes(raw)
        with self.assertRaises(n.EvidenceError): n.pointer_length_pair(self.image, changed, 0, b'nv stream client block or tx')

    def test_literal_pointer_register_mismatch_rejected(self):
        insns = self.decoded[0x227a0e0]
        i = next(i for i, x in enumerate(insns) if x['site'] == 0x227ac37)
        changed = copy.deepcopy(insns[i:i+3])
        changed[1]['raw'] = bytes.fromhex('48898424c8000000')
        with self.assertRaises(n.EvidenceError): n.pointer_length_pair(self.image, changed, 0, b'nv stream client block or tx')

    def test_literal_content_corruption_rejected(self):
        insns = self.decoded[0x227a0e0]
        i = next(i for i, x in enumerate(insns) if x['site'] == 0x227ac37)
        with self.mutated(0x3d7ea7, b'X') as (_, image):
            with self.assertRaises(n.EvidenceError): n.pointer_length_pair(image, insns, i, b'nv stream client block or tx')

    def test_register_length_setup_rejects_clobber(self):
        insns = self.decoded[0x227a0e0]
        i = next(i for i, x in enumerate(insns) if x['site'] == 0x227ae86)
        result = n.pointer_length_pair(self.image, insns, i, b'nv_gossip_priority')
        self.assertEqual((result['pointer_register'], result['length_register'], result['length']), (2, 1, 18))
        changed = copy.deepcopy(insns[i:i+6])
        raw = bytearray(changed[1]['raw']); raw[0] = 0x48; raw[2] = 0x15
        changed[1]['raw'] = bytes(raw)
        with self.assertRaises(n.EvidenceError): n.pointer_length_pair(self.image, changed, 0, b'nv_gossip_priority')

    def test_counted_template_binding_does_not_cross_to_neighbor(self):
        start = self.diagnostics['starting bootstrap']['anchors']
        self.assertEqual([(x['owner'], x['lea']['va']) for x in start], [('0x4389070', '0x438924b')])
        old = self.diagnostics['received old client block, is peer behind?']['anchors']
        self.assertEqual({x['length'] for x in old}, {61})
        self.assertEqual(len(old), 3)

    def test_target_counted_length_and_marker_corruption(self):
        for va, replacement in ((0x20249e, b'\x24'), (0x20249e+38, b'\xc1')):
            with self.mutated(va, replacement) as (_, image):
                with self.assertRaises(n.EvidenceError):
                    n.counted_fragment(image, 0x20249e, 0x20249f, b'failed to verify client block batch')

    def test_unbound_and_absent_probes_not_promoted(self):
        self.assertEqual({d['probe'] for d in self.e['diagnostics'] if d['status'] == 'present-but-unbound'}, {
            'nv_stream_apply_execution_state', 'nv_stream_forward_client_blocks', 'Too many unconfirmed blocks',
            'too many blocks to request', 'bootstrap ended past original block, is peer malicious?'})
        for d in self.e['diagnostics']:
            if d['status'] == 'absent': self.assertEqual(d['occurrences'], [])
            if d['status'] != 'bound': self.assertEqual(d['anchors'], [])

    def test_constants_are_only_unique_adjacent_numeric_fields(self):
        bound = {c['value']: c for c in self.e['constants'] if c['status'] == 'bound'}
        self.assertEqual({x['instruction']['va'] for x in bound[5000]['co_locations']}, {'0x227ac52', '0x227acf3'})
        self.assertEqual(bound[8000000]['co_locations'][0]['instruction']['bytes'], '48c7832803000000127a00')
        self.assertTrue(all(c['semantic_name_and_units'] == 'unresolved' for c in self.e['constants']))
        changed = copy.deepcopy(self.e['diagnostics'])
        changed[0]['anchors'].append(copy.deepcopy(changed[0]['anchors'][0]))
        constants = n.constant_inventory(self.image, self.decoded, changed)
        self.assertEqual(constants[0]['status'], 'unresolved')

    def test_call_edges_exact_target_landing_and_mutation(self):
        self.assertEqual(n.scoped_edges(self.image, self.decoded), self.e['call_edges'])
        decoded = copy.deepcopy(self.decoded)
        call = next(x for x in decoded[0x439baf0] if x['site'] == 0x439c9b2)
        call['raw'] = b'\xe8'+struct.pack('<i', struct.unpack_from('<i', call['raw'], 1)[0]+1)
        edges = n.scoped_edges(self.image, decoded)
        self.assertEqual(len(edges), 5)  # Callee interior must not be promoted.

    def test_transfer_evidence_rejects_stale_instruction_bytes(self):
        decoded = copy.deepcopy(self.decoded)
        call = next(x for x in decoded[0x439baf0] if x['site'] == 0x439c9b2)
        call['raw'] = b'\xe8'+struct.pack('<i', 0x4389070-call['site']-5)
        with self.assertRaises(n.EvidenceError): n.scoped_edges(self.image, decoded)

    def test_literal_setup_cannot_splice_noncontiguous_instructions(self):
        insns = self.decoded[0x227a0e0]
        i = next(i for i, x in enumerate(insns) if x['site'] == 0x227ac37)
        changed = copy.deepcopy(insns[i:i+3])
        changed[2]['site'] += 1
        with self.assertRaises(n.EvidenceError):
            n.pointer_length_pair(self.image, changed, 0, b'nv stream client block or tx')

    def test_instructions_redecode_exactly_cover_fdes(self):
        for fde in self.e['fdes']:
            start, end = int(fde['start'], 16), int(fde['end_exclusive'], 16)
            insns = n.decode_fde(self.image, {'start': start, 'end': end})
            self.assertEqual(insns, self.decoded[start])
            self.assertEqual(hashlib.sha256(b''.join(x['raw'] for x in insns)).hexdigest(), fde['code_sha256'])

    def test_metrics_recompute_from_records(self):
        e, m = self.e, self.e['metrics']
        self.assertEqual(m['location_leas'], len(e['location_leas']))
        self.assertEqual(m['scoped_fdes'], len(e['fdes']))
        self.assertEqual(m['diagnostics_probed'], len(e['diagnostics']))
        for status, suffix in (('bound', 'bound'), ('present-but-unbound', 'unresolved'), ('absent', 'absent')):
            self.assertEqual(m['diagnostics_'+suffix], sum(d['status'] == status for d in e['diagnostics']))
        self.assertEqual(m['scoped_rel32_calls'], len(e['call_edges']))
        self.assertEqual(m['pointer_length_anchors']+m['counted_fragment_anchors'], sum(len(d['anchors']) for d in e['diagnostics']))

    def test_committed_byte_identical_regeneration_and_docs(self):
        v.verify_outputs(PACKET, n, self.results)

    def test_manifest_whitelist(self):
        v.verify_manifest(PACKET)

    @contextmanager
    def copied_packet(self):
        with tempfile.TemporaryDirectory() as temp:
            here = Path(temp)
            for name in v.MANIFEST | {'MANIFEST.sha256'}: shutil.copyfile(PACKET/name, here/name)
            yield here

    def test_manifest_extra_file_directory_and_symlink_rejected(self):
        for kind in ('file', 'directory', 'symlink'):
            with self.subTest(kind=kind), self.copied_packet() as here:
                extra = here/'unexpected'
                if kind == 'file': extra.write_bytes(b'new')
                elif kind == 'directory': extra.mkdir()
                else: extra.symlink_to('README.md')
                with self.assertRaises(ValueError): v.verify_manifest(here)

    def test_manifest_omission_duplicate_traversal_and_tamper(self):
        for kind in ('omit', 'duplicate', 'traversal', 'tamper'):
            with self.subTest(kind=kind), self.copied_packet() as here:
                manifest = here/'MANIFEST.sha256'; lines = manifest.read_text().splitlines()
                if kind == 'omit': manifest.write_text('\n'.join(lines[1:])+'\n')
                elif kind == 'duplicate': manifest.write_text('\n'.join(lines+[lines[0]])+'\n')
                elif kind == 'traversal': manifest.write_text(lines[0][:66]+'../README.md\n'+'\n'.join(lines[1:])+'\n')
                else: (here/'RESULT.md').write_text('changed')
                with self.assertRaises(ValueError): v.verify_manifest(here)

    def test_readme_and_result_counts_equal_regenerated_json(self):
        v.verify_docs(PACKET, n, self.e['metrics'])
        for name in ('README.md', 'RESULT.md'):
            with self.copied_packet() as here:
                path = here/name
                path.write_text(path.read_text().replace('| locations | 28 |', '| locations | 29 |'))
                with self.assertRaises(ValueError): v.verify_docs(here, n, self.e['metrics'])

    def test_updated_manifest_does_not_hide_json_corruption(self):
        with self.copied_packet() as here:
            path = here/'inventory.json'; changed = json.loads(path.read_text())
            changed['locations'][0]['line'] += 1; path.write_bytes(n.render(changed))
            (here/'MANIFEST.sha256').write_text(''.join(hashlib.sha256((here/name).read_bytes()).hexdigest()+'  '+name+'\n'
                                                      for name in sorted(v.MANIFEST)))
            v.verify_manifest(here)
            with self.assertRaises(ValueError): v.verify_outputs(here, n, self.results)


if __name__ == '__main__':
    unittest.main()
