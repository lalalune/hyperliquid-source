"""Target-grounded and adversarial spot_meta evidence checks; stdlib only (MIT)."""
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

from tools import spot_meta_inventory as n

PACKET = n.ROOT/'research/work-items/spot-meta-inventory-94'
spec = importlib.util.spec_from_file_location('spot_meta_verify', PACKET/'verify.py')
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

    def test_scoped_sse_bswap_and_double_shift_lengths(self):
        # These forms occur in selected target FDEs; truncated forms fail.
        for raw in ('0f138424a0040000', '490fcf', '660f120cc1', '480fa4ce3f'):
            code = bytes.fromhex(raw)
            self.assertEqual(n.decode_instruction(code)['raw'], code)
            for end in range(len(code)):
                with self.subTest(raw=raw, end=end), self.assertRaises(n.EvidenceError):
                    n.decode_instruction(code[:end])
        with self.assertRaises(n.EvidenceError): n.decode_instruction(bytes.fromhex('0f13c0'))

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
        with mock.patch('subprocess.Popen', side_effect=AssertionError('external process forbidden')), \
             mock.patch('socket.create_connection', side_effect=AssertionError('network forbidden')):
            cls.results = n.build(cls.data)
        cls.e = cls.results['inventory.json']
        cls.image = n.Image(cls.data)
        cls.relocations = n.relative_relocations(cls.image)
        cls.decoded = {int(f['start'], 16): [{'site': int(f['start'], 16)+int(row[0], 16),
                         'raw': bytes.fromhex(row[1]), 'kind': row[2]} for row in f['instructions']]
                       for f in cls.results['instructions.json']['fdes']}
        cls.location = cls.e['locations'][0]
        cls.slot = int(cls.location['va'], 16)
        cls.anchor = next(a for d in cls.e['diagnostics'] for a in d['anchors'])

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.handle.close()

    @contextmanager
    def mutated(self, va, replacement):
        _, off = self.image.mapping(va, len(replacement))
        with mmap.mmap(self.handle.fileno(), 0, access=mmap.ACCESS_COPY) as data:
            data[off:off+len(replacement)] = replacement
            yield data, n.Image(data)

    def test_exact_regeneration_facts_and_report_counts(self):
        v.verify_outputs(PACKET, n, self.results)
        self.assertEqual(self.e['metrics']['unique_line_column'], 6)
        self.assertEqual(self.e['metrics']['decoded_instructions'], 139408)

    def test_every_location_and_lea_is_relocation_and_boundary_checked(self):
        for loc in self.e['locations']:
            slot = int(loc['va'], 16)
            self.assertTrue(loc['lea_sites'])
            self.assertEqual(self.relocations[slot]['target'], int(loc['path_bytes']['va'], 16))
            self.assertEqual(loc['path'], 'l1/src/spot_meta.rs')
        for row in self.e['location_leas']:
            n.verified_lea(self.image, self.decoded[int(row['owner'], 16)],
                           int(row['instruction']['va'], 16), int(row['location'], 16))

    def test_wrong_digest_and_empty_input_rejected(self):
        for raw in (b'', b'\x7fELF'+bytes(60)):
            with self.assertRaisesRegex(n.EvidenceError, 'SHA-256 mismatch'):
                n.build(raw)
        with self.mutated(self.slot+16, struct.pack('<I', 567)) as (data, _):
            with self.assertRaisesRegex(n.EvidenceError, 'SHA-256 mismatch'):
                n.build(data)

    def test_wrong_digest_cli_does_not_write(self):
        with tempfile.TemporaryDirectory() as temp:
            binary, out = Path(temp)/'wrong.bin', Path(temp)/'output'
            binary.write_bytes(b'incorrect target')
            with mock.patch('sys.argv', ['spot_meta_inventory.py', '--binary', str(binary), '--out', str(out)]), \
                 mock.patch('sys.stderr', new_callable=io.StringIO):
                with self.assertRaises(SystemExit) as error: n.main()
            self.assertEqual(error.exception.code, 1)
            self.assertFalse(out.exists())

    def test_corrupt_location_fields_rejected(self):
        for delta, replacement in ((0, struct.pack('<Q', 1)), (8, struct.pack('<Q', 1)),
                                   (16, struct.pack('<I', 0)), (20, struct.pack('<I', 0))):
            with self.subTest(delta=delta), self.mutated(self.slot+delta, replacement) as (_, image):
                with self.assertRaises(n.EvidenceError):
                    n.decode_location(image, self.slot, self.relocations[self.slot])

    def test_corrupt_path_and_shifted_slot(self):
        path = self.relocations[self.slot]['target']
        with self.mutated(path+len(n.PREFIX), b'X') as (_, image):
            with self.assertRaises(n.EvidenceError): n.decode_location(image, self.slot, self.relocations[self.slot])
        with self.assertRaises(n.EvidenceError): n.decode_location(self.image, self.slot+1, self.relocations[self.slot])

    def test_corrupt_relocation_and_duplicate_slot(self):
        relocation = self.relocations[self.slot]
        with self.mutated(relocation['entry_va']+8, struct.pack('<Q', 0x100000008)) as (_, image):
            with self.assertRaises(n.EvidenceError): n.relative_relocations(image)
        with self.assertRaises(n.EvidenceError):
            n.decode_location(self.image, self.slot, {**relocation, 'target': relocation['target']+1})
        first, second = list(self.relocations.values())[:2]
        slot = self.image.read(first['entry_va'], 8)
        with self.mutated(second['entry_va'], slot) as (_, image):
            with self.assertRaisesRegex(n.EvidenceError, 'duplicate relocation'): n.relative_relocations(image)

    def test_missing_section(self):
        shoff = struct.unpack_from('<Q', self.data, 40)[0]
        entsize, _, names_index = struct.unpack_from('<HHH', self.data, 58)
        names_off = struct.unpack_from('<Q', self.data, shoff+names_index*entsize+24)[0]
        for section in (b'.text\0', b'.rela.dyn\0', b'.eh_frame\0'):
            off = self.data.find(section, names_off)
            with mmap.mmap(self.handle.fileno(), 0, access=mmap.ACCESS_COPY) as data:
                data[off+1:off+2] = b'X'
                with self.assertRaisesRegex(n.EvidenceError, 'missing section'): n.Image(data)

    def test_non_executable_section(self):
        shoff = struct.unpack_from('<Q', self.data, 40)[0]
        entsize = struct.unpack_from('<H', self.data, 58)[0]
        index = next(i for i, s in enumerate(self.image.sections) if s['name'] == '.text')
        off = shoff+index*entsize+8
        with mmap.mmap(self.handle.fileno(), 0, access=mmap.ACCESS_COPY) as data:
            flags = struct.unpack_from('<Q', data, off)[0]
            data[off:off+8] = struct.pack('<Q', flags & ~4)
            with self.assertRaisesRegex(n.EvidenceError, 'non-executable'): n.Image(data)

    def test_malformed_fde_and_unwind_header(self):
        record = self.e['fdes'][0]['fde_record']
        with self.mutated(int(record['va'], 16)+12, struct.pack('<i', -1)) as (_, image):
            with self.assertRaises(ValueError): n.Fdes(image)
        hdr = self.image.by_name['.eh_frame_hdr']['address']
        with self.mutated(hdr+4, bytes(4)) as (_, image):
            with self.assertRaises(ValueError): n.Fdes(image)

    def test_shifted_lea_and_changed_displacement(self):
        row = self.e['location_leas'][0]
        site, slot = int(row['instruction']['va'], 16), int(row['location'], 16)
        insns = self.decoded[int(row['owner'], 16)]
        with self.assertRaises(n.EvidenceError): n.verified_lea(self.image, insns, site+1, slot)
        with self.mutated(site+3, bytes(4)) as (_, image):
            with self.assertRaises(n.EvidenceError): n.verified_lea(image, insns, site, slot)

    def test_literal_length_pointer_and_content_corruption(self):
        a = self.anchor
        owner, site = int(a['owner'], 16), int(a['lea']['va'], 16)
        insns = self.decoded[owner]
        i = next(i for i, x in enumerate(insns) if x['site'] == site)
        diagnostic = next(d for d in self.e['diagnostics'] if a in d['anchors'])
        literal = diagnostic['probe'].encode()
        proof = n.pointer_length_pair(self.image, insns, i, literal)
        self.assertEqual(proof['length'], len(literal))
        changed = copy.deepcopy(insns[i:i+3])
        raw = bytearray(changed[2]['raw']); raw[-4:] = struct.pack('<i', len(literal)+1)
        changed[2]['raw'] = bytes(raw)
        with self.assertRaises(n.EvidenceError): n.pointer_length_pair(self.image, changed, 0, literal)
        changed = copy.deepcopy(insns[i:i+3])
        changed[1]['raw'] = bytes.fromhex('48898424c8000000')
        with self.assertRaises(n.EvidenceError): n.pointer_length_pair(self.image, changed, 0, literal)
        with self.mutated(int(a['anchor'], 16), b'X') as (_, image):
            with self.assertRaises(n.EvidenceError): n.pointer_length_pair(image, insns, i, literal)

    def test_unbound_absent_and_constants_remain_unpromoted(self):
        for d in self.e['diagnostics']:
            if d['status'] == 'absent': self.assertEqual(d['occurrences'], [])
            if d['status'] != 'bound': self.assertEqual(d['anchors'], [])
        self.assertTrue(all(c['status'] == 'unresolved' and c['semantic_name_and_units'] == 'unresolved'
                            for c in self.e['constants']))

    def test_edges_require_exact_target_and_original_bytes(self):
        self.assertEqual(n.scoped_edges(self.image, self.decoded), self.e['call_edges'])
        edge = self.e['call_edges'][0]
        caller, site = int(edge['caller'], 16), int(edge['instruction']['va'], 16)
        changed = copy.deepcopy(self.decoded[caller])
        call = next(x for x in changed if x['site'] == site)
        call['raw'] = call['raw'][:1]+struct.pack('<i', struct.unpack_from('<i', call['raw'], 1)[0]+1)
        edges = n.scoped_edges(self.image, {**self.decoded, caller: changed})
        self.assertEqual(len(edges), len(self.e['call_edges'])-1)
        other = next(start for start in self.decoded if start != int(edge['callee'], 16))
        call['raw'] = call['raw'][:1]+struct.pack('<i', other-site-5)
        with self.assertRaises(n.EvidenceError): n.scoped_edges(self.image, {**self.decoded, caller: changed})

    def test_docs_counts_are_verified(self):
        with tempfile.TemporaryDirectory() as temp:
            here = Path(temp)
            for name in ('README.md', 'RESULT.md'):
                (here/name).write_bytes((PACKET/name).read_bytes())
            v.verify_docs(here, n, self.e['metrics'])
            readme = here/'README.md'
            readme.write_text(readme.read_text().replace('| locations | 17 |', '| locations | 18 |'))
            with self.assertRaisesRegex(ValueError, 'derived metrics differ'):
                v.verify_docs(here, n, self.e['metrics'])

    def test_manifest_rejects_unlisted_and_tampered_files(self):
        with tempfile.TemporaryDirectory() as temp:
            here = Path(temp)
            for name in v.MANIFEST | {'MANIFEST.sha256'}:
                shutil.copyfile(PACKET/name, here/name)
            v.verify_manifest(here)
            (here/'extra').write_text('unexpected')
            with self.assertRaises(ValueError): v.verify_manifest(here)
            (here/'extra').unlink()
            (here/'RESULT.md').write_text('tampered')
            with self.assertRaisesRegex(ValueError, 'manifest mismatch'): v.verify_manifest(here)

if __name__ == '__main__':
    unittest.main()
