"""Target-grounded and adversarial slack_alert evidence checks; stdlib only (MIT)."""
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

from tools import slack_alert_inventory as n

PACKET = n.ROOT/'research/work-items/slack-alert-inventory-94'
spec = importlib.util.spec_from_file_location('slack_alert_verify', PACKET/'verify.py')
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

    def test_sse_bswap_and_double_shift_lengths(self):
        # Supported instruction lengths; truncated forms fail.
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
                    'f0833801', 'f090', 'f2f390', '666601c0', 'f0f20100', 'f20f1f00',
                    '0f710001', '0f17c0', '0fd600', '66'*14+'0f1f00'):
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


    def test_target_specific_fs_and_double_shift_encodings(self):
        for text in ('64f3410f6f0424', '646641c74424440180', '490fa5f0'):
            raw = bytes.fromhex(text)
            self.assertEqual(n.decode_instruction(raw)['raw'], raw)
            for end in range(len(raw)):
                with self.subTest(raw=text, end=end), self.assertRaises(n.EvidenceError):
                    n.decode_instruction(raw[:end])
        for text in ('f201c0', 'f390', '64660f6f00', '64f30f6fc0', 'f2660f1000'):
            with self.subTest(raw=text), self.assertRaises(n.EvidenceError):
                n.decode_instruction(bytes.fromhex(text))

    def test_immediate_mov_rejects_truncation_and_movabs(self):
        for text in ('41b910000000', '49c786280200000b000000'):
            raw = bytes.fromhex(text)
            for end in range(len(raw)):
                with self.subTest(raw=text, end=end), self.assertRaises(n.EvidenceError):
                    n.decode_mov_immediate(raw[:end])
        with self.assertRaises(n.EvidenceError):
            n.decode_mov_immediate(bytes.fromhex('48b81000000000000000'))

    def test_call_edge_requires_entry_not_interior(self):
        raw = bytes.fromhex('e80100000090c3')
        image = SmallImage(raw)
        insns = n.decode_fde(image, {'start': 0x1000, 'end': 0x1007})
        self.assertEqual(n.scoped_edges(image, {0x1000: insns}), [])
        edges = n.scoped_edges(image, {0x1000: insns, 0x1006: [insns[-1]]})
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0]['callee'], '0x1006')

    def test_false_instruction_kind_is_rejected(self):
        image = SmallImage(bytes.fromhex('e800000000'))
        with self.assertRaises(n.EvidenceError):
            n.instruction_evidence(image, {'site': 0x1000, 'raw': image.raw, 'kind': 'jmp_rel32'})


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
        cls.anchor = next(a for d in cls.e['diagnostics'] if d.get('probe') == 'slack alert' for a in d['anchors'])

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
        self.assertEqual(self.e['metrics']['unique_line_column'], 7)
        self.assertEqual(self.e['metrics']['decoded_instructions'], 6272)

    def test_every_location_and_lea_is_relocation_and_boundary_checked(self):
        for loc in self.e['locations']:
            slot = int(loc['va'], 16)
            self.assertTrue(loc['lea_sites'])
            self.assertEqual(self.relocations[slot]['target'], int(loc['path_bytes']['va'], 16))
            self.assertEqual(loc['path'], 'base/src/slack_alert.rs')
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
            with mock.patch('sys.argv', ['slack_alert_inventory.py', '--binary', str(binary), '--out', str(out)]), \
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
        with self.assertRaises(n.EvidenceError): n.scoped_edges(self.image, {**self.decoded, caller: changed})
        other = next(start for start in self.decoded if start != int(edge['callee'], 16))
        call['raw'] = call['raw'][:1]+struct.pack('<i', other-site-5)
        with self.assertRaises(n.EvidenceError): n.scoped_edges(self.image, {**self.decoded, caller: changed})

    def test_docs_counts_are_verified(self):
        with tempfile.TemporaryDirectory() as temp:
            here = Path(temp)
            for name in ('README.md', 'RESULT.md'):
                (here/name).write_bytes((PACKET/name).read_bytes())
            v.verify_docs(here, n, self.e)
            readme = here/'README.md'
            readme.write_text(readme.read_text().replace('| locations | 21 |', '| locations | 22 |'))
            with self.assertRaisesRegex(ValueError, 'derived metrics/facts differ'):
                v.verify_docs(here, n, self.e)

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

    def literal_fixture(self, text):
        diagnostic = next(d for d in self.e['diagnostics'] if d.get('probe') == text)
        anchor = diagnostic['anchors'][0]
        insns = self.decoded[int(anchor['owner'], 16)]
        index = next(i for i, x in enumerate(insns) if x['site'] == int(anchor['lea']['va'], 16))
        return diagnostic, anchor, insns, index

    def test_all_literal_bindings_redecode_and_length_match(self):
        for d in self.e['diagnostics']:
            for a in d['anchors']:
                insns = self.decoded[int(a['owner'], 16)]
                i = next(i for i, x in enumerate(insns) if x['site'] == int(a['lea']['va'], 16))
                proof = n.pointer_length_pair(self.image, insns, i, d['probe'].encode('ascii'))
                self.assertEqual(proof['length'], d['probe_length'])
                self.assertEqual(proof['setup'], a['setup'])
                self.assertIn(proof['kind'], ('adjacent_pointer_length_fields', 'register_pointer_length_pair'))

    def test_mutated_register_pair_lengths_fail_below_digest_gate(self):
        for text in ('https://slack.com/api/chat.postMessage', 'content-type', 'application/json'):
            d, a, insns, index = self.literal_fixture(text)
            length = next(x for x in a['setup'] if x['kind'] == 'mov_imm' and
                          n.decode_mov_immediate(bytes.fromhex(x['bytes'])).get('register') == a['length_register'])
            site, raw = int(length['va'], 16), bytes.fromhex(length['bytes'])
            with self.subTest(literal=text), self.mutated(site+len(raw)-4, struct.pack('<I', len(text)+1)) as (_, image):
                fde = next(f for f in self.e['fdes'] if f['start'] == a['owner'])
                changed = n.decode_fde(image, {'start': int(fde['start'], 16), 'end': int(fde['end_exclusive'], 16)})
                with self.assertRaisesRegex(n.EvidenceError, 'length differs'):
                    n.pointer_length_pair(image, changed, index, text.encode('ascii'))

    def test_intervening_lea_clobber_rejected(self):
        text = 'https://slack.com/api/chat.postMessage'
        _, _, insns, index = self.literal_fixture(text)
        lea = insns[index+1]
        raw = bytearray(lea['raw']); raw[2] = raw[2] & 0xc7 | (2 << 3)  # RDI -> RDX
        with self.mutated(lea['site'], raw) as (_, image):
            changed = copy.deepcopy(insns)
            changed[index+1]['raw'] = bytes(raw)
            with self.assertRaisesRegex(n.EvidenceError, 'clobbers register'):
                n.pointer_length_pair(image, changed, index, text.encode('ascii'))

    def test_register_pair_requires_uninterrupted_contiguous_call_setup(self):
        text = 'https://slack.com/api/chat.postMessage'
        _, a, insns, index = self.literal_fixture(text)
        changed = copy.deepcopy(insns)
        changed[index+1]['site'] += 1
        with self.assertRaisesRegex(n.EvidenceError, 'noncontiguous'):
            n.pointer_length_pair(self.image, changed, index, text.encode('ascii'))
        call_site = int(a['setup'][-1]['va'], 16)
        with self.mutated(call_site, b'\xe9') as (_, image):
            changed = copy.deepcopy(insns)
            x = next(x for x in changed if x['site'] == call_site)
            x['raw'], x['kind'] = b'\xe9'+x['raw'][1:], 'jmp_rel32'
            with self.assertRaises(n.EvidenceError):
                n.pointer_length_pair(image, changed, index, text.encode('ascii'))

    def test_wrong_adjacent_field_and_store_width_rejected(self):
        text = 'slack alert'
        _, _, insns, index = self.literal_fixture(text)
        store = insns[index+2]
        # Actual +8 field becomes +9, keeping instruction size and immediate.
        raw = bytearray(store['raw']); raw[3:7] = struct.pack('<i', 0x229)
        with self.mutated(store['site'], raw) as (_, image):
            changed = copy.deepcopy(insns); changed[index+2]['raw'] = bytes(raw)
            with self.assertRaisesRegex(n.EvidenceError, 'not adjacent'):
                n.pointer_length_pair(image, changed, index, text.encode('ascii'))
        raw = bytearray(store['raw']); raw[0] &= ~8  # remove REX.W
        with self.mutated(store['site'], raw) as (_, image):
            changed = copy.deepcopy(insns); changed[index+2]['raw'] = bytes(raw)
            with self.assertRaises(n.EvidenceError):
                n.pointer_length_pair(image, changed, index, text.encode('ascii'))

    def test_reference_search_hints_pinned_and_absent_text_not_exported(self):
        absent = [d for d in self.e['diagnostics'] if d['origin'].startswith('unlicensed')]
        self.assertEqual([d['status'] for d in absent], ['absent']*3)
        for d in absent:
            self.assertNotIn('probe', d)
            self.assertEqual(d['occurrences'], [])
            self.assertEqual(d['anchors'], [])
        with mock.patch.object(n, 'REFERENCE_SHA256', '0'*64):
            with self.assertRaisesRegex(n.EvidenceError, 'reference lead file SHA-256 mismatch'):
                n.diagnostic_probes()

    def test_nonzero_line_mutation_is_not_hidden_by_schema_acceptance(self):
        with self.mutated(self.slot+16, struct.pack('<I', 999)) as (data, image):
            record = n.decode_location(image, self.slot, self.relocations[self.slot])
            self.assertEqual(record['line'], 999)  # syntactically valid, not the pinned target
            changed = copy.deepcopy(self.e); changed['locations'][0] = record
            with self.assertRaisesRegex(ValueError, 'pinned Location'): v.verify_facts(changed)
            with self.assertRaisesRegex(n.EvidenceError, 'SHA-256 mismatch'): n.build(data)

    def test_missing_location_is_not_a_complete_census(self):
        changed = copy.deepcopy(self.e); changed['locations'].pop()
        with self.assertRaisesRegex(ValueError, 'pinned Location'): v.verify_facts(changed)

    def test_all_fde_transcripts_cover_bytes_and_hashes(self):
        for f in self.e['fdes']:
            insns = self.decoded[int(f['start'], 16)]
            raw = b''.join(x['raw'] for x in insns)
            self.assertEqual(len(raw), f['size'])
            self.assertEqual(n.sha(raw), f['code_sha256'])
            self.assertEqual(insns[-1]['site']+len(insns[-1]['raw']), int(f['end_exclusive'], 16))
            n.validate_branch_boundaries(insns, int(f['start'], 16), int(f['end_exclusive'], 16))

    def test_transfer_partition_is_complete_and_internal_jumps_not_external(self):
        kinds = [x['instruction']['kind'] for x in self.e['rel32_transfers']]
        all_decoded = [x for insns in self.decoded.values() for x in insns
                       if x['kind'] in ('call_rel32', 'jmp_rel32')]
        self.assertEqual(len(kinds), len(all_decoded))
        internal = [x for x in self.e['rel32_transfers'] if x['disposition'] == 'internal_instruction']
        self.assertEqual(len(internal), 331)
        self.assertTrue(all(x['instruction']['kind'] == 'jmp_rel32' for x in internal))
        self.assertEqual(sum(x['disposition'] == 'outside_scoped_entries_unresolved'
                             for x in self.e['rel32_transfers']), 224)

    def test_missing_each_required_section_and_wrong_machine(self):
        shoff = struct.unpack_from('<Q', self.data, 40)[0]
        entsize, _, names_index = struct.unpack_from('<HHH', self.data, 58)
        names_off = struct.unpack_from('<Q', self.data, shoff+names_index*entsize+24)[0]
        for name in ('.rodata', '.data.rel.ro', '.eh_frame_hdr'):
            off = self.data.find(name.encode()+b'\0', names_off)
            with mmap.mmap(self.handle.fileno(), 0, access=mmap.ACCESS_COPY) as data:
                data[off+1] = ord('X')
                with self.assertRaisesRegex(n.EvidenceError, 'missing section'): n.Image(data)
        with mmap.mmap(self.handle.fileno(), 0, access=mmap.ACCESS_COPY) as data:
            data[18:20] = struct.pack('<H', 183)
            with self.assertRaisesRegex(n.EvidenceError, 'x86-64'): n.Image(data)

    def test_manifest_rejects_missing_duplicate_traversal_and_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            here = Path(temp)
            for name in v.MANIFEST | {'MANIFEST.sha256'}:
                shutil.copyfile(PACKET/name, here/name)
            manifest = here/'MANIFEST.sha256'; original = manifest.read_text()
            for changed in ('\n'.join(original.splitlines()[1:])+'\n',
                            original+original.splitlines()[0]+'\n',
                            original.replace('  README.md', '  ../README.md')):
                manifest.write_text(changed)
                with self.assertRaises(ValueError): v.verify_manifest(here)
            manifest.write_text(original)
            (here/'RESULT.md').unlink()
            with self.assertRaisesRegex(ValueError, 'whitelist'): v.verify_manifest(here)
            (here/'RESULT.md').symlink_to(PACKET/'RESULT.md')
            with self.assertRaisesRegex(ValueError, 'symlink'): v.verify_manifest(here)

    def test_generated_location_table_drift_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            here = Path(temp)
            for name in ('README.md', 'RESULT.md'):
                shutil.copyfile(PACKET/name, here/name)
            p = here/'README.md'
            p.write_text(p.read_text().replace('| 24:67 |', '| 24:68 |', 1))
            with self.assertRaisesRegex(ValueError, 'derived metrics/facts differ'):
                v.verify_docs(here, n, self.e)

    def test_packet_verifier_runs_without_external_tools_or_network(self):
        with mock.patch('subprocess.Popen', side_effect=AssertionError('external process forbidden')), \
             mock.patch('socket.socket', side_effect=AssertionError('network forbidden')), \
             mock.patch('sys.stdout', new_callable=io.StringIO):
            v.main()

    def test_generated_files_do_not_capture_local_state(self):
        forbidden = (str(n.ROOT).encode(), str(Path.home()).encode(), b'"PATH"', b'"timestamp"', b'"hostname"')
        for name in n.OUTPUTS:
            raw = n.render(self.results[name])
            for needle in forbidden:
                self.assertNotIn(needle, raw)
        # The sole expected compiler path is preserved as original hexadecimal bytes.
        for loc in self.e['locations']:
            self.assertEqual(bytes.fromhex(loc['path_bytes']['bytes']), n.PREFIX+n.SCOPE)

    def test_substring_is_not_given_full_literal_length(self):
        short = 'https://slack.com/api/chat.postMessag'
        with mock.patch.object(n, 'DIAGNOSTICS', (short,)):
            row = n.diagnostic_inventory(self.image, self.decoded)[0]
        self.assertEqual(row['status'], 'present-but-unbound')
        self.assertEqual(row['anchors'], [])
        self.assertEqual(len(row['rejected_candidates']), 3)
        self.assertTrue(all('length differs' in x['reason'] for x in row['rejected_candidates']))

    def test_global_presence_does_not_bind_without_scoped_lea(self):
        remaining = {start: insns for start, insns in self.decoded.items()
                     if start in (0x1457070, 0x1479d30, 0x14b23d0)}
        with mock.patch.object(n, 'DIAGNOSTICS', ('https://slack.com/api/chat.postMessage',)):
            row = n.diagnostic_inventory(self.image, remaining)[0]
        self.assertEqual(row['status'], 'present-but-unbound')
        self.assertEqual(len(row['occurrences']), 3)
        self.assertEqual(row['anchors'], [])

if __name__ == '__main__':
    unittest.main()
