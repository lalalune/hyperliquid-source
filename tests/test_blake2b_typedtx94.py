"""Static evidence and negative controls for the selected node94 type-2 slice."""
import csv
import hashlib
import io
import itertools
import json
import struct
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import blake2b_typedtx94 as target


def tsv(blob):
    return list(csv.DictReader(io.StringIO(blob.decode()), delimiter='\t'))


def decode_rlp(raw, pos):
    """Small independent decoder for the single synthetic fixture in this test."""
    first = raw[pos]
    if first < 0x80:
        return raw[pos:pos+1], pos + 1
    if first < 0xb8:
        start, size, is_list = pos + 1, first - 0x80, False
    elif first < 0xc0:
        width = first - 0xb7
        start = pos + 1 + width
        size, is_list = int.from_bytes(raw[pos+1:start], 'big'), False
    elif first < 0xf8:
        start, size, is_list = pos + 1, first - 0xc0, True
    else:
        width = first - 0xf7
        start = pos + 1 + width
        size, is_list = int.from_bytes(raw[pos+1:start], 'big'), True
    end = start + size
    if end > len(raw):
        raise ValueError('truncated fixture')
    if not is_list:
        return raw[start:end], end
    values = []
    while start < end:
        value, start = decode_rlp(raw, start)
        values.append(value)
    if start != end:
        raise ValueError('list item exceeded enclosing list')
    return values, end


class StaticTypedTransaction(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = target.ARTIFACT.read_bytes()
        target.authenticate(cls.data)
        cls.sec = target.sections(cls.data)
        cls.fdes, cls.cies = target.selected_fdes(cls.data, cls.sec)
        cls.rel = target.read_relatives(cls.data, cls.sec)
        cls.files = target.generate(cls.data)
        cls.key = target.at(cls.data, cls.sec, 0x574f0c0, 20)

    def test_hash_rejected_before_any_elf_read(self):
        with patch.object(target, 'sections', side_effect=AssertionError('parsed before hash')):
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                target.generate(b'\x7fELF corrupted')
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), target.SHA256)
        altered = bytearray(self.data)
        altered[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            target.authenticate(altered)

    def test_unwind_index_duplicate_and_wrong_fde_pointer(self):
        _, entries = target.unwind_index(self.data)
        chosen = next(r for r in entries if r['start'] == 0x134d5c0)
        header = next(s for s in self.sec if s['name'] == '.eh_frame_hdr')
        row = header['offset'] + 12 + 8*chosen['index']
        damaged = bytearray(self.data)
        damaged[row:row+4] = damaged[row-8:row-4]
        with self.assertRaisesRegex(ValueError, 'duplicate starts'):
            target.selected_fdes(damaged, self.sec)
        damaged[row:row+4] = self.data[row:row+4]
        damaged[row+4:row+8] = damaged[row-4:row]
        with self.assertRaisesRegex(ValueError, 'FDE/index disagreement'):
            target.selected_fdes(damaged, self.sec)

    def test_selected_actual_unwind_extents_and_raw_bodies(self):
        rows = tsv(self.files['functions.tsv'])
        self.assertEqual(len(rows), 15)
        bodies = json.loads(self.files['bodies.json'])
        self.assertEqual(len(bodies), len(rows))
        for row, body in zip(rows, bodies):
            start, end = int(row['start_va'], 16), int(row['end_va'], 16)
            self.assertEqual(start, int(body['start'], 16))
            self.assertEqual(end, int(body['end'], 16))
            self.assertEqual(end - start, int(row['bytes']))
            self.assertEqual(hashlib.sha256(bytes.fromhex(body['bytes'])).hexdigest(), row['sha256'])
            self.assertEqual(bytes.fromhex(body['bytes']), target.at(self.data, self.sec, start, end-start))
        self.assertEqual(sum(int(x['bytes']) for x in rows), 11628)

    def test_complete_selected_instruction_streams(self):
        rows = tsv(self.files['instructions.tsv'])
        controls = tsv(self.files['control-flow.tsv'])
        self.assertEqual(len(rows), 2478)
        self.assertEqual(len(controls), 392)
        self.assertEqual(sum(r['flow_class'] == 'conditional' for r in controls), 156)
        summary = tsv(self.files['flow-summary.tsv'])
        self.assertEqual(len(summary), len(self.fdes))
        self.assertEqual(sum(int(r['instructions']) for r in summary), 2478)
        self.assertEqual(sum(int(r['direct_call']) + int(r['indirect_call']) for r in summary), 122)
        for start, fde in self.fdes.items():
            subset = [r for r in rows if int(r['fde_start'], 16) == start]
            self.assertTrue(subset)
            cursor = start
            for row in subset:
                self.assertEqual(int(row['site_va'], 16), cursor)
                raw = bytes.fromhex(row['bytes'])
                self.assertEqual(len(raw), int(row['length']))
                self.assertEqual(raw, target.at(self.data, self.sec, cursor, len(raw)))
                cursor += len(raw)
            self.assertEqual(cursor, fde['end'])

    def test_instruction_decoder_truncation_and_bad_local_target(self):
        good = target.decode_stream(b'\x48\x89\xd8\x75\x01\xc3\xc3', 0x1000)
        self.assertEqual([i['site'] for i in good], [0x1000,0x1003,0x1005,0x1006])
        self.assertEqual(target.direct_target(good[1]), 0x1006)
        with self.assertRaisesRegex(ValueError, 'inside an instruction'):
            target.decode_stream(b'\x75\xff\xc3', 0x1000)
        with self.assertRaisesRegex(ValueError, 'truncated instruction'):
            target.decode_stream(b'\x0f', 0x1000)
        with self.assertRaisesRegex(ValueError, 'unsupported 0f opcode'):
            target.decode_stream(b'\x0f\xff', 0x1000)
        with self.assertRaisesRegex(ValueError, 'overlong instruction|unsupported'):
            target.decode_stream(b'\x66'*15+b'\x90', 0x1000)

    def test_file_backed_address_mapping_negative_controls(self):
        section = next(s for s in self.sec if s['name'] == '.text')
        self.assertEqual(target.map_va(self.sec, section['address'], 1), section['offset'])
        self.assertEqual(target.map_va(self.sec, section['address'] + section['size'] - 1, 1),
                         section['offset'] + section['size'] - 1)
        bss = next(s for s in self.sec if s['name'] == '.bss')
        for address, length in ((bss['address'], 1), (0, 1),
                                (section['address'] + section['size'] - 1, 2),
                                ((1 << 64)-1, 2), (section['address'], 0)):
            with self.subTest(address=address, length=length), self.assertRaises(ValueError):
                target.map_va(self.sec, address, length)
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            target.map_va(self.sec + [dict(section)], section['address'], 1)
        tls = next(s for s in self.sec if s['name'] == '.tbss')
        with self.assertRaisesRegex(ValueError, 'NOBITS'):
            target.map_va([tls], tls['address'], 1)

    def test_every_instruction_window_detects_changed_bytes(self):
        damaged = bytearray(self.data)
        for label, address, expected in target.PINS:
            with self.subTest(label=label):
                off = target.map_va(self.sec, address, 1)
                damaged[off] ^= 1
                try:
                    with self.assertRaisesRegex(ValueError, 'window mismatch'):
                        target.exact(damaged, self.sec, address, expected)
                finally:
                    damaged[off] ^= 1

    def test_rip_references_and_tampered_displacement(self):
        for row in target.RIP_REFS:
            target.decode_rip_ref(self.data, self.sec, self.fdes, *row)
        damaged = bytearray(self.data)
        row = target.RIP_REFS[0]
        off = target.map_va(self.sec, row[1], 7)
        damaged[off+3] ^= 1
        with self.assertRaisesRegex(ValueError, 'target mismatch'):
            target.decode_rip_ref(damaged, self.sec, self.fdes, *row)

    def test_call_bindings_and_opcode_target_corruptions(self):
        for row in target.CALLS:
            target.decode_call(self.data, self.sec, self.fdes, self.rel, *row)
        damaged = bytearray(self.data)
        row = next(r for r in target.CALLS if r[0] == 'type2_dispatch')
        off = target.map_va(self.sec, row[1], 5)
        damaged[off+1] ^= 1
        with self.assertRaisesRegex(ValueError, 'target mismatch'):
            target.decode_call(damaged, self.sec, self.fdes, self.rel, *row)
        damaged[off] = 0x90
        with self.assertRaisesRegex(ValueError, 'unsupported selected call'):
            target.decode_call(damaged, self.sec, self.fdes, self.rel, *row)
        rows = {r['name']: r for r in tsv(self.files['calls.tsv'])}
        self.assertEqual(rows['payload_copy']['target_va'], 'memcpy')
        self.assertEqual(rows['recipient']['target_va'], '0x135b670')
        self.assertEqual(rows['payload_allocate']['scope'], 'external')

    def test_relocation_addend_and_duplicate_corruption(self):
        damaged = bytearray(self.data)
        address = 0x576e140
        row = self.rel[address]
        off = row['file_offset']
        damaged[off+16] ^= 1
        with self.assertRaisesRegex(ValueError, 'relative relocation mismatch'):
            target.read_relatives(damaged, self.sec)
        damaged[off+16] ^= 1
        other = self.rel[0x576e148]['file_offset']
        struct.pack_into('<Q', damaged, other, address)
        with self.assertRaisesRegex(ValueError, 'duplicate target relocation'):
            target.read_relatives(damaged, self.sec)

    def test_branch_rejects_bad_opcode_and_outside_fde(self):
        row = target.BRANCHES[0]
        damaged = bytearray(self.data)
        off = target.map_va(self.sec, row[1], 2)
        damaged[off] = 0x90
        with self.assertRaisesRegex(ValueError, 'unsupported branch'):
            target.decode_branch(damaged, self.sec, self.fdes, *row)
        damaged[off] = self.data[off]
        damaged[off+1] = 0x80
        with self.assertRaisesRegex(ValueError, 'branch leaves'):
            target.decode_branch(damaged, self.sec, self.fdes, *row)

    def test_switch_targets_and_bad_type2_entry(self):
        rows = target.switch_entries(self.data, self.sec, self.fdes)
        self.assertEqual(len(rows), 15)
        self.assertEqual([row[-1] for row in rows if row[2] == 2],
                         ['0x4e4e76e', '0x4e4ef79', '0x4e501ca'])
        damaged = bytearray(self.data)
        off = target.map_va(self.sec, 0x7c1660 + 8, 4)
        damaged[off] ^= 1
        with self.assertRaisesRegex(ValueError, 'type-2 switch mismatch'):
            target.switch_entries(damaged, self.sec, self.fdes)

    def test_lsda_landing_and_bad_encoding(self):
        rows = tsv(self.files['exception-sites.tsv'])
        row = next(r for r in rows if r['start_va'] == '0x4e4f237')
        self.assertEqual((row['end_va'], row['landing_va'], row['action']),
                         ('0x4e4f23a', '0x4e4f7e6', '0'))
        fde = self.fdes[0x4e4eee0]
        damaged = bytearray(self.data)
        off = target.map_va(self.sec, fde['lsda'], 1)
        damaged[off] = 0
        with self.assertRaisesRegex(ValueError, 'unsupported LSDA landing base'):
            target.exceptions(damaged, self.sec, fde)

    def test_recipient_all_short_widths_and_truncation(self):
        for length in range(56):
            raw = bytes([0x80 + length]) + bytes([0x80])*length
            got = target.address_field(raw)
            with self.subTest(length=length):
                if length == 0:
                    self.assertEqual(got, ('none', None, 1, b''))
                elif length == 20:
                    self.assertEqual(got, ('address', None, 21, bytes([0x80])*20))
                else:
                    self.assertEqual(got, ('error', 5, length+1, b''))
                if length:
                    self.assertEqual(target.address_field(raw[:-1]), ('error', 2, 1, b''))

    def test_recipient_error_and_noncanonical_boundaries(self):
        samples = {
            b'': ('error',2,0,b''), b'\x80': ('none',None,1,b''),
            b'\x81\x00': ('error',3,1,b''), b'\x81\x80': ('error',5,2,b''),
            b'\xc0': ('error',7,1,b''), b'\xb8\x14'+self.key: ('error',4,2,b''),
            b'\xb8\x00': ('error',1,2,b''), b'\xb8': ('error',2,1,b''),
            b'\xf8\x38': ('error',2,2,b''),
        }
        for raw, expected in samples.items():
            with self.subTest(raw=raw.hex()):
                self.assertEqual(target.address_field(raw), expected)
        self.assertEqual(target.address_field(b'\x94'+self.key), ('address',None,21,self.key))
        self.assertEqual(target.address_field(b'\x94'+self.key[:-1]), ('error',2,1,b''))

    def test_payload_all_short_widths_and_truncation(self):
        for length in range(56):
            payload = bytes([0x80])*length
            raw = bytes([0x80 + length]) + payload
            with self.subTest(length=length):
                self.assertEqual(target.payload_field(raw), ('bytes',None,length+1,payload))
                if length:
                    self.assertEqual(target.payload_field(raw[:-1]), ('error',2,1,b''))
        self.assertEqual(target.payload_field(b'\x81\x00'), ('error',3,1,b''))
        self.assertEqual(target.payload_field(b'\xc0'), ('error',7,1,b''))
        self.assertEqual(target.payload_field(b'\xb8\x00'), ('error',1,2,b''))
        self.assertEqual(target.payload_field(b'\xb8\x37'+bytes(55)), ('error',4,2,b''))

    def test_payload_long_213_and_controls(self):
        sample = bytes(range(213))
        self.assertEqual(target.payload_field(b'\xb8\xd5'+sample), ('bytes',None,215,sample))
        self.assertEqual(target.payload_field(b'\xb8\xd5'+sample[:-1]), ('error',2,2,b''))
        self.assertEqual(target.payload_field(b'\xf8\x38'+bytes(56)), ('error',7,2,b''))
        shorter = target.payload_field(b'\xb8\xd4'+sample)
        self.assertEqual(shorter, ('bytes',None,214,sample[:-1]))

    def test_payload_layout_operands_and_displacement_corruption(self):
        layout = target.payload_layout(self.data, self.sec)
        self.assertEqual(layout['decoder_result_offsets'], ['0x0','0x8','0x10','0x18'])
        self.assertEqual(layout['unsigned_field_result_offsets'], ['0x20','0x28','0x30','0x38'])
        self.assertEqual(layout['typed_converter_input_offsets'], ['0x30','0x38','0x40','0x48'])
        self.assertEqual(layout['environment_output_offsets'], ['0xc0','0xc8','0xd0','0xd8'])
        damaged = bytearray(self.data)
        off = target.map_va(self.sec, 0x4e4f209, 4)
        damaged[off+3] ^= 1
        with self.assertRaisesRegex(ValueError, 'payload layout displacement mismatch'):
            target.payload_layout(damaged, self.sec)

    def test_parity_and_scalar_positive_and_negative_controls(self):
        self.assertEqual(target.parity_field(b'\x80'), ('value',None,1,0))
        self.assertEqual(target.parity_field(b'\x01'), ('value',None,1,1))
        self.assertEqual(target.parity_field(b'\x00'), ('error',1,1,None))
        self.assertEqual(target.parity_field(b'\x02'), ('error',9,1,None))
        self.assertEqual(target.parity_field(b'\x81\x01'), ('error',3,1,None))
        self.assertEqual(target.parity_field(b'\x82\x01\x02'), ('error',0,3,None))
        self.assertEqual(target.scalar_field(b'\x80'), ('value',None,1,0))
        self.assertEqual(target.scalar_field(b'\x00'), ('error',1,1,None))
        self.assertEqual(target.scalar_field(b'\xa0'+b'\x80'*32),
                         ('value',None,33,int.from_bytes(b'\x80'*32,'big')))
        self.assertEqual(target.scalar_field(b'\xa1'+b'\x80'*33), ('error',8,34,None))
        self.assertEqual(target.scalar_field(b'\x82\x00\x01'), ('error',1,3,None))
        self.assertEqual(target.scalar_field(b'\xa0'+bytes(31)), ('error',2,1,None))

    def test_four_word_signature_bound_and_equality(self):
        bound = target.signature_bound(self.data, self.sec)
        limit = int.from_bytes(b''.join(x.to_bytes(8, 'big') for x in bound), 'big')
        candidates = ([bound[0]-1, bound[0], bound[0]+1],
                      [bound[1]-1, bound[1]],
                      [bound[2]-1, bound[2], bound[2]+1],
                      [bound[3]-1, bound[3], bound[3]+1])
        for words in itertools.product(*candidates):
            value = int.from_bytes(b''.join(x.to_bytes(8, 'big') for x in words), 'big')
            with self.subTest(words=words):
                self.assertEqual(target.bound_exceeded(words, bound), value > limit)
        self.assertFalse(target.bound_exceeded(bound, bound))
        with self.assertRaisesRegex(ValueError, 'four limbs'):
            target.bound_exceeded(bound[:-1], bound)
        with self.assertRaisesRegex(ValueError, 'invalid limb'):
            target.bound_exceeded((-1, 0, 0, 0), bound)

    def test_all_160_address_bits_survive_lane_projection(self):
        expected_names = ('inner','type2','envelope','verified_envelope','tx_env')
        self.assertEqual(self.key, bytes(19)+b'\x09')
        for bit in range(160):
            changed = bytearray(self.key)
            changed[bit//8] ^= 1 << (bit % 8)
            projection = target.lane_projection(bytes(changed))
            for name in expected_names:
                with self.subTest(bit=bit, name=name):
                    self.assertEqual(projection[name], b'\x01'+changed)
        with self.assertRaisesRegex(ValueError, '20 bytes'):
            target.lane_projection(self.key[:-1])

    def test_independent_fixture_decode_and_truncation(self):
        obj = json.loads(self.files['synthetic-transaction.json'])
        raw = bytes.fromhex(obj['raw_hex'])
        self.assertEqual(raw[0], 2)
        fields, end = decode_rlp(raw, 1)
        self.assertEqual(end, len(raw))
        self.assertEqual(len(fields), 12)
        self.assertEqual(fields[4], b'\x01\x86\xa0')
        self.assertEqual(fields[5], self.key)
        self.assertEqual(fields[7], bytes(213))
        self.assertEqual(fields[8], [])
        self.assertEqual(fields[9:], [b'',b'',b''])
        self.assertEqual(raw[obj['recipient_field_offset']], 0x94)
        self.assertEqual(raw[obj['input_field_offset']:obj['input_field_offset']+2], b'\xb8\xd5')
        with self.assertRaisesRegex(ValueError, 'truncated fixture'):
            decode_rlp(raw[:-1], 1)

    def test_selected_success_and_unwind_copy_shapes(self):
        names = {r['name']: r for r in tsv(self.files['windows.tsv'])}
        self.assertIn('f0480fb119', names['payload_promote_publish']['bytes'])
        self.assertIn('4883c901', names['payload_owner_store']['bytes'])
        self.assertIn('ff10', names['env_type2_payload']['bytes'])
        self.assertIn('eb000f10442408', names['env_payload_unwind']['bytes'])
        rel = {r['slot_va']: r['addend'] for r in tsv(self.files['relocations.tsv'])}
        self.assertEqual(rel['0x576e140'], '0x5670ae8')
        self.assertEqual(rel['0x5670ae8'], '0x1510c60')
        self.assertEqual(rel['0x576e148'], '0x5670ac0')
        self.assertEqual(rel['0x5670ac0'], '0x1510c10')
        self.assertEqual(rel['0x5670a08'], '0x1510360')


if __name__ == '__main__':
    unittest.main()
