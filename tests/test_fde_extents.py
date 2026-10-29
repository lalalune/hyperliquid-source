from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from fde_extents import eh_frame_records, fde_extents

TEXT, HDR, FRAME, EXCEPT = 0x1000, 0x2000, 0x3000, 0x4000
OFFSET = {TEXT: 0x400, HDR: 0x500, FRAME: 0x600, EXCEPT: 0x700}
SHOFF = 0x800
# (start, size, lsda, cie): one int3 gap at 0x1010 and one non-int3 gap at 0x1030.
FUNCTIONS = [(0x1000, 0x10, None, 'zR'), (0x1020, 0x10, 0x4000, 'zPLR'), (0x1038, 0x8, None, 'zR')]


def sdata4(value):
    return struct.pack('<i', value)


def build(functions=FUNCTIONS):
    """Build a minimal ELF64-LE image with the encodings observed in the captured nodes."""
    frame, layout = bytearray(), {'cie': {}, 'fde': []}

    def record(make_body):
        start = len(frame)
        body = make_body(FRAME + start + 4)
        body += b'\0' * (-len(body) % 4)  # DW_CFA_nop padding
        frame.extend(struct.pack('<I', len(body)) + body)
        return start

    def cie(augmentation):
        def body(va):
            head = struct.pack('<I', 0) + b'\1' + augmentation.encode() + b'\0' + bytes([1, 0x78, 16])
            if augmentation == 'zR':
                return head + b'\1\x1b'
            slot = va + len(head) + 2
            return head + b'\7\x9b' + sdata4(0x4008 - slot) + b'\x1b\x1b'
        return body

    for augmentation in ['zR', 'zPLR']:
        start = record(cie(augmentation))
        layout['cie'][augmentation] = start
    for start_va, size, lsda, augmentation in functions:
        cie_va = FRAME + layout['cie'][augmentation]

        def body(va, start_va=start_va, size=size, lsda=lsda, augmentation=augmentation, cie_va=cie_va):
            out = struct.pack('<I', va - cie_va) + sdata4(start_va - (va + 4)) + struct.pack('<I', size)
            if augmentation == 'zR':
                return out + b'\0'
            return out + b'\4' + (sdata4(0) if lsda is None else sdata4(lsda - (va + 13)))
        layout['fde'].append(record(body))
    frame.extend(b'\0' * 4)

    rows = sorted((f[0], FRAME + off) for f, off in zip(functions, layout['fde']))
    header = bytes([1, 0x1b, 3, 0x3b]) + sdata4(FRAME - (HDR + 4)) + struct.pack('<I', len(rows))
    for start_va, fde_va in rows:
        header += sdata4(start_va - HDR) + sdata4(fde_va - HDR)

    data = bytearray(SHOFF + 6 * 64)
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 40, SHOFF)
    struct.pack_into('<HHH', data, 58, 64, 6, 1)
    names = b'\0.shstrtab\0.text\0.eh_frame_hdr\0.eh_frame\0.gcc_except_table\0'
    data[64:64 + len(names)] = names
    text = bytearray(b'\xcc' * 0x40)
    text[0x30:0x38] = b'\x90' * 8
    data[OFFSET[TEXT]:OFFSET[TEXT] + 0x40] = text
    data[OFFSET[HDR]:OFFSET[HDR] + len(header)] = header
    data[OFFSET[FRAME]:OFFSET[FRAME] + len(frame)] = frame
    table = [(0, 0, 0, 0, 0, 0), (names.index(b'.shstrtab'), 3, 0, 0, 64, len(names)),
             (names.index(b'.text'), 1, 6, TEXT, OFFSET[TEXT], 0x40),
             (names.index(b'.eh_frame_hdr'), 1, 2, HDR, OFFSET[HDR], len(header)),
             (names.index(b'.eh_frame\0'), 1, 2, FRAME, OFFSET[FRAME], len(frame)),
             (names.index(b'.gcc_except_table'), 1, 2, EXCEPT, OFFSET[EXCEPT], 0x10)]
    for index, row in enumerate(table):
        struct.pack_into('<IIQQQQIIQQ', data, SHOFF + index * 64, *row, 0, 0, 1, 0)
    layout['frame_size_field'] = SHOFF + 4 * 64 + 32
    return data, layout


class FdeExtentTests(unittest.TestCase):
    def test_decodes_extents_lsda_and_gaps(self):
        data, _ = build()
        summary, ordered, gaps = fde_extents(data)
        self.assertEqual([(f['start'], f['end'], f['lsda']) for f in ordered],
                         [(0x1000, 0x1010, None), (0x1020, 0x1030, 0x4000), (0x1038, 0x1040, None)])
        self.assertEqual([(g['start'], g['end'], g['int3_only']) for g in gaps],
                         [(0x1010, 0x1020, True), (0x1030, 0x1038, False)])
        self.assertEqual(summary['cie_augmentations'], {'zPLR': 1, 'zR': 1})
        self.assertEqual((summary['fde_records'], summary['unwind_table_entries'], summary['with_lsda']), (3, 3, 1))
        self.assertEqual(summary['unwind_start_differs_from_fde_start'], 0)
        self.assertEqual(summary['fde_records_not_in_unwind_table'], 0)
        self.assertEqual(summary['end_equals_next_index_upper_bound'], 1)
        self.assertEqual(summary['same_section_gaps'],
                         {'int3_only_gaps': 1, 'int3_only_bytes': 16, 'other_bytes_gaps': 1, 'other_bytes_bytes': 8})
        self.assertEqual(summary['executable_sections']['.text'],
                         {'section_bytes': 64, 'fde_extent_bytes': 40, 'bytes_before_first_fde': 0, 'bytes_after_last_fde': 0})

    def test_zero_lsda_is_null_not_a_pointer(self):
        functions = [FUNCTIONS[0], (0x1020, 0x10, None, 'zPLR'), FUNCTIONS[2]]
        summary, ordered, _ = fde_extents(build(functions)[0])
        self.assertIsNone(ordered[1]['lsda'])
        self.assertEqual(summary['with_lsda'], 0)

    def test_rejects_negative_range(self):
        data, layout = build()
        struct.pack_into('<i', data, OFFSET[FRAME] + layout['fde'][0] + 12, -16)
        with self.assertRaises(ValueError): eh_frame_records(data)

    def test_counts_overlap_instead_of_hiding_it(self):
        data, layout = build()
        struct.pack_into('<I', data, OFFSET[FRAME] + layout['fde'][0] + 12, 0x28)  # first range now ends at 0x1028
        self.assertEqual(fde_extents(data)[0]['overlapping_pairs'], 1)

    def test_counts_table_start_that_differs_from_fde(self):
        data, layout = build()
        start_field = OFFSET[HDR] + 12
        struct.pack_into('<i', data, start_field, 0x1004 - HDR)
        self.assertEqual(fde_extents(data)[0]['unwind_start_differs_from_fde_start'], 1)

    def test_counts_fde_missing_from_table(self):
        data, _ = build()
        struct.pack_into('<I', data, OFFSET[HDR] + 8, 2)
        self.assertEqual(fde_extents(data)[0]['fde_records_not_in_unwind_table'], 1)

    def test_rejects_table_entry_that_is_not_an_fde(self):
        data, _ = build()
        field = OFFSET[HDR] + 16
        struct.pack_into('<i', data, field, struct.unpack_from('<i', data, field)[0] + 4)
        with self.assertRaises(ValueError): fde_extents(data)

    def test_rejects_unsupported_pointer_encoding(self):
        data, layout = build()
        data[OFFSET[FRAME] + layout['cie']['zR'] + 16] = 0x03  # R: udata4 instead of pcrel|sdata4
        with self.assertRaises(ValueError): eh_frame_records(data)

    def test_rejects_unsupported_augmentation(self):
        data, layout = build()
        data[OFFSET[FRAME] + layout['cie']['zR'] + 10] = ord('X')
        with self.assertRaises(ValueError): eh_frame_records(data)

    def test_rejects_64_bit_record(self):
        data, layout = build()
        struct.pack_into('<I', data, OFFSET[FRAME] + layout['fde'][0], 0xffffffff)
        with self.assertRaises(ValueError): eh_frame_records(data)

    def test_rejects_bad_cie_pointer(self):
        data, layout = build()
        struct.pack_into('<I', data, OFFSET[FRAME] + layout['fde'][0] + 4, 2)
        with self.assertRaises(ValueError): eh_frame_records(data)

    def test_rejects_augmentation_length_mismatch(self):
        data, layout = build()
        data[OFFSET[FRAME] + layout['fde'][1] + 16] = 3
        with self.assertRaises(ValueError): eh_frame_records(data)

    def test_rejects_missing_terminator(self):
        data, layout = build()
        size = struct.unpack_from('<Q', data, layout['frame_size_field'])[0]
        struct.pack_into('<Q', data, layout['frame_size_field'], size - 4)
        with self.assertRaises(ValueError): eh_frame_records(data)

    def test_rejects_bytes_after_terminator(self):
        data, layout = build()
        size = struct.unpack_from('<Q', data, layout['frame_size_field'])[0]
        struct.pack_into('<Q', data, layout['frame_size_field'], size + 4)
        data[OFFSET[FRAME] + size] = 1
        with self.assertRaises(ValueError): eh_frame_records(data)

    def test_rejects_header_frame_pointer_mismatch(self):
        data, _ = build()
        struct.pack_into('<i', data, OFFSET[HDR] + 4, FRAME + 4 - (HDR + 4))
        with self.assertRaises(ValueError): fde_extents(data)


if __name__ == '__main__':
    unittest.main()
