#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 set-once cell setter evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.

The five windows are [0x1515880, 0x15158b2), 50 bytes; [0x15158c0, 0x1515900),
64 bytes; [0x1515900, 0x1515937), 55 bytes; [0x1515940, 0x1515979), 57 bytes;
and [0x1515980, 0x15159b9), 57 bytes, followed by fourteen, zero, nine, seven
and seven int3 padding bytes. Each implements the same observed set-once
protocol with per-window fields and ranges: out-of-range input returns 0, an
unset cell stores the input and returns 8, a set cell returns 8 when the
stored value matches and 1 when it differs. No stdlib type, enum meaning for
the 0/1/8 returns, or struct owner is claimed for any window.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from elf_index import sections

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
W1_START, W1_END = 0x1515880, 0x15158b2
W2_START, W2_END = 0x15158c0, 0x1515900
W3_START, W3_END = 0x1515900, 0x1515937
W4_START, W4_END = 0x1515940, 0x1515979
W5_START, W5_END = 0x1515980, 0x15159b9
W1 = bytes.fromhex(
    '48ffce4883fe0677150fb687a00000003c07750d4088b7a0000000b008c331c0c34038f0'
    'b908000000b8010000000f44c1c3')
W2 = bytes.fromhex(
    '4883fe067727c1e60348b8060001020304050089f148d3e80fb68fa000000080f907750c'
    '8887a0000000b008c331c0c338c1b908000000b8010000000f44c1c3')
W3 = bytes.fromhex(
    '488d4eff31c04883f90b772a4883fe0c0f44f0807f7800741139777cb908000000b8010000'
    '000f44c1c3c747780100000089777cb008c3')
W4 = bytes.fromhex(
    '4883fe3b771d83bf8000000001751739b784000000b908000000b8010000000f44c1c331'
    'c0c3c787800000000100000089b784000000b008c3')
W5 = bytes.fromhex(
    '4883fe3c771d83bf8800000001751739b78c000000b908000000b8010000000f44c1c331'
    'c0c3c787880000000100000089b78c000000b008c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
W1_FDE = bytes.fromhex('10000000584401000cff81003200000000000000')
W2_FDE = bytes.fromhex('100000006c44010038ff81004000000000000000')
W3_FDE = bytes.fromhex('100000008044010064ff81003700000000000000')
W4_FDE = bytes.fromhex('100000009444010090ff81003900000000000000')
W5_FDE = bytes.fromhex('10000000a8440100bcff81003900000000000000')
TABLE = (6, 0, 1, 2, 3, 4, 5)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def byte_cell_path(cell, original):
    """Window 0x1515880: original input 1..7, stored value is original - 1."""
    if not 1 <= original <= 7:
        return 0, None
    stored = original - 1
    if cell == 7:
        return 8, stored
    return (8, None) if cell == stored else (1, None)


def table_cell_path(cell, original):
    """Window 0x15158c0: original input 0..6, remapped through the byte table."""
    if not 0 <= original <= 6:
        return 0, None
    stored = TABLE[original]
    if cell == 7:
        return 8, stored
    return (8, None) if cell == stored else (1, None)


def flag_cell_path(flag_set, value, original, lo, hi, remap=None):
    """Flag windows: out of range returns 0; unset stores and returns 8;
    set returns 8 on match, 1 on mismatch. flag_set is the window's own
    set test: low byte nonzero for 0x1515900, full u32 equal to 1 for the
    other two."""
    if not lo <= original <= hi:
        return 0, None
    stored = remap(original) if remap is not None else original
    if not flag_set:
        return 8, stored
    return (8, None) if value == stored else (1, None)


def analyze(data):
    """Structural checks, separate from identity so corruption controls reach them."""
    secs = sections(data)
    by_name = {s['name']: s for s in secs}

    def read(va, size):
        matches = [s for s in secs if s['type'] != 8 and s['address'] <= va
                   and va + size <= s['address'] + s['size']]
        require(len(matches) == 1, 'Ambiguous or unmapped VA')
        s = matches[0]
        off = s['offset'] + va - s['address']
        return data[off:off + size]

    windows = ((W1_START, W1_END, W1), (W2_START, W2_END, W2),
               (W3_START, W3_END, W3), (W4_START, W4_END, W4),
               (W5_START, W5_END, W5))
    got = []
    for start, end, raw in windows:
        w = read(start, end - start)
        require(w == raw, 'Window changed at %s' % hex(start))
        require(len(w) == end - start, 'Window length changed at %s' % hex(start))
        got.append(w)
    w1, w2, w3, w4, w5 = got
    # Window 1: dec rsi; cmp $6, rsi; ja out-of-range return 0.
    require(w1[0:3] == b'\x48\xff\xce', 'Window 1 dec changed')
    require(w1[3:7] == b'\x48\x83\xfe\x06', 'Window 1 range compare changed')
    require(w1[7] == 0x77 and W1_START + 7 + 2 + w1[8] == 0x151589e,
            'Window 1 out-of-range branch changed')
    require(w1[8] == 0x15, 'Window 1 out-of-range displacement changed')
    # Window 1: movzbl 0xa0(rdi), eax; cmp $7, al; jne compare arm.
    require(w1[9:16] == b'\x0f\xb6\x87\xa0\x00\x00\x00', 'Window 1 cell load changed')
    require(w1[16:18] == b'\x3c\x07', 'Window 1 sentinel compare changed')
    require(w1[18] == 0x75 and W1_START + 18 + 2 + w1[19] == 0x15158a1,
            'Window 1 sentinel branch changed')
    # Window 1: store arm writes sil to the cell and returns 8; the
    # out-of-range arm zeroes eax and returns.
    require(w1[20:27] == b'\x40\x88\xb7\xa0\x00\x00\x00', 'Window 1 store changed')
    require(w1[27:29] == b'\xb0\x08' and w1[29] == 0xc3, 'Window 1 store return changed')
    require(w1[30:32] == b'\x31\xc0' and w1[32] == 0xc3,
            'Window 1 out-of-range return changed')
    # Window 1: compare arm, cmove selects 8 on equality, else 1.
    require(w1[33:36] == b'\x40\x38\xf0', 'Window 1 value compare changed')
    require(w1[36:41] == b'\xb9\x08\x00\x00\x00', 'Window 1 equal value changed')
    require(w1[41:46] == b'\xb8\x01\x00\x00\x00', 'Window 1 mismatch value changed')
    require(w1[46:49] == b'\x0f\x44\xc1' and w1[49] == 0xc3,
            'Window 1 compare return changed')
    # Window 2: cmp $6, rsi; ja out-of-range return 0; shl $3, esi.
    require(w2[0:4] == b'\x48\x83\xfe\x06', 'Window 2 range compare changed')
    require(w2[4] == 0x77 and W2_START + 4 + 2 + w2[5] == 0x15158ed,
            'Window 2 out-of-range branch changed')
    require(w2[6:9] == b'\xc1\xe6\x03', 'Window 2 shift changed')
    # Window 2: movabs byte table 0x5040302010006, shr by input*8, low byte
    # is the remapped value: 0->6, 1->0, 2->1, 3->2, 4->3, 5->4, 6->5.
    require(w2[9:11] == b'\x48\xb8', 'Window 2 table load opcode changed')
    require(struct.unpack_from('<Q', w2, 11)[0] == 0x5040302010006,
            'Window 2 table changed')
    require(w2[19:21] == b'\x89\xf1' and w2[21:24] == b'\x48\xd3\xe8',
            'Window 2 table shift changed')
    require([TABLE[i] for i in range(7)] == [6, 0, 1, 2, 3, 4, 5],
            'Window 2 table map changed')
    # Window 2: same cell at 0xa0(rdi), sentinel 7, store/compare/returns.
    require(w2[24:31] == b'\x0f\xb6\x8f\xa0\x00\x00\x00', 'Window 2 cell load changed')
    require(w2[31:34] == b'\x80\xf9\x07', 'Window 2 sentinel compare changed')
    require(w2[34] == 0x75 and W2_START + 34 + 2 + w2[35] == 0x15158f0,
            'Window 2 sentinel branch changed')
    require(w2[36:42] == b'\x88\x87\xa0\x00\x00\x00', 'Window 2 store changed')
    require(w2[42:44] == b'\xb0\x08' and w2[44] == 0xc3, 'Window 2 store return changed')
    require(w2[45:47] == b'\x31\xc0' and w2[47] == 0xc3,
            'Window 2 out-of-range return changed')
    require(w2[48:50] == b'\x38\xc1', 'Window 2 value compare changed')
    require(w2[50:55] == b'\xb9\x08\x00\x00\x00', 'Window 2 equal value changed')
    require(w2[55:60] == b'\xb8\x01\x00\x00\x00', 'Window 2 mismatch value changed')
    require(w2[60:63] == b'\x0f\x44\xc1' and w2[63] == 0xc3,
            'Window 2 compare return changed')
    # Window 3: lea rcx = rsi - 1; xor eax; cmp $0xb, rcx; ja return 0.
    # Valid original inputs are 1..12. cmp $0xc, rsi; cmove zeroes esi
    # when the input is 12, so 12 is stored as 0.
    require(w3[0:4] == b'\x48\x8d\x4e\xff', 'Window 3 range base changed')
    require(w3[4:6] == b'\x31\xc0', 'Window 3 zero changed')
    require(w3[6:10] == b'\x48\x83\xf9\x0b', 'Window 3 range compare changed')
    require(w3[10] == 0x77 and W3_START + 10 + 2 + w3[11] == 0x1515936,
            'Window 3 out-of-range branch changed')
    require(w3[12:16] == b'\x48\x83\xfe\x0c', 'Window 3 remap compare changed')
    require(w3[16:19] == b'\x0f\x44\xf0', 'Window 3 remap cmove changed')
    # Window 3: the set test reads only the LOW BYTE of the field at
    # 0x78(rdi): zero goes to the store arm, any nonzero goes to compare.
    # The store writes the full u32 value 1 to 0x78(rdi) and the value to
    # 0x7c(rdi), then returns 8.
    require(w3[19:23] == b'\x80\x7f\x78\x00', 'Window 3 flag-byte test changed')
    require(w3[23] == 0x74 and W3_START + 23 + 2 + w3[24] == 0x151592a,
            'Window 3 store branch changed')
    require(w3[25:28] == b'\x39\x77\x7c', 'Window 3 value compare changed')
    require(w3[28:33] == b'\xb9\x08\x00\x00\x00', 'Window 3 equal value changed')
    require(w3[33:38] == b'\xb8\x01\x00\x00\x00', 'Window 3 mismatch value changed')
    require(w3[38:41] == b'\x0f\x44\xc1' and w3[41] == 0xc3,
            'Window 3 compare return changed')
    require(w3[42:49] == b'\xc7\x47\x78\x01\x00\x00\x00', 'Window 3 flag store changed')
    require(w3[49:52] == b'\x89\x77\x7c', 'Window 3 value store changed')
    require(w3[52:54] == b'\xb0\x08' and w3[54] == 0xc3, 'Window 3 store return changed')
    # Windows 4 and 5: cmp range, ja return 0; cmpl $1, flag(rdi); jne
    # store arm; cmp value; cmove selects 8 on equality, else 1; the
    # store arm writes flag 1 and the value, then returns 8. Window 4
    # fields are 0x80/0x84 with range 0..59; window 5 fields are 0x88/0x8c
    # with range 0..60.
    for w, start, lo, hi, flag_off, val_off, out_arm, store_arm in (
            (w4, W4_START, 0, 59, 0x80, 0x84, 0x1515963, 0x1515966),
            (w5, W5_START, 0, 60, 0x88, 0x8c, 0x15159a3, 0x15159a6)):
        require(w[0:3] == b'\x48\x83\xfe' and w[3] == hi,
                'Flag window range changed at %s' % hex(start))
        require(w[4] == 0x77 and start + 4 + 2 + w[5] == out_arm,
                'Flag window out-of-range branch changed at %s' % hex(start))
        require(w[6:8] == b'\x83\xbf' and w[8] == flag_off and w[12] == 0x01,
                'Flag window flag compare changed at %s' % hex(start))
        require(w[13] == 0x75 and start + 13 + 2 + w[14] == store_arm,
                'Flag window store branch changed at %s' % hex(start))
        require(w[15:17] == b'\x39\xb7' and w[17] == val_off,
                'Flag window value compare changed at %s' % hex(start))
        require(w[21:26] == b'\xb9\x08\x00\x00\x00',
                'Flag window equal value changed at %s' % hex(start))
        require(w[26:31] == b'\xb8\x01\x00\x00\x00',
                'Flag window mismatch value changed at %s' % hex(start))
        require(w[31:34] == b'\x0f\x44\xc1' and w[34] == 0xc3,
                'Flag window compare return changed at %s' % hex(start))
        require(w[35:37] == b'\x31\xc0' and w[37] == 0xc3,
                'Flag window out-of-range return changed at %s' % hex(start))
        require(w[38:40] == b'\xc7\x87' and w[40] == flag_off,
                'Flag window flag store changed at %s' % hex(start))
        require(w[44:48] == b'\x01\x00\x00\x00',
                'Flag window flag store value changed at %s' % hex(start))
        require(w[48:50] == b'\x89\xb7' and w[50] == val_off,
                'Flag window value store changed at %s' % hex(start))
        require(w[54:56] == b'\xb0\x08' and w[56] == 0xc3,
                'Flag window store return changed at %s' % hex(start))
    # Padding: fourteen int3 bytes after window 1, none after window 2,
    # nine after window 3, seven after window 4, seven after window 5.
    require(read(W1_END, 14) == b'\xcc' * 14, 'Window 1 padding changed')
    require(read(W3_END, 9) == b'\xcc' * 9, 'Window 3 padding changed')
    require(read(W4_END, 7) == b'\xcc' * 7, 'Window 4 padding changed')
    require(read(W5_END, 7) == b'\xcc' * 7, 'Window 5 padding changed')
    # FDE/CIE locks.
    eh = by_name['.eh_frame']
    require(read(eh['address'], len(CIE)) == CIE, 'CIE changed')
    for offset, raw, start, end in ((0x14454, W1_FDE, W1_START, W1_END),
                                    (0x14468, W2_FDE, W2_START, W2_END),
                                    (0x1447c, W3_FDE, W3_START, W3_END),
                                    (0x14490, W4_FDE, W4_START, W4_END),
                                    (0x144a4, W5_FDE, W5_START, W5_END)):
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # Observed transition model, as pure arithmetic over the inputs the
    # windows actually read. No return-code meaning is claimed.
    require([byte_cell_path(7, o) for o in (1, 7, 8, 0)] ==
            [(8, 0), (8, 6), (0, None), (0, None)], 'Byte cell paths changed')
    require([byte_cell_path(c, 3) for c in (7, 2, 5)] ==
            [(8, 2), (8, None), (1, None)], 'Byte cell stored paths changed')
    require([table_cell_path(7, o) for o in (0, 1, 6, 7)] ==
            [(8, 6), (8, 0), (8, 5), (0, None)], 'Table cell paths changed')
    require([table_cell_path(c, 2) for c in (7, 1, 3)] ==
            [(8, 1), (8, None), (1, None)], 'Table cell stored paths changed')
    require([flag_cell_path(False, 0, o, 1, 12, lambda v: 0 if v == 12 else v)
             for o in (1, 12, 13, 0)] ==
            [(8, 1), (8, 0), (0, None), (0, None)], 'Window 3 paths changed')
    require([flag_cell_path(True, v, 5, 1, 12) for v in (5, 6)] ==
            [(8, None), (1, None)], 'Window 3 stored paths changed')
    require([flag_cell_path(False, 0, o, 0, 59) for o in (0, 59, 60)] ==
            [(8, 0), (8, 59), (0, None)], 'Window 4 paths changed')
    require([flag_cell_path(True, v, 30, 0, 59) for v in (30, 31)] ==
            [(8, None), (1, None)], 'Window 4 stored paths changed')
    require([flag_cell_path(False, 0, o, 0, 60) for o in (0, 60, 61)] ==
            [(8, 0), (8, 60), (0, None)], 'Window 5 paths changed')
    require([flag_cell_path(True, v, 30, 0, 60) for v in (30, 31)] ==
            [(8, None), (1, None)], 'Window 5 stored paths changed')

    return dict(target_release='94', target_sha256=SHA256,
                coordinate_system='ELF virtual addresses, no runtime rebase',
                windows=[
                    dict(start_va=hex(W1_START), fde_end_va_exclusive=hex(W1_END),
                         fde_bytes=50, fde_body_sha256=hashlib.sha256(w1).hexdigest(),
                         fde_section_offset='0x14454', padding_int3_bytes=14),
                    dict(start_va=hex(W2_START), fde_end_va_exclusive=hex(W2_END),
                         fde_bytes=64, fde_body_sha256=hashlib.sha256(w2).hexdigest(),
                         fde_section_offset='0x14468', padding_int3_bytes=0),
                    dict(start_va=hex(W3_START), fde_end_va_exclusive=hex(W3_END),
                         fde_bytes=55, fde_body_sha256=hashlib.sha256(w3).hexdigest(),
                         fde_section_offset='0x1447c', padding_int3_bytes=9),
                    dict(start_va=hex(W4_START), fde_end_va_exclusive=hex(W4_END),
                         fde_bytes=57, fde_body_sha256=hashlib.sha256(w4).hexdigest(),
                         fde_section_offset='0x14490', padding_int3_bytes=7),
                    dict(start_va=hex(W5_START), fde_end_va_exclusive=hex(W5_END),
                         fde_bytes=57, fde_body_sha256=hashlib.sha256(w5).hexdigest(),
                         fde_section_offset='0x144a4', padding_int3_bytes=7)],
                cells=dict(
                    byte_cell=dict(window='0x1515880', field='0xa0(rdi)',
                                   field_size='byte', sentinel=7,
                                   input_range='1..7', stored='input - 1'),
                    table_cell=dict(window='0x15158c0', field='0xa0(rdi)',
                                    field_size='byte', sentinel=7,
                                    input_range='0..6',
                                    table='0x5040302010006',
                                    table_map='0->6, 1->0, 2->1, 3->2, 4->3, 5->4, 6->5',
                                    stored='table[input]'),
                    flag_cells=[
                        dict(window='0x1515900', flag_field='0x78(rdi)',
                             flag_test='low byte == 0 means unset',
                             flag_store='full u32 value 1',
                             value_field='0x7c(rdi)', input_range='1..12',
                             remap='12 stored as 0'),
                        dict(window='0x1515940', flag_field='0x80(rdi)',
                             flag_test='full u32 == 1 means set',
                             flag_store='full u32 value 1',
                             value_field='0x84(rdi)', input_range='0..59',
                             remap=None),
                        dict(window='0x1515980', flag_field='0x88(rdi)',
                             flag_test='full u32 == 1 means set',
                             flag_store='full u32 value 1',
                             value_field='0x8c(rdi)', input_range='0..60',
                             remap=None)]),
                protocol='out-of-range input returns 0; an unset cell stores '
                         'the input and returns 8; a set cell returns 8 when '
                         'the stored value matches and 1 when it differs',
                distinction='mechanically distinct from the submitted once-flag '
                            'packet (PR #174): these five windows contain no lock '
                            'prefix, no atomic exchange, no call, no thread-local '
                            'test, and no tail jump through an imported slot; '
                            'every path ends in a plain ret',
                claim='these windows implement the same set-once protocol with '
                      'per-window fields and ranges',
                inferred_label=None,
                captured_binary_executed=False, progress_gate_requested=False)


def inspect(path):
    data = Path(path).read_bytes()
    require(len(data) == 91774280 and hashlib.sha256(data).hexdigest() == SHA256,
            'Expected exact node #94 size/SHA-256')
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--check', type=Path, help='Compare with retained JSON; fail on drift')
    args = parser.parse_args()
    result = inspect(args.binary)
    if args.check:
        require(result == json.loads(args.check.read_text()), 'Retained evidence differs')
        print('Foundation set-once evidence reproduces exactly.')
    else:
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
