#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 seconds-as-f64 evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.

The window's FDE covers [0x1450a60, 0x1450ad3) (115 bytes). The unwind index
stride to the next entry, 0x1450ae0, is 128 bytes only because thirteen int3
padding bytes follow the FDE end; the stride is not the FDE extent.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import struct
from elf_index import sections

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
START, FDE_END, INDEX_END = 0x1450a60, 0x1450ad3, 0x1450ae0
BODY = bytes.fromhex(
    '50ff1539e031044885c0400f98c685d20f9fc14020f10fb6f14801c64869c640420f00660f'
    '57c070408db2003665c484c90f44f24863ce4869c9d34d62104889ca48c1ea3f48c1f92601'
    'd14863c94801c80f90c1f6c10175100f57c0f2480f2ac0f20f5e0597a3dbfe660f5405ff23db'
    'fe58c3')
PADDING = b'\xcc' * 13
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('1400000028ad00001c4876007300000000410e1002710e08')
HELPER_FDE = bytes.fromhex(
    '2c000000f84d01009c6e82008f01000000410e10420e18410e2083048e038602037a010e184'
    '20e10410e08410e200000')
HELPER_SLOT, HELPER_TARGET = 0x576eaa0, 0x151d1b0
WINDOW_SLOT, CALL_SITE = 0x576f6c8, 0x44ab1b2
DIVISOR_VA, MASK_VA = 0x20ae60, 0x202ed0
I64_MIN, I64_MAX = -(1 << 63), (1 << 63) - 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def trunc_div_1000(value):
    """The window's signed magic division: truncating division by 1000."""
    magic = 0x10624dd3
    product = value * magic
    return (product >> 38) + (1 if product < 0 else 0)


def window_result(whole, sub):
    """Pure-arithmetic simulation of the window's formula from its constants.

    Returns the f64 seconds value, or +0.0 on either integer overflow path.
    This evaluates the retained arithmetic; it never runs target code.
    """
    borrow = 1 if whole < 0 and sub > 0 else 0
    scaled = whole + borrow
    micros = scaled * 1000000
    if micros < I64_MIN or micros > I64_MAX:
        return 0.0
    micros += trunc_div_1000(sub - borrow * 1000000000)
    if micros < I64_MIN or micros > I64_MAX:
        return 0.0
    return micros / 1000000.0


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

    body = read(START, FDE_END - START)
    require(body == BODY, 'Seconds-as-f64 instruction window changed')
    require(read(FDE_END, INDEX_END - FDE_END) == PADDING, 'FDE padding changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'], len(CIE)) == CIE, 'CIE changed')
    for offset, raw, start, end in [(0xad24, FDE, START, FDE_END),
                                    (0x14df4, HELPER_FDE, HELPER_TARGET, 0x151d33f)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        # Both retained records use the CIE-confirmed pcrel/sdata4 initial PC.
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    relsec = by_name['.rela.dyn']
    require(relsec['size'] % 24 == 0, 'Truncated RELA section')
    rels = {}
    raw = read(relsec['address'], relsec['size'])
    for off in range(0, len(raw), 24):
        address, info, addend = struct.unpack_from('<QQq', raw, off)
        require(address not in rels, 'Duplicate relocation address')
        rels[address] = (info, addend)

    def relative(address, expected):
        require(rels.get(address) == (8, expected), 'Relative relocation changed')
        require(read(address, 8) == b'\0' * 8, 'Unexpected pre-relocation pointer')

    relative(HELPER_SLOT, HELPER_TARGET)
    relative(WINDOW_SLOT, START)
    # Call bytes and RIP-relative slot targets.
    require(read(0x1450a61, 6) == bytes.fromhex('ff1539e03104'), 'Helper call changed')
    require(0x1450a61 + 6 + struct.unpack_from('<i', read(0x1450a61, 6), 2)[0] == HELPER_SLOT,
            'Helper call slot changed')
    require(read(CALL_SITE, 6) == bytes.fromhex('ff1510452c01'), 'Incoming call changed')
    require(CALL_SITE + 6 + struct.unpack_from('<i', read(CALL_SITE, 6), 2)[0] == WINDOW_SLOT,
            'Incoming call slot changed')
    # Arithmetic constants parsed from the retained instruction bytes.
    require(struct.unpack_from('<I', body, 31)[0] == 1000000, 'Seconds scale changed')
    require(struct.unpack_from('<i', body, 43)[0] == -1000000000, 'Borrow constant changed')
    require(struct.unpack_from('<I', body, 58)[0] == 0x10624dd3, 'Division magic changed')
    require(START + 41 + struct.unpack_from('<b', body, 40)[0] == 0x1450ac9, 'Multiply overflow branch changed')
    require(START + 89 + struct.unpack_from('<b', body, 88)[0] == 0x1450ac9, 'Add overflow branch changed')
    require(0x1450ac1 + 8 + struct.unpack_from('<i', body, 101)[0] == DIVISOR_VA, 'Divisor address changed')
    require(0x1450ac9 + 8 + struct.unpack_from('<i', body, 109)[0] == MASK_VA, 'Overflow mask address changed')
    divisor = struct.unpack_from('<d', read(DIVISOR_VA, 8), 0)[0]
    require(divisor == 1000000.0, 'Divisor constant changed')
    require(struct.unpack_from('<Q', read(MASK_VA, 8), 0)[0] == 0x7fffffffffffffff, 'Overflow mask changed')
    # The magic division is exactly truncating division by 1000, checked on
    # positive, negative, boundary and extreme samples, not assumed.
    for value in (0, 1, -1, 999, 1000, -1000, 1500, -1500, 999999, -999999,
                  1000000000, -1000000000, 2147483647, -2147483648, 10 ** 12, -(10 ** 12)):
        require(trunc_div_1000(value) == math.trunc(value / 1000), 'Magic division mismatch')
    worked = {
        '(0, 0)': window_result(0, 0),
        '(-1, 500000000)': window_result(-1, 500000000),
        '(2, 1500)': window_result(2, 1500),
        '(0, -1500)': window_result(0, -1500),
        '(1, -1)': window_result(1, -1),
        '(-2, -2500)': window_result(-2, -2500),
        '(9223372036855, 0)': window_result(9223372036855, 0),
        '(9223372036854, 2147483647)': window_result(9223372036854, 2147483647),
    }
    require(worked == {'(0, 0)': 0.0, '(-1, 500000000)': -0.5, '(2, 1500)': 2.000001,
                       '(0, -1500)': -0.000001, '(1, -1)': 1.0, '(-2, -2500)': -2.000002,
                       '(9223372036855, 0)': 0.0, '(9223372036854, 2147483647)': 0.0},
            'Worked formula values changed')

    # This byte-pattern scan is explicitly NOT a complete xref census. GNU
    # disassembly from the caller FDE start validates the retained candidate
    # as an instruction start.
    text = by_name['.text']
    code = read(text['address'], text['size'])
    indirect, direct = [], []
    for opcode in (b'\xff\x15', b'\xff\x25', b'\xe8'):
        pos = 0
        while (pos := code.find(opcode, pos)) >= 0:
            length = len(opcode) + 4
            if pos + length <= len(code):
                destination = text['address'] + pos + length + struct.unpack_from('<i', code, pos + len(opcode))[0]
                if destination == (START if opcode == b'\xe8' else WINDOW_SLOT):
                    (direct if opcode == b'\xe8' else indirect).append(text['address'] + pos)
            pos += 1
    require(indirect == [CALL_SITE] and direct == [], 'Call-pattern candidate set changed')
    return dict(target_release='94', target_sha256=SHA256, coordinate_system='ELF virtual addresses, no runtime rebase',
                function=dict(start_va=hex(START), fde_end_va_exclusive=hex(FDE_END),
                              index_stride_end_va_exclusive=hex(INDEX_END),
                              fde_bytes=len(body), index_stride_bytes=INDEX_END - START,
                              fde_body_sha256=hashlib.sha256(body).hexdigest(),
                              index_stride_sha256=hashlib.sha256(body + PADDING).hexdigest(),
                              fde_section_offset='0xad24',
                              inferred_label='seconds-as-f64 conversion window'),
                arithmetic=dict(inputs='helper return pair: whole seconds in rax, sub-second field in edx (low 32 bits of rdx, sign-extended)',
                                borrow='1 iff whole < 0 and sub > 0; sub adjusted by -1000000000 when borrowed',
                                seconds_scale=1000000, sub_divisor=1000, result_divisor=divisor,
                                formula='((whole + borrow) * 1000000 + trunc((sub - borrow * 1000000000) / 1000)) / 1000000.0',
                                resolution='microsecond truncation of the sub-second field (toward zero)',
                                overflow='multiply overflow or add overflow both return +0.0 via the shared andpd tail at 0x1450ac9',
                                worked_examples=worked),
                call_edges=dict(helper_slot=hex(HELPER_SLOT), helper_target=hex(HELPER_TARGET),
                                helper_fde=['0x151d1b0', '0x151d33f'],
                                incoming_slot=hex(WINDOW_SLOT),
                                incoming_sites=[hex(CALL_SITE)],
                                incoming_caller_fde=['0x44aa5a0', '0x44ab55b'],
                                overflow_tail='0x1450ac9', divisor_va=hex(DIVISOR_VA), mask_va=hex(MASK_VA)),
                incoming_pattern_scan=dict(section='.text', byte_count=len(code),
                                           ff15_ff25_candidates=list(map(hex, indirect)),
                                           e8_candidates=direct,
                                           validated_caller_fde=['0x44aa5a0', '0x44ab55b'],
                                           complete_xref_census=False),
                captured_binary_executed=False, progress_gate_requested=False)


def inspect(path):
    data = Path(path).read_bytes()
    require(len(data) == 91774280 and hashlib.sha256(data).hexdigest() == SHA256, 'Expected exact node #94 size/SHA-256')
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--check', type=Path, help='Compare with retained JSON; fail on drift')
    args = parser.parse_args()
    result = inspect(args.binary)
    if args.check:
        require(result == json.loads(args.check.read_text()), 'Retained evidence differs')
        print('Foundation seconds-as-f64 evidence reproduces exactly.')
    else:
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
