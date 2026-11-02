#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 tagged-count-with-cap packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.

The window at 0x22c3f10 (69 bytes) takes rdi = a struct pointer and returns a
single unsigned qword in rax. It reads a tag at [rdi]. Three arms select a
``base`` value, which every arm then caps by [rdi+0x28] (cmp %rax,%rcx ;
cmovb %rcx,%rax -> rax = umin(rax, [rdi+0x28])):

  * tag == 0 (full 64-bit zero): base = [rdi+0x18].
  * low 32 bits of tag == 1: base = usub_sat([rdi+0x10], [rdi+0x18]), i.e.
    [rdi+0x10] - [rdi+0x18] when [rdi+0x10] >= [rdi+0x18] unsigned, else 0
    (sub + cmovae, so an underflow saturates to 0 rather than wrapping).
  * otherwise: base = 0, and the cap step can never lower 0, so it returns 0.

The emptiness check uses the whole 64-bit tag (test %rax,%rax); the ==1
discriminant compares only the low 32 bits (cmp $0x1,%eax). No source-level
type is claimed for the struct, the tag, or the three fields.
"""

import argparse
import hashlib
import json
from pathlib import Path
import struct
from elf_index import sections

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
START, END = 0x22c3f10, 0x22c3f55
PAD_END = 0x22c3f60
BODY = bytes.fromhex(
    '488b074885c0741f83f801752a488b4f1031c0482b4f18480f43c1488b4f28'
    '4839c1480f42c1c3488b4718488b4f284839c1480f42c1c331c0488b4f2848'
    '39c1480f42c1c3')
PAD = b'\xcc' * 11
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000842e060070fb570145000000')
NEXT_FDE = bytes.fromhex('10000000982e0600acfb570105000000')
TAG_OFFSET = 0x0
FIELD_A_OFFSET = 0x10
FIELD_B_OFFSET = 0x18
CAP_OFFSET = 0x28
TAG_ONE = 1
# One direct e8 caller inside .text; no tail jumps, no RELATIVE record names
# this window as its addend.
DIRECT_CALLERS = [0x227d52d]
MASK64 = (1 << 64) - 1
MASK32 = (1 << 32) - 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def tagged_count(tag, field_a, field_b, cap):
    """Decoded rule of the window, for edge checks only.

    This is a Python restatement of the retained instruction sequence, not a
    run or emulation of the captured binary. ``tag`` is the full 64-bit qword
    at [rdi]; ``field_a`` = [rdi+0x10], ``field_b`` = [rdi+0x18] and ``cap`` =
    [rdi+0x28] are unsigned qwords. The result is umin(base, cap).
    """
    for name, value in (('tag', tag), ('field_a', field_a),
                        ('field_b', field_b), ('cap', cap)):
        require(0 <= value <= MASK64, f'{name} outside the u64 domain')
    if tag == 0:
        base = field_b
    elif (tag & MASK32) == TAG_ONE:
        base = field_a - field_b if field_a >= field_b else 0
    else:
        base = 0
    return min(base, cap)


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

    body = read(START, END - START)
    require(body == BODY, 'Tagged-count instruction window changed')
    require(read(END, PAD_END - END) == PAD, 'FDE padding changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE)) == CIE, 'CIE changed')
    for offset, raw, start, end in [(0x62e80, FDE, START, END),
                                    (0x62e94, NEXT_FDE, 0x22c3f60, 0x22c3f65)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x22c3f10. All field accesses use
    # disp8 displacements (mod=01), so each field offset is a single byte.
    require(body[0:3] == bytes.fromhex('488b07'), 'tag-load opcode changed')
    require(body[3:6] == bytes.fromhex('4885c0'), 'tag test opcode changed')
    require(body[6] == 0x74, 'tag-zero branch opcode changed')
    require(START + 0x6 + 2 + struct.unpack_from('<b', body, 7)[0] == 0x22c3f37,
            'tag-zero branch target changed')
    require(body[8:10] == bytes.fromhex('83f8'), 'tag compare opcode changed')
    require(body[10] == TAG_ONE, 'tag-one immediate changed')
    require(body[11] == 0x75, 'default branch opcode changed')
    require(START + 0xb + 2 + struct.unpack_from('<b', body, 12)[0] == 0x22c3f47,
            'default branch target changed')
    # tag-one arm
    require(body[13:16] == bytes.fromhex('488b4f'), 'tag1 field_a load opcode changed')
    require(body[16] == FIELD_A_OFFSET, 'tag1 field_a offset changed')
    require(body[17:19] == bytes.fromhex('31c0'), 'tag1 xor changed')
    require(body[19:22] == bytes.fromhex('482b4f'), 'tag1 field_b sub opcode changed')
    require(body[22] == FIELD_B_OFFSET, 'tag1 field_b offset changed')
    require(body[23:27] == bytes.fromhex('480f43c1'), 'tag1 cmovae (saturate) changed')
    require(body[27:30] == bytes.fromhex('488b4f'), 'tag1 cap load opcode changed')
    require(body[30] == CAP_OFFSET, 'tag1 cap offset changed')
    require(body[31:34] == bytes.fromhex('4839c1'), 'tag1 cap compare changed')
    require(body[34:38] == bytes.fromhex('480f42c1'), 'tag1 cap cmovb changed')
    require(body[38] == 0xc3, 'tag1 ret changed')
    # tag-zero arm (0x22c3f37)
    require(body[39:42] == bytes.fromhex('488b47'), 'tag0 field_b load opcode changed')
    require(body[42] == FIELD_B_OFFSET, 'tag0 field_b offset changed')
    require(body[43:46] == bytes.fromhex('488b4f'), 'tag0 cap load opcode changed')
    require(body[46] == CAP_OFFSET, 'tag0 cap offset changed')
    require(body[47:50] == bytes.fromhex('4839c1'), 'tag0 cap compare changed')
    require(body[50:54] == bytes.fromhex('480f42c1'), 'tag0 cap cmovb changed')
    require(body[54] == 0xc3, 'tag0 ret changed')
    # default arm (0x22c3f47)
    require(body[55:57] == bytes.fromhex('31c0'), 'default xor changed')
    require(body[57:60] == bytes.fromhex('488b4f'), 'default cap load opcode changed')
    require(body[60] == CAP_OFFSET, 'default cap offset changed')
    require(body[61:64] == bytes.fromhex('4839c1'), 'default cap compare changed')
    require(body[64:68] == bytes.fromhex('480f42c1'), 'default cap cmovb changed')
    require(body[68] == 0xc3, 'default ret changed')
    # No calls or indirect branches inside the window: the fixed-offset locks
    # above pin every instruction boundary, and no e8/e9/ff byte appears.
    require(b'\xe8' not in body, 'Unexpected call opcode in window')
    require(b'\xe9' not in body, 'Unexpected tail-jump opcode in window')
    require(b'\xff' not in body, 'Unexpected indirect branch in window')
    # Incoming calls: one direct e8 call in .text, no e9 tail jump.
    text = by_name['.text']
    code = read(text['address'], text['size'])
    direct = []
    pos = 0
    while (pos := code.find(b'\xe8', pos)) >= 0:
        rel = struct.unpack_from('<i', code, pos + 1)[0]
        if text['address'] + pos + 5 + rel == START:
            direct.append(text['address'] + pos)
        pos += 1
    require(direct == DIRECT_CALLERS, 'Incoming direct calls changed')
    tail = []
    pos = 0
    while (pos := code.find(b'\xe9', pos)) >= 0:
        rel = struct.unpack_from('<i', code, pos + 1)[0]
        if text['address'] + pos + 5 + rel == START:
            tail.append(text['address'] + pos)
        pos += 1
    require(tail == [], 'Incoming tail jumps changed')
    # Relocations: no RELATIVE record names this window as its addend.
    relsec = by_name['.rela.dyn']
    require(relsec['size'] % 24 == 0, 'Truncated RELA section')
    raw = read(relsec['address'], relsec['size'])
    window_slots = []
    for off in range(0, len(raw), 24):
        address, info, addend = struct.unpack_from('<QQq', raw, off)
        if info == 8 and addend == START:
            window_slots.append(address)
    require(window_slots == [], 'Relocation slots naming window changed')
    # Decoded-rule edges (restatement of the retained bytes, not execution).
    require(tagged_count(0, 0, 5, 10) == 5, 'tag0 under-cap edge changed')
    require(tagged_count(0, 0, 20, 10) == 10, 'tag0 over-cap edge changed')
    require(tagged_count(1, 30, 10, 100) == 20, 'tag1 normal edge changed')
    require(tagged_count(1, 10, 30, 100) == 0, 'tag1 underflow edge changed')
    require(tagged_count(1, 50, 10, 5) == 5, 'tag1 capped edge changed')
    require(tagged_count(2, 99, 99, 99) == 0, 'default edge changed')
    require(tagged_count((1 << 32) | 1, 30, 10, 100) == 20,
            'high-bits low32==1 edge changed')
    require(tagged_count(1 << 32, 99, 99, 99) == 0,
            'low32==0 high-set edge changed')
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'tag_offset': hex(TAG_OFFSET),
        'field_a_offset': hex(FIELD_A_OFFSET),
        'field_b_offset': hex(FIELD_B_OFFSET),
        'cap_offset': hex(CAP_OFFSET),
        'direct_callers': [hex(c) for c in direct],
        'relocation_slots_naming_window': window_slots,
        'text_byte_count': len(code),
    }


def inspect(binary):
    data = Path(binary).read_bytes()
    require(len(data) == 91774280, 'Target size changed')
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Target digest changed')
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(
        description='Verify a digest-bound, static node #94 tagged-count-with-cap '
                    'evidence packet.')
    parser.add_argument('--binary', default=str(TARGET))
    parser.add_argument('--check', help='Compare with retained JSON; fail on drift')
    args = parser.parse_args()
    result = inspect(args.binary)
    if args.check:
        retained = json.loads(Path(args.check).read_text())
        require(retained['target_sha256'] == SHA256, 'Retained digest changed')
        require(retained['function']['start_va'] == hex(START), 'Retained start changed')
        require(retained['function']['end_va_exclusive'] == hex(END), 'Retained end changed')
        require(retained['function']['bytes'] == END - START, 'Retained size changed')
        require(retained['function']['sha256'] == result['body_sha256'],
                'Retained body hash changed')
        require(retained['behavior']['tag_offset'] == result['tag_offset'],
                'Retained tag offset changed')
        require(retained['behavior']['field_a_offset'] == result['field_a_offset'],
                'Retained field_a offset changed')
        require(retained['behavior']['field_b_offset'] == result['field_b_offset'],
                'Retained field_b offset changed')
        require(retained['behavior']['cap_offset'] == result['cap_offset'],
                'Retained cap offset changed')
        require(retained['incoming_pattern_scan']['direct_callers'] ==
                result['direct_callers'], 'Retained callers changed')
        require(retained['incoming_pattern_scan']['relocation_slots'] ==
                result['relocation_slots_naming_window'],
                'Retained window slots changed')
        require(retained['incoming_pattern_scan']['byte_count'] ==
                result['text_byte_count'], 'Retained scan size changed')
        print('Tagged-count-with-cap evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
