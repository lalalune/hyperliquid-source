#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 cursor-walk packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window walks a cursor in 0x38 steps: each visited node must have byte
+9 == 2 and byte +0 == 0, the cursor slot *(rdi) is advanced before the
node checks, and the walk returns 1 exactly when an advance lands on the
limit stored at rdi+8. The return value is fully determined (eax is zeroed
on every return path), so no low-byte-only caveat applies here, unlike
packets #27/#32.

This window is bound ALONE. No census of similar windows is claimed.
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
START, END = 0x3c1d690, 0x3c1d6e1
BODY = bytes.fromhex(
    '488b37488b4f084839ce7442488d5638488917440fb6460931c04180f803742d'
    '4180f8027527803e0075220f1f4400004839ca0f94c07415488d7238488937807'
    'a09027508803a004889f274e3c331c0c3')
STRIDE_END = 0x3c1d6f0
PADDING = bytes.fromhex('cc' * 15)
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# The window CIE and FDE encodings are zR: initial_location is a 4-byte
# signed PC-relative value under the CIE's zR encoding; range is a 4-byte
# unsigned value. The next and caller FDEs belong to the same zR CIE; their
# raw bytes are locked and their ranges are the GNU-decoded values, not
# hand re-derivations.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000c8ee1b00acd2d7025100000000000000')
NEXT_FDE = bytes.fromhex(
    '38000000dcee1b00f8d2d7020e01000000410e10420e18420e20410e28410e308'
    '3058e048f0386020300010e28410e20420e18420e10410e08000000')
CALLER_FDE = bytes.fromhex(
    '2800000090811100849856029200000000440e206a0e08420e20660e08460e20500'
    'e08410e20640e08000000')
CALL_SITE = 0x3362fb8
CALL_BYTES = bytes.fromhex('e8d3a68b00')
CALLER_START, CALLER_END = 0x3362f30, 0x3362fc2


def require(condition, message):
    if not condition:
        raise ValueError(message)


def walk(cursor, limit, nodes, max_steps=1024):
    """Decoded rule of the window, for edge checks only.

    A restatement of the retained bytes, not execution: nodes maps each
    visited node address to (tag_byte_at_+9, first_byte_at_+0). Returns
    (return_value, final_cursor_slot). The step cap only bounds this
    restatement; the window itself has no bound check (see README).
    """
    slot = cursor
    if cursor == limit:
        return 0, slot
    node = cursor
    for _ in range(max_steps):
        nxt = node + 0x38
        slot = nxt
        tag, first = nodes[node]
        if tag != 2 or first != 0:
            return 0, slot
        if nxt == limit:
            return 1, slot
        node = nxt
    raise ValueError('Walk did not terminate within step cap')


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
    require(body == BODY, 'Cursor-walk instruction window changed')
    require(read(END, STRIDE_END - END) == PADDING,
            'Stride padding changed')
    eh = by_name['.eh_frame']

    def check_fde(offset, raw, start, end):
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')

    require(read(eh['address'] + 0x0, len(CIE)) == CIE, 'CIE changed')
    check_fde(0x1beec4, FDE, START, END)
    check_fde(0x1beed8, NEXT_FDE, 0x3c1d6f0, 0x3c1d7fe)
    check_fde(0x11818c, CALLER_FDE, CALLER_START, CALLER_END)
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x3c1d690.
    require(body[0:3] == bytes.fromhex('488b37'), 'Cursor load changed')
    require(body[3:7] == bytes.fromhex('488b4f08'), 'Limit load changed')
    require(body[6] == 0x08, 'Limit offset changed')
    require(body[7:10] == bytes.fromhex('4839ce'), 'Entry compare changed')
    require(body[10:12] == bytes.fromhex('7442'), 'Entry branch changed')
    require(START + 12 + 0x42 == 0x3c1d6de, 'Entry branch target changed')
    require(body[12:16] == bytes.fromhex('488d5638'), 'First advance changed')
    require(body[15] == 0x38, 'Step constant changed')
    require(body[16:19] == bytes.fromhex('488917'), 'Cursor store changed')
    require(body[19:24] == bytes.fromhex('440fb64609'),
            'First tag load changed')
    require(body[23] == 0x09, 'Tag offset changed')
    require(body[24:26] == bytes.fromhex('31c0'), 'Zeroing changed')
    require(body[26:30] == bytes.fromhex('4180f803'), 'Tag-3 compare changed')
    require(body[30:32] == bytes.fromhex('742d'), 'Tag-3 branch changed')
    require(START + 32 + 0x2d == 0x3c1d6dd, 'Tag-3 branch target changed')
    require(body[32:36] == bytes.fromhex('4180f802'), 'Tag-2 compare changed')
    require(body[36:38] == bytes.fromhex('7527'), 'Tag-2 branch changed')
    require(START + 38 + 0x27 == 0x3c1d6dd, 'Tag-2 branch target changed')
    require(body[38:41] == bytes.fromhex('803e00'), 'First-byte test changed')
    require(body[41:43] == bytes.fromhex('7522'), 'First-byte branch changed')
    require(START + 43 + 0x22 == 0x3c1d6dd, 'First-byte branch target changed')
    require(body[43:48] == bytes.fromhex('0f1f440000'), 'Loop nopl changed')
    require(body[48:51] == bytes.fromhex('4839ca'), 'Limit compare changed')
    require(body[51:54] == bytes.fromhex('0f94c0'), 'Limit set changed')
    require(body[54:56] == bytes.fromhex('7415'), 'Limit branch changed')
    require(START + 56 + 0x15 == 0x3c1d6dd, 'Limit branch target changed')
    require(body[56:60] == bytes.fromhex('488d7238'), 'Loop advance changed')
    require(body[60:63] == bytes.fromhex('488937'), 'Loop cursor store changed')
    require(body[63:67] == bytes.fromhex('807a0902'), 'Loop tag test changed')
    require(body[67:69] == bytes.fromhex('7508'), 'Loop tag branch changed')
    require(START + 69 + 0x08 == 0x3c1d6dd, 'Loop tag branch target changed')
    require(body[69:72] == bytes.fromhex('803a00'), 'Loop first-byte test changed')
    require(body[72:75] == bytes.fromhex('4889f2'), 'Loop next move changed')
    require(body[75:77] == bytes.fromhex('74e3'), 'Loop-back branch changed')
    require(START + 77 - 0x1d == 0x3c1d6c0, 'Loop-back target changed')
    require(body[77:78] == bytes.fromhex('c3'), 'Fail return changed')
    require(body[78:80] == bytes.fromhex('31c0'), 'Entry-equal zeroing changed')
    require(body[80:81] == bytes.fromhex('c3'), 'Entry-equal return changed')
    # Data edge: no relocation record of any type in any .rela.* section
    # names this window as addend (full-section scan).
    naming = []
    for name, sec in by_name.items():
        if name.startswith('.rela.') and sec['size'] % 24 == 0:
            raw = read(sec['address'], sec['size'])
            for off in range(0, len(raw), 24):
                address, info, addend = struct.unpack_from('<QQq', raw, off)
                if addend == START:
                    naming.append((address, info & 0xffffffff))
    require(naming == [], 'Naming relocation changed')
    # Incoming calls: exactly one direct e8 call site in .text, confirmed
    # as an instruction start by linear disassembly from its caller FDE
    # start. This is a byte-pattern scan, explicitly not a complete xref
    # census.
    text = by_name['.text']
    code = read(text['address'], text['size'])
    direct = []
    pos = 0
    while (pos := code.find(b'\xe8', pos)) >= 0:
        rel = struct.unpack_from('<i', code, pos + 1)[0]
        if text['address'] + pos + 5 + rel == START:
            direct.append(text['address'] + pos)
        pos += 1
    require(direct == [CALL_SITE], 'Incoming direct calls changed')
    require(read(CALL_SITE, 5) == CALL_BYTES, 'Caller call bytes changed')
    require(CALLER_START <= CALL_SITE < CALLER_END,
            'Caller site outside caller FDE')
    # Decoded-rule edges (restatement of the retained bytes, not execution).
    require(walk(0x1000, 0x1000, {}) == (0, 0x1000),
            'Entry-equal edge changed')
    require(walk(0x1000, 0x1038, {0x1000: (2, 0)}) == (1, 0x1038),
            'Single-step edge changed')
    require(walk(0x1000, 0x1038, {0x1000: (3, 0)}) == (0, 0x1038),
            'Tag-3 edge changed')
    require(walk(0x1000, 0x1038, {0x1000: (1, 0)}) == (0, 0x1038),
            'Tag-1 edge changed')
    require(walk(0x1000, 0x1038, {0x1000: (2, 1)}) == (0, 0x1038),
            'First-byte edge changed')
    require(walk(0x1000, 0x1070, {0x1000: (2, 0), 0x1038: (2, 0)})
            == (1, 0x1070), 'Two-node edge changed')
    require(walk(0x1000, 0x1070, {0x1000: (2, 0), 0x1038: (2, 5)})
            == (0, 0x1070), 'Second-node-bad edge changed')
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'call_sites': direct,
        'naming_slot': None,
    }


def inspect(binary):
    data = Path(binary).read_bytes()
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Target digest changed')
    result = analyze(data)
    result['target_sha256'] = SHA256
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', default=str(TARGET))
    parser.add_argument('--check', metavar='EVIDENCE')
    args = parser.parse_args()
    result = inspect(args.binary)
    if args.check:
        retained = json.loads(Path(args.check).read_text())
        require(retained['function']['sha256'] == result['body_sha256'],
                'Retained body hash changed')
        require(retained['function']['start_va'] == hex(START)
                and retained['function']['end_va_exclusive'] == hex(END),
                'Retained window range changed')
        require(retained['incoming_pattern_scan']['e8_candidates']
                == [hex(c) for c in result['call_sites']],
                'Retained call sites changed')
        print('Foundation cursor-walk evidence reproduces exactly.')
    else:
        print(json.dumps(result, default=str, indent=2))


if __name__ == '__main__':
    main()
