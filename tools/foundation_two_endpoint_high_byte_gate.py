#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 two-endpoint high-byte gate packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window takes (rdi, rsi, rdx=base, rcx=limit) and returns base+rdi unless
a gate fails: rsi < rdi (unsigned) returns 0; rdi > rcx returns 0; rsi > rcx
returns 0; and when an endpoint index is strictly below rcx, the byte at that
endpoint must not be in 0x80..0xbf (signed byte <= -65), else 0. Endpoint
indices exactly equal to rcx skip their byte check. The two byte gates use
different immediates (0xc0 with jl, 0xbf with jle) but reject exactly the same
byte set. No meaning is claimed for the endpoints, the base, or the limit.
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
START, END = 0x3cd2460, 0x3cd2490
BODY = bytes.fromhex(
    '4889d04889f24829fa730331c0c34839cf7308803c38c07cf2eb0275ee4839ce'
    '7308803c30bf7ee3eb0275df4801f8c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('100000000cdd1c003832e2023000000000000000')
FDE_OFFSET = 0x1cdd08
CALLER = 0x3cd2aa2
CALLER_BYTES = bytes.fromhex('e8b9f9ffff')
CALLER_SETUP_RDI = bytes.fromhex('488b7c2448')
CALLER_SETUP_RSI = bytes.fromhex('488b742428')
CALLER_SETUP_RDX = bytes.fromhex('488b542410')
CALLER_SETUP_RCX = bytes.fromhex('488b4c2418')
# The FDE whose PC equals the window end is the caller FDE itself (its CIE
# differs from the window's; only the head and PC/range are locked).
CALLER_FDE_OFFSET = 0x50f1bc
CALLER_FDE_HEAD = bytes.fromhex('50000000ac2a2300b41dae02c3080000')
CALLER_START, CALLER_END = 0x3cd2490, 0x3cd2d53


def require(condition, message):
    if not condition:
        raise ValueError(message)


def signed(byte):
    return byte if byte < 0x80 else byte - 256


def gate(rdi, rsi, base, rcx, mem):
    """Decoded formula of the window, for edge checks only.

    This is a Python restatement of the retained instruction sequence, not a
    run or emulation of the captured binary. ``mem`` maps absolute addresses
    to byte values. All index/limit comparisons are unsigned (the window
    uses jae/jne, never signed branches, for them); only the two byte gates
    read signed bytes, and both reject exactly signed byte <= -65, i.e.
    unsigned byte in 0x80..0xbf.
    """
    if rsi < rdi:
        return 0
    if rdi > rcx:
        return 0
    if rdi < rcx and signed(mem[base + rdi]) <= -65:
        return 0
    if rsi > rcx:
        return 0
    if rsi < rcx and signed(mem[base + rsi]) <= -65:
        return 0
    return base + rdi


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
    require(body == BODY, 'Two-endpoint gate instruction window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE)) == CIE, 'CIE changed')
    record = read(eh['address'] + FDE_OFFSET, len(FDE))
    require(record == FDE, 'FDE record changed')
    pc = eh['address'] + FDE_OFFSET + 8 + struct.unpack_from('<i', record, 8)[0]
    extent = struct.unpack_from('<I', record, 12)[0]
    require((pc, pc + extent) == (START, END), 'FDE PC/range changed')
    # No padding: the next FDE starts exactly at END, and that FDE is the
    # caller FDE (section offset 0x50f1bc). The physically adjacent record
    # in .eh_frame order (offset 0x1cdd1c, PC 0x3cd3860) is not the next
    # function in address order and is not locked as "next".
    chead = read(eh['address'] + CALLER_FDE_OFFSET, len(CALLER_FDE_HEAD))
    require(chead == CALLER_FDE_HEAD, 'Caller FDE record changed')
    cpc = (eh['address'] + CALLER_FDE_OFFSET + 8
           + struct.unpack_from('<i', chead, 8)[0])
    cent = struct.unpack_from('<I', chead, 12)[0]
    require((cpc, cpc + cent) == (CALLER_START, CALLER_END),
            'Caller FDE PC/range changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x3cd2460.
    require(body[0:3] == bytes.fromhex('4889d0'), 'Base move changed')
    require(body[3:6] == bytes.fromhex('4889f2'), 'End move changed')
    require(body[6:9] == bytes.fromhex('4829fa'), 'Span subtract changed')
    require(body[9:11] == bytes.fromhex('7303'), 'Span branch changed')
    require(body[11:13] == bytes.fromhex('31c0'), 'Zero changed')
    require(body[13:14] == bytes.fromhex('c3'), 'First return changed')
    require(body[14:17] == bytes.fromhex('4839cf'), 'Start/limit compare changed')
    require(body[17:19] == bytes.fromhex('7308'), 'Start/limit branch changed')
    require(body[19:23] == bytes.fromhex('803c38c0'), 'Start byte compare changed')
    require(body[23:25] == bytes.fromhex('7cf2'), 'Start byte branch changed')
    require(body[25:27] == bytes.fromhex('eb02'), 'Start pass jump changed')
    require(body[27:29] == bytes.fromhex('75ee'), 'Start equal branch changed')
    require(body[29:32] == bytes.fromhex('4839ce'), 'End/limit compare changed')
    require(body[32:34] == bytes.fromhex('7308'), 'End/limit branch changed')
    require(body[34:38] == bytes.fromhex('803c30bf'), 'End byte compare changed')
    require(body[38:40] == bytes.fromhex('7ee3'), 'End byte branch changed')
    require(body[40:42] == bytes.fromhex('eb02'), 'End pass jump changed')
    require(body[42:44] == bytes.fromhex('75df'), 'End equal branch changed')
    require(body[44:47] == bytes.fromhex('4801f8'), 'Base add changed')
    require(body[47:48] == bytes.fromhex('c3'), 'Final return changed')
    # Caller call bytes and argument setup: rdi, rsi, rdx, rcx are loaded
    # from the caller's stack slots immediately before the call.
    require(read(CALLER, 5) == CALLER_BYTES, 'Caller call bytes changed')
    require(read(0x3cd2a8e, 5) == CALLER_SETUP_RDI, 'Caller rdi setup changed')
    require(read(0x3cd2a93, 5) == CALLER_SETUP_RSI, 'Caller rsi setup changed')
    require(read(0x3cd2a98, 5) == CALLER_SETUP_RDX, 'Caller rdx setup changed')
    require(read(0x3cd2a9d, 5) == CALLER_SETUP_RCX, 'Caller rcx setup changed')
    # Data edge: no relocation record of any type in any .rela.* section
    # names this window as addend. The full-section scan counts are locked
    # so a truncated scan cannot pass silently.
    naming = []
    rela_counts = {}
    for relname in ('.rela.dyn', '.rela.plt'):
        relsec = by_name[relname]
        require(relsec['size'] % 24 == 0, 'Truncated RELA section')
        raw = read(relsec['address'], relsec['size'])
        rela_counts[relname] = len(raw) // 24
        for off in range(0, len(raw), 24):
            address, info, addend = struct.unpack_from('<QQq', raw, off)
            if addend == START:
                naming.append(address)
    require(naming == [], 'Naming slots changed')
    require(rela_counts == {'.rela.dyn': 80022, '.rela.plt': 278},
            'RELA section counts changed')
    # Incoming calls: exactly one direct e8 call, the confirmed caller.
    text = by_name['.text']
    code = read(text['address'], text['size'])
    direct = []
    pos = 0
    while (pos := code.find(b'\xe8', pos)) >= 0:
        rel = struct.unpack_from('<i', code, pos + 1)[0]
        if text['address'] + pos + 5 + rel == START:
            direct.append(text['address'] + pos)
        pos += 1
    require(direct == [CALLER], 'Incoming direct calls changed')
    # Decoded-formula edges (restatement of the retained bytes, not execution).
    # Base 0x1000, limit 0x10; mem covers the endpoint indices used.
    base, rcx = 0x1000, 0x10
    mem = {base + i: 0x41 for i in range(0x20)}
    require(gate(0x2, 0x8, base, rcx, mem) == base + 0x2, 'Clean path changed')
    require(gate(0x8, 0x2, base, rcx, mem) == 0, 'Reversed span changed')
    require(gate(0x11, 0x12, base, rcx, mem) == 0, 'Start past limit changed')
    require(gate(0x2, 0x11, base, rcx, mem) == 0, 'End past limit changed')
    require(gate(0x10, 0x10, base, rcx, mem) == base + 0x10,
            'At-limit skip changed')
    for bad in (0x80, 0x90, 0xbf):
        m = dict(mem)
        m[base + 0x2] = bad
        require(gate(0x2, 0x8, base, rcx, m) == 0, 'Start byte reject changed')
        m = dict(mem)
        m[base + 0x8] = bad
        require(gate(0x2, 0x8, base, rcx, m) == 0, 'End byte reject changed')
    for good in (0x00, 0x41, 0x7f, 0xc0, 0xff):
        m = dict(mem)
        m[base + 0x2] = good
        m[base + 0x8] = good
        require(gate(0x2, 0x8, base, rcx, m) == base + 0x2,
                'Byte accept changed')
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'caller': CALLER,
        'rela_counts': rela_counts,
    }


def inspect(binary):
    data = Path(binary).read_bytes()
    require(len(data) == 91774280, 'Target size changed')
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Target digest changed')
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(
        description='Verify a digest-bound, static node #94 two-endpoint '
                    'high-byte gate evidence packet.')
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
        require(retained['incoming_pattern_scan']['e8_candidates'] == [hex(CALLER)],
                'Retained callers changed')
        require(retained['data_edge']['relative_slots_naming_window'] == [],
                'Retained naming slots changed')
        print('Foundation two-endpoint-high-byte-gate evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
