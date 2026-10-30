#!/usr/bin/env python3
"""Authenticated node94 ema window-guard binding (0x474fb90).

Binds the only caller of the ema_tracker update body to the node #94 digest:
its FDE-bounded body, the two chrono-0.4.38 anchors (a NaiveDateTime + TimeDelta
overflow panic and the 86400-second day division), the datetime range constants,
the three lexicographic timestamp cascades, the forwarded f64 sample, the
post-call timestamp copy, and the two-site direct-call census. Static
byte/record checks only; the captured binary is never executed.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from elf_index import sections

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

START, END = 0x474fb90, 0x474fce5
FDE_VA = 0xef91d0
MSG_VA = 0x21a01f
PANIC_MSG = b'`NaiveDateTime + TimeDelta` overflowed'
LOC_VA = 0x566af18
CHRONO_PATH = (b'/home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/'
               b'chrono-0.4.38/src/naive/datetime/mod.rs')
PANIC_FN = 0x157a9b0
CALLEE1, CALLEE2 = 0x15206e0, 0x151f870
UPDATE_FN = 0x14791c0
GOT_PANIC, GOT_CALLEE1, GOT_CALLEE2, GOT_UPDATE = 0x576e468, 0x576e8a8, 0x576e8b0, 0x576f8f0
RANGE_LO, RANGE_HI = 0xffff574000000000, 0xfffeae7ffffeae81
DAY_MAGIC = 0x1845c8a0ce512957
SECS_PER_DAY = 86400
CALLERS = [0x4899415, 0x4899910]
CALLER_FN = (0x4898810, 0x489a550)

BODY = bytes.fromhex(
    '55415741564154534883ec304889f34989fe8b2e3b2a0f9ec075188b43043b42'
    '040f96c0750d8b43083b4208770de9fc00000084c00f85f4000000f20f114424'
    '08418b463c89442418498b46344889442410488d742414488d7c2420ba1e0000'
    '0031c9ff15afec0101488b44242848b9000000004057ffff4801c148ba81aefe'
    'ff7faefeff4839d10f82ae000000448b642420448b7c24248b7c241048b95729'
    '51cea0c8451848f7e94889d648c1ee3f48c1ea0d01d6ff1564ec010185c0747c'
    '39c50f9ec07517443963040f96c0750e44397b08f20f10442408770ceb5184c0'
    'f20f104424087547418b462885c0742239e80f9fc17517498b462c3943040f92'
    'c1750b48c1e8203943087306eb2184c9751d4d8d7e284c89f74889deff153efc'
    '01018b430841894708488b034989074883c4305b415c415e415f5dc3488d3d4c'
    'a3acfb488d153eb2f100be26000000ff1583e70101')

FDE = bytes.fromhex(
    '40000000bc7c2100b86985035501000000410e10420e18420e20420e28410e30'
    '440e6083068c058e048f0386020327010e30410e28420e20420e18420e10410e'
    '08410e60')

# Verified conditional branches and the tail jump (offset, pattern,
# rel32 position, instruction length, destination).
BRANCHES = [
    (0x19, '7518', 1, 2, 0x474fbc3),
    (0x24, '750d', 1, 2, 0x474fbc3),
    (0x2c, '770d', 1, 2, 0x474fbcb),
    (0x2e, 'e9fc000000', 1, 5, 0x474fcbf),
    (0x35, '0f85f4000000', 2, 6, 0x474fcbf),
    (0x88, '0f82ae000000', 2, 6, 0x474fccc),
    (0xbe, '747c', 1, 2, 0x474fccc),
    (0xc5, '7517', 1, 2, 0x474fc6e),
    (0xce, '750e', 1, 2, 0x474fc6e),
    (0xda, '770c', 1, 2, 0x474fc78),
    (0xdc, 'eb51', 1, 2, 0x474fcbf),
    (0xe6, '7547', 1, 2, 0x474fcbf),
    (0xee, '7422', 1, 2, 0x474fca2),
    (0xf5, '7517', 1, 2, 0x474fc9e),
    (0x101, '750b', 1, 2, 0x474fc9e),
    (0x10a, '7306', 1, 2, 0x474fca2),
    (0x10c, 'eb21', 1, 2, 0x474fcbf),
    (0x110, '751d', 1, 2, 0x474fcbf),
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


class Reader:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)
        self.by_name = {s['name']: s for s in self.sections}

    def read(self, va, size):
        matches = [s for s in self.sections if s['type'] != 8
                   and s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(matches) == 1, f'Ambiguous or unmapped VA {va:#x}')
        s = matches[0]
        off = s['offset'] + va - s['address']
        return self.data[off:off + size]


def relocations(reader):
    raw = reader.read(reader.by_name['.rela.dyn']['address'],
                      reader.by_name['.rela.dyn']['size'])
    rels = {}
    for off in range(0, len(raw), 24):
        address, info, addend = struct.unpack_from('<QQq', raw, off)
        if info == 8:
            require(address not in rels, 'Duplicate relative relocation')
            rels[address] = addend
    return rels


def analyze(data):
    reader = Reader(data)
    body = reader.read(START, END - START)
    require(body == BODY, 'Window-guard body bytes changed')
    require(len(body) == 0x155, 'FDE extent length changed')

    eh = reader.by_name['.eh_frame']
    require(eh['address'] <= FDE_VA < eh['address'] + eh['size'], 'FDE outside .eh_frame')
    record = reader.read(FDE_VA, len(FDE))
    require(record == FDE, 'Window-guard FDE record changed')
    length = struct.unpack_from('<I', record, 0)[0]
    pc = FDE_VA + 8 + struct.unpack_from('<i', record, 8)[0]
    extent = struct.unpack_from('<I', record, 12)[0]
    require(length == len(FDE) - 4, 'FDE length changed')
    require((pc, pc + extent) == (START, END), 'FDE PC range changed')

    for offset, pattern, rel_pos, insn_len, destination in BRANCHES:
        raw = bytes.fromhex(pattern)
        require(body[offset:offset + len(raw)] == raw,
                f'Branch instruction changed at +{offset:#x}')
        fmt = '<b' if insn_len == 2 else ('<i' if insn_len in (5, 6) else '<b')
        rel = struct.unpack_from(fmt, body, offset + rel_pos)[0]
        require(START + offset + insn_len + rel == destination,
                f'Branch destination changed at +{offset:#x}')
        require(START <= destination < END, 'Branch escapes body')

    # Datetime range gate: rax + RANGE_LO compared against RANGE_HI.
    require(struct.unpack_from('<Q', body, 0x70)[0] == RANGE_LO, 'Range low constant changed')
    require(struct.unpack_from('<Q', body, 0x7d)[0] == RANGE_HI, 'Range high constant changed')

    # 86400-second day division through the magic multiplier.
    require(struct.unpack_from('<Q', body, 0x9e)[0] == DAY_MAGIC, 'Day-division magic changed')
    require(body[0xb0:0xb4] == bytes.fromhex('48c1ea0d'), 'Day-division shift changed')

    # First chrono callee takes (out, timestamp fields, 30, 0).
    require(body[0x5c:0x61] == bytes.fromhex('ba1e000000'), 'callee1 constant 30 changed')
    require(body[0x61:0x63] == bytes.fromhex('31c9'), 'callee1 zero argument changed')

    rels = relocations(reader)
    require(rels.get(GOT_CALLEE1) == CALLEE1, 'callee1 GOT slot changed')
    require(rels.get(GOT_CALLEE2) == CALLEE2, 'callee2 GOT slot changed')
    require(rels.get(GOT_UPDATE) == UPDATE_FN, 'update GOT slot changed')
    require(rels.get(GOT_PANIC) == PANIC_FN, 'Panic callee GOT slot changed')
    for insn_va, got in [(0x474fbf3, GOT_CALLEE1), (0x474fc46, GOT_CALLEE2),
                         (0x474fcac, GOT_UPDATE), (0x474fcdf, GOT_PANIC)]:
        off = insn_va - START
        require(body[off:off + 2] == b'\xff\x15', f'Indirect call opcode changed at {insn_va:#x}')
        disp = struct.unpack_from('<i', body, off + 2)[0]
        require(insn_va + 6 + disp == got, f'Indirect call target changed at {insn_va:#x}')

    # Panic anchors: message, Location, esi length.
    require(reader.read(MSG_VA, len(PANIC_MSG)) == PANIC_MSG, 'Panic message changed')
    require(rels.get(LOC_VA) is not None, 'Panic Location relocation missing')
    path_va = rels[LOC_VA]
    length_, line, column = struct.unpack('<QII', reader.read(LOC_VA + 8, 16))
    require((length_, line, column) == (len(CHRONO_PATH), 1631, 38),
            'Panic Location layout changed')
    require(reader.read(path_va, length_) == CHRONO_PATH, 'chrono datetime path changed')
    off = 0x474fccc - START
    require(body[off:off + 3] == b'\x48\x8d\x3d', 'Panic message lea changed')
    require(0x474fcd3 + struct.unpack_from('<i', body, off + 3)[0] == MSG_VA,
            'Panic message address changed')
    require(body[0x474fcd3 - START:0x474fcd3 - START + 3] == b'\x48\x8d\x15',
            'Panic location lea changed')
    require(0x474fcda + struct.unpack_from('<i', body, 0x474fcd3 - START + 3)[0] == LOC_VA,
            'Panic location address changed')
    require(body[0x474fcda - START:0x474fcdf - START] == b'\xbe\x26\x00\x00\x00',
            'Panic message length operand changed')

    # The forwarded f64 sample is saved at entry and restored around the update call.
    require(body[0x3b:0x41] == bytes.fromhex('f20f11442408'), 'Sample spill changed')
    require(body[0xd4:0xda] == bytes.fromhex('f20f10442408'), 'Sample reload changed')
    require(body[0x112:0x116] == bytes.fromhex('4d8d7e28'), 'Window base lea changed')

    # Census: two direct callers inside one FDE function, no lea references.
    text = reader.by_name['.text']
    code = reader.read(text['address'], text['size'])
    pos, direct = 0, []
    while (pos := code.find(b'\xe8', pos)) >= 0:
        if pos + 5 <= len(code):
            destination = text['address'] + pos + 5 + struct.unpack_from('<i', code, pos + 1)[0]
            if destination == START:
                direct.append(text['address'] + pos)
        pos += 1
    require(direct == CALLERS, f'Direct caller census changed: {[hex(x) for x in direct]}')
    require(CALLER_FN[0] <= CALLERS[0] < CALLER_FN[1]
            and CALLER_FN[0] <= CALLERS[1] < CALLER_FN[1], 'Caller outside the statistics body')

    # Magic-division identity for non-negative operands: the decoded sequence
    # computes trunc(n / 86400) for the range-checked callee result.
    for n in (0, 1, 30, 599, 3600, 86399, 86400, 86401, 172800, 10**9):
        high = (n * DAY_MAGIC) >> 64
        q = high >> 13
        require(q == n // SECS_PER_DAY, f'Day-division identity failed for {n}')

    return dict(
        target_release='94', target_sha256=SHA256,
        coordinate_system='ELF virtual addresses, no runtime rebase',
        guard=dict(start_va=hex(START), end_va_exclusive=hex(END), bytes=len(body),
                   sha256=hashlib.sha256(body).hexdigest(), fde_va=hex(FDE_VA),
                   inferred_label='ema window guard around the update body'),
        chrono_anchors=dict(
            panic=dict(message=PANIC_MSG.decode(), message_va=hex(MSG_VA),
                       location_va=hex(LOC_VA), line=1631, column=38,
                       path='chrono-0.4.38/src/naive/datetime/mod.rs',
                       callee=hex(PANIC_FN)),
            range_gate=dict(low=hex(RANGE_LO), high=hex(RANGE_HI),
                            observed='callee1 result + low compared against high; below routes to the panic'),
            day_division=dict(magic=hex(DAY_MAGIC), divisor=SECS_PER_DAY,
                              observed='callee1 result divided into whole days for callee2'),
            callee1=dict(target=hex(CALLEE1), got=hex(GOT_CALLEE1),
                         observed='takes (out, timestamp fields, 30, 0)'),
            callee2=dict(target=hex(CALLEE2), got=hex(GOT_CALLEE2))),
        structure=dict(
            cascades='three lexicographic three-dword timestamp comparisons '
                     '(sample vs window argument; sample vs callee2 result; stored window vs sample)',
            update_call=dict(target=hex(UPDATE_FN), site='0x474fcac',
                             note='the only caller of the ema_tracker update body'),
            sample_forward='xmm0 spilled at entry, reloaded before the update call',
            post_update='12-byte sample timestamp copied to context +0x28'),
        call_census=dict(direct_e8=[hex(x) for x in CALLERS], lea_references=0,
                         containing_function=dict(start=hex(CALLER_FN[0]), end=hex(CALLER_FN[1])),
                         denominator='complete .text scan for e8 and lea encodings'),
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
    parser.add_argument('--output', type=Path, help='Write the record JSON to this path')
    args = parser.parse_args()
    result = inspect(args.binary)
    text = json.dumps(result, indent=2, sort_keys=True) + '\n'
    if args.check is not None:
        expected = args.check.read_text()
        require(text == expected, 'Retained evidence record drifted')
        print('Record matches retained evidence.')
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text)
    else:
        print(text)


if __name__ == '__main__':
    main()
