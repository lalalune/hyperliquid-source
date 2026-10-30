#!/usr/bin/env python3
"""Authenticated node94 shared "Time Sub" helper binding (0x1447130).

Binds the widely-shared 12-byte-operand difference helper to the node #94
digest: its FDE-bounded body, the three-stage dword comparison cascade, the
saturating microsecond conversion of the inner callee's (i64, i32) pair
(1e6/1e9 constants and the 0x10624dd3 magic divisor), the "Time Sub" format
anchor, its five GOT-mediated targets, and the complete direct/indirect call
census. Static byte/record checks only; the captured binary is never executed
and the inner callee's own semantics stay explicitly unresolved.
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

START, END = 0x1447130, 0x14472a0
FDE_VA = 0xfcf3a8
INNER, FMT_FN, DEALLOC, PANIC_PATH = 0x151d1b0, 0x1344760, 0x54c8cb0, 0x4ee3b20
GOT_INNER, GOT_FMT, GOT_DEALLOC, GOT_PANICPATH, GOT_SELF = (
    0x576eaa0, 0x576e040, 0x576e010, 0x576e8b8, 0x576e8c0)
ONE_E6_VA = 0x20ae60
TIMESUB_STR_VA = 0x1f9cb6
TIMESUB_PREFIX = b'\tTime Sub '
PANIC_STATE_VA = 0x577ab98

BODY = bytes.fromhex(
    '534883ec508b460889442408488b06488904248b5e1039070f9cc00f85830000'
    '008b47043b4424040f92c075778b47083b4424087272ff15347932044885c040'
    '0f98c685d20f9fc14020f10fb6f14801c64869c640420f00660f57c070408db2'
    '003665c484c90f44f24863ce4869c9d34d62104889ca48c1ea3f48c1f92601d1'
    '4863c94801c80f90c1f6c10175100f57c0f2480f2ac0f20f5e05923cdcfe4883'
    'c4505bc384c0748e48897c2418488d05ccd6000048894424204889e148894c24'
    '284889442430488d35b92adbfe488d7c2438488d542418ff15336e3204f6c301'
    '740a8b058039330485c07525488b742438660f57c04885f674a4488b7c244031'
    'd2ff15d96d3204660f57c04883c4505bc3488d05383933044889442410488d44'
    '24104889442418488d3d3a393304488d0d032d22044c8d05e42c2204488d5424'
    '18be01000000ff153c763204eb9e4889c3488b7424384885f6740d488b7c2440'
    '31d2ff15786d32044889dfe8708e2104')

FDE = bytes.fromhex(
    '3000000080170100807d470070010000045f6b95ff410e10440e608302029d0e'
    '10410e08410e60026b0e10410e08410e60000000')

# Conditional branches (body offset, full instruction pattern, rel32
# position, total instruction length, expected destination).
BRANCHES = [
    (0x1b, '0f8583000000', 2, 6, 0x14471d4),  # jne L1 after setl
    (0x2b, '7577', 1, 2, 0x14471d4),          # jne L1 after setb
    (0x34, '7272', 1, 2, 0x14471d8),          # jb  L2
    (0x5c, '7040', 1, 2, 0x14471ce),          # jo  imul overflow return
    (0x8c, '7510', 1, 2, 0x14471ce),          # jne add overflow return
    (0xe0, '740a', 1, 2, 0x144721c),          # je  flag-even return
    (0xea, '7525', 1, 2, 0x1447241),          # jne panic path
    (0xf8, '74a4', 1, 2, 0x14471ce),          # je  zero return
    (0x159, '740d', 1, 2, 0x1447298),         # je  cleanup skip
]

MICROS_PER_SECOND = 1_000_000
NANOS_PER_SECOND = 1_000_000_000
MAGIC_DIVISOR = 0x10624dd3


def require(condition, message):
    if not condition:
        raise ValueError(message)


def relocations(reader):
    raw = reader.read(reader.by_name['.rela.dyn']['address'],
                      reader.by_name['.rela.dyn']['size'])
    require(len(raw) % 24 == 0, 'Truncated .rela.dyn')
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
    require(body == BODY, 'Helper body bytes changed')
    require(len(body) == 0x170, 'FDE extent length changed')

    eh = reader.by_name['.eh_frame']
    require(eh['address'] <= FDE_VA < eh['address'] + eh['size'], 'FDE outside .eh_frame')
    record = reader.read(FDE_VA, len(FDE))
    require(record == FDE, 'Helper FDE record changed')
    length = struct.unpack_from('<I', record, 0)[0]
    pc = FDE_VA + 8 + struct.unpack_from('<i', record, 8)[0]
    extent = struct.unpack_from('<I', record, 12)[0]
    require(length == len(FDE) - 4, 'FDE length changed')
    require((pc, pc + extent) == (START, END), 'FDE PC range changed')

    for offset, pattern, rel_pos, insn_len, destination in BRANCHES:
        raw = bytes.fromhex(pattern)
        require(body[offset:offset + len(raw)] == raw,
                f'Branch instruction changed at +{offset:#x}')
        rel = struct.unpack_from('<i' if insn_len > 2 else '<b', body, offset + rel_pos)[0]
        require(START + offset + insn_len + rel == destination,
                f'Branch destination changed at +{offset:#x}')
        require(START <= destination < END, 'Branch escapes body')

    rels = relocations(reader)
    require(rels.get(GOT_INNER) == INNER, 'Inner callee GOT slot changed')
    require(rels.get(GOT_FMT) == FMT_FN, 'Format callee GOT slot changed')
    require(rels.get(GOT_DEALLOC) == DEALLOC, 'Dealloc callee GOT slot changed')
    require(rels.get(GOT_PANICPATH) == PANIC_PATH, 'Panic-path callee GOT slot changed')
    require(rels.get(GOT_SELF) == START, 'Helper self GOT slot changed')

    for insn_va, got in [(0x1447166, GOT_INNER), (0x1447207, GOT_FMT),
                         (0x1447231, GOT_DEALLOC), (0x1447276, GOT_PANICPATH)]:
        off = insn_va - START
        require(body[off:off + 2] == b'\xff\x15', f'Indirect call opcode changed at {insn_va:#x}')
        disp = struct.unpack_from('<i', body, off + 2)[0]
        require(insn_va + 6 + disp == got, f'Indirect call target changed at {insn_va:#x}')

    require(reader.read(ONE_E6_VA, 8) == struct.pack('<d', 1e6), '1e6 divisor constant changed')
    require(reader.read(TIMESUB_STR_VA, len(TIMESUB_PREFIX)) == TIMESUB_PREFIX,
            '"Time Sub" format anchor changed')
    off = 0x14471f6 - START
    require(body[off:off + 3] == b'\x48\x8d\x35', 'Format anchor lea changed')
    disp = struct.unpack_from('<i', body, off + 3)[0]
    require(0x14471fd + disp == TIMESUB_STR_VA, 'Format anchor address changed')
    require(struct.unpack('<I', reader.read(PANIC_STATE_VA, 4))[0] == 3,
            'Panic-state global initial value changed')

    # Call census over the whole .text: direct e8, GOT-indirect ff15, lea refs.
    text = reader.by_name['.text']
    code = reader.read(text['address'], text['size'])
    starts = sorted_fde_starts(reader)
    direct, indirect, lea_refs = [], [], []
    pos = 0
    while (pos := code.find(b'\xe8', pos)) >= 0:
        if pos + 5 <= len(code):
            destination = text['address'] + pos + 5 + struct.unpack_from('<i', code, pos + 1)[0]
            if destination == START:
                direct.append(text['address'] + pos)
        pos += 1
    pos = 0
    while (pos := code.find(b'\xff\x15', pos)) >= 0:
        if pos + 6 <= len(code):
            got = text['address'] + pos + 6 + struct.unpack_from('<i', code, pos + 2)[0]
            if got == GOT_SELF:
                indirect.append(text['address'] + pos)
        pos += 2
    prefixes = tuple(bytes((r, 0x8d, m)) for r in (0x48, 0x4c)
                     for m in (0x05, 0x0d, 0x15, 0x1d, 0x25, 0x2d, 0x35, 0x3d))
    pos = 0
    while (pos := code.find(b'\x8d', pos)) >= 0:
        for prefix in prefixes:
            begin = pos - 1
            if code[begin:begin + 3] == prefix:
                if begin + 7 <= len(code):
                    destination = text['address'] + begin + 7 + struct.unpack_from('<i', code, begin + 3)[0]
                    if destination == START:
                        lea_refs.append(text['address'] + begin)
                break
        pos += 1
    require(direct == [] and lea_refs == [], 'Unexpected direct/lea references')
    require(len(indirect) == 72, f'GOT-indirect caller census changed: {len(indirect)}')
    import bisect
    caller_functions = set()
    for site in indirect:
        i = bisect.bisect_right(starts, site) - 1
        require(i >= 0 and starts[i] <= site, 'Caller outside indexed text')
        caller_functions.add(starts[i])
    require(len(caller_functions) == 60, 'Distinct caller function count changed')

    return dict(
        target_release='94', target_sha256=SHA256,
        coordinate_system='ELF virtual addresses, no runtime rebase',
        helper=dict(start_va=hex(START), end_va_exclusive=hex(END), bytes=len(body),
                    sha256=hashlib.sha256(body).hexdigest(), fde_va=hex(FDE_VA),
                    inferred_label='shared "Time Sub" difference helper'),
        signature=dict(
            observed=dict(
                rdi='pointer to 12-byte operand A (three dwords)',
                rsi='pointer to 12-byte operand B (three dwords) followed by '
                    'a dword flag and a 16-byte descriptor',
                xmm0='f64 result'),
            cascade='A/0 vs B/2 (setl), A/1 vs B/1 (setb), A/2 vs B/2 (jb); '
                   'field meaning unresolved'),
        arithmetic=dict(
            inner_pair='call 0x151d1b0 returns (i64 rax, i32 edx); meaning unresolved',
            borrow_adjust='if rax < 0 and edx > 0 then rax += 1 and edx -= 1e9',
            micros='(rax_adjusted * 1e6) + trunc_div(edx_adjusted, 1000)',
            magic_divisor=hex(MAGIC_DIVISOR),
            magic_shift=38,
            result='f64(micros) / 1e6',
            overflow='imul or add overflow returns 0.0',
            negative_route='comparison cascade routes to format/saturate path returning 0.0',
            constants=dict(one_e6_va=hex(ONE_E6_VA), one_e9_immediate=True)),
        format_anchor=dict(string_va=hex(TIMESUB_STR_VA), prefix='\tTime Sub ',
                           panic_state_va=hex(PANIC_STATE_VA), panic_state_value=3,
                           flag_gated='odd flag dword may route to the panic path'),
        got_targets=dict(inner=hex(INNER), fmt=hex(FMT_FN), dealloc=hex(DEALLOC),
                         panic_path=hex(PANIC_PATH), self_slot=hex(GOT_SELF)),
        call_census=dict(direct_e8=0, lea_references=0, got_indirect_sites=len(indirect),
                         distinct_caller_functions=len(caller_functions),
                         denominators='complete .text byte scan for e8 / ff15-to-slot / lea encodings',
                         known_consumers=['0x1479229 (ema_tracker update, separate packet)',
                                          '0x4726c81 (heartbeat status body, PR #22)']),
        captured_binary_executed=False, progress_gate_requested=False)


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


def sorted_fde_starts(reader):
    # Reuse the repository's own unwind index when materialized; the census
    # only needs function start VAs for grouping.
    index = ROOT / 'work/index/node-94-unwind.tsv'
    require(index.is_file(), 'Missing work/index/node-94-unwind.tsv; run tools/elf_index.py --release 94')
    starts = []
    for line in index.read_text().splitlines()[1:]:
        _, start, _, _, _ = line.split('\t')
        starts.append(int(start, 16))
    starts.sort()
    return starts


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
