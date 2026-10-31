#!/usr/bin/env python3
"""Authenticated node94 std Once state-machine binding (0x4ee3b20).

Binds the once machinery both read-lock guards consult (RE-001-lock-descriptor-94)
to the node #94 digest: the 540-byte body 0x4ee3b20..0x4ee3d3c with its two-bit
state machine (Incomplete/Poisoned/Running/Complete plus the waiter flag), the
four-entry jump table at 0x7cb390 whose computed dispatch targets are validated,
the futex wake/wait sequences (syscall selector 0xca with the 0x89/0x81
operations and the 0x7fffffff wake count), the poison panic site whose message
begins 'Once instance has previously been poisoned', and the whole-`.text`
census — 1252 GOT-mediated call sites through slot 0x576e8b8, the most-shared
helper measured in this series. Static byte/record checks only; the captured
binary is never executed.
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

START, END = 0x4ee3b20, 0x4ee3d3c
FDE_VA = 0x12f68c0
GOT_SELF = 0x576e8b8
GOT_PANIC, PANIC_FN = 0x576e098, 0x157b810
FUTEX_GOT = 0x576ea40          # indirect futex wrapper slot (no static relocation)
TLS_GOT = 0x576e8d8            # indirect TLS/park slot getter
RESUME_UNWIND = 0x5660110
JUMP_TABLE_VA = 0x7cb390
JUMP_TARGETS = [0x4ee3c3a, 0x4ee3c76, 0x4ee3cf7, 0x4ee3c52]
POISON_MSG_VA = 0x7cd78c
POISON_MSG = b'Once instance has previously been poisoned'
POISON_ESI = 0x55
FUTEX_NR = 0xca                # SYS_futex, x86-64 Linux ABI
FUTEX_WAKE_PRIVATE = 0x81
FUTEX_WAIT_PRIVATE = 0x89

# The lock-cell sibling guard's call site (RE-001-lock-descriptor-94) and the
# 952-site helper's own call are both inside the census.
SIBLING_SITE = 0x358dc26

BODY = bytes.fromhex(
'554889e54157415641554154534883ec3848894db0488955b84889fb8b074c8d'
'6dc885f60f84ff0000004c8b35efae88004c8b3d80ad8800eb13660f1f440000'
'83ca01f00fb1130f848b00000089c183e10389c283e2048d71fe83fe0272e183'
'f9010f85b20000004189c485d275104183cc04b801000000f0440fb12375ce48'
'c745c000000000660f1f8400000000008b034439e0753a807dc00041b8000000'
'004d0f45c5c70424ffffffffbfca0000004889deba890000004489e14531c931'
'c041ffd64885c0790841ffd783380474bf8b03e975ffffff83f9020f94c2c745'
'c0000000008855c4488d75c0488b7db8488b45b0ff50208b45c08703a804741a'
'bfca0000004889deba81000000b9ffffff7f31c0ff1506ae88004883c4385b41'
'5c415d415e415f5dc34c8d3d40778efbeb0e83c90131d24489e0f00fb10b749e'
'89c283e20389c183e104496314974c01fa4189c4ffe285c975104183cc04b801'
'000000f0440fb12375d64d89c648c745c0000000008b034439e07540807dc000'
'41b8000000004d0f45c5c70424ffffffffbfca0000004889deba890000004489'
'e14531c931c0ff1574ad88004885c0790bff1501ac880083380474b9448b2344'
'89e083e0034489e183e104496304874c01f84d89f0ffe0488d3d8e9a8efbbe55'
'0000004c89c2ff158ca388004989c6b8020000008703a804741abfca00000048'
'89deba81000000b9ffffff7f31c0ff150cad88004c89f7e8d4c37700')

FDE = bytes.fromhex(
'30000000988c330058d2be031c02000004dfc68cff410e108602430d064d8307'
'8c068d058e048f030317010c0708410c06100000')

# (offset, bytes, label) anchors.
ANCHORS = [
    (0x1c, '8b07', 'load state word'),
    (0x4f, '83e103', 'state mask 3'),
    (0x54, '83e204', 'waiter flag mask 4'),
    (0x43, 'f00fb1', 'lock cmpxchg dword (first)'),
    (0x13a, 'f00fb1', 'lock cmpxchg dword (second)'),
    (0xac, 'bfca000000', 'futex syscall selector'),
    (0xb4, 'ba89000000', 'futex wait operation'),
    (0x108, 'ba81000000', 'futex wake operation (first)'),
    (0x10d, 'b9ffffff7f', 'wake all count'),
    (0x1de, 'be55000000', 'poison panic operand'),
    (0x202, 'ba81000000', 'futex wake operation (second)'),
    (0x207, 'b9ffffff7f', 'wake all count (second)'),
]

# Jump-table dispatch sites (offset of the movsxd that reads the table).
DISPATCH_SITES = [0x14a, 0x1cb]
JUMP_TABLE_LEA_OFFSET = 0x129


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
    rels = relocations(reader)

    body = reader.read(START, END - START)
    require(body == BODY, 'Once state machine body bytes changed')
    eh = reader.by_name['.eh_frame']
    require(eh['address'] <= FDE_VA < eh['address'] + eh['size'], 'FDE outside .eh_frame')
    fde = reader.read(FDE_VA, len(FDE))
    require(fde == FDE, 'Once FDE record changed')
    length = struct.unpack_from('<I', fde, 0)[0]
    pc = FDE_VA + 8 + struct.unpack_from('<i', fde, 8)[0]
    extent = struct.unpack_from('<I', fde, 12)[0]
    require(length == len(FDE) - 4, 'FDE length changed')
    require((pc, pc + extent) == (START, END), 'FDE PC range changed')

    for offset, hexstr, label in ANCHORS:
        raw = bytes.fromhex(hexstr)
        require(body[offset:offset + len(raw)] == raw, f'Anchor changed: {label}')

    # Jump table: lea base plus four i32 displacements, all targets in-body.
    require(body[JUMP_TABLE_LEA_OFFSET:JUMP_TABLE_LEA_OFFSET + 3] == bytes.fromhex('4c8d3d'),
            'jump table lea opcode changed')
    disp = struct.unpack_from('<i', body, JUMP_TABLE_LEA_OFFSET + 3)[0]
    require(START + JUMP_TABLE_LEA_OFFSET + 7 + disp == JUMP_TABLE_VA,
            'jump table address changed')
    entries = struct.unpack_from('<4i', reader.read(JUMP_TABLE_VA, 16), 0)
    targets = [JUMP_TABLE_VA + e for e in entries]
    require(targets == JUMP_TARGETS,
            f'Jump table targets changed: {[hex(t) for t in targets]}')
    for target in targets:
        require(START <= target < END, f'Jump target {target:#x} left the body')
    for offset, hexstr in zip(DISPATCH_SITES, ('49631497', '49630487')):
        require(body[offset:offset + 4] == bytes.fromhex(hexstr),
                f'dispatch movsxd at +0x{offset:x} changed')

    # Futex wrapper slots are loaded indirectly (no static relocation); the
    # calls carry the selector and operations as immediates.
    require(body.count(bytes.fromhex('bfca000000')) == 4,
            'futex selector count changed')

    # Poison panic: lea to the message, esi operand, callee, unwind resume.
    require(body[0x1d7:0x1da] == bytes.fromhex('488d3d'),
            'poison panic lea opcode changed')
    disp = struct.unpack_from('<i', body, 0x1da)[0]
    require(START + 0x1d7 + 7 + disp == POISON_MSG_VA, 'poison message address changed')
    require(reader.read(POISON_MSG_VA, len(POISON_MSG)) == POISON_MSG,
            'poison panic message bytes changed')
    require(rels.get(GOT_PANIC) == PANIC_FN, 'poison panic callee changed')
    require(body[0x1e6:0x1e8] == bytes.fromhex('ff15'),
            'poison panic call opcode changed')
    disp = struct.unpack_from('<i', body, 0x1e8)[0]
    require(START + 0x1e6 + 6 + disp == GOT_PANIC, 'poison panic call GOT changed')
    require(body[0x217:0x21c] == bytes.fromhex('e8d4c37700'),
            'resume unwind call changed')

    # Census over the whole .text: the most-shared helper in the series.
    text = reader.by_name['.text']
    code = reader.read(text['address'], text['size'])
    direct, indirect, lea = [], [], []
    pos = 0
    while (pos := code.find(b'\xff\x15', pos)) >= 0:
        if pos + 6 <= len(code):
            slot = text['address'] + pos + 6 + struct.unpack_from('<i', code, pos + 2)[0]
            if rels.get(slot) == START:
                indirect.append(text['address'] + pos)
        pos += 2
    pos = 0
    while (pos := code.find(b'\xe8', pos)) >= 0:
        if pos + 5 <= len(code):
            destination = text['address'] + pos + 5 + struct.unpack_from('<i', code, pos + 1)[0]
            if destination == START:
                direct.append(text['address'] + pos)
        pos += 1
    for m in range(len(code) - 7):
        if code[m] == 0x48 and code[m + 1] == 0x8d and (code[m + 2] & 0xC7) == 0x05:
            d = struct.unpack_from('<i', code, m + 3)[0]
            if text['address'] + m + 7 + d == START:
                lea.append(text['address'] + m)
    require(direct == [], 'Unexpected direct callers')
    require(lea == [], 'Unexpected lea references')
    require(len(indirect) == 1252,
            f'Census changed: {len(indirect)} sites')
    require(rels.get(GOT_SELF) == START, 'self GOT slot changed')
    require(SIBLING_SITE in indirect, 'lock-cell sibling call site missing')

    return dict(
        target_release='94', target_sha256=SHA256,
        coordinate_system='ELF virtual addresses, no runtime rebase',
        state_machine=dict(start_va=hex(START), end_va_exclusive=hex(END),
                           bytes=len(body), sha256=hashlib.sha256(body).hexdigest(),
                           fde_va=hex(FDE_VA), got_slot=hex(GOT_SELF),
                           inferred_label='std sync Once call_once_force state machine'),
        states=dict(mask=3, waiter_flag=4,
                    observed='two-bit state with a waiter bit; two lock cmpxchg '
                             'sites and one xchg completion store',
                    jump_table=dict(va=hex(JUMP_TABLE_VA), entries=4,
                                    targets=[hex(t) for t in JUMP_TARGETS],
                                    dispatch_sites=[hex(START + o) for o in DISPATCH_SITES])),
        futex=dict(syscall_selector='0xca (SYS_futex, x86-64)',
                   wait_operation='0x89', wake_operation='0x81',
                   wake_count='0x7fffffff (wake all)',
                   wrapper_slot=hex(FUTEX_GOT), observed_sites=4),
        poison_panic=dict(message_va=hex(POISON_MSG_VA),
                          message_prefix=POISON_MSG.decode(),
                          message_bytes=len(POISON_MSG),
                          esi_operand=hex(POISON_ESI),
                          callee=hex(PANIC_FN), got=hex(GOT_PANIC),
                          resume_unwind=hex(RESUME_UNWIND)),
        call_census=dict(got_slot=hex(GOT_SELF), got_indirect_sites=1252,
                         direct_e8=0, lea_refs=0,
                         rank='the most-shared helper measured in this series '
                              '(read-lock helper 952, day-count constructor 324)',
                         lock_cell_sibling_site=hex(SIBLING_SITE),
                         note='byte-pattern census over the complete .text for '
                              'e8/ff15/lea encodings'),
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
