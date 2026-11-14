#!/usr/bin/env python3
"""RE-004 / node #115: static verifier for the saturating sum at 0x294bcd0.

Reads, hashes and decodes the authenticated captured ELF. Nothing is executed
or emulated, and nothing touches the network.

    python3 research/work-items/RE-004-node115-ntl-saturating-sum-294bcd0/verify.py [--json] [--write-listing]

Requires Python 3.10+, capstone (version pinned by CI) and this repository's
tools/ helpers. A GNU objdump on PATH adds an independent instruction-boundary
cross-check; without one that stage is reported as skipped, not passed.
"""
import argparse
import hashlib
import json
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))

from capstone import CS_AC_WRITE, CS_ARCH_X86, CS_MODE_64, Cs  # noqa: E402
from capstone.x86 import X86_OP_MEM  # noqa: E402
from elf_index import sections, unwind_index  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

TARGET = ROOT / 'artifacts/node/115/hl-node'
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
LISTING = Path(__file__).with_name('instructions.tsv')

START, END = 0x294bcd0, 0x294bd73  # FDE extent, .text VA coordinates
WINDOW_SHA256 = '088105b64593c7f48681cd39c8371b2aeac8b1f7f673b4df555815acd92c541b'
CALLEE = (0x2a8ae60, 0x2a8b095)  # direct callee FDE
REPORTER_SLOT = 0x64e4ea8  # .got slot called through at 0x294bd3c
REPORTER = (0x4524e40, 0x4524fb1)  # FDE the slot's RELATIVE addend points into
LOCATION = (0x6443cd8, 'l1/src/qtys/impl_ntl.rs', 682, 1)
CALLERS = {0x2c75f4f: (0x2c75620, 0x2c7637b), 0x2c76e4d: (0x2c767d0, 0x2c774c0)}
PRECEDING_CALLEE = 0x29dfea0  # called with esi = 0 before each call site; not characterised here

# Load-bearing instructions, pinned as Capstone prints them. The full 54-instruction
# listing is separately pinned by instructions.tsv.
FACTS = {
    # Entry: accumulator seeded from rsi; a null vector or a zero length returns it.
    0x294bcde: 'mov r14, rsi',
    0x294bce1: 'test rdi, rdi', 0x294bce4: 'je 0x294bd61',
    0x294bce6: 'mov rbp, qword ptr [rdi + 0x10]', 0x294bcea: 'test rbp, rbp', 0x294bced: 'je 0x294bd61',
    0x294bd61: 'mov rax, r14', 0x294bd64: 'add rsp, 0x18',
    # Setup: context loaded once from [rdx]; records start at [rdi + 8] + 0x18.
    0x294bcef: 'mov rbx, qword ptr [rdx]', 0x294bcf2: 'mov r12, qword ptr [rdi + 8]',
    0x294bcf6: 'add r12, 0x18', 0x294bcfa: 'mov r15, rsp',
    # Per record: 20 bytes at record + 0x18 are copied to the stack and passed by reference.
    0x294bd00: 'mov eax, dword ptr [r12 + 0x10]', 0x294bd05: 'mov dword ptr [rsp + 0x10], eax',
    0x294bd09: 'movups xmm0, xmmword ptr [r12]', 0x294bd0e: 'movaps xmmword ptr [rsp], xmm0',
    0x294bd12: 'mov rdi, rbx', 0x294bd15: 'mov rsi, r15', 0x294bd18: 'call 0x2a8ae60',
    # Accumulate: carry out of the 64-bit add selects the overflow path; stride is 0x40.
    0x294bd1d: 'mov r13, rax', 0x294bd20: 'add rax, r14', 0x294bd23: 'jb 0x294bd33',
    0x294bd25: 'add r12, 0x40', 0x294bd29: 'mov r14, rax', 0x294bd2c: 'dec rbp', 0x294bd2f: 'jne 0x294bd00',
    0x294bd31: 'jmp 0x294bd64',
    # Overflow: report (edi = 0, rsi = &Location), re-add, clamp to u64::MAX, continue.
    0x294bd33: 'xor edi, edi', 0x294bd35: 'lea rsi, [rip + 0x3af7f9c]',
    0x294bd3c: 'call qword ptr [rip + 0x3b99166]', 0x294bd42: 'add r13, r14',
    0x294bd45: 'mov rax, 0xffffffffffffffff', 0x294bd4c: 'cmovb r13, rax', 0x294bd50: 'mov rax, r13',
    0x294bd53: 'add r12, 0x40', 0x294bd57: 'mov r14, rax', 0x294bd5a: 'dec rbp', 0x294bd5d: 'jne 0x294bd00',
    0x294bd5f: 'jmp 0x294bd64',
}
STORES = {0x294bd05: (0x10, 4), 0x294bd0e: (0x0, 16)}  # only explicit memory writes: [rsp + off], bytes

# Argument set-up from the preceding call to 0x29dfea0 through the call site, plus the first use of
# the result. Every instruction between the preceding call and the site is listed.
CALLER_CONTEXT = {
    0x2c75f4f: {
        0x2c75f28: 'lea rdi, [rsp + 0x60]', 0x2c75f2d: 'xor esi, esi', 0x2c75f2f: 'call 0x29dfea0',
        0x2c75f34: 'mov rcx, qword ptr [rsp + 0x30]', 0x2c75f39: 'mov qword ptr [rsp + 0xa0], rcx',
        0x2c75f41: 'lea rdx, [rsp + 0xa0]', 0x2c75f49: 'mov rdi, r14', 0x2c75f4c: 'mov rsi, rax',
        0x2c75f4f: 'call 0x294bcd0', 0x2c75f54: 'cmp rax, 0x989680', 0x2c75f5a: 'jae 0x2c75fd6',
    },
    0x2c76e4d: {
        0x2c76e24: 'lea rdi, [rsp + 0x40]', 0x2c76e29: 'xor esi, esi', 0x2c76e2b: 'call 0x29dfea0',
        0x2c76e30: 'mov rcx, qword ptr [rsp + 0xe0]', 0x2c76e38: 'mov qword ptr [rsp + 0x70], rcx',
        0x2c76e3d: 'lea rdx, [rsp + 0x70]', 0x2c76e42: 'mov rdi, r13', 0x2c76e45: 'mov rbx, qword ptr [rsp + 0x18]',
        0x2c76e4a: 'mov rsi, rax', 0x2c76e4d: 'call 0x294bcd0', 0x2c76e52: 'mov r12, rax',
    },
}


class CheckError(Exception):
    pass


def require(condition, stage, message):
    if not condition:
        raise CheckError(f'[{stage}] {message}')


class Image:
    """The captured ELF as bytes plus the few indexes the checks need."""

    def __init__(self, data):
        self.data = data
        self.sections = sections(data)
        self.by_name = {s['name']: s for s in self.sections}

    def locate(self, va, size, stage):
        for s in self.sections:
            if s['type'] != 8 and s['flags'] & 2 and s['address'] <= va and va + size <= s['address'] + s['size']:
                return s['offset'] + va - s['address']
        raise CheckError(f'[{stage}] VA {va:#x}+{size} is outside every allocated file-backed section')

    def read(self, va, size, stage):
        offset = self.locate(va, size, stage)
        return bytes(self.data[offset:offset + size])

    def relocations(self):
        rela = self.by_name['.rela.dyn']
        blob = bytes(self.data[rela['offset']:rela['offset'] + rela['size']])
        return {slot: (info & 0xffffffff, addend)
                for slot, info, addend in struct.iter_unpack('<QQq', blob)}

    def rela_entry_offset(self, slot):
        rela = self.by_name['.rela.dyn']
        for index in range(rela['size'] // 24):
            offset = rela['offset'] + 24 * index
            if struct.unpack_from('<Q', self.data, offset)[0] == slot:
                return offset
        raise CheckError(f'no .rela.dyn entry for slot {slot:#x}')


def disassembler():
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    return md


def decode_window(image, start, end, stage):
    """Linear decode that must tile [start, end) exactly."""
    raw = image.read(start, end - start, stage)
    instructions = list(disassembler().disasm(raw, start))
    covered = instructions[-1].address + instructions[-1].size if instructions else start
    require(covered == end, stage, f'decode stops at {covered:#x}, expected {end:#x}')
    return instructions


def text_of(insn):
    return f'{insn.mnemonic} {insn.op_str}'.strip()


def rip_target(insn):
    match = re.search(r'\[rip ([+-]) (0x[0-9a-f]+)\]', insn.op_str)
    require(match, 'decode', f'{insn.address:#x} has no RIP-relative operand')
    displacement = int(match.group(2), 16) * (1 if match.group(1) == '+' else -1)
    return insn.address + insn.size + displacement


def fde_bounds(image):
    secs, header = unwind_index(bytes(image.data))
    _, fdes = eh_frame_records(bytes(image.data), secs)
    indexed = {(row['start'], row['fde']) for row in header}
    return {(row['start'], row['end']) for row in fdes if (row['start'], row['fde']) in indexed}


# ---- stages ---------------------------------------------------------------------------------

def stage_authenticate(image):
    digest = hashlib.sha256(image.data).hexdigest()
    require(digest == TARGET_SHA256, 'authenticate', f'target digest {digest}')
    return f'sha256 {digest}'


def stage_window(image):
    digest = hashlib.sha256(image.read(START, END - START, 'window')).hexdigest()
    require(digest == WINDOW_SHA256, 'window', f'window digest {digest}')
    return f'{END - START} bytes, sha256 {digest}'


def stage_fde(image):
    bounds = fde_bounds(image)
    for name, extent in (('function', (START, END)), ('callee', CALLEE), ('reporter', REPORTER),
                         *((f'caller {site:#x}', extent) for site, extent in CALLERS.items())):
        require(extent in bounds, 'fde', f'{name} extent {extent[0]:#x}..{extent[1]:#x} is not an indexed FDE')
    return f'{len(bounds)} indexed FDEs; function, callee, reporter and both callers are FDE extents'


def listing_rows(instructions):
    return [(f'{i.address:#x}', str(i.size), i.bytes.hex(), i.mnemonic, i.op_str) for i in instructions]


def stage_decode(image):
    instructions = decode_window(image, START, END, 'decode')
    require(len(instructions) == 54, 'decode', f'{len(instructions)} instructions, expected 54')
    return instructions


def stage_listing(instructions):
    expected = [tuple(line.split('\t')) for line in LISTING.read_text().splitlines()[1:]]
    require(listing_rows(instructions) == expected, 'listing', 'instructions.tsv differs from the live decode')
    return f'{len(expected)} rows match instructions.tsv'


def stage_control_flow(image, instructions):
    starts = {i.address for i in instructions}
    direct, indirect, returns = [], [], []
    for insn in instructions:
        if insn.mnemonic == 'call':
            if insn.op_str.startswith('0x'):
                direct.append((insn.address, int(insn.op_str, 16)))
            else:
                require(insn.op_str.startswith('qword ptr [rip '), 'control-flow', f'{insn.address:#x} unexpected call form')
                indirect.append((insn.address, rip_target(insn)))
        elif insn.mnemonic.startswith('j'):
            require(insn.op_str.startswith('0x'), 'control-flow', f'{insn.address:#x} indirect jump')
            target = int(insn.op_str, 16)
            require(target in starts, 'control-flow', f'{insn.address:#x} branches to {target:#x}, not an instruction in the window')
        elif insn.mnemonic == 'ret':
            returns.append(insn.address)
    shown = lambda pairs: [(hex(a), hex(t)) for a, t in pairs]  # noqa: E731
    require(direct == [(0x294bd18, CALLEE[0])], 'control-flow', f'direct calls {shown(direct)}')
    require(indirect == [(0x294bd3c, REPORTER_SLOT)], 'control-flow', f'indirect calls {shown(indirect)}')
    require(returns == [END - 1], 'control-flow', f'returns {[hex(a) for a in returns]}')
    return 'one direct call, one call through the reporter slot, one ret, every branch lands in the window'


def stage_facts(instructions):
    by_address = {i.address: text_of(i) for i in instructions}
    for address, expected in FACTS.items():
        require(by_address.get(address) == expected, 'facts', f'{address:#x}: {by_address.get(address)!r}, expected {expected!r}')
    pops = [by_address[a] for a in sorted(by_address) if a >= 0x294bd68]
    require(pops == ['pop rbx', 'pop r12', 'pop r13', 'pop r14', 'pop r15', 'pop rbp', 'ret'], 'facts', 'epilogue')
    return f'{len(FACTS)} pinned instructions plus the epilogue'


def stage_stores(instructions):
    found = {}
    for insn in instructions:
        for operand in insn.operands:
            if operand.type == X86_OP_MEM and operand.access & CS_AC_WRITE:
                require(insn.reg_name(operand.mem.base) == 'rsp' and not operand.mem.index, 'stores',
                        f'{insn.address:#x} writes outside the stack frame')
                found[insn.address] = (operand.mem.disp, operand.size)
    require(found == STORES, 'stores', f'explicit memory writes {found}')
    return 'explicit memory writes: dword [rsp+0x10] and xmmword [rsp] only (20 bytes of stack)'


def stage_relocations(image, instructions):
    by_address = {i.address: i for i in instructions}
    relocs = image.relocations()
    slot = rip_target(by_address[0x294bd3c])
    require(slot == REPORTER_SLOT, 'relocations', f'reporter slot {slot:#x}')
    found = relocs.get(slot)
    require(found == (8, REPORTER[0]), 'relocations',
            f'slot {slot:#x} relocation (type, addend) = {found and (found[0], hex(found[1]))}, expected (8, {REPORTER[0]:#x})')
    location = rip_target(by_address[0x294bd35])
    require(location == LOCATION[0], 'relocations', f'location record {location:#x}')
    _, length, line, column = struct.unpack('<QQII', image.read(location, 24, 'relocations'))
    kind_addend = relocs.get(location)
    require(kind_addend is not None and kind_addend[0] == 8, 'relocations', 'location path pointer has no RELATIVE entry')
    path = image.read(kind_addend[1], length, 'relocations').decode('ascii')
    require((path, line, column) == LOCATION[1:], 'relocations', f'location record says {(path, line, column)}')
    return f'slot {REPORTER_SLOT:#x} -> {REPORTER[0]:#x}; location {location:#x} = {path}:{line}:{column}'


def stage_callers(image):
    text = image.by_name['.text']
    code = bytes(image.data[text['offset']:text['offset'] + text['size']])
    base = text['address']
    candidates = []
    for opcode in (0xe8, 0xe9):
        pattern = bytes([opcode])
        i = code.find(pattern)
        while i != -1:
            if i + 5 <= len(code) and base + i + 5 + struct.unpack_from('<i', code, i + 1)[0] == START:
                candidates.append((base + i, opcode))
            i = code.find(pattern, i + 1)
    bounds = sorted(fde_bounds(image))
    verified = {}
    for site, opcode in candidates:
        extent = next(((s, e) for s, e in bounds if s <= site < e), None)
        require(extent is not None, 'callers', f'{site:#x} is outside every FDE')
        window = decode_window(image, extent[0], extent[1], 'callers')
        hit = next((i for i in window if i.address == site), None)
        require(hit is not None, 'callers', f'candidate {site:#x} is not an instruction boundary')
        require(text_of(hit) == f'{"call" if opcode == 0xe8 else "jmp"} {START:#x}', 'callers', f'{site:#x} decodes as {text_of(hit)}')
        verified[site] = (extent, window)
    require({s: e for s, (e, _) in verified.items()} == CALLERS, 'callers', f'direct callers {sorted(hex(s) for s in verified)}')
    require(all(opcode == 0xe8 for _, opcode in candidates), 'callers', 'unexpected tail jump to the function')
    relocs = image.relocations()
    require(not [s for s, (_, addend) in relocs.items() if addend == START], 'callers', 'function pointer slot references the function')
    lea = []
    i = code.find(b'\x8d')
    while i != -1:
        if 1 <= i and i + 5 <= len(code) and code[i - 1] in (0x48, 0x4c) and code[i + 1] & 0xc7 == 0x05 \
                and base + i - 1 + 7 + struct.unpack_from('<i', code, i + 2)[0] == START:
            lea.append(base + i - 1)
        i = code.find(b'\x8d', i + 1)
    require(not lea, 'callers', f'RIP-relative address-of sites {lea}')
    for site, (extent, window) in verified.items():
        by_address = {i.address: text_of(i) for i in window}
        context = CALLER_CONTEXT[site]
        first = min(context)
        between = sorted(a for a in by_address if first <= a <= site)
        require(between == sorted(a for a in context if a <= site), 'callers', f'{site:#x}: window of instructions differs')
        for address, expected in context.items():
            require(by_address.get(address) == expected, 'callers', f'{address:#x}: {by_address.get(address)!r}, expected {expected!r}')
    return f'direct call sites {", ".join(hex(s) for s in sorted(verified))}; no tail jump, pointer slot or address-of site'


def stage_objdump(image):
    tool = shutil.which('objdump')
    if not tool or 'GNU' not in subprocess.run([tool, '--version'], capture_output=True, text=True).stdout.splitlines()[0]:
        return None
    out = subprocess.run([tool, '-d', '-M', 'intel', f'--start-address={START:#x}', f'--stop-address={END:#x}', str(TARGET)],
                         capture_output=True, text=True, check=True).stdout
    rows = {}
    last = None
    for line in out.splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\t((?:[0-9a-f]{2} )+)\s*(?:\t(.*))?$', line)
        if not match:
            continue
        address, raw, mnemonic = int(match.group(1), 16), match.group(2).replace(' ', ''), match.group(3)
        if mnemonic is None and last is not None:
            rows[last] += raw
        else:
            rows[address] = raw
            last = address
    live = {i.address: i.bytes.hex() for i in decode_window(image, START, END, 'objdump')}
    require(rows == live, 'objdump', 'GNU objdump and Capstone disagree on instruction boundaries or bytes')
    return f'GNU objdump agrees on {len(rows)} instruction boundaries and bytes ({subprocess.run([tool, "--version"], capture_output=True, text=True).stdout.splitlines()[0]})'


# ---- corruption controls --------------------------------------------------------------------

def patch(image, va, new, old=None):
    offset = image.locate(va, len(new), 'control')
    if old is not None:
        assert bytes(image.data[offset:offset + len(old)]) == old, f'control precondition at {va:#x}'
    image.data[offset:offset + len(new)] = new


def control_jb_to_jae(image):
    patch(image, 0x294bd23, b'\x73', b'\x72')


def control_stride(image):
    patch(image, 0x294bd28, b'\x44', b'\x40')


def control_cmovb_to_cmovae(image):
    patch(image, 0x294bd4d, b'\x0f\x43', b'\x0f\x42')


def control_guard_inverted(image):
    patch(image, 0x294bce4, b'\x75', b'\x74')


def control_callee_displacement(image):
    patch(image, 0x294bd19, b'\x44', b'\x43')


def control_reporter_addend(image):
    offset = image.rela_entry_offset(REPORTER_SLOT) + 16
    image.data[offset] ^= 0x10


def control_location_line(image):
    patch(image, LOCATION[0] + 16, struct.pack('<I', 683), struct.pack('<I', 682))


def control_caller_displacement(image):
    patch(image, 0x2c75f50, b'\x00', None)


def control_padding_byte(image):
    patch(image, 0x294bcff, b'\x01', b'\x00')  # operand byte of a NOP: semantics unchanged, digest must still fail


CONTROLS = (  # (name, mutation, stage that must reject it)
    ('jb flipped to jae at 0x294bd23', control_jb_to_jae, 'facts'),
    ('record stride 0x40 changed to 0x44', control_stride, 'facts'),
    ('cmovb flipped to cmovae at 0x294bd4c', control_cmovb_to_cmovae, 'facts'),
    ('null-vector guard je flipped to jne', control_guard_inverted, 'facts'),
    ('callee call displacement off by one', control_callee_displacement, 'control-flow'),
    ('reporter slot relocation addend corrupted', control_reporter_addend, 'relocations'),
    ('source location line 682 changed to 683', control_location_line, 'relocations'),
    ('caller 0x2c75f4f displacement corrupted', control_caller_displacement, 'callers'),
    ('NOP operand byte changed (digest-only)', control_padding_byte, 'window'),
)


def structural(image):
    instructions = stage_decode(image)
    stage_control_flow(image, instructions)
    stage_facts(instructions)
    stage_stores(instructions)
    stage_relocations(image, instructions)
    return instructions


def run_control(original, name, mutate, expected):
    image = Image(bytearray(original))
    mutate(image)
    try:
        if expected == 'window':
            stage_window(image)
        elif expected == 'callers':
            stage_callers(image)
        else:
            structural(image)
    except CheckError as error:
        stage = str(error).split(']')[0].lstrip('[')
        require(stage == expected, 'controls', f'{name}: rejected by [{stage}], expected [{expected}]')
        return str(error)
    raise CheckError(f'[controls] {name}: corruption was NOT rejected')


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--json', action='store_true', help='print a machine-readable summary')
    parser.add_argument('--write-listing', action='store_true', help='regenerate instructions.tsv from the live decode')
    args = parser.parse_args()

    image = Image(TARGET.read_bytes())
    results = []

    def run(name, function, *arguments):
        outcome = function(*arguments)
        results.append((name, 'skipped' if outcome is None else 'ok', outcome if isinstance(outcome, str) else ''))
        return outcome

    run('authenticate', stage_authenticate, image)
    run('window', stage_window, image)
    run('fde', stage_fde, image)
    instructions = stage_decode(image)
    if args.write_listing:
        lines = ['va\tsize\tbytes\tmnemonic\toperands'] + ['\t'.join(row) for row in listing_rows(instructions)]
        LISTING.write_text('\n'.join(lines) + '\n')
    results.append(('decode', 'ok', f'{len(instructions)} instructions tile {START:#x}..{END:#x}'))
    run('listing', stage_listing, instructions)
    run('control-flow', stage_control_flow, image, instructions)
    run('facts', stage_facts, instructions)
    run('stores', stage_stores, instructions)
    run('relocations', stage_relocations, image, instructions)
    run('callers', stage_callers, image)
    run('objdump', stage_objdump, image)

    original = bytes(image.data)
    controls = [(name, expected, run_control(original, name, mutate, expected)) for name, mutate, expected in CONTROLS]

    if args.json:
        print(json.dumps({'target_sha256': TARGET_SHA256, 'checks': [dict(zip(('name', 'status', 'detail'), r)) for r in results],
                          'controls': [dict(zip(('name', 'rejected_by', 'message'), c)) for c in controls]}, indent=1))
    else:
        for name, status, detail in results:
            print(f'{status.upper():8} {name:13} {detail}')
        for name, expected, message in controls:
            print(f'REJECTED control: {name} -> {message}')
    skipped = [r[0] for r in results if r[1] == 'skipped']
    print(f'ALL CHECKS PASSED ({sum(r[1] == "ok" for r in results)} checks, {len(controls)} corruption controls rejected'
          + (f'; skipped: {", ".join(skipped)}' if skipped else '') + ')', file=sys.stderr if args.json else sys.stdout)


if __name__ == '__main__':
    try:
        main()
    except CheckError as error:
        print(f'FAILED {error}', file=sys.stderr)
        sys.exit(1)
