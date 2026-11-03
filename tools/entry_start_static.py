#!/usr/bin/env python3
"""RE-001: node115 program entry point `_start` and its Rust `main` handoff, static only.

Static byte-anchored reconstruction of the authenticated node #115 entry chain:
the ELF entry `_start`, its glibc `__libc_start_main` call, and the Rust
`main` shim that tail-calls `std::rt::lang_start_internal`. No captured code is
executed; only file-backed bytes, RIP displacements and dynamic relocations are
read. Boundaries come from the authenticated FDE index, not inferred sizes.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
from artifacts import ROOT
from elf_index import sections
from fde_extents import fde_extents

TARGET = ROOT / 'artifacts/node/115/hl-node'
PACKET = ROOT / 'research/work-items/RE-001-node115-entry-start'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SIZE = 105896032

# Authenticated FDE-bounded entry function and the Rust main shim it names.
START = (0x1419300, 0x1419326)
START_SHA = 'cf432d50b96a11a67b03f671fe51599dd44a6b9c5a009eefba514c487d9e23bd'
MAIN = (0x2cef8f0, 0x2cef917)
MAIN_SHA = 'c0621248d6ec3fd7ae1ee2df6b09bdd79541219362b313e5567717eb8f59a5c9'

# Exact opcode bytes at each instruction boundary. A single changed byte in any
# anchored row changes the extracted relation and is rejected before output.
START_ANCHORS = [
    (0x1419300, 'f30f1efa'),    # endbr64
    (0x1419304, '31ed'),        # xor ebp,ebp
    (0x1419306, '4989d1'),      # mov r9,rdx            (r9 = rtld_fini)
    (0x1419309, '5e'),          # pop rsi               (rsi = argc)
    (0x141930a, '4889e2'),      # mov rdx,rsp           (rdx = argv)
    (0x141930d, '4883e4f0'),    # and rsp,-16
    (0x1419311, '50'),          # push rax
    (0x1419312, '54'),          # push rsp              (stack_end on stack)
    (0x1419313, '4531c0'),      # xor r8d,r8d           (r8 = fini = NULL)
    (0x1419316, '31c9'),        # xor ecx,ecx           (rcx = init = NULL)
    (0x1419318, '488d3d'),      # lea rdi,[rip+disp]    (rdi = main)
    (0x141931f, 'ff15'),        # call [rip+disp]       (__libc_start_main)
    (0x1419325, 'f4'),          # hlt
]
MAIN_ANCHORS = [
    (0x2cef8f0, '50'),          # push rax              (align + slot for &main)
    (0x2cef8f1, '4889f1'),      # mov rcx,rsi           (rcx = argv)
    (0x2cef8f4, '4863d7'),      # movsxd rdx,edi        (rdx = argc, sign-extended)
    (0x2cef8f7, '488d05'),      # lea rax,[rip+disp]    (rax = user main fn)
    (0x2cef8fe, '48890424'),    # mov [rsp],rax         (store fn ptr = &dyn Fn data)
    (0x2cef902, '488d35'),      # lea rsi,[rip+disp]    (rsi = &dyn Fn vtable)
    (0x2cef909, '4889e7'),      # mov rdi,rsp           (rdi = &dyn Fn data ptr)
    (0x2cef90c, '4531c0'),      # xor r8d,r8d           (r8 = sigpipe = 0)
    (0x2cef90f, 'ff15'),        # call [rip+disp]       (lang_start_internal)
    (0x2cef915, '59'),          # pop rcx
    (0x2cef916, 'c3'),          # ret                   (returns i32 exit code)
]

# Expected resolved RIP targets: (anchor VA, opcode length) -> resolved VA.
# Each anchor encodes a 4-byte signed displacement after its opcode; the target
# is the instruction's end VA plus that displacement.
START_RIP = {0x1419318: ('main', 0x2cef8f0), 0x141931f: ('libc_start_main_got', 0x64df458)}
MAIN_RIP = {0x2cef8f7: ('user_main', 0x2cd8370),
            0x2cef902: ('dyn_fn_vtable', 0x6440b48),
            0x2cef90f: ('lang_start_internal_got', 0x64e6c30)}

GLOB_DAT = 6
RELATIVE = 8
# __libc_start_main is an undefined dynamic symbol bound through a GLOB_DAT slot;
# lang_start_internal is an internal function bound through a RELATIVE slot.
LIBC_SLOT = 0x64df458
LANG_SLOT = 0x64e6c30
LANG_START_INTERNAL = 0x5c99970


def read(data, va, n):
    matches = [s for s in sections(data)
               if s['type'] != 8 and s['address'] <= va and va + n <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('expected unique file-backed mapping')
    s = matches[0]
    off = s['offset'] + va - s['address']
    return off, bytes(data[off:off + n])


def rip_target(data, site, opcode_len):
    """Resolve a RIP-relative displacement: end-of-instruction VA + signed disp32."""
    end = site + opcode_len + 4
    disp = struct.unpack('<i', read(data, site + opcode_len, 4)[1])[0]
    return end + disp


def anchors_ok(data, anchors):
    for site, raw in anchors:
        b = bytes.fromhex(raw)
        if read(data, site, len(b))[1] != b:
            raise ValueError(f'entry opcode changed at {site:#x}')


def relocations(data):
    s = next(s for s in sections(data) if s['name'] == '.rela.dyn')
    return {o: (i, v) for o, i, v in struct.iter_unpack('<QQq', data[s['offset']:s['offset'] + s['size']])}


def dynsym_name(data, index):
    syms = next(s for s in sections(data) if s['name'] == '.dynsym')
    strs = next(s for s in sections(data) if s['name'] == '.dynstr')
    name_off = struct.unpack_from('<I', data, syms['offset'] + index * 24)[0]
    base = strs['offset'] + name_off
    end = data.find(b'\0', base)
    return data[base:end].decode('ascii')


def analyze(data):
    # The ELF entry VA must name _start; it is also what loaders transfer to.
    entry = struct.unpack_from('<Q', data, 24)[0]
    if entry != START[0]:
        raise ValueError('ELF e_entry is not the mapped _start')

    anchors_ok(data, START_ANCHORS)
    anchors_ok(data, MAIN_ANCHORS)

    # RIP targets resolve to the expected function/slot addresses.
    for site, (name, expected) in START_RIP.items():
        opcode_len = 3 if name == 'main' else 2  # lea rdi vs call [rip]
        if rip_target(data, site, opcode_len) != expected:
            raise ValueError(f'_start RIP target {name} changed')
    for site, (name, expected) in MAIN_RIP.items():
        opcode_len = 2 if name == 'lang_start_internal_got' else 3
        if rip_target(data, site, opcode_len) != expected:
            raise ValueError(f'main RIP target {name} changed')

    # __libc_start_main binds through a GLOB_DAT slot to the versioned dynamic
    # symbol; lang_start_internal binds through a RELATIVE slot to its body.
    rels = relocations(data)
    libc = rels.get(LIBC_SLOT)
    if libc is None or libc[0] & 0xffffffff != GLOB_DAT or libc[1] != 0:
        raise ValueError('libc_start_main relocation changed')
    if dynsym_name(data, libc[0] >> 32) != '__libc_start_main':
        raise ValueError('libc_start_main dynamic symbol changed')
    lang = rels.get(LANG_SLOT)
    if lang is None or lang[0] != RELATIVE or lang[1] != LANG_START_INTERNAL:
        raise ValueError('lang_start_internal relocation changed')

    # Boundaries are authenticated by the FDE index, not inferred sizes.
    _, fdes, _ = fde_extents(data)
    frames = {(f['start'], f['end']) for f in fdes}
    if START not in frames:
        raise ValueError('_start FDE extent changed')

    owners = []
    for (a, b), expected_sha in ((START, START_SHA), (MAIN, MAIN_SHA)):
        off, body = read(data, a, b - a)
        got = hashlib.sha256(body).hexdigest()
        if got != expected_sha:
            raise ValueError('entry instruction bytes changed')
        owners.append({'start': hex(a), 'end': hex(b), 'bytes': b - a,
                       'file_offset': hex(off), 'sha256': got,
                       'has_fde': (a, b) in frames})

    return {
        'target_sha256': SHA,
        'entry_va': hex(entry),
        'owners': owners,
        'start_handoff': {
            'callee': '__libc_start_main@GLIBC_2.34',
            'callee_got_slot': hex(LIBC_SLOT),
            'relocation': 'R_X86_64_GLOB_DAT',
            'arguments': {
                'rdi_main': hex(START_RIP[0x1419318][1]),
                'rsi_argc': 'popped from stack at 0x1419309',
                'rdx_argv': 'rsp after argc pop (0x141930a)',
                'rcx_init': 0,
                'r8_fini': 0,
                'r9_rtld_fini': 'entry rdx (0x1419306)',
                'stack_end': 'push rsp at 0x1419312',
            },
        },
        'main_shim': {
            'role': 'Rust std::rt::lang_start lowering of fn main',
            'callee': 'std::rt::lang_start_internal',
            'callee_got_slot': hex(LANG_SLOT),
            'relocation': 'R_X86_64_RELATIVE',
            'callee_body': hex(LANG_START_INTERNAL),
            'arguments': {
                'main_dyn_fn_data': hex(MAIN_RIP[0x2cef8f7][1]),
                'main_dyn_fn_vtable': hex(MAIN_RIP[0x2cef902][1]),
                'argc_rdx': 'movsxd edi (0x2cef8f4)',
                'argv_rcx': 'mov rsi (0x2cef8f1)',
                'sigpipe_r8': 0,
            },
            'returns': 'i32 exit code in eax',
        },
        'captured_code_executed': False,
        'limits': ('Entry and main-shim control/argument relation only. The glibc '
                   '__libc_start_main body, lang_start_internal body, the user main at '
                   '0x2cd8370, runtime side effects and any Rust reconstruction gate '
                   'remain unproved. No captured code is executed.'),
    }


def generate(binary, output):
    data = binary.read_bytes()
    if len(data) != SIZE or hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('expected pinned node115')
    report = analyze(data)
    output.mkdir(parents=True, exist_ok=True)
    frame_lines = []
    with tempfile.TemporaryDirectory() as directory:
        snapshot = Path(directory) / 'node115.elf'
        snapshot.write_bytes(data)
        frames = subprocess.check_output(['readelf', '-wf', str(snapshot)], text=True)
        for a, b in (START, MAIN):
            rows = [l for l in frames.splitlines() if f'pc={a:016x}..{b:016x}' in l]
            frame_lines.extend(rows)  # MAIN may have no FDE; that is recorded, not required.
            asm = subprocess.check_output(
                ['objdump', '-d', '-M', 'intel', '--insn-width=16',
                 f'--start-address={a:#x}', f'--stop-address={b:#x}', str(snapshot)], text=True)
            (output / f'{a:x}.objdump.txt').write_bytes(
                asm.replace(str(snapshot), '<authenticated-node115>').encode('utf-8'))
        raw = subprocess.check_output(['readelf', '-rW', str(snapshot)], text=True)
        rows = [l for l in raw.splitlines()
                if l.startswith(f'{LIBC_SLOT:016x} ') or l.startswith(f'{LANG_SLOT:016x} ')]
        if len(rows) != 2:
            raise ValueError('native entry relocation disagreement')
        (output / 'selected-relocations.txt').write_bytes(('\n'.join(rows) + '\n').encode('utf-8'))
    (output / 'frames.txt').write_bytes(('\n'.join(frame_lines) + '\n').encode('utf-8'))
    (output / 'records.json').write_bytes((json.dumps(report, indent=2) + '\n').encode('utf-8'))
    return report


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--binary', type=Path, default=TARGET)
    ap.add_argument('--output', type=Path, default=ROOT / 'work/entry-start115')
    args = ap.parse_args()
    r = generate(args.binary, args.output)
    print(json.dumps({'functions': len(r['owners']),
                      'bytes': sum(x['bytes'] for x in r['owners']), 'executed': False}))
