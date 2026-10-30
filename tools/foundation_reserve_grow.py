#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 reserve/grow evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.

The window is [0x1520ce0, 0x1520d41), 97 bytes, followed by fifteen int3
padding bytes before the next FDE start at 0x1520d50. The fast path copies
the requested amount through the platform memcpy binding into the buffer
past its current length and advances the length field; the slow arm calls
the unnamed routine at 0x1564e60 and then jumps back into the fast path
without re-checking capacity. No stdlib type or source-level function name
is claimed for this window.
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
START, END = 0x1520ce0, 0x1520d41
WINDOW = bytes.fromhex(
    '41574156534889fb488b074c8b77104c29f04839c27722488b7b084c01f74989d7ff15d9d224044d01fe4c89731031c04c89fa5b415e415fc3b90100000041b8010000004889df4989f74c89f64989d6e82b4104004c89fe4c89f24c8b7310ebb6')
PADDING = b'\xcc' * 15
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('28000000f8530100cca382006100000000420e10420e18410e2083048e038f026f0e18420e10420e08410e20')
CALLEE_FDE = bytes.fromhex('2800000068800100dcb886008e00000000420e10410e18440e3083038e0202730e18410e10420e08410e3000')
CALLEE_START, CALLEE_END = 0x1564e60, 0x1564eee
MEMCPY_SLOT = 0x576dfe0
MEMCPY_INFO = 0x600000006


def require(condition, message):
    if not condition:
        raise ValueError(message)


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

    w = read(START, END - START)
    require(w == WINDOW, 'Reserve/grow window changed')
    require(len(w) == 97, 'Window length changed')
    # Entry: push r15, push r14, push rbx; rbx = rdi.
    require(w[0:5] == b'\x41\x57\x41\x56\x53', 'Entry pushes changed')
    require(w[5:8] == b'\x48\x89\xfb', 'Object register move changed')
    # Fields: rax = [rdi], r14 = [rdi + 0x10]; rax -= r14 (remaining).
    require(w[8:11] == b'\x48\x8b\x07', 'Capacity field load changed')
    require(w[11:15] == b'\x4c\x8b\x77\x10', 'Length field load changed')
    require(w[15:18] == b'\x4c\x29\xf0', 'Remaining subtraction changed')
    # cmp %rax,%rdx; ja slow arm. Taken exactly when requested > remaining.
    require(w[18:21] == b'\x48\x39\xc2', 'Capacity compare changed')
    require(w[21] == 0x77, 'Slow-arm branch opcode changed')
    require(START + 0x15 + 2 + w[22] == START + 0x39, 'Slow-arm branch target changed')
    # Fast path: rdi = [rbx + 8] + r14; r15 = rdx; call *memcpy slot.
    require(w[0x17:0x1b] == b'\x48\x8b\x7b\x08', 'Base field load changed')
    require(w[0x1b:0x1e] == b'\x4c\x01\xf7', 'Destination advance changed')
    require(w[0x1e:0x21] == b'\x49\x89\xd7', 'Requested amount save changed')
    require(w[0x21:0x23] == b'\xff\x15', 'Memcpy indirect call opcode changed')
    disp = struct.unpack_from('<i', w, 0x23)[0]
    require(START + 0x21 + 6 + disp == MEMCPY_SLOT, 'Memcpy call slot changed')
    # Length advance, zero return, requested amount restored to rdx, pops, ret.
    require(w[0x27:0x2a] == b'\x4d\x01\xfe', 'Length advance changed')
    require(w[0x2a:0x2e] == b'\x4c\x89\x73\x10', 'Length store changed')
    require(w[0x2e:0x30] == b'\x31\xc0', 'Zero return changed')
    require(w[0x30:0x33] == b'\x4c\x89\xfa', 'Return amount restore changed')
    require(w[0x33:0x39] == b'\x5b\x41\x5e\x41\x5f\xc3', 'Epilogue changed')
    # Slow arm: ecx = 1, r8d = 1, argument shuffles, direct call, restores.
    require(w[0x39:0x3e] == b'\xb9\x01\x00\x00\x00', 'Slow-arm ecx immediate changed')
    require(w[0x3e:0x44] == b'\x41\xb8\x01\x00\x00\x00', 'Slow-arm r8d immediate changed')
    require(w[0x44:0x47] == b'\x48\x89\xdf', 'Slow-arm object move changed')
    require(w[0x47:0x4a] == b'\x49\x89\xf7', 'Slow-arm source save changed')
    require(w[0x4a:0x4d] == b'\x4c\x89\xf6', 'Slow-arm length argument changed')
    require(w[0x4d:0x50] == b'\x49\x89\xd6', 'Slow-arm amount save changed')
    require(w[0x50] == 0xe8, 'Grow call opcode changed')
    disp = struct.unpack_from('<i', w, 0x51)[0]
    require(START + 0x50 + 5 + disp == CALLEE_START, 'Grow call target changed')
    require(w[0x55:0x58] == b'\x4c\x89\xfe', 'Slow-arm source restore changed')
    require(w[0x58:0x5b] == b'\x4c\x89\xf2', 'Slow-arm amount restore changed')
    require(w[0x5b:0x5f] == b'\x4c\x8b\x73\x10', 'Slow-arm length reload changed')
    require(w[0x5f] == 0xeb, 'Retry jump opcode changed')
    require(START + 0x5f + 2 + struct.unpack_from('<b', w, 0x60)[0] == START + 0x17,
            'Retry jump target changed')
    # Unsigned capacity arithmetic: fast path exactly when requested <= remaining.
    def takes_slow_arm(capacity, length, requested):
        remaining = (capacity - length) % (1 << 64)
        return requested > remaining
    require([takes_slow_arm(10, 4, n) for n in (5, 6, 7)] == [False, False, True],
            'Capacity boundary values changed')
    require(takes_slow_arm(0, 0, 0) is False, 'Zero-request boundary changed')
    require(takes_slow_arm(0, 0, 1) is True, 'Empty-buffer boundary changed')
    # Fifteen int3 padding bytes follow the window before the next FDE start.
    require(read(END, 15) == PADDING, 'Window padding changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'], len(CIE)) == CIE, 'CIE changed')
    for offset, raw, start, end in [(0x153f4, FDE, START, END),
                                    (0x18064, CALLEE_FDE, CALLEE_START, CALLEE_END)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
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
    require(rels.get(MEMCPY_SLOT) == (MEMCPY_INFO, 0), 'Memcpy slot relocation changed')
    require(read(MEMCPY_SLOT, 8) == b'\0' * 8, 'Unexpected pre-relocation pointer')

    return dict(target_release='94', target_sha256=SHA256,
                coordinate_system='ELF virtual addresses, no runtime rebase',
                windows=[
                    dict(start_va=hex(START), fde_end_va_exclusive=hex(END),
                         fde_bytes=97, fde_body_sha256=hashlib.sha256(w).hexdigest(),
                         fde_section_offset='0x153f4')],
                memcpy_slot=dict(slot=hex(MEMCPY_SLOT), relocation='R_X86_64_GLOB_DAT',
                                 symbol_index=6, symbol='memcpy@GLIBC_2.14',
                                 addend=0, stored_file_bytes='zero'),
                grow_callee=dict(start_va=hex(CALLEE_START),
                                 fde_end_va_exclusive=hex(CALLEE_END),
                                 fde_section_offset='0x18064',
                                 body_decoded=False, runtime_target_named=False),
                behavior=dict(
                    input_fields='capacity field at 0(rdi), base pointer at 8(rdi), length field at 0x10(rdi)',
                    remaining='remaining = capacity - length, unsigned 64-bit',
                    gate='slow arm taken exactly when requested (rdx) > remaining, unsigned',
                    fast_path='memcpy(base + length, entry rsi, requested); length += requested; return 0 with rdx restored to requested',
                    slow_arm='call 0x1564e60 with (object, old length, requested, rcx = 1, r8d = 1); reload length; jump back to the fast path without re-checking capacity',
                    capacity_boundaries={'10/4/5': 'fast', '10/4/6': 'fast', '10/4/7': 'slow', '0/0/0': 'fast', '0/0/1': 'slow'},
                    padding='fifteen int3 bytes follow the window before the next FDE start'),
                claim='one append window: memcpy past the current length when capacity allows, otherwise an unnamed grow call and a retry',
                inferred_label=None,
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
        print('Foundation reserve-grow evidence reproduces exactly.')
    else:
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
