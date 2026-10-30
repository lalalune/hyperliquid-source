#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 twin-widen evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.

The two windows are [0x151f0a0, 0x151f0fe) and [0x151f100, 0x151f15e), 94
bytes each, each followed by two int3 padding bytes before the next FDE
start. The windows are instruction-identical except at three byte offsets:
the element-size immediate (4 vs 8), the shared-routine call displacement,
and the indirect-call displacement (both displacements differ only because
the call sites sit 0x60 bytes apart while their targets are identical).
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
W1_START, W1_END = 0x151f0a0, 0x151f0fe
W2_START, W2_END = 0x151f100, 0x151f15e
SHARED_START, SHARED_END = 0x151f160, 0x151f238
W1 = bytes.fromhex(
    '4156534883ec184889fb488b37488d04364883f80541be040000004c0f43f0488b57084889e741b8040000004c89f1e88c000000833c24017414488b442408488943084c89334883c4185b415ec3488b7c2408488b742410ff15baee2404')
W2 = bytes.fromhex(
    '4156534883ec184889fb488b37488d04364883f80541be040000004c0f43f0488b57084889e741b8080000004c89f1e82c000000833c24017414488b442408488943084c89334883c4185b415ec3488b7c2408488b742410ff155aee2404')
PADDING = b'\xcc' * 2
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE1 = bytes.fromhex('28000000604f0100248c82005e00000000420e10410e18440e3083038e0202430e18410e10420e08410e3000')
FDE2 = bytes.fromhex('280000008c4f0100588c82005e00000000420e10410e18440e3083038e0202430e18410e10420e08410e3000')
SHARED_FDE = bytes.fromhex('34000000b84f01008c8c8200d800000000420e10420e18420e20410e28410e3083058c048e038f0202c80e28410e20420e18420e10420e08')
SLOT = 0x576dfb8
SLOT_ADDEND = 0x1346068


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

    w1 = read(W1_START, W1_END - W1_START)
    w2 = read(W2_START, W2_END - W2_START)
    require(w1 == W1, 'First widen window changed')
    require(w2 == W2, 'Second widen window changed')
    require(len(w1) == len(w2) == 94, 'Window length changed')
    diffs = [(i, w1[i], w2[i]) for i in range(94) if w1[i] != w2[i]]
    require([d[0] for d in diffs] == [0x28, 0x30, 0x5a],
            'Twin-difference offsets changed')
    require((w1[0x28], w2[0x28]) == (4, 8), 'Element-size immediates changed')
    # Shared-routine call: e8 at window offset 0x2f, displacement at 0x30.
    require(w1[0x2f] == 0xe8 and w2[0x2f] == 0xe8, 'Shared call opcode changed')
    for start, body in ((W1_START, w1), (W2_START, w2)):
        disp = struct.unpack_from('<i', body, 0x30)[0]
        require(start + 0x2f + 5 + disp == SHARED_START,
                'Shared call displacement changed')
    # Indirect error-arm call: ff 15 at window offset 0x58, displacement 0x5a.
    require(w1[0x58:0x5a] == b'\xff\x15' and w2[0x58:0x5a] == b'\xff\x15',
            'Indirect call opcode changed')
    for start, body in ((W1_START, w1), (W2_START, w2)):
        disp = struct.unpack_from('<i', body, 0x5a)[0]
        require(start + 0x58 + 6 + disp == SLOT, 'Indirect call slot changed')
    # Flag branch: je at window offset 0x38, displacement 0x39, to the error arm.
    for start, body in ((W1_START, w1), (W2_START, w2)):
        require(body[0x38] == 0x74, 'Flag branch opcode changed')
        disp = struct.unpack_from('<b', body, 0x39)[0]
        require(start + 0x38 + 2 + disp == start + 0x4e, 'Flag branch target changed')
    # Clamp immediates parsed from the retained bytes: doubled length in rax,
    # compared against 5, floor value 4. Count = rax if rax >= 5 else 4.
    for body in (w1, w2):
        require(body[0x0d:0x11] == b'\x48\x8d\x04\x36', 'Doubling lea changed')
        require(body[0x14] == 5, 'Clamp compare changed')
        require(struct.unpack_from('<I', body, 0x17)[0] == 4, 'Clamp floor changed')
        require(body[0x1d] == 0x43, 'Conditional move changed')

    def count_for(length):
        doubled = 2 * length
        return doubled if doubled >= 5 else 4

    require([count_for(n) for n in (0, 1, 2, 3, 4)] == [4, 4, 4, 6, 8],
            'Clamp boundary values changed')
    # Two int3 padding bytes follow each window before the next FDE start.
    require(read(W1_END, 2) == PADDING, 'First window padding changed')
    require(read(W2_END, 2) == PADDING, 'Second window padding changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'], len(CIE)) == CIE, 'CIE changed')
    for offset, raw, start, end in [(0x14f5c, FDE1, W1_START, W1_END),
                                    (0x14f88, FDE2, W2_START, W2_END),
                                    (0x14fb4, SHARED_FDE, SHARED_START, SHARED_END)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        # All three retained records use the CIE-confirmed pcrel/sdata4 initial PC.
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
    require(rels.get(SLOT) == (8, SLOT_ADDEND), 'Error-arm slot relocation changed')
    require(read(SLOT, 8) == b'\0' * 8, 'Unexpected pre-relocation pointer')

    return dict(target_release='94', target_sha256=SHA256,
                coordinate_system='ELF virtual addresses, no runtime rebase',
                windows=[
                    dict(start_va=hex(W1_START), fde_end_va_exclusive=hex(W1_END),
                         fde_bytes=94, fde_body_sha256=hashlib.sha256(w1).hexdigest(),
                         fde_section_offset='0x14f5c', element_size=4),
                    dict(start_va=hex(W2_START), fde_end_va_exclusive=hex(W2_END),
                         fde_bytes=94, fde_body_sha256=hashlib.sha256(w2).hexdigest(),
                         fde_section_offset='0x14f88', element_size=8)],
                shared_routine=dict(start_va=hex(SHARED_START),
                                    fde_end_va_exclusive=hex(SHARED_END),
                                    fde_section_offset='0x14fb4',
                                    body_decoded=False),
                behavior=dict(
                    input_fields='first field at 0(rdi) is the length, second field at 8(rdi) is passed through in rdx',
                    doubled_length='lea (rsi, rsi, 1) doubles the length field',
                    clamp='count = doubled length if doubled length >= 5 else 4',
                    clamp_boundaries={'0': 4, '1': 4, '2': 4, '3': 6, '4': 8},
                    call_arguments='rdi = stack out-slot, rsi = original length, rdx = second input field, rcx = count, r8d = element size',
                    flag_arm='out-slot flag == 1 takes the indirect-call arm, else out-slot pointer is stored at 8(rbx) and count at (rbx)',
                    padding='two int3 bytes follow each window before the next FDE start'),
                twin_difference=dict(
                    differing_byte_offsets=['0x28', '0x30', '0x5a'],
                    element_size_immediates=[4, 8],
                    shared_call_target='0x151f160',
                    indirect_call_slot='0x576dfb8'),
                error_arm_slot=dict(slot=hex(SLOT), relocation='R_X86_64_RELATIVE',
                                    addend=hex(SLOT_ADDEND),
                                    stored_file_bytes='zero',
                                    runtime_target_named=False),
                claim='two near-identical windows differing only in element size',
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
        print('Foundation twin-widen evidence reproduces exactly.')
    else:
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
