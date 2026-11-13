#!/usr/bin/env python3
"""Bind the node #115 l1 hash input and its callers (57th stage).

Stage 56 found that the hardfork_hashes message carries {height, l1 hash},
computed by the timed BLAKE3 function 0x457cf60 behind the blocking helper
0x452aab0. This tool binds:

1. the l1 hash shape: 0x457cf60 takes an argument record {ptr, len,
   &digest32, &height}; it hashes the slice (ptr, len) with BLAKE3, then
   hashes the 32-byte result followed by the 32 bytes at *digest32 with a
   fresh BLAKE3, and writes that 32-byte value to its output. So
   l1 = BLAKE3(BLAKE3(bytes) || digest32);
2. the helper 0x452aab0 passes its rdi/rsi straight to 0x457cf60 at both
   direct call sites (0x452ac61, 0x452ad4f);
3. the census: 0x457cf60 has two direct calls, both in 0x452aab0;
   0x452aab0 has seven direct calls, each passing a 4-word record;
4. the hardfork_hashes worker 0x5484670: bytes = the Vec (cap, ptr, len)
   returned by 0x4e48ee0 (the 'serialized abci state' path of #6037),
   digest32 = the root digest returned through slot 0x64e7820
   (0x41c5140, #6030), height = box +0x28.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses.
"""
import argparse
import json
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import direct_calls, fixed, read_va, rip_target

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-l1-hash-input-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

L1 = 0x457cf60
HELPER = 0x452aab0
WORKER = 0x5484670
UPDATE_SLOT, FINALIZE_SLOT, ROOT_SLOT = 0x64df510, 0x64df518, 0x64e7820
IV = 0x457ae0
LOG = (0x431bda, b'\x12computed l1 hash: ')

FIXED = {
    # l1 hash: argument record in r14, output in rbx
    0x457cf71: '4989f6',                # mov r14, rsi
    0x457cf74: '4889fb',                # mov rbx, rdi
    0x457cf8a: '4d8b3e',                # mov r15, [r14]          (ptr)
    0x457cf8d: '4d8b6e08',              # mov r13, [r14+8]        (len)
    0x457d03e: '4c89e7',                # mov rdi, r12            (hasher)
    0x457d041: '4c89fe',                # mov rsi, r15
    0x457d044: '4c89ea',                # mov rdx, r13
    0x457d047: 'ffd5',                  # call rbp                (update bytes)
    0x457d050: '488dbc2430010000',      # lea rdi, [rsp+0x130]
    0x457d05b: '41ffd7',                # call r15                (finalize -> H1)
    0x457d066: '498b4610',              # mov rax, [r14+0x10]     (&digest32)
    0x457d06a: '0f1000',                # movups xmm0, [rax]
    0x457d123: '0f10842430010000',      # movups xmm0, [rsp+0x130] (H1)
    0x457d14a: 'ba20000000',            # mov edx, 0x20
    0x457d155: 'ffd5',                  # call rbp                (update H1)
    0x457d157: '0f10842450010000',      # movups xmm0, [rsp+0x150] (digest32)
    0x457d171: 'ba20000000',            # mov edx, 0x20
    0x457d17c: 'ffd5',                  # call rbp                (update digest32)
    0x457d186: '41ffd7',                # call r15                (finalize)
    0x457d195: '660f114b10',            # movupd [rbx+0x10], xmm1
    0x457d19a: '660f1103',              # movupd [rbx], xmm0
    # helper: rdi/rsi passed through
    0x452ac5b: '4889df',                # mov rdi, rbx
    0x452ac5e: '4c89fe',                # mov rsi, r15
    0x452ad49: '4889df',
    0x452ad4c: '4c89fe',
    # worker record
    0x5484684: '488b1e',                # mov rbx, [rsi]          (box)
    0x5484687: '4c8b7b28',              # mov r15, [rbx+0x28]     (height)
    0x54846ad: '4c8b742420',            # mov r14, [rsp+0x20]     (Vec ptr)
    0x54846b2: '4c8b642428',            # mov r12, [rsp+0x28]     (Vec len)
    0x548475b: '0f10842480000000',      # movups xmm0, [rsp+0x80] (root digest)
    0x5484770: '0f29442460',            # movaps [rsp+0x60], xmm0
    0x5484775: '4c897c2458',            # mov [rsp+0x58], r15
    0x548477a: '4c89742418',            # record +0x0 = ptr
    0x548477f: '4c89642420',            # record +0x8 = len
    0x5484784: '488d442460',            # lea rax, [rsp+0x60]
    0x5484789: '4889442428',            # record +0x10 = &digest32
    0x548478e: '488d442458',            # lea rax, [rsp+0x58]
    0x5484793: '4889442430',            # record +0x18 = &height
    0x54847a5: 'ba01000000',            # mov edx, 1
}
REFERENCES = (
    (0x457cfae, b'\x0f\x10\x15', 7, IV),           # movups xmm2, IV
    (0x457d09e, b'\x0f\x10\x05', 7, IV),
    (0x457d02f, b'\x48\x8b\x2d', 7, UPDATE_SLOT),
    (0x457d049, b'\x4c\x8b\x3d', 7, FINALIZE_SLOT),
    (0x457d313, b'\x48\x8d\x05', 7, LOG[0]),
    (0x54846f7, b'\xff\x15', 6, ROOT_SLOT),
    (0x54846a3, b'\xe8', 5, 0x4e48ee0),
    (0x54847aa, b'\xe8', 5, HELPER),
)
CALL_SITES = {
    # site: (enclosing FDE start, note)
    0x2ad8dc1: (0x2ad7140, 'record at rsp+0x350'),
    0x2cae5c8: (0x2cad9b0, 'record at rsp+0x40'),
    0x2d26391: (0x2d25620, 'record at rsp'),
    0x54847aa: (0x5484670, 'hardfork_hashes worker: serialised state, root digest, height'),
    0x5a080b9: (0x5a07ec0, 'layout-A step; digest from 0x548dad0 at rsp+0x130'),
    0x5a08919: (0x5a08720, 'layout-B step'),
    0x5a6812a: (0x5a64aa0, 'record at rsp+0x370'),
}


def frame_start(fdes, va):
    hits = [f['start'] for f in fdes if f['start'] <= va < f['end']]
    if len(hits) != 1:
        raise ValueError(f'{va:#x} has no unique FDE')
    return hits[0]


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    if read_va(data, LOG[0], len(LOG[1])) != LOG[1]:
        raise ValueError('log template changed')
    l1_calls = direct_calls(data, L1)
    helper_calls = direct_calls(data, HELPER)
    if l1_calls != [0x452ac61, 0x452ad4f]:
        raise ValueError('l1 hash call census changed')
    if helper_calls != sorted(CALL_SITES):
        raise ValueError('helper call census changed')
    sites = []
    for site, (start, note) in CALL_SITES.items():
        if frame_start(fdes, site) != start:
            raise ValueError(f'enclosing function of {site:#x} changed')
        if read_va(data, site - 5, 5) != bytes.fromhex('ba01000000'):
            raise ValueError(f'blocking flag at {site:#x} changed')
        sites.append({'site': hex(site), 'function': hex(start), 'edx': 1, 'note': note})
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'l1_hash': {
            'fn': hex(L1),
            'argument_record': '{+0x0 ptr, +0x8 len, +0x10 &digest32, +0x18 &height}',
            'formula': 'BLAKE3(BLAKE3(bytes[ptr..ptr+len]) || digest32)',
            'hasher_iv': hex(IV),
            'update_slot': hex(UPDATE_SLOT),
            'finalize_slot': hex(FINALIZE_SLOT),
            'log_template': hex(LOG[0]) + ' "computed l1 hash: "',
            'direct_calls': [hex(v) for v in l1_calls],
        },
        'helper': {'fn': hex(HELPER), 'passes_rdi_rsi': True, 'direct_calls': len(helper_calls)},
        'call_sites': sites,
        'worker': {
            'fn': hex(WORKER),
            'bytes': 'Vec (cap, ptr, len) from 0x4e48ee0 at rsp+0x18..+0x30',
            'digest32': 'root digest from slot %s (0x41c5140) at rsp+0x80' % hex(ROOT_SLOT),
            'height': 'box +0x28',
        },
        'gates_changed': False,
    }


def render(result):
    return (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()


def generate(binary=TARGET, output=PACKET):
    identity = manifest_item(ROOT, RELATIVE)
    check(binary, identity)
    if identity['sha256'] != SHA256:
        raise ValueError('pinned node #115 digest changed')
    data = binary.read_bytes()
    _, fdes, _ = fde_extents(data)
    result = bind(data, fdes)
    output.mkdir(parents=True, exist_ok=True)
    (output / 'evidence.json').write_bytes(render(result))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=PACKET)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args(argv)
    expected = (PACKET / 'evidence.json').read_bytes() if args.check else None
    result = generate(output=args.out)
    if args.check and (args.out / 'evidence.json').read_bytes() != expected:
        raise SystemExit('evidence.json does not match the committed packet')
    print(f"l1_calls={len(result['l1_hash']['direct_calls'])} helper_calls={result['helper']['direct_calls']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
