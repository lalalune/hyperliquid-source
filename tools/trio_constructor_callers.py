#!/usr/bin/env python3
"""RE-004: trio-constructor callers in node #94 (static, no execution).

The same-callee trio of #166 (callers 0x4e6fd50/0x4e856f0/0x4e6bcb0 plus the
double-gate 0x4e852a0) shares three 501-byte constructors.  This tool verifies
that the three constructors are one template with different embedded
addresses, records the fixed 6-qword output contract, the per-instance
tag slot / 30-byte thunk pair, and the 12 direct call sites (6 functions),
and writes evidence.json plus the case TSVs.  Only the Python standard
library is used; the binary is read, never executed.

    python3 tools/trio_constructor_callers.py --out <dir>

writes evidence.json, constructors.tsv, constructor-differences.tsv,
call-sites.tsv and helper-sites.tsv.  README.md and MANIFEST.sha256 are
hand-maintained beside them.
"""

import argparse
import csv
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections  # noqa: E402
from fde_extents import fde_extents  # noqa: E402

BINARY = 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
TEXT_VA = 0x1343c80
TEXT_OFF = 0x1342c80

# id -> (fde_start, fde_end, tag_slot_va, thunk_start, thunk_end)
CONSTRUCTORS = {
    'A': (0x4e6c8b0, 0x4e6caa5, 0x574b9c0, 0x4e73650, 0x4e7366e),
    'B': (0x4e81dc0, 0x4e81fb5, 0x574ce30, 0x4e84aa0, 0x4e84abe),
    'C': (0x4e6b5f0, 0x4e6b7e5, 0x574b950, 0x4e6c880, 0x4e6c89e),
}
# body offsets of the 10 instructions whose disp32 fields carry every
# differing byte, and the target they must resolve to in every instance
# (None = the per-instance tag slot, which differs by design).
DIFF_SITES = [
    (29, 'ff15', 0x576dfd8),
    (99, 'e8', 0x4e7d270),
    (295, 'e8', 0x4e7c6b0),
    (326, 'ff15', 0x576dfd8),
    (368, 'lea', None),
    (383, 'lea', 0x1e629b),
    (447, 'ff15', 0x576e020),
    (465, 'ff15', 0x576dfb8),
    (487, 'ff15', 0x576e010),
    (496, 'e8', 0x5660110),
]
# Fixed template bytes (identical in all three bodies): heap-block stores,
# masked-copy AND + store, and the output-store opcodes around the leas.
TEMPLATE_PATTERNS = [
    (0x151, bytes.fromhex('48c70001000000')),   # mov [rax],1 (heap field 0)
    (0x158, bytes.fromhex('48c7400801000000')),  # mov [rax+8],1 (heap field 1)
    (0x160, bytes.fromhex('4c897010')),          # mov [rax+0x10],r14 (buffer)
    (0x164, bytes.fromhex('48c7401808000000')),  # mov [rax+0x18],8
    (0x16c, bytes.fromhex('4c897820')),          # mov [rax+0x20],r15 (capacity)
    (0x94, bytes.fromhex('4120ef')),             # and r15b,bpl (mask)
    (0x9e, bytes.fromhex('47883c26')),           # mov [r14+r12],r15b (store)
    (0x18a, bytes.fromhex('48c7421001000000')),  # mov [rdx+0x10],1 (out field 2)
    (0x192, bytes.fromhex('48c7421800000000')),  # mov [rdx+0x18],0 (out field 3)
    (0x19a, bytes.fromhex('48c7422800000000')),  # mov [rdx+0x28],0 (out field 5)
    (0x1a2, bytes.fromhex('48894220')),          # mov [rdx+0x20],rax (heap ptr)
]
# caller_fde_start, caller_fde_end, role, callee_id, call_va, out_buffer,
# header_store, install_range
CALL_SITES = [
    (0x4e6fd50, 0x4e6fee2, 'trio', 'A', 0x4e6fdb7, '[rsp+0x38]', '[rsp+0x30]=1',
     '[obj+0x0..0x40] from [rsp+0x30..0x70] (non-match)'),
    (0x4e6fd50, 0x4e6fee2, 'trio', 'A', 0x4e6fe3c, '[rsp+0x0] (mov rdi,rsp)',
     '[r14]=1', '[r14+0x0..0x38] from [rsp+0x0..0x30] (match)'),
    (0x4e6fef0, 0x4e713bd, 'orchestrator', 'A', 0x4e70804, '[rsp+0x28]',
     '[rsp+0x20]=1', 'join-block install (not traced here)'),
    (0x4e6fef0, 0x4e713bd, 'orchestrator', 'A', 0x4e70e58, '[rsp+0xe0]',
     'none (direct movups reads)', 'direct movups reads from [rsp+0xe0..]'),
    (0x4e852a0, 0x4e85663, 'double-gate', 'B', 0x4e85320, '[rsp+0x58]',
     '[rsp+0x50]=1', '[r14+0x0..0x40] from [rsp+0x50..0x90] (non-match)'),
    (0x4e852a0, 0x4e85663, 'double-gate', 'B', 0x4e85454, '[rsp+0x20]',
     '[r14]=1', '[r14+0x0..0x38] from [rsp+0x20..0x50] (match)'),
    (0x4e856f0, 0x4e85b12, 'trio', 'B', 0x4e85769, '[rsp+0x78]',
     '[rsp+0x70]=1', '[r14+0x0..0x40] from [rsp+0x70..0xb0] (non-match)'),
    (0x4e856f0, 0x4e85b12, 'trio', 'B', 0x4e858cd, '[rsp+0x20]',
     '[r14]=1', '[r14+0x0..0x38] from [rsp+0x20..0x50] (match)'),
    (0x4e862b0, 0x4e8673a, 'gate-like', 'B', 0x4e86384, '[rsp+0x98]',
     '[rsp+0x90]=1', '[r14+0x0..0x40] from [rsp+0x90..0xd0]'),
    (0x4e862b0, 0x4e8673a, 'gate-like', 'B', 0x4e8644c, '[rsp+0x20]',
     '[r14]=1', '[r14+0x0..0x38] from [rsp+0x20..0x50]'),
    (0x4e6bcb0, 0x4e6c840, 'trio', 'C', 0x4e6bf8b, '[rsp+0x38]',
     '[rsp+0x30]=1', '[rbp+0x0..0x40] from [rsp+0x30..0x70] (non-match)'),
    (0x4e6bcb0, 0x4e6c840, 'trio', 'C', 0x4e6c028, '[rsp+0x30]',
     '[rbp]=1', '[rbp+0x0..0x38] from [rsp+0x30..0x60] (match)'),
]
# helper_va, call_va, caller_fde_start
HELPER_SITES = [
    (0x4e7d270, 0x4e6b653, 0x4e6b5f0),
    (0x4e7d270, 0x4e6c913, 0x4e6c8b0),
    (0x4e7d270, 0x4e76963, 0x4e76900),
    (0x4e7d270, 0x4e81e23, 0x4e81dc0),
    (0x4e7c6b0, 0x4e6b717, 0x4e6b5f0),
    (0x4e7c6b0, 0x4e6c9d7, 0x4e6c8b0),
    (0x4e7c6b0, 0x4e76a27, 0x4e76900),
    (0x4e7c6b0, 0x4e81ee7, 0x4e81dc0),
    (0x4e7c6b0, 0x4e88e40, 0x4e88d10),
]
EMPTY_STRING_VA = 0x1e629b
CHRONO_PATH = b'/home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/chrono-0.4.38/src/naive/date/mod.rs'


class EvidenceError(Exception):
    pass


def check_digest(data, expected=SHA256):
    got = hashlib.sha256(data).hexdigest()
    if got != expected:
        raise EvidenceError(f'node digest mismatch: {got} != {expected}')
    return got


def va_to_off(va):
    return va - TEXT_VA + TEXT_OFF


def resolve_e8(data, va):
    off = va_to_off(va)
    if data[off] != 0xe8:
        raise EvidenceError(f'not an E8 call at {hex(va)}: {data[off]:02x}')
    return va + 5 + struct.unpack_from('<i', data, off + 1)[0]


def resolve_ff15(data, va):
    off = va_to_off(va)
    if data[off:off + 2] != bytes.fromhex('ff15'):
        raise EvidenceError(f'not an FF15 call at {hex(va)}')
    return va + 6 + struct.unpack_from('<i', data, off + 2)[0]


def resolve_lea(data, va):
    off = va_to_off(va)
    if data[off:off + 3] != bytes.fromhex('488d0d'):
        raise EvidenceError(f'not a 48 8d 0d lea at {hex(va)}')
    return va + 7 + struct.unpack_from('<i', data, off + 3)[0]


def resolve_diff_instruction(data, base, offset):
    kind = next(k for o, k, _ in DIFF_SITES if o == offset)
    va = base + offset
    if kind == 'e8':
        return 'e8', resolve_e8(data, va)
    if kind == 'ff15':
        return 'ff15', resolve_ff15(data, va)
    return 'lea', resolve_lea(data, va)


def build(data):
    check_digest(data)
    _, ordered, _ = fde_extents(data)
    fde_by_start = {f['start']: f for f in ordered}
    bodies = {}
    for cid, (start, end, slot, tstart, tend) in CONSTRUCTORS.items():
        fde = fde_by_start.get(start)
        if fde is None or fde['end'] != end:
            raise EvidenceError(f'constructor {cid} FDE mismatch')
        body = data[va_to_off(start):va_to_off(end)]
        if len(body) != 501:
            raise EvidenceError(f'constructor {cid} size {len(body)} != 501')
        for off, pat in TEMPLATE_PATTERNS:
            if body[off:off + len(pat)] != pat:
                raise EvidenceError(f'constructor {cid} template pattern at {off} mismatch')
        for off, kind, expected in DIFF_SITES:
            _, tgt = resolve_diff_instruction(data, start, off)
            want = slot if expected is None else expected
            if tgt != want:
                raise EvidenceError(f'constructor {cid} diff site {off} resolves to {hex(tgt)} != {hex(want)}')
        # thunk: same 30-byte shape, lea at +19 must name this constructor's slot
        thunk = data[va_to_off(tstart):va_to_off(tend)]
        if len(thunk) != 30 or thunk[:3] != bytes.fromhex('4889f8'):
            raise EvidenceError(f'thunk {cid} prologue mismatch')
        if thunk[3:11] != bytes.fromhex('4889570848894f10'):
            raise EvidenceError(f'thunk {cid} field stores mismatch')
        if thunk[11:19] != bytes.fromhex('48c7471800000000'):
            raise EvidenceError(f'thunk {cid} zero store mismatch')
        if resolve_lea(data, tstart + 19) != slot:
            raise EvidenceError(f'thunk {cid} lea does not name slot {hex(slot)}')
        if thunk[26:29] != bytes.fromhex('48890f') or thunk[29] != 0xc3:
            raise EvidenceError(f'thunk {cid} epilogue mismatch')
        bodies[cid] = body
    # empty-string field: NUL byte terminating the chrono path string
    secs = sections(data)
    rodata = next(s for s in secs if s['name'] == '.rodata')
    if rodata['address'] != rodata['offset']:
        raise EvidenceError('.rodata VA != file offset; empty-string check needs a VA map')
    if data[EMPTY_STRING_VA] != 0 or data[EMPTY_STRING_VA - 1] != 0:
        raise EvidenceError('bytes at 0x1e629a..0x1e629b are not NUL,NUL')
    if data[EMPTY_STRING_VA - 1 - len(CHRONO_PATH):EMPTY_STRING_VA - 1] != CHRONO_PATH:
        raise EvidenceError('chrono path string before 0x1e629b mismatch')
    # call sites: E8 -> callee, inside the claimed caller FDE
    for fstart, fend, _, cid, call, _, _, _ in CALL_SITES:
        fde = fde_by_start.get(fstart)
        if fde is None or fde['end'] != fend:
            raise EvidenceError(f'caller FDE {hex(fstart)} mismatch')
        if not (fstart <= call < fend):
            raise EvidenceError(f'call {hex(call)} outside caller FDE')
        if resolve_e8(data, call) != CONSTRUCTORS[cid][0]:
            raise EvidenceError(f'call {hex(call)} does not reach constructor {cid}')
    # helper sites: E8 -> helper, inside the claimed caller FDE
    for helper, call, fstart in HELPER_SITES:
        fde = fde_by_start.get(fstart)
        if fde is None or not (fstart <= call < fde['end']):
            raise EvidenceError(f'helper call {hex(call)} outside FDE {hex(fstart)}')
        if resolve_e8(data, call) != helper:
            raise EvidenceError(f'helper call {hex(call)} does not reach {hex(helper)}')
    # pairwise diffs
    import itertools
    diffs = {}
    for x, y in itertools.combinations(sorted(bodies), 2):
        diffs[x + y] = [i for i in range(501) if bodies[x][i] != bodies[y][i]]
    evidence = {
        'node_sha256': SHA256,
        'constructors': {
            cid: {
                'fde_start': hex(start), 'fde_end': hex(end), 'size': end - start,
                'sha256': hashlib.sha256(bodies[cid]).hexdigest(),
                'tag_slot_va': hex(slot),
                'thunk_fde_start': hex(tstart), 'thunk_fde_end': hex(tend),
                'thunk_sha256': hashlib.sha256(
                    data[va_to_off(tstart):va_to_off(tend)]).hexdigest(),
            } for cid, (start, end, slot, tstart, tend) in CONSTRUCTORS.items()
        },
        'diff_instruction_offsets': [o for o, _, _ in DIFF_SITES],
        'pairwise_differing_bytes': {k: len(v) for k, v in diffs.items()},
        'pairwise_agreement': {
            k: f'{501 - len(v)}/501' for k, v in diffs.items()},
        'empty_string_va': hex(EMPTY_STRING_VA),
        'chrono_path_before': CHRONO_PATH.decode(),
        'call_sites': len(CALL_SITES),
        'helper_sites': len(HELPER_SITES),
        'output_fields': ['tag_slot_ptr', 'empty_string_ptr', '1', '0',
                          'heap_block_ptr', '0'],
        'heap_block_fields': ['1', '1', 'buffer_ptr', '8', 'capacity'],
    }
    tables = {'diffs': diffs}
    return evidence, tables


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', required=True)
    args = parser.parse_args(argv)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    data = (ROOT / BINARY).read_bytes()
    evidence, tables = build(data)
    # constructors.tsv from the evidence record (single source of truth)
    with (out / 'constructors.tsv').open('w', newline='') as handle:
        writer = csv.writer(handle, delimiter='\t', lineterminator='\n')
        writer.writerow(['id', 'fde_start', 'fde_end', 'size', 'sha256',
                         'tag_slot_va', 'thunk_fde_start', 'thunk_fde_end',
                         'thunk_sha256'])
        for cid in sorted(evidence['constructors']):
            c = evidence['constructors'][cid]
            writer.writerow([cid, c['fde_start'], c['fde_end'], c['size'],
                             c['sha256'], c['tag_slot_va'],
                             c['thunk_fde_start'], c['thunk_fde_end'],
                             c['thunk_sha256']])
    # differences with actual bytes
    bodies = {}
    for cid, (start, end, _, _, _) in CONSTRUCTORS.items():
        bodies[cid] = data[va_to_off(start):va_to_off(end)]
    with (out / 'constructor-differences.tsv').open('w', newline='') as handle:
        writer = csv.writer(handle, delimiter='\t', lineterminator='\n')
        writer.writerow(['pair', 'body_offset', 'byte_first', 'byte_second'])
        for pair in sorted(tables['diffs']):
            for off in tables['diffs'][pair]:
                writer.writerow([pair, off, f'{bodies[pair[0]][off]:02x}',
                                 f'{bodies[pair[1]][off]:02x}'])
    with (out / 'call-sites.tsv').open('w', newline='') as handle:
        writer = csv.writer(handle, delimiter='\t', lineterminator='\n')
        writer.writerow(['caller_fde_start', 'caller_fde_end', 'caller_role',
                         'callee', 'call_va', 'out_buffer', 'header_store',
                         'install_range'])
        for row in CALL_SITES:
            writer.writerow([hex(row[0]), hex(row[1]), row[2], row[3],
                             hex(row[4]), row[5], row[6], row[7]])
    with (out / 'helper-sites.tsv').open('w', newline='') as handle:
        writer = csv.writer(handle, delimiter='\t', lineterminator='\n')
        writer.writerow(['helper_va', 'call_va', 'caller_fde_start'])
        for helper, call, fstart in HELPER_SITES:
            writer.writerow([hex(helper), hex(call), hex(fstart)])
    (out / 'evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')
    print(json.dumps({
        'constructors': 3, 'call_sites': len(CALL_SITES),
        'helper_sites': len(HELPER_SITES),
        'pairwise_differing_bytes': evidence['pairwise_differing_bytes'],
    }, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
