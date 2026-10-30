#!/usr/bin/env python3
"""RE-009: what blake3 hashes inside 0x3269ae0 (l1/src/evm/evm_db.rs:154).

Static evidence from artifacts/node/94/hl-node only (no execution, no network).
Pins, for the three blake3 rounds in FDE 0x3269ae0..0x326a6ee:
* the rocksdb iterator producer that fills each 0x810-byte buffer;
* the blake3 update call (rdi=hasher, rsi=that buffer, rdx=0x800);
* the finalize call and its 32-byte output slot;
* the stores that overwrite every output slot before any read.
Also pins the relocated blake3 slots, the producers' rocksdb Location, the
two rel32 callers of 0x3269ae0 and the call into the lt_hashes writer.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bincode_varint as bv  # noqa: E402
from bincode_varint import EvidenceError  # noqa: E402

FN = (0x3269ae0, 0x326a6ee)
SLOTS = {0x57700c0: 0x14fa220, 0x57700c8: 0x14f93e0, 0x57700d0: 0x14fa010}
SLOT_ROLE = {0x57700c0: 'platform_detect', 0x57700c8: 'update', 0x57700d0: 'finalize'}
CALLERS = (0x326e4bb, 0x32fc41f)
LT_WRITER = 0x32699c0
PRODUCER_LOCATION = ('rocksdb-0.21.0/src/db_iterator.rs', 109)

ANCHORS = (
    (0x3269c54, 'be18000000', 'mov esi,0x18'),
    (0x3269c5c, 'e83f323200', 'call 358cea0'),
    (0x3269c96, 'ba10080000', 'mov edx,0x810'),
    (0x3269ca0, 'ff1552455002', 'call QWORD PTR [rip+0x2504552] # 576e1f8'),
    (0x3269ca6, '488dbc2450010000', 'lea rdi,[rsp+0x150]'),
    (0x3269cae, 'ba40420f00', 'mov edx,0xf4240'),
    (0x3269cbe, 'e8ad935600', 'call 37d3070'),
    (0x3269cd1, 'ff15e9635002', 'call QWORD PTR [rip+0x25063e9] # 57700c0'),
    (0x3269d81, '488dbc24600a0000', 'lea rdi,[rsp+0xa60]'),
    (0x3269d89, '488db42450010000', 'lea rsi,[rsp+0x150]'),
    (0x3269d91, 'ba00080000', 'mov edx,0x800'),
    (0x3269d96, 'ff152c635002', 'call QWORD PTR [rip+0x250632c] # 57700c8'),
    (0x3269d9c, '488dbc24902e0000', 'lea rdi,[rsp+0x2e90]'),
    (0x3269da4, '488db424600a0000', 'lea rsi,[rsp+0xa60]'),
    (0x3269dac, 'ff151e635002', 'call QWORD PTR [rip+0x250631e] # 57700d0'),
    (0x3269db7, 'e8449ac701', 'call 4ee3800'),
    (0x3269dcb, '4c89b424902e0000', 'mov QWORD PTR [rsp+0x2e90],r14'),
    (0x3269df7, '488dbc24902e0000', 'lea rdi,[rsp+0x2e90]'),
    (0x3269dff, '488db42480250000', 'lea rsi,[rsp+0x2580]'),
    (0x3269e0e, 'baf8000000', 'mov edx,0xf8'),
    (0x3269e13, '41ffd6', 'call r14'),
    (0x3269e16, '488dbc24882f0000', 'lea rdi,[rsp+0x2f88]'),
    (0x3269e1e, '488db42450010000', 'lea rsi,[rsp+0x150]'),
    (0x3269e5f, 'ba10080000', 'mov edx,0x810'),
    (0x3269e64, '41ffd6', 'call r14'),
    (0x3269e6f, 'be19000000', 'mov esi,0x19'),
    (0x3269e77, 'e8a4383200', 'call 358d720'),
    (0x3269eb1, 'ba10080000', 'mov edx,0x810'),
    (0x3269ebb, 'ff1537435002', 'call QWORD PTR [rip+0x2504337] # 576e1f8'),
    (0x3269ec1, '488dbc2450010000', 'lea rdi,[rsp+0x150]'),
    (0x3269ec9, 'ba40420f00', 'mov edx,0xf4240'),
    (0x3269ed9, 'e8f29c5600', 'call 37d3bd0'),
    (0x3269eec, 'ff15ce615002', 'call QWORD PTR [rip+0x25061ce] # 57700c0'),
    (0x3269f9c, '488dbc24600a0000', 'lea rdi,[rsp+0xa60]'),
    (0x3269fa4, '488db42450010000', 'lea rsi,[rsp+0x150]'),
    (0x3269fac, 'ba00080000', 'mov edx,0x800'),
    (0x3269fb1, 'ff1511615002', 'call QWORD PTR [rip+0x2506111] # 57700c8'),
    (0x3269fb7, '488dbc2480250000', 'lea rdi,[rsp+0x2580]'),
    (0x3269fbf, '488db424600a0000', 'lea rsi,[rsp+0xa60]'),
    (0x3269fc7, 'ff1503615002', 'call QWORD PTR [rip+0x2506103] # 57700d0'),
    (0x3269fd2, 'e82998c701', 'call 4ee3800'),
    (0x3269fe0, '4c89b42480250000', 'mov QWORD PTR [rsp+0x2580],r14'),
    (0x326a009, '488dbc2480250000', 'lea rdi,[rsp+0x2580]'),
    (0x326a011, '488db42498370000', 'lea rsi,[rsp+0x3798]'),
    (0x326a020, 'baf8000000', 'mov edx,0xf8'),
    (0x326a025, '41ffd6', 'call r14'),
    (0x326a07e, 'be1a000000', 'mov esi,0x1a'),
    (0x326a086, 'e855323200', 'call 358d2e0'),
    (0x326a0bd, 'ba10080000', 'mov edx,0x810'),
    (0x326a0c7, 'ff152b415002', 'call QWORD PTR [rip+0x250412b] # 576e1f8'),
    (0x326a0cd, '488dbc2498370000', 'lea rdi,[rsp+0x3798]'),
    (0x326a0d5, 'ba40420f00', 'mov edx,0xf4240'),
    (0x326a0e5, 'e866845600', 'call 37d2550'),
    (0x326a0f8, 'ff15c25f5002', 'call QWORD PTR [rip+0x2505fc2] # 57700c0'),
    (0x326a1a8, '488dbc24600a0000', 'lea rdi,[rsp+0xa60]'),
    (0x326a1b0, '488db42498370000', 'lea rsi,[rsp+0x3798]'),
    (0x326a1b8, 'ba00080000', 'mov edx,0x800'),
    (0x326a1bd, 'ff15055f5002', 'call QWORD PTR [rip+0x2505f05] # 57700c8'),
    (0x326a1c3, '488dbc2450010000', 'lea rdi,[rsp+0x150]'),
    (0x326a1cb, '488db424600a0000', 'lea rsi,[rsp+0xa60]'),
    (0x326a1d3, 'ff15f75e5002', 'call QWORD PTR [rip+0x2505ef7] # 57700d0'),
    (0x326a1de, 'e81d96c701', 'call 4ee3800'),
    (0x326a1ec, '4c89b42450010000', 'mov QWORD PTR [rsp+0x150],r14'),
    (0x326a215, '488dbc2450010000', 'lea rdi,[rsp+0x150]'),
    (0x326a21d, '488d742458', 'lea rsi,[rsp+0x58]'),
    (0x326a229, 'baf8000000', 'mov edx,0xf8'),
    (0x326a22e, 'ffd3', 'call rbx'),
    (0x326a2e0, 'e8dbf6ffff', 'call 32699c0'),
)

# (round, db_wrapper_call, db_code, producer, buffer, update, finalize, digest_slot,
#  overwrite_lo (mov [slot],r14), overwrite_memcpy (call with edx=0xf8 into slot))
ROUNDS = (
    (1, 0x3269c5c, 0x18, 0x37d3070, 0x150, 0x3269d96, 0x3269dac, 0x2e90, 0x3269dcb, 0x3269e13),
    (2, 0x3269e77, 0x19, 0x37d3bd0, 0x150, 0x3269fb1, 0x3269fc7, 0x2580, 0x3269fe0, 0x326a025),
    (3, 0x326a086, 0x1a, 0x37d2550, 0x3798, 0x326a1bd, 0x326a1d3, 0x150, 0x326a1ec, 0x326a22e),
)
PRODUCER_FDES = {0x37d3070: 0x37d3bc7, 0x37d3bd0: 0x37d47b1, 0x37d2550: 0x37d3067}
UPDATE_LEN = 0x800
BUFFER_LEN = 0x810


def _anchors(data, secs):
    rows = []
    for va, hexbytes, text in ANCHORS:
        want = bytes.fromhex(hexbytes)
        o = bv.va_to_off(secs, va)
        if not FN[0] <= va < FN[1] or data[o:o + len(want)] != want:
            raise EvidenceError(f'bytes at {va:#x} are not {hexbytes} ({text})')
        rows.append({'va': f'{va:#x}', 'bytes': hexbytes, 'insn': text})
    return rows


def _slot_calls(data, secs, relocs):
    o = bv.va_to_off(secs, FN[0])
    body = data[o:o + FN[1] - FN[0]]
    out = {f'{s:#x}': [] for s in SLOTS}
    for i in range(len(body) - 6):
        if body[i:i + 2] == b'\xff\x15':
            slot = FN[0] + i + 6 + struct.unpack_from('<i', body, i + 2)[0]
            if slot in SLOTS:
                out[f'{slot:#x}'].append(f'{FN[0] + i:#x}')
    for s, t in SLOTS.items():
        if relocs.get(s) != t:
            raise EvidenceError(f'slot {s:#x} does not relocate to {t:#x}')
        if len(out[f'{s:#x}']) != 3:
            raise EvidenceError(f'slot {s:#x}: {len(out[f"{s:#x}"])} call sites, expected 3')
    return out


def _rel32_callers(data, secs, target):
    text = secs['.text']
    tb = data[text['offset']:text['offset'] + text['size']]
    base = text['addr']
    hits = []
    i = tb.find(b'\xe8')
    while i != -1 and i + 5 <= len(tb):
        if base + i + 5 + struct.unpack_from('<i', tb, i + 1)[0] == target:
            hits.append(base + i)
        i = tb.find(b'\xe8', i + 1)
    return hits


def _location(data, secs, relocs, lo, hi):
    o = bv.va_to_off(secs, lo)
    body = data[o:o + hi - lo]
    found = set()
    for i in range(len(body) - 7):
        if body[i] in (0x48, 0x4c) and body[i + 1] == 0x8d and (body[i + 2] & 0xc7) == 0x05:
            a = lo + i + 7 + struct.unpack_from('<i', body, i + 3)[0]
            p = relocs.get(a)
            if p is None:
                continue
            try:
                ao = bv.va_to_off(secs, a)
                n = struct.unpack_from('<Q', data, ao + 8)[0]
                line = struct.unpack_from('<I', data, ao + 16)[0]
                s = data[bv.va_to_off(secs, p):bv.va_to_off(secs, p) + n] if 3 < n < 300 else b''
            except (EvidenceError, struct.error, KeyError, ValueError):
                continue
            if s.endswith(b'.rs'):
                found.add((s.decode('latin1'), line))
    return sorted(found)


def scan(data, expected_sha256=bv.SHA256, check_callers=True):
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected_sha256:
        raise EvidenceError(f'input SHA-256 {digest} is not node #94 {bv.SHA256}')
    secs = bv.sections(data)
    fdes = bv.fde_extents(data, secs)
    relocs = bv.relative_relocs(data, secs)
    if fdes.get(FN[0]) != FN[1]:
        raise EvidenceError(f'FDE is not {FN[0]:#x}..{FN[1]:#x}')
    rows = _anchors(data, secs)
    slot_calls = _slot_calls(data, secs, relocs)
    rounds = []
    for r, dbcall, code, prod, buf, upd, fin, slot, ow_lo, ow_cp in ROUNDS:
        if fdes.get(prod) != PRODUCER_FDES[prod]:
            raise EvidenceError(f'producer FDE {prod:#x}')
        locs = _location(data, secs, relocs, prod, PRODUCER_FDES[prod])
        if not any(p.endswith(PRODUCER_LOCATION[0]) and ln == PRODUCER_LOCATION[1] for p, ln in locs):
            raise EvidenceError(f'producer {prod:#x} has no {PRODUCER_LOCATION} Location')
        rounds.append({
            'round': r, 'db_wrapper_call': f'{dbcall:#x}', 'db_wrapper_esi': f'{code:#x}',
            'producer': f'{prod:#x}', 'producer_fde_end': f'{PRODUCER_FDES[prod]:#x}',
            'producer_location': f'{PRODUCER_LOCATION[0]}:{PRODUCER_LOCATION[1]}',
            'buffer': f'rsp+{buf:#x}', 'buffer_zeroed_len': BUFFER_LEN,
            'update_call': f'{upd:#x}', 'update_args': {'rdi': 'rsp+0xa60', 'rsi': f'rsp+{buf:#x}', 'rdx': UPDATE_LEN},
            'hashed_bytes': f'[rsp+{buf:#x}, rsp+{buf + UPDATE_LEN:#x})',
            'finalize_call': f'{fin:#x}', 'finalize_out': f'rsp+{slot:#x}',
            'digest_overwritten_by': [f'{ow_lo:#x} mov [rsp+{slot:#x}],r14 (+ dword at +8)',
                                      f'{ow_cp:#x} memcpy(rsp+{slot:#x}, .., 0xf8)'],
        })
    callers = None
    if check_callers:
        got = tuple(_rel32_callers(data, secs, FN[0]))
        if got != CALLERS:
            raise EvidenceError(f'rel32 callers {[hex(x) for x in got]}')
        callers = [f'{c:#x}' for c in got]
    return {
        'schema': 're009-evm-db-blake3/1',
        'target': {'release': 94, 'sha256': digest, 'size': len(data)},
        'function': {'fde_start': f'{FN[0]:#x}', 'fde_end': f'{FN[1]:#x}',
                     'location': 'l1/src/evm/evm_db.rs:154', 'rel32_callers': callers},
        'blake3_slots': {f'{s:#x}': {'target': f'{t:#x}', 'role': SLOT_ROLE[s],
                                     'call_sites': slot_calls[f'{s:#x}']} for s, t in SLOTS.items()},
        'rounds': rounds,
        'lt_hashes_writer_call': {'va': '0x326a2e0', 'target': f'{LT_WRITER:#x}'},
        'anchors': rows,
        'finding': ('three independent blake3 hashes, each of exactly 0x800 bytes: the first 0x800 bytes '
                    'of a 0x810-byte buffer filled by a rocksdb-iterator producer; order 0x37d3070, '
                    '0x37d3bd0, 0x37d2550. Each 32-byte finalize output is overwritten before any read, '
                    'so no digest reaches the 0x32699c0 (/lt_hashes.json) call'),
        'what_this_does_not_claim': [
            'No claim about what the producers compute; that the 0x800 bytes are an LtHash state is an inference.',
            'No claim about the meaning of db wrapper codes 0x18/0x19/0x1a (labelled by open PR #245).',
            'Roles update/finalize for 0x14f93e0/0x14fa010 are inferred from blake3-1.7.0 FDEs and the argument shapes.',
            'No runtime claim; evidence is static. The hash may serve timing only; not proven.',
            'Merged RE-009 packet files are unchanged; their JSON hashes are the negative control.',
        ],
    }


def render(result):
    return (json.dumps(result, sort_keys=True, separators=(',', ':')) + '\n').encode()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--input', type=Path, default=bv.TARGET)
    ap.add_argument('--output', type=Path)
    a = ap.parse_args(argv)
    try:
        text = render(scan(a.input.read_bytes()))
    except (EvidenceError, OSError, struct.error, ValueError) as e:
        print(f'evm_db_blake3: {e}', file=sys.stderr)
        return 1
    if a.output:
        a.output.write_bytes(text)
    else:
        sys.stdout.buffer.write(text)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
