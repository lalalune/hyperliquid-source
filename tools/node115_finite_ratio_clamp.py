#!/usr/bin/env python3
"""Static #115 finite-ratio certificate; Python 3.10+ stdlib, no target execution."""
import argparse
import bisect
import hashlib
import json
import mmap
from pathlib import Path
import struct
import sys

from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-001-node115-finite-ratio-clamp'
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
BASE = '8fd8db680ec4bfef40996e5616bce3d5156d0b86'
START, END = 0x14ca350, 0x14ca3e4
BODY_SHA = 'c2f3b2eebf2e5723e5217cbfda7e5b463ab59c0d8c3c850b7af527b2ce8e4ff6'
FDE, CIE = 0xcae708, 0xca6ed8
SLOT = 0x64e0058
EPS = 0x3cd203af9ee75616
SIGN, ABS, MAX_FINITE, INF = 1 << 63, (1 << 63) - 1, 0x7fefffffffffffff, 0x7ff0000000000000
SOURCE_FILES = ('tools/node115_finite_ratio_clamp.py',
                'tests/test_node115_finite_ratio_clamp.py',
                'tools/elf_index.py', 'tools/fde_extents.py')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def mapping(data, secs, va, size):
    matches = [s for s in secs if s['type'] != 8 and s['address'] <= va
               and va + size <= s['address'] + s['size']]
    require(size >= 0 and len(matches) == 1, 'ambiguous or absent ELF mapping')
    section = matches[0]
    off = section['offset'] + va - section['address']
    require(off + size <= len(data), 'truncated mapped bytes')
    return off


def read_va(data, secs, va, size):
    off = mapping(data, secs, va, size)
    return data[off:off + size]


# Closed instruction subset: complete encodings including ModRM, REX and prefixes.
# Only immediate/relative fields are variable. Unsupported bytes never resynchronize.
FIXED = {
    '66480f7ec8': ('movq', 'rax, xmm1'),
    '66480f7ec2': ('movq', 'rdx, xmm0'),
    '4821ca': ('and', 'rdx, rcx'),
    '4839f2': ('cmp', 'rdx, rsi'),
    '0f9fc2': ('setg', 'dl'),
    '4821c8': ('and', 'rax, rcx'),
    '4839f0': ('cmp', 'rax, rsi'),
    '0f9fc0': ('setg', 'al'),
    '08d0': ('or', 'al, dl'),
    '31c0': ('xor', 'eax, eax'),
    'c3': ('ret', ''),
    '660f57d2': ('xorpd', 'xmm2, xmm2'),
    '660f2ed0': ('ucomisd', 'xmm2, xmm0'),
    '660f57c0': ('xorpd', 'xmm0, xmm0'),
    '660f2ed1': ('ucomisd', 'xmm2, xmm1'),
    'f20f5ec1': ('divsd', 'xmm0, xmm1'),
    '4839ca': ('cmp', 'rdx, rcx'),
    '0f9cc0': ('setl', 'al'),
    'a801': ('test', 'al, 0x1'),
    '4883f801': ('cmp', 'rax, 0x1'),
}
FIXED_BYTES = [(bytes.fromhex(k), *v) for k, v in FIXED.items()]


def decode(code, start):
    """Strict linear decode of the entire supplied window, including return tails."""
    rows, p = [], 0
    while p < len(code):
        row = {'va': start + p}
        tail = code[p:]
        matched = next((x for x in FIXED_BYTES if tail.startswith(x[0])), None)
        if matched:
            raw, mnemonic, operands = matched
            n = len(raw)
            row.update(mnemonic=mnemonic, operands=operands)
        elif tail[:2] in (b'\x48\xb9', b'\x48\xbe'):
            require(len(tail) >= 10, 'truncated movabs')
            n = 10
            value = struct.unpack_from('<Q', tail, 2)[0]
            reg = 'rcx' if tail[1] == 0xb9 else 'rsi'
            row.update(mnemonic='movabs', operands=f'{reg}, {value:#x}', immediate=value)
        elif tail[0] in (0x74, 0x75, 0x76, 0x77, 0xeb):
            require(len(tail) >= 2, 'truncated short branch')
            n = 2
            target = start + p + n + struct.unpack_from('<b', tail, 1)[0]
            mnemonic = {0x74: 'je', 0x75: 'jne', 0x76: 'jbe', 0x77: 'ja', 0xeb: 'jmp'}[tail[0]]
            row.update(mnemonic=mnemonic, operands=hex(target), target=target)
        elif tail[:2] == b'\x0f\x85':
            require(len(tail) >= 6, 'truncated near branch')
            n = 6
            target = start + p + n + struct.unpack_from('<i', tail, 2)[0]
            row.update(mnemonic='jne', operands=hex(target), target=target)
        else:
            forms = ((b'\x66\x0f\x2e\x05', 'ucomisd', 'xmm0', 8),
                     (b'\xf2\x0f\x10\x15', 'movsd', 'xmm2', 8),
                     (b'\x48\x8d\x3d', 'lea', 'rdi', 7),
                     (b'\xff\x15', 'call', '', 6),
                     (b'\xff\x25', 'jmp_indirect', '', 6))
            form = next((x for x in forms if tail.startswith(x[0])), None)
            require(form is not None, f'unsupported instruction at {start + p:#x}')
            prefix, mnemonic, reg, n = form
            require(len(tail) >= n, 'truncated RIP-relative instruction')
            target = start + p + n + struct.unpack_from('<i', tail, len(prefix))[0]
            row.update(mnemonic=mnemonic, operands=f'{reg + ", " if reg else ""}[rip -> {target:#x}]',
                       memory_va=target)
        row.update(size=n, bytes=code[p:p + n].hex())
        rows.append(row)
        p += n
    return rows


# The independently reviewed instruction order and local control-flow topology.
ORDER = ('movq movq movabs and movabs cmp setg and cmp setg or je xor ret '
         'xorpd ucomisd jbe ucomisd jbe xorpd movsd ucomisd ja jmp xor '
         'ucomisd ja movsd ucomisd ja divsd movq and movabs xor cmp setl ret').split()
BRANCHES = {0x32: ('je', 0x37), 0x3f: ('jbe', 0x5f), 0x49: ('jbe', 0x5f),
            0x5b: ('ja', 0x34), 0x5d: ('jmp', 0x75), 0x65: ('ja', 0x36),
            0x73: ('ja', 0x36)}


def certify_body(body):
    rows = decode(body, START)
    require(len(body) == END - START, 'body extent changed')
    require([r['mnemonic'] for r in rows] == ORDER, 'instruction rule changed')
    observed = {r['va'] - START: (r['mnemonic'], r['target'] - START)
                for r in rows if 'target' in r}
    require(observed == BRANCHES, 'branch topology changed')
    by_offset = {r['va'] - START: r for r in rows}
    require([by_offset[o]['immediate'] for o in (0xa, 0x17, 0x81)] ==
            [ABS, MAX_FINITE, INF], 'finite masks or bounds changed')
    require([(r['va'] - START, r['memory_va']) for r in rows if 'memory_va' in r] ==
            [(0x41, 0x458fa0), (0x4f, 0x459ba0), (0x67, 0x459ba0)],
            'constant reference changed')
    starts = {r['va'] for r in rows}
    require(all(r['target'] in starts for r in rows if 'target' in r), 'branch enters instruction')
    require(sha(body) == BODY_SHA, 'body bytes changed')
    edges = []
    for row in rows:
        if row['mnemonic'] == 'ret':
            dest = []
        elif row['mnemonic'] == 'jmp':
            dest = [row['target']]
        elif 'target' in row:
            dest = [row['va'] + row['size'], row['target']]
        else:
            dest = [row['va'] + row['size']]
        require(all(v in starts for v in dest), 'control flow escapes body')
        edges.append({'va': row['va'], 'successors': dest})
    seen, pending = set(), [START]
    graph = {r['va']: r['successors'] for r in edges}
    while pending:
        va = pending.pop()
        if va not in seen:
            seen.add(va)
            pending.extend(graph[va])
    require(seen == starts, 'unreachable instruction in certified body')
    return rows, edges


def frame_record(data, secs, frame):
    result = dict(frame)
    for label in ('fde', 'cie'):
        va = frame[label]
        off = mapping(data, secs, va, 4)
        size = 4 + struct.unpack_from('<I', data, off)[0]
        raw = read_va(data, secs, va, size)
        result[label + '_file_offset'] = off
        result[label + '_bytes'] = raw.hex()
    return result


def owner_of(frames, starts, site):
    i = bisect.bisect_right(starts, site) - 1
    require(i >= 0 and site < frames[i]['end'], 'reference without FDE owner')
    return frames[i]


def scan_direct(data, text, target):
    """Every byte position capable of holding E8/E9 rel32, not a CFG census."""
    matches, examined = [], {}
    lo, hi = text['offset'], text['offset'] + text['size']
    for opcode in (0xe8, 0xe9):
        pos, count = lo, 0
        while True:
            pos = data.find(bytes([opcode]), pos, hi - 4)
            if pos < 0:
                break
            count += 1
            va = text['address'] + pos - lo
            destination = va + 5 + struct.unpack_from('<i', data, pos + 1)[0]
            if destination == target:
                matches.append({'site': va, 'opcode': hex(opcode), 'target': destination,
                                'bytes': data[pos:pos + 5].hex()})
            pos += 1
        examined[hex(opcode)] = count
    return {'start': text['address'], 'end': text['address'] + text['size'],
            'method': 'all byte positions, E8/E9 signed rel32; raw candidates, not CFG reachability',
            'examined_opcode_positions': examined, 'matches': sorted(matches, key=lambda r: r['site'])}


def relocations(data, secs):
    section = next(s for s in secs if s['name'] == '.rela.dyn')
    require(section['size'] % 24 == 0, 'malformed RELA size')
    rows = {}
    for off in range(section['offset'], section['offset'] + section['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, off)
        require(slot not in rows, 'duplicate dynamic relocation destination')
        rows[slot] = {'slot': slot, 'info': info, 'addend': addend, 'file_offset': off,
                      'bytes': data[off:off + 24].hex()}
    return rows


def source_location(data, secs, relocs, va):
    raw = read_va(data, secs, va, 24)
    pointer, length, line, column = struct.unpack('<QQII', raw)
    rel = relocs[va]
    require(pointer == 0 and rel['info'] == 8, 'Location pointer relocation changed')
    path_bytes = read_va(data, secs, rel['addend'], length)
    path = path_bytes.decode('ascii')
    require(path in ('l1/src/clearinghouse/clearinghouse.rs', 'l1/src/vault/mod.rs'),
            'first-party Location path changed')
    return {'va': va, 'bytes': raw.hex(), 'relocation': rel, 'path_va': rel['addend'],
            'path_bytes': path_bytes.hex(), 'path': path, 'length': length,
            'line': line, 'column': column}


def inspect_static(data):
    """Internal certificate checks; public generate() additionally authenticates all bytes."""
    secs = sections(data)
    text = next(s for s in secs if s['name'] == '.text')
    require((text['address'], text['size'], text['offset'], text['flags']) ==
            (0x1419300, 0x4fd7700, 0x1418300, 6), 'text geometry changed')
    _, frames = eh_frame_records(data, secs)
    frames.sort(key=lambda r: (r['start'], r['end']))
    starts = [f['start'] for f in frames]
    matching = [f for f in frames if f['start'] < END and f['end'] > START]
    require(matching == [{'fde': FDE, 'cie': CIE, 'start': START, 'end': END, 'lsda': None}],
            'exact FDE extent or CIE changed')
    frame = frame_record(data, secs, matching[0])
    require(frame['fde_bytes'] == '100000003478000040bc81009400000000000000' and
            frame['cie_bytes'] == '1400000000000000017a5200017810011b0c070890010000',
            'unwind record bytes changed')
    body = read_va(data, secs, START, END - START)
    instructions, cfg = certify_body(body)
    next_start = starts[bisect.bisect_right(starts, START)]
    padding = read_va(data, secs, END, next_start - END)
    require(next_start == 0x14ca3f0 and padding == b'\xcc' * 12, 'padding changed')
    constants = []
    for va, expected in ((0x458fa0, SIGN | EPS), (0x459ba0, EPS)):
        raw = read_va(data, secs, va, 8)
        bits = int.from_bytes(raw, 'little')
        require(bits == expected, 'epsilon constant changed')
        constants.append({'va': va, 'file_offset': mapping(data, secs, va, 8),
                          'bytes': raw.hex(), 'bits': bits,
                          'binary64_hex': struct.unpack('<d', raw)[0].hex()})
    direct = scan_direct(data, text, START)
    require(not direct['matches'], 'new direct reference candidate')
    relocs = relocations(data, secs)
    entry_refs = [r for r in relocs.values() if r['info'] == 8 and r['addend'] == START]
    require(len(entry_refs) == 1 and entry_refs[0]['slot'] == SLOT, 'callee relocation target changed')
    require(read_va(data, secs, SLOT, 8) == b'\0' * 8, 'unrelocated slot changed')
    sites = []
    lo, hi = text['offset'], text['offset'] + text['size']
    for opcode in (b'\xff\x15', b'\xff\x25'):
        pos = lo
        while True:
            pos = data.find(opcode, pos, hi - 5)
            if pos < 0:
                break
            va = text['address'] + pos - lo
            slot = va + 6 + struct.unpack_from('<i', data, pos + 2)[0]
            if slot == SLOT:
                sites.append(va)
            pos += 1
    require(sorted(sites) == [0x44807b9, 0x4480895, 0x44af279], 'slot reference census changed')
    references = []
    expected_locations = {0x44807b9: (0x648bb58, 1224, 57),
                          0x4480895: (0x648bb40, 1270, 57),
                          0x44af279: (0x648c188, 382, 34)}
    for site in sorted(sites):
        # A bounded instruction witness; no claim to decode its entire caller CFG.
        length = 23 if site == 0x44af279 else 21
        witness = decode(read_va(data, secs, site - 7, length), site - 7)
        require(witness[0]['mnemonic'] == 'lea' and witness[1]['mnemonic'] == 'call'
                and witness[1]['memory_va'] == SLOT, 'caller witness changed')
        if site == 0x44af279:
            require([r['mnemonic'] for r in witness[2:]] == ['cmp', 'jne']
                    and witness[-1]['target'] == 0x44af129, 'caller result use changed')
        else:
            require([r['mnemonic'] for r in witness[2:]] == ['test', 'jne', 'xorpd']
                    and witness[3]['target'] == site - 7 + length,
                    'caller result use changed')
        loc, line, column = expected_locations[site]
        require(witness[0]['memory_va'] == loc, 'caller Location target changed')
        location = source_location(data, secs, relocs, loc)
        require((location['line'], location['column']) == (line, column), 'Location coordinates changed')
        owner = owner_of(frames, starts, site)
        require(owner['start'] <= site - 7 and site - 7 + length <= owner['end'], 'witness escapes FDE')
        references.append({'site': site, 'slot': SLOT, 'resolved_target': START,
                           'owner_fde': frame_record(data, secs, owner),
                           'instructions': witness, 'location': location})
    return {
        'target': {'release': 115, 'sha256': SHA, 'size': len(data)},
        'window': {'start': START, 'end': END, 'size': len(body),
                   'file_offset': mapping(data, secs, START, len(body)),
                   'body_sha256': sha(body), 'body_bytes': body.hex(), 'frame': frame,
                   'padding': {'start': END, 'end': next_start, 'size': len(padding), 'bytes': padding.hex()}},
        'instructions': instructions, 'cfg': cfg, 'callees': [],
        'constants': constants, 'direct_reference_scan': direct,
        'entry_relocation': entry_refs[0], 'slot_references': references,
        'rule': {'input_registers': ['xmm0.low64: numerator', 'xmm1.low64: divisor'],
                 'status_register': 'eax (zero-extended into rax)',
                 'output_register': 'xmm0.low64',
                 'epsilon_bits': EPS,
                 'clamp_interval': 'negative epsilon < numerator < zero; both endpoints excluded',
                 'divisor_constraint': 'divisor >= positive epsilon',
                 'finite_filter': 'both inputs and the divided result have abs(bits) < infinity_bits',
                 'model_environment': 'binary64 round-to-nearest ties-to-even; DAZ/FTZ off; SSE exceptions masked',
                 'environment_established_by_leaf': False},
        'vectors': vectors(),
    }


def positive_ratio(bits):
    """Exact rational magnitude of a finite binary64 encoding, using only integers."""
    magnitude = bits & ABS
    exponent, fraction = magnitude >> 52, magnitude & ((1 << 52) - 1)
    require(exponent != 0x7ff, 'nonfinite rational input')
    significand = fraction if exponent == 0 else (1 << 52) | fraction
    shift = -1074 if exponent == 0 else exponent - 1023 - 52
    return (significand << shift, 1) if shift >= 0 else (significand, 1 << -shift)


def rounded_division(numerator, divisor):
    """Exact-rational binary64 division rounded to nearest/even, including subnormals."""
    an, ad = positive_ratio(numerator)
    bn, bd = positive_ratio(divisor)
    require(bn != 0, 'zero divisor outside rule domain')
    sign = (numerator ^ divisor) & SIGN
    if an == 0:
        return sign
    n, d = an * bd, ad * bn
    exponent = n.bit_length() - d.bit_length()
    below_power = n < (d << exponent) if exponent >= 0 else (n << -exponent) < d
    if below_power:
        exponent -= 1
    if exponent > 1023:
        return sign | INF
    unit = max(exponent - 52, -1074)
    scaled_n, scaled_d = (n, d << unit) if unit >= 0 else (n << -unit, d)
    quotient, remainder = divmod(scaled_n, scaled_d)
    if 2 * remainder > scaled_d or (2 * remainder == scaled_d and quotient & 1):
        quotient += 1
    if quotient == 0:
        return sign
    if unit == -1074 and quotient < (1 << 52):
        return sign | quotient
    exponent = unit + quotient.bit_length() - 1
    if exponent > 1023:
        return sign | INF
    if quotient.bit_length() == 54:
        quotient >>= 1
    return sign | ((exponent + 1023) << 52) | (quotient & ((1 << 52) - 1))


def model(numerator, divisor, epsilon=EPS):
    """Independent value model, not an instruction emulator or target execution."""
    require(all(type(v) is int and 0 <= v < (1 << 64) for v in (numerator, divisor)),
            'expected binary64 bit patterns')
    if (numerator & ABS) >= INF or (divisor & ABS) >= INF:
        return {'status': 0, 'xmm0_bits': numerator, 'division_reached': False}
    x = numerator
    if numerator & SIGN and 0 < (numerator & ABS) < epsilon:
        x = 0
    elif numerator & SIGN and (numerator & ABS) != 0:
        return {'status': 0, 'xmm0_bits': x, 'division_reached': False}
    if divisor & SIGN or divisor < epsilon:
        return {'status': 0, 'xmm0_bits': x, 'division_reached': False}
    result = rounded_division(x, divisor)
    return {'status': int((result & ABS) < INF), 'xmm0_bits': result, 'division_reached': True}


def vectors():
    """Boundary encodings chosen from the decoded masks, epsilon loads and branch rule."""
    one, two = 0x3ff0000000000000, 0x4000000000000000
    cases = [
        ('unit_ratio', one, one), ('half', one, two),
        ('positive_zero', 0, EPS), ('negative_zero_preserved', SIGN, EPS),
        ('negative_epsilon_rejected', SIGN | EPS, one),
        ('negative_just_inside_clamped', SIGN | (EPS - 1), one),
        ('negative_just_outside_rejected', SIGN | (EPS + 1), one),
        ('negative_min_subnormal_clamped', SIGN | 1, EPS),
        ('negative_clamp_before_bad_divisor', SIGN | (EPS - 1), 0),
        ('epsilon_divisor_equal', EPS, EPS),
        ('epsilon_divisor_below', EPS, EPS - 1),
        ('epsilon_divisor_above', EPS, EPS + 1),
        ('zero_divisor', one, 0), ('negative_zero_divisor', one, SIGN),
        ('negative_divisor', one, SIGN | one),
        ('max_finite_preserved', MAX_FINITE, one),
        ('finite_division_overflow', MAX_FINITE, EPS),
        ('minimum_subnormal_preserved', 1, one),
        ('subnormal_half_tie_to_zero', 1, two),
        ('subnormal_three_halves_tie_to_even', 3, two),
        ('positive_underflow', 1, MAX_FINITE),
        ('positive_infinity_input', INF, one), ('negative_infinity_input', SIGN | INF, one),
        ('quiet_nan_numerator', INF | (1 << 51) | 7, one),
        ('signaling_nan_numerator', INF | 1, one),
        ('nonfinite_divisor_precedes_clamp', SIGN | 1, INF),
        ('quiet_nan_divisor', one, INF | (1 << 51)),
        ('signaling_nan_divisor', one, INF | 1),
    ]
    return [{'name': name, 'numerator_bits': x, 'divisor_bits': y, **model(x, y)}
            for name, x, y in cases]


def json_bytes(record):
    return (json.dumps(record, indent=2, sort_keys=True) + '\n').encode('utf-8')


def render_readme(r):
    w, rule = r['window'], r['rule']
    f, padding, direct = w['frame'], w['padding'], r['direct_reference_scan']
    refs = r['slot_references']
    owners = {x['owner_fde']['start'] for x in refs}
    returns = sum(x['mnemonic'] == 'ret' for x in r['instructions'])
    branches = sum('target' in x for x in r['instructions'])
    walk = '\n'.join(f"| `{x['va']:#x}` | `{x['bytes']}` | `{x['mnemonic']} {x['operands']}` |"
                     for x in r['instructions'])
    callers = '\n'.join(f"| `{x['site']:#x}` | `{x['owner_fde']['start']:#x}..{x['owner_fde']['end']:#x}` | "
                        f"`{x['location']['path']}:{x['location']['line']}:{x['location']['column']}` |"
                        for x in refs)
    return f'''# RE-001: node #{r['target']['release']} finite ratio with a strict negative clamp

- Component: foundation arithmetic; first-party clearinghouse/vault caller association, not recovered source ownership.
- Target: `artifacts/node/{r['target']['release']}/hl-node`, {r['target']['size']:,} bytes, SHA-256 `{r['target']['sha256']}`.
- Source/reference baseline: `{BASE}`. New Python and evidence are independently authored under the repository MIT license; no inferred source copied.
- Bounded question: what does the complete leaf at `{w['start']:#x}` return for finite, nonfinite, near-zero and overflow-producing numerator/divisor inputs?
- Status: instruction/byte observations and an all-input value rule under the stated floating-point environment; source name and domain units unresolved.
- Intended new files: this packet, `tools/node115_finite_ratio_clamp.py`, and `tests/test_node115_finite_ratio_clamp.py`. Task RE-001; no existing work item or milestone edit.

The leaf takes a numerator in XMM0.low64 and divisor in XMM1.low64. It returns RAX zero for either nonfinite input. With finite inputs, it clamps the numerator to positive zero exactly when it is strictly between negative epsilon and zero; a numerator at or below negative epsilon rejects. Signed zero is admitted without clamping. A divisor below positive epsilon rejects; equality is admitted. Otherwise DIVSD computes the quotient in XMM0.low64 and RAX is one exactly when that quotient is finite. Epsilon is the binary64 encoding `{rule['epsilon_bits']:#018x}` (the rounded binary64 value of decimal `1e-15`, not the exact decimal rational). The model assumes nearest/even rounding, masked SSE exceptions and DAZ/FTZ disabled. This leaf neither sets nor proves that environment.

## Extent and closure

Original ELF virtual addresses are used throughout, with explicit file mappings in JSON. The window is `[{w['start']:#x}, {w['end']:#x})`, **{w['size']} bytes**, file offset `{w['file_offset']:#x}`. Body SHA-256: `{w['body_sha256']}`. The actual FDE is at VA/file offset `{f['fde']:#x}` / `{f['fde_file_offset']:#x}` and refers to CIE `{f['cie']:#x}`; LSDA is absent. Raw FDE/CIE records are in JSON. Following padding is `{padding['bytes']}`, **{padding['size']} INT3 bytes**, ending at the next FDE start `{padding['end']:#x}`. Padding is excluded from the body hash.

The strict Python decoder consumes **{len(r['instructions'])} instructions**, including **{branches} local branches** and **{returns} RET instructions**. Every instruction is reachable in the local CFG, every branch lands at an instruction start, and every path reaches a local RET. There are **{len(r['callees'])} callees**, no indirect dispatch, no stack frame, and no memory writes. Apart from RET's implicit return-address read, only the recorded read-only constants are loaded. Full body coverage and closed control flow support the function extent independently of treating an FDE as a function definition. No hot/cold helper or exceptional call is elided; floating-point traps remain subject to MXCSR. Valid instruction/constant mappings and an ordinary return-address stack are preconditions.

## Instruction walk and value proof

| VA | Bytes | Strict decode |
| --- | --- | --- |
{walk}

MOVQ and AND first clear each input's sign bit in integer registers. Signed SETG against MAX_FINITE is valid here because the sign-cleared words are nonnegative signed integers; exponent-all-ones encodings reject before any floating-point comparison. The zeroed XMM2 then compares zero with the numerator. On the negative route, UCOMISD against the recorded negative epsilon and JBE exclude equality from the clamp. The clamped route explicitly zeroes XMM0. On the other route, the second zero comparison rejects remaining negative inputs. Both divisor checks compare positive epsilon with the divisor and use JA, admitting equality. Finally DIVSD, MOVQ, sign masking, and signed SETL against the infinity encoding accept every finite result, including signed zero and subnormals, and reject overflow to infinity.

On an early rejection, XMM0 retains the original numerator unless the negative clamp has already run; that case leaves positive zero. On quotient overflow, XMM0 holds the quotient infinity and RAX is zero. Signaling/quiet NaNs are rejected by integer operations with their input XMM0 bits preserved. The input nonfinite check precedes clamping. RAX is always zero-extended from EAX on return. Other volatile register values, flags and upper vector lanes are not a source ABI claim.

The JSON contains **{len(r['constants'])} constant objects** and **{len(r['vectors'])} instruction-grounded boundary vectors**. The independent model uses exact integer rational division and explicit binary64 nearest/even rounding, including ties, underflow and overflow. It does not advance a captured PC or execute captured instructions. Tests separately freeze boundary expectations and compare the rational rounding helper with Python binary64 arithmetic on synthetic finite cases. These are static model checks, not a differential target run.

## Callers and source association

A full `.text` scan covers `[{direct['start']:#x}, {direct['end']:#x})`: each byte position at which an E8/E9 signed rel32 instruction fits is considered, including unaligned positions. It examined **{direct['examined_opcode_positions']['0xe8']} E8 positions** and **{direct['examined_opcode_positions']['0xe9']} E9 positions**, finding **{len(direct['matches'])} direct caller/tail-transfer candidates** to the entry. This raw scan cannot identify indirect callers or prove instruction alignment; the empty result is stronger than omitting unaligned matches, but is not a reachability claim.

The retained R_X86_64_RELATIVE relocation at file offset `{r['entry_relocation']['file_offset']:#x}` resolves slot `{r['entry_relocation']['slot']:#x}` to the leaf entry. A separate full `.text` FF15/FF25 RIP-relative scan found **{len(refs)} slot reference sites** in **{len(owners)} containing FDEs**. Each has a strictly decoded adjacent Location LEA and result-use witness. The witnesses and actual caller FDE/CIE records are retained; their entire caller bodies/CFGs are not semantically bound.

| Slot call site | Containing FDE range | Adjacent relocated Location |
| --- | --- | --- |
{callers}

The clearinghouse witnesses test the low status bit and replace XMM0 with zero on failure; the vault witness compares RAX with one and branches on inequality. The Location argument is unused by this leaf. These data relocations prove a first-party call-context association, not the leaf's original symbol, defining module or financial interpretation. Register-indirect references, copied function pointers, vtables, other relocation types and dynamically modified slots are outside this census.

## Novelty before binding

At the baseline above, before creating this packet, these commands each exited with status one, empty stdout and empty stderr:

```sh
rg -i '{w['start']:x}' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -i '{w['start']}' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -i 'finite-ratio-clamp' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -i 'finite_ratio_clamp' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

The leaf is inside the assigned band and outside the supplied claimed-address list. There are no callee behaviors requiring a second novelty check. These are pre-write observations against local PR title lists, not a fresh remote search; rerunning against the completed packet naturally finds this packet. Before: no local packet bound the entry. After: the entire leaf, constants, closed CFG, boundary rule and caller associations are independently regenerable.

## Reproduce and validation scope

Working directory: repository root. Generation and verification require Python 3.10+ standard library and the authenticated ELF; neither imports nor invokes objdump. Discovery used GNU binutils 2.44 on Linux x86-64; final Python checks used Python 3.13.5. Generated records contain no machine-local paths or runtime state. The whole input digest is checked before parsing or creating output, using a read-only memory map. Existing ELF/FDE parsers are hash-pinned in the whitelist manifest. All recorded byte comparisons are exact; there are no normalization masks.

```sh
python3 tools/node115_finite_ratio_clamp.py --out research/work-items/RE-001-node115-finite-ratio-clamp/
python3 -m unittest tests.test_node115_finite_ratio_clamp -v
python3 research/work-items/RE-001-node115-finite-ratio-clamp/verify.py
make verify
make catalogue-check
```

Negative controls cover wrong digest and same-size window mutation at the public gate, unsupported/truncated instruction encodings, changed mask/branch/constant operands, shifted actual FDE bytes, a wrong relocation-backed callee target, caller displacement and padding corruption, and missing/extra/changed manifest files. README counts are rendered only from JSON and the tests compare the complete README with that rendering. Packet verification checks the exact manifest whitelist and regenerates JSON/README from the authenticated binary. Repository-wide tests and hosted CI are not claimed here; final command outcomes are recorded in the uncommitted submission report.

## Non-claims, limitations and next step

No native target or emulator was run; no network, signing, chain action, install or deployment occurred. No Rust reconstruction, source build, compiled-byte equivalence, recovered Rust Result/Option type, complete financial operation, panic behavior, runtime MXCSR state, whole-caller closure, whole-ELF equivalence or component gate is claimed. Code/data/helper/relocation closure is limited to the complete leaf and its constant loads; caller data/type provenance and exception-environment integration remain open. No inventory/literal analysis input or catalogue was modified or reinterpreted. All progress gates remain unchanged.

Next: trace numerator/divisor production and the result consumers in the retained first-party caller contexts, then establish their runtime floating-point environment before assigning units or integrating a Rust implementation.
'''.encode('utf-8')


def payloads(record):
    return {'records.json': json_bytes(record), 'README.md': render_readme(record),
            'verify.py': (PACKET / 'verify.py').read_bytes()}


def manifest_bytes(files):
    hashes = {name: sha(value) for name, value in files.items()}
    hashes.update({name: sha((ROOT / name).read_bytes()) for name in SOURCE_FILES})
    return ''.join(f'{hashes[name]}  {name}\n' for name in sorted(hashes)).encode('ascii')


def generate(binary=TARGET, out=None):
    with Path(binary).open('rb') as handle:
        require(handle.seek(0, 2) > 0, 'node #115 digest mismatch')
        with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
            require(sha(data) == SHA, 'node #115 digest mismatch')
            record = inspect_static(data)
    files = payloads(record)
    files['MANIFEST.sha256'] = manifest_bytes(files)
    if out is not None:
        out = Path(out)
        out.mkdir(parents=True, exist_ok=True)
        for name, content in files.items():
            (out / name).write_bytes(content)
    return record, files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    record, _ = generate(args.binary, args.out)
    print(f"Bound {record['window']['start']:#x}: {record['window']['size']} bytes, "
          f"{len(record['instructions'])} instructions; static only")


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, struct.error) as error:
        print(f'finite-ratio-clamp: {error}', file=sys.stderr)
        raise SystemExit(1)
