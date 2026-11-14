#!/usr/bin/env python3
"""Census the node #115 callers of the 0x-prefixed hex encoder (fifty-first stage).

The fiftieth stage found that abci hash-tree leaves are written as d9 42
"0x" + 64 lowercase hex digits by the encoder 0x2eabb50, reached through slot
0x64e4d08. This tool binds:

1. the encoder: rdi = output, rsi = output capacity, rdx = input bytes,
   rcx = input length, r8b = trim flag; it requires capacity > 2*len + 1,
   writes "0x" first, and with r8b set skips the first byte's high hex digit
   when that digit is 0; digits come from the table 0x455d40;
2. a census of every `call [rip+disp]` to the slot (629 sites; no direct
   `call rel32` to 0x2eabb50; 39 RIP-relative loads of the slot are listed
   but not classified);
3. fixed-shape sites, where the 24 bytes before the call hold
   `mov esi, imm32; mov ecx, imm32` and end with `xor r8d, r8d`:
   20 bytes into 42 (440 sites), 32 bytes into 66 (123 sites, including the
   two hash-tree leaf sites of the fiftieth stage), 16 bytes into 34
   (46 sites); every fixed shape has capacity = 2*len + 2 and no trim;
4. the 20 remaining sites, with their enclosing FDE and trim flag.

The captured binary is not executed. objdump and readelf are not started.
"""
import argparse
import bisect
import collections
import json
import re
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import RELATIVE, TARGET, SHA256, read_va, fixed, relative_relocations, text, direct_calls

PACKET = ROOT / 'research/work-items/RE-008-hex-digest-callers-115'
SLOT, ENCODER, TABLE = 0x64e4d08, 0x2eabb50, 0x455d40
LEAF_SITES = (0x41c5203, 0x41c794d)

FIXED = {
    0x2eabb51: '488d044d01000000',  # lea rax, [rcx*2+1]
    0x2eabb59: '4839c6',            # cmp rsi, rax
    0x2eabb5c: '0f8622010000',      # jbe (capacity too small)
    0x2eabb62: '66c7073078',        # mov word [rdi], "0x"
    0x2eabb77: '41c1ea04',          # shr r10d, 4 (high digit)
    0x2eabb7b: '410f94c3',          # sete r11b (high digit == 0)
    0x2eabb84: '4584d8',            # test r8b, r11b (trim)
    0x2eabb87: '7514',              # jne: skip the high digit
    0x2eabb89: '488d05b0a15afd',    # lea rax, [rip -> 0x455d40]
    0x41c51f6: 'be42000000',        # leaf site: mov esi, 0x42
    0x41c51fb: 'b920000000',        # mov ecx, 0x20
    0x41c5200: '4531c0',            # xor r8d, r8d
}
TAGS = (b'tx_hash', b'block_hash', b'hash', b'evm', b'abci', b'digest', b'user', b'address')
SHAPE = re.compile(rb'\xbe(.)\x00\x00\x00\xb9(.)\x00\x00\x00', re.S)


def slot_sites(data):
    base, code = text(data)
    calls, loads = [], []
    for m in re.finditer(rb'\xff\x15', code):
        i = m.start()
        if i + 6 <= len(code) and base + i + 6 + struct.unpack_from('<i', code, i + 2)[0] == SLOT:
            calls.append(base + i)
    for m in re.finditer(rb'[\x48\x4c]\x8b[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', code):
        i = m.start()
        if i + 7 <= len(code) and base + i + 7 + struct.unpack_from('<i', code, i + 3)[0] == SLOT:
            loads.append(base + i)
    return calls, loads


def classify(data, calls):
    base, code = text(data)
    shapes, other = collections.defaultdict(list), []
    for va in calls:
        i = va - base
        window = code[i - 24:i]
        found = list(SHAPE.finditer(window)) if window[-3:] == b'\x45\x31\xc0' else []
        if found:
            shapes[(found[-1].group(1)[0], found[-1].group(2)[0])].append(va)
            continue
        if window[-3:] == b'\x45\x31\xc0':
            trim = 0
        elif window[-6:-4] == b'\x41\xb8':
            trim = struct.unpack_from('<I', window, 20)[0]
        else:
            trim = None
        other.append((va, trim))
    return shapes, other


def function_of(fdes):
    ordered = sorted(fdes, key=lambda f: f['start'])
    starts = [f['start'] for f in ordered]

    def start(va):
        k = bisect.bisect_right(starts, va) - 1
        if k < 0 or not ordered[k]['start'] <= va < ordered[k]['end']:
            raise ValueError(f'{va:#x} has no FDE')
        return ordered[k]['start']
    return start


def string_ties(data, fdes, functions):
    """Per tag, how many of the functions load (lea rip) a string that starts with that tag."""
    base, code = text(data)
    ends = {f['start']: f['end'] for f in fdes}
    ties = collections.Counter()
    for start in functions:
        seg = code[start - base:ends[start] - base]
        seen = set()
        for m in re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', seg):
            if m.start() + 7 > len(seg):
                continue
            target = start + m.start() + 7 + struct.unpack_from('<i', seg, m.start() + 3)[0]
            try:
                head = read_va(data, target, 16)
            except ValueError:
                continue
            seen.update(t.decode() for t in TAGS if head.startswith(t))
        ties.update(seen)
    return dict(sorted(ties.items()))


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    if relative_relocations(data).get(SLOT) != ENCODER:
        raise ValueError('slot no longer points at the encoder')
    if read_va(data, TABLE, 16) != b'0123456789abcdef':
        raise ValueError('hex table changed')
    if direct_calls(data, ENCODER):
        raise ValueError('direct calls to the encoder appeared')
    calls, loads = slot_sites(data)
    shapes, other = classify(data, calls)
    fn = function_of(fdes)
    for (cap, length) in shapes:
        if cap != 2 * length + 2:
            raise ValueError(f'shape capacity {cap:#x} does not fit length {length:#x}')
    if not all(site in shapes.get((0x42, 0x20), []) for site in LEAF_SITES):
        raise ValueError('hash-tree leaf sites left the 32-byte shape')
    table = {}
    for (cap, length), sites in sorted(shapes.items(), key=lambda kv: -len(kv[1])):
        table['%d_bytes' % length] = {
            'capacity': cap, 'output_chars': cap - 2, 'trim': 0, 'sites': len(sites),
            'functions': len({fn(v) for v in sites}), 'first_sites': [hex(v) for v in sites[:5]],
            'functions_loading_tag_strings': string_ties(data, fdes, {fn(v) for v in sites}),
        }
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'encoder': {
            'fn': hex(ENCODER), 'slot': hex(SLOT), 'table': hex(TABLE),
            'arguments': 'rdi out, rsi capacity, rdx bytes, rcx length, r8b trim',
            'requires': 'capacity > 2*length + 1', 'prefix': '0x',
            'trim': 'skip the first byte high digit when it is 0 and r8b is set',
        },
        'census': {
            'slot_calls': len(calls), 'direct_calls': 0, 'slot_loads': len(loads),
            'fixed_shape_sites': sum(len(v) for v in shapes.values()), 'other_sites': len(other),
        },
        'fixed_shapes': table,
        'leaf_sites_in_32_byte_shape': [hex(v) for v in LEAF_SITES],
        'other_sites': [{'site': hex(v), 'function': hex(fn(v)),
                         'trim': 'set earlier' if t is None else t} for v, t in other],
        'slot_loads': [hex(v) for v in loads],
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
    c = result['census']
    print(f"slot_calls={c['slot_calls']} fixed={c['fixed_shape_sites']} other={c['other_sites']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
