#!/usr/bin/env python3
"""Node #115 callers of the second MessagePack position decoder 0x32d3c90.

Open PR #6580 found that 0x32d3c90 is a second MessagePack position decoder
(success tag 9) and named its two direct callers, 0x318126c and 0x372f3ae,
without mapping them. This tool checks:

1. 0x372f3ae is in 0x372f280, the map-form visitor. For each entry it reads
   the key through 0x2f48380 with the name `Perp` (4), then the value
   through 0x32d3c90. Entries are 0x48 bytes (`lea rcx,[rbx+rbx*8]`, store
   at `[rax+rcx*8]`).
2. 0x318126c is in 0x3180b40. Its only direct caller is 0x37b7b6e in
   0x37b7a80, the array-form visitor, which calls it once per element.
3. Both visitors have one direct caller, 0x314bba0. It reads one
   MessagePack marker: fixmap (below 0x90) goes to 0x372f280, fixarray
   (0x90 to 0x9f) goes to 0x37b7a80. So the two callers are the map form
   and the array form of one map decoder, 0x314bba0.
4. 0x314bba0 has two direct callers, both in 0x3184540. That function reads
   its keys with 0x2fd31e0 (result tag 9). 0x2fd31e0 maps the 1-byte key
   `p` and the 16-byte key `perp_to_position` to index 0, `n` and
   `n_open_positions` to index 1, and any other key to 2. These are the
   keys of the per-user `p` field decoder 0x191bf90 in #6239, so 0x3184540
   is a second decoder of the same `p` value.
5. One call to 0x314bba0 (0x318480b) runs after a not-seen check against
   0x8000000000000001; the other (0x3184deb) runs after a non-zero length
   check.
6. 0x3184540 has two direct callers, at 0x30bd552 and 0x30be015, both in
   0x30bcb40. They are counted, not mapped.

The tool only compares fixed bytes at fixed addresses, branch and call
targets, function starts from .eh_frame_hdr, a count of direct `call rel32`
instructions in .text, and strings. The captured binary is not executed.
objdump and readelf are not started. Addresses are ELF virtual addresses.
"""
import argparse
import bisect
import json
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from elf_index import sections, unwind_index

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-position-decoder-callers-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

DECODER = 0x32d3c90
MAP_VISITOR = 0x372f280
SEQ_VISITOR = 0x37b7a80
ELEMENT = 0x3180b40
MAP_DECODER = 0x314bba0
P_DECODER = 0x3184540
P_MATCHER = 0x2fd31e0
P_MATCHER_END = 0x2fd3319
UPPER = 0x30bcb40

PINS = {   # address -> (bytes, meaning)
    0x372f305: ('488d0cdb4c8924c844896cc808', 'map visitor: entry index * 9 * 8 (0x48-byte entries)'),
    0x372f37a: ('488d7c2450488b742448488d1545add2fce8f08f81ff0fb64424503c090f854c010000'
                '4c8b642458488d7c2450488b74244831d2e8dd48baff448b6c24504183fd02',
                'map visitor: key read with name Perp (4), tag 9, then value via 0x32d3c90'),
    0x314bbf5: ('3c90730a240f4189c0e99b0000003ca0730a240f4189c0e93b010000',
                'map decoder: below 0x90 -> map form, below 0xa0 -> array form'),
    0x314bcc2: ('4889742450895c2458488d7c2428488d742450e8a6355e00',
                'map form: call 0x372f280'),
    0x314bd70: ('4889742450895c2458488d7c2428488d742450e8f8bc6600',
                'array form: call 0x37b7a80'),
    0x37b7b61: ('488dbc24000100004c89fe31d2e8cd8f9cff448bac24080100004183fd02',
                'array visitor: element via 0x3180b40'),
    0x318125f: ('488dbc24c00000004889de31d2e81f2a1500', 'element: value via 0x32d3c90'),
    0x3184aea: ('488d7c24384c89ee4c89fae8e6e6e4ff807c2438097555',
                'p decoder: key via 0x2fd31e0, tag 9'),
    0x31847e9: ('48b801000000000000804839442418488d7c24380f8509120000410fb656244c89f6'
                'e89073fcff',
                'p decoder: not-seen check, then call 0x314bba0'),
    0x3184dd6: ('85ed0f842b030000410fb65624488d7c24384c89f6e8b06dfcff',
                'p decoder: non-zero length check, then call 0x314bba0'),
}

# call / jump site -> (opcode bytes, instruction length, target)
JUMPS = {0x372f38b: ('e8', 5, 0x2f48380), 0x372f3ae: ('e8', 5, DECODER),
         0x314bbf7: ('73', 2, 0x314bc03), 0x314bbfe: ('e9', 5, 0x314bc9e),
         0x314bc0c: ('e9', 5, 0x314bd4c),
         0x314bcd5: ('e8', 5, MAP_VISITOR), 0x314bd83: ('e8', 5, SEQ_VISITOR),
         0x37b7b6e: ('e8', 5, ELEMENT), 0x318126c: ('e8', 5, DECODER),
         0x3184af5: ('e8', 5, P_MATCHER),
         0x318480b: ('e8', 5, MAP_DECODER), 0x3184deb: ('e8', 5, MAP_DECODER)}
# lea site -> (address, length, text)
LEAS = {0x372f384: (0x45a0d0, 4, 'Perp')}
# call site -> function that holds it (from .eh_frame_hdr)
HOLDERS = {0x372f3ae: MAP_VISITOR, 0x318126c: ELEMENT, 0x37b7b6e: SEQ_VISITOR,
           0x314bcd5: MAP_DECODER, 0x314bd83: MAP_DECODER,
           0x318480b: P_DECODER, 0x3184deb: P_DECODER, 0x3184af5: P_DECODER,
           0x30bd552: UPPER, 0x30be015: UPPER}
# function -> its direct `call rel32` sites in .text
CALLERS = {DECODER: (0x318126c, 0x372f3ae), MAP_VISITOR: (0x314bcd5,),
           SEQ_VISITOR: (0x314bd83,), ELEMENT: (0x37b7b6e,),
           MAP_DECODER: (0x318480b, 0x3184deb), P_DECODER: (0x30bd552, 0x30be015)}
# key text -> field index the matcher returns
P_KEYS = {'p': 0, 'n': 1, 'perp_to_position': 0, 'n_open_positions': 1}
MATCHER_BYTES = (
    '4883fa10742683fa010f85210100000fb6063c6e0f94c1b20228ca31c93c700fb6c20f44c188'
    '4701c60709c30fb60683f86e0f849800000083f8700f85ef000000807e01650f85e5000000807e'
    '02720f85db000000807e03700f85d1000000807e045f0f85c7000000807e05740f85bd000000807e'
    '066f0f85b3000000807e075f0f85a9000000807e08700f859f000000807e096f0f8595000000807e'
    '0a730f858b000000807e0b690f8581000000807e0c74757b807e0d697575807e0e6f756f807e0f6e'
    '756931c0884701c60709c3807e015f755a807e026f7554807e0370754e807e04657548807e056e75'
    '42807e065f753c807e07707536807e086f7530807e0973752a807e0a697524807e0b74751e807e0c'
    '697518807e0d6f7512807e0e6e750cb001807e0f730f84f5feffffb002884701c60709c3')


def read_va(data, va, size):
    hits = [s for s in sections(data)
            if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(hits) != 1:
        raise ValueError(f'expected one file-backed mapping at {va:#x}')
    off = hits[0]['offset'] + va - hits[0]['address']
    return data[off:off + size]


def rel_target(data, va, length):
    width = 1 if length == 2 else 4
    fmt = '<b' if width == 1 else '<i'
    return va + length + struct.unpack(fmt, read_va(data, va + length - width, width))[0]


def pin_check(data):
    for va, (want, meaning) in PINS.items():
        raw = bytes.fromhex(want)
        if read_va(data, va, len(raw)) != raw:
            raise ValueError(f'instruction bytes changed at {va:#x} ({meaning})')
    raw = bytes.fromhex(MATCHER_BYTES)
    if len(raw) != P_MATCHER_END - P_MATCHER or read_va(data, P_MATCHER, len(raw)) != raw:
        raise ValueError(f'instruction bytes changed at {P_MATCHER:#x} (p key matcher)')


def matcher_keys(data):
    """Spell the 16-byte keys from the compare bytes of 0x2fd31e0."""
    body = read_va(data, P_MATCHER, P_MATCHER_END - P_MATCHER)
    # `cmp eax,imm8` for the first byte: n is tested first (je to the second run), then p
    firsts = [body[i + 2] for i in range(len(body) - 2) if body[i:i + 2] == b'\x83\xf8']
    if firsts != [ord('n'), ord('p')]:
        raise ValueError('first-byte compares of the long keys changed')
    runs, run = [], []
    for i in range(len(body) - 3):
        if body[i:i + 2] == b'\x80\x7e':
            idx, ch = body[i + 2], body[i + 3]
            if idx == 1 and run:
                runs.append(run)
                run = []
            run.append((idx, ch))
    runs.append(run)
    if len(runs) != 2 or any([i for i, _ in r] != list(range(1, 16)) for r in runs):
        raise ValueError('long-key compare runs changed')
    # first run belongs to p, second to n
    spelled = ['p' + bytes(c for _, c in runs[0]).decode(),
               'n' + bytes(c for _, c in runs[1]).decode()]
    if spelled != ['perp_to_position', 'n_open_positions']:
        raise ValueError(f'long keys spell {spelled}, not perp_to_position / n_open_positions')
    return {k: P_KEYS[k] for k in ('p', 'n', 'perp_to_position', 'n_open_positions')}


def jumps(data):
    out = {}
    for site, (op, length, target) in JUMPS.items():
        if read_va(data, site, len(op) // 2) != bytes.fromhex(op) or rel_target(data, site, length) != target:
            raise ValueError(f'branch at {site:#x} is not to {target:#x}')
        out[hex(site)] = hex(target)
    return out


def leas(data):
    out = {}
    for site, (addr, length, text) in LEAS.items():
        if read_va(data, site + 1, 1) != b'\x8d' or rel_target(data, site, 7) != addr:
            raise ValueError(f'lea at {site:#x} is not to {addr:#x}')
        if read_va(data, addr, length) != text.encode():
            raise ValueError(f'string at {addr:#x} is not {text!r}')
        out[hex(site)] = {'address': hex(addr), 'text': text}
    return out


def holders(data):
    _, entries = unwind_index(data)
    starts = [e['start'] for e in entries]
    out = {}
    for site, func in HOLDERS.items():
        i = bisect.bisect_right(starts, site) - 1
        if i < 0 or starts[i] != func or not site < entries[i]['next_index_upper_bound']:
            raise ValueError(f'call site {site:#x} is not in function {func:#x}')
        out[hex(site)] = hex(func)
    return out


def callers(data):
    text = [s for s in sections(data) if s['name'] == '.text' and s['type'] != 8]
    if len(text) != 1:
        raise ValueError('expected one .text section')
    sec = text[0]
    body = data[sec['offset']:sec['offset'] + sec['size']]
    base = sec['address']
    found = {f: [] for f in CALLERS}
    pos = body.find(b'\xe8')
    while 0 <= pos <= len(body) - 5:
        target = base + pos + 5 + struct.unpack_from('<i', body, pos + 1)[0]
        if target in found:
            found[target].append(base + pos)
        pos = body.find(b'\xe8', pos + 1)
    out = {}
    for func, want in CALLERS.items():
        if tuple(found[func]) != want:
            raise ValueError(f'direct callers of {func:#x} are '
                             f'{[hex(x) for x in found[func]]}, not {[hex(x) for x in want]}')
        out[hex(func)] = [hex(x) for x in want]
    return out


def bind(data):
    pin_check(data)
    return {
        'target': {'path': RELATIVE, 'sha256': SHA256},
        'decoder': hex(DECODER),
        'map_form': {'visitor': hex(MAP_VISITOR), 'key_name': 'Perp', 'entry_bytes': 0x48},
        'array_form': {'visitor': hex(SEQ_VISITOR), 'element': hex(ELEMENT)},
        'map_decoder': {'function': hex(MAP_DECODER),
                        'fixmap': hex(MAP_VISITOR), 'fixarray': hex(SEQ_VISITOR)},
        'p_decoder': {'function': hex(P_DECODER), 'key_matcher': hex(P_MATCHER),
                      'ok_tag': 9, 'keys': matcher_keys(data), 'other_key': 2,
                      'map_decoder_calls': {'0x318480b': 'after not-seen check',
                                            '0x3184deb': 'after non-zero length check'}},
        'upper_boundary': {'function': hex(UPPER), 'mapped': False},
        'branches': jumps(data),
        'leas': leas(data),
        'holders': holders(data),
        'direct_callers': callers(data),
        'links': {'second_msgpack_decoder': '#6580', 'p_field_first_decoder': '#6239'},
        'pins': len(PINS) + 1,
        'gates_changed': False,
    }


def render(result):
    return (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()


def generate(binary=TARGET, output=PACKET):
    identity = manifest_item(ROOT, RELATIVE)
    check(binary, identity)
    if identity['sha256'] != SHA256:
        raise ValueError('pinned node #115 digest changed')
    result = bind(binary.read_bytes())
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
    print(f"pins={result['pins']} map_decoder={result['map_decoder']['function']} "
          f"p_decoder={result['p_decoder']['function']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
