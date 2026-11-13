#!/usr/bin/env python3
"""Bind the node #115 JSON shape of the abci_hashes `exchange_abci_hash` tree (54th stage).

The 53rd stage found that each abci_hashes line carries the hash tree under the
key `exchange_abci_hash`, written by the field writer 0x506d4e0: tag 1 goes to
the node writer 0x5025a10 and any other tag writes the 32 leaf bytes. This tool
binds the exact byte shape:

1. field writer 0x506d4e0: ',' unless the state byte at +0x1 is 1 (first
   field), then '"' key '"' ':' and the value; tag 1 tail-jumps to 0x5025a10,
   other tags write the 32 bytes at value +0x1 through the leaf writer;
2. node writer 0x5025a10: '[' then, per 0x30-byte element, '[' index ','
   child ']', elements separated by ','; then ']'; an empty Vec writes "[]";
   child tag 1 (element +0x8) recurses on element +0x10, other tags write the
   32 bytes at element +0x9;
3. index: element +0x0 as an unsigned decimal through 0x50fc010 (20-byte
   buffer, two-digit table 0x91b2fc, /10000 by the 0x346dc5d63886594b
   multiply);
4. leaf writer 0x4e1c250: hex through slot 0x64e4d08 (trim byte 0, capacity
   0x42, 0x20 input bytes) then '"' string '"' via 0x50a3510; a zero-length
   input writes the 2-byte literal "0x" at 0x918564.

No byte between tokens is a space or newline. The captured binary is not
executed. Addresses are ELF virtual addresses; ends are exclusive.
"""
import argparse
import json
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import direct_calls, fixed, read_va, rip_target

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-abci-hashes-tree-json-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

FIELD, NODE, LEAF, UINT = 0x506d4e0, 0x5025a10, 0x4e1c250, 0x50fc010
HEX_SLOT, ESCAPE = 0x64e4d08, 0x50a3510
DIGITS, EMPTY_HEX = 0x91b2fc, 0x918564

FIXED = {
    # field writer: separator, key quotes, colon, tag dispatch, leaf arguments
    0x506d4ee: '803f01',                # cmp byte [rdi], 1            (unreachable state)
    0x506d4fe: '807f0101',              # cmp byte [rdi+1], 1          (first field)
    0x506d502: '741f',                  # je -> skip ','
    0x506d518: 'c604012c',              # ','
    0x506d523: 'c6470102',              # state byte := 2
    0x506d53b: 'c6040122',              # '"' before key
    0x506d55f: 'c6043022',              # '"' after key
    0x506d581: 'c604303a',              # ':'
    0x506d58c: '803a01',                # cmp byte [value], 1          (node tag)
    0x506d58f: '751d',                  # jne -> leaf
    0x506d5d1: 'be42000000',            # capacity 0x42
    0x506d5d6: 'b920000000',            # 0x20 bytes
    # node writer: brackets, separators, element stride, child dispatch
    0x5025a3a: 'c604305b',              # '['  node open
    0x5025a5f: 'c604305b',              # '['  first element open
    0x5025abf: '42c604202c',            # ','  index/child
    0x5025acb: '41807e0801',            # cmp byte [elem+8], 1
    0x5025ad0: '7538',                  # jne -> leaf
    0x5025ad2: '498d7610',              # lea rsi, [elem+0x10]         (child Vec)
    0x5025afa: 'c604305d',              # ']'  empty node close
    0x5025b28: '498d5609',              # lea rdx, [elem+9]            (leaf bytes)
    0x5025b31: 'be42000000',            # capacity 0x42
    0x5025b36: 'b920000000',            # 0x20 bytes
    0x5025b61: 'c604305d',              # ']'  first element close
    0x5025b87: 'c604305d',              # ']'  node close (one element)
    0x5025ba3: '488d046d00000000',      # rbp*2
    0x5025bab: '4801e8',                # + rbp
    0x5025bae: '48c1e004',              # << 4                         (0x30 stride)
    0x5025bd5: 'c604302c',              # ','  between elements
    0x5025bfc: 'c604305b',              # '['  later element open
    0x5025c65: 'c604302c',              # ','  index/child
    0x5025c71: '807b0801',              # cmp byte [elem+8], 1
    0x5025cae: '498d56f9',              # lea rdx, [r14-7] = elem+9
    0x5025cb2: 'be42000000',
    0x5025cb7: 'b920000000',
    0x5025ceb: 'c604305d',              # ']'  later element close
    0x5025cf6: '4983c630',              # r14 += 0x30
    0x5025cfa: '4883c330',              # rbx += 0x30
    # leaf writer
    0x4e1c258: '4885c9',                # test rcx, rcx                (length 0?)
    0x4e1c25b: '7453',                  # je -> "0x" literal
    0x4e1c25d: '4531c0',                # trim byte 0
    0x4e1c27a: 'c6043122',              # '"'
    0x4e1c29d: 'c6043022',              # '"'
    0x4e1c2d2: 'ba02000000',            # literal length 2
    # unsigned decimal
    0x50fc011: 'b814000000',            # 20-byte buffer
    0x50fc016: '4881ff10270000',        # cmp rdi, 10000
    0x50fc028: '49b84b598638d6c56d34',  # movabs r8, 0x346dc5d63886594b
    0x50fc057: '4c69da10270000',        # imul r11, rdx, 10000
}
REFERENCES = (
    # (instruction va, prefix, length, target)
    (0x506d5a9, b'\xe9', 5, NODE),
    (0x506d5de, b'\xe8', 5, LEAF),
    (0x5025a72, b'\xe8', 5, UINT),
    (0x5025add, b'\xe8', 5, NODE),
    (0x5025b42, b'\xe8', 5, LEAF),
    (0x5025c10, b'\xe8', 5, UINT),
    (0x5025c81, b'\xe8', 5, NODE),
    (0x5025cc8, b'\xe8', 5, LEAF),
    (0x4e1c260, b'\xff\x15', 6, HEX_SLOT),
    (0x4e1c28b, b'\xe8', 5, ESCAPE),
    (0x4e1c2cb, b'\x48\x8d\x35', 7, EMPTY_HEX),
    (0x4e1c2da, b'\xe8', 5, ESCAPE),
    (0x50fc032, b'\x4c\x8d\x0d', 7, DIGITS),
)


def render_tree(children):
    """Render a node exactly as the decoded writer does: children are (index, leaf bytes | list)."""
    parts = []
    for index, child in children:
        value = render_tree(child) if isinstance(child, list) else '"0x' + child.hex() + '"'
        parts.append('[' + str(index) + ',' + value + ']')
    return '[' + ','.join(parts) + ']'


EXAMPLE = [(0, bytes(range(0x00, 0x20))), (3, bytes(range(0x20, 0x40)))]


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    if read_va(data, EMPTY_HEX, 2) != b'0x' or read_va(data, DIGITS, 6) != b'000102':
        raise ValueError('string constants changed')

    node_end = next(f['end'] for f in fdes if f['start'] == NODE)
    node_calls = direct_calls(data, NODE)
    if sorted(v for v in node_calls if NODE <= v < node_end) != [0x5025add, 0x5025c81]:
        raise ValueError('node recursion sites changed')
    leaf_calls = direct_calls(data, LEAF)
    example = render_tree(EXAMPLE)
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'field_writer': {
            'fn': hex(FIELD),
            'shape': '[","] "\\"" key "\\"" ":" value; comma skipped while state byte +0x1 == 1',
            'node_tail_jump': hex(0x506d5a9) + ' -> ' + hex(NODE),
            'leaf': hex(0x506d5de) + ' -> ' + hex(LEAF) + ' (value +0x1, 0x20 bytes, capacity 0x42)',
        },
        'node_writer': {
            'fn': hex(NODE),
            'direct_calls_in_fn': sorted(hex(v) for v in node_calls if NODE <= v < node_end),
            'element_stride': '0x30 (rbp*3 << 4)',
            'shape': '"[" ( "[" index "," child "]" ) *("," ...) "]"; empty Vec -> "[]"',
            'child': 'tag byte elem+0x8 == 1 -> recurse on elem+0x10; else leaf bytes elem+0x9',
            'index': 'elem+0x0 unsigned decimal via ' + hex(UINT),
        },
        'leaf_writer': {
            'fn': hex(LEAF),
            'direct_calls': len(leaf_calls),
            'shape': '"\\"0x" + 64 lowercase hex + "\\"" (hex slot ' + hex(HEX_SLOT) + ', trim 0)',
            'zero_length': 'writes literal "0x" at ' + hex(EMPTY_HEX),
        },
        'uint_writer': {'fn': hex(UINT), 'buffer': 20, 'digit_pairs': hex(DIGITS)},
        'whitespace': 'none written between tokens',
        'derived_example': {
            'children': [[i, b.hex()] for i, b in EXAMPLE],
            'json': example,
            'length': len(example),
            'status': 'derived from the bound writer logic, not executed',
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
    print(f"example_length={result['derived_example']['length']} leaf_calls={result['leaf_writer']['direct_calls']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
