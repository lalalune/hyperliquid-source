#!/usr/bin/env python3
"""Bind the node #115 abci hash tree byte encoding fed to the root BLAKE3 (fiftieth stage).

Continues the abci hash packets (#6024 BLAKE3 digest, #6027 slots, #6029 tree
fold). #6029 found that the root step 0x41c5140 serialises the slot tree and
hashes those bytes. This tool binds the encoder bytes:

1. root 0x41c5140: the serializer state holds a Vec, a config dword 0x400 at
   +0x8 and a byte 0 at +0xc; a root tag byte 1 goes to the node encoder
   0x41444a0 with the node at +0x8, any other tag hex-encodes the 32 bytes at
   +0x1 and writes them as a string;
2. node 0x41444a0: writes an array header with the element count through
   0x3d50270, then encodes each 0x30-byte element through 0x41c7780;
3. element 0x41c7780: with config byte +0xc != 2 it writes a 2-element array
   header, the u64 index at element +0x0 through 0x41d2670 -> 0x3d517e0,
   then the child at +0x8: tag byte != 0 recurses into 0x41444a0 with the
   node at +0x10, tag 0 hex-encodes the 32 bytes at +0x9;
4. array header 0x3d50270 / marker 0x3d52310: len < 0x10 -> 0x90 | len,
   len < 0x10000 -> 0xdc, else 0xdd;
5. uint 0x3d517e0: < 0x80 one byte, < 0x100 0xcc, < 0x10000 0xcd,
   < 2^32 0xce, else 0xcf;
6. string 0x41c6110: len < 0x20 -> 0xa0 | len, len < 0x100 -> 0xd9 len8;
7. hex 0x2eabb50 (slot 0x64e4d08): writes "0x" then two lowercase digits per
   byte from table 0x455d40 "0123456789abcdef"; both callers pass 0x42 output
   bytes, 0x20 input bytes and r8 = 0 (no leading-zero trim), so a leaf is
   always the 66-byte string 0xd9 0x42 "0x" + 64 hex digits.

These are the MessagePack (rmp) markers; the label is an inference from the
marker values. derived_example() rebuilds the bytes for a small tree from the
bound rules only; the captured binary is not executed. Addresses are ELF
virtual addresses.
"""
import argparse
import json
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import direct_calls, fixed, read_va, relative_relocations, rip_target

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-abci-hash-tree-encoding-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

ROOT_FN = 0x41c5140
NODE = 0x41444a0
ELEMENT = 0x41c7780
INDEX = 0x41d2670
ARRAY_LEN = 0x3d50270
MARKER = 0x3d52310
UINT = 0x3d517e0
STR = 0x41c6110
HEX = 0x2eabb50
HEX_SLOT = 0x64e4d08
HEX_TABLE = 0x455d40

FIXED = {
    # root: serializer config and root dispatch
    0x41c5185: 'c744242800040000',      # mov dword [rsp+0x28], 0x400       (config +0x8)
    0x41c518d: 'c644242c00',            # mov byte [rsp+0x2c], 0            (config +0xc)
    0x41c5192: '803e01',                # cmp byte [rsi], 1                 (root tag)
    0x41c5197: '4883c208',              # add rdx, 8                        (node at +0x8)
    0x41c51eb: '48ffc2',                # inc rdx                           (leaf digest at +0x1)
    0x41c51f6: 'be42000000',            # mov esi, 0x42                     (66 output bytes)
    0x41c51fb: 'b920000000',            # mov ecx, 0x20                     (32 input bytes)
    0x41c5200: '4531c0',                # xor r8d, r8d                      (no trim)
    # node: count from the Vec, header, 0x30-byte stride
    0x41444b9: '4c8b6a08',              # mov r13, [rdx+0x8]                (ptr)
    0x41444bd: '4c8b7210',              # mov r14, [rdx+0x10]               (len)
    0x41444cb: '807e0c00',              # cmp byte [rsi+0xc], 0
    0x4144503: '4489f2',                # mov edx, r14d                     (header len)
    0x4144650: '4b8d0476',              # lea rax, [r14+r14*2]
    0x4144654: '48c1e004',              # shl rax, 4                        (len * 0x30)
    0x414469c: '4983c730',              # add r15, 0x30
    # element: [index, child]
    0x41c77b0: '41807c240c02',          # cmp byte [r12+0xc], 2
    0x41c7800: 'ba02000000',            # mov edx, 2                        (2-element array)
    0x41c7840: '498b17',                # mov rdx, [r15]                    (index)
    0x41c7875: '410fb64708',            # movzx eax, byte [r15+0x8]         (child tag)
    0x41c787a: '84c0',                  # test al, al
    0x41c787c: '0f8475010000',          # je leaf
    0x41c7882: '4983c710',              # add r15, 0x10                     (child node)
    0x41c7a1e: '4983c709',              # add r15, 9                        (child digest)
    0x41c7a27: 'be42000000',            # mov esi, 0x42
    0x41c7a2c: 'b920000000',            # mov ecx, 0x20
    0x41c7a34: '4531c0',                # xor r8d, r8d
    # array header
    0x3d5027e: '81fa00000100',          # cmp edx, 0x10000
    0x3d50284: '0f92c0',                # setb al
    0x3d50287: '34dd',                  # xor al, 0xdd                      (0xdc / 0xdd)
    0x3d50289: '83fa10',                # cmp edx, 0x10
    0x3d5028f: 'bd90000000',            # mov ebp, 0x90
    0x3d50294: '0f43e8',                # cmovae ebp, eax
    # marker: 0x90 | (len & 0xf)
    0x3d52329: '81f990000000',          # cmp ecx, 0x90
    0x3d52353: '4080e60f',              # and sil, 0xf
    0x3d52357: '4080ce90',              # or sil, 0x90
    # uint
    0x3d517f0: '4881fa00010000',        # cmp rdx, 0x100
    0x3d51810: '84d2',                  # test dl, dl
    0x3d51812: '0f8800010000',          # js -> 0xcc path
    0x3d51825: '881430',                # mov [rax+rsi], dl                 (fixint)
    0x3d51925: 'c60430cc',              # mov byte [rax+rsi], 0xcc
    0x3d5183c: '4881fa00000100',        # cmp rdx, 0x10000
    0x3d51855: 'c64308cd',              # 0xcd
    0x3d5185e: '48c1e820',              # shr rax, 0x20
    0x3d51874: 'c64308ce',              # 0xce
    0x3d5188b: 'c64308cf',              # 0xcf
    # string
    0x41c6126: '4183fe20',              # cmp r14d, 0x20
    0x41c612c: 'b3a0',                  # mov bl, 0xa0
    0x41c6133: '4181fe00010000',        # cmp r14d, 0x100
    0x41c6160: 'c60430d9',              # mov byte [rax+rsi], 0xd9
    # hex
    0x2eabb62: '66c7073078',            # mov word [rdi], 0x7830            ("0x")
}
CALLS = (
    # (call site, target)
    (0x41c51a5, NODE), (0x41c5211, STR), (0x4144506, ARRAY_LEN), (0x4144689, ELEMENT),
    (0x41c7805, ARRAY_LEN), (0x41c784d, INDEX), (0x41c7893, NODE), (0x41c7a45, STR),
    (0x41d2745, UINT), (0x3d502bd, MARKER),
)
SLOT_CALLS = ((0x41c5203, HEX_SLOT), (0x41c7a37, HEX_SLOT))
TABLE_REFS = ((0x2eabb89, b'\x48\x8d\x05'), (0x2eabbaa, b'\x4c\x8d\x15'))


def call_target(data, va):
    raw = read_va(data, va, 5)
    if raw[0] != 0xe8:
        raise ValueError(f'call at {va:#x} changed')
    return va + 5 + struct.unpack_from('<i', raw, 1)[0]


# Derived encoder: built only from the bound rules above.
def enc_array_len(n):
    if n < 0x10:
        return bytes([0x90 | n])
    if n < 0x10000:
        return b'\xdc' + n.to_bytes(2, 'big')
    return b'\xdd' + n.to_bytes(4, 'big')


def enc_uint(v):
    if v < 0x80:
        return bytes([v])
    if v < 0x100:
        return b'\xcc' + bytes([v])
    if v < 0x10000:
        return b'\xcd' + v.to_bytes(2, 'big')
    if v < 1 << 32:
        return b'\xce' + v.to_bytes(4, 'big')
    return b'\xcf' + v.to_bytes(8, 'big')


def enc_leaf(digest):
    s = b'0x' + digest.hex().encode()
    return (bytes([0xa0 | len(s)]) if len(s) < 0x20 else b'\xd9' + bytes([len(s)])) + s


def enc_tree(tree):
    """tree: 32-byte digest (leaf) or list of (index, subtree) (node)."""
    if isinstance(tree, (bytes, bytearray)):
        return enc_leaf(bytes(tree))
    out = enc_array_len(len(tree))
    for index, child in tree:
        out += enc_array_len(2) + enc_uint(index) + enc_tree(child)
    return out


def derived_example():
    a, b = bytes(range(32)), bytes(range(32, 64))
    blob = enc_tree([(0, a), (3, b)])
    return {
        'tree': 'node [(0, leaf 00..1f), (3, leaf 20..3f)]',
        'length': len(blob),
        'prefix_hex': blob[:6].hex(),
        'second_element_head_hex': blob[71:76].hex(),
        'second_element_offset': 71,
        'status': 'derived from the bound encoder rules, not executed',
    }


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for site, target in CALLS:
        if call_target(data, site) != target:
            raise ValueError(f'call at {site:#x} changed')
    for site, slot in SLOT_CALLS:
        if rip_target(data, site, b'\xff\x15', 6) != slot:
            raise ValueError(f'slot call at {site:#x} changed')
    if relative_relocations(data).get(HEX_SLOT) != HEX:
        raise ValueError('hex slot relocation changed')
    for site, prefix in TABLE_REFS:
        if rip_target(data, site, prefix, 7) != HEX_TABLE:
            raise ValueError(f'hex table reference at {site:#x} changed')
    if read_va(data, HEX_TABLE, 16) != b'0123456789abcdef':
        raise ValueError('hex table changed')
    node_calls = direct_calls(data, NODE)
    element_calls = direct_calls(data, ELEMENT)
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'root': {
            'fn': hex(ROOT_FN),
            'config': '+0x8 dword 0x400, +0xc byte 0 (0x41c5185, 0x41c518d)',
            'dispatch': 'tag byte 1 -> node encoder %s (node at +0x8); else leaf string of 32 bytes at +0x1'
                        % hex(NODE),
        },
        'node': {
            'fn': hex(NODE),
            'header': 'array header with the Vec length via %s' % hex(ARRAY_LEN),
            'elements': '0x30-byte stride, each via %s' % hex(ELEMENT),
            'direct_calls': [hex(v) for v in node_calls],
        },
        'element': {
            'fn': hex(ELEMENT),
            'layout': 'index u64 at +0x0; child tag byte at +0x8; node Vec at +0x10; leaf digest at +0x9',
            'encoding': 'array header 2 (config byte +0xc != 2), index via %s -> %s, child' % (hex(INDEX), hex(UINT)),
            'direct_calls': [hex(v) for v in element_calls],
        },
        'markers': {
            'array': {'len < 0x10': '0x90 | len', 'len < 0x10000': '0xdc + u16', 'else': '0xdd + u32'},
            'uint': {'< 0x80': 'one byte', '< 0x100': '0xcc', '< 0x10000': '0xcd', '< 2^32': '0xce',
                     'else': '0xcf'},
            'str': {'len < 0x20': '0xa0 | len', 'len < 0x100': '0xd9 + u8'},
            'label': 'MessagePack (rmp) markers (inference from values)',
        },
        'leaf': {
            'hex_fn': hex(HEX) + ' via slot ' + hex(HEX_SLOT),
            'format': '"0x" + 64 lowercase hex digits (table %s), 66 bytes, header 0xd9 0x42' % hex(HEX_TABLE),
            'callers_pass': 'esi 0x42, ecx 0x20, r8d 0 (both callers)',
        },
        'derived_example': derived_example(),
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
    ex = result['derived_example']
    print('node_calls=%d element_calls=%d example_len=%d' % (
        len(result['node']['direct_calls']), len(result['element']['direct_calls']), ex['length']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
