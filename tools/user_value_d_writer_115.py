#!/usr/bin/env python3
"""Bind how node #115 writes the per-user value D field (stage 113).

Open PR #6223 found that the per-user value writer 0x3beac00 writes D (+0x28)
through 0x464d090. Open PR #6319 found that the D decoder 0x18d4f40 reads a
date-keyed map of {a, c}: entry 0x18 bytes, key dword at +0x0, a at +0x8,
c at +0x10, a small form (cap, ptr, 0, len) and a large form tagged
0x8000000000000000. This tool binds, from the bytes, the writer side:

1. 0x464d090 picks the form: a first word of i64::MIN (neg overflows) is the
   large form (root +0x8, height +0x10, length +0x18); any other value is the
   small form (cap +0x0, ptr +0x8, head +0x10, length +0x18) iterated as two
   slices of 0x18-byte entries (iterator tag 2);
2. 0x45fa240 writes D as a JSON list of [key, value] pairs: '[' then, for each
   entry, '[', the key (0x46f3a10), ',\\n', the value (0x3674da0), ']'. In the
   small form the key is entry+0x0 and the value entry+0x8;
3. 0x46f3a10 writes the key as a quoted string through core::fmt::write with
   the closure 0x44dbf10, which jumps to the date slot 0x64e1158 (the same slot
   the l date-time Display 0x46dd720 calls);
4. 0x3674da0 writes the value as an object: a (value+0x0) then c (value+0x8),
   each through the u64 field writer 0x465f980 and each left out when 0; if
   both are 0 it writes '{}'.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses.
"""
import argparse
import json
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from elf_index import sections

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-user-value-d-writer-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

D_SEQ = 0x464d090
PAIRS = 0x45fa240
KEY = 0x46f3a10
VALUE = 0x3674da0
FIELD = 0x465f980
U64_FORMAT = 0x46ef580
BTREE_NEXT = 0x37c4c80
KEY_CLOSURE = 0x44dbf10
DATE_SLOT = 0x64e1158
FMT_WRITE_SLOT = 0x64df6f0
L_DISPLAY_DATE_CALL = 0x46dd733

# Instruction bytes that frame the derived checks below.
PINS = {
    0x464d0da: '498b06',              # mov rax,[r14]             D first word
    0x464d0dd: '4889c1',              # mov rcx,rax
    0x464d0e0: '48f7d9',              # neg rcx                   overflows only for i64::MIN
    0x464d0e5: '498b4608',            # mov rax,[r14+0x8]         large: root
    0x464d0f7: '498b7618',            # mov rsi,[r14+0x18]        large: length
    0x464d0fb: '498b5610',            # mov rdx,[r14+0x10]        large: height
    0x464d109: '498b5618',            # mov rdx,[r14+0x18]        small: length
    0x464d112: '498b4e10',            # mov rcx,[r14+0x10]        small: head
    0x464d140: '498b5608',            # mov rdx,[r14+0x8]         small: ptr
    0x464d144: '488d0c49',            # lea rcx,[rcx+rcx*2]       0x18 entries
    0x464d148: '488d3cca',            # lea rdi,[rdx+rcx*8]
    0x45fa294: '48c1e803',            # shr rax,3                 /8 then *inv(3): /0x18
    0x45fa2e9: '498b4608',            # mov rax,[r14+0x8]
    0x45fa3a3: '4889442460',          # mov [rsp+0x60],rax        key pointer
    0x45fa3b0: '4889542458',          # mov [rsp+0x58],rdx        value pointer
    0x45fa540: '488b7c2460',          # mov rdi,[rsp+0x60]        key -> key writer
    0x45fa600: '488b7c2458',          # mov rdi,[rsp+0x58]        value -> value writer
    0x46f3a49: '488b4308',            # mov rax,[rbx+0x8]
    0x44dbf10: '488b07488b00488b38',  # closure: three loads, then jmp [slot]
    0x3674dbf: '4c8b2f',              # mov r13,[rdi]             a
    0x3674df2: '4c89f9',              # mov rcx,r15
    0x3674df5: '4c09e9',              # or rcx,r13                both zero -> '{}'
    0x3674e05: '4d85ed',              # test r13,r13              a == 0 -> skip a
    0x3674e1d: '4889d9',              # mov rcx,rbx               a value = value+0x0
    0x3674e32: '4d85ff',              # test r15,r15
    0x3674f39: '4d85ff',              # test r15,r15              c == 0 -> skip c
    0x3674f5a: '4889d9',              # mov rcx,rbx               c value = value+0x8
}
# direct calls: site -> target
CALLS = {
    0x464d19b: PAIRS,
    0x45fa395: BTREE_NEXT,
    0x45fa54d: KEY,
    0x45fa60d: VALUE,
    0x3674e20: FIELD,
    0x3674f5d: FIELD,
    0x465f9d0: U64_FORMAT,
}
# relative jumps: site -> (opcode bytes, target, meaning)
JUMPS = {
    0x464d0e3: ('71', 0x464d109, 'no overflow: small form'),
    0x3674df8: ('74', 0x3674e3d, 'a and c both 0: close the object'),
    0x3674e08: ('0f84', 0x3674f37, 'a == 0: go to the c test'),
    0x3674e35: ('0f85', 0x3674f42, 'after a, c != 0: write c'),
    0x3674f3c: ('0f84', 0x3674e65, 'c == 0: end'),
}
# (site, opcode prefix, instruction length, target)
RIP = (
    (0x3674e0e, b'\x48\x8d\x35', 7, 0x79d2d7),          # lea rsi, name a
    (0x3674f4b, b'\x48\x8d\x35', 7, 0x79d2d8),          # lea rsi, name c
    (0x46f3a79, b'\x48\x8d\x05', 7, KEY_CLOSURE),       # lea rax, key closure
    (0x46f3a9b, b'\xff\x15', 6, FMT_WRITE_SLOT),        # call [core::fmt::write]
    (0x44dbf19, b'\xff\x25', 6, DATE_SLOT),             # jmp [date Display]
    (L_DISPLAY_DATE_CALL, b'\xff\x15', 6, DATE_SLOT),   # l date-time uses the same slot
)
NAMES = {0x79d2d7: b'a', 0x79d2d8: b'c'}
# (site, opcode prefix, expected immediate or byte, meaning)
IMMEDIATES = (
    (0x464d15c, b'\x41\xb8', 4, 2, 'small form iterator tag (mov r8d,2)'),
    (0x45fa27d, b'\x48\x83\x7c\x24\x10', 1, 2, 'iterator tag compared with 2'),
    (0x45fa298, b'\x48\xb9', 8, 0xaaaaaaaaaaaaaaab, 'inverse of 3 (entry count = bytes / 0x18)'),
    (0x45fa375, b'\x48\x8d\x48', 1, 0x18, 'next entry = entry + 0x18'),
    (0x45fa37e, b'\x48\x8d\x50', 1, 0x08, 'value pointer = entry + 0x8'),
    (0x3674dc2, b'\x4c\x8b\x7f', 1, 0x08, 'c = value + 0x8 (mov r15,[rdi+8])'),
    (0x3674f47, b'\x48\x83\xc3', 1, 0x08, 'c field pointer = value + 0x8'),
    (0x3674e18, b'\xba', 4, 1, 'a name length 1'),
    (0x3674f55, b'\xba', 4, 1, 'c name length 1'),
)
# byte stores of JSON punctuation: (site, prefix, byte, meaning)
PUNCT = (
    (0x45fa2ed, b'\xc6\x04\x30', 0x5b, "outer '['"),
    (0x45fa4ca, b'\x42\xc6\x04\x38', 0x5b, "pair '['"),
    (0x45fa6d2, b'\x42\xc6\x04\x38', 0x5d, "pair ']'"),
    (0x46f3a4d, b'\xc6\x04\x30', 0x22, 'key opening quote'),
    (0x46f3ab5, b'\xc6\x04\x30', 0x22, 'key closing quote'),
    (0x3674de7, b'\xc6\x04\x01', 0x7b, "value '{'"),
    (0x3674e4e, b'\xc6\x04\x01', 0x7d, "empty value '}'"),
)
SEPARATOR = (0x45fa57d, b'\x66\x42\xc7\x04\x38', 0x0a2c)   # ',\n' between key and value


def read_va(data, va, size):
    hits = [s for s in sections(data)
            if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(hits) != 1:
        raise ValueError(f'expected one file-backed mapping at {va:#x}')
    off = hits[0]['offset'] + va - hits[0]['address']
    return data[off:off + size]


def rel_target(data, va, prefix, length):
    raw = read_va(data, va, length)
    if raw[:len(prefix)] != prefix:
        raise ValueError(f'instruction at {va:#x} changed')
    width = length - len(prefix)
    fmt = {1: '<b', 4: '<i'}[width]
    return va + length + struct.unpack_from(fmt, raw, len(prefix))[0]


def immediate(data, va, prefix, width):
    raw = read_va(data, va, len(prefix) + width)
    if raw[:len(prefix)] != prefix:
        raise ValueError(f'instruction at {va:#x} changed')
    return int.from_bytes(raw[len(prefix):], 'little')


def pin_check(data):
    for va, expect in PINS.items():
        if read_va(data, va, len(expect) // 2) != bytes.fromhex(expect):
            raise ValueError(f'instruction at {va:#x} changed')


def bind(data):
    pin_check(data)
    calls = {}
    for va, target in CALLS.items():
        if rel_target(data, va, b'\xe8', 5) != target:
            raise ValueError(f'call at {va:#x} changed')
        calls[hex(va)] = hex(target)
    jumps = {}
    for va, (op, target, meaning) in JUMPS.items():
        prefix = bytes.fromhex(op)
        length = len(prefix) + (1 if len(prefix) == 1 else 4)
        if rel_target(data, va, prefix, length) != target:
            raise ValueError(f'jump at {va:#x} changed')
        jumps[hex(va)] = {'target': hex(target), 'meaning': meaning}
    refs = {}
    for va, prefix, length, target in RIP:
        if rel_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
        refs[hex(va)] = hex(target)
    names = {}
    for va, name in NAMES.items():
        if read_va(data, va, 1) != name:
            raise ValueError(f'field name at {va:#x} changed')
        names[hex(va)] = name.decode()
    imms = {}
    for va, prefix, width, expect, meaning in IMMEDIATES:
        if immediate(data, va, prefix, width) != expect:
            raise ValueError(f'immediate at {va:#x} changed')
        imms[hex(va)] = {'value': hex(expect), 'meaning': meaning}
    punct = {}
    for va, prefix, byte, meaning in PUNCT:
        if immediate(data, va, prefix, 1) != byte:
            raise ValueError(f'punctuation at {va:#x} changed')
        punct[hex(va)] = {'byte': chr(byte), 'meaning': meaning}
    va, prefix, word = SEPARATOR
    if immediate(data, va, prefix, 2) != word:
        raise ValueError(f'separator at {va:#x} changed')
    punct[hex(va)] = {'byte': ',\\n', 'meaning': 'between key and value'}
    return {
        'target': {'path': RELATIVE, 'sha256': SHA256},
        'task': 'RE-008',
        'component': 'abci',
        'd_writer': hex(D_SEQ),
        'forms': {
            'test': 'neg of the first word overflows only for 0x8000000000000000',
            'large': {'tag_word': '+0x0 == 0x8000000000000000', 'root': '+0x8',
                      'height': '+0x10', 'length': '+0x18', 'iterator': hex(BTREE_NEXT)},
            'small': {'cap': '+0x0', 'ptr': '+0x8', 'head': '+0x10', 'length': '+0x18',
                      'iterator_tag': 2, 'entry_size': '0x18'},
        },
        'pairs_writer': {
            'function': hex(PAIRS),
            'shape': '[ [key, value], ... ]',
            'key_pointer': 'entry + 0x0',
            'value_pointer': 'entry + 0x8',
            'key_writer': hex(KEY),
            'value_writer': hex(VALUE),
        },
        'key_writer': {
            'function': hex(KEY),
            'shape': 'quoted string through core::fmt::write',
            'closure': hex(KEY_CLOSURE),
            'date_slot': hex(DATE_SLOT),
            'same_slot_as_l_date': hex(L_DISPLAY_DATE_CALL),
        },
        'value_writer': {
            'function': hex(VALUE),
            'order': ['a', 'c'],
            'a': {'value_offset': '+0x0', 'entry_offset': '+0x8', 'skip': 'value == 0'},
            'c': {'value_offset': '+0x8', 'entry_offset': '+0x10', 'skip': 'value == 0'},
            'both_zero': '{}',
            'field_writer': hex(FIELD),
            'integer_format': hex(U64_FORMAT) + ' (unsigned, per #6223)',
        },
        'link_6319': {'decoder': '0x18d4f40', 'item_decoder': '0x1be12b0',
                      'entry_size': '0x18', 'key': '+0x0', 'a': '+0x8', 'c': '+0x10',
                      'missing_field_default': 0},
        'calls': calls,
        'jumps': jumps,
        'references': refs,
        'names': names,
        'immediates': imms,
        'punctuation': punct,
        'pins': len(PINS),
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
    print(f"pins={result['pins']} calls={len(result['calls'])} jumps={len(result['jumps'])} "
          f"order={result['value_writer']['order']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
