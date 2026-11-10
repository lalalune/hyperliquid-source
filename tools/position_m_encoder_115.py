#!/usr/bin/env python3
"""Node #115 position field M: the value encoder writes the u32 as decimal text.

Open PR #6456 left one limit: it did not read the value encoder 0x4648d30
that the position writer 0x448ae20 calls for M. This tool checks that
encoder with fixed bytes only:

1. The writer M site (0x448affb) passes rcx = position + 0x38 (M), the
   1-byte key `M` and length 1, and calls 0x4648d30.
2. 0x4648d30 calls the entry-start writer 0x4713ba0 (it writes "\\n" for
   the first entry and ",\\n" for later ones), then writes ": " (0x203a),
   loads the 4-byte value (`mov edi,[rbx]`, rbx = rcx), calls 0x46ef430,
   copies the result through the GOT slot 0x64df508 (memcpy) and returns 0.
3. 0x46ef430 is a decimal u32 formatter. It fills a 10-byte buffer from the
   end: four digits per pass by division by 10000 (0xd1b71759, shift 45)
   while the value is above 99999999, two digits per step from the digit
   table 0x7d9d8e ("00".."99"), a last single digit with `or cl,0x30`. It
   returns the start and the length 10 - start.

So M is written as its full decimal text; no digit is dropped and the value
is not changed. The output is text (",\\n" and ": " separators), while the
position decoder 0x1bb6b90 (#6453, #6456) reads MessagePack markers. The
writer and that decoder do not share one encoding.

The tool only compares fixed bytes at fixed addresses, call targets,
relocations, a dynamic symbol name and table bytes. The captured binary is
not executed. objdump and readelf are not started. Addresses are ELF
virtual addresses.
"""
import argparse
import json
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from elf_index import sections

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-position-m-encoder-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

WRITER_SITE = 0x448affb
ENCODER = 0x4648d30
ENTRY_START = 0x4713ba0
FORMATTER = 0x46ef430
DIGITS = 0x7d9d8e
MEMCPY_SLOT = 0x64df508

PINS = {   # address -> (bytes, meaning)
    0x448affb: ('488d4b38488d35bb6334fc488d7c2410ba01000000e81bdd1b004885c0',
                'writer: rcx = +0x38 (M), key M, length 1, call 0x4648d30, test result'),
    0x4648d3b: ('4889cb4989fee85aae0c00',
                'encoder: keep value pointer in rbx; call entry start 0x4713ba0'),
    0x4648d64: ('498b460866c704303a204883c602498976108b3b498b1c244889e6e8ac660a00',
                'encoder: append ": "; edi = u32 at [rbx]; call formatter 0x46ef430'),
    0x4648d9b: ('488b7b084c01ff4889c64c89f2ff155a67e9014d01f74c897b1041c64424200131c0',
                'encoder: copy digits via slot 0x64df508; mark entry written; return 0'),
    0x4713bd3: ('4d8b6c24104d392c240f847c010000498b44240842c604280a49ffc5eb26',
                'entry start: first entry appends "\\n"'),
    0x4713c07: ('498b4424086642c704282c0a4983c502',
                'entry start: later entry appends ",\\n"'),
    0x46ef431: ('b80a00000081ff102700000f82aa000000b90a000000ba5917b7d1',
                'formatter: start index 10; below 10000 skips the 4-digit loop; magic 1/10000'),
    0x46ef46d: ('4189f94c0fafca49c1e92d4569d910270000',
                'formatter: q = value / 10000 (mul 0xd1b71759, shr 45)'),
    0x46ef4c6: ('81ffffe0f5054489cf778f',
                'formatter: repeat while value > 99999999'),
    0x46ef4e4: ('80c930880c06',
                'formatter: last single digit = value | 0x30'),
    0x46ef541: ('4883f80a7710ba0a0000004829c24801c64889f05bc3',
                'formatter: return start pointer and length 10 - start'),
}

# lea site -> table address used by the formatter
DIGIT_LOADS = (0x46ef44c, 0x46ef515, 0x46ef532)

# call / jmp site -> (opcode bytes, instruction length, target)
JUMPS = {0x448b010: ('e8', 5, ENCODER), 0x4648d41: ('e8', 5, ENTRY_START),
         0x4648d7f: ('e8', 5, FORMATTER)}

KEY_LEA = (0x448afff, 0x7d13c1, b'M')


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


def jumps(data):
    out = {}
    for site, (op, length, target) in JUMPS.items():
        if read_va(data, site, len(op) // 2) != bytes.fromhex(op) or rel_target(data, site, length) != target:
            raise ValueError(f'call at {site:#x} is not to {target:#x}')
        out[hex(site)] = hex(target)
    return out


def key(data):
    site, addr, text = KEY_LEA
    if read_va(data, site, 3) != b'\x48\x8d\x35' or rel_target(data, site, 7) != addr:
        raise ValueError(f'key load at {site:#x} is not {addr:#x}')
    if read_va(data, addr, len(text)) != text:
        raise ValueError(f'key at {addr:#x} is not {text!r}')
    if read_va(data, 0x448b00b, 5) != b'\xba\x01\x00\x00\x00':
        raise ValueError('key length is not 1')
    return {'site': hex(site), 'address': hex(addr), 'text': text.decode(), 'length': 1}


def separators(data):
    # mov word [rax+rsi],0x203a -> bytes 3a 20 = ": "
    if read_va(data, 0x4648d6c, 2) != b': ':
        raise ValueError('encoder no longer appends ": "')
    if read_va(data, 0x4713beb, 1) != b'\n':
        raise ValueError('first entry no longer starts with "\\n"')
    if read_va(data, 0x4713c11, 2) != b',\n':
        raise ValueError('later entry no longer starts with ",\\n"')
    return {'after_key': ': ', 'first_entry': '\\n', 'later_entry': ',\\n'}


def digit_table(data):
    want = b''.join(f'{i:02d}'.encode() for i in range(100))
    if read_va(data, DIGITS, len(want)) != want:
        raise ValueError(f'digit table at {DIGITS:#x} is not "00".."99"')
    for site in DIGIT_LOADS:
        if read_va(data, site + 1, 1) != b'\x8d' or rel_target(data, site, 7) != DIGITS:
            raise ValueError(f'lea at {site:#x} is not the digit table')
    return {'address': hex(DIGITS), 'entries': 100, 'loads': [hex(s) for s in DIGIT_LOADS]}


def formatter(data):
    if read_va(data, 0x46ef432, 4) != struct.pack('<I', 10):
        raise ValueError('formatter buffer is not 10 bytes')
    if read_va(data, 0x46ef448, 4) != struct.pack('<I', 0xd1b71759) or read_va(data, 0x46ef477, 1) != b'\x2d':
        raise ValueError('formatter division by 10000 changed')
    if read_va(data, 0x46ef4c8, 4) != struct.pack('<I', 99999999):
        raise ValueError('formatter loop bound changed')
    if read_va(data, 0x46ef4e6, 1) != b'\x30':
        raise ValueError('formatter single digit is not ASCII')
    if read_va(data, 0x4648d76, 2) != b'\x8b\x3b':
        raise ValueError('encoder does not pass a 4-byte value')
    return {'function': hex(FORMATTER), 'input': 'u32 (edi)', 'buffer': 10, 'output': 'decimal ASCII digits',
            'max_digits': 10, 'digit_table': digit_table(data)}


def memcpy_slot(data):
    call = read_va(data, 0x4648da8, 6)
    if call[:2] != b'\xff\x15' or 0x4648da8 + 6 + struct.unpack('<i', call[2:])[0] != MEMCPY_SLOT:
        raise ValueError('encoder copy does not call slot 0x64df508')
    secs = {s['name']: s for s in sections(data)}
    dynsym, dynstr = secs['.dynsym'], secs['.dynstr']
    for sec in sections(data):
        if sec['type'] != 4:
            continue
        for va, info, _ in struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']]):
            if va != MEMCPY_SLOT:
                continue
            if info & 0xffffffff != 6:
                raise ValueError('slot 0x64df508 is not a GLOB_DAT relocation')
            name_off = struct.unpack_from('<I', data, dynsym['offset'] + 24 * (info >> 32))[0]
            start = dynstr['offset'] + name_off
            name = data[start:data.index(b'\0', start)].decode()
            if name != 'memcpy':
                raise ValueError(f'slot 0x64df508 is bound to {name}, not memcpy')
            return {'slot': hex(MEMCPY_SLOT), 'symbol': name}
    raise ValueError('no relocation for slot 0x64df508')


def bind(data):
    pin_check(data)
    return {
        'target': {'path': RELATIVE, 'sha256': SHA256},
        'writer_m_site': {'site': hex(WRITER_SITE), 'value': '+0x38', 'key': key(data)},
        'encoder': {'function': hex(ENCODER), 'entry_start': hex(ENTRY_START),
                    'separators': separators(data), 'copy': memcpy_slot(data)},
        'formatter': formatter(data),
        'calls': jumps(data),
        'result': {
            'm_text': 'full unsigned decimal of the 4-byte M, after "M" and ": "',
            'value_changed': False,
            'encoding': 'text; the position decoder 0x1bb6b90 reads MessagePack (#6453)',
        },
        'links': {'closes_limit_of': '#6456', 'writer': '#6224 (0x448ae20)'},
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
    print(f"pins={result['pins']} formatter={result['formatter']['function']} "
          f"copy={result['encoder']['copy']['symbol']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
