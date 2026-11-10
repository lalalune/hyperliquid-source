#!/usr/bin/env python3
"""Node #115 position field M: the decoder rejects 0 and the writer skips 20.

Open PR #6453 found that the position decoder 0x1bb6b90 gives a missing M
the default 0x14 (20), and that its end-of-map code also turns an M of 0
into 20. Open PR #6224 mapped the position writer 0x448ae20. This tool
checks whether M can change on a write and read:

1. The M arm of the decoder (0x1bb6f07) treats a stored 0 as "not seen"
   (duplicate check `cmp dword [rsp+0x48],0`), calls 0x2d15d00 and keeps
   the 4-byte result at rsp+0x48.
2. 0x2d15d00 jumps to 0x17e4bb0 with the name `MarginTableId`, which reads
   the value through slot 0x64e25d8. The slot is relocated to 0x34861d0.
3. 0x34861d0 picks an arm by MessagePack marker (jump table 0x78db10).
   Every integer arm tests the value for zero (or for <= 0, or for the
   range 1..0xffffffff) and sends a failing value to the error code at
   0x34864c8. That code builds `invalid value: ..., expected ...` with
   the expected text `a nonzero u32` (0x38dbaa0).
4. The writer 0x448ae20 reads M at +0x38, counts the field only when
   M != 0x14, and skips the `M` key and value when M == 0x14.

So the decoder never gives 0 to the M arm, a missing M reads as 20, and
the writer leaves out only 20. The tool only compares fixed bytes at fixed
addresses, jump-table entries, branch and call targets, relocation values
and strings. The captured binary is not executed. objdump and readelf are
not started. Addresses are ELF virtual addresses.
"""
import argparse
import json
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from elf_index import sections

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-position-m-zero-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

M_ARM = 0x1bb6f07
M_DECODER = 0x2d15d00
NAMED_READ = 0x17e4bb0
INT_SLOT = 0x64e25d8
INT_READ = 0x34861d0
MARKER_TABLE = 0x78db10      # markers 0xc0..0xe0
ERROR_ZERO = 0x34864c8       # Unsigned(0)
ERROR_SIGNED = (0x34864d3, 0x34864d7, 0x348654c)
ERROR_UNSIGNED = 0x34864e3   # Unsigned(value) for a u64 out of range
EXPECTED_VTABLE_FMT = 0x646c068
EXPECTED_FMT = 0x38dbaa0
WRITER = 0x448ae20

PINS = {   # address -> (bytes, meaning)
    0x1bb6f07: ('837c2448000f85b91000004c89f64c89efe8e3ed15010fb604243c090f85950e0000'
                '8b44240489442448e964feffff',
                'decoder M arm: 0 means not seen; call 0x2d15d00; keep u32 at rsp+0x48'),
    0x2d15d00: ('488d15380d90fdb90d000000e99feeacfe',
                'M decoder: name MarginTableId (13), jump 0x17e4bb0'),
    0x17e4cd4: ('0fb6d10fb6c84889e7ff15f5d8cf040fb604248b4c24043c09750f894b04c60309'
                '4889d84883c4305bc3',
                'named read: call slot 0x64e25d8; tag 9 keeps the u32'),
    0x3486230: ('4585c0750d84c90f85b9000000e986020000',
                'positive fixint: value 0 -> 0x34864c8'),
    0x34862bc: ('488b46184885c00f8452010000488b561048ffc80fb60a48ffc2488956104889461885'
                'c90f84e2010000894f04e977010000',
                'u8: test ecx; je 0x34864c8'),
    0x3486334: ('488b4610488b4e184883f902723d4883c1fe0fb7104883c0024889461048894e1866'
                '85d20f846a01000066c1c2080fb7c2894704e9f8000000',
                'u16: test dx; je 0x34864c8'),
    0x3486286: ('488b4610488b4e184883f9040f82e70000004883c1fc8b104883c0044889461048894e'
                '1885d20f84160200000fca895704e9a9010000',
                'u32: test edx; je 0x34864c8'),
    0x34863fe: ('488b4e10488b56184883fa087326',
                'u64: 8 bytes left -> 0x3486432'),
    0x3486432: ('4883c2f8488b014883c108480fc848894e104889561848b900000000ffffffff488d14'
                '0848ffc14839ca0f8281000000894704',
                'u64: value - 2^32 below 2^64 - 2^32 + 1 (0 or > 0xffffffff) -> 0x34864e3'),
    0x348638b: ('488b46184885c00f8483000000488b561048ffc8480fbe0a48ffc24889561048894618'
                '4885c90f8e95010000894f04e9a6000000',
                'i8: test rcx; jle 0x348654c'),
    0x3486301: ('488b4610488b4e184883f90272704883c1fe0fb71066c1c2084883c0024889461048'
                '894e186685d27f37480fbfc2e9a3010000',
                'i16: test dx; jg ok, else 0x34864d7'),
    0x3486254: ('488b4610488b4e184883f9040f82190100004883c1fc8b104883c0040fca48894610'
                '48894e1885d27f364863c2e951020000',
                'i32: test edx; jg ok, else 0x34864d7'),
    0x34863bf: ('488b4e10488b56184883fa08723f4883c2f8488b014883c108480fc848894e104889'
                '561848b900000000ffffffff488d140848ffc14839ca7369e9d9000000',
                'i64: range 1..0xffffffff, else 0x34864d7'),
    0x34862ee: ('84c90f8edd010000',
                'negative fixint: jle 0x34864d3'),
    0x34864c8: ('48c744244000000000eb15480fbec14889442440c644243802eb0a4889442440c64424'
                '3801488d4424074889442408488d05525bfe024889442410488d4424384889442418'
                '488b05bc9905034889442420488d4424084889442428488d05263b0a01488944243048'
                '8d353505fcfc488d5424184889fbe8fd01bcff',
                'error: Unexpected (1 unsigned / 2 signed), expected vtable 0x646c050, '
                'template 0x446a6b, call 0x3046740'),
    0x38dbaa0: ('488b3e488b4608488b4018488d35fb9606fdba0d000000ffe0',
                'expected text: a nonzero u32 (13)'),
    0x448ae5d: ('448b4338488b5328488b4b304c8b3e4531e448894c24284885c9410f95c431ed4489'
                '4424244183f814400f95c5',
                'writer: M from +0x38; field count +1 only when M != 0x14'),
    0x448aff4: ('837c2424147459488d4b38488d35bb6334fc488d7c2410ba01000000e81bdd1b00',
                'writer: M == 0x14 skips; else key M (1) and value +0x38'),
    0x1bb7b4c: ('83fd02b914000000448b9c24ec000000440f44d90f44e8448b7424484585f6440f44f1',
                'decoder end of map: M 0 (not seen) -> 0x14'),
}

# marker -> (arm, zero-test site, test bytes, branch site, branch opcode, branch length,
#            jmp site, error). With no jmp site the branch goes to the error.
# With a jmp site the branch skips the error for a good value, and the jmp
# at that site goes to the error.
ZERO_TESTS = {
    0xcc: (0x34862bc, 0x34862de, '85c9', 0x34862e0, '0f84', 6, None, ERROR_ZERO),
    0xcd: (0x3486334, 0x3486355, '6685d2', 0x3486358, '0f84', 6, None, ERROR_ZERO),
    0xce: (0x3486286, 0x34862aa, '85d2', 0x34862ac, '0f84', 6, None, ERROR_ZERO),
    0xd0: (0x348638b, 0x34863ae, '4885c9', 0x34863b1, '0f8e', 6, None, 0x348654c),
    0xd1: (0x3486301, 0x3486326, '6685d2', 0x3486329, '7f', 2, 0x348632f, 0x34864d7),
    0xd2: (0x3486254, 0x348627a, '85d2', 0x348627c, '7f', 2, 0x3486281, 0x34864d7),
    0xe0: (0x34862ee, 0x34862ee, '84c9', 0x34862f0, '0f8e', 6, None, 0x34864d3),
}
# u64 and i64 take a range test: movabs rcx,0xffffffff00000000;
# lea rdx,[rax+rcx]; inc rcx; cmp rdx,rcx. Only 1..0xffffffff pass.
# marker -> (arm, movabs site, branch site, branch opcode, branch length, jmp site, error)
RANGE_TESTS = {
    0xcf: (0x34863fe, 0x3486448, 0x348645c, '0f82', 6, None, ERROR_UNSIGNED),
    0xd3: (0x34863bf, 0x34863e3, 0x34863f7, '73', 2, 0x34863f9, 0x34864d7),
}
FIXINT = (0x3486235, '84c9', 0x3486237, 0x348623d, ERROR_ZERO)   # test cl; jne ok; jmp error
ERROR_TAGS = {ERROR_ZERO: (0x34864c8, '48c744244000000000', 'Unsigned(0)'),
              0x34864e3: (0x34864e3, '4889442440c644243801', 'Unsigned(value)')}

# call / jmp site -> (opcode bytes, instruction length, target)
JUMPS = {0x1bb6f18: ('e8', 5, M_DECODER), 0x2d15d0c: ('e9', 5, NAMED_READ),
         0x348653e: ('e8', 5, 0x3046740), 0x448b010: ('e8', 5, 0x4648d30),
         0x448aff9: ('74', 2, 0x448b054)}

# lea site -> (string address, length, text)
STRINGS = {0x2d15d00: (0x616a3f, 13, 'MarginTableId'),
           0x38dbaab: (0x9451ad, 13, 'a nonzero u32'),
           0x448afff: (0x7d13c1, 1, 'M'),
           0x348652f: (0x446a6b, 1, '\x0f')}
TEMPLATE = {0x446a6c: 'invalid value: ', 0x446a7d: ', expected '}

M_DEFAULT = 0x14


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


def table(data, base, i):
    return base + struct.unpack('<i', read_va(data, base + 4 * i, 4))[0]


def relative_relocations(data):
    rel = {}
    for sec in sections(data):
        if sec['type'] != 4:
            continue
        if sec['size'] % 24:
            raise ValueError(f"relocation section {sec['name']} is truncated")
        for va, info, addend in struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']]):
            if info & 0xffffffff == 8:
                rel[va] = addend
    return rel


def pin_check(data):
    for va, (want, meaning) in PINS.items():
        raw = bytes.fromhex(want)
        if read_va(data, va, len(raw)) != raw:
            raise ValueError(f'instruction bytes changed at {va:#x} ({meaning})')


def jumps(data):
    out = {}
    for site, (op, length, target) in JUMPS.items():
        if read_va(data, site, len(op) // 2) != bytes.fromhex(op) or rel_target(data, site, length) != target:
            raise ValueError(f'branch at {site:#x} is not to {target:#x}')
        out[hex(site)] = hex(target)
    return out


def strings(data):
    out = {}
    for site, (addr, length, text) in STRINGS.items():
        if read_va(data, site + 1, 1) != b'\x8d' or rel_target(data, site, 7) != addr:
            raise ValueError(f'lea at {site:#x} is not to {addr:#x}')
        if read_va(data, addr, length) != text.encode():
            raise ValueError(f'string at {addr:#x} is not {text!r}')
        out[hex(site)] = {'address': hex(addr), 'length': length, 'text': text}
    for addr, text in TEMPLATE.items():
        if read_va(data, addr, len(text)) != text.encode():
            raise ValueError(f'template piece at {addr:#x} is not {text!r}')
    out['template'] = 'invalid value: {}, expected {}'
    return out


def slots(data):
    rel = relative_relocations(data)
    want = {INT_SLOT: INT_READ, EXPECTED_VTABLE_FMT: EXPECTED_FMT}
    for slot, target in want.items():
        if rel.get(slot) != target:
            raise ValueError(f'slot {slot:#x} is not relocated to {target:#x}')
    call = read_va(data, 0x17e4cdd, 6)
    if call[:2] != b'\xff\x15' or 0x17e4cdd + 6 + struct.unpack('<i', call[2:])[0] != INT_SLOT:
        raise ValueError('named read does not call slot 0x64e25d8')
    return {hex(k): hex(v) for k, v in want.items()}


def branch(data, site, op, length, jmp, error):
    if read_va(data, site, len(op) // 2) != bytes.fromhex(op):
        return False
    got = rel_target(data, site, length)
    if jmp is None:
        return got == error
    return got != error and read_va(data, jmp, 1) == b'\xe9' and rel_target(data, jmp, 5) == error


def zero_rejected(data):
    out = {}
    for marker, (arm, test_site, test, br, op, length, jmp, error) in ZERO_TESTS.items():
        if table(data, MARKER_TABLE, marker - 0xc0) != arm:
            raise ValueError(f'marker {marker:#x} does not go to {arm:#x}')
        if read_va(data, test_site, len(test) // 2) != bytes.fromhex(test):
            raise ValueError(f'marker {marker:#x}: zero test changed at {test_site:#x}')
        if not branch(data, br, op, length, jmp, error):
            raise ValueError(f'marker {marker:#x}: zero does not reach the error {error:#x}')
        out[hex(marker)] = {'arm': hex(arm), 'error': hex(error)}
    for marker, (arm, movabs, br, op, length, jmp, error) in RANGE_TESTS.items():
        if table(data, MARKER_TABLE, marker - 0xc0) != arm:
            raise ValueError(f'marker {marker:#x} does not go to {arm:#x}')
        want = bytes.fromhex('48b900000000ffffffff488d140848ffc14839ca')
        if read_va(data, movabs, len(want)) != want:
            raise ValueError(f'marker {marker:#x}: range test changed at {movabs:#x}')
        if not branch(data, br, op, length, jmp, error):
            raise ValueError(f'marker {marker:#x}: out-of-range value does not reach {error:#x}')
        out[hex(marker)] = {'arm': hex(arm), 'error': hex(error), 'accepts': '1..0xffffffff'}
    test_site, test, br, jmp, error = FIXINT
    if read_va(data, 0x3486230, 3) != bytes.fromhex('4585c0'):
        raise ValueError('positive fixint path changed')
    if read_va(data, test_site, 2) != bytes.fromhex(test) or read_va(data, br, 2) != b'\x0f\x85':
        raise ValueError('positive fixint zero test changed')
    if read_va(data, jmp, 1) != b'\xe9' or rel_target(data, jmp, 5) != error:
        raise ValueError('positive fixint 0 does not reach the error')
    out['fixint'] = {'arm': '0x3486230', 'error': hex(error)}
    for error, (site, raw, meaning) in ERROR_TAGS.items():
        if read_va(data, site, len(raw) // 2) != bytes.fromhex(raw):
            raise ValueError(f'error entry {site:#x} ({meaning}) changed')
    return out


def writer(data):
    head = read_va(data, 0x448ae5d, 4)
    if head != bytes.fromhex('448b4338'):
        raise ValueError('writer does not read M at +0x38')
    count = read_va(data, 0x448ae82, 8)
    if count != bytes.fromhex('4183f814400f95c5'):
        raise ValueError('writer field count no longer tests M != 0x14')
    skip = read_va(data, 0x448aff4, 5)
    if skip != bytes.fromhex('837c242414') or read_va(data, 0x448ae7d, 5) != bytes.fromhex('4489442424'):
        raise ValueError('writer no longer skips M == 0x14')
    if read_va(data, 0x448affb, 4) != bytes.fromhex('488d4b38'):
        raise ValueError('writer value is not +0x38')
    return {'function': hex(WRITER), 'field_offset': '+0x38', 'skips_when': M_DEFAULT,
            'counts_field_when': f'M != {M_DEFAULT:#x}'}


def decoder(data):
    arm = read_va(data, M_ARM, 5)
    if arm != bytes.fromhex('837c244800'):
        raise ValueError('decoder M arm no longer treats 0 as not seen')
    store = read_va(data, 0x1bb6f29, 8)
    if store != bytes.fromhex('8b44240489442448'):
        raise ValueError('decoder M arm no longer keeps the u32 at rsp+0x48')
    end = read_va(data, 0x1bb7b4f, 5) + read_va(data, 0x1bb7b63, 12)
    if end != bytes.fromhex('b914000000') + bytes.fromhex('448b7424484585f6440f44f1'):
        raise ValueError('end-of-map M default changed')
    return {'arm': hex(M_ARM), 'not_seen': 0, 'default': M_DEFAULT}


def bind(data):
    pin_check(data)
    zero = zero_rejected(data)
    return {
        'target': {'path': RELATIVE, 'sha256': SHA256},
        'decoder_m': decoder(data),
        'm_value_decoder': {'head': hex(M_DECODER), 'named_read': hex(NAMED_READ),
                            'integer_read': hex(INT_READ), 'marker_table': hex(MARKER_TABLE),
                            'zero_rejected': zero},
        'writer_m': writer(data),
        'slots': slots(data),
        'branches': jumps(data),
        'strings': strings(data),
        'round_trip': {
            'missing': 'read as 0x14',
            '0x14': 'writer skips; read back as 0x14',
            'other nonzero u32': 'writer writes key M and the u32 at +0x38 (value encoder 0x4648d30 not read)',
            '0': 'decoder rejects (invalid value, expected a nonzero u32)',
        },
        'links': {'decoder_keys_defaults': '#6453', 'writer': '#6224 (0x4634470, 0x448ae20)'},
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
    print(f"pins={result['pins']} zero_rejected={sorted(result['m_value_decoder']['zero_rejected'])} "
          f"writer_skips={result['writer_m']['skips_when']:#x}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
