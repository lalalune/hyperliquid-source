#!/usr/bin/env python3
"""Node #115 position decoder 0x1bb6b90: field keys, long key names, defaults.

Open PR #6224 mapped the position writer (keys s, l, M, f, e). This tool
checks the decoder side:

1. The decoder 0x1bb6b90 matches each map key with one of two matchers:
   0x2d129d0 for a string key that passes the UTF-8 check (slot 0x64dfca8),
   and 0x183e010 for a key that fails it or comes as binary bytes.
2. Both matchers accept a key of length 1 to 11 only (`dec; cmp 0xa; ja`),
   and map the same keys to the same field index:
   s / szi -> 0, l / leverage -> 1, M -> 2, f / cum_funding -> 3,
   e / entry_ntl -> 4, any other key -> 5.
   `margin_table_id` is 15 bytes, so it is index 5 (skipped).
3. The field table 0x59c45c sends index 0..4 to the field decoders and
   index 5 to the skip function 0x19ccaf0.
4. A field seen twice gives `duplicate field` with the one-byte name.
5. At the end of the map, a missing field gets a default: s 0, e 0,
   l tag 0 with 0x14 (20), M 0x14 (20; also when the decoded M is 0),
   f 0, 0, 0.

The tool only compares fixed bytes at fixed addresses, jump-table entries,
call targets and strings. The captured binary is not executed. objdump and
readelf are not started. Addresses are ELF virtual addresses.
"""
import argparse
import json
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from elf_index import sections

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-position-long-keys-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

DECODER = 0x1bb6b90
MATCH_BYTES = 0x183e010   # key not valid UTF-8, or binary key
MATCH_STR = 0x2d129d0     # key valid UTF-8
SKIP = 0x19ccaf0

PINS = {   # address -> (bytes, meaning)
    0x183e010: ('ffca83fa0a0f8734010000488d052adfc6fe48630c904801c1ffe10fb60683c0b383f8260f8715010000488d'
                '0d37dfc6fe486304814801c8ffe0b002884701c60709c3803e6c0f85f3000000807e01650f85e9000000807e'
                '02760f85df000000807e03650f85d5000000807e04720f85cb000000807e05610f85c1000000807e06670f85'
                'b7000000b001807e076574ace9aa000000803e730f85a1000000807e017a0f8597000000807e02690f858d00'
                '000031c0884701c60709c3803e65757f807e016e7579807e02747573807e0372756d807e04797567807e055f'
                '7561807e066e755b807e07747555b004807e086c0f8446ffffffeb47803e637542807e0175753c807e026d75'
                '36807e035f7530807e0466752a807e05757524807e066e751e807e07647518807e08697512807e096e750cb0'
                '03807e0a670f84fdfeffffb005884701c60709c3b003884701c60709c3b004884701c60709c3b001884701c6'
                '0709c3',
                'byte-key matcher, whole function'),
    0x2d129d0: ('4889f848ffca4883fa0a0f87b1000000488d0d41d28ffd486314914801caffe20fb60e83c1b383f9260f8792'
                '000000488d154ed28ffd48630c8a4801d1ffe1b102884801c60009c348b96c6576657261676548390e756ab1'
                '01884801c60009c30fb70e81f1737a00000fb6560283f2696609ca754c31c9884801c60009c348b9656e7472'
                '795f6e7448330e0fb656084883f26c4809ca7529b104884801c60009c348b963756d5f66756e6448330e48ba'
                '5f66756e64696e67483356034809ca7409b105884801c60009c3b103884801c60009c3',
                'string-key matcher, whole function'),
    0x1bb71fc: ('ff15a68a920483bc24b00000000175244889e74889ee4c89e2e8f66dc8ff803c2409752d0fb6442401884424'
                '51c644245009eb5c488bb424b8000000488b9424c00000004c89ed4c89efe885b71501',
                'UTF-8 check; error -> byte matcher, ok -> string matcher'),
    0x1bb73a0: ('4889ef4889c6e8656cc8ff',
                'binary key -> byte matcher'),
    0x1bb6cb4: ('48c78424d800000000000000c78424d000000002000000488d6c24504c8d2585579efe4989e5c74424480000'
                '000048c78424200100000000000048c78424e000000000000000',
                'map start: fields unset (l tag 2, M 0), field table 0x59c45c'),
    0x1bb728f: ('4c8d25c6519efe',
                'field table 0x59c45c after a key'),
    0x1bb6e4a: ('0fb64424503c090f851f0a00000fb6442451496304844c01e0ffe0',
                'jump on field index'),
    0x1bb6e65: ('4883bc24d8000000010f843c1100004c89f6b9030000004c89ef488d1587d3a3fee865f5c1ff',
                'index 0 s: duplicate check, 0x17d63f0 with name Szi'),
    0x1bb6f97: ('83bc24d0000000020f852f1000004c89f64c89efe800f3bfff',
                'index 1 l: 0x17b62b0'),
    0x1bb6f07: ('837c2448000f85b91000004c89f64c89efe8e3ed15010fb604243c09',
                'index 2 M: 0x2d15d00'),
    0x1bb6f36: ('4883bc2420010000010f847d1000004c89f64c89ef31d2e81e7ff7ff',
                'index 3 f: 0x1b2ee70'),
    0x1bb6eb6: ('4883bc24e0000000010f84f41000004c89f6b9030000004c89ef488d159fa9a3fee894d8c1ff',
                'index 4 e: 0x17d4770 with name Ntl'),
    0x1bb6d80: ('4c89ef4c89f6ba01000000e8605de1ff',
                'index 5: skip value 0x19ccaf0'),
    0x2d15d00: ('488d15380d90fdb90d000000e99feeacfe',
                'M decoder: name MarginTableId, length 13'),
    0x1bb7fb0: ('488d051d08a1feeb22488d05650da1feeb19488d05c609a1feeb10488d05d114a1feeb07488d05b909a1fe48'
                '898424b000000048c78424b800000001000000',
                'duplicate field names, length 1'),
    0x1bb7b1b: ('31c0f68424d800000001488b942458010000480f44d0f68424e0000000014c8b8c24400100004c0f44c88bac'
                '24d000000083fd02b914000000448b9c24ec000000440f44d90f44e8448b7424484585f6440f44f1f6842420'
                '010000014c8b8424480100004c0f44c0488b8c2460010000480f44c8488bbc2450010000480f44f8',
                'end of map: defaults for missing fields'),
    0x1bb7649: ('31c941be140000004531c931d241bb1400000031ed4531c031ff',
                'empty map: same defaults'),
}

FIELD_TABLE = 0x59c45c
FIELD_ARMS = {0: 0x1bb6e65, 1: 0x1bb6f97, 2: 0x1bb6f07, 3: 0x1bb6f36, 4: 0x1bb6eb6, 5: 0x1bb6d80}
FIELD_NAMES = {0: 's', 1: 'l', 2: 'M', 3: 'f', 4: 'e'}

# call site -> target
CALLS = {0x1bb7215: MATCH_BYTES, 0x1bb73a6: MATCH_BYTES, 0x1bb7246: MATCH_STR,
         0x1bb6e86: 0x17d63f0, 0x1bb6fab: 0x17b62b0, 0x1bb6f18: 0x2d15d00,
         0x1bb6f4d: 0x1b2ee70, 0x1bb6ed7: 0x17d4770, 0x1bb6d8b: SKIP}

# lea site -> (string address, length, text)
STRINGS = {0x1bb6e7f: (0x5f420d, 3, 'Szi'), 0x1bb6ed0: (0x5f1876, 3, 'Ntl'),
           0x2d15d00: (0x616a3f, 13, 'MarginTableId'),
           0x1bb7fb0: (0x5c87d4, 1, 's'), 0x1bb7fb9: (0x5c8d25, 1, 'e'),
           0x1bb7fc2: (0x5c898f, 1, 'f'), 0x1bb7fcb: (0x5c94a3, 1, 'M'),
           0x1bb7fd4: (0x5c8994, 1, 'l')}

# Each matcher: length table (lengths 1..11), first-byte table for length 1
# (bytes 'M'..'s'), and for each key the arm, the compare sites and the
# site that sets the field index.
MATCHERS = {
    'bytes': {
        'function': MATCH_BYTES, 'cap_site': 0x183e012, 'cap_op': b'\x83\xfa', 'length_table': 0x4abf4c,
        'byte_table': 0x4abf78, 'other': 0x183e14f, 'index_op': 0xb0, 'zero_op': 'c0',
        'single': {'s': 0x183e0c2, 'l': 0x183e16a, 'M': 0x183e04a, 'f': 0x183e158, 'e': 0x183e161},
        'long': {
            'szi': (0x183e0a5, [0x183e0a5, 0x183e0ae, 0x183e0b8], 0x183e0c2),
            'leverage': (0x183e053, [0x183e053, 0x183e05c, 0x183e066, 0x183e070, 0x183e07a,
                                     0x183e084, 0x183e08e, 0x183e09a], 0x183e098),
            'entry_ntl': (0x183e0cb, [0x183e0cb, 0x183e0d0, 0x183e0d6, 0x183e0dc, 0x183e0e2,
                                      0x183e0e8, 0x183e0ee, 0x183e0f4, 0x183e0fc], 0x183e0fa),
            'cum_funding': (0x183e108, [0x183e108, 0x183e10d, 0x183e113, 0x183e119, 0x183e11f,
                                        0x183e125, 0x183e12b, 0x183e131, 0x183e137, 0x183e13d,
                                        0x183e145], 0x183e143),
        },
    },
    'string': {
        'function': MATCH_STR, 'cap_site': 0x2d129d6, 'cap_op': b'\x48\x83\xfa', 'length_table': 0x60fc28,
        'byte_table': 0x60fc54, 'other': 0x2d12a91, 'index_op': 0xb1, 'zero_op': 'c9',
        'single': {'s': 0x2d12a45, 'l': 0x2d12a27, 'M': 0x2d12a0f, 'f': 0x2d12a9a, 'e': 0x2d12a68},
        'long': {   # key -> (arm, [(immediate address, size, key offset)], index site)
            'szi': (0x2d12a30, [(0x2d12a35, 2, 0), (0x2d12a3f, 1, 2)], 0x2d12a45),
            'leverage': (0x2d12a18, [(0x2d12a1a, 8, 0)], 0x2d12a27),
            'entry_ntl': (0x2d12a4e, [(0x2d12a50, 8, 0), (0x2d12a62, 1, 8)], 0x2d12a68),
            'cum_funding': (0x2d12a71, [(0x2d12a73, 8, 0), (0x2d12a80, 8, 3)], 0x2d12a9a),
        },
    },
}
KEY_INDEX = {'s': 0, 'szi': 0, 'l': 1, 'leverage': 1, 'M': 2, 'f': 3, 'cum_funding': 3,
             'e': 4, 'entry_ntl': 4}
MAX_KEY_LENGTH = 11
DEFAULT_SITE = 0x1bb7b4f    # mov ecx, 0x14 used for leverage and M
L_UNSET_SITE = 0x1bb7b4c    # cmp ebp, 2 (l tag 2 = not seen)


def read_va(data, va, size):
    hits = [s for s in sections(data)
            if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(hits) != 1:
        raise ValueError(f'expected one file-backed mapping at {va:#x}')
    off = hits[0]['offset'] + va - hits[0]['address']
    return data[off:off + size]


def rel32(data, va, length):
    return va + length + struct.unpack('<i', read_va(data, va + length - 4, 4))[0]


def table(data, base, i):
    return base + struct.unpack('<i', read_va(data, base + 4 * i, 4))[0]


def pin_check(data):
    for va, (want, meaning) in PINS.items():
        raw = bytes.fromhex(want)
        if read_va(data, va, len(raw)) != raw:
            raise ValueError(f'instruction bytes changed at {va:#x} ({meaning})')


def calls(data):
    for site, target in CALLS.items():
        if read_va(data, site, 1) != b'\xe8' or rel32(data, site, 5) != target:
            raise ValueError(f'call at {site:#x} is not to {target:#x}')
    return {hex(k): hex(v) for k, v in CALLS.items()}


def strings(data):
    out = {}
    for site, (addr, length, text) in STRINGS.items():
        if read_va(data, site + 1, 1) != b'\x8d' or rel32(data, site, 7) != addr:
            raise ValueError(f'lea at {site:#x} is not to {addr:#x}')
        if read_va(data, addr, length) != text.encode():
            raise ValueError(f'string at {addr:#x} is not {text!r}')
        out[hex(site)] = {'address': hex(addr), 'length': length, 'text': text}
    return out


def index_at(data, m, site):
    raw = read_va(data, site, 2)
    if raw[0] == m['index_op']:
        return raw[1]
    if raw == bytes.fromhex('31' + m['zero_op']):
        return 0
    raise ValueError(f'no field index set at {site:#x}')


def spell_bytes(data, sites):
    out = b''
    for site in sites:
        raw = read_va(data, site, 4)
        if raw[:2] == b'\x80\x3e':
            off, ch = 0, raw[2]
        elif raw[:2] == b'\x80\x7e':
            off, ch = raw[2], raw[3]
        else:
            raise ValueError(f'no byte compare at {site:#x}')
        if off != len(out):
            raise ValueError(f'compare at {site:#x} checks byte {off}, not {len(out)}')
        out += bytes([ch])
    return out.decode()


def spell_string(data, parts):
    key = bytearray(max(off + size for _, size, off in parts))
    for site, size, off in parts:
        key[off:off + size] = read_va(data, site, size)
    return key.decode()


def matcher(data, name, m):
    cap = read_va(data, m['cap_site'], len(m['cap_op']) + 1)
    if cap[:-1] != m['cap_op']:
        raise ValueError(f'{name} matcher length check changed')
    imm = cap[-1]
    if imm + 1 != MAX_KEY_LENGTH:
        raise ValueError(f'{name} matcher accepts keys up to {imm + 1} bytes')
    keys = {}
    for key, arm in m['single'].items():
        got = table(data, m['byte_table'], ord(key) - 0x4d)
        if got != arm:
            raise ValueError(f'{name} matcher sends {key!r} to {got:#x}, not {arm:#x}')
        keys[key] = index_at(data, m, arm)
    if table(data, m['length_table'], 0) == m['other']:
        raise ValueError(f'{name} matcher has no one-byte key path')
    for key, (arm, parts, idx_site) in m['long'].items():
        got = table(data, m['length_table'], len(key) - 1)
        if got != arm:
            raise ValueError(f'{name} matcher sends length {len(key)} to {got:#x}, not {arm:#x}')
        spelled = spell_bytes(data, parts) if name == 'bytes' else spell_string(data, parts)
        if spelled != key:
            raise ValueError(f'{name} matcher arm {arm:#x} matches {spelled!r}, not {key!r}')
        keys[key] = index_at(data, m, idx_site)
    for length in range(2, MAX_KEY_LENGTH + 1):
        if length not in {len(k) for k in m['long']} and table(data, m['length_table'], length - 1) != m['other']:
            raise ValueError(f'{name} matcher has an unlisted key of length {length}')
    if index_at(data, m, m['other']) != 5:
        raise ValueError(f'{name} matcher other-key index changed')
    if keys != KEY_INDEX:
        raise ValueError(f'{name} matcher key indexes changed: {keys}')
    return {'function': hex(m['function']), 'max_key_length': MAX_KEY_LENGTH,
            'keys': keys, 'other_index': 5}


def fields(data):
    out = {}
    for idx, arm in FIELD_ARMS.items():
        got = table(data, FIELD_TABLE, idx)
        if got != arm:
            raise ValueError(f'field index {idx} goes to {got:#x}, not {arm:#x}')
        out[str(idx)] = {'arm': hex(arm), 'field': FIELD_NAMES.get(idx, 'skip')}
    return out


def defaults(data):
    if read_va(data, DEFAULT_SITE, 5) != bytes.fromhex('b914000000'):
        raise ValueError('leverage / M default changed')
    if read_va(data, L_UNSET_SITE, 3) != bytes.fromhex('83fd02'):
        raise ValueError('l unset tag changed')
    return {'s': 0, 'l': {'tag': 0, 'leverage': 0x14}, 'M': 0x14, 'f': [0, 0, 0], 'e': 0,
            'M_decoded_zero': 'replaced by 0x14 (test r14d; cmove)'}


def bind(data):
    pin_check(data)
    return {
        'target': {'path': RELATIVE, 'sha256': SHA256},
        'decoder': hex(DECODER),
        'matchers': {name: matcher(data, name, m) for name, m in MATCHERS.items()},
        'field_table': {'address': hex(FIELD_TABLE), 'entries': fields(data)},
        'calls': calls(data),
        'strings': strings(data),
        'defaults': defaults(data),
        'rejected_long_name': {'margin_table_id': 'length 15 > 11 -> index 5 (skipped)'},
        'links': {'writer': '#6224 (0x4634470, 0x448ae20)', 'per_user_value': '#6239'},
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
    keys = result['matchers']['string']['keys']
    print(f"pins={result['pins']} keys={sorted(keys)} max_key_length={MAX_KEY_LENGTH}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
