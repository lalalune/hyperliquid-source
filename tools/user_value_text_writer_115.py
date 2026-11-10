#!/usr/bin/env python3
"""Node #115 per-user value text writer: it is the pretty JSON form of the state.

Open PR #6575 showed that the position writer 0x448ae20 writes text
("M: <decimal>", entries joined by ",\\n"), while the position decoder
0x1bb6b90 (#6453, #6456) reads MessagePack. This tool checks, with fixed
bytes only, what that text is and whether a reader for it exists:

1. Key writer 0x4713ba0 (#6575 "entry start") is a pretty JSON object-key
   writer: "\\n" before the first key, ",\\n" before later keys, then the
   indent string repeated `current_indent` times, then the key between two
   '"' bytes through the string escaper 0x46708b0. The value side writes
   ": ". The position keys are the 1-byte strings s, l, M, f, e.
2. Entry 0x422ed40 picks the format by the output path: when the file
   extension equals the 3-byte "rmp" (0x4659e5) it calls the MessagePack
   serializer 0x3c13960; otherwise it builds a 0x80-byte buffer and a
   pretty formatter with the 2-byte indent "  " (0x7c809e) and calls the
   JSON serializer 0x3c136f0.
3. 0x3c136f0 reaches the per-user value writer 0x3beac00 through a chain in
   which each function has exactly one direct caller: 0x422ed40 ->
   0x3c136f0 -> 0x3c2f460 (Exchange fields, `locus`, `perp_dexs`) ->
   0x3c2e340 -> 0x4615470 -> 0x4482170 (`user_states`) -> 0x446b620
   (`user_to_state`) -> 0x4663f30 -> 0x3beac00.
4. A JSON reader for the position exists: 0x402e7c0 skips JSON whitespace
   (mask 0x100002600 = space, \\t, \\n, \\r), accepts '[' or '{', and calls
   the field matcher 0x4455890. That matcher gives the same field indices as
   the MessagePack matchers of #6453: s/szi 0, l/leverage 1, M 2,
   f/cum_funding 3, e/entry_ntl 4, any other key 5.

So the text form is not output-only. The two callers of 0x422ed40
(0x2ae41e0, 0x2cde430) and the file write after the serializer are the
boundary of this packet and are not mapped.

The tool only compares fixed bytes at fixed addresses, jump-table entries,
call targets, string bytes and a direct-call census. The captured binary is
not executed. objdump and readelf are not started. Addresses are ELF
virtual addresses.
"""
import argparse
import bisect
import json
import re
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from elf_index import sections, unwind_index

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-user-value-text-writer-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

KEY_WRITER = 0x4713ba0
ESCAPER = 0x46708b0
ENTRY = 0x422ed40
RMP = 0x4659e5
INDENT = 0x7c809e
MSGPACK_SER = 0x3c13960
JSON_SER = 0x3c136f0
USER_VALUE_WRITER = 0x3beac00
JSON_POSITION = 0x402e7c0
JSON_MATCHER = 0x4455890
LEN_TABLE = 0x7ce038
CHAR_TABLE = 0x7ce064

PINS = {   # address -> (bytes, meaning)
    0x4713bd3: ('4d8b6c24104d392c240f847c010000498b44240842c604280a49ffc5eb26',
                'key writer: first key appends "\\n"'),
    0x4713c07: ('498b4424086642c704282c0a4983c502',
                'key writer: later key appends ",\\n"'),
    0x4713c21: ('4c8b7b184d85ff7477',
                'key writer: r15 = current_indent; zero skips the indent'),
    0x4713c38: ('488b58084c8b35c5b8dc01',
                'key writer: indent bytes; memcpy slot 0x64df508'),
    0x4713ca1: ('488b442420c6400102',
                'key writer: state = Rest (2)'),
    0x4713cc5: ('498b4708c604302248ffc6498977104c89ff4889cee8d1cbf5ff',
                'key writer: append \'"\', call escaper 0x46708b0'),
    0x4713ce8: ('498b4708c604302248ffc6',
                'key writer: append closing \'"\''),
    0x422ee28: ('488d15b66b23fcb903000000e8670e37fd84c07471',
                'entry: compare extension with 3-byte "rmp"; no match -> JSON branch'),
    0x422ee82: ('e8d94a9eff',
                'entry: "rmp" branch calls MessagePack serializer 0x3c13960'),
    0x422eeae: ('bf80000000ff15c7052b02',
                'entry: JSON branch allocates a 0x80-byte buffer'),
    0x422eedd: ('488d05ba9159fc488944244048c74424480200000048c744245000000000'
                'c644245800488d7424384c89e7e8e3479eff',
                'entry: formatter indent "  " (len 2), current_indent 0, '
                'has_value false; call JSON serializer 0x3c136f0'),
    0x402e7ee: ('49bd0026000001000000',
                'JSON reader: whitespace mask 0x100002600'),
    0x402e838: ('83fe5b0f84bf00000083fe7b',
                'JSON reader: accepts "[" (sequence) or "{" (map)'),
    0x402ea50: ('e83b6e4200',
                'JSON reader: call field matcher 0x4455890'),
    0x4455890: ('4889f848ffca4883fa0a0f87b1000000488d0d918737fc486314914801caffe2',
                'matcher: dispatch on key length 1..11 through 0x7ce038'),
    0x44558b0: ('0fb60e83c1b383f9260f8792000000488d159e8737fc48630c8a4801d1ffe1',
                'matcher: 1-byte key dispatch on byte - 0x4d through 0x7ce064'),
    0x44558cf: ('b102884801c60000c3', 'matcher: index 2 (M)'),
    0x44558d8: ('48b96c6576657261676548390e756ab101884801c60000c3',
                'matcher: "leverage" -> index 1'),
    0x44558f0: ('0fb70e81f1737a00000fb6560283f2696609ca754c31c9884801c60000c3',
                'matcher: "szi" -> index 0'),
    0x445590e: ('48b9656e7472795f6e7448330e0fb656084883f26c4809ca7529b104884801c60000c3',
                'matcher: "entry_ntl" -> index 4'),
    0x4455931: ('48b963756d5f66756e6448330e48ba5f66756e64696e67483356034809ca7409'
                'b105884801c60000c3b103884801c60000c3',
                'matcher: "cum_funding" -> index 3; other key -> index 5'),
}

# lea site -> (string address, text); each key is passed with length 1
POSITION_KEYS = {0x448af18: (0x7d082f, b's'), 0x448af87: (0x7d0946, b'l'),
                 0x448afff: (0x7d13c1, b'M'), 0x448b06d: (0x7d13cd, b'f'),
                 0x448b0f3: (0x7d0bd9, b'e')}

STRINGS = {RMP: b'rmp', INDENT: b'  ', 0x7db8e6: b'internal error: entered unreachable code'}

# 1-byte keys: byte -> handler; key length -> handler
CHAR_ARMS = {'s': 0x4455905, 'l': 0x44558e7, 'M': 0x44558cf, 'f': 0x445595a, 'e': 0x4455928}
LEN_ARMS = {1: 0x44558b0, 3: 0x44558f0, 8: 0x44558d8, 9: 0x445590e, 11: 0x4455931}
OTHER_ARM = 0x4455951
INDEX_AT = {0x4455905: 0, 0x44558e7: 1, 0x44558cf: 2, 0x445595a: 3, 0x4455928: 4,
            0x44558f0: 0, 0x44558d8: 1, 0x445590e: 4, 0x4455931: 3, OTHER_ARM: 5}

# callee -> (only direct caller function, string the caller loads or None)
CHAIN = [
    (JSON_SER, ENTRY, None),
    (0x3c2f460, JSON_SER, None),
    (0x3c2e340, 0x3c2f460, (0x7ba2fa, b'locusperp_dexs')),
    (0x4615470, 0x3c2e340, None),
    (0x4482170, 0x4615470, None),
    (0x446b620, 0x4482170, (0x7d07c9, b'user_states')),
    (0x4663f30, 0x446b620, (0x7d1614, b'user_to_state')),
    (USER_VALUE_WRITER, 0x4663f30, None),
]
ENTRY_CALLERS = [0x2ae41e0, 0x2cde430]


def read_va(data, va, size):
    hits = [s for s in sections(data)
            if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(hits) != 1:
        raise ValueError(f'expected one file-backed mapping at {va:#x}')
    off = hits[0]['offset'] + va - hits[0]['address']
    return data[off:off + size]


def pin_check(data):
    for va, (want, meaning) in PINS.items():
        raw = bytes.fromhex(want)
        if read_va(data, va, len(raw)) != raw:
            raise ValueError(f'instruction bytes changed at {va:#x} ({meaning})')


def strings(data):
    for va, text in STRINGS.items():
        if read_va(data, va, len(text)) != text:
            raise ValueError(f'string at {va:#x} is not {text!r}')
    # rip-relative loads of "rmp" and the indent inside the entry
    for site, target in ((0x422ee28, RMP), (0x422eedd, INDENT)):
        if site + 7 + struct.unpack('<i', read_va(data, site + 3, 4))[0] != target:
            raise ValueError(f'lea at {site:#x} is not {target:#x}')
    if read_va(data, 0x422ee2f, 5) != b'\xb9\x03\x00\x00\x00':
        raise ValueError('extension length is not 3')
    return {hex(k): v.decode() for k, v in STRINGS.items()}


def position_keys(data):
    out = {}
    for site, (addr, text) in POSITION_KEYS.items():
        raw = read_va(data, site, 17)
        if raw[:3] != b'\x48\x8d\x35' or site + 7 + struct.unpack('<i', raw[3:7])[0] != addr:
            raise ValueError(f'key load at {site:#x} is not {addr:#x}')
        if raw[12:17] != b'\xba\x01\x00\x00\x00':
            raise ValueError(f'key at {site:#x} is not passed with length 1')
        if read_va(data, addr, 1) != text:
            raise ValueError(f'key at {addr:#x} is not {text!r}')
        out[hex(site)] = text.decode()
    return out


def table(data, base, index):
    return base + struct.unpack('<i', read_va(data, base + 4 * index, 4))[0]


def matcher(data):
    fields = {}
    for ch, arm in CHAR_ARMS.items():
        if table(data, CHAR_TABLE, ord(ch) - 0x4d) != arm:
            raise ValueError(f'1-byte key {ch!r} no longer goes to {arm:#x}')
        fields[ch] = INDEX_AT[arm]
    for length in range(1, 12):
        want = LEN_ARMS.get(length, OTHER_ARM)
        if table(data, LEN_TABLE, length - 1) != want:
            raise ValueError(f'key length {length} no longer goes to {want:#x}')
    for name, arm in (('szi', 0x44558f0), ('leverage', 0x44558d8),
                      ('entry_ntl', 0x445590e), ('cum_funding', 0x4455931)):
        fields[name] = INDEX_AT[arm]
    if read_va(data, 0x4455896, 4) != b'\x48\x83\xfa\x0a':
        raise ValueError('matcher key length bound changed')
    return {'function': hex(JSON_MATCHER), 'fields': fields, 'other_key': 5,
            'length_table': hex(LEN_TABLE), 'byte_table': hex(CHAR_TABLE)}


def call_census(data):
    secs, entries = unwind_index(data)
    starts = [e['start'] for e in entries]
    text = next(s for s in secs if s['name'] == '.text')
    body = data[text['offset']:text['offset'] + text['size']]
    base = text['address']
    callers = {}
    wanted = {c for c, _, _ in CHAIN} | {ENTRY, JSON_MATCHER}
    for m in re.finditer(b'\xe8', body):
        p = m.start()
        if p + 5 > len(body):
            break
        target = base + p + 5 + struct.unpack_from('<i', body, p + 1)[0]
        if target in wanted:
            site = base + p
            callers.setdefault(target, set()).add(starts[bisect.bisect_right(starts, site) - 1])
    return callers


def loads(data, function, addr):
    _, entries = unwind_index(data)
    starts = [e['start'] for e in entries]
    end = starts[starts.index(function) + 1]
    code = read_va(data, function, end - function)
    for m in re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', code):
        p = m.start()
        if p + 7 <= len(code) and function + p + 7 + struct.unpack_from('<i', code, p + 3)[0] == addr:
            return True
    return False


def chain(data):
    callers = call_census(data)
    rows = []
    for callee, caller, loaded in CHAIN:
        if callers.get(callee) != {caller}:
            got = sorted(hex(x) for x in callers.get(callee, ()))
            raise ValueError(f'{callee:#x} direct callers are {got}, not only {caller:#x}')
        if loaded:
            addr, text = loaded
            if read_va(data, addr, len(text)) != text:
                raise ValueError(f'string at {addr:#x} is not {text!r}')
            if not loads(data, caller, addr):
                raise ValueError(f'{caller:#x} does not load {addr:#x}')
        rows.append({'callee': hex(callee), 'caller': hex(caller),
                     'caller_loads': loaded[1].decode() if loaded else None})
    if callers.get(ENTRY) != set(ENTRY_CALLERS):
        raise ValueError('entry 0x422ed40 callers changed')
    if callers.get(JSON_MATCHER) != {JSON_POSITION}:
        raise ValueError('JSON matcher 0x4455890 is not called only from 0x402e7c0')
    return {'path': rows, 'entry_callers': [hex(x) for x in ENTRY_CALLERS],
            'json_matcher_caller': hex(JSON_POSITION)}


def bind(data):
    pin_check(data)
    return {
        'target': {'path': RELATIVE, 'sha256': SHA256},
        'key_writer': {'function': hex(KEY_WRITER), 'escaper': hex(ESCAPER),
                       'first_key': '\\n', 'later_key': ',\\n', 'quote': '"',
                       'indent': 'current_indent x indent string'},
        'position_keys': position_keys(data),
        'strings': strings(data),
        'entry': {'function': hex(ENTRY), 'rmp_extension': hex(MSGPACK_SER),
                  'other_extension': hex(JSON_SER), 'buffer': 0x80, 'indent': '  '},
        'chain': chain(data),
        'json_reader': {'function': hex(JSON_POSITION), 'whitespace_mask': '0x100002600',
                        'opens': ['[', '{'], 'matcher': matcher(data)},
        'result': {
            'text_form': 'pretty JSON (2-space indent); MessagePack when the path ends in .rmp',
            'output_only': False,
            'not_mapped': ['callers 0x2ae41e0 and 0x2cde430', 'the file write after serialization',
                           'M zero rule and defaults in the JSON reader'],
        },
        'links': {'follows': '#6575', 'msgpack_matchers': '#6453'},
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
    print(f"pins={result['pins']} chain={len(result['chain']['path'])} "
          f"matcher={result['json_reader']['matcher']['function']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
