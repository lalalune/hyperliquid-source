#!/usr/bin/env python3
"""RE-009-B: byte format of the /lt_hashes.json writer 0x32699c0 (node #94).

Static evidence only. Pins:
* writer 0x32699c0 (l1/src/evm/hash.rs:69): fmt template with the literal
  "/lt_hashes.json", three 0x810-byte memcpys from rec+0xf8/+0xa00/+0x1308
  into one 0x1830-byte value, then save helper 0x3c16810;
* 0x3c16810: "/dev/null" short-circuit, a path predicate (slot -> 0x144a3e0)
  choosing between a MessagePack encoder (0x37e2510, config byte +0xb = 1)
  and a serde_json pretty encoder (0x37e21c0, indent "  "), then two path
  helpers (slots -> 0x144c180, 0x144c560);
* both encoders write a 3-field struct with keys accounts_hash (+0x0),
  contracts_hash (+0x810), storage_hash (+0x1020) from one key pool
  0x59b249 that is followed by "struct LtHash";
* serde_json-1.0.120 src/ser.rs Locations in the JSON encoder subtree and
  MessagePack map/array header bytes (0x80/0xde/0xdf, 0x90/0xdc/0xdd) in
  the two header helpers.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bincode_varint as bv  # noqa: E402
from bincode_varint import EvidenceError  # noqa: E402

FDES = {
    0x32699c0: (0x3269ad1, 'lt_hashes writer'),
    0x3c16810: (0x3c16a61, 'save helper: /dev/null check, format branch, write'),
    0x37e2510: (0x37e2610, 'MessagePack struct encoder (3 fields)'),
    0x37e21c0: (0x37e250b, 'serde_json pretty struct encoder (3 fields)'),
    0x35981d0: (0x3598499, 'MessagePack map header (0x80|n, 0xde, 0xdf)'),
    0x3598e20: (0x35990e9, 'MessagePack array header (0x90|n, 0xdc, 0xdd)'),
    0x3815120: (0x3815294, 'MessagePack field encoder'),
    0x37eb840: (0x37eba6c, 'serde_json field value encoder'),
    0x3c9e9c0: (0x3c9ebad, 'serde_json key encoder'),
    0x3c16cd0: (0x3c16d3c, 'error wrapper (JSON path)'),
    0x3c16d40: (0x3c16da5, 'error wrapper (MessagePack path)'),
}
SLOTS = {0x576f620: 0x144a3e0, 0x576ea68: 0x144c180, 0x576f670: 0x144c560}
PATH_TEMPLATE = (0x201e63, bytes.fromhex('c00f') + b'/lt_hashes.json')
KEY_POOL = (0x59b249, b'accounts_hashcontracts_hashstorage_hashstruct LtHash')
FIELDS = (('accounts_hash', 0x59b249, 13, 0x0), ('contracts_hash', 0x59b256, 14, 0x810),
          ('storage_hash', 0x59b264, 12, 0x1020))
INDENT = (0x5b876a, b'  ')
COPIES = ((0xf8, 0x30), (0xa00, 0x840), (0x1308, 0x1050))
BLOCK = 0x810
SERDE_JSON = 'serde_json-1.0.120/src/ser.rs'
LOCATIONS = {0x37e21c0: [(SERDE_JSON, 660), (SERDE_JSON, 2004), (SERDE_JSON, 2014)],
             0x37eb840: [(SERDE_JSON, 2004), (SERDE_JSON, 2014)],
             0x3c9e9c0: [(SERDE_JSON, 637)],
             0x32699c0: [('l1/src/evm/hash.rs', 69)]}
LEAS = ((0x32699fe, 0x201e63), (0x3c1690d, 0x5b876a), (0x37e2581, 0x59b249), (0x37e25a8, 0x59b256),
        (0x37e25cc, 0x59b264), (0x37e2215, 0x59b249), (0x37e227d, 0x59b256), (0x37e22e9, 0x59b264),
        (0x3269a6e, 0x56dfb28))
CALLERS = {0x32699c0: (0x326a2e0, 0x326aff3, 0x32fc267), 0x3c16810: (0x3269a7b,)}

ANCHORS = (
    (0x32699fe, '488d355e84f9fc', 'lea rsi,[rip+0xfffffffffcf9845e] # 201e63'),
    (0x3269a0f, 'ff152b465002', 'call QWORD PTR [rip+0x250462b] # 576e040'),
    (0x3269a15, '488db3f8000000', 'lea rsi,[rbx+0xf8]'),
    (0x3269a28, 'ba10080000', 'mov edx,0x810'),
    (0x3269a30, '41ffd7', 'call r15'),
    (0x3269a33, '488db3000a0000', 'lea rsi,[rbx+0xa00]'),
    (0x3269a42, 'ba10080000', 'mov edx,0x810'),
    (0x3269a47, '41ffd7', 'call r15'),
    (0x3269a4a, '4881c308130000', 'add rbx,0x1308'),
    (0x3269a59, 'ba10080000', 'mov edx,0x810'),
    (0x3269a5e, '4889de', 'mov rsi,rbx'),
    (0x3269a61, '41ffd7', 'call r15'),
    (0x3269a6e, '488d0db3604702', 'lea rcx,[rip+0x24760b3] # 56dfb28'),
    (0x3269a7b, 'e890cd9a00', 'call 3c16810'),
    (0x3269a8b, 'ff11', 'call QWORD PTR [rcx]'),
    (0x3c16834, '4883fa09', 'cmp rdx,0x9'),
    (0x3c1683a, '48b82f6465762f6e756c', 'movabs rax,0x6c756e2f7665642f'),
    (0x3c1684c, '4883f16c', 'xor rcx,0x6c'),
    (0x3c1685f, 'ff15bb8db501', 'call QWORD PTR [rip+0x1b58dbb] # 576f620'),
    (0x3c1688e, 'c744246000040001', 'mov DWORD PTR [rsp+0x60],0x1000400'),
    (0x3c16896, 'c644246400', 'mov BYTE PTR [rsp+0x64],0x0'),
    (0x3c168a8, 'e863bcbcff', 'call 37e2510'),
    (0x3c1690d, '488d05561e9afc', 'lea rax,[rip+0xfffffffffc9a1e56] # 5b876a'),
    (0x3c16919, '48c744243002000000', 'mov QWORD PTR [rsp+0x30],0x2'),
    (0x3c16938, 'e883b8bcff', 'call 37e21c0'),
    (0x3c1696a, 'ff15f880b501', 'call QWORD PTR [rip+0x1b580f8] # 576ea68'),
    (0x3c16984, 'ff15e68cb501', 'call QWORD PTR [rip+0x1b58ce6] # 576f670'),
    (0x37e252e, '807a0b00', 'cmp BYTE PTR [rdx+0xb],0x0'),
    (0x37e253a, 'ba03000000', 'mov edx,0x3'),
    (0x37e253f, 'e88c5cdbff', 'call 35981d0'),
    (0x37e256d, 'ba03000000', 'mov edx,0x3'),
    (0x37e2572, 'e8a968dbff', 'call 3598e20'),
    (0x37e2581, '488d15c18cdbfc', 'lea rdx,[rip+0xfffffffffcdb8cc1] # 59b249'),
    (0x37e258b, 'b90d000000', 'mov ecx,0xd'),
    (0x37e2596, 'e8852b0300', 'call 3815120'),
    (0x37e25a1, '4d8d8610080000', 'lea r8,[r14+0x810]'),
    (0x37e25a8, '488d15a78cdbfc', 'lea rdx,[rip+0xfffffffffcdb8ca7] # 59b256'),
    (0x37e25b2, 'b90e000000', 'mov ecx,0xe'),
    (0x37e25c5, '4981c620100000', 'add r14,0x1020'),
    (0x37e25cc, '488d15918cdbfc', 'lea rdx,[rip+0xfffffffffcdb8c91] # 59b264'),
    (0x37e25d6, 'b90c000000', 'mov ecx,0xc'),
    (0x37e21fe, 'c604017b', 'mov BYTE PTR [rcx+rax*1],0x7b'),
    (0x37e2215, '488d352d90dbfc', 'lea rsi,[rip+0xfffffffffcdb902d] # 59b249'),
    (0x37e2221, 'ba0d000000', 'mov edx,0xd'),
    (0x37e2256, '66c704303a20', 'mov WORD PTR [rax+rsi*1],0x203a'),
    (0x37e226a, 'e8d1950000', 'call 37eb840'),
    (0x37e227d, '488d35d28fdbfc', 'lea rsi,[rip+0xfffffffffcdb8fd2] # 59b256'),
    (0x37e2289, 'ba0e000000', 'mov edx,0xe'),
    (0x37e229e, '488dbb10080000', 'lea rdi,[rbx+0x810]'),
    (0x37e22e9, '488d35748fdbfc', 'lea rsi,[rip+0xfffffffffcdb8f74] # 59b264'),
    (0x37e22f5, 'ba0c000000', 'mov edx,0xc'),
    (0x37e230a, '4881c320100000', 'add rbx,0x1020'),
    (0x35981e7, '34df', 'xor al,0xdf'),
    (0x35981ef, 'bd80000000', 'mov ebp,0x80'),
    (0x3598e37, '34dd', 'xor al,0xdd'),
    (0x3598e3f, 'bd90000000', 'mov ebp,0x90'),
)


def _rd(data, secs, va, n):
    o = bv.va_to_off(secs, va)
    return data[o:o + n]


def _lea_target(data, secs, va):
    b = _rd(data, secs, va, 7)
    if b[0] not in (0x48, 0x4c) or b[1] != 0x8d or (b[2] & 0xc7) != 0x05:
        raise EvidenceError(f'{va:#x} is not a RIP lea')
    return va + 7 + struct.unpack_from('<i', b, 3)[0]


def _locations(data, secs, relocs, lo, hi):
    body = _rd(data, secs, lo, hi - lo)
    found = set()
    for i in range(len(body) - 7):
        if body[i] in (0x48, 0x4c) and body[i + 1] == 0x8d and (body[i + 2] & 0xc7) == 0x05:
            a = lo + i + 7 + struct.unpack_from('<i', body, i + 3)[0]
            p = relocs.get(a)
            if p is None:
                continue
            try:
                n, line = struct.unpack_from('<QI', _rd(data, secs, a + 8, 12))
                path = _rd(data, secs, p, n) if 3 < n < 300 else b''
            except (EvidenceError, struct.error, KeyError, ValueError):
                continue
            if path.endswith(b'.rs'):
                text = path.decode('latin1')
                if 'serde_json-' in text:
                    text = text[text.index('serde_json-'):]
                elif '/code_Mainnet/' in text:
                    text = text.split('/code_Mainnet/', 1)[1]
                found.add((text, line))
    return sorted(found)


def _rel32_callers(data, secs, targets):
    text = secs['.text']
    tb = data[text['offset']:text['offset'] + text['size']]
    base = text['addr']
    hits = {t: [] for t in targets}
    i = tb.find(b'\xe8')
    while i != -1 and i + 5 <= len(tb):
        t = base + i + 5 + struct.unpack_from('<i', tb, i + 1)[0]
        if t in hits:
            hits[t].append(base + i)
        i = tb.find(b'\xe8', i + 1)
    return hits


def scan(data, expected_sha256=bv.SHA256, check_callers=True):
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected_sha256:
        raise EvidenceError(f'input SHA-256 {digest} is not node #94 {bv.SHA256}')
    secs = bv.sections(data)
    fdes = bv.fde_extents(data, secs)
    relocs = bv.relative_relocs(data, secs)
    for lo, (hi, _) in FDES.items():
        if fdes.get(lo) != hi:
            raise EvidenceError(f'FDE {lo:#x} does not end at {hi:#x}')
    rows = []
    for va, hexbytes, text in ANCHORS:
        if _rd(data, secs, va, len(hexbytes) // 2).hex() != hexbytes:
            raise EvidenceError(f'bytes at {va:#x} are not {hexbytes} ({text})')
        rows.append({'va': f'{va:#x}', 'bytes': hexbytes, 'insn': text})
    for va, lit in (PATH_TEMPLATE, KEY_POOL, INDENT):
        if _rd(data, secs, va, len(lit)) != lit:
            raise EvidenceError(f'literal at {va:#x} is not {lit!r}')
    for va, want in LEAS:
        if _lea_target(data, secs, va) != want:
            raise EvidenceError(f'lea {va:#x} does not target {want:#x}')
    for s, t in SLOTS.items():
        if relocs.get(s) != t:
            raise EvidenceError(f'slot {s:#x} does not relocate to {t:#x}')
    locs = {}
    for fn, want in LOCATIONS.items():
        got = _locations(data, secs, relocs, fn, FDES[fn][0])
        if got != want:
            raise EvidenceError(f'Locations in {fn:#x}: {got}')
        locs[f'{fn:#x}'] = [f'{p}:{ln}' for p, ln in got]
    for fn in (0x37e2510, 0x35981d0, 0x3598e20, 0x3815120):
        if _locations(data, secs, relocs, fn, FDES[fn][0]):
            raise EvidenceError(f'{fn:#x} unexpectedly has a Location')
    callers = None
    if check_callers:
        got = _rel32_callers(data, secs, tuple(CALLERS))
        for t, want in CALLERS.items():
            if tuple(got[t]) != want:
                raise EvidenceError(f'rel32 callers of {t:#x}: {[hex(x) for x in got[t]]}')
        callers = {f'{t:#x}': [f'{x:#x}' for x in got[t]] for t in CALLERS}
    return {
        'schema': 're009b-lt-hashes-format/1',
        'target': {'release': 94, 'sha256': digest, 'size': len(data)},
        'functions': {f'{lo:#x}': {'end': f'{hi:#x}', 'role': role} for lo, (hi, role) in FDES.items()},
        'relocated_slots': {f'{s:#x}': f'{t:#x}' for s, t in SLOTS.items()},
        'rel32_callers': callers,
        'locations': locs,
        'path_template': {'va': f'{PATH_TEMPLATE[0]:#x}', 'bytes': PATH_TEMPLATE[1].hex(),
                          'literal': '/lt_hashes.json', 'fmt_call': '0x3269a0f'},
        'value': {'blocks': [{'src': f'rec+{s:#x}', 'dst': f'rsp+{d:#x}', 'len': BLOCK} for s, d in COPIES],
                  'total_len': BLOCK * 3},
        'fields': [{'name': n, 'key_va': f'{va:#x}', 'key_len': ln, 'value_offset': f'{off:#x}'}
                   for n, va, ln, off in FIELDS],
        'key_pool': {'va': f'{KEY_POOL[0]:#x}', 'text': KEY_POOL[1].decode()},
        'encodings': {
            'messagepack': {'encoder': '0x37e2510', 'config_dword_0x1000400_at': '0x3c1688e',
                            'struct_map_byte': '+0xb = 0x01 -> map header 0x35981d0 with edx=3',
                            'else': 'array header 0x3598e20 with edx=3'},
            'serde_json_pretty': {'encoder': '0x37e21c0', 'indent_va': f'{INDENT[0]:#x}', 'indent': '  ',
                                  'open_brace_store': '0x37e21fe', 'key_value_sep_store': '0x37e2256 (": ")'},
            'selector': 'call via slot 0x576f620 -> 0x144a3e0 at 0x3c1685f (path argument); nonzero -> MessagePack',
        },
        'dev_null_short_circuit': '0x3c16834..0x3c16853: len 9 and bytes "/dev/null" -> return 0',
        'anchors': rows,
        'what_this_does_not_claim': [
            'Which branch runs for "/lt_hashes.json": the 0x144a3e0 predicate is not decoded.',
            'What 0x144c180 and 0x144c560 do (file write is an inference).',
            'How each 0x810-byte value is encoded inside a field (0x37eb840 / 0x3815120 internals).',
            'What the 0x810-byte buffers mean (LtHash accumulator is an inference from the "struct LtHash" literal).',
            'Any runtime behaviour, file contents on disk, or #115 parity.',
        ],
    }


def render(result):
    return (json.dumps(result, sort_keys=True, separators=(',', ':')) + '\n').encode()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--input', type=Path, default=bv.TARGET)
    ap.add_argument('--output', type=Path)
    a = ap.parse_args(argv)
    try:
        text = render(scan(a.input.read_bytes()))
    except (EvidenceError, OSError, struct.error, ValueError) as e:
        print(f'lt_hashes_format: {e}', file=sys.stderr)
        return 1
    if a.output:
        a.output.write_bytes(text)
    else:
        sys.stdout.buffer.write(text)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
