#!/usr/bin/env python3
"""Reproduce a bounded, static node #115 instruction and caller record."""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import struct

from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
START, END = 0x29962e0, 0x299632f
TEXT_START, TEXT_END = 0x1419300, 0x63f0a00
FDE, CIE = 0xd73c58, 0xca6ed8
# Complete fixed-form decoder: each accepted byte sequence has exactly the
# instruction and operands shown. Unsupported encodings fail, rather than
# being guessed. The conditional displacement is independently checked.
FORMS = [
 ('488b4730', 'mov rax, qword [rdi+0x30]'),
 ('483dff030000', 'cmp rax, 0x3ff'),
 ('7740', 'ja 0x299632c'),
 ('488b8f18010000', 'mov rcx, qword [rdi+0x118]'),
 ('488d5001', 'lea rdx, [rax+1]'),
 ('488b7728', 'mov rsi, qword [rdi+0x28]'),
 ('48895730', 'mov qword [rdi+0x30], rdx'),
 ('488b11', 'mov rdx, qword [rcx]'),
 ('480fca', 'bswap rdx'),
 ('48c1e005', 'shl rax, 5'),
 ('48891406', 'mov qword [rsi+rax], rdx'),
 ('0f57c0', 'xorps xmm0, xmm0'),
 ('0f11440608', 'movups [rsi+rax+8], xmm0'),
 ('48c744061800000000', 'mov qword [rsi+rax+0x18], 0'),
 ('4883c108', 'add rcx, 8'),
 ('48898f18010000', 'mov qword [rdi+0x118], rcx'),
 ('31c0', 'xor eax, eax'),
 ('c3', 'ret'),
 ('b02d', 'mov al, 0x2d'),
 ('c3', 'ret'),
]


def decode(body, start=START):
    rows, pos = [], 0
    for encoded, meaning in FORMS:
        pattern = bytes.fromhex(encoded)
        actual = body[pos:pos + len(pattern)]
        if actual != pattern:
            raise ValueError('unsupported or changed instruction at offset %#x' % pos)
        rows.append({'va': start + pos, 'bytes': actual.hex(), 'instruction': meaning})
        if pattern[0] == 0x77:
            displacement = struct.unpack('b', pattern[1:])[0]
            if start + pos + 2 + displacement != start + len(body) - 3:
                raise ValueError('branch target changed')
        pos += len(pattern)
    if pos != len(body):
        raise ValueError('unconsumed function bytes')
    return rows


def check_fde(raw, start=START, end=END):
    if len(raw) != 20:
        raise ValueError('truncated FDE')
    length, delta, relative, size = struct.unpack_from('<IIiI', raw)
    if (length, FDE + 4 - delta, FDE + 8 + relative, size, raw[16:]) != (16, CIE, start, end-start, b'\0'*4):
        raise ValueError('FDE or CIE binding changed')


def model(count, source, cursor=0):
    """Normal result with valid, non-overlapping memory; u64 pointer arithmetic."""
    if not 0 <= count < 1 << 64 or not 0 <= cursor < 1 << 64:
        raise ValueError('u64 inputs required')
    if count > 1023:
        return {'al': 45, 'rax': (count & ~255) | 45, 'count': count, 'cursor': cursor, 'slot': None}
    if len(source) != 8:
        raise ValueError('success requires exactly eight source bytes')
    return {'al': 0, 'rax': 0, 'count': count+1, 'cursor': (cursor+8) % (1 << 64),
            'slot': (int.from_bytes(source, 'big').to_bytes(8, 'little') + bytes(24)).hex()}


def scan(data, text):
    # Byte-wise rel32 census: candidates can be embedded in other instructions.
    found = []
    lo, hi = text['offset'], text['offset'] + text['size']
    for opcode in (0xe8, 0xe9):
        p = lo
        while True:
            p = data.find(bytes([opcode]), p, hi-4)
            if p < 0:
                break
            va = TEXT_START + p-lo
            target = va+5+struct.unpack_from('<i', data, p+1)[0]
            if target == START:
                found.append({'va': va, 'opcode': hex(opcode), 'target': target})
            p += 1
    return sorted(found, key=lambda x: x['va'])


def collect(data):
    if hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('node #115 digest mismatch')
    secs = sections(data)
    text = next(s for s in secs if s['name'] == '.text')
    if (text['address'], text['size'], text['offset']) != (TEXT_START, TEXT_END-TEXT_START, TEXT_START-0x1000):
        raise ValueError('unexpected text mapping')
    cies, fdes = eh_frame_records(data, secs)
    exact = [x for x in fdes if x['start'] == START]
    expected = {'fde': FDE, 'cie': CIE, 'start': START, 'end': END, 'lsda': None}
    if exact != [expected]:
        raise ValueError('missing or ambiguous FDE')
    check_fde(data[FDE:FDE+20])
    cie = cies[CIE]
    if (cie['augmentation'], cie['fde_encoding'], cie['lsda_encoding']) != ('zR', 0x1b, None):
        raise ValueError('CIE changed')
    off = text['offset'] + START - TEXT_START
    body = data[off:off+END-START]
    instructions = decode(body)
    following = sorted(x['start'] for x in fdes if x['start'] >= END)
    next_start = following[0]
    padding = data[off+len(body):off+len(body)+next_start-END]
    if next_start != END+1 or padding != b'\xcc':
        raise ValueError('unexpected padding')
    callers = scan(data, text)
    return {'target_sha256': SHA, 'source_revision': '8fd8db680ec4bfef40996e5616bce3d5156d0b86',
            'window': {'start': START, 'end': END, 'size': len(body), 'file_offset': off,
                       'sha256': hashlib.sha256(body).hexdigest(), 'bytes': body.hex(),
                       'fde': expected, 'fde_bytes': data[FDE:FDE+20].hex(), 'cie': cie,
                       'cie_bytes': data[CIE:CIE+24].hex(), 'next_fde_start': next_start, 'padding': padding.hex()},
            'instructions': instructions, 'callees': [], 'direct_rel32_candidates': callers,
            'census': {'text_start': TEXT_START, 'text_end': TEXT_END,
                       'method': 'every byte e8/e9 with signed little-endian rel32 wholly inside .text',
                       'count': len(callers)}, 'normalization_masks': []}


def render(r):
    w = r['window']; lines = '\n'.join('- `0x%x` `%s` %s' % (i['va'], i['bytes'], i['instruction']) for i in r['instructions'])
    return f'''# RE-001: eight-byte big-endian value into a 32-byte slot

- Component: RE-001 function map; ownership and original name unknown.
- Target: Linux x86-64 node #115 SHA-256 `{SHA}`.
- Source revision: `{r['source_revision']}`; reference revision: none.
- Bounded question: what does the complete function at `0x{START:x}` do with its input cursor and slot array?

For valid, non-overlapping input/object/destination memory, when the unsigned
qword at `rdi+0x30` is at most 1023, the function increments it, reads eight
bytes from the pointer at `rdi+0x118`, interprets those bytes as a big-endian
u64, stores that number in little-endian form at the start of the 32-byte slot
indexed by the original count, clears the slot's remaining 24 bytes, advances
the input pointer by eight modulo 2^64, and returns zero in RAX. Otherwise it
leaves memory untouched and sets AL to 45; the upper 56 bits of RAX retain the
original count. No source-length or destination-capacity check is performed here.

## Observations and extent

ELF virtual range `0x{START:x}..0x{END:x}`, {w['size']} bytes, file offset
`0x{w['file_offset']:x}`, SHA-256 `{w['sha256']}`. The `.eh_frame` FDE at
`0x{FDE:x}` references CIE `0x{CIE:x}` (`zR`, no LSDA), and describes exactly
this range. The following byte is `cc`, before the next FDE at
`0x{w['next_fde_start']:x}`. FDE bounds alone do not prove function bounds;
the decoded entry, internal branch, and both returns support this local extent.
The body has {len(r['instructions'])} instructions, {len(r['callees'])} callees and no indirect transfers.
Raw bytes, FDE and CIE records are in `records.json`; no normalization masks are used.

## Complete instruction walk

{lines}

The unsigned `ja` skips all writes. On the success route the count store
precedes the source load, and the cursor store follows all slot stores. These
ordering details matter if memory aliases or faults: the rule above assumes
valid non-overlapping memory and makes no atomicity claim. `bswap` reverses the
loaded bytes on little-endian x86-64; it does not establish a protocol type.

## Callers and scope

A byte-wise scan of the entire `.text` range `0x{TEXT_START:x}..0x{TEXT_END:x}`
for `e8` and `e9` followed by signed rel32 found {r['census']['count']} candidates
targeting this entry. This is not a complete caller census: indirect calls,
relocations, and code outside `.text` are not resolved; byte candidates, if any,
may start within another instruction. No caller identity or first-party ownership
is claimed. No callee behavior is bound because the body calls none.

## Novelty check

Before selection, the combined hex and decimal search produced no matches (ripgrep exit 1):

```sh
rg -i '29962e0|43606752' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

## Reproduction and controls

From the repository root, with Python 3.10+ and the authenticated artifact:

```sh
python3 tools/node115_be64_slot.py --out research/work-items/RE-001-node115-be64-slot/
python3 -m unittest tests.test_node115_be64_slot -v
python3 research/work-items/RE-001-node115-be64-slot/verify.py
```

The stdlib-only producer hashes the input before parsing; it decodes only the
listed exact instruction forms and rejects any other encoding. It regenerates
this README, `records.json` and the manifest. The focused tests exercise count
boundaries, byte order, pointer wrap, altered instructions/branch, FDE shift,
wrong digest, truncation and README count consistency. Static analysis only; no
captured executable or network is used. Tool observation was complete within
the stated window and scan range. Analysis environment: Linux x86-64, Python
3.13.5; no native disassembler is needed for regeneration.

## Inference, non-claims and next step

The big-endian value and slot are raw layout observations, not recovered Rust
types, application meaning, source identity, or wire format. Runtime pointer
validity, faults, aliasing, indirect callers and source bounds remain unknown.
There is no reconstructed Rust implementation, build, raw or normalized binary
comparison, relocation closure, whole-node equivalence, or component gate claim.
Before this packet the address had no binding in the checked research and PR
lists; after it the local normal-return rule is byte-backed. Next, locate an
indirect reference or containing dispatch table to establish the caller and the
meaning and bounds of the eight input bytes.
'''


def produce(out, target=TARGET):
    with open(target, 'rb') as f:
        if not f.seek(0, 2):
            raise ValueError('empty input')
        f.seek(0)
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
            record = collect(data)
    out.mkdir(parents=True, exist_ok=True)
    (out/'records.json').write_text(json.dumps(record, indent=2)+'\n')
    (out/'README.md').write_text(render(record))
    files = ['README.md', 'records.json', 'verify.py']
    if not (out/'verify.py').is_file():
        raise ValueError('verify.py must exist in output directory')
    (out/'MANIFEST.sha256').write_text(''.join(hashlib.sha256((out/n).read_bytes()).hexdigest()+'  '+n+'\n' for n in files))
    return record


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--target', type=Path, default=TARGET)
    args = p.parse_args()
    produce(args.out, args.target)
