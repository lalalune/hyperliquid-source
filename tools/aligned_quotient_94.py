#!/usr/bin/env python3
"""Reproduce a strictly decoded node #94 arithmetic leaf; static inspection only."""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parent.parent
BINARY = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
START, END, FDE = 0x538c990, 0x538c9c4, 0x2b3880
# Each complete instruction is accepted only in this encoding. Immediate and
# branch fields are additionally decoded and checked below; unknown bytes fail.
INSNS = [
 ('f30f1efa', 'endbr64'), ('31c0', 'xor eax, eax'),
 ('4883fe04', 'cmp rsi, 4'), ('761b', 'jbe 0x538c9b7'),
 ('b8c0ffffff', 'mov eax, 0xffffffc0'), ('4883ee05', 'sub rsi, 5'),
 ('4839c6', 'cmp rsi, rax'), ('480f47f0', 'cmova rsi, rax'),
 ('4883e6c0', 'and rsi, -64'), ('4869c6401f0000', 'imul rax, rsi, 8000'),
 ('48638f20010000', 'movsxd rcx, dword [rdi+0x120]'),
 ('31d2', 'xor edx, edx'), ('48f7f1', 'div rcx'), ('c3', 'ret'),
]


def need(condition, message):
    if not condition:
        raise ValueError(message)


def sections(data):
    need(data[:6] == b'\x7fELF\x02\x01', 'not little-endian ELF64')
    off = struct.unpack_from('<Q', data, 0x28)[0]
    size, count, names = struct.unpack_from('<HHH', data, 0x3a)
    need(size == 64 and names < count, 'bad section table')
    entries = [struct.unpack_from('<IIQQQQIIQQ', data, off + i * size) for i in range(count)]
    names_entry = entries[names]
    string_table = data[names_entry[4]:names_entry[4]+names_entry[5]]
    found = {}
    for e in entries:
        end = string_table.find(b'\0', e[0])
        if end >= 0:
            found[string_table[e[0]:end].decode('ascii')] = e
    text, frame = found['.text'], found['.eh_frame']
    need(text[2] & 4 and text[5] == 0x431c430, 'unexpected text')
    return text, frame


def decode(body):
    pos = 0
    walk = []
    for raw, asm in INSNS:
        expected = bytes.fromhex(raw)
        actual = body[pos:pos+len(expected)]
        need(actual == expected, 'unknown instruction at %#x' % (START + pos))
        walk.append((START + pos, actual.hex(), asm))
        pos += len(expected)
    need(pos == len(body), 'trailing or truncated instruction')
    # Derive the control transfer, cap, mask, multiplier and field offset.
    need(walk[3][0] + 2 + struct.unpack('<b', bytes.fromhex(walk[3][1])[1:])[0] == walk[10][0], 'branch target')
    need(int.from_bytes(bytes.fromhex(walk[4][1])[1:], 'little') == 0xffffffc0, 'cap')
    need(struct.unpack('<i', bytes.fromhex(walk[9][1])[3:])[0] == 8000, 'multiplier')
    need(struct.unpack('<i', bytes.fromhex(walk[10][1])[3:])[0] == 0x120, 'field offset')
    return walk


def frame_at(data, frame, offset, start, end):
    at = frame[4] + offset
    length, cie_delta, initial, extent = struct.unpack_from('<IIiI', data, at)
    need(length == 0x10 and offset + 4 - cie_delta == 0, 'FDE length or CIE mismatch')
    need(frame[3] + offset + 8 + initial == start and extent == end-start, 'FDE range mismatch')
    need(data[at+16:at+20] == bytes(4), 'unexpected FDE augmentation')


def scan(data, text, target):
    # Byte-pattern census, including possible embedded-data/overlapping false positives.
    out = []
    lo, hi, va = text[4], text[4]+text[5], text[3]
    for op in (0xe8, 0xe9):
        p = lo
        while True:
            p = data.find(bytes((op,)), p, hi-4)
            if p < 0:
                break
            site = va + p-lo
            if site + 5 + struct.unpack_from('<i', data, p+1)[0] == target:
                out.append({'site': hex(site), 'opcode': hex(op)})
            p += 1
    return sorted(out, key=lambda r: int(r['site'], 16))


def inspect(data, digest=DIGEST, fde=FDE):
    need(hashlib.sha256(data).hexdigest() == digest == DIGEST, 'target digest mismatch')
    text, frame = sections(data)
    need(text[3] <= START < END <= text[3]+text[5], 'window outside .text')
    frame_at(data, frame, fde, START, END)
    frame_at(data, frame, 0x2b3894, 0x538c9d0, 0x538ca1a)
    offset = text[4] + START-text[3]
    body = data[offset:offset+END-START]
    walk = decode(body)
    padding = data[offset+len(body):offset+len(body)+12]
    need(padding == b'\xcc'*12, 'padding mismatch')
    callers = scan(data, text, START)
    return {'target': {'sha256': DIGEST, 'size': len(data)},
            'function': {'start': hex(START), 'end_exclusive': hex(END), 'size': len(body),
                         'body_sha256': hashlib.sha256(body).hexdigest(), 'file_offset': hex(offset),
                         'fde_length': '0x10', 'fde_offset': hex(fde), 'cie_offset': '0x0',
                         'padding_size': len(padding), 'next_fde_start': '0x538c9d0'},
            'rule': {'threshold': 4, 'subtract': 5, 'cap': 0xffffffc0,
                     'alignment': 64, 'multiplier': 8000, 'divisor_field': '0x120',
                     'division': 'unsigned with sign-extended 32-bit divisor'},
            'callees': [], 'direct_callers': callers, 'instruction_count': len(walk)}


def model(n, dword):
    need(0 <= n < 1 << 64 and 0 <= dword < 1 << 32, 'input width')
    divisor = dword if dword < 1 << 31 else dword + (1 << 64) - (1 << 32)
    if divisor == 0:
        raise ZeroDivisionError('x86 divide exception')
    numerator = 0 if n <= 4 else (min(n-5, 0xffffffc0) & ~63) * 8000
    return numerator // divisor


def readme(r):
    f, rule = r['function'], r['rule']
    walk = decode(bytes.fromhex(''.join(x[0] for x in INSNS)))
    lines = '\n'.join('| `%s` | `%s` | `%s` |' % (hex(a), b, s) for a,b,s in walk)
    callers = ', '.join('%s (%s)' % (x['site'], x['opcode']) for x in r['direct_callers']) or 'none'
    return f'''# RE-001: aligned quotient leaf (node #94)

Task: RE-001; component ownership unresolved. Bounded question: what does the
function at `{f['start']}` compute from `rsi` and the dword at `[rdi+{rule['divisor_field']}]`?

The function sets the numerator to zero when the unsigned `rsi` is at most
{rule['threshold']}; otherwise it subtracts {rule['subtract']}, caps the result at
`0x{rule['cap']:x}`, rounds it down to a multiple of {rule['alignment']}, and
multiplies by {rule['multiplier']}. It divides that numerator unsigned by the
64-bit sign extension of the dword at `[rdi+{rule['divisor_field']}]`, returning the
quotient in `rax`. A zero divisor raises the x86 divide exception even when
the numerator is zero. A negative signed dword becomes a large unsigned divisor;
it is not signed division. No source-level unit or type is established.

## Identity and bounds

Node #94 SHA-256 `{r['target']['sha256']}`; `{r['target']['size']}` bytes,
identity from `provenance/artifacts.json`. ELF virtual addresses are used.
The FDE range is `{f['start']}..{f['end_exclusive']}` ({f['size']} bytes),
file offset `{f['file_offset']}`, `.eh_frame+{f['fde_offset']}` (FDE length
`{f['fde_length']}`), CIE section offset `{f['cie_offset']}`.
The body SHA-256 is `{f['body_sha256']}`. It ends in `ret`, followed by
{f['padding_size']} `cc` bytes to the next FDE at `{f['next_fde_start']}`.
The branch stays within the range and both paths reach the return or the
processor's divide exception. These facts support the bound, without claiming
all possible entries are known. The baseline repository revision is `e5c9b643`;
the reference tree is not used for a semantic claim.

## Instruction walk

The decoder rejects any different instruction encoding, resolves the branch,
and checks the immediate values and field offset. Every instruction in the
FDE is shown ({r['instruction_count']} instructions):

| VA | Bytes | Instruction |
| --- | --- | --- |
{lines}

`mov eax` zero-extends the cap into `rax`; `cmova` uses an unsigned comparison.
The largest numerator fits in 64 bits. `xor edx, edx` makes the dividend
`0:rax`; for a nonzero divisor the quotient fits in `rax`. Memory validity
and an operational exception handler are assumptions outside this packet.

## Calls and scope

The function contains {len(r['callees'])} calls or tail jumps: there are no callee
identities or extents to bind. A complete `.text` byte-pattern scan for `e8`
and `e9` rel32 operands targeting the entry finds {len(r['direct_callers'])}
sites: {callers}. The scan includes possible false positives from instruction
interiors; indirect calls, other opcodes, relocations and data references are
not covered. No direct site does not establish that the function is unused.

## Novelty check

Before building this packet, both commands below returned no matches (exit 1):

```sh
rg -i '538c990|87607696' research/
rg -i '538c990|87607696' ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

There are no callees whose behavior is bound. The nearby arithmetic function
at the next FDE is not bound here. The address and behavior have no claimed
first-party attribution; the nearest dynamic symbol is not evidence of ownership.

## Reproduce and limits

From the repository root, with Python 3.10+ and the authenticated binary:

```sh
python3 tools/aligned_quotient_94.py --out research/work-items/RE-001-aligned-quotient-94/
python3 -m unittest tests.test_aligned_quotient_94 -v
python3 research/work-items/RE-001-aligned-quotient-94/verify.py
make verify
make catalogue-check
```

The generator parses the ELF sections and FDE, decodes the complete window,
scans all of `.text`, and emits deterministic records and this README. It
never executes the target or invokes an external disassembler. The Python
model checks consequences of the instructions, not observed target execution.
No Rust build, binary equivalence, wire format, global ownership, data or
whole-component completion is claimed; no progress gate changes. Next, trace
indirect references and examine the adjacent function's relationship to this
quotient before assigning units or a source-level name.
'''


def render_records(r):
    return json.dumps(r, indent=2, sort_keys=True) + '\n'


def generate(out, binary=BINARY):
    with open(binary, 'rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        r = inspect(data)
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    (out/'records.json').write_text(render_records(r), encoding='utf-8')
    (out/'README.md').write_text(readme(r), encoding='utf-8')
    names = ('README.md', 'records.json', 'verify.py')
    manifest = ''.join(hashlib.sha256((out/name).read_bytes()).hexdigest() + '  ' + name + '\n' for name in names)
    (out/'MANIFEST.sha256').write_text(manifest, encoding='ascii')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--binary', type=Path, default=BINARY)
    args = parser.parse_args()
    generate(args.out, args.binary)
