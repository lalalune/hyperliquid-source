#!/usr/bin/env python3
"""Authenticate and bind a #115 32-byte reverse-and-append leaf; never execute it."""
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
PACKET = ROOT / 'research/work-items/RE-001-node115-reverse-word256'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
START, END = 0x4332f70, 0x4332fd2
BODY_SHA = '2284a6038d49dc3add1dc92b244708a1728b9d88418338a7c63c4ea82f675045'
FDE, CIE = 0xe9cae4, 0xca6ed8
# This is a deliberately closed decoder for this window, including operands.
# A different instruction or operand fails rather than being guessed.
OPS = [
 ('488b4730', 'mov rax,[rdi+0x30]'),
 ('483dff030000', 'cmp rax,0x3ff'),
 ('7753', 'ja 0x4332fcf'),
 ('488b8f18010000', 'mov rcx,[rdi+0x118]'),
 ('488d5001', 'lea rdx,[rax+1]'),
 ('488b7728', 'mov rsi,[rdi+0x28]'),
 ('48c1e005', 'shl rax,5'),
 ('48895730', 'mov [rdi+0x30],rdx'),
 ('488b5118', 'mov rdx,[rcx+0x18]'),
 ('480fca', 'bswap rdx'),
 ('48891406', 'mov [rsi+rax],rdx'),
 ('488b5110', 'mov rdx,[rcx+0x10]'),
 ('480fca', 'bswap rdx'),
 ('4889540608', 'mov [rsi+rax+0x8],rdx'),
 ('488b5108', 'mov rdx,[rcx+0x8]'),
 ('480fca', 'bswap rdx'),
 ('4889540610', 'mov [rsi+rax+0x10],rdx'),
 ('488b11', 'mov rdx,[rcx]'),
 ('480fca', 'bswap rdx'),
 ('4889540618', 'mov [rsi+rax+0x18],rdx'),
 ('4883c120', 'add rcx,0x20'),
 ('48898f18010000', 'mov [rdi+0x118],rcx'),
 ('31c0', 'xor eax,eax'),
 ('c3', 'ret'),
 ('b02d', 'mov al,0x2d'),
 ('c3', 'ret'),
]


def digest(data):
    if hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('node #115 digest mismatch')


def decode(body):
    rows, pos = [], 0
    for expected, meaning in OPS:
        code = bytes.fromhex(expected)
        if body[pos:pos + len(code)] != code:
            raise ValueError('instruction or operand mismatch at %#x' % (START + pos))
        if code[0] == 0x77:
            target = START + pos + 2 + struct.unpack('b', code[1:])[0]
            if target != 0x4332fcf:
                raise ValueError('branch target mismatch')
        rows.append({'va': START + pos, 'bytes': code.hex(), 'instruction': meaning})
        pos += len(code)
    if pos != len(body) or pos != END - START:
        raise ValueError('incomplete instruction coverage')
    return rows


def validate_fde(row):
    if row != {'fde': FDE, 'cie': CIE, 'start': START, 'end': END, 'lsda': None}:
        raise ValueError('FDE mismatch')


def direct_scan(data, text, target=START):
    """Complete bytewise E8/E9 rel32 scan; hits need instruction-boundary proof."""
    if target != START:
        raise ValueError('unexpected scan target')
    begin, end = text['offset'], text['offset'] + text['size']
    found = []
    for op in (0xe8, 0xe9):
        pos = begin
        while True:
            pos = data.find(bytes([op]), pos, end - 4)
            if pos < 0:
                break
            va = text['address'] + pos - begin
            if va + 5 + struct.unpack_from('<i', data, pos + 1)[0] == target:
                found.append({'va': va, 'opcode': '%02x' % op})
            pos += 1
    return sorted(found, key=lambda x: x['va'])


def relocations(data, secs):
    """Read ELF64 Rela records naming this entry as a relative addend."""
    rela = next(s for s in secs if s['name'] == '.rela.dyn')
    if rela['size'] % 24:
        raise ValueError('invalid Rela size')
    rows = []
    for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, pos)
        if addend == START:
            if info != 8:
                raise ValueError('unexpected relocation type or symbol')
            rows.append({'file_offset': pos, 'slot_va': slot, 'type': 'R_X86_64_RELATIVE',
                         'addend': addend})
    if [r['slot_va'] for r in rows] != [0x64862f0, 0x6487058]:
        raise ValueError('relocation targets mismatch')
    ro = next(s for s in secs if s['name'] == '.data.rel.ro')
    if not all(ro['address'] <= r['slot_va'] and r['slot_va'] + 8 <= ro['address'] + ro['size'] for r in rows):
        raise ValueError('relocation slot outside data.rel.ro')
    return rows


def evidence(data):
    digest(data)
    secs = sections(data)
    text = next(s for s in secs if s['name'] == '.text')
    if (text['address'], text['size']) != (0x1419300, 0x63f0a00 - 0x1419300):
        raise ValueError('text extent mismatch')
    offset = text['offset'] + START - text['address']
    body = data[offset:offset + END - START]
    if hashlib.sha256(body).hexdigest() != BODY_SHA:
        raise ValueError('body hash mismatch')
    instructions = decode(body)
    cies, fdes = eh_frame_records(data, secs)
    matches = [row for row in fdes if row['start'] == START]
    if len(matches) != 1:
        raise ValueError('FDE is not unique')
    validate_fde(matches[0])
    cie = cies[CIE]
    if cie['augmentation'] != 'zR':
        raise ValueError('CIE mismatch')
    frame = next(s for s in secs if s['name'] == '.eh_frame')
    def raw_record(va):
        off = frame['offset'] + va - frame['address']
        length = struct.unpack_from('<I', data, off)[0] + 4
        return {'file_offset': off, 'bytes': data[off:off + length].hex()}
    before = data[offset - 15:offset]
    after = data[offset + len(body):offset + len(body) + 14]
    if before != b'\xcc' * 15 or after != b'\xcc' * 14:
        raise ValueError('padding mismatch')
    return {
        'target_sha256': SHA,
        'base_revision': '8fd8db680ec4bfef40996e5616bce3d5156d0b86',
        'window': {'start': START, 'end': END, 'size': len(body), 'file_offset': offset,
                   'body_sha256': BODY_SHA, 'fde': matches[0], 'fde_record': raw_record(FDE),
                   'cie_record': raw_record(CIE), 'cie': cie,
                   'padding_before': before.hex(), 'padding_after': after.hex()},
        'instructions': instructions,
        'callees': [],
        'relative_relocations': relocations(data, secs),
        'direct_rel32_candidates': direct_scan(data, text),
        'scan': {'start': text['address'], 'end': text['address'] + text['size'],
                 'opcodes': ['e8', 'e9'], 'instruction_boundaries_verified': False},
    }


def model(count, source):
    """Rule under valid, nonoverlapping memory and ordinary return assumptions."""
    if not 0 <= count < 2**64 or len(source) != 32:
        raise ValueError('expected u64 count and 32 input bytes')
    if count > 1023:
        return {'count': count, 'cursor_delta': 0, 'slot': None,
                'rax': (count & ~255) | 45}
    return {'count': count + 1, 'cursor_delta': 32, 'slot': source[::-1], 'rax': 0}


def render(record):
    w = record['window']
    walk = '\n'.join('| `0x%x` | `%s` | `%s` |' % (r['va'], r['bytes'], r['instruction'])
                     for r in record['instructions'])
    return '''# RE-001: reverse a 32-byte input into a bounded slot

- Component: serialization / foundation lead; original ownership unknown.
- Target: Linux x86-64 node #115, SHA-256 `{sha}`.
- Base/reference revision: `{revision}`; no external source used.
- Bounded question: what does the complete leaf at `0x{start:x}` write and return, including its capacity boundary?
- Answer: Given valid, nonoverlapping state, source and destination memory, if the unsigned qword at state `+0x30` is at most 1023, the function writes the 32 bytes at the pointer in state `+0x118` in reverse order to the slot at the pointer in state `+0x28` plus 32 times that count, increments the count, advances the source pointer by 32 and returns RAX 0. If the count is greater than 1023, it writes nothing and sets AL to `0x2d`; the upper 56 RAX bits retain the count's upper bits. These are register and memory observations, not a recovered type or error name.

## Evidence and scope

All addresses are original ELF virtual addresses; byte offsets are file offsets. The complete unwind-described window is `0x{start:x}..0x{end:x}` ({size} bytes), file offset `0x{offset:x}`, body SHA-256 `{body}`. FDE VA `0x{fde:x}` at file offset `0x{fdeoff:x}` references CIE VA `0x{cie:x}` at file offset `0x{cieoff:x}`, with no LSDA. The raw records and parsed CIE are in records.json. The preceding {before} and following {after} bytes are all `cc` padding; this and the two returns support, but do not by themselves prove, a source-level function boundary. The disassembly below covers the entire FDE, including both branches; every opcode and operand is checked by the closed Python decoder.

| VA | Bytes | Decoded instruction |
| --- | --- | --- |
{walk}

The `ja` uses unsigned comparison. On the success path each little-endian qword load is byte-swapped before its little-endian store; the four chunks are read in order +24, +16, +8, +0 and written at +0, +8, +16, +24. Hence the destination is the full reversal of the 32 source bytes. The count store occurs before the first input load; the cursor store occurs after all destination writes. The stated simple rule assumes state, source and destination do not overlap, readable and writable ranges are valid, and pointer arithmetic does not wrap. The failure branch touches no pointer or destination beyond the initial count read. No external or indirect call or tail call occurs in the body: **{callees} callees**. The complete bytewise `.text` scan for E8/E9 rel32 to this entry found **{callers} direct-call/jump candidates**; the scan tests every byte, including non-instruction bytes. Thus it establishes no direct rel32 caller here, but cannot find indirect calls, alternate entrypoints or code outside `.text`. The `.rela.dyn` scan found **{relocs} relative relocations** whose addend is this entry: destination slots `0x64862f0` and `0x6487058` in `.data.rel.ro`. Their presence supplies a lead for indirect references; it does not establish that either slot is called or identify an owner.

## Novelty

Before selection, both commands below produced no matches; no callee behavior is bound by this packet:

```sh
rg -i '4332f70' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -i '70463344' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

The search covers the available local research and PR-title lists at the base revision, not unlisted remote work.

## Reproduce and controls

From the repository root on Linux x86-64 with Python 3.10+ (local validation used 3.13.5), materialize the authenticated capture, then run. The producer uses the repository’s `elf_index` and `fde_extents` parsers, which use the Python standard library only:

```sh
python3 tools/node115_reverse_word256.py --out research/work-items/RE-001-node115-reverse-word256/
python3 -m unittest tests.test_node115_reverse_word256 -v
python3 research/work-items/RE-001-node115-reverse-word256/verify.py
```

The producer hashes the complete input before parsing, checks exact FDE, padding, all instruction operands and the full `.text` scan, then deterministically regenerates records, this README and the manifest. Tests cover boundary values, byte order, digest, mutated instructions, changed FDE, scan target and manifest corruption. No captured executable is run, and no network or side effects outside the selected output files occur.

## Limitations and next step

Before: no local packet bound this entry's rule. After: one complete {size}-byte FDE and {insns} decoded instructions are bound to the capture. There is no source build, Rust reconstruction, byte comparison or normalization mask. The original type, protocol role, input length validation, callers via function pointers, aliasing effects, invalid memory, exceptions and whole-node behavior remain unproved; no component gate or node equivalence is claimed. Next, identify the data relocation or function-pointer table that references this entry, then validate its dispatch and input bounds before attributing it to a codec.
'''.format(sha=record['target_sha256'], revision=record['base_revision'], start=w['start'],
           end=w['end'], size=w['size'], offset=w['file_offset'], body=w['body_sha256'],
           fde=w['fde']['fde'], fdeoff=w['fde_record']['file_offset'], cie=w['fde']['cie'],
           cieoff=w['cie_record']['file_offset'], before=len(bytes.fromhex(w['padding_before'])),
           after=len(bytes.fromhex(w['padding_after'])), walk=walk, callees=len(record['callees']),
           callers=len(record['direct_rel32_candidates']), relocs=len(record['relative_relocations']),
           insns=len(record['instructions']))


def generate(data, out):
    record = evidence(data)
    out = Path(out)
    if not (out / 'verify.py').is_file():
        raise ValueError('verify.py must already exist in output directory')
    files = {'records.json': json.dumps(record, indent=2) + '\n', 'README.md': render(record)}
    for name, content in files.items():
        (out / name).write_text(content, encoding='utf-8')
    names = ['README.md', 'records.json', 'verify.py']
    manifest = ''.join('%s  %s\n' % (hashlib.sha256((out / n).read_bytes()).hexdigest(), n) for n in names)
    (out / 'MANIFEST.sha256').write_text(manifest, encoding='ascii')
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    with TARGET.open('rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
        record = generate(data, args.out)
    print('Bound %#x: %d bytes, %d instructions, %d callees, %d direct rel32 candidates' %
          (START, record['window']['size'], len(record['instructions']), len(record['callees']),
           len(record['direct_rel32_candidates'])))


if __name__ == '__main__':
    main()
