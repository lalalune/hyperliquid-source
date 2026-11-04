#!/usr/bin/env python3
"""Produce an offline byte-bound certificate for the #115 20-byte record comparator."""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import re
import struct

from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
START, END = 0x5429440, 0x5429493
TEXT_START, TEXT_END = 0x1419300, 0x63f0a00
FDE, CIE = 0xf7d1a8, 0xca6ed8
CALLERS = (0x4e09521, 0x4e09549)

# Complete instruction grammar for this single window. Exact encodings are
# deliberately required; branches are additionally decoded and bounded below.
INSTRUCTIONS = [
 ('4885d2', 'test rdx,rdx'), ('744b', 'je empty'),
 ('48ffca', 'dec rdx'), ('0f1f840000000000', 'nop'),
 ('f30f6f07', 'movdqu xmm0,[rdi]'), ('f30f6f0e', 'movdqu xmm1,[rsi]'),
 ('660f74c8', 'pcmpeqb xmm1,xmm0'), ('660f6e4710', 'movd xmm0,[rdi+16]'),
 ('660f6e5610', 'movd xmm2,[rsi+16]'), ('660f74d0', 'pcmpeqb xmm2,xmm0'),
 ('660fdbd1', 'pand xmm2,xmm1'), ('660fd7c2', 'pmovmskb eax,xmm2'),
 ('4883c2ff', 'add rdx,-1'), ('0f92c1', 'setb cl'),
 ('3dffff0000', 'cmp eax,65535'), ('0f94c0', 'sete al'),
 ('750c', 'jne return'), ('4883c614', 'add rsi,20'),
 ('4883c714', 'add rdi,20'), ('84c9', 'test cl,cl'),
 ('75c1', 'jne loop'), ('c3', 'ret'), ('b001', 'mov al,1'), ('c3', 'ret')]
BRANCHES = {0x5429443: 0x5429490, 0x5429481: 0x542948f, 0x542948d: 0x5429450}

CALLER_INSTRUCTIONS = [
 ('488b5718', 'mov rdx,[rdi+24]'), ('483b5618', 'cmp rdx,[rsi+24]'),
 ('0f8519040000', 'jne mismatch'), ('4889f3', 'mov rbx,rsi'),
 ('488b7610', 'mov rsi,[rsi+16]'), ('4989fe', 'mov r14,rdi'),
 ('488b7f10', 'mov rdi,[rdi+16]'), ('e81aff6100', 'call comparator'),
 ('84c0', 'test al,al'), ('0f84fe030000', 'je mismatch'),
 ('498b5630', 'mov rdx,[r14+48]'), ('483b5330', 'cmp rdx,[rbx+48]'),
 ('0f85f0030000', 'jne mismatch'), ('488b7328', 'mov rsi,[rbx+40]'),
 ('498b7e28', 'mov rdi,[r14+40]'), ('5b', 'pop rbx'), ('415e', 'pop r14'),
 ('415f', 'pop r15'), ('e9f2fe6100', 'jmp comparator')]


def decode_caller_context(data):
    rows, pos, start = [], 0, 0x4e09505
    for encoded, instruction in CALLER_INSTRUCTIONS:
        expected = bytes.fromhex(encoded)
        actual = bytes(data[pos:pos + len(expected)])
        demand(actual == expected, 'caller context instruction changed at %#x' % (start + pos))
        row = {'va': hex(start + pos), 'bytes': actual.hex(), 'instruction': instruction}
        if actual[0] in (0xe8, 0xe9):
            row['target'] = hex(start + pos + len(actual) + struct.unpack_from('<i', actual, 1)[0])
            demand(int(row['target'], 16) == START, 'caller target changed')
        elif actual[:2] in (b'\x0f\x84', b'\x0f\x85'):
            row['target'] = hex(start + pos + len(actual) + struct.unpack_from('<i', actual, 2)[0])
            demand(int(row['target'], 16) == 0x4e0992c, 'caller branch target changed')
        rows.append(row)
        pos += len(expected)
    demand(pos == len(data), 'caller context coverage changed')
    return rows


def demand(value, message):
    if not value:
        raise ValueError(message)


def decode_body(body):
    rows = []
    pos = 0
    for encoded, text in INSTRUCTIONS:
        expected = bytes.fromhex(encoded)
        actual = bytes(body[pos:pos + len(expected)])
        demand(actual == expected, 'instruction encoding changed at %#x' % (START + pos))
        va = START + pos
        row = {'va': hex(va), 'bytes': actual.hex(), 'instruction': text}
        if va in BRANCHES:
            displacement = struct.unpack('b', actual[1:2])[0]
            dest = va + len(actual) + displacement
            demand(dest == BRANCHES[va] and START <= dest < END, 'branch target changed')
            row['target'] = hex(dest)
        rows.append(row)
        pos += len(expected)
    demand(pos == END - START == len(body), 'instruction coverage changed')
    return rows


def caller_target(data, file_offset, va):
    code = data[file_offset:file_offset + 5]
    demand(len(code) == 5 and code[0] in (0xe8, 0xe9), 'caller opcode changed')
    target = va + 5 + struct.unpack_from('<i', code, 1)[0]
    demand(target == START, 'caller target changed')
    return {'va': hex(va), 'opcode': 'call' if code[0] == 0xe8 else 'jmp',
            'bytes': bytes(code).hex(), 'target': hex(target)}


def extract(data, authenticate=True):
    if authenticate:
        demand(hashlib.sha256(data).hexdigest() == SHA, 'node #115 digest mismatch')
    secs = sections(data)
    text = [s for s in secs if s['name'] == '.text']
    demand(len(text) == 1 and text[0]['address'] == TEXT_START and
           text[0]['size'] == TEXT_END - TEXT_START, '.text mapping changed')
    section = text[0]
    def off(va):
        return section['offset'] + va - TEXT_START
    cies, fdes = eh_frame_records(data, secs)
    matching = [f for f in fdes if f['start'] == START]
    demand(matching == [{'fde': FDE, 'cie': CIE, 'start': START, 'end': END, 'lsda': None}], 'FDE changed')
    caller_fdes = [f for f in fdes if f['start'] == 0x4e08ed0]
    demand(caller_fdes == [{'fde': 0xf25dac, 'cie': CIE, 'start': 0x4e08ed0,
                            'end': 0x4e09953, 'lsda': None}], 'caller FDE changed')
    frame = next(s for s in secs if s['name'] == '.eh_frame')
    demand(frame['address'] == frame['offset'], '.eh_frame mapping changed')
    cie = cies[CIE]
    demand(cie == {'va': CIE, 'augmentation': 'zR', 'code_align': 1, 'data_align': -8,
                   'fde_encoding': 0x1b, 'lsda_encoding': None, 'personality_slot': None}, 'CIE changed')
    body = bytes(data[off(START):off(END)])
    ins = decode_body(body)
    padding = bytes(data[off(END):off(0x54294a0)])
    demand(padding == b'\xcc' * 13, 'padding changed')
    # Raw byte-pattern census: may include candidates starting inside instructions.
    context = bytes(data[off(0x4e09505):off(0x4e0954e)])
    context_rows = decode_caller_context(context)
    calls = []
    for match in re.compile(b'[\xe8\xe9]').finditer(data, off(TEXT_START), off(TEXT_END)):
        pos = match.start()
        if pos + 5 > off(TEXT_END):
            continue
        va = TEXT_START + pos - section['offset']
        target = va + 5 + struct.unpack_from('<i', data, pos + 1)[0]
        if target == START:
            calls.append(caller_target(data, pos, va))
    demand(tuple(int(x['va'], 16) for x in calls) == CALLERS, 'caller census changed')
    return {
        'target_sha256': SHA, 'coordinate': 'ELF virtual address',
        'window': {'start': hex(START), 'end': hex(END), 'size': len(body),
                   'file_offset': hex(off(START)), 'sha256': hashlib.sha256(body).hexdigest(),
                   'fde': hex(FDE), 'fde_file_offset': hex(FDE), 'cie': hex(CIE),
                   'cie_file_offset': hex(CIE), 'cie_bytes': bytes(data[CIE:CIE + 20]).hex(),
                   'cie_augmentation': cie['augmentation'],
                   'fde_encoding': hex(cie['fde_encoding']), 'lsda': None,
                   'fde_bytes': bytes(data[FDE:FDE + 20]).hex(),
                   'padding_start': hex(END), 'padding_end': hex(0x54294a0),
                   'padding_bytes': padding.hex()},
        'instructions': ins, 'callees': [], 'direct_rel32_candidates': calls,
        'caller_context': {'start': '0x4e09505', 'end': '0x4e0954e', 'bytes': context.hex(),
                           'fde': '0xf25dac', 'fde_start': '0x4e08ed0', 'fde_end': '0x4e09953',
                           'instructions': context_rows},
        'census_scope': {'start': hex(TEXT_START), 'end': hex(TEXT_END),
                         'method': 'all byte offsets with e8/e9 followed by signed rel32'},
        'rule': 'AL is one iff both valid sequences of count 20-byte records are bytewise equal',
    }


def model(left, right, count):
    """The bounded value relation; no native pointer or ABI emulation."""
    if count < 0 or len(left) < 20 * count or len(right) < 20 * count:
        raise ValueError('invalid record buffers')
    return all(left[20*i:20*i+20] == right[20*i:20*i+20] for i in range(count))


def readme(r):
    w = r['window']
    return f'''# RE-001: node #115 20-byte record equality

- Component: RE-001 function map; potential serialization/consensus use unproven.
- Target: node #115 SHA-256 `{SHA}`; base revision `8fd8db680ec4bfef40996e5616bce3d5156d0b86`. No external source is used.
- Bounded question: what predicate does the function at `{w['start']}` compute for its two input pointers and record count?
- Answer: given two readable, valid sequences of `count` consecutive 20-byte records, it returns AL=1 exactly when all corresponding bytes are equal, and AL=0 at the first unequal record. Count zero returns AL=1 without dereferencing either pointer. The function has no calls and writes no input memory. The original type and application meaning are unknown.

## Evidence and interpretation

ELF virtual-address window `{w['start']}..{w['end']}` is {w['size']} bytes at file offset `{w['file_offset']}`, body SHA-256 `{w['sha256']}`. Its actual FDE at `{w['fde']}` references CIE `{w['cie']}` (`zR`, PC-relative signed 4-byte encoding), with no LSDA. The {len(bytes.fromhex(w['padding_bytes']))} bytes from `{w['padding_start']}` to `{w['padding_end']}` are `cc` padding; they are outside the FDE. FDE and terminating control flow support this local extent; FDE alone does not prove a source-level boundary. The full {len(r['instructions'])}-instruction byte walk, branch destinations and original FDE bytes are in `records.json`.

RDI and RSI address the records; RDX is the count. The zero test branches to `mov al,1; ret`. For each nonempty record, two unaligned 16-byte loads and `pcmpeqb` compare offsets 0..15. The two `movd` instructions load offsets 16..19 and zero their upper 12 SIMD bytes; a second `pcmpeqb` therefore produces equal upper lanes and compares the final four in its low lanes. AND combines those lanes with the first comparison, and `pmovmskb` equals `0xffff` iff all 20 bytes match. The register decrement and carry track remaining records; a mismatch returns immediately, while matching records advance both pointers by 20. The final matched record returns one. This is a static all-input argument, not a captured execution or an assertion about the rest of RAX.

There are {len(r['callees'])} callees in the complete instruction walk. The full `.text` scan for `e8`/`e9` plus signed rel32 finds {len(r['direct_rel32_candidates'])} candidate sites: `0x4e09521` (call) and `0x4e09549` (tail jump). They are actual instruction starts in their enclosing FDE `0x4e08ed0..0x4e09953`; the nearby preceding comparisons check the two input lengths before each site. The raw scan checks every byte offset and can contain false positives; indirect references and code outside `.text` are excluded, so it is not a whole-program caller census. This observation does not identify the records' type or owner.

## Novelty and reproduction

The following commands returned no matches before selection (hex is case-insensitive):

```sh
rg -i '5429440|88249408' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

From the repository root, Python 3.10+ and standard library; no disassembler is used by these commands:

```sh
python3 tools/node115_record20_equality.py --out research/work-items/RE-001-node115-record20-equality/
python3 -m unittest tests.test_node115_record20_equality -v
python3 research/work-items/RE-001-node115-record20-equality/verify.py
make verify
make catalogue-check
```

Generation authenticates the full artifact and verifies the FDE, exact instruction encodings, branch targets, padding and all raw direct-relative candidates. The independent Python value model and tests cover zero, single/multiple records, every byte position and corruption below the identity gate. Discovery used GNU objdump 2.44, but retained generation and verification use strict Python decoding. No binary was executed, no native source was copied, and no source build, normalized comparison or implementation equivalence is claimed. Original compiler flags, relocations, indirect references, caller reachability, object layouts and fault behavior are unresolved. Valid readable buffers and non-wrapping pointer arithmetic are prerequisites; invalid pointers and concurrency are outside this claim. No full-scope progress gate is requested.

Next: identify the enclosing caller's record types and their provenance using independent data and caller evidence.
'''


def generate(out, target=TARGET):
    with target.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        records = extract(data)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'records.json').write_text(json.dumps(records, indent=2) + '\n')
    (out / 'README.md').write_text(readme(records))
    return records


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    generate(args.out)
