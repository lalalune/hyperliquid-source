#!/usr/bin/env python3
"""Static RE-001 binding of node #115's bounded 256-bit byte selection leaf.

Python 3.10+ stdlib and the repository's stdlib ELF/FDE parsers only. No native
disassembler, subprocess, target execution, network, or third-party packages.
"""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import struct

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
PACKET = ROOT / 'research/work-items/RE-001-node115-wide-byte-select'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
BASE = '05bc2de303c05525b71e7e257426e741bc66a390'
START, END, PAD_END = 0x43352f0, 0x4335379, 0x4335380
FDE, CIE = 0xe9ce8c, 0xca6ed8
BODY_SHA = '91bb3b777dc0a11d83080f40def59bbec98eec1490f24f6bf92e51d88f79f45c'
TEXT_START, TEXT_END, TEXT_OFFSET = 0x1419300, 0x63f0a00, 0x1418300
FDE_HEX = '10000000b85f1f005c8449038900000000000000'
CIE_HEX = '1400000000000000017a5200017810011b0c070890010000'
U64, U256 = (1 << 64) - 1, (1 << 256) - 1
LOCAL_FILES = {'README.md', 'records.json', 'verify.py'}
SOURCE_FILES = {'../../../tools/node115_wide_byte_select.py',
                '../../../tests/test_node115_wide_byte_select.py'}

# Deliberately finite decoder: each form specifies *all* opcode, prefix, ModRM,
# SIB and displacement bytes. Variable immediates and relative edges below are
# decoded separately, then checked against the observed contract. Unknown forms
# are errors, never guessed instruction lengths. This is not a general decoder.
FORMS = {
    '488b4f30': 'mov rcx,qword [rdi+0x30]',
    '48ffc9': 'dec rcx',
    '48894f30': 'mov qword [rdi+0x30],rcx',
    '488b7728': 'mov rsi,qword [rdi+0x28]',
    '488d040e': 'lea rax,[rsi+rcx]',
    '488b140e': 'mov rdx,qword [rsi+rcx]',
    '488b7c0e10': 'mov rdi,qword [rsi+rcx+0x10]',
    '480b7c0e08': 'or rdi,qword [rsi+rcx+0x08]',
    '480b7c0e18': 'or rdi,qword [rsi+rcx+0x18]',
    '0f94c1': 'sete cl',
    '400f92c6': 'setb sil',
    '4084f1': 'test cl,sil',
    '48f7d2': 'not rdx',
    '0fb60c02': 'movzx ecx,byte [rdx+rax]',
    '0f57c0': 'xorps xmm0,xmm0',
    '0f294424e8': 'movaps oword [rsp-0x18],xmm0',
    '48c74424f800000000': 'mov qword [rsp-0x08],0',
    '31c9': 'xor ecx,ecx',
    '488948e0': 'mov qword [rax-0x20],rcx',
    '0f284424e8': 'movaps xmm0,oword [rsp-0x18]',
    '0f1140e8': 'movups oword [rax-0x18],xmm0',
    '488b4c24f8': 'mov rcx,qword [rsp-0x08]',
    '488948f8': 'mov qword [rax-0x08],rcx',
    '31c0': 'xor eax,eax',
    'c3': 'ret',
}
FIXED = [(bytes.fromhex(raw), asm) for raw, asm in FORMS.items()]
IMMEDIATES = {
    b'\x48\x83\xf9': ('cmp rcx', 'minimum_depth', True),
    b'\x48\xc1\xe1': ('shl rcx', 'slot_shift', False),
    b'\x48\x83\xfa': ('cmp rdx', 'index_limit', True),
    b'\xb0': ('mov al', 'underflow_al', False),
}
BRANCHES = {0x72: 'jb', 0x74: 'je', 0xeb: 'jmp'}
EXPECTED_EDGES = {0x43352f8: ('jb', 0x4335376),
                  0x433532e: ('je', 0x433534a),
                  0x4335348: ('jmp', 0x433535d)}
EXPECTED_FACTS = {'minimum_depth': 2, 'slot_shift': 5,
                  'index_limit': 32, 'underflow_al': 44}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def decode(body):
    """Decode every byte of the bounded instruction vocabulary, including edges."""
    rows, pos = [], 0
    while pos < len(body):
        row = {'address': START + pos}
        opcode = body[pos]
        if opcode in BRANCHES:
            if pos + 2 > len(body):
                raise ValueError('truncated relative branch')
            size = 2
            delta = int.from_bytes(body[pos + 1:pos + 2], 'little', signed=True)
            row.update(branch=BRANCHES[opcode], target=START + pos + size + delta)
            row['instruction'] = f"{row['branch']} {row['target']:#x}"
        else:
            matched = False
            for prefix, (asm, fact, signed) in IMMEDIATES.items():
                if body[pos:pos + len(prefix)] != prefix:
                    continue
                size = len(prefix) + 1
                if pos + size > len(body):
                    raise ValueError('truncated immediate')
                value = int.from_bytes(body[pos + len(prefix):pos + size],
                                       'little', signed=signed)
                row.update(fact=fact, value=value, instruction=f'{asm},{value:#x}')
                matched = True
                break
            if not matched:
                matches = [(code, asm) for code, asm in FIXED
                           if body[pos:pos + len(code)] == code]
                if len(matches) != 1:
                    raise ValueError(f'unsupported instruction at {START + pos:#x}')
                code, row['instruction'] = matches[0]
                size = len(code)
        row['bytes'] = body[pos:pos + size].hex()
        row['size'] = size
        rows.append(row)
        pos += size
    return rows


def validate_walk(body):
    rows = decode(body)
    if len(body) != END - START:
        raise ValueError('body extent changed')
    by_address = {row['address']: row for row in rows}
    edges = {r['address']: (r['branch'], r['target']) for r in rows if 'branch' in r}
    if edges != EXPECTED_EDGES or any(t not in by_address for _, t in edges.values()):
        raise ValueError('branch target or condition changed')
    facts = {r['fact']: r['value'] for r in rows if 'fact' in r}
    if facts != EXPECTED_FACTS or sum('fact' in r for r in rows) != len(facts):
        raise ValueError('semantic immediate changed')
    # Enumerate all reachable edges; no call, external transfer, undecoded byte,
    # fall-through beyond the FDE, or unreachable hidden body is admitted.
    pending, reached = [START], set()
    while pending:
        pc = pending.pop()
        if pc in reached:
            continue
        if pc not in by_address:
            raise ValueError('control flow leaves decoded body')
        reached.add(pc)
        row = by_address[pc]
        if row['instruction'] == 'ret':
            continue
        if 'branch' in row:
            pending.append(row['target'])
        if row.get('branch') != 'jmp':
            pending.append(pc + row['size'])
    if reached != set(by_address):
        raise ValueError('unreachable instructions')
    if digest(body) != BODY_SHA:
        raise ValueError('body hash changed')
    return rows, facts


def file_offset(secs, address, size):
    matches = [s for s in secs if s['type'] != 8
               and s['address'] <= address
               and address + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('ambiguous or missing VA mapping')
    return matches[0]['offset'] + address - matches[0]['address']


def validate_sections(data):
    if len(data) < 64 or data[:16] != bytes.fromhex('7f454c46020101000000000000000000'):
        raise ValueError('unexpected ELF identity')
    if struct.unpack_from('<HH', data, 16) != (3, 62):
        raise ValueError('expected x86-64 ET_DYN')
    secs = sections(data)
    for name in ('.text', '.eh_frame', '.eh_frame_hdr', '.rela.dyn', '.data.rel.ro'):
        if sum(s['name'] == name for s in secs) != 1:
            raise ValueError('missing or duplicate section')
    text = next(s for s in secs if s['name'] == '.text')
    if (text['type'], text['flags'], text['address'], text['offset'], text['size']) != (
            1, 6, TEXT_START, TEXT_OFFSET, TEXT_END - TEXT_START):
        raise ValueError('text section changed')
    return secs


def frame_record(data, secs):
    cies, fdes = eh_frame_records(data, secs)
    matches = [f for f in fdes if f['start'] <= START < f['end'] or f['fde'] == FDE]
    expected = {'fde': FDE, 'cie': CIE, 'start': START, 'end': END, 'lsda': None}
    if matches != [expected]:
        raise ValueError('FDE extent or identity changed')
    fde_off, cie_off = file_offset(secs, FDE, 20), file_offset(secs, CIE, 24)
    if data[fde_off:fde_off + 20].hex() != FDE_HEX:
        raise ValueError('FDE bytes changed')
    if data[cie_off:cie_off + 24].hex() != CIE_HEX:
        raise ValueError('CIE bytes changed')
    _, index = unwind_index(data)
    indexed = [r for r in index if r['start'] == START or r['fde'] == FDE]
    if len(indexed) != 1 or (indexed[0]['start'], indexed[0]['fde'],
                            indexed[0]['next_index_upper_bound']) != (START, FDE, PAD_END):
        raise ValueError('unwind index changed')
    frame = next(s for s in secs if s['name'] == '.eh_frame')
    return {**expected, 'file_offset': fde_off,
            'section_offset': FDE - frame['address'], 'bytes': FDE_HEX,
            'cie_file_offset': cie_off, 'cie_bytes': CIE_HEX,
            'cie_fields': cies[CIE], 'index': indexed[0]}


def direct_candidates(data):
    """All .text byte positions holding e8/e9 + signed rel32 to this entry."""
    hits = []
    limit = TEXT_OFFSET + TEXT_END - TEXT_START
    for opcode in (b'\xe8', b'\xe9'):
        pos = TEXT_OFFSET
        while True:
            pos = data.find(opcode, pos, limit - 4)
            if pos < 0:
                break
            va = TEXT_START + pos - TEXT_OFFSET
            target = va + 5 + struct.unpack_from('<i', data, pos + 1)[0]
            if target == START:
                hits.append({'address': va, 'bytes': data[pos:pos + 5].hex(),
                             'kind': 'call' if opcode == b'\xe8' else 'jump',
                             'target': target})
            pos += 1
    return sorted(hits, key=lambda r: r['address'])


def pointer_references(data, secs):
    """Record actual relocation addends, without interpreting their users."""
    rela = next(s for s in secs if s['name'] == '.rela.dyn')
    if rela['type'] != 4 or rela['size'] % 24:
        raise ValueError('unsupported RELA section')
    refs = []
    for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, pos)
        if addend != START:
            continue
        if info != 8:
            raise ValueError('unexpected function pointer relocation type')
        off = file_offset(secs, slot, 8)
        refs.append({'rela_file_offset': pos, 'rela_bytes': data[pos:pos + 24].hex(),
                     'type': 'R_X86_64_RELATIVE', 'symbol_index': info >> 32,
                     'slot': slot, 'slot_file_offset': off, 'addend': addend,
                     'slot_file_bytes': data[off:off + 8].hex()})
    if [(r['rela_file_offset'], r['slot'], r['slot_file_bytes']) for r in refs] != [
            (0xb3dc0, 0x6485fc8, '0000000000000000'),
            (0xb5bf0, 0x6486d30, '0000000000000000')]:
        raise ValueError('function pointer references changed')
    return refs


def model(slots, depth=None, entry_rax=0):
    """Independent logical-slot model; inactive/popped storage is preserved.

    The native preconditions (valid, nonoverlapping object/buffer/red-zone and
    nonwrapping address arithmetic) are outside this integer-only API.
    """
    if depth is None:
        depth = len(slots)
    if type(depth) is not int or not 0 <= depth <= len(slots):
        raise ValueError('invalid logical depth')
    if any(type(v) is not int or not 0 <= v <= U256 for v in slots):
        raise ValueError('slot is not u256')
    if type(entry_rax) is not int or not 0 <= entry_rax <= U64:
        raise ValueError('entry RAX is not u64')
    after = list(slots)
    if depth < 2:
        return {'depth': depth, 'slots': after, 'rax': (entry_rax & ~255) | 44}
    index, value = slots[depth - 1], slots[depth - 2]
    after[depth - 2] = (value >> (8 * (31 - index))) & 255 if index < 32 else 0
    return {'depth': depth - 1, 'slots': after, 'rax': 0}


def byte_address_rule(index, value, facts):
    """Instruction-derived relation: OR high limbs, unsigned guard, NOT offset.

    This computes an equation over bytes, not a CPU or target execution trace.
    """
    raw = index.to_bytes(32, 'little')
    low = int.from_bytes(raw[:8], 'little')
    upper_or = (int.from_bytes(raw[8:16], 'little') |
                int.from_bytes(raw[16:24], 'little') |
                int.from_bytes(raw[24:], 'little'))
    if upper_or or low >= facts['index_limit']:
        return 0
    relative_to_lower_slot = ((1 << facts['slot_shift']) + ((~low) & U64)) & U64
    return value.to_bytes(32, 'little')[relative_to_lower_slot]


def vectors(facts):
    # Asymmetric bytes distinguish byte order and every in-range index. Wide
    # indexes with a small low limb distinguish the high-limb OR from truncation.
    value = int.from_bytes(bytes(range(1, 33)), 'little')
    cases = [(f'index-{i}', i, value) for i in range(33)]
    cases += [(f'wide-index-{i}', j, U256) for i, j in enumerate(
        (33, 63, 255, 1 << 32, 1 << 63, U64, 1 << 64,
         (1 << 64) + 31, 1 << 128, 1 << 192, U256))]
    cases += [('zero-value', 0, 0), ('all-ones-value', 31, U256),
              ('msb-only', 0, 1 << 255), ('lsb-only', 31, 255)]
    out = []
    for label, index, value in cases:
        # Prefix, popped and inactive cells are all observable controls.
        before = [0x123456, value, index, 0xabcdef]
        expected = {'depth': 2,
                    'slots': [before[0], byte_address_rule(index, value, facts),
                              index, before[3]], 'rax': 0}
        out.append({'label': label, 'depth': 3, 'entry_rax': U64,
                    'slots': before, 'expected': expected})
    for depth in (0, 1):
        before = [0x123456, 0xabcdef]
        out.append({'label': f'underflow-{depth}', 'depth': depth,
                    'entry_rax': 0x123456789abcdeff, 'slots': before,
                    'expected': {'depth': depth, 'slots': before,
                                 'rax': 0x123456789abcde00 | facts['underflow_al']}})
    if any(model(v['slots'], v['depth'], v['entry_rax']) != v['expected'] for v in out):
        raise ValueError('independent model and byte-address relation disagree')
    return out


def inspect(data, *, authenticate=True):
    """Internal authenticate=False exists only for focused byte-corruption tests.

    The CLI and packet verifier always authenticate the entire original input.
    """
    if authenticate and digest(data) != SHA:
        raise ValueError('node #115 digest mismatch')
    secs = validate_sections(data)
    frame = frame_record(data, secs)
    off = file_offset(secs, START, END - START)
    body = data[off:off + END - START]
    rows, facts = validate_walk(body)
    pad = data[off + len(body):off + PAD_END - START]
    if pad != b'\xcc' * (PAD_END - END):
        raise ValueError('padding changed')
    hits = direct_candidates(data)
    if hits:
        raise ValueError('direct caller census changed')
    refs = pointer_references(data, secs)
    fixtures = vectors(facts)
    return {
        'target': {'release': 115, 'sha256': SHA, 'size': len(data),
                   'artifact': 'artifacts/node/115/hl-node'},
        'coordinate_system': 'original ELF virtual addresses; ends exclusive',
        'window': {'start': START, 'end': END, 'size': len(body), 'file_offset': off,
                   'body_sha256': digest(body), 'body_hex': body.hex(), 'frame': frame,
                   'padding_start': END, 'padding_end': PAD_END, 'padding_hex': pad.hex()},
        'instructions': rows, 'facts': facts,
        'callees': [], 'direct_rel32_candidates': hits,
        'scan': {'start': TEXT_START, 'end': TEXT_END, 'file_offset': TEXT_OFFSET,
                 'method': 'every byte position e8/e9 with signed little-endian rel32',
                 'instruction_boundaries_assumed': False},
        'function_pointer_relocations': refs,
        'relation': {
            'inputs': 'n=qword[entry RDI+0x30], p=qword[entry RDI+0x28] on n>=2',
            'slots': '32-byte little-endian unsigned integers; top index at p+32*(n-1)',
            'underflow': 'n<2: AL=44, upper RAX unchanged, no memory writes',
            'normal': 'n>=2: depth=n-1; lower slot=(value>>(8*(31-index)))&255 if index<32 else 0; RAX=0',
            'buffer_effects': 'overwrite only slot n-2; popped index slot and other slots unchanged',
            'scratch_effects': 'zero the 24 bytes [entry RSP-24,entry RSP)',
            'preconditions': 'valid nonoverlapping header, slot buffer and aligned red-zone; nonwrapping buffer addresses',
            'ownership': 'unresolved; no first-party or original source-name claim'},
        'vectors': fixtures,
        'counts': {'body_bytes': len(body), 'instructions': len(rows),
                   'branches': sum('branch' in r for r in rows),
                   'returns': sum(r['instruction'] == 'ret' for r in rows),
                   'callees': 0, 'caller_candidates': len(hits),
                   'padding_bytes': len(pad), 'pointer_relocations': len(refs),
                   'vectors': len(fixtures)},
    }


def readme(r):
    w, c, f = r['window'], r['counts'], r['facts']
    frame = w['frame']
    return f'''# RE-001: node #115 wide byte selection

- Component/task: RE-001 function map; a complete computational leaf, with original module ownership unresolved.
- Target: Linux x86-64 node #115, SHA-256 `{r['target']['sha256']}`.
- Source/reference revision: repository base `{BASE}`. Independently authored analysis/model under MIT; no original Rust source is available.
- Question: which byte does `{w['start']:#x}` select from its two wide operands, what happens for a wide or out-of-range index, and which state changes occur?
- Claim status: instructions, extents, references and writes are observations; the integer rule below is a deduction from them. Source names, source types and callers' protocol meaning remain unresolved.

**Answer:** Read unsigned depth `n` from `[entry RDI+0x30]`. If `n<{f['minimum_depth']}`, return `AL={f['underflow_al']:#x}` with upper RAX preserved and no memory writes. Otherwise, read buffer pointer `p=[entry RDI+0x28]`, interpret its slots as little-endian 256-bit integers, let `index=slot[n-1]` and `value=slot[n-2]`, decrement depth, and replace `slot[n-2]` with `(value >> (8*(31-index))) & 255` when the full-width index is below `{f['index_limit']}`, or zero otherwise. Return `RAX=0`. Index zero selects the most significant byte. The popped index slot and all other buffer slots retain their bytes; the red-zone scratch described below is zeroed.

## Extent and evidence

| Measurement | Value |
| --- | ---: |
| Body bytes | {c['body_bytes']} |
| Decoded instructions | {c['instructions']} |
| Internal branch instructions | {c['branches']} |
| Return instructions | {c['returns']} |
| Direct or indirect callees | {c['callees']} |
| Direct rel32 caller candidates | {c['caller_candidates']} |
| Following padding bytes | {c['padding_bytes']} |
| Relocated function pointers | {c['pointer_relocations']} |
| Instruction-grounded model vectors | {c['vectors']} |

The full body is ELF VA `[{w['start']:#x},{w['end']:#x})`, file offset `{w['file_offset']:#x}`, SHA-256 `{w['body_sha256']}`. FDE VA/file offset `{frame['fde']:#x}` (section offset `{frame['section_offset']:#x}`) refers to CIE VA/file offset `{frame['cie']:#x}`. Its `zR` augmentation uses `pcrel|sdata4`, no personality or LSDA, and default CFA `RSP+8` with return address at CFA-8. Raw FDE/CIE bytes and decoded fields are in `records.json`. The unwind index independently names this entry/FDE and the next entry `{w['padding_end']:#x}`; the intervening padding is entirely `cc`. The FDE, complete reachable walk and local returns jointly support this extent. No function census denominator is inferred from unwind starts.

`records.json` retains every instruction's original bytes, VA and strict Python decoding, with no normalization. All conditional paths and the merge are covered. No body instruction transfers to a callee; therefore callee identities/extents and wrong-callee-target controls are inapplicable. An injected CALL is rejected as unsupported, and retargeted local branches are rejected.

## Instruction proof and memory contract

At `0x43352f4`, unsigned `CMP/JB` checks depth before the buffer pointer or any slot is read. The underflow arm at `0x4335376` writes AL only. On the other arm, `DEC` and the store at `0x43352fd` reduce depth before any slot read. The shift by `{f['slot_shift']}` and LEA put the popped index slot address in RAX; subsequent writes to CL and SIL do not alter that retained address.

The load at `0x433530d` obtains the index's low limb. The load/OR/OR at `0x4335311..0x4335320` tests all remaining limbs for zero. `SETE CL`, unsigned `CMP RDX,{f['index_limit']}`, `SETB SIL` and `TEST CL,SIL` jointly admit exactly a full-width index below the bound. A nonzero high limb is rejected even when its low limb is small. This is not a truncating index operation.

For an admitted low limb `j`, NOT computes `-j-1` modulo the machine word. The byte load at `0x4335333` therefore reads `p+32*(n-1)-j-1`, namely byte `31-j` of the preceding little-endian slot. MOVZX zero-extends it; the alternative arm clears ECX. The common stores overwrite the result slot's low qword and zero its upper bytes. The other loaded index limbs are never written back. Both normal arms write zero to `[entry RSP-0x18,entry RSP)` and read that scratch back for the result; they leave RSP unchanged. The aligned MOVAPS scratch accesses require the usual entry alignment `RSP mod 16 = 8` and a valid red-zone. The body performs no allocation and reads no globals, import slots or constant pool.

The normal-return rule assumes valid readable header fields, a writable buffer holding the active slots, nonwrapping address arithmetic, and disjoint buffer/header/red-zone memory. It does not describe invalid pointer faults, asynchronous interference or aliasing those regions. In particular, the depth store precedes later accesses, so an access fault is not claimed to roll back state. The early underflow arm needs only the depth field and a valid return stack. ABI register preservation beyond the decoded effects and original Rust types remain unclaimed.

## References and ownership

The raw census scans the entire `.text` interval `[{r['scan']['start']:#x},{r['scan']['end']:#x})` at every possible byte position for `e8`/`e9` plus signed rel32 landing at the entry. Its empty result establishes no direct byte-pattern candidates in that interval. This scan is not a whole-program caller proof: it misses indirect calls and non-rel32 encodings, and a nonempty result would need instruction-boundary validation.

Actual `.rela.dyn` R_X86_64_RELATIVE entries at file offsets `0xb3dc0` and `0xb5bf0` have this entry as addend and write pointer slots `0x6485fc8` and `0x6486d30`. Their raw records and original zero-filled slots are retained. The pointer consumers and dispatch tables are unbound; pointer references are not counted as callers. This leaf has no panic Location or proven first-party attribution. Selection considered source-associated candidates, but this packet binds a complete byte operation rather than inheriting ownership from proximity or from a vendor name.

## Novelty, reproduction and controls

Before adding these files, both address searches produced empty stdout and exit status 1. The spelling search also produced empty stdout and exit status 1:

```sh
rg -i '43352f0|70472432' research/
rg -i '43352f0|70472432' ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -i 'wide-byte-select|wide_byte_select' ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt research/ tools/ tests/
```

From repository root, with materialized inputs and Python 3.10+ stdlib (observed locally with Python 3.13.5, Linux x86-64):

```sh
python3 tools/node115_wide_byte_select.py --out research/work-items/RE-001-node115-wide-byte-select/
python3 -m unittest tests.test_node115_wide_byte_select -v
python3 research/work-items/RE-001-node115-wide-byte-select/verify.py
make verify
make catalogue-check
```

The producer maps the binary once, authenticates its complete digest before parsing or writing output, reuses the repository's stdlib ELF/FDE parsers, decodes its complete bounded instruction vocabulary and regenerates the packet byte-identically. GNU objdump 2.44 was used for initial inspection only; no generator, verifier or test invokes it. Analysis is static and complete for this body. The Python logical-slot model and separately derived byte-address equation are independently authored; vectors cover every admitted index, boundary rejection, nonzero high limbs, byte order, unchanged storage and both underflow depths. They are instruction-grounded expectations, not runtime observations.

Controls reject wrong digest, an actual window mutation, a shifted FDE, altered CIE/index metadata, changed padding, unsupported CALL, incorrect branch target, semantic immediate changes, changed function-pointer addend and newly injected direct caller patterns. README counts are tested against the JSON. The whitelist verifier authenticates the exact packet file set, tool/test source hashes and regenerated evidence. No captured executable, emulator, network, signing or chain action is used.

## Results, non-claims and next step

Before this work no retained address match existed; after it, the bounded byte-selection rule, underflow behavior and memory writes are explained from the complete authenticated body. No Rust implementation, source-build comparison, normalization mask, instruction equivalence measurement, source identity, original ABI, dispatch closure, full-node behavior or component gate is claimed. All full-scope acceptance gates remain unchanged. Local checks validate this packet and its controls; they do not claim hosted CI or repository-wide tests.

Observed local result: regeneration, targeted unit tests, the packet verifier and `make verify` pass. `make catalogue-check` fails on the root README's pre-existing stale generated work-item inventory; this was confirmed while the tracked tree and index were still unchanged from the recorded base. Adding this packet also changes that inventory. Catalogue/progress files remain untouched under the add-only scope. Repository-wide `make test` was not run.

Next: resolve the consumers of the recorded function-pointer slots and prove their operand construction and returned-byte handling before attaching an opcode, API or protocol name.
'''


VERIFIER = '''#!/usr/bin/env python3
"""Whitelist, authenticate and regenerate this packet without target execution."""
from pathlib import Path
import sys

sys.dont_write_bytecode = True
packet = Path(__file__).resolve().parent
sys.path.insert(0, str(packet.parents[2] / 'tools'))
from node115_wide_byte_select import verify_packet

verify_packet(packet)
print('Packet whitelist, source hashes and authenticated regeneration OK')
'''


def packet_bytes(record):
    contents = {'README.md': readme(record).encode(),
                'records.json': (json.dumps(record, indent=2, sort_keys=True) + '\n').encode(),
                'verify.py': VERIFIER.encode()}
    hashes = {name: digest(data) for name, data in contents.items()}
    for relative in SOURCE_FILES:
        hashes[relative] = digest(ROOT.joinpath(*Path(relative).parts[3:]).read_bytes())
    contents['MANIFEST.sha256'] = ''.join(
        f'{hashes[name]}  {name}\n' for name in sorted(hashes)).encode()
    return contents


def inspect_file(path):
    with Path(path).open('rb') as stream:
        if stream.seek(0, 2) == 0:
            raise ValueError('node #115 digest mismatch')
        stream.seek(0)
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
            return inspect(data)


def generate(binary, out):
    result = inspect_file(binary)
    contents = packet_bytes(result)
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    for name, content in contents.items():
        (out / name).write_bytes(content)
    return result


def verify_manifest(packet):
    packet = Path(packet)
    if {p.name for p in packet.iterdir()} != LOCAL_FILES | {'MANIFEST.sha256'}:
        raise ValueError('packet file whitelist changed')
    seen = set()
    for line in (packet / 'MANIFEST.sha256').read_text().splitlines():
        want, separator, name = line.partition('  ')
        if (separator != '  ' or name not in LOCAL_FILES | SOURCE_FILES or name in seen
                or len(want) != 64 or any(c not in '0123456789abcdef' for c in want)):
            raise ValueError('manifest whitelist violation')
        path = packet / name if name in LOCAL_FILES else ROOT.joinpath(*Path(name).parts[3:])
        if path.is_symlink() or not path.is_file() or digest(path.read_bytes()) != want:
            raise ValueError('manifest hash mismatch: ' + name)
        seen.add(name)
    if seen != LOCAL_FILES | SOURCE_FILES:
        raise ValueError('manifest entries missing')


def verify_packet(packet):
    verify_manifest(packet)
    expected = packet_bytes(inspect_file(TARGET))
    for name, data in expected.items():
        if (Path(packet) / name).read_bytes() != data:
            raise ValueError('regeneration mismatch: ' + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--out', type=Path, default=PACKET)
    args = parser.parse_args()
    result = generate(args.binary, args.out)
    print(json.dumps(result['counts'], sort_keys=True))


if __name__ == '__main__':
    main()
