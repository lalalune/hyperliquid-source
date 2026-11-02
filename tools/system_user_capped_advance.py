#!/usr/bin/env python3
"""Static RE-001 bind of node #94 0x3b9d9b0; Python 3.10+ stdlib only.

No target execution or external disassembler. ELF/FDE parsing reuses the
repository's stdlib readers. The deliberately small instruction decoder
accepts only the encodings needed by this complete function, never guesses
instruction lengths, and rejects unsupported or truncated input.
"""

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import mmap
from pathlib import Path
import re
import struct
import sys

from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
NAME = 'system_user_capped_advance'
PACKET_REL = 'research/work-items/RE-001-system-user-capped-advance-94'
PACKET = ROOT / PACKET_REL
TARGET_REL = 'artifacts/node/94/hl-node'
TARGET = ROOT / TARGET_REL
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SIZE = 91774280
START, END, NEXT = 0x3b9d9b0, 0x3b9d9f7, 0x3b9da00
CALLEE, CALLEE_END, CALLEE_NEXT = 0x157b480, 0x157b499, 0x157b4a0
SLOT, LOCATION, PATH_VA, POINTER_SLOT = 0x576e118, 0x5712ff0, 0x1f5836, 0x5776280
CAP, MASK = 30, (1 << 64) - 1
BODY = bytes.fromhex(
    '5048033772344889f048ffc0742c488b4f084801c172234883f91e760b'
    '48c7071e000000b01e59c34889074883fe1eb81e000000480f42c659c3'
    '488d3dff55b701ff152107bd01')
BODY_SHA = '1b77785b7ec902c12d4792412e3e3d0302844e66d94a947905be97b539ae3d64'
CALLEE_SHA = '1942fe4d3c3a14b88f1cc4ad4a627f2c97b5bd6983d5ba6a77dfd50fb8e395e6'
# Captured build-root bytes, not a path on the analyst's machine. Output uses
# only the source suffix and hashes; it never serializes an absolute path.
SOURCE_PREFIX = bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f')
SOURCE_SUFFIX = 'l1/src/system_user.rs'
BASE_COMMIT = 'e5c9b6436876b2a4a39daef813171f9879317699'
SNAPSHOTS = [
    ('open_prs.txt', 56488, 'c254c57d541b199fd589cb386324a579eba28a74cabff3309aaa9e2971c4066c'),
    ('merged_prs.txt', 110952, 'c291aef81f04946a0e6594630e2a5538052c57d12bc79580150555ee0d89ac6d'),
    ('closed_unmerged_prs.txt', 15108, '7ffc9b73e46cf197874fe3cc691a8c8380e5ef8139dc4d23d90ff7db86819406'),
]
GENERATED = ('README.md', 'records.json', 'instructions.txt')
MANIFEST_NAMES = tuple(f'{PACKET_REL}/{name}' for name in (*GENERATED, 'verify.py')) + (
    f'tools/{NAME}.py', f'tests/test_{NAME}.py')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


@contextmanager
def mapped(path):
    with Path(path).open('rb') as handle:
        require(handle.seek(0, 2) == SIZE, 'Target size mismatch')
        handle.seek(0)
        with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
            require(sha(data) == SHA256, 'Target SHA-256 mismatch')
            yield data


class Image:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)
        self.by_name = {s['name']: s for s in self.sections}
        require(len(self.by_name) == len(self.sections), 'Duplicate ELF section')

    def offset(self, va, size):
        matches = [s for s in self.sections if s['type'] != 8 and size >= 0
                   and s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(matches) == 1, 'Unmapped or ambiguous VA range')
        s = matches[0]
        return s['offset'] + va - s['address']

    def read(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off + size]

    def frame_rows(self):
        _, rows = eh_frame_records(self.data, self.sections)
        return rows


@dataclass(frozen=True)
class Instruction:
    va: int
    raw: bytes
    op: str
    args: tuple = ()

    @property
    def after(self):
        return self.va + len(self.raw)

    def text(self):
        args = ', '.join(hex(a) if isinstance(a, int) else a for a in self.args)
        return self.op + (' ' + args if args else '')


# Every fixed pattern is a complete, reviewed x86-64 encoding. Variable
# fields below are read with their actual width and signedness.
FIXED = (
    ('50', 'push', ('rax',)), ('59', 'pop', ('rcx',)), ('c3', 'ret', ()),
    ('480337', 'add', ('rsi', 'qword [rdi]')),
    ('4889f0', 'mov', ('rax', 'rsi')),
    ('48ffc0', 'inc', ('rax',)),
    ('488b4f08', 'mov', ('rcx', 'qword [rdi+0x8]')),
    ('4801c1', 'add', ('rcx', 'rax')),
    ('488907', 'mov', ('qword [rdi]', 'rax')),
    ('480f42c6', 'cmovb', ('rax', 'rsi')),
)
FIXED = tuple((bytes.fromhex(raw), op, args) for raw, op, args in FIXED)


def decode_one(body, pos, base=START):
    require(0 <= pos < len(body), 'Instruction offset outside body')
    va = base + pos

    def take(n):
        require(pos + n <= len(body), 'Truncated instruction')
        return body[pos:pos + n]

    for raw, op, args in FIXED:
        if body[pos:pos + len(raw)] == raw:
            return Instruction(va, take(len(raw)), op, args)
    first = body[pos]
    if first in (0x72, 0x74, 0x76):
        raw = take(2)
        target = va + 2 + struct.unpack_from('<b', raw, 1)[0]
        return Instruction(va, raw, {0x72: 'jb', 0x74: 'je', 0x76: 'jbe'}[first], (target,))
    for prefix, op, dest in ((b'\x48\x83\xf9', 'cmp', 'rcx'),
                             (b'\x48\x83\xfe', 'cmp', 'rsi')):
        if body[pos:pos + 3] == prefix:
            raw = take(4)
            return Instruction(va, raw, op, (dest, struct.unpack_from('<b', raw, 3)[0]))
    if body[pos:pos + 3] == b'\x48\xc7\x07':
        raw = take(7)
        return Instruction(va, raw, 'mov', ('qword [rdi]', struct.unpack_from('<i', raw, 3)[0]))
    if first in (0xb0, 0xb8):
        raw = take(2 if first == 0xb0 else 5)
        value = raw[1] if first == 0xb0 else struct.unpack_from('<I', raw, 1)[0]
        return Instruction(va, raw, 'mov', ('al' if first == 0xb0 else 'eax', value))
    if body[pos:pos + 3] == b'\x48\x8d\x3d':
        raw = take(7)
        return Instruction(va, raw, 'lea', ('rdi', va + 7 + struct.unpack_from('<i', raw, 3)[0]))
    if body[pos:pos + 2] == b'\xff\x15':
        raw = take(6)
        return Instruction(va, raw, 'call_slot', (va + 6 + struct.unpack_from('<i', raw, 2)[0],))
    raise ValueError(f'Unsupported instruction at {va:#x}')


def decode_window(body, base=START):
    out, pos = [], 0
    while pos < len(body):
        ins = decode_one(body, pos, base)
        out.append(ins)
        pos += len(ins.raw)
    starts = {ins.va for ins in out}
    for ins in out:
        if ins.op in ('jb', 'je', 'jbe'):
            require(ins.args[0] in starts, 'Branch does not target an instruction boundary')
    return out


def checked_program(body):
    program = decode_window(body)
    require(body == BODY and sha(body) == BODY_SHA, 'Function body changed')
    require([i.args for i in program if i.op == 'call_slot'] == [(SLOT,)], 'Wrong call slot')
    require([i.args for i in program if i.op == 'lea'] == [('rdi', LOCATION)], 'Wrong Location')
    return program


def model(old, offset, extra):
    """Independent integer rule; return exact RAX as well as the low byte.

    Overflow returns a transfer record before any object store. It does not
    model the shared callee or claim that it returns, unwinds, or terminates.
    """
    for value in (old, offset, extra):
        require(type(value) is int and 0 <= value <= MASK, 'Expected u64 input')
    total = old + offset
    if total > MASK:
        return {'outcome': 'transfer', 'stage': 'old_plus_offset', 'stored': None}
    following = total + 1
    if following > MASK:
        return {'outcome': 'transfer', 'stage': 'plus_one', 'stored': None}
    if following + extra > MASK:
        return {'outcome': 'transfer', 'stage': 'plus_extra', 'stored': None}
    if following + extra > CAP:
        return {'outcome': 'return', 'stored': CAP,
                'rax': (following & ~0xff) | CAP, 'al': CAP}
    return {'outcome': 'return', 'stored': following, 'rax': total, 'al': total}


# Independently worked examples, not outputs generated by the model itself.
VECTORS = (
    ('initial', (0, 0, 0), ('return', 1, 0, 0)),
    ('below_cap', (0, 28, 0), ('return', 29, 28, 28)),
    ('equal_cap_with_extra', (28, 0, 1), ('return', 29, 28, 28)),
    ('equal_cap_without_extra', (29, 0, 0), ('return', 30, 29, 29)),
    ('past_cap_with_extra', (29, 0, 1), ('return', 30, 30, 30)),
    ('extra_forces_cap', (0, 0, 30), ('return', 30, 30, 30)),
    ('already_at_cap', (30, 0, 0), ('return', 30, 30, 30)),
    ('low_byte_only_256', (255, 0, 0), ('return', 30, 0x11e, 30)),
    ('low_byte_only_257', (0, 256, 0), ('return', 30, 0x11e, 30)),
    ('largest_nonoverflow', (0, MASK - 1, 0), ('return', 30, 0xffffffffffffff1e, 30)),
    ('first_add_overflow', (MASK, 1, 0), ('transfer', 'old_plus_offset')),
    ('increment_overflow', (MASK, 0, 0), ('transfer', 'plus_one')),
    ('last_add_overflow', (0, 0, MASK), ('transfer', 'plus_extra')),
    ('last_add_overflow_at_max', (0, MASK - 1, 1), ('transfer', 'plus_extra')),
)


def vectors():
    out = []
    for label, inputs, expected in VECTORS:
        if expected[0] == 'return':
            result = dict(outcome='return', stored=expected[1], rax=expected[2], al=expected[3])
        else:
            result = dict(outcome='transfer', stage=expected[1], stored=None)
        require(model(*inputs) == result, 'Model differs from instruction-derived vector')
        out.append(dict(label=label, inputs=dict(zip(('old', 'offset', 'extra'), inputs)), expected=result))
    return out


def frame_record(image, rows, start, end, next_start, fde_offset, expected_sha):
    matches = [f for f in rows if f['start'] == start]
    require(len(matches) == 1, 'Missing or ambiguous function FDE')
    row = matches[0]
    eh = image.by_name['.eh_frame']
    require(row['end'] == end and row['fde'] - eh['address'] == fde_offset
            and row['cie'] == eh['address'] and row['lsda'] is None, 'FDE association changed')
    # Reject an overlapping earlier FDE or an interior entry, even if the
    # selected FDE still has the expected range.
    require(not any(f is not row and f['start'] < end and f['end'] > start for f in rows),
            'Overlapping function FDE')
    later = min((f for f in rows if f['start'] > start), key=lambda f: f['start'])
    require(later['start'] == next_start, 'Next FDE changed')
    body = image.read(start, end - start)
    require(sha(body) == expected_sha, 'Body SHA-256 changed')
    padding = image.read(end, next_start - end)
    require(padding == b'\xcc' * (next_start - end), 'Padding changed')
    length = struct.unpack('<I', image.read(row['fde'], 4))[0]
    cie_length = struct.unpack('<I', image.read(row['cie'], 4))[0]
    return {
        'start_va': hex(start), 'end_va_exclusive': hex(end), 'bytes': len(body),
        'file_offset': hex(image.offset(start, len(body))), 'sha256': sha(body),
        'fde_section_offset': hex(fde_offset), 'fde_length_field': length,
        'fde_raw_hex': image.read(row['fde'], length + 4).hex(),
        'cie_section_offset': hex(row['cie'] - eh['address']),
        'cie_raw_hex': image.read(row['cie'], cie_length + 4).hex(),
        'lsda': None, 'next_fde_start': hex(next_start),
        'next_fde_section_offset': hex(later['fde'] - eh['address']),
        'padding_bytes': len(padding), 'padding_hex': padding.hex(),
    }


def relocation_records(image):
    out = []
    for sec in image.sections:
        if sec['type'] != 4:
            continue
        require(sec['size'] % 24 == 0, 'Malformed RELA section')
        for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', image.data, off)
            if slot in (SLOT, LOCATION) or addend == START:
                out.append({'section': sec['name'], 'section_offset': hex(off - sec['offset']),
                            'slot_va': hex(slot), 'type': info & 0xffffffff,
                            'symbol_index': info >> 32, 'addend_va': hex(addend),
                            'slot_file_hex': image.read(slot, 8).hex()})
    expected = [(LOCATION, 8, 0, PATH_VA), (SLOT, 8, 0, CALLEE), (POINTER_SLOT, 8, 0, START)]
    require([(int(r['slot_va'], 16), r['type'], r['symbol_index'], int(r['addend_va'], 16))
             for r in out] == expected, 'Call/Location/function-pointer relocation changed')
    require(all(r['slot_file_hex'] == '00' * 8 for r in out), 'Relocated slot contents changed')
    return out


def scan_direct(data, text, targets):
    """Every byte position of .text, e8/e9 rel32, signed displacement.

    Candidates are not generally proven instruction starts. No match means
    no unprefixed e8/e9 encoding to the exact entry in this section. This
    cannot exclude indirect, data, interior-entry, or other-section routes.
    mmap.find avoids making a second copy of the .text section.
    """
    hits = []
    begin, end = text['offset'], text['offset'] + text['size']
    for opcode in (0xe8, 0xe9):
        pos = begin
        while (pos := data.find(bytes([opcode]), pos, end)) >= 0:
            if pos + 5 <= end:
                site = text['address'] + pos - begin
                target = site + 5 + struct.unpack_from('<i', data, pos + 1)[0]
                if target in targets:
                    hits.append({'site_va': hex(site), 'opcode': hex(opcode), 'target_va': hex(target)})
            pos += 1
    return sorted(hits, key=lambda r: int(r['site_va'], 16))


def analyze_structure(data):
    """Structural layer for corruption tests. Public entrypoints authenticate first."""
    image = Image(data)
    body = image.read(START, END - START)
    program = checked_program(body)
    rows = image.frame_rows()
    function = frame_record(image, rows, START, END, NEXT, 0x1b9f64, BODY_SHA)
    callee = frame_record(image, rows, CALLEE, CALLEE_END, CALLEE_NEXT, 0x199b4, CALLEE_SHA)
    callee['claim'] = 'Identity and extent only; behavior, transitive calls and nonreturn status excluded.'
    relocations = relocation_records(image)
    location = image.read(LOCATION, 24)
    ptr, n, line, column = struct.unpack('<QQII', location)
    source = image.read(PATH_VA, n)
    require((ptr, n, line, column) == (0, 50, 3, 23), 'Location layout changed')
    require(source == SOURCE_PREFIX + SOURCE_SUFFIX.encode(), 'First-party source path changed')
    text = image.by_name['.text']
    require(text['flags'] & 4 and text['address'] <= START < END <= text['address'] + text['size'],
            'Function outside executable .text')
    hits = scan_direct(data, text, {START})
    require(hits == [], 'Direct caller census changed')
    branches = [dict(site_va=hex(i.va), condition=i.op, target_va=hex(i.args[0]))
                for i in program if i.op in ('jb', 'je', 'jbe')]
    vs = vectors()
    rec = {
        'task': 'RE-001', 'component': 'l1-shared', 'claim': 'Static function behavior bind; no gate requested.',
        'target': {'path': TARGET_REL, 'release': '94', 'size': len(data), 'sha256': SHA256},
        'coordinates': 'ELF virtual addresses, no rebasing; file offsets explicitly labelled.',
        'function': function, 'callees': [callee],
        'control_flow': {'branches': branches, 'return_sites': [hex(i.va) for i in program if i.op == 'ret'],
                         'call': {'site_va': hex(START + 0x41), 'encoding': 'ff15 RIP-relative slot',
                                  'slot_va': hex(SLOT), 'resolved_target_va': hex(CALLEE)},
                         'instruction_count': len(program), 'complete_function_decode': True},
        'location': {'va': hex(LOCATION), 'raw_hex': location.hex(), 'source_va': hex(PATH_VA),
                     'source_suffix': SOURCE_SUFFIX, 'source_bytes': n, 'source_sha256': sha(source),
                     'omitted_build_prefix_sha256': sha(SOURCE_PREFIX), 'line': line, 'column': column},
        'relocations': relocations,
        'caller_census': {'method': 'Full .text byte-position e8/e9 rel32 pattern scan to exact entry.',
                          'text_va': hex(text['address']), 'text_file_offset': hex(text['offset']),
                          'text_bytes': text['size'], 'direct_e8_sites': [], 'direct_e9_sites': [],
                          'candidates': hits, 'pointer_slots': [hex(POINTER_SLOT)],
                          'limitation': 'Not a complete xref or instruction-boundary census; pointer-slot use unknown.'},
        'rule': {'word_bits': 64, 'return_low_bits': 8, 'cap': CAP,
                 'old_offset': 0, 'extra_offset': 8, 'old_register': 'rdi', 'input_register': 'rsi',
                 'checked_stages': ['old_plus_offset', 'plus_one', 'plus_extra'],
                 'store_width_bits': 64, 'extra_written': False,
                 'in_range': 't=old+offset; q=t+1; z=q+extra. If z<=cap: store q at [rdi], return RAX=t.',
                 'capped': 'If z>cap: store cap at [rdi], return RAX=(q & ~0xff)|cap (AL=cap).',
                 'overflow': 'On carry in either add, or zero after inc: transfer at call site with RDI=Location, before object store.',
                 'precondition': 'Readable object qwords, writable first qword, valid disjoint stack, no concurrent mutation; unsigned arithmetic.',
                 'vectors': vs},
        'counts': {'instructions': len(program), 'conditional_branches': len(branches),
                   'returns': sum(i.op == 'ret' for i in program), 'callees': 1,
                   'direct_e8_callers': 0, 'direct_e9_callers': 0, 'pointer_slots': 1,
                   'overflow_checks': 3, 'vectors': len(vs), 'novelty_research_matches': 0, 'novelty_pr_matches': 0},
        'novelty': {'baseline_commit': BASE_COMMIT, 'function_hex_without_prefix': format(START, 'x'),
                    'function_decimal': str(START), 'research_results': 'Empty before adding this packet (rg exit 1).',
                    'pr_results': 'Empty in all supplied snapshots (rg exit 1).',
                    'behavior_bound_callees': [],
                    'identity_only_callee_note': 'The shared callee already occurs in research; no new behavior bind is made for it.',
                    'snapshots': [dict(name=n, bytes=size, sha256=h) for n, size, h in SNAPSHOTS]},
        'non_claims': ['No captured execution, Rust implementation, compiled comparison or whole-node equivalence.',
                       'No source-level function/type name, iterator trait, system-user policy or field ownership recovered.',
                       'No shared-callee behavior, nonreturn guarantee, transitive call closure or runtime relocation execution.',
                       'No #115/visor transfer, catalogue/progress change or full-scope acceptance gate.'],
    }
    return rec, program


def instruction_text(program):
    lines = ['ELF VAs; strict Python decoder; complete function, no normalization.',
             'call_slot names a RIP-relative pointer slot, resolved separately via RELA.', '']
    lines += [f'{i.va:#011x}  {i.raw.hex():<22}  {i.text()}' for i in program]
    lines += [f'{END:#011x}..{NEXT:#011x}  ' + ('cc' * (NEXT - END)) + '  int3 padding (outside FDE)']
    return '\n'.join(lines) + '\n'


def render_readme(r):
    f, c, counts, rule = r['function'], r['callees'][0], r['counts'], r['rule']
    loc, census, nov = r['location'], r['caller_census'], r['novelty']
    body = f'''# RE-001: checked capped advance at {f['start_va']} (node #{r['target']['release']})

Task: {r['task']}; component: {r['component']}. Bounded question: how does this
function update the first object qword and produce its return value from the
input offset and the second object qword, including overflow and cap boundaries?

Answer: let `old=qword[rdi+{rule['old_offset']}]`, `extra=qword[rdi+{rule['extra_offset']}]`,
and `offset=rsi`, all unsigned {rule['word_bits']}-bit values. Compute `t=old+offset`,
`q=t+1`, then `z=q+extra`, checking overflow at each stage. Before any object
store, an overflow transfers to the fixed-slot callee identified below with
the source Location in RDI; the callee's behavior is outside this bind. If
`z<={rule['cap']}`, store `q` to the first qword and return `RAX=t`. Otherwise,
store {rule['cap']} and return `RAX=(q & ~0xff)|{rule['cap']}`: only AL is overwritten
on this path. The second qword is read only. This is a complete decode of the
function's own instructions, with a deliberately explicit callee boundary.

## Identity and scope

Target: `{r['target']['path']}`, {r['target']['size']} bytes, SHA-256
`{r['target']['sha256']}`. All addresses are ELF VAs, with no analysis rebase.
Baseline repository commit: `{nov['baseline_commit']}`. No inferred reference
source was used or copied; the rule and model were authored from binary bytes.
Source-build flags, dependency closure and compiled comparison are unmeasured.

| Function field | Observed value |
| --- | --- |
| Interval (exclusive end) | `{f['start_va']}..{f['end_va_exclusive']}` |
| Body bytes | {f['bytes']} |
| File offset | `{f['file_offset']}` |
| Body SHA-256 | `{f['sha256']}` |
| FDE section offset / length field | `{f['fde_section_offset']}` / {f['fde_length_field']} |
| CIE section offset | `{f['cie_section_offset']}` |
| Following FDE | `{f['next_fde_start']}` at `.eh_frame+{f['next_fde_section_offset']}` |
| Inter-FDE padding bytes | {f['padding_bytes']} (`cc`, outside function) |

The actual `.eh_frame` records, including CIE association, determine the
extent. The verifier rejects overlapping FDEs and shifted boundaries. The
instruction decode corroborates the successful return paths and the final
outgoing call. It does not infer a nonreturn guarantee from the FDE end.

## Instruction walk and source evidence

[`instructions.txt`](instructions.txt) contains the bytes and the strict
decoder's instruction walk: {counts['instructions']} instructions,
{counts['conditional_branches']} conditional branches and {counts['returns']}
return sites. `push rax` reserves stack space; successful paths balance it
with `pop rcx`. `add rsi,[rdi]` checks carry; `inc rax` checks zero after
increment; `add rcx,rax` checks carry again. All failure edges converge at
the Location load. The unsigned `jbe` accepts equality at the cap. On that
path `q+extra<=cap` implies `t<cap`, proving the final `cmovb` selects `t`.
On the capped path `mov al,cap` preserves upper RAX bits. The model and
vectors retain this distinction instead of assuming an integer-wide return.
The return type itself remains unknown.

The relocated Location at `{loc['va']}` points to the binary's first-party
build-root path ending in `{loc['source_suffix']}:{loc['line']}:{loc['column']}`.
Its full path is {loc['source_bytes']} bytes, SHA-256 `{loc['source_sha256']}`;
the captured build prefix is checked but omitted from prose. The file pointer
is zero on disk and resolved by `R_X86_64_RELATIVE`; the parser checks the
relocation, path bytes, length, line and column. This supports a first-party
system-user connection, not a source-level function name or iterator type.

## Callee and incoming references

Outgoing callee count: {counts['callees']}. The instruction at
`{r['control_flow']['call']['site_va']}` is `ff15` through RIP-relative slot
`{r['control_flow']['call']['slot_va']}`. Its on-disk slot is zero; a checked
`R_X86_64_RELATIVE` relocation resolves it to `{c['start_va']}`.
This is a statically fixed slot, not demonstrated polymorphic dispatch.

| Callee field (identity only) | Observed value |
| --- | --- |
| Interval / bytes | `{c['start_va']}..{c['end_va_exclusive']}` / {c['bytes']} |
| Body SHA-256 | `{c['sha256']}` |
| FDE offset / length field / CIE | `{c['fde_section_offset']}` / {c['fde_length_field']} / `{c['cie_section_offset']}` |
| Padding bytes / next FDE | {c['padding_bytes']} / `{c['next_fde_start']}` |

The shared callee has existing research mentions. Only its digest, extent,
CIE, padding and slot identity are checked here; no behavior or transitive
callee is rebound. In particular, the packet does not claim that the call
returns, unwinds or aborts. If it returns normally, the next address lies in
the recorded `int3` padding. No object store precedes this call, although the
function has pushed a stack word.

A full `.text` e8/e9 rel32 scan examines {census['text_bytes']} bytes starting
at `{census['text_va']}`: {counts['direct_e8_callers']} e8 candidates and
{counts['direct_e9_callers']} e9 candidates target this exact entry. It is a
byte-position scan, not a general instruction-boundary proof. It does not
cover indirect calls, interior-entry targets, other sections or all data
xrefs. A separate full RELA scan finds {counts['pointer_slots']} pointer slot,
`{census['pointer_slots'][0]}`, relocating to the function. Its use is unknown;
absence of direct calls does not establish that this function is unused.

## Novelty checked before implementation

Against the baseline above, these research commands returned empty output
(rg status 1), with {counts['novelty_research_matches']} matches:

```sh
rg -i '{nov['function_hex_without_prefix']}' research/
rg -i '{nov['function_decimal']}' research/
```

The following command also returned empty output (rg status 1), with
{counts['novelty_pr_matches']} matches. `PR_LIST_DIR` denotes the supplied
snapshot directory; its machine-local absolute path is intentionally omitted.

```sh
rg -i '{nov['function_hex_without_prefix']}|{nov['function_decimal']}' "$PR_LIST_DIR/open_prs.txt" "$PR_LIST_DIR/merged_prs.txt" "$PR_LIST_DIR/closed_unmerged_prs.txt"
```

| Snapshot | Bytes | SHA-256 |
| --- | ---: | --- |
'''
    body += ''.join(f"| {s['name']} | {s['bytes']} | `{s['sha256']}` |\n" for s in nov['snapshots'])
    body += f'''
These are historical pre-addition checks; repeating them on this branch will
find this packet. No callee behavior is in the novelty claim. Neighbors and
shared-callee mentions are not claimed as new work.

## Reproduction and checks

Python 3.10+ standard library only. No target execution, network access,
external disassembler or installed package is required. The reproducer maps
the binary read-only, authenticates its entire digest, parses ELF/FDE/RELA,
strictly decodes the function, scans `.text`, and emits byte-identical evidence.
`records.json` contains semantic records, not an instruction inventory.
`verify.py` enforces an exact manifest whitelist, hashes the evidence and
checker/test sources, and regenerates the evidence from the authenticated
input for equality. The verifier shares the reproducer's parser and decoder;
it is not an independently implemented disassembler.
No normalization or byte substitution is used.

```sh
python3 tools/{NAME}.py --out {PACKET_REL}/
python3 -m unittest tests.test_{NAME} -v
python3 {PACKET_REL}/verify.py
make verify
make catalogue-check
```

The model uses {counts['overflow_checks']} checked arithmetic stages and
{counts['vectors']} manually worked instruction-derived vectors. Tests cover
the cap equality, the low-byte-only write, each overflow transfer before an
object store, and a separate interpreter of decoded instructions. Corruption
controls reach the structural checker with the digest gate deliberately
separated: body mutation, shifted FDE, CIE association, callee relocation,
Location relocation, padding and callee body. Public entrypoints always
authenticate the target and have no digest-bypass option. README equality
with its JSON-derived rendering is tested. Manifest traversal, duplicate,
missing and extra entries are rejected. These are static checks and model
comparisons; they are not differential execution of the target.

The initial repository `make verify` stopped at the unrelated node #115 LFS
pointer. The final repository-check outcomes are reported in the local result
and PR draft; no repository-wide success is implied by this packet's verifier.

## Non-claims, limitations and next step

'''
    body += ''.join('- ' + value + '\n' for value in r['non_claims'])
    body += '''
The model assumes valid readable/writable object memory, a valid disjoint
stack and no concurrent mutation. It does not model memory faults. The callee's effects and
nonreturn status remain open; the function's ABI type and pointer-slot use are
also unresolved. Next, trace the relocating pointer slot to its consumer to
establish the return-width contract and the meanings of the object fields.
All full-scope gates remain unchanged.
'''
    return body


def evidence_bytes(records, program):
    return {'records.json': (json.dumps(records, indent=2) + '\n').encode(),
            'instructions.txt': instruction_text(program).encode(),
            'README.md': render_readme(records).encode()}


def manifest_paths(packet):
    out = {}
    for name in MANIFEST_NAMES:
        out[name] = packet / name.removeprefix(PACKET_REL + '/') if name.startswith(PACKET_REL + '/') else ROOT / name
    return out


def manifest_bytes(packet):
    return ''.join(f'{sha(path.read_bytes())}  {name}\n'
                   for name, path in sorted(manifest_paths(packet).items())).encode()


def check_manifest(packet):
    paths = manifest_paths(packet)
    lines = (packet / 'MANIFEST.sha256').read_text().splitlines()
    seen = set()
    for line in lines:
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        require(match is not None, 'Malformed manifest entry')
        digest, name = match.groups()
        require(name in paths and name not in seen, 'Non-whitelisted or duplicate manifest entry')
        seen.add(name)
        path = paths[name]
        require(not path.is_symlink(), 'Symlink manifest member')
        require(sha(path.read_bytes()) == digest, f'Manifest hash mismatch: {name}')
    require(seen == set(paths), 'Incomplete manifest whitelist')


def verify_packet(packet=PACKET, binary=TARGET):
    packet = Path(packet)
    check_manifest(packet)
    with mapped(binary) as data:
        records, program = analyze_structure(data)
    for name, expected in evidence_bytes(records, program).items():
        require((packet / name).read_bytes() == expected, f'Generated evidence mismatch: {name}')
    return records


def generate(out, binary=TARGET):
    with mapped(binary) as data:
        records, program = analyze_structure(data)
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    for name, value in evidence_bytes(records, program).items():
        (out / name).write_bytes(value)
    if out.resolve() != PACKET.resolve():
        (out / 'verify.py').write_bytes((PACKET / 'verify.py').read_bytes())
    (out / 'MANIFEST.sha256').write_bytes(manifest_bytes(out))
    return records


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--out', type=Path)
    mode.add_argument('--check', type=Path)
    args = parser.parse_args(argv)
    try:
        if args.out is not None:
            generate(args.out, args.binary)
            print('Generated the digest-bound capped-advance packet.')
        else:
            verify_packet(args.check, args.binary)
            print('ALL CHECKS PASSED: capped-advance packet reproduces byte-identically.')
    except (OSError, ValueError, struct.error) as exc:
        print(f'FAIL: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
