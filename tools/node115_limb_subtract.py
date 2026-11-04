#!/usr/bin/env python3
"""Bind the #115 four-limb subtraction leaf by static ELF inspection."""
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
START = 0x564c830
END = 0x564c861
FDE = {'fde': 0xf8b80c, 'cie': 0xca6ed8, 'start': START, 'end': END, 'lsda': None}
CALLS = (0x5600943, 0x56009a7, 0x56009ea, 0x56017b3, 0x5601817, 0x560185a)
# Exact opcode and ModR/M forms, in entry-to-return order. No operand bytes are masked.
OPS = (
 ('488b02', 'mov rax, [rdx]'), ('482906', 'sub [rsi], rax'),
 ('488b4208', 'mov rax, [rdx+8]'), ('48194608', 'sbb [rsi+8], rax'),
 ('488b4210', 'mov rax, [rdx+16]'), ('48194610', 'sbb [rsi+16], rax'),
 ('488b4218', 'mov rax, [rdx+24]'), ('48194618', 'sbb [rsi+24], rax'),
 ('0f1006', 'movups xmm0, [rsi]'), ('0f1107', 'movups [rdi], xmm0'),
 ('0f104610', 'movups xmm0, [rsi+16]'), ('0f114710', 'movups [rdi+16], xmm0'),
 ('0f924720', 'setb byte [rdi+32]'), ('c3', 'ret'),
)
VERIFY = '''#!/usr/bin/env python3
"""Verify the packet whitelist, hashes and independent regeneration."""
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
NAMES = ("README.md", "records.json", "verify.py")
if {p.name for p in HERE.iterdir()} != set(NAMES) | {"MANIFEST.sha256"}:
    raise SystemExit("Unexpected packet contents")
manifest = "".join(hashlib.sha256((HERE / n).read_bytes()).hexdigest() + "  " + n + "\\n" for n in NAMES)
if (HERE / "MANIFEST.sha256").read_text() != manifest:
    raise SystemExit("Manifest mismatch")
with tempfile.TemporaryDirectory() as tmp:
    subprocess.run([sys.executable, str(ROOT / "tools/node115_limb_subtract.py"), "--out", tmp], check=True)
    for name in (*NAMES, "MANIFEST.sha256"):
        if (HERE / name).read_bytes() != (Path(tmp) / name).read_bytes():
            raise SystemExit("Regenerated packet mismatch: " + name)
print("Packet whitelist, hashes and regeneration verified")
'''


def decode_body(body):
    """Strictly decode only the exact observed x86 forms; reject every other encoding."""
    pos = 0
    rows = []
    for encoding, mnemonic in OPS:
        raw = bytes.fromhex(encoding)
        if body[pos:pos + len(raw)] != raw:
            raise ValueError('Unexpected instruction at offset %#x' % pos)
        rows.append({'va': START + pos, 'bytes': encoding, 'instruction': mnemonic})
        pos += len(raw)
    if pos != len(body):
        raise ValueError('Unexpected body length')
    return rows


def check_fde(rows):
    matches = [r for r in rows if r['start'] == START or r['fde'] == FDE['fde']]
    if matches != [FDE]:
        raise ValueError('Function FDE changed or is ambiguous')


def decode_call(raw, address, target=START):
    if len(raw) != 5 or raw[0] != 0xe8:
        raise ValueError('Not a direct call rel32')
    dest = address + 5 + struct.unpack_from('<i', raw, 1)[0]
    if dest != target:
        raise ValueError('Call target changed')
    return dest


def scan_calls(data, text, target=START):
    """Exhaustive byte-offset scan, including overlapping potential instructions."""
    first, limit = text['offset'], text['offset'] + text['size']
    hits = []
    for opcode in (0xe8, 0xe9):
        pos = first
        while True:
            pos = data.find(bytes([opcode]), pos, limit - 4)
            if pos < 0:
                break
            va = text['address'] + pos - first
            dest = va + 5 + struct.unpack_from('<i', data, pos + 1)[0]
            if dest == target:
                hits.append({'va': va, 'opcode': '%02x' % opcode, 'bytes': data[pos:pos + 5].hex()})
            pos += 1
    return sorted(hits, key=lambda h: h['va'])


def model(a, b):
    """Value-level model for disjoint valid operands, little-endian u64 limbs."""
    if len(a) != 4 or len(b) != 4 or any(not 0 <= x < 1 << 64 for x in (*a, *b)):
        raise ValueError('Expected four unsigned 64-bit limbs per operand')
    out, borrow = [], 0
    for x, y in zip(a, b):
        value = x - y - borrow
        out.append(value % (1 << 64))
        borrow = int(value < 0)
    return out, borrow



def source_locations(data, secs, text):
    """Bind caller RIP-relative LEAs to RELATIVE-relocated Rust Locations."""
    rela = next(s for s in secs if s['name'] == '.rela.dyn')
    wanted = {0x64aa398: ('l1/src/qtys/mod.rs', 835, 1),
              0x6487478: ('l1/src/qtys/impl_wei.rs', 6, 1)}
    refs = {0x56004c4: 0x64aa398, 0x5600a84: 0x6487478, 0x5600aab: 0x6487478}

    def offset(va, length):
        matches = [s for s in secs if s['type'] != 8 and s['address'] <= va and va + length <= s['address'] + s['size']]
        if len(matches) != 1:
            raise ValueError('Location VA has ambiguous file mapping')
        return matches[0]['offset'] + va - matches[0]['address']

    relocations = {}
    for i in range(rela['offset'], rela['offset'] + rela['size'], 24):
        place, info, addend = struct.unpack_from('<QQq', data, i)
        if place in wanted:
            if place in relocations or info != 8:
                raise ValueError('Location relocation changed')
            relocations[place] = (i, addend)
    if set(relocations) != set(wanted):
        raise ValueError('Missing location relocation')
    records = []
    for va, (path, line, col) in wanted.items():
        loc_off = offset(va, 24)
        pointer, size, observed_line, observed_col = struct.unpack_from('<QQII', data, loc_off)
        reloc_off, string_va = relocations[va]
        if pointer != 0 or (size, observed_line, observed_col) != (len(path), line, col):
            raise ValueError('Location metadata changed')
        if data[offset(string_va, size):offset(string_va, size) + size] != path.encode():
            raise ValueError('Location path changed')
        records.append({'va': va, 'file_offset': loc_off, 'bytes': data[loc_off:loc_off + 24].hex(),
                        'path': path, 'line': line, 'column': col,
                        'relocation_file_offset': reloc_off, 'relocation_type': 'R_X86_64_RELATIVE',
                        'path_va': string_va, 'references': []})
    for va, location in refs.items():
        off = text['offset'] + va - text['address']
        raw = data[off:off + 7]
        if raw[:3] != bytes.fromhex('488d35') or va + 7 + struct.unpack_from('<i', raw, 3)[0] != location:
            raise ValueError('Caller location reference changed')
        next(r for r in records if r['va'] == location)['references'].append({'va': va, 'bytes': raw.hex()})
    return records


def extract(data):
    if hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('Node #115 digest mismatch')
    secs = sections(data)
    text = next(s for s in secs if s['name'] == '.text')
    if (text['address'], text['offset'], text['size']) != (0x1419300, 0x1418300, 0x4fd7700):
        raise ValueError('Unexpected .text mapping')
    cies, fdes = eh_frame_records(data, secs)
    check_fde(fdes)
    cie = cies[FDE['cie']]
    if cie['augmentation'] != 'zR' or cie['fde_encoding'] != 0x1b:
        raise ValueError('Unexpected CIE encoding')
    offset = text['offset'] + START - text['address']
    body = data[offset:offset + END - START]
    instructions = decode_body(body)
    if data[offset + len(body):offset + len(body) + 15] != b'\xcc' * 15:
        raise ValueError('Padding changed')
    next_rows = [x for x in fdes if x['start'] == END + 15]
    if len(next_rows) != 1:
        raise ValueError('Next FDE changed')
    calls = scan_calls(data, text)
    if tuple(x['va'] for x in calls) != CALLS or any(x['opcode'] != 'e8' for x in calls):
        raise ValueError('Direct branch census changed')
    for call in calls:
        addr = call['va']; off = text['offset'] + addr - text['address']
        decode_call(data[off:off + 5], addr)
        # These exact instruction forms frame each call: stack addresses in the
        # three argument registers, then a byte test of the returned borrow.
        before = data[off - 21:off]
        after = data[off + 5:off + 10]
        if not (before[:5] == bytes.fromhex('488d7c2420') and
                before[5:9] == bytes.fromhex('488db424') and
                before[13:17] == bytes.fromhex('488d9424') and
                after == bytes.fromhex('807c244000')):
            raise ValueError('Caller instruction context changed')
        call['context_bytes'] = (before + data[off:off + 5] + after).hex()
        containing = [f for f in fdes if f['start'] <= addr < f['end']]
        if len(containing) != 1:
            raise ValueError('Caller extent ambiguous')
        call['containing_fde'] = containing[0]
    return {'target_sha256': SHA, 'coordinate_system': 'ELF virtual address',
            'window': {'start': START, 'end': END, 'size': len(body),
                       'file_offset': offset, 'body_sha256': hashlib.sha256(body).hexdigest(),
                       'fde': FDE, 'cie': cie, 'padding_hex': 'cc' * 15,
                       'next_fde_start': END + 15},
            'instructions': instructions, 'callees': [], 'direct_branch_candidates': calls,
            'caller_locations': source_locations(data, secs, text),
            'scan': {'start': text['address'], 'end': text['address'] + text['size'],
                     'opcodes': ['e8', 'e9'], 'method': 'each byte offset; signed rel32'},
            'rule': 'four little-endian 64-bit limbs: difference modulo 2^256 and unsigned borrow'}


def readme(r):
    w = r['window']; calls = r['direct_branch_candidates']; ins = r['instructions']
    walk = '\n'.join('`%#x` | `%s` | `%s`' % (x['va'], x['bytes'], x['instruction']) for x in ins)
    sites = ', '.join('`%#x`' % c['va'] for c in calls)
    return f'''# RE-001: four-limb unsigned subtraction with borrow

- Component: RE-001 function mapping; arithmetic context unassigned.
- Target: Linux x86-64 node #115, SHA-256 `{SHA}`.
- Reference revision: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; no source used or recovered. Claim: static observation and value-level inference.
- Bounded question: what does the leaf at `0x564c830` compute on valid, disjoint input/output regions?

**Answer.** Treat the four little-endian qwords at RSI and RDX as unsigned 256-bit integers A and B. The leaf updates the four qwords at RSI to `(A - B) mod 2^256`, copies those 32 bytes to RDI, and stores at RDI+32 the byte 1 exactly when A < B, otherwise 0. The four subtract instructions propagate the carry flag as a borrow. The intervening moves, including the SIMD copies, do not alter flags, so SETB captures the final borrow. This describes machine behavior on normal return under the memory preconditions below; it does not establish a native type or business meaning.

## Evidence and scope

All addresses are original ELF virtual addresses; `.text` file offset is VA minus `0x1000`. The body is `0x{w['start']:x}..0x{w['end']:x}`, {w['size']} bytes, file offset `0x{w['file_offset']:x}`, SHA-256 `{w['body_sha256']}`. FDE at `.eh_frame` VA and file offset `0x{w['fde']['fde']:x}` references CIE `0x{w['fde']['cie']:x}` (`zR`, pcrel-sdata4); it has no LSDA. The end is followed by {len(bytes.fromhex(w['padding_hex']))} `cc` bytes until the next FDE entry `0x{w['next_fde_start']:x}`. The unwind extent, entry-to-return walk and post-body padding support this particular boundary; FDEs alone do not establish all functions.

Complete instruction walk, {len(ins)} instructions; bytes and operand widths are unmasked:

VA | bytes | decoded instruction
--- | --- | ---
{walk}

The body has {len(r['callees'])} direct or indirect calls or tail calls, and thus no callee identity or extent to resolve. A full `.text` byte-by-byte scan for E8/E9 signed rel32 transfers to the entry found {len(calls)} candidates: {sites}. Each is an E8 call framed by decoded stack-address argument setup and a post-call test of byte `[rsp+0x40]`, corresponding to output+32. The containing FDE records and complete context bytes are retained in `records.json`. The scan includes overlapping byte positions; these local instruction contexts support these sites, but do not prove a global instruction-boundary census. It cannot detect indirect calls, data pointers, or branches to the interior.

The first enclosing caller FDE also contains RIP-relative LEAs at `0x56004c4`, `0x5600a84` and `0x5600aab`. Their resolved location objects, ELF `R_X86_64_RELATIVE` addends, path bytes and line/column values associate this caller with `l1/src/qtys/mod.rs:835:1` and `l1/src/qtys/impl_wei.rs:6:1`; raw records and reference bytes are in `records.json`. This is a caller-context association, not proof that the leaf itself originated in those files or that its values are a particular quantity type.

**Assumptions and limits.** The 32-byte A, 32-byte B and 33-byte result regions are valid and pairwise disjoint; other aliasing cases are not claimed. Reads and writes can fault and no execution has been performed. The result is a static theorem, not a recovered Rust implementation, source ownership, original function name, ABI beyond observed registers, or protocol meaning. Source comparison, source build, normalization, whole-ELF equivalence, caller semantics and component acceptance gates remain unmeasured. No normalizations or comparison masks are used. Next: resolve the two caller FDEs and trace the provenance and use of these values before assigning a domain meaning.

## Reproduction and controls

From the repository root, Python 3.10+ (stdlib) with the authenticated materialized target. Observed locally on Linux x86-64 with Python 3.13.5; initial focused inspection also used GNU objdump 2.44 as below. The generator and verifier do not invoke objdump:

```sh
objdump -d -Mintel --start-address=0x564c830 --stop-address=0x564c870 artifacts/node/115/hl-node
objdump -d -Mintel --start-address=0x55ffc90 --stop-address=0x5600af9 artifacts/node/115/hl-node
python3 tools/node115_limb_subtract.py --out research/work-items/RE-001-node115-limb-subtract/
python3 -m unittest tests.test_node115_limb_subtract -v
python3 research/work-items/RE-001-node115-limb-subtract/verify.py
make verify
make catalogue-check
```

The generator checks the full target digest before parsing, uses the repository's stdlib ELF/FDE parsers and strict instruction-form decoder, and scans all `.text` offsets. The focused tests exercise instruction, FDE, direct-target and digest corruption, arithmetic boundaries and packet reproducibility. No target or visor execution, network or external state is used. No independent implementation or build comparison is claimed. New code is MIT.

Novelty check before selection: the following searches returned no matches (exit status 1) in `research/` or the three local PR title lists:

```sh
rg -in '564c830' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -n '90490928' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```
'''


def generate(out, target=TARGET):
    with Path(target).open('rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
        record = extract(data)
    payload = {'README.md': readme(record), 'records.json': json.dumps(record, indent=2) + '\n', 'verify.py': VERIFY}
    out = Path(out); out.mkdir(parents=True, exist_ok=True)
    for name, value in payload.items():
        (out / name).write_text(value, encoding='utf-8')
    (out / 'MANIFEST.sha256').write_text(''.join(hashlib.sha256(value.encode()).hexdigest() + '  ' + name + '\n' for name, value in payload.items()), encoding='utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    generate(args.out)
