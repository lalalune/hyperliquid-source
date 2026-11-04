#!/usr/bin/env python3
"""Bind one node #115 leaf from authenticated ELF bytes, without executing it."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
START, END = 0x45514d0, 0x4551523
FDE, CIE = 0xecfb5c, 0xca6ed8
TEXT_START, TEXT_END, TEXT_OFFSET = 0x1419300, 0x63f0a00, 0x1418300
CALLER = 0x3d6ecb8
MASK = (1 << 64) - 1

# Exact opcode/operand forms are a deliberately narrow decoder, not a general x86 decoder.
# Relative branches are checked against instruction boundaries below.
FORMS = [
 ('488b4f18','mov rcx,[rdi+0x18]'), ('4885c9','test rcx,rcx'),
 ('7429','je 0x4551502'), ('488b37','mov rsi,[rdi]'),
 ('488b7f10','mov rdi,[rdi+0x10]'), ('31c0','xor eax,eax'),
 ('4839f7','cmp rdi,rsi'), ('4889f2','mov rdx,rsi'),
 ('480f42d0','cmovb rdx,rax'), ('4829fa','sub rdx,rdi'),
 ('4801f2','add rdx,rsi'), ('4839ca','cmp rdx,rcx'),
 ('722b','jb 0x4551522'), ('4883f901','cmp rcx,1'),
 ('750d','jne 0x455150a'), ('31d2','xor edx,edx'),
 ('31c0','xor eax,eax'), ('c3','ret'),
 ('b801000000','mov eax,1'), ('31d2','xor edx,edx'), ('c3','ret'),
 ('31c0','xor eax,eax'), ('31d2','xor edx,edx'), ('6690','nop'),
 ('4889ce','mov rsi,rcx'), ('48d1ee','shr rsi,1'),
 ('4801f2','add rdx,rsi'), ('4829f1','sub rcx,rsi'),
 ('4883f901','cmp rcx,1'), ('77ee','ja 0x4551510'), ('c3','ret'),
]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def model(capacity, head, length):
    """Raw register result for valid u64 input words, with wrapping arithmetic."""
    if any(not isinstance(x, int) or not 0 <= x <= MASK for x in (capacity, head, length)):
        raise ValueError('inputs must be u64')
    if length == 0:
        return (1, 0)
    distance = (capacity - head + (0 if head < capacity else capacity)) & MASK
    return (0, min(distance, length - 1))


def decode(body):
    rows, pos = [], 0
    for raw, mnemonic in FORMS:
        code = bytes.fromhex(raw)
        if body[pos:pos + len(code)] != code:
            raise ValueError('unexpected instruction at %#x' % (START + pos))
        rows.append({'address': START + pos, 'bytes': raw, 'instruction': mnemonic})
        pos += len(code)
    if pos != len(body) or START + pos != END:
        raise ValueError('instruction extent mismatch')
    boundaries = {x['address'] for x in rows}
    for row in rows:
        op = bytes.fromhex(row['bytes'])
        if op[0] in (0x72, 0x74, 0x75, 0x77):
            dest = row['address'] + 2 + int.from_bytes(op[1:2], 'little', signed=True)
            if dest not in boundaries or row['instruction'].split()[-1] != hex(dest):
                raise ValueError('invalid branch target')
    return rows


def offset(va):
    return TEXT_OFFSET + va - TEXT_START


def validate_sections(data):
    if data[:16] != bytes.fromhex('7f454c46020101000000000000000000'):
        raise ValueError('unsupported ELF identification')
    shoff = struct.unpack_from('<Q', data, 40)[0]
    entsize, count, strings_index = struct.unpack_from('<HHH', data, 58)
    if entsize != 64 or not 0 < strings_index < count:
        raise ValueError('unsupported ELF section table')
    def section(i):
        return struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * entsize)
    strings = section(strings_index)
    table = data[strings[4]:strings[4] + strings[5]]
    found = {}
    for i in range(count):
        row = section(i)
        end = table.find(b'\0', row[0])
        if end < 0:
            raise ValueError('invalid section name')
        name = bytes(table[row[0]:end])
        if name in (b'.text', b'.eh_frame'):
            if name in found:
                raise ValueError('duplicate section')
            found[name] = row
    text = found.get(b'.text')
    frame = found.get(b'.eh_frame')
    if not text or (text[1], text[2], text[3], text[4], text[5]) != (1, 6, TEXT_START, TEXT_OFFSET, TEXT_END - TEXT_START):
        raise ValueError('text section changed')
    if not frame or (frame[1], frame[3], frame[4]) != (1, CIE, CIE) or not CIE <= FDE < FDE + 20 <= CIE + frame[5]:
        raise ValueError('frame section changed')


def validate_frame(data):
    # The authenticated ELF uses an identity-mapped .eh_frame; decode its complete
    # fixed-size FDE and the zR CIE fields, including relative pointer encodings.
    if data[CIE:CIE + 24] != bytes.fromhex('1400000000000000017a5200017810011b0c070890010000'):
        raise ValueError('CIE changed')
    length, cie_delta, start_delta, size = struct.unpack_from('<IIiI', data, FDE)
    if (length, FDE + 4 - cie_delta, FDE + 8 + start_delta, size,
            data[FDE + 16:FDE + 20]) != (16, CIE, START, END - START, b'\0\0\0\0'):
        raise ValueError('FDE extent or encoding changed')


def callers(data):
    # Scan every byte, including unaligned byte patterns. Such hits are candidates,
    # and the separately decoded caller context establishes the observed call site.
    hits = []
    segment = memoryview(data)[TEXT_OFFSET:TEXT_OFFSET + TEXT_END - TEXT_START]
    for opcode in (b'\xe8', b'\xe9'):
        pos = TEXT_OFFSET
        limit = TEXT_OFFSET + len(segment)
        while True:
            pos = data.find(opcode, pos, limit - 4)
            if pos < 0:
                break
            va = TEXT_START + pos - TEXT_OFFSET
            if va + 5 + struct.unpack_from('<i', data, pos + 1)[0] == START:
                hits.append({'address': va, 'opcode': opcode.hex(), 'target': START})
            pos += 1
    return sorted(hits, key=lambda x: x['address'])


def inspect(data, authenticate=True):
    if authenticate and digest(data) != SHA:
        raise ValueError('node #115 digest mismatch')
    validate_sections(data)
    validate_frame(data)
    body = data[offset(START):offset(END)]
    insns = decode(body)
    padding = data[offset(END):offset(0x4551530)]
    if padding != b'\xcc' * 13:
        raise ValueError('padding changed')
    hits = callers(data)
    expected = [{'address': CALLER, 'opcode': 'e8', 'target': START}]
    if hits != expected:
        raise ValueError('caller scan changed')
    caller_context = data[offset(CALLER - 8):offset(CALLER + 13)]
    if caller_context != bytes.fromhex('be010000004889efe813287e00a80175514989d648'):
        raise ValueError('caller instruction context changed')
    return {'target_sha256': SHA, 'coordinate_system': 'ELF virtual address',
            'window': {'start': START, 'end_exclusive': END, 'size': len(body),
                       'file_offset': offset(START), 'body_sha256': digest(body),
                       'fde': FDE, 'cie': CIE, 'lsda': None,
                       'padding_end_exclusive': 0x4551530, 'padding_hex': padding.hex()},
            'instructions': insns, 'callees': [], 'direct_rel32_candidates': hits,
            'caller_context_hex': caller_context.hex(),
            'scan': {'start': TEXT_START, 'end_exclusive': TEXT_END,
                     'method': 'all byte positions e8/e9 followed by signed little-endian rel32'},
            'counts': {'instructions': len(insns), 'callees': 0, 'caller_candidates': len(hits),
                       'padding_bytes': len(padding)}}


def readme(r):
    w, c = r['window'], r['counts']
    return f'''# RE-001: node #115 bounded ring-style offset

- Component: RE-001 function map; original component and type are unresolved.
- Target: Linux x86-64 node #115, SHA-256 `{SHA}`. Source/reference revision: repository base `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; no original source is available.
- Question: what raw return pair does the whole function at `0x{START:x}` compute from its three loaded words?

**Answer (inference from the complete decoded body):** let `C=[RDI]`, `H=[RDI+0x10]`, and `N=[RDI+0x18]` be unsigned 64-bit words, with wrapping arithmetic. If `N=0`, return `(RAX,RDX)=(1,0)`. Otherwise set `D=(C-H+(0 if H<C else C)) mod 2^64`, and return `(0,min(D,N-1))`. The last arm uses a loop to sum successive `floor(N/2)` terms until the remainder is one, which equals `N-1`. The input RSI value is overwritten before use. This is a raw register relation; ring terminology is a hypothesis, not an identified original type.

## Evidence and scope

The window is ELF VA `0x{w['start']:x}..0x{w['end_exclusive']:x}` (exclusive), {w['size']} bytes, file offset `0x{w['file_offset']:x}`; body SHA-256 `{w['body_sha256']}`. FDE `0x{w['fde']:x}` points to CIE `0x{w['cie']:x}`, has no LSDA and describes exactly this range. The following {c['padding_bytes']} bytes up to `0x{w['padding_end_exclusive']:x}` are `cc`. The {c['instructions']} individually decoded instructions and their original bytes are in `records.json`. Strict matching accepts only the recorded opcode/operand forms, validates all relative branch destinations, and covers the whole FDE. Each path returns locally; there are {c['callees']} direct or indirect callees. FDE plus reachable control flow and terminal returns support this bounded extent; unwind records alone do not establish every function.

The full `.text` byte-position `e8`/`e9` signed-rel32 scan yields {c['caller_candidates']} candidate, an `e8` at `0x{CALLER:x}`. Its contiguous instruction context loads RSI with one, moves the object pointer into RDI, calls the entry, tests AL and copies RDX on the non-error path. Byte scanning can include false positives and misses indirect calls, so it is not a complete semantic caller census. The caller's surrounding function and semantic purpose remain unbound.

## Instruction rule

The first `test`/`je` handles zero length. `cmp rdi,rsi` and unsigned `cmovb` select zero when `H<C`, otherwise `C`. Subtraction and addition wrap in 64 bits. An unsigned comparison returns `D` directly when `D<N`. Otherwise `N=1` returns zero; for larger `N`, the loop adds `floor(k/2)` to RDX and replaces `k` by `ceil(k/2)` until `k=1`, so the sum telescopes to `N-1`. Every control-flow edge and `ret` is included in the recorded walk. The model takes raw words and is not captured-node execution.

## Novelty and reproduction

Before selection, both commands below returned no matches (exit status 1):

```sh
rg -i '45514d0|72684752' research/
rg -i '45514d0|72684752' ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

From the repository root, Python 3.10+ stdlib only, with the materialized target:

```sh
python3 tools/node115_ring_offset.py --out research/work-items/RE-001-node115-ring-offset/
python3 -m unittest tests.test_node115_ring_offset -v
python3 research/work-items/RE-001-node115-ring-offset/verify.py
make verify
make catalogue-check
```

The generator authenticates the full input before producing output, decodes the fixed FDE/CIE and instruction forms, scans the entire `.text` for candidate rel32 calls/jumps, and reproduces the packet. No target binary is executed; no disassembler is needed by the generator, verifier or tests. Wrong digest, changed body, shifted FDE and changed caller target are rejected by focused controls. No byte comparison normalization is used.

## Limitations and next step

No original Rust signature, caller-wide behavior, source ownership, object invariants, units, implementation equivalence, data/relocation closure, full node behavior or acceptance gate is claimed. Counts are bounded to this packet and the specified raw scan. No Rust implementation or comparison build exists. Resolve the enclosing caller's object layout and establish its source association before assigning a domain meaning to these words.
'''


def verify_script():
    return '''#!/usr/bin/env python3
"""Verify only the expected packet files against the manifest."""
import hashlib
from pathlib import Path

p = Path(__file__).resolve().parent
names = {"README.md", "records.json", "verify.py"}
lines = (p / "MANIFEST.sha256").read_text().splitlines()
seen = set()
for line in lines:
    h, sep, name = line.partition("  ")
    if sep != "  " or name not in names or name in seen or len(h) != 64:
        raise SystemExit("invalid manifest whitelist")
    if hashlib.sha256((p / name).read_bytes()).hexdigest() != h:
        raise SystemExit("packet hash mismatch: " + name)
    seen.add(name)
if seen != names or {x.name for x in p.iterdir()} != names | {"MANIFEST.sha256"}:
    raise SystemExit("packet file set changed")
print("Packet manifest and whitelist OK")
'''


def generate(data, out):
    r = inspect(data)
    out.mkdir(parents=True, exist_ok=True)
    files = {'README.md': readme(r), 'records.json': json.dumps(r, indent=2) + '\n',
             'verify.py': verify_script()}
    for name, contents in files.items():
        (out / name).write_text(contents, encoding='utf-8')
    (out / 'MANIFEST.sha256').write_text(''.join(digest(files[n].encode()) + '  ' + n + '\n' for n in sorted(files)), encoding='utf-8')
    return r


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--binary', type=Path, default=TARGET)
    a = p.parse_args()
    r = generate(a.binary.read_bytes(), a.out)
    print(json.dumps(r['counts'], sort_keys=True))


if __name__ == '__main__':
    main()
