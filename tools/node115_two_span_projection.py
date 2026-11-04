#!/usr/bin/env python3
"""Recover an FDE-backed two-span projection from authenticated node #115."""
import argparse
import hashlib
import json
import mmap
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
START, END = 0x152e360, 0x152e3d2
FRAME, FDE = 0xca6ed8, 0xd470
TEXT_START, TEXT_END = 0x1419300, 0x63f0a00
# Exact opcode/operand forms, independently decoded for this FDE. Short-branch
# displacements are decoded separately, not included in these opcode forms.
OPS = [
('4889f8','mov rax,rdi'), ('4c8b4618','mov r8,[rsi+0x18]'),
('4d85c0','test r8,r8'), ('74','je'), ('488b16','mov rdx,[rsi]'),
('488b4e10','mov rcx,[rsi+0x10]'), ('31ff','xor edi,edi'),
('4839d1','cmp rcx,rdx'), ('480f43fa','cmovae rdi,rdx'),
('4829f9','sub rcx,rdi'), ('4989d1','mov r9,rdx'),
('4929c9','sub r9,rcx'), ('4c89c7','mov rdi,r8'),
('4c29cf','sub rdi,r9'), ('77','ja'), ('4901c8','add r8,rcx'),
('31ff','xor edi,edi'), ('4c89c2','mov rdx,r8'), ('eb','jmp'),
('31c9','xor ecx,ecx'), ('31d2','xor edx,edx'), ('31ff','xor edi,edi'),
('488b7608','mov rsi,[rsi+8]'), ('488d0c89','lea rcx,[rcx+rcx*4]'),
('48c1e104','shl rcx,4'), ('4801f1','add rcx,rsi'),
('488d1492','lea rdx,[rdx+rdx*4]'), ('48c1e204','shl rdx,4'),
('4801f2','add rdx,rsi'), ('488d3cbf','lea rdi,[rdi+rdi*4]'),
('48c1e704','shl rdi,4'), ('4801f7','add rdi,rsi'),
('488908','mov [rax],rcx'), ('48895008','mov [rax+8],rdx'),
('48897010','mov [rax+0x10],rsi'), ('48897818','mov [rax+0x18],rdi'),
('c3','ret')]
BRANCHES = {0x152e36a: 0x152e397, 0x152e38b: 0x152e39d, 0x152e395: 0x152e39d}
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
EXPECTED_CALLS = [0x14f7fdc, 0x14fa686]


def decode(body):
    rows = []
    pos = 0
    for pattern, instruction in OPS:
        op = bytes.fromhex(pattern)
        if body[pos:pos + len(op)] != op:
            raise ValueError('Unexpected instruction at %#x' % (START + pos))
        length = len(op) + (instruction in ('je', 'ja', 'jmp'))
        raw = body[pos:pos + length]
        if len(raw) != length:
            raise ValueError('Truncated instruction')
        address = START + pos
        row = {'address': address, 'bytes': raw.hex(), 'instruction': instruction}
        if length > len(op):
            destination = address + length + struct.unpack('b', raw[-1:])[0]
            if BRANCHES.get(address) != destination:
                raise ValueError('Unexpected branch target')
            row['target'] = destination
        rows.append(row)
        pos += length
    if pos != len(body) or START + pos != END:
        raise ValueError('Unexpected extent')
    return rows


def frame_record(cie, fde):
    if cie != CIE or len(fde) != 20:
        raise ValueError('Unexpected CIE/FDE')
    length, cie_back, relative, size = struct.unpack_from('<IIiI', fde)
    initial = FRAME + FDE + 8 + relative
    cie_offset = FDE + 4 - cie_back
    if (length, cie_offset, initial, size, fde[16:]) != (16, 0, START, END - START, b'\0' * 4):
        raise ValueError('Shifted or malformed FDE')
    return {'section_offset': FDE, 'file_offset': FRAME + FDE,
            'cie_section_offset': cie_offset, 'cie_file_offset': FRAME,
            'fde_bytes': fde.hex(), 'cie_bytes': cie.hex(),
            'start': initial, 'end': initial + size}


def scan_calls(data):
    # The .text section has a constant VA minus file offset of 0x1000.
    first, last = TEXT_START - 0x1000, TEXT_END - 0x1000
    hits = []
    for opcode in (0xe8, 0xe9):
        i = first
        while True:
            i = data.find(bytes([opcode]), i, last - 4)
            if i < 0:
                break
            target = i + 0x1000 + 5 + struct.unpack_from('<i', data, i + 1)[0]
            if target == START:
                hits.append({'site': i + 0x1000, 'opcode': '%02x' % opcode,
                             'bytes': data[i:i + 5].hex(), 'target': target})
            i += 1
    hits.sort(key=lambda x: x['site'])
    if [h['site'] for h in hits] != EXPECTED_CALLS or any(h['opcode'] != 'e8' for h in hits):
        raise ValueError('Direct rel32 census changed')
    return hits


def rule(capacity, base, start, count):
    """Raw unsigned-word result; memory validity and collection semantics unproved."""
    mask = (1 << 64) - 1
    capacity, base, start, count = (x & mask for x in (capacity, base, start, count))
    if count == 0:
        a = b = c = 0
    else:
        a = (start - (capacity if start >= capacity else 0)) & mask
        remaining = (capacity - a) & mask
        if count > remaining:
            b, c = capacity, (count - remaining) & mask
        else:
            b, c = (count + a) & mask, 0
    return tuple((base + 80 * x) & mask for x in (a, b, 0, c))


def check_sections(data):
    if data[:6] != b"\x7fELF\x02\x01":
        raise ValueError('Not a little-endian ELF64')
    section_offset = struct.unpack_from('<Q', data, 40)[0]
    entry_size, count, strings_index = struct.unpack_from('<HHH', data, 58)
    if entry_size != 64 or not 0 < strings_index < count:
        raise ValueError('Unexpected section table')
    def section(index):
        return struct.unpack_from('<IIQQQQIIQQ', data, section_offset + index * entry_size)
    strings = section(strings_index)
    names = data[strings[4]:strings[4] + strings[5]]
    found = {}
    for i in range(count):
        sh = section(i)
        end = names.find(b'\0', sh[0])
        if end < 0:
            raise ValueError('Malformed section name')
        name = names[sh[0]:end]
        if name in (b'.text', b'.eh_frame'):
            if name in found:
                raise ValueError('Duplicate section')
            found[name] = sh
    text = found.get(b'.text')
    frame = found.get(b'.eh_frame')
    if text is None or (text[2], text[3], text[4], text[5]) != (6, TEXT_START, TEXT_START - 0x1000, TEXT_END - TEXT_START):
        raise ValueError('Unexpected text mapping')
    if frame is None or (frame[3], frame[4]) != (FRAME, FRAME) or frame[5] < FDE + 20:
        raise ValueError('Unexpected frame mapping')


def collect(data):
    if hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('Node #115 digest mismatch')
    check_sections(data)
    body = data[START - 0x1000:END - 0x1000]
    rows = decode(body)
    fde = frame_record(data[FRAME:FRAME + 24], data[FRAME + FDE:FRAME + FDE + 20])
    padding = data[END - 0x1000:END - 0x1000 + 14]
    if padding != b'\xcc' * 14:
        raise ValueError('Unexpected alignment bytes')
    return {'target_sha256': SHA, 'window': {'start': START, 'end': END,
            'size': len(body), 'file_offset': START - 0x1000,
            'sha256': hashlib.sha256(body).hexdigest(), 'padding_hex': padding.hex()},
            'fde': fde, 'instructions': rows, 'callees': [], 'direct_rel32_candidates': scan_calls(data)}


def readme(r):
    w = r['window']
    rows = '\n'.join(f"| `0x{x['address']:x}` | `{x['bytes']}` | `{x['instruction']}`" +
                     (f" → `0x{x['target']:x}`" if 'target' in x else '') + ' |' for x in r['instructions'])
    callers = ', '.join(f"`0x{x['site']:x}`" for x in r['direct_rel32_candidates'])
    return f'''# RE-001: two-span address projection at 0x152e360

- Component: unassigned collection/iteration helper; RE-001 function map. Target node #115, SHA-256 `{SHA}`. Base/source revision: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; no upstream source used.
- Question: what four words does this complete function produce from the four input words, and how does it handle a wrap across the capacity-like boundary?
- Answer: with unsigned 64-bit modular arithmetic, let C, B, H, N be the input words at offsets 0, 8, 16 and 24. If N is zero, the four outputs are all B. Otherwise set A = H-C if H >= C, else H; let R = C-A (modulo 2^64). If N > R unsigned, output `(B+80*A, B+80*C, B, B+80*(N-R))`; otherwise output `(B+80*A, B+80*(A+N), B, B)`. All output arithmetic is modulo 2^64. RAX returns the supplied output pointer. Under the usual ring preconditions C > 0, H < 2*C and N <= C, these are the endpoints of up to two contiguous 80-byte-stride spans; that interpretation and the word names are inferred, not original types.

## Evidence and procedure

The original ELF VA range is `0x{w['start']:x}..0x{w['end']:x}` ({w['size']} bytes), file offset `0x{w['file_offset']:x}`. Body SHA-256 is `{w['sha256']}`. The FDE is at `.eh_frame+0x{r['fde']['section_offset']:x}` (file `0x{r['fde']['file_offset']:x}`), CIE at `.eh_frame+0x{r['fde']['cie_section_offset']:x}`; raw records and decoded endpoints are in JSON. The FDE ends at RET; the next {len(bytes.fromhex(w['padding_hex']))} bytes are `cc` padding. This establishes this window, not a whole-function census. The output buffer must be writable for 32 bytes; the accessed input words must be readable and disjoint from output. Arbitrary pointers, object invariants, aliasing, concurrency and unwinding are outside the claim.

The complete byte walk has {len(r['instructions'])} instructions; branch destinations are computed from signed encoded displacements. The subtract at `0x152e388` sets flags for unsigned `ja`: equality belongs to the nonwrap arm. The single conditional subtraction at `0x152e378` does not perform a general modulo. The three LEA/shift sequences multiply by 80 modulo 2^64. The zero-count arm skips loading C and H. There are {len(r['callees'])} callees, including tail transfers, and no indirect dispatch in this body.

| ELF VA | Bytes | Decoded operation |
| --- | --- | --- |
{rows}

A full `.text` byte scan for `e8` and `e9` plus signed rel32 yields {len(r['direct_rel32_candidates'])} candidate sites: {callers}. Both are direct call opcodes, in FDEs `0x14f7200..0x14f8469` and `0x14f9dd0..0x14fabb0` respectively, with local disassembly confirming instruction starts. This byte scan includes possible embedded-data/overlapping false positives and excludes indirect calls and transfers into the body; it is not reachability or a complete call graph. Caller ownership is not identified. No callee behavior is bound.

## Reproduce and controls

Static only; Python 3.10+ stdlib, run from repository root. The producer authenticates the whole artifact before extraction and scans the specified complete `.text` byte interval, without executing it. GNU readelf/objdump 2.44 were used independently for focused FDE/caller inspection, not by the producer or tests. Analysis is complete only for this body and the specified byte scan; no normalization masks or binary comparisons were applied.

```sh
python3 tools/node115_two_span_projection.py --out research/work-items/RE-001-node115-two-span-projection/
python3 -m unittest tests.test_node115_two_span_projection -v
python3 research/work-items/RE-001-node115-two-span-projection/verify.py
make verify
make catalogue-check
```

Novelty before analysis: `rg -i '152e360|22209376' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt` returned no matches (exit 1). This includes both hex and decimal start; there are no callees to check. The catalogue seed record contains no inferred node #115 reference-address seeds. `make doctor` and `make verify` passed before selection.

The tests exercise instruction and FDE corruption, wrong full-file digest, a redirected direct call, the README counts against JSON, and boundary vectors based on the decoded operations. The independent model is a statement of the byte-level relation, not target execution or evidence of a recovered original API.

## Limits and next step

Original name, owner, collection type, allocation validity, callers' full behavior and first-party attribution remain unknown. No Rust implementation, source build, byte comparison, whole-node behavior or progress gate is claimed. Next, trace the two caller FDEs and their input construction to establish whether the four addresses actually delimit ring segments in a first-party path.
'''

VERIFY = '''#!/usr/bin/env python3
"""Verify the packet's exact file whitelist and SHA-256 manifest."""
import hashlib
from pathlib import Path

p = Path(__file__).resolve().parent
names = ("README.md", "records.json", "verify.py")
lines = (p / "MANIFEST.sha256").read_text().splitlines()
expected = [hashlib.sha256((p / n).read_bytes()).hexdigest() + "  " + n for n in names]
if lines != expected or {x.name for x in p.iterdir()} != set(names) | {"MANIFEST.sha256"}:
    raise SystemExit("Packet whitelist or manifest mismatch")
print("Packet whitelist and SHA-256 manifest OK")
'''


def produce(out, target=TARGET):
    with open(target, 'rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
        r = collect(data)
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    files = {'README.md': readme(r), 'records.json': json.dumps(r, indent=2) + '\n', 'verify.py': VERIFY}
    for name, content in files.items():
        (out / name).write_text(content, encoding='utf-8')
    manifest = ''.join(hashlib.sha256(files[n].encode()).hexdigest() + '  ' + n + '\n' for n in files)
    (out / 'MANIFEST.sha256').write_text(manifest, encoding='utf-8')
    return r


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    result = produce(args.out)
    print('Bound %#x: %d bytes, %d instructions, %d rel32 candidates' %
          (START, result['window']['size'], len(result['instructions']), len(result['direct_rel32_candidates'])))
