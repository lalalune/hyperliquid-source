#!/usr/bin/env python3
"""Regenerate one static, authenticated node #115 function-bind packet."""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
START, END = 0x55ff9e0, 0x55ffa44
TEXT_START, TEXT_END, TEXT_OFFSET = 0x1419300, 0x63f0a00, 0x1418300
FDE, CIE = 0xf86fb8, 0xca6ed8
BODY_SHA = 'c7eae84020e629ae599eb400ad0d31b78d3a037651d47d2cdc3ce4a83995acf0'
CALLERS = (0x517adc5, 0x517b61d, 0x57ca47b, 0x57ca990)
CALLER_CONTEXTS = (('488b7c2448', 'mov rdi, [rsp+0x48]', '440a7424160f94c13c02', 'or r14b, [rsp+0x16]; sete cl; cmp al, 2'),
                   ('4c89ef', 'mov rdi, r13', '400a6c240e0f94c13c02', 'or bpl, [rsp+0xe]; sete cl; cmp al, 2'),
                   ('488b7c2410', 'mov rdi, [rsp+0x10]', '3c02', 'cmp al, 2'),
                   ('4889df', 'mov rdi, rbx', '3c02', 'cmp al, 2'))
CALLER_FDES = ((0x132785c, 0x517a670, 0x517af4d), (0xf58b04, 0x517af50, 0x517b75d), (0x1376b58, 0x57c9f60, 0x57ca54e), (0xf92e30, 0x57ca550, 0x57caa3a))
# Exact supported encodings. Fixed memory offsets and register operands are part
# of the instruction decoder's contract; branches are decoded separately.
OPS = {
 '8b4760': 'mov eax, dword [rdi+0x60]',
 '488b4f28': 'mov rcx, qword [rdi+0x28]',
 '3b8794420000': 'cmp eax, dword [rdi+0x4294]',
 '0f9cc0': 'setl al (signed less)',
 '8b4764': 'mov eax, dword [rdi+0x64]',
 '3b8798420000': 'cmp eax, dword [rdi+0x4298]',
 '0f92c0': 'setb al (unsigned less)',
 '8b4768': 'mov eax, dword [rdi+0x68]',
 '3b879c420000': 'cmp eax, dword [rdi+0x429c]',
 '84c0': 'test al, al',
 'b002': 'mov al, 2',
 '483b8f28420000': 'cmp rcx, qword [rdi+0x4228]',
 '488b4710': 'mov rax, qword [rdi+0x10]',
 '4889c2': 'mov rdx, rax',
 '4881ea78ecffff': 'sub rdx, sign-extended -5000',
 '480588130000': 'add rax, 5000',
 '48c7c2ffffffff': 'mov rdx, -1',
 '480f43d0': 'cmovae rdx, rax',
 '4839d1': 'cmp rcx, rdx',
 '0f93c0': 'setae al (unsigned greater or equal)',
 'c3': 'ret',
}
BRANCH = {0x75:'jne', 0x73:'jae', 0x72:'jb', 0xeb:'jmp'}
# Strict instruction order also ensures this decoder cannot silently reinterpret
# padding or an unexpected but individually valid encoding as this function.
SEQUENCE = ['8b4760','488b4f28','3b8794420000','0f9cc0','75','8b4764',
 '3b8798420000','0f92c0','75','8b4768','3b879c420000','73','eb',
 '84c0','75','b002','483b8f28420000','73','488b4710','4889c2',
 '4881ea78ecffff','72','480588130000','48c7c2ffffffff','480f43d0',
 '4839d1','0f93c0','c3']
BRANCH_TARGETS = [0x55ffa0d,0x55ffa0d,0x55ffa11,0x55ffa1c,
                  0x55ffa1c,0x55ffa43,0x55ffa3d]


def decode(body):
    pos = 0
    rows, targets = [], []
    for spec in SEQUENCE:
        raw = bytes.fromhex(spec)
        va = START + pos
        if len(raw) == 1 and raw[0] in BRANCH:
            if len(body) < pos + 2 or body[pos] != raw[0]:
                raise ValueError('unsupported branch encoding')
            disp = struct.unpack_from('<b', body, pos + 1)[0]
            target = va + 2 + disp
            targets.append(target)
            inst = bytes(body[pos:pos+2])
            description = f'{BRANCH[raw[0]]} {target:#x}'
        else:
            if bytes(body[pos:pos+len(raw)]) != raw:
                raise ValueError('unsupported instruction encoding')
            inst, description = raw, OPS[spec]
        rows.append({'address':va, 'bytes':inst.hex(), 'instruction':description})
        pos += len(inst)
    if pos != len(body) or targets != BRANCH_TARGETS:
        raise ValueError('instruction extent or branch target changed')
    if any(t not in {r['address'] for r in rows} for t in targets):
        raise ValueError('branch into instruction')
    return rows


def frame(data):
    # Exact CIE and FDE, including augmentation and unwind program. These
    # section virtual addresses equal file offsets in this particular ELF.
    if bytes(data[CIE:CIE+24]).hex() != '1400000000000000017a5200017810011b0c070890010000':
        raise ValueError('CIE changed')
    b = bytes(data[FDE:FDE+20])
    if len(b) != 20:
        raise ValueError('truncated FDE')
    length, delta, rel, size = struct.unpack_from('<IIiI', b)
    if (length, FDE+4-delta, FDE+8+rel, size, b[16:]) != (16,CIE,START,END-START,b'\0\0\0\0'):
        raise ValueError('FDE changed')
    return {'fde_address':FDE, 'fde_file_offset':FDE, 'cie_address':CIE,
            'cie_file_offset':CIE, 'cie_augmentation':'zR',
            'fde_bytes':b.hex(), 'cie_bytes':bytes(data[CIE:CIE+24]).hex(), 'lsda':None}


def check_call(site, raw):
    if len(raw) != 5 or raw[0] != 0xe8 or site + 5 + struct.unpack_from('<i',raw,1)[0] != START:
        raise ValueError('caller target changed')
    return {'site':site, 'bytes':bytes(raw).hex(), 'opcode':'call rel32', 'target':START}


def census(data):
    found = []
    end = TEXT_OFFSET + TEXT_END - TEXT_START
    for opcode in (b'\xe8', b'\xe9'):
        pos = TEXT_OFFSET
        while True:
            pos = data.find(opcode, pos, end-4)
            if pos < 0:
                break
            site = TEXT_START + pos - TEXT_OFFSET
            if site + 5 + struct.unpack_from('<i',data,pos+1)[0] == START:
                found.append((site, bytes(data[pos:pos+5])))
            pos += 1
    found.sort()
    if tuple(site for site, _ in found) != CALLERS:
        raise ValueError('rel32 census changed')
    rows = []
    for (site, raw), (fde, start, end_va), (before_hex, before_desc, after_hex, after_desc) in zip(found, CALLER_FDES, CALLER_CONTEXTS):
        header = bytes(data[fde:fde+16])
        length, delta, rel, extent = struct.unpack('<IIiI', header)
        if fde+8+rel != start or start+extent != end_va or not start <= site < end_va:
            raise ValueError('caller FDE changed')
        before, after = bytes.fromhex(before_hex), bytes.fromhex(after_hex)
        offset = site-0x1000
        if bytes(data[offset-len(before):offset]) != before or bytes(data[offset+5:offset+5+len(after)]) != after:
            raise ValueError('caller context instruction changed')
        row = check_call(site, raw)
        row.update({'before_bytes':before_hex, 'before_instruction':before_desc,
                    'after_bytes':after_hex, 'after_instructions':after_desc})
        row.update({'caller_fde':fde, 'caller_cie':fde+4-delta,
                    'caller_start':start, 'caller_end':end_va, 'fde_header':header.hex()})
        rows.append(row)
    return rows


def analyze(data):
    if hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('node #115 digest mismatch')
    off = TEXT_OFFSET + START-TEXT_START
    body = bytes(data[off:off+END-START])
    instructions = decode(body)
    if hashlib.sha256(body).hexdigest() != BODY_SHA:
        raise ValueError('body digest mismatch')
    pad = bytes(data[off+len(body):off+len(body)+12])
    if pad != b'\xcc'*12:
        raise ValueError('padding changed')
    loc_site, loc = 0x517ac9f, 0x64768a8
    lea = bytes(data[loc_site-0x1000:loc_site-0x1000+7])
    if lea[:3] != bytes.fromhex('488d3d') or loc_site+7+struct.unpack_from('<i',lea,3)[0] != loc:
        raise ValueError('caller Location reference changed')
    relocation = bytes(data[0xa29d8:0xa29d8+24])
    if struct.unpack('<QQq',relocation) != (loc,8,0x437df7):
        raise ValueError('Location relocation changed')
    location = bytes(data[loc-0x2000:loc-0x2000+24])
    if struct.unpack('<QQII',location) != (0,19,163,38) or bytes(data[0x437df7:0x437df7+19]) != b'l1/src/perp_meta.rs':
        raise ValueError('Location metadata changed')
    context = {'caller_fde_start':0x517a670, 'location_site':loc_site,
               'location_lea_bytes':lea.hex(), 'location_address':loc,
               'relocation_file_offset':0xa29d8, 'relocation_bytes':relocation.hex(),
               'path':'l1/src/perp_meta.rs', 'path_address':0x437df7,
               'location_file_offset':loc-0x2000, 'location_bytes':location.hex(),
               'line':163, 'column':38}
    return {'target_sha256':SHA, 'target_size':len(data), 'caller_context':context,
      'window':{'start':START,'end':END,'size':len(body),'file_offset':off,
                'sha256':BODY_SHA,'padding_hex':pad.hex()},
      'frame':frame(data), 'instructions':instructions, 'callees':[],
      'rel32_census':{'range_start':TEXT_START,'range_end':TEXT_END,
                     'method':'all byte offsets: e8/e9 followed by signed rel32',
                     'sites':census(data)}}


def model(first, second, tick, base, cutoff):
    """Machine-level normal-return relation; words are unsigned raw bit patterns."""
    if any(not 0 <= x < 2**32 for x in (*first,*second)) or any(not 0 <= x < 2**64 for x in (tick,base,cutoff)):
        raise ValueError('out of range')
    signed = lambda x: x if x < 2**31 else x-2**32
    left = (signed(first[0]), first[1], first[2])
    right = (signed(second[0]), second[1], second[2])
    if left >= right and tick >= cutoff:
        return 2
    return int(tick >= min(base+5000, 2**64-1))


def readme(r):
    w, f, rows, sites = r['window'], r['frame'], r['instructions'], r['rel32_census']['sites']
    walk = '\n'.join(f"| `0x{x['address']:x}` | `{x['bytes']}` | {x['instruction']} |" for x in rows)
    callers = ', '.join(f"`0x{x['site']:x}`" for x in sites)
    return f'''# RE-001: node #115 lexicographic and saturating threshold

- Component: RE-001 function map; candidate first-party context, not a subsystem claim.
- Target: node #115, SHA-256 `{SHA}`; source baseline `8fd8db680ec4bfef40996e5616bce3d5156d0b86`. No upstream source revision is asserted.
- Bounded question: what does the complete leaf at `0x{START:x}` return from its input fields?
- Scope: one function, no execution of the captured executable; observation and arithmetic inference only. No progress gate requested.

**Answer.** Read 32-bit fields A at offsets `+0x60,+0x64,+0x68` and B at `+0x4294,+0x4298,+0x429c`. Compare their triples lexicographically, treating the first field as signed and the other two as unsigned. Let T, X and C be unsigned 64-bit fields at `+0x28`, `+0x10` and `+0x4228`. If A is greater than or equal to B and T >= C, AL is 2. Otherwise AL is 1 if T >= min(X + 5000, 2^64 - 1), and 0 otherwise. This is conditional on valid readable input memory. Only AL is claimed; upper return-register bits are not uniformly defined.

## Evidence and interpretation

All addresses are original ELF virtual addresses, half-open. The window `0x{w['start']:x}..0x{w['end']:x}` is {w['size']} bytes, file offset `0x{w['file_offset']:x}`, SHA-256 `{w['sha256']}`. Its FDE at VA/file offset `0x{f['fde_address']:x}` references CIE `0x{f['cie_address']:x}` (`zR`, no LSDA). FDE and CIE bytes are in records.json. The following {len(bytes.fromhex(w['padding_hex']))} bytes are INT3 padding; this and the terminating return support the FDE extent, but unwind information alone is not a proof of universal function boundaries.

The {len(rows)} instructions below cover every body byte. SETL uses signed flags from the first comparison; SETB and JAE use unsigned flags for the remaining fields. The first two JNEs consume the flags of CMP because SETcc does not modify flags. For X below `2^64-5000`, subtracting sign-extended -5000 wraps to X+5000 and sets borrow; at or above that boundary, the ADD/CMOVAE pair selects the sum if no carry, otherwise `UINT64_MAX`. The final unsigned comparison includes equality. No call or indirect transfer occurs inside the body: callee count {len(r['callees'])}.

| VA | Bytes | Strict decoded instruction |
| --- | --- | --- |
{walk}

The complete `.text` byte-offset scan for `e8`/`e9` followed by signed rel32 finds {len(sites)} candidate sites: {callers}; all {len(sites)} have opcode `e8`. Strictly decoded adjacent instructions support instruction boundaries, but the scan can include incidental byte patterns and cannot find indirect calls, alternate encodings, or prove reachability. The site `0x517adc5` lies in the FDE beginning `0x517a670`, whose LEA at `0x517ac9f` references Location `0x64768a8`; its relative relocation points to `l1/src/perp_meta.rs`, line 163, column 38. The LEA, metadata and relocation bytes are validated and recorded in JSON. This caller association does not name this leaf or prove ownership. The remaining sites' context is not semantically closed. No call-target normalization was applied.

## Reproduce and controls

From the repository root, Python 3.10+ stdlib and the authenticated artifact are required. This run used Python 3.13.5 on Linux x86-64; GNU objdump 2.44 was used only for exploratory cross-checking. REA was unavailable because the pinned local package was absent; no installation was attempted. Generation is deterministic, static, and validates the full artifact digest before analysis or writing. `records.json` stores semantic instruction and caller records. `verify.py` checks an exact packet-file whitelist and SHA-256 manifest. The model is independently authored from this walk, not recovered source.

```sh
python3 tools/node115_saturating_threshold.py --out research/work-items/RE-001-node115-saturating-threshold/
python3 -m unittest tests.test_node115_saturating_threshold -v
python3 research/work-items/RE-001-node115-saturating-threshold/verify.py
make verify
make catalogue-check
```

Novelty check before development: the combined hexadecimal and decimal search returned no matches (ripgrep exit 1):

```sh
rg -i '55ff9e0|90175968' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

Negative controls reject a wrong digest, altered instruction, changed branch, shifted FDE and changed direct-call target. Boundary vectors check signed versus unsigned ordering, equality, and saturation. These tests establish the local rule against decoded bytes, not a native execution comparison.

## Limitations and next step

No original Rust type, field name, units, protocol meaning, caller argument provenance, full caller behavior, relocation/data closure, ABI beyond the observed input register and AL, native behavior under invalid pointers, compiler provenance, independently built Rust or whole-node equivalence is claimed. There is no before/after binary comparison or normalization mask. The first-party path is a caller-context lead only. Next, trace the four callers' input construction to establish field meaning and whether the return values have a common protocol interpretation.
'''


VERIFY_SCRIPT = '#!/usr/bin/env python3\n"""Fail closed on packet file additions or changed content."""\nimport hashlib\nfrom pathlib import Path\n\nfolder = Path(__file__).resolve().parent\nexpected = {\'README.md\', \'records.json\', \'verify.py\', \'MANIFEST.sha256\'}\nif {p.name for p in folder.iterdir()} != expected:\n    raise SystemExit(\'packet whitelist mismatch\')\nlines = (folder/\'MANIFEST.sha256\').read_text().splitlines()\nexpected_files = (\'README.md\', \'records.json\', \'verify.py\')\nif len(lines) != len(expected_files):\n    raise SystemExit(\'manifest length mismatch\')\nfor line, name in zip(lines, expected_files):\n    digest, separator, filename = line.partition(\'  \')\n    if separator != \'  \' or filename != name or digest != hashlib.sha256((folder/name).read_bytes()).hexdigest():\n        raise SystemExit(\'manifest mismatch\')\nprint(\'Packet whitelist and manifest verified\')\n'


def emit(out, record):
    out.mkdir(parents=True, exist_ok=True)
    (out/'records.json').write_text(json.dumps(record,indent=2)+'\n')
    (out/'README.md').write_text(readme(record))
    (out/'verify.py').write_text(VERIFY_SCRIPT)
    names = ('README.md','records.json','verify.py')
    manifest = ''.join(f"{hashlib.sha256((out/n).read_bytes()).hexdigest()}  {n}\n" for n in names)
    (out/'MANIFEST.sha256').write_text(manifest)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--target', type=Path, default=TARGET)
    args=p.parse_args()
    with args.target.open('rb') as f, mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as data:
        record=analyze(data)
    emit(args.out,record)

if __name__ == '__main__':
    main()
