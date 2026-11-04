#!/usr/bin/env python3
"""Static, digest-bound RE-001 packet producer; no target code is executed."""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
TARGET_HASH = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
START = 0x2995ab0
END = 0x2995aea
FDE = 0xd73a50
CIE = 0xca6ed8
TEXT_START = 0x1419300
TEXT_END = 0x63f0a00
EXPECTED_HASH = 'b4397d5b09239add74b760338497bd4a84d0703975daf03592d823afd15271f4'

# The instruction forms and fixed operands are independently checked at each
# boundary. Branch displacement and RIP-free immediates are decoded separately.
FORMS = [
 ('488b4730', 'mov rax, [rdi+0x30]'),
 ('488d48fe', 'lea rcx, [rax-2]'),
 ('4881f9fd030000', 'cmp rcx, 0x3fd'),
 ('7726', 'ja 0x2995ae7'),
 ('488d4801', 'lea rcx, [rax+1]'),
 ('488b5728', 'mov rdx, [rdi+0x28]'),
 ('48c1e005', 'shl rax, 5'),
 ('0f104402c0', 'movups xmm0, [rdx+rax-0x40]'),
 ('0f104c02d0', 'movups xmm1, [rdx+rax-0x30]'),
 ('0f114c0210', 'movups [rdx+rax+0x10], xmm1'),
 ('0f110402', 'movups [rdx+rax], xmm0'),
 ('48894f30', 'mov [rdi+0x30], rcx'),
 ('31c0', 'xor eax, eax'),
 ('c3', 'ret'),
 ('b02d', 'mov al, 0x2d'),
 ('c3', 'ret'),
]


def sections(data):
    if data[:16] != b'\x7fELF\x02\x01\x01' + b'\0' * 9:
        raise ValueError('unsupported ELF identity')
    shoff = struct.unpack_from('<Q', data, 40)[0]
    entsize, count, names = struct.unpack_from('<HHH', data, 58)
    if entsize != 64 or not 0 < names < count or shoff + count * entsize > len(data):
        raise ValueError('invalid section table')
    entries = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * entsize) for i in range(count)]
    strings = entries[names]
    if strings[4] + strings[5] > len(data):
        raise ValueError('invalid section strings')
    table = data[strings[4]:strings[4] + strings[5]]
    result = {}
    for entry in entries:
        no, typ, flags, va, off, size, *_ = entry
        if no >= len(table):
            raise ValueError('invalid section name')
        end = table.find(b'\0', no)
        if end < 0:
            raise ValueError('unterminated section name')
        name = table[no:end].decode('ascii')
        if name in ('.text', '.eh_frame', '.rela.dyn'):
            if name in result or off + size > len(data):
                raise ValueError('invalid or duplicate section')
            result[name] = (typ, flags, va, off, size)
    if set(result) != {'.text', '.eh_frame', '.rela.dyn'}:
        raise ValueError('missing required sections')
    if result['.text'] != (1, 6, TEXT_START, 0x1418300, TEXT_END-TEXT_START):
        raise ValueError('unexpected text section')
    if result['.eh_frame'][2:] != (CIE, CIE, 0x77137c):
        raise ValueError('unexpected unwind section')
    return result


def decode(body):
    """Decode all instructions, reject altered forms and invalid branch target."""
    out, pos = [], 0
    for pattern, operation in FORMS:
        raw = bytes.fromhex(pattern)
        if body[pos:pos + len(raw)] != raw:
            raise ValueError('unexpected instruction at offset %#x' % pos)
        if raw[0] == 0x77:
            target = START + pos + 2 + struct.unpack('<b', raw[1:])[0]
            if target != START + 55:
                raise ValueError('unexpected conditional target')
        out.append({'va': hex(START + pos), 'bytes': raw.hex(), 'instruction': operation})
        pos += len(raw)
    if pos != len(body):
        raise ValueError('instruction coverage mismatch')
    return out


def unwind(data):
    # Exact CIE form zR, pcrel/sdata4, and the complete FDE record.
    cie = data[CIE:CIE + 24]
    if cie != bytes.fromhex('1400000000000000017a5200017810011b0c070890010000'):
        raise ValueError('unexpected CIE')
    raw = data[FDE:FDE + 20]
    if len(raw) != 20:
        raise ValueError('truncated FDE')
    size, delta, rel, extent = struct.unpack_from('<IIii', raw)
    if (size, FDE + 4 - delta, FDE + 8 + rel, extent, raw[16:]) != (16, CIE, START, END-START, b'\0\0\0\0'):
        raise ValueError('unexpected FDE or CIE reference')
    return {'fde_file_offset': hex(FDE), 'fde_section_offset': hex(FDE-CIE),
            'cie_file_offset': hex(CIE), 'cie_section_offset': '0x0',
            'fde_bytes': raw.hex(), 'cie_bytes': cie.hex(), 'lsda': None}


def relocations(data, sec):
    typ, flags, va, off, size = sec
    if (typ, va, off, size) != (4, 0x6be8, 0x6be8, 0x163cc8) or size % 24:
        raise ValueError('unexpected relocation section')
    found = []
    for pos in range(off, off + size, 24):
        slot, info, addend = struct.unpack_from('<QQq', data, pos)
        if addend == START and info == 8:
            found.append({'record_file_offset': hex(pos), 'slot_va': hex(slot), 'type': 'R_X86_64_RELATIVE', 'addend': hex(addend)})
    if [x['slot_va'] for x in found] != ['0x6441618', '0x6442308']:
        raise ValueError('unexpected relocation references')
    return found


def direct_transfers(data, sec):
    _, _, va, off, size = sec
    end = off + size
    found = []
    for op, name in ((b'\xe8', 'call'), (b'\xe9', 'jmp')):
        pos = off
        while True:
            pos = data.find(op, pos, end - 4)
            if pos < 0:
                break
            destination = va + pos - off + 5 + struct.unpack_from('<i', data, pos + 1)[0]
            if destination == START:
                found.append({'site': hex(va + pos - off), 'kind': name})
            pos += 1
    return sorted(found, key=lambda x: int(x['site'], 16))


def analyze(data, authenticate=True):
    if authenticate and hashlib.sha256(data).hexdigest() != TARGET_HASH:
        raise ValueError('target SHA-256 mismatch')
    sec = sections(data)
    frame = unwind(data)
    offset = sec['.text'][3] + START - TEXT_START
    body = data[offset:offset + END-START]
    if hashlib.sha256(body).hexdigest() != EXPECTED_HASH:
        raise ValueError('function body SHA-256 mismatch')
    instructions = decode(body)
    padding = data[offset + len(body):offset + len(body) + 6]
    if padding != b'\xcc' * 6:
        raise ValueError('unexpected padding')
    relocs = relocations(data, sec['.rela.dyn'])
    calls = direct_transfers(data, sec['.text'])
    return {'target_sha256': TARGET_HASH,
            'window': {'start_va': hex(START), 'end_va': hex(END), 'file_offset': hex(offset),
                       'size': len(body), 'body_sha256': hashlib.sha256(body).hexdigest(),
                       'padding_hex': padding.hex()},
            'unwind': frame, 'instructions': instructions,
            'callees': [], 'direct_rel32_transfers': calls, 'relative_relocations': relocs,
            'counts': {'instructions': len(instructions), 'callees': 0,
                       'direct_rel32_transfers': len(calls), 'relative_relocations': len(relocs)}}


def model(length, cells):
    """Return (AL, length, copied cells); one cell consists of 32 bytes."""
    if not 0 <= length < 1 << 64:
        raise ValueError('length is not u64')
    if ((length - 2) & ((1 << 64) - 1)) > 0x3fd:
        return 0x2d, length, list(cells)
    if len(cells) < length or any(len(c) != 32 for c in cells):
        raise ValueError('insufficient valid cells')
    result = list(cells)
    copied = result[length-2]
    if len(result) == length:
        result.append(copied)
    else:
        result[length] = copied
    return 0, length + 1, result


def readme(r):
    c, w, u = r['counts'], r['window'], r['unwind']
    return f'''# RE-001: bounded 32-byte stack copy at 0x2995ab0

- Component: RE-001 function map; potential RE-011 execution-adapter lead.
- Target: Linux x86-64 node #115, SHA-256 `{TARGET_HASH}`.
- Base revision: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; no reference source used.
- Bounded question: what does this entire previously unbound function do to its length and 32-byte elements, and what happens at its bounds?

**Answer (inference from the complete instructions):** Let `n` be the unsigned 64-bit word at `[rdi+0x30]`, and let `[rdi+0x28]` point to an array of 32-byte elements. If `2 <= n <= 1023`, it copies element `n-2` into element `n`, stores `n+1` at `[rdi+0x30]`, and returns AL=0. Otherwise it returns AL=0x2d without accessing the array or writing the length. The rejection arm only writes AL; the upper return-register bits are not specified as a return value. Valid object, readable source and writable destination memory are preconditions for the success arm.

## Evidence and coordinates

All addresses are original ELF virtual addresses; the window `{w['start_va']}..{w['end_va']}` is {w['size']} bytes, at file offset `{w['file_offset']}`. Its SHA-256 is `{w['body_sha256']}`. The FDE starts at file offset `{u['fde_file_offset']}` (section offset `{u['fde_section_offset']}`), names CIE file offset `{u['cie_file_offset']}` (section offset `{u['cie_section_offset']}`), and describes exactly the window with no LSDA. The six bytes after the described body are `cc` padding. The FDE alone does not prove a function; the entry, complete decoded control flow and two dynamic relative relocation references support this particular boundary. The CIE and FDE bytes are in records.json.

The complete instruction walk ({c['instructions']} instructions) and bytes are in records.json. `lea rcx,[rax-2]` wraps modulo 2^64; unsigned `cmp rcx,0x3fd` / `ja` therefore accepts exactly 2 through 1023, inclusive. On success, shifting the original `n` by five forms the 32-byte stride. The two 16-byte loads happen before either store, from `32*n-64` and `32*n-48`; stores target `32*n` and `32*n+16`. The length update follows both stores. No calls, indirect transfers, or external data references occur in the body: callee count {c['callees']}.

A complete bytewise `.text` scan for every `e8` and `e9` with an in-section four-byte rel32 operand found {c['direct_rel32_transfers']} candidate direct transfers to the entry. This is a raw opcode-byte census, not instruction-boundary disassembly and not a census of indirect callers. The `.rela.dyn` scan found {c['relative_relocations']} `R_X86_64_RELATIVE` records whose addend is the entry, at the slots listed in records.json. They establish address references, not execution or the identities of any callers.

## Novelty and reproduction

Before analysis, these searches returned no matches (exit 1) in the specified corpus:

```sh
rg -i '2995ab0|43604656' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

The producer authenticates the entire input before any output, checks ELF sections, exact instruction forms and branch target, CIE/FDE and padding, and records the full raw transfer scan and relocation records. From the repository root, Python 3.10+ standard library only:

```sh
python3 tools/node115_stack_copy.py --out research/work-items/RE-001-node115-stack-copy/
python3 -m unittest tests.test_node115_stack_copy -v
python3 research/work-items/RE-001-node115-stack-copy/verify.py
make verify
make catalogue-check
```

Static inspection only; no captured executable, network or external state is used. Reproduction requires the authenticated artifact at `artifacts/node/115/hl-node`. Results, instruction bytes and hashes are deterministic; no disassembler is required. The producer and verifier are independently authored under the repository MIT terms.

## Limits and next step

The names “array” and “length” describe observed memory operations, not recovered Rust types. Neither a specific EVM opcode nor the meaning of status 0x2d is proven. No direct or indirect caller semantics, runtime behavior, invalid-pointer behavior, Rust reconstruction, compiled-byte comparison, normalization masks, whole-ELF equivalence, component completion or acceptance gate is claimed. The Python model tests this local rule only; it is not a differential execution of the node. Next, trace both relocation slots and their consumers to establish dispatch context and the original operation identity.
'''


def generate(binary, out):
    with binary.open('rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
        result = analyze(data)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'records.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    (out / 'README.md').write_text(readme(result), encoding='utf-8')
    names = ('README.md', 'records.json', 'verify.py')
    manifest = ''.join(hashlib.sha256((out / name).read_bytes()).hexdigest() + '  ' + name + '\n' for name in names)
    (out / 'MANIFEST.sha256').write_text(manifest, encoding='ascii')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, default=ROOT / 'artifacts/node/115/hl-node')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    generate(args.binary, args.out)


if __name__ == '__main__':
    main()
