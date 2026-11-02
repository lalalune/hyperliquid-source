#!/usr/bin/env python3
"""Reproduce the RE-001 #94 tx/receipt byte classifier, without disassemblers."""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/94/hl-node'
SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BODY_SHA = '213c01340f32ae87e79642007c421dbc12076300d668be28d065bf5bafd6b937'
START, END, NEXT = 0x1e72770, 0x1e727b4, 0x1e727c0
CALLER = 0x1a66898
# Every instruction must match one of these complete, supported encodings. Branch
# displacements are decoded separately and checked against instruction boundaries.
INSTRUCTIONS = [
 ('4889f8','mov rax, rdi'), ('4883fa07','cmp rdx, 7'), ('7416','je 0x1e7278f'),
 ('4883fa02','cmp rdx, 2'), ('7523','jne 0x1e727a2'),
 ('66813e7478','cmp word [rsi], 0x7874'), ('751c','jne 0x1e727a2'),
 ('31c9','xor ecx, ecx'), ('884801','mov [rax+1], cl'), ('c60009','mov byte [rax], 9'), ('c3','ret'),
 ('b972656365','mov ecx, 0x65636572'), ('330e','xor ecx, dword [rsi]'),
 ('ba65697074','mov edx, 0x74706965'), ('335603','xor edx, dword [rsi+3]'),
 ('09ca','or edx, ecx'), ('7409','je 0x1e727ab'),
 ('b102','mov cl, 2'), ('884801','mov [rax+1], cl'), ('c60009','mov byte [rax], 9'), ('c3','ret'),
 ('b101','mov cl, 1'), ('884801','mov [rax+1], cl'), ('c60009','mov byte [rax], 9'), ('c3','ret'),
]

def require(condition, message):
    if not condition:
        raise ValueError(message)

def sections(m):
    require(m[:6] == b'\x7fELF\x02\x01', 'ELF format')
    shoff = struct.unpack_from('<Q', m, 0x28)[0]
    size, count, names = struct.unpack_from('<HHH', m, 0x3a)
    require(size == 64 and names < count and shoff + count * size <= len(m), 'section table')
    table = [struct.unpack_from('<IIQQQQIIQQ', m, shoff + n * size) for n in range(count)]
    noff, nsize = table[names][4:6]
    strings = m[noff:noff+nsize]
    result = {}
    for row in table:
        i = row[0]
        end = strings.find(b'\0', i)
        require(end >= i, 'section name')
        result[strings[i:end].decode('ascii')] = row
    return result

def decode(body):
    """Strictly decode the complete supported instruction sequence, reject deviations."""
    pos = 0
    walk, branches = [], []
    for encoded, meaning in INSTRUCTIONS:
        raw = bytes.fromhex(encoded)
        require(body[pos:pos+len(raw)] == raw, 'unsupported or changed instruction at %#x' % (START + pos))
        if raw[0] in (0x74, 0x75):
            target = START + pos + 2 + struct.unpack('<b', raw[1:])[0]
            require(meaning.endswith(hex(target)), 'branch target')
            branches.append({'site': hex(START+pos), 'target': hex(target), 'condition': 'equal' if raw[0] == 0x74 else 'not_equal'})
        walk.append((START + pos, raw.hex(' '), meaning))
        pos += len(raw)
    require(pos == len(body), 'incomplete instruction walk')
    boundaries = {x[0] for x in walk}
    require(all(int(b['target'],16) in boundaries for b in branches), 'branch boundary')
    return walk, branches

def frame(m, eh, off, expected_start, expected_end, expected_cie):
    base = eh[4] + off
    length, link, delta, extent = struct.unpack_from('<IIiI', m, base)
    cie = off + 4 - link
    start = eh[3] + off + 8 + delta
    require(length >= 16 and off + 4 + length <= eh[5], 'FDE extent')
    require((start, start + extent, cie) == (expected_start, expected_end, expected_cie), 'FDE association')
    return {'section_offset': hex(off), 'length': length, 'cie_offset': hex(cie), 'start': hex(start), 'end': hex(start + extent)}

def header_entries(m, hdr, eh):
    """Decode the complete sorted DW_EH_PE_datarel/sdata4 search table."""
    off, va, size = hdr[4], hdr[3], hdr[5]
    require(m[off:off+4] == b'\x01\x1b\x03\x3b', 'frame header encoding')
    eh_delta, count = struct.unpack_from('<iI', m, off+4)
    require(va + 4 + eh_delta == eh[3] and 12 + 8*count == size, 'frame header extent')
    entries = []
    for i in range(count):
        pc, fde = struct.unpack_from('<ii', m, off+12+8*i)
        entries.append((va + pc, va + fde - eh[3]))
    require(all(entries[i][0] <= entries[i+1][0] for i in range(len(entries)-1)), 'frame header order')
    matches = [e for e in entries if START <= e[0] <= NEXT]
    require(matches == [(START, 0x3d07c), (NEXT, 0x36d1f0)], 'frame header associations')
    return count

def scan(m, text, target):
    start, end = text[4], text[4] + text[5]
    out = {'calls': [], 'jumps': []}
    for opcode, key in ((b'\xe8', 'calls'), (b'\xe9', 'jumps')):
        pos = start
        while True:
            pos = m.find(opcode, pos, end - 4)
            if pos < 0:
                break
            site = text[3] + pos - text[4]
            if site + 5 + struct.unpack_from('<i', m, pos + 1)[0] == target:
                out[key].append(hex(site))
            pos += 1
    return out

def model(value):
    tag = 0 if value == b'tx' else 1 if value == b'receipt' else 2
    return bytes((9, tag))

def collect(m, expected_sha=SHA):
    require(hashlib.sha256(m).hexdigest() == expected_sha, 'target digest mismatch')
    ss = sections(m)
    text, eh = ss['.text'], ss['.eh_frame']
    require((text[3], text[4], text[5]) == (0x1343c80, 0x1342c80, 0x431c430), '.text mapping')
    require((eh[3], eh[4], eh[5]) == (0xce1518, 0xce1518, 0x661768), '.eh_frame mapping')
    require(m[eh[4]:eh[4]+24] == bytes.fromhex('1400000000000000017a5200017810011b0c070890010000'), 'primary CIE encoding')
    header_entries(m, ss['.eh_frame_hdr'], eh)
    off = text[4] + START - text[3]
    body = m[off:off + END - START]
    require(hashlib.sha256(body).hexdigest() == BODY_SHA, 'body hash mismatch')
    walk, branches = decode(body)
    fde = frame(m, eh, 0x3d07c, START, END, 0)
    neighbor = frame(m, eh, 0x36d1f0, NEXT, 0x1e72ade, 0x2dc714)
    padding = m[off + len(body):off + NEXT - START]
    require(padding == b'\xcc' * 12, 'padding')
    incoming = scan(m, text, START)
    require(incoming == {'calls': [hex(CALLER)], 'jumps': []}, 'direct caller scan')
    vectors = [b'', b'tx', b'receipt', b'Tx', b't', b'txx', b'receip', b'receipts', b'receipT', b'\0'*7]
    records = {
      'target': {'name': 'node #94', 'sha256': SHA, 'file_size': len(m)},
      'window': {'start': hex(START), 'end': hex(END), 'size': len(body), 'file_offset': hex(off), 'sha256': BODY_SHA,
                 'fde': fde, 'padding_hex': padding.hex(), 'next_fde': neighbor},
      'rule': {'input_abi': {'output': 'rdi', 'bytes': 'rsi', 'length': 'rdx'},
               'equal_cases': [{'bytes_hex': '7478', 'tag': 0}, {'bytes_hex': '72656365697074', 'tag': 1}],
               'other_tag': 2, 'output_marker': 9, 'return': 'output pointer in rax',
               'receipt_compare_chunks': [{'offset': 0, 'size': 4}, {'offset': 3, 'size': 4}]},
      'branches': branches, 'callees': [], 'direct_incoming': incoming,
      'vectors': [{'input_hex': x.hex(), 'output_hex': model(x).hex()} for x in vectors],
      'scan': {'section': '.text', 'method': 'every byte e8/e9 rel32, including unaligned candidates',
               'start': hex(text[3]), 'end': hex(text[3] + text[5])},
    }
    return records, walk

def readme(r, walk):
    w, inc, rule = r['window'], r['direct_incoming'], r['rule']
    cases = rule['equal_cases']
    rows = '\n'.join('| `0x%x` | `%s` | `%s` |' % x for x in walk)
    return f'''# RE-001: node #94 tx / receipt classifier

Task RE-001, component: serialization / function map. **Question:** what does the
function at `{w['start']}` compute from a byte slice? **Answer:** for a readable
slice `(rsi, rdx)`, it writes two bytes to `rdi`: marker {rule['output_marker']} followed by tag {cases[0]['tag']}
for exactly `tx`, tag {cases[1]['tag']} for exactly `receipt`, and tag {rule['other_tag']} for all other byte
strings. It returns the output pointer in `rax`. This is a byte-level rule;
no source type or enclosing protocol is assumed.

## Target and boundaries

Node #94 SHA-256 `{r['target']['sha256']}`; source baseline commit
`e5c9b6436876b2a4a39daef813171f9879317699`, reference gitlink
`999556f6e0a474b8312db96ec3149e1c44e97c23` (reference not consulted for the
rule). ELF virtual-address window `{w['start']}..{w['end']}` is {w['size']}
bytes, file offset `{w['file_offset']}`, body SHA-256 `{w['sha256']}`.
The `.eh_frame` FDE at section offset `{w['fde']['section_offset']}` has
length {w['fde']['length']} and CIE offset `{w['fde']['cie_offset']}`. The
next FDE starts at `{w['next_fde']['start']}`; the intervening
{len(bytes.fromhex(w['padding_hex']))} bytes are `cc` padding. The full `.eh_frame_hdr` search table confirms those adjacent starts. The FDE
and complete control flow support this extent; it is not inferred merely from a seed.

## Instruction walk

All bytes and instructions below are decoded by the strict Python decoder; no
external disassembler is used to generate or check the packet. Branches land on
instruction boundaries within the window. The {len(rule['receipt_compare_chunks'])} overlapping dword reads on
the {len(bytes.fromhex(cases[1]['bytes_hex']))}-byte path compare bytes 0..3 and 3..6, so the whole string must match.

| VA | Bytes | Decoded instruction |
| --- | --- | --- |
{rows}

## Calls, inference, and limits

The body has {len(r['callees'])} callees and no indirect transfer. A full `.text`
byte scan for `e8` and `e9` rel32 encodings produces {len(inc['calls'])} call
candidate(s) ({', '.join('`'+x+'`' for x in inc['calls']) or 'none'}) and
{len(inc['jumps'])} jump candidate(s). The call encoding at that site resolves
to this entry. A byte-pattern census can include opcode-like bytes inside other
instructions; it does not cover indirect calls, pointers, other sections, or
prefixed encodings. Input and output must be valid for the actual reads/writes;
behavior for invalid pointers is outside the rule. No Rust type, source owner,
message schema, protocol semantics, compilation equivalence, or execution result
is claimed. `records.json` includes {len(r['vectors'])} static model vectors;
they are derived from the instructions, not target executions. No full-scope
gate is advanced. Next, trace the caller's enclosing decode path and identify
what consumes the resulting tag using separate evidence.

## Novelty

Before creating this packet, the following command returned no matches (exit 1):

```sh
rg -i '1e72770|31926128' research/ ../../hl-re1-base/open_prs.txt ../../hl-re1-base/merged_prs.txt ../../hl-re1-base/closed_unmerged_prs.txt
```

There are no behavior-bound callees to check. The PR lists are external static
snapshots; the result does not assert that later work has not claimed the address.

## Reproduction

From the repository root, with Python 3.10+ standard library and the authenticated
artifact (static reads only):

```sh
python3 tools/node94_tx_receipt.py --out research/work-items/RE-001-tx-receipt-classifier-94/
python3 -m unittest tests.test_node94_tx_receipt -v
python3 research/work-items/RE-001-tx-receipt-classifier-94/verify.py
```

The collector checks the full target digest, ELF section coordinates, both FDE
associations, body hash, every instruction, padding, and full-section incoming
scan. `verify.py` enforces the packet file whitelist and manifest and regenerates
all generated files for byte comparison. No target binary is executed. Compiler,
linker, helper/data/relocation closure and whole-ELF reconstruction remain open.
'''

def render(r, walk, verify_bytes):
    files = {'records.json': (json.dumps(r, indent=2) + '\n').encode(),
             'README.md': readme(r, walk).encode(), 'verify.py': verify_bytes}
    manifest = ''.join(hashlib.sha256(files[n]).hexdigest() + '  ' + n + '\n' for n in sorted(files))
    files['MANIFEST.sha256'] = manifest.encode()
    return files

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--binary', type=Path, default=BINARY)
    args = parser.parse_args()
    with args.binary.open('rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
        r, walk = collect(m)
    files = render(r, walk, (args.out / 'verify.py').read_bytes())
    for name, content in files.items():
        if name != 'verify.py':
            (args.out / name).write_bytes(content)
    print('Generated', args.out)

if __name__ == '__main__':
    main()
