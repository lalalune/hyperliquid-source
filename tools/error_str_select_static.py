#!/usr/bin/env python3
"""RE-001: node115 two-variant error-string selector @ 0x14cad10, static only.

The leaf at 0x14cad10 reads one discriminant byte through RDI and returns a
`&'static str` fat pointer (RAX=data, RDX=length) selecting between two rodata
messages. The length is produced by the branchless arithmetic `3*(b^1)+14`
(b==0 -> 17, b==1 -> 14) and the data pointer by a CMOVNE between two
RIP-relative LEAs. Its address is taken exactly once, as a RELATIVE relocation
into a .data.rel.ro dispatch table, so this is an observed method-slot leaf;
no original Rust type, trait or error enum identity is claimed here.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
from artifacts import ROOT
from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import decode_export

TARGET = ROOT / 'artifacts/node/115/hl-node'
PACKET = ROOT / 'research/work-items/RE-001-node115-error-str-select'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SPEC_SHA = '3742e2a24c90ebf36529968d08274b7f155e6335819a3d25c0796b7e4b4f8b45'


def specification():
    raw = (PACKET / 'spec.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != SPEC_SHA:
        raise ValueError('error-str-select specification changed')
    return json.loads(raw)


def read(data, va, n):
    matches = [s for s in sections(data)
               if s['type'] != 8 and s['address'] <= va and va + n <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('expected unique file-backed mapping')
    s = matches[0]
    off = s['offset'] + va - s['address']
    return off, bytes(data[off:off + n])


def model(spec, discriminant):
    """Independently authored relation for the leaf's observed normal returns.

    Returns (data_pointer, length) exactly as the native body computes them for
    the discriminant byte in RDI. Faithful only for the boolean inputs {0,1};
    the formula is reported for other bytes without asserting the caller ever
    supplies them.
    """
    if not 0 <= discriminant <= 0xff:
        raise ValueError('discriminant is a single byte')
    p = spec['parameters']
    length = p['length_factor'] * (discriminant ^ p['xor_immediate']) + p['length_base']
    pointer = p['zero_pointer'] if discriminant == 0 else p['nonzero_pointer']
    return pointer, length


def analyze(data):
    spec = specification()
    owner = spec['owner']
    a, b = owner['start'], owner['end']
    p = spec['parameters']

    # 1. Exact body bytes and digest over the complete FDE extent.
    off, body = read(data, a, b - a)
    if body.hex() != owner['bytes_hex'] or hashlib.sha256(body).hexdigest() != owner['body_sha256']:
        raise ValueError('error-str-select body bytes changed')
    if off != owner['file_offset']:
        raise ValueError('error-str-select file offset changed')

    # 2. The arithmetic/select opcodes that carry the semantics.
    for site, raw in spec['opcodes'].items():
        expect = bytes.fromhex(raw)
        if read(data, int(site), len(expect))[1] != expect:
            raise ValueError(f'error-str-select opcode changed at {int(site):#x}')

    # 3. RIP-relative LEAs resolve to the two rodata message starts.
    for site, target in owner['rip_bindings'].items():
        site = int(site)
        code = read(data, site, 7)[1]
        if code[:3] not in (b'\x48\x8d\x35', b'\x48\x8d\x05'):
            raise ValueError('error-str-select LEA prefix changed')
        if site + 7 + struct.unpack_from('<i', code, 3)[0] != target:
            raise ValueError('error-str-select LEA target changed')

    # 4. The selected rodata strings themselves.
    strings = {}
    for addr, row in spec['strings'].items():
        got = read(data, int(addr), row['length'])[1]
        if got.hex() != row['bytes_hex']:
            raise ValueError('error-str-select rodata message changed')
        strings[addr] = got.decode('ascii')

    # 5. The single RELATIVE relocation that publishes the address.
    s = next(s for s in sections(data) if s['name'] == '.rela.dyn')
    slot = spec['vtable_slot']
    found = None
    for rva, info, add in struct.iter_unpack('<QQq', data[s['offset']:s['offset'] + s['size']]):
        if add == a and (info & 0xffffffff) == slot['reloc_info']:
            found = rva
    if found != slot['address']:
        raise ValueError('error-str-select vtable relocation changed')

    # 6. FDE/CIE extents and raw bytes.
    _, fs, _ = fde_extents(data)
    frames = {(f['start'], f['end']): f for f in fs}
    if (a, b) not in frames:
        raise ValueError('error-str-select FDE extent changed')
    frame = frames[a, b]
    raw = {}
    for kind in ('fde', 'cie'):
        va = frame[kind]
        n = struct.unpack('<I', read(data, va, 4)[1])[0] + 4
        got = read(data, va, n)[1]
        if got.hex() != owner[f'{kind}_bytes_hex']:
            raise ValueError(f'error-str-select {kind} bytes changed')
        raw[kind] = {'va': hex(va), 'bytes_hex': got.hex()}

    # 7. The branchless length/pointer relation, enumerated for the boolean domain.
    examples = []
    for disc in (0, 1):
        pointer, length = model(spec, disc)
        examples.append({'discriminant': disc, 'data_pointer': hex(pointer),
                         'length': length, 'text': strings[str(pointer)]})
    if examples[0] != {'discriminant': 0, 'data_pointer': hex(p['zero_pointer']),
                       'length': 17, 'text': 'invalid character'}:
        raise ValueError('error-str-select discriminant-0 relation changed')
    if examples[1] != {'discriminant': 1, 'data_pointer': hex(p['nonzero_pointer']),
                       'length': 14, 'text': 'invalid length'}:
        raise ValueError('error-str-select discriminant-1 relation changed')

    return {
        'target_sha256': SHA,
        'spec_sha256': SPEC_SHA,
        'owner': {'start': hex(a), 'end': hex(b), 'bytes': b - a,
                  'instructions': owner['instructions'], 'file_offset': hex(off),
                  'body_sha256': owner['body_sha256'], 'frames': raw},
        'vtable_slot': hex(slot['address']),
        'relation': 'data = (b==0)? &"invalid character" : &"invalid length"; len = 3*(b^1)+14',
        'examples': examples,
        'captured_code_executed': False,
        'limits': ('One selected two-variant error-string leaf and its single dispatch-table '
                   'slot. The owning trait/error type, the dispatch table as a whole, all '
                   'callers, non-boolean discriminant inputs, Rust reconstruction and every '
                   'component gate remain unproved. No captured execution.'),
    }


def generate(binary, output):
    data = binary.read_bytes()
    if len(data) != 105896032 or hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('expected pinned node115')
    report = analyze(data)
    spec = specification()
    owner = spec['owner']
    a, b = owner['start'], owner['end']
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as directory:
        snapshot = Path(directory) / 'node115.elf'
        snapshot.write_bytes(data)
        frames = subprocess.check_output(['readelf', '-wf', str(snapshot)], text=True)
        rows = [l for l in frames.splitlines() if f'pc={a:016x}..{b:016x}' in l]
        if len(rows) != 1:
            raise ValueError('native error-str-select FDE disagreement')
        asm = subprocess.check_output(
            ['objdump', '-d', '-M', 'intel', '--insn-width=16',
             f'--start-address={a:#x}', f'--stop-address={b:#x}', str(snapshot)], text=True)
        ins = decode_export(asm, a, b, read(data, a, b - a)[1])
        required = {int(v) for v in owner['rip_bindings']} | {int(v) for v in spec['opcodes']}
        if len(ins) != owner['instructions'] or not required <= set(ins):
            raise ValueError('native error-str-select instruction disagreement')
        (output / f'{a:x}.objdump.txt').write_bytes(
            asm.replace(str(snapshot), '<authenticated-node115>').encode('utf-8'))
        (output / 'frames.txt').write_bytes(('\n'.join(rows) + '\n').encode('utf-8'))
    (output / 'records.json').write_bytes((json.dumps(report, indent=2) + '\n').encode('utf-8'))
    return report


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--binary', type=Path, default=TARGET)
    ap.add_argument('--output', type=Path, default=ROOT / 'work/error-str-select115')
    args = ap.parse_args()
    r = generate(args.binary, args.output)
    print(json.dumps({'owner': r['owner']['start'], 'bytes': r['owner']['bytes'],
                      'examples': len(r['examples']), 'executed': False}))
