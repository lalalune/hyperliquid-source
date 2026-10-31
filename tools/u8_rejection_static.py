#!/usr/bin/env python3
"""RE-001: selected node115 byte-fed first-value rejection; no target execution."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile
from artifacts import ROOT
from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import decode_export

TARGET = ROOT / 'artifacts/node/115/hl-node'
PACKET = ROOT / 'research/work-items/RE-001-node115-u8-rejection'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
RANGES = {'config': (0x186d0f0, 0x186d3a1), 'change': (0x18500a0, 0x18503fc),
          'enum_u8': (0x2751700, 0x2751772), 'option_u8': (0x26502f0, 0x2650362),
          'carrier': (0x18be120, 0x18be1ba), 'length': (0x17fbb40, 0x17fbb9d),
          'expect_enum': (0x2773d10, 0x2773d29), 'expect_option': (0x26a1410, 0x26a1429)}
RELATIVE = {0x643a610: 0x2773d10, 0x6436ae8: 0x26a1410,
            0x64dfed0: 0x5c4f380, 0x64df6e8: 0x141e3a0,
            0x641f450: 0x5cbd5d, 0x641f200: 0x5cb11e}
CALLS = {0x186d16c: 0x2751700, 0x18500f5: 0x26502f0,
         0x2751764: 0x18be120, 0x2650354: 0x18be120,
         0x17fbb8f: 0x18be120, 0x18500d6: 0x17fbb40}
CONTROLS = {
    0x186d0fe: '4c8b2e4d85ed74094c8b7e084d39fd7523',
    0x186d10f: '488d153a23bb04488d0d73fdba0431f6',
    0x186d12d: 'e90eeaf8ff',
    0x186d132: '48897c2408498d6d0148892e4c8b66104983fcff0f8448020000',
    0x186d151: '410fb645004989f648894c241048894e10',
    0x186d171: '0fb64424180fb67424193c090f85b4000000',
    0x186d237: '660f1044241a0f104c2428488b4c24080f114910660f114102880140887101',
    0x18500b1: '4c8b264d85e474094c8b6e084d39ec751b',
    0x18500c2: '488d7b08488d1533f1bc04488d0dbccdbc0431f6',
    0x18500dd: '4c8b7e104983ffff0f84cd020000410fb63424488d7c2410',
    0x18500fa: '0fb64424100fb66c24113c09742f',
    0x1850108: '0f104424120f104c24200f114b180f11430a88430840886b0948c70302000000',
    0x2751708: '400fb6c64889442440c644243801',
    0x2751720: '488d05d18ece03',
    0x2751736: '488b0593e7d803',
    0x2751758: '488d351bd9cffd488d542418',
    0x26502f8: '400fb6c64889442440c644243801',
    0x2650310: '488d05b967de03',
    0x2650326: '488b05a3fbe803',
    0x2650348: '488d352bed dffd488d542418'.replace(' ', ''),
    0x18be183: '488b44241048894318488b042448894308488b44240848894310',
    0x18be1a0: '4883c4185b415c415e415fc3',
    0x2773d1b: '488d35ba4905feba18000000ffe0',
    0x26a141b: '488d35b430f5fdba06000000ffe0',
}


def read(data, va, n):
    matches = [s['offset'] + va - s['address'] for s in sections(data)
               if s['type'] != 8 and s['address'] <= va and va + n <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('expected unique file-backed mapping')
    off = matches[0]
    return off, bytes(data[off:off + n])


def tag_constants(data):
    raw = read(data, 0x18be19d, 3)[1]
    if raw[:2] != b'\xc6\x03':
        raise ValueError('carrier tag-store opcode changed')
    compares = []
    for va in [0x186d17b, 0x1850104]:
        code = read(data, va, 2)[1]
        if code[0] != 0x3c:
            raise ValueError('caller comparison opcode changed')
        compares.append(code[1])
    return raw[2], compares


def constructor_graph(data):
    """A static basic-block supergraph; calls model normal fallthrough only."""
    def destination(site, opcode):
        raw = read(data, site, 2)[1]
        if raw[0] != opcode:
            raise ValueError('carrier branch opcode changed')
        return site + 2 + struct.unpack('<b', raw[1:])[0]
    edges = {0x18be120: [0x18be137, destination(0x18be135, 0x75)],
             0x18be137: [destination(0x18be143, 0xeb)],
             0x18be145: [0x18be14a, destination(0x18be148, 0x74)],
             0x18be14a: [0x18be15b, destination(0x18be159, 0x74)],
             0x18be15b: [destination(0x18be16d, 0xeb)],
             0x18be16f: [0x18be175], 0x18be175: [0x18be183],
             0x18be183: [0x18be19d], 0x18be19d: [0x18be1a0],
             0x18be1a0: [], 0x18be1ac: []}
    if any(v not in edges for vs in edges.values() for v in vs):
        raise ValueError('carrier branch leaves declared basic-block certificate')
    return edges


def has_path(edges, start, end, blocked=None):
    pending, seen = [start], set()
    while pending:
        v = pending.pop()
        if v == blocked or v in seen:
            continue
        if v == end:
            return True
        seen.add(v)
        pending.extend(edges[v])
    return False


def analyze(data):
    _, frames, _ = fde_extents(data)
    mapping = {(f['start'], f['end']): f for f in frames}
    if any(pair not in mapping for pair in RANGES.values()):
        raise ValueError('rejection scope FDE changed')
    tag, comparisons = tag_constants(data)
    if tag != 6 or comparisons != [9, 9]:
        raise ValueError('first-value rejection tag relation changed')
    graph = constructor_graph(data)
    if not has_path(graph, 0x18be120, 0x18be1a0) or has_path(graph, 0x18be120, 0x18be1a0, 0x18be19d):
        raise ValueError('normal-return path bypasses carrier tag write')
    for va, value in CONTROLS.items():
        expected = bytes.fromhex(value)
        if read(data, va, len(expected))[1] != expected:
            raise ValueError(f'rejection instruction changed at {va:#x}')
    for site, target in CALLS.items():
        raw = read(data, site, 5)[1]
        if raw[0] != 0xe8 or site + 5 + struct.unpack_from('<i', raw, 1)[0] != target:
            raise ValueError('rejection direct call changed')
    sec = next(s for s in sections(data) if s['name'] == '.rela.dyn')
    rels = {a: (i, v) for a, i, v in struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']])}
    if any(rels.get(a) != (8, v) for a, v in RELATIVE.items()):
        raise ValueError('rejection type/format relocation changed')
    literals = [(0x7c86dc, b'enum ReferenceOracleMode'), (0x5f44d6, b'option'),
                (0x44f07a, b'\x0einvalid type: \xc0\x0b, expected \xc0\0')]
    for va, text in literals:
        if read(data, va, len(text))[1] != text:
            raise ValueError('rejection expectation/template changed')
    diagnostics = []
    for slot, name in [(0x641f450, 'ReferenceOracleConfig'), (0x641f200, 'UnvalidatedReferenceOracleConfigChange')]:
        text = f'struct {name} with 5 elements'.encode()
        if read(data, slot + 8, 8)[1] != struct.pack('<Q', len(text)) or read(data, RELATIVE[slot], len(text))[1] != text:
            raise ValueError('named owner diagnostic changed')
        diagnostics.append({'slot': hex(slot), 'string_va': hex(RELATIVE[slot]), 'text': text.decode()})
    ranges = {}
    for name, (start, end) in RANGES.items():
        off, body = read(data, start, end - start)
        f, frame_raw = mapping[(start, end)], {}
        for key in ['fde', 'cie']:
            va = f[key]
            n = struct.unpack('<I', read(data, va, 4)[1])[0] + 4
            frame_raw[key] = {'va': hex(va), 'bytes_hex': read(data, va, n)[1].hex()}
        ranges[name] = {'start': hex(start), 'end': hex(end), 'file_offset': hex(off),
                        'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest(), 'frame_records': frame_raw}
    return {'target_sha256': SHA, 'ranges': ranges, 'diagnostics': diagnostics,
            'constructor_normal_return_tag': tag, 'caller_continuation_comparisons': comparisons,
            'constructor_graph': {hex(k): [hex(v) for v in values] for k, values in graph.items()},
            'carrier_store_dominates_observed_return': True,
            'relative_bindings': {hex(a): hex(v) for a, v in RELATIVE.items()},
            'instruction_controls': {hex(a): v for a, v in CONTROLS.items()},
            'direct_calls': {hex(a): hex(v) for a, v in CALLS.items()},
            'config_failure_output_byte0': 6, 'change_failure_output_word0': 2,
            'change_failure_inner_byte8': 6, 'captured_binary_executed': False,
            'limits': 'Only these two byte-fed entrypoints under valid input/output buffers and ABI-preserving normal helper returns. No general config decoder, oracle policy, all caller reachability, formatted error text, allocation/unwind/indirect closure, Rust type ABI or positive codec equivalence. No gates.'}


def generate(binary, output):
    data = binary.read_bytes()
    if len(data) != 105896032 or hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('expected pinned node115')
    report = analyze(data)
    output.mkdir(parents=True, exist_ok=True)
    frame_lines = []
    with tempfile.TemporaryDirectory() as directory:
        snapshot = Path(directory) / 'node115.elf'
        snapshot.write_bytes(data)
        frames = subprocess.check_output(['readelf', '-wf', str(snapshot)], text=True)
        for name, (start, end) in RANGES.items():
            chosen = [l for l in frames.splitlines() if f'pc={start:016x}..{end:016x}' in l]
            if len(chosen) != 1:
                raise ValueError('native rejection FDE confirmation failed')
            frame_lines.append(f'{name} {chosen[0]}')
            asm = subprocess.check_output(['objdump', '-d', '-M', 'intel', '--insn-width=16',
                                          f'--start-address={start:#x}', f'--stop-address={end:#x}', str(snapshot)], text=True)
            ins = decode_export(asm, start, end, read(data, start, end - start)[1])
            sites = {a for a in CONTROLS if start <= a < end} | {a for a in CALLS if start <= a < end}
            if not sites <= set(ins):
                raise ValueError('rejection controls must start decoded instructions')
            if name in ['carrier', 'enum_u8', 'option_u8', 'length']:
                mnemonics = {int(line.split(':', 1)[0], 16): line.split('\t')[-1].split()[0]
                             for line in asm.splitlines() if re.match(r'^\s*[0-9a-f]+:', line)}
                branches = {a for a, op in mnemonics.items() if op.startswith(('j', 'loop'))}
                returns = {a for a, op in mnemonics.items() if op.startswith('ret')}
                if name == 'carrier':
                    if branches != {0x18be135, 0x18be143, 0x18be148, 0x18be159, 0x18be16d} or returns != {0x18be1ab}:
                        raise ValueError('carrier transfer certificate changed')
                else:
                    expected_return = {'enum_u8': 0x2751771, 'option_u8': 0x2650361, 'length': 0x17fbb9c}[name]
                    calls = {a for a, op in mnemonics.items() if op == 'call'}
                    if branches or returns != {expected_return} or calls != {a for a in CALLS if start <= a < end}:
                        raise ValueError('straight-line rejection helper certificate changed')
            (output / f'{name}.objdump.txt').write_bytes(asm.replace(str(snapshot), '<authenticated-node115>').encode('utf-8'))
    (output / 'frames.txt').write_bytes(('\n'.join(frame_lines) + '\n').encode('utf-8'))
    (output / 'records.json').write_bytes((json.dumps(report, indent=2) + '\n').encode('utf-8'))
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--output', type=Path, default=ROOT / 'work/u8-rejection-115')
    args = parser.parse_args()
    report = generate(args.binary, args.output)
    print(json.dumps({'functions': len(report['ranges']), 'bytes': sum(x['bytes'] for x in report['ranges'].values()), 'executed': False}))
