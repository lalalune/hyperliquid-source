#!/usr/bin/env python3
"""RE-003: a static three-byte fixture certificate, never captured-code execution."""
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
PACKET = ROOT / 'research/work-items/RE-003-node115-priority-prefix'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
OWNERS = [(0x1839480, 0x1839913, 0x641eec0),
          (0x2fbf570, 0x2fbfa03, 0x64644c0),
          (0x48117a0, 0x4811c33, 0x64998d8)]
PREFIX_SIZE = 0x169
PREFIX_SHA = 'b4091a331954a0ae3179501a2950606f7214e9df48ae684be0062a652f0913c2'
EPILOGUE = bytes.fromhex('4883c4485b415c415d415e415f5dc3')
BRANCHES = {0x14: (0x84, 0x169), 0x21: (0x84, 0x169),
            0x36: (0x84, 0x486), 0x79: (0x84, 0x188),
            0x82: (0x84, 0x1ce), 0x93: (0x84, 0x486),
            0xcc: (0x84, 0x1e7), 0xd5: (0x84, 0x235),
            0xe6: (0x84, 0x486), 0xfc: (0x85, 0x26d),
            0x11b: (0x85, 0x31b), 0x127: (0x85, 0x38c)}


def read(data, va, n):
    matches = [s for s in sections(data) if s['type'] != 8
               and s['address'] <= va and va + n <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('expected one file-backed mapping')
    s = matches[0]
    off = s['offset'] + va - s['address']
    return off, bytes(data[off:off+n])


def numeric_certificate(prefix):
    """Algebra on the two captured bit tests, not an instruction interpreter."""
    addend = struct.unpack_from('<Q', prefix, 0x53)[0]
    gates = []
    for shift_offset, threshold_offset in [(0x62, 0x65), (0xb5, 0xb8)]:
        shift = prefix[shift_offset]
        threshold = struct.unpack_from('<I', prefix, threshold_offset)[0]
        accepted = []
        for value in range(256):
            # CVTSI2SD of these zero-extended u8s is exact binary64.
            bits = struct.unpack('<Q', struct.pack('<d', value))[0]
            shifted = ((bits + addend) & ((1 << 64) - 1)) >> shift
            if ((bits >> 63 == 0) and shifted < threshold) or bits == 0:
                accepted.append(value)
        gates.append({'addend': hex(addend), 'shift': shift, 'threshold': threshold,
                      'accepted_u8': accepted})
    return gates


def transfer_certificate(prefix):
    edges = {}
    for site, (opcode, _) in BRANCHES.items():
        raw = prefix[site:site+6]
        if raw[:2] != bytes([0x0f, opcode]):
            raise ValueError('prefix conditional opcode changed')
        edges[site] = site + 6 + struct.unpack_from('<i', raw, 2)[0]
    if prefix[0x164] != 0xe9:
        raise ValueError('prefix epilogue jump opcode changed')
    edges[0x164] = 0x169 + struct.unpack_from('<i', prefix, 0x165)[0]
    return edges


def analyze(data):
    _, fs, _ = fde_extents(data)
    frames = {(f['start'], f['end']): f for f in fs}
    relsec = next(s for s in sections(data) if s['name'] == '.rela.dyn')
    rels = {a: (i, v) for a, i, v in struct.iter_unpack('<QQq', data[relsec['offset']:relsec['offset']+relsec['size']])}
    owners = []
    text = b'struct PriorityRateDelayParams with 6 elements'
    for start, end, slot in OWNERS:
        if (start, end) not in frames:
            raise ValueError('priority prefix FDE changed')
        off, body = read(data, start, end-start)
        prefix = body[:PREFIX_SIZE]
        gates = numeric_certificate(prefix)
        if any(g['accepted_u8'] != list(range(256)) for g in gates):
            raise ValueError('numeric gate excludes a u8 value')
        edges = transfer_certificate(prefix)
        if edges != {**{s: d for s, (_, d) in BRANCHES.items()}, 0x164: 0x25e}:
            raise ValueError('prefix transfer destination changed')
        if hashlib.sha256(prefix).hexdigest() != PREFIX_SHA or body[0x25e:0x26d] != EPILOGUE:
            raise ValueError('prefix dataflow or epilogue changed')
        info, string_va = rels.get(slot, (None, None))
        if info != 8 or read(data, slot+8, 8)[1] != struct.pack('<Q', len(text)) or read(data, string_va, len(text))[1] != text:
            raise ValueError('priority diagnostic relocation/text changed')
        # Three different missing-prefix branches bind the same diagnostic.
        diagnostic_leas = []
        for relative in [0x16d, 0x1d2, 0x239]:
            code = body[relative:relative+7]
            if code[:3] != b'\x48\x8d\x15' or start+relative+7+struct.unpack_from('<i',code,3)[0] != slot:
                raise ValueError('priority diagnostic LEA changed')
            diagnostic_leas.append(hex(start+relative))
        raw_frames = {}
        for kind in ['fde', 'cie']:
            va = frames[(start, end)][kind]
            n = struct.unpack('<I', read(data, va, 4)[1])[0] + 4
            raw_frames[kind] = {'va': hex(va), 'bytes_hex': read(data, va, n)[1].hex()}
        owners.append({'start': hex(start), 'end': hex(end), 'file_offset': hex(off),
                       'bytes': len(body), 'body_sha256': hashlib.sha256(body).hexdigest(),
                       'diagnostic_slot': hex(slot), 'diagnostic_string_va': hex(string_va),
                       'diagnostic_leas': diagnostic_leas, 'frames': raw_frames,
                       'numeric_gates': [{k:v for k,v in g.items() if k != 'accepted_u8'} | {'accepted_u8_count':len(g['accepted_u8']), 'accepted_u8_range':[0,255]} for g in gates], 'transfers_relative_to_start': {hex(a):hex(b) for a,b in edges.items()}})
    return {'target_sha256': SHA, 'owners': owners, 'prefix_sha256': PREFIX_SHA,
            'input_form': 'non-null cursor p; end p+3; finite item counter <= u64::MAX-3; valid nonaliasing buffers',
            'number_of_three_u8_value_combinations': 256**3,
            'defined_output': {'qword+0x0': 0, 'qword+0x10': 0, 'byte+0x38': 0,
                               'f64+0x20': 'first u8', 'f64+0x28': 'second u8', 'f64+0x30': 'third u8'},
            'unspecified_output': ['+0x8..+0xf (incoming XMM4 low bits)', '+0x18..+0x1f (incoming XMM0 low bits)', 'padding/other bytes'],
            'incoming_state_after_local_path': 'cursor p+3; counter c+3',
            'calls_on_certified_path': 0, 'captured_code_executed': False,
            'limits': 'Static normal local path only. No Rust type/Option ABI, wire codec, semantic field names, API acceptance, caller reachability, general suffix/default/helper behavior, clone identity outside measured ranges, or progress gate.'}


def generate(binary, output):
    data = binary.read_bytes()
    if len(data) != 105896032 or hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('expected pinned node115')
    report = analyze(data)
    output.mkdir(parents=True, exist_ok=True)
    lines = []
    with tempfile.TemporaryDirectory() as directory:
        snap = Path(directory) / 'node115.elf'
        snap.write_bytes(data)
        frames = subprocess.check_output(['readelf', '-wf', str(snap)], text=True)
        for start, end, slot in OWNERS:
            matched = [l for l in frames.splitlines() if f'pc={start:016x}..{end:016x}' in l]
            if len(matched) != 1:
                raise ValueError('native priority FDE disagreement')
            lines.extend(matched)
            asm = subprocess.check_output(['objdump','-d','-M','intel','--insn-width=16', f'--start-address={start:#x}',f'--stop-address={end:#x}',str(snap)],text=True)
            ins = decode_export(asm, start, end, read(data,start,end-start)[1])
            observed = {}
            for line in asm.splitlines():
                if re.match(r'^\s*[0-9a-f]+:', line):
                    at = int(line.split(':',1)[0],16)
                    observed[at-start] = line.split('\t')[-1].split()[0]
            prefix_transfers = {a for a,op in observed.items() if a<PREFIX_SIZE and op.startswith(('j','loop','call','ret'))}
            if prefix_transfers != set(BRANCHES) | {0x164} or observed.get(0x26c) != 'ret':
                raise ValueError('native prefix transfer set changed')
            if not {start+0x16d,start+0x1d2,start+0x239,start+0x25e} <= set(ins):
                raise ValueError('priority evidence boundary disagreement')
            (output/f'{start:x}.objdump.txt').write_bytes(asm.replace(str(snap),'<authenticated-node115>').encode('utf-8'))
    (output/'frames.txt').write_bytes(('\n'.join(lines)+'\n').encode('utf-8'))
    (output/'records.json').write_bytes((json.dumps(report,indent=2)+'\n').encode('utf-8'))
    return report


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,default=TARGET)
    p.add_argument('--output',type=Path,default=ROOT/'work/priority-prefix115')
    args=p.parse_args()
    result=generate(args.binary,args.output)
    print(json.dumps({'owners':len(result['owners']), 'certified_input_value_combinations':256**3, 'executed':False}))
