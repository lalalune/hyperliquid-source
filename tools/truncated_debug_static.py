#!/usr/bin/env python3
"""Authenticated node94 source-location-linked truncated-debug guard census."""
import argparse
import bisect
import hashlib
import json
import re
import struct
import subprocess
from pathlib import Path
from artifacts import ROOT, check
from elf_index import sections

PATH_VA = 0x201a1a
SOURCE = b'/home/ubuntu/hl/code_Mainnet/base/src/truncated_debug.rs'
SLOTS = (0x566a630, 0x56bcf10, 0x56f1710, 0x57189a8, 0x572aa50)
PROFILES = {
    'bf-jle': bytes.fromhex('4881fe10270000764e488b7c241880bf10270000bf0f8e86000000'),
    'c0-jl': bytes.fromhex('4881fe10270000764e488b7c241880bf10270000c00f8c86000000'),
}

def read_va(data, va, size):
    matches = [s for s in sections(data) if s['type'] != 8 and s['address'] <= va and va+size <= s['address']+s['size']]
    if len(matches) != 1:
        raise ValueError('Ambiguous file-backed VA')
    off = matches[0]['offset']+va-matches[0]['address']
    return off, data[off:off+size]

def source_bindings(data):
    if read_va(data, PATH_VA, len(SOURCE))[1] != SOURCE:
        raise ValueError('Source path changed')
    found = {}
    for sec in sections(data):
        if sec['type'] != 4:
            continue
        for off in range(sec['offset'], sec['offset']+sec['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, off)
            if slot in SLOTS:
                if info != 8 or addend != PATH_VA:
                    raise ValueError('Source relocation changed')
                found[slot] = {'slot_va': hex(slot), 'addend': hex(addend), 'info': info}
    if set(found) != set(SLOTS):
        raise ValueError('Missing source relocation')
    return [found[s] for s in SLOTS]

def profile(body):
    names = [name for name, expected in PROFILES.items() if body[0x37:0x52] == expected]
    if len(body) != 272 or len(names) != 1:
        raise ValueError('Guard profile changed')
    if body[0x57:0x60] != bytes.fromhex('48c744243010270000'):
        raise ValueError('Prefix length changed')
    if body[0xdf:0xe6] != bytes.fromhex('b91027000031d2') or body[0xec:0xee] != b'\x0f\x0b':
        raise ValueError('Failure argument or terminator changed')
    return names[0]

def rip_target(body, start, off, prefix, length):
    if body[off:off+len(prefix)] != prefix:
        raise ValueError('RIP-relative instruction changed')
    return start+off+length+struct.unpack_from('<i', body, off+len(prefix))[0]

def census(data, fdes):
    # Scan every byte of .text for this exact RIP-relative LEA encoding. Raw
    # candidates are then tied to a unique FDE and checked as decoded instructions.
    text = next((s for s in sections(data) if s['name'] == '.text'), None)
    if text is None:
        raise ValueError('No .text section')
    raw = data[text['offset']:text['offset']+text['size']]
    ordered = sorted(fdes)
    starts = [a for a, b in ordered]
    rows = []
    for match in re.finditer(rb'(?=([\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d].{4}))', raw, re.S):
        insn = match.group(1)
        site = text['address']+match.start()
        slot = site+7+struct.unpack_from('<i', insn, 3)[0]
        if slot not in SLOTS:
            continue
        index = bisect.bisect_right(starts, site)-1
        if index < 0 or not ordered[index][0] <= site < ordered[index][1]:
            raise ValueError('Source xref outside an FDE')
        start, end = ordered[index]
        if site != start+0xd8:
            raise ValueError('Unexpected source-location position')
        fileoff, body = read_va(data, start, end-start)
        kind = profile(body)
        if rip_target(body, start, 0xd8, b'\x4c\x8d\x05', 7) != slot:
            raise ValueError('Source instruction changed')
        calls = {}
        for off, expected in [(0x2c,0x576e040),(0x86,0x576e008),(0xaf,0x576e008),(0xe6,0x576e070)]:
            target = rip_target(body,start,off,b'\xff\x15',6)
            if target != expected:
                raise ValueError('Formatter/failure call slot changed')
            calls[hex(start+off)] = hex(target)
        descriptor = rip_target(body,start,0x7c,b'\x48\x8d\x15',7)
        if descriptor != 0x201a53 or read_va(data, descriptor, 8)[1] != bytes.fromhex('c0055b2e2e2e5d00'):
            raise ValueError('Compact descriptor changed')
        rows.append({'start_va':hex(start),'end_va':hex(end),'file_offset':hex(fileoff),'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest(),'guard_profile':kind,'source_slot':hex(slot),'source_xref':hex(site),'call_slots':calls,'generic_formatter_callback':hex(rip_target(body,start,0xe,b'\x48\x8d\x05',7)),'body_hex':body.hex()})
    if len(rows) != 66 or len({r['start_va'] for r in rows}) != 66:
        raise ValueError('Source-linked family census changed')
    return rows

def rejects_boundary_byte(value, kind):
    """Architectural signed-byte predicate only; not a UTF-8 validator."""
    signed = value if value < 128 else value-256
    return signed <= -65 if kind == 'bf-jle' else signed < -64

def generate(binary, output):
    identity = next(i for i in json.loads((ROOT/'provenance/artifacts.json').read_text())['files'] if i['path']=='artifacts/node/94/hl-node')
    check(binary,identity)
    data = binary.read_bytes()
    bindings = source_bindings(data)
    frames = subprocess.check_output(['readelf','-wf',str(binary)],text=True)
    fdes = [(int(a,16),int(b,16)) for a,b in re.findall(r'FDE[^\n]*pc=([0-9a-f]+)\.\.([0-9a-f]+)',frames)]
    rows = census(data,fdes)
    output.mkdir(parents=True,exist_ok=True)
    raw = []
    for row in rows:
        start,end = int(row['start_va'],16),int(row['end_va'],16)
        disasm = subprocess.check_output(['objdump','-d',f'--start-address={start:#x}',f'--stop-address={end:#x}',str(binary)],text=True)
        site = int(row['source_xref'],16)
        if not re.search(rf'^\s*{site:x}:\s+4c 8d 05 .*\blea\b',disasm,re.M):
            raise ValueError('Candidate source LEA is not decoded instruction')
        raw.append(disasm.replace(str(binary),'<authenticated-node94>'))
    (output/'family.objdump.txt').write_text('\n'.join(raw))
    selected = {(int(r['start_va'],16),int(r['end_va'],16)) for r in rows}
    (output/'frames.txt').write_text('\n'.join(line for line in frames.splitlines() if any(f'pc={a:016x}..{b:016x}' in line for a,b in selected))+'\n')
    relas = subprocess.check_output(['readelf','-rW',str(binary)],text=True)
    wanted = set(SLOTS)|{0x576e040,0x576e008,0x576e070}
    (output/'relocations.txt').write_text('\n'.join(line for line in relas.splitlines() if re.match(r'^[0-9a-f]+\s',line) and int(line.split()[0],16) in wanted)+'\n')
    result = {'target_sha256':identity['sha256'],'target_bytes':len(data),'fde_records_parsed':len(fdes),'census_scope':'Every .text byte for RIP-relative 64-bit LEAs to these five source Location slots, validated as instructions within FDEs; not all functions or all possible source references.','family_bytes':sum(r['bytes'] for r in rows),'profiles':{kind:sum(r['guard_profile']==kind for r in rows) for kind in PROFILES},'source_bindings':bindings,'ranges':rows,'captured_binary_executed':False,'limits':'Local branch/prefix evidence, not complete UTF-8 validation, target input reachability, exact formatted output, formatter/helper closure, runtime equivalence or component completion.'}
    (output/'records.json').write_text(json.dumps(result,indent=2)+'\n')
    return result

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,default=ROOT/'artifacts/node/94/hl-node')
    parser.add_argument('--output',type=Path,default=ROOT/'work/truncated-debug-94')
    args = parser.parse_args()
    result = generate(args.binary.resolve(),args.output)
    print(json.dumps({k:v for k,v in result.items() if k!='ranges'},indent=2))
