#!/usr/bin/env python3
"""Offline node94 ren source-linked two-format-wrapper evidence collector."""
import argparse
import hashlib
import json
import re
import struct
import subprocess
from pathlib import Path
from artifacts import ROOT, check
from elf_index import sections

PATH_VA = 0x1f8849
SOURCE = b"/home/ubuntu/hl/code_Mainnet/base/src/ren.rs"
RANGES = ((0x13cea50, 0x13ceb5b), (0x13ceb60, 0x13cec7c))
SLOTS = (0x5666d90, 0x5666da8)


def read_va(data, va, size):
    matches = [s for s in sections(data) if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size'] and s['offset'] + va - s['address'] + size <= len(data)]
    if len(matches) != 1:
        raise ValueError("Range not uniquely file backed")
    off = matches[0]['offset'] + va - matches[0]['address']
    return off, data[off:off + size]


def relocations(data):
    result = {}
    for sec in sections(data):
        if sec['type'] != 4:
            continue
        if sec['size'] % 24 or sec['offset'] + sec['size'] > len(data):
            raise ValueError("Invalid RELA section extent")
        for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, off)
            if slot in result:
                raise ValueError("Duplicate relocation")
            result[slot] = (info, addend)
    return result


def rip(data, start, off, prefix, length):
    insn = read_va(data, start + off, length)[1]
    if insn[:len(prefix)] != prefix:
        raise ValueError("Instruction encoding changed")
    return start + off + length + struct.unpack_from('<i', insn, len(prefix))[0]


def validate(data, fdes):
    if read_va(data, PATH_VA, len(SOURCE))[1] != SOURCE:
        raise ValueError("Source path changed")
    relas = relocations(data)
    rows = []
    specs = [
        (0x13cea50, 0x13ceb5b, 0x5666d90, 206, 0x3b, 0x1dd419, bytes.fromhex('c0023a20c000'), 0x47, 0x4d),
        (0x13ceb60, 0x13cec7c, 0x5666da8, 259, 0x4c, 0x1f4d9e, bytes.fromhex('c0022c20c0023a20c000'), 0x58, 0x5e),
    ]
    for start, end, slot, line, source_off, desc, descriptor, calloff, trapoff in specs:
        if fdes.count((start, end)) != 1:
            raise ValueError("Selected FDE missing or duplicate")
        location = read_va(data, slot, 24)[1]
        if struct.unpack('<QQII', location) != (0, len(SOURCE), line, 21) or relas.get(slot) != (8, PATH_VA):
            raise ValueError("Source Location binding changed")
        if rip(data, start, source_off, b'\x48\x8d\x15', 7) != slot:
            raise ValueError("Location LEA changed")
        if rip(data, start, source_off - 7, b'\x48\x8d\x3d', 7) != desc or read_va(data, desc, len(descriptor))[1] != descriptor:
            raise ValueError("Format descriptor changed")
        if rip(data, start, calloff, b'\xff\x15', 6) != 0x576e098:
            raise ValueError("Formatting call slot changed")
        if read_va(data, start + trapoff, 2)[1] != b'\x0f\x0b':
            raise ValueError("Nonreturning fallthrough changed")
        # Both cleanup landing pads discriminate the low two bits against tag 1.
        tagoff = trapoff + 11
        if read_va(data, start + tagoff, 8)[1] != bytes.fromhex('83e10383f9017408'):
            raise ValueError("Cleanup tag predicate changed")
        # Decode the stack-built callback pairs and captured operands. This
        # distinguishes one callback argument from two, without assigning Rust types.
        callback_specs = [(0x14, 0x13d94b0)] if start == 0x13cea50 else [(0x14, 0x13e28a0), (0x25, 0x13e27c0)]
        callbacks = [hex(rip(data, start, pos, b'\x48\x8d\x05', 7)) for pos, _ in callback_specs]
        if callbacks != [hex(target) for _, target in callback_specs]:
            raise ValueError("Callback address changed")
        stores = [(0xb, '4889342448897c2408'), (0x1b, '48894424104889e04889442418'), (0x2f, '4889442420')] if start == 0x13cea50 else [(0xb, '4889142448897c2408'), (0x1b, '48894424104889742418'), (0x2c, '48894424204889e04889442428'), (0x40, '4889442430')]
        for pos, encoded in stores:
            expected = bytes.fromhex(encoded)
            if read_va(data, start + pos, len(expected))[1] != expected:
                raise ValueError("Argument pair layout changed")
        slot_load = 0x28 if start == 0x13cea50 else 0x39
        if rip(data, start, slot_load, b'\x48\x8b\x05', 7) != 0x576ea70:
            raise ValueError("Shared callback slot load changed")
        # Normal cleanup continuation enters shared unwinder, while tag 1 enters
        # a payload/vtable path. Check the payload/vtable loads and indirect drop.
        payload_off = trapoff + 0x1b
        payload = read_va(data, start + payload_off, 26)[1]
        if payload != bytes.fromhex('488d58ff4c8b78ff4c8b6007498b04244885c074054c89ffffd0'):
            raise ValueError("Tagged payload cleanup changed")
        resume = rip(data, start, trapoff + 0x16, b'\xe8', 5)
        if resume != 0x5660110:
            raise ValueError("Unwind continuation changed")
        off, body = read_va(data, start, end - start)
        rows.append({'start_va': hex(start), 'end_va_exclusive': hex(end), 'file_offset': hex(off), 'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest(), 'body_hex': body.hex(), 'callback_addresses': callbacks, 'callback_pairs': len(callbacks), 'cleanup_payload_va': hex(start + payload_off), 'unwind_resume_plt': hex(resume), 'location_record_hex': location.hex(), 'source_location_va': hex(slot), 'source_line': line, 'source_column': 21, 'descriptor_va': hex(desc), 'descriptor_hex': descriptor.hex(), 'format_call_va': hex(start + calloff), 'format_call_slot': '0x576e098', 'trap_va': hex(start + trapoff), 'cleanup_tag_test_va': hex(start + tagoff)})
    expected_relas = {0x576e098: (8,0x157b810), 0x576ea70: (8,0x4f0d950), 0x576e010: (8,0x54c8cb0), 0x576ea78: (8,0x14bf1b0), 0x576e128: (8,0x157b63b)}
    if any(relas.get(slot) != value for slot,value in expected_relas.items()):
        raise ValueError("Selected callback/call relocation changed")
    wanted = set(SLOTS) | {0x576e098, 0x576ea70, 0x576e010, 0x576ea78, 0x576e128}
    selected = {hex(s): {'info': relas[s][0], 'addend': hex(relas[s][1])} for s in sorted(wanted) if s in relas}
    if len(selected) != len(wanted):
        raise ValueError("Missing referenced call relocation")
    callers = []
    for site, target in ((0x13ce25b, 0x13cea50), (0x13ce96a, 0x13ceb60)):
        if rip(data, site, 0, b'\xe8', 5) != target:
            raise ValueError("Observed caller changed")
        containing = [(a,b) for a,b in fdes if a <= site < b]
        # Unit tests may supply only selected wrapper FDEs; production supplies all.
        callers.append({'site_va': hex(site), 'target_va': hex(target), 'containing_fdes': [[hex(a),hex(b)] for a,b in containing], 'instruction_hex': read_va(data,site,5)[1].hex()})
    return {'ranges': rows, 'relocations': selected, 'observed_callers_not_census': callers}


def generate(binary, output):
    identity = next(x for x in json.loads((ROOT/'provenance/artifacts.json').read_text())['files'] if x['path'] == 'artifacts/node/94/hl-node')
    check(binary, identity)
    data = binary.read_bytes()
    frames = subprocess.check_output(['readelf', '-wf', str(binary)], text=True)
    fdes = [(int(a, 16), int(b, 16)) for a, b in re.findall(r'FDE[^\n]*pc=([0-9a-f]+)\.\.([0-9a-f]+)', frames)]
    result = validate(data, fdes)
    output.mkdir(parents=True, exist_ok=True)
    assembly = []
    for a, b in RANGES:
        assembly.append(subprocess.check_output(['objdump', '-d', f'--start-address={a:#x}', f'--stop-address={b:#x}', str(binary)], text=True).replace(str(binary), '<authenticated-node94>'))
    # Two observed call sites only; this is deliberately not a caller census.
    for a, b in ((0x13ce24e, 0x13ce260), (0x13ce95b, 0x13ce96f)):
        assembly.append(subprocess.check_output(['objdump', '-d', f'--start-address={a:#x}', f'--stop-address={b:#x}', str(binary)], text=True).replace(str(binary), '<authenticated-node94>'))
    (output/'wrappers.objdump.txt').write_text('\n'.join(assembly))
    (output/'frames.txt').write_text('\n\n'.join(block for block in frames.split('\n\n') if any(f'pc={a:016x}..{b:016x}' in block for a,b in RANGES)) + '\n')
    relas = subprocess.check_output(['readelf', '-rW', str(binary)], text=True)
    (output/'relocations.txt').write_text('\n'.join(line for line in relas.splitlines() if re.match(r'^[0-9a-f]+\s', line) and hex(int(line.split()[0],16)) in result['relocations']) + '\n')
    result.update({'target_sha256': identity['sha256'], 'target_bytes': len(data), 'selected_windows': 2, 'selected_bytes': sum(r['bytes'] for r in result['ranges']), 'fde_records_parsed': len(fdes), 'captured_binary_executed': False, 'source_path_va': hex(PATH_VA), 'scope': 'Two FDE-described nonreturning formatting wrappers; source identity is a relocated Location, names and types remain inferred. No whole-component or equivalence claim.'})
    (output/'records.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT/'artifacts/node/94/hl-node')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = generate(args.binary, args.output)
    print(json.dumps({'selected_windows': result['selected_windows'], 'selected_bytes': result['selected_bytes']}))

if __name__ == '__main__':
    main()
