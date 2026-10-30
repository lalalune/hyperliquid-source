#!/usr/bin/env python3
"""Digest-bound node94 compact-string LSDA/call map; no target execution."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile

from artifacts import ROOT
from elf_index import sections
from fde_extents import eh_frame_records, sleb, uleb
from short_string_static import read_va

SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BEGIN, END = 0x1449A80, 0x144A009
LOCATION, SOURCE = 0x566A990, 0x1EA56A
SOURCE_BYTES = b'/home/ubuntu/hl/code_Mainnet/base/src/short_string.rs'
RESUME_CALL = 0x1449FED


def decode_lines(text):
    records = {}
    for line in text.splitlines():
        match = re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)\s*(\S.*)', line)
        if match:
            va = int(match[1], 16)
            if va in records:
                raise ValueError('Duplicate native instruction address')
            records[va] = (bytes.fromhex(match[2]), match[3].strip())
    return records


def join_lock_prefixes(records):
    """LLVM17 prints LOCK separately; retain every byte when joining it.

    Only the two observed REX.W CMPXCHG/XADD forms are accepted. This is a
    display-record join, not an operand mask or a machine-code change.
    """
    joined, prefixes, consumed = {}, [], set()
    for va, (body, asm) in records.items():
        if va in consumed:
            continue
        if body == b'\xf0' and asm == 'lock':
            following = records.get(va+1)
            if following is None or following[0][:3] not in (b'\x48\x0f\xb1', b'\x48\x0f\xc1'):
                raise ValueError('Unsupported or orphan standalone LOCK prefix')
            joined[va] = (body+following[0], 'lock '+following[1])
            consumed.add(va+1)
            prefixes.append(hex(va))
        else:
            joined[va] = (body, asm)
    return joined, prefixes


def gnu_disassemble(binary, data):
    common = [f'--start-address={BEGIN:#x}', f'--stop-address={END:#x}', str(binary)]
    gnu = subprocess.check_output(['objdump', '-d', '--insn-width=16', *common], text=True)
    one = decode_lines(gnu)
    cursor = BEGIN
    for va, (body, _) in one.items():
        if va != cursor or body != read_va(data, va, len(body))[1]:
            raise ValueError('Incomplete or non-target constructor decode')
        cursor += len(body)
    if cursor != END:
        raise ValueError('Constructor decode does not reach FDE end')
    return one, gnu.replace(str(binary), '<authenticated-node94>')


def disassemble(binary, data):
    one, gnu = gnu_disassemble(binary, data)
    llvm = subprocess.check_output([os.environ.get('LLVM_OBJDUMP', 'llvm-objdump'), '-d',
                                    f'--start-address={BEGIN:#x}', f'--stop-address={END:#x}',
                                    str(binary)], text=True)
    two, prefixes = join_lock_prefixes(decode_lines(llvm))
    if {v: b for v, (b, _) in one.items()} != {v: b for v, (b, _) in two.items()}:
        raise ValueError('Native instruction boundary/byte disagreement')
    return one, {'constructor.gnu.txt':gnu,
                 'constructor.llvm.txt':llvm.replace(str(binary), '<authenticated-node94>')}, prefixes


def call_target(va, body):
    if len(body) == 5 and body[0] == 0xE8:
        return 'direct', va+5+struct.unpack_from('<i', body, 1)[0]
    if len(body) == 6 and body[:2] == b'\xff\x15':
        return 'rip-slot', va+6+struct.unpack_from('<i', body, 2)[0]
    return 'register-indirect', None


def relocation(data, secs, slot):
    matches = []
    for section in secs:
        if section['type'] == 4:
            for p in range(section['offset'], section['offset']+section['size'], 24):
                address, info, addend = struct.unpack_from('<QQq', data, p)
                if address == slot:
                    matches.append((info, addend))
    if len(matches) != 1:
        raise ValueError('Expected one relocation for selected slot')
    info, addend = matches[0]
    result = {'slot_va': hex(slot), 'type': info & 0xFFFFFFFF, 'addend': hex(addend)}
    symbol = info >> 32
    if symbol:
        names = {s['name']: s for s in secs}
        symtab, strings = names['.dynsym'], names['.dynstr']
        shoff = struct.unpack_from('<Q', data, 40)[0]
        stride = struct.unpack_from('<H', data, 58)[0]
        index_in_sections = next(i for i, s in enumerate(secs) if s['name'] == '.dynsym')
        entry_size = struct.unpack_from('<Q', data, shoff+stride*index_in_sections+56)[0]
        if entry_size != 24 or symbol*24+24 > symtab['size']:
            raise ValueError('Selected dynamic symbol is out of bounds')
        index = struct.unpack_from('<I', data, symtab['offset']+symbol*24)[0]
        if index >= strings['size']:
            raise ValueError('Selected dynamic name is out of bounds')
        start = strings['offset']+index
        end = data.find(b'\0', start, strings['offset']+strings['size'])
        if end < 0:
            raise ValueError('Unterminated selected dynamic name')
        result['symbol'] = data[start:end].decode('ascii')
    return result


def lsda_table(data, fde, upper, instruction_starts):
    """Only this target's omit/indirect-pcrel-sdata4/ULEB call-site format.

    `upper` is the next LSDA pointer, an upper bound, not an asserted object
    size. Action chains are decoded as signed fields; type/filter semantics
    and personality execution are deliberately not implemented.
    """
    address = fde['lsda']
    offset, raw = read_va(data, address, upper-address)
    if len(raw) < 5 or raw[0:2] != b'\xff\x9b':
        raise ValueError('Unsupported LPStart/type-table encoding')
    type_distance, p = uleb(raw, 2, len(raw))
    type_base = p+type_distance
    if type_base > len(raw):
        raise ValueError('Type-table base outside LSDA upper bound')
    if p >= len(raw) or raw[p] != 1:
        raise ValueError('Unsupported call-site encoding')
    p += 1
    length, p = uleb(raw, p, len(raw))
    table_end = p+length
    if table_end > type_base:
        raise ValueError('Call-site table overlaps type-table base')
    rows, previous_end = [], BEGIN
    while p < table_end:
        fields, positions = [], []
        for _ in range(4):
            positions.append(p)
            value, p = uleb(raw, p, table_end)
            fields.append(value)
        start, size, pad, action = fields
        start, end = BEGIN+start, BEGIN+start+size
        landing = BEGIN+pad if pad else None
        if not BEGIN <= start < end <= END or start < previous_end:
            raise ValueError('Invalid or overlapping call-site extent')
        if start not in instruction_starts or (end != END and end not in instruction_starts):
            raise ValueError('Call-site boundary is inside an instruction')
        if landing is not None and landing not in instruction_starts:
            raise ValueError('Landing pad is not a decoded instruction start')
        previous_end = end
        chain, seen = [], set()
        a = table_end+action-1 if action else None
        while a is not None:
            if not table_end <= a < type_base or a in seen:
                raise ValueError('Action chain escapes or cycles')
            seen.add(a)
            filter_value, displacement_pos = sleb(raw, a, type_base)
            displacement, after = sleb(raw, displacement_pos, type_base)
            chain.append({'va': hex(address+a), 'filter': filter_value,
                          'next_displacement': displacement,
                          'bytes': raw[a:after].hex()})
            a = displacement_pos+displacement if displacement else None
        rows.append({'start_va': hex(start), 'end_va': hex(end),
                     'landing_pad_va': hex(landing) if landing else None,
                     'action_index': action, 'action_chain': chain,
                     'field_lsda_offsets': positions})
    return {'va': hex(address), 'file_offset': hex(offset),
            'upper_bound_va': hex(upper), 'upper_bound_is_object_size': False,
            'bytes_through_upper_bound': raw.hex(), 'type_table_base_va': hex(address+type_base),
            'call_site_encoding': 'DW_EH_PE_uleb128', 'call_site_bytes': length,
            'action_table_va': hex(address+table_end), 'rows': rows}


def analyse(data, instructions):
    secs = sections(data)
    cies, fdes = eh_frame_records(data, secs)
    owners = [f for f in fdes if (f['start'], f['end']) == (BEGIN, END)]
    if len(owners) != 1:
        raise ValueError('Expected one exact constructor FDE')
    fde = owners[0]
    cie = cies[fde['cie']]
    table = next(s for s in secs if s['name'] == '.gcc_except_table')
    if not table['address'] <= fde['lsda'] < table['address']+table['size']:
        raise ValueError('Selected LSDA is not in .gcc_except_table')
    upper = min([f['lsda'] for f in fdes if f['lsda'] and fde['lsda'] < f['lsda'] < table['address']+table['size']]
                + [table['address']+table['size']])
    lsda = lsda_table(data, fde, upper, set(instructions))
    personality = relocation(data, secs, cie['personality_slot'])
    if personality['type'] != 8 or 'symbol' in personality:
        raise ValueError('Expected local personality relocation')
    targets = [f for f in fdes if f['start'] == int(personality['addend'], 16)]
    if len(targets) != 1:
        raise ValueError('Personality target is not one FDE start')
    location = relocation(data, secs, LOCATION)
    if location != {'slot_va': hex(LOCATION), 'type': 8, 'addend': hex(SOURCE)}:
        raise ValueError('Source Location relocation changed')
    source_length = struct.unpack('<Q', read_va(data, LOCATION+8, 8)[1])[0]
    if source_length != len(SOURCE_BYTES) or read_va(data, SOURCE, source_length)[1] != SOURCE_BYTES:
        raise ValueError('Source path binding changed')
    at = 0x1449F8F
    lea = instructions[at][0]
    if lea[:3] != b'\x48\x8d\x3d' or at+7+struct.unpack_from('<i', lea, 3)[0] != LOCATION:
        raise ValueError('Constructor does not reference source Location')
    body = instructions[RESUME_CALL][0]
    kind, plt = call_target(RESUME_CALL, body)
    if kind != 'direct':
        raise ValueError('Expected direct resume call')
    stub = read_va(data, plt, 6)[1]
    if stub[:2] != b'\xff\x25':
        raise ValueError('Resume PLT stub is not a RIP jump')
    slot = plt+6+struct.unpack_from('<i', stub, 2)[0]
    resume = relocation(data, secs, slot)
    if resume['type'] != 7 or resume.get('symbol') != '_Unwind_Resume' or int(resume['addend'], 16):
        raise ValueError('PLT slot does not bind _Unwind_Resume')
    calls = []
    for va, (body, asm) in instructions.items():
        if not re.match(r'call\w*\s', asm):
            continue
        matches = [i for i, r in enumerate(lsda['rows']) if
                   int(r['start_va'], 16) <= va+len(body)-1 < int(r['end_va'], 16)]
        if len(matches) > 1:
            raise ValueError('Call is covered by overlapping rows')
        kind, target = call_target(va, body)
        calls.append({'site_va': hex(va), 'bytes': body.hex(), 'return_pc_minus_one': hex(va+len(body)-1),
                      'kind': kind, 'target_or_slot_va': hex(target) if target else None,
                      'lsda_row': matches[0] if matches else None})
    offset, raw = read_va(data, BEGIN, END-BEGIN)
    return {'target_sha256': hashlib.sha256(data).hexdigest(), 'target_bytes':len(data),
            'fde': {k:hex(v) for k, v in fde.items()},
            'constructor_file_offset': hex(offset), 'constructor_bytes': len(raw),
            'constructor_sha256': hashlib.sha256(raw).hexdigest(),
            'decoded_constructor_instructions': len(instructions),
            'cie': cie, 'personality_binding': personality,
            'opaque_personality_fde': {k:hex(v) if v is not None else None for k, v in targets[0].items()},
            'source_location_binding': location, 'source_path': SOURCE_BYTES.decode(),
            'lsda': lsda, 'calls': calls,
            'resume_binding': {'call_va':hex(RESUME_CALL), 'plt_va':hex(plt), 'plt_bytes':stub.hex(), **resume},
            'denominator': {'constructor_fdes':1, 'call_site_intervals':len(lsda['rows']),
                            'distinct_landing_pads':len({r['landing_pad_va'] for r in lsda['rows'] if r['landing_pad_va']}),
                            'decoded_calls':len(calls),
                            'calls_with_table_entry':sum(c['lsda_row'] is not None for c in calls)},
            'captured_executable_launched':False,
            'limits':'Static metadata and decoded-call association only. Personality, type-filter semantics, cleanup helpers and runtime paths are not executed or recovered. No whole-crate panic flag, panic handler, Rust build, equivalence or gate claim.'}


def collect_native(binary, data):
    code, raw, prefixes = disassemble(binary, data)
    result = analyse(data, code)
    raw['decoder-formatting.json'] = json.dumps({'llvm_standalone_lock_records_joined':prefixes}, indent=2)+'\n'
    # Retain native readelf corroboration, distinct from the Python decoder.
    frame_text = subprocess.check_output(['readelf', '-wf', str(binary)], text=True)
    blocks = re.split(r'\n\s*\n', frame_text)
    selected = [b for b in blocks if f'pc={BEGIN:016x}..{END:016x}' in b]
    if len(selected) != 1:
        raise ValueError('Native readelf FDE disagreement')
    frame = next(s for s in sections(data) if s['name'] == '.eh_frame')
    cie_offset = int(result['fde']['cie'], 16)-frame['address']
    selected_cie = [b for b in blocks if re.match(rf'^\s*{cie_offset:08x}\s.*\bCIE\b', b)]
    if len(selected_cie) != 1:
        raise ValueError('Native readelf CIE disagreement')
    raw['frames.txt'] = '\n\n'.join(selected_cie+selected)+'\n'
    relas = subprocess.check_output(['readelf', '-rW', str(binary)], text=True)
    slots = {result['personality_binding']['slot_va'], result['source_location_binding']['slot_va'], result['resume_binding']['slot_va']}
    lines = [line for line in relas.splitlines() if any(re.match(rf'^0*{int(v,16):x}\s', line) for v in slots)]
    if len(lines) != 3:
        raise ValueError('Native readelf relocation disagreement')
    raw['relocations.txt'] = '\n'.join(lines)+'\n'
    return result, raw


def generate(binary, output):
    item = next(x for x in json.loads((ROOT/'provenance/artifacts.json').read_text())['files']
                if x['path'] == 'artifacts/node/94/hl-node')
    data = binary.read_bytes()
    if item['sha256'] != SHA256 or len(data) != item['size'] or hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError('Target size/SHA-256 mismatch')
    # Native readers see the same authenticated bytes as the Python readers.
    # This owned snapshot is data-only and is never launched.
    with tempfile.TemporaryDirectory(prefix='compact-unwind-') as directory:
        snapshot = Path(directory)/'node94.elf'
        snapshot.write_bytes(data)
        snapshot.chmod(0o400)
        result, raw = collect_native(snapshot, data)
    output.mkdir(parents=True, exist_ok=True)
    for name, value in raw.items():
        (output/name).write_text(value)
    (output/'records.json').write_text(json.dumps(result, indent=2)+'\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT/'artifacts/node/94/hl-node')
    parser.add_argument('--output', type=Path, default=ROOT/'work/compact-string-unwind-94')
    args = parser.parse_args()
    result = generate(args.binary.resolve(), args.output)
    print(json.dumps(result['denominator'], indent=2))
