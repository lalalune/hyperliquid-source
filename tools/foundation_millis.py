#!/usr/bin/env python3
"""Reproduce one node #94 millisecond-conversion path without executing it."""
import argparse
import calendar
import datetime
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
from elf_index import sections

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/foundation-millis-94'
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
U64 = (1 << 64) - 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def prove_division(multiplier, shift, divisor, maximum):
    """Prove floor(n*C/2**k) == floor(n/d), for every n in [0,N].

    For each n=q*d+r, C*d=2**k+e. If e>=0, the fractional
    numerator q*e+r*C is largest at the largest allowed q for that r.
    Checking every remainder is a finite exhaustive proof, not random sampling.
    """
    require(multiplier > 0 and shift > 0 and divisor > 0 and maximum >= 0, 'Invalid proof parameters')
    scale = 1 << shift
    error = multiplier * divisor - scale
    require(error >= 0, 'Reciprocal rounds downward')
    count = min(divisor, maximum + 1)
    worst = max(((maximum-r)//divisor)*error+r*multiplier for r in range(count))
    require(worst < scale, 'Reciprocal proof failed')
    return dict(divisor=divisor, multiplier=hex(multiplier), shift=shift,
                maximum_input=maximum, remainder_classes=count,
                reciprocal_error=error, worst_fractional_numerator=worst,
                scale=scale, complete_integer_domain=True)


def decode_export(output, start, end, body):
    rows = []
    for line in output.splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)', line)
        if match:
            rows.append((int(match[1],16), bytes.fromhex(match[2])))
    cursor = start
    for address, raw in rows:
        require(address == cursor, 'Noncontiguous disassembly or off-by-one address')
        cursor += len(raw)
    require(cursor == end and b''.join(raw for _,raw in rows) == body, 'Disassembly bytes/extent changed')
    return dict(rows)


def analyze(data, records, objdump=None):
    secs = sections(data)
    named = {s['name']:s for s in secs}

    def read(va, size):
        matches = [s for s in secs if s['type'] != 8 and s['address'] <= va
                   and va+size <= s['address']+s['size']]
        require(len(matches) == 1, 'Unmapped or ambiguous VA')
        s = matches[0]; offset = s['offset']+va-s['address']
        return data[offset:offset+size]

    require(records['target_sha256'] == SHA256, 'Record target identity changed')
    windows = []
    instruction_starts = set()
    exports = {}
    eh = named['.eh_frame']['address']
    for row in records['windows']:
        start,end = int(row['start_va'],16),int(row['end_va_exclusive'],16)
        body = read(start,end-start)
        require(hashlib.sha256(body).hexdigest() == row['body_sha256'], 'Instruction window changed')
        fde_offset = int(row['fde_offset'],16)
        fde,cie = bytes.fromhex(row['fde_hex']),bytes.fromhex(row['cie_hex'])
        require(read(eh+fde_offset,len(fde)) == fde, 'FDE changed')
        require(read(eh+int(row['cie_offset'],16),len(cie)) == cie, 'CIE changed')
        # Narrow locks for the two independently exported pcrel/sdata4 records;
        # no new general FDE decoder or CFI/LSDA interpretation is introduced.
        pc = eh+fde_offset+8+struct.unpack_from('<i',fde,8)[0]
        require((pc,pc+struct.unpack_from('<I',fde,12)[0]) == (start,end), 'FDE range disagrees')
        if objdump:
            output = subprocess.check_output([objdump,'-d',f'--start-address={start:#x}',
                                              f'--stop-address={end:#x}','artifacts/node/94/hl-node'],cwd=ROOT,text=True)
        else:
            output = (PACKET / (row['name']+'.objdump.txt')).read_text()
        exports[row['name']] = output
        ins = decode_export(output,start,end,body)
        instruction_starts.update(ins)
        windows.append(dict(name=row['name'],start_va=hex(start),end_va_exclusive=hex(end),
                            bytes=len(body),instructions=len(ins),body_sha256=row['body_sha256']))
    required = [0x13c8e25,0x13c8eeb,0x13c8ef3,0x13c8f2d,0x14509ba]
    require(all(va in instruction_starts for va in required), 'Required address is not an instruction boundary')
    require(0x13c8ef3+5+struct.unpack('<i',read(0x13c8ef4,4))[0] == 0x14509a0, 'Error call target changed')
    require(0x14509ba+7+struct.unpack('<i',read(0x14509bd,4))[0] == 0x1e1152, 'Format reference changed')
    message = b'from_unix_millis: out-of-range input '
    require(read(0x1e1153,len(message)) == message, 'Error message changed')
    rel = named['.rela.dyn']; raw = read(rel['address'],rel['size'])
    require(len(raw)%24 == 0, 'Truncated relocations')
    rels = {address:(info,addend) for address,info,addend in struct.iter_unpack('<QQq',raw)}
    for address,target in records['relative_slots'].items():
        require(rels.get(int(address,16)) == (8,int(target,16)), 'Relative call slot changed')
    # Attribute call sites through relocated Location-shaped records. This
    # identifies source ownership; it does not establish a reproduced build.
    for location in records['calendar_source_locations']:
        address, path_va = int(location['record_va'],16), int(location['path_va'],16)
        path = location['path'].encode()
        require(rels.get(address) == (8,path_va), 'Calendar source relocation changed')
        length,line,column = struct.unpack('<QII',read(address+8,16))
        require((length,line,column) == (len(path),location['line'],location['column']),
                'Calendar source location changed')
        require(read(path_va,length) == path, 'Calendar source path changed')
    # Independently derive Gregorian tables with arithmetic / Python's calendar,
    # without copying the upstream implementation or its table initializer.
    expected_tables = {
        'leap_corrections': bytes((y+3)//4-(y+99)//100+(y+399)//400 for y in range(401)),
        'year_flags': bytes((0 if calendar.isleap(y+400) else 8) |
                            ((datetime.date(y+400,1,1)-datetime.timedelta(days=1)).weekday() or 7)
                            for y in range(400)),
    }
    for table in records['calendar_tables']:
        raw_table = read(int(table['start_va'],16),table['bytes'])
        require(hashlib.sha256(raw_table).hexdigest() == table['sha256'], 'Calendar table digest changed')
        require(raw_table == expected_tables[table['name']], 'Gregorian table identity failed')
    # These actual RIP-relative references connect the code to the table bytes.
    for instruction,target in [(0x151f755,0x250354),(0x151f7fb,0x2504e5),
                               (0x151f829,0x5672140),(0x151f836,0x56721a0),
                               (0x151f848,0x5672158),(0x151f85d,0x5672170)]:
        require(instruction in instruction_starts, 'Calendar table LEA boundary changed')
        require(instruction+7+struct.unpack('<i',read(instruction+3,4))[0] == target,
                'Calendar table reference changed')
    require(not re.search(r'%(?:r(?:bx|bp|12|13|14|15)(?:d|w|b)?|ebx|ebp|bx|bp|bh|bl|bpl)\b',exports['calendar_helper']),
            'Calendar helper uses a nonvolatile register')
    # Read actual immediates. The division result uses MUL's high 64 bits.
    first = struct.unpack('<Q',read(0x13c8e3b,8))[0]
    second = struct.unpack('<Q',read(0x13c8e56,8))[0]
    third = struct.unpack('<Q',read(0x13c8e6a,8))[0]
    pre1,post1 = read(0x13c8e38,1)[0],read(0x13c8e4c,1)[0]
    pre2,post2 = read(0x13c8e53,1)[0],read(0x13c8e67,1)[0]
    post3 = read(0x13c8eb5,1)[0]
    require((pre1,pre2) == (3,10), 'Unexpected preshift')
    nanos_scale = struct.unpack('<I',read(0x13c8eae,4))[0]
    seconds_scale = struct.unpack('<I',read(0x13c8ea4,4))[0]
    day_scale = struct.unpack('<I',read(0x13c8eb9,4))[0]
    day_offset = struct.unpack('<I',read(0x13c8e93,4))[0]
    gate_bias = struct.unpack('<i',read(0x13c8e7b,4))[0]
    gate_threshold = struct.unpack('<Q',read(0x13c8e81,8))[0]
    require((nanos_scale,seconds_scale,day_scale,day_offset,gate_bias,gate_threshold) ==
            (1000000,1000,86400,719163,-2146764485,(1<<64)-(1<<32)), 'Unit/gate constants changed')
    require(read(0x13c8f2d,7) == bytes.fromhex('49c7c6ffffffff'), 'Saturation value changed')
    proofs = [prove_division(first,64+post1,125,U64>>pre1),
              prove_division(second,64+post2,84375,U64>>pre2),
              prove_division(third,64+post3,86400,U64//1000)]
    return dict(target_release='94',target_sha256=SHA256,coordinate_system='ELF virtual addresses',
                windows=windows,division_proofs=proofs,
                arithmetic=dict(input='u64 fields at input pointer offsets 0 and 8',
                                product='min(a*b, 2**64-1)',seconds='product // 1000',
                                days='product // 86400000',nanoseconds='(product % 1000) * 1000000',
                                seconds_within_day='(product // 1000) % 86400',
                                preliminary_day_gate=[0,-gate_bias-1],calendar_day_offset=day_offset,
                                additional_calendar_helper_slot='0x576e890',additional_calendar_helper_target='0x151f6f0',
                                calendar_helper_success_condition='eax != 0; full accepted domain unresolved'),
                calendar_attribution=dict(library='chrono',version_path='0.4.38',
                                          inferred_method='NaiveDate::from_num_days_from_ce_opt',
                                          source_locations=records['calendar_source_locations'],
                                          tables=records['calendar_tables'],matched_table_bytes=801,
                                          nonvolatile_registers_absent=True,build_equivalence=False),
                error_formatter_entry='0x14509a0',error_call_va='0x13c8ef3',
                captured_binary_executed=False,complete_cfg=False,progress_gate_requested=False)


def _unique_object(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f'Duplicate key in retained check input: {key}')
        out[key] = value
    return out


def load_check(path):
    return json.loads(Path(path).read_text(), object_pairs_hook=_unique_object)


def inspect(path, objdump=None):
    data = Path(path).read_bytes()
    require(len(data) == 91774280 and hashlib.sha256(data).hexdigest() == SHA256, 'Expected exact node #94 size/SHA-256')
    return analyze(data,json.loads((PACKET/'records.json').read_text()),objdump)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,default=TARGET)
    parser.add_argument('--objdump',help='Rerun LLVM instead of using retained raw exports')
    parser.add_argument('--check',type=Path)
    args = parser.parse_args(); result = inspect(args.binary,args.objdump)
    if args.check:
        require(result == load_check(args.check), 'Retained evidence changed')
        print('Foundation millis evidence reproduces exactly.')
    else:
        print(json.dumps(result,indent=2))


if __name__ == '__main__':
    main()
