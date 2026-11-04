#!/usr/bin/env python3
"""RE-012: static Node115 declaration/validator producer record; never run the ELF."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from elf_index import sections
from fde_extents import eh_frame_records
ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-012-node115-cli-command-factory'
TARGET = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

def require(ok, message):
    if not ok:
        raise ValueError(message)

def read_va(blob, secs, address, size):
    require(isinstance(size, int) and size >= 0, 'invalid extent')
    candidates = [s for s in secs if s['type'] != 8 and s['address'] <= address
                  and address + size <= s['address'] + s['size']]
    require(len(candidates) == 1, 'not uniquely file-backed')
    p = candidates[0]['offset'] + address - candidates[0]['address']
    return blob[p:p + size]

def instruction(blob, secs, spec, address, exact=True):
    row = spec['witnesses'][address]
    original = bytes.fromhex(row['bytes'])
    actual = read_va(blob, secs, int(address, 16), len(original))
    prefix = 2 if original[:2] == b'\xff\x15' else 3
    require(actual == original if exact else actual[:prefix] == original[:prefix],
            'instruction shape at ' + address)
    return actual

def derive_declarations(blob, secs, spec):
    """Static displacement/immediate reads, not an instruction interpreter."""
    result = []
    for d in spec['arguments']:
        raw = instruction(blob, secs, spec, d['pointerDefinition'], False)
        require(len(raw) == 7, 'LEA extent')
        pointer = int(d['pointerDefinition'], 16) + 7 + struct.unpack('<i', raw[-4:])[0]
        length = int.from_bytes(instruction(blob, secs, spec, d['lengthStore'], False)[-4:], 'little')
        require(0 < length <= 32, 'name length')
        name = read_va(blob, secs, pointer, length)
        require(name == d['name'].encode('ascii'), 'declaration name')
        instruction(blob, secs, spec, d['pointerStore'])
        flags = int.from_bytes(instruction(blob, secs, spec, d['settings']['site'], False)[-4:], 'little')
        require(flags == int(d['settings']['raw'], 0), 'declaration flags')
        raw = instruction(blob, secs, spec, d['registration'], False)
        require(len(raw) == 6 and raw[:2] == b'\xff\x15', 'registration opcode')
        slot = int(d['registration'], 16) + 6 + struct.unpack('<i', raw[2:])[0]
        require(slot == 0x64e1cf0, 'registration slot')
        result.append({'command': d['command']['name'], 'argument': name.decode('ascii'),
                       'registration': d['registration'], 'namePointer': hex(pointer),
                       'nameLength': length, 'rawFlags': hex(flags),
                       'requiredNameAppendBit': bool(flags & 1),
                       'globalBit': bool(flags & 8)})
    require(len(result) == 24, 'declaration count')
    return result

def derive_commands(blob, secs, spec):
    result = []
    for c in spec['commands']:
        data = bytearray(c['length'])
        covered = set()
        for w in c['writes']:
            instruction(blob, secs, spec, w['site'])
            raw = instruction(blob, secs, spec, w['source'])
            width = len(bytes.fromhex(w['bytes']))
            if w['sourceRIPTarget'] is not None:
                require(len(raw) == 7, 'literal load extent')
                target = int(w['source'], 16) + 7 + struct.unpack('<i', raw[-4:])[0]
                value = read_va(blob, secs, target, width)
            else:
                value = raw[-width:]
            require(value == bytes.fromhex(w['bytes']), 'literal data')
            offset = w['offset']
            require(0 <= offset <= len(data) - width, 'literal store extent')
            data[offset:offset + width] = value
            covered.update(range(offset, offset + width))
        require(len(covered) == len(data) and data == c['text'].encode('ascii'), 'command literal')
        result.append({'name': data.decode('ascii'), 'length': len(data),
                       'allocationCall': c['allocationCall'], 'writes': c['writes']})
    require(len(result) == 14, 'command count')
    return result

def derive_validators(blob, secs, spec):
    expected_slots = {int(w['slot'], 16) for d in spec['validators']
                      for v in d['validatorCandidates'] for w in v['writers']}
    writers = {slot: [] for slot in expected_slots}
    for sec in secs:
        if sec['type'] != 4:
            continue
        require(sec['size'] % 24 == 0, 'RELA extent')
        for p in range(sec['offset'], sec['offset'] + sec['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', blob, p)
            if slot in writers:
                writers[slot].append((info, addend))
    result = []
    for d in spec['validators']:
        bindings = []
        for v in d['validatorCandidates']:
            instruction(blob, secs, spec, v['load'])
            va = int(v['vtable'], 16)
            require(struct.unpack('<3Q', read_va(blob, secs, va, 24)) == (0, 0, 1), 'vtable header')
            methods = []
            for w in v['writers']:
                require(writers[int(w['slot'], 16)] == [(8, int(w['addend'], 16))], 'vtable RELA writer')
                methods.append({'slot': w['slot'], 'target': w['addend']})
            require(len(methods) == 3, 'method count')
            bindings.append({'vtable': v['vtable'], 'methods': methods})
        result.append({'command': d['command'], 'argument': d['argument'], 'bindings': bindings})
    require(sum(len(d['bindings']) for d in result) == 20, 'validator binding count')
    return result

def lsda_table(blob, secs, function):
    """Decode retained LSDA header and call-site table, not action/type semantics."""
    if function['lsda'] is None:
        return None
    va = int(function['lsda'], 16)
    sec = next(s for s in secs if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
    start = sec['offset'] + va - sec['address']
    end = sec['offset'] + sec['size']
    pos = start
    def byte():
        nonlocal pos
        require(pos < end, 'LSDA byte extent')
        value = blob[pos]
        pos += 1
        return value
    def uleb():
        value = shift = 0
        while True:
            require(shift <= 63, 'LSDA ULEB overflow')
            part = byte()
            value |= (part & 127) << shift
            if not part & 128:
                return value
            shift += 7
    require(byte() == 255, 'LSDA omitted LPStart required')
    type_encoding = byte()
    require(type_encoding in (255, 155), 'LSDA type encoding')
    type_offset = None if type_encoding == 255 else uleb()
    encoding_va = va + pos - start
    require(byte() == 1, 'LSDA call-site encoding')
    size = uleb()
    table_end = pos + size
    require(table_end <= end, 'LSDA table extent')
    sites = []
    base = int(function['start'], 16)
    limit = int(function['end'], 16)
    while pos < table_end:
        a, length, landing, action = uleb(), uleb(), uleb(), uleb()
        require(pos <= table_end and base + a + length <= limit, 'LSDA call-site range')
        require(not landing or base <= base + landing < limit, 'LSDA landing range')
        sites.append({'start': hex(base + a), 'end': hex(base + a + length),
                      'landing': hex(base + landing) if landing else None, 'action': action})
    require(pos == table_end, 'LSDA table end')
    return {'va': function['lsda'], 'callSiteEncodingVA': hex(encoding_va),
            'typeEncoding': type_encoding, 'typeOffset': type_offset,
            'headerAndCallSiteBytes': pos - start,
            'sha256': hashlib.sha256(blob[start:pos]).hexdigest(), 'sites': sites,
            'limits': 'Type/action chains and arbitrary callee unwinding not interpreted.'}

def derive_functions(blob, secs, spec):
    _, fdes = eh_frame_records(blob, secs)
    result = []
    for expected in spec['functions']:
        matching = [f for f in fdes if f['start'] == int(expected['start'], 16)]
        require(len(matching) == 1, 'FDE start multiplicity')
        actual = matching[0]
        for key in ('fde', 'cie', 'start', 'end', 'lsda'):
            require(actual[key] == (None if expected[key] is None else int(expected[key], 16)), 'FDE ' + key)
        raw = read_va(blob, secs, actual['start'], actual['end'] - actual['start'])
        require(hashlib.sha256(raw).hexdigest() == expected['bodySHA256'], 'body identity')
        result.append(dict(expected, exceptionTable=lsda_table(blob, secs, expected)))
    return result

def collect(blob, spec):
    require(len(blob) == spec['targetBytes'] and hashlib.sha256(blob).hexdigest() == TARGET
            and spec['targetSHA256'] == TARGET, 'target identity')
    secs = sections(blob)
    return {'schema': 1, 'targetSHA256': TARGET, 'functions': derive_functions(blob, secs, spec),
            'commands': derive_commands(blob, secs, spec),
            'arguments': derive_declarations(blob, secs, spec),
            'validators': derive_validators(blob, secs, spec),
            'literalData': [{'va': hex(va), 'length': size, 'bytes': read_va(blob, secs, va, size).hex(), 'text': read_va(blob, secs, va, size).decode('ascii')} for va, size in [(0x479018,38),(0x47903e,29),(0x47905b,38),(0x478fe8,41),(0x453ab0,16)]],
            'limits': 'Static producer record. Construction-order command association is supported by retained call-site dataflow; full parser/default/help behavior, address/IP grammar, allocation/formatter/error trait closure, arbitrary aliases, Rust ABI/build and node equivalence remain open. No gate changes; no target execution or emulation.'}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact', type=Path, default=ROOT / 'artifacts/node/115/hl-node')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    spec = json.loads((PACKET / 'spec.json').read_text(encoding='utf8'))
    record = collect(args.artifact.read_bytes(), spec)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'records.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n', encoding='utf8', newline=chr(10))
    print('Node115 declaration record: 14 commands / 24 registrations / 20 validator bindings')

if __name__ == '__main__':
    main()
