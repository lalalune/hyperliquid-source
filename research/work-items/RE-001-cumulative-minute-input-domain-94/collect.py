#!/usr/bin/env python3
"""Static producer/consumer composition; never evaluate captured instructions."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
TARGET = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SIZE = 91774280
DEPENDENCIES = {
    'tools/elf_index.py': 'd77a002e9b2d3dce86822f6c67169298ad0ea54f5f4cb5c0d244328cbed1774f',
    'tools/fde_extents.py': '9ce52ed319743ecfbaaafec799f6cef20148e0d46f161091f89b7c58ffdd2345',
    'tools/foundation_millis.py': '77e9dc23e2db38e09953ca6792c18f85ce39a33f8b84c0b6f2c2b212e4c5bead',
    'tools/state_dump_result_projection_static.py': '4a5ddb8991011b16b391718987d8abffa81a0cd40beeec189b71e123520d396d',
    'tools/artifacts.py': 'e69b7e1f35ad460fc9f0bcd2e568900b9b7420a3d71cf15f9e6c44a3b3463abf',
}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


for dependency, digest in DEPENDENCIES.items():
    need(sha((ROOT / dependency).read_bytes()) == digest, 'Dependency changed: ' + dependency)
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records
from foundation_millis import prove_division
import state_dump_result_projection_static as projection

RANGES = {'caller-a': (0x4925220, 0x4925f0c),
          'caller-b': (0x4925f10, 0x4926dac),
          'producer': (0x151cba0, 0x151cca5)}
CALLERS = {'caller-a': {'lea': 0x49255b7, 'call': 0x49255bc, 'use': 0x4925bac, 'base': 0x44},
           'caller-b': {'lea': 0x4926378, 'call': 0x492637d, 'use': 0x4926952, 'base': 0x54}}
TABLE = 0x700454
DISPATCH = 0x4926093
SLOT = 0x576e8a0
LLVM_DEFAULT = '/Library/Developer/CommandLineTools/usr/bin/llvm-objdump'


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


class Image:
    def __init__(self, data):
        need(len(data) == SIZE and sha(data) == TARGET, 'Wrong complete node94 identity')
        self.data = data
        self.secs = sections(data)
        need(struct.unpack_from('<H', data, 18)[0] == 62, 'Expected x86-64')
        offset = struct.unpack_from('<Q', data, 32)[0]
        stride, count = struct.unpack_from('<HH', data, 54)
        need(stride == 56, 'Program-header size differs')
        self.loads = [struct.unpack_from('<IIQQQQQQ', data, offset + i * stride) for i in range(count)]
        self.loads = [p for p in self.loads if p[0] == 1]

    def offset(self, va, size):
        matches = [p[2] + va - p[3] for p in self.loads if p[3] <= va and va + size <= p[3] + p[5]]
        need(size >= 0 and len(matches) == 1, 'Expected one file-backed PT_LOAD mapping')
        offset = matches[0]
        need(0 <= offset <= offset + size <= len(self.data), 'File range differs')
        return offset

    def at(self, va, size):
        offset = self.offset(va, size)
        return self.data[offset:offset + size]


def native(args, cwd):
    result = subprocess.run(args, cwd=cwd, capture_output=True, timeout=60,
                            env=dict(os.environ, LC_ALL='C'))
    need(result.returncode == 0, 'Native parser failed: ' + args[0])
    return result.stdout.decode('utf-8')


def rows(text, image, start, end):
    result, cursor = [], start
    for line in text.splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}[ \t]+)+)(.*)$', line)
        if not match:
            continue
        address, raw = int(match[1], 16), bytes.fromhex(match[2])
        assembly = match[3].strip()
        need(address == cursor and raw and address + len(raw) <= end, 'Native instruction tiling differs')
        need(raw == image.at(address, len(raw)), 'Native instruction bytes differ')
        need(assembly and '(bad)' not in assembly and '.byte' not in assembly, 'Incomplete native decoding')
        result.append({'va': hex(address), 'bytes': raw.hex(), 'assembly': assembly})
        cursor += len(raw)
    need(cursor == end and result, 'Missing native instruction rows')
    return result


def reach(graph, start, blocked=None):
    seen, todo = set(), [start]
    while todo:
        address = todo.pop()
        if address in seen or address == blocked:
            continue
        seen.add(address)
        todo.extend(graph.get(address, ()))
    return seen


def admit_prefix_form(row):
    """Only the exact observed prefixed NOP forms are reviewed by these audits."""
    mnemonic = row['assembly'].split()[0]
    prefixes = {'cs', 'ds', 'es', 'fs', 'gs', 'ss', 'data16', 'addr16', 'addr32',
                'lock', 'rep', 'repz', 'repnz', 'repe', 'repne', 'bnd', 'notrack',
                'xacquire', 'xrelease'}
    if mnemonic in prefixes or mnemonic.startswith('rex'):
        padding = {'66' * n + '2e0f1f840000000000' for n in (2, 3, 4, 5)}
        need(row['bytes'] in padding and
             re.fullmatch(r'(?:data16 )+cs nop WORD PTR \[rax\+rax\*1\+0x0\]', row['assembly']),
             'Unreviewed prefixed instruction')


def cfg(decoded, dispatch_targets=()):
    """Decode control-flow operands only. Calls have ordinary-return fallthrough."""
    by = {int(row['va'], 16): row for row in decoded}
    graph, transfers, exits = {}, [], []
    for address, row in by.items():
        admit_prefix_form(row)
        raw = bytes.fromhex(row['bytes']); next_address = address + len(raw)
        mnemonic = row['assembly'].split()[0]
        targets, kind = [], 'fallthrough'
        if raw[:1] in (b'\xc3', b'\xc2') or raw == b'\x0f\x0b':
            kind = 'return' if raw[0] in (0xc3, 0xc2) else 'trap'
            exits.append({'va': hex(address), 'kind': kind})
        elif len(raw) == 5 and raw[0] == 0xe9:
            kind = 'jump'; targets = [next_address + struct.unpack('<i', raw[1:])[0]]
        elif len(raw) == 2 and raw[0] == 0xeb:
            kind = 'jump'; targets = [next_address + struct.unpack('<b', raw[1:])[0]]
        elif len(raw) == 2 and 0x70 <= raw[0] <= 0x7f:
            kind = 'conditional'; targets = [next_address, next_address + struct.unpack('<b', raw[1:])[0]]
        elif len(raw) == 6 and raw[0] == 15 and 0x80 <= raw[1] <= 0x8f:
            kind = 'conditional'; targets = [next_address, next_address + struct.unpack('<i', raw[2:])[0]]
        elif address == DISPATCH and raw == b'\xff\xe0':
            need(dispatch_targets, 'Missing bounded dispatch destinations')
            kind = 'conditional-domain-indirect-jump'; targets = sorted(set(dispatch_targets))
        else:
            need(not mnemonic.startswith('j') and not mnemonic.startswith('loop'), 'Unresolved control transfer')
            if next_address in by:
                targets = [next_address]
            else:
                exits.append({'va': hex(address), 'kind': 'out-of-FDE-fallthrough',
                              'note': 'No noreturn assumption made for the final call.'})
        need(all(target in by for target in targets), 'Control edge not a decoded in-FDE start')
        graph[address] = targets
        if kind != 'fallthrough':
            transfers.append({'va': hex(address), 'kind': kind, 'successors': [hex(x) for x in targets]})
    return graph, transfers, exits


def cfi(image):
    cies, fdes = eh_frame_records(image.data, image.secs)
    result = {}
    for label, (start, end) in RANGES.items():
        found = [f for f in fdes if f['start'] == start]
        need(len(found) == 1 and found[0]['end'] == end, 'Exact FDE extent differs')
        fde = found[0]; record = {'decoded': fde, 'cie': cies[fde['cie']]}
        for kind, address in [('fdeBytes', fde['fde']), ('cieBytes', fde['cie'])]:
            size = struct.unpack('<I', image.at(address, 4))[0] + 4
            need(8 <= size < 4096, 'CFI size differs')
            record[kind] = {'va': hex(address), 'fileOffset': hex(image.offset(address, size)),
                            'bytes': image.at(address, size).hex()}
        result[label] = record
    return result


def relocations(image, slots):
    sec = [s for s in image.secs if s['name'] == '.rela.dyn']
    need(len(sec) == 1 and sec[0]['size'] % 24 == 0, 'RELA section differs')
    found = {slot: [] for slot in slots}
    raw = image.at(sec[0]['address'], sec[0]['size'])
    for i, (slot, info, addend) in enumerate(struct.iter_unpack('<QQq', raw)):
        if slot in found:
            found[slot].append({'slot': hex(slot), 'type': info & 0xffffffff,
                                'symbolIndex': info >> 32, 'addend': hex(addend),
                                'fileOffset': hex(sec[0]['offset'] + i * 24),
                                'bytes': raw[i * 24:i * 24 + 24].hex()})
    need(all(len(v) == 1 for v in found.values()), 'Missing or ambiguous selected relocation')
    return [found[slot][0] for slot in sorted(found)]


def call_info(row):
    address, raw = int(row['va'], 16), bytes.fromhex(row['bytes'])
    result = {'va': row['va'], 'bytes': row['bytes'], 'assembly': row['assembly']}
    if len(raw) == 5 and raw[0] == 0xe8:
        result['directTarget'] = hex(address + 5 + struct.unpack('<i', raw[1:])[0])
    elif len(raw) == 6 and raw[:2] == b'\xff\x15':
        result['slot'] = hex(address + 6 + struct.unpack('<i', raw[2:])[0])
    else:
        result['indirectRegister'] = True
    return result


def memory_inventory(decoded, addresses, field_offset):
    """Inventory explicit first-operand destinations, not a general effect analysis."""
    writes, stack_addresses, stack_changes, implicit = [], [], [], []
    for row in decoded:
        if int(row['va'], 16) not in addresses:
            continue
        text = row['assembly'].split(' #')[0].split(' <')[0]
        fields = text.split(None, 1)
        op = fields[0]; operands = fields[1] if len(fields) == 2 else ''
        first = operands.split(',')[0]
        if (op == 'lea' and '[rsp' in operands or
                op == 'mov' and re.fullmatch(r'r[a-z0-9]+,rsp', operands.strip())):
            stack_addresses.append(row)
        if first == 'rsp' or op in ('push', 'pop', 'enter', 'leave'):
            stack_changes.append(row)
        if (op in ('rep', 'repz', 'repnz', 'repe', 'repne', 'movs', 'stos', 'lods', 'scas', 'cmps', 'ins', 'outs') or
                op.startswith(('stos', 'lods', 'scas', 'cmps')) or op in ('movsb', 'movsw', 'movsq', 'insb', 'insw', 'insd')):
            implicit.append(row)
        if '[' in first and op not in ('cmp', 'test', 'call') and 'nop' not in text:
            item = dict(row)
            match = re.search(r'(XMMWORD|QWORD|DWORD|WORD|BYTE) PTR \[rsp(?:\+(0x[0-9a-f]+))?\]', first)
            if match:
                offset = int(match[2] or '0', 16)
                size = {'BYTE': 1, 'WORD': 2, 'DWORD': 4, 'QWORD': 8, 'XMMWORD': 16}[match[1]]
                item['directStackInterval'] = [offset, offset + size]
                item['overlapsInput'] = offset < field_offset + 4 and field_offset < offset + size
            else:
                item['aliasUnresolved'] = True
            writes.append(item)
    return {'memoryWrites': writes, 'stackAddressFormations': stack_addresses,
            'stackPointerChanges': stack_changes, 'implicitMemoryOperations': implicit,
            'inventoryScope': 'Explicit first-memory-operand destinations only. CALL stack writes/effects require the matching-return/no-clobber premises.'}


def writes_register(row, aliases):
    text = row['assembly'].split(' #')[0].split(' <')[0]
    fields = text.split(None, 1)
    if len(fields) == 1 or fields[0] in ('cmp', 'test', 'push', 'call') or fields[0].startswith('j'):
        return False
    operands = [operand.strip() for operand in fields[1].split(',')]
    return operands[0] in aliases or fields[0] == 'xchg' and any(op in aliases for op in operands)


def selector_audit(image, decoded):
    by = {int(row['va'], 16): row for row in decoded}
    need(image.at(0x4925f24, 2) == bytes.fromhex('89f5'), 'Original ESI-to-EBP copy changed')
    need(image.at(0x4925fdc, 4) == bytes.fromhex('400fb6c5'), 'Original BPL selector load changed')
    before = [row for row in decoded if 0x4925f26 <= int(row['va'], 16) < 0x4925fdc]
    need(not any(writes_register(row, {'rbp', 'ebp', 'bp', 'bpl'}) for row in before), 'Saved selector is overwritten')
    after = [row for row in decoded if 0x4925fe0 <= int(row['va'], 16) < 0x492608c]
    for row in before + after:
        admit_prefix_form(row)
    allowed = {'test', 'je', 'mov', 'movzx', 'lea', 'neg', 'nop', 'data16', 'cmp',
               'setl', 'setg', 'sub', 'add', 'inc', 'jmp', 'jb', 'xor'}
    need(all(row['assembly'].split()[0] in allowed for row in after), 'Unreviewed selector-span operation')
    need(not any(writes_register(row, {'rax', 'eax', 'ax', 'al', 'ah'}) for row in after), 'Dispatch selector is overwritten')
    return {'entryCopy': by[0x4925f24], 'zeroExtension': by[0x4925fdc],
            'callsRequiringCalleeSavedRBP': [call_info(row) for row in before if row['assembly'].split()[0] == 'call'],
            'eaxPreservationSpan': after,
            'scope': 'First-destination and XCHG register writes checked; only exact observed prefixed NOP forms admitted; post-load mnemonic allowlist excludes implicit EAX writers and calls; input-domain restriction remains a premise.'}


def minute_contract(image, use):
    raw = image.at(use, 75)
    # Exact decoded register sequence, with input displacement extracted separately.
    need(raw[:3] == b'\x8b\x54\x24', 'Minute input load changed')
    fixed = {4: 'b9', 9: '480fafca', 13: '48c1e9', 17: '6bf1', 20: 'b9',
             25: '480fafca', 29: '48c1e9', 33: '4869d1', 40: '48c1ea',
             44: '6bd2', 47: '29d101f1', 51: '81f9', 57: '0f87',
             63: '81f9', 69: '0f83'}
    for offset, encoded_hex in fixed.items():
        expected = bytes.fromhex(encoded_hex)
        need(raw[offset:offset + len(expected)] == expected, 'Minute register/guard sequence changed')
    c0, c1, c2 = [struct.unpack_from('<I', raw, offset)[0] for offset in (5, 21, 36)]
    shifts = [raw[offset] for offset in (16, 32, 43)]
    need(raw[19] == raw[46] == 60, 'Minute combine multiplier changed')
    proofs = [prove_division(c0, shifts[0], 3600, (1 << 32) - 1),
              prove_division(c1, shifts[1], 60, (1 << 32) - 1),
              prove_division(c2, shifts[2], 60, ((1 << 32) - 1) // 60)]
    limits = [struct.unpack_from('<I', raw, offset)[0] for offset in (53, 65)]
    need(limits == [65535, 1441], 'Observed minute guards changed')
    return {'loadOffset': raw[3], 'bytes': raw.hex(), 'divisionProofs': proofs,
            'guards': [{'kind': 'unsigned-above', 'limit': limits[0],
                        'target': hex(use + 63 + struct.unpack_from('<i', raw, 59)[0])},
                       {'kind': 'unsigned-above-or-equal', 'limit': limits[1],
                        'target': hex(use + 75 + struct.unpack_from('<i', raw, 71)[0])}]}


def producer_contract(image, decoded):
    for address, encoded_hex in projection.ANCHORS.items():
        expected = bytes.fromhex(encoded_hex)
        need(image.at(address, len(expected)) == expected, 'Producer structural transfer changed')
    # Retain the complete known arithmetic/store sequence; extract operands used by prove().
    opcodes = {0x151cbef: '48b9', 0x151cc02: '48c1e8', 0x151cc06: '48c1fa',
               0x151cc0d: '4869c2', 0x151cc1a: '49c1ff', 0x151cc22: '4805',
               0x151cc28: '48b9', 0x151cc3a: '81c2', 0x151cc4c: '4181e7',
               0x151cbe9: '833c2401', 0x151cc32: '4839c8',
               0x151cc56: '890344897b04896b08'}
    for address, encoded_hex in opcodes.items():
        expected = bytes.fromhex(encoded_hex)
        need(image.at(address, len(expected)) == expected, 'Producer arithmetic/store operation changed')
    read32 = lambda address: struct.unpack('<I', image.at(address, 4))[0]
    p = {'multiplier': struct.unpack('<Q', image.at(0x151cbf1, 8))[0],
         'high_shift': image.at(0x151cc09, 1)[0], 'quotient_sign_shift': image.at(0x151cc05, 1)[0],
         'divisor': read32(0x151cc10), 'remainder_sign_shift': image.at(0x151cc1d, 1)[0],
         'repair_mask': read32(0x151cc4f),
         'index_guard_add': struct.unpack('<i', image.at(0x151cc24, 4))[0],
         'index_threshold': struct.unpack('<Q', image.at(0x151cc2a, 8))[0],
         'index_offset': read32(0x151cc3c)}
    proof = projection.prove(p)
    need(p['divisor'] == 86400, 'Producer remainder domain changed')
    graph, transfers, exits = cfg(decoded)
    need([row['va'] for row in exits if row['kind'] == 'return'] == ['0x151cc6c'] and
         0x151cc6c in reach(graph, 0x151cba0), 'Expected reachable sole producer RET')
    stores = (0x151cc56, 0x151cc58, 0x151cc5c)
    need(all(0x151cc6c not in reach(graph, 0x151cba0, store) for store in stores),
         'Producer stores do not dominate retained RET')
    return {'parameters': p, 'proof': proof, 'resultOffsets': [0, 4, 8],
            'secondFieldInterval': [0, 86399], 'transfers': transfers, 'exits': exits}


def analyze(image, decoded):
    frames = cfi(image)
    for label, (start, end) in RANGES.items():
        need(decoded[label][0]['va'] == hex(start), 'Decoded range start differs')
        cursor = start
        for row in decoded[label]:
            raw = bytes.fromhex(row['bytes'])
            need(int(row['va'], 16) == cursor and raw == image.at(cursor, len(raw)), 'Decoded bytes/gap differs')
            cursor += len(raw)
        need(cursor == end, 'Decoded range end differs')
    producer = producer_contract(image, decoded['producer'])
    selector = selector_audit(image, decoded['caller-b'])
    need(image.at(0x4926085, 3) == bytes.fromhex('488d0d') and
         0x492608c + struct.unpack('<i', image.at(0x4926088, 4))[0] == TABLE and
         image.at(0x492608c, 9) == bytes.fromhex('486304814801c8ffe0'), 'Dispatch transfer sequence changed')
    candidates = [TABLE + n for n in struct.unpack('<256i', image.at(TABLE, 1024))]
    local_targets = candidates[:6]
    caller_reports, all_calls = {}, []
    for label, site in CALLERS.items():
        ins = decoded[label]; by = {int(row['va'], 16): row for row in ins}
        graph, transfers, exits = cfg(ins, local_targets if label == 'caller-b' else ())
        entry = RANGES[label][0]; call, use = site['call'], site['use']
        need(image.at(site['lea'], 4) == bytes.fromhex('488d7c24'), 'Producer destination LEA changed')
        destination = image.at(site['lea'] + 4, 1)[0]
        producer_call = call_info(by[call])
        need(producer_call.get('slot') == hex(SLOT), 'Producer call slot changed')
        contract = minute_contract(image, use)
        need(destination == site['base'] and contract['loadOffset'] == destination + 4,
             'Producer/consumer field offsets differ')
        reachable = reach(graph, entry)
        need(use in reachable and use not in reach(graph, entry, call), 'Producer does not dominate consumer')
        reverse = {a: [] for a in graph}
        for a, successors in graph.items():
            for b in successors:
                reverse[b].append(a)
        corridor = (reach(graph, call + 6) & reach(reverse, use)) - {use}
        prefix = reach(graph, entry) & reach(reverse, call)
        inventory = memory_inventory(ins, corridor, destination + 4)
        need(not inventory['stackPointerChanges'], 'Stack pointer changes inside producer/use corridor')
        need(not inventory['implicitMemoryOperations'], 'Unreviewed implicit memory operation in corridor')
        need(not any(row.get('overlapsInput') for row in inventory['memoryWrites']), 'Explicit overlapping input write')
        calls = [call_info(row) for row in ins if row['assembly'].split()[0] == 'call']
        corridor_calls = [row for row in calls if int(row['va'], 16) in corridor]
        all_calls.extend(calls)
        caller_reports[label] = {'producerCall': producer_call, 'producerDestinationOffset': destination,
            'consumerVA': hex(use), 'minuteContract': contract, 'producerDominatesConsumer': True,
            'cfgScope': 'Ordinary matching-call-return edges; local branches; caller-b dispatch only for selector0..5; no exception/out-of-FDE reentry.',
            'entryReachableRows': len(reachable), 'corridorRows': len(corridor),
            'corridorAddresses': [hex(x) for x in sorted(corridor)], 'interveningCalls': corridor_calls,
            'prefixStackAddressFormations': memory_inventory(ins, prefix, destination + 4)['stackAddressFormations'],
            'prefixCalls': [row for row in calls if int(row['va'], 16) in prefix],
            'inventory': inventory, 'transfers': transfers, 'exits': exits,
            'conditionalMinuteInterval': [0, 1439],
            'unclosedMemoryEffects': 'Opaque calls and non-RSP stores may alias this frame or earlier escaped addresses. Preservation of the four consumed bytes is an explicit premise, not inferred from this inventory.'}
    all_calls += [call_info(row) for row in decoded['producer'] if row['assembly'].split()[0] == 'call']
    slots = {int(row['slot'], 16) for row in all_calls if 'slot' in row}
    relas = relocations(image, slots)
    producer_rela = next(row for row in relas if row['slot'] == hex(SLOT))
    need((producer_rela['type'], producer_rela['symbolIndex'], producer_rela['addend']) == (8, 0, '0x151cba0'),
         'Producer relocation binding changed')
    return {'targetSha256': TARGET, 'targetBytes': SIZE, 'dependencies': DEPENDENCIES,
            'ranges': {label: {'start': hex(start), 'end': hex(end), 'bytes': end - start,
                              'fileOffset': hex(image.offset(start, end - start)),
                              'sha256': sha(image.at(start, end - start)), 'frames': frames[label],
                              'instructions': decoded[label]}
                       for label, (start, end) in RANGES.items()},
            'producerContract': producer, 'callers': caller_reports, 'allCalls': all_calls,
            'relocations': relas,
            'dispatch': {'va': hex(DISPATCH), 'tableBase': hex(TABLE), 'selectedIndexDomain': [0, 5],
                         'selectorTransferAudit': selector,
                         'selectedBytes': image.at(TABLE, 24).hex(),
                         'selectedTargets': [hex(x) for x in local_targets],
                         'rawByteCandidateCensus': [{'index': i, 'target': hex(x),
                             'insideCallerFDE': RANGES['caller-b'][0] <= x < RANGES['caller-b'][1]}
                             for i, x in enumerate(candidates)],
                         'censusLimit': '1024 adjacent data bytes, not a claim of256 actual table entries or valid variants; no local bounds check.'},
            'targetExecution': False, 'instructionEvaluation': False}


def collect(binary, llvm=LLVM_DEFAULT):
    image = Image(Path(binary).read_bytes())
    files, decoded, llvm_rows = {}, {}, {}
    with tempfile.TemporaryDirectory(prefix='node94-minute-static-') as temporary:
        directory = Path(temporary); snapshot = directory / 'node94.elf'
        snapshot.write_bytes(image.data); snapshot.chmod(0o400)
        versions = {tool: native([tool, '--version'], directory).splitlines()[0] for tool in ('objdump', 'readelf')}
        need(all('GNU' in value for value in versions.values()), 'GNU binutils required')
        versions['llvm'] = native([llvm, '--version'], directory).splitlines()[0]
        frames = native(['readelf', '-W', '--debug-dump=frames', 'node94.elf'], directory)
        blocks = re.split(r'\n\s*\n', frames)
        for label, (start, end) in RANGES.items():
            listing = native(['objdump', '-d', '-M', 'intel', '--insn-width=16',
                              '--start-address=' + hex(start), '--stop-address=' + hex(end), 'node94.elf'], directory)
            decoded[label] = rows(listing, image, start, end)
            files[label + '.objdump.txt'] = listing.encode()
            independent = native([llvm, '-d', '--x86-asm-syntax=intel', '--start-address=' + hex(start),
                                  '--stop-address=' + hex(end), 'node94.elf'], directory)
            llvm_rows[label] = rows(independent, image, start, end)
            fields = lambda records: [(r['va'], r['bytes']) for r in records]
            need(fields(decoded[label]) == fields(llvm_rows[label]), 'GNU/LLVM instruction boundaries differ')
            files[label + '.llvm.txt'] = independent.encode()
            matching = [block for block in blocks if re.search(
                r'FDE cie=[0-9a-f]+ pc=0*' + f'{start:x}' + r'\.\.0*' + f'{end:x}' + r'\b', block)]
            need(len(matching) == 1, 'Native FDE range differs')
            cie_offset = re.search(r'FDE cie=([0-9a-f]+)', matching[0])[1]
            cie = [block for block in blocks if re.match(r'^\s*' + cie_offset + r'\s+.*\bCIE\b', block)]
            need(len(cie) == 1, 'Missing native CIE')
            files[label + '.frames.txt'] = (cie[0] + '\n\n' + matching[0] + '\n').encode()
        need(snapshot.read_bytes() == image.data, 'Native provider changed snapshot')
    report = analyze(image, decoded)
    report['providers'] = versions
    report['independentDecoderComparison'] = {'instructionBoundariesAndBytes': 'equal',
        'rows': sum(len(x) for x in decoded.values()), 'bytes': sum(end - start for start, end in RANGES.values()),
        'normalizationMasks': [], 'semanticProof': False}
    files['records.json'] = encoded(report)
    return files


def write_new(output, files):
    output = Path(output)
    need(not output.exists(), 'Preserve existing output')
    output.mkdir(parents=True)
    for name, data in files.items():
        (output / name).write_bytes(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'artifacts/node/94/hl-node')
    parser.add_argument('--llvm-objdump', default=LLVM_DEFAULT)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        need(not args.output.exists(), 'Preserve existing output')
        files = collect(args.binary, args.llvm_objdump)
        write_new(args.output, files)
        print(json.dumps({'files': len(files), 'targetExecution': False}))
    except (ValueError, OSError, UnicodeError, subprocess.TimeoutExpired) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()
