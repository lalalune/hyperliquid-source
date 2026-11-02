#!/usr/bin/env python3
"""Static, digest-bound controls for the node 94 size-decimal update path."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from elf_index import sections
from fde_extents import fde_extents

ROOT = HERE.parent
TARGET = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
FUNCTIONS = (0x36ff3c0, 0x3705690, 0x3315e90, 0x3bdc1b0, 0x1e801c0, 0x445c750, 0x33a83d0)
# These are instruction-aligned windows checked independently with disassembly.
CONTROLS = {
 'copy_list_guard': (0x445c75e, '488b4610483d10270000763e66c7034301488b'),
 'copy_list_success': (0x445c7a8, '488b4610488943180f10060f11430866c7038601eb'),
 'list_guard': (0x1e801ce, '488b4610483d10270000763e66c7034301488b'),
 'list_success': (0x1e80218, '488b4610488943180f10060f11430866c7038601eb'),
 'long_name_error': (0x235b982, '488b0c2466c7014301488d842420020000'),
 'dispatch': (0x2355f5a, '488d45ee4883fd12b94e000000480f43c848893c24488d05427208fe48630c884801c1ffe1'),
 'arm_init': (0x2357565, '4983c7084981c5b80500004c89ef31f6ff1505c841034989c6488d7c24204c89fee8358cb2ff0fb74424203d860100000f85562a0000'),
 'iterator_end': (0x2357617, '4c89e74c89eee8ce335100488b4424204885c00f8400310000488b4c2430488d14494c8b7cd008'),
 'name_guard': (0x235767a, '488b9424300200004883fa650f83f6420000488bac24280200004c89e74889ee4c89f1ff1575bc4103'),
 'resolver_gate_and_update': (0x23576a3, '0fb74424203d860100000f85f4420000488b7424280fb6d34c89f7ff15dcc64103'),
 'update_entry': (0x36ff3c0, '41574156534881ec8000000089d34989f64989ff488d7c24084c89feff15de690702488b4424084885c00f84c0000000'),
 'update_found_gate': (0x36ff453, '48837c3858007555'),
 'update_split': (0x36ff45b, '48b94b598638d6c56d344c89f048f7e148c1ea0b493b573075254869ca102700004c89f04829c8493b47107312'),
 'update_store': (0x36ff488, '498b4f08488d044048c1e004885c012a'),
 'update_error': (0x36ff49a, '66c744242060004c89742428488d7c2420e860300600'),
 'collect_init': (0x37056a1, '4889f34989fe488b46104889b424c001000048c78424c80100000000000048898424d0010000488d7c2418488db424c0010000e8b707c1ff'),
 'collect_mode': (0x37056d9, '80bba0010000004c89b424780100000f846a040000'),
 'collect_record_gate': (0x37058d1, '488d04c04c8d34c5000000004d01ee418b450883f8020f84430200004d8b6500'),
 'nested_key_compare': (0x33a844c, '4b8d342eba140000004c89e7ff152a603c0248984885c00f98c10f9fc028'),
 'nested_replace': (0x33a84b2, '410f1007410f104f10410f105720410f105f30488b4424080f1158300f1150200f1148100f1100488b0c240f10010f1049100f1051200f105930410f1107410f114f10410f115720410f115f30'),
 'nested_insert': (0x33a8612, '8b731089b490d80200000f10030f118490c8020000c1e106488b14240f10020f104a100f1052200f105a300f115c08300f115408200f114c08100f11040849ff4610488b44'),
 'collect_append_loop': (0x3705b09, 'e8c228caff4983c5484d39f50f85c5fdffff'),
 'collect_position_copy': (0x3705eb7, '488b9cd1c802000048c1e206f30f6f0411f30f6f4c1110f30f6f541120f30f6f5c1130660f7f4c2460660f7f9c2480000000660f7f542470660f7f442450'),
 'collect_position_gate': (0x3705ef5, '48837c2460000f8404feffff'),
 'collect_user_roots': (0x3705b58, '488b83580100004885c00f95c24c8b8b600100004c8bbb680100004d85ff0f95c120d14883bb10010000000f8423080000'),
 'tree_seed_call': (0x3315e9b, '4889fb488d7c2408e808638c00488b7424184885f60f84a8000000'),
 'seed_bounds': (0x3bdc1be, '4c8b76084c8b7e1031c04d89fc4d29f44c0f42e04c89e348c1e3054c89e148c1e93b0f95c148baf8ffffffffffff7f4839d30f97c208ca'),
 'seed_loop': (0x3bdc250, 'b81027000048f766307055498d14064c01fa4839c2725848891148c741080000000048c741180000000049ffc74883c1204c89c04c01f875c7'),
}


def checked(condition, message):
    if not condition:
        raise ValueError(message)


def authenticate(data):
    checked(hashlib.sha256(data).hexdigest() == DIGEST, 'target SHA-256 mismatch')


class Image:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)

    def read(self, address, size):
        checked(size >= 0, 'negative size')
        matches = [s for s in self.sections if s['type'] != 8 and s['size'] and
                   s['address'] <= address and address + size <= s['address'] + s['size']]
        checked(len(matches) == 1, 'address has no unique file-backed section')
        section = matches[0]
        offset = section['offset'] + address - section['address']
        return self.data[offset:offset + size]

    def relative(self, slot):
        candidates = [s for s in self.sections if s['name'] == '.rela.dyn' and s['type'] == 4]
        checked(len(candidates) == 1, 'invalid relocation section')
        sec = candidates[0]
        checked(sec['size'] % 24 == 0, 'truncated relocation section')
        result = []
        for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
            where, info, addend = struct.unpack_from('<QQq', self.data, off)
            if where == slot and info == 8:
                result.append(addend)
        checked(len(result) == 1, 'missing or ambiguous relative relocation')
        return result[0]


def control_bytes(img):
    rows = []
    for name, (address, expected) in CONTROLS.items():
        data = img.read(address, len(bytes.fromhex(expected)))
        checked(data == bytes.fromhex(expected), 'instruction control mismatch: ' + name)
        rows.append({'name': name, 'va': hex(address), 'bytes': data.hex()})
    return rows


def edge(img, site, target):
    op = img.read(site, 6)
    checked(op[:2] == b'\xff\x15', 'indirect-call opcode mismatch')
    slot = site + 6 + struct.unpack_from('<i', op, 2)[0]
    checked(img.relative(slot) == target, 'indirect call relocation mismatch')
    return {'site': hex(site), 'bytes': op.hex(), 'slot': hex(slot), 'target': hex(target)}


def direct_edge(img, site, target):
    raw = img.read(site, 5)
    checked(raw[0] == 0xe8, 'direct-call opcode mismatch')
    resolved = site + 5 + struct.unpack_from('<i', raw, 1)[0]
    checked(resolved == target, 'direct-call target mismatch')
    return {'site': hex(site), 'bytes': raw.hex(), 'target': hex(resolved)}


def branch(img, name, site, opcode):
    prefix = bytes.fromhex(opcode)
    checked(img.read(site, len(prefix)) == prefix, 'branch opcode mismatch: ' + name)
    width = 4 if len(prefix) == 2 else 1
    raw = img.read(site, len(prefix) + width)
    displacement = int.from_bytes(raw[len(prefix):], 'little', signed=True)
    return {'name': name, 'site': hex(site), 'bytes': raw.hex(),
            'target': hex(site + len(raw) + displacement)}


def outcome(asset, entry, inner_count, dex, row_count, new_byte, divisor):
    """Decision only after a completed collector; no target machine code is run."""
    if not (0 <= asset < 1 << 64 and 0 <= dex < 1 << 64 and
            0 <= row_count < 1 << 64 and 0 <= new_byte < 256 and inner_count >= 0):
        raise ValueError('input outside declared unsigned width')
    if not entry:
        return 'no-entry'
    if inner_count:
        return 'nonempty'
    q, r = divmod(asset, divisor)
    if q != dex or r >= row_count:
        return 'report-0x60'
    return 'write'


def seed_keys(dex, start, end, divisor):
    """Model a small supplied interval; no machine-code execution."""
    limit = (1 << 64) - 1
    if not all(0 <= x <= limit for x in (dex, start, end)) or divisor <= 0:
        raise ValueError('input outside declared unsigned width')
    if end <= start:
        return []
    if end - start > 16:
        raise ValueError('model interval too large')
    base = dex * divisor
    if base > limit:
        raise OverflowError('dex multiply')
    result = []
    for index in range(start, end):
        if base + index > limit:
            raise OverflowError('asset addition')
        result.append(base + index)
    return result


def collect(data):
    authenticate(data)
    img = Image(data)
    controls = control_bytes(img)
    _, fdes, _ = fde_extents(data)
    by_start = {}
    for f in fdes:
        checked(f['start'] not in by_start, 'duplicate FDE')
        by_start[f['start']] = f
    functions = []
    for start in FUNCTIONS:
        checked(start in by_start, 'missing FDE')
        f = by_start[start]
        raw = img.read(start, f['end'] - start)
        functions.append({'start': hex(start), 'end': hex(f['end']),
                          'fde': hex(f['fde']), 'length': len(raw),
                          'sha256': hashlib.sha256(raw).hexdigest()})
    edges = [edge(img, site, 0x36ff3c0) for site in (0x23576be, 0x4cabf77, 0x4cb4907)]
    edges.append(edge(img, 0x36ff3dc, 0x3705690))
    directs = [direct_edge(img, 0x2357586, 0x1e801c0),
               direct_edge(img, 0x4cabe3f, 0x445c750),
               direct_edge(img, 0x4cb47cf, 0x445c750),
               direct_edge(img, 0x37056d4, 0x3315e90),
               direct_edge(img, 0x3315ea3, 0x3bdc1b0),
               direct_edge(img, 0x3705b09, 0x33a83d0),
               direct_edge(img, 0x3705d00, 0x33a83d0)]
    branch_specs = [('list-count-in-range', 0x1e801d8, '76'),
                    ('copy-list-count-in-range', 0x445c768, '76'),
                    ('input-error', 0x2357595, '0f85'),
                    ('iterator-end', 0x235762a, '0f84'),
                    ('long-name', 0x2357686, '0f83'),
                    ('resolver-error', 0x23576ad, '0f85'),
                    ('empty-tree', 0x36ff3ea, '0f84'),
                    ('nonempty-nested-map', 0x36ff459, '75'),
                    ('wrong-dex', 0x36ff473, '75'),
                    ('row-out-of-range', 0x36ff486, '73'),
                    ('collector-mode-zero', 0x37056e8, '0f84'),
                    ('source-tag-two', 0x37058e7, '0f84'),
                    ('position-word-zero', 0x3705efb, '0f84'),
                    ('seed-multiply-overflow', 0x3bdc259, '70'),
                    ('seed-add-overflow', 0x3bdc265, '72')]
    branches = [branch(img, *item) for item in branch_specs]
    # Decode the normalized selector's rel32 jump table directly from file data.
    table = 0x3dd1b8
    slot = table + 9 * 4
    destination = table + struct.unpack('<i', img.read(slot, 4))[0]
    checked(destination == 0x2357565, 'vote selector mismatch')
    dispatch_copies = []
    for table_copy, expected in ((0x711064, 0x4cabe1e), (0x711244, 0x4cb47ae)):
        entry = table_copy + 9 * 4
        raw = img.read(entry, 4)
        target = table_copy + struct.unpack('<i', raw)[0]
        checked(target == expected, 'copied vote selector mismatch')
        dispatch_copies.append({'table_va': hex(table_copy), 'slot_va': hex(entry),
                                'slot_bytes': raw.hex(), 'destination': hex(target)})
    divisor = struct.unpack('<I', img.read(0x3bdc251, 4))[0]
    update_divisor = struct.unpack('<I', img.read(0x36ff478, 4))[0]
    magic = struct.unpack('<Q', img.read(0x36ff45d, 8))[0]
    shift = img.read(0x36ff46e, 1)[0]
    checked(divisor == update_divisor and divisor > 0 and shift == 11, 'division controls')
    # Unsigned division identity for every 64-bit value, using the extracted magic.
    delta = divisor * magic - (1 << (64 + shift))
    checked(0 <= delta < divisor and
            ((1 << 64) - 1) // divisor * delta + (divisor - 1) * magic < (1 << (64 + shift)),
            'magic quotient proof failed')
    checks = []
    # Explicitly distinguish missing, populated, invalid, and valid final-row cases.
    probes = [('missing', 0, False, 0, 0, 1, 0),
              ('occupied', 0, True, 1, 0, 1, 0),
              ('first', 0, True, 0, 0, 1, 0),
              ('last', divisor - 1, True, 0, 0, divisor, 6),
              ('row-at-end', divisor - 1, True, 0, 0, divisor - 1, 6),
              ('different-dex', divisor, True, 0, 0, 1, 1),
              ('dex-one-first', divisor, True, 0, 1, 1, 7),
              ('populated-bad-dex', divisor, True, 1, 0, 1, 255)]
    for name, asset, found, length, dex, rows, byte in probes:
        checks.append((name, asset, int(found), length, dex, rows, byte,
                       outcome(asset, found, length, dex, rows, byte, divisor)))
    result = {'binary_sha256': DIGEST, 'coordinate_system': 'ELF virtual address',
              'functions': functions, 'controls': controls, 'branches': branches,
              'indirect_calls': edges, 'direct_calls': directs,
              'vote_dispatch': {'normalized_selector': 9, 'raw_tag': 9 - int.from_bytes(img.read(0x2355f5d, 1), 'little', signed=True),
                                'table_va': hex(table),
                                'slot_va': hex(slot), 'slot_bytes': img.read(slot, 4).hex(),
                                'copies': dispatch_copies,
                                'destination': hex(destination)},
              'input_guards': {'max_entries': struct.unpack('<I', img.read(0x1e801d4, 4))[0],
                               'name_length_rejected_at': img.read(0x2357685, 1)[0],
                               'too_long_status': struct.unpack('<H', img.read(0x1e801dd, 2))[0],
                               'success_status': struct.unpack('<H', img.read(0x1e8022a, 2))[0]},
              'division': {'divisor': divisor, 'magic': hex(magic), 'shift': shift,
                           'delta': delta, 'proof_domain': 'all unsigned 64-bit inputs'},
              'notes': ['FDE extents describe unwind ranges, not a complete function census.',
                        'The collector has two modes. The completeness and semantic identity of all collected rows remain unresolved.',
                        'Decision cases model the checked final gate and are not target execution.']}
    seed_probes = [('empty', 0, 0, 0), ('two', 1, 0, 2),
                   ('last-dex', ((1 << 64) - 1) // divisor, 0, 1),
                   ('multiply-overflow', ((1 << 64) - 1) // divisor + 1, 0, 1),
                   ('addition-overflow', ((1 << 64) - 1) // divisor,
                    ((1 << 64) - 1) % divisor + 1, ((1 << 64) - 1) % divisor + 2),
                   ('empty-before-overflow', (1 << 64) - 1, 0, 0)]
    seeds = []
    for name, dex, start, end in seed_probes:
        try:
            outcome_text = ','.join(str(x) for x in seed_keys(dex, start, end, divisor)) or 'empty'
        except OverflowError as exc:
            outcome_text = str(exc)
        seeds.append((name, dex, start, end, outcome_text))
    return result, checks, seeds


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    try:
        result, cases, seeds = collect(TARGET.read_bytes())
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / 'evidence.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n', encoding='utf-8')
        buf = io.StringIO(newline='')
        writer = csv.writer(buf, delimiter='\t', lineterminator='\n')
        writer.writerow(('case', 'asset', 'entry', 'inner_count', 'dex', 'row_count', 'new_byte', 'result'))
        writer.writerows(cases)
        (args.out / 'decisions.tsv').write_text(buf.getvalue(), encoding='utf-8')
        buf = io.StringIO(newline='')
        writer = csv.writer(buf, delimiter='\t', lineterminator='\n')
        writer.writerow(('case', 'dex', 'start', 'end', 'result'))
        writer.writerows(seeds)
        (args.out / 'seeds.tsv').write_text(buf.getvalue(), encoding='utf-8')
    except (ValueError, OSError, struct.error, KeyError) as exc:
        print('size-decimal update: ' + str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
