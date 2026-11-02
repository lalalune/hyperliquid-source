#!/usr/bin/env python3
"""Static node 94 evidence for a resting-slot insertion and growth path."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SOURCE_PATH_SHA256 = '091d95a20511bab39f4b8f31d9150df25b5ffbf79cd632dc3788a4137cb7db94'
U64 = (1 << 64) - 1
COPIES = (0x28e0e40, 0x28e0f80, 0x45a4dd0)
GROW = 0x32d5940
FUNCTIONS = COPIES + (GROW,)
CALLERS = ((0x232c4ed, COPIES[0]), (0x232c63d, COPIES[1]),
           (0x42e87ed, COPIES[2]))
# Masks cover only complete x86-64 RIP-relative displacements, not opcodes.
MASKS = (0x4f, 0x68, 0xbc, 0xcb, 0xd7, 0xde, 0xe9, 0x127, 0x12f)
# Fixed bytes are anchored after displacement masking; full-body hashes below
# separately bind every unmasked and masked byte in each selected FDE.
EXPECTED_MASKED = '6f7a20c12ce97520c38d281b53ccb67a5fbc198db68bcef4f4b130aa5a5b4d23'
EXPECTED_GROW = '8898656a046dbd360eb5de17426b7e9c725e0af142da0ebf82371c9f7d27e2d8'
EXPECTED_RAW = (
    '4a822463fbcd02b764e3b6bb9e32725cefd64a8ba7d5356aa51ef5640f295ae6',
    '251309d9e37cec6babbb4c7872a21694eb5107fb3a86cdbd060f6da26c686e33',
    '9e44b29d08ac4ed7df150ff6dd915bae4e8318d77e1d25aea5930472a162aa24',
)
EXPECTED_LSDA = 'ffff01153f14ef01005381010000d401198f0200ed01460000'


class EvidenceError(ValueError):
    pass


def need(ok, message):
    if not ok:
        raise EvidenceError(message)


class Image:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)

    def offset(self, va, size=1):
        need(size >= 0, 'negative size')
        found = [s for s in self.sections if s['type'] != 8 and
                 s['address'] <= va and va + size <= s['address'] + s['size']]
        need(len(found) == 1, 'address lacks a unique file-backed section')
        s = found[0]
        return s['offset'] + va - s['address']

    def read(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off + size]

    def call(self, va):
        raw = self.read(va, 5)
        need(raw[0] == 0xe8, 'expected direct call opcode')
        return va + 5 + struct.unpack_from('<i', raw, 1)[0]

    def rip(self, va, op):
        raw = self.read(va, len(op) + 4)
        need(raw.startswith(op), 'expected RIP-relative opcode')
        return va + len(raw) + struct.unpack_from('<i', raw, len(op))[0]

    def branch(self, va, opcode):
        raw = self.read(va, 2)
        need(raw[0] == opcode, 'expected short conditional branch')
        return va + 2 + struct.unpack('b', raw[1:])[0]


def relative_relocations(image, slots, *, with_raw=False):
    found = {}
    for s in image.sections:
        if s['type'] != 4:
            continue
        need(s['size'] % 24 == 0, 'partial RELA record')
        for off in range(s['offset'], s['offset'] + s['size'], 24):
            address, info, addend = struct.unpack_from('<QQq', image.data, off)
            if address in slots:
                need(address not in found, 'duplicate relocation slot')
                found[address] = ((info, addend, off, image.data[off:off + 24])
                                  if with_raw else (info, addend))
    need(set(found) == set(slots), 'missing relocation')
    return found


def normalize(body):
    need(len(body) == 0x133, 'unexpected slot routine length')
    body = bytearray(body)
    for pos in MASKS:
        body[pos:pos + 4] = b'\0' * 4
    return bytes(body)


def lsda_rows(image, frame):
    va = frame['lsda']
    need(va is not None, 'slot routine lacks LSDA')
    offset = image.offset(va, 4)
    sec = next(s for s in image.sections if s['name'] == '.gcc_except_table')
    need(sec['type'] != 8 and sec['offset'] <= offset < sec['offset'] + sec['size'], 'LSDA outside exception table')
    end_section = sec['offset'] + sec['size']
    need(image.data[offset:offset + 3] == b'\xff\xff\x01', 'unsupported LSDA encoding')
    size, pos = uleb(image.data, offset + 3, end_section)
    end = pos + size
    need(end <= end_section, 'call-site table exceeds section')
    rows = []
    while pos < end:
        values = []
        for _ in range(4):
            value, pos = uleb(image.data, pos, end)
            values.append(value)
        start, count, landing, action = values
        need(start + count <= frame['end'] - frame['start'], 'LSDA range outside FDE')
        need(not landing or landing < frame['end'] - frame['start'], 'landing outside FDE')
        rows.append((frame['start'] + start, frame['start'] + start + count,
                     frame['start'] + landing if landing else 0, action))
    need(pos == end and image.data[offset:end].hex() == EXPECTED_LSDA, 'LSDA bytes changed')
    need(len(rows) == 4, 'unexpected call-site rows')
    return offset, image.data[offset:end], rows


def growth_capacity(capacity):
    need(isinstance(capacity, int) and 0 <= capacity <= U64, 'capacity outside u64')
    return max(4, (capacity * 2) & U64)


def simulate(key, length, capacity, occupied, next_free, vacancy, grow_ok, tag, source_cap):
    """Branch projection only; it does not run or emulate target instructions."""
    for n in (key, length, capacity, occupied, next_free, tag, source_cap):
        need(isinstance(n, int) and 0 <= n <= U64, 'projection value outside u64')
    occupied = min(occupied + 1, U64)
    if key == length:
        if key == capacity:
            new_capacity = growth_capacity(capacity)
            if not grow_ok:
                return ('growth-unwind', length, capacity, occupied, key,
                        int(tag != 2 and source_cap != 0),
                        ((source_cap << 3) & U64) if tag != 2 and source_cap else 0, new_capacity)
            capacity = new_capacity
        return ('append', (length + 1) & U64, capacity, occupied,
                (key + 1) & U64, 0, 0, 0)
    if key >= length or not vacancy:
        return ('invalid-unwind', length, capacity, occupied, key,
                int(source_cap != 0), (source_cap << 3) & U64, 0)
    return ('reuse', length, capacity, occupied, next_free, 0, 0, 0)


CASES = (
    ('empty-grow', 0, 0, 0, 0, 0, False, True, 1, 0),
    ('grow-from-four', 4, 4, 4, 4, 4, False, True, 1, 2),
    ('grow-from-two', 2, 2, 2, 2, 2, False, True, 1, 2),
    ('grow-from-three', 3, 3, 3, 3, 3, False, True, 1, 2),
    ('append-spare', 3, 3, 8, 3, 3, False, True, 1, 2),
    ('reuse-vacant', 1, 3, 8, 2, 7, True, True, 1, 2),
    ('beyond-length', 4, 3, 8, 2, 7, True, True, 1, 2),
    ('reuse-occupied', 1, 3, 8, 2, 7, False, True, 1, 2),
    ('grow-unwind-owned', 4, 4, 4, 4, 4, False, False, 1, 2),
    ('grow-unwind-tag-two', 4, 4, 4, 4, 4, False, False, 2, 2),
    ('grow-unwind-empty', 4, 4, 4, 4, 4, False, False, 1, 0),
    ('invalid-tag-two', 4, 3, 8, 2, 7, True, True, 2, 2),
    ('saturated-count', 1, 3, 8, U64, 7, True, True, 1, 2),
)


def make_rows(data):
    image = Image(data)
    cies, fdes = eh_frame_records(data, image.sections)
    unused_secs, table = unwind_index(data)
    index = {x['start']: x['fde'] for x in table}
    selected = {}
    for va in FUNCTIONS:
        match = [f for f in fdes if f['start'] == va]
        need(len(match) == 1 and index.get(va) == match[0]['fde'], 'missing or ambiguous indexed FDE')
        selected[va] = match[0]
    funcs, edges, lsdas, branches, routes, diagnostics = [], [], [], [], [], []
    for i, va in enumerate(COPIES):
        f = selected[va]
        need(f['end'] - va == 0x133, 'slot extent changed')
        body = image.read(va, f['end'] - va)
        need(hashlib.sha256(body).hexdigest() == EXPECTED_RAW[i], 'slot body changed')
        need(hashlib.sha256(normalize(body)).hexdigest() == EXPECTED_MASKED, 'normalized body changed')
        off, raw, rows = lsda_rows(image, f)
        for role, call_offset, landing_offset in (('growth', 0x4d, 0xef), ('invalid-slot', 0xe7, 0x10f)):
            call_site = va + call_offset
            lookup_pc = call_site + 5  # last byte of six-byte FF /2 call
            matching = [row for row in rows if row[0] <= lookup_pc < row[1]]
            need(len(matching) == 1 and matching[0][2] == va + landing_offset and matching[0][3] == 0,
                 'call-site landing association changed')
            routes.append((hex(va), role, hex(call_site), hex(lookup_pc), hex(matching[0][2]), matching[0][3]))
        for start, end, landing, action in rows:
            lsdas.append((hex(va), hex(f['lsda']), hex(off), raw.hex(), hex(start), hex(end),
                          hex(landing) if landing else '-', action))
        funcs.append((hex(va), hex(f['end']), hex(f['fde']), hex(f['cie']), hex(f['lsda']),
                      hex(image.offset(va, len(body))), len(body), hashlib.sha256(body).hexdigest()))
        for pos, opcode, purpose, expected in (
            (0x38, 0x75, 'key_ne_length', va + 0x86),
            (0x3d, 0x75, 'key_ne_capacity', va + 0x53),
            (0x86, 0x73, 'key_ge_length', va + 0xc0),
            (0x97, 0x75, 'slot_not_vacant', va + 0xc0),
            (0x101, 0x75, 'growth_cleanup_skip', va + 0x12b),
            (0x119, 0x74, 'invalid_cleanup_skip', va + 0x12b),
        ):
            dest = image.branch(va + pos, opcode)
            need(dest == expected, 'branch destination changed')
            branches.append((hex(va), hex(va + pos), hex(dest), purpose, image.read(va + pos, 2).hex()))
        for pos, op, role in ((0x4d, b'\xff\x15', 'growth'),
                              (0x66, b'\xff\x15', 'append-copy'),
                              (0xba, b'\xff\x25', 'reuse-tail-copy'),
                              (0xc8, b'\x48\x8b\x05', 'failure-format-helper'),
                              (0xe7, b'\xff\x15', 'invalid-slot-failure'),
                              (0x125, b'\xff\x15', 'cleanup-free')):
            slot = image.rip(va + pos, op)
            edges.append((hex(va + pos), op.hex(), hex(slot), role))
        literal = image.rip(va + 0xd4, b'\x48\x8d\x3d')
        literal_length = image.read(literal, 1)[0]
        raw_literal = image.read(literal, 1 + literal_length + 2)
        need(raw_literal == b'\x16expected vacant entry \xc0\x00', 'diagnostic literal changed')
        diagnostics.append((hex(va), hex(va + 0xd4), hex(literal), literal_length,
                            raw_literal[1:-2].decode('ascii'), raw_literal.hex()))
        need(image.rip(va + 0xdb, b'\x48\x8d\x15') == (0x56c73e8 if i < 2 else 0x572afd0), 'source location reference changed')
        need(image.call(va + 0x12e) == 0x5660110, 'unwind edge changed')
        site = CALLERS[i][0]
        need(image.read(site - 13, 13) == bytes.fromhex('498b5e204c89f74889de4c89fa'), 'context arguments changed')
        need(image.call(site) == va, 'context caller edge changed')
        edges.append((hex(CALLERS[i][0]), 'e8', hex(va), 'slot-entry-context'))
        edges.append((hex(va + 0x12e), 'e8', hex(image.call(va + 0x12e)), 'resume-edge'))
    f = selected[GROW]
    need(f['lsda'] is None and f['end'] - GROW == 0x64, 'growth extent changed')
    body = image.read(GROW, f['end'] - GROW)
    need(hashlib.sha256(body).hexdigest() == EXPECTED_GROW, 'growth bytes changed')
    funcs.append((hex(GROW), hex(f['end']), hex(f['fde']), hex(f['cie']), '-',
                  hex(image.offset(GROW, len(body))), len(body), hashlib.sha256(body).hexdigest()))
    target = image.call(GROW + 0x35)
    need(target == 0x32d6740, 'growth delegate changed')
    edges.append((hex(GROW + 0x35), 'e8', hex(target), 'allocation-delegate-edge'))
    error_slot = image.rip(GROW + 0x5e, b'\xff\x15')
    edges.append((hex(GROW + 0x5e), 'ff15', hex(error_slot), 'growth-error-edge'))
    dest = image.branch(GROW + 0x3e, 0x74)
    need(dest == GROW + 0x54, 'growth error branch changed')
    branches.append((hex(GROW), hex(GROW + 0x3e), hex(dest), 'delegate_tag_one', image.read(GROW + 0x3e, 2).hex()))
    slot_a = image.rip(COPIES[0] + 0x4d, b'\xff\x15')
    slot_b = image.rip(COPIES[1] + 0x4d, b'\xff\x15')
    need(image.rip(COPIES[2] + 0x4d, b'\xff\x15') == slot_b, 'third growth slot changed')
    reloc = relative_relocations(image, (slot_a, slot_b, 0x576dfe0, 0x576e010, 0x576e090, 0x576e098, error_slot, 0x56c73e8, 0x572afd0), with_raw=True)
    need(all(reloc[x][:2] == (8, GROW) for x in (slot_a, slot_b)), 'growth relocation changed')
    for va in COPIES:
        need(image.rip(va + 0x66, b'\xff\x15') == 0x576dfe0 and
             image.rip(va + 0xba, b'\xff\x25') == 0x576dfe0 and
             image.rip(va + 0xc8, b'\x48\x8b\x05') == 0x576e090 and
             image.rip(va + 0xe7, b'\xff\x15') == 0x576e098 and
             image.rip(va + 0x125, b'\xff\x15') == 0x576e010,
             'slot external edge changed')
    # Resolve the one imported copy routine from ELF symbol and RELA records.
    info, addend = reloc[0x576dfe0][:2]
    sym_index, kind = info >> 32, info & 0xffffffff
    dynsym = next(s for s in image.sections if s['name'] == '.dynsym')
    dynstr = next(s for s in image.sections if s['name'] == '.dynstr')
    need(kind == 6 and addend == 0 and (sym_index + 1) * 24 <= dynsym['size'], 'copy relocation changed')
    name_offset = struct.unpack_from('<I', image.data, dynsym['offset'] + sym_index * 24)[0]
    need(name_offset < dynstr['size'], 'symbol name outside dynamic strings')
    string_start = dynstr['offset'] + name_offset
    string_end = image.data.find(b'\0', string_start, dynstr['offset'] + dynstr['size'])
    need(string_end >= 0 and image.data[string_start:string_end] == b'memcpy', 'copy import changed')
    imports = [(hex(0x576dfe0), kind, sym_index, 'memcpy')]
    reloc_rows = [(hex(slot), hex(rec[0]), hex(rec[1]), hex(rec[2]), rec[3].hex())
                  for slot, rec in sorted(reloc.items())]
    locations = []
    for slot in (0x56c73e8, 0x572afd0):
        rel = reloc[slot][:2]
        need(rel[0] == 8, 'location relocation type changed')
        pointer, size, line, column = struct.unpack('<QQII', image.read(slot, 24))
        path = image.read(rel[1], size)
        need(pointer == 0 and path.endswith(b'l1/src/slab/slab.rs') and
             hashlib.sha256(path).hexdigest() == SOURCE_PATH_SHA256 and (line, column) == (79, 21), 'source location changed')
        locations.append((hex(slot), hex(rel[1]), size, line, column, 'l1/src/slab/slab.rs',
                          image.read(slot, 24).hex(), hashlib.sha256(path).hexdigest()))
    # The shared growth target is a boundary: its delegate is deliberately
    # not decoded. These constants are read from validated instruction bytes.
    sample = image.read(COPIES[0], 0x133)
    growth = image.read(GROW, 0x64)
    layout = [
        ('slab_capacity', sample[0x3c] >> 6, hex(COPIES[0] + 0x3c)),
        ('slab_data_pointer', sample[0x5d], hex(COPIES[0] + 0x5d)),
        ('slab_length', sample[0x1e], hex(COPIES[0] + 0x1e)),
        ('slab_occupied', sample[0x22], hex(COPIES[0] + 0x22)),
        ('slab_free_head', sample[0xa3], hex(COPIES[0] + 0xa3)),
        ('vacant_discriminant', sample[0x96], hex(COPIES[0] + 0x96)),
        ('entry_stride', struct.unpack_from('<I', sample, 0x56)[0], hex(COPIES[0] + 0x56)),
        ('source_capacity', sample[0x45], hex(COPIES[0] + 0x45)),
        ('source_pointer', sample[0x49], hex(COPIES[0] + 0x49)),
        ('source_element_shift', sample[0x106], hex(COPIES[0] + 0x106)),
        ('growth_minimum', struct.unpack_from('<I', growth, 0x17)[0], hex(GROW + 0x17)),
        ('growth_alignment', struct.unpack_from('<I', growth, 0x28)[0], hex(GROW + 0x28)),
        ('growth_element_size', struct.unpack_from('<I', growth, 0x2e)[0], hex(GROW + 0x2e)),
    ]
    need([row[1] for row in layout] == [0, 8, 16, 24, 32, 2, 248, 80, 88, 3, 4, 8, 248], 'layout operands changed')
    contexts = [(hex(site - 13), image.read(site - 13, 18).hex()) for site, _ in CALLERS]
    witness_spec = (
        ('counter-before-check', COPIES[0] + 0x17, COPIES[0] + 0x38),
        ('append-capacity-choice', COPIES[0] + 0x38, COPIES[0] + 0x53),
        ('append-copy-and-writes', COPIES[0] + 0x53, COPIES[0] + 0x86),
        ('reuse-and-invalid-guard', COPIES[0] + 0x86, COPIES[0] + 0xc0),
        ('invalid-slot-failure', COPIES[0] + 0xc0, COPIES[0] + 0xef),
        ('growth-cleanup', COPIES[0] + 0xef, COPIES[0] + 0x10f),
        ('invalid-slot-cleanup', COPIES[0] + 0x10f, COPIES[0] + 0x133),
        ('growth-wrapper', GROW, selected[GROW]['end']),
    )
    witnesses = [(label, hex(start), hex(end), image.read(start, end - start).hex())
                 for label, start, end in witness_spec]
    cfi, cie_rows = [], []
    for va in FUNCTIONS:
        f = selected[va]
        cie = cies[f['cie']]
        need(cie['augmentation'] == ('zR' if va == GROW else 'zPLR'), 'CIE profile changed')
        cie_rows.append((hex(va), hex(cie['va']), cie['augmentation'], cie['code_align'], cie['data_align'],
                         hex(cie['fde_encoding']),
                         hex(cie['lsda_encoding']) if cie['lsda_encoding'] is not None else '-',
                         hex(cie['personality_slot']) if cie['personality_slot'] is not None else '-'))
        for kind, loc in (('fde', f['fde']), ('cie', f['cie'])):
            size = struct.unpack('<I', image.read(loc, 4))[0] + 4
            need(8 <= size <= 4096, 'invalid CFI size')
            cfi.append((hex(va), kind, hex(loc), image.read(loc, size).hex()))
    case_rows = []
    for name, *args in CASES:
        result = simulate(*args)
        case_rows.append((name, *args, *result))
    return {'functions': funcs, 'branches': branches, 'calls': edges, 'lsda': lsdas,
            'relocations': reloc_rows, 'locations': locations, 'imports': imports, 'cases': case_rows,
            'layout': layout, 'contexts': contexts, 'cfi': cfi, 'routes': routes, 'diagnostics': diagnostics,
            'witnesses': witnesses, 'cie': cie_rows,
            'bodies': [(hex(v), image.read(v, selected[v]['end'] - v).hex()) for v in FUNCTIONS]}


def render_tsv(header, rows):
    stream = io.StringIO(newline='')
    writer = csv.writer(stream, delimiter='\t', lineterminator='\n')
    writer.writerow(header)
    writer.writerows(rows)
    return stream.getvalue().encode()


def render(data):
    need(hashlib.sha256(data).hexdigest() == SHA256, 'target digest mismatch')
    r = make_rows(data)
    specs = {
        'functions.tsv': (('start_va','end_va','fde_va','cie_va','lsda_va','file_offset','body_bytes','sha256'), 'functions'),
        'branches.tsv': (('function_va','branch_va','target_va','condition','bytes'), 'branches'),
        'calls.tsv': (('site_va','opcode','target_va_or_slot','role'), 'calls'),
        'lsda.tsv': (('function_va','lsda_va','file_offset','raw_table_hex','start_va','end_va','landing_va','action'), 'lsda'),
        'relocations.tsv': (('slot_va','info','addend_va','record_file_offset','raw_rela_hex'), 'relocations'),
        'locations.tsv': (('slot_va','path_va','path_length','line','column','path_suffix','raw_location_hex','full_path_sha256'), 'locations'),
        'bodies.tsv': (('start_va','raw_hex'), 'bodies'),
        'layout.tsv': (('field','value','operand_va'), 'layout'),
        'contexts.tsv': (('start_va','raw_hex'), 'contexts'),
        'imports.tsv': (('slot_va','relocation_type','symbol_index','symbol'), 'imports'),
        'cfi.tsv': (('function_va','kind','record_va','raw_hex'), 'cfi'),
        'cie.tsv': (('function_va','cie_va','augmentation','code_align','data_align','fde_encoding','lsda_encoding','personality_slot'), 'cie'),
        'exception-routes.tsv': (('function_va','role','call_va','return_pc_minus_one','landing_va','action'), 'routes'),
        'diagnostics.tsv': (('function_va','lea_va','literal_va','text_bytes','text','raw_hex'), 'diagnostics'),
        'witnesses.tsv': (('role','start_va','end_va','raw_hex'), 'witnesses'),
        'cases.tsv': (('case','key','length','capacity','occupied','vacant_next','vacant','grow_ok','source_tag','source_capacity','projected_path','new_length','new_capacity','new_occupied','new_free','cleanup_call','cleanup_bytes','requested_capacity'), 'cases'),
    }
    out = {name: render_tsv(header, r[key]) for name, (header, key) in specs.items()}
    out['summary.json'] = (json.dumps({'target_sha256': SHA256, 'coordinate_system': 'linked ELF VA',
        'function_count': len(r['functions']), 'slot_copies': len(COPIES),
        'masked_displacement_fields_per_copy': len(MASKS), 'normalized_slot_sha256': EXPECTED_MASKED,
        'branch_rows': len(r['branches']), 'edge_rows': len(r['calls']), 'lsda_rows': len(r['lsda']),
        'exception_routes': len(r['routes']),
        'case_rows': len(r['cases']), 'cases_are': 'synthetic branch projections, not target executions',
        'normalization': 'nine four-byte RIP-relative displacements; all other bytes retained'},
        sort_keys=True, indent=2) + '\n').encode()
    return out


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', required=True, type=Path)
    args = p.parse_args()
    generated = render(TARGET.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    for name, content in sorted(generated.items()):
        (args.out / name).write_bytes(content)


if __name__ == '__main__':
    main()
