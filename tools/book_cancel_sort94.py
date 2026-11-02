#!/usr/bin/env python3
"""Extract cancellation ID sort control flow from authenticated node 94 ELF bytes."""
import argparse
import csv
import hashlib
import io
import itertools
import json
from pathlib import Path
import struct
import sys

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
FUNCTIONS = {
    0x4497a90: (0x4498022, 'bf665db5f3a63b27ae18b6aa81c17b0ee3264ad56086e1f8a85f8b2e2d85f0a3', 'partition'),
    0x45c35b0: (0x45c366f, 'f67989ba39d179fb513972a647a359207dd2ef3a9ab054d50fdc304d2d303990', 'pivot'),
    0x4912a50: (0x4912d13, 'dd0aa09a10e58302a205c8e2ea0dac5c9f1428519d96b4a60c26bfb5c666f38a', 'four-item network'),
    0x4918d30: (0x49190b7, '9ae5e9107aca9a7ef4fd40d9b6dccee0cfa521a205a1422ea0a84b0ff9c05ed3', 'small sort'),
    0x4dbd490: (0x4dbdb5e, '3c4cf31225ada53f7cb30d9d2b16c805db9e47f30cc63ae8dbcb6167d901c1f3', 'run and merge'),
}
# Instruction windows were selected through bounded manual review. They are exact,
# not variable-length disassembly or masks.
PINS = (
    ('context book user root', 0x26e4266, '488b97b80000004885d20f845a030000'),
    ('context book user height', 0x26e4294, '488b81c00000004889442418'),
    ('context slot eligibility and key', 0x256367d, '498b4c2448488b10483b511073e5488b41084869caf8000000833c080274d44801c84805d8000000'),
    ('context set key load', 0x26e4550, '488b74c8088b4310898424000100000f10030f298424'),
    ('context empty candidates', 0x27e7cbf, '4c8b7c24104d85ff0f8499000000'),
    ('context singleton candidates', 0x27e7cd8, '4983ff010f85bf000000'),
    ('context cutoff', 0x27e7da1, '4983ff150f83f0000000'),
    ('context long call', 0x27e7e9b, '488d5424304c89f74c89feff15a4d0f802'),
    ('context sort return', 0x27e7eac, '4d89fce92efeffff'),
    ('scratch formula', 0x4486d23, '4889f148d1e94889f04829c84881fe40420f00bb40420f00480f42de4839c3480f46d8'),
    ('scratch cutoff', 0x4486d46, '4881fb01020000722e4c8d24dd0000000048c1e83d0f95c0'),
    ('sort flag and run call', 0x4486da7, '4531c04883fe41410f92c04c89fa4d89f1e8d3669300'),
    ('run length and scale', 0x4dbd4b0, '4883fe020f82920600004989d74889cf48b8000000000000004031d248f7f64883fa014883d8ff'),
    ('run short threshold', 0x4dbd4dc, '4881fe0110000048897424384889f0731d48d1e84889f14829c14883f940b840000000480f42c14889442418'),
    ('run long threshold', 0x4dbd50a, '4883c801480fbdc889c8d1e883e10101c1b80100000048d3e048d3ee4801c648d1ee4889742418'),
    ('descending run gate', 0x4dbd647, '488b4424084c8b00488b50084c39c273254983f90275'),
    ('backward merge choice', 0x4dbda50, '488b4af8498b76f831ff4531c04839f1400f92c7410f93c0480f47f14889304f8d34c64983c6f8488d14fa4883c2f8'),
    ('forward merge choice', 0x4dbdaa0, '498b3e4c8b0631c04531c94c39c70f92c1410f93c14c0f42c74d8904244a8d34ce4983c4084839d60f84aafdffff88c8'),
    ('partition small dispatch', 0x4497ab1, '4883fe2173204c89e74c89ee4c89fa488b4c24184c8b842480000000e85e124800e9ff040000'),
    ('partition depth and pivot cutoff', 0x4497b00, '83ed010f82ac0400004c89f148c1e9034889c848c1e0054c01e0486bd1384c01e24983fe40896c24'),
    ('partition selected failures', 0x4497ff1, '0f0b488d3dc1cb25fc488d158f7e2801be13000000ff158c602d01488d0d957e28014889df4c89f64c89f2ff15be622d01'),
    ('small length and scratch guard', 0x4918d3b, '4883fe020f823d0300004889f3488d46104839c10f82420300004989d64989ff4989dc49d1ec'),
    ('small four network', 0x4918dae, '498b4708498b771831c931d2493b070f93c10f92c231ff493b7710400f92c78d770283f7034d8b04f74d8b0cd74d39c84d8b14ff498b04cf4189f3440f42d94939c20f42ce440f42df490f47c2488904244d39c84b8b34df0f42ca498b0ccf4d0f42c84d890e4839ce'),
    ('small network middle stores', 0x4918e14, '4839ce4889ca480f42d649895608480f47ce'),
    ('small network final stores', 0x4918e7c, '49894e104c0f47c5488b042449894618'),
    ('four-item output selection', 0x4912a5b, '488b4f084c8b4f1831c04531c0483b0f0f93c0410f92c04531d24c3b4f10410f92c24c8d0cc7458d5a024183f2034a8b1cdf4a8b0cc74839cb4e8b34d74589df440f42f84c3b34c7410f42c3450f42fa4e8d14d74d0f42d14839cb4e8d0cff4e8b1cff410f42c0480f42cb4c3b1cc7488d04c74989c04d0f42c148890a4d8b004c0f42c84c894208498b01488942104d8b024c894218'),
    ('pivot recursive gate', 0x45c35c4, '48b8f8ffffffffffff1f4885c1746148c1e9034989cc49c1e4054b8d34264c6be9384b8d142e'),
    ('pivot three-way selection', 0x45c3634, '498b06488b0b4839c80f92c2498b374839f00f92c030d04839f10f92c130d1490f45df84c0490f45de4889d8'),
)
# Conditional branches are selected, not a complete CFG.
BRANCHES = (
    (0x2563689, 'slot index >= slab length', 0x2563670),
    (0x256369a, 'slot low dword == 2', 0x2563670),
    (0x27e7da5, 'candidate count >= 21', 0x27e7e9b),
    (0x4486d4d, 'scratch count < 513', 0x4486d7d),
    (0x4486d70, 'byte layout passes local tests', 0x4486d87),
    (0x4486da5, 'allocation result is null', 0x4486de9),
    (0x4486dc4, 'scratch count <= 512', 0x4486dd8),
    (0x4dbd4b4, 'input length < 2', 0x4dbdb4c),
    (0x4dbd4eb, 'input length >= 4097', 0x4dbd50a),
    (0x4dbd656, 'second key >= first key unsigned', 0x4dbd67d),
    (0x4dbd6af, 'next key < previous key unsigned', 0x4dbd6ec),
    (0x4dbd6df, 'next key >= previous key unsigned', 0x4dbd6ec),
    (0x4497ab5, 'partition length >= 33', 0x4497ad7),
    (0x4497b03, 'depth decrement borrows', 0x4497fb5),
    (0x4497b29, 'partition length >= 64', 0x4497b60),
    (0x4497ba3, 'scratch length below current partition length', 0x4497ff1),
    (0x4918d3f, 'small length < 2', 0x4919082),
    (0x4918d4f, 'small scratch below length plus 16', 0x4919097),
    (0x4918d65, 'small length <= 15', 0x4918da4),
    (0x4918da8, 'small length <= 7', 0x4918ed1),
    (0x45c35d1, 'pivot recursion mask is zero', 0x45c3634),
)
DIRECT = (
    (0x26e4441, 0x27e7c90, 'context user sweep to collector adapter'),
    (0x27e7cba, 0x2563650, 'context adapter to collector'),
    (0x27e7d4e, 0x1b0de70, 'context sorted vector to tree builder'),
    (0x26e4536, 0x286b520, 'context tree iterator'),
    (0x26e457f, 0x26de3d0, 'context order removal'),
    (0x4486db8, 0x4dbd490, 'context wrapper to run'),
    (0x4497acd, 0x4918d30, 'partition to small'),
    (0x4497b6e, 0x45c35b0, 'partition to pivot'),
    (0x4497fd1, 0x4dbd490, 'partition fallback to run'),
    (0x4918d71, 0x4912a50, 'small to four-item network'),
    (0x4918d86, 0x4912a50, 'small to four-item network'),
    (0x45c35f4, 0x45c35b0, 'pivot recursion'),
    (0x45c360e, 0x45c35b0, 'pivot recursion'),
    (0x45c362c, 0x45c35b0, 'pivot recursion'),
)
INDIRECT = (
    (0x27e7ea6, 0x5774f50, 0x4486d10, 'context long-sort entry'),
    (0x27e6bd1, 0x5774f50, 0x4486d10, 'context long-sort entry'),
    (0x4dbd5d1, 0x57768a0, 0x4497a90, 'run to partition'),
    (0x4dbd97e, 0x57768a0, 0x4497a90, 'run to partition'),
    (0x4dbd9d0, 0x57768a0, 0x4497a90, 'run to partition'),
    (0x4dbdb46, 0x57768a0, 0x4497a90, 'run to partition'),
    (0x4497da5, 0x57768a0, 0x4497a90, 'partition recursion'),
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def check_digest(data):
    require(hashlib.sha256(data).hexdigest() == DIGEST, 'input SHA-256 mismatch')


class Image:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)

    def read(self, address, size, executable=False):
        require(type(address) is int and type(size) is int and address >= 0 and size >= 0, 'invalid address or size')
        choices = [s for s in self.sections if s['type'] != 8 and s['size'] and
                   (not executable or s['flags'] & 4) and s['address'] <= address and
                   address + size <= s['address'] + s['size']]
        require(len(choices) == 1, 'range not uniquely file backed')
        section = choices[0]
        offset = section['offset'] + address - section['address']
        require(offset + size <= len(self.data), 'truncated file range')
        return bytes(self.data[offset:offset + size])

    def offset(self, address, size):
        self.read(address, size)
        s = next(s for s in self.sections if s['type'] != 8 and s['size'] and
                 s['address'] <= address and address + size <= s['address'] + s['size'])
        return s['offset'] + address - s['address']

    def relocation_rows(self, slots):
        result = []
        sections_found = [s for s in self.sections if s['name'] == '.rela.dyn' and s['type'] == 4]
        require(len(sections_found) == 1 and sections_found[0]['size'] % 24 == 0, 'invalid relocation section')
        sec = sections_found[0]
        for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
            addr, info, addend = struct.unpack_from('<QQq', self.data, off)
            if addr in slots:
                result.append((hex(addr), hex(off), hex(info), hex(addend), bytes(self.data[off:off + 24]).hex()))
        require(len(result) == len(slots), 'missing or duplicate relocation')
        return sorted(result)

    def relatives(self, slots):
        found = {}
        rows = [s for s in self.sections if s['name'] == '.rela.dyn' and s['type'] == 4]
        require(len(rows) == 1 and rows[0]['size'] % 24 == 0, 'invalid relocation section')
        section = rows[0]
        for off in range(section['offset'], section['offset'] + section['size'], 24):
            addr, info, addend = struct.unpack_from('<QQq', self.data, off)
            if addr in slots:
                require(addr not in found and info == 8, 'bad or duplicate relative relocation')
                found[addr] = addend
        require(set(found) == set(slots), 'missing relative relocation')
        return found


def pin_rows(image):
    result = []
    for name, address, expected in PINS:
        raw = image.read(address, len(bytes.fromhex(expected)), True)
        require(raw == bytes.fromhex(expected), 'instruction bytes changed at ' + hex(address))
        result.append((name, hex(address), raw.hex()))
    return result


def function_rows(image):
    _, index = unwind_index(image.data)
    _, fdes = eh_frame_records(image.data, image.sections)
    result = []
    for start, (end, expected_hash, role) in sorted(FUNCTIONS.items()):
        matches = [f for f in fdes if f['start'] == start]
        headers = [e for e in index if e['start'] == start]
        require(len(matches) == len(headers) == 1, 'missing or duplicate FDE')
        f = matches[0]
        require(f['end'] == end and f['fde'] == headers[0]['fde'], 'FDE range/index mismatch')
        body = image.read(start, end - start, True)
        actual_hash = hashlib.sha256(body).hexdigest()
        require(actual_hash == expected_hash, 'function body bytes changed at ' + hex(start))
        result.append((role, hex(start), hex(end), len(body), hex(f['fde']),
                       '' if f['lsda'] is None else hex(f['lsda']), hex(image.offset(start, len(body))), actual_hash, body.hex()))
    return result


def lsda_rows(image, start, end, address):
    tables = [s for s in image.sections if s['name'] == '.gcc_except_table' and s['type'] != 8]
    require(len(tables) == 1 and tables[0]['address'] <= address < tables[0]['address'] + tables[0]['size'],
            'LSDA outside exception table')
    limit = tables[0]['address'] + tables[0]['size']
    data = image.read(address, min(128, limit - address))
    require(data[:3] == b'\xff\xff\x01', 'unsupported LSDA header')
    length, pos = uleb(data, 3, len(data))
    limit = pos + length
    require(limit <= len(data), 'truncated LSDA table')
    rows = []
    while pos < limit:
        fields = []
        for _ in range(4):
            x, pos = uleb(data, pos, limit)
            fields.append(x)
        low, size, landing, action = fields
        require(size > 0 and low + size <= end - start and action == 0, 'invalid LSDA range or action')
        require(not landing or landing < end - start, 'LSDA landing outside FDE')
        rows.append((start + low, start + low + size, start + landing if landing else None, action))
    require(pos == limit and all(a[1] <= b[0] for a, b in zip(rows, rows[1:])), 'overlapping LSDA ranges')
    return rows


def branch(image, address):
    first = image.read(address, 2, True)
    if 0x70 <= first[0] <= 0x7f:
        return first, address + 2 + struct.unpack('<b', first[1:])[0]
    require(first[0] == 0x0f and 0x80 <= first[1] <= 0x8f, 'unexpected branch encoding')
    raw = image.read(address, 6, True)
    return raw, address + 6 + struct.unpack('<i', raw[2:])[0]


def calls(image):
    rel = image.relatives({slot for _, slot, _, _ in INDIRECT})
    rows = []
    for address, expected, role in DIRECT:
        raw = image.read(address, 5, True)
        require(raw[0] == 0xe8, 'unexpected direct call opcode')
        target = address + 5 + struct.unpack('<i', raw[1:])[0]
        require(target == expected, 'direct call target changed')
        rows.append((role, hex(address), raw.hex(), '', hex(target)))
    for address, slot, expected, role in INDIRECT:
        raw = image.read(address, 6, True)
        require(raw[:2] == b'\xff\x15', 'unexpected indirect call opcode')
        decoded = address + 6 + struct.unpack('<i', raw[2:])[0]
        require(decoded == slot and rel[slot] == expected, 'indirect call binding changed')
        rows.append((role, hex(address), raw.hex(), hex(slot), hex(expected)))
    return rows


def constants(image):
    def byte(addr): return image.read(addr, 1, True)[0]
    def u32(addr): return struct.unpack('<I', image.read(addr, 4, True))[0]
    values = {'external_sort_min': byte(0x27e7da4),
              'scratch_max_stack': u32(0x4486d49) - 1,
              'scratch_cap': u32(0x4486d32),
              'flag_limit': byte(0x4486dad),
              'run_long_min': u32(0x4dbd4df),
              'run_small_cap': byte(0x4dbd4f9),
              'partition_small_min': byte(0x4497ab4),
              'pivot_recursive_min': byte(0x4497b24),
              'small_scratch_extra': byte(0x4918d4b)}
    expected = {'external_sort_min': 21, 'scratch_max_stack': 512, 'scratch_cap': 1000000,
                'flag_limit': 65, 'run_long_min': 4097, 'run_small_cap': 64,
                'partition_small_min': 33, 'pivot_recursive_min': 64, 'small_scratch_extra': 16}
    require(values == expected, 'constant mismatch')
    return values


def layout_rows(image):
    entries = (
        ('book user-map root offset', 0x26e4269, 4, 0xb8),
        ('book user-map height offset', 0x26e4297, 4, 0xc0),
        ('collector slab-header pointer offset', 0x2563681, 1, 0x48),
        ('slab entry-count offset', 0x2563688, 1, 0x10),
        ('slab entry-pointer offset', 0x256368e, 1, 0x08),
        ('slot stride', 0x2563692, 4, 0xf8),
        ('vacant low-dword tag', 0x2563699, 1, 2),
        ('live slot key offset', 0x25636a1, 4, 0xd8),
        ('tree node qword key base', 0x26e4554, 1, 0x08),
    )
    rows = []
    for role, address, width, expected in entries:
        raw = image.read(address, width, True)
        value = int.from_bytes(raw, 'little')
        require(value == expected, 'layout immediate changed')
        rows.append((role, hex(address), width, raw.hex(), hex(value)))
    return rows


def four_network(values, mutant=False):
    # Scalar projection of the checked first network, never target execution.
    a = list(values)
    require(len(a) == 4 and all(type(x) is int and 0 <= x < 1 << 64 for x in a), 'expected four u64 keys')
    lo1 = 1 if a[1] < a[0] else 0
    hi1 = 0 if a[1] < a[0] else 1
    lo2 = 3 if a[3] < a[2] else 2
    hi2 = 2 if a[3] < a[2] else 3
    middle_a = hi1 if a[lo2] < a[lo1] else lo2
    middle_b = lo2 if a[hi2] < a[hi1] else hi1
    if a[hi2] < a[hi1]:
        middle_a = hi2
    if a[lo2] < a[lo1]:
        middle_b = lo1
    if mutant:
        middle_a = lo2
    return (min(a[lo1], a[lo2]), min(a[middle_a], a[middle_b]),
            max(a[middle_a], a[middle_b]), max(a[hi1], a[hi2]))


def pivot_leaf(values, mutant=False):
    # Index selection follows the checked leaf comparisons, including equal keys.
    require(len(values) == 3 and all(type(x) is int and 0 <= x < 1 << 64 for x in values), 'expected three u64 keys')
    x, y, z = values
    xy = x < y
    xz = x < z
    yz = y < z
    chosen = 2 if yz != xy else 1
    if xz != xy and not mutant:
        chosen = 0
    return chosen


def buffer_projection(n, c):
    require(type(n) is int and 0 <= n < 1 << 64, 'expected a u64 length')
    half = n - n // 2
    scratch = max(min(n, c['scratch_cap']), half)
    return scratch, 'stack' if scratch <= c['scratch_max_stack'] else 'heap', int(n < c['flag_limit'])


def run_projection(n, c):
    require(type(n) is int and 2 <= n < 1 << 64, 'run formula requires a u64 length of at least two')
    if n < c['run_long_min']:
        threshold = min(c['run_small_cap'], n - n // 2)
    else:
        log = (n | 1).bit_length() - 1
        shift = (log + 1) // 2
        threshold = ((n >> shift) + (1 << shift)) // 2
    scale = ((1 << 62) + n - 1) // n
    return threshold, scale


def analyze(data, verify_digest=True):
    if verify_digest:
        check_digest(data)
    image = Image(data)
    pins = pin_rows(image)
    layout = layout_rows(image)
    functions = function_rows(image)
    c = constants(image)
    edges = calls(image)
    exception_ranges = lsda_rows(image, 0x4918d30, 0x49190b7, 0xb8638c)
    exceptional = [r for r in exception_ranges if r[0] <= 0x4919091 < r[1]]
    require(len(exceptional) == 1 and exceptional[0][2] == 0x4919099, 'small-sort cleanup landing changed')
    branches = []
    for address, predicate, expected in BRANCHES:
        raw, target = branch(image, address)
        require(target == expected, 'conditional destination changed')
        branches.append((hex(address), predicate, raw.hex(), hex(target), hex(address + len(raw))))
    counts = (20, 21, 32, 33, 64, 65, 511, 512, 513, 4096, 4097,
              999999, 1000000, 1000001, 2000000, 2000001)
    buffers = [(n, *buffer_projection(n, c)) for n in counts]
    runs = [(n, *run_projection(n, c)) for n in counts if n >= 2]
    networks = []
    killed = 0
    for values in itertools.product(range(4), repeat=4):
        result = four_network(values)
        require(result == tuple(sorted(values)), 'network projection differs from sorted reference')
        killed += four_network(values, mutant=True) != result
        networks.append((*values, *result, int(four_network(values, mutant=True) != result)))
    require(killed > 0, 'network negative control did not differ')
    pivots = []
    pivot_killed = 0
    for values in itertools.product(range(4), repeat=3):
        index = pivot_leaf(values)
        require(values[index] == sorted(values)[1], 'pivot projection differs from median reference')
        different = values[pivot_leaf(values, mutant=True)] != values[index]
        pivot_killed += different
        pivots.append((*values, index, values[index], int(different)))
    require(pivot_killed > 0, 'pivot negative control did not differ')
    # Element equality has no identity in a plain u64 list; do not claim stable payload ordering.
    merges = []
    for left, right in ((0, 1), (1, 0), (1, 1), (0, (1 << 64) - 1), ((1 << 64) - 1, 0)):
        merges.append((left, right, min(left, right), max(left, right),
                       'first' if left < right else 'second', 'first' if left > right else 'second'))
    summary = {'target_sha256': DIGEST, 'coordinates': 'linked ELF virtual addresses; file offsets separate',
               'constants': c, 'selected_fde_count': len(functions), 'selected_branch_count': len(branches),
               'selected_call_count': len(edges), 'network_projection_cases': len(networks),
               'network_mutant_differences': killed, 'pivot_projection_cases': len(pivots),
               'pivot_mutant_differences': pivot_killed,
               'scope': 'Selected static paths only. Synthetic projections are not target execution. No complete sort correctness, ABI or order-book gate is established.'}
    return {'functions.tsv': (('role','start_va','end_va','bytes','fde_va','lsda_va','file_offset','sha256','body_hex'), functions),
            'anchors.tsv': (('role','va','bytes_hex'), pins),
            'layout.tsv': (('role','immediate_va','bytes','raw_hex','value'), layout),
            'branches.tsv': (('va','taken_predicate','bytes_hex','target_va','fallthrough_va'), branches),
            'calls.tsv': (('role','va','bytes_hex','relocation_slot_va','target_va'), edges),
            'unwind.tsv': (('fde_start','range_start_va','range_end_va','landing_va','action'),
                           [(hex(0x4918d30), hex(a), hex(b), '' if landing is None else hex(landing), action)
                            for a, b, landing, action in exception_ranges]),
            'relocations.tsv': (('slot_va','file_offset','info','addend','record_hex'), image.relocation_rows({slot for _, slot, _, _ in INDIRECT})),
            'buffer-projections.tsv': (('count','scratch_elements','storage','flag'), buffers),
            'run-projections.tsv': (('count','run_threshold','scale_ceil_2p62_div_count'), runs),
            'network-projections.tsv': (('a','b','c','d','out0','out1','out2','out3','mutant_differs'), networks),
            'pivot-projections.tsv': (('x','y','z','chosen_index','chosen_value','mutant_differs'), pivots),
            'merge-projections.tsv': (('first','second','minimum','maximum','forward_choice','backward_choice'), merges),
            'summary.json': summary}


def write_results(results, out):
    out.mkdir(parents=True, exist_ok=True)
    for name, result in results.items():
        if name.endswith('.json'):
            content = json.dumps(result, indent=2, sort_keys=True) + '\n'
        else:
            output = io.StringIO(newline='')
            writer = csv.writer(output, delimiter='\t', lineterminator='\n')
            writer.writerow(result[0])
            writer.writerows(result[1])
            content = output.getvalue()
        (out / name).write_text(content, encoding='utf-8', newline='\n')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', required=True, type=Path)
    args = p.parse_args()
    write_results(analyze(BINARY.read_bytes()), args.out)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, struct.error) as error:
        print('book_cancel_sort94: ' + str(error), file=sys.stderr)
        sys.exit(1)
