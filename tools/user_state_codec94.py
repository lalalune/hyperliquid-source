#!/usr/bin/env python3
"""Recover selected node 94 user-state codec decisions from authenticated ELF bytes."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct

from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# Starts, exclusive FDE ends and SHA-256 of the unmasked FDE byte ranges.
FUNCTIONS = {
    0x1a47aa0: (0x1a4a5b8, 'f829ecadf544cbcdb096589e46dee1d3246418a2bea3354ee227baafae9140b9', 'binary reader'),
    0x1d1fa20: (0x1d22963, '82303a7f94ddaa950329b184a34e462c327e967f061d8d4945ad4bd353f189a0', 'JSON reader'),
    0x2301330: (0x230148b, '2b80c43cd768eb262e4a901be4362470f56a6f840a8ea91e2eeedab7fa2da62e', 'binary field classifier'),
    0x2301490: (0x23015eb, 'bb4b9d21eea7e1ef3269088e0267624e254e8d80acfeb0f87978235548cc758f', 'JSON field classifier'),
    0x230d7e0: (0x230dae8, '7abe9129e40b35572fe3250d23e119d0ec6771f08c445659b624258f492bd49d', 'binary writer'),
    0x230daf0: (0x230de3d, '8e200542603b59e38350bc265217d385dfa5af7a0b4a96c32a22b10b4761348f', 'direct binary writer'),
    0x230de40: (0x230e106, '348d905b0e65644694eaf210db9806bcdb8cfd2dbc91f7f608825ef1bf53b047', 'JSON writer'),
    0x23d5450: (0x23d54b0, '047f80e82b9c4fe6f808311a5708b5a2de81a74e3189481fe87d91d837b16044', 'binary ar name helper'),
    0x23d72f0: (0x23d73ad, '7e69133e466beb6028ec00e9535cfe86460d1bdd3b6246f28dc8601a04652ebf', 'direct binary ar name helper'),
    0x23d2c60: (0x23d2d29, '80a61298b3d00799e15609d48ffe4061765f12f70a6bd08c5df5257abd7e4629', 'JSON open-order field helper'),
    0x23d1d10: (0x23d1dd9, '0c6e8ec8145f731ea10544d1cb34dc84aeb97a1005a62adb349fa9403cef7559', 'JSON ar name helper'),
}

# Each row is a manually located instruction boundary, checked against body hashes,
# relative displacements and field diagnostics, not discovered by byte-sweeping.
BINARY_BRANCHES = [0x1a49abd, 0x1a49d04, 0x1a49c2a,
                   0x1a49c6d, 0x1a49b72, 0x1a49d95]
JSON_BRANCHES = [0x1d1fcd7, 0x1d1fe42, 0x1d1fd8a,
                 0x1d1fde6, 0x1d1fd32, 0x1d1fe9e]
JSON_DIAGNOSTIC_LEAS = [0x1d22091, 0x1d21b1d, 0x1d21bd3,
                        0x1d2214a, 0x1d21c84, 0x1d21d3a]
NAME_LEAS = [0x230d85d, 0x230d8a1, 0x230d8ec, 0x230d95b, 0x230d994, 0x23d545f]
LENGTH_MOVS = [0x230d864, 0x230d8a8, 0x230d8f3, 0x230d962, 0x230d99b, 0x23d5469]
# These sites identify the values following names. The byte immediately before
# each site is not assumed to establish an instruction boundary.
VALUE_CALLS = [0x230d886, 0x230d8cb, None, 0x230d981, 0x230d9ba, 0x230d9d8]


def require(condition, message):
    if not condition:
        raise ValueError(message)


class Image:
    def __init__(self, data, *, check_digest=True):
        if check_digest:
            require(hashlib.sha256(data).hexdigest() == DIGEST, 'artifact SHA-256 mismatch')
        self.data = data
        self.secs = sections(data)
        _, fdes = eh_frame_records(data, self.secs)
        self.fdes = {}
        for f in fdes:
            if f['start'] in FUNCTIONS:
                require(f['start'] not in self.fdes, 'duplicate selected FDE start')
                self.fdes[f['start']] = f
        require(set(self.fdes) == set(FUNCTIONS), 'selected FDE missing')

    def offset(self, va, n):
        require(isinstance(va, int) and isinstance(n, int) and va >= 0 and n > 0,
                'invalid VA or size')
        matches = [s for s in self.secs if s['type'] != 8 and
                   s['address'] <= va and va + n <= s['address'] + s['size']]
        require(len(matches) == 1, 'VA is not uniquely file-backed')
        return matches[0]['offset'] + va - matches[0]['address']

    def read(self, va, n):
        off = self.offset(va, n)
        return bytes(self.data[off:off+n])

    def check_functions(self):
        rows = []
        for start, (end, expected, role) in FUNCTIONS.items():
            f = self.fdes[start]
            require(f['end'] == end, 'selected FDE endpoint changed')
            body = self.read(start, end - start)
            digest = hashlib.sha256(body).hexdigest()
            require(digest == expected, 'selected FDE body changed')
            rows.append({'role': role, 'start_va': hex(start), 'end_va_exclusive': hex(f['end']),
                         'fde_va': hex(f['fde']), 'file_offset': hex(self.offset(start, len(body))),
                         'size': len(body), 'sha256': digest})
        return rows


def rel32(image, site, prefix):
    raw = image.read(site, len(prefix) + 4)
    require(raw.startswith(prefix), 'unexpected relative instruction encoding')
    return site + len(raw) + struct.unpack('<i', raw[-4:])[0]


def conditional(image, site, opcode):
    if len(opcode) == 2:
        return rel32(image, site, opcode)
    raw = image.read(site, 2)
    require(raw[:1] == opcode, 'unexpected short conditional opcode')
    return site + 2 + struct.unpack('<b', raw[1:])[0]


def rip_lea(image, site):
    return rel32(image, site, b'\x48\x8d\x05')


def direct_call(image, site):
    return rel32(image, site, b'\xe8')


def table(image, base, count, lower, upper):
    raw = image.read(base, count * 4)
    targets = [base + x[0] for x in struct.iter_unpack('<i', raw)]
    require(all(lower <= t < upper for t in targets), 'table entry outside selected FDE')
    return targets


def writer_layout(image):
    lengths = []
    for site in LENGTH_MOVS:
        raw = image.read(site, 5)
        require(raw[0] == 0xba, 'unexpected field length instruction')
        lengths.append(struct.unpack('<I', raw[1:])[0])
    require(lengths == [13, 20, 33, 15, 18, 2], 'field lengths changed')
    require(image.read(0x230d880, 3) == b'\x4c\x89\xf6', 'first field base changed')
    offsets = [0]
    for site, prefix in [(0x230d8bf, b'\x49\x8d\x56'),
                         (0x230d8db, b'\x41\x0f\xb6\xb6'),
                         (0x230d975, b'\x49\x8d\x76'),
                         (0x230d9ae, b'\x49\x8d\x76'),
                         (0x230d9c6, b'\x49\x81\xc6')]:
        width = 4 if site in (0x230d8db, 0x230d9c6) else 1
        raw = image.read(site, len(prefix) + width)
        require(raw.startswith(prefix), 'unexpected field-offset instruction')
        offsets.append(int.from_bytes(raw[len(prefix):], 'little'))
    require(offsets == [0, 0x60, 0xa8, 0x78, 0x30, 0x90], 'field offsets changed')
    return lengths, offsets


def names_and_classifier(image, lengths):
    # Diagnostics independently supply canonical names, through checked RIP LEAs.
    names = []
    for site, length in zip(JSON_DIAGNOSTIC_LEAS, lengths):
        names.append(image.read(rip_lea(image, site), length))
    require(names == [b'user_to_state', b'users_with_positions',
                      b'check_all_users_for_liquidatables', b'asset_to_oi_szi',
                      b'open_order_tracker', b'ar'], 'unexpected diagnostic names')

    # The length-11 and length-15 arms use two overlapping imm64 comparisons.
    def overlap(first, second, offset, length):
        a, b = image.read(first, 8), image.read(second, 8)
        require(a[offset:] == b[:8-offset], 'overlapping comparison operands disagree')
        value = a + b[8-offset:]
        require(len(value) == length, 'bad comparison length')
        return value
    old = overlap(0x230139d, 0x23013aa, 3, 11)
    user = overlap(0x23013fd, 0x230140a, 5, 13)
    new = overlap(0x2301426, 0x2301433, 7, 15)
    require(old == b'asset_to_oi' and user == names[0] and new == names[3],
            'immediate field comparisons changed')
    require(image.read(0x2301354, 2) == names[5], 'ar comparison changed')
    require(image.read(0x205830, 16) + image.read(0x206c60, 4) == names[1],
            'users field vector constants changed')
    require(image.read(0x207a70, 16) + image.read(0x204f20, 2) == names[4],
            'open-order vector constants changed')
    check_name = rel32(image, 0x23013c9, b'\x48\x8d\x0d')
    require(image.read(check_name, len(names[2])) == names[2], 'long field changed')
    # The add and unsigned compare immediately before each table determine the
    # length domain and number of entries; do not infer it from padding.
    guard = image.read(0x2301333, 8)
    require(guard[:3] == b'\x48\x83\xc2' and guard[4:7] == b'\x48\x83\xfa',
            'classifier length guard changed')
    require(image.read(0x2301493, 8) == guard, 'classifier length guards disagree')
    first_length = -struct.unpack('<b', guard[3:4])[0]
    count = guard[7] + 1
    require((first_length, count) == (2, 32), 'unexpected classifier length domain')
    a = table(image, 0x3dc380, count, 0x2301330, 0x230148b)
    b = table(image, 0x3dc400, count, 0x2301490, 0x23015eb)
    require(all(y - x == 0x160 for x, y in zip(a, b)), 'classifier tables differ')
    lengths = [2, 11, 13, 15, 18, 20, 33]
    expected_arms = [0x2301351, 0x230139b, 0x23013fb, 0x2301424,
                     0x230144d, 0x2301365, 0x23013c8]
    require([a[n - first_length] for n in lengths] == expected_arms, 'classifier arms changed')
    require(all(a[i] == 0x2301479 for i in range(count) if i + first_length not in lengths),
            'unexpected classifier length arm')
    tag_sites = [0x230135c, 0x23013bf, None, 0x2301444, 0x2301482, 0x2301392, 0x23013f2]
    tags = []
    for pos in tag_sites:
        if pos is None:
            require(image.read(0x230141b, 2) == b'\x31\xc9', 'zero classifier tag changed')
            require(image.read(0x230157b, 2) == b'\x31\xc9', 'second zero tag changed')
            tags.append(0)
        else:
            raw = image.read(pos, 2)
            require(raw[0] == 0xb1, 'classifier tag instruction changed')
            require(image.read(pos + 0x160, 2) == raw, 'classifier tag copies disagree')
            tags.append(raw[1])
    require(tags == [5, 3, 0, 3, 4, 1, 2], 'field tag map changed')
    unknown = image.read(0x2301479, 2)
    require(unknown == b'\xb1\x06' and image.read(0x23015d9, 2) == unknown,
            'unknown field tag changed')
    field_names = [names[5], old, names[0], names[3], names[4], names[1], names[2]]
    return names, [{'name': n.decode('ascii'), 'length': len(n), 'tag': tag,
                    'binary_arm_va': hex(arm), 'json_arm_va': hex(arm + 0x160)}
                   for n, tag, arm in zip(field_names, tags, expected_arms)], a, b, unknown[1]


def classify(name, rows):
    """Bounded classifier model, not target execution or an input parser."""
    require(isinstance(name, bytes), 'field must be bytes')
    for row in rows:
        if name == row['name'].encode('ascii'):
            return row['tag']
    return 6


def generate_records(image):
    functions = image.check_functions()
    name_lengths, value_offsets = writer_layout(image)
    names, classifiers, length_a, length_b, unknown_tag = names_and_classifier(image, name_lengths)
    binary_arms = table(image, 0x3a86fc, unknown_tag + 1, 0x1a47aa0, 0x1a4a5b8)
    json_arms = table(image, 0x3b70b4, unknown_tag + 1, 0x1d1fa20, 0x1d22963)
    require(binary_arms == [0x1a49ab7, 0x1a49cfb, 0x1a49c26, 0x1a49c64,
                            0x1a49b6c, 0x1a49d8f, 0x1a49e44], 'binary map dispatch changed')
    require(json_arms == [0x1d1fccf, 0x1d1fe39, 0x1d1fd85, 0x1d1fddd,
                          0x1d1fd2a, 0x1d1fe95, 0x1d1fef1], 'JSON map dispatch changed')
    fields = []
    for i, (name, lb, lj, lea, length, value_call, offset) in enumerate(zip(
            names, BINARY_BRANCHES, JSON_BRANCHES, NAME_LEAS, name_lengths,
            VALUE_CALLS, value_offsets)):
        bt = conditional(image, lb, b'\x0f\x85')
        jt = conditional(image, lj, b'\x0f\x85')
        # Binary duplicate block starts with an LEA of its diagnostic name.
        require(image.read(rip_lea(image, bt), length) == name, 'binary duplicate name mismatch')
        require(image.read(rip_lea(image, JSON_DIAGNOSTIC_LEAS[i]), length) == name,
                'JSON duplicate name mismatch')
        prefix = b'\x48\x8d\x05' if i == 5 else b'\x48\x8d\x35'
        writer_name = rel32(image, lea, prefix)
        require(image.read(writer_name, length) == name, 'writer name mismatch')
        tag = classify(name, classifiers)
        require(tag == i, 'writer field order disagrees with classifier')
        fields.append({'tag': tag, 'name': name.decode('ascii'), 'input_offset': hex(offset),
                       'binary_reader_arm_va': hex(binary_arms[i]),
                       'binary_duplicate_branch_va': hex(lb), 'binary_duplicate_target_va': hex(bt),
                       'json_reader_arm_va': hex(json_arms[i]),
                       'json_duplicate_branch_va': hex(lj), 'json_duplicate_target_va': hex(jt),
                       'writer_name_site_va': hex(lea), 'writer_name_data_va': hex(writer_name),
                       'writer_value_call_va': None if value_call is None else hex(value_call),
                       'writer_value_callee_va': None if value_call is None else hex(direct_call(image, value_call))})
    require(image.read(0x1df8f3, 15).endswith(b'missing field '), 'missing diagnostic changed')
    require(image.read(0x1e0fd5, 17).endswith(b'duplicate field '), 'duplicate diagnostic changed')
    # On a successful tag-3 child decode, both readers set the very slot
    # subsequently tested by their duplicate branches.
    require(image.read(0x1a49ce9, 13) == bytes.fromhex('b8010000004889842490000000'),
            'binary alias presence store changed')
    require(image.read(0x1d200b7, 13) == bytes.fromhex('b90100000048898c2420010000'),
            'JSON alias presence store changed')
    required = []
    # JSON object completion checks the first three fields in order.
    for tag, branch, lea in [(0, 0x1d207bd, 0x1d208f0),
                             (1, 0x1d207cb, 0x1d20951),
                             (2, 0x1d207da, 0x1d207e0)]:
        target = conditional(image, branch, b'\x0f\x84') if tag < 2 else conditional(image, branch, b'\x0f\x85')
        # For tag 2 the branch skips the missing diagnostic on presence.
        require((target == lea) if tag < 2 else (target == 0x1d209d4), 'missing-field branch changed')
        require(image.read(rip_lea(image, lea), len(names[tag])) == names[tag], 'missing name mismatch')
        required.append({'tag': tag, 'test_branch_va': hex(branch), 'branch_target_va': hex(target),
                         'missing_name_lea_va': hex(lea)})
    optional = []
    for tag, site, opcode in [(3, 0x1d209dc, b'\x0f\x84'),
                              (4, 0x1d20b95, b'\x74'),
                              (5, 0x1d20c0f, b'\x74')]:
        target = conditional(image, site, opcode)
        optional.append({'tag': tag, 'missing_branch_va': hex(site), 'default_target_va': hex(target),
                         'bytes': image.read(site, 6 if len(opcode) == 2 else 2).hex()})
    require([x['default_target_va'] for x in optional] == ['0x1d20b77', '0x1d20bc9', '0x1d20c1d'],
            'default branch target changed')
    writer_branch_sites = [
        (0x230d805, b'\x74', 'header array mode'),
        (0x230d822, b'\x74', 'header accepted'),
        (0x230d854, b'\x75', 'header error'),
        (0x230d85b, b'\x75', 'skip first key when flag differs from one'),
        (0x230d875, b'\x0f\x85', 'first key error'),
        (0x230d894, b'\x0f\x85', 'first value error'),
        (0x230d8d5, b'\x0f\x85', 'second value error'),
        (0x230d906, b'\x0f\x85', 'third key error'),
        (0x230d973, b'\x75', 'fourth key error'),
        (0x230d98b, b'\x75', 'fourth value error'),
        (0x230d9ac, b'\x75', 'fifth key error'),
        (0x230d9c4, b'\x75', 'fifth value error'),
        (0x230d9e2, b'\x75', 'sixth value error'),
        (0x230db38, b'\x75', 'direct writer omits names outside flag one'),
        (0x230db9f, b'\x0f\x85', 'direct first value error'),
        (0x230dc06, b'\x0f\x85', 'direct second value error'),
        (0x230dc33, b'\x0f\x85', 'direct third key error'),
        (0x230dc81, b'\x0f\x85', 'direct fourth key error'),
        (0x230dc9a, b'\x0f\x85', 'direct fourth value error'),
        (0x230dcbf, b'\x75', 'direct fifth key error'),
        (0x230dcd4, b'\x75', 'direct fifth value error'),
        (0x230dcef, b'\x75', 'direct sixth value error'),
        (0x230deeb, b'\x0f\x85', 'JSON first value error'),
        (0x230df51, b'\x0f\x85', 'JSON second value error'),
        (0x230df7a, b'\x0f\x85', 'JSON third field error'),
        (0x230dfe5, b'\x75', 'JSON fourth value error'),
        (0x230dffb, b'\x75', 'JSON fifth value error'),
        (0x230e012, b'\x75', 'JSON sixth value error'),
    ]
    writer_branches = [{'role': role, 'site_va': hex(site),
                        'target_va': hex(conditional(image, site, op)),
                        'bytes': image.read(site, 6 if len(op) == 2 else 2).hex()}
                       for site, op, role in writer_branch_sites]
    # These exact windows establish optional/default paths and key writer modes.
    windows = [(0x1a49ce9, 13), (0x1d200b7, 13),
               (0x1d209d4, 14), (0x1d20b77, 24), (0x1d20b8f, 8),
               (0x1d20c07, 27), (0x1a490cf, 10), (0x1a490fa, 24),
               (0x230db07, 20), (0x230dc0c, 8), (0x230dc46, 22),
               (0x23d72f0, 10), (0x23d730f, 29), (0x230d9c6, 18),
               (0x230dff3, 15), (0x230e00a, 10)]
    selected = [{'va': hex(va), 'bytes': image.read(va, n).hex()} for va, n in windows]
    # Fixarray/fixmap headers, field name marker, boolean marker, and ar marker
    # are read from verified instructions, not fabricated sample data.
    hdr = image.read(0x230db07, 20)
    require(hdr[:4] == b'\x0f\xb6\x6a\x1b' and hdr[4:8] == b'\x48\x8b\x72\x10' and
            hdr[8:12] == b'\x40\x80\xf5\x01' and hdr[12:16] == b'\x40\xc0\xe5\x04' and
            hdr[16:19] == b'\x40\x80\xcd', 'header instruction sequence changed')
    or_mask = hdr[19]
    map_header = (((1 ^ 1) << 4) | or_mask) & 0xff
    array_header = (((0 ^ 1) << 4) | or_mask) & 0xff
    ar_marker = image.read(0x23d7313, 1)[0]
    require((map_header, array_header, ar_marker) == (0x86, 0x96, 0xa2), 'header constants changed')
    call_sites = sorted({0x1a4996b, 0x1d1fc84, 0x230d814, 0x230d846,
                         0x230d86c, 0x230d886, 0x230d8b0, 0x230d8cb,
                         0x230d8fb, 0x230d931, 0x230d96a, 0x230d981,
                         0x230d9a3, 0x230d9ba, 0x230d9d8, 0x230db96,
                         0x230dbfd, 0x230dc2a, 0x230dc4e, 0x230dc78,
                         0x230dc91, 0x230dcb6, 0x230dccb, 0x230dce6,
                         0x230dea0, 0x230dee3, 0x230df05, 0x230df49,
                         0x230df72, 0x230df99, 0x230dfdd, 0x230dff3,
                         0x230e00a, 0x23d547a, 0x23d1d30, 0x23d2c80})
    calls = [{'site_va': hex(site), 'target_va': hex(direct_call(image, site)),
              'bytes': image.read(site, 5).hex()} for site in call_sites]
    require(direct_call(image, 0x1a4996b) == 0x2301330 and
            direct_call(image, 0x1d1fc84) == 0x2301490 and
            direct_call(image, 0x230d9d8) == 0x23d5450 and
            direct_call(image, 0x230dce6) == 0x23d72f0 and
            direct_call(image, 0x230dff3) == 0x23d2c60 and
            direct_call(image, 0x230e00a) == 0x23d1d10, 'path call changed')
    return {'artifact_sha256': hashlib.sha256(image.data).hexdigest(),
            'coordinate': 'linked ELF virtual address; FDE ends exclusive',
            'functions': functions, 'classifiers': classifiers,
            'classifier_length_tables': [{'va': hex(va), 'targets': [hex(x) for x in entries]}
                                         for va, entries in ((0x3dc380, length_a), (0x3dc400, length_b))],
            'binary_map_table_va': hex(0x3a86fc), 'json_map_table_va': hex(0x3b70b4),
            'unknown_binary_arm_va': hex(binary_arms[6]), 'unknown_json_arm_va': hex(json_arms[6]),
            'fields': fields, 'json_required_tests': required, 'json_optional_tests': optional,
            'writer_branches': writer_branches, 'selected_windows': selected,
            'direct_binary_headers': {'map_when_flag_1': hex(map_header),
                                      'array_when_flag_0': hex(array_header),
                                      'ar_name_marker': hex(ar_marker)}, 'calls': calls}


def generate(image, out):
    records = generate_records(image)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'records.json').write_text(json.dumps(records, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    buf = io.StringIO(newline='')
    columns = ['tag', 'name', 'input_offset', 'binary_reader_arm_va', 'binary_duplicate_branch_va',
               'binary_duplicate_target_va', 'json_reader_arm_va', 'json_duplicate_branch_va',
               'json_duplicate_target_va', 'writer_name_site_va', 'writer_value_call_va', 'writer_value_callee_va']
    writer = csv.DictWriter(buf, fieldnames=columns, delimiter='\t', lineterminator='\n', extrasaction='ignore')
    writer.writeheader()
    writer.writerows(records['fields'])
    (out / 'fields.tsv').write_text(buf.getvalue(), encoding='utf-8')
    return records


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, required=True)
    args = p.parse_args()
    generate(Image(BINARY.read_bytes()), args.out)


if __name__ == '__main__':
    main()
