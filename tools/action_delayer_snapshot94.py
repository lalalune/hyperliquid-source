#!/usr/bin/env python3
"""Extract node #94 ActionDelayer snapshot decisions from ELF bytes, offline."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records

DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BINARY = ROOT / 'artifacts/node/94/hl-node'
# Inspected unwind ranges, not a claim that all target functions are known.
FUNCTIONS = (
 ('queue_map_writer', 0x25e5480, 0x25e5549, '7e2fa1c3d511eba97cf8d760f2116c4a824cac0246631e7116c8551fcc0d6d44'),
 ('queue_row_collector', 0x25781a0, 0x25784a0, '34b8450b9c20808517b051386a408d8845b7021bfecb3bec0c64af241d157fef'),
 ('queue_rows_writer', 0x1e258b0, 0x1e25b3b, '9416f0ada57394176587f5e079ed7a018b1caf6876f5d95a3673091b963ba39e'),
 ('queue_pair_writer', 0x1dee8d0, 0x1def4e3, '9a636c9460fa289adcf92ef05a8809e7a33cf3247938aa4d86cdbc1840a5b0cb'),
 ('queue_map_reader', 0x1778870, 0x1779009, '1ae5324905065fd179d0d73102ed7cc1671038d083f822dd24abb658b3250d67'),
 ('queue_rows_reader', 0x264d710, 0x264d9d3, '8ecae1f8f1e02c5e9964af662f6a2e1a41e686042f1e5d1e06e80285a7115df8'),
 ('queue_sequence_reader', 0x2683490, 0x2683703, '6a1407979eb82c22c8db6994271d32721e48d4f6fe693db7afc9430743d1e0fc'),
 ('queue_pair_reader', 0x1993520, 0x199402e, '58c8350ae165760216bb56340e870b540b793cf52b0bd063598748b91d6109ac'),
 ('queue_time_reader', 0x16b8a80, 0x16b8d86, 'abc2f2138f54db0e4a66958ab7246d83077413e450cc1915214c1a6350a72114'),
 ('queue_values_reader', 0x19da140, 0x19da8c3, 'f473ae0361c572463e19c700b759f09be843a04da735206bc2c8f72f91fd2885'),
 ('queue_value_vector', 0x24cf220, 0x24cf4bb, '2335f1bed194d5ea2de5ed59bddc2828f0795d148677074b3dbcf6e7793c9070'),
 ('queue_record_reader', 0x17b1000, 0x17b3ae7, '3de84739b2a21a48a9bb2bc4b86a6f7cf0722177e7906c6547e5ac352463285b'),
 ('queue_record_classifier', 0x22ed680, 0x22ed76c, '8fd93a24a2cda8362b5eec686860368075979c94154ea475212b339db94991f5'),
 ('queue_record_writer', 0x2312900, 0x2312c4a, 'ce980918522ea0f366d2cb682d3c120db79178f5c77f06ee1940ba88f4344e19'),
 ('queue_record_broadcaster_writer', 0x23d3d60, 0x23d3dbc, '30c43defe6cf701980aad527a4c5078bd9498b6d47cd291355d6ef6533af8e02'),
 ('queue_expiry_nil_writer', 0x1e4c9c0, 0x1e4caa8, '3dfff6f8edfa27f8ed9e61a69ed397ce9436ba651745f039d8af1f51f9dfc50f'),
 ('queue_record_id_reader', 0x1885ef0, 0x18872aa, '69d146ce037b6d14e69096d44ebebe9bbe81d7c8ba4f506e3605982bed4e60cc'),
 ('queue_record_id_classifier', 0x22edcb0, 0x22edcfe, 'ca4c95ac91d2704f3906706732bf0bfc3bf808e44a64fdca232d62d8905ce964'),
 ('broadcaster_writer', 0x2207a70, 0x2207b5a, '2a4dfb38e9c17256ea1cde289381cdece9c501e8570001d07bf62f98c7293bf6'),
 ('broadcaster_reader', 0x168b630, 0x168b89c, 'e8425e1b20d3a358c182edfb10f83d59b951715f13eeb8aa4769887347e9162d'),
 ('broadcaster_name_reader', 0x1782650, 0x1782d70, '92863556bb85e5b61692cac43de602476939250f0062a95203948bcad3a84d6b'),
 ('broadcaster_name_classifier', 0x21e7b30, 0x21e7c4a, 'b7fe599972b3c6fe0a18f3a0d9363099c00d1239a6a5905b774d2fa778062d7f'),
 ('broadcaster_map_reader', 0x21e72e0, 0x21e73ef, '1e8f0495b362a6bb1abd9999addd7b825aba7bf8bd5068f442db7c7bf89a18fb'),
 ('queue_tree_insert', 0x284e5d0, 0x284e859, '0e5a65a47b5eebb3ae599b74011048f5acc3a4441375418b3fc8fbb8f2e80d9a'),
 ('msgpack_writer', 0x2311e90, 0x2312134, '7473a0dd47da329869bf2406f3561e9b78eab0f8d9f7462220bd8d2d5dd98713'),
 ('msgpack_mode_writer', 0x23d8e00, 0x23d8ef9, 'fbfde04083d995f2bf40d9e456225aeb1a86b56145d8ec0e531257ea29ebf569'),
 ('msgpack_reader', 0x1767dd0, 0x176ba2b, '72c84e6530bd580eae507d8f038a0c996cab0f87a44adbb5ab47d247fbd716cc'),
 ('field_classifier', 0x22ecd20, 0x22ed241, '5d7d650f48e4dc6ab63fc8a0a7dfd043d91fbdf6520ef6112501e838857d36a0'),
 ('msgpack_mode_reader', 0x16850e0, 0x168533c, '137b8ae2e7ab3379b2e32536c16033e1da19ac48b18d196bddde71699ea19a73'),
 ('per_asset_writer', 0x25ecca0, 0x25ecd69, '60fad4cf0c3d5014c58f5d89a51f42ebd37348c4bd29cc57bdf0e25bdbb3f8bd'),
 ('per_asset_reader', 0x180e990, 0x180f129, '88ed66f25403c08e04348d9c3d6a3b95743a8324b4b97fc76d2ebbe67f93a14a'),
 ('per_asset_map_rows', 0x2637d80, 0x2637f96, '98bb2693cd1dcdc09174ede5944874350a4f68d0da49dc7ad0e6389cdd0c0b38'),
 ('per_asset_sequence_rows', 0x267e930, 0x267eaa9, '7bde655294d35be3d703027f85ff2df9707c44a00711c6e2ec10991faa9a66d4'),
 ('per_asset_pair_reader', 0x18bb650, 0x18bbfcc, '5bc0566ca590f3725633510d5febd8ae2d56f8f00ad65d89098b4416c556c182'),
 ('per_asset_tree_insert', 0x2850ce0, 0x2850e5d, 'f51225c817863ea7f093d8afedc956306d1e9915e206985b805ff09791b55e2f'),
 ('per_asset_rows_writer', 0x1e470f0, 0x1e4737b, '22323e09cf2218bddba672b6aed50e7062eafc0a6802c2352f7489e6aebb6343'),
 ('per_asset_pair_writer', 0x1df7030, 0x1df7585, 'c6a30947abe343f70a6e4a6eedcf9402aae5eb0722f95e43547e2fd0bd3ab7a2'),
 ('per_asset_status_writer', 0x2313be0, 0x2313d10, 'a41b3f4b5f3611a63ec333499a8b4201d93849b4bb9874349f5ab835b99da4ec'),
 ('per_asset_status_reader', 0x1687c50, 0x1687f12, '5aa2e4626d8980d2ba1b1a17b3860275b0d2f037c1944fda9c6c3eb11f436ffe'),
 ('per_asset_status_name_reader', 0x1849bd0, 0x184a2f0, '09577e065f5617f96649996c1f53ddd98deb9e14639276a019889d8a28ad0196'),
 ('per_asset_status_name_classifier', 0x22ef330, 0x22ef444, '7baa9c1b4a708b1e19c0606b09eaa8938c4f88da96bb7430aa83dff3ca576fb7'),
 ('per_asset_status_seconds_reader', 0x19b3460, 0x19b4665, '46ce08ab28c4bcebc2549fdf165cc44910bf036b050ec754edb6a3b8c36c628d'),
 ('nonzero_seconds_entry', 0x16845c0, 0x1684650, '22c4eef17c94157bdcbb0b19921663511a124f43d28c85a95ea52398d36c794d'),
 ('nonzero_seconds_number_reader', 0x2eb9f30, 0x2eba283, '9173b6c0e6ce1cdcf877bcf226f09695c1be0f746a8dd59d934d2279f86e0b29'),
 ('mode_name_reader', 0x1715d70, 0x1716490, '0af5cf86e074ae63681e8c5dd09041c5b3cf7ff31a9f6fab54b5c92010e5ffdf'),
 ('mode_name_classifier', 0x22ee7a0, 0x22ee8c0, 'fdb812bcabea82c7d41359d61a54b00f19cee70e5b5e54eb4c413097d67b46b2'),
 ('mode_map_reader', 0x22ec060, 0x22ec1a2, '3e46a3afe09ecc2c87e184267c374e095b61ebbaf2ad78a5fd637d6423424977'),
 ('json_reader', 0x1c28450, 0x1c2b4ce, '858b2d17c0fbab1d13f96e635f54f9e56203a98c9a37a02f1c12ac249cf8009b'),
 ('json_writer', 0x48b23b0, 0x48b2658, '1d6649af9cd2c9aef636d72764126b83d0b79a7d5b2a0871451176cce3687835'),
 ('msgpack_writer_copy', 0x48b2660, 0x48b2904, '07433c66c6b9324cbe7416aabdba9bbc274f469f543d4d4278d77580ada517c8'),
 ('json_mode_field', 0x4972ca0, 0x4972d69, '8cf6b28c1b56d381d381e57a61b76203e185bea2ff1525a14842bc9d41b89f9a'),
 ('json_vty_field', 0x4972d70, 0x4972e39, '4f551aa90436bc1443704c5283c0febc684734ee0dd4742bf024830056c1209f'),
 ('json_mode_writer', 0x48b3900, 0x48b3ce0, '856af34cdeafede5293e5ecfc43cba6d8d12fd0d7db5be12dd9be84775c745b7'),
)
# Key classifier path start, byte count, and (where 12-byte arms share a
# first-byte discriminator) a separately checked first byte.
CLASSIFIER_ARMS = (
 (0x22ecdb5, 15, b''), (0x22ece53, 25, b''),
 (0x22ed0be, 23, b''), (0x22ecfe6, 21, b''),
 (0x22ecf71, 12, b'v'), (0x22ed1aa, 12, b's'),
 (0x22ed1f4, 12, b'd'), (0x22ecd41, 11, b''),
)
# Each writer LEA names a UTF-8 field. Offsets and immediate widths are checked
# independently against the surrounding fixed instruction shapes below.
WRITER_NAMES = (0x2311f10, 0x2311f51, 0x2311f96, 0x2311fde,
                0x2312022, 0x2312060, 0x23d8e18, 0x23120a8)
JSON_WRITER_NAMES = (0x48b2401, 0x48b2467, 0x48b24d1, 0x48b24fc,
                     0x4972d84, 0x48b2538, 0x4972cb4, 0x48b256e)
MSG_MISSING = (0x176834e, 0x17684db, 0x176857e, 0x1768613, 0x1768b71, 0x1768c12, None, None)
MSG_DUPLICATE = (0x176b707, 0x176b57d, 0x176b7cc, 0x176b642,
                 0x176b4b8, 0x176b891, 0x176b32e, 0x176b3f3)
JSON_MISSING = (0x1c2972f, 0x1c29855, 0x1c2996a, 0x1c299ba, 0x1c29ad3, 0x1c29fe1, None, None)
JSON_DUPLICATE = (0x1c2ac23, 0x1c2a8e0, 0x1c2ab7c, 0x1c2aa2e,
                  0x1c2a987, 0x1c2acca, 0x1c2aad5, 0x1c2ad71)
DUP_BRANCHES = (0x176a9a0, 0x176ab95, 0x176aa9a, 0x176aaed,
                0x176aa1b, 0x176ac1c, 0x176ac70, 0x176ab40)
CHILD_CALLS = (0x176a9c2, 0x176abb7, 0x176aaab, 0x176aafe,
               0x176aa3d, 0x176ac39, 0x176ac81, 0x176ab51)
# Per-field memory-offset instruction on the writer path. The parser below
# admits only the instruction forms listed here.
MEMORY = (0x2311f2e, 0x2311f6f, 0x2311f8b, 0x2311fd3,
          0x2312040, 0x231205c, None, 0x231209f)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def check_digest(data):
    if digest(data) != DIGEST:
        raise ValueError('node #94 digest mismatch')


def mapped(data, secs, va, size):
    if va < 0 or size <= 0:
        raise ValueError('invalid file-backed address or size')
    candidates = [s for s in secs if s['type'] != 8 and s['size'] and s['address'] and
                  s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(candidates) != 1:
        raise ValueError('unmapped, ambiguous, or non-file-backed address')
    s = candidates[0]
    off = s['offset'] + va - s['address']
    if off < 0 or off + size > len(data):
        raise ValueError('file-backed address extends beyond file')
    return data[off:off + size], off


def read(data, secs, va, size):
    return mapped(data, secs, va, size)[0]


def pin(data, secs, va, expected):
    actual = read(data, secs, va, len(expected))
    if actual != expected:
        raise ValueError('instruction bytes changed at %#x' % va)
    return actual


def rip_target(data, secs, va):
    b = read(data, secs, va, 7)
    if b[:2] not in (b'\x48\x8d', b'\x4c\x8d') or b[2] & 0xc7 != 5:
        raise ValueError('expected RIP-relative LEA')
    return va + 7 + struct.unpack_from('<i', b, 3)[0]


def rel_call(data, secs, va):
    b = read(data, secs, va, 5)
    if b[0] != 0xe8:
        raise ValueError('expected direct rel32 call')
    return va + 5 + struct.unpack_from('<i', b, 1)[0]


def rel_jump(data, secs, va):
    b = read(data, secs, va, 5)
    if b[0] != 0xe9:
        raise ValueError('expected direct rel32 jump')
    return va + 5 + struct.unpack_from('<i', b, 1)[0]


def indirect_slot(data, secs, va):
    b = read(data, secs, va, 6)
    if b[:2] != b'\xff\x15':
        raise ValueError('expected RIP-relative indirect call')
    return va + 6 + struct.unpack_from('<i', b, 2)[0]


def relative_slot(data, secs, slot, detail=False):
    """Resolve one unique ELF64 RELA relative slot; refuse other relocation forms."""
    if any(s['type'] in (9, 19) for s in secs):
        raise ValueError('unsupported REL or RELR relocation section')
    matches = []
    for sec in secs:
        if sec['type'] != 4:
            continue
        start, size = sec['offset'], sec['size']
        if start < 0 or size % 24 or start + size > len(data):
            raise ValueError('truncated RELA section')
        for i, (where, info, addend) in enumerate(struct.iter_unpack('<QQq', data[start:start + size])):
            if where == slot:
                matches.append((info, addend, sec.get('name'), start + i * 24))
    if len(matches) != 1 or matches[0][0] != 8:
        raise ValueError('slot is missing, duplicated, or not symbol-free RELATIVE')
    if detail:
        info, addend, name, off = matches[0]
        return {'section': name, 'file_offset': hex(off), 'record_bytes': data[off:off + 24].hex(),
                'offset': hex(slot), 'info': hex(info), 'addend': hex(addend)}
    return matches[0][1]


def branch(data, secs, va):
    b = read(data, secs, va, 2)
    if 0x70 <= b[0] <= 0x7f:
        return b[0], va + 2 + struct.unpack('<b', b[1:])[0], 2
    if b[0] == 0x0f and 0x80 <= b[1] <= 0x8f:
        return b[1], va + 6 + struct.unpack('<i', read(data, secs, va + 2, 4))[0], 6
    raise ValueError('expected conditional branch at %#x' % va)


def signed_table(data, secs, va, count):
    raw = read(data, secs, va, 4 * count)
    return [va + x[0] for x in struct.iter_unpack('<i', raw)]


def classifier_arm(data, secs, start, length, prefix=b''):
    """Read byte-compare chains and their mismatch exits, without executing x86."""
    name = bytearray(prefix)
    at = start
    result = None
    comparisons = []
    for index in range(len(prefix), length):
        # Most arms load the result before their final comparison.
        if read(data, secs, at, 1) == b'\xb1':
            result = read(data, secs, at + 1, 1)[0]
            at += 2
        if index == 0:
            b = read(data, secs, at, 3)
            if b[:2] != b'\x80\x3e':
                raise ValueError('first compare shape changed')
            value, width = b[2], 3
        else:
            b = read(data, secs, at, 4)
            if b[:2] != b'\x80\x7e' or b[2] != index:
                raise ValueError('indexed compare shape changed')
            value, width = b[3], 4
        comparisons.append({'va': hex(at), 'offset': index, 'byte': value})
        name.append(value)
        at += width
        opcode, target, size = branch(data, secs, at)
        # The final comparison of the mode arm jumps over the reject block.
        if opcode in (0x74, 0x84):
            if index != length - 1 or target != 0x22ed23a:
                raise ValueError('unexpected equality target')
        elif opcode not in (0x75, 0x85) or target != 0x22ed238:
            raise ValueError('comparison does not reject mismatches')
        at += size
    if result is None:
        pin(data, secs, at, b'\x31\xc9')
        result = 0
    return {'text': name.decode('ascii'), 'code': result, 'start': hex(start),
            'comparisons': comparisons}


def variant_arm(data, secs, start, length, code, reject=0x22ee828):
    at = start
    name = bytearray()
    for i in range(length):
        n = 3 if i == 0 else 4
        b = read(data, secs, at, n)
        if (i == 0 and b[:2] != b'\x80\x3e') or (i and (b[:2] != b'\x80\x7e' or b[2] != i)):
            raise ValueError('variant comparison changed')
        name.append(b[-1]); at += n
        op, dest, size = branch(data, secs, at)
        if op != 0x75 or dest != reject:
            raise ValueError('variant mismatch does not reach error')
        at += size
    pin(data, secs, at, bytes((0x66, 0xc7, 0x00, 9, code)))
    return name.decode('ascii')


def mem_offset(data, secs, va):
    if va is None:
        return 0
    b = read(data, secs, va, 9)
    if b[:3] in (b'\x49\x8d\x77', b'\x4d\x8b\x67', b'\x4d\x8d\x47'):
        return b[3]
    if b[:5] == b'\xf2\x41\x0f\x10\x87':
        return struct.unpack_from('<I', b, 5)[0]
    raise ValueError('unsupported state field load')


def compare_queue_keys(left, right):
    """Model the inspected signed/unsigned three-word comparator."""
    if len(left) != 12 or len(right) != 12:
        raise ValueError('queue key must contain 12 bytes')
    a = struct.unpack('<iII', left)
    b = struct.unpack('<iII', right)
    return (a > b) - (a < b)


def classify(rows, candidate):
    """Apply the extracted equality predicates, not target code."""
    for row in rows:
        if candidate == row['text'].encode('ascii'):
            return row['code']
    return 8


def record_fields(data, secs):
    """Extract the inner six-field classifier's immediate comparisons."""
    pin(data, secs, 0x22ed683, bytes.fromhex('4883c2fe4883fa0b'))
    if branch(data, secs, 0x22ed68b)[1] != 0x22ed751 or rip_target(data, secs, 0x22ed691) != 0x3da2ac:
        raise ValueError('record field length dispatch changed')
    table = signed_table(data, secs, 0x3da2ac, 12)
    if table != [0x22ed6a1, 0x22ed751, 0x22ed6d7, 0x22ed751, 0x22ed6b5,
                 0x22ed751, 0x22ed751, 0x22ed751, 0x22ed751, 0x22ed6e8,
                 0x22ed751, 0x22ed731]:
        raise ValueError('record field length destinations changed')
    pin(data, secs, 0x22ed6a1, bytes.fromhex('66813e'))
    pin(data, secs, 0x22ed6b5, b'\xb9')
    pin(data, secs, 0x22ed6ba, bytes.fromhex('330e0fb7560481f2'))
    pin(data, secs, 0x22ed6d7, bytes.fromhex('813e'))
    for a in (0x22ed6e8, 0x22ed708, 0x22ed731):
        pin(data, secs, a, bytes.fromhex('48b9'))
        pin(data, secs, a + 10, bytes.fromhex('48330e48ba'))
    def overlap(a, shift):
        left = read(data, secs, a + 2, 8)
        right = read(data, secs, a + 15, 8)
        if left[shift:] != right[:8 - shift]:
            raise ValueError('record classifier comparison overlap changed')
        return left + right[8 - shift:]
    names = [read(data, secs, 0x22ed6d9, 4),
             read(data, secs, 0x22ed6b6, 4) + read(data, secs, 0x22ed6c2, 2),
             read(data, secs, 0x22ed6a4, 2),
             overlap(0x22ed6e8, 3), overlap(0x22ed731, 5), overlap(0x22ed708, 3)]
    code_sites = (0x22ed6df, 0x22ed6ce, 0x22ed6ac, 0x22ed75a, 0x22ed763, 0x22ed728)
    pin(data, secs, code_sites[0], bytes.fromhex('31c9'))
    tags = [0]
    for a in code_sites[1:]:
        pin(data, secs, a, b'\xb1')
        tags.append(read(data, secs, a + 1, 1)[0])
    if tags != list(range(6)):
        raise ValueError('record field tags changed')
    if rip_target(data, secs, 0x17b317e) != 0x2d09e0 or rel_call(data, secs, 0x17b2ef0) != 0x22ed680:
        raise ValueError('record dispatch edge changed')
    cases = signed_table(data, secs, 0x2d09e0, 7)
    tests = (0x17b3193, 0x17b3394, 0x17b32f2, 0x17b3349, 0x17b329b, 0x17b3462)
    ops = (0x85, 0x85, 0x84, 0x85, 0x85, 0x85)
    calls = (0x17b31e8, 0x17b33a5, 0x17b3305, 0x17b335a, 0x17b32ac, 0x17b3473)
    errors = (0x17b38a3, 0x17b38f8, 0x17b384e, 0x17b37f9, 0x17b37a4, 0x17b394a)
    if cases != [0x17b318e, 0x17b3389, 0x17b32ec, 0x17b3344, 0x17b3295, 0x17b345e, 0x17b34e6]:
        raise ValueError('record value dispatch changed')
    rows = []
    writer_names = (0x2312977, 0x23129df, 0x2312a34, 0x2312b29, 0x2312b5f, 0x23d3d71)
    missing_names = (0x17b1453, 0x17b1525, 0x17b1706, 0x17b1785, None, 0x17b1806)
    offsets = (struct.unpack('<I', read(data, secs, 0x2312998, 4))[0],
               read(data, secs, 0x2312a00, 1)[0],
               struct.unpack('<I', read(data, secs, 0x2312a1d, 4))[0],
               struct.unpack('<I', read(data, secs, 0x2312b1e, 4))[0],
               0, struct.unpack('<I', read(data, secs, 0x2312c1b, 4))[0])
    for i, name in enumerate(names):
        if branch(data, secs, tests[i])[:2] != (ops[i], errors[i]) or read(data, secs, rip_target(data, secs, errors[i]), len(name)) != name:
            raise ValueError('record duplicate branch or diagnostic changed')
        if read(data, secs, rip_target(data, secs, writer_names[i]), len(name)) != name:
            raise ValueError('record writer/reader name mismatch')
        if missing_names[i] is not None and read(data, secs, rip_target(data, secs, missing_names[i]), len(name)) != name:
            raise ValueError('record missing diagnostic field changed')
        rows.append({'tag': tags[i], 'name': name.decode('ascii'), 'bytes': len(name),
                     'record_offset': hex(offsets[i]), 'writer_name_lea_va': hex(writer_names[i]),
                     'missing_name_lea_va': hex(missing_names[i]) if missing_names[i] is not None else None,
                     'reader_case_va': hex(cases[i]), 'duplicate_test_va': hex(tests[i]),
                     'duplicate_branch_va': hex(errors[i]), 'reader_value_call_va': hex(calls[i]),
                     'reader_value_callee_va': hex(rel_call(data, secs, calls[i]))})
    return rows


def record_id_fields(data, secs):
    pin(data, secs, 0x22edcb3, bytes.fromhex('4883fa08'))
    pin(data, secs, 0x22edcb9, bytes.fromhex('4883fa06'))
    pin(data, secs, 0x22edcbf, b'\xb9')
    pin(data, secs, 0x22edcc4, bytes.fromhex('330e0fb7560481f2'))
    pin(data, secs, 0x22edcdd, bytes.fromhex('48b9'))
    if branch(data, secs, 0x22edcb7)[1] != 0x22edcdd or branch(data, secs, 0x22edcbd)[1] != 0x22edcec:
        raise ValueError('id classifier length branches changed')
    names = (read(data, secs, 0x22edcc0, 4) + read(data, secs, 0x22edccc, 2),
             read(data, secs, 0x22edcdf, 8))
    pin(data, secs, 0x22edcd4, bytes.fromhex('31c9'))
    pin(data, secs, 0x22edcf5, bytes.fromhex('b101'))
    sites = (0x2312a9d, 0x2312ade)
    branches = (0x1886b82, 0x1887076)
    ops = (0x74, 0x84)
    errors = (0x1886bc5, 0x18871d3)
    diagnostic_leas = (0x1886bc8, 0x18871d6)
    missing_leas = (0x18863c2, 0x1886799)
    calls = (0x1886b8a, 0x1887082)
    rows = []
    for i, name in enumerate(names):
        if read(data, secs, rip_target(data, secs, sites[i]), len(name)) != name:
            raise ValueError('id writer/classifier name mismatch')
        if branch(data, secs, branches[i])[:2] != (ops[i], errors[i]) or read(data, secs, rip_target(data, secs, diagnostic_leas[i]), len(name)) != name:
            raise ValueError('id duplicate route changed')
        if read(data, secs, rip_target(data, secs, missing_leas[i]), len(name)) != name:
            raise ValueError('id missing diagnostic changed')
        offset = struct.unpack('<I', read(data, secs, (0x2312a1d, 0x2312a24)[i], 4))[0]
        rows.append({'tag': i, 'name': name.decode('ascii'), 'bytes': len(name),
                     'writer_name_lea_va': hex(sites[i]), 'record_offset': hex(offset),
                     'duplicate_test_va': hex(branches[i]), 'duplicate_branch_va': hex(errors[i]),
                     'missing_name_lea_va': hex(missing_leas[i]),
                     'reader_value_callee_va': hex(rel_call(data, secs, calls[i]))})
    return rows


def analyze(data):
    check_digest(data)
    secs = sections(data)
    _, fdes = eh_frame_records(data, secs)
    by_start = {}
    for f in fdes:
        by_start.setdefault(f['start'], []).append(f)
    functions = []
    for label, start, end, expected in FUNCTIONS:
        rows = by_start.get(start, [])
        if len(rows) != 1 or rows[0]['end'] != end:
            raise ValueError('FDE extent changed')
        code, fileoff = mapped(data, secs, start, end - start)
        if digest(code) != expected:
            raise ValueError('body changed')
        functions.append({'role': label, 'start_va': hex(start), 'end_va_exclusive': hex(end),
                          'file_offset': hex(fileoff), 'fde_va': hex(rows[0]['fde']),
                          'length': len(code), 'sha256': digest(code)})
    # Bounds of the length selector and its 15 signed relative table rows.
    pin(data, secs, 0x22ecd23, bytes.fromhex('4883c2f54883fa0e'))
    if branch(data, secs, 0x22ecd2b)[1] != 0x22ed238 or rip_target(data, secs, 0x22ecd31) != 0x3da1c8:
        raise ValueError('field length selector changed')
    lengths = signed_table(data, secs, 0x3da1c8, 15)
    # Disambiguate the three length-12 fields by the first byte.
    pin(data, secs, 0x22ecf53, bytes.fromhex('0fb60e83f964'))
    pin(data, secs, 0x22ecf5f, bytes.fromhex('83f973'))
    pin(data, secs, 0x22ecf68, bytes.fromhex('83f976'))
    if [branch(data, secs, x)[1] for x in (0x22ecf59, 0x22ecf62, 0x22ecf6b)] != [0x22ed1f4, 0x22ed1aa, 0x22ed238]:
        raise ValueError('shared length selector changed')
    extracted = [classifier_arm(data, secs, *x) for x in CLASSIFIER_ARMS]
    for spec, row in zip(CLASSIFIER_ARMS, extracted):
        target = lengths[len(row['text']) - 11]
        expected = 0x22ecf53 if spec[2] else spec[0]
        if target != expected:
            raise ValueError('length table does not select classifier arm')
    if [x['code'] for x in extracted] != list(range(8)):
        raise ValueError('unexpected field tags')
    dispatch = signed_table(data, secs, 0x2b92f8, 9)
    if rip_target(data, secs, 0x176a987) != 0x2b92f8:
        raise ValueError('reader dispatch changed')
    pin(data, secs, 0x176a4c3, b'\xe8\x58\x28\xb8\x00')
    if rel_call(data, secs, 0x176a4c3) != 0x22ecd20:
        raise ValueError('reader/classifier edge changed')
    fields = []
    for i, row in enumerate(extracted):
        name = row['text']; n = len(name)
        a = rip_target(data, secs, WRITER_NAMES[i])
        if read(data, secs, a, n) != name.encode():
            raise ValueError('writer and classifier key mismatch')
        ja = rip_target(data, secs, JSON_WRITER_NAMES[i])
        if read(data, secs, ja, n) != name.encode():
            raise ValueError('JSON writer and classifier key mismatch')
        for site in (MSG_MISSING[i], MSG_DUPLICATE[i], JSON_MISSING[i], JSON_DUPLICATE[i]):
            if site is not None and read(data, secs, rip_target(data, secs, site), n) != name.encode():
                raise ValueError('error diagnostic field mismatch')
        op, dest, _ = branch(data, secs, DUP_BRANCHES[i])
        if op != (0x85, 0x85, 0x84, 0x84, 0x85, 0x85, 0x85, 0x84)[i]:
            raise ValueError('duplicate conditional changed')
        target_name = rip_target(data, secs, MSG_DUPLICATE[i])
        if not (dest <= MSG_DUPLICATE[i] < dest + 140):
            raise ValueError('duplicate branch no longer reaches field diagnostic')
        fields.append({'tag': i, 'name': name, 'bytes': n,
                       'state_offset': hex(mem_offset(data, secs, MEMORY[i])),
                       'writer_name_lea_va': hex(WRITER_NAMES[i]), 'writer_name_va': hex(a),
                       'json_writer_name_lea_va': hex(JSON_WRITER_NAMES[i]),
                       'reader_case_va': hex(dispatch[i]), 'duplicate_test_va': hex(DUP_BRANCHES[i]),
                       'duplicate_branch_va': hex(dest), 'duplicate_name_va': hex(target_name),
                       'duplicate_name_lea_va': hex(MSG_DUPLICATE[i]),
                       'reader_value_call_va': hex(CHILD_CALLS[i]),
                       'reader_value_callee_va': hex(rel_call(data, secs, CHILD_CALLS[i])),
                       'msgpack_missing_name_lea_va': hex(MSG_MISSING[i]) if MSG_MISSING[i] else None,
                       'json_missing_name_lea_va': hex(JSON_MISSING[i]) if JSON_MISSING[i] else None,
                       'json_duplicate_name_lea_va': hex(JSON_DUPLICATE[i])})
    if dispatch[8] != 0x176acf9 or rel_call(data, secs, 0x176ad09) != 0x19682d0:
        raise ValueError('unknown-field route changed')
    if rel_call(data, secs, 0x48b2520) != 0x4972d70 or rel_call(data, secs, 0x48b2557) != 0x4972ca0:
        raise ValueError('JSON field helper edge changed')
    if rel_call(data, secs, 0x4972cfa) != 0x48b3900:
        raise ValueError('JSON mode value edge changed')
    if rel_call(data, secs, 0x231208f) != 0x23d8e00:
        raise ValueError('mode writer edge changed')
    if rel_call(data, secs, 0x1715e8f) != 0x22ee7a0 or rel_call(data, secs, 0x22ec077) != 0x1715d70:
        raise ValueError('mode reader name edge changed')
    if rel_call(data, secs, 0x1685154) != 0x22ec060 or rel_call(data, secs, 0x1685230) != 0x1715d70:
        raise ValueError('mode reader container edge changed')
    if rel_jump(data, secs, 0x23d8e82) != 0x25ecca0 or rel_call(data, secs, 0x22ec09c) != 0x180e990:
        raise ValueError('per-asset writer/reader edges changed')
    per_asset_calls = (0x180ed66, 0x180eeaa, 0x2637ddf, 0x2637e14, 0x2637e30,
                       0x267e97c, 0x267e996, 0x18bbb2c, 0x18bbb54)
    per_asset_callees = (0x2637d80, 0x267e930, 0x16bc020, 0x1687c50, 0x2850ce0,
                         0x18bb650, 0x2850ce0, 0x1684360, 0x1687c50)
    if [rel_call(data, secs, a) for a in per_asset_calls] != list(per_asset_callees):
        raise ValueError('per-asset row edge changed')
    status_calls = (0x25ecd18, 0x1e472de, 0x1df71c5, 0x1687d3e, 0x1849cef, 0x1687d60, 0x19b3f18)
    status_callees = (0x1e470f0, 0x1df7030, 0x2313be0, 0x1849bd0, 0x22ef330, 0x19b3460, 0x16845c0)
    if [rel_call(data, secs, a) for a in status_calls] != list(status_callees):
        raise ValueError('per-asset status codec edge changed')
    pin(data, secs, 0x22ef33a, bytes.fromhex('4883fa02'))
    pin(data, secs, 0x22ef358, bytes.fromhex('4883fa0b'))
    if branch(data, secs, 0x22ef33e)[:2] != (0x75, 0x22ef358) or branch(data, secs, 0x22ef35c)[:2] != (0x75, 0x22ef3ac):
        raise ValueError('status variant length guards changed')
    status_variants = [variant_arm(data, secs, 0x22ef340, 2, 0, 0x22ef3ac),
                       variant_arm(data, secs, 0x22ef35e, 11, 1, 0x22ef3ac)]
    if [read(data, secs, rip_target(data, secs, a), len(name)).decode('ascii')
        for a, name in zip((0x2313c6b, 0x2313c24), status_variants)] != status_variants:
        raise ValueError('status writer/reader names changed')
    pin(data, secs, 0x2313bfe, bytes.fromhex('4d85ff'))
    if branch(data, secs, 0x2313c01)[:2] != (0x74, 0x2313c6b):
        raise ValueError('status writer zero branch changed')
    seconds = read(data, secs, rip_target(data, secs, 0x2313cbc), 7)
    if seconds != b'seconds' or any(read(data, secs, rip_target(data, secs, a), len(seconds)) != seconds for a in (0x19b3f5a, 0x19b4475)):
        raise ValueError('status seconds field changed')
    if rip_target(data, secs, 0x19b3f82) != 0x1df8f3 or rip_target(data, secs, 0x19b44a0) != 0x1e0fd5:
        raise ValueError('status seconds diagnostics changed')
    if branch(data, secs, 0x19b3f0a)[:2] != (0x85, 0x19b4472) or branch(data, secs, 0x19b3f51)[:2] != (0x85, 0x19b40d0):
        raise ValueError('status seconds presence guards changed')
    numeric_slot = indirect_slot(data, secs, 0x1684645)
    if numeric_slot != 0x5770c68 or relative_slot(data, secs, numeric_slot) != 0x2eb9f30:
        raise ValueError('seconds numeric reader relocation changed')
    pin(data, secs, 0x16845f3, bytes.fromhex('84c0'))
    pin(data, secs, 0x168460e, bytes.fromhex('b1e03cdf'))
    if branch(data, secs, 0x16845f5)[:2] != (0x78, 0x168460e) or branch(data, secs, 0x1684612)[:2] != (0x77, 0x168463c):
        raise ValueError('seconds fixint normalization changed')
    if rip_target(data, secs, 0x2eb9f45) != 0x567f74:
        raise ValueError('seconds numeric marker table changed')
    number_routes = signed_table(data, secs, 0x567f74, 33)
    expected_routes = (0x2eba01c, 0x2eba090, 0x2eb9fe9, 0x2eba170,
                       0x2eba10c, 0x2eba059, 0x2eb9fb4, 0x2eba13d)
    if tuple(number_routes[i - 0xc0] for i in range(0xcc, 0xd4)) != expected_routes:
        raise ValueError('seconds integer marker routes changed')
    if number_routes[0x20] != 0x2eba04c:
        raise ValueError('seconds negative fixint route changed')
    for a, expected in ((0x2eb9f95, '84c9'), (0x2eba03e, '4885c9'),
                        (0x2eba0b5, '6685d2'), (0x2eba00d, '85d2'),
                        (0x2eba1b7, '4885d2'), (0x2eba12b, '4885c9'),
                        (0x2eba082, '6685d2'), (0x2eb9fda, '85d2'), (0x2eba161, '4885d2'),
                        (0x2eba04c, '84c9')):
        pin(data, secs, a, bytes.fromhex(expected))
    guards = (0x2eb9f97, 0x2eba041, 0x2eba0b8, 0x2eba00f, 0x2eba1ba,
              0x2eba12e, 0x2eba085, 0x2eb9fdc, 0x2eba164, 0x2eba04e)
    expected_guards = ((0x85, 0x2eba054), (0x85, 0x2eba134), (0x84, 0x2eba1fa),
                       (0x84, 0x2eba1fa), (0x74, 0x2eba1fa), (0x8e, 0x2eba210),
                       (0x7f, 0x2eba0c2), (0x8e, 0x2eba217), (0x7f, 0x2eba1bf), (0x8e, 0x2eba20a))
    if [branch(data, secs, a)[:2] for a in guards] != list(expected_guards):
        raise ValueError('seconds integer sign or zero guard changed')
    pin(data, secs, 0x2eba1c3, bytes.fromhex('c60709'))
    pin(data, secs, 0x2eba203, bytes.fromhex('c644243801'))
    pin(data, secs, 0x2eba21f, bytes.fromhex('c644243802'))
    pin(data, secs, 0x2637dcd, bytes.fromhex('b909000000'))
    pin(data, secs, 0x2637df5, bytes.fromhex('b913000000'))
    asset_name = read(data, secs, rip_target(data, secs, 0x2637dd8), read(data, secs, 0x2637dce, 1)[0])
    status_name = read(data, secs, rip_target(data, secs, 0x2637e06), read(data, secs, 0x2637df6, 1)[0])
    if (asset_name, status_name) != (b'AssetWire', b'ActionDelayerStatus'):
        raise ValueError('per-asset visitor type labels changed')
    pin(data, secs, 0x2850d15, bytes.fromhex('3b6cb064410f97c14180d900'))
    pin(data, secs, 0x2850d57, bytes.fromhex('488b54f00848895cf008b801000000'))
    pin(data, secs, 0x2637e37, bytes.fromhex('4883f801'))
    pin(data, secs, 0x267e99b, bytes.fromhex('4883f801'))
    if branch(data, secs, 0x2637e3b)[:2] != (0x75, 0x2637dc0) or branch(data, secs, 0x267e99f)[:2] != (0x74, 0x267e9fc):
        raise ValueError('per-asset duplicate branches changed')
    for first_va, last_va in ((0x2637e61, 0x2637e53), (0x267ea1c, 0x267ea0e)):
        first = read(data, secs, first_va, 8)
        last = read(data, secs, last_va, 8)
        if first[5:] != last[:3] or first + last[3:] != b'duplicate key':
            raise ValueError('per-asset duplicate diagnostic changed')
    pin(data, secs, 0x18bbb1b, bytes.fromhex('4585f6'))
    pin(data, secs, 0x18bbb3a, bytes.fromhex('4183fe01'))
    pin(data, secs, 0x18bbc85, bytes.fromhex('4585ff'))
    if [branch(data, secs, a)[:2] for a in (0x18bbb1e, 0x18bbb3e, 0x18bbc88)] != [(0x84, 0x18bbbd5), (0x84, 0x18bbc52), (0x74, 0x18bbcd7)]:
        raise ValueError('per-asset pair length guards changed')
    queue_calls = (0x2311f3a, 0x25e54ea, 0x25e54f8, 0x1e25a9e,
                   0x176a9c2, 0x1778c46, 0x264d766, 0x264d793, 0x264d7e7,
                   0x1778d8a, 0x26834ec, 0x268356f, 0x1993a72, 0x1993aaa,
                   0x19da620, 0x24cf2de)
    queue_expected = (0x25e5480, 0x25781a0, 0x1e258b0, 0x1dee8d0,
                      0x1778870, 0x264d710, 0x16b8a80, 0x19da140, 0x284e5d0,
                      0x2683490, 0x1993520, 0x284e5d0, 0x16bcd60, 0x19da140,
                      0x24cf220, 0x17b1000)
    if [rel_call(data, secs, a) for a in queue_calls] != list(queue_expected):
        raise ValueError('queue read/write edges changed')
    if rip_target(data, secs, 0x17b1487) != 0x1df8f3 or rip_target(data, secs, 0x17b37d8) != 0x1e0fd5:
        raise ValueError('record diagnostic templates changed')
    if rip_target(data, secs, 0x18863ed) != 0x1df8f3 or rip_target(data, secs, 0x18867c4) != 0x1df8f3:
        raise ValueError('id missing diagnostic templates changed')
    if branch(data, secs, 0x1886773)[1] != 0x18867f4 or branch(data, secs, 0x188678d)[1] != 0x188712c:
        raise ValueError('id missing presence guards changed')
    pin(data, secs, 0x1886807, bytes.fromhex('e9b6fbffff'))
    missing_prefix = read(data, secs, 0x1df8f3, 16)
    duplicate_prefix = read(data, secs, 0x1e0fd5, 18)
    if missing_prefix != b'\x0fmissing field `' or duplicate_prefix != b'\x11duplicate field `':
        raise ValueError('record diagnostic text changed')
    if rel_call(data, secs, 0x1deee66) != 0x2312900 or rel_call(data, secs, 0x2312c28) != 0x23d3d60 or rel_call(data, secs, 0x1886ff8) != 0x22edcb0:
        raise ValueError('record or id codec edge changed')
    if [rel_call(data, secs, x) for x in (0x168b76d, 0x168b70a, 0x21e72f5, 0x178276f)] != [0x1782650, 0x21e72e0, 0x1782650, 0x21e7b30]:
        raise ValueError('broadcaster codec edge changed')
    if rel_call(data, secs, 0x168b78b) != 0x17057b0 or rel_call(data, secs, 0x168b819) != 0x1705c20:
        raise ValueError('broadcaster payload reader changed')
    pin(data, secs, 0x2207a83, bytes.fromhex('803e01'))
    if branch(data, secs, 0x2207a86)[1] != 0x2207ad8 or branch(data, secs, 0x168b782)[1] != 0x168b816:
        raise ValueError('broadcaster variant branch changed')
    pin(data, secs, 0x21e7b3a, bytes.fromhex('4883fa03'))
    pin(data, secs, 0x21e7b5e, bytes.fromhex('4883fa0b'))
    if branch(data, secs, 0x21e7b3e)[1] != 0x21e7b5e or branch(data, secs, 0x21e7b62)[1] != 0x21e7bb2:
        raise ValueError('broadcaster variant length guard changed')
    broadcaster_variants = [variant_arm(data, secs, 0x21e7b40, 3, 0, 0x21e7bb2),
                            variant_arm(data, secs, 0x21e7b64, 11, 1, 0x21e7bb2)]
    for a, name in ((0x2207af2, broadcaster_variants[0]), (0x2207aa2, broadcaster_variants[1])):
        if read(data, secs, rip_target(data, secs, a), len(name)).decode('ascii') != name:
            raise ValueError('broadcaster writer/reader variant mismatch')
    pin(data, secs, 0x168b79a, bytes.fromhex('8b4424118943120f104424010f114302c6430101'))
    pin(data, secs, 0x168b847, bytes.fromhex('0f104424010f104c24110f114b120f114302c6430100'))
    for a, value in ((0x2312995, '498d9610010000'), (0x23129fd, '498d7610'),
                     (0x2312a1a, '4d8bae00010000'), (0x2312a21, '498b8608010000'),
                     (0x2312b1a, '450fb6ae24010000'), (0x2312b79, '41833e01'),
                     (0x2312b7f, '498b5608'), (0x2312c18, '4981c625010000')):
        pin(data, secs, a, bytes.fromhex(value))
    pin(data, secs, 0x231292d, bytes.fromhex('ba06000000'))
    pin(data, secs, 0x2312a5f, bytes.fromhex('ba02000000'))
    pin(data, secs, 0x17b13d9, bytes.fromhex('b802000000'))
    pin(data, secs, 0x17b13e2, bytes.fromhex('4889442470'))
    pin(data, secs, 0x17b1d0a, bytes.fromhex('4531e4488b4424704883f8024c0f45e0'))
    if branch(data, secs, 0x2312b7d)[1] != 0x2312bef or rel_call(data, secs, 0x2312bf5) != 0x1e4c9c0:
        raise ValueError('absent expiry writer edge changed')
    pin(data, secs, 0x1e4c9f4, bytes.fromhex('c60431c0'))
    if read(data, secs, rip_target(data, secs, 0x264d75f), 4) != b'Time':
        raise ValueError('queue key type label changed')
    if read(data, secs, rip_target(data, secs, 0x1993a5e), 4) != b'Time':
        raise ValueError('queue pair key type label changed')
    pin(data, secs, 0x1993a56, bytes.fromhex('85ed'))
    pin(data, secs, 0x1993a92, bytes.fromhex('83fd01'))
    pin(data, secs, 0x1993b43, bytes.fromhex('83fd02'))
    if [branch(data, secs, a)[:2] for a in (0x1993a58, 0x1993a95, 0x1993b46)] != [(0x84, 0x1993c74), (0x84, 0x1993cea), (0x85, 0x1993c18)]:
        raise ValueError('queue pair length guards changed')
    pin(data, secs, 0x1deeabd, bytes.fromhex('c6040192'))
    pin(data, secs, 0x264d8b6, bytes.fromhex('4c8dbf48010000'))
    pin(data, secs, 0x264d7f1, bytes.fromhex('48b800000000000000804939c4'))
    pin(data, secs, 0x26834cb, bytes.fromhex('48bd0000000000000080'))
    pin(data, secs, 0x2683579, bytes.fromhex('4839eb'))
    pin(data, secs, 0x24cf254, bytes.fromhex('4969df48010000'))
    pin(data, secs, 0x284e63d, bytes.fromhex('4139e8410f9cc5400f9fc5'))
    pin(data, secs, 0x284e652, bytes.fromhex('4539e9400f97c54080dd00'))
    pin(data, secs, 0x284e662, bytes.fromhex('423b8c1818010000400f97c54080dd00'))
    if branch(data, secs, 0x268357c)[:2] != (0x75, 0x26835c6):
        raise ValueError('queue sequence duplicate branch changed')
    if branch(data, secs, 0x264d7fe)[:2] != (0x85, 0x264d89c):
        raise ValueError('queue duplicate branch changed')
    first = read(data, secs, 0x264d901, 8)
    last = read(data, secs, 0x264d8f3, 8)
    if first[5:] != last[:3]:
        raise ValueError('queue duplicate text overlap changed')
    duplicate = first + last[3:]
    if duplicate != b'duplicate key':
        raise ValueError('queue duplicate text changed')
    sequence_first = read(data, secs, 0x2683631, 8)
    sequence_last = read(data, secs, 0x2683623, 8)
    if sequence_first[5:] != sequence_last[:3] or sequence_first + sequence_last[3:] != duplicate:
        raise ValueError('queue sequence duplicate text changed')
    pin(data, secs, 0x2311ebe, bytes.fromhex('ba08000000'))
    pin(data, secs, 0x2311ef4, bytes.fromhex('ba08000000'))
    if branch(data, secs, 0x2311eb4)[1] != 0x2311eec:
        raise ValueError('outer writer header choice changed')
    pin(data, secs, 0x1778bfe, bytes.fromhex('0f879afcffff'))
    pin(data, secs, 0x1778c04, bytes.fromhex('80f990'))
    pin(data, secs, 0x1778d48, bytes.fromhex('80f9a0'))
    # Default evidence: code paths plus literal binary64, not a guessed value.
    pin(data, secs, 0x1769cba, bytes.fromhex('f68424b003000001'))
    if branch(data, secs, 0x1769cc2)[1] != 0x1769cd5:
        raise ValueError('scale presence branch changed')
    if rip_target_float(data, secs, 0x1769cc4) != 0x20a730:
        raise ValueError('scale constant target changed')
    scale = read(data, secs, 0x20a730, 8)
    if scale != bytes.fromhex('000000000000f03f'):
        raise ValueError('scale default changed')
    pin(data, secs, 0x1768c8c, bytes.fromhex('4983fd02'))
    if branch(data, secs, 0x1768c90)[1] != 0x1768ccd:
        raise ValueError('mode default branch changed')
    pin(data, secs, 0x1768c92, bytes.fromhex('41bd0100000031d231c9'))
    pin(data, secs, 0x22ee7aa, bytes.fromhex('4883fa07'))
    pin(data, secs, 0x22ee7e6, bytes.fromhex('4883fa08'))
    if branch(data, secs, 0x22ee7ae)[1] != 0x22ee7e6 or branch(data, secs, 0x22ee7ea)[1] != 0x22ee828:
        raise ValueError('variant length guards changed')
    if branch(data, secs, 0x23d8e36)[1] != 0x23d8e87:
        raise ValueError('mode writer discriminator changed')
    variants = [variant_arm(data, secs, 0x22ee7b0, 7, 0),
                variant_arm(data, secs, 0x22ee7ec, 8, 1)]
    if read(data, secs, rip_target(data, secs, 0x23d8e91), 7).decode() != variants[0]:
        raise ValueError('enabled writer/reader mismatch')
    if read(data, secs, rip_target(data, secs, 0x23d8e52), 8).decode() != variants[1]:
        raise ValueError('per-asset writer/reader mismatch')
    sequence_guards = (0x17687ad, 0x176880f, 0x176886e, 0x176889c,
                       0x17688cf, 0x1768925, 0x176896e)
    sequence_targets = (0x1768b2a, 0x1768a4b, 0x1768b4f, 0x1768ef3,
                        0x1769099, 0x1769260, 0x17695d7)
    if [branch(data, secs, a)[1] for a in sequence_guards] != list(sequence_targets):
        raise ValueError('sequence missing-element guards changed')
    if branch(data, secs, 0x17698c6)[1] != 0x17698fc:
        raise ValueError('sequence trailing-item branch changed')
    pin(data, secs, 0x1c2956b, bytes.fromhex('4883fa02b801000000480f45c2'))
    pin(data, secs, 0x1c29580, bytes.fromhex('480f44f1'))
    pin(data, secs, 0x1c2958e, bytes.fromhex('f684243802000001'))
    if branch(data, secs, 0x1c29596)[1] != 0x1c295a9:
        raise ValueError('JSON scale presence branch changed')
    if read(data, secs, 0x1c29598, 4) != bytes.fromhex('f20f100d') or 0x1c295a0 + struct.unpack('<i', read(data, secs, 0x1c2959c, 4))[0] != 0x20a730:
        raise ValueError('JSON scale constant changed')
    pins = {
      'queue_map_collect': (0x25e54df, 30),
      'queue_outer_count': (0x1e2590c, 31),
      'queue_pair_header': (0x1deeab9, 10),
      'queue_map_or_sequence_choice': (0x1778bf8, 32),
      'queue_sequence_reader': (0x26834e0, 33),
      'queue_sequence_insert': (0x268355a, 36),
      'queue_sequence_duplicate': (0x2683611, 47),
      'queue_pair_zero_length': (0x1993a53, 34),
      'queue_pair_one_length': (0x1993a89, 38),
      'queue_pair_exact_length': (0x1993b43, 9),
      'queue_pair_excess_length_error': (0x1993c18, 35),
      'queue_value_vector_stride': (0x24cf249, 36),
      'queue_value_record_loop': (0x24cf2a0, 67),
      'queue_record_classifier_dispatch': (0x17b3179, 20),
      'queue_record_field_classifier': (0x22ed683, 233),
      'queue_record_id_classifier': (0x22edcb3, 75),
      'queue_record_missing_user': (0x17b1453, 25),
      'queue_record_missing_action': (0x17b150c, 51),
      'queue_record_missing_id': (0x17b16fc, 35),
      'queue_record_missing_frontend': (0x17b177b, 41),
      'queue_record_missing_broadcaster': (0x17b17f4, 47),
      'queue_record_optional_expiry': (0x17b1d0a, 16),
      'queue_record_expiry_missing_sentinel': (0x17b13d9, 14),
      'queue_expiry_nil_byte': (0x1e4c9f0, 8),
      'queue_record_writer_start': (0x2312921, 52),
      'queue_record_writer_user': (0x2312977, 37),
      'queue_record_writer_action': (0x23129df, 45),
      'queue_record_writer_id': (0x2312a1a, 80),
      'queue_record_writer_id_height': (0x2312a96, 54),
      'queue_record_writer_id_tx_index': (0x2312ad7, 54),
      'queue_record_writer_frontend': (0x2312b1a, 58),
      'queue_record_writer_expiry': (0x2312b5f, 48),
      'queue_record_writer_broadcaster': (0x2312c18, 21),
      'queue_record_broadcaster_name': (0x23d3d6b, 27),
      'queue_record_id_height_duplicate': (0x1886b79, 29),
      'queue_record_id_tx_duplicate': (0x1887064, 35),
      'queue_record_id_missing_guards': (0x188676b, 50),
      'queue_record_id_missing_height': (0x18863c2, 63),
      'queue_record_id_missing_tx': (0x1886799, 63),
      'per_asset_map_value_types': (0x2637dcd, 106),
      'per_asset_map_duplicate': (0x2637e26, 68),
      'per_asset_sequence_duplicate': (0x267e98a, 34),
      'per_asset_sequence_diagnostic': (0x267e9fc, 42),
      'per_asset_pair_length': (0x18bbb18, 55),
      'per_asset_pair_remainder': (0x18bbc80, 32),
      'per_asset_tree_key_order': (0x2850d10, 39),
      'per_asset_tree_existing_replace': (0x2850d57, 17),
      'per_asset_tree_new_value': (0x2850db2, 28),
      'per_asset_writer_walk': (0x25eccff, 30),
      'per_asset_reader_map': (0x180ed5c, 25),
      'per_asset_reader_sequence': (0x180eea0, 25),
      'per_asset_status_writer_choice': (0x2313bfb, 34),
      'per_asset_status_alternating_name': (0x2313c24, 25),
      'per_asset_status_on_name': (0x2313c6b, 25),
      'per_asset_status_seconds_name': (0x2313cbc, 47),
      'per_asset_status_reader_branch': (0x1687d39, 44),
      'per_asset_status_seconds_duplicate': (0x19b3f01, 44),
      'per_asset_status_seconds_missing': (0x19b3f46, 82),
      'per_asset_status_seconds_duplicate_name': (0x19b4472, 80),
      'per_asset_status_classifier': (0x22ef33a, 106),
      'seconds_indirect_dispatch': (0x168463c, 18),
      'seconds_fixint_normalization': (0x16845f3, 36),
      'seconds_marker_table_dispatch': (0x2eb9f35, 32),
      'seconds_positive_fixint': (0x2eb9f90, 18),
      'seconds_negative_fixint': (0x2eba04c, 13),
      'seconds_unsigned8': (0x2eba01c, 48),
      'seconds_unsigned16': (0x2eba090, 53),
      'seconds_unsigned32': (0x2eb9fe9, 51),
      'seconds_unsigned64': (0x2eba170, 84),
      'seconds_signed8': (0x2eba10c, 44),
      'seconds_signed16': (0x2eba059, 55),
      'seconds_signed32': (0x2eb9fb4, 53),
      'seconds_signed64': (0x2eba13d, 50),
      'seconds_integer_success': (0x2eba1bf, 16),
      'seconds_integer_error': (0x2eba1fa, 42),
      'broadcaster_writer_choice': (0x2207a7f, 20),
      'broadcaster_writer_variant_one': (0x2207aa2, 60),
      'broadcaster_writer_variant_zero': (0x2207af2, 46),
      'broadcaster_reader_choice': (0x168b780, 16),
      'broadcaster_reader_variant_one_payload': (0x168b79a, 20),
      'broadcaster_reader_variant_zero_payload': (0x168b847, 23),
      'broadcaster_classifier': (0x21e7b3a, 108),
      'queue_reader_row_loop': (0x264d738, 52),
      'queue_reader_insert': (0x264d7d5, 47),
      'queue_duplicate_error': (0x264d8e1, 47),
      'queue_key_signed_compare': (0x284e635, 23),
      'queue_key_unsigned_compare': (0x284e64a, 43),
      'queue_existing_replace': (0x284e6a6, 35),
      'queue_insert_sentinel': (0x284e7dd, 17),
      'writer_map_or_array_count': (0x2311eb0, 21),
      'writer_mode_compare': (0x23d8e32, 6),
      'writer_per_asset_name_and_call': (0x23d8e52, 24),
      'writer_enabled_name': (0x23d8e87, 25),
      'reader_input_short_two_bytes': (0x1768082, 23),
      'reader_sequence_start': (0x1768776, 30),
      'reader_unknown_key_call': (0x176acf9, 34),
      'reader_default_scale': (0x1769cba, 27),
      'reader_default_mode': (0x1768c8c, 20),
      'mode_map_length': (0x1685136, 24),
      'mode_map16_length': (0x16851a3, 31),
      'mode_map32_length': (0x16852bd, 29),
      'mode_string_classifier_call': (0x1715e86, 19),
      'mode_variant_classifier': (0x22ee7aa, 126),
      'mode_map_classifier_call': (0x22ec06d, 27),
      'mode_value_branch': (0x22ec086, 34),
      'mode_unit_requires_nil': (0x22ec166, 22),
      'sequence_required_guards': (0x17687aa, 9),
      'sequence_missing_mode': (0x176896c, 14),
      'sequence_mode_default': (0x17695d7, 23),
      'sequence_scale_default': (0x17696cb, 15),
      'sequence_remainder': (0x17698bd, 34),
      'json_default_mode': (0x1c2955e, 40),
      'json_default_scale': (0x1c2958e, 34),
      'json_container_entry': (0x1c284e1, 18),
      'json_vty_name_helper': (0x4972d84, 17),
      'json_mode_name_helper': (0x4972cb4, 17),
      'json_writer_open': (0x48b23da, 28),
      'json_mode_tag': (0x48b390e, 9),
    }
    windows = []
    for label, (start, size) in pins.items():
        b, off = mapped(data, secs, start, size)
        owners = [f for f in functions if int(f['start_va'], 16) <= start and start + size <= int(f['end_va_exclusive'], 16)]
        if len(owners) != 1:
            raise ValueError('pin outside selected FDE')
        windows.append({'label': label, 'start_va': hex(start), 'file_offset': hex(off), 'bytes': b.hex()})
    left = read(data, secs, 0x2311e90, 0x2a4)
    right = read(data, secs, 0x48b2660, 0x2a4)
    different = [i for i, (a, b) in enumerate(zip(left, right)) if a != b]
    ranges = []
    for offset in different:
        if ranges and offset == ranges[-1]['end_offset_exclusive']:
            ranges[-1]['end_offset_exclusive'] += 1
        else:
            ranges.append({'start_offset': offset, 'end_offset_exclusive': offset + 1})
    for row in ranges:
        a, b = row['start_offset'], row['end_offset_exclusive']
        row['left_bytes'] = left[a:b].hex()
        row['right_bytes'] = right[a:b].hex()
    return {'target_sha256': DIGEST, 'coordinate_system': 'ELF virtual address; exclusive ends',
            'functions': functions, 'fields': fields, 'field_classifier': extracted,
            'queue_record_fields': record_fields(data, secs), 'queue_record_id_fields': record_id_fields(data, secs),
            'broadcaster_variants': [{'tag': i, 'name': x, 'payload_memory_bytes': (32, 20)[i]}
                                     for i, x in enumerate(broadcaster_variants)],
            'record_diagnostic_prefixes': {'missing': missing_prefix[1:].decode('ascii'),
                                           'duplicate': duplicate_prefix[1:].decode('ascii')},
            'per_asset': {'key_type_label': asset_name.decode('ascii'), 'value_type_label': status_name.decode('ascii'),
                          'key_order': 'u32', 'value_slot_bytes': 8,
                          'status_variants': [{'tag': i, 'name': name} for i, name in enumerate(status_variants)],
                          'status_payload_field': seconds.decode('ascii'),
                          'status_missing_field_lea_va': hex(0x19b3f5a),
                          'status_duplicate_field_lea_va': hex(0x19b4475),
                          'seconds_numeric_slot_va': hex(numeric_slot),
                          'seconds_numeric_rela_addend': hex(relative_slot(data, secs, numeric_slot)),
                          'seconds_numeric_rela_record': relative_slot(data, secs, numeric_slot, detail=True),
                          'seconds_marker_routes': [{'marker': hex(i + 0xc0), 'target_va': hex(x)} for i, x in enumerate(number_routes)],
                          'seconds_integer_guards': [{'va': hex(a), 'opcode': hex(branch(data, secs, a)[0]),
                                                      'target_va': hex(branch(data, secs, a)[1])} for a in guards],
                          'existing_key_result': read(data, secs, 0x2850d62, 1)[0],
                          'map_duplicate_error_va': hex(0x2637e3b + branch(data, secs, 0x2637e3b)[2]),
                          'sequence_duplicate_error_va': hex(branch(data, secs, 0x267e99f)[1]),
                          'read_call_sites': [hex(a) for a in per_asset_calls]},
            'absent_record_expiry': {'writer_null_byte': read(data, secs, 0x1e4c9f7, 1)[0],
                                     'missing_presence_sentinel': read(data, secs, 0x17b1d15, 1)[0]},
            'raw_copy_comparison': {'total_bytes': len(left), 'equal_byte_positions': len(left) - len(different),
                                    'different_byte_positions': len(different), 'difference_ranges': ranges,
                                    'normalization_masks': []},
            'length_dispatch': [{'length': i + 11, 'target_va': hex(x)} for i, x in enumerate(lengths)],
            'field_dispatch': [hex(x) for x in dispatch],
            'queue': {'key_label': read(data, secs, rip_target(data, secs, 0x264d75f), 4).decode('ascii'),
                      'key_size_bytes': read(data, secs, 0x284e5fb, 3)[2] + 4,
                      'key_order': ['i32', 'u32', 'u32'],
                      'pair_marker_byte': read(data, secs, 0x1deeac0, 1)[0],
                      'pair_expected_length': read(data, secs, 0x1993b45, 1)[0],
                      'pair_zero_length_error_va': hex(branch(data, secs, 0x1993a58)[1]),
                      'pair_one_length_error_va': hex(branch(data, secs, 0x1993a95)[1]),
                      'pair_excess_length_error_va': hex(branch(data, secs, 0x1993b46)[1]),
                      'record_stride_bytes': struct.unpack('<I', read(data, secs, 0x264d8b9, 4))[0], 'duplicate_diagnostic': duplicate.decode('ascii'),
                      'write_call_sites': [hex(a) for a in queue_calls[:4]],
                      'read_call_sites': [hex(a) for a in queue_calls[4:]],
                      'duplicate_branch_va': hex(branch(data, secs, 0x264d7fe)[1]),
                      'sequence_duplicate_branch_va': hex(branch(data, secs, 0x268357c)[1])},
            'unknown_field_call': hex(rel_call(data, secs, 0x176ad09)),
            'sequence_missing_guards': [{'position': i, 'branch_va': hex(a), 'target_va': hex(b)}
                                        for i, (a, b) in enumerate(zip(sequence_guards, sequence_targets))],
            'writer_declared_fields': struct.unpack('<I', read(data, secs, 0x2311ebf, 4))[0],
            'scale_default': {'literal_va': hex(0x20a730), 'bytes': scale.hex(),
                              'binary64': struct.unpack('<d', scale)[0]},
            'variants': [{'tag': i, 'name': n} for i, n in enumerate(variants)],
            'raw_windows': windows,
            'limits': 'Static byte-pattern evidence; no captured binary was executed. FDE ranges are unwind extents, not a complete function census.'}


def rip_target_float(data, secs, va):
    b = read(data, secs, va, 8)
    if b[:4] != bytes.fromhex('f30f7e05'):
        raise ValueError('expected scalar constant load')
    return va + 8 + struct.unpack_from('<i', b, 4)[0]


def render_tsv(rows):
    buf = io.StringIO(newline='')
    keys = ('tag', 'name', 'bytes', 'state_offset', 'writer_name_lea_va', 'reader_case_va',
            'duplicate_test_va', 'duplicate_branch_va', 'reader_value_callee_va',
            'msgpack_missing_name_lea_va', 'json_missing_name_lea_va')
    out = csv.DictWriter(buf, fieldnames=keys, delimiter='\t', lineterminator='\n', extrasaction='ignore')
    out.writeheader()
    out.writerows(rows)
    return buf.getvalue()


def render_record_tsv(rows):
    buf = io.StringIO(newline='')
    keys = ('tag', 'name', 'bytes', 'record_offset', 'writer_name_lea_va', 'missing_name_lea_va', 'reader_case_va', 'duplicate_test_va',
            'duplicate_branch_va', 'reader_value_call_va', 'reader_value_callee_va')
    out = csv.DictWriter(buf, fieldnames=keys, delimiter='\t', lineterminator='\n')
    out.writeheader()
    out.writerows(rows)
    return buf.getvalue()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    data = BINARY.read_bytes()
    result = analyze(data)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'evidence.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    (args.out / 'fields.tsv').write_text(render_tsv(result['fields']), encoding='utf-8')
    (args.out / 'record-fields.tsv').write_text(render_record_tsv(result['queue_record_fields']), encoding='utf-8')


if __name__ == '__main__':
    main()
