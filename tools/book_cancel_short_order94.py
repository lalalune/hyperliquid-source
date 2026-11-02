"""Read the bounded cancellation-candidate collection and short sort in node 94.

Static ELF input only. Synthetic fixtures are manual interpretations, not node runs.
"""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
U64 = (1 << 64) - 1
I64_MIN = -(1 << 63)
I64_MAX = (1 << 63) - 1
# These are selected unwind extents, not a census of target functions.
FUNCTIONS = {
    0x42bb100: (0x42bb246, 'c6cafce342e1af3c9994b8f6af99b6531835d445e70df137c511b6419e874c6a'),
    0x4339fe0: (0x433a11b, '1c99bda40d1483ab51dd5d5a407d83601a5c8d8342f7a89d66162c8c50c9982d'),
    0x490d700: (0x490dd30, 'bd91348922855907fabdfa7f1d91a28ba26478e59134944c30c24ac4b02a4045'),
}
# The enclosing function was mapped previously: retain only the windows needed
# to connect the newly selected helpers, and do not claim it as a new subject.
WINDOWS = (
    ('entry-gap', 0x4cdd620, 0x4cdd64b, '40585f4808de34c02b22a995eccc77f4f1d95b4e271961feaa3e0d4ef2fe1e16'),
    ('entry-overflow', 0x4cde17c, 0x4cde1ad, 'c30e62d13126f2c7c5d3cc7089bd72e881c333618c0dd86ca5e39bcdd9bcb2f4'),
    ('iterator-handoff', 0x4cdd862, 0x4cdd8a7, '36f13196969dbe59bfc345ec29590fb00a828a2c193fdb77cdd6c4626e0669a9'),
    ('collect-call', 0x4cdd8a7, 0x4cdd8ca, '7bc4ca3d50555973834a0a16aae9de08e4bcdd8fb3642f982f1e96b61896f340'),
    ('row-build', 0x4cdd8e0, 0x4cdd994, 'db45b29007a84c2858a5b444872b22a808fd33c2037b65cbda2301ce22570c00'),
    ('small-sort-dispatch', 0x4cddd2b, 0x4cddd7b, 'f58bfcb201e34cae484e61b320e59af2ba35e1c0849fc4226d6a59faa46b3558'),
    ('baseline-metric', 0x4cddd7b, 0x4cdde85, 'cf3b34890fa93af1dcff51641d1792e7af4e2fc410b33911dd382d1a3a156ac6'),
    ('cancel-call', 0x4cddec4, 0x4cddf52, 'd0c68c5f3821d48de0c90ace00052d52ae06c19a1c2ceae07fb83fba42a571ed'),
    ('post-cancel-metric', 0x4cddf58, 0x4cde0b9, '720bf64b282249b959880e807bf5663c03feff1491b69394f54fbb623733dacd'),
    ('cancel-stop', 0x4cde0b9, 0x4cde0e5, '6f87fbfc0fd7f3056373a6e28b9bc763244dba3879abd5a0b4678322e406c85a'),
    ('loop-exit', 0x4cde0e5, 0x4cde146, '1370c59f2076feea24bb7cdfd85d2816f09b1525bd407b7f033da86517f0ed73'),
    ('iterator-missing', 0x4cde146, 0x4cde16a, '6341630843b46c0a39ffdb53b414987ec83025522e008411d69125f0f58dbae3'),
    ('book-bounds', 0x4cde16a, 0x4cde17c, '682206930eb32816af59507a8e4ffb91cee12d38cc88af99947a0a4b3d0873f0'),
    ('iterator-tag', 0x4cde1ad, 0x4cde1d1, 'eeee3328dff0ea3eb629cb9821bc5d2fa7a70f192bcb521c1f1329f0cfb5d5ea'),
    ('market-row-bounds', 0x4cde1d1, 0x4cde1ff, '31664ef0d8868cf54cd0c5f902af0a0fe43e42ee714c72508411151012cbb040'),
    ('large-sort-dispatch', 0x4cde25b, 0x4cde271, '82324040218a707c93e95b19103ed36ff9aa6321d71c010920a244b7708f95c4'),
)
CALLS = ((0x4cdd722, 0x4303460), (0x4cde522, 0x4303460),
         (0x4cdd868, 0x42bb100), (0x4cde668, 0x42bb100),
         (0x4cdd8bc, 0x4339fe0), (0x4cde6bc, 0x4339fe0),
         (0x4cdd94c, 0x454f5d0),
         (0x4cddd5e, 0x490d700), (0x4cdeb5e, 0x490d700),
         (0x490d751, 0x36f57f0), (0x490d83c, 0x36f57f0),
         (0x490da3c, 0x36f57f0), (0x490db44, 0x36f57f0),
         (0x4cdddbd, 0x399c7a0), (0x4cddfdd, 0x399c7a0),
         (0x4cddf47, 0x42f7420), (0x4cde12f, 0x432a100),
         (0x490dd2b, 0x5660110))
INDIRECT = ((0x42bb130, bytes.fromhex('488b2d'), 0x576e010, 0x54c8cb0),
            (0x42bb1cb, bytes.fromhex('ff15'), 0x576e010, 0x54c8cb0),
            (0x4cdd61a, bytes.fromhex('ff15'), 0x5774660, 0x36f7560),
            (0x4cddd92, bytes.fromhex('ff15'), 0x5773228, 0x37e4fb0),
            (0x4cddfb0, bytes.fromhex('ff15'), 0x5773228, 0x37e4fb0),
            (0x4cde0fe, bytes.fromhex('ff15'), 0x576e010, 0x54c8cb0),
            (0x4cde14d, bytes.fromhex('ff15'), 0x576e470, 0x157a9f0),
            (0x4cde15f, bytes.fromhex('ff15'), 0x576e470, 0x157a9f0),
            (0x4cde171, bytes.fromhex('ff15'), 0x576e470, 0x157a9f0),
            (0x4cde1b4, bytes.fromhex('ff15'), 0x576e470, 0x157a9f0),
            (0x4cde1c6, bytes.fromhex('ff15'), 0x576e470, 0x157a9f0),
            (0x4cde1f7, bytes.fromhex('ff15'), 0x576e048, 0x157aa10),
            (0x4cde19f, bytes.fromhex('ff15'), 0x5773190, 0x358dcd0),
            (0x4cde26b, bytes.fromhex('ff15'), 0x5776740, 0x44885a0))
LOCATIONS = ((0x5733f20, 'collections/btree/navigate.rs', 600, 48),
             (0x5733f98, 'collections/btree/navigate.rs', 198, 39),
             (0x56e9ae0, 'src/dex_registry/clearinghouses.rs', 11, 29),
             (0x5742338, 'l1/src/books.rs', 19, 47))
BRANCHES = (
    0x42bb120,0x42bb146,0x42bb16c,0x433a002,0x433a060,0x433a07d,
    0x433a08a,0x433a09c,0x433a0bb,0x433a0cc,0x490d75d,0x490d783,
    0x490d7a0,0x490d7a8,0x490d7aa,0x490d7b7,0x490d8fc,0x490d905,
    0x490d907,0x490d91d,0x490d921,0x490d923,0x490d930,0x490d98c,
    0x490da09,0x490dc52,0x490dc60,0x490dc6e,0x490dc74,0x490dc97,
    0x490dc9d,0x4cdd8c4,0x4cdd92f,0x4cddd2f,0x4cddd35,0x4cddd6a,
    0x4cddec8,0x4cddf14,0x4cddf52,0x4cddf75,0x4cde0d0,0x4cde0d5,0x4cde0df,
)


def authenticate(data):
    if hashlib.sha256(data).hexdigest() != DIGEST:
        raise ValueError('target digest mismatch')


def resolve(data, secs, va, length, *, executable=False):
    if va < 0 or length <= 0:
        raise ValueError('invalid range')
    matches = [s for s in secs if s['type'] != 8 and s['flags'] & 2 and
               (not executable or s['flags'] & 4) and
               s['address'] <= va and va + length <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('range is not uniquely file backed')
    s = matches[0]
    off = s['offset'] + va - s['address']
    if off + length > len(data):
        raise ValueError('range exceeds input')
    return off


def read(data, secs, va, length):
    off = resolve(data, secs, va, length, executable=True)
    return data[off:off + length]


def validate_ranges(data, secs):
    for start, (end, expected) in FUNCTIONS.items():
        if hashlib.sha256(read(data, secs, start, end - start)).hexdigest() != expected:
            raise ValueError('selected function bytes mismatch')
    for _, start, end, expected in WINDOWS:
        if hashlib.sha256(read(data, secs, start, end - start)).hexdigest() != expected:
            raise ValueError('context window bytes mismatch')


def direct_call(data, secs, va):
    raw = read(data, secs, va, 5)
    if raw[0] != 0xe8:
        raise ValueError('unexpected call opcode')
    target = va + 5 + struct.unpack_from('<i', raw, 1)[0]
    resolve(data, secs, target, 1, executable=True)
    return target


def branch(data, secs, va):
    lead = read(data, secs, va, 2)
    if 0x70 <= lead[0] <= 0x7f or lead[0] == 0xeb:
        raw = lead
        disp = struct.unpack_from('<b', raw, 1)[0]
    elif lead[0] == 0xe9:
        raw = read(data, secs, va, 5)
        disp = struct.unpack_from('<i', raw, 1)[0]
    elif lead[0] == 0x0f and 0x80 <= lead[1] <= 0x8f:
        raw = read(data, secs, va, 6)
        disp = struct.unpack_from('<i', raw, 2)[0]
    else:
        raise ValueError('unexpected branch opcode')
    target = va + len(raw) + disp
    resolve(data, secs, target, 1, executable=True)
    return target, raw.hex()


def relocation(data, secs, address):
    matches = []
    for s in secs:
        if s['type'] != 4:
            continue
        if s['size'] % 24:
            raise ValueError('partial relocation')
        for off in range(s['offset'], s['offset'] + s['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, off)
            if slot == address:
                matches.append((info, addend))
    if len(matches) != 1 or matches[0][0] != 8:
        raise ValueError('ambiguous or non-relative relocation')
    return matches[0][1]


def indirect_edge(data, secs, site, prefix):
    raw = read(data, secs, site, len(prefix) + 4)
    if raw[:len(prefix)] != prefix:
        raise ValueError('indirect opcode changed')
    slot = site + len(raw) + struct.unpack_from('<i', raw, len(prefix))[0]
    return slot, relocation(data, secs, slot), raw.hex()


def location(data, secs, slot):
    """Read a relocated Rust Location while emitting only a path suffix."""
    pointer = relocation(data, secs, slot)
    off = resolve(data, secs, slot+8, 16)
    length, line, column = struct.unpack_from('<QII', data, off)
    if length == 0 or length > 256:
        raise ValueError('invalid location path length')
    text_off = resolve(data, secs, pointer, length)
    try:
        path = data[text_off:text_off+length].decode('utf-8')
    except UnicodeDecodeError as error:
        raise ValueError('invalid location path') from error
    pieces = path.split('/')
    if len(pieces) < 3:
        raise ValueError('unexpected location path')
    return pointer, length, '/'.join(pieces[-3:]), line, column


def instructions_constants(data, secs):
    # Fixed instruction-start patterns; no disassembler rendering is consumed.
    def immediate(va, prefix, size):
        raw = read(data, secs, va, len(prefix) + size)
        if raw[:len(prefix)] != prefix:
            raise ValueError('constant opcode mismatch')
        return int.from_bytes(raw[len(prefix):], 'little')
    return {
        'hash_multiplier': immediate(0x433a008, bytes.fromhex('48ba'), 8),
        'hash_rotate': immediate(0x433a016, bytes.fromhex('48c1c2'), 1),
        'hash_tag_shift': immediate(0x433a01d, bytes.fromhex('48c1e8'), 1),
        'book_control_offset': immediate(0x433a021, bytes.fromhex('488b79'), 1),
        'book_mask_offset': immediate(0x433a025, bytes.fromhex('4c8b41'), 1),
        'book_slab_length_offset': immediate(0x433a0b7, bytes.fromhex('483b41'), 1),
        'book_slab_pointer_offset': immediate(0x433a0bd, bytes.fromhex('488b49'), 1),
        'slot_vacant_tag': immediate(0x433a0c8, bytes.fromhex('833c01'), 1),
        'slot_owner_offset': immediate(0x433a0e1, bytes.fromhex('f30f6f81'), 4),
        'product_limit': immediate(0x490d8cc, bytes.fromhex('48bf'), 8),
        'position_node_length_offset': immediate(0x490d765, bytes.fromhex('0fb7b9'), 4),
        'position_node_child_offset': immediate(0x490d7b9, bytes.fromhex('488b8cf1'), 4),
        'slot_stride': immediate(0x433a0c1, bytes.fromhex('4869c0'), 4),
        'slot_price_offset': immediate(0x4cdd911, bytes.fromhex('4c8bb0'), 4),
        'book_asset_offset': immediate(0x4cdd8e8, bytes.fromhex('488b89'), 4),
        'slot_size_offset': immediate(0x4cdd902, bytes.fromhex('488b88'), 4),
        'slot_order_id_offset': immediate(0x4cdd918, bytes.fromhex('4c8ba8'), 4),
        'slot_side_offset': immediate(0x4cdd8f7, bytes.fromhex('0fb688'), 4),
        'iterator_length_offset': immediate(0x42bb119, bytes.fromhex('0fb74f'), 1),
        'iterator_leaf_size': immediate(0x42bb12a, bytes.fromhex('41bd'), 4),
        'iterator_internal_size': immediate(0x42bb154, bytes.fromhex('be'), 4),
        'row_stride': immediate(0x4cddd47, bytes.fromhex('41bf'), 4),
        'short_sort_min': immediate(0x4cddd2b, bytes.fromhex('4983fc'), 1),
        'large_sort_min': immediate(0x4cddd31, bytes.fromhex('4983fc'), 1),
        'candidate_sentinel': immediate(0x4cddec4, bytes.fromhex('807820'), 1),
        'book_stride': immediate(0x4cddf1e, bytes.fromhex('4869d9'), 4),
        'asset_divisor': immediate(0x4cddefe, bytes.fromhex('4869c2'), 4),
        'cancel_reason': immediate(0x4cddf41, bytes.fromhex('41b9'), 4),
    }


def hash64(key, multiplier):
    value = (key * multiplier) & U64
    return ((value << 20) | (value >> 44)) & U64


def probe(key, user, controls, buckets, slots, count, multiplier):
    """Lift of bounded control-group probe and slab/user validation.

    Fixtures use a full 16-or-more bucket table, a power-of-two mask and
    well-formed mirrored control bytes. None of the data is from a live node.
    """
    if not 0 <= key <= U64 or len(user) != 20 or count < 0:
        raise ValueError('invalid input')
    capacity = len(controls)
    if capacity < 16 or capacity & (capacity - 1):
        raise ValueError('invalid control capacity')
    if any(not 0 <= c <= 255 for c in controls):
        raise ValueError('invalid control byte')
    if count == 0:
        return 'empty-map', None
    h = hash64(key, multiplier)
    mask = capacity - 1
    tag = h >> 57
    offset = h & mask
    step = 0
    visited = set()
    while offset not in visited:
        visited.add(offset)
        group = [controls[(offset + i) & mask] for i in range(16)]
        for i, control in enumerate(group):
            if control != tag:
                continue
            bucket = (offset + i) & mask
            if bucket not in buckets:
                raise ValueError('occupied control has no bucket')
            candidate, index = buckets[bucket]
            if candidate != key:
                continue
            if index >= len(slots) or index < 0:
                return 'slot-out-of-range', None
            vacancy, owner = slots[index]
            if vacancy == 2:
                return 'vacant-slot', None
            if len(owner) != 20:
                raise ValueError('invalid owner fixture')
            if owner != user:
                return 'owner-mismatch', None
            return 'matched', index
        if 0xff in group:
            return 'key-absent', None
        step += 16
        offset = (offset + step) & mask
    raise ValueError('control probe has no empty marker')


def row(price, asset, size, oid, side, padding=b'\x00' * 7):
    if (any(not 0 <= x <= U64 for x in (price, asset, size, oid)) or
            not 0 <= side <= 255 or len(padding) != 7):
        raise ValueError('invalid row fixture')
    return struct.pack('<QQQQB7s', price, asset, size, oid, side, padding)


def row_from_slot(slot, asset, padding):
    """Copy the fields written by the contextual row builder.

    Padding is supplied explicitly: the target does not initialize it here.
    Slot liveness and ownership have already been checked by the lookup.
    """
    if len(slot) != 0xf8:
        raise ValueError('slot must have the observed stride')
    price = struct.unpack_from('<Q', slot, 0xa0)[0]
    size = struct.unpack_from('<Q', slot, 0xc8)[0]
    oid = struct.unpack_from('<Q', slot, 0xd8)[0]
    return row(price, asset, size, oid, slot[0xc2], padding)


def fields(raw, position):
    if len(raw) != 40 or not I64_MIN <= position <= I64_MAX:
        raise ValueError('invalid record or position')
    return struct.unpack('<QQQQB7s', raw)


def rank_flags(raw, position, limit):
    price, _, size, _, side, _ = fields(raw, position)
    bits = position & U64
    neg = (-bits) & U64
    magnitude = bits if neg & (1 << 63) else neg
    flag = int(size <= magnitude and ((side == 0) != (position > 0)))
    product = price * size
    low, high = product & U64, product >> 64
    invalid = int(high != 0 or low > limit)
    return flag, invalid, low


def position_lookup(node, height, key):
    """Model the selected unsigned-key tree walk on well-formed fixtures.

    The external user lookup that returns the tree is not modeled. Each node
    is a tuple of sorted keys, signed values and child nodes. An absent root or
    an unsuccessful leaf lookup supplies zero, as the selected bytes do.
    """
    if not 0 <= key <= U64 or not 0 <= height <= 255:
        raise ValueError('invalid tree input')
    trace = []
    while node is not None:
        keys, values, children = node
        if (len(keys) != len(values) or
                any(not 0 <= k <= U64 for k in keys) or
                any(a >= b for a,b in zip(keys, keys[1:])) or
                any(not I64_MIN <= v <= I64_MAX for v in values)):
            raise ValueError('malformed node fixture')
        i = 0
        while i < len(keys) and key > keys[i]:
            i += 1
        trace.append(i)
        if i < len(keys) and key == keys[i]:
            return values[i], trace
        if height == 0:
            return 0, trace
        if len(children) != len(keys) + 1 or children[i] is None:
            raise ValueError('malformed tree children')
        node, height = children[i], height - 1
    return 0, trace


def move_before(left, right, positions, limit):
    """Lift selected short-sort decisions: whether right moves before left."""
    a = rank_flags(left, positions.get(fields(left, 0)[1], 0), limit)
    b = rank_flags(right, positions.get(fields(right, 0)[1], 0), limit)
    return flag_decision(a, b)


def flag_decision(a, b):
    """Whether the right-hand class precedes the left-hand class."""
    if any(x not in (0, 1) for x in (a[0], a[1], b[0], b[1])):
        raise ValueError('rank flags must be bits')
    if not 0 <= a[2] <= U64 or not 0 <= b[2] <= U64:
        raise ValueError('rank product lows must be u64')
    if a[0] != b[0]:
        return a[0] == 1 and b[0] == 0
    if b[1]:
        return not a[1]
    return not a[1] and b[2] < a[2]


def short_sort(rows, positions, limit, large_min):
    if len(rows) >= large_min:
        raise ValueError('outside selected short-sort path')
    result = list(rows)
    for i in range(1, len(result)):
        moving = result[i]
        j = i
        while j and move_before(result[j - 1], moving, positions, limit):
            result[j] = result[j - 1]
            j -= 1
        result[j] = moving
    return result


def oracle_key(raw, positions, limit):
    price, asset, size, _, side, _ = fields(raw, 0)
    p = positions.get(asset, 0)
    if not I64_MIN <= p <= I64_MAX:
        raise ValueError('position outside signed word')
    flag = int(size <= abs(p) and ((side == 0) != (p > 0)))
    product = price * size
    valid = product <= limit
    return flag, int(valid), product if valid else 0


def lookup_cases(multiplier):
    user = bytes(range(20))
    other = bytes(reversed(range(20)))
    key = 0x1234
    h = hash64(key, multiplier)
    bucket = h & 31
    tag = h >> 57
    result = []
    for name, mode in (
        ('empty-map', 'empty'), ('key-absent', 'absent'),
        ('tag-collision', 'collision'), ('slot-out-of-range', 'range'),
        ('vacant-slot', 'vacant'), ('owner-mismatch', 'owner'),
        ('live-match', 'live'), ('vacancy-low-word', 'wide-vacancy')):
        controls = [0xff] * 32
        buckets = {}
        slots = [(0, user)]
        count = 1
        if mode == 'empty':
            count = 0
        elif mode == 'collision':
            controls[bucket] = tag
            buckets[bucket] = (key + 1, 0)
        elif mode != 'absent':
            controls[bucket] = tag
            buckets[bucket] = (key, 1 if mode == 'range' else 0)
            if mode == 'vacant': slots = [(2, user)]
            if mode == 'owner': slots = [(0, other)]
            # The actual instruction compares a dword: model the low dword.
            if mode == 'wide-vacancy': slots = [((0x100000002 & 0xffffffff), user)]
        outcome, index = probe(key, user, controls, buckets, slots, count, multiplier)
        result.append((name, hex(key), hex(h), hex(bucket), hex(tag), outcome,
                       '' if index is None else index))
    return result


def tree_cases():
    leaf = ([10,20], [-9,14], [])
    root = ([20,40], [-2,4], [([10],[-1],[]),([30],[3],[]),([50],[5],[])])
    cases = [('empty', None, 0, 10)]
    cases += [('leaf', leaf, 0, key) for key in (0,10,15,20,21,U64)]
    cases += [('branch', root, 1, key) for key in (0,10,15,20,25,30,35,40,45,50,55)]
    result = []
    for name, node, height, key in cases:
        value, trace = position_lookup(node,height,key)
        result.append((name,height,key,value,','.join(str(x) for x in trace)))
    return result


def sort_cases(limit, large_min):
    pos = {11: 3, 12: -4, 13: 0, 14: I64_MIN}
    rows = [row(4,11,2,1,0,b'A'*7), row(limit,13,2,2,1,b'B'*7),
            row(2,12,3,3,1,b'C'*7), row(3,12,2,4,1,b'D'*7),
            row(1,14,1 << 63,5,0,b'E'*7), row(0,13,0,6,0,b'F'*7),
            row(3,12,2,7,1,b'G'*7)]
    seqs = [('empty', []), ('one', rows[:1]), ('pair', rows[:2]),
            ('tie', [rows[3], rows[6]]), ('mixed', rows),
            ('twenty', (rows * 3)[:20])]
    out = []
    for name, raw in seqs:
        observed = short_sort(raw, pos, limit, large_min)
        expected = sorted(raw, key=lambda x: oracle_key(x, pos, limit))
        if observed != expected:
            raise ValueError('manual lift disagrees with independent key oracle')
        ids = lambda seq: ','.join(str(fields(x, 0)[3]) for x in seq)
        out.append((name, len(raw), ids(raw), ids(observed), ids(expected)))
    return out


def rank_cases():
    out = []
    for af in (0, 1):
        for bf in (0, 1):
            for ai in (0, 1):
                for bi in (0, 1):
                    for ap in (0, 1, U64):
                        for bp in (0, 1, U64):
                            left, right = (af, ai, ap), (bf, bi, bp)
                            got = flag_decision(left, right)
                            # An independent lexicographic reading of the flags.
                            key = lambda x: (x[0], 1-x[1], x[2] if not x[1] else 0)
                            expected = key(right) < key(left)
                            if got != expected:
                                raise ValueError('rank flag lift disagrees with oracle')
                            out.append((af, bf, ai, bi, ap, bp, int(got)))
    return out


def entry_gap(requested, current):
    """Signed saturating subtraction, then clamp the result to zero."""
    if not I64_MIN <= requested <= I64_MAX or not I64_MIN <= current <= I64_MAX:
        raise ValueError('entry inputs must be signed words')
    difference = requested-current
    saturated = min(I64_MAX, max(I64_MIN, difference))
    return max(0, saturated), difference != saturated


def consume(rows, book_count, initial, threshold, outcomes, after, divisor, *,
            book_assets, market_count):
    """Finite supplied outcomes for the cancellation loop, not target execution.

    Outcomes map IDs to the callee's low-byte return. On a zero return the
    caller observes the supplied post-cancel book asset and metric. Other
    external mutations are not modeled. Prior sorting is input order.
    """
    if (book_count < 0 or market_count < 0 or not 0 <= initial <= U64 or
            not 0 <= threshold <= U64 or divisor <= 0):
        raise ValueError('invalid loop fixture')
    calls = []
    for raw in rows:
        _, asset, _, oid, side, _ = fields(raw, 0)
        if side == 2:
            return calls, 'sentinel'
        local = asset % divisor
        if local >= book_count:
            return calls, 'book-bound-failure'
        if oid not in outcomes or not 0 <= outcomes[oid] <= 255:
            raise ValueError('missing or invalid callee result')
        calls.append(oid)
        if outcomes[oid] == 0:
            if local not in book_assets or not 0 <= book_assets[local] <= U64:
                raise ValueError('missing or invalid post-cancel book asset')
            if book_assets[local] // divisor >= market_count:
                return calls, 'market-row-bound-failure'
            if oid not in after or not 0 <= after[oid] <= U64:
                raise ValueError('missing or invalid post-cancel metric')
            decrease = max(0, initial - after[oid])
            if decrease >= threshold:
                return calls, 'threshold'
    return calls, 'end'


def transition_cases(divisor):
    a = row(10, 10001, 1, 11, 0)
    b = row(11, 10002, 2, 12, 1)
    sentinel = row(0, 0, 0, 13, 2)
    invalid = row(0, 10003, 0, 14, 0)
    normal = {1:10001,2:10002}
    cases = (
        ('no-rows', [], 3, 9, 2, {}, {}, normal, 2),
        ('first-sentinel', [sentinel, a], 3, 9, 2, {}, {}, normal, 2),
        ('bad-book', [invalid], 3, 9, 2, {}, {}, normal, 2),
        ('nonzero-then-success', [a, b], 3, 9, 2, {11:1, 12:0}, {12:7}, normal, 2),
        ('success-below-threshold', [a, b], 3, 9, 3, {11:0, 12:0}, {11:7, 12:5}, normal, 2),
        ('counter-increases', [a], 3, 9, 1, {11:0}, {11:10}, normal, 2),
        ('threshold-zero', [a, b], 3, 9, 0, {11:0, 12:0}, {11:9, 12:9}, normal, 2),
        ('selected-book-market-bound', [a], 3, 9, 1, {11:0}, {}, {1:30001}, 2),
        ('nonzero-skips-market-bound', [a], 3, 9, 1, {11:1}, {}, {1:30001}, 2),
    )
    result = []
    for name, rows, count, initial, threshold, outcomes, after, book_assets, markets in cases:
        calls, stop = consume(rows, count, initial, threshold, outcomes, after, divisor,
                              book_assets=book_assets, market_count=markets)
        render = lambda values: ','.join(f'{k}={values[k]}' for k in sorted(values))
        result.append((name, len(rows), count, initial, threshold, markets,
                       render(book_assets), render(outcomes), render(after),
                       ','.join(str(x) for x in calls), stop))
    return result


def pipeline_case(constants):
    """Compose synthetic lookup, row construction, ranking and consumption."""
    multiplier = constants['hash_multiplier']
    owner = bytes(range(20))
    other = bytes(reversed(range(20)))
    capacity = 32
    controls = [0xff] * capacity
    buckets = {}
    keys = []
    # Choose distinct initial buckets deterministically for this fixture.
    for key in range(1,1000):
        index = hash64(key,multiplier) & (capacity-1)
        if index not in buckets:
            keys.append(key)
            controls[index] = hash64(key,multiplier) >> 57
            buckets[index] = (key,len(keys)-1)
            if len(keys) == 4:
                break
    if len(keys) != 4:
        raise ValueError('fixture could not allocate four buckets')
    slots = []
    for i, (price,size,oid,side,who) in enumerate(((8,2,11,0,owner),
                                                     (3,2,12,1,owner),
                                                     (1,1,13,0,other),
                                                     (0,1,14,0,owner))):
        record = bytearray(constants['slot_stride'])
        struct.pack_into('<Q',record,0xa0,price)
        struct.pack_into('<Q',record,0xc8,size)
        struct.pack_into('<Q',record,0xd8,oid)
        record[0xc2] = side
        record[0xe0:0xf4] = who
        slots.append(record)
    # Fourth index is deliberately stale. Slot three exists but is not used.
    fourth = hash64(keys[3],multiplier) & (capacity-1)
    buckets[fourth] = (keys[3],len(slots))
    slab = [(struct.unpack_from('<I',s,0)[0],bytes(s[0xe0:0xf4])) for s in slots]
    picked = []
    lookup_outcomes = []
    for key, asset in zip(keys, (10001,10002,10003,10004)):
        outcome, index = probe(key,owner,controls,buckets,slab,len(keys),multiplier)
        lookup_outcomes.append(outcome)
        if index is not None:
            picked.append(row_from_slot(slots[index],asset,bytes([index])*7))
    positions = {10001:3, 10002:-3}
    ordered = short_sort(picked,positions,constants['product_limit'],constants['large_sort_min'])
    calls, stop = consume(ordered,5,10,2,{11:0,12:1},{11:8},constants['asset_divisor'],
                          book_assets={1:10001,2:10002}, market_count=2)
    ids = lambda seq: ','.join(str(fields(x,0)[3]) for x in seq)
    return [(','.join(str(k) for k in keys), ','.join(lookup_outcomes),
             ids(picked),ids(ordered),','.join(str(k) for k in calls),stop)]


def tsv(path, header, rows):
    buf = io.StringIO(newline='')
    writer = csv.writer(buf, delimiter='\t', lineterminator='\n')
    writer.writerow(header)
    writer.writerows(rows)
    path.write_text(buf.getvalue(), encoding='utf-8')


def generate(data, out):
    authenticate(data)
    secs, index = unwind_index(data)
    _, fdes = eh_frame_records(data, secs)
    validate_ranges(data, secs)
    fde_rows = []
    for start, (end, _) in sorted(FUNCTIONS.items()):
        found = [f for f in fdes if f['start'] == start]
        ix = [e for e in index if e['start'] == start]
        if len(found) != 1 or len(ix) != 1 or found[0]['fde'] != ix[0]['fde'] or found[0]['end'] != end:
            raise ValueError('ambiguous or changed FDE')
        body = read(data, secs, start, end-start)
        fde_rows.append({'start_va': hex(start), 'end_va': hex(end),
                         'fde_va': hex(found[0]['fde']),
                         'lsda_va': None if found[0]['lsda'] is None else hex(found[0]['lsda']),
                         'file_offset': hex(resolve(data, secs, start, len(body))),
                         'length_bytes': len(body),
                         'sha256': hashlib.sha256(body).hexdigest(), 'bytes': body.hex()})
    for site, target in CALLS:
        if direct_call(data, secs, site) != target:
            raise ValueError('direct call target changed')
    # Bounded RIP-relative loads/calls and their ELF RELATIVE relocations.
    # Their targets remain external edges, not selected functions.
    indirect = []
    for site, prefix, expected_slot, expected_target in INDIRECT:
        slot, target, raw = indirect_edge(data, secs, site, prefix)
        if (slot, target) != (expected_slot, expected_target):
            raise ValueError('indirect edge changed')
        indirect.append((hex(site),raw,hex(slot),hex(target)))
    locations = []
    for slot, expected_path, expected_line, expected_column in LOCATIONS:
        pointer, length, path, line, column = location(data,secs,slot)
        if (path,line,column) != (expected_path,expected_line,expected_column):
            raise ValueError('location changed')
        locations.append((hex(slot),hex(pointer),length,path,line,column))
    c = instructions_constants(data, secs)
    expected = {'hash_multiplier':0xf1357aea2e62a9c5, 'hash_rotate':20,
                'hash_tag_shift':57, 'book_control_offset':0x28, 'book_mask_offset':0x30,
                'book_slab_length_offset':0x10, 'book_slab_pointer_offset':0x08,
                'slot_vacant_tag':2, 'slot_owner_offset':0xe0,
                'product_limit':0x7ffffffffffffffe, 'position_node_length_offset':0x322,
                'position_node_child_offset':0x328, 'slot_stride':0xf8, 'slot_price_offset':0xa0,
                'book_asset_offset':0xb0, 'slot_size_offset':0xc8, 'slot_order_id_offset':0xd8,
                'slot_side_offset':0xc2, 'iterator_length_offset':0x62,
                'iterator_leaf_size':0x68, 'iterator_internal_size':0xc8, 'row_stride':0x28,
                'short_sort_min':2, 'large_sort_min':21, 'candidate_sentinel':2,
                'book_stride':0xd8, 'asset_divisor':10000, 'cancel_reason':7}
    if c != expected:
        raise ValueError('constants changed')
    lookup = lookup_cases(c['hash_multiplier'])
    trees = tree_cases()
    sort = sort_cases(c['product_limit'], c['large_sort_min'])
    rank = rank_cases()
    transitions = transition_cases(c['asset_divisor'])
    pipeline = pipeline_case(c)
    gap_inputs = ((0,0), (1,0), (0,1), (I64_MAX,-1), (I64_MIN,1),
                  (I64_MAX,I64_MIN), (I64_MIN,I64_MAX))
    out.mkdir(parents=True, exist_ok=True)
    evidence = {'artifact_sha256': DIGEST, 'functions': fde_rows,
                'counts': {'selected_fdes': len(fde_rows), 'context_windows': len(WINDOWS),
                           'direct_call_sites': len(CALLS), 'selected_branches': len(BRANCHES),
                           'indirect_sites': len(indirect),
                           'location_records': len(locations),
                           'lookup_cases': len(lookup), 'tree_cases': len(trees),
                           'sort_cases': len(sort), 'rank_cases': len(rank),
                           'gap_cases': len(gap_inputs), 'transition_cases': len(transitions),
                           'pipeline_cases': len(pipeline)},
                'constants': {k: hex(v) for k,v in sorted(c.items())},
                'scope': 'Selected FDEs and bounded context only; synthetic models are not target execution.'}
    (out/'evidence.json').write_text(json.dumps(evidence, indent=2, sort_keys=True)+'\n', encoding='utf-8')
    tsv(out/'windows.tsv', ('name','start_va','end_va','file_offset','sha256','bytes'),
        [(name,hex(start),hex(end),hex(resolve(data,secs,start,end-start)),expected,
          read(data,secs,start,end-start).hex()) for name,start,end,expected in WINDOWS])
    tsv(out/'branches.tsv', ('site_va','target_va','bytes'),
        [(hex(site),hex(branch(data,secs,site)[0]),branch(data,secs,site)[1]) for site in BRANCHES])
    tsv(out/'calls.tsv', ('site_va','target_va','bytes'),
        [(hex(site),hex(direct_call(data,secs,site)),read(data,secs,site,5).hex()) for site,_ in CALLS])
    tsv(out/'indirect.tsv', ('site_va','bytes','slot_va','relative_addend_va'), indirect)
    tsv(out/'locations.tsv', ('slot_va','path_va','path_length','path_suffix','line','column'), locations)
    tsv(out/'lookup-cases.tsv', ('fixture','key','hash','bucket','tag','outcome','slot'), lookup)
    tsv(out/'tree-cases.tsv', ('fixture','height','key','position','child_indices'), trees)
    tsv(out/'sort-cases.tsv', ('fixture','count','input_oids','result_oids','oracle_oids'), sort)
    tsv(out/'rank-cases.tsv', ('left_flag','right_flag','left_invalid','right_invalid',
                               'left_low','right_low','move_right_before_left'), rank)
    tsv(out/'transition-cases.tsv', ('fixture','rows','book_count','initial','threshold',
                                     'market_count','post_book_assets','callee_results',
                                     'post_metrics','called_oids','stop'), transitions)
    tsv(out/'gap-cases.tsv', ('requested','current','positive_gap','signed_overflow'),
        [(a,b,entry_gap(a,b)[0],int(entry_gap(a,b)[1])) for a,b in gap_inputs])
    tsv(out/'pipeline-cases.tsv', ('candidate_keys','lookup_outcomes','collected_oids',
                                   'sorted_oids','called_oids','stop'), pipeline)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    generate(TARGET.read_bytes(), args.out)


if __name__ == '__main__':
    main()
