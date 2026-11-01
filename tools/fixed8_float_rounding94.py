#!/usr/bin/env python3
"""Static node #94 fixed-eight formatting path and rounding guard evidence.

Only file-backed ELF bytes are read. All machine-instruction interpretations are
bounded lifts, not execution of the captured program. See the work-item README
for the exact domain and for the assumptions at calls into shared formatter code.
"""
from __future__ import annotations

import argparse
from collections import Counter
from fractions import Fraction
import hashlib
import itertools
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import elf_index
import fde_extents

TARGET = ROOT / 'artifacts/node/94/hl-node'
TARGET_HASH = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
FUNCTIONS = {
    0x13cd260: ('fixed-eight wrapper', '5bff25d001f328af543afda0068ff3c84be638e3ad6fc2528eff736c9cbd9781'),
    0x15711b0: ('precision formatter and routing', 'b1d6c3085f7b62365d3accb3541856c56e8af205e65eb3246662eaf677d90705'),
    0x1575e20: ('decimal pieces', 'afa9fb72101e6d30beb4c0a593e81d209a01f08e893d3063324542fb5e473548'),
    0x1575f90: ('fast rounding decision', 'cbe5c33cdecb8ebcef3a9fe499713a76210b1d8325b5295c88f9a1b741e40a6d'),
    0x1576140: ('fast digit generator', 'c50840d4035c67154747870ea3afdbbc24b8e7caba85f9d1af2f956d1565dd73'),
    0x1576b90: ('fallback digit generator', '8c4617277e8e48b921ff6673bcae9bea70b5851fb395336caa65ac83e9940f7e'),
    0x15728c0: ('piece writer', '69dccfbf115aa7abea913e32cb73b58aa323895dd87db03ddd27f009a9679434'),
}
# These instruction bytes bind the manually transcribed arithmetic predicates.
GUARD_START = 0x1575f9e
GUARD_END = 0x1575fe1
GUARD_BYTES = bytes.fromhex(
    '4c8b5520488b45184989c34d29d376334d39d3762e4c8b5d104889c3'
    '4c29db4c39db76124989c64d29de4d29de4b8d1c124939de73234d29d3'
    '76084c29d84c39d87627')
GUARD_LEAVES = {0x1575fe1: 'fallback', 0x1575ff7: 'keep', 0x1576008: 'increment'}

# Selected, manually reviewed conditional instruction starts, not a linear
# sweep or a claim that every conditional in these FDEs was decoded.
BRANCH_SITES = (
    0x13cd2b5, 0x13cd2d3, 0x13cd2db, 0x13cd2ee, 0x13cd384, 0x13cd392, 0x13cd39a, 0x13cd3aa,
    0x15712d7, 0x15712dc, 0x1571370, 0x15713c9, 0x15713ef, 0x1571462, 0x15714c8, 0x15714dc,
    0x1571d60,  # branch at a previously scoped shared callback; edge only
    0x15728e0, 0x1572900, 0x15729c4, 0x1572a19, 0x1572aa2, 0x1572ab7, 0x1572afa,
    0x1575e27, 0x1575e30, 0x1575e3a, 0x1575e49, 0x1575e58, 0x1575e96, 0x1575ee0, 0x1575ee5, 0x1575f01,
    0x1575ffa, 0x157600b, 0x1576023, 0x1576035, 0x1576072, 0x15760d4, 0x15760df,
    0x157615b, 0x157616b, 0x1576174, 0x15761c1, 0x1576218, 0x1576243, 0x1576251,
    0x157636f, 0x1576394, 0x157793d, 0x1577953, 0x1577967, 0x1577971, 0x1577975,
    0x1577994, 0x157799d, 0x15779b3, 0x15779c5, 0x15779ec, 0x1577a14, 0x1577a19,
    0x1577a2e, 0x1577a39,
)
COND = ('o', 'no', 'b', 'ae', 'e', 'ne', 'be', 'a', 's', 'ns', 'p', 'np', 'l', 'ge', 'le', 'g')

# Windows whose manually read semantics underpin the proof. A full-body hash
# also binds every other byte in each selected FDE.
WINDOWS = {
    'request': (0x13cd267, 70),
    'trimming_test': (0x13cd2ad, 41),
    'dot_and_negative_zero': (0x13cd379, 73),
    'float_classification': (0x15711c4, 147),
    'normal_conversion': (0x157125e, 47),
    'subnormal_conversion': (0x1571295, 22),
    'formatter_buffer_guard': (0x157134d, 58),
    'fast_route': (0x15713b5, 21),
    'fallback_route': (0x15714a2, 32),
    'fast_index': (0x1576155, 144),
    'fast_rounded_product': (0x15761c7, 31),
    'fast_rounding_guard': (GUARD_START, GUARD_END - GUARD_START),
    'piece_builder_guards': (0x1575e20, 32),
    'writer_error_branches': (0x15729b2, 24),
    'external_callback_precision_edge_only': (0x1571d5a, 42),
    'fast_carry': (0x1575ff7, 104),
    'fast_all_nines': (0x157606f, 116),
    'slow_compare': (0x1577947, 77),
    'slow_carry': (0x157799a, 50),
    'slow_all_nines': (0x15779e8, 63),
    'slow_tie_parity': (0x1577a27, 24),
    'slow_buffer_pointer': (0x1577272, 14),
    'slow_times_ten': (0x1577710, 31),
    'slow_times_five': (0x1577880, 45),
}

ASSERTIONS = {
    'formatter_capacity': (0x255d93, b'assertion failed: buf.len() >= maxlen'),
    'positive_mantissa': (0x2562c8, b'assertion failed: d.mant > 0'),
    'mantissa_width': (0x2562e4, b'assertion failed: d.mant < (1 << 61)'),
    'buffer_nonempty': (0x255d4d, b'assertion failed: !buf.is_empty()'),
    'first_digit_positive': (0x255d6e, b"assertion failed: buf[0] > b'0'"),
    'piece_capacity': (0x255cf0, b'assertion failed: parts.len() >= 4'),
}
# Each target below is resolved from a direct rel32 call, an R_X86_64_RELATIVE
# slot, or a GLOB_DAT symbol. Prior work already covers shared formatting
# edges; they are retained as edges only, not selected subject bodies here.
EDGES = (
    ('input_call_site_only', 0x3330289, 'indirect', 0x576ea10, 0x13cd260),
    ('format_dispatch', 0x13cd2a7, 'indirect', 0x576e040, 0x1344760),
    ('format_controller_edge_only', 0x1344873, 'indirect', 0x576e008, 0x1571d90),
    ('display_callback_load', 0x13cd27a, 'load', 0x576ea18, 0x1571d50),
    ('precision_dispatch_edge_only', 0x1571d7f, 'jump', None, 0x15711b0),
    ('fast_generator', 0x15713bb, 'indirect', 0x5770600, 0x1576140),
    ('slow_generator', 0x15714ba, 'indirect', 0x5770610, 0x1576b90),
    ('piece_builder', 0x157140e, 'indirect', 0x5770608, 0x1575e20),
    ('piece_writer', 0x1571573, 'direct', None, 0x15728c0),
    ('fast_guard_a', 0x15763da, 'direct', None, 0x1575f90),
    ('fast_guard_b', 0x1576498, 'direct', None, 0x1575f90),
    ('fast_carry_fill', 0x157605b, 'symbolic', 0x576e1f8, 'memset'),
    ('fast_all_nines_fill', 0x157609c, 'symbolic', 0x576e1f8, 'memset'),
    ('slow_carry_fill', 0x15779da, 'symbolic', 0x576e1f8, 'memset'),
    ('slow_all_nines_fill', 0x1577a02, 'symbolic', 0x576e1f8, 'memset'),
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def check_target(data):
    if digest(data) != TARGET_HASH:
        raise ValueError('node 94 SHA-256 mismatch')


class Image:
    def __init__(self, data, authenticate=True):
        if authenticate:
            check_target(data)
        self.data = data
        self.sections = elf_index.sections(data)
        _, all_fdes = fde_extents.eh_frame_records(data, self.sections)
        _, index = elf_index.unwind_index(data)
        indexed = {r['start']: r['fde'] for r in index}
        self.fdes = {}
        for row in all_fdes:
            if row['start'] in FUNCTIONS:
                if row['start'] in self.fdes:
                    raise ValueError('duplicate selected FDE start')
                if indexed.get(row['start']) != row['fde']:
                    raise ValueError('selected FDE is not the indexed FDE')
                self.fdes[row['start']] = row
        if set(self.fdes) != set(FUNCTIONS):
            raise ValueError('missing selected FDE')
        rela = [s for s in self.sections if s['name'] == '.rela.dyn' and s['type'] != 8]
        if len(rela) != 1 or rela[0]['size'] % 24:
            raise ValueError('invalid relative relocation section')
        self.relocations = {}
        self.symbol_relocations = {}
        for off in range(rela[0]['offset'], rela[0]['offset'] + rela[0]['size'], 24):
            address, info, addend = struct.unpack_from('<QQq', data, off)
            if info & 0xffffffff == 8:
                if address in self.relocations:
                    raise ValueError('duplicate relative relocation')
                self.relocations[address] = addend
            if info & 0xffffffff == 6:
                if address in self.symbol_relocations:
                    raise ValueError('duplicate symbol relocation')
                self.symbol_relocations[address] = (info >> 32, addend)

    def region(self, va, length, executable=False):
        if va < 0 or length <= 0:
            raise ValueError('invalid address or length')
        matching = [s for s in self.sections if s['type'] != 8 and s['size'] and
                    s['address'] <= va and va + length <= s['address'] + s['size'] and
                    (not executable or s['flags'] & 4)]
        if len(matching) != 1:
            raise ValueError('address is not uniquely file-backed')
        sec = matching[0]
        off = sec['offset'] + va - sec['address']
        if off + length > len(self.data):
            raise ValueError('file-backed range truncated')
        return off, bytes(self.data[off:off + length])

    def bytes(self, va, length, executable=False):
        return self.region(va, length, executable)[1]

    def body(self, start):
        fde = self.fdes[start]
        length = fde['end'] - start
        off, raw = self.region(start, length, executable=True)
        if digest(raw) != FUNCTIONS[start][1]:
            raise ValueError('selected function body mismatch')
        return off, raw

    def relative(self, slot, expected):
        if self.relocations.get(slot) != expected:
            raise ValueError('relative relocation target mismatch')
        return expected

    def symbolic(self, slot, expected):
        """Resolve one GLOB_DAT symbol using file-backed shared section data."""
        found = self.symbol_relocations.get(slot)
        if found is None or found[1] != 0:
            raise ValueError('symbol relocation mismatch')
        symbol_index = found[0]
        dynsym = [s for s in self.sections if s['name'] == '.dynsym' and s['type'] == 11]
        dynstr = [s for s in self.sections if s['name'] == '.dynstr' and s['type'] == 3]
        if (len(dynsym) != 1 or len(dynstr) != 1 or dynsym[0]['size'] % 24 or
                24 * (symbol_index + 1) > dynsym[0]['size']):
            raise ValueError('symbol table bounds mismatch')
        name_offset = struct.unpack_from('<I', self.data, dynsym[0]['offset'] + 24 * symbol_index)[0]
        if name_offset >= dynstr[0]['size']:
            raise ValueError('symbol name outside string table')
        start = dynstr[0]['offset'] + name_offset
        end = self.data.find(b'\0', start, dynstr[0]['offset'] + dynstr[0]['size'])
        if end < 0 or bytes(self.data[start:end]) != expected.encode('ascii'):
            raise ValueError('symbol name mismatch')
        return {'symbol': expected, 'symbol_index': symbol_index, 'relocation_type': 6, 'addend': found[1]}


def branch(image, va):
    data = image.bytes(va, 6, executable=True)
    if 0x70 <= data[0] <= 0x7f:
        length, cc, disp = 2, data[0] & 15, struct.unpack_from('<b', data, 1)[0]
    elif data[0] == 0x0f and 0x80 <= data[1] <= 0x8f:
        length, cc, disp = 6, data[1] & 15, struct.unpack_from('<i', data, 2)[0]
    else:
        raise ValueError('expected conditional branch')
    return {'site': hex(va), 'bytes': data[:length].hex(), 'condition': COND[cc],
            'target': hex(va + length + disp)}


def read_edge(image, entry):
    label, site, kind, slot, expected = entry
    if kind in ('direct', 'jump'):
        data = image.bytes(site, 5, True)
        if data[0] != (0xe8 if kind == 'direct' else 0xe9):
            raise ValueError('expected direct call')
        target = site + 5 + struct.unpack_from('<i', data, 1)[0]
        if target != expected:
            raise ValueError('direct call target mismatch')
        return {'kind': kind, 'site': hex(site), 'bytes': data.hex(), 'target': hex(target)}
    size = 6 if kind in ('indirect', 'symbolic') else 7
    data = image.bytes(site, size, True)
    if kind in ('indirect', 'symbolic') and data[:2] != b'\xff\x15':
        raise ValueError('expected RIP-relative indirect call')
    if kind == 'load' and data[:3] != b'\x48\x8b\x05':
        raise ValueError('expected RIP-relative load')
    actual_slot = site + size + struct.unpack_from('<i', data, size - 4)[0]
    if actual_slot != slot:
        raise ValueError('call or load slot mismatch')
    if kind == 'symbolic':
        result = image.symbolic(slot, expected)
        result.update({'kind': kind, 'site': hex(site), 'bytes': data.hex(), 'slot': hex(slot)})
        return result
    image.relative(slot, expected)
    return {'kind': kind, 'site': hex(site), 'bytes': data.hex(),
            'slot': hex(slot), 'target': hex(expected)}


def read_request(image):
    """Bind this caller's descriptor rows and the external precision edge."""
    request = bytes.fromhex(
        'f20f11442420488d4424204889442428'
        '488b0597173a04488944243048c74424380000000066c74424400800')
    if image.bytes(0x13cd26a, len(request), True) != request:
        raise ValueError('format descriptor bytes changed')
    template = image.bytes(0x20a150, 8)
    if template != bytes.fromhex('e520000070010000'):
        raise ValueError('format request template changed')
    if (image.bytes(0x1571d5a, 8, True) != bytes.fromhex('f7c6000000107510') or
            image.bytes(0x1571d72, 13, True) != bytes.fromhex('c1ee1583e6010fb750164889c7')):
        raise ValueError('shared callback precision edge changed')
    return template


def guard_program(raw):
    """Parse fixed opcode patterns and relative branch targets without executing them."""
    if raw != GUARD_BYTES:
        raise ValueError('fast rounding guard bytes changed')
    steps = {
        bytes.fromhex('4c8b5520'): ('load_c', 4),
        bytes.fromhex('488b4518'): ('load_b', 4),
        bytes.fromhex('4989c3'): ('copy_b', 3),
        bytes.fromhex('4d29d3'): ('r11_sub_r10', 3),
        bytes.fromhex('4d39d3'): ('cmp_r11_r10', 3),
        bytes.fromhex('4c8b5d10'): ('load_a', 4),
        bytes.fromhex('4889c3'): ('rbx_from_rax', 3),
        bytes.fromhex('4c29db'): ('rbx_sub_r11', 3),
        bytes.fromhex('4c39db'): ('cmp_rbx_r11', 3),
        bytes.fromhex('4989c6'): ('r14_from_rax', 3),
        bytes.fromhex('4d29de'): ('r14_sub_r11', 3),
        bytes.fromhex('4b8d1c12'): ('rbx_double_r10', 4),
        bytes.fromhex('4939de'): ('cmp_r14_rbx', 3),
        bytes.fromhex('4c29d8'): ('rax_sub_r11', 3),
        bytes.fromhex('4c39d8'): ('cmp_rax_r11', 3),
    }
    plan = {}
    pos = 0
    while pos < len(raw):
        va = GUARD_START + pos
        opcode = raw[pos]
        if opcode in (0x76, 0x73):
            if pos + 2 > len(raw):
                raise ValueError('truncated guard branch')
            dest = va + 2 + struct.unpack_from('<b', raw, pos + 1)[0]
            plan[va] = ('jbe' if opcode == 0x76 else 'jae', 2, dest)
            pos += 2
            continue
        match = next(((name, n) for op, (name, n) in steps.items() if raw[pos:pos+n] == op), None)
        if match is None:
            raise ValueError('unsupported fast guard instruction')
        name, length = match
        plan[va] = (name, length, None)
        pos += length
    for name, _, dest in plan.values():
        if dest is not None and dest not in plan and dest not in GUARD_LEAVES:
            raise ValueError('guard branch leaves verified instruction starts')
    return plan


def guard_lift(plan, a, b, c, bits=64):
    """Static transcription of the guard's unsigned predicates on the proved domain."""
    if GUARD_START not in plan:
        raise ValueError('incomplete guard plan')
    if not 1 <= bits <= 64:
        raise ValueError('invalid word width')
    mask = (1 << bits) - 1
    if any(not isinstance(v, int) or not 0 <= v <= mask for v in (a, b, c)):
        raise ValueError('guard operand outside word')
    if a > b or c == 0:
        raise ValueError('guard proof domain')
    # Subtractions are nonnegative where they are used. The first tests also
    # establish 2*c < b, so the later doubling fits in the selected word.
    if b <= c or b - c <= c:
        return 'fallback'
    if b - a > a and b - a - a >= 2 * c:
        return 'keep'
    if a <= c:
        return 'fallback'
    reduced = a - c
    if b - reduced <= reduced:
        return 'increment'
    return 'fallback'


def guard_spec(a, b, c):
    """Independent inequalities, valid for 0 <= a <= b and c > 0."""
    if not 0 <= a <= b or c <= 0:
        raise ValueError('guard proof domain')
    if 2 * c >= b:
        return 'fallback'
    if 2 * (a + c) <= b:
        return 'keep'
    if 2 * (a - c) >= b:
        return 'increment'
    return 'fallback'


def rounded_product_high(a, b, bits=64):
    """Lift MUL; SHR low by w-1; ADD to the high word."""
    if not 1 <= bits <= 64:
        raise ValueError('invalid word width')
    mask = (1 << bits) - 1
    if any(not isinstance(x, int) or not 0 <= x <= mask for x in (a, b)):
        raise ValueError('product operand outside word')
    product = a * b
    return (product >> bits) + ((product & mask) >> (bits - 1))


def slow_compare(left, right, last_digit):
    """Lift the fallback comparator; limbs are equal-length, least first."""
    if len(left) != len(right) or len(left) > 40:
        raise ValueError('invalid limb count')
    if any(not isinstance(v, int) or not 0 <= v < 1 << 32 for v in (*left, *right)):
        raise ValueError('invalid limb')
    if last_digit is not None and (not isinstance(last_digit, int) or not 0 <= last_digit <= 9):
        raise ValueError('invalid decimal digit')
    relation = 0
    for a, b in zip(reversed(left), reversed(right)):
        if a != b:
            relation = 1 if a > b else -1
            break
    return relation > 0 or (relation == 0 and last_digit is not None and bool(last_digit & 1))


def trim_ascii(data):
    """Lift the wrapper's post-formatter byte loop, assuming stable memory."""
    if not isinstance(data, bytes):
        raise ValueError('formatter output must be bytes')
    end = len(data)
    while end and data[end - 1] == ord('0'):
        end -= 1
    if end and data[end - 1] == ord('.'):
        end -= 1
    result = data[:end]
    return b'0' if result == b'-0' else result


def trim_program(image):
    """Bind the byte and length tests needed to replay the wrapper's trim."""
    instructions = {
        0x13cd2ad: '488b4424184885c0',       # load and test length
        0x13cd2d0: '4801c8',                 # apply the decrement
        0x13cd2d5: '41807c06ff30',           # compare the last byte with '0'
        0x13cd2e1: '48c7c1ffffffff',         # decrement by one
        0x13cd2e8: '41807c06ff00',           # signed test of the same byte
        0x13cd37e: '41807c06ff2e',           # compare last byte with '.'
        0x13cd386: '48ffc8',                 # remove the dot
        0x13cd38e: '4883f802',               # compare length with two
        0x13cd394: '6641813e2d30',           # compare first two bytes with '-0'
        0x13cd3ac: 'c60030',                 # store replacement '0'
    }
    for va, expected in instructions.items():
        raw = bytes.fromhex(expected)
        if image.bytes(va, len(raw), True) != raw:
            raise ValueError('trim instruction changed')
    expected_branches = {
        0x13cd2b5: ('e', 0x13cd354), 0x13cd2d3: ('e', 0x13cd354),
        0x13cd2db: ('ne', 0x13cd379), 0x13cd2ee: ('ns', 0x13cd2d0),
        0x13cd384: ('ne', 0x13cd38e), 0x13cd392: ('ne', 0x13cd35d),
        0x13cd39a: ('ne', 0x13cd35d),
    }
    for va, (condition, dest) in expected_branches.items():
        observed = branch(image, va)
        if observed['condition'] != condition or int(observed['target'], 16) != dest:
            raise ValueError('trim branch changed')
    return expected_branches


def walk_trim(plan, data):
    """Interpret the bound tests for stable input and successful allocation."""
    if not isinstance(data, bytes):
        raise ValueError('formatter output must be bytes')
    if len(plan) != 7:
        raise ValueError('incomplete trim plan')
    length = len(data)
    while length:
        byte = data[length - 1]
        if byte != 0x30:                       # jne to the dot test
            break
        if byte & 0x80:                        # jns follows equality with 0x30
            raise ValueError('unreachable signed-byte branch')
        length -= 1
    if not length:
        return b''
    if data[length - 1] == 0x2e:               # optional final dot
        length -= 1
    if length == 2 and data[:2] == b'-0':      # successful one-byte allocation
        return b'0'
    return data[:length]


def piece_program(image):
    """Check the digit-to-decimal piece predicates and the two literal bytes."""
    instructions = {
        0x1575e24: '4885f6',
        0x1575e2d: '803f30',
        0x1575e36: '4983f903',
        0x1575e46: '6685d2',
        0x1575e55: '4929c1',
        0x1575e93: '4c29c9',
        0x1575edd: '4829f1',
        0x1575ee2: '4c39c9',
        0x1575ee7: '4801c1',
        0x1575efe: '4885c9',
    }
    for va, expected in instructions.items():
        raw = bytes.fromhex(expected)
        if image.bytes(va, len(raw), True) != raw:
            raise ValueError('piece instruction changed')
    destinations = {
        0x1575e27: ('e', 0x1575f3c), 0x1575e30: ('be', 0x1575f55),
        0x1575e3a: ('be', 0x1575f6e), 0x1575e49: ('le', 0x1575ea1),
        0x1575e58: ('be', 0x1575eec), 0x1575e96: ('a', 0x1575f1d),
        0x1575ee0: ('be', 0x1575e9c), 0x1575ee5: ('be', 0x1575e9c),
        0x1575f01: ('e', 0x1575f32),
    }
    for va, (cc, target) in destinations.items():
        row = branch(image, va)
        if row['condition'] != cc or int(row['target'], 16) != target:
            raise ValueError('piece branch changed')
    if image.bytes(0x255d45, 2) != b'0.' or image.bytes(0x252be7, 1) != b'.':
        raise ValueError('piece literal changed')
    return destinations


def build_pieces(plan, digits, exponent, precision, capacity=4):
    """Lift the builder's slice/zero-piece decisions for admissible buffers."""
    if len(plan) != 9:
        raise ValueError('incomplete piece plan')
    if not isinstance(digits, bytes) or not digits:
        raise ValueError('piece digit buffer is empty')
    if digits[0] <= ord('0'):
        raise ValueError('piece first byte is not above zero')
    if capacity < 4:
        raise ValueError('piece capacity below four')
    if not -32768 <= exponent <= 32767 or not 0 <= precision < 1 << 64:
        raise ValueError('piece argument outside machine width')
    n = len(digits)
    if exponent <= 0:
        parts = [('literal', b'0.'), ('zeros', -exponent), ('literal', digits)]
        if precision > n and precision - n > -exponent:
            parts.append(('zeros', precision - n + exponent))
    elif n > exponent:
        parts = [('literal', digits[:exponent]), ('literal', b'.'), ('literal', digits[exponent:])]
        if precision > n - exponent:
            parts.append(('zeros', precision - (n - exponent)))
    else:
        parts = [('literal', digits), ('zeros', exponent - n)]
        if precision:
            parts.extend([('literal', b'.'), ('zeros', precision)])
    return parts


def render_pieces(parts):
    return b''.join(value if kind == 'literal' else b'0' * value for kind, value in parts)


def carry_program(image):
    """Bind both digit-carry predicates and their conditional append tests."""
    instructions = {
        0x157602c: '42807c16ff39', 0x1576037: '42fe041e',
        0x1576074: 'c60631', 0x15760bb: '41ffc0', 0x15760be: '664539c8',
        0x15760c2: '400f9fc6', 0x15760c6: '4839d1', 0x15760c9: '410f92c1',
        0x15760d6: '88040b', 0x15779bc: '41807c0fff39', 0x15779c7: '41fe0437',
        0x15779ee: '41c60731', 0x1577a0d: '8d4301', 0x1577a10: '664439e3',
        0x1577a16: '4d39f0', 0x1577a1b: '43880c07',
    }
    for va, expected in instructions.items():
        raw = bytes.fromhex(expected)
        if image.bytes(va, len(raw), True) != raw:
            raise ValueError('carry instruction changed')
    destinations = {
        0x1576023: ('e', 0x157606f), 0x1576035: ('e', 0x1576020),
        0x1576072: ('e', 0x15760b6), 0x15760d4: ('ne', 0x15760dc),
        0x15779b3: ('e', 0x15779e8), 0x15779c5: ('e', 0x15779b0),
        0x15779ec: ('ne', 0x1577a0d), 0x1577a14: ('l', 0x1577a22),
        0x1577a19: ('ae', 0x1577a22),
    }
    for va, (cc, target) in destinations.items():
        row = branch(image, va)
        if row['condition'] != cc or int(row['target'], 16) != target:
            raise ValueError('carry branch changed')
    return destinations


def signed16(value):
    value &= 0xffff
    return value - 0x10000 if value & 0x8000 else value


def carry_lift(plan, digits, exponent, cutoff, capacity, mode):
    """Static carry relation for nonempty ASCII digits, assuming normal memset."""
    if len(plan) != 9:
        raise ValueError('incomplete carry plan')
    if not isinstance(digits, bytes) or not digits or any(not 48 <= byte <= 57 for byte in digits):
        raise ValueError('invalid carry digits')
    if (not isinstance(exponent, int) or not isinstance(cutoff, int) or
            not (-32768 <= exponent <= 32767 and -32768 <= cutoff <= 32767)):
        raise ValueError('carry exponent outside signed word')
    if not isinstance(capacity, int) or capacity < len(digits) or capacity >= 1 << 64:
        raise ValueError('carry buffer too small')
    if mode not in ('fast', 'slow'):
        raise ValueError('invalid carry path')
    pos = len(digits) - 1
    while pos >= 0 and digits[pos] == ord('9'):
        pos -= 1
    if pos >= 0:
        changed = digits[:pos] + bytes([digits[pos] + 1]) + b'0' * (len(digits) - pos - 1)
        return changed, exponent, False
    next_exp = signed16(exponent + 1)
    predicate = next_exp > cutoff if mode == 'fast' else exponent >= cutoff
    append = predicate and len(digits) < capacity
    result = b'1' + b'0' * (len(digits) - 1 + int(append))
    return result, next_exp, append


def float_parts(bits):
    if not isinstance(bits, int) or not 0 <= bits < 1 << 64:
        raise ValueError('binary64 word outside range')
    sign = bits >> 63
    exponent = (bits >> 52) & 0x7ff
    fraction = bits & ((1 << 52) - 1)
    if exponent == 0x7ff:
        return sign, exponent, fraction, ('infinity' if fraction == 0 else 'nan')
    if exponent == 0:
        return sign, exponent, fraction, ('zero' if fraction == 0 else 'subnormal')
    return sign, exponent, fraction, 'normal'


def factor_for_bits(bits):
    _, exp, frac, kind = float_parts(bits)
    if kind == 'normal':
        significand = (1 << 52) | frac
        if frac == 0:
            return 1 << 54, exp - 1077
        return 2 * significand, exp - 1076
    if kind == 'subnormal':
        return 2 * frac, -1075
    raise ValueError('nonzero finite word required')


def index_operand(mantissa, exponent, parameters):
    if not 0 < mantissa < 1 << 61:
        raise ValueError('fast-path mantissa outside proved domain')
    leading = 64 - mantissa.bit_length()
    intermediate = (parameters['bias'] - (exponent - leading)) * parameters['factor'] + parameters['offset']
    if intermediate < 0:
        raise ValueError('unproved signed index path')
    return exponent - leading, intermediate


def index_for_factor(mantissa, exponent, parameters):
    _, intermediate = index_operand(mantissa, exponent, parameters)
    return (intermediate * parameters['multiplier']) >> parameters['shift']


def formatter_capacity(exponent, parameters):
    """Apply the finite-path signed-exponent guard and capacity calculation."""
    if not -32768 <= exponent <= 32767:
        raise ValueError('formatter exponent outside signed word')
    factor = parameters['negative_factor'] if exponent < 0 else parameters['positive_factor']
    metric = exponent * factor
    if metric >= parameters['metric_limit']:
        raise ValueError('formatter buffer guard')
    return metric, (metric >> parameters['capacity_shift']) + parameters['capacity_base']


def decoded_constants(image):
    """Decode arithmetic immediates used by the manual lift from verified bytes."""
    def operand(va, prefix, fmt):
        raw = image.bytes(va, len(prefix) + struct.calcsize(fmt), True)
        if raw[:len(prefix)] != prefix:
            raise ValueError('arithmetic instruction changed')
        return struct.unpack_from(fmt, raw, len(prefix))[0]

    mantissa_bit = operand(0x15711c7, bytes.fromhex('49b9'), '<Q')
    exponent_mask = operand(0x1571208, bytes.fromhex('49ba'), '<Q')
    normal_exp = operand(0x1571285, bytes.fromhex('4181c0'), '<i')
    subnormal_exp = operand(0x1571299, bytes.fromhex('4181c0'), '<i')
    negative_factor = operand(0x1571351, bytes.fromhex('48c7c0'), '<i')
    positive_factor = operand(0x1571358, b'\xb9', '<I')
    metric_limit = operand(0x1571369, bytes.fromhex('4981fc'), '<I')
    capacity_shift = operand(0x157137e, bytes.fromhex('49c1ec'), '<B')
    capacity_base = operand(0x1571382, bytes.fromhex('4983c4'), '<B')
    bias = operand(0x157618d, b'\xba', '<i')
    offset = operand(0x157619d, bytes.fromhex('81c2'), '<i')
    multiplier = operand(0x15761a6, bytes.fromhex('4869d2'), '<i')
    shift = operand(0x15761b4, bytes.fromhex('48c1fa'), '<B')
    limit = operand(0x15761bd, bytes.fromhex('4183f8'), '<B')
    precision = operand(0x13cd28f, bytes.fromhex('66c7442440'), '<H')
    if image.bytes(0x1576197, 6, True) != bytes.fromhex('8d1492c1e204'):
        raise ValueError('fast-index factor changed')
    if (image.bytes(0x15761d5, 8, True) != bytes.fromhex('4af7240748c1e83f') or
            image.bytes(0x15761e3, 3, True) != bytes.fromhex('4801d0')):
        raise ValueError('rounded high product instructions changed')
    constants = {'mantissa_bit': mantissa_bit, 'exponent_mask': exponent_mask,
                 'normal_exp': normal_exp, 'subnormal_exp': subnormal_exp,
                 'negative_factor': negative_factor, 'positive_factor': positive_factor,
                 'metric_limit': metric_limit, 'capacity_shift': capacity_shift, 'capacity_base': capacity_base,
                 'bias': bias, 'factor': 5 << 4, 'offset': offset,
                 'multiplier': multiplier, 'shift': shift, 'limit': limit, 'precision': precision}
    if (mantissa_bit, exponent_mask, normal_exp, subnormal_exp, bias, offset, shift, limit, precision) != (
            1 << 52, 0x7ff0000000000000, -1076, -1075, -96, 0x153b0, 42, 80, 8):
        raise ValueError('unexpected binary64 or precision immediates')
    if (negative_factor, positive_factor, metric_limit, capacity_shift, capacity_base) != (-12, 5, 0x3ec0, 4, 21):
        raise ValueError('unexpected formatter capacity immediates')
    return constants


def pow10_fraction(exponent):
    return Fraction(10 ** exponent, 1) if exponent >= 0 else Fraction(1, 10 ** (-exponent))


def power_two(exponent):
    return Fraction(1 << exponent, 1) if exponent >= 0 else Fraction(1, 1 << (-exponent))


def read_table(image, limit):
    slot = 0x5770680
    base = image.relative(slot, 0x255db8)
    # cmp index with 0x50 then a 16-byte stride, both validated in full body.
    raw = image.bytes(base, (limit + 1) * 16)
    result = []
    for i in range(limit + 1):
        mantissa, binary_exp, decimal_exp, padding = struct.unpack_from('<QhhI', raw, 16 * i)
        if decimal_exp != -308 + 8 * i or padding != 0:
            raise ValueError('unexpected power table layout')
        exact = pow10_fraction(decimal_exp) / power_two(binary_exp)
        floor, remainder = divmod(exact.numerator, exact.denominator)
        nearest = floor + int(2 * remainder > exact.denominator or
                              (2 * remainder == exact.denominator and floor & 1))
        if mantissa != nearest or not 1 << 63 <= mantissa < 1 << 64:
            raise ValueError('power table is not the qualified rounded power')
        kind = 'exact' if remainder == 0 else ('floor' if mantissa == floor else 'ceil')
        result.append({'index': i, 'va': hex(base + 16 * i), 'mantissa_hex': hex(mantissa),
                       'binary_exp': binary_exp, 'decimal_exp': decimal_exp, 'rounding': kind,
                       'bytes': raw[16*i:16*(i+1)].hex()})
    return result


def fixed8_model(bits):
    """Exact rational model, conditional on nearest-even formatting; not target execution."""
    sign, exp, frac, kind = float_parts(bits)
    if kind == 'nan': return 'NaN'
    if kind == 'infinity': return '-inf' if sign else 'inf'
    if kind == 'zero': return '0'
    mantissa, e = factor_for_bits(bits)
    value = Fraction(mantissa) * power_two(e) * 10 ** 8
    n, rem = divmod(value.numerator, value.denominator)
    n += int(2 * rem > value.denominator or (2 * rem == value.denominator and n & 1))
    if n == 0: return '0'
    whole, fraction = divmod(n, 10 ** 8)
    text = str(whole) + '.' + str(fraction).rjust(8, '0')
    text = text.rstrip('0').rstrip('.')
    return ('-' if sign else '') + text


def write_tsv(path, columns, rows):
    with path.open('w', encoding='utf-8', newline='\n') as stream:
        stream.write('\t'.join(columns) + '\n')
        for row in rows:
            stream.write('\t'.join(str(row[c]) for c in columns) + '\n')


def generate(image, out):
    bodies = {}
    for start, (name, _) in sorted(FUNCTIONS.items()):
        off, raw = image.body(start)
        fde = image.fdes[start]
        bodies[hex(start)] = {'role': name, 'end_exclusive': hex(fde['end']),
                              'file_offset': hex(off), 'fde_va': hex(fde['fde']),
                              'cie_va': hex(fde['cie']), 'bytes': raw.hex(), 'sha256': digest(raw)}
    windows = {name: {'va': hex(va), 'bytes': image.bytes(va, count, True).hex()}
               for name, (va, count) in sorted(WINDOWS.items())}
    plan = guard_program(image.bytes(GUARD_START, GUARD_END - GUARD_START, True))
    trim_plan = trim_program(image)
    pieces_plan = piece_program(image)
    carry_plan = carry_program(image)
    branches = [branch(image, va) for va in BRANCH_SITES]
    for va, (op, n, dest) in sorted(plan.items()):
        if op in ('jbe', 'jae'):
            branches.append(branch(image, va))
    branches.sort(key=lambda r: int(r['site'], 16))
    edges = {x[0]: read_edge(image, x) for x in EDGES}
    template = read_request(image)
    jumps_raw = image.bytes(0x251b18, 20)
    jump_targets = [0x251b18 + struct.unpack_from('<i', jumps_raw, 4*i)[0] for i in range(5)]
    if jump_targets != [0x157125a, 0x15712ab, 0x1571291, 0x1571295, 0x157125e]:
        raise ValueError('classification jump table changed')
    constants = decoded_constants(image)
    table = read_table(image, constants['limit'])
    assertions = {}
    for name, (va, expected) in sorted(ASSERTIONS.items()):
        raw = image.bytes(va, len(expected))
        if raw != expected:
            raise ValueError('assertion literal changed')
        assertions[name] = {'va': hex(va), 'bytes': raw.hex(), 'ascii': raw.decode('ascii')}
    class_literals = image.bytes(0x255d3f, 8)
    if class_literals != b'NaNinf0.':
        raise ValueError('floating class literals changed')
    if constants['multiplier'] <= 0:
        raise ValueError('unexpected index multiplier')
    indices, index_rows = [], []
    metrics, capacities, mantissas, exponents = [], [], [], []
    def observe_factor(mantissa, exponent):
        metric, capacity = formatter_capacity(exponent, constants)
        if mantissa == 0 or mantissa >= 1 << 61 or capacity == 0:
            raise ValueError('finite input reaches a fast-path precondition failure')
        mantissas.append(mantissa)
        exponents.append(exponent)
        metrics.append(metric)
        capacities.append(capacity)
        return index_for_factor(mantissa, exponent, constants)
    # At every normal exponent there are only two leading-bit shapes: an exact
    # power of two and all other fractions. In subnormals the 52 possible most
    # significant set-bit positions cover all positive fraction patterns.
    for exp in range(1, 2047):
        group, operands = [], []
        for frac in (0, 1, (1 << 52) - 1):
            mantissa, e = factor_for_bits((exp << 52) | frac)
            group.append(observe_factor(mantissa, e))
            operands.append(index_operand(mantissa, e, constants))
        if len(set(group)) != 1 or len(set(operands)) != 1:
            raise ValueError('normal significand changed the index')
        indices.extend(group)
        index_rows.append({'class': 'normal', 'encoded_exponent': exp, 'subnormal_msb': '',
                           'fraction_low': '0x0', 'fraction_high': hex((1 << 52) - 1),
                           'exponent_minus_clz': operands[0][0], 'index_operand': operands[0][1],
                           'table_index': group[0]})
    for bit in range(52):
        group, operands = [], []
        for frac in (1 << bit, (1 << (bit + 1)) - 1):
            mantissa, e = factor_for_bits(frac)
            group.append(observe_factor(mantissa, e))
            operands.append(index_operand(mantissa, e, constants))
        if group[0] != group[1] or operands[0] != operands[1]:
            raise ValueError('subnormal leading bit changed the index')
        indices.extend(group)
        index_rows.append({'class': 'subnormal', 'encoded_exponent': 0, 'subnormal_msb': bit,
                           'fraction_low': hex(1 << bit), 'fraction_high': hex((1 << (bit + 1)) - 1),
                           'exponent_minus_clz': operands[0][0], 'index_operand': operands[0][1],
                           'table_index': group[0]})
    if min(indices) != 1 or max(indices) != 80 or set(indices) != set(range(1, 81)):
        raise ValueError('unexpected binary64 fast table index range')
    if (min(mantissas), max(mantissas), min(exponents), max(exponents), max(metrics),
            min(capacities), max(capacities)) != (2, 1 << 54, -1076, 970, 12912, 21, 828):
        raise ValueError('finite formatter precondition range changed')
    proof_counts = Counter()
    width = 7
    for b in range(1, 1 << width):
        for c in range(1, (b - 1) // 2 + 1):
            for a in range(b + 1):
                actual = guard_lift(plan, a, b, c, width)
                expected = guard_spec(a, b, c)
                if actual != expected:
                    raise ValueError('fast guard proof mismatch')
                proof_counts[actual] += 1
    full_small = Counter()
    for b in range(1 << 6):
        for c in range(1, 1 << 6):
            for a in range(b + 1):
                actual = guard_lift(plan, a, b, c, 6)
                if actual != guard_spec(a, b, c):
                    raise ValueError('full six-bit guard proof mismatch')
                full_small[actual] += 1
    sample_triples = [(0, 10, 1), (4, 10, 1), (5, 10, 1), (6, 10, 1), (10, 10, 1),
                      (4, 10, 5), (0, (1 << 64)-1, 1), ((1 << 64)-1, (1 << 64)-1, 1)]
    guard_rows = [{'a': a, 'b': b, 'c': c, 'decision': guard_lift(plan, a, b, c),
                   'spec': guard_spec(a, b, c)} for a, b, c in sample_triples]
    trim_count = 0
    for size in range(7):
        for letters in itertools.product(b'01.-', repeat=size):
            data = bytes(letters)
            if walk_trim(trim_plan, data) != trim_ascii(data):
                raise ValueError('trim replay mismatch')
            trim_count += 1
    trim_samples = [b'', b'0.00000000', b'-0.00000000', b'1.23000000',
                    b'100.00000000', b'1000', b'inf', b'NaN', b'\xff0']
    trim_rows = [{'input_hex': data.hex(), 'result_hex': walk_trim(trim_plan, data).hex()}
                 for data in trim_samples]
    piece_count = 0
    for size in range(1, 5):
        for first in b'19':
            for tail in itertools.product(b'019', repeat=size - 1):
                digits = bytes((first, *tail))
                for exponent in range(-5, 6):
                    for precision in range(9):
                        parts = build_pieces(pieces_plan, digits, exponent, precision)
                        if exponent <= 0:
                            whole, frac = b'0', b'0' * -exponent + digits
                        elif exponent >= len(digits):
                            whole, frac = digits + b'0' * (exponent - len(digits)), b''
                        else:
                            whole, frac = digits[:exponent], digits[exponent:]
                        frac += b'0' * max(0, precision - len(frac))
                        dot = b'.' if exponent <= 0 or exponent < len(digits) or precision else b''
                        expected = whole + dot + frac
                        if not 2 <= len(parts) <= 4 or render_pieces(parts) != expected:
                            raise ValueError('piece layout mismatch')
                        piece_count += 1
    piece_samples = [(b'123', e, p) for e, p in [(-2, 8), (0, 8), (1, 8), (2, 8),
                                                       (3, 8), (5, 8), (5, 0)]]
    piece_rows = []
    for digits, exponent, precision in piece_samples:
        parts = build_pieces(pieces_plan, digits, exponent, precision)
        piece_rows.append({'digits': digits.decode('ascii'), 'exponent': exponent, 'precision': precision,
                           'piece_count': len(parts), 'rendered': render_pieces(parts).decode('ascii')})
    carry_count = carry_disagreements = 0
    for size in range(1, 5):
        for value in range(10 ** size):
            digits = str(value).rjust(size, '0').encode('ascii')
            all_nines = value == 10 ** size - 1
            core = (b'1' + b'0' * (size - 1)) if all_nines else str(value + 1).rjust(size, '0').encode('ascii')
            for exponent in (-32768, -1, 0, 1, 32766, 32767):
                for cutoff in (-32768, 0, 32767):
                    for spare in (0, 1):
                        outputs = []
                        for mode in ('fast', 'slow'):
                            got = carry_lift(carry_plan, digits, exponent, cutoff, size + spare, mode)
                            # Independent signed-order formulation: e+1 > cutoff
                            # iff e >= cutoff, except at the signed upper wrap.
                            append = bool(all_nines and spare and exponent >= cutoff and
                                          not (mode == 'fast' and exponent == 32767))
                            expect = (core + (b'0' if append else b''),
                                      signed16(exponent + 1) if all_nines else exponent, append)
                            if got != expect:
                                raise ValueError('carry arithmetic mismatch')
                            outputs.append(got)
                            carry_count += 1
                        different = outputs[0] != outputs[1]
                        if different != bool(all_nines and exponent == 32767 and spare):
                            raise ValueError('carry path disagreement outside overflow boundary')
                        carry_disagreements += different
    carry_samples = [(b'129', 1, 0, 4), (b'999', 1, 0, 4), (b'999', 1, 0, 3),
                     (b'999', -1, 0, 4), (b'9', 32767, 0, 2)]
    carry_rows = []
    for digits, exponent, cutoff, capacity in carry_samples:
        for mode in ('fast', 'slow'):
            result, next_exp, append = carry_lift(carry_plan, digits, exponent, cutoff, capacity, mode)
            carry_rows.append({'digits': digits.decode('ascii'), 'exponent': exponent, 'cutoff': cutoff,
                               'capacity': capacity, 'path': mode, 'result': result.decode('ascii'),
                               'next_exponent': next_exp, 'appended': int(append)})
    if (carry_count, carry_disagreements) != (799920, 12):
        raise ValueError('carry proof case count changed')
    product_rows = []
    for exp in (1, 1023, 2046):
        bits = exp << 52
        mantissa, binary_exp = factor_for_bits(bits)
        table_index = index_for_factor(mantissa, binary_exp, constants)
        normalized = mantissa << (64 - mantissa.bit_length())
        table_multiplier = int(table[table_index]['mantissa_hex'], 16)
        product = normalized * table_multiplier
        hi, lo = product >> 64, product & ((1 << 64)-1)
        half_up = rounded_product_high(normalized, table_multiplier)
        half_even = hi + int(lo > 1 << 63 or (lo == 1 << 63 and hi & 1))
        product_rows.append({'binary64_bits': f'{bits:016x}', 'table_index': table_index,
                             'normalized_mantissa': hex(normalized), 'table_multiplier': hex(table_multiplier),
                             'high': hex(hi), 'low': hex(lo), 'half_up': hex(half_up), 'half_even': hex(half_even)})
    if product_rows[0]['low'] != hex(1 << 63) or product_rows[0]['half_up'] == product_rows[0]['half_even']:
        raise ValueError('rounded product witness changed')
    sample_words = [0, 1 << 63, 1, (1 << 52)-1, 1 << 52, (0x7fe << 52),
                    0x7fefffffffffffff, 0x7ff0000000000000, 0xfff0000000000000,
                    0x7ff8000000000000, (1014 << 52), (1015 << 52) | (1 << 51)]
    sample_words += [x | (1 << 63) for x in sample_words[1:7]]
    sample_words = list(dict.fromkeys(sample_words))
    vectors = []
    for bits in sample_words:
        sign, exp, frac, kind = float_parts(bits)
        vectors.append({'bits': f'{bits:016x}', 'sign': sign, 'exponent': exp,
                        'fraction': hex(frac), 'class': kind, 'conditional_fixed8_model': fixed8_model(bits)})
    class_counts = {'zero': 2, 'subnormal': 2*((1 << 52)-1),
                    'normal': 2*2046*(1 << 52), 'infinity': 2, 'nan': 2*((1 << 52)-1)}
    if sum(class_counts.values()) != 1 << 64:
        raise ValueError('binary64 class partition mismatch')
    evidence = {
        'target': {'release': 94, 'sha256': TARGET_HASH},
        'scope': 'Static selected x86-64 byte windows; complete FDE bodies are identity controls, not complete function semantics.',
        'functions': bodies, 'windows': windows, 'edges': edges,
        'request_template_hex': template.hex(), 'float_class_jump_table_hex': jumps_raw.hex(),
        'float_class_jump_targets': list(map(hex, jump_targets)), 'binary64_class_counts': class_counts,
        'class_literals': {'va': hex(0x255d3f), 'bytes': class_literals.hex()},
        'assertion_literals': assertions,
        'finite_factor_min': min(mantissas), 'finite_factor_max': max(mantissas),
        'finite_exponent_min': min(exponents), 'finite_exponent_max': max(exponents),
        'finite_buffer_metric_max': max(metrics), 'finite_buffer_capacity_min': min(capacities),
        'finite_buffer_capacity_max': max(capacities),
        'finite_precondition_scope': 'Algebraic partition of nonzero finite binary64; actual callback and uncorrupted memory assumed.',
        'power_table_slot': hex(0x5770680), 'power_table_base': hex(0x255db8),
        'power_table_rounding_counts': dict(sorted(Counter(r['rounding'] for r in table).items())),
        'decoded_instruction_constants': constants, 'fast_index_min': min(indices),
        'fast_index_max': max(indices), 'fast_index_distinct': len(set(indices)),
        'product_witnesses': product_rows,
        'index_representatives': len(indices), 'seven_bit_guard_cases': sum(proof_counts.values()),
        'index_partitions': len(index_rows),
        'seven_bit_guard_outcomes': dict(sorted(proof_counts.items())),
        'six_bit_guard_cases': sum(full_small.values()),
        'six_bit_guard_outcomes': dict(sorted(full_small.items())),
        'trim_replay_cases': trim_count,
        'piece_layout_cases': piece_count,
        'carry_cases': carry_count, 'carry_path_disagreements': carry_disagreements,
        'carry_scope': 'Nonempty ASCII digit buffers, valid capacity and normal memset resolution. Slow path assumes AL=0.',
        'guard_proof_scope': '0 <= a <= b < 2^w and 0 < c < 2^w. The link to the fast generator operands is not proved.',
        'model_limit': 'Fixed-eight vector text is an exact rational nearest-even model, not target execution or a complete proof of the digit generators.',
    }
    out.mkdir(parents=True, exist_ok=True)
    (out / 'evidence.json').write_text(json.dumps(evidence, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    write_tsv(out / 'branches.tsv', ('site', 'bytes', 'condition', 'target'), branches)
    write_tsv(out / 'power-table.tsv', ('index', 'va', 'mantissa_hex', 'binary_exp', 'decimal_exp', 'rounding', 'bytes'), table)
    write_tsv(out / 'index-partitions.tsv', ('class', 'encoded_exponent', 'subnormal_msb', 'fraction_low',
              'fraction_high', 'exponent_minus_clz', 'index_operand', 'table_index'), index_rows)
    write_tsv(out / 'guard-cases.tsv', ('a', 'b', 'c', 'decision', 'spec'), guard_rows)
    write_tsv(out / 'trim-cases.tsv', ('input_hex', 'result_hex'), trim_rows)
    write_tsv(out / 'piece-cases.tsv', ('digits', 'exponent', 'precision', 'piece_count', 'rendered'), piece_rows)
    write_tsv(out / 'carry-cases.tsv', ('digits', 'exponent', 'cutoff', 'capacity', 'path',
              'result', 'next_exponent', 'appended'), carry_rows)
    write_tsv(out / 'product-cases.tsv', ('binary64_bits', 'table_index', 'normalized_mantissa',
              'table_multiplier', 'high', 'low', 'half_up', 'half_even'), product_rows)
    write_tsv(out / 'float-model.tsv', ('bits', 'sign', 'exponent', 'fraction', 'class', 'conditional_fixed8_model'), vectors)
    return {'functions': len(bodies), 'branches': len(branches), 'power_entries': len(table),
            'index_representatives': len(indices), 'trim_cases': trim_count,
            'index_partitions': len(index_rows),
            'piece_cases': piece_count,
            'carry_cases': carry_count, 'carry_disagreements': carry_disagreements,
            'guard_cases': sum(proof_counts.values()) + sum(full_small.values())}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    data = TARGET.read_bytes()
    check_target(data)  # authenticate before decoding any target bytes
    print(json.dumps(generate(Image(data, authenticate=False), args.out), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, struct.error) as error:
        print('fixed8_float_rounding94:', error, file=sys.stderr)
        raise SystemExit(1)
