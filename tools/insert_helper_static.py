#!/usr/bin/env python3
"""Pin the RE-015 insert helper 0x4741960 in node 115.

Question (carried by the payload-constructor packet
RE-015-node115-payload-constructor / PR #2736): the insert helper
0x4741960 (1,988 bytes, two further call sites inside its own
body) -- for each Vec C element, how does it mutate the head
struct S built by the payload ctor 0x4741180?  Which fields of S
does it read and write, and how do the element's first word, its
+0x38 low byte and the mapped nested block decide the outcome?

The packet pins: (1) the helper's whole-.text direct-call census
is exactly three sites: the payload ctor's call at 0x47414e0 and
the two self-calls at 0x4741ccf (map-hit recursion) and 0x4741e86
(empty-map tail recursion); the ctor passes rdi = &S,
rsi = the element's +0x10 word (key byte pointer),
rdx = the element's +0x18 word (key byte length),
rcx = a pointer to the 0x18-byte mapped nested block
{capacity words +0x00, buffer +0x08, length +0x10},
r8b = the element's +0x38 low byte, r9 = the element's first
word; (2) phase 1 splits the key on the first "::" (needle bytes
at 0x7df837, length 2): a searcher state is built at [rsp+0x90]
through slot 0x64dfcb8 -> 0x167ff90 from (key ptr, key len,
needle ptr, 2) and stepped once by 0x4740170 (boundary); the
result tag dword at [rsp+0x100] is 1 with the match index at
[rsp+0x108], or not-1 for no match; slicing at the split is
guarded by the compiled-in char-boundary checks (continuation
bytes 0x80..0xbf rejected) whose failure path is the noreturn
slice-error call through slot 0x64df670 -> 0x16806c0;
(3) phase 2 dispatches on S+0x38: nonzero means the map embedded
at S+0x20 is populated, so the head segment is FNV-1a hashed
(basis 0xcbf29ce484222325, prime 0x100000001b3, a final 0xff
byte folded in; an empty head uses the constant
0xaf64724c8602eb6e, which is exactly that hash of [0xff]) and the
RawTable at S+0x20 (control pointer) / S+0x28 (bucket mask) is
probed in 16-byte control groups with the hash's top 7 bits
(hash >> 0x39) as the control-byte pattern; a candidate bucket
(0x58-byte records located before the control bytes) is a hit
only when the key length at bucket+0x10 equals the head length
and bcmp (slot 0x64df9f8, dynsym 11) of the stored key pointer at
bucket+0x08 against the head returns 0; an empty control byte
(0xff) ends the probe as a miss; (4) on a hit the helper recurses
into the bucket's stored child S at bucket+0x18 with the tail
(tail pointer, tail length), a verbatim 0x18-byte copy of the
mapped block, the flag byte and the first word, and returns;
(5) on a miss (or when S+0x38 is 0, which skips the probe) with a
nonempty tail, it first builds a child S on the stack --
+0x00 = S+0x00, +0x08 = S+0x18, +0x10 = a fresh allocated copy of
S's mapped array (S+0x18 words from the S+0x10 buffer; the word 8
stands in when S+0x18 is 0), +0x18 = S+0x18, +0x20..0x40 = the
static empty-map block at 0x6494c58 (relocated words
{0x450150, 0, 0, 0}) -- recurses on the tail into that child, and
then uses the (possibly mutated) child as the value for the head
segment; (6) with an empty tail it builds the leaf value
directly: a fresh 0x40-byte S whose +0x00 is the element's first
word and whose +0x08..0x20 is the mapped block -- after, only
when the +0x38 flag byte is nonzero, first appending S's mapped
array (S+0x18 words from S+0x10) into the mapped block's buffer
(growing it through 0x474e640, boundary, when the block's
capacity word minus its length is too small) and storing the
increased length back at block+0x10; (7) the head segment is
copied into a fresh allocation (length 0 keeps the sentinel
pointer 1) and the map insert 0x474b620 (boundary) is called
with the map at S+0x20, a key descriptor {len, ptr, len} and the
value block; the helper's own body stores nothing to
S+0x00..0x20 -- its only writes to S run through that insert
call (the S+0x20..0x40 map words) and through recursion into
child S values stored in the map's buckets; (8) if the insert
result dword is 6 the helper returns at once; otherwise the
result carries a displaced record whose array (count at +0x08,
buffer at +0x10) is freed through the dealloc slot and whose
sub-record at +0x20 is dropped by 0x4742960 (boundary) before
returning.  Static evidence only; no captured code is executed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import decode_export, require

SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'

OWNERS = {
    'insert_helper': (
        0x4741960, 0x4742124,
        '19ab10dcba77aea7e558737bddc7bace985b7d49bc254b69d731e23bb805136d'),
}
BOUNDARIES = {
    'payload_ctor': (
        0x4741180, 0x4741869,
        '8b5d5c27780fad807407377de2a30320bd15ad6a8902c960b9d0f5ccb4955e6a'),
    'searcher_next': (
        0x4740170, 0x474031f,
        '61665365392f79cf0ccb5af674672a22b9e9777b3bcc4bad44e51ee6d033d9d1'),
    'map_insert': (
        0x474b620, 0x474ba5d,
        'f6d9ca4362a1a81c592c33e5e75d6522a738b71a143b4c6b9bcb0b1739cd6658'),
    'record_drop': (
        0x4742960, 0x4742a93,
        '1aae44edc7f846da821541c9455706506403ae72981926a7927dd0aa0a3069e1'),
    'vec_grow': (
        0x474e640, 0x474e6bf,
        '43935a1cdae8c5854d4a239f0992801b4808673b0bb5ff24da951160a868e8bf'),
    'cleanup_drop': (
        0x4740a30, 0x4740a5d,
        'b9665ed96a0cac53d797b8f522125f800644ca4b34fdb8928466bee2d5811c09'),
}

HELPER_PINS = {
    'save_first_word': (0x4741971, b'L\x89L$8'),
    'result_tag_cmp': (0x47419b7,
                       b'\x83\xbc$\x00\x01\x00\x00\x01'),
    'keylen_save': (0x47419bf, b'H\x89l$\x18'),
    's38_test_a': (0x4741a13, b'I\x83y8\x00'),
    'fnv_basis': (0x4741a53,
                  b'H\xbb\x25\x23\x22\x84\xe4\x9c\xf2\xcb'),
    'fnv_prime': (0x4741a5d,
                  b'H\xb8\xb3\x01\x00\x00\x00\x01\x00\x00'),
    'empty_hash_const': (0x4741b14,
                         b'H\xbbn\xeb\x02\x86Lrd\xaf'),
    'h2_shift': (0x4741b21, b'H\xc1\xe89'),
    'ctrl_load': (0x4741b25, b'I\x8bI '),
    'mask_load': (0x4741b29, b'I\x8bQ('),
    'bcmp_ptr_load': (0x4741b45,
                      b'L\x8b5\xac\xde\xd9\x01'),
    'flag_test': (0x4741cd9, b'\x80\x7c\x24\x0c\x00'),
    'child_block_load': (0x4741e29,
                         b'\x0f\x10\x05(\x2e\xd5\x01'),
    'block_len_store': (0x4741f38, b'I\x89v\x10'),
    'value_word0_load': (0x4741f4e, b'H\x8bD$8'),
    'key_desc_store': (0x4741fb3,
                       b'L\x89\xbc$H\x01\x00\x00'),
    'insert_result_cmp': (0x474202a,
                          b'\x83\xbc$\x00\x01\x00\x00\x06'),
}
HELPER_DIRECT_CALLS = {
    'searcher_next_call': (0x47419b2, 0x4740170),
    'self_call_hit': (0x4741ccf, 0x4741960),
    'self_call_tail': (0x4741e86, 0x4741960),
    'insert_call': (0x4742025, 0x474b620),
    'drop_call': (0x474205d, 0x4742960),
    'grow_call': (0x4742085, 0x474e640),
}
HELPER_SLOT_CALLS = {
    'searcher_build_call': (0x474199c, 0x64dfcb8),
    'alloc_call_copy': (0x4741c63, 0x64df480),
    'memcpy_call_copy': (0x4741c7e, 0x64df508),
    'alloc_err_call': (0x4741ee6, 0x64df498),
    'alloc_call_key': (0x4741f8a, 0x64df480),
    'memcpy_call_key': (0x4741fa5, 0x64df508),
    'dealloc_call': (0x474204f, 0x64df4a0),
    'slice_error_call': (0x4741df8, 0x64df670),
    'panic_call': (0x47420ad, 0x64df520),
}
HELPER_LEAS = {
    'needle': (0x4741987, 0x7df837),
    'slice_static_a': (0x47419dc, 0x6494ca8),
    'slice_static_b': (0x4741de6, 0x6494cd8),
    'panic_static': (0x47420a6, 0x6494cc0),
}
CTOR_PINS = {
    'insert_call_site_rsi': (0x47414d2, b'L\x89\xf6'),
    'insert_call_site_r9': (0x47414dd, b'M\x89\xe9'),
}
CTOR_DIRECT_CALLS = {
    'insert_call': (0x47414e0, 0x4741960),
}

SLOT_BINDINGS_WANTED = {
    'searcher_build': 0x64dfcb8, 'slice_error': 0x64df670,
    'panic_fn': 0x64df520, 'bcmp': 0x64df9f8,
    'alloc': 0x64df480, 'memcpy': 0x64df508,
    'dealloc': 0x64df4a0, 'alloc_error': 0x64df498,
    'slice_static_a': 0x6494ca8, 'panic_static': 0x6494cc0,
    'slice_static_b': 0x6494cd8, 'static_block': 0x6494c58,
}
EXPECTED_BINDINGS = {
    'searcher_build': ('rela', '0x167ff90'),
    'slice_error': ('rela', '0x16806c0'),
    'panic_fn': ('rela', '0x1681da0'),
    'bcmp': ('glob', 'bcmp'),
    'alloc': ('rela', '0x6355830'),
    'memcpy': ('glob', 'memcpy'),
    'dealloc': ('rela', '0x635de30'),
    'alloc_error': ('rela', '0x141e264'),
    'slice_static_a': ('rela', '0x44dc38'),
    'panic_static': ('rela', '0x44dc38'),
    'slice_static_b': ('rela', '0x44dc38'),
    'static_block': ('rela', '0x450150'),
}


def read(data, va, n):
    for s in sections(data):
        if s['type'] != 8 and s['address'] <= va < s['address'] + s['size']:
            off = s['offset'] + va - s['address']
            if off + n > s['offset'] + s['size']:
                break
            return off, data[off:off + n]
    raise ValueError(f'unmapped {va:#x}')


def _pin(data, site, expected, label):
    if read(data, site, len(expected))[1] != expected:
        raise ValueError(f'{label} changed')


def _pins(data, table, role):
    for label, (site, expected) in table.items():
        _pin(data, site, expected, f'{role} {label}')


def _slot_call(data, site, slot, label):
    raw = read(data, site, 6)[1]
    require(raw[:2] in (b'\xff\x15', b'\xff%'),
            f'{label} is not a slot call')
    disp = struct.unpack('<i', raw[2:])[0]
    require(site + 6 + disp == slot, f'{label} slot changed')


def _direct_call(data, site, target, label):
    raw = read(data, site, 5)[1]
    require(raw[:1] == b'\xe8', f'{label} is not a direct call')
    rel = struct.unpack('<i', raw[1:])[0]
    require(site + 5 + rel == target, f'{label} target changed')


def _lea(data, site, target, label):
    raw = read(data, site, 7)[1]
    disp = struct.unpack('<i', raw[3:])[0]
    require(site + 7 + disp == target, f'{label} target changed')


def _relocations(data):
    s = next(s for s in sections(data) if s['name'] == '.rela.dyn')
    out = {}
    for off in range(s['offset'], s['offset'] + s['size'], 24):
        offset, info, addend = struct.unpack_from('<QQq', data, off)
        out[offset] = {'type': info & 0xffffffff,
                       'symbol': info >> 32, 'addend': addend}
    return out


def _dynsym_names(data):
    secs = sections(data)
    sym = next(s for s in secs if s['name'] == '.dynsym')
    strs = next(s for s in secs if s['name'] == '.dynstr')
    names = {}
    for i, off in enumerate(range(sym['offset'],
                                  sym['offset'] + sym['size'], 24)):
        noff = struct.unpack_from('<I', data, off)[0]
        end = data.index(b'\x00', strs['offset'] + noff)
        names[i] = data[strs['offset'] + noff:end].decode()
    return names


def slot_bindings(data):
    rel = _relocations(data)
    names = _dynsym_names(data)
    out = {}
    for name, slot in SLOT_BINDINGS_WANTED.items():
        entry = rel[slot]
        kind, want = EXPECTED_BINDINGS[name]
        if kind == 'rela':
            got = hex(entry['addend'])
            out[name] = {'slot': hex(slot), 'type': entry['type'],
                         'addend': got}
            if got != want:
                raise ValueError(f'slot binding {name} changed')
        else:
            got = names[entry['symbol']]
            out[name] = {'slot': hex(slot), 'type': entry['type'],
                         'symbol': entry['symbol'], 'name': got}
            if got != want:
                raise ValueError(f'slot binding {name} changed')
    return out


def direct_call_census(data, targets):
    secs = sections(data)
    text = next(s for s in secs if s['name'] == '.text')
    raw = data[text['offset']:text['offset'] + text['size']]
    base = text['address']
    found = {t: [] for t in targets}
    for i in range(len(raw) - 5):
        if raw[i] == 0xe8:
            disp = struct.unpack_from('<i', raw, i + 1)[0]
            tgt = base + i + 5 + disp
            if tgt in found:
                found[tgt].append(base + i)
    return {hex(k): [hex(x) for x in v] for k, v in found.items()}


def static_block(data):
    rel = _relocations(data)
    words = []
    for i in range(4):
        va = 0x6494c58 + 8 * i
        raw = struct.unpack('<Q', read(data, va, 8)[1])[0]
        if va in rel and rel[va]['type'] == 8:
            raw = rel[va]['addend']
        words.append(hex(raw))
    return {'address': '0x6494c58', 'words_after_relocation': words}


def fnv1a_ff_empty():
    h = (0xcbf29ce484222325 ^ 0xff) * 0x100000001b3 % (1 << 64)
    return hex(h)


def analyze(data):
    if hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('wrong node115 capture')
    _pins(data, HELPER_PINS, 'insert_helper')
    for label, (site, target) in HELPER_DIRECT_CALLS.items():
        _direct_call(data, site, target, f'insert_helper {label}')
    for label, (site, slot) in HELPER_SLOT_CALLS.items():
        _slot_call(data, site, slot, f'insert_helper {label}')
    for label, (site, target) in HELPER_LEAS.items():
        _lea(data, site, target, f'insert_helper {label}')
    _pins(data, CTOR_PINS, 'payload_ctor')
    for label, (site, target) in CTOR_DIRECT_CALLS.items():
        _direct_call(data, site, target, f'payload_ctor {label}')
    if read(data, 0x7df837, 2)[1] != b'::':
        raise ValueError('needle bytes changed')
    bindings = slot_bindings(data)
    census = direct_call_census(data, (0x4741960,))
    if census['0x4741960'] != ['0x47414e0', '0x4741ccf', '0x4741e86']:
        raise ValueError('insert helper caller census changed')
    block = static_block(data)
    if block['words_after_relocation'] != ['0x450150', '0x0', '0x0', '0x0']:
        raise ValueError('static block changed')
    if fnv1a_ff_empty() != '0xaf64724c8602eb6e':
        raise ValueError('empty-head hash constant mismatch')
    _, fs, _ = fde_extents(data)
    fdes = {(f['start'], f['end']): f for f in fs}

    def frame_records(a, b, sha, role):
        if (a, b) not in fdes:
            raise ValueError(f'{role} scope FDE changed')
        offset, raw = read(data, a, b - a)
        digest = hashlib.sha256(raw).hexdigest()
        if digest != sha:
            raise ValueError(f'{role} body changed')
        records = {}
        for kind in ['fde', 'cie']:
            va = fdes[(a, b)][kind]
            n = struct.unpack('<I', read(data, va, 4)[1])[0] + 4
            records[kind] = {'va': hex(va),
                             'bytes_hex': read(data, va, n)[1].hex()}
        return {'role': role, 'start': hex(a), 'end': hex(b),
                'file_offset': hex(offset), 'bytes': b - a,
                'sha256': digest, 'frames': records}

    owners = [frame_records(a, b, sha, role)
              for role, (a, b, sha) in OWNERS.items()]
    boundaries = [frame_records(a, b, sha, role)
                  for role, (a, b, sha) in BOUNDARIES.items()]
    return {
        'target_sha256': SHA,
        'owners': owners,
        'boundaries': boundaries,
        'slot_bindings': bindings,
        'direct_call_census': census,
        'static_block': block,
        'needle': {'address': '0x7df837', 'bytes': '::', 'length': 2},
        'empty_head_hash': fnv1a_ff_empty(),
        'call_args': {
            'rdi': '&S (head struct built by the payload ctor)',
            'rsi': "element +0x10 word: key byte pointer",
            'rdx': "element +0x18 word: key byte length",
            'rcx': 'pointer to mapped nested block '
                   '{cap words +0x00, buffer +0x08, len +0x10}',
            'r8b': "element +0x38 low byte (append flag)",
            'r9': "element first word (stored as a leaf child's S+0x00)",
        },
        's_fields_read': [
            {'offset': '0x00', 'role': 'copied into a tail-built child S+0x00'},
            {'offset': '0x10', 'role': 'mapped array buffer: copied into a '
                                       'tail-built child and appended into '
                                       'the mapped block on the leaf path'},
            {'offset': '0x18', 'role': 'mapped array word count: child S+0x08 '
                                       'and +0x18, copy length, append count'},
            {'offset': '0x20', 'role': 'map control pointer (probe) and the '
                                       'map passed to the insert call'},
            {'offset': '0x28', 'role': 'map bucket mask (probe)'},
            {'offset': '0x38', 'role': 'map-populated dispatch word: nonzero '
                                       'probes the map, zero skips the probe'},
        ],
        's_fields_written': [
            'no direct store to S appears in the helper body',
            'via the map insert call 0x474b620 on &S+0x20 (map words at '
            'S+0x20..0x40, including the bucket allocation)',
            'via recursion into child S values stored in map buckets '
            '(bucket+0x18), not into the 0x40 bytes of S itself',
        ],
        'phases': [
            'split: searcher for "::" over (key ptr, key len); tag 1 -> '
            'head = key[..idx], tail = key[idx+2..]; no match -> head = '
            'whole key, tail empty; char-boundary guards fail through the '
            'slice-error slot 0x64df670',
            'probe (only if S+0x38 != 0): FNV-1a head hash with 0xff '
            'terminator, top-7-bit control pattern, 16-byte control-group '
            'probe of the S+0x20/S+0x28 table; hit needs bucket+0x10 == '
            'head len and bcmp(bucket+0x08, head, len) == 0; an empty '
            'control byte (0xff) is a miss',
            'hit: recurse into bucket+0x18 child S with (tail ptr, tail '
            'len, copy of mapped block, flag byte, first word); return',
            'miss with tail: build child S {S+0x00, S+0x18, copied mapped '
            'array, S+0x18, static empty-map block}, recurse on the tail, '
            'then insert the head segment with that child as value',
            'leaf (empty tail): if flag byte != 0, append S mapped array '
            'into the mapped block (grow via 0x474e640 if needed, store '
            'new len at block+0x10); value = fresh S {first word, mapped '
            'block, static empty-map block}',
            'insert: copy head bytes into a fresh allocation (len 0 -> '
            'pointer 1), call 0x474b620(&S+0x20, key {len, ptr, len}, '
            'value); result dword 6 -> return; otherwise free the '
            'displaced array via the dealloc slot and drop the displaced '
            'sub-record at result+0x20 via 0x4742960',
        ],
        'verdict': (
            'The insert helper treats S as the root of a "::"-keyed '
            'tree: it splits the element key on the first "::", '
            'probes the hash map embedded at S+0x20 (only when '
            'S+0x38 is nonzero) with an FNV-1a/0xff-terminated head '
            'hash, recurses into the matching bucket\'s child S '
            'with the tail, and otherwise inserts the head segment '
            'with a fresh child S as value -- built by recursing on '
            'the tail when S\'s map was empty, or, at a leaf, from '
            'the element\'s first word and the mapped nested block, '
            'appending S\'s own mapped array into that block first '
            'when the element\'s +0x38 low byte is nonzero. The '
            'helper body stores nothing to S directly; S changes '
            'only through the map insert at S+0x20 and through '
            'recursion into stored children.'),
    }


def _objdump(path, start, end):
    return subprocess.check_output(
        ['objdump', '-d', '-M', 'intel', '--insn-width=16',
         f'--start-address={start:#x}', f'--stop-address={end:#x}',
         str(path)]).decode('utf-8')


WINDOWS = [
    ('insert_helper_objdump.txt', 0x4741960, 0x4742124,
     [s for s, _ in HELPER_PINS.values()]
     + [s for s, _ in HELPER_DIRECT_CALLS.values()]
     + [s for s, _ in HELPER_SLOT_CALLS.values()]
     + [s for s, _ in HELPER_LEAS.values()]),
    ('payload_ctor_callsite_objdump.txt', 0x4741440, 0x47414e5,
     [s for s, _ in CTOR_PINS.values()]
     + [s for s, _ in CTOR_DIRECT_CALLS.values()]),
]


def generate(binary, output):
    data = Path(binary).read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('wrong node115 capture')
    report = analyze(data)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
            dir=output, suffix='.elf', delete=False) as handle:
        handle.write(data)
        snapshot = Path(handle.name)
    try:
        native = subprocess.check_output(
            ['readelf', '--debug-dump=frames-interp',
             str(snapshot)]).decode('utf-8')
        lines = []
        for role, (a, b, _) in list(OWNERS.items()) + \
                list(BOUNDARIES.items()):
            rows = [l for l in native.splitlines()
                    if f'pc={a:016x}..{b:016x}' in l]
            if len(rows) != 1:
                raise ValueError('native FDE disagreement')
            lines.extend(rows)
        for name, start, end, sites in WINDOWS:
            asm = _objdump(snapshot, start, end)
            ins = decode_export(asm, start, end,
                                read(data, start, end - start)[1])
            if not set(sites) <= set(ins):
                raise ValueError(f'{name} evidence site not a '
                                 'native instruction start')
            (output / name).write_bytes(
                asm.replace(str(snapshot),
                            '<authenticated-node115>').encode('utf-8'))
    finally:
        snapshot.unlink()
    (output / 'frames.txt').write_bytes(
        ('\n'.join(lines) + '\n').encode('utf-8'))
    (output / 'records.json').write_bytes(
        (json.dumps(report, indent=2) + '\n').encode('utf-8'))
    return report


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, default=TARGET)
    p.add_argument('--output', type=Path,
                   default=ROOT / 'work/insert-helper115')
    args = p.parse_args()
    report = generate(args.binary, args.output)
    print(json.dumps({'functions': len(report['owners']),
                      'bytes': sum(x['bytes'] for x in report['owners']),
                      'executed': False}))
