#!/usr/bin/env python3
"""Pin the RE-015 payload constructor 0x4741180 in node 115.

Question (one of the open edges carried by the entry-tag-consumers
packet RE-015-node115-entry-tag-consumers / PR #2696): the payload
constructor body 0x4741180 -- what does it build, field by field,
from which inputs; where does the constructed payload go (who
stores/reads the pointer afterwards)?

The packet pins: (1) the ctor's sole direct call site is inside
its only caller, the refcount wrap ctor 0x4742470 (site 0x474248e),
which passes rdi = a 0x68-byte stack temp in its own frame,
rsi = the 0x50-byte source struct pointer it received unchanged,
rdx = 1, rcx = 0x6494c78 (a .data.rel.ro table pointer); (2) the
source struct is three Vec headers plus a head word: +0x00 scalar,
Vec A {cap +0x08, ptr +0x10, len +0x18} of 0x18-byte elements,
Vec B {cap +0x20, ptr +0x28, len +0x30} of 0x40-byte elements,
Vec C {cap +0x38, ptr +0x40, len +0x48} of 0x40-byte elements;
(3) phase 1 builds a lookup collection at [rsp+0x1b0] from a
Vec B iterator via helper 0x4747a70 (boundary); (4) phase 2 maps
Vec A through helper 0x4749d80 (boundary) into a caller-allocated
len*8 buffer and assembles the 0x40-byte head struct S:
S+0x00 = source +0x00, S+0x08 = len_A, S+0x10 = the mapped buffer,
S+0x18 = the helper-updated slot word (initialised 0), and
S+0x20..0x40 = the 32-byte static block at 0x6494c58, whose only
nonzero relocated word is the table pointer 0x450150;
(5) phase 3 sorts Vec C's buffer in place when len_C >= 2 (direct
small-sort 0x474ee70 below 21 elements, the function behind slot
0x64eaf68 = 0x47483e0 at 21 or more), then walks Vec C at 0x40
stride: an element whose first word is 6 TERMINATES the walk;
every other element is copied verbatim to a stack record, its
nested Vec {cap +0x20, ptr +0x28, len +0x30} of 0x18-byte
elements is mapped through the twin-shaped helper 0x4749f70
(boundary) into a len*8 buffer, and the insert helper 0x4741960
(boundary) merges it into S with the element's +0x10/+0x18 words,
its +0x38 low byte and its first word as arguments; the copied
record's inner buffers are freed per element through the dealloc
slot; (6) post-loop the Vec C header snapshot is dropped via
0x4753770 (boundary), the collection buffer is freed if its
capacity word is nonzero, helper 0x47534b0 (boundary) builds a
0x18-byte tail T from a Vec B descriptor {ptr, ptr, cap, end},
and the 0x68-byte payload is written to the out pointer:
out+0x00..0x40 = S, out+0x40..0x58 = T, out+0x58 = the rdx
argument verbatim, out+0x60 = the rcx argument verbatim;
(7) the source is consumed on the success path: every Vec A
element's inner Vec buffer is freed, then Vec A's own buffer is
freed if cap_A is nonzero; no free of the Vec B or Vec C buffers
appears in the body after their uses (Vec C's header snapshot
drop and Vec B's descriptor consumption are the recorded
disposals); (8) storage after the ctor is the wrap ctor only:
it prefixes refcount words {1, 1}, allocates 0x78 bytes, copies
header + payload into the heap object (payload at heap+0x10),
allocates a 0x18-byte node {header pair, payload pointer at
+0x10} and returns the node pointer.  Static evidence only;
no captured code is executed.
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
    'payload_ctor': (
        0x4741180, 0x4741869,
        '8b5d5c27780fad807407377de2a30320bd15ad6a8902c960b9d0f5ccb4955e6a'),
    'arc_wrap_ctor': (
        0x4742470, 0x4742595,
        'fe91e95a97ff89e4df3823200e2973aeb23dd05dabf5737d48ce10a74798ef9c'),
}
BOUNDARIES = {
    'collect_from_vec_b': (
        0x4747a70, 0x4747b8c,
        '94e2a7361dea19622e98cd267c3079c6f5ef77aaf99c24a6af8c1692a8a1a734'),
    'map_vec_a': (
        0x4749d80, 0x4749f6e,
        '013503c907293d54e1826ea124ba61578b152e6b9ae6abb2655e19a8b0d714e1'),
    'map_nested_vec': (
        0x4749f70, 0x474a15e,
        'ea0826a03cce2cdafa2284acb2eb19257ce802723a71087246eb6ee88717597c'),
    'insert_into_head': (
        0x4741960, 0x4742124,
        '19ab10dcba77aea7e558737bddc7bace985b7d49bc254b69d731e23bb805136d'),
    'small_sort': (
        0x474ee70, 0x474ef61,
        'c10705ca00e108908e051353b7469c2317002ed94d09b823f0443c3ed1a65fa1'),
    'large_sort': (
        0x47483e0, 0x47484fb,
        '12c45f1ed09a4c81a65e8e496ab9e94a3b96ce60bde0aef67e60bd5dc02cb1f1'),
    'drop_vec_c_snapshot': (
        0x4753770, 0x4753864,
        '95719dc118a1c123f82dd721aeba0f0488383549aa9e0cedeb045c851c246e98'),
    'build_vec_b_tail': (
        0x47534b0, 0x47536bf,
        '6b363d437328781c2760591acf6c594fc661ac13daa401668d858bf1892117b6'),
    'collection_drop': (
        0x4742810, 0x474284b,
        'c3e2db799db8445cc9b10c4d52f66d1d74d14c401d723c1031396be43445ff01'),
    'registrar': (
        0x474f6a0, 0x474f7ff,
        'a26fb8c2033f2f6c6242755b86e5377a13bce19b1459d1761ddf9b56c8132c1e'),
}

CTOR_PINS = {
    'len_b_load': (0x47411a7, b'H\x8bn0'),
    'len_c_load': (0x47411bf, b'H\x8bFH'),
    'const_block_load': (0x47412f0, b'\x0f\x10\x05a9\xd5\x01'),
    'len_c_gate': (0x4741328, b'I\x83\xfe\x02'),
    'terminator_cmp': (0x47413b6, b'I\x83\xfd\x06'),
    'out_tail_load': (0x4741663,
                      b'\x0f\x10\x84$\x00\x02\x00\x00'),
    'out_rdx_store': (0x474167b,
                      b'H\x8b\x84$\x88\x00\x00\x00'),
    'out_rcx_store': (0x4741687,
                      b'H\x8b\x84$\x90\x00\x00\x00'),
}
CTOR_DIRECT_CALLS = {
    'collect_call': (0x4741216, 0x4747a70),
    'map_a_call': (0x47412c9, 0x4749d80),
    'map_nested_call': (0x4741495, 0x4749f70),
    'insert_call': (0x47414e0, 0x4741960),
    'drop_c_call': (0x474156f, 0x4753770),
    'build_b_call': (0x4741633, 0x47534b0),
    'small_sort_call': (0x4741715, 0x474ee70),
}
CTOR_SLOT_CALLS = {
    'alloc_call_a': (0x474125e, 0x64df480),
    'alloc_err_call_a': (0x4741271, 0x64df498),
    'large_sort_call': (0x4741746, 0x64eaf68),
}
WRAP_PINS = {
    'refcount_store': (0x4742493,
                       b'H\xc7\x04$\x01\x00\x00\x00'),
    'alloc78': (0x47424a4, b'\xbfx\x00\x00\x00'),
    'payload_ptr_off': (0x47424fe, b'H\x83\xc0\x10'),
    'alloc18': (0x4742518, b'\xbf\x18\x00\x00\x00'),
    'node_payload_store': (0x474252d, b'H\x89H\x10'),
    'one_edx': (0x4742486, b'\xba\x01\x00\x00\x00'),
}
WRAP_DIRECT_CALLS = {
    'ctor_call': (0x474248e, 0x4741180),
}
WRAP_LEAS = {
    'table_arg': (0x474247f, 0x6494c78),
}

SLOT_BINDINGS_WANTED = {
    'alloc': 0x64df480, 'alloc_error': 0x64df498,
    'dealloc': 0x64df4a0, 'large_sort': 0x64eaf68,
    'arc_wrap': 0x64eaf70, 'global_cell': 0x64eaf08,
    'static_table': 0x6494c58, 'registrar': 0x64e1488,
}
EXPECTED_BINDINGS = {
    'alloc': '0x6355830', 'alloc_error': '0x141e264',
    'dealloc': '0x635de30', 'large_sort': '0x47483e0',
    'arc_wrap': '0x4742470', 'global_cell': '0x64ffef8',
    'static_table': '0x450150', 'registrar': '0x474f6a0',
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


def slot_bindings(data):
    rel = _relocations(data)
    out = {}
    for name, slot in SLOT_BINDINGS_WANTED.items():
        entry = rel[slot]
        out[name] = {'slot': hex(slot), 'type': entry['type'],
                     'addend': hex(entry['addend'])}
        if out[name]['addend'] != EXPECTED_BINDINGS[name]:
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


def analyze(data):
    if hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('wrong node115 capture')
    _pins(data, CTOR_PINS, 'payload_ctor')
    for label, (site, target) in CTOR_DIRECT_CALLS.items():
        _direct_call(data, site, target, f'payload_ctor {label}')
    for label, (site, slot) in CTOR_SLOT_CALLS.items():
        _slot_call(data, site, slot, f'payload_ctor {label}')
    _pins(data, WRAP_PINS, 'arc_wrap_ctor')
    for label, (site, target) in WRAP_DIRECT_CALLS.items():
        _direct_call(data, site, target, f'arc_wrap_ctor {label}')
    for label, (site, target) in WRAP_LEAS.items():
        _lea(data, site, target, f'arc_wrap_ctor {label}')
    bindings = slot_bindings(data)
    census = direct_call_census(data, (0x4741180, 0x4742470))
    if census['0x4741180'] != ['0x474248e']:
        raise ValueError('payload ctor caller census changed')
    if census['0x4742470'] != []:
        raise ValueError('wrap ctor gained a direct caller')
    block = static_block(data)
    if block['words_after_relocation'] != ['0x450150', '0x0', '0x0', '0x0']:
        raise ValueError('static block changed')
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
        'source_layout': {
            'size': '0x50',
            'fields': [
                {'offset': '0x00', 'role': 'head scalar -> S+0x00'},
                {'offset': '0x08', 'role': 'Vec A capacity'},
                {'offset': '0x10', 'role': 'Vec A pointer (0x18-byte elements)'},
                {'offset': '0x18', 'role': 'Vec A length -> S+0x08'},
                {'offset': '0x20', 'role': 'Vec B capacity'},
                {'offset': '0x28', 'role': 'Vec B pointer (0x40-byte elements)'},
                {'offset': '0x30', 'role': 'Vec B length'},
                {'offset': '0x38', 'role': 'Vec C capacity'},
                {'offset': '0x40', 'role': 'Vec C pointer (0x40-byte elements)'},
                {'offset': '0x48', 'role': 'Vec C length'},
            ],
        },
        'payload_layout': {
            'size': '0x68',
            'fields': [
                {'offset': '0x00', 'role': 'head struct S (0x40 bytes, see phases)'},
                {'offset': '0x40', 'role': 'tail T from Vec B descriptor (0x18 bytes)'},
                {'offset': '0x58', 'role': 'rdx argument verbatim (sole caller passes 1)'},
                {'offset': '0x60', 'role': 'rcx argument verbatim (sole caller passes 0x6494c78)'},
            ],
            'head_struct_S': [
                {'offset': '0x00', 'role': 'source +0x00'},
                {'offset': '0x08', 'role': 'Vec A length'},
                {'offset': '0x10', 'role': 'mapped Vec A buffer (len*8 bytes)'},
                {'offset': '0x18', 'role': 'map helper slot word (initialised 0)'},
                {'offset': '0x20', 'role': 'static table pointer 0x450150'},
                {'offset': '0x28', 'role': '0'},
                {'offset': '0x30', 'role': '0'},
                {'offset': '0x38', 'role': '0'},
            ],
        },
        'phases': [
            'collect: Vec B iterator {ptr, end} -> collection at [rsp+0x1b0] via 0x4747a70',
            'map A: iterator {ptr_A, end_A, &collection} -> 0x4749d80 fills len_A*8 buffer',
            'sort C in place if len_C >= 2: 0x474ee70 (<21) or slot 0x64eaf68 -> 0x47483e0 (>=21)',
            'walk C: element word0 == 6 terminates; else copy element, map nested Vec via 0x4749f70, insert via 0x4741960',
            'post: drop C snapshot via 0x4753770, free collection buffer, build tail via 0x47534b0, write out 0x68 bytes',
            'consume: free every Vec A element inner buffer, then Vec A buffer if cap_A != 0',
        ],
        'storage_after': [
            'wrap ctor prefixes refcount words {1, 1} at its frame +0x00',
            'wrap ctor allocates 0x78 bytes and copies header+payload; payload at heap+0x10',
            'wrap ctor allocates a 0x18-byte node; node+0x10 = heap+0x10 (payload pointer)',
            'wrap ctor returns the node pointer in rax; no other access to the stack temp between ctor return and the heap copy',
        ],
        'verdict': (
            'The payload ctor consumes the 0x50-byte source struct '
            '(head word + three Vecs) and builds a 0x68-byte payload: '
            'a 0x40-byte head struct assembled from the head word, '
            'the mapped Vec A and per-element inserts from Vec C '
            '(terminated by a word0==6 element, after an in-place '
            'sort), a 0x18-byte tail built from the Vec B '
            'descriptor, and the caller\'s rdx/rcx arguments stored '
            'verbatim. Its sole caller, the wrap ctor, moves the '
            'payload into a refcounted 0x78-byte heap object at '
            '+0x10 and returns a 0x18-byte node pointing at it.'),
    }


def _objdump(path, start, end):
    return subprocess.check_output(
        ['objdump', '-d', '-M', 'intel', '--insn-width=16',
         f'--start-address={start:#x}', f'--stop-address={end:#x}',
         str(path)]).decode('utf-8')


WINDOWS = [
    ('payload_ctor_objdump.txt', 0x4741180, 0x4741869,
     [s for s, _ in CTOR_PINS.values()]
     + [s for s, _ in CTOR_DIRECT_CALLS.values()]
     + [s for s, _ in CTOR_SLOT_CALLS.values()]),
    ('arc_wrap_ctor_objdump.txt', 0x4742470, 0x4742595,
     [s for s, _ in WRAP_PINS.values()]
     + [s for s, _ in WRAP_DIRECT_CALLS.values()]
     + [s for s, _ in WRAP_LEAS.values()]),
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
                   default=ROOT / 'work/payload-ctor115')
    args = p.parse_args()
    report = generate(args.binary, args.output)
    print(json.dumps({'functions': len(report['owners']),
                      'bytes': sum(x['bytes'] for x in report['owners']),
                      'executed': False}))
