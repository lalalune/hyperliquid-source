#!/usr/bin/env python3
"""RE-009-C: the per-entry hashing mechanism inside three node #94 leaf functions.

Derives, from the instruction bytes of three pinned leaves, a blake3 XOF read of
0x800 bytes, a 16-bit lattice add whose byte order is decoded by register
dataflow (not assumed), and a saturating 64-bit count add. Output is sorted,
deterministic JSON. A full .text reference scan (rel32 call/jmp, RIP-relative
lea, RELATIVE relocs) pins the exact backward closure of each leaf. Uses only main-branch ELF helpers (elf_index, fde_extents).
"""
import argparse
import bisect
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections  # noqa: E402
from fde_extents import fde_extents  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts' / 'node' / '94' / 'hl-node'
BINARY_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SLOT_PLATFORM, SLOT_UPDATE, SLOT_XOF = 0x57700c0, 0x57700c8, 0x57700b0
# Each GOT slot is filled by one R_X86_64_RELATIVE entry; the addend is the target.
# Labels rest on the target bytes (names are stripped): 0x14fa220 reads the CPU
# feature word and returns a SIMD level; 0x14f93e0 buffers a 0x400-byte chunk;
# 0x14f7e40 ORs ROOT flag 8 and emits 64-byte output blocks for a caller length.
SLOT_TARGETS = {SLOT_PLATFORM: 0x14fa220, SLOT_UPDATE: 0x14f93e0, SLOT_XOF: 0x14f7e40}
SLOT_ROLES = {
    SLOT_PLATFORM: 'blake3 platform-detect slot 0x57700c0 (target 0x14fa220; constructor inlined)',
    SLOT_UPDATE: 'blake3 update slot 0x57700c8 (target 0x14f93e0; 0x400-byte chunk buffer)',
    SLOT_XOF: 'blake3 XOF fill slot 0x57700b0 (target 0x14f7e40; ROOT flag 8, 64-byte output blocks)',
}
XOF_LEN = 0x800
SAT_CONST = 0xffffffffffffffff
# Canonical Intel multi-byte NOP encodings (SDM Vol. 2B, NOP), used as loop alignment.
NOPS = {bytes.fromhex(h) for h in ('', '90', '6690', '0f1f00', '0f1f4000', '0f1f440000',
                                   '660f1f440000', '0f1f8000000000', '0f1f840000000000',
                                   '660f1f840000000000')}
REG = {0: 'ax', 1: 'cx', 2: 'dx', 3: 'bx', 4: 'sp', 5: 'bp', 6: 'si', 7: 'di'}

# One record per leaf. Field names are an inference from Locations (see README).
LEAVES = (
    {'leaf': 0x37f3f00, 'end': 0x37f4277, 'field_inference': 'accounts',
     'producer': 0x37d3070, 'top_call': 0x3269cbe,
     'fold': 0x3bc4760, 'producer_fold_calls': (0x37d3574, 0x37d386c),
     'rayon': 0x3443160, 'fold_rayon_call': 0x3bc47f4, 'rayon_leaf_call': 0x344320e,
     'preparer': 0x3284d90, 'leaf_preparer_call': 0x37f3f59,
     'call_new': 0x37f3f96, 'call_update': 0x37f4045, 'xof_len': 0x37f408a, 'call_xof': 0x37f408f,
     'loop_a': (0x37f40c3, 0x37f40d0, 0x37f4128), 'count': (0x37f4170, 0x37f41ba),
     'loop_b': (0x37f41ba, 0x37f41c0, 0x37f4218)},
    {'leaf': 0x37f4280, 'end': 0x37f4607, 'field_inference': 'contracts',
     'producer': 0x37d3bd0, 'top_call': 0x3269ed9,
     'fold': 0x3bc50e0, 'producer_fold_calls': (0x37d4080, 0x37d43ae),
     'rayon': 0x3440b50, 'fold_rayon_call': 0x3bc5174, 'rayon_leaf_call': 0x3440bfe,
     'preparer': 0x3284ad0, 'leaf_preparer_call': 0x37f42e7,
     'call_new': 0x37f4324, 'call_update': 0x37f43d6, 'xof_len': 0x37f441b, 'call_xof': 0x37f4420,
     'loop_a': (0x37f4454, 0x37f4460, 0x37f44b8), 'count': (0x37f4500, 0x37f454a),
     'loop_b': (0x37f454a, 0x37f4550, 0x37f45a8)},
    {'leaf': 0x37f4610, 'end': 0x37f49a7, 'field_inference': 'storage',
     'producer': 0x37d2550, 'top_call': 0x326a0e5,
     'fold': 0x3bc4a40, 'producer_fold_calls': (0x37d29c2, 0x37d2d00),
     'rayon': 0x343c390, 'fold_rayon_call': 0x3bc4ad4, 'rayon_leaf_call': 0x343c43e,
     'preparer': 0x3284c70, 'leaf_preparer_call': 0x37f4689,
     'call_new': 0x37f46c6, 'call_update': 0x37f477b, 'xof_len': 0x37f47c0, 'call_xof': 0x37f47c5,
     'loop_a': (0x37f47f9, 0x37f4800, 0x37f4858), 'count': (0x37f48a0, 0x37f48ea),
     'loop_b': (0x37f48ea, 0x37f48f0, 0x37f4948)},
)
TOP_FN, WRITER, WRITER_CALL = 0x3269ae0, 0x32699c0, 0x326a2e0


class Image:
    def __init__(self, data):
        self.data = data
        self.text = next(s for s in sections(data) if s['name'] == '.text')

    def read(self, va, n):
        t = self.text
        if not (t['address'] <= va and va + n <= t['address'] + t['size']):
            raise ValueError(f'{va:#x}+{n} outside .text')
        off = va - t['address'] + t['offset']
        return self.data[off:off + n]

    def rel32_target(self, va):
        b = self.read(va, 5)
        if b[0] != 0xe8:
            raise ValueError(f'{va:#x}: not call rel32')
        return va + 5 + struct.unpack('<i', b[1:])[0]

    def got_slot(self, va):
        b = self.read(va, 6)
        if b[:2] != b'\xff\x15':
            raise ValueError(f'{va:#x}: not call [rip+disp32]')
        return va + 6 + struct.unpack('<i', b[2:])[0]


def slot_table(data):
    """Resolve each pinned GOT slot through its R_X86_64_RELATIVE entry."""
    rd = next(s for s in sections(data) if s['name'] == '.rela.dyn')
    found = {}
    for j in range(rd['offset'], rd['offset'] + rd['size'] - 23, 24):
        off, info, add = struct.unpack_from('<QQq', data, j)
        if off in SLOT_TARGETS:
            if info & 0xffffffff != 8 or off in found:
                raise ValueError(f'{off:#x}: GOT slot relocation is not a single R_X86_64_RELATIVE')
            found[off] = add
    if found != SLOT_TARGETS:
        raise ValueError(f'GOT slot targets {found} != pinned')
    return [{'slot': hex(s), 'target': hex(SLOT_TARGETS[s]), 'role': SLOT_ROLES[s]}
            for s in sorted(SLOT_TARGETS)]


# --- reference closure (full .text) -------------------------------------
# Reference kinds scanned over all of .text: e8 call rel32, e9 jmp rel32,
# 8d /r RIP-relative lea; plus every R_X86_64_RELATIVE addend in .rela.dyn.
# REFS pins, for every function in each leaf's backward closure and for the
# top function and writer, the exact set of (site, kind, source function).
REFS = {
    0x32699c0: ((0x326a2e0, 'call', 0x3269ae0), (0x326aff3, 'call', 0x326aec0), (0x32fc267, 'call', 0x32fc190)),
    0x3269ae0: ((0x326e4bb, 'call', 0x326e460), (0x32fc41f, 'call', 0x32fc190)),
    0x343c390: ((0x3830c14, 'call', 0x3830a40), (0x3830e08, 'call', 0x3830a40), (0x38adbb4, 'call', 0x38adb50), (0x3bc4ad4, 'call', 0x3bc4a40)),
    0x3440b50: ((0x3828cf4, 'call', 0x3828b20), (0x3828ee8, 'call', 0x3828b20), (0x38d0864, 'call', 0x38d0800), (0x3bc5174, 'call', 0x3bc50e0)),
    0x3443160: ((0x381f4e4, 'call', 0x381f310), (0x381f6d8, 'call', 0x381f310), (0x38ba7e4, 'call', 0x38ba780), (0x3bc47f4, 'call', 0x3bc4760)),
    0x37d2550: ((0x326a0e5, 'call', 0x3269ae0),),
    0x37d3070: ((0x3269cbe, 'call', 0x3269ae0),),
    0x37d3bd0: ((0x3269ed9, 'call', 0x3269ae0),),
    0x37f3f00: ((0x344320e, 'call', 0x3443160),),
    0x37f4280: ((0x3440bfe, 'call', 0x3440b50),),
    0x37f4610: ((0x343c43e, 'call', 0x343c390),),
    0x381f310: ((0x34433a7, 'call', 0x3443160), (0x38b0a58, 'call', 0x38b09c0), (0x38d95a4, 'call', 0x38d9510)),
    0x3828b20: ((0x3440d97, 'call', 0x3440b50), (0x38b7d74, 'call', 0x38b7ce0), (0x38d0e18, 'call', 0x38d0d80)),
    0x3830a40: ((0x343c5d3, 'call', 0x343c390), (0x38bd8c4, 'call', 0x38bd830), (0x38c6758, 'call', 0x38c66c0)),
    0x3843510: ((0x3440e8c, 'call', 0x3440b50),),
    0x3846fa0: ((0x344349c, 'call', 0x3443160),),
    0x384e2d0: ((0x343c6cc, 'call', 0x343c390),),
    0x3851320: ((0x343c6e7, 'call', 0x343c390),),
    0x3854d90: ((0x34434b7, 'call', 0x3443160),),
    0x3857170: ((0x3440ea7, 'call', 0x3440b50),),
    0x38adb50: ((0x3830b52, 'lea', 0x3830a40),),
    0x38b09c0: ((0x3854e2c, 'lea', 0x3854d90),),
    0x38b7ce0: ((0x384359f, 'lea', 0x3843510),),
    0x38ba780: ((0x381f422, 'lea', 0x381f310),),
    0x38bd830: ((0x384e35f, 'lea', 0x384e2d0),),
    0x38c66c0: ((0x38513bc, 'lea', 0x3851320),),
    0x38d0800: ((0x3828c32, 'lea', 0x3828b20),),
    0x38d0d80: ((0x385720c, 'lea', 0x3857170),),
    0x38d9510: ((0x384702f, 'lea', 0x3846fa0),),
    0x3bc4760: ((0x37d3574, 'call', 0x37d3070), (0x37d386c, 'call', 0x37d3070)),
    0x3bc4a40: ((0x37d29c2, 'call', 0x37d2550), (0x37d2d00, 'call', 0x37d2550)),
    0x3bc50e0: ((0x37d4080, 'call', 0x37d3bd0), (0x37d43ae, 'call', 0x37d3bd0)),
}


def _scan_refs(data, targets):
    secs = {s['name']: s for s in sections(data)}
    t = secs['.text']
    tb = data[t['offset']:t['offset'] + t['size']]
    base = t['address']
    hits = {x: [] for x in targets}
    for op, kind, ln, disp in ((b'\xe8', 'call', 5, 1), (b'\xe9', 'jmp', 5, 1)):
        i = tb.find(op)
        while i != -1 and i + ln <= len(tb):
            x = base + i + ln + struct.unpack_from('<i', tb, i + disp)[0]
            if x in hits:
                hits[x].append((base + i, kind))
            i = tb.find(op, i + 1)
    i = tb.find(b'\x8d')
    while i != -1 and i + 6 <= len(tb):
        if tb[i + 1] & 0xc7 == 5:
            x = base + i + 6 + struct.unpack_from('<i', tb, i + 2)[0]
            if x in hits:
                hits[x].append((base + i - 1, 'lea'))
        i = tb.find(b'\x8d', i + 1)
    r = secs['.rela.dyn']
    rb = data[r['offset']:r['offset'] + r['size']]
    for j in range(0, len(rb) - 23, 24):
        off, info, add = struct.unpack_from('<QQq', rb, j)
        if info & 0xffffffff == 8 and add in hits:
            hits[add].append((off, 'reloc'))
    return {x: sorted(v) for x, v in hits.items()}


def reference_closure(data, extents):
    starts = sorted(extents)

    def owner(va):
        k = bisect.bisect_right(starts, va) - 1
        return starts[k] if k >= 0 and va < extents[starts[k]] else None
    got = _scan_refs(data, tuple(REFS))
    for tgt, want in REFS.items():
        have = [(site, kind, owner(site) if kind != 'reloc' else None) for site, kind in got[tgt]]
        if have != list(want):
            raise ValueError(f'{tgt:#x}: references {[(hex(a), k, f and hex(f)) for a, k, f in have]}')
    leaves = []
    for L in LEAVES:
        seen, todo, edges = {L['leaf']}, [L['leaf']], []
        while todo:
            f = todo.pop()
            if f == TOP_FN:
                continue
            if f not in REFS:
                raise ValueError(f'{f:#x}: reached a function without pinned references')
            for site, kind, src in REFS[f]:
                if src is None:
                    raise ValueError(f'{f:#x}: non-code reference {site:#x} inside the closure')
                edges.append((site, kind, src, f))
                if src not in seen:
                    seen.add(src)
                    todo.append(src)
        external = sorted({(s, k, a, b) for s, k, a, b in edges if a == TOP_FN})
        leaves.append({
            'leaf': hex(L['leaf']),
            'closure_functions': [[hex(f), hex(extents[f])] for f in sorted(seen)],
            'closure_edges': [[hex(s), k, hex(a), hex(b)] for s, k, a, b in sorted(edges)],
            'entry_from_top': [[hex(s), k, hex(a), hex(b)] for s, k, a, b in external],
        })
    return {
        'reference_kinds': ['e8 call rel32', 'e9 jmp rel32', 'rip-relative lea', 'R_X86_64_RELATIVE addend'],
        'leaves': leaves,
        'top_function_refs': [[hex(s), k, f and hex(f)] for s, k, f in REFS[TOP_FN]],
        'writer_refs': [[hex(s), k, f and hex(f)] for s, k, f in REFS[WRITER]],
        'counts': {'closure_functions_per_leaf': [len(x['closure_functions']) for x in leaves],
                   'closure_edges_per_leaf': [len(x['closure_edges']) for x in leaves],
                   'writer_callers': len(REFS[WRITER]), 'top_function_callers': len(REFS[TOP_FN])},
    }


def decode_lattice(img, init_va, body_va, end_va):
    """Straight-line dataflow over one loop body; returns the derived semantics."""
    b = img.read(body_va, end_va - body_va)
    init = img.read(init_va, body_va - init_va)
    if init[:1] == b'\xb8':
        start, pad = struct.unpack('<I', init[1:5])[0], init[5:]
    elif init[:2] == b'\x31\xc0':
        start, pad = 0, init[2:]
    else:
        raise ValueError(f'{init_va:#x}: unknown index init')
    if pad not in NOPS:
        raise ValueError(f'{init_va:#x}: index init padding is not a canonical NOP')
    val, stores, loads, swaps, pos = {}, [], 0, 0, 0
    step = bound = None
    while pos < len(b):
        if b[pos:pos + 2] == b'\x0f\xb7':          # movzx r32, WORD [rsp+rax*2+d32]
            modrm, sib = b[pos + 2], b[pos + 3]
            if modrm >> 6 != 2 or modrm & 7 != 4 or sib != 0x44:
                raise ValueError(f'{body_va + pos:#x}: unexpected movzx form')
            disp = struct.unpack_from('<i', b, pos + 4)[0]
            val[(modrm >> 3) & 7] = ('load', disp)
            loads += 1
            pos += 8
        elif b[pos:pos + 2] == b'\x66\xc1' and b[pos + 2] >> 3 == 0x18 and b[pos + 3] == 8:
            r = b[pos + 2] & 7                         # rol r16, 8  == 16-bit byte swap
            val[r] = ('swap', val[r])
            swaps += 1
            pos += 4
        elif b[pos] == 0x01 and b[pos + 1] >> 6 == 3:  # add r32, r32
            src, dst = (b[pos + 1] >> 3) & 7, b[pos + 1] & 7
            val[dst] = ('add', val[dst], val[src])
            pos += 2
        elif b[pos:pos + 2] == b'\x66\x89':          # mov WORD [rsp+rax*2+d32], r16
            modrm, sib = b[pos + 2], b[pos + 3]
            if modrm >> 6 != 2 or modrm & 7 != 4 or sib != 0x44:
                raise ValueError(f'{body_va + pos:#x}: unexpected store form')
            disp = struct.unpack_from('<i', b, pos + 4)[0]
            stores.append((disp, val[(modrm >> 3) & 7]))
            pos += 8
        elif b[pos:pos + 3] == b'\x48\x83\xc0':      # add rax, imm8
            step = b[pos + 3]
            pos += 4
        elif b[pos:pos + 2] == b'\x48\x3d':          # cmp rax, imm32
            bound = struct.unpack_from('<I', b, pos + 2)[0]
            pos += 6
        elif b[pos] == 0x75:                           # jne rel8
            if body_va + pos + 2 + struct.unpack_from('<b', b, pos + 1)[0] != body_va:
                raise ValueError(f'{body_va + pos:#x}: back-edge does not close the loop')
            pos += 2
        else:
            raise ValueError(f'{body_va + pos:#x}: undecoded byte {b[pos]:#04x}')
    if pos != len(b) or step is None or bound is None:
        raise ValueError(f'{body_va:#x}: incomplete loop')

    def be_add(v):
        return (v[0] == 'swap' and v[1][0] == 'add'
                and v[1][1][0] == 'swap' and v[1][1][1][0] == 'load'
                and v[1][2][0] == 'swap' and v[1][2][1][0] == 'load')
    if not stores or not all(be_add(v) for _, v in stores):
        raise ValueError(f'{body_va:#x}: store values are not swap(add(swap(load),swap(load)))')
    addend_offsets = set()
    for disp, v in stores:
        a, c = v[1][1][1][1], v[1][2][1][1]
        if disp not in (a, c):
            raise ValueError(f'{body_va:#x}: accumulator lane is not stored back in place')
        addend_offsets.add((c if disp == a else a) - disp)
    if len(addend_offsets) != 1:
        raise ValueError(f'{body_va:#x}: lanes do not share one addend buffer')
    base = min(d for d, _ in stores) + start * 2
    iters = len(range(start, bound, step))
    lanes = len(stores)
    return {
        'body': [hex(body_va), hex(end_va)], 'body_len': len(b),
        'body_sha256': hashlib.sha256(b).hexdigest(),
        'index_start': start, 'index_bound': hex(bound), 'index_step': step,
        'iterations': iters, 'lanes_per_iteration': lanes, 'u16_words_total': iters * lanes,
        'bytes_covered': iters * lanes * 2,
        'word_loads': loads, 'rol16_8_swaps': swaps, 'u16_stores': lanes,
        'accumulator_base': hex(base),
        'addend_minus_accumulator': hex(addend_offsets.pop()),
        'byte_order': 'big-endian', 'add_width_bits': 32, 'store_width_bits': 16,
        'overflow': 'wrapping-mod-2^16',
    }


def decode_count(img, va, end):
    b = img.read(va, end - va)
    sat = b.count(b'\x48\xc7\xc1\xff\xff\xff\xff')    # mov rcx, -1
    cmovb = b.count(b'\x48\x0f\x42')
    cmovae = b.count(b'\x48\x0f\x43')
    adds = b.count(b'\x48\x03')                        # add r64, [mem]
    if sat != 1 or cmovb < 1 or adds != 2:
        raise ValueError(f'{va:#x}: saturating count block not found')
    disps = []
    for i in range(len(b) - 7):
        # REX.W 8b/03/89 with ModRM mod=10 rm=100 and SIB 0x24: [rsp+disp32]
        if b[i] == 0x48 and b[i + 1] in (0x8b, 0x03, 0x89) and b[i + 2] >> 6 == 2 \
                and b[i + 2] & 7 == 4 and b[i + 3] == 0x24:
            disps.append(struct.unpack_from('<i', b, i + 4)[0])
    return {'block': [hex(va), hex(end)], 'block_len': len(b),
            'rsp_operands': [hex(x) for x in sorted(set(disps))],
            'block_sha256': hashlib.sha256(b).hexdigest(),
            'u64_adds': adds, 'saturate_const': hex(SAT_CONST), 'cmovb': cmovb, 'cmovae': cmovae,
            'overflow': 'saturating-u64'}


def leaf_extents(data):
    return {f['start']: f['end'] for f in fde_extents(data)[1]}


def analyse(data, require_sha=True, extents=None, check_refs=True):
    """require_sha/extents exist so tests can tamper one byte and hit one check."""
    if require_sha and hashlib.sha256(data).hexdigest() != BINARY_SHA256:
        raise ValueError('binary sha256 mismatch')
    img = Image(data)
    if extents is None:
        extents = leaf_extents(data)
    out_leaves = []
    for L in LEAVES:
        if extents.get(L['leaf']) != L['end']:
            raise ValueError(f"{L['leaf']:#x}: FDE extent mismatch")
        chain = {
            'top_to_producer': img.rel32_target(L['top_call']) == L['producer'],
            'producer_to_fold': all(img.rel32_target(v) == L['fold'] for v in L['producer_fold_calls']),
            'fold_to_rayon': img.rel32_target(L['fold_rayon_call']) == L['rayon'],
            'rayon_to_leaf': img.rel32_target(L['rayon_leaf_call']) == L['leaf'],
            'leaf_to_preparer': img.rel32_target(L['leaf_preparer_call']) == L['preparer'],
        }
        if not all(chain.values()):
            raise ValueError(f"{L['leaf']:#x}: call chain mismatch {chain}")
        slots = {'platform_detect': img.got_slot(L['call_new']), 'update': img.got_slot(L['call_update']),
                 'xof_fill': img.got_slot(L['call_xof'])}
        if slots != {'platform_detect': SLOT_PLATFORM, 'update': SLOT_UPDATE, 'xof_fill': SLOT_XOF}:
            raise ValueError(f"{L['leaf']:#x}: blake3 slot mismatch")
        if img.read(L['xof_len'], 5) != b'\xba' + struct.pack('<I', XOF_LEN):
            raise ValueError(f"{L['xof_len']:#x}: xof length is not 0x800")
        merge = decode_lattice(img, *L['loop_b'])
        count = decode_count(img, *L['count'])
        mb, ma = int(merge['accumulator_base'], 16), int(merge['addend_minus_accumulator'], 16)
        trailer = sorted({mb + 0x800, mb + 0x808, mb + ma + 0x800, mb + ma + 0x808})
        if [int(x, 16) for x in count['rsp_operands']] != trailer:
            raise ValueError(f"{L['leaf']:#x}: count operands are not the +0x800/+0x808 trailer")
        out_leaves.append({
            'leaf': hex(L['leaf']), 'fde_end': hex(L['end']),
            'field_inference': L['field_inference'],
            'chain': {k: hex(L[k]) for k in ('producer', 'fold', 'rayon', 'preparer')},
            'chain_calls': {'top_call': hex(L['top_call']),
                            'producer_fold_calls': [hex(v) for v in L['producer_fold_calls']],
                            'fold_rayon_call': hex(L['fold_rayon_call']),
                            'rayon_leaf_call': hex(L['rayon_leaf_call']),
                            'leaf_preparer_call': hex(L['leaf_preparer_call'])},
            'blake3_slots': {k: hex(v) for k, v in slots.items()},
            'blake3_calls': {'platform_detect': hex(L['call_new']), 'update': hex(L['call_update']),
                             'xof_fill': hex(L['call_xof'])},
            'xof_len': hex(XOF_LEN), 'xof_len_va': hex(L['xof_len']),
            'lattice_entry_add': decode_lattice(img, *L['loop_a']),
            'count_add': count,
            'lattice_merge_add': merge,
            'state_layout': {'size': hex(0x810), 'lattice': ['0x0', '0x800'],
                             'u64_counters': ['0x800', '0x808']},
        })
    if img.rel32_target(WRITER_CALL) != WRITER:
        raise ValueError('top function writer call mismatch')
    out = {
        'schema': 're009c-lthash-mechanism/2',
        'binary_sha256': BINARY_SHA256,
        'coordinates': 'virtual addresses (VA), ELF64 x86-64',
        'top_function': hex(TOP_FN), 'writer': hex(WRITER), 'writer_call': hex(WRITER_CALL),
        'leaves': out_leaves,
        'blake3_slots': slot_table(data),
        'counts': {'leaves': len(out_leaves), 'lattice_loops': 2 * len(out_leaves),
                   'count_blocks': len(out_leaves)},
    }
    if check_refs:
        out['reference_closure'] = reference_closure(data, extents)
    return out


def render(result):
    return json.dumps(result, indent=2, sort_keys=True) + '\n'


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--binary', type=Path, default=TARGET)
    p.add_argument('--out', type=Path)
    a = p.parse_args(argv)
    text = render(analyse(a.binary.read_bytes()))
    if a.out:
        a.out.write_text(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
