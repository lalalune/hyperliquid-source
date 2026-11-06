#!/usr/bin/env python3
"""Pin the consumers of the lu.rs LazyLock accessor (node 115).

PR #2999 pinned the base crate's `LazyLock` cell at `0x64f01c0`:
its initializer is `0x1568de0`, and the cached value's only direct
reader is the accessor `0x1560a40` (GOT slot `0x64e0b20`), which
returns the cell's +8/+0x10 words at 100 call sites in 65 bodies.
This tool re-derives, from the materialised artifact alone:

- the accessor slot relocation and the accessor / initializer /
  transform-function body pins (FDE extent + SHA-256);
- the whole-`.text` census of references to the accessor slot
  (100 indirect-call sites in 65 bodies, no other reference form);
- the initializer's evidence set: the two `panic::Location`
  records inside it name `base/src/build_mode.rs` (28:13, 30:26),
  the packed literal block beside its assertion holds `/cham/`,
  `debug`, `release`, `run-client`, and its sret result is a
  24-byte `String` stored (length, pointer, length);
- the per-site analyst classification of what each caller does
  with the returned pair (bound to the census: every site is
  classified exactly once, and the counts are re-checked).

The classification itself -- at all 100 sites the returned
(pointer, length) pair is discarded, never read as data -- was
established by a fall-through fate scan of both registers, a
block-level CFG walk inside each body, and manual reading of
every flagged exception; the retained `consumer-windows.txt`
export is the window evidence each classification rests on, and
this tool regenerates it byte for byte.
"""
import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
PACKET = (ROOT / 'research/work-items/'
          'RE-005-node115-lu-lazylock-consumers')
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278' \
      'fa39f249e98c3867b5301'
SIZE = 105896032
BASE_COMMIT = '05bc2de303c05525b71e7e257426e741bc66a390'

CELL = 0x64f01c0
SLOT = 0x64e0b20
ACCESSOR = (0x1560a40, 0x1560aab)
INIT_FN = (0x1568de0, 0x156971c)
TRIM_FN = (0x150caf0, 0x150cd87)
LOC_BUILD_MODE_28 = 0x63fe3a8
LOC_BUILD_MODE_30 = 0x63fe390

BYTE_PINS = {
    # accessor loads the +8 / +0x10 words of the cell
    0x1560a4a: '488b0577f7f804',
    0x1560a51: '488b1578f7f804',
    # initializer: default (0, 1, 0) triple
    0x1568df6: '48c7042400000000',
    0x1568dfe: '48c744240801000000',
    0x1568e07: '48c744241000000000',
    # argument-iterator construction and step through the
    # adjacent slots 0x64e1290 / 0x64e1298
    0x1568e18: 'ff157284f704',
    0x1568e6b: 'ff152784f704',
    # "--" comparison at the top of the per-argument dispatch
    0x1568f40: '6641813c242d2d',
    # "/cham/" component compares
    0x1568f62: 'be2f636861',
    0x1568f6d: '81f66d2f0000',
    # sret store of the built String: (len, ptr, len)
    0x1569609: '488b442478',
    0x156960e: '488918',
    0x1569611: '4c897008',
    0x1569615: '48895810',
    # ends_with('/') assertion message setup (len 0x25 = 37)
    0x1569663: '488d3d8ee0effe',
    0x1569671: 'be25000000',
    # transform fn: per-byte UTF-8 walk of the candidate string
    0x150cb13: '470fb60c08',
}

LITERALS = [
    (0x4676f2, 6, '/cham/'),
    (0x4676f8, 37, "assertion failed: !arg.ends_with('/')"),
    (0x46771d, 5, 'debug'),
    (0x467722, 7, 'release'),
    (0x467729, 10, 'run-client'),
]

# Analyst classification of every call site, verified against the
# retained windows (see module docstring). Keys are site VAs.
SITE_CONTEXT = {
    '0x150abff': 'cleanup_block',
    '0x150ac16': 'cleanup_block',
    '0x15d6074': 'statement',
    '0x2317bf9': 'statement',
    '0x269f7f3': 'drop_glue',
    '0x28cda6f': 'statement',
    '0x28ceae1': 'statement',
    '0x28cf7d2': 'statement',
    '0x28d0568': 'statement',
    '0x28d14c6': 'statement',
    '0x28d2369': 'statement',
    '0x28d75d2': 'statement',
    '0x2c02a8e': 'statement',
    '0x2c02aff': 'statement',
    '0x2c3f181': 'err_exit',
    '0x2c3f1aa': 'statement',
    '0x2c40d21': 'statement',
    '0x2c40db3': 'statement',
    '0x2c40f08': 'statement',
    '0x2c48026': 'statement',
    '0x2e08569': 'statement',
    '0x2e0a951': 'statement',
    '0x2e0eea8': 'statement',
    '0x2e18562': 'statement',
    '0x36ca452': 'statement',
    '0x38bc373': 'err_exit',
    '0x38bc3f5': 'err_exit',
    '0x38bc6e1': 'statement',
    '0x38bc9dd': 'statement',
    '0x38c02c6': 'statement',
    '0x38d343a': 'drop_glue',
    '0x38d381b': 'drop_glue',
    '0x38d393c': 'drop_glue',
    '0x38d3e48': 'drop_glue',
    '0x38d4746': 'drop_glue',
    '0x38d4ead': 'drop_glue',
    '0x38d5431': 'drop_glue',
    '0x38d57f9': 'drop_glue',
    '0x38d5ef7': 'drop_glue',
    '0x38d64e7': 'drop_glue',
    '0x38d6acd': 'drop_glue',
    '0x38d6e76': 'drop_glue',
    '0x38d7213': 'drop_glue',
    '0x38d77cd': 'drop_glue',
    '0x38d7b3c': 'drop_glue',
    '0x38d7eb3': 'drop_glue',
    '0x38dfaf3': 'drop_glue',
    '0x38e063b': 'drop_glue',
    '0x38e0ff9': 'drop_glue',
    '0x38e16fe': 'drop_glue',
    '0x38e22c4': 'drop_glue',
    '0x38e2d66': 'drop_glue',
    '0x38e3598': 'drop_glue',
    '0x38e3aea': 'drop_glue',
    '0x38e4193': 'drop_glue',
    '0x38e4824': 'drop_glue',
    '0x38e5014': 'drop_glue',
    '0x38e5c59': 'drop_glue',
    '0x38e6454': 'drop_glue',
    '0x38e6ce7': 'drop_glue',
    '0x38e7697': 'drop_glue',
    '0x38e7c2e': 'drop_glue',
    '0x38e8143': 'drop_glue',
    '0x38e8d84': 'drop_glue',
    '0x38e937d': 'drop_glue',
    '0x38ea4e0': 'drop_glue',
    '0x421eb74': 'statement',
    '0x4470c19': 'statement',
    '0x44abd67': 'err_exit',
    '0x4e36f53': 'drop_glue',
    '0x538cffc': 'statement',
    '0x538e087': 'statement',
    '0x538edf6': 'statement',
    '0x538faf3': 'statement',
    '0x5390a41': 'statement',
    '0x53917d7': 'statement',
    '0x539666f': 'statement',
    '0x5397e1c': 'statement',
    '0x5398ea7': 'statement',
    '0x5399c16': 'statement',
    '0x539a913': 'statement',
    '0x539b861': 'statement',
    '0x539c5f7': 'statement',
    '0x53a148f': 'statement',
    '0x54f0f3f': 'statement',
    '0x54f0faf': 'statement',
    '0x54f250f': 'statement',
    '0x54f257f': 'statement',
    '0x55966d7': 'statement',
    '0x559676c': 'statement',
    '0x55969eb': 'statement',
    '0x5597e31': 'err_exit',
    '0x5597e5a': 'statement',
    '0x559a03b': 'statement',
    '0x559a0cd': 'statement',
    '0x559a34f': 'statement',
    '0x559e6f1': 'err_exit',
    '0x559e71a': 'statement',
    '0x55ad3e6': 'statement',
    '0x55b30e6': 'statement',
}

BODY_FILES = {
    '0x1509b70': ['base/src/file_mod_time_tracker.rs'],
    '0x28cd7a0': ['l1/src/dex_registry/clearinghouses.rs', 'l1/src/qtys/impl_ntl.rs', 'l1/src/action/vote_global.rs', 'l1/src/qtys/impl_wei.rs'],
    '0x2c01920': ['l1/src/qtys/mod.rs', 'l1/src/spot_meta.rs'],
    '0x2c3edb0': ['l1/src/qtys/impl_ntl.rs'],
    '0x2c3f5e0': ['l1/src/exchange/impl_vault.rs', 'l1/src/books.rs', 'l1/src/qtys/mod.rs', 'l1/src/qtys/impl_ntl.rs'],
    '0x2c47660': ['l1/src/asset/pdi.rs'],
    '0x2e098e0': ['node/src/consensus/state.rs', 'node/src/consensus/mempool.rs', 'node/src/consensus/signature_tracker.rs', 'node/src/consensus/timer.rs'],
    '0x2e157c0': ['node/src/consensus/mempool.rs', 'base/src/l1_map/entry.rs'],
    '0x38bc000': ['l1/src/spot_meta.rs', 'l1/src/hyperliquidity.rs'],
    '0x38df640': ['l1/src/dex_registry/clearinghouses.rs'],
    '0x38e0100': ['l1/src/dex_registry/perp_dex.rs', 'l1/src/books.rs'],
    '0x38e06a0': ['l1/src/dex_registry/clearinghouses.rs'],
    '0x38e1760': ['/home/ubuntu/hl/code_Mainnet/z_vendor/alloy-sol-types/src/abi/encoder.rs'],
    '0x38e23a0': ['/home/ubuntu/hl/code_Mainnet/z_vendor/alloy-sol-types/src/abi/encoder.rs', '/home/ubuntu/hl/code_Mainnet/z_vendor/alloy-sol-types/src/utils.rs'],
    '0x38e2e10': ['l1/src/dex_registry/clearinghouses.rs'],
    '0x38e4880': ['l1/src/spot_meta.rs'],
    '0x38e5070': ['/home/ubuntu/hl/code_Mainnet/z_vendor/alloy-sol-types/src/abi/encoder.rs', 'l1/src/perp_meta.rs', 'l1/src/dex_registry/clearinghouses.rs', '/home/ubuntu/hl/code_Mainnet/z_vendor/alloy-sol-types/src/utils.rs'],
    '0x38e6d40': ['/home/ubuntu/hl/code_Mainnet/z_vendor/indexmap/src/map.rs'],
    '0x38e76f0': ['l1/src/dex_registry/clearinghouses.rs', 'l1/src/clearinghouse/oracle/oracle.rs'],
    '0x38e81a0': ['/home/ubuntu/hl/code_Mainnet/z_vendor/alloy-sol-types/src/abi/encoder.rs'],
    '0x38e8e40': ['l1/src/dex_registry/clearinghouses.rs', 'l1/src/clearinghouse/oracle/oracle.rs'],
    '0x38e93e0': ['/home/ubuntu/hl/code_Mainnet/z_vendor/alloy-sol-types/src/abi/encoder.rs', '/home/ubuntu/hl/code_Mainnet/z_vendor/alloy-sol-types/src/abi/token.rs', '/home/ubuntu/hl/code_Mainnet/z_vendor/alloy-sol-types/src/utils.rs'],
    '0x446c200': ['l1/src/clearinghouse/clearinghouse.rs', 'l1/src/qtys/mod.rs', 'BUG:', 'l1/src/qtys/impl_ntl.rs'],
    '0x44ab4a0': ['l1/src/vault/mod.rs', 'l1/src/qtys/mod.rs', 'l1/src/qtys/impl_ntl.rs'],
    '0x538cd30': ['l1/src/dex_registry/clearinghouses.rs', 'l1/src/qtys/impl_ntl.rs', 'l1/src/action/vote_global.rs', 'l1/src/qtys/impl_wei.rs'],
    '0x5397b50': ['l1/src/dex_registry/clearinghouses.rs', 'l1/src/qtys/impl_ntl.rs', 'l1/src/action/vote_global.rs', 'l1/src/qtys/impl_wei.rs'],
    '0x54efca0': ['l1/src/spot_meta.rs', 'l1/src/qtys/impl_ntl.rs', 'l1/src/qtys/mod.rs'],
    '0x54f1270': ['l1/src/spot_meta.rs', 'l1/src/qtys/impl_ntl.rs', 'l1/src/qtys/mod.rs'],
    '0x5594f60': ['l1/src/exchange/impl_vault.rs', 'l1/src/qtys/impl_ntl.rs', 'l1/src/books.rs', 'l1/src/qtys/mod.rs'],
    '0x5597a60': ['l1/src/qtys/impl_ntl.rs'],
    '0x55988f0': ['l1/src/exchange/impl_vault.rs', 'l1/src/qtys/impl_ntl.rs', 'l1/src/books.rs', 'l1/src/qtys/mod.rs'],
    '0x559e320': ['l1/src/qtys/impl_ntl.rs'],
    '0x55aca20': ['l1/src/asset/pdi.rs'],
    '0x55b2720': ['l1/src/asset/pdi.rs'],
}

CONTEXT_LEGEND = {
    'drop_glue': 'call sits in a generated drop/cleanup sequence: '
                 'an adjacent TLS-state store, reference-count '
                 'decrement, or the field-dispatch finalizer '
                 '0x452a890 within the surrounding instructions',
    'err_exit': 'call immediately precedes loading an error '
                'tag/message and jumping to the shared exit',
    'cleanup_block': 'call sits in an unwind cleanup block',
    'statement': 'call in ordinary statement position; the pair '
                 'is overwritten or ignored and execution '
                 'continues',
}


def va_bytes(data, secs, va, size):
    for s in secs:
        if (s['type'] != 8 and s['address'] <= va
                < s['address'] + s['size']):
            off = s['offset'] + (va - s['address'])
            return data[off:off + size]
    raise ValueError(f'va {va:#x} not in a file-backed section')


def offset_of(data, secs, va):
    for s in secs:
        if (s['type'] != 8 and s['address'] <= va
                < s['address'] + s['size']):
            return s['offset'] + (va - s['address'])
    raise ValueError(f'va {va:#x} not in a file-backed section')


def fde_extents(data):
    """(start, end) pairs from .eh_frame FDE headers."""
    import subprocess as sp
    out = sp.run(['objdump', '--dwarf=frames', str(TARGET)],
                 capture_output=True, text=True).stdout
    extents = []
    import re
    for m in re.finditer(r'pc=0*([0-9a-f]+)\.\.0*([0-9a-f]+)', out):
        extents.append((int(m.group(1), 16), int(m.group(2), 16)))
    return sorted(set(extents))


def extent_of(extents, va):
    import bisect
    starts = [e[0] for e in extents]
    i = bisect.bisect_right(starts, va) - 1
    if i >= 0 and extents[i][0] <= va < extents[i][1]:
        return extents[i]
    raise ValueError(f'no FDE extent contains {va:#x}')


def body_record(data, secs, extent):
    lo, hi = extent
    b = va_bytes(data, secs, lo, hi - lo)
    return {'start': hex(lo), 'end': hex(hi), 'size': hi - lo,
            'sha256': hashlib.sha256(b).hexdigest()}


def slot_target(data, secs):
    """Resolve the accessor GOT slot through .rela.dyn."""
    return relocation_addend(data, secs, SLOT)


def cell_refs_in_body(data, secs, lo, hi):
    """Count RIP-relative references to the LazyLock cell inside
    one body (the inlined ensure blocks each take the cell address
    once, to build the closure environment on the stack)."""
    text = next(s for s in secs if s['name'] == '.text')
    start = text['offset'] + (lo - text['address'])
    blob = data[start:start + (hi - lo)]
    count, i, n = 0, 0, len(blob)
    while i < n - 7:
        if 0x48 <= blob[i] <= 0x4f and (blob[i + 2] & 0xc7) == 0x05:
            disp = struct.unpack_from('<i', blob, i + 3)[0]
            if lo + i + 7 + disp == CELL:
                count += 1
        i += 1
    return count


def census(data, secs, extents):
    """Whole-.text scan for references to the accessor slot."""
    text = next(s for s in secs if s['name'] == '.text')
    base, blob = text['address'], data[
        text['offset']:text['offset'] + text['size']]
    hits = []
    i, n = 0, len(blob)
    while i < n - 6:
        two = blob[i:i + 2]
        if two in (b'\xff\x15', b'\xff\x25'):
            disp = struct.unpack_from('<i', blob, i + 2)[0]
            if base + i + 6 + disp == SLOT:
                hits.append((base + i, 'call' if two == b'\xff\x15'
                             else 'jmp'))
            i += 6
            continue
        if two == b'\xe8':
            disp = struct.unpack_from('<i', blob, i + 1)[0]
            if base + i + 5 + disp == ACCESSOR[0]:
                hits.append((base + i, 'e8'))
            i += 5
            continue
        if 0x48 <= blob[i] <= 0x4f and blob[i + 1] in (
                0x8b, 0x8d, 0x3b, 0x39, 0x89) or \
           (blob[i] == 0x48 and blob[i + 1] == 0x8b):
            modrm = blob[i + 2]
            if modrm & 0xc7 == 0x05:
                disp = struct.unpack_from('<i', blob, i + 3)[0]
                if base + i + 7 + disp == SLOT:
                    hits.append((base + i, 'load'))
            i += 1
            continue
        i += 1
    sites = []
    for va, kind in hits:
        lo, hi = extent_of(extents, va)
        sites.append({'va': va, 'kind': kind, 'body': lo})
    return sites


def relocation_addend(data, secs, r_off_want):
    for s in secs:
        if s['name'] != '.rela.dyn':
            continue
        blob = data[s['offset']:s['offset'] + s['size']]
        for i in range(0, len(blob) - 23, 24):
            r_off, r_info, r_add = struct.unpack_from('<QQq', blob, i)
            if r_off == r_off_want:
                return r_add
    raise ValueError(f'no relocation at {r_off_want:#x}')


def decode_location(data, secs, rec_va):
    raw = va_bytes(data, secs, rec_va, 24)
    ln = struct.unpack_from('<Q', raw, 8)[0]
    line, col = struct.unpack_from('<II', raw, 16)
    # the file-path pointer slot is zero in the file; a RELATIVE
    # relocation at the record start supplies the string address
    ptr = relocation_addend(data, secs, rec_va)
    text = va_bytes(data, secs, ptr, ln).decode()
    return {'record': hex(rec_va), 'file': text, 'line': line,
            'column': col}


def analyze(data):
    secs = sections(data)
    extents = fde_extents(data)
    assert slot_target(data, secs) == ACCESSOR[0]
    for va, hexs in BYTE_PINS.items():
        got = va_bytes(data, secs, va, len(hexs) // 2).hex()
        assert got == hexs, f'byte pin at {va:#x}: {got} != {hexs}'
    for va, ln, text in LITERALS:
        got = va_bytes(data, secs, va, ln).decode()
        assert got == text, f'literal at {va:#x}: {got!r}'
    sites = census(data, secs, extents)
    kinds = {}
    for s in sites:
        kinds[s['kind']] = kinds.get(s['kind'], 0) + 1
    assert kinds == {'call': 100}, f'census kinds: {kinds}'
    site_vas = sorted(s['va'] for s in sites)
    assert [int(k, 16) for k in sorted(
        SITE_CONTEXT, key=lambda x: int(x, 16))] == site_vas, \
        'classification keys do not match the census'
    bodies = {}
    for s in sites:
        bodies.setdefault(s['body'], []).append(s)
    consumers = []
    ctx_counts = {}
    for lo in sorted(bodies):
        ext = extent_of(extents, lo)
        rec = body_record(data, secs, ext)
        rows = []
        for s in sorted(bodies[lo], key=lambda x: x['va']):
            ctx = SITE_CONTEXT[hex(s['va'])]
            ctx_counts[ctx] = ctx_counts.get(ctx, 0) + 1
            rows.append({'site': hex(s['va']), 'context': ctx})
        rec['sites'] = rows
        rec['ensure_blocks_in_body'] = cell_refs_in_body(
            data, secs, ext[0], ext[1])
        if hex(lo) in BODY_FILES:
            rec['panic_location_files'] = BODY_FILES[hex(lo)]
        consumers.append(rec)
    loc28 = decode_location(data, secs, LOC_BUILD_MODE_28)
    loc30 = decode_location(data, secs, LOC_BUILD_MODE_30)
    assert loc28['file'] == 'base/src/build_mode.rs'
    assert (loc28['line'], loc28['column']) == (28, 13)
    assert loc30['file'] == 'base/src/build_mode.rs'
    assert (loc30['line'], loc30['column']) == (30, 26)
    return {
        'question': 'What do the 65 bodies that call the lu.rs '
                    'LazyLock accessor 0x1560a40 (GOT slot '
                    '0x64e0b20, 100 call sites) use the returned '
                    'cell +8/+0x10 word pair for, and what does '
                    'that say about the source-level identity of '
                    'the 24-byte value the initializer 0x1568de0 '
                    'builds?',
        'artifact': 'artifacts/node/115/hl-node',
        'artifact_sha256': hashlib.sha256(data).hexdigest(),
        'base_commit': BASE_COMMIT,
        'accessor_slot': {'slot': hex(SLOT),
                          'target': hex(ACCESSOR[0]),
                          'relocation': 'R_X86_64_RELATIVE'},
        'accessor': body_record(data, secs,
                                extent_of(extents, ACCESSOR[0])),
        'accessor_returns': 'rax = *(cell+8), rdx = *(cell+0x10): '
                            'the (data pointer, length) half of '
                            'the cached String; the capacity word '
                            'at cell+0 is not returned',
        'initializer': body_record(data, secs,
                                   extent_of(extents, INIT_FN[0])),
        'initializer_value': {
            'shape': '24-byte String (capacity, pointer, length): '
                     'the sret result is stored (length, pointer, '
                     'length) at 0x1569609..0x156961a',
            'default_before_parse': '(0, 1, 0) stored at '
                                    '0x1568df6..0x1568e10',
            'source_locations': [loc28, loc30],
            'literal_block': [
                {'va': hex(v), 'len': ln, 'text': t}
                for v, ln, t in LITERALS],
            'transform_fn': body_record(
                data, secs, extent_of(extents, TRIM_FN[0])),
            'reading': 'the initializer scans the process '
                       'arguments for a path argument, requires '
                       'it not to end with "/" (the assertion '
                       'panic call at 0x1569663 passes the '
                       'line-28 Location), locates the "/cham/" '
                       'component (a second panic site at '
                       '0x156969b passes the line-30 Location as '
                       'the last argument of a bounds-checked '
                       'operation), and builds the lowercased '
                       'build-mode string (candidate literals '
                       'debug / release / run-client are packed '
                       'beside the assertion). Which exact '
                       'argument and static name: not pinned (see '
                       'boundaries).',
        },
        'census': {'call_sites': len(sites),
                   'consumer_bodies': len(bodies),
                   'direct_e8_sites': 0, 'slot_load_sites': 0,
                   'jmp_sites': 0,
                   'note': 'every site is an indirect call through '
                           'the GOT slot; the body set is '
                           'identical to the census retained by '
                           'PR #2999'},
        'fate': {'sites_where_pair_is_read_as_data': 0,
                 'sites_where_pair_is_discarded': len(sites),
                 'method': 'fall-through fate scan of both '
                           'registers, block-level CFG walk '
                           'inside each body, and manual reading '
                           'of every flagged exception; no site '
                           'dereferences the pointer, compares or '
                           'bounds-checks the length, passes the '
                           'pair to a callee, or stores it'},
        'context_counts': ctx_counts,
        'context_legend': CONTEXT_LEGEND,
        'consumers': consumers,
        'relation_to_pr_2999': 'no contradiction: identical '
                               'census (100 sites, same 65 '
                               'bodies), identical accessor and '
                               'initializer pins. This packet '
                               'refines two points #2999 left '
                               'open: the 24-byte value is a '
                               'String (the word the accessor '
                               'skips at cell+0 is its capacity), '
                               'and the initializer belongs to '
                               'base/src/build_mode.rs',
        'boundaries': [
            'the exact command-line argument the initializer '
            'selects, and the source name of the LazyLock static '
            'and its getter, are not pinned: no Location inside '
            'the initializer names the static',
            "whether wrapper a's kind-1 arm is ever selected at "
            'run time stays open, as PR #2969 left it',
            'the fate classification is a static result about '
            'these 100 sites; the inlined ensure blocks in 19 of '
            'the 65 bodies pass only the cell address to the '
            'once machinery and likewise never load the value '
            'words',
        ],
    }


def objdump_body(lo, hi):
    out = subprocess.run(
        ['objdump', '-d', f'--start-address={lo:#x}',
         f'--stop-address={hi:#x}', 'artifacts/node/115/hl-node'],
        cwd=ROOT, capture_output=True, text=True).stdout
    lines = out.splitlines()
    lines[0] = '<authenticated-node115>:     file format ' \
               'elf64-x86-64'
    return '\n'.join(lines) + '\n'


def parse_insns(export):
    import re
    out = []
    for line in export.splitlines():
        m = re.match(r'\s+([0-9a-f]+):\t', line)
        if m:
            out.append((int(m.group(1), 16), line))
    return out


def windows(payload):
    chunks = []
    for c in payload['consumers']:
        lo, hi = int(c['start'], 16), int(c['end'], 16)
        insns = parse_insns(objdump_body(lo, hi))
        by_va = {va: n for n, (va, _) in enumerate(insns)}
        for s in c['sites']:
            sva = int(s['site'], 16)
            idx = by_va[sva]
            chunks.append(f"# site {s['site']} body {c['start']} "
                          f"context {s['context']}")
            for va, line in insns[max(0, idx - 10):idx + 19]:
                mark = '>>> ' if va == sva else '    '
                chunks.append(mark + line.strip())
            chunks.append('')
    return '\n'.join(chunks) + '\n'


def frames(payload):
    out = subprocess.run(['objdump', '--dwarf=frames',
                          'artifacts/node/115/hl-node'],
                         cwd=ROOT, capture_output=True,
                         text=True).stdout
    want = {int(c['start'], 16) for c in payload['consumers']}
    want |= {ACCESSOR[0], INIT_FN[0], TRIM_FN[0]}
    import re
    lines = []
    for line in out.splitlines():
        m = re.search(r'pc=0*([0-9a-f]+)\.\.', line)
        if m and int(m.group(1), 16) in want:
            lines.append(line)
    return '\n'.join(lines) + '\n'


def generate(binary, outdir):
    data = Path(binary).read_bytes()
    payload = analyze(data)
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    files = {
        'records.json': json.dumps(payload, indent=1) + '\n',
        'accessor.objdump.txt': objdump_body(*ACCESSOR),
        'init_fn.objdump.txt': objdump_body(*INIT_FN),
        'consumer-windows.txt': windows(payload),
        'frames.txt': frames(payload),
    }
    for name, text in files.items():
        (outdir / name).write_text(text)
    manifest = []
    for name in sorted(files):
        digest = hashlib.sha256(
            (outdir / name).read_bytes()).hexdigest()
        manifest.append(f'{digest}  {name}')
    (outdir / 'MANIFEST.sha256').write_text(
        '\n'.join(manifest) + '\n')
    return payload


def main():
    if len(sys.argv) > 1 and sys.argv[1] == 'generate':
        generate(TARGET, PACKET)
        print('packet regenerated')
        return
    data = TARGET.read_bytes()
    assert hashlib.sha256(data).hexdigest() == SHA
    payload = analyze(data)
    retained = json.loads((PACKET / 'records.json').read_text())
    assert payload == retained, 'records.json does not match the ' \
                                'artifact-derived payload'
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        generate(TARGET, td)
        for name in ('accessor.objdump.txt', 'init_fn.objdump.txt',
                     'consumer-windows.txt', 'frames.txt',
                     'MANIFEST.sha256'):
            assert (Path(td) / name).read_bytes() == \
                (PACKET / name).read_bytes(), \
                f'{name} regeneration differs'
    print('OK: census, pins, classification and packet exports '
          'all re-derived from the artifact')


if __name__ == '__main__':
    main()
