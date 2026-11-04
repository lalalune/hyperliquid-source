#!/usr/bin/env python3
"""Trace the node 115 cursor searches of the forward-2 sorted set.

The sorted-set read-side packet (#2493) completed the census of
the forward-2 B-tree layout's standalone readers: among FDEs of
at most 350 bytes carrying the walk signature there are exactly
sixteen - three byte-identical find clones, one boolean
contains, two byte-identical cursor searches, and ten remove
bodies.  That packet traced find, contains and remove and left
the two cursor searches as hash-pinned boundaries, recording
only that they return a four-qword record to their callers.
This packet owns the two cursor searches.

A cursor search (0x1d65920 and its byte-identical clone
0x35bdd20, 143 bytes each) is a pure search over the same node
layout the read-side packet established - keys from node + 0x8,
count word at node + 0x62, child edges from node + 0x68.  The
root node and the height arrive as separate arguments (rsi,
rdx), the probe key arrives by pointer (rcx) and is
dereferenced once, and the result is written through the
out pointer (rdi, also returned in rax) as a four-qword
record:

    +0x00  flag      0 when the key was found, 1 when not
    +0x08  node      the node where the search ended
    +0x10  height    the height remaining at that node
                     (0 at a leaf; on a miss always 0)
    +0x18  position  on a hit, the index of the equal key;
                     on a miss, the insertion index - the
                     first key greater than the probe, or
                     the node count when all keys are less

The body contains no call and no store other than the four
record stores; it never reads the handle total.

Callers.  The clone at 0x1d65920 has exactly two direct call
sites, both in the caller FDE 0x23795c0..0x2379b6b: two loops
that probe successive computed keys (a record field times
0x2710 plus the loop index) against the set whose root/height
pair the caller loads from its argument + 0x18.  At both
sites the first and only use of the record is a byte test of
the flag (cmpb $0x0 at the pinned instruction start after
each call): a miss breaks the loop, a hit advances it - an
existence scan.  The clone at 0x35bdd20 has exactly one
direct call site, in FDE 0x2667140..0x2668202, which probes
one key against the set handle embedded at its record
+ 0x290 and first uses the record as a dword compare of the
flag against 1 (a miss falls through, a hit branches away).
Neither caller ever reads the record's node, height or
position fields after a clone call: in caller A the only
reads of the node/position stack slots in the whole FDE are
four pinned loads inside two windows whose records were
written by the variant search 0x35bd660 (same algorithm over
a shifted node layout, count word at + 0xba and child edges
at + 0xc0; the variants are shared helpers with further call
sites in other clusters, and only their three sites inside
these two caller FDEs are pinned here), and the height slot
is never referenced; in
caller B the node/height/position slots are only ever
stored to, never read, anywhere in the FDE.  No caller calls
both clones, and the bodies are byte-identical, so no caller
can distinguish them behaviourally.

Every cited byte is pinned and validated as a native
instruction start; the call censuses are re-derived from raw
E8/E9 scans, each site re-validated as an instruction start
inside its containing FDE, and the R_X86_64_RELATIVE census
is re-derived from .rela.dyn (neither clone has a slot).
"""

import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from artifacts import ROOT
from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import decode_export as _foundation_decode

TARGET = ROOT / 'artifacts/node/115/hl-node'
PACKET = (ROOT / 'research/work-items'
          / 'RE-006-node115-cursor-search')
EXPECTED_SHA256 = (
    'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301')
TEXT_FILE_OFFSET_DIFFERENCE = 0x1000
CURSOR_SHA256 = (
    '4f7a495bf20876b0606bf10b74cbbce7d6b8a1ebc5'
    'b55e2be63d6f7bac1297ac')

# Byte pins of the cursor-search body, by offset from the body
# start; identical for both clones because the bodies are
# byte-identical (asserted in analyze()).
_PIN_OFFSETS = {
    0x00: '4889f8',        # out pointer -> rax (return value)
    0x03: '488b09',        # key value = *key_ptr
    0x06: '440fb74662',    # loop head: count word at node + 0x62
    0x25: '483b4cfe10',    # key compare at + 0x10, scale 8
    0x2a: '410f97c2',      # seta %r10b (three-way, high half)
    0x2e: '4180da00',      # sbb $0x0, %r10b (three-way, low)
    0x20: '4d85c9',        # scan: keys remaining test
    0x60: '4c89c7',        # exhausted: position = count
    0x6c: '488b74fe68',    # descend: child edge at + 0x68
    0x76: '31c9',          # found: flag = 0
    0x78: '48897008',      # record node at + 0x8
    0x7c: '48895010',      # record height at + 0x10
    0x80: '48897818',      # record position at + 0x18
    0x84: '488908',        # record flag at + 0x0
    0x88: 'b901000000',    # miss: flag = 1
}


def _pins(base):
    return {base + offset: raw for offset, raw in _PIN_OFFSETS.items()}


OWNERS = {
    'cursor_search_a': {
        'range': (0x1d65920, 0x1d659af),
        'sha256': CURSOR_SHA256,
        'pins': _pins(0x1d65920),
        'calls': {},
    },
    'cursor_search_b': {
        'range': (0x35bdd20, 0x35bddaf),
        'sha256': CURSOR_SHA256,
        'pins': _pins(0x35bdd20),
        'calls': {},
    },
}

BOUNDARIES = {
    'caller_a': {
        'range': (0x23795c0, 0x2379b6b),
        'sha256': 'a8bd71e4ae8f0e119d89a42f4362cb11c3f8241e'
                  'f53fdf0ef6609f5bc1d66a82',
    },
    'caller_b': {
        'range': (0x2667140, 0x2668202),
        'sha256': '63f3519ea3be1917603aad0fba34df41e08416d72020c79633a'
                  'a35c1f3aac3e2',
    },
    'variant_search_a': {
        'range': (0x35bd660, 0x35bd6f2),
        'sha256': '3da45a31a814e5cb8c3b77323c8c550b760ad8a76aadc94048d'
                  '13e54a3c16950',
    },
    'variant_search_b': {
        'range': (0x35bd800, 0x35bd892),
        'sha256': '100afb1aa917741ca80b4efc1505a123a89cce43'
                  '457beb3eaa47b5b75437191b',
    },
    'forward_2': {
        'range': (0x51d1b00, 0x51d1c5f),
        'sha256': 'b94dcaca1a7e4fadeb833f24fa47bd30eb9bab8b4'
                  '900a14b314e6b3f19eff3c6',
    },
    'node_insert': {
        'range': (0x4c49f90, 0x4c4a737),
        'sha256': 'b56c5f0edade1f99c0dc818624d46c29912660b712'
                  'b382cdd0cfb206c861f265',
    },
}

# Decoded windows inside the caller FDEs, with their own pins.
WINDOWS = {
    'caller_a_loop_a': {
        'range': (0x23795f3, 0x2379657),
        'pins': {
            0x23795f3: '4c8b6e18',      # handle pair = arg + 0x18
            0x23795fd: '4c8d7c2420',    # key slot = rsp + 0x20
            0x237962e: '4889442420',    # computed key -> key slot
            0x2379633: '498b7500',      # root = pair + 0x0
            0x237963c: '498b5508',      # height = pair + 0x8
            0x2379640: '488d7c2468',    # out record = rsp + 0x68
            0x2379645: '4c89f9',        # key pointer argument
            0x237964d: '807c246800',    # first use: flag byte test
            0x2379654: '48ffc5',        # hit: advance loop index
        },
        'calls': {0x2379648: 0x1d65920},
    },
    'caller_a_loop_b': {
        'range': (0x2379899, 0x2379903),
        'pins': {
            0x2379899: '4c8d742418',    # key slot = rsp + 0x18
            0x23798d3: '4889442418',    # computed key -> key slot
            0x23798d8: '498b7500',      # root = pair + 0x0
            0x23798e1: '498b5508',      # height = pair + 0x8
            0x23798e5: '488d7c2468',    # out record = rsp + 0x68
            0x23798ea: '4c89f1',        # key pointer argument
            0x23798f2: '807c246800',    # first use: flag byte test
            0x23798f9: '48ffc5',        # hit: advance loop index
        },
        'calls': {0x23798ed: 0x1d65920},
    },
    'caller_a_variant_a': {
        'range': (0x2379725, 0x2379765),
        'pins': {
            0x2379725: '498bb7f8000000',  # variant root = rec + 0xf8
            0x2379731: '498b9700010000',  # variant height = + 0x100
            0x2379738: '488d7c2468',    # out record = rsp + 0x68
            0x237973d: '488d4c2420',    # key pointer argument
            0x2379747: '837c246801',    # variant flag test (== 1)
            0x237974e: '488b442470',    # node field load (variant's)
            0x2379753: '488b8c2480000000',  # position load (variant's)
        },
        'calls': {0x2379742: 0x35bd660},
    },
    'caller_a_variant_b': {
        'range': (0x237999a, 0x23799e3),
        'pins': {
            0x237999a: '488bb2f8000000',  # variant root = rec + 0xf8
            0x23799af: '488b9000010000',  # variant height = + 0x100
            0x23799b6: '488d7c2468',    # out record = rsp + 0x68
            0x23799bb: '488d4c2418',    # key pointer argument
            0x23799c5: '837c246801',    # variant flag test (== 1)
            0x23799cc: '488b442470',    # node field load (variant's)
            0x23799d1: '488b8c2480000000',  # position load (variant's)
        },
        'calls': {0x23799c0: 0x35bd660},
    },
    'caller_b_search': {
        'range': (0x2667b5d, 0x2667b9a),
        'pins': {
            0x2667b5d: '488b442410',    # key source = rsp + 0x10
            0x2667b62: '4889442450',    # key -> key slot rsp + 0x50
            0x2667b67: '498bb790020000',  # root = record + 0x290
            0x2667b73: '498b9798020000',  # height = record + 0x298
            0x2667b7a: '488dbc2440010000',  # out = rsp + 0x140
            0x2667b82: '488d4c2450',    # key pointer argument
            0x2667b8c: '83bc244001000001',  # first use: flag == 1
        },
        'calls': {0x2667b87: 0x35bdd20},
    },
    'caller_b_variant': {
        'range': (0x2667aa0, 0x2667ad3),
        'pins': {
            0x2667aa0: '498bb7404b0000',  # variant root = + 0x4b40
            0x2667aac: '498b97484b0000',  # variant height = + 0x4b48
            0x2667ab3: '488dbc2440010000',  # out = rsp + 0x140
            0x2667abb: '488d4c2450',    # key pointer argument
            0x2667ac5: '80bc244001000000',  # variant flag test (== 0)
        },
        'calls': {0x2667ac0: 0x35bd800},
    },
}

# Exact expected direct-call sites (site -> containing FDE start)
# for the two cursor searches.
EXPECTED_SITES = {
    0x1d65920: {   # cursor_search_a
        0x2379648: 0x23795c0, 0x23798ed: 0x23795c0,
    },
    0x35bdd20: {   # cursor_search_b
        0x2667b87: 0x2667140,
    },
}

# The two variant searches are shared helpers for their own
# layouts, with further call sites in other clusters; the
# packet pins only their sites inside its two caller FDEs.
VARIANT_TARGETS = (0x35bd660, 0x35bd800)
VARIANT_CALLER_SITES = {
    0x35bd660: {   # variant_search_a, within the caller FDEs
        0x2379742: 0x23795c0, 0x23799c0: 0x23795c0,
    },
    0x35bd800: {   # variant_search_b, within the caller FDEs
        0x2667ac0: 0x2667140,
    },
}
CALLER_FDES = (0x23795c0, 0x2667140)

# After every search call site the result is first consumed by a
# flag test at exactly this instruction start in the caller.
FLAG_TESTS = {
    0x2379648: (0x237964d, '807c246800'),      # cmpb $0x0, flag
    0x23798ed: (0x23798f2, '807c246800'),      # cmpb $0x0, flag
    0x2667b87: (0x2667b8c, '83bc244001000001'),  # cmpl $0x1, flag
    0x2379742: (0x2379747, '837c246801'),      # variant: cmpl $0x1
    0x23799c0: (0x23799c5, '837c246801'),      # variant: cmpl $0x1
    0x2667ac0: (0x2667ac5, '80bc244001000000'),  # variant: cmpb $0x0
}

# Record-slot read census inside each caller FDE.  The record
# sits at a fixed rsp displacement; for every field slot the
# decoded reads (any instruction that reads the slot - loads
# and compares; address computations and stores excluded) must
# be exactly the listed set.  In caller A the node/position
# reads belong to the variant windows; the clone records'
# fields are read nowhere.
SLOT_CENSUS = {
    'caller_a': {
        'fde_start': 0x23795c0,
        'slots': {
            0x68: [0x237964d, 0x2379747, 0x23798f2, 0x23799c5],
            0x70: [0x237974e, 0x23799cc],
            0x78: [],
            0x80: [0x2379753, 0x23799d1],
        },
    },
    'caller_b': {
        'fde_start': 0x2667140,
        'slots': {
            0x140: [0x2667ac5, 0x2667b8c],
            0x148: [],
            0x150: [],
            0x158: [],
        },
    },
}

FIND_FAMILY = (0x51d1a80, 0x243ca40, 0x39007b0)
CURSOR_FAMILY = (0x1d65920, 0x35bdd20)
REMOVE_FAMILY_273 = (
    0x51d5010, 0x51d6a30, 0x51d7780, 0x51d87e0,
    0x243eea0, 0x243efc0, 0x243fb20,
    0x3901bf0, 0x3902c90, 0x3903c70,
)
SMALL_READER_SET = frozenset(
    FIND_FAMILY + CURSOR_FAMILY + (0x243d260,) + REMOVE_FAMILY_273)
EXPECTED_WALK_SIGNATURE_COUNT = 126

COUNT_RE = re.compile(r'movzwl\s+0x62\(%r')
CHILD_RE = re.compile(r'mov\s+0x68\(%r\w+,\s?%r\w+,8\)')
KEYCMP_RE = re.compile(
    r'cmp\s+0x10\(%r\w+,\s?%r\w+,8\)|cmp\s+%r\w+,\s?0x10\(%r\w+,'
    r'\s?%r\w+,8\)')
SETA_RE = re.compile(r'seta\s')
SBB_RE = re.compile(r'sbb\s')


class PacketError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise PacketError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def hx(value):
    return f'0x{value:x}'


def authenticate(data):
    digest = sha(data)
    require(digest == EXPECTED_SHA256,
            f'Artifact hash mismatch: {digest}')
    return digest


_LINE = re.compile(r'^\s+([0-9a-f]+):\t[0-9a-f ]+\t(.*)$')


def decode_body(data, start, end):
    """objdump-decode one body from a temp copy of the data.

    Returns (rows, texts): rows maps each native instruction
    start to its full bytes (via the shared foundation decoder,
    which merges objdump's wrapped byte rows and requires the
    decode to tile the body exactly); texts maps each start to
    its mnemonic text.
    """
    body = data[start - TEXT_FILE_OFFSET_DIFFERENCE:
                end - TEXT_FILE_OFFSET_DIFFERENCE]
    with tempfile.NamedTemporaryFile(
            suffix='.bin', delete=False) as handle:
        handle.write(body)
        path = handle.name
    try:
        output = subprocess.check_output([
            'objdump', '-D', '-b', 'binary', '-m', 'i386:x86-64',
            f'--adjust-vma={start:#x}', path,
        ], text=True)
    finally:
        os.unlink(path)
    rows = _foundation_decode(output, start, end, body)
    texts = {}
    for line in output.splitlines():
        match = _LINE.match(line)
        if match:
            texts[int(match.group(1), 16)] = match.group(2).strip()
    return rows, texts


def check_pins(name, spec, rows):
    for address, expected in spec.get('pins', {}).items():
        raw = rows.get(address)
        require(raw is not None,
                f'{name} pin is not an instruction start: '
                f'{hx(address)}')
        require(raw == bytes.fromhex(expected),
                f'{name} pin bytes changed at {hx(address)}: '
                f'{raw.hex()} != {expected}')
    for address, target in spec.get('calls', {}).items():
        raw = rows.get(address)
        require(raw is not None,
                f'{name} call is not an instruction start: '
                f'{hx(address)}')
        require(raw[0] == 0xE8,
                f'{name} call opcode changed at {hx(address)}')
        displacement = struct.unpack('<i', raw[1:5])[0]
        require(address + 5 + displacement == target,
                f'{name} call target changed at {hx(address)}')


def walk_signature(texts):
    joined = '\n'.join(texts.values())
    return {
        'count': bool(COUNT_RE.search(joined)),
        'child': bool(CHILD_RE.search(joined)),
        'keycmp': bool(KEYCMP_RE.search(joined)),
        'seta_sbb': bool(SETA_RE.search(joined)
                         and SBB_RE.search(joined)),
    }


def raw_candidates(text_bytes, text_va):
    """FDE-candidate addresses from raw pattern scans of .text.

    Mirrors the read-side packet's census: word accesses at
    displacement 0x62, scale-8 loads at displacement 0x68, and
    scale-8 compares at displacement 0x8 / 0x10.  Raw hits are
    only a superset; every candidate is instruction-validated
    by decoding its FDE.
    """
    raw = set()
    for match in re.finditer(rb'\x0f\xb7|\x66[\x8b\x89\x83\x39\x3b]',
                             text_bytes):
        i = match.start()
        if i + 4 >= len(text_bytes):
            continue
        modrm = text_bytes[i + 2]
        mod, rm = modrm >> 6, modrm & 7
        if mod == 1:
            disp = text_bytes[i + 4] if rm == 4 else text_bytes[i + 3]
            if disp == 0x62:
                raw.add(text_va + i)
    for match in re.finditer(rb'[\x48\x4c\x49\x4d][\x8b\x39\x3b]',
                             text_bytes):
        i = match.start()
        if i + 5 >= len(text_bytes):
            continue
        modrm = text_bytes[i + 2]
        if ((modrm >> 6) == 1 and (modrm & 7) == 4
                and (text_bytes[i + 3] >> 6) == 3
                and text_bytes[i + 4] == 0x68):
            raw.add(text_va + i)
    for match in re.finditer(rb'[\x48\x4c][\x3b\x39]', text_bytes):
        i = match.start()
        if i + 5 >= len(text_bytes):
            continue
        modrm = text_bytes[i + 2]
        if ((modrm >> 6) in (1, 2) and (modrm & 7) == 4
                and (text_bytes[i + 3] >> 6) == 3):
            if (modrm >> 6) == 1 and text_bytes[i + 4] in (0x08, 0x10):
                raw.add(text_va + i)
    return raw


def load_fdes(data):
    summary, fdes, gaps = fde_extents(data)
    starts = sorted(fde['start'] for fde in fdes)
    by_start = {fde['start']: fde for fde in fdes}
    return summary, fdes, starts, by_start


def find_fde(starts, by_start, va):
    import bisect
    index = bisect.bisect_right(starts, va) - 1
    if index < 0:
        return None
    fde = by_start[starts[index]]
    return fde if fde['start'] <= va < fde['end'] else None


def call_site_census(data, starts, by_start):
    """Every direct E8 site for every target of interest, plus
    an E9 (tail-jump) census for the two owners.

    Each site is re-validated as an instruction start inside
    its containing FDE (decoded once per distinct caller).
    """
    secs = sections(data)
    text = next(s for s in secs if s['name'] == '.text')
    text_bytes = data[text['offset']:text['offset'] + text['size']]
    text_va = text['address']
    targets = set(EXPECTED_SITES) | set(VARIANT_TARGETS)
    sites = {target: {} for target in targets}
    tail_sites = {target: [] for target in CURSOR_FAMILY}
    for opcode, store in ((0xE8, sites), (0xE9, tail_sites)):
        for match in re.finditer(bytes([opcode]), text_bytes):
            i = match.start()
            if i + 5 > len(text_bytes):
                continue
            displacement = struct.unpack_from(
                '<i', text_bytes, i + 1)[0]
            target = text_va + i + 5 + displacement
            if opcode == 0xE8 and target in targets:
                site = text_va + i
                fde = find_fde(starts, by_start, site)
                require(fde is not None,
                        f'Call site outside any FDE: {hx(site)}')
                store[target][site] = fde['start']
            elif opcode == 0xE9 and target in tail_sites:
                tail_sites[target].append(text_va + i)
    decoded = {}

    def caller_decode(start):
        if start not in decoded:
            fde = by_start[start]
            decoded[start] = decode_body(data, start, fde['end'])
        return decoded[start]

    for target, site_map in sites.items():
        for site, caller in site_map.items():
            raw = caller_decode(caller)[0].get(site)
            require(raw is not None,
                    f'Call site is not an instruction start: '
                    f'{hx(site)}')
            require(raw[0] == 0xE8,
                    f'Call site opcode changed: {hx(site)}')
            displacement = struct.unpack('<i', raw[1:5])[0]
            require(site + 5 + displacement == target,
                    f'Call site target changed: {hx(site)}')
    for target, expected in EXPECTED_SITES.items():
        require(sites[target] == expected,
                f'Call sites changed for {hx(target)}: '
                f'{sites[target]} != {expected}')
    for target, expected in VARIANT_CALLER_SITES.items():
        within = {site: caller for site, caller
                  in sites[target].items() if caller in CALLER_FDES}
        require(within == expected,
                f'Variant call sites within the caller FDEs '
                f'changed for {hx(target)}: {within} != {expected}')
    for target, found in tail_sites.items():
        require(not found,
                f'Unexpected tail-jump sites for {hx(target)}: '
                f'{found}')
    return sites, caller_decode


def flag_tests(data, caller_decode):
    """Pin the flag test consuming each search call's result."""
    checked = {}
    all_sites = dict(EXPECTED_SITES)
    all_sites.update(VARIANT_CALLER_SITES)
    for site, (test_va, expected) in FLAG_TESTS.items():
        caller = None
        for target, site_map in all_sites.items():
            if site in site_map:
                caller = site_map[site]
        require(caller is not None, f'Unknown search site {hx(site)}')
        raw = caller_decode(caller)[0].get(test_va)
        require(raw is not None,
                f'Flag test is not an instruction start: '
                f'{hx(test_va)}')
        require(raw == bytes.fromhex(expected),
                f'Flag test bytes changed at {hx(test_va)}')
        checked[hx(site)] = hx(test_va)
    return checked


_STORE_RE = re.compile(
    r'^mov\w*\s+[^,]+,\s*0x[0-9a-f]+\(%rsp\)$')


def slot_reads(data, caller_decode):
    """Census of reads of the cursor-record stack slots inside
    each caller FDE: per slot, the sorted instruction starts
    whose text reads the slot (a load or compare naming it as
    a source; lea address computations and stores excluded).
    """
    report = {}
    for name, spec in SLOT_CENSUS.items():
        rows, texts = caller_decode(spec['fde_start'])
        found = {}
        for slot, expected in spec['slots'].items():
            needle = f'{slot:#x}(%rsp)'
            reads = []
            for address, text in texts.items():
                if needle not in text:
                    continue
                if text.startswith('lea'):
                    continue
                if _STORE_RE.match(text):
                    continue
                reads.append(address)
            reads.sort()
            require(reads == expected,
                    f'Caller slot reads changed for {name} '
                    f'slot {hx(slot)}: {reads} != {expected}')
            found[hx(slot)] = [hx(v) for v in reads]
        report[name] = found
    return report


def rela_census(data):
    """R_X86_64_RELATIVE entries of .rela.dyn: offset -> addend,
    plus the inverse map addend -> [offsets]."""
    relas = {}
    for section in sections(data):
        if section['name'] == '.rela.dyn':
            blob = data[section['offset']:
                        section['offset'] + section['size']]
            for cursor in range(0, len(blob), 24):
                offset, info, addend = struct.unpack_from(
                    '<QQq', blob, cursor)
                if info & 0xFFFFFFFF == 8:  # R_X86_64_RELATIVE
                    relas[offset] = addend
    by_addend = {}
    for offset, addend in relas.items():
        by_addend.setdefault(addend, []).append(offset)
    return relas, by_addend


def walk_census(data, starts, by_start):
    secs = sections(data)
    text = next(s for s in secs if s['name'] == '.text')
    text_bytes = data[text['offset']:text['offset'] + text['size']]
    candidates = set()
    for va in raw_candidates(text_bytes, text['address']):
        fde = find_fde(starts, by_start, va)
        if fde is not None:
            candidates.add(fde['start'])
    carriers = {}
    for start in sorted(candidates):
        fde = by_start[start]
        signature = walk_signature(
            decode_body(data, start, fde['end'])[1])
        if all(signature.values()):
            carriers[start] = fde['end'] - start
    require(len(carriers) == EXPECTED_WALK_SIGNATURE_COUNT,
            f'Walk-signature census changed: {len(carriers)} != '
            f'{EXPECTED_WALK_SIGNATURE_COUNT}')
    small = {start for start, size in carriers.items() if size <= 350}
    require(small == set(SMALL_READER_SET),
            f'Small reader census changed: '
            f'{sorted(hx(s) for s in small)}')
    return carriers


def hash_families(data, fdes):
    families = {}
    for fde in fdes:
        body = data[fde['start'] - TEXT_FILE_OFFSET_DIFFERENCE:
                    fde['end'] - TEXT_FILE_OFFSET_DIFFERENCE]
        families.setdefault(sha(body), []).append(fde['start'])
    cursor_family = sorted(families[CURSOR_SHA256])
    require(cursor_family == sorted(CURSOR_FAMILY),
            f'Cursor family changed: {cursor_family}')
    variant_a = sorted(
        families[BOUNDARIES['variant_search_a']['sha256']])
    require(variant_a == [0x35bd660],
            f'Variant A family changed: {variant_a}')
    variant_b = sorted(
        families[BOUNDARIES['variant_search_b']['sha256']])
    require(variant_b == [0x35bd800],
            f'Variant B family changed: {variant_b}')
    return {
        'cursor_search': [hx(v) for v in cursor_family],
        'variant_search_a': [hx(v) for v in variant_a],
        'variant_search_b': [hx(v) for v in variant_b],
    }


def analyze(data, binary):
    # No whole-artifact authentication here: generate() authenticates
    # first, and analyze() reports the first specific check a mutated
    # byte fails (the counterfactual tests rely on that order).
    digest = sha(data)
    summary, fdes, starts, by_start = load_fdes(data)

    owners = {}
    owner_bodies = {}
    for name, spec in OWNERS.items():
        start, end = spec['range']
        fde = by_start.get(start)
        require(fde is not None and fde['end'] == end,
                f'Owner FDE changed: {name}')
        body = data[start - TEXT_FILE_OFFSET_DIFFERENCE:
                    end - TEXT_FILE_OFFSET_DIFFERENCE]
        rows, _texts = decode_body(data, start, end)
        check_pins(name, spec, rows)
        require(sha(body) == spec['sha256'],
                f'Owner body hash changed: {name}')
        owner_bodies[name] = body
        owners[name] = {
            'range': [hx(start), hx(end)],
            'size': end - start,
            'sha256': spec['sha256'],
            'pins': {hx(k): v for k, v in spec['pins'].items()},
            'calls': {hx(k): hx(v)
                      for k, v in spec['calls'].items()},
        }
    require(owner_bodies['cursor_search_a']
            == owner_bodies['cursor_search_b'],
            'Cursor clone bodies are not byte-identical')

    boundaries = {}
    for name, spec in BOUNDARIES.items():
        start, end = spec['range']
        fde = by_start.get(start)
        require(fde is not None and fde['end'] == end,
                f'Boundary FDE changed: {name}')
        body = data[start - TEXT_FILE_OFFSET_DIFFERENCE:
                    end - TEXT_FILE_OFFSET_DIFFERENCE]
        require(sha(body) == spec['sha256'],
                f'Boundary body hash changed: {name}')
        boundaries[name] = {
            'range': [hx(start), hx(end)],
            'size': end - start,
            'sha256': spec['sha256'],
        }

    windows = {}
    for name, spec in WINDOWS.items():
        start, end = spec['range']
        rows, _texts = decode_body(data, start, end)
        check_pins(f'window {name}', spec, rows)
        windows[name] = {
            'range': [hx(start), hx(end)],
            'pins': {hx(k): v for k, v in spec['pins'].items()},
            'calls': {hx(k): hx(v)
                      for k, v in spec['calls'].items()},
        }

    sites, caller_decode = call_site_census(data, starts, by_start)
    tests = flag_tests(data, caller_decode)
    slots = slot_reads(data, caller_decode)
    families = hash_families(data, fdes)
    carriers = walk_census(data, starts, by_start)

    relas, by_addend = rela_census(data)
    for name, spec in OWNERS.items():
        start = spec['range'][0]
        require(start not in by_addend,
                f'Unexpected rela slot for {name}')

    call_sites = {}
    for target, site_map in sites.items():
        call_sites[hx(target)] = {
            hx(site): hx(caller)
            for site, caller in sorted(site_map.items())
        }

    counters = {
        'cursor_search_a_call_sites': len(sites[0x1d65920]),
        'cursor_search_b_call_sites': len(sites[0x35bdd20]),
        'cursor_search_call_sites': (
            len(sites[0x1d65920]) + len(sites[0x35bdd20])),
        'variant_search_call_sites': (
            len(sites[0x35bd660]) + len(sites[0x35bd800])),
        'variant_search_caller_sites': (
            len(VARIANT_CALLER_SITES[0x35bd660])
            + len(VARIANT_CALLER_SITES[0x35bd800])),
        'cursor_family_fdes': len(CURSOR_FAMILY),
        'walk_signature_fdes': len(carriers),
        'small_reader_fdes': len(SMALL_READER_SET),
        'flag_tests': len(tests),
        'variant_window_field_reads': (
            len(slots['caller_a']['0x70'])
            + len(slots['caller_a']['0x80'])),
        'clone_record_field_reads': (
            len(slots['caller_b']['0x148'])
            + len(slots['caller_b']['0x150'])
            + len(slots['caller_b']['0x158'])),
    }

    frames = [list(spec['range']) for spec in
              list(OWNERS.values()) + list(BOUNDARIES.values())]
    return {
        'artifact': {
            'sha256': digest,
            'fde_records': summary['fde_records'],
            'unique_fde_starts': len(by_start),
        },
        'owners': owners,
        'boundaries': boundaries,
        'windows': windows,
        'call_sites': call_sites,
        'flag_tests': tests,
        'slot_reads': slots,
        'hash_families': families,
        'rela_slots': {'owners_with_slots': []},
        'counters': counters,
        'frames': frames,
    }


def generate(binary, output):
    data = Path(binary).read_bytes()
    authenticate(data)
    report = analyze(data, binary)
    output.mkdir(parents=True, exist_ok=True)
    raw = subprocess.check_output(
        ['readelf', '-wf', str(binary)], text=True)
    ranges = [spec['range'] for spec in
              list(OWNERS.values()) + list(BOUNDARIES.values())]
    lines = [
        line.replace(str(binary), '<authenticated-node115>')
        for line in raw.splitlines()
        if any(f'pc={start:016x}..{end:016x}' in line
               for start, end in ranges)
    ]
    require(len(lines) == len(report['frames']),
            'Retained readelf frame changed')
    (output / 'frames.txt').write_text('\n'.join(lines) + '\n')
    exports = {}
    for name, spec in OWNERS.items():
        start, end = spec['range']
        asm = subprocess.check_output([
            'objdump', '-d', '-M', 'intel', '--insn-width=16',
            f'--start-address={start:#x}',
            f'--stop-address={end:#x}',
            str(binary),
        ], text=True)
        safe_name = f'{name}_full_body_{start:x}_{end:x}_objdump.txt'
        rendered = asm.replace(str(binary), '<authenticated-node115>')
        (output / safe_name).write_text(rendered)
        exports[name] = {
            'full_body': {
                'file': safe_name,
                'sha256': sha(rendered.encode()),
                'range': [hx(start), hx(end)],
            },
        }
    report['source_exports'] = exports
    (output / 'records.json').write_text(
        json.dumps(report, indent=2) + '\n')
    return report


def main():
    binary = Path(sys.argv[1]) if len(sys.argv) > 1 else TARGET
    output = Path(sys.argv[2]) if len(sys.argv) > 2 else PACKET
    generate(binary, output)
    print(output / 'records.json')


if __name__ == '__main__':
    main()
