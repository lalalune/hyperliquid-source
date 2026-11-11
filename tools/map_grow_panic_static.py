#!/usr/bin/env python3
"""Settle the panic side of the S-map grow at 0x4742aa0.

The map-grow packet (tools/map_grow_static.py) reconstructed what the
grow at 0x4742aa0 does on the byte level and recorded, as its closing
open question, what a panic does to the records its in-place fixup marks
0x80.  The question decomposes into three checks, and this tool pins all
three against the boundary bodies, the landing pads and the frame
records:

(a) A landing pad in the grow's own frame.  The grow's FDE at 0xefd040
refers to the cluster-shared CIE at 0xca6ed8, whose augmentation string
is exactly 'zR': it declares neither a personality routine ('P') nor an
LSDA encoding ('L'), and the FDE carries no LSDA pointer.  It is the
only FDE covering 0x4742aa0..0x4743347 and no other FDE overlaps the
range, so no cleanup action of any kind runs in this frame during an
unwind.

(b) Reachability of the marked state by a panic.  The failure tail at
0x4743316 (panic formatter call at 0x4743329, allocation-error call at
0x4743337) is the body's only panic origin, and it is reachable from
exactly four branch sources, all pinned below: the three entry/sizing
checks that jump to the failure stub at 0x4742bd1 (0x4742ab7,
0x4742b5b, 0x4742b9f), the stub's own dispatch branch at 0x4742bd3, and
the null-allocation branch at 0x4742bfb, which lands at 0x474329b and
from there reaches only the tail's allocation-error half.  A raw scan
of the body's bytes for every rel8/rel32 branch to the stub or the
tail finds exactly those sites.  All of them sit before the path split:
no mark exists when any of them can fire, and after the split the
in-place path's only callee is memmove through its slot (0x4742f33)
while the fresh rehash loop and the in-place scan contain no call at
all (the call inventory is the six slot calls pinned below, owned by
the map-grow packet).  The marked state and a panic raised in or
through this frame therefore never coexist, so no drop owner is
needed.  The panic itself is not a process-level noreturn here: the
formatter at 0x1680e80 hands its message and location to the panic
implementation shim at 0x5c826c0 through slot 0x64e1f30, the cluster's
cleanup frames run under a live Rust personality (0x5cad7b0, bound by
the RELATIVE relocation in slot 0x64efa28 of the 'zPLR' CIE), and when
the unwind crosses the grow's frame it reaches the caller 0x474b620,
whose LSDA assigns the grow call site (0x474ba06) the pad at 0x474ba2e
-- which drops only the caller's own pending value and buffer.

(c) Why the sibling grow at 0x4743990 is different.  The sibling's
rehash calls its seeded SipHash callee at 0x4744490 once per record in
both paths (fresh call at 0x4743be4, in-place call at 0x4743d5d; the
callee is identified by the SipHash initial constants it mixes from
0x4522f0 and 0x4511c0).  A per-record call inside the marking window is
exactly what forces landing pads, and its LSDA (at 0x34c4f8) wires
them: the fresh-path range 0x4743bdf..0x4743be9 lands at 0x4743fc0,
which calls the free-pending-allocation helper at 0x4742680 with the
stack descriptor; the in-place range 0x4743d58..0x4743d62 lands at
0x4743fd5, which calls the marked-record cleanup at 0x47425c0; and the
cleanup call itself (range 0x4743fd8..0x4743fe2) lands at 0x4743fea,
the LSDA's only action-bearing pad, which calls the panic-in-cleanup
guard through slot 0x64df4c0 (body 0x1680cab, bound to the string
"panic in a destructor during cleanup").  This grow inlines FNV-1a in
both loops and calls nothing per record, so its frame needed no
personality and carries no LSDA.
"""
import hashlib
import json
import struct
import subprocess
import tempfile
from pathlib import Path

from elf_index import sections
from fde_extents import eh_frame_records
from foundation_millis import decode_export, require

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

OWNERS = {
    'map_grow': (0x4742aa0, 0x4743347,
                 'dddec9130ff0171ebc861ae72351d0e4d846e76cbbd9811c5bed'
                 '5d56d0ac4a67'),
    'sibling_grow': (0x4743990, 0x4743ff0,
                     'eeac52dec8e29f0c1c3084ba80545a9b551b44c69b974a60'
                     'f2220d564f961eef'),
    'marked_cleanup': (0x47425c0, 0x4742676,
                       'a27501e59ce2fa4fc610ed13d3da63c01ea578963bec73'
                       'd983d86b584a3e49e4'),
    'pad_helper': (0x4742680, 0x47426d1,
                   'da0038dfd88d2675f82db29375445a91dc3116e140ab87ae0'
                   '2e1c6eac7fb3401'),
}
BOUNDARIES = {
    'prev_body': (0x4742850, 0x4742958,
                  '19805cd457f128d16f1325f9b077f925f5dde1d5246cb637'
                  '4881910ed5b03288'),
    'whole_map_drop': (0x4742960, 0x4742a93,
                       '1aae44edc7f846da821541c9455706506403ae72981926'
                       'a7927dd0aa0a3069e1'),
    'next_body': (0x4743350, 0x474398c,
                  'bc09ee782d62721d2cbc93cc2e52d6f447caebbf7ef36da1'
                  '9f5ae89cfef84ae4'),
    'map_insert': (0x474b620, 0x474ba5d,
                   'f6d9ca4362a1a81c592c33e5e75d6522a738b71a143b4c6b9'
                   'bcb0b1739cd6658'),
    'sibling_hasher': (0x4744490, 0x47445fb,
                       'a63e8df74f90feb19a2edfb54c63f81974bac2b7c325c3'
                       '63bc7fe23f9c757f62'),
    'insert_value_drop': (0x474ac30, 0x474ac5d,
                          'a40c63266a40637f39a94b76a535c5f934ad1679a466'
                          '075465f8f8871e569c87'),
}
SHIMS = {
    'rust_personality': (0x5cad7b0, 0x5cadd4f,
                         'fc2600274388c9ee5a7c1aec72fae9aebbb6dffb18ee'
                         '91059e8b3679ec92d677'),
    'panic_formatter': (0x1680e80, 0x1680eac,
                        '28fc3434a04bb9e49d5a0164306a5c31abf6bce26425'
                        'd99d27031ac1c9beb2e3'),
    'panic_impl_shim': (0x5c826c0, 0x5c826dd,
                        'ae57c1f06e3254ce7cd3518d42154be71831103b748b6'
                        'f19f74cacc64c5fb766'),
    'alloc_error_adapter': (0x141e251, 0x141e264,
                            '8443a2a6c5074055f5abdf1b4b2041c6434ff00ba2'
                            '3ebfcb33a91176170035b9'),
    'alloc_handler_shim': (0x5c827a0, 0x5c827b3,
                           '0c812a743791010c3c3ec26bb02400d2081851a700c'
                           '58237af89161da151228e'),
    'cleanup_guard': (0x1680cab, 0x1680cbf,
                      '7604c0d4f26a7d70e59c5dcb8a39928bfd7207a5d4439d9'
                      '1d8fb1e50be9846e7'),
    'guard_panic_entry': (0x1680e40, 0x1680e5e,
                          '8506c2e60ef3206c2566cee1c87d5709e1a0b465109'
                          '4519c2d07355a9deec427'),
}

ZR_CIE = 0xca6ed8
ZPLR_CIE = 0x103d604
PERSONALITY_SLOT = 0x64efa28
UNWIND_RESUME = 0x63f0a50

# Relocation-derived slot bindings this packet relies on: every value
# is read back out of .rela.dyn at analysis time; nothing here is
# trusted without that read.
SLOT_BINDINGS = {
    0x64df4a0: 0x635de30,   # dealloc shim (map-grow packet)
    0x64df490: 0x141e251,   # allocation-error adapter
    0x64df6b8: 0x1680e80,   # panic formatter
    0x64df4c0: 0x1680cab,   # panic-in-cleanup guard
    0x64df6a8: 0x5c827a0,   # allocation handler shim
    0x64e1f28: 0x1680e40,   # guard's panic entry
    0x64e1f30: 0x5c826c0,   # panic implementation shim
    PERSONALITY_SLOT: 0x5cad7b0,
}
# GLOB_DAT slots the personality reads through, bound by symbol name.
ACCESSOR_SLOTS = {
    0x64eca58: '_Unwind_GetLanguageSpecificData',
    0x64eca60: '_Unwind_GetIPInfo',
    0x64eca68: '_Unwind_GetRegionStart',
}

GUARD_STRING_VA = 0x46e9bd
GUARD_STRING = b'panic in a destructor during cleanup'
PANIC_MESSAGE_VA = 0x49bd80
PANIC_MESSAGE = b'Hash table capacity overflow'

# The SipHash initial-constant blocks the sibling's hasher mixes: the
# four IV words of the string "somepseudorandomlygeneratedbytes", read
# as two 16-byte vectors.
SIPHASH_CONST_A = (0x4522f0, '75657370656d6f736172656e6567796c')
SIPHASH_CONST_B = (0x4511c0, '6d6f646e61726f647365747962646574')

# Call-site tables, decoded from each LSDA blob: (range start, range
# length, landing pad or 0, action).  Addresses are absolute.
SIBLING_LSDA_VA = 0x34c4f8
SIBLING_LSDA_SHA256 = ('3533100047f67ca002e96d6c230f3bec06297b95d72'
                       'cf23b5fd79031b5ea1087')
SIBLING_LSDA_ENTRIES = [
    (0x4743990, 0x24f, 0, 0),
    (0x4743bdf, 0xa, 0x4743fc0, 0),
    (0x4743be9, 0x16f, 0, 0),
    (0x4743d58, 0xa, 0x4743fd5, 0),
    (0x4743d62, 0x276, 0, 0),
    (0x4743fd8, 0xa, 0x4743fea, 1),
    (0x4743fe2, 0xe, 0, 0),
]
INSERT_LSDA_VA = 0x34caf4
INSERT_LSDA_SHA256 = ('f7779adae3e80355c13d4a1a156d4d089fdaf7a4320d33'
                      'e04ff22060062e0b6b')
INSERT_LSDA_ENTRIES = [
    (0x474b620, 0x3ce, 0, 0),
    (0x474b9ee, 0x23, 0x474ba2e, 0),
    (0x474ba31, 0xa, 0x474ba57, 1),
    (0x474ba3b, 0x22, 0, 0),
]
GROW_CALL_SITES = 0x474ba06  # inside the insert range that has a pad

# The grow's complete call inventory: six slot calls and no others
# (owned and pinned instruction-by-instruction by the map-grow packet;
# the sites are re-pinned here because the reachability verdict rests
# on them).
GROW_SLOT_CALLS = {
    0x4742bf2: (0x64df480, 'alloc'),
    0x4742c34: (0x64df750, 'memset'),
    0x4742f33: (0x64df568, 'memmove'),
    0x4743301: (0x64df4a0, 'dealloc'),
    0x4743329: (0x64df6b8, 'panic formatter'),
    0x4743337: (0x64df490, 'allocation error'),
}
# Every branch in the grow body whose target is the failure stub
# (0x4742bd1) or the failure tail (0x4743316): site -> target.
STUB = 0x4742bd1
TAIL = 0x4743316
FAILURE_BRANCHES = {
    0x4742ab7: STUB,
    0x4742b5b: STUB,
    0x4742b9f: STUB,
    0x4742bd3: TAIL,
}
NULL_BRANCH = 0x4742bfb       # je to the null-allocation block
NULL_BLOCK = 0x474329b
PATH_SPLIT = 0x4742c24        # fresh/in-place split (map-grow packet)

# Direct-call censuses over the whole .text.
DIRECT_CALL_CENSUS = {
    0x47425c0: [0x4743fdd],               # cleanup <- sibling pad only
    0x4742680: [0x4743fc8],               # helper <- sibling pad only
    0x4744490: [0x4743be4, 0x4743d5d,     # sibling hasher <- 6 sites
                0x4748984, 0x47491b3,
                0x474a1c3, 0x474ba7e],
}

PINS = [
    # The failure stub and its entry branches.
    (0x4742ab7, '0f8214010000', 'checked-add jb to the failure stub'),
    (0x4742b5b, '7774', 'capacity-cap ja to the failure stub'),
    (0x4742b9f, '7030', 'size-overflow jo to the failure stub'),
    (STUB, '84db', 'stub tests the fallibility byte'),
    (0x4742bd3, '0f853d070000', 'stub jne to the failure tail head'),
    # The null-allocation wiring on the fresh path.
    (NULL_BRANCH, '0f849a060000', 'null allocation je to the null block'),
    (NULL_BLOCK, '84db', 'null block tests the fallibility byte'),
    (0x474329d, '0f858c000000', 'null block jne into the tail half'),
    (0x47432a3, 'b810000000', 'null block loads the empty-table tag'),
    # The failure tail itself.
    (TAIL, '488d3d638ad5fb', 'tail loads the capacity-overflow message'),
    (0x4743324, 'be39000000', 'tail loads the message length 0x39'),
    # The sibling's per-record hasher calls.
    (0x4744490, '534883ec60f30f6f07', 'hasher prologue mixes a record'),
    # The sibling's landing pads.
    (0x4743fc0, '4889c3', 'fresh pad saves the exception object'),
    (0x4743fc3, '488d7c2420', 'fresh pad loads the stack descriptor'),
    (0x4743fd5, '4889c3', 'in-place pad saves the exception object'),
    (0x4743fd8, '488d7c2420', 'in-place pad loads the map descriptor'),
    # The insert's landing pads.
    (0x474ba2e, '4889c3', 'insert pad saves the exception object'),
    (0x474ba31, '488b7c2410', 'insert pad loads the pending value'),
    # The personality's phase check.
    (0x5cad7c6, '83ff01', 'personality tests for the search phase'),
    # The cleanup guard's string load.
    (0x1680caf, '488d3d07dddefe', 'guard loads its panic string'),
    (0x1680cb6, '6a24', 'guard loads the string length 0x24'),
]
DIRECT_CALL_PINS = [
    (0x4743fc8, 0x4742680, 'fresh pad calls the pad helper'),
    (0x4743fdd, 0x47425c0, 'in-place pad calls the marked cleanup'),
    (0x4743be4, 0x4744490, 'sibling fresh path calls the hasher'),
    (0x4743d5d, 0x4744490, 'sibling in-place path calls the hasher'),
    (0x474ba36, 0x474ac30, 'insert pad drops the pending value'),
]
SLOT_CALL_PINS = [
    (0x4743fd0, UNWIND_RESUME, 'fresh pad resumes the unwind'),
    (0x4743fe5, UNWIND_RESUME, 'in-place pad resumes the unwind'),
    (0x474ba52, UNWIND_RESUME, 'insert pad resumes the unwind'),
    (0x4743fea, 0x64df4c0, 'guard pad calls through the guard slot'),
    (0x474ba49, 0x64df4a0, 'insert pad frees through the dealloc slot'),
    (0x474ba57, 0x64df4c0, 'insert guard pad calls the guard slot'),
    (0x1680cb9, 0x64e1f28, 'guard calls its panic entry slot'),
    (0x1680ea6, 0x64e1f30, 'formatter calls the panic-impl slot'),
    (0x141e25e, 0x64df6a8, 'adapter calls the alloc-handler slot'),
    (0x5cad7df, 0x64eca58, 'personality reads the LSDA accessor slot'),
    (0x5cad7f6, 0x64eca60, 'personality reads the IP-info slot'),
    (0x5cad80a, 0x64eca68, 'personality reads the region-start slot'),
]
WINDOWS = [
    ('grow_failure_entry_objdump.txt', 0x4742aa0, 0x4742c40,
     [0x4742ab7, 0x4742b5b, 0x4742b9f, STUB, 0x4742bf2, NULL_BRANCH,
      0x4742c34]),
    ('grow_install_tail_objdump.txt', 0x4743290, 0x4743347,
     [NULL_BLOCK, 0x4743301, TAIL, 0x4743329, 0x4743337]),
    ('sibling_hash_call_fresh_objdump.txt', 0x4743bc8, 0x4743bf0,
     [0x4743bdf, 0x4743be4]),
    ('sibling_hash_call_inplace_objdump.txt', 0x4743d50, 0x4743d70,
     [0x4743d58, 0x4743d5d]),
    ('sibling_pads_objdump.txt', 0x4743f80, 0x4743ff0,
     [0x4743f8f, 0x4743fc0, 0x4743fc8, 0x4743fd0, 0x4743fd5, 0x4743fdd,
      0x4743fe5, 0x4743fea]),
    ('insert_pads_objdump.txt', 0x474ba2e, 0x474ba5d,
     [0x474ba36, 0x474ba49, 0x474ba52, 0x474ba57]),
    ('pad_helper_objdump.txt', 0x4742680, 0x47426d1,
     [0x4742680, 0x47426ca]),
    ('panic_guard_objdump.txt', 0x1680cab, 0x1680cc0,
     [0x1680cab, 0x1680cb9]),
    ('panic_fmt_objdump.txt', 0x1680e80, 0x1680ead,
     [0x1680e80, 0x1680ea6]),
]


def _sections(data):
    secs = {}
    for section in sections(data):
        secs.setdefault(section['name'], section)
    return secs


def _reader(secs, data):
    def read(va, count):
        for name in ('.text', '.eh_frame', '.rodata', '.gcc_except_table',
                     '.data.rel.ro', '.data'):
            section = secs.get(name)
            if section is None:
                continue
            start = section['address']
            if section['type'] != 8 and start <= va < start + section['size']:
                offset = section['offset'] + va - start
                return offset, data[offset:offset + count]
        raise ValueError(f'address {va:#x} is not file-backed')
    return read


def _relocations(secs, data):
    rela = secs['.rela.dyn']
    out = {}
    for offset in range(rela['offset'], rela['offset'] + rela['size'], 24):
        r_offset, r_info, r_addend = struct.unpack_from('<QQq', data, offset)
        out[r_offset] = (r_info & 0xffffffff, r_addend, r_info >> 32)
    return out


def _dynsym_names(secs, data):
    dynsym, dynstr = secs['.dynsym'], secs['.dynstr']
    names = []
    for index in range(dynsym['size'] // 24):
        st_name, _info, _other, _shndx, _value, _size = \
            struct.unpack_from('<IBBHQQ', data,
                               dynsym['offset'] + index * 24)
        end = data.index(b'\0', dynstr['offset'] + st_name)
        names.append(data[dynstr['offset'] + st_name:end].decode())
    return names


def _slot_bytes(site, slot):
    disp = slot - (site + 6)
    return b'\xff\x15' + struct.pack('<i', disp)


def _direct_call(site, target):
    return b'\xe8' + struct.pack('<i', target - (site + 5))


def _branch_to(read, start, body):
    """Every rel8/rel32 branch in the body whose target is the failure
    stub or the failure tail, found by a raw byte scan.  The scan runs
    over raw bytes, so it can in principle report a byte pattern inside
    another instruction; on this body it returns exactly the four
    instruction sites the disassembly shows, and the caller pins each
    site's full encoding, so a false candidate fails the comparison."""
    found = {}
    for i in range(len(body) - 1):
        va = start + i
        opcode = body[i]
        target = None
        if opcode in (0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
                      0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
                      0xeb):
            disp = struct.unpack_from('<b', body, i + 1)[0]
            target = va + 2 + disp
        elif opcode == 0x0f and i + 5 < len(body) and \
                0x80 <= body[i + 1] <= 0x8f:
            disp = struct.unpack_from('<i', body, i + 2)[0]
            target = va + 6 + disp
            if target in (STUB, TAIL):
                found[va] = target
            continue
        elif opcode == 0xe9 and i + 4 < len(body):
            disp = struct.unpack_from('<i', body, i + 1)[0]
            target = va + 5 + disp
        if target in (STUB, TAIL):
            found[va] = target
    return found


def _uleb(blob, pos):
    result, shift = 0, 0
    while True:
        byte = blob[pos]
        pos += 1
        result |= (byte & 0x7f) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7


def _decode_lsda(read, lsda_va, fde_start):
    """Decode one LSDA under the exact header shape the cluster's two
    tables use (lpstart omitted, ttype encoding 0x9b, call-site
    encoding uleb128); anything else fails closed."""
    _off, blob = read(lsda_va, 0x80)
    pos = 0
    lp_enc = blob[pos]
    pos += 1
    if lp_enc != 0xff:
        raise ValueError('unexpected LSDA lpstart encoding')
    tt_enc = blob[pos]
    pos += 1
    if tt_enc != 0x9b:
        raise ValueError('unexpected LSDA ttype encoding')
    tt_base_off, pos = _uleb(blob, pos)
    tt_base = lsda_va + pos + tt_base_off
    cs_enc = blob[pos]
    pos += 1
    if cs_enc != 0x01:
        raise ValueError('unexpected LSDA call-site encoding')
    cs_len, pos = _uleb(blob, pos)
    header_end = pos
    entries = []
    end = header_end + cs_len
    while pos < end:
        start_off, pos = _uleb(blob, pos)
        length, pos = _uleb(blob, pos)
        pad_off, pos = _uleb(blob, pos)
        action, pos = _uleb(blob, pos)
        entries.append((fde_start + start_off, length,
                        fde_start + pad_off if pad_off else 0, action))
    if pos != end:
        raise ValueError('LSDA call-site table overruns its length')
    action_table = lsda_va + end
    raw = blob[:tt_base - lsda_va]
    return {
        'lsda': hex(lsda_va),
        'lpstart_encoding': lp_enc,
        'ttype_encoding': tt_enc,
        'ttype_base': hex(tt_base),
        'call_site_encoding': cs_enc,
        'call_site_table_bytes': cs_len,
        'action_table': hex(action_table),
        'action_table_head_hex': blob[end:end + 2].hex(),
        'raw_bytes_hex': raw.hex(),
        'sha256': hashlib.sha256(raw).hexdigest(),
        'entries': [{'start': hex(s), 'length': ln,
                     'landing_pad': hex(p) if p else None,
                     'action': a} for s, ln, p, a in entries],
    }, entries


def analyze(data):
    digest = hashlib.sha256(data).hexdigest()
    require(digest == SHA, 'node115 digest drift')
    secs = _sections(data)
    read = _reader(secs, data)
    relocations = _relocations(secs, data)
    dynsym = _dynsym_names(secs, data)
    _cies, fde_list = eh_frame_records(data)
    fdes = {(f['start'], f['end']): f for f in fde_list}

    def frame_records(a, b, sha, role):
        if (a, b) not in fdes:
            raise ValueError(f'{role} scope FDE changed')
        offset, raw = read(a, b - a)
        body_digest = hashlib.sha256(raw).hexdigest()
        if body_digest != sha:
            raise ValueError(f'{role} body changed')
        rec = fdes[(a, b)]
        records = {}
        for kind in ('fde', 'cie'):
            va = rec[kind]
            n = struct.unpack('<I', read(va, 4)[1])[0] + 4
            records[kind] = {'va': hex(va),
                             'bytes_hex': read(va, n)[1].hex()}
        row = {'role': role, 'start': hex(a), 'end': hex(b),
               'file_offset': hex(offset), 'bytes': b - a,
               'sha256': body_digest, 'frames': records}
        cie = _cies[rec['cie']]
        unwind = {'cie': hex(rec['cie']),
                  'augmentation': cie['augmentation'],
                  'lsda': hex(rec['lsda']) if rec['lsda'] else None,
                  'personality_slot': (hex(cie['personality_slot'])
                                       if cie['personality_slot']
                                       else None),
                  'lsda_encoding': cie['lsda_encoding']}
        return row, unwind

    owners, boundaries, shims = [], [], []
    unwinds = {}
    for role, spec in OWNERS.items():
        row, unwind = frame_records(*spec, role)
        owners.append(row)
        unwinds[role] = unwind
    for role, spec in BOUNDARIES.items():
        row, unwind = frame_records(*spec, role)
        boundaries.append(row)
        unwinds[role] = unwind
    for role, spec in SHIMS.items():
        row, unwind = frame_records(*spec, role)
        shims.append(row)
        unwinds[role] = unwind

    # (a) The grow's frame: plain-'zR' CIE, no LSDA, unique coverage.
    grow_unwind = unwinds['map_grow']
    if grow_unwind != {'cie': hex(ZR_CIE), 'augmentation': 'zR',
                       'lsda': None, 'personality_slot': None,
                       'lsda_encoding': None}:
        raise ValueError('map grow frame is not the plain-zR frame')
    grow_range = OWNERS['map_grow'][:2]
    covering = [(f['start'], f['end']) for f in fde_list
                if f['start'] < grow_range[1] and f['end'] > grow_range[0]]
    if covering != [grow_range]:
        raise ValueError('map grow range coverage changed')
    for role in ('marked_cleanup', 'pad_helper', 'whole_map_drop',
                 'prev_body', 'next_body'):
        if unwinds[role]['cie'] != hex(ZR_CIE) or \
                unwinds[role]['lsda'] is not None:
            raise ValueError(f'{role} left the plain-zR cluster')
    for role in ('sibling_grow', 'map_insert'):
        if unwinds[role]['cie'] != hex(ZPLR_CIE) or \
                unwinds[role]['augmentation'] != 'zPLR' or \
                unwinds[role]['personality_slot'] != \
                hex(PERSONALITY_SLOT) or \
                unwinds[role]['lsda_encoding'] != 0x1b:
            raise ValueError(f'{role} left the personality cluster')

    # The personality binding and its body.
    r_type, r_addend, _sym = relocations[PERSONALITY_SLOT]
    if r_type != 8 or r_addend != SHIMS['rust_personality'][0]:
        raise ValueError('personality relocation changed')
    bindings = {}
    for slot, want in SLOT_BINDINGS.items():
        r_type, r_addend, _sym = relocations[slot]
        if r_addend != want:
            raise ValueError(f'slot {slot:#x} binding changed')
        bindings[hex(slot)] = {'type': r_type, 'addend': hex(r_addend)}
    accessors = {}
    for slot, name in ACCESSOR_SLOTS.items():
        r_type, _addend, sym = relocations[slot]
        if r_type != 6 or dynsym[sym] != name:
            raise ValueError(f'accessor slot {slot:#x} changed')
        accessors[hex(slot)] = name

    # (c) The two LSDA call-site tables.
    sibling_lsda, sibling_entries = _decode_lsda(
        read, SIBLING_LSDA_VA, OWNERS['sibling_grow'][0])
    if sibling_entries != SIBLING_LSDA_ENTRIES or \
            sibling_lsda['sha256'] != SIBLING_LSDA_SHA256 or \
            sibling_lsda['action_table_head_hex'] != '7f00' or \
            unwinds['sibling_grow']['lsda'] != hex(SIBLING_LSDA_VA):
        raise ValueError('sibling LSDA changed')
    insert_lsda, insert_entries = _decode_lsda(
        read, INSERT_LSDA_VA, BOUNDARIES['map_insert'][0])
    if insert_entries != INSERT_LSDA_ENTRIES or \
            insert_lsda['sha256'] != INSERT_LSDA_SHA256 or \
            insert_lsda['action_table_head_hex'] != '7f00' or \
            unwinds['map_insert']['lsda'] != hex(INSERT_LSDA_VA):
        raise ValueError('insert LSDA changed')
    grow_site = [e for e in insert_entries
                 if e[0] <= GROW_CALL_SITES < e[0] + e[1]]
    if grow_site != [INSERT_LSDA_ENTRIES[1]]:
        raise ValueError('grow call site is not in the padded range')

    # Byte pins, direct calls, slot calls.
    for va, want, _label in PINS:
        if read(va, len(bytes.fromhex(want)))[1] != bytes.fromhex(want):
            raise ValueError(f'byte pin changed at {va:#x}')
    for site, target, _label in DIRECT_CALL_PINS:
        if read(site, 5)[1] != _direct_call(site, target):
            raise ValueError(f'direct call changed at {site:#x}')
    for site, second, _label in SLOT_CALL_PINS:
        if second == UNWIND_RESUME:
            want = _direct_call(site, second)
        else:
            want = _slot_bytes(site, second)
        if read(site, len(want))[1] != want:
            raise ValueError(f'slot call changed at {site:#x}')

    # (b) The grow's failure reachability.
    _off, grow_body = read(grow_range[0], grow_range[1] - grow_range[0])
    branches = _branch_to(read, grow_range[0], grow_body)
    if branches != FAILURE_BRANCHES:
        raise ValueError('failure branch census changed')
    if max(FAILURE_BRANCHES) >= PATH_SPLIT or NULL_BRANCH >= PATH_SPLIT:
        raise ValueError('a failure source sits past the path split')
    for site, (slot, _name) in GROW_SLOT_CALLS.items():
        if read(site, 6)[1] != _slot_bytes(site, slot):
            raise ValueError(f'grow slot call changed at {site:#x}')
    _off, message = read(PANIC_MESSAGE_VA, len(PANIC_MESSAGE) + 1)
    if message[:len(PANIC_MESSAGE)] != PANIC_MESSAGE:
        raise ValueError('panic message changed')
    _off, guard_text = read(GUARD_STRING_VA, len(GUARD_STRING) + 1)
    if guard_text[:len(GUARD_STRING)] != GUARD_STRING:
        raise ValueError('cleanup guard string changed')
    for va, want_hex in (SIPHASH_CONST_A, SIPHASH_CONST_B):
        if read(va, 16)[1].hex() != want_hex:
            raise ValueError('SipHash constant block changed')

    # Direct-call censuses over the whole .text.
    text = secs['.text']
    text_bytes = data[text['offset']:text['offset'] + text['size']]
    census = {}
    for target, want in DIRECT_CALL_CENSUS.items():
        sites = []
        for i in range(len(text_bytes) - 4):
            if text_bytes[i] == 0xe8:
                disp = struct.unpack_from('<i', text_bytes, i + 1)[0]
                if text['address'] + i + 5 + disp == target:
                    sites.append(text['address'] + i)
        if sites != want:
            raise ValueError(f'call census changed for {target:#x}')
        census[hex(target)] = [hex(s) for s in sites]

    return {
        'target_sha256': SHA,
        'owners': owners,
        'boundaries': boundaries,
        'shims': shims,
        'unwind': unwinds,
        'slot_bindings': bindings,
        'personality': {'slot': hex(PERSONALITY_SLOT), 'type': 8,
                        'addend': hex(SHIMS['rust_personality'][0]),
                        'accessor_slots': accessors,
                        'unwind_resume': hex(UNWIND_RESUME)},
        'sibling_lsda': sibling_lsda,
        'insert_lsda': insert_lsda,
        'grow_call_site_range': {
            'call': hex(GROW_CALL_SITES),
            'range': [hex(INSERT_LSDA_ENTRIES[1][0]),
                      hex(INSERT_LSDA_ENTRIES[1][0] +
                          INSERT_LSDA_ENTRIES[1][1])],
            'landing_pad': hex(INSERT_LSDA_ENTRIES[1][2])},
        'failure_branches': {hex(k): hex(v)
                             for k, v in sorted(branches.items())},
        'grow_slot_calls': {hex(site): {'slot': hex(slot), 'name': name}
                            for site, (slot, name) in
                            sorted(GROW_SLOT_CALLS.items())},
        'null_branch': hex(NULL_BRANCH),
        'path_split': hex(PATH_SPLIT),
        'direct_call_census': census,
        'siphash_constants': {
            hex(SIPHASH_CONST_A[0]): SIPHASH_CONST_A[1],
            hex(SIPHASH_CONST_B[0]): SIPHASH_CONST_B[1]},
        'guard_string': {'address': hex(GUARD_STRING_VA),
                         'text': GUARD_STRING.decode()},
        'panic_message': {'address': hex(PANIC_MESSAGE_VA),
                          'text': PANIC_MESSAGE.decode()},
        'methods': [
            'FDE/CIE records are re-derived from .eh_frame with the '
            'repository eh_frame_records parser; body extents and '
            'SHA-256 values are pinned for the two grows, the cleanup, '
            'the pad helper, the four boundary bodies and the seven '
            'panic-path shims.',
            'LSDA call-site tables are decoded byte-by-byte under '
            'their pinned header shape (lpstart omitted, ttype '
            'encoding 0x9b, uleb128 call sites) and compared entry '
            'for entry; each blob is also pinned by SHA-256.',
            'The failure-branch census is a raw rel8/rel32 scan of '
            'the grow body for branches to the stub or the tail; '
            'every returned site is additionally pinned by its full '
            'instruction bytes, so a scan artefact cannot pass.',
            'Slot bindings come from .rela.dyn addends read at '
            'analysis time; the personality accessors come from '
            'GLOB_DAT relocations resolved through .dynsym names.',
            'Native objdump/readelf cross-checks run only in '
            'generate().',
        ],
        'verdict': (
            'The grow at 0x4742aa0 has no landing pad of its own: its '
            'only FDE uses the plain-zR CIE at 0xca6ed8 and carries no '
            'LSDA.  None is needed.  The marked state exists only on '
            'the in-place path, whose only callee is memmove through '
            'its slot, and the body\'s only panic origin -- the '
            'failure tail at 0x4743316 -- is reachable solely from '
            'the three pre-split sizing branches to the stub at '
            '0x4742bd1 and from the fresh path\'s null-allocation '
            'branch at 0x4742bfb, states in which no record is '
            'marked.  A panic that does unwind through the frame is '
            'handled one frame up: the insert at 0x474b620 gives the '
            'grow call site the pad at 0x474ba2e, which drops only '
            'the caller\'s pending value and buffer.  The sibling '
            'grow at 0x4743990 differs because its rehash calls the '
            'seeded SipHash callee at 0x4744490 once per record '
            'inside the marking window, so its LSDA wires the '
            'fresh-path pad at 0x4743fc0 to the pad helper at '
            '0x4742680 and the in-place pad at 0x4743fd5 to the '
            'marked-record cleanup at 0x47425c0, with the cleanup '
            'call itself guarded by the panic-in-cleanup pad at '
            '0x4743fea.'),
    }


def _objdump(path, start, end):
    return subprocess.check_output(
        ['objdump', '-d', '-M', 'intel', '--insn-width=16',
         f'--start-address={start:#x}', f'--stop-address={end:#x}',
         str(path)]).decode('utf-8')


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
                list(BOUNDARIES.items()) + list(SHIMS.items()):
            rows = [l for l in native.splitlines()
                    if f'pc={a:016x}..{b:016x}' in l]
            if len(rows) != 1:
                raise ValueError('native FDE disagreement')
            lines.extend(rows)
        secs = _sections(data)
        read = _reader(secs, data)
        for name, start, end, sites in WINDOWS:
            asm = _objdump(snapshot, start, end)
            ins = decode_export(asm, start, end,
                                read(start, end - start)[1])
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
    print(json.dumps(analyze(TARGET.read_bytes()), indent=2))
