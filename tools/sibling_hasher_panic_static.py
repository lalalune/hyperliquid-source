#!/usr/bin/env python3
"""Settle whether the sibling grow's seeded hasher can itself panic.

The grow-panic packet (tools/map_grow_panic_static.py) closed the
map-grow packet's open question about the grow at 0x4742aa0 and
explained why the sibling grow at 0x4743990 is wired differently: its
rehash calls the seeded SipHash callee at 0x4744490 once per record
inside the marking window, so its LSDA pads exist.  That packet's
limits section left one sentence explicitly unestablished: "Whether
the sibling's hasher at 0x4744490 can itself panic is not established
and is not needed: the sibling's pads exist because a call sits in
the window."  This tool settles that sentence, and with it what the
frame records around the hasher actually cover:

(a) The hasher's own frame.  Its only FDE (at 0xefd12c) refers to
the cluster-shared CIE at 0xca6ed8, whose augmentation is exactly
'zR': no personality, no LSDA encoding, and the FDE carries no LSDA
pointer.  It is the only FDE covering 0x4744490..0x47445fb.  The
body itself is straight-line apart from its calls: a linear decode
(byte-exact against the body) finds no branch, no division and no
overflow-checked operation anywhere in its 363 bytes.

(b) The hasher's callees.  The body makes exactly two calls, both
direct, both to the buffered absorb at 0x4744980: the first absorbs
the record bytes described by the incoming pair at [rsi+0x8] and
[rsi+0x10], the second absorbs the single 0xff terminator byte the
prologue plants at [rsp+0xf] with length 1.  The absorb is a leaf:
again by byte-exact linear decode it contains no call of any form,
and every one of its branches lands inside its own extent
0x4744980..0x4744b57; its frame records are the same plain-'zR'
shape.  Its one add of an untrusted length (the total counter at
[rdi+0x30]) is unchecked -- neither body contains an overflow
branch.  The transitive call graph beneath the hasher therefore
closes after one step and contains no panic origin: nothing below
any hasher call site can raise at all, so the sibling's pads are
coverage for an exposure that the callee side never realises.

(c) What the callers' wiring covers anyway.  A binary-wide
direct-call census finds exactly six call sites for the hasher, and
every one of them sits inside a padded range of its caller's LSDA:
the sibling's fresh-path range 0x4743bdf..0x4743be9 (pad 0x4743fc0,
the pad helper) and in-place range 0x4743d58..0x4743d62 (pad
0x4743fd5, the marked-record cleanup), both pinned by the
grow-panic packet and re-pinned here; caller A (0x4748500) covers
its sites 0x4748984 and 0x47491b3 with its own cleanup pads at
0x4749948 and 0x4749814; caller B (0x474a160) covers 0x474a1c3 with
the range 0x474a1c0..0x474a1c8, whose pad at 0x474a361 decrements
the qword at [rbx] and resumes the unwind; caller C (0x474ba60)
covers 0x474ba7e with the range 0x474ba7b..0x474ba83, whose pad at
0x474bcb4 frees a pending buffer through the deallocation slot
0x64df4a0 and resumes.  The absorb's own direct-call census is the
same shape: six sites, the hasher's two plus two each in the
neighbouring hash bodies at 0x4744330 and 0x4744600, whose frames
are likewise plain-'zR'.

So the frame records around the hasher cover nothing in the
hasher's own frame -- there is nothing to cover -- and the pads
that do exist sit one frame up at every call site in the binary,
each dropping that caller's own state, exactly as in the cluster
pattern the grow-panic packet established for the grow/insert pair.
"""
import hashlib
import json
import re
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
    'seeded_hasher': (0x4744490, 0x47445fb,
                      'a63e8df74f90feb19a2edfb54c63f81974bac2b7c325c3'
                      '63bc7fe23f9c757f62'),
    'absorb': (0x4744980, 0x4744b57,
               '2de0e4e06f65af3f729cc6b2a4d12d7dcbbcb25902272a15c5'
               'f238c5096ed8b0'),
}
BOUNDARIES = {
    'sibling_grow': (0x4743990, 0x4743ff0,
                     'eeac52dec8e29f0c1c3084ba80545a9b551b44c69b974a60'
                     'f2220d564f961eef'),
    'caller_a': (0x4748500, 0x4749aa9,
                 '7b1d3b86c285b089e030cba72aa9fc2b71cba2009d2849c91'
                 'ec06977ea9b2691'),
    'caller_b': (0x474a160, 0x474a36c,
                 'a2ca8b7c65a4ed7eb69ff5fb090acb7daead9c234e681b08'
                 '67b3d0c70a1b5d7d'),
    'caller_c': (0x474ba60, 0x474bcd3,
                 '4527e1e0d1ad267cdd6951f2eb2898a962a2124d6096038f'
                 'd63087ea43637d44'),
    'prev_variant': (0x4744330, 0x4744490,
                     '6a63f80b87467acfa021f1e6f6348428254af8bf6eb366'
                     'a0b6c23c762053df69'),
    'next_variant': (0x4744600, 0x474476a,
                     '45b8c11384591251d95dfd535ffa593b439d7f0f2673e14'
                     '1dcd44888e88bcdc1'),
}
SHIMS = {
    'rust_personality': (0x5cad7b0, 0x5cadd4f,
                         'fc2600274388c9ee5a7c1aec72fae9aebbb6dffb18ee'
                         '91059e8b3679ec92d677'),
}

ZR_CIE = 0xca6ed8
ZPLR_CIE = 0x103d604
PERSONALITY_SLOT = 0x64efa28
UNWIND_RESUME = 0x63f0a50
DEALLOC_SLOT = 0x64df4a0
DEALLOC_SHIM = 0x635de30

HASHER = 0x4744490
ABSORB = 0x4744980

# The SipHash initial-constant blocks the hasher mixes (re-pinned
# from the grow-panic packet, which identified the callee by them).
SIPHASH_CONST_A = (0x4522f0, '75657370656d6f736172656e6567796c')
SIPHASH_CONST_B = (0x4511c0, '6d6f646e61726f647365747962646574')

# Direct-call censuses over the whole .text.
HASHER_CALL_SITES = [0x4743be4, 0x4743d5d, 0x4748984, 0x47491b3,
                     0x474a1c3, 0x474ba7e]
ABSORB_CALL_SITES = [0x4744380, 0x4744397, 0x47444eb, 0x4744502,
                     0x474465a, 0x4744671]

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
CALLER_A_LSDA_VA = 0x34c818
CALLER_A_LSDA_SHA256 = ('582dacc3fa8508b8e3bee377480c8c57cb224858875'
                        '2de6f2c226a819702a6a0')
CALLER_A_LSDA_ENTRIES = [
    (0x4748500, 0x235, 0, 0),
    (0x4748735, 0x12, 0x4749995, 0),
    (0x474875b, 0xb, 0x4749870, 0),
    (0x47487aa, 0x5, 0x47498ab, 0),
    (0x47487e5, 0xd, 0x4749906, 0),
    (0x4748836, 0xe, 0x4749875, 0),
    (0x474885a, 0xa, 0x4749809, 0),
    (0x4748977, 0x12, 0x4749948, 0),
    (0x4748aa6, 0xe, 0x4749869, 0),
    (0x4748af1, 0xb, 0x4749895, 0),
    (0x4748afc, 0x2a8, 0, 0),
    (0x4748da4, 0xf, 0x47498f6, 0),
    (0x4748dce, 0xb, 0x47497e6, 0),
    (0x4748dd9, 0x1e4, 0, 0),
    (0x4748fbd, 0xb, 0x47497a6, 0),
    (0x47491a3, 0x15, 0x4749814, 0),
    (0x47492e6, 0xe, 0x47497a4, 0),
    (0x4749344, 0xb, 0x47497d7, 0),
    (0x474944a, 0xe, 0x474978f, 0),
    (0x474945d, 0xd, 0x47497cf, 0),
    (0x474946a, 0x2a2, 0, 0),
    (0x474970c, 0x10, 0x47499e8, 0),
    (0x474971e, 0xc, 0x474977f, 0),
    (0x474972f, 0xc, 0x4749774, 0),
    (0x4749745, 0xe, 0x4749943, 0),
    (0x4749755, 0xe, 0x474986b, 0),
    (0x474983e, 0xa, 0x4749aa3, 1),
    (0x474987d, 0xd, 0x474988f, 1),
    (0x47498df, 0x19d, 0x4749aa3, 1),
    (0x4749a7c, 0x2d, 0, 0),
]
CALLER_B_LSDA_VA = 0x34c9a0
CALLER_B_LSDA_SHA256 = ('3e85b0eead4fcb109a76d75f07555e25f6e35f2aa02f9'
                        'b9321583af292840011')
CALLER_B_LSDA_ENTRIES = [
    (0x474a160, 0x60, 0, 0),
    (0x474a1c0, 0x8, 0x474a361, 0),
    (0x474a1c8, 0x15e, 0, 0),
    (0x474a326, 0xf, 0x474a361, 0),
    (0x474a335, 0x37, 0, 0),
]
CALLER_C_LSDA_VA = 0x34cb18
CALLER_C_LSDA_SHA256 = ('40027343d58280050a8843f4b29072a15b583d22ff0f'
                        '226dc30933e8e2563a7d')
CALLER_C_LSDA_ENTRIES = [
    (0x474ba7b, 0x8, 0x474bcb4, 0),
    (0x474ba83, 0x1fe, 0, 0),
    (0x474bc81, 0x16, 0x474bcb4, 0),
    (0x474bc97, 0x3c, 0, 0),
]

# Which caller each hasher call site belongs to, the LSDA range that
# covers it, and the pad that range lands on.
COVERAGE = {
    0x4743be4: ('sibling_grow', (0x4743bdf, 0x4743be9), 0x4743fc0),
    0x4743d5d: ('sibling_grow', (0x4743d58, 0x4743d62), 0x4743fd5),
    0x4748984: ('caller_a', (0x4748977, 0x4748989), 0x4749948),
    0x47491b3: ('caller_a', (0x47491a3, 0x47491b8), 0x4749814),
    0x474a1c3: ('caller_b', (0x474a1c0, 0x474a1c8), 0x474a361),
    0x474ba7e: ('caller_c', (0x474ba7b, 0x474ba83), 0x474bcb4),
}

PINS = [
    # The hasher's seed load and absorb-call argument setup.
    (0x4744495, 'f30f6f07', 'hasher loads the 16-byte seed block'),
    (0x47444d8, '488b4608', 'first absorb length-ptr field load'),
    (0x47444dc, '488b5610', 'first absorb length field load'),
    (0x47444f0, 'c644240fff', 'terminator byte 0xff planted'),
    (0x47444fa, 'ba01000000', 'second absorb length is 1'),
    # The other callers' pads for the hasher call sites.
    (0x4749948, '4989c7', 'caller A second pad saves the exception'),
    (0x4749814, '4989c7', 'caller A first pad saves the exception'),
    (0x474a361, '48ff0b', 'caller B pad decrements the qword'),
    (0x474a364, '4889c7', 'caller B pad moves the exception object'),
    (0x474bcb4, '4889c3', 'caller C pad saves the exception object'),
    (0x474bcb7, '498b36', 'caller C pad loads the pending buffer'),
]
DIRECT_CALL_PINS = [
    (0x47444eb, ABSORB, 'hasher absorbs the record bytes'),
    (0x4744502, ABSORB, 'hasher absorbs the terminator byte'),
    (0x474a367, UNWIND_RESUME, 'caller B pad resumes the unwind'),
    (0x474bcce, UNWIND_RESUME, 'caller C pad resumes the unwind'),
]
SLOT_CALL_PINS = [
    (0x4749969, DEALLOC_SLOT, 'caller A second pad frees via dealloc'),
    (0x4749838, DEALLOC_SLOT, 'caller A first pad frees via dealloc'),
    (0x474bcc5, DEALLOC_SLOT, 'caller C pad frees via dealloc'),
]
WINDOWS = [
    ('hasher_objdump.txt', 0x4744490, 0x47445fb,
     [0x4744495, 0x47444eb, 0x4744502]),
    ('absorb_objdump.txt', 0x4744980, 0x4744b57,
     [0x4744980]),
    ('sibling_hasher_call_fresh_objdump.txt', 0x4743bc8, 0x4743bf0,
     [0x4743bdf, 0x4743be4]),
    ('sibling_hasher_call_inplace_objdump.txt', 0x4743d50, 0x4743d70,
     [0x4743d58, 0x4743d5d]),
    ('caller_a_call_first_objdump.txt', 0x4749198, 0x47491c0,
     [0x47491b3]),
    ('caller_a_call_second_objdump.txt', 0x4748970, 0x4748990,
     [0x4748984]),
    ('caller_a_pad_first_objdump.txt', 0x4749814, 0x4749869,
     [0x4749814, 0x4749838]),
    ('caller_a_pad_second_objdump.txt', 0x4749948, 0x4749995,
     [0x4749948, 0x4749969]),
    ('caller_b_call_objdump.txt', 0x474a1b8, 0x474a1d0,
     [0x474a1c3]),
    ('caller_b_pad_objdump.txt', 0x474a361, 0x474a36c,
     [0x474a361, 0x474a367]),
    ('caller_c_call_objdump.txt', 0x474ba70, 0x474ba90,
     [0x474ba7e]),
    ('caller_c_pad_objdump.txt', 0x474bcb4, 0x474bcd3,
     [0x474bcb4, 0x474bcc5, 0x474bcce]),
]


ABSORB_BRANCHES = {
    0x474498c: 0x47449bd, 0x47449a5: 0x47449c5, 0x47449b9: 0x47449d6,
    0x47449bb: 0x47449eb, 0x47449c0: 0x4744a75, 0x47449d4: 0x47449eb,
    0x47449ee: 0x4744a00, 0x4744a16: 0x4744a21, 0x4744a86: 0x4744af2,
    0x4744ae1: 0x4744aa0, 0x4744af6: 0x4744b0d, 0x4744b09: 0x4744b1b,
    0x4744b0b: 0x4744b35, 0x4744b19: 0x4744b35, 0x4744b38: 0x4744b4d,
}
HASHER_INSTRUCTIONS = 93
ABSORB_INSTRUCTIONS = 141


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


def _slot_bytes(site, slot):
    disp = slot - (site + 6)
    return b'\xff\x15' + struct.pack('<i', disp)


def _direct_call(site, target):
    return b'\xe8' + struct.pack('<i', target - (site + 5))


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
    """Decode one LSDA under either header shape the cluster's tables
    use: lpstart omitted (0xff), then either a 0x9b ttype offset (the
    table extent runs to the type-table base) or an omitted ttype
    (0xff; the extent runs two bytes past the call-site table, the
    action-table head).  Call-site encoding must be uleb128 (0x01);
    anything else fails closed."""
    _off, blob = read(lsda_va, 0x200)
    pos = 0
    lp_enc = blob[pos]
    pos += 1
    if lp_enc != 0xff:
        raise ValueError('unexpected LSDA lpstart encoding')
    tt_enc = blob[pos]
    pos += 1
    tt_base = None
    if tt_enc == 0x9b:
        tt_off, pos = _uleb(blob, pos)
        tt_base = lsda_va + pos + tt_off
    elif tt_enc != 0xff:
        raise ValueError('unexpected LSDA ttype encoding')
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
    extent = (tt_base - lsda_va) if tt_base is not None else end + 2
    raw = blob[:extent]
    return {
        'lsda': hex(lsda_va),
        'lpstart_encoding': lp_enc,
        'ttype_encoding': tt_enc,
        'ttype_base': hex(tt_base) if tt_base is not None else None,
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


def _parse_objdump(text):
    out = {}
    for line in text.splitlines():
        match = re.match(r'\s+([0-9a-f]+):\t([0-9a-f ]+?)\s*\t(.*)', line)
        if match:
            site = int(match.group(1), 16)
            raw = bytes(int(x, 16) for x in match.group(2).split())
            out[site] = (raw, match.group(3).strip())
    return out


def _decode_body(data, read, start, end):
    """Linear-decode one body with native objdump and require the
    decode to be byte-exact and contiguous over the extent (the
    repository decode_export contract), so the instruction census
    below runs over true instruction boundaries, not raw bytes."""
    with tempfile.NamedTemporaryFile(suffix='.elf', delete=False) as handle:
        handle.write(data)
        snapshot = Path(handle.name)
    try:
        asm = subprocess.check_output(
            ['objdump', '-d', '-M', 'intel', '--insn-width=16',
             f'--start-address={start:#x}', f'--stop-address={end:#x}',
             str(snapshot)]).decode('utf-8')
    finally:
        snapshot.unlink()
    textmap = _parse_objdump(asm)
    decoded = decode_export(asm, start, end,
                            read(start, end - start)[1])
    if set(textmap) != set(decoded):
        raise ValueError('text map disagrees with byte decode')
    for site, raw in decoded.items():
        if textmap[site][0] != raw:
            raise ValueError('text map byte disagreement')
    return textmap


def _instruction_census(textmap):
    calls, branches, divisions, traps = [], {}, [], []
    for site in sorted(textmap):
        text = textmap[site][1]
        parts = text.split()
        mnemonic = parts[0]
        if mnemonic == 'call':
            operand = parts[1]
            target = int(operand, 16) if \
                all(c in '0123456789abcdef' for c in operand) else None
            calls.append((site, target))
        elif mnemonic.startswith('j') or mnemonic in ('loop', 'loope',
                                                      'loopne'):
            branches[site] = int(parts[1], 16)
        elif mnemonic in ('div', 'idiv'):
            divisions.append(site)
        elif mnemonic in ('int3', 'ud2', 'hlt', 'int'):
            traps.append(site)
    return {'instructions': len(textmap), 'calls': calls,
            'branches': branches, 'divisions': divisions,
            'traps': traps}


def _call_census(data, secs, target):
    text = secs['.text']
    raw = data[text['offset']:text['offset'] + text['size']]
    base = text['address']
    sites = []
    pos = raw.find(b'\xe8')
    while pos != -1:
        disp = struct.unpack_from('<i', raw, pos + 1)[0]
        if base + pos + 5 + disp == target:
            sites.append(base + pos)
        pos = raw.find(b'\xe8', pos + 1)
    return sites


def analyze(data):
    digest = hashlib.sha256(data).hexdigest()
    require(digest == SHA, 'node115 digest drift')
    secs = _sections(data)
    read = _reader(secs, data)
    relocations = _relocations(secs, data)
    _cies, fde_list = eh_frame_records(data)
    cies = _cies
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
        cie = cies[rec['cie']]
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

    # (a) The two owner frames and the neighbouring hash bodies are
    # the plain-'zR' shape; unique FDE coverage of both owner ranges.
    plain = {'cie': hex(ZR_CIE), 'augmentation': 'zR', 'lsda': None,
             'personality_slot': None, 'lsda_encoding': None}
    for role in ('seeded_hasher', 'absorb', 'prev_variant',
                 'next_variant'):
        if unwinds[role] != plain:
            raise ValueError(f'{role} frame is not the plain-zR frame')
    for role, spec in OWNERS.items():
        a, b = spec[:2]
        covering = [(f['start'], f['end']) for f in fde_list
                    if f['start'] < b and f['end'] > a]
        if covering != [(a, b)]:
            raise ValueError(f'{role} range coverage changed')
    # The four callers run under the personality CIE with an LSDA.
    caller_lsdas = {}
    for role, lsda_va in (('sibling_grow', SIBLING_LSDA_VA),
                          ('caller_a', CALLER_A_LSDA_VA),
                          ('caller_b', CALLER_B_LSDA_VA),
                          ('caller_c', CALLER_C_LSDA_VA)):
        unwind = unwinds[role]
        if unwind['cie'] != hex(ZPLR_CIE) or \
                unwind['augmentation'] != 'zPLR' or \
                unwind['personality_slot'] != hex(PERSONALITY_SLOT) or \
                unwind['lsda_encoding'] != 0x1b or \
                unwind['lsda'] != hex(lsda_va):
            raise ValueError(f'{role} left the personality cluster')
        caller_lsdas[role] = lsda_va

    # The personality and deallocation slot bindings.
    r_type, r_addend, _sym = relocations[PERSONALITY_SLOT]
    if r_type != 8 or r_addend != SHIMS['rust_personality'][0]:
        raise ValueError('personality relocation changed')
    _t, dealloc_addend, _s = relocations[DEALLOC_SLOT]
    if dealloc_addend != DEALLOC_SHIM:
        raise ValueError('deallocation slot binding changed')

    # (b) Instruction censuses of the two owner bodies.
    hasher_map = _decode_body(data, read, *OWNERS['seeded_hasher'][:2])
    absorb_map = _decode_body(data, read, *OWNERS['absorb'][:2])
    hasher_census = _instruction_census(hasher_map)
    absorb_census = _instruction_census(absorb_map)
    if hasher_census['instructions'] != HASHER_INSTRUCTIONS or \
            hasher_census['calls'] != [(0x47444eb, ABSORB),
                                       (0x4744502, ABSORB)] or \
            hasher_census['branches'] != {} or \
            hasher_census['divisions'] or hasher_census['traps']:
        raise ValueError('hasher instruction census changed')
    if absorb_census['instructions'] != ABSORB_INSTRUCTIONS or \
            absorb_census['calls'] != [] or \
            absorb_census['branches'] != ABSORB_BRANCHES or \
            absorb_census['divisions'] or absorb_census['traps']:
        raise ValueError('absorb instruction census changed')
    absorb_start, absorb_end = OWNERS['absorb'][:2]
    for target in absorb_census['branches'].values():
        if not absorb_start <= target < absorb_end:
            raise ValueError('an absorb branch leaves the body')
    # Byte-level backstop: the hasher body's only 0xe8 bytes are its
    # two call instructions, and the absorb body has none at all, so
    # no direct call can hide inside another instruction's bytes.
    for role, want in (('seeded_hasher', [0x47444eb, 0x4744502]),
                       ('absorb', [])):
        a, b = OWNERS[role][:2]
        _off, raw = read(a, b - a)
        e8_sites = [a + i for i in range(len(raw)) if raw[i] == 0xe8]
        if e8_sites != want:
            raise ValueError(f'{role} raw call-byte census changed')

    # Whole-.text direct-call censuses.
    hasher_sites = _call_census(data, secs, HASHER)
    if hasher_sites != HASHER_CALL_SITES:
        raise ValueError('hasher call census changed')
    absorb_sites = _call_census(data, secs, ABSORB)
    if absorb_sites != ABSORB_CALL_SITES:
        raise ValueError('absorb call census changed')

    # (c) The four callers' LSDA tables and the coverage of every
    # hasher call site.
    tables = {}
    decoded = {}
    for role, va, want_entries, want_sha in (
            ('sibling_grow', SIBLING_LSDA_VA, SIBLING_LSDA_ENTRIES,
             SIBLING_LSDA_SHA256),
            ('caller_a', CALLER_A_LSDA_VA, CALLER_A_LSDA_ENTRIES,
             CALLER_A_LSDA_SHA256),
            ('caller_b', CALLER_B_LSDA_VA, CALLER_B_LSDA_ENTRIES,
             CALLER_B_LSDA_SHA256),
            ('caller_c', CALLER_C_LSDA_VA, CALLER_C_LSDA_ENTRIES,
             CALLER_C_LSDA_SHA256)):
        table, entries = _decode_lsda(read, va, BOUNDARIES[role][0])
        if entries != want_entries or table['sha256'] != want_sha:
            raise ValueError(f'{role} LSDA changed')
        tables[role] = table
        decoded[role] = entries
    if tables['sibling_grow']['action_table_head_hex'] != '7f00' or \
            tables['caller_a']['action_table_head_hex'] != '7f00' or \
            tables['caller_b']['action_table_head_hex'] != '0000' or \
            tables['caller_c']['action_table_head_hex'] != '0000':
        raise ValueError('an LSDA action-table head changed')
    coverage = {}
    for site, (role, (r_start, r_end), pad) in COVERAGE.items():
        covering = [e for e in decoded[role]
                    if e[0] <= site < e[0] + e[1]]
        if covering != [(r_start, r_end - r_start, pad, 0)]:
            raise ValueError(f'coverage changed for site {site:#x}')
        coverage[hex(site)] = {'caller': role,
                               'range': [hex(r_start), hex(r_end)],
                               'landing_pad': hex(pad)}

    # Byte pins, direct calls, slot calls.
    for va, want, _label in PINS:
        if read(va, len(bytes.fromhex(want)))[1] != bytes.fromhex(want):
            raise ValueError(f'byte pin changed at {va:#x}')
    for site, target, _label in DIRECT_CALL_PINS:
        if read(site, 5)[1] != _direct_call(site, target):
            raise ValueError(f'direct call changed at {site:#x}')
    for site, slot, _label in SLOT_CALL_PINS:
        if read(site, 6)[1] != _slot_bytes(site, slot):
            raise ValueError(f'slot call changed at {site:#x}')

    # The seeded-hasher identification constants.
    for va, want_hex in (SIPHASH_CONST_A, SIPHASH_CONST_B):
        if read(va, 16)[1].hex() != want_hex:
            raise ValueError('SipHash constant block changed')

    return {
        'target_sha256': SHA,
        'owners': owners,
        'boundaries': boundaries,
        'shims': shims,
        'unwind': unwinds,
        'personality': {'slot': hex(PERSONALITY_SLOT), 'type': 8,
                        'addend': hex(SHIMS['rust_personality'][0])},
        'dealloc_slot': {'slot': hex(DEALLOC_SLOT),
                         'addend': hex(DEALLOC_SHIM)},
        'instruction_census': {
            'seeded_hasher': {
                'instructions': hasher_census['instructions'],
                'calls': [{'site': hex(s), 'target': hex(t)}
                          for s, t in hasher_census['calls']],
                'branches': {},
                'divisions': [],
                'traps': []},
            'absorb': {
                'instructions': absorb_census['instructions'],
                'calls': [],
                'branches': {hex(k): hex(v) for k, v in
                             sorted(absorb_census['branches'].items())},
                'divisions': [],
                'traps': []}},
        'direct_call_census': {
            hex(HASHER): [hex(s) for s in hasher_sites],
            hex(ABSORB): [hex(s) for s in absorb_sites]},
        'lsda_tables': tables,
        'call_site_coverage': coverage,
        'siphash_constants': {
            hex(SIPHASH_CONST_A[0]): SIPHASH_CONST_A[1],
            hex(SIPHASH_CONST_B[0]): SIPHASH_CONST_B[1]},
        'methods': [
            'FDE/CIE records are re-derived from .eh_frame with the '
            'repository eh_frame_records parser; body extents and '
            'SHA-256 values are pinned for the two owner bodies, the '
            'six boundary bodies and the personality shim.',
            'The instruction censuses run over a native objdump '
            'linear decode that decode_export requires to be '
            'byte-exact and contiguous over each owner extent, '
            'cross-checked against an independent text parse; a raw '
            '0xe8-byte census of both bodies backstops the direct-'
            'call counts.',
            'LSDA call-site tables are decoded byte-by-byte under '
            'both header shapes present in the cluster (0x9b ttype '
            'offset and omitted ttype) and compared entry for '
            'entry; each blob is also pinned by SHA-256.',
            'Slot bindings come from .rela.dyn addends read at '
            'analysis time.',
            'Native objdump/readelf cross-checks run only in '
            'generate().',
        ],
        'verdict': (
            'The sibling grow\'s seeded hasher at 0x4744490 cannot '
            'itself panic, and neither can anything it calls.  Its '
            'own frame carries no landing pad -- the plain-zR CIE, '
            'no LSDA -- and needs none: the body is straight-line '
            'apart from two direct calls to the buffered absorb at '
            '0x4744980, and the absorb is a leaf whose fifteen '
            'branches all land inside its own extent, so the '
            'transitive call graph beneath the hasher closes after '
            'one step with no panic origin in it.  The coverage '
            'that does exist sits one frame up and is complete '
            'across the binary: every one of the hasher\'s six '
            'direct call sites lies in a padded LSDA range of its '
            'caller -- the sibling\'s two ranges on the pad helper '
            'and the marked-record cleanup, caller A\'s two ranges '
            'on its cleanup pads at 0x4749948 and 0x4749814, caller '
            'B\'s range on its decrement pad at 0x474a361 and '
            'caller C\'s range on its buffer-freeing pad at '
            '0x474bcb4 -- each dropping that caller\'s own state, '
            'never anything in the hasher\'s frame.'),
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
