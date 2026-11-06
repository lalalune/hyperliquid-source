"""RE-005 node 115: who writes the park / park_timeout pair.

Re-derives, from the authenticated hl-node 115 artifact
only: the predicate the two io-driver selectors
(0x5ce0160 park_timeout, 0x5ce0850 park) apply to the
pair they receive; the complete writer census for the
pair head {[+0] tag, [+8] word, [+0x10] pointer} across
.text rel32 references, stored pointers and .rela.dyn
addends; the single constructor (0x5ce01f0) and its two
variants (parker and poll) plus its tag-3 error exits;
the single installing builder (0x5cf9600) and its tag-3
rejection; the two scheduler passages (current_thread
snapshot / multi_thread Arc payload); and what the
three slow-path bodies behind the selectors actually
do (0x5ceed20 io poll, 0x5ce7380 signal drain,
0x5cee650 global refresh). Any drift in a body hash,
census, slot resolution, Location, byte pin, message
or sentinel site fails verification rather than
silently rewriting the packet.
"""

import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts' / 'node' / '115' / 'hl-node'
SNAPSHOT = 'artifacts/node/115/hl-node'
TARGET_SIZE = 105896032
TARGET_SHA256 = ('a6e2897cd051213d004802deca416e8eca62b7a8278'
                 'fa39f249e98c3867b5301')
WORK_ITEM = 'RE-005-node115-timeout-pair-writers'
OUT = ROOT / 'research' / 'work-items' / WORK_ITEM
SENTINEL = 0x8000000000000000


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def sections(data):
    check(data[:4] == b'\x7fELF', 'not an ELF')
    e_shoff = struct.unpack_from('<Q', data, 0x28)[0]
    e_shentsize = struct.unpack_from('<H', data, 0x3a)[0]
    e_shnum = struct.unpack_from('<H', data, 0x3c)[0]
    e_shstrndx = struct.unpack_from('<H', data, 0x3e)[0]
    raw = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        name, typ, flags, addr, offset, size = struct.unpack_from(
            '<IIQQQQ', data, off)
        raw.append({'name_idx': name, 'type': typ, 'flags': flags,
                    'address': addr, 'offset': offset, 'size': size})
    strsec = raw[e_shstrndx]
    strtab = data[strsec['offset']:strsec['offset'] + strsec['size']]
    for sec in raw:
        end = strtab.index(b'\x00', sec['name_idx'])
        sec['name'] = strtab[sec['name_idx']:end].decode()
    return raw


def read(va, data, size=None):
    for section in sections(data):
        start = section['address']
        if start <= va < start + section['size']:
            off = section['offset'] + (va - start)
            if size is None:
                return data[off:section['offset'] + section['size']]
            check(off + size <= section['offset'] + section['size'],
                  f'read overruns section at {va:#x}')
            return data[off:off + size]
    raise ValueError(f'no section holds {va:#x}')


def fde_map():
    text = subprocess.run(['readelf', '-wf', str(TARGET)],
                          check=True, capture_output=True,
                          text=True).stdout
    extents = {}
    for line in text.splitlines():
        if 'pc=' not in line:
            continue
        needle = line.split('pc=')[1].split()[0]
        lo, hi = needle.split('..')
        extents.setdefault(int(lo, 16), int(hi, 16))
    return extents


def body_record(data, start, end, want_sha, extents):
    check(extents.get(start) == end, f'no FDE for body {start:#x}')
    raw = read(start, data, end - start)
    digest = sha(raw)
    check(digest == want_sha, f'digest drift {start:#x}')
    offset = None
    for section in sections(data):
        if section['address'] <= start < (section['address']
                                          + section['size']):
            offset = section['offset'] + (start - section['address'])
    return {'start': hex(start), 'end': hex(end),
            'file_offset': hex(offset), 'bytes': end - start,
            'sha256': digest}


def owners(data):
    extents = fde_map()
    return {role: body_record(data, start, end, OWNER_SHA256[role],
                              extents)
            for role, (start, end) in OWNERS.items()}


def pinned_bodies(data):
    extents = fde_map()
    records = {}
    for role, (start, end, want) in PINNED_BODIES.items():
        rec = body_record(data, start, end, want, extents)
        rec['note'] = 'extent/digest only; not exported'
        records[role] = rec
    return records


def frame_lines():
    text = subprocess.run(['readelf', '-wf', str(TARGET)],
                          check=True, capture_output=True,
                          text=True).stdout
    wanted = []
    spans = list(OWNERS.values())
    spans += [(s, e) for s, e, _ in PINNED_BODIES.values()]
    for start, end in spans:
        needle = f'pc={start:016x}..{end:016x}'
        wanted += [ln for ln in text.splitlines() if needle in ln]
    check(len(wanted) == len(spans), 'frame lines missing')
    return [line + '\n' for line in wanted]


def exports(role):
    start, end = OWNERS[role]
    text = subprocess.run(
        ['objdump', '-d', '-M', 'intel', '--no-show-raw-insn',
         '--start-address', hex(start), '--stop-address', hex(end),
         str(TARGET)], check=True, capture_output=True,
        text=True).stdout
    return text.replace(str(TARGET), SNAPSHOT, 1)


def disasm_rows(start, end):
    text = subprocess.run(
        ['objdump', '-d', '--start-address', hex(start),
         '--stop-address', hex(end), str(TARGET)],
        check=True, capture_output=True, text=True).stdout
    rows = []
    pat = re.compile(r'^\s+([0-9a-f]+):\t((?:[0-9a-f]{2} )+)\s*'
                     r'\t(.*)$')
    for line in text.splitlines():
        m = pat.match(line)
        if m:
            rows.append((int(m.group(1), 16), m.group(3).strip()))
    return rows


def relocations(data):
    """offset -> list of (type, sym_index, addend) for every
    SHT_RELA section."""
    out = {}
    for sec in sections(data):
        if sec['type'] != 4:  # SHT_RELA
            continue
        for i in range(sec['size'] // 24):
            off = sec['offset'] + i * 24
            r_off, r_info, r_add = struct.unpack_from(
                '<QQq', data, off)
            out.setdefault(r_off, []).append(
                (r_info & 0xffffffff, r_info >> 32, r_add))
    return out


def dynsym_names(data):
    secs = {s['name']: s for s in sections(data)}
    sym = secs.get('.dynsym')
    strs = secs.get('.dynstr')
    if not sym or not strs:
        return {}
    strtab = data[strs['offset']:strs['offset'] + strs['size']]
    names = {}
    for i in range(sym['size'] // 24):
        off = sym['offset'] + i * 24
        name_idx = struct.unpack_from('<I', data, off)[0]
        if name_idx:
            end = strtab.index(b'\x00', name_idx)
            names[i] = strtab[name_idx:end].decode()
    return names


SLOTS_EXPECTED = {
    0x64df480: ('relative', '0x6355830'),
    0x64df4a0: ('relative', '0x635de30'),
    0x64df508: ('glob_dat', 'memcpy'),
    0x64dfe40: ('relative', '0x5ceafd0'),
    0x64dfe78: ('glob_dat', 'close'),
    0x64e01e8: ('relative', '0x5ce57c0'),
    0x64e01f8: ('relative', '0x5bb59d0'),
    0x64e0f38: ('relative', '0x5bb5650'),
    0x64e0ff0: ('relative', '0x5bb2440'),
    0x64e1000: ('relative', '0x5bb35f0'),
    0x64e12c0: ('glob_dat', 'epoll_ctl'),
    0x64e1760: ('relative', '0x5cf9600'),
    0x64e1768: ('relative', '0x5cde590'),
    0x64e1790: ('relative', '0x5cfb610'),
    0x64e1798: ('relative', '0x5cfb920'),
    0x64e8a18: ('glob_dat', 'fcntl'),
    0x64eb050: ('glob_dat', 'eventfd'),
    0x64eb058: ('glob_dat', 'epoll_create1'),
    0x64eb060: ('glob_dat', 'epoll_wait'),
    0x64eb080: ('glob_dat', 'recv'),
    0x64ecba8: ('relative', '0x5cfcc50'),
}


def resolve_slots(data):
    rela = relocations(data)
    names = dynsym_names(data)
    records = {}
    for slot, want in SLOTS_EXPECTED.items():
        entries = rela.get(slot, [])
        check(len(entries) == 1, f'slot {slot:#x} rela count drift')
        typ, sym_idx, add = entries[0]
        if typ == 8:
            got = ('relative', hex(add))
        elif typ == 6:
            got = ('glob_dat', names.get(sym_idx, '').split('@')[0])
        else:
            got = (f'type{typ}', hex(add))
        check(got == want, f'slot {slot:#x} resolution drift: {got}')
        records[hex(slot)] = {'kind': got[0], 'value': got[1]}
    return records


def body_start_of(extents, va):
    best = None
    for start, end in extents.items():
        if start <= va < end and (best is None or start > best):
            best = start
    return best


def rel32_census(data, targets, extents):
    text_sec = next(s for s in sections(data)
                    if s['name'] == '.text')
    base = text_sec['address']
    raw = data[text_sec['offset']:text_sec['offset']
               + text_sec['size']]
    wanted = set(targets.values())
    found = {t: [] for t in wanted}
    for i in range(len(raw) - 5):
        op = raw[i]
        if op == 0xE8 or op == 0xE9:
            rel = struct.unpack_from('<i', raw, i + 1)[0]
            tgt = base + i + 5 + rel
            if tgt in wanted:
                found[tgt].append(
                    (base + i, 'call' if op == 0xE8 else 'jmp'))
    out = {}
    for role, va in targets.items():
        out[role] = [{'site': hex(s), 'kind': k,
                      'in_body': hex(body_start_of(extents, s))}
                     for (s, k) in sorted(found[va])]
    return out


def rela_refs(data, targets):
    rela = relocations(data)
    out = {}
    for role, va in targets.items():
        hits = []
        for off, entries in rela.items():
            for (typ, _sym, add) in entries:
                if add == va:
                    hits.append({'slot': hex(off), 'type': typ})
        out[role] = sorted(hits, key=lambda h: h['slot'])
    return out


def stored_ptr_refs(data, targets):
    pats = {role: struct.pack('<Q', va) for role, va in
            targets.items()}
    out = {role: [] for role in targets}
    for sec in sections(data):
        if sec['type'] != 1:  # SHT_PROGBITS only
            continue
        if sec['flags'] & 0x4:  # SHF_EXECINSTR
            continue
        if sec['name'].startswith('.rela'):
            continue
        raw = data[sec['offset']:sec['offset'] + sec['size']]
        for role, pat in pats.items():
            i = 0
            while True:
                j = raw.find(pat, i)
                if j < 0:
                    break
                out[role].append(
                    hex(sec['address'] + j))
                i = j + 1
    return out


def locations_record(data):
    rela = relocations(data)
    records = {}
    all_bodies = dict(OWNERS)
    all_bodies.update({r: (s, e) for r, (s, e, _w)
                       in PINNED_BODIES.items()})
    all_bodies['ctor'] = OWNERS['ctor']
    for role, expected in LOCATIONS_EXPECTED.items():
        start, end = all_bodies[role]
        found = {}
        for (_va, text) in disasm_rows(start, end):
            for m in re.finditer(r'#\s+([0-9a-f]+)\b', text):
                cand = int(m.group(1), 16)
                if not (0x6400000 <= cand < 0x6600000):
                    continue
                for (typ, _sym, add) in rela.get(cand, []):
                    if typ != 8:
                        continue
                    raw = read(add, data, 200)
                    nul = raw.find(b'\x00')
                    path = raw[:nul if nul >= 0 else 200]
                    try:
                        path = path.decode('utf-8')
                    except UnicodeDecodeError:
                        continue
                    if '.rs' not in path or '/' not in path:
                        continue
                    line, col = struct.unpack_from(
                        '<II', read(cand + 16, data, 8))
                    found[hex(cand)] = (hex(cand), path, line, col)
        got = sorted(found.values())
        want = sorted(expected)
        check(got == want,
              f'location drift for {role}: {got} != {want}')
        records[role] = [{'static': s, 'path': p, 'line': ln,
                          'col': c} for (s, p, ln, c) in got]
    return records


def movabs_sites(data):
    pat = struct.pack('<Q', SENTINEL)
    records = {}
    all_bodies = dict(OWNERS)
    all_bodies.update({r: (s, e) for r, (s, e, _w)
                       in PINNED_BODIES.items()})
    for role, want in MOVABS_EXPECTED.items():
        start, end = all_bodies[role]
        raw = read(start, data, end - start)
        sites = []
        i = 0
        while True:
            j = raw.find(pat, i)
            if j < 0:
                break
            sites.append(hex(start + j))
            i = j + 1
        check(sites == want,
              f'sentinel sites drift for {role}: {sites}')
        records[role] = sites
    return records


PINS = {
    0x5ce06a4: '48c70303000000',
    0x5cf967e: '4983fc03',
    0x5cf9700: '4983fc03',
    0x5ce02c2: '48b90000000000000080',
    0x5ceedf3: '8b7b18',
    0x5ce7391: '0fb6471cc6471c00',
    0x5ce73d2: '8b5f28',
}

MOVABS_EXPECTED = {
    'sel_timeout': [],
    'sel_park': [],
    'ctor': ['0x5ce02c4', '0x5ce036f'],
    'forwarder': ['0x5cfdd8e', '0x5cfdf65'],
    'poll_new': ['0x5ceebab', '0x5ceebe2', '0x5ceec1d'],
    'waker_reg': ['0x5ce72b2', '0x5ce7306'],
    'builder': ['0x5cf9958', '0x5cf9bb0'],
    'slow_a_poll': [],
    'slow_b_signal': [],
    'slow_c_refresh': [],
}

MESSAGES = {
    0x94ca03: ('A Tokio 1.x context was found, but IO is '
               'disabled. Call `enable_io` on the runtime '
               'builder to enable IO.'),
    0x94db81: 'driver missing',
    0x454b60: 'EOF on self-pipe',
    0x443685: '.unexpected error when polling the I/O driver: ',
}

RELA_REFS_EXPECTED = {
    'builder': [{'slot': '0x64e1760', 'type': 8}],
    'top_a1_ct': [{'slot': '0x64e1790', 'type': 8}],
    'top_a2_ct': [{'slot': '0x64e1798', 'type': 8}],
}
OWNERS = {
    'sel_timeout': (0x5ce0160, 0x5ce01e9),
    'sel_park': (0x5ce0850, 0x5ce08dc),
    'forwarder': (0x5cfdd00, 0x5cfe0e9),
    'ctor': (0x5ce01f0, 0x5ce084b),
    'poll_new': (0x5ceeae0, 0x5ceed20),
    'waker_reg': (0x5ce71f0, 0x5ce7374),
    'builder': (0x5cf9600, 0x5cfa8b1),
    'top_a1_ct': (0x5cfb610, 0x5cfb77a),
    'top_a2_ct': (0x5cfb920, 0x5cfbddb),
    'reg_a_ct': (0x5cfb780, 0x5cfb919),
    'reg_b_mt': (0x5cec8b0, 0x5cecc58),
    'park_entry_mt': (0x5ce2fd0, 0x5ce30c7),
    'slow_a_poll': (0x5ceed20, 0x5ceeff9),
    'slow_b_signal': (0x5ce7380, 0x5ce75a6),
    'slow_c_refresh': (0x5cee650, 0x5cee8f7),
}
PINNED_BODIES = {
    'top_b_mt': (0x5cecc60, 0x5cedd12, '6daa4de9236c851758d6f62ee795cdd95d9450cb932fe723046dd5218d53604d'),
    'park_body': (0x5cfdb90, 0x5cfdcd1, '9dc44a93c0da072cf5a3b6d11462c014b695de176ed7fb01fb09b7e3ac5dcc2e'),
    'park_timeout_body': (0x5cfd9a0, 0x5cfdb8d, '411cc42aff700d68883fd2371a63226cf62e426c5530e188ed619f6fb98cbef5'),
}
OWNER_SHA256 = {
    'sel_timeout': 'f0eb5ff4372093ba8f617e6f52555f35e6f4e77659dc9928372825790444357b',
    'sel_park': 'b0882248d77cea8ba4ee9d4fae1b1f50c69bb5cba4e7dcd01ddd777981a6caa9',
    'forwarder': '2d8ea94341d17a31bd755de9d3226f6911a337d3a6c97134ed1721c6a097c647',
    'ctor': '90919826d6842d84b3b1229420978c82d49b767f5c609650b17c3785a73e0cba',
    'poll_new': 'fa4bb2a034f3b5d5d1ca3569b76fdb6e4d59bd32a3a9f2c701bf9abd7bfa9a64',
    'waker_reg': '53d22092e6cf21707c22a3c004e2ef4ea4089a642db1c457f340b535b17853a9',
    'builder': '12813161d76cb5aa11039d12cbbf45d6f170b2aa53da586df8e03b579e02d13b',
    'top_a1_ct': 'a8c6ab86806fc95db1800ecd0dbe1879ad987c51ff7361aadbcedc5f80cc8640',
    'top_a2_ct': 'c0182c69f7564a102b726d9fc4a38df8418bf923f073d16e92e0ecbede1b344c',
    'reg_a_ct': '3be383ace482e644674d7916cca63e4a37988f50c0ce1478256c16df4dfb4139',
    'reg_b_mt': 'e732e6851f0a42f5bbf4bcb63d5a44f8e1a030d7428404c514f5af8f92103a77',
    'park_entry_mt': '17d62a55fe9d639eee5e5d26f3694a090f7f07e629ca729d11bc66c31d3e0e37',
    'slow_a_poll': 'db225d79160a4dbfd379cb0f603e5a8c3afe77a41c50f154900c87d39349e240',
    'slow_b_signal': 'b0d541b3058ae4035211645b3440e15a0e391b25347f1729f06787bdf6aff06f',
    'slow_c_refresh': '99aec8bb669106276f9784e558325882a2bd5a3e13e28bb7aa714da1846d4d01',
}
CENSUS_EXPECTED = {
    'sel_timeout': [('0x5ce2ff3', 'call', '0x5ce2fd0'), ('0x5ce3045', 'call', '0x5ce2fd0'), ('0x5cfb801', 'call', '0x5cfb780')],
    'ctor': [('0x5cf9669', 'call', '0x5cf9600'), ('0x5cf96eb', 'call', '0x5cf9600')],
    'sel_park': [('0x5ce3022', 'call', '0x5ce2fd0'), ('0x5cec986', 'call', '0x5cec8b0'), ('0x5cfb7f6', 'call', '0x5cfb780')],
    'park_entry_mt': [('0x5cec9d9', 'call', '0x5cec8b0')],
    'slow_b_signal': [('0x5ce01b8', 'call', '0x5ce0160'), ('0x5ce08ab', 'call', '0x5ce0850'), ('0x5cfdfe3', 'call', '0x5cfdd00')],
    'slow_c_refresh': [('0x5ce01cb', 'jmp', '0x5ce0160'), ('0x5ce08be', 'jmp', '0x5ce0850'), ('0x5cfdfef', 'call', '0x5cfdd00')],
    'slow_a_poll': [('0x5ce01b0', 'call', '0x5ce0160'), ('0x5ce08a3', 'call', '0x5ce0850'), ('0x5cfdfdb', 'call', '0x5cfdd00')],
    'poll_new': [('0x5ce0218', 'call', '0x5ce01f0')],
    'waker_reg': [('0x5ce02bd', 'call', '0x5ce01f0')],
    'reg_b_mt': [('0x5cece59', 'call', '0x5cecc60'), ('0x5ced567', 'call', '0x5cecc60'), ('0x5ced78d', 'call', '0x5cecc60')],
    'top_b_mt': [('0x5cfa8e3', 'call', '0x5cfa8c0')],
    'builder': [],
    'top_a1_ct': [],
    'reg_a_ct': [('0x5cfb680', 'call', '0x5cfb610'), ('0x5cfba84', 'call', '0x5cfb920'), ('0x5cfbbf3', 'call', '0x5cfb920')],
    'top_a2_ct': [],
    'forwarder': [('0x5ce019f', 'jmp', '0x5ce0160'), ('0x5ce088d', 'jmp', '0x5ce0850')],
    'park_body': [('0x158e6dc', 'call', '0x158cdc0'), ('0x158f415', 'call', '0x158f270'), ('0x2ae1ac7', 'call', '0x2ae1690'), ('0x2b14bb4', 'call', '0x2b149d0'), ('0x5ab7137', 'call', '0x5ab6df0'), ('0x5ce087c', 'jmp', '0x5ce0850'), ('0x5cfd7f5', 'call', '0x5cfd6a0'), ('0x5cfdf8b', 'call', '0x5cfdd00')],
    'park_timeout_body': [('0x5ce0193', 'jmp', '0x5ce0160'), ('0x5cf29c8', 'call', '0x5cf27c0'), ('0x5cfdeab', 'call', '0x5cfdd00'), ('0x5cfdfa5', 'call', '0x5cfdd00')],
}
LOCATIONS_EXPECTED = {
    'sel_timeout': [('0x64c64b0', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/io/driver.rs', 165, 32)],
    'sel_park': [('0x64c64c8', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/io/driver.rs', 160, 32)],
    'ctor': [('0x64c6080', '/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/alloc/src/sync.rs', 1930, 13)],
    'forwarder': [('0x64c64b0', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/io/driver.rs', 165, 32), ('0x64c64c8', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/io/driver.rs', 160, 32), ('0x64c6f78', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/time/mod.rs', 214, 32), ('0x64c6f90', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/time/mod.rs', 217, 9)],
    'slow_a_poll': [('0x64c64e0', '/home/ubuntu/hl/code_Mainnet/z_vendor/mio/src/event/events.rs', 212, 9), ('0x64c64f8', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/io/driver.rs', 221, 17), ('0x64c6510', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/io/driver.rs', 196, 23)],
    'slow_b_signal': [('0x64c5f80', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/signal/mod.rs', 118, 26), ('0x64c5f98', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/signal/mod.rs', 121, 27)],
    'slow_c_refresh': [],
    'reg_a_ct': [('0x64c6d10', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/current_thread/mod.rs', 491, 50), ('0x64c6d28', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/current_thread/mod.rs', 491, 30), ('0x64c6d40', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/current_thread/mod.rs', 485, 20), ('0x64c6dd0', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/defer.rs', 33, 47)],
    'reg_b_mt': [('0x64c59c0', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/multi_thread/park.rs', 271, 18), ('0x64c59d8', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/multi_thread/park.rs', 258, 28), ('0x64c62c0', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/multi_thread/worker.rs', 862, 41), ('0x64c62d8', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/multi_thread/worker.rs', 909, 46), ('0x64c62f0', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/multi_thread/worker.rs', 909, 26), ('0x64c6308', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/multi_thread/worker.rs', 864, 20), ('0x64c6dd0', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/defer.rs', 33, 47)],
    'top_a1_ct': [('0x64c6c98', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/current_thread/mod.rs', 449, 45)],
    'top_a2_ct': [('0x64c6cb0', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/current_thread/mod.rs', 411, 45), ('0x64c6cc8', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/metrics/batch.rs', 186, 17), ('0x64c6ce0', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/metrics/batch.rs', 187, 17), ('0x64c6cf8', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/metrics/batch.rs', 208, 9), ('0x64c6d10', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/current_thread/mod.rs', 491, 50), ('0x64c6d28', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/current_thread/mod.rs', 491, 30), ('0x64c6d40', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/current_thread/mod.rs', 485, 20), ('0x64c6e00', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/defer.rs', 29, 23)],
    'park_entry_mt': [('0x64c59c0', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/multi_thread/park.rs', 271, 18), ('0x64c59d8', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/multi_thread/park.rs', 258, 28)],
    'builder': [('0x64c66a0', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/handle.rs', 90, 25), ('0x64c6768', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/context/current.rs', 53, 9), ('0x64c6780', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/context/current.rs', 50, 46), ('0x64c6b10', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/builder.rs', 2014, 54)],
    'poll_new': [],
    'waker_reg': [],
    'top_b_mt': [('0x64c5a68', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/multi_thread/queue.rs', 118, 9), ('0x64c5a80', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/multi_thread/queue.rs', 382, 17), ('0x64c61d0', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/multi_thread/worker.rs', 1165, 21), ('0x64c61e8', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/multi_thread/worker.rs', 1172, 27), ('0x64c6200', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/multi_thread/worker.rs', 1278, 22), ('0x64c6218', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/util/sharded_list.rs', 123, 9), ('0x64c6230', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/multi_thread/worker.rs', 1307, 22), ('0x64c6260', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/multi_thread/worker.rs', 1077, 12), ('0x64c6278', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/multi_thread/worker.rs', 1124, 17), ('0x64c62a8', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/multi_thread/worker.rs', 795, 12), ('0x64c6320', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/metrics/batch.rs', 186, 17), ('0x64c6338', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/metrics/batch.rs', 187, 17), ('0x64c6350', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/multi_thread/worker.rs', 833, 30), ('0x64c6368', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/metrics/batch.rs', 208, 9), ('0x64c6e00', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/defer.rs', 29, 23)],
    'park_body': [('0x64c6f48', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/park.rs', 107, 28)],
    'park_timeout_body': [('0x64c6f18', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/park.rs', 173, 18), ('0x64c6f30', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/park.rs', 153, 28)],
}

FINDINGS = [
    'The two selectors read a 0x40-byte pair {+0 tag, +8 word, '
    '+0x10 pointer}: sel_park 0x5ce0850 (io/driver.rs:160:32) '
    'and sel_timeout 0x5ce0160 (io/driver.rs:165:32). Tag 0 '
    'tail-jumps to the forwarder 0x5cfdd00; any other tag '
    'takes the fast arm iff [pair+8] == INT64_MIN '
    '(0x8000000000000000), jumping to the park body '
    '0x5cfdb90 / park_timeout body 0x5cfd9a0 with '
    'rdi = [pair+0x10] + 0x10 and the (secs, nanos) '
    'arguments; otherwise it runs slow_a 0x5ceed20, '
    'slow_b 0x5ce7380 and tail-jumps slow_c 0x5cee650 on '
    'X = pair+8. The forwarder re-tests [arg+0] against '
    'INT64_MIN on its own (sentinel immediates at '
    '0x5cfdd8e and 0x5cfdf65) before its own calls to the '
    'same three bodies.',
    'Writer census (full .text rel32 + every stored '
    'pointer in non-executable sections + every .rela.dyn '
    'addend): the pair head is written by exactly one '
    'constructor, 0x5ce01f0, behind exactly one installing '
    'builder, 0x5cf9600 (builder.rs:2014:54); the only '
    'other head stores are the current_thread park '
    'entries transient 3 marker. No pinned body except '
    'the builder and the two current_thread tops is named '
    'by any stored pointer or relocation; the selectors, '
    'forwarder, three slow bodies, constructor, poll '
    'constructor, waker registration, register bodies and '
    'park entry are reached by direct rel32 references '
    'only.',
    'The constructor takes its variant and tag bits from '
    'two independent bytes of the config the builder '
    'builds from its own config u16 at +0xe5: the low '
    'byte (constructor config +8) selects the variant, '
    'the byte at constructor config +9 selects the tag. '
    'The shared write block at 0x5ce0442 writes only tag '
    '0 (byte == 1) or tag 2 (byte != 1) on success.',
    'Parker variant (variant byte 0): Poll::new is never '
    'called; the head is {tag, INT64_MIN, pointer}, the '
    'pointer being the fresh 0x28-byte parker allocation '
    'the RE-005 TLS value-object packet identified (the '
    'sentinel is materialised at 0x5ce036d and lands at '
    '[pair+8]; the allocation pointer lands at '
    '[pair+0x10]).',
    'Poll variant (variant byte != 0): poll_new '
    '0x5ceeae0 builds the poll object {+0 capacity, +8 '
    'events buffer, +0x10 0, +0x18 epoll fd, +0x30 the '
    '0x10 key word, +0x38 the 0x80-byte registry buffer, '
    '+0x60 fcntl result, +0x64 eventfd} and waker_reg '
    '0x5ce71f0 returns {capacity, events buffer, 0, epoll '
    'fd, registration Arc, token}; through the shared '
    'write block the installed 0xd8-byte driver value '
    'carries the head {tag, capacity, events buffer, 0 '
    'count, epoll fd} with the poll object embedded at '
    '+0x40.',
    'Tag 3 is an error encoding and is never installed: '
    'a poll_new failure (first sret word == INT64_MIN) '
    'exits the constructor through 0x5ce06a0 with '
    '{[+0] = 3, [+8] = (errno << 32) | 2}; a waker_reg '
    'failure (registration word == INT64_MIN, compared '
    'at 0x5ce02c2) reaches the same tail. The builder '
    'compares the constructed tag against 3 at both call '
    'sites (0x5cf967e, 0x5cf9700) and converts a tag-3 '
    'result into its own error return; it installs the '
    'value (memcpy through slot 0x64df508) only for '
    'tags 0 and 2.',
    'current_thread passage: the two top entries '
    '(current_thread/mod.rs:449:45 at 0x5cfb610 and '
    ':411:45 at 0x5cfb920) snapshot [O+0..0x40) of the '
    'stored 0x98-byte object O to the stack, write 3 '
    'into [O+0] (panicking "driver missing" if it was '
    'already 3), call reg_a 0x5cfb780 with the SNAPSHOT '
    'as the selector pair, then write the snapshot back. '
    'The pair the selectors see therefore carries the '
    'pre-existing installed head; the 3 exists only in '
    'the stored object while a park is in flight. reg_a '
    'also drains the registry waker queue at [S+0x28] '
    'after parking.',
    'multi_thread passage: reg_b 0x5cec8b0 '
    '(worker.rs:862:41) takes T = [P+8] out of the '
    '0x78-byte worker park object, zeroes [P+8], and '
    'forms the pair base as [T+0x10] + 0x10; the park '
    'entry 0x5ce2fd0 (multi_thread/park.rs:258:28, '
    '271:18) runs the state-word protocol on [T+0x18] '
    'and calls sel_timeout with (0, 0) or the computed '
    '(secs, nanos), sel_park when nanos is the sentinel; '
    'reg_b also calls sel_park directly at 0x5cec986.',
    'slow_a 0x5ceed20 is the I/O poll (mio '
    'event/events.rs:212:9, io/driver.rs:196:23 and '
    ':221:17): it converts (secs, nanos) to a saturating '
    'millisecond timeout (nanos == sentinel means -1), '
    'calls epoll_wait through slot 0x64eb060 with fd '
    '[X+0x18], buffer [X+8], maxevents dword [X+0], '
    'stores the returned count at [X+0x10], then walks '
    'the 12-byte events: data 0 skipped, data 1 sets '
    'byte [X+0x1c] = 1, a data pointer CAS-merges event '
    'bits into [data+0x10] and calls the wake body '
    '0x5cfd1d0. EINTR returns through helper 0x5cee460; '
    'any other failure panics with ".unexpected error '
    'when polling the I/O driver: ".',
    'slow_b 0x5ce7380 is the signal drain (signal/mod.rs'
    ':118:26, :121:27): it reads byte [X+0x1c], clears '
    'it and returns at once unless it was 1; then it '
    'drains the self-pipe fd dword [X+0x28] with recv '
    'through slot 0x64eb080 ("EOF on self-pipe" panic), '
    'unregisters the current thread through helpers '
    '0x5ce6df0 / 0x5ce6eb0, and sweeps the global '
    'registry at 0x64fee28 (count 0x64fee30, stride '
    '0x20): entries with flag byte +8 set have their '
    'object lock word [obj+0x130] CASed 0->8, counter '
    '[obj+0x138] incremented by 2, and the callback in '
    'slot 0x64ecba8 (-> 0x5cfcc50) invoked on obj+0x10.',
    'slow_c 0x5cee650 is a global cached-object refresh '
    'keyed by the pair+0x38 value alone (its argument is '
    'pair+0x38, used only as a key): it claims lock byte '
    '0x64fee00 bit 0 (returning at once if already set), '
    'returns after unlocking if the cached object '
    '0x64fee08 satisfies [obj+0x138] & ~1 == 0x64fee10, '
    'and otherwise looks up a replacement through '
    '0x5cde710 (17-byte key), decrements the old '
    "object's Arc count at [obj+0x140], swaps the "
    'globals and notifies through 0x5cee900. It '
    'references no panic Location.',
    'Answer to the chased question: pairs with '
    'discriminator > 1 ARE constructed - tag 2 is one of '
    'the two success tags, written by the constructor '
    'whenever the builder config tag byte is not 1, in '
    'both variants - but the slow path is not selected '
    'by the tag. It is selected by [pair+8] != INT64_MIN, '
    'i.e. by the poll variant: a tag-2 parker-variant '
    'pair takes the fast arm, and the only constructed '
    'heads outside the poll variant with [pair+8] != '
    'INT64_MIN are the tag-3 error values the builder '
    'discards.',
]

OPEN_EDGES = [
    'The constructor Poll-path registration loop '
    '(0x5ce05ab..0x5ce0676) can divert to the tag-3 exit '
    'on its exit compare at 0x5ce066d (rcx against the '
    'capacity word); under which builder configurations '
    'that diversion fires is not settled here.',
    'The global object slow_c refreshes (cached at '
    '0x64fee08, key word 0x64fee10, lookup 0x5cde710 on '
    'a 17-byte key) is not identified here.',
    'The two constructor config bytes (config +8 low '
    'byte, config +9) are recorded mechanically from the '
    'builder config u16 at +0xe5; which source-level '
    'Builder settings set them is not named here.',
    'The construction provenance of the multi_thread '
    'worker park object (the 0x78-byte object reg_b '
    'unwraps) is outside this packet; the RE-005 '
    'park_timeout provenance packet covers the (0, 0) / '
    '(0, sentinel) supply side.',
]


def analyze(data):
    check(len(data) == TARGET_SIZE, 'artifact size drift')
    check(sha(data) == TARGET_SHA256, 'artifact sha drift')
    for va, want in PINS.items():
        raw = read(va, data, len(want) // 2)
        check(raw.hex() == want, f'pin drift at {va:#x}')
    extents = fde_map()
    all_targets = dict(OWNERS)
    all_targets.update({r: (s, e) for r, (s, e, _w)
                        in PINNED_BODIES.items()})
    starts = {role: span[0] for role, span in
              all_targets.items()}
    census = rel32_census(data, starts, extents)
    for role in all_targets:
        want = [tuple(x) for x in CENSUS_EXPECTED[role]]
        got = [(c['site'], c['kind'], c['in_body'])
               for c in census[role]]
        check(got == want, f'call census drift for {role}')
    rrefs = rela_refs(data, starts)
    for role, hits in rrefs.items():
        want = RELA_REFS_EXPECTED.get(role, [])
        check(hits == want, f'rela refs drift for {role}: {hits}')
    srefs = stored_ptr_refs(data, starts)
    for role, hits in srefs.items():
        check(hits == [], f'stored ptr refs for {role}: {hits}')
    for va, text in MESSAGES.items():
        raw = read(va, data, len(text.encode()))
        check(raw.decode() == text, f'message drift at {va:#x}')
    records = {
        'artifact': {'size': TARGET_SIZE,
                     'sha256': TARGET_SHA256},
        'work_item': WORK_ITEM,
        'owners': owners(data),
        'pinned_bodies': pinned_bodies(data),
        'slots': resolve_slots(data),
        'locations': locations_record(data),
        'call_census': census,
        'rela_refs': rrefs,
        'stored_ptr_refs': srefs,
        'sentinel_sites': movabs_sites(data),
        'pins': {hex(va): want for va, want in PINS.items()},
        'messages': {hex(va): text for va, text
                     in MESSAGES.items()},
        'findings': FINDINGS,
        'open_edges': OPEN_EDGES,
    }
    return records


def generate(records):
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / 'records.json').write_text(
        json.dumps(records, indent=1, sort_keys=True) + '\n')
    for role in OWNERS:
        (OUT / f'{role}.objdump.txt').write_text(exports(role))
    (OUT / 'frames.txt').write_text(''.join(frame_lines()))
    manifest = []
    for path in sorted(OUT.iterdir()):
        if path.name == 'MANIFEST.sha256':
            continue
        manifest.append(f'{sha(path.read_bytes())}  {path.name}\n')
    (OUT / 'MANIFEST.sha256').write_text(''.join(manifest))


def main(argv):
    data = TARGET.read_bytes()
    records = analyze(data)
    if '--generate' in argv:
        generate(records)
        print(json.dumps({'generated': True}))
        return 0
    expected = json.loads((OUT / 'records.json').read_text())
    print(json.dumps({'matches': records == expected}))
    return 0 if records == expected else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
