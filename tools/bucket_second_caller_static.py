"""Static evidence for the RE-005 bucket-second-caller packet.

Answers, for the authenticated hl-node 115 artifact only
(the open edge the insert-return packet, PR #2651,
recorded but did not census): the bucket body
0x5ce29a0 has exactly two direct callers - the
predicate-chain setter 0x5cea7c0 at 0x5cea839 (pinned by
PR #2617) and a second call site at 0x5ceb06e.  This
packet traces the second caller's owner body
0x5ceafd0..0x5ceb1a4 end to end:

1.  Owner and dispatch: the second caller is a 468-byte
    body with no direct call or jump references anywhere
    in .text and no rip-relative references; the only
    reference to its start in the artifact is one
    R_X86_64_RELATIVE addend at 0x64dfe40, a code-pointer
    table slot in .data.rel.ro - it is reached through
    data, not through a call site.
2.  The call at 0x5ceb06e: which conditions reach it
    (timers guard, wheel lock, value-slot gate, the
    [entry+0x10] == -1 inline arm), the exact argument
    setup (rdi = level bucket of the same wheel,
    rsi = the entry at &[S+0x20] - the same entry object
    the setter passes), and the bucket body's own traps.
3.  Consumption: the bucket body's return value is
    ignored; the caller then consumes the entry in
    place (fired byte cleared, value slot := -1, the
    wake pair claimed on the shared state word with a
    callback through [head+0x18]) and unlocks the wheel.
4.  Comparison with the known call path: the setter's
    pre-flag call at 0x5cea839 shares the gating, the
    level formula, the level-trap Location static, the
    inline wheel-list arm and the argument shape; it
    differs in the surrounding operation (pre-flag
    preliminary vs a standalone lock-owning removal),
    in the entry self pointer, in the timers guard, and
    in everything that happens after the call.

Method: both bodies are exported in full.  Store
censuses are taken over the disassembly.  Direct
callers of the bucket body and references to the second
caller are censused by whole-.text scans for relative
call/jump sites and rip-relative slot forms plus a
.rela.dyn addend scan.  Strings and tables resolve
through the section table (.rodata is identity-mapped;
.text resolves at VA-0x1000; .data.rel.ro at
VA-0x2000); GOT slots are resolved from .rela.dyn
addends; panic Location statics are read as raw qwords
plus their RELATIVE addend.
"""

import hashlib
import json
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from artifacts import ROOT  # noqa: E402
from elf_index import sections  # noqa: E402

TARGET = ROOT / 'artifacts' / 'node' / '115' / 'hl-node'
TARGET_SIZE = 105896032
TARGET_SHA256 = ('a6e2897cd051213d004802deca416e8eca62b7a8278'
                 'fa39f249e98c3867b5301')
WORK_ITEM = 'RE-005-node115-bucket-second-caller'
OUT = ROOT / 'research' / 'work-items' / WORK_ITEM
SNAPSHOT = '<authenticated-node115>'

OWNERS = {
    'caller': (0x5CEAFD0, 0x5CEB1A4),
    'bucket': (0x5CE29A0, 0x5CE2A76),
}
EXPORTED = list(OWNERS)

OWNER_SHA256 = {
    'caller': '5b1addcef08123e292e9e2110d74cdf9516ac713d91a'
              '19fb6a988b9bee7c52a3',
    'bucket': '7f1bf0ac13bf0df1287b21da22e231bf1b29ea287ea'
              '2182aa5b8433b1fef89d8',
}

# GOT slots: va -> expected R_X86_64_RELATIVE resolution.
SLOT_TARGETS = {
    0x64DF770: 0x1680BD0,   # assert-fail callee (timers)
    0x64DF620: 0x1680CBF,   # level assert callee
    0x64E01F8: 0x5BB59D0,   # contention wait (lock)
    0x64E0F38: 0x5BB5650,   # release fn (unlock tail)
    0x64DF4C0: 0x1680CAB,   # landing-pad cleanup callee
    0x64DF730: 0x1680E60,   # panic-format callee (bucket)
    0x64DF870: 0x1681DC0,   # overflow panic shim (bucket)
    0x64E0820: 0x1681E20,   # range panic shim (bucket)
}

STRINGS = {
    'timers_disabled': (0x94CA6B, 115,
                        'A Tokio 1.x context was found, but '
                        'timers are disabled. Call '
                        '`enable_time` on the runtime builder '
                        'to enable timers.'),
    'tail_assert': (0x94CB3F, 37,
                    'assertion failed: self.tail.is_none()'),
    'entry_rs': (0x44CEF5, 69,
                 '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/'
                 'src/runtime/time/entry.rs'),
    'wheel_rs': (0x446310, 73,
                 '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/'
                 'src/runtime/time/wheel/mod.rs'),
    'level_rs': (0x43A333, 75,
                 '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/'
                 'src/runtime/time/wheel/level.rs'),
    'linked_list_rs': (0x44AA38, 67,
                       '/home/ubuntu/hl/code_Mainnet/z_vendor/'
                       'tokio/src/util/linked_list.rs'),
}

# Panic Location statics in .data.rel.ro: the file qwords
# are [0, len, packed line/col]; the first field's target
# is the RELATIVE addend at the static's address.
LOCATIONS = {
    0x64C6158: (0x44CEF5, 69, 549, 30),    # entry.rs (timers)
    0x64C6A48: (0x446310, 73, 130, 17),    # wheel/mod.rs (lvl)
    0x64C5900: (0x43A333, 75, 173, 19),    # level.rs (mul)
    0x64C5918: (0x43A333, 75, 173, 6),     # level.rs (range)
    0x64C5930: (0x44AA38, 67, 188, 9),     # linked_list.rs
}

CONSTANTS = {
    'bucket_stride': 0x410,
    'bucket_slot_bytes': 16,
    'slots_per_bucket': 64,
    'level_magic_mul': 0x2B,
    'level_magic_shift': 8,
    'level_trap_threshold': 0x23,
    'level_clamp': '0xffffffffe',
    'bucket_shift_mul': 6,
    'bucket_shift_limit': 0x40,
    'bucket_header_offset': 0x400,
    'occupancy_mask_offset': 0x408,
    'timers_sentinel': 1000000000,
    'lock_timeout': 1000000000,
}

# Frozen instruction-byte pins: site -> bytes (hex).
PINS = {
    0x5CEB00A: 'f0410fb04f50',          # caller: lock wheel
    0x5CEB016: '498b4628',              # caller: rax=[C+0x28]
    0x5CEB030: '7443',                  # caller: je inline arm
    0x5CEB05D: '0f8705010000',          # caller: ja level trap
    0x5CEB063: '4869ff10040000',        # caller: rdi *= 0x410
    0x5CEB06A: '49037f58',              # caller: rdi += buckets
    0x5CEB06E: 'e82d79ffff',            # caller -> bucket call
    0x5CEB0BB: '41c6464800',            # consume: byte := 0
    0x5CEB0C0: '49c74628ffffffff',      # consume: slot := -1
    0x5CEB0FF: 'ff5018',                # consume: call [rax+0x18]
    0x5CEB106: 'f00fb00b',              # caller: unlock wheel
    0x5CE29A1: '4c8b4610',              # bucket: r8=[rsi+0x10]
    0x5CE29AA: '48f7a700040000',        # bucket: mul [rdi+0x400]
    0x5CE29C3: '49d3e8',                # bucket: shr r8, cl
    0x5CE2A31: '48318708040000',        # bucket: xor occupancy
    0x5CE2A43: '488d3df5a0c6fa',        # bucket: lea assert msg
    0x5CEA839: 'e86281ffff',            # setter -> bucket call
    0x5CEA7D8: 'f00fb00f',              # setter: lock wheel
}

STORE_MNEMS = {'mov', 'movq', 'movl', 'movw', 'movb', 'movups',
               'movaps', 'movsd', 'cmpxchg', 'xchg', 'xadd',
               'decq', 'incq', 'or', 'xor'}


def check(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


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


def fde_extents(data):
    with tempfile.NamedTemporaryFile(suffix='.bin',
                                     delete=False) as tmp:
        tmp.write(data)
        name = tmp.name
    try:
        text = subprocess.run(['readelf', '-wf', name],
                              check=True, capture_output=True,
                              text=True).stdout
    finally:
        Path(name).unlink()
    extents = set()
    for line in text.splitlines():
        if 'pc=' not in line:
            continue
        needle = line.split('pc=')[1].split()[0]
        lo, hi = needle.split('..')
        extents.add((int(lo, 16), int(hi, 16)))
    return extents


def owners(data):
    extents = fde_extents(data)
    records = {}
    for role, (start, end) in OWNERS.items():
        check((start, end) in extents, f'no FDE for {role}')
        raw = read(start, data, end - start)
        digest = sha(raw)
        check(digest == OWNER_SHA256[role], f'digest drift {role}')
        for section in sections(data):
            if section['address'] <= start < (section['address']
                                              + section['size']):
                offset = section['offset'] + (start
                                              - section['address'])
        records[role] = {
            'start': hex(start), 'end': hex(end),
            'file_offset': hex(offset), 'bytes': end - start,
            'sha256': digest}
    return records


def frame_lines(data):
    with tempfile.NamedTemporaryFile(suffix='.bin',
                                     delete=False) as tmp:
        tmp.write(data)
        name = tmp.name
    try:
        text = subprocess.run(['readelf', '-wf', name],
                              check=True, capture_output=True,
                              text=True).stdout
    finally:
        Path(name).unlink()
    wanted = []
    for start, end in OWNERS.values():
        needle = f'pc={start:016x}..{end:016x}'
        wanted += [ln for ln in text.splitlines() if needle in ln]
    check(len(wanted) == len(OWNERS), 'owner frame lines missing')
    return [line + '\n' for line in wanted]


def exports(data, role):
    start, end = OWNERS[role]
    text = subprocess.run(
        ['objdump', '-d', '-M', 'intel', '--no-show-raw-insn',
         '--start-address', hex(start), '--stop-address', hex(end),
         str(TARGET)],
        check=True, capture_output=True, text=True).stdout
    return text.replace(str(TARGET), SNAPSHOT, 1)


def disasm_rows(data, start, end):
    with tempfile.NamedTemporaryFile(suffix='.bin',
                                     delete=False) as tmp:
        tmp.write(data)
        name = tmp.name
    try:
        text = subprocess.run(
            ['objdump', '-d', '--start-address', hex(start),
             '--stop-address', hex(end), name],
            check=True, capture_output=True, text=True).stdout
    finally:
        Path(name).unlink()
    rows = []
    pat = re.compile(r'^\s+([0-9a-f]+):\t((?:[0-9a-f]{2} )+)'
                     r'\s*\t(.*)$')
    for line in text.splitlines():
        m = pat.match(line)
        if m:
            rows.append((int(m.group(1), 16), m.group(3).strip()))
    return rows


def store_census(data, start, end, bases=None):
    """All memory-writing instructions in [start, end).

    Returns [{'site', 'base', 'disp'}] in address order.  The
    destination operand of an AT&T store is its last operand;
    a destination is a memory operand iff it contains '(' or
    starts with '%fs:'.
    """
    found = []
    for va, ins in disasm_rows(data, start, end):
        text = ins.split('#')[0].strip()
        if not text:
            continue
        parts = text.split(None, 1)
        mnem = parts[0]
        if mnem == 'lock':
            sub = parts[1].split(None, 1)
            mnem = sub[0]
            rest = sub[1] if len(sub) > 1 else ''
        else:
            rest = parts[1] if len(parts) > 1 else ''
        if mnem not in STORE_MNEMS or not rest:
            continue
        operands = [o.strip() for o in rest.split(',')]
        dst = operands[-1]
        if '(' not in dst and not dst.startswith('%fs:'):
            continue
        if dst.startswith('%fs:'):
            base, disp = 'fs', None
        else:
            m = re.match(r'^(.*)\(%(\w+)', dst)
            check(m is not None, f'unparsed store dst {dst}')
            raw_disp, base = m.group(1), m.group(2)
            if raw_disp in ('', '+'):
                disp = 0
            else:
                disp = int(raw_disp, 0)
        if bases is not None and base not in bases:
            continue
        found.append({'site': hex(va), 'base': base, 'disp': disp})
    return found


def expect(found, wanted, label):
    got = [(e['site'], e['base'], e['disp']) for e in found]
    check(got == wanted, f'{label} census drift: {got}')
    return found


def store_censuses(data):
    caller_all = store_census(data, *OWNERS['caller'])
    expect(caller_all,
           [('0x5ceb00a', 'r15', 80), ('0x5ceb081', 'rcx', 8),
            ('0x5ceb08d', 'rax', 0), ('0x5ceb093', 'rsi', 0),
            ('0x5ceb0a2', 'r15', 104), ('0x5ceb0bb', 'r14', 72),
            ('0x5ceb0c0', 'r14', 40), ('0x5ceb0d7', 'r14', 64),
            ('0x5ceb0ec', 'r14', 48), ('0x5ceb0f6', 'r14', 64),
            ('0x5ceb106', 'rbx', 0), ('0x5ceb115', 'r15', 112),
            ('0x5ceb183', 'rbx', 0)],
           'caller')
    caller_r14 = store_census(data, *OWNERS['caller'],
                              bases={'r14'})
    expect(caller_r14,
           [('0x5ceb0bb', 'r14', 72), ('0x5ceb0c0', 'r14', 40),
            ('0x5ceb0d7', 'r14', 64), ('0x5ceb0ec', 'r14', 48),
            ('0x5ceb0f6', 'r14', 64)],
           'caller r14')
    bucket_all = store_census(data, *OWNERS['bucket'])
    expect(bucket_all,
           [('0x5ce29df', 'rdx', 8), ('0x5ce29eb', 'rcx', 0),
            ('0x5ce29f1', 'rsi', 0), ('0x5ce2a09', 'rax', 0),
            ('0x5ce2a31', 'rdi', 1032), ('0x5ce2a3d', 'rax', 8)],
           'bucket')
    return {
        'caller_all_stores': caller_all,
        'caller_r14_stores': caller_r14,
        'bucket_all_stores': bucket_all,
    }


def rela_entries(data):
    entries = {}
    for section in sections(data):
        if section['name'] != '.rela.dyn':
            continue
        blob = data[section['offset']:
                    section['offset'] + section['size']]
        for i in range(0, len(blob) - 23, 24):
            off, info, addend = struct.unpack_from('<QQq', blob, i)
            entries[off] = (info & 0xFFFFFFFF, info >> 32, addend)
    return entries


def direct_refs(data, target):
    """Direct relative call/jump sites to `target` in .text."""
    text = next(s for s in sections(data) if s['name'] == '.text')
    base_va, base_off = text['address'], text['offset']
    blob = data[base_off:base_off + text['size']]
    hits = []
    for m in re.finditer(rb'[\xe8\xe9]', blob):
        i = m.start()
        rel = int.from_bytes(blob[i + 1:i + 5], 'little',
                             signed=True)
        if base_va + i + 5 + rel == target:
            hits.append({'site': hex(base_va + i),
                         'kind': 'call' if blob[i] == 0xE8
                         else 'jmp'})
    return hits


def rip_relative_refs(data, target):
    """Rip-relative slot/lea references to `target` in .text."""
    text = next(s for s in sections(data) if s['name'] == '.text')
    va0, fo0, size = text['address'], text['offset'], text['size']
    blob = data[fo0:fo0 + size]
    starts = set()
    for pat in (rb'\xff[\x15\x25]', rb'[\x48-\x4f][\x8b\x8d]',
                rb'[\x8b\x8d]'):
        for m in re.finditer(pat, blob):
            starts.add(m.start())
    out = {}
    for i in sorted(starts):
        if i > size - 7:
            continue
        va = va0 + i
        b0, b1 = blob[i], blob[i + 1]
        if b0 == 0xFF and b1 in (0x15, 0x25):
            disp = struct.unpack_from('<i', blob, i + 2)[0]
            if va + 6 + disp == target:
                out[va] = 'call' if b1 == 0x15 else 'jmp'
        elif 0x48 <= b0 <= 0x4F and b1 in (0x8B, 0x8D) \
                and (blob[i + 2] & 0xC7) == 0x05:
            disp = struct.unpack_from('<i', blob, i + 3)[0]
            if va + 7 + disp == target:
                out[va] = 'load' if b1 == 0x8B else 'lea'
        elif b0 in (0x8B, 0x8D) and (b1 & 0xC7) == 0x05:
            disp = struct.unpack_from('<i', blob, i + 2)[0]
            if va + 6 + disp == target:
                out[va] = 'load32' if b0 == 0x8B else 'lea32'
    return {hex(k): v for k, v in sorted(out.items())}


def bucket_call_sites(data):
    hits = direct_refs(data, OWNERS['bucket'][0])
    check(hits == [{'site': '0x5cea839', 'kind': 'call'},
                   {'site': '0x5ceb06e', 'kind': 'call'}],
          f'bucket call sites drift: {hits}')
    return hits


def caller_references(data):
    """Every static reference to the second caller's start."""
    entries = rela_entries(data)
    addend_refs = sorted(hex(off) for off, (typ, _, addend)
                         in entries.items()
                         if typ == 8
                         and addend == OWNERS['caller'][0])
    check(addend_refs == ['0x64dfe40'],
          f'caller addend refs drift: {addend_refs}')
    direct = direct_refs(data, OWNERS['caller'][0])
    check(direct == [], f'caller direct refs drift: {direct}')
    rip = rip_relative_refs(data, OWNERS['caller'][0])
    check(rip == {}, f'caller rip-relative refs drift: {rip}')
    bucket_addends = [off for off, (typ, _, addend)
                      in entries.items()
                      if typ == 8
                      and addend == OWNERS['bucket'][0]]
    check(bucket_addends == [],
          f'bucket addend refs drift: {bucket_addends}')
    bucket_rip = rip_relative_refs(data, OWNERS['bucket'][0])
    check(bucket_rip == {},
          f'bucket rip-relative refs drift: {bucket_rip}')
    neighbours = {}
    for off in (0x64DFE30, 0x64DFE38, 0x64DFE40, 0x64DFE48):
        check(off in entries, f'table slot {off:#x} missing')
        typ, _, addend = entries[off]
        check(typ == 8, f'table slot {off:#x} is not RELATIVE')
        neighbours[hex(off)] = hex(addend)
    check(neighbours == {'0x64dfe30': '0x5cf31f0',
                         '0x64dfe38': '0x5ce88e0',
                         '0x64dfe40': '0x5ceafd0',
                         '0x64dfe48': '0x15c2d00'},
          f'table neighbourhood drift: {neighbours}')
    check(entries[0x64DFE50][0] == 6,
          'slot after the code-pointer run is not GLOB_DAT')
    return {
        'caller_direct_refs': direct,
        'caller_rip_relative_refs': rip,
        'caller_addend_refs': addend_refs,
        'bucket_addend_refs': [],
        'bucket_rip_relative_refs': bucket_rip,
        'table_neighbourhood': neighbours,
    }


def slots_census(data):
    entries = rela_entries(data)
    records = {}
    for slot, target in SLOT_TARGETS.items():
        check(slot in entries, f'slot {slot:#x} has no relocation')
        typ, _, addend = entries[slot]
        check(typ == 8, f'slot {slot:#x} is not RELATIVE')
        check(addend == target,
              f'slot {slot:#x} resolves to {addend:#x}')
        records[hex(slot)] = hex(target)
    return records


def strings_census(data):
    records = {}
    for role, (va, size, text) in STRINGS.items():
        raw = read(va, data, size)
        check(raw.decode() == text, f'string drift {role}')
        records[role] = {'va': hex(va), 'bytes': size, 'text': text}
    return records


def locations_census(data):
    entries = rela_entries(data)
    records = {}
    for va, (ptr, length, line, col) in LOCATIONS.items():
        qwords = list(struct.unpack_from('<3Q', read(va, data, 24),
                                         0))
        check(qwords[0] == 0, f'location {va:#x} ptr field in file')
        check(qwords[1] == length, f'location {va:#x} len drift')
        packed = qwords[2]
        check(packed & 0xFFFFFFFF == line and packed >> 32 == col,
              f'location {va:#x} line/col drift')
        check(va in entries, f'location {va:#x} has no relocation')
        typ, _, addend = entries[va]
        check(typ == 8 and addend == ptr,
              f'location {va:#x} ptr resolves to {addend:#x}')
        records[hex(va)] = {
            'qwords': [hex(q) for q in qwords],
            'file_ptr': hex(ptr), 'len': length,
            'line': line, 'col': col}
    return records


def pins_census(data):
    records = {}
    for site, want in PINS.items():
        raw = read(site, data, len(bytes.fromhex(want)))
        check(raw.hex() == want, f'pin drift at {site:#x}')
        records[hex(site)] = want
    return records


FINDINGS = {
    'bucket_contract': (
        '0x5ce29a0(rdi = bucket, rsi = entry) removes the '
        'entry from its level-bucket slot list; it is the '
        'body both callers share.  It computes shift = '
        '6 * [bucket+0x400] (multiplication overflow '
        'traps through slot 0x64df870 (0x1681dc0) with '
        'the level.rs Location static 0x64c5900, line '
        '173 col 19; shift >= 0x40 traps through slot '
        '0x64e0820 (0x1681e20) with Location 0x64c5918, '
        'line 173 col 6), slot index = ([entry+0x10] >> '
        'shift) & 0x3f, and slot = bucket + index * 16 '
        'with {head +0x0, tail +0x8}.  The unlink: if '
        '[entry+0x0] (prev) is non-null it writes '
        '[prev+0x8] := [entry+0x8] and, when the next '
        'pointer is non-null, [next+0x0] := prev; if '
        'prev is null it replaces the slot head with '
        '[entry+0x8] when the head is the entry, and '
        'returns unchanged when the head is a different '
        'non-null entry (the entry is not in this slot).  '
        'When the entry was the tail, [slot+0x8] := '
        '[entry+0x0].  The entry link pair is zeroed '
        '(movups at 0x5ce29f1).  Only when the slot is '
        'then empty (head null) does it finish: a '
        'non-null tail with a null head panic-formats '
        'through slot 0x64df730 (0x1680e60) with the '
        '37-byte message at 0x94cb3f ("assertion failed: '
        'self.tail.is_none()") and the linked_list.rs '
        'Location static 0x64c5930 (line 188, col 9); '
        'otherwise it toggles the occupancy bit '
        '[bucket+0x408] ^= 1 << slot index at 0x5ce2a31 '
        '(the bit was set for the occupied slot, so the '
        'toggle clears it).  Its complete store census '
        'is six stores; it returns no meaningful value.  '
        'This settles the predicate-chain packet\'s '
        '"unlinks or bucket-inserts" hedge: the body '
        'only unlinks - no path stores the entry into a '
        'list it was not already in.'),
    'caller_contract': (
        '0x5ceafd0(rdi = C), where C = &[S+0x10] for the '
        'same S the predicate-chain builder fills: the '
        'handle is [C+0x8] (= [S+0x18]), the selector '
        'byte is [C+0x0] (= [S+0x10], sel 0x160 if '
        'non-zero else 0x240), and the entry the bucket '
        'call receives is &[C+0x10] = &[S+0x20] - the '
        'setter\'s entry.  Prologue: if dword '
        '[handle+sel+0x90] == 1000000000 the body traps '
        'through slot 0x64df770 (0x1680bd0) with the '
        '115-byte timers-disabled message at 0x94ca6b '
        'and the entry.rs Location static 0x64c6158 '
        '(line 549, col 30), before any lock.  It then '
        'byte-locks the wheel (lock cmpxchg '
        '[wheel+0x0], 1 at 0x5ceb00a; contention waits '
        'via slot 0x64e01f8 (0x5bb59d0) with a '
        '1000000000 timeout and re-reads the value '
        'slot).  Wheel here is handle+sel+0x50, so '
        '[wheel+0x8] is read as [r15+0x58], the elapsed '
        'field [wheel+0x10] as [r15+0x60], and the '
        'wheel list pair as [r15+0x68]/[r15+0x70].'),
    'call_site': (
        'The call at 0x5ceb06e is reached iff the value '
        'slot [C+0x28] ([entry+0x18]) is not -1 and the '
        'stored value [C+0x20] ([entry+0x10]) is not '
        '-1.  The level is ((bsr(([C+0x20] xor '
        '[wheel+0x10]) | 0x3f) ^ 1) * 0x2b) >> 8 with '
        'the pre-bsr input clamped to 0xffffffffe; a '
        'bsr-derived index above 0x23 traps at '
        '0x5ceb168 through slot 0x64df620 (0x1680cbf) '
        'with esi = the computed level and the '
        'wheel/mod.rs Location static 0x64c6a48 (line '
        '130, col 17).  Argument setup: rdi = '
        '[wheel+0x8] + level * 0x410 (imul at '
        '0x5ceb063, add at 0x5ceb06a), rsi = &[C+0x10] '
        '(loaded at 0x5ceb024 and never rewritten '
        'before the call).  The bucket body\'s return '
        'value is ignored: rax is not read on any path '
        'out of the call, and control falls to the '
        'consume phase at 0x5ceb0b1.'),
    'inline_arm': (
        'When the value slot is set but [entry+0x10] '
        '== -1, the entry is not in a level bucket and '
        'the caller splices it out inline (0x5ceb075..'
        '0x5ceb119) from the wheel list whose head is '
        '[wheel+0x18] and tail is [wheel+0x20] - the '
        'same splice shape as the bucket body (prev/'
        'next fixups at 0x5ceb081/0x5ceb08d, head '
        'fixup at 0x5ceb0a2, tail fixup at 0x5ceb115, '
        'links zeroed at 0x5ceb093), with no occupancy '
        'bit to toggle.  The setter has the identical '
        'arm at 0x5cea840 against the same wheel list '
        'pair ([rbx+0x18]/[rbx+0x20]).'),
    'consume_phase': (
        'After the unlink (either arm), if the value '
        'slot is still not -1 the caller consumes the '
        'entry in place - exactly five stores through '
        'r14 (= C): byte [C+0x48] := 0 at 0x5ceb0bb, '
        '[C+0x28] := -1 at 0x5ceb0c0, lock cmpxchg '
        '[C+0x40] |= 2 in the retry loop at 0x5ceb0d7, '
        '[C+0x30] := 0 at 0x5ceb0ec and xchg [C+0x40] '
        'at 0x5ceb0f6.  In S offsets these are the '
        'fired byte [S+0x58] := 0 (the byte the '
        'setter\'s due arm also clears, and its '
        'timer-error arm sets to 1), the value slot '
        '[S+0x38] := -1, the state word [S+0x50] and '
        'the wake pair [S+0x40]/[S+0x48].  The pair is '
        'taken only when the cmpxchg\'s old [C+0x40] '
        'was 0; then, when the taken head [C+0x30] is '
        'non-null, the caller invokes [head+0x18] at '
        '0x5ceb0ff with rdi = the taken argument '
        '[C+0x38] - a plain call, where the setter\'s '
        'shared tail tail-calls [head+0x8].  An old '
        'value other than 0 means the pair was already '
        'claimed; the caller only unlocks.  Unlock is '
        'lock cmpxchg [wheel+0x0], 0 at 0x5ceb106; '
        'contention takes the release tail through '
        'slot 0x64e0f38 (0x5bb5650) with esi = 0 at '
        '0x5ceb158.  The landing pad at 0x5ceb17c '
        'repeats the unlock (contention via a call '
        'through the same slot) before _Unwind_Resume; '
        'a second pad at 0x5ceb19e calls through slot '
        '0x64df4c0 (0x1680cab).'),
    'dispatch_context': (
        'The second caller has no direct callers: a '
        'whole-.text scan finds no relative call/jump '
        'site to 0x5ceafd0 and no rip-relative slot or '
        'lea reference, and .rela.dyn holds exactly one '
        'RELATIVE addend for it, at 0x64dfe40 - one slot '
        'in a run of four code-pointer addends in '
        '.data.rel.ro (neighbours pinned in records: '
        '0x5cf31f0, 0x5ce88e0, this body, 0x15c2d00; '
        'the run ends at 0x64dfe50, a GLOB_DAT slot).  '
        'It is therefore invoked through a data-held '
        'pointer, consistent with a vtable or trait-'
        'method slot; which object the table belongs '
        'to is not traced here.  The bucket body, by '
        'contrast, has no data-held references at all: '
        'its two direct call sites are the complete '
        'reference set.'),
    'comparison': (
        'Same: the entry object (&[S+0x20]); the value-'
        'slot gate ([entry+0x18] == -1 skips the '
        'unlink); the [entry+0x10] == -1 inline arm '
        'against the wheel list pair; the level '
        'formula and clamp; the level trap through '
        'slot 0x64df620 with the wheel/mod.rs Location '
        'static 0x64c6a48 (130:17); the argument shape '
        '(rdi = [wheel+0x8] + level * 0x410, rsi = '
        'entry); the bucket body\'s return ignored.  '
        'Different: (1) the setter reaches its call '
        'already holding the wheel lock it took at '
        '0x5cea7d8, as a pre-flag preliminary inside a '
        'larger operation that goes on to test '
        '[wheel+0x30] and may store a new value and '
        'call the insert body 0x5cf6880; the second '
        'caller takes the lock itself and removal plus '
        'consumption is its whole operation.  (2) The '
        'setter receives the wheel in rdi and the entry '
        'in rcx; the second caller receives a self '
        'pointer at &[S+0x10] and derives handle, '
        'selector and wheel itself.  (3) Only the '
        'second caller performs the entry.rs 549:30 '
        'timers guard before locking (the setter\'s '
        'path is guarded by the conversion body '
        'instead, per the predicate-chain packet).  '
        '(4) After the call the setter falls through '
        'to its flag test with the entry untouched by '
        'the consume idiom; the second caller clears '
        'the fired byte, sets the value slot to -1 and '
        'claims the wake pair, invoking [head+0x18] '
        'where the setter\'s tail uses [head+0x8].'),
}

CALL_TABLE = {
    'scope': 'second caller 0x5ceafd0(rdi = C = '
             '&[S+0x10]); entry = &[C+0x10] = &[S+0x20]; '
             'wheel = [C+0x8] + sel + 0x50 with sel from '
             'byte [C+0x0]',
    'rows': [
        {'condition': 'dword [handle+sel+0x90] == '
                      '1000000000',
         'outcome': 'no return: assert-fail trap via '
                    'slot 0x64df770 (0x1680bd0), '
                    'timers-disabled message (0x94ca6b), '
                    'Location entry.rs 549:30 (static '
                    '0x64c6158); before any lock',
         'stores': 'none'},
        {'condition': '[entry+0x18] == -1 (value slot '
                      'unset)',
         'outcome': 'no unlink and no consumption: '
                    'lock, test, unlock, return',
         'stores': 'the wheel lock cmpxchg pair only'},
        {'condition': '[entry+0x18] != -1 and '
                      '[entry+0x10] == -1',
         'outcome': 'inline splice of the entry out of '
                    'the wheel list ([wheel+0x18] head, '
                    '[wheel+0x20] tail), then the '
                    'consume phase',
         'stores': 'splice stores at 0x5ceb081, '
                   '0x5ceb08d, 0x5ceb093, 0x5ceb0a2, '
                   '0x5ceb115; then the consume stores'},
        {'condition': '[entry+0x18] != -1, '
                      '[entry+0x10] != -1, bsr-derived '
                      'level index > 0x23',
         'outcome': 'no return: level assert via slot '
                    '0x64df620 (0x1680cbf), esi = '
                    'computed level, Location '
                    'wheel/mod.rs 130:17 (static '
                    '0x64c6a48)',
         'stores': 'the wheel lock cmpxchg only'},
        {'condition': '[entry+0x18] != -1, '
                      '[entry+0x10] != -1, level in '
                      'range',
         'outcome': 'call bucket body 0x5ce29a0 at '
                    '0x5ceb06e (rdi = level bucket, '
                    'rsi = entry); its own traps are '
                    'level.rs 173:19 / 173:6 and '
                    'linked_list.rs 188:9; return value '
                    'ignored; then the consume phase',
         'stores': 'the bucket body\'s six stores; '
                   'then the consume stores'},
    ],
    'consume_phase': {
        'condition': 'value slot still != -1 after '
                     'the unlink phase',
        'stores': 'byte [S+0x58] := 0, [S+0x38] := -1, '
                  '[S+0x50] |= 2 (cmpxchg), [S+0x40] '
                  ':= 0 and [S+0x50] taken by xchg when '
                  'the claim wins',
        'callback': 'when the claim wins and the taken '
                    'head is non-null: call [head+0x18] '
                    'with the taken argument [S+0x48]'},
    'testable_statement': (
        'The bucket body 0x5ce29a0 has exactly two '
        'direct callers and no data-held references.  '
        'Its second caller - reachable only through '
        'the code-pointer slot 0x64dfe40 - removes the '
        'same &[S+0x20] entry from the same wheel '
        'under the same gating as the setter\'s '
        'pre-flag call (value slot set, level from the '
        'stored [entry+0x10], the inline wheel-list '
        'arm when that field is -1), and then consumes '
        'the entry: fired byte cleared, value slot '
        ':= -1, wake pair claimed with a [head+0x18] '
        'callback.  Nothing in either caller inserts '
        'into a bucket: the shared body only unlinks.'),
}

OPEN_EDGES = [
    'The writer identity of the wheel flag byte at '
    '[wheel+0x30] the setter tests at 0x5cea881 '
    '(open edge 1 of #2617) remains untraced; this '
    'packet does not touch it.',
    'The runtime contents of the handle fields and '
    'of the entry fields - runtime data, not '
    'statically decidable (open edge 2 of #2617) - '
    'remain open; this packet pins only the second '
    'caller\'s static conditions and effects.',
    'Who re-invokes the gates to reach checker state '
    '3 and the provenance of [record+0x1d8] before '
    'its first checker_a call (open edge 4 of #2613) '
    'remain open.',
    'New: the dispatch context of the second caller '
    '- which object\'s code-pointer table holds the '
    'slot at 0x64dfe40 and on what runtime event the '
    'body is invoked through it - is not established '
    'here; only the slot and its immediate '
    'neighbourhood are pinned.',
    'New: the consumers of the wheel list '
    '([wheel+0x18] head / [wheel+0x20] tail) that '
    'both callers\' inline arms maintain - the '
    'poll-side bodies that walk that list - are not '
    'traced here.',
]


def derive(data):
    check(len(data) == TARGET_SIZE, 'artifact size mismatch')
    check(sha(data) == TARGET_SHA256, 'artifact sha256 mismatch')
    return {
        'artifact': {'size': len(data), 'sha256': sha(data)},
        'work_item': WORK_ITEM,
        'owners': owners(data),
        'exported_bodies': EXPORTED,
        'slots': slots_census(data),
        'strings': strings_census(data),
        'locations': locations_census(data),
        'constants': CONSTANTS,
        'store_censuses': store_censuses(data),
        'bucket_call_sites': bucket_call_sites(data),
        'caller_references': caller_references(data),
        'pins': pins_census(data),
        'findings': FINDINGS,
        'call_table': CALL_TABLE,
        'open_edges': OPEN_EDGES,
    }


def analyze(data):
    return derive(data)


def generate(data):
    OUT.mkdir(parents=True, exist_ok=True)
    records = analyze(data)
    (OUT / 'records.json').write_text(
        json.dumps(records, indent=1, sort_keys=True) + '\n')
    (OUT / 'frames.txt').write_text(''.join(frame_lines(data)))
    for role in EXPORTED:
        (OUT / f'{role}.objdump.txt').write_text(
            exports(data, role))


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--generate', action='store_true')
    args = parser.parse_args()
    data = TARGET.read_bytes()
    if args.generate:
        generate(data)
        return
    records = analyze(data)
    expected = json.loads((OUT / 'records.json').read_text())
    check(records == expected, 'records.json is stale')
    for role in EXPORTED:
        check((OUT / f'{role}.objdump.txt').read_text() ==
              exports(data, role), f'{role}.objdump.txt is stale')
    check((OUT / 'frames.txt').read_text() ==
          ''.join(frame_lines(data)), 'frames.txt is stale')
    print(json.dumps({'packet': WORK_ITEM, 'matches': True},
                     sort_keys=True))


if __name__ == '__main__':
    main()
