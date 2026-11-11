"""Static evidence for the RE-005 insert-return packet.

Answers, for the authenticated hl-node 115 artifact only
(open edge 3 of RE-005-node115-predicate-chain, PR #2617):
the wheel insert body 0x5cf6880 - called by the
predicate-chain setter 0x5cea7c0 after its direct store -
under exactly which conditions hands the entry back
instead of linking it into a level bucket, what the
returned (rax, rdx) pair means on each arm, which traps
guard the body, and how the setter consumes each arm,
including the stores after the 0x5cea8d5 rebind that the
predicate-chain packet's setter census stopped short of.

1.  Insert producer conditions: the value trap, the
    already-due comparison against the wheel elapsed
    field, the level computation and its traps, the
    bucket-header shift traps, the double-link guard,
    and the link arm's store census.
2.  Return shape: rdx is an entry pointer iff rax == 1
    and the deadline value itself iff rax == 0.
3.  Setter consumption: the post-rebind store census on
    the returned entry (the fire block and the shared
    take-pair tail), and the linked arm's notify call
    into 0x5ce09a0 with its entry contract.

Method: the three bodies are exported in full.  Store
censuses are taken over the disassembly; the setter
census covers [0x5cea8d5, end) - the range the
predicate-chain packet explicitly did not census.
Direct callers of the insert body are censused by a
whole-.text scan for relative call/jump sites.  Strings
and tables resolve through the section table (.rodata
is identity-mapped; .text resolves at VA-0x1000;
.data.rel.ro at VA-0x2000); GOT slots are resolved from
.rela.dyn addends; panic Location statics are read as
raw qwords plus their RELATIVE addend.
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
WORK_ITEM = 'RE-005-node115-insert-return'
OUT = ROOT / 'research' / 'work-items' / WORK_ITEM
SNAPSHOT = '<authenticated-node115>'

OWNERS = {
    'insert': (0x5CF6880, 0x5CF69BF),
    'setter': (0x5CEA7C0, 0x5CEAA17),
    'notify': (0x5CE09A0, 0x5CE0AA2),
}
EXPORTED = list(OWNERS)

OWNER_SHA256 = {
    'insert': '9b9b96ad18568130435d9442cbc897deef1bd531a6b2bab7'
              '1e050997e87ef6ef',
    'setter': '5fbfddaf7831cf129e1dc6734e16b7aa37d5e51b3355c96a'
              '8da582d905f4d8e2',
    'notify': 'c7efc9b1071af6d1e1a162ccdff36175ffd1fe4a7dbfaa96'
              '28965f187d18b8e7',
}

# The linked-list guard shim behind slot 0x64ecbd8: not an
# owner (not exported), but its extent and digest are
# pinned so the double-link path is bound to the artifact.
GUARD_SHIM = (0x5CE82B8, 0x5CE82EB)
GUARD_SHIM_SHA256 = ('250c6658ebf21ec1e6fb4cab7c9d9e96c965a30e'
                     '794bcb1eca6e9b8db6b098cb')

# GOT slots: va -> expected R_X86_64_RELATIVE resolution.
SLOT_TARGETS = {
    0x64DF770: 0x1680BD0,   # assert-fail callee (insert -1 trap)
    0x64DF620: 0x1680CBF,   # level assert callee (insert)
    0x64DF870: 0x1681DC0,   # overflow panic shim (bucket shift)
    0x64E0820: 0x1681E20,   # range panic shim (bucket shift)
    0x64ECBD8: 0x5CE82B8,   # linked-list guard shim
    0x64E0F38: 0x5BB5650,   # setter / notify release fn
    0x64E01F8: 0x5BB59D0,   # contention wait (setter / notify)
    0x64EC188: 0x5BB42E0,   # notify wake tail-call target
    0x64DF6B8: 0x1680E80,   # notify state panic-format callee
    0x64DF6A0: 0x1680C30,   # notify wake-failure panic-format
}

STRINGS = {
    'timer_already_fired': (0x94D3B8, 19, 'Timer already fired'),
    'wake_io_driver': (0x94D466, 25, 'failed to wake I/O driver'),
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
    'park_rs': (0x447492, 63,
                '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/'
                'src/runtime/park.rs'),
}

# Panic Location statics in .data.rel.ro: the file qwords
# are [0, len, packed line/col]; the first field's target
# is the RELATIVE addend at the static's address.
LOCATIONS = {
    0x64C6170: (0x44CEF5, 69, 417, 27),    # entry.rs (-1 trap)
    0x64C6A30: (0x446310, 73, 102, 13),    # wheel/mod.rs (level)
    0x64C5900: (0x43A333, 75, 173, 19),    # level.rs (shift mul)
    0x64C5918: (0x43A333, 75, 173, 6),     # level.rs (shift rng)
    0x64C5D70: (0x44AA38, 67, 125, 9),     # linked_list.rs
    0x64C6F60: (0x447492, 63, 187, 18),    # park.rs (notify)
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
}

# Frozen instruction-byte pins: site -> bytes (hex).
PINS = {
    0x5CF6881: '4c8b4618',              # insert: v = [entry+0x18]
    0x5CF6889: '0f84ce000000',          # insert: je -1 trap
    0x5CF688F: '4c894610',              # insert: [entry+0x10] := v
    0x5CF689F: '0f86b3000000',          # insert: jbe due return
    0x5CF691C: '4839f1',                # insert: slot head == entry?
    0x5CF694C: '49098108040000',        # insert: occupancy bit or
    0x5CF6953: '31c0',                  # insert: rax := 0 (link arm)
    0x5CEA8D0: 'e8abbf0000',            # setter -> insert call
    0x5CEA8D5: '4989d6',                # setter: r14 := rdx rebind
    0x5CEA8D8: '4883f801',              # setter: cmp rax, 1
    0x5CEA8EC: '41c6463800',            # fire: byte [entry+0x38] := 0
    0x5CEA8F1: '49c74618ffffffff',      # fire: [entry+0x18] := -1
    0x5CEA936: '498b5620',              # tail: rdx := [entry+0x20]
    0x5CEA97D: 'e81e60ffff',            # setter -> notify call
    0x5CE09A5: '837f44ff',              # notify: cmp [rdi+0x44], -1
    0x5CE09C7: '48874310',              # notify: xchg [rbx+0x10], 2
    0x5CE09AF: 'e8eca4a7fe',            # notify -> 0x475aea0 call
}

STORE_MNEMS = {'mov', 'movq', 'movl', 'movw', 'movb', 'movups',
               'movaps', 'movsd', 'cmpxchg', 'xchg', 'xadd',
               'decq', 'incq', 'or'}


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
    gstart, gend = GUARD_SHIM
    check((gstart, gend) in extents, 'no FDE for guard shim')
    check(sha(read(gstart, data, gend - gstart)) ==
          GUARD_SHIM_SHA256, 'guard shim digest drift')
    records['guard_shim'] = {
        'start': hex(gstart), 'end': hex(gend),
        'bytes': gend - gstart, 'sha256': GUARD_SHIM_SHA256,
        'note': 'extent/digest only; not exported'}
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
    pat = re.compile(r'^\s+([0-9a-f]+):\t((?:[0-9a-f]{2} )+)\s*'
                     r'\t(.*)$')
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
    insert_all = store_census(data, *OWNERS['insert'])
    expect(insert_all,
           [('0x5cf688f', 'rsi', 16), ('0x5cf6914', 'rsp', 0),
            ('0x5cf6921', 'rsi', 8), ('0x5cf6925', 'rsi', 0),
            ('0x5cf6931', 'rcx', 0), ('0x5cf6934', 'rax', 0),
            ('0x5cf693e', 'rax', 8), ('0x5cf694c', 'r9', 1032)],
           'insert')

    setter_r14 = store_census(data, 0x5CEA8D5, OWNERS['setter'][1],
                              bases={'r14'})
    expect(setter_r14,
           [('0x5cea8ec', 'r14', 56), ('0x5cea8f1', 'r14', 24),
            ('0x5cea907', 'r14', 48), ('0x5cea93e', 'r14', 32),
            ('0x5cea948', 'r14', 48)],
           'setter post-rebind r14')
    setter_rbx = store_census(data, 0x5CEA8D5, OWNERS['setter'][1],
                              bases={'rbx'})
    expect(setter_rbx,
           [('0x5cea91a', 'rbx', 0), ('0x5cea950', 'rbx', 0),
            ('0x5cea986', 'rbx', 0), ('0x5cea99b', 'rbx', 32),
            ('0x5cea9f6', 'rbx', 0)],
           'setter post-rebind rbx')

    notify_rbx = store_census(data, *OWNERS['notify'],
                              bases={'rbx'})
    expect(notify_rbx,
           [('0x5ce09c7', 'rbx', 16), ('0x5ce09f9', 'rbx', 32),
            ('0x5ce0a04', 'rbx', 32), ('0x5ce0a65', 'rbx', 32)],
           'notify rbx')

    return {
        'insert_all_stores': insert_all,
        'setter_post_rebind_r14_stores': setter_r14,
        'setter_post_rebind_rbx_stores': setter_rbx,
        'notify_rbx_stores': notify_rbx,
    }


def insert_call_sites(data):
    """Direct relative call/jump sites to the insert body."""
    text = next(s for s in sections(data) if s['name'] == '.text')
    base_va, base_off = text['address'], text['offset']
    blob = data[base_off:base_off + text['size']]
    target = OWNERS['insert'][0]
    hits = []
    for m in re.finditer(rb'[\xe8\xe9]', blob):
        i = m.start()
        rel = int.from_bytes(blob[i + 1:i + 5], 'little',
                             signed=True)
        if base_va + i + 5 + rel == target:
            hits.append({'site': hex(base_va + i),
                         'kind': 'call' if blob[i] == 0xE8
                         else 'jmp'})
    check(hits == [{'site': '0x5cea8d0', 'kind': 'call'}],
          f'insert call sites drift: {hits}')
    return hits


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
    'insert_contract': (
        '0x5cf6880(rdi = &[wheel+0x8], rsi = entry).  The '
        'entry layout as this body sees it: +0x00 previous '
        'link, +0x08 next link, +0x10 last-written value, '
        '+0x18 value slot.  It loads v = [entry+0x18] at '
        '0x5cf6881 and traps if v == -1 through the '
        'assert-fail callee behind slot 0x64df770 '
        '(0x1680bd0) with the 19-byte message at 0x94d3b8 '
        '("Timer already fired") and the entry.rs Location '
        'static 0x64c6170 (line 417, col 27).  It then '
        'stores [entry+0x10] := v at 0x5cf688f - on every '
        'non-trapping path, before any return - and '
        'compares v unsigned against the wheel elapsed '
        'field [wheel+0x10], read as [rdi+0x8] because the '
        'sole caller passes &[wheel+0x8]; [wheel+0x10] is '
        'the same field the setter\'s level computation '
        'XORs the entry value against.'),
    'due_arm': (
        'Producer condition for the hand-back: v <= '
        '[wheel+0x10] (unsigned, jbe at 0x5cf689f).  The '
        'body links nothing and returns (rax = 1, rdx = '
        'rsi = the entry pointer, both unchanged since '
        'entry).  The complete store census of the body '
        'shows the due arm performs exactly one store - '
        'the [entry+0x10] := v write at 0x5cf688f that '
        'precedes the comparison - so an already-due '
        'entry comes back with its +0x10 field refreshed '
        'and every link field untouched.'),
    'link_arm': (
        'v > [wheel+0x10]: level = ((bsr((v xor elapsed) '
        '| 0x3f) ^ 1) * 0x2b) >> 8, with the pre-bsr input '
        'clamped to 0xffffffffe; if the bsr-derived index '
        'exceeds 0x23 (a level of 6 or more) the body '
        'traps through slot 0x64df620 (0x1680cbf) with the '
        'computed level and the wheel/mod.rs Location '
        'static 0x64c6a30 (line 102, col 13).  The bucket '
        'is [wheel+0x8] + level * 0x410; the slot index '
        'is (v >> shift) & 0x3f with shift = 6 * [bucket '
        '+ 0x400], and the header word is trapped on '
        'multiplication overflow (slot 0x64df870, '
        '0x1681dc0, level.rs Location 0x64c5900, line 173 '
        'col 19) and on shift >= 0x40 (slot 0x64e0820, '
        '0x1681e20, Location 0x64c5918, line 173 col 6).  '
        'If the computed slot\'s head already is the '
        'entry itself the body calls the linked-list '
        'guard shim behind slot 0x64ecbd8 (0x5ce82b8, '
        '51 B) with r9 = the linked_list.rs Location '
        'static 0x64c5d70 (line 125, col 9) and does not '
        'return - a double-link guard, not a second '
        'return path.  Otherwise it links the entry at '
        'the slot head (stores: [entry+0x8] := old head, '
        '[entry+0x0] := 0, [old head+0x0] := entry when '
        'non-null, [slot+0x0] := entry, [slot+0x8] := '
        'entry when the tail was empty), sets the '
        'occupancy bit [bucket+0x408] |= 1 << slot index '
        'at 0x5cf694c, and returns (rax = 0, rdx = v).'),
    'return_shape': (
        'rdx is typed by rax: an entry pointer iff '
        'rax == 1, and the deadline value v itself iff '
        'rax == 0.  The predicate-chain packet\'s '
        '"returned (rax, rdx) object" phrasing is exact '
        'only on the rax == 1 arm; on the link arm the '
        'setter rebinds r14 to an integer and never '
        'dereferences it (see setter_linked_consumption).'),
    'setter_due_consumption': (
        'Continuation of the predicate-chain setter '
        'census, which stopped at the rebind 0x5cea8d5: '
        'over [0x5cea8d5, 0x5ceaa17) the setter performs '
        'exactly five stores through r14 - byte '
        '[r14+0x38] := 0 at 0x5cea8ec, [r14+0x18] := -1 '
        'at 0x5cea8f1, lock cmpxchg [r14+0x30] |= 2 at '
        '0x5cea907, [r14+0x20] := 0 at 0x5cea93e and xchg '
        '[r14+0x30] at 0x5cea948.  On the rax == 1 arm '
        'the handed-back pointer is the setter\'s own '
        'entry (insert returns rsi unchanged and its '
        'sole direct call site, 0x5cea8d0, passes the '
        'entry the setter just stored into), so these '
        'stores land on the same S+0x20-based entry: '
        'byte [S+0x58] := 0 (fired as due, where the '
        'timer-error arm writes 1), the value slot '
        '[S+0x38] := -1 (consumed), and [S+0x50] |= 2.  '
        'The shared tail at 0x5cea90f then tests the '
        'cmpxchg\'s old [S+0x50]: if it was 0 the setter '
        'takes the pair ([S+0x40] -> rdx, [S+0x48] -> '
        'wake argument, [S+0x40] := 0, [S+0x50] taken by '
        'xchg), unlocks the wheel and, when the taken '
        'head is non-null, tail-calls [head+0x8] with '
        'the argument; if it was non-zero the setter '
        'only unlocks - the pair was already claimed, '
        'the race the postcall body 0x5ce91b0\'s swap on '
        'the same state word arbitrates (predicate-chain '
        'packet).  The -1 re-check at 0x5cea8e2 cannot '
        'fire on this call path (insert traps on v == -1 '
        'and the due arm does not rewrite [entry+0x18]); '
        'the shared tail is also the timer-error arm\'s '
        'continuation, which reaches it without the fire '
        'block and with the byte set to 1.'),
    'setter_linked_consumption': (
        'On the rax == 0 arm r14 holds the integer v: '
        'the setter compares [wheel+0x28] - 1 against it '
        'unsigned (0x5cea96e..0x5cea978) and, iff v < '
        '[wheel+0x28], calls the notify body 0x5ce09a0 '
        'on its rsi object at 0x5cea97d.  It then '
        'unlocks the wheel (lock cmpxchg at 0x5cea986; '
        'contention takes the release tail through slot '
        '0x64e0f38 -> 0x5bb5650) and returns.  No store '
        'through the entry occurs on this arm after the '
        'insert call.  (The one rbx store in the '
        'address-range census, [wheel+0x20] at '
        '0x5cea99b, sits in the pre-flag unlink fixup '
        'block at tail addresses and is reached only '
        'from 0x5cea87b, before the insert call.)'),
    'notify_contract': (
        '0x5ce09a0(rdi = object).  If dword [obj+0x44] '
        '!= -1 it calls 0x475aea0 on &[obj+0x44] at '
        '0x5ce09af, returns when that returns null, and '
        'panic-formats through slot 0x64df6a0 '
        '(0x1680c30) with the 25-byte message at '
        '0x94d466 ("failed to wake I/O driver") when it '
        'returns non-null.  Otherwise rbx = [obj+0x0] '
        'and it xchg\'s [rbx+0x10] := 2 at 0x5ce09c7: '
        'old 0 or 2 returns at once; old 1 claims the '
        'byte at [rbx+0x20] (lock cmpxchg pair '
        '0x5ce09f9/0x5ce0a04, contention waiting via '
        'slot 0x64e01f8 with a 1000000000 timeout) and, '
        'when [rbx+0x18] is non-null, tail-jumps '
        'through slot 0x64ec188 (0x5bb42e0) with rdi = '
        '&[rbx+0x18]; any other old value panic-formats '
        'through slot 0x64df6b8 (0x1680e80) with the '
        'park.rs Location static 0x64c6f60 (line 187, '
        'col 18).  Its complete through-rbx store census '
        'is four stores: the +0x10 xchg and the +0x20 '
        'cmpxchg at 0x5ce09f9, 0x5ce0a04 and the '
        'contention retry 0x5ce0a65.'),
    'caller_census': (
        'A whole-.text scan for relative call/jump '
        'sites finds exactly one direct caller of '
        '0x5cf6880 - the setter at 0x5cea8d0 - and no '
        'direct tail-jumps, so the producer conditions '
        'above are the complete direct-call picture.  '
        'Calls through data-held pointers are not '
        'decidable from the artifact; none is known for '
        'this body, which sits on the conversion\'s '
        'tail-jump chain.'),
}

RETURN_TABLE = {
    'scope': 'insert 0x5cf6880(rdi = &[wheel+0x8], '
             'rsi = entry); v = [entry+0x18]; elapsed = '
             '[wheel+0x10], read as [rdi+0x8]',
    'rows': [
        {'condition': 'v == -1',
         'outcome': 'no return: assert-fail trap via '
                    'slot 0x64df770 (0x1680bd0), message '
                    '"Timer already fired" (0x94d3b8), '
                    'Location entry.rs 417:27 (static '
                    '0x64c6170)',
         'stores': 'none'},
        {'condition': 'v <= elapsed (unsigned)',
         'outcome': 'return (rax = 1, rdx = entry): the '
                    'entry is handed back unlinked, '
                    'already due',
         'stores': '[entry+0x10] := v at 0x5cf688f only'},
        {'condition': 'v > elapsed, bsr-derived level '
                      'index > 0x23 (level >= 6)',
         'outcome': 'no return: level assert via slot '
                    '0x64df620 (0x1680cbf), rdi = '
                    'computed level, Location wheel/'
                    'mod.rs 102:13 (static 0x64c6a30)',
         'stores': '[entry+0x10] := v only'},
        {'condition': 'v > elapsed, 6 * [bucket+0x400] '
                      'overflows or >= 0x40',
         'outcome': 'no return: panic shim via slot '
                    '0x64df870 (0x1681dc0), Location '
                    'level.rs 173:19 (static 0x64c5900), '
                    'or via slot 0x64e0820 (0x1681e20), '
                    'Location level.rs 173:6 (static '
                    '0x64c5918)',
         'stores': '[entry+0x10] := v only'},
        {'condition': 'v > elapsed, computed slot head '
                      '== entry',
         'outcome': 'no return: linked-list guard '
                    'shim via slot 0x64ecbd8 '
                    '(0x5ce82b8), Location linked_list.'
                    'rs 125:9 (static 0x64c5d70)',
         'stores': '[entry+0x10] := v and the stack '
                   'scratch at 0x5cf6914 only'},
        {'condition': 'v > elapsed, otherwise',
         'outcome': 'return (rax = 0, rdx = v): the '
                    'entry is linked at the head of its '
                    'level bucket slot',
         'stores': '[entry+0x10] := v, [entry+0x8] := '
                   'old head, [entry+0x0] := 0, [old '
                   'head+0x0] := entry if non-null, '
                   '[slot+0x0] := entry, [slot+0x8] := '
                   'entry if tail was empty, [bucket'
                   '+0x408] |= 1 << slot index'},
    ],
    'setter_consumption': {
        'rax == 1': 'fire block and shared take-pair '
                    'tail on the returned entry (see '
                    'findings.setter_due_consumption)',
        'rax == 0': 'rdx is the deadline value v; iff '
                    'v < [wheel+0x28] the setter calls '
                    'notify 0x5ce09a0 on its rsi object, '
                    'then unlocks and returns (see '
                    'findings.setter_linked_consumption)'},
    'testable_statement': (
        'The setter\'s insert call hands the entry back '
        '(rax = 1, rdx = the entry) iff the converted '
        'value v satisfies v <= [wheel+0x10] unsigned; '
        'it links the entry and returns (rax = 0, '
        'rdx = v) in every other non-trapping case, '
        'and v == -1, an out-of-range level, a corrupt '
        'bucket header word, or an already-linked entry '
        'each trap through the pinned Location statics '
        'instead of returning.'),
}

OPEN_EDGES = [
    'The writer identities of the two wheel fields '
    'this chain reads but never writes - the flag byte '
    'at [wheel+0x30] the setter tests at 0x5cea881 '
    '(open edge 1 of #2617) and the horizon field at '
    '[wheel+0x28] the linked arm compares the new '
    'deadline against - remain untraced; this packet '
    'pins only their read sites, conditions and '
    'effects.',
    'The bucket body 0x5ce29a0\'s second direct '
    'caller at 0x5ceb06e and the poll-side conditions '
    'under which entries are unlinked or '
    'bucket-inserted before the setter\'s flag test '
    'are not censused here; the pre-flag phase is '
    'pinned only at the setter\'s own call site '
    '(0x5cea839) by the predicate-chain packet.',
    'The runtime contents of the handle fields and '
    'of the notify object\'s fields ([obj+0x44], the '
    '[obj+0x0] state object) - runtime data, not '
    'statically decidable from the artifact (open '
    'edge 2 of #2617, restated for the notify path).',
    'Who re-invokes the gates to reach checker state '
    '3 and the provenance of [record+0x1d8] before '
    'its first checker_a call (open edge 4 of #2613) '
    'remain open.',
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
        'insert_call_sites': insert_call_sites(data),
        'pins': pins_census(data),
        'findings': FINDINGS,
        'return_table': RETURN_TABLE,
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
