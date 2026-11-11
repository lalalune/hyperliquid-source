"""Static evidence for the RE-005 TLS value-object packet.

Answers the question the loop-tail-callee packet
carried over, for the authenticated hl-node 115
artifact only: what is the 0x28-byte value object
that the lazy thread-local getter 0x5cdf300 creates
for the dispatcher's cell (TLS base -0x418)?

SETTLED.  The value is the shared parker state of
the vendored tokio runtime park module: every
operation on it panics through a Location in
/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/
runtime/park.rs (park line 107 col 28, park_timeout
lines 153 col 28 and 173 col 18, unpark line 187
col 18).  The 0x28-byte allocation is an Arc-style
header (+0x0 strong count, +0x8 weak count, both
created at 1) plus a 0x18-byte payload at +0x10:
the park state word at +0x10, a waiter-token word
at +0x18 and a mutex byte at +0x20.  The handle the
dispatcher phases share is the fat pair
{vtable 0x64c6ef8, payload pointer} whose methods
are clone (0x5cfdce0), unpark-then-release
(0x5cfd8c0), unpark (0x5cfd600) and release
(0x5cfd5e0); the pair is formed by loading the
value pointer out of the TLS cell, lock-incrementing
the strong count and adding 0x10 (dispatcher rows
at 0x2ae1974..0x2ae1991 and again at 0x2ae1e0f).

(a) Drop.  The drop helper 0x5ce9190 (30 bytes,
exported) takes a pointer to a pointer slot.  A
pointer of -1 (the moved-out sentinel) is a no-op.
Otherwise it lock-decrements the WEAK count at
+0x8; only when that reaches zero does it
tail-jump through slot 0x64df4a0 to the
deallocation body 0x635de30 with (pointer, size
0x28, 0), freeing exactly the allocation.  Nothing
in the chain closes, poisons or destructs the
payload -- it is plain data.  Callers decrement
the STRONG count themselves first (release body,
the glue, the getter's racing arm) and invoke the
helper only at zero, so the helper's decrement is
the second and final count.  The helper is
reached only through slot 0x64e17f8: 18
boundary-verified references in .text (9 calls,
9 tail jumps), no direct call or jump anywhere;
5 of the 18 are in this value's own cluster.

(b) The +0x10 state word.  Values 0 (empty),
1 (parked), 2 (notified).  park 0x5cfdb90 tries
CAS 2->0 first (consume); otherwise it claims the
mutex byte (CAS 0->1), CASes 0->1 to arm, treats a
racing 2 by storing 0 and returning, and panics
at park.rs:107 on any other old value; the wait
loop calls the parking-table wait body 0x5bb4670
(slot 0x64e73b8) with (&+0x18, &+0x20, 1e9 ns)
until CAS 2->0 succeeds, then releases the byte.
park_timeout 0x5cfd9a0 adds a deadline (clock body
0x5c842e0) and two more panic arms (park.rs:153,
:173).  unpark 0x5cfd600 stores 2 with xchg; on
old value 1 it claims and releases the byte (the
registration barrier) and wakes through the token
word.  The dispatcher open-codes the same park
sequence inside driver_c (sites pinned below) and
also calls the out-of-line park once at
0x2ae1ac7; caller bodies 0x5a34440 and 0x5a35480
open-code it too and are the only direct callers
of unpark.

(c) Counts, byte, token.  +0x0 is the strong
count (clone and pair formation increment, with
the clone's signed-overflow trap; release paths
decrement).  +0x8 is the weak count: written only
at creation (:= 1) and by the drop helper
(decrement) in every traced body.  Byte +0x20 is
the parker's mutex byte (claim CAS 0->1, release
CAS 1->0, parking-table byte wait/notify on
contention), held across the whole park wait.
Word +0x18 is the waiter token: the wait body
registers a waiter by storing the address of the
value's own byte (+0x20) into it (0x5bb47e6);
unpark snapshots it (0x5cfd649) and the wake body
0x5bb42e0 validates it, works on the pointed-to
byte's flag bits and stores 0 back (0x5bb447b,
0x5bb4542) to deregister.

Method: eleven bodies are exported in full (the
drop helper, the four vtable methods, park,
park_timeout, the deallocation and clock bodies,
and the parking-table wait and wake bodies);
every other body is extent/digest pinned.
Censuses: whole-.text rel32 call/jump scan and
rip-relative slot-reference scan, every hit
re-verified against its containing body's own
disassembly; .rela.dyn addend census for the
vtable, the four panic Locations and every slot;
instruction byte pins at every load-bearing site.
Section mapping: .rodata identity, .text VA-0x1000,
.data.rel.ro VA-0x2000 (via the section table).
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
WORK_ITEM = 'RE-005-node115-tls-value-object'
OUT = ROOT / 'research' / 'work-items' / WORK_ITEM
SNAPSHOT = '<authenticated-node115>'

OWNERS = {
    'drop_helper': (0x5CE9190, 0x5CE91AE),
    'park': (0x5CFDB90, 0x5CFDCD1),
    'park_timeout': (0x5CFD9A0, 0x5CFDB8D),
    'unpark': (0x5CFD600, 0x5CFD6A0),
    'unpark_release': (0x5CFD8C0, 0x5CFD991),
    'release': (0x5CFD5E0, 0x5CFD5FB),
    'clone_wrap': (0x5CFDCE0, 0x5CFDCF4),
    'dealloc': (0x635DE30, 0x635DED5),
    'clock': (0x5C842E0, 0x5C843A9),
    'wait_fn': (0x5BB4670, 0x5BB4CFD),
    'wake_fn': (0x5BB42E0, 0x5BB4663),
}
EXPORTED = list(OWNERS)

OWNER_SHA256 = {
    'drop_helper': '67ddc5751bdc61595db2fcfe90854482ec02741'
                   'f02ad3bbb83748593ec6e5372',
    'park': '9dc44a93c0da072cf5a3b6d11462c014b695de176ed7'
            'fb01fb09b7e3ac5dcc2e',
    'park_timeout': '411cc42aff700d68883fd2371a63226cf62e42'
                    '6c5530e188ed619f6fb98cbef5',
    'unpark': '9e8b5b9398cb3bf3bc18b1d862a6f9b61f934d78ce'
              '359c8d75c94666aabbdf2d',
    'unpark_release': '23b7197ad9830ea95986fac04b952227e6cf'
                      'b89e0236565482d8b79bfb8a25c5',
    'release': 'aab49d6853da91eb704bb65d9dba27ef91fae1af0f'
               '12ffe87e04226dd6b09743',
    'clone_wrap': '0930392c690f1916e58c2ebe1ca9ec806c8c69f7'
                  '94ec551f805ec6add823d9a3',
    'dealloc': '714fc5cdd28a2587427c9dac8a25685ec09695a3a2'
               '1bc9af0eb09b29ae503f61',
    'clock': '3efe331bdc612bff27ad3c487fbff92d57a2e097820'
             'c38f87506703794918f30',
    'wait_fn': '65c70b3e926bbf20a45563b947502e17d87ead0455'
               '6451512587b556e9f57f1d',
    'wake_fn': '15a928dcf95723b20a24cf6f2e8fed16118e2f4b0f'
               '3fbbe869dc6c6502d82c02',
}

# Extent/digest pins only; none of these is exported.
PINNED_BODIES = {
    'dispatcher': (0x2AE1690, 0x2AE27B2,
                   '6ca0595c13836bca0cb0173bd591a09d6da679153'
                   '2e23a5a71c63715380727d9'),
    'byte_wait': (0x5BB59D0, 0x5BB606D,
                  '1ba3a96e8d451e9299eb16b37f016d4c4f050d0'
                  'ddad46f5f7b3d3e8ce2dc3e76'),
    'byte_notify': (0x5BB5650, 0x5BB59C5,
                    '4eda0eff3310a0ba59b0a0fa1f208cf48e2ec5'
                    '499b3ad5e48c99b8b93df628de'),
    'loop_getter': (0x5CDF300, 0x5CDF3DF,
                    '9adc36e82da9ea2a2ab89c55c9d9e0f900b0564'
                    '670c249d152e34513454ae339'),
    'dtor_glue': (0x5CDF3E0, 0x5CDF40B,
                  '43d63bba6836808e0519bcf9298238408cce90d3'
                  '4fd24c304a2a5b7c9be4c0f9'),
}

# GOT slots resolved through .rela.dyn/.rela.plt
# (all RELATIVE in this artifact).
SLOT_TARGETS = {
    0x64E17F8: 0x5CE9190,   # value drop helper
    0x64DF4A0: 0x635DE30,   # deallocation body
    0x64E73B8: 0x5BB4670,   # parking-table wait body
    0x64EC188: 0x5BB42E0,   # parking-table wake body
    0x64E01F8: 0x5BB59D0,   # parking-table byte wait
    0x64E0F38: 0x5BB5650,   # parking-table byte notify
}

VTABLE_VA = 0x64C6EF8
VTABLE_ENTRIES = [0x5CFDCE0, 0x5CFD8C0, 0x5CFD600,
                  0x5CFD5E0]  # clone, unpark+rel, unpark, rel

PARK_RS_PATH_VA = 0x447492
PARK_RS_PATH = ('/home/ubuntu/hl/code_Mainnet/z_vendor/'
                'tokio/src/runtime/park.rs')

# Panic Location statics: (record VA, line, col).
LOCATIONS = {
    'park': (0x64C6F48, 107, 28),
    'park_timeout_a': (0x64C6F30, 153, 28),
    'park_timeout_b': (0x64C6F18, 173, 18),
    'unpark': (0x64C6F60, 187, 18),
}

# Panic format texts: (lea target VA, text VA, text).
# For the first three the lea target is the final
# byte of the preceding packed literal; the readable
# format text starts one byte later.
MESSAGES = {
    'park': (0x438162, 0x438163,
             'inconsistent park state; actual = '),
    'park_timeout_a': (0x44635A, 0x44635B,
                       'inconsistent park_timeout state; '
                       'actual = '),
    'park_timeout_b': (0x43D49E, 0x43D49F,
                       'inconsistent park_timeout state: '),
    'unpark': (0x94DC34, 0x94DC34,
               'inconsistent state in unpark'),
}

PINS = {
    # dispatcher: pair formation (loop head + driver_c)
    0x2AE1974: '488b00',            # mov rax,[rax] (value)
    0x2AE1977: 'f048ff00',          # lock inc [rax] strong
    0x2AE1981: '4883c010',          # add rax,0x10 payload
    0x2AE1985: '488d0d6c559e03',    # lea rcx,[vtable]
    0x2AE1E0F: 'f048ff00',          # lock inc [rax] strong
    # dispatcher: out-of-line park call (before driver_a)
    0x2AE1AC7: 'e8c4c02103',        # call park
    # dispatcher: inline park copy inside driver_c
    0x2AE1E70: 'b001',              # mov al,0x1
    0x2AE1E72: 'f0440fb06500',      # lock cmpxchg byte release
    0x2AE1F1D: 'ff1515f09f03',      # call *byte_notify slot
    0x2AE1F79: 'f04d0fb16610',      # lock cmpxchg word 2->0
    0x2AE1F85: '498d6e20',          # lea rbp,[r14+0x20]
    0x2AE1F8D: 'f0410fb04e20',      # lock cmpxchg byte claim
    0x2AE1F9C: 'f0490fb14e10',      # lock cmpxchg word 0->1
    0x2AE1FA4: '498d5e18',          # lea rbx,[r14+0x18]
    0x2AE1FBB: '41ffd5',            # call r13 (wait body)
    0x2AE1FC3: 'f04d0fb16610',      # lock cmpxchg word 2->0
    0x2AE1FDC: '49874610',          # xchg [r14+0x10],rax
    0x2AE2005: 'ff15ede19f03',      # call *byte_wait slot
    # drop helper: sentinel, weak dec, dealloc tail jump
    0x5CE9190: '488b3f',            # mov rdi,[rdi]
    0x5CE9193: '4883ffff',          # cmp rdi,-1
    0x5CE9199: 'f048ff4f08',        # lock dec [rdi+0x8]
    0x5CE91A0: 'be28000000',        # mov esi,0x28
    0x5CE91A5: '31d2',              # xor edx,edx
    0x5CE91A7: 'ff25f3627f00',      # jmp *dealloc slot
    0x5CE91AD: 'c3',                # ret
    # wait body: token-word read + registration store
    0x5BB4793: '488b01',            # mov rax,[rcx]
    0x5BB47E1: '488b442408',        # mov rax,[rsp+0x8]
    0x5BB47E6: '488901',            # mov [rcx],rax
    # wake body: token re-read + deregistration stores
    0x5BB42F9: '498b06',            # mov rax,[r14]
    0x5BB447B: '49c70600000000',    # mov [r14],0
    0x5BB4542: '49c70600000000',    # mov [r14],0
    # unpark: token snapshot read
    0x5CFD649: '488b7708',          # mov rsi,[rdi+0x8]
    # caller 0x5a34440: inline park copy sites
    0x5A34B08: 'f0490fb14e10',
    0x5A34B22: 'f0410fb04e20',
    0x5A34B35: 'f0490fb14e10',
    0x5A34B68: 'f0490fb14e10',
    # caller 0x5a35480: inline park copy sites
    0x5A35944: 'f04c0fb17310',
    0x5A3596F: 'f0480fb14b10',
    0x5A35996: 'f04c0fb17b10',
}


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
                return data[off:section['offset']
                            + section['size']]
            check(off + size <= section['offset']
                  + section['size'],
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


def body_record(data, start, end, want_sha, extents):
    check((start, end) in extents,
          f'no FDE for body {start:#x}')
    raw = read(start, data, end - start)
    digest = sha(raw)
    check(digest == want_sha, f'digest drift {start:#x}')
    offset = None
    for section in sections(data):
        if section['address'] <= start < (section['address']
                                          + section['size']):
            offset = section['offset'] + (start
                                           - section['address'])
    return {'start': hex(start), 'end': hex(end),
            'file_offset': hex(offset), 'bytes': end - start,
            'sha256': digest}


def owners(data):
    extents = fde_extents(data)
    records = {}
    for role, (start, end) in OWNERS.items():
        records[role] = body_record(data, start, end,
                                    OWNER_SHA256[role], extents)
    return records


def pinned_bodies(data):
    extents = fde_extents(data)
    records = {}
    for role, (start, end, want) in PINNED_BODIES.items():
        rec = body_record(data, start, end, want, extents)
        rec['note'] = 'extent/digest only; not exported'
        records[role] = rec
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
    spans = list(OWNERS.values())
    spans += [(s, e) for s, e, _ in PINNED_BODIES.values()]
    for start, end in spans:
        needle = f'pc={start:016x}..{end:016x}'
        wanted += [ln for ln in text.splitlines()
                   if needle in ln]
    check(len(wanted) == len(spans), 'frame lines missing')
    return [line + '\n' for line in wanted]


def exports(data, role):
    start, end = OWNERS[role]
    text = subprocess.run(
        ['objdump', '-d', '-M', 'intel',
         '--no-show-raw-insn',
         '--start-address', hex(start),
         '--stop-address', hex(end), str(TARGET)],
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
            rows.append((int(m.group(1), 16),
                         m.group(3).strip()))
    return rows


def relocations(data):
    """(offset -> (type, sym_index, addend)) for both rela
    sections, plus the dynsym name resolver."""
    secs = {s['name']: s for s in sections(data)}
    out = {}
    for name in ('.rela.dyn', '.rela.plt'):
        sec = secs[name]
        for i in range(sec['size'] // 24):
            off, info, add = struct.unpack_from(
                '<QQq', data, sec['offset'] + i * 24)
            out[off] = (info & 0xFFFFFFFF, info >> 32, add)
    dsym = secs['.dynsym']
    dstr = secs['.dynstr']

    def sym_name(idx):
        off = dsym['offset'] + idx * 24
        noff = struct.unpack_from('<I', data, off)[0]
        begin = dstr['offset'] + noff
        return data[begin:data.find(b'\0', begin)].decode()

    return out, sym_name


def resolve_slots(data):
    relocs, sym_name = relocations(data)
    got = {}
    for slot, want in SLOT_TARGETS.items():
        check(slot in relocs, f'no relocation for {slot:#x}')
        typ, sym, add = relocs[slot]
        check(typ == 8, f'slot {slot:#x} not RELATIVE')
        got[hex(slot)] = hex(add)
        check(add == want,
              f'slot {slot:#x} -> {add:#x}, want {want:#x}')
    return got


def vtable_record(data):
    relocs, _ = relocations(data)
    entries = []
    for i, want in enumerate(VTABLE_ENTRIES):
        slot = VTABLE_VA + 8 * i
        check(slot in relocs, f'no relocation for {slot:#x}')
        typ, _sym, add = relocs[slot]
        check(typ == 8, f'vtable slot {slot:#x} not RELATIVE')
        check(add == want,
              f'vtable[{i}] -> {add:#x}, want {want:#x}')
        entries.append(hex(add))
    return {'static': hex(VTABLE_VA), 'entries': entries,
            'methods': ['clone', 'unpark_then_release',
                        'unpark', 'release']}


def locations_record(data):
    relocs, _ = relocations(data)
    path = read(PARK_RS_PATH_VA, data,
                len(PARK_RS_PATH)).decode()
    check(path == PARK_RS_PATH, 'park.rs path drift')
    out = {}
    for role, (va, line, col) in LOCATIONS.items():
        check(va in relocs, f'no relocation for {va:#x}')
        typ, _sym, add = relocs[va]
        check(typ == 8, f'Location {va:#x} not RELATIVE')
        check(add == PARK_RS_PATH_VA,
              f'Location {role} file -> {add:#x}')
        _p, flen, ln, cl = struct.unpack(
            '<QQII', read(va, data, 24))
        check((flen, ln, cl) == (len(PARK_RS_PATH), line, col),
              f'Location {role} fields drift')
        out[role] = {'static': hex(va),
                     'file': PARK_RS_PATH,
                     'line': line, 'col': col}
    return out


def messages_record(data):
    out = {}
    for role, (lea_va, text_va, text) in MESSAGES.items():
        raw = read(text_va, data, len(text))
        check(raw.decode() == text,
              f'message {role} drift')
        out[role] = {'lea_target': hex(lea_va),
                     'text_va': hex(text_va),
                     'text': text}
    return out


CENSUS_TARGETS = {
    'park': 0x5CFDB90, 'park_timeout': 0x5CFD9A0,
    'unpark': 0x5CFD600, 'unpark_release': 0x5CFD8C0,
    'release': 0x5CFD5E0, 'clone_wrap': 0x5CFDCE0,
    'wait_fn': 0x5BB4670, 'wake_fn': 0x5BB42E0,
    'drop_helper': 0x5CE9190, 'dealloc': 0x635DE30,
    'loop_getter': 0x5CDF300,
}

CENSUS_EXPECTED = {
    'park': {'calls': ['0x158e6dc', '0x158f415',
                       '0x2ae1ac7', '0x2b14bb4',
                       '0x5ab7137', '0x5cfd7f5',
                       '0x5cfdf8b'],
             'jmps': ['0x5ce087c']},
    'park_timeout': {'calls': ['0x5cf29c8', '0x5cfdeab',
                               '0x5cfdfa5'],
                     'jmps': ['0x5ce0193']},
    'unpark': {'calls': ['0x5a34bc8', '0x5a358b9'],
               'jmps': []},
    'unpark_release': {'calls': [], 'jmps': []},
    'release': {'calls': ['0x5a34c99', '0x5a35313',
                          '0x5a35aa5', '0x5a35f12',
                          '0x5ab7197', '0x5ab7296'],
                'jmps': []},
    'clone_wrap': {'calls': [], 'jmps': []},
    'wait_fn': {'calls': [], 'jmps': []},
    'wake_fn': {'calls': [], 'jmps': []},
    'drop_helper': {'calls': [], 'jmps': []},
    'dealloc': {'calls': [], 'jmps': []},
    'loop_getter': {'calls': [
        '0x158e6f0', '0x158e7c2', '0x158f424', '0x158f48b',
        '0x2ae1ad6', '0x2ae1fea', '0x2ae20a1', '0x2ae21f7',
        '0x2b14bc3', '0x2b14c51', '0x5a34c05', '0x5a3508d',
        '0x5a359dd', '0x5a35d81', '0x5ab714d', '0x5ab71f8',
        '0x5cf29d9', '0x5cf2a5c', '0x5cfd804', '0x5cfd868'],
        'jmps': []},
}

DROP_SLOT = 0x64E17F8
DROP_SLOT_EXPECTED = {
    'calls': ['0x5cdf38a', '0x5cdf3f6', '0x5ce7fe4',
              '0x5ce89f4', '0x5cea18e', '0x5cf7ffe',
              '0x5cfd5f3', '0x5cfd933', '0x5cfd97d'],
    'jmps': ['0x15dfcd8', '0x243a1b8', '0x26b5708',
             '0x29f22a8', '0x2abfd58', '0x5cdf8de',
             '0x5ce22db', '0x5cf7edb', '0x5cfc85a'],
}


def _verified_sites(data, candidates, want_in_text):
    """Keep only candidates that are true instruction
    starts in their containing FDE body's own
    disassembly, with the expected mnemonic and the
    expected target/slot hex in the row."""
    extents = sorted(fde_extents(data))
    cache = {}
    kept = []
    for va, kind in candidates:
        body = None
        for s, e in extents:
            if s <= va < e:
                body = (s, e)
                break
        if body is None:
            continue
        if body not in cache:
            cache[body] = {rva: txt for rva, txt
                           in disasm_rows(data, *body)}
        rows = cache[body]
        if va not in rows:
            continue
        text = rows[va]
        ins = text.split('#')[0].strip()
        if not ins.startswith(kind):
            continue
        if want_in_text not in text:
            continue
        kept.append((va, kind))
    return kept


def rel32_census(data, target):
    """Whole-.text rel32 scan for E8/E9 to `target`,
    every candidate boundary-verified."""
    secs = {s['name']: s for s in sections(data)}
    sec = secs['.text']
    buf = data[sec['offset']:sec['offset'] + sec['size']]
    va0 = sec['address']
    cand = []
    for m in re.finditer(rb'[\xe8\xe9]', buf):
        i = m.start()
        disp = int.from_bytes(buf[i + 1:i + 5], 'little',
                              signed=True)
        if va0 + i + 5 + disp == target:
            cand.append((va0 + i,
                         'call' if buf[i] == 0xE8 else 'jmp'))
    kept = _verified_sites(data, cand, f'{target:x}')
    return {
        'calls': sorted(hex(v) for v, k in kept
                        if k == 'call'),
        'jmps': sorted(hex(v) for v, k in kept
                       if k == 'jmp'),
    }


def slot_ref_census(data, slot):
    """Whole-.text scan for FF 15 / FF 25 references to
    a GOT slot, every candidate boundary-verified."""
    secs = {s['name']: s for s in sections(data)}
    sec = secs['.text']
    buf = data[sec['offset']:sec['offset'] + sec['size']]
    va0 = sec['address']
    cand = []
    for m in re.finditer(rb'\xff[\x15\x25]', buf):
        i = m.start()
        disp = int.from_bytes(buf[i + 2:i + 6], 'little',
                              signed=True)
        if va0 + i + 6 + disp == slot:
            cand.append((va0 + i,
                         'call' if buf[i + 1] == 0x15
                         else 'jmp'))
    kept = _verified_sites(data, cand, f'{slot:x}')
    return {
        'calls': sorted(hex(v) for v, k in kept
                        if k == 'call'),
        'jmps': sorted(hex(v) for v, k in kept
                       if k == 'jmp'),
    }


STORE_MNEMS = {'mov', 'movb', 'movw', 'movl', 'movq',
               'movups', 'movaps', 'movsd'}


def body_structure(data, start, end):
    rows = disasm_rows(data, start, end)
    rets, backward, locks, stores = [], set(), [], []
    slot_calls, direct_calls = {}, []
    for va, txt in rows:
        ins = txt.split('#')[0].strip()
        if not ins:
            continue
        mnem = ins.split(None, 1)[0]
        if ins == 'ret' or ins.startswith('ret '):
            rets.append(va)
        if mnem.startswith('j'):
            m = re.match(r'^j\w+\s+([0-9a-f]+)', ins)
            if m and int(m.group(1), 16) < va:
                backward.add(int(m.group(1), 16))
        if 'lock' in ins:
            locks.append(va)
        if mnem == 'call':
            if '*' in ins:
                m = re.search(r'#\s*([0-9a-f]+)', txt)
                slot_calls[va] = (hex(int(m.group(1), 16))
                                  if m else None)
            else:
                direct_calls.append(va)
        if mnem in STORE_MNEMS:
            operands = ins[len(mnem):].strip()
            dst = operands.rsplit(',', 1)[-1].strip()
            if '(' in dst:
                stores.append(va)
    return {
        'rets': [hex(v) for v in rets],
        'backward_targets': [hex(v) for v in sorted(backward)],
        'lock_sites': [hex(v) for v in locks],
        'slot_calls': {hex(k): v for k, v in slot_calls.items()},
        'direct_calls': [hex(v) for v in direct_calls],
        'stores': [hex(v) for v in stores],
    }


def rela_refs(data, roles):
    """Relocation references to each role's body start:
    addend hits and offset hits."""
    relocs, _ = relocations(data)
    starts = {}
    for role, span in OWNERS.items():
        starts[role] = span[0]
    for role, span in PINNED_BODIES.items():
        starts[role] = span[0]
    out = {}
    for role in roles:
        va = starts[role]
        out[role] = {
            'addend_hits': sorted(
                hex(off) for off, (t, s, a) in relocs.items()
                if a == va),
            'offset_hits': sorted(
                hex(off) for off, (t, s, a) in relocs.items()
                if off == va),
        }
    return out


DISPATCHER_ROW_VAS = [
    0x2AE1977, 0x2AE1AC7, 0x2AE1E0F, 0x2AE1E72,
    0x2AE1F1D, 0x2AE1F79, 0x2AE1F8D, 0x2AE1F9C,
    0x2AE1FBB, 0x2AE1FC3, 0x2AE1FDC, 0x2AE2005,
]


def dispatcher_rows(data):
    start, end, _sha = PINNED_BODIES['dispatcher']
    rows = {va: txt for va, txt in disasm_rows(data, start, end)}
    out = {}
    for va in DISPATCHER_ROW_VAS:
        check(va in rows, f'dispatcher row {va:#x} lost')
        out[hex(va)] = rows[va]
    check('64e0f38' in out['0x2ae1f1d'],
          'dispatcher notify call slot drift')
    check('64e01f8' in out['0x2ae2005'],
          'dispatcher byte-wait call slot drift')
    check('5cfdb90' in out['0x2ae1ac7'],
          'dispatcher park call drift')
    return out


FINDINGS = {
    'identity':
        'SETTLED. The 0x28-byte value the lazy getter '
        '0x5cdf300 creates for the cell at TLS base '
        '-0x418 is the shared parker state of the '
        'vendored tokio runtime park module. All four '
        'operations on it panic through Locations in '
        '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/'
        'src/runtime/park.rs -- park at line 107 '
        'col 28, park_timeout at lines 153 col 28 '
        'and 173 col 18, unpark at line 187 col 18 '
        '(Location statics 0x64c6f48 / 0x64c6f30 / '
        '0x64c6f18 / 0x64c6f60, all RELATIVE to the '
        'same 63-byte path string at 0x447492). The '
        'allocation is an Arc-style header (+0x0 '
        'strong count, +0x8 weak count, both created '
        'at 1 by the getter) plus a 0x18-byte payload '
        'at +0x10: park state word at +0x10, '
        'waiter-token word at +0x18, mutex byte at '
        '+0x20. The handle the dispatcher phases '
        'share is the fat pair {vtable 0x64c6ef8, '
        'payload pointer}: the vtable\'s four '
        'RELATIVE entries are clone 0x5cfdce0, '
        'unpark-then-release 0x5cfd8c0, unpark '
        '0x5cfd600 and release 0x5cfd5e0. The '
        'dispatcher forms the pair from the cell at '
        '0x2ae1974..0x2ae1991 (load value pointer, '
        'lock-inc its first qword, add 0x10, store '
        '{0x64c6ef8, payload} on the stack) and '
        'again at 0x2ae1e0f. On any one thread every '
        'getter caller operates on the single '
        'allocation that thread\'s getter created.',
    'drop_chain':
        '(a) SETTLED. The drop helper 0x5ce9190 '
        '(30 bytes, exported) takes a pointer to a '
        'pointer slot (rdi = &ptr). It loads the '
        'pointer (0x5ce9190); a pointer of -1 -- the '
        'moved-out sentinel -- returns at once '
        '(0x5ce9193). Otherwise it lock-decrements '
        'the WEAK count at +0x8 (0x5ce9199); if the '
        'count does not reach zero it returns '
        '(0x5ce91ad); if it reaches zero it '
        'tail-jumps through slot 0x64df4a0 to the '
        'deallocation body 0x635de30 (165 bytes, '
        'exported) with (pointer, size 0x28, 0), '
        'freeing exactly the 0x28-byte allocation. '
        'Nothing is closed, poisoned or destructed: '
        'the payload is plain data and has no '
        'destructor anywhere in the chain. The '
        'order around the helper is fixed by its '
        'callers: the strong owner lock-decrements '
        '+0x0 itself (release body 0x5cfd5e0, the '
        'second half of unpark_release, the '
        'getter\'s racing arm, the destructor glue) '
        'and calls the helper only when the strong '
        'count reaches zero, so the helper\'s weak '
        'decrement is the second and final count '
        'and the free happens exactly when both '
        'counts are exhausted. Reachability: the '
        'helper has no direct E8/E9 reference '
        'anywhere; it is reached only through slot '
        '0x64e17f8 -- 18 boundary-verified .text '
        'references (9 calls, 9 tail jumps), of '
        'which 5 are in this value\'s own cluster '
        '(getter 0x5cdf38a, glue 0x5cdf3f6, release '
        '0x5cfd5f3, unpark_release 0x5cfd933 and its '
        'landing pad 0x5cfd97d); the other 13 belong '
        'to other bodies dropping other 0x28-byte '
        'allocations through the same helper.',
    'state_word':
        '(b) SETTLED. The word at payload +0x10 '
        '(value +0x10) takes values 0 (empty), '
        '1 (parked), 2 (notified); the getter '
        'creates it at 0. park 0x5cfdb90 (321 bytes, '
        'exported; rdi = payload) first tries CAS '
        '2->0 to consume a pending notification. '
        'Otherwise it claims the mutex byte (CAS '
        '0->1 on +0x20; contention parks on the '
        'byte through byte-wait slot 0x64e01f8), '
        'then CASes the word 0->1: a racing 2 is '
        'consumed by an xchg to 0 (byte released, '
        'return); any other old value panics at '
        'park.rs:107 with the message at 0x438163. '
        'The wait loop calls the parking-table wait '
        'body 0x5bb4670 through slot 0x64e73b8 with '
        '(key = &+0x18, byte = &+0x20, timeout '
        '0x3b9aca00 = 1e9 ns) and retries CAS 2->0 '
        'until it succeeds; the byte is then '
        'released (CAS 1->0, byte-notify slot '
        '0x64e0f38 on contention). park_timeout '
        '0x5cfd9a0 (493 bytes, exported) runs the '
        'same arming, computes a deadline with the '
        'clock body 0x5c842e0 (clock id 1), and '
        'after the wait stores 0 with xchg and '
        'requires the old value in {1, 2}, panicking '
        'at park.rs:153 (message at 0x44635b) or '
        'park.rs:173 (message at 0x43d49f) '
        'otherwise. unpark 0x5cfd600 (160 bytes, '
        'exported) stores 2 with xchg: old 0 or 2 '
        'returns; old 1 claims and releases the '
        'byte, then, if the +0x18 token word is '
        'non-zero, tail-jumps through slot 0x64ec188 '
        'to the wake body 0x5bb42e0 with '
        '(&+0x18, token snapshot); any other old '
        'value panics at park.rs:187 with the '
        'message "inconsistent state in unpark" at '
        '0x94dc34 (panic call second argument is '
        'the constant 0x39, the same constant the '
        'RE-006 grow packet recorded; it is not a '
        'byte length). unpark_release 0x5cfd8c0 '
        '(209 bytes, exported) is unpark followed '
        'by the release protocol.',
    'dispatcher_use':
        '(b, dispatcher census) The dispatcher '
        '0x2ae1690 open-codes the whole park '
        'sequence inside driver_c on the cell\'s '
        'value (r14 = [cell], r12 = 0 from '
        '0x2ae1d82), at byte-pinned sites: CAS 2->0 '
        'at 0x2ae1f79, byte claim CAS at 0x2ae1f8d '
        '(rbp = &+0x20 from 0x2ae1f85), CAS 0->1 at '
        '0x2ae1f9c, consume xchg at 0x2ae1fdc, wait '
        'call (r13 = [slot 0x64e73b8], loaded at '
        '0x2ae1d85) at 0x2ae1fbb with '
        '(rbx = &+0x18 from 0x2ae1fa4, rsi = rbp, '
        'ecx = 0x3b9aca00), CAS 2->0 retry at '
        '0x2ae1fc3, byte release CAS 1->0 at '
        '0x2ae1e72 (accumulator set at 0x2ae1e70) '
        'with the byte-notify call at 0x2ae1f1d, '
        'byte wait call at 0x2ae2005, and the same '
        'park.rs:107 panic arm at 0x2ae2147 (same '
        'message 0x438162 lea, same Location '
        '0x64c6f48). Before driver_a it also calls '
        'the out-of-line park body once (0x2ae1ac7). '
        'Censused non-value lock operations in the '
        'same body are excluded: the prologue\'s '
        'other TLS cell at fs:[rbp+0x48] '
        '(rbp = -0x1130), the [rsp+0x118] object '
        '(lock inc at 0x2ae1bb5), the neighbouring '
        'TLS Arc at fs-0x428 (lock inc at '
        '0x2ae1c34, drop through a different slot), '
        'and the exit pair at [rsp+0x48]/[rsp+0x50]. '
        'Caller bodies 0x5a34440 and 0x5a35480 '
        'open-code the same park sequence (byte-'
        'pinned sites in records) and hold the only '
        'two direct calls to unpark (0x5a34bc8, '
        '0x5a358b9); the remaining getter callers '
        'use only the out-of-line park / park_timeout '
        '/ release calls (full rel32 census in '
        'records: park 7 calls and 1 tail jump -- '
        '0x5ce087c, in the 140-byte selector body '
        '0x5ce0850, whose one arm tail-jumps to '
        'park with the payload of the handle in '
        'its argument struct and whose zero arm '
        'tail-jumps to the 0x5cfdd00 park / '
        'park_timeout forwarder with ecx = '
        '0x3b9aca00 -- park_timeout 3 calls and 1 '
        'tail jump (0x5ce0193, in the matching '
        '137-byte selector body 0x5ce0160), '
        'unpark 2, release 6, and no direct call or '
        'jump to clone, unpark_release, the wait '
        'body, the wake body, the drop helper or '
        'the deallocation body). driver_a 0x2ae41e0 '
        'and driver_c 0x2cde430 receive the pair '
        'inside their argument structures and never '
        'call its methods or lock its payload.',
    'counts_byte_token':
        '(c) SETTLED. +0x0 is the strong count: '
        'created at 1; incremented by clone '
        '0x5cfdce0 (lock inc on [payload-0x10] with '
        'a signed-overflow trap) and by handle-pair '
        'formation (dispatcher 0x2ae1977 and '
        '0x2ae1e0f, and the guard clones in the '
        'caller bodies); decremented by release '
        '0x5cfd5e0, by unpark_release\'s second '
        'half, by the getter\'s racing arm and by '
        'the destructor glue, each of which invokes '
        'the drop helper exactly when the decrement '
        'reaches zero. +0x8 is the weak count: '
        'created at 1 (the implicit weak the strong '
        'allocation holds on itself); in every body '
        'traced here it is written only by the drop '
        'helper\'s decrement -- no weak-increment '
        'site exists in the value\'s cluster, its '
        'vtable, or the nine getter callers. Byte '
        '+0x20 is the parker\'s mutex byte: 0 free, '
        '1 held; claimed by CAS 0->1 and released '
        'by CAS 1->0 in park, park_timeout, unpark '
        'and the inline copies, with parking-table '
        'byte wait/notify on contention, and held '
        'across the whole park wait -- which is '
        'what makes unpark\'s claim-and-release a '
        'registration barrier against lost wakeups. '
        'Word +0x18 is the waiter token: created '
        'at 0; the parking-table wait body registers '
        'a waiter by storing the address of the '
        'value\'s own byte (+0x20) into it (read at '
        '0x5bb4793, store at 0x5bb47e6, in the '
        'exported wait body 0x5bb4670); it is '
        'therefore non-zero exactly while a waiter '
        'is registered, and its contents are that '
        'byte\'s address, which the parking layer '
        'uses as its per-key state pointer. unpark '
        'reads it only on the parked path '
        '(0x5cfd649) and passes the snapshot to the '
        'wake body, which re-reads the word '
        '(0x5bb42f9), requires it unchanged, works '
        'on the pointed-to byte\'s flag bits, and '
        'stores 0 back into the word (0x5bb447b, '
        '0x5bb4542) to deregister. The writer '
        'census for +0x18 is complete: {getter '
        'creation, wait-body registration, wake-body '
        'deregistration}; no other store to +0x18 '
        'exists in the dispatcher, the protocol '
        'bodies, the vtable methods, or the nine '
        'getter callers.',
}

OPEN_EDGES = [
    'The bit-level protocol the parking layer '
    'runs on the token byte (which bits the wake '
    'body 0x5bb42e0 and the byte wait body '
    '0x5bb59d0 set, test and clear at the byte '
    'the +0x18 word points to, and how the global '
    'table at 0x64ec148 chains waiters under the '
    'golden-ratio address hash) is extent/digest '
    'pinned here, not settled; it is the direct '
    'continuation of this trace.',
    'driver_a 0x2ae41e0 and driver_c 0x2cde430 '
    'receive the {vtable, payload} pair inside '
    'their argument structures and, in the '
    'traced windows, never call its methods or '
    'touch the payload; which structure fields '
    'carry the pair onward to its next consumer '
    'is not traced here.',
    'park_timeout\'s three call sites (0x5cf29c8 '
    'in body 0x5cf27c0; 0x5cfdeab and 0x5cfdfa5 '
    'in body 0x5cfdd00) pass timeout values this '
    'packet does not trace. Body 0x5cfdd00 '
    'selects park vs park_timeout by comparing '
    'a field against 0x3b9aca00, but the '
    'provenance of the timeout values stays '
    'open.',
    'No type-name string for the value itself '
    'was found: the name-bearing statics pinned '
    'are the four park.rs Locations and the '
    'panic messages. The layout matches the '
    'shared parker state of that module; a more '
    'specific source-level type name is not '
    'recorded in the artifact.',
]


def analyze(data):
    check(len(data) == TARGET_SIZE, 'artifact size drift')
    check(sha(data) == TARGET_SHA256, 'artifact sha drift')
    for va, want in PINS.items():
        raw = read(va, data, len(want) // 2)
        check(raw.hex() == want, f'pin drift at {va:#x}')
    census = {}
    for role, target in CENSUS_TARGETS.items():
        census[role] = rel32_census(data, target)
        check(census[role] == CENSUS_EXPECTED[role],
              f'call census drift for {role}: '
              f'{census[role]}')
    drop_refs = slot_ref_census(data, DROP_SLOT)
    check(drop_refs == DROP_SLOT_EXPECTED,
          f'drop slot census drift: {drop_refs}')
    records = {
        'artifact': {'size': TARGET_SIZE,
                     'sha256': TARGET_SHA256},
        'work_item': WORK_ITEM,
        'owners': owners(data),
        'pinned_bodies': pinned_bodies(data),
        'slots': resolve_slots(data),
        'vtable': vtable_record(data),
        'locations': locations_record(data),
        'messages': messages_record(data),
        'call_census': census,
        'drop_slot_refs': drop_refs,
        'dispatcher_rows': dispatcher_rows(data),
        'drop_helper_structure': body_structure(
            data, *OWNERS['drop_helper']),
        'park_structure': body_structure(
            data, *OWNERS['park']),
        'park_timeout_structure': body_structure(
            data, *OWNERS['park_timeout']),
        'unpark_structure': body_structure(
            data, *OWNERS['unpark']),
        'unpark_release_structure': body_structure(
            data, *OWNERS['unpark_release']),
        'wait_fn_structure': body_structure(
            data, *OWNERS['wait_fn']),
        'wake_fn_structure': body_structure(
            data, *OWNERS['wake_fn']),
        'rela_refs': rela_refs(
            data, ['drop_helper', 'park', 'park_timeout',
                   'unpark', 'unpark_release', 'release',
                   'clone_wrap', 'dealloc', 'wait_fn',
                   'wake_fn', 'dispatcher']),
        'findings': FINDINGS,
        'open_edges': OPEN_EDGES,
    }
    return records


def generate(records):
    OUT.mkdir(parents=True, exist_ok=True)
    data = TARGET.read_bytes()
    (OUT / 'records.json').write_text(
        json.dumps(records, indent=1, sort_keys=True) + '\n')
    for role in EXPORTED:
        (OUT / f'{role}.objdump.txt').write_text(
            exports(data, role))
    (OUT / 'frames.txt').write_text(
        ''.join(frame_lines(data)))
    manifest = []
    for path in sorted(OUT.iterdir()):
        if path.name == 'MANIFEST.sha256':
            continue
        manifest.append(
            f'{sha(path.read_bytes())}  {path.name}\n')
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
