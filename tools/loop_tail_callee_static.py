"""Static evidence for the RE-005 loop-tail-callee packet.

Answers the question the thunk / checker-windows packet
(#2755) carried over as its third open edge, for the
authenticated hl-node 115 artifact only: what is the
body 0x5cdf300 whose non-null return at the dispatcher
call site 0x2ae21f7 keeps the dispatcher loop (head
0x2ae1974, back-edge jne at 0x2ae21ff) running?

SETTLED.  The body 0x5cdf300..0x5cdf3df (223 bytes) is
the shared lazy thread-local getter for one key: a cell
{value pointer at +0x0, state byte at +0x8}.  Its own
unreachable arm is pinned by the compiler to std's
native lazy thread-local implementation
(/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/
library/std/src/sys/thread_local/native/lazy.rs,
line 98, col 36; message "internal error: entered
unreachable code").

Behaviour, by entry state byte [cell+0x8]:

- state 1 (live): returns the cell pointer unchanged,
  with no reads or writes beyond the state byte.
- state 0 (uninitialised): slow path.  If the adopt
  slot in rsi is non-null and holds a non-null pointer,
  that pointer is adopted (the slot is zeroed, the
  pointer installed, state set to 1).  Otherwise a
  fresh 0x28-byte value is allocated through slot
  0x64df480 and initialised in place (qwords +0x0 and
  +0x8 set to 1, +0x10..+0x1f zeroed, byte +0x20 set
  to 0), installed, and state set to 1.  Either way the
  per-key destructor glue 0x5cdf3e0 is registered
  through slot 0x64e0510 (registrar body 0x5ca0d20)
  and the cell pointer is returned.  A racing /
  re-entrant install whose reloaded state is 1 drops
  the displaced pointer through slot 0x64e17f8
  (drop helper 0x5ce9190) after a `lock dec` on its
  first qword; any other reloaded state reaches the
  std unreachable panic through slot 0x64df730, and
  allocation failure diverges through slot 0x64df490.
- any other state (2 = destroyed, or anything else):
  returns null, touching nothing.

The destructor glue 0x5cdf3e0..0x5cdf40b (43 bytes,
exported) is what sets state 2: it stores 2 to the
state byte first, then, if the old state was 1,
`lock dec`s the value's first qword and drops it
through the same drop helper when the count reaches
zero.

Nothing in the body counts iterations: it has no
backward branch except jumps to its shared epilogue
(0x5cdf317), no increment of any counter, and exactly
one locked operation (the displaced-pointer `lock
dec`).  It therefore imposes no bound on the
dispatcher loop.  The loop can leave through the tail
call only when the cell state is no longer 0 or 1 --
in practice once the glue has run on that thread
(state 2).

Caller census (whole-.text rel32 call/jump scan,
every hit re-verified against the containing body's
own disassembly): exactly 20 direct call sites in 9
bodies, no tail jumps, and every site passes rsi = 0
(`xor esi,esi` in the setup block), so the adoption
arm is never exercised by a direct caller.  Every
caller body forms the same cell address, TLS base
minus 0x418 (state byte at TLS base minus 0x410; the
cell sits at PT_TLS template offset 0xd68, inside the
zero-initialised tail past filesz 0xb20, so it starts
as {0, 0}).  The dispatcher 0x2ae1690 alone has four
sites -- 0x2ae1ad6, 0x2ae1fea, 0x2ae20a1, 0x2ae21f7 --
each the slow path of an open-coded `state == 1`
guard on the same byte (cmpb at 0x2ae1962, 0x2ae1ab2,
0x2ae1dfa, 0x2ae1f63; cell pointer in r15 from
`lea -0x418(%rax),%r15` at 0x2ae195b / 0x2ae1d7b);
only the 0x2ae21f7 site's non-null return loops back
to the head 0x2ae1974.

Method: two bodies are exported in full (the getter
and its destructor glue); every other body is
extent/digest pinned.  Censuses: whole-.text rel32
call/jump scan for both exported bodies; per-caller
disassembly verification of the argument setup and of
the cell-address formation; rip-relative lea/mov scan
with overlap rejection; .rela.dyn/.rela.plt addend
and offset census; whole-file exact qword/u32 scan
plus an aligned-word interior scan over every
section; PT_TLS header parse.  Section mapping:
.rodata identity, .text VA-0x1000, .data.rel.ro
VA-0x2000 (via the section table).
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
WORK_ITEM = 'RE-005-node115-loop-tail-callee'
OUT = ROOT / 'research' / 'work-items' / WORK_ITEM
SNAPSHOT = '<authenticated-node115>'

OWNERS = {
    'loop_getter': (0x5CDF300, 0x5CDF3DF),
    'dtor_glue': (0x5CDF3E0, 0x5CDF40B),
}
EXPORTED = list(OWNERS)

OWNER_SHA256 = {
    'loop_getter': '9adc36e82da9ea2a2ab89c55c9d9e0f900b056467'
                   '0c249d152e34513454ae339',
    'dtor_glue': '43d63bba6836808e0519bcf9298238408cce90d34'
                 'fd24c304a2a5b7c9be4c0f9',
}

# Extent/digest pins only; none of these is exported.
PINNED_BODIES = {
    'dispatcher': (0x2AE1690, 0x2AE27B2,
                   '6ca0595c13836bca0cb0173bd591a09d6da679153'
                   '2e23a5a71c63715380727d9'),
    'tls_dtor': (0x5CDF410, 0x5CDF457,
                 '83808b635c9c4571afcf4b915c2803f2707f64b0a4'
                 'fc4c43fd5cbe88465c302c'),
    'registrar': (0x5CA0D20, 0x5CA0E1F,
                  'b41b5cc834002de4b875118dffe3ede7cd50f595'
                  'dd8e5103a0f08a9cedae254e'),
    'drop_helper': (0x5CE9190, 0x5CE91AE,
                    '67ddc5751bdc61595db2fcfe90854482ec02741'
                    'f02ad3bbb83748593ec6e5372'),
    'alloc_shim': (0x6355830, 0x63558F2,
                   '72c29274a75359df7c598d254d102cbab84f51d3'
                   '59256facb415bb90bffec5af'),
    'panic_shim': (0x1680E60, 0x1680E72,
                   '2c4e17b271b60cd074de9b63a359b89c8f04f3c5'
                   '9e8c076b156618dc7fba2aee'),
}

# GOT slots resolved through .rela.dyn/.rela.plt
# (all RELATIVE in this artifact).
SLOT_TARGETS = {
    0x64DF480: 0x6355830,   # allocation (size in edi)
    0x64DF490: 0x141E251,   # allocation-failure entry
    0x64DF730: 0x1680E60,   # panic entry
    0x64E0510: 0x5CA0D20,   # destructor registrar
    0x64E17F8: 0x5CE9190,   # value drop helper
}

PINS = {
    # getter: state dispatch
    0x5CDF308: '0fb64708',        # movzbl 0x8(%rdi),%eax
    0x5CDF30C: '85c0',            # test %eax,%eax
    0x5CDF30E: '7410',            # je slow path
    0x5CDF310: '83f801',          # cmp $0x1,%eax
    0x5CDF313: '7402',            # je return cell
    0x5CDF315: '31db',            # xor %ebx,%ebx (null)
    # getter: adoption arm
    0x5CDF320: '4885f6',          # test %rsi,%rsi
    0x5CDF325: '488b06',          # mov (%rsi),%rax
    0x5CDF328: '48c70600000000',  # movq $0,(%rsi)
    0x5CDF334: '488903',          # mov %rax,(%rbx)
    0x5CDF337: 'c6430801',        # movb $1,0x8(%rbx)
    # getter: allocation + value initialisation
    0x5CDF33D: 'bf28000000',      # mov $0x28,%edi
    0x5CDF342: 'ff1538018000',    # call *alloc slot
    0x5CDF34D: '48c70001000000',  # movq $1,(%rax)
    0x5CDF354: '48c7400801000000',  # movq $1,0x8(%rax)
    0x5CDF35C: '0f57c0',          # xorps %xmm0,%xmm0
    0x5CDF35F: '0f114010',        # movups %xmm0,0x10(%rax)
    0x5CDF363: 'c6402000',        # movb $0,0x20(%rax)
    0x5CDF367: '0fb64b08',        # movzbl 0x8(%rbx),%ecx
    0x5CDF36B: '488b13',          # mov (%rbx),%rdx
    0x5CDF373: '488903',          # mov %rax,(%rbx)
    0x5CDF376: 'c6430801',        # movb $1,0x8(%rbx)
    0x5CDF37A: '83f901',          # cmp $0x1,%ecx
    0x5CDF37F: 'f048ff0a',        # lock decq (%rdx)
    0x5CDF385: '488d7c2408',      # lea 0x8(%rsp),%rdi
    0x5CDF38A: 'ff1568248000',    # call *drop slot
    # getter: destructor registration + failure arms
    0x5CDF399: '85c9',            # test %ecx,%ecx
    0x5CDF39D: '488d353c000000',  # lea glue,%rsi
    0x5CDF3A4: '4889df',          # mov %rbx,%rdi
    0x5CDF3A7: 'ff1563118000',    # call *registrar slot
    0x5CDF3B6: 'bf08000000',      # mov $0x8,%edi
    0x5CDF3BB: 'be28000000',      # mov $0x28,%esi
    0x5CDF3C0: 'ff15ca008000',    # call *alloc-fail slot
    0x5CDF3C6: '488d3d0ed6c6fa',  # lea panic msg,%rdi
    0x5CDF3CD: '488d1574637e00',  # lea Location,%rdx
    0x5CDF3D4: 'be28000000',      # mov $0x28,%esi
    0x5CDF3D9: 'ff1551038000',    # call *panic slot
    # glue: state 2 + conditional drop
    0x5CDF3E1: '0fb64708',        # movzbl 0x8(%rdi),%eax
    0x5CDF3E5: 'c6470802',        # movb $2,0x8(%rdi)
    0x5CDF3E9: '3c01',            # cmp $0x1,%al
    0x5CDF3ED: '488b07',          # mov (%rdi),%rax
    0x5CDF3F0: 'f048ff08',        # lock decq (%rax)
    0x5CDF3F6: 'ff15fc238000',    # call *drop slot
    # dispatcher: cell formation + guards
    0x2AE1952: '64488b042500000000',  # mov %fs:0x0,%rax
    0x2AE195B: '4c8db8e8fbffff',  # lea -0x418(%rax),%r15
    0x2AE1962: '64803c25f0fbffff01',  # cmpb $1,fs:-0x410
    0x2AE1AB2: '64803c25f0fbffff01',
    0x2AE1D72: '64488b042500000000',
    0x2AE1D7B: '4c8db8e8fbffff',
    0x2AE1DFA: '64803c25f0fbffff01',
    0x2AE1F63: '64803c25f0fbffff01',
    # dispatcher: the four getter call sites
    0x2AE1AD1: '4c89ff',          # mov %r15,%rdi
    0x2AE1AD4: '31f6',            # xor %esi,%esi
    0x2AE1AD6: 'e825d81f03',      # call getter
    0x2AE1ADB: '4885c0',          # test %rax,%rax
    0x2AE1ADE: '75e0',            # jne use block
    0x2AE1FE5: '4c89ff',
    0x2AE1FE8: '31f6',
    0x2AE1FEA: 'e811d31f03',
    0x2AE1FEF: '4885c0',
    0x2AE1FF2: '0f8579ffffff',    # jne 0x2ae1f71
    0x2AE209C: '4c89ff',
    0x2AE209F: '31f6',
    0x2AE20A1: 'e85ad21f03',
    0x2AE20A6: '4885c0',
    0x2AE20A9: '0f855dfdffff',    # jne 0x2ae1e0c
    0x2AE21F2: '4c89ff',
    0x2AE21F5: '31f6',
    0x2AE21F7: 'e804d11f03',
    0x2AE21FC: '4885c0',
    0x2AE21FF: '0f856ff7ffff',    # jne loop head
}

# The 20 verified direct call sites of the getter and
# the FDE body that contains each.
CALLER_BODIES = {
    0x158CDC0: (0x158F262, [0x158E6F0, 0x158E7C2]),
    0x158F270: (0x158F4E0, [0x158F424, 0x158F48B]),
    0x2AE1690: (0x2AE27B2, [0x2AE1AD6, 0x2AE1FEA,
                            0x2AE20A1, 0x2AE21F7]),
    0x2B149D0: (0x2B14CE7, [0x2B14BC3, 0x2B14C51]),
    0x5A34440: (0x5A3539F, [0x5A34C05, 0x5A3508D]),
    0x5A35480: (0x5A35F48, [0x5A359DD, 0x5A35D81]),
    0x5AB6DF0: (0x5AB72B5, [0x5AB714D, 0x5AB71F8]),
    0x5CF27C0: (0x5CF2AAB, [0x5CF29D9, 0x5CF2A5C]),
    0x5CFD6A0: (0x5CFD8BA, [0x5CFD804, 0x5CFD868]),
}

DISPATCHER_SITES = [
    {'call': 0x2AE1AD6, 'setup': 0x2AE1AD1,
     'test': 0x2AE1ADB, 'branch': 0x2AE1ADE,
     'branch_target': 0x2AE1AC0,
     'on_null': 'falls through to the log-and-exit '
                'block at 0x2ae1ae0'},
    {'call': 0x2AE1FEA, 'setup': 0x2AE1FE5,
     'test': 0x2AE1FEF, 'branch': 0x2AE1FF2,
     'branch_target': 0x2AE1F71,
     'on_null': 'jumps to the dispatcher exit block '
                'at 0x2ae2442'},
    {'call': 0x2AE20A1, 'setup': 0x2AE209C,
     'test': 0x2AE20A6, 'branch': 0x2AE20A9,
     'branch_target': 0x2AE1E0C,
     'on_null': 'falls through to the log-and-exit '
                'block at 0x2ae20af'},
    {'call': 0x2AE21F7, 'setup': 0x2AE21F2,
     'test': 0x2AE21FC, 'branch': 0x2AE21FF,
     'branch_target': 0x2AE1974,
     'on_null': 'falls through to the final cleanup '
                'call at 0x2ae2205'},
]


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


def call_census(data, target):
    """Whole-.text rel32 scan: E8 (call) and E9 (jmp)
    whose target is exactly `target`."""
    secs = {s['name']: s for s in sections(data)}
    sec = secs['.text']
    buf = data[sec['offset']:sec['offset'] + sec['size']]
    va0 = sec['address']
    calls, jmps = [], []
    for m in re.finditer(rb'[\xe8\xe9]', buf):
        i = m.start()
        disp = int.from_bytes(buf[i + 1:i + 5], 'little',
                              signed=True)
        if va0 + i + 5 + disp == target:
            (calls if buf[i] == 0xE8 else jmps).append(
                hex(va0 + i))
    return {'calls': calls, 'jmps': jmps}


LEA_TARGETS = {
    'loop_getter': 0x5CDF300, 'dtor_glue': 0x5CDF3E0,
    'dispatcher': 0x2AE1690,
}


def lea_census(data):
    """Rip-relative lea/mov scan over .text (REX and
    non-REX forms), with the overlap rejection the
    earlier packets used."""
    secs = {s['name']: s for s in sections(data)}
    sec = secs['.text']
    buf = data[sec['offset']:sec['offset'] + sec['size']]
    va0 = sec['address']
    inv = {v: k for k, v in LEA_TARGETS.items()}
    hits = {k: [] for k in LEA_TARGETS}
    spans = []

    def scan(pattern, length, rex):
        last_end = -1
        for m in re.finditer(pattern, buf):
            i = m.start()
            if i < last_end:
                continue
            last_end = i + length
            if rex:
                disp = int.from_bytes(buf[i + 3:i + 7],
                                      'little', signed=True)
                tgt = va0 + i + 7 + disp
            else:
                if any(s <= i < e for s, e in spans):
                    continue
                disp = int.from_bytes(buf[i + 2:i + 6],
                                      'little', signed=True)
                tgt = va0 + i + 6 + disp
            if tgt in inv:
                hits[inv[tgt]].append(hex(va0 + i))
                if rex:
                    spans.append((i, i + 7))

    scan(rb'[\x40-\x4f][\x8d\x8b]'
         rb'[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', 7, True)
    scan(rb'[\x8d\x8b][\x05\x0d\x15\x1d\x25\x2d\x35\x3d]',
         6, False)
    return {k: sorted(v) for k, v in hits.items()}


def absolute_refs(data):
    """Exact qword / u32 occurrences of the getter and
    glue addresses anywhere in the file, plus an
    aligned-u64 interior scan of every section."""
    out = {}
    for name, va in (('loop_getter', 0x5CDF300),
                     ('dtor_glue', 0x5CDF3E0)):
        for width, fmt in (('qword', '<Q'), ('u32', '<I')):
            pat = struct.pack(fmt, va)
            hits = []
            i = 0
            while True:
                i = data.find(pat, i)
                if i < 0:
                    break
                hits.append(hex(i))
                i += 1
            out[f'{name}_{width}'] = hits
    ranges = [(0x5CDF300, 0x5CDF3DF), (0x5CDF3E0, 0x5CDF40B)]
    interior = []
    for sec in sections(data):
        if sec['type'] == 8 or sec['size'] < 8:
            continue
        body = data[sec['offset']:sec['offset'] + sec['size']]
        n = len(body) // 8
        vals = struct.unpack(f'<{n}Q', body[:n * 8])
        for idx, val in enumerate(vals):
            if any(lo <= val < hi for lo, hi in ranges):
                interior.append({'section': sec['name'],
                                 'offset': hex(sec['offset']
                                               + idx * 8),
                                 'value': hex(val)})
    out['interior_aligned'] = interior
    return out


def pt_tls(data):
    """The PT_TLS program header (type 7)."""
    phoff = struct.unpack_from('<Q', data, 32)[0]
    entsize, count = struct.unpack_from('<HH', data, 54)
    for i in range(count):
        base = phoff + i * entsize
        typ = struct.unpack_from('<I', data, base)[0]
        if typ == 7:
            off, vaddr, _p, filesz, memsz = \
                struct.unpack_from('<QQQQQ', data, base + 8)
            return {'offset': hex(off), 'vaddr': hex(vaddr),
                    'filesz': filesz, 'memsz': memsz}
    raise ValueError('no PT_TLS header')


STORE_MNEMS = {'mov', 'movb', 'movw', 'movl', 'movq',
               'movups', 'movaps', 'movsd'}


def verify_callers(data):
    """Re-derive every censused call site from its own
    body's disassembly: the call must be a real
    instruction, its setup block must zero rsi and set
    rdi, and the body must form the cell address with a
    `lea -0x418(%rax)` from the TLS base."""
    extents = fde_extents(data)
    records = []
    for start, (end, sites) in sorted(CALLER_BODIES.items()):
        check((start, end) in extents,
              f'caller body {start:#x} has no FDE')
        rows = disasm_rows(data, start, end)
        by_va = {va: i for i, (va, _t) in enumerate(rows)}
        cell_leas = [va for va, txt in rows
                     if '-0x418(%rax)' in ' '.join(txt.split())]
        check(cell_leas, f'no cell lea in body {start:#x}')
        for site in sites:
            check(site in by_va,
                  f'call site {site:#x} not an instruction')
            idx = by_va[site]
            ins = rows[idx][1].split('#')[0].strip()
            check(ins.startswith('call')
                  and '5cdf300' in ins,
                  f'site {site:#x} is not a getter call')
            window = rows[max(0, idx - 6):idx]
            xor_rows = [va for va, txt in window
                        if 'xor %esi,%esi' in ' '.join(txt.split())]
            check(xor_rows,
                  f'no rsi zeroing before {site:#x}')
            rdi_rows = [va for va, txt in window
                        if txt.split('#')[0].strip()
                        .endswith(',%rdi')]
            check(rdi_rows,
                  f'no rdi setup before {site:#x}')
            records.append({
                'site': hex(site), 'body': hex(start),
                'rdi_setup': hex(rdi_rows[-1]),
                'rsi_zero': hex(xor_rows[-1]),
                'cell_lea': hex(cell_leas[0]),
            })
    return records


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


def dispatcher_sites(data):
    start, end, _sha = PINNED_BODIES['dispatcher']
    rows = disasm_rows(data, start, end)
    by_va = {va: i for i, (va, _t) in enumerate(rows)}
    out = []
    for spec in DISPATCHER_SITES:
        call = spec['call']
        check(call in by_va, f'dispatcher site {call:#x} lost')
        idx = by_va[call]
        setup_va, setup_txt = rows[idx - 2]
        xor_va, xor_txt = rows[idx - 1]
        test_va, test_txt = rows[idx + 1]
        br_va, br_txt = rows[idx + 2]
        check(setup_va == spec['setup']
              and 'mov %r15,%rdi' in ' '.join(setup_txt.split()),
              f'setup drift at {call:#x}')
        check('xor %esi,%esi' in ' '.join(xor_txt.split()),
              f'rsi setup drift at {call:#x}')
        check(test_va == spec['test']
              and 'test %rax,%rax' in ' '.join(test_txt.split()),
              f'test drift at {call:#x}')
        m = re.search(r'([0-9a-f]+)\s*<',
                      br_txt.split('#')[0])
        check(br_va == spec['branch'] and m
              and int(m.group(1), 16) == spec['branch_target'],
              f'branch drift at {call:#x}')
        out.append({
            'call': hex(call), 'setup': hex(spec['setup']),
            'test': hex(spec['test']),
            'branch': hex(spec['branch']),
            'branch_target': hex(spec['branch_target']),
            'on_null': spec['on_null'],
        })
    return out


def dispatcher_guards(data):
    start, end, _sha = PINNED_BODIES['dispatcher']
    rows = disasm_rows(data, start, end)
    return {
        'cell_defs': [hex(va) for va, txt in rows
                      if 'lea -0x418(%rax),%r15' in ' '.join(txt.split())],
        'guard_cmps': [hex(va) for va, txt in rows
                       if '0xfffffffffffffbf0' in txt],
    }


def panic_record(data):
    relocs, _ = relocations(data)
    typ, _sym, add = relocs[0x64C5748]
    check(typ == 8, 'Location pointer not RELATIVE')
    _ptr, flen, line, col = struct.unpack(
        '<QQII', read(0x64C5748, data, 24))
    return {
        'message_va': '0x94c9db',
        'message': read(0x94C9DB, data, 0x28).decode(),
        'location_static': '0x64c5748',
        'location_file': read(add, data, flen).decode(),
        'location_line': line,
        'location_col': col,
    }


def tls_record(data):
    hdr = pt_tls(data)
    template_off = hdr['memsz'] - 0x418
    return {
        'pt_tls_vaddr': hdr['vaddr'],
        'pt_tls_offset': hdr['offset'],
        'filesz': hdr['filesz'],
        'memsz': hdr['memsz'],
        'cell_fs_offset': '-0x418',
        'state_fs_offset': '-0x410',
        'cell_template_offset': hex(template_off),
        'cell_in_zero_region': template_off >= hdr['filesz'],
    }


FINDINGS = {
    'getter_identity':
        'SETTLED. The body 0x5cdf300..0x5cdf3df (223 '
        'bytes) is the shared lazy thread-local getter '
        'for a single key in this artifact. Its cell is '
        '{value pointer at +0x0, state byte at +0x8}; '
        'its unreachable arm is pinned to std\'s native '
        'lazy thread-local code (lazy.rs line 98 col 36, '
        'message "internal error: entered unreachable '
        'code"), and every direct caller in the artifact '
        '(20 call sites in 9 bodies, machine-checked '
        'census) passes the same cell -- the thread-'
        'local at TLS offset -0x418, template offset '
        '0xd68, zero-initialised -- and passes rsi = 0.',
    'null_vs_nonnull':
        'The getter returns the cell pointer itself '
        '(never the value pointer) in exactly two '
        'cases: the entry state byte is 1 (live), or it '
        'is 0 and initialisation completes (adoption of '
        'a non-null *rsi, or allocation of a fresh '
        '0x28-byte value). It returns null in exactly '
        'one case: the entry state byte is neither 0 '
        'nor 1 -- in practice 2, the destroyed state '
        'the destructor glue 0x5cdf3e0 stores before '
        'dropping the value. Allocation failure and a '
        'racing reloaded state other than 0 or 1 do not '
        'return at all: they diverge through the '
        'allocation-failure slot 0x64df490 and the std '
        'unreachable panic slot 0x64df730.',
    'reads_writes':
        'Fast paths (state 1, or state other than 0/1) '
        'read only the state byte and write nothing. '
        'The state-0 path reads and zeroes the adopt '
        'slot *rsi when rsi is non-null, reads the old '
        'cell pointer and the state byte a second time '
        'after installing, writes the value pointer and '
        'state 1 to the cell, initialises a freshly '
        'allocated value in place (qwords +0x0/+0x8 := '
        '1, +0x10..+0x1f := 0, byte +0x20 := 0), and on '
        'the racing arm lock-decrements the displaced '
        'pointer\'s first qword and drops it through '
        'slot 0x64e17f8 if it reaches zero. The only '
        'locked operation in the body is that single '
        'lock dec at 0x5cdf37f.',
    'no_iteration_bound':
        'Nothing in the body bounds any iteration '
        'count: there is no counter field, no increment '
        'anywhere in the body, and no backward branch '
        'except jumps to the shared epilogue at '
        '0x5cdf317. Per dispatcher-loop iteration the '
        'tail call therefore returns non-null whenever '
        'the key is live, and the loop at head '
        '0x2ae1974 can be left through this call only '
        'after the key\'s destructor glue has run on '
        'the dispatcher\'s thread (state 2).',
    'dispatcher_use':
        'The dispatcher 0x2ae1690 calls the getter '
        'four times, each time as the slow path of an '
        'open-coded state==1 guard on the same byte '
        '(cmpb $0x1 at fs:-0x410 at 0x2ae1962, '
        '0x2ae1ab2, 0x2ae1dfa, 0x2ae1f63, with the cell '
        'pointer in r15 from lea -0x418(%rax),%r15 at '
        '0x2ae195b and 0x2ae1d7b, and rsi zeroed at '
        'every setup). Only the last site, the call at '
        '0x2ae21f7, is the loop tail: jne at 0x2ae21ff '
        'returns to the head 0x2ae1974 on non-null, '
        'while null falls through to the final cleanup '
        'call at 0x2ae2205. The earlier sites guard the '
        'per-phase uses of the value (0x2ae1ad6 before '
        'the driver_a phase, 0x2ae1fea and 0x2ae20a1 '
        'around the driver_c phase) and exit the '
        'dispatcher outright on null.',
    'adoption_arm_negative':
        'BOUNDED NEGATIVE. No direct caller exercises '
        'the adoption arm: all 20 censused call sites '
        'pass rsi = 0 (setup verified per site from '
        'each containing body\'s disassembly). The '
        'getter also has no RELATIVE reference, no '
        'rip-relative lea/mov naming it, and no '
        'absolute qword/u32 occurrence anywhere in the '
        'file, so an indirect caller would have to '
        'hold a code pointer in a form outside these '
        'censuses.',
}

OPEN_EDGES = [
    'The source-level name of this thread-local key '
    'is not recorded in the artifact. The 0x28-byte '
    'value is identified only by its uses: two '
    'refcount-shaped leading qwords (the dispatcher '
    'lock-incs the first and lock-cmpxchgs the word '
    'at +0x10), zeroed +0x10..+0x1f at creation, and '
    'a zero byte at +0x20.',
    'Whether the dispatcher loop ever exits through '
    'the tail call at runtime -- which requires the '
    'key\'s destructor glue to have run on the '
    'dispatcher\'s own thread -- is a dynamic '
    'question the static trace does not decide.',
    'The adoption arm (rsi non-null) is traced '
    'inside the getter but has no censused caller; '
    'whether std-internal code reaches it through a '
    'reference form outside this packet\'s censuses '
    'stays open.',
]


def analyze(data):
    check(len(data) == TARGET_SIZE, 'artifact size drift')
    check(sha(data) == TARGET_SHA256, 'artifact sha drift')
    for va, want in PINS.items():
        raw = read(va, data, len(want) // 2)
        check(raw.hex() == want, f'pin drift at {va:#x}')
    census = call_census(data, 0x5CDF300)
    census_glue = call_census(data, 0x5CDF3E0)
    all_sites = sorted(site for _s, (_e, sites)
                       in CALLER_BODIES.items()
                       for site in sites)
    check([int(s, 16) for s in census['calls']] == all_sites,
          'getter call census drift')
    check(census['jmps'] == [] and census_glue['calls'] == []
          and census_glue['jmps'] == [],
          'unexpected tail-jump or glue caller')
    records = {
        'artifact': {'size': TARGET_SIZE,
                     'sha256': TARGET_SHA256},
        'work_item': WORK_ITEM,
        'owners': owners(data),
        'pinned_bodies': pinned_bodies(data),
        'slots': resolve_slots(data),
        'call_census': {'loop_getter': census,
                        'dtor_glue': census_glue},
        'callers': verify_callers(data),
        'dispatcher_sites': dispatcher_sites(data),
        'dispatcher_guards': dispatcher_guards(data),
        'getter_structure': body_structure(
            data, *OWNERS['loop_getter']),
        'glue_structure': body_structure(
            data, *OWNERS['dtor_glue']),
        'tls': tls_record(data),
        'panic': panic_record(data),
        'rela_refs': rela_refs(
            data, ['loop_getter', 'dtor_glue', 'dispatcher',
                   'registrar', 'drop_helper']),
        'lea_census': lea_census(data),
        'absolute_refs': absolute_refs(data),
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
