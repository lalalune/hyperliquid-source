"""Static evidence for the RE-005 thunk / checker-windows packet.

Answers the two questions the remaining-edges packet
(PR #2741) carried over, for the authenticated hl-node
115 artifact only:

1.  The dispatcher's thunk 0x2cd8370: by what mechanism
    is it invoked, and does that mechanism bound how
    often the drivers re-invoke the gates?
    SETTLED.  The mechanism is the ordinary program
    entry chain, not a data-held slot and not an
    .init_array entry: _start passes the Rust main shim
    (0x2cef8f0) to __libc_start_main; the shim builds a
    stack closure whose first word is the thunk address
    (lea at 0x2cef8f7, store at 0x2cef8fe) and calls the
    runtime entry body 0x5c99970 (GOT slot 0x64e6c30,
    RELATIVE -> 0x5c99970) with the closure pointer and
    a static table at 0x6440b48.  After runtime init the
    entry body calls the function pointer stored at
    [table+0x28] (0x5c99e21) -- RELATIVE slot 0x6440b70
    -> trampoline 0x292c5c0 -- which loads closure[0]
    (the thunk) into rdi and calls the 5-byte indirect
    caller 0x2c7bb70 (`call *%rdi`).  The thunk therefore
    runs exactly once per process, on the main thread,
    at start-up.  Every other reference form is censused
    negative below: no direct call/jump to the thunk
    anywhere in .text, no RELATIVE/absolute reference,
    no .init_array/.fini_array entry.
    The invocation mechanism imposes no rate bound:
    re-invocation frequency is set by the dispatcher's
    own loop -- one backward span (head 0x2ae1974,
    back-edge jne at 0x2ae21ff, taken while the TLS
    accessor body 0x5cdf300 called at 0x2ae21f7 returns
    non-null) encloses both driver call sites
    (driver_a 0x2ae1a47, driver_c 0x2ae1eeb), so each
    driver -- and, per #2741, each gate twice -- runs
    once per dispatcher-loop iteration.
2.  The two untraced checker_a call windows
    (0x2b90b05 in body 0x2b905a0, 0x2cc7fb5 in body
    0x2cc1120): does either reach the checker with a
    nonzero state byte?
    BOTH WINDOWS BREAK the zero-before-call invariant
    of #2741 on one of their two inbound edges.  Each
    call-setup block has exactly two inbound edges in
    the whole .text (direct-branch census plus the
    body's jump tables): one jump lands immediately
    after a zero store to the entry byte, the other is
    a jump-table case (table 0x607328 case 4 on byte
    [rbx+0xca] for window A; table 0x60bdb8 case 4 on
    byte [r15+0x1da] for window B) with no zeroing
    store on its path.  Window B's entry byte also has
    a second, non-constant in-body store: at 0x2cc5125
    it is written from cl, a byte copied out of the
    record itself ([r15+0x10d], loaded at 0x2cc5031)
    during a record-duplication phase.  On the
    un-zeroed edges the checker receives the entry byte
    as last written -- by the checker itself (3, on its
    predicate-nonzero arm; #2741) or by the duplication
    copy -- so a nonzero entry byte is not excluded
    for either window and the checker resume arm stays
    reachable in principle through both.

Method: four small bodies are exported in full (thunk,
main shim, trampoline, indirect caller); every other
body is extent/digest pinned.  Censuses: whole-.text
direct-branch scan (E8/E9 rel32, 0F 8x rel32, EB/7x
rel8); whole-.text rip-relative lea/mov scan with
overlap rejection; .rela.dyn/.rela.plt addend and
offset census; whole-file exact qword/u32 scan plus an
aligned-word interior scan over every section;
.init_array/.fini_array resolution through the
relocation map; per-window store censuses over the
disassembly (stores through the object-base register
whose byte range covers the checker entry byte);
jump-table decoding for the two switch tables.
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
WORK_ITEM = 'RE-005-node115-thunk-checker-windows'
OUT = ROOT / 'research' / 'work-items' / WORK_ITEM
SNAPSHOT = '<authenticated-node115>'

OWNERS = {
    'thunk': (0x2CD8370, 0x2CD83AF),
    'main_shim': (0x2CEF8F0, 0x2CEF917),
    'trampoline': (0x292C5C0, 0x292C5CD),
    'indirect_caller': (0x2C7BB70, 0x2C7BB75),
}
EXPORTED = list(OWNERS)

OWNER_SHA256 = {
    'thunk': 'ed23bc89640a43b1a5f373d5cb18929d79ce5b47923e'
             '58ba0565f592ba2b60d6',
    'main_shim': 'c0621248d6ec3fd7ae1ee2df6b09bdd79541219362'
                 'b313e5567717eb8f59a5c9',
    'trampoline': 'db5dda988668ccd38fdd5497478b4debb42cef10'
                  'df0ff03b88cff2b65343976c',
    'indirect_caller': 'dfa92fdb18d3efd032329f2235d028649d'
                       'b70c80c85efbf1934b940879949131',
}

# Extent/digest pins only; none of these is exported.
PINNED_BODIES = {
    'rt_entry': (0x5C99970, 0x5C9A045,
                 '85c321c5ef4dd64cd999ac133e97a170ffa7d088e'
                 'ab3fe7fcb64f31768181111'),
    'dispatcher': (0x2AE1690, 0x2AE27B2,
                   '6ca0595c13836bca0cb0173bd591a09d6da679153'
                   '2e23a5a71c63715380727d9'),
    'caller_a': (0x2B905A0, 0x2B91042,
                 '1211adcc8256be7e443381a98b92f2078c5873033'
                 '2bcd2efc1837eddfe29939f'),
    'caller_b': (0x2CC1120, 0x2CC971B,
                 '3efcb009eaf0ab2e2a477d73edbf7834894109e9f'
                 'dcd943460d2bce59b9a0c57'),
    'checker_a': (0x2C7F360, 0x2C7F71B,
                  'ff59e02e9d3e078985ba6e3b58d8f64f3a6ed5171'
                  'f2120d314cbb5a3c744daed'),
}

# GOT / static-table slots resolved through .rela.dyn
# (RELATIVE addends) or .dynsym (imported names).
SLOT_TARGETS = {
    0x64DF458: '__libc_start_main',
    0x64E6C30: 0x5C99970,
    0x6440B60: 0x292E230,
    0x6440B68: 0x292C5C0,
    0x6440B70: 0x292C5C0,
    0x6440B78: 0x4480D1,
}

PINS = {
    0x1419318: '488d3dd1658d01',      # _start: lea main,%rdi
    0x141931F: 'ff1533610c05',        # _start: call *__libc_start_main
    0x2CEF8F7: '488d05728afeff',      # shim: lea thunk,%rax
    0x2CEF8FE: '48890424',            # shim: mov %rax,(%rsp)
    0x2CEF902: '488d353f127503',      # shim: lea table,%rsi
    0x2CEF90F: 'ff151b737f03',        # shim: call *rt_entry slot
    0x5C99E19: '488b7da0',            # rt_entry: mov -0x60(%rbp),%rdi
    0x5C99E21: 'ff5028',              # rt_entry: call *0x28(%rax)
    0x292C5C1: '488b3f',              # trampoline: mov (%rdi),%rdi
    0x292C5C4: 'e8a7f53400',          # trampoline: call indirect_caller
    0x2C7BB71: 'ffd7',                # indirect_caller: call *%rdi
    0x2CD8395: 'c684242202000000',    # thunk: movb $0,0x222(%rsp)
    0x2CD839D: '488d7c2408',          # thunk: lea 0x8(%rsp),%rdi
    0x2CD83A2: 'e8e992e0ff',          # thunk: call dispatcher
    0x2AE1A47: 'e894270000',          # dispatcher: call driver_a
    0x2AE1EEB: 'e840c51f00',          # dispatcher: call driver_c
    0x2AE21F7: 'e804d11f03',          # dispatcher loop tail: call 0x5cdf300
    0x2AE21FF: '0f856ff7ffff',        # dispatcher: jne loop head
    0x2B90725: '0fb683ca000000',      # A: movzbl 0xca(%rbx),%eax
    0x2B90730: '488d0df16ba7fd',      # A: lea table 0x607328,%rcx
    0x2B9074D: 'ffe0',                # A: jmp *%rax
    0x2B9087E: 'e970020000',          # A: jmp setup block
    0x2B90AF3: '4c8dabf0000000',      # A: lea 0xf0(%rbx),%r13
    0x2B90B05: 'e856e80e00',          # A: call checker_a
    0x2B90B12: '80bb8001000003',      # A: cmpb $3,0x180(%rbx)
    0x2B90DDB: 'c6838001000000',      # A: movb $0,0x180(%rbx)
    0x2B90DE2: 'e90cfdffff',          # A: jmp setup block
    0x2CC21D0: '410fb687da010000',    # B: movzbl 0x1da(%r15),%eax
    0x2CC21E4: '488d0dcd9b94fd',      # B: lea table 0x60bdb8,%rcx
    0x2CC21F2: 'ffe0',                # B: jmp *%rax
    0x2CC5031: '410fb68f0d010000',    # B: movzbl 0x10d(%r15),%ecx
    0x2CC5125: '41888fd0020000',      # B: mov %cl,0x2d0(%r15)
    0x2CC7FA6: '498d9f40020000',      # B: lea 0x240(%r15),%rbx
    0x2CC7FB5: 'e8a673fbff',          # B: call checker_a
    0x2CC7FC6: '80bbd002000003',      # B: cmpb $3,0x2d0(%rbx)
    0x2CC92BE: '41c687d002000000',    # B: movb $0,0x2d0(%r15)
    0x2CC92C6: 'e9dbecffff',          # B: jmp setup block
}

STORE_MNEMS = {'mov', 'movb', 'movw', 'movl', 'movq',
               'movups', 'movaps', 'movsd', 'xchg', 'cmpxchg'}
BYTE_REGS = {'al', 'bl', 'cl', 'dl', 'ah', 'bh', 'ch', 'dh',
             'sil', 'dil', 'spl', 'bpl'} | {f'r{i}b'
                                            for i in range(8, 16)}
WORD_REGS = {'ax', 'bx', 'cx', 'dx', 'si', 'di', 'sp', 'bp'} | \
            {f'r{i}w' for i in range(8, 16)}
LONG_REGS = {'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp',
             'ebp'} | {f'r{i}d' for i in range(8, 16)}


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
        if typ == 8:            # RELATIVE
            got[hex(slot)] = hex(add)
            check(add == want,
                  f'slot {slot:#x} -> {add:#x}, want {want:#x}')
        else:                   # symbolic (GLOB_DAT / JUMP_SLOT)
            got[hex(slot)] = sym_name(sym)
            check(got[hex(slot)] == want,
                  f'slot {slot:#x} name drift')
    return got


def rela_refs(data, roles):
    """ Relocation references to each role's body start:
    addend hits (slots pointing at the body) and offset
    hits (relocations applied at the body address)."""
    relocs, _ = relocations(data)
    starts = {}
    for role, span in list(OWNERS.items()):
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


def branch_census(data, targets):
    """Whole-.text direct-branch scan: E8/E9 rel32,
    0F 8x rel32, EB rel8, 7x rel8.  Returns for each
    target the sorted list of (site, kind)."""
    secs = {s['name']: s for s in sections(data)}
    sec = secs['.text']
    buf = data[sec['offset']:sec['offset'] + sec['size']]
    va0 = sec['address']
    want = {t: [] for t in targets}
    for m in re.finditer(rb'[\xe8\xe9]', buf):
        i = m.start()
        disp = int.from_bytes(buf[i + 1:i + 5], 'little',
                              signed=True)
        tgt = va0 + i + 5 + disp
        if tgt in want:
            want[tgt].append({'site': hex(va0 + i),
                              'kind': 'call' if buf[i] == 0xE8
                              else 'jmp'})
    for m in re.finditer(rb'\x0f[\x80-\x8f]', buf):
        i = m.start()
        disp = int.from_bytes(buf[i + 2:i + 6], 'little',
                              signed=True)
        tgt = va0 + i + 6 + disp
        if tgt in want:
            want[tgt].append({'site': hex(va0 + i),
                              'kind': 'jcc'})
    for m in re.finditer(rb'[\xeb\x70-\x7f]', buf):
        i = m.start()
        disp = int.from_bytes(buf[i + 1:i + 2], 'little',
                              signed=True)
        tgt = va0 + i + 2 + disp
        if tgt in want:
            want[tgt].append({'site': hex(va0 + i),
                              'kind': 'jcc8' if buf[i] != 0xEB
                              else 'jmp8'})
    return {hex(t): sorted(v, key=lambda e: int(e['site'], 16))
            for t, v in want.items()}


LEA_TARGETS = {
    'thunk': 0x2CD8370, 'dispatcher': 0x2AE1690,
    'driver_a': 0x2AE41E0, 'driver_c': 0x2CDE430,
    'gate_a': 0x2AEAEF0, 'gate_c': 0x2CB6500,
    'checker_a': 0x2C7F360,
}


def lea_census(data):
    """Rip-relative lea/mov scan over .text (REX and
    non-REX forms).  Candidates that begin inside an
    already-accepted candidate's span are dropped, which
    removes the overlapping mid-instruction decodes a
    pure byte scan produces."""
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
    """Exact qword / u32 occurrences of the thunk and
    dispatcher addresses anywhere in the file, plus an
    aligned-u64 interior scan of every section for
    values inside either body's extent."""
    out = {}
    for name, va in (('thunk', 0x2CD8370),
                     ('dispatcher', 0x2AE1690)):
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
    ranges = [(0x2CD8370, 0x2CD83AF), (0x2AE1690, 0x2AE27B2)]
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


def init_arrays(data):
    relocs, _ = relocations(data)
    secs = {s['name']: s for s in sections(data)}
    out = {}
    for name in ('.init_array', '.fini_array'):
        sec = secs[name]
        entries = []
        for i in range(sec['size'] // 8):
            va = sec['address'] + i * 8
            raw = struct.unpack_from(
                '<Q', data, sec['offset'] + i * 8)[0]
            if va in relocs and relocs[va][0] == 8:
                raw = relocs[va][2]
            entries.append(raw)
        out[name[1:]] = {
            'count': len(entries),
            'entries': [hex(e) for e in entries],
            'contains_thunk': 0x2CD8370 in entries,
            'contains_dispatcher': 0x2AE1690 in entries,
        }
    return out


def store_width(mnem, src):
    if mnem in ('movups', 'movaps'):
        return 16
    if mnem == 'movsd':
        return 8
    if mnem.endswith('b'):
        return 1
    if mnem.endswith('w'):
        return 2
    if mnem.endswith('l'):
        return 4
    if mnem.endswith('q'):
        return 8
    if src.startswith('%'):
        reg = src[1:].split(',')[0]
        if reg in BYTE_REGS:
            return 1
        if reg in WORD_REGS:
            return 2
        if reg in LONG_REGS:
            return 4
        if reg.startswith('xmm'):
            return 16
        return 8
    if src.startswith('$'):
        return 1
    return 8


def covering_stores(data, start, end, base_reg, byte_off):
    """Stores through `base_reg` whose byte range covers
    `byte_off`, from the body's disassembly."""
    found = []
    for va, ins in disasm_rows(data, start, end):
        text = ins.split('#')[0].strip()
        if not text:
            continue
        parts = text.split(None, 1)
        mnem = parts[0]
        rest = parts[1] if len(parts) > 1 else ''
        if mnem == 'lock':
            sub = rest.split(None, 1)
            mnem = sub[0]
            rest = sub[1] if len(sub) > 1 else ''
        if mnem not in STORE_MNEMS or not rest:
            continue
        operands = [o.strip() for o in rest.split(',')]
        dst = operands[-1]
        m = re.match(r'^([+-]?0x[0-9a-f]+|[+-]?\d+)?\(%'
                     + base_reg + r'\)$', dst)
        if not m:
            continue
        disp = int(m.group(1), 0) if m.group(1) else 0
        width = store_width(mnem, operands[0])
        if disp <= byte_off < disp + width:
            found.append({'site': hex(va), 'mnem': mnem,
                          'src': operands[0], 'disp': disp,
                          'width': width})
    return found


def decode_table(data, base, count):
    raw = read(base, data, count * 4)
    out = []
    for i in range(count):
        off = struct.unpack_from('<i', raw, i * 4)[0]
        out.append(hex(base + off))
    return out


def dispatcher_loop(data):
    start, end, _ = PINNED_BODIES['dispatcher']
    rows = disasm_rows(data, start, end)
    spans = []
    tail = None
    for va, ins in rows:
        text = ins.split('#')[0].strip()
        m = re.match(r'^(j[a-z]+)\s+([0-9a-f]+)(?:\s*<.*>)?$',
                     text)
        if m:
            tgt = int(m.group(2), 16)
            if tgt < va:
                spans.append((tgt, va))
            if va == 0x2AE21FF:
                tail = {'head': hex(tgt), 'backedge': hex(va)}
    check(tail is not None, 'dispatcher back-edge missing')
    inside = {}
    for name, site in (('driver_a', 0x2AE1A47),
                       ('driver_c', 0x2AE1EEB)):
        inside[name] = any(lo <= site <= hi for lo, hi in spans
                           if lo == 0x2AE1974 and hi == 0x2AE21FF)
    return {'loop_head': tail['head'],
            'backedge_site': tail['backedge'],
            'tail_accessor_call': '0x2ae21f7',
            'tail_accessor': '0x5cdf300',
            'driver_calls_inside_span': inside}


FINDINGS = {
    'thunk_mechanism':
        'SETTLED. _start (0x1419300) passes main 0x2cef8f0 '
        'to __libc_start_main (GOT 0x64df458). The main '
        'shim (0x2cef8f0..0x2cef917, exported) builds a '
        'stack closure whose first word is the thunk: lea '
        '0x2cd8370 at 0x2cef8f7, store (%rsp) at '
        '0x2cef8fe; it then calls the runtime entry body '
        '0x5c99970 via GOT slot 0x64e6c30 (RELATIVE -> '
        '0x5c99970) with rdi=&closure, rsi=static table '
        '0x6440b48, rdx=argc, rcx=argv, r8=0. After '
        'runtime initialisation the entry body loads the '
        'table pointer it saved and calls the function '
        'pointer at [table+0x28] at 0x5c99e21; that slot '
        '(0x6440b70, RELATIVE) holds trampoline '
        '0x292c5c0 (exported), which loads closure[0] '
        'into rdi (0x292c5c1) and calls the 5-byte '
        'indirect caller 0x2c7bb70 (exported), whose '
        '`call *%rdi` at 0x2c7bb71 invokes the thunk. '
        'So the thunk is invoked once per process, on '
        'the main thread, by program entry -- not via a '
        'registered table slot in a data segment, and '
        'not via runtime start-up registration: all 168 '
        '.init_array entries and the single .fini_array '
        'entry resolve elsewhere, and no direct branch, '
        'RELATIVE addend/offset, absolute qword/u32 or '
        'aligned interior word anywhere in the artifact '
        'names the thunk or the dispatcher. (The '
        'runtime entry body is the one body in the '
        'chain a relocation does name: GOT slot '
        '0x64e6c30, the very slot the shim calls '
        'through.)',
    'thunk_frequency_bound':
        'The entry mechanism fires exactly once, so it '
        'imposes no rate bound. Re-invocation is bounded '
        'only by the dispatcher body itself: the backward '
        'span with head 0x2ae1974 and back-edge jne at '
        '0x2ae21ff (taken while the body 0x5cdf300 '
        'called at 0x2ae21f7 returns non-null) encloses '
        'both driver call sites (driver_a 0x2ae1a47, '
        'driver_c 0x2ae1eeb), so per dispatcher-loop '
        'iteration each driver runs once and, per #2741, '
        'each gate is called twice by its driver.',
    'window_a_2b90b05':
        'The call at 0x2b90b05 uses instance rbx+0xf0 '
        '(lea at 0x2b90af3); the checker entry byte is '
        '[rbx+0x180] (instance+0x90), tested ==3 right '
        'after the call at 0x2b90b12. The setup block '
        '0x2b90af3 has exactly two inbound edges in the '
        'whole .text: jmp at 0x2b90de2, immediately after '
        'the zero store movb $0,[rbx+0x180] at '
        '0x2b90ddb; and jmp at 0x2b9087e, which is case 4 '
        'of jump table 0x607328 (dispatched on byte '
        '[rbx+0xca], loaded at 0x2b90725, indirect jump '
        'at 0x2b9074d) with no store to the entry byte '
        'on its path. The only store to [rbx+0x180] in '
        'the whole body is the zero store at 0x2b90ddb '
        '(store census). On the table edge the checker '
        'therefore receives the byte as last written -- '
        'by checker_a itself (3 on its predicate-nonzero '
        'arm) or by code outside this body -- and the '
        'zero-before-call invariant of #2741 does NOT '
        'hold for this window.',
    'window_b_2cc7fb5':
        'The call at 0x2cc7fb5 uses instance r15+0x240 '
        '(lea at 0x2cc7fa6); the checker entry byte is '
        '[r15+0x2d0] (instance+0x90), tested ==3 right '
        'after the call at 0x2cc7fc6. The setup block '
        '0x2cc7fa6 has exactly two inbound edges in the '
        'whole .text: jmp at 0x2cc92c6, immediately after '
        'the zero store movb $0,[r15+0x2d0] at '
        '0x2cc92be; and case 4 of jump table 0x60bdb8 '
        '(dispatched on byte [r15+0x1da], loaded at '
        '0x2cc21d0, indirect jump at 0x2cc21f2) with no '
        'zeroing store on its path. The entry byte has '
        'exactly two stores in the body (store census): '
        'the zero store at 0x2cc92be and, at 0x2cc5125, '
        'a non-constant store mov %cl,[r15+0x2d0] in a '
        'record-duplication phase, where cl is the byte '
        'copied from [r15+0x10d] (loaded at 0x2cc5031). '
        'The zero-before-call invariant of #2741 does '
        'NOT hold for this window either.',
}

OPEN_EDGES = [
    'Whether the un-zeroed table edges (0x607328 case 4, '
    '0x60bdb8 case 4) are exercised with a nonzero entry '
    'byte at runtime is a dynamic question: statically '
    'the byte can be 3 (left by a previous checker_a '
    'call) or a copied value (window B), but which '
    'object states actually reach those cases is not '
    'decidable from these two bodies alone.',
    'The two checker_a clone callers of the gate_a '
    'mirror family (census in #2741 records.json, '
    'checker_a_clone sites) were not re-traced here; '
    'their zero-before-call status stays as #2741 left '
    'it.',
    'The dispatcher loop tail callee 0x5cdf300 is '
    'identified only as the body whose non-null return '
    'keeps the loop running (it sits in the TLS '
    'accessor cluster next to the destructor '
    '0x5cdf410 of #2741); its own body is not traced '
    'in this packet.',
]


def analyze(data):
    check(len(data) == TARGET_SIZE, 'artifact size drift')
    check(sha(data) == TARGET_SHA256, 'artifact sha drift')
    for va, want in PINS.items():
        raw = read(va, data, len(want) // 2)
        check(raw.hex() == want, f'pin drift at {va:#x}')
    records = {
        'artifact': {'size': TARGET_SIZE,
                     'sha256': TARGET_SHA256},
        'work_item': WORK_ITEM,
        'owners': owners(data),
        'pinned_bodies': pinned_bodies(data),
        'slots': resolve_slots(data),
        'branch_censuses': branch_census(
            data, [0x2CD8370, 0x2AE1690, 0x2B90AF3,
                   0x2CC7FA6, 0x2B9087E]),
        'lea_census': lea_census(data),
        'rela_refs': rela_refs(
            data, ['thunk', 'dispatcher', 'trampoline',
                   'rt_entry', 'main_shim',
                   'indirect_caller']),
        'absolute_refs': absolute_refs(data),
        'init_arrays': init_arrays(data),
        'jump_tables': {
            '0x607328': {
                'dispatch_load': '0x2b90725',
                'dispatch_byte': '[rbx+0xca]',
                'dispatch_jump': '0x2b9074d',
                'entries': decode_table(data, 0x607328, 5),
                'setup_index': 4,
                'next_table_base': '0x60733c',
            },
            '0x60bdb8': {
                'dispatch_load': '0x2cc21d0',
                'dispatch_byte': '[r15+0x1da]',
                'dispatch_jump': '0x2cc21f2',
                'entries': decode_table(data, 0x60BDB8, 5),
                'setup_index': 4,
                'next_table_base': '0x60bdcc',
            },
        },
        'windows': {
            'caller_a': {
                'body': '0x2b905a0',
                'instance_lea': '0x2b90af3',
                'instance': '[rbx+0xf0]',
                'call': '0x2b90b05',
                'entry_byte': '[rbx+0x180]',
                'post_call_test': '0x2b90b12',
                'stores_covering_entry_byte':
                    covering_stores(data, 0x2B905A0,
                                    0x2B91042, 'rbx', 0x180),
            },
            'caller_b': {
                'body': '0x2cc1120',
                'instance_lea': '0x2cc7fa6',
                'instance': '[r15+0x240]',
                'call': '0x2cc7fb5',
                'entry_byte': '[r15+0x2d0]',
                'post_call_test': '0x2cc7fc6',
                'stores_covering_entry_byte':
                    covering_stores(data, 0x2CC1120,
                                    0x2CC971B, 'r15', 0x2D0),
                'copied_byte_source':
                    {'load': '0x2cc5031',
                     'from': '[r15+0x10d]', 'reg': 'cl'},
            },
        },
        'dispatcher_loop': dispatcher_loop(data),
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
