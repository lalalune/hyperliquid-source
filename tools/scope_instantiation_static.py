#!/usr/bin/env python3
"""Node 115: is std::thread::scope instantiated anywhere in the binary?

The packet-cell-context packet (RE-005-node115-packet-cell-context,
PR #3204) pinned the packet cells' context pointer as the std
scoped-thread state (ScopeData, library/std/src/thread/scoped.rs):
the spawn bodies increment its counter at A+0x18 with an overflow
path through the shared stub 0x5c82d40, and that stub panics with
the artifact's only scoped.rs panic Location (0x64c32f0, line 60
col 9) and the message "too many running threads in thread scope".
That packet also pinned that all 16 call sites of all 14 spawn
monomorphisations pass a null context -- but it left one question
open as an explicit boundary: whether std::thread::scope itself
is instantiated anywhere in the artifact.  A Scope::spawn
instantiation that built its packet without going through those
14 spawn bodies would have evaded the call-site census.

This packet closes the question with four censuses over the
authenticated ELF, each of which a thread::scope instantiation
would necessarily disturb:

1.  String census.  Every monomorphisation of thread::scope
    carries the scope-exit panic

        if a_thread_panicked { panic!("a scoped thread panicked") }

    on a data-dependent branch (the flag is stored by a spawned
    thread's unwind path, so the branch cannot be folded away).
    The 25-byte string "a scoped thread panicked" occurs nowhere
    in the artifact's 105,896,032 bytes, and the substring
    "scoped" occurs exactly once -- inside the scoped.rs file
    path string itself.

2.  Location census.  A panic Location static is a {file ptr,
    file len, line, col} record whose file pointer is a
    R_X86_64_RELATIVE relocation addend.  Scanning all 60,723
    .rela.dyn entries for the scoped.rs path string recovers
    exactly one Location (0x64c32f0: line 60, col 9 -- the
    overflow panic the stub references).  There is no Location
    for the scope-exit panic and none for Scope::spawn's
    .expect("failed to spawn thread"), although the same scan
    recovers 1,209 std .rs Location records overall, so the
    method is not blind.

3.  Stub xref census.  The overflow stub 0x5c82d40 is called
    directly (E8/E9) from exactly 14 sites, and every site lies
    in one of the 14 spawn bodies the context packet pinned
    (site-for-site identical with that packet's stub_call_site
    list).  The stub's address occurs nowhere as data: no
    8-byte literal anywhere outside the relocation tables and
    no relocation addend names it, so it has no indirect entry.
    Any Scope::spawn that built its own packet would still need
    an increment, and an increment's overflow reaches a panic
    only through this stub or through its own reference to the
    Location -- and the Location's only code reference in the
    artifact is the stub's lea at 0x5c82d53 (census 4).

4.  Decrement census.  The standalone ScopeData::decrement body
    (0x5c82d00) has no direct caller at all; its address is
    named by exactly one relocation slot (0x64ec708), and the
    only call through that slot is the overflow stub's rollback
    call at 0x5c82d46 with the panic flag argument zeroed.  The
    decrement therefore exists in the artifact solely as the
    overflow path's undo step.

Conclusion: thread::scope is not instantiated in this artifact.
The scope machinery that survives is exactly {the overflow stub,
the decrement body it rolls back through, and the counter
ledger inlined in the 14 spawn bodies and their payload drops},
and ScopeData is never constructed: the only ScopeData-shaped
object the binary can hand to a spawn is the null every known
call site passes (PR #3204), and there is no other producer.
"""

from __future__ import annotations

import hashlib
import json
import struct
import subprocess
from bisect import bisect_right
from pathlib import Path

from artifacts import ROOT

TARGET = ROOT / 'artifacts/node/115/hl-node'
TARGET_SIZE = 105896032
TARGET_SHA256 = ('a6e2897cd051213d004802deca416e8eca62b7'
                 'a8278fa39f249e98c3867b5301')
SNAPSHOT = '<authenticated-node115>'
WORK_ITEM = 'RE-005-node115-scope-instantiation'
OUT = ROOT / 'research/work-items' / WORK_ITEM

RUSTC = '59807616e1fa2540724bfbac14d7976d7e4a3860'
SCOPED_PATH = (f'/rustc/{RUSTC}/library/std/src/thread/scoped.rs'
               .encode())
EXIT_PANIC = b'a scoped thread panicked'
OVERFLOW_MSG = b'too many running threads in thread scope'

STUB = 0x5c82d40
STUB_END = 0x5c82d65
DECREMENT = 0x5c82d00
DECREMENT_END = 0x5c82d3b
LOCATION = 0x64c32f0
DECREMENT_SLOT = 0x64ec708
PANIC_SLOT = 0x64df6b8
PANIC_TARGET = 0x1680e80
FUTEX_SLOT = 0x64e06b8

OWNERS = {
    'scope_overflow_stub': (STUB, STUB_END),
    'scope_decrement': (DECREMENT, DECREMENT_END),
}
EXPORTED = ('scope_overflow_stub', 'scope_decrement')

# The 14 spawn bodies whose overflow call sites the packet-cell
# context packet pinned (its spawn census), by FDE start.
SPAWN_STARTS = (
    0x15b6d10, 0x15b73c0, 0x15b7a80, 0x15b80e0,
    0x2d46820, 0x2d46f90, 0x2d47710,
    0x5613a70, 0x56141f0, 0x5614960, 0x56150d0,
    0x5bc2c90, 0x5cd9470, 0x5cf6e80,
)

PINS = {
    # decrement: test esi,esi / movb $1,flag / lock decq counter /
    # xchg parker word / jmp futex slot
    'decrement_test_flag_arg': (0x5c82d00, '85f6'),
    'decrement_store_flag': (0x5c82d04, 'c6471001'),
    'decrement_lock_decq': (0x5c82d08, 'f048ff4f08'),
    'decrement_xchg_parker': (0x5c82d17, '874628'),
    'decrement_futex_jmp': (0x5c82d35, 'ff257dd98500'),
    # stub: rollback call through the decrement slot, the two
    # lea's (message, Location), panic call through its slot
    'stub_rollback_call': (0x5c82d46, 'ff15bc998600'),
    'stub_lea_message': (0x5c82d4c, '488d3d6c65ccfa'),
    'stub_lea_location': (0x5c82d53, '488d1596058400'),
    'stub_panic_call': (0x5c82d5f, 'ff1553c98500'),
}

QUESTION = (
    'The packet-cell-context packet (PR #3204) pinned the packet '
    'cells\' context pointer as std\'s ScopeData and showed every '
    'call site of every spawn monomorphisation passing a null '
    'context, but left open whether std::thread::scope itself is '
    'instantiated anywhere in the binary: a Scope::spawn that '
    'built its packet without going through those spawn bodies '
    'would have evaded the call-site census.  Is thread::scope '
    'instantiated in node 115, and if not, what scope machinery '
    'survives?')

ANSWER = (
    'thread::scope is not instantiated in this artifact.  Four '
    'censuses, each of which any instantiation would disturb, '
    'are closed: the scope-exit panic string "a scoped thread '
    'panicked" occurs nowhere in the artifact; exactly one '
    'panic Location names scoped.rs (line 60 col 9, the overflow '
    'panic), with none for the scope-exit panic or for '
    'Scope::spawn\'s expect; the overflow stub 0x5c82d40 is '
    'called from exactly the 14 known spawn bodies and has no '
    'indirect entry; and the standalone ScopeData::decrement '
    'body 0x5c82d00 is entered only as the stub\'s rollback.  '
    'ScopeData is therefore never constructed in the binary: '
    'the surviving scope machinery is the overflow stub, the '
    'decrement body, and the counter ledger inlined in the '
    'spawn bodies and payload drops, all of it reachable only '
    'with the null context every spawn call site passes.')

BOUNDARIES = {
    'static_census': (
        'This is a static census over the artifact\'s bytes, '
        'relocations and code references; it does not execute '
        'the binary.  A thread::scope body could evade it only '
        'if the compiler had deleted the scope-exit panic '
        'together with its string and Location while keeping '
        'the body -- the panic sits on a data-dependent flag '
        'store performed by another thread\'s unwind path, so '
        'it cannot be constant-folded, and every other panic '
        'in the artifact retains its string and Location '
        '(1,209 std .rs Locations are recovered by the same '
        'scan that finds one for scoped.rs).'),
    'inlined_spawn': (
        'A hypothetical Scope::spawn monomorphisation with its '
        'own inlined increment is covered, not assumed away: '
        'its overflow path must either call the shared stub '
        '(census 3: no caller outside the 14 spawn bodies) or '
        'panic through its own reference to the scoped.rs '
        'Location (census 4: the stub\'s lea is the only code '
        'reference to 0x64c32f0 in the artifact).'),
    'cell_internals': (
        'The packet cells\' layouts, the spawn bodies\' ledger '
        'and the 16 null call sites are PR #3204\'s pins and '
        'are used here as premises, not re-derived; this packet '
        'pins only the instantiation question that packet left '
        'open.'),
    'source_names': (
        'Function and field names (thread::scope, ScopeData, '
        'decrement_num_running_threads) are the std source '
        'names for the mechanisms the artifact itself names '
        'through the scoped.rs path string and panic message; '
        'the binary carries no symbol for them.'),
}

LIMITS = (
    'Static trace only; no captured code was executed.  The '
    'censuses cover the artifact\'s file bytes, its .rela.dyn '
    'relocations and rip-relative / direct-branch references '
    'in .text; a reference encoded in some other form (for '
    'example a computed jump through a register loaded from a '
    'non-relocated constant) would have to materialise the '
    'target address as data somewhere, and census 3 covers '
    'that form for the stub.')


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


# ---------------------------------------------------------------- ELF

class Elf:
    def __init__(self, data):
        self.data = data
        d = data
        check(d[:4] == b'\x7fELF' and d[4] == 2, 'not an ELF64')
        phoff = struct.unpack_from('<Q', d, 0x20)[0]
        shoff = struct.unpack_from('<Q', d, 0x28)[0]
        phentsize, phnum = struct.unpack_from('<HH', d, 0x36)
        shentsize, shnum, shstrndx = struct.unpack_from(
            '<HHH', d, 0x3a)
        self.loads = []
        for i in range(phnum):
            p_type, _f, p_off, p_va, _pa, p_filesz, _ms, _al = \
                struct.unpack_from('<IIQQQQQQ', d,
                                   phoff + i * phentsize)
            if p_type == 1:
                self.loads.append((p_va, p_off, p_filesz))
        self.sections = {}
        sh = shoff + shstrndx * shentsize
        str_off = struct.unpack_from('<Q', d, sh + 0x18)[0]
        for i in range(shnum):
            sh = shoff + i * shentsize
            name_off, _t = struct.unpack_from('<II', d, sh)
            addr, off, size = struct.unpack_from('<QQQ', d,
                                                 sh + 0x10)
            end = d.index(b'\0', str_off + name_off)
            name = d[str_off + name_off:end].decode()
            self.sections[name] = (addr, off, size)

    def va2off(self, va):
        for p_va, p_off, p_filesz in self.loads:
            if p_va <= va < p_va + p_filesz:
                return p_off + (va - p_va)
        return None

    def off2va(self, off):
        for p_va, p_off, p_filesz in self.loads:
            if p_off <= off < p_off + p_filesz:
                return p_va + (off - p_off)
        return None

    def read(self, va, n):
        off = self.va2off(va)
        check(off is not None, f'unmapped va {va:#x}')
        return self.data[off:off + n]

    def u64(self, va):
        return struct.unpack('<Q', self.read(va, 8))[0]

    def u32(self, va):
        return struct.unpack('<I', self.read(va, 4))[0]

    def fdes(self):
        addr, off, size = self.sections['.eh_frame']
        d = self.data
        pos, end_all = off, off + size
        while pos < end_all:
            length = struct.unpack_from('<I', d, pos)[0]
            if length == 0:
                break
            if length == 0xffffffff:
                length = struct.unpack_from('<Q', d, pos + 4)[0]
                hdr = 16
            else:
                hdr = 4
            cie_ptr = struct.unpack_from('<i', d, pos + hdr)[0]
            entry_end = pos + hdr + length
            if cie_ptr != 0:
                field_va = addr + (pos + hdr + 4 - off)
                iloc_rel = struct.unpack_from(
                    '<i', d, pos + hdr + 4)[0]
                irange = struct.unpack_from(
                    '<I', d, pos + hdr + 8)[0]
                iloc = field_va + iloc_rel
                if iloc and irange:
                    yield (iloc, iloc + irange)
            pos = entry_end

    def relocations(self):
        """va -> (type, addend) for every .rela.dyn entry."""
        _addr, off, size = self.sections['.rela.dyn']
        out = {}
        for i in range(size // 24):
            r_off, r_info, r_add = struct.unpack_from(
                '<QQq', self.data, off + i * 24)
            out[r_off] = (r_info & 0xffffffff, r_add)
        return out


def find_all(data, pat):
    out, i = [], 0
    while True:
        j = data.find(pat, i)
        if j < 0:
            return out
        out.append(j)
        i = j + 1


# ------------------------------------------------------------ censuses

def owners(data, elf):
    fde = dict()
    for start, end in elf.fdes():
        fde[start] = end
    out = {}
    for role, (start, end) in OWNERS.items():
        check(fde.get(start) == end, f'{role}: FDE extent moved')
        off = elf.va2off(start)
        body = data[off:off + (end - start)]
        out[role] = {'start': hex(start), 'end': hex(end),
                     'offset': off, 'bytes': end - start,
                     'sha256': sha(body)}
    return out


def string_census(data, elf):
    exit_hits = [hex(elf.off2va(o)) for o in find_all(data,
                                                      EXIT_PANIC)]
    check(not exit_hits, 'scope-exit panic string present')
    scoped_hits = []
    for o in find_all(data, b'scoped'):
        s = o
        while s > 0 and 32 <= data[s - 1] < 127:
            s -= 1
        t = o
        while t < len(data) and 32 <= data[t] < 127:
            t += 1
        scoped_hits.append({'va': hex(elf.off2va(o)),
                            'containing': data[s:t].decode()})
    check(len(scoped_hits) == 1, 'unexpected "scoped" occurrences')
    check(scoped_hits[0]['containing'].encode().endswith(
        b'src/thread/scoped.rs'), 'the one "scoped" is not the path')
    msg_hits = find_all(data, OVERFLOW_MSG)
    check(len(msg_hits) == 1, 'overflow message not unique')
    msg_va = elf.off2va(msg_hits[0])
    return {
        'exit_panic_string': {'text': EXIT_PANIC.decode(),
                              'occurrences': exit_hits},
        'scoped_substring': {'occurrences': scoped_hits},
        'overflow_message': {'text': OVERFLOW_MSG.decode(),
                             'len': len(OVERFLOW_MSG),
                             'va': hex(msg_va)},
    }


def location_census(data, elf):
    path_offs = find_all(data, SCOPED_PATH)
    check(len(path_offs) == 1, 'scoped.rs path string not unique')
    path_va = elf.off2va(path_offs[0])
    relocs = elf.relocations()
    records = []
    std_rs_total = 0
    for va, (typ, add) in relocs.items():
        if typ != 8:
            continue
        if add == path_va:
            records.append({
                'record': hex(va), 'len': elf.u64(va + 8),
                'line': elf.u32(va + 16), 'col': elf.u32(va + 20)})
        off = elf.va2off(add)
        if off is not None:
            end = data.find(b'\x00', off)
            s = data[off:end] if end > 0 else b''
            if s.endswith(b'.rs') and b'/library/' in s:
                std_rs_total += 1
    check(len(records) == 1, 'scoped.rs Location count moved')
    rec = records[0]
    check(rec['record'] == hex(LOCATION) and rec['len'] == 80
          and rec['line'] == 60 and rec['col'] == 9,
          'the scoped.rs Location is not the pinned one')
    return {'file': SCOPED_PATH.decode(), 'file_va': hex(path_va),
            'relocations_scanned': len(relocs),
            'std_rs_locations_recovered': std_rs_total,
            'records': records}


def text_window(elf):
    _va, off, size = elf.sections['.text']
    return elf.sections['.text'][0], elf.data[off:off + size]


def direct_xrefs(elf, target):
    """All E8/E9 (call/jmp rel32) sites in .text naming target."""
    tva, text = text_window(elf)
    sites = []
    for op in (b'\xe8', b'\xe9'):
        for o in find_all(text, op):
            if o + 5 <= len(text):
                rel = struct.unpack_from('<i', text, o + 1)[0]
                if tva + o + 5 + rel == target:
                    sites.append(tva + o)
    return sorted(sites)


def fde_owner(fdes, starts, va):
    i = bisect_right(starts, va) - 1
    if i >= 0 and fdes[i][0] <= va < fdes[i][1]:
        return fdes[i]
    return None


def stub_xref_census(data, elf):
    fdes = sorted(elf.fdes())
    starts = [f[0] for f in fdes]
    sites = direct_xrefs(elf, STUB)
    site_records = []
    for s in sites:
        own = fde_owner(fdes, starts, s)
        check(own is not None, f'stub xref {s:#x} outside any FDE')
        site_records.append({'site': hex(s),
                             'owner': hex(own[0])})
    owner_set = sorted({r['owner'] for r in site_records})
    check(owner_set == [hex(s) for s in sorted(SPAWN_STARTS)],
          'stub callers are not exactly the 14 spawn bodies')
    check(len(site_records) == 14, 'stub xref count moved')
    return {'target': hex(STUB), 'count': len(site_records),
            'sites': site_records}


def rip_xrefs(elf, target):
    """REX-prefixed lea/mov rip-relative sites naming target."""
    tva, text = text_window(elf)
    sites = []
    for rex in (b'\x48', b'\x4c'):
        for o in find_all(text, rex):
            if o + 7 <= len(text) and text[o + 1] in (0x8d, 0x8b) \
                    and text[o + 2] & 0xc7 == 0x05:
                disp = struct.unpack_from('<i', text, o + 3)[0]
                if tva + o + 7 + disp == target:
                    sites.append(tva + o)
    return sorted(sites)


def reference_census(data, elf, msg_va):
    loc_refs = rip_xrefs(elf, LOCATION)
    msg_refs = rip_xrefs(elf, msg_va)
    check([hex(s) for s in loc_refs] == ['0x5c82d53'],
          'Location code references moved')
    check([hex(s) for s in msg_refs] == ['0x5c82d4c'],
          'message code references moved')
    dec_direct = direct_xrefs(elf, DECREMENT)
    check(not dec_direct, 'decrement gained a direct caller')
    relocs = elf.relocations()
    dec_slots = [hex(va) for va, (t, a) in relocs.items()
                 if t == 8 and a == DECREMENT]
    check(dec_slots == [hex(DECREMENT_SLOT)],
          'decrement relocation slots moved')
    # the stub's rollback call through that slot: ff 15 disp with
    # disp resolving to DECREMENT_SLOT from 0x5c82d46
    raw = elf.read(0x5c82d46, 6)
    check(raw[:2] == b'\xff\x15', 'rollback call bytes moved')
    disp = struct.unpack('<i', raw[2:])[0]
    check(0x5c82d46 + 6 + disp == DECREMENT_SLOT,
          'rollback call does not name the decrement slot')
    return {
        'location_code_refs': [hex(s) for s in loc_refs],
        'message_code_refs': [hex(s) for s in msg_refs],
        'decrement_direct_callers': [hex(s) for s in dec_direct],
        'decrement_relocation_slots': dec_slots,
        'decrement_slot_call_site': '0x5c82d46',
    }


def data_pointer_census(data, elf):
    relocs = elf.relocations()
    _a, roff, rsize = elf.sections['.rela.dyn']
    out = {}
    for name, target in (('stub', STUB), ('decrement', DECREMENT),
                         ('location', LOCATION)):
        addend_slots = [hex(va) for va, (t, a) in relocs.items()
                        if t == 8 and a == target]
        literals = []
        for o in find_all(data, struct.pack('<Q', target)):
            if not (roff <= o < roff + rsize):
                literals.append(hex(elf.off2va(o)))
        out[name] = {'target': hex(target),
                     'relocation_addend_slots': addend_slots,
                     'literal_occurrences_outside_rela_dyn':
                         literals}
    check(out['stub']['relocation_addend_slots'] == [],
          'stub gained a data entry')
    check(out['stub']['literal_occurrences_outside_rela_dyn']
          == [], 'stub address materialised as data')
    return out


def slots(data, elf):
    relocs = elf.relocations()
    out = {}
    for name, slot in (('scope_decrement', DECREMENT_SLOT),
                       ('panic_entry', PANIC_SLOT)):
        typ, add = relocs[slot]
        out[name] = {'slot': hex(slot), 'type': typ,
                     'target': hex(add)}
    check(out['scope_decrement']['target'] == hex(DECREMENT),
          'decrement slot target moved')
    check(out['panic_entry']['target'] == hex(PANIC_TARGET),
          'panic slot target moved')
    typ, add = relocs[FUTEX_SLOT]
    out['futex_syscall'] = {'slot': hex(FUTEX_SLOT), 'type': typ,
                            'target': None}
    return out


def check_pins(data, elf):
    out = {}
    for name, (va, want) in PINS.items():
        raw = elf.read(va, len(bytes.fromhex(want)))
        check(raw.hex() == want, f'pin {name} moved')
        out[name] = {'va': hex(va), 'bytes': want}
    return out


def analyze(data):
    check(len(data) == TARGET_SIZE and sha(data) == TARGET_SHA256,
          'artifact authentication failed')
    elf = Elf(data)
    strings = string_census(data, elf)
    msg_va = int(strings['overflow_message']['va'], 16)
    return {
        'artifact': {'path': 'artifacts/node/115/hl-node',
                     'bytes': TARGET_SIZE, 'sha256': TARGET_SHA256,
                     'snapshot': SNAPSHOT},
        'packet': WORK_ITEM,
        'captured_code_executed': False,
        'question': QUESTION,
        'answer': ANSWER,
        'owners': owners(data, elf),
        'pins': check_pins(data, elf),
        'slots': slots(data, elf),
        'string_census': strings,
        'location_census': location_census(data, elf),
        'stub_xref_census': stub_xref_census(data, elf),
        'reference_census': reference_census(data, elf, msg_va),
        'data_pointer_census': data_pointer_census(data, elf),
        'boundaries': BOUNDARIES,
        'limits': LIMITS,
    }


# -------------------------------------------------------------- output

def objdump_range(start, end):
    text = subprocess.run(
        ['objdump', '-d', '--start-address', hex(start),
         '--stop-address', hex(end), str(TARGET)],
        check=True, capture_output=True, text=True).stdout
    return text.replace(str(TARGET), SNAPSHOT, 1)


def exports(role):
    start, end = OWNERS[role]
    return objdump_range(start, end)


def frame_lines():
    text = subprocess.run(['readelf', '-wf', str(TARGET)],
                          check=True, capture_output=True,
                          text=True).stdout
    wanted = []
    for start, end in OWNERS.values():
        needle = f'pc={start:016x}..{end:016x}'
        wanted += [ln for ln in text.splitlines() if needle in ln]
    check(len(wanted) == len(OWNERS), 'owner frame lines missing')
    return [line + '\n' for line in wanted]


def manifest_lines():
    names = sorted(p.name for p in OUT.iterdir()
                   if p.is_file() and p.name != 'MANIFEST.sha256')
    lines = []
    for name in names:
        digest = sha((OUT / name).read_bytes())
        lines.append(f'{digest}  {name}\n')
    return lines


def generate(data):
    OUT.mkdir(parents=True, exist_ok=True)
    records = analyze(data)
    (OUT / 'records.json').write_text(
        json.dumps(records, indent=1, sort_keys=True) + '\n')
    (OUT / 'frames.txt').write_text(''.join(frame_lines()))
    for role in EXPORTED:
        (OUT / f'{role}.objdump.txt').write_text(exports(role))
    check((OUT / 'README.md').is_file(),
          'README.md must exist before MANIFEST generation')
    (OUT / 'MANIFEST.sha256').write_text(''.join(manifest_lines()))


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
        check((OUT / f'{role}.objdump.txt').read_text()
              == exports(role), f'{role}.objdump.txt is stale')
    check((OUT / 'frames.txt').read_text() == ''.join(frame_lines()),
          'frames.txt is stale')
    check((OUT / 'MANIFEST.sha256').read_text()
          == ''.join(manifest_lines()), 'MANIFEST.sha256 is stale')
    print(json.dumps({'packet': WORK_ITEM, 'matches': True},
                     sort_keys=True))


if __name__ == '__main__':
    main()
