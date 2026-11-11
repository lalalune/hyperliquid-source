"""RE-005 node 115: what the park slow-path refresh caches.

Re-derives, from the authenticated hl-node 115 artifact
only: the identity of the global object the park /
park_timeout slow-path refresh body 0x5cee650 caches at
0x64fee08 (key word 0x64fee10, lock byte 0x64fee00). The
packet pins the refresh body and its three call sites,
the registry lookup 0x5cde710 it is the sole caller of,
the entry-object getter 0x5cfcf90, the cached object's
0x150-byte Arc layout and its two reference counts, the
orphan reap pass 0x5cee900 the refresh drives when the
object's event counter at [obj+0x138] moves, and the
pair+0x38 driver-liveness cell the lookup dereferences.
Any drift in a body hash, census, slot resolution,
Location, byte pin or message fails verification rather
than silently rewriting the packet.
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
WORK_ITEM = 'RE-005-node115-timeout-cache-object'
OUT = ROOT / 'research' / 'work-items' / WORK_ITEM

BODIES = {
    'refresh': 0x5cee650,
    'lookup': 0x5cde710,
    'getobj': 0x5cfcf90,
    'notify': 0x5cee900,
    'convert': 0x5c902e0,
    'once_entry': 0x5cdf535,
    'once_globals': 0x5cdf582,
    'drop_err': 0x5cee460,
    'release_weak': 0x5ce8860,
    'runclosure': 0x5ce57c0,
    'draincb': 0x5cfcc50,
    'pair_ctor': 0x5ce01f0,
}

GLOBALS = {
    'lock_refresh': 0x64fee00,
    'cache_obj': 0x64fee08,
    'cache_key': 0x64fee10,
    'globals_base': 0x64fee20,
    'reg_base': 0x64fee28,
    'reg_count': 0x64fee30,
    'globals_state': 0x64fee38,
    'lock_orphan': 0x64fede0,
    'queue_base': 0x64fedf0,
    'queue_len': 0x64fedf8,
}

SLOTS = {
    0x64e01e8: ('relative', '0x5ce57c0'),
    0x64ecc58: ('relative', '0x5ce8860'),
    0x64df4a0: ('relative', '0x635de30'),
    0x64ec898: ('relative', '0x5c902e0'),
    0x64ecba8: ('relative', '0x5cfcc50'),
    0x64df9f0: ('relative', '0x5c87d50'),
    0x64dfe78: ('glob_dat', 'close'),
    0x64ec8a0: ('glob_dat', 'waitpid'),
}

MESSAGES = {
    0x44ce8e: 'Refusing to register signal ',
    0x94d26c: 'signal driver gone',
    0x452ef0: 'signal too large',
    0x94c765: 'registering signal handler failed',
}

LOCATIONS = {
    0x64c6e80: ('/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/'
                'src/signal/registry.rs', 73, 32),
    0x64c6ff0: ('/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/'
                'src/signal/unix.rs', 28, 20),
    0x64c6498: ('/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/'
                'src/process/unix/orphan.rs', 118, 20),
}

PINS = {
    0x5cee6f1: 'be11000000',        # refresh: mov esi, 0x11 (17)
    0x5cee6f6: '4889da',            # refresh: mov rdx, rbx (arg fwd)
    0x5cde72a: 'b8100b0800',        # lookup: mov eax, 0x80b10
    0x5cfcfbb: '488b9038010000',    # getobj: mov rdx, [rax+0x138]
    0x5cfcfc2: 'f048ff8040010000',  # getobj: lock inc [rax+0x140]
    0x5ce8870: 'be50010000',        # release_weak: mov esi, 0x150
    0x5cee922: '488d0cc0',          # notify: lea rcx, [rax+rax*8] (x28)
}

FINDINGS = [
    'The cached object at 0x64fee08 is an Arc clone of the '
    'vendored tokio signal registry entry for signal 17 '
    '(SIGCHLD): the refresh body 0x5cee650 is the sole '
    'direct caller of the registry lookup 0x5cde710, and '
    'it passes the immediate 17 as the lookup second '
    'argument (pin 0x5cee6f1). The lookup validates the '
    'value as a signal number (refusal mask 0x80b10 = '
    'signals 4, 8, 9, 11, 19; messages "Refusing to '
    'register signal ", "signal driver gone", "signal '
    'too large", "registering signal handler failed") '
    'and clones entry 16\'s object through the getter '
    '0x5cfcf90, whose panic Location is z_vendor/tokio/'
    'src/signal/registry.rs:73:32.',
    'Correction to the timeout-pair-writers packet '
    '(PR #2944): its "0x5cde710 keyed by 17 bytes at the '
    'argument" reads the constant 17 as a byte count. '
    'The 17 is the SIGCHLD signal number; the pointer '
    'argument is the address of the pair+0x38 slot '
    '(the selectors pass pair+0x38 itself: sel_timeout '
    'computes r14+0x38 from the pair base, the park '
    'forwarder computes X+0x30 from X = pair+8; the '
    'refresh forwards the pointer unchanged, pin '
    '0x5cee6f6), which the lookup dereferences twice as a '
    'driver-liveness cell: value -1 or a zero first word '
    'at the pointee yields "signal driver gone". The '
    'pair constructor 0x5ce01f0 writes the slot once, '
    'from the first qword of its config (builder '
    '0x5cf9600 passes its own config field at +0x60).',
    'Cached object layout (allocation size 0x150 = 336, '
    'from the dealloc size in the weak-release body '
    '0x5ce8860): +0x00 Arc strong count (incremented by '
    'the getter 0x5cfcf90, decremented last on release), '
    '+0x08 Arc weak count (decremented by 0x5ce8860, '
    'which frees 0x150 bytes at zero), +0x110 a tagged '
    'function word with a spin byte at +0x118 (an '
    'embedded deferred-drop sub-object, run by '
    '0x5ce57c0 when the second count reaches zero), '
    '+0x130 the lock word the SIGCHLD drain 0x5ce7380 '
    'CASes 0 -> 8, +0x138 the event counter the drain '
    'advances by 2 per delivery (bit 0 is a separate '
    'flag; the getter returns [obj+0x138] & ~1 as the '
    'snapshot word), +0x140 a second reference count '
    '(incremented by the getter, decremented first on '
    'release; at zero the 0x5ce57c0 closure runs).',
    'Refresh contract: the refresh lock byte 0x64fee00 '
    'is claimed by cmpxchg; contention returns at once. '
    'Cache hit with [obj+0x138] & ~1 equal to the '
    'cached key 0x64fee10 returns without further work. '
    'A moved counter updates the key, takes the orphan '
    'lock byte 0x64fede0 and runs the reap pass '
    '0x5cee900. An empty cache resolves the SIGCHLD '
    'object through the lookup only when the orphan '
    'queue is non-empty; a failed lookup drops the '
    'error value through 0x5cee460, leaves the cache '
    'empty and returns without panicking.',
    'The reap pass 0x5cee900 (panic Location '
    'z_vendor/tokio/src/process/unix/orphan.rs:118:20) '
    'walks the global orphan queue (base 0x64fedf0, '
    'length 0x64fedf8, record stride 0x1c) from the '
    'last record down: the helper 0x5c902e0 tries to '
    'reap the record pid through waitpid@GLIBC (slot '
    '0x64ec8a0, WNOHANG) and builds an ExitStatus-shaped '
    'result; a finished record is swap-removed, its '
    'four i32 words at +0xc..+0x18 are closed through '
    'close@GLIBC (slot 0x64dfe78) when not -1, and its '
    'attached value is dropped through 0x5cee460.',
    'Census: the refresh body has exactly three direct '
    'call sites in .text (sel_timeout 0x5ce0160 tail '
    'jump, sel_park 0x5ce0850 tail jump, park forwarder '
    '0x5cfdd00 call); the lookup has exactly one (the '
    'refresh); the getter has exactly one (the lookup); '
    'the reap pass has exactly two (both in the '
    'refresh). The cache globals 0x64fee00/0x64fee08/'
    '0x64fee10 are referenced only inside the refresh '
    'body. No stored pointer and no .rela.dyn addend '
    'anywhere in the file names the cache globals, the '
    'lookup, the refresh, the getter or the reap pass. '
    'The static block 0x64fede0..0x64fee38 lies in '
    '.data: the lock bytes, cache object/key words, '
    'registry vector pointer/count and queue length '
    'all start at 0; the queue base word at 0x64fedf0 '
    'starts at 4 (its unpopulated marker; it is only '
    'dereferenced once the length is non-zero), the '
    'registry once-state word at 0x64fee38 starts at 3 '
    '(the not-yet-run value the once helpers test), '
    'and the neighbouring id counter at 0x64fee18 '
    'starts at 1.',
]

OPEN_EDGES = [
    'The orphan queue records (stride 0x1c) have no '
    'static pusher: no .text site outside the reap '
    'pass references the queue base/length words, so '
    'records reach the queue through a path that does '
    'not address these globals directly (for example '
    'through a heap-held queue handle). Who enqueues a '
    'record, and the exact source-level name of the '
    'four closed i32 words at +0xc..+0x18, stay open.',
    'The cached object fields +0x10..+0x108 are not '
    'individually identified here; only +0x110 onward '
    'is pinned by the getter and release paths.',
    'The pair+0x38 pointee (the driver-liveness cell) '
    'is identified mechanically: the constructor '
    'stores the builder config +0x60 qword there. '
    'Which source-level driver object that qword '
    'names is not settled by this packet.',
]


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
        raw.append((name, typ, flags, addr, offset, size))
    strbase = raw[e_shstrndx][4]
    out = {}
    for name, typ, flags, addr, offset, size in raw:
        end = data.index(b'\x00', strbase + name)
        sname = data[strbase + name:end].decode()
        out[sname] = {'type': typ, 'addr': addr,
                      'offset': offset, 'size': size}
    return out


def va_slice(data, secs, va, size):
    for sec in secs.values():
        if sec['type'] == 8:  # NOBITS has no file bytes
            continue
        if sec['addr'] <= va < sec['addr'] + sec['size']:
            off = sec['offset'] + (va - sec['addr'])
            return data[off:off + size]
    raise AssertionError(f'va {va:#x} not in a file-backed section')


def fde_table():
    text = subprocess.run(
        ['readelf', '--debug-dump=frames', str(TARGET)],
        capture_output=True, text=True, check=True).stdout
    table = []
    for line in text.splitlines():
        m = re.search(r'pc=([0-9a-f]+)\.\.([0-9a-f]+)', line)
        if m:
            table.append((int(m.group(1), 16), int(m.group(2), 16)))
    table.sort()
    return table


def fde_of(table, va):
    for start, end in table:
        if start <= va < end:
            return start, end
    return None


def rel32_census(data, secs, targets):
    text_sec = secs['.text']
    base = text_sec['addr']
    blob = data[text_sec['offset']:text_sec['offset'] + text_sec['size']]
    found = {t: [] for t in targets}
    for i in range(len(blob) - 5):
        op = blob[i]
        if op in (0xe8, 0xe9):
            rel = struct.unpack_from('<i', blob, i + 1)[0]
            tgt = base + i + 5 + rel
            if tgt in found:
                found[tgt].append((base + i, 'call' if op == 0xe8
                                   else 'jmp'))
    return found


def rip_census(data, secs, table, globals_map):
    text_sec = secs['.text']
    base = text_sec['addr']
    blob = data[text_sec['offset']:text_sec['offset'] + text_sec['size']]
    found = {name: [] for name in globals_map}
    wanted = {g: name for name, g in globals_map.items()}
    for i in range(len(blob) - 4):
        disp = struct.unpack_from('<i', blob, i)[0]
        tgt = base + i + 4 + disp
        if tgt in wanted:
            found[wanted[tgt]].append(base + i + 4)
    out = {}
    for name, ends in found.items():
        rows = []
        for end in sorted(set(ends)):
            fde = fde_of(table, end - 1)
            rows.append({'disp_end': hex(end),
                         'in_body': hex(fde[0]) if fde else None})
        out[name] = rows
    return out


def rela_map():
    text = subprocess.run(['readelf', '-rW', str(TARGET)],
                          capture_output=True, text=True,
                          check=True).stdout
    out = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[2].startswith('R_X86_64'):
            try:
                off = int(parts[0], 16)
            except ValueError:
                continue
            kind = parts[2]
            if kind == 'R_X86_64_RELATIVE':
                out[off] = ('relative', parts[-1].lower())
            elif kind == 'R_X86_64_GLOB_DAT' and len(parts) >= 5:
                out[off] = ('glob_dat',
                            parts[4].split('@')[0].lower())
    return out


def analyze(data):
    check(len(data) == TARGET_SIZE, 'artifact size drift')
    check(sha(data) == TARGET_SHA256, 'artifact sha256 drift')
    secs = sections(data)
    table = fde_table()

    pinned = {}
    for role, va in BODIES.items():
        fde = fde_of(table, va)
        check(fde is not None and fde[0] == va,
              f'{role}: {va:#x} is not an FDE start')
        raw = va_slice(data, secs, va, fde[1] - va)
        pinned[role] = {'va': hex(va), 'size': fde[1] - va,
                        'sha256': sha(raw)}

    calls = rel32_census(data, secs, [BODIES['refresh'],
                                      BODIES['lookup'],
                                      BODIES['getobj'],
                                      BODIES['notify']])
    call_records = {}
    names = {BODIES['refresh']: 'refresh', BODIES['lookup']: 'lookup',
             BODIES['getobj']: 'getobj', BODIES['notify']: 'notify'}
    for tgt, sites in calls.items():
        rows = []
        for site, kind in sorted(sites):
            fde = fde_of(table, site)
            rows.append({'site': hex(site), 'kind': kind,
                         'in_body': hex(fde[0]) if fde else None})
        call_records[names[tgt]] = rows

    rip = rip_census(data, secs, table, GLOBALS)

    stored = {}
    needles = list(GLOBALS.values()) + [BODIES['lookup'],
                                        BODIES['refresh'],
                                        BODIES['getobj'],
                                        BODIES['notify']]
    for va in needles:
        pat = struct.pack('<Q', va)
        hits = []
        pos = 0
        while True:
            pos = data.find(pat, pos)
            if pos < 0:
                break
            hits.append(pos)
            pos += 1
        stored[hex(va)] = hits
        check(not hits, f'stored pointer to {va:#x} appeared')

    rela = rela_map()
    slot_records = {}
    for slot, want in SLOTS.items():
        got = rela.get(slot)
        check(got is not None, f'slot {slot:#x} missing')
        if want[0] == 'relative':
            check(got[0] == 'relative' and
                  int(got[1], 16) == int(want[1], 16),
                  f'slot {slot:#x}: {got} != {want}')
        else:
            check(got == want, f'slot {slot:#x}: {got} != {want}')
        slot_records[hex(slot)] = {'kind': got[0], 'value': got[1]}
    addend_hits = sorted(
        hex(off) for off, (kind, val) in rela.items()
        if kind == 'relative' and int(val, 16) in needles)
    check(not addend_hits, f'rela addend names a needle: {addend_hits}')

    messages = {}
    for va, want in MESSAGES.items():
        raw = va_slice(data, secs, va, len(want))
        check(raw.decode() == want, f'message drift at {va:#x}')
        messages[hex(va)] = want

    locations = {}
    for struct_va, (path, line, col) in LOCATIONS.items():
        ptr_off = None
        for off, (kind, val) in rela.items():
            if off == struct_va and kind == 'relative':
                ptr_off = int(val, 16)
        check(ptr_off is not None,
              f'no rela file pointer for Location {struct_va:#x}')
        raw = va_slice(data, secs, ptr_off, len(path))
        check(raw.decode() == path,
              f'Location file drift at {struct_va:#x}')
        meta = va_slice(data, secs, struct_va + 8, 16)
        length, ln = struct.unpack_from('<QI', meta, 0)
        cl = struct.unpack_from('<I', meta, 12)[0]
        check(length == len(path) and ln == line and cl == col,
              f'Location meta drift at {struct_va:#x}')
        locations[hex(struct_va)] = {'path': path, 'line': line,
                                     'col': col}

    pins = {}
    for va, want_hex in PINS.items():
        raw = va_slice(data, secs, va, len(want_hex) // 2)
        check(raw.hex() == want_hex, f'pin drift at {va:#x}')
        pins[hex(va)] = want_hex

    data_sec = secs['.data']
    block_lo = GLOBALS['lock_orphan']
    block_hi = GLOBALS['globals_state'] + 8
    check(data_sec['addr'] <= block_lo and
          block_hi <= data_sec['addr'] + data_sec['size'],
          'globals block outside .data')
    initial = {}
    for va in range(block_lo, block_hi, 8):
        raw = va_slice(data, secs, va, 8)
        initial[hex(va)] = struct.unpack_from('<Q', raw, 0)[0]
    expected_initial = {
        '0x64fede0': 0, '0x64fede8': 0, '0x64fedf0': 4,
        '0x64fedf8': 0, '0x64fee00': 0, '0x64fee08': 0,
        '0x64fee10': 0, '0x64fee18': 1, '0x64fee20': 0,
        '0x64fee28': 0, '0x64fee30': 0, '0x64fee38': 3,
    }
    check(initial == expected_initial,
          f'globals initial values drift: {initial}')

    return {
        'work_item': WORK_ITEM,
        'artifact': {'size': TARGET_SIZE, 'sha256': TARGET_SHA256,
                     'snapshot': SNAPSHOT},
        'pinned_bodies': pinned,
        'call_census': call_records,
        'rip_refs': rip,
        'stored_ptr_refs': stored,
        'slots': slot_records,
        'messages': messages,
        'locations': locations,
        'pins': pins,
        'globals_initial': initial,
        'findings': FINDINGS,
        'open_edges': OPEN_EDGES,
    }


def exports(role):
    va = BODIES[role]
    table = fde_table()
    fde = fde_of(table, va)
    out = subprocess.run(
        ['objdump', '-d', f'--start-address={va:#x}',
         f'--stop-address={fde[1]:#x}', str(TARGET)],
        capture_output=True, text=True, check=True).stdout
    lines = out.splitlines()
    lines[0] = f'{SNAPSHOT}:     file format elf64-x86-64'
    return '\n'.join(lines) + '\n'


def frame_lines():
    text = subprocess.run(
        ['readelf', '--debug-dump=frames', str(TARGET)],
        capture_output=True, text=True, check=True).stdout
    keep = []
    wanted = {hex(va)[2:].zfill(16) for va in BODIES.values()}
    for line in text.splitlines():
        m = re.search(r'pc=([0-9a-f]+)\.\.', line)
        if m and m.group(1) in wanted:
            keep.append(line + '\n')
    return keep


def generate(records):
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / 'records.json').write_text(
        json.dumps(records, indent=1, sort_keys=True) + '\n')
    for role in BODIES:
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
