"""Static evidence for the RE-005 signal-fd producer packet.

Answers open edge 4 of the RE-005 tag-3 supply packet
(PR #2950) for the authenticated hl-node 115 artifact
only: the signal-attach body 0x5ce71f0 lazily
initialises a global signal state (flag word at
0x64fee38, fd word at 0x64fee24) -- which body
creates the fd posted at 0x64fee24, and from what?

SETTLED.  The global is a 32-byte static at
0x64fee20: a 24-byte value followed by a std Once
state word at +0x18 (born 3, driven to 0 by
std::sync::Once::call_once_force 0x5c87d50).  The
value is produced exactly once by the get_or_init
closure at 0x5cfcec0 -- reached only through the
two call shims of the Once vtable at 0x64c5760
(+0x18 -> 0x5cdf6c0, +0x20 -> 0x5cdf4f0), which the
lazy accessor 0x5cdf582 invokes via the GOT slot
0x64df9f0 (RELATIVE -> 0x5c87d50).  The closure's
own unwrap panic Location names its source:
/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/
signal/unix.rs line 71 col 53 -- this is vendored
tokio's global signal state.

The fd is one end of a Unix socketpair.  The
closure's first call is the socketpair wrapper
0x475b160 (its only call site in the artifact):
it ORs the caller's type word with 0x80800
(SOCK_NONBLOCK | SOCK_CLOEXEC) and calls libc
socketpair (GOT 0x64eb078) with domain AF_UNIX,
returning {disc, sv[0] at +4, sv[1] at +8}.  The
closure then calls __libc_current_sigrtmax
(GOT 0x64ecba0) and the table builder 0x5ce1320,
which builds (via 0x5cfe910) a table of that many
32-byte entries, and assembles the 24-byte value:
+0x00 = sv[1], +0x04 = sv[0] (the fd word),
+0x08 = entries pointer, +0x10 = entries count.
The vtable shim stores the value into the static
with two stores; no .text body ever stores to the
value fields directly.

CONSUMERS (whole-.text RIP-relative census,
disp-final and disp+imm encodings; zero imm64
occurrences of any field address in the file):
the fd word at +0x04 has exactly one reader in
the artifact -- signal_attach's mov edi,
[0x64fee24] at 0x5ce7211, which dups it with
fcntl(F_DUPFD_CLOEXEC) and registers the dup on
the poll's epoll with data 1 (the #2950 attach
path).  The entries pointer (+0x08) and count
(+0x10) are read by the entry-lookup body
0x5cde710 and the table-drain body 0x5ce7380
(which drains the dup fd the driver struct holds
at +0x28 and walks the entries); the Once state
(+0x18) is tested by those two bodies and by
signal_attach.  The +0x00 word (sv[1]) is never
loaded by any .text body: every base reference
is a lea feeding the accessor, the Arc-clone
helper 0x5cfcf90, or field loads of +8/+0x10/
+0x18 -- who writes to sv[1] at run time is an
open edge of this packet, as are the source
identities of the two table consumers.
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
TARGET_SIZE = 105896032
TARGET_SHA256 = ('a6e2897cd051213d004802deca416e8eca62b7a8278'
                 'fa39f249e98c3867b5301')
WORK_ITEM = 'RE-005-node115-signal-fd-producer'
OUT = ROOT / 'research' / 'work-items' / WORK_ITEM

GLOBAL_BASE = 0x64fee20
FIELD_VAS = (0x64fee20, 0x64fee24, 0x64fee28, 0x64fee2c,
             0x64fee30, 0x64fee34, 0x64fee38)

OWNERS = {
    'socketpair_wrap': (0x475b160, 0x475b20f),
    'init_closure': (0x5cfcec0, 0x5cfcf88),
    'vtable_call_shim': (0x5cdf4f0, 0x5cdf535),
    'lazy_accessor': (0x5cdf582, 0x5cdf5c7),
    'call_once_force': (0x5c87d50, 0x5c87f6c),
    'signal_attach': (0x5ce71f0, 0x5ce7374),
}
PINNED_BODIES = {
    'vtable_second_shim': (0x5cdf6c0, 0x5cdf705),
    'table_builder': (0x5ce1320, 0x5ce13ab),
    'table_alloc': (0x5cfe910, 0x5cfeb3e),
    'entry_lookup': (0x5cde710, 0x5cde8b0),
    'entry_arc_clone': (0x5cfcf90, 0x5cfd00f),
    'table_drain': (0x5ce7380, 0x5ce75a6),
}

GOT_SLOTS = (0x64eb078, 0x64e8a18, 0x64e12c0, 0x64dfe78,
             0x64dffc8, 0x64ecba0, 0x64df9f0)

INSTRUCTION_PINS = (
    (0x475b166, '81 ce 00 08 08 00',
     'socketpair_wrap: caller type word OR 0x80800 '
     '(SOCK_NONBLOCK|SOCK_CLOEXEC)'),
    (0x475b17c, 'bf 01 00 00 00',
     'socketpair_wrap: domain = AF_UNIX (1)'),
    (0x475b183, 'ff 15 ef fe d8 01',
     'socketpair_wrap: call libc socketpair via GOT 0x64eb078'),
    (0x475b19e, '89 6b 04',
     'socketpair_wrap: store sv[0] to result +0x04'),
    (0x475b1a1, '89 43 08',
     'socketpair_wrap: store sv[1] to result +0x08'),
    (0x5cfced2, 'e8 89 e2 a5 fe',
     'init_closure: call socketpair_wrap (only call site)'),
    (0x5cfcee8, 'ff 15 b2 fc 7e 00',
     'init_closure: call __libc_current_sigrtmax via '
     'GOT 0x64ecba0'),
    (0x5cfcef1, 'e8 2a 44 fe ff',
     'init_closure: call table_builder with SIGRTMAX'),
    (0x5cfcefd, '66 0f d6 03',
     'init_closure: store value qword0 (sv[1] low, sv[0] high)'),
    (0x5cfcf01, '48 89 43 08',
     'init_closure: store entries pointer at value +0x08'),
    (0x5cfcf05, '48 89 53 10',
     'init_closure: store entries count at value +0x10'),
    (0x5cdf50c, 'e8 af d9 01 00',
     'vtable_call_shim: call init_closure'),
    (0x5cdf516, '48 89 43 10',
     'vtable_call_shim: store third qword at value +0x10'),
    (0x5cdf51f, '0f 11 03',
     'vtable_call_shim: store first 16 bytes at value +0x00'),
    (0x5cdf582, '8b 47 18',
     'lazy_accessor: load Once state word at [rdi+0x18]'),
    (0x5cdf5bc, 'ff 15 2e 04 80 00',
     'lazy_accessor: call call_once_force via GOT 0x64df9f0'),
    (0x5c87e44, 'ff 50 20',
     'call_once_force: invoke closure through vtable +0x20'),
    (0x5ce7203, '8b 05 2f 7c 81 00',
     'signal_attach: test Once state word [0x64fee38]'),
    (0x5ce7211, '8b 3d 0d 7c 81 00',
     'signal_attach: load fd word [0x64fee24] (only reader)'),
    (0x5ce7223, 'ff 15 ef 17 80 00',
     'signal_attach: call fcntl via GOT 0x64e8a18 '
     '(F_DUPFD_CLOEXEC)'),
    (0x5ce7251, 'ff 15 69 a0 7f 00',
     'signal_attach: call epoll_ctl via GOT 0x64e12c0 '
     '(data 1)'),
    (0x5cde7bc, '48 3b 05 6d 06 82 00',
     'entry_lookup: bounds-check against entries count '
     '[0x64fee30]'),
    (0x5cde7c5, '48 8b 0d 5c 06 82 00',
     'entry_lookup: load entries pointer [0x64fee28]'),
    (0x5ce744a, '48 8b 1d df 79 81 00',
     'table_drain: load entries count [0x64fee30]'),
    (0x5ce745a, '4c 8b 35 c7 79 81 00',
     'table_drain: load entries pointer [0x64fee28]'),
)


# ---------- ELF plumbing ----------

def _segments(data):
    e_phoff = struct.unpack_from('<Q', data, 0x20)[0]
    e_phentsize = struct.unpack_from('<H', data, 0x36)[0]
    e_phnum = struct.unpack_from('<H', data, 0x38)[0]
    segs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, _fl, p_offset, p_vaddr, _pa, p_filesz, _ms = \
            struct.unpack_from('<IIQQQQQ', data, off)
        if p_type == 1:
            segs.append((p_vaddr, p_offset, p_filesz))
    return segs


def va2off(data, va):
    for vaddr, offset, filesz in _segments(data):
        if vaddr <= va < vaddr + filesz:
            return offset + (va - vaddr)
    raise ValueError(hex(va))


def read(data, va, size):
    off = va2off(data, va)
    return data[off:off + size]


def _sections(data):
    e_shoff = struct.unpack_from('<Q', data, 0x28)[0]
    e_shentsize = struct.unpack_from('<H', data, 0x3a)[0]
    e_shnum = struct.unpack_from('<H', data, 0x3c)[0]
    e_shstrndx = struct.unpack_from('<H', data, 0x3e)[0]
    raw = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        raw.append(struct.unpack_from('<IIQQQQIIQQ', data, off))
    str_off = raw[e_shstrndx][4]
    out = {}
    for s in raw:
        end = data.index(b'\0', str_off + s[0])
        name = data[str_off + s[0]:end].decode()
        out[name] = s
    return out


def _rela_map(data):
    secs = _sections(data)
    relas = {}
    s = secs['.rela.dyn']
    for i in range(s[5] // s[9]):
        r_off, r_info, r_add = struct.unpack_from(
            '<QQq', data, s[4] + i * s[9])
        relas[r_off] = (r_info >> 32, r_info & 0xffffffff, r_add)
    return relas, secs


def _sym_name(data, secs, idx):
    dynsym = secs['.dynsym']
    dynstr = secs['.dynstr']
    off = dynsym[4] + idx * dynsym[9]
    name_off = struct.unpack_from('<I', data, off)[0]
    end = data.index(b'\0', dynstr[4] + name_off)
    return data[dynstr[4] + name_off:end].decode()


def resolve_pointer(data, relas, va):
    """Effective value of an 8-byte slot after relocation."""
    r = relas.get(va)
    if r is not None and r[1] == 8:
        return r[2]
    off = va2off(data, va)
    return struct.unpack_from('<Q', data, off)[0]


def resolve_got(data, relas, secs, va):
    r = relas.get(va)
    if r is None:
        return {'kind': 'none'}
    symidx, typ, add = r
    if typ == 8:
        return {'kind': 'relative', 'target': hex(add)}
    if symidx:
        return {'kind': 'dynsym', 'symbol': _sym_name(data, secs, symidx)}
    return {'kind': 'type%d' % typ, 'addend': hex(add)}


_FDE_CACHE = None


def fde_extents():
    global _FDE_CACHE
    if _FDE_CACHE is not None:
        return _FDE_CACHE
    text = subprocess.run(
        ['readelf', '-wf', str(TARGET)],
        check=True, capture_output=True, text=True).stdout
    extents = {}
    for m in re.finditer(
            r'pc=0*([0-9a-f]+)\.\.0*([0-9a-f]+)', text):
        extents[int(m.group(1), 16)] = int(m.group(2), 16)
    _FDE_CACHE = extents
    return extents


def body_record(data, extents, start, end):
    if extents.get(start) != end:
        raise ValueError('FDE extent drift at %#x' % start)
    blob = read(data, start, end - start)
    return {'start': hex(start), 'end': hex(end),
            'bytes': end - start,
            'sha256': hashlib.sha256(blob).hexdigest()}


# ---------- censuses ----------

RIP_MODRM = frozenset(
    (0x05, 0x0d, 0x15, 0x1d, 0x25, 0x2d, 0x35, 0x3d))


def rip_census(data):
    """Every RIP-relative disp32 in .text naming a field.

    A RIP-relative ModRM byte (mod=00, rm=101) always
    sits immediately before its disp32, so scanning
    for those eight byte values is complete for the
    disp-final form; the imm-trailing form (reference
    point shifted by a 1- or 4-byte immediate) is
    checked alongside and reported separately.
    """
    secs = _sections(data)
    tsec = secs['.text']
    tva, toff, tsize = tsec[3], tsec[4], tsec[5]
    text = data[toff:toff + tsize]
    final = {hex(t): [] for t in FIELD_VAS}
    trailing = {hex(t): [] for t in FIELD_VAS}
    targets = set(FIELD_VAS)
    for modrm in RIP_MODRM:
        pos = 0
        while True:
            i = text.find(bytes((modrm,)), pos)
            if i < 0:
                break
            pos = i + 1
            disp_pos = i + 1
            if disp_pos + 4 > tsize:
                continue
            disp = struct.unpack_from('<i', text, disp_pos)[0]
            ref = tva + disp_pos + 4
            if ref + disp in targets:
                final[hex(ref + disp)].append(hex(tva + disp_pos))
            # Imm-trailing form: count it only when the opcode
            # before the ModRM (skipping one REX prefix) is an
            # imm-bearing opcode; otherwise a disp-final hit on
            # target T would alias as a trailing hit on T+4.
            op = i - 1
            if op >= 0 and 0x40 <= text[op] <= 0x4f:
                op -= 1
            imm = None
            if op >= 0:
                if text[op] in (0xc6, 0x83):
                    imm = 1
                elif text[op] in (0xc7, 0x81, 0x69):
                    imm = 4
            if imm is not None and ref + imm + disp in targets:
                trailing[hex(ref + imm + disp)].append(
                    hex(tva + disp_pos))
    return {'disp_final': {k: sorted(v) for k, v in final.items()},
            'disp_imm_trailing': {k: sorted(v)
                                  for k, v in trailing.items()}}


def e8_census(data, target):
    secs = _sections(data)
    tsec = secs['.text']
    tva, toff, tsize = tsec[3], tsec[4], tsec[5]
    text = data[toff:toff + tsize]
    hits = []
    pos = 0
    while True:
        i = text.find(b'\xe8', pos)
        if i < 0 or i + 5 > tsize:
            break
        pos = i + 1
        disp = struct.unpack_from('<i', text, i + 1)[0]
        if tva + i + 5 + disp == target:
            hits.append(hex(tva + i))
    return hits


def imm64_census(data, va):
    pat = struct.pack('<Q', va)
    count = 0
    pos = 0
    while True:
        i = data.find(pat, pos)
        if i < 0:
            return count
        count += 1
        pos = i + 1


# ---------- analysis ----------

def _location(data, relas, static_va):
    file_ptr = resolve_pointer(data, relas, static_va)
    file_len = struct.unpack_from(
        '<Q', read(data, static_va + 8, 8), 0)[0]
    packed = struct.unpack_from(
        '<Q', read(data, static_va + 0x10, 8), 0)[0]
    raw = read(data, file_ptr, file_len)
    return {'static': hex(static_va), 'file_ptr': hex(file_ptr),
            'file': raw.decode(), 'file_len': file_len,
            'line': packed & 0xffffffff,
            'col': (packed >> 32) & 0xffffffff}


def analyze(data):
    if len(data) != TARGET_SIZE:
        raise ValueError('artifact size drift')
    if hashlib.sha256(data).hexdigest() != TARGET_SHA256:
        raise ValueError('artifact hash drift')
    relas, secs = _rela_map(data)
    extents = fde_extents()
    owners = {name: body_record(data, extents, s, e)
              for name, (s, e) in OWNERS.items()}
    pinned = {name: body_record(data, extents, s, e)
              for name, (s, e) in PINNED_BODIES.items()}
    words = [hex(w) for w in struct.unpack_from(
        '<8I', read(data, GLOBAL_BASE, 32), 0)]
    got = {hex(va): resolve_got(data, relas, secs, va)
           for va in GOT_SLOTS}
    vtable = {
        'base': '0x64c5760',
        'plus_0x18': hex(resolve_pointer(data, relas, 0x64c5778)),
        'plus_0x20': hex(resolve_pointer(data, relas, 0x64c5780)),
    }
    locations = {
        'once_panic_location': _location(data, relas, 0x64c5788),
        'init_unwrap_location': _location(data, relas, 0x64c5700),
    }
    censuses = {
        'rip': rip_census(data),
        'e8_calls': {
            '0x5cdf582': e8_census(data, 0x5cdf582),
            '0x5cfcec0': e8_census(data, 0x5cfcec0),
            '0x475b160': e8_census(data, 0x475b160),
            '0x5c87d50': e8_census(data, 0x5c87d50),
        },
        'imm64': {hex(t): imm64_census(data, t)
                  for t in (0x64fee20, 0x64fee24, 0x64fee38)},
    }
    pins = []
    for va, want, role in INSTRUCTION_PINS:
        got_bytes = read(data, va, len(bytes.fromhex(want)))
        if got_bytes != bytes.fromhex(want):
            raise ValueError('instruction pin drift at %#x' % va)
        pins.append({'va': hex(va), 'bytes': want, 'role': role})
    return {'artifact': {'snapshot': 'node/115',
                         'size': TARGET_SIZE,
                         'sha256': TARGET_SHA256},
            'work_item': WORK_ITEM,
            'owners': owners,
            'pinned_bodies': pinned,
            'global_state': {'base': hex(GLOBAL_BASE),
                             'initial_u32': words},
            'got_resolutions': got,
            'vtable': vtable,
            'locations': locations,
            'censuses': censuses,
            'instruction_pins': pins}


def frame_lines(spans):
    text = subprocess.run(
        ['readelf', '-wf', str(TARGET)],
        check=True, capture_output=True, text=True).stdout
    keep = []
    for line in text.splitlines():
        m = re.search(r'pc=0*([0-9a-f]+)\.\.', line)
        if m and int(m.group(1), 16) in spans:
            keep.append(line)
    return keep


def generate():
    OUT.mkdir(parents=True, exist_ok=True)
    data = TARGET.read_bytes()
    records = analyze(data)
    (OUT / 'records.json').write_text(
        json.dumps(records, indent=2) + '\n')
    spans = {s for s, _e in list(OWNERS.values())
             + list(PINNED_BODIES.values())}
    (OUT / 'frames.txt').write_text(
        '\n'.join(frame_lines(spans)) + '\n')
    return records


def main():
    if '--generate' in sys.argv:
        generate()
        print('generated', OUT)
        return
    data = TARGET.read_bytes()
    records = analyze(data)
    on_disk = json.loads((OUT / 'records.json').read_text())
    print(json.dumps({'matches': records == on_disk},
                     indent=2))


if __name__ == '__main__':
    main()
