"""Static pins for the node115 lu.rs LazyLock global question.

Question: PR #2969 (the builder caller wrapper identities packet)
pinned wrapper a (0x15d6fd0, base/src/lu.rs) and showed its kind-1
arm first consults a process-global once: state dword 0x64f01d8,
cell 0x64f01c0, entered through call_once_force (GOT slot
0x64df9f0 -> body 0x5c87d50) with a closure static at 0x63fe250 /
0x63fe278. It left open whether that once caches the runtime
wrapper a builds. This tool re-derives, from the materialized
artifact alone, what the global actually is and what is cached:

- the cell's first qword is filled at load time by the binary's
  only relocation touching the range: an R_X86_64_RELATIVE entry
  whose addend is the initializer function 0x1568de0, and the
  once state dword's file value is 3 (INCOMPLETE) -- the static
  shape of a std::sync::LazyLock;
- the closure vtable at 0x63fe250 names two shim bodies
  (0x1568980 call_once, 0x155fd80 call_mut) that take the fn
  pointer out of the cell, call it through a 24-byte sret buffer
  and write the 24-byte result back over the cell -- the value
  the once caches is the initializer's product, not a runtime;
- the initializer 0x1568de0 never calls the runtime builder
  (slot 0x64e1760), the builder 0x5cf9600 or the cfg ctor
  0x5cf93f0 (its own call census is pinned);
- wrapper a's only references to the pair are the state load and
  the slow-path lea pair: after the forced once call it jumps
  unconditionally back into its own build path (cfg ctor kind 1
  at 0x15d7007, builder slot call at 0x15d7026) and never reads
  a single byte of the cached value;
- the cached value's only direct reader is an accessor body
  (0x1560a40, reached through GOT slot 0x64e0b20) that returns
  the cell's +8/+0x10 qword pair;
- a whole-.text census over the 32-byte range closes every other
  path: 1713 validated RIP-relative references in 421 bodies,
  every one an ensure-init site carrying the identical feature
  set (state load, lea cell, lea once, lea vtable, lea location,
  call through the sys once slot), zero store-opcode references,
  and the value words (+8/+0x10) are loaded only inside the
  accessor.

Boundary: what the initializer's 24-byte product denotes at
source level (which LazyLock static of the base crate this is)
is not pinned -- no Location inside the initializer names a
source file for the static itself, and this packet does not
guess. Whether the dispatcher that reaches wrapper a ever
selects its kind-1 arm at run time was already left open by
PR #2969 and stays open here.
"""
import argparse
import hashlib
import json
import struct
import subprocess
import tempfile
from pathlib import Path

from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import decode_export

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
PACKET = (ROOT / 'research/work-items'
          '/RE-005-node115-lu-lazylock-value')

SHA = ('a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e'
       '98c3867b5301')
SIZE = 105896032

CELL = 0x64f01c0
CELL_HI = 0x64f01d8          # one past the 24-byte value cell
ONCE = 0x64f01d8             # state dword lives at cell + 0x18
RANGE_HI = 0x64f01e0
VTABLE = 0x63fe250
CALL_LOCATION = 0x63fe278
NULL_LOCATION = 0x63fe330
SYS_SLOT = 0x64df9f0
ACCESSOR_SLOT = 0x64e0b20
BUILDER_SLOT = 0x64e1760
SYS_ONCE = 0x5c87d50
INIT_FN = 0x1568de0
ACCESSOR = 0x1560a40
BUILDER = 0x5cf9600
CFG_CTOR = 0x5cf93f0

OWNERS = {
 'accessor': (0x1560a40, 0x1560aab,
              '4dd07ff0fab8b3133d896254e0fecef4f983867a311'
              '629f10ccedb52d03ac6bc'),
 'init_fn': (0x1568de0, 0x156971c,
             'c87c9590e5ab4cebd4a7110f74eda4a33237fac384'
             '3105dab89bc132924ac41c'),
 'null_panic': (0x1680c10, 0x1680c29,
                '6c62896561a5c8454ceb1945a882a798dcaefe52'
                'e78852cbbfee08835a16a81e'),
 'poison_helper': (0x5c9d1a0, 0x5c9d1bd,
                   '870d4fb390ff4ccfcdf457e342985dea3b38bf0'
                   'cc68022130bb7b75394ccf6ae'),
 'rep_site': (0x150bd10, 0x150bdca,
              '3be11f24a84521b905a8207b851cb689b06eb822a'
              'f8b83ebc161a6ab6142dbab'),
 'shim_mut': (0x155fd80, 0x155fdce,
              '3947f49378f8f922e075c0d0f310b2f850c354ec1'
              '3a35c90c4ffa192d51bab7b'),
 'shim_once': (0x1568980, 0x15689ce,
               '696fd8a51fa6ff68187603b5376673ad32f706961'
               '2fe47591f3218840cad0806'),
 'sys_once': (0x5c87d50, 0x5c87f6c,
              '677090dab02d8f4089593e314f7dfd16a4acf10c0'
              '866e469734fab4b365853bb'),
 'wrapper_a': (0x15d6fd0, 0x15d8447,
               '0a33a4e33944ad1377a8544831780bcc081401ce3f'
               '7d5e86c33606c88ff44d8c'),
}

# (va, expected bytes, meaning) -- every entry is re-checked
# against the artifact on each analyze() run.
PINS = [
 # wrapper_a kind-1 arm: state check, slow path, unconditional
 # fall back into the body's own build path.
 (0x15d6fec, '8b05e691f104', 'wrapper_a loads the once state dword'),
 (0x15d6ff2, '85c0', 'wrapper_a tests the state'),
 (0x15d6ff4, '0f85b6010000', 'wrapper_a jne to slow path 0x15d71b0'),
 (0x15d71b0, '488d050990f104', 'wrapper_a lea rax, cell'),
 (0x15d71cf, '488d3d0290f104', 'wrapper_a lea rdi, once state'),
 (0x15d71d6, '488d0d7370e204', 'wrapper_a lea rcx, closure vtable'),
 (0x15d71dd, '4c8d059470e204', 'wrapper_a lea r8, call location'),
 (0x15d71ec, 'be01000000', 'wrapper_a force flag esi = 1'),
 (0x15d71f1, 'ff15f987f004', 'wrapper_a calls the sys once slot'),
 (0x15d71f7, 'e9fefdffff', 'wrapper_a jumps back to 0x15d6ffa'),
 (0x15d7002, 'be01000000', 'wrapper_a cfg_ctor kind argument 1'),
 (0x15d7007, 'e8e4237204', 'wrapper_a direct call to cfg_ctor'),
 (0x15d7026, 'ff1534a7f004', 'wrapper_a calls the builder slot'),
 # accessor: state check, fast reads of the value words, slow
 # path through the same once, slow reads of the same words.
 (0x1560a40, '8b0592f7f804', 'accessor loads the once state dword'),
 (0x1560a46, '85c0', 'accessor tests the state'),
 (0x1560a48, '750f', 'accessor jne to slow path 0x1560a59'),
 (0x1560a4a, '488b0577f7f804', 'accessor fast load of cell +8'),
 (0x1560a51, '488b1578f7f804', 'accessor fast load of cell +0x10'),
 (0x1560a58, 'c3', 'accessor fast return'),
 (0x1560a5d, '488d055cf7f804', 'accessor lea rax, cell'),
 (0x1560a73, '488d3d5ef7f804', 'accessor lea rdi, once state'),
 (0x1560a7a, '488d0dcfd7e904', 'accessor lea rcx, closure vtable'),
 (0x1560a81, '4c8d05f0d7e904', 'accessor lea r8, call location'),
 (0x1560a8d, 'be01000000', 'accessor force flag esi = 1'),
 (0x1560a92, 'ff1558eff704', 'accessor calls the sys once slot'),
 (0x1560a9c, '488b0525f7f804', 'accessor slow load of cell +8'),
 (0x1560aa3, '488b1526f7f804', 'accessor slow load of cell +0x10'),
 (0x1560aaa, 'c3', 'accessor slow return'),
 # closure shims: take the fn pointer, null check, poisoned
 # check, call through a 24-byte sret buffer, write back 24
 # bytes over the cell.
 (0x155fd8b, '48c70000000000', 'shim_mut zeroes the caller slot (take)'),
 (0x155fd95, '7424', 'shim_mut je to the null path'),
 (0x155fd97, '807e0401', 'shim_mut tests the OnceState poisoned byte'),
 (0x155fd9b, '742b', 'shim_mut je to the poison helper call'),
 (0x155fda2, 'ff13', 'shim_mut calls the fn pointer from the cell'),
 (0x155fda9, '48894310', 'shim_mut writes back value word +0x10'),
 (0x155fdb2, '0f1103', 'shim_mut writes back value words +0/+8'),
 (0x155fdbb, '488d3d6ee5e904', 'shim_mut lea rdi, null location'),
 (0x155fdc2, 'ff1568faf704', 'shim_mut calls the null panic slot'),
 (0x155fdc8, 'ff150202f804', 'shim_mut calls the poison helper slot'),
 (0x156898b, '48c70000000000', 'shim_once zeroes the caller slot (take)'),
 (0x1568997, '807e0401', 'shim_once tests the OnceState poisoned byte'),
 (0x15689a2, 'ff13', 'shim_once calls the fn pointer from the cell'),
 (0x15689a9, '48894310', 'shim_once writes back value word +0x10'),
 (0x15689b2, '0f1103', 'shim_once writes back value words +0/+8'),
 (0x15689bb, '488d3d6e59e904', 'shim_once lea rdi, null location'),
 (0x15689c2, 'ff15686ef704', 'shim_once calls the null panic slot'),
 (0x15689c8, 'ff150276f704', 'shim_once calls the poison helper slot'),
 # sys once body: claim, closure call, state write-back, the
 # poisoned write on the panic path.
 (0x5c87d93, 'f00fb113', 'sys once lock cmpxchg claims the state'),
 (0x5c87d9f, '83e103', 'sys once masks the state low bits'),
 (0x5c87e28, '83f902', 'sys once compares the OnceState byte with 2'),
 (0x5c87e2e, 'c745c000000000', 'sys once default OnceState byte is 0'),
 (0x5c87e44, 'ff5020', 'sys once calls the closure through +0x20'),
 (0x5c87e4a, '8703', 'sys once xchg writes the new state back'),
 (0x5c87e64, 'ff154e888500', 'sys once calls the futex wake slot'),
 (0x5c87f3f, 'b802000000', 'sys once panic path loads state value 2'),
 (0x5c87f44, '8703', 'sys once xchg writes the poisoned state back'),
 # poison helper: message, location, argument, panic entry.
 (0x5c9d1a4, '488d3df3cacafa', 'poison helper lea rdi, message'),
 (0x5c9d1ab, '488d15a6688200', 'poison helper lea rdx, location'),
 (0x5c9d1b2, 'be5d000000', 'poison helper mov esi, 0x5d'),
 (0x5c9d1b7, 'ff15fb248400', 'poison helper calls the panic entry slot'),
 # representative inlined ensure site in another body: same
 # pattern, then the body's own continuation runs.
 (0x150bd3d, '8b059544fe04', 'rep site loads the once state dword'),
 (0x150bd45, '752d', 'rep site jne to slow path 0x150bd74'),
 (0x150bd4a, 'e841080000', 'rep site calls its continuation 0x150c590'),
 (0x150bd74, '488d054544fe04', 'rep site lea rax, cell'),
 (0x150bd8a, '488d3d4744fe04', 'rep site lea rdi, once state'),
 (0x150bd91, '488d0db824ef04', 'rep site lea rcx, closure vtable'),
 (0x150bd98, '4c8d05d924ef04', 'rep site lea r8, call location'),
 (0x150bda4, 'be01000000', 'rep site force flag esi = 1'),
 (0x150bda9, 'ff15413cfd04', 'rep site calls the sys once slot'),
 (0x150bdaf, 'eb96', 'rep site jumps back to 0x150bd47'),
]

# Instruction starts each retained objdump export must contain
# (the export decoder already proves byte-exact contiguity; this
# proves the pinned sites are real instruction starts).
PIN_STARTS = {
 'wrapper_a': [0x15d6fec, 0x15d6ff4, 0x15d71b0, 0x15d71f1,
               0x15d71f7, 0x15d7007, 0x15d7026],
 'accessor': [0x1560a40, 0x1560a4a, 0x1560a51, 0x1560a92,
              0x1560a9c, 0x1560aa3],
 'shim_mut': [0x155fd8b, 0x155fd97, 0x155fda2, 0x155fda9,
              0x155fdb2, 0x155fdc2, 0x155fdc8],
 'shim_once': [0x156898b, 0x1568997, 0x15689a2, 0x15689a9,
               0x15689b2, 0x15689c2, 0x15689c8],
 'sys_once': [0x5c87d93, 0x5c87e2e, 0x5c87e44, 0x5c87e4a,
              0x5c87f3f],
 'poison_helper': [0x5c9d1a4, 0x5c9d1b7],
 'rep_site': [0x150bd3d, 0x150bd4a, 0x150bd74, 0x150bda9,
              0x150bdaf],
 'init_fn': [0x1568de0],
 'null_panic': [0x1680c10],
}


def require(cond, msg):
    if not cond:
        raise ValueError(msg)


def read(data, va, size):
    for s in sections(data):
        if (s['type'] != 8 and s['address'] <= va
                and va + size <= s['address'] + s['size']):
            off = s['offset'] + va - s['address']
            return s['name'], data[off:off + size]
    raise ValueError(f'no section covers {va:#x}')


def word(data, va):
    return struct.unpack('<Q', read(data, va, 8)[1])[0]


def dynsym_name(data, index):
    sym = next(s for s in sections(data) if s['name'] == '.dynsym')
    strs = next(s for s in sections(data) if s['name'] == '.dynstr')
    noff = struct.unpack_from('<I', data, sym['offset'] + index * 24)[0]
    o = strs['offset'] + noff
    return data[o:data.index(b'\0', o)].decode()


def relocations(data):
    """offset -> (kind, target) for every .rela.dyn entry: RELATIVE
    entries resolve to their addend, GLOB_DAT / JUMP_SLOT entries
    to their dynamic symbol name."""
    sec = next(s for s in sections(data) if s['name'] == '.rela.dyn')
    out = {}
    for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
        r_off, r_info, r_add = struct.unpack_from('<QQq', data, off)
        rtype = r_info & 0xffffffff
        sym = r_info >> 32
        if rtype == 8:
            out[r_off] = ('RELATIVE', r_add)
        elif rtype in (6, 7) and sym:
            out[r_off] = ('GLOB_DAT' if rtype == 6 else 'JUMP_SLOT',
                          dynsym_name(data, sym))
        else:
            out[r_off] = (f'type{rtype}', r_add)
    return out


def decode_location(data, by_offset, va):
    """A core::panic::Location static: (file ptr, len, line,
    column) at +0/+8/+0x10/+0x14; the pointer word is carried by
    a RELATIVE relocation on this toolchain."""
    fptr = by_offset[va][1] if va in by_offset else word(data, va)
    flen = word(data, va + 8)
    line, col = struct.unpack('<II', read(data, va + 0x10, 8)[1])
    path = read(data, fptr, flen)[1].decode()
    return {'static': hex(va), 'file': path, 'line': line,
            'column': col}


def static_records(data, by_offset):
    """The cell/state statics: file-initial bytes and the one
    relocation that touches the range."""
    cell_bytes = read(data, CELL, 0x18)[1]
    state = struct.unpack('<I', read(data, ONCE, 4)[1])[0]
    tail = struct.unpack('<I', read(data, ONCE + 4, 4)[1])[0]
    require(cell_bytes == b'\0' * 0x18,
            'cell file bytes are not all zero')
    require(state == 3, 'once state file value is not INCOMPLETE(3)')
    require(tail == 0, 'dword after the once state is not zero')
    touching = {hex(k): (v[0], hex(v[1]) if isinstance(v[1], int)
                         else v[1])
                for k, v in by_offset.items()
                if CELL <= k < RANGE_HI}
    require(touching == {hex(CELL): ('RELATIVE', hex(INIT_FN))},
            'relocations touching the cell/state range changed')
    return {
     'cell': hex(CELL), 'cell_bytes': '0x18',
     'cell_file_value': 'all zero (the fn pointer slot is filled '
                        'by the deposit relocation at load)',
     'deposit_relocation': {'offset': hex(CELL),
                            'kind': 'RELATIVE',
                            'addend': hex(INIT_FN)},
     'once_state': hex(ONCE), 'once_state_file_value': state,
     'once_state_encoding': {'0': 'COMPLETED', '1': 'RUNNING',
                             '2': 'POISONED', '3': 'INCOMPLETE',
                             'bit 0x4': 'futex waiter flag'},
     'note': 'a 24-byte value cell immediately followed by its '
             'once state dword is the static shape of '
             'std::sync::LazyLock<T> with size_of::<T>() == 0x18; '
             'the LazyLock identity itself is proven by the '
             'poison helper message and its lazy_lock.rs '
             'Location below, not by the shape alone'}


def resolved_word(data, by_offset, va):
    """The value a pointer cell holds after load-time fixups:
    the RELATIVE addend when one targets the cell, else the raw
    stored word."""
    entry = by_offset.get(va)
    if entry is not None and entry[0] == 'RELATIVE':
        return entry[1]
    return word(data, va)


def slot_records(data, by_offset):
    want = {SYS_SLOT: SYS_ONCE, 0x64df830: 0x1680c10,
            0x64dffd0: 0x5c9d1a0, 0x64df6b8: 0x1680e80,
            ACCESSOR_SLOT: ACCESSOR}
    out = {}
    for slot, target in sorted(want.items()):
        kind, val = by_offset[slot]
        require(kind == 'RELATIVE' and val == target,
                f'slot {slot:#x} resolution changed')
        out[hex(slot)] = {'kind': kind, 'target': hex(val)}
    wake = by_offset[0x64e06b8]
    out[hex(0x64e06b8)] = {'kind': wake[0],
                           'target': (hex(wake[1])
                                      if isinstance(wake[1], int)
                                      else wake[1]),
                           'role': 'futex wake slot called by the '
                                   'sys once body'}
    vt = {'base': hex(VTABLE),
          'drop_in_place': hex(resolved_word(data, by_offset,
                                             VTABLE)),
          'size': word(data, VTABLE + 8),
          'align': word(data, VTABLE + 0x10),
          'call_once': hex(resolved_word(data, by_offset,
                                         VTABLE + 0x18)),
          'call_mut': hex(resolved_word(data, by_offset,
                                        VTABLE + 0x20))}
    require(vt['size'] == 8 and vt['align'] == 8,
            'closure vtable size/align changed')
    require(vt['call_once'] == hex(OWNERS['shim_once'][0])
            and vt['call_mut'] == hex(OWNERS['shim_mut'][0]),
            'closure vtable shim entries changed')
    out['closure_vtable'] = vt
    return out


def location_records(data, by_offset):
    call_loc = decode_location(data, by_offset, CALL_LOCATION)
    null_loc = decode_location(data, by_offset, NULL_LOCATION)
    poison_loc = decode_location(data, by_offset, 0x64c3a58)
    require(call_loc['file'].endswith('std/src/sync/once.rs')
            and call_loc['line'] == 219 and call_loc['column'] == 20,
            'call_once closure location changed')
    require(null_loc['file'].endswith('std/src/sync/once.rs')
            and null_loc['line'] == 219 and null_loc['column'] == 49,
            'null fn-pointer location changed')
    require(poison_loc['file'].endswith('std/src/sync/lazy_lock.rs')
            and poison_loc['line'] == 410
            and poison_loc['column'] == 5,
            'poison helper location changed')
    return {'call': call_loc, 'null_fn_pointer': null_loc,
            'poisoned': poison_loc}


def string_records(data):
    msg = read(data, 0x949c9e, 46)[1].decode()
    require(msg == 'LazyLock instance has previously been poisoned',
            'LazyLock poison message changed')
    msg2 = read(data, 0x949565, 42)[1].decode()
    require(msg2 == 'Once instance has previously been poisoned',
            'Once poison message changed')
    return {
     'lazylock_poisoned': {'address': hex(0x949c9e), 'text': msg},
     'once_poisoned': {'address': hex(0x949565), 'text': msg2,
                       'note': 'raised by the sys once body on '
                               'its non-force path; the LazyLock '
                               'message above is the one this '
                               'closure reaches, through the '
                               'poison helper'}}


def check_pins(data):
    out = []
    for va, hx, meaning in PINS:
        got = read(data, va, len(hx) // 2)[1].hex()
        require(got == hx, f'byte pin at {va:#x} changed')
        out.append({'va': hex(va), 'bytes': hx, 'meaning': meaning})
    return out


def init_fn_calls(data, by_offset):
    """Every direct (rel32) and slot-indirect call inside the
    initializer body, re-derived by instruction-accurate decode
    of the retained export in analyze order -- here done on the
    raw bytes with a linear sweep is NOT sound, so this uses the
    objdump decode via decode_export like the packet exports."""
    a, b, _ = OWNERS['init_fn']
    with tempfile.NamedTemporaryFile(suffix='-hl-node') as tf:
        tf.write(data)
        tf.flush()
        asm = subprocess.check_output(
         ['objdump', '-d', f'--start-address={a:#x}',
          f'--stop-address={b:#x}', tf.name], text=True)
    ins = decode_export(asm, a, b, read(data, a, b - a)[1])
    rel32 = []
    slots = []
    vas = sorted(ins)
    for va in vas:
        raw = ins[va]
        if raw[0] == 0xe8 and len(raw) == 5:
            rel32.append({'site': hex(va),
                          'target': hex(va + 5 + struct.unpack(
                           '<i', raw[1:5])[0])})
        elif raw[:2] == b'\xff\x15' and len(raw) == 6:
            slot = va + 6 + struct.unpack('<i', raw[2:6])[0]
            kind, val = by_offset.get(slot, (None, None))
            slots.append({'site': hex(va), 'slot': hex(slot),
                          'target': (hex(val) if isinstance(val, int)
                                     else val)})
    targets = {r['target'] for r in rel32}
    slot_targets = {s['target'] for s in slots}
    require(hex(BUILDER) not in targets
            and hex(CFG_CTOR) not in targets,
            'initializer calls the builder or cfg ctor directly')
    require(hex(BUILDER_SLOT) not in {s['slot'] for s in slots},
            'initializer calls through the builder slot')
    return {'rel32_calls': rel32, 'slot_calls': slots,
            'never_calls': [hex(BUILDER), hex(CFG_CTOR),
                            'builder slot ' + hex(BUILDER_SLOT)]}


def text_census(data):
    """Whole-.text census of every path that can reach the
    cell/state range, the closure statics, or the two bodies
    that must only be reached indirectly. A disp32 field start
    counts only when the two preceding bytes are a RIP-relative
    ModRM (mod=00, rm=101) -- the same validation as the
    reference census."""
    import bisect
    secs = sections(data)
    text = next(s for s in secs if s['name'] == '.text')
    tb = data[text['offset']:text['offset'] + text['size']]
    tbase = text['address']
    _, rows, _ = fde_extents(data)
    rows.sort(key=lambda r: r['start'])
    starts = [r['start'] for r in rows]

    def containing(va):
        i = bisect.bisect_right(starts, va) - 1
        if i >= 0 and rows[i]['start'] <= va < rows[i]['end']:
            return rows[i]['start']
        return None

    def sec_name(off):
        for s in secs:
            if s['type'] != 8 and s['offset'] <= off < s['offset'] + s['size']:
                return s['name']
        return None

    unpack = struct.unpack_from
    range_hits = []
    vt_hits = 0
    loc_hits = 0
    sys_slot_sites = []
    acc_slot_sites = []
    rel32 = {ACCESSOR: [], SYS_ONCE: [], INIT_FN: []}
    features = {}

    def feat(body, name):
        if body is not None:
            features.setdefault(body, set()).add(name)

    n = len(tb)
    for i in range(n - 6):
        b = tb[i]
        if b == 0xe8 or b == 0xe9:
            t = tbase + i + 5 + unpack('<i', tb, i + 1)[0]
            if t in rel32:
                rel32[t].append(tbase + i)
        elif b == 0xff and tb[i + 1] == 0x15:
            slot = tbase + i + 6 + unpack('<i', tb, i + 2)[0]
            if slot == SYS_SLOT:
                sys_slot_sites.append(tbase + i)
                feat(containing(tbase + i), 'call_sys_slot')
            elif slot == ACCESSOR_SLOT:
                acc_slot_sites.append(tbase + i)
        r = tbase + i + 4 + unpack('<i', tb, i)[0]
        if CELL <= r < RANGE_HI:
            if i >= 2 and (tb[i - 1] & 0xC7) == 0x05:
                op = tb[i - 2]
                range_hits.append((tbase + i, r, op))
                body = containing(tbase + i)
                if r == CELL and op == 0x8d:
                    feat(body, 'lea_cell')
                elif r == ONCE and op == 0x8b:
                    feat(body, 'load_state')
                elif r == ONCE and op == 0x8d:
                    feat(body, 'lea_once')
        elif r == VTABLE or r == CALL_LOCATION:
            if (i >= 2 and (tb[i - 1] & 0xC7) == 0x05
                    and tb[i - 2] == 0x8d):
                if r == VTABLE:
                    vt_hits += 1
                    feat(containing(tbase + i), 'lea_vtable')
                else:
                    loc_hits += 1
                    feat(containing(tbase + i), 'lea_loc')

    by_target_op = {}
    value_load_bodies = set()
    wrapper_hits = []
    for fva, target, op in range_hits:
        key = (hex(target), hex(op))
        by_target_op[key] = by_target_op.get(key, 0) + 1
        if target in (CELL + 8, CELL + 0x10):
            value_load_bodies.add(containing(fva))
        if containing(fva) == OWNERS['wrapper_a'][0]:
            wrapper_hits.append({'field': hex(fva),
                                 'target': hex(target),
                                 'opcode': hex(op)})
    require({(k[0], k[1]): v for k, v in by_target_op.items()} == {
     (hex(CELL), '0x8d'): 569, (hex(ONCE), '0x8b'): 572,
     (hex(ONCE), '0x8d'): 568, (hex(CELL + 8), '0x8b'): 2,
     (hex(CELL + 0x10), '0x8b'): 2},
     'cell/state range census changed')
    require(len(range_hits) == 1713, 'range census total changed')
    require(value_load_bodies == {ACCESSOR},
            'the cached value words are loaded outside the accessor')
    bodies = {b for b, s in features.items() if 'lea_cell' in s}
    require(len(bodies) == 421, 'ensure-site body count changed')
    full = {'lea_cell', 'lea_once', 'load_state', 'lea_vtable',
            'lea_loc', 'call_sys_slot'}
    require(all(features[b] == full for b in bodies),
            'an ensure site lacks part of the identical feature set')
    hist = {}
    for s in features.values():
        key = ','.join(sorted(s))
        hist[key] = hist.get(key, 0) + 1
    require(len(sys_slot_sites) == 1553,
            'sys once slot call census changed')
    require(rel32[ACCESSOR] == [] and rel32[SYS_ONCE] == [],
            'the accessor or sys once body gained a direct caller')
    require(all(containing(s) != OWNERS['wrapper_a'][0]
                for s in acc_slot_sites),
            'wrapper_a calls the accessor')
    wa_slot = [s for s in sys_slot_sites
               if containing(s) == OWNERS['wrapper_a'][0]]
    require(wa_slot == [0x15d71f1],
            'wrapper_a sys once slot call sites changed')

    imm64 = {}
    for target in (CELL, ONCE):
        pat = struct.pack('<Q', target)
        hits = []
        pos = 0
        while True:
            j = data.find(pat, pos)
            if j < 0:
                break
            hits.append({'file_offset': hex(j),
                         'section': sec_name(j)})
            pos = j + 1
        imm64[hex(target)] = hits
    require(len(imm64[hex(CELL)]) == 1
            and imm64[hex(CELL)][0]['section'] == '.rela.dyn',
            'cell imm64 census changed')
    return {
     'range': {'lo': hex(CELL), 'hi': hex(RANGE_HI),
               'validated_references': len(range_hits),
               'by_target_opcode': {f'{t}/{o}': c for (t, o), c
                                    in sorted(by_target_op.items())},
               'store_opcodes': 0,
               'distinct_bodies': len({containing(f)
                                       for f, _, _ in range_hits}),
               'value_load_bodies': [hex(b) for b in
                                     sorted(value_load_bodies)]},
     'ensure_sites': {'bodies_with_lea_cell': len(bodies),
                      'feature_set': sorted(full),
                      'bodies_missing_a_feature': 0},
     'body_feature_histogram': hist,
     'closure_statics': {'vtable_lea_references': vt_hits,
                         'location_lea_references': loc_hits,
                         'note': 'both exceed the 421 ensure '
                                 'bodies of this pair: the '
                                 'monomorphized closure is shared '
                                 'with other statics, whose cells '
                                 'are outside this packet'},
     'sys_once_slot_call_sites': len(sys_slot_sites),
     'accessor_slot_call_sites': {
      'count': len(acc_slot_sites),
      'bodies': sorted({hex(containing(s)) for s in acc_slot_sites
                        if containing(s) is not None})},
     'rel32_direct_references': {
      'accessor': [hex(s) for s in rel32[ACCESSOR]],
      'sys_once': [hex(s) for s in rel32[SYS_ONCE]],
      'init_fn': [hex(s) for s in rel32[INIT_FN]]},
     'imm64_references': imm64,
     'wrapper_a_range_references': wrapper_hits}


def analyze(data):
    if len(data) != SIZE or hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('pinned node115 distribution changed')
    by_offset = relocations(data)
    owners = []
    _, rows, _ = fde_extents(data)
    by_start = {r['start']: r for r in rows}
    for role, (a, b, want) in sorted(OWNERS.items()):
        row = by_start.get(a)
        require(row is not None and row['end'] == b,
                f'{role} FDE extent changed')
        digest = hashlib.sha256(read(data, a, b - a)[1]).hexdigest()
        require(digest == want, f'{role} body digest changed')
        owners.append({'role': role, 'start': hex(a), 'end': hex(b),
                       'bytes': b - a, 'sha256': digest})
    pins = check_pins(data)
    statics = static_records(data, by_offset)
    slots = slot_records(data, by_offset)
    locations = location_records(data, by_offset)
    strings = string_records(data)
    init_calls = init_fn_calls(data, by_offset)
    census = text_census(data)
    return {
     'artifact': 'artifacts/node/115/hl-node',
     'artifact_sha256': SHA,
     'artifact_size': SIZE,
     'question': 'PR #2969 pinned wrapper a (0x15d6fd0, '
                 'base/src/lu.rs): its kind-1 arm consults a '
                 'process-global once (state dword 0x64f01d8, '
                 'cell 0x64f01c0) through call_once_force before '
                 'building its runtime. Does that once cache the '
                 'built runtime, and if not, what does it guard?',
     'answer': {
      'caches_the_wrapper_a_runtime': False,
      'the_global': 'std::sync::LazyLock<T>, size_of::<T>() == '
                    '0x18: a 24-byte value cell at 0x64f01c0 '
                    'followed by its once state dword at '
                    '0x64f01d8 (file value 3, INCOMPLETE)',
      'what_is_cached': 'the return value of the initializer '
                        'function 0x1568de0, deposited into the '
                        'cell fn-pointer slot by an '
                        'R_X86_64_RELATIVE relocation and written '
                        'over the cell (24 bytes) by the closure '
                        'shims on the first completed call',
      'what_the_once_guards': 'exactly-once production of that '
                              '24-byte value; after completion '
                              'the state dword is 0 (COMPLETED) '
                              'and the forced calls wrapper a '
                              'makes are no-ops',
      'wrapper_a_use': 'wrapper a never reads the cached value: '
                       'its only references to the pair are the '
                       'state load at 0x15d6fec and the slow-path '
                       'lea pair; after the forced call it jumps '
                       'unconditionally to its own build path '
                       '(cfg_ctor kind 1, builder slot) and '
                       'builds a fresh runtime on every call',
      'value_consumer': 'an accessor body at 0x1560a40, reached '
                        'through GOT slot 0x64e0b20, returns the '
                        'cached value words at cell +8 and '
                        'cell +0x10 (rax:rdx); the +0 word is '
                        'the initializer fn pointer itself until '
                        'it is overwritten by the product',
      'initializer_is_not_the_builder': 'the initializer '
                        '0x1568de0 (2364 bytes) never calls the '
                        'runtime builder 0x5cf9600, the cfg ctor '
                        '0x5cf93f0 or the builder slot '
                        '0x64e1760; its full call census is '
                        'retained under init_fn_calls'},
     'owners': owners,
     'byte_pins': pins,
     'statics': statics,
     'slots': slots,
     'locations': locations,
     'strings': strings,
     'init_fn_calls': init_calls,
     'census': census,
     'boundaries': [
      'the source-level identity of the LazyLock static (which '
      'static of the base crate, and what its 24-byte value '
      'denotes) is not pinned: no Location inside the '
      'initializer names the static, and this packet does not '
      'guess from nearby string literals',
      'whether the dispatcher that reaches wrapper a ever '
      'selects the kind-1 arm at run time stays open, as left '
      'by PR #2969; every statement here is about the linked '
      'code paths, not about observed execution',
      'the 41 further bodies that reference the same closure '
      'vtable/location statics with other cells are other '
      'statics sharing the monomorphized closure; their cells '
      'are outside this packet'],
     'limits': 'Static analysis of the pinned distribution '
               'only; no captured code was executed. The '
               'register-indirect write set is closed by the '
               'census argument in the README: the cell address '
               'is materialized in .text only by the 569 lea '
               'sites, all inside the 421 ensure-init bodies '
               'carrying the identical feature set, and the sys '
               'once body writes only the state dword through '
               'its rdi argument.',
     'captured_code_executed': False}


def exports(data):
    out = {}
    with tempfile.TemporaryDirectory() as td:
        snapshot = Path(td) / 'hl-node'
        snapshot.write_bytes(data)
        for role, (a, b, _) in sorted(OWNERS.items()):
            asm = subprocess.check_output(
             ['objdump', '-d', f'--start-address={a:#x}',
              f'--stop-address={b:#x}', str(snapshot)], text=True)
            ins = decode_export(asm, a, b, read(data, a, b - a)[1])
            for va in PIN_STARTS.get(role, []):
                require(va in ins,
                        f'{role} instruction start missing')
            out[role] = asm.replace(str(snapshot),
                                    '<authenticated-node115>')
    return out


def generate(binary, output):
    data = binary.read_bytes()
    if len(data) != SIZE or hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('pinned node115 distribution changed')
    payload = analyze(data)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        snapshot = Path(td) / 'hl-node'
        snapshot.write_bytes(data)
        native = subprocess.check_output(
         ['readelf', '-wf', str(snapshot)], text=True)
        wanted = []
        for a, b, _ in OWNERS.values():
            needle = f'pc={a:016x}..{b:016x}'
            wanted += [ln for ln in native.splitlines()
                       if needle in ln]
        require(len(wanted) == len(OWNERS),
                'owner frame lines missing')
        (output / 'frames.txt').write_text('\n'.join(wanted) + '\n')
        exps = exports(data)
        for role, asm in exps.items():
            (output / f'{role}.objdump.txt').write_bytes(
             asm.encode('utf-8'))
    (output / 'records.json').write_text(
     json.dumps(payload, indent=1, sort_keys=True) + '\n')
    return payload


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('output', nargs='?', default=str(PACKET))
    args = parser.parse_args()
    payload = generate(TARGET, Path(args.output))
    for owner in payload['owners']:
        print(owner['role'], owner['start'], owner['end'],
              owner['bytes'], owner['sha256'])


if __name__ == '__main__':
    main()
