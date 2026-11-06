"""Static evidence tool for the RE-005 node-115 signal wake-vtable
call_mut packet.

Question (the undecided edge left by RE-005-node115-signal-sv1-writer,
PR #2974): the signal-delivery handler os_handler 0x5c67560 dispatches
the registered per-signal action through slot +0x28 of the wake
vtable 0x64c54b8 only. Both the +0x20 slot (the FnMut::call_mut
position) and the +0x28 slot (the Fn::call position) hold the same
body, wake_call 0x5cdcda0. Is there any reachable path in the
artifact that dispatches the action through the +0x20 slot?

Answer (re-derived here from the artifact bytes alone): no.

  * The vtable address is materialised by exactly five instructions
    in the whole .text, all `lea` inside registry_insert 0x5cdd480;
    the address occurs nowhere as a qword in the file image and in
    no relocation addend. The value is only ever stored into the
    trait-object fat pointers registry_insert builds.
  * The registry global (struct at 0x64fff58..0x64fffb0) is
    referenced, by genuine decoded RIP-relative references, from
    exactly three bodies: os_handler, the registry constructor
    0x5c67aa0 and entry_init 0x5cdbf20. Two further bodies reference
    only the neighbouring word 0x64fff50 below the struct and
    contain no indirect call at all. Every other raw disp-window
    candidate in the binary is a byte-pattern phantom (no genuine
    reference on decode); they are enumerated in records.json.
  * The complete indirect-call inventory of the eighteen cluster
    bodies contains exactly one vtable-slot dispatch: os_handler's
    `call *0x28(%rax)` at 0x5c67834. There is no disp-0x18 and no
    disp-0x20 call/jmp in any cluster body; the seven
    register-indirect sites are classified non-vtable calls
    (previous-handler raw pointers x4, sched_yield, memmove, and a
    boxed-error drop slot).
  * Inside os_handler's action loop the register holding the
    element's vtable word is dereferenced exactly twice: +0x10
    (the align field, a data read for the environment-pointer
    arithmetic) and +0x28 (the call). No +0x20 read exists.

Boundary (unchanged from #2974): the vtable +0x00 drop slot has
file value 0 and no relocation; its run-time value is not
statically claimable and this packet does not touch it.
"""
import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

import numpy as np

WAKE_VTABLE = 0x64c54b8
WAKE_CALL = 0x5cdcda0
WAKE_CALL_ONCE = 0x5cdd040

REGISTRY_BASE = 0x64fff58          # registry global struct base
REGISTRY_END = 0x64fffb0           # one past the +0x50 field word
NEIGHBOUR_WORD = 0x64fff50         # distinct pointer cell below it
SCAN_LO = NEIGHBOUR_WORD           # candidate scan covers both
SCAN_HI = 0x64fffb8

BODY_ANCHORS = {
    'os_handler': 0x5c67560,
    'registry_ctor': 0x5c67aa0,
    'ctor_caller_shim': 0x5c67ceb,
    'ctor_helper_a': 0x5c67d00,
    'ctor_helper_b': 0x5c67df0,
    'entry_init': 0x5cdbf20,
    'registry_insert': 0x5cdd480,
    'entry_lookup': 0x5cde710,
    'raw_table_insert': 0x5cde8b0,
    'io_error_ctor': 0x5cdd280,
    'entry_once_shim_a': 0x5cdf460,
    'entry_once_shim_b': 0x5cdf630,
    'oncelock_shim': 0x5cdf535,
    'generic_send_helper': 0x5cdfc90,
    'wake_call': WAKE_CALL,
    'wake_call_once': WAKE_CALL_ONCE,
    'neighbour_getter': 0x5c4e240,
    'neighbour_user': 0x14353b0,
}

BYTE_PINS = {
    # os_handler action loop: element vtable load, align read, dispatch
    'handler_vtable_load': (0x5c67813, 8),    # mov 0xb8(%rdx,%rax),%rax
    'handler_align_read': (0x5c6781b, 4),     # mov 0x10(%rax),%rdx
    'handler_action_call': (0x5c67834, 3),    # call *0x28(%rax)
    # os_handler previous-handler calls (raw fn pointers, not vtable)
    'prev_handler_load_a': (0x5c67790, 4),    # mov 0x8(%rax),%rcx
    'prev_handler_call_a': (0x5c677ab, 2),    # call *%rcx
    'prev_handler_call_b': (0x5c677c9, 2),    # call *%rax
    'prev_handler_call_c': (0x5c677d0, 2),    # call *%rax
    'prev_handler_call_d': (0x5c67a00, 2),    # call *%rcx
    # entry_init spin-wait: sched_yield through its GOT slot
    'sched_yield_load': (0x5cdc4ad, 7),       # mov 0x64e1558(%rip),%r14
    'sched_yield_call': (0x5cdc510, 3),       # call *%r14
    # registry_insert: memmove through its GOT slot
    'memmove_load': (0x5cdde3b, 7),            # mov 0x64df568(%rip),%rax
    'memmove_call': (0x5cdde42, 2),            # call *%rax
    # io_error_ctor: drop slot of an unrelated boxed-error object
    'error_vtable_load': (0x5cdd2b5, 4),      # mov (%r12),%rax
    'error_drop_call': (0x5cdd2c1, 2),        # call *%rax
    # raw_table_insert: the table's own hasher fn field at +0x30
    'rawtab_fn_load': (0x5cde900, 4),         # mov 0x10(%rdi),%rax
    'rawtab_fn_call': (0x5cde904, 3),         # call *0x30(%rax)
}

GOT_SLOTS = {
    'sched_yield_slot': 0x64e1558,
    'memmove_slot': 0x64df568,
}


class Elf:
    def __init__(self, data):
        self.data = data
        phoff = struct.unpack_from('<Q', data, 0x20)[0]
        phentsize, phnum = struct.unpack_from('<HH', data, 0x36)
        self.segs = []
        for i in range(phnum):
            t, _fl, off, va, _pa, fsz, _msz, _al = struct.unpack_from(
                '<IIQQQQQQ', data, phoff + i * phentsize)
            if t == 1:
                self.segs.append((va, off, fsz))
        shoff = struct.unpack_from('<Q', data, 0x28)[0]
        shentsize, shnum, shstrndx = struct.unpack_from('<HHH', data, 0x3a)
        secs = []
        for i in range(shnum):
            secs.append(struct.unpack_from('<IIQQQQIIQQ', data,
                                           shoff + i * shentsize))
        shstr = secs[shstrndx]
        self.sections = {}
        for nm, _ty, _fl, addr, off, sz, *_rest in secs:
            end = data.index(b'\0', shstr[4] + nm)
            self.sections[data[shstr[4] + nm:end].decode()] = (addr, off, sz)
        self.rela = {}
        for name in ('.rela.dyn', '.rela.plt'):
            if name not in self.sections:
                continue
            _va, off, sz = self.sections[name]
            for j in range(sz // 24):
                r_off, r_info, r_add = struct.unpack_from(
                    '<QQq', data, off + j * 24)
                self.rela[r_off] = (r_info & 0xffffffff, r_add, r_info >> 32)
        self.fdes = self._load_fdes()

    def va2off(self, va):
        for sva, soff, sfz in self.segs:
            if sva <= va < sva + sfz:
                return soff + (va - sva)
        return None

    def read(self, va, n):
        o = self.va2off(va)
        return self.data[o:o + n]

    def u64(self, va):
        return struct.unpack('<Q', self.read(va, 8))[0]

    def _load_fdes(self):
        hva, hoff, hsz = self.sections['.eh_frame_hdr']
        hdr = self.data[hoff:hoff + hsz]
        assert hdr[0] == 1 and hdr[1] == 0x1b and hdr[2] == 0x03 \
            and hdr[3] == 0x3b
        i = 4
        i += 4  # eh_frame_ptr
        count = struct.unpack_from('<I', hdr, i)[0]
        i += 4
        fdes = []
        for _k in range(count):
            init_loc = hva + struct.unpack_from('<i', hdr, i)[0]
            i += 4
            fde_rel = struct.unpack_from('<i', hdr, i)[0]
            i += 4
            fo = self.va2off(hva + fde_rel)
            addr_range = struct.unpack_from('<I', self.data, fo + 12)[0]
            fdes.append((init_loc, init_loc + addr_range))
        fdes.sort()
        return fdes

    def body_of(self, va):
        import bisect
        starts = [s for s, _e in self.fdes]
        idx = bisect.bisect_right(starts, va) - 1
        if idx < 0:
            return None
        s, e = self.fdes[idx]
        if s <= va < e:
            return (s, e)
        return None

    def dynsym_name(self, idx):
        _va, off, _sz = self.sections['.dynsym']
        _va2, off2, _sz2 = self.sections['.dynstr']
        st_name = struct.unpack_from('<I', self.data, off + idx * 24)[0]
        end = self.data.index(b'\0', off2 + st_name)
        return self.data[off2 + st_name:end].decode()

    def text(self):
        va, off, sz = self.sections['.text']
        return va, self.data[off:off + sz]


def _lea_vtable_sites(elf):
    """Every REX.W lea with a RIP-relative target == WAKE_VTABLE.

    Exact encoding match: (48|4c) 8d /r with mod=0, rm=5. Any such
    byte pattern anywhere in .text is reported, aligned or not."""
    tva, text = elf.text()
    b = np.frombuffer(text, dtype=np.uint8).astype(np.int64)
    n = len(b)
    rex = (b[:-6] == 0x48) | (b[:-6] == 0x4c)
    lea = b[1:n - 5] == 0x8d
    modrm = b[2:n - 4]
    riprel = (modrm & 0xC7) == 0x05
    disp = (b[3:n - 3] | (b[4:n - 2] << 8) | (b[5:n - 1] << 16)
            | (b[6:n] << 24))
    disp = np.where(disp >= 0x80000000, disp - 0x100000000, disp)
    pos = tva + np.arange(n - 6, dtype=np.int64)
    tgt = pos + 7 + disp
    hits = np.nonzero(rex & lea & riprel & (tgt == WAKE_VTABLE))[0]
    return sorted(hex(tva + int(i)) for i in hits)


def _raw_candidate_bodies(elf):
    """Bodies containing at least one raw disp32 window whose
    RIP-relative target (with 0, 4 or 8 trailing bytes) lands in
    [SCAN_LO, SCAN_HI). Candidates only: most are byte-pattern
    phantoms; the genuine set is decided by decode (objdump)."""
    tva, text = elf.text()
    b = np.frombuffer(text, dtype=np.uint8).astype(np.int32)
    disp = (b[:-3] | (b[1:-2] << 8) | (b[2:-1] << 16)
            | (b[3:].astype(np.int64) << 24))
    disp = np.where(disp >= 0x80000000, disp - 0x100000000, disp)
    pos = tva + np.arange(len(disp), dtype=np.int64)
    bodies = set()
    for imm in (0, 4, 8):
        tgt = pos + 4 + imm + disp
        for i in np.nonzero((tgt >= SCAN_LO) & (tgt < SCAN_HI))[0]:
            bd = elf.body_of(tva + int(i))
            bodies.add(bd[0] if bd else None)
    return bodies


def _raw_ff_census(elf):
    """Raw byte-pattern census of FF /2 (call) and FF /4 (jmp) whose
    memory operand carries displacement 0x18, 0x20 or 0x28 (mod=1
    disp8 form, plus the mod=2 disp32 form), and of the register
    form (mod=3). SIB bytes are stepped over. This is a superset of
    the decoded census: patterns may start mid-instruction. Exact
    decoded totals are recorded as packet evidence
    (census_decoded.json), not here."""
    _tva, text = elf.text()
    b = np.frombuffer(text, dtype=np.uint8)
    n = len(b)
    ff = b[:n - 7] == 0xFF
    modrm = b[1:n - 6]
    mod = modrm >> 6
    reg = (modrm >> 3) & 7
    sib = (modrm & 7) == 4
    calljmp = (reg == 2) | (reg == 4)
    out = {}
    for d in (0x18, 0x20, 0x28):
        hit = ff & calljmp & (mod == 1) & ~sib & (b[2:n - 5] == d)
        hit |= ff & calljmp & (mod == 1) & sib & (b[3:n - 4] == d)
        hit |= (ff & calljmp & (mod == 2) & ~sib & (b[2:n - 5] == d)
                & (b[3:n - 4] == 0) & (b[4:n - 3] == 0)
                & (b[5:n - 2] == 0))
        hit |= (ff & calljmp & (mod == 2) & sib & (b[3:n - 4] == d)
                & (b[4:n - 3] == 0) & (b[5:n - 2] == 0)
                & (b[6:n - 1] == 0))
        out[f'disp_{d:#x}'] = int(np.count_nonzero(hit))
    out['reg_form'] = int(np.count_nonzero(ff & calljmp & (mod == 3)))
    return out


_LINE_RE = re.compile(r'^\s+([0-9a-f]+):\t(?:[0-9a-f]{2} )+\s*\t(.*)$')
_CMT_RE = re.compile(r'#\s+([0-9a-f]+)\s')
_DISP_RE = re.compile(r'\*(-?0x[0-9a-f]+)\(')


def _objdump_range(path, start, end):
    out = subprocess.run(
        ['objdump', '-d', '--start-address', hex(start),
         '--stop-address', hex(end), str(path)],
        capture_output=True, text=True, check=True).stdout
    lines = []
    for line in out.splitlines():
        m = _LINE_RE.match(line)
        if m:
            lines.append((int(m.group(1), 16), m.group(2).strip(), line))
    return lines


def _decode_layer(elf, path):
    """Genuine registry references and the indirect-call inventory,
    from objdump decodes of the candidate and cluster bodies."""
    cand = _raw_candidate_bodies(elf)
    genuine = {}
    for s, e in sorted(elf.fdes):
        if s not in cand:
            continue
        refs = set()
        for _site, _asm, line in _objdump_range(path, s, e):
            cm = _CMT_RE.search(line)
            if cm:
                t = int(cm.group(1), 16)
                if SCAN_LO <= t < SCAN_HI:
                    refs.add(t)
        if refs:
            genuine[s] = sorted(hex(t) for t in refs)
    genuine = {hex(s): genuine[s] for s in sorted(genuine)}
    phantom = sorted(hex(s) for s in cand
                     if s is not None and s not in
                     {int(k, 16) for k in genuine})
    if None in cand:
        phantom.append(None)
    inventory = {}
    for name, anchor in BODY_ANCHORS.items():
        s, e = elf.body_of(anchor)
        disp = {}
        reg = []
        rip = 0
        for site, asm, _line in _objdump_range(path, s, e):
            if not (asm.startswith('call') or asm.startswith('jmp')):
                continue
            if '*' not in asm:
                continue
            if '(%rip)' in asm:
                rip += 1
            elif '%' in asm.split('*', 1)[1] and '(' not in asm:
                reg.append(hex(site))
            else:
                dm = _DISP_RE.search(asm)
                if dm:
                    disp.setdefault(dm.group(1), []).append(hex(site))
        inventory[name] = {'disp': disp, 'reg': sorted(reg),
                           'rip_indirect': rip}
    return genuine, phantom, inventory


def analyze(data, artifact_path=None):
    elf = Elf(data)
    rec = {}
    rec['artifact'] = {
        'sha256': hashlib.sha256(data).hexdigest(),
        'size': len(data),
    }
    bodies = {}
    for name, anchor in BODY_ANCHORS.items():
        s, e = elf.body_of(anchor)
        bodies[name] = {
            'start': hex(s), 'end': hex(e), 'bytes': e - s,
            'sha256': hashlib.sha256(elf.read(s, e - s)).hexdigest(),
        }
    rec['bodies'] = bodies
    rec['byte_pins'] = {
        name: {'addr': hex(a), 'bytes': elf.read(a, n).hex()}
        for name, (a, n) in BYTE_PINS.items()
    }
    # ---- wake vtable layout ----
    slots = {}
    for off in (0x00, 0x08, 0x10, 0x18, 0x20, 0x28):
        va = WAKE_VTABLE + off
        r = elf.rela.get(va)
        slots[f'+{off:#x}'] = {
            'file_qword': hex(elf.u64(va)),
            'rela': None if r is None else {
                'type': r[0], 'addend': hex(r[1]), 'sym': r[2]},
        }
    rec['wake_vtable'] = {'address': hex(WAKE_VTABLE), 'slots': slots}
    # ---- vtable address materialisation census ----
    lea_sites = _lea_vtable_sites(elf)
    ins = elf.body_of(int(lea_sites[0], 16)) if lea_sites else None
    rec['vtable_materialisation'] = {
        'lea_sites': lea_sites,
        'all_in_registry_insert': bool(lea_sites) and all(
            ins[0] <= int(x, 16) < ins[1] for x in lea_sites),
        'qword_occurrences_in_file': data.count(
            struct.pack('<Q', WAKE_VTABLE)),
        'rela_addend_occurrences': sum(
            1 for _t, add, _s in elf.rela.values() if add == WAKE_VTABLE),
    }
    # ---- GOT slot resolutions ----
    got = {}
    for name, slot in GOT_SLOTS.items():
        t, _add, sym = elf.rela[slot]
        got[name] = {'slot': hex(slot), 'rela_type': t,
                     'symbol': elf.dynsym_name(sym)}
    rec['got'] = got
    rec['raw_ff_census'] = _raw_ff_census(elf)
    # ---- decode layer (needs the artifact on disk for objdump) ----
    if artifact_path is None:
        default = (Path(__file__).resolve().parents[1]
                   / 'artifacts' / 'node' / '115' / 'hl-node')
        artifact_path = default if default.exists() else None
    if artifact_path is not None:
        genuine, phantom, inventory = _decode_layer(elf, artifact_path)
        rec['registry_global'] = {
            'struct_range': [hex(REGISTRY_BASE), hex(REGISTRY_END)],
            'neighbour_word': hex(NEIGHBOUR_WORD),
            'genuine_refs': genuine,
            'phantom_bodies': phantom,
        }
        rec['cluster_indirect_inventory'] = inventory
    return rec


if __name__ == '__main__':
    p = Path(sys.argv[1]) if len(sys.argv) > 1 else (
        Path(__file__).resolve().parents[1]
        / 'artifacts' / 'node' / '115' / 'hl-node')
    print(json.dumps(analyze(p.read_bytes(), p), indent=1, sort_keys=True))
