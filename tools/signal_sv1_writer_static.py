"""Static evidence tool for the RE-005 node-115 signal sv[1] writer packet.

Question (open edge 1 of the signal-fd producer packet, PR #2952):
the 32-byte global signal state at 0x64fee20 holds a socketpair as
+0x00 sv[1] / +0x04 sv[0]. #2952 pinned that no .text body loads the
+0x00 word through an absolute reference. This tool re-derives who
writes to sv[1] at run time: the registered per-signal action of the
vendored tokio signal machinery (signal-hook-registry style), whose
two call shims load the fd through a pointer carried in the action's
closure environment {&state, signal} and `send` one byte on it.

Everything is re-derived from the artifact bytes alone: ELF program
and section headers, the .eh_frame_hdr FDE table, .rela.dyn/.dynsym
GOT resolutions, whole-.text RIP-relative and E8 censuses (numpy),
and exact instruction byte pins.
"""
import hashlib
import json
import struct
import sys
from pathlib import Path

import numpy as np

GLOBAL = 0x64fee20
GLOBAL_END = 0x64fee38          # base + 0x18 (Once word included)
NEIGHBOR = 0x64fee18            # distinct atomic word 8 bytes below
WAKE_VTABLE = 0x64c54b8
WAKE_BYTE = 0x94c786

BODY_ANCHORS = {
    'wake_call': 0x5cdcda0,
    'wake_call_once': 0x5cdd040,
    'entry_init': 0x5cdbf20,
    'registry_insert': 0x5cdd480,
    'os_handler': 0x5c67560,
    'entry_lookup': 0x5cde710,
    'signal_attach': 0x5ce71f0,
    'table_drain': 0x5ce7380,
    'init_closure': 0x5cfcec0,
    'entry_arc_clone': 0x5cfcf90,
    'oncelock_shim': 0x5cdf535,
    'entry_once_shim_a': 0x5cdf460,
    'entry_once_shim_b': 0x5cdf630,
    'generic_send_helper': 0x5cdfc90,
    'lazy_accessor': 0x5cdf582,
    'vtable_call_shim': 0x5cdf4f0,
    'io_error_ctor': 0x5cdd280,
}

BYTE_PINS = {
    'wake_call_fd_load': (0x5cdcdc9, 2),        # mov (%rcx),%edi
    'wake_call_send': (0x5cdcddc, 6),           # call *send(%rip)
    'wake_call_once_fd_load': (0x5cdd069, 2),   # mov (%rcx),%edi
    'wake_call_once_send': (0x5cdd07c, 6),      # call *send(%rip)
    'handler_action_call': (0x5c67834, 3),      # call *0x28(%rax)
    'entry_init_env_stores': (0x5cdbf92, 8),    # &state @+0x10, sig @+0x18
    'entry_init_handler_lea': (0x5cdc655, 7),   # lea handler,%rax
    'entry_init_handler_store': (0x5cdc65c, 8),  # mov %rax,act+0
    'entry_init_sigaction_query': (0x5cdc418, 6),
    'entry_init_sigaction_install': (0x5cdc6e2, 6),
    'entry_init_insert_call': (0x5cdc14b, 5),   # call registry_insert
}

GOT_SLOTS = {
    'send': 0x64eb088,
    'recv': 0x64eb080,
    'socketpair': 0x64eb078,
    'fcntl': 0x64e8a18,
    'epoll_ctl': 0x64e12c0,
    'close': 0x64dfe78,
    'sigaction': 0x64ec510,
    'errno_location': 0x64dffc8,
    'memcpy': 0x64df508,
    'call_once_force': 0x64df9f0,
    'drain_dispatch': 0x64ecba8,
    'drain_step': 0x64e01e8,
}


class Elf:
    def __init__(self, data):
        self.data = data
        phoff = struct.unpack_from('<Q', data, 0x20)[0]
        phes, phnum = struct.unpack_from('<HH', data, 0x36)
        self.segs = []
        for i in range(phnum):
            t, fl, off, va, pa, fsz, msz, al = struct.unpack_from(
                '<IIQQQQQQ', data, phoff + i * phes)
            if t == 1:
                self.segs.append((va, off, fsz))
        shoff = struct.unpack_from('<Q', data, 0x28)[0]
        shes, shnum, shstrndx = struct.unpack_from('<HHH', data, 0x3a)
        raw = []
        for i in range(shnum):
            raw.append(struct.unpack_from('<IIQQQQIIQQ', data,
                                          shoff + i * shes))
        stroff = raw[shstrndx][4]
        self.sections = {}
        for nm, ty, fl, addr, off, sz, *_ in raw:
            end = data.index(b'\0', stroff + nm)
            self.sections[data[stroff + nm:end].decode()] = (addr, off, sz)
        self._fdes = None

    def va2off(self, va):
        for sva, soff, sfz in self.segs:
            if sva <= va < sva + sfz:
                return soff + (va - sva)
        return None

    def read(self, va, n):
        o = self.va2off(va)
        return self.data[o:o + n]

    def fdes(self):
        if self._fdes is not None:
            return self._fdes
        hva, hoff, hsz = self.sections['.eh_frame_hdr']
        hdr = self.data[hoff:hoff + hsz]
        count = struct.unpack_from('<I', hdr, 8)[0]
        out = []
        i = 12
        for _ in range(count):
            init = hva + struct.unpack_from('<i', hdr, i)[0]
            frel = struct.unpack_from('<i', hdr, i + 4)[0]
            i += 8
            fo = self.va2off(hva + frel)
            rng = struct.unpack_from('<I', self.data, fo + 12)[0]
            out.append((init, init + rng))
        out.sort()
        self._fdes = out
        return out

    def body_of(self, va):
        import bisect
        fdes = self.fdes()
        starts = [s for s, _ in fdes]
        idx = bisect.bisect_right(starts, va) - 1
        if idx < 0:
            return None
        s, e = fdes[idx]
        return (s, e) if s <= va < e else None

    def syms(self):
        dva, doff, dsz = self.sections['.dynsym']
        sta, soff, ssz = self.sections['.dynstr']
        out = []
        for i in range(dsz // 24):
            nm, *_rest, _val, _sz = struct.unpack_from(
                '<IBBHQQ', self.data, doff + i * 24)
            end = self.data.index(b'\0', soff + nm)
            out.append(self.data[soff + nm:end].decode())
        return out

    def relas(self):
        out = {}
        syms = self.syms()
        for sec in ('.rela.dyn', '.rela.plt'):
            if sec not in self.sections:
                continue
            rva, roff, rsz = self.sections[sec]
            for i in range(rsz // 24):
                off, info, add = struct.unpack_from(
                    '<QQq', self.data, roff + i * 24)
                out[off] = (info & 0xffffffff, info >> 32, add)
        self._syms = syms
        return out

    def resolve(self, slot):
        rela = self.relas()
        if slot not in rela:
            return {'kind': 'file_value',
                    'value': hex(struct.unpack(
                        '<Q', self.read(slot, 8))[0])}
        typ, sym, add = rela[slot]
        if typ == 8:
            b = self.body_of(add)
            return {'kind': 'RELATIVE', 'target': hex(add),
                    'body': [hex(b[0]), hex(b[1])] if b else None}
        name = self._syms[sym] if sym < len(self._syms) else str(sym)
        return {'kind': {6: 'GLOB_DAT', 7: 'JUMP_SLOT'}.get(typ, str(typ)),
                'symbol': name}


def analyze(data):
    elf = Elf(data)
    rec = {}
    rec['artifact'] = {
        'sha256': hashlib.sha256(data).hexdigest(),
        'size': len(data),
    }
    # ---- bodies ----
    bodies = {}
    for name, anchor in BODY_ANCHORS.items():
        s, e = elf.body_of(anchor)
        bodies[name] = {
            'start': hex(s), 'end': hex(e), 'bytes': e - s,
            'sha256': hashlib.sha256(elf.read(s, e - s)).hexdigest(),
        }
    rec['bodies'] = bodies

    # ---- global born state ----
    born = elf.read(GLOBAL, 0x20)
    rec['global_state'] = {
        'address': hex(GLOBAL),
        'born_bytes': born.hex(),
        'once_word': hex(struct.unpack_from('<Q', born, 0x18)[0]),
        'value_words_zero': born[:0x18] == b'\0' * 0x18,
    }

    # ---- whole-.text censuses ----
    tva, toff, tsz = elf.sections['.text']
    text = data[toff:toff + tsz]
    b = np.frombuffer(text, dtype=np.uint8).astype(np.int32)
    disp = (b[:-3] | (b[1:-2] << 8) | (b[2:-1] << 16) | (b[3:] << 24))
    pos = tva + np.arange(len(disp), dtype=np.int64)
    final = pos + 4 + disp

    def verified_sites(target):
        """Disp positions whose disp-final target == target AND whose
        preceding bytes form a RIP-relative ModRM instruction:
        [REX] op (modrm&0xc7)==0x05, or 0f c1 (modrm&0xc7)==0x05."""
        out = []
        for i in np.nonzero(final == target)[0]:
            i = int(i)
            start = None
            # 3-byte prefix: REX, opcode, ModRM at i-1
            if i >= 3 and 0x40 <= text[i - 3] <= 0x4f \
                    and (text[i - 1] & 0xc7) == 0x05:
                start = i - 3
            # 0f c1 /r (xadd): 0f, c1, ModRM at i-1
            elif i >= 3 and text[i - 3] == 0x0f and text[i - 2] == 0xc1 \
                    and (text[i - 1] & 0xc7) == 0x05:
                start = i - 3
            # 2-byte prefix: opcode, ModRM at i-1
            elif i >= 2 and (text[i - 1] & 0xc7) == 0x05 \
                    and text[i - 2] != 0x0f:
                start = i - 2
            if start is not None:
                site = tva + start
                body = elf.body_of(site)
                out.append({'site': hex(site),
                            'body': hex(body[0]) if body else None})
        return out

    census = {}
    for off in (0x00, 0x04, 0x08, 0x10, 0x18):
        census[hex(off)] = verified_sites(GLOBAL + off)
    rec['absolute_census'] = census
    rec['neighbor_xadd_sites'] = verified_sites(NEIGHBOR)

    # imm64 occurrences of any global address inside .text
    imm = {}
    for addr in range(GLOBAL, GLOBAL_END):
        pat = struct.pack('<Q', addr)
        n = 0
        start = 0
        while True:
            j = text.find(pat, start)
            if j < 0:
                break
            n += 1
            start = j + 1
        imm[hex(addr)] = n
    rec['imm64_census'] = imm

    # ---- E8 direct-call census (vectorised) ----
    def e8_callers(target):
        idx = np.nonzero(b[:-4] == 0xe8)[0].astype(np.int64)
        tg = tva + idx + 5 + disp[idx + 1].astype(np.int64)
        return sorted(hex(tva + int(i)) for i in idx[tg == target])

    rec['e8_callers'] = {
        'entry_init': e8_callers(BODY_ANCHORS['entry_init']),
        'signal_attach': e8_callers(BODY_ANCHORS['signal_attach']),
        'wake_call': e8_callers(BODY_ANCHORS['wake_call']),
        'wake_call_once': e8_callers(BODY_ANCHORS['wake_call_once']),
    }

    # ---- GOT resolutions ----
    rec['got'] = {name: elf.resolve(slot)
                  for name, slot in GOT_SLOTS.items()}

    # FF 15 call sites targeting the send GOT slot
    ff15 = []
    idx = np.nonzero((b[:-5] == 0xff) & (b[1:-4] == 0x15))[0].astype(np.int64)
    tg = tva + idx + 6 + disp[idx + 2].astype(np.int64)
    for i in idx[tg == GOT_SLOTS['send']]:
        site = tva + int(i)
        body = elf.body_of(site)
        ff15.append({'site': hex(site),
                     'body': hex(body[0]) if body else None})
    rec['send_call_sites'] = sorted(ff15, key=lambda d: d['site'])

    # ---- wake vtable ----
    vt = {}
    for i in range(6):
        slot = WAKE_VTABLE + 8 * i
        vt[hex(8 * i)] = elf.resolve(slot)
    rec['wake_vtable'] = {'base': hex(WAKE_VTABLE), 'slots': vt}
    rec['wake_vtable_refs'] = verified_sites(WAKE_VTABLE)
    rec['wake_byte'] = {'address': hex(WAKE_BYTE),
                        'value': elf.read(WAKE_BYTE, 1).hex()}

    # ---- byte pins ----
    rec['byte_pins'] = {name: elf.read(va, n).hex()
                        for name, (va, n) in BYTE_PINS.items()}
    return rec


def main():
    root = Path(__file__).resolve().parents[1]
    target = root / 'artifacts' / 'node' / '115' / 'hl-node'
    records_path = (root / 'research' / 'work-items' /
                    'RE-005-node115-signal-sv1-writer' / 'records.json')
    got = analyze(target.read_bytes())
    want = json.loads(records_path.read_text())
    print(json.dumps({'matches': got == want}))
    if got != want:
        for key in want:
            if got.get(key) != want[key]:
                print('MISMATCH', key, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
