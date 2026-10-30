#!/usr/bin/env python3
"""Static node #94 net_utils TCP frame-read census, checked from authenticated bytes.

Question: across every copy of the frame reader linked to
net_utils/src/tcp/read.rs, what header layout, length admission, compression
predicate, chunk size and progress-log order do the instructions implement?

Only the Python standard library is used. Copies are found by scanning every
.text byte for the exact chunk-cap encoding and RIP-relative LEAs to the shared
over-limit/progress literals, then bounded by parsed .eh_frame FDEs. Each fact
is a fixed instruction encoding at a pinned VA whose branch, LEA and GOT-slot
targets are decoded here; relocations and Location records come from
.rela.dyn. Nothing from the binary is executed.
"""
import argparse
import json
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from artifacts import ROOT, check  # noqa: E402
from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

TARGET = 'artifacts/node/94/hl-node'
CHUNK = 4_000_000
CHUNK_CAP = bytes.fromhex('483d00093d00' 'b900093d00' '480f42c8')  # cmp rax,CHUNK; mov ecx,CHUNK; cmovb rcx,rax
GATE_CMP = bytes.fromhex('4881ff00093d00')                       # cmp rdi,CHUNK
SUB_JBE = bytes.fromhex('4829f8')                                # sub rax,rdi
SOURCE = b'/home/ubuntu/hl/code_Mainnet/net_utils/src/tcp/read.rs'
SOURCE_VA = 0x1e3bd5
LITERALS = {
    'over_limit_desc': (0x1eaa25, b'$tcp read bytes over limit @@ [desc: '),
    'over_limit_len': (0x1f0cba, b'$tcp::read_bytes over limit @@ [len: '),
    'progress_warn': (0x1f228d, b'\xc0\n WARN >>> \xc0\x16 @@ reading bytes for '),
    'early_eof': (0x7d0cd4, b'early eof'),
}
SLOTS = {'alloc': 0x576e298, 'io_error_new': 0x576ee60, 'decompress': 0x5773810}
F64_40 = bytes.fromhex('48b9' '0000000000004440')   # movabs rcx,40.0
F64_20 = bytes.fromhex('48b9' '0000000000003440')   # movabs rcx,20.0
EOF_SEQ_TAIL = bytes.fromhex('ba09000000' 'bf25000000' 'ff15')  # mov edx,9; mov edi,0x25; call [rip+X]

# Reader copies.  `limits`: (cmp VA, branch VA); `gate_jb`: VA of the jb after GATE_CMP;
# `header`: VAs of mov r32,[base+D] / bswap / movzx r32,BYTE [base+D+4].
COPIES = (
    dict(fde=0x2049950, header_call=(0x2049f47, 0x20485e0), limits=((0x204a0b5, 0x204a0b9),),
         flag=0x204a1d9, gate_jb=0x204a89f, decompress=0x204aad2),
    dict(fde=0x43a0260, header_call=(0x43a0857, 0x439edd0), limits=((0x43a09c5, 0x43a09c9),),
         flag=0x43a0ae9, gate_jb=0x43a11af, decompress=0x43a13e2),
    dict(fde=0x4b72900, header=(0x4b731eb, 0x4b731f2, 0x4b731f5), eof=0x4b72eba,
         limits=((0x4b730b8, 0x4b730bc), (0x4b7320b, 0x4b7320f)),
         flag=0x4b73215, gate_jb=0x4b738c8, decompress=0x4b73a4d),
    dict(fde=0x22615b0, header=(0x2263e78, 0x2263e80, 0x2263e83), eof=0x2263e22,
         limits=((0x2263e9d, 0x2263ea2),), flag=0x2263ea8, gate_jb=0x2264c75, decompress=0x2264edb),
    dict(fde=0x4744160, header=(0x4747123, 0x474712a, 0x474712d), eof=0x4746f25,
         limits=((0x4747019, 0x4747020),), flag=0x4747026, gate_jb=0x474522a, decompress=0x47470c9),
)
# Out-of-line five-byte header readers called by the first two copies.
HEADER_HELPERS = {0x20485e0: dict(len5=0x2048622, eof=0x20486cf, swap=0x2048737),
                  0x439edd0: dict(len5=0x439ee12, eof=0x439eebf, swap=0x439ef27)}


class EvidenceError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


class Image:
    def __init__(self, data):
        self.data = data
        self.secs = sections(data)
        self.text = next((s for s in self.secs if s['name'] == '.text' and s['type'] != 8), None)
        require(self.text is not None, 'no file-backed .text')
        self.relative = self._relative()
        _, fdes = eh_frame_records(data, self.secs)
        self.fdes = sorted((f['start'], f['end']) for f in fdes)
        self.fde_starts = [s for s, _ in self.fdes]

    def _relative(self):
        rela = next((s for s in self.secs if s['name'] == '.rela.dyn' and s['type'] == 4), None)
        require(rela is not None and rela['size'] % 24 == 0, 'no well-formed .rela.dyn')
        out = {}
        for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
            where, info, addend = struct.unpack_from('<QQq', self.data, pos)
            if info & 0xffffffff == 8:
                out[where] = addend
        return out

    def offset(self, va, size=1):
        hits = [s for s in self.secs if s['type'] != 8 and s['address'] and
                s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(hits) == 1, f'VA {va:#x}+{size} is not in exactly one file-backed section')
        return hits[0]['offset'] + va - hits[0]['address']

    def read(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off + size]

    def try_read(self, va, size):
        try:
            return self.read(va, size)
        except EvidenceError:
            return b''

    def fde(self, start):
        hits = [f for f in self.fdes if f[0] == start]
        require(len(hits) == 1, f'{start:#x} is not exactly one FDE start')
        return hits[0]

    def fde_of(self, va):
        hits = [f for f in self.fdes if f[0] <= va < f[1]]
        return hits[0] if len(hits) == 1 else None

    def expect(self, va, hexbytes, what):
        want = bytes.fromhex(hexbytes) if isinstance(hexbytes, str) else hexbytes
        require(self.read(va, len(want)) == want, f'{what} at {va:#x}: bytes changed')

    def rel32(self, va, length):
        return va + length + struct.unpack('<i', self.read(va + length - 4, 4))[0]

    def lea_target(self, va):
        b = self.read(va, 7)
        require(b[0] in (0x48, 0x4c) and b[1] == 0x8d and b[2] & 0xc7 == 0x05, f'no RIP-relative LEA at {va:#x}')
        return self.rel32(va, 7)

    def call_slot(self, va):
        self.expect(va, 'ff15', 'indirect call')
        slot = self.rel32(va, 6)
        require(slot in self.relative, f'call at {va:#x} reads unrelocated slot {slot:#x}')
        return slot, self.relative[slot]

    def location(self, va):
        ptr = self.relative.get(va)
        size, line, col = struct.unpack('<QII', self.read(va + 8, 16))
        require(ptr is not None and self.read(ptr, size) == SOURCE, f'Location {va:#x} does not name read.rs')
        return line, col

    def lea_census(self, targets):
        base, off, size = self.text['address'], self.text['offset'], self.text['size']
        out = {t: [] for t in targets}
        for m in re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', self.data[off:off + size - 7], re.S):
            i = m.start()
            t = base + i + 7 + struct.unpack_from('<i', self.data, off + i + 3)[0]
            if t in out:
                out[t].append(base + i)
        return out


def scan(img, pattern):
    base, off, size = img.text['address'], img.text['offset'], img.text['size']
    text = img.data[off:off + size]
    return [base + m.start() for m in re.finditer(re.escape(pattern), text)]


def modrm_mov_rax_len(b):
    """Length of `mov rax, QWORD PTR [base+disp]` (REX.W 8b /0) or None."""
    if len(b) < 3 or b[0] not in (0x48, 0x49) or b[1] != 0x8b or (b[2] >> 3) & 7 != 0:
        return None
    mod, rm = b[2] >> 6, b[2] & 7
    if mod == 3 or (mod == 0 and rm == 5):
        return None
    n = 3 + (rm == 4)
    return n + {0: 0, 1: 1, 2: 4}[mod]


def check_header_helper(img, start, pins):
    img.fde(start)
    img.expect(pins['len5'], '48c7431005000000', 'buffer length 5')
    img.expect(pins['len5'] + 0x10, 'b905000000', 'remaining length 5')
    img.expect(pins['swap'], '8b4b50' '0fc9' '0fb64354', 'u32 load, bswap, flag byte at +4')
    eof = check_eof(img, pins['eof'])
    return {'fde': hex(start), 'buffer_len': 5, 'length_dword_offset': 0x50, 'flag_byte_offset': 0x54,
            'length_byte_order': 'big-endian (bswap)', 'early_eof': eof}


def check_eof(img, va):
    require(img.lea_target(va) == LITERALS['early_eof'][0], f'early-eof LEA retargeted at {va:#x}')
    img.expect(va + 7, EOF_SEQ_TAIL, 'early-eof io::Error kind/len/call')
    slot, target = img.call_slot(va + 17)
    require(slot == SLOTS['io_error_new'], f'early-eof constructor slot changed at {va + 17:#x}')
    return {'lea': hex(va), 'kind_imm': 0x25, 'message_len': 9, 'call_slot': hex(slot), 'callee': hex(target)}


def check_header_inline(img, pins):
    load, swap, flag = pins
    lb, sb, fb = img.read(load, 8), img.read(swap, 3), img.read(flag, 9)
    require(sb[:2] in (b'\x41\x0f',) and 0xc8 <= sb[2] <= 0xcf, f'no bswap r32 at {swap:#x}')
    reg = sb[2] - 0xc8 + 8
    # mov r32,[base+disp32] (REX 44/45 8b, mod=10) directly before the bswap of the same register
    require(lb[0] in (0x44, 0x45) and lb[1] == 0x8b and lb[2] >> 6 == 2 and ((lb[2] >> 3) & 7) + 8 == reg,
            f'length load does not feed bswap at {load:#x}')
    sib = (lb[2] & 7) == 4
    disp = struct.unpack('<i', lb[3 + sib:7 + sib])[0]
    require(load + 7 + sib == swap, f'length load not adjacent to bswap at {load:#x}')
    require(fb[0] in (0x41, 0x44) and fb[1:3] == b'\x0f\xb6' and fb[3] >> 6 == 2, f'no movzx flag byte at {flag:#x}')
    fsib = (fb[3] & 7) == 4
    fdisp = struct.unpack('<i', fb[4 + fsib:8 + fsib])[0]
    same_base = (fb[3] & 7) == (lb[2] & 7) and fb[0] & 1 == lb[0] & 1 and (not sib or fb[4] == lb[3])
    require(fdisp == disp + 4 and same_base, f'flag byte is not length dword + 4 at {flag:#x}')
    return {'length_load': hex(load), 'bswap': hex(swap), 'flag_load': hex(flag), 'frame_offset': hex(disp),
            'flag_offset': hex(fdisp), 'length_byte_order': 'big-endian (bswap)'}


def check_limit(img, cmp_va, jcc_va, flag_va, fde):
    b = img.read(cmp_va, 8)
    # cmp QWORD PTR [base+disp], r14   (REX.WR 4c/4d 39, reg=110)
    require(b[0] in (0x4c, 0x4d) and b[1] == 0x39 and (b[2] >> 3) & 7 == 6, f'no cmp [max_len], r14 at {cmp_va:#x}')
    j = img.read(jcc_va, 2)
    require(j[0] == 0x0f and j[1] in (0x82, 0x83), f'no unsigned jb/jae after limit compare at {jcc_va:#x}')
    target = img.rel32(jcc_va, 6)
    ok, over = (target, jcc_va + 6) if j[1] == 0x83 else (jcc_va + 6, target)
    require(ok == flag_va, f'accepted length does not reach the flag test ({ok:#x})')
    require(fde[0] <= over < fde[1], 'over-limit path leaves the FDE')
    return {'compare': hex(cmp_va), 'branch': hex(jcc_va), 'kind': 'jae ok' if j[1] == 0x83 else 'jb over',
            'accepted_target': hex(ok), 'over_target': hex(over), 'equal_length_admitted': True}


def check_flag_alloc(img, va):
    b = img.read(va, 4)
    require(b[0] in (0x40, 0x41) and b[1] == 0x80 and b[2] >> 3 == 0x1f and b[3] == 1, f'no cmp r8,1 at {va:#x}')
    s = img.read(va + 4, 3)
    require(s[:2] == b'\x0f\x94' or s == b'\x41\x0f\x94', f'compression flag not set by sete at {va + 4:#x}')
    window = img.read(va, 0x30)
    t = window.find(bytes.fromhex('4d85f6'))
    a = window.find(bytes.fromhex('bf01000000' '4c89f6' 'ff15'))
    require(0 < t < a, f'no test r14 then alloc(1, r14) after flag at {va:#x}')
    slot, target = img.call_slot(va + a + 8)
    require(slot == SLOTS['alloc'], f'allocation slot changed after {va:#x}')
    return {'flag_compare': hex(va), 'predicate': 'flag == 1', 'zero_length_skips_alloc': hex(va + t),
            'alloc_call': hex(va + a + 8), 'alloc_slot': hex(slot), 'alloc_callee': hex(target), 'align': 1}


def check_gate(img, jb_va, fde):
    cmp_va = None
    for back in range(7, 7 + 16):
        if img.read(jb_va - back, 7) == GATE_CMP:
            cmp_va = jb_va - back
            break
    require(cmp_va is not None, f'no cmp rdi,CHUNK before {jb_va:#x}')
    between = img.read(cmp_va + 7, jb_va - cmp_va - 7)
    # only flag-preserving moves may separate the compare from its branch
    require(between in (b'', bytes.fromhex('4989df' '488bac24a8000000')), f'unexpected code between gate compare and jb at {jb_va:#x}')
    img.expect(jb_va, '0f82', 'gate jb')
    rem = img.rel32(jb_va, 6)
    n = modrm_mov_rax_len(img.read(rem, 8))
    require(n is not None, f'gate target {rem:#x} does not load the frame length')
    img.expect(rem + n, SUB_JBE + b'\x0f\x86', 'remaining = len - offset; jbe done')
    cap = rem + n + 3 + 6
    img.expect(cap, CHUNK_CAP, 'min(remaining, 4_000_000)')
    require(all(fde[0] <= v < fde[1] for v in (cmp_va, jb_va, rem, cap)), 'gate layout leaves the FDE')
    stores = [k for k in (4, 5, 7) if img.read(cmp_va - k, 2) in (b'\x48\x89', b'\x49\x89')
              and (img.read(cmp_va - k + 2, 1)[0] >> 3) & 7 == 7]
    require(len(stores) == 1, f'updated offset (rdi) is not stored directly before the gate at {cmp_va:#x}')
    return {'gate_compare': hex(cmp_va), 'gate_jb': hex(jb_va), 'remaining_check': hex(rem), 'chunk_cap': hex(cap)}


def progress_join(img, gate, warn):
    """The WARN LEA must lie on the gate fallthrough path, which rejoins the remaining check."""
    jb, rem = int(gate['gate_jb'], 16), int(gate['remaining_check'], 16)
    require(jb + 6 <= warn, f'progress WARN LEA {warn:#x} precedes the gate fallthrough')
    if jb < rem:
        require(warn < rem, f'progress WARN LEA {warn:#x} is past the remaining check')
        return {'warn_lea': hex(warn), 'rejoin': 'fallthrough', 'rejoin_va': hex(rem)}
    window = img.read(warn, 0x80)
    for i in range(len(window) - 5):
        if window[i] == 0xe9 and img.rel32(warn + i, 5) == rem:
            return {'warn_lea': hex(warn), 'rejoin': 'jmp', 'rejoin_va': hex(warn + i)}
    raise EvidenceError(f'progress path after {warn:#x} does not rejoin the remaining check')


def check_timeouts(img, fde, lea_map):
    lo, hi = fde
    out = {}
    for name, text, movabs, seconds in (('header', b'tcp_bytes', F64_40, 40.0), ('chunk', b'tcp_read_exact', F64_20, 20.0)):
        moves = [v for v in scan_range(img, movabs, lo, hi)]
        require(len(moves) == 1, f'{name} timeout constant count {len(moves)} in {lo:#x}')
        leas = [v for t, vs in lea_map.items() for v in vs if lo <= v < hi and v < moves[0] <= v + 0x50 and
                img.try_read(t, len(text)) == text]
        require(len(leas) == 1, f'{name} descriptor {text!r} not bound to its timeout in {lo:#x}')
        out[name] = {'descriptor': text.decode(), 'descriptor_lea': hex(leas[0]), 'timeout_movabs': hex(moves[0]),
                     'seconds': seconds}
    return out


def scan_range(img, pattern, lo, hi):
    off = img.offset(lo, hi - lo)
    blob = img.data[off:off + hi - lo]
    return [lo + m.start() for m in re.finditer(re.escape(pattern), blob)]


def descriptor_leas(img, fde):
    lo, hi = fde
    off = img.offset(lo, hi - lo)
    blob = img.data[off:off + hi - lo]
    out = {}
    for m in re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', blob, re.S):
        va = lo + m.start()
        if va + 7 > hi:
            continue
        t = va + 7 + struct.unpack_from('<i', blob, m.start() + 3)[0]
        out.setdefault(t, []).append(va)
    return out


def analyse(data):
    img = Image(data)
    census = img.lea_census([v for v, _ in LITERALS.values()])
    for name, (va, text) in LITERALS.items():
        require(img.read(va, len(text)) == text, f'literal {name} changed at {va:#x}')
    caps = scan(img, CHUNK_CAP)
    gates = scan(img, GATE_CMP)
    require(img.read(SOURCE_VA, len(SOURCE)) == SOURCE, 'read.rs path literal changed')
    loc_slots = sorted(s for s, t in img.relative.items() if t == SOURCE_VA)
    require(len(loc_slots) == 4 * len(COPIES), f'read.rs Location record count {len(loc_slots)}')
    loc_lines = {s: img.location(s) for s in loc_slots}
    loc_census = img.lea_census(loc_slots)
    copies = []
    for c in COPIES:
        fde = img.fde(c['fde'])
        rec = {'fde': [hex(fde[0]), hex(fde[1])], 'bytes': fde[1] - fde[0]}
        if 'header_call' in c:
            site, helper = c['header_call']
            img.expect(site, 'e8', 'header helper call')
            require(img.rel32(site, 5) == helper, f'header call at {site:#x} retargeted')
            rec['header'] = {'call': hex(site), 'helper': hex(helper)}
        else:
            rec['header'] = check_header_inline(img, c['header'])
            rec['header']['early_eof'] = check_eof(img, c['eof'])
        rec['limits'] = [check_limit(img, cv, jv, c['flag'], fde) for cv, jv in c['limits']]
        rec['flag_alloc'] = check_flag_alloc(img, c['flag'])
        rec['chunk'] = check_gate(img, c['gate_jb'], fde)
        slot, target = img.call_slot(c['decompress'])
        require(slot == SLOTS['decompress'], f'decompression slot changed at {c["decompress"]:#x}')
        rec['decompress'] = {'call': hex(c['decompress']), 'slot': hex(slot), 'callee': hex(target)}
        leas = descriptor_leas(img, fde)
        rec['timeouts'] = check_timeouts(img, fde, leas)
        for name in ('over_limit_desc', 'over_limit_len', 'progress_warn'):
            hits = [v for v in census[LITERALS[name][0]] if fde[0] <= v < fde[1]]
            require(len(hits) == 1, f'{name} LEA count {len(hits)} in copy {fde[0]:#x}')
            rec.setdefault('literals', {})[name] = hex(hits[0])
        over = rec['literals']['over_limit_desc']
        for lim in rec['limits']:
            require(0 <= int(over, 16) - int(lim['over_target'], 16) < 0x100,
                    f'over-limit target {lim["over_target"]} does not format the over-limit message')
        rec['chunk']['progress'] = progress_join(img, rec['chunk'], int(rec['literals']['progress_warn'], 16))
        lines = {}
        for slot_va, vs in loc_census.items():
            for v in vs:
                if fde[0] <= v < fde[1]:
                    lines.setdefault(loc_lines[slot_va][0], []).append(hex(v))
        require(35 in lines and 51 in lines, f'copy {fde[0]:#x} lacks read.rs:35/51 Locations')
        rec['read_rs_locations'] = {str(k): sorted(v) for k, v in sorted(lines.items())}
        copies.append(rec)
    copy_fdes = [img.fde(c['fde']) for c in COPIES]

    def owners(vas):
        return [next((hex(f[0]) for f in copy_fdes if f[0] <= v < f[1]), None) for v in vas]
    require(len(caps) == len(COPIES) and None not in owners(caps) and len(set(owners(caps))) == len(COPIES),
            f'chunk-cap census {len(caps)} does not match one site per copy')
    require(len(gates) == len(COPIES) and None not in owners(gates), f'gate census {len(gates)} does not match copies')
    for name in ('over_limit_desc', 'over_limit_len', 'progress_warn'):
        vas = census[LITERALS[name][0]]
        require(len(vas) == len(COPIES) and None not in owners(vas), f'{name} census {len(vas)} outside copies')
    helpers = {hex(s): check_header_helper(img, s, p) for s, p in HEADER_HELPERS.items()}
    eof_sites = census[LITERALS['early_eof'][0]]
    eof_rows = []
    for v in eof_sites:
        f = img.fde_of(v)
        require(f is not None, f'early-eof LEA {v:#x} outside every FDE')
        eof_rows.append({'lea': hex(v), 'fde': [hex(f[0]), hex(f[1])], **check_eof(img, v)})
    return {
        'target': TARGET,
        'captured_binary_executed': False,
        'census_scope': ('Every .text byte for the exact chunk-cap encoding, cmp rdi,4000000 and RIP-relative '
                         'LEAs to the over-limit, progress and early-eof literals and read.rs Location records; '
                         'not every TCP reader, decoder or caller.'),
        'census': {'chunk_cap_sites': [hex(v) for v in caps], 'gate_compares': [hex(v) for v in gates],
                   **{name: [hex(v) for v in census[LITERALS[name][0]]] for name in LITERALS},
                   'read_rs_location_records': {hex(s): {'line': l, 'col': c} for s, (l, c) in loc_lines.items()}},
        'copies': copies,
        'header_helpers': helpers,
        'early_eof_sites': eof_rows,
        'model': model_summary(),
    }


# ----------------------------------------------------------------- transcribed model

def admitted(length, max_len):
    """Observed: u32 length zero-extended, unsigned compare, equal admitted."""
    return 0 <= length <= 0xffffffff and length <= max_len


def compressed(flag):
    """Observed: cmp flag8,1; sete."""
    return flag & 0xff == 1


def chunk_plan(length):
    """Observed loop: chunk=min(remaining, CHUNK); offset+=chunk (saturating); WARN gate offset>=CHUNK; then remaining."""
    offset, plan = 0, []
    while length - offset > 0:
        chunk = min(length - offset, CHUNK)
        offset = min(offset + chunk, (1 << 64) - 1)
        plan.append((chunk, offset >= CHUNK))
    return plan


def reference_plan(length):
    """can1357 read.rs lead: log only while offset >= CHUNK and offset < total."""
    offset, plan = 0, []
    while length - offset > 0:
        chunk = min(length - offset, CHUNK)
        offset += chunk
        plan.append((chunk, CHUNK <= offset < length))
    return plan


MODEL_LENGTHS = (0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 2 * CHUNK - 1, 2 * CHUNK, 2 * CHUNK + 1, 0xffffffff)


def model_summary():
    rows = []
    for n in MODEL_LENGTHS:
        ours, ref = chunk_plan(n), reference_plan(n)
        rows.append({'length': n, 'chunks': len(ours), 'warn_points': sum(w for _, w in ours),
                     'reference_warn_points': sum(w for _, w in ref), 'chunk_sizes_equal': [c for c, _ in ours] == [c for c, _ in ref]})
    return {'lengths': rows,
            'differing_lengths': [r['length'] for r in rows if r['warn_points'] != r['reference_warn_points']],
            'flag_values_compressed': [f for f in range(256) if compressed(f)]}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--binary', type=Path, default=ROOT / TARGET)
    ap.add_argument('--out', type=Path)
    args = ap.parse_args(argv)
    identity = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files'] if i['path'] == TARGET)
    try:
        check(args.binary, identity)
        result = analyse(args.binary.read_bytes())
    except (EvidenceError, ValueError) as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1
    result['target_sha256'] = identity['sha256']
    text = json.dumps(result, indent=2, sort_keys=True) + '\n'
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / 'records.json').write_text(text)
    print(json.dumps({'copies': len(result['copies']), 'chunk_cap_sites': len(result['census']['chunk_cap_sites']),
                      'early_eof_sites': len(result['early_eof_sites']),
                      'model_differing_lengths': result['model']['differing_lengths']}, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
