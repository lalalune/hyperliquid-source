#!/usr/bin/env python3
"""l1-shared: extra-agent name length and count cap in node #94 (static, no execution).

Starts from the rodata message "Extra agent name must be between 1 and 16
characters long." and follows bytes only:

    message -> its one LEA -> the error Display arm -> enum tag(s) of that arm
    tag -> the one `mov word [r15], tag` store -> FDE of the save function
    save function -> name-length guard, error drop path, count-cap block
    GOT slot of the save function -> every caller -> tier derivation

For the guard it evaluates the decoded 64-bit arithmetic over its exact
admitted interval and boundary inputs.  For the cap it emulates the decoded
instructions for boundary tiers and compares them with the inferred formula
`3 + 2 * tier` (saturating, negative tier -> no cap).  For callers it decodes
the equity gate, divisor (from the multiply-high magic), clamp and offset.

    python3 tools/extra_agent_admission.py --out <dir>

writes evidence.json, callers.tsv and windows.txt.  Only the Python standard
library is used; the binary is read, never executed.
"""

import argparse
import bisect
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections  # noqa: E402

BINARY = 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
MESSAGE = b'Extra agent name must be between 1 and 16 characters long.'
U64 = 1 << 64
M64 = U64 - 1

# Error Display: `sub rsp,0x48; movzx eax,word [rdi]; lea rcx,[rip+T]; movsxd rax,[rcx+4*rax]; add rax,rcx; jmp rax`.
DISPLAY_HEAD = re.compile(rb'\x48\x83\xec\x48\x0f\xb7\x07\x48\x8d\x0d(?P<t>.{4})\x48\x63\x04\x81\x48\x01\xc8\xff\xe0', re.S)
# Display arm: `mov rdi,[rsi]; mov rax,[rsi+8]; mov rax,[rax+0x18]; lea rsi,[rip+msg]; mov edx,len; add rsp,0x48; jmp rax`.
DISPLAY_ARM = re.compile(rb'\x48\x8b\x3e\x48\x8b\x46\x08\x48\x8b\x40\x18\x48\x8d\x35(?P<msg>.{4})\xba(?P<len>.{4})'
                         rb'\x48\x83\xc4\x48\xff\xe0', re.S)
# Save-function entry: `mov [rsp+0x30],r9; mov rbp,r8; mov r15,rdi; mov r13,[r8+D]; lea rax,[r13+K]; cmp rax,C; ja/jae ok;`
# then the once-gate `mov eax,[rip+G]; test eax,eax; jne init` and the tag store `mov word [r15],TAG`.
GUARD = re.compile(rb'\x4c\x89\x4c\x24\x30\x4c\x89\xc5\x49\x89\xff\x4d\x8b\x68(?P<disp>.)'
                   rb'\x49\x8d\x45(?P<k>.)\x48\x83\xf8(?P<c>.)(?P<jcc>[\x77\x73])(?P<ok>.)'
                   rb'\x8b\x05(?P<once>.{4})\x85\xc0\x0f\x85(?P<init>.{4})'
                   rb'\x66\x41\xc7\x07(?P<tag>.{2})'
                   rb'\x48\x8b\x75\x00\x48\x85\xf6\x0f\x85(?P<drop>.{4})\xe9(?P<ret>.{4})', re.S)
# Drop path: `mov rdi,[rbp+8]; xor edx,edx; call [rip+slot]` then `mov rax,r15; add rsp,0xf8; pop*6; ret`.
DROP = re.compile(rb'\x48\x8b\x7d\x08\x31\xd2\xff\x15(?P<slot>.{4})\x4c\x89\xf8\x48\x81\xc4\xf8\x00\x00\x00'
                  rb'\x5b\x41\x5c\x41\x5d\x41\x5e\x41\x5f\x5d\xc3', re.S)
# Once init returns to the tag store: `... call [rip+X]; jmp store`.
ONCE_INIT = re.compile(rb'\x48\x8d\x3d(?P<once>.{4}).{19}\xbe\x01\x00\x00\x00\xff\x15.{4}\xe9(?P<back>.{4})', re.S)
# Sized free used by the drop path: `endbr64; cmp rsi,0x1000` (size argument in rsi).
SIZED_FREE_HEAD = bytes.fromhex('f30f1efa4881fe00100000')
# Existing extra agents: `mov rax,[rax+0x10]; imul rbx,rax,STRIDE; mov [rsp+0x58],rax; test rax,rax; je cap`
# and the name-match loop `add r12,STRIDE; cmp rbx,r12; je cap; cmp [rbp+r12+0x10],r13`.
COUNT = re.compile(rb'\x48\x8b\x40\x10\x48\x6b\xd8(?P<stride>.)\x48\x89\x44\x24\x58\x48\x85\xc0\x0f\x84(?P<empty>.{4})', re.S)
LOOP = re.compile(rb'\x49\x83\xc4(?P<stride>.)\x4c\x39\xe3\x0f\x84(?P<done>.{4})\x4e\x39\x6c\x25\x10', re.S)
# Cap: `mov rax,[rsp+0x30]; test rax,rax; js neg; add rax,rax; <2 reloads>; add rax,A; mov r14,-1; cmovae r14,rax`.
CAP = re.compile(rb'\x48\x8b\x44\x24\x30\x48\x85\xc0\x0f\x88(?P<neg>.{4})\x48\x01\xc0'
                 rb'(?P<reload>\x4c\x8b\x7c\x24\x48\x4c\x8b\x64\x24\x50)\x48\x83\xc0(?P<add>.)'
                 rb'\x49\xc7\xc6\xff\xff\xff\xff\x4c\x0f\x43\xf0', re.S)
# One bypass compare: 16 + 4 address bytes from rip against [r12]; `je skip_cap`.
BYPASS = re.compile(rb'\xf3\x0f\x6f\x05(?P<a>.{4})\xf3\x41\x0f\x6f\x0c\x24\x66\x0f\x74\xc8'
                    rb'\x66\x0f\x6e\x05(?P<b>.{4})\x66\x41\x0f\x6e\x54\x24\x10\x66\x0f\x74\xd0'
                    rb'\x66\x0f\xdb\xd1\x66\x0f\xd7\xc2\x3d\xff\xff\x00\x00\x74(?P<skip>.)', re.S)
CAP_CMP = re.compile(rb'\x4c\x39\x74\x24\x58\x0f\x83(?P<err>.{4})', re.S)
# Too-many error: once-gate, `mov word [r15],TAG; mov [r15+8],r14`.
CAP_ERR = re.compile(rb'\x8b\x05(?P<once>.{4})\x85\xc0\x0f\x85.{4}\x66\x41\xc7\x07(?P<tag>.{2})\x4d\x89\x77\x08', re.S)
NEG = re.compile(rb'\x48\xc7\xc0\xff\xff\xff\xff\xe9(?P<back>.{4})', re.S)
# Caller tier derivation (rel32 of the equity call masked):
# `call equity; ...; cmp rax,GATE; jae big; xor r9d,r9d; jmp join; <copy-out>;
#  big: movabs rcx,M; mul rcx; shr rdx,S; cmp rdx,CAP; mov r9d,CAP; cmovb r9,rdx; add r9,OFF`.
TIER = re.compile(rb'\x4c\x89\xff\x48\x8b\x5c\x24\x30\x48\x89\xde\xe8.{4}\x4c\x8b\x64\x24\x10\x0f\xb6\x6c\x24\x07'
                  rb'\x48\x3d(?P<gate>.{4})\x73(?P<big>.)\x45\x31\xc9\xe9.{4}'
                  rb'.{%d}'
                  rb'\x48\xb9(?P<magic>.{8})\x48\xf7\xe1\x48\xc1\xea(?P<shift>.)\x48\x83\xfa(?P<cap>.)'
                  rb'\x41\xb9(?P<cap2>.{4})\x4c\x0f\x42\xca\x49\x83\xc1(?P<off>.)', re.S)
TIER_GAP = 0x6d  # bytes between `jmp join` and the movabs (the error copy-out block), checked by `big`.
FIXED_TIER = bytes.fromhex('41b90a000000')  # mov r9d,0xa (the list-membership branch)
CALL_SITE = re.compile(rb'\x4c\x8d\x84\x24\xc0\x00\x00\x00\x48\x8b\xb4\x24\x20\x01\x00\x00\xff\x15(?P<slot>.{4})'
                       rb'\x66\x81\x7c\x24\x60(?P<ok>.{2})', re.S)


class EvidenceError(Exception):
    pass


def check_digest(data, expected=SHA256):
    got = hashlib.sha256(data).hexdigest()
    if got != expected:
        raise EvidenceError(f'sha256 mismatch: {got} != {expected}')
    return got


def s8(b):
    return struct.unpack('<b', b)[0]


def s32(b):
    return struct.unpack('<i', b)[0]


class Image:
    def __init__(self, data):
        self.data = data
        try:
            self.sec = {s['name']: s for s in sections(data)}
        except ValueError as exc:
            raise EvidenceError(str(exc)) from exc

    def off(self, va, size=1):
        for s in self.sec.values():
            if s['type'] != 8 and s['address'] and s['address'] <= va and va + size <= s['address'] + s['size']:
                return s['offset'] + va - s['address']
        raise EvidenceError(f'VA {va:#x} is outside every allocated section')

    def read(self, va, size):
        o = self.off(va, size)
        return self.data[o:o + size]

    def section(self, name):
        s = self.sec[name]
        return s['address'], self.data[s['offset']:s['offset'] + s['size']]


class Fdes:
    """Binary-search table from .eh_frame_hdr; pc ranges from each FDE (pcrel sdata4 only)."""

    def __init__(self, img):
        self.img = img
        hdr = img.sec['.eh_frame_hdr']['address']
        if tuple(img.read(hdr, 4)) != (1, 0x1b, 0x03, 0x3b):
            raise EvidenceError('unexpected .eh_frame_hdr encodings')
        count = struct.unpack('<I', img.read(hdr + 8, 4))[0]
        table = img.read(hdr + 12, count * 8)
        pairs = [struct.unpack_from('<ii', table, i * 8) for i in range(count)]
        self.starts = [hdr + a for a, _ in pairs]
        self.fde = [hdr + b for _, b in pairs]
        if any(b <= a for a, b in zip(self.starts, self.starts[1:])):
            raise EvidenceError('.eh_frame_hdr table not strictly increasing')
        self.count = count

    def range_of(self, va):
        k = bisect.bisect_right(self.starts, va) - 1
        if k < 0:
            raise EvidenceError(f'{va:#x} precedes every FDE')
        fde = self.fde[k]
        cie = fde + 4 - struct.unpack('<I', self.img.read(fde + 4, 4))[0]
        if self.img.read(cie + 8, 1) != b'\x01' or not self.img.read(cie + 9, 4).startswith(b'zR') \
                and not self.img.read(cie + 9, 4).startswith(b'zPLR'):
            raise EvidenceError(f'unsupported CIE at {cie:#x}')
        begin = fde + 8 + s32(self.img.read(fde + 8, 4))
        length = struct.unpack('<I', self.img.read(fde + 12, 4))[0]
        if begin != self.starts[k]:
            raise EvidenceError(f'FDE {fde:#x} pc_begin disagrees with .eh_frame_hdr')
        if not begin <= va < begin + length:
            raise EvidenceError(f'{va:#x} is outside FDE [{begin:#x},{begin + length:#x})')
        return begin, begin + length, fde


def one(pattern, buf, what):
    hits = list(pattern.finditer(buf))
    if len(hits) != 1:
        raise EvidenceError(f'expected exactly one {what}, found {len(hits)}')
    return hits[0]


def rip(base_va, m, group, insn_end):
    """Target of a rip-relative disp32 captured by `group`; insn_end is the match-relative end of its instruction."""
    return base_va + m.start() + insn_end + s32(m.group(group))


def lea_refs(text_va, text, target):
    out = []
    for m in re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', text):
        if text_va + m.start() + 7 + s32(text[m.start() + 3:m.start() + 7]) == target:
            out.append(text_va + m.start())
    return out


def word_stores(text_va, text, tag):
    """`mov word [base(+disp)], imm16` (66 [REX.B] C7 /0) storing exactly `tag`."""
    imm, out = struct.pack('<H', tag), []
    for m in re.finditer(rb'\x66[\x41\x43]?\xc7', text):
        i = m.end()
        modrm = text[i]
        mod, reg, rm = modrm >> 6, (modrm >> 3) & 7, modrm & 7
        if reg or mod == 3:
            continue
        j = i + 1 + (rm == 4) + {0: 4 if rm == 5 else 0, 1: 1, 2: 4}[mod]
        if text[j:j + 2] == imm:
            out.append(text_va + m.start())
    return out


def got_slots(img, target):
    """r_offset of every R_X86_64_RELATIVE in .rela.dyn whose addend is `target`."""
    _, rela = img.section('.rela.dyn')
    if len(rela) % 24:
        raise EvidenceError('truncated .rela.dyn')
    return [o for o, info, add in struct.iter_unpack('<QQq', rela) if info == 8 and add == target]


def reloc_addend(img, slot):
    _, rela = img.section('.rela.dyn')
    got = [add for o, info, add in struct.iter_unpack('<QQq', rela) if o == slot and info == 8]
    if len(got) != 1:
        raise EvidenceError(f'no single RELATIVE relocation at {slot:#x}')
    return got[0]


def indirect_calls(text_va, text, slot):
    return [text_va + m.start() for m in re.finditer(rb'\xff\x15', text)
            if text_va + m.start() + 6 + s32(text[m.start() + 2:m.start() + 6]) == slot]


def guard_interval(k, c, jcc):
    """Admitted n for `lea rax,[n+k]; cmp rax,c; ja|jae` as one interval [lo, hi] mod 2^64 (k, c sign-extended)."""
    k, c = k & M64, c & M64
    first = c + 1 if jcc == 'ja' else c
    if first > M64:
        return None
    return (first - k) & M64, (M64 - k) & M64


def guard_admits(n, k, c, jcc):
    v = (n + k) & M64
    return v > (c & M64) if jcc == 'ja' else v >= (c & M64)


def cap_limit(tier, add):
    """Emulate the decoded cap block for a signed 64-bit tier."""
    if tier < 0:
        rax = M64                          # js -> mov rax,-1 -> rejoins after `add rax,rax`
    else:
        rax = (tier * 2) & M64             # add rax,rax
    total = rax + add                      # add rax,imm8 (CF = carry out)
    return M64 if total > M64 else total   # mov r14,-1; cmovae r14,rax


def reference_limit(tier, base=3):
    return M64 if tier < 0 else min(M64, base + min(M64, tier * 2))


def divisor_from_magic(magic, shift):
    """Exact d with floor(x*magic / 2^(64+shift)) == floor(x/d) for every u64 x, or None."""
    s = 64 + shift
    d = round((1 << s) / magic)
    if d <= 0:
        return None
    err = magic * d - (1 << s)
    # Granlund-Montgomery: 0 <= err and err * (2^64 - 1) < 2^s is sufficient for all x < 2^64.
    return d if 0 <= err and err * M64 < (1 << s) else None


def tier_of(equity, gate, d, cap, off):
    return 0 if equity < gate else off + min(equity // d, cap)


def analyse(data, skip_digest=False):
    """skip_digest lets corruption controls reach the structural checks; the CLI never sets it."""
    digest = hashlib.sha256(data).hexdigest() if skip_digest else check_digest(data)
    img = Image(data)
    fdes = Fdes(img)
    ro_va, ro = img.section('.rodata')
    text_va, text = img.section('.text')
    first = ro.find(MESSAGE)
    if first == -1 or ro.find(MESSAGE, first + 1) != -1:
        raise EvidenceError('expected exactly one message in .rodata')
    msg_va = ro_va + first
    leas = lea_refs(text_va, text, msg_va)
    if len(leas) != 1:
        raise EvidenceError(f'expected one LEA of the message, found {len(leas)}')

    # Display arm -> tag.
    d_lo, d_hi, d_fde = fdes.range_of(leas[0])
    disp_fn = img.read(d_lo, d_hi - d_lo)
    head = DISPLAY_HEAD.match(disp_fn)
    if not head:
        raise EvidenceError('Display function head does not decode as a u16 jump table')
    table_va = d_lo + 14 + s32(head.group('t'))
    entries = []
    while True:
        tgt = table_va + s32(img.read(table_va + 4 * len(entries), 4))
        if not d_lo <= tgt < d_hi:
            break
        entries.append(tgt)
    arm = max(t for t in set(entries) if t <= leas[0])
    tags = [i for i, t in enumerate(entries) if t == arm]
    arm_m = DISPLAY_ARM.match(disp_fn, arm - d_lo)
    if not arm_m or rip(d_lo, arm_m, 'msg', 18) != msg_va:
        raise EvidenceError('Display arm does not write the message')
    arm_len = struct.unpack('<I', arm_m.group('len'))[0]
    if len(tags) != 1:
        raise EvidenceError(f'message arm serves {len(tags)} tags')
    tag = tags[0]

    # Tag store -> save function -> guard.
    stores = word_stores(text_va, text, tag)
    if len(stores) != 1:
        raise EvidenceError(f'expected one store of tag {tag}, found {len(stores)}')
    s_lo, s_hi, s_fde = fdes.range_of(stores[0])
    fn = img.read(s_lo, s_hi - s_lo)
    g = one(GUARD, fn, 'name-length guard')
    jcc = 'ja' if g.group('jcc') == b'\x77' else 'jae'
    k, c = s8(g.group('k')), s8(g.group('c'))
    g_va = s_lo + g.start()
    lea_va = g_va + 15
    store_va = g_va + g.start('tag') - g.start() - 4
    if store_va != stores[0] or struct.unpack('<H', g.group('tag'))[0] != tag:
        raise EvidenceError('guard fall-through does not reach the tag store')
    interval = guard_interval(k, c, jcc)
    ok_va = lea_va + 10 + s8(g.group('ok'))
    once_va = rip(s_lo, g, 'once', g.start('once') - g.start() + 4)
    init_va = rip(s_lo, g, 'init', g.start('init') - g.start() + 4)
    drop_va = rip(s_lo, g, 'drop', g.start('drop') - g.start() + 4)
    ret_va = rip(s_lo, g, 'ret', g.start('ret') - g.start() + 4)
    init = ONCE_INIT.match(fn, init_va - s_lo + 0x1c)
    if not init or rip(s_lo, init, 'once', 7) != once_va or rip(s_lo, init, 'back', init.end() - init.start()) != store_va:
        raise EvidenceError('once-init path does not return to the tag store')
    drop = DROP.match(fn, drop_va - s_lo)
    if not drop or drop_va + 12 != ret_va:
        raise EvidenceError('error path does not free [r8+8] with size [r8] and return')
    free_slot = rip(s_lo, drop, 'slot', 12)
    free_fn = reloc_addend(img, free_slot)
    if img.read(free_fn, len(SIZED_FREE_HEAD)) != SIZED_FREE_HEAD:
        raise EvidenceError('drop callee is not the sized-free fast path')

    # Count cap.
    cnt = one(COUNT, fn, 'extra-agent count load')
    loop = one(LOOP, fn, 'name-match loop')
    cap = one(CAP, fn, 'cap block')
    cap_va = s_lo + cap.start()
    empty_va = rip(s_lo, cnt, 'empty', cnt.end() - cnt.start())
    done_va = rip(s_lo, loop, 'done', 13)
    neg = NEG.match(fn, rip(s_lo, cap, 'neg', 14) - s_lo)
    rejoin = rip(s_lo, neg, 'back', 12) if neg else None
    add = cap.group('add')[0]
    bypass, pos = [], cap.end()
    for _ in range(3):
        b = BYPASS.match(fn, pos)
        if not b:
            raise EvidenceError('expected three bypass address compares after the cap block')
        a_va, b_va = rip(s_lo, b, 'a', 8), rip(s_lo, b, 'b', 26)
        if b_va != a_va + 16:
            raise EvidenceError('bypass address halves are not contiguous')
        bypass.append({'va': hex(a_va), 'address': '0x' + img.read(a_va, 20).hex(),
                       'skip_va': hex(s_lo + b.end() + s8(b.group('skip')))})
        pos = b.end()
    cmp_m = CAP_CMP.match(fn, pos)
    if not cmp_m:
        raise EvidenceError('cap compare does not follow the bypass compares')
    skip_va = s_lo + cmp_m.end()
    err_va = rip(s_lo, cmp_m, 'err', 11)
    err = CAP_ERR.match(fn, err_va - s_lo)
    if not err:
        raise EvidenceError('cap error block does not decode')
    cap_tag = struct.unpack('<H', err.group('tag'))[0]
    tiers = [-(1 << 63), -1, 0, 1, 10, 50, (1 << 62), (1 << 63) - 2, (1 << 63) - 1]
    limits = {str(t): cap_limit(t, add) for t in tiers}

    # Callers through the GOT slot.
    slots = got_slots(img, s_lo)
    calls = [(slot, va) for slot in slots for va in indirect_calls(text_va, text, slot)]
    callers = []
    tier_re = re.compile(TIER.pattern % TIER_GAP, re.S)
    for slot, call_va in calls:
        c_lo, c_hi, c_fde = fdes.range_of(call_va)
        cf = img.read(c_lo, c_hi - c_lo)
        site = CALL_SITE.match(cf, call_va - c_lo - 16)
        t = one(tier_re, cf, f'tier derivation in {c_lo:#x}')
        magic, shift = struct.unpack('<Q', t.group('magic'))[0], t.group('shift')[0]
        cap1, cap2 = t.group('cap')[0], struct.unpack('<I', t.group('cap2'))[0]
        callers.append({
            'call_va': hex(call_va), 'got_slot': hex(slot), 'fn_start': hex(c_lo), 'fn_end': hex(c_hi),
            'fn_fde': hex(c_fde), 'r8_is_rsp_0xc0': bool(site),
            'ok_tag': struct.unpack('<H', site.group('ok'))[0] if site else None,
            'tier_va': hex(c_lo + t.start()), 'tier_len': t.end() - t.start(), 'equity_gate': struct.unpack('<I', t.group('gate'))[0],
            'big_branch_lands_on_movabs': c_lo + t.start() + 34 + s8(t.group('big')) == c_lo + t.start('magic') - 2,
            'magic': hex(magic), 'shift': 64 + shift, 'divisor': divisor_from_magic(magic, shift),
            'clamp': cap1 if cap1 == cap2 else None, 'offset': t.group('off')[0],
            'fixed_tier_10_stores': cf.count(FIXED_TIER),
        })
    forms = {json.dumps({k: v for k, v in c.items() if k in ('equity_gate', 'divisor', 'clamp', 'offset', 'ok_tag')},
                        sort_keys=True) for c in callers}

    result = {
        'task': 'l1-shared', 'question': 'extra-agent name length and count cap',
        'binary': BINARY, 'sha256': digest, 'coordinates': 'virtual addresses (ELF VA)',
        'fde_table_entries': fdes.count,
        'message': {'va': hex(msg_va), 'text': MESSAGE.decode(), 'length': len(MESSAGE), 'lea_va': hex(leas[0])},
        'display': {'fn_start': hex(d_lo), 'fn_end': hex(d_hi), 'fn_fde': hex(d_fde), 'table_va': hex(table_va),
                    'table_entries': len(entries), 'arm_va': hex(arm), 'arm_tags': tags, 'arm_length_imm': arm_len},
        'save_fn': {'start': hex(s_lo), 'end': hex(s_hi), 'fde': hex(s_fde), 'size': s_hi - s_lo},
        'name_guard': {
            'entry_va': hex(g_va), 'lea_va': hex(lea_va), 'input':f"r13 = [r8+{g.group('disp')[0]:#x}]", 'k': k, 'c': c, 'jcc': jcc,
            'ok_target_va': hex(ok_va), 'tag_store_va': hex(store_va), 'tag': tag,
            'admitted_interval': list(interval) if interval else None,
            'boundary': {str(n): guard_admits(n, k, c, jcc) for n in (0, 1, 16, 17, M64)},
            'once_gate_va': hex(once_va), 'once_init_returns_to_store': True,
            'error_drop': {'va': hex(drop_va), 'free_got_slot': hex(free_slot), 'free_fn': hex(free_fn),
                           'size_arg': '[r8]', 'ptr_arg': '[r8+8]'},
        },
        'count_cap': {
            'count_va': hex(s_lo + cnt.start()), 'record_stride': cnt.group('stride')[0],
            'loop_stride': loop.group('stride')[0], 'empty_exit_va': hex(empty_va), 'loop_exit_va': hex(done_va),
            'cap_va': hex(cap_va), 'negative_tier_rejoin_va': hex(rejoin) if rejoin else None,
            'rejoin_after_doubling': rejoin == cap_va + 17, 'add_imm': add, 'bypass': bypass,
            'bypass_skip_target_va': hex(skip_va), 'error_va': hex(err_va), 'error_tag': cap_tag,
            'limits': limits, 'matches_reference_formula': all(cap_limit(t, add) == reference_limit(t) for t in tiers),
        },
        'callers': callers,
        'summary': {
            'message_leas': len(leas), 'arm_tags': tags, 'display_entries': len(entries),
            'tag_stores': len(stores), 'admitted_name_bytes': list(interval) if interval else None,
            'cap_base': cap_limit(0, add), 'cap_per_tier': cap_limit(1, add) - cap_limit(0, add),
            'cap_error_tag': cap_tag, 'bypass_addresses': len(bypass),
            'cap_matches_reference_formula': all(cap_limit(t, add) == reference_limit(t) for t in tiers),
            'got_slots': len(slots), 'callers': len(callers), 'caller_forms': len(forms),
            'callers_ok_tag_equals_display_entries': sum(1 for c in callers if c['ok_tag'] == len(entries)),
            'equity_gate': callers[0]['equity_gate'] if callers else None,
            'tier_divisor': callers[0]['divisor'] if callers else None,
            'tier_clamp': callers[0]['clamp'] if callers else None,
            'tier_offset': callers[0]['offset'] if callers else None,
        },
    }
    windows = [('display head', d_lo, 23), ('display arm', arm, arm_m.end() - arm_m.start()),
               ('name guard', g_va, g.end() - g.start()), ('error drop', drop_va, drop.end() - drop.start()),
               ('sized free head', free_fn, len(SIZED_FREE_HEAD)),
               ('count load', s_lo + cnt.start(), cnt.end() - cnt.start()),
               ('cap block', cap_va, cmp_m.end() + s_lo - cap_va), ('cap error', err_va, err.end() - err.start()),
               ('negative tier', rip(s_lo, cap, 'neg', 14), 12)]
    windows += [(f"tier {c['fn_start']}", int(c['tier_va'], 16), c['tier_len']) for c in callers]
    return result, [(name, va, img.read(va, n)) for name, va, n in windows]


def write(out, result, windows):
    out.mkdir(parents=True, exist_ok=True)
    (out / 'evidence.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    cols = ['call_va', 'got_slot', 'fn_start', 'fn_end', 'tier_va', 'equity_gate', 'magic', 'shift', 'divisor',
            'clamp', 'offset', 'fixed_tier_10_stores', 'ok_tag', 'r8_is_rsp_0xc0', 'big_branch_lands_on_movabs']
    rows = ['\t'.join(cols)] + ['\t'.join(str(c[k]) for k in cols) for c in result['callers']]
    (out / 'callers.tsv').write_text('\n'.join(rows) + '\n')
    lines = []
    for name, va, raw in windows:
        lines.append(f'# {name} {va:#x}..{va + len(raw):#x}')
        lines += [f'{va + i:x}: {raw[i:i + 16].hex(" ")}' for i in range(0, len(raw), 16)]
        lines.append('')
    (out / 'windows.txt').write_text('\n'.join(lines))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--out', required=True, type=Path)
    ap.add_argument('--binary', type=Path, default=ROOT / BINARY)
    args = ap.parse_args(argv)
    try:
        result, windows = analyse(args.binary.read_bytes())
    except EvidenceError as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1
    write(args.out, result, windows)
    print(json.dumps(result['summary'], sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
