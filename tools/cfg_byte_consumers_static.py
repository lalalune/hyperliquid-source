#!/usr/bin/env python3
"""RE-005: who consumes the cfg bytes +0xa/+0xb on the driver-build path?

Question (the open edge the tag-3 supply packet #2950 left, in its
own words: "cfg+0xa/+0xb are assembled but never read by the
ctor"). The runtime builder 0x5cf9600 assembles a 16-byte config
on its own stack and hands it to driver_ctor 0x5ce01f0 at two call
sites. Who reads the bytes at +0xa/+0xb of that config, and what
do they decide?

Answer. Nobody reads them, and they decide nothing.

The builder receives the runtime config built by cfg_ctor
0x5cf93f0 (bcfg here) and assembles the ctor config (dcfg) at
rsp+0x70 (call site 1, 0x5cf9669) and rsp+0x730 (call site 2,
0x5cf96eb) as:

  dcfg+0x00  qword  = [bcfg+0x60]
  dcfg+0x08  byte   = [bcfg+0xe5]   (variant)
  dcfg+0x09  byte   = [bcfg+0xe6]   (tag)
  dcfg+0x0a  byte   = 1 at site 1; [bcfg+0xe4] ^ 1 at site 2
  dcfg+0x0b  byte   = [bcfg+0xe7]

driver_ctor reads exactly three dcfg fields — the +0x00 qword
(forwarded as Poll::new 0x5ceeae0's second argument), the +0x08
byte (its entry variant branch) and the +0x09 byte (compared
against 1 in the install sequence, the flag #2948 showed
selecting the base pair). No access at any width in the ctor
covers +0xa or +0xb, and the dcfg pointer never escapes: it is
not passed to any callee and not stored anywhere in the ctor.

The reachable values are closed by the wrappers. bcfg+0xe4 is
cfg_ctor's second argument, fixed to 1, 0, 1 at the three
wrapper call sites (wrapper A 0x15d7007 / 0x15d70a3, wrapper B
0x2ae16d1), and ctor call site 2 is entered only when it is 1,
so dcfg+0xa is 1 at site 1 and 0 at site 2 — uniformly NOT
[bcfg+0xe4]. bcfg+0xe7 is 0: cfg_ctor stores a zero dword at
+0xe5 (covering +0xe7) and the wrapper overwrite is a two-byte
store at +0xe5..+0xe6 only, so dcfg+0xb is 0 at both sites.
Both bytes are dead on every path the artifact can build.

The received config's own +0xa/+0xb bytes (inside the qword
slot [bcfg+0x8]) have exactly one covering access in the
artifact: the builder's fast-path qword load at 0x5cf962d,
gated on [bcfg+0xe4] == 1 and [bcfg+0x0] == 1. cfg_ctor never
writes the +0x8 slot and always writes [bcfg+0x0] = 0, so
that arm — the one #2950 recorded as not supplied by the
artifact's own config constructor — is unreachable for every
config the artifact builds, and the two bytes are never even
loaded. The other bcfg consumers make no covering access
either: the pair helper 0x5cf3d00 (called by the builder with
bcfg at 0x5cf9798 / 0x5cf99f3) and the cfg drop body
0x5cf1af0 (called by wrapper A at 0x15d7034) are censused in
full in records.json. After the drop call the wrappers reuse
the bcfg stack slot for unrelated values; those later stores
are recorded separately and cannot reach the build.
"""

import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
PACKET = ROOT / 'research/work-items/RE-005-node115-cfg-byte-consumers'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SIZE = 105896032

BODIES = {
    'driver_ctor': (0x5ce01f0, 0x5ce084b),
    'builder': (0x5cf9600, 0x5cfa8b1),
    'cfg_ctor': (0x5cf93f0, 0x5cf959f),
    'builder_precall': (0x5cf5db0, 0x5cf60af),
    'pair_helper': (0x5cf3d00, 0x5cf3fd1),
    'cfg_drop': (0x5cf1af0, 0x5cf1cd2),
    'wrapper_a': (0x15d6fd0, 0x15d8447),
    'wrapper_b': (0x2ae1690, 0x2ae27b2),
}

# Body digests already published by the tag-3 supply packet
# (#2950); this packet re-derives them and cross-pins the overlap.
PRIOR_PINS = {
    'driver_ctor': '90919826d6842d84b3b1229420978c82d49b767f5c609650b17c3785a73e0cba',
    'builder': '12813161d76cb5aa11039d12cbbf45d6f170b2aa53da586df8e03b579e02d13b',
    'cfg_ctor': '9736d15280792f960bb0b52a53ff015185c0ac78b5f3a7f4daaf0387ead23680',
    'builder_precall': '59b3791ae5ccc42304f0f0c45734387c46d1f782722f398cef3bb146abb9d3f0',
    'wrapper_a': '0a33a4e33944ad1377a8544831780bcc081401ce3f7d5e86c33606c88ff44d8c',
    'wrapper_b': '6ca0595c13836bca0cb0173bd591a09d6da6791532e23a5a71c63715380727d9',
}

DRIVER_CTOR = 0x5ce01f0
BUILDER = 0x5cf9600
CFG_CTOR = 0x5cf93f0
PRECALL = 0x5cf5db0
PAIR_HELPER = 0x5cf3d00
CFG_DROP = 0x5cf1af0

EXCERPTS = {
    'builder_head': (0x5cf9600, 0x5cf9715),
    'driver_ctor_head': (0x5ce01f0, 0x5ce0332),
    'driver_ctor_install': (0x5ce0332, 0x5ce04b0),
    'cfg_ctor': (0x5cf93f0, 0x5cf959f),
    'wrapper_a_head': (0x15d6fd0, 0x15d7130),
    'wrapper_b_head': (0x2ae1690, 0x2ae1710),
    'pair_helper_head': (0x5cf3d00, 0x5cf3e30),
    'cfg_drop': (0x5cf1af0, 0x5cf1cd2),
}

LINE = re.compile(
    r'^\s*([0-9a-f]+):\t((?:[0-9a-f]{2} )+|[0-9a-f]+ )\s*\t(.*)$')
MEM = re.compile(r'(-?0x[0-9a-f]+)?\((%[a-z0-9]+)\)')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def segments(data):
    require(data[:4] == b'\x7fELF', 'target is not ELF')
    phoff = struct.unpack_from('<Q', data, 0x20)[0]
    phentsize = struct.unpack_from('<H', data, 0x36)[0]
    phnum = struct.unpack_from('<H', data, 0x38)[0]
    segs = []
    for i in range(phnum):
        off = phoff + i * phentsize
        p_type = struct.unpack_from('<I', data, off)[0]
        if p_type != 1:
            continue
        p_offset, p_vaddr, _p, p_filesz = struct.unpack_from(
            '<QQQQ', data, off + 8)
        segs.append((p_vaddr, p_offset, p_filesz))
    return segs


def read(data, segs, va, n):
    for vaddr, offset, filesz in segs:
        if vaddr <= va < vaddr + filesz:
            return data[offset + va - vaddr: offset + va - vaddr + n]
    raise ValueError('unmapped va %#x' % va)


def disasm(path, start, end):
    out = subprocess.check_output(
        ['objdump', '-d', '--start-address=%#x' % start,
         '--stop-address=%#x' % end, str(path)], text=True)
    insns = []
    for line in out.splitlines():
        m = LINE.match(line)
        if m:
            text = ' '.join(m.group(3).split())
            insns.append((int(m.group(1), 16), text))
    return insns


def reg_width(reg):
    if reg.startswith('xmm'):
        return 16
    if re.fullmatch(r'r\d+', reg):
        return 8
    if re.fullmatch(r'r\d+d', reg):
        return 4
    if re.fullmatch(r'r\d+w', reg):
        return 2
    if re.fullmatch(r'r\d+b', reg):
        return 1
    return {
        'rax': 8, 'rbx': 8, 'rcx': 8, 'rdx': 8, 'rsi': 8, 'rdi': 8,
        'rbp': 8, 'rsp': 8,
        'eax': 4, 'ebx': 4, 'ecx': 4, 'edx': 4, 'esi': 4, 'edi': 4,
        'ebp': 4, 'esp': 4,
        'ax': 2, 'bx': 2, 'cx': 2, 'dx': 2, 'si': 2, 'di': 2,
        'bp': 2, 'sp': 2,
        'al': 1, 'bl': 1, 'cl': 1, 'dl': 1, 'sil': 1, 'dil': 1,
        'bpl': 1, 'spl': 1,
    }.get(reg)


def width_of(text, mem_span):
    mnem = text.split()[0]
    if mnem in ('movups', 'movaps', 'movdqa', 'movdqu'):
        return 16
    if mnem.startswith(('movzbl', 'movsbl')):
        return 1
    if mnem.startswith(('movzwl', 'movswl')):
        return 2
    rest = text[:mem_span[0]] + text[mem_span[1]:]
    regs = re.findall(r'%([a-z0-9]+)', rest)
    widths = [reg_width(r) for r in regs]
    widths = [w for w in widths if w]
    if widths:
        return widths[0]
    if mnem.endswith('b'):
        return 1
    if mnem.endswith('w'):
        return 2
    if mnem.endswith('l'):
        return 4
    if mnem.endswith('q'):
        return 8
    return None


def kind_of(text, mem_is_last):
    mnem = text.split()[0]
    if mnem.startswith(('cmp', 'test')):
        return 'compare'
    if mnem == 'lea':
        return 'address'
    if text.startswith('lock'):
        return 'readwrite'
    return 'store' if mem_is_last else 'load'


def accesses(insns, bases, maxva=None, minva=None):
    """All memory accesses through the given base registers."""
    rows = []
    for va, text in insns:
        if maxva is not None and va > maxva:
            continue
        if minva is not None and va < minva:
            continue
        for m in MEM.finditer(text):
            base = m.group(2)
            if base not in bases or base == '%rip':
                continue
            disp = int(m.group(1), 16) if m.group(1) else 0
            tail = text[m.end():].strip()
            mem_is_last = not tail.startswith(',')
            rows.append({
                'va': hex(va),
                'disp': hex(disp),
                'width': width_of(text, m.span()),
                'kind': kind_of(text, mem_is_last),
                'text': text,
            })
    return rows


def covering(rows, lo, hi):
    out = []
    for r in rows:
        d = int(r['disp'], 16)
        w = r['width'] or 0
        if d < hi and d + w > lo:
            out.append(r)
    return out


def insn_at(insns, va):
    for v, text in insns:
        if v == va:
            return text
    raise ValueError('no instruction at %#x' % va)


def pin(insns, va, expected, message):
    text = insn_at(insns, va)
    require(text == expected,
            '%s (at %#x: %r != %r)' % (message, va, text, expected))


def pin_prefix(insns, va, prefix, message):
    text = insn_at(insns, va)
    require(text.startswith(prefix),
            '%s (at %#x: %r does not start with %r)'
            % (message, va, text, prefix))


def census_tuples(rows):
    return [(r['va'], r['disp'], r['width'], r['kind']) for r in rows]


def analyze(data):
    require(len(data) == SIZE, 'target size is not the pinned size')
    segs = segments(data)
    with tempfile.NamedTemporaryFile(suffix='.bin') as tmp:
        tmp.write(data)
        tmp.flush()
        path = tmp.name
        asm = {role: disasm(path, a, b)
               for role, (a, b) in BODIES.items()}

    bodies = {}
    for role, (a, b) in BODIES.items():
        raw = read(data, segs, a, b - a)
        bodies[role] = {
            'start': hex(a), 'end': hex(b), 'bytes': b - a,
            'sha256': hashlib.sha256(raw).hexdigest(),
        }

    ctor = asm['driver_ctor']
    builder = asm['builder']
    cfg_ctor = asm['cfg_ctor']
    helper = asm['pair_helper']
    drop = asm['cfg_drop']
    wrap_a = asm['wrapper_a']
    wrap_b = asm['wrapper_b']

    # --- driver_ctor: the complete cfg-access census -------------
    ctor_rows = accesses(ctor, {'%r12'})
    ctor_rows += [r for r in accesses(ctor, {'%rsi'})
                  if int(r['va'], 16) <= 0x5ce0211]
    ctor_rows.sort(key=lambda r: int(r['va'], 16))
    require(census_tuples(ctor_rows) == [
        ('0x5ce0207', '0x8', 1, 'compare'),
        ('0x5ce0211', '0x0', 8, 'load'),
        ('0x5ce03f6', '0x9', 1, 'compare'),
    ], 'driver_ctor cfg-access census is exactly the three pinned '
       'accesses (+0x0 qword, +0x8 byte, +0x9 byte)')
    require(not covering(ctor_rows, 0xa, 0xc),
            'driver_ctor has no access covering cfg +0xa/+0xb')
    pin(ctor, 0x5ce0201, 'mov %rsi,%r12',
        'driver_ctor keeps the cfg pointer in r12')
    for va, text in ctor:
        require(not re.match(r'mov\w*\s+%r12\w*,', text),
                'driver_ctor never moves the cfg pointer into '
                'another register (escape) at %#x' % va)

    # --- builder: assembly of the ctor config --------------------
    pin(builder, 0x5cf961e, 'cmpb $0x1,0xe4(%rsi)',
        'builder entry compares [bcfg+0xe4] against 1')
    pin(builder, 0x5cf9627, 'cmpl $0x1,(%r14)',
        'fast path is gated on [bcfg+0x0] == 1')
    pin(builder, 0x5cf962d, 'mov 0x8(%r14),%r13',
        'fast path loads the [bcfg+0x8] qword')
    pin(builder, 0x5cf9631, 'xor %eax,%eax',
        'fast path enters the shared tail with the flag byte 0')
    # site 1 (dcfg at rsp+0x70)
    pin(builder, 0x5cf9635, 'movzwl 0xe5(%r14),%eax',
        'site 1 loads the [bcfg+0xe5] u16')
    pin(builder, 0x5cf963d, 'movzbl 0xe7(%r14),%ecx',
        'site 1 loads the [bcfg+0xe7] byte')
    pin(builder, 0x5cf9645, 'mov 0x60(%r14),%rdx',
        'site 1 loads [bcfg+0x60]')
    pin(builder, 0x5cf9649, 'mov %ax,0x78(%rsp)',
        'site 1 stores the u16 at dcfg+0x8')
    pin(builder, 0x5cf964e, 'movb $0x1,0x7a(%rsp)',
        'site 1 dcfg+0xa store is the immediate 1')
    pin(builder, 0x5cf9653, 'mov %cl,0x7b(%rsp)',
        'site 1 stores [bcfg+0xe7] at dcfg+0xb')
    pin(builder, 0x5cf9657, 'mov %rdx,0x70(%rsp)',
        'site 1 stores [bcfg+0x60] at dcfg+0x0')
    pin(builder, 0x5cf965c, 'lea 0x400(%rsp),%rdi',
        'site 1 passes the result slot as ctor arg 1')
    pin(builder, 0x5cf9664, 'lea 0x70(%rsp),%rsi',
        'site 1 passes dcfg as ctor arg 2')
    pin_prefix(builder, 0x5cf9669, 'call 5ce01f0',
               'site 1 calls driver_ctor')
    # site 2 (dcfg at rsp+0x730)
    pin_prefix(builder, 0x5cf9697, 'call 5cf5db0',
               'the non-fast path calls builder_precall')
    pin(builder, 0x5cf969f, 'movzbl 0xe4(%r14),%eax',
        'site 2 reloads [bcfg+0xe4]')
    pin(builder, 0x5cf96a7, 'xor $0x1,%al',
        'site 2 inverts the [bcfg+0xe4] byte')
    pin(builder, 0x5cf96a9, 'movzwl 0xe5(%r14),%ecx',
        'site 2 loads the [bcfg+0xe5] u16')
    pin(builder, 0x5cf96b1, 'movzbl 0xe7(%r14),%edx',
        'site 2 loads the [bcfg+0xe7] byte')
    pin(builder, 0x5cf96b9, 'mov 0x60(%r14),%rsi',
        'site 2 loads [bcfg+0x60]')
    pin(builder, 0x5cf96bd, 'mov %cx,0x738(%rsp)',
        'site 2 stores the u16 at dcfg+0x8')
    pin(builder, 0x5cf96c5, 'mov %al,0x73a(%rsp)',
        'site 2 stores the inverted flag at dcfg+0xa')
    pin(builder, 0x5cf96cc, 'mov %dl,0x73b(%rsp)',
        'site 2 stores [bcfg+0xe7] at dcfg+0xb')
    pin(builder, 0x5cf96d3, 'mov %rsi,0x730(%rsp)',
        'site 2 stores [bcfg+0x60] at dcfg+0x0')
    pin(builder, 0x5cf96db, 'lea 0x400(%rsp),%rdi',
        'site 2 passes the result slot as ctor arg 1')
    pin(builder, 0x5cf96e3, 'lea 0x730(%rsp),%rsi',
        'site 2 passes dcfg as ctor arg 2')
    pin_prefix(builder, 0x5cf96eb, 'call 5ce01f0',
               'site 2 calls driver_ctor')
    # no other stores land in either dcfg extent before its call
    for lo, hi, callva in ((0x70, 0x7c, 0x5cf9669),
                           (0x730, 0x73c, 0x5cf96eb)):
        rows = [r for r in accesses(builder, {'%rsp'})
                if lo <= int(r['disp'], 16) < hi
                and int(r['va'], 16) < callva]
        stores = sorted(int(r['disp'], 16) for r in rows
                        if r['kind'] == 'store')
        require(stores == [lo, lo + 8, lo + 0xa, lo + 0xb],
                'dcfg extent %#x is written by exactly the four '
                'pinned stores' % lo)
    # bcfg census while r14 holds it (until the reload at 0x5cf9bc6)
    bcfg_rows = accesses(builder, {'%r14'}, maxva=0x5cf9bc6)
    bcfg_rows += [r for r in accesses(builder, {'%rsi'})
                  if int(r['va'], 16) < 0x5cf9635]
    bcfg_rows.sort(key=lambda r: int(r['va'], 16))
    require([r['va'] for r in covering(bcfg_rows, 0x8, 0xc)]
            == ['0x5cf962d'],
            'the only builder access covering [bcfg+0x8] is the '
            'fast-path qword load')
    require([r['va'] for r in covering(bcfg_rows, 0xa, 0xc)]
            == ['0x5cf962d'],
            'the only builder access covering [bcfg+0xa] is the '
            'fast-path qword load')
    pin(builder, 0x5cf9bc6, 'mov 0x28(%r14),%r14',
        'r14 stops holding bcfg at the pinned reload')
    pin(builder, 0x5cf9795, 'mov %r14,%rdi',
        'pair helper call 1 receives bcfg')
    pin_prefix(builder, 0x5cf9798, 'call 5cf3d00',
               'pair helper call 1 target')
    pin(builder, 0x5cf99f0, 'mov %r14,%rdi',
        'pair helper call 2 receives bcfg')
    pin_prefix(builder, 0x5cf99f3, 'call 5cf3d00',
               'pair helper call 2 target')

    # --- cfg_ctor: who writes bcfg -------------------------------
    store_rows = [r for r in accesses(cfg_ctor, {'%rbx'})
                  if r['kind'] == 'store']
    require(not covering(store_rows, 0x8, 0x10),
            'cfg_ctor never writes the [bcfg+0x8] slot')
    by_disp = {int(r['disp'], 16): r for r in store_rows}
    require(by_disp.get(0x0, {}).get('text') == 'movq $0x0,(%rbx)',
            'cfg_ctor stores 0 at [bcfg+0x0]')
    require(by_disp.get(0xe4, {}).get('text')
            == 'mov %bpl,0xe4(%rbx)',
            'cfg_ctor stores its second argument at [bcfg+0xe4]')
    require(by_disp.get(0xe5, {}).get('text')
            == 'movl $0x0,0xe5(%rbx)'
            and by_disp.get(0xe5, {}).get('width') == 4,
            'cfg_ctor zero dword at +0xe5 covers [bcfg+0xe7]')
    pin(cfg_ctor, 0x5cf93fc, 'mov %esi,%ebp',
        'cfg_ctor captures its second argument in ebp')
    pin(cfg_ctor, 0x5cf957f, 'mov %rax,%rbx',
        'rbx is overwritten by the exception pointer in the '
        'unwind tail')
    for va, text in cfg_ctor:
        if va < 0x5cf957f:
            require(not re.match(r'mov\w*\s+%rbx,', text),
                    'cfg_ctor passes bcfg to no callee at %#x' % va)

    # --- the other bcfg consumers --------------------------------
    helper_rows = accesses(helper, {'%r12'})
    require(not covering(helper_rows, 0x8, 0xc),
            'pair helper has no access covering [bcfg+0x8]')
    drop_rows = accesses(drop, {'%rbx'})
    drop_rows += [r for r in accesses(drop, {'%rdi'})
                  if int(r['va'], 16) < 0x5cf1b00]
    drop_rows.sort(key=lambda r: int(r['va'], 16))
    require(not covering(drop_rows, 0x8, 0xc),
            'cfg drop body has no access covering [bcfg+0x8]')

    # --- wrappers -------------------------------------------------
    wrap_info = {}
    for role, insns, base in (('wrapper_a', wrap_a, 0x510),
                              ('wrapper_b', wrap_b, 0x130)):
        rows = []
        for va, text in insns:
            for m in MEM.finditer(text):
                if m.group(2) != '%rsp':
                    continue
                disp = int(m.group(1), 16) if m.group(1) else 0
                w = width_of(text, m.span()) or 0
                if disp < base + 0xec and disp + w > base:
                    tail = text[m.end():].strip()
                    rows.append({
                        'va': hex(va), 'offset': hex(disp - base),
                        'disp': hex(disp - base),
                        'width': w,
                        'kind': kind_of(text,
                                        not tail.startswith(',')),
                        'text': text,
                    })
        wrap_info[role] = rows
    a_rows = wrap_info['wrapper_a']
    a_stores = [r for r in a_rows if r['kind'] == 'store']
    require([(r['va'], r['offset']) for r in a_stores
             if int(r['va'], 16) < 0x15d70c2]
            == [('0x15d700c', '0xe5'), ('0x15d70a8', '0xe5')],
            'wrapper A stores into bcfg before the build calls '
            'are exactly the two +0xe5 overwrites')
    require(all(int(r['va'], 16) > 0x15d7034
                for r in covering(a_rows, 0x8, 0x10)),
            'wrapper A stores covering [bcfg+0x8] all follow the '
            'cfg drop call (dead slot reuse)')
    require(not covering(a_rows, 0xe7, 0xe8),
            'wrapper A never touches [bcfg+0xe7]')
    b_rows = wrap_info['wrapper_b']
    require([(r['va'], r['offset']) for r in b_rows
             if r['kind'] == 'store'] == [('0x2ae16d6', '0xe5')],
            'wrapper B stores into bcfg are exactly the +0xe5 '
            'overwrite')
    require(not covering(b_rows, 0x8, 0x10),
            'wrapper B never touches the [bcfg+0x8] slot')
    require(not covering(b_rows, 0xe7, 0xe8),
            'wrapper B never touches [bcfg+0xe7]')
    pin(wrap_a, 0x15d7002, 'mov $0x1,%esi',
        'wrapper A site 1 passes cfg_ctor flag 1')
    pin_prefix(wrap_a, 0x15d7007, 'call 5cf93f0',
               'wrapper A site 1 calls cfg_ctor')
    pin(wrap_a, 0x15d700c, 'movw $0x101,0x5f5(%rsp)',
        'wrapper A site 1 overwrites the +0xe5 u16 with 0x0101')
    pin_prefix(wrap_a, 0x15d7026, 'call *',
               'wrapper A site 1 calls the builder slot')
    require('64e1760' in insn_at(wrap_a, 0x15d7026),
            'wrapper A site 1 calls through GOT slot 0x64e1760')
    pin(wrap_a, 0x15d702c, 'lea 0x510(%rsp),%rdi',
        'wrapper A passes bcfg to the drop body')
    pin_prefix(wrap_a, 0x15d7034, 'call 5cf1af0',
               'wrapper A calls the cfg drop body')
    pin(wrap_a, 0x15d70a1, 'xor %esi,%esi',
        'wrapper A site 2 passes cfg_ctor flag 0')
    pin_prefix(wrap_a, 0x15d70a3, 'call 5cf93f0',
               'wrapper A site 2 calls cfg_ctor')
    pin(wrap_a, 0x15d70a8, 'movw $0x101,0x5f5(%rsp)',
        'wrapper A site 2 overwrites the +0xe5 u16 with 0x0101')
    require('64e1760' in insn_at(wrap_a, 0x15d70c2),
            'wrapper A site 2 calls through GOT slot 0x64e1760')
    pin(wrap_b, 0x2ae16cc, 'mov $0x1,%esi',
        'wrapper B passes cfg_ctor flag 1')
    pin_prefix(wrap_b, 0x2ae16d1, 'call 5cf93f0',
               'wrapper B calls cfg_ctor')
    pin(wrap_b, 0x2ae16d6, 'movw $0x101,0x215(%rsp)',
        'wrapper B overwrites the +0xe5 u16 with 0x0101')
    require('64e1760' in insn_at(wrap_b, 0x2ae16f2),
            'wrapper B calls through GOT slot 0x64e1760')

    # --- body digest cross-pins against #2950 ---------------------
    for role, digest in PRIOR_PINS.items():
        require(bodies[role]['sha256'] == digest,
                'body digest for %s differs from the #2950 pin'
                % role)

    return {
        'artifact': {'snapshot': 'node/115', 'size': SIZE,
                     'sha256': hashlib.sha256(data).hexdigest()},
        'work_item': 'RE-005-node115-cfg-byte-consumers',
        'bodies': bodies,
        'ctor_cfg_census': ctor_rows,
        'builder_bcfg_census': bcfg_rows,
        'cfg_ctor_store_census': store_rows,
        'pair_helper_census': helper_rows,
        'cfg_drop_census': drop_rows,
        'wrapper_census': wrap_info,
        'dcfg_assembly': {
            'site_1': {
                'dcfg_base': 'rsp+0x70', 'ctor_call': '0x5cf9669',
                'fields': {
                    '+0x00': '[bcfg+0x60]',
                    '+0x08': '[bcfg+0xe5] (variant byte)',
                    '+0x09': '[bcfg+0xe6] (tag byte)',
                    '+0x0a': 'immediate 1',
                    '+0x0b': '[bcfg+0xe7]',
                },
            },
            'site_2': {
                'dcfg_base': 'rsp+0x730', 'ctor_call': '0x5cf96eb',
                'fields': {
                    '+0x00': '[bcfg+0x60]',
                    '+0x08': '[bcfg+0xe5] (variant byte)',
                    '+0x09': '[bcfg+0xe6] (tag byte)',
                    '+0x0a': '[bcfg+0xe4] ^ 1',
                    '+0x0b': '[bcfg+0xe7]',
                },
            },
            'fast_path': {
                'gate': '[bcfg+0xe4] == 1 && [bcfg+0x0] == 1',
                'load': '0x5cf962d mov 0x8(%r14),%r13',
                'flag_byte': 'eax zeroed at 0x5cf9631, so the '
                             'shared tail assembles dcfg+0x0a = 0, '
                             'the same value as [bcfg+0xe4] ^ 1',
            },
        },
        'reachable_values': {
            'bcfg+0xe4': {'wrapper_a_site_1': 1,
                          'wrapper_a_site_2': 0, 'wrapper_b': 1},
            'dcfg+0x08': 1,
            'dcfg+0x09': 1,
            'dcfg+0x0a': {
                'site_1': 1, 'site_2': 0,
                'rule': 'uniformly NOT [bcfg+0xe4]; site 2 is '
                        'entered only when [bcfg+0xe4] == 1',
            },
            'dcfg+0x0b': {
                'site_1': 0, 'site_2': 0,
                'source': '[bcfg+0xe7], zeroed by the cfg_ctor '
                          'dword store at +0xe5; the wrapper '
                          'overwrite is a 2-byte store at +0xe5',
            },
        },
        'consumers': {
            'dcfg+0x0a': 'none: no access at any width in '
                         'driver_ctor covers +0xa, and the dcfg '
                         'pointer is never passed to a callee or '
                         'stored',
            'dcfg+0x0b': 'none: same census',
            'bcfg+0x0a_b': 'no byte-granular access exists; the '
                           'only covering access is the builder '
                           'fast-path qword load [bcfg+0x8] at '
                           '0x5cf962d, gated on [bcfg+0x0] == 1, '
                           'which cfg_ctor never supplies',
        },
        'open_edges': [
            'The two wrapper bodies\' source-level identity '
            'remains unpinned (inherited from #2950); this packet '
            'pins their cfg-relevant instructions only.',
            'What [bcfg+0xe4] means at source level (the cfg_ctor '
            'argument the wrappers fix to 1/0/1) is not '
            'identified; the packet pins its flow into '
            'dcfg+0x0a and the builder entry compare only.',
            'The builder\'s [bcfg+0x0] == 1 arm takes a config '
            'built outside this artifact; who writes such a '
            'config, and the [bcfg+0x8] qword it forwards to the '
            'post-build path, is outside the artifact and not '
            'claimed.',
            'builder_precall 0x5cf5db0 is pinned by extent and '
            'digest (cross-checked against #2950) and as the '
            'fast path\'s replaced value supplier; its '
            'source-level identity is not re-derived here.',
        ],
    }


def frames_for(path):
    out = subprocess.check_output(['readelf', '-wf', str(path)],
                                  text=True)
    lines = []
    for role, (a, _b) in BODIES.items():
        needle = 'pc=%016x..' % a
        for line in out.splitlines():
            if 'FDE' in line and needle in line:
                lines.append(line.strip())
                break
        else:
            raise ValueError('no FDE line for %s' % role)
    return lines


def generate(target, outdir):
    data = Path(target).read_bytes()
    payload = analyze(data)
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'records.json').write_text(
        json.dumps(payload, indent=1, sort_keys=True) + '\n')
    (out / 'frames.txt').write_text(
        '\n'.join(frames_for(target)) + '\n')
    for name, (a, b) in EXCERPTS.items():
        raw = subprocess.check_output(
            ['objdump', '-d', '--start-address=%#x' % a,
             '--stop-address=%#x' % b, str(target)])
        (out / ('%s.objdump.txt' % name)).write_bytes(raw)
    return payload


def verify():
    payload = analyze(TARGET.read_bytes())
    with tempfile.TemporaryDirectory() as tmp:
        generate(TARGET, tmp)
        names = ['records.json', 'frames.txt'] + [
            '%s.objdump.txt' % n for n in EXCERPTS]
        ok = all((Path(tmp) / n).read_bytes()
                 == (PACKET / n).read_bytes() for n in names)
    print(json.dumps({'matches': bool(ok and payload)}))
    return 0 if ok else 1


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'generate':
        generate(TARGET, PACKET)
    else:
        sys.exit(verify())
