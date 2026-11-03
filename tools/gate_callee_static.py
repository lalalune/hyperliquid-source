#!/usr/bin/env python3
"""Pin the RE-006 gate callee behind GOT slot 0x64e71b8.

Question (RE-006 packet after inner-bodies #2605): what does the gate
callee behind GOT slot 0x64e71b8 decide?  The slot resolves (single
R_X86_64_RELATIVE relocation, addend 0x434f790) to the 369-byte body
0x434f790..0x434f901.  The two inner bodies packeted by #2605 call it
twice per cursor item through the slot and require return value 1;
this packet pins the callee's own contract, a binary-wide census of
the slot's call sites, and what the two per-item calls each guard.

Method: the authenticated node-115 ELF is decoded with the pinned
objdump wrapper from foundation_millis.  Every string read resolves
through the section table (elf_index.sections): .rodata is identity
mapped, .text carries delta 0x1000, .data.rel.ro delta 0x2000.  GOT
slot references are resolved from raw instruction bytes
(ff15/ff25/rip-relative loads), never from objdump comments.  The
binary-wide census starts from a raw byte scan of .text (a superset
of every instruction-boundary reference) and validates each candidate
against the decoded rows of its containing FDE.
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
from foundation_millis import decode_export as _foundation_decode  # noqa: E402

PACKET_DIR = ROOT / 'research' / 'work-items' / 'RE-006-node115-gate-callee'
UPSTREAM_MAIN = '8fd8db680ec4bfef40996e5616bce3d5156d0b86'
NODE_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
NODE_SIZE = 105896032

GATE_SLOT = 0x64E71B8
DIV_SLOT = 0x64DFAF8
TRAP_SLOT = 0x64DF830
FMT_SLOT = 0x64DF730
DIVIDER = 0x63EFEC0
TRAP = 0x1680C10

GATE = (0x434F790, 0x434F901)
STUB = (0x1680C10, 0x1680C29)
RECORD_STRIDE = 0x158
DIVISOR_1E14 = 0x5AF3107A4000
THRESHOLD = 0x28F5C28F5C28F5C

BODIES = {
    'gate_callee': (GATE[0], GATE[1], True),
    'unwrap_stub': (STUB[0], STUB[1], True),
    'inner_ca': (0x2BBBBA0, 0x2BBC74D, True),
    'inner_c750': (0x2BBC750, 0x2BBD0A3, True),
    'inner_s3': (0x2BBD0B0, 0x2BBDB9A, True),
    'inner_fam_b1': (0x5493080, 0x5493C2D, True),
    'inner_fam_b2': (0x5493C30, 0x549471A, True),
    'inner_fam_b3': (0x5494720, 0x5495073, True),
}
FAMILY = ('inner_ca', 'inner_c750', 'inner_s3',
          'inner_fam_b1', 'inner_fam_b2', 'inner_fam_b3')


class PacketError(AssertionError):
    """The artifact does not authenticate against node 115."""


def _hx(value):
    return f'0x{value:x}'


def _section_bytes(data, secs, start, end):
    for sec in secs:
        if sec['type'] != 8 and sec['address'] <= start \
                and end <= sec['address'] + sec['size']:
            off = sec['offset'] + (start - sec['address'])
            return data[off:off + end - start]
    raise AssertionError(f'no file-backed section covers {start:#x}..{end:#x}')


def _digest(data, secs, start, end):
    return hashlib.sha256(_section_bytes(data, secs, start, end)).hexdigest()


_LINE_RE = re.compile(r'^\s*([0-9a-f]+):\t([0-9a-f ]+?)\s*(?:\t(.*))?$')


def _decode(data, secs, start, end):
    body = _section_bytes(data, secs, start, end)
    handle = tempfile.NamedTemporaryFile(suffix='.bin', delete=False)
    try:
        handle.write(body)
        handle.close()
        out = subprocess.check_output(
            ['objdump', '-D', '-b', 'binary', '-m', 'i386:x86-64',
             f'--adjust-vma={start:#x}', handle.name], text=True)
    finally:
        Path(handle.name).unlink()
    _foundation_decode(out, start, end, body)
    rows = {}
    last = None
    for line in out.splitlines():
        match = _LINE_RE.match(line)
        if not match:
            continue
        addr = int(match.group(1), 16)
        raw = re.sub(r'\s', '', match.group(2))
        text = (match.group(3) or '').strip().split('#')[0].rstrip()
        if not text and last is not None \
                and addr == last + len(bytes.fromhex(rows[last][0])):
            rows[last] = (rows[last][0] + raw, rows[last][1])
        else:
            rows[addr] = (raw, text)
            last = addr
    cursor = start
    for addr in sorted(rows):
        if addr != cursor:
            raise AssertionError(f'decode gap at {addr:#x} != {cursor:#x}')
        cursor += len(bytes.fromhex(rows[addr][0]))
    if cursor != end:
        raise AssertionError(f'decode ends at {cursor:#x} != {end:#x}')
    return rows


def _check_pins(rows, pins, what):
    if rows != pins:
        for address in sorted(set(rows) | set(pins)):
            if rows.get(address) != pins.get(address):
                raise AssertionError(
                    f'{what} instruction at {address:#x} differs: '
                    f'{rows.get(address)!r} != {pins.get(address)!r}')
        raise AssertionError(f'{what} instructions differ')
    return rows


def _check_pins_subset(rows, pins, what):
    for address, want in pins.items():
        if rows.get(address) != want:
            raise AssertionError(
                f'{what} instruction at {address:#x} differs: '
                f'{rows.get(address)!r} != {want!r}')
    return rows


def _rela_entries(data, secs):
    entries = []
    for sec in secs:
        if sec['type'] != 4:
            continue
        blob = _section_bytes(data, secs, sec['address'],
                              sec['address'] + sec['size'])
        for off in range(0, len(blob) - 23, 24):
            r_offset, r_info, r_addend = struct.unpack_from('<QQq', blob, off)
            entries.append((r_offset, r_info & 0xFFFFFFFF, r_info >> 32,
                            r_addend))
    return entries


def _dynsym_name(data, secs, index):
    shoff = struct.unpack_from('<Q', data, 40)[0]
    entsize = struct.unpack_from('<H', data, 58)[0]
    dynsym_idx = next(i for i, s in enumerate(secs) if s['type'] == 11)
    link = struct.unpack_from('<I', data, shoff + dynsym_idx * entsize + 40)[0]
    dynsym = secs[dynsym_idx]
    dynstr = secs[link]
    st_name = struct.unpack_from(
        '<I', data, dynsym['offset'] + index * 24)[0]
    table = _section_bytes(data, secs, dynstr['address'],
                           dynstr['address'] + dynstr['size'])
    end = table.find(b'\0', st_name)
    return table[st_name:end].decode('utf-8')


def _slot_resolution(data, secs, relas, slot):
    hits = [e for e in relas if e[0] == slot]
    if len(hits) != 1:
        raise PacketError(f'slot {_hx(slot)} has {len(hits)} relocations')
    _off, rtype, sym, addend = hits[0]
    content = struct.unpack_from(
        '<Q', _section_bytes(data, secs, slot, slot + 8), 0)[0]
    if content != 0:
        raise PacketError(f'slot {_hx(slot)} initialised content is not zero')
    fact = {'slot': _hx(slot), 'rela_type': rtype,
            'initialised_content': '0x0'}
    if rtype == 8:
        fact['addend'] = _hx(addend)
    elif rtype == 6:
        fact['symbol'] = _dynsym_name(data, secs, sym)
    return fact


_ALIASES = {'rax': ('rax', 'eax', 'ax', 'al'), 'rbx': ('rbx', 'ebx', 'bx', 'bl'),
            'rcx': ('rcx', 'ecx', 'cx', 'cl'), 'rdx': ('rdx', 'edx', 'dx', 'dl'),
            'rsi': ('rsi', 'esi', 'si', 'sil'), 'rdi': ('rdi', 'edi', 'di', 'dil'),
            'rbp': ('rbp', 'ebp', 'bp', 'bpl'), 'rsp': ('rsp', 'esp', 'sp', 'spl')}
for _i in range(8, 16):
    _ALIASES[f'r{_i}'] = (f'r{_i}', f'r{_i}d', f'r{_i}w', f'r{_i}b')
_MNEM_RE = re.compile(
    r'^(lea|mov|movabs|xor|movzbl|movzwl|movsbl|movswl|movslq|movsbq|'
    r'movzbq|movzwq|add|sub|imul|and|or|shl|shr|sar|neg|not|pop|inc|dec|'
    r'cdqe|movupd|movups|movdqa|movdqu|movaps|movapd)\s+(.*)$')


def _last_writer(rows, reg, before, window=16):
    names = _ALIASES.get(reg, (reg,))
    addrs = [a for a in sorted(rows) if a < before][-window:]
    for addr in reversed(addrs):
        text = rows[addr][1]
        match = _MNEM_RE.match(text)
        if not match:
            continue
        parts = [p.strip() for p in match.group(2).split(',')]
        dst = parts[-1].lstrip('%')
        if dst not in names:
            continue
        src = parts[0] if len(parts) > 1 else ''
        out = {'addr': _hx(addr), 'text': text}
        if match.group(1) == 'lea':
            found = re.match(r'^(-?0x[0-9a-f]+)\(%rsp\)$', src)
            if found:
                out.update(form='lea_rsp', disp=int(found.group(1), 16))
            else:
                out.update(form='lea_other', src=src)
            return out
        if match.group(1) == 'xor' and src == '%' + dst:
            return dict(out, form='imm', value=0)
        if src.startswith('%'):
            return dict(out, form='reg', reg=src[1:])
        found = re.match(r'^(-?0x[0-9a-f]+)\(%rsp\)$', src)
        if found:
            return dict(out, form='load_rsp', disp=int(found.group(1), 16))
        found = re.match(r'^\$(-?0x[0-9a-f]+|\d+)$', src)
        if found:
            return dict(out, form='imm', value=int(found.group(1), 0))
        return dict(out, form='other', src=src)
    return None


def _bindings(rows, call, regs=('rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'),
              window=16):
    return {reg: _last_writer(rows, reg, call, window) for reg in regs}


def _slot_refs_all(rows):
    out = {}
    for addr in sorted(rows):
        raw, _text = rows[addr]
        blob = bytes.fromhex(raw)
        if raw.startswith('ff15') and len(blob) == 6:
            out[addr] = ('call', addr + 6 + struct.unpack('<i', blob[2:6])[0])
        elif raw.startswith('ff25') and len(blob) == 6:
            out[addr] = ('jmp', addr + 6 + struct.unpack('<i', blob[2:6])[0])
        elif len(blob) == 7 and blob[0] in (0x48, 0x4C) and blob[1] == 0x8B \
                and (blob[2] & 0xC7) == 0x05:
            out[addr] = ('load', addr + 7 + struct.unpack('<i', blob[3:7])[0])
    return out


def _direct_calls(rows):
    out = {}
    for addr in sorted(rows):
        raw, text = rows[addr]
        if text.startswith('call') and raw.startswith('e8'):
            out[_hx(addr)] = _hx(
                addr + 5 + struct.unpack('<i', bytes.fromhex(raw[2:10]))[0])
    return out


def _split_ops(text):
    parts = text.split(None, 1)
    if len(parts) < 2:
        return (parts[0] if parts else ''), []
    ops, depth, cur = [], 0, ''
    for ch in parts[1]:
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
        if ch == ',' and depth == 0:
            ops.append(cur.strip())
            cur = ''
        else:
            cur += ch
    if cur.strip():
        ops.append(cur.strip())
    return parts[0], ops


_STORE_BASES = {'mov', 'add', 'sub', 'and', 'or', 'xor', 'inc', 'dec',
                'movups', 'movaps', 'movdqa', 'movdqu', 'movsd', 'movss',
                'movlps', 'movhps', 'adc', 'sbb', 'neg', 'not', 'shl', 'shr',
                'sar', 'rol', 'ror', 'imul'}


def _is_store(text):
    mnem, ops = _split_ops(text)
    base = mnem[:-1] if mnem and mnem[-1] in 'bwlq' else mnem
    if base not in _STORE_BASES or len(ops) < 2:
        return False
    return '(' in ops[-1] and not ops[-1].startswith('%')


def _mem_reads(rows):
    """Rows that read memory (any operand), excluding calls and stores."""
    out = []
    for addr in sorted(rows):
        _raw, text = rows[addr]
        mnem, ops = _split_ops(text)
        if mnem in ('call', 'jmp', 'ret', 'lea') or _is_store(text):
            continue
        if any('(' in op for op in ops):
            out.append([_hx(addr), text])
    return out


def _stores(rows):
    return [[_hx(a), rows[a][1]] for a in sorted(rows) if _is_store(rows[a][1])]


_RDX_RE = re.compile(r'%(rdx|edx|dx|dl)\b')


def _rdx_used(rows, call, window=16):
    addrs = [a for a in sorted(rows) if a > call][:window]
    for addr in addrs:
        mnem, ops = _split_ops(rows[addr][1])
        if mnem == 'call':
            break
        srcs = ops[:-1] if len(ops) > 1 else ops
        if any(_RDX_RE.search(op) for op in srcs):
            return True
    return False


def _fde_index(data):
    handle = tempfile.NamedTemporaryFile(suffix='.elf', delete=False)
    try:
        handle.write(data)
        handle.close()
        out = subprocess.check_output(
            ['readelf', '--debug-dump=frames', handle.name], text=True)
    finally:
        Path(handle.name).unlink()
    index = {}
    for line in out.splitlines():
        if ' FDE ' not in line:
            continue
        match = re.search(r'pc=([0-9a-f]+)\.\.([0-9a-f]+)', line)
        if match:
            index[int(match.group(1), 16)] = (
                int(match.group(2), 16), line)
    return index


def _frames(fde_index):
    retained = {(start, end) for start, end, _e in BODIES.values()}
    lines = []
    for start in sorted(fde_index):
        end, line = fde_index[start]
        if (start, end) in retained:
            lines.append(line)
    if len(lines) != len(retained):
        raise AssertionError(
            f'frames cover {len(lines)} of {len(retained)} FDEs')
    return '\n'.join(lines) + '\n'


def _body_export(data, start, end):
    handle = tempfile.NamedTemporaryFile(suffix='.elf', delete=False)
    try:
        handle.write(data)
        handle.close()
        out = subprocess.check_output(
            ['objdump', '-d', '-M', 'intel', '--insn-width=16',
             f'--start-address={start:#x}', f'--stop-address={end:#x}',
             handle.name], text=True)
    finally:
        Path(handle.name).unlink()
    return out.replace(handle.name, '<authenticated-node115>')


def _export_name(name, start, end):
    return f'{name}_full_body_{start:x}_{end:x}_objdump.txt'


def _raw_slot_scan(data, secs, slot):
    """Raw rip-relative references to `slot` in .text (superset scan)."""
    text_sec = next(s for s in secs if s['name'] == '.text')
    va0, fo0, size = text_sec['address'], text_sec['offset'], text_sec['size']
    blob = data[fo0:fo0 + size]
    out = {}
    for i in range(size - 7):
        va = va0 + i
        b0, b1 = blob[i], blob[i + 1]
        if b0 == 0xFF and b1 in (0x15, 0x25):
            disp = struct.unpack_from('<i', blob, i + 2)[0]
            if va + 6 + disp == slot:
                out[va] = 'call' if b1 == 0x15 else 'jmp'
        elif 0x48 <= b0 <= 0x4F and b1 in (0x8B, 0x8D) \
                and (blob[i + 2] & 0xC7) == 0x05:
            disp = struct.unpack_from('<i', blob, i + 3)[0]
            if va + 7 + disp == slot:
                out[va] = 'load' if b1 == 0x8B else 'lea'
        elif b0 in (0x8B, 0x8D) and (b1 & 0xC7) == 0x05:
            disp = struct.unpack_from('<i', blob, i + 2)[0]
            if va + 6 + disp == slot:
                out[va] = 'load32' if b0 == 0x8B else 'lea32'
    return out


def _lea_target(rows, addr):
    raw, _text = rows[addr]
    blob = bytes.fromhex(raw)
    return addr + len(blob) + struct.unpack_from('<i', blob, 3)[0]


def _descriptor(data, secs, relas, va):
    """Decode a panic Location static at `va` in .data.rel.ro."""
    q = struct.unpack_from(
        '<QQQ', _section_bytes(data, secs, va, va + 24), 0)
    hits = [e for e in relas if e[0] == va and e[1] == 8]
    if len(hits) != 1:
        raise PacketError(f'descriptor {_hx(va)} has {len(hits)} relocations')
    file_ptr = hits[0][3]
    file_len = q[1]
    text = _section_bytes(data, secs, file_ptr, file_ptr + file_len)
    return {'va': _hx(va), 'file_ptr': _hx(file_ptr), 'file_len': file_len,
            'file': text.decode('utf-8'),
            'line': q[2] & 0xFFFFFFFF, 'col': q[2] >> 32}


# === FROZEN DATA (injected) ===
FROZEN = {'gate_rows': {'70580112': ['4157', 'push   %r15'], '70580114': ['4156', 'push   %r14'], '70580116': ['4155', 'push   %r13'], '70580118': ['4154', 'push   %r12'], '70580120': ['53', 'push   %rbx'], '70580121': ['493b7028', 'cmp    0x28(%r8),%rsi'], '70580125': ['0f8351010000', 'jae    0x434f8f4'], '70580131': ['89cb', 'mov    %ecx,%ebx'], '70580133': ['498b4820', 'mov    0x20(%r8),%rcx'], '70580137': ['4869f658010000', 'imul   $0x158,%rsi,%rsi'], '70580144': ['0fb6443149', 'movzbl 0x49(%rcx,%rsi,1),%eax'], '70580149': ['2a443148', 'sub    0x48(%rcx,%rsi,1),%al'], '70580153': ['0f8228010000', 'jb     0x434f8e7'], '70580159': ['b901000000', 'mov    $0x1,%ecx'], '70580164': ['0f858a000000', 'jne    0x434f854'], '70580170': ['4889d0', 'mov    %rdx,%rax'], '70580173': ['48f7e7', 'mul    %rdi'], '70580176': ['4989c6', 'mov    %rax,%r14'], '70580179': ['4989d7', 'mov    %rdx,%r15'], '70580182': ['ba64000000', 'mov    $0x64,%edx'], '70580187': ['4889c8', 'mov    %rcx,%rax'], '70580190': ['48f7e2', 'mul    %rdx'], '70580193': ['4989d5', 'mov    %rdx,%r13'], '70580196': ['4989c4', 'mov    %rax,%r12'], '70580199': ['4c89f7', 'mov    %r14,%rdi'], '70580202': ['4c89fe', 'mov    %r15,%rsi'], '70580205': ['4889c2', 'mov    %rax,%rdx'], '70580208': ['4c89e9', 'mov    %r13,%rcx'], '70580211': ['ff15ff021902', 'call   *0x21902ff(%rip)'], '70580217': ['4889c1', 'mov    %rax,%rcx'], '70580220': ['4889d6', 'mov    %rdx,%rsi'], '70580223': ['84db', 'test   %bl,%bl'], '70580225': ['7429', 'je     0x434f82c'], '70580227': ['4889c8', 'mov    %rcx,%rax'], '70580230': ['49f7e4', 'mul    %r12'], '70580233': ['4c0fafe9', 'imul   %rcx,%r13'], '70580237': ['4901d5', 'add    %rdx,%r13'], '70580240': ['4c0fafe6', 'imul   %rsi,%r12'], '70580244': ['4d01ec', 'add    %r13,%r12'], '70580247': ['4929c6', 'sub    %rax,%r14'], '70580250': ['4d19e7', 'sbb    %r12,%r15'], '70580253': ['31c0', 'xor    %eax,%eax'], '70580255': ['4d09f7', 'or     %r14,%r15'], '70580258': ['0f95c0', 'setne  %al'], '70580261': ['4801c1', 'add    %rax,%rcx'], '70580264': ['4883d600', 'adc    $0x0,%rsi'], '70580268': ['4885f6', 'test   %rsi,%rsi'], '70580271': ['0f94c0', 'sete   %al'], '70580274': ['48ba5c8fc2f5285c8f02', 'movabs $0x28f5c28f5c28f5c,%rdx'], '70580284': ['4839d1', 'cmp    %rdx,%rcx'], '70580287': ['0f92c2', 'setb   %dl'], '70580290': ['20c2', 'and    %al,%dl'], '70580292': ['0fb6c2', 'movzbl %dl,%eax'], '70580295': ['4889ca', 'mov    %rcx,%rdx'], '70580298': ['5b', 'pop    %rbx'], '70580299': ['415c', 'pop    %r12'], '70580301': ['415d', 'pop    %r13'], '70580303': ['415e', 'pop    %r14'], '70580305': ['415f', 'pop    %r15'], '70580307': ['c3', 'ret'], '70580308': ['0fb6f0', 'movzbl %al,%esi'], '70580311': ['40f6c601', 'test   $0x1,%sil'], '70580315': ['740e', 'je     0x434f86b'], '70580317': ['b90a000000', 'mov    $0xa,%ecx'], '70580322': ['83fe01', 'cmp    $0x1,%esi'], '70580325': ['0f845fffffff', 'je     0x434f7ca'], '70580331': ['a802', 'test   $0x2,%al'], '70580333': ['7415', 'je     0x434f884'], '70580335': ['486bc964', 'imul   $0x64,%rcx,%rcx'], '70580339': ['4189f0', 'mov    %esi,%r8d'], '70580342': ['4183e0fe', 'and    $0xfffffffe,%r8d'], '70580346': ['4183f802', 'cmp    $0x2,%r8d'], '70580350': ['0f8446ffffff', 'je     0x434f7ca'], '70580356': ['a804', 'test   $0x4,%al'], '70580358': ['7418', 'je     0x434f8a0'], '70580360': ['4869c910270000', 'imul   $0x2710,%rcx,%rcx'], '70580367': ['4189f0', 'mov    %esi,%r8d'], '70580370': ['4183e0fc', 'and    $0xfffffffc,%r8d'], '70580374': ['4183f804', 'cmp    $0x4,%r8d'], '70580378': ['0f842affffff', 'je     0x434f7ca'], '70580384': ['a808', 'test   $0x8,%al'], '70580386': ['7418', 'je     0x434f8bc'], '70580388': ['4869c900e1f505', 'imul   $0x5f5e100,%rcx,%rcx'], '70580395': ['4189f0', 'mov    %esi,%r8d'], '70580398': ['4183e0f8', 'and    $0xfffffff8,%r8d'], '70580402': ['4183f808', 'cmp    $0x8,%r8d'], '70580406': ['0f840effffff', 'je     0x434f7ca'], '70580412': ['a810', 'test   $0x10,%al'], '70580414': ['7427', 'je     0x434f8e7'], '70580416': ['49b80000c16ff2862300', 'movabs $0x2386f26fc10000,%r8'], '70580426': ['4889c8', 'mov    %rcx,%rax'], '70580429': ['4889d1', 'mov    %rdx,%rcx'], '70580432': ['49f7e0', 'mul    %r8'], '70580435': ['7012', 'jo     0x434f8e7'], '70580437': ['4889ca', 'mov    %rcx,%rdx'], '70580440': ['4889c1', 'mov    %rax,%rcx'], '70580443': ['83e6f0', 'and    $0xfffffff0,%esi'], '70580446': ['83fe10', 'cmp    $0x10,%esi'], '70580449': ['0f84e3feffff', 'je     0x434f7ca'], '70580455': ['488d3d5a711202', 'lea    0x212715a(%rip),%rdi'], '70580462': ['ff153cff1802', 'call   *0x218ff3c(%rip)'], '70580468': ['488d3ddd6f1202', 'lea    0x2126fdd(%rip),%rdi'], '70580475': ['ff152fff1802', 'call   *0x218ff2f(%rip)']}, 'stub_rows': {'23596048': ['55', 'push   %rbp'], '23596049': ['4889e5', 'mov    %rsp,%rbp'], '23596052': ['4889fa', 'mov    %rdi,%rdx'], '23596055': ['488d3d74dddefe', 'lea    -0x121228c(%rip),%rdi'], '23596062': ['be2b000000', 'mov    $0x2b,%esi'], '23596067': ['ff1507ebe504', 'call   *0x4e5eb07(%rip)']}, 'bodies': {'gate_callee': [70580112, 70580481, '0929c3bc21a049c48aef024cf8ceb3c6bc43f66d93558ca6950b0e9b96299300'], 'unwrap_stub': [23596048, 23596073, '6c62896561a5c8454ceb1945a882a798dcaefe52e78852cbbfee08835a16a81e'], 'inner_ca': [45857696, 45860685, 'f3e69ec027f6e24352c49415a533d2cc5e75443ce6681b3c6b51331a3446fa35'], 'inner_c750': [45860688, 45863075, '1e485c8260263eee0fb80e2871c1aaabde9f381b30e9159662d64e5a991a04fa'], 'inner_s3': [45863088, 45865882, '889874f504716879ed3af8bfab1a9f7909972bfee409b4125910ce5a114c1a6e'], 'inner_fam_b1': [88682624, 88685613, '3f64074e76c5885610e7e95dd1b66853e70f74d1e0b406fb3b9e25ac2c9abae3'], 'inner_fam_b2': [88685616, 88688410, 'ce21c020d8136334be1bb89799253a295aeab1ab10c688d4d5ef4744294f0c9e'], 'inner_fam_b3': [88688416, 88690803, '22fd22d11c09bf61900af25dcb36f4d1cf63865c696382add27794a1004db4ee']}, 'family_pins': {'inner_ca': {'45859003': ['498b5710', 'mov    0x10(%r15),%rdx'], '45859013': ['31c9', 'xor    %ecx,%ecx'], '45859020': ['ff15e6b09203', 'call   *0x392b0e6(%rip)'], '45859196': ['498b5710', 'mov    0x10(%r15),%rdx'], '45859203': ['b901000000', 'mov    $0x1,%ecx'], '45859213': ['ff1525b09203', 'call   *0x392b025(%rip)'], '45859535': ['498b5710', 'mov    0x10(%r15),%rdx'], '45859542': ['b901000000', 'mov    $0x1,%ecx'], '45859552': ['ff15d2ae9203', 'call   *0x392aed2(%rip)'], '45859851': ['31c9', 'xor    %ecx,%ecx'], '45859856': ['498b5710', 'mov    0x10(%r15),%rdx'], '45859866': ['31c9', 'xor    %ecx,%ecx'], '45859873': ['ff1591ad9203', 'call   *0x392ad91(%rip)'], '45860106': ['31c9', 'xor    %ecx,%ecx'], '45860111': ['498b5710', 'mov    0x10(%r15),%rdx'], '45860121': ['31c9', 'xor    %ecx,%ecx'], '45860128': ['ff1592ac9203', 'call   *0x392ac92(%rip)'], '45860295': ['31c9', 'xor    %ecx,%ecx'], '45860299': ['498b5710', 'mov    0x10(%r15),%rdx'], '45860309': ['31c9', 'xor    %ecx,%ecx'], '45860316': ['ff15d6ab9203', 'call   *0x392abd6(%rip)'], '45860322': ['b107', 'mov    $0x7,%cl'], '45860587': ['b107', 'mov    $0x7,%cl']}, 'inner_c750': {'45861437': ['488b5310', 'mov    0x10(%rbx),%rdx'], '45861449': ['31c9', 'xor    %ecx,%ecx'], '45861456': ['ff1562a79203', 'call   *0x392a762(%rip)'], '45861624': ['488b5310', 'mov    0x10(%rbx),%rdx'], '45861633': ['b901000000', 'mov    $0x1,%ecx'], '45861643': ['ff15a7a69203', 'call   *0x392a6a7(%rip)'], '45861967': ['488b5310', 'mov    0x10(%rbx),%rdx'], '45861976': ['b901000000', 'mov    $0x1,%ecx'], '45861986': ['ff1550a59203', 'call   *0x392a550(%rip)'], '45862229': ['31c9', 'xor    %ecx,%ecx'], '45862234': ['488b5310', 'mov    0x10(%rbx),%rdx'], '45862246': ['31c9', 'xor    %ecx,%ecx'], '45862253': ['ff1545a49203', 'call   *0x392a445(%rip)'], '45862468': ['31c9', 'xor    %ecx,%ecx'], '45862473': ['488b5310', 'mov    0x10(%rbx),%rdx'], '45862485': ['31c9', 'xor    %ecx,%ecx'], '45862492': ['ff1556a39203', 'call   *0x392a356(%rip)'], '45862645': ['31c9', 'xor    %ecx,%ecx'], '45862650': ['488b5310', 'mov    0x10(%rbx),%rdx'], '45862662': ['31c9', 'xor    %ecx,%ecx'], '45862669': ['ff15a5a29203', 'call   *0x392a2a5(%rip)'], '45862675': ['b107', 'mov    $0x7,%cl'], '45862977': ['b107', 'mov    $0x7,%cl']}, 'inner_s3': {'45864211': ['498b5710', 'mov    0x10(%r15),%rdx'], '45864221': ['31c9', 'xor    %ecx,%ecx'], '45864228': ['ff158e9c9203', 'call   *0x3929c8e(%rip)'], '45864399': ['498b5710', 'mov    0x10(%r15),%rdx'], '45864406': ['b901000000', 'mov    $0x1,%ecx'], '45864416': ['ff15d29b9203', 'call   *0x3929bd2(%rip)'], '45864735': ['498b5710', 'mov    0x10(%r15),%rdx'], '45864742': ['b901000000', 'mov    $0x1,%ecx'], '45864752': ['ff15829a9203', 'call   *0x3929a82(%rip)'], '45865053': ['31c9', 'xor    %ecx,%ecx'], '45865058': ['498b5710', 'mov    0x10(%r15),%rdx'], '45865068': ['31c9', 'xor    %ecx,%ecx'], '45865075': ['ff153f999203', 'call   *0x392993f(%rip)'], '45865310': ['31c9', 'xor    %ecx,%ecx'], '45865315': ['498b5710', 'mov    0x10(%r15),%rdx'], '45865325': ['31c9', 'xor    %ecx,%ecx'], '45865332': ['ff153e989203', 'call   *0x392983e(%rip)'], '45865494': ['31c9', 'xor    %ecx,%ecx'], '45865502': ['498b5710', 'mov    0x10(%r15),%rdx'], '45865512': ['31c9', 'xor    %ecx,%ecx'], '45865519': ['ff1583979203', 'call   *0x3929783(%rip)'], '45865525': ['b107', 'mov    $0x7,%cl'], '45865780': ['b107', 'mov    $0x7,%cl']}, 'inner_fam_b1': {'88683931': ['498b5710', 'mov    0x10(%r15),%rdx'], '88683941': ['31c9', 'xor    %ecx,%ecx'], '88683948': ['ff15063c0501', 'call   *0x1053c06(%rip)'], '88684124': ['498b5710', 'mov    0x10(%r15),%rdx'], '88684131': ['b901000000', 'mov    $0x1,%ecx'], '88684141': ['ff15453b0501', 'call   *0x1053b45(%rip)'], '88684463': ['498b5710', 'mov    0x10(%r15),%rdx'], '88684470': ['b901000000', 'mov    $0x1,%ecx'], '88684480': ['ff15f2390501', 'call   *0x10539f2(%rip)'], '88684779': ['31c9', 'xor    %ecx,%ecx'], '88684784': ['498b5710', 'mov    0x10(%r15),%rdx'], '88684794': ['31c9', 'xor    %ecx,%ecx'], '88684801': ['ff15b1380501', 'call   *0x10538b1(%rip)'], '88685034': ['31c9', 'xor    %ecx,%ecx'], '88685039': ['498b5710', 'mov    0x10(%r15),%rdx'], '88685049': ['31c9', 'xor    %ecx,%ecx'], '88685056': ['ff15b2370501', 'call   *0x10537b2(%rip)'], '88685223': ['31c9', 'xor    %ecx,%ecx'], '88685227': ['498b5710', 'mov    0x10(%r15),%rdx'], '88685237': ['31c9', 'xor    %ecx,%ecx'], '88685244': ['ff15f6360501', 'call   *0x10536f6(%rip)'], '88685250': ['b107', 'mov    $0x7,%cl'], '88685515': ['b107', 'mov    $0x7,%cl']}, 'inner_fam_b2': {'88686739': ['498b5710', 'mov    0x10(%r15),%rdx'], '88686749': ['31c9', 'xor    %ecx,%ecx'], '88686756': ['ff150e310501', 'call   *0x105310e(%rip)'], '88686927': ['498b5710', 'mov    0x10(%r15),%rdx'], '88686934': ['b901000000', 'mov    $0x1,%ecx'], '88686944': ['ff1552300501', 'call   *0x1053052(%rip)'], '88687263': ['498b5710', 'mov    0x10(%r15),%rdx'], '88687270': ['b901000000', 'mov    $0x1,%ecx'], '88687280': ['ff15022f0501', 'call   *0x1052f02(%rip)'], '88687581': ['31c9', 'xor    %ecx,%ecx'], '88687586': ['498b5710', 'mov    0x10(%r15),%rdx'], '88687596': ['31c9', 'xor    %ecx,%ecx'], '88687603': ['ff15bf2d0501', 'call   *0x1052dbf(%rip)'], '88687838': ['31c9', 'xor    %ecx,%ecx'], '88687843': ['498b5710', 'mov    0x10(%r15),%rdx'], '88687853': ['31c9', 'xor    %ecx,%ecx'], '88687860': ['ff15be2c0501', 'call   *0x1052cbe(%rip)'], '88688022': ['31c9', 'xor    %ecx,%ecx'], '88688030': ['498b5710', 'mov    0x10(%r15),%rdx'], '88688040': ['31c9', 'xor    %ecx,%ecx'], '88688047': ['ff15032c0501', 'call   *0x1052c03(%rip)'], '88688053': ['b107', 'mov    $0x7,%cl'], '88688308': ['b107', 'mov    $0x7,%cl']}, 'inner_fam_b3': {'88689165': ['488b5310', 'mov    0x10(%rbx),%rdx'], '88689177': ['31c9', 'xor    %ecx,%ecx'], '88689184': ['ff1592270501', 'call   *0x1052792(%rip)'], '88689352': ['488b5310', 'mov    0x10(%rbx),%rdx'], '88689361': ['b901000000', 'mov    $0x1,%ecx'], '88689371': ['ff15d7260501', 'call   *0x10526d7(%rip)'], '88689695': ['488b5310', 'mov    0x10(%rbx),%rdx'], '88689704': ['b901000000', 'mov    $0x1,%ecx'], '88689714': ['ff1580250501', 'call   *0x1052580(%rip)'], '88689957': ['31c9', 'xor    %ecx,%ecx'], '88689962': ['488b5310', 'mov    0x10(%rbx),%rdx'], '88689974': ['31c9', 'xor    %ecx,%ecx'], '88689981': ['ff1575240501', 'call   *0x1052475(%rip)'], '88690196': ['31c9', 'xor    %ecx,%ecx'], '88690201': ['488b5310', 'mov    0x10(%rbx),%rdx'], '88690213': ['31c9', 'xor    %ecx,%ecx'], '88690220': ['ff1586230501', 'call   *0x1052386(%rip)'], '88690373': ['31c9', 'xor    %ecx,%ecx'], '88690378': ['488b5310', 'mov    0x10(%rbx),%rdx'], '88690390': ['31c9', 'xor    %ecx,%ecx'], '88690397': ['ff15d5220501', 'call   *0x10522d5(%rip)'], '88690403': ['b107', 'mov    $0x7,%cl'], '88690705': ['b107', 'mov    $0x7,%cl']}}, 'census_digests': {'2a8be00-2a8cbb3': ['6192142ab8921f4faa4e927aa42bfa0cd9d9f3b2f836dc8f57b66e783d4d4c5f'], '2bbbba0-2bbc74d': ['f3e69ec027f6e24352c49415a533d2cc5e75443ce6681b3c6b51331a3446fa35'], '2bbc750-2bbd0a3': ['1e485c8260263eee0fb80e2871c1aaabde9f381b30e9159662d64e5a991a04fa'], '2bbd0b0-2bbdb9a': ['889874f504716879ed3af8bfab1a9f7909972bfee409b4125910ce5a114c1a6e'], '2bfb830-2bfbe1a': ['2ebd20a20be37eef9a21fccf1767de03632df456d2b9fa8c45722c8a649bcfeb'], '2bfbe20-2bfc4d2': ['066c01582b6f1688af0db1973da82af5abeedbe9aeefabf53aa41298fa37d8f9'], '2bfd0c0-2bfd357': ['5762f41ade6d1f819df3de86b3796696c06ccf51938404b4f66ecf7402bc2894'], '2bfd360-2c0045a': ['896175f4c46e32e0e65b92a6fdd22c15c973db48a814310c1c7015b52b1a8d5d'], '2c01570-2c01919': ['1264dfa0b7d5aa1dd4f7b19a186bb1588e7970687d23abaff178357da4724949'], '2c01920-2c02dc9': ['27909acc5e83d0567ff22c4a9b454590f86ee32751b254f560b315b6fa9e57fd'], '2c289b0-2c28f1b': ['56e2a5f856c8bf307b33bca728140ddaf0f8291c44dcdb540084107331500b0c'], '2c32960-2c3323d': ['b41372b433fcdd8f1dea0efe6ca533b0172b987c6fa6283bbecf138aa6a94ccf'], '2c36af0-2c37edb': ['4055967cc8fd9863bdb5ab181a8824fc5e02a0a6ed51d6f95936e6e997f17d68'], '2d27720-2d27a78': ['2e3e51ea9925edc38ae111c2eed527b463dadf3d01e73342a90fdca9752a2a1c'], '36961e0-3698ed2': ['1d6d91dfde0615441347f8c8a676e0c6e2d943fa1d26e17e64db41197a146dee'], '369d2c0-369dc7c': ['c05744100d46d44a1c0f8daed2ba2948b732686cbe0401b1084432bc4bb8d61e'], '3bf4cb0-3bf4f9f': ['1454c3f6ba2656698193ed17c1294914d719ec225572952d1d050e1a264e2779'], '3bfa270-3bfa338': ['bdcadb371dd3732d2d8275a1e2b7ca4cdd0819be4797d32ba6296206f31b6977'], '4215360-42155fb': ['dc4e137760d3ef42278db2b620c4f2a4237dc4f599c4c4982e7923cf74dc3a0f'], '5493080-5493c2d': ['3f64074e76c5885610e7e95dd1b66853e70f74d1e0b406fb3b9e25ac2c9abae3'], '5493c30-549471a': ['ce21c020d8136334be1bb89799253a295aeab1ab10c688d4d5ef4744294f0c9e'], '5494720-5495073': ['22fd22d11c09bf61900af25dcb36f4d1cf63865c696382add27794a1004db4ee'], '54a9c70-54b66a2': ['c8b4563b262d24c124d4ee54a7e00146f41aeb8dc57799cdf5db6970562fceac'], '54b66b0-54c2ae8': ['824ba23a3fbf24fe416e3f682d908c73e0c3504d82c6f1c8f20c79a61ee44d03'], '54e2920-54e3026': ['38e0350548e712c5a66548e6dcb54924e0cba57778d49639e93c5cce462b650d'], '54e3030-54e3736': ['b5e09b216fff91e08d1d0db7a79ab824c53393ef4521a529f879c240e3dad40f'], '54e3740-54e3efc': ['a1485583df2343211d2c45fb443c0bacae2db0b4360f744705cb59b5cfac7db2'], '54e3f00-54e46bc': ['ee2f0c08e36ef349108e80a0de42c16fe80f3abd4fde9976d5c9b457d132fdf8'], '54e5f90-54e624f': ['8b27420c0cc8c7829b7727296c8b58d0202ad092645baa6da2802838d3eabe19'], '54e6250-54e650f': ['6f5e26526478642459c55d4d934c11aebe00a222e31ed57e4864f7042c226aad'], '54e6510-54e9607': ['c80839cb926bce8590ebc0c54c3d39617086a00c57037ca050f100ca2709ae84'], '54e9610-54ec707': ['e8991eb0f110450987cf0ccc30fffdbc24b9be3aa35148e636ae10596a1e245a'], '54eeea0-54ef0a9': ['498bdefd557cced4607abc3537e23f8d2b69e801fcd19734d0fd5eb5c6c3c950'], '54ef0b0-54ef2b9': ['c011d71e153dce994bff783c91dc7a038d58b8caa1232bc59ef3f7b9174592f4'], '54ef2c0-54ef7ac': ['c4a4da6996a16a4409e8501e76b20d63e0a7e9002b268fcb38bd0210faf55fd8'], '54ef7b0-54efc9c': ['5020df80460d7cc491b3b74e98b71bb6625513de12690a043f3d7edf621825c3'], '5560d60-5561369': ['8c131c686e0b286f43dfb34f835c31d4768e2936aca0bd90fca55e81664724ae'], '5561370-5561979': ['e4c02e06ede14de11fe917dc7da0a253a39d054197f9cda564a4418d9ca5b4c8'], '5575680-5575f5d': ['552341d2551eefcfbd97f9faf833d2e318fcc907fc62c70f68056128da25fb62'], '5575f60-557683d': ['4fabdd5ddb9c9b99992a35c8569c9edb69b1693da4391fad568bd8e41d4fb6e9'], '557df20-557f2d3': ['7d8dc08adee6b813d9b8870351abdf9b00f9c26dda65a1af01fd3b16980ba33a'], '557f2e0-55806d1': ['39ff97aade1191a254c99f1b79208ede2e418c63a633363913946392a7ef7405'], '5a090d0-5a09428': ['31f21a47108d6f188544974541c345ef1b4259a784e42910a0adb9ddbab56bd9']}}


def _pins(mapping):
    return {int(a): tuple(v) for a, v in mapping.items()}


def _flag_of(binding):
    if binding is None:
        return 'unknown'
    if binding.get('form') == 'imm':
        return binding.get('value')
    return 'register'


def analyze(data):
    if len(data) != NODE_SIZE \
            or hashlib.sha256(data).hexdigest() != NODE_SHA256:
        raise PacketError('artifact does not authenticate as node 115')
    secs = sections(data)
    relas = _rela_entries(data, secs)
    slot_facts = {}
    for slot in (GATE_SLOT, DIV_SLOT, TRAP_SLOT, FMT_SLOT):
        slot_facts[_hx(slot)] = _slot_resolution(data, secs, relas, slot)
    if slot_facts[_hx(GATE_SLOT)].get('addend') != _hx(GATE[0]):
        raise PacketError('gate slot does not resolve to the gate body')
    if slot_facts[_hx(DIV_SLOT)].get('addend') != _hx(DIVIDER):
        raise PacketError('divider slot does not resolve as expected')
    if slot_facts[_hx(TRAP_SLOT)].get('addend') != _hx(TRAP):
        raise PacketError('trap slot does not resolve as expected')
    if THRESHOLD * 100 >= 2 ** 64 or (THRESHOLD + 1) * 100 <= 2 ** 64:
        raise AssertionError('threshold is not floor(2^64/100)')

    fdes = _fde_index(data)
    bodies = {}
    for name, (start, end, exported) in BODIES.items():
        dg = _digest(data, secs, start, end)
        if [start, end, dg] != FROZEN['bodies'][name]:
            raise PacketError(f'body {name} range or digest drift')
        if fdes.get(start, (None,))[0] != end:
            raise PacketError(f'body {name} is not an FDE extent')
        bodies[name] = {'start': _hx(start), 'end': _hx(end),
                        'size': end - start, 'sha256': dg,
                        'exported': exported}

    # --- the gate callee itself -------------------------------------
    gate_rows = _decode(data, secs, *GATE)
    _check_pins(gate_rows, _pins(FROZEN['gate_rows']), 'gate callee')
    gate_refs = _slot_refs_all(gate_rows)
    gate_slot_calls = {_hx(a): _hx(t) for a, (k, t) in sorted(gate_refs.items())
                       if k == 'call'}
    if gate_slot_calls != {'0x434f7f3': _hx(DIV_SLOT),
                           '0x434f8ee': _hx(TRAP_SLOT),
                           '0x434f8fb': _hx(TRAP_SLOT)}:
        raise PacketError(f'gate slot calls drift: {gate_slot_calls}')
    gate = {
        'rows': len(gate_rows),
        'reads': _mem_reads(gate_rows),
        'stores': _stores(gate_rows),
        'direct_calls': _direct_calls(gate_rows),
        'slot_calls': gate_slot_calls,
        'rets': [_hx(a) for a in sorted(gate_rows)
                 if gate_rows[a][1] == 'ret'],
        'r9_refs': [_hx(a) for a in sorted(gate_rows)
                    if '%r9' in gate_rows[a][1]],
        'descriptors': {
            'bounds': _descriptor(data, secs, relas,
                                  _lea_target(gate_rows, 0x434F8F4)),
            'scale': _descriptor(data, secs, relas,
                                 _lea_target(gate_rows, 0x434F8E7)),
        },
        'scale_bases': {'bit0': 10, 'bit1': 100, 'bit2': 10000,
                        'bit3': 100000000, 'bit4': 10 ** 16},
        'exponent_range': [0, 19],
        'threshold': _hx(THRESHOLD),
        'threshold_decimal': THRESHOLD,
        'threshold_identity': 'floor(2^64/100)',
    }
    if gate['stores'] or gate['direct_calls'] or gate['r9_refs']:
        raise PacketError('gate census drift: stores/direct calls/r9')
    if gate['rets'] != ['0x434f853'] or len(gate['reads']) != 4:
        raise PacketError('gate census drift: rets/reads')

    # --- the unwrap stub behind the trap slot -----------------------
    stub_rows = _decode(data, secs, *STUB)
    _check_pins(stub_rows, _pins(FROZEN['stub_rows']), 'unwrap stub')
    stub_refs = _slot_refs_all(stub_rows)
    fmt_ptr = _lea_target(stub_rows, 0x1680C17)
    fmt_len = 0x2B
    fmt_text = _section_bytes(data, secs, fmt_ptr, fmt_ptr + fmt_len)
    stub = {
        'rows': len(stub_rows),
        'arg_forward': stub_rows[0x1680C14][1],
        'fmt_ptr': _hx(fmt_ptr), 'fmt_len': fmt_len,
        'fmt': fmt_text.decode('utf-8'),
        'slot_calls': {_hx(a): _hx(t) for a, (k, t) in sorted(stub_refs.items())
                       if k == 'call'},
        'byte_after_body': _section_bytes(
            data, secs, STUB[1], STUB[1] + 1).hex(),
    }
    if stub['slot_calls'] != {'0x1680c23': _hx(FMT_SLOT)} \
            or stub['byte_after_body'] != 'cc':
        raise PacketError('unwrap stub drift')

    # --- binary-wide census of the gate slot ------------------------
    raw = _raw_slot_scan(data, secs, GATE_SLOT)
    kinds = {}
    for kind in raw.values():
        kinds[kind] = kinds.get(kind, 0) + 1
    if kinds != {'call': 89}:
        raise PacketError(f'slot reference kinds drift: {kinds}')
    starts = sorted(fdes)

    def owner(va):
        import bisect
        i = bisect.bisect_right(starts, va) - 1
        if i < 0 or not (starts[i] <= va < fdes[starts[i]][0]):
            raise PacketError(f'candidate {_hx(va)} is inside no FDE')
        return starts[i]

    groups = {}
    for va in sorted(raw):
        groups.setdefault(owner(va), []).append(va)
    if {f'{s:x}-{fdes[s][0]:x}' for s in groups} \
            != set(FROZEN['census_digests']):
        raise PacketError('census FDE set drift')
    family_by_range = {(BODIES[n][0], BODIES[n][1]): n for n in FAMILY}
    decoded = {}
    census = {}
    flag_counts = {'0': 0, '1': 0, 'register': 0, 'unknown': 0}
    rdx_used = 0
    select_sites = 0
    for start in sorted(groups):
        end = fdes[start][0]
        dg = _digest(data, secs, start, end)
        key = f'{start:x}-{end:x}'
        if FROZEN['census_digests'][key] != [dg]:
            raise PacketError(f'census FDE {key} digest drift')
        rows = decoded.get(start)
        if rows is None:
            rows = _decode(data, secs, start, end)
            decoded[start] = rows
        refs = _slot_refs_all(rows)
        calls = sorted(a for a, (k, t) in refs.items()
                       if k == 'call' and t == GATE_SLOT)
        others = [(a, k, t) for a, (k, t) in refs.items()
                  if t == GATE_SLOT and k != 'call']
        if calls != groups[start] or others:
            raise PacketError(f'census validation drift in FDE {_hx(start)}')
        name = family_by_range.get((start, end), f'fde_{start:x}')
        if name not in bodies:
            bodies[name] = {'start': _hx(start), 'end': _hx(end),
                            'size': end - start, 'sha256': dg,
                            'exported': False}
        sites = {}
        addrs = sorted(rows)
        for a in calls:
            binds = _bindings(rows, a)
            i = addrs.index(a)
            post = [rows[x][1] for x in addrs[i + 1:i + 5]]
            flag = _flag_of(binds.get('rcx'))
            flag_counts[str(flag) if flag in (0, 1) else
                        ('register' if flag == 'register' else 'unknown')] += 1
            used = _rdx_used(rows, a)
            rdx_used += 1 if used else 0
            if any('cmov' in t for t in post[:3]):
                select_sites += 1
            sites[_hx(a)] = {'pin': list(rows[a]), 'bindings': binds,
                             'flag': flag, 'post': post,
                             'rdx_used': used}
        census[name] = {'sites': sites}
    for name in FAMILY:
        start, end, _e = BODIES[name]
        _check_pins_subset(decoded[start], _pins(FROZEN['family_pins'][name]),
                           f'family body {name}')
    family_sites = sum(len(census[n]['sites']) for n in FAMILY)
    counters = {
        'bodies': len(bodies),
        'exported_bodies': sum(1 for b in bodies.values() if b['exported']),
        'census_sites': sum(len(c['sites']) for c in census.values()),
        'census_fdes': len(census),
        'family_sites': family_sites,
        'flag_zero': flag_counts['0'],
        'flag_one': flag_counts['1'],
        'flag_register': flag_counts['register'],
        'rdx_used_sites': rdx_used,
        'select_sites': select_sites,
    }
    return {
        'artifact': {'sha256': NODE_SHA256, 'size': NODE_SIZE},
        'upstream_main': UPSTREAM_MAIN,
        'bodies': bodies,
        'slot_facts': slot_facts,
        'gate': gate,
        'unwrap_stub': stub,
        'census': census,
        'counters': counters,
        'decision_rule': (
            'gate(A=rdi, idx=rsi, C=rdx, flag=rcx low byte, '
            'table=r8) -> (rax, rdx): if idx >= [table+0x28] the body '
            'traps through the unwrap stub with the bounds Location '
            '(l1/src/spot_meta.rs:119:33); let d = byte[table_base + '
            'idx*0x158 + 0x49] - byte[table_base + idx*0x158 + 0x48] '
            'as an unsigned byte difference (table_base = [table+0x20]); '
            'if the +0x49 byte is smaller, or d > 19, the body traps '
            'with the scale Location (l1/src/spot_meta.rs:1206:57); '
            'otherwise S = 10^d and Q = (A*C) / (100*S) computed with '
            'the 128-bit divider behind slot 0x64dfaf8, rounded up by '
            'one when flag != 0 and the division leaves a remainder; '
            'the body returns rax = 1 and rdx = Q iff Q < '
            'floor(2^64/100) = 184467440737095516 (which also forces '
            'the quotient high half to zero), and rax = 0 with rdx = Q '
            'otherwise; it stores nothing and reads nothing else'),
        'verdict': (
            'the gate callee is a checked decimal-scaling primitive: '
            'it scales A*C by 10^-d, where d is a per-record byte '
            'difference in the table its fifth argument points to, '
            'and reports whether the result fits the u64/100 bound, '
            'returning the scaled quotient itself in rdx; the two '
            'per-item calls in each inner body guard different terms '
            '(the [element+0x78] product with flag 0, the '
            '[element+0x58] product with flag 1), not the same check '
            'repeated'),
    }


def generate(data, out_dir):
    records = analyze(data)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / 'records.json').write_text(
        json.dumps(records, indent=1, sort_keys=True) + '\n')
    secs = sections(data)
    fdes = _fde_index(data)
    (out_dir / 'frames.txt').write_text(_frames(fdes))
    for name, (start, end, exported) in BODIES.items():
        if exported:
            (out_dir / _export_name(name, start, end)).write_text(
                _body_export(data, start, end))
    return records


def _verify():
    with tempfile.TemporaryDirectory() as tmp:
        generate((ROOT / 'artifacts/node/115/hl-node').read_bytes(), tmp)
        generated = {p.name: p.read_bytes() for p in Path(tmp).iterdir()}
    committed = {p.name: p.read_bytes() for p in PACKET_DIR.iterdir()
                 if p.name != 'README.md' and p.name != 'MANIFEST.sha256'}
    ok = generated == committed
    print(json.dumps({'matches': ok, 'packet': 'RE-006-node115-gate-callee'}))
    return 0 if ok else 1


def main(argv):
    if len(argv) == 3 and argv[1] == 'generate':
        artifact = ROOT / 'artifacts/node/115/hl-node'
        generate(artifact.read_bytes(), argv[2])
        return 0
    if len(argv) == 2 and argv[1] == 'verify':
        return _verify()
    raise SystemExit(
        'usage: gate_callee_static.py (generate <out-dir> | verify)')


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
