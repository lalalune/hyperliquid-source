#!/usr/bin/env python3
"""Static node #94 net_utils TCP frame-write census, checked from authenticated bytes.

Question: across every frame writer that can LZ4-compress a payload, what
compression predicate, compressed-buffer sizing, size prefix, frame header,
write chunk size and default chunk timeout do the instructions implement?

Only the Python standard library is used.  Writers are found as the only
.text sites of the port-mask compare and the only callers of the two lz4_flex
compressor GOT slots, then bounded by parsed .eh_frame FDEs.  Inside each FDE
every fact is an exact instruction sequence that must occur exactly once;
branch, LEA and GOT-slot targets are decoded here and relocations come from
.rela.dyn.  Nothing from the binary is executed.
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
THRESHOLD = 0x401
PORT_MASKED = 0xf9e
SMALL_LIMIT = 0xffff
CHUNK = 4_000_000
DEFAULT_TIMEOUT = 20.0
SLOTS = {'alloc_zeroed': 0x576e298, 'compress_u16_table': 0x5773820, 'compress_u32_table': 0x5773828,
         'lz4_stats_record': 0x5773818}
SLOT_TARGETS = {0x576e298: 0x54c0780, 0x5773820: 0x4e4d600, 0x5773828: 0x4e4dd30, 0x5773818: 0x3d2a730}
UNWRAP_MSG = b'called `Result::unwrap()` on an `Err` value'
DESC = b'tcp_chunk'
WRITERS = (0x204b340, 0x43a17c0, 0x4b363b0)
WRAPPERS = (  # bincode wrappers: (call VA, store of [arg+0], store of 60.0 to [arg+8], arg-base LEA)
    dict(fde=0x204b0a0, call=0x204b123, tag=(0x204b0f4, '48c7431000000000'),
         secs=(0x204b0fc, '48b8000000000000' '4e40' '48894318'), base=(0x204b11c, '4c8d6310' '4c89e7')),
    dict(fde=0x204b1f0, call=0x204b273, tag=(0x204b244, '48c7431000000000'),
         secs=(0x204b24c, '48b8000000000000' '4e40' '48894318'), base=(0x204b26c, '4c8d6310' '4c89e7')),
)

R = rb'[\x40-\x4f]'
SIG = {
    # cmp r12,0x401; jb raw
    'threshold': rb'\x49\x81\xfc\x01\x04\x00\x00\x0f\x82(....)',
    # movzx eax,WORD [r?+0x90]; and eax,0xfffffffe; movzx eax,ax; cmp eax,0xf9e; je raw
    'port': rb'\x41?\x0f\xb7[\x80-\x87]\x90\x00\x00\x00\x83\xe0\xfe\x0f\xb7\xc0\x3d\x9e\x0f\x00\x00\x0f\x84(....)',
    # mov ecx,110; mov rax,r12; mul rcx; jo; shr rax,2; mov rcx,M; mul rcx; mov r15,rdx; shr r15,2;
    # lea rsi,[r15+0x18]; mov edi,1; mov [rsp+X],rsi; call [rip+slot]
    'capacity': (rb'\xb9\x6e\x00\x00\x00\x4c\x89\xe0\x48\xf7\xe1\x0f\x80....\x48\xc1\xe8\x02'
                 rb'\x48\xb9\xc3\xf5\x28\x5c\x8f\xc2\xf5\x28\x48\xf7\xe1\x49\x89\xd7\x49\xc1\xef\x02'
                 rb'\x49\x8d\x77\x18\xbf\x01\x00\x00\x00\x48\x89\x74\x24.\xff\x15(....)'),
    # test rax,rax; je; [mov r13,rax]; mov [rax],r12d; add r15,0x14
    'prefix': rb'\x48\x85\xc0\x0f\x84....(?:\x49\x89\xc5)?\x44\x89\x20\x49\x83\xc7\x14',
    # cmp r12,0xffff; jae big
    'table_split': rb'\x49\x81\xfc\xff\xff\x00\x00\x0f\x83(....)',
    # mov r15d,size; mov edi,1; mov esi,size; call [rip+alloc]
    'table_small': rb'\x41\xbf\x00\x20\x00\x00\xbf\x01\x00\x00\x00\xbe\x00\x20\x00\x00\xff\x15(....)',
    'table_big': rb'\x41\xbf\x00\x40\x00\x00\xbf\x01\x00\x00\x00\xbe\x00\x40\x00\x00\xff\x15(....)',
    # test r15b,1; jne unwrap-panic; cmp rX,-5; [mov rax,[rsp+X]]; ja; add rX,4
    'compressed_len': (rb'\x41\xf6\xc7\x01\x0f\x85(....)\x49\x83[\xfd\xfe]\xfb(?:\x48\x8b\x44\x24.)?'
                       rb'\x0f\x87....\x49\x83[\xc5\xc6]\x04'),
    # shr rax,32; je ok
    'u32_check': rb'\x48\xc1\xe8\x20\x74(.)',
    # bswap r12d ... mov [rax],r12d
    'be_length': rb'\x41\x0f\xcc(?:\x48\xc7\x43\x58\x04\x00\x00\x00\x48\x89\x43\x60|'
                 rb'\x48\xc7\x83\xa8\x02\x00\x00\x04\x00\x00\x00\x48\x89\x83\xb0\x02\x00\x00)\x44\x89\x20',
    # mov BYTE [rax+4],r14b|r13b; mov QWORD [rbx+X],5
    'flag_byte': rb'\x44\x88[\x70\x68]\x04\x48\xc7[\x43\x83](?:.|....)\x05\x00\x00\x00',
    # add r15,0x40; mov r14b|r13b,1   (before the lz4 stats call on the compressed path)
    'flag_compressed': rb'\x49\x83\xc7\x40\x41[\xb6\xb5]\x01',
    # call [memcpy] of the raw payload; xor r14d|r13d
    'flag_raw': rb'\xff\x15....\x45\x31[\xf6\xed]',
    # mov QWORD [rbx+X],4000000
    'chunk_size': rb'\x48\xc7[\x43\x83](.|....)\x00\x09\x3d\x00',
    # mov rcx,[rbx+X]; cmp rcx,rax; cmovae rcx,rax
    'chunk_min': rb'\x48\x8b\x8b(....)\x48\x39\xc1\x48\x0f\x43\xc8',
    # cmp BYTE [rbx+X],0; jne +8; movsd xmm0,[rip+const]
    'timeout_default': rb'\x80[\x7b\xbb](?:.|....)\x00\x75\x08\xf2\x0f\x10\x05(....)',
}


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
        rela = next((s for s in self.secs if s['name'] == '.rela.dyn' and s['type'] == 4), None)
        require(rela is not None and rela['size'] % 24 == 0, 'no well-formed .rela.dyn')
        self.relative = {}
        for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
            where, info, addend = struct.unpack_from('<QQq', data, pos)
            if info & 0xffffffff == 8:
                self.relative[where] = addend
        _, fdes = eh_frame_records(data, self.secs)
        self.fdes = sorted((f['start'], f['end']) for f in fdes)

    def offset(self, va, size=1):
        hits = [s for s in self.secs if s['type'] != 8 and s['address'] and
                s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(hits) == 1, f'VA {va:#x}+{size} is not in exactly one file-backed section')
        return hits[0]['offset'] + va - hits[0]['address']

    def read(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off + size]

    def fde(self, start):
        hits = [f for f in self.fdes if f[0] == start]
        require(len(hits) == 1, f'{start:#x} is not exactly one FDE start')
        return hits[0]

    def fde_of(self, va):
        hits = [f for f in self.fdes if f[0] <= va < f[1]]
        return hits[0][0] if len(hits) == 1 else None

    def expect(self, va, want, what):
        want = bytes.fromhex(want) if isinstance(want, str) else want
        require(self.read(va, len(want)) == want, f'{what} at {va:#x}: bytes changed')

    def rel32(self, va, length):
        return va + length + struct.unpack('<i', self.read(va + length - 4, 4))[0]

    def text_bytes(self):
        t = self.text
        return t['address'], self.data[t['offset']:t['offset'] + t['size']]

    def rip_refs(self, prefixes, target, length):
        base, text = self.text_bytes()
        out = []
        for m in re.finditer(prefixes, text):
            o = m.start()
            if o + length <= len(text) and base + o + length + struct.unpack_from('<i', text, o + length - 4)[0] == target:
                out.append(base + o)
        return out


def one(img, fde, name):
    lo, hi = fde
    blob = img.read(lo, hi - lo)
    hits = list(re.finditer(SIG[name], blob, re.S))
    require(len(hits) == 1, f'{name} signature occurs {len(hits)} times in writer {lo:#x}')
    m = hits[0]
    return lo + m.start(), m


def rel_at(va, m, group, base_off):
    """Target of a rel32/rel8 whose displacement is regex group `group`, the instruction ending after it."""
    raw = m.group(group)
    disp = struct.unpack('<i' if len(raw) == 4 else '<b', raw)[0]
    return va + (m.end(group) - m.start()) + disp + base_off


def slot_of(img, va, m, group):
    slot = rel_at(va, m, group, 0)
    require(slot in img.relative, f'call near {va:#x} reads unrelocated slot {slot:#x}')
    return slot


def check_writer(img, start):
    fde = img.fde(start)
    rec = {'fde': [hex(fde[0]), hex(fde[1])], 'bytes': fde[1] - fde[0]}
    va, m = one(img, fde, 'threshold')
    raw_path = rel_at(va, m, 1, 0)
    rec['threshold'] = {'compare': hex(va), 'raw_when': f'len < {THRESHOLD:#x}', 'raw_path': hex(raw_path)}
    va, m = one(img, fde, 'port')
    require(rel_at(va, m, 1, 0) == raw_path, 'port check does not share the raw path')
    require(va > int(rec['threshold']['compare'], 16), 'port check precedes the length threshold')
    rec['port'] = {'compare': hex(va), 'field': '[stream+0x90] u16', 'raw_when': f'(port & 0xfffe) == {PORT_MASKED:#x}',
                   'ports': [PORT_MASKED, PORT_MASKED + 1]}
    va, m = one(img, fde, 'capacity')
    slot = slot_of(img, va, m, 1)
    require(slot == SLOTS['alloc_zeroed'], 'compressed buffer allocation slot changed')
    rec['capacity'] = {'sequence': hex(va), 'bytes': '24 + len * 110 / 100', 'alloc_slot': hex(slot),
                       'overflow_checked': True}
    va, m = one(img, fde, 'prefix')
    require(0 < va - int(rec['capacity']['sequence'], 16) < 0x60, 'prefix store is not after the buffer allocation')
    rec['prefix'] = {'store': hex(va + m.end() - m.start() - 7),
                     'value': 'len as u32 (low 32 bits), little-endian', 'output_window': 'buffer+4, len*110/100 + 20'}
    va, m = one(img, fde, 'table_split')
    big = rel_at(va, m, 1, 0)
    sva, sm = one(img, fde, 'table_small')
    bva, bm = one(img, fde, 'table_big')
    require(sva == va + 13, 'small hash table allocation does not follow the split')
    require(bva == big, 'large hash table allocation is not the split target')
    for tva, tm in ((sva, sm), (bva, bm)):
        require(slot_of(img, tva, tm, 1) == SLOTS['alloc_zeroed'], 'hash table allocation slot changed')
    small_call = slot_calls_in(img, (sva, sva + 0x60), SLOTS['compress_u16_table'])
    big_call = slot_calls_in(img, (bva, bva + 0x60), SLOTS['compress_u32_table'])
    require(len(small_call) == 1 and len(big_call) == 1, 'compressor call does not follow its hash table')
    rec['hash_table'] = {'split': hex(va), 'small_when': f'len < {SMALL_LIMIT:#x}',
                         'small': {'bytes': 0x2000, 'compressor_call': hex(small_call[0])},
                         'large': {'bytes': 0x4000, 'compressor_call': hex(big_call[0])}}
    va, m = one(img, fde, 'compressed_len')
    panic = rel_at(va, m, 1, 0)
    require(UNWRAP_MSG in unwrap_lea_text(img, panic), f'compress error at {va:#x} does not reach Result::unwrap panic')
    rec['compress_result'] = {'error_test': hex(va), 'on_error': 'Result::unwrap panic', 'len': 'compressed + 4'}
    stats = slot_calls_in(img, fde, SLOTS['lz4_stats_record'])
    require(len(stats) == 1, 'lz4 stats record call count changed')
    rec['stats_call'] = hex(stats[0])
    va, m = one(img, fde, 'u32_check')
    rec['u32_check'] = {'shr': hex(va), 'ok': hex(va + 6 + struct.unpack('<b', m.group(1))[0]),
                        'rejects': 'payload len >= 2**32'}
    va, m = one(img, fde, 'be_length')
    rec['header'] = {'bswap': hex(va), 'length': 'payload len, u32 big-endian at +0'}
    fva, fm = one(img, fde, 'flag_byte')
    require(0 < fva - va < 0x60, 'flag byte store is not after the length store')
    reg = {0x70: ('r14', 0xb6, 0xf6), 0x68: ('r13', 0xb5, 0xed)}[fm.group(0)[2]]
    cva_, _ = one(img, fde, 'flag_compressed')
    rva_, _ = one(img, fde, 'flag_raw')
    require(img.read(cva_ + 5, 1)[0] == reg[1] and img.read(rva_ + 8, 1)[0] == reg[2],
            f'flag register {reg[0]} is not the one set to 1 (compressed) and 0 (raw)')
    require(cva_ < int(rec['stats_call'], 16) < cva_ + 0x20, 'flag=1 is not on the compressed (stats) path')
    rec['header']['flag_set'] = {'compressed': hex(cva_ + 4), 'raw': hex(rva_ + 6), 'register': reg[0]}
    rec['header']['flag_store'] = hex(fva)
    rec['header']['flag'] = '1 compressed, 0 raw, at +4; payload from +5'
    va, m = one(img, fde, 'chunk_size')
    require(0 < va - fva < 0x80, 'chunk size store is not after the frame build')
    rec['chunking'] = {'chunk_size_store': hex(va), 'chunk_bytes': CHUNK}
    cva, cm = one(img, fde, 'chunk_min')
    rec['chunking']['chunk_min'] = hex(cva)
    rec['chunking']['chunk'] = 'min(remaining, chunk_bytes)'
    tva, tm = one(img, fde, 'timeout_default')
    cmp = img.read(tva, 7)
    flag_disp = cmp[2] if cmp[1] == 0x7b else struct.unpack('<i', cmp[2:6])[0]
    seconds_disp = flag_disp + 8
    load = (bytes.fromhex('f20f1043') + bytes([seconds_disp]) if seconds_disp < 0x80 else
            bytes.fromhex('f20f1083') + struct.pack('<i', seconds_disp))
    require(load in img.read(tva - 0x18, 0x18), 'timeout seconds are not loaded from flag field + 8')
    const = rel_at(tva, tm, 1, 0)
    value = struct.unpack('<d', img.read(const, 8))[0]
    require(value == DEFAULT_TIMEOUT, f'default chunk timeout is {value}')
    require(0 < tva - cva < 0x80, 'timeout selection is not in the chunk loop')
    desc_va, desc_lit = chunk_descriptor(img, (tva, tva + 0x40))
    rec['timeout'] = {'select': hex(tva), 'default_seconds': value, 'default_const': hex(const),
                      'rule': 'arg[+8] f64 if byte arg[+0] != 0, else default', 'descriptor_lea': hex(desc_va),
                      'descriptor': desc_lit}
    return rec


def unwrap_lea_text(img, va):
    b = img.read(va, 7)
    require(b[:2] == b'\x48\x8d' and b[2] & 0xc7 == 0x05, f'no message LEA at panic {va:#x}')
    target = img.rel32(va, 7)
    return img.read(target, len(UNWRAP_MSG))


def slot_calls_in(img, rng, slot):
    lo, hi = rng
    blob = img.read(lo, hi - lo)
    out = []
    for m in re.finditer(rb'\xff\x15', blob):
        va = lo + m.start()
        if m.start() + 6 <= len(blob) and va + 6 + struct.unpack_from('<i', blob, m.start() + 2)[0] == slot:
            out.append(va)
    return out


def chunk_descriptor(img, rng):
    lo, hi = rng
    blob = img.read(lo, hi - lo)
    for m in re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', blob):
        va = lo + m.start()
        target = img.rel32(va, 7)
        try:
            text = img.read(target, len(DESC))
        except EvidenceError:
            continue
        if text == DESC:
            tail = blob[m.end() + 4:m.end() + 4 + 0x30]
            require(re.search(rb'\x48\xc7[\x43\x83](?:.|....)\x09\x00\x00\x00', tail, re.S), 'descriptor length is not 9')
            return va, DESC.decode()
    raise EvidenceError(f'no tcp_chunk descriptor LEA after {lo:#x}')


def check_wrappers(img):
    rows = []
    for w in WRAPPERS:
        fde = img.fde(w['fde'])
        require(fde[0] <= w['call'] < fde[1], 'wrapper call outside its FDE')
        img.expect(w['call'], 'e8', 'writer call')
        require(img.rel32(w['call'], 5) == WRITERS[0], 'wrapper no longer calls the first writer')
        for key in ('tag', 'secs', 'base'):
            va, hexbytes = w[key]
            img.expect(va, hexbytes, f'wrapper {key}')
        require(w['tag'][0] < w['secs'][0] < w['base'][0] < w['call'], 'wrapper argument stores out of order')
        rows.append({'fde': hex(fde[0]), 'call': hex(w['call']), 'arg_base': '[rbx+0x10]', 'arg0': 0, 'arg8_seconds': 60.0,
                     'chunk_timeout_selected': DEFAULT_TIMEOUT})
    return rows


def check_inline_pair(img):
    """The inline writer 0x4b363b0 builds its own (flag, seconds) pair before the compression decision."""
    img.expect(0x4b3759a, '31c0', 'xor eax,eax (flag = 0)')
    img.expect(0x4b375a3, 'f20f108358020000', 'seconds from [rbx+0x258]')
    img.expect(0x4b375ab, '48898380020000' 'f20f118388020000', 'pair store to [rbx+0x280]/[rbx+0x288]')
    return {'writer': '0x4b363b0', 'flag_store': '0x4b375ab', 'flag': 0, 'seconds_source': '[rbx+0x258]',
            'chunk_timeout_selected': DEFAULT_TIMEOUT}


INLINE_POLL_CALL = 0x4b5fbc6
ARG_STORE0 = re.compile(rb'\x48\xc7(?:\x43(.)|\x83(....))(....)', re.S)
ARG_SECS = re.compile(rb'\x48([\xb8-\xbf])\x00{6}\x4e\x40', re.S)
ARG_BASE = re.compile(rb'([\x48\x4c])\x8d(?:([\x43-\x7b])(.)|([\x83-\xbb])(....))([\x48\x4c])\x89([\xc0-\xff])', re.S)


def disp(short, long_):
    return struct.unpack('<b', short)[0] if short is not None else struct.unpack('<i', long_)[0]


def caller_arg(img, call):
    """Decode `mov QWORD [rbx+D],imm; movabs r,60.0; mov [rbx+D+8],r; ...; lea R,[rbx+D]; mov rdi,R` before a writer call."""
    lo = call - 0x50
    win = img.read(lo, call - lo)
    tags = [(lo + m.start(), disp(m.group(1), m.group(2)), struct.unpack('<i', m.group(3))[0]) for m in ARG_STORE0.finditer(win)]
    secs = [(lo + m.start(), m.group(1)[0] - 0xb8) for m in ARG_SECS.finditer(win)]
    require(len(secs) == 1, f'writer call {call:#x}: {len(secs)} movabs 60.0 loads')
    sva, sreg = secs[0]
    rows = []
    for m in ARG_BASE.finditer(win):
        rex, m8, d8, m32, d32, rex2, mrm = m.groups()
        modrm = (m8 or m32)[0]
        reg = ((modrm >> 3) & 7) | (8 if rex == b'\x4c' else 0)
        if modrm & 7 != 3 or rex2 != rex or (mrm[0] >> 3) & 7 != reg & 7 or mrm[0] & 7 != 7:
            continue
        rows.append((lo + m.start(), disp(d8, d32)))
    require(len(rows) == 1, f'writer call {call:#x}: {len(rows)} lea R,[rbx+D]; mov rdi,R pairs')
    bva, base = rows[0]
    tag = [t for t in tags if t[1] == base]
    require(len(tag) == 1, f'writer call {call:#x}: no unique store to [rbx+{base:#x}]')
    store8 = (b'\x48\x89' + bytes([0x43 | (sreg << 3)]) + struct.pack('<b', base + 8)) if -128 <= base + 8 < 128 else \
        (b'\x48\x89' + bytes([0x83 | (sreg << 3)]) + struct.pack('<i', base + 8))
    s8 = win.find(store8, sva - lo)
    require(s8 >= 0 and win.find(store8, s8 + 1) < 0, f'writer call {call:#x}: 60.0 not stored to [rbx+{base + 8:#x}]')
    require(tag[0][0] < bva and sva < lo + s8 < bva, f'writer call {call:#x}: argument stores out of order')
    flag = tag[0][2]
    return {'call': hex(call), 'owner_fde': hex(img.fde_of(call)), 'arg_base': f'[rbx+{base:#x}]',
            'arg0_store': hex(tag[0][0]), 'arg0': flag, 'arg8_seconds': 60.0, 'arg8_store': hex(lo + s8),
            'chunk_timeout_selected': 60.0 if flag & 0xff else DEFAULT_TIMEOUT}


CALL_LABELS = {  # writer call -> (lea rcx,[rip+label], mov r8d,len, helper call) before the pair build
    0x1fd7930: (0x1fd786f, 0x1fd78a0, 0x1fd78f3, b'write evm kv batch'),
    0x203812e: (0x2038096, 0x20380cd, 0x20380df, b'abci_stream send tcp greeting'),
    0x20399f7: (0x203995c, 0x2039993, 0x20399a8, b'send gossip rpc request'),
    0x438384e: (0x43837b6, 0x43837ed, 0x43837ff, b'abci_stream send tcp greeting'),
    0x43888d7: (0x438883c, 0x4388873, 0x4388888, b'send gossip rpc request'),
}


def call_label(img, call, arg0_store):
    lea, r8, helper, text = CALL_LABELS[call]
    img.expect(lea, '488d0d', 'label lea rcx,[rip+X]')
    target = img.rel32(lea, 7)
    require(img.read(target, len(text)) == text, f'label at {target:#x} is not {text!r}')
    img.expect(r8, '41b8' + struct.pack('<I', len(text)).hex(), 'label length in r8d')
    img.expect(helper, 'e8', 'label helper call')
    require(lea < r8 < helper < arg0_store and arg0_store - helper <= 0x30, f'label setup for {call:#x} out of order')
    return {'label': text.decode(), 'label_va': hex(target), 'helper': hex(img.rel32(helper, 5)), 'helper_call': hex(helper)}


def check_callers(img):
    """Every direct call to a writer in .text: decoded argument pair, or the inline future's poll."""
    base, text = img.text_bytes()
    calls = []
    for m in re.finditer(rb'\xe8', text):
        va = base + m.start()
        if m.start() + 5 <= len(text) and img.rel32(va, 5) in WRITERS:
            calls.append(va)
    wrapper_calls = {w['call'] for w in WRAPPERS}
    require(wrapper_calls <= set(calls), 'wrapper calls missing from direct-call census')
    rows = []
    for call in calls:
        if call in wrapper_calls:
            continue
        target = img.rel32(call, 5)
        if call == INLINE_POLL_CALL:
            require(target == WRITERS[2], 'inline poll call retargeted')
            rows.append({'call': hex(call), 'owner_fde': hex(img.fde_of(call)), 'target': hex(target),
                         'arg': 'future state passed through (pair built inside, see inline_pair)'})
            continue
        require(target != WRITERS[2], f'unexpected direct call {call:#x} to the inline writer')
        row = caller_arg(img, call)
        row['target'] = hex(target)
        if call in CALL_LABELS:
            row.update(call_label(img, call, int(row['arg0_store'], 16)))
        rows.append(row)
    require(len(calls) == 12, f'direct writer call census {[hex(c) for c in calls]}')
    return rows


def census(img):
    base, text = img.text_bytes()
    port = [base + m.start() for m in re.finditer(rb'\x3d\x9e\x0f\x00\x00', text)]
    out = {'port_compares': [hex(v) for v in port]}
    for name in ('compress_u16_table', 'compress_u32_table', 'lz4_stats_record'):
        out[name] = [hex(v) for v in img.rip_refs(rb'\xff[\x15\x25]', SLOTS[name], 6)]
    for name, slot in SLOTS.items():
        require(img.relative.get(slot) == SLOT_TARGETS[slot], f'GOT slot {name} relocation changed')
    owners = sorted({img.fde_of(v) for v in port})
    require(owners == list(WRITERS) and len(port) == 3, f'port-mask census {[hex(v) for v in port]}')
    for name in ('compress_u16_table', 'compress_u32_table'):
        require(sorted(img.fde_of(int(v, 16)) for v in out[name]) == sorted(WRITERS), f'{name} caller census changed')
    out['lz4_stats_record_owner_fdes'] = sorted({hex(img.fde_of(int(v, 16))) for v in out['lz4_stats_record']})
    return out


def analyse(data):
    img = Image(data)
    c = census(img)
    writers = [check_writer(img, w) for w in WRITERS]
    require(writers[2]['timeout']['select'] == '0x4b386bb', 'inline writer timeout selection moved')
    return {'census': c, 'writers': writers, 'wrappers': check_wrappers(img), 'inline_pair': check_inline_pair(img),
            'callers': check_callers(img), 'model': model_summary()}


# Transcribed model of the observed decisions; it does not compress.
def compresses(length, port):
    return length >= THRESHOLD and (port & 0xfffe) != PORT_MASKED


def compressed_capacity(length):
    return 24 + length * 110 // 100


def binary_div100(x):
    """The instruction sequence: ((x >> 2) * 0x28f5c28f5c28f5c3) >> 64 >> 2."""
    return (((x >> 2) * 0x28f5c28f5c28f5c3) >> 64) >> 2


def size_prefix(length):
    return (length & 0xffffffff).to_bytes(4, 'little')


def frame_header(payload_len, compressed):
    if payload_len >> 32:
        return None
    return payload_len.to_bytes(4, 'big') + bytes([1 if compressed else 0])


def chunks(total):
    return [min(CHUNK, total - off) for off in range(0, total, CHUNK)]


def reference_capacity(length):
    """can1357 net_utils/tcp/write.rs `compress_payload_prepend_size` initial reserve."""
    return 4 + max(0x2000 if length < SMALL_LIMIT else 0x4000, length)


def reference_prefix(length):
    return min(length, 0xffffffff).to_bytes(4, 'little')


MODEL_LENGTHS = (0, 1, 0x400, 0x401, 0xfffe, 0xffff, CHUNK, CHUNK + 1, 1 << 32, (1 << 32) + 5)


def model_summary():
    rows = []
    for n in MODEL_LENGTHS:
        rows.append({'len': n, 'compresses_any_port': compresses(n, 4001), 'compresses_port_3998': compresses(n, 3998),
                     'capacity': compressed_capacity(n), 'reference_capacity': reference_capacity(n),
                     'prefix': size_prefix(n).hex(), 'reference_prefix': reference_prefix(n).hex(),
                     'wire_chunks_for_raw_frame': len(chunks(5 + n)) if n < (1 << 32) else None})
    return {'rows': rows,
            'capacity_differs': sum(r['capacity'] != r['reference_capacity'] for r in rows),
            'prefix_differs': sum(r['prefix'] != r['reference_prefix'] for r in rows)}


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
    print(json.dumps({'writers': len(result['writers']), 'wrappers': len(result['wrappers']),
                      'callers_60s': sum(r.get('chunk_timeout_selected') == 60.0 for r in result['callers']),
                      'capacity_differs': result['model']['capacity_differs'],
                      'prefix_differs': result['model']['prefix_differs']}, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
