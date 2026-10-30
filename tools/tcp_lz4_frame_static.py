#!/usr/bin/env python3
"""Static node #94 TCP LZ4 frame-payload decoder, checked from authenticated bytes.

Question: when a net_utils TCP frame has compression flag 1, what limit, prefix
format, allocation and error classes does the shared decompressor behind GOT
slot 0x5773810 implement, and which max_len does each frame reader pass it?

Only the Python standard library is used.  The decompressor is bound through
its R_X86_64_RELATIVE GOT slot and its .eh_frame FDE; every indirect call
through the slot in .text is counted.  Each fact is a fixed instruction
encoding at a pinned VA whose branch, LEA and GOT-slot targets are decoded
here; memory operands at the call sites are decoded from ModRM/SIB bytes.
Nothing from the binary is executed.
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
SLOT = 0x5773810
DECOMP = 0x3d1abc0
ALLOC_SLOT = 0x576e298
LZ4_PATH = b'/home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/lz4_flex-'
LZ4_VERSION = '0.11.6'
TEMPLATES = {
    'over_limit': (0x1ee8cb, b'$lz4 bytes over limit @@ [buf.len(): \xc0\x18] @ [uncompressed_size: \xc0\x0e]'
                             b' @ [max_len: \xc0\x01]'),
    'failure': (0x20101d, b'\x18decompress_lz4 failure: \xc0\x00'),
}
# lz4_flex 0.11.6 src/block/mod.rs `DecompressError` declaration order (no repr).
DECOMPRESS_ERRORS = ('OutputTooSmall', 'LiteralOutOfBounds', 'ExpectedAnotherByte', 'OffsetZero',
                     'OffsetOutOfBounds')
COMMON_ERROR = 0x3d1b309
# (VA of mov r14d,imm32 or xor r14d,r14d, VA of the jmp/fallthrough reaching COMMON_ERROR, the branch
#  that selects it, expected tag)
ERROR_SITES = (
    dict(tag_va=0x3d1b431, tag=0, join=0x3d1b434, branch=(0x3d1afab, '4939de', 0x3d1afae, 'ja'), entry=0x3d1b42e),
    dict(tag_va=0x3d1b444, tag=1, join=0x3d1b44a, branch=(0x3d1b06e, '4839c5', 0x3d1b071, 'ja'), entry=0x3d1b444),
    dict(tag_va=0x3d1b303, tag=2, join=None, branch=None, entry=0x3d1b303),
    dict(tag_va=0x3d1b2ef, tag=3, join=0x3d1b2f5, branch=(0x3d1ad46, '4885d2', 0x3d1ad49, 'je'), entry=0x3d1b2ec),
    dict(tag_va=0x3d1b2c7, tag=4, join=0x3d1b2cd, branch=(0x3d1ad55, '4829d7', 0x3d1ad58, 'jb'), entry=0x3d1b2c7),
)
OVER_LIMIT_ARGS = bytes.fromhex(
    '4c89bc24c0000000'      # mov [rsp+0xc0],r15        buf.len()
    '488d8424c0000000' '48898424b8000000'
    '488d8424b0000000' '48898424c8000000'
    '488d8424a8000000' '4889442440'
    '488d8424b8000000' '4889442450')
OVER_LIMIT_ARG_SLOTS = bytes.fromhex('488d8c24c8000000' '48894c2460')  # at 0x3d1b534
OVER_LIMIT_ARG3 = bytes.fromhex('488d4c2440' '48894c2470')               # at 0x3d1b546

# Frame-reader call sites.  `admit`: the read.rs length-admission compare (tools/tcp_frame_read_static.py);
# `flag_store`: the sete of the compression flag; `gate`: flag test immediately before the call;
# `loads`: mov rcx/rsi/rdx,[base+disp]; `link`: a mov copying the admission base into the call base.
CALLERS = (
    dict(fde=0x2049950, admit=0x204a0b5, flag_store=0x204a1dd, gate=0x204aaa5, loads=(0x204aabe, 0x204aac2, 0x204aac6),
         call=0x204aad2, result=0x204aaf2),
    dict(fde=0x43a0260, admit=0x43a09c5, flag_store=0x43a0aed, gate=0x43a13b5, loads=(0x43a13ce, 0x43a13d2, 0x43a13d6),
         call=0x43a13e2, result=0x43a1402),
    dict(fde=0x4b72900, admit=0x4b7320b, flag_store=0x4b73219, gate=0x4b73a20, loads=(0x4b73a39, 0x4b73a3d, 0x4b73a41),
         call=0x4b73a4d, result=0x4b73a6d),
    dict(fde=0x22615b0, admit=0x2263e9d, flag_store=0x2263eac, gate=0x2264ea8, loads=(0x2264ec4, 0x2264ec9, 0x2264ece),
         call=0x2264edb, result=0x2264efb),
    dict(fde=0x4744160, admit=0x4747019, flag_store=0x474702a, gate=0x474708f, loads=(0x47470ac, 0x47470b3, 0x47470ba),
         call=0x47470c9, result=0x47470e9, link=(0x4747039, '4989cf')),
)
REGS = ('rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
        'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15')


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

    def expect(self, va, want, what):
        want = bytes.fromhex(want) if isinstance(want, str) else want
        require(self.read(va, len(want)) == want, f'{what} at {va:#x}: bytes changed')

    def rel32(self, va, length):
        return va + length + struct.unpack('<i', self.read(va + length - 4, 4))[0]

    def jcc(self, va, kind):
        op = {'jb': 0x82, 'jae': 0x83, 'je': 0x84, 'jne': 0x85, 'jbe': 0x86, 'ja': 0x87}[kind]
        b = self.read(va, 2)
        if b[0] == 0x70 + (op - 0x80):
            return va + 2 + struct.unpack('<b', b[1:2])[0]
        require(b == bytes((0x0f, op)), f'no {kind} at {va:#x}')
        return self.rel32(va, 6)

    def jmp(self, va):
        b = self.read(va, 1)[0]
        if b == 0xeb:
            return va + 2 + struct.unpack('<b', self.read(va + 1, 1))[0]
        require(b == 0xe9, f'no jmp at {va:#x}')
        return self.rel32(va, 5)

    def call(self, va):
        self.expect(va, 'e8', 'direct call')
        return self.rel32(va, 5)

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
        require(ptr is not None, f'Location {va:#x} has no relocated path pointer')
        size, line, col = struct.unpack('<QII', self.read(va + 8, 16))
        return self.read(ptr, size), line, col

    def text_bytes(self):
        t = self.text
        return t['address'], self.data[t['offset']:t['offset'] + t['size']]


def mem_operand(img, va):
    """Decode `[optional REX] opcode... ModRM [SIB] disp` for the forms used here.

    Returns (mnemonic, reg field, base register, displacement, length)."""
    b = img.read(va, 12)
    pos, rex = 0, 0
    if 0x40 <= b[0] <= 0x4f:
        rex, pos = b[0], 1
    if b[pos] == 0x0f:
        opcode, pos = b[pos:pos + 2].hex(), pos + 2
    else:
        opcode, pos = b[pos:pos + 1].hex(), pos + 1
    names = {'39': 'cmp_rm_r', '8b': 'mov_r_rm', '80': 'grp1_rm8_imm8', '0f94': 'sete_rm8'}
    require(opcode in names, f'unexpected opcode {opcode} at {va:#x}')
    modrm = b[pos]
    pos += 1
    mod, reg, rm = modrm >> 6, (modrm >> 3) & 7, modrm & 7
    require(mod in (1, 2), f'operand at {va:#x} is not [base+disp]')
    if rm == 4:
        sib = b[pos]
        pos += 1
        require(sib & 0x3f == 0x24, f'operand at {va:#x} uses an index register')
        rm = sib & 7
    base = rm + (8 if rex & 1 else 0)
    if mod == 1:
        disp = struct.unpack('<b', b[pos:pos + 1])[0]
        pos += 1
    else:
        disp = struct.unpack('<i', b[pos:pos + 4])[0]
        pos += 4
    reg += 8 if rex & 4 else 0
    if opcode == '80':
        pos += 1
    return names[opcode], reg, REGS[base], disp, pos


def slot_calls(img):
    base, text = img.text_bytes()
    out = []
    for m in re.finditer(rb'\xff[\x15\x25]', text):
        va = base + m.start()
        if m.start() + 6 <= len(text) and va + 6 + struct.unpack_from('<i', text, m.start() + 2)[0] == SLOT:
            out.append(va)
    return out


def direct_refs(img, target):
    base, text = img.text_bytes()
    out = []
    for m in re.finditer(rb'[\xe8\xe9]', text):
        o = m.start()
        if o + 5 <= len(text) and base + o + 5 + struct.unpack_from('<i', text, o + 1)[0] == target:
            out.append(base + o)
    return out


def lea_census(img, targets):
    base, text = img.text_bytes()
    hits = {t: [] for t in targets}
    for m in re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', text):
        o = m.start()
        if o + 7 <= len(text):
            t = base + o + 7 + struct.unpack_from('<i', text, o + 3)[0]
            if t in hits:
                hits[t].append(base + o)
    return hits


def check_entry(img):
    img.expect(0x3d1abd1, '48898c24a8000000', 'max_len (rcx) spill to [rsp+0xa8]')
    img.expect(0x3d1abd9, '4883fa03', 'input length compare with 3')
    short = img.jcc(0x3d1abdd, 'jbe')
    img.expect(short, '48c744245002000000', 'short-input error tag')
    require(img.call(short + 17) == 0x3d26e80, 'short-input error constructor retargeted')
    img.expect(0x3d1abe3, '4989d7', 'input length kept in r15')
    img.expect(0x3d1abee, '8b1e', 'little-endian u32 prefix load mov ebx,[rsi]')
    window = img.read(0x3d1abee, 0x3d1abfb - 0x3d1abee)
    require(not re.search(rb'\x0f[\xc8-\xcf]', window), 'byte swap between prefix load and limit compare')
    img.expect(0x3d1abf0, '48899c24b0000000', 'uncompressed_size spill to [rsp+0xb0]')
    img.expect(0x3d1abf8, '4839d9', 'cmp rcx(max_len), rbx(uncompressed_size)')
    over = img.jcc(0x3d1abfb, 'jb')
    img.expect(0x3d1ac01, '4885db', 'zero-size test')
    zero = img.jcc(0x3d1ac09, 'je')
    img.expect(0x3d1ac0b, 'bf01000000' '4889de', 'alloc(1, uncompressed_size) arguments')
    slot, callee = img.call_slot(0x3d1ac13)
    require(slot == ALLOC_SLOT, 'decoded-buffer allocation slot changed')
    return {
        'short_input': {'compare': '0x3d1abd9', 'rejects_len_at_most': 3, 'target': hex(short),
                        'error_tag': 2, 'error': DECOMPRESS_ERRORS[2], 'constructor': '0x3d26e80'},
        'prefix': {'load': '0x3d1abee', 'width_bits': 32, 'byte_order': 'little', 'offset': 0},
        'limit': {'compare': '0x3d1abf8', 'branch': '0x3d1abfb', 'rejects': 'max_len < uncompressed_size',
                  'equal_admitted': True, 'over_target': hex(over), 'before_allocation': True},
        'allocation': {'zero_size_test': '0x3d1ac01', 'zero_size_target': hex(zero), 'call': '0x3d1ac13',
                       'slot': hex(slot), 'callee': hex(callee), 'args': ['1', 'uncompressed_size']},
    }


def check_over_limit(img, over):
    require(over == 0x3d1b4e6, f'over-limit path moved to {over:#x}')
    img.expect(over, OVER_LIMIT_ARGS, 'over-limit argument array')
    img.expect(0x3d1b534, OVER_LIMIT_ARG_SLOTS, 'over-limit argument 2 slot')
    img.expect(0x3d1b546, OVER_LIMIT_ARG3, 'over-limit argument 3 slot')
    va, text = TEMPLATES['over_limit']
    require(img.lea_target(0x3d1b555) == va, 'over-limit template LEA retargeted')
    require(img.call(0x3d1b575) == 0x3d26ab0, 'over-limit error constructor retargeted')
    return {'template': hex(va), 'template_lea': '0x3d1b555', 'constructor': '0x3d26ab0',
            'arguments_in_order': [{'name': 'buf.len()', 'value': 'input length (r15, [rsp+0xc0])'},
                                   {'name': 'uncompressed_size', 'value': 'prefix ([rsp+0xb0])'},
                                   {'name': 'max_len', 'value': 'caller rcx ([rsp+0xa8])'}]}


def check_errors(img):
    rows = []
    for site in ERROR_SITES:
        tag = site['tag']
        if tag == 0:
            img.expect(site['tag_va'] - 3, '4c89f5' '4531f6', 'OutputTooSmall {expected} and tag 0')
        else:
            img.expect(site['tag_va'], bytes((0x41, 0xbe)) + struct.pack('<I', tag), f'error tag {tag}')
        if site['join'] is None:
            require(site['tag_va'] + 6 == COMMON_ERROR, 'tag 2 no longer falls into the common error path')
        else:
            require(img.jmp(site['join']) == COMMON_ERROR, f'error tag {tag} does not reach the common path')
        row = {'tag': tag, 'error': DECOMPRESS_ERRORS[tag], 'tag_va': hex(site['tag_va'])}
        if site['branch']:
            cmp_va, cmp_hex, jcc_va, kind = site['branch']
            img.expect(cmp_va, cmp_hex, f'compare selecting error {tag}')
            require(img.jcc(jcc_va, kind) == site['entry'], f'branch to error {tag} retargeted')
            row['selected_by'] = {'compare': hex(cmp_va), 'branch': hex(jcc_va), 'kind': kind}
        rows.append(row)
    img.expect(COMMON_ERROR, '4885db', 'common error path tests the decoded buffer')
    img.expect(0x3d1b31d, '4c89742450' '48896c2458' '48895c2460', 'DecompressError {tag, a, b} spill')
    va, _ = TEMPLATES['failure']
    require(img.lea_target(0x3d1b342) == va, 'decompress_lz4 failure template LEA retargeted')
    require(img.call(0x3d1b34e) == 0x3d1ab80, 'failure formatter retargeted')
    img.expect(0x3d1b35c, '48b80000000000000080' '488901', 'Err niche store')
    return {'tags': rows, 'common_path': hex(COMMON_ERROR), 'failure_template': hex(va),
            'failure_template_lea': '0x3d1b342', 'failure_formatter': '0x3d1ab80',
            'err_niche': '0x8000000000000000'}


def check_ok(img):
    img.expect(0x3d1b2cf, '4939df' '4c0f43fb', 'len = min(write position, uncompressed_size)')
    img.expect(0x3d1b2d6, '488b4c2420' '488919' '488b0424' '48894108' '4c897910', 'Vec {cap, ptr, len} store')
    return {'len_clamp': '0x3d1b2cf', 'vec_store': '0x3d1b2db', 'capacity': 'uncompressed_size',
            'len': 'min(write position, uncompressed_size)', 'length_equality_checked': False}


def location_line(img, loc):
    path, line, col = img.location(loc)
    require(path.startswith(LZ4_PATH), f'Location {loc:#x} is not an lz4_flex record')
    return path[len(LZ4_PATH):].decode().split('/', 1)[1], line, col


def check_source_bindings(img):
    """Literal-length checks bound to lz4_flex Location records (overflow panics) and error tags."""
    rows = []
    for add_va, add_hex, jb_va in ((0x3d1af2e, '01d1', 0x3d1af30), (0x3d1af73, '01c8', 0x3d1af75)):
        img.expect(add_va, add_hex, 'u32 length-extension add')
        require(img.jcc(jb_va, 'jb') == 0x3d1b57f, 'length-extension overflow branch retargeted')
    require(img.lea_target(0x3d1b57f) == 0x5718f48, 'length-extension overflow Location changed')
    require(img.jmp(0x3d1b586) == 0x3d1b58f, 'overflow panic join moved')
    rows.append({'location': location_line(img, 0x5718f48), 'check': 'u32 extension byte sum overflow',
                 'sites': ['0x3d1af2e', '0x3d1af73'], 'outcome': 'panic via slot 0x576e118'})
    img.call_slot(0x3d1b58f)

    require(img.lea_target(0x3d1ac99) == 0x5718fa8, 'input-remaining Location changed')
    img.expect(0x3d1aca0, '4889442438', 'input-remaining Location spill')
    img.expect(0x3d1b062, '4c89d8' '4829f0', 'input.len() - input_pos')
    require(img.jcc(0x3d1b068, 'jb') == 0x3d1b5b4, 'input-remaining underflow branch retargeted')
    img.expect(0x3d1b5b4, '488b7c2438', 'underflow panic Location load')
    img.call_slot(0x3d1b5b9)
    rows.append({'location': location_line(img, 0x5718fa8), 'check': 'literal_length > input.len() - input_pos',
                 'compare': '0x3d1b06e', 'outcome': 'tag 1 LiteralOutOfBounds'})

    img.expect(0x3d1b077, '4889d8' '4c29f0', 'capacity - pos')
    require(img.jcc(0x3d1b07d, 'jb') == 0x3d1b5a8, 'output-remaining underflow branch retargeted')
    require(img.lea_target(0x3d1b5a8) == 0x5718fc0, 'output-remaining Location changed')
    img.expect(0x3d1b5af, '4889442438', 'output-remaining Location spill')
    img.expect(0x3d1b083, '4839c5', 'literal_length > capacity - pos')
    require(img.jcc(0x3d1b086, 'ja') == 0x3d1b44f, 'output-too-small branch retargeted')
    rows.append({'location': location_line(img, 0x5718fc0), 'check': 'literal_length > capacity - pos',
                 'compare': '0x3d1b083', 'outcome': 'tag 0 OutputTooSmall'})

    img.expect(0x3d1b44f, '4c01f5', 'expected = pos + literal_length')
    require(img.jcc(0x3d1b452, 'jb') == 0x3d1b5ff, 'expected overflow branch retargeted')
    require(img.lea_target(0x3d1b5ff) == 0x5719008, 'expected overflow Location changed')
    img.expect(0x3d1b458, '4531f6', 'OutputTooSmall tag 0')
    require(img.jmp(0x3d1b45b) == COMMON_ERROR, 'OutputTooSmall does not reach the common error path')
    rows.append({'location': location_line(img, 0x5719008), 'check': 'expected = pos + literal_length',
                 'add': '0x3d1b44f', 'outcome': 'tag 0 OutputTooSmall {expected, actual}'})
    img.expect(0x3d1af99, '4989d6' '4d01fe', 'pos + match_length')
    require(img.jcc(0x3d1afa5, 'jb') == 0x3d1b59f, 'match-end overflow branch retargeted')
    require(img.lea_target(0x3d1b59f) == 0x5718fd8, 'match-end Location changed')
    require(img.jmp(0x3d1b5a6) == 0x3d1b58f, 'match-end overflow panic join moved')
    rows.append({'location': location_line(img, 0x5718fd8), 'check': 'pos + match_length > capacity',
                 'compare': '0x3d1afab', 'outcome': 'tag 0 OutputTooSmall'})
    for row in rows:
        row['location'] = dict(zip(('file', 'line', 'col'), row['location']))
    return rows


def lz4_path_census(img):
    """Every relocated pointer whose target starts with the lz4_flex registry path -> {path tail: count}."""
    out = {}
    for where, target in img.relative.items():
        head = b''
        try:
            head = img.read(target, len(LZ4_PATH))
        except EvidenceError:
            pass
        if head != LZ4_PATH:
            continue
        size = struct.unpack('<Q', img.read(where + 8, 8))[0]
        tail = img.read(target, size)[len(LZ4_PATH):].decode()
        out[tail] = out.get(tail, 0) + 1
    return dict(sorted(out.items()))


def lz4_locations(img, fde):
    lo, hi = fde
    base, text = img.text_bytes()
    seen = {}
    for m in re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', text[lo - base:hi - base]):
        va = lo + m.start()
        t = img.lea_target(va)
        if t in img.relative:
            try:
                path, line, col = img.location(t)
            except EvidenceError:
                continue
            if path.startswith(LZ4_PATH):
                seen[hex(t)] = {'path': path[len(LZ4_PATH):].decode(), 'line': line, 'col': col}
    return dict(sorted(seen.items()))


def check_caller(img, c):
    fde = img.fde(c['fde'])
    require(fde[0] <= c['call'] < fde[1], 'decompress call outside its reader FDE')
    admit = mem_operand(img, c['admit'])
    require(admit[0] == 'cmp_rm_r' and REGS[admit[1]] == 'r14', f'no cmp [max_len],r14 at {c["admit"]:#x}')
    store = mem_operand(img, c['flag_store'])
    require(store[0] == 'sete_rm8', f'no sete flag store at {c["flag_store"]:#x}')
    gate = mem_operand(img, c['gate'])
    require(gate[0] == 'grp1_rm8_imm8' and gate[1] == 7, f'no cmp BYTE flag test at {c["gate"]:#x}')
    imm = img.read(c['gate'] + gate[4] - 1, 1)[0]
    require(imm in (0, 1), 'flag test immediate changed')
    target = img.jcc(c['gate'] + gate[4], 'je' if imm == 0 else 'jne')
    require(fde[0] <= target < fde[1], 'flag test skips out of the reader FDE')
    loads = [mem_operand(img, va) for va in c['loads']]
    require([l[0] for l in loads] == ['mov_r_rm'] * 3 and [REGS[l[1]] for l in loads] == ['rcx', 'rsi', 'rdx'],
            f'call arguments at {c["call"]:#x} are not rcx/rsi/rdx loads')
    slot, callee = img.call_slot(c['call'])
    require(slot == SLOT and callee == DECOMP, f'decompressor slot changed at {c["call"]:#x}')
    img.expect(c['result'] - 10, '48b80000000000000080', 'Err niche compare')
    base = loads[0][2]
    require(all(l[2] == base for l in loads) and gate[2] == base, 'call-site loads use different bases')
    if 'link' in c:
        va, hexbytes = c['link']
        img.expect(va, hexbytes, 'admission base copied into call base')
        require(admit[2] == store[2] == 'rcx' and base == 'r15', 'linked base registers changed')
    else:
        require(admit[2] == store[2] == base, 'admission and call bases differ')
    max_disp = admit[3]
    require(loads[0][3] == max_disp, f'decompressor limit is not the admission max_len at {c["call"]:#x}')
    require(store[3] == gate[3] == max_disp + 0x28, 'flag slot is not max_len+0x28')
    require((loads[1][3], loads[2][3]) == (max_disp + 0x40, max_disp + 0x48), 'frame buffer is not max_len+0x40/+0x48')
    return {'fde': hex(fde[0]), 'call': hex(c['call']), 'admission_compare': hex(c['admit']),
            'max_len': f'[{admit[2]}+{max_disp:#x}]', 'limit_arg': f'rcx = [{base}+{loads[0][3]:#x}]',
            'flag': f'[{base}+{gate[3]:#x}]', 'flag_test': {'va': hex(c['gate']), 'imm': imm,
                                                             'skip_target': hex(target)},
            'input_ptr': f'[{base}+{loads[1][3]:#x}]', 'input_len': f'[{base}+{loads[2][3]:#x}]',
            'same_max_len_as_admission': True, **({'base_link': hex(c['link'][0])} if 'link' in c else {})}


def analyse(data):
    img = Image(data)
    require(img.relative.get(SLOT) == DECOMP, 'decompressor GOT slot no longer relocates to 0x3d1abc0')
    others = sorted(k for k, v in img.relative.items() if v == DECOMP)
    require(others == [SLOT], f'other relocations reach the decompressor: {[hex(o) for o in others]}')
    fde = img.fde(DECOMP)
    for name, (va, text) in TEMPLATES.items():
        require(img.read(va, len(text)) == text, f'template {name} changed at {va:#x}')
    calls = slot_calls(img)
    require(calls == sorted(c['call'] for c in CALLERS), f'decompressor slot call census {[hex(v) for v in calls]}')
    direct = direct_refs(img, DECOMP)
    require(not direct, 'direct calls/jumps to the decompressor')
    leas = lea_census(img, [va for va, _ in TEMPLATES.values()])
    require(leas[TEMPLATES['over_limit'][0]] == [0x3d1b555] and leas[TEMPLATES['failure'][0]] == [0x3d1b342],
            'template LEA census changed')
    entry = check_entry(img)
    entry['over_limit'] = check_over_limit(img, int(entry['limit']['over_target'], 16))
    locs = lz4_locations(img, fde)
    require(locs, 'no lz4_flex Location records referenced by the decompressor')
    versions = {r['path'].split('/', 1)[0] for r in locs.values()}
    require(versions == {LZ4_VERSION}, f'lz4_flex versions referenced: {sorted(versions)}')
    crate_paths = lz4_path_census(img)
    require({p.split('/', 1)[0] for p in crate_paths} == {LZ4_VERSION},
            f'lz4_flex versions in the binary: {sorted(crate_paths)}')
    return {
        'decompressor': {'fde': [hex(fde[0]), hex(fde[1])], 'bytes': fde[1] - fde[0], 'got_slot': hex(SLOT)},
        'census': {'slot_calls': [hex(v) for v in calls], 'direct_refs': [], 'relocations_to_decompressor': [hex(SLOT)],
                   'lz4_flex_path_pointers': crate_paths,
                   'template_leas': {hex(k): [hex(v) for v in vs] for k, vs in leas.items()}},
        'entry': entry,
        'errors': check_errors(img),
        'ok': check_ok(img),
        'source_bindings': check_source_bindings(img),
        'lz4_flex_locations': locs,
        'callers': [check_caller(img, c) for c in CALLERS],
        'model': model_summary(),
    }


# Transcribed model of the observed wrapper decision.  It does not decode LZ4.
def payload_outcome(payload_len, prefix, max_len):
    if payload_len <= 3:
        return 'ExpectedAnotherByte'
    if prefix > max_len:
        return 'lz4 bytes over limit'
    return 'decode'


def reference_outcome(payload_len, prefix, max_len):
    """can1357 net_utils/tcp/read.rs `decompress_lz4_size_prepended_with_limit` predicates and variants."""
    if payload_len < 4:
        return 'Lz4InputTooShort'
    if prefix > max_len:
        return 'Lz4DecodedOverLimit'
    return 'decode'


MODEL_CASES = ((0, 0, 16), (3, 0, 16), (4, 0, 16), (4, 16, 16), (4, 17, 16), (100, 0xffffffff, 0xffffffff),
               (100, 0xffffffff, 0xfffffffe))


def model_summary():
    rows = [{'payload_len': p, 'prefix': x, 'max_len': m, 'binary': payload_outcome(p, x, m),
             'reference': reference_outcome(p, x, m)} for p, x, m in MODEL_CASES]
    same = {('ExpectedAnotherByte', 'Lz4InputTooShort'), ('lz4 bytes over limit', 'Lz4DecodedOverLimit'),
            ('decode', 'decode')}
    return {'cases': rows, 'predicate_disagreements': sum((r['binary'], r['reference']) not in same for r in rows)}


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
    print(json.dumps({'callers': len(result['callers']), 'slot_calls': len(result['census']['slot_calls']),
                      'error_tags': len(result['errors']['tags']),
                      'predicate_disagreements': result['model']['predicate_disagreements']}, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
