#!/usr/bin/env python3
"""Inspect the node 94 receipt blob-quantity path without executing its ELF."""
import argparse
import csv
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/94/hl-node'
SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
MASK = (1 << 64) - 1
TOP128 = 1 << 128
BODIES = {
    0x26b79b0: (0x26b7e66, '21b04157687b3ff0d9dc616343b9e215a96ddf2314e82e4f5c4f7fa365098e0a'),
    0x4e5b5b0: (0x4e5c144, '4fbc1c3b3894c455e98fbfa61c04340d976e7b437466189276ce641ce9807354'),
}
# Fixed machine-code windows. These cover the selected decisions, their arithmetic,
# and the relevant writes; they are not a disassembly or a complete CFG.
WINDOWS = {
 'caller_first': (0x26b79c4, '4c8b6e084c3b6e180f84aa0200004989f64c8b6620498d85500100004889460866410f6f4500660f7405cebab4fd660fd7c03dffff00000f847b020000'),
 'caller_second': (0x26b7a38, '4d3b66280f8416020000488dbc2450030000498d44242849894620'),
 'caller_args': (0x26b7aa9, '498b4e480f10010f1049100f1148100f1100498b4650498b4e58488b00498b5660498b7668488b364889ac24b000000048898424d80000000f10010f29442470f30f6f02660f7f8424800000004889b424e0000000498b46704c8b40084c8b4810488dbc24f0000000488db42440030000488d5424704c89e1ff15d8cb0b03'),
 'caller_finish': (0x26b7d3d, '4883fdff746948ffc549896e40'),
 'receipt_delta': (0x4e5b631, '80bc24c00100000175518b8424d1010000898424b00000000f108424c10100000f298424a0000000498b4e404885c97464488d41ff4839e87361498b5518488d0480488b742440482b54c618734f488d3d12fc8e00ff15c42a9100'),
 'receipt_rejection': (0x4e5b68c, '49c74424180000000049c74424100200000049c74424200100000049c74424300100000049c74424080000000049c7042402000000e9c6090000'),
 'receipt_delta_zero': (0x4e5b6c6, '498b5518eb0231d2660f6f03660f740516ca3afb660fd7c03dffff00004c89242448894c247048899424e000000048899c24e80000004c897424384c897c24304c896c242848896c24180f8534010000'),
 'receipt_fee': (0x4e5b716, '488bb3c00000004889f048c1e82f0f85ab09000048c1e61141807e10004889b424d80000000f8422010000498b4618488944240841be0100000031ed31ff31f6b9edf0320031d20f1f004801cf4811d60f824f0900004889d04c8b44240849f7e04989c2410f90c14889c849f7e04989c54889d34c01d30f92c04408c80f852f090000488974241048897c24204889e8bfedf0320048f7e74889c1400f90c64c89f048f7e74989c44989d74901cf0f92c04008f00f85de0800004983c6014883d5004c89ef4889de4c89e24c89f9ff15be2991004889c14d39e54c19fb488b7c2420488b7424100f835dffffff48c744246000000000baedf0320031c9ff158f2991004889d148c1e90848894c24584889442408480fa4c2384889542450b801000000488944246848894424484c8b6c2428eb4c'),
 'receipt_absence': (0x4e5b84a, '48c744246800000000488944240848c744245000000000eb18b801000000488944246848c744245000000000488944240848c74424580000000048c74424480000000048c744246000000000'),
 'receipt_packing': (0x4e5bf86, '4c8b6c2458488b442450490fa4c50848c1e008450fb6ff4909c7'),
 'receipt_stores': (0x4e5bfcf, '488b4424604989442408488b442448498904244d896c24184d897c241049c744242001000000488b442470498944242849c744243001000000488b4424284989442438488b4424684989442440488b8424d80000004989442448'),
 'receipt_delta_store': (0x4e5c05b, '488b8424e000000049898424e8010000'),
 'receipt_failures': (0x4e5c0a1, '488d3d08f28e00ff156a209100488d3db3f18e00ff15f5209100488d3d76f18e00ff1550209100488d3d81f18e00ff15db209100488d3da4f18e00ff15ce209100'),
}
# Addresses are branch-instruction VAs, not guessed function boundaries.
BRANCHES = {
 0x26b79cc:'first_empty', 0x26b79fb:'first_sentinel', 0x26b7a3c:'second_empty',
 0x26b7d41:'index_overflow', 0x4e5b639:'receipt_rejected',
 0x4e5b660:'index_zero', 0x4e5b669:'previous_index_outside',
 0x4e5b67d:'previous_delta_fits', 0x4e5b710:'not_blob_variant',
 0x4e5b724:'blob_count_overflow', 0x4e5b73b:'excess_absent',
 0x4e5b766:'series_sum_overflow', 0x4e5b793:'series_product_overflow',
 0x4e5b7ca:'series_divisor_overflow', 0x4e5b7fd:'series_continue',
}
LOCATIONS = {
 0x574b238: ('eip4844/mod.rs', 164, 9),
 0x574b250: ('eip4844/mod.rs', 167, 27),
 0x574b268: ('eip4844/mod.rs', 167, 59),
 0x574b280: ('transaction/mod.rs', 173, 50),
 0x574b298: ('rpc-eth-types/src/receipt.rs', 34, 33),
 0x574b2b0: ('rpc-eth-types/src/receipt.rs', 47, 9),
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


class Image:
    def __init__(self, blob, expected=SHA):
        if digest(blob) != expected:
            raise ValueError('input SHA-256 mismatch')
        self.blob = blob
        self.sections = sections(blob)
        self.rel = {}
        candidates = [s for s in self.sections if s['name'] == '.rela.dyn' and s['type'] != 8]
        if len(candidates) != 1:
            raise ValueError('missing or duplicate dynamic relocation section')
        sec = candidates[0]
        if sec['size'] % 24:
            raise ValueError('truncated relocation section')
        for at, info, addend in struct.iter_unpack('<QQq', blob[sec['offset']:sec['offset'] + sec['size']]):
            if info & 0xffffffff == 8:
                if at in self.rel:
                    raise ValueError('duplicate relative relocation')
                self.rel[at] = addend
        _, self.fdes = eh_frame_records(blob, self.sections)

    def offset(self, addr, size, executable=False):
        if addr < 0 or size < 0:
            raise ValueError('invalid address or size')
        matches = [s for s in self.sections if s['type'] != 8 and s['flags'] & 2
                   and (not executable or s['flags'] & 4)
                   and s['address'] <= addr and addr + size <= s['address'] + s['size']]
        if len(matches) != 1:
            raise ValueError('address is not uniquely file-backed')
        s = matches[0]
        return s['offset'] + addr - s['address']

    def read(self, addr, size, executable=False):
        off = self.offset(addr, size, executable)
        return self.blob[off:off + size]

    def u32(self, addr):
        return struct.unpack('<I', self.read(addr, 4))[0]

    def fde(self, start):
        rows = [x for x in self.fdes if x['start'] == start]
        if len(rows) != 1:
            raise ValueError('missing or duplicate FDE start')
        return rows[0]

    def call_target(self, site):
        b = self.read(site, 6, True)
        if b[:2] != b'\xff\x15':
            raise ValueError('unexpected call encoding')
        slot = site + 6 + struct.unpack('<i', b[2:])[0]
        if slot not in self.rel:
            raise ValueError('missing relative call relocation')
        return slot, self.rel[slot]

    def branch(self, site):
        b = self.read(site, 6, True)
        if b[0] in (0x72, 0x73, 0x74, 0x75):
            return site + 2 + struct.unpack('<b', b[1:2])[0], b[:2]
        if b[0] == 0x0f and b[1] in (0x82, 0x83, 0x84, 0x85):
            return site + 6 + struct.unpack('<i', b[2:6])[0], b[:6]
        raise ValueError('unexpected branch encoding')

    def location(self, addr):
        _, length, line, col = struct.unpack('<QQII', self.read(addr, 24))
        if addr not in self.rel or length > 1024:
            raise ValueError('invalid source-location relocation')
        path = self.read(self.rel[addr], length).decode('utf8')
        # Keep only a reproducible package-relative suffix in generated evidence.
        parts = path.split('/')
        if 'src' not in parts:
            raise ValueError('unrecognized source location')
        index = len(parts) - 1 - parts[::-1].index('src')
        if index < 1:
            raise ValueError('unrecognized source location')
        return '/'.join(parts[index-1:]), line, col


def validate(img, bodies=BODIES):
    for start, (end, want) in sorted(bodies.items()):
        f = img.fde(start)
        if f['end'] != end:
            raise ValueError('unexpected FDE extent')
        if digest(img.read(start, end-start, True)) != want:
            raise ValueError('function body mismatch')
    for name, (addr, raw) in WINDOWS.items():
        expected = bytes.fromhex(raw)
        if not any(start <= addr and addr + len(expected) <= end for start,(end,_) in bodies.items()):
            raise ValueError('instruction window outside selected FDEs')
        if img.read(addr, len(expected), True) != expected:
            raise ValueError('instruction window mismatch: ' + name)
    for addr, value in ((0x2080f0,3),(0x2034c0,5),(0x2054d0,2)):
        if img.read(addr,16) != value.to_bytes(16,'little'):
            raise ValueError('tag constant mismatch')
    for site, (want_slot, want_target) in {
        0x26b7b22:(0x5774700, 0x4e5b5b0),
        0x4e5b7e4:(0x576e1a8, 0x565f5a0),
        0x4e5b813:(0x576e1a8, 0x565f5a0),
    }.items():
        if img.call_target(site) != (want_slot, want_target):
            raise ValueError('unexpected call relocation')
    for addr, (suffix, ln, col) in LOCATIONS.items():
        path, line, column = img.location(addr)
        if not path.endswith(suffix) or (line, column) != (ln, col):
            raise ValueError('source-location mismatch')
    for site in BRANCHES:
        target, _ = img.branch(site)
        owner = next((start for start, (end, _) in bodies.items() if start <= site < end), None)
        if owner is None or not owner <= target < bodies[owner][0]:
            raise ValueError('branch outside selected FDE')
    return {
        'denominator': img.u32(0x4e5b757),
        'denominator_immediates': [img.u32(a) for a in (0x4e5b757,0x4e5b7a7,0x4e5b80d)],
        'gas_shift': img.read(0x4e5b72d, 1, True)[0],
        'overflow_shift': img.read(0x4e5b723, 1, True)[0],
        'blob_tag_bytes': img.read(0x2080f0, 16).hex(),
        'iterator_stop_bytes': img.read(0x2034c0, 16).hex(),
        'special_return_bytes': img.read(0x2054d0, 16).hex(),
    }


def add64(a, b, carry=0):
    total = a + b + carry
    return total & MASK, total >> 64


def mul64(a, b):
    value = a * b
    return value & MASK, value >> 64


def run_series(x, denominator):
    """Lift the pinned limb instructions; the two division calls are modeled."""
    if not 0 <= x <= MASK or not 1 <= denominator <= MASK:
        raise ValueError('input outside modeled u64 domain')
    r14, rbp = 1, 0
    rdi, rsi = 0, 0
    rcx, rdx = denominator, 0
    iterations = 0
    while True:
        iterations += 1
        if iterations > 1024:
            raise ValueError('modeled step limit')
        rdi, carry = add64(rdi, rcx)
        rsi, carry = add64(rsi, rdx, carry)
        if carry:
            return {'status':'sum_overflow', 'iterations':iterations}
        # mul x on high then low term limbs, and add the cross product.
        r10, high = mul64(rdx, x)
        r13, rbx = mul64(rcx, x)
        rbx, carry = add64(rbx, r10)
        if high or carry:
            return {'status':'product_overflow', 'iterations':iterations}
        # mul denominator on high then low loop-index limbs.
        high_low, high_high = mul64(rbp, denominator)
        r12, r15 = mul64(r14, denominator)
        r15, carry = add64(r15, high_low)
        if high_high or carry:
            return {'status':'divisor_overflow', 'iterations':iterations}
        r14, carry = add64(r14, 1)
        rbp, _ = add64(rbp, 0, carry)
        product = r13 | (rbx << 64)
        divisor = r12 | (r15 << 64)
        if not divisor:
            raise ValueError('division helper would receive zero')
        quotient = product // divisor  # shared helper contract, not run
        rcx, rdx = quotient & MASK, quotient >> 64
        if product < divisor:
            result = (rdi | (rsi << 64)) // denominator
            return {'status':'ok', 'price':result, 'iterations':iterations}



def execute_loop(img, x, denominator, coverage=None):
    """Interpret the selected x86 loop; the unsigned divide is a model hook."""
    if not 0 <= x <= MASK or denominator != 3338477:
        raise ValueError('invalid byte-walk input')
    start, stop = 0x4e5b760, 0x4e5b803
    failures = {0x4e5c0bb:'sum_overflow', 0x4e5c0c8:'product_overflow',
                0x4e5c0ae:'divisor_overflow'}
    reg = {k:0 for k in ('rax','rbx','rcx','rdx','rsi','rdi','rbp','r8','r9','r10','r12','r13','r14','r15')}
    reg['rcx'], reg['r14'] = denominator, 1
    stack = {8:x}
    moves = {bytes.fromhex(k):v for k,v in {
        '4889d0':('rax','rdx'), '4989c2':('r10','rax'),
        '4889c8':('rax','rcx'), '4989c5':('r13','rax'),
        '4889d3':('rbx','rdx'), '4889e8':('rax','rbp'),
        '4889c1':('rcx','rax'), '4c89f0':('rax','r14'),
        '4989c4':('r12','rax'), '4989d7':('r15','rdx'),
        '4c89ef':('rdi','r13'), '4889de':('rsi','rbx'),
        '4c89e2':('rdx','r12'), '4c89f9':('rcx','r15'),
    }.items()}
    loads = {bytes.fromhex(k):v for k,v in {
        '4c8b442408':('r8',8), '488b7c2420':('rdi',32),
        '488b742410':('rsi',16)}.items()}
    stores = {bytes.fromhex(k):v for k,v in {
        '4889742410':('rsi',16), '48897c2420':('rdi',32)}.items()}
    adds = {bytes.fromhex(k):v for k,v in {
        '4801cf':('rdi','rcx',False), '4811d6':('rsi','rdx',True),
        '4c01d3':('rbx','r10',False), '4901cf':('r15','rcx',False)}.items()}
    cf = of = zf = steps = iterations = 0
    pc = start
    text = next(s for s in img.sections if s['name']=='.text' and s['type']!=8 and s['flags'] & 4)
    while True:
        if pc == stop:
            return {'status':'ok','price':((reg['rsi']<<64)|reg['rdi'])//denominator,'iterations':iterations}
        if pc in failures:
            return {'status':failures[pc], 'iterations':iterations}
        if not start <= pc < stop:
            raise ValueError('byte walk left selected loop')
        if pc == start:
            iterations += 1
        steps += 1
        if steps > 100000:
            raise ValueError('byte-walk step limit')
        if coverage is not None:
            coverage[pc] = coverage.get(pc,0) + 1
        off = text['offset'] + pc - text['address']
        raw = img.blob[off:off+6]
        matched = False
        for table in (moves,loads,stores,adds):
            for opcode, args in table.items():
                if not raw.startswith(opcode):
                    continue
                if table is moves:
                    reg[args[0]] = reg[args[1]]
                elif table is loads:
                    if args[1] not in stack:
                        raise ValueError('uninitialized byte-walk stack')
                    reg[args[0]] = stack[args[1]]
                elif table is stores:
                    stack[args[1]] = reg[args[0]]
                else:
                    dst,src,with_carry = args
                    reg[dst],cf = add64(reg[dst],reg[src],cf if with_carry else 0)
                pc += len(opcode)
                matched = True
                break
            if matched:
                break
        if matched:
            continue
        if raw[:3] in (bytes.fromhex('49f7e0'),bytes.fromhex('48f7e7')):
            operand = reg['r8'] if raw[0]==0x49 else reg['rdi']
            reg['rax'],reg['rdx'] = mul64(reg['rax'],operand)
            cf = of = int(reg['rdx'] != 0)
            pc += 3
        elif raw.startswith(bytes.fromhex('410f90c1')):
            reg['r9'] = (reg['r9'] & ~255) | of
            pc += 4
        elif raw.startswith(bytes.fromhex('400f90c6')):
            reg['rsi'] = (reg['rsi'] & ~255) | of
            pc += 4
        elif raw.startswith(bytes.fromhex('0f92c0')):
            reg['rax'] = (reg['rax'] & ~255) | cf
            pc += 3
        elif raw.startswith(bytes.fromhex('4408c8')) or raw.startswith(bytes.fromhex('4008f0')):
            value = (reg['rax'] | (reg['r9'] if raw[0]==0x44 else reg['rsi'])) & 255
            reg['rax'] = (reg['rax'] & ~255) | value
            zf, cf, of = int(value==0), 0, 0
            pc += 3
        elif raw[0] == 0xbf:
            value = struct.unpack_from('<I',raw,1)[0]
            if value != denominator:
                raise ValueError('byte-walk denominator changed')
            reg['rdi'] = value
            pc += 5
        elif raw.startswith(bytes.fromhex('4983c601')):
            reg['r14'], cf = add64(reg['r14'],1)
            pc += 4
        elif raw.startswith(bytes.fromhex('4883d500')):
            reg['rbp'], cf = add64(reg['rbp'],0,cf)
            pc += 4
        elif raw.startswith(bytes.fromhex('4d39e5')):
            cf = int(reg['r13'] < reg['r12'])
            pc += 3
        elif raw.startswith(bytes.fromhex('4c19fb')):
            value = reg['rbx'] - reg['r15'] - cf
            reg['rbx'],cf = value & MASK,int(value < 0)
            pc += 3
        elif raw[:2] == b'\xff\x15':
            slot = pc + 6 + struct.unpack_from('<i',raw,2)[0]
            if slot != 0x576e1a8 or img.rel.get(slot) != 0x565f5a0:
                raise ValueError('unexpected divide call')
            numerator = (reg['rsi'] << 64) | reg['rdi']
            divisor = (reg['rcx'] << 64) | reg['rdx']
            if not divisor:
                raise ValueError('byte-walk division by zero')
            quotient = numerator // divisor
            reg['rax'],reg['rdx'] = quotient & MASK, quotient >> 64
            pc += 6
        elif raw[:2] in (b'\x0f\x82',b'\x0f\x83',b'\x0f\x85'):
            take = cf if raw[1]==0x82 else (not cf if raw[1]==0x83 else not zf)
            target = pc + 6 + struct.unpack_from('<i',raw,2)[0]
            pc = target if take else pc+6
        else:
            raise ValueError('unmodeled byte-walk instruction at ' + hex(pc))

def specification(x, denominator):
    """Independent wide-integer version of the selected arithmetic."""
    if not 0 <= x <= MASK or not 1 <= denominator <= MASK:
        raise ValueError('input outside modeled u64 domain')
    total, term, index = 0, denominator, 1
    while True:
        total += term
        if total >= TOP128:
            return {'status':'sum_overflow', 'iterations':index}
        product = term * x
        if product >= TOP128:
            return {'status':'product_overflow', 'iterations':index}
        div = index * denominator
        if div >= TOP128:
            return {'status':'divisor_overflow', 'iterations':index}
        term = product // div
        if not term:
            return {'status':'ok', 'price':total // denominator, 'iterations':index}
        index += 1
        if index > 1024:
            raise ValueError('modeled step limit')


def receipt_case(valid, blob, count, excess_present, excess, index, current, previous, denom, shift):
    """Selected gates and observable quantity fields, in instruction order."""
    if not 0 <= valid <= 255 or not 0 <= excess_present <= 255 or blob not in (0,1):
        raise ValueError('tag or Boolean outside modeled domain')
    for value in (count, excess, index, current):
        if not 0 <= value <= MASK:
            raise ValueError('input outside u64 domain')
    if valid != 1:
        return {'status':'receipt_rejected'}
    if index == 0:
        delta = current
    elif index - 1 >= len(previous):
        delta = 0
    else:
        prior = previous[index-1]
        if not 0 <= prior <= MASK:
            raise ValueError('previous cumulative value outside u64 domain')
        if current < prior:
            return {'status':'delta_underflow'}
        delta = current - prior
    if not blob:
        return {'status':'ok', 'delta':delta, 'gas_present':0, 'price_present':0}
    if count >= (1 << (64 - shift)):
        return {'status':'blob_count_overflow'}
    gas = count << shift
    result = {'status':'ok', 'delta':delta, 'gas_present':1, 'gas':gas, 'price_present':0}
    if excess_present:
        calculation = run_series(excess, denom)
        if calculation['status'] != 'ok':
            return calculation
        result.update(price_present=1, price=calculation['price'], iterations=calculation['iterations'])
    return result



def matches_blob_tag(img, tag):
    if len(tag) != 16:
        raise ValueError('blob tag must contain exactly 16 bytes')
    return tag == img.read(0x2080f0,16)


def walk_gate(img, valid, blob, count, excess_present, excess, index, current, previous, denom, shift, coverage=None):
    """Walk selected Jcc bytes, with record loads and decoder result as inputs."""
    if not 0 <= valid <= 255 or not 0 <= excess_present <= 255 or blob not in (0,1):
        raise ValueError('tag or Boolean outside modeled domain')
    if any(not 0 <= value <= MASK for value in (count,excess,index,current)):
        raise ValueError('input outside u64 domain')
    def jcc(site, zero=0, carry=0):
        target, raw = img.branch(site)
        op = raw[1] if raw[0] == 0x0f else raw[0]
        # Near Jcc low opcode nibble and short Jcc low nibble match.
        cond = op & 15
        taken = {2:bool(carry),3:not carry,4:bool(zero),5:not zero}.get(cond)
        if taken is None:
            raise ValueError('unmodeled conditional branch')
        if coverage is not None:
            key=(site,int(taken))
            coverage[key]=coverage.get(key,0)+1
        return target if taken else site+len(raw)
    decoder_tag = img.read(0x4e5b638,1,True)[0]
    if jcc(0x4e5b639,zero=(valid==decoder_tag)) == 0x4e5b68c:
        return {'status':'receipt_rejected'}
    if jcc(0x4e5b660,zero=(index==0)) == 0x4e5b6c6:
        delta=current
    elif jcc(0x4e5b669,carry=(index-1<len(previous))) == 0x4e5b6cc:
        delta=0
    else:
        prior=previous[index-1]
        if not 0 <= prior <= MASK:
            raise ValueError('previous cumulative value outside u64 domain')
        if jcc(0x4e5b67d,carry=(current<prior)) != 0x4e5b6ce:
            return {'status':'delta_underflow'}
        delta=current-prior
    actual_tag=img.read(0x2080f0,16) if blob else bytes(16)
    if jcc(0x4e5b710,zero=matches_blob_tag(img,actual_tag)) == 0x4e5b84a:
        return {'status':'ok','delta':delta,'gas_present':0,'price_present':0}
    if jcc(0x4e5b724,zero=((count >> (64-shift))==0)) == 0x4e5c0d5:
        return {'status':'blob_count_overflow'}
    result={'status':'ok','delta':delta,'gas_present':1,'gas':count << shift,'price_present':0}
    if jcc(0x4e5b73b,zero=(excess_present==0)) != 0x4e5b863:
        computed=execute_loop(img,excess,denom)
        if computed['status'] != 'ok':
            return computed
        result.update(price_present=1,price=computed['price'],iterations=computed['iterations'])
    return result


def ideal_exp_bounds(x, denominator, terms=160):
    """Exact rational lower and upper bounds for exp(x / denominator)."""
    if not 0 <= x <= MASK or denominator <= 0 or terms < 2:
        raise ValueError('invalid rational-bound input')
    ratio=Fraction(x,denominator)
    term=Fraction(1)
    total=Fraction(1)
    for n in range(1,terms):
        term=term * ratio / n
        total += term
    next_ratio=ratio / (n+2)
    if next_ratio >= 1:
        raise ValueError('geometric tail bound does not converge')
    tail_bound=(term * ratio / (n+1)) / (1-next_ratio)
    return total, total + tail_bound

def caller_gate(first_present, sentinel, second_present, counter):
    if any(flag not in (0,1) for flag in (first_present,sentinel,second_present)):
        raise ValueError('caller flag outside Boolean domain')
    if not 0 <= counter <= MASK:
        raise ValueError('counter outside u64 domain')
    if not first_present:
        return 'first_empty', 0, 0
    if sentinel:
        return 'first_sentinel', 1, 0
    if not second_present:
        return 'second_empty', 1, 0
    if counter == MASK:
        return 'counter_overflow_after_call', 1, 1
    return 'call_and_increment', 1, 1


def boundary(d):
    low, high = 0, MASK
    while low < high:
        mid = (low + high + 1) // 2
        if specification(mid, d)['status'] == 'ok':
            low = mid
        else:
            high = mid - 1
    return low


def write_tsv(path, columns, rows):
    with path.open('w', newline='', encoding='utf8') as f:
        w = csv.writer(f, delimiter='\t', lineterminator='\n')
        w.writerow(columns)
        w.writerows(rows)


def build(img, out):
    constants = validate(img)
    d, shift = constants['denominator'], constants['gas_shift']
    if constants['denominator_immediates'] != [d,d,d]:
        raise ValueError('receipt denominator immediates disagree')
    if (d, shift, constants['overflow_shift']) != (3338477, 17, 47):
        raise ValueError('unexpected arithmetic constant')
    out.mkdir(parents=True, exist_ok=True)
    functions = []
    for start, (end, _) in sorted(BODIES.items()):
        f = img.fde(start)
        b = img.read(start, end-start, True)
        functions.append([hex(start),hex(end),hex(img.offset(start,len(b),True)),len(b),hex(f['fde']),hex(f['cie']),digest(b),b.hex()])
    write_tsv(out/'functions.tsv', ['start_va','end_va','file_offset','length','fde_va','cie_va','sha256','body_hex'],functions)
    windows = [[name,hex(a),hex(img.offset(a,len(bytes.fromhex(raw)),True)),raw] for name,(a,raw) in sorted(WINDOWS.items())]
    write_tsv(out/'windows.tsv',['role','va','file_offset','raw_bytes'],windows)
    layout = []
    for label, va, length, offset, width in (
        ('caller first stride',0x26b79d9,7,3,4),
        ('caller second stride',0x26b7a4a,5,4,1),
        ('caller context pointer offset',0x26b7ac6,4,3,1),
        ('receipt index offset',0x4e5b659,4,3,1),
        ('receipt current cumulative offset',0x4e5b66b,4,3,1),
        ('receipt preceding cumulative offset',0x4e5b678,5,4,1),
        ('transaction blob count offset',0x4e5b716,7,3,4),
        ('context excess option offset',0x4e5b72e,5,3,1),
        ('context excess payload offset',0x4e5b741,4,3,1),
        ('output price high offset',0x4e5bfe2,5,4,1),
        ('output price low offset',0x4e5bfe7,5,4,1),
        ('output gas presence offset',0x4e5c017,5,4,1),
        ('output gas amount offset',0x4e5c024,5,4,1),
        ('output delta offset',0x4e5c063,8,4,4),
    ):
        raw=img.read(va,length,True)
        value=int.from_bytes(raw[offset:offset+width],'little')
        layout.append([label,hex(va),raw.hex(),value,hex(value)])
    # LEA rax,[rax+rax*4], then a memory operand [rsi+rax*8+disp].
    lea=img.read(0x4e5b66f,4,True)
    mem=img.read(0x4e5b678,5,True)
    if lea != bytes.fromhex('488d0480') or mem[:4] != bytes.fromhex('482b54c6'):
        raise ValueError('unexpected prior-row stride encoding')
    stride=(1+(1 << (lea[3]>>6))) * (1 << (mem[3]>>6))
    layout.append(['previous row stride',hex(0x4e5b66f),lea.hex()+'+'+mem.hex(),stride,hex(stride)])
    # The caller copies 16 bytes into its stack, then passes a stack pointer.
    copy_load=img.read(0x26b7ae9,4,True)
    copy_store=img.read(0x26b7aed,9,True)
    arg_base=img.read(0x26b7b1a,5,True)
    if copy_load != bytes.fromhex('f30f6f02') or copy_store[:5] != bytes.fromhex('660f7f8424') or arg_base[:4] != bytes.fromhex('488d5424'):
        raise ValueError('unexpected caller context-copy encoding')
    context_offset=struct.unpack_from('<I',copy_store,5)[0]-arg_base[4]
    if context_offset < 0:
        raise ValueError('invalid caller context mapping')
    layout.append(['copied context within callee argument',hex(0x26b7ae9),copy_load.hex()+'+'+copy_store.hex()+'+'+arg_base.hex(),context_offset,hex(context_offset)])
    write_tsv(out/'layout.tsv',['field','instruction_va','raw_bytes','value','value_hex'],layout)
    branches = []
    for addr, name in sorted(BRANCHES.items()):
        target, raw = img.branch(addr)
        branches.append([name,hex(addr),hex(target),raw.hex()])
    write_tsv(out/'branches.tsv',['decision','branch_va','target_va','raw_bytes'],branches)
    bnd = boundary(d)
    xs = {0,1,d-1,d,d+1,5007716,70108017,100000000,bnd-1,bnd,bnd+1,MASK}
    # A fixed grid is reproducible and is not a claim of exhaustive execution.
    xs.update((bnd*i)//256 for i in range(257))
    series = []
    for x in sorted(xs):
        actual = run_series(x,d)
        expected = specification(x,d)
        if actual != expected:
            raise ValueError('limb and wide models disagree')
        series.append([x,actual['status'],actual.get('price',''),actual['iterations']])
    write_tsv(out/'series.tsv',['excess_u64','status','price_u128','iterations'],series)
    walks=[]
    coverage={}
    walk_xs=sorted({0,1,d-1,d,d+1,5007716,70108017,100000000,bnd-1,bnd,bnd+1,MASK} | {(bnd*i)//64 for i in range(65)})
    for x in walk_xs:
        result=execute_loop(img,x,d,coverage)
        if result != specification(x,d):
            raise ValueError('byte walk and wide model disagree')
        walks.append([x,result['status'],result.get('price',''),result['iterations']])
    write_tsv(out/'walk-cases.tsv',['excess_u64','status','price_u128','iterations'],walks)
    write_tsv(out/'walk-sites.tsv',['instruction_va','visits'],[[hex(pc),n] for pc,n in sorted(coverage.items())])
    witness=100000000
    lower,upper=ideal_exp_bounds(witness,d)
    lo,hi=lower.numerator//lower.denominator,upper.numerator//upper.denominator
    staged=execute_loop(img,witness,d)
    if lo != hi or staged['status'] != 'ok' or staged['price'] == lo:
        raise ValueError('rounding witness not established')
    write_tsv(out/'rounding-witness.tsv',
        ['excess','denominator','terms','staged_price','ideal_lower_floor','ideal_upper_floor','difference','lower_num','lower_den','upper_num','upper_den'],
        [[witness,d,160,staged['price'],lo,hi,lo-staged['price'],lower.numerator,lower.denominator,upper.numerator,upper.denominator]])
    ranges = [
        ['blob_count','accepted',0,(1 << (64-shift))-1,'count << shift fits u64'],
        ['blob_count','rejected',1 << (64-shift),MASK,'upper count bits are nonzero'],
        ['excess','ok_model',0,bnd,'conditional on the modeled unsigned division helper'],
        ['excess','overflow_model',bnd+1,MASK,'monotone term and sum bounds in the wide model'],
    ]
    write_tsv(out/'ranges.tsv',['input','decision','minimum','maximum','basis'],ranges)
    # Each output bit comes from a distinct input bit; one-hot vectors cover the mapping.
    packing=[]
    for q in [0] + [1 << bit for bit in range(128)] + [(1 << 128)-1]:
        low,high = q & MASK,q >> 64
        middle = ((high << 56) | (low >> 8)) & MASK
        upper = high >> 8
        out_low = ((middle << 8) & MASK) | (low & 255)
        out_high = ((upper << 8) | (middle >> 56)) & MASK
        if out_low | (out_high << 64) != q:
            raise ValueError('price output packing mismatch')
        packing.append([hex(q),hex(middle),hex(upper),hex(out_low),hex(out_high)])
    write_tsv(out/'packing.tsv',['input_u128','middle_u64','upper_u64','stored_low_u64','stored_high_u64'],packing)
    fixtures = [
       ('rejected_first',0,1,MASK,1,MASK,1,0,[1]),
       ('rejected_non_one',2,1,1,1,0,0,13,[]),
       ('non_blob',1,0,MASK,1,MASK,0,13,[]),
       ('zero_count_no_excess',1,1,0,0,0,0,13,[]),
       ('max_count_no_excess',1,1,(1<<(64-shift))-1,0,0,0,13,[]),
       ('count_first_overflow',1,1,1<<(64-shift),0,0,0,13,[]),
       ('present_zero',1,1,1,1,0,0,13,[]),
       ('present_non_one_byte',1,1,1,128,0,0,13,[]),
       ('present_denom',1,1,1,1,d,1,13,[10]),
       ('present_limit',1,1,1,1,bnd,1,13,[10]),
       ('present_first_failure',1,1,1,1,bnd+1,1,13,[10]),
       ('delta_underflow_before_count',1,1,MASK,1,MASK,1,9,[10]),
       ('previous_index_outside',1,1,2,0,0,2,9,[10]),
    ]
    cases=[]
    gate_coverage={}
    for name,valid,blob,count,present,x,index,current,prev in fixtures:
        result=receipt_case(valid,blob,count,present,x,index,current,prev,d,shift)
        walked=walk_gate(img,valid,blob,count,present,x,index,current,prev,d,shift,gate_coverage)
        if result != walked:
            raise ValueError('selected branch walk and receipt model disagree')
        cases.append([name,valid,blob,count,present,x,index,current,','.join(map(str,prev)),json.dumps(result,sort_keys=True,separators=(',',':'))])
    write_tsv(out/'cases.tsv',['case','valid','blob','count','excess_present','excess','index','current','previous','modeled_result'],cases)
    tags=[]
    for byte in range(256):
        got=receipt_case(byte,1,1,1,0,0,0,[],d,shift)
        if got != walk_gate(img,byte,1,1,1,0,0,0,[],d,shift,gate_coverage):
            raise ValueError('decoder-byte branch walk mismatch')
        tags.append(['decoder',byte,got['status'],got.get('price_present','')])
    for byte in range(256):
        got=receipt_case(1,1,1,byte,0,0,0,[],d,shift)
        if got != walk_gate(img,1,1,1,byte,0,0,0,[],d,shift,gate_coverage):
            raise ValueError('excess-byte branch walk mismatch')
        tags.append(['excess_present',byte,got['status'],got.get('price_present','')])
    write_tsv(out/'tag-decisions.tsv',['byte_role','byte_value','status','price_present'],tags)
    tag_original=img.read(0x2080f0,16)
    tag_bits=[['original',tag_original.hex(),int(matches_blob_tag(img,tag_original))]]
    for bit in range(len(tag_original)*8):
        edited=bytearray(tag_original)
        edited[bit//8] ^= 1 << (bit%8)
        tag_bits.append([bit,edited.hex(),int(matches_blob_tag(img,bytes(edited)))])
    write_tsv(out/'tag-bits.tsv',['changed_bit','tag_bytes','matches'],tag_bits)
    write_tsv(out/'gate-coverage.tsv',['branch_va','taken','visits'],[[hex(pc),taken,n] for (pc,taken),n in sorted(gate_coverage.items())])
    callers=[]
    for first in (0,1):
        for sentinel in (0,1):
            for second in (0,1):
                for count in (0,MASK):
                    result=caller_gate(first,sentinel,second,count)
                    callers.append([first,sentinel,second,count,*result])
    write_tsv(out/'caller-cases.tsv',['first_present','sentinel','second_present','counter','decision','first_advanced','second_advanced'],callers)
    calls=[]
    for at in (0x26b7b22,0x4e5b7e4,0x4e5b813):
        slot,target=img.call_target(at)
        calls.append({'site_va':hex(at),'slot_va':hex(slot),'target_va':hex(target),'bytes':img.read(at,6,True).hex()})
    locs=[]
    for at in sorted(LOCATIONS):
        path,line,col=img.location(at)
        locs.append({'record_va':hex(at),'suffix':path,'line':line,'column':col})
    info={'artifact_sha256':SHA,'coordinate_system':'linked ELF virtual addresses',
          'constants':constants,'function_count':len(functions),'windows':len(windows),'layout_rows':len(layout),
          'branches':len(branches),'series_cases':len(series),'walk_cases':len(walks),'walk_sites':len(coverage),'receipt_cases':len(cases),
          'caller_cases':len(callers),'rounding_witnesses':1,'tag_cases':len(tags),'tag_bit_cases':len(tag_bits),'gate_edges':len(gate_coverage),'range_rows':len(ranges),'packing_cases':len(packing),'last_success_excess_model':bnd,
          'last_success_model':specification(bnd,d),'first_failure_model':specification(bnd+1,d),
          'calls':calls,'source_locations':locs,
          'limitations':'The byte walks cover the selected loop and selected conditional branches with modeled data, decoder and unsigned division; other logic is a static lift, not captured node execution or full CFG coverage.'}
    (out/'evidence.json').write_text(json.dumps(info,sort_keys=True,indent=2)+'\n',encoding='utf8')
    return info


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out',required=True,type=Path)
    args=p.parse_args()
    info=build(Image(BINARY.read_bytes()),args.out)
    print('wrote %d byte-bound functions and %d modeled series cases' % (info['function_count'],info['series_cases']))

if __name__ == '__main__':
    main()
