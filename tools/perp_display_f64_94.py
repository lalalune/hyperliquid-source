#!/usr/bin/env python3
"""Static node #94 evidence: two perp raw-quantity to binary64 paths."""
import argparse
import csv
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import elf_index
import fde_extents

TARGET = 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
TABLE = 0x6f7470
BODIES = {
    0x45a47a0: '536f0e5d7412d73ef9239e88d47864d1a2c23b70213baf385ae3acc59c00c423',
    0x45a4b80: '2fa38f98b5b6d14d4ee85d59fc1b04a824d8463e6423c0f605ccc0f7d0dc95bd',
}
MASK = (1 << 64) - 1


def checked_input(data):
    if hashlib.sha256(data).hexdigest() != DIGEST:
        raise ValueError('target SHA-256 mismatch')


def file_offset(secs, va, size=1, executable=False):
    if size <= 0:
        raise ValueError('invalid extent')
    matches = [s for s in secs if s['type'] != 8 and (not executable or s['flags'] & 4)
               and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('range has no unique file-backed section')
    s = matches[0]
    return s['offset'] + va - s['address']


def body_check(data, secs, fde):
    start, end = fde['start'], fde['end']
    if start not in BODIES or end <= start:
        raise ValueError('unknown body')
    off = file_offset(secs, start, end - start, executable=True)
    body = data[off:off + end - start]
    if hashlib.sha256(body).hexdigest() != BODIES[start]:
        raise ValueError('body bytes changed')
    return body, off


def rip_target(data, secs, va, prefix):
    off = file_offset(secs, va, len(prefix) + 4, executable=True)
    if data[off:off + len(prefix)] != prefix:
        raise ValueError('instruction prefix changed')
    return va + len(prefix) + 4 + struct.unpack_from('<i', data, off + len(prefix))[0]


def conditional(data, secs, va, opcode):
    off = file_offset(secs, va, 2, executable=True)
    if data[off] != opcode:
        raise ValueError('branch opcode changed')
    return va + 2 + struct.unpack_from('<b', data, off + 1)[0]


def bits_to_fraction(bits):
    exp = (bits >> 52) & 0x7ff
    mantissa = bits & ((1 << 52) - 1)
    if bits >> 63 or exp == 0x7ff:
        raise ValueError('expected positive finite binary64')
    if exp == 0:
        return Fraction(mantissa, 1 << 1074)
    significand = (1 << 52) | mantissa
    power = exp - 1023 - 52
    return Fraction(significand << power, 1) if power >= 0 else Fraction(significand, 1 << -power)


def round_even_div(n, d):
    q, r = divmod(n, d)
    return q + (2 * r > d or (2 * r == d and q & 1))


def rounded_binary64(value):
    """Round nonnegative Fraction to binary64 bits, nearest/ties-to-even."""
    if value < 0:
        raise ValueError('negative input')
    if not value:
        return 0
    n, d = value.numerator, value.denominator
    exponent = n.bit_length() - d.bit_length()
    if (n < (d << exponent)) if exponent >= 0 else ((n << -exponent) < d):
        exponent -= 1
    if exponent < -1022:
        mant = round_even_div(n << 1074, d)
        if mant > 1 << 52:
            raise ValueError('subnormal rounding failed')
        return mant
    shift = 52 - exponent
    mant = round_even_div(n << shift, d) if shift >= 0 else round_even_div(n, d << -shift)
    if mant == 1 << 53:
        mant >>= 1
        exponent += 1
    if exponent > 1023:
        return 0x7ff0000000000000
    return ((exponent + 1023) << 52) | (mant - (1 << 52))


def scale_bits(raw, table_bits):
    if not 0 <= raw <= MASK:
        raise ValueError('raw input is not u64')
    denominator = bits_to_fraction(table_bits)
    if not denominator:
        raise ValueError('zero scale')
    # SSE adds exactly represented low- and high-half terms first, rounding to f64;
    # DIVSD rounds a second time. Do not replace with one exact rational division.
    first = bits_to_fraction(rounded_binary64(Fraction(raw)))
    return rounded_binary64(first / denominator)


def classify(kind, raw, asset, namespace, length, dec):
    if kind not in ('price', 'size') or any(not 0 <= x <= MASK for x in (raw, asset, namespace, length)) or not 0 <= dec <= 255:
        raise ValueError('invalid input')
    if kind == 'size' and raw == 0:
        return 'zero', None
    q, r = divmod(asset, 10000)
    if q != namespace or r >= length:
        return 'asset_failure', None
    if kind == 'price' and dec >= 7:
        return 'decimal_failure', None
    return 'divide', 6 - dec if kind == 'price' else dec



def interpreted(data, secs, kind, raw, asset, namespace, length, dec, words):
    """Execute the two fixed, fully checked bodies' integer control/data flow.

    Metadata loads are supplied as values; failure calls are terminal markers. SSE
    is evaluated with rational arithmetic and round-to-nearest ties-to-even.
    """
    if kind not in ('price', 'size') or any(not 0 <= x <= MASK for x in (raw, asset, namespace, length)) or not 0 <= dec <= 255:
        raise ValueError('invalid input')
    base = 0x45a47a0 if kind == 'price' else 0x45a4b80
    def read(va, size):
        off = file_offset(secs, va, size, executable=True)
        return data[off:off+size]
    if kind == 'size':
        if read(base,3) != bytes.fromhex('4885ff'):
            raise ValueError('zero test changed')
        target=conditional(data,secs,base+3,0x74)
        if raw == 0:
            if read(target,4) != bytes.fromhex('0f57c0c3'):
                raise ValueError('zero return changed')
            return 'zero', None, 0
    mov = base + (4 if kind == 'price' else 8)
    if read(mov,2) != bytes.fromhex('48ba'):
        raise ValueError('reciprocal load changed')
    magic = int.from_bytes(read(mov+2,8),'little')
    shift_va = base + (0x14 if kind == 'price' else 0x18)
    shift = read(shift_va,4)
    if shift[:3] != bytes.fromhex('48c1ea'):
        raise ValueError('quotient shift changed')
    quotient = ((asset * magic) >> 64) >> shift[3]
    b1 = base + (0x1c if kind == 'price' else 0x20)
    failure = conditional(data,secs,b1,0x75)
    if quotient != namespace:
        return 'asset_failure', None, failure
    multiply = base + (0x1e if kind == 'price' else 0x22)
    instr=read(multiply,7)
    if instr[:3] != bytes.fromhex('4869c2'):
        raise ValueError('remainder multiplier changed')
    divisor=int.from_bytes(instr[3:7],'little',signed=True)
    remainder=(asset-quotient*divisor)&MASK
    b2 = base + (0x2c if kind == 'price' else 0x30)
    failure2 = conditional(data,secs,b2,0x73)
    if remainder >= length:
        return 'asset_failure', None, failure2
    if kind == 'price':
        cmp_instr=read(base+0x3f,4)
        if cmp_instr[:3] != bytes.fromhex('4883f8'):
            raise ValueError('decimal test changed')
        failure=conditional(data,secs,base+0x43,0x73)
        if dec >= cmp_instr[3]:
            return 'decimal_failure', None, failure
        mov=read(base+0x45,5)
        if mov[0] != 0xb9:
            raise ValueError('price exponent constant changed')
        index=int.from_bytes(mov[1:],'little')-dec
    else:
        index=dec
    # PUNPCKLDQ makes two exact doubles; SUBPD removes their biases.
    const_off=file_offset(secs,0x203e80,8)
    bias_off=file_offset(secs,0x202ea0,16)
    lo_tag,hi_tag=struct.unpack_from('<II',data,const_off)
    bias_lo,bias_hi=struct.unpack_from('<QQ',data,bias_off)
    lo=bits_to_fraction(((lo_tag << 32)|(raw & 0xffffffff))) - bits_to_fraction(bias_lo)
    hi=bits_to_fraction(((hi_tag << 32)|(raw >> 32))) - bits_to_fraction(bias_hi)
    numerator=bits_to_fraction(rounded_binary64(lo+hi))
    result=rounded_binary64(numerator/bits_to_fraction(words[index]))
    return 'divide',index,result


def relative_relocations(data,secs,targets):
    relsec = [s for s in secs if s['name']=='.rela.dyn' and s['type'] != 8]
    if len(relsec)!=1 or relsec[0]['size']%24:
        raise ValueError('invalid relocation section')
    s=relsec[0]; found={}
    for offset in range(s['offset'],s['offset']+s['size'],24):
        place,info,addend=struct.unpack_from('<QQq',data,offset)
        if place in targets:
            if place in found or info != 8:
                raise ValueError('ambiguous or non-relative relocation')
            found[place]=addend
    if set(found)!=set(targets):
        raise ValueError('missing relocation')
    return found


def table_words(data, secs):
    off = file_offset(secs, TABLE, 256 * 8)
    words = struct.unpack_from('<256Q', data, off)
    for w in words:
        if not bits_to_fraction(w):
            raise ValueError('zero table entry')
    return words, off


def write_tsv(out, name, fields, rows):
    with (out / name).open('w', newline='', encoding='ascii') as f:
        w = csv.writer(f, delimiter='\t', lineterminator='\n')
        w.writerow(fields)
        w.writerows(rows)


def generate(data, out):
    checked_input(data)
    secs = elf_index.sections(data)
    _, fdes, _ = fde_extents.fde_extents(data)
    selected = []
    for start in BODIES:
        found = [f for f in fdes if f['start'] == start and 'index' in f]
        if len(found) != 1:
            raise ValueError('missing or ambiguous indexed FDE')
        f = found[0]
        body, off = body_check(data, secs, f)
        selected.append({'entry_va': hex(start), 'end_va_exclusive': hex(f['end']),
                         'fde_va': hex(f['fde']), 'body_file_offset': hex(off),
                         'body_size': len(body), 'body_sha256': hashlib.sha256(body).hexdigest(),
                         'body_hex': body.hex()})
    words, table_off = table_words(data, secs)
    prior_offset=file_offset(secs,0x5b8f60,256*8)
    previous_words=struct.unpack_from('<256Q',data,prior_offset)
    recurrence_mismatches=sum(rounded_binary64(bits_to_fraction(words[i-1])*10)!=words[i] for i in range(1,256))
    checks = [(0x45a47b1, bytes.fromhex('48f7e2')), (0x45a4b95, bytes.fromhex('48f7e2'))]
    for va, pat in checks:
        off = file_offset(secs, va, len(pat), executable=True)
        if data[off:off+len(pat)] != pat:
            raise ValueError('multiply bytes changed')
    refs = []
    for va, prefix in [(0x45a47f1, '660f620d'), (0x45a47f9, '660f5c0d'),
                       (0x45a4810, '488d05'), (0x45a4bc8, '660f620d'),
                       (0x45a4bd0, '660f5c0d'), (0x45a4be4, '488d0d')]:
        target = rip_target(data, secs, va, bytes.fromhex(prefix))
        expected = {'660f620d': 0x203e80, '660f5c0d': 0x202ea0,
                    '488d05': TABLE, '488d0d': TABLE}[prefix]
        if target != expected:
            raise ValueError('unexpected RIP-relative target')
        refs.append((hex(va), prefix, hex(target), hex(file_offset(secs, target, 8))))
    branches = []
    for va, op, meaning in [(0x45a47bc,0x75,'namespace mismatch'),
                            (0x45a47cc,0x73,'index outside length'),
                            (0x45a47e3,0x73,'decimal at least seven'),
                            (0x45a4b83,0x74,'raw zero'),
                            (0x45a4ba0,0x75,'namespace mismatch'),
                            (0x45a4bb0,0x73,'index outside length')]:
        branches.append((hex(va), hex(op), hex(conditional(data, secs, va, op)), meaning))
    rel=relative_relocations(data,secs,(0x56f21c0,0x56f3350,0x576e470,0x576e150))
    locations=[]
    for va in (0x56f21c0,0x56f3350):
        off=file_offset(secs,va,24)
        _,length,line,col=struct.unpack_from('<QQII',data,off)
        pathoff=file_offset(secs,rel[va],length)
        raw_path=data[pathoff:pathoff+length].decode('ascii')
        marker='l1/src/'
        if marker not in raw_path:
            raise ValueError('unrecognised source path suffix')
        path=raw_path[raw_path.rindex(marker):]
        locations.append((hex(va),path,line,col,hex(rel[va])))
    reloc_rows=[(hex(k),hex(rel[k])) for k in sorted(rel)]
    pow_rows=[]
    for k, bits in enumerate(words):
        exact = rounded_binary64(Fraction(10**k))
        pow_rows.append((k, hex(TABLE+k*8), f'{bits:016x}', f'{exact:016x}', bits-exact))
    raw_values=(0,1,9,10,999999,1000000,(1<<53)-1,1<<53,(1<<53)+1,(1<<53)+3,(1<<63)-1,(1<<64)-1)
    vectors=[]
    for k, bits in enumerate(words):
        for raw in raw_values:
            actual=scale_bits(raw,bits)
            ideal=rounded_binary64(Fraction(raw,10**k))
            vectors.append((k, raw, f'{actual:016x}', f'{ideal:016x}', actual-ideal))
    cases=[]
    for kind in ('price','size'):
        for raw in (0,1):
            for asset,ns,length in ((0,0,1),(0,1,1),(10000,1,1),(10001,1,1)):
                for dec in (0,6,7,255):
                    result, exponent=classify(kind,raw,asset,ns,length,dec)
                    cases.append((kind,raw,asset,ns,length,dec,result,'' if exponent is None else exponent))
    machine=[]
    for kind in ('price','size'):
        for raw in (0,1,(1<<53)+1,MASK):
            for asset,ns,length in ((0,0,1),(0,1,1),(10000,1,1),(10001,1,1),
                                    (9999,0,10000),(MASK,MASK//10000,10000)):
                for dec in range(256):
                    got,index,bits=interpreted(data,secs,kind,raw,asset,ns,length,dec,words)
                    expected,ei=classify(kind,raw,asset,ns,length,dec)
                    if (got,index)!=(expected,ei):
                        raise ValueError('control-flow model mismatch')
                    if got=='divide' and bits!=scale_bits(raw,words[index]):
                        raise ValueError('floating model mismatch')
                    machine.append((kind,raw,asset,ns,length,dec,got,'' if index is None else index,
                                    f'{bits:016x}' if got in ('divide','zero') else hex(bits)))
    out.mkdir(parents=True,exist_ok=True)
    write_tsv(out,'machine-cases.tsv',('kind','raw','asset','namespace','length','decimal_byte','outcome','table_index','result_bits_or_failure_va'),machine)
    write_tsv(out,'locations.tsv',('record_va','path','line','column','path_va'),locations)
    write_tsv(out,'relocations.tsv',('slot_va','relative_addend'),reloc_rows)
    write_tsv(out,'power-table.tsv',('index','va','observed_f64_bits','ideal_10_power_bits','bit_delta'),pow_rows)
    write_tsv(out,'rounding-vectors.tsv',('exponent','raw_u64','two_round_bits','one_round_exact_decimal_bits','bit_delta'),vectors)
    write_tsv(out,'branch-cases.tsv',('kind','raw','asset','namespace','length','decimal_byte','outcome','table_index'),cases)
    write_tsv(out,'branches.tsv',('va','opcode','taken_target_va','predicate'),branches)
    write_tsv(out,'references.tsv',('instruction_va','prefix_hex','target_va','target_file_offset'),refs)
    unpack_constants = data[file_offset(secs,0x203e80,8):file_offset(secs,0x203e80,8)+8].hex()
    subtract_constants = data[file_offset(secs,0x202ea0,16):file_offset(secs,0x202ea0,16)+16].hex()
    if unpack_constants != '0000304300003045' or subtract_constants != '00000000000030430000000000003045':
        raise ValueError('SSE conversion constants changed')
    reciprocal=int.from_bytes(data[file_offset(secs,0x45a47a6,8):file_offset(secs,0x45a47a6,8)+8],'little')
    divisor=int.from_bytes(data[file_offset(secs,0x45a47c1,4):file_offset(secs,0x45a47c1,4)+4],'little')
    error=divisor*reciprocal-(1<<75)
    if divisor != 10000 or error != 432 or MASK*error >= 1<<75:
        raise ValueError('reciprocal proof bound changed')
    summary={'unpack_constants_hex':unpack_constants,'subtract_constants_hex':subtract_constants,
             'artifact_sha256':DIGEST,'coordinate_system':'ELF virtual addresses, linked image',
             'functions':selected,'table_file_offset':hex(table_off),'table_entries_read':len(words),
             'table_entries_differ_from_correctly_rounded_10_power':sum(r[-1]!=0 for r in pow_rows),
             'earlier_table_va':hex(0x5b8f60),
             'table_words_equal_to_earlier_copy':sum(a==b for a,b in zip(words,previous_words)),
             'table_round_multiply_by_ten_transition_mismatches':recurrence_mismatches,
             'rounding_vectors':len(vectors),'rounding_vectors_differ_from_exact_decimal':sum(r[-1]!=0 for r in vectors),
             'branch_cases':len(cases),'interpreted_cases':len(machine),'divisor':divisor,'reciprocal':hex(reciprocal),
             'reciprocal_error':error,
             'reciprocal_error_times_u64_max_less_than_2_pow_75':MASK*error < (1<<75),
             'limits':'FDEs describe unwind extents; no target execution or caller interpretation. Values assume round-to-nearest ties-to-even.'}
    (out/'evidence.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='ascii')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out',required=True,type=Path)
    args=p.parse_args()
    generate((ROOT/TARGET).read_bytes(),args.out)


if __name__ == '__main__':
    main()
