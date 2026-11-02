#!/usr/bin/env python3
"""Verify a bounded node94 reserve adjustment from inert ELF bytes.

The frozen decode is a GNU objdump transcript, never an instruction emulator.
The numeric model assumes helper returns and default binary64 rounding.
"""
import argparse
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records
from info_request_path import Elf, relative_relocs, first_party_locations

TARGET_SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
DECODE_SHA = 'd6aea0014816c3746146fb5455d5025d079c71052e1c90a5090dfb61a54e0798'
LOW, HIGH = -(1 << 63), (1 << 63) - 1
FACTOR = Fraction(0x1028f5c28f5c29, 1 << 52)
CONSTANTS = {0x20a528: '295c8fc2f528f03f', 0x20a4b0: '000000000000f07f',
             0x20acb8: '000000000000e0c3', 0x20a7f0: '000000000000e043',
             0x20a2c8: 'ffffffffffffdf43'}
SLOTS = {0x5773178: 0x37d79e0, 0x5773228: 0x37e4fb0,
         0x5773190: 0x358dcd0, 0x576e048: 0x157aa10, 0x57738b8: 0x3708bf0}
LOCATIONS = {0x56f3a78: ('l1/src/qtys/impl_ntl.rs', 62, 1),
             0x56f1cf8: ('l1/src/qtys/impl_ntl.rs', 62, 1),
             0x56f3a60: ('l1/src/qtys/mod.rs', 843, 1)}
EXEMPTIONS = ('010461c14e146ac35fe42271bdc1134ee31c703a',
              '31ca8395cf837de08b24da3f660e77761dfb974b',
              '768484f7e2ebb675c57838366c02ae99ba2a9b08',
              'c64cc00b46101bd40aa1c3121195e85c0b0918d8',
              '07bed5c08306e026797e5ea93c293abc5673c2ad',
              '93e2551d821dda1080a372f0b04b86468320333d',
              'a15099a30bbf2e68942d6f4c43d70d04faeab0a0',
              'dfc24b077bc1425ad1dea75bcb6f8158e10df303')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def frozen_decode():
    raw = (HERE / 'decode.json').read_bytes()
    require(hashlib.sha256(raw).hexdigest() == DECODE_SHA, 'frozen decoder transcript changed')
    return json.loads(raw)


def rel32(ins, va, displacement_offset):
    return va + len(ins) + struct.unpack_from('<i', ins, displacement_offset)[0]


def structural(data):
    """Validate structure separately so controls can bypass only whole-file SHA."""
    elf = Elf(data)
    secs = sections(data)
    _, frames = eh_frame_records(data, secs)
    relocations = relative_relocs(elf)
    locations = first_party_locations(elf, relocations)
    function_records, edges, branches = [], [], []
    for f in frozen_decode():
        start, end = int(f['start'], 16), int(f['end'], 16)
        matches = [r for r in frames if r['start'] == start]
        require(len(matches) == 1, 'missing or duplicate FDE')
        row = matches[0]
        require(row['end'] == end and row['fde'] == int(f['fde'], 16)
                and row['cie'] == int(f['cie'], 16) and row['lsda'] is None, 'FDE identity changed')
        for kind in ('fde', 'cie'):
            raw = bytes.fromhex(f[kind + '_bytes'])
            require(elf.read(int(f[kind], 16), len(raw)) == raw, kind + ' bytes changed')
        body = elf.read(start, end - start)
        require(hashlib.sha256(body).hexdigest() == f['body_sha256'], 'bounded body changed')
        at = start
        starts = {int(i['va'], 16) for i in f['instructions']}
        for i in f['instructions']:
            va, ins = int(i['va'], 16), bytes.fromhex(i['bytes'])
            require(va == at and ins and elf.read(va, len(ins)) == ins, 'decode byte coverage changed')
            at += len(ins)
            mnemonic = i['asm'].split()[0]
            if mnemonic.startswith('j'):
                if ins[0] in (0xe9, 0x0f):
                    target = rel32(ins, va, 1 if ins[0] == 0xe9 else 2)
                else:
                    require(ins[0] == 0xeb or 0x70 <= ins[0] <= 0x7f, 'bad short branch')
                    target = va + 2 + struct.unpack('<b', ins[1:])[0]
                require(target in starts and target == int(i['asm'].split()[1], 16), 'branch target changed')
                branches.append(dict(site=hex(va), kind=mnemonic, target=hex(target),
                                     fallthrough=None if mnemonic == 'jmp' else hex(at), bytes=ins.hex()))
            if mnemonic == 'call':
                if ins[0] == 0xe8:
                    target, slot = rel32(ins, va, 1), None
                    require(target == int(i['asm'].split()[1], 16), 'direct call changed')
                else:
                    require(ins[:2] == b'\xff\x15', 'unknown call encoding')
                    slot = rel32(ins, va, 2)
                    require(slot in SLOTS and relocations.get(slot) == SLOTS[slot], 'call relocation changed')
                    target = relocations[slot]
                edges.append(dict(site=hex(va), target=hex(target),
                                  slot=None if slot is None else hex(slot), bytes=ins.hex()))
        require(at == end, 'decode does not cover complete FDE range')
        function_records.append({k: v for k, v in f.items() if k != 'instructions'} |
                                dict(file_offset=hex(elf.off(start)),
                                     length=end-start, instruction_count=len(starts)))
    for va, raw in CONSTANTS.items():
        require(elf.read(va, 8).hex() == raw, 'binary64 constant changed')
    for slot, target in SLOTS.items():
        require(relocations.get(slot) == target, 'helper relocation changed')
    for va, expected in LOCATIONS.items():
        require(locations.get(va) == expected, 'source Location changed')
    require(elf.read(0x21bc862, 11).hex() == 'ba04000000ff154b705b03', 'mode-4 caller edge changed')
    require(elf.read(0x21bc86d, 5).hex() == '4885c07e13', 'positive-only caller branch changed')

    # Validate every RIP-relative SIMD comparison operand of the existing list
    # helper, not just the first 20 bytes. MOVD zeros its high twelve bytes.
    predicate = frozen_decode()[1]['instructions']
    comparisons = [i for i in predicate if i['asm'].startswith('pcmpeqb') and '[rip+' in i['asm']]
    require(len(comparisons) == 16, 'predicate comparison count changed')
    exempt_records = []
    for index in range(8):
        tail_i, head_i = comparisons[2*index:2*index+2]
        tail_va = rel32(bytes.fromhex(tail_i['bytes']), int(tail_i['va'], 16), 4)
        head_va = rel32(bytes.fromhex(head_i['bytes']), int(head_i['va'], 16), 4)
        tail, head = elf.read(tail_va, 16), elf.read(head_va, 16)
        require(tail[4:] == bytes(12) and (head + tail[:4]).hex() == EXEMPTIONS[index],
                'fixed-list bytes or zero tail changed')
        exempt_records.append(dict(index=index, head_va=hex(head_va), tail_va=hex(tail_va),
                                   address=EXEMPTIONS[index], tail_bytes=tail.hex()))
    closure = []
    for target, status in ((0x36f57f0, 'row lookup: body outside new semantic scope'),
                           (0x37d79e0, 'aggregate: existing RE-007-margin-path-94; inputs not independently closed here'),
                           (0x37e4fb0, 'eight-address predicate: complete static body, previously described by fees-open-order-cap-94'),
                           (0x399c7a0, 'hash: body outside new semantic scope'),
                           (0x358dcd0, 'recorder: body and effects outside new semantic scope; conditional model assumes return'),
                           (0x157aa10, 'unwrap failure: body outside new semantic scope; no normal return claimed')):
        matches = [f for f in frames if f['start'] == target]
        require(len(matches) == 1, 'callee FDE missing or ambiguous')
        closure.append(dict(target=hex(target), end=hex(matches[0]['end']),
                            fde=hex(matches[0]['fde']), status=status))
    return dict(target_sha256=TARGET_SHA, coordinates='ELF virtual addresses; explicit file_offset fields',
                functions=function_records, branches=branches, calls=edges,
                constants=[dict(va=hex(va), bytes=raw, binary64=repr(struct.unpack('<d', bytes.fromhex(raw))[0]))
                           for va, raw in CONSTANTS.items()],
                locations=[dict(va=hex(va), path=v[0], line=v[1], column=v[2]) for va,v in LOCATIONS.items()],
                exemption_list=exempt_records, helper_closure=closure,
                counts=dict(function_ranges=len(function_records),
                            instructions=sum(f['instruction_count'] for f in function_records),
                            body_bytes=sum(f['length'] for f in function_records),
                            conditional_branches=sum(b['kind'] != 'jmp' for b in branches),
                            unconditional_branches=sum(b['kind'] == 'jmp' for b in branches), calls=len(edges)),
                unknowns=['Decimal exponents, price/size/wei denomination, all producers of the reserve table.',
                          'Aggregate helper and hash/lookup/recorder/failure bodies are not semantically closed here.',
                          'Full caller census, source-level function boundaries and exceptional cold fragments.',
                          'Target MXCSR, external helper effects and actual chain/runtime reachability.'],
                captured_execution=False, reconstructed_rust=False, gate_requested=False)


def round_binary64_positive(value):
    """Integer-only ties-to-even rounding of this packet's positive normal values."""
    if value == 0:
        return value
    require(value > 0, 'positive normal value required')
    exponent = value.numerator.bit_length() - value.denominator.bit_length()
    if value < Fraction(2) ** exponent:
        exponent -= 1
    step = Fraction(2) ** (exponent - 52)
    scaled = value / step
    q, r = divmod(scaled.numerator, scaled.denominator)
    if 2*r > scaled.denominator or (2*r == scaled.denominator and q % 2):
        q += 1
    return q * step


def rational_reserve(word):
    """Independent exact-rational oracle: round conversion, then multiplication."""
    require(type(word) is int and 0 <= word <= HIGH, 'nonnegative signed reserve required')
    converted = round_binary64_positive(Fraction(word))
    product = round_binary64_positive(converted * FACTOR)
    return min(HIGH, product.numerator // product.denominator)


def float_reserve(word):
    require(type(word) is int and 0 <= word <= HIGH, 'nonnegative signed reserve required')
    return min(HIGH, int(float(word) * struct.unpack('<d', bytes.fromhex(CONSTANTS[0x20a528]))[0]))


def model(equity, requirement, reserve=0, *, exempt=False, found=True, row_word=0):
    """Conditional numeric model; all external helpers are assumed to return."""
    require(type(equity) is int and LOW <= equity <= HIGH, 'equity width')
    require(type(requirement) is int and LOW <= requirement <= HIGH, 'requirement width')
    require(type(reserve) is int and LOW <= reserve <= HIGH, 'reserve width')
    if requirement < 0:
        return dict(status='requirement_unwrap_error')
    subtotal = max(LOW, equity-requirement)
    events = ['first_subtraction'] if equity-requirement < LOW else []
    if not exempt and found and reserve < 0:
        return dict(status='reserve_unwrap_error', recorder_events=events)
    adjustment = 0 if exempt or not found else float_reserve(reserve)
    if subtotal-adjustment < LOW:
        events.append('second_subtraction')
    return dict(status='return', amount=max(LOW, subtotal-adjustment),
                adjustment=adjustment, flag=int(row_word != 0), recorder_events=events)


def samples():
    values = set(range(1001))
    for k in range(1, 63):
        values.update(x for x in (2**k-2, 2**k-1, 2**k, 2**k+1, 2**k+2) if 0 <= x <= HIGH)
    edge = HIGH * FACTOR.denominator // FACTOR.numerator
    values.update(edge+i for i in range(-2048, 2049, 127))
    values.add(HIGH)
    scaled = []
    for n in sorted(values):
        independent, host = rational_reserve(n), float_reserve(n)
        require(independent == host, 'binary64 model disagrees with exact-rational oracle')
        scaled.append(dict(reserve=n, adjustment=independent,
                           exact_101_over_100=n*101//100))
    cases = [dict(equity=1000, requirement=100, reserve=100),
             dict(equity=1000, requirement=100, reserve=99),
             dict(equity=0, requirement=0, reserve=1),
             dict(equity=LOW, requirement=HIGH, reserve=HIGH),
             dict(equity=LOW+10, requirement=9, reserve=2),
             dict(equity=HIGH, requirement=0, reserve=HIGH),
             dict(equity=100, requirement=-1, reserve=0),
             dict(equity=100, requirement=1, reserve=-1),
             dict(equity=100, requirement=1, reserve=-1, exempt=True),
             dict(equity=100, requirement=1, reserve=-1, found=False),
             dict(equity=HIGH, requirement=HIGH, reserve=0, row_word=1),
             dict(equity=0, requirement=0, reserve=0, row_word=HIGH)]
    return dict(binary64_scaling=scaled, scalar_cases=[dict(input=x, output=model(**x)) for x in cases],
                note='Synthetic conditional model cases; no captured binary or instruction execution.')


def packet_samples():
    """Compact boundary witnesses; the full deterministic sweep stays in tests."""
    full = samples()
    edge = HIGH * FACTOR.denominator // FACTOR.numerator
    chosen = sorted({0, 1, 2, 99, 100, 101, 2**52-1, 2**52, 2**52+1,
                     2**53-1, 2**53, 2**53+1, 2**53+2, HIGH-1, HIGH,
                     edge-1, edge, edge+1})
    full['binary64_scaling'] = [dict(reserve=n, adjustment=rational_reserve(n),
                                     exact_101_over_100=n*101//100) for n in chosen]
    sweep = samples()['binary64_scaling']
    full['sweep_summary'] = dict(comparisons=len(sweep), model_mismatches=0,
                                wrong_exact_ratio_mismatches=sum(
                                    r['adjustment'] != min(HIGH, r['exact_101_over_100']) for r in sweep))
    return full


def build(data):
    require(hashlib.sha256(data).hexdigest() == TARGET_SHA, 'target SHA-256 mismatch')
    return structural(data)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, default=ROOT/'artifacts/node/94/hl-node')
    p.add_argument('--out', type=Path, required=True)
    args = p.parse_args()
    try:
        evidence = build(args.binary.read_bytes())
        args.out.mkdir(parents=True, exist_ok=True)
        for name, value in (('evidence.json', evidence), ('samples.json', packet_samples())):
            (args.out/name).write_text(json.dumps(value, indent=2, sort_keys=True)+'\n')
    except (OSError, ValueError, KeyError, struct.error) as exc:
        print('risk reserve evidence:', exc, file=sys.stderr)
        return 2
    print('PASS: 2 FDE ranges, 999 bytes, 224 instructions, 24 branches, 8 call edges')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
