#!/usr/bin/env python3
"""Static node94 reserve reweighting evidence; never execute captured code."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT/'tools'))
from elf_index import sections
from fde_extents import eh_frame_records
from info_request_path import Elf, relative_relocs, first_party_locations

SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
DECODE_SHA = '2d292cc94a0f0492c0dfa9febca1d70e8195d9fae1fa5068f76d906dfcea69f6'
U64 = (1 << 64)-1
U32 = (1 << 32)-1


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def frozen():
    raw = (HERE/'decode.json').read_bytes()
    require(hashlib.sha256(raw).hexdigest() == DECODE_SHA, 'frozen decode changed')
    return json.loads(raw)


def relative(ins, va, offset):
    return va+len(ins)+struct.unpack_from('<i', ins, offset)[0]


def structural(data):
    """Deliberately separate SHA admission from structure for corruption tests."""
    elf = Elf(data)
    _, frames = eh_frame_records(data, sections(data))
    relocations = relative_relocs(elf)
    functions, branches, calls = [], [], []
    for f in frozen():
        start, end = int(f['start'],16), int(f['end'],16)
        selected = [r for r in frames if r['start'] == start]
        require(len(selected) == 1, 'ambiguous FDE')
        row = selected[0]
        require(row['end'] == end and row['fde'] == int(f['fde'],16)
                and row['cie'] == int(f['cie'],16), 'FDE coordinates changed')
        require(row['lsda'] == (None if f['lsda'] is None else int(f['lsda'],16)), 'LSDA pointer changed')
        for key in ('fde','cie'):
            raw = bytes.fromhex(f[key+'_bytes'])
            require(elf.read(int(f[key],16),len(raw)) == raw, key+' bytes changed')
        require(hashlib.sha256(elf.read(start,end-start)).hexdigest() == f['body_sha256'],
                'body bytes changed')
        at = start if f['role'] != 'caller_link' else 0x3709f41
        instruction_starts = {int(i['va'],16) for i in f['instructions']}
        for i in f['instructions']:
            va, ins = int(i['va'],16), bytes.fromhex(i['bytes'])
            require(va == at and elf.read(va,len(ins)) == ins, 'decode coverage changed')
            at += len(ins)
            mnemonic = i['asm'].split()[0]
            if mnemonic.startswith('j'):
                if ins[0] in (0x0f,0xe9):
                    target = relative(ins,va,2 if ins[0] == 0x0f else 1)
                else:
                    require(ins[0] == 0xeb or 0x70 <= ins[0] <= 0x7f, 'branch opcode')
                    target = va+2+struct.unpack('<b',ins[1:])[0]
                require(target == int(i['asm'].split()[1],16), 'branch target changed')
                if f['role'] != 'caller_link':
                    require(target in instruction_starts or
                            (va == 0x370e86a and target == 0x370e2a0), 'branch leaves selected body')
                branches.append(dict(site=hex(va),kind=mnemonic,target=hex(target),
                                     fallthrough=None if mnemonic == 'jmp' else hex(at),bytes=ins.hex()))
            if mnemonic == 'call':
                slot = None
                if ins[0] == 0xe8:
                    target = relative(ins,va,1)
                    require(target == int(i['asm'].split()[1],16), 'direct call target changed')
                else:
                    require(ins[:2] == b'\xff\x15', 'call encoding changed')
                    slot = relative(ins,va,2)
                    require(slot == 0x5773190 and relocations.get(slot) == 0x358dcd0,
                            'recorder relocation changed')
                    target = relocations[slot]
                calls.append(dict(site=hex(va),target=hex(target),slot=None if slot is None else hex(slot),bytes=ins.hex()))
        require(at == (end if f['role'] != 'caller_link' else 0x3709f65), 'range coverage changed')
        functions.append({k:v for k,v in f.items() if k != 'instructions'} |
                         dict(file_offset=hex(elf.off(start)),full_semantic_scope=False,
                              retained_instruction_count=len(instruction_starts)))

    # Connect the writer to the reader's exact outer-entry final word.
    anchors = {0x3709f4d:'488db828010000', 0x370e854:'4983c7f8',
               0x370e858:'4c89ff', 0x3708d50:'4a8b4c12f8',
               0x370e39f:'44894e30', 0x370e3ce:'44894e30',
               0x370e399:'48f7f5', 0x370e3c9:'f7f5',
               0x370e466:'48f7f1', 0x370e493:'f7f1',
               0x370e49f:'4c8937', 0x370e4a5:'4801d8', 0x370e4aa:'488907'}
    for va, raw in anchors.items():
        require(elf.read(va,len(bytes.fromhex(raw))).hex() == raw, 'ordered arithmetic anchor changed')
    locs = first_party_locations(elf,relocations)
    expected = {0x56f1f00:('l1/src/qtys/impl_sz.rs',9,1),
                0x56f1f30:('l1/src/qtys/impl_ntl.rs',26,1),
                0x56f1de8:('l1/src/qtys/mod.rs',829,1)}
    for va, value in expected.items():
        require(locs.get(va) == value, 'Location changed')
    return dict(target_sha256=SHA,coordinates='ELF virtual addresses; explicit file offsets',
                functions=functions,branches=branches,calls=calls,
                ordered_anchors=[dict(va=hex(v),bytes=r) for v,r in anchors.items()],
                locations=[dict(va=hex(v),path=r[0],line=r[1],column=r[2]) for v,r in expected.items()],
                semantic_domain=dict(size_at_0x20=0,selected_count_at_0x10=0,price_like_word_at_0x28=0,
                                     numerator='unsigned row +0x08',old_divisor='positive u32 row +0x30',new_divisor='positive u32 edx'),
                limits=['General numerator formula, nonzero sizes and complete producer invariants are outside semantic scope.',
                        'Hash helpers, recorder effects/termination, caller rollback and complete input admission are unresolved.',
                        'No economic denomination, full component gate, Rust reconstruction or captured execution.'],
                counts=dict(full_retained_bodies=2,full_retained_body_bytes=1474,
                            full_retained_instructions=415,caller_link_instructions=8,
                            conditional_branches=sum(b['kind'] != 'jmp' for b in branches),
                            unconditional_branches=sum(b['kind'] == 'jmp' for b in branches),calls=len(calls)))


def model(total, numerator, old, new, *, recorder_returns=True):
    """Synthetic value/store contract for the stated zero-size/count slice only."""
    require(all(type(x) is int and 0 <= x <= U64 for x in (total,numerator)), 'u64 width')
    require(all(type(x) is int and 1 <= x <= U32 for x in (old,new)), 'positive u32 model precondition')
    result = dict(total=total,divisor=old,writes=[],recorders=[])
    if old == new:
        return result | dict(status='no_op')
    before = numerator//old
    result['divisor'] = new
    result['writes'].append(['row+0x30',new])
    after = numerator//new
    if total < before:
        result['recorders'].append('unsigned_subtraction')
        if not recorder_returns:
            return result | dict(status='recorder_continuation_unknown')
        result['total'] = after
        result['writes'].append(['total',after])
        return result | dict(status='return')
    subtotal = total-before
    result['total'] = subtotal
    result['writes'].append(['total',subtotal])
    if subtotal+after > U64:
        result['recorders'].append('unsigned_addition')
        if not recorder_returns:
            return result | dict(status='recorder_continuation_unknown')
    result['total'] = min(U64,subtotal+after)
    result['writes'].append(['total',result['total']])
    return result | dict(status='return')


def oracle(total,numerator,old,new):
    """Closed form for returned total only; does not predict the store trace."""
    if old == new:
        return total
    require(old > 0 and new > 0, 'positive-divisor oracle precondition')
    removed = min(total,numerator//old)
    added = numerator//new
    return min(U64,total-removed+added)


def samples():
    chosen = [(2,10,1,2), (U64,10,2,1), (100,10,1,2),
              (5,0,1,1), (U64, U64,1,2), (0,1,2,1)]
    records = [dict(input=dict(total=s,numerator=n,old=o,new=v),output=model(s,n,o,v)) for s,n,o,v in chosen]
    for args in ((2,10,1,2),(U64,10,2,1)):
        records.append(dict(input=dict(zip(('total','numerator','old','new'),args)) |
                            dict(recorder_returns=False),output=model(*args,recorder_returns=False)))
    comparisons, wrong_order, no_op = 0,0,0
    for s in (0,1,2,5,U64-5,U64):
        for n in (0,1,2,9,10,(1<<63)-1,U64):
            for o in (1,2,3,U32):
                for v in (1,2,3,U32):
                    actual=model(s,n,o,v)
                    if o == v:
                        no_op += 1
                    else:
                        comparisons += 1
                        require(actual['total'] == oracle(s,n,o,v), 'closed-form mismatch')
                        wrong=max(0,min(U64,s+n//v)-n//o)
                        wrong_order += actual['total'] != wrong
    return dict(cases=records,sweep=dict(total_cases=672,normal_changed_cases=comparisons,
                                       changed_case_mismatches=0,wrong_add_first_mismatches=wrong_order,
                                       no_op_cases=no_op),
                note='Synthetic algebra and state/store models; no target instructions were executed or emulated.')


def build(data):
    require(hashlib.sha256(data).hexdigest() == SHA,'target SHA-256 mismatch')
    return structural(data)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,default=ROOT/'artifacts/node/94/hl-node')
    p.add_argument('--out',required=True,type=Path)
    args=p.parse_args()
    try:
        evidence=build(args.binary.read_bytes())
        args.out.mkdir(parents=True,exist_ok=True)
        for name,value in (('evidence.json',evidence),('samples.json',samples())):
            (args.out/name).write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
    except (OSError,ValueError,KeyError,struct.error) as exc:
        print('reserve reweight evidence:',exc,file=sys.stderr)
        return 2
    print('PASS: 1474 retained body bytes, 415 instructions, 8 caller-link instructions; 672 positive-divisor synthetic cases')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
