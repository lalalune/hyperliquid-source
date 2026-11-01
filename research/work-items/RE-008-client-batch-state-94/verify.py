#!/usr/bin/env python3
"""Reproduce static exports/value fixtures and adversarial admission controls.

No captured execution or emulation. Below-identity controls are modified bytes
decoded by native tools and checked against structural obligations, not evaluated.
"""
from __future__ import annotations
import argparse
import copy
import gzip
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import evidence as e
import corpus

HERE=e.HERE


def freeze(pre_freeze_check=False):
    if pre_freeze_check:
        e.need(not (HERE/'PRE-RUST-FREEZE.json').exists(),'pre-freeze mode after freeze')
        return None
    receipt=json.loads((HERE/'PRE-RUST-FREEZE.json').read_text())
    for name,wanted in receipt['files'].items():
        e.need(e.digest((HERE/name).read_bytes())==wanted,'pre-Rust freeze: '+name)
    return e.digest((HERE/'PRE-RUST-FREEZE.json').read_bytes())


def retained_decoded(outputs):
    return {start:(e.native_rows(outputs[f'gnu/{start:x}.gnu.txt'].decode()),
                   e.native_rows(gzip.decompress(outputs[f'llvm/{start:x}.llvm.txt.gz']).decode()))
            for start in e.EXPECTED_STARTS}


def controls(elf,decoded,gnu,llvm):
    results=[]
    def rejected(name,action,**extra):
        try:action()
        except e.EvidenceError as err:
            results.append(dict(name=name,rejection=str(err),**extra))
        else:raise e.EvidenceError('negative control survived: '+name)
    data=bytearray(elf.data);data[-1]^=1
    rejected('changed byte under SHA admission',lambda:e.Elf(bytes(data)))
    rejected('truncated target under size admission',lambda:e.Elf(elf.data[:-1]))
    scope=json.loads((HERE/'scope.json').read_text())
    for label,edit in [
        ('wrong target',lambda s:s.update(sha256='0'*64)),
        ('missing full FDE',lambda s:s['ranges'].pop()),
        ('wrong range denominator',lambda s:s['ranges'][0].update(size=s['ranges'][0]['size']-1)),
        ('shortened full FDE',lambda s:s['ranges'][0].update(end=hex(int(s['ranges'][0]['end'],16)-1))),
    ]:
        changed=copy.deepcopy(scope);edit(changed)
        rejected('scope '+label,lambda s=changed:e.validate(elf,decoded,scope=s))
    changed=copy.deepcopy(decoded);changed.pop(e.EXPECTED_STARTS[-1])
    rejected('missing decoded function',lambda:e.validate(elf,changed))
    changed=copy.deepcopy(decoded);changed[e.EXPECTED_STARTS[0]][1][0]['raw']=b'\x90'
    rejected('LLVM byte partition disagreement',lambda:e.validate(elf,changed))
    # Concrete field, width, order, stride, branch and hash-wrapper changes. Each
    # is fresh native disassembly of the changed full FDE with body SHA disabled.
    mutations=[('proof offset', 72644350, 3, 1), ('proof last comparison', 72644360, 2, 1), ('proof guard', 72644370, 1, 1), ('QC round offset', 72644376, -1, 1), ('QC round comparison', 72644380, 2, 1), ('first hash skip', 72644391, 0, 1), ('parent hash second half', 72644399, -1, 1), ('parent full equality mask', 72644436, 1, 1), ('block verifier pointer', 72644452, -1, 1), ('block verifier callee', 72644467, 1, 1), ('block result guard', 72644480, 1, 1), ('tx count pointer', 72644513, -1, 1), ('tx row stride', 72644521, 2, 1), ('tx byte Arc offset', 72644564, -1, 1), ('hash rate', 72644686, 8, 1), ('hash delimiter', 72644698, 8, 1), ('tx bytes length offset', 72644712, -1, 1), ('hash result length', 72644742, 1, 1), ('tx row advance', 72644808, -1, 1), ('tx count guard', 72644863, 1, 1), ('tx block list pointer', 72644873, -1, 1), ('time word0', 72644986, 3, 1), ('time word1', 72645003, 3, 1), ('time word2', 72645020, 3, 1), ('block round load', 72645033, 3, 1), ('block digest selector', 72645040, 8, 1), ('missing proof guard', 72645135, 1, 1), ('child pointer', 72645435, 3, 1), ('proof QC pointer', 72645530, 3, 1), ('child hash upper half', 72645581, 5, 1), ('proof hash upper half', 72645701, 5, 1), ('child digest repeat callee', 72645771, 1, 1), ('saturation condition', 72645805, 2, 1), ('child round pointer', 72645809, 3, 1), ('buffer round offset', 70647838, 3, 1), ('buffer round guard', 70647845, 1, 1), ('received round store', 70647861, 3, 1), ('pending append stride', 70647925, -1, 1), ('pending length store', 70647954, -1, 1), ('proof flush guard', 70647961, 1, 1), ('unconfirmed100 limit', 70647967, -1, 1), ('unconfirmed inclusive boundary', 70647971, 1, 1), ('confirmed start pointer', 70648129, 3, 1), ('batch call target', 70648171, 1, 1), ('batch success guard', 70648188, 1, 1), ('confirmed round store', 70648216, 3, 1), ('pending empty length', 70648249, 4, 1), ('channel closed bit', 70648400, -1, 1), ('queue push callee', 70648465, 1, 1), ('closed error tag', 70649141, -1, 1), ('empty stake root offset', 70031671, -1, 1), ('empty stake branch', 70031678, 1, 1), ('missing stake result tag', 72660895, 2, 1), ('signed block digest pointer', 72660959, -1, 1), ('queue slot shift', 78937233, -1, 1), ('queue second copy offset', 78937243, -1, 1), ('queue publish pointer', 78937263, 4, 1), ('hash tail offset', 83205556, 3, 1), ('hash high padding bit', 83205898, -1, 1)]
    all_rows={r['va']:r for pair in decoded.values() for r in pair[0]}
    for label,va,index,mask in mutations:
        row=all_rows[va];raw=bytearray(row['raw']);raw[index]^=mask
        offset=elf.offset(va,len(raw));data=bytearray(elf.data);data[offset:offset+len(raw)]=raw
        changed_elf=copy.copy(elf);changed_elf.data=bytes(data)
        owner=next(int(r['start'],16) for r in scope['ranges'] if int(r['start'],16)<=va<int(r['end'],16))
        _,fresh=e.decode_snapshot(changed_elf,gnu=gnu,llvm=llvm,subset={owner})
        changed=dict(decoded);changed.update(fresh)
        rejected(label,lambda x=changed_elf,y=changed:e.validate(x,y,body_identity=False),
                 va=hex(va),file_offset=offset,before=row['raw'].hex(),after=raw.hex(),level='below target/body identity; fresh GNU+LLVM')
    pins=json.loads((HERE/'obligations.json').read_text())
    for pin in pins['data']:
        va=int(pin['va'],16);offset=elf.offset(va,1);data=bytearray(elf.data);data[offset]^=1
        changed_elf=copy.copy(elf);changed_elf.data=bytes(data)
        rejected('data '+pin['reason'],lambda x=changed_elf:e.validate(x,decoded,body_identity=False),
                 va=hex(va),file_offset=offset,level='below identity; data obligation')
    # Raw RELA controls exercise parsing and the explicit sym0/import bindings.
    for label,slot,field,changed in [
        ('RELATIVE nonzero symbol',0x5777790,8,(1<<32)|8),
        ('RELATIVE wrong kind',0x5777790,8,6),
        ('RELATIVE wrong callee',0x5777790,16,0x4f59481),
        ('memcpy wrong import symbol',0x576dfe0,8,(7<<32)|6),
    ]:
        off=elf.relas[slot]['offset']+field;data=bytearray(elf.data);struct.pack_into('<Q',data,off,changed)
        rejected(label,lambda d=bytes(data):e.validate(e.Elf(d,identity=False),decoded,body_identity=False),
                 file_offset=off,level='below identity; raw ELF relocation parse')
    f=next(x for x in elf.fdes if x['start']==e.EXPECTED_STARTS[0]);off=elf.offset(f['fde']+12,1)
    data=bytearray(elf.data);data[off]^=1
    rejected('raw FDE extent byte',lambda:e.validate(e.Elf(bytes(data),identity=False),decoded,body_identity=False),
             file_offset=off,level='below identity; raw DWARF parse')
    # Order checks are also exercised independently of byte pins/body hashes.
    for label,va,raw in [
        ('CFG skips received store',0x436002b,bytes.fromhex('eb3b90')),
        ('CFG skips confirmation before send',0x4360191,bytes.fromhex('e9230000009090')),
    ]:
        offset=elf.offset(va,len(raw));data=bytearray(elf.data);data[offset:offset+len(raw)]=raw
        changed_elf=copy.copy(elf);changed_elf.data=bytes(data)
        _,fresh=e.decode_snapshot(changed_elf,gnu=gnu,llvm=llvm,subset={0x4360000})
        changed=dict(decoded);changed.update(fresh)
        rejected(label,lambda y=changed:e.local_state_facts(y),va=hex(va),level='CFG only; no target/body hash or instruction pins')
    va=0x45479c9;offset=elf.offset(va,5);data=bytearray(elf.data);data[offset:offset+5]=bytes.fromhex('6666b8ffff')
    changed_elf=copy.copy(elf);changed_elf.data=bytes(data)
    _,fresh=e.decode_snapshot(changed_elf,gnu=gnu,llvm=llvm,subset={0x4547690})
    changed=dict(decoded);changed.update(fresh)
    rejected('data16 hides AX write',lambda:e.validate(changed_elf,changed,body_identity=False),va=hex(va),level='below identity; prefixed native write')
    return results


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--binary',type=Path)
    ap.add_argument('--out',type=Path,required=True);ap.add_argument('--gnu',default=e.GNU);ap.add_argument('--llvm',default=e.LLVM)
    ap.add_argument('--pre-freeze-check',action='store_true');a=ap.parse_args();e.need(not a.out.exists(),'output must be new')
    frozen=freeze(a.pre_freeze_check);binary=a.binary or e.ROOT/'artifacts/node/94/hl-node'
    elf=e.Elf(binary.read_bytes());trees=[]
    with tempfile.TemporaryDirectory(prefix='consensus-reproduce-') as temp:
        for i in range(2):
            outputs=e.collect(binary,gnu=a.gnu,llvm=a.llvm)
            outputs.update({'fixtures/'+k:v for k,v in corpus.generate().items()})
            e.write_new(Path(temp)/str(i),outputs)
            for name,data in outputs.items():e.need((HERE/name).read_bytes()==data,'retained export mismatch: '+name)
            trees.append(outputs)
        e.need(trees[0]==trees[1],'two deterministic trees')
        checks=controls(elf,retained_decoded(trees[0]),a.gnu,a.llvm)
    summary=dict(target=e.SHA,functions=16,bytes=10566,instructions=2320,instruction_obligations=1451,
                 data_obligations=1,cases=len(corpus.cases()),deterministic_trees=2,negative_controls=len(checks),
                 freeze_sha256=frozen,controls=checks,scope='Static parsing/native disassembly and independent value arithmetic only; no captured evaluation.')
    a.out.mkdir(parents=True);(a.out/'validation.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps({k:v for k,v in summary.items() if k!='controls'}))


if __name__=='__main__':main()
