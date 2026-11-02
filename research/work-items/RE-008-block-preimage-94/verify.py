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
    mutations=[('block proposer offset', 74935642, 3, 1), ('block round offset', 74935674, 3, 1), ('hash count offset', 74935713, -1, 1), ('hash stride shift', 74935761, -1, 1), ('hash row advance', 74935804, -1, 1), ('hash count decrement', 74935808, -1, 1), ('block time pointer', 74935814, 3, 1), ('QC version offset', 74935842, -1, 1), ('QC start offset', 74935881, -1, 1), ('QC round offset', 74935912, -1, 1), ('QC hash offset', 74935952, -1, 1), ('QC vector offset', 74935981, -1, 1), ('TC offset', 74936010, -1, 1), ('block success store', 74936034, 3, 1), ('block sizer initial20', 74935004, -1, 1), ('block sizer count', 74935045, -1, 1), ('block sizer hashstride', 74935093, -1, 1), ('block sizer time pointer', 74935142, 3, 1), ('time packed year shift', 73157205, -1, 1), ('time positive-year guard', 73157215, 0, 1), ('time reciprocal400', 73157224, 3, 1), ('time cycle400', 73157237, 2, 1), ('time cycle compensation', 73157245, 2, 1), ('time seconds shift', 73157254, -1, 1), ('time ordinal mask', 73157261, 2, 1), ('time days1461', 73157269, 2, 1), ('time reciprocal100', 73157281, 3, 1), ('time epoch', 73157314, 2, 1), ('time seconds86400', 73157323, 3, 1), ('time zigzag condition', 73157361, 2, 1), ('time nanosecond pointer', 73157384, -1, 1), ('time u32 call target', 73157397, 1, 1), ('TC niche overflow branch', 73845297, 0, 1), ('TC absent byte', 73845313, -1, 1), ('TC present byte', 73845340, -1, 1), ('TC round offset', 74930206, -1, 1), ('TC count offset', 74930236, -1, 1), ('TC row span184', 74930286, 3, 1), ('TC signature pointerb0', 74930298, 3, 1), ('TC signature first load70', 74930320, -1, 1), ('TC signature call target', 74930378, 1, 1), ('TC body pointer', 74930401, 3, 1), ('TC next row184', 74930430, 3, 1), ('TC row loop', 74930444, 0, 1), ('TC sizer signature pointer', 72919666, 3, 1), ('QC vote count', 75872602, -1, 1), ('QC vote stride96', 75872658, -1, 1), ('QC signature final pointer', 75872713, -1, 1), ('signature second limb offset', 81731847, -1, 1), ('signature final byte offset', 81732055, -1, 1), ('block caller selector', 72658278, 5, 1), ('block verifier selector', 72660950, 5, 1), ('block tag caller', 72906307, 3, 1), ('block sizer call target', 72905764, 1, 1), ('block writer call target', 72906357, 1, 1), ('block status guard', 74935659, -1, 1), ('u32 width threshold', 78289642, 2, 1), ('u64 width threshold', 78290827, 3, 1), ('hash fullblock advance', 83204825, -1, 1), ('hash tail offset store', 83205556, 3, 1), ('hash delimiter offset', 83205863, -1, 1), ('hash high padding bit', 83205898, -1, 1), ('hash output count', 83206184, -1, 1), ('concat destination', 75781585, -1, 1)]
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
    summary=dict(target=e.SHA,functions=32,bytes=14506,instructions=3560,instruction_obligations=1246,
                 data_obligations=6,cases=1141,deterministic_trees=2,negative_controls=len(checks),
                 freeze_sha256=frozen,controls=checks,scope='Static parsing/native disassembly and independent value arithmetic only; no captured evaluation.')
    a.out.mkdir(parents=True);(a.out/'validation.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps({k:v for k,v in summary.items() if k!='controls'}))


if __name__=='__main__':main()
