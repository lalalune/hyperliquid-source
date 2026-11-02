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


def freeze():
    receipt=json.loads((HERE/'PRE-RUST-FREEZE.json').read_text())
    correction=json.loads((HERE/'POST-FREEZE-PROOF-CORRECTION.json').read_text())
    e.need(e.digest((HERE/'PRE-RUST-FREEZE.json').read_bytes())==correction['original_freeze_sha256'],'original freeze receipt')
    for name,wanted in receipt['files'].items():
        data=(HERE/name).read_bytes()
        if name=='PROOF.md':
            e.need(e.digest(data)==correction['new_proof_sha256'],'corrected proof hash')
            inserted=(correction['inserted_text']+correction['inserted_before']).encode()
            e.need(data.count(inserted)==1,'proof amendment location')
            data=data.replace(inserted,correction['inserted_before'].encode())
            e.need(e.digest(data)==correction['old_proof_sha256'],'reconstructed original proof')
        e.need(e.digest(data)==wanted,f'pre-Rust freeze: {name}')
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
    mutations=[
        ('timeout signer offset',0x477883a,-1,1),('timeout round offset',0x477885d,-1,1),
        ('timeout row stride',0x4778944,-1,1),('timeout row loop comparison',0x47789c2,1,1),
        ('signature second limb offset',0x4df2107,-1,1),('signature final byte offset',0x4df21d7,-1,1),
        ('signature writer advance',0x4df21f1,-1,1),('heartbeat signer offset',0x44c5866,3,1),
        ('heartbeat outer option tag',0x44c589f,-1,1),('heartbeat Some marker',0x44c58f9,-1,1),
        ('heartbeat peer option tag',0x44c5919,-1,1),('heartbeat random offset',0x44c5989,3,1),
        ('snapshot absent marker',0x4779d18,-1,1),('triple first word offset',0x466cf24,-1,1),
        ('map count offset',0x496d924,-1,1),('map child offset',0x496da31,3,1),
        ('map remaining decrement',0x496db7b,-1,1),('set next-key scale',0x44c6557,-1,1),
        ('set loop branch',0x44c6583,1,1),('ack random offset',0x4587712,-1,1),
        ('ack round source register',0x458773a,-1,1),('timeout caller selector',0x454b185,5,1),
        ('heartbeat caller selector',0x454aed6,5,1),('ack caller selector',0x454b319,4,1),
        ('u32 width threshold',0x4aa9aea,2,1),('u64 width threshold',0x4aa9f8b,3,1),
        ('hash full-block advance',0x4f59ad9,-1,1),('hash offset store',0x4f59db4,3,1),
        ('hash delimiter store offset',0x4f59ee7,-1,1),('hash final high bit',0x4f59f0a,-1,1),
        ('hash output count register',0x4f5a028,-1,1),('concat destination addressing',0x48455d1,-1,1),
    ]
    all_rows={r['va']:r for pair in decoded.values() for r in pair[0]}
    # Also change an actual status guard and direct serializer call target.
    status=next(r for va,r in sorted(all_rows.items()) if 0x4778820<=va<0x4778a62 and r['asm'].startswith('cmp') and r['asm'].split('#')[0].strip().endswith(',0x8'))
    mutations += [('timeout success guard',status['va'],-1,1),('ack scalar call target',0x4587723,-1,1)]
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
    a=ap.parse_args();e.need(not a.out.exists(),'output must be new')
    frozen=freeze();binary=a.binary or e.ROOT/'artifacts/node/94/hl-node'
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
    summary=dict(target=e.SHA,functions=38,bytes=19172,instructions=4655,instruction_obligations=619,
                 data_obligations=8,cases=534,deterministic_trees=2,negative_controls=len(checks),
                 freeze_sha256=frozen,controls=checks,scope='Static parsing/native disassembly and independent value arithmetic only; no captured evaluation.')
    a.out.mkdir(parents=True);(a.out/'validation.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps({k:v for k,v in summary.items() if k!='controls'}))


if __name__=='__main__':main()
