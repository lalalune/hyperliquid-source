#!/usr/bin/env python3
"""Static full-FDE reproduction, independent fixtures and corrupted-byte controls.

Native providers only decode bytes. No target instruction is executed/emulated.
"""
import argparse
import copy
import gzip
import json
from pathlib import Path
import struct
import tempfile
import corpus
import evidence as e


def decoded(outputs):
    return {s:tuple(e.native_rows(gzip.decompress(outputs[f'native/{s:x}.{p}.txt.gz']).decode())
                    for p in ('gnu','llvm')) for s in e.EXPECTED_STARTS}


def controls(elf,original,gnu,llvm):
    checks=[]
    def reject(name,action,**metadata):
        try:action()
        except e.EvidenceError as err:checks.append(dict(name=name,rejection=str(err),**metadata))
        else:raise e.EvidenceError('negative control survived: '+name)
    d=bytearray(elf.data);d[-1]^=1
    reject('changed byte under target SHA',lambda:e.Elf(bytes(d)))
    reject('truncated target',lambda:e.Elf(elf.data[:-1]))
    scope=json.loads((e.HERE/'scope.json').read_text())
    for label,edit in [
        ('wrong target',lambda s:s.update(sha256='0'*64)),
        ('missing helper',lambda s:s['ranges'].pop()),
        ('short range',lambda s:s['ranges'][4].update(end=hex(int(s['ranges'][4]['end'],16)-1))),
        ('wrong denominator',lambda s:s['ranges'][4].update(size=1357)),
    ]:
        s=copy.deepcopy(scope);edit(s)
        reject('scope '+label,lambda s=s:e.validate(elf,original,scope=s))
    bad=copy.deepcopy(original);bad.pop(e.EXPECTED_STARTS[-1])
    reject('missing decoded helper',lambda:e.validate(elf,bad))
    bad=copy.deepcopy(original);bad[0x4548050][1][0]['raw']=b'\x90'
    reject('LLVM raw partition disagreement',lambda:e.validate(elf,bad))
    rows={r['va']:r for pair in original.values() for r in pair[0]}
    mutations=[
        ('provided rows offset',0x4548069,-1),('provided guard',0x4548074,0),
        ('provided time upper word',0x4548076,-1),('provided block output',0x4548083,-1),
        ('provided rows output',0x4548087,-1),('success tag increment',0x4548095,-1),
        ('hash count offset',0x45480b1,-1),('count limit',0x45480b6,2),
        ('inclusive count branch',0x45480c3,0),('empty branch',0x45480e0,1),
        ('row allocation scale',0x45480f6,-1),('initial allocation target',0x45480fd,2),
        ('count reload',0x454810f,-1),('initial length zero',0x454811e,-1),
        ('hash pointer offset',0x4548133,-1),('map root offset',0x4548138,-1),
        ('hash span stride',0x454814d,-1),('map height offset',0x454815c,-1),
        ('row pointer slot',0x454817c,-1),('row hash second half',0x454818b,-1),
        ('length update',0x454819a,-1),('request advance',0x45481bf,-1),
        ('node count field',0x45481f4,4),('node key stride',0x45481ff,-1),
        ('memcmp width',0x454821b,1),('memcmp import slot',0x4548225,2),
        ('negative sign',0x4548230,1),('positive sign',0x4548233,1),
        ('comparison normalization',0x4548236,1),('continue greater',0x454823f,-1),
        ('equal branch',0x4548248,0),('height decrement',0x4548253,-1),
        ('leaf borrow branch',0x4548257,1),('child field',0x454825d,4),
        ('temporary tag',0x454828b,2),('temporary drop target',0x454829f,1),
        ('value field',0x45482a4,4),('value clone direction',0x45482ac,-1),
        ('growth cap comparison',0x45482df,-1),('growth guard',0x45482e9,1),
        ('empty row length',0x4548319,-1),('miss tag',0x454835d,2),
        ('miss upper hash output',0x454837b,-1),('miss middle hash output',0x4548384,-1),
        ('miss first hash output',0x454838b,-1),('prefix initial Arc offset',0x4548394,-1),
        ('prefix iteration stride',0x45483b0,-1),('prefix decrement termination',0x45483b8,0),
        ('prefix release direction',0x45483be,-1),('block release direction',0x45483f1,-1),
        ('new row Arc length',0x4548473,-1),('new time upper word',0x4548490,-1),
        ('new output block',0x45484a0,-1),('new output rows',0x45484a4,-1),
        ('error-drop discriminant adjustment',0x453ea2d,-1),('error-drop bound',0x453ea30,-1),
    ]
    for label,va,index in mutations:
        row=rows[va];raw=bytearray(row['raw']);raw[index]^=1
        offset=elf.offset(va,len(raw));data=bytearray(elf.data);data[offset:offset+len(raw)]=raw
        changed=copy.copy(elf);changed.data=bytes(data)
        owner=next(int(r['start'],16) for r in scope['ranges'] if int(r['start'],16)<=va<int(r['end'],16))
        _,fresh=e.decode_snapshot(changed,gnu=gnu,llvm=llvm,subset={owner})
        all_decoded=dict(original);all_decoded.update(fresh)
        reject(label,lambda x=changed,y=all_decoded:e.validate(x,y,body_identity=False),
               va=hex(va),file_offset=offset,before=row['raw'].hex(),after=raw.hex(),
               level='fresh full-FDE GNU/LLVM below whole-target/body identity')
    for label,slot,field,value in [
        ('RELATIVE nonzero symbol',0x5773008,8,(1<<32)|8),
        ('RELATIVE wrong type',0x5773008,8,6),
        ('loaded transaction drop wrong target',0x5773008,16,0x4760f81),
        ('memcmp wrong symbol',0x576e488,8,(7<<32)|6),
        ('memcmp nonzero addend',0x576e488,16,1),
    ]:
        off=elf.relas[slot]['offset']+field;data=bytearray(elf.data);struct.pack_into('<Q',data,off,value)
        reject(label,lambda d=bytes(data):e.validate(e.Elf(d,identity=False),original,body_identity=False),
               file_offset=off,level='raw ELF relocation parse below identity')
    f=next(f for f in elf.fdes if f['start']==0x4548050);off=elf.offset(f['fde']+12,1)
    data=bytearray(elf.data);data[off]^=1
    reject('raw FDE extent',lambda:e.validate(e.Elf(bytes(data),identity=False),original,body_identity=False),
           file_offset=off,level='raw DWARF parse below identity')
    off=elf.offset(0x6f5ac0+4*27,4);data=bytearray(elf.data);struct.pack_into('<i',data,off,0x453ea46-0x6f5ac0)
    changed=copy.copy(elf);changed.data=bytes(data)
    reject('selected error drop becomes payload release',lambda:e.local_facts(changed,original),
           file_offset=off,level='selected table/path fact without body identity or instruction pins')
    for label,va,dest,width,prefix in [
        ('provided path consults hash pointer',0x4548076,0x4548133,6,b''),
        ('missing path skips publication',0x4548347,0x45483ec,5,b''),
        ('prefixed hidden branch',0x45483a4,0x45483ec,12,b'\x2e'),
    ]:
        raw=prefix+b'\xe9'+struct.pack('<i',dest-(va+len(prefix)+5));raw+=b'\x90'*(width-len(raw))
        off=elf.offset(va,width);data=bytearray(elf.data);data[off:off+width]=raw
        changed=copy.copy(elf);changed.data=bytes(data)
        _,fresh=e.decode_snapshot(changed,gnu=gnu,llvm=llvm,subset={0x4548050})
        all_decoded=dict(original);all_decoded.update(fresh)
        reject(label,lambda d=all_decoded:e.local_facts(changed,d),va=hex(va),before=elf.read(va,width).hex(),
               after=raw.hex(),level='CFG facts without target/body hash or instruction pins')
    return checks


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--binary',type=Path);ap.add_argument('--out',type=Path,required=True)
    ap.add_argument('--gnu',default=e.GNU);ap.add_argument('--llvm',default=e.LLVM)
    ap.add_argument('--pre-freeze-check',action='store_true');a=ap.parse_args()
    e.need(not a.out.exists(),'output must be new');freeze=e.HERE/'PRE-RUST-FREEZE.json';frozen=None
    if a.pre_freeze_check:e.need(not freeze.exists(),'pre-freeze mode after freeze')
    else:
        receipt=json.loads(freeze.read_text());frozen=e.digest(freeze.read_bytes())
        for name,sha in receipt['files'].items():e.need(e.digest((e.HERE/name).read_bytes())==sha,'freeze '+name)
    binary=a.binary or e.ROOT/'artifacts/node/94/hl-node';elf=e.Elf(binary.read_bytes());trees=[]
    with tempfile.TemporaryDirectory(prefix='txjoin-reproduce-') as temporary:
        for i in range(2):
            result=e.collect(binary,gnu=a.gnu,llvm=a.llvm)
            result.update({'fixtures/'+k:v for k,v in corpus.generate().items()})
            e.write_new(Path(temporary)/str(i),result)
            for name,raw in result.items():e.need((e.HERE/name).read_bytes()==raw,'retained export '+name)
            trees.append(result)
        e.need(trees[0]==trees[1],'two deterministic regeneration trees')
        checks=controls(elf,decoded(trees[0]),a.gnu,a.llvm)
    summary=dict(target=e.SHA,full_export_fdes=12,core_helper_fdes=9,core_helper_bytes=2580,
                 core_helper_rows=634,caller_context_bytes=51145,caller_context_rows=8727,
                 instruction_pins=622,data_tables=1,negative_controls=len(checks),
                 cases=len(corpus.cases()),deterministic_trees=2,freeze_sha256=frozen,controls=checks,
                 scope='Static parsing/disassembly and independent finite relation arithmetic; no captured execution/evaluation, no Rust build.')
    a.out.mkdir(parents=True);(a.out/'validation.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps({k:v for k,v in summary.items() if k!='controls'}))


if __name__=='__main__':main()
