#!/usr/bin/env python3
"""Reproduce static decoders, certificates, independent corpus and real byte controls."""
import argparse
import copy
import gzip
import json
from pathlib import Path
import struct
import tempfile
import certificates
import corpus
import evidence as e


def decoded(outputs):
    return {s:tuple(e.native_rows(gzip.decompress(outputs[f'native/{s:x}.{p}.txt.gz']).decode())
                    for p in ('gnu','llvm')) for s in e.EXPECTED_STARTS}


def controls(elf,original,gnu,llvm):
    checks=[]
    def reject(name,fn,**detail):
        try:fn()
        except (e.EvidenceError,ValueError) as error:checks.append(dict(name=name,rejection=str(error),**detail))
        else:raise e.EvidenceError('negative control survived: '+name)
    d=bytearray(elf.data);d[-1]^=1
    reject('wrong target SHA',lambda:e.Elf(bytes(d)))
    reject('wrong target size',lambda:e.Elf(elf.data[:-1]))
    scope=json.loads((e.HERE/'scope.json').read_text())
    for name,edit in [('wrong scope target',lambda s:s.update(sha256='0'*64)),
                      ('missing full helper',lambda s:s['ranges'].pop()),
                      ('shortened main FDE',lambda s:s['ranges'][9].update(end='0x44b8409')),
                      ('changed byte denominator',lambda s:s['ranges'][9].update(size=953))]:
        s=copy.deepcopy(scope);edit(s);reject(name,lambda s=s:e.validate(elf,original,scope=s))
    bad=copy.deepcopy(original);bad.pop(e.EXPECTED_STARTS[-1]);reject('missing decoded helper',lambda:e.validate(elf,bad))
    bad=copy.deepcopy(original);bad[0x44b8050][1][0]['raw']=b'\x90';reject('LLVM raw mismatch',lambda:e.validate(elf,bad))
    rows={r['va']:r for pair in original.values() for r in pair[0]}
    mutations=[
        ('round source',0x44b8078,3),('key tag',0x44b8095,-1),('hash upper half',0x44b8087,-1),
        ('map root',0x44b80d9,3),('map height',0x44b80e5,3),('lookup call',0x44b80fc,1),
        ('occupied result branch',0x44b8109,1),('row helper target',0x44b81f7,1),
        ('reason byte projection',0x44b81ff,-1),('reason helper target',0x44b8206,1),
        ('default delay option bit',0x44b820b,-1),('default/custom branch',0x44b820f,0),
        ('stamp upper word',0x44b821f,-1),('stamp low word',0x44b822b,-1),
        ('deadline helper slot',0x44b824b,2),('signed date comparison',0x44b8258,1),
        ('unsigned seconds comparison',0x44b8265,1),('inclusive nanos boundary',0x44b8272,0),
        ('sent flag field',0x44b827a,-2),('held result tag',0x44b8287,-1),
        ('log before sent',0x44b82f5,1),('sent stored one',0x44b830b,-1),
        ('statistic five',0x44b832a,1),('active result upper half',0x44b8353,-1),
        ('active result tag',0x44b835e,-1),('occupied row tag',0x495874d,-1),
        ('registration stat four',0x495881b,1),('registration timestamp source',0x4958834,-1),
        ('new row sent zero',0x4958847,-1),('initial reason root',0x495884c,-1),
        ('map insertion helper',0x49588d7,1),('row size',0x4958971,-1),
        ('map count increment',0x4958998,-1),('row pointer offset',0x49589a4,2),
        ('unsigned round compare',0x42b9280,1),('hash compare width',0x42b928a,1),
        ('map child array',0x42b92ee,4),('reason compare greater',0x492d4f7,2),
        ('reason duplicate branch',0x492d50e,0),('reason leaf count',0x492d4c7,-1),
        ('reason insert helper',0x492d603,1),('reason count increment',0x492d5ac,-1),
        ('map full-node capacity',0x41e1ec6,-1),('map pivot boundary',0x41e1ed5,-1),
        ('map pivot four',0x41e1eed,2),('map right gap adjustment',0x41e2097,-1),
        ('map key move width',0x41e1f99,-1),('map value offset',0x41e2004,4),
        ('map child repair index',0x41e2779,3),('map new root height',0x41e2be8,-1),
        ('reason full-node capacity',0x4235438,-1),('reason pivot boundary',0x423548e,-1),
        ('reason right gap adjustment',0x42354d5,-1),('reason child repair index',0x4235722,-1),
        ('reason root height',0x4235890,-1),('multiply nanoseconds literal',0x1459cb6,4),
        ('nonfinite product gate',0x1459ce1,0),('signed reciprocal multiplier',0x1459d2c,2),
        ('ns to seconds remainder',0x1459d4a,3),('time addition slot',0x1459d70,2),
        ('date addition slot',0x1459dc0,2),('date failure zero check',0x1459dc8,0),
        ('time normalize billion',0x1520765,-1),('time seconds reciprocal',0x152078d,2),
        ('date ordinal mask',0x151f878,-1),('date year divisor',0x151f8ac,3),
        ('date cycle divisor',0x151f908,3),('date year bound',0x151f9ff,-1),
    ]
    for label,va,index in mutations:
        row=rows[va];raw=bytearray(row['raw']);raw[index]^=1;off=elf.offset(va,len(raw))
        d=bytearray(elf.data);d[off:off+len(raw)]=raw;changed=copy.copy(elf);changed.data=bytes(d)
        owner=next(int(x['start'],16) for x in scope['ranges'] if int(x['start'],16)<=va<int(x['end'],16))
        _,fresh=e.decode_snapshot(changed,gnu=gnu,llvm=llvm,subset={owner});merged=dict(original);merged.update(fresh)
        reject(label,lambda a=changed,b=merged:e.validate(a,b,body_identity=False),
               va=hex(va),file_offset=off,before=row['raw'].hex(),after=raw.hex(),
               level='fresh complete GNU/LLVM decode below whole-target/body identity')
    for label,slot,field,value in [
        ('RELATIVE symbol index',0x576efb8,8,(1<<32)|8),('deadline target',0x576efb8,16,0x1459ca1),
        ('memcmp import symbol',0x576e488,8,(6<<32)|6),('memmove import symbol',0x576e0e0,8,(6<<32)|6),
        ('memcpy nonzero addend',0x576dfe0,16,1)]:
        off=elf.relas[slot]['offset']+field;d=bytearray(elf.data);struct.pack_into('<Q',d,off,value)
        reject(label,lambda d=bytes(d):e.validate(e.Elf(d,identity=False),original,body_identity=False),
               file_offset=off,level='raw RELA parse below identity')
    f=next(f for f in elf.fdes if f['start']==0x44b8050);off=elf.offset(f['fde']+12,1);d=bytearray(elf.data);d[off]^=1
    reject('raw FDE extent',lambda:e.validate(e.Elf(bytes(d),identity=False),original,body_identity=False),file_offset=off)
    for va in (0x20a220,0x20a308,0x20a730,0x250354+100,0x2504e5+100):
        off=elf.offset(va,1);d=bytearray(elf.data);d[off]^=1;changed=copy.copy(elf);changed.data=bytes(d)
        reject('constant/table '+hex(va),lambda x=changed:e.validate(x,original,body_identity=False),file_offset=off)
    for label,va,dest,width,prefix in [
        ('skip reason and deadline',0x44b8073,0x44b8282,5,b''),
        ('skip reason before deadline',0x44b81db,0x44b821f,5,b''),
        ('skip sent update',0x44b8305,0x44b8311,6,b''),
        ('hidden prefixed branch',0x44b8073,0x44b8282,10,b'\x2e')]:
        raw=prefix+b'\xe9'+struct.pack('<i',dest-(va+len(prefix)+5));raw+=b'\x90'*(width-len(raw))
        off=elf.offset(va,width);d=bytearray(elf.data);d[off:off+width]=raw;changed=copy.copy(elf);changed.data=bytes(d)
        _,fresh=e.decode_snapshot(changed,gnu=gnu,llvm=llvm,subset={0x44b8050});merged=dict(original);merged.update(fresh)
        reject(label,lambda a=changed,b=merged:e.local_facts(a,b),va=hex(va),before=elf.read(va,width).hex(),after=raw.hex(),
               level='CFG facts without target/body identity or instruction pins')
    return checks


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--binary',type=Path);ap.add_argument('--out',type=Path,required=True)
    ap.add_argument('--gnu',default=e.GNU);ap.add_argument('--llvm',default=e.LLVM);ap.add_argument('--pre-freeze-check',action='store_true');a=ap.parse_args()
    e.need(not a.out.exists(),'output must be new');freeze=e.HERE/'PRE-RUST-FREEZE.json';frozen=None
    if a.pre_freeze_check:e.need(not freeze.exists(),'pre-freeze mode after freeze')
    else:
        receipt=json.loads(freeze.read_text());frozen=e.digest(freeze.read_bytes())
        for name,sha in receipt['files'].items():e.need(e.digest((e.HERE/name).read_bytes())==sha,'freeze '+name)
    binary=a.binary or e.ROOT/'artifacts/node/94/hl-node';elf=e.Elf(binary.read_bytes())
    e.need(list(elf.read(0x250354,401))==[corpus.PREFIX[y]-365*y for y in range(401)],'native leap-prefix table identity')
    e.need(list(elf.read(0x2504e5,400))==[corpus.flag(y) for y in range(400)],'native canonical flag table identity')
    trees=[]
    with tempfile.TemporaryDirectory(prefix='throttle-reproduce-') as temporary:
        for i in range(2):
            result=e.collect(binary,gnu=a.gnu,llvm=a.llvm)
            result.update({'fixtures/'+k:v for k,v in corpus.generate().items()})
            result['certificates.json']=(json.dumps(certificates.check(),separators=(',',':'))+'\n').encode()
            e.write_new(Path(temporary)/str(i),result)
            for name,raw in result.items():e.need((e.HERE/name).read_bytes()==raw,'retained export '+name)
            trees.append(result)
        e.need(trees[0]==trees[1],'two deterministic regeneration trees')
        checks=controls(elf,decoded(trees[0]),a.gnu,a.llvm)
    summary=dict(target=e.SHA,full_export_fdes=12,full_export_bytes=28005,full_export_rows=5595,
                 core_helper_fdes=9,core_helper_bytes=10639,core_helper_rows=2306,
                 caller_context_bytes=17366,caller_context_rows=3289,instruction_pins=2362,data_spans=10,
                 negative_controls=len(checks),cases=len(corpus.cases()),steps=sum(len(x['steps']) for x in corpus.cases()),
                 deterministic_trees=2,freeze_sha256=frozen,controls=checks,
                 scope='Static native parsing and authored mathematical certificates/finite histories; no captured execution/emulation, Rust or universal corpus proof.')
    a.out.mkdir(parents=True);(a.out/'validation.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps({k:v for k,v in summary.items() if k!='controls'}))


if __name__=='__main__':main()
