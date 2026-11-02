#!/usr/bin/env python3
"""Static-only admission, actual inert-byte corruptions, and deterministic replay.

No captured binary/instruction is executed or emulated. Native providers only
decode private non-executable byte snapshots. Binding controls do not establish
semantic equivalence; the manual proof supplies the conditional theorem.
"""
from __future__ import annotations
import argparse
import copy
import gzip
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import evidence as e
import corpus
import certificates
import oracle

HERE=Path(__file__).resolve().parent


def retained_streams():
    return {start:tuple(e.native_rows(gzip.decompress((HERE/'native'/f'{start:x}.{provider}.txt.gz').read_bytes()).decode())
                       for provider in ('gnu','llvm')) for start,end in e.RANGES}


def corruptions(original, streams, gnu, llvm):
    checks=[]; files={}; base=e.Elf(original)
    scope=json.loads((HERE/'scope.json').read_text()); obligations=json.loads((HERE/'obligations.json').read_text())

    def reject(name, layer, callback, change=None):
        try:callback()
        except (e.EvidenceError,ValueError,KeyError,struct.error,IndexError) as error:
            checks.append(dict(name=name,layer=layer,outcome='rejected',reason=str(error),change=change))
        else:raise e.EvidenceError(f'negative control accepted: {name}')

    reject('wrong-target-sha','identity',lambda:e.Elf(original[:-1]+bytes([original[-1]^1])))
    reject('short-target','identity',lambda:e.Elf(original[:-1]))
    for field,value in [('op',2),('op',-1),('op',True),('enabled',2),('enabled',-1),
                        ('enabled',0.0),('cursor',2),('charged',-1),('limit',1<<64)]:
        case={'data':b'\x02',field:value}
        for method in (oracle.encode_input,oracle.expected):
            reject(f'oracle-domain-{method.__name__}-{field}-{value!r}','oracle-domain',lambda case=case,method=method:method(case))
    altered=bytearray(original);altered[18:20]=b'\xb7\0'
    reject('wrong-elf-machine','below-identity',lambda:e.Elf(bytes(altered),identity=False))
    for name,alter in [
        ('scope-wrong-target',lambda x:x.update(sha256='0'*64)),
        ('scope-wrong-size',lambda x:x.update(size=e.SIZE-1)),
        ('scope-missing-range',lambda x:x['ranges'].pop()),
        ('scope-shortened-range',lambda x:x['ranges'][0].update(end=hex(e.RANGES[0][1]-1))),
        ('scope-wrong-file-offset',lambda x:x['ranges'][0].update(file_offset=x['ranges'][0]['file_offset']+1)),
        ('scope-wrong-fde',lambda x:x['ranges'][0].update(fde='0x0')),
        ('scope-wrong-call',lambda x:x['ranges'][0]['calls'][0].update(slot='0x0')),
    ]:
        modified=copy.deepcopy(scope);alter(modified)
        reject(name,'scope',lambda m=modified:e.validate(base,streams,scope=m))
    missing=dict(streams);missing.pop(e.RANGES[-1][0])
    reject('missing-native-body','native-partition',lambda:e.validate(base,missing))
    bad=copy.deepcopy(streams);first=e.RANGES[0][0];bad[first][1].pop()
    reject('short-llvm-body','native-partition',lambda:e.validate(base,bad))
    for name,alter in [
        ('missing-instruction-obligation',lambda x:x['instructions'].pop()),
        ('shifted-instruction-obligation',lambda x:x['instructions'][0].update(va='0x0')),
        ('missing-literal-obligation',lambda x:x['data'].pop()),
        ('shifted-literal-obligation',lambda x:x['data'][0].update(va='0x0')),
    ]:
        modified=copy.deepcopy(obligations);alter(modified)
        reject(name,'obligation-set',lambda m=modified:e.validate(base,streams,obligations=m))

    def bytes_mutant(va,new):
        raw=bytearray(original);at=base.offset(va,len(new));old=raw[at:at+len(new)]
        e.need(old!=new,'effective byte mutation');raw[at:at+len(new)]=new
        return bytes(raw),dict(va=hex(va),file_offset=at,before=bytes(old).hex(),after=new.hex())

    # Every altered instruction below is actually decoded by both providers.
    # The primary binding controls intentionally retain the original manual
    # obligations. They establish rejection of changed evidence, not execution
    # or a theorem about arbitrary modified programs.
    byte_cases=[
        ('u32-charge-four-to-five',0x466bc27,b'\x05'),
        ('u32-threshold-four-to-three',0x466bc40,b'\x03'),
        ('u64-charge-eight-to-seven',0x466bd27,b'\x07'),
        ('u64-fast-expected-two-to-three',0x466bdc9,b'\x03'),
        ('u64-cursor-store-field',0x466bda0,b'\x18'),
        ('usize-expected-category',0x466bf29,b'\x04'),
        ('group-reserve32-to31',0x466bf8e,b'\x1f'),
        ('group-refund8-to7',0x466bff4,b'\xf9'),
        ('signature-byte-charge',0x466bb28,b'\x02'),
        ('record-fixed-width',0x466dec4,b'\x01'),
        ('record-first-scalar-offset',0x466df80,b'\x10'),
        ('record-copy-length',0x466df72,b'\xe8'),
        ('outer-tag-bound',0x4674855,b'\x04'),
        ('outer-triple-order',0x46749d5,b'\x10'),
        ('outer-scalar-call-target',0x46748a5,b'\x68'),
        ('boxed-allocation-size',0x485bc24,b'\x31'),
        ('map-reservation96-to95',0x496eca6,b'\x5f'),
        ('map-overflow-branch',0x496ecb0,b'\x71'),
        ('map-refund96-to95',0x496ed47,b'\xa1'),
        ('map-row-decrement',0x496eed0,b'\xc7'),
        ('map-output-count-offset',0x496eedf,b'\x10'),
        ('key-compare-width',0x493df51,b'\x13'),
        ('node-count-offset',0x493df0d,b'\x03'),
        ('split-first-pivot',0x4217a1b,b'\x05'),
        ('split-right-gap-subtract',0x4217b47,b'\xfa'),
        ('split-internal-child-source',0x4218135,b'\x00'),
        ('split-child-parent-index',0x4218168,b'\xfe'),
        ('parent-insert-child-gap',0x4218676,b'\x00'),
        ('cleanup-parent-edge-offset',0x494e724,b'\xfe'),
        ('caller-limit-tag',0x471b948,b'\x00'),
        ('caller-consumed-offset',0x471ba6e,b'\x88'),
    ]

    def decode(name,raw,start,end):
        pair=[]
        with tempfile.TemporaryDirectory(prefix='greeting-corruption-') as tmp:
            target=Path(tmp)/'hl-node';target.write_bytes(raw);target.chmod(0o400)
            for provider,head in [('gnu',[gnu,'-d','-w','-Mintel']),('llvm',[llvm,'-d','--x86-asm-syntax=intel'])]:
                args=head+[f'--start-address={start}',f'--stop-address={end}','hl-node']
                result=subprocess.run(args,cwd=tmp,capture_output=True,env={**os.environ,'LC_ALL':'C'},timeout=60)
                e.need(result.returncode==0 and not result.stderr,'mutant decoder completion')
                dest=f'controls/{name}.{provider}.txt.gz';files[dest]=gzip.compress(result.stdout,mtime=0)
                pair.append(e.native_rows(result.stdout.decode()))
            e.need(target.read_bytes()==raw,'mutant inert snapshot changed')
        return tuple(pair)

    for name,va,new in byte_cases:
        raw,change=bytes_mutant(va,new)
        start,end=next((a,b) for a,b in e.RANGES if a<=va<b)
        mutant=dict(streams);mutant[start]=decode(name,raw,start,end)
        reject(name,'below-identity-native-binding',lambda r=raw,m=mutant:e.validate(e.Elf(r,identity=False),m,body_identity=False),change)

    # These two controls deliberately bypass fixed instruction obligations and
    # challenge the register-load-to-call checker itself, on actual native decodes.
    for name,va,new,start,end in [
        ('clobber-rbx-between-copy-calls',0x4217c79,bytes.fromhex('4831db'),0x42179a0,0x421889f),
        ('clobber-r12-before-copy-call',0x485bbda,bytes.fromhex('4531e4'),0x485baa0,0x485bc68),
    ]:
        raw,change=bytes_mutant(va,new);pair=decode(name,raw,start,end);elf=e.Elf(raw,identity=False)
        for rows in pair:e.partition(elf,rows,start,end)
        e.need([(x['va'],x['raw'])for x in pair[0]]==[(x['va'],x['raw'])for x in pair[1]],'mutant decoder byte agreement')
        reject(name,'register-corridor-checker',lambda elf=elf,pair=pair:e.register_bindings(elf,pair[0]),change)
    # An ignored multi-prefix NOP must not be reusable to hide a register write
    # or branch. This challenges the CFG prefix admission before obligation checks.
    for name,new in [('prefixed-mov-is-not-padding',bytes.fromhex('6666b8ffff')+b'\x90'*10),
                     ('prefixed-jump-is-not-padding',bytes.fromhex('2ee900000000')+b'\x90'*9)]:
        raw,change=bytes_mutant(0x496ed21,new);pair=decode(name,raw,0x496ec70,0x496f026)
        reject(name,'prefix-cfg-checker',lambda pair=pair:e.cfg(pair[0]),change)

    # Relocation/dispatch/LSDA controls mutate raw ELF data below the identity
    # gate. They do not run any loader, import or exception personality.
    for slot,name,offset,new in [
        (0x5775138,'relative-nonzero-symbol',12,struct.pack('<I',1)),
        (0x5775138,'wrong-reader-relocation',16,struct.pack('<q',0x466d980)),
        (0x576dfe0,'wrong-import-kind',8,struct.pack('<I',8)),
    ]:
        rel=base.relas[slot];raw=bytearray(original);at=rel['offset']+offset;old=raw[at:at+len(new)];raw[at:at+len(new)]=new
        reject(name,'raw-relocation',lambda raw=bytes(raw):e.validate(e.Elf(raw,identity=False),streams,body_identity=False),
               dict(file_offset=at,before=bytes(old).hex(),after=new.hex()))
    for table in e.TABLES:
        old=base.read(table,4);raw,change=bytes_mutant(table,struct.pack('<i',struct.unpack('<i',old)[0]+1))
        reject(f'dispatch-{table:x}-off-instruction','raw-data',lambda raw=raw:e.validate(e.Elf(raw,identity=False),streams,body_identity=False),change)
    for va in [0x6f877f,0x6f878b,0x20358c,0x20941c]:
        raw,change=bytes_mutant(va,bytes([base.read(va,1)[0]^1]))
        reject(f'literal-{va:x}','raw-data',lambda raw=raw:e.validate(e.Elf(raw,identity=False),streams,body_identity=False),change)
    f=next(f for f in base.fdes if f['start']==0x4674820)
    raw,change=bytes_mutant(f['lsda'],b'\x00')
    reject('lsda-unsupported-lpstart','raw-lsda',lambda:e.validate(e.Elf(raw,identity=False),streams,body_identity=False),change)
    raw,change=bytes_mutant(f['fde']+8,bytes([base.read(f['fde']+8,1)[0]^1]))
    reject('fde-start-corruption','raw-fde',lambda:e.validate(e.Elf(raw,identity=False),streams,body_identity=False),change)
    rel=next(iter(base.relas.values()));raw=bytearray(original)
    raw[rel['offset']:rel['offset']+8]=struct.pack('<Q',0x4674820)
    reject('relocation-overlaps-code','raw-relocation',lambda:e.validate(e.Elf(bytes(raw),identity=False),streams,body_identity=False))
    files['controls.json']=(json.dumps(dict(schema=1,count=len(checks),checks=checks,
        limitation='Rejection of corrupted static evidence and explicit structural guard tests; no modified native program was executed or emulated.'),indent=2)+'\n').encode()
    return checks,files


def run(target,out,gnu,llvm):
    e.need(not out.exists(),'fresh verification output');out.mkdir(parents=True)
    original=target.read_bytes();elf=e.Elf(original);streams=retained_streams()
    baseline=e.validate(elf,streams)
    e.need((json.dumps(baseline,separators=(',',':'))+'\n').encode()==(HERE/'records.json').read_bytes(),'retained record correspondence')
    checks,controls=corruptions(original,streams,gnu,llvm)
    for name,raw in controls.items():
        dest=out/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(raw)
    regenerated=[]
    for index in range(2):
        files=e.collect(target,gnu,llvm)
        files.update({'fixtures/'+name:raw for name,raw in corpus.generate().items()})
        files['certificates.json']=certificates.generate()
        for name,raw in files.items():e.need((HERE/name).read_bytes()==raw,f'regenerated retained file {name}')
        e.write_new(out/f'tree-{index+1}',files)
        regenerated.append({name:e.digest(raw)for name,raw in files.items()})
    e.need(regenerated[0]==regenerated[1],'two fresh trees byte identical')
    e.need(target.read_bytes()==original,'original target changed during verification')
    report=dict(schema=1,status='pass',target_sha256=e.SHA,target_size=e.SIZE,
                full_fdes=baseline['full_fdes'],core_fdes=baseline['core_fdes'],native_bytes=baseline['native_bytes'],
                native_rows=baseline['native_rows'],instruction_obligations=baseline['instruction_obligations'],
                data_obligations=baseline['data_obligations'],all_relocations=baseline['all_relocations'],
                negative_controls=len(checks),regenerated_trees=2,regenerated_files_per_tree=len(regenerated[0]),
                corpus=json.loads((HERE/'fixtures/corpus.json').read_text()),
                controls_sha256=e.digest(controls['controls.json']),regenerated=regenerated[0],
                scope='Static ELF/native parsing and independently authored mathematics only; no captured execution/emulation, no production source/client/build qualification.')
    raw=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode();(out/'validation.json').write_bytes(raw)
    print(json.dumps({k:report[k]for k in ['status','full_fdes','native_bytes','native_rows','negative_controls','regenerated_trees']}))
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--target',type=Path,default=e.ROOT/'artifacts/node/94/hl-node')
    p.add_argument('--gnu',default=e.GNU);p.add_argument('--llvm',default=e.LLVM);p.add_argument('--out',type=Path,required=True)
    a=p.parse_args();run(a.target,a.out,a.gnu,a.llvm)
