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
                      ('shortened main FDE',lambda s:next(r for r in s['ranges'] if r['start']=='0x3703f20').update(end='0x3704677')),
                      ('changed byte denominator',lambda s:next(r for r in s['ranges'] if r['start']=='0x3703f20').update(size=1879))]:
        s=copy.deepcopy(scope);edit(s);reject(name,lambda s=s:e.validate(elf,original,scope=s))
    bad=copy.deepcopy(original);bad.pop(e.EXPECTED_STARTS[-1]);reject('missing decoded helper',lambda:e.validate(elf,bad))
    bad=copy.deepcopy(original);bad[0x3703f20][1][0]['raw']=b'\x90';reject('LLVM raw mismatch',lambda:e.validate(elf,bad))
    rows={r['va']:r for pair in original.values() for r in pair[0]}
    mutations=[('supplied collector call', 57688113, 1), ('sorted consume call', 57688228, 1), ('sum field', 57688273, -1), ('sum signed overflow', 57688313, 0), ('sum stride', 57688318, -1), ('sum saturation', 57688353, 2), ('odd tag dword', 57688447, -1), ('odd magnitude tie', 57688469, 0), ('odd asset', 57688471, -1), ('odd address last4', 57688475, -1), ('odd address first16', 57688482, -1), ('back vector absent', 57688545, -1), ('flatten call', 57688585, 1), ('winner gate', 57688594, 1), ('zero total gate', 57688628, 1), ('existing user call', 57688675, 1), ('count snapshot', 57688683, -1), ('ARU map offset', 57688697, 3), ('ARU call', 57688728, 1), ('position root', 57688742, -1), ('position key count', 57688764, 4), ('position key offset', 57688805, 4), ('position child offset', 57688860, 4), ('pair first byte tag', 57688915, -1), ('first magnitude unsigned', 57688940, 0), ('pair second dword tag', 57688945, -1), ('second magnitude tie', 57689009, 0), ('position entry call', 57689124, 1), ('size field', 57689132, -1), ('leverage field', 57689136, -1), ('isolated mode exactly1', 57689143, -1), ('isolated subtract', 57689156, 2), ('isolated destination', 57689165, -1), ('cross subtract', 57689177, 2), ('cross destination', 57689186, 2), ('old size argument', 57689189, 2), ('aux map offset', 57689201, 3), ('new size argument', 57689208, -1), ('leverage reread before aux', 57689212, -1), ('aux helper call', 57689222, 1), ('leverage equality branch', 57689232, 0), ('count zero branch', 57689269, 0), ('output length store', 57689357, -1), ('rates drop call', 57689380, 1), ('aux old zero test', 57635679, 2), ('aux new zero test', 57635685, 2), ('aux decrement store', 57635733, 2), ('aux unsigned key compare', 57635786, 2), ('aux child offset', 57635837, 4), ('entry before abs call', 57635934, 1), ('old abs signed choice', 57635945, 2), ('MIN rejection branch', 57635952, 1), ('aux subtract order', 57635964, 2), ('aux first store', 57635969, 2), ('aux add order', 57635994, 2), ('aux second store', 57635999, 2), ('aux default value0', 54248741, 1), ('aux insert target', 54248743, 1), ('aux occupied value offset', 54248776, -1), ('summary compare20', 54157040, 1), ('summary count', 54157542, 3), ('ARU compare20', 54113790, 1), ('summary full threshold', 49694448, -1), ('summary pivot boundary', 49694461, -1), ('summary pivot4', 49694486, 2), ('summary pivot6', 49694967, 2), ('summary count truncate', 49695304, 4), ('ARU full threshold', 49494753, -1), ('ARU pivot5', 49494883, -1), ('ARU pivot6', 49494962, 2), ('ARU parent repair', 49495781, 3), ('aux full threshold', 49385279, -1), ('aux pivot5', 49385447, -1), ('aux pivot6', 49385519, 2), ('aux value destination', 49385416, -1), ('aux parent repair', 49386389, 3), ('flatten row stride', 62585807, -1), ('flatten sentinel source', 62585815, -1), ('flatten tag2 sentinel', 62585992, -1), ('flatten marker copy', 62586447, -1), ('flatten next record marker', 62586787, -1), ('flatten growth stride', 62587221, 2), ('hash high7 bits', 58303411, -1), ('user bucket stride120', 58303494, -1), ('user collection stride120', 62692197, -1), ('user pointer offset', 62692209, -1), ('existing user pointer', 56191653, -1), ('position element stride64', 54252841, -1)]
    for label,va,index in mutations:
        row=rows[va];raw=bytearray(row['raw']);raw[index]^=1;off=elf.offset(va,len(raw))
        d=bytearray(elf.data);d[off:off+len(raw)]=raw;changed=copy.copy(elf);changed.data=bytes(d)
        owner=next(int(x['start'],16) for x in scope['ranges'] if int(x['start'],16)<=va<int(x['end'],16))
        _,fresh=e.decode_snapshot(changed,gnu=gnu,llvm=llvm,subset={owner});merged=dict(original);merged.update(fresh)
        reject(label,lambda a=changed,b=merged:e.validate(a,b,body_identity=False),
               va=hex(va),file_offset=off,before=row['raw'].hex(),after=raw.hex(),
               level='fresh complete GNU/LLVM decode below whole-target/body identity')
    for label,slot,field,value in [
        ('RELATIVE symbol index',0x5773a78,8,(1<<32)|8),('caller target',0x5773a78,16,0x3703f21),
        ('memcmp import symbol',0x576e488,8,(6<<32)|6),('memmove import symbol',0x576e0e0,8,(6<<32)|6),
        ('memcpy nonzero addend',0x576dfe0,16,1),('diagnostic target',0x5773190,16,0x358dcd1)]:
        off=elf.relas[slot]['offset']+field;d=bytearray(elf.data);struct.pack_into('<Q',d,off,value)
        reject(label,lambda d=bytes(d):e.validate(e.Elf(d,identity=False),original,body_identity=False),
               file_offset=off,level='raw RELA parse below identity')
    for va in (0x3703f20,0x2f646d0):
        f=next(f for f in elf.fdes if f['start']==va);off=elf.offset(f['fde']+12,1);d=bytearray(elf.data);d[off]^=1
        reject('raw FDE extent '+hex(va),lambda d=bytes(d):e.validate(e.Elf(d,identity=False),original,body_identity=False),file_offset=off)
    for va in (0x204ec0,0x203e70):
        off=elf.offset(va,1);d=bytearray(elf.data);d[off]^=1;changed=copy.copy(elf);changed.data=bytes(d)
        reject('hash constant '+hex(va),lambda x=changed:e.validate(x,original,body_identity=False),file_offset=off)
    # Below all instruction pins, actual fresh decoded graph must reject order bypasses.
    for label,va,dest,width,prefix in [
        ('skip flatten',0x37041f9,0x370420e,8,b''),
        ('skip ARU',0x370426f,0x370429d,5,b''),
        ('skip output stores',0x3704505,0x3704524,8,b''),
        ('hidden prefixed branch',0x37041f9,0x3704263,8,b'\x2e')]:
        raw=prefix+b'\xe9'+struct.pack('<i',dest-(va+len(prefix)+5));raw+=b'\x90'*(width-len(raw))
        off=elf.offset(va,width);d=bytearray(elf.data);d[off:off+width]=raw;changed=copy.copy(elf);changed.data=bytes(d)
        _,fresh=e.decode_snapshot(changed,gnu=gnu,llvm=llvm,subset={0x3703f20});merged=dict(original);merged.update(fresh)
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
    trees=[]
    with tempfile.TemporaryDirectory(prefix='residual-reproduce-') as temporary:
        for i in range(2):
            result=e.collect(binary,gnu=a.gnu,llvm=a.llvm)
            result.update({'fixtures/'+k:v for k,v in corpus.generate().items()})
            result['certificates.json']=(json.dumps(certificates.check(),separators=(',',':'))+'\n').encode()
            e.write_new(Path(temporary)/str(i),result)
            for name,raw in result.items():e.need((e.HERE/name).read_bytes()==raw,'retained export '+name)
            trees.append(result)
        e.need(trees[0]==trees[1],'two deterministic regeneration trees')
        checks=controls(elf,decoded(trees[0]),a.gnu,a.llvm)
    records=json.loads(trees[0]['records.json']);case_summary=json.loads(trees[0]['fixtures/summary.json'])
    summary=dict(target=e.SHA,full_export=records['full_export'],core_and_bounded_helpers=records['core_and_bounded_helpers'],
                 context_only=records['caller_context_only'],instruction_pins=records['instruction_pins'],data_spans=records['data_pins'],
                 negative_controls=len(checks),cases=case_summary,deterministic_trees=2,freeze_sha256=frozen,controls=checks,
                 scope='Static native parsing and authored mathematical certificates/finite cases; no captured execution/emulation, Rust or universal corpus proof.')
    a.out.mkdir(parents=True);(a.out/'validation.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps({k:v for k,v in summary.items() if k!='controls'}))


if __name__=='__main__':main()
