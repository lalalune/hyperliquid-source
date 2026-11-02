#!/usr/bin/env python3
"""Reproduce node115 evidence and compare only the independently built Rust API."""
import argparse
import importlib.metadata
import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import collect as evidence
from corpus import corpus,MUTANTS
from context import verify_context

P=Path(__file__).resolve().parent
R=evidence.ROOT
SOURCE=R/'src/node115-tcp-frame-plan/lib.rs'


def corruption_controls(data,inputs,expected):
    original=evidence.Image(data);results=[]
    semantic=[
        ('no-byte-swap',{0x2b78228:0x66,0x2b78229:0x90}),
        ('strict-length-limit',{0x2b79044:0x87}),
        ('zero-compression-tag',{0x2b791c9:0}),
        ('chunk-cap-minus-one',{**dict(zip(range(0x2b799f8,0x2b799fc),(3999999).to_bytes(4,'little'))),**dict(zip(range(0x2b799fd,0x2b79a01),(3999999).to_bytes(4,'little')))}),
        ('maximum-chunk-select',{0x2b79a03:0x47}),
    ]
    parsed=[(bytes.fromhex(s.split()[0]),int(s.split()[1]),int(s.split()[2])) for s in inputs.splitlines()]
    for name,overlay in semantic:
        p=evidence.parameters(evidence.Image(data,overlay));different=sum(evidence.relation(h,limit,done,p)!=want for (h,limit,done),want in zip(parsed,expected))
        evidence.need(different>0,'undetected target-operand counterfactual '+name)
        results.append({'name':name,'kind':'below-identity operand counterfactual','different_rows':different,'patch':{hex(k):v for k,v in overlay.items()}})
    for name,va in [('header-buffer-field',0x2b78227),('length-limit-operands',0x2b79041),('flag-store',0x2b791cc),('allocated-length-store',0x2b7921a),('remaining-subtraction',0x2b799ee),('header-read-size-destination',0x2b78115)]:
        try:evidence.parameters(evidence.Image(data,{va:original.read(va,1)[0]^1}))
        except ValueError:results.append({'name':name,'kind':'structural operand corruption rejected','va':hex(va)})
        else:raise ValueError('structural operand corruption escaped '+name)
    cies,fdes=evidence.eh_frame_records(data,original.ss)
    duplicate=next(f for f in fdes if f['start']==0x2b780d0)
    with patch.object(evidence,'eh_frame_records',return_value=(cies,fdes+[duplicate])):
        try:evidence.collect(data)
        except ValueError as error:
            evidence.need('FDE' in str(error),'duplicate FDE rejected for unrelated reason')
            results.append({'name':'duplicate-selected-FDE','kind':'corrupt parsed-provider record rejected'})
        else:raise ValueError('duplicate FDE escaped')
    try:evidence.collect(data[:-1])
    except ValueError:results.append({'name':'truncated-artifact','kind':'public full-identity gate rejected'})
    else:raise ValueError('truncated artifact escaped')
    return results


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True);ap.add_argument('--rustc',type=Path,required=True);a=ap.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    data=evidence.TARGET.read_bytes();record,exports=evidence.collect(data,native=True)
    evidence.need(record==json.loads((P/'evidence.json').read_text()),'retained evidence differs')
    context=verify_context(data,record)
    evidence.need(context==json.loads((P/'context.json').read_text()),'helper context differs')
    for name,text in exports.items():evidence.need(text==(P/name).read_text(),'retained native listing differs: '+name)
    inputs,expected_text=corpus(record['parameters'],evidence.relation);expected=expected_text.splitlines()
    frozen={'cases':len(expected),'input_sha256':evidence.digest(inputs.encode()),'expected_sha256':evidence.digest(expected_text.encode()),'generator_sha256':evidence.digest((P/'corpus.py').read_bytes()),'collector_sha256':evidence.digest((P/'collect.py').read_bytes())}
    evidence.need(frozen==json.loads((P/'corpus.json').read_text()),'pre-Rust corpus or collector identity changed')
    (a.output/'inputs.tsv').write_text(inputs);(a.output/'expected.tsv').write_text(expected_text)
    commands=[]
    def run(cmd,**kw):
        cmd=list(map(str,cmd));commands.append(cmd);r=subprocess.run(cmd,text=True,capture_output=True,**kw)
        (a.output/'commands.json').write_text(evidence.dump(commands))
        with (a.output/'compiler-and-process.log').open('a') as log:log.write(evidence.dump(cmd)+r.stderr)
        evidence.need(r.returncode==0,'own command failed: '+' '.join(cmd)+'\n'+r.stderr)
        return r.stdout
    version=run([a.rustc,'-vV']);evidence.need(version.startswith('rustc 1.95.0 '),'expected pinned rustc1.95.0')
    def build(name,source,opt):
        out=a.output/name;out.mkdir();lib=out/'libprojection.rlib';driver=out/'driver'
        flags=['--edition=2021','-D','warnings','-C','overflow-checks=on','-C','opt-level='+str(opt)]
        run([a.rustc,*flags,'--crate-name','projection','--crate-type','rlib',source,'-o',lib])
        run([a.rustc,*flags,P/'driver.rs','--extern','projection='+str(lib),'-o',driver])
        return lib,driver
    comparisons=[];hashes=[]
    for name,opt in [('debug',0),('optimized',3),('repeat',3)]:
        lib,driver=build(name,SOURCE,opt);actual=run([driver],input=inputs);(a.output/(name+'.tsv')).write_text(actual)
        evidence.need(actual==expected_text,name+' Rust comparison mismatch')
        comparisons.append({'name':name,'rows':len(expected),'mismatches':0,'output_sha256':evidence.digest(actual.encode())});hashes.append(evidence.digest(lib.read_bytes()))
    evidence.need(hashes[1]==hashes[2],'optimized library hashes differ')
    unit=a.output/'unit-tests';run([a.rustc,'--edition=2021','-D','warnings','--test',SOURCE,'-o',unit]);(a.output/'unit-tests.txt').write_text(run([unit]))
    source=SOURCE.read_text();production,separator,tests=source.partition('#[cfg(test)]');compiled=[]
    for name,(old,new) in MUTANTS.items():
        evidence.need(production.count(old)==1,'ambiguous production mutation '+name)
        mutant=a.output/(name+'.rs');mutant.write_text(production.replace(old,new)+separator+tests)
        _,driver=build(name,mutant,3);actual=run([driver],input=inputs);(a.output/(name+'.tsv')).write_text(actual);rows=actual.splitlines()
        evidence.need(len(rows)==len(expected),'mutant failed normal output protocol '+name)
        different=sum(x!=y for x,y in zip(rows,expected));evidence.need(different>0,'compiled mutation escaped '+name)
        compiled.append({'name':name,'different_rows':different,'normal_exit':True})
    target_controls=corruption_controls(data,inputs,expected)
    # Native FDE headers come from GNU, separately from the repository parser.
    text=run(['readelf','-wf',evidence.TARGET]);native_frames=[]
    for owner in record['owners']:
        fragment=f"pc={int(owner['start'],16):016x}..{int(owner['end_exclusive'],16):016x}"
        rows=[line for line in text.splitlines() if fragment in line];evidence.need(len(rows)==1,'native FDE header mismatch');native_frames.extend(rows)
    (a.output/'readelf-selected-frames.txt').write_text('\n'.join(native_frames)+'\n')
    versions={name:run([name,'--version']).splitlines()[0] for name in ['objdump','llvm-objdump','readelf']};versions['llvm-objdump']=run(['llvm-objdump','--version']).splitlines();versions['python']=sys.version;versions['capstone']=importlib.metadata.version('capstone')
    result={'target_sha256':evidence.SHA,'corpus':frozen,'source_sha256':evidence.digest(SOURCE.read_bytes()),'driver_sha256':evidence.digest((P/'driver.rs').read_bytes()),'verifier_sha256':evidence.digest(Path(__file__).read_bytes()),'rustc':version.splitlines(),'versions':versions,'context_verifier_sha256':evidence.digest((P/'context.py').read_bytes()),'comparisons':comparisons,'optimized_repeat_hashes':hashes[1:],'compiled_controls':compiled,'target_controls':target_controls,'native_frames':native_frames,'normalization_masks':[],'captured_code_executed':False,'limits':'Static-derived finite scalar comparison, not target execution or whole-reader/ABI/code equivalence.'}
    (a.output/'results.json').write_text(evidence.dump(result));print(evidence.dump(result))


if __name__=='__main__':main()
