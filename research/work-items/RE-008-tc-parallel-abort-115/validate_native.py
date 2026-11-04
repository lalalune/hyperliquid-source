#!/usr/bin/env python3
"""Compile/run only this packet's new Rust, never the captured executable."""
import argparse
import base64
import gzip
import hashlib
import json
import lzma
import os
from pathlib import Path
import platform
import subprocess
import time

HERE=Path(__file__).resolve().parent


def sha(b): return hashlib.sha256(b).hexdigest()


def compare(actual, expected):
    a=actual.splitlines(); e=expected.splitlines()
    if len(a)!=len(e): raise ValueError('line count')
    mismatches=[i for i,(x,y) in enumerate(zip(a,e)) if x!=y]
    return {'cases':len(e),'mismatches':len(mismatches),'first_indices':mismatches[:10]}


MUTANTS=[
 ('success-tag','pub const SUCCESS: u8 = 0x2e;','pub const SUCCESS: u8 = 0x2d;'),
 ('stop-tag','pub const STOP: u8 = 0x2f;','pub const STOP: u8 = 0x30;'),
 ('cleanup-second-offset','descriptor(32);','descriptor(24);'),
 ('cleanup-order','descriptor(8);\n            descriptor(32);','descriptor(32);\n            descriptor(8);'),
 ('cleanup-zero-length','if length != 0 {','if true {'),
 ('cleanup-tag','0x13 | 0x20 => descriptor(8),','0x13 | 0x21 => descriptor(8),'),
 ('right-error-wins','seed = left;\n        selection = 0;','seed = right;\n        selection = 0;'),
 ('success-overwrites-payload','seed[0] = SUCCESS;\n        selection = 2;','seed = left;\n        seed[0] = SUCCESS;\n        selection = 2;'),
 ('fold-precheck','for (next, &observed) in outcomes.iter().zip(after) {','for (next, &observed) in outcomes.iter().zip(after) {\n        if observed != 0 { result.reason = 3; break; }'),
 ('fold-stop-cancel-write','result.reason = 1;\n            break;','result.reason = 1;\n            result.writes += 1;\n            break;'),
 ('fold-replaces-existing-error','if folder[0] == SUCCESS {','if true {'),
 ('fold-missing-flag-write','result.writes += 1;','result.writes += 0;'),
 ('fold-cancel-one-only','if observed != 0 {','if observed == 1 {'),
 ('fold-tail-clobber','result.folder = folder;','folder[72..].fill(0);\n    result.folder = folder;'),
 ('fold-cursor-step','result.cursor.wrapping_add(stride)','result.cursor.wrapping_add(stride + 1)'),
 ('minimum-inclusive','p.half < minimum','p.half <= minimum'),
 ('abort-one-only','if cancel != 0 {','if cancel == 1 {'),
 ('signed-half','p.half = logical >> 1;','p.half = ((logical as i64) >> 1) as u64;'),
 ('budget-quarter','p.budget = budget >> 1;','p.budget = budget >> 2;'),
 ('worker-minimum','p.budget.max(workers)','p.budget.min(workers)'),
 ('migrated-one-only','if migrated != 0 {','if migrated == 1 {'),
 ('underflow-wrap','count.checked_sub(p.half)','Some(count.wrapping_sub(p.half))'),
 ('right-address-count','p.half.wrapping_mul(stride)','count.wrapping_mul(stride)'),
 ('closure-swapped-round','initialized[16..24].copy_from_slice(&cert_round.to_le_bytes());','initialized[16..24].copy_from_slice(&value.to_le_bytes());'),
 ('closure-al-one','if returned_al != 0 {','if returned_al == 1 {'),
 ('closure-signature-offset','value_address.wrapping_add(8)','value_address.wrapping_add(0)'),
 ('closure-key-last-four','initialized[32..].copy_from_slice(&key);','initialized[32..48].copy_from_slice(&key[..16]);'),
 ('caller-round-equality','m >= round','m > round'),
 ('caller-minimum','old.max(row)','old.min(row)'),
 ('caller-empty-tag','None => seed[0] = 8,','None => seed[0] = 11,'),
 ('caller-quorum-one','if quorum_al == 0 {','if quorum_al != 1 {'),
 ('caller-missing-cleanup','drop_collection = true;','drop_collection = false;'),
 ('entry-representation-one','if representation != 0 {','if representation == 1 {'),
 ('entry-capacity-equal-fails','capacity < count','capacity <= count'),
 ('entry-no-tls-route','else if tls_after == 0 { 1 }','else if tls_after == 0 { 2 }'),
 ('entry-allocation-width','capacity.wrapping_mul(16)','capacity.wrapping_mul(8)'),
]


def run(out, toolchain):
    out.mkdir(parents=True,exist_ok=False)
    source=(HERE/'rust/lib.rs').read_bytes();driver=(HERE/'rust/driver.rs').read_bytes()
    inputs=gzip.decompress((HERE/'inputs.tsv.gz').read_bytes());expected=gzip.decompress((HERE/'expected.tsv.gz').read_bytes())
    commands=[]; streams={}; result={'schema':1,'source_sha256':sha(source),'driver_sha256':sha(driver),
        'inputs_sha256':sha(inputs),'expected_sha256':sha(expected),'platform':platform.platform(),
        'normal':[],'mutants':[],'commands':commands,'status':'incomplete'}
    def command(label,args,cwd=None,data=None):
        before=time.monotonic();p=subprocess.run(args,cwd=cwd,input=data,capture_output=True)
        for suffix,raw in [('stdout',p.stdout),('stderr',p.stderr)]:
            name=label+'.'+suffix; (out/name).write_bytes(raw)
            streams[name]={'sha256':sha(raw),'bytes':len(raw),'base64':base64.b64encode(raw).decode()}
        def norm(s): return str(s).replace(str(out),'$OUT').replace(str(toolchain),'$TOOLCHAIN')
        commands.append({'label':label,'argv':[norm(a) for a in args],'cwd':norm(cwd) if cwd else None,
                         'stdin_sha256':sha(data) if data is not None else None,'exit':p.returncode,
                         'seconds':time.monotonic()-before,'stdout_sha256':sha(p.stdout),'stderr_sha256':sha(p.stderr)})
        (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
        return p
    rustc=toolchain/'rustc'
    def build(label,opt,code):
        d=out/label;d.mkdir();(d/'source.rs').write_bytes(code);(d/'driver.rs').write_bytes(driver)
        opts=['--edition=2021','-C',f'opt-level={opt}','-C','debuginfo=0','-C','metadata=tc115',
              '--remap-path-prefix',str(d)+'=/tc-build']
        p=command(label+'-lib',[str(rustc),'source.rs','--crate-name','node115_tc_parallel_abort','--crate-type','rlib','-o','libtc.rlib']+opts,d)
        if p.returncode: raise ValueError(label+' library compilation failed')
        p=command(label+'-client',[str(rustc),'driver.rs','--extern','node115_tc_parallel_abort=libtc.rlib','-o','client']+opts,d)
        if p.returncode: raise ValueError(label+' client compilation failed')
        return d,{'rlib_sha256':sha((d/'libtc.rlib').read_bytes()),'client_sha256':sha((d/'client').read_bytes())}
    try:
        version=command('rustc-version',[str(rustc),'-vV'])
        if b'rustc 1.94.1 ' not in version.stdout: raise ValueError('requires Rust 1.94.1')
        for opt in (0,3):
            for repeat in (1,2):
                label=f'opt{opt}-repeat{repeat}';d,hashes=build(label,opt,source)
                p=command(label+'-run',[str(d/'client')],d,inputs)
                check=compare(p.stdout,expected)
                result['normal'].append(dict(label=label,exit=p.returncode,**hashes,**check))
                if p.returncode or check['mismatches']: raise ValueError(label+' failed')
            pair=result['normal'][-2:]
            if any(pair[0][k]!=pair[1][k] for k in ('rlib_sha256','client_sha256')): raise ValueError('repeat artifacts differ')
        for name,old,new in MUTANTS:
            text=source.decode()
            if text.count(old)!=1: raise ValueError('mutant anchor not unique: '+name)
            code=text.replace(old,new).encode();label='mutant-'+name;d,hashes=build(label,3,code)
            p=command(label+'-run',[str(d/'client')],d,inputs);check=compare(p.stdout,expected)
            result['mutants'].append(dict(label=label,source_sha256=sha(code),exit=p.returncode,**hashes,**check))
            if p.returncode or not check['mismatches']: raise ValueError(label+' ineffective')
        good=streams['opt3-repeat1-run.stdout'];raw=base64.b64decode(good['base64'])
        result['comparator_controls']=[]
        for label,bad in [('missing-line',raw[:raw.rfind(b'\n',0,-1)+1]),('extra-line',raw+b'0\n'),
                          ('changed-value',b'X'+raw[1:]),('reversed-lines',b'\n'.join(reversed(raw.splitlines()))+b'\n')]:
            try: rejected=compare(bad,expected)['mismatches']>0
            except ValueError: rejected=True
            if not rejected: raise ValueError('comparator accepted '+label)
            result['comparator_controls'].append({'label':label,'rejected':True,'sha256':sha(bad)})
        result['parser_controls']=[]; client=out/'opt3-repeat1/client'
        for label,data,args,code in [('empty',b'',[],0),('unknown',b'Z\n',[],2),('missing',b'M\n',[],2),
                  ('bad-number',b'P\t16\t0\t-1\t0\t0\t0\t1\t0\t0\n',[],2),
                  ('bad-byte',b'P\t16\t256\t0\t0\t0\t0\t1\t0\t0\n',[],2),
                  ('bad-stride',b'P\t17\t0\t0\t0\t0\t0\t1\t0\t0\n',[],2),
                  ('bad-width',b'M\t00\t00\t00\n',[],2),('arguments',b'',['unexpected'],2)]:
            p=command('parser-'+label,[str(client)]+args,out,data)
            if p.returncode!=code: raise ValueError('parser '+label)
            result['parser_controls'].append(dict(label=label,expected_exit=code,actual_exit=p.returncode))
        result['status']='PASS'
    except Exception as e:
        result['failure']=str(e)
        raise
    finally:
        archive=(json.dumps({'schema':1,'streams':streams},sort_keys=True,separators=(',',':'))+'\n').encode()
        packed=lzma.compress(archive,preset=6);(out/'raw-streams.json.xz').write_bytes(packed)
        if lzma.decompress(packed)!=archive: raise ValueError('archive roundtrip')
        result['archive']={'path':'raw-streams.json.xz','sha256':sha(packed),'raw_json_sha256':sha(archive),
                           'raw_json_bytes':len(archive),'streams':len(streams)}
        (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True)
    p.add_argument('--toolchain-bin',type=Path,required=True);a=p.parse_args()
    r=run(a.out.resolve(),a.toolchain_bin.resolve())
    print(json.dumps({'status':r['status'],'normal':r['normal'],'mutants':len(r['mutants']),'archive':r['archive']},indent=2))
