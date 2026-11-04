#!/usr/bin/env python3
"""Compile/run only the new Rust against immutable pre-Rust expectations."""
import argparse
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

HERE=Path(__file__).resolve().parent


def sha(data): return hashlib.sha256(data).hexdigest()


def compare(actual, expected):
    a=actual.splitlines();b=expected.splitlines()
    differences=[i for i,(x,y) in enumerate(zip(a,b)) if x!=y]
    return dict(actual_lines=len(a),expected_lines=len(b),mismatches=len(differences)+abs(len(a)-len(b)),first_difference=(differences or [min(len(a),len(b)) if len(a)!=len(b) else None])[0],exact=actual==expected)


MUTANTS=[
 ('history-early-switch','base.saturating_add(2000)','base.saturating_add(1999)',1),
 ('history-wrapped-threshold','base.saturating_add(2000)','base.wrapping_add(2000)',1),
 ('history-delay-199','round.wrapping_sub(200)','round.wrapping_sub(199)',1),
 ('history-exclusive','r <= query','r < query',1),
 ('history-wrong-max','base.max(round.wrapping_sub(200))','base.min(round.wrapping_sub(200))',1),
 ('filter-inverted','blocked.binary_search(key).is_err()','blocked.binary_search(key).is_ok()',1),
 ('union-duplicates','members.dedup();','// omit union deduplication',1),
 ('sum-wrapped','total.saturating_add(weight)','total.wrapping_add(weight)',1),
 ('threshold-999','total.saturating_sub(1000)','total.saturating_sub(999)',1),
 ('threshold-map-count','/ members.len() as u64','/ (kept.len().max(1)) as u64',1),
 ('member-wrapped-subtract','weight.saturating_sub(threshold)','weight.wrapping_sub(threshold)',1),
 ('outside-double','weight.saturating_mul(3)','weight.saturating_mul(2)',1),
 ('fallback-double','(weight.saturating_mul(3), key)','(weight.saturating_mul(2), key)',1),
 ('fallback-wrapped','(weight.saturating_mul(3), key)','(weight.wrapping_mul(3), key)',1),
 ('fallback-key-ascending','b.cmp(a)','b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1))',2),
 ('fallback-weight-ascending','b.cmp(a)','a.0.cmp(&b.0).then_with(|| b.1.cmp(&a.1))',2),
 ('reciprocal-double','let inverse = 1.0 /','let inverse = 2.0 /',1),
 ('index-u32','i as i64 as f64','i as u32 as f64',1),
 ('count-u32','product / n as f64','product / n as u32 as f64',1),
 ('unfused','inverse.mul_add(j as f64, base)','inverse * j as f64 + base',1),
 ('event-index-u32','inverse.mul_add(j as f64, base)','inverse.mul_add(j as u32 as f64, base)',1),
 ('event-base-omitted','inverse.mul_add(j as f64, base)','inverse.mul_add(j as f64, 0.0)',1),
 ('event-order-reversed','.total_cmp(&f64::from_bits(b.bits))','.total_cmp(&f64::from_bits(b.bits)).reverse()',1),
 ('event-payload-reversed','a.key.cmp(&b.key)','b.key.cmp(&a.key)',1),
 ('event-key-truncated','a.key.cmp(&b.key)','a.key.map(|k| k[..16].to_vec()).cmp(&b.key.map(|k| k[..16].to_vec()))',1),
 ('batch-same-key','[0, usize::from(pool.len() != 1), 2 % pool.len()]','[0, 0, 0]',1),
 ('batch-wrong-third','2 % pool.len()','1 % pool.len()',1),
 ('batch-wrapped-decrement','pool[index].0.saturating_sub(1)','pool[index].0.wrapping_sub(1)',1),
 ('batch-rerank-each','pool[index].0 = pool[index].0.saturating_sub(1);','pool[index].0 = pool[index].0.saturating_sub(1); pool.sort_unstable_by(|a,b|b.cmp(a));',1),
 ('initial-zero-pruning','let mut pool = fallback.to_vec();','let mut pool = fallback.to_vec(); pool.retain(|x| x.0 != 0);',1),
 ('skip-zero-pruning','while pool.last().is_some_and(|x| x.0 == 0)','while false && pool.last().is_some_and(|x| x.0 == 0)',1),
 ('remainder-u32','round % keys.len() as u64','(round as u32 as u64) % keys.len() as u64',1),
 ('selected-tag','SELECTED: u8 = 0x2e','SELECTED: u8 = 0x2d',1),
 ('empty-tag','EMPTY: u8 = 0x0f','EMPTY: u8 = 0x0e',1),
 ('missing-tag','MISSING: u8 = 0x28','MISSING: u8 = 0x27',1),
 ('selected-key-endian','image[1..21].copy_from_slice(&key);','let mut key = key; key.reverse(); image[1..21].copy_from_slice(&key);',1),
 ('missing-clears-tail','scratch[8..16].copy_from_slice(&query_round.to_le_bytes());','scratch[8..16].copy_from_slice(&query_round.to_le_bytes()); scratch[16..].fill(0);',1),
 ('diagnostic-boundary','query_round >= limit','query_round > limit',1),
 ('diagnostic-execution-delay','execution.saturating_add(201)','execution.saturating_add(200)',1),
 ('diagnostic-wrapped-limit','stake_base\n        .saturating_add(2000)','stake_base\n        .wrapping_add(2000)',1),
 ('diagnostic-minimum','.max(execution.saturating_add(201))','.min(execution.saturating_add(201))',1),
 ('diagnostic-counter-saturates','counter.wrapping_add(u64::from(warning))','counter.saturating_add(u64::from(warning))',1),
 ('ring-exclusive','physical[at(mid)] <= query','physical[at(mid)] < query',1),
 ('ring-predecessor-logical','lo.checked_sub(1).map(at)','lo.checked_sub(1)',1),
 ('selected-round-conflated','            selected_round,','            query_round,',1),
 ('missing-uses-output','        scratch[0] = MISSING;','        scratch = image; scratch[0] = MISSING;',1),
 ('missing-round-endian','query_round.to_le_bytes()','query_round.to_be_bytes()',1),

]


def run(out, rustc):
    if out.exists(): raise ValueError('fresh output directory required; preserve earlier results')
    out.mkdir(parents=True)
    freeze=json.loads((HERE/'freeze.json').read_text())
    source=(HERE/'rust/lib.rs').read_bytes();driver=(HERE/'rust/driver.rs').read_bytes()
    if sha((HERE/'oracle.py').read_bytes())!=freeze['oracle_sha256']:raise ValueError('oracle drift')
    raw={}
    for kind in ('inputs','expected'):
        compressed=(HERE/f'{kind}.txt.gz').read_bytes();raw[kind]=gzip.decompress(compressed)
        if sha(compressed)!=freeze['files'][kind]['gzip_sha256'] or sha(raw[kind])!=freeze['files'][kind]['raw_sha256']:raise ValueError('frozen fixture drift')
    records=[];streams=[];results=[]
    def command(label,args,stdin=None):
        begin=time.monotonic();p=subprocess.run(args,input=stdin,capture_output=True,timeout=180)
        rec=dict(label=label,argv=[str(x).replace(str(out),'$OUT').replace(str(HERE),'$PACKET').replace(str(rustc.parent),'$TOOLCHAIN') for x in args],exit_code=p.returncode,seconds=round(time.monotonic()-begin,6))
        for channel,data in [('stdout',p.stdout),('stderr',p.stderr)]:
            name=label+'.'+channel
            streams.append(dict(name=name,sha256=sha(data),bytes=len(data),base64=base64.b64encode(data).decode()))
            rec[channel]=dict(sha256=sha(data),bytes=len(data))
        records.append(rec)
        (out/'commands.json').write_text(json.dumps(records,indent=2)+'\n')
        return p
    def checkpoint():
        data=json.dumps(streams,separators=(',',':')).encode()
        (out/'raw-streams.json.gz').write_bytes(gzip.compress(data,mtime=0))
        restored=json.loads(gzip.decompress((out/'raw-streams.json.gz').read_bytes()))
        for item in restored:
            b=base64.b64decode(item['base64'],validate=True)
            if sha(b)!=item['sha256'] or len(b)!=item['bytes']:raise ValueError('archive verification failed')
    try:
        version=command('compiler-version',[str(rustc),'-vV'])
        if version.returncode:raise ValueError('rustc version failed')
        for opt in (0,3):
            outputs=[];objects=[]
            for repeat in (1,2):
                label=f'opt{opt}-repeat{repeat}';d=out/label;d.mkdir();(d/'lib.rs').write_bytes(source);(d/'driver.rs').write_bytes(driver)
                exe=d/'client';obj=d/'library.o'
                flags=['--edition=2021',f'-Copt-level={opt}','-Ccodegen-units=1','-Cdebuginfo=0','--remap-path-prefix',str(d)+'=qualification']
                p=command(label+'-compile',[str(rustc),*flags,str(d/'driver.rs'),'-o',str(exe)])
                if p.returncode:raise ValueError(label+' compilation failed')
                p=command(label+'-object',[str(rustc),*flags,'--crate-type=lib','--crate-name=proposer_selection115','--emit=obj',str(d/'lib.rs'),'-o',str(obj)])
                if p.returncode:raise ValueError(label+' object compile failed')
                objects.append(sha(obj.read_bytes()))
                p=command(label+'-run',[str(exe)],raw['inputs']);c=compare(p.stdout,raw['expected']);c.update(label=label,exit_code=p.returncode,object_sha256=objects[-1]);results.append(c);outputs.append(p.stdout)
                if p.returncode or not c['exact']:raise ValueError(label+' frozen comparison failed')
            if outputs[0]!=outputs[1] or objects[0]!=objects[1]:raise ValueError('repeat differs')
            checkpoint()
        mutation_results=[]
        text=source.decode()
        input_lines=raw['inputs'].splitlines(keepends=True)
        expected_lines=raw['expected'].splitlines(keepends=True)
        stage=[i for i,x in enumerate(input_lines) if x[:1] in b'PHEQGR']
        selected=b''.join(input_lines[i] for i in stage)
        stage_expected=b''.join(expected_lines[i] for i in stage)
        for name,old,new,count in MUTANTS:
            actual=text.count(old)
            if actual<count:raise ValueError(f'mutation anchor {name}: {actual} < {count}')
            modified=text.replace(old,new,count);d=out/('mutant-'+name);d.mkdir();(d/'lib.rs').write_text(modified);(d/'driver.rs').write_bytes(driver);exe=d/'client'
            p=command('mutant-'+name+'-compile',[str(rustc),'--edition=2021','-Copt-level=3','-Ccodegen-units=1','-Cdebuginfo=0','--remap-path-prefix',str(d)+'=qualification',str(d/'driver.rs'),'-o',str(exe)])
            if p.returncode:raise ValueError(name+' failed to compile; not an effective native control')
            # Arithmetic corruption can create enormous schedules. Run P/H/E/Q
            # stage fixtures first and stop on an observed mismatch. Input-only
            # driver still gets no expected data. S/F follow only when necessary.
            p=command('mutant-'+name+'-stage-run',[str(exe)],selected);c=compare(p.stdout,stage_expected)
            if p.returncode==0 and c['exact']:
                p=command('mutant-'+name+'-full-run',[str(exe)],raw['inputs']);c=compare(p.stdout,raw['expected']);phase='full'
            else:phase='stage'
            c.update(name=name,phase=phase,exit_code=p.returncode,source_sha256=sha(modified.encode()),effective=p.returncode!=0 or not c['exact']);mutation_results.append(c)
            checkpoint()
        survivors=[m['name'] for m in mutation_results if not m['effective']]
        if survivors:raise ValueError('surviving controls: '+', '.join(survivors))
        comparator_controls=[compare(raw['expected'][:-1],raw['expected']),compare(raw['expected']+b'x\n',raw['expected']),compare(b'',raw['expected']),compare(raw['expected'].replace(b'H ',b'X ',1),raw['expected'])]
        if any(c['exact'] for c in comparator_controls):raise ValueError('comparator control survived')
        result=dict(status='PASS',cases=freeze['cases'],pre_node115_adaptation_cases=freeze['cases'],correct_builds=results,mutants=mutation_results,comparator_controls=comparator_controls,
                    source_sha256=sha(source),driver_sha256=sha(driver),oracle_sha256=freeze['oracle_sha256'],
                    stream_count=len(streams),raw_archive_sha256=sha((out/'raw-streams.json.gz').read_bytes()),
                    limit='Only newly authored Rust ran; these are conditional static-derived expectations, not captured target observations.')
        (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps({k:v for k,v in result.items() if k not in ('correct_builds','mutants')},indent=2))
    except Exception as e:
        checkpoint();(out/'failure.json').write_text(json.dumps({'error':str(e),'correct_builds':results,'mutants':locals().get('mutation_results',[]),'source_sha256':sha(source),'driver_sha256':sha(driver),'completed_commands':len(records)},indent=2)+'\n')
        raise


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);p.add_argument('--rustc',type=Path,required=True);a=p.parse_args();run(a.out.resolve(),a.rustc.resolve())
