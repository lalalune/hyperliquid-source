#!/usr/bin/env python3
"""Compile independently authored Rust only, with frozen input-only comparison.

Real three-package copies preserve manifests/lock/relative dependencies. No fake
workspace, captured execution, emulator, network, or expected values in clients.
"""
from __future__ import annotations
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
COMPONENT='src/node94-consensus-admission'
PACKAGES=[COMPONENT,'src/bincode-varint','src/node94-action-signable']
MODULE=COMPONENT+'/src/block_preimage.rs'
DEFAULT_BIN=Path.home()/'.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin'


def need(value,why):
    if not value:raise ValueError(why)


def sha(data):return hashlib.sha256(data).hexdigest()


def ancestors(path,package=False):
    records=[]
    for form in sorted({path.absolute(),path.resolve()}):
        for parent in [form,*form.parents]:
            for name in ('.cargo/config','.cargo/config.toml'):
                need(not (parent/name).exists(),'unreviewed Cargo config: '+str(parent/name))
            if not package or parent!=form:
                need(not (parent/'Cargo.toml').exists(),'unreviewed ancestor manifest: '+str(parent))
            records.append(str(parent))
    return sorted(set(records))


def audit(root):
    files={};checked=[]
    for package in PACKAGES:
        p=root/package;checked.extend(ancestors(p,True))
        m=tomllib.loads((p/'Cargo.toml').read_text())
        need(m['package']['publish'] is False and m['package']['license']=='MIT','MIT unpublished package')
        need(not m['package'].get('build') and not m.get('lib',{}).get('proc-macro'),'build hook')
        need(not any(k in m for k in ('workspace','patch','replace','build-dependencies','dev-dependencies','target')),'manifest graph')
        wanted={'hl-bincode-varint':{'path':'../bincode-varint'},
                'node94-action-signable':{'path':'../node94-action-signable'}} if package==COMPONENT else {}
        need(m.get('dependencies',{})==wanted,'exact baseline path dependencies')
        for f in sorted(p.rglob('*')):
            if 'target' in f.relative_to(p).parts:continue
            need(not f.is_symlink(),'package symlink')
            need(f.name!='build.rs' and '.cargo' not in f.relative_to(p).parts,'package build/config hook')
            if f.is_file():files[str(f.relative_to(root))]=sha(f.read_bytes())
    lock=tomllib.loads((root/COMPONENT/'Cargo.lock').read_text())
    need(len(lock['package'])==3 and {x['name'] for x in lock['package']}==
         {'node94-consensus-admission','hl-bincode-varint','node94-action-signable'},'three-package lock')
    need(all('source' not in x and 'checksum' not in x for x in lock['package']),'external dependency')
    return files,sorted(set(checked))


def frozen():
    pre=json.loads((HERE/'PRE-RUST-FREEZE.json').read_text())
    for name,wanted in pre['files'].items():need(sha((HERE/name).read_bytes())==wanted,'pre-Rust '+name)
    source=json.loads((HERE/'rust-validation/SOURCE-FREEZE.json').read_text())
    for name,wanted in source['source_files'].items():need(sha((ROOT/name).read_bytes())==wanted,'source freeze '+name)
    for name,wanted in source['harness_files'].items():need(sha((HERE/name).read_bytes())==wanted,'harness freeze '+name)
    return source


def replace(source,old,new,count=1):
    need(source.count(old)==count,'mutant anchor: '+old[:80])
    return source.replace(old,new)


def mutants(source):
    truncated=source
    for n in (4,100,400):truncated=replace(truncated,f'previous_year.div_euclid({n})',f'(previous_year / {n})')
    omitted=replace(source,'count(qc.votes.len(), 96)?','0')
    omitted=replace(omitted,'word(out, qc.votes.len() as u64);','word(out, 0);')
    omitted=replace(omitted,'for vote in &qc.votes {','for vote in qc.votes.iter().take(0) {',2)
    empty=replace(source,'fn tc_len(tc: Option<&Tc>) -> Result<usize, BlockPreimageError> {',
                  'fn tc_len(tc: Option<&Tc>) -> Result<usize, BlockPreimageError> {\n    let tc = tc.filter(|x| !x.votes.is_empty());')
    empty=replace(empty,'fn append_tc(out: &mut Vec<u8>, tc: Option<&Tc>) {',
                  'fn append_tc(out: &mut Vec<u8>, tc: Option<&Tc>) {\n    let tc = tc.filter(|x| !x.votes.is_empty());')
    after=replace(source,'    append_signature(out, &timeout.signature);\n','')
    after=replace(after,'    append_qc(out, &timeout.qc);','    append_qc(out, &timeout.qc);\n    append_signature(out, &timeout.signature);')
    raw=replace(source,'1 + signature_words(signature)\n        .map(encoded_len_u64)\n        .sum::<usize>()','{ let _ = signature; 65 }')
    raw=replace(raw,'    for limb in signature_words(signature) {\n        word(out, limb);\n    }\n    out.push(signature.0[64]);',
                '    out.extend_from_slice(&signature.0[..65]);')
    return {
        'tag-one':replace(source,'    out.push(0);','    out.push(1);'),
        'clamp-negative-seconds':replace(source,'let seconds = time.timestamp_seconds();','let seconds = time.timestamp_seconds().max(0);'),
        'truncate-negative-year-division':truncated,
        'epoch-plus-one-day':replace(source,'- 719_163;','- 719_162;'),
        'raw-seconds-word':replace(source,'let seconds = time.timestamp_seconds();','let seconds = time.seconds as i64;'),
        'nanoseconds-to-milliseconds':replace(source,'time.nanoseconds','time.nanoseconds / 1_000_000',2),
        'reverse-transactions':replace(source,'for hash in &block.transaction_hashes {','for hash in block.transaction_hashes.iter().rev() {'),
        'reverse-QC-votes':replace(source,'for vote in &qc.votes {','for vote in qc.votes.iter().rev() {',2),
        'omit-QC-votes':omitted,
        'collapse-empty-TC':empty,
        'timeout-signature-after-body':after,
        'raw65-signature':raw,
        'big-endian-signature-limbs':replace(source,'u64::from_le_bytes(bytes)','u64::from_be_bytes(bytes)'),
        'inactive-padding-as-final-byte':replace(source,'out.push(signature.0[64]);','out.push(signature.0[65]);'),
        'zero-claimed-proposer':replace(source,'out.extend_from_slice(&block.proposer.0);','out.extend_from_slice(&[0; 20]);'),
        'one-block-hash':replace(source,'keccak256(&preimage)','keccak256(&preimage[..preimage.len().min(136)])'),
        'rate-multiple-drop-byte':replace(source,'keccak256(&preimage)',
            'keccak256(&preimage[..if preimage.len() % 136 == 0 { preimage.len()-1 } else { preimage.len() }])'),
    }


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--out',type=Path,required=True)
    ap.add_argument('--toolchain-bin',type=Path,default=DEFAULT_BIN);a=ap.parse_args()
    need(not a.out.exists(),'new output directory required');a.out.mkdir(parents=True)
    source_freeze=frozen();files,root_ancestors=audit(ROOT)
    need(files==source_freeze['source_files'],'audited graph equals source freeze')
    vectors=[line.split('\t') for line in gzip.decompress((HERE/'fixtures/vectors.tsv.gz').read_bytes()).decode().splitlines()]
    need(len(vectors)==1141 and all(len(v)==5 and v[0]==f'C{i:06d}' for i,v in enumerate(vectors)),'opaque frozen vector shape')
    stdin=('\n'.join(v[0]+'\t'+v[1] for v in vectors)+'\n').encode()
    expected=['\t'.join([v[0],v[2],v[3],v[4]]) for v in vectors]
    changes=mutants((ROOT/MODULE).read_text());commands=[];runs={};outputs={};raw_streams={}
    tools={n:{'path':'<TOOLCHAIN>/'+n,'sha256':sha((a.toolchain_bin/n).read_bytes())} for n in ('cargo','rustc','rustdoc','rustfmt','cargo-clippy','clippy-driver')}
    with tempfile.TemporaryDirectory(prefix='block-own-rust-',dir='/tmp') as temp:
        work=Path(temp);canonical=work.resolve();temporary_ancestors=ancestors(work)
        (work/'cargo-home').mkdir()
        replacements=sorted({str(work):'<WORK>',str(canonical):'<WORK>',str(ROOT):'<ROOT>',str(ROOT.resolve()):'<ROOT>',str(a.toolchain_bin):'<TOOLCHAIN>',str(Path.home()):'<HOME>'}.items(),key=lambda x:-len(x[0]))
        def normalize(text):
            for old,new in replacements:text=text.replace(old,new)
            return text
        remaps=['--remap-path-prefix='+old+'='+new for old,new in replacements]
        env={'PATH':str(a.toolchain_bin)+':/usr/bin:/bin:/usr/sbin:/sbin','CARGO_HOME':str(work/'cargo-home'),
             'RUSTC':str(a.toolchain_bin/'rustc'),'RUSTDOC':str(a.toolchain_bin/'rustdoc'),'LC_ALL':'C',
             'CARGO_TERM_COLOR':'never','CARGO_INCREMENTAL':'0','CARGO_ENCODED_RUSTFLAGS':'\x1f'.join(remaps)}
        def run(argv,cwd=ROOT,data=None,target=None):
            chosen=dict(env)
            if target is not None:chosen['CARGO_TARGET_DIR']=str(target)
            result=subprocess.run([str(x) for x in argv],cwd=cwd,env=chosen,input=data,capture_output=True)
            record={'argv':[normalize(str(x)) for x in argv],'cwd':normalize(str(cwd)),'exit':result.returncode}
            for label,raw in [('stdout',result.stdout),('stderr',result.stderr)]:
                digest=sha(raw);filename='raw/'+digest+'.gz'
                raw_streams[filename]=gzip.compress(raw,mtime=0)
                path=a.out/filename;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw_streams[filename])
                record[label]={'raw_sha256':digest,'archive':filename,'archive_sha256':sha(raw_streams[filename]),'bytes':len(raw)}
            if data is not None:record['stdin_sha256']=sha(data)
            commands.append(record)
            (a.out/'commands.json.gz').write_bytes(gzip.compress((json.dumps(commands,separators=(',',':'))+'\n').encode(),mtime=0))
            need(result.returncode==0,'command failed: '+normalize(str(argv))+'\n'+normalize(result.stderr.decode()))
            return result.stdout
        version=run([a.toolchain_bin/'rustc','--version']).decode().strip()
        verbose=run([a.toolchain_bin/'rustc','-vV']).decode()
        need(version.startswith('rustc 1.94.1 '),'pinned toolchain version')
        run([a.toolchain_bin/'cargo','--version'])
        run([a.toolchain_bin/'rustfmt','--edition','2021','--check',ROOT/MODULE,ROOT/COMPONENT/'tests/block_preimage.rs',HERE/'driver.rs'])
        def clone(root):
            for package in PACKAGES:shutil.copytree(ROOT/package,root/package,ignore=shutil.ignore_patterns('target'))
            need(audit(root)[0]==files,'real package copy')
        original=work/'source';clone(original)
        metadata=json.loads(run([a.toolchain_bin/'cargo','metadata','--offline','--locked','--format-version','1','--manifest-path',original/COMPONENT/'Cargo.toml']))
        need(len(metadata['packages'])==3 and all(x['source'] is None for x in metadata['packages']),'actual three-package graph')
        need(all(not set(t['kind']) & {'custom-build','proc-macro'} for p in metadata['packages'] for t in p['targets']),'no executable build hooks')
        artifacts={}
        def build(root,label,profile,original_run=False,rebuild=False):
            target=work/('target-'+label);binary=work/('client-'+label)
            if rebuild:
                shutil.rmtree(target);binary.unlink()
            extra=['--release'] if profile=='release' else []
            manifest=root/COMPONENT/'Cargo.toml'
            run([a.toolchain_bin/'cargo','build','--offline','--locked','--lib','--manifest-path',manifest,*extra],root/COMPONENT,target=target)
            if original_run and not rebuild:
                # Existing evidence_contract launches only shasum, but is outside
                # this copied graph. Run own integration and library tests only.
                run([a.toolchain_bin/'cargo','test','--offline','--locked','--lib','--test','block_preimage','--manifest-path',manifest,*extra],root/COMPONENT,target=target)
            rlib=target/profile/'libnode94_consensus_admission.rlib'
            run([a.toolchain_bin/'rustc','--edition=2021',HERE/'driver.rs','--extern','node94_consensus_admission='+str(rlib),
                 '-L','dependency='+str(target/profile/'deps'),'-C','opt-level='+('3' if profile=='release' else '0'),*remaps,'-o',binary])
            stdout=run([binary],data=stdin);rows=stdout.decode().splitlines()
            need(len(rows)==len(expected),'client output count')
            mismatch=[vectors[i][0] for i,(x,y) in enumerate(zip(rows,expected)) if x!=y]
            key=label+('-rebuild' if rebuild else '')
            archive='outputs/'+key+'.tsv.gz';outputs[archive]=gzip.compress(stdout,mtime=0)
            identities={'rlib_sha256':sha(rlib.read_bytes()),'client_sha256':sha(binary.read_bytes())}
            runs[key]={'cases':len(rows),'mismatches':len(mismatch),'first_mismatches':mismatch[:8],
                       'output':archive,'output_sha256':sha(outputs[archive]),'stdout_sha256':sha(stdout),**identities}
            if original_run:
                need(not mismatch,'frozen preimage comparison')
                if rebuild:
                    need(identities==artifacts[label],'clean same-path artifact mismatch')
                    need(runs[key]['stdout_sha256']==runs[label]['stdout_sha256'],'clean rebuild output mismatch')
                else:
                    artifacts[label]=identities
                    minimal=bytes.fromhex(vectors[0][1]);option=44+60
                    bad_option=bytearray(minimal);bad_option[option]=2
                    bad_count=bytearray(minimal);bad_count[40:44]=(0xffffffff).to_bytes(4,'little')
                    malformed=['','C000000\tgg','C000000\t0','C000000\t'+minimal[:-1].hex(),
                               'C000000\t'+(minimal+b'\0').hex(),'C000000\t'+bad_option.hex(),
                               'C000000\t'+bad_count.hex(),'rate-length-91\t'+minimal.hex()]
                    invalid=run([binary],data=('\n'.join(malformed)+'\n').encode()).decode().splitlines()
                    need(invalid==['ERR']*len(malformed),'malformed frame rejection')
                    renamed=run([binary],data=('C999999\t'+vectors[0][1]+'\n').encode()).decode().strip()
                    need(renamed.split('\t')[1:]==expected[0].split('\t')[1:],'ID must be inert')
                    runs[key]['malformed_rejected']=len(invalid);runs[key]['opaque_ID_invariance']=True
            else:need(mismatch,'compiled source mutant survived')
        for profile in ('debug','release'):
            build(original,profile,profile,True)
            build(original,profile,profile,True,True)
        run([a.toolchain_bin/'cargo','clippy','--offline','--locked','--lib','--test','block_preimage','--manifest-path',original/COMPONENT/'Cargo.toml','--','-D','warnings'],original/COMPONENT,target=work/'target-clippy')
        for name,changed in changes.items():
            root=work/('mutant-'+name);clone(root);(root/MODULE).write_text(changed)
            for profile in ('debug','release'):
                label='mutant-'+name+'-'+profile;build(root,label,profile)
                runs[label]['module_sha256']=sha(changed.encode())
        audit_report={'root_ancestor_checks':[normalize(x) for x in root_ancestors],
                      'temporary_ancestor_checks':[normalize(x) for x in temporary_ancestors],
                      'lexical_and_canonical_temporary_roots_checked':True,'remap_flags':[normalize(x) for x in remaps],
                      'environment_keys':sorted(env),'inherit_parent_environment':False,
                      'command_path_metadata_normalized':True,
                      'raw_stream_policy':'Raw bytes unchanged; compiler path remapping is active. Metadata paths normalize ROOT/WORK/TOOLCHAIN; raw streams checked for personal paths.'}
        need(audit(ROOT)[0]==files,'original graph changed during build');frozen()
        for name,identity in tools.items():need(sha((a.toolchain_bin/name).read_bytes())==identity['sha256'],'tool changed')
        for filename,blob in raw_streams.items():
            need(b'/Users/' not in gzip.decompress(blob),'personal path in raw stream: '+filename)
        result={'toolchain':version,'rustc_verbose_version':verbose,'toolchain_executables':tools,
                'built_sources':files,'driver_sha256':sha((HERE/'driver.rs').read_bytes()),
                'source_freeze_sha256':sha((HERE/'rust-validation/SOURCE-FREEZE.json').read_bytes()),
                'pre_Rust_freeze_sha256':sha((HERE/'PRE-RUST-FREEZE.json').read_bytes()),
                'input_only_sha256':sha(stdin),'captured_execution_or_emulation':False,'audit':audit_report,'runs':runs}
        outputs.update(raw_streams)
        outputs['results.json']=(json.dumps(result,indent=2)+'\n').encode()
        outputs['commands.json.gz']=gzip.compress((json.dumps(commands,separators=(',',':'))+'\n').encode(),mtime=0)
        for name,data in outputs.items():
            path=a.out/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
        print(json.dumps({'commands':len(commands),'runs':{k:{'cases':v['cases'],'mismatches':v['mismatches']} for k,v in runs.items()}}))


if __name__=='__main__':main()
