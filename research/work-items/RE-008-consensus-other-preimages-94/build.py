#!/usr/bin/env python3
"""Build only reviewed own Rust; compare an input-only driver with frozen fixtures.

Mutants copy the three genuine local packages and preserve their manifests/lock
and dependency paths. No synthetic workspace, target execution or emulator.
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

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
COMPONENT = 'src/node94-consensus-admission'
PACKAGES = [COMPONENT, 'src/bincode-varint', 'src/node94-action-signable']
MODULE = COMPONENT + '/src/message_preimages.rs'
DEFAULT_BIN = Path.home()/'.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin'


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def audit(root):
    """Fail closed on added Cargo configuration/build hooks or dependency graphs."""
    files = {}
    for package in PACKAGES:
        p = root/package
        for parent in [p, *p.parents]:
            for rel in ['.cargo/config', '.cargo/config.toml']:
                need(not (parent/rel).exists(), f'unreviewed ancestor Cargo config: {parent/rel}')
            if parent != p:
                need(not (parent/'Cargo.toml').exists(), f'unreviewed ancestor manifest: {parent}')
        manifest = tomllib.loads((p/'Cargo.toml').read_text())
        need(manifest['package']['publish'] is False and manifest['package']['license'] == 'MIT', 'package scope')
        need(not manifest['package'].get('build') and not manifest.get('lib',{}).get('proc-macro'), 'build hook')
        need(not any(k in manifest for k in ['workspace','patch','replace','build-dependencies','dev-dependencies']), 'unreviewed manifest table')
        expected = {'hl-bincode-varint': {'path':'../bincode-varint'},
                    'node94-action-signable': {'path':'../node94-action-signable'}} if package == COMPONENT else {}
        need(manifest.get('dependencies',{}) == expected, 'exact two baseline local dependencies')
        for f in sorted(p.rglob('*')):
            if 'target' in f.relative_to(p).parts:
                continue
            need(not f.is_symlink(), 'package symlink')
            need(f.name != 'build.rs' and '.cargo' not in f.relative_to(p).parts, 'package hook/config')
            if f.is_file():
                files[str(f.relative_to(root))] = sha(f.read_bytes())
    lock = tomllib.loads((root/COMPONENT/'Cargo.lock').read_text())
    need({p['name'] for p in lock['package']} == {'node94-consensus-admission','hl-bincode-varint','node94-action-signable'}, 'lock graph')
    need(all('source' not in p and 'checksum' not in p for p in lock['package']), 'registry/git dependency')
    return files


def replacement(source, old, new, count=1):
    need(source.count(old) == count, f'mutant anchor count: {old[:80]}')
    return source.replace(old,new)


def mutants(source):
    raw = replacement(source,
        'for limb in signature_words(&vote.signature) {\n            add(&mut size, encoded_len_u64(limb))?;\n        }',
        'add(&mut size, 64)?;')
    raw = replacement(raw,
        'for limb in signature_words(&vote.signature) {\n            word(&mut out, limb);\n        }\n        out.push(vote.signature.0[64]);',
        'out.extend_from_slice(&vote.signature.0[..65]);')
    omitted = replacement(source, 'count(qc.votes.len())?', '0', 2)
    omitted = replacement(omitted,'for vote in &qc.votes {','for vote in qc.votes.iter().take(0) {',2)
    reversed_rows = replacement(source,'for vote in &qc.votes {','for vote in qc.votes.iter().rev() {',2)
    zero_signer = replacement(source,'out.extend_from_slice(&signer.0);','out.extend_from_slice(&[0; 20]);',2)
    zero_signer = replacement(zero_signer,'out.extend_from_slice(&message.signer.0);','out.extend_from_slice(&[0; 20]);')
    ack = replacement(source,
        'encode_u32(random, PayloadOrder::Little, &mut out);\n    word(&mut out, round.0);',
        'word(&mut out, round.0);\n    encode_u32(random, PayloadOrder::Little, &mut out);')
    empty = replacement(source,'let mut size = 1;\n    if let Some(rows) = rows {',
        'let rows = rows.filter(|r| !r.is_empty());\n    let mut size = 1;\n    if let Some(rows) = rows {')
    empty = replacement(empty,'out.push(u8::from(rows.is_some()));',
        'let rows = rows.filter(|r| !r.is_empty());\n    out.push(u8::from(rows.is_some()));')
    triple = replacement(source,
        'word(&mut out, summary.first);\n                word(&mut out, summary.second);\n                out.extend_from_slice(&summary.block_hash.0);',
        'out.extend_from_slice(&summary.block_hash.0);\n                word(&mut out, summary.first);\n                word(&mut out, summary.second);')
    one = replacement(source,'keccak256(&preimage)', 'keccak256(&preimage[..preimage.len().min(136)])')
    exact = replacement(source,'keccak256(&preimage)',
        'keccak256(&preimage[..if preimage.len() % 136 == 0 { preimage.len()-1 } else { preimage.len() }])')
    endian = replacement(source,'u64::from_le_bytes(limb)','u64::from_be_bytes(limb)')
    return {'raw65-signature':raw,'omit-nested-votes':omitted,'reverse-votes':reversed_rows,
            'zero-claimed-signers':zero_signer,'ack-round-before-random':ack,'collapse-empty-map':empty,
            'summary-hash-before-words':triple,'one-block-hash':one,'rate-multiple-drop-byte':exact,
            'big-endian-signature-limbs':endian}


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--out',type=Path,required=True)
    ap.add_argument('--toolchain-bin',type=Path,default=DEFAULT_BIN);a=ap.parse_args()
    need(not a.out.exists(),'output must be new');a.out.mkdir(parents=True)
    files=audit(ROOT); commands=[]; results={}; outputs={}
    tool_identities={name:dict(path=str(a.toolchain_bin/name),sha256=sha((a.toolchain_bin/name).read_bytes()))
                     for name in ['cargo','rustc','rustdoc','rustfmt']}
    vectors=[line.split('\t') for line in gzip.decompress((HERE/'fixtures/vectors.tsv.gz').read_bytes()).decode().splitlines()]
    need(len(vectors)==534 and all(len(x)==4 for x in vectors),'frozen corpus shape')
    input_data=('\n'.join(x[1] for x in vectors)+'\n').encode()
    expected=[f'{len(bytes.fromhex(x[2]))}\t{x[2]}\t{x[3]}' for x in vectors]
    source=(ROOT/MODULE).read_text(); changes=mutants(source)
    with tempfile.TemporaryDirectory(prefix='consensus-own-rust-') as temp:
        work=Path(temp);(work/'cargo-home').mkdir()
        env={'HOME':str(Path.home()),'PATH':str(a.toolchain_bin)+':/usr/bin:/bin:/usr/sbin:/sbin',
             'CARGO_HOME':str(work/'cargo-home'),'RUSTC':str(a.toolchain_bin/'rustc'),
             'RUSTDOC':str(a.toolchain_bin/'rustdoc'),'LC_ALL':'C','CARGO_TERM_COLOR':'never'}
        def normalized(text):
            return text.replace(str(work),'<WORK>').replace(str(ROOT),'<ROOT>').replace(str(a.toolchain_bin),'<TOOLCHAIN>')
        def run(argv,cwd=ROOT,data=None,target=None):
            chosen={**env}
            if target is not None: chosen['CARGO_TARGET_DIR']=str(target)
            p=subprocess.run([str(x) for x in argv],cwd=cwd,env=chosen,input=data,capture_output=True)
            commands.append(dict(argv=[normalized(str(x)) for x in argv],cwd=normalized(str(cwd)),
                                 exit=p.returncode,stdout=normalized(p.stdout.decode()),stderr=normalized(p.stderr.decode())))
            need(p.returncode==0, f'command failed: {argv}\n{p.stderr.decode()}')
            return p.stdout
        version=run([a.toolchain_bin/'rustc','--version']).decode().strip()
        verbose_version=run([a.toolchain_bin/'rustc','-vV']).decode()
        need(version.startswith('rustc 1.94.1 '),'pinned Rust 1.94.1 required')
        run([a.toolchain_bin/'cargo','--version'])
        run([a.toolchain_bin/'rustfmt','--edition','2021','--check',ROOT/MODULE,
             ROOT/COMPONENT/'tests/message_preimages.rs',HERE/'driver.rs'])
        metadata=json.loads(run([a.toolchain_bin/'cargo','metadata','--offline','--locked','--format-version','1',
                                '--manifest-path',ROOT/COMPONENT/'Cargo.toml']))
        need(len(metadata['packages'])==3 and all(x['source'] is None for x in metadata['packages']),'actual Cargo graph')
        need(all(t['kind'] not in [['custom-build'],['proc-macro']] for p in metadata['packages'] for t in p['targets']), 'executable build hook')
        def compile_and_run(root,label,profile,tests=False):
            target=work/('target-'+label);manifest=root/COMPONENT/'Cargo.toml'
            release=['--release'] if profile=='release' else []
            run([a.toolchain_bin/'cargo','build','--offline','--locked','--lib','--manifest-path',manifest,*release],root/COMPONENT,target=target)
            if tests:
                run([a.toolchain_bin/'cargo','test','--offline','--locked','--manifest-path',manifest,*release],root/COMPONENT,target=target)
            binary=work/('driver-'+label)
            run([a.toolchain_bin/'rustc','--edition=2021',HERE/'driver.rs','--extern',
                 'node94_consensus_admission='+str(target/profile/'libnode94_consensus_admission.rlib'),
                 '-L','dependency='+str(target/profile/'deps'),'-C','opt-level='+('3' if profile=='release' else '0'),'-o',binary])
            stdout=run([binary],data=input_data).decode()
            actual=stdout.splitlines();need(len(actual)==len(expected),'driver result count')
            mismatches=[vectors[i][0] for i,(x,y) in enumerate(zip(actual,expected)) if x!=y]
            compressed=gzip.compress(stdout.encode(),mtime=0);filename=label+'.tsv.gz';outputs[filename]=compressed
            results[label]=dict(cases=len(actual),mismatches=len(mismatches),first_mismatches=mismatches[:8],
                                output_file=filename,output_sha256=sha(compressed),stdout_sha256=sha(stdout.encode()))
            if tests:
                need(not mismatches,'frozen fixture disagreement')
                malformed=['','gg','0','05'+'00'*20,vectors[0][1]+'00',vectors[0][1][:-2]]
                bad=run([binary],data=('\n'.join(malformed)+'\n').encode()).decode().splitlines()
                need(bad==['ERR']*len(malformed),'driver malformed-input rejection')
                results[label]['malformed_inputs_rejected']=len(bad)
            else:need(mismatches,'compiled mutant survived all fixtures')
        compile_and_run(ROOT,'debug','debug',True)
        compile_and_run(ROOT,'release','release',True)
        run([a.toolchain_bin/'cargo','clippy','--offline','--locked','--all-targets','--manifest-path',ROOT/COMPONENT/'Cargo.toml','--','-D','warnings'],ROOT/COMPONENT,target=work/'target-clippy')
        for name,changed in changes.items():
            clone=work/name
            for package in PACKAGES:
                shutil.copytree(ROOT/package,clone/package,ignore=shutil.ignore_patterns('target'))
            need(audit(clone)==files,'genuine package copy changed')
            (clone/MODULE).write_text(changed)
            compile_and_run(clone,'mutant-'+name,'release')
            results['mutant-'+name]['module_sha256']=sha(changed.encode())
    need(audit(ROOT)==files,'source graph changed during build')
    # Driver stdout is retained once per run; omit its duplicate bulk from command logs.
    for row in commands:
        if row['argv'][0].startswith('<WORK>/driver-') and row['stdout'].count('\n')==534:
            row['stdout_sha256']=sha(row['stdout'].encode());row['stdout']='(retained in corresponding .tsv.gz)'
    need(all(sha((a.toolchain_bin/name).read_bytes())==x['sha256'] for name,x in tool_identities.items()),'toolchain changed during build')
    results={'toolchain':version,'toolchain_executables':tool_identities,'rustc_verbose_version':verbose_version,
             'input_only_sha256':sha(input_data),'built_sources':files,'driver_sha256':sha((HERE/'driver.rs').read_bytes()),
             'expectation_freeze_sha256':sha((HERE/'PRE-RUST-FREEZE.json').read_bytes()),'runs':results}
    outputs['results.json']=(json.dumps(results,indent=2)+'\n').encode()
    outputs['commands.json.gz']=gzip.compress((json.dumps(commands,separators=(',',':'))+'\n').encode(),mtime=0)
    for name,data in outputs.items():(a.out/name).write_bytes(data)
    print(json.dumps({k:{'cases':v['cases'],'mismatches':v['mismatches']} for k,v in results['runs'].items()}))


if __name__=='__main__':main()
