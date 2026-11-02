#!/usr/bin/env python3
"""Fixed authored-Rust hash comparison, not captured-node execution."""
import argparse
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PIN = '54735068738b50c515b09550b78164c12762107d'
HASH_FREEZE = 'bb9c60696d5dd557299b7a4309868717c3eec6b31f3c17fdd8f413cf6c8a7582'
COMPOSITION_FREEZE = 'ecf9483b158c444f3557e7015ad66e4f4e925c16e9d52e360984bbfdde0755ae'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def render(value):
    return json.dumps(value, sort_keys=True, indent=2)+'\n'


def tree(path):
    result = {}
    for child in sorted(path.rglob('*')):
        need(not child.is_symlink(), 'symlink in compiler snapshot')
        if child.is_file() and child != path/'SOURCE-FREEZE.json':
            raw = child.read_bytes()
            result[str(child.relative_to(path))] = dict(bytes=len(raw), sha256=sha(raw))
    return result


def authentic(snapshot, digest):
    raw = (snapshot/'SOURCE-FREEZE.json').read_bytes()
    need(sha(raw) == digest, 'source freeze identity changed')
    frozen = json.loads(raw)
    need(tree(snapshot) == frozen['manifest'], 'compiler/input snapshot changed')
    return frozen



def extract_context(destination):
    need(not destination.exists(), 'fresh pre-source context directory required')
    raw = gzip.decompress(base64.b64decode(b''.join((HERE/'pre-source-context.json.gz.b64').read_bytes().split()),validate=True))
    records = json.loads(raw)
    expected_names = {'hash-intake/PRE-MODEL-FREEZE.json'} | {
        'hash-preparation/'+name for name in ['oracle.py','cases.json','controls.json','input.bin','expected.bin',
        'PRE-RUST-FREEZE.json','composition-input.bin','composition-expected.bin','composition-cases.json','COMPOSITION-FREEZE.json']}
    need(set(records)==expected_names,'pre-source context file set changed')
    for name,encoded in records.items():
        relative = Path(name)
        need(not relative.is_absolute() and '..' not in relative.parts, 'pre-source context path escaped')
        path = destination/relative
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(base64.b64decode(encoded,validate=True))
    data = destination/'hash-preparation'
    for name,digest in [('PRE-RUST-FREEZE.json',HASH_FREEZE),('COMPOSITION-FREEZE.json',COMPOSITION_FREEZE)]:
        raw = (data/name).read_bytes()
        need(sha(raw)==digest,'pre-source freeze identity changed')
        for filename,record in json.loads(raw)['files'].items():
            payload = (data/filename).read_bytes()
            need(dict(bytes=len(payload),sha256=sha(payload))==record,'pre-source payload identity changed')
    need(sha((destination/'hash-intake/PRE-MODEL-FREEZE.json').read_bytes())=='07719944d888e2820c856c79e6ef91de8de5b8eb3b20df81187518f83788de8f','native pre-model freeze changed')
    return destination

def variants(source):
    changes = {
        'swapped-seeds': [('let [k0, k1] = seeds;', 'let [k1, k0] = seeds;', 1)],
        'big-endian-words': [('u64::from_le_bytes', 'u64::from_be_bytes', 2)],
        'big-endian-tail': [('u32::from_le_bytes', 'u32::from_be_bytes', 1)],
        'missing-tail': [('tail | (20u64 << 56)', '(20u64 << 56)', 1)],
        'length21': [('20u64 << 56', '21u64 << 56', 1)],
        'missing-length-byte': [('tail | (20u64 << 56)', 'tail', 1)],
        'second-word-zero': [('[first, second, final_block]', '[first, 0, final_block]', 1)],
        'spurious-length-prefix': [('[first, second, final_block]', '[20u64, first, second, final_block]', 1)],
        'two-compression-rounds': [('sip_round(state);', 'sip_round(state);\n    sip_round(state);', 1)],
        'saturating-add': [('.wrapping_add(', '.saturating_add(', 4)],
        'final-marker-fe': [('state[1] ^= 0xff;', 'state[1] ^= 0xfe;', 1)],
        'two-final-rounds': [('for _ in 0..3 {', 'for _ in 0..2 {', 1)],
        'truncate32': [('state[0] ^ state[1] ^ state[2] ^ state[3]', '(state[0] ^ state[1] ^ state[2] ^ state[3]) as u32 as u64', 1)],
    }
    result = {}
    for name, replacements in changes.items():
        changed = source
        for old, new, count in replacements:
            need(changed.count(old) == count, 'operative source anchor '+name)
            changed = changed.replace(old, new)
        result[name] = changed
    return result


def prepare(snapshot):
    need(not snapshot.exists(), 'fresh compiler snapshot required')
    context = extract_context(snapshot/'context')
    data = context/'hash-preparation'
    component_source = ROOT/'src/node94-margin-risk'
    paths = [path for path in sorted(component_source.rglob('*'))
             if path.is_file() and path.relative_to(component_source).parts[0] != 'target']
    for path in paths:
        need(not path.is_symlink(), 'live compiler source symlink')
        target = snapshot/'repo'/path.relative_to(ROOT)
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(path.read_bytes())
    literal = ROOT/'research/work-items/RE-007-margin-path-94/boundaries.tsv'
    target = snapshot/'repo'/literal.relative_to(ROOT)
    target.parent.mkdir(parents=True,exist_ok=True)
    target.write_bytes(literal.read_bytes())
    component = snapshot/'repo/src/node94-margin-risk'
    source = (component/'src/hash20.rs').read_text()
    (snapshot/'drivers').mkdir()
    for name in ['hash_driver.rs','composition_driver.rs']:
        (snapshot/'drivers'/name).write_bytes((HERE/name).read_bytes())
    shutil.copytree(data,snapshot/'data')
    (snapshot/'data/native-freeze.json').write_bytes((context/'hash-intake/PRE-MODEL-FREEZE.json').read_bytes())
    (snapshot/'mutants').mkdir()
    controls = json.loads((data/'controls.json').read_text())
    for control in controls:
        name = control['name']
        directory = snapshot/'mutants'/name
        directory.mkdir()
        (directory/'hash20.rs').write_text(variants(source)[name])
        witness = control['witness']
        payload = b'K20IN001'+struct.pack('<I',1)+(data/'input.bin').read_bytes()[12+40*witness:52+40*witness]
        golden = b'K20OUT01'+struct.pack('<IIQ',1,witness,control['wrong_hash'])
        (directory/'input.bin').write_bytes(payload)
        (directory/'wrong-expected.bin').write_bytes(golden)
    (snapshot/'verify.py').write_bytes(Path(__file__).read_bytes())
    for path in paths:
        need(path.read_bytes()==(snapshot/'repo'/path.relative_to(ROOT)).read_bytes(), 'live compiler input changed')
    frozen = dict(status='current integrated component/compiler inputs frozen before compilation',
                  credited_selector_component_commit=PIN,input_freeze_sha256=HASH_FREEZE,
                  composition_freeze_sha256=COMPOSITION_FREEZE,hash_cases=990,composition_cases=1980,
                  compiled_outcomes='not run',whole_lookup_admitted_vectors=0,manifest=tree(snapshot))
    (snapshot/'SOURCE-FREEZE.json').write_text(render(frozen))
    return sha((snapshot/'SOURCE-FREEZE.json').read_bytes())


def build(snapshot, digest, out, rustc):
    frozen = authentic(snapshot,digest)
    need(not out.exists(), 'fresh build outputs required')
    out.mkdir(parents=True)
    rustc = rustc.resolve()
    cargo, rustdoc = rustc.with_name('cargo'), rustc.with_name('rustdoc')
    version = subprocess.check_output([rustc,'-vV'],text=True)
    need(version.startswith('rustc 1.94.1 '), 'wrong compiler')
    tool_hashes = {str(path):sha(path.read_bytes()) for path in [rustc,cargo,rustdoc]}
    logs = []
    def run(label,argv,payload=None,expected_exit=0,env=None):
        result = subprocess.run(list(map(str,argv)),input=payload,capture_output=True,env=env,timeout=120)
        for channel in ['stdout','stderr']:
            (out/(label+'.'+channel)).write_bytes(getattr(result,channel))
        logs.append(dict(label=label,argv=list(map(str,argv)),exit_code=result.returncode,
                         stdin_sha256=None if payload is None else sha(payload),
                         stdout_sha256=sha(result.stdout),stderr_sha256=sha(result.stderr),
                         explicit_environment={} if env is None else {k:env[k] for k in ['RUSTC','RUSTDOC','CARGO_HOME','CARGO_TARGET_DIR','CARGO_BUILD_JOBS','RUST_TEST_THREADS']}))
        (out/'commands.json').write_text(render(logs))
        need(result.returncode==expected_exit,'command failed '+label)
        return result.stdout
    component = snapshot/'repo/src/node94-margin-risk'
    profiles = []
    for opt in [0,3]:
        for repeat in [0,1]:
            authentic(snapshot,digest)
            prefix = f'o{opt}-r{repeat}'
            lib = out/('libnode94_margin_risk-'+prefix+'.rlib')
            flags = ['--edition=2024','-D','warnings','-C',f'opt-level={opt}','-C','overflow-checks=yes']
            run(prefix+'-library',[rustc,'--crate-name','node94_margin_risk','--crate-type=rlib',component/'src/lib.rs','-o',lib,*flags])
            record = dict(profile=prefix,library_sha256=sha(lib.read_bytes()))
            for kind,input_name,expected_name in [('hash','input.bin','expected.bin'),('composition','composition-input.bin','composition-expected.bin')]:
                driver = out/(prefix+'-'+kind)
                run(prefix+'-'+kind+'-build',[rustc,snapshot/'drivers'/(kind+'_driver.rs'),'--extern','node94_margin_risk='+str(lib),'-o',driver,*flags])
                authentic(snapshot,digest)
                actual = run(prefix+'-'+kind+'-run',[driver],(snapshot/'data'/input_name).read_bytes())
                need(actual==(snapshot/'data'/expected_name).read_bytes(),'compiled '+kind+' value mismatch')
                record[kind] = dict(cases=990 if kind=='hash' else 1980,driver_sha256=sha(driver.read_bytes()),output_sha256=sha(actual),mismatches=0)
            profiles.append(record)
        env = os.environ.copy()
        env.update(RUSTC=str(rustc),RUSTDOC=str(rustdoc),CARGO_HOME=str(out/'cargo-home'),CARGO_TARGET_DIR=str(out/f'cargo-o{opt}'),CARGO_BUILD_JOBS='2',RUST_TEST_THREADS='2')
        command = [cargo,'test','--offline','--locked','--manifest-path',component/'Cargo.toml']
        if opt==3:command.append('--release')
        run(f'o{opt}-component-tests',command,env=env)
    mutant_results = []
    for control in json.loads((snapshot/'data/controls.json').read_text()):
        authentic(snapshot,digest)
        name = control['name']
        path = out/('mutant-'+name)
        shutil.copytree(component,path)
        (path/'src/hash20.rs').write_bytes((snapshot/'mutants'/name/'hash20.rs').read_bytes())
        fixed = tree(path)
        lib,driver = out/('lib-mutant-'+name+'.rlib'),out/('mutant-'+name+'-hash')
        run(name+'-library',[rustc,'--edition=2024','--crate-name','node94_margin_risk','--crate-type=rlib',path/'src/lib.rs','-C','opt-level=3','-C','overflow-checks=yes','-o',lib])
        run(name+'-driver-build',[rustc,'--edition=2024',snapshot/'drivers/hash_driver.rs','--extern','node94_margin_risk='+str(lib),'-o',driver])
        authentic(snapshot,digest)
        actual = run(name+'-driver-run',[driver],(snapshot/'mutants'/name/'input.bin').read_bytes())
        need(actual==(snapshot/'mutants'/name/'wrong-expected.bin').read_bytes(),'compiled mutant disagrees with pre-source wrong-math witness '+name)
        need(tree(path)==fixed,'mutant source changed')
        mutant_results.append(dict(name=name,witness=control['witness'],witness_name=control['witness_name'],wrong_hash=control['wrong_hash'],actual_sha256=sha(actual),source_manifest=fixed,normal_value_distinction=True))
    source = (snapshot/'drivers/composition_driver.rs').read_text()
    anchor = 'select_row_after_hash(1, hash, controls'
    need(source.count(anchor)==1,'composition wiring anchor')
    wrong = out/'composition-wrong-hash.rs'
    wrong.write_text(source.replace(anchor,'select_row_after_hash(1, hash ^ 1, controls'))
    driver = out/'composition-wrong-hash'
    lib = out/'libnode94_margin_risk-o3-r1.rlib'
    run('composition-wiring-build',[rustc,'--edition=2024','--crate-name','composition_wiring_driver',wrong,'--extern','node94_margin_risk='+str(lib),'-o',driver])
    # Pre-driver frozen witness4: emit real H while only corrupting selector input.
    raw = (snapshot/'data/composition-input.bin').read_bytes()
    payload = b'K20CMP01'+struct.pack('<I',1)+raw[12+4*720:12+5*720]
    actual = run('composition-wiring-run',[driver],payload)
    golden = (snapshot/'data/composition-expected.bin').read_bytes()[12+4*22:12+5*22]
    need(len(actual)==34 and actual[12:24]==golden[:12] and actual[24]==0 and golden[12]==1
         and actual[25]==golden[13] and actual[26:34]==bytes([255])*8,
         'composition wiring control lacks normal marker distinction')
    framing = {'hash-bad-magic':b'BADIN001'+(snapshot/'data/input.bin').read_bytes()[8:],
               'hash-truncated':(snapshot/'data/input.bin').read_bytes()[:-1],
               'hash-trailing':(snapshot/'data/input.bin').read_bytes()+b'\0'}
    for name,payload in framing.items():
        need(not run(name,[out/'o3-r1-hash'],payload,expected_exit=2),'malformed input wrote stdout')
    authentic(snapshot,digest)
    need(all(sha(Path(path).read_bytes())==value for path,value in tool_hashes.items()),'tool executable changed')
    result = dict(status='observed authored-Rust hash/composition comparisons; synthetic seed/table premises',source_freeze_sha256=digest,frozen=frozen,compiler_version=version,tool_hashes=tool_hashes,profiles=profiles,source_mutants=mutant_results,composition_wiring_control=dict(normal_result_changed=True,actual_sha256=sha(actual)),driver_framing_controls=list(framing),commands=logs,whole_lookup_admitted_vectors=0,captured_execution=False)
    (out/'REPORT.json').write_text(render(result))
    print(render(dict(profiles=len(profiles),hash_cases=990,composition_cases=1980,hash_source_mutants=len(mutant_results),composition_wiring_controls=1,framing_controls=len(framing),report_sha256=sha((out/'REPORT.json').read_bytes()))))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot',type=Path,required=True)
    parser.add_argument('--prepare',action='store_true')
    parser.add_argument('--freeze-sha256')
    parser.add_argument('--out',type=Path)
    parser.add_argument('--rustc',type=Path)
    args=parser.parse_args()
    if args.prepare:
        print(prepare(args.snapshot.resolve()))
    else:
        need(args.freeze_sha256 and args.out and args.rustc,'build arguments missing')
        build(args.snapshot.resolve(),args.freeze_sha256,args.out.resolve(),args.rustc)
