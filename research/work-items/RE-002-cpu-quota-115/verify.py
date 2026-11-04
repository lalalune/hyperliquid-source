#!/usr/bin/env python3
"""Replay static CPU115 evidence and retained own-program observations."""
import argparse,base64,gzip,hashlib,json,sys
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3]
PACKET=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tools'))
import cpu_quota_115_static as c
PACKET_FILES = ['CONTRACT.md', 'README.md', 'native/driver.rs', 'native/qualify.py', 'native/result.json', 'oracle/AFFINITY-FREEZE.json', 'oracle/FREEZE.json', 'oracle/affinity-vectors.json', 'oracle/vectors.json', 'peer-result.json', 'peer-review.json', 'peer-review.py', 'peer-streams.json.gz', 'preparation/build_affinity_oracle.py', 'preparation/build_oracle.py', 'raw-streams.json.gz', 'research-handoff.json', 'scope-review.json', 'sources.json', 'static/ceil_context.gnu.stderr', 'static/ceil_context.gnu.txt', 'static/ceil_context.llvm.stderr', 'static/ceil_context.llvm.txt', 'static/initializer.gnu.stderr', 'static/initializer.gnu.txt', 'static/initializer.llvm.stderr', 'static/initializer.llvm.txt', 'static/logical_getter.gnu.stderr', 'static/logical_getter.gnu.txt', 'static/logical_getter.llvm.stderr', 'static/logical_getter.llvm.txt', 'static/native-commands.json', 'static/once_adapter.gnu.stderr', 'static/once_adapter.gnu.txt', 'static/once_adapter.llvm.stderr', 'static/once_adapter.llvm.txt', 'static/records.json', 'upstream-source.json.gz', 'validation.json', 'verify.py']
DEPENDENCIES = {'tools/elf_index.py', 'tools/fde_extents.py', 'src/node115-cpu-quota/src/lib.rs', 'src/node115-cpu-quota/README.md', 'src/node115-cpu-quota/Cargo.toml', 'src/node115-cpu-quota/Cargo.lock', 'tests/test_cpu_quota_115_static.py', 'tools/cpu_quota_115_static.py'}

def verify_packet_inventory(packet, expected):
    expected=set(expected)|{'manifest.json'}
    directories={p.as_posix()for name in expected for p in Path(name).parents if p.as_posix()!='.'}
    c.require(packet.is_dir() and not packet.is_symlink(),'invalid packet directory')
    files=set();dirs=set()
    for path in packet.rglob('*'):
        c.require(not path.is_symlink(),'packet symlink')
        name=path.relative_to(packet).as_posix()
        if path.is_dir():dirs.add(name)
        else:c.require(path.is_file(),'packet non-file');files.add(name)
    c.require(files==expected and dirs==directories,'packet inventory differs')

def read_json(path):
    return json.loads(Path(path).read_bytes(), object_pairs_hook=c.unique)

def verify_manifest(root, rows, expected):
    c.require(type(rows) is dict and set(rows) == expected, 'manifest inventory differs')
    for name, item in rows.items():
        path = root / name
        c.require(not Path(name).is_absolute() and '..' not in Path(name).parts,
                  'unsafe manifest path')
        component = root
        c.require(not root.is_symlink(), 'manifest root symlink')
        for part in Path(name).parts:
            component = component / part
            c.require(not component.is_symlink(), 'manifest parent/file symlink')
        c.require(not path.is_symlink() and path.is_file(), 'missing manifest file')
        c.require(type(item) is dict and set(item) == {'bytes', 'sha256'}, 'invalid manifest row')
        raw = path.read_bytes()
        c.require(type(item['bytes']) is int and item['bytes'] == len(raw)
                  and item['sha256'] == c.digest(raw), 'manifest hash differs: ' + name)

def verify_archive(path):
    archive = json.loads(gzip.decompress(Path(path).read_bytes()), object_pairs_hook=c.unique)
    c.require(archive['schema'] == 1 and type(archive['streams']) is list, 'invalid archive')
    labels = set()
    total = 0
    for row in archive['streams']:
        c.require(row['label'] not in labels, 'duplicate archived stream')
        labels.add(row['label'])
        raw = base64.b64decode(row['base64'], validate=True)
        c.require(type(row['bytes']) is int and len(raw) == row['bytes']
                  and c.digest(raw) == row['sha256'], 'archived stream differs')
        total += len(raw)
    return {'streams': len(labels), 'raw_bytes': total}

def verify_native(report, directory):
    commands = read_json(directory / 'native-commands.json')
    expected = {(name, provider) for name in c.RANGES for provider in ('gnu', 'llvm')}
    c.require({(r['name'], r['provider']) for r in commands} == expected
              and len(commands) == len(expected), 'native command inventory differs')
    for row in commands:
        name, provider = row['name'], row['provider']
        raw = (directory / f'{name}.{provider}.txt').read_bytes()
        c.require(c.digest(raw) == row['stdout_sha256'] and row['exit_code'] == 0,
                  'native output hash/exit differs')
        c.require(row['stderr_hex'] == '', 'unexpected retained disassembler stderr')
        rows = c.native_bytes(raw.decode(), *c.RANGES[name])
        want = [(int(i['va'], 16), bytes.fromhex(i['bytes'])) for i in report['instructions'][name]]
        c.require(rows == want and len(rows) == row['instruction_rows'], 'native instructions differ')
    return len(commands)

def read_json_gzip(path):
    return json.loads(gzip.decompress(Path(path).read_bytes()), object_pairs_hook=c.unique)

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--native-output',type=Path);args=parser.parse_args()
    verify_packet_inventory(PACKET,PACKET_FILES)
    prefix=PACKET.relative_to(ROOT).as_posix()+'/'
    verify_manifest(ROOT,read_json(PACKET/'manifest.json'),{prefix+n for n in PACKET_FILES}|DEPENDENCIES)
    report=c.analyze(c.TARGET.read_bytes());c.require(report==read_json(PACKET/'static/records.json'),'static facts differ')
    exports=verify_native(report,PACKET/'static')
    archive=verify_archive(PACKET/'raw-streams.json.gz');verify_archive(PACKET/'upstream-source.json.gz')
    streams={r['label']:base64.b64decode(r['base64'],validate=True)for r in read_json_gzip(PACKET/'raw-streams.json.gz')['streams']}
    result=read_json(PACKET/'native/result.json')
    c.require(result['source_sha256']==c.digest((ROOT/'src/node115-cpu-quota/src/lib.rs').read_bytes()),'native-qualified source changed')
    c.require(result['driver_sha256']==c.digest((PACKET/'native/driver.rs').read_bytes()),'native-qualified driver changed')
    inputs=streams['native/inputs.txt'];expected=streams['native/expected.txt']
    c.require(c.digest(inputs)==result['input_sha256'] and c.digest(expected)==result['expected_sha256'],'native fixture hash differs')
    c.require(len(inputs.splitlines())==len(expected.splitlines())==3635,'fixture count differs')
    c.require(len(result['correct_builds'])==4 and len(result['compiled_mutant_controls'])==8,'qualification inventory differs')
    for row in result['correct_builds']:
        out=streams['native/'+row['label']+'-run.stdout']
        c.require(out==expected and c.digest(out)==row['output_sha256'] and row['cases']==3635,'native output mismatch')
    want=expected.decode().splitlines()
    for row in result['compiled_mutant_controls']:
        got=streams['native/mutant-'+row['name']+'-run.stdout'].decode().splitlines()
        differences=[i for i,(a,b)in enumerate(zip(got,want))if a!=b]
        c.require(len(got)==len(want) and differences and len(differences)==row['differences'] and differences[0]==row['first_index'],'compiled control mismatch')
        c.require(c.digest(streams['native/'+row['name']+'.rs'])==row['source_sha256'],'mutant source mismatch')
    for item in read_json(PACKET/'sources.json')['pinned_files']:
        source=next(r for r in read_json_gzip(PACKET/'upstream-source.json.gz')['streams']if r['label']==item['path'])
        c.require((source['bytes'],source['sha256'])==(item['bytes'],item['sha256']),'upstream source mismatch')
    verify_archive(PACKET/'peer-streams.json.gz')
    peer=read_json(PACKET/'peer-result.json');review=read_json(PACKET/'peer-review.json')
    c.require(peer['target_sha256']==c.SHA256 and peer['body_bytes']==6915 and peer['independent_value_mismatches']==0,'peer record differs')
    c.require(peer['reviewed_source_sha256']==result['source_sha256'] and peer['contract_sha256']==c.digest((PACKET/'CONTRACT.md').read_bytes()),'peer reviewed material changed')
    c.require(review['publication']['portable_script_sha256']==c.digest((PACKET/'peer-review.py').read_bytes()),'portable peer script changed')
    pstreams={r['label']:base64.b64decode(r['base64'],validate=True)for r in read_json_gzip(PACKET/'peer-streams.json.gz')['streams']}
    for name,span in c.RANGES.items():
        rows=c.native_bytes(pstreams[name+'.gnu.stdout'].decode(),*span)
        want=[(int(i['va'],16),bytes.fromhex(i['bytes']))for i in report['instructions'][name]]
        c.require(rows==want,'independent peer bytes differ')
    if args.native_output:
        c.require(not args.native_output.resolve().is_relative_to(PACKET),'output inside packet')
        fresh=c.export(c.TARGET,args.native_output);c.require(fresh==report,'fresh static facts differ');verify_native(fresh,args.native_output)
        for f in args.native_output.iterdir():c.require(f.read_bytes()==(PACKET/'static'/f.name).read_bytes(),'fresh export differs')
    print(json.dumps(dict(status='pass',fdes=4,static_bytes=6915,primary_bytes=6796,native_exports=exports,own_native_observations=14540,compiled_controls=8,archive=archive,captured_execution=False,whole_initializer_equivalence=False)))

if __name__=='__main__':main()
