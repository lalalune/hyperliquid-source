#!/usr/bin/env python3
"""Offline target, frozen oracle and retained native qualification replay."""
import base64
import gzip
import hashlib
import importlib.util
import json
import lzma
import os
from pathlib import Path
import re
import stat
import sys
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
sys.path.insert(0,str(ROOT/'tools'))
import tc_parallel_abort115 as p


def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


def verify_manifest(root, packet):
    """Closed task inventory; paths must stay ordinary throughout this check."""
    root, packet = Path(root), Path(packet)
    if not root.is_absolute() or not packet.is_relative_to(root):
        raise ValueError('manifest root/packet coordinate mismatch')
    external = {'tools/tc_parallel_abort115.py', 'tests/test_tc_parallel_abort115.py'}
    prefix = packet.relative_to(root).as_posix() + '/'

    def ordinary(path, directory=False):
        current = path
        while current != root:
            if not current.is_relative_to(root):
                raise ValueError('manifest path outside root')
            mode = current.lstat().st_mode
            if stat.S_ISLNK(mode):
                raise ValueError('manifest symlink: ' + str(current))
            want_dir = current != path or directory
            if not (stat.S_ISDIR(mode) if want_dir else stat.S_ISREG(mode)):
                raise ValueError('manifest nonordinary path: ' + str(current))
            current = current.parent
        if not stat.S_ISDIR(root.lstat().st_mode):
            raise ValueError('manifest root is not an ordinary directory')

    ordinary(packet, directory=True)
    manifest = packet / 'MANIFEST.sha256'
    ordinary(manifest)
    records = {}
    for line in manifest.read_text().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        if not match:
            raise ValueError('malformed manifest row')
        wanted, name = match.groups()
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts or relative.as_posix() != name:
            raise ValueError('noncanonical manifest path')
        if name in records:
            raise ValueError('duplicate manifest path')
        if name not in external and not name.startswith(prefix):
            raise ValueError('manifest path outside task inventory')
        if root / name == manifest:
            raise ValueError('manifest cannot hash itself')
        ordinary(root / name)
        if p.digest((root / name).read_bytes()) != wanted:
            raise ValueError('manifest mismatch: ' + name)
        records[name] = wanted
    if not external <= records.keys():
        raise ValueError('manifest omits task tool/test')
    expected_files = {root / name for name in records if name.startswith(prefix)} | {manifest}
    expected_dirs = {packet}
    for path in expected_files:
        parent = path.parent
        while parent != packet:
            expected_dirs.add(parent)
            parent = parent.parent
    actual_files, actual_dirs = set(), {packet}

    def walk_error(error):
        raise error

    for directory, dirs, files in os.walk(packet, followlinks=False, onerror=walk_error):
        for name in dirs:
            path = Path(directory) / name
            ordinary(path, directory=True)
            actual_dirs.add(path)
        for name in files:
            path = Path(directory) / name
            ordinary(path)
            actual_files.add(path)
    if actual_files != expected_files or actual_dirs != expected_dirs:
        raise ValueError('manifest inventory differs: unlisted file or directory')
    return len(records)


def archive_rows(rows):
    table={}
    for name,item in rows.items():
        raw=base64.b64decode(item['base64'],validate=True)
        if len(raw)!=item['bytes'] or p.digest(raw)!=item['sha256']:
            raise ValueError('archive stream corruption')
        table[name]=raw
    return table


def native_replay():
    freeze=json.loads((HERE/'freeze.json').read_text())
    for name in ('oracle.py','inputs.tsv.gz','expected.tsv.gz'):
        if p.digest((HERE/name).read_bytes())!=freeze['files'][name]['sha256']:
            raise ValueError('pre-Rust freeze changed')
    if p.digest((HERE/'validation/preliminary-static/bindings.json.gz').read_bytes())!=freeze['files']['bindings.json.gz']['sha256']:
        raise ValueError('preliminary binding not preserved')
    oracle=module('tc115_oracle_replay',HERE/'oracle.py')
    inputs,expected=oracle.generate()
    if inputs!=gzip.decompress((HERE/'inputs.tsv.gz').read_bytes()) or expected!=gzip.decompress((HERE/'expected.tsv.gz').read_bytes()):
        raise ValueError('independent oracle regeneration mismatch')
    result=json.loads((HERE/'native/result.json').read_text())
    if result['status']!='PASS': raise ValueError('native qualification incomplete')
    source=(HERE/'rust/lib.rs').read_bytes();driver=(HERE/'rust/driver.rs').read_bytes()
    for key,raw in [('source',source),('driver',driver),('inputs',inputs),('expected',expected)]:
        if result[key+'_sha256']!=p.digest(raw): raise ValueError('qualified '+key+' drift')
    packed=(HERE/'native/raw-streams.json.xz').read_bytes();raw=lzma.decompress(packed)
    if p.digest(packed)!=result['archive']['sha256'] or p.digest(raw)!=result['archive']['raw_json_sha256']:
        raise ValueError('archive identity')
    table=archive_rows(json.loads(raw)['streams'])
    commands={c['label']:c for c in result['commands']}
    if len(commands)!=len(result['commands']) or set(table)!={n+'.'+s for n in commands for s in ('stdout','stderr')}:
        raise ValueError('command/stream inventory')
    for name,c in commands.items():
        for channel in ('stdout','stderr'):
            if p.digest(table[name+'.'+channel])!=c[channel+'_sha256']:
                raise ValueError('command stream hash')
    validator=module('tc115_native_validator',HERE/'validate_native.py')
    if len(result['normal'])!=4: raise ValueError('normal builds incomplete')
    for r in result['normal']:
        label=r['label'];check=validator.compare(table[label+'-run.stdout'],expected)
        if check['mismatches'] or any(check[k]!=r[k] for k in check): raise ValueError('positive comparison')
        if any(commands[label+s]['exit']!=0 for s in ('-lib','-client','-run')): raise ValueError('positive command failed')
        if commands[label+'-run']['stdin_sha256']!=p.digest(inputs): raise ValueError('client did not receive input-only corpus')
    for opt in (0,3):
        rows=[r for r in result['normal'] if r['label'].startswith('opt'+str(opt))]
        if len(rows)!=2 or any(rows[0][k]!=rows[1][k] for k in ('rlib_sha256','client_sha256')):
            raise ValueError('repeat artifact identities')
    if len(result['mutants'])!=len(validator.MUTANTS): raise ValueError('missing mutants')
    for r,(name,old,new) in zip(result['mutants'],validator.MUTANTS):
        label='mutant-'+name
        if source.decode().count(old)!=1 or r['source_sha256']!=p.digest(source.decode().replace(old,new).encode()):
            raise ValueError('mutant source identity')
        check=validator.compare(table[label+'-run.stdout'],expected)
        if not check['mismatches'] or any(check[k]!=r[k] for k in check): raise ValueError('mutant not observable')
        if r['label']!=label or any(commands[label+s]['exit']!=0 for s in ('-lib','-client','-run')):
            raise ValueError('mutant failed rather than returned mismatch')
    if len(result['comparator_controls'])!=4 or not all(c['rejected'] for c in result['comparator_controls']):
        raise ValueError('comparator controls incomplete')
    if len(result['parser_controls'])!=8: raise ValueError('parser controls incomplete')
    for r in result['parser_controls']:
        if commands['parser-'+r['label']]['exit']!=r['expected_exit'] or r['actual_exit']!=r['expected_exit']:
            raise ValueError('parser result')
    return dict(frozen_cases=len(inputs.splitlines()),correct_observations=4*len(inputs.splitlines()),
                compiled_mutants=len(result['mutants']),streams=len(table),
                artifact_limit='Compiler artifacts have recorded hashes; this replay does not rebuild them')


def disassembly_replay(bindings):
    records=json.loads((HERE/'static/result.json').read_text())
    packed=(HERE/'static/raw-disassembly.json.gz').read_bytes();raw=gzip.decompress(packed)
    if p.digest(packed)!=records['archive_sha256'] or p.digest(raw)!=records['archive_raw_sha256']:
        raise ValueError('disassembly archive hash')
    table=json.loads(raw)
    bodies={b['start']:b for b in bindings['bodies']+[c['body'] for c in bindings['incoming']['callers']]}
    for kind in ('gnu','llvm'):
        for address,b in bodies.items():
            rows=[]
            for line in table[kind+'-'+hex(address)+'.stdout'].splitlines():
                m=re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}(?:\s+|$))+)',line)
                if m: rows.append((int(m[1],16),bytes.fromhex(m[2]).hex()))
            merged=[];i=0
            while i<len(rows):
                if rows[i][1]=='f0' and i+1<len(rows) and rows[i+1][0]==rows[i][0]+1:
                    merged.append((rows[i][0],rows[i][1]+rows[i+1][1]));i+=2
                else: merged.append(rows[i]);i+=1
            if merged!=[(r[0],r[1]) for r in b['instructions']]: raise ValueError('native decoder boundary mismatch')
    return dict(unique_complete_bodies=len(bodies),decoded_bytes=sum(b['length'] for b in bodies.values()),
                decoded_instructions=sum(len(b['instructions']) for b in bodies.values()))


def main():
    n=verify_manifest(ROOT,HERE)
    binding=json.loads(gzip.decompress((HERE/'bindings.json.gz').read_bytes()))
    result=p.verify(p.TARGET.read_bytes(),binding)
    result.update(native_replay());result.update(disassembly_replay(binding))
    source=archive_rows(json.loads(gzip.decompress((HERE/'primary-source-files.json.gz').read_bytes())))
    for name in ('LICENSE-MIT','LICENSE-APACHE'):
        if source[name]!=(HERE/('upstream-'+name)).read_bytes(): raise ValueError('upstream notice')
    result.update(status='PASS',manifest_files=n)
    print(json.dumps(result,indent=2))


if __name__=='__main__': main()
