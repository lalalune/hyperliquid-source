"""Compile owned Rust and compare input-only clients with frozen native outputs."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import native

def run(command, log, **kwargs):
    result = subprocess.run([str(x) for x in command], capture_output=True, **kwargs)
    log.write_bytes(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(f'{command[0]} exited {result.returncode}; see {log}')
    return result.stdout

def build(rustc, output):
    inputs, expected = native.verify()
    output.mkdir(parents=True, exist_ok=False)
    (output/'inputs.tsv').write_bytes(inputs)
    (output/'expected.tsv').write_bytes(expected)
    source = native.ROOT/'src/node115-gossip-reload'
    original = (source/'lib.rs').read_text()
    compiler = run([rustc, '-vV'], output/'compiler.txt').decode()
    if not compiler.startswith('rustc 1.94.1 '):
        raise ValueError('research compiler must be 1.94.1')
    variants = [('original', original),
                ('first-unsigned', original.replace('v[0] as i32', 'v[0]')),
                ('second-signed', original.replace('v[1], v[2]', 'v[1] as i32, v[2]')),
                ('equal-admitted', original.replace('normalize(new) > normalize(cached)', 'normalize(new) >= normalize(cached)'))]
    results = []
    for name, text in variants:
        if name != 'original' and text == original:
            raise ValueError('mutation anchor missing')
        text = text.replace('../../research/work-items/RE-014-gossip-reload-115/target-smoke.tsv', str(native.PACKET/'target-smoke.tsv'))
        candidate = output/(name+'.rs')
        candidate.write_text(text)
        for opt in (['0', '3'] if name == 'original' else ['3']):
            stem = name+'-o'+opt
            rlib = output/('lib'+stem+'.rlib')
            flags = ['--edition=2021', '-D', 'warnings', '-C', 'opt-level='+opt]
            run([rustc, *flags, '--crate-name', 'node115_gossip_reload', '--crate-type', 'rlib', candidate, '-o', rlib], output/(stem+'-library.log'))
            executable = output/(stem+'-client')
            run([rustc, *flags, source/'input_only_driver.rs', '--extern', 'node115_gossip_reload='+str(rlib), '-o', executable], output/(stem+'-client-build.log'))
            actual = run([executable], output/(stem+'-actual.tsv'), input=inputs)
            if len(actual.splitlines()) != len(expected.splitlines()):
                raise ValueError('comparison denominator changed')
            mismatches = sum(a != b for a,b in zip(actual.splitlines(),expected.splitlines()))
            if (name == 'original') != (mismatches == 0):
                raise ValueError('compiled comparison or corruption control failed')
            test = output/(stem+'-test')
            run([rustc, *flags, '--test', candidate, '-o', test], output/(stem+'-test-build.log'))
            smoke = subprocess.run([str(test)], capture_output=True)
            (output/(stem+'-test.log')).write_bytes(smoke.stdout+smoke.stderr)
            if (name == 'original' and smoke.returncode != 0) or (name != 'original' and (smoke.returncode != 101 or b'assertion `left == right` failed' not in smoke.stdout)):
                raise ValueError('unexpected smoke outcome')
            if name == 'original' and opt == '3':
                repeat = run([executable], output/'own-rlib-repeat.tsv', input=inputs)
                if repeat != actual:
                    raise ValueError('own rlib repeat differs')
            results.append({'variant':name,'opt':opt,'rows':len(expected.splitlines()),'mismatches':mismatches,'smoke_exit':smoke.returncode,'actual_sha256':hashlib.sha256(actual).hexdigest()})
    report = {'target_sha256':native.SHA,'pre_rust_freeze_commit':'cfa74eaf','source_sha256':hashlib.sha256((source/'lib.rs').read_bytes()).hexdigest(),'driver_sha256':hashlib.sha256((source/'input_only_driver.rs').read_bytes()).hexdigest(),'compiler':compiler,'runs':results,'captured_process_executed':False,'whole_function_or_machine_byte_equivalence':False}
    (output/'results.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))

if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--rustc',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();build(a.rustc.resolve(),a.output.resolve())
