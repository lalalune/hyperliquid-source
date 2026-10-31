#!/usr/bin/env python3
"""Static stripping-inference controls. Never executes a generated or captured ELF."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[3])
    parser.add_argument('--work', type=Path, required=True, help='new owned directory; never reused')
    parser.add_argument('--cc', default='cc')
    parser.add_argument('--strip', default='strip')
    parser.add_argument('--readelf', default='readelf')
    args = parser.parse_args()
    repo, work = args.repo.resolve(), args.work.resolve()
    work.mkdir(parents=True, exist_ok=False)
    environment = dict(os.environ, TMPDIR=str(work), PYTHONDONTWRITEBYTECODE='1')
    commands = []

    def run(argv):
        result = subprocess.run(argv, cwd=work, env=environment, capture_output=True, text=True, check=True)
        commands.append({'argv': [x.replace(str(work), '<work>') for x in argv],
                         'returncode': result.returncode,
                         'stdout': result.stdout.replace(str(work), '<work>'),
                         'stderr': result.stderr.replace(str(work), '<work>')})
        return result.stdout

    tools = {name: shutil.which(getattr(args, name)) for name in ('cc', 'strip', 'readelf')}
    if not all(tools.values()):
        raise ValueError('cc, GNU strip and GNU readelf are required')
    versions = {name: run([path, '--version']).splitlines()[0] for name, path in tools.items()}
    if 'GNU' not in versions['strip'] or 'GNU' not in versions['readelf']:
        raise ValueError('this proof requires GNU strip/readelf; no substitute result is claimed')
    source = b'int main(void) { return 7; }\n'
    (work / 'fixture.c').write_bytes(source)
    run([tools['cc'], '-g', '-O0', '-fdebug-prefix-map=' + str(work) + '=/fixture',
         '-Wl,--build-id=none', 'fixture.c', '-o', 'unstripped'])
    for output, options in (
            ('debug-retained', ['--strip-all', '--keep-section=.debug*']),
            ('fully-stripped', ['--strip-all']), ('symbols-retained', ['--strip-debug'])):
        run([tools['strip'], *options, '-o', output, 'unstripped'])
    sys.path.insert(0, str(repo / 'tools'))
    spec = importlib.util.spec_from_file_location('strip_inference_provenance', repo / 'tools/build_provenance.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    cases = []
    for name in ('unstripped', 'debug-retained', 'fully-stripped', 'symbols-retained'):
        data = (work / name).read_bytes()
        exact = module.derive(data)
        section_rows = run([tools['readelf'], '-W', '-S', name])
        debug_rows = run([tools['readelf'], '--debug-dump=info', name])
        cases.append({'fixture': name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                      'exact': {x['key']: x['value'] for x in exact
                                if x['key'] in ('elf.has_symtab', 'elf.debug_sections')},
                      'stripped': [x for x in module.interpret(exact) if x['key'] == 'stripped'],
                      'readelfCompilationUnits': debug_rows.count('Compilation Unit @ offset'),
                      'sectionEvidence': [line.strip() for line in section_rows.splitlines()
                                          if '.symtab' in line or '.debug_' in line]})
    report = {'schema': 'provenance-strip-inference-control-v1',
              'targetContext': {'release': '94', 'sha256':
                                '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'},
              'toolSHA256': hashlib.sha256((repo / 'tools/build_provenance.py').read_bytes()).hexdigest(),
              'fixtureSourceSHA256': hashlib.sha256(source).hexdigest(), 'tools': versions,
              'workAlias': '<work> is the new directory supplied by --work; command cwd is <work>',
              'cases': cases, 'commands': commands,
              'limits': 'Only newly authored host C fixtures are compiled and statically read. '
                        'No fixture or captured target is executed. This is a tooling classification '
                        'proof, not Hyperliquid source recovery, build identity or behavior evidence.'}
    (work / 'observations.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n',
                                           encoding='utf-8', newline='\n')
    print(json.dumps({'cases': cases, 'report': str(work / 'observations.json')}))


if __name__ == '__main__':
    main()
