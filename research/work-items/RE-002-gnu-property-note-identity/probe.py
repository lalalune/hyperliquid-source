#!/usr/bin/env python3
"""Compile one owned metadata control, rename its note, never execute either ELF."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

BASE = '1f8c67c63ca4794c9689235471c60297f8a5c985'
BASE_HELPER_SHA = '0e5d85c97c671fabd528882566b5bcb3e8187e84f53c3fdcb45210c88df29887'
ROOT = Path(__file__).resolve().parents[3]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    work = args.work.resolve()
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    sys.path.insert(0, str(ROOT / 'tools'))
    source = subprocess.check_output(['git', '-C', str(ROOT), 'show',
                                      BASE + ':tools/build_provenance.py'])
    if sha(source) != BASE_HELPER_SHA:
        raise ValueError('Unexpected base helper identity')
    base_path = work / 'base-helper.py'
    base_path.write_bytes(source)
    old = load(base_path, 'base_note_helper')
    fixed = load(ROOT / 'tools/build_provenance.py', 'candidate_note_helper')
    versions = {}
    for tool in ('gcc', 'objcopy', 'readelf'):
        text = subprocess.check_output([tool, '--version'], text=True)
        versions[tool] = text.splitlines()[0]
        if tool != 'gcc' and not text.startswith('GNU '):
            raise ValueError('GNU binutils are required for this control')
    control = b'int main(void) { return 0; }\n'
    (work / 'fixture.c').write_bytes(control)
    commands = []

    def run(argv, export=None):
        env = {**os.environ, 'LC_ALL': 'C', 'PYTHONDONTWRITEBYTECODE': '1'}
        result = subprocess.run(argv, cwd=work, env=env, capture_output=True, check=True)
        if result.stderr:
            raise ValueError('Control emitted a warning: ' + result.stderr.decode())
        if export:
            (work / export).write_bytes(result.stdout)
        commands.append({'argv': argv, 'exitCode': result.returncode,
                         'stdoutSHA256': sha(result.stdout), 'stderr': '', 'export': export})
        return result.stdout

    # -z ibt is a fixture-only way to ensure a GNU property note is emitted.
    # It is not a hypothesis about any captured target's compiler/linker flags.
    run(['gcc', '-O0', '-Wl,--build-id=none,-z,ibt', 'fixture.c', '-o', 'original.elf'])
    run(['objcopy', '--rename-section', '.note.gnu.property=.note.provenance-control',
         'original.elf', 'renamed.elf'])
    results = {}
    notes = []
    for label in ('original', 'renamed'):
        path = work / (label + '.elf')
        path.chmod(0o600)
        data = path.read_bytes()
        native = run(['readelf', '--notes', '--program-headers', '--wide', path.name],
                     label + '.readelf.txt')
        if b'NT_GNU_PROPERTY_TYPE_0' not in native or b'GNU_PROPERTY' not in native:
            raise ValueError('Native control lacks the expected GNU property metadata')
        field = lambda module: next(f for f in module.derive(data)
                                   if f['key'] == 'elf.has_gnu_property_note')
        section_name = '.note.gnu.property' if label == 'original' else '.note.provenance-control'
        sec = next(s for s in old.sections(data) if s['name'] == section_name)
        raw = old.section_bytes(data, sec)
        if sec['type'] != 7:
            raise ValueError('Control note no longer has SHT_NOTE type')
        notes.append(raw)
        phoff = struct.unpack_from('<Q', data, 32)[0]
        width, count = struct.unpack_from('<HH', data, 54)
        program_notes = []
        for i in range(count):
            p = struct.unpack_from('<IIQQQQQQ', data, phoff + i * width)
            if p[0] in (4, 0x6474e553) and p[2] <= sec['offset'] and sec['offset'] + sec['size'] <= p[2] + p[5]:
                program_notes.append({'type': p[0], 'file_offset': p[2], 'bytes': p[5]})
        if {p['type'] for p in program_notes} != {4, 0x6474e553}:
            raise ValueError('Control lost its PT_NOTE/PT_GNU_PROPERTY mappings')
        results[label] = {'bytes': len(data), 'SHA256': sha(data), 'baseFact': field(old),
                          'fixedFact': field(fixed), 'noteSection': sec,
                          'noteSHA256': sha(raw), 'noteHex': raw.hex(),
                          'containingNoteSegments': program_notes}
    if notes[0] != notes[1] or results['original']['containingNoteSegments'] != results['renamed']['containingNoteSegments'] or \
            results['original']['baseFact']['value'] is not True or \
            results['renamed']['baseFact']['value'] is not False or \
            any(r['fixedFact']['value'] is not True for r in results.values()):
        raise ValueError('Expected before/after observation was not reproduced')
    report = {'baseCommit': BASE, 'baseHelperSHA256': sha(source),
              'fixedHelperSHA256': sha((ROOT / 'tools/build_provenance.py').read_bytes()),
              'fixtureSource': control.decode(), 'fixtureSourceSHA256': sha(control),
              'toolVersions': versions, 'commands': commands, 'results': results,
              'noteBytesUnchanged': True, 'ELFExecuted': False,
              'limits': 'Independent ordinary host-ELF metadata control. No captured target flags, '
                        'CPU features, host/runtime compatibility or reconstruction are inferred. '
                        'Fixture hashes bind this observed compiler/linker run.'}
    (work / 'RESULT.json').write_bytes((json.dumps(report, indent=2) + '\n').encode())
    print(json.dumps({'baseRenamedFact': results['renamed']['baseFact']['value'],
                      'fixedRenamedFact': results['renamed']['fixedFact']['value'],
                      'noteBytesUnchanged': True, 'ELFExecuted': False}))


if __name__ == '__main__':
    main()
