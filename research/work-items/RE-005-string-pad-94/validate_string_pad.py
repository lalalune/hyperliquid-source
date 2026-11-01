#!/usr/bin/env python3
"""Run only independently authored Rust and bounded static padding checks.

Never executes or emulates the captured program. Keep output outside source.
The supplied head must be a committed, clean current-base contribution.
"""
import argparse
import hashlib
import importlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import time

CLEAN_ENV = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'TZ': 'UTC', 'PYTHONDONTWRITEBYTECODE': '1'}
PROVIDER_SHA256 = '56969b4e39acf17cf6f60f7c94d840a06bb37feb89cc577d0dcadfed7a71fdd6'
CURRENT_BASE = '56c0ec672bd8fdcfaa80f2db700a61e6240b3663'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def need(ok, message):
    if not ok:
        raise ValueError(message)


def physical(path):
    path = Path(path)
    mode = path.lstat().st_mode
    if stat.S_ISLNK(mode):
        data = os.fsencode(os.readlink(path))
        return {'kind': 'symlink', 'mode': stat.S_IMODE(mode), 'bytes': len(data), 'sha256': sha(data),
                'resolved_path': str(path.resolve()), 'resolved_sha256': sha(path.read_bytes())}
    need(stat.S_ISREG(mode), 'Expected physical regular file: ' + str(path))
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            h.update(block)
    return {'kind': 'file', 'mode': stat.S_IMODE(mode), 'bytes': path.stat().st_size, 'sha256': h.hexdigest()}


def git(path, *args):
    return subprocess.check_output(['git', '-C', str(path), *args], env=CLEAN_ENV).decode().strip()


def compare(raw, expected, expected_rows):
    got = [json.loads(line) for line in raw.splitlines()]
    need(len(got) == len(expected), 'Changed complete row denominator')
    ids = [row['id'] for row in got]
    need(len(ids) == len(set(ids)), 'Duplicate actual row ID')
    need(ids == [row['id'] for row in expected], 'Changed ordered input IDs')
    return [index for index, (actual, wanted) in enumerate(zip(raw.splitlines(), expected_rows)) if actual != wanted]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--head', required=True)
    parser.add_argument('--core-archive', type=Path, required=True)
    parser.add_argument('--provider-audit', type=Path, default=Path('/tmp/hl-resume-20261101/toolchain/PROVIDER-AUDIT.json'))
    args = parser.parse_args()
    root, output = args.root.resolve(), args.output.resolve()
    need(git(root, 'merge-base', CURRENT_BASE, args.head) == CURRENT_BASE, 'Contribution does not descend from the admitted current base')
    need(not output.exists() and not output.is_relative_to(root), 'Preserve outputs outside checkout')
    output.mkdir(parents=True)
    provider_raw = args.provider_audit.read_bytes()
    need(sha(provider_raw) == PROVIDER_SHA256, 'Changed authenticated official provider audit')
    provider = json.loads(provider_raw)
    prefix = Path(provider['prefix'])
    rustc = prefix / 'bin/rustc'
    gcc = Path('/usr/bin/gcc').resolve()
    ld = Path('/usr/bin/ld.bfd').resolve()
    fixture = root / 'research/work-items/RE-005-string-pad-94/independent-pre-source'
    source = root / 'src/node94-string-pad/lib.rs'
    driver = source.with_name('input_only_driver.rs')
    target = root / 'artifacts/node/94/hl-node'
    pins = json.loads((root / 'provenance/sources.json').read_text())['repositories']
    need(len(pins) == 7, 'Changed pin denominator')
    calls = []
    env = dict(CLEAN_ENV, NODE94_STRING_PAD_FIXTURES=str(fixture))

    def run(label, argv, expected_exit=0):
        start = time.monotonic()
        result = subprocess.run([str(a) for a in argv], cwd=root, env=env, capture_output=True)
        row = {'label': label, 'argv': [str(a) for a in argv], 'cwd': str(root),
               'seconds': time.monotonic() - start, 'exit': result.returncode, 'streams': {}}
        for name, raw in [('stdout', result.stdout), ('stderr', result.stderr)]:
            path = output / (label + '.' + name)
            path.write_bytes(raw)
            row['streams'][name] = {'file': path.name, 'bytes': len(raw), 'sha256': sha(raw)}
        calls.append(row)
        (output / 'CALLS.json').write_text(json.dumps(calls, sort_keys=True, indent=2) + '\n')
        if expected_exit is not None:
            need(result.returncode == expected_exit, label + ': unexpected exit')
        return result

    def audit():
        repositories, inputs = [], {}
        for relative, expected in [('.', args.head)] + [(p['path'], p['commit']) for p in pins]:
            base = root / relative
            need(Path(git(base, 'rev-parse', '--show-toplevel')).resolve() == base.resolve(), 'Inherited fake repository')
            head = git(base, 'rev-parse', 'HEAD')
            status = git(base, 'status', '--porcelain', '--untracked-files=all')
            need(head == expected and not status, 'Changed head/status: ' + relative)
            repositories.append({'path': relative, 'head': head, 'tree': git(base, 'rev-parse', 'HEAD^{tree}'), 'status': status})
            rows = subprocess.check_output(['git', '-C', str(base), 'ls-files', '--stage', '-z'], env=CLEAN_ENV)
            for raw in rows.split(b'\0')[:-1]:
                metadata, name_raw = raw.split(b'\t', 1)
                mode, oid, stage = metadata.split(b' ')
                need(stage == b'0', 'Unmerged tracked input')
                name = os.fsdecode(name_raw)
                path = base / name
                if mode == b'160000':
                    need(relative == '.' and name in {p['path'] for p in pins}, 'Unexpected gitlink')
                    continue
                inputs[str(Path(relative) / name)] = physical(path)
        payloads = {}
        need(provider['payload_count'] == len(provider['payloads']) == 103, 'Changed provider payload count')
        for record in provider['payloads']:
            value = physical(prefix / record['path'])
            need(value['sha256'] == record['sha256'] and value['bytes'] == record['bytes'], 'Changed official provider payload')
            payloads[record['path']] = value
        manifests = {}
        need(set(provider['installed_manifest_sha256']) == {'manifest-rustc', 'manifest-rust-std-x86_64-unknown-linux-gnu'},
             'Changed installed component-manifest set')
        for name, digest in provider['installed_manifest_sha256'].items():
            value = physical(prefix / 'lib/rustlib' / name)
            need(value['sha256'] == digest, 'Changed actual installed component manifest')
            manifests[name] = value
        return {'repositories': repositories, 'tracked_physical_inputs': inputs, 'provider_payloads': payloads,
                'installed_component_manifests': manifests,
                'provider_audit': physical(args.provider_audit), 'linker': physical(gcc), 'ld_bfd': physical(ld),
                'target': physical(target), 'core_archive': physical(args.core_archive),
                'runner': physical(Path(__file__))}

    before = audit()
    (output / 'BEFORE.json').write_text(json.dumps(before, sort_keys=True, indent=2) + '\n')
    summary = {'status': 'FAIL', 'full_test_suite': 'NOT_RUN: expanded instruction-evaluator scope is not authorized',
               'admitted_base': CURRENT_BASE,
               'captured_execution_or_instruction_evaluator': False, 'component_gates_requested': False,
               'command_environment': env,
               'removed_injection_variable_names': sorted(k for k in os.environ if k.startswith(('LD_', 'DYLD_', 'GCC_', 'COMPILER_', 'LIBRARY_', 'RUST', 'CARGO', 'GIT_')))}
    # The imported bounded static exporter also launches native binutils.
    # Give those subprocesses the same fixed environment as direct commands.
    os.environ.clear()
    os.environ.update(env)
    try:
        need(sha((fixture / 'FREEZE.json').read_bytes()) == '00eaff92d84ae4a569aab8c1950fa991f8c271dd4445b3a02fb4f11b697d06e9', 'Changed pre-source freeze')
        inputs = (fixture / 'inputs.tsv').read_bytes()
        wanted = (fixture / 'expected.jsonl').read_bytes()
        need(sha(inputs) == 'bf40d855ffc68481fa0e1acb37043d51f4207888160176060ce68b61b3c79300', 'Changed sealed inputs')
        need(sha(wanted) == '29d8d003b50f09978f0699f8d1a2d5d598070f35470e59fd5ec10fbbff8e46df', 'Changed sealed expected rows')
        expected = [json.loads(line) for line in wanted.splitlines()]
        expected_rows = wanted.splitlines()
        tuples = [line.split(b'\t')[1:] for line in inputs.splitlines()]
        need(len(expected) == len(tuples) == 26054 and all(len(row) == 7 for row in tuples), 'Changed eight-field input denominator')
        need(len({tuple(row) for row in tuples}) == 26054, 'Duplicate complete input')
        need(sum(row['callback_count'] for row in expected) == 9915008, 'Changed callback observation denominator')
        need(sum(len(row['events']) for row in expected) == 49649, 'Changed RLE denominator')
        input_path = output / 'inputs.tsv'
        input_path.write_bytes(inputs)
        run('rustc-identity', [rustc, '-vV'])
        run('gcc-identity', [gcc, '--version'])
        run('ld-bfd-identity', [ld, '--version'])
        chosen_ld = run('gcc-selected-ld', [gcc, '-print-prog-name=ld.bfd']).stdout.decode().strip()
        chosen_ld_path = Path(chosen_ld) if Path(chosen_ld).is_absolute() else Path(shutil.which(chosen_ld, path=CLEAN_ENV['PATH']))
        need(chosen_ld_path.resolve() == ld, 'Actual gcc-selected BFD linker differs')
        sys.path.insert(0, str(root / 'tools'))
        native = importlib.import_module('string_pad_static')
        target_bytes, archive_bytes = target.read_bytes(), args.core_archive.read_bytes()
        report, exports = native.analyze(target_bytes, archive_bytes)
        native_out = output / 'native'
        native_out.mkdir()
        for name, raw in exports.items():
            (native_out / name).write_bytes(raw)
        (native_out / 'REPORT.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
        # These call the structural producer below the whole-image hash gate,
        # so the semantic/code/data/helper guards must reject each corruption.
        image = native.elf.Elf(target_bytes, 3)
        controls = [('main-option-mask', 0x1573450 + 0x1B),
                    ('main-counter-relocation', 0x1573450 + 190),
                    ('precision-advance', 0x15734C0),
                    ('count-helper-body', 0x15796C0 + 20),
                    ('classifier-data', 0x2086A0),
                    ('alignment-table', 0x251B74),
                    ('main-FDE-extent', report['functions']['main']['FDE']['fde'] + 12)]
        static_controls = []
        for label, va in controls:
            _, mapping = image.va_bytes(va, 1)
            damaged = bytearray(target_bytes)
            damaged[mapping['file_offset']] ^= 1
            try:
                native.derive(bytes(damaged), archive_bytes)
            except ValueError as error:
                static_controls.append({'label': label, 'va': hex(va), 'rejection': str(error)})
            else:
                raise ValueError('Surviving below-digest static control: ' + label)
        # Corrupt only a different RELA destination, preserving original code,
        # constants and the exact selected GOT relocation. Exact-slot lookup
        # alone would miss these competing/cross-start write intervals.
        rela_offset = next(s['offset'] for s in image.sections if s['type'] == 4 and s['size'])
        selected_offset = report['actual_loader_write_audit']['selected_slot_writers'][0]['record_file_offset']
        need(rela_offset != selected_offset, 'Independent relocation control must use a different record')
        for label, destination in [('loader-code-cross-start', 0x1573450 - 7),
                                   ('loader-data-cross-end', 0x251B74 + 15),
                                   ('loader-competing-slot-plus1', 0x5770628 + 1),
                                   ('loader-competing-slot-minus7', 0x5770628 - 7)]:
            damaged = bytearray(target_bytes)
            damaged[rela_offset:rela_offset + 8] = destination.to_bytes(8, 'little')
            try:
                native.derive(bytes(damaged), archive_bytes)
            except ValueError as error:
                static_controls.append({'label': label, 'RELA_record_file_offset': rela_offset,
                                        'destination': hex(destination), 'rejection': str(error)})
            else:
                raise ValueError('Surviving loader-overlap control: ' + label)
        (native_out / 'CONTROLS.json').write_text(json.dumps(static_controls, sort_keys=True, indent=2) + '\n')
        common = ['--edition=2021', '-C', 'debuginfo=0', '-C', 'codegen-units=1', '-C', 'linker=' + str(gcc), '-C', 'link-arg=-fuse-ld=bfd']

        def build(folder, level, libsource=source, units=False):
            folder.mkdir()
            rlib = folder / 'libnode94_string_pad.rlib'
            run(folder.name + '-library', [rustc, *common, '-C', 'opt-level=' + str(level), '--crate-name', 'node94_string_pad', '--crate-type=rlib', libsource, '-o', rlib])
            client = folder / 'input-client'
            run(folder.name + '-client-link', [rustc, *common, '-C', 'opt-level=' + str(level), driver, '--extern', 'node94_string_pad=' + str(rlib), '-o', client])
            actual = run(folder.name + '-client-run', [client, input_path])
            different = compare(actual.stdout, expected, expected_rows)
            if libsource == source:
                need(actual.stdout == wanted, 'Real source did not emit exact sealed canonical JSONL bytes')
            if units:
                test = folder / 'units'
                run(folder.name + '-unit-build', [rustc, *common, '-C', 'opt-level=' + str(level), '--test', libsource, '-o', test])
                run(folder.name + '-unit-run', [test, '--test-threads=1'])
            return {'rlib': physical(rlib), 'client': physical(client), 'different_rows': len(different),
                    'first_different_IDs': [expected[i]['id'] for i in different[:8]]}

        profiles = {}
        for label, level in [('debug', 0), ('optimized', 3)]:
            profiles[label] = build(output / label, level, units=True)
            need(profiles[label]['different_rows'] == 0, label + ': mismatched real source output')
        profiles['repro-optimized'] = build(output / 'repro-optimized', 3)
        need(profiles['repro-optimized'] == profiles['optimized'], 'Same-recipe raw artifact/output reproducibility differs')
        text = source.read_text()
        changes = [('fast-option-mask', 'flags & 0x1800_0000 == 0', 'flags & 0x0800_0000 == 0'), ('precision-wrong-bit', 'flags & (1 << 28) != 0', 'flags & (1 << 27) != 0'), ('precision-extra-scalar', 'text.chars().take(precision)', 'text.chars().take(precision.saturating_add(1))'), ('byte-count-width', '(text, count_scalars(text))', '(text, text.len())'), ('width-gated-after-precision', 'let width = ((initial >> 32) & 0xffff) as usize;', 'let width = if flags & (1 << 27) == 0 { 0 } else { ((initial >> 32) & 0xffff) as usize };'), ('default-right', '1 => padding,', '1 | 3 => padding,'), ('center-extra-before', '2 => padding / 2,', '2 => (padding + 1) / 2,'), ('fast-raw-status-normalized', 'return dispatch(ctx, tables, data, table, Operation::Str(text.as_bytes()), writer, sink);', 'return u8::from(dispatch(ctx, tables, data, table, Operation::Str(text.as_bytes()), writer, sink) != 0);'), ('selected-raw-status-normalized', 'return dispatch(ctx, tables, data, table, Operation::Str(selected.as_bytes()), writer, sink);', 'return u8::from(dispatch(ctx, tables, data, table, Operation::Str(selected.as_bytes()), writer, sink) != 0);'), ('writer-data-reloaded', 'Request { data, table, method, operation }', 'Request { data: ctx.data.get(), table, method, operation }'), ('writer-table-reloaded', 'let selected = tables.iter()', 'let table = ctx.table.get();\n    let selected = tables.iter()'), ('unwanted-header-write', 'let fill = flags & 0x1f_ffff;', 'let fill = flags & 0x1f_ffff; ctx.tailword.set(initial ^ 1);'), ('final-trailing-error-zero', 'for _ in 0..(padding - before) {\n        if dispatch(ctx, tables, data, table, Operation::Char(fill), writer, sink) != 0 {\n            return 1;', 'for _ in 0..(padding - before) {\n        if dispatch(ctx, tables, data, table, Operation::Char(fill), writer, sink) != 0 {\n            return 0;')]
        mutants = {}
        for label, old, new in changes:
            need(text.count(old) == 1, 'Ambiguous source control: ' + label)
            mutation = output / ('control-' + label + '.rs')
            mutation.write_text(text.replace(old, new))
            mutants[label] = build(output / ('mutant-' + label), 3, mutation)
            need(mutants[label]['different_rows'] > 0, 'Surviving source control: ' + label)
        comparator_controls = []
        base = (output / 'optimized-client-run.stdout').read_bytes()
        for label, damaged in [('missing-row', b'\n'.join(base.splitlines()[:-1]) + b'\n'),
                               ('extra-row', base + base.splitlines()[0] + b'\n'),
                               ('duplicate-ID', b'\n'.join([base.splitlines()[1], *base.splitlines()[1:]]) + b'\n')]:
            try:
                compare(damaged, expected, expected_rows)
            except ValueError:
                comparator_controls.append(label)
            else:
                raise ValueError('Accepted damaged comparator input: ' + label)
        changed = dict(expected[0])
        changed['raw_status'] ^= 1
        changed_raw = b'\n'.join([json.dumps(changed, sort_keys=True, separators=(',', ':')).encode(), *expected_rows[1:]]) + b'\n'
        need(compare(changed_raw, expected, expected_rows) == [0], 'Changed raw status was missed')
        comparator_controls.append('changed-raw-status')
        first_text = expected_rows[0].decode()
        for label, changed_first in [
            ('noncanonical-whitespace', first_text.replace(':', ': ', 1)),
            ('duplicate-json-key', first_text[:-1] + ',"raw_status":' + str(expected[0]['raw_status']) + '}'),
            ('boolean-instead-of-integer', first_text.replace('"raw_status":' + str(expected[0]['raw_status']), '"raw_status":false')),
        ]:
            damaged = b'\n'.join([changed_first.encode(), *expected_rows[1:]]) + b'\n'
            need(compare(damaged, expected, expected_rows) == [0], 'Accepted noncanonical row: ' + label)
            comparator_controls.append(label)
        summary.update(status='PASS', cases=26054, distinct_complete_inputs=26054, callback_observations=9915008,
                       exact_RLE_records=49649, profiles=profiles, compiled_source_controls=mutants,
                       comparator_controls=comparator_controls, below_digest_static_controls=static_controls)
    finally:
        after = audit()
        (output / 'AFTER.json').write_text(json.dumps(after, sort_keys=True, indent=2) + '\n')
        summary.update(same_inputs=before == after, tracked_physical_input_count=len(before['tracked_physical_inputs']), calls=len(calls))
        if before != after:
            summary['status'] = 'FAIL'
        (output / 'RESULT.json').write_text(json.dumps(summary, sort_keys=True, indent=2) + '\n')
    print(json.dumps(summary, sort_keys=True))
    need(summary['status'] == 'PASS', 'Validation did not pass')


if __name__ == '__main__':
    main()
