#!/usr/bin/env python3
"""MIT. Checked-fold static-byte and collector-effect controls; no captured execution.

This is the single focused control entrypoint. It authenticates target and source
before loading the exact reviewed collector bytes. All modified images stay in
memory; all subprocess calls in failure tests are mocks. No semantic evaluator.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
import types
from unittest import mock

PACKET = Path(__file__).resolve().parent
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
TARGET_SIZE = 105896032
COLLECT_SHA256 = 'cb58af451e70739c581a601154140d40d37da606cc69fa97bcccd1d8184a5914'
OBLIGATIONS_SHA256 = 'adefbf6528341cbb93d34e1c686bc89ef928981b69b97181dc4435fa0ccf8be9'


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


class Results:
    def __init__(self, output):
        self.output = output
        self.rows = []

    def save(self):
        write_json(self.output / 'result.json', {
            'target_sha256': TARGET_SHA256, 'collector_sha256': COLLECT_SHA256,
            'obligations_sha256': OBLIGATIONS_SHA256, 'controls': self.rows,
            'passed': sum(row['passed'] for row in self.rows), 'count': len(self.rows),
            'limits': ['Static data checks and mocked subprocesses only.',
                       'No target execution, instruction evaluation or runtime differential oracle.',
                       'Synthetic subprocess failures are collector controls, not observations of GNU failure.']})

    def check(self, label, category, fn, expected_error=None):
        error = None
        try:
            fn()
        except Exception as exc:
            error = type(exc).__name__ + ': ' + str(exc)
        passed = error is None if expected_error is None else (
            error is not None and error.startswith('ValueError: ') and expected_error in error)
        self.rows.append({'id': label, 'category': category, 'expected_error': expected_error,
                          'observed_error': error, 'passed': passed})
        self.save()
        require(passed, 'control failed; retained result: ' + label)


def run_controls(module, data, evidence, output, scratch):
    spec = module.obligations()
    image = module.Image(data)
    result = Results(output)
    result.check('baseline-inner', 'positive', lambda: module.validate_inner(data, spec))

    def evidence_identity():
        module.compare_packet(evidence, evidence)
        record = module.load_json((evidence / 'records.json').read_bytes())
        require(record['target_sha256'] == TARGET_SHA256 and record['target_bytes'] == TARGET_SIZE and
                record['obligations_sha256'] == OBLIGATIONS_SHA256 and record['bodies'] == spec['bodies'],
                'evidence identity')
        for body in spec['bodies']:
            raw = (evidence / f'native/{int(body["start"], 16):x}.objdump.txt').read_bytes()
            module.decode_export(raw, image, body, spec)

    result.check('baseline-native-evidence', 'positive', evidence_identity)

    def altered(va, replacement):
        changed = bytearray(data)
        offset = image.offset(va, len(replacement))
        changed[offset:offset + len(replacement)] = replacement
        return changed

    for control in spec['semantic_controls']:
        va = int(control['pc'], 16)
        before, replacement = bytes.fromhex(control['raw']), bytes.fromhex(control['replacement'])
        require(before == image.read(va, len(before)) and len(before) == len(replacement) and
                before != replacement, 'operative semantic preimage')
        result.check(control['id'], 'semantic-byte',
                     lambda va=va, replacement=replacement: module.validate_inner(altered(va, replacement), spec),
                     'semantic guard ' + control['id'])

    def raw_file_mutation(offset, replacement):
        changed = bytearray(data)
        require(0 <= offset and offset + len(replacement) <= len(changed), 'control file extent')
        changed[offset:offset + len(replacement)] = replacement
        module.validate_inner(changed, spec)

    def changed_va(label, va, replacement, message):
        result.check(label, 'metadata-byte',
                     lambda: module.validate_inner(altered(va, replacement), spec), message)

    po, so = struct.unpack_from('<QQ', data, 32)
    pe, pn, se, sn = struct.unpack_from('<HHHH', data, 54)
    load_i = next(i for i, p in enumerate(image.ph) if p[0] == 1)
    other_i = next(i for i, p in enumerate(image.ph) if p[0] != 1)
    result.check('duplicate-PT-LOAD', 'ELF-byte',
                 lambda: raw_file_mutation(po + other_i * pe, data[po + load_i * pe:po + (load_i + 1) * pe]),
                 'nonunique or missing PT_LOAD/section mapping')
    text = image.section('.text')
    duplicate_section = list(text)
    duplicate_section[0] = image.sh[0][0]
    result.check('duplicate-allocated-section', 'ELF-byte',
                 lambda: raw_file_mutation(so, struct.pack('<IIQQQQIIQQ', *duplicate_section)),
                 'nonunique or missing PT_LOAD/section mapping')
    result.check('wrong-program-entry-width', 'ELF-byte',
                 lambda: raw_file_mutation(54, struct.pack('<H', 55)), 'ELF header sizes')
    result.check('section-table-out-of-file', 'ELF-byte',
                 lambda: raw_file_mutation(40, struct.pack('<Q', len(data))), 'ELF tables')
    body = spec['bodies'][0]
    fva, cva = int(body['fde_va'], 16), int(body['cie_va'], 16)
    changed_va('FDE-range-byte', fva + 12, bytes([image.read(fva + 12, 1)[0] ^ 1]), 'full FDE raw bytes')
    changed_va('FDE-CIE-backlink', fva + 4, bytes([image.read(fva + 4, 1)[0] ^ 1]), 'full FDE raw bytes')
    changed_va('CIE-encoding-byte', cva + 16, bytes([image.read(cva + 16, 1)[0] ^ 1]), 'full CIE raw bytes')
    h = image.section('.eh_frame_hdr')
    index = module.Image(data).frame_index()
    entry_i = list(index).index(int(body['start'], 16))
    changed_va('FDE-header-entry-target', h[3] + 12 + entry_i * 8 + 4,
               struct.pack('<i', fva + 1 - h[3]), 'selected header raw bytes')
    relatives = {int(r['slot'], 16): r for r in spec['relative_bindings']}
    panic, location_rela = relatives[0x64df830], relatives[0x646ebd8]
    changed_va('panic-slot-addend', int(panic['record_va'], 16) + 16,
               struct.pack('<q', panic['addend'] + 1), 'RELATIVE record/overlap 0x64df830')
    changed_va('Location-slot-symbol', int(location_rela['record_va'], 16) + 8,
               struct.pack('<Q', (1 << 32) | 8), 'RELATIVE record/overlap 0x646ebd8')
    import_slots = {int(entry['slot'], 16) for entry in spec['imports']}
    first_rela = int(next(r for r in image.relocations(spec)
                         if int(r['slot'], 16) not in relatives and int(r['slot'], 16) not in import_slots)['record_va'], 16)
    for slot in sorted(set(relatives) | import_slots):
        message = f'RELATIVE record/overlap {slot:#x}' if slot in relatives else 'import relocation'
        changed_va(f'partial-slot-overlap-{slot:x}', first_rela, struct.pack('<Q', slot + 1), message)
    changed_va('relocation-overlays-code', first_rela, struct.pack('<Q', int(body['start'], 16)),
               'relocation overlays selected code')
    changed_va('relocation-overlays-CFI', first_rela, struct.pack('<Q', fva),
               'relocation overlays selected CFI')
    changed_va('relocation-overlays-CIE', first_rela, struct.pack('<Q', cva),
               'relocation overlays selected CFI')
    changed_va('relocation-overlays-header', first_rela,
               struct.pack('<Q', int(spec['frame_header_pins'][1]['address'], 16)),
               'relocation overlays selected header')
    imported = spec['imports'][0]
    sym = int(imported['symbol_va'], 16)
    name = int(imported['name_va'], 16)
    for label, va in [('symbol', sym), ('name', name)]:
        changed_va('relocation-overlays-import-' + label, first_rela, struct.pack('<Q', va + 1),
                   'relocation overlays import metadata')
    changed_va('relocation-overlays-path', first_rela, struct.pack('<Q', 0x43a957),
               'unbound data relocation')
    changed_va('dynsym-name-offset', sym, bytes([image.read(sym, 1)[0] ^ 1]), 'import symbol bytes')
    changed_va('import-relocation-kind', int(imported['relocation']['record_va'], 16) + 8,
               struct.pack('<Q', (imported['symbol_index'] << 32) | 7), 'import relocation')
    changed_va('import-name-byte', name, b'n', 'import name bytes')
    changed_va('import-name-terminator', name + 6, b'x', 'import name bytes')
    location = spec['source_locations'][0]
    loc, path = int(location['address'], 16), int(location['path_address'], 16)
    changed_va('Location-pointer', int(relatives[loc]['record_va'], 16) + 16,
               struct.pack('<q', path + 1), f'RELATIVE record/overlap {loc:#x}')
    changed_va('Location-path-byte', path, bytes([image.read(path, 1)[0] ^ 1]), f'data anchor {path:#x}')
    changed_va('Location-line-byte', loc + 16, bytes([image.read(loc + 16, 1)[0] ^ 1]), f'data anchor {loc:#x}')
    changed_va('Location-column-byte', loc + 20, bytes([image.read(loc + 20, 1)[0] ^ 1]), f'data anchor {loc:#x}')

    rela_section = image.section('.rela.dyn')
    rela_section_i = image.sh.index(rela_section)
    name_section = image.sh[struct.unpack_from('<H', data, 62)[0]]
    result.check('missing-RELA-section', 'ELF-byte',
                 lambda: raw_file_mutation(name_section[4] + rela_section[0], b'!'),
                 'missing section .rela.dyn')
    result.check('truncated-RELA-section', 'ELF-byte',
                 lambda: raw_file_mutation(so + rela_section_i * se + 32,
                                           struct.pack('<Q', rela_section[5] - 1)),
                 'RELA shape/count')

    def invalid_scope():
        wrong = dict(spec, bodies=spec['bodies'][:-1])
        module.validate_inner(data, wrong)

    result.check('missing-body-scope', 'obligation-structure', invalid_scope, 'exact three-body scope')
    result.check('duplicate-row-obligation', 'obligation-structure',
                 lambda: module.validate_inner(data, dict(spec, row_guards=spec['row_guards'] + [spec['row_guards'][0]])),
                 'instruction obligation count/uniqueness')

    def duplicate_control():
        entries = [dict(c) for c in spec['semantic_controls']]
        entries[1]['id'] = entries[0]['id']
        module.validate_inner(data, dict(spec, semantic_controls=entries))

    result.check('duplicate-control-ID', 'obligation-structure', duplicate_control,
                 'semantic control uniqueness')

    def outside_row():
        changed = [list(r) for r in spec['row_guards']]
        end = int(spec['bodies'][-1]['end'], 16)
        changed[-1] = [hex(end), image.read(end, 1).hex(), 'outside-selected-body']
        module.validate_inner(data, dict(spec, row_guards=changed))

    result.check('outside-row-obligation', 'obligation-structure', outside_row,
                 'obligation full-body partition')

    def admission_case(label, wrong):
        candidate_output = output / ('rejected-' + label)
        with mock.patch.object(module, 'select_tool') as select, mock.patch.object(module.subprocess, 'run') as run:
            try:
                module.collect(wrong, candidate_output)
            finally:
                require(not select.called and not run.called and not candidate_output.exists(),
                        'identity gate allowed effects')

    wrong_hash = bytearray(data); wrong_hash[-1] ^= 1
    for label, wrong in [('short', data[:-1]), ('oversize', data + b'\0'), ('same-size', wrong_hash),
                         ('LFS-pointer', b'version https://git-lfs.github.com/spec/v1\n')]:
        result.check('outer-' + label, 'outer-admission', lambda label=label, wrong=wrong: admission_case(label, wrong),
                     'node115 identity mismatch')
    del wrong_hash, wrong
    fake_tool = scratch / 'mock-objdump'
    fake_tool.write_bytes(b'not executable content; all provider subprocesses are mocked\n')
    fake_tool.chmod(0o700)

    def captured_tool(capture_sha):
        with mock.patch.object(module, 'digest', return_value=capture_sha), \
                mock.patch.object(module.subprocess, 'run') as run:
            try:
                module.select_tool(str(fake_tool))
            finally:
                require(not run.called, 'captured tool launched')

    for index, capture_sha in enumerate(sorted(module.CAPTURE_HASHES)):
        result.check(f'captured-tool-{index}', 'tool-admission', lambda s=capture_sha: captured_tool(s),
                     'captured binary is not an objdump provider')

    def failure_retention(label):
        destination = output / ('mock-' + label)
        version = subprocess.CompletedProcess([], 0, b'GNU objdump (mock control)\n', b'')
        if label == 'exit':
            failure = subprocess.CompletedProcess([], 17, b'partial-native', b'failure-detail')
        elif label == 'stderr':
            failure = subprocess.CompletedProcess([], 0, b'partial-native', b'warning-detail')
        elif label == 'timeout':
            failure = subprocess.TimeoutExpired(['mock'], 60, output=b'partial-native', stderr=b'timeout-detail')
        else:
            failure = OSError('synthetic launch refusal')
        caught = None
        with mock.patch.object(module, 'select_tool', return_value=(fake_tool, sha(fake_tool.read_bytes()))), \
                mock.patch.object(module.subprocess, 'run', side_effect=[version, failure]) as run:
            try:
                module.collect(data, destination)
            except ValueError as exc:
                caught = str(exc)
        require(caught == 'GNU tool failure/nonempty stderr' and run.call_count == 2, 'mock failure classification')
        commands = module.load_json((destination / 'commands.json').read_bytes())
        require(len(commands) == 2 and not (destination / 'records.json').exists(), 'failed command census/status')
        command = commands[-1]
        for stream in ('stdout', 'stderr'):
            raw = (destination / command[stream + '_file']).read_bytes()
            require(sha(raw) == command[stream + '_sha256'], 'failed raw stream identity')
        if label == 'launch':
            require(command['failure'] == 'launch-error' and command['exit_code'] is None, 'launch failure status')
            diagnostic = command['launch_error_diagnostic']
            raw = (destination / diagnostic['file']).read_bytes()
            require(raw == b'synthetic launch refusal' and sha(raw) == diagnostic['sha256'], 'launch diagnostic retention')
        elif label == 'timeout':
            require(command['failure'] == 'timeout' and command['exit_code'] is None, 'timeout failure status')
            require((destination / command['stdout_file']).read_bytes() == b'partial-native' and
                    (destination / command['stderr_file']).read_bytes() == b'timeout-detail', 'timeout partial retention')
        else:
            require(command['failure'] is None and command['exit_code'] == (17 if label == 'exit' else 0), 'exit status')
            require((destination / command['stdout_file']).read_bytes() == b'partial-native', 'partial stdout retention')

    for label in ('exit', 'stderr', 'timeout', 'launch'):
        result.check('mock-provider-' + label, 'mocked-tool-effects', lambda label=label: failure_retention(label))

    first_body = spec['bodies'][0]
    native = (evidence / f'native/{int(first_body["start"], 16):x}.objdump.txt').read_bytes()
    lines = native.decode('utf-8').splitlines(keepends=True)
    positions = [i for i, line in enumerate(lines) if module.ROW.match(line)]

    def export_case(label):
        changed = list(lines)
        i, j = positions[:2]
        if label == 'missing':
            del changed[i]
        elif label == 'duplicate':
            changed.insert(i, changed[i])
        elif label == 'reordered':
            changed[i], changed[j] = changed[j], changed[i]
        elif label == 'raw-byte':
            changed[i] = changed[i].replace('55', '54', 1)
        else:
            k = next(k for k in positions if len(bytes.fromhex(module.ROW.match(lines[k])[2])) > 1)
            match = module.ROW.match(lines[k]); pc = int(match[1], 16); raw = bytes.fromhex(match[2])
            changed[k:k+1] = [f' {pc:x}:\t{raw[:1].hex()}\tcontrol\n',
                              f' {pc+1:x}:\t{raw[1:].hex(" ")}\tcontrol\n']
        module.decode_export(''.join(changed).encode(), image, first_body, spec)

    for label in ('missing', 'duplicate', 'reordered', 'raw-byte'):
        result.check('export-' + label, 'native-text-structure', lambda label=label: export_case(label),
                     'GNU/raw byte partition disagreement')
    result.check('export-width-split', 'native-text-structure', lambda: export_case('width'),
                 'GNU instruction boundary/width disagreement')
    removed_ret = b'\n'.join(line for line in native.split(b'\n') if not re.match(rb'^\s*4351881:', line))
    result.check('export-missing-terminal-ret', 'native-text-structure',
                 lambda: module.decode_export(removed_ret, image, first_body, spec), 'incomplete GNU full-body export')

    def replay_case(label):
        copied = scratch / ('replay-' + label)
        shutil.copytree(evidence, copied)
        if label == 'extra-file':
            (copied / 'unexpected').write_text('control')
        elif label == 'changed-record':
            records = module.load_json((copied / 'records.json').read_bytes())
            records['target_bytes'] += 1
            write_json(copied / 'records.json', records)
        elif label == 'version-filename':
            commands = module.load_json((copied / 'commands.json').read_bytes())
            commands[0]['stdout_file'] = '../unadmitted-version'
            write_json(copied / 'commands.json', commands)
        else:
            records = module.load_json((copied / 'records.json').read_bytes())
            records['tool_sha256'] = '0' * 64
            records['tool_version'] = 'GNU objdump (synthetic provenance control)'
            write_json(copied / 'records.json', records)
            version = (records['tool_version'] + '\n').encode()
            (copied / 'objdump-version.txt').write_bytes(version)
            commands = module.load_json((copied / 'commands.json').read_bytes())
            commands[0]['stdout_sha256'] = sha(version)
            write_json(copied / 'commands.json', commands)
            if label == 'provenance-plus-native':
                (copied / 'native/43516d0.objdump.txt').write_bytes(native.replace(b'55', b'54', 1))
        module.compare_packet(copied, evidence)

    for label, message in [('extra-file', 'generated artifact set mismatch'),
                           ('changed-record', 'native/data/CFI/RELA record mismatch'),
                           ('version-filename', 'command identity'),
                           ('provenance-plus-native', 'native artifact mismatch')]:
        result.check('replay-' + label, 'replay', lambda label=label: replay_case(label), message)
    result.check('replay-version-only', 'replay-positive', lambda: replay_case('version-only'))
    return {'count': len(result.rows), 'passed': sum(r['passed'] for r in result.rows),
            'semantic_byte_controls': sum(r['category'] == 'semantic-byte' for r in result.rows),
            'result_sha256': sha((output / 'result.json').read_bytes())}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True, help='fresh collector output to parse, never execute')
    parser.add_argument('--output', type=Path, required=True, help='fresh control result directory')
    args = parser.parse_args()
    with args.target.open('rb') as stream:
        data = stream.read(TARGET_SIZE + 1)
    require(len(data) == TARGET_SIZE and sha(data) == TARGET_SHA256, 'node115 identity mismatch')
    source, obligations = (PACKET / 'collect.py').read_bytes(), (PACKET / 'obligations.json').read_bytes()
    require(sha(source) == COLLECT_SHA256 and sha(obligations) == OBLIGATIONS_SHA256, 'collector/input source pins')
    require(not args.output.exists(), 'fresh control output required')
    args.output.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix='node115-checked-fold-controls-') as temporary:
        scratch = Path(temporary)
        for name, raw in [('collect.py', source), ('obligations.json', obligations)]:
            path = scratch / name
            path.write_bytes(raw)
            path.chmod(0o400)
        module = types.ModuleType('authenticated_checked_fold_collector')
        module.__file__ = str(scratch / 'collect.py')
        exec(compile(source, module.__file__, 'exec'), module.__dict__)
        summary = run_controls(module, data, args.evidence, args.output, scratch)
    print(json.dumps(summary, sort_keys=True))


if __name__ == '__main__':
    main()
