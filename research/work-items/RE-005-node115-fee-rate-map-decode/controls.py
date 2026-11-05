#!/usr/bin/env python3
"""MIT. Focused static-data controls; no captured or source program is run.

The paired collector is authenticated and compiled from that exact source buffer.
Subprocess sites are mocked in failure-path tests. Real GNU replay is a separate
explicit collector command reviewed by the caller, not invoked by this script.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import types
from unittest.mock import patch


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--collector-sha256', required=True)
    parser.add_argument('--target', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    here = Path(__file__).resolve().parent
    raw = (here / 'collect.py').read_bytes()
    require(hashlib.sha256(raw).hexdigest() == args.collector_sha256,
            'collector source identity')
    collector = types.ModuleType('fee_rate_static_checked')
    collector.__file__ = str(here / 'collect.py')
    exec(compile(raw, collector.__file__, 'exec'), collector.__dict__)
    data = collector.read_target(args.target)
    spec = collector.obligations()
    image = collector.Image(data)
    require(not args.output.exists(), 'fresh output directory required')
    args.output.mkdir(parents=True)
    results = []

    def keep():
        (args.output / 'results.json').write_text(json.dumps({
            'collector_sha256': args.collector_sha256,
            'target_sha256': collector.digest(data),
            'controls_completed': len(results), 'results': results,
            'limits': 'Static byte/metadata/format and mocked-process guards only; not decoder behavior, ISA execution, native oracle or all-input equivalence.'
        }, indent=2) + '\n')

    def accepted(name, fn):
        fn()
        results.append({'name': name, 'passed': True, 'outcome': 'accepted'})
        keep()

    def rejected(name, fn, message):
        try:
            fn()
        except ValueError as exc:
            require(message in str(exc), name + ': wrong rejection: ' + str(exc))
            results.append({'name': name, 'passed': True,
                            'outcome': 'rejected', 'reason': str(exc)})
            keep()
        else:
            raise ValueError(name + ': mutation survived')

    def changed(va, replacement):
        out = bytearray(data)
        offset = image.offset(va, len(replacement))
        out[offset:offset + len(replacement)] = replacement
        return out

    def flipped(va):
        return changed(va, bytes([image.read(va, 1)[0] ^ 1]))

    accepted('original-inner-31-full-bodies', lambda: collector.validate_inner(data))
    damaged = bytearray(data)
    damaged[-1] ^= 1
    with tempfile.TemporaryDirectory(prefix='fee-rate-controls-') as tmp:
        destination = Path(tmp) / 'must-not-exist'
        with patch.object(collector, 'select_tool') as select, \
                patch.object(collector.subprocess, 'run') as run:
            rejected('whole-target-before-output-or-tool',
                     lambda: collector.collect(damaged, destination), 'node115 identity mismatch')
            require(not select.called and not run.called and not destination.exists(),
                    'admission side effect before target check')
        with patch.object(collector.os, 'access', return_value=True), \
                patch.object(collector.subprocess, 'run') as run:
            rejected('known-captured-binary-is-not-tool',
                     lambda: collector.select_tool(str(args.target)),
                     'captured binary is not an objdump provider')
            require(not run.called, 'captured tool spawned')

    for entry in spec['semantic_controls']:
        pc = int(entry['pc'], 16)
        # Last encoded byte includes the immediate, displacement or ModRM operand
        # for these selected real rows; exact named guards must reject below SHA.
        va = pc + len(bytes.fromhex(entry['raw'])) - 1
        rejected('semantic-' + entry['id'],
                 lambda va=va: collector.validate_inner(flipped(va)),
                 'instruction ' + entry['id'] + ' at ' + hex(pc))

    for address, item in spec['data'].items():
        va = int(address, 16) + len(bytes.fromhex(item['raw'])) - 1
        rejected('data-' + item['label'],
                 lambda va=va: collector.validate_inner(flipped(va)), 'data anchor ' + address)

    body = spec['bodies'][0]
    for kind in ('fde', 'cie'):
        va = int(body[kind + '_va'], 16) + len(bytes.fromhex(body[kind + '_raw'])) - 1
        rejected('full-' + kind + '-last-byte',
                 lambda va=va: collector.validate_inner(flipped(va)),
                 'full ' + kind.upper() + ' raw bytes')
    hdr = image.section('.eh_frame_hdr')
    hb = image.read(hdr[3], hdr[5])
    for i in range(struct.unpack_from('<I', hb, 8)[0]):
        if hdr[3] + struct.unpack_from('<i', hb, 12 + 8 * i)[0] == int(body['start'], 16):
            va = hdr[3] + 16 + 8 * i
            rejected('fde-header-index-pointer',
                     lambda: collector.validate_inner(flipped(va)), 'FDE-header binding')
            break
    else:
        raise ValueError('selected FDE missing')

    relative = spec['relative_bindings'][0]
    for delta, label, why in ((8, 'type', 'unsupported RELA width/type'),
                              (12, 'symbol', 'RELATIVE record/overlap'),
                              (16, 'addend', 'RELATIVE record/overlap')):
        va = int(relative['record_va'], 16) + delta
        rejected('relative-' + label, lambda va=va: collector.validate_inner(flipped(va)), why)
    va = int(relative['record_va'], 16)
    replacement = struct.pack('<Q', int(body['start'], 16))
    rejected('relocation-overlay-code',
             lambda: collector.validate_inner(changed(va, replacement)),
             'relocation overlays selected code')

    for imported in spec['imports']:
        name = imported['name']
        for key, delta, why in (('symbol_va', 4, 'import symbol bytes'),
                               ('name_va', 0, 'import name bytes'),
                               ('slot', 0, 'import initial slot')):
            va = int(imported[key], 16) + delta
            rejected(name + '-' + key,
                     lambda va=va: collector.validate_inner(flipped(va)), why)
        va = int(imported['relocation']['record_va'], 16) + 12
        rejected(name + '-relocation-symbol',
                 lambda va=va: collector.validate_inner(flipped(va)), 'import relocation')
        if 'plt' in imported:
            va = int(imported['plt'], 16) + 2
            rejected(name + '-plt-displacement',
                     lambda va=va: collector.validate_inner(flipped(va)), 'PLT raw stub')

    # Re-guarding the changed instruction bytes must not bypass an independent
    # branch target or RIP target binding. No executable is made from these bytes.
    for name, pc, edge_key, message in (
        ('reguarded-wrapper-call', 0x27667b9, 'transfers', 'transfer target binding'),
        ('reguarded-f32-mask-address', 0x3423183, 'rip_edges', 'RIP target binding')):
        altered = copy.deepcopy(spec)
        row = next(row for row in altered['row_guards'] if int(row[0], 16) == pc)
        original = bytes.fromhex(row[1])
        va = pc + len(original) - 1
        mutant = flipped(va)
        row[1] = image.read(pc, len(original))[:-1].hex() + bytes([original[-1] ^ 1]).hex()
        for control in altered['semantic_controls']:
            if int(control['pc'], 16) == pc:
                control['raw'] = row[1]
        if edge_key == 'transfers':
            next(e for e in altered[edge_key] if int(e['pc'], 16) == pc)['raw'] = row[1]
        rejected(name, lambda: collector.validate_inner(mutant, altered), message)

    # Synthetic text tests the retained-row parser, not a claimed GNU execution.
    selected = [r for r in spec['row_guards']
                if int(body['start'], 16) <= int(r[0], 16) < int(body['end'], 16)]
    lines = [f' {int(pc,16):x}:\t{" ".join(raw[i:i+2] for i in range(0,len(raw),2))}\tstatic-row\n'
             for pc, raw, _ in selected]
    synthetic = ''.join(lines).encode()
    accepted('synthetic-full-row-parser',
             lambda: collector.decode_export(synthetic, image, body, spec))
    for name, text in [('missing-first', ''.join(lines[1:])),
                       ('duplicate-first', lines[0] + ''.join(lines))]:
        rejected('synthetic-' + name,
                 lambda text=text: collector.decode_export(text.encode(), image, body, spec),
                 'partition disagreement')
    combined = selected[0][1] + selected[1][1]
    merged = (f' {int(selected[0][0],16):x}:\t' +
              ' '.join(combined[i:i+2] for i in range(0,len(combined),2)) + '\tmerged-row\n')
    rejected('synthetic-resegmented-bytes',
             lambda: collector.decode_export((merged+''.join(lines[2:])).encode(), image, body, spec),
             'boundary/width disagreement')
    rejected('duplicate-json-key', lambda: collector.load_json('{"a":1,"a":2}'),
             'duplicate JSON key')

    for label, failure in [('nonzero-child', None),
                           ('launch-error', OSError('synthetic launch diagnostic')),
                           ('timeout', collector.subprocess.TimeoutExpired('synthetic', 1,
                               output=b'partial timeout stdout\n', stderr=b'partial timeout stderr\n'))]:
        with tempfile.TemporaryDirectory(prefix='fee-rate-mocked-') as tmp:
            tool = Path(tmp) / 'not-executed-provider'
            tool.write_bytes(b'not executable, mocked subprocess only')
            destination = Path(tmp) / 'fresh'
            version = collector.subprocess.CompletedProcess([], 0, b'GNU objdump synthetic\n', b'')
            failed = collector.subprocess.CompletedProcess([], 9, b'partial stdout\n', b'child stderr\n')
            effects = [version, failed] if failure is None else failure
            with patch.object(collector, 'select_tool', return_value=(tool, collector.digest(tool.read_bytes()))), \
                    patch.object(collector.subprocess, 'run', side_effect=effects):
                rejected('mocked-' + label, lambda: collector.collect(data, destination),
                         'GNU tool failure/nonempty stderr')
            records = json.loads((destination / 'commands.json').read_bytes())
            last = records[-1]
            actual_out = (destination / last['stdout_file']).read_bytes()
            actual_err = (destination / last['stderr_file']).read_bytes()
            if failure is None:
                require(last['exit_code'] == 9 and actual_out == failed.stdout and actual_err == failed.stderr,
                        'failed child raw streams not preserved')
            elif isinstance(failure, collector.subprocess.TimeoutExpired):
                require(last['exit_code'] is None and last['failure'] == 'timeout' and
                        actual_out == failure.stdout and actual_err == failure.stderr,
                        'timeout partial child streams not preserved')
            else:
                require(last['exit_code'] is None and not actual_out and not actual_err,
                        'launch diagnostic must not pretend to be child stream')
                require((destination / last['launch_error_diagnostic']['file']).read_bytes() ==
                        b'synthetic launch diagnostic', 'launch diagnostic not preserved')
            require(not (destination / 'records.json').exists(), 'failure falsely produced final records')
    # Generate complete synthetic disassembly streams through the mocked collector
    # to exercise compare_packet without claiming real GNU tool execution.
    with tempfile.TemporaryDirectory(prefix='fee-rate-replay-controls-') as tmp:
        root = Path(tmp)
        expected, actual = root / 'expected', root / 'actual'
        tool = root / 'not-executed-provider'
        tool.write_bytes(b'mocked provider, not executed')
        version = collector.subprocess.CompletedProcess([], 0, b'GNU objdump synthetic\n', b'')
        effects = [version]
        for selected_body in spec['bodies']:
            selected_rows = [row for row in spec['row_guards']
                             if int(selected_body['start'], 16) <= int(row[0], 16) <
                             int(selected_body['end'], 16)]
            text = ''.join(f' {int(pc,16):x}:\t{" ".join(raw[i:i+2] for i in range(0,len(raw),2))}\tstatic-row\n'
                           for pc, raw, _ in selected_rows).encode()
            effects.append(collector.subprocess.CompletedProcess([], 0, text, b''))
        with patch.object(collector, 'select_tool', return_value=(tool, collector.digest(tool.read_bytes()))), \
                patch.object(collector.subprocess, 'run', side_effect=effects):
            collector.collect(data, expected)
        collector.shutil.copytree(expected, actual)
        accepted('synthetic-identical-generated-replay',
                 lambda: collector.compare_packet(actual, expected))
        record = json.loads((actual / 'records.json').read_bytes())
        record['tool_sha256'] = '0' * 64
        record['tool_version'] = 'GNU objdump other synthetic version'
        (actual / 'records.json').write_text(json.dumps(record))
        other_version = b'GNU objdump other synthetic version\n'
        (actual / 'objdump-version.txt').write_bytes(other_version)
        commands = json.loads((actual / 'commands.json').read_bytes())
        commands[0]['stdout_sha256'] = collector.digest(other_version)
        (actual / 'commands.json').write_text(json.dumps(commands))
        accepted('synthetic-version-only-replay-exception',
                 lambda: collector.compare_packet(actual, expected))
        record['facts']['rows'] += 1
        (actual / 'records.json').write_text(json.dumps(record))
        rejected('synthetic-semantic-record-drift',
                 lambda: collector.compare_packet(actual, expected), 'record mismatch')
        record['facts']['rows'] -= 1
        (actual / 'records.json').write_text(json.dumps(record))
        commands[0]['stdout_file'] = '../must-not-read'
        (actual / 'commands.json').write_text(json.dumps(commands))
        rejected('synthetic-version-command-path-escape',
                 lambda: collector.compare_packet(actual, expected), 'command identity')
    print(json.dumps({'completed': len(results), 'all_passed': True}, sort_keys=True))


if __name__ == '__main__':
    main()
