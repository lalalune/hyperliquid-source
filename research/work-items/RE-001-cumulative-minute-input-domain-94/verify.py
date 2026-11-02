#!/usr/bin/env python3
"""Regenerate static evidence and attack the composition with byte controls."""
import argparse
import copy
import json
from pathlib import Path
import struct
import tempfile
from unittest.mock import patch

import collect


def compare(expected, actual):
    collect.need(expected.keys() == actual.keys(), 'Retained file membership differs')
    for name in expected:
        collect.need(expected[name] == actual[name], 'Retained evidence differs: ' + name)


def rejects(action, label, expected=None):
    try:
        action()
    except ValueError as error:
        if expected:
            collect.need(expected in str(error), 'Control failed for an unintended reason: ' + str(error))
        return str(error)
    raise ValueError('Control accepted: ' + label)


def verify(binary, retained, llvm):
    first = collect.collect(binary, llvm)
    second = collect.collect(binary, llvm)
    compare(first, second)
    compare(first, {p.name: p.read_bytes() for p in Path(retained).iterdir() if p.is_file()})
    report = json.loads(first['records.json'])
    original = collect.Image(Path(binary).read_bytes())
    decoded = {label: row['instructions'] for label, row in report['ranges'].items()}
    controls = []
    with tempfile.TemporaryDirectory(prefix='minute-admission-') as tmp:
        path = Path(tmp) / 'bad-input'
        variants = [('truncated', original.data[:-1]), ('extended', original.data + b'\0'),
                    ('changed-byte', original.data[:100] + bytes([original.data[100] ^ 1]) + original.data[101:])]
        for label, data in variants:
            path.write_bytes(data)
            with patch.object(collect, 'native', side_effect=RuntimeError('Native reached before admission')):
                reason = rejects(lambda: collect.collect(path, llvm), label, 'Wrong complete node94 identity')
            controls.append({'control': label + '-before-native', 'rejected': reason})

    def mutant(label, changes, expected, witness):
        # Copy only an already authenticated input. Public collect() has no bypass.
        # These altered bytes are supplied solely to native static decoding and analyze().
        image = copy.copy(original)
        data = bytearray(original.data)
        changed_ranges = set()
        changes_record = []
        for coordinate, address, new in changes:
            offset = original.offset(address, len(new)) if coordinate == 'va' else address
            before = bytes(data[offset:offset + len(new)])
            collect.need(before != new, 'Ineffective control')
            data[offset:offset + len(new)] = new
            changes_record.append({'coordinate': coordinate, 'address': hex(address),
                                   'before': before.hex(), 'after': new.hex()})
            for key, (start, end) in collect.RANGES.items():
                begin = original.offset(start, end - start)
                if offset < begin + end - start and begin < offset + len(new):
                    changed_ranges.add(key)
        image.data = bytes(data)
        actual = copy.deepcopy(decoded)
        with tempfile.TemporaryDirectory(prefix='minute-byte-control-') as tmp:
            directory = Path(tmp)
            for label_key in changed_ranges:
                start, end = collect.RANGES[label_key]
                path = directory / 'slice.bin'
                path.write_bytes(image.at(start, end - start)); path.chmod(0o400)
                listing = collect.native(['objdump', '-D', '-b', 'binary', '-m', 'i386:x86-64',
                    '-M', 'intel', '--insn-width=16', '--adjust-vma=' + hex(start), 'slice.bin'], directory)
                actual[label_key] = collect.rows(listing, image, start, end)
            reason = rejects(lambda: collect.analyze(image, actual), label, expected)
        controls.append({'control': label, 'changes': changes_record, 'rejected': reason,
                         'staticCounterfactual': witness, 'targetExecution': False})

    mutant('producer-destination-offset', [('va', 0x49255bb, b'\x45')],
           'Producer/consumer field offsets differ', 'The consumer remains at0x48; the new destination+4 is0x49.')
    mutant('consumer-field-offset', [('va', 0x4925baf, b'\x4c')],
           'Producer/consumer field offsets differ', 'The consumed word changes from producer+4 to producer+8.')
    call = 0x49255bc
    mutant('producer-call-slot', [('va', call + 2, struct.pack('<i', collect.SLOT + 8 - call - 6))],
           'Producer call slot changed', 'The relative operand now selects the adjacent slot, not the proven producer.')
    mutant('producer-second-store-offset', [('va', 0x151cc5b, b'\x08')],
           'Producer arithmetic/store operation changed', 'The remainder store is redirected from+4 to+8.')
    old_m = struct.unpack('<Q', original.at(0x151cbf1, 8))[0]
    mutant('producer-reciprocal-minus-two', [('va', 0x151cbf1, struct.pack('<Q', old_m - 2))],
           'Positive approximation bound fails', 'M-2 remains odd but makes M*86400-2^77 negative; the complete-domain certificate fails.')
    mutant('minute-inclusive-guard', [('va', 0x4925bed, struct.pack('<I', 1440))],
           'Observed minute guards changed', 'The second comparison threshold changes from1441 to1440; retained local semantics no longer match.')
    mutant('intermediate-overlapping-store', [('va', 0x4925b35, b'\x48')],
           'Explicit overlapping input write', 'The real QWORD zero store moves from[RSP+0x58] to[RSP+0x48], overwriting the consumed word.')
    branch = 0x4925366
    mutant('entry-bypasses-producer', [('va', branch + 1, struct.pack('<i', 0x4925bac - branch - 5))],
           'Producer does not dominate consumer', 'The real earlier JMP now reaches the conversion without visiting the producer call.')
    mutant('dispatch-bypasses-producer', [('va', collect.TABLE, struct.pack('<i', 0x4926952 - collect.TABLE))],
           'Producer does not dominate consumer', 'Selected index0 now reaches the consumer directly; the completed CFG detects loss of dominance.')
    mutant('dispatch-selector-register', [('va', 0x4925fdf, b'\xc3')],
           'Original BPL selector load changed', 'MOVZX now reads BL instead of BPL, invalidating the documented original-selector transfer.')
    mutant('dispatch-original-selector-copy', [('va', 0x4925f25, b'\xdd')],
           'Original ESI-to-EBP copy changed', 'The entry MOV now saves EBX instead of the original ESI selector.')
    mutant('dispatch-selector-overwrite', [('va', 0x4926044, b'\xc0')],
           'Dispatch selector is overwritten', 'The real MOVZX writes EAX instead of EDX after the selector load.')
    mutant('prefixed-selector-overwrite', [('va', 0x4926005, bytes.fromhex('6666b8ffff909090909090'))],
           'Unreviewed prefixed instruction', 'The original 11-byte NOP becomes data16 MOV AX,65535 plus padding, overwriting the selector despite a misleading leading prefix mnemonic.')
    mutant('prefixed-entry-bypasses-producer', [('va', 0x492531d, bytes.fromhex('2ee9890800009090'))],
           'Unreviewed prefixed instruction', 'The original comparison becomes CS-prefixed JMP to the consumer at0x4925bac plus padding, bypassing the producer.')
    mutant('producer-ret-unreachable', [('va', 0x151cbed, b'\xeb')],
           'Expected reachable sole producer RET', 'Changing the raw-status JE to JMP removes every local entry path to the producer RET.')
    fde = report['ranges']['caller-a']['frames']['decoded']['fde']
    old_length = struct.unpack('<I', original.at(fde + 12, 4))[0]
    mutant('fde-extent', [('va', fde + 12, struct.pack('<I', old_length + 1))],
           'Exact FDE extent differs', 'The decoded unwind extent is one byte longer than the selected complete range.')
    relocation = next(row for row in report['relocations'] if row['slot'] == hex(collect.SLOT))
    mutant('producer-relocation-target', [('file', int(relocation['fileOffset'], 16) + 16,
                                         struct.pack('<q', 0x151cba1))],
           'Producer relocation binding changed', 'The admitted relative slot would resolve one byte into the producer instead of its entry.')

    altered = copy.deepcopy(decoded)
    altered['caller-a'].pop(0)
    controls.append({'control': 'missing-decoder-row', 'rejected': rejects(
        lambda: collect.analyze(original, altered), 'missing-decoder-row', 'Decoded range start differs')})
    altered_files = dict(first); altered_files.pop('caller-b.llvm.txt')
    controls.append({'control': 'missing-independent-export', 'rejected': rejects(
        lambda: compare(first, altered_files), 'missing-independent-export', 'Retained file membership differs')})
    altered_files = dict(first); altered_files['records.json'] += b'changed'
    controls.append({'control': 'modified-retained-record', 'rejected': rejects(
        lambda: compare(first, altered_files), 'modified-retained-record', 'Retained evidence differs')})
    with tempfile.TemporaryDirectory(prefix='minute-preserve-output-') as tmp:
        output = Path(tmp) / 'existing'; output.mkdir()
        sentinel = output / 'keep'; sentinel.write_bytes(b'preserved')
        reason = rejects(lambda: collect.write_new(output, first), 'existing-output', 'Preserve existing output')
        collect.need(sentinel.read_bytes() == b'preserved' and len(list(output.iterdir())) == 1, 'Existing output changed')
        controls.append({'control': 'preserve-existing-output', 'rejected': reason})
    return {'status': 'PASS', 'regenerations': 2, 'retainedFiles': len(first),
            'decoderComparison': report['independentDecoderComparison'],
            'rejectedControls': controls, 'targetExecution': False, 'instructionEvaluation': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=collect.ROOT / 'artifacts/node/94/hl-node')
    parser.add_argument('--retained', type=Path, default=collect.HERE / 'observed')
    parser.add_argument('--llvm-objdump', default=collect.LLVM_DEFAULT)
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.binary, args.retained, args.llvm_objdump), indent=2))
    except (ValueError, OSError) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()
