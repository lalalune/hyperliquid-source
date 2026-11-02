#!/usr/bin/env python3
"""Reproduce static evidence and attack proof bindings below image identity."""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import subprocess
import tempfile

from collect import (Image, RANGES, bindings, collect, encode, need, partition, sha)


def patched(image, offset, new):
    other = copy.copy(image)
    other.data = image.data[:offset] + new + image.data[offset + len(new):]
    return other


def verify(target, retained, witnesses, objdump):
    fresh = collect(target, witnesses, objdump)
    for name, data in fresh.items():
        need((retained / name).read_bytes() == data, 'retained regeneration:' + name)
    image = Image(target.read_bytes())
    controls = []

    def reject(name, fn, expected, **details):
        try:
            fn()
        except ValueError as error:
            need(expected in str(error), 'wrong rejection:' + name + ':' + str(error))
            controls.append({'name': name, 'rejected_by': str(error), **details})
        else:
            raise ValueError('accepted control:' + name)

    reject('truncated', lambda: Image(image.data[:-1]), 'target identity')
    reject('LFS pointer', lambda: Image(b'version https://git-lfs.github.com/spec/v1\n'), 'target identity')
    changed = patched(image, image.offset(0x2027d53, 1), b'\x85')
    reject('changed image', lambda: Image(changed.data), 'target identity')
    del changed
    # Each control changes an actual operative byte, then is decoded afresh.
    # Binding rejection is not a theorem about execution of the changed program.
    mutations = (
        ('key length offset', 0x2027d18, '10', '0x2027d14'),
        ('comparator slot displacement', 0x2027c96, 'df', '0x2027c93'),
        ('comparator register', 0x2027d3f, 'd5', '0x2027d3d'),
        ('lookup bucket stride', 0x2027d13, 'd2', '0x2027d10'),
        ('comparison success polarity', 0x2027d53, '85', '0x2027d52'),
        ('matched value tag offset', 0x202801e, 'e0', '0x202801a'),
        ('callback slot', 0x20280d2, '18', '0x20280d0'),
        ('registered method length', 0x27ab672, '0e', '0x27ab671'),
        ('registered descriptor tag', 0x1f6d919, '01', '0x1f6d914'),
        ('registered callback table displacement', 0x1f6d90b, '82', '0x1f6d908'),
        ('insertion bucket stride', 0x2a48584, 'd2', '0x2a48581'),
        ('insertion descriptor offset', 0x2a485a3, 'e0', '0x2a4859f'),
        ('callback captured pointer offset', 0x1f702e7, '18', '0x1f702e4'),
        ('probe returned key pointer', 0x2a48c28, '10', '0x2a48c24'),
        ('probe returned key length', 0x2a48c2e, '7b', '0x2a48c2c'),
        ('probe returned first word', 0x2a48c2b, '13', '0x2a48c29'),
    )
    for name, va, new_hex, witness in mutations:
        new = bytes.fromhex(new_hex)
        old = image.at(va, len(new))
        need(old != new, 'mutation applied:' + name)
        mutant = patched(image, image.offset(va, len(new)), new)
        matches = [(key, a, b) for key, (a, b) in RANGES.items() if a <= va < b]
        need(len(matches) == 1, 'mutation range')
        key, start, end = matches[0]
        with tempfile.TemporaryDirectory(prefix='rpc-lookup-mutant-') as tmp:
            p = Path(tmp) / 'body.bin'
            p.write_bytes(mutant.at(start, end - start))
            p.chmod(0o400)
            argv = [objdump, '-D', '-b', 'binary', '-m', 'i386:x86-64', '-M', 'intel',
                    '--wide', '--insn-width=16', f'--adjust-vma={start}', 'body.bin']
            native = subprocess.check_output(argv, cwd=tmp, text=True)
        rows = partition(mutant, native, start, end)
        affected = [{'va': hex(a), 'raw': raw.hex(), 'text': text}
                    for a, raw, text in rows if a <= va < a + len(raw)]
        reject(name, lambda: bindings(mutant, witnesses), 'witness:' + witness,
               kind='fresh native decode / below identity binding', va=hex(va),
               original=old.hex(), changed=new.hex(), affected_rows=affected,
               native_sha256=sha(native.encode()))
        del mutant
    relas = image.relas({0x576e378, 0x56919b8})
    for slot, field_offset, expected in ((0x576e378, 8, 'bcmp relocation'),
                                         (0x56919b8, 16, 'RELATIVE:0x56919b8')):
        off = relas[slot]['file_offset'] + field_offset
        mutant = patched(image, off, bytes([image.data[off] ^ 1]))
        reject('relocation ' + hex(slot), lambda: bindings(mutant, witnesses), expected,
               kind='below identity relocation', file_offset=off)
        del mutant
    record = bindings(image, witnesses)
    nameoff = record['comparator_symbol']['name_file_offset']
    mutant = patched(image, nameoff, b'x')
    reject('symbol string', lambda: bindings(mutant, witnesses), 'undefined bcmp symbol')
    del mutant
    mutant = patched(image, image.offset(0x5691998, 1), b'\x09')
    reject('callback size header', lambda: bindings(mutant, witnesses), 'raw callback table')
    del mutant
    mutant = patched(image, image.offset(0x3f05a2, 1), b'E')
    reject('method spelling', lambda: bindings(mutant, witnesses), 'method literal')
    del mutant
    fr = image.frame(0x2027610, 0x2028519)
    for name, off, expected in (
        ('FDE extent', fr['fde_file_offset'] + 12, 'FDE PC interval'),
        ('CIE backreference', fr['fde_file_offset'] + 4, 'CIE'),
        ('index target', fr['index_file_offset'], 'selected exact unwind index'),
    ):
        mutant = patched(image, off, bytes([image.data[off] ^ 1]))
        reject(name, lambda: mutant.frame(0x2027610, 0x2028519), expected,
               kind='below identity unwind', file_offset=off)
        del mutant
    # Affine layout corroboration only: no target scanner/register evaluator.
    layout = []
    for i in (0, 1, 15, 16, 31, 255):
        ctrl = 0x100000
        inserted_key = ctrl - 40 * i - 40
        looked_up_key = (ctrl - 40) + (-5 * i) * 8
        matched_tag = ctrl + (-5 * i) * 8 - 24
        need(inserted_key == looked_up_key and inserted_key + 16 == matched_tag,
             'layout address identity')
        layout.append({'bucket_index': i, 'key': hex(inserted_key), 'tag': hex(matched_tag)})
    need((0x100000 - 40) - 72 != 0x100000 - 80, 'wrong-stride address witness')
    return {'regenerated_files': len(fresh), 'controls': controls, 'control_count': len(controls),
            'fresh_native_control_count': len(mutations), 'layout_cases': layout,
            'wrong_stride_index1': {'baseline_key': hex(0x100000 - 80),
                                     'mutant_key': hex((0x100000 - 40) - 72)},
            'captured_execution': False, 'instruction_evaluation': False,
            'limitations': 'Exact selected bindings and scalar address identities only. No changed-program execution, full probe or insertion helper semantics, table transport or actual callback effects are proved.'}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--target', type=Path, default=Path('artifacts/node/94/hl-node'))
    p.add_argument('--retained', type=Path, default=Path(__file__).with_name('observed'))
    p.add_argument('--witnesses', type=Path, default=Path(__file__).with_name('WITNESSES.json'))
    p.add_argument('--objdump', default='objdump')
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    need(not a.output.exists(), 'preserve existing output')
    result = verify(a.target, a.retained, json.loads(a.witnesses.read_text()), a.objdump)
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_bytes(encode(result))
    print(f"Eleven retained corridors reproduce; {result['control_count']} controls reject; no target execution.")


if __name__ == '__main__':
    main()
