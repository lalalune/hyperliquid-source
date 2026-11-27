#!/usr/bin/env python3
"""Verify the selected node #115 replay timer f64 input pointer flow; never run the target."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-017-node115-replay-timer-delay-pointer'
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SOURCE_COMMIT = 'e1528748a34c6ef79736ba16002caadbdff163a4'
FDE_SPECS = {
    'tracker_drain': (0x5afa030, 0x5afa1ee),
    'timer_map_apply': (0x4de0540, 0x4de0907),
    'flat_map_walk': (0x57f1690, 0x57f1874),
    'entry_timer_compare': (0x57d44d0, 0x57d4aea),
}


def decode_window(body, start, end):
    insns = list(Cs(CS_ARCH_X86, CS_MODE_64).disasm(body, start))
    if sum(i.size for i in insns) != end - start:
        raise ValueError(f'incomplete instruction decode for {start:#x}..{end:#x}')
    return {i.address: i for i in insns}


def verify(data, authenticate=True):
    if authenticate and hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('node #115 target digest mismatch')
    secs = sections(data)

    def read(va, count):
        maps = [s for s in secs if s['type'] != 8 and s['address'] <= va
                and va + count <= s['address'] + s['size']]
        if len(maps) != 1:
            raise ValueError(f'ambiguous or missing VA mapping: {va:#x}+{count:#x}')
        sec = maps[0]
        offset = sec['offset'] + va - sec['address']
        return data[offset:offset + count], offset

    _, fdes = eh_frame_records(data)
    windows = {}
    for name, (start, end) in FDE_SPECS.items():
        matches = [f for f in fdes if f['start'] == start and f['end'] == end]
        if len(matches) != 1:
            raise ValueError(f'exact {name} FDE missing')
        body, file_offset = read(start, end - start)
        windows[name] = dict(start=start, end=end, file_offset=file_offset,
                             body=body, instructions=decode_window(body, start, end),
                             fde=matches[0])

    anchors = {
        'tracker_drain': {
            0x5afa03e: ('mov', 'r14, rsi'),
            0x5afa044: ('lea', 'rdi, [rsi + 0x60]'),
            0x5afa06a: ('lea', 'rsi, [r14 + 0x88]'),
            0x5afa07f: ('mov', 'qword ptr [rsp + 0x18], rsi'),
            0x5afa09d: ('mov', 'rsi, rsp'),
            0x5afa0a0: ('call', '0x4de0540'),
        },
        'timer_map_apply': {
            0x4de0562: ('jno', '0x4de05f7'),
            0x4de05f7: ('mov', 'rdi, rbx'),
            0x4de05fa: ('call', '0x57f1690'),
        },
        'flat_map_walk': {
            0x57f169e: ('mov', 'qword ptr [rsp + 0x10], rsi'),
            0x57f16ec: ('mov', 'rsi, rbp'),
            0x57f16f2: ('mov', 'rdi, qword ptr [rsp + 0x10]'),
            0x57f16f7: ('call', '0x57d44d0'),
        },
        'entry_timer_compare': {
            0x57d4503: ('mov', 'r13, qword ptr [rdi]'),
            0x57d4506: ('mov', 'qword ptr [rsp + 0x78], rdi'),
            0x57d450b: ('mov', 'rax, qword ptr [rdi + 0x18]'),
            0x57d450f: ('movsd', 'xmm0, qword ptr [rax]'),
        },
    }
    for name, expected in anchors.items():
        insns = windows[name]['instructions']
        for pc, pair in expected.items():
            insn = insns.get(pc)
            if insn is None or (insn.mnemonic, insn.op_str) != pair:
                raise ValueError(f'{name} instruction changed at {pc:#x}')

    # The selected no-overflow branch reaches the flat-map call without changing RSI.
    branch = windows['timer_map_apply']['instructions'][0x4de0562]
    if branch.mnemonic != 'jno' or branch.op_str != '0x4de05f7':
        raise ValueError('selected timer branch changed')
    between = [i for pc, i in windows['timer_map_apply']['instructions'].items()
               if 0x4de05f7 <= pc < 0x4de05fa]
    if [(i.address, i.mnemonic, i.op_str) for i in between] != [
            (0x4de05f7, 'mov', 'rdi, rbx')]:
        raise ValueError('flat-map handoff no longer preserves the context pointer')

    rela = next(s for s in secs if s['name'] == '.rela.dyn')
    relocs = list(struct.iter_unpack('<QQq', data[rela['offset']:rela['offset'] + rela['size']]))

    def relocation_at(slot):
        matches = [dict(slot=offset, info=info, addend=addend)
                   for offset, info, addend in relocs if offset == slot]
        if len(matches) != 1 or matches[0]['info'] != 8:
            raise ValueError(f'expected one R_X86_64_RELATIVE relocation at {slot:#x}')
        return matches[0]

    slots = {hex(slot): relocation_at(slot) for slot in (0x64e0f70, 0x64e0f78)}
    if slots['0x64e0f70']['addend'] != 0x15ed960:
        raise ValueError('f64-to-time conversion slot target changed')
    if slots['0x64e0f78']['addend'] != 0x162a9a0:
        raise ValueError('time threshold constructor slot target changed')

    result_windows = {}
    for name, record in windows.items():
        insns = record['instructions']
        selected = anchors.get(name, {})
        result_windows[name] = {
            'start': record['start'], 'end': record['end'],
            'file_offset': record['file_offset'],
            'fde': record['fde'],
            'body_sha256': hashlib.sha256(record['body']).hexdigest(),
            'native_instruction_count': len(insns),
            'anchors': [dict(va=pc, bytes=insns[pc].bytes.hex(),
                             mnemonic=insns[pc].mnemonic, operands=insns[pc].op_str)
                        for pc in selected],
        }
    return {
        'target_sha256': SHA,
        'target_size': len(data),
        'source_commit': SOURCE_COMMIT,
        'question': 'Does the selected replay flat-map timer comparator consume tracker+0x88?',
        'claim_status': 'exact pointer-flow observation; timer-delay meaning and stored value remain inferred/unresolved',
        'windows': result_windows,
        'pointer_flow': [
            {'at': 0x5afa06a, 'observation': 'tracker+0x88 address is formed'},
            {'at': 0x5afa07f, 'observation': 'address is stored in callback-context word +0x18'},
            {'at': 0x5afa09d, 'observation': 'context base is passed to 0x4de0540 in RSI'},
            {'at': 0x4de0562, 'observation': 'selected no-overflow branch reaches flat-map call'},
            {'at': 0x4de05fa, 'observation': 'context pointer is preserved in RSI at call to 0x57f1690'},
            {'at': 0x57f169e, 'observation': 'flat-map walker saves the context pointer'},
            {'at': 0x57f16f7, 'observation': 'saved context is passed to 0x57d44d0 in RDI'},
            {'at': 0x57d450b, 'observation': 'callback loads context word +0x18 as a pointer'},
            {'at': 0x57d450f, 'observation': 'callback reads one 8-byte IEEE-754 value through that pointer'},
        ],
        'relocations': slots,
        'remaining_unknowns': [
            'who initializes or updates tracker+0x88 and its exact stored value',
            'the time unit or configuration meaning of the f64',
            'runtime branch reachability, concurrent mutation and full timer eligibility',
            'the separate tree/sentinel timer route and complete component gates',
        ],
        'captured_target_executed': False,
        'component_gate_changed': False,
    }


def self_test(data):
    result = verify(data)
    if len(result['pointer_flow']) != 9:
        raise AssertionError('pointer-flow record count changed')
    for name, expected in FDE_SPECS.items():
        changed = bytearray(data)
        window = result['windows'][name]
        anchor_va = window['anchors'][0]['va']
        changed[window['file_offset'] + anchor_va - window['start']] ^= 1
        try:
            verify(changed, authenticate=False)
        except ValueError:
            continue
        raise AssertionError(f'{name} window mutation accepted')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    data = TARGET.read_bytes()
    result = self_test(data) if args.self_test else verify(data)
    rendered = json.dumps(result, indent=2, sort_keys=True) + '\n'
    if args.write:
        PACKET.mkdir(parents=True, exist_ok=True)
        (PACKET / 'records.json').write_text(rendered, encoding='utf-8')
        for name, (start, end) in FDE_SPECS.items():
            raw = subprocess.check_output([
                'objdump', '-d', '-M', 'intel', f'--start-address={start:#x}',
                f'--stop-address={end:#x}', str(TARGET.relative_to(ROOT))], cwd=ROOT)
            (PACKET / f'{name}.asm').write_bytes(
                b'\n'.join(line.rstrip() for line in raw.splitlines()) + b'\n')
    elif (PACKET / 'records.json').read_text(encoding='utf-8') != rendered:
        raise ValueError('retained records differ from authenticated target')
    print(json.dumps({'target_sha256': SHA, 'windows': len(FDE_SPECS),
                      'fdes': len(result['windows']), 'relocations': len(result['relocations']),
                      'anchors': sum(len(v['anchors']) for v in result['windows'].values()),
                      'pointer_flow_steps': len(result['pointer_flow']),
                      'mutations_rejected': len(FDE_SPECS) if args.self_test else 0}))


if __name__ == '__main__':
    main()
