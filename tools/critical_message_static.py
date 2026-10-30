#!/usr/bin/env python3
"""RE-001: three optional node94 critical-message entry gates and one caller."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile
from artifacts import ROOT
from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import decode_export

TARGET = ROOT / 'artifacts/node/94/hl-node'
PACKET = ROOT / 'research/work-items/RE-001-critical-message-admission-94'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
RANGES = [(0x143d010, 0x143e888), (0x4779e30, 0x4779eac)]
CONTROLS = {
    0x143d021: "4989cf4989f64989fc4889b4243002000048895424284889942438020000",
    0x143d047: "ff1553183304",
    0x143d04d: "498b2c24498b542408410fb64424118844240b410fb65c2413450fb66c241441807c2412007431",
    0x143d074: "4c8b25ad183304418b44245085c00f8519030000410fb644244883f81e0f87be120000b9006000400fa3c10f83b0120000",
    0x143d0a5: "84db740f0fb60560b2340484c00f859d1200004584ed74144889d3ff15d21733044889da84c00f8584120000",
    0x143d3a1: "4c89642440488d44244048898424f0000000498d7c2450488d0d51de23044c8d0572de23044889942498000000488d9424f0000000be01000000ff15d7143304488b942498000000410fb644244883f81e0f869ffcffffe9580f0000",
    0x143e355: "4881c4780200005b415c415d415e415f5dc3",
    0x4779e58: "48c744241800000000c744242800000000c644242c00",
    0x4779e82: "488d356a9da7fb488d0d184afb00488d7c2418488d5424084889c3ff15d54aff004889d8",
}
RIP = {(0x143d047, 'ff15'): 0x576e8a0,
       (0x143d074, '4c8b25'): 0x576e928,
       (0x143d0a9, '0fb605'): 0x5788310,
       (0x143d0c0, 'ff15'): 0x576e898,
       (0x143d3b8, '488d0d'): 0x567b210,
       (0x143d3bf, '4c8d05'): 0x567b238,
       (0x143d3db, 'ff15'): 0x576e8b8,
       (0x143def3, '488d35'): 0x566a278,
       (0x4779e82, '488d35'): 0x1f3bf3,
       (0x4779e89, '488d0d'): 0x572e8a8,
       (0x4779e9d, 'ff15'): 0x576e978}
RELATIVE = {0x576e8a0: 0x151cba0, 0x576e928: 0x577b288,
            0x576e898: 0x13c8f60, 0x576e8b8: 0x4ee3b20,
            0x576e978: 0x143d010, 0x567b238: 0x1f87cf,
            0x566a278: 0x1fcf88, 0x572e8a8: 0x1f9bb7}


def read(data, va, size):
    found = [s['offset'] + va - s['address'] for s in sections(data) if s['type'] != 8
             and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(found) != 1:
        raise ValueError('expected unique file-backed mapping')
    off = found[0]
    return off, bytes(data[off:off + size])


def abstract_gate_reason(flag12, raw_tag_after_initialization, flag13, global_byte, flag14, helper_al):
    """Conditional entry predicate only; assumes preceding helper calls return."""
    tag = raw_tag_after_initialization
    if flag12 and (tag > 30 or not (0x40006000 & (1 << tag))):
        return 'tag_gate'
    if flag13 and global_byte:
        return 'global_byte_gate'
    if flag14 and helper_al:
        return 'helper_gate'
    return 'continue_past_entry_gates'


def analyze(data):
    _, frames, _ = fde_extents(data)
    if not set(RANGES) <= {(f['start'], f['end']) for f in frames}:
        raise ValueError('selected FDE changed')
    for va, value in CONTROLS.items():
        raw = bytes.fromhex(value)
        if read(data, va, len(raw))[1] != raw:
            raise ValueError(f'entry/caller instruction changed at {va:#x}')
    for (va, prefix), target in RIP.items():
        prefix = bytes.fromhex(prefix)
        raw = read(data, va, len(prefix) + 4)[1]
        if not raw.startswith(prefix) or va + len(raw) + struct.unpack_from('<i', raw, len(prefix))[0] != target:
            raise ValueError('RIP target changed')
    sec = next(s for s in sections(data) if s['name'] == '.rela.dyn')
    rels = {a: (i, v) for a, i, v in struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']])}
    if any(rels.get(a) != (8, v) for a, v in RELATIVE.items()):
        raise ValueError('helper/global/Location relocation changed')
    locations = [(0x566a278, 0x1fcf88, '/home/ubuntu/hl/code_Mainnet/base/src/crit_msg.rs', 291, 19),
                 (0x567b238, 0x1f87cf, '/rustc/e408947bfd200af42db322daf0fadfe7e26d3bd1/library/std/src/sync/once.rs', 219, 20),
                 (0x572e8a8, 0x1f9bb7, '/home/ubuntu/hl/code_Mainnet/base/src/file_mod_time_tracker.rs', 63, 13)]
    source = []
    for slot, path_va, path, line, column in locations:
        raw = path.encode()
        if read(data, path_va, len(raw))[1] != raw or read(data, slot + 8, 16)[1] != struct.pack('<QII', len(raw), line, column):
            raise ValueError('source Location changed')
        source.append({'slot': hex(slot), 'path_va': hex(path_va), 'path': path, 'line': line, 'column': column})
    rows = []
    for start, end in RANGES:
        off, body = read(data, start, end - start)
        rows.append({'start_va': hex(start), 'end_va': hex(end), 'bytes': len(body),
                     'file_offset': hex(off), 'sha256': hashlib.sha256(body).hexdigest()})
    return {'target_sha256': SHA256, 'ranges': rows,
            'entry_gate_fields': ['options+0x12', 'options+0x13', 'options+0x14'],
            'first_gate': {'object_slot': '0x576e928', 'object_relative_addend': '0x577b288',
                           'initialization_state_offset': '0x50', 'post_init_tag_offset': '0x48',
                           'unsigned_max': 30, 'mask': '0x40006000', 'accepted_raw_tags': [13, 14, 30]},
            'second_gate_global_byte_va': '0x5788310',
            'third_gate_helper': {'slot': '0x576e898', 'relative_addend': '0x13c8f60', 'tested_register': 'al'},
            'shared_return_epilogue_va': '0x143e355',
            'clock_call_before_gate_reads': {'site': '0x143d047', 'slot': '0x576e8a0', 'relative_addend': '0x151cba0'},
            'selected_caller': {'site': '0x4779e9d', 'slot': '0x576e978',
                                'options_rdi': 'rsp+0x18', 'cleared_fields': ['qword+0', 'bytes+0x10..+0x14'],
                                'payload_plus8_initialization': 'not established by this caller window',
                                'callee_rax': 'ignored; caller restores its own pre-call pointer from rbx'},
            'sources': source, 'relative_bindings': {hex(a): hex(v) for a, v in RELATIVE.items()},
            'instruction_controls': {hex(a): v for a, v in CONTROLS.items()},
            'rip_targets': [{'site': hex(a), 'prefix_hex': p, 'target': hex(v)} for (a, p), v in RIP.items()],
            'captured_binary_executed': False,
            'limits': 'Entry gates only and one selected caller. Concrete policy names, default values, options type, helpers, full record/alert effects, later occurrence/repeat gates and a structured decision-return ABI remain unproved. Predicate assumes helpers return.'}


def generate(binary, output):
    data = binary.read_bytes()
    if len(data) != 91774280 or hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError('expected pinned node94')
    report = analyze(data)
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as directory:
        snapshot = Path(directory) / 'node94.elf'
        snapshot.write_bytes(data)
        frames = subprocess.check_output(['readelf', '-wf', str(snapshot)], text=True)
        chosen = [line for line in frames.splitlines() if any(f'pc={a:016x}..{b:016x}' in line for a, b in RANGES)]
        if len(chosen) != 2:
            raise ValueError('native FDE confirmation failed')
        (output / 'frames.txt').write_text('\n'.join(chosen) + '\n')
        for start, end in RANGES:
            asm = subprocess.check_output(['objdump', '-d', '-M', 'intel', '--insn-width=16',
                                          f'--start-address={start:#x}', f'--stop-address={end:#x}', str(snapshot)], text=True)
            ins = decode_export(asm, start, end, read(data, start, end - start)[1])
            sites = set(CONTROLS) | {a for a, _ in RIP}
            if not {a for a in sites if start <= a < end} <= set(ins):
                raise ValueError('selected controls must be decoded instruction starts')
            (output / f'{start:x}.objdump.txt').write_text(asm.replace(str(snapshot), '<authenticated-node94>'))
    (output / 'records.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--output', type=Path, default=ROOT / 'work/critical-message-admission-94')
    args = parser.parse_args()
    print(json.dumps({'ranges': len(generate(args.binary, args.output)['ranges']), 'executed': False}))
