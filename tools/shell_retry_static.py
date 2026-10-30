#!/usr/bin/env python3
"""RE-001 node94 optional retry schedule, explicit attempt sites and sleep imports."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
from artifacts import ROOT
from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import decode_export

TARGET = ROOT / 'artifacts/node/94/hl-node'
PACKET = ROOT / 'research/work-items/RE-001-shell-retry-schedule-94'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
RANGES = [(0x13c9080, 0x13c9363), (0x14b5530, 0x14b559e)]
CONTROLS = {
    0x13c9091: "4d89c44989ce48897424604889542468488d3590dd290448897c2428ff1515583a044885c074254889c3488904244d85f674214c897424184c896424204d85e40f84b30100004b8d04e6eb24",
    0x13c90dd: "4531f6e91a0200004c8d35ecdce4fe4c8974241848c744242003000000488d05efdce4fe488944241049bfffffffffffffff7f",
    0x13c9120: "f2410f100ef20f590d331de4fe",
    0x13c91b6: "4889c848badb34b6d782de1b4348f7e24889d548c1ed124869c540420f004881f940420f000f92c24829c10f94c084c27561",
    0x13c91e8: "4869c1e8030000904c39fd4c89f9480f42cd48894c243048894424384829cd4c89ef4c89ee41ffd483f8ff740b31c04885c07e28ebd26690ff15b2563a048b008944240c83f8040f85df00000048036c2430488b4424384885c07fac4885ed75a7",
    0x13c9249: "488b7c2428488d35e3db2904ff156d563a044889c54885c00f848d000000488b034889dfff104983c60848892c244889eb4c3b742410be000000000f8596feffff",
    0x13c928a: "488d4424604889442430488d05154811004889442438488d4424184889442440488d050ffe070048894424484889e04889442450488b052b523a044889442458488d35de3be3fe488d7c2470488d542430ff155f4d3a04488d7c2470e845c20e004989c6488b1c24eb034531f6488b034889dfff104c89f04881c4880000005b415c415d415e415f5dc3",
    0x14b5539: "4989fe488b1f4c8b7f08488d7c2430ff158aa72b040f104424300f104c24400f105424500f295424200f294c24100f2904244889e64c89f7e8fa0500004883c4605b415e415f",
}
RIP = {(0x13c90a1, '488d35'): 0x5666e38,
       (0x13c90ad, 'ff15'): 0x576e8c8,
       (0x13c90e5, '4c8d35'): 0x216dd8,
       (0x13c90fa, '488d05'): 0x216df0,
       (0x13c9117, '4c8b25'): 0x576e8d0,
       (0x13c9125, 'f20f590d'): 0x20ae60,
       (0x13c9220, 'ff15'): 0x576e8d8,
       (0x13c924e, '488d35'): 0x5666e38,
       (0x13c9255, 'ff15'): 0x576e8c8,
       (0x13c92ca, '488d35'): 0x1fceaf,
       (0x13c92db, 'ff15'): 0x576e040,
       (0x14b5548, 'ff15'): 0x576fcd8}
RELATIVE = {0x576e8c8: 0x13e4e40, 0x5666e38: 0x1ef309,
            0x576e040: 0x1344760, 0x576fcd8: 0x4eeee40}


def read(data, va, size):
    found = [s['offset'] + va - s['address'] for s in sections(data) if s['type'] != 8
             and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(found) != 1:
        raise ValueError('expected one file-backed mapping')
    off = found[0]
    return off, bytes(data[off:off + size])


def explicit_attempt_trace(schedule_length, outcomes):
    """Abstract count of visits to the two explicit wait-call sites, not execution."""
    trace = []
    for i in range(schedule_length + 1):
        trace.append('initial_call' if i == 0 else 'sleep_then_loop_call')
        if outcomes[i]:
            return trace, 'zero_return'
    trace.append('format_then_distinct_helper')
    return trace, 'exhausted'


def analyze(data):
    _, frames, _ = fde_extents(data)
    if not set(RANGES) <= {(f['start'], f['end']) for f in frames}:
        raise ValueError('selected FDE changed')
    for va, value in CONTROLS.items():
        raw = bytes.fromhex(value)
        if read(data, va, len(raw))[1] != raw:
            raise ValueError(f'retry instruction changed at {va:#x}')
    for (va, prefix), target in RIP.items():
        prefix = bytes.fromhex(prefix)
        raw = read(data, va, len(prefix) + 4)[1]
        if not raw.startswith(prefix) or va + len(raw) + struct.unpack_from('<i', raw, len(prefix))[0] != target:
            raise ValueError('retry RIP target changed')
    for va, target in [(0x13c92e6, 0x14b5530), (0x14b5571, 0x14b5b70)]:
        raw = read(data, va, 5)[1]
        if raw[0] != 0xe8 or va + 5 + struct.unpack_from('<i', raw, 1)[0] != target:
            raise ValueError('exhaustion helper edge changed')
    defaults = read(data, 0x216dd8, 24)[1]
    if defaults.hex() != 'fca9f1d24d62503f9a9999999999a93f000000000000f03f':
        raise ValueError('default retry schedule changed')
    if read(data, 0x20ae60, 8)[1] != struct.pack('<d', 1000000.0):
        raise ValueError('seconds scale changed')
    descriptor = b'\x14sleep_retry retried \xc0\x11 for sleep times \xc0\n last err \xc0\0'
    if read(data, 0x1fceaf, len(descriptor))[1] != descriptor:
        raise ValueError('retry diagnostic descriptor changed')
    secs = sections(data)
    rela = next(s for s in secs if s['name'] == '.rela.dyn')
    rels = {a: (i, v) for a, i, v in struct.iter_unpack('<QQq', data[rela['offset']:rela['offset'] + rela['size']])}
    if any(rels.get(a) != (8, v) for a, v in RELATIVE.items()):
        raise ValueError('wait/source/format/helper binding changed')
    sym = next(s for s in secs if s['name'] == '.dynsym')
    strings = next(s for s in secs if s['name'] == '.dynstr')
    imports = []
    for slot, index, name in [(0x576e8d0, 17, b'nanosleep'), (0x576e8d8, 18, b'__errno_location')]:
        if rels.get(slot) != ((index << 32) | 6, 0):
            raise ValueError('import slot changed')
        name_off = struct.unpack_from('<I', data, sym['offset'] + index * 24)[0]
        start = strings['offset'] + name_off
        if data[start:start + len(name) + 1] != name + b'\0':
            raise ValueError('sleep/errno dynamic symbol changed')
        imports.append({'slot': hex(slot), 'dynsym_index': index, 'name': name.decode(), 'relocation_type': 6})
    path = b'/home/ubuntu/hl/code_Mainnet/base/src/shell.rs'
    if read(data, 0x1ef309, 46)[1] != path or read(data, 0x5666e40, 16)[1] != struct.pack('<QII', 46, 48, 32):
        raise ValueError('shell Location changed')
    rows = []
    for start, end in RANGES:
        off, raw = read(data, start, end - start)
        rows.append({'start_va': hex(start), 'end_va': hex(end), 'bytes': len(raw),
                     'file_offset': hex(off), 'sha256': hashlib.sha256(raw).hexdigest()})
    return {'target_sha256': SHA256, 'ranges': rows,
            'schedule': {'pointer_rcx_null': 'default three-element table', 'pointer_nonnull_length_r8_zero': 'empty schedule',
                         'table_va': '0x216dd8', 'end_va': '0x216df0', 'body_hex': defaults.hex(),
                         'binary64_values': list(struct.unpack('<ddd', defaults))},
            'explicit_wait_calls': [{'site': '0x13c90ad', 'role': 'initial'}, {'site': '0x13c9255', 'role': 'loop'}],
            'wait_slot': {'va': '0x576e8c8', 'relative_addend': '0x13e4e40'},
            'exhaustion': {'format_slot': '0x576e040', 'distinct_helper': '0x14b5530',
                           'extra_explicit_wait_slot_call': False, 'helper_closure_closed': False},
            'sleep_imports': imports, 'nanosleep_call': '0x13c920d',
            'request_and_remaining_pointers': 'same stack buffer rsp+0x30', 'retry_errno_immediate': 4,
            'source': {'slot': '0x5666e38', 'path': path.decode(), 'line': 48, 'column': 32},
            'diagnostic': {'va': '0x1fceaf', 'descriptor_hex': descriptor.hex(), 'complete_rendering_proved': False},
            'relative_bindings': {hex(a): hex(v) for a, v in RELATIVE.items()},
            'instruction_controls': {hex(a): v for a, v in CONTROLS.items()},
            'captured_binary_executed': False,
            'limits': 'One retry routine and one exhaustion helper. Default values and explicit call-site budget observed; concrete Rust types, all callers, wait implementation, helper/trait-call closure, arbitrary f64 behavior, OS timing and runtime equivalence unproved.'}


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
        selected = [line for line in frames.splitlines() if any(f'pc={a:016x}..{b:016x}' in line for a, b in RANGES)]
        if len(selected) != 2:
            raise ValueError('native FDE confirmation failed')
        (output / 'frames.txt').write_text('\n'.join(selected) + '\n')
        for start, end in RANGES:
            asm = subprocess.check_output(['objdump', '-d', '-M', 'intel', '--insn-width=16',
                                          f'--start-address={start:#x}', f'--stop-address={end:#x}', str(snapshot)], text=True)
            ins = decode_export(asm, start, end, read(data, start, end - start)[1])
            required = set(CONTROLS) | {a for a, _ in RIP} | {0x13c92e6, 0x14b5571}
            if not {a for a in required if start <= a < end} <= set(ins):
                raise ValueError('controls/calls must be decoded instruction starts')
            if start == 0x13c9080:
                calls = [a for a, raw in ins.items() if raw.startswith(b'\xff\x15')
                         and a + 6 + struct.unpack_from('<i', raw, 2)[0] == 0x576e8c8]
                if calls != [0x13c90ad, 0x13c9255]:
                    raise ValueError('explicit wait-slot call denominator changed')
            (output / f'{start:x}.objdump.txt').write_text(asm.replace(str(snapshot), '<authenticated-node94>'))
    (output / 'records.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--output', type=Path, default=ROOT / 'work/shell-retry-schedule-94')
    args = parser.parse_args()
    print(json.dumps({'ranges': len(generate(args.binary, args.output)['ranges']), 'executed': False}))
