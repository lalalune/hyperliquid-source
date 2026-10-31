#!/usr/bin/env python3
"""Digest-bound node #94 static traffic-recorder seed validation; never executes the target."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess

from artifacts import ROOT, check
from elf_index import sections, unwind_index

# Comment seeds imported from references/can1357-hl net_utils/src/tcp/traffic_recorder.rs.
SEEDS = ('0x3D13CD0', '0x3D21670', '0x3D0EEE0', '0x3D1DA50', '0x3D1DDE0', '0x3D1E500')

# Independently decoded FDE pc ranges (half-open) keyed by role.
RANGES = {
    'recorder-poll-a': (0x3D13CD0, 0x3D1438D),
    'recorder-poll-b': (0x3D14390, 0x3D14819),
    'report-task': (0x3D21670, 0x3D2198F),
    'sleep-from-f64': (0x3D0EEE0, 0x3D0F26A),
    'format-helper-1': (0x3D1DA50, 0x3D1DDD8),
    'format-helper-2': (0x3D1DDE0, 0x3D1E168),
    'format-helper-3': (0x3D1E500, 0x3D1E82D),
    'caller-a': (0x3CFD380, 0x3CFD496),
    'caller-b': (0x3CFDD60, 0x3CFDEE6),
    'caller-report': (0x3D13840, 0x3D13CC9),
    'caller-c': (0x3D12780, 0x3D12F16),
    'caller-d': (0x3D21990, 0x3D21D5F),
}

# One instruction-level control per claimed observation, exact bytes.
CONTROLS = {
    0x3D13D0A: '80bb6801000000',  # first-sample gate on future+0x168
    0x3D13D16: 'c6836801000001',  # one-shot first-sample flag set
    0x3D13D7E: 'f048015058',      # lock addq elapsed -> stats+0x58
    0x3D13D8A: 'f048ff4018',      # lock incq stats+0x18
    0x3D13D92: '31c948874810',    # xorl ecx; xchgq rcx, inner+0x10 pending drain (seed A)
    0x3D13D98: '48398b60010000',  # overrun gate: cmp drained vs future+0x160 budget
    0x3D13DA5: 'f048ff4020',      # lock incq stats+0x20 overruns
    0x3D13DBE: 'f048014260',      # lock addq (bytes-budget) -> stats+0x60
    0x3D13DC8: '0f8403010000',    # empty drain jumps to waker handoff
    0x3D13DD2: 'f048ff4028',      # lock incq stats+0x28 non-empty drains
    0x3D13DDA: '48c1e809',        # shrq $9 before the 1953125 multiply
    0x3D13DDE: '49bc535a9ba02fb84400',  # movabsq 0x44B82FA09B5A53 (ceil(2^75/5^9))
    0x3D13EA6: 'ba80000000be48000000',  # direction slot bytes -> stats+0x80/count +0x48
    0x3D13EB4: 'ba88000000be40000000',  # direction slot bytes -> stats+0x88/count +0x40
    0x3D13EBE: 'f048ff0430',      # lock incq (counters, rsi) selected count slot
    0x3D13EC3: 'f048010c10',      # lock addq rcx, (counters, rdx) selected byte slot
    0x3D13ECC: 'f048014868',      # lock addq elapsed -> stats+0x68
    0x3D13EDB: 'f0480fb14d28',    # waker state lock cmpxchgq inner+0x28
    0x3D14039: 'e8a2aeffff',      # call 0x3D0EEE0 sleep-from-f64 poll
    0x3D14076: 'f00fb00d0224a701',  # lock cmpxchgb global bucket-table lock 0x5786480
    0x3D14126: 'e825990000',      # call 0x3D1DA50 format helper
    0x3D1412B: '48b80000000000003e40',  # movabsq 30.0 seconds into sleep future
    0x3D14135: '488983b8000000',  # store 30.0 at future+0xB8
    0x3D14447: 'f048015058',      # copy B: lock addq elapsed -> stats+0x58
    0x3D14457: 'f048ff4018',      # copy B: lock incq stats+0x18
    0x3D14463: '31c948874810',    # copy B: xchgq drain on inner+0x10 (seed claim)
    0x3D14469: '48398be0000000',  # copy B: overrun gate vs future+0xE0 budget
    0x3D14476: 'f048ff4020',      # copy B: lock incq stats+0x20
    0x3D2175E: 'e8edc2ffff',      # report task: call 0x3D1DA50 format helper
    0x3D21763: '48b80000000000003e40',  # report task: movabsq 30.0 seconds
    0x3D2176D: '488983d8000000',  # store 30.0 at future+0xD8
    0x3D217C2: 'f00fb00db64ca601',  # report task: same global lock 0x5786480
}

STRINGS = {
    0x5BC78D: b'tcp_traffic',
    0x5BC798: b'traffic_logger',
    0x5BC7A6: b'In',
    0x5BC7A8: b'Out',
    0x5BC7AB: b'profiled_rw_lock_increment',
    0x7CE45A: b'overflow when adding duration to instant',
}

MAGIC = 0x44B82FA09B5A53

EXPECTED_CALLERS = {
    0x3D13CD0: [0x3CFD416],
    0x3D14390: [0x3CFDDF4],
    0x3D21670: [0x3D13B5C],
    0x3D0EEE0: [0x3D12B0B, 0x3D14039],
    0x3D1DA50: [0x3D14126, 0x3D2175E],
    0x3D1DDE0: [0x3D12C31, 0x3D21B7A],
    0x3D1E500: [0x3D12CB1, 0x3D21BF1],
}


def mapped(data, va, size):
    matches = [s for s in sections(data) if s['type'] != 8 and
               s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError(f'No unique file-backed mapping: {va:#x}+{size}')
    offset = matches[0]['offset'] + va - matches[0]['address']
    return offset, data[offset:offset + size]


def expect(data, va, value):
    if mapped(data, va, len(value))[1] != value:
        raise ValueError(f'Instruction/data control changed at {va:#x}')


def static_controls(data):
    """Independent byte controls for every claimed traffic-recorder observation."""
    for va, value in CONTROLS.items():
        expect(data, va, bytes.fromhex(value))
    for va, value in STRINGS.items():
        expect(data, va, value)
    return [{'va': hex(va), 'bytes': CONTROLS[va]} for va in sorted(CONTROLS)]


def fde_ranges(data):
    """Decode the .eh_frame pc ranges covering the traffic-recorder family."""
    _, entries = unwind_index(data)
    starts = [e['start'] for e in entries]
    import bisect
    result = {}
    for role, (begin, _end) in RANGES.items():
        index = bisect.bisect_right(starts, begin) - 1
        fde = entries[index]['fde']
        pcrel = struct.unpack_from('<i', data, fde + 8)[0]
        pc_begin = fde + 8 + pcrel
        pc_range = struct.unpack_from('<I', data, fde + 12)[0]
        if pc_begin != begin:
            raise ValueError(f'FDE start disagrees for {role}: {pc_begin:#x}')
        result[role] = (pc_begin, pc_begin + pc_range)
    expected = {role: tuple(pair) for role, pair in RANGES.items()}
    if result != expected:
        raise ValueError(f'Decoded FDE ranges disagree: {result}')
    return result


def division_identity(exhaustive_bits=24, samples=1_000_007):
    """The observed multiplier computes bytes // 10**9 exactly (bytes as nanoseconds -> seconds).

    x = bytes >> 9 loses only the 2**9 factor of 10**9 = 2**9 * 5**9, so the
    check is x * MAGIC >> 75 == x // 5**9 for every x = bytes >> 9 < 2**55.
    MAGIC == ceil(2**75 / 5**9) is proven exactly; the division identity is
    verified exhaustively for x < 2**24, at boundaries near 2**55, and at
    deterministic samples across [0, 2**55).
    """
    if MAGIC != -(-(1 << 75) // 5 ** 9):
        raise ValueError('Multiplier is not ceil(2^75/5^9)')
    if MAGIC != -(-(1 << 84) // 10 ** 9):
        raise ValueError('Multiplier is not ceil(2^84/10^9)')
    for x in range(1 << exhaustive_bits):
        if ((x * MAGIC) >> 75) != x // 5 ** 9:
            raise ValueError(f'Division identity fails at {x:#x}')
    for base in (1 << 55) - 1, (1 << 54), (1 << 48), (1 << 40):
        for x in range(max(0, base - 4), base + 5):
            if ((x * MAGIC) >> 75) != x // 5 ** 9:
                raise ValueError(f'Division identity fails at boundary {x:#x}')
    step = (1 << 55) // samples
    for x in range(0, 1 << 55, max(1, step)):
        if ((x * MAGIC) >> 75) != x // 5 ** 9:
            raise ValueError(f'Division identity fails at sample {x:#x}')
    # End-to-end form actually encoded in the binary: shift, then mulhi, then >>11.
    for b in (0, 1, 511, 512, 10 ** 9 - 1, 10 ** 9, 10 ** 9 + 1, 2 ** 55 - 1, (1 << 64) - 1):
        x = b >> 9
        if (((x * MAGIC) >> 64) >> 11) != b // 10 ** 9:
            raise ValueError(f'Encoded division shape fails at {b:#x}')
    return {'multiplier': hex(MAGIC), 'is_ceil_2_75_over_5_9': True,
            'exhaustive_below': hex(1 << exhaustive_bits),
            'sampled_stride': hex(max(1, step)),
            'probes': 'shift-then-mulhi-then-shr11 shape verified at 2^64-scale boundaries'}


def locate_objdump():
    candidates = []
    if os.environ.get('LLVM_OBJDUMP'):
        candidates.append(os.environ['LLVM_OBJDUMP'])
    candidates += ['llvm-objdump', '/opt/homebrew/opt/llvm/bin/llvm-objdump',
                   '/usr/local/opt/llvm/bin/llvm-objdump', 'objdump']
    import shutil
    for candidate in candidates:
        found = shutil.which(candidate)
        if found:
            return found
    raise ValueError('No llvm-objdump or objdump found for the caller census')


def direct_callers(binary, objdump):
    """Stream the complete .text disassembly once and collect direct call sites."""
    pattern = re.compile(r'^\s*([0-9a-f]+):\s+(?:[0-9a-f]{2}\s+)*callq?\s+(?:0x)?0*([0-9a-f]+)\b')
    wanted = {hex(va) for va in EXPECTED_CALLERS}
    found = {va: [] for va in EXPECTED_CALLERS}
    with subprocess.Popen([objdump, '-d', '-j', '.text', str(binary)],
                          stdout=subprocess.PIPE, text=True) as proc:
        for line in proc.stdout:
            match = pattern.match(line)
            if not match:
                continue
            target = int(match[2], 16)
            if target in found:
                found[target].append(int(match[1], 16))
        if proc.wait() != 0:
            raise ValueError('Full .text disassembly failed')
    for target, sites in found.items():
        if sites != EXPECTED_CALLERS[target]:
            raise ValueError(f'Direct caller set changed for {target:#x}: {sites}')
    return {hex(t): [hex(s) for s in found[t]] for t in sorted(found)}


def run(binary, output):
    item = next(x for x in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                if x['path'] == 'artifacts/node/94/hl-node')
    check(binary, item)
    data = binary.read_bytes()
    controls = static_controls(data)
    ranges = fde_ranges(data)
    identity = division_identity()
    objdump = locate_objdump()
    callers = direct_callers(binary, objdump)
    output.mkdir(parents=True, exist_ok=True)
    raw = {}
    for name in ('recorder-poll-a', 'recorder-poll-b', 'report-task', 'sleep-from-f64'):
        begin, end = RANGES[name]
        command = [objdump, '-d', f'--start-address={begin:#x}', f'--stop-address={end:#x}', str(binary)]
        text = subprocess.check_output(command, text=True)
        text = text.replace(str(binary), '<authenticated-node94>')
        (output / f'{name}.objdump.txt').write_text(text)
        offset, body = mapped(data, begin, end - begin)
        raw[name] = {'start_va': hex(begin), 'end_va': hex(end), 'file_offset': hex(offset),
                     'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}
    result = {'target_sha256': item['sha256'], 'target_bytes': len(data),
              'seeds': list(SEEDS), 'ranges': {k: [hex(a), hex(b)] for k, (a, b) in ranges.items()},
              'instruction_controls': controls,
              'string_anchors': {hex(va): value.decode() for va, value in STRINGS.items()},
              'magic_division': identity,
              'direct_callers_in_decoded_text': callers,
              'disassembler': objdump,
              'captured_binary_executed': False,
              'limits': 'Static seed validation of the traffic-recorder family only; '
                        'no full-caller completeness for indirect dispatch, no live behavior, '
                        'no Rust build, and no component gate. The reference elapsed/budget '
                        'model is corrected: the binary advances the stored sample instant by '
                        'the drained byte count in nanoseconds (floor-divide by 1e9 proven '
                        'below 2^24, sampled to 2^55) instead of storing elapsed as the budget.'}
    (output / 'records.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'artifacts/node/94/hl-node')
    parser.add_argument('--output', type=Path, default=ROOT / 'work/traffic-recorder-94')
    args = parser.parse_args()
    print(json.dumps(run(args.binary.resolve(), args.output), indent=2))
