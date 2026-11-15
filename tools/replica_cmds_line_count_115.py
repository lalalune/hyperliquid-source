#!/usr/bin/env python3
"""Bind how node #115 counts lines in a replica_cmds file, and where the startup check flag comes from (74th stage).

Continues the stage 73 packet (open PR #6069). That packet found that the
startup helper 0x595b1a0 adds the line count from 0x1500e50 to the newest
command file's first height. This tool binds:

1. 0x1500e50: a '.lz4' suffix test (dword 0x347a6c2e at the end of the
   path); an '.lz4' path only runs a Once initialiser for the lazy cell
   0x64f01c0 (value word relocated to 0x1568de0, state 0x64f01d8) and then
   jumps back to the same code path as any other file;
2. the command: an argv of three slices, "wc" (2 bytes, 0x4659f2), "-l"
   (2 bytes, 0x4659f4) and the path, passed to 0x15b0450, which joins
   them with the separator at 0x468cca (" ") through 0x150d100;
3. the runner: slot 0x64e0960 (relocated to 0x1536720) starts "/bin/sh"
   (7 bytes, 0x466adc) with "-c" (2 bytes, 0x466ada) and the joined string,
   and its error text is 'Shell::output() failed. cmd: "{}". output: "{}"'
   (0x442e16);
4. the parse: a base-10 loop (mov edi, 10) over the output, with the error
   text 'file_n_lines empty wc output {}' (0x442df6);
5. the startup flag: the byte that 0x2b41b70 tests before calling slot
   0x64e7720 (cmp r12b, 1) is future byte +0x1; 0x2af0660 builds the future
   from its own state bytes +0x0..+0x10, and the poller 0x2aeaef0 fills that
   state at +0x1728 from its stack at rsp+0x320.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses.
"""
import argparse
import json
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import direct_calls, fixed, read_va, relative_relocations, rip_target

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-replica-cmds-line-count-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

LINE_COUNT = 0x1500e50
JOIN = 0x15b0450
SHELL = 0x1536720
SHELL_SLOT = 0x64e0960
LAZY_CELL = 0x64f01c0
LAZY_INIT = 0x1568de0
STARTUP = 0x2b41b70
STARTUP_CALLER = 0x2af0660

FIXED = {
    0x1500e71: '817c37fc2e6c7a34',      # cmp dword [rdi+rsi-4], '.lz4'
    0x1500e79: '750e',                  # jne 0x1500e89 (not .lz4)
    0x1500e81: '85c0',                  # test eax, eax (Once state)
    0x1500e83: '0f8595030000',          # jne 0x150121e (run the Once)
    0x1500e95: '48c744242802000000',    # len "wc" = 2
    0x1500eaa: '48c744243802000000',    # len "-l" = 2
    0x1500eb3: '48897c2440',            # argv[2].ptr = path
    0x1500eb8: '4889742448',            # argv[2].len
    0x1500ed1: '488d542420',            # lea rdx, [rsp+0x20] (argv)
    0x15011a8: 'bf0a000000',            # mov edi, 10 (decimal parse)
    0x1501262: '4889df',                # mov rdi, rbx (path back)
    0x1501265: '4c89f6',                # mov rsi, r14
    0x1501268: 'e91cfcffff',            # jmp 0x1500e89 (same command)
    0x1536752: 'ba07000000',            # len "/bin/sh" = 7
    0x1536776: 'ba02000000',            # len "-c" = 2
    0x2b41bae: '440fb66301',            # movzx r12d, byte [rbx+0x1]
    0x2b41d32: '4180fc01',              # cmp r12b, 1
    0x2b41d36: '0f8593010000',          # jne 0x2b41ecf (skip the check)
    0x2af07ef: '488b7b01',              # mov rdi, [rbx+0x1]
    0x2af082f: '48895329',              # mov [rbx+0x29], rdx
    0x2af087d: '410f100c24',            # movups xmm1, [r12] (r12 = rbx+0x28)
    0x2af09f0: '660f7f8424f0050000',    # movdqa [rsp+0x5f0], xmm0 (future +0x0)
    0x2aec10d: '660f6f842420030000',    # movdqa xmm0, [rsp+0x320]
    0x2aec116: 'f30f7f8328170000',      # movdqu [rbx+0x1728], xmm0
}
REFERENCES = (
    (0x1500e7b, b'\x8b\x05', 6, LAZY_CELL + 0x18),
    (0x1500e89, b'\x48\x8d\x05', 7, 0x4659f2),
    (0x1500e9e, b'\x48\x8d\x05', 7, 0x4659f4),
    (0x1500ed6, b'\xe8', 5, JOIN),
    (0x1500f1a, b'\xff\x15', 6, SHELL_SLOT),
    (0x150118b, b'\x48\x8d\x3d', 7, 0x442df6),
    (0x150121e, b'\x48\x8d\x05', 7, LAZY_CELL),
    (0x15b052f, b'\x48\x8d\x0d', 7, 0x468cca),
    (0x15b0546, b'\xe8', 5, 0x150d100),
    (0x1536743, b'\x48\x8d\x35', 7, 0x466adc),
    (0x1536767, b'\x48\x8d\x35', 7, 0x466ada),
    (0x1536865, b'\x48\x8d\x35', 7, 0x442e16),
    (0x2b41d3c, b'\xff\x15', 6, 0x64e7720),
    (0x595bb9c, b'\xff\x15', 6, 0x64e0958),        # mapper -> line count slot
    (0x2af0a5f, b'\xe8', 5, STARTUP),
    (0x2aec151, b'\xe8', 5, STARTUP_CALLER),
)
STRINGS = {
    0x4659f2: b'wc',
    0x4659f4: b'-l',
    0x468cca: b' ',
    0x466adc: b'/bin/sh',
    0x466ada: b'-c',
    0x442df7: b'file_n_lines empty wc output ',
    0x442e17: b'Shell::output() failed. cmd: "',
}
LINE_COUNT_SLOT = 0x64e0958
RELOCATIONS = {SHELL_SLOT: SHELL, LAZY_CELL: LAZY_INIT, LINE_COUNT_SLOT: LINE_COUNT}


def call_census(data, targets):
    """One pass over .text: direct E8 calls to each target."""
    import re
    import struct
    from freeze_snapshot_115 import text
    base, code = text(data)
    out = {t: [] for t in targets}
    for m in re.finditer(rb'\xe8', code):
        i = m.start()
        if i + 5 <= len(code):
            dest = base + i + 5 + struct.unpack_from('<i', code, i + 1)[0]
            if dest in out:
                out[dest].append(base + i)
    return out


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    for va, raw in STRINGS.items():
        if read_va(data, va, len(raw)) != raw:
            raise ValueError(f'string at {va:#x} changed')
    rel = relative_relocations(data)
    for slot, target in RELOCATIONS.items():
        if rel.get(slot) != target:
            raise ValueError(f'relocation at {slot:#x} changed')
    calls = call_census(data, (LINE_COUNT, JOIN, STARTUP, STARTUP_CALLER))
    if calls[LINE_COUNT] or calls[STARTUP_CALLER] != [0x2aec151]:
        raise ValueError('call census changed')
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'line_count': {
            'fn': hex(LINE_COUNT),
            'direct_calls': [hex(v) for v in calls[LINE_COUNT]],
            'reached_via': 'slot %s (R_X86_64_RELATIVE) from the stage 73 mapper at %s' % (hex(LINE_COUNT_SLOT), hex(0x595bb9c)),
            'lz4_suffix_test': hex(0x1500e71) + " cmp dword [rdi+rsi-4], 0x347a6c2e ('.lz4')",
            'lz4_path': 'Once on lazy cell %s (value word -> %s, state %s), then jmp %s: same command'
                        % (hex(LAZY_CELL), hex(LAZY_INIT), hex(LAZY_CELL + 0x18), hex(0x1500e89)),
            'argv': ['wc (0x4659f2, 2)', '-l (0x4659f4, 2)', 'path (rdi, rsi)'],
            'join': '%s joins argv with %s via %s' % (hex(JOIN), "0x468cca ' '", hex(0x150d100)),
            'join_direct_calls': len(calls[JOIN]),
            'runner': 'slot %s -> %s: "/bin/sh" (0x466adc, 7) "-c" (0x466ada, 2) + joined string; '
                      'error "Shell::output() failed. cmd: ..." (0x442e16)' % (hex(SHELL_SLOT), hex(SHELL)),
            'parse': 'base-10 loop (mov edi, 10 at 0x15011a8); empty output -> "file_n_lines empty wc output {}" (0x442df6)',
        },
        'startup_flag': {
            'test': hex(0x2b41d32) + ' cmp r12b, 1 on future byte +0x1 (0x2b41bae), else skip slot 0x64e7720',
            'startup_direct_calls': [hex(v) for v in calls[STARTUP]],
            'future_source': '0x2af0660 state +0x0..+0x10 -> state +0x28 (0x2af07ef, 0x2af082f) -> rsp+0x5a0 '
                             '(0x2af087d) -> future +0x0 (0x2af09f0)',
            'state_source': 'poller 0x2aeaef0 rsp+0x320 -> state +0x1728 (0x2aec10d, 0x2aec116); call 0x2aec151',
            'caller_direct_calls': [hex(v) for v in calls[STARTUP_CALLER]],
        },
        'gates_changed': False,
    }


def render(result):
    return (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()


def generate(binary=TARGET, output=PACKET):
    identity = manifest_item(ROOT, RELATIVE)
    check(binary, identity)
    if identity['sha256'] != SHA256:
        raise ValueError('pinned node #115 digest changed')
    data = binary.read_bytes()
    _, fdes, _ = fde_extents(data)
    result = bind(data, fdes)
    output.mkdir(parents=True, exist_ok=True)
    (output / 'evidence.json').write_bytes(render(result))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=PACKET)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args(argv)
    expected = (PACKET / 'evidence.json').read_bytes() if args.check else None
    result = generate(output=args.out)
    if args.check and (args.out / 'evidence.json').read_bytes() != expected:
        raise SystemExit('evidence.json does not match the committed packet')
    print('line_count calls=%s startup calls=%s' % (result['line_count']['direct_calls'],
                                                   result['startup_flag']['startup_direct_calls']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
