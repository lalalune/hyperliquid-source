#!/usr/bin/env python3
"""Bind the node #115 non-validator catch-up task poll 0x2b1df60 (69th stage).

Stage 68 found a third layout-A abci step 0x2d25620, reached only from the
task poll 0x2b1df60. This tool binds that poll's loop:

1. the poll is reached only through the R_X86_64_RELATIVE word at 0x6449fb0;
   before its loop it calls the shim 0x2d275d0 once and sets the block
   counter [rsp+0x28] to 0;
2. each iteration receives through 0x2b149d0 (its only direct call); a zero
   result panics with the message at 0x60608e ("client block recver ended
   before valid block") through slot 0x64df6b8; the receiver itself is not
   followed (networking boundary);
3. a received block goes through 0x2774590 (only direct call 0x2b1e3ee),
   whose only call of the wrapper 0x2d23610 leads to the stage 68 step;
4. the counter is incremented and saturates at u64::MAX; the box consensus
   time (+0x60 qword, +0x68 dword) is loaded;
5. caught-up test: counter >= 6 and the box consensus time plus 2 s +
   500000000 ns (time-of-day add slot 0x64e0f78, overflow / 86400 days via
   date add slot 0x64e0aa0, fallback tuple 0x4679d0) is strictly later than
   the wall clock (date signed, then seconds, then fraction);
6. otherwise, when counter % 10 == 0, it logs template 0x44bccf
   ("... [n_abci_blocks_seen: {}]") with the message at 0x606039
   ("non-validator abci state not caught up yet");
7. when caught up, it logs template 0x4309cd ("[abci_time] [wall_time]
   [round] [height]") with the message at 0x606063 ("using initial abci
   state from non-validator"), box +0x30 as the round argument, and copies
   the 0x470-byte engine value out of its state.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses; ends are exclusive.
"""
import argparse
import json
import re
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import fixed, read_va, relative_relocations, rip_target, text

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-nonvalidator-catchup-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

POLL = (0x2b1df60, 0x2b1f5f2)
POLL_RELOC = 0x6449fb0
SHIM, RECV, PER_BLOCK, WRAPPER, STEP = 0x2d275d0, 0x2b149d0, 0x2774590, 0x2d23610, 0x2d25620
STRINGS = {
    0x606039: b'non-validator abci state not caught up yet',
    0x606063: b'using initial abci state from non-validator',
    0x60608e: b'client block recver ended before valid block',
}
TEMPLATES = {
    0x44bccf: b' @@ [n_abci_blocks_seen: ',
    0x4309cd: b' @@ [abci_time: ',
}


def movabs(reg_byte, value):
    return (b'\x48' + bytes([reg_byte]) + struct.pack('<Q', value)).hex()


FIXED = {
    # loop entry: counter = 0
    0x2b1e1fd: '48c744242800000000',            # mov qword [rsp+0x28], 0
    # receive result: zero -> recver-ended panic
    0x2b1e257: '4883bc249001000000',            # cmp qword [rsp+0x190], 0
    0x2b1e260: '0f84590d0000',                  # je 0x2b1efbf
    # saturating counter increment
    0x2b1e5f6: '488b442428',                    # mov rax, [rsp+0x28]
    0x2b1e5fb: '48ffc0',                        # inc rax
    0x2b1e5fe: '48c7c1ffffffff',                # mov rcx, -1
    0x2b1e605: '480f44c1',                      # cmove rax, rcx
    0x2b1e609: '4889442428',                    # mov [rsp+0x28], rax
    # box consensus time (+0x60 qword, +0x68 dword)
    0x2b1e616: '488b4860',                      # mov rcx, [rax+0x60]
    0x2b1e622: '8b4868',                        # mov ecx, [rax+0x68]
    # counter >= 6
    0x2b1e652: '4883f806',                      # cmp rax, 6
    0x2b1e65e: '0f8245010000',                  # jb 0x2b1e7a9 (skip test)
    # deadline = consensus time + 2 s + 500000000 ns
    0x2b1e682: 'ba02000000',                    # mov edx, 2
    0x2b1e692: 'b90065cd1d',                    # mov ecx, 500000000
    0x2b1e6a5: movabs(0xb9, 0xffdf3b645a1cac08),
    0x2b1e6b2: movabs(0xba, 0xffbe76c8b4395810),
    0x2b1e6c5: movabs(0xb9, 0xffff574000000000),
    0x2b1e6d2: movabs(0xba, 0xfffeae7ffffeae81),
    0x2b1e6f6: movabs(0xb9, 0x1845c8a0ce512957),  # /86400 magic
    0x2b1e70a: '48c1ea0d',                      # shr rdx, 13
    # deadline vs wall clock (date signed, seconds, fraction)
    0x2b1e744: '8b12',                          # mov edx, [rdx]          (deadline date)
    0x2b1e746: '3b542474',                      # cmp edx, [rsp+0x74]     (now date)
    0x2b1e74a: '0f9fc2',                        # setg dl
    0x2b1e784: '8b09',
    0x2b1e786: '3b4c2478',                      # seconds
    0x2b1e78a: '0f97c2',                        # seta dl
    0x2b1e78f: '8b00',
    0x2b1e791: '3b44247c',                      # fraction
    0x2b1e795: '760d',                          # jbe 0x2b1e7a4 (not later -> not caught up)
    0x2b1e797: 'e917030000',                    # jmp 0x2b1eab3 (caught up)
    0x2b1e79c: '84d2',                          # test dl, dl
    0x2b1e79e: '0f850f030000',                  # jne 0x2b1eab3 (caught up)
    # counter % 10 == 0 -> log
    0x2b1e7a9: movabs(0xb9, 0xcccccccccccccccd),
    0x2b1e7b3: '480fafc1',                      # imul rax, rcx
    0x2b1e7b7: '48d1c8',                        # ror rax, 1
    0x2b1e7ba: movabs(0xb9, 0x199999999999999a),
    0x2b1e7c4: '4839c8',                        # cmp rax, rcx
    0x2b1e7cf: '0f83cb010000',                  # jae 0x2b1e9a0 (no log)
    # caught up: round = box +0x30; engine value copy 0x470
    0x2b1eabb: '488b4030',                      # mov rax, [rax+0x30]
    0x2b1ecc9: 'ba70040000',                    # mov edx, 0x470
}
REFERENCES = (
    (0x2b1e1f8, b'\xe8', 5, SHIM),
    (0x2b1e252, b'\xe8', 5, RECV),
    (0x2b1e3ee, b'\xe8', 5, PER_BLOCK),
    (0x27745e0, b'\xe8', 5, WRAPPER),
    (0x2b1e697, b'\xff\x15', 6, 0x64e0f78),      # time-of-day add
    (0x2b1e710, b'\xff\x15', 6, 0x64e0aa0),      # date add
    (0x2b1e75c, b'\x48\x8d\x0d', 7, 0x4679d4),   # fallback tuple seconds
    (0x2b1e879, b'\x48\x8d\x05', 7, 0x606039),
    (0x2b1e94e, b'\x48\x8d\x3d', 7, 0x44bccf),
    (0x2b1eb71, b'\x48\x8d\x05', 7, 0x606063),
    (0x2b1ec78, b'\x48\x8d\x3d', 7, 0x4309cd),
    (0x2b1ecce, b'\xff\x15', 6, 0x64df508),      # memcpy slot
    (0x2b1efbf, b'\x48\x8d\x3d', 7, 0x60608e),
    (0x2b1efd2, b'\xff\x15', 6, 0x64df6b8),      # panic with message
)


def call_census(data, targets):
    base, code = text(data)
    want = set(targets)
    out = {t: [] for t in targets}
    for m in re.finditer(rb'\xe8', code):
        i = m.start()
        if i + 5 <= len(code):
            t = base + i + 5 + struct.unpack_from('<i', code, i + 1)[0]
            if t in want:
                out[t].append(base + i)
    return out


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    for va, text_ in STRINGS.items():
        if read_va(data, va, len(text_)) != text_:
            raise ValueError(f'string at {va:#x} changed')
    for va, piece in TEMPLATES.items():
        if piece not in read_va(data, va, 0x60):
            raise ValueError(f'template at {va:#x} changed')
    if relative_relocations(data).get(POLL_RELOC) != POLL[0]:
        raise ValueError('poll relocation changed')
    hits = [f for f in fdes if f['start'] == POLL[0]]
    if len(hits) != 1 or hits[0]['end'] != POLL[1]:
        raise ValueError('poll FDE changed')
    census = call_census(data, (POLL[0], SHIM, RECV, PER_BLOCK, WRAPPER))
    expect = {POLL[0]: [], SHIM: [0x2b1e1f8], RECV: [0x2b1e252], PER_BLOCK: [0x2b1e3ee], WRAPPER: [0x27745e0]}
    if census != expect:
        raise ValueError('call census changed')

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'poll': {'fde': [hex(v) for v in POLL], 'reached_by': 'R_X86_64_RELATIVE at %s, no direct call' % hex(POLL_RELOC)},
        'loop_entry': {'shim_call': hex(0x2b1e1f8) + ' -> ' + hex(SHIM), 'counter_reset': hex(0x2b1e1fd) + ' [rsp+0x28] = 0'},
        'receive': {
            'call': hex(0x2b1e252) + ' -> ' + hex(RECV) + ' (only direct call; receiver not followed)',
            'end': 'result word 0 -> %s message %s via slot 0x64df6b8' % (hex(0x2b1efbf), STRINGS[0x60608e].decode()),
        },
        'per_block': '%s -> %s; its only call of %s is %s; %s reaches the stage 68 step %s'
                     % (hex(0x2b1e3ee), hex(PER_BLOCK), hex(WRAPPER), hex(0x27745e0), hex(WRAPPER), hex(STEP)),
        'counter': '[rsp+0x28] += 1, saturating at u64::MAX (%s)' % hex(0x2b1e605),
        'caught_up': {
            'requires': 'counter >= 6 (%s) and box consensus time (+0x60/+0x68) + 2 s + 500000000 ns '
                        'strictly later than the wall clock' % hex(0x2b1e652),
            'deadline': 'slot 0x64e0f78 (time of day add), days = overflow / 86400 (magic 0x1845c8a0ce512957 >> 13), '
                        'slot 0x64e0aa0 (date add); failure -> fallback tuple 0x4679d0',
            'compare': 'date signed (setg), then seconds (seta), then fraction (jbe -> not caught up)',
            'log': 'template 0x4309cd [abci_time][wall_time][round][height], message 0x606063 %r, round = box +0x30'
                   % STRINGS[0x606063].decode(),
            'engine_value_copy': '0x470 bytes via slot 0x64df508 at %s' % hex(0x2b1ecce),
        },
        'not_caught_up_log': {
            'when': 'counter % 10 == 0 (multiply by 0xcccccccccccccccd, ror 1, compare 0x199999999999999a)',
            'log': 'template 0x44bccf [n_abci_blocks_seen], message 0x606039 %r' % STRINGS[0x606039].decode(),
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
    generate(output=args.out)
    if args.check and (args.out / 'evidence.json').read_bytes() != expected:
        raise SystemExit('evidence.json does not match the committed packet')
    print('catch-up poll bound')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
