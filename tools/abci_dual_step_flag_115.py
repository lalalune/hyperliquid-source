#!/usr/bin/env python3
"""Bind the node #115 engine value flag +0x46d, its source and the two step results (38th stage).

Continues #6006 and #6008. #6008 found that 0x5a6bfb0 runs the layout-B step
0x5a08720 on a clone and the layout-A step 0x5a07ec0 through 0x5a08f80, and
that 0x5a08f80 puts a byte (0x5a6bfb0 +0x431, set only when the poller byte
+0x2a1a is non-zero) at engine value +0x46d. This tool binds:

1. what both steps do with engine value +0x46d: they read it, and only when
   the date or the hour/3 bucket differs from the value stored at +0x460 they
   pass it as the last argument to a thread spawn (A: 0x56141f0, B:
   0x56150d0); the spawned closure calls the thread body 0x4d98c40 with the
   flag & 1;
2. the thread body: a non-zero flag first calls slot 0x64e9540 (error text
   "tar_evm_checkpoints failed: ") with the date one day back; both flag
   values then call slot 0x64e9548 (error text
   "prune_lowest_evm_checkpoints failed: ");
3. where the poller byte comes from: both pollers copy state +0x118..+0x158
   to +0xae8 and read +0xb00 (= +0x118 + 0x18) into +0x2a1a; +0x118 is the
   setter argument built at +0x90, whose byte +0x18 is the constant 0 that
   the merged #5892 tool pins (output_flags_path_115);
4. the two results in 0x5a6bfb0: the B engine value is built with +0x46d = 0
   and the B step result is freed unread; 0x5a08f80 frees the A step result
   unread and returns the engine value, which 0x5a6bfb0 passes with the name
   "node_slow_abci_engine" to slot 0x64ebc98.

The bodies behind slots 0x64e9540 and 0x64e9548 are not disassembled.
The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses.
"""
import argparse
import json
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import read_va, fixed, rip_target, relative_relocations, direct_calls
import output_flags_path_115

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-abci-dual-step-flag-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

STEP_A, STEP_B = 0x5a07ec0, 0x5a08720
SPAWN_A, SPAWN_B = 0x56141f0, 0x56150d0
BODY = 0x4d98c40
WRAP_A = 0x5a08f80
RUN = 0x5a6bfb0
TAR_SLOT, PRUNE_SLOT = 0x64e9540, 0x64e9548
TAR_TEXT = (0x44bf20, b'tar_evm_checkpoints failed: ')
PRUNE_TEXT = (0x43905e, b'prune_lowest_evm_checkpoints failed: ')
SLOW_NAME = (0x93afc4, b'node_slow_abci_engine')

FIXED = {
    # A step 0x5a07ec0: flag read, 3-hour bucket check, flag as last spawn argument
    0x5a0836d: '410fb6ae6d0400',        # movzx ebp, byte [r14+0x46d]
    0x5a0837a: '40886c2448',            # mov [rsp+0x48], bpl
    0x5a08395: '413b8660040000',        # cmp eax, [r14+0x460]          (stored date)
    0x5a083bc: '69c9ab000000',          # imul ecx, ecx, 0xab
    0x5a083c2: 'c1e909',                # shr ecx, 9                    (hour / 3)
    0x5a083c8: '69c0ab000000',          # imul eax, eax, 0xab
    0x5a083ce: 'c1e809',                # shr eax, 9
    0x5a083d6: '38c1',                  # cmp cl, al
    0x5a08454: '0fb66c2448',            # movzx ebp, byte [rsp+0x48]
    0x5a0846b: '400fb6c5',              # movzx eax, bpl
    0x5a08482: '50',                    # push rax                      (last argument)
    # B step 0x5a08720: same shape, box offsets +0xb70 (#6006)
    0x5a08bcd: '410fb6ae6d0400',        # movzx ebp, byte [r14+0x46d]
    0x5a08bda: '40886c2448',            # mov [rsp+0x48], bpl
    0x5a08bf5: '413b8660040000',        # cmp eax, [r14+0x460]
    0x5a08c1c: '69c9ab000000',
    0x5a08c22: 'c1e909',
    0x5a08c36: '38c1',
    0x5a08cb4: '0fb66c2448',            # movzx ebp, byte [rsp+0x48]
    0x5a08ccb: '400fb6c5',              # movzx eax, bpl
    0x5a08ce2: '50',                    # push rax
    # spawns: last argument copied into the closure at +0x30
    0x5614472: '0fb68c24680200',        # movzx ecx, byte [rsp+0x268]
    0x561447a: '888c2480000000',        # mov [rsp+0x80], cl            (closure rsp+0x50 + 0x30)
    0x5615352: '0fb68c24680200',
    0x561535a: '888c2480000000',
    # closure call_once: flag & 1 to the body
    0x561f985: '0fb66f30',              # movzx ebp, byte [rdi+0x30]
    0x561f9d4: '400fb6f5',              # movzx esi, bpl
    0x561f9d8: '83e601',                # and esi, 1
    0x5620135: '0fb66f30',
    0x5620184: '400fb6f5',
    0x5620188: '83e601',
    # thread body 0x4d98c40
    0x4d98c61: '85f6',                  # test esi, esi
    0x4d98c63: '0f84e8000000',          # je 0x4d98d51                  (skip the tar call)
    0x4d98c8e: 'beffffffff',            # mov esi, -1                   (date - 1 day)
    # pollers: +0x118 block -> +0xae8, byte +0xb00 -> +0x2a1a
    0x2aebde4: '4c8dabe80a0000',        # lea r13, [rbx+0xae8]
    0x2aebe97: 'f30f6f83180100',        # movdqu xmm0, [rbx+0x118]
    0x2aebe9f: 'f30f6f8b280100',        # movdqu xmm1, [rbx+0x128]
    0x2aebf3f: 'f3410f7f4d10',          # movdqu [r13+0x10], xmm1
    0x2aebf45: '410f114500',            # movups [r13+0x0], xmm0
    0x2aebfa6: '0fb683000b0000',        # movzx eax, byte [rbx+0xb00]
    0x2aebfdc: '88831a2a0000',          # mov [rbx+0x2a1a], al
    0x2cb7404: '4c8dabe80a0000',
    0x2cb74b7: 'f30f6f83180100',
    0x2cb74bf: 'f30f6f8b280100',
    0x2cb755f: 'f3410f7f4d10',
    0x2cb7565: '410f114500',
    0x2cb75c6: '0fb683000b0000',
    0x2cb75fc: '88831a2a0000',
    # 0x5a6bfb0: B engine value +0x46d = 0 (value at rsp+0x1240), A flag, slow engine name
    0x5a6c157: 'c68424ad160000',        # mov byte [rsp+0x16ad], 0
    0x5a6c179: '488bb424b00200',        # mov rsi, [rsp+0x2b0]          (B result tag)
    0x5a6c5d3: 'ba38040000',            # mov edx, 0x438
    0x5a6c5db: '4084ed',                # test bpl, bpl
    0x5a6c5e0: 'c6842439590000',        # mov byte [rsp+0x5939], 1      (0x5508 + 0x431)
    0x5a6c614: 'b915000000',            # mov ecx, 21                   (len node_slow_abci_engine)
    # 0x5a08f80: flag to engine value +0x46d (value at rsp+0x10), A result freed
    0x5a08f92: '4c8bb620040000',        # mov r14, [rsi+0x420]
    0x5a08fa8: '0fb6ae31040000',        # movzx ebp, byte [rsi+0x431]
    0x5a0900c: '4088ac247d0400',        # mov [rsp+0x47d], bpl
    0x5a09024: '488bb424800400',        # mov rsi, [rsp+0x480]          (A result tag)
}
REFERENCES = (
    # (instruction va, prefix, length, target)
    (0x5a08485, b'\xe8', 5, SPAWN_A),
    (0x5a08ce5, b'\xe8', 5, SPAWN_B),
    (0x5614547, b'\x48\x8d\x05', 7, 0x64aa788),     # closure vtable A
    (0x5615427, b'\x48\x8d\x05', 7, 0x64aa7c8),     # closure vtable B
    (0x561f9de, b'\xff\x15', 6, 0x64e86a0),         # body slot A
    (0x562018e, b'\xff\x15', 6, 0x64eb2a8),         # body slot B
    (0x4d98cab, b'\xff\x15', 6, TAR_SLOT),
    (0x4d98cfa, b'\x48\x8d\x05', 7, TAR_TEXT[0] - 1),
    (0x4d98d59, b'\xff\x15', 6, PRUNE_SLOT),
    (0x4d98d9f, b'\x48\x8d\x05', 7, PRUNE_TEXT[0] - 1),
    (0x5a6c16a, b'\xe8', 5, STEP_B),
    (0x5a6c5f8, b'\xe8', 5, WRAP_A),
    (0x5a6c5fd, b'\x48\x8d\x15', 7, SLOW_NAME[0]),
    (0x5a6c619, b'\xff\x15', 6, 0x64ebc98),
    (0x5a0901f, b'\xe8', 5, STEP_A),
)
RELOCS = {
    0x64aa7a0: 0x561f970,      # vtable A call_once
    0x64aa7e0: 0x5620120,      # vtable B call_once
    0x64e86a0: BODY,
    0x64eb2a8: BODY,
    0x64ebc98: 0x5649680,
}


def hour_bucket(hour):
    """The step's (hour * 0xab) >> 9 on a byte-sized hour."""
    return ((hour & 0xff) * 0xab) >> 9


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    rel = relative_relocations(data)
    for slot, target in RELOCS.items():
        if rel.get(slot) != target:
            raise ValueError(f'relocation at {slot:#x} changed')
    for va, text in (TAR_TEXT, PRUNE_TEXT, SLOW_NAME):
        if read_va(data, va, len(text)) != text:
            raise ValueError(f'string at {va:#x} changed')
    if read_va(data, TAR_TEXT[0] - 1, 1)[0] != len(TAR_TEXT[1]) or \
            read_va(data, PRUNE_TEXT[0] - 1, 1)[0] != len(PRUNE_TEXT[1]):
        raise ValueError('template literal lengths changed')
    buckets = [hour_bucket(h) for h in range(24)]
    if buckets != [h // 3 for h in range(24)]:
        raise ValueError('hour bucket arithmetic changed')
    census = {hex(t): [hex(v) for v in direct_calls(data, t)]
              for t in (SPAWN_A, SPAWN_B, STEP_A, STEP_B, WRAP_A)}
    if census[hex(SPAWN_A)] != ['0x5a08485'] or census[hex(SPAWN_B)] != ['0x5a08ce5']:
        raise ValueError('spawn call census changed')
    setter = output_flags_path_115.bind(data)
    if setter['setter_bytes'].get('0x18') != 'constant 0':
        raise ValueError('setter byte +0x18 is no longer the constant 0 (#5892)')

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'flag_in_steps': {
            'A': 'step %s reads engine value +0x46d at 0x5a0836d; spawn %s at 0x5a08485' % (hex(STEP_A), hex(SPAWN_A)),
            'B': 'step %s reads engine value +0x46d at 0x5a08bcd; spawn %s at 0x5a08ce5' % (hex(STEP_B), hex(SPAWN_B)),
            'gate': 'spawn only when the current date differs from engine value +0x460 '
                    'or hour/3 differs (imul 0xab, shr 9 on both hours)',
            'hour_buckets': buckets,
            'argument': 'flag pushed as the last stack argument; spawn copies it to closure +0x30',
        },
        'thread': {
            'closure_vtables': {'A': '0x64aa788 (call_once 0x561f970)', 'B': '0x64aa7c8 (call_once 0x5620120)'},
            'body': '%s via slots 0x64e86a0 (A) and 0x64eb2a8 (B), esi = closure +0x30 & 1' % hex(BODY),
            'flag_set': 'date one day back (esi = -1), then slot %s; error text %r' % (hex(TAR_SLOT), TAR_TEXT[1].decode()),
            'always': 'slot %s; error text %r' % (hex(PRUNE_SLOT), PRUNE_TEXT[1].decode()),
            'not_disassembled': [hex(TAR_SLOT), hex(PRUNE_SLOT)],
        },
        'flag_source': {
            'pollers': ['0x2aeaef0', '0x2cb6500'],
            'copy': 'state +0x118..+0x158 -> +0xae8..+0xb28 (lea r13, [rbx+0xae8])',
            'read': '+0xb00 = +0xae8 + 0x18 -> +0x2a1a (0x2aebfa6/0x2aebfdc, 0x2cb75c6/0x2cb75fc)',
            'value': 'setter argument byte +0x18 = %s (#5892 tool)' % setter['setter_bytes']['0x18'],
            'to_engine_value': '0x5a6bfb0 +0x431 = 1 only when the byte is non-zero (0x5a6c5db, 0x5a6c5e0); '
                               '0x5a08f80 stores +0x431 at engine value +0x46d (0x5a08fa8, 0x5a0900c)',
        },
        'results_in_run': {
            'B': 'engine value +0x46d stored 0 (0x5a6c157); step result tag read at 0x5a6c179 and freed',
            'A': 'step result tag read at 0x5a09024 and freed; engine value returned',
            'after_A': 'engine value passed with %r (len %d) to slot 0x64ebc98 -> 0x5649680'
                       % (SLOW_NAME[1].decode(), len(SLOW_NAME[1])),
            'compared': False,
        },
        'direct_call_census': census,
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
    print('flag source: %s' % result['flag_source']['value'])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
