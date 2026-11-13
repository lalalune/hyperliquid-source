#!/usr/bin/env python3
"""Bind the node #115 catch-up task's initial engine value and its output (70th stage).

Continues the non-validator catch-up poll 0x2b1df60 (#6060) and the third
abci step 0x2d25620 (#6058). This tool binds:

1. the shim 0x2d275d0: byte-identical to the layout-A engine value builder
   0x5a08f80 (#6008) except its step call (0x2d25620 instead of 0x5a07ec0);
   it fills 0x450 bytes through slot 0x64e80e8 (0x38c6590), stores the box
   (+0x450), an Arc (+0x458), 0xf6401a (+0x460), 0 (+0x468), two bytes
   (+0x46c, +0x46d), runs the step once and returns the 0x470-byte value;
2. 0x38c6590: copies the input's first 0x420 bytes and registers the
   singleton key 'abci_engine' with value 'true' when the input's first
   dword is 2, else 'false' (slot 0x64e11e0 -> 0x1560e30, template
   '{}::{}', panic 'Singleton already created: ');
3. the poll's shim input: first qword 2, box = future +0x320 (stack
   [rsp+0x990] after the 0x350-byte future copy from the task cell +0x40),
   Arc {1, 1, [box+0x28]}, word 0 at +0x430;
4. the future's builder 0x2b41b70: WARN reference to 'running non-validator
   to get initial abci state for consensus', future +0x320 = [state+0x50]
   = result +0x380 of 0x2af45f0, task name 'initial_slow_state_for_join'
   (27 bytes), spawned through 0x2b3aba0 (state 0xcc, vtable 0x6449fb0 whose
   first entry is the poll 0x2b1df60);
5. the poll's exit: it copies the 0x470-byte engine value out, keeps its box
   (+0x450), drops the rest through 0x2df7710 (skips tag 2; drops the l1 map
   +0x3e0 and the digest map +0x400), and writes {1, 0, box, ...} as its
   0x358-byte task output.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses; ends are exclusive.
"""
import argparse
import json
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from freeze_snapshot_115 import read_va, fixed, rip_target, relative_relocations, direct_calls

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-catchup-initial-state-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

SHIM, SHIM_LEN = 0x2d275d0, 0x109          # 0x2d275d0..0x2d276d9 (body up to ret)
TWIN = 0x5a08f80                           # layout-A builder (#6008)
STEP_C, STEP_A = 0x2d25620, 0x5a07ec0
INIT_SLOT, INIT = 0x64e80e8, 0x38c6590
SINGLETON_SLOT, SINGLETON = 0x64e11e0, 0x1560e30
POLL, BUILDER, SPAWN, VTABLE = 0x2b1df60, 0x2b41b70, 0x2b3aba0, 0x6449fb0
DROP = 0x2df7710

STRINGS = {
    0x7a14dc: b'abci_engine',
    0x459fd8: b'true',
    0x7a145d: b'false',
    0x440f12: b'\xc0\x02::\xc0\x00',
    0x43777f: b'\x1bSingleton already created: ',
    0x605fe1: b'running non-validator to get initial abci state for consensus',
    0x60601e: b'initial_slow_state_for_join',
}

FIXED = {
    # shim: input fields and engine value tail
    0x2d275e2: '4c8bb620040000',          # mov r14, [rsi+0x420]  (box)
    0x2d275e9: '4c8bbe28040000',          # mov r15, [rsi+0x428]  (Arc)
    0x2d275f0: '440fb6a630040000',        # movzx r12d, byte [rsi+0x430]
    0x2d27645: '48c78424700400001a40f600',  # mov qword [rsp+0x470], 0xf6401a
    0x2d27651: 'c7842478040000' '00000000',  # mov dword [rsp+0x478], 0
    0x2d2765c: '4088ac247d040000',        # mov [rsp+0x47d], bpl
    # 0x38c6590: tag test and true/false length
    0x38c65aa: '833e02',                  # cmp dword [rsi], 2
    0x38c65f1: '4983fc02',                # cmp r12, 2
    0x38c65f5: '410f94c6',                # sete r14b
    0x38c65f9: '4983f605',                # xor r14, 5  (4 'true' / 5 'false')
    0x38c6640: 'ba0b000000',              # mov edx, 11 (len 'abci_engine')
    # poll: take the future out of the task cell
    0x2b1e104: '488b4140',                # mov rax, [rcx+0x40]
    0x2b1e108: '48c7414002000000',        # mov qword [rcx+0x40], 2
    0x2b1e110: '4883f802',                # cmp rax, 2
    # poll: shim input
    0x2b1e18c: '488b9c2490090000',        # mov rbx, [rsp+0x990]  (future +0x320: box)
    0x2b1e194: '4c8b7328',                # mov r14, [rbx+0x28]
    0x2b1e198: 'bf18000000',              # mov edi, 0x18
    0x2b1e1ac: '48c70001000000',          # Arc strong = 1
    0x2b1e1b3: '48c7400801000000',        # Arc weak = 1
    0x2b1e1bb: '4c897010',                # Arc payload = [box+0x28]
    0x2b1e1bf: '48899c2420060000',        # input +0x420 = box
    0x2b1e1c7: '66c784243006000000' '00',  # input +0x430 = word 0
    0x2b1e1d1: '4889842428060000',        # input +0x428 = Arc
    0x2b1e1d9: '48c784240002000002000000',  # input +0x0 = 2
    0x2b1e1e5: '488dbc24180d0000',        # rdi = rsp+0xd18 (engine value)
    0x2b1e1ed: '4c8da42400020000',        # r12 = rsp+0x200 (input)
    # poll: exit
    0x2b1ecb9: '488dbc2400020000',        # rdi = rsp+0x200
    0x2b1ecc1: '488db424180d0000',        # rsi = rsp+0xd18
    0x2b1ecc9: 'ba70040000',              # mov edx, 0x470
    0x2b1ecd4: '4c8bb42450060000',        # r14 = copy +0x450 (box)
    0x2b1ecfa: '488dbc2400020000',        # rdi = rsp+0x200
    0x2b1eef7: '4c89b424d0090000',        # output +0x10 = box
    0x2b1ef07: 'c78424c009000001000000',  # output +0x0 = 1
    0x2b1ef63: 'ba58030000',              # mov edx, 0x358 (output size)
    # drop glue 0x2df7710
    0x2df771c: '833f02',                  # cmp dword [rdi], 2
    0x2df7725: '488b83e0030000',          # mov rax, [rbx+0x3e0]  (l1 map)
    0x2df77cd: '488b8300040000',          # mov rax, [rbx+0x400]  (digest map)
    # builder 0x2b41b70: future box and task name
    0x2b42442: '488dbc2430040000',        # rdi = rsp+0x430
    0x2b4244f: 'bab8030000',              # mov edx, 0x3b8 (result copy)
    0x2b42473: '48894350',                # [state+0x50] = [rsp+0x7b0] (result +0x380)
    0x2b42525: '4c8b7b50',                # r15 = [state+0x50]
    0x2b42539: '4c8dab80000000',          # r13 = state+0x80 (future)
    0x2b42597: '4c89bba0030000',          # future +0x320 = r15
    0x2b425cb: '48c783d80300001b000000',  # name length 27
    0x2b425f3: 'ba50030000',              # mov edx, 0x350 (future size)
    # spawn 0x2b3aba0
    0x2b3ac37: 'ba50030000',              # mov edx, 0x350
    0x2b3ac3f: '48c7842480000000cc000000',  # task state 0xcc
}
REFERENCES = (
    # (instruction va, prefix, length, target)
    (0x2d2760c, b'\xff\x15', 6, INIT_SLOT),
    (0x2d2766f, b'\xe8', 5, STEP_C),
    (0x38c661d, b'\x48\x8d\x35', 7, 0x7a145d),
    (0x38c6616, b'\x48\x8d\x05', 7, 0x459fd8),
    (0x38c6634, b'\x48\x8d\x35', 7, 0x7a14dc),
    (0x38c664b, b'\xff\x15', 6, SINGLETON_SLOT),
    (0x1560ea4, b'\x48\x8d\x35', 7, 0x440f12),
    (0x1560f23, b'\x48\x8d\x3d', 7, 0x43777f),
    (0x2b1e1f8, b'\xe8', 5, SHIM),
    (0x2b1ed02, b'\xe8', 5, DROP),
    (0x2b42331, b'\x48\x8d\x05', 7, 0x605fe1),
    (0x2b42429, b'\xe8', 5, 0x2af45f0),
    (0x2b425bd, b'\x4c\x8d\x25', 7, 0x60601e),
    (0x2b4261c, b'\xe8', 5, SPAWN),
    (0x2b3ac57, b'\x48\x8d\x05', 7, VTABLE),
)
RELOCS = {INIT_SLOT: INIT, SINGLETON_SLOT: SINGLETON, VTABLE: POLL}


def disp_sites(raw):
    """rel32 positions (start of the 4-byte field) for e8, ff 15 and rex 8b/8d rip forms."""
    sites = {}
    for i in range(len(raw)):
        if raw[i] == 0xe8 and i + 5 <= len(raw):
            sites[i + 1] = i + 5
        if raw[i:i + 2] == b'\xff\x15' and i + 6 <= len(raw):
            sites[i + 2] = i + 6
        if (raw[i] in (0x48, 0x4c) and i + 7 <= len(raw) and raw[i + 1] in (0x8b, 0x8d)
                and raw[i + 2] & 0xc7 == 0x05):
            sites[i + 3] = i + 7
    return sites


def twin_diff(data):
    """Compare the shim with the layout-A builder; return differing rel32 fields."""
    a = read_va(data, SHIM, SHIM_LEN)
    b = read_va(data, TWIN, SHIM_LEN)
    diffs = [i for i in range(SHIM_LEN) if a[i] != b[i]]
    sites = disp_sites(a)
    fields = {}
    for i in diffs:
        owner = [p for p in sites if p <= i < p + 4]
        if len(owner) != 1:
            raise ValueError(f'shim byte +{i:#x} differs outside a rel32 field')
        p = owner[0]
        end = sites[p]
        ta = SHIM + end + struct.unpack_from('<i', a, p)[0]
        tb = TWIN + end + struct.unpack_from('<i', b, p)[0]
        fields[p] = (ta, tb)
    same = sum(1 for ta, tb in fields.values() if ta == tb)
    different = {hex(SHIM + p - 1): [hex(ta), hex(tb)] for p, (ta, tb) in fields.items() if ta != tb}
    return len(diffs), same, different


def census(data):
    """One pass over .text: direct calls and rip-relative loads of interest."""
    from freeze_snapshot_115 import text
    base, code = text(data)
    want_calls = {SHIM: [], SPAWN: [], DROP: [], STEP_C: []}
    want_lea = {VTABLE: [], 0x60601e: []}
    for i in range(len(code) - 7):
        c = code[i]
        if c == 0xe8:
            t = base + i + 5 + struct.unpack_from('<i', code, i + 1)[0]
            if t in want_calls:
                want_calls[t].append(base + i)
        elif c in (0x48, 0x4c) and code[i + 1] == 0x8d and code[i + 2] & 0xc7 == 0x05:
            t = base + i + 7 + struct.unpack_from('<i', code, i + 3)[0]
            if t in want_lea:
                want_lea[t].append(base + i)
    return ({hex(k): [hex(v) for v in vs] for k, vs in want_calls.items()},
            {hex(k): [hex(v) for v in vs] for k, vs in want_lea.items()})


def bind(data, fdes=None):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    for va, s in STRINGS.items():
        if read_va(data, va, len(s)) != s:
            raise ValueError(f'string at {va:#x} changed')
    rel = relative_relocations(data)
    for slot, target in RELOCS.items():
        if rel.get(slot) != target:
            raise ValueError(f'relocation at {slot:#x} changed')
    n_diff, same, different = twin_diff(data)
    if different != {hex(0x2d2766f): [hex(STEP_C), hex(STEP_A)]}:
        raise ValueError('shim differs from 0x5a08f80 beyond its step call')
    calls, leas = census(data)
    expect_calls = {hex(SHIM): [hex(0x2b1e1f8)], hex(SPAWN): [hex(0x2b4261c)]}
    for k, v in expect_calls.items():
        if calls[k] != v:
            raise ValueError(f'call census for {k} changed')
    if leas[hex(VTABLE)] != [hex(0x2b3ac57)] or leas[hex(0x60601e)] != [hex(0x2b425bd)]:
        raise ValueError('vtable / task name census changed')
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'shim': {
            'fn': hex(SHIM),
            'twin_of': hex(TWIN) + ' (#6008 layout-A builder)',
            'compared_bytes': hex(SHIM_LEN),
            'differing_bytes': n_diff,
            'rel32_fields_same_target': same,
            'rel32_fields_different_target': different,
            'engine_value_tail': '+0x450 box ([in+0x420]), +0x458 Arc ([in+0x428]), +0x460 0xf6401a, '
                                 '+0x468 0, +0x46c byte [in+0x430], +0x46d byte [in+0x431]',
            'runs_step_once': hex(0x2d2766f) + ' call ' + hex(STEP_C),
        },
        'init_0x450': {
            'slot': hex(INIT_SLOT) + ' -> ' + hex(INIT),
            'input_tag_test': hex(0x38c65aa) + ' cmp dword [rsi], 2',
            'singleton': "slot %s -> %s registers key 'abci_engine' (11 bytes) with value 'true' when tag == 2 "
                         "else 'false'; template '{}::{}' (%s); panic text 'Singleton already created: ' (%s)"
                         % (hex(SINGLETON_SLOT), hex(SINGLETON), hex(0x440f12), hex(0x43777f)),
        },
        'poll_input': {
            'future_take': 'cell +0x40 read then set to 2; 2 before -> panic path; 0x350 bytes copied to rsp+0x670',
            'box': '[rsp+0x990] = future +0x320',
            'input': '+0x0 = 2, +0x420 = box, +0x428 = Arc {1, 1, [box+0x28]}, +0x430 = word 0',
            'shim_call': hex(0x2b1e1f8),
        },
        'future_builder': {
            'fn': hex(BUILDER),
            'warn_message': hex(0x605fe1) + " 'running non-validator to get initial abci state for consensus'",
            'box_source': '0x2af45f0 result copied 0x3b8 to rsp+0x430; [rsp+0x7b0] (result +0x380) -> '
                          '[state+0x50] -> future (state+0x80) +0x320',
            'task_name': hex(0x60601e) + " 'initial_slow_state_for_join' (27 bytes)",
            'spawn': hex(0x2b4261c) + ' call ' + hex(SPAWN) + ' (state 0xcc, vtable ' + hex(VTABLE) +
                     ' -> poll ' + hex(POLL) + ', future 0x350 bytes)',
        },
        'poll_exit': {
            'copy': '0x470 bytes rsp+0xd18 -> rsp+0x200',
            'kept': 'box = copy +0x450 (rsp+0x650)',
            'dropped': hex(DROP) + ' (tag 2 skips; drops +0x3e0 l1 map and +0x400 digest map); callers ' +
                       ', '.join(calls[hex(DROP)]),
            'output': '0x358 bytes: dword 1 at +0x0, box at +0x10',
        },
        'step_callers': calls[hex(STEP_C)],
        'gates_changed': False,
    }


def render(result):
    return (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()


def generate(binary=TARGET, output=PACKET):
    identity = manifest_item(ROOT, RELATIVE)
    check(binary, identity)
    if identity['sha256'] != SHA256:
        raise ValueError('pinned node #115 digest changed')
    result = bind(binary.read_bytes())
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
    print('shim twin diff', result['shim']['differing_bytes'], 'task', result['future_builder']['task_name'])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
