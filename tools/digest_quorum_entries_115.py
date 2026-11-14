#!/usr/bin/env python3
"""Bind where the node #115 step wrappers' 0x68-byte quorum entries come from (60th stage).

#6023 found that the step wrappers 0x5a04e40 (layout A) and 0x5a06600 (layout B)
walk 0x68-byte entries and compare each entry's +0x48..+0x68 with the computed
abci digest; #6042 found the slice at wrapper [rsp+0x180] (pointer) and
[rsp+0x188] (length). This tool binds:

1. the slice is field +0x20/+0x28 of the 0x48-byte result that the A wrapper
   gets from 0x54897e0 (rdi = rsp+0x160, only direct call 0x5a055b0); the B
   wrapper calls the twin 0x5486720 the same way (only direct call 0x5a06db6);
2. 0x54897e0 copies a Vec held at its rsp+0xc0..0xd8 to rsp+0x48..0x60 and
   then to result +0x18..+0x30 (pointer +0x20, length +0x28);
3. that Vec is built by 0x5afa1f0(out = rsp+0xc0, store = box +0x3d98,
   time = rsp+0x220, aux = box +0x3f08); a second Vec is built by 0x5afa030
   from box +0x3e50 into result +0x30..+0x48; the B twin passes box +0x4908,
   +0x49c0 and +0x4a78 (each 0xb70 higher, #6006);
4. 0x5afa1f0: threshold = max(0, store +0x78 - 1000); calls 0x4de1d80 on the
   store's map at +0x60 with that context; takes the Vec at store +0x48 and
   leaves {0, 8, 0}; keeps only entries whose qword +0x20 is non-zero and
   drops the rest through 0x5b0d830 on entry +0x8; elements are 0x68 bytes;
5. entry drop glue 0x5626ce0 walks 0x68-byte elements; 0x5b0d830 frees a
   buffer of len * 0x60 at entry +0x8;
6. the store is filled inside the engine: 0x54cae80 calls 0x5afa5d0 with box
   +0x3d98 (its B twin 0x54ca6b0 with +0x4908) (and 0x5afa3b0 with box +0x3e50); 0x5afa5d0 inserts into store +0x60
   through 0x4dbe1e0; dispatcher 0x538cd30 calls 0x54cae80 four times with
   esi = 0, 1, 2, 3;
7. box +0x3d98 and +0x3e50 are fields of the abci hash input builder 0x4e34ce0
   and the rmp serialiser 0x5480950.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses.
"""
import argparse
import json
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import SHA256, RELATIVE, direct_calls, fixed, frame, read_va, render

TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-digest-quorum-entries-115'

WRAPPER_A, WRAPPER_B = 0x5a04e40, 0x5a06600
PRODUCE_A, PRODUCE_B = 0x54897e0, 0x5486720
TAKE, TAKE2 = 0x5afa1f0, 0x5afa030
FILL_HELPER = 0x4de1d80
ENTRY_DROP, FIELD_DROP = 0x5626ce0, 0x5b0d830
INSERT_DISPATCH, INSERT = 0x54cae80, 0x5afa5d0
MAP_INSERT = 0x4dbe1e0
DISPATCHER_A = 0x538cd30

FIXED = {
    # A wrapper: result at rsp+0x160 from 0x54897e0; slice read at +0x20/+0x28
    0x5a055a0: '488dbc2460010000',      # lea rdi, [rsp+0x160]
    0x5a055b0: 'e82b42a8ff',            # call 0x54897e0
    0x5a05649: '488b9c2488010000',      # mov rbx, [rsp+0x188]       (length)
    0x5a05671: '488bb42480010000',      # mov rsi, [rsp+0x180]       (pointer)
    0x5a05686: '486bfb68',              # imul rdi, rbx, 0x68
    # B wrapper: same result slot from the twin
    0x5a06da9: '488dbc2460010000',      # lea rdi, [rsp+0x160]
    0x5a06db6: 'e865f9a7ff',            # call 0x5486720
    # 0x54897e0: build two Vecs from box +0x3d98 and +0x3e50
    0x548beed: '498db424983d0000',      # lea rsi, [r12+0x3d98]
    0x548bef5: '4d8db424083f0000',      # lea r14, [r12+0x3f08]
    0x548befd: '4c8dbc24c0000000',      # lea r15, [rsp+0xc0]
    0x548bf13: 'e8d8e26600',            # call 0x5afa1f0
    0x548bf2d: '498db424503e0000',      # lea rsi, [r12+0x3e50]
    0x548bf4b: 'e8e0e06600',            # call 0x5afa030
    # 0x54897e0: Vec rsp+0xc0..0xd8 -> rsp+0x48..0x60 -> result +0x18..+0x30
    0x548c019: '0f108424c0000000',      # movups xmm0, [rsp+0xc0]
    0x548c021: '0f11442448',            # movups [rsp+0x48], xmm0
    0x548c026: '488b8c24d0000000',      # mov rcx, [rsp+0xd0]
    0x548c02e: '48894c2458',            # mov [rsp+0x58], rcx
    0x548c204: '488b842420050000',      # mov rax, [rsp+0x520]        (result)
    0x548c21a: '488b542450',            # mov rdx, [rsp+0x50]
    0x548c21f: '488b4c2458',            # mov rcx, [rsp+0x58]
    0x548c22d: '48895020',              # mov [rax+0x20], rdx          (pointer)
    0x548c231: '48894828',              # mov [rax+0x28], rcx          (length)
    # B twin builds from +0x4908 / +0x49c0 / +0x4a78
    0x5488dae: '488db508490000',        # lea rsi, [rbp+0x4908]
    0x5488db5: '4c8db5784a0000',        # lea r14, [rbp+0x4a78]
    0x5488dd2: 'e819146700',            # call 0x5afa1f0
    0x5488def: '488db5c0490000',        # lea rsi, [rbp+0x49c0]
    0x5488e0c: 'e81f126700',            # call 0x5afa030
    # 0x5afa1f0: threshold, fill, take, filter, 0x68 stride
    0x5afa204: '488d7e60',              # lea rdi, [rsi+0x60]          (map)
    0x5afa208: '488b4678',              # mov rax, [rsi+0x78]
    0x5afa20e: '482de8030000',          # sub rax, 1000
    0x5afa214: '480f43f0',              # cmovae rsi, rax              (else 0)
    0x5afa260: 'e81b7b2eff',            # call 0x4de1d80
    0x5afa26e: '410f104648',            # movups xmm0, [r14+0x48]     (take Vec)
    0x5afa277: '49c7464800000000',      # mov qword [r14+0x48], 0
    0x5afa27f: '49c7465008000000',      # mov qword [r14+0x50], 8
    0x5afa287: '49c7465800000000',      # mov qword [r14+0x58], 0
    0x5afa2b0: '48837d9800',            # cmp qword [rbp-0x68], 0      (entry +0x20)
    0x5afa2f8: '496bcf68',              # imul rcx, r15, 0x68
    0x5afa048: '488b4678',              # 0x5afa030: mov rax, [rsi+0x78]
    0x5afa0a0: 'e89b642eff',            # 0x5afa030: call 0x4de0540
    # drop glue
    0x5626d06: '4c8d6768',              # lea r12, [rdi+0x68]
    0x5626d1f: '486bf068',              # imul rsi, rax, 0x68
    0x5b0d887: '488b7b08',              # mov rdi, [rbx+0x8]
    0x5b0d88b: '48c1e005',              # shl rax, 5
    0x5b0d88f: '488d3440',              # lea rsi, [rax+rax*2]          (len * 0x60)
    # producer
    0x54ca872: '488dbd08490000',        # B twin 0x54ca6b0: lea rdi, [rbp+0x4908]
    0x54ca888: 'e843fd6200',            # call 0x5afa5d0
    0x54cb042: '488dbd983d0000',        # lea rdi, [rbp+0x3d98]
    0x54cb049: '488d95083f0000',        # lea rdx, [rbp+0x3f08]
    0x54cb058: 'e873f56200',            # call 0x5afa5d0
    0x54cb062: '488dbd503e0000',        # lea rdi, [rbp+0x3e50]
    0x54cb078: 'e833f36200',            # call 0x5afa3b0
    0x5afa6da: '498d7760',              # lea rsi, [r15+0x60]
    0x5afa6eb: 'e8f03a2cff',            # call 0x4dbe1e0
    0x5392009: '31f6',                  # xor esi, esi
    0x539200b: 'e8708e1300',            # call 0x54cae80
    0x5392013: 'be01000000',            # mov esi, 1
    0x5392020: 'be02000000',            # mov esi, 2
    0x539202d: 'be03000000',            # mov esi, 3
    # state membership
    0x4e35128: '498d87983d0000',        # lea rax, [r15+0x3d98]   (hash input builder)
    0x4e35137: '498d87503e0000',        # lea rax, [r15+0x3e50]
    0x54815ff: '498d97983d0000',        # lea rdx, [r15+0x3d98]   (rmp serialiser)
}


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)

    def calls(target):
        return [hex(v) for v in direct_calls(data, target)]

    census = {
        'produce_a': calls(PRODUCE_A), 'produce_b': calls(PRODUCE_B),
        'take': calls(TAKE), 'take2': calls(TAKE2),
        'entry_drop': calls(ENTRY_DROP), 'insert_dispatch': calls(INSERT_DISPATCH),
        'insert': calls(INSERT),
    }
    expected = {
        'produce_a': ['0x5a055b0'], 'produce_b': ['0x5a06db6'],
        'take': ['0x5488dd2', '0x548bf13'], 'take2': ['0x5488e0c', '0x548bf4b'],
        'insert_dispatch': ['0x539200b', '0x5392018', '0x5392025', '0x5392032', '0x54cf27f'],
        'insert': ['0x54ca888', '0x54cb058'],
    }
    for key, want in expected.items():
        if census[key] != want:
            raise ValueError(f'call census {key} changed')
    owners = {
        '0x5a055b0': WRAPPER_A, '0x5a06db6': WRAPPER_B, '0x548bf13': PRODUCE_A,
        '0x5488dd2': PRODUCE_B, '0x539200b': DISPATCHER_A, '0x54cb058': INSERT_DISPATCH, '0x54ca888': 0x54ca6b0,
        '0x5afa6eb': INSERT, '0x4e35128': 0x4e34ce0, '0x54815ff': 0x5480950,
    }
    for site, fn in owners.items():
        if frame(fdes, int(site, 16)) != fn:
            raise ValueError(f'{site} is not in {fn:#x}')

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'slice_origin': {
            'wrapper_a': '%s: lea rdi,[rsp+0x160]; call %s; slice ptr [rsp+0x180] = result +0x20, len [rsp+0x188] = result +0x28; 0x68 stride at 0x5a05686'
                         % (hex(WRAPPER_A), hex(PRODUCE_A)),
            'wrapper_b': '%s: lea rdi,[rsp+0x160]; call %s (twin)' % (hex(WRAPPER_B), hex(PRODUCE_B)),
            'result_copy': '0x54897e0 rsp+0xc0..0xd8 -> rsp+0x48..0x60 (0x548c019) -> result +0x18..+0x30 (0x548c204..0x548c231)',
        },
        'builders': {
            'take': {'fn': hex(TAKE), 'a': 'store box +0x3d98, aux box +0x3f08, time rsp+0x220 (0x548bf13)',
                     'b': 'store box +0x4908, aux box +0x4a78 (0x5488dd2)'},
            'take2': {'fn': hex(TAKE2), 'a': 'store box +0x3e50 -> result +0x30..+0x48 (0x548bf4b)',
                      'b': 'store box +0x49c0 (0x5488e0c)', 'fill_helper': '0x4de0540'},
            'take_logic': 'threshold = max(0, store +0x78 - 1000); %s(store +0x60, ctx); take Vec store +0x48 leaving {0,8,0}; keep entries with qword +0x20 != 0; drop others via %s(entry +0x8)'
                          % (hex(FILL_HELPER), hex(FIELD_DROP)),
        },
        'entry': {
            'size': hex(0x68),
            'fields': {'+0x0': 'height (u64, #6023 key)', '+0x8': 'owned buffer, freed as len * 0x60 by 0x5b0d830',
                       '+0x20': 'qword; zero entries are dropped by 0x5afa1f0', '+0x48..+0x68': 'quorum digest (#6023)'},
            'drop_glue': hex(ENTRY_DROP),
        },
        'producer': {
            'insert': '%s: store +0x60 map insert via %s (0x5afa6eb)' % (hex(INSERT), hex(MAP_INSERT)),
            'dispatch': '%s: 0x5afa5d0(box +0x3d98, box, box +0x3f08, ...) at 0x54cb058; 0x5afa3b0(box +0x3e50, ...) at 0x54cb078'
                        % hex(INSERT_DISPATCH),
            'dispatch_callers': census['insert_dispatch'],
            'dispatch_b': '0x54ca6b0: 0x5afa5d0(box +0x4908, box, box +0x4a78, ...) at 0x54ca888',
            'dispatcher_a': '%s calls %s with esi = 0, 1, 2, 3 (0x539200b..0x5392032)' % (hex(DISPATCHER_A), hex(INSERT_DISPATCH)),
        },
        'state_membership': {'hash_input_builder': '0x4e34ce0 lea [r15+0x3d98] 0x4e35128, [r15+0x3e50] 0x4e35137',
                             'rmp_serialiser': '0x5480950 lea [r15+0x3d98] 0x54815ff'},
        'calls': census,
        'gates_changed': False,
    }


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
    print('take calls=%s insert_dispatch calls=%d' % (result['calls']['take'], len(result['calls']['insert_dispatch'])))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
