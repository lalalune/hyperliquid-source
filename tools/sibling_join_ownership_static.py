#!/usr/bin/env python3
"""Node 115: who owns the JoinHandle of each dispatcher-table spawn.

The dispatcher-table packet (#3000) pinned eleven static-table
dispatchers, and the packet-cell packet (#3050) pinned the spawn
body (0x15b80e0), join body (0x15b8810) and packet cell of the
family-L entry 0x6400530 (dispatcher_v4).  #3050 left one end
open verbatim: "Sibling dispatchers' JoinHandle ownership and
whether their callers read the returned pair are not traced
here."  This packet traces exactly that, for all eleven entries.

Answers, all static and re-derived by analyze() below:

1.  Spawns: each entry base is loaded by exactly one lea in
    .text, each inside its own spawn body (the per-entry spawn
    monomorphisation); each spawn body has exactly one direct
    call site in .text.  A spawn writes a 0x18-byte handle
    {thread Arc, packet-cell Arc, pthread_t} through the
    caller's sret pointer and panics with the std message
    "failed to spawn thread" when word 0 comes back zero.
2.  Fates at the eleven call sites: nine drop the handle in
    place -- pthread_detach on the fresh pthread word, then
    release of both Arcs (thread-Arc drop slot 0x64dfe58, the
    family cell drop slot) -- so those threads run detached
    and their stored pairs can never be read through a handle:
    v1, v3, v4 (the #3050 dispatcher's own site), x1, x2a,
    x2b, x2c, x3, x4.  Two sites keep the handle:
    - v2's caller never detaches; the handle is moved into an
      owned local whose outlined drop is body 0x15df8a0
      (detach + both releases), wired into the caller's
      landing pads, and the caller registers the worker and
      returns.  The body itself is reached through RELATIVE
      slot 0x64e1750 (no direct callers).
    - x5's caller copies the fresh handle and hands it to a
      hash-map insert body (0x5cf0700) that stores it in a
      map inside the owner struct (map field at owner +0x68);
      only the value the insert displaces -- the previous
      handle under the same key, written back into the spawn
      slot -- is detached and dropped in place.
3.  Readers: exactly two take-style join bodies exist in
    .text (testb $1 / movq $0 at cell +0x18 with the pair
    loaded from +0x20/+0x28): join_a 0x15b8810 for the shared
    type-A cell of families L, X1, X2 and X3, and join_x5
    0x5cf7550 for the X5 cell.  pthread_join is called from
    exactly three bodies in the binary: those two, plus
    0x56467d0, which joins a handle over a different, larger
    cell (it reads cell +0x58) and is reachable only through
    RELATIVE slot 0x64e7388 -- not a reader of any of the
    eleven packet cells.  No join body exists for the X4
    cell type, so an x4 pair is never read by any body.
    - join_a has exactly one call site (0x15ec467 in body
      0x15ec360), which loads a stored handle from its owner
      struct at +0xa0 and consumes the returned pair (null
      test, conversion call, report call).  Of the nine
      type-A handles, v2's is the only one not destroyed at
      its call site.
    - join_x5 has exactly three call sites (0x5cf4186 and
      0x5cf4321 in 0x5cf3fe0, 0x5cf4d67 in 0x5cf47f0); its
      callers dispatch the returned pair's first vtable slot
      on the pair's data.  The same two bodies also remove
      handles from the map and detach them (detach sites
      0x5cf422b / 0x5cf4c6b), so stored x5 handles are joined
      on some paths and abandoned on others.
"""
import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from elf_index import sections, unwind_index
from fde_extents import fde_extents

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
TARGET_SIZE = 105896032
TARGET_SHA256 = ('a6e2897cd051213d004802deca416e8eca62b7'
                 'a8278fa39f249e98c3867b5301')
SNAPSHOT = '<authenticated-node115>'
WORK_ITEM = 'RE-005-node115-sibling-join-ownership'
OUT = ROOT / 'research/work-items' / WORK_ITEM

OWNERS = {
    'spawn_v1': (0x15b6d10, 0x15b73bd,
                 'ba8b646eae1ddb1e3e25a5f388619e4f23b39d4cf3b0f2bd'
                                  'd9cb7290e44480da'),
    'spawn_v2': (0x15b73c0, 0x15b7a7f,
                 '943383faaace0e66199d8f4dbd32c3bff3d77df00d7b6c3f'
                                  '1b82876b5c6d1033'),
    'spawn_v3': (0x15b7a80, 0x15b80d7,
                 'eb31d0e0353e6eebbec0ee2a7b175bf18bf6c44c4fa0e8f5'
                                  '59ee1bb43e1541b5'),
    'spawn_v4': (0x15b80e0, 0x15b8804,
                 '967d4b0bb72e2e86245bc092d3d850f2324631adaf5482ac'
                                  '4df09804e3f152b8'),
    'spawn_x1': (0x2d46820, 0x2d46f86,
                 '769211d5e800f3423079524b2cc23b7625e95d362ad3a4c0'
                                  'cfc3fa7340b5cc68'),
    'spawn_x2a': (0x56141f0, 0x5614956,
                  'd4886b8b5f001183acc7a9b66f478d9c91899fc7b9e2b4d1'
                                   '88952f5970486b77'),
    'spawn_x2b': (0x5614960, 0x56150ca,
                  'd816dbbad7406ae4b9a4640b907ec91341010d63afed189e'
                                   'aaa40e41bb9b716d'),
    'spawn_x2c': (0x56150d0, 0x5615836,
                  '804a18ab97e4ee7d77e2049abb8ae0027c9cb643ddd2ce45'
                                   'a6c8d48185dda2d4'),
    'spawn_x3': (0x5bc2c90, 0x5bc334e,
                 'bd5dabb011c5845b7cf67357024d004b34c8b2502998ea6e'
                                  '46202ee41b03bf8e'),
    'spawn_x4': (0x5cd9470, 0x5cd9b2f,
                 'a67df4f7707481778d223fca1d10a1dcb3360ea805ae3215'
                                  'f317882fa163c6a2'),
    'spawn_x5': (0x5cf6e80, 0x5cf7550,
                 '1de6a1382a5d5557a56bcc242cf2a8e7e543e089832f43bc'
                                  'f8548b32a05c5a87'),
    'caller_v1': (0x1534ed0, 0x1534feb,
                  '079f065e8dafba89ad7b3072aae69bd5e9e9461c2176bde7'
                                   'f89d9c641eb1431a'),
    'caller_v2': (0x15d63c0, 0x15d6729,
                  'e420738675a592463dc312bdaf60b560b89413e19fba05bb'
                                   '4d1508ea71ac3564'),
    'caller_v3': (0x15d5b00, 0x15d5cae,
                  'e3da8549dab30d424bdd4e00a2ba6c188da8685494618d0c'
                                   'd40af420dbf91c5c'),
    'caller_v4': (0x150b310, 0x150baaf,
                  '19ca3e09da69f37a39c2ed3da2e50a02184d75157857d65c'
                                   '0edd955c1369c2f2'),
    'caller_x1': (0x2d25620, 0x2d275c3,
                  'b6a28678f373cd6049bd3c0c76d2ab49b647945309679f3c'
                                   '14aa6393a88ffccf'),
    'caller_x2a': (0x5a07ec0, 0x5a0871c,
                   '25f84ed2821128021473629dafd092fe1058087d196097c3'
                                    '6ebfe83d9cae466b'),
    'caller_x2b': (0x5a6dd30, 0x5a6e1e0,
                   'faeb006ffef7f6f534d6e73955d54ca9d97b2eaa427b881c'
                                    'f0ad29c9a58c68fb'),
    'caller_x2c': (0x5a08720, 0x5a08f7c,
                   'd6ea4dbd983c09a2478b3a0c29e68639713ad28a4af0d62f'
                                    'feb2767b4803ef82'),
    'caller_x3': (0x5bbea20, 0x5bbebb1,
                  '22a1a299fcadd42d7421275fc09ed3312178270f0a8e290e'
                                   '28c4212f06a83c89'),
    'caller_x4': (0x5cd5ea0, 0x5cd603c,
                  '78c17eaf8863e6bb09cf2622c31002bc8a612caaff93c71e'
                                   'aa40d3c851f5427d'),
    'caller_x5': (0x5cf5100, 0x5cf55d7,
                  '3ede3e0de6239df2546301485ff8664996a025ed907a977b'
                                   '2d99c6cdc054fcd8'),
    'join_a': (0x15b8810, 0x15b896e,
               'f57a1ff86b1b2a431d2c168a23145ea2e603de76a51c6628'
                                '52d29c39853587aa'),
    'join_x5': (0x5cf7550, 0x5cf76ae,
                '12fbb6bdf25c91d5912271bcae41e6422635dd8ca655bb02'
                                 '33e985ad9b685c03'),
    'other_join': (0x56467d0, 0x56471a8,
                   '2373b558d88eaa2c36015fb268764e192574a9e097c18583'
                                    '416d8c356fef01eb'),
    'handle_drop_a': (0x15df8a0, 0x15df8da,
                      '579a8fed83bf447af533fd1101700b679abed0743cc2cfe9'
                                       'ea034f544ab8ef38'),
    'handle_drop_x5': (0x5cf3570, 0x5cf35e1,
                       '9911fa28fba1d840186bde1b9cafc0f7a2b7b9915d616e89'
                                        'dff4317d23eb8c9a'),
    'join_consumer_a': (0x15ec360, 0x15ec6da,
                        'c4e3d4aca8594e5526f9c6a2e64e309e4a4fc9dedafb4eb6'
                                         '14fb8b067ec0c070'),
    'join_consumer_top': (0x15fe220, 0x15fe336,
                          'f08ce2f3390b8afb72fcb86c3120451d261cb56cb5fa2dfa'
                                           '938fde02238f738b'),
    'join_x5_consumer_a': (0x5cf3fe0, 0x5cf4536,
                           '187d899dd8e0dd2ffb90181036a90c1585f25a24f21f40fe'
                                            '56e402f9c65f1bb0'),
    'join_x5_consumer_b': (0x5cf47f0, 0x5cf50f2,
                           '172b33905a2455009ebec2e18ec7a98537b5acf341755ed2'
                                            '37f76b0446a8249e'),
    'insert_x5': (0x5cf0700, 0x5cf08da,
                  'd8f85a397dc273fe300177b34dcf9913cb2237c2a5a45d8a'
                                   '33ed136330715cb8'),
}

EXPORTED = ('spawn_v4', 'join_a', 'join_x5', 'handle_drop_a',
            'handle_drop_x5', 'caller_v2', 'caller_x5',
            'join_consumer_a', 'other_join', 'insert_x5')

# Byte pins: the fate-decisive instructions, read from the
# artifact's disassembly.  Indirect calls are annotated with the
# GOT slot they reference.
PINS = {
    'caller_v1': [
        (0x1534f04, 'e8071e0800'),        # call spawn_v1
        (0x1534f09, '4c8b742410'),        # mov 0x10(%rsp),%r14 word0
        (0x1534f31, 'ff1519affa04'),      # call *pthread_detach slot
        (0x1534f37, 'f049ff0e'),          # lock decq (%r14)
        (0x1534f42, 'ff1510affa04'),      # call *thread-arc drop slot
        (0x1534f4d, 'f048ff08'),          # lock decq (%rax) cell
        (0x1534f56, 'ff1504affa04'),      # call *cell drop slot A
    ],
    'caller_v4': [
        (0x150b98c, 'e84fc70a00'),        # call spawn_v4
        (0x150b9bd, 'ff158d44fd04'),      # call *pthread_detach slot
        (0x150b9c3, 'f049ff0e'),          # lock decq (%r14)
        (0x150b9ce, 'ff158444fd04'),      # call *thread-arc drop slot
        (0x150b9d9, 'f048ff08'),          # lock decq (%rax) cell
        (0x150b9e6, 'ff157444fd04'),      # call *cell drop slot A
    ],
    'caller_v3': [
        (0x15d5b51, 'e82a1ffeff'),        # call spawn_v3
        (0x15d5b81, 'ff15c9a2f004'),      # call *pthread_detach slot
        (0x15d5b87, 'f049ff0c24'),        # lock decq (%r12)
        (0x15d5b93, 'ff15bfa2f004'),      # call *thread-arc drop slot
        (0x15d5b9e, 'f048ff08'),          # lock decq (%rax) cell
        (0x15d5ba7, 'ff15b3a2f004'),      # call *cell drop slot A
    ],
    'caller_x1': [
        (0x2d2726c, 'e8aff50100'),        # call spawn_x1
        (0x2d272a4, 'ff15a68b7b03'),      # call *pthread_detach slot
        (0x2d272aa, 'f048ff0b'),          # lock decq (%rbx)
        (0x2d272b3, 'ff159f8b7b03'),      # call *thread-arc drop slot
        (0x2d272be, 'f048ff08'),          # lock decq (%rax) cell
        (0x2d272c9, 'ff15918b7b03'),      # call *cell drop slot A
    ],
    'caller_x2a': [
        (0x5a08485, 'e866bdc0ff'),        # call spawn_x2a
        (0x5a084b8, 'ff159279ad00'),      # call *pthread_detach slot
        (0x5a084be, 'f049ff0c24'),        # lock decq (%r12)
        (0x5a084c8, 'ff158a79ad00'),      # call *thread-arc drop slot
        (0x5a084d3, 'f048ff08'),          # lock decq (%rax) cell
        (0x5a084dc, 'ff157e79ad00'),      # call *cell drop slot A
    ],
    'caller_x2b': [
        (0x5a6dfa7, 'e8b469baff'),        # call spawn_x2b
        (0x5a6dfd3, 'ff15771ea700'),      # call *pthread_detach slot
        (0x5a6dfd9, 'f048ff0b'),          # lock decq (%rbx)
        (0x5a6dfe4, 'ff156e1ea700'),      # call *thread-arc drop slot
        (0x5a6dfef, 'f048ff08'),          # lock decq (%rax) cell
        (0x5a6dffa, 'ff15601ea700'),      # call *cell drop slot A
    ],
    'caller_x2c': [
        (0x5a08ce5, 'e8e6c3c0ff'),        # call spawn_x2c
        (0x5a08d18, 'ff153271ad00'),      # call *pthread_detach slot
        (0x5a08d1e, 'f049ff0c24'),        # lock decq (%r12)
        (0x5a08d28, 'ff152a71ad00'),      # call *thread-arc drop slot
        (0x5a08d33, 'f048ff08'),          # lock decq (%rax) cell
        (0x5a08d3c, 'ff151e71ad00'),      # call *cell drop slot A
    ],
    'caller_x3': [
        (0x5bbeb06, 'e885410000'),        # call spawn_x3
        (0x5bbeb33, 'ff1517139200'),      # call *pthread_detach slot
        (0x5bbeb39, 'f049ff0e'),          # lock decq (%r14)
        (0x5bbeb44, 'ff150e139200'),      # call *thread-arc drop slot
        (0x5bbeb4f, 'f048ff08'),          # lock decq (%rax) cell
        (0x5bbeb58, 'ff1502139200'),      # call *cell drop slot A
    ],
    'caller_x4': [
        (0x5cd5f45, 'e826350000'),        # call spawn_x4
        (0x5cd5f72, 'ff15d89e8000'),      # call *pthread_detach slot
        (0x5cd5f78, 'f048ff0b'),          # lock decq (%rbx)
        (0x5cd5f83, 'ff15cf9e8000'),      # call *thread-arc drop slot
        (0x5cd5f8e, 'f048ff08'),          # lock decq (%rax) cell
        (0x5cd5f97, 'ff15b36b8100'),      # call *cell drop slot X4
    ],
    'caller_x5': [
        (0x5cf5347, 'e8341b0000'),        # call spawn_x5
        (0x5cf5364, '4889442440'),        # mov %rax,0x40(%rsp) copy w0
        (0x5cf5369, '4889542448'),        # mov %rdx,0x48(%rsp) copy w1
        (0x5cf536e, '48894c2450'),        # mov %rcx,0x50(%rsp) copy w2
        (0x5cf53b9, 'e842b3ffff'),        # call insert_x5
        (0x5cf53d1, 'ff1579aa7e00'),      # detach displaced value
        (0x5cf53d7, 'f049ff0e'),          # lock decq (%r14)
        (0x5cf53e2, 'ff1570aa7e00'),      # call *thread-arc drop slot
        (0x5cf53ed, 'f048ff08'),          # lock decq (%rax) cell
        (0x5cf53fc, 'ff1546787f00'),      # call *cell drop slot X5
    ],
    'caller_v2': [
        (0x15d64a3, 'e8180ffeff'),        # call spawn_v2
        (0x15d64b6, '4885c9'),            # test %rcx,%rcx word0 check
        (0x15d64c4, '48894c2408'),        # mov %rcx,0x8(%rsp) keep w0
        (0x15d6561, '0f10442408'),        # movups 0x8(%rsp),%xmm0 copy
        (0x15d6587, 'e83433ffff'),        # call registry body 15c98c0
        (0x15d66f0, 'e8ab910000'),        # landing pad: call drop_a
    ],
    'join_a': [
        (0x15b8824, 'ff15668df204'),      # call *pthread_join slot
        (0x15b886b, '4c8b7020'),          # mov 0x20(%rax),%r14 take
        (0x15b886f, '4c8b7828'),          # mov 0x28(%rax),%r15 take
        (0x15b8873, 'f6401801'),          # testb $1,0x18(%rax)
        (0x15b8877, '48c7401800000000'),  # movq $0,0x18(%rax)
    ],
    'join_x5': [
        (0x5cf7564, 'ff1526a07e00'),      # call *pthread_join slot
        (0x5cf75ab, '4c8b7020'),          # mov 0x20(%rax),%r14 take
        (0x5cf75af, '4c8b7828'),          # mov 0x28(%rax),%r15 take
        (0x5cf75b3, 'f6401801'),          # testb $1,0x18(%rax)
        (0x5cf75b7, '48c7401800000000'),  # movq $0,0x18(%rax)
    ],
    'other_join': [
        (0x564680d, 'ff157dade900'),      # call *pthread_join slot
        (0x564685c, '488b5058'),          # mov 0x58(%rax),%rdx big cell
    ],
    'handle_drop_a': [
        (0x15df8a4, '488b7f10'),          # mov 0x10(%rdi),%rdi word2
        (0x15df8a8, 'ff15a205f004'),      # call *pthread_detach slot
        (0x15df8ba, 'ff159805f004'),      # call *thread-arc drop slot
        (0x15df8d2, 'ff258805f004'),      # jmp *cell drop slot A
    ],
    'handle_drop_x5': [
        (0x5cf3577, '488b7f10'),          # mov 0x10(%rdi),%rdi word2
        (0x5cf357b, 'ff15cfc87e00'),      # call *pthread_detach slot
        (0x5cf358d, 'ff15c5c87e00'),      # call *thread-arc drop slot
        (0x5cf35ab, 'ff2597967f00'),      # jmp *cell drop slot X5
    ],
    'join_consumer_a': [
        (0x15ec44d, '488b83b0000000'),    # mov 0xb0(%rbx),%rax w2
        (0x15ec459, '0f1083a0000000'),    # movups 0xa0(%rbx),%xmm0
        (0x15ec467, 'e8a4c3fcff'),        # call join_a
        (0x15ec46c, '4885c0'),            # test %rax,%rax pair data
        (0x15ec480, 'e88b5af7ff'),        # call pair conversion
    ],
    'join_x5_consumer_a': [
        (0x5cf4186, 'e8c5330000'),        # call join_x5
        (0x5cf4196, '488b02'),            # mov (%rdx),%rax pair vt
        (0x5cf41a1, 'ffd0'),              # call *%rax dispatch pair
        (0x5cf4321, 'e82a320000'),        # call join_x5 (second)
    ],
    'join_x5_consumer_b': [
        (0x5cf4d67, 'e8e4270000'),        # call join_x5
        (0x5cf4d77, '488b02'),            # mov (%rdx),%rax pair vt
        (0x5cf4d82, 'ffd0'),              # call *%rax dispatch pair
    ],
    'insert_x5': [
        (0x5cf071b, '488d6e20'),          # lea 0x20(%rsi),%rbp map
        (0x5cf0725, 'e8864affff'),        # call map lock helper
    ],
    'spawn_v2': [
        (0x15b76d0, '488d05198ee404'),    # lea entry 0x64004f0
        (0x15b7710, 'ff156a9ef204'),      # call *thread-create slot
    ],
    'spawn_v4': [
        (0x15b8436, '488d05f380e404'),    # lea entry 0x6400530
        (0x15b8476, 'ff150491f204'),      # call *thread-create slot
    ],
}

# Static one-method vtable entries: (base, family, dispatcher role).
ENTRIES = [
    (0x64004d0, 'L', 'dispatcher_v1'),
    (0x64004f0, 'L', 'dispatcher_v2'),
    (0x6400510, 'L', 'dispatcher_v3'),
    (0x6400530, 'L', 'dispatcher_v4'),
    (0x6451280, 'X1', 'dispatcher_x1'),
    (0x64aa788, 'X2', 'dispatcher_x2a'),
    (0x64aa7a8, 'X2', 'dispatcher_x2b'),
    (0x64aa7c8, 'X2', 'dispatcher_x2c'),
    (0x64bdc50, 'X3', 'dispatcher_x3'),
    (0x64c5330, 'X4', 'dispatcher_x4'),
    (0x64c6ac0, 'X5', 'dispatcher_x5'),
]

DISPATCHER_START = {
    'dispatcher_v1': 0x15b8cd0, 'dispatcher_v2': 0x15b8e40,
    'dispatcher_v3': 0x15b91d0, 'dispatcher_v4': 0x15b8fd0,
    'dispatcher_x1': 0x2dd4f10, 'dispatcher_x2a': 0x561f970,
    'dispatcher_x2b': 0x561fed0, 'dispatcher_x2c': 0x5620120,
    'dispatcher_x3': 0x5bc3350, 'dispatcher_x4': 0x5cd9b30,
    'dispatcher_x5': 0x5cf7710,
}

SPAWN_OF = {'dispatcher_v1': 'spawn_v1', 'dispatcher_v2': 'spawn_v2',
            'dispatcher_v3': 'spawn_v3', 'dispatcher_v4': 'spawn_v4',
            'dispatcher_x1': 'spawn_x1', 'dispatcher_x2a': 'spawn_x2a',
            'dispatcher_x2b': 'spawn_x2b', 'dispatcher_x2c': 'spawn_x2c',
            'dispatcher_x3': 'spawn_x3', 'dispatcher_x4': 'spawn_x4',
            'dispatcher_x5': 'spawn_x5'}
CALLER_OF = {v: 'caller_' + k.split('_', 1)[1]
             for k, v in SPAWN_OF.items()}

DETACH_SLOT = 0x64dfe50
JOIN_SLOT_USED = 0x64e1590
JOIN_SLOT_UNUSED = 0x64ee1f0

# Hashes published by the packet-cell packet (#3050) for the two
# bodies both packets pin; equality is the no-contradiction check.
PREV_3050 = {
    'spawn_v4': '967d4b0bb72e2e86245bc092d3d850f2324631adaf5482ac'
                '4df09804e3f152b8',
    'join_a': 'f57a1ff86b1b2a431d2c168a23145ea2e603de76a51c662852d'
              '29c39853587aa',
}

FATES = {
    'dispatcher_v1': 'dropped_detached_in_place',
    'dispatcher_v2': 'kept_owned_guard_registered',
    'dispatcher_v3': 'dropped_detached_in_place',
    'dispatcher_v4': 'dropped_detached_in_place',
    'dispatcher_x1': 'dropped_detached_in_place',
    'dispatcher_x2a': 'dropped_detached_in_place',
    'dispatcher_x2b': 'dropped_detached_in_place',
    'dispatcher_x2c': 'dropped_detached_in_place',
    'dispatcher_x3': 'dropped_detached_in_place',
    'dispatcher_x4': 'dropped_detached_in_place',
    'dispatcher_x5': 'stored_in_owner_map',
}

QUESTION = (
    'The packet-cell packet (#3050) left sibling dispatchers\' '
    'JoinHandle ownership untraced: for each of the eleven '
    'static-table dispatchers of #3000, who spawns its thread, '
    'what does the spawn\'s only caller do with the returned '
    '0x18-byte JoinHandle {thread Arc, packet-cell Arc, '
    'pthread_t} -- keep it, store it, or drop it -- and does '
    'any body ever read the pair the thread stores into the '
    'packet cell through the matching join body?')

ANSWER = {
    'spawns': ('Each entry base is loaded by exactly one lea '
               'in .text, inside its own spawn body; each spawn '
               'body has exactly one direct call site.'),
    'dropped': ('Nine call sites (v1, v3, v4, x1, x2a, x2b, '
                'x2c, x3, x4) drop the handle in place: '
                'pthread_detach on the fresh pthread word, '
                'then release of both Arcs. Those threads run '
                'detached; their pairs are never read through '
                'a handle.'),
    'kept_v2': ('v2\'s caller keeps the handle in an owned '
                'local (outlined drop 0x15df8a0) and registers '
                'the worker; it is the only type-A handle not '
                'destroyed at its call site.'),
    'stored_x5': ('x5\'s caller stores the fresh handle in a '
                  'hash map inside the owner struct via insert '
                  'body 0x5cf0700 and detaches only the value '
                  'the insert displaces.'),
    'readers': ('Exactly two take-style join bodies exist: '
                'join_a 0x15b8810 (type-A cell) with one call '
                'site in 0x15ec360 consuming a stored handle\'s '
                'pair, and join_x5 0x5cf7550 with three call '
                'sites in two bodies that dispatch the returned '
                'pair. The only other pthread_join caller, '
                '0x56467d0, joins a different, larger cell. '
                'No join body exists for the X4 cell type.'),
}

BOUNDARIES = [
    'The instruction-level data flow from v2\'s registered '
    'guard into the exact owner field the join consumer reads '
    '(+0xa0) is not traced; the v2 claim is the elimination '
    'form: it is the only type-A handle that survives its '
    'call site, and the only type-A join call site consumes '
    'a stored handle.',
    'Join-internal semantics (the CAS/take order) of join_x5 '
    'and of the x5 detach path are the subject of open PR '
    '#3074 and are not re-derived here; both bodies are '
    'pinned only as census nodes.',
    'Censuses cover direct (E8) calls and indirect calls '
    'through GOT slots; register-indirect calls (call *%reg) '
    'cannot be enumerated statically and are out of scope. '
    'No RELATIVE slot points at join_a or join_x5.',
    'The X4 cell layout remains as #3050 left it (only its '
    'finish-store idiom is classified); the no-join claim '
    'for X4 rests on the pthread_join caller census and the '
    'take-idiom census, not on the X4 layout.',
]

LIMITS = ('Static analysis only: the artifact was '
          'disassembled, never executed. Every census is '
          're-derived from the materialised artifact by '
          'analyze(); byte pins fix the decisive instructions '
          'at each call site.')


def read(va, data, size=None):
    for section in sections(data):
        if section['type'] == 8:
            continue
        if (section['address'] <= va and
                va < section['address'] + section['size']):
            offset = section['offset'] + va - section['address']
            end = (section['offset'] + section['size'] if size is None
                   else offset + size)
            return offset, bytes(data[offset:end])
    raise ValueError(hex(va))


def check(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def owners(data):
    check(len(data) == TARGET_SIZE and sha(data) == TARGET_SHA256,
          'unexpected node artifact')
    _, fdes, _ = fde_extents(data)
    extents = {(f['start'], f['end']) for f in fdes}
    records = {}
    for role, (start, end, digest) in OWNERS.items():
        check((start, end) in extents, f'missing FDE {role}')
        offset, body = read(start, data, end - start)
        check(sha(body) == digest, f'body hash mismatch {role}')
        records[role] = {'start': hex(start), 'end': hex(end),
                         'file_offset': hex(offset),
                         'bytes': end - start, 'sha256': digest}
    return records


def check_pins(data):
    records = {}
    for role, rows in PINS.items():
        start, end, _ = OWNERS[role]
        _, body = read(start, data, end - start)
        for va, expected in rows:
            got = body[va - start:va - start +
                       len(bytes.fromhex(expected))]
            check(got.hex() == expected,
                  f'byte pin mismatch {role} at {va:#x}')
        records[role] = {hex(va): expected for va, expected in rows}
    return records


def rela_entries(data):
    """All rela rows: offset -> [(type, sym_index, addend)]."""
    secs = sections(data)
    out = {}
    for name in ('.rela.dyn', '.rela.plt'):
        dyn = next((s for s in secs if s['name'] == name), None)
        if dyn is None:
            continue
        for i in range(dyn['size'] // 24):
            off, info, add = struct.unpack_from(
                '<QQq', data, dyn['offset'] + i * 24)
            out.setdefault(off, []).append(
                (info & 0xffffffff, info >> 32, add))
    return out


def relative_map(data):
    return {off: add for off, rows in rela_entries(data).items()
            for typ, sym, add in rows if typ == 8}


def sym_names(data):
    secs = sections(data)
    dynsym = next(s for s in secs if s['name'] == '.dynsym')
    dynstr = next(s for s in secs if s['name'] == '.dynstr')
    table = data[dynstr['offset']:dynstr['offset'] + dynstr['size']]

    def name(idx):
        off = dynsym['offset'] + idx * 24
        name_off = struct.unpack_from('<I', data, off)[0]
        end = table.find(b'\0', name_off)
        return table[name_off:end].decode('utf-8', 'replace')
    return name


def tables(data):
    rel = relative_map(data)
    records = []
    for base, family, role in ENTRIES:
        _, raw = read(base + 8, data, 16)
        size, align = struct.unpack('<QQ', raw)
        drop = rel.get(base)
        method = rel.get(base + 0x18)
        check(drop is not None and method is not None,
              f'table entry {base:#x} missing relocations')
        check(method == DISPATCHER_START[role],
              f'table method mismatch at {base:#x}')
        check(align == 8, f'table align mismatch at {base:#x}')
        records.append({'base': hex(base), 'family': family,
                        'dispatcher': role, 'drop': hex(drop),
                        'size': hex(size), 'align': hex(align),
                        'method': hex(method),
                        'spawn': SPAWN_OF[role],
                        'caller': CALLER_OF[SPAWN_OF[role]]})
    return records


def slots(data):
    rela = rela_entries(data)
    name = sym_names(data)
    records = {}
    for label, slot in (('pthread_detach', DETACH_SLOT),
                        ('thread_arc_drop', 0x64dfe58),
                        ('cell_drop_a', 0x64dfe60),
                        ('cell_drop_x4', 0x64ecb50),
                        ('cell_drop_x5', 0x64ecc48),
                        ('thread_create', 0x64e1580)):
        rows = rela.get(slot)
        check(rows, f'slot {label} {slot:#x} has no relocation')
        typ, sym, add = rows[0]
        rec = {'slot': hex(slot), 'type': typ,
               'target': hex(add) if typ == 8 else None}
        if sym:
            rec['symbol'] = name(sym)
        records[label] = rec
    check(records['pthread_detach'].get('symbol') == 'pthread_detach',
          'detach slot is not pthread_detach')
    join_slots = {}
    for slot in (JOIN_SLOT_USED, JOIN_SLOT_UNUSED):
        rows = rela.get(slot)
        check(rows, f'join slot {slot:#x} has no relocation')
        typ, sym, add = rows[0]
        check(name(sym) == 'pthread_join',
              f'slot {slot:#x} is not pthread_join')
        join_slots[hex(slot)] = {'type': typ, 'symbol': 'pthread_join'}
    records['pthread_join_slots'] = join_slots
    return records


def _text(data):
    sec = next(s for s in sections(data) if s['name'] == '.text')
    return sec, data[sec['offset']:sec['offset'] + sec['size']]


def _starts(data):
    _, entries = unwind_index(data)
    return sorted(e['start'] for e in entries)


def _containing(starts, va):
    import bisect
    i = bisect.bisect_right(starts, va) - 1
    check(i >= 0, f'no FDE for {va:#x}')
    return starts[i]


_LEA = re.compile(rb'[\x48\x49\x4c\x4d]\x8d[\x05\x0d\x15\x1d'
                  rb'\x25\x2d\x35\x3d]')


def lea_census(data):
    sec, tb = _text(data)
    base = sec['address']
    starts = _starts(data)
    targets = {b for b, _, _ in ENTRIES}
    out = {}
    for m in _LEA.finditer(tb):
        va = base + m.start()
        disp = struct.unpack_from('<i', tb, m.end())[0]
        tgt = va + (m.end() - m.start()) + 4 + disp
        if tgt in targets:
            body = _containing(starts, va)
            out.setdefault(hex(tgt), []).append(
                {'site': hex(va), 'body': hex(body)})
    expect = {}
    for base_va, _, role in ENTRIES:
        spawn = SPAWN_OF[role]
        expect[hex(base_va)] = OWNERS[spawn][0]
    check(set(out) == set(expect), 'lea census coverage mismatch')
    for entry, sites in out.items():
        check(len(sites) == 1, f'entry {entry} lea count != 1')
        check(int(sites[0]['body'], 16) == expect[entry],
              f'entry {entry} lea not in its spawn body')
    return out


def _e8_census(data, targets):
    """targets: {name: start}. Returns {name: [{site, body}]}."""
    sec, tb = _text(data)
    base = sec['address']
    starts = _starts(data)
    inv = {v: k for k, v in targets.items()}
    out = {k: [] for k in targets}
    for m in re.finditer(rb'\xe8', tb):
        va = base + m.start()
        disp = struct.unpack_from('<i', tb, m.start() + 1)[0]
        tgt = va + 5 + disp
        if tgt in inv:
            body = _containing(starts, va)
            out[inv[tgt]].append({'site': hex(va), 'body': hex(body)})
    return out


def spawn_call_census(data):
    targets = {role: OWNERS[role][0]
               for role in OWNERS if role.startswith('spawn_')}
    out = _e8_census(data, targets)
    for role, sites in out.items():
        caller = CALLER_OF[role]
        check(len(sites) == 1, f'{role} call count != 1')
        check(int(sites[0]['body'], 16) == OWNERS[caller][0],
              f'{role} caller is not {caller}')
    return out


_TESTB = re.compile(rb'(?:\x41)?\xf6[\x40-\x47]\x18\x01')
_ZERO18 = re.compile(rb'[\x48\x49]\xc7[\x40-\x47]\x18\x00\x00\x00\x00')


def take_idiom_census(data):
    sec, tb = _text(data)
    base = sec['address']
    starts = _starts(data)
    hits = {}
    for label, pat in (('testb', _TESTB), ('zero', _ZERO18)):
        for m in pat.finditer(tb):
            body = _containing(starts, base + m.start())
            hits.setdefault(body, set()).add(label)
    bodies = sorted(b for b, kinds in hits.items()
                    if kinds == {'testb', 'zero'})
    check(bodies == [OWNERS['join_a'][0], OWNERS['join_x5'][0]],
          'take-idiom census != the two pinned join bodies')
    return {'bodies': [hex(b) for b in bodies], 'count': len(bodies)}


def _slot_sites(data, slot):
    sec, tb = _text(data)
    base = sec['address']
    starts = _starts(data)
    out = []
    for m in re.finditer(rb'\xff[\x15\x25]', tb):
        va = base + m.start()
        disp = struct.unpack_from('<i', tb, m.end())[0]
        if va + 6 + disp == slot:
            out.append({'site': hex(va),
                        'body': hex(_containing(starts, va)),
                        'kind': 'jmp' if tb[m.start() + 1] == 0x25
                                else 'call'})
    return out


def pthread_census(data):
    join_used = _slot_sites(data, JOIN_SLOT_USED)
    join_unused = _slot_sites(data, JOIN_SLOT_UNUSED)
    bodies = sorted({r['body'] for r in join_used})
    check(bodies == sorted([hex(OWNERS['join_a'][0]),
                            hex(OWNERS['join_x5'][0]),
                            hex(OWNERS['other_join'][0])]),
          'pthread_join caller bodies mismatch')
    check(join_unused == [], 'unused pthread_join slot has sites')
    detach = _slot_sites(data, DETACH_SLOT)
    check(len(detach) == 40, 'pthread_detach site count != 40')
    return {'pthread_join_sites': join_used,
            'pthread_join_bodies': bodies,
            'pthread_join_unused_slot_sites': join_unused,
            'pthread_detach_sites': detach,
            'pthread_detach_count': len(detach)}


def detach_census(data):
    """Detach sites inside each pinned caller / consumer / drop."""
    sites = _slot_sites(data, DETACH_SLOT)
    by_body = {}
    for r in sites:
        by_body.setdefault(r['body'], []).append(r['site'])
    expect = {}
    for role in ('caller_v1', 'caller_v3', 'caller_v4', 'caller_x1',
                 'caller_x2a', 'caller_x2b', 'caller_x2c', 'caller_x3',
                 'caller_x4', 'caller_x5', 'join_x5_consumer_a',
                 'join_x5_consumer_b', 'handle_drop_a',
                 'handle_drop_x5'):
        expect[role] = 1
    expect['caller_v2'] = 0
    records = {}
    for role, want in expect.items():
        start = hex(OWNERS[role][0])
        got = sorted(by_body.get(start, []))
        check(len(got) == want,
              f'detach sites in {role}: {len(got)} != {want}')
        records[role] = got
    return records


def join_census(data):
    targets = {'join_a': OWNERS['join_a'][0],
               'join_x5': OWNERS['join_x5'][0],
               'join_consumer_a': OWNERS['join_consumer_a'][0],
               'join_consumer_top': OWNERS['join_consumer_top'][0],
               'insert_x5': OWNERS['insert_x5'][0],
               'handle_drop_a': OWNERS['handle_drop_a'][0]}
    out = _e8_census(data, targets)
    ja = out['join_a']
    check(len(ja) == 1 and
          int(ja[0]['body'], 16) == OWNERS['join_consumer_a'][0],
          'join_a call sites mismatch')
    jx = out['join_x5']
    check(len(jx) == 3, 'join_x5 call count != 3')
    check({r['body'] for r in jx} ==
          {hex(OWNERS['join_x5_consumer_a'][0]),
           hex(OWNERS['join_x5_consumer_b'][0])},
          'join_x5 caller bodies mismatch')
    jc = out['join_consumer_a']
    check(len(jc) == 1 and
          int(jc[0]['body'], 16) == OWNERS['join_consumer_top'][0],
          'join_consumer_a call sites mismatch')
    check(len(out['join_consumer_top']) == 2,
          'join_consumer_top call count != 2')
    ins = out['insert_x5']
    check(len(ins) == 1 and
          int(ins[0]['body'], 16) == OWNERS['caller_x5'][0],
          'insert_x5 call sites mismatch')
    hd = out['handle_drop_a']
    check(any(int(r['body'], 16) == OWNERS['caller_v2'][0]
              for r in hd),
          'caller_v2 landing pads do not call handle_drop_a')
    rel = relative_map(data)
    slots_to = {}
    for role in ('join_a', 'join_x5', 'other_join', 'caller_v2'):
        start = OWNERS[role][0]
        slots_to[role] = [hex(s) for s, t in rel.items() if t == start]
    check(slots_to['join_a'] == [] and slots_to['join_x5'] == [],
          'a RELATIVE slot points at a join body')
    check(slots_to['other_join'] == ['0x64e7388'],
          'other_join RELATIVE slots mismatch')
    check(slots_to['caller_v2'] == ['0x64e1750'],
          'caller_v2 RELATIVE slots mismatch')
    out['relative_slots_to'] = slots_to
    return out


def fates(data):
    records = {}
    for base, family, role in ENTRIES:
        records[role] = {'entry': hex(base), 'family': family,
                         'spawn': SPAWN_OF[role],
                         'caller': CALLER_OF[SPAWN_OF[role]],
                         'fate': FATES[role]}
    return records


def prev_packet_check(data):
    records = {}
    for role, digest in PREV_3050.items():
        check(OWNERS[role][2] == digest,
              f'{role} hash differs from #3050 constants')
        records[role] = {'sha256': digest, 'matches_3050': True}
    return records


def objdump_range(data, start, end):
    text = subprocess.run(
        ['objdump', '-d', '--start-address', hex(start),
         '--stop-address', hex(end), str(TARGET)],
        check=True, capture_output=True, text=True).stdout
    return text.replace(str(TARGET), SNAPSHOT, 1)


def exports(data, role):
    start, end, _ = OWNERS[role]
    return objdump_range(data, start, end)


def frame_lines(data):
    text = subprocess.run(['readelf', '-wf', str(TARGET)],
                          check=True, capture_output=True,
                          text=True).stdout
    wanted = []
    for start, end, _ in OWNERS.values():
        needle = (f'pc={start:016x}..{end:016x}')
        wanted += [ln for ln in text.splitlines() if needle in ln]
    check(len(wanted) == len(OWNERS), 'owner frame lines missing')
    return [line + '\n' for line in wanted]


def analyze(data):
    owner_records = owners(data)
    pin_records = check_pins(data)
    return {
        'artifact': {'path': 'artifacts/node/115/hl-node',
                     'bytes': TARGET_SIZE, 'sha256': TARGET_SHA256,
                     'snapshot': SNAPSHOT},
        'packet': WORK_ITEM,
        'captured_code_executed': False,
        'question': QUESTION,
        'answer': ANSWER,
        'owners': owner_records,
        'pins': pin_records,
        'tables': tables(data),
        'slots': slots(data),
        'lea_census': lea_census(data),
        'spawn_call_census': spawn_call_census(data),
        'take_idiom_census': take_idiom_census(data),
        'pthread_census': pthread_census(data),
        'detach_census': detach_census(data),
        'join_census': join_census(data),
        'fates': fates(data),
        'prev_packet_check': prev_packet_check(data),
        'boundaries': BOUNDARIES,
        'limits': LIMITS,
    }


def generate(data):
    OUT.mkdir(parents=True, exist_ok=True)
    records = analyze(data)
    (OUT / 'records.json').write_text(
        json.dumps(records, indent=1, sort_keys=True) + '\n')
    (OUT / 'frames.txt').write_text(''.join(frame_lines(data)))
    for role in EXPORTED:
        (OUT / f'{role}.objdump.txt').write_text(exports(data, role))


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--generate', action='store_true')
    args = parser.parse_args()
    data = TARGET.read_bytes()
    if args.generate:
        generate(data)
        return
    records = analyze(data)
    expected = json.loads((OUT / 'records.json').read_text())
    check(records == expected, 'records.json is stale')
    for role in EXPORTED:
        check((OUT / f'{role}.objdump.txt').read_text() ==
              exports(data, role), f'{role}.objdump.txt is stale')
    check((OUT / 'frames.txt').read_text() ==
          ''.join(frame_lines(data)), 'frames.txt is stale')
    print(json.dumps({'packet': WORK_ITEM, 'matches': True},
                     sort_keys=True))


if __name__ == '__main__':
    main()
