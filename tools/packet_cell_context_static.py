#!/usr/bin/env python3
"""Node 115: the packet cell's context pointer (cell +0x10).

The packet-cell layout packets (#3050 for type-A, #3160 for
X4/X5) pinned the 0x30-byte packet cell field by field and
left exactly one field unidentified: the pointer at cell
+0x10, called context A.  What the layouts established about
it: the spawn body stores it from its r9 argument and
increments a counter at A+0x18; the payload drop sets a flag
byte at A+0x20 when it discards a live pair, decrements the
counter at A+0x18 and, when the counter reaches zero, xchgs
1 into the word at [A+0x10]+0x28; the cell glue releases the
pointer through a family context-release glue.  What A is,
who creates it and who hands it to the spawn bodies was left
open ("the same limit as #3050 for type-A").

Answers, all static and re-derived by analyze() below:

1.  Identity.  A is the std scoped-thread scope state: the
    object library/std/src/thread/scoped.rs calls ScopeData,
    held here as a 0x28-byte Arc allocation -- strong count
    at A+0x00, weak count at A+0x08, then the payload:
    the scope-creating thread's handle at A+0x10, the
    running-thread counter (num_running_threads) at A+0x18,
    and a flag byte (a_thread_panicked) at A+0x20.  The
    identification does not rest on a name string: the
    counter increment in every spawn body is guarded by a
    signed-overflow branch to a shared cold stub
    (0x5c82d40) that panics at the only scoped.rs Location
    record in the whole binary (0x64c32f0: scoped.rs line
    60, column 9) with the message "too many running
    threads in thread scope" (40 packed bytes at
    0x9492bf) --
    the ScopeData::increment overflow panic.  The payload
    drop's tail is the matching decrement: flag at A+0x20
    when a live result pair is discarded, lock decq at
    A+0x18, and on reaching zero an xchg of 1 into the word
    at [A+0x10]+0x28 -- the main thread's parker state word
    -- followed, iff the old word was -1 (parked), by a
    futex wake through the libc `syscall` slot 0x64e06b8
    (number 202, op 0x81 = FUTEX_WAKE|FUTEX_PRIVATE_FLAG,
    count 1): ScopeData::decrement unparking the scope's
    main thread.  The release chain agrees: the cell glue
    decrements the strong count at A+0x00 and, at zero,
    calls the family context-release glue (A 0x5bc24b0 via
    slot 0x64e1588, X4 0x5cd88d0 via 0x64ecb68, X5
    0x5ce8660 via 0x64ecc50), which drops the thread handle
    at A+0x10 (its strong count, then the shared thread
    drop glue 0x5c98b40 via slot 0x64dfe58), decrements
    the weak count at A+0x08 and deallocates exactly
    0x28 bytes -- the Arc<ScopeData> allocation size for
    a {handle, counter, flag} payload.
2.  Producers in this binary: none live.  The counter
    increment idiom (lock incq 0x18(%rdi) on the fresh
    cell's +0x10 word, null-guarded, overflow to the
    scoped panic stub) occurs in exactly 14 spawn bodies
    binary-wide -- the three packet families' spawns
    (A 0x15b80e0, X4 0x5cd9470, X5 0x5cf6e80) plus eleven
    more monomorphisations.  Those 14 bodies have exactly
    16 direct call sites between them, and at every one
    the last write to r9 before the call is
    `xor %r9d,%r9d`: the scope argument is null at all 16.
    No indirect entry exists (no slot call, lea reference
    or relocated data pointer names any of the 14).  The
    three families' own callers are the vendored
    threadpool crate's thread spawn (caller_x4, Location
    z_vendor/threadpool/src/lib.rs:777), tokio's blocking
    pool spawn (caller_x5, Locations
    z_vendor/tokio/src/runtime/blocking/pool.rs:415/424/
    450), and a spawn reached from std thread functions
    and base/src/lazy_mutex.rs (caller_a) -- none of them
    a thread::scope site, so the packet cells of all
    three families always carry a null context and the
    ScopeData ledger in their payload drops is inert.
    The machinery is live code only as the shared Packet
    implementation of scoped and unscoped spawn.
3.  Census closure.  The payload-drop ledger template
    (flag store at payload +0x10 of the context ledger,
    counter decrement, thread-handle load, parker xchg)
    occurs in exactly 6 bodies: the three families'
    payload drops (A 0x5bc3bf0, X4 0x5cda210, X5
    0x5cfc3e0) and three more for other result types
    (0x2deb7e0, 0x565bfc0, 0x565c0c0).  A bare
    lock decq/incq at displacement +0x18 is NOT the
    discriminator -- two further bodies (0x5bc0f60,
    0x5cf3830) decrement a +0x18 word of unrelated
    structures and lack the flag/xchg companions; the
    four-instruction template is what discriminates.
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
WORK_ITEM = 'RE-005-node115-packet-cell-context'
OUT = ROOT / 'research/work-items' / WORK_ITEM

OWNERS = {
    'spawn_a': (0x15b80e0, 0x15b8804,
                '967d4b0bb72e2e86245bc092d3d850f2324631adaf'
                '5482ac4df09804e3f152b8'),
    'caller_a': (0x150b310, 0x150baaf,
                 '19ca3e09da69f37a39c2ed3da2e50a02184d751578'
                 '57d65c0edd955c1369c2f2'),
    'payload_drop_a': (0x5bc3bf0, 0x5bc3d5e,
                       '34b27ee7a0f42fc39e8ec6eb5ff80aac859e4e'
                       'fa05834dfc7cc2e39d8443c667'),
    'cell_glue_a': (0x5bc2a80, 0x5bc2bb4,
                    'fd3d9290228daf8af09b05b6c33b186878cb988f7'
                    'e7eb2af500c61c5e5957ca2'),
    'context_release_a': (0x5bc24b0, 0x5bc251f,
                          '9f81ff6a58706bb981ed5dad414257dd5107'
                          'd35299d0f06258c088a17f72f30e'),
    'spawn_x4': (0x5cd9470, 0x5cd9b2f,
                 'a67df4f7707481778d223fca1d10a1dcb3360ea805ae'
                 '3215f317882fa163c6a2'),
    'caller_x4': (0x5cd5ea0, 0x5cd603c,
                  '78c17eaf8863e6bb09cf2622c31002bc8a612caaff'
                  '93c71eaa40d3c851f5427d'),
    'payload_drop_x4': (0x5cda210, 0x5cda37e,
                        '6cfdb2d06e84078fd1f654681ea6a1d4cc4fb711'
                        'a2fddf7883c66390f668b12e'),
    'cell_glue_x4': (0x5cd86e0, 0x5cd880f,
                     'b00b49cda8cc6f4e875da8f3046d7bd18e270fbec6'
                     'a3235ccbba0e67b376f5ac'),
    'context_release_x4': (0x5cd88d0, 0x5cd8908,
                           '6804f49815f9909b13e7c26c15ce5103f24c5b'
                           '79c52b4cb99bed9101fec66d0a'),
    'spawn_x5': (0x5cf6e80, 0x5cf7550,
                 '1de6a1382a5d5557a56bcc242cf2a8e7e543e089832'
                 'f43bcf8548b32a05c5a87'),
    'caller_x5': (0x5cf5100, 0x5cf55d7,
                  '3ede3e0de6239df2546301485ff8664996a025ed907'
                  'a977b2d99c6cdc054fcd8'),
    'payload_drop_x5': (0x5cfc3e0, 0x5cfc54e,
                        '7e67f86b57437f1c4a119a9872eb1786806413a7'
                        'ef944396711a70d8403d3561'),
    'cell_glue_x5': (0x5ce8390, 0x5ce84c4,
                     '47595306d82fbac24e1c7ec4c42550d1177efaa13'
                     '0783bc81ba7c27b79dc8af9'),
    'context_release_x5': (0x5ce8660, 0x5ce86cf,
                           'fea36aaf5fa44c33bc5d56acb20324576efb31'
                           'b12739faa9281508a19a9395a7'),
    'scope_panic_stub': (0x5c82d40, 0x5c82d65,
                         '8e56d981e4d3963755c766b4afc64f7601e92faa'
                         '51e0d3be992cc5df698ba8cc'),
    'scope_decrement': (0x5c82d00, 0x5c82d3b,
                        'c0e94d3d28434c43010bfb30b7db80e3ebe8d815'
                        '1133fe5a875795ec6a4d68c5'),
    'thread_field_drop': (0x5c98b40, 0x5c98b89,
                          '7ca6f244918e5003e12f248d655375601a436ae72776897c6aad46457a258c15'),
}

EXPORTED = list(OWNERS)

PINS = {
    'spawn_a': [
        (0x15b810a, '4c898c24a8000000'),
        (0x15b82ae, '488b8424a8000000'),
        (0x15b82b6, '48898424c0000000'),
        (0x15b8351, '488b7810'),
        (0x15b8355, '4885ff'),
        (0x15b835a, 'f048ff4718'),
        (0x15b8665, 'e8d6a66c04'),
    ],
    'spawn_x4': [
        (0x5cd94a3, '4c898c2488000000'),
        (0x5cd9655, '488b842488000000'),
        (0x5cd965d, '48898424a0000000'),
        (0x5cd96da, '488b7810'),
        (0x5cd96de, '4885ff'),
        (0x5cd96e3, 'f048ff4718'),
        (0x5cd99a2, 'e89993faff'),
    ],
    'spawn_x5': [
        (0x5cf6ea6, '4c898c2498000000'),
        (0x5cf704d, '488b842498000000'),
        (0x5cf7055, '48898424b0000000'),
        (0x5cf70ec, 'f048ff4718'),
        (0x5cf73d7, 'e864b9f8ff'),
    ],
    'payload_drop_a': [
        (0x5bc3c5e, '488b0348'),
        (0x5bc3c6b, 'c6402001'),
        (0x5bc3c6f, 'f048ff4818'),
        (0x5bc3c76, '488b7010'),
        (0x5bc3c7f, '874628'),
        (0x5bc3c82, '83f8ff'),
    ],
    'payload_drop_x4': [
        (0x5cda28b, 'c6402001'),
        (0x5cda28f, 'f048ff4818'),
        (0x5cda296, '488b7010'),
        (0x5cda29f, '874628'),
    ],
    'payload_drop_x5': [
        (0x5cfc45b, 'c6402001'),
        (0x5cfc45f, 'f048ff4818'),
        (0x5cfc466, '488b7010'),
        (0x5cfc46f, '874628'),
    ],
    'cell_glue_a': [
        (0x5bc2a92, 'e859110000'),
        (0x5bc2a97, '498b07'),
        (0x5bc2a9f, 'f048ff08'),
        (0x5bc2aa8, 'ff15daea9100'),
    ],
    'cell_glue_x4': [
        (0x5cd86f2, 'e8191b0000'),
        (0x5cd86f7, '498b07'),
        (0x5cd86ff, 'f048ff08'),
        (0x5cd8708, 'ff155a448100'),
    ],
    'cell_glue_x5': [
        (0x5ce83a2, 'e839400100'),
        (0x5ce83a7, '498b07'),
        (0x5ce83af, 'f048ff08'),
        (0x5ce83b8, 'ff1592488000'),
    ],
    'context_release_a': [
        (0x5bc24b4, '488b1f'),
        (0x5bc24b7, '488b4310'),
        (0x5bc24bb, 'f048ff08'),
        (0x5bc24c5, 'ff158dd99100'),
        (0x5bc24d1, 'f048ff4b08'),
        (0x5bc24d8, 'be28000000'),
    ],
    'context_release_x4': [
        (0x5cd88d1, '488b1f'),
        (0x5cd88d4, '488b4310'),
        (0x5cd88d8, 'f048ff08'),
        (0x5cd88e2, 'ff1570758000'),
        (0x5cd88ee, 'f048ff4b08'),
        (0x5cd88f5, 'be28000000'),
    ],
    'context_release_x5': [
        (0x5ce8664, '488b1f'),
        (0x5ce8667, '488b4310'),
        (0x5ce866b, 'f048ff08'),
        (0x5ce8675, 'ff15dd777f00'),
        (0x5ce8681, 'f048ff4b08'),
        (0x5ce8688, 'be28000000'),
    ],
    'scope_panic_stub': [
        (0x5c82d4c, '488d3d6c65ccfa'),
        (0x5c82d53, '488d1596058400'),
        (0x5c82d5a, 'be51000000'),
    ],
    'scope_decrement': [
        (0x5c82d04, 'c6471001'),
        (0x5c82d08, 'f048ff4f08'),
        (0x5c82d0f, '488b37'),
        (0x5c82d17, '874628'),
        (0x5c82d1a, '83f8ff'),
        (0x5c82d24, 'bfca000000'),
        (0x5c82d29, 'ba81000000'),
        (0x5c82d35, 'ff257dd98500'),
    ],
    'caller_a': [
        (0x150b989, '4531c9'),
        (0x150b98c, 'e84fc70a00'),
    ],
    'caller_x4': [
        (0x5cd5f42, '4531c9'),
        (0x5cd5f45, 'e826350000'),
    ],
    'caller_x5': [
        (0x5cf5344, '4531c9'),
        (0x5cf5347, 'e8341b0000'),
    ],
    'thread_field_drop': [
        (0x5c98b46, '488b1f'),
        (0x5c98b49, '488b7b18'),
        (0x5c98b6c, 'f048ff4b08'),
    ],
}

SLOTS = {
    'a_context_release': 0x64e1588,
    'x4_context_release': 0x64ecb68,
    'x5_context_release': 0x64ecc50,
    'thread_field_drop': 0x64dfe58,
    'scope_decrement': 0x64ec708,
    'panic_entry': 0x64df6b8,
    'alloc': 0x64df480,
    'dealloc': 0x64df4a0,
    'futex_syscall': 0x64e06b8,
}

SLOT_TARGETS = {
    'a_context_release': 0x5bc24b0,
    'x4_context_release': 0x5cd88d0,
    'x5_context_release': 0x5ce8660,
    'thread_field_drop': 0x5c98b40,
    'scope_decrement': 0x5c82d00,
    'panic_entry': 0x1680e80,
}

STUB = 0x5c82d40
SCOPED_LOCATION_RECORD = 0x64c32f0
PANIC_MESSAGE_VA = 0x9492bf
PANIC_MESSAGE_LEN = 40
PANIC_MESSAGE = 'too many running threads in thread scope'

INC_PATTERN = bytes.fromhex('f048ff4718')
PD_PATTERNS = {
    'flag_store': bytes.fromhex('c6402001'),
    'counter_dec': bytes.fromhex('f048ff4818'),
    'thread_load': bytes.fromhex('488b7010'),
    'parker_xchg': bytes.fromhex('874628'),
}

EXPECTED_SPAWNS = [
    0x15b6d10, 0x15b73c0, 0x15b7a80, 0x15b80e0,
    0x2d46820, 0x2d46f90, 0x2d47710,
    0x5613a70, 0x56141f0, 0x5614960, 0x56150d0,
    0x5bc2c90, 0x5cd9470, 0x5cf6e80,
]
EXPECTED_PD = [
    0x2deb7e0, 0x565bfc0, 0x565c0c0,
    0x5bc3bf0, 0x5cda210, 0x5cfc3e0,
]

QUESTION = (
    'The packet-cell packets (#3050, #3160) pinned the '
    '0x30-byte packet cell field by field and left the '
    'pointer at cell +0x10 ("context A") unidentified: the '
    'spawn body stores it from argument r9 and increments '
    'a counter at A+0x18, the payload drop keeps a ledger '
    'on it (flag byte at A+0x20, counter decrement at '
    'A+0x18, an xchg on the word at [A+0x10]+0x28), and '
    'the cell glue releases it through a family '
    'context-release glue -- but what the object is, who '
    'creates it and who hands it to the spawn bodies was '
    'left open.  What is context A?')

ANSWER = {
    'identity': (
        'Context A is the std scoped-thread scope state '
        '(ScopeData in library/std/src/thread/scoped.rs): '
        'a 0x28-byte Arc allocation whose payload the '
        'scope-creating thread shares with every thread '
        'it spawns inside std::thread::scope.  The '
        'identification is anchored in the binary, not in '
        'a name string: the increment every spawn body '
        'performs on A+0x18 overflows into the shared '
        'stub 0x5c82d40, which panics at the only '
        'scoped.rs Location record in the binary '
        '(0x64c32f0, line 60 column 9) with the message '
        '"too many running threads in thread scope" -- '
        'the ScopeData::increment overflow panic.'),
    'layout': [
        {'offset': '0x00', 'name': 'strong_count',
         'evidence': ('decremented by each family cell '
                      'glue (A 0x5bc2a9f, X4 0x5cd86ff, '
                      'X5 0x5ce83af); at zero the glue '
                      'calls the family context-release '
                      'glue through its slot')},
        {'offset': '0x08', 'name': 'weak_count',
         'evidence': ('decremented by the context-release '
                      'glue (A 0x5bc24d1, X4 0x5cd88ee, '
                      'X5 0x5ce8681); at zero the glue '
                      'deallocates 0x28 bytes')},
        {'offset': '0x10', 'name': 'main_thread_handle',
         'evidence': ('a refcounted handle: the '
                      'context-release glue decrements '
                      'the count at [A+0x10] and at zero '
                      'runs the shared thread drop glue '
                      '0x5c98b40 on the field (slot '
                      '0x64dfe58); the payload drop loads '
                      'it to reach the parker word at '
                      'handle +0x28')},
        {'offset': '0x18', 'name': 'num_running_threads',
         'evidence': ('incremented, null-guarded, by '
                      'every spawn body on the fresh '
                      'cell\u2019s context word (A '
                      '0x15b835a, X4 0x5cd96e3, X5 '
                      '0x5cf70ec), overflow to the '
                      'scoped.rs:60 panic stub; '
                      'decremented by the payload drops '
                      'when a packet is discarded')},
        {'offset': '0x20', 'name': 'a_thread_panicked_flag',
         'evidence': ('byte set to 1 by the payload drop '
                      'only when it discards a live '
                      '(state nonzero, data nonzero) '
                      'result pair: A 0x5bc3c6b, X4 '
                      '0x5cda28b, X5 0x5cfc45b')},
    ],
    'decrement_tail': (
        'When the payload drop\u2019s decrement of A+0x18 '
        'reaches zero it performs the scope wake-up: eax '
        '= 1 is xchg\u2019d into the word at '
        '[A+0x10]+0x28 (the main thread\u2019s parker '
        'state word: 1 = notified); iff the old word was '
        '-1 (parked) it calls the libc syscall slot '
        '0x64e06b8 with number 202 (futex), the word\u2019s '
        'address, op 0x81 (FUTEX_WAKE | '
        'FUTEX_PRIVATE_FLAG) and count 1.  The same '
        'ledger also survives as a standalone body, '
        'ScopeData::decrement (0x5c82d00, payload-relative '
        'offsets: flag at +0x10 gated on its boolean '
        'argument, counter at +0x08, thread handle at '
        '+0x00, identical unpark tail); its only caller '
        'in the binary is the panic stub\u2019s overflow '
        'rollback, through slot 0x64ec708 with the flag '
        'argument clear -- the payload drops inline the '
        'ledger rather than calling it.'),
    'producers': (
        'No spawn call site in this binary passes a live '
        'scope.  The 14 spawn bodies carrying the '
        'increment idiom have 16 direct call sites between '
        'them; at every site the last r9 write before the '
        'call is `xor %r9d,%r9d`, and no indirect reference '
        '(slot call, lea, relocated data pointer) names '
        'any of the 14.  The three packet families\u2019 '
        'callers are unscoped spawns: the vendored '
        'threadpool crate (caller_x4), tokio\u2019s '
        'blocking pool (caller_x5), and a std-functions / '
        'lazy_mutex spawn (caller_a).  Every packet cell '
        'of these families therefore carries a null '
        'context, and the ScopeData ledger in the payload '
        'drops never fires for them.'),
}

BOUNDARIES = {
    'live_scope_instantiation': (
        'Whether std::thread::scope itself is instantiated '
        'anywhere in the binary is not decided here: no '
        'producer passes a non-null scope to any of the 14 '
        'spawn bodies, and the scope-exit panic string "a '
        'scoped thread panicked" does not occur in the '
        'artifact, but a Scope::spawn instantiation that '
        'built its packet without going through these '
        'spawn bodies would evade the call-site census.  '
        'What is pinned is narrower and complete for the '
        'packet cells: the context slot\u2019s type, role '
        'and ledger, and that all 16 call sites of all 14 '
        'spawn monomorphisations pass null.'),
    'thread_handle_internals': (
        'The decomposition of the main-thread handle\u2019s '
        'own allocation beyond the parker state word at '
        'handle +0x28 is not pinned: its drop glue '
        '(0x5c98b40) frees a (pointer, length) buffer at '
        'handle +0x18/+0x20 before the weak-count release, '
        'consistent with a name buffer, but no claim about '
        'its remaining fields is made.'),
    'other_payload_drops': (
        'The three further payload-drop bodies carrying '
        'the same ledger template (0x2deb7e0, 0x565bfc0, '
        '0x565c0c0) belong to other result types; their '
        'spawn/caller families were not traced here.  '
        'Their context slots are the same ScopeData '
        'pointer by template identity (flag store, counter '
        'decrement, thread-handle load, parker xchg at '
        'the same relative sites).'),
    'source_names': (
        'The field names num_running_threads / '
        'a_thread_panicked / main_thread are the '
        'source-level names of library/std/src/thread/'
        'scoped.rs for exactly this layout and ledger; '
        'the binary itself names only the file (the '
        'scoped.rs Location record) and the mechanism '
        '(the increment panic message).  Roles, offsets '
        'and the release chain are pinned from code, not '
        'from the names.'),
}

LIMITS = (
    'Static analysis only; no captured code was executed. '
    'Body boundaries are FDE extents cross-checked by '
    'SHA-256.  The call-site audit reads each caller '
    'body\u2019s objdump text: for every one of the 16 '
    'sites it requires the last r9-writing instruction '
    'before the call to be `xor %r9d,%r9d` and no jump '
    'target inside the caller to land between that xor '
    'and the call.  The spawn-side half of the argument '
    '(entry r9 saved, then copied into the cell image at '
    '+0x10) is byte-pinned on the three packet families\u2019 '
    'spawn bodies; the other eleven monomorphisations '
    'share the prologue template and the increment/panic '
    'idiom.')


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
    secs = sections(data)
    dyn = next(s for s in secs if s['name'] == '.rela.dyn')
    out = {}
    for i in range(dyn['size'] // 24):
        off, info, add = struct.unpack_from(
            '<QQq', data, dyn['offset'] + i * 24)
        out.setdefault(off, []).append((info & 0xffffffff,
                                         info >> 32, add))
    return out


def relative_map(data):
    return {off: add for off, rows in rela_entries(data).items()
            for typ, sym, add in rows if typ == 8}


def dynsym_name(data, index):
    secs = sections(data)
    sym = next(s for s in secs if s['name'] == '.dynsym')
    strs = next(s for s in secs if s['name'] == '.dynstr')
    name_off = struct.unpack_from(
        '<I', data, sym['offset'] + index * 24)[0]
    begin = strs['offset'] + name_off
    end = data.index(b'\0', begin)
    return data[begin:end].decode()


def slots(data):
    rela = rela_entries(data)
    records = {}
    for name, slot in SLOTS.items():
        rows = rela.get(slot)
        check(rows, f'slot {name} {slot:#x} has no relocation')
        typ, sym, add = rows[0]
        record = {'slot': hex(slot), 'type': typ,
                  'target': hex(add) if typ == 8 else None}
        if name in SLOT_TARGETS:
            check(typ == 8 and add == SLOT_TARGETS[name],
                  f'slot {name} target mismatch')
        if name == 'futex_syscall':
            check(typ == 6, 'futex_syscall slot is not GLOB_DAT')
            record['symbol'] = dynsym_name(data, sym)
            check(record['symbol'] == 'syscall',
                  'futex_syscall slot does not name syscall')
        records[name] = record
    return records


def relocated_u64(data, rel, va):
    if va in rel:
        return rel[va]
    _, raw = read(va, data, 8)
    return struct.unpack('<Q', raw)[0]


def location_at(data, rel, va):
    """Decode a core::panic::Location record at va, or None."""
    try:
        fp = relocated_u64(data, rel, va)
        _, raw = read(va, data, 24)
        length, line, col = struct.unpack_from('<QII', raw, 8)
        if fp is None or not (0 < length < 400):
            return None
        _, sraw = read(fp, data, length)
        text = sraw.decode()
    except Exception:
        return None
    if text.endswith('.rs') and all(32 <= ord(c) < 127
                                    for c in text):
        return {'record': hex(va), 'file': text,
                'line': line, 'col': col}
    return None


def scoped_location_census(data):
    rel = relative_map(data)
    secs = sections(data)
    sec = next(s for s in secs if s['name'] == '.data.rel.ro')
    found = []
    va = sec['address']
    while va < sec['address'] + sec['size'] - 24:
        loc = location_at(data, rel, va)
        if loc and loc['file'].endswith('thread/scoped.rs'):
            found.append(loc)
        va += 8
    check(len(found) == 1,
          f'scoped.rs location census: {len(found)} records')
    loc = found[0]
    check(loc['record'] == hex(SCOPED_LOCATION_RECORD),
          'scoped.rs location record moved')
    check(loc['line'] == 60 and loc['col'] == 9,
          'scoped.rs location is not 60:9')
    return {'records': found, 'count': 1}


def panic_message(data):
    _, raw = read(PANIC_MESSAGE_VA, data, PANIC_MESSAGE_LEN)
    text = raw.decode()
    check(text == PANIC_MESSAGE, 'panic message mismatch')
    # The stub must lea exactly this message and the scoped
    # Location record.
    start, end, _ = OWNERS['scope_panic_stub']
    _, body = read(start, data, end - start)
    targets = []
    for i in range(len(body) - 7):
        if (body[i] in (0x48, 0x4c) and body[i + 1] == 0x8d
                and (body[i + 2] & 0xc7) == 0x05):
            disp = struct.unpack_from('<i', body, i + 3)[0]
            targets.append(start + i + 7 + disp)
    check(PANIC_MESSAGE_VA in targets,
          'stub does not reference the panic message')
    check(SCOPED_LOCATION_RECORD in targets,
          'stub does not reference the scoped location')
    return {'va': hex(PANIC_MESSAGE_VA),
            'len': PANIC_MESSAGE_LEN, 'text': text,
            'stub_lea_targets': [hex(t) for t in targets]}


def text_section(data):
    sec = next(s for s in sections(data) if s['name'] == '.text')
    _, raw = read(sec['address'], data, sec['size'])
    return sec['address'], raw


def fde_map(data):
    _, fdes, _ = fde_extents(data)
    starts = sorted(f['start'] for f in fdes)
    by_start = {f['start']: f for f in fdes}

    def owner(va):
        import bisect
        i = bisect.bisect_right(starts, va) - 1
        if i >= 0:
            f = by_start[starts[i]]
            if f['start'] <= va < f['end']:
                return f
        return None

    return by_start, owner


def spawn_census(data):
    base, text = text_section(data)
    by_start, owner = fde_map(data)
    hits = {}
    i = 0
    while True:
        j = text.find(INC_PATTERN, i)
        if j < 0:
            break
        va = base + j
        f = owner(va)
        check(f is not None, f'inc idiom outside any FDE at {va:#x}')
        hits.setdefault(f['start'], []).append(va)
        i = j + 1
    check(sorted(hits) == EXPECTED_SPAWNS,
          'spawn inc census mismatch: '
          f'{[hex(x) for x in sorted(hits)]}')
    records = []
    for start in EXPECTED_SPAWNS:
        f = by_start[start]
        _, body = read(start, data, f['end'] - start)
        stub_calls = []
        for k in range(len(body) - 5):
            if body[k] == 0xe8:
                rel32 = struct.unpack_from('<i', body, k + 1)[0]
                if start + k + 5 + rel32 == STUB:
                    stub_calls.append(start + k)
        check(len(hits[start]) == 1,
              f'spawn {start:#x} inc count {len(hits[start])}')
        check(len(stub_calls) == 1,
              f'spawn {start:#x} stub calls {len(stub_calls)}')
        records.append({
            'start': hex(start), 'end': hex(f['end']),
            'bytes': f['end'] - start, 'sha256': sha(body),
            'inc_site': hex(hits[start][0]),
            'stub_call_site': hex(stub_calls[0]),
        })
    return records


def payload_drop_census(data):
    base, text = text_section(data)
    _, owner = fde_map(data)
    grouped = {}
    for name, pattern in PD_PATTERNS.items():
        sites = {}
        i = 0
        while True:
            j = text.find(pattern, i)
            if j < 0:
                break
            va = base + j
            f = owner(va)
            if f is not None:
                sites.setdefault(f['start'], []).append(va)
            i = j + 1
        grouped[name] = sites
    starts = set(grouped['flag_store'])
    for name in PD_PATTERNS:
        starts &= set(grouped[name])
    check(sorted(starts) == EXPECTED_PD,
          'payload drop census mismatch: '
          f'{[hex(x) for x in sorted(starts)]}')
    records = []
    for start in EXPECTED_PD:
        row = {'start': hex(start)}
        for name in PD_PATTERNS:
            sites = grouped[name][start]
            check(len(sites) == 1,
                  f'pd {start:#x} {name} count {len(sites)}')
            row[name] = hex(sites[0])
        records.append(row)
    return records


_LINE = re.compile(r'^\s+([0-9a-f]+):\t[0-9a-f ]+\t(.*)$')
_R9_WRITE = re.compile(
    r'(,%r9[bwd]?$)|(^pop\s+%r9)|(^xchg\s+%r9)')
_JUMP = re.compile(r'^j[a-z]+\s+([0-9a-f]+)\s')


def objdump_range(data, start, end):
    text = subprocess.run(
        ['objdump', '-d', '--start-address', hex(start),
         '--stop-address', hex(end), str(TARGET)],
        check=True, capture_output=True, text=True).stdout
    return text.replace(str(TARGET), SNAPSHOT, 1)


def audit_call_site(data, owner_start, owner_end, site, spawn):
    text = objdump_range(data, owner_start, owner_end)
    insns = []
    jumps = []
    for line in text.splitlines():
        m = _LINE.match(line)
        if not m:
            continue
        va, ins = int(m.group(1), 16), ' '.join(m.group(2).split())
        insns.append((va, ins))
        jm = _JUMP.match(ins)
        if jm:
            jumps.append(int(jm.group(1), 16))
    calls = [va for va, ins in insns
             if va == site and ins.startswith('call')]
    check(len(calls) == 1, f'call site {site:#x} not found')
    prior = [(va, ins) for va, ins in insns
             if va < site and _R9_WRITE.search(ins)]
    check(prior, f'no r9 write before call at {site:#x}')
    xor_va, xor_ins = prior[-1]
    check(xor_ins == 'xor %r9d,%r9d',
          f'last r9 write before {site:#x} is {xor_ins!r}')
    for target in jumps:
        check(not (xor_va + 3 <= target <= site),
              f'jump into audited window at {site:#x}: '
              f'target {target:#x}')
    return {'spawn': hex(spawn), 'site': hex(site),
            'owner_start': hex(owner_start),
            'owner_end': hex(owner_end),
            'xor_r9_site': hex(xor_va), 'r9_null': True}


def call_site_census(data):
    base, text = text_section(data)
    by_start, owner = fde_map(data)
    spawn_set = set(EXPECTED_SPAWNS)
    sites = []
    for i in range(len(text) - 5):
        if text[i] in (0xe8, 0xe9):
            rel32 = struct.unpack_from('<i', text, i + 1)[0]
            dst = base + i + 5 + rel32
            if dst in spawn_set:
                sites.append((base + i, dst,
                              'call' if text[i] == 0xe8 else 'jmp'))
    check(len(sites) == 16,
          f'spawn call site census: {len(sites)} sites')
    records = []
    for site, dst, kind in sorted(sites):
        check(kind == 'call', f'spawn reached by jmp at {site:#x}')
        f = owner(site)
        check(f is not None, f'call site {site:#x} outside FDE')
        records.append(audit_call_site(data, f['start'], f['end'],
                                       site, dst))
    return records


def indirect_reference_census(data):
    base, text = text_section(data)
    rel = relative_map(data)
    spawn_set = set(EXPECTED_SPAWNS)
    slot_calls = 0
    lea_refs = 0
    for i in range(len(text) - 7):
        if text[i] == 0xff and text[i + 1] == 0x15:
            disp = struct.unpack_from('<i', text, i + 2)[0]
            slot = base + i + 6 + disp
            if rel.get(slot) in spawn_set:
                slot_calls += 1
        if (text[i] in (0x48, 0x4c) and text[i + 1] == 0x8d
                and (text[i + 2] & 0xc7) == 0x05):
            disp = struct.unpack_from('<i', text, i + 3)[0]
            if base + i + 7 + disp in spawn_set:
                lea_refs += 1
    data_ptrs = 0
    for sec in sections(data):
        if sec['name'] not in ('.data.rel.ro', '.rodata', '.data'):
            continue
        va = sec['address']
        while va < sec['address'] + sec['size'] - 8:
            if relocated_u64(data, rel, va) in spawn_set:
                data_ptrs += 1
            va += 8
    check(slot_calls == 0 and lea_refs == 0 and data_ptrs == 0,
          'indirect reference to a spawn body found')
    return {'slot_calls': slot_calls, 'lea_refs': lea_refs,
            'data_ptrs': data_ptrs}


def decrement_census(data):
    """The standalone ScopeData decrement body 0x5c82d00 is
    reached only through its GOT slot 0x64ec708, from exactly
    one site: the panic stub's overflow rollback (argument
    flag = 0).  The packet drops carry their own inlined
    copy of the same ledger instead of calling it."""
    base, text = text_section(data)
    direct = []
    slot_sites = []
    for i in range(len(text) - 6):
        if text[i] == 0xe8:
            rel32 = struct.unpack_from('<i', text, i + 1)[0]
            if base + i + 5 + rel32 == OWNERS['scope_decrement'][0]:
                direct.append(base + i)
        if text[i] == 0xff and text[i + 1] == 0x15:
            disp = struct.unpack_from('<i', text, i + 2)[0]
            if base + i + 6 + disp == SLOTS['scope_decrement']:
                slot_sites.append(base + i)
    check(direct == [], f'direct decrement calls: {direct}')
    check(slot_sites == [0x5c82d46],
          f'decrement slot call sites: {slot_sites}')
    return {'direct_calls': 0,
            'slot': hex(SLOTS['scope_decrement']),
            'slot_call_sites': [hex(s) for s in slot_sites],
            'sole_caller': 'scope_panic_stub'}


def caller_locations(data):
    rel = relative_map(data)
    records = {}
    for role in ('caller_a', 'caller_x4', 'caller_x5'):
        start, end, _ = OWNERS[role]
        _, body = read(start, data, end - start)
        found = {}
        for i in range(len(body) - 7):
            if (body[i] in (0x48, 0x4c) and body[i + 1] == 0x8d
                    and (body[i + 2] & 0xc7) == 0x05):
                disp = struct.unpack_from('<i', body, i + 3)[0]
                loc = location_at(data, rel, start + i + 7 + disp)
                if loc:
                    found[loc['record']] = loc
        records[role] = [found[k] for k in sorted(found)]
    return records


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
        'slots': slots(data),
        'scoped_location_census': scoped_location_census(data),
        'panic_message': panic_message(data),
        'spawn_census': spawn_census(data),
        'call_site_census': call_site_census(data),
        'indirect_reference_census':
            indirect_reference_census(data),
        'payload_drop_census': payload_drop_census(data),
        'decrement_census': decrement_census(data),
        'caller_locations': caller_locations(data),
        'boundaries': BOUNDARIES,
        'limits': LIMITS,
    }


def manifest_lines():
    names = sorted(p.name for p in OUT.iterdir()
                   if p.is_file() and p.name != 'MANIFEST.sha256')
    lines = []
    for name in names:
        digest = sha((OUT / name).read_bytes())
        lines.append(f'{digest}  {name}\n')
    return lines


def generate(data):
    OUT.mkdir(parents=True, exist_ok=True)
    records = analyze(data)
    (OUT / 'records.json').write_text(
        json.dumps(records, indent=1, sort_keys=True) + '\n')
    (OUT / 'frames.txt').write_text(''.join(frame_lines(data)))
    for role in EXPORTED:
        (OUT / f'{role}.objdump.txt').write_text(exports(data, role))
    check((OUT / 'README.md').is_file(),
          'README.md must exist before MANIFEST generation')
    (OUT / 'MANIFEST.sha256').write_text(''.join(manifest_lines()))


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
    check((OUT / 'MANIFEST.sha256').read_text() ==
          ''.join(manifest_lines()), 'MANIFEST.sha256 is stale')
    print(json.dumps({'packet': WORK_ITEM, 'matches': True},
                     sort_keys=True))


if __name__ == '__main__':
    main()
