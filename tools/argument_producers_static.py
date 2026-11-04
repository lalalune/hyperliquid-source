#!/usr/bin/env python3
"""Pin the node 115 argument-producer window for RE-006 (static only).

PR #2584 traced the 13 direct E8 call sites of the four
insert-or-assign drivers and classified how the 0xb0-byte element
argument is produced at each: one per-field writer (FDE 0x36a1330),
six wholesale copies and six incoming-argument forwards.  It left
four producer questions open.  This extractor answers them:

(i) Who produces the inputs of the six (c)-kind boundary FDEs?
    The three join-consumer clones (jc1 0x2a89500, jc2 0x55a07e0,
    jc3 0x55a12e0) have exactly two direct callers each, all small
    wrapper FDEs.  In the A wrappers the join consumer's
    5th-argument array is the 0x118-byte output record of a sibling
    lookup helper (0x27622f0 for jc1, 0x5491190 for jc2/jc3), staged
    on the wrapper's stack at [rsp+0x80], its tail round-tripped
    through a second staging record.  In the B wrappers the array
    is a verbatim 0x118-byte memcpy of the wrapper's own incoming
    5th argument into [rsp+0xb0].  The three adapters of #2584 have
    no direct callers at all: each is reached only through one GOT
    slot (s1 0x64e6be0, s2 0x64e6488, s3 0x64e7e60).  At s1's three
    slot-call sites, inside three giant FDEs, the element record is
    assembled in the caller itself (tag and byte stores plus a
    0xff-byte tail memcpy).  At s2's three sites the element is a
    0xc8-byte record re-staged from the output of helper 0x369b770
    (reached through slot 0x64e6480).  At s3's four sites the
    element is a verbatim 0xf8-byte copy of the output record of
    the sibling helpers 0x2c62820 / 0x55e16d0.

(ii) The records r12 points to in big1 (0x2c64870) and big2
    (0x55e3770) are the FDEs' own staging buffers ([rsp+0x140] /
    [rsp+0x150]): on both driver phases of each FDE the sibling
    0xf8-helper (0x2c62820 for big1, 0x55e16d0 for big2) is called
    with rdi = r12 and writes the record in place, the FDE checks
    the record tag at the staging base, and only then memcpys
    0xf8 bytes from r12 into the element buffer.

(iii) Helper 0x2762570 does not assemble its result record's
    serialised tail: it copies the tail (bytes [9, 0x118), 0x10f
    bytes) verbatim from the output record of its sub-lookup
    0x2bb7270, prepends that record's tag and byte, gates the copy
    on the shared predicate bodies 0x369a210 / 0x3bf4fa0, and
    memcpys the whole 0x118-byte record to its result pointer.
    The sub-lookup in turn assembles its output from an internal
    staging record whose tail is copied from a second internal
    record, whose tail is copied from a third.

(iv) The [rsp+0x410] record in big3 (0x55defd0) is assembled
    inside big3 itself, in the same shape as the sub-lookups:
    tag and byte stored directly, the 0xff-byte tail memcpy'd
    from an inner stack record, and a closing qword/byte pair at
    +0x108/+0x110.

Sub-question verdict: the {tag, byte, serialised tail} idiom is
one record family (sizes 0xc8, 0xf8, 0x118 seen here), but it has
no single decode-site producer.  It is produced by a clone family
of distinct lookup helpers (0x27622f0, 0x2762570, 0x5491190), by
two distinct sub-lookups (0x2bb7270, 0x2bb52a0), by per-field
construction in helper 0x369b770, and by inlined copies of the
same assembly inside big3 and the three s1 caller giants; the
only shared code is the memcpy slot and the two predicate bodies
the 0x118 helpers all call.
"""
import hashlib
import json
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from artifacts import ROOT
from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import decode_export as _foundation_decode

PACKET_ID = 'RE-006-node115-argument-producers'
ARTIFACT_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ARTIFACT_SIZE = 105896032

MEMCPY_SLOT = 0x64DF508
S1_SLOT = 0x64E6BE0
S2_SLOT = 0x64E6488
S3_SLOT = 0x64E7E60
HELPER_S2_SLOT = 0x64E6480
PRED_A_SLOT = 0x64E6498
PRED_B_SLOT = 0x64E64A0

# Anchor bodies: digest + FDE extent only (pinned by earlier
# packets; not decoded here).
ANCHORS = {
    'jc1': {'range': (0x2a89500, 0x2a8a000), 'sha256': 'd33c9906f43bb0c54ab7cf6a21f3b8cd465f135cb9716ea7e4991eefafbb2aa0',
        'role': 'join-consumer clone 1, pinned by PR #2558/#2584 (boundary anchor)'},
    'jc2': {'range': (0x55a07e0, 0x55a12e0), 'sha256': '41e588d7db79f90108f6981acc95af94e2534e68a0aa570c5f0270ece139ec5d',
        'role': 'join-consumer clone 2, pinned by PR #2558/#2584 (boundary anchor)'},
    'jc3': {'range': (0x55a12e0, 0x55a1de0), 'sha256': '1c2af67af44f5fe0dcb0eb706c5b9c2db8d4793c5ac01475387cfe160a6cf0ba',
        'role': 'join-consumer clone 3, pinned by PR #2558/#2584 (boundary anchor)'},
    's1': {'range': (0x369a3d0, 0x369a47f), 'sha256': '768501712fcc2479fdf53b139682ea2b3469821304c8462889121e15aa51a6b0',
        'role': 'caller_b1 adapter pinned by PR #2584: forwards its 3rd argument as the element'},
    's2': {'range': (0x369b650, 0x369b76c), 'sha256': '8c20fb08970a99a8a734d575806160e0fbf3799dd4614a0d757ac8c5b81ac7f4',
        'role': 'caller_b1 adapter pinned by PR #2584: element = head of its 4th-argument struct'},
    's3': {'range': (0x3f10ac0, 0x3f10c10), 'sha256': 'd7c86cd56d991a055f838ca5f34dff560da20e906b0841985493f08f3fadca66',
        'role': 'caller_b1 adapter pinned by PR #2584: forwards its 1st argument as the element'},
    'ca': {'range': (0x2c62590, 0x2c6281a), 'sha256': 'fc17db535dc2531e7a0f6148da56ad4eede1fe361159a35e29358d2ed6390bad',
        'role': 'caller_a boundary FDE pinned by PR #2584: the one direct caller of helper_ca'},
}

BODIES = {
    'jc1wa': {'range': (0x2a890d0, 0x2a892ea), 'sha256': '595213e6922a37d88993b974bf44a0963dbfacc24f3425ffc22e92a3ce9e94af',
        'role': 'jc1 wrapper A: passes the output record of helper_jc1 as the 5th-argument array'},
    'jc1wb': {'range': (0x2a892f0, 0x2a894f3), 'sha256': '4baf4e6d6cced4771553c5b0d1076588e41b3a4615c18ec2ca1b15e89942878b',
        'role': 'jc1 wrapper B: passes a 0x118-byte memcpy of its own 5th argument as the array'},
    'jc2wa': {'range': (0x55a01a0, 0x55a03ba), 'sha256': 'ecb821c3f2b409280ce5b8eed9e5be48fc0634f154d9001a6ff6a40dd31c49fb',
        'role': 'jc2 wrapper A: passes the output record of helper_jc23 as the 5th-argument array'},
    'jc2wb': {'range': (0x55a03c0, 0x55a05c3), 'sha256': 'ed441b6a9a65d6c87b64a934b2cb20cda64baa62a1ecf2460d2cca2d438057d2',
        'role': 'jc2 wrapper B: passes a 0x118-byte memcpy of its own 5th argument as the array'},
    'jc3wa': {'range': (0x559ff80, 0x55a019a), 'sha256': 'e935cc87d1d70421f3c8103e35e44ab062475e92aa6e50f856e538c92220bbc6',
        'role': 'jc3 wrapper A: passes the output record of helper_jc23 as the 5th-argument array'},
    'jc3wb': {'range': (0x55a05d0, 0x55a07d3), 'sha256': 'cd81189e54a7827889842baf9abc422764e4b3d154a99ed85399ac637f47baad',
        'role': 'jc3 wrapper B: passes a 0x118-byte memcpy of its own 5th argument as the array'},
    'helper_jc1': {'range': (0x27622f0, 0x2762566), 'sha256': '541bda52d9b9f4847527b05b035b59183c14d8932f2c565eda40fdde48c5c031',
        'role': 'lookup helper called by jc1wa: builds a 0x118-byte record from sublookup_jc1'},
    'helper_ca': {'range': (0x2762570, 0x2762876), 'sha256': 'b4af5ad1c0b1454353bc30fbe30dce5968cc6dbe15366e79cab54ddd384abec1',
        'role': 'lookup helper pinned by PR #2584: builds a 0x118-byte record from sublookup_ca'},
    'helper_jc23': {'range': (0x5491190, 0x5492434), 'sha256': '91beb13ee0905b3db7ef6e6d9d41df49af7f06195fa9f147888c866925b4ae8a',
        'role': 'lookup helper called by jc2wa/jc3wa: builds a 0x118-byte record with an inlined decode phase (no sub-lookup call)'},
    'sublookup_ca': {'range': (0x2bb7270, 0x2bb9893), 'sha256': '6dbf7f8390953d24bdd5b7a225e83f3e1614fb79ee6b3f40d423f8728d44234b',
        'role': 'sub-lookup called only by helper_ca: assembles the 0x118-byte record the helper copies'},
    'sublookup_jc1': {'range': (0x2bb52a0, 0x2bb68d6), 'sha256': '879e56724ec4d83c7b7ef7699fa08a1f6b3a12ecd72f50972d828c02a5b2fe13',
        'role': 'sub-lookup called only by helper_jc1: clone sibling of sublookup_ca'},
    'helper_s2': {'range': (0x369b770, 0x369be69), 'sha256': '98077e29db5853267d79952ee15443bab8deea572e07e54354dd98ee04c931df',
        'role': 'helper behind slot 0x64e6480: builds its 0xc8-byte output record per-field through its result pointer'},
    'pred_a': {'range': (0x369a210, 0x369a3c2), 'sha256': '8c86bd680d63133344795a9dd60fbf793f2d90da6777a4d4b10182c430a4e0ea',
        'role': 'shared predicate body behind slot 0x64e6498, called by all three 0x118 helpers'},
    'pred_b': {'range': (0x3bf4fa0, 0x3bf511a), 'sha256': 'db2f4278269ff1c699adeeb03ed8be1d3611dcd37368d0737ea90d0d264b7960',
        'role': 'shared validation body behind slot 0x64e64a0, called by all three 0x118 helpers'},
    's2c_a': {'range': (0x2761c40, 0x2761cce), 'sha256': 'a045115ff5d64309d89684e801c81fd81af90d2b2a8498526d04184333c14089',
        'role': 's2 slot caller: re-stages the helper_s2 output record and calls s2 through its slot'},
    's2c_b': {'range': (0x5490540, 0x54905ce), 'sha256': 'f4c59f170d88aaf4e8d07dbdb58d45bfb27b0cc2c5abc378edf5bdba6fa31a11',
        'role': 's2 slot caller, clone of s2c_a'},
    's2c_c': {'range': (0x54905d0, 0x549065e), 'sha256': '49c26d9cb9052b8c2b1f88fe41e8f72917aab9a4660f14295b64fb41935d5ef3',
        'role': 's2 slot caller, clone of s2c_a'},
    's3c_a': {'range': (0x2c619b0, 0x2c61b23), 'sha256': '686377756e6bf5b6cc147ff71f3ba95e219316b08bb5d49ce383dce2105d7fe3',
        'role': 's3 slot caller: copies the helper_s3a output record twice and calls s3 through its slot'},
    's3c_b': {'range': (0x55debb0, 0x55ded23), 'sha256': 'd165200140989b760b390fbac09e366439b2fbfc13e6ac2816d7b01f30540b24',
        'role': 's3 slot caller, clone of s3c_a with helper_s3b'},
    'helper_s3a': {'range': (0x2c62820, 0x2c64862), 'sha256': '9176b5c3361b91321a3b0cd99c2e90bf4538c1d7b21a68d63f68d5082e33fe96',
        'role': 'sibling 0xf8-record helper: writes the records s3c_a copies and the records big1 memcpys from r12'},
    'helper_s3b': {'range': (0x55e16d0, 0x55e3762), 'sha256': '22651e5a99e6a1279013c659838c4b561df8dd2d2e6ad97b0f8ce31b6b783b30',
        'role': 'sibling 0xf8-record helper, clone counterpart of helper_s3a for s3c_b and big2'},
    'big1': {'range': (0x2c64870, 0x2c6597a), 'sha256': '329dab1fd2ec234b39ab7fd55495231baeb0bb6168dfb986e02cfc2b1431e936',
        'role': 'caller_b1 boundary FDE pinned by PR #2584 (two driver sites): r12 record produced by helper_s3a into the staging buffer'},
    'big2': {'range': (0x55e3770, 0x55e4ad0), 'sha256': '8bbad0402c82e8a7f4cff483782d653a7c4f7dec7254d13e8f2ddc6cbafca03d',
        'role': 'caller_b1 boundary FDE pinned by PR #2584 (two driver sites): r12 record produced by helper_s3b into the staging buffer'},
    'big3': {'range': (0x55defd0, 0x55e16ca), 'sha256': '33773d4f76f1b5f3cb9790d204e74484410ba56dedeb90451221ee829c785c64',
        'role': 'caller_c boundary FDE pinned by PR #2584: assembles its [rsp+0x410] record in-FDE'},
    'giant_s1a': {'range': (0x28cd7a0, 0x28d8ac4), 'sha256': '40df69913a9976f4cf044e6f9b686fac43d0f63ba54b984ff79524a3a1794a76',
        'role': 'giant FDE holding s1 slot site 0x28d7741: assembles the element record in-FDE at [rsp+0x20]'},
    'giant_s1b': {'range': (0x538cd30, 0x5397b4d), 'sha256': 'fe615521c3cebf329ae984293dd270e6aefd1a74dec4f2b7989b12a555ef833d',
        'role': 'giant FDE holding s1 slot site 0x53967de: clone of giant_s1a'},
    'giant_s1c': {'range': (0x5397b50, 0x53a296d), 'sha256': 'a69d025534ce5dca6536f52e51c69a0402842bfce4a0e0b148eb3d429d0282d0',
        'role': 'giant FDE holding s1 slot site 0x53a15fe: clone of giant_s1a'},
}

# FDEs exported in full in the packet (<= ~4 KB); the rest are
# pinned by digest + selected rows only.
EXPORTED = ('jc1wa', 'jc1wb', 'jc2wa', 'jc2wb', 'jc3wa', 'jc3wb',
            'helper_jc1', 'helper_ca', 'helper_s2', 'pred_a',
            'pred_b', 's2c_a', 's2c_b', 's2c_c', 's3c_a', 's3c_b')

# Binary-wide E8 caller census expectations:
# target -> sorted [(site, caller_fde_start)].
EXPECTED_E8_CALLERS = {
    'jc1': [(0x2a8921a, 0x2a890d0), (0x2a89434, 0x2a892f0)],
    'jc2': [(0x55a02ea, 0x55a01a0), (0x55a0504, 0x55a03c0)],
    'jc3': [(0x55a00ca, 0x559ff80), (0x55a0714, 0x55a05d0)],
    'helper_jc1': [(0x2a89175, 0x2a890d0)],
    'helper_ca': [(0x2c62653, 0x2c62590)],
    'helper_jc23': [(0x55a0025, 0x559ff80), (0x55a0245, 0x55a01a0)],
    'sublookup_ca': [(0x27626a6, 0x2762570)],
    'sublookup_jc1': [(0x27623ae, 0x27622f0)],
    'helper_s3a': [(0x2c61a1a, 0x2c619b0), (0x2c61acb, 0x2c619b0),
                   (0x2c65297, 0x2c64870), (0x2c65462, 0x2c64870)],
    'helper_s3b': [(0x55dec1a, 0x55debb0), (0x55deccb, 0x55debb0),
                   (0x55e4397, 0x55e3770), (0x55e4562, 0x55e3770)],
    's3c_a': [(0x2c64fcd, 0x2c64870), (0x2c655eb, 0x2c64870)],
    's3c_b': [(0x55e40cb, 0x55e3770), (0x55e46eb, 0x55e3770)],
}

# Binary-wide indirect (ff15) caller census expectations:
# slot name -> sorted [(site, caller_fde_start)].
EXPECTED_SLOT_CALLERS = {
    's1': [(0x28d7741, 0x28cd7a0), (0x53967de, 0x538cd30),
           (0x53a15fe, 0x5397b50)],
    's2': [(0x2761cb2, 0x2761c40), (0x54905b2, 0x5490540),
           (0x5490642, 0x54905d0)],
    's3': [(0x2c61a55, 0x2c619b0), (0x2c61afb, 0x2c619b0),
           (0x55dec55, 0x55debb0), (0x55decfb, 0x55debb0)],
    'helper_s2': [(0x2761c62, 0x2761c40), (0x5490562, 0x5490540),
                  (0x54905f2, 0x54905d0)],
}
SLOT_OF = {'s1': S1_SLOT, 's2': S2_SLOT, 's3': S3_SLOT,
           'helper_s2': HELPER_S2_SLOT}
SLOT_TARGET = {'s1': 's1', 's2': 's2', 's3': 's3',
               'helper_s2': 'helper_s2'}

# A wrappers: name -> (helper body, helper call site, jc body, jc site).
WRAPPER_A = {
    'jc1wa': ('helper_jc1', 0x2a89175, 'jc1', 0x2a8921a),
    'jc2wa': ('helper_jc23', 0x55a0245, 'jc2', 0x55a02ea),
    'jc3wa': ('helper_jc23', 0x55a0025, 'jc3', 0x55a00ca),
}
# B wrappers: name -> (jc body, jc site, memcpy site).
WRAPPER_B = {
    'jc1wb': ('jc1', 0x2a89434, 0x2a89343),
    'jc2wb': ('jc2', 0x55a0504, 0x55a0413),
    'jc3wb': ('jc3', 0x55a0714, 0x55a0623),
}
# s1 giants: name -> (slot site, tail source rsp disp).
GIANT_S1 = {
    'giant_s1a': (0x28d7741, 0xd49),
    'giant_s1b': (0x53967de, 0xd29),
    'giant_s1c': (0x53a15fe, 0xd29),
}
# s2 callers: name -> (helper slot site, memcpy site, s2 slot site).
S2_CALLERS = {
    's2c_a': (0x2761c62, 0x2761c8a, 0x2761cb2),
    's2c_b': (0x5490562, 0x549058a, 0x54905b2),
    's2c_c': (0x54905f2, 0x549061a, 0x5490642),
}
# s3 callers: name -> (helper body, [helper sites], [memcpy tuples],
# [s3 slot sites], [rdi bindings at the s3 sites]).
S3_CALLERS = {
    's3c_a': ('helper_s3a', [0x2c61a1a, 0x2c61acb],
              [(0x2c61a3c, 0x148, 0x50, 0xf8),
               (0x2c61aec, 0x240, 0x50, 0xf8)],
              [0x2c61a55, 0x2c61afb], [0x148, 0x240]),
    's3c_b': ('helper_s3b', [0x55dec1a, 0x55deccb],
              [(0x55dec3c, 0x148, 0x50, 0xf8),
               (0x55decec, 0x240, 0x50, 0xf8)],
              [0x55dec55, 0x55decfb], [0x148, 0x240]),
}

PINNED_ROWS = {
    'helper_ca': {
        41297264: ('55', 'push   %rbp'),
        41297265: ('4157', 'push   %r15'),
        41297267: ('4156', 'push   %r14'),
        41297269: ('4155', 'push   %r13'),
        41297271: ('4154', 'push   %r12'),
        41297273: ('53', 'push   %rbx'),
        41297274: ('4881ecc8020000', 'sub    $0x2c8,%rsp'),
        41297281: ('4889f0', 'mov    %rsi,%rax'),
        41297284: ('4889fb', 'mov    %rdi,%rbx'),
        41297287: ('4c8b7a30', 'mov    0x30(%rdx),%r15'),
        41297291: ('0f100a', 'movups (%rdx),%xmm1'),
        41297294: ('0f105210', 'movups 0x10(%rdx),%xmm2'),
        41297298: ('4c8b4210', 'mov    0x10(%rdx),%r8'),
        41297302: ('0fb66a60', 'movzbl 0x60(%rdx),%ebp'),
        41297306: ('440fb66a61', 'movzbl 0x61(%rdx),%r13d'),
        41297311: ('4c8b5220', 'mov    0x20(%rdx),%r10'),
        41297315: ('4c8b7228', 'mov    0x28(%rdx),%r14'),
        41297319: ('488b7238', 'mov    0x38(%rdx),%rsi'),
        41297323: ('0fb6884c010000', 'movzbl 0x14c(%rax),%ecx'),
        41297330: ('0fb6b84d010000', 'movzbl 0x14d(%rax),%edi'),
        41297337: ('4c8d0db831e9fd', 'lea    -0x216ce48(%rip),%r9'),
        41297344: ('4f630481', 'movslq (%r9,%r8,4),%r8'),
        41297348: ('4d01c8', 'add    %r9,%r8'),
        41297351: ('41ffe0', 'jmp    *%r8'),
        41297354: ('f6c101', 'test   $0x1,%cl'),
        41297357: ('751a', 'jne    0x27625e9'),
        41297359: ('c643080a', 'movb   $0xa,0x8(%rbx)'),
        41297363: ('48c70303000000', 'movq   $0x3,(%rbx)'),
        41297370: ('e97d010000', 'jmp    0x276275c'),
        41297375: ('f6d1', 'not    %cl'),
        41297377: ('4008f9', 'or     %dil,%cl'),
        41297380: ('f6c101', 'test   $0x1,%cl'),
        41297383: ('75e6', 'jne    0x27625cf'),
        41297385: ('4c8d624c', 'lea    0x4c(%rdx),%r12'),
        41297389: ('4883c240', 'add    $0x40,%rdx'),
        41297393: ('4885f6', 'test   %rsi,%rsi'),
        41297396: ('7556', 'jne    0x276264c'),
        41297398: ('418b4c2410', 'mov    0x10(%r12),%ecx'),
        41297403: ('894c2420', 'mov    %ecx,0x20(%rsp)'),
        41297407: ('410f100424', 'movups (%r12),%xmm0'),
        41297412: ('0f29442410', 'movaps %xmm0,0x10(%rsp)'),
        41297417: ('488d742410', 'lea    0x10(%rsp),%rsi'),
        41297422: ('4889c7', 'mov    %rax,%rdi'),
        41297425: ('4c893c24', 'mov    %r15,(%rsp)'),
        41297429: ('4889542408', 'mov    %rdx,0x8(%rsp)'),
        41297434: ('4d89d7', 'mov    %r10,%r15'),
        41297437: ('0f298c24800000', 'movaps %xmm1,0x80(%rsp)'),
        41297445: ('0f29542470', 'movaps %xmm2,0x70(%rsp)'),
        41297450: ('ff15683ed803', 'call   *0x3d83e68(%rip)'),
        41297456: ('0f28542470', 'movaps 0x70(%rsp),%xmm2'),
        41297461: ('0f288c24800000', 'movaps 0x80(%rsp),%xmm1'),
        41297469: ('4d89fa', 'mov    %r15,%r10'),
        41297472: ('488b542408', 'mov    0x8(%rsp),%rdx'),
        41297477: ('4c8b3c24', 'mov    (%rsp),%r15'),
        41297481: ('4889c6', 'mov    %rax,%rsi'),
        41297484: ('4c891424', 'mov    %r10,(%rsp)'),
        41297488: ('498d4210', 'lea    0x10(%r10),%rax'),
        41297492: ('8b4a08', 'mov    0x8(%rdx),%ecx'),
        41297495: ('894c2450', 'mov    %ecx,0x50(%rsp)'),
        41297499: ('488b0a', 'mov    (%rdx),%rcx'),
        41297502: ('48894c2448', 'mov    %rcx,0x48(%rsp)'),
        41297507: ('410f100424', 'movups (%r12),%xmm0'),
        41297512: ('0f11442454', 'movups %xmm0,0x54(%rsp)'),
        41297517: ('418b4c2410', 'mov    0x10(%r12),%ecx'),
        41297522: ('894c2464', 'mov    %ecx,0x64(%rsp)'),
        41297526: ('4c897c2440', 'mov    %r15,0x40(%rsp)'),
        41297531: ('0f29542420', 'movaps %xmm2,0x20(%rsp)'),
        41297536: ('40886c2468', 'mov    %bpl,0x68(%rsp)'),
        41297541: ('44886c2469', 'mov    %r13b,0x69(%rsp)'),
        41297546: ('4c89742430', 'mov    %r14,0x30(%rsp)'),
        41297551: ('0f294c2410', 'movaps %xmm1,0x10(%rsp)'),
        41297556: ('4889442438', 'mov    %rax,0x38(%rsp)'),
        41297561: ('488dbc24900000', 'lea    0x90(%rsp),%rdi'),
        41297569: ('488d542410', 'lea    0x10(%rsp),%rdx'),
        41297574: ('e8c54b4500', 'call   0x2bb7270'),
        41297579: ('4c8bb424900000', 'mov    0x90(%rsp),%r14'),
        41297587: ('0fb6ac24980000', 'movzbl 0x98(%rsp),%ebp'),
        41297595: ('4983fe03', 'cmp    $0x3,%r14'),
        41297599: ('7510', 'jne    0x27626d1'),
        41297601: ('40886b08', 'mov    %bpl,0x8(%rbx)'),
        41297605: ('48c70303000000', 'movq   $0x3,(%rbx)'),
        41297612: ('e98b000000', 'jmp    0x276275c'),
        41297617: ('488db424990000', 'lea    0x99(%rsp),%rsi'),
        41297625: ('488dbc24b90100', 'lea    0x1b9(%rsp),%rdi'),
        41297633: ('ba0f010000', 'mov    $0x10f,%edx'),
        41297638: ('ff151cced703', 'call   *0x3d7ce1c(%rip)'),
        41297644: ('4c89b424b00100', 'mov    %r14,0x1b0(%rsp)'),
        41297652: ('4088ac24b80100', 'mov    %bpl,0x1b8(%rsp)'),
        41297660: ('4983fe02', 'cmp    $0x2,%r14'),
        41297664: ('7444', 'je     0x2762746'),
        41297666: ('80bc24c0020000', 'cmpb   $0x0,0x2c0(%rsp)'),
        41297674: ('743a', 'je     0x2762746'),
        41297676: ('488b8c24b80200', 'mov    0x2b8(%rsp),%rcx'),
        41297684: ('418b442410', 'mov    0x10(%r12),%eax'),
        41297689: ('898424a0000000', 'mov    %eax,0xa0(%rsp)'),
        41297696: ('410f100424', 'movups (%r12),%xmm0'),
        41297701: ('0f298424900000', 'movaps %xmm0,0x90(%rsp)'),
        41297709: ('488db424900000', 'lea    0x90(%rsp),%rsi'),
        41297717: ('488b3c24', 'mov    (%rsp),%rdi'),
        41297721: ('4c89fa', 'mov    %r15,%rdx'),
        41297724: ('ff155e3dd803', 'call   *0x3d83d5e(%rip)'),
        41297730: ('84c0', 'test   %al,%al'),
        41297732: ('742b', 'je     0x2762771'),
        41297734: ('488db424b00100', 'lea    0x1b0(%rsp),%rsi'),
        41297742: ('ba18010000', 'mov    $0x118,%edx'),
        41297747: ('4889df', 'mov    %rbx,%rdi'),
        41297750: ('ff15accdd703', 'call   *0x3d7cdac(%rip)'),
        41297756: ('4889d8', 'mov    %rbx,%rax'),
        41297759: ('4881c4c8020000', 'add    $0x2c8,%rsp'),
        41297766: ('5b', 'pop    %rbx'),
        41297767: ('415c', 'pop    %r12'),
        41297769: ('415d', 'pop    %r13'),
        41297771: ('415e', 'pop    %r14'),
        41297773: ('415f', 'pop    %r15'),
        41297775: ('5d', 'pop    %rbp'),
        41297776: ('c3', 'ret'),
        41297777: ('c643080c', 'movb   $0xc,0x8(%rbx)'),
        41297781: ('48c70303000000', 'movq   $0x3,(%rbx)'),
        41297788: ('488b8424600200', 'mov    0x260(%rsp),%rax'),
        41297796: ('4889c1', 'mov    %rax,%rcx'),
        41297799: ('48f7d9', 'neg    %rcx'),
        41297802: ('715c', 'jno    0x27627e8'),
        41297804: ('488b8c24680200', 'mov    0x268(%rsp),%rcx'),
        41297812: ('4885c9', 'test   %rcx,%rcx'),
        41297815: ('7472', 'je     0x276280b'),
        41297817: ('488b9424700200', 'mov    0x270(%rsp),%rdx'),
        41297825: ('488b8424780200', 'mov    0x278(%rsp),%rax'),
        41297833: ('48c78424980000', 'movq   $0x0,0x98(%rsp)'),
        41297845: ('48898c24a00000', 'mov    %rcx,0xa0(%rsp)'),
        41297853: ('48899424a80000', 'mov    %rdx,0xa8(%rsp)'),
        41297861: ('48c78424b80000', 'movq   $0x0,0xb8(%rsp)'),
        41297873: ('48898c24c00000', 'mov    %rcx,0xc0(%rsp)'),
        41297881: ('48899424c80000', 'mov    %rdx,0xc8(%rsp)'),
        41297889: ('b901000000', 'mov    $0x1,%ecx'),
        41297894: ('eb27', 'jmp    0x276280f'),
        41297896: ('0f836effffff', 'jae    0x276275c'),
        41297902: ('488bbc24680200', 'mov    0x268(%rsp),%rdi'),
        41297910: ('48c1e003', 'shl    $0x3,%rax'),
        41297914: ('488d3480', 'lea    (%rax,%rax,4),%rsi'),
        41297918: ('31d2', 'xor    %edx,%edx'),
        41297920: ('ff159accd703', 'call   *0x3d7cc9a(%rip)'),
        41297926: ('e951ffffff', 'jmp    0x276275c'),
        41297931: ('31c9', 'xor    %ecx,%ecx'),
        41297933: ('31c0', 'xor    %eax,%eax'),
        41297935: ('48898c24900000', 'mov    %rcx,0x90(%rsp)'),
        41297943: ('48898c24b00000', 'mov    %rcx,0xb0(%rsp)'),
        41297951: ('48898424d00000', 'mov    %rax,0xd0(%rsp)'),
        41297959: ('4c8d742410', 'lea    0x10(%rsp),%r14'),
        41297964: ('4c8dbc24900000', 'lea    0x90(%rsp),%r15'),
        41297972: ('6666662e0f1f84', 'data16 data16 cs nopw 0x0(%rax,%rax,1)'),
        41297984: ('4c89f7', 'mov    %r14,%rdi'),
        41297987: ('4c89fe', 'mov    %r15,%rsi'),
        41297990: ('e85527ceff', 'call   0x2444fa0'),
        41297995: ('48837c241000', 'cmpq   $0x0,0x10(%rsp)'),
        41298001: ('75ed', 'jne    0x2762840'),
        41298003: ('e904ffffff', 'jmp    0x276275c'),
        41298008: ('4889c3', 'mov    %rax,%rbx'),
        41298011: ('488dbc24b00100', 'lea    0x1b0(%rsp),%rdi'),
        41298019: ('e878e30100', 'call   0x2780be0'),
        41298024: ('4889df', 'mov    %rbx,%rdi'),
        41298027: ('e8e0e1c803', 'call   0x63f0a50'),
        41298032: ('ff154accd703', 'call   *0x3d7cc4a(%rip)'),
    },
    'helper_jc1': {
        41296624: ('55', 'push   %rbp'),
        41296625: ('4157', 'push   %r15'),
        41296627: ('4156', 'push   %r14'),
        41296629: ('4155', 'push   %r13'),
        41296631: ('4154', 'push   %r12'),
        41296633: ('53', 'push   %rbx'),
        41296634: ('4881ec68020000', 'sub    $0x268,%rsp'),
        41296641: ('4889f0', 'mov    %rsi,%rax'),
        41296644: ('4889fb', 'mov    %rdi,%rbx'),
        41296647: ('4c8d624c', 'lea    0x4c(%rdx),%r12'),
        41296651: ('4c8b7230', 'mov    0x30(%rdx),%r14'),
        41296655: ('0f100a', 'movups (%rdx),%xmm1'),
        41296658: ('0f105210', 'movups 0x10(%rdx),%xmm2'),
        41296662: ('488d6a40', 'lea    0x40(%rdx),%rbp'),
        41296666: ('4c8b7a20', 'mov    0x20(%rdx),%r15'),
        41296670: ('4c8b6a28', 'mov    0x28(%rdx),%r13'),
        41296674: ('488b7238', 'mov    0x38(%rdx),%rsi'),
        41296678: ('4885f6', 'test   %rsi,%rsi'),
        41296681: ('7536', 'jne    0x2762361'),
        41296683: ('418b4c2410', 'mov    0x10(%r12),%ecx'),
        41296688: ('894c2430', 'mov    %ecx,0x30(%rsp)'),
        41296692: ('410f100424', 'movups (%r12),%xmm0'),
        41296697: ('0f29442420', 'movaps %xmm0,0x20(%rsp)'),
        41296702: ('488d742420', 'lea    0x20(%rsp),%rsi'),
        41296707: ('4889c7', 'mov    %rax,%rdi'),
        41296710: ('0f294c2410', 'movaps %xmm1,0x10(%rsp)'),
        41296715: ('0f291424', 'movaps %xmm2,(%rsp)'),
        41296719: ('ff154341d803', 'call   *0x3d84143(%rip)'),
        41296725: ('0f281424', 'movaps (%rsp),%xmm2'),
        41296729: ('0f284c2410', 'movaps 0x10(%rsp),%xmm1'),
        41296734: ('4889c6', 'mov    %rax,%rsi'),
        41296737: ('498d4710', 'lea    0x10(%r15),%rax'),
        41296741: ('8b4d08', 'mov    0x8(%rbp),%ecx'),
        41296744: ('894c2460', 'mov    %ecx,0x60(%rsp)'),
        41296748: ('488b4d00', 'mov    0x0(%rbp),%rcx'),
        41296752: ('48894c2458', 'mov    %rcx,0x58(%rsp)'),
        41296757: ('410f100424', 'movups (%r12),%xmm0'),
        41296762: ('0f11442464', 'movups %xmm0,0x64(%rsp)'),
        41296767: ('418b4c2410', 'mov    0x10(%r12),%ecx'),
        41296772: ('894c2474', 'mov    %ecx,0x74(%rsp)'),
        41296776: ('4c89742450', 'mov    %r14,0x50(%rsp)'),
        41296781: ('0f29542430', 'movaps %xmm2,0x30(%rsp)'),
        41296786: ('4c896c2440', 'mov    %r13,0x40(%rsp)'),
        41296791: ('0f294c2420', 'movaps %xmm1,0x20(%rsp)'),
        41296796: ('4889442448', 'mov    %rax,0x48(%rsp)'),
        41296801: ('488dbc24500100', 'lea    0x150(%rsp),%rdi'),
        41296809: ('488d542420', 'lea    0x20(%rsp),%rdx'),
        41296814: ('e8ed2e4500', 'call   0x2bb52a0'),
        41296819: ('4c8bac24500100', 'mov    0x150(%rsp),%r13'),
        41296827: ('0fb6ac24580100', 'movzbl 0x158(%rsp),%ebp'),
        41296835: ('4983fd03', 'cmp    $0x3,%r13'),
        41296839: ('750d', 'jne    0x27623d6'),
        41296841: ('40886b08', 'mov    %bpl,0x8(%rbx)'),
        41296845: ('48c70303000000', 'movq   $0x3,(%rbx)'),
        41296852: ('eb7e', 'jmp    0x2762454'),
        41296854: ('488db424590100', 'lea    0x159(%rsp),%rsi'),
        41296862: ('488d7c2429', 'lea    0x29(%rsp),%rdi'),
        41296867: ('ba0f010000', 'mov    $0x10f,%edx'),
        41296872: ('ff151ad1d703', 'call   *0x3d7d11a(%rip)'),
        41296878: ('4c896c2420', 'mov    %r13,0x20(%rsp)'),
        41296883: ('40886c2428', 'mov    %bpl,0x28(%rsp)'),
        41296888: ('4983fd02', 'cmp    $0x2,%r13'),
        41296892: ('7443', 'je     0x2762441'),
        41296894: ('80bc2430010000', 'cmpb   $0x0,0x130(%rsp)'),
        41296902: ('7439', 'je     0x2762441'),
        41296904: ('488b8c24280100', 'mov    0x128(%rsp),%rcx'),
        41296912: ('418b442410', 'mov    0x10(%r12),%eax'),
        41296917: ('89842460010000', 'mov    %eax,0x160(%rsp)'),
        41296924: ('410f100424', 'movups (%r12),%xmm0'),
        41296929: ('0f298424500100', 'movaps %xmm0,0x150(%rsp)'),
        41296937: ('488db424500100', 'lea    0x150(%rsp),%rsi'),
        41296945: ('4c89ff', 'mov    %r15,%rdi'),
        41296948: ('4c89f2', 'mov    %r14,%rdx'),
        41296951: ('ff156340d803', 'call   *0x3d84063(%rip)'),
        41296957: ('84c0', 'test   %al,%al'),
        41296959: ('7428', 'je     0x2762469'),
        41296961: ('488d742420', 'lea    0x20(%rsp),%rsi'),
        41296966: ('ba18010000', 'mov    $0x118,%edx'),
        41296971: ('4889df', 'mov    %rbx,%rdi'),
        41296974: ('ff15b4d0d703', 'call   *0x3d7d0b4(%rip)'),
        41296980: ('4889d8', 'mov    %rbx,%rax'),
        41296983: ('4881c468020000', 'add    $0x268,%rsp'),
        41296990: ('5b', 'pop    %rbx'),
        41296991: ('415c', 'pop    %r12'),
        41296993: ('415d', 'pop    %r13'),
        41296995: ('415e', 'pop    %r14'),
        41296997: ('415f', 'pop    %r15'),
        41296999: ('5d', 'pop    %rbp'),
        41297000: ('c3', 'ret'),
        41297001: ('c6430805', 'movb   $0x5,0x8(%rbx)'),
        41297005: ('48c70303000000', 'movq   $0x3,(%rbx)'),
        41297012: ('488b8424d00000', 'mov    0xd0(%rsp),%rax'),
        41297020: ('4889c1', 'mov    %rax,%rcx'),
        41297023: ('48f7d9', 'neg    %rcx'),
        41297026: ('715c', 'jno    0x27624e0'),
        41297028: ('488b8c24d80000', 'mov    0xd8(%rsp),%rcx'),
        41297036: ('4885c9', 'test   %rcx,%rcx'),
        41297039: ('7472', 'je     0x2762503'),
        41297041: ('488b9424e00000', 'mov    0xe0(%rsp),%rdx'),
        41297049: ('488b8424e80000', 'mov    0xe8(%rsp),%rax'),
        41297057: ('48c78424580100', 'movq   $0x0,0x158(%rsp)'),
        41297069: ('48898c24600100', 'mov    %rcx,0x160(%rsp)'),
        41297077: ('48899424680100', 'mov    %rdx,0x168(%rsp)'),
        41297085: ('48c78424780100', 'movq   $0x0,0x178(%rsp)'),
        41297097: ('48898c24800100', 'mov    %rcx,0x180(%rsp)'),
        41297105: ('48899424880100', 'mov    %rdx,0x188(%rsp)'),
        41297113: ('b901000000', 'mov    $0x1,%ecx'),
        41297118: ('eb27', 'jmp    0x2762507'),
        41297120: ('0f836effffff', 'jae    0x2762454'),
        41297126: ('488bbc24d80000', 'mov    0xd8(%rsp),%rdi'),
        41297134: ('48c1e003', 'shl    $0x3,%rax'),
        41297138: ('488d3480', 'lea    (%rax,%rax,4),%rsi'),
        41297142: ('31d2', 'xor    %edx,%edx'),
        41297144: ('ff15a2cfd703', 'call   *0x3d7cfa2(%rip)'),
        41297150: ('e951ffffff', 'jmp    0x2762454'),
        41297155: ('31c9', 'xor    %ecx,%ecx'),
        41297157: ('31c0', 'xor    %eax,%eax'),
        41297159: ('48898c24500100', 'mov    %rcx,0x150(%rsp)'),
        41297167: ('48898c24700100', 'mov    %rcx,0x170(%rsp)'),
        41297175: ('48898424900100', 'mov    %rax,0x190(%rsp)'),
        41297183: ('4c8db424380100', 'lea    0x138(%rsp),%r14'),
        41297191: ('4c8dbc24500100', 'lea    0x150(%rsp),%r15'),
        41297199: ('90', 'nop'),
        41297200: ('4c89f7', 'mov    %r14,%rdi'),
        41297203: ('4c89fe', 'mov    %r15,%rsi'),
        41297206: ('e8652aceff', 'call   0x2444fa0'),
        41297211: ('4883bc24380100', 'cmpq   $0x0,0x138(%rsp)'),
        41297220: ('75ea', 'jne    0x2762530'),
        41297222: ('e909ffffff', 'jmp    0x2762454'),
        41297227: ('4889c3', 'mov    %rax,%rbx'),
        41297230: ('488d7c2420', 'lea    0x20(%rsp),%rdi'),
        41297235: ('e888e60100', 'call   0x2780be0'),
        41297240: ('4889df', 'mov    %rbx,%rdi'),
        41297243: ('e8f0e4c803', 'call   0x63f0a50'),
        41297248: ('ff155acfd703', 'call   *0x3d7cf5a(%rip)'),
    },
    'helper_s2': {
        57259888: ('55', 'push   %rbp'),
        57259889: ('4157', 'push   %r15'),
        57259891: ('4156', 'push   %r14'),
        57259893: ('4155', 'push   %r13'),
        57259895: ('4154', 'push   %r12'),
        57259897: ('53', 'push   %rbx'),
        57259898: ('4881ec68010000', 'sub    $0x168,%rsp'),
        57259905: ('894c2404', 'mov    %ecx,0x4(%rsp)'),
        57259909: ('4989d6', 'mov    %rdx,%r14'),
        57259912: ('4989f7', 'mov    %rsi,%r15'),
        57259915: ('4889fb', 'mov    %rdi,%rbx'),
        57259918: ('48899424c80000', 'mov    %rdx,0xc8(%rsp)'),
        57259926: ('4889542450', 'mov    %rdx,0x50(%rsp)'),
        57259931: ('4c8b6658', 'mov    0x58(%rsi),%r12'),
        57259935: ('4c89e0', 'mov    %r12,%rax'),
        57259938: ('48f7d8', 'neg    %rax'),
        57259941: ('717c', 'jno    0x369b823'),
        57259943: ('498b4760', 'mov    0x60(%r15),%rax'),
        57259947: ('4885c0', 'test   %rax,%rax'),
        57259950: ('0f84b0000000', 'je     0x369b864'),
        57259956: ('498b4f68', 'mov    0x68(%r15),%rcx'),
        57259960: ('0fb7b0f2070000', 'movzwl 0x7f2(%rax),%esi'),
        57259967: ('4c69c6b0000000', 'imul   $0xb0,%rsi,%r8'),
        57259974: ('48c7c2ffffffff', 'mov    $0xffffffffffffffff,%rdx'),
        57259981: ('31ff', 'xor    %edi,%edi'),
        57259983: ('90', 'nop'),
        57259984: ('4d89c1', 'mov    %r8,%r9'),
        57259987: ('4901f9', 'add    %rdi,%r9'),
        57259990: ('7438', 'je     0x369b810'),
        57259992: ('4c3bb4d0a00700', 'cmp    0x7a0(%rax,%rdx,8),%r14'),
        57260000: ('410f97c1', 'seta   %r9b'),
        57260004: ('4180d900', 'sbb    $0x0,%r9b'),
        57260008: ('4881c750ffffff', 'add    $0xffffffffffffff50,%rdi'),
        57260015: ('48ffc2', 'inc    %rdx'),
        57260018: ('4180f901', 'cmp    $0x1,%r9b'),
        57260022: ('74d8', 'je     0x369b7d0'),
        57260024: ('410fb6f1', 'movzbl %r9b,%esi'),
        57260028: ('85f6', 'test   %esi,%esi'),
        57260030: ('7513', 'jne    0x369b813'),
        57260032: ('eb72', 'jmp    0x369b874'),
        57260034: ('66666666662e0f', 'data16 data16 data16 data16 cs nopw 0x0(%rax,%rax,1)'),
        57260048: ('4889f2', 'mov    %rsi,%rdx'),
        57260051: ('4883e901', 'sub    $0x1,%rcx'),
        57260055: ('724b', 'jb     0x369b864'),
        57260057: ('488b84d0f80700', 'mov    0x7f8(%rax,%rdx,8),%rax'),
        57260065: ('eb95', 'jmp    0x369b7b8'),
        57260067: ('498d7f58', 'lea    0x58(%r15),%rdi'),
        57260071: ('488d742450', 'lea    0x50(%rsp),%rsi'),
        57260076: ('e8dfabeb00', 'call   0x4556410'),
        57260081: ('a801', 'test   $0x1,%al'),
        57260083: ('752f', 'jne    0x369b864'),
        57260085: ('493b5770', 'cmp    0x70(%r15),%rdx'),
        57260089: ('7329', 'jae    0x369b864'),
        57260091: ('48895c2408', 'mov    %rbx,0x8(%rsp)'),
        57260096: ('49035768', 'add    0x68(%r15),%rdx'),
        57260100: ('31c0', 'xor    %eax,%eax'),
        57260102: ('4c39e2', 'cmp    %r12,%rdx'),
        57260105: ('490f43c4', 'cmovae %r12,%rax'),
        57260109: ('4829c2', 'sub    %rax,%rdx'),
        57260112: ('498b4760', 'mov    0x60(%r15),%rax'),
        57260116: ('4869cab8000000', 'imul   $0xb8,%rdx,%rcx'),
        57260123: ('4801c8', 'add    %rcx,%rax'),
        57260126: ('4883c008', 'add    $0x8,%rax'),
        57260130: ('eb1e', 'jmp    0x369b882'),
        57260132: ('c6430809', 'movb   $0x9,0x8(%rbx)'),
        57260136: ('48c70302000000', 'movq   $0x2,(%rbx)'),
        57260143: ('e982050000', 'jmp    0x369bdf6'),
        57260148: ('48895c2408', 'mov    %rbx,0x8(%rsp)'),
        57260153: ('4829f8', 'sub    %rdi,%rax'),
        57260156: ('480550ffffff', 'add    $0xffffffffffffff50,%rax'),
        57260162: ('49bd0000000000', 'movabs $0x8000000000000000,%r13'),
        57260172: ('0f104018', 'movups 0x18(%rax),%xmm0'),
        57260176: ('0f298424100100', 'movaps %xmm0,0x110(%rsp)'),
        57260184: ('0f104028', 'movups 0x28(%rax),%xmm0'),
        57260188: ('0f298424000100', 'movaps %xmm0,0x100(%rsp)'),
        57260196: ('488b4838', 'mov    0x38(%rax),%rcx'),
        57260200: ('48894c2430', 'mov    %rcx,0x30(%rsp)'),
        57260205: ('488b4840', 'mov    0x40(%rax),%rcx'),
        57260209: ('48898c24a00000', 'mov    %rcx,0xa0(%rsp)'),
        57260217: ('4c8b6058', 'mov    0x58(%rax),%r12'),
        57260221: ('0f104048', 'movups 0x48(%rax),%xmm0'),
        57260225: ('0f298424400100', 'movaps %xmm0,0x140(%rsp)'),
        57260233: ('488b4860', 'mov    0x60(%rax),%rcx'),
        57260237: ('48898c24980000', 'mov    %rcx,0x98(%rsp)'),
        57260245: ('488b4878', 'mov    0x78(%rax),%rcx'),
        57260249: ('48894c2438', 'mov    %rcx,0x38(%rsp)'),
        57260254: ('0f104068', 'movups 0x68(%rax),%xmm0'),
        57260258: ('0f298424500100', 'movaps %xmm0,0x150(%rsp)'),
        57260266: ('0f108080000000', 'movups 0x80(%rax),%xmm0'),
        57260273: ('0f108890000000', 'movups 0x90(%rax),%xmm1'),
        57260280: ('0f298424200100', 'movaps %xmm0,0x120(%rsp)'),
        57260288: ('0f298c24300100', 'movaps %xmm1,0x130(%rsp)'),
        57260296: ('488b5010', 'mov    0x10(%rax),%rdx'),
        57260300: ('0f1000', 'movups (%rax),%xmm0'),
        57260303: ('0f298424f00000', 'movaps %xmm0,0xf0(%rsp)'),
        57260311: ('8b88a8000000', 'mov    0xa8(%rax),%ecx'),
        57260317: ('894c2448', 'mov    %ecx,0x48(%rsp)'),
        57260321: ('488b80a0000000', 'mov    0xa0(%rax),%rax'),
        57260328: ('4889442440', 'mov    %rax,0x40(%rsp)'),
        57260333: ('48c74424100000', 'movq   $0x0,0x10(%rsp)'),
        57260342: ('48c74424180800', 'movq   $0x8,0x18(%rsp)'),
        57260351: ('48c74424200000', 'movq   $0x0,0x20(%rsp)'),
        57260360: ('498b8788000000', 'mov    0x88(%r15),%rax'),
        57260367: ('4c39e8', 'cmp    %r13,%rax'),
        57260370: ('48899424a80000', 'mov    %rdx,0xa8(%rsp)'),
        57260378: ('752d', 'jne    0x369b989'),
        57260380: ('498b8790000000', 'mov    0x90(%r15),%rax'),
        57260387: ('31d2', 'xor    %edx,%edx'),
        57260389: ('4889c7', 'mov    %rax,%rdi'),
        57260392: ('4885c0', 'test   %rax,%rax'),
        57260395: ('400f95c6', 'setne  %sil'),
        57260399: ('7407', 'je     0x369b978'),
        57260401: ('498bbfa0000000', 'mov    0xa0(%r15),%rdi'),
        57260408: ('498b8f98000000', 'mov    0x98(%r15),%rcx'),
        57260415: ('4088f2', 'mov    %sil,%dl'),
        57260418: ('31f6', 'xor    %esi,%esi'),
        57260420: ('4989d0', 'mov    %rdx,%r8'),
        57260423: ('eb6b', 'jmp    0x369b9f4'),
        57260425: ('498b8fa0000000', 'mov    0xa0(%r15),%rcx'),
        57260432: ('4885c9', 'test   %rcx,%rcx'),
        57260435: ('742b', 'je     0x369b9c0'),
        57260437: ('498b9798000000', 'mov    0x98(%r15),%rdx'),
        57260444: ('31f6', 'xor    %esi,%esi'),
        57260446: ('4839c2', 'cmp    %rax,%rdx'),
        57260449: ('480f43f0', 'cmovae %rax,%rsi'),
        57260453: ('4829f2', 'sub    %rsi,%rdx'),
        57260456: ('4889c6', 'mov    %rax,%rsi'),
        57260459: ('4829d6', 'sub    %rdx,%rsi'),
        57260462: ('4889cf', 'mov    %rcx,%rdi'),
        57260465: ('4829f7', 'sub    %rsi,%rdi'),
        57260468: ('7710', 'ja     0x369b9c6'),
        57260470: ('4801d1', 'add    %rdx,%rcx'),
        57260473: ('31ff', 'xor    %edi,%edi'),
        57260475: ('4889c8', 'mov    %rcx,%rax'),
        57260478: ('eb06', 'jmp    0x369b9c6'),
        57260480: ('31d2', 'xor    %edx,%edx'),
        57260482: ('31c0', 'xor    %eax,%eax'),
        57260484: ('31ff', 'xor    %edi,%edi'),
        57260486: ('498b8f90000000', 'mov    0x90(%r15),%rcx'),
        57260493: ('488d3492', 'lea    (%rdx,%rdx,4),%rsi'),
        57260497: ('48c1e604', 'shl    $0x4,%rsi'),
        57260501: ('4801ce', 'add    %rcx,%rsi'),
        57260504: ('488d0480', 'lea    (%rax,%rax,4),%rax'),
        57260508: ('48c1e004', 'shl    $0x4,%rax'),
        57260512: ('4801c8', 'add    %rcx,%rax'),
        57260515: ('488d14bf', 'lea    (%rdi,%rdi,4),%rdx'),
        57260519: ('48c1e204', 'shl    $0x4,%rdx'),
        57260523: ('4801ca', 'add    %rcx,%rdx'),
        57260526: ('41b802000000', 'mov    $0x2,%r8d'),
        57260532: ('448b4c2404', 'mov    0x4(%rsp),%r9d'),
        57260537: ('4584c9', 'test   %r9b,%r9b'),
        57260540: ('4c8b542438', 'mov    0x38(%rsp),%r10'),
        57260545: ('4d0f45d4', 'cmovne %r12,%r10'),
        57260549: ('4c899424b80000', 'mov    %r10,0xb8(%rsp)'),
        57260557: ('4c89442450', 'mov    %r8,0x50(%rsp)'),
        57260562: ('488d5c2458', 'lea    0x58(%rsp),%rbx'),
        57260567: ('4889742458', 'mov    %rsi,0x58(%rsp)'),
        57260572: ('4889442460', 'mov    %rax,0x60(%rsp)'),
        57260577: ('48894c2468', 'mov    %rcx,0x68(%rsp)'),
        57260582: ('4889542470', 'mov    %rdx,0x70(%rsp)'),
        57260587: ('48c74424780000', 'movq   $0x0,0x78(%rsp)'),
        57260596: ('48898424800000', 'mov    %rax,0x80(%rsp)'),
        57260604: ('48898c24880000', 'mov    %rcx,0x88(%rsp)'),
        57260612: ('4889bc24900000', 'mov    %rdi,0x90(%rsp)'),
        57260620: ('4489c8', 'mov    %r9d,%eax'),
        57260623: ('3401', 'xor    $0x1,%al'),
        57260625: ('0fb6c0', 'movzbl %al,%eax'),
        57260628: ('c1e004', 'shl    $0x4,%eax'),
        57260631: ('4883c808', 'or     $0x8,%rax'),
        57260635: ('48898424b00000', 'mov    %rax,0xb0(%rsp)'),
        57260643: ('48c74424280000', 'movq   $0x0,0x28(%rsp)'),
        57260652: ('4c89a424c00000', 'mov    %r12,0xc0(%rsp)'),
        57260660: ('837c245002', 'cmpl   $0x2,0x50(%rsp)'),
        57260665: ('7417', 'je     0x369ba92'),
        57260667: ('e980000000', 'jmp    0x369bb00'),
        57260672: ('31c0', 'xor    %eax,%eax'),
        57260674: ('4885c0', 'test   %rax,%rax'),
        57260677: ('0f857f010000', 'jne    0x369bc0a'),
        57260683: ('837c245002', 'cmpl   $0x2,0x50(%rsp)'),
        57260688: ('756e', 'jne    0x369bb00'),
        57260690: ('488b442458', 'mov    0x58(%rsp),%rax'),
        57260695: ('488b4c2460', 'mov    0x60(%rsp),%rcx'),
        57260700: ('4839c8', 'cmp    %rcx,%rax'),
        57260703: ('751d', 'jne    0x369babe'),
        57260705: ('0f104310', 'movups 0x10(%rbx),%xmm0'),
        57260709: ('0f1103', 'movups %xmm0,(%rbx)'),
        57260712: ('4889442468', 'mov    %rax,0x68(%rsp)'),
        57260717: ('48894c2470', 'mov    %rcx,0x70(%rsp)'),
        57260722: ('488b442458', 'mov    0x58(%rsp),%rax'),
        57260727: ('483b442460', 'cmp    0x60(%rsp),%rax'),
        57260732: ('7417', 'je     0x369bad5'),
        57260734: ('488d4850', 'lea    0x50(%rax),%rcx'),
        57260738: ('48894c2458', 'mov    %rcx,0x58(%rsp)'),
        57260743: ('488d6818', 'lea    0x18(%rax),%rbp'),
        57260747: ('4885c0', 'test   %rax,%rax'),
        57260750: ('7546', 'jne    0x369bb16'),
        57260752: ('e92f020000', 'jmp    0x369bd04'),
        57260757: ('31c0', 'xor    %eax,%eax'),
        57260759: ('488d6818', 'lea    0x18(%rax),%rbp'),
        57260763: ('4885c0', 'test   %rax,%rax'),
        57260766: ('7536', 'jne    0x369bb16'),
        57260768: ('e91f020000', 'jmp    0x369bd04'),
        57260773: ('66662e0f1f8400', 'data16 cs nopw 0x0(%rax,%rax,1)'),
        57260784: ('4829f8', 'sub    %rdi,%rax'),
        57260787: ('4883c0e0', 'add    $0xffffffffffffffe0,%rax'),
        57260791: ('eb89', 'jmp    0x369ba82'),
        57260793: ('0f1f8000000000', 'nopl   0x0(%rax)'),
        57260800: ('488d7c2450', 'lea    0x50(%rsp),%rdi'),
        57260805: ('e816c61200', 'call   0x37c8120'),
        57260810: ('4889d5', 'mov    %rdx,%rbp'),
        57260813: ('4885c0', 'test   %rax,%rax'),
        57260816: ('0f84ee010000', 'je     0x369bd04'),
        57260822: ('8b4810', 'mov    0x10(%rax),%ecx'),
        57260825: ('898c24e0000000', 'mov    %ecx,0xe0(%rsp)'),
        57260832: ('0f1000', 'movups (%rax),%xmm0'),
        57260835: ('0f298424d00000', 'movaps %xmm0,0xd0(%rsp)'),
        57260843: ('4c8b7d00', 'mov    0x0(%rbp),%r15'),
        57260847: ('4d39ef', 'cmp    %r13,%r15'),
        57260850: ('0f8588000000', 'jne    0x369bbc0'),
        57260856: ('488b4508', 'mov    0x8(%rbp),%rax'),
        57260860: ('4885c0', 'test   %rax,%rax'),
        57260863: ('0f843bffffff', 'je     0x369ba80'),
        57260869: ('488b4d10', 'mov    0x10(%rbp),%rcx'),
        57260873: ('0fb7b0c2010000', 'movzwl 0x1c2(%rax),%esi'),
        57260880: ('4189f0', 'mov    %esi,%r8d'),
        57260883: ('41c1e005', 'shl    $0x5,%r8d'),
        57260887: ('48c7c2ffffffff', 'mov    $0xffffffffffffffff,%rdx'),
        57260894: ('31ff', 'xor    %edi,%edi'),
        57260896: ('4d89c1', 'mov    %r8,%r9'),
        57260899: ('4901f9', 'add    %rdi,%r9'),
        57260902: ('7438', 'je     0x369bba0'),
        57260904: ('4c3bb4d0700100', 'cmp    0x170(%rax,%rdx,8),%r14'),
        57260912: ('410f97c1', 'seta   %r9b'),
        57260916: ('4180d900', 'sbb    $0x0,%r9b'),
        57260920: ('4883c7e0', 'add    $0xffffffffffffffe0,%rdi'),
        57260924: ('48ffc2', 'inc    %rdx'),
        57260927: ('4180f901', 'cmp    $0x1,%r9b'),
        57260931: ('74db', 'je     0x369bb60'),
        57260933: ('410fb6f1', 'movzbl %r9b,%esi'),
        57260937: ('85f6', 'test   %esi,%esi'),
        57260939: ('0f845fffffff', 'je     0x369baf0'),
        57260945: ('4883e901', 'sub    $0x1,%rcx'),
        57260949: ('7316', 'jae    0x369bbad'),
        57260951: ('e9e4feffff', 'jmp    0x369ba80'),
        57260956: ('0f1f4000', 'nopl   0x0(%rax)'),
        57260960: ('4889f2', 'mov    %rsi,%rdx'),
        57260963: ('4883e901', 'sub    $0x1,%rcx'),
        57260967: ('0f82d3feffff', 'jb     0x369ba80'),
        57260973: ('488b84d0c80100', 'mov    0x1c8(%rax,%rdx,8),%rax'),
        57260981: ('eb92', 'jmp    0x369bb49'),
        57260983: ('660f1f84000000', 'nopw   0x0(%rax,%rax,1)'),
        57260992: ('4889ef', 'mov    %rbp,%rdi'),
        57260995: ('488db424c80000', 'lea    0xc8(%rsp),%rsi'),
        57261003: ('e8e0fbeb00', 'call   0x455b7b0'),
        57261008: ('a801', 'test   $0x1,%al'),
        57261010: ('0f85a8feffff', 'jne    0x369ba80'),
        57261016: ('b800000000', 'mov    $0x0,%eax'),
        57261021: ('483b5518', 'cmp    0x18(%rbp),%rdx'),
        57261025: ('0f839bfeffff', 'jae    0x369ba82'),
        57261031: ('48035510', 'add    0x10(%rbp),%rdx'),
        57261035: ('4c39fa', 'cmp    %r15,%rdx'),
        57261038: ('b800000000', 'mov    $0x0,%eax'),
        57261043: ('490f43c7', 'cmovae %r15,%rax'),
        57261047: ('4829c2', 'sub    %rax,%rdx'),
        57261050: ('488b4508', 'mov    0x8(%rbp),%rax'),
        57261054: ('488d0c92', 'lea    (%rdx,%rdx,4),%rcx'),
        57261058: ('488d04c8', 'lea    (%rax,%rcx,8),%rax'),
        57261062: ('4883c008', 'add    $0x8,%rax'),
        57261066: ('488b8c24b00000', 'mov    0xb0(%rsp),%rcx'),
        57261074: ('4c8b3c08', 'mov    (%rax,%rcx,1),%r15'),
        57261078: ('4c89f8', 'mov    %r15,%rax'),
        57261081: ('48f7a424b80000', 'mulq   0xb8(%rsp)'),
        57261089: ('4989d5', 'mov    %rdx,%r13'),
        57261092: ('4989c4', 'mov    %rax,%r12'),
        57261095: ('4889c7', 'mov    %rax,%rdi'),
        57261098: ('4889d6', 'mov    %rdx,%rsi'),
        57261101: ('48bb00407a10f3', 'movabs $0x5af3107a4000,%rbx'),
        57261111: ('4889da', 'mov    %rbx,%rdx'),
        57261114: ('31c9', 'xor    %ecx,%ecx'),
        57261116: ('ff15b63ee402', 'call   *0x2e43eb6(%rip)'),
        57261122: ('4889c5', 'mov    %rax,%rbp'),
        57261125: ('4889d1', 'mov    %rdx,%rcx'),
        57261128: ('807c240400', 'cmpb   $0x0,0x4(%rsp)'),
        57261133: ('7425', 'je     0x369bc74'),
        57261135: ('4889e8', 'mov    %rbp,%rax'),
        57261138: ('48f7e3', 'mul    %rbx'),
        57261141: ('4889ce', 'mov    %rcx,%rsi'),
        57261144: ('480faff3', 'imul   %rbx,%rsi'),
        57261148: ('4801d6', 'add    %rdx,%rsi'),
        57261151: ('4929c4', 'sub    %rax,%r12'),
        57261154: ('4919f5', 'sbb    %rsi,%r13'),
        57261157: ('31c0', 'xor    %eax,%eax'),
        57261159: ('4d09e5', 'or     %r12,%r13'),
        57261162: ('0f95c0', 'setne  %al'),
        57261165: ('4801c5', 'add    %rax,%rbp'),
        57261168: ('4883d100', 'adc    $0x0,%rcx'),
        57261172: ('4885c9', 'test   %rcx,%rcx'),
        57261175: ('4c8ba424c00000', 'mov    0xc0(%rsp),%r12'),
        57261183: ('49bd0000000000', 'movabs $0x8000000000000000,%r13'),
        57261193: ('488d5c2458', 'lea    0x58(%rsp),%rbx'),
        57261198: ('0f8577010000', 'jne    0x369be0b'),
        57261204: ('4d85ff', 'test   %r15,%r15'),
        57261207: ('7509', 'jne    0x369bca2'),
        57261209: ('4809e9', 'or     %rbp,%rcx'),
        57261212: ('0f856d010000', 'jne    0x369be0f'),
        57261218: ('48016c2428', 'add    %rbp,0x28(%rsp)'),
        57261223: ('0f8290010000', 'jb     0x369be3d'),
        57261229: ('4c8b7c2420', 'mov    0x20(%rsp),%r15'),
        57261234: ('4c3b7c2410', 'cmp    0x10(%rsp),%r15'),
        57261239: ('750b', 'jne    0x369bcc4'),
        57261241: ('488d7c2410', 'lea    0x10(%rsp),%rdi'),
        57261246: ('ff15cca9e402', 'call   *0x2e4a9cc(%rip)'),
        57261252: ('488b442418', 'mov    0x18(%rsp),%rax'),
        57261257: ('4c89f9', 'mov    %r15,%rcx'),
        57261260: ('48c1e105', 'shl    $0x5,%rcx'),
        57261264: ('8b9424e0000000', 'mov    0xe0(%rsp),%edx'),
        57261271: ('89540810', 'mov    %edx,0x10(%rax,%rcx,1)'),
        57261275: ('0f288424d00000', 'movaps 0xd0(%rsp),%xmm0'),
        57261283: ('0f110408', 'movups %xmm0,(%rax,%rcx,1)'),
        57261287: ('48896c0818', 'mov    %rbp,0x18(%rax,%rcx,1)'),
        57261292: ('49ffc7', 'inc    %r15'),
        57261295: ('4c897c2420', 'mov    %r15,0x20(%rsp)'),
        57261300: ('837c245002', 'cmpl   $0x2,0x50(%rsp)'),
        57261305: ('0f8501feffff', 'jne    0x369bb00'),
        57261311: ('e98efdffff', 'jmp    0x369ba92'),
        57261316: ('807c240400', 'cmpb   $0x0,0x4(%rsp)'),
        57261321: ('7423', 'je     0x369bd2e'),
        57261323: ('49bc00407a10f3', 'movabs $0x5af3107a4000,%r12'),
        57261333: ('488b7c2438', 'mov    0x38(%rsp),%rdi'),
        57261338: ('488b542428', 'mov    0x28(%rsp),%rdx'),
        57261343: ('488b4c2430', 'mov    0x30(%rsp),%rcx'),
        57261348: ('488bb424980000', 'mov    0x98(%rsp),%rsi'),
        57261356: ('eb1c', 'jmp    0x369bd4a'),
        57261358: ('488b742428', 'mov    0x28(%rsp),%rsi'),
        57261363: ('488b4c2430', 'mov    0x30(%rsp),%rcx'),
        57261368: ('488b9424a00000', 'mov    0xa0(%rsp),%rdx'),
        57261376: ('48bf00407a10f3', 'movabs $0x5af3107a4000,%rdi'),
        57261386: ('488b5c2408', 'mov    0x8(%rsp),%rbx'),
        57261391: ('0f288424400100', 'movaps 0x140(%rsp),%xmm0'),
        57261399: ('0f114348', 'movups %xmm0,0x48(%rbx)'),
        57261403: ('0f288424500100', 'movaps 0x150(%rsp),%xmm0'),
        57261411: ('0f114368', 'movups %xmm0,0x68(%rbx)'),
        57261415: ('0f288424200100', 'movaps 0x120(%rsp),%xmm0'),
        57261423: ('0f288c24300100', 'movaps 0x130(%rsp),%xmm1'),
        57261431: ('0f118b90000000', 'movups %xmm1,0x90(%rbx)'),
        57261438: ('0f118380000000', 'movups %xmm0,0x80(%rbx)'),
        57261445: ('488b442440', 'mov    0x40(%rsp),%rax'),
        57261450: ('488983a0000000', 'mov    %rax,0xa0(%rbx)'),
        57261457: ('8b442448', 'mov    0x48(%rsp),%eax'),
        57261461: ('8983a8000000', 'mov    %eax,0xa8(%rbx)'),
        57261467: ('0f10442410', 'movups 0x10(%rsp),%xmm0'),
        57261472: ('0f1183b0000000', 'movups %xmm0,0xb0(%rbx)'),
        57261479: ('488b442420', 'mov    0x20(%rsp),%rax'),
        57261484: ('488983c0000000', 'mov    %rax,0xc0(%rbx)'),
        57261491: ('0f288424f00000', 'movaps 0xf0(%rsp),%xmm0'),
        57261499: ('0f1103', 'movups %xmm0,(%rbx)'),
        57261502: ('488b8424a80000', 'mov    0xa8(%rsp),%rax'),
        57261510: ('48894310', 'mov    %rax,0x10(%rbx)'),
        57261514: ('0f288424100100', 'movaps 0x110(%rsp),%xmm0'),
        57261522: ('0f114318', 'movups %xmm0,0x18(%rbx)'),
        57261526: ('0f288424000100', 'movaps 0x100(%rsp),%xmm0'),
        57261534: ('0f114328', 'movups %xmm0,0x28(%rbx)'),
        57261538: ('48894b38', 'mov    %rcx,0x38(%rbx)'),
        57261542: ('48895340', 'mov    %rdx,0x40(%rbx)'),
        57261546: ('4c896358', 'mov    %r12,0x58(%rbx)'),
        57261550: ('48897360', 'mov    %rsi,0x60(%rbx)'),
        57261554: ('48897b78', 'mov    %rdi,0x78(%rbx)'),
        57261558: ('4889d8', 'mov    %rbx,%rax'),
        57261561: ('4881c468010000', 'add    $0x168,%rsp'),
        57261568: ('5b', 'pop    %rbx'),
        57261569: ('415c', 'pop    %r12'),
        57261571: ('415d', 'pop    %r13'),
        57261573: ('415e', 'pop    %r14'),
        57261575: ('415f', 'pop    %r15'),
        57261577: ('5d', 'pop    %rbp'),
        57261578: ('c3', 'ret'),
        57261579: ('b003', 'mov    $0x3,%al'),
        57261581: ('eb02', 'jmp    0x369be11'),
        57261583: ('b002', 'mov    $0x2,%al'),
        57261585: ('488b5c2408', 'mov    0x8(%rsp),%rbx'),
        57261590: ('884308', 'mov    %al,0x8(%rbx)'),
        57261593: ('48c70302000000', 'movq   $0x2,(%rbx)'),
        57261600: ('488b742410', 'mov    0x10(%rsp),%rsi'),
        57261605: ('4885f6', 'test   %rsi,%rsi'),
        57261608: ('74cc', 'je     0x369bdf6'),
        57261610: ('488b7c2418', 'mov    0x18(%rsp),%rdi'),
        57261615: ('48c1e605', 'shl    $0x5,%rsi'),
        57261619: ('31d2', 'xor    %edx,%edx'),
        57261621: ('ff156536e402', 'call   *0x2e43665(%rip)'),
        57261627: ('ebb9', 'jmp    0x369bdf6'),
        57261629: ('b007', 'mov    $0x7,%al'),
        57261631: ('ebd0', 'jmp    0x369be11'),
        57261633: ('eb00', 'jmp    0x369be43'),
        57261635: ('4889c3', 'mov    %rax,%rbx'),
        57261638: ('488b742410', 'mov    0x10(%rsp),%rsi'),
        57261643: ('4885f6', 'test   %rsi,%rsi'),
        57261646: ('7411', 'je     0x369be61'),
        57261648: ('488b7c2418', 'mov    0x18(%rsp),%rdi'),
        57261653: ('48c1e605', 'shl    $0x5,%rsi'),
        57261657: ('31d2', 'xor    %edx,%edx'),
        57261659: ('ff153f36e402', 'call   *0x2e4363f(%rip)'),
        57261665: ('4889df', 'mov    %rbx,%rdi'),
        57261668: ('e8e74bd502', 'call   0x63f0a50'),
    },
    'jc1wa': {
        44601552: ('4885c9', 'test   %rcx,%rcx'),
        44601555: ('410f94c0', 'sete   %r8b'),
        44601559: ('b011', 'mov    $0x11,%al'),
        44601561: ('4484c2', 'test   %r8b,%dl'),
        44601564: ('0f8550010000', 'jne    0x2a89232'),
        44601570: ('55', 'push   %rbp'),
        44601571: ('4157', 'push   %r15'),
        44601573: ('4156', 'push   %r14'),
        44601575: ('4155', 'push   %r13'),
        44601577: ('4154', 'push   %r12'),
        44601579: ('53', 'push   %rbx'),
        44601580: ('4881eca8020000', 'sub    $0x2a8,%rsp'),
        44601587: ('488b1f', 'mov    (%rdi),%rbx'),
        44601590: ('488d8370060000', 'lea    0x670(%rbx),%rax'),
        44601597: ('448b4718', 'mov    0x18(%rdi),%r8d'),
        44601601: ('4489442464', 'mov    %r8d,0x64(%rsp)'),
        44601606: ('48893c24', 'mov    %rdi,(%rsp)'),
        44601610: ('0f104708', 'movups 0x8(%rdi),%xmm0'),
        44601614: ('0f11442454', 'movups %xmm0,0x54(%rsp)'),
        44601619: ('488b7b60', 'mov    0x60(%rbx),%rdi'),
        44601623: ('48897c2448', 'mov    %rdi,0x48(%rsp)'),
        44601628: ('8b7b68', 'mov    0x68(%rbx),%edi'),
        44601631: ('897c2450', 'mov    %edi,0x50(%rsp)'),
        44601635: ('488dbb80000000', 'lea    0x80(%rbx),%rdi'),
        44601642: ('4c8d83c8060000', 'lea    0x6c8(%rbx),%r8'),
        44601649: ('4989f6', 'mov    %rsi,%r14'),
        44601652: ('4889742438', 'mov    %rsi,0x38(%rsp)'),
        44601657: ('48c74424180300', 'movq   $0x3,0x18(%rsp)'),
        44601666: ('4989d4', 'mov    %rdx,%r12'),
        44601669: ('4889542408', 'mov    %rdx,0x8(%rsp)'),
        44601674: ('4989cd', 'mov    %rcx,%r13'),
        44601677: ('48894c2410', 'mov    %rcx,0x10(%rsp)'),
        44601682: ('48897c2428', 'mov    %rdi,0x28(%rsp)'),
        44601687: ('4c89442430', 'mov    %r8,0x30(%rsp)'),
        44601692: ('48c74424400000', 'movq   $0x0,0x40(%rsp)'),
        44601701: ('488dbc24800000', 'lea    0x80(%rsp),%rdi'),
        44601709: ('488d542408', 'lea    0x8(%rsp),%rdx'),
        44601714: ('4889c6', 'mov    %rax,%rsi'),
        44601717: ('e87691cdff', 'call   0x27622f0'),
        44601722: ('488bac24800000', 'mov    0x80(%rsp),%rbp'),
        44601730: ('0fb68424880000', 'movzbl 0x88(%rsp),%eax'),
        44601738: ('4883fd03', 'cmp    $0x3,%rbp'),
        44601742: ('0f848d000000', 'je     0x2a89221'),
        44601748: ('4189c7', 'mov    %eax,%r15d'),
        44601751: ('488db424890000', 'lea    0x89(%rsp),%rsi'),
        44601759: ('488dbc24990100', 'lea    0x199(%rsp),%rdi'),
        44601767: ('ba0f010000', 'mov    $0x10f,%edx'),
        44601772: ('ff155663a503', 'call   *0x3a56356(%rip)'),
        44601778: ('83fd02', 'cmp    $0x2,%ebp'),
        44601781: ('7468', 'je     0x2a8921f'),
        44601783: ('488dbc24890000', 'lea    0x89(%rsp),%rdi'),
        44601791: ('488db424990100', 'lea    0x199(%rsp),%rsi'),
        44601799: ('ba0f010000', 'mov    $0x10f,%edx'),
        44601804: ('ff153663a503', 'call   *0x3a56336(%rip)'),
        44601810: ('4889ac24800000', 'mov    %rbp,0x80(%rsp)'),
        44601818: ('4488bc24880000', 'mov    %r15b,0x88(%rsp)'),
        44601826: ('4c3bac24880100', 'cmp    0x188(%rsp),%r13'),
        44601834: ('0f95c0', 'setne  %al'),
        44601837: ('80bc2490010000', 'cmpb   $0x0,0x190(%rsp)'),
        44601845: ('753c', 'jne    0x2a89233'),
        44601847: ('4420e0', 'and    %r12b,%al'),
        44601850: ('7537', 'jne    0x2a89233'),
        44601852: ('488b3424', 'mov    (%rsp),%rsi'),
        44601856: ('4883c608', 'add    $0x8,%rsi'),
        44601860: ('4c8d8424800000', 'lea    0x80(%rsp),%r8'),
        44601868: ('4889df', 'mov    %rbx,%rdi'),
        44601871: ('4c89f2', 'mov    %r14,%rdx'),
        44601874: ('b903000000', 'mov    $0x3,%ecx'),
        44601879: ('4531c9', 'xor    %r9d,%r9d'),
        44601882: ('e8e1020000', 'call   0x2a89500'),
        44601887: ('b011', 'mov    $0x11,%al'),
        44601889: ('4881c4a8020000', 'add    $0x2a8,%rsp'),
        44601896: ('5b', 'pop    %rbx'),
        44601897: ('415c', 'pop    %r12'),
        44601899: ('415d', 'pop    %r13'),
        44601901: ('415e', 'pop    %r14'),
        44601903: ('415f', 'pop    %r15'),
        44601905: ('5d', 'pop    %rbp'),
        44601906: ('c3', 'ret'),
        44601907: ('488b8c24300100', 'mov    0x130(%rsp),%rcx'),
        44601915: ('4889c8', 'mov    %rcx,%rax'),
        44601918: ('48f7d8', 'neg    %rax'),
        44601921: ('714a', 'jno    0x2a8928d'),
        44601923: ('488b8c24380100', 'mov    0x138(%rsp),%rcx'),
        44601931: ('4885c9', 'test   %rcx,%rcx'),
        44601934: ('7460', 'je     0x2a892b0'),
        44601936: ('488b9424400100', 'mov    0x140(%rsp),%rdx'),
        44601944: ('488b8424480100', 'mov    0x148(%rsp),%rax'),
        44601952: ('48c74424100000', 'movq   $0x0,0x10(%rsp)'),
        44601961: ('48894c2418', 'mov    %rcx,0x18(%rsp)'),
        44601966: ('4889542420', 'mov    %rdx,0x20(%rsp)'),
        44601971: ('48c74424300000', 'movq   $0x0,0x30(%rsp)'),
        44601980: ('48894c2438', 'mov    %rcx,0x38(%rsp)'),
        44601985: ('4889542440', 'mov    %rdx,0x40(%rsp)'),
        44601990: ('b901000000', 'mov    $0x1,%ecx'),
        44601995: ('eb27', 'jmp    0x2a892b4'),
        44601997: ('b00c', 'mov    $0xc,%al'),
        44601999: ('7390', 'jae    0x2a89221'),
        44602001: ('488bbc24380100', 'mov    0x138(%rsp),%rdi'),
        44602009: ('48c1e103', 'shl    $0x3,%rcx'),
        44602013: ('488d3489', 'lea    (%rcx,%rcx,4),%rsi'),
        44602017: ('31d2', 'xor    %edx,%edx'),
        44602019: ('ff15f761a503', 'call   *0x3a561f7(%rip)'),
        44602025: ('b00c', 'mov    $0xc,%al'),
        44602027: ('e971ffffff', 'jmp    0x2a89221'),
        44602032: ('31c9', 'xor    %ecx,%ecx'),
        44602034: ('31c0', 'xor    %eax,%eax'),
        44602036: ('48894c2408', 'mov    %rcx,0x8(%rsp)'),
        44602041: ('48894c2428', 'mov    %rcx,0x28(%rsp)'),
        44602046: ('4889442448', 'mov    %rax,0x48(%rsp)'),
        44602051: ('488d5c2468', 'lea    0x68(%rsp),%rbx'),
        44602056: ('4c8d742408', 'lea    0x8(%rsp),%r14'),
        44602061: ('0f1f00', 'nopl   (%rax)'),
        44602064: ('4889df', 'mov    %rbx,%rdi'),
        44602067: ('4c89f6', 'mov    %r14,%rsi'),
        44602070: ('e8c5bc9bff', 'call   0x2444fa0'),
        44602075: ('48837c246800', 'cmpq   $0x0,0x68(%rsp)'),
        44602081: ('75ed', 'jne    0x2a892d0'),
        44602083: ('b00c', 'mov    $0xc,%al'),
        44602085: ('e937ffffff', 'jmp    0x2a89221'),
    },
    'jc1wb': {
        44602096: ('55', 'push   %rbp'),
        44602097: ('4157', 'push   %r15'),
        44602099: ('4156', 'push   %r14'),
        44602101: ('53', 'push   %rbx'),
        44602102: ('4881ece8010000', 'sub    $0x1e8,%rsp'),
        44602109: ('4889f3', 'mov    %rsi,%rbx'),
        44602112: ('4989fe', 'mov    %rdi,%r14'),
        44602115: ('4889542410', 'mov    %rdx,0x10(%rsp)'),
        44602120: ('884c240e', 'mov    %cl,0xe(%rsp)'),
        44602124: ('44884c240f', 'mov    %r9b,0xf(%rsp)'),
        44602129: ('4889b424c80100', 'mov    %rsi,0x1c8(%rsp)'),
        44602137: ('488d442410', 'lea    0x10(%rsp),%rax'),
        44602142: ('48898424d00100', 'mov    %rax,0x1d0(%rsp)'),
        44602150: ('488d44240e', 'lea    0xe(%rsp),%rax'),
        44602155: ('48898424d80100', 'mov    %rax,0x1d8(%rsp)'),
        44602163: ('488dbc24b00000', 'lea    0xb0(%rsp),%rdi'),
        44602171: ('ba18010000', 'mov    $0x118,%edx'),
        44602176: ('4c89c6', 'mov    %r8,%rsi'),
        44602179: ('ff15bf61a503', 'call   *0x3a561bf(%rip)'),
        44602185: ('488d44240f', 'lea    0xf(%rsp),%rax'),
        44602190: ('48898424e00100', 'mov    %rax,0x1e0(%rsp)'),
        44602198: ('488d7c2418', 'lea    0x18(%rsp),%rdi'),
        44602203: ('4c89f6', 'mov    %r14,%rsi'),
        44602206: ('4889da', 'mov    %rbx,%rdx'),
        44602209: ('e8fa0f0000', 'call   0x2a8a360'),
        44602214: ('48ba0000000000', 'movabs $0x8000000000000000,%rdx'),
        44602224: ('488b4c2418', 'mov    0x18(%rsp),%rcx'),
        44602229: ('488d7201', 'lea    0x1(%rdx),%rsi'),
        44602233: ('0fb6442420', 'movzbl 0x20(%rsp),%eax'),
        44602238: ('4839f1', 'cmp    %rsi,%rcx'),
        44602241: ('7564', 'jne    0x2a893e7'),
        44602243: ('488b8c24600100', 'mov    0x160(%rsp),%rcx'),
        44602251: ('4839d1', 'cmp    %rdx,%rcx'),
        44602254: ('0f85ba000000', 'jne    0x2a8944e'),
        44602260: ('488b8c24680100', 'mov    0x168(%rsp),%rcx'),
        44602268: ('89c5', 'mov    %eax,%ebp'),
        44602270: ('4885c9', 'test   %rcx,%rcx'),
        44602273: ('0f84ca000000', 'je     0x2a89471'),
        44602279: ('488b9424700100', 'mov    0x170(%rsp),%rdx'),
        44602287: ('488b8424780100', 'mov    0x178(%rsp),%rax'),
        44602295: ('48c74424200000', 'movq   $0x0,0x20(%rsp)'),
        44602304: ('48894c2428', 'mov    %rcx,0x28(%rsp)'),
        44602309: ('4889542430', 'mov    %rdx,0x30(%rsp)'),
        44602314: ('48c74424400000', 'movq   $0x0,0x40(%rsp)'),
        44602323: ('48894c2448', 'mov    %rcx,0x48(%rsp)'),
        44602328: ('4889542450', 'mov    %rdx,0x50(%rsp)'),
        44602333: ('b901000000', 'mov    $0x1,%ecx'),
        44602338: ('e98e000000', 'jmp    0x2a89475'),
        44602343: ('0f10442421', 'movups 0x21(%rsp),%xmm0'),
        44602348: ('0f104c2431', 'movups 0x31(%rsp),%xmm1'),
        44602353: ('0f10542440', 'movups 0x40(%rsp),%xmm2'),
        44602358: ('0f119424880000', 'movups %xmm2,0x88(%rsp)'),
        44602366: ('0f114c2479', 'movups %xmm1,0x79(%rsp)'),
        44602371: ('0f11442469', 'movups %xmm0,0x69(%rsp)'),
        44602376: ('4c8b7c2450', 'mov    0x50(%rsp),%r15'),
        44602381: ('48894c2460', 'mov    %rcx,0x60(%rsp)'),
        44602386: ('88442468', 'mov    %al,0x68(%rsp)'),
        44602390: ('488b542410', 'mov    0x10(%rsp),%rdx'),
        44602395: ('440fb64c240f', 'movzbl 0xf(%rsp),%r9d'),
        44602401: ('0fb64c240e', 'movzbl 0xe(%rsp),%ecx'),
        44602406: ('4c8d8424b00000', 'lea    0xb0(%rsp),%r8'),
        44602414: ('4c89f7', 'mov    %r14,%rdi'),
        44602417: ('4889de', 'mov    %rbx,%rsi'),
        44602420: ('e8c7000000', 'call   0x2a89500'),
        44602425: ('488d542460', 'lea    0x60(%rsp),%rdx'),
        44602430: ('4c89f7', 'mov    %r14,%rdi'),
        44602433: ('4889de', 'mov    %rbx,%rsi'),
        44602436: ('4c89f9', 'mov    %r15,%rcx'),
        44602439: ('e8b40b0000', 'call   0x2a8a000'),
        44602444: ('eb6a', 'jmp    0x2a894b8'),
        44602446: ('4885c9', 'test   %rcx,%rcx'),
        44602449: ('7465', 'je     0x2a894b8'),
        44602451: ('488bbc24680100', 'mov    0x168(%rsp),%rdi'),
        44602459: ('48c1e103', 'shl    $0x3,%rcx'),
        44602463: ('488d3489', 'lea    (%rcx,%rcx,4),%rsi'),
        44602467: ('31d2', 'xor    %edx,%edx'),
        44602469: ('89c3', 'mov    %eax,%ebx'),
        44602471: ('ff153360a503', 'call   *0x3a56033(%rip)'),
        44602477: ('89d8', 'mov    %ebx,%eax'),
        44602479: ('eb47', 'jmp    0x2a894b8'),
        44602481: ('31c9', 'xor    %ecx,%ecx'),
        44602483: ('31c0', 'xor    %eax,%eax'),
        44602485: ('48894c2418', 'mov    %rcx,0x18(%rsp)'),
        44602490: ('48894c2438', 'mov    %rcx,0x38(%rsp)'),
        44602495: ('4889442458', 'mov    %rax,0x58(%rsp)'),
        44602500: ('488d9c24980000', 'lea    0x98(%rsp),%rbx'),
        44602508: ('4c8d742418', 'lea    0x18(%rsp),%r14'),
        44602513: ('6666666666662e', 'data16 data16 data16 data16 data16 cs nopw 0x0(%rax,%rax,1)'),
        44602528: ('4889df', 'mov    %rbx,%rdi'),
        44602531: ('4c89f6', 'mov    %r14,%rsi'),
        44602534: ('e8f5ba9bff', 'call   0x2444fa0'),
        44602539: ('4883bc24980000', 'cmpq   $0x0,0x98(%rsp)'),
        44602548: ('75ea', 'jne    0x2a894a0'),
        44602550: ('89e8', 'mov    %ebp,%eax'),
        44602552: ('4881c4e8010000', 'add    $0x1e8,%rsp'),
        44602559: ('5b', 'pop    %rbx'),
        44602560: ('415e', 'pop    %r14'),
        44602562: ('415f', 'pop    %r15'),
        44602564: ('5d', 'pop    %rbp'),
        44602565: ('c3', 'ret'),
        44602566: ('4889c3', 'mov    %rax,%rbx'),
        44602569: ('488d7c2460', 'lea    0x60(%rsp),%rdi'),
        44602574: ('e80dca0200', 'call   0x2ab5ee0'),
        44602579: ('eb10', 'jmp    0x2a894e5'),
        44602581: ('4889c3', 'mov    %rax,%rbx'),
        44602584: ('488dbc24b00000', 'lea    0xb0(%rsp),%rdi'),
        44602592: ('e80bc20100', 'call   0x2aa56f0'),
        44602597: ('4889df', 'mov    %rbx,%rdi'),
        44602600: ('e863759603', 'call   0x63f0a50'),
        44602605: ('ff15cd5fa503', 'call   *0x3a55fcd(%rip)'),
    },
    'jc2wa': {
        89784736: ('4885c9', 'test   %rcx,%rcx'),
        89784739: ('410f94c0', 'sete   %r8b'),
        89784743: ('b011', 'mov    $0x11,%al'),
        89784745: ('4484c2', 'test   %r8b,%dl'),
        89784748: ('0f8550010000', 'jne    0x55a0302'),
        89784754: ('55', 'push   %rbp'),
        89784755: ('4157', 'push   %r15'),
        89784757: ('4156', 'push   %r14'),
        89784759: ('4155', 'push   %r13'),
        89784761: ('4154', 'push   %r12'),
        89784763: ('53', 'push   %rbx'),
        89784764: ('4881eca8020000', 'sub    $0x2a8,%rsp'),
        89784771: ('488b1f', 'mov    (%rdi),%rbx'),
        89784774: ('488d8370060000', 'lea    0x670(%rbx),%rax'),
        89784781: ('448b4718', 'mov    0x18(%rdi),%r8d'),
        89784785: ('4489442464', 'mov    %r8d,0x64(%rsp)'),
        89784790: ('48893c24', 'mov    %rdi,(%rsp)'),
        89784794: ('0f104708', 'movups 0x8(%rdi),%xmm0'),
        89784798: ('0f11442454', 'movups %xmm0,0x54(%rsp)'),
        89784803: ('488b7b60', 'mov    0x60(%rbx),%rdi'),
        89784807: ('48897c2448', 'mov    %rdi,0x48(%rsp)'),
        89784812: ('8b7b68', 'mov    0x68(%rbx),%edi'),
        89784815: ('897c2450', 'mov    %edi,0x50(%rsp)'),
        89784819: ('488dbb80000000', 'lea    0x80(%rbx),%rdi'),
        89784826: ('4c8d83c8060000', 'lea    0x6c8(%rbx),%r8'),
        89784833: ('4989f6', 'mov    %rsi,%r14'),
        89784836: ('4889742438', 'mov    %rsi,0x38(%rsp)'),
        89784841: ('48c74424180300', 'movq   $0x3,0x18(%rsp)'),
        89784850: ('4989d4', 'mov    %rdx,%r12'),
        89784853: ('4889542408', 'mov    %rdx,0x8(%rsp)'),
        89784858: ('4989cd', 'mov    %rcx,%r13'),
        89784861: ('48894c2410', 'mov    %rcx,0x10(%rsp)'),
        89784866: ('48897c2428', 'mov    %rdi,0x28(%rsp)'),
        89784871: ('4c89442430', 'mov    %r8,0x30(%rsp)'),
        89784876: ('48c74424400000', 'movq   $0x0,0x40(%rsp)'),
        89784885: ('488dbc24800000', 'lea    0x80(%rsp),%rdi'),
        89784893: ('488d542408', 'lea    0x8(%rsp),%rdx'),
        89784898: ('4889c6', 'mov    %rax,%rsi'),
        89784901: ('e8460fefff', 'call   0x5491190'),
        89784906: ('488bac24800000', 'mov    0x80(%rsp),%rbp'),
        89784914: ('0fb68424880000', 'movzbl 0x88(%rsp),%eax'),
        89784922: ('4883fd03', 'cmp    $0x3,%rbp'),
        89784926: ('0f848d000000', 'je     0x55a02f1'),
        89784932: ('4189c7', 'mov    %eax,%r15d'),
        89784935: ('488db424890000', 'lea    0x89(%rsp),%rsi'),
        89784943: ('488dbc24990100', 'lea    0x199(%rsp),%rdi'),
        89784951: ('ba0f010000', 'mov    $0x10f,%edx'),
        89784956: ('ff1586f2f300', 'call   *0xf3f286(%rip)'),
        89784962: ('83fd02', 'cmp    $0x2,%ebp'),
        89784965: ('7468', 'je     0x55a02ef'),
        89784967: ('488dbc24890000', 'lea    0x89(%rsp),%rdi'),
        89784975: ('488db424990100', 'lea    0x199(%rsp),%rsi'),
        89784983: ('ba0f010000', 'mov    $0x10f,%edx'),
        89784988: ('ff1566f2f300', 'call   *0xf3f266(%rip)'),
        89784994: ('4889ac24800000', 'mov    %rbp,0x80(%rsp)'),
        89785002: ('4488bc24880000', 'mov    %r15b,0x88(%rsp)'),
        89785010: ('4c3bac24880100', 'cmp    0x188(%rsp),%r13'),
        89785018: ('0f95c0', 'setne  %al'),
        89785021: ('80bc2490010000', 'cmpb   $0x0,0x190(%rsp)'),
        89785029: ('753c', 'jne    0x55a0303'),
        89785031: ('4420e0', 'and    %r12b,%al'),
        89785034: ('7537', 'jne    0x55a0303'),
        89785036: ('488b3424', 'mov    (%rsp),%rsi'),
        89785040: ('4883c608', 'add    $0x8,%rsi'),
        89785044: ('4c8d8424800000', 'lea    0x80(%rsp),%r8'),
        89785052: ('4889df', 'mov    %rbx,%rdi'),
        89785055: ('4c89f2', 'mov    %r14,%rdx'),
        89785058: ('b903000000', 'mov    $0x3,%ecx'),
        89785063: ('4531c9', 'xor    %r9d,%r9d'),
        89785066: ('e8f1040000', 'call   0x55a07e0'),
        89785071: ('b011', 'mov    $0x11,%al'),
        89785073: ('4881c4a8020000', 'add    $0x2a8,%rsp'),
        89785080: ('5b', 'pop    %rbx'),
        89785081: ('415c', 'pop    %r12'),
        89785083: ('415d', 'pop    %r13'),
        89785085: ('415e', 'pop    %r14'),
        89785087: ('415f', 'pop    %r15'),
        89785089: ('5d', 'pop    %rbp'),
        89785090: ('c3', 'ret'),
        89785091: ('488b8c24300100', 'mov    0x130(%rsp),%rcx'),
        89785099: ('4889c8', 'mov    %rcx,%rax'),
        89785102: ('48f7d8', 'neg    %rax'),
        89785105: ('714a', 'jno    0x55a035d'),
        89785107: ('488b8c24380100', 'mov    0x138(%rsp),%rcx'),
        89785115: ('4885c9', 'test   %rcx,%rcx'),
        89785118: ('7460', 'je     0x55a0380'),
        89785120: ('488b9424400100', 'mov    0x140(%rsp),%rdx'),
        89785128: ('488b8424480100', 'mov    0x148(%rsp),%rax'),
        89785136: ('48c74424100000', 'movq   $0x0,0x10(%rsp)'),
        89785145: ('48894c2418', 'mov    %rcx,0x18(%rsp)'),
        89785150: ('4889542420', 'mov    %rdx,0x20(%rsp)'),
        89785155: ('48c74424300000', 'movq   $0x0,0x30(%rsp)'),
        89785164: ('48894c2438', 'mov    %rcx,0x38(%rsp)'),
        89785169: ('4889542440', 'mov    %rdx,0x40(%rsp)'),
        89785174: ('b901000000', 'mov    $0x1,%ecx'),
        89785179: ('eb27', 'jmp    0x55a0384'),
        89785181: ('b00c', 'mov    $0xc,%al'),
        89785183: ('7390', 'jae    0x55a02f1'),
        89785185: ('488bbc24380100', 'mov    0x138(%rsp),%rdi'),
        89785193: ('48c1e103', 'shl    $0x3,%rcx'),
        89785197: ('488d3489', 'lea    (%rcx,%rcx,4),%rsi'),
        89785201: ('31d2', 'xor    %edx,%edx'),
        89785203: ('ff1527f1f300', 'call   *0xf3f127(%rip)'),
        89785209: ('b00c', 'mov    $0xc,%al'),
        89785211: ('e971ffffff', 'jmp    0x55a02f1'),
        89785216: ('31c9', 'xor    %ecx,%ecx'),
        89785218: ('31c0', 'xor    %eax,%eax'),
        89785220: ('48894c2408', 'mov    %rcx,0x8(%rsp)'),
        89785225: ('48894c2428', 'mov    %rcx,0x28(%rsp)'),
        89785230: ('4889442448', 'mov    %rax,0x48(%rsp)'),
        89785235: ('488d5c2468', 'lea    0x68(%rsp),%rbx'),
        89785240: ('4c8d742408', 'lea    0x8(%rsp),%r14'),
        89785245: ('0f1f00', 'nopl   (%rax)'),
        89785248: ('4889df', 'mov    %rbx,%rdi'),
        89785251: ('4c89f6', 'mov    %r14,%rsi'),
        89785254: ('e82503c4ff', 'call   0x51e06d0'),
        89785259: ('48837c246800', 'cmpq   $0x0,0x68(%rsp)'),
        89785265: ('75ed', 'jne    0x55a03a0'),
        89785267: ('b00c', 'mov    $0xc,%al'),
        89785269: ('e937ffffff', 'jmp    0x55a02f1'),
    },
    'jc2wb': {
        89785280: ('55', 'push   %rbp'),
        89785281: ('4157', 'push   %r15'),
        89785283: ('4156', 'push   %r14'),
        89785285: ('53', 'push   %rbx'),
        89785286: ('4881ece8010000', 'sub    $0x1e8,%rsp'),
        89785293: ('4889f3', 'mov    %rsi,%rbx'),
        89785296: ('4989fe', 'mov    %rdi,%r14'),
        89785299: ('4889542410', 'mov    %rdx,0x10(%rsp)'),
        89785304: ('884c240e', 'mov    %cl,0xe(%rsp)'),
        89785308: ('44884c240f', 'mov    %r9b,0xf(%rsp)'),
        89785313: ('4889b424c80100', 'mov    %rsi,0x1c8(%rsp)'),
        89785321: ('488d442410', 'lea    0x10(%rsp),%rax'),
        89785326: ('48898424d00100', 'mov    %rax,0x1d0(%rsp)'),
        89785334: ('488d44240e', 'lea    0xe(%rsp),%rax'),
        89785339: ('48898424d80100', 'mov    %rax,0x1d8(%rsp)'),
        89785347: ('488dbc24b00000', 'lea    0xb0(%rsp),%rdi'),
        89785355: ('ba18010000', 'mov    $0x118,%edx'),
        89785360: ('4c89c6', 'mov    %r8,%rsi'),
        89785363: ('ff15eff0f300', 'call   *0xf3f0ef(%rip)'),
        89785369: ('488d44240f', 'lea    0xf(%rsp),%rax'),
        89785374: ('48898424e00100', 'mov    %rax,0x1e0(%rsp)'),
        89785382: ('488d7c2418', 'lea    0x18(%rsp),%rdi'),
        89785387: ('4c89f6', 'mov    %r14,%rsi'),
        89785390: ('4889da', 'mov    %rbx,%rdx'),
        89785393: ('e81a210000', 'call   0x55a2550'),
        89785398: ('48ba0000000000', 'movabs $0x8000000000000000,%rdx'),
        89785408: ('488b4c2418', 'mov    0x18(%rsp),%rcx'),
        89785413: ('488d7201', 'lea    0x1(%rdx),%rsi'),
        89785417: ('0fb6442420', 'movzbl 0x20(%rsp),%eax'),
        89785422: ('4839f1', 'cmp    %rsi,%rcx'),
        89785425: ('7564', 'jne    0x55a04b7'),
        89785427: ('488b8c24600100', 'mov    0x160(%rsp),%rcx'),
        89785435: ('4839d1', 'cmp    %rdx,%rcx'),
        89785438: ('0f85ba000000', 'jne    0x55a051e'),
        89785444: ('488b8c24680100', 'mov    0x168(%rsp),%rcx'),
        89785452: ('89c5', 'mov    %eax,%ebp'),
        89785454: ('4885c9', 'test   %rcx,%rcx'),
        89785457: ('0f84ca000000', 'je     0x55a0541'),
        89785463: ('488b9424700100', 'mov    0x170(%rsp),%rdx'),
        89785471: ('488b8424780100', 'mov    0x178(%rsp),%rax'),
        89785479: ('48c74424200000', 'movq   $0x0,0x20(%rsp)'),
        89785488: ('48894c2428', 'mov    %rcx,0x28(%rsp)'),
        89785493: ('4889542430', 'mov    %rdx,0x30(%rsp)'),
        89785498: ('48c74424400000', 'movq   $0x0,0x40(%rsp)'),
        89785507: ('48894c2448', 'mov    %rcx,0x48(%rsp)'),
        89785512: ('4889542450', 'mov    %rdx,0x50(%rsp)'),
        89785517: ('b901000000', 'mov    $0x1,%ecx'),
        89785522: ('e98e000000', 'jmp    0x55a0545'),
        89785527: ('0f10442421', 'movups 0x21(%rsp),%xmm0'),
        89785532: ('0f104c2431', 'movups 0x31(%rsp),%xmm1'),
        89785537: ('0f10542440', 'movups 0x40(%rsp),%xmm2'),
        89785542: ('0f119424880000', 'movups %xmm2,0x88(%rsp)'),
        89785550: ('0f114c2479', 'movups %xmm1,0x79(%rsp)'),
        89785555: ('0f11442469', 'movups %xmm0,0x69(%rsp)'),
        89785560: ('4c8b7c2450', 'mov    0x50(%rsp),%r15'),
        89785565: ('48894c2460', 'mov    %rcx,0x60(%rsp)'),
        89785570: ('88442468', 'mov    %al,0x68(%rsp)'),
        89785574: ('488b542410', 'mov    0x10(%rsp),%rdx'),
        89785579: ('440fb64c240f', 'movzbl 0xf(%rsp),%r9d'),
        89785585: ('0fb64c240e', 'movzbl 0xe(%rsp),%ecx'),
        89785590: ('4c8d8424b00000', 'lea    0xb0(%rsp),%r8'),
        89785598: ('4c89f7', 'mov    %r14,%rdi'),
        89785601: ('4889de', 'mov    %rbx,%rsi'),
        89785604: ('e8d7020000', 'call   0x55a07e0'),
        89785609: ('488d542460', 'lea    0x60(%rsp),%rdx'),
        89785614: ('4c89f7', 'mov    %r14,%rdi'),
        89785617: ('4889de', 'mov    %rbx,%rsi'),
        89785620: ('4c89f9', 'mov    %r15,%rcx'),
        89785623: ('e8341b0000', 'call   0x55a2050'),
        89785628: ('eb6a', 'jmp    0x55a0588'),
        89785630: ('4885c9', 'test   %rcx,%rcx'),
        89785633: ('7465', 'je     0x55a0588'),
        89785635: ('488bbc24680100', 'mov    0x168(%rsp),%rdi'),
        89785643: ('48c1e103', 'shl    $0x3,%rcx'),
        89785647: ('488d3489', 'lea    (%rcx,%rcx,4),%rsi'),
        89785651: ('31d2', 'xor    %edx,%edx'),
        89785653: ('89c3', 'mov    %eax,%ebx'),
        89785655: ('ff1563eff300', 'call   *0xf3ef63(%rip)'),
        89785661: ('89d8', 'mov    %ebx,%eax'),
        89785663: ('eb47', 'jmp    0x55a0588'),
        89785665: ('31c9', 'xor    %ecx,%ecx'),
        89785667: ('31c0', 'xor    %eax,%eax'),
        89785669: ('48894c2418', 'mov    %rcx,0x18(%rsp)'),
        89785674: ('48894c2438', 'mov    %rcx,0x38(%rsp)'),
        89785679: ('4889442458', 'mov    %rax,0x58(%rsp)'),
        89785684: ('488d9c24980000', 'lea    0x98(%rsp),%rbx'),
        89785692: ('4c8d742418', 'lea    0x18(%rsp),%r14'),
        89785697: ('6666666666662e', 'data16 data16 data16 data16 data16 cs nopw 0x0(%rax,%rax,1)'),
        89785712: ('4889df', 'mov    %rbx,%rdi'),
        89785715: ('4c89f6', 'mov    %r14,%rsi'),
        89785718: ('e85501c4ff', 'call   0x51e06d0'),
        89785723: ('4883bc24980000', 'cmpq   $0x0,0x98(%rsp)'),
        89785732: ('75ea', 'jne    0x55a0570'),
        89785734: ('89e8', 'mov    %ebp,%eax'),
        89785736: ('4881c4e8010000', 'add    $0x1e8,%rsp'),
        89785743: ('5b', 'pop    %rbx'),
        89785744: ('415e', 'pop    %r14'),
        89785746: ('415f', 'pop    %r15'),
        89785748: ('5d', 'pop    %rbp'),
        89785749: ('c3', 'ret'),
        89785750: ('4889c3', 'mov    %rax,%rbx'),
        89785753: ('488d7c2460', 'lea    0x60(%rsp),%rdi'),
        89785758: ('e80d680900', 'call   0x5636db0'),
        89785763: ('eb10', 'jmp    0x55a05b5'),
        89785765: ('4889c3', 'mov    %rax,%rbx'),
        89785768: ('488dbc24b00000', 'lea    0xb0(%rsp),%rdi'),
        89785776: ('e80ba10800', 'call   0x562a6c0'),
        89785781: ('4889df', 'mov    %rbx,%rdi'),
        89785784: ('e89304e500', 'call   0x63f0a50'),
        89785789: ('ff15fdeef300', 'call   *0xf3eefd(%rip)'),
    },
    'jc3wa': {
        89784192: ('4885c9', 'test   %rcx,%rcx'),
        89784195: ('410f94c0', 'sete   %r8b'),
        89784199: ('b011', 'mov    $0x11,%al'),
        89784201: ('4484c2', 'test   %r8b,%dl'),
        89784204: ('0f8550010000', 'jne    0x55a00e2'),
        89784210: ('55', 'push   %rbp'),
        89784211: ('4157', 'push   %r15'),
        89784213: ('4156', 'push   %r14'),
        89784215: ('4155', 'push   %r13'),
        89784217: ('4154', 'push   %r12'),
        89784219: ('53', 'push   %rbx'),
        89784220: ('4881eca8020000', 'sub    $0x2a8,%rsp'),
        89784227: ('488b1f', 'mov    (%rdi),%rbx'),
        89784230: ('488d8370060000', 'lea    0x670(%rbx),%rax'),
        89784237: ('448b4718', 'mov    0x18(%rdi),%r8d'),
        89784241: ('4489442464', 'mov    %r8d,0x64(%rsp)'),
        89784246: ('48893c24', 'mov    %rdi,(%rsp)'),
        89784250: ('0f104708', 'movups 0x8(%rdi),%xmm0'),
        89784254: ('0f11442454', 'movups %xmm0,0x54(%rsp)'),
        89784259: ('488b7b60', 'mov    0x60(%rbx),%rdi'),
        89784263: ('48897c2448', 'mov    %rdi,0x48(%rsp)'),
        89784268: ('8b7b68', 'mov    0x68(%rbx),%edi'),
        89784271: ('897c2450', 'mov    %edi,0x50(%rsp)'),
        89784275: ('488dbb80000000', 'lea    0x80(%rbx),%rdi'),
        89784282: ('4c8d83c8060000', 'lea    0x6c8(%rbx),%r8'),
        89784289: ('4989f6', 'mov    %rsi,%r14'),
        89784292: ('4889742438', 'mov    %rsi,0x38(%rsp)'),
        89784297: ('48c74424180300', 'movq   $0x3,0x18(%rsp)'),
        89784306: ('4989d4', 'mov    %rdx,%r12'),
        89784309: ('4889542408', 'mov    %rdx,0x8(%rsp)'),
        89784314: ('4989cd', 'mov    %rcx,%r13'),
        89784317: ('48894c2410', 'mov    %rcx,0x10(%rsp)'),
        89784322: ('48897c2428', 'mov    %rdi,0x28(%rsp)'),
        89784327: ('4c89442430', 'mov    %r8,0x30(%rsp)'),
        89784332: ('48c74424400000', 'movq   $0x0,0x40(%rsp)'),
        89784341: ('488dbc24800000', 'lea    0x80(%rsp),%rdi'),
        89784349: ('488d542408', 'lea    0x8(%rsp),%rdx'),
        89784354: ('4889c6', 'mov    %rax,%rsi'),
        89784357: ('e86611efff', 'call   0x5491190'),
        89784362: ('488bac24800000', 'mov    0x80(%rsp),%rbp'),
        89784370: ('0fb68424880000', 'movzbl 0x88(%rsp),%eax'),
        89784378: ('4883fd03', 'cmp    $0x3,%rbp'),
        89784382: ('0f848d000000', 'je     0x55a00d1'),
        89784388: ('4189c7', 'mov    %eax,%r15d'),
        89784391: ('488db424890000', 'lea    0x89(%rsp),%rsi'),
        89784399: ('488dbc24990100', 'lea    0x199(%rsp),%rdi'),
        89784407: ('ba0f010000', 'mov    $0x10f,%edx'),
        89784412: ('ff15a6f4f300', 'call   *0xf3f4a6(%rip)'),
        89784418: ('83fd02', 'cmp    $0x2,%ebp'),
        89784421: ('7468', 'je     0x55a00cf'),
        89784423: ('488dbc24890000', 'lea    0x89(%rsp),%rdi'),
        89784431: ('488db424990100', 'lea    0x199(%rsp),%rsi'),
        89784439: ('ba0f010000', 'mov    $0x10f,%edx'),
        89784444: ('ff1586f4f300', 'call   *0xf3f486(%rip)'),
        89784450: ('4889ac24800000', 'mov    %rbp,0x80(%rsp)'),
        89784458: ('4488bc24880000', 'mov    %r15b,0x88(%rsp)'),
        89784466: ('4c3bac24880100', 'cmp    0x188(%rsp),%r13'),
        89784474: ('0f95c0', 'setne  %al'),
        89784477: ('80bc2490010000', 'cmpb   $0x0,0x190(%rsp)'),
        89784485: ('753c', 'jne    0x55a00e3'),
        89784487: ('4420e0', 'and    %r12b,%al'),
        89784490: ('7537', 'jne    0x55a00e3'),
        89784492: ('488b3424', 'mov    (%rsp),%rsi'),
        89784496: ('4883c608', 'add    $0x8,%rsi'),
        89784500: ('4c8d8424800000', 'lea    0x80(%rsp),%r8'),
        89784508: ('4889df', 'mov    %rbx,%rdi'),
        89784511: ('4c89f2', 'mov    %r14,%rdx'),
        89784514: ('b903000000', 'mov    $0x3,%ecx'),
        89784519: ('4531c9', 'xor    %r9d,%r9d'),
        89784522: ('e811120000', 'call   0x55a12e0'),
        89784527: ('b011', 'mov    $0x11,%al'),
        89784529: ('4881c4a8020000', 'add    $0x2a8,%rsp'),
        89784536: ('5b', 'pop    %rbx'),
        89784537: ('415c', 'pop    %r12'),
        89784539: ('415d', 'pop    %r13'),
        89784541: ('415e', 'pop    %r14'),
        89784543: ('415f', 'pop    %r15'),
        89784545: ('5d', 'pop    %rbp'),
        89784546: ('c3', 'ret'),
        89784547: ('488b8c24300100', 'mov    0x130(%rsp),%rcx'),
        89784555: ('4889c8', 'mov    %rcx,%rax'),
        89784558: ('48f7d8', 'neg    %rax'),
        89784561: ('714a', 'jno    0x55a013d'),
        89784563: ('488b8c24380100', 'mov    0x138(%rsp),%rcx'),
        89784571: ('4885c9', 'test   %rcx,%rcx'),
        89784574: ('7460', 'je     0x55a0160'),
        89784576: ('488b9424400100', 'mov    0x140(%rsp),%rdx'),
        89784584: ('488b8424480100', 'mov    0x148(%rsp),%rax'),
        89784592: ('48c74424100000', 'movq   $0x0,0x10(%rsp)'),
        89784601: ('48894c2418', 'mov    %rcx,0x18(%rsp)'),
        89784606: ('4889542420', 'mov    %rdx,0x20(%rsp)'),
        89784611: ('48c74424300000', 'movq   $0x0,0x30(%rsp)'),
        89784620: ('48894c2438', 'mov    %rcx,0x38(%rsp)'),
        89784625: ('4889542440', 'mov    %rdx,0x40(%rsp)'),
        89784630: ('b901000000', 'mov    $0x1,%ecx'),
        89784635: ('eb27', 'jmp    0x55a0164'),
        89784637: ('b00c', 'mov    $0xc,%al'),
        89784639: ('7390', 'jae    0x55a00d1'),
        89784641: ('488bbc24380100', 'mov    0x138(%rsp),%rdi'),
        89784649: ('48c1e103', 'shl    $0x3,%rcx'),
        89784653: ('488d3489', 'lea    (%rcx,%rcx,4),%rsi'),
        89784657: ('31d2', 'xor    %edx,%edx'),
        89784659: ('ff1547f3f300', 'call   *0xf3f347(%rip)'),
        89784665: ('b00c', 'mov    $0xc,%al'),
        89784667: ('e971ffffff', 'jmp    0x55a00d1'),
        89784672: ('31c9', 'xor    %ecx,%ecx'),
        89784674: ('31c0', 'xor    %eax,%eax'),
        89784676: ('48894c2408', 'mov    %rcx,0x8(%rsp)'),
        89784681: ('48894c2428', 'mov    %rcx,0x28(%rsp)'),
        89784686: ('4889442448', 'mov    %rax,0x48(%rsp)'),
        89784691: ('488d5c2468', 'lea    0x68(%rsp),%rbx'),
        89784696: ('4c8d742408', 'lea    0x8(%rsp),%r14'),
        89784701: ('0f1f00', 'nopl   (%rax)'),
        89784704: ('4889df', 'mov    %rbx,%rdi'),
        89784707: ('4c89f6', 'mov    %r14,%rsi'),
        89784710: ('e84505c4ff', 'call   0x51e06d0'),
        89784715: ('48837c246800', 'cmpq   $0x0,0x68(%rsp)'),
        89784721: ('75ed', 'jne    0x55a0180'),
        89784723: ('b00c', 'mov    $0xc,%al'),
        89784725: ('e937ffffff', 'jmp    0x55a00d1'),
    },
    'jc3wb': {
        89785808: ('55', 'push   %rbp'),
        89785809: ('4157', 'push   %r15'),
        89785811: ('4156', 'push   %r14'),
        89785813: ('53', 'push   %rbx'),
        89785814: ('4881ece8010000', 'sub    $0x1e8,%rsp'),
        89785821: ('4889f3', 'mov    %rsi,%rbx'),
        89785824: ('4989fe', 'mov    %rdi,%r14'),
        89785827: ('4889542410', 'mov    %rdx,0x10(%rsp)'),
        89785832: ('884c240e', 'mov    %cl,0xe(%rsp)'),
        89785836: ('44884c240f', 'mov    %r9b,0xf(%rsp)'),
        89785841: ('4889b424c80100', 'mov    %rsi,0x1c8(%rsp)'),
        89785849: ('488d442410', 'lea    0x10(%rsp),%rax'),
        89785854: ('48898424d00100', 'mov    %rax,0x1d0(%rsp)'),
        89785862: ('488d44240e', 'lea    0xe(%rsp),%rax'),
        89785867: ('48898424d80100', 'mov    %rax,0x1d8(%rsp)'),
        89785875: ('488dbc24b00000', 'lea    0xb0(%rsp),%rdi'),
        89785883: ('ba18010000', 'mov    $0x118,%edx'),
        89785888: ('4c89c6', 'mov    %r8,%rsi'),
        89785891: ('ff15dfeef300', 'call   *0xf3eedf(%rip)'),
        89785897: ('488d44240f', 'lea    0xf(%rsp),%rax'),
        89785902: ('48898424e00100', 'mov    %rax,0x1e0(%rsp)'),
        89785910: ('488d7c2418', 'lea    0x18(%rsp),%rdi'),
        89785915: ('4c89f6', 'mov    %r14,%rsi'),
        89785918: ('4889da', 'mov    %rbx,%rdx'),
        89785921: ('e87a1c0000', 'call   0x55a22c0'),
        89785926: ('48ba0000000000', 'movabs $0x8000000000000000,%rdx'),
        89785936: ('488b4c2418', 'mov    0x18(%rsp),%rcx'),
        89785941: ('488d7201', 'lea    0x1(%rdx),%rsi'),
        89785945: ('0fb6442420', 'movzbl 0x20(%rsp),%eax'),
        89785950: ('4839f1', 'cmp    %rsi,%rcx'),
        89785953: ('7564', 'jne    0x55a06c7'),
        89785955: ('488b8c24600100', 'mov    0x160(%rsp),%rcx'),
        89785963: ('4839d1', 'cmp    %rdx,%rcx'),
        89785966: ('0f85ba000000', 'jne    0x55a072e'),
        89785972: ('488b8c24680100', 'mov    0x168(%rsp),%rcx'),
        89785980: ('89c5', 'mov    %eax,%ebp'),
        89785982: ('4885c9', 'test   %rcx,%rcx'),
        89785985: ('0f84ca000000', 'je     0x55a0751'),
        89785991: ('488b9424700100', 'mov    0x170(%rsp),%rdx'),
        89785999: ('488b8424780100', 'mov    0x178(%rsp),%rax'),
        89786007: ('48c74424200000', 'movq   $0x0,0x20(%rsp)'),
        89786016: ('48894c2428', 'mov    %rcx,0x28(%rsp)'),
        89786021: ('4889542430', 'mov    %rdx,0x30(%rsp)'),
        89786026: ('48c74424400000', 'movq   $0x0,0x40(%rsp)'),
        89786035: ('48894c2448', 'mov    %rcx,0x48(%rsp)'),
        89786040: ('4889542450', 'mov    %rdx,0x50(%rsp)'),
        89786045: ('b901000000', 'mov    $0x1,%ecx'),
        89786050: ('e98e000000', 'jmp    0x55a0755'),
        89786055: ('0f10442421', 'movups 0x21(%rsp),%xmm0'),
        89786060: ('0f104c2431', 'movups 0x31(%rsp),%xmm1'),
        89786065: ('0f10542440', 'movups 0x40(%rsp),%xmm2'),
        89786070: ('0f119424880000', 'movups %xmm2,0x88(%rsp)'),
        89786078: ('0f114c2479', 'movups %xmm1,0x79(%rsp)'),
        89786083: ('0f11442469', 'movups %xmm0,0x69(%rsp)'),
        89786088: ('4c8b7c2450', 'mov    0x50(%rsp),%r15'),
        89786093: ('48894c2460', 'mov    %rcx,0x60(%rsp)'),
        89786098: ('88442468', 'mov    %al,0x68(%rsp)'),
        89786102: ('488b542410', 'mov    0x10(%rsp),%rdx'),
        89786107: ('440fb64c240f', 'movzbl 0xf(%rsp),%r9d'),
        89786113: ('0fb64c240e', 'movzbl 0xe(%rsp),%ecx'),
        89786118: ('4c8d8424b00000', 'lea    0xb0(%rsp),%r8'),
        89786126: ('4c89f7', 'mov    %r14,%rdi'),
        89786129: ('4889de', 'mov    %rbx,%rsi'),
        89786132: ('e8c70b0000', 'call   0x55a12e0'),
        89786137: ('488d542460', 'lea    0x60(%rsp),%rdx'),
        89786142: ('4c89f7', 'mov    %r14,%rdi'),
        89786145: ('4889de', 'mov    %rbx,%rsi'),
        89786148: ('4c89f9', 'mov    %r15,%rcx'),
        89786151: ('e8b4160000', 'call   0x55a1de0'),
        89786156: ('eb6a', 'jmp    0x55a0798'),
        89786158: ('4885c9', 'test   %rcx,%rcx'),
        89786161: ('7465', 'je     0x55a0798'),
        89786163: ('488bbc24680100', 'mov    0x168(%rsp),%rdi'),
        89786171: ('48c1e103', 'shl    $0x3,%rcx'),
        89786175: ('488d3489', 'lea    (%rcx,%rcx,4),%rsi'),
        89786179: ('31d2', 'xor    %edx,%edx'),
        89786181: ('89c3', 'mov    %eax,%ebx'),
        89786183: ('ff1553edf300', 'call   *0xf3ed53(%rip)'),
        89786189: ('89d8', 'mov    %ebx,%eax'),
        89786191: ('eb47', 'jmp    0x55a0798'),
        89786193: ('31c9', 'xor    %ecx,%ecx'),
        89786195: ('31c0', 'xor    %eax,%eax'),
        89786197: ('48894c2418', 'mov    %rcx,0x18(%rsp)'),
        89786202: ('48894c2438', 'mov    %rcx,0x38(%rsp)'),
        89786207: ('4889442458', 'mov    %rax,0x58(%rsp)'),
        89786212: ('488d9c24980000', 'lea    0x98(%rsp),%rbx'),
        89786220: ('4c8d742418', 'lea    0x18(%rsp),%r14'),
        89786225: ('6666666666662e', 'data16 data16 data16 data16 data16 cs nopw 0x0(%rax,%rax,1)'),
        89786240: ('4889df', 'mov    %rbx,%rdi'),
        89786243: ('4c89f6', 'mov    %r14,%rsi'),
        89786246: ('e845ffc3ff', 'call   0x51e06d0'),
        89786251: ('4883bc24980000', 'cmpq   $0x0,0x98(%rsp)'),
        89786260: ('75ea', 'jne    0x55a0780'),
        89786262: ('89e8', 'mov    %ebp,%eax'),
        89786264: ('4881c4e8010000', 'add    $0x1e8,%rsp'),
        89786271: ('5b', 'pop    %rbx'),
        89786272: ('415e', 'pop    %r14'),
        89786274: ('415f', 'pop    %r15'),
        89786276: ('5d', 'pop    %rbp'),
        89786277: ('c3', 'ret'),
        89786278: ('4889c3', 'mov    %rax,%rbx'),
        89786281: ('488d7c2460', 'lea    0x60(%rsp),%rdi'),
        89786286: ('e8fd650900', 'call   0x5636db0'),
        89786291: ('eb10', 'jmp    0x55a07c5'),
        89786293: ('4889c3', 'mov    %rax,%rbx'),
        89786296: ('488dbc24b00000', 'lea    0xb0(%rsp),%rdi'),
        89786304: ('e8fb9e0800', 'call   0x562a6c0'),
        89786309: ('4889df', 'mov    %rbx,%rdi'),
        89786312: ('e88302e500', 'call   0x63f0a50'),
        89786317: ('ff15edecf300', 'call   *0xf3eced(%rip)'),
    },
    'pred_a': {
        57254416: ('55', 'push   %rbp'),
        57254417: ('4157', 'push   %r15'),
        57254419: ('4156', 'push   %r14'),
        57254421: ('4155', 'push   %r13'),
        57254423: ('4154', 'push   %r12'),
        57254425: ('53', 'push   %rbx'),
        57254426: ('4883ec28', 'sub    $0x28,%rsp'),
        57254430: ('4889f3', 'mov    %rsi,%rbx'),
        57254433: ('4989fe', 'mov    %rdi,%r14'),
        57254436: ('4c8ba788000000', 'mov    0x88(%rdi),%r12'),
        57254443: ('4c89e0', 'mov    %r12,%rax'),
        57254446: ('48f7d8', 'neg    %rax'),
        57254449: ('0f81c2000000', 'jno    0x369a2f9'),
        57254455: ('498b8690000000', 'mov    0x90(%r14),%rax'),
        57254462: ('4885c0', 'test   %rax,%rax'),
        57254465: ('0f8407010000', 'je     0x369a34e'),
        57254471: ('498b8e98000000', 'mov    0x98(%r14),%rcx'),
        57254478: ('48890c24', 'mov    %rcx,(%rsp)'),
        57254482: ('4c8b2df758e402', 'mov    0x2e458f7(%rip),%r13'),
        57254489: ('488db070020000', 'lea    0x270(%rax),%rsi'),
        57254496: ('0fb7884e030000', 'movzwl 0x34e(%rax),%ecx'),
        57254503: ('4889442410', 'mov    %rax,0x10(%rsp)'),
        57254508: ('4c8d78d0', 'lea    -0x30(%rax),%r15'),
        57254512: ('48894c2408', 'mov    %rcx,0x8(%rsp)'),
        57254517: ('8d048d00000000', 'lea    0x0(,%rcx,4),%eax'),
        57254524: ('4c8d3480', 'lea    (%rax,%rax,4),%r14'),
        57254528: ('48c7c5ffffffff', 'mov    $0xffffffffffffffff,%rbp'),
        57254535: ('660f1f84000000', 'nopw   0x0(%rax,%rax,1)'),
        57254544: ('4d85f6', 'test   %r14,%r14'),
        57254547: ('743b', 'je     0x369a2d0'),
        57254549: ('4c8d6614', 'lea    0x14(%rsi),%r12'),
        57254553: ('ba14000000', 'mov    $0x14,%edx'),
        57254558: ('4889df', 'mov    %rbx,%rdi'),
        57254561: ('41ffd5', 'call   *%r13'),
        57254564: ('4898', 'cltq'),
        57254566: ('4885c0', 'test   %rax,%rax'),
        57254569: ('0f98c1', 'sets   %cl'),
        57254572: ('0f9fc0', 'setg   %al'),
        57254575: ('28c8', 'sub    %cl,%al'),
        57254577: ('4983c738', 'add    $0x38,%r15'),
        57254581: ('48ffc5', 'inc    %rbp'),
        57254584: ('4983c6ec', 'add    $0xffffffffffffffec,%r14'),
        57254588: ('4c89e6', 'mov    %r12,%rsi'),
        57254591: ('3c01', 'cmp    $0x1,%al'),
        57254593: ('74cd', 'je     0x369a290'),
        57254595: ('0fb6c0', 'movzbl %al,%eax'),
        57254598: ('85c0', 'test   %eax,%eax'),
        57254600: ('0f8483000000', 'je     0x369a351'),
        57254606: ('eb05', 'jmp    0x369a2d5'),
        57254608: ('488b6c2408', 'mov    0x8(%rsp),%rbp'),
        57254613: ('488b0424', 'mov    (%rsp),%rax'),
        57254617: ('4883e801', 'sub    $0x1,%rax'),
        57254621: ('0f8295000000', 'jb     0x369a378'),
        57254627: ('48890424', 'mov    %rax,(%rsp)'),
        57254631: ('488b442410', 'mov    0x10(%rsp),%rax'),
        57254636: ('488b84e8500300', 'mov    0x350(%rax,%rbp,8),%rax'),
        57254644: ('e960ffffff', 'jmp    0x369a259'),
        57254649: ('498dbe88000000', 'lea    0x88(%r14),%rdi'),
        57254656: ('4889de', 'mov    %rbx,%rsi'),
        57254659: ('e848afeb00', 'call   0x4555250'),
        57254664: ('4531ff', 'xor    %r15d,%r15d'),
        57254667: ('a801', 'test   $0x1,%al'),
        57254669: ('7542', 'jne    0x369a351'),
        57254671: ('493b96a0000000', 'cmp    0xa0(%r14),%rdx'),
        57254678: ('7339', 'jae    0x369a351'),
        57254680: ('49039698000000', 'add    0x98(%r14),%rdx'),
        57254687: ('31c0', 'xor    %eax,%eax'),
        57254689: ('4c39e2', 'cmp    %r12,%rdx'),
        57254692: ('490f43c4', 'cmovae %r12,%rax'),
        57254696: ('4829c2', 'sub    %rax,%rdx'),
        57254699: ('498b8690000000', 'mov    0x90(%r14),%rax'),
        57254706: ('488d0c92', 'lea    (%rdx,%rdx,4),%rcx'),
        57254710: ('48c1e104', 'shl    $0x4,%rcx'),
        57254714: ('4c8d3c08', 'lea    (%rax,%rcx,1),%r15'),
        57254718: ('4983c718', 'add    $0x18,%r15'),
        57254722: ('8b05a015e602', 'mov    0x2e615a0(%rip),%eax'),
        57254728: ('85c0', 'test   %eax,%eax'),
        57254730: ('740f', 'je     0x369a35b'),
        57254732: ('eb37', 'jmp    0x369a385'),
        57254734: ('4531ff', 'xor    %r15d,%r15d'),
        57254737: ('8b059115e602', 'mov    0x2e61591(%rip),%eax'),
        57254743: ('85c0', 'test   %eax,%eax'),
        57254745: ('752a', 'jne    0x369a385'),
        57254747: ('4d85ff', 'test   %r15,%r15'),
        57254750: ('488d054b15e602', 'lea    0x2e6154b(%rip),%rax'),
        57254757: ('490f45c7', 'cmovne %r15,%rax'),
        57254761: ('4883c428', 'add    $0x28,%rsp'),
        57254765: ('5b', 'pop    %rbx'),
        57254766: ('415c', 'pop    %r12'),
        57254768: ('415d', 'pop    %r13'),
        57254770: ('415e', 'pop    %r14'),
        57254772: ('415f', 'pop    %r15'),
        57254774: ('5d', 'pop    %rbp'),
        57254775: ('c3', 'ret'),
        57254776: ('4531ff', 'xor    %r15d,%r15d'),
        57254779: ('8b056715e602', 'mov    0x2e61567(%rip),%eax'),
        57254785: ('85c0', 'test   %eax,%eax'),
        57254787: ('74d6', 'je     0x369a35b'),
        57254789: ('488d052415e602', 'lea    0x2e61524(%rip),%rax'),
        57254796: ('4889442418', 'mov    %rax,0x18(%rsp)'),
        57254801: ('488d442418', 'lea    0x18(%rsp),%rax'),
        57254806: ('4889442420', 'mov    %rax,0x20(%rsp)'),
        57254811: ('488d3d4615e602', 'lea    0x2e61546(%rip),%rdi'),
        57254818: ('488d0d3fe9dc02', 'lea    0x2dce93f(%rip),%rcx'),
        57254825: ('4c8d0560e9dc02', 'lea    0x2dce960(%rip),%r8'),
        57254832: ('488d542420', 'lea    0x20(%rsp),%rdx'),
        57254837: ('be01000000', 'mov    $0x1,%esi'),
        57254842: ('ff153056e402', 'call   *0x2e45630(%rip)'),
        57254848: ('eb99', 'jmp    0x369a35b'),
    },
    'pred_b': {
        62869408: ('4157', 'push   %r15'),
        62869410: ('4156', 'push   %r14'),
        62869412: ('4154', 'push   %r12'),
        62869414: ('53', 'push   %rbx'),
        62869415: ('4883ec18', 'sub    $0x18,%rsp'),
        62869419: ('4889cb', 'mov    %rcx,%rbx'),
        62869422: ('4989d6', 'mov    %rdx,%r14'),
        62869425: ('4881c770030000', 'add    $0x370,%rdi'),
        62869432: ('e8031db200', 'call   0x4716cc0'),
        62869437: ('8b0de5899002', 'mov    0x29089e5(%rip),%ecx'),
        62869443: ('85c9', 'test   %ecx,%ecx'),
        62869445: ('0f8505010000', 'jne    0x3bf50d0'),
        62869451: ('4885c0', 'test   %rax,%rax'),
        62869454: ('4c8d3d83899002', 'lea    0x2908983(%rip),%r15'),
        62869461: ('4c0f45f8', 'cmovne %rax,%r15'),
        62869465: ('4c89742408', 'mov    %r14,0x8(%rsp)'),
        62869470: ('4d8b27', 'mov    (%r15),%r12'),
        62869473: ('4c89e0', 'mov    %r12,%rax'),
        62869476: ('48f7d8', 'neg    %rax'),
        62869479: ('717a', 'jno    0x3bf5063'),
        62869481: ('498b4708', 'mov    0x8(%r15),%rax'),
        62869485: ('4885c0', 'test   %rax,%rax'),
        62869488: ('0f84bc000000', 'je     0x3bf50b2'),
        62869494: ('498b5710', 'mov    0x10(%r15),%rdx'),
        62869498: ('31c9', 'xor    %ecx,%ecx'),
        62869500: ('0fb7b86a010000', 'movzwl 0x16a(%rax),%edi'),
        62869507: ('8d34fd00000000', 'lea    0x0(,%rdi,8),%esi'),
        62869514: ('4c8d0c76', 'lea    (%rsi,%rsi,2),%r9'),
        62869518: ('48c7c6ffffffff', 'mov    $0xffffffffffffffff,%rsi'),
        62869525: ('4531c0', 'xor    %r8d,%r8d'),
        62869528: ('0f1f8400000000', 'nopl   0x0(%rax,%rax,1)'),
        62869536: ('4d89ca', 'mov    %r9,%r10'),
        62869539: ('4d01c2', 'add    %r8,%r10'),
        62869542: ('7428', 'je     0x3bf5050'),
        62869544: ('4c3b74f010', 'cmp    0x10(%rax,%rsi,8),%r14'),
        62869549: ('410f97c2', 'seta   %r10b'),
        62869553: ('4180da00', 'sbb    $0x0,%r10b'),
        62869557: ('4983c0e8', 'add    $0xffffffffffffffe8,%r8'),
        62869561: ('48ffc6', 'inc    %rsi'),
        62869564: ('4180fa01', 'cmp    $0x1,%r10b'),
        62869568: ('74de', 'je     0x3bf5020'),
        62869570: ('410fb6fa', 'movzbl %r10b,%edi'),
        62869574: ('85ff', 'test   %edi,%edi'),
        62869576: ('7509', 'jne    0x3bf5053'),
        62869578: ('eb56', 'jmp    0x3bf50a2'),
        62869580: ('0f1f4000', 'nopl   0x0(%rax)'),
        62869584: ('4889fe', 'mov    %rdi,%rsi'),
        62869587: ('4883ea01', 'sub    $0x1,%rdx'),
        62869591: ('725b', 'jb     0x3bf50b4'),
        62869593: ('488b84f0700100', 'mov    0x170(%rax,%rsi,8),%rax'),
        62869601: ('eb99', 'jmp    0x3bf4ffc'),
        62869603: ('488d742408', 'lea    0x8(%rsp),%rsi'),
        62869608: ('4c89ff', 'mov    %r15,%rdi'),
        62869611: ('e840349600', 'call   0x45584b0'),
        62869616: ('31c9', 'xor    %ecx,%ecx'),
        62869618: ('a801', 'test   $0x1,%al'),
        62869620: ('753e', 'jne    0x3bf50b4'),
        62869622: ('be00000000', 'mov    $0x0,%esi'),
        62869627: ('493b5718', 'cmp    0x18(%r15),%rdx'),
        62869631: ('7335', 'jae    0x3bf50b6'),
        62869633: ('49035710', 'add    0x10(%r15),%rdx'),
        62869637: ('31c0', 'xor    %eax,%eax'),
        62869639: ('4c39e2', 'cmp    %r12,%rdx'),
        62869642: ('490f43c4', 'cmovae %r12,%rax'),
        62869646: ('4829c2', 'sub    %rax,%rdx'),
        62869649: ('498b4708', 'mov    0x8(%r15),%rax'),
        62869653: ('48c1e205', 'shl    $0x5,%rdx'),
        62869657: ('4801d0', 'add    %rdx,%rax'),
        62869660: ('4883c008', 'add    $0x8,%rax'),
        62869664: ('eb07', 'jmp    0x3bf50a9'),
        62869666: ('4c29c0', 'sub    %r8,%rax'),
        62869669: ('4883c048', 'add    $0x48,%rax'),
        62869673: ('488b08', 'mov    (%rax),%rcx'),
        62869676: ('488b7008', 'mov    0x8(%rax),%rsi'),
        62869680: ('eb04', 'jmp    0x3bf50b6'),
        62869682: ('31c9', 'xor    %ecx,%ecx'),
        62869684: ('31f6', 'xor    %esi,%esi'),
        62869686: ('4801f3', 'add    %rsi,%rbx'),
        62869689: ('4839cb', 'cmp    %rcx,%rbx'),
        62869692: ('0f96c0', 'setbe  %al'),
        62869695: ('4839f3', 'cmp    %rsi,%rbx'),
        62869698: ('7252', 'jb     0x3bf5116'),
        62869700: ('4883c418', 'add    $0x18,%rsp'),
        62869704: ('5b', 'pop    %rbx'),
        62869705: ('415c', 'pop    %r12'),
        62869707: ('415e', 'pop    %r14'),
        62869709: ('415f', 'pop    %r15'),
        62869711: ('c3', 'ret'),
        62869712: ('488d0d81889002', 'lea    0x2908881(%rip),%rcx'),
        62869719: ('48894c2410', 'mov    %rcx,0x10(%rsp)'),
        62869724: ('488d4c2410', 'lea    0x10(%rsp),%rcx'),
        62869729: ('48894c2408', 'mov    %rcx,0x8(%rsp)'),
        62869734: ('488d3dbb889002', 'lea    0x29088bb(%rip),%rdi'),
        62869741: ('488d0d2c1a8802', 'lea    0x2881a2c(%rip),%rcx'),
        62869748: ('4c8d054d1a8802', 'lea    0x2881a4d(%rip),%r8'),
        62869755: ('488d542408', 'lea    0x8(%rsp),%rdx'),
        62869760: ('be01000000', 'mov    $0x1,%esi'),
        62869765: ('4989c7', 'mov    %rax,%r15'),
        62869768: ('ff15e2a88e02', 'call   *0x28ea8e2(%rip)'),
        62869774: ('4c89f8', 'mov    %r15,%rax'),
        62869777: ('e9b5feffff', 'jmp    0x3bf4fcb'),
        62869782: ('31c0', 'xor    %eax,%eax'),
        62869784: ('ebaa', 'jmp    0x3bf50c4'),
    },
    's2c_a': {
        41294912: ('55', 'push   %rbp'),
        41294913: ('4157', 'push   %r15'),
        41294915: ('4156', 'push   %r14'),
        41294917: ('4154', 'push   %r12'),
        41294919: ('53', 'push   %rbx'),
        41294920: ('4881ec90010000', 'sub    $0x190,%rsp'),
        41294927: ('89d5', 'mov    %edx,%ebp'),
        41294929: ('4889f3', 'mov    %rsi,%rbx'),
        41294932: ('4989fe', 'mov    %rdi,%r14'),
        41294935: ('4889e7', 'mov    %rsp,%rdi'),
        41294938: ('4c89f6', 'mov    %r14,%rsi'),
        41294941: ('4889da', 'mov    %rbx,%rdx'),
        41294944: ('89e9', 'mov    %ebp,%ecx'),
        41294946: ('ff151848d803', 'call   *0x3d84818(%rip)'),
        41294952: ('4c8b2424', 'mov    (%rsp),%r12'),
        41294956: ('440fb67c2408', 'movzbl 0x8(%rsp),%r15d'),
        41294962: ('4983fc02', 'cmp    $0x2,%r12'),
        41294966: ('7443', 'je     0x2761cbb'),
        41294968: ('488d742409', 'lea    0x9(%rsp),%rsi'),
        41294973: ('488dbc24d10000', 'lea    0xd1(%rsp),%rdi'),
        41294981: ('babf000000', 'mov    $0xbf,%edx'),
        41294986: ('ff1578d8d703', 'call   *0x3d7d878(%rip)'),
        41294992: ('4c89a424c80000', 'mov    %r12,0xc8(%rsp)'),
        41295000: ('4488bc24d00000', 'mov    %r15b,0xd0(%rsp)'),
        41295008: ('400fb6d5', 'movzbl %bpl,%edx'),
        41295012: ('488d8c24c80000', 'lea    0xc8(%rsp),%rcx'),
        41295020: ('4c89f7', 'mov    %r14,%rdi'),
        41295023: ('4889de', 'mov    %rbx,%rsi'),
        41295026: ('ff15d047d803', 'call   *0x3d847d0(%rip)'),
        41295032: ('41b711', 'mov    $0x11,%r15b'),
        41295035: ('4489f8', 'mov    %r15d,%eax'),
        41295038: ('4881c490010000', 'add    $0x190,%rsp'),
        41295045: ('5b', 'pop    %rbx'),
        41295046: ('415c', 'pop    %r12'),
        41295048: ('415e', 'pop    %r14'),
        41295050: ('415f', 'pop    %r15'),
        41295052: ('5d', 'pop    %rbp'),
        41295053: ('c3', 'ret'),
    },
    's2c_b': {
        88671552: ('55', 'push   %rbp'),
        88671553: ('4157', 'push   %r15'),
        88671555: ('4156', 'push   %r14'),
        88671557: ('4154', 'push   %r12'),
        88671559: ('53', 'push   %rbx'),
        88671560: ('4881ec90010000', 'sub    $0x190,%rsp'),
        88671567: ('89d5', 'mov    %edx,%ebp'),
        88671569: ('4889f3', 'mov    %rsi,%rbx'),
        88671572: ('4989fe', 'mov    %rdi,%r14'),
        88671575: ('4889e7', 'mov    %rsp,%rdi'),
        88671578: ('4c89f6', 'mov    %r14,%rsi'),
        88671581: ('4889da', 'mov    %rbx,%rdx'),
        88671584: ('89e9', 'mov    %ebp,%ecx'),
        88671586: ('ff15185f0501', 'call   *0x1055f18(%rip)'),
        88671592: ('4c8b2424', 'mov    (%rsp),%r12'),
        88671596: ('440fb67c2408', 'movzbl 0x8(%rsp),%r15d'),
        88671602: ('4983fc02', 'cmp    $0x2,%r12'),
        88671606: ('7443', 'je     0x54905bb'),
        88671608: ('488d742409', 'lea    0x9(%rsp),%rsi'),
        88671613: ('488dbc24d10000', 'lea    0xd1(%rsp),%rdi'),
        88671621: ('babf000000', 'mov    $0xbf,%edx'),
        88671626: ('ff1578ef0401', 'call   *0x104ef78(%rip)'),
        88671632: ('4c89a424c80000', 'mov    %r12,0xc8(%rsp)'),
        88671640: ('4488bc24d00000', 'mov    %r15b,0xd0(%rsp)'),
        88671648: ('400fb6d5', 'movzbl %bpl,%edx'),
        88671652: ('488d8c24c80000', 'lea    0xc8(%rsp),%rcx'),
        88671660: ('4c89f7', 'mov    %r14,%rdi'),
        88671663: ('4889de', 'mov    %rbx,%rsi'),
        88671666: ('ff15d05e0501', 'call   *0x1055ed0(%rip)'),
        88671672: ('41b711', 'mov    $0x11,%r15b'),
        88671675: ('4489f8', 'mov    %r15d,%eax'),
        88671678: ('4881c490010000', 'add    $0x190,%rsp'),
        88671685: ('5b', 'pop    %rbx'),
        88671686: ('415c', 'pop    %r12'),
        88671688: ('415e', 'pop    %r14'),
        88671690: ('415f', 'pop    %r15'),
        88671692: ('5d', 'pop    %rbp'),
        88671693: ('c3', 'ret'),
    },
    's2c_c': {
        88671696: ('55', 'push   %rbp'),
        88671697: ('4157', 'push   %r15'),
        88671699: ('4156', 'push   %r14'),
        88671701: ('4154', 'push   %r12'),
        88671703: ('53', 'push   %rbx'),
        88671704: ('4881ec90010000', 'sub    $0x190,%rsp'),
        88671711: ('89d5', 'mov    %edx,%ebp'),
        88671713: ('4889f3', 'mov    %rsi,%rbx'),
        88671716: ('4989fe', 'mov    %rdi,%r14'),
        88671719: ('4889e7', 'mov    %rsp,%rdi'),
        88671722: ('4c89f6', 'mov    %r14,%rsi'),
        88671725: ('4889da', 'mov    %rbx,%rdx'),
        88671728: ('89e9', 'mov    %ebp,%ecx'),
        88671730: ('ff15885e0501', 'call   *0x1055e88(%rip)'),
        88671736: ('4c8b2424', 'mov    (%rsp),%r12'),
        88671740: ('440fb67c2408', 'movzbl 0x8(%rsp),%r15d'),
        88671746: ('4983fc02', 'cmp    $0x2,%r12'),
        88671750: ('7443', 'je     0x549064b'),
        88671752: ('488d742409', 'lea    0x9(%rsp),%rsi'),
        88671757: ('488dbc24d10000', 'lea    0xd1(%rsp),%rdi'),
        88671765: ('babf000000', 'mov    $0xbf,%edx'),
        88671770: ('ff15e8ee0401', 'call   *0x104eee8(%rip)'),
        88671776: ('4c89a424c80000', 'mov    %r12,0xc8(%rsp)'),
        88671784: ('4488bc24d00000', 'mov    %r15b,0xd0(%rsp)'),
        88671792: ('400fb6d5', 'movzbl %bpl,%edx'),
        88671796: ('488d8c24c80000', 'lea    0xc8(%rsp),%rcx'),
        88671804: ('4c89f7', 'mov    %r14,%rdi'),
        88671807: ('4889de', 'mov    %rbx,%rsi'),
        88671810: ('ff15405e0501', 'call   *0x1055e40(%rip)'),
        88671816: ('41b711', 'mov    $0x11,%r15b'),
        88671819: ('4489f8', 'mov    %r15d,%eax'),
        88671822: ('4881c490010000', 'add    $0x190,%rsp'),
        88671829: ('5b', 'pop    %rbx'),
        88671830: ('415c', 'pop    %r12'),
        88671832: ('415e', 'pop    %r14'),
        88671834: ('415f', 'pop    %r15'),
        88671836: ('5d', 'pop    %rbp'),
        88671837: ('c3', 'ret'),
    },
    's3c_a': {
        46537136: ('55', 'push   %rbp'),
        46537137: ('4157', 'push   %r15'),
        46537139: ('4156', 'push   %r14'),
        46537141: ('4155', 'push   %r13'),
        46537143: ('4154', 'push   %r12'),
        46537145: ('53', 'push   %rbx'),
        46537146: ('4881ec38030000', 'sub    $0x338,%rsp'),
        46537153: ('4d89cc', 'mov    %r9,%r12'),
        46537156: ('4489c5', 'mov    %r8d,%ebp'),
        46537159: ('4889cb', 'mov    %rcx,%rbx'),
        46537162: ('4989d5', 'mov    %rdx,%r13'),
        46537165: ('4989f7', 'mov    %rsi,%r15'),
        46537168: ('4889fe', 'mov    %rdi,%rsi'),
        46537171: ('4c8bb424700300', 'mov    0x370(%rsp),%r14'),
        46537179: ('418b4710', 'mov    0x10(%r15),%eax'),
        46537183: ('89442438', 'mov    %eax,0x38(%rsp)'),
        46537187: ('410f1007', 'movups (%r15),%xmm0'),
        46537191: ('0f11442428', 'movups %xmm0,0x28(%rsp)'),
        46537196: ('4889542420', 'mov    %rdx,0x20(%rsp)'),
        46537201: ('48c70424020000', 'movq   $0x2,(%rsp)'),
        46537209: ('48894c2408', 'mov    %rcx,0x8(%rsp)'),
        46537214: ('40886c243c', 'mov    %bpl,0x3c(%rsp)'),
        46537219: ('4c894c2410', 'mov    %r9,0x10(%rsp)'),
        46537224: ('4c89742418', 'mov    %r14,0x18(%rsp)'),
        46537229: ('488d7c2450', 'lea    0x50(%rsp),%rdi'),
        46537234: ('4889e2', 'mov    %rsp,%rdx'),
        46537237: ('4889742448', 'mov    %rsi,0x48(%rsp)'),
        46537242: ('e8010e0000', 'call   0x2c62820'),
        46537247: ('837c245003', 'cmpl   $0x3,0x50(%rsp)'),
        46537252: ('0f84e4000000', 'je     0x2c61b0e'),
        46537258: ('488dbc24480100', 'lea    0x148(%rsp),%rdi'),
        46537266: ('488d742450', 'lea    0x50(%rsp),%rsi'),
        46537271: ('baf8000000', 'mov    $0xf8,%edx'),
        46537276: ('ff15c6da8703', 'call   *0x387dac6(%rip)'),
        46537282: ('488dbc24480100', 'lea    0x148(%rsp),%rdi'),
        46537290: ('4c89642440', 'mov    %r12,0x40(%rsp)'),
        46537295: ('4c89e6', 'mov    %r12,%rsi'),
        46537298: ('4c89f2', 'mov    %r14,%rdx'),
        46537301: ('ff1505648803', 'call   *0x3886405(%rip)'),
        46537307: ('4839c3', 'cmp    %rax,%rbx'),
        46537310: ('7316', 'jae    0x2c61a76'),
        46537312: ('488d35115a8203', 'lea    0x3825a11(%rip),%rsi'),
        46537319: ('31db', 'xor    %ebx,%ebx'),
        46537321: ('31ff', 'xor    %edi,%edi'),
        46537323: ('ff1537348803', 'call   *0x3883437(%rip)'),
        46537329: ('e998000000', 'jmp    0x2c61b0e'),
        46537334: ('4829c3', 'sub    %rax,%rbx'),
        46537337: ('0f848d000000', 'je     0x2c61b0c'),
        46537343: ('418b4710', 'mov    0x10(%r15),%eax'),
        46537347: ('89442438', 'mov    %eax,0x38(%rsp)'),
        46537351: ('410f1007', 'movups (%r15),%xmm0'),
        46537355: ('0f11442428', 'movups %xmm0,0x28(%rsp)'),
        46537360: ('4c896c2420', 'mov    %r13,0x20(%rsp)'),
        46537365: ('48c70424010000', 'movq   $0x1,(%rsp)'),
        46537373: ('48895c2408', 'mov    %rbx,0x8(%rsp)'),
        46537378: ('40886c243c', 'mov    %bpl,0x3c(%rsp)'),
        46537383: ('4c8b642440', 'mov    0x40(%rsp),%r12'),
        46537388: ('4c89642410', 'mov    %r12,0x10(%rsp)'),
        46537393: ('4c8bb424700300', 'mov    0x370(%rsp),%r14'),
        46537401: ('4c89742418', 'mov    %r14,0x18(%rsp)'),
        46537406: ('488d7c2450', 'lea    0x50(%rsp),%rdi'),
        46537411: ('4889e2', 'mov    %rsp,%rdx'),
        46537414: ('488b742448', 'mov    0x48(%rsp),%rsi'),
        46537419: ('e8500d0000', 'call   0x2c62820'),
        46537424: ('837c245003', 'cmpl   $0x3,0x50(%rsp)'),
        46537429: ('7437', 'je     0x2c61b0e'),
        46537431: ('4c8dbc24400200', 'lea    0x240(%rsp),%r15'),
        46537439: ('488d742450', 'lea    0x50(%rsp),%rsi'),
        46537444: ('baf8000000', 'mov    $0xf8,%edx'),
        46537449: ('4c89ff', 'mov    %r15,%rdi'),
        46537452: ('ff1516da8703', 'call   *0x387da16(%rip)'),
        46537458: ('4c89ff', 'mov    %r15,%rdi'),
        46537461: ('4c89e6', 'mov    %r12,%rsi'),
        46537464: ('4c89f2', 'mov    %r14,%rdx'),
        46537467: ('ff155f638803', 'call   *0x388635f(%rip)'),
        46537473: ('4829c3', 'sub    %rax,%rbx'),
        46537476: ('0f8256ffffff', 'jb     0x2c61a60'),
        46537482: ('eb02', 'jmp    0x2c61b0e'),
        46537484: ('31db', 'xor    %ebx,%ebx'),
        46537486: ('4889d8', 'mov    %rbx,%rax'),
        46537489: ('4881c438030000', 'add    $0x338,%rsp'),
        46537496: ('5b', 'pop    %rbx'),
        46537497: ('415c', 'pop    %r12'),
        46537499: ('415d', 'pop    %r13'),
        46537501: ('415e', 'pop    %r14'),
        46537503: ('415f', 'pop    %r15'),
        46537505: ('5d', 'pop    %rbp'),
        46537506: ('c3', 'ret'),
    },
    's3c_b': {
        90041264: ('55', 'push   %rbp'),
        90041265: ('4157', 'push   %r15'),
        90041267: ('4156', 'push   %r14'),
        90041269: ('4155', 'push   %r13'),
        90041271: ('4154', 'push   %r12'),
        90041273: ('53', 'push   %rbx'),
        90041274: ('4881ec38030000', 'sub    $0x338,%rsp'),
        90041281: ('4d89cc', 'mov    %r9,%r12'),
        90041284: ('4489c5', 'mov    %r8d,%ebp'),
        90041287: ('4889cb', 'mov    %rcx,%rbx'),
        90041290: ('4989d5', 'mov    %rdx,%r13'),
        90041293: ('4989f7', 'mov    %rsi,%r15'),
        90041296: ('4889fe', 'mov    %rdi,%rsi'),
        90041299: ('4c8bb424700300', 'mov    0x370(%rsp),%r14'),
        90041307: ('418b4710', 'mov    0x10(%r15),%eax'),
        90041311: ('89442438', 'mov    %eax,0x38(%rsp)'),
        90041315: ('410f1007', 'movups (%r15),%xmm0'),
        90041319: ('0f11442428', 'movups %xmm0,0x28(%rsp)'),
        90041324: ('4889542420', 'mov    %rdx,0x20(%rsp)'),
        90041329: ('48c70424020000', 'movq   $0x2,(%rsp)'),
        90041337: ('48894c2408', 'mov    %rcx,0x8(%rsp)'),
        90041342: ('40886c243c', 'mov    %bpl,0x3c(%rsp)'),
        90041347: ('4c894c2410', 'mov    %r9,0x10(%rsp)'),
        90041352: ('4c89742418', 'mov    %r14,0x18(%rsp)'),
        90041357: ('488d7c2450', 'lea    0x50(%rsp),%rdi'),
        90041362: ('4889e2', 'mov    %rsp,%rdx'),
        90041365: ('4889742448', 'mov    %rsi,0x48(%rsp)'),
        90041370: ('e8b12a0000', 'call   0x55e16d0'),
        90041375: ('837c245003', 'cmpl   $0x3,0x50(%rsp)'),
        90041380: ('0f84e4000000', 'je     0x55ded0e'),
        90041386: ('488dbc24480100', 'lea    0x148(%rsp),%rdi'),
        90041394: ('488d742450', 'lea    0x50(%rsp),%rsi'),
        90041399: ('baf8000000', 'mov    $0xf8,%edx'),
        90041404: ('ff15c608f000', 'call   *0xf008c6(%rip)'),
        90041410: ('488dbc24480100', 'lea    0x148(%rsp),%rdi'),
        90041418: ('4c89642440', 'mov    %r12,0x40(%rsp)'),
        90041423: ('4c89e6', 'mov    %r12,%rsi'),
        90041426: ('4c89f2', 'mov    %r14,%rdx'),
        90041429: ('ff150592f000', 'call   *0xf09205(%rip)'),
        90041435: ('4839c3', 'cmp    %rax,%rbx'),
        90041438: ('7316', 'jae    0x55dec76'),
        90041440: ('488d351188ea00', 'lea    0xea8811(%rip),%rsi'),
        90041447: ('31db', 'xor    %ebx,%ebx'),
        90041449: ('31ff', 'xor    %edi,%edi'),
        90041451: ('ff153762f000', 'call   *0xf06237(%rip)'),
        90041457: ('e998000000', 'jmp    0x55ded0e'),
        90041462: ('4829c3', 'sub    %rax,%rbx'),
        90041465: ('0f848d000000', 'je     0x55ded0c'),
        90041471: ('418b4710', 'mov    0x10(%r15),%eax'),
        90041475: ('89442438', 'mov    %eax,0x38(%rsp)'),
        90041479: ('410f1007', 'movups (%r15),%xmm0'),
        90041483: ('0f11442428', 'movups %xmm0,0x28(%rsp)'),
        90041488: ('4c896c2420', 'mov    %r13,0x20(%rsp)'),
        90041493: ('48c70424010000', 'movq   $0x1,(%rsp)'),
        90041501: ('48895c2408', 'mov    %rbx,0x8(%rsp)'),
        90041506: ('40886c243c', 'mov    %bpl,0x3c(%rsp)'),
        90041511: ('4c8b642440', 'mov    0x40(%rsp),%r12'),
        90041516: ('4c89642410', 'mov    %r12,0x10(%rsp)'),
        90041521: ('4c8bb424700300', 'mov    0x370(%rsp),%r14'),
        90041529: ('4c89742418', 'mov    %r14,0x18(%rsp)'),
        90041534: ('488d7c2450', 'lea    0x50(%rsp),%rdi'),
        90041539: ('4889e2', 'mov    %rsp,%rdx'),
        90041542: ('488b742448', 'mov    0x48(%rsp),%rsi'),
        90041547: ('e8002a0000', 'call   0x55e16d0'),
        90041552: ('837c245003', 'cmpl   $0x3,0x50(%rsp)'),
        90041557: ('7437', 'je     0x55ded0e'),
        90041559: ('4c8dbc24400200', 'lea    0x240(%rsp),%r15'),
        90041567: ('488d742450', 'lea    0x50(%rsp),%rsi'),
        90041572: ('baf8000000', 'mov    $0xf8,%edx'),
        90041577: ('4c89ff', 'mov    %r15,%rdi'),
        90041580: ('ff151608f000', 'call   *0xf00816(%rip)'),
        90041586: ('4c89ff', 'mov    %r15,%rdi'),
        90041589: ('4c89e6', 'mov    %r12,%rsi'),
        90041592: ('4c89f2', 'mov    %r14,%rdx'),
        90041595: ('ff155f91f000', 'call   *0xf0915f(%rip)'),
        90041601: ('4829c3', 'sub    %rax,%rbx'),
        90041604: ('0f8256ffffff', 'jb     0x55dec60'),
        90041610: ('eb02', 'jmp    0x55ded0e'),
        90041612: ('31db', 'xor    %ebx,%ebx'),
        90041614: ('4889d8', 'mov    %rbx,%rax'),
        90041617: ('4881c438030000', 'add    $0x338,%rsp'),
        90041624: ('5b', 'pop    %rbx'),
        90041625: ('415c', 'pop    %r12'),
        90041627: ('415d', 'pop    %r13'),
        90041629: ('415e', 'pop    %r14'),
        90041631: ('415f', 'pop    %r15'),
        90041633: ('5d', 'pop    %rbp'),
        90041634: ('c3', 'ret'),
    },
}

PINNED_ROWS_PARTIAL = {
    'big1': {
        46549236: ('488b4c2418', 'mov    0x18(%rsp),%rcx'),
        46549241: ('488b9938130000', 'mov    0x1338(%rcx),%rbx'),
        46549248: ('4869c010050000', 'imul   $0x510,%rax,%rax'),
        46549255: ('4889442428', 'mov    %rax,0x28(%rsp)'),
        46549260: ('807c241400', 'cmpb   $0x0,0x14(%rsp)'),
        46549265: ('740d', 'je     0x2c64920'),
        46549267: ('4531ed', 'xor    %r13d,%r13d'),
        46549270: ('e974010000', 'jmp    0x2c64a8f'),
        46549275: ('0f1f440000', 'nopl   0x0(%rax,%rax,1)'),
        46549280: ('4c8b6350', 'mov    0x50(%rbx),%r12'),
        46549284: ('4c8b6b58', 'mov    0x58(%rbx),%r13'),
        46549288: ('488b4c2420', 'mov    0x20(%rsp),%rcx'),
        46549293: ('8b4110', 'mov    0x10(%rcx),%eax'),
        46549296: ('89842450010000', 'mov    %eax,0x150(%rsp)'),
        46549303: ('0f1001', 'movups (%rcx),%xmm0'),
        46549306: ('0f298424400100', 'movaps %xmm0,0x140(%rsp)'),
        46549314: ('0fb68b09050000', 'movzbl 0x509(%rbx),%ecx'),
        46549321: ('4889df', 'mov    %rbx,%rdi'),
        46549324: ('488db424400100', 'lea    0x140(%rsp),%rsi'),
        46549600: ('0f298c24500100', 'movaps %xmm1,0x150(%rsp)'),
        46549608: ('0f298424400100', 'movaps %xmm0,0x140(%rsp)'),
        46549616: ('488dbc24400100', 'lea    0x140(%rsp),%rdi'),
        46549624: ('e883040300', 'call   0x2c94f00'),
        46549629: ('4981c510050000', 'add    $0x510,%r13'),
        46549636: ('4c396c2428', 'cmp    %r13,0x28(%rsp)'),
        46549641: ('0f84ed000000', 'je     0x2c64b7c'),
        46549647: ('4e8b642b50', 'mov    0x50(%rbx,%r13,1),%r12'),
        46549652: ('4e8b7c2b58', 'mov    0x58(%rbx,%r13,1),%r15'),
        46549657: ('488b4c2420', 'mov    0x20(%rsp),%rcx'),
        46549662: ('8b4110', 'mov    0x10(%rcx),%eax'),
        46549665: ('89842450010000', 'mov    %eax,0x150(%rsp)'),
        46549672: ('0f1001', 'movups (%rcx),%xmm0'),
        46549675: ('0f298424400100', 'movaps %xmm0,0x140(%rsp)'),
        46549683: ('41b802000000', 'mov    $0x2,%r8d'),
        46549689: ('488dbc24f00200', 'lea    0x2f0(%rsp),%rdi'),
        46550915: ('4889bc24800100', 'mov    %rdi,0x180(%rsp)'),
        46550923: ('488d9c24400100', 'lea    0x140(%rsp),%rbx'),
        46550931: ('4c8db424180100', 'lea    0x118(%rsp),%r14'),
        46550939: ('4c8d7c2430', 'lea    0x30(%rsp),%r15'),
        46550944: ('4889df', 'mov    %rbx,%rdi'),
        46550947: ('e848989cff', 'call   0x262e7f0'),
        46550952: ('4885c0', 'test   %rax,%rax'),
        46550955: ('742b', 'je     0x2c64fd8'),
        46550957: ('4989d4', 'mov    %rdx,%r12'),
        46550960: ('488b10', 'mov    (%rax),%rdx'),
        46550963: ('498b0c24', 'mov    (%r12),%rcx'),
        46550967: ('4c893424', 'mov    %r14,(%rsp)'),
        46550971: ('488b7c2418', 'mov    0x18(%rsp),%rdi'),
        46550976: ('488b742420', 'mov    0x20(%rsp),%rsi'),
        46550981: ('448b442428', 'mov    0x28(%rsp),%r8d'),
        46550986: ('4d89f9', 'mov    %r15,%r9'),
        46550989: ('e8dec9ffff', 'call   0x2c619b0'),
        46550994: ('49890424', 'mov    %rax,(%r12)'),
        46550998: ('ebc8', 'jmp    0x2c64fa0'),
        46551000: ('48c78424400200', 'movq   $0x0,0x240(%rsp)'),
        46551012: ('48c78424480200', 'movq   $0x8,0x248(%rsp)'),
        46551024: ('0f57c0', 'xorps  %xmm0,%xmm0'),
        46551027: ('0f118424500200', 'movups %xmm0,0x250(%rsp)'),
        46551035: ('488b8424f00000', 'mov    0xf0(%rsp),%rax'),
        46551241: ('48c78424d00000', 'movq   $0x0,0xd0(%rsp)'),
        46551253: ('48898424d80000', 'mov    %rax,0xd8(%rsp)'),
        46551261: ('4889bc24e00000', 'mov    %rdi,0xe0(%rsp)'),
        46551269: ('4c898424e80000', 'mov    %r8,0xe8(%rsp)'),
        46551277: ('4584ed', 'test   %r13b,%r13b'),
        46551280: ('0f8467050000', 'je     0x2c6565d'),
        46551286: ('4c8da424400100', 'lea    0x140(%rsp),%r12'),
        46551294: ('eb32', 'jmp    0x2c65132'),
        46551296: ('4829c5', 'sub    %rax,%rbp'),
        46551299: ('666666662e0f1f', 'data16 data16 data16 cs nopw 0x0(%rax,%rax,1)'),
        46551312: ('488dbc24400200', 'lea    0x240(%rsp),%rdi'),
        46551320: ('488d0d41887e03', 'lea    0x37e8841(%rip),%rcx'),
        46551327: ('4c89ee', 'mov    %r13,%rsi'),
        46551330: ('4889ea', 'mov    %rbp,%rdx'),
        46551333: ('e8d69b1400', 'call   0x2daed00'),
        46551641: ('0f1106', 'movups %xmm0,(%rsi)'),
        46551644: ('4c89ac24800200', 'mov    %r13,0x280(%rsp)'),
        46551652: ('48c78424600200', 'movq   $0x3,0x260(%rsp)'),
        46551664: ('888c249c020000', 'mov    %cl,0x29c(%rsp)'),
        46551671: ('4889bc24700200', 'mov    %rdi,0x270(%rsp)'),
        46551679: ('4c898424780200', 'mov    %r8,0x278(%rsp)'),
        46551687: ('4c89e7', 'mov    %r12,%rdi'),
        46551690: ('488b742418', 'mov    0x18(%rsp),%rsi'),
        46551695: ('488d9424600200', 'lea    0x260(%rsp),%rdx'),
        46551703: ('e884d5ffff', 'call   0x2c62820'),
        46551708: ('83bc2440010000', 'cmpl   $0x3,0x140(%rsp)'),
        46551716: ('0f8466feffff', 'je     0x2c65110'),
        46551722: ('baf8000000', 'mov    $0xf8,%edx'),
        46551727: ('488dbc24f00200', 'lea    0x2f0(%rsp),%rdi'),
        46551735: ('4c89e6', 'mov    %r12,%rsi'),
        46551738: ('ff1548a28703', 'call   *0x387a248(%rip)'),
        46551744: ('83bc24f0020000', 'cmpl   $0x2,0x2f0(%rsp)'),
        46551752: ('7508', 'jne    0x2c652d2'),
        46551754: ('4531f6', 'xor    %r14d,%r14d'),
        46551757: ('e91f010000', 'jmp    0x2c653f1'),
        46551762: ('488b9c24d80300', 'mov    0x3d8(%rsp),%rbx'),
        46551770: ('4c8bb424e00300', 'mov    0x3e0(%rsp),%r14'),
        46551778: ('488b442430', 'mov    0x30(%rsp),%rax'),
        46551783: ('48b90000000000', 'movabs $0x8000000000000000,%rcx'),
        46552106: ('8b442414', 'mov    0x14(%rsp),%eax'),
        46552110: ('8884249c020000', 'mov    %al,0x29c(%rsp)'),
        46552117: ('488d442430', 'lea    0x30(%rsp),%rax'),
        46552122: ('48898424700200', 'mov    %rax,0x270(%rsp)'),
        46552130: ('488d8424180100', 'lea    0x118(%rsp),%rax'),
        46552138: ('48898424780200', 'mov    %rax,0x278(%rsp)'),
        46552146: ('4c89e7', 'mov    %r12,%rdi'),
        46552149: ('488b742418', 'mov    0x18(%rsp),%rsi'),
        46552154: ('488d9424600200', 'lea    0x260(%rsp),%rdx'),
        46552162: ('e8b9d3ffff', 'call   0x2c62820'),
        46552167: ('83bc2440010000', 'cmpl   $0x3,0x140(%rsp)'),
        46552175: ('0f849bfcffff', 'je     0x2c65110'),
        46552181: ('baf8000000', 'mov    $0xf8,%edx'),
        46552186: ('488dbc24f00200', 'lea    0x2f0(%rsp),%rdi'),
        46552194: ('4c89e6', 'mov    %r12,%rsi'),
        46552197: ('ff157da08703', 'call   *0x387a07d(%rip)'),
        46552203: ('83bc24f0020000', 'cmpl   $0x2,0x2f0(%rsp)'),
        46552211: ('7508', 'jne    0x2c6549d'),
        46552213: ('4531ff', 'xor    %r15d,%r15d'),
        46552216: ('e914010000', 'jmp    0x2c655b1'),
        46552221: ('4c8bb424d80300', 'mov    0x3d8(%rsp),%r14'),
        46552229: ('4c8bbc24e00300', 'mov    0x3e0(%rsp),%r15'),
        46552237: ('488b442430', 'mov    0x30(%rsp),%rax'),
        46552242: ('48b90000000000', 'movabs $0x8000000000000000,%rcx'),
        46552508: ('4829e9', 'sub    %rbp,%rcx'),
        46552511: ('0f823bfbffff', 'jb     0x2c65100'),
        46552517: ('488d8424180100', 'lea    0x118(%rsp),%rax'),
        46552525: ('48890424', 'mov    %rax,(%rsp)'),
        46552529: ('488b7c2418', 'mov    0x18(%rsp),%rdi'),
        46552534: ('488db424100400', 'lea    0x410(%rsp),%rsi'),
        46552542: ('4c89ea', 'mov    %r13,%rdx'),
        46552545: ('448b442428', 'mov    0x28(%rsp),%r8d'),
        46552550: ('4c8d4c2430', 'lea    0x30(%rsp),%r9'),
        46552555: ('e8c0c3ffff', 'call   0x2c619b0'),
        46552560: ('4889c5', 'mov    %rax,%rbp'),
        46552563: ('488dbc24800000', 'lea    0x80(%rsp),%rdi'),
        46552571: ('488d0d46837e03', 'lea    0x37e8346(%rip),%rcx'),
        46552578: ('e918fbffff', 'jmp    0x2c6511f'),
        46552583: ('31ff', 'xor    %edi,%edi'),
        46552585: ('488d35501e8203', 'lea    0x3821e50(%rip),%rsi'),
        46552592: ('ff1592f88703', 'call   *0x387f892(%rip)'),
        46552598: ('4d01fe', 'add    %r15,%r14'),
        46552601: ('48c7c0ffffffff', 'mov    $0xffffffffffffffff,%rax'),
        46552786: ('0f8489000000', 'je     0x2c65761'),
        46552792: ('488d4810', 'lea    0x10(%rax),%rcx'),
        46552796: ('48898c24b00000', 'mov    %rcx,0xb0(%rsp)'),
        46552804: ('488d5008', 'lea    0x8(%rax),%rdx'),
        46552808: ('eb0e', 'jmp    0x2c656f8'),
        46552810: ('660f1f440000', 'nopw   0x0(%rax,%rax,1)'),
        46552816: ('4c89ff', 'mov    %r15,%rdi'),
        46552819: ('e8782a72ff', 'call   0x2388170'),
        46552824: ('4885c0', 'test   %rax,%rax'),
        46552827: ('746b', 'je     0x2c65768'),
        46552829: ('4c8b20', 'mov    (%rax),%r12'),
        46552832: ('4c89642470', 'mov    %r12,0x70(%rsp)'),
        46552837: ('b864000000', 'mov    $0x64,%eax'),
        46552842: ('48f722', 'mulq   (%rdx)'),
        46552845: ('0f806dffffff', 'jo     0x2c65680'),
        46552851: ('4989c5', 'mov    %rax,%r13'),
        46552854: ('4889df', 'mov    %rbx,%rdi'),
        46552857: ('488d742470', 'lea    0x70(%rsp),%rsi'),
        46552862: ('e8ed6a1600', 'call   0x2dcc210'),
        46552867: ('a801', 'test   $0x1,%al'),
        46552869: ('b800000000', 'mov    $0x0,%eax'),
        46552874: ('480f44d0', 'cmove  %rax,%rdx'),
    },
    'big2': {
        90060720: ('0f57c0', 'xorps  %xmm0,%xmm0'),
        90060723: ('0f118424f00200', 'movups %xmm0,0x2f0(%rsp)'),
        90060731: ('48c78424000300', 'movq   $0x0,0x300(%rsp)'),
        90060743: ('48c78424080300', 'movq   $0x8,0x308(%rsp)'),
        90060755: ('0f118424100300', 'movups %xmm0,0x310(%rsp)'),
        90060763: ('4c8ba638130000', 'mov    0x1338(%rsi),%r12'),
        90060770: ('4c69be40130000', 'imul   $0x510,0x1340(%rsi),%r15'),
        90060781: ('894c242c', 'mov    %ecx,0x2c(%rsp)'),
        90060785: ('85c9', 'test   %ecx,%ecx'),
        90060787: ('4889742420', 'mov    %rsi,0x20(%rsp)'),
        90060792: ('7426', 'je     0x55e3820'),
        90060794: ('4889f5', 'mov    %rsi,%rbp'),
        90060797: ('4d01e7', 'add    %r12,%r15'),
        90060800: ('4c89bc24180100', 'mov    %r15,0x118(%rsp)'),
        90060808: ('488d8688150000', 'lea    0x1588(%rsi),%rax'),
        90060929: ('488db424000300', 'lea    0x300(%rsp),%rsi'),
        90060937: ('4c89ea', 'mov    %r13,%rdx'),
        90060940: ('e8ef447eff', 'call   0x4dc7d80'),
        90060945: ('488dbc24500100', 'lea    0x150(%rsp),%rdi'),
        90060953: ('e822097cff', 'call   0x4da41c0'),
        90060958: ('4989c5', 'mov    %rax,%r13'),
        90060961: ('4c8b30', 'mov    (%rax),%r14'),
        90060964: ('4c89f3', 'mov    %r14,%rbx'),
        90060967: ('4801eb', 'add    %rbp,%rbx'),
        90060970: ('7033', 'jo     0x55e38df'),
        90060972: ('4981c410050000', 'add    $0x510,%r12'),
        90060979: ('49895d00', 'mov    %rbx,0x0(%r13)'),
        90060983: ('4981c7f0faffff', 'add    $0xfffffffffffffaf0,%r15'),
        90060990: ('488dbc24e00200', 'lea    0x2e0(%rsp),%rdi'),
        90060998: ('488b742418', 'mov    0x18(%rsp),%rsi'),
        90061003: ('4889ea', 'mov    %rbp,%rdx'),
        90061006: ('488d0deb6cec00', 'lea    0xec6ceb(%rip),%rcx'),
        90061013: ('e8d6ad7dff', 'call   0x4dbe6b0'),
        90061018: ('e941ffffff', 'jmp    0x55e3820'),
        90061023: ('31ff', 'xor    %edi,%edi'),
        90061025: ('488d3510daeb00', 'lea    0xebda10(%rip),%rsi'),
        90061032: ('ff15ba15f000', 'call   *0xf015ba(%rip)'),
        90061038: ('48c1fb3f', 'sar    $0x3f,%rbx'),
        90061042: ('48b80000000000', 'movabs $0x8000000000000000,%rax'),
        90061052: ('4831c3', 'xor    %rax,%rbx'),
        90061055: ('4901ee', 'add    %rbp,%r14'),
        90061058: ('490f41de', 'cmovno %r14,%rbx'),
        90061062: ('eba4', 'jmp    0x55e38ac'),
        90061064: ('4c8b642468', 'mov    0x68(%rsp),%r12'),
        90061069: ('66898424500100', 'mov    %ax,0x150(%rsp)'),
        90061077: ('488b8424a80200', 'mov    0x2a8(%rsp),%rax'),
        90061085: ('48898424580100', 'mov    %rax,0x158(%rsp)'),
        90061093: ('488b8424b80200', 'mov    0x2b8(%rsp),%rax'),
        90061101: ('48898424600100', 'mov    %rax,0x160(%rsp)'),
        90061109: ('488b8424b00200', 'mov    0x2b0(%rsp),%rax'),
        90061117: ('48898424680100', 'mov    %rax,0x168(%rsp)'),
        90061125: ('488dbc24500100', 'lea    0x150(%rsp),%rdi'),
        90061133: ('e8aec60400', 'call   0x5630000'),
        90061138: ('4c3ba424180100', 'cmp    0x118(%rsp),%r12'),
        90061146: ('0f8419030000', 'je     0x55e3c79'),
        90061152: ('498b442450', 'mov    0x50(%r12),%rax'),
        90061157: ('483b8540130000', 'cmp    0x1340(%rbp),%rax'),
        90061164: ('0f8353100000', 'jae    0x55e49c5'),
        90061170: ('498b4c2458', 'mov    0x58(%r12),%rcx'),
        90061175: ('48898c24d80200', 'mov    %rcx,0x2d8(%rsp)'),
        90061183: ('48898424d00200', 'mov    %rax,0x2d0(%rsp)'),
        90061191: ('4c69f810050000', 'imul   $0x510,%rax,%r15'),
        90061198: ('4c03bd38130000', 'add    0x1338(%rbp),%r15'),
        90061205: ('66c78424500100', 'movw   $0x156,0x150(%rsp)'),
        90061215: ('488dbc24500100', 'lea    0x150(%rsp),%rdi'),
        90061223: ('e864ceeffe', 'call   0x44e0810'),
        90061228: ('4981c410050000', 'add    $0x510,%r12'),
        90061235: ('498b4758', 'mov    0x58(%r15),%rax'),
        90061239: ('4889442418', 'mov    %rax,0x18(%rsp)'),
        90061244: ('488b4c2410', 'mov    0x10(%rsp),%rcx'),
        90061249: ('8b4110', 'mov    0x10(%rcx),%eax'),
        90061252: ('89842460010000', 'mov    %eax,0x160(%rsp)'),
        90061259: ('0f1001', 'movups (%rcx),%xmm0'),
        90061262: ('0f298424500100', 'movaps %xmm0,0x150(%rsp)'),
        90061270: ('488bbc24c00200', 'mov    0x2c0(%rsp),%rdi'),
        90061307: ('4d85ed', 'test   %r13,%r13'),
        90061310: ('0f846b010000', 'je     0x55e3b6f'),
        90061316: ('4c89642468', 'mov    %r12,0x68(%rsp)'),
        90061321: ('488b8598150000', 'mov    0x1598(%rbp),%rax'),
        90061328: ('48898424200100', 'mov    %rax,0x120(%rsp)'),
        90061336: ('498db5f0070000', 'lea    0x7f0(%r13),%rsi'),
        90061343: ('410fb785ce0800', 'movzwl 0x8ce(%r13),%eax'),
        90061351: ('4d8da550ffffff', 'lea    -0xb0(%r13),%r12'),
        90061358: ('48898424c80200', 'mov    %rax,0x2c8(%rsp)'),
        90061366: ('8d048500000000', 'lea    0x0(,%rax,4),%eax'),
        90061373: ('488d1c80', 'lea    (%rax,%rax,4),%rbx'),
        90061377: ('49c7c6ffffffff', 'mov    $0xffffffffffffffff,%r14'),
        90061384: ('0f1f8400000000', 'nopl   0x0(%rax,%rax,1)'),
        90061392: ('4885db', 'test   %rbx,%rbx'),
        90061395: ('746b', 'je     0x55e3ac0'),
        90061397: ('488d6e14', 'lea    0x14(%rsi),%rbp'),
        90061401: ('ba14000000', 'mov    $0x14,%edx'),
        90061406: ('488dbc24500100', 'lea    0x150(%rsp),%rdi'),
        90061414: ('ff15e4c0ef00', 'call   *0xefc0e4(%rip)'),
        90061420: ('4898', 'cltq'),
        90061422: ('4885c0', 'test   %rax,%rax'),
        90061425: ('0f98c1', 'sets   %cl'),
        90061428: ('0f9fc0', 'setg   %al'),
        90061431: ('28c8', 'sub    %cl,%al'),
        90061433: ('4981c4b8000000', 'add    $0xb8,%r12'),
        90061440: ('49ffc6', 'inc    %r14'),
        90061443: ('4883c3ec', 'add    $0xffffffffffffffec,%rbx'),
        90061447: ('4889ee', 'mov    %rbp,%rsi'),
        90061450: ('3c01', 'cmp    $0x1,%al'),
        90061452: ('74c2', 'je     0x55e3a50'),
        90061454: ('0fb6c0', 'movzbl %al,%eax'),
        90061457: ('85c0', 'test   %eax,%eax'),
        90061459: ('488b6c2420', 'mov    0x20(%rsp),%rbp'),
        90061464: ('0f84ad000000', 'je     0x55e3b4b'),
        90061470: ('488b8424200100', 'mov    0x120(%rsp),%rax'),
        90061478: ('4883e801', 'sub    $0x1,%rax'),
        90061482: ('4c8b642468', 'mov    0x68(%rsp),%r12'),
        90061487: ('7333', 'jae    0x55e3ae4'),
        90061489: ('e9b9000000', 'jmp    0x55e3b6f'),
        90061494: ('662e0f1f840000', 'cs nopw 0x0(%rax,%rax,1)'),
        90061504: ('4c8bb424c80200', 'mov    0x2c8(%rsp),%r14'),
        90061512: ('488b6c2420', 'mov    0x20(%rsp),%rbp'),
        90061517: ('488b8424200100', 'mov    0x120(%rsp),%rax'),
        90061525: ('4883e801', 'sub    $0x1,%rax'),
        90061529: ('4c8b642468', 'mov    0x68(%rsp),%r12'),
        90061534: ('0f828b000000', 'jb     0x55e3b6f'),
        90061540: ('48898424200100', 'mov    %rax,0x120(%rsp)'),
        90061548: ('4f8bacf5d00800', 'mov    0x8d0(%r13,%r14,8),%r13'),
        90061556: ('e91fffffff', 'jmp    0x55e3a18'),
        90061561: ('0f1f8000000000', 'nopl   0x0(%rax)'),
        90061568: ('488db424500100', 'lea    0x150(%rsp),%rsi'),
        90061576: ('e8e3542100', 'call   0x57f8ff0'),
        90061592: ('7355', 'jae    0x55e3b6f'),
        90061594: ('4c89642468', 'mov    %r12,0x68(%rsp)'),
        90061599: ('48039598150000', 'add    0x1598(%rbp),%rdx'),
        90061606: ('4839da', 'cmp    %rbx,%rdx'),
        90061609: ('b800000000', 'mov    $0x0,%eax'),
        90061614: ('480f43c3', 'cmovae %rbx,%rax'),
        90061618: ('4829c2', 'sub    %rax,%rdx'),
        90061621: ('488b8590150000', 'mov    0x1590(%rbp),%rax'),
        90061628: ('4869cad0000000', 'imul   $0xd0,%rdx,%rcx'),
        90061635: ('4c8d2408', 'lea    (%rax,%rcx,1),%r12'),
        90061639: ('4983c418', 'add    $0x18,%r12'),
        90061643: ('66b81500', 'mov    $0x15,%ax'),
        90061647: ('48837c241800', 'cmpq   $0x0,0x18(%rsp)'),
        90061653: ('0f85adfdffff', 'jne    0x55e3908'),
        90061659: ('4180bc24b70000', 'cmpb   $0x0,0xb7(%r12)'),
        90061668: ('4c8b642468', 'mov    0x68(%rsp),%r12'),
        90061673: ('0f849efdffff', 'je     0x55e390d'),
        90061679: ('488b4c2410', 'mov    0x10(%rsp),%rcx'),
        90061684: ('8b4110', 'mov    0x10(%rcx),%eax'),
        90061687: ('89842460010000', 'mov    %eax,0x160(%rsp)'),
        90061694: ('0f1001', 'movups (%rcx),%xmm0'),
        90061697: ('0f298424500100', 'movaps %xmm0,0x150(%rsp)'),
        90061705: ('4c89ff', 'mov    %r15,%rdi'),
        90061708: ('488db424500100', 'lea    0x150(%rsp),%rsi'),
        90061716: ('ba02000000', 'mov    $0x2,%edx'),
        90062976: ('488d9c24500100', 'lea    0x150(%rsp),%rbx'),
        90062984: ('4c8db424280100', 'lea    0x128(%rsp),%r14'),
        90062992: ('4c8d7c2430', 'lea    0x30(%rsp),%r15'),
        90062997: ('66662e0f1f8400', 'data16 cs nopw 0x0(%rax,%rax,1)'),
        90063008: ('4889df', 'mov    %rbx,%rdi'),
        90063011: ('e8a85b83ff', 'call   0x4e19c50'),
        90063016: ('4885c0', 'test   %rax,%rax'),
        90063019: ('7429', 'je     0x55e40d6'),
        90063021: ('4989d4', 'mov    %rdx,%r12'),
        90063024: ('488b10', 'mov    (%rax),%rdx'),
        90063027: ('498b0c24', 'mov    (%r12),%rcx'),
        90063031: ('4c893424', 'mov    %r14,(%rsp)'),
        90063035: ('4c89ef', 'mov    %r13,%rdi'),
        90063038: ('488b742410', 'mov    0x10(%rsp),%rsi'),
        90063043: ('448b442418', 'mov    0x18(%rsp),%r8d'),
        90063048: ('4d89f9', 'mov    %r15,%r9'),
        90063051: ('e8e0aaffff', 'call   0x55debb0'),
        90063056: ('49890424', 'mov    %rax,(%r12)'),
        90063060: ('ebca', 'jmp    0x55e40a0'),
        90063062: ('48c78424480200', 'movq   $0x0,0x248(%rsp)'),
        90063303: ('48c78424d00000', 'movq   $0x0,0xd0(%rsp)'),
        90063315: ('48898424d80000', 'mov    %rax,0xd8(%rsp)'),
        90063323: ('4889bc24e00000', 'mov    %rdi,0xe0(%rsp)'),
        90063331: ('4c898424e80000', 'mov    %r8,0xe8(%rsp)'),
        90063339: ('4084ed', 'test   %bpl,%bpl'),
        90063342: ('0f8469050000', 'je     0x55e475d'),
        90063348: ('4c8da424500100', 'lea    0x150(%rsp),%r12'),
        90063356: ('eb34', 'jmp    0x55e4232'),
        90063358: ('4829c5', 'sub    %rax,%rbp'),
        90063361: ('6666666666662e', 'data16 data16 data16 data16 data16 cs nopw 0x0(%rax,%rax,1)'),
        90063376: ('488dbc24480200', 'lea    0x248(%rsp),%rdi'),
        90063384: ('488d0d0164ec00', 'lea    0xec6401(%rip),%rcx'),
        90063391: ('4c89ee', 'mov    %r13,%rsi'),
        90063394: ('4889ea', 'mov    %rbp,%rdx'),
        90063705: ('0f1106', 'movups %xmm0,(%rsi)'),
        90063708: ('4c89ac24880200', 'mov    %r13,0x288(%rsp)'),
        90063716: ('48c78424680200', 'movq   $0x3,0x268(%rsp)'),
        90063728: ('888c24a4020000', 'mov    %cl,0x2a4(%rsp)'),
        90063735: ('4889bc24780200', 'mov    %rdi,0x278(%rsp)'),
        90063743: ('4c898424800200', 'mov    %r8,0x280(%rsp)'),
        90063751: ('4c89e7', 'mov    %r12,%rdi'),
        90063754: ('488b742420', 'mov    0x20(%rsp),%rsi'),
        90063759: ('488d9424680200', 'lea    0x268(%rsp),%rdx'),
        90063767: ('e834d3ffff', 'call   0x55e16d0'),
        90063772: ('83bc2450010000', 'cmpl   $0x3,0x150(%rsp)'),
        90063780: ('0f8466feffff', 'je     0x55e4210'),
        90063786: ('baf8000000', 'mov    $0xf8,%edx'),
        90063791: ('488dbc24600300', 'lea    0x360(%rsp),%rdi'),
        90063799: ('4c89e6', 'mov    %r12,%rsi'),
        90063802: ('ff1548b1ef00', 'call   *0xefb148(%rip)'),
        90063808: ('83bc2460030000', 'cmpl   $0x2,0x360(%rsp)'),
        90063816: ('7508', 'jne    0x55e43d2'),
        90063818: ('4531f6', 'xor    %r14d,%r14d'),
        90063821: ('e91f010000', 'jmp    0x55e44f1'),
        90063826: ('488b9c24480400', 'mov    0x448(%rsp),%rbx'),
        90063834: ('4c8bb424500400', 'mov    0x450(%rsp),%r14'),
        90063842: ('488b442430', 'mov    0x30(%rsp),%rax'),
        90063847: ('48b90000000000', 'movabs $0x8000000000000000,%rcx'),
        90064170: ('8b44242c', 'mov    0x2c(%rsp),%eax'),
        90064174: ('888424a4020000', 'mov    %al,0x2a4(%rsp)'),
        90064181: ('488d442430', 'lea    0x30(%rsp),%rax'),
        90064186: ('48898424780200', 'mov    %rax,0x278(%rsp)'),
        90064194: ('488d8424280100', 'lea    0x128(%rsp),%rax'),
        90064202: ('48898424800200', 'mov    %rax,0x280(%rsp)'),
        90064210: ('4c89e7', 'mov    %r12,%rdi'),
        90064213: ('488b742420', 'mov    0x20(%rsp),%rsi'),
        90064218: ('488d9424680200', 'lea    0x268(%rsp),%rdx'),
        90064226: ('e869d1ffff', 'call   0x55e16d0'),
        90064231: ('83bc2450010000', 'cmpl   $0x3,0x150(%rsp)'),
        90064239: ('0f849bfcffff', 'je     0x55e4210'),
        90064245: ('baf8000000', 'mov    $0xf8,%edx'),
        90064250: ('488dbc24600300', 'lea    0x360(%rsp),%rdi'),
        90064258: ('4c89e6', 'mov    %r12,%rsi'),
        90064261: ('ff157dafef00', 'call   *0xefaf7d(%rip)'),
        90064267: ('83bc2460030000', 'cmpl   $0x2,0x360(%rsp)'),
        90064275: ('7508', 'jne    0x55e459d'),
        90064277: ('4531ff', 'xor    %r15d,%r15d'),
        90064280: ('e914010000', 'jmp    0x55e46b1'),
        90064285: ('4c8bb424480400', 'mov    0x448(%rsp),%r14'),
        90064293: ('4c8bbc24500400', 'mov    0x450(%rsp),%r15'),
        90064301: ('488b442430', 'mov    0x30(%rsp),%rax'),
        90064306: ('48b90000000000', 'movabs $0x8000000000000000,%rcx'),
        90064850: ('0f8489000000', 'je     0x55e4861'),
        90064856: ('488d4810', 'lea    0x10(%rax),%rcx'),
        90064860: ('48898c24b00000', 'mov    %rcx,0xb0(%rsp)'),
        90064868: ('488d5008', 'lea    0x8(%rax),%rdx'),
        90064872: ('eb0e', 'jmp    0x55e47f8'),
        90064874: ('660f1f440000', 'nopw   0x0(%rax,%rax,1)'),
        90064880: ('4c89ff', 'mov    %r15,%rdi'),
        90064883: ('e8f8ffb4ff', 'call   0x51347f0'),
        90064888: ('4885c0', 'test   %rax,%rax'),
        90064891: ('746b', 'je     0x55e4868'),
        90064893: ('4c8b20', 'mov    (%rax),%r12'),
        90064896: ('4c89642470', 'mov    %r12,0x70(%rsp)'),
        90064901: ('b864000000', 'mov    $0x64,%eax'),
        90064906: ('48f722', 'mulq   (%rdx)'),
        90064909: ('0f806dffffff', 'jo     0x55e4780'),
        90064915: ('4989c5', 'mov    %rax,%r13'),
        90064918: ('4889df', 'mov    %rbx,%rdi'),
        90064921: ('488d742470', 'lea    0x70(%rsp),%rsi'),
        90064926: ('e8dd8a7fff', 'call   0x4ddd300'),
        90064931: ('a801', 'test   $0x1,%al'),
        90064933: ('b800000000', 'mov    $0x0,%eax'),
        90064938: ('480f44d0', 'cmove  %rax,%rdx'),
    },
    'big3': {
        90042552: ('8b5108', 'mov    0x8(%rcx),%edx'),
        90042555: ('89942408020000', 'mov    %edx,0x208(%rsp)'),
        90042562: ('488b09', 'mov    (%rcx),%rcx'),
        90042565: ('48898c24000200', 'mov    %rcx,0x200(%rsp)'),
        90042573: ('8b4810', 'mov    0x10(%rax),%ecx'),
        90042576: ('898c2490020000', 'mov    %ecx,0x290(%rsp)'),
        90042583: ('660f1000', 'movupd (%rax),%xmm0'),
        90042587: ('660f2984248002', 'movapd %xmm0,0x280(%rsp)'),
        90042596: ('48c78424100400', 'movq   $0x4,0x410(%rsp)'),
        90042608: ('48c78424d80300', 'movq   $0x3,0x3d8(%rsp)'),
        90042620: ('48c78424e00300', 'movq   $0x0,0x3e0(%rsp)'),
        90042632: ('48c78424f00300', 'movq   $0x1,0x3f0(%rsp)'),
        90042644: ('48b8ae47e17a14', 'movabs $0x3fefae147ae147ae,%rax'),
        90047163: ('48898c24c00000', 'mov    %rcx,0xc0(%rsp)'),
        90047171: ('48898424e00000', 'mov    %rax,0xe0(%rsp)'),
        90047179: ('0f1f440000', 'nopl   0x0(%rax,%rax,1)'),
        90047184: ('488dbc24a80800', 'lea    0x8a8(%rsp),%rdi'),
        90047192: ('4c89ee', 'mov    %r13,%rsi'),
        90047195: ('e8f003c0ff', 'call   0x51e06d0'),
        90047200: ('4883bc24a80800', 'cmpq   $0x0,0x8a8(%rsp)'),
        90047209: ('75e5', 'jne    0x55e02d0'),
        90047211: ('4c89a424100400', 'mov    %r12,0x410(%rsp)'),
        90047219: ('8b442430', 'mov    0x30(%rsp),%eax'),
        90047223: ('88842418040000', 'mov    %al,0x418(%rsp)'),
        90047230: ('baff000000', 'mov    $0xff,%edx'),
        90047235: ('488dbc24190400', 'lea    0x419(%rsp),%rdi'),
        90047243: ('488db4248a0900', 'lea    0x98a(%rsp),%rsi'),
        90047251: ('ff15eff1ef00', 'call   *0xeff1ef(%rip)'),
        90047257: ('488b8424b80100', 'mov    0x1b8(%rsp),%rax'),
        90047265: ('48898424180500', 'mov    %rax,0x518(%rsp)'),
        90047273: ('0fb644242f', 'movzbl 0x2f(%rsp),%eax'),
        90047278: ('88842420050000', 'mov    %al,0x520(%rsp)'),
        90047285: ('498d4424fb', 'lea    -0x5(%r12),%rax'),
        90047290: ('4883f8fe', 'cmp    $0xfffffffffffffffe,%rax'),
        90047294: ('488b8c24400200', 'mov    0x240(%rsp),%rcx'),
        90047302: ('0f82730f0000', 'jb     0x55e12bf'),
        90047308: ('4c89e2', 'mov    %r12,%rdx'),
        90047311: ('4883f903', 'cmp    $0x3,%rcx'),
        90047315: ('0f8577eeffff', 'jne    0x55df1d0'),
        90047321: ('e9610f0000', 'jmp    0x55e12bf'),
        90047326: ('4889c8', 'mov    %rcx,%rax'),
        90049607: ('4983fd02', 'cmp    $0x2,%r13'),
        90049611: ('750b', 'jne    0x55e0c58'),
        90049613: ('41b501', 'mov    $0x1,%r13b'),
        90049616: ('4189c7', 'mov    %eax,%r15d'),
        90049619: ('e995000000', 'jmp    0x55e0ced'),
        90049624: ('baa7000000', 'mov    $0xa7,%edx'),
        90049629: ('488dbc24f00600', 'lea    0x6f0(%rsp),%rdi'),
        90049637: ('488db424290300', 'lea    0x329(%rsp),%rsi'),
        90049645: ('4189c6', 'mov    %eax,%r14d'),
        90049648: ('ff1592e8ef00', 'call   *0xefe892(%rip)'),
        90049654: ('4c896c2438', 'mov    %r13,0x38(%rsp)'),
        90049659: ('4c89ac24280500', 'mov    %r13,0x528(%rsp)'),
        90049667: ('4488742420', 'mov    %r14b,0x20(%rsp)'),
        90049672: ('4488b424300500', 'mov    %r14b,0x530(%rsp)'),
        90049680: ('baa7000000', 'mov    $0xa7,%edx'),
        90049685: ('488dbc24310500', 'lea    0x531(%rsp),%rdi'),
        90049693: ('488db424f00600', 'lea    0x6f0(%rsp),%rsi'),
        90049701: ('ff155de8ef00', 'call   *0xefe85d(%rip)'),
        90049707: ('4c8bb424c00100', 'mov    0x1c0(%rsp),%r14'),
        90049715: ('4d85f6', 'test   %r14,%r14'),
        90049718: ('7432', 'je     0x55e0cea'),
        90049720: ('4c03a424880000', 'add    0x88(%rsp),%r12'),
        90049728: ('48837c245001', 'cmpq   $0x1,0x50(%rsp)'),
        90049734: ('0f8626010000', 'jbe    0x55e0df2'),
        90049740: ('41b501', 'mov    $0x1,%r13b'),
        90049743: ('488b4c2470', 'mov    0x70(%rsp),%rcx'),
        90049748: ('4885c9', 'test   %rcx,%rcx'),
        90051119: ('0f9344242f', 'setae  0x2f(%rsp)'),
        90051124: ('4c8ba424a00000', 'mov    0xa0(%rsp),%r12'),
        90051132: ('0fb68424a80000', 'movzbl 0xa8(%rsp),%eax'),
        90051140: ('89442430', 'mov    %eax,0x30(%rsp)'),
        90051144: ('baff000000', 'mov    $0xff,%edx'),
        90051149: ('488dbc248a0900', 'lea    0x98a(%rsp),%rdi'),
        90051157: ('488db424a90000', 'lea    0xa9(%rsp),%rsi'),
        90051165: ('ff15a5e2ef00', 'call   *0xefe2a5(%rip)'),
        90051171: ('4c89b424b80100', 'mov    %r14,0x1b8(%rsp)'),
        90051179: ('e999efffff', 'jmp    0x55e0209'),
        90051184: ('488b8424500100', 'mov    0x150(%rsp),%rax'),
        90051192: ('48b90000000000', 'movabs $0x8000000000000000,%rcx'),
        90051202: ('4839c8', 'cmp    %rcx,%rax'),
        90051205: ('7512', 'jne    0x55e1299'),
        90051207: ('488dbc24580100', 'lea    0x158(%rsp),%rdi'),
        90051242: ('48c1e003', 'shl    $0x3,%rax'),
        90051246: ('488d3480', 'lea    (%rax,%rax,4),%rsi'),
        90051250: ('31d2', 'xor    %edx,%edx'),
        90051252: ('ff15e6e1ef00', 'call   *0xefe1e6(%rip)'),
        90051258: ('e931efffff', 'jmp    0x55e01f0'),
        90051263: ('4983fc04', 'cmp    $0x4,%r12'),
        90051267: ('7421', 'je     0x55e12e6'),
        90051269: ('488dbc24980700', 'lea    0x798(%rsp),%rdi'),
        90051277: ('ba0f010000', 'mov    $0x10f,%edx'),
        90051282: ('488db424190400', 'lea    0x419(%rsp),%rsi'),
        90051290: ('ff1528e2ef00', 'call   *0xefe228(%rip)'),
        90051296: ('4983fc03', 'cmp    $0x3,%r12'),
        90051300: ('7514', 'jne    0x55e12fa'),
        90051302: ('31c0', 'xor    %eax,%eax'),
        90051304: ('4881c4880b0000', 'add    $0xb88,%rsp'),
        90051311: ('5b', 'pop    %rbx'),
        90051312: ('415c', 'pop    %r12'),
        90051314: ('415d', 'pop    %r13'),
        90051316: ('415e', 'pop    %r14'),
        90051318: ('415f', 'pop    %r15'),
        90051320: ('5d', 'pop    %rbp'),
        90051321: ('c3', 'ret'),
        90051322: ('4c8dbc24e10500', 'lea    0x5e1(%rsp),%r15'),
        90051330: ('488db424980700', 'lea    0x798(%rsp),%rsi'),
        90051338: ('ba0f010000', 'mov    $0x10f,%edx'),
        90051343: ('4c89ff', 'mov    %r15,%rdi'),
        90051346: ('ff15f0e1ef00', 'call   *0xefe1f0(%rip)'),
        90051352: ('4c89a424d80500', 'mov    %r12,0x5d8(%rsp)'),
        90051360: ('8b442430', 'mov    0x30(%rsp),%eax'),
        90051364: ('888424e0050000', 'mov    %al,0x5e0(%rsp)'),
        90051371: ('488b8c24e00600', 'mov    0x6e0(%rsp),%rcx'),
        90051379: ('4983fc02', 'cmp    $0x2,%r12'),
        90051383: ('0f8480000000', 'je     0x55e13bd'),
        90051389: ('80bc24e8060000', 'cmpb   $0x0,0x6e8(%rsp)'),
        90051397: ('7476', 'je     0x55e13bd'),
        90051399: ('8b842470020000', 'mov    0x270(%rsp),%eax'),
        90051406: ('89842420040000', 'mov    %eax,0x420(%rsp)'),
        90051413: ('660f2884246002', 'movapd 0x260(%rsp),%xmm0'),
        90051422: ('660f2984241004', 'movapd %xmm0,0x410(%rsp)'),
        90051431: ('488db424100400', 'lea    0x410(%rsp),%rsi'),
        90051439: ('488bbc24300200', 'mov    0x230(%rsp),%rdi'),
        90051447: ('4889da', 'mov    %rbx,%rdx'),
        90051450: ('4989cd', 'mov    %rcx,%r13'),
        90051453: ('ff151d51f000', 'call   *0xf0511d(%rip)'),
        90051459: ('84c0', 'test   %al,%al'),
        90051461: ('0f84e8000000', 'je     0x55e1473'),
        90051467: ('4c8db424890a00', 'lea    0xa89(%rsp),%r14'),
        90051475: ('baff000000', 'mov    $0xff,%edx'),
        90051480: ('4c89f7', 'mov    %r14,%rdi'),
        90051483: ('4c89fe', 'mov    %r15,%rsi'),
        90051486: ('4c8b3d63e1ef00', 'mov    0xefe163(%rip),%r15'),
        90051493: ('41ffd7', 'call   *%r15'),
        90051496: ('488dbc24100400', 'lea    0x410(%rsp),%rdi'),
        90051578: ('4c89a424980700', 'mov    %r12,0x798(%rsp)'),
        90051586: ('8b442430', 'mov    0x30(%rsp),%eax'),
        90051590: ('888424a0070000', 'mov    %al,0x7a0(%rsp)'),
        90051597: ('488dbc24a10700', 'lea    0x7a1(%rsp),%rdi'),
        90051605: ('4c8dbc24100400', 'lea    0x410(%rsp),%r15'),
        90051613: ('baa7000000', 'mov    $0xa7,%edx'),
        90051618: ('4c89fe', 'mov    %r15,%rsi'),
        90051621: ('ff15dde0ef00', 'call   *0xefe0dd(%rip)'),
        90051627: ('4c8bb424800000', 'mov    0x80(%rsp),%r14'),
        90051635: ('498b06', 'mov    (%r14),%rax'),
        90051638: ('4889c1', 'mov    %rax,%rcx'),
        90051641: ('48f7d9', 'neg    %rcx'),
        90051644: ('705e', 'jo     0x55e149c'),
        90051646: ('48b90100000000', 'movabs $0x8000000000000001,%rcx'),
        90051656: ('4839c8', 'cmp    %rcx,%rax'),
        90051659: ('0f840d010000', 'je     0x55e155e'),
        90051665: ('4885c0', 'test   %rax,%rax'),
        90051668: ('0f8404010000', 'je     0x55e155e'),
        90052150: ('410f108fb70000', 'movups 0xb7(%r15),%xmm1'),
        90052158: ('410f1097c70000', 'movups 0xc7(%r15),%xmm2'),
        90052166: ('0f115120', 'movups %xmm2,0x20(%rcx)'),
        90052170: ('0f114910', 'movups %xmm1,0x10(%rcx)'),
        90052174: ('0f1101', 'movups %xmm0,(%rcx)'),
        90052177: ('4889df', 'mov    %rbx,%rdi'),
        90052180: ('e8f7f3e000', 'call   0x63f0a50'),
        90052185: ('eb02', 'jmp    0x55e165d'),
        90052187: ('eb00', 'jmp    0x55e165d'),
        90052189: ('4889c3', 'mov    %rax,%rbx'),
        90052192: ('eb4d', 'jmp    0x55e16af'),
        90052194: ('4889c3', 'mov    %rax,%rbx'),
        90052197: ('4c89a424100400', 'mov    %r12,0x410(%rsp)'),
        90052205: ('8b442430', 'mov    0x30(%rsp),%eax'),
        90052209: ('88842418040000', 'mov    %al,0x418(%rsp)'),
        90052216: ('488db4248a0900', 'lea    0x98a(%rsp),%rsi'),
        90052224: ('baff000000', 'mov    $0xff,%edx'),
        90052229: ('488dbc24190400', 'lea    0x419(%rsp),%rdi'),
        90052237: ('ff1575deef00', 'call   *0xefde75(%rip)'),
        90052243: ('488b8424b80100', 'mov    0x1b8(%rsp),%rax'),
        90052251: ('48898424180500', 'mov    %rax,0x518(%rsp)'),
        90052259: ('0fb644242f', 'movzbl 0x2f(%rsp),%eax'),
        90052264: ('88842420050000', 'mov    %al,0x520(%rsp)'),
        90052271: ('488dbc24100400', 'lea    0x410(%rsp),%rdi'),
        90052279: ('e8546b0400', 'call   0x5628210'),
        90052284: ('4889df', 'mov    %rbx,%rdi'),
        90052287: ('e88cf3e000', 'call   0x63f0a50'),
        90052292: ('ff15f6ddef00', 'call   *0xefddf6(%rip)'),
    },
    'giant_s1a': {
        42825454: ('0f294520', 'movaps %xmm0,0x20(%rbp)'),
        42825458: ('660f1084243001', 'movupd 0x130(%rsp),%xmm0'),
        42825467: ('e9d5a2ffff', 'jmp    0x28d19d5'),
        42825472: ('488b6c2410', 'mov    0x10(%rsp),%rbp'),
        42825477: ('4c8db590000000', 'lea    0x90(%rbp),%r14'),
        42825484: ('488d7c2429', 'lea    0x29(%rsp),%rdi'),
        42825489: ('488db424490d00', 'lea    0xd49(%rsp),%rsi'),
        42825497: ('baff000000', 'mov    $0xff,%edx'),
        42825502: ('ff15e47dc003', 'call   *0x3c07de4(%rip)'),
        42825508: ('4c89642420', 'mov    %r12,0x20(%rsp)'),
        42825513: ('44886c2428', 'mov    %r13b,0x28(%rsp)'),
        42825518: ('4c8da424300100', 'lea    0x130(%rsp),%r12'),
        42825526: ('488d542420', 'lea    0x20(%rsp),%rdx'),
        42825531: ('4c89e7', 'mov    %r12,%rdi'),
        42825534: ('4889de', 'mov    %rbx,%rsi'),
        42825537: ('ff1599f4c003', 'call   *0x3c0f499(%rip)'),
        42825543: ('4c89e7', 'mov    %r12,%rdi'),
        42825546: ('e891c20500', 'call   0x29339e0'),
        42825551: ('660f6f0599a1b7', 'movdqa -0x2485e67(%rip),%xmm0'),
        42825559: ('660f7f442420', 'movdqa %xmm0,0x20(%rsp)'),
        42825565: ('c7442430bbbbbb', 'movl   $0xbbbbbbbb,0x30(%rsp)'),
        42825573: ('488d742420', 'lea    0x20(%rsp),%rsi'),
        42825578: ('4889df', 'mov    %rbx,%rdi'),
        42825581: ('ff1525edc003', 'call   *0x3c0ed25(%rip)'),
    },
    'giant_s1b': {
        87648139: ('0f294520', 'movaps %xmm0,0x20(%rbp)'),
        87648143: ('660f1084243001', 'movupd 0x130(%rsp),%xmm0'),
        87648152: ('e9bba7ffff', 'jmp    0x5390f58'),
        87648157: ('488b6c2410', 'mov    0x10(%rsp),%rbp'),
        87648162: ('4c8db590000000', 'lea    0x90(%rbp),%r14'),
        87648169: ('488d7c2429', 'lea    0x29(%rsp),%rdi'),
        87648174: ('488db424290d00', 'lea    0xd29(%rsp),%rsi'),
        87648182: ('baff000000', 'mov    $0xff,%edx'),
        87648187: ('ff15478d1401', 'call   *0x1148d47(%rip)'),
        87648193: ('4c89642420', 'mov    %r12,0x20(%rsp)'),
        87648198: ('44886c2428', 'mov    %r13b,0x28(%rsp)'),
        87648203: ('4c8dac24300100', 'lea    0x130(%rsp),%r13'),
        87648211: ('488d542420', 'lea    0x20(%rsp),%rdx'),
        87648216: ('4c89ef', 'mov    %r13,%rdi'),
        87648219: ('4889de', 'mov    %rbx,%rsi'),
        87648222: ('ff15fc031501', 'call   *0x11503fc(%rip)'),
        87648228: ('4c89ef', 'mov    %r13,%rdi'),
        87648231: ('e8c4670400', 'call   0x53dcfb0'),
        87648236: ('660f6f05fcb00b', 'movdqa -0x4f44f04(%rip),%xmm0'),
        87648244: ('660f7f442420', 'movdqa %xmm0,0x20(%rsp)'),
        87648250: ('c7442430bbbbbb', 'movl   $0xbbbbbbbb,0x30(%rsp)'),
        87648258: ('488d742420', 'lea    0x20(%rsp),%rsi'),
        87648263: ('4889df', 'mov    %rbx,%rdi'),
        87648266: ('ff1588fc1401', 'call   *0x114fc88(%rip)'),
    },
    'giant_s1c': {
        87692715: ('0f294520', 'movaps %xmm0,0x20(%rbp)'),
        87692719: ('660f1084243001', 'movupd 0x130(%rsp),%xmm0'),
        87692728: ('e9bba7ffff', 'jmp    0x539bd78'),
        87692733: ('488b6c2410', 'mov    0x10(%rsp),%rbp'),
        87692738: ('4c8db590000000', 'lea    0x90(%rbp),%r14'),
        87692745: ('488d7c2429', 'lea    0x29(%rsp),%rdi'),
        87692750: ('488db424290d00', 'lea    0xd29(%rsp),%rsi'),
        87692758: ('baff000000', 'mov    $0xff,%edx'),
        87692763: ('ff1527df1301', 'call   *0x113df27(%rip)'),
        87692769: ('4c89642420', 'mov    %r12,0x20(%rsp)'),
        87692774: ('44886c2428', 'mov    %r13b,0x28(%rsp)'),
        87692779: ('4c8dac24300100', 'lea    0x130(%rsp),%r13'),
        87692787: ('488d542420', 'lea    0x20(%rsp),%rdx'),
        87692792: ('4c89ef', 'mov    %r13,%rdi'),
        87692795: ('4889de', 'mov    %rbx,%rsi'),
        87692798: ('ff15dc551401', 'call   *0x11455dc(%rip)'),
        87692804: ('4c89ef', 'mov    %r13,%rdi'),
        87692807: ('e8a4b90300', 'call   0x53dcfb0'),
        87692812: ('660f6f05dc020b', 'movdqa -0x4f4fd24(%rip),%xmm0'),
        87692820: ('660f7f442420', 'movdqa %xmm0,0x20(%rsp)'),
        87692826: ('c7442430bbbbbb', 'movl   $0xbbbbbbbb,0x30(%rsp)'),
        87692834: ('488d742420', 'lea    0x20(%rsp),%rsi'),
        87692839: ('4889df', 'mov    %rbx,%rdi'),
        87692842: ('ff15684e1401', 'call   *0x1144e68(%rip)'),
    },
    'helper_jc23': {
        88674704: ('55', 'push   %rbp'),
        88674705: ('4157', 'push   %r15'),
        88674707: ('4156', 'push   %r14'),
        88674709: ('4155', 'push   %r13'),
        88674711: ('4154', 'push   %r12'),
        88674713: ('53', 'push   %rbx'),
        88674714: ('4881ec28090000', 'sub    $0x928,%rsp'),
        88674721: ('48897c2428', 'mov    %rdi,0x28(%rsp)'),
        88674726: ('488d5a4c', 'lea    0x4c(%rdx),%rbx'),
        88674730: ('8b425c', 'mov    0x5c(%rdx),%eax'),
        88674733: ('898424f0020000', 'mov    %eax,0x2f0(%rsp)'),
        88674740: ('0f10424c', 'movups 0x4c(%rdx),%xmm0'),
        88674744: ('0f298424e00200', 'movaps %xmm0,0x2e0(%rsp)'),
        88674752: ('488b4230', 'mov    0x30(%rdx),%rax'),
        88674756: ('4889442418', 'mov    %rax,0x18(%rsp)'),
        88674761: ('4c8b6210', 'mov    0x10(%rdx),%r12'),
        88674765: ('488b4218', 'mov    0x18(%rdx),%rax'),
        88674769: ('4889442460', 'mov    %rax,0x60(%rsp)'),
        88674801: ('488b4238', 'mov    0x38(%rdx),%rax'),
        88674805: ('4885c0', 'test   %rax,%rax'),
        88674808: ('752f', 'jne    0x5491229'),
        88674810: ('8b4310', 'mov    0x10(%rbx),%eax'),
        88674813: ('89842490030000', 'mov    %eax,0x390(%rsp)'),
        88674820: ('0f1003', 'movups (%rbx),%xmm0'),
        88674823: ('0f298424800300', 'movaps %xmm0,0x380(%rsp)'),
        88674831: ('488d8424800300', 'lea    0x380(%rsp),%rax'),
        88674839: ('4889f7', 'mov    %rsi,%rdi'),
        88674842: ('4889c6', 'mov    %rax,%rsi'),
        88674845: ('4989cd', 'mov    %rcx,%r13'),
        88674848: ('ff1572520501', 'call   *0x1055272(%rip)'),
        88674854: ('4c89e9', 'mov    %r13,%rcx'),
        88674857: ('4c89bc24e80100', 'mov    %r15,0x1e8(%rsp)'),
        88674865: ('498d5710', 'lea    0x10(%r15),%rdx'),
        88674869: ('48899424080200', 'mov    %rdx,0x208(%rsp)'),
        88674877: ('4889c2', 'mov    %rax,%rdx'),
        88674880: ('418b4608', 'mov    0x8(%r14),%eax'),
        88674884: ('898424b8000000', 'mov    %eax,0xb8(%rsp)'),
        88674891: ('498b06', 'mov    (%r14),%rax'),
        88674894: ('48898424b00000', 'mov    %rax,0xb0(%rsp)'),
        88675984: ('4d89ef', 'mov    %r13,%r15'),
        88675987: ('4c89bc24800300', 'mov    %r15,0x380(%rsp)'),
        88675995: ('8b442410', 'mov    0x10(%rsp),%eax'),
        88675999: ('88842488030000', 'mov    %al,0x388(%rsp)'),
        88676006: ('baff000000', 'mov    $0xff,%edx'),
        88676011: ('488dbc24890300', 'lea    0x389(%rsp),%rdi'),
        88676019: ('488db424290800', 'lea    0x829(%rsp),%rsi'),
        88676027: ('ff1547de0401', 'call   *0x104de47(%rip)'),
        88676033: ('488b442468', 'mov    0x68(%rsp),%rax'),
        88676038: ('48898424880400', 'mov    %rax,0x488(%rsp)'),
        88676046: ('0fb6442415', 'movzbl 0x15(%rsp),%eax'),
        88676051: ('88842490040000', 'mov    %al,0x490(%rsp)'),
        88676058: ('488b8c24100200', 'mov    0x210(%rsp),%rcx'),
        88676066: ('4885c9', 'test   %rcx,%rcx'),
        88676069: ('0f858a0a0000', 'jne    0x5492175'),
        88676075: ('498d47fb', 'lea    -0x5(%r15),%rax'),
        88677166: ('48c1e003', 'shl    $0x3,%rax'),
        88677170: ('488d3480', 'lea    (%rax,%rax,4),%rsi'),
        88677174: ('31d2', 'xor    %edx,%edx'),
        88677176: ('ff1562d90401', 'call   *0x104d962(%rip)'),
        88677182: ('e96d030000', 'jmp    0x5491eb0'),
        88677187: ('baa7000000', 'mov    $0xa7,%edx'),
        88677192: ('488dbc24a10600', 'lea    0x6a1(%rsp),%rdi'),
        88677200: ('488db424390200', 'lea    0x239(%rsp),%rsi'),
        88677208: ('4189c5', 'mov    %eax,%r13d'),
        88677211: ('4989cc', 'mov    %rcx,%r12'),
        88677214: ('ff15a4d90401', 'call   *0x104d9a4(%rip)'),
        88677220: ('4c89a424c80100', 'mov    %r12,0x1c8(%rsp)'),
        88677228: ('4c89a424f00500', 'mov    %r12,0x5f0(%rsp)'),
        88677236: ('44886c2416', 'mov    %r13b,0x16(%rsp)'),
        88677241: ('4488ac24f80500', 'mov    %r13b,0x5f8(%rsp)'),
        88677249: ('baa7000000', 'mov    $0xa7,%edx'),
        88677254: ('488dbc24f90500', 'lea    0x5f9(%rsp),%rdi'),
        88677262: ('488db424a10600', 'lea    0x6a1(%rsp),%rsi'),
        88677270: ('ff156cd90401', 'call   *0x104d96c(%rip)'),
        88677276: ('488b4c2470', 'mov    0x70(%rsp),%rcx'),
        88677281: ('4885c9', 'test   %rcx,%rcx'),
        88677284: ('7470', 'je     0x5491c16'),
        88677286: ('4c8ba424f00100', 'mov    0x1f0(%rsp),%r12'),
        88677294: ('4c03642458', 'add    0x58(%rsp),%r12'),
        88677299: ('837c244001', 'cmpl   $0x1,0x40(%rsp)'),
        88677304: ('48894c2450', 'mov    %rcx,0x50(%rsp)'),
        88677309: ('0f86d3000000', 'jbe    0x5491c96'),
        88677315: ('488b8c24e00100', 'mov    0x1e0(%rsp),%rcx'),
        88677943: ('4889fb', 'mov    %rdi,%rbx'),
        88677946: ('4c8bac24c00000', 'mov    0xc0(%rsp),%r13'),
        88677954: ('0fb68424c80000', 'movzbl 0xc8(%rsp),%eax'),
        88677962: ('89442410', 'mov    %eax,0x10(%rsp)'),
        88677966: ('baff000000', 'mov    $0xff,%edx'),
        88677971: ('488dbc24290800', 'lea    0x829(%rsp),%rdi'),
        88677979: ('488db424c90000', 'lea    0xc9(%rsp),%rsi'),
        88677987: ('ff159fd60401', 'call   *0x104d69f(%rip)'),
        88677993: ('48895c2468', 'mov    %rbx,0x68(%rsp)'),
        88677998: ('e91df8ffff', 'jmp    0x5491690'),
        88678003: ('31c9', 'xor    %ecx,%ecx'),
        88678005: ('31c0', 'xor    %eax,%eax'),
        88678007: ('48898c24c00000', 'mov    %rcx,0xc0(%rsp)'),
        88678015: ('48898c24e00000', 'mov    %rcx,0xe0(%rsp)'),
        88678023: ('48898424000100', 'mov    %rax,0x100(%rsp)'),
        88678031: ('90', 'nop'),
        88678032: ('488dbc24300200', 'lea    0x230(%rsp),%rdi'),
        88678766: ('75e0', 'jne    0x5492150'),
        88678768: ('e91ef6ffff', 'jmp    0x5491793'),
        88678773: ('4983ff04', 'cmp    $0x4,%r15'),
        88678777: ('7509', 'jne    0x5492184'),
        88678779: ('b105', 'mov    $0x5,%cl'),
        88678781: ('488b442428', 'mov    0x28(%rsp),%rax'),
        88678786: ('eb2a', 'jmp    0x54921ae'),
        88678788: ('488dbc24e00400', 'lea    0x4e0(%rsp),%rdi'),
        88678796: ('ba0f010000', 'mov    $0x10f,%edx'),
        88678801: ('488db424890300', 'lea    0x389(%rsp),%rsi'),
        88678809: ('ff1569d30401', 'call   *0x104d369(%rip)'),
        88678815: ('4983ff03', 'cmp    $0x3,%r15'),
        88678819: ('7525', 'jne    0x54921ca'),
        88678821: ('488b442428', 'mov    0x28(%rsp),%rax'),
        88678826: ('8b4c2410', 'mov    0x10(%rsp),%ecx'),
        88678830: ('884808', 'mov    %cl,0x8(%rax)'),
        88678833: ('48c70003000000', 'movq   $0x3,(%rax)'),
        88678840: ('4881c428090000', 'add    $0x928,%rsp'),
        88678847: ('5b', 'pop    %rbx'),
        88678848: ('415c', 'pop    %r12'),
        88678850: ('415d', 'pop    %r13'),
        88678852: ('415e', 'pop    %r14'),
        88678854: ('415f', 'pop    %r15'),
        88678856: ('5d', 'pop    %rbp'),
        88678857: ('c3', 'ret'),
        88678858: ('488dbc24890300', 'lea    0x389(%rsp),%rdi'),
        88678866: ('488db424e00400', 'lea    0x4e0(%rsp),%rsi'),
        88678874: ('ba0f010000', 'mov    $0x10f,%edx'),
        88678879: ('ff1523d30401', 'call   *0x104d323(%rip)'),
        88678885: ('4c89bc24800300', 'mov    %r15,0x380(%rsp)'),
        88678893: ('8b442410', 'mov    0x10(%rsp),%eax'),
        88678897: ('88842488030000', 'mov    %al,0x388(%rsp)'),
        88678904: ('4983ff02', 'cmp    $0x2,%r15'),
        88678908: ('7451', 'je     0x549224f'),
        88678910: ('80bc2490040000', 'cmpb   $0x0,0x490(%rsp)'),
        88678918: ('7447', 'je     0x549224f'),
        88678920: ('488b8c24880400', 'mov    0x488(%rsp),%rcx'),
        88678935: ('898424f0040000', 'mov    %eax,0x4f0(%rsp)'),
        88678942: ('660f288424e002', 'movapd 0x2e0(%rsp),%xmm0'),
        88678951: ('660f298424e004', 'movapd %xmm0,0x4e0(%rsp)'),
        88678960: ('488db424e00400', 'lea    0x4e0(%rsp),%rsi'),
        88678968: ('488bbc24e80100', 'mov    0x1e8(%rsp),%rdi'),
        88678976: ('488b542418', 'mov    0x18(%rsp),%rdx'),
        88678981: ('ff1555420501', 'call   *0x1054255(%rip)'),
        88678987: ('84c0', 'test   %al,%al'),
        88678989: ('741d', 'je     0x549226c'),
        88678991: ('488db424800300', 'lea    0x380(%rsp),%rsi'),
        88678999: ('ba18010000', 'mov    $0x118,%edx'),
        88679004: ('488b7c2428', 'mov    0x28(%rsp),%rdi'),
        88679009: ('ff15a1d20401', 'call   *0x104d2a1(%rip)'),
        88679015: ('e94cffffff', 'jmp    0x54921b8'),
        88679020: ('488b442428', 'mov    0x28(%rsp),%rax'),
        88679025: ('c6400805', 'movb   $0x5,0x8(%rax)'),
        88679029: ('48c70003000000', 'movq   $0x3,(%rax)'),
        88679036: ('488b8424300400', 'mov    0x430(%rsp),%rax'),
        88679044: ('48b90000000000', 'movabs $0x8000000000000000,%rcx'),
        88679054: ('4839c8', 'cmp    %rcx,%rax'),
        88679057: ('755c', 'jne    0x54922ef'),
        88679366: ('eb4e', 'jmp    0x5492416'),
        88679368: ('4989c6', 'mov    %rax,%r14'),
        88679371: ('48899c24800300', 'mov    %rbx,0x380(%rsp)'),
        88679379: ('8b442410', 'mov    0x10(%rsp),%eax'),
        88679383: ('88842488030000', 'mov    %al,0x388(%rsp)'),
        88679390: ('488db424290800', 'lea    0x829(%rsp),%rsi'),
        88679398: ('baff000000', 'mov    $0xff,%edx'),
        88679403: ('488dbc24890300', 'lea    0x389(%rsp),%rdi'),
        88679411: ('ff150fd10401', 'call   *0x104d10f(%rip)'),
        88679417: ('488b442468', 'mov    0x68(%rsp),%rax'),
        88679422: ('48898424880400', 'mov    %rax,0x488(%rsp)'),
        88679430: ('0fb6442415', 'movzbl 0x15(%rsp),%eax'),
        88679435: ('88842490040000', 'mov    %al,0x490(%rsp)'),
        88679442: ('eb05', 'jmp    0x5492419'),
        88679444: ('eb00', 'jmp    0x5492416'),
        88679446: ('4989c6', 'mov    %rax,%r14'),
        88679449: ('488dbc24800300', 'lea    0x380(%rsp),%rdi'),
        88679457: ('e8ea5d1900', 'call   0x5628210'),
    },
    'sublookup_ca': {
        45838960: ('55', 'push   %rbp'),
        45838961: ('4157', 'push   %r15'),
        45838963: ('4156', 'push   %r14'),
        45838965: ('4155', 'push   %r13'),
        45838967: ('4154', 'push   %r12'),
        45838969: ('53', 'push   %rbx'),
        45838970: ('4881ec68080000', 'sub    $0x868,%rsp'),
        45838977: ('4889bc24500200', 'mov    %rdi,0x250(%rsp)'),
        45838985: ('8b4240', 'mov    0x40(%rdx),%eax'),
        45838988: ('89842438010000', 'mov    %eax,0x138(%rsp)'),
        45838995: ('488b4238', 'mov    0x38(%rdx),%rax'),
        45838999: ('48898424300100', 'mov    %rax,0x130(%rsp)'),
        45839007: ('660f104244', 'movupd 0x44(%rdx),%xmm0'),
        45839012: ('660f2984243003', 'movapd %xmm0,0x330(%rsp)'),
        45839021: ('8b4254', 'mov    0x54(%rdx),%eax'),
        45839024: ('89842440030000', 'mov    %eax,0x340(%rsp)'),
        45841771: ('48898424800100', 'mov    %rax,0x180(%rsp)'),
        45841779: ('666666662e0f1f', 'data16 data16 data16 cs nopw 0x0(%rax,%rax,1)'),
        45841792: ('488dbc24880600', 'lea    0x688(%rsp),%rdi'),
        45841800: ('4889ee', 'mov    %rbp,%rsi'),
        45841803: ('e810d288ff', 'call   0x2444fa0'),
        45841808: ('4883bc24880600', 'cmpq   $0x0,0x688(%rsp)'),
        45841817: ('75e5', 'jne    0x2bb7d80'),
        45841819: ('4c89a424c80400', 'mov    %r12,0x4c8(%rsp)'),
        45841827: ('448974246c', 'mov    %r14d,0x6c(%rsp)'),
        45841832: ('4488b424d00400', 'mov    %r14b,0x4d0(%rsp)'),
        45841840: ('baff000000', 'mov    $0xff,%edx'),
        45841845: ('488dbc24d10400', 'lea    0x4d1(%rsp),%rdi'),
        45841853: ('488db424690700', 'lea    0x769(%rsp),%rsi'),
        45841861: ('ff153d779203', 'call   *0x392773d(%rip)'),
        45841867: ('488b8424d80000', 'mov    0xd8(%rsp),%rax'),
        45841875: ('48898424d00500', 'mov    %rax,0x5d0(%rsp)'),
        45841883: ('0fb6442427', 'movzbl 0x27(%rsp),%eax'),
        45841888: ('888424d8050000', 'mov    %al,0x5d8(%rsp)'),
        45841895: ('4883bc24e80000', 'cmpq   $0x0,0xe8(%rsp)'),
        45841904: ('488b8c24680200', 'mov    0x268(%rsp),%rcx'),
        45841912: ('0f859c190000', 'jne    0x2bb979a'),
        45841918: ('498d4424fb', 'lea    -0x5(%r12),%rax'),
        45841923: ('4883f8fe', 'cmp    $0xfffffffffffffffe,%rax'),
        45841927: ('0f828d190000', 'jb     0x2bb979a'),
        45841933: ('4c89a424e00000', 'mov    %r12,0xe0(%rsp)'),
        45841941: ('4883f903', 'cmp    $0x3,%rcx'),
        45841945: ('0f85e1f5ffff', 'jne    0x2bb7400'),
        45841951: ('e976190000', 'jmp    0x2bb979a'),
        45841956: ('48b800f040e966', 'movabs $0x5666e940f000,%rax'),
        45841966: ('4889442440', 'mov    %rax,0x40(%rsp)'),
        45841971: ('e947f7ffff', 'jmp    0x2bb757f'),
        45841976: ('4d85e4', 'test   %r12,%r12'),
        45841979: ('0f848bfdffff', 'je     0x2bb7bcc'),
        45841985: ('48b800407a10f3', 'movabs $0x5af3107a4000,%rax'),
        45841995: ('488b4c2470', 'mov    0x70(%rsp),%rcx'),
        45846001: ('4839f0', 'cmp    %rsi,%rax'),
        45846004: ('0f93442427', 'setae  0x27(%rsp)'),
        45846009: ('4c8ba424400100', 'mov    0x140(%rsp),%r12'),
        45846017: ('440fb6b4244801', 'movzbl 0x148(%rsp),%r14d'),
        45846026: ('baff000000', 'mov    $0xff,%edx'),
        45846031: ('488dbc24690700', 'lea    0x769(%rsp),%rdi'),
        45846039: ('488db424490100', 'lea    0x149(%rsp),%rsi'),
        45846047: ('ff15e3669203', 'call   *0x39266e3(%rip)'),
        45846053: ('48899c24d80000', 'mov    %rbx,0xd8(%rsp)'),
        45846061: ('e9a3edffff', 'jmp    0x2bb7bd5'),
        45846066: ('4889df', 'mov    %rbx,%rdi'),
        45846069: ('488db424800200', 'lea    0x280(%rsp),%rsi'),
        45846077: ('e8ced59901', 'call   0x4556410'),
        45846082: ('a801', 'test   $0x1,%al'),
        45846084: ('0f8582edffff', 'jne    0x2bb7bcc'),
        45846090: ('483b5318', 'cmp    0x18(%rbx),%rdx'),
        45846094: ('0f8378edffff', 'jae    0x2bb7bcc'),
        45848427: ('e9d6feffff', 'jmp    0x2bb9646'),
        45848432: ('31ff', 'xor    %edi,%edi'),
        45848434: ('488d35ffdc8c03', 'lea    0x38cdcff(%rip),%rsi'),
        45848441: ('ff1529b79203', 'call   *0x392b729(%rip)'),
        45848447: ('488b4c2410', 'mov    0x10(%rsp),%rcx'),
        45848452: ('4c01e1', 'add    %r12,%rcx'),
        45848455: ('48c7c0ffffffff', 'mov    $0xffffffffffffffff,%rax'),
        45848462: ('480f42c8', 'cmovb  %rax,%rcx'),
        45848466: ('4889c8', 'mov    %rcx,%rax'),
        45848469: ('e951e8ffff', 'jmp    0x2bb7feb'),
        45848474: ('488b9c24500200', 'mov    0x250(%rsp),%rbx'),
        45848482: ('488d7b08', 'lea    0x8(%rbx),%rdi'),
        45848486: ('4983fc04', 'cmp    $0x4,%r12'),
        45848490: ('750b', 'jne    0x2bb97b7'),
        45848492: ('c6070c', 'movb   $0xc,(%rdi)'),
        45848495: ('41bc03000000', 'mov    $0x3,%r12d'),
        45848501: ('eb13', 'jmp    0x2bb97ca'),
        45848503: ('ba10010000', 'mov    $0x110,%edx'),
        45848508: ('488db424d00400', 'lea    0x4d0(%rsp),%rsi'),
        45848516: ('ff153e5d9203', 'call   *0x3925d3e(%rip)'),
        45848522: ('4c8923', 'mov    %r12,(%rbx)'),
        45848525: ('4889d8', 'mov    %rbx,%rax'),
        45848528: ('4881c468080000', 'add    $0x868,%rsp'),
        45848535: ('5b', 'pop    %rbx'),
        45848536: ('415c', 'pop    %r12'),
        45848538: ('415d', 'pop    %r13'),
        45848540: ('415e', 'pop    %r14'),
        45848542: ('415f', 'pop    %r15'),
        45848544: ('5d', 'pop    %rbp'),
        45848545: ('c3', 'ret'),
        45848546: ('488d3dd76c8703', 'lea    0x3876cd7(%rip),%rdi'),
        45848553: ('ff1541609203', 'call   *0x3926041(%rip)'),
        45848559: ('0f0b', 'ud2'),
        45848561: ('4889c3', 'mov    %rax,%rbx'),
        45848564: ('488dbc24400100', 'lea    0x140(%rsp),%rdi'),
        45848572: ('e8ef250e00', 'call   0x2c9bdf0'),
        45848577: ('eb75', 'jmp    0x2bb9878'),
        45848579: ('ff15b75c9203', 'call   *0x3925cb7(%rip)'),
        45848585: ('eb6a', 'jmp    0x2bb9875'),
        45848587: ('eb68', 'jmp    0x2bb9875'),
        45848589: ('4889c3', 'mov    %rax,%rbx'),
        45848592: ('488dbc24f80000', 'lea    0xf8(%rsp),%rdi'),
        45848600: ('e883170e00', 'call   0x2c9afa0'),
        45848605: ('eb59', 'jmp    0x2bb9878'),
        45848607: ('ff159b5c9203', 'call   *0x3925c9b(%rip)'),
        45848613: ('eb4e', 'jmp    0x2bb9875'),
        45848615: ('eb4c', 'jmp    0x2bb9875'),
        45848617: ('4889c3', 'mov    %rax,%rbx'),
        45848620: ('4c89a424c80400', 'mov    %r12,0x4c8(%rsp)'),
        45848628: ('4488b424d00400', 'mov    %r14b,0x4d0(%rsp)'),
        45848636: ('488db424690700', 'lea    0x769(%rsp),%rsi'),
        45848644: ('baff000000', 'mov    $0xff,%edx'),
        45848649: ('488dbc24d10400', 'lea    0x4d1(%rsp),%rdi'),
        45848657: ('ff15b15c9203', 'call   *0x3925cb1(%rip)'),
        45848663: ('488b8424d80000', 'mov    0xd8(%rsp),%rax'),
        45848671: ('48898424d00500', 'mov    %rax,0x5d0(%rsp)'),
        45848679: ('0fb6442427', 'movzbl 0x27(%rsp),%eax'),
        45848684: ('888424d8050000', 'mov    %al,0x5d8(%rsp)'),
        45848691: ('eb03', 'jmp    0x2bb9878'),
        45848693: ('4889c3', 'mov    %rax,%rbx'),
        45848696: ('488dbc24c80400', 'lea    0x4c8(%rsp),%rdi'),
        45848704: ('e89b2c0d00', 'call   0x2c8c520'),
        45848709: ('4889df', 'mov    %rbx,%rdi'),
        45848712: ('e8c3718303', 'call   0x63f0a50'),
        45848717: ('ff152d5c9203', 'call   *0x3925c2d(%rip)'),
    },
    'sublookup_jc1': {
        45830816: ('55', 'push   %rbp'),
        45830817: ('4157', 'push   %r15'),
        45830819: ('4156', 'push   %r14'),
        45830821: ('4155', 'push   %r13'),
        45830823: ('4154', 'push   %r12'),
        45830825: ('53', 'push   %rbx'),
        45830826: ('4881ec88070000', 'sub    $0x788,%rsp'),
        45830833: ('4889bc24280300', 'mov    %rdi,0x328(%rsp)'),
        45830841: ('8b4240', 'mov    0x40(%rdx),%eax'),
        45830844: ('89842450010000', 'mov    %eax,0x150(%rsp)'),
        45830851: ('488b4238', 'mov    0x38(%rdx),%rax'),
        45830855: ('48898424480100', 'mov    %rax,0x148(%rsp)'),
        45830863: ('660f104244', 'movupd 0x44(%rdx),%xmm0'),
        45830868: ('660f2984245003', 'movapd %xmm0,0x350(%rsp)'),
        45830877: ('8b4254', 'mov    0x54(%rdx),%eax'),
        45830880: ('89842460030000', 'mov    %eax,0x360(%rsp)'),
        45832579: ('75eb', 'jne    0x2bb5970'),
        45832581: ('4989df', 'mov    %rbx,%r15'),
        45832584: ('89e9', 'mov    %ebp,%ecx'),
        45832586: ('4c89bc24700500', 'mov    %r15,0x570(%rsp)'),
        45832594: ('89cd', 'mov    %ecx,%ebp'),
        45832596: ('888c2478050000', 'mov    %cl,0x578(%rsp)'),
        45832603: ('baff000000', 'mov    $0xff,%edx'),
        45832608: ('488dbc24790500', 'lea    0x579(%rsp),%rdi'),
        45832616: ('488db424890600', 'lea    0x689(%rsp),%rsi'),
        45832624: ('ff15529b9203', 'call   *0x3929b52(%rip)'),
        45832630: ('488b8424380100', 'mov    0x138(%rsp),%rax'),
        45832638: ('48898424780600', 'mov    %rax,0x678(%rsp)'),
        45832646: ('0fb6442405', 'movzbl 0x5(%rsp),%eax'),
        45832651: ('88842480060000', 'mov    %al,0x680(%rsp)'),
        45832658: ('4883bc24400100', 'cmpq   $0x0,0x140(%rsp)'),
        45832667: ('0f85010e0000', 'jne    0x2bb67e2'),
        45836006: ('483b442458', 'cmp    0x58(%rsp),%rax'),
        45836011: ('0f93442405', 'setae  0x5(%rsp)'),
        45836016: ('488b9c24880100', 'mov    0x188(%rsp),%rbx'),
        45836024: ('0fb6ac24900100', 'movzbl 0x190(%rsp),%ebp'),
        45836032: ('baff000000', 'mov    $0xff,%edx'),
        45836037: ('488dbc24890600', 'lea    0x689(%rsp),%rdi'),
        45836045: ('488db424910100', 'lea    0x191(%rsp),%rsi'),
        45836053: ('ff15ed8d9203', 'call   *0x3928ded(%rip)'),
        45836059: ('4c89b424380100', 'mov    %r14,0x138(%rsp)'),
        45836067: ('e9c0f0ffff', 'jmp    0x2bb57e8'),
        45836072: ('31ff', 'xor    %edi,%edi'),
        45836074: ('488d352f0d8d03', 'lea    0x38d0d2f(%rip),%rsi'),
        45836081: ('ff1571e79203', 'call   *0x392e771(%rip)'),
        45836087: ('488b442440', 'mov    0x40(%rsp),%rax'),
        45836092: ('488b742420', 'mov    0x20(%rsp),%rsi'),
        45836097: ('4801f0', 'add    %rsi,%rax'),
        45836100: ('48c7c1ffffffff', 'mov    $0xffffffffffffffff,%rcx'),
        45836231: ('4c01f3', 'add    %r14,%rbx'),
        45836234: ('48c7c0ffffffff', 'mov    $0xffffffffffffffff,%rax'),
        45836241: ('480f42d8', 'cmovb  %rax,%rbx'),
        45836245: ('4889d8', 'mov    %rbx,%rax'),
        45836248: ('488b4c2438', 'mov    0x38(%rsp),%rcx'),
        45836253: ('e92cfcffff', 'jmp    0x2bb640e'),
        45836258: ('488b9c24280300', 'mov    0x328(%rsp),%rbx'),
        45836266: ('488d7b08', 'lea    0x8(%rbx),%rdi'),
        45836270: ('4983ff04', 'cmp    $0x4,%r15'),
        45836274: ('750b', 'jne    0x2bb67ff'),
        45836276: ('c60705', 'movb   $0x5,(%rdi)'),
        45836279: ('41bf03000000', 'mov    $0x3,%r15d'),
        45836285: ('eb13', 'jmp    0x2bb6812'),
        45836287: ('ba10010000', 'mov    $0x110,%edx'),
        45836292: ('488db424780500', 'lea    0x578(%rsp),%rsi'),
        45836300: ('ff15f68c9203', 'call   *0x3928cf6(%rip)'),
        45836306: ('4c893b', 'mov    %r15,(%rbx)'),
        45836309: ('4889d8', 'mov    %rbx,%rax'),
        45836312: ('4881c488070000', 'add    $0x788,%rsp'),
        45836319: ('5b', 'pop    %rbx'),
        45836320: ('415c', 'pop    %r12'),
        45836322: ('415d', 'pop    %r13'),
        45836324: ('415e', 'pop    %r14'),
        45836326: ('415f', 'pop    %r15'),
        45836328: ('5d', 'pop    %rbp'),
        45836329: ('c3', 'ret'),
        45836330: ('488d3d8f9c8703', 'lea    0x3879c8f(%rip),%rdi'),
        45836337: ('ff15f98f9203', 'call   *0x3928ff9(%rip)'),
        45836343: ('0f0b', 'ud2'),
        45836345: ('4989c6', 'mov    %rax,%r14'),
        45836348: ('488dbc24880100', 'lea    0x188(%rsp),%rdi'),
        45836390: ('eb50', 'jmp    0x2bb68b8'),
        45836392: ('eb4e', 'jmp    0x2bb68b8'),
        45836394: ('4989c6', 'mov    %rax,%r14'),
        45836397: ('48899c24700500', 'mov    %rbx,0x570(%rsp)'),
        45836405: ('4088ac24780500', 'mov    %bpl,0x578(%rsp)'),
        45836413: ('488db424890600', 'lea    0x689(%rsp),%rsi'),
        45836421: ('baff000000', 'mov    $0xff,%edx'),
        45836426: ('488dbc24790500', 'lea    0x579(%rsp),%rdi'),
        45836434: ('ff15708c9203', 'call   *0x3928c70(%rip)'),
        45836440: ('488b8424380100', 'mov    0x138(%rsp),%rax'),
        45836448: ('48898424780600', 'mov    %rax,0x678(%rsp)'),
        45836456: ('0fb6442405', 'movzbl 0x5(%rsp),%eax'),
        45836461: ('88842480060000', 'mov    %al,0x680(%rsp)'),
        45836468: ('eb05', 'jmp    0x2bb68bb'),
        45836470: ('eb00', 'jmp    0x2bb68b8'),
        45836472: ('4989c6', 'mov    %rax,%r14'),
        45836475: ('488dbc24700500', 'lea    0x570(%rsp),%rdi'),
    },
}

EXPECTED = {'bodies': 34, 'rows': 37685, 'jc_sites': 6, 'adapter_sites': 10, 's1_sites': 3, 's2_sites': 3, 's3_sites': 4, 'sublookup_ca_staging_stores': 9, 'sublookup_jc1_staging_stores': 6, 'helper_s2_rbx_stores': 22, 'big1_staging_stores': 55, 'big2_staging_stores': 56, 'big3_record_stores': 11, 'big3_memcpys': 8}


def _hx(value):
    return f'0x{value:x}'


def _section_bytes(data, secs, start, end):
    for sec in secs:
        if sec['type'] != 8 and sec['address'] <= start and end <= sec['address'] + sec['size']:
            off = sec['offset'] + (start - sec['address'])
            return data[off:off + end - start]
    raise AssertionError(f'no file-backed section covers {start:#x}..{end:#x}')


def _digest(data, secs, start, end):
    return hashlib.sha256(_section_bytes(data, secs, start, end)).hexdigest()


_LINE_RE = re.compile(r'^\s*([0-9a-f]+):\t([0-9a-f ]+)\t(.*)$')


def _decode(data, secs, start, end):
    body = _section_bytes(data, secs, start, end)
    handle = tempfile.NamedTemporaryFile(suffix='.bin', delete=False)
    try:
        handle.write(body)
        handle.close()
        out = subprocess.check_output(
            ['objdump', '-D', '-b', 'binary', '-m', 'i386:x86-64',
             f'--adjust-vma={start:#x}', handle.name], text=True)
    finally:
        Path(handle.name).unlink()
    _foundation_decode(out, start, end, body)
    rows = {}
    for line in out.splitlines():
        match = _LINE_RE.match(line)
        if match:
            rows[int(match.group(1), 16)] = (
                re.sub(r'\s', '', match.group(2)),
                match.group(3).strip().split('#')[0].rstrip())
    return rows


def _check_pins(rows, pins, what):
    if rows != pins:
        for address in sorted(set(rows) | set(pins)):
            if rows.get(address) != pins.get(address):
                raise AssertionError(
                    f'{what} instruction at {address:#x} differs: '
                    f'{rows.get(address)!r} != {pins.get(address)!r}')
        raise AssertionError(f'{what} instructions differ')
    return rows


def _check_pins_subset(rows, pins, what):
    for address, want in pins.items():
        if rows.get(address) != want:
            raise AssertionError(
                f'{what} instruction at {address:#x} differs: '
                f'{rows.get(address)!r} != {want!r}')
    return rows


def _rela_entries(data, secs):
    """All (offset, type, sym, addend) tuples from SHT_RELA sections."""
    entries = []
    for sec in secs:
        if sec['type'] != 4:
            continue
        if sec['size'] % 24 != 0:
            raise AssertionError(f"truncated.{sec['name'][1:]} section")
        blob = _section_bytes(data, secs, sec['address'],
                              sec['address'] + sec['size'])
        for off in range(0, len(blob) - 23, 24):
            r_offset, r_info, r_addend = struct.unpack_from('<QQq', blob, off)
            entries.append((r_offset, r_info & 0xFFFFFFFF, r_info >> 32,
                            r_addend))
    return entries


def _dynsym_name(data, secs, index):
    """Resolve a .dynsym index to its symbol name via sh_link."""
    shoff = struct.unpack_from('<Q', data, 40)[0]
    entsize = struct.unpack_from('<H', data, 58)[0]
    dynsym_idx = next((i for i, s in enumerate(secs) if s['type'] == 11), None)
    if dynsym_idx is None:
        raise AssertionError('missing.dynsym section')
    link = struct.unpack_from('<I', data, shoff + dynsym_idx * entsize + 40)[0]
    if link >= len(secs):
        raise AssertionError('dynamic symbol table link out of range')
    dynsym = secs[dynsym_idx]
    dynstr = secs[link]
    st_name = struct.unpack_from(
        '<I', data, dynsym['offset'] + index * 24)[0]
    table = _section_bytes(data, secs, dynstr['address'],
                           dynstr['address'] + dynstr['size'])
    end = table.find(b'\0', st_name)
    try:
        return table[st_name:end].decode('utf-8')
    except UnicodeDecodeError:
        raise AssertionError('dynamic symbol name is not valid UTF-8')


def _slot_fact(data, secs, relas, slot, want_type, want_addend=None,
               want_sym=None):
    hits = [e for e in relas if e[0] == slot]
    if len(hits) != 1:
        raise AssertionError(f'slot {_hx(slot)} has {len(hits)} relocations')
    _off, rtype, sym, addend = hits[0]
    if rtype != want_type:
        raise AssertionError(f'slot {_hx(slot)} relocation type is {rtype}')
    fact = {'slot': _hx(slot), 'rela_type': rtype}
    if want_addend is not None:
        if addend != want_addend:
            raise AssertionError(
                f'slot {_hx(slot)} relocation addend is {_hx(addend)}')
        fact['rela_addend'] = _hx(addend)
    if want_sym is not None:
        name = _dynsym_name(data, secs, sym)
        if name != want_sym:
            raise AssertionError(
                f'slot {_hx(slot)} binds {name!r}, not {want_sym!r}')
        fact['symbol'] = name
    content = struct.unpack_from(
        '<Q', _section_bytes(data, secs, slot, slot + 8), 0)[0]
    if content != 0:
        raise AssertionError(f'slot {_hx(slot)} initialised content is not zero')
    fact['initialised_content'] = '0x0'
    return fact


_REG64 = {}
for _full, _base in [('rax', 'rax'), ('eax', 'rax'), ('ax', 'rax'),
                     ('al', 'rax'), ('ah', 'rax'), ('rbx', 'rbx'),
                     ('ebx', 'rbx'), ('bx', 'rbx'), ('bl', 'rbx'),
                     ('bh', 'rbx'), ('rcx', 'rcx'), ('ecx', 'rcx'),
                     ('cx', 'rcx'), ('cl', 'rcx'), ('ch', 'rcx'),
                     ('rdx', 'rdx'), ('edx', 'rdx'), ('dx', 'rdx'),
                     ('dl', 'rdx'), ('dh', 'rdx'), ('rsi', 'rsi'),
                     ('esi', 'rsi'), ('si', 'rsi'), ('sil', 'rsi'),
                     ('rdi', 'rdi'), ('edi', 'rdi'), ('di', 'rdi'),
                     ('dil', 'rdi'), ('rbp', 'rbp'), ('ebp', 'rbp'),
                     ('bp', 'rbp'), ('bpl', 'rbp'), ('rsp', 'rsp'),
                     ('esp', 'rsp'), ('sp', 'rsp'), ('spl', 'rsp')]:
    _REG64[_full] = _base
for _i in range(8, 16):
    for _suf in ('', 'd', 'w', 'b'):
        _REG64[f'r{_i}{_suf}'] = f'r{_i}'

_REG_WIDTH = {}
for _base in ('rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp'):
    _REG_WIDTH[_base] = 8
for _i in range(8, 16):
    _REG_WIDTH[f'r{_i}'] = 8
for _n32 in ('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp'):
    _REG_WIDTH[_n32] = 4
for _i in range(8, 16):
    _REG_WIDTH[f'r{_i}d'] = 4
    _REG_WIDTH[f'r{_i}w'] = 2
    _REG_WIDTH[f'r{_i}b'] = 1
for _n16 in ('ax', 'bx', 'cx', 'dx', 'si', 'di', 'bp', 'sp'):
    _REG_WIDTH[_n16] = 2
for _n8 in ('al', 'ah', 'bl', 'bh', 'cl', 'ch', 'dl', 'dh',
            'sil', 'dil', 'bpl', 'spl'):
    _REG_WIDTH[_n8] = 1

_MEMFULL_RE = re.compile(
    r'^(-?0x[0-9a-f]+)?\(%([a-z0-9]+)(?:,%([a-z0-9]+)(?:,([0-9]+))?)?\)$')
_STORE_BASES = {'mov', 'movabs', 'movups', 'movaps', 'movdqa', 'movdqu',
                'movupd', 'movapd', 'movsd', 'movss'}
_XMM_STORES = {'movups', 'movaps', 'movdqa', 'movdqu', 'movupd', 'movapd'}


def _split_ops(text):
    parts = text.split(None, 1)
    if len(parts) < 2:
        return (parts[0] if parts else ''), []
    ops, depth, cur = [], 0, ''
    for ch in parts[1]:
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
        if ch == ',' and depth == 0:
            ops.append(cur.strip())
            cur = ''
        else:
            cur += ch
    if cur.strip():
        ops.append(cur.strip())
    return parts[0], ops


def _base_mnem(mnem):
    if mnem in _STORE_BASES:
        return mnem
    if mnem and mnem[-1] in 'bwlq' and mnem[:-1] in _STORE_BASES:
        return mnem[:-1]
    return mnem


def _store_width(mnem, base_mnem, src_tok):
    if base_mnem in _XMM_STORES:
        return 16
    if mnem != base_mnem and mnem[-1] in 'bwlq':
        return {'b': 1, 'w': 2, 'l': 4, 'q': 8}[mnem[-1]]
    if src_tok.startswith('%xmm'):
        return 16
    if src_tok.startswith('%'):
        return _REG_WIDTH.get(src_tok[1:], 8)
    return 8


def _stores(rows):
    """All stores to memory: (addr, disp, base_reg, width, text)."""
    out = []
    for addr in sorted(rows):
        _b, text = rows[addr]
        mnem, ops = _split_ops(text)
        base_mnem = _base_mnem(mnem)
        if base_mnem not in _STORE_BASES or len(ops) < 2:
            continue
        match = _MEMFULL_RE.match(ops[-1])
        if not match:
            continue
        disp = int(match.group(1), 16) if match.group(1) else 0
        if match.group(1) and match.group(1).startswith('-'):
            disp = -int(match.group(1)[1:], 16)
        base = _REG64.get(match.group(2), match.group(2))
        out.append((addr, disp, base,
                    _store_width(mnem, base_mnem, ops[0]), text))
    return out


def _slot_calls(rows, slot):
    """Addresses of `call *disp(%rip)` rows whose target is `slot`."""
    out = []
    for addr in sorted(rows):
        raw, text = rows[addr]
        if raw.startswith('ff15') and len(raw) == 12:
            disp = struct.unpack('<i', bytes.fromhex(raw[4:]))[0]
            if addr + 6 + disp == slot:
                out.append(addr)
    return out


def _binding_before(rows, reg, before, window=8):
    """Most recent binding of %reg within `window` rows before `before`.

    Returns ('stack', disp) as the disp int for an rsp-relative lea,
    the source register name for a register move, the immediate for
    a constant load, or None when no binding is found in the window.
    """
    addrs = [a for a in sorted(rows) if a < before][-window:]
    found = {}
    for addr in addrs:
        _b, text = rows[addr]
        mnem, ops = _split_ops(text)
        if len(ops) < 2:
            continue
        dst = ops[-1]
        if not dst.startswith('%'):
            continue
        dst_reg = _REG64.get(dst[1:])
        if dst_reg is None or dst_reg == 'rsp':
            continue
        src = ops[0]
        lea = _MEMFULL_RE.match(src)
        if mnem == 'lea' and lea and _REG64.get(lea.group(2)) == 'rsp' \
                and not lea.group(3):
            disp = int(lea.group(1), 16) if lea.group(1) else 0
            found[dst_reg] = ('stack', disp)
        elif src.startswith('%'):
            src_reg = _REG64.get(src[1:])
            if src_reg == 'rsp':
                found[dst_reg] = ('stack', 0)
            elif src_reg in found:
                found[dst_reg] = found[src_reg]
            else:
                found[dst_reg] = ('reg', src_reg)
        elif src.startswith('$'):
            found[dst_reg] = ('imm', int(src[1:], 16))
        else:
            found.pop(dst_reg, None)
    got = found.get(reg)
    if got is None:
        return None
    kind, value = got
    if kind == 'stack':
        return value
    if kind == 'imm':
        return value
    return value


def _memcpy_args(rows, call_addr):
    """(dst, src, size) for a memcpy-slot call from its setup rows."""
    dst = _binding_before(rows, 'rdi', call_addr)
    src = _binding_before(rows, 'rsi', call_addr)
    size = _binding_before(rows, 'rdx', call_addr)
    return dst, src, size


def _memcpy_census(rows):
    out = []
    for addr in _slot_calls(rows, MEMCPY_SLOT):
        out.append((addr,) + _memcpy_args(rows, addr))
    return out


def _value_writes(rows, reg, before):
    """Addresses of value writes to %reg before `before` (push/pop of
    the callee-save frame excluded)."""
    aliases = {name for name, base in _REG64.items() if base == reg}
    out = []
    for addr in sorted(rows):
        if addr >= before:
            break
        _b, text = rows[addr]
        mnem, ops = _split_ops(text)
        if mnem in ('push', 'pop') or not ops:
            continue
        dst = ops[-1]
        if dst.startswith('%') and dst[1:] in aliases:
            out.append(addr)
    return out


def _e8_callers(data, secs, ordered, targets):
    """Binary-wide E8 census: target name -> [(site, (fde_lo, fde_hi))]."""
    import bisect
    text_sec = next((s for s in secs if s['name'] == '.text'), None)
    if text_sec is None:
        raise AssertionError('missing.text section')
    tbody = _section_bytes(data, secs, text_sec['address'],
                           text_sec['address'] + text_sec['size'])
    tva = text_sec['address']
    starts = [o['start'] for o in ordered]

    def fde_of(va):
        i = bisect.bisect_right(starts, va) - 1
        if i >= 0 and ordered[i]['start'] <= va < ordered[i]['end']:
            return (ordered[i]['start'], ordered[i]['end'])
        return None

    want = {v: k for k, v in targets.items()}
    hits = {k: [] for k in targets}
    pos = 0
    while True:
        j = tbody.find(b'\xe8', pos)
        if j < 0:
            break
        rel = struct.unpack_from('<i', tbody, j + 1)[0]
        tgt = tva + j + 5 + rel
        if tgt in want:
            hits[want[tgt]].append((tva + j, fde_of(tva + j)))
        pos = j + 1
    return hits


def _slot_callers(data, secs, ordered, slots):
    """Binary-wide ff15 census: slot name -> [(site, (fde_lo, fde_hi))]."""
    import bisect
    text_sec = next((s for s in secs if s['name'] == '.text'), None)
    if text_sec is None:
        raise AssertionError('missing.text section')
    tbody = _section_bytes(data, secs, text_sec['address'],
                           text_sec['address'] + text_sec['size'])
    tva = text_sec['address']
    starts = [o['start'] for o in ordered]

    def fde_of(va):
        i = bisect.bisect_right(starts, va) - 1
        if i >= 0 and ordered[i]['start'] <= va < ordered[i]['end']:
            return (ordered[i]['start'], ordered[i]['end'])
        return None

    want = {v: k for k, v in slots.items()}
    hits = {k: [] for k in slots}
    pos = 0
    while True:
        j = tbody.find(b'\xff\x15', pos)
        if j < 0:
            break
        disp = struct.unpack_from('<i', tbody, j + 2)[0]
        tgt = tva + j + 6 + disp
        if tgt in want:
            hits[want[tgt]].append((tva + j, fde_of(tva + j)))
        pos = j + 1
    return hits


def _e8_sites_in(rows, target):
    """Direct E8 call sites to `target` within one decoded body."""
    out = []
    for addr in sorted(rows):
        _b, text = rows[addr]
        mnem, ops = _split_ops(text)
        if mnem != 'call' or not ops:
            continue
        try:
            got = int(ops[0], 16)
        except ValueError:
            continue
        if got == target:
            out.append(addr)
    return out


def _fmt_memcpy(entry):
    a, d, s, n = entry
    return {'site': _hx(a),
            'dst': _hx(d) if isinstance(d, int) else d,
            'src': _hx(s) if isinstance(s, int) else s,
            'size': _hx(n) if isinstance(n, int) else n}


def _fmt_stores(stores):
    return [{'site': _hx(a), 'disp': _hx(d), 'width': w}
            for a, d, _b, w, _t in stores]


def analyze(data):
    secs = sections(data)
    summary, ordered, _gaps = fde_extents(data)
    by_start = {o['start']: o for o in ordered}
    all_bodies = dict(ANCHORS)
    all_bodies.update(BODIES)
    for name, body in all_bodies.items():
        start, end = body['range']
        if start not in by_start or by_start[start]['end'] != end:
            raise AssertionError(f'{name} range is not an FDE extent')
        if _digest(data, secs, start, end) != body['sha256']:
            raise AssertionError(f'{name} differs from its pinned digest')
    decoded = {}
    for name, body in BODIES.items():
        start, end = body['range']
        rows = _decode(data, secs, start, end)
        if name in PINNED_ROWS:
            _check_pins(rows, PINNED_ROWS[name], name)
        if name in PINNED_ROWS_PARTIAL:
            _check_pins_subset(rows, PINNED_ROWS_PARTIAL[name], name)
        decoded[name] = rows
    relas = _rela_entries(data, secs)
    slots = {
        'memcpy': _slot_fact(data, secs, relas, MEMCPY_SLOT, 6,
                             want_sym='memcpy'),
        's1': _slot_fact(data, secs, relas, S1_SLOT, 8,
                         want_addend=ANCHORS['s1']['range'][0]),
        's2': _slot_fact(data, secs, relas, S2_SLOT, 8,
                         want_addend=ANCHORS['s2']['range'][0]),
        's3': _slot_fact(data, secs, relas, S3_SLOT, 8,
                         want_addend=ANCHORS['s3']['range'][0]),
        'helper_s2': _slot_fact(data, secs, relas, HELPER_S2_SLOT, 8,
                                want_addend=BODIES['helper_s2']['range'][0]),
        'pred_a': _slot_fact(data, secs, relas, PRED_A_SLOT, 8,
                             want_addend=BODIES['pred_a']['range'][0]),
        'pred_b': _slot_fact(data, secs, relas, PRED_B_SLOT, 8,
                             want_addend=BODIES['pred_b']['range'][0]),
    }
    # No relocation names a join consumer: the jc FDEs are reached
    # only by direct E8 calls (censused below).
    for name in ('jc1', 'jc2', 'jc3'):
        start = ANCHORS[name]['range'][0]
        if any(e[3] == start for e in relas):
            raise AssertionError(f'a relocation names {name}')

    # Binary-wide caller censuses.
    e8_targets = {}
    for name in list(ANCHORS) + list(BODIES):
        e8_targets[name] = all_bodies[name]['range'][0]
    e8_hits = _e8_callers(data, secs, ordered,
                          {k: e8_targets[k] for k in EXPECTED_E8_CALLERS})
    e8_record = {}
    for name, want in EXPECTED_E8_CALLERS.items():
        got = sorted((site, fde[0]) for site, fde in e8_hits[name])
        if got != sorted(want):
            raise AssertionError(
                f'E8 callers of {name} differ: {got!r} != {want!r}')
        e8_record[name] = [
            {'site': _hx(s), 'caller_fde': _hx(f)} for s, f in got]
    slot_hits = _slot_callers(data, secs, ordered, SLOT_OF)
    slot_record = {}
    for name, want in EXPECTED_SLOT_CALLERS.items():
        got = sorted((site, fde[0]) for site, fde in slot_hits[name])
        if got != sorted(want):
            raise AssertionError(
                f'slot callers of {name} differ: {got!r} != {want!r}')
        # Each censused site must be a genuine decoded call row in
        # its caller FDE.
        for site, fde_start in got:
            fde_name = next(
                n for n, b in BODIES.items()
                if b['range'][0] == fde_start)
            if site not in _slot_calls(decoded[fde_name], SLOT_OF[name]):
                raise AssertionError(
                    f'slot site {_hx(site)} is not a decoded call row '
                    f'in {fde_name}')
        slot_record[name] = [
            {'site': _hx(s), 'caller_fde': _hx(f)} for s, f in got]

    counters = {'bodies': len(all_bodies),
                'rows': sum(len(r) for r in decoded.values()),
                'jc_sites': 6, 'adapter_sites': 10,
                's1_sites': 3, 's2_sites': 3, 's3_sites': 4}
    ev = {}
    site_records = []

    # (i) A wrappers: the jc array is the helper's output record at
    # [rsp+0x80]; its tail round-trips through a second staging
    # record at [rsp+0x190].
    for name, (helper, hsite, jc, jsite) in WRAPPER_A.items():
        rows = decoded[name]
        mc = _memcpy_census(rows)
        want_mc = [(a, d, s, n) for a, d, s, n in mc]
        if len(mc) != 2 or mc[0][1:] != (0x199, 0x89, 0x10f) \
                or mc[1][1:] != (0x89, 0x199, 0x10f):
            raise AssertionError(f'{name} memcpy census differs: {mc!r}')
        if _e8_sites_in(rows, BODIES[helper]['range'][0]) != [hsite]:
            raise AssertionError(f'{name} helper call sites differ')
        if _binding_before(rows, 'rdi', hsite) != 0x80:
            raise AssertionError(f'{name} helper output is not [rsp+0x80]')
        if _binding_before(rows, 'r8', jsite) != 0x80:
            raise AssertionError(f'{name} jc array is not [rsp+0x80]')
        ev[name] = {
            'helper': helper, 'helper_call': _hx(hsite),
            'array_base_rsp': '0x80',
            'tail_round_trip_memcpys': [_fmt_memcpy(e) for e in mc]}
        site_records.append({
            'site': _hx(jsite), 'callee': jc, 'caller_fde': name,
            'kind': 'helper-output-record',
            'production': (
                f'the 0x118-byte output record of {helper}, staged '
                f'at [rsp+0x80] in {name}; its 0x10f-byte tail is '
                f'copied out to a second staging record at '
                f'[rsp+0x190] and back verbatim before the call')})

    # (i) B wrappers: the jc array is a verbatim 0x118-byte memcpy
    # of the wrapper's own 5th argument into [rsp+0xb0], untouched
    # between the copy and the call.
    for name, (jc, jsite, msite) in WRAPPER_B.items():
        rows = decoded[name]
        mc = _memcpy_census(rows)
        if mc != [(msite, 0xb0, 'r8', 0x118)]:
            raise AssertionError(f'{name} memcpy census differs: {mc!r}')
        late = [s for s in _stores(rows)
                if s[0] > msite and s[2] == 'rsp'
                and s[1] < 0x1c8 and s[1] + s[3] > 0xb0]
        if late:
            raise AssertionError(
                f'{name} stores into the array after its memcpy: {late!r}')
        if _binding_before(rows, 'r8', jsite) != 0xb0:
            raise AssertionError(f'{name} jc array is not [rsp+0xb0]')
        ev[name] = {'array_base_rsp': '0xb0',
                    'source': 'the wrapper\'s own 5th argument (r8)',
                    'stores_into_array_after_memcpy': 0}
        site_records.append({
            'site': _hx(jsite), 'callee': jc, 'caller_fde': name,
            'kind': 'incoming-argument-copy',
            'production': (
                f'memcpy([rsp+0xb0], r8, 0x118) at {_hx(msite)}: a '
                f'verbatim copy of the wrapper\'s own incoming '
                f'5th-argument record; no store touches the buffer '
                f'between the copy and the call')})

    # (i) s1 giants: the element record is assembled in the giant
    # itself at [rsp+0x20] (tag store, byte store, 0xff tail copy)
    # and passed in rdx.
    for name, (site, tail_src) in GIANT_S1.items():
        rows = decoded[name]
        if _slot_calls(rows, S1_SLOT) != [site]:
            raise AssertionError(f'{name} s1 slot sites differ')
        mc = _memcpy_census(rows)
        build = [e for e in mc if e[1] == 0x29 and e[2] == tail_src
                 and e[3] == 0xff]
        if len(build) != 1:
            raise AssertionError(f'{name} record-build memcpy differs')
        stores = _stores(rows)
        tag = [s for s in stores if s[2] == 'rsp' and s[1] == 0x20
               and s[3] == 8 and s[0] < site]
        byte = [s for s in stores if s[2] == 'rsp' and s[1] == 0x28
                and s[3] == 1 and s[0] < site]
        if not tag or not byte:
            raise AssertionError(f'{name} tag/byte stores missing')
        tag, byte = tag[-1], byte[-1]
        if not (build[0][0] < tag[0] < site and byte[0] < site):
            raise AssertionError(f'{name} build order differs')
        if _binding_before(rows, 'rdx', site) != 0x20:
            raise AssertionError(f'{name} s1 element is not [rsp+0x20]')
        ev[name] = {
            'element_base_rsp': '0x20',
            'tail_memcpy': _fmt_memcpy(build[0]),
            'tag_store': _hx(tag[0]), 'byte_store': _hx(byte[0])}
        site_records.append({
            'site': _hx(site), 'callee': 's1', 'caller_fde': name,
            'kind': 'inlined-record-assembly',
            'production': (
                f'the giant assembles the record at [rsp+0x20] '
                f'itself: tail memcpy ({_hx(build[0][0])}, from '
                f'[rsp+{_hx(tail_src)}], 0xff bytes), tag store at '
                f'{_hx(tag[0])}, byte store at {_hx(byte[0])}; '
                f'the record is passed in rdx')})

    # (i) s2 callers: the element is helper_s2's 0xc8-byte output
    # record, re-staged at [rsp+0xc8] (tag/byte stores + 0xbf tail
    # copy) and passed in rcx.
    for name, (hsite, msite, site) in S2_CALLERS.items():
        rows = decoded[name]
        if _slot_calls(rows, HELPER_S2_SLOT) != [hsite]:
            raise AssertionError(f'{name} helper_s2 slot sites differ')
        if _slot_calls(rows, S2_SLOT) != [site]:
            raise AssertionError(f'{name} s2 slot sites differ')
        mc = _memcpy_census(rows)
        if mc != [(msite, 0xd1, 0x9, 0xbf)]:
            raise AssertionError(f'{name} memcpy census differs: {mc!r}')
        if _binding_before(rows, 'rdi', hsite) != 0:
            raise AssertionError(f'{name} helper output is not [rsp]')
        if _binding_before(rows, 'rcx', site) != 0xc8:
            raise AssertionError(f'{name} s2 element is not [rsp+0xc8]')
        stores = _stores(rows)
        tag = [s for s in stores if s[2] == 'rsp' and s[1] == 0xc8]
        byte = [s for s in stores if s[2] == 'rsp' and s[1] == 0xd0]
        if len(tag) != 1 or len(byte) != 1:
            raise AssertionError(f'{name} re-stage stores differ')
        ev[name] = {
            'helper_output_base_rsp': '0x0', 'element_base_rsp': '0xc8',
            'tail_memcpy': _fmt_memcpy(mc[0]),
            'tag_store': _hx(tag[0][0]), 'byte_store': _hx(byte[0][0])}
        site_records.append({
            'site': _hx(site), 'callee': 's2', 'caller_fde': name,
            'kind': 'helper-output-record-restage',
            'production': (
                f'helper_s2 (slot {_hx(HELPER_S2_SLOT)}) writes its '
                f'0xc8-byte record at [rsp]; {name} re-stages it at '
                f'[rsp+0xc8] (tag store {_hx(tag[0][0])}, byte store '
                f'{_hx(byte[0][0])}, tail memcpy at {_hx(msite)}) and '
                f'passes it in rcx')})

    # (i) s3 callers: the element is a verbatim 0xf8-byte copy of
    # the sibling helper's output record at [rsp+0x50].
    for name, (helper, hsites, want_mc, sites, binds) in S3_CALLERS.items():
        rows = decoded[name]
        if _e8_sites_in(rows, BODIES[helper]['range'][0]) != hsites:
            raise AssertionError(f'{name} helper call sites differ')
        for hsite in hsites:
            if _binding_before(rows, 'rdi', hsite) != 0x50:
                raise AssertionError(
                    f'{name} helper output is not [rsp+0x50]')
        mc = _memcpy_census(rows)
        if mc != want_mc:
            raise AssertionError(f'{name} memcpy census differs: {mc!r}')
        if _slot_calls(rows, S3_SLOT) != sites:
            raise AssertionError(f'{name} s3 slot sites differ')
        for site, bind in zip(sites, binds):
            if _binding_before(rows, 'rdi', site) != bind:
                raise AssertionError(
                    f'{name} s3 element binding at {_hx(site)} differs')
        ev[name] = {
            'helper': helper, 'helper_output_base_rsp': '0x50',
            'memcpys': [_fmt_memcpy(e) for e in mc]}
        for site, bind in zip(sites, binds):
            site_records.append({
                'site': _hx(site), 'callee': 's3', 'caller_fde': name,
                'kind': 'helper-output-record-copy',
                'production': (
                    f'memcpy([rsp+{_hx(bind)}], [rsp+0x50], 0xf8): a '
                    f'verbatim copy of the output record {helper} '
                    f'wrote at [rsp+0x50]; passed in rdi')})

    # (iii) The 0x118 helpers: each copies its sub-lookup's output
    # record (or, for helper_jc23, its inlined decode record) into
    # the result, gated on the shared predicates.
    helper_specs = {
        'helper_ca': {
            'sub': 'sublookup_ca', 'sub_site': 0x27626a6,
            'out_base': 0x90,
            'memcpys': [(0x27626e6, 0x1b9, 0x99, 0x10f),
                        (0x2762756, 'rbx', 0x1b0, 0x118)],
            'staging': 0x1b0,
            'pred_a_site': 0x276262a, 'pred_b_site': 0x276273c,
            'rbx_stores': [(0x27625cf, 8, 1), (0x27625d3, 0, 8),
                           (0x27626c1, 8, 1), (0x27626c5, 0, 8),
                           (0x2762771, 8, 1), (0x2762775, 0, 8)]},
        'helper_jc1': {
            'sub': 'sublookup_jc1', 'sub_site': 0x27623ae,
            'out_base': 0x150,
            'memcpys': [(0x27623e8, 0x29, 0x159, 0x10f),
                        (0x276244e, 'rbx', 0x20, 0x118)],
            'staging': 0x20,
            'pred_a_site': 0x276234f, 'pred_b_site': 0x2762437,
            'rbx_stores': [(0x27623c9, 8, 1), (0x27623cd, 0, 8),
                           (0x2762469, 8, 1), (0x276246d, 0, 8)]},
    }
    for name, spec in helper_specs.items():
        rows = decoded[name]
        if _e8_sites_in(rows, BODIES[spec['sub']]['range'][0]) \
                != [spec['sub_site']]:
            raise AssertionError(f'{name} sub-lookup sites differ')
        mc = _memcpy_census(rows)
        if mc != spec['memcpys']:
            raise AssertionError(f'{name} memcpy census differs: {mc!r}')
        if _slot_calls(rows, PRED_A_SLOT) != [spec['pred_a_site']]:
            raise AssertionError(f'{name} pred_a sites differ')
        if _slot_calls(rows, PRED_B_SLOT) != [spec['pred_b_site']]:
            raise AssertionError(f'{name} pred_b sites differ')
        rbx = [(s[0], s[1], s[3]) for s in _stores(rows) if s[2] == 'rbx']
        if rbx != spec['rbx_stores']:
            raise AssertionError(f'{name} rbx stores differ: {rbx!r}')
        ev[name] = {
            'sub_lookup': spec['sub'],
            'sub_lookup_call': _hx(spec['sub_site']),
            'sub_output_base_rsp': _hx(spec['out_base']),
            'staging_base_rsp': _hx(spec['staging']),
            'memcpys': [_fmt_memcpy(e) for e in mc],
            'direct_result_stores': [
                {'site': _hx(a), 'disp': _hx(d), 'width': w}
                for a, d, w in rbx]}
    # helper_jc23: no sub-lookup; the decode phase is inlined.
    rows = decoded['helper_jc23']
    mc = _memcpy_census(rows)
    want_jc23 = [(0x54916bb, 905, 2089, 255), (0x5491b5e, 1697, 569, 167),
                 (0x5491b96, 1529, 1697, 167), (0x5491e63, 2089, 201, 255),
                 (0x5492199, 1248, 905, 271), (0x54921df, 905, 1248, 271),
                 (0x5492261, None, 896, 280), (0x54923f3, 905, 2089, 255)]
    if mc != want_jc23:
        raise AssertionError(f'helper_jc23 memcpy census differs: {mc!r}')
    if [s for s in _stores(rows) if s[2] in ('rbx', 'rdi')]:
        raise AssertionError('helper_jc23 stores through rbx/rdi')
    if _slot_calls(rows, PRED_A_SLOT) != [0x5491220]:
        raise AssertionError('helper_jc23 pred_a sites differ')
    if _slot_calls(rows, PRED_B_SLOT) != [0x5492245]:
        raise AssertionError('helper_jc23 pred_b sites differ')
    e8_targets_jc23 = set()
    for addr in sorted(rows):
        mnem, ops = _split_ops(rows[addr][1])
        if mnem == 'call' and ops:
            try:
                e8_targets_jc23.add(int(ops[0], 16))
            except ValueError:
                pass
    if any(0x2bb0000 <= t < 0x2bc0000 for t in e8_targets_jc23):
        raise AssertionError('helper_jc23 calls a sub-lookup after all')
    if 0x35bf460 not in e8_targets_jc23:
        raise AssertionError('helper_jc23 lost its inlined search call')
    ev['helper_jc23'] = {
        'sub_lookup': None,
        'memcpys': [_fmt_memcpy(e) for e in mc],
        'direct_result_stores': [],
        'note': ('no direct E8 call into the 0x2bbxxxx sub-lookup '
                 'range; the sibling-search body 0x35bf460 is called '
                 'directly, so the decode phase is inlined')}

    # (iii) Sub-lookup final assembly: the output record is written
    # exactly twice -- a 0x110-byte memcpy into output+8 from the
    # staging record's byte position, plus the tag store; on the
    # error arm a single byte store replaces the memcpy.
    sub_specs = {
        'sublookup_ca': {
            'save': (0x2bb7281, 0x250), 'staging': 0x4c8,
            'memcpys': [(0x2bb7dc5, 0x4d1, 0x769, 0xff),
                        (0x2bb8e1f, 0x769, 0x149, 0xff),
                        (0x2bb97c4, None, 0x4d0, 0x110),
                        (0x2bb9851, 0x4d1, 0x769, 0xff)],
            'rbx_stores': [(0x2bb97ca, 0, 8)],
            'rdi_stores': [(0x2bb97ac, 0, 1)],
            'assembly_branches': [0x2bb7df8, 0x2bb7e07, 0x2bb7e1f],
            'assembly_target': 0x2bb979a},
        'sublookup_jc1': {
            'save': (0x2bb52b1, 0x328), 'staging': 0x578,
            'memcpys': [(0x2bb59b0, 0x579, 0x689, 0xff),
                        (0x2bb6715, 0x689, 0x191, 0xff),
                        (0x2bb680c, None, 0x578, 0x110),
                        (0x2bb6892, 0x579, 0x689, 0xff)],
            'rbx_stores': [(0x2bb6812, 0, 8)],
            'rdi_stores': [(0x2bb67f4, 0, 1)],
            'assembly_branches': None,
            'assembly_target': None},
    }
    for name, spec in sub_specs.items():
        rows = decoded[name]
        save_addr, save_disp = spec['save']
        save = [s for s in _stores(rows)
                if s[0] == save_addr and s[1] == save_disp]
        if len(save) != 1:
            raise AssertionError(f'{name} rdi save store differs')
        mc = _memcpy_census(rows)
        if mc != spec['memcpys']:
            raise AssertionError(f'{name} memcpy census differs: {mc!r}')
        rbx = [(s[0], s[1], s[3]) for s in _stores(rows) if s[2] == 'rbx']
        if rbx != spec['rbx_stores']:
            raise AssertionError(f'{name} rbx stores differ: {rbx!r}')
        rdi = [(s[0], s[1], s[3]) for s in _stores(rows) if s[2] == 'rdi']
        # rdi is reused as a scratch structure pointer mid-body;
        # the final-assembly byte store is the only store through
        # it with displacement 0 and width 1 (rdi = output + 8
        # there, bound by the lea in the assembly block).
        rdi_final = [r for r in rdi if r[1] == 0 and r[2] == 1]
        if rdi_final != spec['rdi_stores']:
            raise AssertionError(
                f'{name} final rdi stores differ: {rdi_final!r}')
        staging = spec['staging']
        st = [s for s in _stores(rows) if s[2] == 'rsp'
              and s[1] < staging + 0x118 and s[1] + s[3] > staging]
        if spec['assembly_branches'] is not None:
            branches = []
            for addr in sorted(rows):
                mnem, ops = _split_ops(rows[addr][1])
                if ops and ops[0] == _hx(spec['assembly_target']) \
                        and mnem.startswith('j'):
                    branches.append(addr)
            if branches != spec['assembly_branches']:
                raise AssertionError(
                    f'{name} assembly branches differ: {branches!r}')
        ev[name] = {
            'rdi_save': {'site': _hx(save_addr),
                         'rsp_disp': _hx(save_disp)},
            'staging_base_rsp': _hx(staging),
            'staging_stores': _fmt_stores(st),
            'memcpys': [_fmt_memcpy(e) for e in mc],
            'output_stores': (
                [{'site': _hx(a), 'base': 'rbx', 'disp': _hx(d),
                  'width': w} for a, d, w in spec['rbx_stores']]
                + [{'site': _hx(a), 'base': 'rdi', 'disp': _hx(d),
                    'width': w} for a, d, w in spec['rdi_stores']])}
        counters[f'{name}_staging_stores'] = len(st)

    # helper_s2: builds its output record per-field through rbx
    # (its result pointer); zero memcpys.
    rows = decoded['helper_s2']
    rbx = [(s[0], s[1], s[3]) for s in _stores(rows) if s[2] == 'rbx']
    if _memcpy_census(rows):
        raise AssertionError('helper_s2 unexpectedly calls memcpy')
    ev['helper_s2'] = {
        'rbx_stores': [{'site': _hx(a), 'disp': _hx(d), 'width': w}
                       for a, d, w in rbx],
        'memcpy_calls': 0}
    counters['helper_s2_rbx_stores'] = len(rbx)

    # (ii) big1/big2: r12's write set, the helper fill with
    # rdi = r12 before each memcpy, and the staging store census.
    big_specs = {
        'big1': {
            'helper': 'helper_s3a', 'staging': 0x140,
            'r12_writes': [0x2c64920, 0x2c64a8f, 0x2c64fad, 0x2c650f6,
                           0x2c656fd],
            'helper_sites': [0x2c65297, 0x2c65462],
            'tag_checks': [0x2c6529c, 0x2c65467],
            'memcpys': [(0x2c652ba, 0x2f0, 'r12', 0xf8),
                        (0x2c65485, 0x2f0, 'r12', 0xf8)]},
        'big2': {
            'helper': 'helper_s3b', 'staging': 0x150,
            'r12_writes': [0x55e37db, 0x55e38ac, 0x55e3908, 0x55e3952,
                           0x55e39ac, 0x55e3a27, 0x55e3a79, 0x55e3aaa,
                           0x55e3ad9, 0x55e3b43, 0x55e3b47, 0x55e3b64,
                           0x55e40ad, 0x55e41f4, 0x55e47fd],
            'helper_sites': [0x55e4397, 0x55e4562],
            'tag_checks': [0x55e439c, 0x55e4567],
            'memcpys': [(0x55e43ba, 0x360, 'r12', 0xf8),
                        (0x55e4585, 0x360, 'r12', 0xf8)]},
    }
    for name, spec in big_specs.items():
        rows = decoded[name]
        end = BODIES[name]['range'][1]
        writes = _value_writes(rows, 'r12', end)
        if writes != spec['r12_writes']:
            raise AssertionError(
                f'{name} r12 writes differ: {writes!r}')
        if _e8_sites_in(rows, BODIES[spec['helper']]['range'][0]) \
                != spec['helper_sites']:
            raise AssertionError(f'{name} helper sites differ')
        for hsite in spec['helper_sites']:
            if _binding_before(rows, 'rdi', hsite) != 'r12':
                raise AssertionError(
                    f'{name} helper at {_hx(hsite)} does not get r12')
        for check in spec['tag_checks']:
            text = rows[check][1]
            if 'cmp' not in text or f"{_hx(spec['staging'])}(%rsp)" \
                    not in text.replace(' ', ''):
                raise AssertionError(
                    f'{name} tag check at {_hx(check)} differs: {text!r}')
        mc = _memcpy_census(rows)
        if mc != spec['memcpys']:
            raise AssertionError(f'{name} memcpy census differs: {mc!r}')
        staging = spec['staging']
        st = [s for s in _stores(rows) if s[2] == 'rsp'
              and s[1] < staging + 0x118 and s[1] + s[3] > staging]
        ev[name] = {
            'helper': spec['helper'],
            'helper_sites': [_hx(a) for a in spec['helper_sites']],
            'staging_base_rsp': _hx(staging),
            'r12_writes': [_hx(a) for a in writes],
            'staging_stores': len(st),
            'memcpys': [_fmt_memcpy(e) for e in mc]}
        counters[f'{name}_staging_stores'] = len(st)

    # (iv) big3: the [rsp+0x410] record is assembled in-FDE.
    rows = decoded['big3']
    mc = _memcpy_census(rows)
    want_big3_mc = [(0x55e0313, 0x419, 0x98a, 0xff),
                    (0x55e0c70, 0x6f0, 0x329, 0xa7),
                    (0x55e0ca5, 0x531, 0x6f0, 0xa7),
                    (0x55e125d, 0x98a, 0xa9, 0xff),
                    (0x55e12da, 0x798, 0x419, 0x10f),
                    (0x55e1312, 0x5e1, 0x798, 0x10f),
                    (0x55e1425, 0x7a1, 0x410, 0xa7),
                    (0x55e168d, 0x419, 0x98a, 0xff)]
    if mc != want_big3_mc:
        raise AssertionError(f'big3 memcpy census differs: {mc!r}')
    st410 = [s for s in _stores(rows) if s[2] == 'rsp'
             and s[1] < 0x410 + 0x118 and s[1] + s[3] > 0x410]
    want_410 = [0x55df0e4, 0x55e02eb, 0x55e02f7, 0x55e0321, 0x55e032e,
                0x55e134e, 0x55e135e, 0x55e1665, 0x55e1671, 0x55e169b,
                0x55e16a8]
    if [s[0] for s in st410] != want_410:
        raise AssertionError(
            f'big3 record stores differ: {[s[0] for s in st410]!r}')
    ev['big3'] = {
        'record_base_rsp': '0x410',
        'direct_stores': _fmt_stores(st410),
        'memcpys': [_fmt_memcpy(e) for e in mc]}
    counters['big3_record_stores'] = len(st410)
    counters['big3_memcpys'] = len(mc)

    if counters != EXPECTED:
        raise AssertionError(f'counters differ: {counters!r} != {EXPECTED!r}')

    bodies_record = {}
    for name, body in all_bodies.items():
        start, end = body['range']
        bodies_record[name] = {
            'role': body['role'], 'range': [_hx(start), _hx(end)],
            'size': end - start, 'sha256': body['sha256']}
    records = {
        'packet': PACKET_ID,
        'node': {
            'artifact_sha256': ARTIFACT_SHA256,
            'artifact_size': ARTIFACT_SIZE,
            'authenticated_fdes': len(ordered),
        },
        'question': (
            'PR #2584 classified how the drivers\' 0xb0-byte element '
            'argument is produced at its 13 boundary sites and left '
            'four producer questions: (i) who produces the incoming '
            'arrays/structs of the six (c)-kind FDEs, (ii) the '
            'lookup-phase records r12 points to in 0x2c64870 and '
            '0x55e3770, (iii) the serialised tail of helper '
            '0x2762570\'s 0x118-byte result record, and (iv) the '
            '[rsp+0x410] record in 0x55defd0; plus whether the '
            '{tag, byte, serialised tail} idiom has a single '
            'decode-site producer.'),
        'duplicate_gate': (
            'open-PR sweep of lalalune/hyperliquid-source for the '
            'join-consumer addresses (2a89500, 55a07e0, 55a12e0), '
            'the adapter addresses (369a3d0, 369b650, 3f10ac0), the '
            'big-FDE addresses (2c64870, 55e3770, 55defd0), the '
            'helper addresses (2762570, 2bb7270) and the phrases '
            '"argument producers" and "element array": no hits '
            'beyond the RE-006 predecessor packets (#2542, #2546, '
            '#2548, #2552, #2558, #2561, #2564, #2584); no open PR '
            'traces who produces these inputs.'),
        'slots': slots,
        'bodies': bodies_record,
        'boundary': {
            'jc_e8_callers': e8_record,
            'adapter_slot_callers': slot_record,
            'helper_e8_callers': {
                k: e8_record[k] for k in
                ('helper_jc1', 'helper_ca', 'helper_jc23',
                 'sublookup_ca', 'sublookup_jc1', 'helper_s3a',
                 'helper_s3b', 's3c_a', 's3c_b', 'jc1', 'jc2', 'jc3')},
            'statement': (
                'the join consumers have exactly two direct callers '
                'each (six wrapper FDEs); the adapters have no '
                'direct callers and exactly the censused indirect '
                'callers through their single GOT slots; each '
                'sub-lookup has exactly one caller (its helper); '
                'helper_s3a/helper_s3b are called by their s3 '
                'caller FDE and by big1/big2 respectively')},
        'sites': site_records,
        'fde_evidence': ev,
        'record_idiom': {
            'shape': (
                'a serialised record of a qword tag at +0x0, a byte '
                'at +0x8 and a serialised tail at +0x9; sizes seen: '
                '0xc8 (helper_s2 output), 0xf8 (helper_s3a/helper_s3b '
                'output), 0x118 (the 0x118 helpers and sub-lookups)'),
            'producers': (
                'helper clone family 0x27622f0 / 0x2762570 / '
                '0x5491190 (the last with an inlined decode phase), '
                'sub-lookup clone pair 0x2bb7270 / 0x2bb52a0, '
                'per-field construction in helper 0x369b770, and '
                'inlined assemblies inside 0x55defd0 and the three '
                's1 slot-caller giants'),
            'shared_code': (
                'the memcpy GOT slot 0x64df508 and the two shared '
                'predicate bodies 0x369a210 (slot 0x64e6498) and '
                '0x3bf4fa0 (slot 0x64e64a0), called by all three '
                '0x118 helpers; no single decode-site producer '
                'exists'),
        },
        'counters': counters,
        'verdict': (
            'every input PR #2584 left open is a serialised record '
            'of the {tag, byte, tail} family, and every producer is '
            'now pinned: (i) the join consumers\' arrays are lookup '
            'helpers\' output records (A wrappers) or verbatim '
            'copies of the wrappers\' own incoming record (B '
            'wrappers); the adapters\' elements are assembled in '
            'their giant callers (s1), re-staged from helper '
            '0x369b770\'s per-field record (s2), or copied verbatim '
            'from the sibling 0xf8 helpers\' output (s3).  (ii) The '
            'r12 records in big1/big2 are the FDEs\' staging '
            'buffers, written in place by those same 0xf8 helpers '
            'called with rdi = r12 immediately before each memcpy.  '
            '(iii) Helper 0x2762570\'s tail is its sub-lookup '
            '0x2bb7270\'s output tail, copied verbatim; the '
            'sub-lookup assembles its own record from a chain of '
            'two further internal records.  (iv) big3 assembles '
            'its [rsp+0x410] record in-FDE in the sub-lookup shape.  '
            'The idiom is one record family with many producers, '
            'not a single decode site.'),
        'extractor': 'tools/argument_producers_static.py',
    }
    return records


def _frames(data):
    retained = {tuple(b['range']) for b in BODIES.values()}
    retained.update(tuple(b['range']) for b in ANCHORS.values())
    handle = tempfile.NamedTemporaryFile(suffix='.elf', delete=False)
    try:
        handle.write(data)
        handle.close()
        out = subprocess.check_output(
            ['readelf', '--debug-dump=frames', handle.name], text=True)
    finally:
        Path(handle.name).unlink()
    lines = []
    for line in out.splitlines():
        if ' FDE ' not in line:
            continue
        match = re.search(r'pc=([0-9a-f]+)\.\.([0-9a-f]+)', line)
        if match and (int(match.group(1), 16),
                      int(match.group(2), 16)) in retained:
            lines.append(line)
    if len(lines) != len(retained):
        raise AssertionError(
            f'frames cover {len(lines)} of {len(retained)} FDEs')
    return '\n'.join(lines) + '\n'


def _body_export(data, start, end):
    handle = tempfile.NamedTemporaryFile(suffix='.elf', delete=False)
    try:
        handle.write(data)
        handle.close()
        out = subprocess.check_output(
            ['objdump', '-d', '-M', 'intel', '--insn-width=16',
             f'--start-address={start:#x}', f'--stop-address={end:#x}',
             handle.name], text=True)
    finally:
        Path(handle.name).unlink()
    return out.replace(handle.name, '<authenticated-node115>')


def _export_name(name, start, end):
    return f'{name}_full_body_{start:x}_{end:x}_objdump.txt'


class PacketError(AssertionError):
    """The artifact does not authenticate against node 115."""


def generate(data, out_dir):
    if hashlib.sha256(data).hexdigest() != ARTIFACT_SHA256 \
            or len(data) != ARTIFACT_SIZE:
        raise PacketError('artifact SHA-256 mismatch')
    records = analyze(data)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / 'records.json').write_text(
        json.dumps(records, indent=1, sort_keys=True) + '\n')
    (out_dir / 'frames.txt').write_text(_frames(data))
    for name in EXPORTED:
        start, end = BODIES[name]['range']
        (out_dir / _export_name(name, start, end)).write_text(
            _body_export(data, start, end))
    return records


def main(argv):
    if len(argv) != 3 or argv[1] != 'generate':
        raise SystemExit(
            'usage: argument_producers_static.py generate <out-dir>')
    artifact = ROOT / 'artifacts/node/115/hl-node'
    generate(artifact.read_bytes(), argv[2])
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
