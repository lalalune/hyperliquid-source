#!/usr/bin/env python3
"""Static trace of the map construction inside the two RE-005 trail-1
boundaries: the registry worker 0x1630c90 (path A) and the merge
builder 0x1667780 (path B).

The chain-origin packet (#2486) established that the `chain` string
the apply function 0x564cce0 reads through the getter 0x4e4ca30 is
input data: the value's entries materialise only inside the registry
worker (path A — called with (result, spec copy, ctx, &sentinel+1);
its 0x50-byte result struct is copied verbatim into out) or the
merge builder (path B — (ctx, pairs, count, temp); pairs extracted
from the spec copy's +0x190/+0x198 entry array are merged into the
ctx, which becomes out). It left one question open: inside those
two bodies, where is the `chain` entry first inserted into the map
the getter later reads? This packet traces both bodies and the
three map helpers they share (insert-or-replace 0x1669390,
get-or-insert 0x1667540, ctx remove/convert 0x16683e0), and answers:

Path B (merge builder). The builder's only two calls to the shared
insert-or-replace helper 0x1669390 are the pair-loop staging insert
at 0x1667c0e (into the temp table) and the drain insert at
0x1668034 (into the table embedded in the ctx at ctx +0x18 — the
table the getter probes). The pair loop stages a pair's key into
temp only when the key is already present in the ctx (a ctx miss
reaches the next-pair edge at 0x1667ca0 with no insert); the staged
value is built by the value copy helper 0x16595d0 from the ctx/temp
entries. The drain then copies each temp entry's key (ptr/len taken
from the temp entry itself) and value (again via 0x16595d0) into
the ctx table. The builder never references the key bytes at
0x92a7be and never creates a key: a `chain` entry reaches the
getter's map in path B only through the drain insert, and only if
temp holds a `chain` entry at drain time — either pre-existing in
the core-built temp (upstream of this packet's boundary) or staged
by the pair loop when a spec pair's key is "chain" and "chain" is
already present in the ctx.

Path A (registry worker). The worker body contains no insertion
into the result's map at all. Its only insert-capable callee — by
direct call, bound slot, descriptor-table function pointer, or
lea'd callback — is the get-or-insert helper 0x1667540, and both
of its call sites (0x16327b9, and the element loop at 0x163281e)
pass the worker's third argument, the ctx, as the map, with keys
taken from the spec entry being processed (its name at entry
+0x170/+0x178, and the entry's element strings). The inserted
default value has a zero word at value +0x28 — the word the getter
requires to be nonzero before it reads a value's string — so even
a spec entry named "chain" could not produce a getter-readable
entry through this path. The worker's other map operation on the
ctx is the remove/convert helper 0x16683e0 (three sites, all with
the ctx as first argument), which deletes ctx entries. The
result's own 0x50 bytes are written at the exits by direct field
stores from frame-local structs, and on one exit path by the
delegated final-assembly call at 0x16343d1 (0x164df60, a
hash-pinned boundary). No instruction in the worker body
references the key bytes at 0x92a7be.

The map layout both paths converge on (pinned here from the
getter and the helpers): a value is 0x50 bytes — a 0x18-byte
prefix, then a table header at +0x18 (buckets +0x18, mask +0x20,
growth-left +0x28, items +0x30), the 16-byte hash state at +0x38,
and an inner pointer at +0x48. Entries have stride 0x48: key
pointer +0x0, key length +0x8, and a 0x38-byte value record at
+0x10 whose +0x20 word is the value-object pointer the getter
dereferences for the string ([obj +0x8], [obj +0x10]) and whose
+0x28 word must be nonzero for the getter to read it.

Captured code is never executed; every claim is a byte pin, an
instruction-start-validated census, or a relocation binding read
from the authenticated node #115 artifact.
"""
import argparse
import bisect
import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from artifacts import ROOT
from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import decode_export, require

TARGET = ROOT / 'artifacts/node/115/hl-node'
TARGET_SIZE = 105_896_032
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
PACKET = ROOT / 'research/work-items/RE-005-node115-chain-entry-insert'

WORKER = (0x1630c90, 0x16352c2)
BUILDER = (0x1667780, 0x16681f7)
INSERT = (0x1669390, 0x1669656)
GETORINSERT = (0x1667540, 0x166777e)
REMOVEOP = (0x16683e0, 0x16688de)
VALUECOPY = (0x16595d0, 0x1659775)
COUNTERA = (0x162cee0, 0x162cfeb)
COUNTERB = (0x163a070, 0x163a4a8)
GETTER = (0x4e4ca30, 0x4e4cba7)

OWNERS = {'registry_worker': WORKER, 'value_merge_builder': BUILDER,
          'map_insert': INSERT, 'get_or_insert': GETORINSERT,
          'ctx_remove_op': REMOVEOP, 'value_copy': VALUECOPY,
          'entry_counter_a': COUNTERA, 'entry_counter_b': COUNTERB}
REF_BODIES = {'field_getter': GETTER}

# Contiguous worker windows committed as exports. The worker is
# 17,970 bytes; the packet pins its map-relevant regions (argument
# saves, the map-operation sites, the result-exit stores, and the
# final-assembly call) and validates every asserted site in the
# full body as an instruction start at generation time.
WORKER_WINDOWS = {
    'worker_entry_window': (0x1630c90, 0x1630cd7),
    'worker_remove_site_a_window': (0x163179e, 0x16317c5),
    'worker_result_stores_a_window': (0x1633155, 0x16331e8),
    'worker_result_store_b_window': (0x1633375, 0x1633393),
    'worker_result_store_c_window': (0x1633650, 0x16336a0),
    'worker_map_ops_window': (0x16326fa, 0x163285e),
    'worker_assembly_window': (0x163432d, 0x16343d7),
    'worker_result_stores_b_window': (0x1634435, 0x1634600),
}

CHAIN_NAME_VA = 0x92a7be
INSERT_VA = 0x1669390
GETORINSERT_VA = 0x1667540
REMOVEOP_VA = 0x16683e0
SENTINEL = 0x8000000000000000

BOUNDARIES = {
    'key_hash_ctx': (0x1665f10, 352,
                     '15b6ada5049a1a77050265a9c6b5b9241ca05e06f9ce81900fe432e6c5b05d5d'),
    'key_hash_temp': (0x1665da0, 362,
                      'da865e1c711dafeb25db1787a8fa055826055a0e7ce37dbe8099f56aec9734af'),
    'key_hash_getter': (0x4e52640, 352,
                        '932c1acb8ca5b6a618258042875784bf789fe91e511657af2143f4f017945003'),
    'insert_reserve': (0x16663d0, 1799,
                       '98f127decbe7fe9c8b5d72aac3d15e89aa426e97feaccbd80c5c42f288559209'),
    'vec_grow': (0x16604b0, 100,
                 '6fdd660cecbe20fa55c4f6241c7fe6fed7d318cfcc2e7c0bddcecf71aa2b7b5d'),
    'remove_continuation': (0x1668200, 476,
                            '1d640f73a26d3df618bba6550741e923254ab4f3eb7cb24bcbfaff4154beaa4b'),
    'value_dtor': (0x1668e50, 165,
                   '9d655d9d22137b0660ab254131afc021b3a03e188e6892739997924c62167832'),
    'merge_temp_dtor': (0x1666250, 383,
                        'd5f3eb8215b255054518ca78ef760d7d5a931263d47ab77cd7dc36e9d3ca1b0d'),
    'final_assembly': (0x164df60, 23327,
                       'a023ea6de0a9c1a7e5e4b81e1dffe82f3274dca6b93d1ecc2852a4cab74fd8df'),
    'after_worker_fn': (0x16352d0, 311,
                        '4180bc6338a1102903dee90a79ebee6ff66906af270ae05c7f2656dd3c13dc6d'),
    'counter_companion': (0x1667010, 388,
                          'e1d7ea012559ff99b220c4afb36db8f29060812b0425d7488ea9cd77ef373a00'),
}

# Every FDE-bounded callee of the registry worker (direct or via a
# bound slot), hash-pinned so the insert-capability census runs
# over authenticated bytes. The worker's one remaining call target,
# the PLT stub at 0x63f0a50 (_Unwind_Resume), has no FDE body.
WORKER_CALLEES = {
    0x141ca00: (565, '78d424ddd336f24cf3baac2c2f00199b8109d70ce638e25f8bc528f0dc2a4c85'),
    0x141e264: (21, '0ebfd9ba496f95eb3b50668da6bdfb6f60cdfea033bc8736545f457d87a46af0'),
    0x141e3a0: (408, 'aa4d4d0611c533e38c65e1577c0426b5163846c01225556743d4d4345cadd1fe'),
    0x141e750: (104, '60f5ae5e0aca594f9ff5526b4552775de18d1505f4186845932450d70bc35068'),
    0x162c890: (1606, '3eb271192d0fe500cb0943cde1f7be38e2bc3cb44c1ebb234225e55f58274446'),
    0x162f9c0: (655, '29cd8998927c26d6fe3fdfceac17323434107d1699b112a02845cc3275eeb371'),
    0x162fc50: (655, 'f90969743633ebdbb05dfead2d9f91debf54561f346023b1faa72943c8dda111'),
    0x162fee0: (468, '0cc6987fc9ef572a25706b7e0020b8a6b8bc03ea176260924f064aaa30ef23b6'),
    0x16300c0: (3024, '5604e375c0d9c846e0866131cb77806adac330f0185bf900e8ee8bc87787c556'),
    0x16352d0: (311, '4180bc6338a1102903dee90a79ebee6ff66906af270ae05c7f2656dd3c13dc6d'),
    0x1635940: (373, '659664f472b7cfd8e29cfa8e10603b3667dc0551c59c0a1b272f1e4d0587d753'),
    0x1635bd0: (600, 'fef94b352f77e03a5acb219f3f2b070b09ab9ca22c537f06a53ad01911cf4d81'),
    0x1636460: (5745, '5ee207c3dab41eeb8c4a8d2487fd58187cf3243710cda3123169bbbedf1548fd'),
    0x1637ae0: (2007, '154702038b9e23e1600feff57505a545e83f5e5dde5c0fc7ab8ed3090f576690'),
    0x16382c0: (189, '20af26fda53a7040488540215d9e352e7a025bd9af170b4f764fceae43207cd7'),
    0x1638800: (49, 'f7502552d38a2f32f2d7440bdca45f8058cd21ec2c3b18a5a188a61c29294e0c'),
    0x163ad40: (181, 'f4a6b57d72bb6224cbac5c2e7ac265873ba6eca59a5e1027a5951e25b3ee0886'),
    0x163b220: (124, '6f912ce52a043dd064c7eb2cb4b051f212d14791b03e5d4dcc4e2ed7ffbf2100'),
    0x163b490: (289, '0d42d63f10cddcbd19677b3a4ed62a78926973c31576eebd8d07225fce8d7f00'),
    0x16462d0: (7984, 'a4097e029f7a2407e99bcc2aa3047b60b5217920de836fe40df01d49dca90e89'),
    0x164df60: (23327, 'a023ea6de0a9c1a7e5e4b81e1dffe82f3274dca6b93d1ecc2852a4cab74fd8df'),
    0x1657730: (563, '6a431c4c5fdf7c1d046d722ca582fa3c76f7b4804ef254c80974b010fd6a986b'),
    0x165ae70: (693, '38788c5a636f98be3b3e3cde383cecd11e1ecea7b811bee72e348439ce79c89e'),
    0x165b410: (307, '27a99ebb1479513439dae157c826430635cb977e059c0ae9ddc8a999a470b79e'),
    0x165b6d0: (240, 'a56440f991cc0b26780d727ca26b5d2f584758ee3722350e0ab1cfbdb30b450c'),
    0x1660210: (100, '02b58ac8c9f370a212339cdf79c9f72e6b9b06182c7c37f2c0f7f160b770ef6a'),
    0x1660680: (142, 'e196b82593357464a296331fbe13be93e3b9d42a54e0ea067ec3716a0529c137'),
    0x1662ad0: (349, '97d30015359c81b68e0757a926989e6c78a9f792bde351e774944e4ed2e9a0ea'),
    0x16635b0: (9053, 'f94c8036e9cf0a46e8ad200eef31f9fa969d5dcd287116f73075c40f0eff33a6'),
    0x1666cc0: (611, '94ea21cad1939f156ced5bcfd91136f162ae95d537ef4429607120c9b229396b'),
    0x1666f30: (222, '637e8db8212ff0fb2f2cc101b0f5ec691de1afb3f70026accb066b16940634a5'),
    0x1667540: (574, '21dbfce6a49d692b60fb0f0b3d33da2e5f9fadd751698c224b735537106ac7af'),
    0x16683e0: (1278, 'c1457eeb4364f3144c55511040a2146129f44b8a51f0b97b00bba48bcc538eeb'),
    0x166abb0: (285, '330f87930a81a26e7f565eb090b69cc73c93754e6fd8c0de5b3f4a81459ba224'),
    0x16728f0: (202, '455d8e72ef7afa30732c63b7a8acb24ef504c075394acf032b8c7b0cdc888094'),
    0x1673b90: (766, 'e0fba0dcca9fe4a73fa117609c12b641a4df1d6687fb5f9ce1075f0e8e28dc9a'),
    0x1674d30: (498, '56fc8461eaf0493a207241793831ac5378d7cdf33e846c6f4b0a9573aa42d36d'),
    0x1680bd0: (52, '6dc901ad3d8318c0ad4ea63c6cbcfbc96ed76f5d1a86ff705ecf54d6cf04c7b2'),
    0x1680c10: (25, '6c62896561a5c8454ceb1945a882a798dcaefe52e78852cbbfee08835a16a81e'),
    0x1680c30: (82, '2d00fd36dc6102ab0738e08907482bb818bca6e76e32a5b941eabf431f20767a'),
    0x1680cab: (20, '7604c0d4f26a7d70e59c5dcb8a39928bfd7207a5d4439d91d8fb1e50be9846e7'),
    0x16815e0: (503, '3ff2fdb7228f89579b15327cfe53871b0d275e0c54668dfeca9b349800836de0'),
    0x16817e0: (200, '002f50151d50c9884dc671db9023071d4db87bb150a52d4b510e653c39a293ba'),
    0x1681da0: (25, 'e1cd56206ba06a2e8b10aee1d66a6e7e8b17d1ab1226d2710a72e512ba163b54'),
    0x1681e40: (25, '8a6730057246ec48aa51aeb1316e0a664563932d075052e6cb78492da793fa0b'),
    0x16876b0: (1402, 'edac1854c12ef757e45fa240477648e59377d31622b6335905a5c0614ecdab47'),
    0x5c9fd80: (48, 'effbfb286e9e1702f2f9533c24931929c8e6e22da264f579774acee9c5793c62'),
    0x6355830: (194, '72c29274a75359df7c598d254d102cbab84f51d359256facb415bb90bffec5af'),
    0x635de30: (165, '714fc5cdd28a2587427c9dac8a25685ec09695a3a21bc9af0eb09b29ae503f61'),
}

SLOTS = {0x64df508: ('memcpy', 'memcpy'),
         0x64df9f8: ('bcmp', 'bcmp'),
         0x64df480: (0x6355830, 'alloc'),
         0x64df498: (0x141e264, 'alloc_error'),
         0x64df4a0: (0x635de30, 'value_drop'),
         0x64df520: (0x1681da0, 'counter_overflow_panic'),
         0x64df770: (0x1680bd0, 'panic_location_helper'),
         0x64dfca8: (0x16815e0, 'value_converter'),
         0x64e1b98: (0x166abb0, 'predicate_bit_test'),
         0x64e1ba8: (0x1667540, 'get_or_insert'),
         0x64e1bb8: (0x162fee0, 'entry_name_register'),
         0x64e1c70: (0x16683e0, 'ctx_remove_op'),
         0x64e1cb0: (0x16352d0, 'after_worker_fn'),
    0x64e1ba0: (0x162cee0, 'entry_counter_a'),
    0x64e1c58: (0x163a070, 'entry_counter_b'),
    0x64e1bb0: (0x1667010, 'counter_companion'),
    0x64e1c40: (0x16300c0, 'worker_predecessor'),
         0x64e1cb8: (0x164df60, 'final_assembly'),
         0x64e1c98: (0x5c9fd80, 'tls_cell_init'),
         0x64e1dd0: (0x16604b0, 'vec_grow'),
         0x64e1de0: (0x16663d0, 'insert_reserve'),
         0x64e1df8: (0x1668200, 'remove_continuation')}

# Static ranges whose relocation targets the worker can reach as
# function pointers: the three per-kind descriptor tables it
# selects between, and the two vtable-style statics it loads.
DESCRIPTOR_RANGES = [(0x6405a48, 0x100), (0x6405b40, 0xf8),
                     (0x6405c38, 0x110), (0x64059b8, 0x90),
                     (0x6405d48, 0x210)]

WORKER_PINS = [
    (0x1630ca1, '48898c24f0000000', 'worker arg4 (sentinel cell) saved at [rsp+0xf0]'),
    (0x1630ca9, '4889542430', 'worker arg3 (ctx) saved at [rsp+0x30]'),
    (0x1630cb1, '48897c2458', 'worker arg1 (result) saved at [rsp+0x58]'),
    (0x16317a7, '488b7c2430', 'remove-op site A: ctx reloaded into rdi'),
    (0x16317bf, 'ff15ab04eb04', 'remove-op site A: call through slot 0x64e1c70'),
    (0x163272b, '488b7c2430', 'remove-op site B: ctx reloaded into rdi'),
    (0x1632743, 'ff1527f5ea04', 'remove-op site B: call through slot 0x64e1c70'),
    (0x16327ae, '488b7c2430', 'get-or-insert site 1: ctx reloaded into rdi'),
    (0x16327b3, '4889de', 'get-or-insert site 1: key ptr = spec entry name (entry +0x170, in rbx)'),
    (0x16327b6, '4c89f2', 'get-or-insert site 1: key len = spec entry +0x178 (in r14)'),
    (0x16327b9, 'ff15e9f3ea04', 'get-or-insert site 1: call through slot 0x64e1ba8'),
    (0x1632810, '498b3424', 'get-or-insert site 2 (element loop): element key ptr load'),
    (0x1632814, '498b542408', 'get-or-insert site 2: element key len load'),
    (0x1632819, '488b7c2430', 'get-or-insert site 2: ctx reloaded into rdi'),
    (0x163281e, 'ff1584f3ea04', 'get-or-insert site 2: call through slot 0x64e1ba8'),
    (0x1633161, '488b4c2458', 'result exit store A: result pointer reloaded'),
    (0x1633166, '48894130', 'result exit store A: [result +0x30] (items) stored from a frame struct'),
    (0x16331c1, '488b542458', 'result exit store B: result pointer reloaded'),
    (0x16331c6, '48894a30', 'result exit store B: [result +0x30] stored'),
    (0x1633381, '488b542458', 'result exit store C: result pointer reloaded'),
    (0x1633386, '48894a18', 'result exit store C: [result +0x18] (buckets) stored'),
    (0x163365e, '488b4c2458', 'result exit store D: result pointer reloaded'),
    (0x1633663, '48894130', 'result exit store D: [result +0x30] stored'),
    (0x16343c7, '488b7c2458', 'final assembly: result pointer into rdi'),
    (0x16343cc, '4c8b442430', 'final assembly: ctx into r8'),
    (0x16343d1, 'ff15e1d8ea04', 'final assembly: call through slot 0x64e1cb8'),
    (0x16344a8, '488b4c2458', 'result exit store E: result pointer reloaded'),
    (0x16344ad, '48894130', 'result exit store E: [result +0x30] stored'),
    (0x16344eb, '488b4c2458', 'result exit store F: result pointer reloaded'),
    (0x16344f0, '48894130', 'result exit store F: [result +0x30] stored'),
    (0x163458d, '488b442458', 'result exit store G: result pointer reloaded'),
    (0x1634592, '0f115028', 'result exit store G: block store at [result +0x28]'),
    (0x16345de, '488b542458', 'sentinel exit store: result pointer reloaded'),
    (0x16345e3, '48894a18', 'sentinel exit store: [result +0x18] (buckets) stored'),
]
BUILDER_PINS = [
    (0x1667791, '4989cf', 'temp (arg4) into r15'),
    (0x1667794, '4889742448', 'pairs (arg2) saved at [rsp+0x48]'),
    (0x1667799, '4989fc', 'ctx (arg1) into r12'),
    (0x16677a6, '4889542450', 'count (arg3) saved at [rsp+0x50]'),
    (0x16677ab, '4885d2', 'pair count == 0 test'),
    (0x16677ae, '0f84af050000', 'pair count == 0 -> base case'),
    (0x16677b4, '49837c243000', 'ctx items [r12 +0x30] == 0 test'),
    (0x16677ba, '0f84a3050000', 'ctx items == 0 -> base case'),
    (0x16677d9, '498d4c2438', 'ctx hash state address &(ctx +0x38) saved'),
    (0x16677e6, '498d4f20', 'temp hash state address &(temp +0x20) saved'),
    (0x16677f2, '4c89642428', 'ctx saved at [rsp+0x28]'),
    (0x16677f7, '4c897c2438', 'temp saved at [rsp+0x38]'),
    (0x1667868, 'ff158a81e704', 'ctx probe: bcmp through slot 0x64df9f8'),
    (0x1667870, '745e', 'ctx probe: key match -> found path'),
    (0x16678a0, '660f76c0', 'ctx probe: empty-group test block'),
    (0x16678b8, '0f85e2030000', 'ctx probe: miss -> next-pair edge (no insert)'),
    (0x16678d5, '48837b1800', 'ctx-found path: temp items [temp +0x18] == 0 test'),
    (0x1667ba0, '488d7c2460', 'merged value: copy helper out at rsp+0x60'),
    (0x1667ba8, 'e8231affff', 'merged value: call the value copy helper'),
    (0x1667bb5, '488b442410', 'value record assembly: word from the copy output'),
    (0x1667bf2, '488b4c2408', 'pair insert: key len (rcx) from [rsp+0x8]'),
    (0x1667bf7, '488d7c2460', 'pair insert: out record at rsp+0x60 (rdi)'),
    (0x1667bfc, '488b742438', 'pair insert: map = temp from [rsp+0x38] (rsi)'),
    (0x1667c01, '488b542440', 'pair insert: key ptr from [rsp+0x40] (rdx)'),
    (0x1667c06, '4c8d8424b8000000', 'pair insert: value record at rsp+0xb8 (r8)'),
    (0x1667c0e, 'e87d170000', 'pair insert: call the map insert'),
    (0x1667d63, '498b5c2448', 'base case: inner pointer [ctx +0x48] load'),
    (0x1667d6b, '0f844b010000', 'base case: inner == 0 -> drain loop'),
    (0x1667d95, '0f1005ccf7d904', 'base case: template block from 0x6407568'),
    (0x1667da4, '0f1005adf7d904', 'base case: template block from 0x6407558'),
    (0x1667ded, '48894b18', 'base case: recursion head word [inner +0x18] = sentinel'),
    (0x1667e3d, 'e83ef9ffff', 'base case: recursive call to the merge builder'),
    (0x1667eb7, 'e8940f0000', 'base case: local value destroyed via the value dtor'),
    (0x1667ebc, '498b5718', 'drain: temp items [r15 +0x18] load'),
    (0x1667ee6, '4983c418', 'drain: ctx +0x18 applied to r12 (target table header)'),
    (0x1667f62, '4b8b44f5b8', 'drain: entry key ptr saved'),
    (0x1667f6c, '4b8b44f5c0', 'drain: entry key len saved'),
    (0x1667fd9, 'e8f215ffff', 'drain: call the value copy helper'),
    (0x166801d, '4c89f7', 'drain insert: out record = the copy record (rdi = r14)'),
    (0x1668020, '488b742428', 'drain insert: map header from [rsp+0x28] (rsi)'),
    (0x1668025, '488b542458', 'drain insert: key ptr from [rsp+0x58] (rdx)'),
    (0x166802a, '488b4c2450', 'drain insert: key len from [rsp+0x50] (rcx)'),
    (0x166802f, '4c8d442460', 'drain insert: value record at rsp+0x60 (r8)'),
    (0x1668034, 'e857130000', 'drain insert: call the map insert'),
    (0x166804f, '4839c6', 'drain insert: displaced-value head vs sentinel compare'),
    (0x16680d9, '4c8b642428', 'drain loop: r12 restored from [rsp+0x28]'),
]
INSERT_PINS = [
    (0x16693a4, '4989f5', 'table header (arg2) into r13'),
    (0x16693be, '4c8d6620', 'hash state = header +0x20'),
    (0x16693ca, 'e8d1c9ffff', 'call the temp-layout key hash 0x1665da0'),
    (0x16693d2, '49837d1000', 'growth-left [header +0x10] == 0 test (reserve path)'),
    (0x1669588, '47883404', 'fresh insert: control byte store at the bucket'),
    (0x166958c, '4588740c10', 'fresh insert: control byte mirror store'),
    (0x16695a7, '660ffbc1', 'fresh insert: psubq growth accounting over [header +0x10]'),
    (0x16695bd, '49894cc4b8', 'fresh insert: key ptr stored at entry +0x0'),
    (0x16695c2, '498954c4c0', 'fresh insert: key len stored at entry +0x8'),
    (0x16695d5, '410f1144c4c8', 'fresh insert: value record stored at entry +0x10'),
    (0x1669551, '410f1147c8', 'replace: new value record block stored over the old'),
    (0x1669564, '498947f8', 'replace: last value word stored'),
    (0x16695f0, '48b80000000000000080', 'sentinel constant 0x8000000000000000'),
    (0x16695fa, '488906', 'fresh insert: sentinel written to the out record'),
    (0x166961f, 'ff15bb87e704', 'reserve: call through slot 0x64e1de0'),
]
GETORINSERT_PINS = [
    (0x166755a, '48837f3000', 'empty-map test at [map +0x30]'),
    (0x1667565, '498d7f38', 'hasher state at map +0x38'),
    (0x166756f, 'e89ce9ffff', 'call the ctx-layout key hash 0x1665f10'),
    (0x166766c, '48c744247801000000', 'default record +0x30 (counter) = 1'),
    (0x1667675, '48c744244800000000', 'default record +0x0 = 0'),
    (0x166767e, '48c744245008000000', 'default record +0x8 = 8'),
    (0x166768b, 'f30f7f442458', 'default record +0x10/+0x18 = 0'),
    (0x1667691, '48c744246808000000', 'default record +0x20 (object word) = 8'),
    (0x166769a, '48c744247000000000', 'default record +0x28 (getter presence word) = 0'),
    (0x16676a3, '4983c718', 'insert target = table header at map +0x18'),
    (0x16676af, '4c8d442448', 'insert value = the default record at rsp+0x48'),
    (0x16676bd, 'e8ce1c0000', 'call the map insert'),
    (0x166772c, '498b45f8', 'found path: value counter word load at entry +0x40'),
    (0x1667739, '498945f8', 'found path: incremented counter stored back'),
]
REMOVEOP_PINS = [
    (0x1668415, 'ff5228', 'descriptor iterator call through [descriptor +0x28]'),
    (0x1668536, 'e8d5d9ffff', 'call the ctx-layout key hash 0x1665f10'),
    (0x16685d2, 'ff152074e704', 'ctx probe: bcmp through slot 0x64df9f8'),
    (0x16686dc, '48ff4228', 'found path: growth-left [ctx +0x28] incremented (removal)'),
    (0x16686e2, '41881407', 'found path: tombstone control byte store'),
    (0x16686e6, '4188540f10', 'found path: tombstone control byte mirror store'),
    (0x16686f0, '48ff4830', 'found path: items [ctx +0x30] decremented (removal)'),
]
VALUECOPY_PINS = [
    (0x16595de, '4c8b7e10', 'buffer word count load at [src +0x10]'),
    (0x1659614, '488b6e08', 'buffer pointer load at [src +0x8]'),
    (0x165961b, 'ff155f5ee804', 'buffer allocation through slot 0x64df480'),
]
GETTER_PINS = [
    (0x4e4ca3e, '48837f3000', 'getter: empty-map test at [map +0x30]'),
    (0x4e4ca4f, '488d4738', 'getter: hasher state at map +0x38'),
    (0x4e4ca59, 'e8e25b0000', 'getter: call the key hash 0x4e52640'),
    (0x4e4ca65, '4d8b7c2418', 'getter: entries base from [map +0x18]'),
    (0x4e4ca6a, '498b742420', 'getter: bucket mask from [map +0x20]'),
    (0x4e4ca87, '4c8b256a2f6901', 'getter: bcmp fn ptr loaded from slot 0x64df9f8'),
    (0x4e4cadb, '493b5cc7c0', 'getter: key length compare against the entry'),
    (0x4e4cae6, '488b75b8', 'getter: entry key pointer load'),
    (0x4e4caf0, '41ffd4', 'getter: bcmp call through r12'),
    (0x4e4cb4c, '48837df000', 'getter: value presence test at entry +0x38'),
    (0x4e4cb53, '488b45e8', 'getter: value object pointer from entry +0x30'),
    (0x4e4cb57, '488b7008', 'getter: value string pointer at [object +0x8]'),
    (0x4e4cb5b, '488b5010', 'getter: value string length at [object +0x10]'),
    (0x4e4cb64, 'ff153e316901', 'getter: value converter through slot 0x64dfca8'),
]
OWNER_PINS = {'registry_worker': WORKER_PINS, 'value_merge_builder': BUILDER_PINS,
              'map_insert': INSERT_PINS, 'get_or_insert': GETORINSERT_PINS,
              'ctx_remove_op': REMOVEOP_PINS, 'value_copy': VALUECOPY_PINS}
REF_PINS = {'field_getter': GETTER_PINS}


def read(data, va, n):
    for sec in sections(data):
        if sec['type'] != 8 and sec['address'] <= va and va + n <= sec['address'] + sec['size']:
            return data[sec['offset'] + va - sec['address']:sec['offset'] + va - sec['address'] + n]
    raise ValueError(f'unmapped read {va:#x}+{n}')


def relocations(data):
    """All dynamic relocations as dicts. Covers .rela.dyn and .rela.plt:
    (slot, type, sym index, addend, addend file offset)."""
    out = []
    for name in ('.rela.dyn', '.rela.plt'):
        sec = next((s for s in sections(data) if s['name'] == name), None)
        if sec is None:
            continue
        for i, (off, info, add) in enumerate(
                struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']])):
            out.append({'slot': off, 'type': info & 0xffffffff, 'sym': info >> 32,
                        'addend': add, 'addend_file_offset': sec['offset'] + 24 * i + 16,
                        'offset_file_offset': sec['offset'] + 24 * i})
    return out


def dynsym_name(data, index):
    sym = next(s for s in sections(data) if s['name'] == '.dynsym')
    strs = next(s for s in sections(data) if s['name'] == '.dynstr')
    st_name = struct.unpack_from('<I', data, sym['offset'] + 24 * index)[0]
    start = strs['offset'] + st_name
    return data[start:data.index(b'\0', start)].decode()


def _pin(body, base, va, hexbytes, what):
    want = bytes.fromhex(hexbytes)
    if body[va - base:va - base + len(want)] != want:
        raise ValueError(f'byte pin failed for {what} at {va:#x}')


def _call_target(body, base, va, insn_len=5):
    disp = struct.unpack_from('<i', body, va - base + 1)[0]
    return va + insn_len + disp


def _slot_target(body, base, va):
    disp = struct.unpack_from('<i', body, va - base + 2)[0]
    return va + 6 + disp


def _rip_target(body, base, va, insn_len):
    disp = struct.unpack_from('<i', body, va - base + insn_len - 4)[0]
    return va + insn_len + disp


def _fde_owner(data):
    _summary, extents, _records = fde_extents(data)
    starts = sorted(e['start'] for e in extents)
    ends = {e['start']: e['end'] for e in extents}

    def owner(va):
        i = bisect.bisect_right(starts, va) - 1
        return starts[i] if i >= 0 and starts[i] <= va < ends[starts[i]] else None

    return owner


def _role_of(fde_start):
    for table in (OWNERS, REF_BODIES):
        for role, rng in table.items():
            if rng[0] == fde_start:
                return role
    return None


def body_call_census(body, base, targets):
    """Find-based direct call/jump census inside one body for the
    given target VAs. Sites inside packet owners are additionally
    validated as instruction starts by generate()."""
    by_va = {va: [] for va in targets}
    for opcode in (b'\xe8', b'\xe9'):
        idx = body.find(opcode)
        while idx != -1:
            site = base + idx
            tgt = site + 5 + struct.unpack_from('<i', body, idx + 1)[0]
            if tgt in by_va:
                by_va[tgt].append(site)
            idx = body.find(opcode, idx + 1)
    return by_va


def body_slot_census(body, base, slots):
    """Find-based ff 15 / ff 25 RIP-relative census inside one body
    for the given slots."""
    by_slot = {slot: [] for slot in slots}
    for opcode in (b'\xff\x15', b'\xff\x25'):
        idx = body.find(opcode)
        while idx != -1:
            site = base + idx
            if site + 6 + struct.unpack_from('<i', body, idx + 2)[0] in by_slot:
                by_slot[site + 6 + struct.unpack_from('<i', body, idx + 2)[0]].append(site)
            idx = body.find(opcode, idx + 1)
    return by_slot


def body_lea_targets(body, base):
    """Find-based census of RIP-relative lea targets inside one
    body: REX and non-REX forms with ModRM mod=00 rm=101."""
    hits = []
    for i in range(len(body) - 7):
        b0 = body[i]
        if 0x40 <= b0 <= 0x4f and body[i + 1] == 0x8d and (body[i + 2] & 0xc7) == 0x05:
            hits.append((base + i, base + i + 7 + struct.unpack_from('<i', body, i + 3)[0]))
        elif b0 == 0x8d and (body[i + 1] & 0xc7) == 0x05:
            hits.append((base + i, base + i + 6 + struct.unpack_from('<i', body, i + 2)[0]))
    return hits


def slot_census(data, slot, owner):
    text = next(s for s in sections(data) if s['name'] == '.text')
    blob = data[text['offset']:text['offset'] + text['size']]
    base = text['address']
    found = []
    for opcode in (b'\xff\x15', b'\xff\x25'):
        idx = blob.find(opcode)
        while idx != -1:
            site = base + idx
            if site + 6 + struct.unpack_from('<i', blob, idx + 2)[0] == slot:
                fde = owner(site)
                found.append({'site': hex(site),
                              'fde_start': hex(fde) if fde else None,
                              'owner': _role_of(fde) if fde else None})
            idx = blob.find(opcode, idx + 1)
    return sorted(found, key=lambda e: e['site'])


PSUBQ = bytes.fromhex('660ffb')


def analyze(data):
    rels = relocations(data)
    rel_by_slot = {}
    for entry in rels:
        rel_by_slot.setdefault(entry['slot'], []).append(entry)

    bindings = {}
    for slot, (target, name) in SLOTS.items():
        entries = rel_by_slot.get(slot, [])
        require(len(entries) == 1, f'slot {slot:#x} relocation count changed')
        entry = entries[0]
        if isinstance(target, str):
            require(entry['type'] == 6 and dynsym_name(data, entry['sym']) == target,
                    f'{name} slot binding changed')
            bindings[hex(slot)] = {'target': target, 'name': name,
                                   'rela_type': entry['type']}
        else:
            require(entry['type'] == 8 and entry['addend'] == target,
                    f'{name} slot binding changed')
            bindings[hex(slot)] = {'target': hex(target), 'name': name,
                                   'rela_type': entry['type']}

    # Which slots anywhere in the binary bind the three map helpers?
    slots_binding = {INSERT_VA: [], GETORINSERT_VA: [], REMOVEOP_VA: []}
    for entry in rels:
        if entry['type'] == 8 and entry['addend'] in slots_binding:
            slots_binding[entry['addend']].append(entry['slot'])
    require(slots_binding[INSERT_VA] == [],
            'a slot now binds the map insert directly')
    require(slots_binding[GETORINSERT_VA] == [0x64e1ba8],
            'get-or-insert slot binding census changed')
    require(slots_binding[REMOVEOP_VA] == [0x64e1c70],
            'remove-op slot binding census changed')

    owners = {}
    bodies = {}
    for table in (OWNERS, REF_BODIES):
        for role, (start, end) in table.items():
            body = read(data, start, end - start)
            bodies[role] = (body, start)
            owners[role] = {'role': role, 'start': hex(start), 'end': hex(end),
                            'bytes': end - start,
                            'sha256': hashlib.sha256(body).hexdigest(),
                            'file_offset': hex(start - 0x1000)}
    for role, pins in OWNER_PINS.items():
        body, base = bodies[role]
        for va, hexbytes, what in pins:
            _pin(body, base, va, hexbytes, what)
    for role, pins in REF_PINS.items():
        body, base = bodies[role]
        for va, hexbytes, what in pins:
            _pin(body, base, va, hexbytes, what)

    for name, (start, size, sha) in BOUNDARIES.items():
        body = read(data, start, size)
        require(hashlib.sha256(body).hexdigest() == sha,
                f'boundary {name} body hash changed')
    callee_records = {}
    for start, (size, sha) in WORKER_CALLEES.items():
        body = read(data, start, size)
        require(hashlib.sha256(body).hexdigest() == sha,
                f'worker callee {start:#x} body hash changed')
        callee_records[start] = body

    require(read(data, CHAIN_NAME_VA, 5) == b'chain', 'chain name bytes changed')

    # ---- registry worker censuses -------------------------------------
    wbody, wbase = bodies['registry_worker']
    wdirect = body_call_census(wbody, wbase,
                               {INSERT_VA, GETORINSERT_VA, REMOVEOP_VA,
                                0x162f9c0, 0x162fc50, WORKER[0]})
    require(wdirect[INSERT_VA] == [], 'worker gained a direct call to the map insert')
    require(wdirect[GETORINSERT_VA] == [], 'worker gained a direct call to get-or-insert')
    require(wdirect[REMOVEOP_VA] == [], 'worker gained a direct call to the remove op')
    require(wdirect[0x162f9c0] == [0x1632783], 'worker entry-value builder call census changed')
    require(wdirect[0x162fc50] == [0x1631720], 'worker entry-value builder twin call census changed')
    require(wdirect[WORKER[0]] == [0x1633e56], 'worker recursion census changed')
    wslot = body_slot_census(wbody, wbase,
                             {0x64e1ba8, 0x64e1c70, 0x64e1cb8, 0x64e1cb0, 0x64e1bb8,
                              0x64e1ba0, 0x64e1c58, 0x64e1c40})
    require(wslot[0x64e1ba8] == [0x16327b9, 0x163281e],
            'worker get-or-insert slot call census changed')
    require(wslot[0x64e1c70] == [0x16317bf, 0x1632743, 0x1634350],
            'worker remove-op slot call census changed')
    require(wslot[0x64e1cb8] == [0x16343d1], 'worker final-assembly slot call census changed')
    require(wslot[0x64e1cb0] == [0x163436b], 'worker after-worker slot call census changed')
    require(wslot[0x64e1bb8] == [0x16327cd], 'worker entry-name register slot call census changed')
    require(wslot[0x64e1ba0] == [0x1631e47], 'worker counter A slot call census changed')
    require(wslot[0x64e1c58] == [0x1631c90], 'worker counter B slot call census changed')
    require(wslot[0x64e1c40] == [0x163180c], 'worker predecessor slot call census changed')
    for site, slot in ((0x16327b9, 0x64e1ba8), (0x163281e, 0x64e1ba8),
                       (0x16317bf, 0x64e1c70), (0x1632743, 0x64e1c70),
                       (0x1634350, 0x64e1c70), (0x16343d1, 0x64e1cb8),
                       (0x163436b, 0x64e1cb0), (0x16327cd, 0x64e1bb8),
                       (0x1631e47, 0x64e1ba0), (0x1631c90, 0x64e1c58),
                       (0x163180c, 0x64e1c40)):
        require(_slot_target(wbody, wbase, site) == slot,
                f'worker slot call target changed at {site:#x}')
    require(wbody.count(PSUBQ) == 0
            and wbody.count(bytes.fromhex('660f74')) == 0
            and wbody.count(bytes.fromhex('f30fbc')) == 0,
            'worker gained inline probe or growth-accounting bytes')
    wlea = body_lea_targets(wbody, wbase)
    wlea_targets = {t for _s, t in wlea}
    require(CHAIN_NAME_VA not in wlea_targets,
            'worker gained a reference to the chain key bytes')
    require(wbody.count(struct.pack('<I', CHAIN_NAME_VA)) == 0,
            'worker body gained a raw occurrence of the chain key address')
    require({0x165bae0, 0x165bbd0, 0x1666c80, 0x16697c0} <= wlea_targets,
            'worker callback lea census changed')

    # Descriptor-table function-pointer census: no table the worker
    # can dispatch through names any of the three map helpers.
    descriptor = {}
    for base_va, length in DESCRIPTOR_RANGES:
        targets = sorted({e['addend'] for e in rels
                          if e['type'] == 8 and base_va <= e['slot'] < base_va + length})
        require(not ({INSERT_VA, GETORINSERT_VA, REMOVEOP_VA} & set(targets)),
                f'descriptor range at {base_va:#x} gained a map-helper pointer')
        descriptor[hex(base_va)] = {'distinct_targets': len(targets)}

    # Insert capability of every worker callee (direct call, bound
    # slot, or an inline psubq growth accounting of its own).
    binding_of_slot = {}
    for entry in rels:
        if entry['type'] == 8:
            binding_of_slot[entry['slot']] = entry['addend']
    capability = {'calls_insert': [], 'calls_get_or_insert': [],
                  'calls_remove_op': [], 'psubq_bodies': []}
    for start, body in callee_records.items():
        direct = body_call_census(body, start, {INSERT_VA, GETORINSERT_VA, REMOVEOP_VA})
        slotc = body_slot_census(body, start, set(binding_of_slot))
        slot_targets = {binding_of_slot[s] for s, sites in slotc.items() if sites}
        if direct[INSERT_VA] or INSERT_VA in slot_targets:
            capability['calls_insert'].append(hex(start))
        if direct[GETORINSERT_VA] or GETORINSERT_VA in slot_targets:
            capability['calls_get_or_insert'].append(hex(start))
        if direct[REMOVEOP_VA] or REMOVEOP_VA in slot_targets:
            capability['calls_remove_op'].append(hex(start))
        if body.count(PSUBQ):
            capability['psubq_bodies'].append(hex(start))
    require(capability['calls_insert'] == [hex(GETORINSERT_VA)],
            'worker callee insert-capability census changed')
    require(capability['calls_get_or_insert'] == [],
            'a worker callee gained a call to get-or-insert')
    require(capability['calls_remove_op'] == [],
            'a worker callee gained a call to the remove op')
    require(capability['psubq_bodies'] == [],
            'a worker callee gained inline growth accounting')

    # ---- counter callee censuses --------------------------------------
    for role, site in (('entry_counter_a', 0x162cf0b), ('entry_counter_b', 0x163a239)):
        cbody, cbase = bodies[role]
        cslot = body_slot_census(cbody, cbase, {0x64e1ba8})
        require(cslot[0x64e1ba8] == [site], f'{role} get-or-insert slot call census changed')
        require(_slot_target(cbody, cbase, site) == 0x64e1ba8,
                f'{role} get-or-insert slot target changed')
        cdirect = body_call_census(cbody, cbase, {INSERT_VA, GETORINSERT_VA, REMOVEOP_VA})
        require(all(not v for v in cdirect.values()),
                f'{role} gained a direct helper call')
        require(cbody.count(PSUBQ) == 0, f'{role} gained inline growth accounting')

    owner_of = _fde_owner(data)
    get_or_insert_sites = slot_census(data, 0x64e1ba8, owner_of)
    require([(e['site'], e['owner']) for e in get_or_insert_sites] == [
        ('0x162cf0b', 'entry_counter_a'), ('0x16327b9', 'registry_worker'),
        ('0x163281e', 'registry_worker'), ('0x163a239', 'entry_counter_b')],
        'whole-binary get-or-insert slot call census changed')
    remove_op_sites = slot_census(data, 0x64e1c70, owner_of)
    require([(e['site'], e['owner']) for e in remove_op_sites] == [
        ('0x16317bf', 'registry_worker'), ('0x1632743', 'registry_worker'),
        ('0x1634350', 'registry_worker')],
        'whole-binary remove-op slot call census changed')

    # ---- merge builder censuses ---------------------------------------
    bbody, bbase = bodies['value_merge_builder']
    bdirect = body_call_census(bbody, bbase,
                               {INSERT_VA, VALUECOPY[0], 0x1665f10, 0x1665da0,
                                BUILDER[0], 0x1668e50})
    require(bdirect[INSERT_VA] == [0x1667c0e, 0x1668034],
            'builder map-insert call census changed')
    require(bdirect[VALUECOPY[0]] == [0x1667a47, 0x1667af9, 0x1667ba8, 0x1667fd9],
            'builder value-copy call census changed')
    require(bdirect[0x1665f10] == [0x1667cdd], 'builder ctx-hash call census changed')
    require(bdirect[0x1665da0] == [0x16678eb], 'builder temp-hash call census changed')
    require(bdirect[BUILDER[0]] == [0x1667e3d], 'builder recursion census changed')
    require(bdirect[0x1668e50] == [0x1667eb7, 0x16681e4],
            'builder value-dtor call census changed')
    for site in (0x1667c0e, 0x1668034):
        require(_call_target(bbody, bbase, site) == INSERT_VA,
                f'builder insert call target changed at {site:#x}')
    blea_targets = {t for _s, t in body_lea_targets(bbody, bbase)}
    require(CHAIN_NAME_VA not in blea_targets,
            'builder gained a reference to the chain key bytes')
    require(bbody.count(struct.pack('<I', CHAIN_NAME_VA)) == 0,
            'builder body gained a raw occurrence of the chain key address')
    require(_rip_target(bbody, bbase, 0x1667d95, 7) == 0x6407568,
            'builder base-case template block 2 target changed')
    require(_rip_target(bbody, bbase, 0x1667da4, 7) == 0x6407558,
            'builder base-case template block 1 target changed')

    # ---- helper censuses ----------------------------------------------
    ibody, ibase = bodies['map_insert']
    idirect = body_call_census(ibody, ibase, {0x1665da0, 0x1668f00})
    require(idirect[0x1665da0] == [0x16693ca], 'insert hash call census changed')
    require(idirect[0x1668f00] == [0x1669649], 'insert unwind call census changed')
    islot = body_slot_census(ibody, ibase, {0x64e1de0})
    require(islot[0x64e1de0] == [0x166961f], 'insert reserve slot call census changed')
    require(ibody.count(PSUBQ) == 1, 'insert psubq census changed')

    gbody, gbase = bodies['get_or_insert']
    gdirect = body_call_census(gbody, gbase, {0x1665f10, INSERT_VA})
    require(gdirect[0x1665f10] == [0x166756f], 'get-or-insert hash call census changed')
    require(gdirect[INSERT_VA] == [0x16676bd], 'get-or-insert insert call census changed')
    require(_call_target(gbody, gbase, 0x16676bd) == INSERT_VA,
            'get-or-insert insert call target changed')

    rbody, rbase = bodies['ctx_remove_op']
    rdirect = body_call_census(rbody, rbase, {0x1665f10, 0x1672490, INSERT_VA})
    require(rdirect[0x1665f10] == [0x1668536], 'remove-op hash call census changed')
    require(rdirect[0x1672490] == [0x1668503], 'remove-op predicate call census changed')
    require(rdirect[INSERT_VA] == [], 'remove op gained a call to the map insert')
    rslot = body_slot_census(rbody, rbase, {0x64e1dd0, 0x64e1df8, 0x64df9f8})
    require(rslot[0x64e1dd0] == [0x166865f, 0x1668849],
            'remove-op vec-grow slot call census changed')
    require(rslot[0x64e1df8] == [0x166876d, 0x16688d8],
            'remove-op continuation slot call census changed')
    require(rslot[0x64df9f8] == [0x16684e7, 0x16685d2, 0x16687ec],
            'remove-op bcmp slot call census changed')

    records = {
        'target_sha256': TARGET_SHA256,
        'target_size': TARGET_SIZE,
        'captured_code_executed': False,
        'owners': [owners[r] for r in
                   ('registry_worker', 'value_merge_builder', 'map_insert',
                    'get_or_insert', 'ctx_remove_op', 'value_copy',
                    'entry_counter_a', 'entry_counter_b')],
        'reference_bodies': [owners[r] for r in ('field_getter',)],
        'boundaries': {name: {'start': hex(start), 'bytes': size, 'sha256': sha}
                       for name, (start, size, sha) in BOUNDARIES.items()},
        'worker_callees': {hex(start): {'bytes': size, 'sha256': sha}
                           for start, (size, sha) in sorted(WORKER_CALLEES.items())},
        'slot_bindings': bindings,
        'helper_slot_bindings': {
            'map_insert': [], 'get_or_insert': ['0x64e1ba8'],
            'ctx_remove_op': ['0x64e1c70']},
        'worker_census': {
            'direct_insert_calls': [],
            'direct_get_or_insert_calls': [],
            'direct_remove_op_calls': [],
            'get_or_insert_slot_sites': [hex(s) for s in wslot[0x64e1ba8]],
            'remove_op_slot_sites': [hex(s) for s in wslot[0x64e1c70]],
            'final_assembly_slot_site': hex(wslot[0x64e1cb8][0]),
            'counter_a_slot_site': hex(wslot[0x64e1ba0][0]),
            'counter_b_slot_site': hex(wslot[0x64e1c58][0]),
            'predecessor_slot_site': hex(wslot[0x64e1c40][0]),
            'whole_binary_get_or_insert_sites': get_or_insert_sites,
            'whole_binary_remove_op_sites': remove_op_sites,
            'chain_name_references': 'none (lea census and raw dword census both empty)',
            'descriptor_tables': descriptor,
            'callee_capability': capability,
        },
        'builder_census': {
            'insert_call_sites': [hex(s) for s in bdirect[INSERT_VA]],
            'value_copy_call_sites': [hex(s) for s in bdirect[VALUECOPY[0]]],
            'ctx_hash_call_sites': [hex(s) for s in bdirect[0x1665f10]],
            'temp_hash_call_sites': [hex(s) for s in bdirect[0x1665da0]],
            'recursion_site': hex(bdirect[BUILDER[0]][0]),
            'chain_name_references': 'none (lea census and raw dword census both empty)',
        },
        'helper_census': {
            'map_insert': {'hash_call_site': hex(idirect[0x1665da0][0]),
                           'reserve_slot_site': hex(islot[0x64e1de0][0]),
                           'psubq_count': 1},
            'get_or_insert': {'hash_call_site': hex(gdirect[0x1665f10][0]),
                              'insert_call_site': hex(gdirect[INSERT_VA][0])},
            'ctx_remove_op': {'hash_call_site': hex(rdirect[0x1665f10][0]),
                              'insert_call_sites': [],
                              'vec_grow_slot_sites': [hex(s) for s in rslot[0x64e1dd0]],
                              'continuation_slot_sites': [hex(s) for s in rslot[0x64e1df8]]},
        },
        'map_layout': {
            'value': '0x50 bytes: prefix +0x0..+0x18; table header at +0x18 '
                     '(buckets +0x18, mask +0x20, growth-left +0x28, items +0x30); '
                     'hash state +0x38 (16 bytes); inner pointer +0x48',
            'table_header': 'standalone form (temp): buckets +0x0, mask +0x8, '
                            'growth-left +0x10, items +0x18, hash state +0x20',
            'entry': 'stride 0x48: key ptr +0x0, key len +0x8, value record '
                     '(0x38 bytes) at +0x10; value +0x20 = value-object pointer, '
                     'value +0x28 = getter presence word, value +0x30 = counter word',
            'getter_read': 'items gate [map +0x30]; hash 0x4e52640 over state '
                           'at map +0x38; on a key match the presence word at '
                           'entry +0x38 must be nonzero, then the string is '
                           '([object +0x8], [object +0x10]) of the object at '
                           'entry +0x30',
        },
        'path_a_registry_worker': {
            'insert_into_result': 'none: no direct or slot call to the shared '
                                  'insert-or-replace 0x1669390 anywhere in the '
                                  'worker body, and no worker callee reaches it '
                                  'except get-or-insert 0x1667540',
            'get_or_insert_sites': '0x16327b9 (spec entry name key) and '
                                   '0x163281e (per-element string keys, loop); '
                                   'both pass the ctx (arg3, saved at [rsp+0x30]) '
                                   'as the map — never the result pointer saved '
                                   'at [rsp+0x58]. Two dedicated counter callees '
                                   'reach the same helper: entry_counter_a '
                                   '0x162cee0 at its site 0x162cf0b (map = its '
                                   'arg4, which the worker fills with the ctx '
                                   'at 0x1631e42; key from its arg3 +0x78/+0x80) '
                                   'and entry_counter_b 0x163a070 at its site '
                                   '0x163a239 (map = its first stack argument, '
                                   'which the worker stores the ctx into at '
                                   '0x1631c7f; key = the spec entry name at '
                                   '+0x170/+0x178). A whole-binary census of '
                                   'slot 0x64e1ba8 finds exactly these four '
                                   'call sites',
            'remove_op_sites': '0x16317bf, 0x1632743, 0x1634350 — all pass the '
                               'ctx as first argument; the helper deletes ctx '
                               'entries (items decrement at ctx +0x30, '
                               'growth-left increment at ctx +0x28, tombstone '
                               'control bytes)',
            'inserted_default': 'the get-or-insert default record has word 0 at '
                                'value +0x28, so the getter presence gate would '
                                'reject any entry it creates; its counter word '
                                'at value +0x30 starts at 1 and is incremented '
                                'on a hit',
            'result_writes': 'direct field stores from frame-local structs at '
                             'the exit sites pinned in the packet (items word '
                             '[result +0x30], buckets word [result +0x18], and '
                             'block copies), plus the delegated final-assembly '
                             'call at 0x16343d1 (slot 0x64e1cb8 -> 0x164df60, '
                             'hash-pinned boundary) with (result, three frame '
                             'structs, ctx)',
            'verdict': 'the chain entry is not inserted into the result map '
                       'inside the registry worker body; the worker\'s only '
                       'map inserts target the ctx, with spec-derived keys '
                       'and a counter default value the getter cannot read '
                       'as a string',
        },
        'path_b_merge_builder': {
            'pair_insert': 'site 0x1667c0e -> 0x1669390 with map = temp '
                           '([rsp+0x38]), key = the pair\'s own (ptr, len), '
                           'value record built at rsp+0xb8 from the ctx/temp '
                           'entries via the value copy helper 0x16595d0; '
                           'reached only below the ctx-match fall-through '
                           '(bcmp at 0x1667868, je at 0x1667870): a ctx miss '
                           'exits through the empty-group edge at 0x16678b8 '
                           'to the next-pair edge 0x1667ca0 with no insert',
            'drain_insert': 'site 0x1668034 -> 0x1669390 with map header = '
                            'ctx +0x18 (r12 advanced by the single +0x18 add '
                            'at 0x1667ee6, saved/restored through [rsp+0x28]), '
                            'key = the temp entry\'s own key ptr/len (saved '
                            'at 0x1667f62/0x1667f6c), value = the temp entry\'s '
                            'value copied via 0x16595d0 at 0x1667fd9; the '
                            'displaced old value\'s head is compared against '
                            'the sentinel at 0x166804f and dropped when '
                            'different',
            'base_case': 'pair count == 0 or ctx items == 0 -> 0x1667d63: '
                         'with an inner pointer at [ctx +0x48], a local '
                         'header is built from the template at '
                         '0x6407558/0x6407568 and the inner pointee\'s '
                         'fields, its [inner +0x18] word is set to the '
                         'sentinel, the builder recurses (0x1667e3d), and '
                         'the resulting fields are swapped back; with no '
                         'inner pointer it falls straight into the drain',
            'verdict': 'the builder never creates a key and never references '
                       'the chain key bytes at 0x92a7be; a chain entry '
                       'reaches the getter\'s map in path B only through '
                       'the drain insert at 0x1668034, and only if the '
                       'temp table holds a chain entry at drain time — '
                       'pre-existing from the core-built temp, or staged '
                       'by the pair loop when a spec pair\'s key is '
                       '"chain" and "chain" is already present in the ctx',
        },
        'boundary': 'what the final-assembly callee 0x164df60 and the '
                    'worker\'s frame-struct builders (0x162f9c0, 0x162fc50 '
                    'and the per-entry helpers) write into the structs the '
                    'worker copies into the path-A result is inside those '
                    'hash-pinned boundaries; likewise who first writes a '
                    'chain key into the path-B ctx, the core-built temp, or '
                    'the spec entry array the pairs are taken from is '
                    'upstream of the core boundary pinned by #2486. Which '
                    'of paths A/B a given run takes, and the runtime '
                    'contents of the registry, are execution facts outside '
                    'static evidence.',
        'limits': 'Static evidence only: byte pins, relocation bindings, '
                  'and find-based censuses validated as instruction starts '
                  'for every asserted site inside a packet owner. No '
                  'captured code was executed. Semantic names (spec, '
                  'value, ctx, temp, registry) follow the earlier RE-005 '
                  'packets and the byte-level roles proven here; no type '
                  'names are claimed.',
        'validation': 'tools/chain_entry_insert_static.py regenerates '
                      'records.json, frames.txt and the disassembly '
                      'exports from the authenticated artifact and '
                      're-derives every pin, binding, and census; '
                      'tests/test_chain_entry_insert_static.py asserts '
                      'regeneration byte-identity and counterfactual '
                      'rejection.',
        'next_question': 'For path A, which of the worker\'s '
                         'frame-struct builders — or the delegated '
                         'final assembly 0x164df60 — first writes a '
                         'chain entry into a value-layout table, and '
                         'can the ctx table the worker\'s get-or-insert '
                         'pass counts spec names into be the same table '
                         'the result is later copied from? For path B, '
                         'who first writes a chain key into the registry '
                         'ctx the builder merges from, or into the spec '
                         'entry array the pairs are taken from?',
    }
    return records


def executable(path, args, marker=None):
    out = subprocess.run([str(path), *args], capture_output=True, text=True,
                         check=False)
    require(out.returncode == 0, f'{path} failed: {out.stderr.strip()}')
    if marker is not None:
        require(marker in out.stdout, f'{path} output changed')
    return out.stdout


def generate(binary, output):
    data = Path(binary).read_bytes()
    if len(data) != TARGET_SIZE or hashlib.sha256(data).hexdigest() != TARGET_SHA256:
        raise ValueError('expected pinned node115')
    records = analyze(data)
    output.mkdir(parents=True, exist_ok=True)
    bodies = {}
    for table in (OWNERS, REF_BODIES):
        for role, (start, end) in table.items():
            bodies[role] = (read(data, start, end - start), start, end)

    def export(role, start, end, body, name):
        text = executable('objdump',
                          ['-d', '-M', 'intel', '--insn-width=16',
                           f'--start-address={start:#x}',
                           f'--stop-address={end:#x}', str(binary)])
        insns = decode_export(text, start, end, body)
        (output / name).write_text(text)
        return insns

    export_roles = ('value_merge_builder', 'map_insert', 'get_or_insert',
                    'ctx_remove_op', 'value_copy', 'field_getter',
                    'entry_counter_a', 'entry_counter_b')
    for role in export_roles:
        body, start, end = bodies[role]
        export(role, start, end, body, f'{role}_disassembly.txt')
    for name, (start, end) in WORKER_WINDOWS.items():
        body = read(data, start, end - start)
        export(name, start, end, body, f'{name}.txt')
    # Instruction-start validation for every asserted site inside the
    # worker body (pins and census sites): decode the full body here
    # without committing the export.
    wbody, wstart, wend = bodies['registry_worker']
    text = executable('objdump',
                      ['-d', '-M', 'intel', '--insn-width=16',
                       f'--start-address={wstart:#x}',
                       f'--stop-address={wend:#x}', str(binary)])
    starts = set(decode_export(text, wstart, wend, wbody))
    asserted = [va for va, _h, _w in WORKER_PINS]
    asserted += [0x16327b9, 0x163281e, 0x16317bf, 0x1632743, 0x1634350,
                 0x16343d1, 0x163436b, 0x16327cd, 0x1632783, 0x1631720,
                 0x1633e56, 0x1631e47, 0x1631c90, 0x163180c]
    for site in asserted:
        require(site in starts, f'worker site {site:#x} is not an instruction start')

    readelf = executable('readelf',
                         ['--debug-dump=frames', str(binary)]).splitlines()
    cie_lines = {}
    for line in readelf:
        parts = line.split()
        if len(parts) >= 4 and parts[3] == 'CIE':
            cie_lines[parts[0]] = line

    def record(line):
        parts = line.split()
        return {'va': hex(int(parts[0], 16)), 'bytes_hex': parts[1] + parts[2]}

    def cie_record(line):
        parts = line.split()
        return {'va': hex(int(parts[0], 16)), 'bytes_hex': parts[1] + parts[2]}

    all_records = records['owners'] + records['reference_bodies']
    for entry in all_records:
        start = int(entry['start'], 16)
        end = int(entry['end'], 16)
        fde_line = next(l for l in readelf
                        if 'FDE' in l and f'pc={start:016x}..{end:016x}' in l)
        cie_ref = fde_line.split('cie=')[1].split()[0]
        entry['frames'] = {'fde': record(fde_line),
                           'cie': cie_record(cie_lines[cie_ref])}
    frames = []
    for entry in all_records:
        start = int(entry['start'], 16)
        end = int(entry['end'], 16)
        frames += [l for l in readelf
                   if 'FDE' in l and f'pc={start:016x}..{end:016x}' in l]
    (output / 'frames.txt').write_text('\n'.join(frames) + '\n')
    (output / 'records.json').write_text(
        json.dumps(records, indent=1, sort_keys=True) + '\n')
    return records


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', default=str(TARGET))
    parser.add_argument('--output', default=str(PACKET))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    if args.check:
        data = Path(args.binary).read_bytes()
        if len(data) != TARGET_SIZE or hashlib.sha256(data).hexdigest() != TARGET_SHA256:
            raise ValueError('expected pinned node115')
        records = analyze(data)
        print(json.dumps({'owners': len(records['owners']),
                          'worker_get_or_insert_sites':
                          records['worker_census']['get_or_insert_slot_sites'],
                          'builder_insert_sites':
                          records['builder_census']['insert_call_sites']}))
    else:
        generate(args.binary, Path(args.output))
        print(f'wrote {args.output}')


if __name__ == '__main__':
    main()
