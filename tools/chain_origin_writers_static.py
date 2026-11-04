#!/usr/bin/env python3
"""Static trace of the two trails above the RE-005 tag-writer packet.

The tag-writer packet (#2466) established that the apply function
0x564cce0 writes the chain-class byte at record +0x90 after reading
the value's "chain" field through the getter 0x4e4ca30, and that the
byte B4 reads at arg2 +0xbd5 is staged into Z's (0x2af77f0) own object
by a 0xbd8-byte memcpy from the object itself. It left two questions
open, and this packet answers both:

Trail 1 (chain origin). Where does the value's "chain" string
originate inside the inputs of the value producer 0x165de90 /
0x165dfb0? The producer's only slot-bound callers (B2 0x2ae41e0 and
the buffer converter 0x2b7b640, both owned by earlier packets) hand
it a 0x250-byte spec built by the spec builder 0x564d700. The wrapper
0x165de90 copies the spec onto its frame, and the core 0x165dfb0 is
its only direct caller. Inside the core, no instruction writes any
map entry: the core's own stores into its spec copy are exactly the
flag-byte or at +0x1ec and the file-loaded string move at
+0x38..+0x48, and the value (the map the getter reads) materialises
only inside two hash-pinned boundary helpers — the registry worker
0x1630c90 on path A, whose 0x50-byte result struct is copied into
out verbatim, or the merge builder 0x1667780 on path B, whose pair
input is extracted from the spec copy's +0x190/+0x198 entry array
(written by the spec builder's second block copy) and merged into
the ctx header that becomes out. The getter itself is a pure
hash-map lookup: it never stores to the map, an entry, or a value
object. So the "chain" string is input data at exactly those two
named boundaries; no traced code computes it.

Trail 2 (+0xbd5 writer above Z). Z has no direct .text call site
(the direct call/jump census is empty) and exactly one reference in
the whole binary: the RELATIVE relocation at slot 0x6447268, the
function-pointer word of a 0x28-byte static registration record at
0x6447260 pairing Z with its source location (base/src/lu.rs line
24, col 16). The record is one of 447 statics of the same shape in
.data.rel.ro. No .text instruction references Z, the record base, or
the fn-pointer slot by RIP-relative addressing, and neither the
record base nor the slot appears as data anywhere except the
relocation entry itself. The record's location field is referenced
independently as a &Location by panic sites in two lu.rs FDEs. The
trail therefore ends at a census-proven boundary: Z is reachable
only through that registration record, so whoever constructs the
object Z receives as arg1 — and first writes its +0xbd5 field — is
the external consumer of the registration, not traced code in this
binary.

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
PACKET = ROOT / 'research/work-items/RE-005-node115-chain-origin-writers'

PRODUCER = (0x165de90, 0x165dfaa)
CORE = (0x165dfb0, 0x165e513)
GETTER = (0x4e4ca30, 0x4e4cba7)
TLS_REGISTRY = (0x1668ce0, 0x1668d1c)
B2 = (0x2ae41e0, 0x2ae6d66)
APPLY = (0x564cce0, 0x564cf36)
SPEC = (0x564d700, 0x564df8c)
Z = (0x2af77f0, 0x2af8bd3)
CONVERTER = (0x2b7b640, 0x2b7b79c)

OWNERS = {'value_producer': PRODUCER, 'value_producer_core': CORE,
          'field_getter': GETTER, 'tls_registry': TLS_REGISTRY}
REF_BODIES = {'gb_b2': B2, 'chain_class_writer': APPLY,
              'spec_builder': SPEC, 'b4_caller_stager': Z}
# FDE starts used only to name census-site owners (owned by #2466).
CENSUS_OWNERS = {'buffer_converter': CONVERTER}

WORKER = 0x1630c90
BUILDER = 0x1667780
CHAIN_NAME_VA = 0x92a7be
Z_RECORD = 0x6447260
Z_SLOT = 0x6447268
Z_LOCATION = 0x6447270
Z_FILE_VA = 0x4326c1

BOUNDARIES = {
    'registry_worker': (0x1630c90, 17970,
                        'b38566cd8062d559cbc2d01f63fa4a80854ffbb6c65560a23ae26b27c5fa1791'),
    'value_merge_builder': (0x1667780, 2679,
                            'a3cd3033412c3b151c94388b3299fbf561644dbbe1d150ea7177e12b6b9fc37e'),
    'file_reader': (0x5cab560, 1041,
                    '969e7b89df3bbcae23c4cba1f0876a424c4eaa8e76dfdeb78ae87740fe31517a'),
    'container_init': (0x5c9a530, 473,
                       'b6b76f3468de4d602292c73e93663512580783d98eaaa7e6b263e90780c37ec0'),
    'container_dtor': (0x1675a40, 143,
                       'b6112b3f5fc4a62b1969119ba89dbc0cda7a7181ea1f07dc16b313f63641701e'),
    'spec_copy_dtor': (0x165e570, 1096,
                       'e0257afd1cedde9099cb7b04655126f7828c5ba9ef6d235df218fbbae48626c9'),
    'producer_ctx_dtor': (0x165ea30, 176,
                          'faa43a096df22e9a3a738007999c95e97070a4f84942dc21a21efbe292c998f6'),
    'merge_temp_dtor': (0x1666250, 383,
                        'd5f3eb8215b255054518ca78ef760d7d5a931263d47ab77cd7dc36e9d3ca1b0d'),
    'predicate_bit_test': (0x166abb0, 285,
                           '330f87930a81a26e7f565eb090b69cc73c93754e6fd8c0de5b3f4a81459ba224'),
    'record_fixup_a': (0x1635410, 216,
                       '1e7bf0747b29d8baf8feed03937f846b6ac9858905abdf0f613c0a2567a83a95'),
    'record_fixup_b': (0x1635ac0, 265,
                       'e58dc13733a510cafa5a41f61597e9cde12aff19733989e6c600bbe10262ad81'),
    'record_fixup_c': (0x1635e30, 585,
                       '768d8bb99eb35ade760ba6b58b8ee9480cfe97cc98479748e07a56bb20956862'),
    'value_converter': (0x16815e0, 503,
                        '3ff2fdb7228f89579b15327cfe53871b0d275e0c54668dfeca9b349800836de0'),
    'key_hash': (0x4e52640, 352,
                 '932c1acb8ca5b6a618258042875784bf789fe91e511657af2143f4f017945003'),
    'tls_cell_init': (0x5c9fd80, 48,
                      'effbfb286e9e1702f2f9533c24931929c8e6e22da264f579774acee9c5793c62'),
    'tls_lazy_init': (0x1671e70, 83,
                      '898139622d7cd464941bcae6e1b3afd6b0eca964ca7cc6e598e9d55e33c5f8ac'),
    'registry_panic_helper': (0x5c9d1c0, 47,
                              'd45fd179c2169d54392a9c7075a7f69fbedb70bf399931fff6cf06a18cfc9e9e'),
    'location_panic_helper_a': (0x1681e60, 25,
                                '8a90c5d6381cb31e7c35b642e9e12852181f751e0fd95c46b000930b27619260'),
    'location_panic_helper_b': (0x1681e80, 25,
                                'd3e235b445fb7b5451049676754231f05ace1fdf255e55a113b4c4405e556a39'),
    'panic_formatter': (0x1680e80, 44,
                        '28fc3434a04bb9e49d5a0164306a5c31abf6bce26425d99d27031ac1c9beb2e3'),
    'panic_location_helper': (0x1680bd0, 52,
                              '6dc901ad3d8318c0ad4ea63c6cbcfbc96ed76f5d1a86ff705ecf54d6cf04c7b2'),
    'alloc': (0x6355830, 194,
              '72c29274a75359df7c598d254d102cbab84f51d359256facb415bb90bffec5af'),
    'alloc_error': (0x141e264, 21,
                    '0ebfd9ba496f95eb3b50668da6bdfb6f60cdfea033bc8736545f457d87a46af0'),
    'value_drop': (0x635de30, 165,
                   '714fc5cdd28a2587427c9dac8a25685ec09695a3a21bc9af0eb09b29ae503f61'),
    'alloc_stub': (0x1680cab, 20,
                   '7604c0d4f26a7d70e59c5dcb8a39928bfd7207a5d4439d91d8fb1e50be9846e7'),
    'lu_panic_fde_a': (0x2accee0, 16080,
                       '73de7d70235eee244bbfc1b605d48e680c3753eda7399dbe284ae2a2420a8847'),
    'lu_panic_fde_b': (0x2ad0db0, 16391,
                       'efa7a22d973e50959dd1c0eb347fb907e9e488aa73801c5b6ec965504c5bb45f'),
}

SLOTS = {0x64df508: ('memcpy', 'memcpy'),
         0x64df9f8: ('bcmp', 'bcmp'),
         0x64e1290: (0x5c9a530, 'container_init'),
         0x64df4a0: (0x635de30, 'value_drop'),
         0x64df4c0: (0x1680cab, 'alloc_stub'),
         0x64df480: (0x6355830, 'alloc'),
         0x64df498: (0x141e264, 'alloc_error'),
         0x64e1b98: (0x166abb0, 'predicate_bit_test'),
         0x64e1cd0: (0x1635410, 'record_fixup_a'),
         0x64e1ce0: (0x1635ac0, 'record_fixup_b'),
         0x64e1ce8: (0x1635e30, 'record_fixup_c'),
         0x64e1c98: (0x5c9fd80, 'tls_cell_init'),
         0x64e0938: (0x5cab560, 'file_reader'),
         0x64dfca8: (0x16815e0, 'value_converter'),
         0x64e09a8: (0x5c9d1c0, 'registry_panic_helper'),
         0x64df770: (0x1680bd0, 'panic_location_helper'),
         0x64df6b8: (0x1680e80, 'panic_formatter'),
         0x64e1da8: (0x165de90, 'value_producer'),
         0x64e73c0: (0x564d700, 'spec_builder'),
         0x64e73c8: (0x564cce0, 'chain_class_writer'),
         0x64e1d08: (0x163a4b0, 'record_constructor'),
         0x64e1360: (0x1681e80, 'location_panic_helper_b'),
         0x64e1368: (0x1681e60, 'location_panic_helper_a')}
TEMPLATE_WORDS = {0x6407558: (0x450150, 'producer_ctx_template_fn'),
                  0x6406be8: (0x450150, 'merge_temp_template_fn'),
                  0x64074a8: (0x438966, 'registry_panic_static')}

WRAPPER_PINS = [
    (0x165dea4, '488d7c2428', 'frame spec copy at rsp+0x28'),
    (0x165dea9, 'ba50020000', 'spec copy length = 0x250'),
    (0x165deae, 'ff155416e804', 'memcpy through the bound memcpy slot (dest = frame copy, src = caller spec in rsi)'),
    (0x165deb4, '488d7c2408', 'container at rsp+0x8'),
    (0x165deb9, 'ff15d133e804', 'container init through slot 0x64e1290'),
    (0x165debf, '488d742428', 'core arg2 = frame spec copy'),
    (0x165dec4, '488d542408', 'core arg3 = container'),
    (0x165dec9, '4889df', 'core arg1 = out'),
    (0x165decc, 'e8df000000', 'call the producer core'),
    (0x165ded6, 'e895060000', 'spec copy destructor after the core returns'),
    (0x165df08, '4c8b259115e804', 'element drop fn ptr loaded from slot 0x64df4a0'),
    (0x165df37, '41ffd4', 'drop one container element (0x18-byte stride)'),
    (0x165df55, 'ff154515e804', 'free the container buffer through slot 0x64df4a0'),
]
CORE_PINS = [
    (0x165dfca, '4c8da6e8010000', 'r12 = &spec_copy +0x1e8 (predicate subject)'),
    (0x165dfd4, 'be27000000', 'predicate bit index 0x27'),
    (0x165dfd9, 'ff15b93be804', 'predicate call through slot 0x64e1b98'),
    (0x165dfe6, 'ff15e43ce804', 'fixup A through slot 0x64e1cd0 (arg = whole copy)'),
    (0x165dfef, 'ff15eb3ce804', 'fixup B through slot 0x64e1ce0'),
    (0x165dff8, 'ff15ea3ce804', 'fixup C through slot 0x64e1ce8'),
    (0x165dffe, '41808eec01000010', 'or byte [spec_copy +0x1ec], 0x10 — direct write into the copy'),
    (0x165e006, '49c7c5b0fbffff', 'r13 = -0x450 (TLS cell offset)'),
    (0x165e00d, '6441807d1001', 'TLS init flag test at fs:[r13 +0x10]'),
    (0x165e019, '64498b4500', 'load the TLS counter'),
    (0x165e01e, '64498b5508', 'load the TLS pointer'),
    (0x165e023, '48bd0000000000000080', 'rbp = sentinel 0x8000000000000000'),
    (0x165e031, '6449894d00', 'store the incremented TLS counter'),
    (0x165e036, '0f10051b95da04', 'ctx template block 1 from 0x6407558'),
    (0x165e045, '0f10051c95da04', 'ctx template block 2 from 0x6407568'),
    (0x165e054, '48898424e0000000', 'ctx +0x38 = TLS counter'),
    (0x165e05c, '48899424e8000000', 'ctx +0x40 = TLS pointer'),
    (0x165e064, '48c78424f000000000000000', 'ctx +0x48 = 0'),
    (0x165e070, '4889ac24a8000000', 'ctx +0x0 = sentinel'),
    (0x165e07b, 'be16000000', 'predicate bit index 0x16'),
    (0x165e080, 'ff15123be804', 'predicate call 2 through slot 0x64e1b98'),
    (0x165e08e, '498b4708', 'container cursor load'),
    (0x165e092, '493b4718', 'container end compare'),
    (0x165e0a0, '49894f08', 'container cursor advance (0x18-byte elements)'),
    (0x165e0a4, '4c8b20', 'element key load'),
    (0x165e0a7, '4939ec', 'element key vs sentinel compare'),
    (0x165e0b0, '488b5008', 'element string pointer'),
    (0x165e0b4, '488b4010', 'element string length'),
    (0x165e0bd, '803a2f', "first-byte '/' test on the element string"),
    (0x165e0d6, 'c644243006', 'file-reader input discriminant byte 6'),
    (0x165e0df, '66c74424580102', 'file-reader input flag word 0x201'),
    (0x165e0f0, 'ff154228e804', 'file read through slot 0x64e0938'),
    (0x165e0f6, '807c247009', 'file-read result tag must be 9'),
    (0x165e173, 'ff152f1be804', 'loaded string converted through slot 0x64dfca8'),
    (0x165e179, '837c242001', 'converter output tag compare with 1'),
    (0x165e189, '49396e38', 'spec_copy +0x38 length word vs sentinel'),
    (0x165e212, '4d896e38', 'spec_copy +0x38 = loaded string length'),
    (0x165e216, '49894640', 'spec_copy +0x40 = loaded string pointer'),
    (0x165e21a, '4d896e48', 'spec_copy +0x48 = loaded string capacity'),
    (0x165e251, '4c897c2470', 'worker arg4 cell = sentinel + 1'),
    (0x165e256, '488d7c2420', 'worker arg1 = result at rsp+0x20'),
    (0x165e25b, '488d9424a8000000', 'worker arg3 = ctx at rsp+0xa8'),
    (0x165e263, '488d4c2470', 'worker arg4 = sentinel+1 cell at rsp+0x70'),
    (0x165e268, '4c89f6', 'worker arg2 = spec copy'),
    (0x165e26b, 'e8202afdff', 'call the registry worker (path A boundary)'),
    (0x165e270, '48396c2420', 'worker result head vs sentinel selects path A'),
    (0x165e2cf, '48894338', 'path A: out +0x38 from the worker result'),
    (0x165e2d3, '0f10442420', 'path A: out body copied from the worker result'),
    (0x165e2ee, '4c893b', 'path A: out head = sentinel + 1'),
    (0x165e28e, '4d8ba698010000', 'path B: entry count from spec_copy +0x198'),
    (0x165e2a1, '4d8bae90010000', 'path B: entry array from spec_copy +0x190'),
    (0x165e374, '410f10840d80010000', 'path B: pair load from entry +0x180'),
    (0x165e381, '410f110406', 'path B: pair store into the fresh allocation'),
    (0x165e388, 'e853a90000', 'call the TLS registry accessor'),
    (0x165e399, '48ff00', 'increment the registry counter'),
    (0x165e39c, '0f100d5588da04', 'temp template block from 0x6406bf8'),
    (0x165e3a8, '0f100d3988da04', 'temp template block from 0x6406be8'),
    (0x165e3c6, '4c89f6', 'builder arg2 = extracted pairs (r14 reassigned at 0x165e2ba)'),
    (0x165e3c9, '4c89e2', 'builder arg3 = entry count'),
    (0x165e3cc, 'e8af930000', 'call the merge builder (path B boundary), out = ctx'),
    (0x165e3d6, 'e8757e0000', 'temp destructor after the builder'),
    (0x165e3db, '0f108424e8000000', 'path B: out copied from the ctx header'),
]
GETTER_PINS = [
    (0x4e4ca3e, '48837f3000', 'empty-map test at [map +0x30]'),
    (0x4e4ca4f, '488d4738', 'hasher state at map +0x38'),
    (0x4e4ca59, 'e8e25b0000', 'call the key hash'),
    (0x4e4ca65, '4d8b7c2418', 'entries base from [map +0x18]'),
    (0x4e4ca6a, '498b742420', 'bucket mask from [map +0x20]'),
    (0x4e4ca87, '4c8b256a2f6901', 'bcmp fn ptr loaded from slot 0x64df9f8'),
    (0x4e4cadb, '493b5cc7c0', 'key length compare against the entry'),
    (0x4e4cae6, '488b75b8', 'entry key pointer load'),
    (0x4e4caf0, '41ffd4', 'bcmp call through r12'),
    (0x4e4cb4c, '48837df000', 'matched entry value presence test'),
    (0x4e4cb53, '488b45e8', 'value object pointer from the entry'),
    (0x4e4cb57, '488b7008', 'value string pointer at [value +0x8]'),
    (0x4e4cb5b, '488b5010', 'value string length at [value +0x10]'),
    (0x4e4cb64, 'ff153e316901', 'value converter through slot 0x64dfca8'),
    (0x4e4cb6a, '837c241801', 'converter tag compare with 1'),
    (0x4e4cb8e, '488d3d7cbcacfb', 'panic string at 0x918811'),
    (0x4e4cb9c, 'be23000000', 'panic string length 0x23'),
    (0x4e4cba1, 'ff15c92b6901', 'panic through slot 0x64df770'),
]
TLS_PINS = [
    (0x1668ce0, '48c7c1b0fbffff', 'rcx = -0x450'),
    (0x1668ce7, '64488b042500000000', 'load the TLS base'),
    (0x1668cf3, '6480791000', 'init flag test at fs:[rcx +0x10]'),
    (0x1668cfc, '4889fe', 'lazy init arg2 = accessor arg'),
    (0x1668cff, '64488b3c2500000000', 'reload the TLS base for the init call'),
    (0x1668d08, '488dbfb0fbffff', 'lazy init arg1 = cell pointer'),
    (0x1668d12, 'e859910000', 'call the lazy init (boundary)'),
]
B2_PINS = [
    (0x2ae42ac, '48c784248003000007000000', 'key length word = 7 on the frame'),
    (0x2ae42cc, '488dbc24d0000000', 'ctor arg1 = record at rsp+0xd0'),
    (0x2ae42d4, '488db42480030000', 'ctor arg2 = key at rsp+0x380'),
    (0x2ae42dc, 'ff1526da9f03', 'record constructor through slot 0x64e1d08'),
    (0x2ae42e2, '488dbc2480030000', 'spec arg1 (out) = rsp+0x380'),
    (0x2ae42ea, '4c8da424d0000000', 'r12 = record at rsp+0xd0'),
    (0x2ae42f2, '4c89e6', 'spec arg2 = record'),
    (0x2ae42f5, 'ff15c530a003', 'spec builder through slot 0x64e73c0'),
    (0x2ae42fb, '488d7c2450', 'producer arg1 (out) = rsp+0x50'),
    (0x2ae4300, '4c8dbc2480030000', 'r15 = spec at rsp+0x380'),
    (0x2ae4308, '4c89fe', 'producer arg2 = spec'),
    (0x2ae430b, 'ff1597da9f03', 'value producer through slot 0x64e1da8'),
    (0x2ae4330, '0f10442450', 'value copy: first block from rsp+0x50'),
    (0x2ae435f, '0f29842480030000', 'value copy: last block to rsp+0x380'),
    (0x2ae4367, '488dbc24d0000000', 'apply arg1 = record'),
    (0x2ae436f, '4c8dac2480030000', 'r13 = value copy at rsp+0x380'),
    (0x2ae4377, '4c89ee', 'apply arg2 = value copy'),
    (0x2ae437a, 'ff154830a003', 'apply through slot 0x64e73c8'),
]
APPLY_PINS = [
    (0x564ccf7, '488d35c0da2dfb', 'lea rsi = "chain" field name'),
    (0x564ccfe, 'ba05000000', 'key length 5'),
    (0x564cd03, '4c89f7', 'getter arg1 = the value (r14)'),
    (0x564cd06, 'e825fd7fff', 'call the field getter for "chain"'),
]
SPEC_PINS = [
    (0x564de53, 'ba90000000', 'first block length 0x90'),
    (0x564de58, '4889df', 'first block dest = out'),
    (0x564de5b, '4c89fe', 'first block src = frame +0x808'),
    (0x564de5e, '41ffd4', 'memcpy through r12: out +0x0..+0x90'),
    (0x564de61, '488db424a8080000', 'second block src = frame +0x8a8'),
    (0x564de69, '488dbba0000000', 'second block dest = out +0xa0'),
    (0x564de70, 'bab0010000', 'second block length 0x1b0 (covers +0x190/+0x198)'),
    (0x564de75, '41ffd4', 'memcpy through r12: out +0xa0..+0x250'),
    (0x564de78, '488d055aca2dfb', 'lea rax = build-stamp string at 0x92a8d9'),
    (0x564de7f, '48898390000000', 'out +0x90 = build-stamp string pointer'),
    (0x564de86, '48c7839800000054000000', 'out +0x98 = 0x54'),
]
Z_PINS = [
    (0x2af7839, '4c8dbfa00c0000', 'r15 = obj +0xca0 (the staged copy base)'),
    (0x2af7840, 'bad80b0000', 'staging memcpy length = 0xbd8 (covers +0xbd5)'),
    (0x2af784b, 'ff15b77c9e03', 'staging memcpy call through slot 0x64df508 (obj -> obj +0xca0)'),
]
OWNER_PINS = {'value_producer': WRAPPER_PINS, 'value_producer_core': CORE_PINS,
              'field_getter': GETTER_PINS, 'tls_registry': TLS_PINS}
REF_PINS = {'gb_b2': B2_PINS, 'chain_class_writer': APPLY_PINS,
            'spec_builder': SPEC_PINS, 'b4_caller_stager': Z_PINS}

LU_RS_RECORDS = [(0x64012f8, 0x15d5b00, 159, 64),
                 (0x6401400, 0x15d8530, 247, 13),
                 (0x6401438, 0x15c0bc0, 242, 12),
                 (0x64014b8, 0x15d6e00, 220, 26),
                 (0x64471b0, 0x2a92960, 75, 5),
                 (0x6447260, 0x2af77f0, 24, 16)]
REGISTRATION_COUNT = 447


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
        require(sec['size'] % 24 == 0, f'truncated{name} section')
        for i, (off, info, add) in enumerate(
                struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']])):
            out.append({'slot': off, 'type': info & 0xffffffff, 'sym': info >> 32,
                        'addend': add, 'addend_file_offset': sec['offset'] + 24 * i + 16,
                        'offset_file_offset': sec['offset'] + 24 * i})
    return out


def dynsym_name(data, index):
    sym = next((s for s in sections(data) if s['name'] == '.dynsym'), None)
    strs = next((s for s in sections(data) if s['name'] == '.dynstr'), None)
    require(sym is not None, 'missing.dynsym section')
    require(strs is not None, 'missing.dynstr section')
    st_name = struct.unpack_from('<I', data, sym['offset'] + 24 * index)[0]
    start = strs['offset'] + st_name
    try:
        return data[start:data.index(b'\0', start)].decode()
    except UnicodeDecodeError:
        require(False, 'dynamic symbol name is not valid UTF-8')


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


def _lea_target(body, base, va, insn_len=7):
    disp = struct.unpack_from('<i', body, va - base + 3)[0]
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
    for table in (OWNERS, REF_BODIES, CENSUS_OWNERS):
        for role, rng in table.items():
            if rng[0] == fde_start:
                return role
    return None


def call_census(data, targets):
    """Every direct call/jump site in .text for each target VA, with the
    containing FDE for each site. Raw byte-pattern hits; sites inside
    packet owners are additionally validated as instruction starts by
    generate()."""
    text = next((s for s in sections(data) if s['name'] == '.text'), None)
    require(text is not None, 'missing.text section')
    blob = data[text['offset']:text['offset'] + text['size']]
    base = text['address']
    owner = _fde_owner(data)
    by_va = {va: role for role, va in targets.items()}
    found = {role: [] for role in targets}
    for opcode in (b'\xe8', b'\xe9'):
        idx = blob.find(opcode)
        while idx != -1:
            site = base + idx
            tgt = site + 5 + struct.unpack_from('<i', blob, idx + 1)[0]
            if tgt in by_va:
                own = owner(site)
                found[by_va[tgt]].append({'site': hex(site),
                                          'kind': 'call' if opcode == b'\xe8' else 'jump',
                                          'owner': _role_of(own),
                                          'owner_start': hex(own) if own else None})
            idx = blob.find(opcode, idx + 1)
    return found


def slot_census(data, slot):
    """Every ff 15 / ff 25 RIP-relative reference to a slot in .text,
    with the containing FDE for each site."""
    text = next((s for s in sections(data) if s['name'] == '.text'), None)
    require(text is not None, 'missing.text section')
    blob = data[text['offset']:text['offset'] + text['size']]
    base = text['address']
    owner = _fde_owner(data)
    found = []
    for opcode, kind in ((b'\xff\x15', 'call'), (b'\xff\x25', 'jump')):
        idx = blob.find(opcode)
        while idx != -1:
            site = base + idx
            if site + 6 + struct.unpack_from('<i', blob, idx + 2)[0] == slot:
                own = owner(site)
                found.append({'site': hex(site), 'kind': kind,
                              'owner': _role_of(own),
                              'owner_start': hex(own) if own else None})
            idx = blob.find(opcode, idx + 1)
    return sorted(found, key=lambda r: int(r['site'], 16))


RIP_OPS = {0x8d, 0x8b, 0x89, 0x88, 0x8a, 0x39, 0x3b, 0x38, 0x3a, 0x85, 0x84,
           0x01, 0x03, 0x29, 0x2b, 0x21, 0x23, 0x31, 0x33, 0x63, 0xc7,
           0x80, 0x81, 0x83}


def rip_relative_census(data, target):
    """Candidate RIP-relative instruction sites in .text whose computed
    target equals the given VA. Candidate generation covers the REX and
    non-REX ModRM disp32 forms and the ff 15/25 forms; every candidate
    for a non-empty result is additionally validated as an instruction
    start (see generate()/the packet tests)."""
    text = next((s for s in sections(data) if s['name'] == '.text'), None)
    require(text is not None, 'missing.text section')
    blob = data[text['offset']:text['offset'] + text['size']]
    base = text['address']
    owner = _fde_owner(data)
    hits = []
    for i in range(len(blob) - 7):
        b0 = blob[i]
        site = None
        if 0x40 <= b0 <= 0x4f and blob[i + 1] in RIP_OPS and (blob[i + 2] & 0xc7) == 0x05:
            if base + i + 7 + struct.unpack_from('<i', blob, i + 3)[0] == target:
                site = base + i
        elif b0 in RIP_OPS and (blob[i + 1] & 0xc7) == 0x05:
            if base + i + 6 + struct.unpack_from('<i', blob, i + 2)[0] == target:
                site = base + i
        elif b0 == 0xff and blob[i + 1] in (0x15, 0x25):
            if base + i + 6 + struct.unpack_from('<i', blob, i + 2)[0] == target:
                site = base + i
        if site is not None:
            own = owner(site)
            hits.append({'site': hex(site), 'owner': _role_of(own),
                         'owner_start': hex(own) if own else None})
    return hits


def core_spec_copy_store_census(body, base):
    """Mov-form stores through r14 in the core body, scoped to the
    address range where r14 still holds the spec copy (before its
    reassignment to the path-B pairs allocation at 0x165e2ba). Covers
    the REX.B mov-store forms (88/89/c7) and SSE stores (0f 11) with
    disp8/disp32. Returns [(site, disp)]."""
    limit = 0x165e2ba
    hits = []
    i = 0
    while i < len(body) - 4:
        va = base + i
        if va >= limit:
            break
        rex = body[i]
        if rex in (0x49, 0x4d):
            op = body[i + 1]
            if op in (0x88, 0x89, 0xc7) and (body[i + 2] & 0xc7) in (0x46, 0x86):
                modrm = body[i + 2]
                if op == 0xc7 and (modrm >> 3) & 7 != 0:
                    i += 1
                    continue
                disp = body[i + 3] if (modrm & 0xc0) == 0x40 else \
                    struct.unpack_from('<i', body, i + 3)[0]
                hits.append((va, disp))
            elif op == 0x0f and body[i + 2] == 0x11 and (body[i + 3] & 0xc7) in (0x46, 0x86):
                modrm = body[i + 3]
                disp = body[i + 4] if (modrm & 0xc0) == 0x40 else \
                    struct.unpack_from('<i', body, i + 4)[0]
                hits.append((va, disp))
        i += 1
    return hits


def getter_store_census(body, base):
    """Store-form instructions in the getter body whose destination
    base is r15 (entries, REX.B rm=111), rbp (entry pointer, rm=101
    with disp), or rax (value object, rm=000 with disp). Any hit would
    be a write to the map's entries or a value object. Frame stores
    (rsp SIB / rbp before its reassignment) are excluded by
    construction of the pattern set: rbp is reassigned to the entry
    pointer at 0x4e4cae2, and the only earlier rbp-relative accesses
    are the prologue pushes, which are not 88/89/c7 forms."""
    hits = []
    for i in range(len(body) - 4):
        rex = body[i]
        op_idx = i + 1 if 0x40 <= rex <= 0x4f else i
        op = body[op_idx]
        if op not in (0x88, 0x89, 0xc7):
            continue
        modrm = body[op_idx + 1]
        mod = modrm & 0xc0
        rm = modrm & 0x07
        if mod == 0xc0:
            continue
        rex_b = (rex & 0x01) if 0x40 <= rex <= 0x4f else 0
        if op == 0xc7 and (modrm >> 3) & 7 != 0:
            continue
        if rex_b and rm == 0x07:
            hits.append((base + i, 'r15'))
        elif not rex_b and rm == 0x05 and mod in (0x40, 0x80):
            hits.append((base + i, 'rbp'))
        elif not rex_b and rm == 0x00 and mod in (0x40, 0x80):
            hits.append((base + i, 'rax'))
    return hits


def registration_census(data, rels):
    """Scan .data.rel.ro for the 0x28-byte registration records
    {8, fn ptr in .text, .rs file ptr, file len, packed line/col}
    with relocation-applied words."""
    secs = sections(data)
    dr = next((s for s in secs if s['name'] == '.data.rel.ro'), None)
    require(dr is not None, 'missing.data.rel.ro section')
    text = next((s for s in secs if s['name'] == '.text'), None)
    require(text is not None, 'missing.text section')
    rel = {r['slot']: r for r in rels if r['type'] == 8}

    def eff(va):
        raw = read(data, va, 8)
        value = struct.unpack('<Q', raw)[0]
        entry = rel.get(va)
        return entry['addend'] if entry is not None else value

    hits = []
    va = dr['address']
    end = dr['address'] + dr['size']
    while va < end - 0x28:
        w = [eff(va + 8 * k) for k in range(5)]
        if (w[0] == 8 and text['address'] <= w[1] < text['address'] + text['size']
                and 0 < w[3] < 300 and (w[4] >> 32) < 10000
                and 0 < (w[4] & 0xffffffff) < 100000):
            fname = read(data, w[2], w[3])
            if fname.endswith(b'.rs') and all(32 <= c < 127 for c in fname):
                hits.append({'record': va, 'fn': w[1], 'file': fname.decode(),
                             'file_va': w[2], 'file_len': w[3],
                             'line': w[4] & 0xffffffff, 'col': w[4] >> 32})
        va += 8
    return hits


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
    for slot, (target, name) in TEMPLATE_WORDS.items():
        entries = rel_by_slot.get(slot, [])
        require(len(entries) == 1 and entries[0]['type'] == 8
                and entries[0]['addend'] == target,
                f'{name} template word binding changed')
        bindings[hex(slot)] = {'target': hex(target), 'name': name,
                               'rela_type': entries[0]['type']}

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

    wbody, wbase = bodies['value_producer']
    require(_call_target(wbody, wbase, 0x165decc) == CORE[0],
            'wrapper core call target changed')
    require(_slot_target(wbody, wbase, 0x165deae) == 0x64df508,
            'wrapper memcpy slot changed')
    require(_slot_target(wbody, wbase, 0x165deb9) == 0x64e1290,
            'wrapper container init slot changed')
    require(_slot_target(wbody, wbase, 0x165df55) == 0x64df4a0,
            'wrapper container free slot changed')
    require(_call_target(wbody, wbase, 0x165ded6) == 0x165e570,
            'wrapper spec copy dtor call changed')

    cbody, cbase = bodies['value_producer_core']
    require(_slot_target(cbody, cbase, 0x165dfd9) == 0x64e1b98,
            'core predicate slot changed')
    require(_slot_target(cbody, cbase, 0x165dfe6) == 0x64e1cd0,
            'core fixup A slot changed')
    require(_slot_target(cbody, cbase, 0x165dfef) == 0x64e1ce0,
            'core fixup B slot changed')
    require(_slot_target(cbody, cbase, 0x165dff8) == 0x64e1ce8,
            'core fixup C slot changed')
    require(_lea_target(cbody, cbase, 0x165e036) == 0x6407558,
            'core ctx template block 1 target changed')
    require(_lea_target(cbody, cbase, 0x165e045) == 0x6407568,
            'core ctx template block 2 target changed')
    require(_slot_target(cbody, cbase, 0x165e0f0) == 0x64e0938,
            'core file reader slot changed')
    require(_slot_target(cbody, cbase, 0x165e173) == 0x64dfca8,
            'core converter slot changed')
    require(_call_target(cbody, cbase, 0x165e26b) == WORKER,
            'registry worker call target changed')
    require(_call_target(cbody, cbase, 0x165e388) == TLS_REGISTRY[0],
            'core registry accessor call target changed')
    require(_lea_target(cbody, cbase, 0x165e39c) == 0x6406bf8,
            'core temp template block 1 target changed')
    require(_lea_target(cbody, cbase, 0x165e3a8) == 0x6406be8,
            'core temp template block 2 target changed')
    require(_call_target(cbody, cbase, 0x165e3cc) == BUILDER,
            'value merge builder call target changed')
    require(_slot_target(cbody, cbase, 0x165e43b) == 0x64e1c98,
            'core TLS init slot changed')
    require(_slot_target(cbody, cbase, 0x165e458) == 0x64e09a8,
            'core registry panic slot changed')

    gbody, gbase = bodies['field_getter']
    require(_call_target(gbody, gbase, 0x4e4ca59) == 0x4e52640,
            'getter key hash call target changed')
    require(_lea_target(gbody, gbase, 0x4e4ca87) == 0x64df9f8,
            'getter bcmp slot load changed')
    require(_slot_target(gbody, gbase, 0x4e4cb64) == 0x64dfca8,
            'getter converter slot changed')
    require(_slot_target(gbody, gbase, 0x4e4cba1) == 0x64df770,
            'getter panic slot changed')
    require(_lea_target(gbody, gbase, 0x4e4cb8e) == 0x918811,
            'getter panic string target changed')
    require(read(data, 0x918811, 0x23) ==
            b'unexpected invalid UTF-8 code point',
            'getter panic string bytes changed')

    tbody, tbase = bodies['tls_registry']
    require(_call_target(tbody, tbase, 0x1668d12) == 0x1671e70,
            'registry lazy init call target changed')

    abody, abase = bodies['chain_class_writer']
    require(_lea_target(abody, abase, 0x564ccf7) == CHAIN_NAME_VA,
            'chain lea target changed')
    require(read(data, CHAIN_NAME_VA, 5) == b'chain', 'chain name bytes changed')
    require(_call_target(abody, abase, 0x564cd06) == GETTER[0],
            'getter call target changed')

    sbody, sbase = bodies['spec_builder']
    require(_lea_target(sbody, sbase, 0x564de78) == 0x92a8d9,
            'spec build-stamp lea target changed')

    b2body, b2base = bodies['gb_b2']
    for site, slot in ((0x2ae42dc, 0x64e1d08), (0x2ae42f5, 0x64e73c0),
                       (0x2ae430b, 0x64e1da8), (0x2ae437a, 0x64e73c8)):
        require(_slot_target(b2body, b2base, site) == slot,
                f'B2 helper slot changed at {site:#x}')

    zbody, zbase = bodies['b4_caller_stager']
    require(_slot_target(zbody, zbase, 0x2af784b) == 0x64df508,
            'Z staging memcpy slot changed')
    require(zbody.count(b'\xd5\x0b\x00\x00') == 0,
            'Z body +0xbd5 displacement census changed')

    # The ctx and temp templates: only the first word of each copied
    # 0x20-byte span is non-zero (the bound function pointer).
    for span in (0x6407558, 0x6406be8):
        words = [struct.unpack('<Q', read(data, span + 8 * k, 8))[0]
                 for k in range(4)]
        eff = []
        for k, word in enumerate(words):
            entry = next((r for r in rel_by_slot.get(span + 8 * k, [])
                          if r['type'] == 8), None)
            eff.append(entry['addend'] if entry is not None else word)
        require(eff == [0x450150, 0, 0, 0],
                f'template span at {span:#x} changed')

    store_hits = core_spec_copy_store_census(cbody, cbase)
    require(store_hits == [(0x165e212, 0x38), (0x165e216, 0x40), (0x165e21a, 0x48)],
            'core spec-copy store census changed')
    getter_hits = getter_store_census(gbody, gbase)
    require(getter_hits == [], 'getter store census changed')

    direct = call_census(data, {'value_producer': PRODUCER[0],
                                'value_producer_core': CORE[0],
                                'field_getter': GETTER[0],
                                'tls_registry': TLS_REGISTRY[0],
                                'b4_caller_stager': Z[0],
                                'registry_worker': WORKER,
                                'value_merge_builder': BUILDER})
    require(direct['value_producer'] == [],
            'value producer direct call census changed')
    require([s['site'] for s in direct['value_producer_core']] == ['0x165decc'],
            'core direct call census changed')
    require([s['site'] for s in direct['tls_registry']] == ['0x165e388'],
            'registry accessor direct call census changed')
    require(direct['b4_caller_stager'] == [],
            'Z direct call census changed')

    slot_calls = {'value_producer': slot_census(data, 0x64e1da8),
                  'spec_builder': slot_census(data, 0x64e73c0),
                  'chain_class_writer': slot_census(data, 0x64e73c8)}
    for role, want in (('value_producer', ['0x2ae430b', '0x2b7b6b8']),
                       ('spec_builder', ['0x2ae42f5', '0x2b7b6ac']),
                       ('chain_class_writer', ['0x2ae437a', '0x2b7b73f'])):
        require([s['site'] for s in slot_calls[role]] == want,
                f'{role} slot call census changed')

    # Trail 2: Z's reference census.
    z_rela = [r for r in rels if r['type'] == 8 and r['addend'] == Z[0]]
    require(len(z_rela) == 1 and z_rela[0]['slot'] == Z_SLOT,
            'Z relocation census changed')
    z_entry = z_rela[0]
    pat = struct.pack('<Q', Z[0])
    raw_hits = []
    idx = data.find(pat)
    while idx != -1:
        raw_hits.append(idx)
        idx = data.find(pat, idx + 1)
    require(raw_hits == [z_entry['addend_file_offset']],
            'Z raw qword census changed')
    for value, want, label in (
            (Z_RECORD, [], 'registration record base'),
            (Z_SLOT, [z_entry['offset_file_offset']], 'registration fn slot')):
        pat = struct.pack('<Q', value)
        hits = []
        idx = data.find(pat)
        while idx != -1:
            hits.append(idx)
            idx = data.find(pat, idx + 1)
        require(hits == want, f'{label} raw qword census changed')
    rip = {hex(t): rip_relative_census(data, t)
           for t in (Z[0], Z_RECORD, Z_SLOT, Z_LOCATION)}
    require(rip[hex(Z[0])] == [], 'Z RIP-relative census changed')
    require(rip[hex(Z_RECORD)] == [], 'registration record RIP-relative census changed')
    require(rip[hex(Z_SLOT)] == [], 'registration slot RIP-relative census changed')
    loc_sites = rip[hex(Z_LOCATION)]
    lea_sites = [s for s in loc_sites
                 if read(data, int(s['site'], 16), 3) == b'\x48\x8d\x3d']
    require([s['site'] for s in lea_sites] ==
            ['0x2acf71a', '0x2acf743', '0x2acf755', '0x2acf767',
             '0x2ad370a', '0x2ad3733', '0x2ad3745', '0x2ad3769'],
            'Z location lea census changed')
    require(sorted(int(s['site'], 16) for s in loc_sites) ==
            sorted([int(s['site'], 16) for s in lea_sites]
                   + [int(s['site'], 16) + 1 for s in lea_sites]),
            'Z location candidate shadow set changed')

    require(not [r for r in rels if r['slot'] == Z_RECORD],
            'registration record head gained a relocation')
    require(not [r for r in rels if r['slot'] in (Z_RECORD + 0x18, Z_RECORD + 0x20)],
            'registration record tail gained a relocation')
    rec_words = [struct.unpack('<Q', read(data, Z_RECORD + 8 * k, 8))[0]
                 for k in range(5)]
    fn_entry = next(r for r in rels if r['slot'] == Z_SLOT)
    file_entry = next(r for r in rels if r['slot'] == Z_LOCATION)
    require(rec_words[0] == 8 and fn_entry['addend'] == Z[0]
            and file_entry['addend'] == Z_FILE_VA
            and rec_words[3] == 0xe and rec_words[4] == 0x1000000018,
            'registration record words changed')
    require(read(data, Z_FILE_VA, 0xe) == b'base/src/lu.rs',
            'registration record file bytes changed')

    reg = registration_census(data, rels)
    require(len(reg) == REGISTRATION_COUNT,
            'registration pattern census changed')
    lu = [(r['record'], r['fn'], r['line'], r['col']) for r in reg
          if r['file'] == 'base/src/lu.rs']
    require(lu == LU_RS_RECORDS, 'lu.rs registration family changed')
    z_rec = next(r for r in reg if r['record'] == Z_RECORD)
    require(z_rec['fn'] == Z[0] and z_rec['line'] == 24 and z_rec['col'] == 16,
            'Z registration record changed')

    records = {
        'target_sha256': TARGET_SHA256,
        'target_size': TARGET_SIZE,
        'captured_code_executed': False,
        'owners': [owners[r] for r in
                   ('value_producer', 'value_producer_core', 'field_getter',
                    'tls_registry')],
        'reference_bodies': [owners[r] for r in
                             ('gb_b2', 'chain_class_writer', 'spec_builder',
                              'b4_caller_stager')],
        'boundaries': {name: {'start': hex(start), 'bytes': size, 'sha256': sha}
                       for name, (start, size, sha) in BOUNDARIES.items()},
        'slot_bindings': bindings,
        'direct_call_census': direct,
        'slot_call_census': slot_calls,
        'core_spec_copy_stores': [{'site': hex(s), 'disp': hex(d)}
                                  for s, d in store_hits],
        'getter_store_census': [],
        'z_reference_census': {
            'rela': [{'slot': hex(z_entry['slot']), 'rela_type': z_entry['type'],
                      'addend': hex(z_entry['addend'])}],
            'raw_qword_occurrences': {'z': 1, 'record_base': 0, 'fn_slot': 1},
            'rip_relative': {t: sites for t, sites in rip.items()},
            'location_lea_sites': [s['site'] for s in lea_sites],
        },
        'registration_record': {
            'record': hex(Z_RECORD), 'head_word': 8,
            'fn_word_slot': hex(Z_SLOT), 'fn': hex(Z[0]),
            'location': {'address': hex(Z_LOCATION), 'file': 'base/src/lu.rs',
                         'file_va': hex(Z_FILE_VA), 'file_len': 14,
                         'line': 24, 'col': 16},
        },
        'registration_census': {
            'count': len(reg),
            'lu_rs_records': [{'record': hex(r), 'fn': hex(f), 'line': ln, 'col': c}
                              for r, f, ln, c in lu],
        },
        'trail1_chain_origin': {
            'producer_inputs': 'the 0x250-byte spec (spec builder out) via B2 '
                               '(rsp+0x380) or the buffer converter; the wrapper '
                               'copies it to its frame and the core works on the copy',
            'core_direct_writes_to_copy': 'flag-byte or at +0x1ec (0x165dffe) and '
                                          'the file-loaded string move at '
                                          '+0x38/+0x40/+0x48 (0x165e212..0x165e21a) only',
            'path_a': 'registry worker 0x1630c90 result struct copied verbatim '
                      'into out (0x165e2ca..0x165e2ee); entries materialise '
                      'inside the worker',
            'path_b': 'pairs extracted from the spec copy +0x190/+0x198 entry '
                      'array (spec-builder-written) are merged by builder '
                      '0x1667780 into the ctx header, which becomes out',
            'getter': 'pure lookup: hash (0x4e52640) + bcmp via slot '
                      '0x64df9f8 + converter via slot 0x64dfca8; no store to '
                      'map, entry, or value object (store census empty)',
            'verdict': 'the "chain" string is input data at the registry '
                       'worker / merge builder boundary; no traced code in '
                       'the producer, the wrapper, or the getter computes it',
        },
        'trail2_bd5_writer': {
            'z_references': 'exactly one: the RELATIVE relocation at slot '
                            '0x6447268 inside the registration record at '
                            '0x6447260; no direct call site, no RIP-relative '
                            'reference, no other raw qword occurrence',
            'registration': 'one of 447 records of the shape {8, fn ptr, '
                            '.rs file, len, line/col} in .data.rel.ro; six '
                            'name base/src/lu.rs, Z at line 24 col 16',
            'location_use': 'the record location field (0x6447270) is '
                            'referenced as a &Location by panic sites in FDEs '
                            '0x2accee0 and 0x2ad0db0 through the bound '
                            'location panic helpers 0x1681e60 / 0x1681e80',
            'verdict': 'the first writer of the +0xbd5 field of Z\'s arg1 '
                       'object is above the registration dispatch, in the '
                       'consumer of the registration record; it is not '
                       'traced code in this binary',
        },
        'boundary': {
            'trail1': 'what the registry worker 0x1630c90 and the merge '
                      'builder 0x1667780 do inside their own bodies — in '
                      'particular where the "chain" entry is first inserted '
                      'into the value map — is inside those hash-pinned '
                      'boundaries; the three record fixups (0x1635410, '
                      '0x1635ac0, 0x1635e30) receive the spec copy on the '
                      'predicate-failure path and are likewise boundaries',
            'trail2': 'the consumer of the 447 registration records is not '
                      'statically reachable from .text in this binary; who '
                      'invokes Z, and what constructs its arg1 object, is '
                      'unresolved above the registration record',
        },
        'limits': 'Static evidence only: byte pins, relocation bindings, '
                  'and find-based censuses validated as instruction starts '
                  'for every site inside a packet owner or reference body. '
                  'No captured code was executed. Semantic names (spec, '
                  'value, registry) follow the earlier RE-005 packets and '
                  'the byte-level roles proven here; no type names are '
                  'claimed.',
        'validation': 'tools/chain_origin_writers_static.py regenerates '
                      'records.json and the disassembly exports from the '
                      'authenticated artifact and re-derives every pin, '
                      'binding, and census; tests/test_chain_origin_writers'
                      '_static.py asserts regeneration byte-identity and '
                      'counterfactual rejection.',
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
    export_roles = ('value_producer', 'value_producer_core', 'field_getter',
                    'tls_registry', 'chain_class_writer', 'spec_builder')
    for role in export_roles:
        body, start, end = bodies[role]
        text = executable('objdump',
                          ['-d', '-M', 'intel', '--insn-width=16',
                           f'--start-address={start:#x}',
                           f'--stop-address={end:#x}', str(binary)])
        decode_export(text, start, end, body)
        (output / f'{role}_disassembly.txt').write_text(text)
    # Instruction-start validation for pins in the two reference bodies
    # without committed exports (gb_b2, b4_caller_stager): decode fresh
    # exports here; earlier packets (#2444/#2466) commit full exports of
    # both bodies with the same pins validated there.
    for role in ('gb_b2', 'b4_caller_stager'):
        body, start, end = bodies[role]
        text = executable('objdump',
                          ['-d', '-M', 'intel', '--insn-width=16',
                           f'--start-address={start:#x}',
                           f'--stop-address={end:#x}', str(binary)])
        decode_export(text, start, end, body)
    readelf = executable('readelf',
                         ['--debug-dump=frames', str(binary)]).splitlines()
    cie_lines = {}
    for line in readelf:
        parts = line.split()
        if len(parts) >= 4 and parts[3] == 'CIE':
            cie_lines[parts[0]] = line

    def record(line):
        parts = line.split()
        payload = ''.join(parts[3:])
        off = payload.find('cie=')
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
                          'registration_count':
                          records['registration_census']['count'],
                          'getter_census_sites':
                          len(records['direct_call_census']['field_getter'])}))
    else:
        generate(args.binary, Path(args.output))
        print(f'wrote {args.output}')


if __name__ == '__main__':
    main()
