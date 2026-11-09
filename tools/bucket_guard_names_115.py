#!/usr/bin/env python3
"""Bind the node #115 bucket_guard observer names (RE-008, after the observer catalogue).

The observer catalogue found four functions that build an observer named
"bucket_guard/{}" (0x26d4660, 0x3704070, 0x4770930, 0x51eaff0) and 50 record
calls that use them, all with the Location base/src/bucket_guard.rs:118:21.
This tool binds:

1. the shape of the four getters: an occupied-entry fast path that returns
   entries + index * 0x260, a vacant path that reads three captures from the
   closure in rsi (the name &str pointer, then two f64 pointers), formats the
   name into "bucket_guard/{}" through one of four 4-instruction &str Display
   thunks, calls the observer constructor, and stores (1, f64) in the first
   16 bytes of the new value;
2. the direct-call census of the four getters (11, 8, 1, 30 = 50) and that a
   record call through slot 0x64e1010 follows each one;
3. for each of the 50 calls: the global loaded through slot 0x64e0168, the
   clock_gettime(CLOCK_MONOTONIC) calls in the same function, and the name:
   a static string at the site (36), or a string stored by the caller of the
   wrapper function that holds the site (14 sites, 24 callers, one more hop
   for median_risk_free_rate); plus the f64 pair stored after the name.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses; FDE ends are exclusive.
"""
import argparse
import collections
import json
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-bucket-guard-names-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

RECORD_SLOT = 0x64e1010
RECORD = 0x1547530
CTOR_SLOT = 0x64e1020
CTOR = 0x1548bb0
FORMAT_SLOT = 0x64df6e8
FORMAT = 0x141e3a0
PAD_SLOT = 0x64df720
PAD = 0x167fa70
GLOBAL_SLOT = 0x64e0168
GLOBAL = 0x64efc58
TEMPLATE = 0x43bb25
NOW = 0x5c842e0
CLOCK_GOT = 0x64e1248
HOP = 0x3673a10

# getter, FDE, display lea, display thunk, template lea, format call, constructor call,
# fixed pins (va, bytes): cmp rax,[rdi]; imul rax,[rdi|rbx+0x18],0x260; mov rax,[rdi|rbx+0x30];
# three closure loads from rsi; mov qword [rsp+N],1; mov edx,0x238
GETTERS = (
    (0x26d4660, (0x26d4660, 0x26d47fb), 0x26d46c4, 0x24a7c50, 0x26d46d0, 0x26d46e1, 0x26d4700,
     ((0x26d466c, '483b07'), (0x26d4671, '4869471860020000'), (0x26d4688, '488b4730'),
      (0x26d46ab, '488b06'), (0x26d46ae, '488b4e08'), (0x26d46b2, '4c8b7610'),
      (0x26d470b, '48c744245801000000'), (0x26d4727, 'ba38020000'))),
    (0x3704070, (0x3704070, 0x370420b), 0x37040d4, 0x46dd7f0, 0x37040e0, 0x37040f1, 0x3704110,
     ((0x370407c, '483b07'), (0x3704081, '4869471860020000'), (0x3704098, '488b4730'),
      (0x37040bb, '488b06'), (0x37040be, '488b4e08'), (0x37040c2, '4c8b7610'),
      (0x370411b, '48c744245801000000'), (0x3704137, 'ba38020000'))),
    (0x4770930, (0x4770930, 0x4770c21), 0x4770999, 0x47735c0, 0x47709a5, 0x47709b6, 0x47709d6,
     ((0x4770946, '483b07'), (0x477094b, '4869431860020000'), (0x477095c, '488b4330'),
      (0x477097f, '488b06'), (0x4770982, '488b4e08'), (0x4770986, '4c8b7e10'),
      (0x47709e1, '48c744246001000000'), (0x47709fd, 'ba38020000'))),
    (0x51eaff0, (0x51eaff0, 0x51eb18b), 0x51eb054, 0x5616320, 0x51eb060, 0x51eb071, 0x51eb090,
     ((0x51eaffc, '483b07'), (0x51eb001, '4869471860020000'), (0x51eb018, '488b4730'),
      (0x51eb03b, '488b06'), (0x51eb03e, '488b4e08'), (0x51eb042, '4c8b7610'),
      (0x51eb09b, '48c744245801000000'), (0x51eb0b7, 'ba38020000'))),
)
GETTER_CALLS = {0x26d4660: 11, 0x3704070: 8, 0x4770930: 1, 0x51eaff0: 30}
STATIC_SITES = (
    # getter call, getter, FDE, lock-slot load, closure pins (lea rsi / name capture / its lea),
    # name lea, length store, name, pair lea, pair store, ptr store
    (0x2bdf7e9, 0x26d4660, (0x2bdf270, 0x2bdf8ee), (0x2bdf746, '4c8b2d1b0a9003'), ((0x2bdf7e4, '488d742460'), (0x2bdf7d0, '4889442460'), (0x2bdf7cb, '488d442478')), (0x2bdf44b, '488d0541eda2fd'), (0x2bdf457, '48c78424800000000b000000'), 'begin_block', (0x2bdf46b, '660f2805ad4087fd'), (0x2bdf473, '660f11842488000000'), (0x2bdf452, '4889442478')),
    (0x2be05ed, 0x26d4660, (0x2bdf8f0, 0x2beafa1), (0x2be052a, '4c8b3537fc8f03'), ((0x2be05e5, '488db424f0010000'), (0x2be05b8, '48898424f0010000'), (0x2be05b0, '488d842430010000')), (0x2bdfb11, '488d0586e6a2fd'), (0x2bdfb20, '48c784243801000012000000'), 'distribute_funding', (0x2bdfb34, '660f2805543d87fd'), (0x2bdfb3c, '660f11842440010000'), (0x2bdfb18, '4889842430010000')),
    (0x2be103b, 0x26d4660, (0x2bdf8f0, 0x2beafa1), (0x2be0f8a, '4c8b35d7f18f03'), ((0x2be1033, '488db42430010000'), (0x2be1016, '4889842430010000'), (0x2be100e, '488d8424f0010000')), (0x2be0732, '488d05a2daa2fd'), (0x2be0741, '48c78424f801000014000000'), 'update_funding_rates', (0x2be074d, '660f2805db2d87fd'), (0x2be0755, '660f11842400020000'), (0x2be0739, '48898424f0010000')),
    (0x2be17fd, 0x26d4660, (0x2bdf8f0, 0x2beafa1), (0x2be173a, '4c8b3527ea8f03'), ((0x2be17f5, '488db424f0010000'), (0x2be17c8, '48898424f0010000'), (0x2be17c0, '488d842430010000')), (0x2be11a0, '488d0593d0a2fd'), (0x2be11af, '48c784243801000022000000'), 'cancel_aggressive_orders_at_oi_cap', (0x2be11bb, '660f28056d2387fd'), (0x2be11c3, '660f11842440010000'), (0x2be11a7, '4889842430010000')),
    (0x2be1d8d, 0x26d4660, (0x2bdf8f0, 0x2beafa1), (0x2be1cca, '4c8b3597e48f03'), ((0x2be1d85, '488db424f0010000'), (0x2be1d58, '48898424f0010000'), (0x2be1d50, '488d842430010000')), (0x2be191a, '488d05fdc8a2fd'), (0x2be1929, '48c78424380100001c000000'), 'prune_book_empty_user_states', (0x2be193d, '660f2805db1b87fd'), (0x2be1945, '660f11842440010000'), (0x2be1921, '4889842430010000')),
    (0x2be6b6b, 0x26d4660, (0x2bdf8f0, 0x2beafa1), (0x2be6aba, '4c8b35a7968f03'), ((0x2be6b63, '488db42430010000'), (0x2be6b3e, '4889842430010000'), (0x2be6b36, '488d842480020000')), (0x2be66b6, '488d059f7ba2fd'), (0x2be66c5, '48c784248802000022000000'), 'refresh_main_perp_dex_stale_oracle', (0x2be66d1, '660f280557ce86fd'), (0x2be66d9, '660f11842490020000'), (0x2be66bd, '4889842480020000')),
    (0x2be797d, 0x26d4660, (0x2bdf8f0, 0x2beafa1), (0x2be78ba, '4c8b35a7888f03'), ((0x2be7975, '488db42430010000'), (0x2be7948, '4889842430010000'), (0x2be7940, '488d8424c0030000')), (0x2be6cb5, '488d054775a2fd'), (0x2be6cc4, '48c78424c80300001b000000'), 'refresh_hip3_stale_mark_pxs', (0x2be6cd0, '660f280558c886fd'), (0x2be6cd8, '660f118424d0030000'), (0x2be6cbc, '48898424c0030000')),
    (0x2be82fb, 0x26d4660, (0x2bdf8f0, 0x2beafa1), (0x2be824a, '4c8b35177f8f03'), ((0x2be82f3, '488db42430010000'), (0x2be82d6, '4889842430010000'), (0x2be82ce, '488d842400030000')), (0x2be7ab5, '488d05f466a2fd'), (0x2be7ac4, '48c784240803000017000000'), 'apply_bole_liquidations', (0x2be7ad0, '0f280559ba86fd'), (0x2be7ad7, '0f11842410030000'), (0x2be7abc, '4889842400030000')),
    (0x2c72412, 0x26d4660, (0x2c71eb0, 0x2c74a69), (0x2c72334, '4c8b252dde8603'), ((0x2c7240d, '488d742430'), (0x2c723e6, '4889442430'), (0x2c723de, '488d842410010000')), (0x2c71ff8, '488d0505ca99fd'), (0x2c72007, '48c78424180100002a000000'), 'build_small_evm_block_and_apply_l1_effects', (0x2c7201b, '660f2805cd347efd'), (0x2c72023, '660f11842420010000'), (0x2c71fff, '4889842410010000')),
    (0x2c728f5, 0x26d4660, (0x2c71eb0, 0x2c74a69), (0x2c7281a, '488b0d47d98603'), ((0x2c728ed, '488db424e0000000'), (0x2c728c3, '48898424e0000000'), (0x2c728be, '488d442430')), (0x2c72512, '488d0515c599fd'), (0x2c7251e, '48c744243828000000'), 'build_big_evm_block_and_apply_l1_effects', (0x2c7252c, '660f2805ec0f7efd'), (0x2c72534, '660f11442440'), (0x2c72519, '4889442430')),
    (0x5483ddf, 0x51eaff0, (0x5483850, 0x5483f43), (0x5483d16, '488b2d4bc40501'), ((0x5483dda, '488d742470'), (0x5483db3, '4889442470'), (0x5483dab, '488d842488000000')), (0x5483a27, '488d057f634afb'), (0x5483a36, '48c78424900000000b000000'), 'begin_block', (0x5483a4a, '660f2805cefafcfa'), (0x5483a52, '660f11842498000000'), (0x5483a2e, '4889842488000000')),
    (0x54844ff, 0x51eaff0, (0x5483f50, 0x5484663), (0x5484436, '488b2d2bbd0501'), ((0x54844fa, '488d742470'), (0x54844d3, '4889442470'), (0x54844cb, '488d842488000000')), (0x5484143, '488d05635c4afb'), (0x5484152, '48c78424900000000b000000'), 'begin_block', (0x5484166, '660f2805b2f3fcfa'), (0x548416e, '660f11842498000000'), (0x548414a, '4889842488000000')),
    (0x5487122, 0x51eaff0, (0x5486720, 0x54897e0), (0x5487044, '4c8b251d910501'), ((0x548711d, '488d742430'), (0x54870f6, '4889442430'), (0x54870ee, '488d842410010000')), (0x5486d0b, '488d05bd384afb'), (0x5486d1a, '48c78424180100002a000000'), 'build_small_evm_block_and_apply_l1_effects', (0x5486d2e, '660f2805bae7fcfa'), (0x5486d36, '660f11842420010000'), (0x5486d12, '4889842410010000')),
    (0x54875f5, 0x51eaff0, (0x5486720, 0x54897e0), (0x548751a, '488b0d478c0501'), ((0x54875ed, '488db424c0000000'), (0x54875c3, '48898424c0000000'), (0x54875be, '488d442430')), (0x548721e, '488d05d4334afb'), (0x548722a, '48c744243828000000'), 'build_big_evm_block_and_apply_l1_effects', (0x5487238, '660f2805e0c2fcfa'), (0x5487240, '660f11442440'), (0x5487225, '4889442430')),
    (0x548a262, 0x51eaff0, (0x54897e0, 0x548c8e0), (0x548a184, '4c8b25dd5f0501'), ((0x548a25d, '488d742430'), (0x548a236, '4889442430'), (0x548a22e, '488d842430010000')), (0x5489e4f, '488d0579074afb'), (0x5489e5e, '48c78424380100002a000000'), 'build_small_evm_block_and_apply_l1_effects', (0x5489e72, '660f280576b6fcfa'), (0x5489e7a, '660f11842440010000'), (0x5489e56, '4889842430010000')),
    (0x548a735, 0x51eaff0, (0x54897e0, 0x548c8e0), (0x548a65a, '488b0d075b0501'), ((0x548a72d, '488db424c0000000'), (0x548a703, '48898424c0000000'), (0x548a6fe, '488d442430')), (0x548a35e, '488d0594024afb'), (0x548a36a, '48c744243828000000'), 'build_big_evm_block_and_apply_l1_effects', (0x548a378, '660f2805a091fcfa'), (0x548a380, '660f11442440'), (0x548a365, '4889442430')),
    (0x54aa9a2, 0x51eaff0, (0x54a9c70, 0x54b66a2), (0x54aa8da, '488b0d87580301'), ((0x54aa99a, '488db42450020000'), (0x54aa96d, '4889842450020000'), (0x54aa965, '488d842460010000')), (0x54a9e9d, '488d0514ff47fb'), (0x54a9eac, '48c784246801000012000000'), 'distribute_funding', (0x54a9ec0, '660f2805c899fafa'), (0x54a9ec8, '660f11842470010000'), (0x54a9ea4, '4889842460010000')),
    (0x54ab402, 0x51eaff0, (0x54a9c70, 0x54b66a2), (0x54ab33a, '488b0d274e0301'), ((0x54ab3fa, '488db42460010000'), (0x54ab3cd, '4889842460010000'), (0x54ab3c5, '488d842450020000')), (0x54aaae8, '488d0506f347fb'), (0x54aaaf7, '48c784245802000014000000'), 'update_funding_rates', (0x54aab03, '660f2805258afafa'), (0x54aab0b, '660f11842460020000'), (0x54aaaef, '4889842450020000')),
    (0x54abc52, 0x51eaff0, (0x54a9c70, 0x54b66a2), (0x54abb8a, '488b0dd7450301'), ((0x54abc4a, '488db42450020000'), (0x54abc1d, '4889842450020000'), (0x54abc15, '488d842460010000')), (0x54ab5d7, '488d0576e847fb'), (0x54ab5e6, '48c784246801000022000000'), 'cancel_aggressive_orders_at_oi_cap', (0x54ab5f2, '660f2805367ffafa'), (0x54ab5fa, '660f11842470010000'), (0x54ab5de, '4889842460010000')),
    (0x54ac1e2, 0x51eaff0, (0x54a9c70, 0x54b66a2), (0x54ac11a, '488b0d47400301'), ((0x54ac1da, '488db42450020000'), (0x54ac1ad, '4889842450020000'), (0x54ac1a5, '488d842460010000')), (0x54abd99, '488d0598e047fb'), (0x54abda8, '48c78424680100001c000000'), 'prune_book_empty_user_states', (0x54abdbc, '660f28055c77fafa'), (0x54abdc4, '660f11842470010000'), (0x54abda0, '4889842460010000')),
    (0x54b1552, 0x51eaff0, (0x54a9c70, 0x54b66a2), (0x54b149d, '488b0dc4ec0201'), ((0x54b154a, '488db42460010000'), (0x54b151d, '4889842460010000'), (0x54b1515, '488d8424f0020000')), (0x54b0fe3, '488d058c8e47fb'), (0x54b0ff2, '48c78424f802000022000000'), 'refresh_main_perp_dex_stale_oracle', (0x54b0ffe, '0f28052b25fafa'), (0x54b1005, '0f11842400030000'), (0x54b0fea, '48898424f0020000')),
    (0x54b23c5, 0x51eaff0, (0x54a9c70, 0x54b66a2), (0x54b22fd, '488b0d64de0201'), ((0x54b23bd, '488db42460010000'), (0x54b2390, '4889842460010000'), (0x54b2388, '488d842418040000')), (0x54b1695, '488d05818747fb'), (0x54b16a4, '48c78424200400001b000000'), 'refresh_hip3_stale_mark_pxs', (0x54b16b0, '660f2805781efafa'), (0x54b16b8, '660f11842428040000'), (0x54b169c, '4889842418040000')),
    (0x54b3792, 0x51eaff0, (0x54a9c70, 0x54b66a2), (0x54b36ca, '488b0d97ca0201'), ((0x54b378a, '488db42460010000'), (0x54b375d, '4889842460010000'), (0x54b3755, '488d842460030000')), (0x54b2521, '488d05a27847fb'), (0x54b2530, '48c784246803000017000000'), 'apply_bole_liquidations', (0x54b253c, '0f2805ed0ffafa'), (0x54b2543, '0f11842470030000'), (0x54b2528, '4889842460030000')),
    (0x54b73c2, 0x51eaff0, (0x54b66b0, 0x54c2ae8), (0x54b72fa, '488b0d678e0201'), ((0x54b73ba, '488db424e0010000'), (0x54b738d, '48898424e0010000'), (0x54b7385, '488d842420010000')), (0x54b68d1, '488d05e03447fb'), (0x54b68e0, '48c784242801000012000000'), 'distribute_funding', (0x54b68f4, '660f280594cff9fa'), (0x54b68fc, '660f11842430010000'), (0x54b68d8, '4889842420010000')),
    (0x54b7e22, 0x51eaff0, (0x54b66b0, 0x54c2ae8), (0x54b7d5a, '488b0d07840201'), ((0x54b7e1a, '488db42420010000'), (0x54b7ded, '4889842420010000'), (0x54b7de5, '488d8424e0010000')), (0x54b7508, '488d05e62847fb'), (0x54b7517, '48c78424e801000014000000'), 'update_funding_rates', (0x54b7523, '660f280505c0f9fa'), (0x54b752b, '660f118424f0010000'), (0x54b750f, '48898424e0010000')),
    (0x54b85f2, 0x51eaff0, (0x54b66b0, 0x54c2ae8), (0x54b852a, '488b0d377c0201'), ((0x54b85ea, '488db424e0010000'), (0x54b85bd, '48898424e0010000'), (0x54b85b5, '488d842420010000')), (0x54b7f88, '488d05c51e47fb'), (0x54b7f97, '48c784242801000022000000'), 'cancel_aggressive_orders_at_oi_cap', (0x54b7fa3, '660f280585b5f9fa'), (0x54b7fab, '660f11842430010000'), (0x54b7f8f, '4889842420010000')),
    (0x54b8b42, 0x51eaff0, (0x54b66b0, 0x54c2ae8), (0x54b8a7a, '488b0de7760201'), ((0x54b8b3a, '488db424e0010000'), (0x54b8b0d, '48898424e0010000'), (0x54b8b05, '488d842420010000')), (0x54b8710, '488d05211747fb'), (0x54b871f, '48c78424280100001c000000'), 'prune_book_empty_user_states', (0x54b8733, '660f2805e5adf9fa'), (0x54b873b, '660f11842430010000'), (0x54b8717, '4889842420010000')),
    (0x54bdb8f, 0x51eaff0, (0x54b66b0, 0x54c2ae8), (0x54bdada, '488b0d87260201'), ((0x54bdb87, '488db42420010000'), (0x54bdb5a, '4889842420010000'), (0x54bdb52, '488d842480020000')), (0x54bd626, '488d0549c846fb'), (0x54bd635, '48c784248802000022000000'), 'refresh_main_perp_dex_stale_oracle', (0x54bd641, '0f2805e85ef9fa'), (0x54bd648, '0f11842490020000'), (0x54bd62d, '4889842480020000')),
    (0x54bea02, 0x51eaff0, (0x54b66b0, 0x54c2ae8), (0x54be93a, '488b0d27180201'), ((0x54be9fa, '488db42420010000'), (0x54be9cd, '4889842420010000'), (0x54be9c5, '488d842490030000')), (0x54bdcda, '488d053cc146fb'), (0x54bdce9, '48c78424980300001b000000'), 'refresh_hip3_stale_mark_pxs', (0x54bdcf5, '660f28053358f9fa'), (0x54bdcfd, '660f118424a0030000'), (0x54bdce1, '4889842490030000')),
    (0x54bfda2, 0x51eaff0, (0x54b66b0, 0x54c2ae8), (0x54bfcda, '488b0d87040201'), ((0x54bfd9a, '488db42420010000'), (0x54bfd6d, '4889842420010000'), (0x54bfd65, '488d842410030000')), (0x54beb3b, '488d0588b246fb'), (0x54beb4a, '48c784241803000017000000'), 'apply_bole_liquidations', (0x54beb56, '0f2805d349f9fa'), (0x54beb5d, '0f11842420030000'), (0x54beb42, '4889842410030000')),
    (0x5647b7e, 0x51eaff0, (0x5647720, 0x5647d98), (0x5647abd, '488b0da486e900'), ((0x5647b6a, '488d742458'), (0x5647b46, '4889442458'), (0x5647b41, '488d442470')), (0x564787a, '488d05742f2efb'), (0x5647886, '48c74424781f000000'), 'slow_abci_engine_read_increment', (0x564788f, '660f280599bce0fa'), (0x5647897, '660f11842480000000'), (0x5647881, '4889442470')),
    (0x56481f8, 0x51eaff0, (0x5647da0, 0x56483fe), (0x564813b, '488b0d2680e900'), ((0x56481e4, '488d742450'), (0x56481c3, '4889442450'), (0x56481be, '488d442468')), (0x5647f04, '488d05ea282efb'), (0x5647f10, '48c74424701f000000'), 'slow_abci_engine_read_increment', (0x5647f19, '660f28050fb6e0fa'), (0x5647f21, '660f11442478'), (0x5647f0b, '4889442468')),
    (0x564885e, 0x51eaff0, (0x5648400, 0x5648a26), (0x564879d, '488b0dc479e900'), ((0x564884a, '488d742458'), (0x5648826, '4889442458'), (0x5648821, '488d442470')), (0x564855a, '488d0594222efb'), (0x5648566, '48c74424781f000000'), 'slow_abci_engine_read_increment', (0x564856f, '660f2805b9afe0fa'), (0x5648577, '660f11842480000000'), (0x5648561, '4889442470')),
    (0x5648e88, 0x51eaff0, (0x5648a30, 0x5649054), (0x5648dcb, '488b0d9673e900'), ((0x5648e74, '488d742450'), (0x5648e53, '4889442450'), (0x5648e4e, '488d442468')), (0x5648b8a, '488d05641c2efb'), (0x5648b96, '48c74424701f000000'), 'slow_abci_engine_read_increment', (0x5648b9f, '660f280589a9e0fa'), (0x5648ba7, '660f11442478'), (0x5648b91, '4889442468')),
    (0x56494be, 0x51eaff0, (0x5649060, 0x5649678), (0x56493fd, '488b0d646de900'), ((0x56494aa, '488d742458'), (0x5649486, '4889442458'), (0x5649481, '488d442470')), (0x56491ba, '488d0534162efb'), (0x56491c6, '48c74424781f000000'), 'slow_abci_engine_read_increment', (0x56491cf, '660f280559a3e0fa'), (0x56491d7, '660f11842480000000'), (0x56491c1, '4889442470')),
    (0x564a276, 0x51eaff0, (0x5649df0, 0x564a40d), (0x564a26f, '4c8b25f25ee900'), ((0x564a267, '488db42488000000'), (0x564a240, '4c89b42488000000'), (0x564a1ee, '4c8d742460')), (0x5649f4b, '488d05a3082efb'), (0x5649f57, '48c74424681f000000'), 'slow_abci_engine_read_increment', (0x5649f60, '660f2805c895e0fa'), (0x5649f68, '660f11442470'), (0x5649f52, '4889442460')),
)

WRAPPER_SITES = (
    # getter call, getter, wrapper FDE, lock-slot load, closure pins (lea rsi / name capture / its load), p+0x10 lea
    (0x2c7e411, 0x26d4660, (0x2c7e0b0, 0x2c7e4cf), (0x2c7e364, '488b2dfd1d8603'), ((0x2c7e40c, '488d742468'), (0x2c7e3f4, '48894c2468'), (0x2c7e3eb, '488b4c2460'))),
    (0x422a53e, 0x3704070, (0x4229fe0, 0x422a628), (0x422a494, '488b2dcd5c2b02'), ((0x422a539, '488d742420'), (0x422a521, '4c89742420'), (0x422a4cf, '4c8bb42488000000'))),
    (0x422ab27, 0x3704070, (0x422a630, 0x422abe5), (0x422aa74, '488b2ded562b02'), ((0x422ab22, '488d742478'), (0x422ab04, '48894c2478'), (0x422aafb, '488b4c2470'))),
    (0x422c0c4, 0x3704070, (0x422abf0, 0x422c320), (0x422c009, '488b0d58412b02'), ((0x422c0bc, '488db42490010000'), (0x422c09b, '48898c2490010000'), (0x422c08f, '488b8c2480010000'))),
    (0x422c6be, 0x3704070, (0x422c320, 0x422c95f), (0x422c613, '4c8b2d4e3b2b02'), ((0x422c6b9, '488d742428'), (0x422c6a1, '4c89742428'), (0x422c652, '4c8b742418'))),
    (0x422ce87, 0x3704070, (0x422c960, 0x422cfee), (0x422cdda, '488b0d87332b02'), ((0x422ce82, '488d742460'), (0x422ce6a, '4c89742460'), (0x422ce18, '4c8bb42488000000'))),
    (0x422d361, 0x3704070, (0x422cff0, 0x422d41f), (0x422d2b4, '488b2dad2e2b02'), ((0x422d35c, '488d742468'), (0x422d344, '48894c2468'), (0x422d33b, '488b4c2460'))),
    (0x422da1e, 0x3704070, (0x422d420, 0x422dba4), (0x422d974, '4c8b35ed272b02'), ((0x422da19, '488d742460'), (0x422da01, '48895c2460'), (0x422d9af, '488b9c2488000000'))),
    (0x422df01, 0x3704070, (0x422dbb0, 0x422dfbf), (0x422de54, '488b2d0d232b02'), ((0x422defc, '488d742468'), (0x422dee4, '48894c2468'), (0x422dedb, '488b4c2460'))),
    (0x4780781, 0x4770930, (0x4780430, 0x478083f), (0x47806d4, '488b2d8dfad501'), ((0x478077c, '488d742468'), (0x4780764, '48894c2468'), (0x478075b, '488b4c2460'))),
    (0x56176c1, 0x51eaff0, (0x5617370, 0x561777f), (0x5617614, '488b2d4d8bec00'), ((0x56176bc, '488d742468'), (0x56176a4, '48894c2468'), (0x561769b, '488b4c2460'))),
    (0x5617ae1, 0x51eaff0, (0x5617780, 0x5617b9f), (0x5617a34, '488b2d2d87ec00'), ((0x5617adc, '488d742468'), (0x5617ac4, '48894c2468'), (0x5617abb, '488b4c2460'))),
    (0x5617f01, 0x51eaff0, (0x5617ba0, 0x5617fbf), (0x5617e54, '488b2d0d83ec00'), ((0x5617efc, '488d742468'), (0x5617ee4, '48894c2468'), (0x5617edb, '488b4c2460'))),
    (0x5618311, 0x51eaff0, (0x5617fc0, 0x56183cf), (0x5618264, '488b2dfd7eec00'), ((0x561830c, '488d742468'), (0x56182f4, '48894c2468'), (0x56182eb, '488b4c2460'))),
)

WRAPPER_CALLERS = (
    # wrapper call, wrapper, argument register, argument pins, name lea, length store, name, pair lea, pair store, ptr store
    (0x2be1fca, 0x422cff0, 'rdi', ((0x2be1fc4, '4c89f7'), (0x2be1ed3, '4c8d742460'),), (0x2be1f6d, '488d05de8cbdfd'), (0x2be1f79, '48c744246813000000'), 'gas_auction_restart', (0x2be1f82, '660f2805a61587fd'), (0x2be1f8a, '660f11442470'), (0x2be1f74, '4889442460')),
    (0x2be5ce0, 0x422dbb0, 'rdi', ((0x2be5cd3, '488d7c2460'),), (0x2be5c80, '488d05ce76bbfd'), (0x2be5c8c, '48c744246827000000'), 'validator_l1_vote_tracker_prune_expired', (0x2be5c95, '660f280593d886fd'), (0x2be5c9d, '660f11442470'), (0x2be5c87, '4889442460')),
    (0x2be608b, 0x4229fe0, 'rdi', ((0x2be6085, '4c89ff'), (0x2be601b, '4c8d7c2460'),), (0x2be6014, '4c8d2d65dd86fd'), (0x2be603f, '48c744246810000000'), 'reset_recent_ois', (0x2be6048, '660f2805e0d486fd'), (0x2be6050, '660f11442470'), (0x2be603a, '4c896c2460')),
    (0x2d1d80c, 0x2c7e0b0, 'rdi', ((0x2d1d804, '488d7c2430'),), (0x2d1d7c9, '488d05d1928ffd'), (0x2d1d7d5, '48c74424381c000000'), 'hyperliquidity_ensure_orders', (0x2d1d7e3, '660f6f05f55273fd'), (0x2d1d7eb, 'f30f7f442440'), (0x2d1d7d0, '4889442430')),
    (0x366ee4f, 0x422d420, 'rdi', ((0x366ee44, '488dbc2420010000'),), (0x366edb2, '4c8d25d3e412fd'), (0x366edcf, '48c78424280100001a000000'), 'median_reference_oracle_px', (0x366eddb, '0f28054e47defc'), (0x366ede2, '0f11842430010000'), (0x366edc7, '4c89a42420010000')),
    (0x3c3f938, 0x422c320, 'rsi', ((0x3c3f928, '488db424f0000000'),), (0x3c3f8bb, '488d0597c5b7fc'), (0x3c3f8ca, '48c78424f800000016000000'), 'c_staking_stage_reward', (0x3c3f8d6, '0f2805533c81fc'), (0x3c3f8dd, '0f11842400010000'), (0x3c3f8c2, '48898424f0000000')),
    (0x3c3fad4, 0x422abf0, 'rsi', ((0x3c3fac7, '488db424f0000000'),), (0x3c3fa71, '488d05f7c3b7fc'), (0x3c3fa80, '48c78424f800000023000000'), 'c_staking_distribute_staged_rewards', (0x3c3fa8c, '0f28059d3a81fc'), (0x3c3fa93, '0f11842400010000'), (0x3c3fa78, '48898424f0000000')),
    (0x3c402fa, 0x422a630, 'rdi', ((0x3c402ef, '488dbc24f0000000'),), (0x3c402bd, '488d051fbcb7fc'), (0x3c402cc, '48c78424f80000000d000000'), 'decay_staking', (0x3c402d8, '0f2805513281fc'), (0x3c402df, '0f11842400010000'), (0x3c402c4, '48898424f0000000')),
    (0x3d73162, 0x422cff0, 'rdi', ((0x3d73155, '488d7c2468'),), (0x3d730fe, '488d054d7ba4fc'), (0x3d7310a, '48c744247013000000'), 'gas_auction_restart', (0x3d73113, '660f280515046efc'), (0x3d7311b, '660f11442478'), (0x3d73105, '4889442468')),
    (0x4230891, 0x422cff0, 'rdi', ((0x4230887, '488d7c2408'),), (0x4230841, '488d050aa458fc'), (0x423084d, '48c744241013000000'), 'gas_auction_restart', (0x4230856, '0f2805d32c22fc'), (0x423085d, '0f11442418'), (0x4230848, '4889442408')),
    (0x4770e9e, 0x4780430, 'rdi', ((0x4770e94, '488d7c2418'),), (0x4770e6e, '488d05db0507fc'), (0x4770e7a, '48c74424201a000000'), 'profiled_rw_lock_increment', (0x4770e83, '0f2805a626cefb'), (0x4770e8a, '0f11442428'), (0x4770e75, '4889442418')),
    (0x518540c, 0x5617ba0, 'rdi', ((0x5185404, '488d7c2430'),), (0x51853c9, '488d05b99e79fb'), (0x51853d5, '48c74424381c000000'), 'hyperliquidity_ensure_orders', (0x51853e3, '660f6f05f5d62cfb'), (0x51853eb, 'f30f7f442440'), (0x51853d0, '4889442430')),
    (0x518568c, 0x5617780, 'rdi', ((0x5185684, '488d7c2430'),), (0x5185649, '488d05399c79fb'), (0x5185655, '48c74424381c000000'), 'hyperliquidity_ensure_orders', (0x5185663, '660f6f0575d42cfb'), (0x518566b, 'f30f7f442440'), (0x5185650, '4889442430')),
    (0x54ac45a, 0x422cff0, 'rdi', ((0x54ac454, '4c89f7'), (0x54ac360, '4c8d742460'),), (0x54ac3fd, '488d054ee830fb'), (0x54ac409, '48c744246813000000'), 'gas_auction_restart', (0x54ac412, '660f28051671fafa'), (0x54ac41a, '660f11442470'), (0x54ac404, '4889442460')),
    (0x54b0610, 0x422dbb0, 'rdi', ((0x54b0603, '488d7c2460'),), (0x54b05b0, '488d059ecd2efb'), (0x54b05bc, '48c744246827000000'), 'validator_l1_vote_tracker_prune_expired', (0x54b05c5, '660f2805632ffafa'), (0x54b05cd, '660f11442470'), (0x54b05b7, '4889442460')),
    (0x54b09bb, 0x4229fe0, 'rdi', ((0x54b09b5, '4c89f7'), (0x54b094b, '4c8d742460'),), (0x54b0944, '4c8d2d3534fafa'), (0x54b096f, '48c744246810000000'), 'reset_recent_ois', (0x54b0978, '660f2805b02bfafa'), (0x54b0980, '660f11442470'), (0x54b096a, '4c896c2460')),
    (0x54b8d8a, 0x422cff0, 'rdi', ((0x54b8d84, '4c89f7'), (0x54b8c89, '4c8d742460'),), (0x54b8d2d, '488d051e1f30fb'), (0x54b8d39, '48c744246813000000'), 'gas_auction_restart', (0x54b8d42, '660f2805e6a7f9fa'), (0x54b8d4a, '660f11442470'), (0x54b8d34, '4889442460')),
    (0x54bcc5f, 0x422dbb0, 'rdi', ((0x54bcc52, '488d7c2460'),), (0x54bcbff, '488d054f072efb'), (0x54bcc0b, '48c744246827000000'), 'validator_l1_vote_tracker_prune_expired', (0x54bcc14, '660f28051469f9fa'), (0x54bcc1c, '660f11442470'), (0x54bcc06, '4889442460')),
    (0x54bcffb, 0x4229fe0, 'rdi', ((0x54bcff5, '4c89f7'), (0x54bcf8b, '4c8d742460'),), (0x54bcf84, '4c8d2df56df9fa'), (0x54bcfaf, '48c744246810000000'), 'reset_recent_ois', (0x54bcfb8, '660f28057065f9fa'), (0x54bcfc0, '660f11442470'), (0x54bcfaa, '4c896c2460')),
    (0x595ee07, 0x5617fc0, 'rdi', ((0x595edff, '488d7c2410'),), (0x595edd7, '488d059398fdfa'), (0x595ede3, '48c74424180e000000'), 'reset_counters', (0x595edec, '660f6f053c47affa'), (0x595edf4, 'f30f7f442420'), (0x595edde, '4889442410')),
    (0x5a5de24, 0x5617370, 'rdi', ((0x5a5de1c, '488d7c2428'),), (0x5a5ddf6, '488d0574a8edfa'), (0x5a5de02, '48c74424300e000000'), 'reset_counters', (0x5a5de0b, '0f28051e579ffa'), (0x5a5de12, '0f11442438'), (0x5a5ddfd, '4889442428')),
    (0x5a5fffe, 0x5617370, 'rdi', ((0x5a5fff3, '488dbc2490140000'),), (0x5a5ffbf, '488d05ab86edfa'), (0x5a5ffce, '48c78424981400000e000000'), 'reset_counters', (0x5a5ffda, '660f28054e359ffa'), (0x5a5ffe2, '660f118424a0140000'), (0x5a5ffc6, '4889842490140000')),
    (0x5a62fb8, 0x5617370, 'rdi', ((0x5a62fb0, '488d7c2430'),), (0x5a62f8a, '488d05e056edfa'), (0x5a62f96, '48c74424380e000000'), 'reset_counters', (0x5a62f9f, '0f28058a059ffa'), (0x5a62fa6, '0f11442440'), (0x5a62f91, '4889442430')),
)

# median_risk_free_rate: 0x3673a10 receives the name in r9 (pointer) and its 7th
# argument slot [rsp+0x90] (length), copies them to [rsp+0x58]/[rsp+0x60] and
# passes rsp+0x58 to the wrapper 0x422c960 in rdi.
HOP_BODY = (
    (0x3673a18, '4c8b942490000000'),  # mov r10, [rsp+0x90]
    (0x3673b0c, '4c894c2458'),        # mov [rsp+0x58], r9
    (0x3673b11, '4c89542460'),        # mov [rsp+0x60], r10
    (0x3673b59, '488d7c2458'),        # lea rdi, [rsp+0x58]
    (0x3673b63, 'e8f88dbb00'),        # call 0x422c960
)
HOP_PAIR = ((0x3673b16, '0f280513faddfc'), (0x3673b1d, '0f11442468'))
# call, lea r9 (va, bytes), mov qword [rsp], 0x15 (va, bytes)
HOP_CALLERS = (
    (0x2be6219, (0x2be6202, '4c8d0dda52bdfd'), (0x2be61fa, '48c7042415000000')),
    (0x54b0b6f, (0x54b0b58, '4c8d0d84a930fb'), (0x54b0b50, '48c7042415000000')),
    (0x54bd189, (0x54bd172, '4c8d0d6ae32ffb'), (0x54bd16a, '48c7042415000000')),
)
HOP_NAME = 'median_risk_free_rate'

# Key search in front of the first site (begin_block, 0x2bdf7e9): node keys at
# +0x1a28 (stride 0x18), u16 length at +0x1b32, memcmp of the key bytes, child
# edges at +0x1b38, height counted down to the leaf.
BTREE = (
    (0x2bdf688, '488d81281a0000'),    # lea rax, [rcx+0x1a28]
    (0x2bdf694, '0fb789321b0000'),    # movzx ecx, word [rcx+0x1b32]
    (0x2bdf6e0, 'ff156a049003'),      # call [memcmp GOT]
    (0x2bdf6fc, '4883c5e8'),          # add rbp, -0x18
    (0x2bdf72a, '4883e801'),          # sub rax, 1 (height)
    (0x2bdf739, '4a8b8ce1381b0000'),  # mov rcx, [rcx+r12*8+0x1b38]
)
MEMCMP_GOT = 0x64dfb50
MEMCPY_GOT = 0x64df508


def read_va(data, va, size):
    matches = [s for s in sections(data)
               if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError(f'expected one file-backed mapping at {va:#x}')
    off = matches[0]['offset'] + va - matches[0]['address']
    return off, data[off:off + size]


def pinned(data, pin):
    va, text = pin
    raw = bytes.fromhex(text)
    if read_va(data, va, len(raw))[1] != raw:
        raise ValueError(f'instruction at {va:#x} changed')
    return raw


def rip(data, pin):
    """Target of a rip-relative instruction whose disp32 ends the instruction or precedes no immediate."""
    raw = pinned(data, pin)
    return pin[0] + len(raw) + struct.unpack_from('<i', raw, len(raw) - 4)[0]


def rsp_disp(raw):
    """Displacement of the [rsp+disp] operand: ModRM rm=100 with SIB 0x24."""
    for i in range(1, len(raw) - 1):
        modrm = raw[i]
        if raw[i + 1] == 0x24 and modrm & 7 == 4 and modrm >> 6 in (1, 2):
            if modrm >> 6 == 1:
                return raw[i + 2]
            return struct.unpack_from('<I', raw, i + 2)[0]
    raise ValueError(f'no [rsp+disp] operand in {raw.hex()}')


def relocations(data):
    rel, glob = {}, {}
    secs = sections(data)
    for sec in secs:
        if sec['type'] != 4:
            continue
        if sec['size'] % 24:
            raise ValueError(f"relocation section {sec['name']} is truncated")
        for va, info, addend in struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']]):
            if info & 0xffffffff == 8:
                rel[va] = addend
            elif info & 0xffffffff == 6:
                glob[va] = info >> 32
    return rel, glob


def dynamic_symbol(data, index):
    secs = sections(data)
    dynsym = next(s for s in secs if s['name'] == '.dynsym')
    dynstr = next(s for s in secs if s['name'] == '.dynstr')
    name_off = struct.unpack_from('<I', data, dynsym['offset'] + 24 * index)[0]
    end = data.index(b'\0', dynstr['offset'] + name_off)
    return data[dynstr['offset'] + name_off:end].decode()


def frame(fdes, va):
    rows = [(f['start'], f['end']) for f in fdes if f['start'] <= va < f['end']]
    if len(rows) != 1:
        raise ValueError(f'expected one FDE at {va:#x}')
    return rows[0]


def direct_calls(data, targets):
    sec = next(s for s in sections(data) if s['name'] == '.text')
    base, raw = sec['address'], data[sec['offset']:sec['offset'] + sec['size']]
    out, start = collections.defaultdict(list), 0
    while True:
        i = raw.find(b'\xe8', start)
        if i < 0 or i + 5 > len(raw):
            return out
        start = i + 1
        target = base + i + 5 + struct.unpack_from('<i', raw, i + 1)[0]
        if target in targets:
            out[target].append(base + i)


def call_target(data, va):
    _, raw = read_va(data, va, 5)
    if raw[0] != 0xe8:
        raise ValueError(f'no direct call at {va:#x}')
    return va + 5 + struct.unpack_from('<i', raw, 1)[0]


def clock_calls(data, fde):
    """mov edi, 1 immediately followed by call NOW inside the FDE."""
    off, raw = read_va(data, fde[0], fde[1] - fde[0])
    count, start = 0, 0
    while True:
        i = raw.find(b'\xbf\x01\x00\x00\x00\xe8', start)
        if i < 0:
            return count
        start = i + 1
        if fde[0] + i + 10 + struct.unpack_from('<i', raw, i + 6)[0] == NOW:
            count += 1


def record_follows(data, va):
    _, raw = read_va(data, va + 5, 0x30)
    for i in range(len(raw) - 6):
        if raw[i:i + 2] == b'\xff\x15' and va + 5 + i + 6 + struct.unpack_from('<i', raw, i + 2)[0] == RECORD_SLOT:
            return va + 5 + i
    raise ValueError(f'no record call after {va:#x}')


def name_struct(data, lea, length_store, ptr_store, pair_lea, pair_store, name):
    text_va = rip(data, lea)
    length_raw = pinned(data, length_store)
    length = struct.unpack_from('<I', length_raw, len(length_raw) - 4)[0]
    _, text = read_va(data, text_va, length)
    if text.decode() != name:
        raise ValueError(f'name at {text_va:#x} changed')
    ptr_raw = pinned(data, ptr_store)
    base = rsp_disp(ptr_raw)
    if rsp_disp(length_raw) != base + 8:
        raise ValueError(f'length store at {length_store[0]:#x} is not beside the pointer')
    if bytes.fromhex(lea[1])[2] >> 3 & 7 != ptr_raw[2] >> 3 & 7 or bytes.fromhex(lea[1])[0] & 4 != ptr_raw[0] & 4:
        raise ValueError(f'pointer store at {ptr_store[0]:#x} does not store the lea register')
    pair_raw = pinned(data, pair_store)
    if rsp_disp(pair_raw) != base + 0x10:
        raise ValueError(f'pair store at {pair_store[0]:#x} is not 16 bytes after the name')
    pair = struct.unpack('<2d', read_va(data, rip(data, pair_lea), 16)[1])
    return {'name': name, 'string': hex(text_va), 'length': length, 'struct': hex(base), 'pair': list(pair)}


def bind(data, fdes):
    rel, glob = relocations(data)
    for slot, target in ((RECORD_SLOT, RECORD), (CTOR_SLOT, CTOR), (FORMAT_SLOT, FORMAT),
                         (PAD_SLOT, PAD), (GLOBAL_SLOT, GLOBAL)):
        if rel.get(slot) != target:
            raise ValueError(f'slot {slot:#x} changed')
    data_sec = next(s for s in sections(data) if s['name'] == '.data')
    if not data_sec['address'] <= GLOBAL < data_sec['address'] + data_sec['size']:
        raise ValueError('global is not in .data')
    if CLOCK_GOT not in glob or dynamic_symbol(data, glob[CLOCK_GOT]) != 'clock_gettime':
        raise ValueError('clock_gettime GOT entry changed')
    if rip(data, (0x5c842ed, 'ff1555cf8500')) != CLOCK_GOT:
        raise ValueError('clock call changed')
    for got, symbol in ((MEMCMP_GOT, 'memcmp'), (MEMCPY_GOT, 'memcpy')):
        if got not in glob or dynamic_symbol(data, glob[got]) != symbol:
            raise ValueError(f'{symbol} GOT entry changed')
    for pin in BTREE:
        pinned(data, pin)
    if rip(data, BTREE[2]) != MEMCMP_GOT:
        raise ValueError('key comparison no longer calls memcmp')
    if read_va(data, TEMPLATE, 16)[1] != bytes.fromhex('0d6275636b65745f67756172642fc000'):
        raise ValueError('bucket_guard/{} template changed')

    getters = []
    for g, fde, disp_lea, thunk, tmpl_lea, fmt_call, ctor_call, pins in GETTERS:
        if frame(fdes, g) != fde:
            raise ValueError(f'FDE of getter {g:#x} changed')
        for pin in pins:
            pinned(data, pin)
        if rip(data, (disp_lea, read_va(data, disp_lea, 7)[1].hex())) != thunk:
            raise ValueError(f'display lea at {disp_lea:#x} changed')
        raw = read_va(data, thunk, 19)[1]
        if raw[:13] != bytes.fromhex('4889f0488b37488b57084889c7') or raw[13:15] != b'\xff\x25':
            raise ValueError(f'display thunk {thunk:#x} changed')
        if thunk + 19 + struct.unpack_from('<i', raw, 15)[0] != PAD_SLOT:
            raise ValueError(f'display thunk {thunk:#x} no longer jumps through the pad slot')
        if bytes.fromhex(read_va(data, tmpl_lea, 3)[1].hex()) != b'\x48\x8d\x35' or \
                rip(data, (tmpl_lea, read_va(data, tmpl_lea, 7)[1].hex())) != TEMPLATE:
            raise ValueError(f'template lea at {tmpl_lea:#x} changed')
        copy = pins[-1][0] + 5
        for call, slot in ((fmt_call, FORMAT_SLOT), (ctor_call, CTOR_SLOT), (copy, MEMCPY_GOT)):
            raw = read_va(data, call, 6)[1]
            if raw[:2] != b'\xff\x15' or rip(data, (call, raw.hex())) != slot:
                raise ValueError(f'slot call at {call:#x} changed')
        getters.append({'getter': hex(g), 'display': hex(thunk), 'format_call': hex(fmt_call),
                        'constructor_call': hex(ctor_call)})

    wrappers = sorted({row[1] for row in WRAPPER_CALLERS} | {0x422c960})
    census = direct_calls(data, set(GETTER_CALLS) | set(wrappers) | {HOP})
    for g, n in GETTER_CALLS.items():
        if len(census[g]) != n:
            raise ValueError(f'getter {g:#x} call census changed')
    expected = sorted([row[0] for row in STATIC_SITES] + [row[0] for row in WRAPPER_SITES])
    if sorted(v for g in GETTER_CALLS for v in census[g]) != expected:
        raise ValueError('getter call sites changed')

    def common(call, getter, fde, lock, closure):
        if frame(fdes, call) != fde:
            raise ValueError(f'FDE of {call:#x} changed')
        if call_target(data, call) != getter:
            raise ValueError(f'call at {call:#x} changed')
        if rip(data, lock) != GLOBAL_SLOT:
            raise ValueError(f'global load at {lock[0]:#x} changed')
        rsi, capture, source = (pinned(data, p) for p in closure)
        if rsi[:3] != b'\x48\x8d\x74' and rsi[:3] != b'\x48\x8d\xb4':
            raise ValueError(f'closure lea at {closure[0][0]:#x} changed')
        if rsp_disp(capture) != rsp_disp(rsi):
            raise ValueError(f'name capture at {closure[1][0]:#x} is not the closure start')
        clocks = clock_calls(data, fde)
        if clocks < 2:
            raise ValueError(f'fewer than two clock reads in {fde[0]:#x}')
        return {'call': hex(call), 'getter': hex(getter), 'function': hex(fde[0]), 'global_load': hex(lock[0]),
                'closure': hex(rsp_disp(rsi)), 'clock_reads': clocks, 'record_call': hex(record_follows(data, call))}

    sites = []
    for call, getter, fde, lock, closure, lea, length, name, pair_lea, pair_store, ptr in STATIC_SITES:
        row = common(call, getter, fde, lock, closure)
        info = name_struct(data, lea, length, ptr, pair_lea, pair_store, name)
        if rsp_disp(pinned(data, closure[2])) != int(info['struct'], 16):
            raise ValueError(f'closure at {call:#x} does not capture the name struct')
        row.update(kind='static', **info)
        sites.append(row)

    callers = collections.defaultdict(list)
    for call, wrapper, reg, arg_pins, lea, length, name, pair_lea, pair_store, ptr in WRAPPER_CALLERS:
        if call_target(data, call) != wrapper:
            raise ValueError(f'wrapper call at {call:#x} changed')
        info = name_struct(data, lea, length, ptr, pair_lea, pair_store, name)
        if rsp_disp(pinned(data, arg_pins[-1])) != int(info['struct'], 16):
            raise ValueError(f'argument at {call:#x} does not point at the name struct')
        for pin in arg_pins:
            pinned(data, pin)
        callers[wrapper].append({'call': hex(call), 'argument': reg, **info})

    for pin in HOP_BODY + HOP_PAIR:
        pinned(data, pin)
    if call_target(data, 0x3673b63) != 0x422c960 or frame(fdes, 0x3673b63)[0] != HOP:
        raise ValueError('median_risk_free_rate hop changed')
    hop_pair = struct.unpack('<2d', read_va(data, rip(data, HOP_PAIR[0]), 16)[1])
    hop_rows = []
    for call, lea, length in HOP_CALLERS:
        if call_target(data, call) != HOP:
            raise ValueError(f'hop call at {call:#x} changed')
        text_va = rip(data, lea)
        n = struct.unpack_from('<I', pinned(data, length), 4)[0]
        if read_va(data, text_va, n)[1].decode() != HOP_NAME:
            raise ValueError(f'hop name at {call:#x} changed')
        hop_rows.append({'call': hex(call), 'string': hex(text_va), 'length': n})
    if sorted(census[HOP]) != [row[0] for row in HOP_CALLERS]:
        raise ValueError('hop caller census changed')
    callers[0x422c960].append({'call': '0x3673b63', 'argument': 'rdi', 'name': HOP_NAME, 'struct': '0x58',
                               'pair': list(hop_pair), 'passed_from': hop_rows})

    for w in wrappers:
        if sorted(int(c['call'], 16) for c in callers[w]) != sorted(census[w]):
            raise ValueError(f'wrapper {w:#x} caller census changed')

    for call, getter, fde, lock, closure in WRAPPER_SITES:
        row = common(call, getter, fde, lock, closure)
        row.update(kind='wrapper', wrapper_callers=sorted(callers[fde[0]], key=lambda c: c['call']))
        row['names'] = sorted({c['name'] for c in callers[fde[0]]})
        sites.append(row)
    sites.sort(key=lambda r: int(r['call'], 16))

    names = collections.Counter()
    for row in sites:
        for n in ([row['name']] if row['kind'] == 'static' else row['names']):
            names[n] += 1
    pairs = collections.Counter()
    for row in sites:
        if row['kind'] == 'static':
            pairs[json.dumps(row['pair'])] += 1
        for c in row.get('wrapper_callers', ()):
            pairs[json.dumps(c['pair'])] += 1
    return {
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'template': {'va': hex(TEMPLATE), 'text': 'bucket_guard/{}'},
        'global': {'slot': hex(GLOBAL_SLOT), 'address': hex(GLOBAL), 'section': '.data'},
        'clock': {'now': hex(NOW), 'got': hex(CLOCK_GOT), 'symbol': 'clock_gettime', 'clock_id': 1},
        'getters': getters,
        'key_search': {'site': '0x2bdf7e9', 'keys': '0x1a28', 'key_stride': '0x18', 'length_u16': '0x1b32',
                       'edges': '0x1b38', 'compare': 'memcmp'},
        'calls': {hex(g): len(census[g]) for g in sorted(GETTER_CALLS)},
        'by_kind': dict(sorted(collections.Counter(r['kind'] for r in sites).items())),
        'names': dict(sorted(names.items())),
        'distinct_names': len(names),
        'pairs': dict(sorted(pairs.items())),
        'wrapper_callers': sum(len(v) for v in callers.values()),
        'sites': sites,
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
    print(f"getter_calls={sum(result['calls'].values())} names={result['distinct_names']} "
          f"wrapper_callers={result['wrapper_callers']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
