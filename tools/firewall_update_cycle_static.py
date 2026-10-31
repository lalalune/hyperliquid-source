#!/usr/bin/env python3
"""Static node #94 firewall IP update cycle in `0x28f6960`, checked from authenticated bytes.

Question: `0x28f6960` runs the sections `firewall_ips_maybe_update`,
`check_computed_ips` and `update_computed_ips`. Which of them run on a given
call, what decides whether the computed IPs are stored, and what happens when
a section is slow? The can1357 lead (`node/firewall_ips.rs`,
`firewall_ips_maybe_update`) returns early for non-validators, logs a
firewall mismatch and stops, and otherwise stores the computed set when it
differs from the cache. Where does the binary differ?

Only the Python standard library is used. Every fact is an exact byte window
at a fixed VA inside a parsed .eh_frame FDE; call, branch and RIP-relative
targets, the f64 slow threshold, section names, a Location and RELATIVE slots
are decoded here. A byte scan of the whole `0x28f6960` FDE shows that it has
no call to the log emitter or to the mismatch logger. Nothing from the binary
is executed.
"""
import argparse
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from artifacts import ROOT, check  # noqa: E402
from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

TARGET = 'artifacts/node/94/hl-node'
CYCLE_FDE = 0x28f6960
MAYBE_FDE = 0x27dc3f0
CHECK_FDE = 0x27cdf00
UPDATE_FDE = 0x27d6460
SET_EQ = 0x28a6f50
MAP_EQ = 0x28a73c0
LAZY_INIT = 0x143ea60
LOADER = 0x28f52d0
LOG_EMIT_SLOT = 0x576e978
LOG_EMIT = 0x143d010
MISMATCH_LOG = 0x4b28ff0

WINDOWS = {
    'entry': (CYCLE_FDE, 0x28f6960,
        '554157415641554154534881ec680400004989f74889fdbf01000000e87fce5e0248894424688954240c80bd60020000'
        '01750ac644242b00e9b20300008b857102000089442420660f108561020000660f29442410488dbc2418030000ff15dd'
        '7ee7028b858002000085c00f8488000000f20f108578020000f20f11442460488b8d840200008b942420030000899424'
        'd0010000488b94241803000048899424c80100008944247048894c247448b8010000001c000000488984248000000048'
        '8d05470592fd488984248800000048c784249000000030000000488dbc24c8010000488d742470ff15737ee702660f2e'
        '4424600f86d5000000488d85800200008b8c2420030000894808488b8c2418030000488908488bb598020000488d5610'
        '440fb68ee00500004883c638488d0ddcffaffd488d7c247041b819000000e84d59eefff20f10442470f20f5844247841'
        'b401660f2e05fe3f91fd7675488b1d657ee7028b435085c00f85fe0600000fb6434883f81f775ab900603c800fa3c173'
        '508b05b140e80285c07446488d058e40e80248898424c8010000488d8424c80100004889442470488d3d8a40e802488d'
        '0d5334d7024c8d053434d702488d542470be01000000ff158c7de702eb034531e4'),
    'sections': (CYCLE_FDE, 0x28f6b31,
        '450fb6b7f2080000498d97f80800008b442420898424d9010000660f28442410660f118424c9010000c68424c8010000'
        '014c8d6c2470488d8c24c80100004c89ef4489f6ff15cdcfe702488b8d980200004883c110450fb6c44c8da424c80100'
        '004c89e74c89ee4489f2ff15afcfe702488bb590020000488d56100fb686c80500004881c6d80200008904244c8d05c4'
        'feaffd488d7c247041b9120000004c89e1e82973edfff20f10442470f20f58442478440fb6b42480000000660f2e05c4'
        '3e91fd7633488b1d2b7de7028b435085c00f85420500000fb6434883f81f7718b900603c800fa3c1730e8b05773fe802'
        '85c00f855d0500004584f60f84dd000000488bbd90020000488b84240802000048898424b0000000660f108424c80100'
        '00660f108c24d8010000660f109424e80100000f109c24f80100000f299c24a0000000660f29942490000000660f298c'
        '2480000000660f29442470488d7710440fb68fc80500004883c738488d0df7fdaffd488d54247041b813000000e8adf7'
        'edfff20f58c8660f2e0df93d91fd7633488b1d607ce7028b435085c00f85420500000fb6434883f81f7718b900603c80'
        '0fa3c1730e8b05ac3ee80285c00f856a0500008b4424208944243c660f28442410660f1144242cc644242b01eb408b44'
        '24208944243c660f28442410660f1144242cc644242b01488dbc24c8010000e8cba1fbff488dbc24e0010000e83e5efb'
        'ff488dbc24f8010000e8315efbff660f1085d0020000660f1144247848c744247001000000488dbc2418030000488d54'
        '2470488d4c242b4c89fee850e5ffff'),
    'lazy_paths': (CYCLE_FDE, 0x28f714a,
        '48899c2418030000488d8424180300004889442470488d7b50488d0da640d8024c8d05c740d802488d542470be010000'
        '00ff153777e702e982faffff488d05f339e8024889842418030000488d8424180300004889442470488d3def39e80248'
        '8d0db82dd7024c8d05992dd702488d542470be01000000ff15f176e702e95dfaffff48899c24c8010000488d8424c801'
        '00004889442470488d7b50488d0d2440d8024c8d054540d802488d542470be01000000ff15b576e7020fb6434883f81f'
        '0f86c7f8ffffe91cf9ffff48899c2418030000488d8424180300004889442470488d7b50488d0ddb3fd8024c8d05fc3f'
        'd802488d542470be01000000ff156c76e7020fb6434883f81f0f8683faffffe996faffff488d051b39e8024889842418'
        '030000488d8424180300004889442470488d3d1739e802488d0de02cd7024c8d05c12cd702488d542470be01000000ff'
        '151976e702e950faffff'),
    'maybe_lock': (MAYBE_FDE, 0x27dc3f0,
        '554157415641554154534883ec7844894c241c4989d74889fbbf01000000e8ed7370024889c54189d6498d8768050000'
        '48890424b90800000031c0f0490fb18f680500000f8555010000bf01000000e8bc7370024989c44189d5488944242089'
        '54242848896c24304489742438488d7c2440488d742420488d542430e8bf7270020f284424400f294424608b6c245049'
        '81c770050000488d35231cee024c89ffe8bb12a5ff4189c731c9b808000000488b3c24f0480fb10f0f85f5000000'),
    'maybe_sleep': (MAYBE_FDE, 0x27dc4ea, '807c241c007415bf32000000660f7f2424ff15f723f902'),
    'check_section': (CHECK_FDE, 0x27cdf00,
        '554157415641554154534883ec684989cd4989d648897c2448bf01000000e8dd5871024889c589d34d8dbe6805000049'
        '8b866805000089c183e108c1e9034883f8f00f93c208ca74124c89ff31f6b900ca9a3bff158f16fa02eb0b488d4810f0'
        '490fb10f75e34c893c24bf01000000e88c5871024989c74189d448894424108954241848896c2420895c2428488d7c24'
        '30488d742410488d542420e8905771020f284424300f294424508b5c2440498dbe700500004c89eee803940d0040b501'
        '84c07430498dbe88050000498d7518e87c8f0d0084c0741c4981c6a00500004983c5304c89f74c89eee8628f0d0089c5'
        '4080f50148c7c0f0ffffff488b3c24f0480fc107440fb6b424a00000004883e0f24883f8120f84e1000000bf01000000'
        'e8db5771024889442410895424184c897c24204489642428488d7c2430488d742410488d542420e8e4567102660f6f64'
        '2430448b7c24404584f67415bf32000000660f7f2424ff158c08fa02660f6f2424660f6f5c2450660f6fc3660f6cc466'
        '0f70c0a0660f72f01f660f72e01f66410f6ecf660f6ed3660f62d1f30fe6ca660f6ddc660f6f1575afa3fd660fdbd366'
        '0feb152996a3fd660f73d320660feb1d5c6ba3fd660f5c1d646ba3fd660f58da660f5e0dd871a3fd660f58cb660fdfc1'
        '488b442448f30f7f00408868104883c4685b415c415d415e415f5dc3'),
    'update_lock': (UPDATE_FDE, 0x27d6460,
        '554157415641554154534883ec7844894c241c4889d34989f7bf01000000e87dd370024989c689d5498d876805000048'
        '890424b90800000031c0f0490fb18f680500000f8587010000bf01000000'),
    'set_eq': (SET_EQ, 0x28a6f50, '5541574156415453488b4f10483b4e100f8515040000'),
    'set_eq_false': (SET_EQ, 0x28a737b, '31c05b415c415e415f5dc3'),
    'map_eq': (MAP_EQ, 0x28a73c0,
        '5541574156415453488b4f10483b4e100f854c0400004c8b374d85f60f95c00f94c24885c9410f94c04108d00f853404'
        '0000'),
    'map_eq_result': (MAP_EQ, 0x28a7822, '31c0eb02b0015b415c415e415f5dc3'),
    'lazy_init': (LAZY_INIT, 0x143ea60,
        '534883ec20488b07488b1848c700000000004885db7424807e0401742b488d7c2408ff13488b442418488943100f1044'
        '24080f11034883c4205bc3'),
}

# name: (va, hex) -- every entry must sit inside a checked window.
FACTS = {
    'self_arg': (0x28f6974, '4889fd'),  # mov    rbp,rdi
    'state_arg': (0x28f6971, '4989f7'),  # mov    r15,rsi
    'skip_test': (0x28f698a, '80bd6002000001'),  # cmp    BYTE PTR [rbp+0x260],0x1
    'skip_flag_store': (0x28f6993, 'c644242b00'),  # mov    BYTE PTR [rsp+0x2b],0x0
    'payload_hi': (0x28f699d, '8b8571020000'),  # mov    eax,DWORD PTR [rbp+0x271]
    'payload_lo': (0x28f69a7, '660f108561020000'),  # movupd xmm0,XMMWORD PTR [rbp+0x261]
    'last_date': (0x28f69c3, '8b8580020000'),  # mov    eax,DWORD PTR [rbp+0x280]
    'last_test': (0x28f69c9, '85c0'),  # test   eax,eax
    'interval': (0x28f69d1, 'f20f108578020000'),  # movsd  xmm0,QWORD PTR [rbp+0x278]
    'interval_store': (0x28f69d9, 'f20f11442460'),  # movsd  QWORD PTR [rsp+0x60],xmm0
    'last_rest': (0x28f69df, '488b8d84020000'),  # mov    rcx,QWORD PTR [rbp+0x284]
    'cmp_interval': (0x28f6a4d, '660f2e442460'),  # ucomisd xmm0,QWORD PTR [rsp+0x60]
    'store_base': (0x28f6a59, '488d8580020000'),  # lea    rax,[rbp+0x280]
    'store_hi': (0x28f6a67, '894808'),  # mov    DWORD PTR [rax+0x8],ecx
    'store_lo': (0x28f6a72, '488908'),  # mov    QWORD PTR [rax],rcx
    'maybe_base': (0x28f6a75, '488bb598020000'),  # mov    rsi,QWORD PTR [rbp+0x298]
    'maybe_lock_arg': (0x28f6a7c, '488d5610'),  # lea    rdx,[rsi+0x10]
    'maybe_sleep_flag': (0x28f6a80, '440fb68ee0050000'),  # movzx  r9d,BYTE PTR [rsi+0x5e0]
    'maybe_name_arg': (0x28f6a88, '4883c638'),  # add    rsi,0x38
    'maybe_name_len': (0x28f6a98, '41b819000000'),  # mov    r8d,0x19
    'maybe_wait': (0x28f6aa3, 'f20f10442470'),  # movsd  xmm0,QWORD PTR [rsp+0x70]
    'maybe_sum': (0x28f6aa9, 'f20f58442478'),  # addsd  xmm0,QWORD PTR [rsp+0x78]
    'ran_set': (0x28f6aaf, '41b401'),  # mov    r12b,0x1
    'level_byte': (0x28f6ace, '0fb64348'),  # movzx  eax,BYTE PTR [rbx+0x48]
    'level_bound': (0x28f6ad2, '83f81f'),  # cmp    eax,0x1f
    'level_mask': (0x28f6ad7, 'b900603c80'),  # mov    ecx,0x803c6000
    'ran_clear': (0x28f6b2e, '4531e4'),  # xor    r12d,r12d
    'abci_flag': (0x28f6b31, '450fb6b7f2080000'),  # movzx  r14d,BYTE PTR [r15+0x8f2]
    'abci_state': (0x28f6b39, '498d97f8080000'),  # lea    rdx,[r15+0x8f8]
    'abci_tag': (0x28f6b5a, 'c68424c801000001'),  # mov    BYTE PTR [rsp+0x1c8],0x1
    'compute_base': (0x28f6b7b, '488b8d98020000'),  # mov    rcx,QWORD PTR [rbp+0x298]
    'compute_base_off': (0x28f6b82, '4883c110'),  # add    rcx,0x10
    'compute_ran': (0x28f6b86, '450fb6c4'),  # movzx  r8d,r12b
    'compute_out': (0x28f6b8a, '4c8da424c8010000'),  # lea    r12,[rsp+0x1c8]
    'check_base': (0x28f6ba1, '488bb590020000'),  # mov    rsi,QWORD PTR [rbp+0x290]
    'check_lock_arg': (0x28f6ba8, '488d5610'),  # lea    rdx,[rsi+0x10]
    'check_sleep_flag': (0x28f6bac, '0fb686c8050000'),  # movzx  eax,BYTE PTR [rsi+0x5c8]
    'check_name_len': (0x28f6bc9, '41b912000000'),  # mov    r9d,0x12
    'check_value': (0x28f6bcf, '4c89e1'),  # mov    rcx,r12
    'changed': (0x28f6be3, '440fb6b42480000000'),  # movzx  r14d,BYTE PTR [rsp+0x80]
    'check_sum': (0x28f6bdd, 'f20f58442478'),  # addsd  xmm0,QWORD PTR [rsp+0x78]
    'changed_test': (0x28f6c29, '4584f6'),  # test   r14b,r14b
    'update_base': (0x28f6c32, '488bbd90020000'),  # mov    rdi,QWORD PTR [rbp+0x290]
    'update_lock_arg': (0x28f6c8c, '488d7710'),  # lea    rsi,[rdi+0x10]
    'update_sleep_flag': (0x28f6c90, '440fb68fc8050000'),  # movzx  r9d,BYTE PTR [rdi+0x5c8]
    'update_name_len': (0x28f6ca8, '41b813000000'),  # mov    r8d,0x13
    'update_sum': (0x28f6cb3, 'f20f58c8'),  # addsd  xmm1,xmm0
    'flag_store_a': (0x28f6d08, 'c644242b01'),  # mov    BYTE PTR [rsp+0x2b],0x1
    'flag_store_b': (0x28f6d23, 'c644242b01'),  # mov    BYTE PTR [rsp+0x2b],0x1
    'loader_flag': (0x28f6d73, '488d4c242b'),  # lea    rcx,[rsp+0x2b]
    'loader_state': (0x28f6d78, '4c89fe'),  # mov    rsi,r15
    'mw_sleep_store': (0x27dc3fe, '44894c241c'),  # mov    DWORD PTR [rsp+0x1c],r9d
    'mw_lock_addr': (0x27dc419, '498d8768050000'),  # lea    rax,[r15+0x568]
    'mw_lock_val': (0x27dc424, 'b908000000'),  # mov    ecx,0x8
    'mw_lock': (0x27dc42b, 'f0490fb18f68050000'),  # lock cmpxchg QWORD PTR [r15+0x568],rcx
    'mw_data': (0x27dc47f, '4981c770050000'),  # add    r15,0x570
    'mw_unlock': (0x27dc4a3, 'f0480fb10f'),  # lock cmpxchg QWORD PTR [rdi],rcx
    'mw_sleep_test': (0x27dc4ea, '807c241c00'),  # cmp    BYTE PTR [rsp+0x1c],0x0
    'mw_sleep_ms': (0x27dc4f1, 'bf32000000'),  # mov    edi,0x32
    'ck_lock_addr': (0x27cdf28, '4d8dbe68050000'),  # lea    r15,[r14+0x568]
    'ck_read_inc': (0x27cdf5b, '488d4810'),  # lea    rcx,[rax+0x10]
    'ck_read_lock': (0x27cdf5f, 'f0490fb10f'),  # lock cmpxchg QWORD PTR [r15],rcx
    'ck_map': (0x27cdfae, '498dbe70050000'),  # lea    rdi,[r14+0x570]
    'ck_value_arg': (0x27cdfb5, '4c89ee'),  # mov    rsi,r13
    'ck_changed_default': (0x27cdfbd, '40b501'),  # mov    bpl,0x1
    'ck_set1': (0x27cdfc4, '498dbe88050000'),  # lea    rdi,[r14+0x588]
    'ck_set1_value': (0x27cdfcb, '498d7518'),  # lea    rsi,[r13+0x18]
    'ck_set2': (0x27cdfd8, '4981c6a0050000'),  # add    r14,0x5a0
    'ck_set2_value': (0x27cdfdf, '4983c530'),  # add    r13,0x30
    'ck_last_not': (0x27cdff0, '4080f501'),  # xor    bpl,0x1
    'ck_unlock_val': (0x27cdff4, '48c7c0f0ffffff'),  # mov    rax,0xfffffffffffffff0
    'ck_unlock': (0x27cdfff, 'f0480fc107'),  # lock xadd QWORD PTR [rdi],rax
    'ck_sleep_flag': (0x27ce004, '440fb6b424a0000000'),  # movzx  r14d,BYTE PTR [rsp+0xa0]
    'ck_sleep_ms': (0x27ce05c, 'bf32000000'),  # mov    edi,0x32
    'ck_out_changed': (0x27ce0e9, '40886810'),  # mov    BYTE PTR [rax+0x10],bpl
    'up_lock_addr': (0x27d6488, '498d8768050000'),  # lea    rax,[r15+0x568]
    'up_lock_val': (0x27d6493, 'b908000000'),  # mov    ecx,0x8
    'up_lock': (0x27d649a, 'f0490fb18f68050000'),  # lock cmpxchg QWORD PTR [r15+0x568],rcx
    'set_len': (0x28a6f58, '488b4f10'),  # mov    rcx,QWORD PTR [rdi+0x10]
    'set_len_cmp': (0x28a6f5c, '483b4e10'),  # cmp    rcx,QWORD PTR [rsi+0x10]
    'set_false': (0x28a737b, '31c0'),  # xor    eax,eax
    'map_len': (0x28a73c8, '488b4f10'),  # mov    rcx,QWORD PTR [rdi+0x10]
    'map_len_cmp': (0x28a73cc, '483b4e10'),  # cmp    rcx,QWORD PTR [rsi+0x10]
    'map_false': (0x28a7822, '31c0'),  # xor    eax,eax
    'map_true': (0x28a7826, 'b001'),  # mov    al,0x1
    'lazy_take': (0x143ea6b, '48c70000000000'),  # mov    QWORD PTR [rax],0x0
    'lazy_call': (0x143ea82, 'ff13'),  # call   QWORD PTR [rbx]
    'lazy_store': (0x143ea92, '0f1103'),  # movups XMMWORD PTR [rbx],xmm0
    'ck_value_reg': (0x27cdf0e, '4989cd'),  # mov    r13,rcx
    'ck_base_reg': (0x27cdf11, '4989d6'),  # mov    r14,rdx
    'mw_base_reg': (0x27dc403, '4989d7'),  # mov    r15,rdx
    'up_base_reg': (0x27d6476, '4989f7'),  # mov    r15,rsi
}

# name: (va, instruction length, target)
FLOW = {
    'skip_branch': (0x28f6991, 2, 0x28f699d),
    'skip_jump': (0x28f6998, 5, 0x28f6d4f),
    'no_last': (0x28f69cb, 6, 0x28f6a59),
    'throttled': (0x28f6a53, 6, 0x28f6b2e),
    'maybe_call': (0x28f6a9e, 5, 0x27dc3f0),
    'maybe_fast': (0x28f6aba, 2, 0x28f6b31),
    'level_high_a': (0x28f6ad5, 2, 0x28f6b31),
    'level_clear_a': (0x28f6adf, 2, 0x28f6b31),
    'lazy_done_a': (0x28f6ae9, 2, 0x28f6b31),
    'lazy_back_a': (0x28f6b2c, 2, 0x28f6b31),
    'check_call': (0x28f6bd2, 5, 0x27cdf00),
    'check_fast': (0x28f6bf4, 2, 0x28f6c29),
    'lazy_init_b': (0x28f6c23, 6, 0x28f7186),
    'unchanged': (0x28f6c2c, 6, 0x28f6d0f),
    'update_call': (0x28f6cae, 5, 0x27d6460),
    'update_fast': (0x28f6cbf, 2, 0x28f6cf4),
    'lazy_init_c': (0x28f6cee, 6, 0x28f725e),
    'to_loader': (0x28f6d0d, 2, 0x28f6d4f),
    'drop_value': (0x28f6d30, 5, 0x28b0f00),
    'loader_call': (0x28f6d7b, 5, 0x28f52d0),
    'lazy_back_b': (0x28f71c7, 5, 0x28f6c29),
    'lazy_back_c': (0x28f729f, 5, 0x28f6cf4),
    'mw_closure': (0x27dc490, 5, 0x222d750),
    'ck_map_eq': (0x27cdfb8, 5, 0x28a73c0),
    'ck_map_ne': (0x27cdfc2, 2, 0x27cdff4),
    'ck_set1_eq': (0x27cdfcf, 5, 0x28a6f50),
    'ck_set1_ne': (0x27cdfd6, 2, 0x27cdff4),
    'ck_set2_eq': (0x27cdfe9, 5, 0x28a6f50),
    'set_len_ne': (0x28a6f60, 6, 0x28a737b),
    'map_len_ne': (0x28a73d0, 6, 0x28a7822),
    'map_empty': (0x28a73ec, 6, 0x28a7826),
}

RIP = {
    'now_slot': (0x28f69bd, 6, 0x576e8a0),
    'elapsed_slot': (0x28f6a47, 6, 0x576e8c0),
    'raw_mdg_path': (0x28f6a1f, 7, 0x216f6d),
    'maybe_name': (0x28f6a8c, 7, 0x3f6a6f),
    'slow_a': (0x28f6ab2, 8, 0x20aab8),
    'level_slot': (0x28f6abc, 7, 0x576e928),
    'lazy_state': (0x28f6ae1, 6, 0x577ab98),
    'lazy_value': (0x28f6aeb, 7, 0x577ab80),
    'lazy_vtable': (0x28f6b0e, 7, 0x5669f68),
    'lazy_location': (0x28f6b15, 7, 0x5669f50),
    'once_slot': (0x28f6b26, 6, 0x576e8b8),
    'abci_slot': (0x28f6b75, 6, 0x5773b48),
    'compute_slot': (0x28f6b9b, 6, 0x5773b50),
    'check_name': (0x28f6bbd, 7, 0x3f6a88),
    'slow_b': (0x28f6bec, 8, 0x20aab8),
    'update_name': (0x28f6c9c, 7, 0x3f6a9a),
    'slow_c': (0x28f6cb7, 8, 0x20aab8),
    'mw_sleep': (0x27dc4fb, 6, 0x576e8f8),
    'ck_sleep': (0x27ce066, 6, 0x576e8f8),
}
SLOTS = {'now_slot': 0x151cba0, 'elapsed_slot': 0x1447130, 'level_slot': 0x577b288, 'once_slot': 0x4ee3b20,
         'abci_slot': 0x45c3d20, 'compute_slot': 0x45c42b0, 'mw_sleep': 0x13c9e20, 'ck_sleep': 0x13c9e20}
NAMES = {'maybe_name': ('maybe_name_len', 'firewall_ips_maybe_update'),
         'check_name': ('check_name_len', 'check_computed_ips'),
         'update_name': ('update_name_len', 'update_computed_ips')}


class EvidenceError(RuntimeError):
    pass


def require(ok, message):
    if not ok:
        raise EvidenceError(message)


class Image:
    def __init__(self, data):
        self.data = data
        self.secs = sections(data)
        rela = next((s for s in self.secs if s['name'] == '.rela.dyn' and s['type'] == 4), None)
        require(rela is not None and rela['size'] % 24 == 0, 'no well-formed .rela.dyn')
        self.relative = {}
        for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
            where, info, addend = struct.unpack_from('<QQq', data, pos)
            if info & 0xffffffff == 8:
                self.relative[where] = addend
        _, fdes = eh_frame_records(data, self.secs)
        self.fdes = sorted((f['start'], f['end']) for f in fdes)

    def offset(self, va, size=1):
        hits = [s for s in self.secs if s['type'] != 8 and s['address'] and
                s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(hits) == 1, f'VA {va:#x}+{size} is not in exactly one file-backed section')
        return hits[0]['offset'] + va - hits[0]['address']

    def read(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off + size]

    def fde(self, start):
        hits = [f for f in self.fdes if f[0] == start]
        require(len(hits) == 1, f'{start:#x} is not exactly one FDE start')
        return hits[0]

    def target(self, va, length):
        if length == 2:
            return va + 2 + struct.unpack('<b', self.read(va + 1, 1))[0]
        return va + length + struct.unpack('<i', self.read(va + length - 4, 4))[0]

    def f64(self, va):
        return struct.unpack('<d', self.read(va, 8))[0]


def windows(img):
    out = {}
    for name, (fde, va, hexs) in WINDOWS.items():
        raw = bytes.fromhex(hexs)
        start, end = img.fde(fde)
        require(start <= va and va + len(raw) <= end, f'{name} window {va:#x} is outside FDE {fde:#x}')
        require(img.read(va, len(raw)) == raw, f'{name} at {va:#x}: bytes changed')
        out[name] = va
    return out


def windowed(va, size):
    return any(va >= w[1] and va + size <= w[1] + len(bytes.fromhex(w[2])) for w in WINDOWS.values())


def facts(img):
    out = {}
    for name, (va, hx) in FACTS.items():
        raw = bytes.fromhex(hx)
        require(windowed(va, len(raw)), f'fact {name} at {va:#x} is outside every window')
        require(img.read(va, len(raw)) == raw, f'fact {name} at {va:#x}: bytes changed')
        out[name] = raw
    return out


def check_flow(img):
    out = {}
    for name, (va, n, want) in {**FLOW, **RIP}.items():
        require(windowed(va, n), f'{name} at {va:#x} is outside every window')
        got = img.target(va, n)
        require(got == want, f'{name} at {va:#x} goes to {got:#x}')
        out[name] = hex(got)
    for name, want in SLOTS.items():
        got = img.relative.get(RIP[name][2])
        require(got == want, f'{name} resolves to {got}')
    return out


def location(img, va):
    ptr = img.relative.get(va)
    require(ptr is not None, f'Location {va:#x} has no RELATIVE file pointer')
    n, line, col = struct.unpack('<QII', img.read(va + 8, 16))
    require(0 < n < 256, f'Location {va:#x} has length {n}')
    path = img.read(ptr, n)
    require(all(0x20 <= c < 0x7f for c in path), f'Location {va:#x} path is not text')
    return f'{path.decode()}:{line}:{col}'


def disp32(raw, at):
    return struct.unpack('<I', raw[at:at + 4])[0]


def imm32(raw):
    return struct.unpack('<I', raw[-4:])[0]


def check_names(img, f):
    out = {}
    for rip, (length_fact, want) in NAMES.items():
        n = imm32(f[length_fact])
        got = img.read(RIP[rip][2], n).decode('ascii', 'replace')
        require(got == want, f'{rip} is {got!r}')
        out[rip.split('_')[0]] = got
    return out


def check_skip(f):
    require(f['self_arg'] == bytes.fromhex('4889fd') and f['state_arg'] == bytes.fromhex('4989f7'),
            'rbp/r15 are not rdi/rsi')
    require(disp32(f['skip_test'], 2) == 0x260 and f['skip_test'][-1] == 1, 'skip test is not [rbp+0x260] == 1')
    require(f['skip_flag_store'][-1] == 0 and f['flag_store_a'][-1] == f['flag_store_b'][-1] == 1,
            'loader flag stores changed')
    require(disp32(f['payload_lo'], 4) == 0x261 and disp32(f['payload_hi'], 2) == 0x271, '20-byte payload moved')
    return dict(test='[rbp+0x260] == 1', skips='all three sections', loader_flag='[rsp+0x2b] = 0 (1 otherwise)',
                payload='20 bytes at [rbp+0x261], passed to the abci builder with tag 1')


def check_throttle(img, f):
    require(disp32(f['last_date'], 2) == 0x280 and f['last_test'] == bytes.fromhex('85c0'), 'last test changed')
    require(disp32(f['interval'], 4) == 0x278 and disp32(f['last_rest'], 3) == 0x284, 'interval/last moved')
    require(f['interval_store'][-1] == f['cmp_interval'][-1] == 0x60, 'interval slot changed')
    require(disp32(f['store_base'], 3) == 0x280 and f['store_hi'][-1] == 8, 'now store changed')
    path = img.read(RIP['raw_mdg_path'][2], 0x30)
    require(path.endswith(b'/base/src/raw_mdg.rs'), f'elapsed path is {path!r}')
    require(f['ran_set'] == bytes.fromhex('41b401') and f['ran_clear'] == bytes.fromhex('4531e4'), 'ran flag changed')
    return dict(state='[rbp+0x278] f64 interval, [rbp+0x280] 12-byte wall time (dword 0 = never)',
                rule='never run, or elapsed > interval (ucomisd/jbe, NaN skips) -> store now, run the section',
                elapsed=hex(SLOTS['elapsed_slot']), ran_flag='r12b = 1 if the section ran, else 0; passed as r8 to '
                f"{SLOTS['compute_slot']:#x}")


def check_sections(img, f):
    require(disp32(f['maybe_base'], 3) == 0x298 and f['maybe_lock_arg'][-1] == 0x10
            and disp32(f['maybe_sleep_flag'], 4) == 0x5e0, 'maybe section arguments changed')
    require(disp32(f['check_base'], 3) == 0x290 and f['check_lock_arg'][-1] == 0x10
            and disp32(f['check_sleep_flag'], 3) == 0x5c8, 'check section arguments changed')
    require(disp32(f['update_base'], 3) == 0x290 and f['update_lock_arg'][-1] == 0x10
            and disp32(f['update_sleep_flag'], 4) == 0x5c8, 'update section arguments changed')
    require(disp32(f['compute_base'], 3) == 0x298 and f['compute_base_off'][-1] == 0x10
            and f['compute_ran'] == bytes.fromhex('450fb6c4'), 'compute arguments changed')
    require(disp32(f['compute_out'], 4) == 0x1c8 and f['check_value'] == bytes.fromhex('4c89e1'),
            'check does not get the computed value')
    require(disp32(f['abci_flag'], 4) == 0x8f2 and disp32(f['abci_state'], 3) == 0x8f8 and f['abci_tag'][-1] == 1,
            'abci builder arguments changed')
    require(disp32(f['changed'], 5) == 0x80 and f['changed_test'] == bytes.fromhex('4584f6'),
            'update is not gated by check output +0x10')
    for k in ('mw', 'up'):
        require(disp32(f[f'{k}_lock_addr'], 3) == 0x568 and imm32(f[f'{k}_lock_val']) == 8
                and disp32(f[f'{k}_lock'], 5) == 0x568, f'{k} write lock changed')
    require(f['mw_base_reg'] == bytes.fromhex('4989d7') and f['up_base_reg'] == bytes.fromhex('4989f7'),
            'lock base registers changed')
    require(disp32(f['mw_data'], 3) == 0x570, 'maybe closure data is not +0x570')
    require(f['mw_sleep_store'] == bytes.fromhex('44894c241c') and f['mw_sleep_test'] == bytes.fromhex('807c241c00')
            and imm32(f['mw_sleep_ms']) == 50, 'maybe sleep flag changed')
    return {'firewall_ips_maybe_update': dict(call=hex(MAYBE_FDE), base='[rbp+0x298] + 0x10',
                                              lock='write, +0x568 (0 -> 8)', closure='0x222d750(+0x570)',
                                              sleep='50 if byte [[rbp+0x298]+0x5e0]', runs='throttle passed'),
            'compute': dict(call=f"slot 0x5773b50 -> {SLOTS['compute_slot']:#x}",
                            args='abci set (slot 0x5773b48), byte [r15+0x8f2], [rbp+0x298]+0x10, ran flag',
                            out='[rsp+0x1c8], three 0x18-byte fields', runs='unless skipped'),
            'check_computed_ips': dict(call=hex(CHECK_FDE), base='[rbp+0x290] + 0x10', lock='read, +0x568 (+0x10)',
                                       runs='unless skipped', returns='{wait, hold, changed byte +0x10}'),
            'update_computed_ips': dict(call=hex(UPDATE_FDE), base='[rbp+0x290] + 0x10', lock='write, +0x568 (0 -> 8)',
                                        runs='changed != 0', otherwise='computed value dropped (0x28b0f00, 0x28acb80 x2)')}


def check_compare(f):
    require(f['ck_base_reg'] == bytes.fromhex('4989d6') and f['ck_value_reg'] == bytes.fromhex('4989cd'),
            'check registers changed')
    require(disp32(f['ck_lock_addr'], 3) == 0x568 and f['ck_read_inc'][-1] == 0x10, 'read lock changed')
    require(disp32(f['ck_map'], 3) == 0x570 and disp32(f['ck_set1'], 3) == 0x588 and disp32(f['ck_set2'], 3) == 0x5a0,
            'stored fields moved')
    require(f['ck_value_arg'] == bytes.fromhex('4c89ee') and f['ck_set1_value'][-1] == 0x18
            and f['ck_set2_value'][-1] == 0x30, 'computed fields moved')
    require(f['ck_changed_default'] == bytes.fromhex('40b501') and f['ck_last_not'] == bytes.fromhex('4080f501'),
            'changed computation changed')
    require(f['ck_unlock_val'] == bytes.fromhex('48c7c0f0ffffff') and f['ck_out_changed'][-1] == 0x10,
            'unlock or output changed')
    require(disp32(f['ck_sleep_flag'], 5) == 0xa0 and imm32(f['ck_sleep_ms']) == 50, 'check sleep flag changed')
    for k in ('set', 'map'):
        require(f[f'{k}_len'] == bytes.fromhex('488b4f10') and f[f'{k}_len_cmp'] == bytes.fromhex('483b4e10')
                and f[f'{k}_false'] == bytes.fromhex('31c0'), f'{k} equality does not start with a length test')
    require(f['map_true'] == bytes.fromhex('b001'), 'empty map is not equal')
    return dict(changed='not (map_eq(+0x570, v+0x0) and set_eq(+0x588, v+0x18) and set_eq(+0x5a0, v+0x30))',
                map_eq=hex(MAP_EQ), set_eq=hex(SET_EQ), equality='len differs -> false; both empty -> true (map)',
                short_circuit='a false comparison skips the rest (changed stays 1)')


def check_slow(img, f):
    slow = {img.f64(RIP[k][2]) for k in ('slow_a', 'slow_b', 'slow_c')}
    require(slow == {3.0}, f'slow threshold is {slow}')
    require(f['maybe_wait'][-1] == 0x70 and f['maybe_sum'][-1] == 0x78 and f['check_sum'][-1] == 0x78
            and f['update_sum'] == bytes.fromhex('f20f58c8'), 'section durations are not wait + hold')
    require(f['level_byte'][-1] == 0x48 and f['level_bound'][-1] == 0x1f, 'level gate changed')
    mask = imm32(f['level_mask'])
    require(mask == 0x803c6000, f'level mask is {mask:#x}')
    init = img.relative.get(RIP['lazy_vtable'][2] + 0x18)
    require(init == LAZY_INIT, f'lazy vtable call resolves to {init}')
    loc = location(img, RIP['lazy_location'][2])
    require(loc.endswith('library/std/src/sync/once.rs:219:20'), f'lazy Location is {loc}')
    require(f['lazy_take'] == bytes.fromhex('48c70000000000') and f['lazy_call'] == bytes.fromhex('ff13')
            and f['lazy_store'] == bytes.fromhex('0f1103'), 'lazy init body changed')
    return dict(threshold=3.0, measure='wait + hold of each section',
                when=f'> 3.0 and byte [{SLOTS["level_slot"]:#x}+0x48] in mask {mask:#x}',
                action=f'call_once (slot 0x576e8b8) on the lazy static {RIP["lazy_value"][2]:#x} if its state '
                       f'{RIP["lazy_state"][2]:#x} is not 0; init {LAZY_INIT:#x} takes the init fn, calls it, stores 24 bytes',
                location=loc, then='continues with the next step; nothing else on this path')


def check_no_log(img):
    start, end = img.fde(CYCLE_FDE)
    code = img.read(start, end - start)
    hits = []
    for i in range(len(code) - 5):
        if code[i] == 0xe8 and start + i + 5 + struct.unpack_from('<i', code, i + 1)[0] in (LOG_EMIT, MISMATCH_LOG):
            hits.append(start + i)
        if code[i:i + 2] == b'\xff\x15' and i + 6 <= len(code) and \
                start + i + 6 + struct.unpack_from('<i', code, i + 2)[0] == LOG_EMIT_SLOT:
            hits.append(start + i)
    require(not hits, f'log calls at {[hex(v) for v in hits]}')
    require(img.relative.get(LOG_EMIT_SLOT) == LOG_EMIT, 'log slot moved')
    return dict(fde=f'{start:#x}..{end:#x}', scanned=f'e8 to {LOG_EMIT:#x} or {MISMATCH_LOG:#x}; ff15 via {LOG_EMIT_SLOT:#x}',
                hits=[])


def changed(map_eq, set1_eq, set2_eq):
    return not (map_eq and set1_eq and set2_eq)


def cycle(skip, last_set=False, elapsed=0.0, interval=0.0, is_changed=False):
    """Which sections one call runs."""
    if skip:
        return dict(maybe_update=False, compute=False, check=False, update=False, loader_flag=0)
    ran = (not last_set) or elapsed > interval
    return dict(maybe_update=ran, compute=True, check=True, update=bool(is_changed), loader_flag=1)


def analyse(data):
    img = Image(data)
    win = windows(img)
    f = facts(img)
    return dict(target=TARGET, fde=hex(CYCLE_FDE), windows={k: hex(v) for k, v in win.items()},
                flow=check_flow(img), names=check_names(img, f), skip=check_skip(f),
                throttle=check_throttle(img, f), sections=check_sections(img, f), compare=check_compare(f),
                slow=check_slow(img, f), no_log=check_no_log(img),
                after=dict(loader=hex(LOADER), args='(out [rsp+0x318], r15, {1, [rbp+0x2d0], [rbp+0x2d8]}, &[rsp+0x2b])'))


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--json', action='store_true')
    a = p.parse_args(argv)
    identity = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                    if i['path'] == TARGET)
    path = ROOT / TARGET
    check(path, identity)
    result = dict(analyse(path.read_bytes()), target_sha256=identity['sha256'])
    if a.json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    print(f"skip: {result['skip']['test']} -> {result['skip']['skips']}")
    print(f"maybe_update: {result['throttle']['rule']}")
    print(f"update_computed_ips runs when {result['compare']['changed']}")
    print(f"slow (> {result['slow']['threshold']} s): lazy init only; log calls in FDE: {len(result['no_log']['hits'])}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
