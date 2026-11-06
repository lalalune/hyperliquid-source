#!/usr/bin/env python3
"""Pin the three remaining RE-006 gate edges of PR #2608.

Question (open edges 3, 4 and 5 of RE-006-node115-gate-callee,
carried unchanged through PR #2652 and PR #2698):

3. The branchless-select callers of the gate behind slot
   0x64e71b8: which running value does the gate's `rdx` result
   conditionally replace in each, and does a 0 return leave a
   stale value or a defined default?
4. The one register-supplied flag site (0x3698891 in FDE
   0x36961e0): where does its `r14b` come from -- when does that
   caller ask the gate for ceiling instead of floor?
5. The panic-formatting callee 0x1680e60 behind slot 0x64df730,
   shared by every unwrap stub of the gate's shape: what is it?

Method: the authenticated node-115 ELF is decoded with the
pinned objdump wrapper from foundation_millis (through
gate_callee_static's helpers).  Every address resolves through
the section table (.rodata identity-mapped, .text delta 0x1000,
.data.rel.ro delta 0x2000).  Slot references are resolved from
raw instruction bytes, never from objdump comments.  The gate
census of #2608 is re-derived here from a raw byte scan of
.text (a superset of every instruction-boundary reference) with
each candidate validated against the decoded rows of its
containing FDE, so the branchless subset and the flag-site
uniqueness are exact, not sampled.
"""
import bisect
import json
import re
import struct
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from artifacts import ROOT  # noqa: E402
from elf_index import sections  # noqa: E402
from gate_callee_static import (  # noqa: E402
    _ALIASES, _body_export, _decode, _digest, _direct_calls,
    _fde_index, _last_writer, _mem_reads, _raw_slot_scan,
    _rela_entries, _section_bytes, _slot_refs_all, _slot_resolution,
    _split_ops, _stores)

PACKET_DIR = ROOT / 'research' / 'work-items' / 'RE-006-node115-remaining-edges'
UPSTREAM_MAIN = '05bc2de303c05525b71e7e257426e741bc66a390'
NODE_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
NODE_SIZE = 105896032
EXPORT_MAX = 4096

GATE_SLOT = 0x64E71B8
GATE_BODY = 0x434F790
FMT_SLOT = 0x64DF730

# name -> (start, end, exported)
BODIES = {
    'sel_2bfb830': (0x2BFB830, 0x2BFBE1A, True),
    'sel_2bfbe20': (0x2BFBE20, 0x2BFC4D2, True),
    'sel_2bfd0c0': (0x2BFD0C0, 0x2BFD357, True),
    'sel_2c01920': (0x2C01920, 0x2C02DC9, False),
    'sel_2c32960': (0x2C32960, 0x2C3323D, True),
    'sel_2c36af0': (0x2C36AF0, 0x2C37EDB, False),
    'sel_3bfa270': (0x3BFA270, 0x3BFA338, True),
    'sel_4215360': (0x4215360, 0x42155FB, True),
    'sel_54e2920': (0x54E2920, 0x54E3026, True),
    'sel_54e3030': (0x54E3030, 0x54E3736, True),
    'sel_54e3740': (0x54E3740, 0x54E3EFC, True),
    'sel_54e3f00': (0x54E3F00, 0x54E46BC, True),
    'sel_54e5f90': (0x54E5F90, 0x54E624F, True),
    'sel_54e6250': (0x54E6250, 0x54E650F, True),
    'sel_54eeea0': (0x54EEEA0, 0x54EF0A9, True),
    'sel_54ef0b0': (0x54EF0B0, 0x54EF2B9, True),
    'sel_5575680': (0x5575680, 0x5575F5D, True),
    'sel_5575f60': (0x5575F60, 0x557683D, True),
    'sel_557df20': (0x557DF20, 0x557F2D3, False),
    'sel_557f2e0': (0x557F2E0, 0x55806D1, False),
    'flag_fde': (0x36961E0, 0x3698ED2, False),
    'panic_shim_len': (0x1680E60, 0x1680E72, True),
    'panic_shim_record': (0x1680E80, 0x1680EAC, True),
    'panic_shim_rewrap': (0x5C826C0, 0x5C826DD, True),
    'panic_shim_tail': (0x5C78380, 0x5C78389, True),
    'panic_consumer': (0x5C812D0, 0x5C8136A, True),
    'panic_formatter': (0x5C9B316, 0x5C9B4F2, False),
    'panic_hook': (0x635DE30, 0x635DED5, False),
    'flag_lookup': (0x4505030, 0x4505076, False),
    'flag_accessor': (0x3CC6670, 0x3CC6774, False),
}
CHAIN = ('panic_shim_len', 'panic_shim_record', 'panic_shim_rewrap',
         'panic_shim_tail', 'panic_consumer')
FLAG_FDE = (0x36961E0, 0x3698ED2)
FLAG_SITE = 0x3698891
PLT_ADDR = 0x63F0A50
PLT_SLOT = 0x64E2180


class PacketError(AssertionError):
    """The artifact does not authenticate against node 115."""


def _hx(value):
    return f'0x{value:x}'


def _norm(text):
    return ' '.join(text.split())


def _pins(mapping):
    return {int(a): tuple(v) for a, v in mapping.items()}


def _check_rows(rows, pins, what):
    for address, want in pins.items():
        if rows.get(address) != want:
            raise PacketError(
                f'{what} instruction at {address:#x} differs: '
                f'{rows.get(address)!r} != {want!r}')
    return rows


def _bindings(rows, call):
    regs = ('rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9')
    out = {}
    for reg in regs:
        w = _last_writer(rows, reg, call)
        out[reg] = w
    return out


def _flag_of(binding):
    if binding is None:
        return 'unknown'
    if binding.get('form') == 'imm':
        return binding.get('value')
    return 'register'


# === FROZEN DATA (injected) ===
FROZEN = {'bodies': {'flag_accessor': [63727216,
                              63727476,
                              '27d3c189b5117ed36d9a64cd5a6582a5469a32aad710933e1eba62b8eea780c0'],
            'flag_fde': [57237984,
                         57249490,
                         '1d6d91dfde0615441347f8c8a676e0c6e2d943fa1d26e17e64db41197a146dee'],
            'flag_lookup': [72372272,
                            72372342,
                            '3ac32c990899ad288054d6118cf80dbbf998885f105b05f1c1977343fd00e527'],
            'panic_consumer': [96998096,
                               96998250,
                               '3fca2663c162e38720359e497da92bdbfa107de21895d95c5ccd4bc1805b963e'],
            'panic_formatter': [97104662,
                                97105138,
                                'fadeb8e6d96fbfb6a5feaa7ffd0ade2bc367d2ad0847be1dc7e91ebe9668ba7b'],
            'panic_hook': [104193584,
                           104193749,
                           '714fc5cdd28a2587427c9dac8a25685ec09695a3a21bc9af0eb09b29ae503f61'],
            'panic_shim_len': [23596640,
                               23596658,
                               '2c4e17b271b60cd074de9b63a359b89c8f04f3c59e8c076b156618dc7fba2aee'],
            'panic_shim_record': [23596672,
                                  23596716,
                                  '28fc3434a04bb9e49d5a0164306a5c31abf6bce26425d99d27031ac1c9beb2e3'],
            'panic_shim_rewrap': [97003200,
                                  97003229,
                                  'ae57c1f06e3254ce7cd3518d42154be71831103b748b6f19f74cacc64c5fb766'],
            'panic_shim_tail': [96961408,
                                96961417,
                                '08fb6e72c15ea7e57ddd63674548e9d7d506e423939aececc347a07fc9e0330b'],
            'sel_2bfb830': [46118960,
                            46120474,
                            '2ebd20a20be37eef9a21fccf1767de03632df456d2b9fa8c45722c8a649bcfeb'],
            'sel_2bfbe20': [46120480,
                            46122194,
                            '066c01582b6f1688af0db1973da82af5abeedbe9aeefabf53aa41298fa37d8f9'],
            'sel_2bfd0c0': [46125248,
                            46125911,
                            '5762f41ade6d1f819df3de86b3796696c06ccf51938404b4f66ecf7402bc2894'],
            'sel_2c01920': [46143776,
                            46149065,
                            '27909acc5e83d0567ff22c4a9b454590f86ee32751b254f560b315b6fa9e57fd'],
            'sel_2c32960': [46344544,
                            46346813,
                            'b41372b433fcdd8f1dea0efe6ca533b0172b987c6fa6283bbecf138aa6a94ccf'],
            'sel_2c36af0': [46361328,
                            46366427,
                            '4055967cc8fd9863bdb5ab181a8824fc5e02a0a6ed51d6f95936e6e997f17d68'],
            'sel_3bfa270': [62890608,
                            62890808,
                            'bdcadb371dd3732d2d8275a1e2b7ca4cdd0819be4797d32ba6296206f31b6977'],
            'sel_4215360': [69292896,
                            69293563,
                            'dc4e137760d3ef42278db2b620c4f2a4237dc4f599c4c4982e7923cf74dc3a0f'],
            'sel_54e2920': [89008416,
                            89010214,
                            '38e0350548e712c5a66548e6dcb54924e0cba57778d49639e93c5cce462b650d'],
            'sel_54e3030': [89010224,
                            89012022,
                            'b5e09b216fff91e08d1d0db7a79ab824c53393ef4521a529f879c240e3dad40f'],
            'sel_54e3740': [89012032,
                            89014012,
                            'a1485583df2343211d2c45fb443c0bacae2db0b4360f744705cb59b5cfac7db2'],
            'sel_54e3f00': [89014016,
                            89015996,
                            'ee2f0c08e36ef349108e80a0de42c16fe80f3abd4fde9976d5c9b457d132fdf8'],
            'sel_54e5f90': [89022352,
                            89023055,
                            '8b27420c0cc8c7829b7727296c8b58d0202ad092645baa6da2802838d3eabe19'],
            'sel_54e6250': [89023056,
                            89023759,
                            '6f5e26526478642459c55d4d934c11aebe00a222e31ed57e4864f7042c226aad'],
            'sel_54eeea0': [89058976,
                            89059497,
                            '498bdefd557cced4607abc3537e23f8d2b69e801fcd19734d0fd5eb5c6c3c950'],
            'sel_54ef0b0': [89059504,
                            89060025,
                            'c011d71e153dce994bff783c91dc7a038d58b8caa1232bc59ef3f7b9174592f4'],
            'sel_5575680': [89609856,
                            89612125,
                            '552341d2551eefcfbd97f9faf833d2e318fcc907fc62c70f68056128da25fb62'],
            'sel_5575f60': [89612128,
                            89614397,
                            '4fabdd5ddb9c9b99992a35c8569c9edb69b1693da4391fad568bd8e41d4fb6e9'],
            'sel_557df20': [89644832,
                            89649875,
                            '7d8dc08adee6b813d9b8870351abdf9b00f9c26dda65a1af01fd3b16980ba33a'],
            'sel_557f2e0': [89649888,
                            89654993,
                            '39ff97aade1191a254c99f1b79208ede2e418c63a633363913946392a7ef7405']},
 'branchless_sites': ['0x2bfbaa3',
                      '0x2bfbfe5',
                      '0x2bfd1a1',
                      '0x2bfd2a6',
                      '0x2c01f94',
                      '0x2c32d37',
                      '0x2c37133',
                      '0x3bfa2a8',
                      '0x4215436',
                      '0x421553c',
                      '0x54e2b88',
                      '0x54e3298',
                      '0x54e3914',
                      '0x54e40d4',
                      '0x54e608d',
                      '0x54e634d',
                      '0x54eeeec',
                      '0x54ef0fc',
                      '0x5575a57',
                      '0x5576337',
                      '0x557e569',
                      '0x557f923'],
 'census_digests': {'2a8be00-2a8cbb3': '6192142ab8921f4faa4e927aa42bfa0cd9d9f3b2f836dc8f57b66e783d4d4c5f',
                    '2bbbba0-2bbc74d': 'f3e69ec027f6e24352c49415a533d2cc5e75443ce6681b3c6b51331a3446fa35',
                    '2bbc750-2bbd0a3': '1e485c8260263eee0fb80e2871c1aaabde9f381b30e9159662d64e5a991a04fa',
                    '2bbd0b0-2bbdb9a': '889874f504716879ed3af8bfab1a9f7909972bfee409b4125910ce5a114c1a6e',
                    '2bfb830-2bfbe1a': '2ebd20a20be37eef9a21fccf1767de03632df456d2b9fa8c45722c8a649bcfeb',
                    '2bfbe20-2bfc4d2': '066c01582b6f1688af0db1973da82af5abeedbe9aeefabf53aa41298fa37d8f9',
                    '2bfd0c0-2bfd357': '5762f41ade6d1f819df3de86b3796696c06ccf51938404b4f66ecf7402bc2894',
                    '2bfd360-2c0045a': '896175f4c46e32e0e65b92a6fdd22c15c973db48a814310c1c7015b52b1a8d5d',
                    '2c01570-2c01919': '1264dfa0b7d5aa1dd4f7b19a186bb1588e7970687d23abaff178357da4724949',
                    '2c01920-2c02dc9': '27909acc5e83d0567ff22c4a9b454590f86ee32751b254f560b315b6fa9e57fd',
                    '2c289b0-2c28f1b': '56e2a5f856c8bf307b33bca728140ddaf0f8291c44dcdb540084107331500b0c',
                    '2c32960-2c3323d': 'b41372b433fcdd8f1dea0efe6ca533b0172b987c6fa6283bbecf138aa6a94ccf',
                    '2c36af0-2c37edb': '4055967cc8fd9863bdb5ab181a8824fc5e02a0a6ed51d6f95936e6e997f17d68',
                    '2d27720-2d27a78': '2e3e51ea9925edc38ae111c2eed527b463dadf3d01e73342a90fdca9752a2a1c',
                    '36961e0-3698ed2': '1d6d91dfde0615441347f8c8a676e0c6e2d943fa1d26e17e64db41197a146dee',
                    '369d2c0-369dc7c': 'c05744100d46d44a1c0f8daed2ba2948b732686cbe0401b1084432bc4bb8d61e',
                    '3bf4cb0-3bf4f9f': '1454c3f6ba2656698193ed17c1294914d719ec225572952d1d050e1a264e2779',
                    '3bfa270-3bfa338': 'bdcadb371dd3732d2d8275a1e2b7ca4cdd0819be4797d32ba6296206f31b6977',
                    '4215360-42155fb': 'dc4e137760d3ef42278db2b620c4f2a4237dc4f599c4c4982e7923cf74dc3a0f',
                    '5493080-5493c2d': '3f64074e76c5885610e7e95dd1b66853e70f74d1e0b406fb3b9e25ac2c9abae3',
                    '5493c30-549471a': 'ce21c020d8136334be1bb89799253a295aeab1ab10c688d4d5ef4744294f0c9e',
                    '5494720-5495073': '22fd22d11c09bf61900af25dcb36f4d1cf63865c696382add27794a1004db4ee',
                    '54a9c70-54b66a2': 'c8b4563b262d24c124d4ee54a7e00146f41aeb8dc57799cdf5db6970562fceac',
                    '54b66b0-54c2ae8': '824ba23a3fbf24fe416e3f682d908c73e0c3504d82c6f1c8f20c79a61ee44d03',
                    '54e2920-54e3026': '38e0350548e712c5a66548e6dcb54924e0cba57778d49639e93c5cce462b650d',
                    '54e3030-54e3736': 'b5e09b216fff91e08d1d0db7a79ab824c53393ef4521a529f879c240e3dad40f',
                    '54e3740-54e3efc': 'a1485583df2343211d2c45fb443c0bacae2db0b4360f744705cb59b5cfac7db2',
                    '54e3f00-54e46bc': 'ee2f0c08e36ef349108e80a0de42c16fe80f3abd4fde9976d5c9b457d132fdf8',
                    '54e5f90-54e624f': '8b27420c0cc8c7829b7727296c8b58d0202ad092645baa6da2802838d3eabe19',
                    '54e6250-54e650f': '6f5e26526478642459c55d4d934c11aebe00a222e31ed57e4864f7042c226aad',
                    '54e6510-54e9607': 'c80839cb926bce8590ebc0c54c3d39617086a00c57037ca050f100ca2709ae84',
                    '54e9610-54ec707': 'e8991eb0f110450987cf0ccc30fffdbc24b9be3aa35148e636ae10596a1e245a',
                    '54eeea0-54ef0a9': '498bdefd557cced4607abc3537e23f8d2b69e801fcd19734d0fd5eb5c6c3c950',
                    '54ef0b0-54ef2b9': 'c011d71e153dce994bff783c91dc7a038d58b8caa1232bc59ef3f7b9174592f4',
                    '54ef2c0-54ef7ac': 'c4a4da6996a16a4409e8501e76b20d63e0a7e9002b268fcb38bd0210faf55fd8',
                    '54ef7b0-54efc9c': '5020df80460d7cc491b3b74e98b71bb6625513de12690a043f3d7edf621825c3',
                    '5560d60-5561369': '8c131c686e0b286f43dfb34f835c31d4768e2936aca0bd90fca55e81664724ae',
                    '5561370-5561979': 'e4c02e06ede14de11fe917dc7da0a253a39d054197f9cda564a4418d9ca5b4c8',
                    '5575680-5575f5d': '552341d2551eefcfbd97f9faf833d2e318fcc907fc62c70f68056128da25fb62',
                    '5575f60-557683d': '4fabdd5ddb9c9b99992a35c8569c9edb69b1693da4391fad568bd8e41d4fb6e9',
                    '557df20-557f2d3': '7d8dc08adee6b813d9b8870351abdf9b00f9c26dda65a1af01fd3b16980ba33a',
                    '557f2e0-55806d1': '39ff97aade1191a254c99f1b79208ede2e418c63a633363913946392a7ef7405',
                    '5a090d0-5a09428': '31f21a47108d6f188544974541c345ef1b4259a784e42910a0adb9ddbab56bd9'},
 'chain_rows': {'panic_consumer': {'96998096': ['55', 'push   %rbp'],
                                   '96998097': ['4889e5', 'mov    %rsp,%rbp'],
                                   '96998100': ['53', 'push   %rbx'],
                                   '96998101': ['4883ec28', 'sub    $0x28,%rsp'],
                                   '96998105': ['488b0f', 'mov    (%rdi),%rcx'],
                                   '96998108': ['488b4108', 'mov    0x8(%rcx),%rax'],
                                   '96998112': ['a801', 'test   $0x1,%al'],
                                   '96998114': ['7536', 'jne    0x5c8131a'],
                                   '96998116': ['48897df0', 'mov    %rdi,-0x10(%rbp)'],
                                   '96998120': ['48b80000000000000080',
                                                'movabs $0x8000000000000000,%rax'],
                                   '96998130': ['488945d8', 'mov    %rax,-0x28(%rbp)'],
                                   '96998134': ['488b5708', 'mov    0x8(%rdi),%rdx'],
                                   '96998138': ['488b4710', 'mov    0x10(%rdi),%rax'],
                                   '96998142': ['0fb64810', 'movzbl 0x10(%rax),%ecx'],
                                   '96998146': ['440fb64011', 'movzbl 0x11(%rax),%r8d'],
                                   '96998151': ['488d35b21e8400', 'lea    0x841eb2(%rip),%rsi'],
                                   '96998158': ['488d7dd8', 'lea    -0x28(%rbp),%rdi'],
                                   '96998162': ['ff1528b38600', 'call   *0x86b328(%rip)'],
                                   '96998168': ['0f0b', 'ud2'],
                                   '96998170': ['488b09', 'mov    (%rcx),%rcx'],
                                   '96998173': ['48d1e8', 'shr    $1,%rax'],
                                   '96998176': ['48894dd8', 'mov    %rcx,-0x28(%rbp)'],
                                   '96998180': ['488945e0', 'mov    %rax,-0x20(%rbp)'],
                                   '96998184': ['488b5708', 'mov    0x8(%rdi),%rdx'],
                                   '96998188': ['488b4710', 'mov    0x10(%rdi),%rax'],
                                   '96998192': ['0fb64810', 'movzbl 0x10(%rax),%ecx'],
                                   '96998196': ['440fb64011', 'movzbl 0x11(%rax),%r8d'],
                                   '96998201': ['488d35481e8400', 'lea    0x841e48(%rip),%rsi'],
                                   '96998208': ['488d7dd8', 'lea    -0x28(%rbp),%rdi'],
                                   '96998212': ['ff15f6b28600', 'call   *0x86b2f6(%rip)'],
                                   '96998218': ['4889c3', 'mov    %rax,%rbx'],
                                   '96998221': ['488b75d8', 'mov    -0x28(%rbp),%rsi'],
                                   '96998225': ['4885f6', 'test   %rsi,%rsi'],
                                   '96998228': ['7e0c', 'jle    0x5c81362'],
                                   '96998230': ['488b7de0', 'mov    -0x20(%rbp),%rdi'],
                                   '96998234': ['31d2', 'xor    %edx,%edx'],
                                   '96998236': ['ff153ee18500', 'call   *0x85e13e(%rip)'],
                                   '96998242': ['4889df', 'mov    %rbx,%rdi'],
                                   '96998245': ['e8e6f67600', 'call   0x63f0a50']},
                'panic_shim_len': {'23596640': ['55', 'push   %rbp'],
                                   '23596641': ['4889e5', 'mov    %rsp,%rbp'],
                                   '23596644': ['488d347501000000', 'lea    0x1(,%rsi,2),%rsi'],
                                   '23596652': ['ff1546e8e504', 'call   *0x4e5e846(%rip)']},
                'panic_shim_record': {'23596672': ['55', 'push   %rbp'],
                                      '23596673': ['4889e5', 'mov    %rsp,%rbp'],
                                      '23596676': ['4883ec30', 'sub    $0x30,%rsp'],
                                      '23596680': ['48897df0', 'mov    %rdi,-0x10(%rbp)'],
                                      '23596684': ['488975f8', 'mov    %rsi,-0x8(%rbp)'],
                                      '23596688': ['488d45f0', 'lea    -0x10(%rbp),%rax'],
                                      '23596692': ['488945d8', 'mov    %rax,-0x28(%rbp)'],
                                      '23596696': ['488955e0', 'mov    %rdx,-0x20(%rbp)'],
                                      '23596700': ['66c745e80100', 'movw   $0x1,-0x18(%rbp)'],
                                      '23596706': ['488d7dd8', 'lea    -0x28(%rbp),%rdi'],
                                      '23596710': ['ff158410e604', 'call   *0x4e61084(%rip)']},
                'panic_shim_rewrap': {'97003200': ['55', 'push   %rbp'],
                                      '97003201': ['4889e5', 'mov    %rsp,%rbp'],
                                      '97003204': ['4883ec20', 'sub    $0x20,%rsp'],
                                      '97003208': ['0f1007', 'movups (%rdi),%xmm0'],
                                      '97003211': ['0f1145e8', 'movups %xmm0,-0x18(%rbp)'],
                                      '97003215': ['48897df8', 'mov    %rdi,-0x8(%rbp)'],
                                      '97003219': ['488d7de8', 'lea    -0x18(%rbp),%rdi'],
                                      '97003223': ['ff15fb9e8600', 'call   *0x869efb(%rip)']},
                'panic_shim_tail': {'96961408': ['55', 'push   %rbp'],
                                    '96961409': ['4889e5', 'mov    %rsp,%rbp'],
                                    '96961412': ['e8478f0000', 'call   0x5c812d0']}},
 'flag_rows': {'57247565': ['4d85ed', 'test   %r13,%r13'],
               '57247568': ['742f', 'je     0x3698781'],
               '57247570': ['4c3bac24d0000000', 'cmp    0xd0(%rsp),%r13'],
               '57247578': ['7419', 'je     0x3698775'],
               '57247580': ['498d4518', 'lea    0x18(%r13),%rax'],
               '57247584': ['498b4d00', 'mov    0x0(%r13),%rcx'],
               '57247588': ['4983c508', 'add    $0x8,%r13'],
               '57247592': ['48898424c8000000', 'mov    %rax,0xc8(%rsp)'],
               '57247600': ['41b601', 'mov    $0x1,%r14b'],
               '57247603': ['eb3a', 'jmp    0x36987af'],
               '57247605': ['48c78424c800000000000000', 'movq   $0x0,0xc8(%rsp)'],
               '57247617': ['4883bc248000000003', 'cmpq   $0x3,0x80(%rsp)'],
               '57247626': ['0f84f2020000', 'je     0x3698a82'],
               '57247632': ['488dbc2480000000', 'lea    0x80(%rsp),%rdi'],
               '57247640': ['e893c8e600', 'call   0x4505030'],
               '57247645': ['4885c0', 'test   %rax,%rax'],
               '57247648': ['0f84dc020000', 'je     0x3698a82'],
               '57247654': ['4989d5', 'mov    %rdx,%r13'],
               '57247657': ['488b08', 'mov    (%rax),%rcx'],
               '57247660': ['4531f6', 'xor    %r14d,%r14d'],
               '57247663': ['48894c2418', 'mov    %rcx,0x18(%rsp)'],
               '57247668': ['48898c2470010000', 'mov    %rcx,0x170(%rsp)'],
               '57247676': ['488b7c2450', 'mov    0x50(%rsp),%rdi'],
               '57247681': ['488db42470010000', 'lea    0x170(%rsp),%rsi'],
               '57247689': ['e8a2de6200', 'call   0x3cc6670'],
               '57247694': ['4889c5', 'mov    %rax,%rbp'],
               '57247697': ['4885c0', 'test   %rax,%rax'],
               '57247700': ['0f8401030000', 'je     0x3698adb'],
               '57247706': ['498b4508', 'mov    0x8(%r13),%rax'],
               '57247710': ['4489f1', 'mov    %r14d,%ecx'],
               '57247713': ['80f101', 'xor    $0x1,%cl'],
               '57247716': ['0fb6c9', 'movzbl %cl,%ecx'],
               '57247719': ['c1e105', 'shl    $0x5,%ecx'],
               '57247722': ['4889442410', 'mov    %rax,0x10(%rsp)'],
               '57247727': ['48f7640d58', 'mulq   0x58(%rbp,%rcx,1)'],
               '57247732': ['4989d5', 'mov    %rdx,%r13'],
               '57247735': ['4889c3', 'mov    %rax,%rbx'],
               '57247738': ['4889c7', 'mov    %rax,%rdi'],
               '57247741': ['4889d6', 'mov    %rdx,%rsi'],
               '57247744': ['49bf00407a10f35a0000', 'movabs $0x5af3107a4000,%r15'],
               '57247754': ['4c89fa', 'mov    %r15,%rdx'],
               '57247757': ['31c9', 'xor    %ecx,%ecx'],
               '57247759': ['ff15e372e402', 'call   *0x2e472e3(%rip)'],
               '57247765': ['4889d7', 'mov    %rdx,%rdi'],
               '57247768': ['4584f6', 'test   %r14b,%r14b'],
               '57247771': ['742c', 'je     0x3698849'],
               '57247773': ['4889c6', 'mov    %rax,%rsi'],
               '57247776': ['49f7e7', 'mul    %r15'],
               '57247779': ['4889f9', 'mov    %rdi,%rcx'],
               '57247782': ['490fafcf', 'imul   %r15,%rcx'],
               '57247786': ['4801d1', 'add    %rdx,%rcx'],
               '57247789': ['4829c3', 'sub    %rax,%rbx'],
               '57247792': ['4919cd', 'sbb    %rcx,%r13'],
               '57247795': ['31c0', 'xor    %eax,%eax'],
               '57247797': ['4909dd', 'or     %rbx,%r13'],
               '57247800': ['0f95c0', 'setne  %al'],
               '57247803': ['4801c6', 'add    %rax,%rsi'],
               '57247806': ['4889742440', 'mov    %rsi,0x40(%rsp)'],
               '57247811': ['4883d700', 'adc    $0x0,%rdi'],
               '57247815': ['eb05', 'jmp    0x369884e'],
               '57247817': ['4889442440', 'mov    %rax,0x40(%rsp)'],
               '57247822': ['41b503', 'mov    $0x3,%r13b'],
               '57247825': ['4885ff', 'test   %rdi,%rdi'],
               '57247828': ['0f853d030000', 'jne    0x3698b97'],
               '57247834': ['48837c241000', 'cmpq   $0x0,0x10(%rsp)'],
               '57247840': ['750e', 'jne    0x3698870'],
               '57247842': ['488b442440', 'mov    0x40(%rsp),%rax'],
               '57247847': ['4809f8', 'or     %rdi,%rax'],
               '57247850': ['0f8573020000', 'jne    0x3698ae3'],
               '57247856': ['48897c2460', 'mov    %rdi,0x60(%rsp)'],
               '57247861': ['488b5510', 'mov    0x10(%rbp),%rdx'],
               '57247865': ['410fb6ce', 'movzbl %r14b,%ecx'],
               '57247869': ['488b7c2440', 'mov    0x40(%rsp),%rdi'],
               '57247874': ['488b742418', 'mov    0x18(%rsp),%rsi'],
               '57247879': ['4889542430', 'mov    %rdx,0x30(%rsp)'],
               '57247884': ['4c8b442468', 'mov    0x68(%rsp),%r8'],
               '57247889': ['ff1521e9e402', 'call   *0x2e4e921(%rip)'],
               '57247895': ['4883f801', 'cmp    $0x1,%rax'],
               '57247899': ['0f854a020000', 'jne    0x3698aeb'],
               '57247905': ['4889d3', 'mov    %rdx,%rbx'],
               '57247908': ['4885d2', 'test   %rdx,%rdx'],
               '57247911': ['0f88bd040000', 'js     0x3698d6a'],
               '57247917': ['4584f6', 'test   %r14b,%r14b'],
               '57247920': ['4c8b7c2420', 'mov    0x20(%rsp),%r15'],
               '57247925': ['4c0f457c2408', 'cmovne 0x8(%rsp),%r15']},
 'plt_rows': {'104794704': ['ff2522d70f00', 'jmp    *0xfd722(%rip)'],
              '104794710': ['6801000000', 'push   $0x1'],
              '104794715': ['e9d0ffffff', 'jmp    0x63f0a30']}}
# === END FROZEN DATA ===


def _frozen_rows(section, rows, what):
    pins = FROZEN.get(section)
    if pins:
        _check_rows(rows, _pins(pins), what)


def analyze(data):
    if len(data) != NODE_SIZE \
            or __import__('hashlib').sha256(data).hexdigest() != NODE_SHA256:
        raise PacketError('artifact does not authenticate as node 115')
    secs = sections(data)
    relas = _rela_entries(data, secs)
    fdes = _fde_index(data)

    slot_facts = {}
    for slot in (GATE_SLOT, FMT_SLOT, 0x64DF6B8, 0x64E1F30, 0x64EC5D8,
                 0x64EC640, 0x64DF4A0, PLT_SLOT):
        slot_facts[_hx(slot)] = _slot_resolution(data, secs, relas, slot)
    if slot_facts[_hx(GATE_SLOT)].get('addend') != _hx(GATE_BODY):
        raise PacketError('gate slot does not resolve to the gate body')
    if slot_facts[_hx(FMT_SLOT)].get('addend') != '0x1680e60':
        raise PacketError('panic slot does not resolve to 0x1680e60')

    bodies = {}
    decoded = {}
    for name, (start, end, exported) in BODIES.items():
        dg = _digest(data, secs, start, end)
        want = FROZEN.get('bodies', {}).get(name)
        if want is not None and want != [start, end, dg]:
            raise PacketError(f'body {name} range or digest drift')
        if fdes.get(start, (None,))[0] != end:
            raise PacketError(f'body {name} is not an FDE extent')
        bodies[name] = {'start': _hx(start), 'end': _hx(end),
                        'size': end - start, 'sha256': dg,
                        'exported': exported}

    def rows_of(start, end):
        if start not in decoded:
            decoded[start] = _decode(data, secs, start, end)
        return decoded[start]

    # ---------- edge 5: the panic-formatting callee chain ----------
    chain = {}
    for name in CHAIN:
        start, end, _e = BODIES[name]
        rows = rows_of(start, end)
        if FROZEN.get('chain_rows', {}).get(name):
            if rows != _pins(FROZEN['chain_rows'][name]):
                raise PacketError(f'chain body {name} rows drift')
        refs = _slot_refs_all(rows)
        chain[name] = {
            'rows': len(rows),
            'rets': [_hx(a) for a in sorted(rows)
                     if rows[a][1] == 'ret'],
            'stores': _stores(rows),
            'mem_reads': len(_mem_reads(rows)),
            'slot_calls': {_hx(a): _hx(t) for a, (k, t)
                           in sorted(refs.items()) if k == 'call'},
            'direct_calls': _direct_calls(rows),
            'byte_after': _section_bytes(data, secs, end, end + 1).hex(),
        }
        if chain[name]['rets'] or chain[name]['byte_after'] != 'cc':
            raise PacketError(f'chain body {name} returns or lacks int3')
    plt_rows = _decode(data, secs, PLT_ADDR, PLT_ADDR + 16)
    _frozen_rows('plt_rows', plt_rows, 'plt stub')
    plt_sec = next(s['name'] for s in secs
                   if s['address'] <= PLT_ADDR < s['address'] + s['size'])
    plt = {'addr': _hx(PLT_ADDR), 'section': plt_sec,
           'rows': [[_hx(a), plt_rows[a][1]] for a in sorted(plt_rows)],
           'slot': _hx(PLT_SLOT),
           'target_addend': slot_facts[_hx(PLT_SLOT)].get('addend')}
    fmt0_addends = [[_hx(e[0]), e[1]] for e in relas
                    if e[3] == BODIES['panic_shim_len'][0]]
    if fmt0_addends != [[_hx(FMT_SLOT), 8]]:
        raise PacketError(f'formatter rela addends drift: {fmt0_addends}')
    text_sec = next(s for s in secs if s['name'] == '.text')
    blob = data[text_sec['offset']:text_sec['offset'] + text_sec['size']]
    va0 = text_sec['address']
    e8_counts = {}
    for target in (BODIES['panic_shim_len'][0], BODIES['panic_shim_record'][0]):
        n = 0
        for match in re.finditer(rb'\xe8', blob):
            i = match.start()
            if va0 + i + 5 + struct.unpack_from('<i', blob, i + 1)[0] \
                    == target:
                n += 1
        e8_counts[_hx(target)] = n
    if any(e8_counts.values()):
        raise PacketError(f'direct E8 calls to chain heads: {e8_counts}')

    # ---------- edge 4: the register-supplied flag site ----------
    flag_rows = rows_of(*FLAG_FDE)
    _frozen_rows('flag_rows', flag_rows, 'flag FDE')
    flag_addrs = sorted(flag_rows)
    writes_in_window = []
    _wr = re.compile(r'%(r14|r14d|r14w|r14b)\b')
    for a in flag_addrs:
        if not (0x3698704 < a < FLAG_SITE):
            continue
        text = flag_rows[a][1]
        mnem, ops = _split_ops(text)
        if ops and _wr.search(ops[-1]) and mnem not in ('cmp', 'test'):
            writes_in_window.append(a)
    if [_hx(a) for a in writes_in_window] != ['0x3698770', '0x36987ac']:
        raise PacketError(
            f'r14 writes in the site window drift: {writes_in_window}')
    flag_bindings = _bindings(flag_rows, FLAG_SITE)
    if _flag_of(flag_bindings.get('rcx')) != 'register':
        raise PacketError('flag site rcx is not register-supplied')
    arm_rows = {}
    for lo, hi, key in ((0x369874D, 0x3698774, 'walk_arm'),
                        (0x3698775, 0x36987AD, 'lookup_arm'),
                        (0x36987AF, 0x36988B6, 'shared')):
        arm_rows[key] = [[_hx(a), flag_rows[a][1]] for a in flag_addrs
                         if lo <= a < hi]
    edge4 = {
        'fde': bodies['flag_fde'],
        'site': _hx(FLAG_SITE),
        'call_row': list(flag_rows[FLAG_SITE]),
        'bindings': flag_bindings,
        'r14_writes_in_window': [_hx(a) for a in writes_in_window],
        'arm_rows': arm_rows,
        'boundaries': {n: bodies[n]
                       for n in ('flag_lookup', 'flag_accessor')},
    }

    # ---------- edge 3: gate census + branchless classification ----
    raw = _raw_slot_scan(data, secs, GATE_SLOT)
    kinds = {}
    for kind in raw.values():
        kinds[kind] = kinds.get(kind, 0) + 1
    if kinds != {'call': 89}:
        raise PacketError(f'gate slot reference kinds drift: {kinds}')
    starts = sorted(fdes)

    def owner(va):
        i = bisect.bisect_right(starts, va) - 1
        if i < 0 or not (starts[i] <= va < fdes[starts[i]][0]):
            raise PacketError(f'candidate {_hx(va)} is inside no FDE')
        return starts[i]

    groups = {}
    for va in sorted(raw):
        groups.setdefault(owner(va), []).append(va)
    census_digests = {}
    for start in sorted(groups):
        end = fdes[start][0]
        dg = _digest(data, secs, start, end)
        key = f'{start:x}-{end:x}'
        census_digests[key] = dg
        want = FROZEN.get('census_digests', {}).get(key)
        if want is not None and want != dg:
            raise PacketError(f'census FDE {key} digest drift')
    if FROZEN.get('census_digests') is not None and \
            set(census_digests) != set(FROZEN['census_digests']):
        raise PacketError('census FDE set drift')

    flag_counts = {'0': 0, '1': 0, 'register': 0, 'unknown': 0}
    register_sites = []
    branchless = {}
    subset_2608_rule = 0
    for start in sorted(groups):
        end = fdes[start][0]
        rows = rows_of(start, end)
        refs = _slot_refs_all(rows)
        calls = sorted(a for a, (k, t) in refs.items()
                       if k == 'call' and t == GATE_SLOT)
        if calls != groups[start]:
            raise PacketError(f'census validation drift in FDE {_hx(start)}')
        addrs = sorted(rows)
        for a in calls:
            binds = _bindings(rows, a)
            flag = _flag_of(binds.get('rcx'))
            flag_counts[str(flag) if flag in (0, 1) else
                        ('register' if flag == 'register'
                         else 'unknown')] += 1
            if flag == 'register':
                register_sites.append(a)
            i = addrs.index(a)
            post = [rows[x][1] for x in addrs[i + 1:i + 5]]
            if any('cmov' in t for t in post[:3]):
                subset_2608_rule += 1
            # branchless rule: first cmov within the next 10 rows
            # (stopping at the next call), no conditional branch
            # before it, and a test of the return in between.
            window = []
            for x in addrs[i + 1:i + 11]:
                if rows[x][1].startswith('call'):
                    break
                window.append(x)
            cmov_at = None
            tested = False
            ok = True
            for j, x in enumerate(window):
                text = rows[x][1]
                mnem = text.split()[0] if text.split() else ''
                if mnem.startswith('cmov'):
                    cmov_at = j
                    break
                if mnem.startswith('j') and mnem != 'jmp':
                    ok = False
                    break
                if mnem == 'test':
                    tested = True
            if cmov_at is None or not ok or not tested:
                continue
            cx = window[cmov_at]
            cmov_text = _norm(rows[cx][1])
            mnem, ops = _split_ops(rows[cx][1])
            src, dst = ops[0].lstrip('%'), ops[-1].lstrip('%')
            entry = {
                'fde': _hx(start),
                'call_row': list(rows[a]),
                'cmov_addr': _hx(cx),
                'cmov_row': list(rows[cx]),
                'flag': flag,
                'dst': dst,
                'post_cmov': [rows[x][1] for x in
                              addrs[addrs.index(cx) + 1:
                                    addrs.index(cx) + 5]],
            }
            wtexts = [_norm(rows[x][1]) for x in window[:cmov_at]]
            if mnem == 'cmovne' and dst == 'rax':
                if 'xor %eax,%eax' not in wtexts:
                    raise PacketError(
                        f'branchless site {_hx(a)}: rax-zero pattern '
                        f'drift: {wtexts}')
                entry['class'] = 'rax-zero-return'
                entry['zero_row'] = [_hx(window[wtexts.index(
                    'xor %eax,%eax')]),
                    rows[window[wtexts.index('xor %eax,%eax')]][1]]
            elif mnem == 'cmovne' and src == 'rdx' and dst != 'rdx':
                zero = _last_writer(rows, dst, a, window=40)
                if not zero or zero.get('form') != 'imm' \
                        or zero.get('value') != 0:
                    raise PacketError(
                        f'branchless site {_hx(a)}: dst {dst} is not '
                        f'zero-initialised before the call: {zero}')
                entry['class'] = 'zeroed-dst'
                entry['zero_row'] = [zero['addr'], zero['text']]
            elif mnem == 'cmovne' and dst == 'rdx':
                if len(wtexts) < 3 \
                        or not wtexts[0].startswith(f'mov %rdx,%{src}') \
                        or wtexts[1] != 'xor %edx,%edx':
                    raise PacketError(
                        f'branchless site {_hx(a)}: rdx-self-zero '
                        f'pattern drift: {wtexts}')
                entry['class'] = 'rdx-self-zero'
                entry['zero_row'] = [_hx(window[1]), rows[window[1]][1]]
            elif mnem == 'cmove' and dst == 'rbp':
                if len(wtexts) < 3 or wtexts[0] != 'mov %rdx,%rbp' \
                        or 'mov $0x0,%eax' not in wtexts:
                    raise PacketError(
                        f'branchless site {_hx(a)}: copy-zero pattern '
                        f'drift: {wtexts}')
                entry['class'] = 'copy-zero-on-eq'
                entry['zero_row'] = [_hx(window[wtexts.index(
                    'mov $0x0,%eax')]),
                    rows[window[wtexts.index('mov $0x0,%eax')]][1]]
            elif mnem == 'cmove' and dst == 'rdx':
                if 'mov $0x0,%eax' in wtexts and src == 'rax':
                    entry['class'] = 'rdx-zero-on-eq'
                    entry['zero_row'] = [_hx(window[wtexts.index(
                        'mov $0x0,%eax')]),
                        rows[window[wtexts.index('mov $0x0,%eax')]][1]]
                else:
                    zero = _last_writer(rows, src, a, window=40)
                    if not zero or zero.get('form') != 'imm' \
                            or zero.get('value') != 0:
                        raise PacketError(
                            f'branchless site {_hx(a)}: cmov source '
                            f'{src} is not zero-initialised: {zero}')
                    entry['class'] = 'rdx-zero-on-eq'
                    entry['zero_row'] = [zero['addr'], zero['text']]
            else:
                raise PacketError(
                    f'branchless site {_hx(a)}: unclassifiable cmov '
                    f'{cmov_text}')
            # first read of the destination after the cmov
            names = _ALIASES.get(dst, (dst,))
            first_use = None
            ci = addrs.index(cx)
            for x in addrs[ci + 1:ci + 9]:
                t = rows[x][1]
                if any(re.search(r'%' + n + r'\b', t) for n in names):
                    first_use = [_hx(x), t]
                    break
            entry['first_dst_use'] = first_use
            branchless[_hx(a)] = entry
    if register_sites != [FLAG_SITE]:
        raise PacketError(
            f'register-flag sites drift: {register_sites}')
    if FROZEN.get('branchless_sites') is not None and \
            set(branchless) != set(FROZEN['branchless_sites']):
        raise PacketError(
            f'branchless set drift: {sorted(branchless)}')
    class_counts = {}
    for entry in branchless.values():
        class_counts[entry['class']] = \
            class_counts.get(entry['class'], 0) + 1
    sign_tests = sum(1 for e in branchless.values()
                     if e['first_dst_use']
                     and e['first_dst_use'][1].startswith('test'))
    edge3 = {
        'rule': ('a gate site is branchless when, in the rows after '
                 'the call (up to the next call, at most 10 rows), a '
                 'cmov consuming the result appears before any '
                 'conditional branch and a test of the return value '
                 'precedes the cmov'),
        'counters': {
            'census_sites': sum(len(v) for v in groups.values()),
            'census_fdes': len(groups),
            'branchless_sites': len(branchless),
            'branch_handled_sites': 89 - len(branchless),
            'subset_2608_rule': subset_2608_rule,
            'class_counts': class_counts,
            'sign_test_first_use': sign_tests,
            'flag_counts': flag_counts,
        },
        'sites': branchless,
    }

    # ---------- edge 5: caller census of the panic slot ----------
    raw_fmt = _raw_slot_scan(data, secs, FMT_SLOT)
    fmt_kinds = {}
    for kind in raw_fmt.values():
        fmt_kinds[kind] = fmt_kinds.get(kind, 0) + 1
    fmt_groups = {}
    for va in sorted(raw_fmt):
        fmt_groups.setdefault(owner(va), []).append(va)
    small = {s: v for s, v in fmt_groups.items()
             if fdes[s][0] - s <= 64}
    validated = 0
    stub_shape = []
    for start in sorted(small):
        end = fdes[start][0]
        rows = rows_of(start, end)
        refs = _slot_refs_all(rows)
        calls = sorted(a for a, (k, t) in refs.items()
                       if k == 'call' and t == FMT_SLOT)
        if calls != sorted(small[start]):
            raise PacketError(
                f'panic-slot validation drift in FDE {_hx(start)}')
        validated += len(calls)
        texts = [_norm(rows[a][1]) for a in sorted(rows)]
        if len(rows) == 6 and texts[0] == 'push %rbp' \
                and texts[2] == 'mov %rdi,%rdx' \
                and texts[3].startswith('lea') \
                and texts[4].startswith('mov') \
                and texts[5].startswith('call'):
            stub_shape.append(_hx(start))
    edge5 = {
        'chain': chain,
        'plt': plt,
        'boundaries': {n: bodies[n]
                       for n in ('panic_formatter', 'panic_hook')},
        'caller_census': {
            'raw_refs': len(raw_fmt),
            'kinds': fmt_kinds,
            'distinct_fdes': len(fmt_groups),
            'validated_small_fdes': len(small),
            'validated_small_sites': validated,
            'stub_shape_fdes': stub_shape,
            'rela_addends_for_fmt0': fmt0_addends,
            'e8_direct_calls': e8_counts,
        },
    }

    counters = {
        'bodies': len(bodies),
        'exported_bodies': sum(1 for b in bodies.values()
                               if b['exported']),
        'census_sites': edge3['counters']['census_sites'],
        'census_fdes': edge3['counters']['census_fdes'],
        'branchless_sites': len(branchless),
        'flag_register_sites': len(register_sites),
        'panic_raw_refs': len(raw_fmt),
        'panic_caller_fdes': len(fmt_groups),
        'panic_validated_small_sites': validated,
    }
    return {
        'artifact': {'sha256': NODE_SHA256, 'size': NODE_SIZE},
        'upstream_main': UPSTREAM_MAIN,
        'bodies': bodies,
        'slot_facts': slot_facts,
        'edge3_branchless': edge3,
        'edge4_flag_site': edge4,
        'edge5_panic_callee': edge5,
        'counters': counters,
        'verdicts': {
            'edge3': ('settled: at every one of the 22 branchless '
                      'gate sites the destination of the conditional '
                      'move is zero-initialised in the rows '
                      'immediately around the call, so a gate return '
                      'of 0 leaves the defined default 0, never a '
                      'stale running value; on a return of 1 the '
                      "gate's rdx replaces that 0"),
            'edge4': ('settled: r14b is written at exactly two rows '
                      'on the arms that converge before the site -- '
                      'mov $0x1,%r14b at 0x3698770 on the cursor-walk '
                      'arm and xor %r14d,%r14d at 0x36987ac on the '
                      'fallback-lookup arm -- so this caller asks '
                      'for ceiling exactly for elements taken from '
                      'its own list walk, and floor for elements '
                      'that arrive through the lookup at 0x4505030'),
            'edge5': ('settled for the wrapper chain: the callee '
                      'behind slot 0x64df730 is an 18-byte shim '
                      '(rsi := 2*rsi+1) into a 44-byte record '
                      'builder, a 29-byte rewrap and a 9-byte tail '
                      'shim, ending in the 154-byte consumer '
                      '0x5c812d0, which recovers (ptr, len) by '
                      'shifting the tagged word back and calls the '
                      'formatting body behind slot 0x64ec640; no '
                      'body in the chain returns'),
        },
    }


def generate(data, out_dir):
    records = analyze(data)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / 'records.json').write_text(
        json.dumps(records, indent=1, sort_keys=True) + '\n')
    fdes = _fde_index(data)
    lines = []
    retained = {(s, e) for s, e, _x in BODIES.values()}
    for start in sorted(fdes):
        end, line = fdes[start]
        if (start, end) in retained:
            lines.append(line)
    if len(lines) != len(retained):
        raise AssertionError(
            f'frames cover {len(lines)} of {len(retained)} FDEs')
    (out_dir / 'frames.txt').write_text('\n'.join(lines) + '\n')
    for name, (start, end, exported) in BODIES.items():
        if exported:
            (out_dir / f'{name}_full_body_{start:x}_{end:x}'
                       f'_objdump.txt').write_text(
                _body_export(data, start, end))
    return records


def _verify():
    with tempfile.TemporaryDirectory() as tmp:
        generate((ROOT / 'artifacts/node/115/hl-node').read_bytes(),
                 tmp)
        generated = {p.name: p.read_bytes()
                     for p in Path(tmp).iterdir()}
    committed = {p.name: p.read_bytes() for p in PACKET_DIR.iterdir()
                 if p.name != 'README.md'
                 and p.name != 'MANIFEST.sha256'}
    ok = generated == committed
    print(json.dumps({'matches': ok,
                      'packet': 'RE-006-node115-remaining-edges'}))
    return 0 if ok else 1


def main(argv):
    if len(argv) == 3 and argv[1] == 'generate':
        artifact = ROOT / 'artifacts/node/115/hl-node'
        generate(artifact.read_bytes(), argv[2])
        return 0
    if len(argv) == 2 and argv[1] == 'verify':
        return _verify()
    raise SystemExit(
        'usage: remaining_edges_static.py (generate <out-dir> | verify)')


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
