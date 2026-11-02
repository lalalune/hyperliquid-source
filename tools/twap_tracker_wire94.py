#!/usr/bin/env python3
"""Recover bounded node 94 spot TWAP tracker codec facts from ELF bytes."""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import elf_index
import fde_extents

BINARY = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# FDE starts are selected from prior focused analysis; ends are checked against
# actual records, never inferred from the next start in the unwind index.
FUNCTIONS = {
    'field_reader': (0x16f6830, 0x16f6f8f),
    'heap_reader': (0x171e560, 0x171f0be),
    'tracker_reader': (0x1906c20, 0x1907df4),
    'heap_item_reader': (0x19bdf90, 0x19bfe55),
    'heap_sequence': (0x1e2d480, 0x1e2d7d4),
    'compact_heap_sequence': (0x1e21920, 0x1e21c74),
    'tree_pair': (0x1df5c70, 0x1df6240),
    'compact_tree_pair': (0x1e053c0, 0x1e05673),
    'time_text_writer': (0x1dfca40, 0x1dfcb91),
    'compact_time_text_writer': (0x1dfcba0, 0x1dfccf1),
    'address_key_writer': (0x1e0d0a0, 0x1e0d205),
    'compact_tree_rows': (0x1e1eda0, 0x1e1f100),
    'tree_rows': (0x1e246e0, 0x1e2496b),
    'named_tree_wrapper': (0x25e7c00, 0x25e7cc9),
    'compact_tree_wrapper': (0x25e57c0, 0x25e5889),
    'field_classifier': (0x26c0260, 0x26c02cf),
    'heap_item_classifier': (0x26bfd80, 0x26bfdf4),
    'compact_heap_item': (0x26d8eb0, 0x26d9188),
    'heap_item': (0x26d9190, 0x26d9331),
    'tracker_writer': (0x26db260, 0x26db38d),
    'compact_tracker_writer': (0x26db390, 0x26db581),
    'json_tracker_writer': (0x26db590, 0x26db821),
    'json_spot_field_wrapper': (0x27b0e70, 0x27b0f39),
    'spot_field_wrapper': (0x27b2a20, 0x27b2a7c),
}

# Fixed instruction windows are anchored at manually checked starts. Their
# bytes are qualified by the FDE, and the few decoded rel operands are below.
PINS = {
    0x171ec42: '8d04dd000000004c8d3480',
    0x171ec90: '488d7c2460',
    0x171ec95: '31d2',
    0x171ec97: 'e8f4f22900',
    0x171ecb7: '807c246000',
    0x171ecbc: '7568',
    0x26bfd80: '4889f84883fa0474514883fa07742f4883fa0f754d48b96e6578745f736c6948330e48ba6963655f74696d65483356074809ca752d31c9884801c60009c3b974776170330eba705f696433560309ca7511b102884801c60009c3813e757365727409b103884801c60009c3b101884801c60009c3',
    0x19bf667: 'e81407d000',
    0x19bf830: '3c09',
    0x19bf832: '0f858e030000',
    0x19bf840: '488d0dfde39bfe',
    0x19bf847: '486304814801c8ffe0',
    0x19bf850: '85ed',
    0x19bf852: '0f8590050000',
    0x19bf86f: 'e8ecd4cfff',
    0x19bf897: '4883bc240001000001',
    0x19bf8a0: '0f8414050000',
    0x19bf8b1: 'e8ea4bccff',
    0x19bf8ed: 'ba01000000',
    0x19bf8f2: 'e8d989faff',
    0x19bf91b: 'f684242801000001',
    0x19bf923: '0f85a8040000',
    0x19bf955: '48c744244014000000',
    0x19bf973: 'e838fcf4ff',
    0x19be45a: '488d05e8239ffe',
    0x19be469: '48c78424880000000f000000',
    0x19be48e: '488d355e1482fe',
    0x19bf034: '488d0581ae84fe',
    0x19bf043: '48c784248800000004000000',
    0x19bf068: '488d35840882fe',
    0x19bf111: '488d0540179ffe',
    0x19bf120: '48c784248800000007000000',
    0x19bf145: '488d35a70782fe',
    0x19bfdba: '488d05970a9ffe',
    0x19bfdc6: '48c744243807000000',
    0x19bfdd1: '488d05e4a084fe',
    0x19bfddd: '48c744243804000000',
    0x19bfde8: '488d055a0a9ffe',
    0x19bfdf4: '48c74424380f000000',
    0x19bfe18: '488d35b61182fe',
    0x27b0e79: '803f007567',
    0x27b0e84: '488d3539e5c3fd',
    0x27b0e8b: 'ba11000000',
    0x27b0e90: 'e8fb321c00',
    0x27b0e95: '41803e017464',
    0x27b0eca: 'e8c1a6f2ff',
    0x27b0ecf: '4885c07507',
    0x27b0ed4: '41c6462001',
    0x27b0ee5: '48c74424080a000000',
    0x27b0eff: '488d3dec50c4fd',
    0x1dfca8b: '488b024c8b38',
    0x1dfca99: 'ff15c12a9703',
    0x1dfca9f: '84c0',
    0x1dfcaa1: '0f8591000000',
    0x1dfcab1: 'be54000000',
    0x1dfcab6: 'ff5020',
    0x1dfcab9: '84c0',
    0x1dfcabb: '757b',
    0x1dfcabd: '4983c704',
    0x1dfcac9: 'ff15992a9703',
    0x1dfcacf: '84c0',
    0x1dfcad1: '7565',
    0x1dfcae8: 'e803dd7a00',
    0x1dfcaf7: '4883f802',
    0x1dfcafb: '750e',
    0x1dfcb38: '488d3d76075cfe',
    0x1dfcb52: 'be37000000',
    0x1dfcb5d: '0f0b',
    0x1dfcbeb: '488b024c8b38',
    0x1dfcbf9: 'ff1561299703',
    0x1dfcbff: '84c0',
    0x1dfcc01: '0f8591000000',
    0x1dfcc11: 'be54000000',
    0x1dfcc16: 'ff5020',
    0x1dfcc19: '84c0',
    0x1dfcc1b: '757b',
    0x1dfcc1d: '4983c704',
    0x1dfcc29: 'ff1539299703',
    0x1dfcc2f: '84c0',
    0x1dfcc31: '7565',
    0x1dfcc48: 'e863e07a00',
    0x16f683a: '8b460885c0745c',
    0x16f689d: '66c7070903',
    0x16f6959: '4829d1',
    0x16f695c: '0f82fc010000',
    0x16f6b59: '4829d9',
    0x16f6b5c: '7318',
    0x16f6b5e: 'c6042401',
    0x16f6b62: '48b80300000025000000',
    0x1e246f9: '4c8b6a084c8b7210',
    0x1e24704: '48c1e820',
    0x1e2470b: '807e0c00',
    0x1e24747: 'e884547800',
    0x1e2479f: 'e8cc14fdff',
    0x1e247a9: '48b900000000000000804883c1044839c8',
    0x1e24893: '49c1e6044d01f5',
    0x1e248c0: '488b5500488b4d08',
    0x1e248ce: 'e89d13fdff',
    0x1e248e1: '4883c510',
    0x1e1edb9: '4c8b6a08488b5210',
    0x1e1ee1c: 'e87fac7800',
    0x1e1ee5c: '488b5008',
    0x1e1ee68: 'e85365feff',
    0x1e1eea3: '488b5308',
    0x1e1eead: 'e80e65feff',
    0x1df5cd5: 'ba02000000',
    0x1df5cda: 'e8f13e7b00',
    0x1df5d25: 'e876730100',
    0x1df5d2e: '4c39742430',
    0x1df5d33: '0f85f2000000',
    0x1df5d57: 'e864187f00',
    0x1df5d80: 'c6040192',
    0x1df5dbc: 'e8ff780100',
    0x1df5dc5: '4c39742430',
    0x1df5dca: '7538',
    0x1df5dec: 'e8ef3e7f00',
    0x1e053e1: '80791c027504',
    0x1e053fc: 'c6043092',
    0x1e05438: 'e883820000',
    0x1e05441: '4c39742430',
    0x1e05446: '7532',
    0x1e05462: 'e8291c7e00',
    0x1e0d18b: 'be2a000000',
    0x1e0d190: 'b914000000',
    0x1e0d198: 'ff15825f9603',
    0x1e0d1a4: 'e847d67900',
    0x27b2a2b: '807e0b007420',
    0x27b2a31: '488d358cc9c3fd',
    0x27b2a38: 'ba11000000',
    0x27b2a43: 'e8a87ddfff',
    0x27b2a4b: '4883f8027510',
    0x27b2a51: '4c89f64889da',
    0x27b2a5c: 'e9ff87f2ff',
    0x27b2a61: '48b9000000000000008048890f48894708488957',
    0x26db280: '807a0b007432',
    0x26db28e: 'ba02000000',
    0x26db293: 'e8e8dcecff',
    0x26db2c0: 'ba02000000',
    0x26db2c5: 'e806e9ecff',
    0x26db2d5: '41807e0b0175',
    0x26db2dc: '488d35443fd1fd',
    0x26db2e3: 'ba0c000000',
    0x26db2eb: 'e800f5ecff',
    0x26db2f4: '755d',
    0x26db2fe: '4c89fa',
    0x26db301: 'e87a2175ff',
    0x26db30b: '4c396c2408',
    0x26db310: '7550',
    0x26db312: '41807e0b0175',
    0x26db319: '488d35133fd1fd',
    0x26db320: 'ba13000000',
    0x26db328: 'e8c3f4ecff',
    0x26db331: '7520',
    0x26db333: '4983c718',
    0x26db342: 'e8b9c8f0ff',
    0x26db347: '4c396c2408',
    0x26db34c: '7514',
    0x26db34e: '4c892b',
    0x26db353: '4c8964240848894424104889542418',
    0x26db362: '488b44241848894310488b442408488903488b44241048894308',
    0x26db3a5: '0fb66a1b',
    0x26db3ad: '4080f501',
    0x26db3b1: '40c0e504',
    0x26db3b5: '4080cd82',
    0x26db3d1: '41807e1b0175',
    0x26db3e4: 'c60430ac',
    0x26db3fc: '48b972756e6e696e675f',
    0x26db40a: 'c744300868656170',
    0x26db42f: 'e8ec6474ff',
    0x26db434: '4c39642408',
    0x26db439: '756e',
    0x26db43b: '4983c718',
    0x26db43f: '41807e1b0175',
    0x26db45a: 'c60431b3',
    0x26db472: '0f1005ba3dd1fd',
    0x26db47d: 'c744310f74617465',
    0x26db498: 'e823a3f0ff',
    0x26db49d: '4c39642408',
    0x26db4a2: '7505',
    0x26db4a4: '4c8923',
    0x26db5e4: '488d353c3cd1fd',
    0x26db5ee: 'ba0c000000',
    0x26db5f6: 'e8c5be2700',
    0x26db5fb: '4885c00f852e010000',
    0x26db60e: '488d351e3cd1fd',
    0x26db618: 'ba13000000',
    0x26db61d: 'e86e8b2900',
    0x26db62c: '4883c318',
    0x26db664: 'e837f0f0ff',
    0x26d91b0: '807a0b007432',
    0x26d91be: 'ba03000000',
    0x26d91c3: 'e8b8fdecff',
    0x26d91f0: 'ba03000000',
    0x26d91f5: 'e8d609edff',
    0x26d9205: '41807e0b0175',
    0x26d920c: '488d358b5fd1fd',
    0x26d9213: 'ba0f000000',
    0x26d924a: 'e8f13772ff',
    0x26d9254: '4c396c2408',
    0x26d9259: '0f8595000000',
    0x26d9266: '488d354f0cb3fd',
    0x26d926d: 'ba04000000',
    0x26d9280: '4d8d4714',
    0x26d9298: 'e8938e77ff',
    0x26d929d: '4c396c2408',
    0x26d92a2: '7550',
    0x26d92ab: '488d35fb5ed1fd',
    0x26d92b2: 'ba07000000',
    0x26d92c5: '498b17',
    0x26d92d0: 'e8fb2dedff',
    0x26d92da: '4883f802',
    0x26d92de: '753f',
    0x26d8ec7: '0fb66a1b',
    0x26d8ecf: '4080f501',
    0x26d8ed3: '40c0e504',
    0x26d8ed7: '4080cd83',
    0x26d8ef3: '4d8d6f08',
    0x26d8f22: '48b96963655f74696d65',
    0x26d8f31: '48b96e6578745f736c69',
    0x26d8f6b: 'e8303c72ff',
    0x26d8f70: '4c3924240f',
    0x26d8f74: '0f85ca000000',
    0x26d8f7a: '4d8d4714',
    0x26d8fb1: 'c7043175736572',
    0x26d8fd2: 'e8495f77ff',
    0x26d8fd7: '4c39242475',
    0x26d8fdb: '7567',
    0x26d9010: 'c7443103705f6964',
    0x26d9018: 'c7043174776170',
    0x26d9027: '498b17',
    0x26d9030: 'e80b2dedff',
    0x1e2d499: '4c8b7208488b5210',
    0x1e2d4a1: '488d04d500000000488d2c8048',
    0x1e2d4c4: '4885d241bc28000000',
    0x1e2d548: 'e843bc8a00',
    0x1e2d579: 'e812bc8a00',
    0x1e2d58c: '4983c428',
    0x1e21939: '4c8b7208488b5210',
    0x1e21941: '488d04d500000000488d2c8048',
    0x1e219e8: 'e8c3748b00',
    0x1e21a19: 'e892748b00',
    0x1e21a2c: '4983c428',
    0x25e7c6a: 'e8f1b3f7ff',
    0x25e7c78: 'e863ca83ff',
    0x25e582a: 'e831d8f7ff',
    0x25e5838: 'e8639583ff',
    0x26c0260: '4889f84883fa13742b4883fa0c754e',
    0x26c026f: '48b972756e6e696e675f',
    0x26c0279: '48330e8b56084881f2686561704809ca',
    0x26c028b: '31c9884801c60009c3',
    0x26c0294: 'f30f6f06f30f6f4e03660f740d8b71b4fd660f74059371b4fd660fdbc1660fd7c881',
    0x26c02bd: 'b102884801c60009c3b101884801c60009c3',
    0x16f6b76: '4989ff4c8b7610498d041e4889461048894e18488d7c24204c89f64889daff155e780704837c2420017530',
    0x16f6bde: 'e87d96fc00',
    0x1907027: '488d2dc2bfa3fe',
    0x190706e: 'e8bdf7deff',
    0x190707f: '4180fc090f858e0a0000',
    0x190708f: '48634485004801e8ff',
    0x1907099: '4883bc24e0000000000f850b0a0000',
    0x19070b7: 'e8946ef3ff',
    0x19070e4: '0f8456ffffff',
    0x190710b: 'ba01000000',
    0x1907110: 'e8bb110600',
    0x190712a: '4c8b7c242848b800000000000000804939c70f85b30a0000',
    0x190714f: 'e80c74e1ff',
    0x1907193: '488b44242848b900000000000000804839c80f851a010000',
    0x19071ab: '488d05d5a4aafe',
    0x19071ba: '48c78424b80000000c000000',
    0x19071e5: '488d3507878dfe',
    0x19072d4: '83bc24e000000001',
    0x19072dc: '7516',
    0x1907304: '488d0588a3aafe',
    0x1907313: '48c78424b800000013000000',
    0x190733e: '488d35ae858dfe',
    0x19074c3: '85ed0f8449020000',
    0x19074d5: 'e88670e1ff',
    0x19074fb: '83fd01757c',
    0x190758e: 'e8bd69f3ff',
    0x19075fd: '83fd020f85c8000000',
    0x1907ab3: '488d05d99baafe',
    0x1907ac2: '48c78424b800000013000000',
    0x1907aed: '488d35e1948dfe',
    0x1907bf5: '488d058b9aaafe',
    0x1907c04: '48c78424b80000000c000000',
    0x1907c2f: '488d359f938dfe',
    0x27b2a2f: '7420',
    0x27b2a4f: '7510',
    0x19070a2: '0f850b0a0000',
    0x190713c: '0f85b30a0000',
    0x19071a5: '0f851a010000',
    0x19074c5: '0f8449020000',
    0x19074fe: '757c',
    0x1907600: '0f85c8000000',
    0x26db5fe: '0f852e010000',
    0x26db608: '0f8433010000',
    0x26db626: '0f8459010000',
    0x26db66c: '0f85c0000000',
}

# Only the specified instruction forms are interpreted, not a general decoder.
EDGES = {
    0x171ec97: 0x19bdf90, 0x171ecbc: 0x171ed26,
    0x19bf667: 0x26bfd80, 0x19bf832: 0x19bfbc6,
    0x19bf852: 0x19bfde8, 0x19bf86f: 0x16bcd60,
    0x19bf8a0: 0x19bfdba, 0x19bf8b1: 0x16844a0,
    0x19bf8f2: 0x19682d0, 0x19bf923: 0x19bfdd1,
    0x19bf973: 0x190f5b0,
    0x27b0e90: 0x2974190, 0x27b0eca: 0x26db590,
    0x1dfcaa1: 0x1dfcb38, 0x1dfcabb: 0x1dfcb38,
    0x1dfcad1: 0x1dfcb38, 0x1dfcae8: 0x25aa7f0,
    0x1dfcafb: 0x1dfcb0b, 0x1dfcc01: 0x1dfcc98,
    0x1dfcc1b: 0x1dfcc98, 0x1dfcc31: 0x1dfcc98,
    0x1dfcc48: 0x25aacb0,
    0x16f695c: 0x16f6b5e, 0x16f6b5c: 0x16f6b76,
    0x1e24747: 0x25a9bd0, 0x1e2479f: 0x1df5c70,
    0x1e248ce: 0x1df5c70, 0x1e1ee1c: 0x25a9aa0,
    0x1e1ee68: 0x1e053c0, 0x1e1eead: 0x1e053c0,
    0x1df5cda: 0x25a9bd0, 0x1df5d25: 0x1e0d0a0,
    0x1df5d33: 0x1df5e2b, 0x1df5d57: 0x25e75c0,
    0x1df5dbc: 0x1e0d6c0, 0x1df5dca: 0x1df5e04,
    0x1df5dec: 0x25e9ce0, 0x1e05438: 0x1e0d6c0,
    0x1e05446: 0x1e0547a, 0x1e05462: 0x25e7090,
    0x1e0d1a4: 0x25aa7f0,
    0x27b2a43: 0x25aa7f0, 0x27b2a5c: 0x26db260,
    0x26db293: 0x25a8f80, 0x26db2c5: 0x25a9bd0,
    0x26db2eb: 0x25aa7f0, 0x26db301: 0x1e2d480,
    0x26db328: 0x25aa7f0, 0x26db342: 0x25e7c00,
    0x26db2f4: 0x26db353, 0x26db310: 0x26db362,
    0x26db331: 0x26db353, 0x26db34c: 0x26db362,
    0x26db42f: 0x1e21920, 0x26db498: 0x25e57c0,
    0x26db439: 0x26db4a9, 0x26db4a2: 0x26db4a9,
    0x26d91c3: 0x25a8f80, 0x26d91f5: 0x25a9bd0,
    0x26d924a: 0x1dfca40, 0x26d9298: 0x1e52130,
    0x26d92d0: 0x25ac0d0, 0x26d9259: 0x26d92f4,
    0x26d92a2: 0x26d92f4, 0x26d92de: 0x26d931f,
    0x26d8f6b: 0x1dfcba0, 0x26d8fd2: 0x1e4ef20,
    0x26d9030: 0x25abd40, 0x26d8f74: 0x26d9044,
    0x26d8fdb: 0x26d9044,
    0x1e2d548: 0x26d9190, 0x1e2d579: 0x26d9190,
    0x1e219e8: 0x26d8eb0, 0x1e21a19: 0x26d8eb0,
    0x25e7c6a: 0x2563060, 0x25e7c78: 0x1e246e0,
    0x25e582a: 0x2563060, 0x25e5838: 0x1e1eda0,
    0x16f6bde: 0x26c0260, 0x190706e: 0x16f6830,
    0x19070b7: 0x183df50, 0x19070e4: 0x1907040,
    0x1907110: 0x19682d0, 0x190714f: 0x171e560,
    0x26db5f6: 0x29574c0, 0x26db61d: 0x2974190,
    0x26db664: 0x25ea6a0,
    0x27b2a2f: 0x27b2a51, 0x27b2a4f: 0x27b2a61,
    0x19070a2: 0x1907ab3, 0x190713c: 0x1907bf5,
    0x19071a5: 0x19072c5, 0x19072dc: 0x19072f4,
    0x19074c5: 0x1907714, 0x19074fe: 0x190757c,
    0x1907600: 0x19076ce,
    0x26db5fe: 0x26db732, 0x26db608: 0x26db741,
    0x26db626: 0x26db785, 0x26db66c: 0x26db732,
}


def verify_digest(data):
    if hashlib.sha256(data).hexdigest() != DIGEST:
        raise ValueError('node 94 SHA-256 mismatch')


class Image:
    def __init__(self, data):
        self.data = data
        self.sections = elf_index.sections(data)

    def offset(self, va, size, executable=False):
        if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
            raise ValueError('invalid range')
        found = [s for s in self.sections if s['type'] != 8 and
                 s['address'] <= va and va + size <= s['address'] + s['size'] and
                 (not executable or s['flags'] & 4)]
        if len(found) != 1:
            raise ValueError('range is not uniquely file backed')
        return found[0]['offset'] + va - found[0]['address']

    def read(self, va, size, executable=False):
        off = self.offset(va, size, executable)
        return self.data[off:off + size]


def require_pin(img, va, expected):
    raw = img.read(va, len(expected), True)
    if raw != expected:
        raise ValueError('instruction window mismatch at ' + hex(va))
    return raw


def relative_target(img, va):
    first = img.read(va, 1, True)[0]
    if first in (0xe8, 0xe9):
        raw = img.read(va, 5, True)
        return va + 5 + struct.unpack_from('<i', raw, 1)[0]
    if 0x70 <= first <= 0x7f:
        raw = img.read(va, 2, True)
        return va + 2 + struct.unpack_from('<b', raw, 1)[0]
    if first == 0x0f:
        raw = img.read(va, 6, True)
        if 0x80 <= raw[1] <= 0x8f:
            return va + 6 + struct.unpack_from('<i', raw, 2)[0]
    raise ValueError('unsupported relative instruction')


def rip_target(img, va, prefix, size):
    raw = img.read(va, size, True)
    if not raw.startswith(prefix) or len(prefix) != size - 4:
        raise ValueError('unexpected RIP-relative instruction')
    return va + size + struct.unpack_from('<i', raw, size - 4)[0]


def length_imm(img, va, prefix):
    raw = img.read(va, len(prefix) + 4, True)
    if not raw.startswith(prefix):
        raise ValueError('unexpected immediate setup')
    return struct.unpack_from('<I', raw, len(prefix))[0]


def relative_relocation(img, slot):
    sections = [s for s in img.sections if s['name'] == '.rela.dyn' and s['type'] == 4]
    if len(sections) != 1 or sections[0]['size'] % 24:
        raise ValueError('invalid relocation section')
    section = sections[0]
    matches = []
    for off in range(section['offset'], section['offset'] + section['size'], 24):
        address, info, addend = struct.unpack_from('<QQq', img.data, off)
        if address == slot:
            matches.append((info, addend))
    if len(matches) != 1 or matches[0][0] != 8:
        raise ValueError('slot does not have one R_X86_64_RELATIVE relocation')
    return matches[0][1]


def classify(key, names, codes):
    # Represents only the fixed-length exact byte comparisons of 0x26c0260.
    if key == names[0]:
        return codes[0]
    if key == names[1]:
        return codes[1]
    return codes[2]


def classify_item(key, names):
    for index, name in enumerate(names):
        if key == name:
            return index
    return 3


def length_fits(remaining, length):
    # Model the unsigned subtract-and-borrow test, not an input parser.
    if not (0 <= remaining < 1 << 64 and 0 <= length < 1 << 64):
        raise ValueError('length outside unsigned 64-bit range')
    return remaining >= length


def map_step(presence, code):
    # Abstract state: bit 0 = heap seen, bit 1 = map seen. The target uses
    # a sentinel and a separate flag; this model does not claim their layout.
    if presence not in range(4) or code not in range(4):
        raise ValueError('invalid abstract reader state')
    if code == 2:
        return presence, 'unknown_value'
    if code == 3:
        if not presence & 1:
            return presence, 'missing_heap'
        if not presence & 2:
            return presence, 'missing_map'
        return presence, 'complete'
    bit = 1 << code
    if presence & bit:
        return presence, 'duplicate_heap' if code == 0 else 'duplicate_map'
    return presence | bit, 'read_heap' if code == 0 else 'read_map'


def sequence_arity(count):
    if type(count) is not int or count < 0 or count >= 1 << 32:
        raise ValueError('invalid sequence count')
    if count == 0:
        return 'missing_first'
    if count == 1:
        return 'missing_second'
    if count == 2:
        return 'two_values'
    return 'excess_values'


def collect(data):
    verify_digest(data)
    img = Image(data)
    _, fdes, _ = fde_extents.fde_extents(data)
    by_start = {}
    for fde in fdes:
        if fde['start'] in by_start:
            raise ValueError('duplicate FDE start')
        by_start[fde['start']] = fde
    functions = []
    for name, (start, end) in sorted(FUNCTIONS.items(), key=lambda item: item[1][0]):
        f = by_start.get(start)
        if f is None or f['end'] != end or f['section'] != '.text':
            raise ValueError('FDE mismatch for ' + name)
        body = img.read(start, end - start, True)
        functions.append({'name': name, 'start_va': hex(start), 'end_va': hex(end),
                          'size': len(body), 'fde_va': hex(f['fde']),
                          'file_offset': hex(img.offset(start, len(body), True)),
                          'body_sha256': hashlib.sha256(body).hexdigest()})
    rows = []
    for va, encoded in sorted(PINS.items()):
        expected = bytes.fromhex(encoded)
        if sum(a <= va and va + len(expected) <= z for a, z in FUNCTIONS.values()) != 1:
            raise ValueError('pin outside one selected FDE')
        raw = require_pin(img, va, expected)
        row = {'va': hex(va), 'file_offset': hex(img.offset(va, len(raw), True)),
               'bytes': raw.hex()}
        if va in EDGES:
            dst = relative_target(img, va)
            if dst != EDGES[va]:
                raise ValueError('relative target mismatch')
            row['target_va'] = hex(dst)
        rows.append(row)
    if set(EDGES) - set(PINS):
        raise ValueError('unanchored edge')

    literal_sites = [(0x26db2dc, 0x26db2e3), (0x26db319, 0x26db320),
                     (0x26d920c, 0x26d9213), (0x26d9266, 0x26d926d),
                     (0x26d92ab, 0x26d92b2), (0x27b2a31, 0x27b2a38),
                     (0x27b0e84, 0x27b0e8b)]
    literals = []
    for ptr_site, length_site in literal_sites:
        dst = rip_target(img, ptr_site, b'\x48\x8d\x35', 7)
        n = length_imm(img, length_site, b'\xba')
        value = img.read(dst, n).decode('ascii')
        literals.append({'pointer_site_va': hex(ptr_site), 'length_site_va': hex(length_site),
                         'literal_va': hex(dst), 'length': n, 'text': value})
    names = [s['text'].encode('ascii') for s in literals[:2]]
    first = img.read(0x26c0271, 8, True) + img.read(0x26c0282, 4, True)
    x = rip_target(img, 0x26c02a5, b'\x66\x0f\x74\x05', 8)
    y = rip_target(img, 0x26c029d, b'\x66\x0f\x74\x0d', 8)
    left, right = img.read(x, 16), img.read(y, 16)
    if left[3:] != right[:13]:
        raise ValueError('classifier vectors do not overlap')
    second = left + right[13:]
    if [first, second] != names:
        raise ValueError('writer and classifier field names disagree')
    codes = [0, img.read(0x26c02c7, 1, True)[0], img.read(0x26c02be, 1, True)[0]]
    if codes != [0, 1, 2]:
        raise ValueError('unexpected field codes')

    # The classifier uses two overlapping 8-byte compares for the 15-byte
    # name, and overlapping 4-byte compares for the 7-byte name.
    item_a, item_b = img.read(0x26bfd97, 8, True), img.read(0x26bfda4, 8, True)
    id_a, id_b = img.read(0x26bfdbf, 4, True), img.read(0x26bfdc6, 4, True)
    if item_a[7:] != item_b[:1] or id_a[3:] != id_b[:1]:
        raise ValueError('item classifier comparisons do not overlap')
    item_names = [item_a + item_b[1:], img.read(0x26bfddc, 4, True), id_a + id_b[1:]]
    if item_names != [s['text'].encode('ascii') for s in literals[2:5]]:
        raise ValueError('item writer and classifier names disagree')
    item_table = rip_target(img, 0x19bf840, b'\x48\x8d\x0d', 7)
    item_dispatch = [item_table + struct.unpack('<i', img.read(item_table + i * 4, 4))[0]
                     for i in range(4)]
    if item_dispatch != [0x19bf850, 0x19bf91b, 0x19bf897, 0x19bf8e2]:
        raise ValueError('item dispatch mismatch')

    table_va = rip_target(img, 0x1907027, b'\x48\x8d\x2d', 7)
    end_code = img.read(0x16f68a1, 1, True)[0]
    dispatch = [table_va + struct.unpack('<i', img.read(table_va + i * 4, 4))[0]
                for i in (*codes, end_code)]
    if end_code != 3 or dispatch != [0x190712a, 0x1907099, 0x1907100, 0x1907193]:
        raise ValueError('field dispatch mismatch')

    # The two formatter paths use separate counted field names. Retain the
    # diagnostic fragments as evidence, without assuming the full formatter.
    errors = []
    for kind, pointer_site, length_site, template_site in [
        ('missing_heap', 0x19071ab, 0x19071ba, 0x19071e5),
        ('missing_map', 0x1907304, 0x1907313, 0x190733e),
        ('duplicate_heap', 0x1907bf5, 0x1907c04, 0x1907c2f),
        ('duplicate_map', 0x1907ab3, 0x1907ac2, 0x1907aed),
    ]:
        field_va = rip_target(img, pointer_site, b'\x48\x8d\x05', 7)
        raw = img.read(length_site, 12, True)
        if raw[:8] != bytes.fromhex('48c78424b8000000'):
            raise ValueError('invalid error field length setup')
        length = struct.unpack_from('<I', raw, 8)[0]
        field = img.read(field_va, length).decode('ascii')
        template_va = rip_target(img, template_site, b'\x48\x8d\x35', 7)
        fragment_length = img.read(template_va, 1)[0]
        fragment = img.read(template_va + 1, fragment_length).decode('ascii')
        expected_field = names[0 if kind.endswith('heap') else 1].decode('ascii')
        expected_fragment = 'missing field `' if kind.startswith('missing') else 'duplicate field `'
        if field != expected_field or fragment != expected_fragment:
            raise ValueError('unexpected field error fragments')
        errors.append({'case': kind, 'field': field, 'field_va': hex(field_va),
                       'field_length': length, 'prefix': fragment,
                       'prefix_va': hex(template_va), 'prefix_length': fragment_length})

    item_errors = []
    for kind, pointer_site, length_site, template_site, field_index in [
        ('missing_time', 0x19be45a, 0x19be469, 0x19be48e, 0),
        ('missing_user', 0x19bf034, 0x19bf043, 0x19bf068, 1),
        ('missing_id', 0x19bf111, 0x19bf120, 0x19bf145, 2),
        ('duplicate_time', 0x19bfde8, 0x19bfdf4, 0x19bfe18, 0),
        ('duplicate_user', 0x19bfdd1, 0x19bfddd, 0x19bfe18, 1),
        ('duplicate_id', 0x19bfdba, 0x19bfdc6, 0x19bfe18, 2),
    ]:
        field_va = rip_target(img, pointer_site, b'\x48\x8d\x05', 7)
        if kind.startswith('missing'):
            raw, prefix_length = img.read(length_site, 12, True), 8
            expected = bytes.fromhex('48c7842488000000')
        else:
            raw, prefix_length = img.read(length_site, 9, True), 5
            expected = bytes.fromhex('48c7442438')
        if raw[:prefix_length] != expected:
            raise ValueError('invalid item error field length setup')
        length = struct.unpack_from('<I', raw, prefix_length)[0]
        field = img.read(field_va, length).decode('ascii')
        template_va = rip_target(img, template_site, b'\x48\x8d\x35', 7)
        fragment_length = img.read(template_va, 1)[0]
        fragment = img.read(template_va + 1, fragment_length).decode('ascii')
        expected_fragment = 'missing field `' if kind.startswith('missing') else 'duplicate field `'
        if field.encode('ascii') != item_names[field_index] or fragment != expected_fragment:
            raise ValueError('unexpected item field error fragments')
        item_errors.append({'case': kind, 'field': field, 'field_va': hex(field_va),
                            'field_length': length, 'prefix': fragment,
                            'prefix_va': hex(template_va), 'prefix_length': fragment_length})

    xor = img.read(0x26db3b0, 1, True)[0]
    shift = img.read(0x26db3b4, 1, True)[0]
    base = img.read(0x26db3b8, 1, True)[0]
    item_xor = img.read(0x26d8ed2, 1, True)[0]
    item_shift = img.read(0x26d8ed6, 1, True)[0]
    item_base = img.read(0x26d8eda, 1, True)[0]
    heap_stride = img.read(0x1e2d58f, 1, True)[0]
    compact_heap_stride = img.read(0x1e21a2f, 1, True)[0]
    tree_row_stride = img.read(0x1e248e4, 1, True)[0]
    pair_marker = img.read(0x1df5d83, 1, True)[0]
    compact_pair_marker = img.read(0x1e053ff, 1, True)[0]
    key_input_length = length_imm(img, 0x1e0d190, b'\xb9')
    key_buffer_length = length_imm(img, 0x1e0d18b, b'\xbe')
    formatter_slot = rip_target(img, 0x1e0d198, b'\xff\x15', 6)
    formatter_target = relative_relocation(img, formatter_slot)
    if (formatter_slot, formatter_target) != (0x5773120, 0x29ed380):
        raise ValueError('unexpected key formatter relocation')
    time_slots = [rip_target(img, va, b'\xff\x15', 6)
                  for va in (0x1dfca99, 0x1dfcac9, 0x1dfcbf9, 0x1dfcc29)]
    time_targets = [relative_relocation(img, slot) for slot in time_slots]
    if time_slots != [0x576f560, 0x576f568] * 2 or time_targets != [0x151f240, 0x15204a0] * 2:
        raise ValueError('unexpected time formatting slots')
    time_separator = length_imm(img, 0x1dfcab1, b'\xbe')
    compact_separator = length_imm(img, 0x1dfcc11, b'\xbe')
    if time_separator != ord('T') or compact_separator != time_separator:
        raise ValueError('unexpected time separator')
    panic_va = rip_target(img, 0x1dfcb38, b'\x48\x8d\x3d', 7)
    panic_length = length_imm(img, 0x1dfcb52, b'\xbe')
    panic_text = img.read(panic_va, panic_length).decode('ascii')
    if (heap_stride, compact_heap_stride, tree_row_stride, pair_marker,
            compact_pair_marker, key_input_length, key_buffer_length) != (40, 40, 16, 146, 146, 20, 42):
        raise ValueError('unexpected sequence or pair layout')
    def header(flag):
        return (((flag ^ xor) << shift) | base) & 0xff
    def item_header(flag):
        return (((flag ^ item_xor) << item_shift) | item_base) & 0xff
    controls = []
    for code, name in enumerate(names):
        controls.append({'case': 'valid_' + str(code), 'hex': name.hex(),
                         'code': classify(name, names, codes)})
        controls.append({'case': 'changed_' + str(code),
                         'hex': (bytes([name[0] ^ 1]) + name[1:]).hex(),
                         'code': classify(bytes([name[0] ^ 1]) + name[1:], names, codes)})
        controls.append({'case': 'short_' + str(code), 'hex': name[:-1].hex(),
                         'code': classify(name[:-1], names, codes)})
    evidence = {'target_sha256': DIGEST, 'coordinate_system': 'ELF link-time virtual address',
                'functions': functions, 'literals': literals,
                'classifier': {'field_names': [n.decode() for n in names], 'codes': codes,
                               'end_of_map_code': end_code,
                               'vector_vas': [hex(x), hex(y)],
                               'dispatch_table_va': hex(table_va),
                               'dispatch_targets': [hex(a) for a in dispatch]},
                'item_classifier': {'field_names': [n.decode() for n in item_names],
                                    'codes': [0, 1, 2, 3],
                                    'dispatch_table_va': hex(item_table),
                                    'dispatch_targets': [hex(a) for a in item_dispatch]},
                'field_errors': errors,
                'item_field_errors': item_errors,
                'reader_model': {
                    'map_steps': [{'presence_before': present, 'code': code,
                                   'presence_after': map_step(present, code)[0],
                                   'decision': map_step(present, code)[1]}
                                  for present in range(4) for code in range(4)],
                    'sequence_arity': [{'count': n, 'decision': sequence_arity(n)}
                                       for n in range(4)]},
                'length_guard': {'subtract_va': hex(0x16f6959),
                                 'borrow_branch_va': hex(0x16f695c),
                                 'short_input_target_va': hex(relative_target(img, 0x16f695c)),
                                 'error_word': struct.unpack('<Q', img.read(0x16f6b64, 8, True))[0],
                                 'model': [{'remaining': a, 'length': b,
                                            'fits': length_fits(a, b)}
                                           for a, b in [(0, 0), (0, 1), (11, 12),
                                                        (12, 12), (13, 12)]]},
                'compact_header': {'xor': xor, 'shift': shift, 'or': base,
                                   'flag_0': header(0), 'flag_1': header(1)},
                'compact_item_header': {'xor': item_xor, 'shift': item_shift,
                                        'or': item_base, 'flag_0': item_header(0),
                                        'flag_1': item_header(1)},
                'layout': {'heap_stride': heap_stride,
                           'compact_heap_stride': compact_heap_stride,
                           'outer_tree_row_stride': tree_row_stride,
                           'pair_marker': pair_marker,
                           'compact_pair_marker': compact_pair_marker,
                           'key_input_length': key_input_length,
                           'key_format_buffer_length': key_buffer_length,
                           'formatter_slot_va': hex(formatter_slot),
                           'formatter_relocation_target_va': hex(formatter_target)},
                'time_text': {'separator': chr(time_separator),
                              'helper_slots': [hex(a) for a in time_slots],
                              'helper_relocation_targets': [hex(a) for a in time_targets],
                              'failure_text_va': hex(panic_va),
                              'failure_text_length': panic_length,
                              'failure_text': panic_text},
                'pin_count': len(rows), 'relative_edge_count': len(EDGES),
                'control_model': controls,
                'limitations': 'Static fixed-pattern facts only; no target execution, full parser, fixture or whole-component claim.'}
    return evidence, rows


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, required=True)
    args = p.parse_args()
    data = BINARY.read_bytes()
    evidence, rows = collect(data)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'tracker-evidence.json').write_text(json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
    with (args.out / 'instruction-windows.tsv').open('w', encoding='utf-8', newline='') as f:
        f.write('va\tfile_offset\tbytes\ttarget_va\n')
        for row in rows:
            f.write('\t'.join([row['va'], row['file_offset'], row['bytes'], row.get('target_va', '')]) + '\n')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, struct.error) as exc:
        print('twap_tracker_wire94: ' + str(exc), file=sys.stderr)
        raise SystemExit(1)
