#!/usr/bin/env python3
"""Static packet for the RE-006 node-#115 variant cursor searches.

The cursor-search packet pinned the two byte-identical 143-byte clones and
the three call sites through which its two callers reach the variant
searches at 0x35bd660 and 0x35bd800, but left the variants themselves - and
their other twenty-three call sites - unexamined.  This module pins both
variant bodies: the first reads up to twenty-two u64 keys per node from
+0x8 with child edges from +0xc0; the second reads up to eleven u64 keys
from +0x168 with child edges from +0x1c8.  It then censuses every direct
call site of either variant (twenty-six sites in eighteen caller FDEs),
what each caller reads from the returned record - in particular whether
any consumer reads the record's height field - and the whole
epilogue-signature family of cursor searches the variants belong to.

Everything here is a byte-level check against the authenticated node #115
ELF.  Regeneration writes records.json, frames.txt, MANIFEST.sha256 and
the per-owner disassembly exports under
research/work-items/RE-006-node115-variant-cursor/.
"""

from __future__ import annotations

import hashlib
import json
import os
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

PACKET_NAME = 'RE-006-node115-variant-cursor'
PACKET_DIR = ROOT / 'research' / 'work-items' / PACKET_NAME
ARTIFACT = ROOT / 'artifacts' / 'node' / '115' / 'hl-node'
ARTIFACT_SHA256 = (
    'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301')
EXPECTED_FDE_RECORDS = 135313

# The two variant bodies.  Both are 146 bytes, call-free, and store only
# the four record fields.  Variant A keeps the clone key base (+0x8) but
# widens the node to twenty-two keys (count word at +0xba, child edges
# from +0xc0).  Variant B keeps eleven keys but shifts the whole key
# block behind a 0x160-byte head (keys from +0x168, count word at +0x1c2,
# child edges from +0x1c8).  The child-index offsets (+0xb8 / +0x1c0)
# follow the layout pair the count word forms with the word below it in
# every family member; the search bodies themselves never read them.
OWNERS = {
    'variant_search_a': {
        'range': (0x35BD660, 0x35BD6F2),
        'sha256': (
            '3da45a31a814e5cb8c3b77323c8c550b760ad8a76aadc94048d13e'
            '54a3c16950'),
        'layout': {
            'key_kind': 'u64',
            'keys_base': '0x8',
            'key_capacity': 22,
            'child_index_offset': '0xb8',
            'count_offset': '0xba',
            'edges_base': '0xc0',
        },
        'pins': {
            0x35BD660: '4889f8',
            0x35BD663: '488b09',
            0x35BD666: '440fb786ba000000',
            0x35BD680: '4d85c9',
            0x35BD685: '483b4cfe10',
            0x35BD68A: '410f97c2',
            0x35BD68E: '4180da00',
            0x35BD6C0: '4c89c7',
            0x35BD6CC: '488bb4fec0000000',
            0x35BD6D9: '31c9',
            0x35BD6DB: '48897008',
            0x35BD6DF: '48895010',
            0x35BD6E3: '48897818',
            0x35BD6E7: '488908',
            0x35BD6EB: 'b901000000',
        },
        'calls': {},
    },
    'variant_search_b': {
        'range': (0x35BD800, 0x35BD892),
        'sha256': (
            '100afb1aa917741ca80b4efc1505a123a89cce43457beb3eaa47b5'
            'b75437191b'),
        'layout': {
            'key_kind': 'u64',
            'keys_base': '0x168',
            'key_capacity': 11,
            'child_index_offset': '0x1c0',
            'count_offset': '0x1c2',
            'edges_base': '0x1c8',
        },
        'pins': {
            0x35BD800: '4889f8',
            0x35BD803: '488b09',
            0x35BD806: '440fb786c2010000',
            0x35BD820: '4d85c9',
            0x35BD825: '483b8cfe70010000',
            0x35BD82D: '410f97c2',
            0x35BD831: '4180da00',
            0x35BD860: '4c89c7',
            0x35BD86C: '488bb4fec8010000',
            0x35BD879: '31c9',
            0x35BD87B: '48897008',
            0x35BD87F: '48895010',
            0x35BD883: '48897818',
            0x35BD887: '488908',
            0x35BD88B: 'b901000000',
        },
        'calls': {},
    },
}

# The eighteen caller FDEs that contain at least one variant call site,
# plus the sibling family member 0x35bf460, whose calls overwrite the
# variant record in three of the callers before it is ever read.
BOUNDARIES = {
    'caller_0x23795c0': (
        0x23795C0, 0x2379B6B,
        'a8bd71e4ae8f0e119d89a42f4362cb11c3f8241ef53fdf0ef6609f5bc1d66a82'),
    'caller_0x2667140': (
        0x2667140, 0x2668202,
        '63f3519ea3be1917603aad0fba34df41e08416d72020c79633aa35c1f3aac3e2'),
    'caller_0x2a84e60': (
        0x2A84E60, 0x2A8829E,
        '7bca2f033becd6f8a8f0d184a434cdd74677915f45e0c9ab31aa61970bbaaace'),
    'caller_0x2a89500': (
        0x2A89500, 0x2A8A000,
        'd33c9906f43bb0c54ab7cf6a21f3b8cd465f135cb9716ea7e4991eefafbb2aa0'),
    'caller_0x2a918f0': (
        0x2A918F0, 0x2A92959,
        '4b858d7e2687993cf369c5518ab73844e8528600ed1c5425bb2e2cb2ba724c03'),
    'caller_0x2c4fe30': (
        0x2C4FE30, 0x2C506E1,
        '49da618c9e3421150b8bb2fb559add550ad3ae65d2c6b5b71699093ebdd855a9'),
    'caller_0x2c61b30': (
        0x2C61B30, 0x2C622E7,
        'fb6986607aeb4f699ed29f505bba328b2ea171995bccc10fd3e418dbed54a2b1'),
    'caller_0x2c6b3b0': (
        0x2C6B3B0, 0x2C6BAC5,
        '8d93c2699a7c8140145b66aabd49987c1d21a4d0791c4383b8380341914add78'),
    'caller_0x3d987f0': (
        0x3D987F0, 0x3D98B32,
        '5d854b54497e96900803e5c4f62820c393a337058dde98bd6be8abcf580e7990'),
    'caller_0x5582180': (
        0x5582180, 0x5585283,
        '0dce413fbb40e408ffca0831ec0ee804509e99cbde0b23f565bbb9b71dd2f19f'),
    'caller_0x5585290': (
        0x5585290, 0x5588393,
        '0c80314b405562e1053ce3a5195ee216628d43b51d5e84e4833c900b19fe051a'),
    'caller_0x55a07e0': (
        0x55A07E0, 0x55A12E0,
        '41e588d7db79f90108f6981acc95af94e2534e68a0aa570c5f0270ece139ec5d'),
    'caller_0x55a12e0': (
        0x55A12E0, 0x55A1DE0,
        '1c2af67af44f5fe0dcb0eb706c5b9c2db8d4793c5ac01475387cfe160a6cf0ba'),
    'caller_0x55bd810': (
        0x55BD810, 0x55BE0C1,
        '3b57611a1ec2b90a6e3a2843cf8c3b93ce3ec33a224cfb1dd514daf670298a09'),
    'caller_0x55be0d0': (
        0x55BE0D0, 0x55BE981,
        '37b135c9b39e7455a68231bc95ed65ffaaee13076c0cdeb5dfa4c4e4eb61ab7f'),
    'caller_0x55f8b70': (
        0x55F8B70, 0x55F9285,
        '2c4ec9b08b1fb8051004159b128ee63201e035a19326156dfebba6616956f932'),
    'caller_0x55f9290': (
        0x55F9290, 0x55F99A5,
        '5981e56a3a4ad2cc929547eec03011384cbd678e429662a87724647c25550e90'),
    'caller_0x5b810d0': (
        0x5B810D0, 0x5B816D9,
        '46d1c2e8aa3b110924f8af2232fa4907ac329be8ec881e1e83280317353b8515'),
    'sibling_search_0x35bf460': (
        0x35BF460, 0x35BF4F2,
        '10b3b34cb2182f4c9bba0efbb6750ada3ec101615535406c3663df2b09f840ca'),
}

# Caller windows: handle setup, the call, and the instructions that read
# the record back.  Each window starts and ends on an instruction
# boundary of its caller FDE and tiles exactly under the decoder.
WINDOWS = {
    # The three windows the cursor-search packet already pinned, kept
    # byte-identical; the other twenty-three variant sites are new.
    'caller_0x23795c0_site_1': {
        'range': (0x2379725, 0x2379765),
        'pins': {
            0x2379725: '498bb7f8000000',
            0x2379731: '498b9700010000',
            0x2379738: '488d7c2468',
            0x237973D: '488d4c2420',
            0x2379747: '837c246801',
            0x237974E: '488b442470',
            0x2379753: '488b8c2480000000',
        },
        'calls': {0x2379742: 0x35BD660},
    },
    'caller_0x23795c0_site_2': {
        'range': (0x237999A, 0x23799E3),
        'pins': {
            0x237999A: '488bb2f8000000',
            0x23799AF: '488b9000010000',
            0x23799B6: '488d7c2468',
            0x23799BB: '488d4c2418',
            0x23799C5: '837c246801',
            0x23799CC: '488b442470',
            0x23799D1: '488b8c2480000000',
        },
        'calls': {0x23799C0: 0x35BD660},
    },
    'caller_0x2667140_site_1': {
        'range': (0x2667AA0, 0x2667AD3),
        'pins': {
            0x2667AA0: '498bb7404b0000',
            0x2667AAC: '498b97484b0000',
            0x2667AB3: '488dbc2440010000',
            0x2667ABB: '488d4c2450',
            0x2667AC5: '80bc244001000000',
        },
        'calls': {0x2667AC0: 0x35BD800},
    },
    'caller_0x2c4fe30_site_1': {
        'range': (0x2C500F8, 0x2C50149),
        'pins': {
            0x2C500F8: '488dbd28040000',
            0x2C50107: '488bb530040000',
            0x2C50113: '488b9538040000',
            0x2C5011A: '488d7c2420',
            0x2C5011F: '488d8c2410010000',
            0x2C5012C: '837c242001',
            0x2C50137: '488b442428',
            0x2C5013C: '488b4c2438',
            0x2C50141: '488d04c8',
            0x2C50145: '4883c060',
        },
        'calls': {0x2C50127: 0x35BD660},
    },
    'caller_0x3d987f0_site_1': {
        'range': (0x3D98833, 0x3D98905),
        'pins': {
            0x3D98833: '498bb424f8000000',
            0x3D98847: '498b942400010000',
            0x3D9884F: '488d7c2430',
            0x3D98854: '488d4c2418',
            0x3D9885E: '837c243001',
            0x3D988F3: '488b442438',
            0x3D988F8: '488b4c2448',
            0x3D988FD: '488d04c8',
            0x3D98901: '4883c060',
        },
        'calls': {0x3D98859: 0x35BD660},
    },
    # A follow-on phase of the same caller copies the record's node into
    # a working slot and loads its height field into rbp.
    'caller_0x3d987f0_height_load': {
        'range': (0x3D989A6, 0x3D989B5),
        'pins': {
            0x3D989A6: '488b442438',
            0x3D989AB: '4889442408',
            0x3D989B0: '488b6c2440',
        },
        'calls': {},
    },
    'caller_0x55bd810_site_1': {
        'range': (0x55BDAD8, 0x55BDB29),
        'pins': {
            0x55BDAD8: '488dbd28040000',
            0x55BDAE7: '488bb530040000',
            0x55BDAF3: '488b9538040000',
            0x55BDAFA: '488d7c2420',
            0x55BDAFF: '488d8c2410010000',
            0x55BDB0C: '837c242001',
            0x55BDB17: '488b442428',
            0x55BDB1C: '488b4c2438',
            0x55BDB21: '488d04c8',
            0x55BDB25: '4883c060',
        },
        'calls': {0x55BDB07: 0x35BD660},
    },
    'caller_0x55be0d0_site_1': {
        'range': (0x55BE398, 0x55BE3E9),
        'pins': {
            0x55BE398: '488dbd28040000',
            0x55BE3A7: '488bb530040000',
            0x55BE3B3: '488b9538040000',
            0x55BE3BA: '488d7c2420',
            0x55BE3BF: '488d8c2410010000',
            0x55BE3CC: '837c242001',
            0x55BE3D7: '488b442428',
            0x55BE3DC: '488b4c2438',
            0x55BE3E1: '488d04c8',
            0x55BE3E5: '4883c060',
        },
        'calls': {0x55BE3C7: 0x35BD660},
    },
    'caller_0x5b810d0_site_1': {
        'range': (0x5B8122F, 0x5B812A5),
        'pins': {
            0x5B8122F: '498dbdf0000000',
            0x5B8125B: '498bb5f8000000',
            0x5B81270: '488b9000010000',
            0x5B81277: '488d7c2478',
            0x5B8127C: '488d4c2418',
            0x5B81286: '837c247801',
            0x5B8128D: '488b842480000000',
            0x5B81295: '488b8c2490000000',
            0x5B8129D: '488d04c8',
            0x5B812A1: '4883c060',
        },
        'calls': {0x5B81281: 0x35BD660},
    },
    'caller_0x5b810d0_site_2': {
        'range': (0x5B8150D, 0x5B8155B),
        'pins': {
            0x5B8150D: '488bb2f8000000',
            0x5B81522: '488b9000010000',
            0x5B81529: '488d7c2478',
            0x5B8152E: '488d4c2458',
            0x5B81538: '837c247801',
            0x5B81543: '488b842480000000',
            0x5B8154B: '488b8c2490000000',
            0x5B81553: '488d04c8',
            0x5B81557: '4883c060',
        },
        'calls': {0x5B81533: 0x35BD660},
    },
    'caller_0x2a84e60_site_1': {
        'range': (0x2A8683F, 0x2A86883),
        'pins': {
            0x2A8683F: '498b7708',
            0x2A8684C: '498b5710',
            0x2A86850: '488dbc24d0000000',
            0x2A86858: '488d8c24e0050000',
            0x2A86865: '83bc24d000000001',
            0x2A8686F: '488b8424e8000000',
            0x2A86877: '48c1e005',
            0x2A8687B: '48038424d8000000',
        },
        'calls': {0x2A86860: 0x35BD800},
    },
    # The same record slot is reused by other phases of this caller; this
    # one is filled by a different call and then read flag/node/height.
    'caller_0x2a84e60_other_record_phase': {
        'range': (0x2A85476, 0x2A854A3),
        'pins': {
            0x2A85476: '488dbc24d0000000',
            0x2A8548B: '4c8bb424d0000000',
            0x2A85493: '4c8bbc24d8000000',
            0x2A8549B: '4c8ba424e0000000',
        },
        'calls': {0x2A85486: 0x22B2450},
    },
    # Site 1 of the 2816-byte caller family: no field of the variant
    # record is read; control joins the sibling search below first.
    'caller_0x2a89500_site_1': {
        'range': (0x2A89823, 0x2A8984E),
        'pins': {
            0x2A89823: '488bb42440010000',
            0x2A89834: '488b942448010000',
            0x2A8983C: '488dbc2480000000',
            0x2A89844: '488d4c2420',
        },
        'calls': {0x2A89849: 0x35BD800},
    },
    'caller_0x2a89500_join_overwrite': {
        'range': (0x2A898EC, 0x2A89933),
        'pins': {
            0x2A898EC: '488bb3d0060000',
            0x2A898FC: '488b93d8060000',
            0x2A89903: '488dbc2480000000',
            0x2A8990B: '488d4c2420',
            0x2A89915: '83bc248000000001',
            0x2A8991F: '4869bc2498000000b0000000',
            0x2A8992B: '4803bc2488000000',
        },
        'calls': {0x2A89910: 0x35BF460},
    },
    'caller_0x2a89500_site_2': {
        'range': (0x2A89A14, 0x2A89A3D),
        'pins': {
            0x2A89A14: '488b742428',
            0x2A89A1E: '488b542430',
            0x2A89A23: '488dbc2480000000',
            0x2A89A2B: '488d4c2460',
            0x2A89A35: '83bc248000000001',
        },
        'calls': {0x2A89A30: 0x35BD800},
    },
    'caller_0x2a89500_site_2_hit': {
        'range': (0x2A89C48, 0x2A89C5C),
        'pins': {
            0x2A89C48: '488b842498000000',
            0x2A89C50: '48c1e005',
            0x2A89C54: '4803842488000000',
        },
        'calls': {},
    },
    'caller_0x2a89500_site_3': {
        'range': (0x2A89D0C, 0x2A89D33),
        'pins': {
            0x2A89D0C: '498b7708',
            0x2A89D15: '498b5710',
            0x2A89D19: '488dbc2480000000',
            0x2A89D21: '488d4c2420',
            0x2A89D2B: '83bc248000000001',
        },
        'calls': {0x2A89D26: 0x35BD800},
    },
    'caller_0x2a89500_site_3_hit': {
        'range': (0x2A89D74, 0x2A89D88),
        'pins': {
            0x2A89D74: '488b842498000000',
            0x2A89D7C: '48c1e005',
            0x2A89D80: '4803842488000000',
        },
        'calls': {},
    },
    'caller_0x2a918f0_site_1': {
        'range': (0x2A920CF, 0x2A920EF),
        'pins': {
            0x2A920CF: '498b7708',
            0x2A920D8: '498b5710',
            0x2A920DC: '4889df',
            0x2A920DF: '4c89f1',
            0x2A920E7: '80bc243001000000',
        },
        'calls': {0x2A920E2: 0x35BD800},
    },
    # After the scan loop an indirect call runs, then the caller copies
    # the record's flag, node and height fields into another struct.
    'caller_0x2a918f0_record_copy': {
        'range': (0x2A921E4, 0x2A92211),
        'pins': {
            0x2A921E4: '488b842430010000',
            0x2A921F1: '488b842438010000',
            0x2A92201: '488b842440010000',
        },
        'calls': {},
    },
    'caller_0x2c61b30_site_1': {
        'range': (0x2C61E24, 0x2C61E69),
        'pins': {
            0x2C61E24: '488d7d20',
            0x2C61E48: '488b7528',
            0x2C61E51: '488b5530',
            0x2C61E55: '488d7c2430',
            0x2C61E5A: '488d4c2410',
            0x2C61E64: '837c243001',
        },
        'calls': {0x2C61E5F: 0x35BD800},
    },
    'caller_0x2c61b30_site_1_hit': {
        'range': (0x2C61EBE, 0x2C61ECC),
        'pins': {
            0x2C61EBE: '488b442448',
            0x2C61EC3: '48c1e005',
            0x2C61EC7: '4803442438',
        },
        'calls': {},
    },
    'caller_0x2c6b3b0_site_1': {
        'range': (0x2C6B525, 0x2C6B557),
        'pins': {
            0x2C6B525: '498bb7d03f0000',
            0x2C6B536: '498b97d83f0000',
            0x2C6B53D: '488dbc2430010000',
            0x2C6B545: '488d4c2430',
            0x2C6B54F: '80bc243001000000',
        },
        'calls': {0x2C6B54A: 0x35BD800},
    },
    'caller_0x5582180_site_1': {
        'range': (0x558391B, 0x558395F),
        'pins': {
            0x558391B: '498b7708',
            0x5583928: '498b5710',
            0x558392C: '488dbc24b0000000',
            0x5583934: '488d8c2420050000',
            0x5583941: '83bc24b000000001',
            0x558394B: '488b8424c8000000',
            0x5583953: '48c1e005',
            0x5583957: '48038424b8000000',
        },
        'calls': {0x558393C: 0x35BD800},
    },
    'caller_0x5582180_other_record_phase': {
        'range': (0x558277B, 0x55827A8),
        'pins': {
            0x558277B: '488dbc24b0000000',
            0x5582790: '4c8bb424b0000000',
            0x5582798: '4c8bbc24b8000000',
            0x55827A0: '4c8ba424c0000000',
        },
        'calls': {0x558278B: 0x5AC9DF0},
    },
    'caller_0x5585290_site_1': {
        'range': (0x5586A2B, 0x5586A6F),
        'pins': {
            0x5586A2B: '498b7708',
            0x5586A38: '498b5710',
            0x5586A3C: '488dbc24b0000000',
            0x5586A44: '488d8c2420050000',
            0x5586A51: '83bc24b000000001',
            0x5586A5B: '488b8424c8000000',
            0x5586A63: '48c1e005',
            0x5586A67: '48038424b8000000',
        },
        'calls': {0x5586A4C: 0x35BD800},
    },
    'caller_0x55a07e0_site_1': {
        'range': (0x55A0B03, 0x55A0B2E),
        'pins': {
            0x55A0B03: '488bb42440010000',
            0x55A0B14: '488b942448010000',
            0x55A0B1C: '488dbc2480000000',
            0x55A0B24: '488d4c2420',
        },
        'calls': {0x55A0B29: 0x35BD800},
    },
    'caller_0x55a07e0_site_2': {
        'range': (0x55A0CF4, 0x55A0D1D),
        'pins': {
            0x55A0CF4: '488b742428',
            0x55A0CFE: '488b542430',
            0x55A0D03: '488dbc2480000000',
            0x55A0D0B: '488d4c2460',
            0x55A0D15: '83bc248000000001',
        },
        'calls': {0x55A0D10: 0x35BD800},
    },
    'caller_0x55a07e0_site_2_hit': {
        'range': (0x55A0F28, 0x55A0F3C),
        'pins': {
            0x55A0F28: '488b842498000000',
            0x55A0F30: '48c1e005',
            0x55A0F34: '4803842488000000',
        },
        'calls': {},
    },
    'caller_0x55a07e0_site_3': {
        'range': (0x55A0FEC, 0x55A1013),
        'pins': {
            0x55A0FEC: '498b7708',
            0x55A0FF5: '498b5710',
            0x55A0FF9: '488dbc2480000000',
            0x55A1001: '488d4c2420',
            0x55A100B: '83bc248000000001',
        },
        'calls': {0x55A1006: 0x35BD800},
    },
    'caller_0x55a07e0_site_3_hit': {
        'range': (0x55A1054, 0x55A1068),
        'pins': {
            0x55A1054: '488b842498000000',
            0x55A105C: '48c1e005',
            0x55A1060: '4803842488000000',
        },
        'calls': {},
    },
    'caller_0x55a12e0_site_1': {
        'range': (0x55A1603, 0x55A162E),
        'pins': {
            0x55A1603: '488bb42440010000',
            0x55A1614: '488b942448010000',
            0x55A161C: '488dbc2480000000',
            0x55A1624: '488d4c2420',
        },
        'calls': {0x55A1629: 0x35BD800},
    },
    'caller_0x55a12e0_site_2': {
        'range': (0x55A17F4, 0x55A181D),
        'pins': {
            0x55A17F4: '488b742428',
            0x55A17FE: '488b542430',
            0x55A1803: '488dbc2480000000',
            0x55A180B: '488d4c2460',
            0x55A1815: '83bc248000000001',
        },
        'calls': {0x55A1810: 0x35BD800},
    },
    'caller_0x55a12e0_site_2_hit': {
        'range': (0x55A1A28, 0x55A1A3C),
        'pins': {
            0x55A1A28: '488b842498000000',
            0x55A1A30: '48c1e005',
            0x55A1A34: '4803842488000000',
        },
        'calls': {},
    },
    'caller_0x55a12e0_site_3': {
        'range': (0x55A1AEC, 0x55A1B13),
        'pins': {
            0x55A1AEC: '498b7708',
            0x55A1AF5: '498b5710',
            0x55A1AF9: '488dbc2480000000',
            0x55A1B01: '488d4c2420',
            0x55A1B0B: '83bc248000000001',
        },
        'calls': {0x55A1B06: 0x35BD800},
    },
    'caller_0x55a12e0_site_3_hit': {
        'range': (0x55A1B54, 0x55A1B68),
        'pins': {
            0x55A1B54: '488b842498000000',
            0x55A1B5C: '48c1e005',
            0x55A1B60: '4803842488000000',
        },
        'calls': {},
    },
    'caller_0x55f8b70_site_1': {
        'range': (0x55F8CE5, 0x55F8D17),
        'pins': {
            0x55F8CE5: '498bb7404b0000',
            0x55F8CF6: '498b97484b0000',
            0x55F8CFD: '488dbc2430010000',
            0x55F8D05: '488d4c2430',
            0x55F8D0F: '80bc243001000000',
        },
        'calls': {0x55F8D0A: 0x35BD800},
    },
    'caller_0x55f9290_site_1': {
        'range': (0x55F9405, 0x55F9437),
        'pins': {
            0x55F9405: '498bb7d03f0000',
            0x55F9416: '498b97d83f0000',
            0x55F941D: '488dbc2430010000',
            0x55F9425: '488d4c2430',
            0x55F942F: '80bc243001000000',
        },
        'calls': {0x55F942A: 0x35BD800},
    },
}

# The stack slot of each caller's search record (flag at +0x0, node at
# +0x8, height at +0x10, position at +0x18).
RECORD_BASES = {
    'caller_0x23795c0': 0x68,
    'caller_0x2667140': 0x140,
    'caller_0x2a84e60': 0xD0,
    'caller_0x2a89500': 0x80,
    'caller_0x2a918f0': 0x130,
    'caller_0x2c4fe30': 0x20,
    'caller_0x2c61b30': 0x30,
    'caller_0x2c6b3b0': 0x130,
    'caller_0x3d987f0': 0x30,
    'caller_0x5582180': 0xB0,
    'caller_0x5585290': 0xB0,
    'caller_0x55a07e0': 0x80,
    'caller_0x55a12e0': 0x80,
    'caller_0x55bd810': 0x20,
    'caller_0x55be0d0': 0x20,
    'caller_0x55f8b70': 0x130,
    'caller_0x55f9290': 0x130,
    'caller_0x5b810d0': 0x78,
}

# Every direct call site of either variant, mapped to its caller FDE.
CALL_SITES = {
    'variant_search_a': {
        0x2379742: 0x23795C0, 0x23799C0: 0x23795C0,
        0x2C50127: 0x2C4FE30, 0x3D98859: 0x3D987F0,
        0x55BDB07: 0x55BD810, 0x55BE3C7: 0x55BE0D0,
        0x5B81281: 0x5B810D0, 0x5B81533: 0x5B810D0,
    },
    'variant_search_b': {
        0x2667AC0: 0x2667140, 0x2A86860: 0x2A84E60,
        0x2A89849: 0x2A89500, 0x2A89A30: 0x2A89500, 0x2A89D26: 0x2A89500,
        0x2A920E2: 0x2A918F0, 0x2C61E5F: 0x2C61B30, 0x2C6B54A: 0x2C6B3B0,
        0x558393C: 0x5582180, 0x5586A4C: 0x5585290,
        0x55A0B29: 0x55A07E0, 0x55A0D10: 0x55A07E0, 0x55A1006: 0x55A07E0,
        0x55A1629: 0x55A12E0, 0x55A1810: 0x55A12E0, 0x55A1B06: 0x55A12E0,
        0x55F8D0A: 0x55F8B70, 0x55F942A: 0x55F9290,
    },
}

# The instruction that first tests the record's flag word after each
# call, for the twenty-three sites that have one.
FLAG_TESTS = {
    0x2379742: 0x2379747, 0x23799C0: 0x23799C5, 0x2667AC0: 0x2667AC5,
    0x2A86860: 0x2A86865, 0x2A89A30: 0x2A89A35, 0x2A89D26: 0x2A89D2B,
    0x2A920E2: 0x2A920E7, 0x2C50127: 0x2C5012C, 0x2C61E5F: 0x2C61E64,
    0x2C6B54A: 0x2C6B54F, 0x3D98859: 0x3D9885E, 0x558393C: 0x5583941,
    0x5586A4C: 0x5586A51, 0x55A0D10: 0x55A0D15, 0x55A1006: 0x55A100B,
    0x55A1810: 0x55A1815, 0x55A1B06: 0x55A1B0B, 0x55BDB07: 0x55BDB0C,
    0x55BE3C7: 0x55BE3CC, 0x55F8D0A: 0x55F8D0F, 0x55F942A: 0x55F942F,
    0x5B81281: 0x5B81286, 0x5B81533: 0x5B81538,
}

# The remaining three sites have no flag test of their own: control
# flow reaches a call to the sibling search 0x35bf460 that overwrites
# the record first.  Site -> the overwriting call's address.
DEFERRED_FLAG_SITES = {
    0x2A89849: 0x2A89910, 0x55A0B29: 0x55A0BF0, 0x55A1629: 0x55A16F0,
}
SIBLING = 0x35BF460

# Sites whose caller goes on to read the record's node and position
# fields (forming node + position * 8 + 0x60 for variant A callers and
# node + position * 32 for variant B callers).
NODE_POSITION_SITES = {
    0x2379742, 0x23799C0, 0x2C50127, 0x3D98859, 0x55BDB07, 0x55BE3C7,
    0x5B81281, 0x5B81533,
    0x2A86860, 0x2A89A30, 0x2A89D26, 0x2C61E5F, 0x558393C, 0x5586A4C,
    0x55A0D10, 0x55A1006, 0x55A1810, 0x55A1B06,
}
# Sites whose caller reads only the flag.
FLAG_ONLY_SITES = {0x2667AC0, 0x2A920E2, 0x2C6B54A, 0x55F8D0A, 0x55F942A}

# The complete read census of each caller's record height slot
# (base + 0x10) across the whole caller FDE, by the textual method of
# the cursor-search packet: instructions naming the slot as a source,
# excluding address computations (lea) and pure stores.
HEIGHT_READS = {
    'caller_0x23795c0': [],
    'caller_0x2667140': [],
    'caller_0x2a84e60': [0x2A8549B, 0x2A85995, 0x2A86FD6],
    'caller_0x2a89500': [],
    'caller_0x2a918f0': [0x2A92201],
    'caller_0x2c4fe30': [],
    'caller_0x2c61b30': [],
    'caller_0x2c6b3b0': [0x2C6B8C8],
    'caller_0x3d987f0': [0x3D989B0],
    'caller_0x5582180': [
        0x55827A0, 0x5582C55, 0x5584082, 0x5584398, 0x55843C8],
    'caller_0x5585290': [
        0x55858B0, 0x5585D65, 0x5587192, 0x55874A8, 0x55874D8],
    'caller_0x55a07e0': [],
    'caller_0x55a12e0': [],
    'caller_0x55bd810': [],
    'caller_0x55be0d0': [],
    'caller_0x55f8b70': [0x55F9088],
    'caller_0x55f9290': [0x55F97A8],
    'caller_0x5b810d0': [],
}

# How each caller's height-slot reads are attributed.  "never_read":
# the slot is never read.  "scalar_read": a phase loads the variant
# record's height as a value.  "vector_copy": a later phase copies the
# whole record region with vector loads that span the height field.
# "other_phase": every read belongs to a phase whose record was filled
# by a different call reusing the same stack slot.
HEIGHT_CLASSES = {
    'never_read': [
        'caller_0x23795c0', 'caller_0x2667140', 'caller_0x2a89500',
        'caller_0x2c4fe30', 'caller_0x2c61b30', 'caller_0x55a07e0',
        'caller_0x55a12e0', 'caller_0x55bd810', 'caller_0x55be0d0',
        'caller_0x5b810d0',
    ],
    'scalar_read': ['caller_0x2a918f0', 'caller_0x3d987f0'],
    'vector_copy': [
        'caller_0x2c6b3b0', 'caller_0x55f8b70', 'caller_0x55f9290'],
    'other_phase': [
        'caller_0x2a84e60', 'caller_0x5582180', 'caller_0x5585290'],
}

# The cursor-search family: every standalone body that ends in the
# shared fourteen-byte record-store epilogue, found by scanning .text
# for that sequence.  Signature pins cite each member's count load, key
# comparison and child-edge load.
EPILOGUE_SEQ = bytes.fromhex('48897008' '48895010' '48897818' '488908')
FAMILY = [
    {
        'name': 'family_0x1d65920', 'range': (0x1D65920, 0x1D659AF),
        'sha256': '4f7a495bf20876b0606bf10b74cbbce7d6b8a1ebc5b55e2be63d'
                  '6f7bac1297ac',
        'key_kind': 'u64', 'keys_base': 0x8, 'child_index_offset': 0x60,
        'count_offset': 0x62, 'edges_base': 0x68, 'key_capacity': 11,
        'pins': {
            0x1D65926: '440fb74662', 0x1D65945: '483b4cfe10',
            0x1D6598C: '488b74fe68',
        },
    },
    {
        'name': 'family_0x35bdd20', 'range': (0x35BDD20, 0x35BDDAF),
        'sha256': '4f7a495bf20876b0606bf10b74cbbce7d6b8a1ebc5b55e2be63d'
                  '6f7bac1297ac',
        'key_kind': 'u64', 'keys_base': 0x8, 'child_index_offset': 0x60,
        'count_offset': 0x62, 'edges_base': 0x68, 'key_capacity': 11,
        'pins': {
            0x35BDD26: '440fb74662', 0x35BDD45: '483b4cfe10',
            0x35BDD8C: '488b74fe68',
        },
    },
    {
        'name': 'family_0x35bd660', 'owner': 'variant_search_a',
        'range': (0x35BD660, 0x35BD6F2),
        'sha256': '3da45a31a814e5cb8c3b77323c8c550b760ad8a76aadc94048d1'
                  '3e54a3c16950',
        'key_kind': 'u64', 'keys_base': 0x8, 'child_index_offset': 0xB8,
        'count_offset': 0xBA, 'edges_base': 0xC0, 'key_capacity': 22,
        'pins': {
            0x35BD666: '440fb786ba000000', 0x35BD685: '483b4cfe10',
            0x35BD6CC: '488bb4fec0000000',
        },
    },
    {
        'name': 'family_0x35bd800', 'owner': 'variant_search_b',
        'range': (0x35BD800, 0x35BD892),
        'sha256': '100afb1aa917741ca80b4efc1505a123a89cce43457beb3eaa4'
                  '7b5b75437191b',
        'key_kind': 'u64', 'keys_base': 0x168,
        'child_index_offset': 0x1C0, 'count_offset': 0x1C2,
        'edges_base': 0x1C8, 'key_capacity': 11,
        'pins': {
            0x35BD806: '440fb786c2010000', 0x35BD825: '483b8cfe70010000',
            0x35BD86C: '488bb4fec8010000',
        },
    },
    {
        'name': 'family_0x35bd8a0', 'range': (0x35BD8A0, 0x35BD932),
        'sha256': '499fcf8ff6b95a70aa3be671ee130d699c83c694ff57a9af4f2'
                  'e05d45ce7a848',
        'key_kind': 'u64', 'keys_base': 0x8, 'child_index_offset': 0xE4,
        'count_offset': 0xE6, 'edges_base': 0xE8, 'key_capacity': 27,
        'layout_note': 'four spare bytes sit between the last key slot '
                       'and the child-index word',
        'pins': {
            0x35BD8A6: '440fb786e6000000', 0x35BD8C5: '483b4cfe10',
            0x35BD90C: '488bb4fee8000000',
        },
    },
    {
        'name': 'family_0x35bddb0', 'range': (0x35BDDB0, 0x35BDE42),
        'sha256': '30f297e738540fa348b161115181d87d0a28167d35a6bc1086a'
                  '8f701e8793058',
        'key_kind': 'u64', 'keys_base': 0x218,
        'child_index_offset': 0x270, 'count_offset': 0x272,
        'edges_base': 0x278, 'key_capacity': 11,
        'pins': {
            0x35BDDB6: '440fb78672020000', 0x35BDDD5: '483b8cfe20020000',
            0x35BDE1C: '488bb4fe78020000',
        },
    },
    {
        'name': 'family_0x35be3b0', 'range': (0x35BE3B0, 0x35BE442),
        'sha256': '0a725341981473211a1f193625896b37ba3fbaaa69354f56b7b'
                  '222651d9db4b8',
        'key_kind': 'u32', 'keys_base': 0xB8, 'child_index_offset': 0xE4,
        'count_offset': 0xE6, 'edges_base': 0xE8, 'key_capacity': 11,
        'pins': {
            0x35BE3B3: '8b09', 0x35BE3B5: '440fb786e6000000',
            0x35BE3D5: '3b8cbebc000000', 0x35BE41C: '488bb4fee8000000',
        },
    },
    {
        'name': 'family_0x35be560', 'range': (0x35BE560, 0x35BE5F2),
        'sha256': 'b9544e43306382e72df633265f96c279104a2f0a6fe9170b3b6e'
                  'c175efe4e79d',
        'key_kind': 'u64', 'keys_base': 0x2C8,
        'child_index_offset': 0x320, 'count_offset': 0x322,
        'edges_base': 0x328, 'key_capacity': 11,
        'pins': {
            0x35BE566: '440fb78622030000', 0x35BE585: '483b8cfed0020000',
            0x35BE5CC: '488bb4fe28030000',
        },
    },
    {
        'name': 'family_0x35bf3c0', 'range': (0x35BF3C0, 0x35BF452),
        'sha256': '89516192c291c89a0ae1ee5c9a2a0783b50e2b61be018780545'
                  '5e6ba2a30c229',
        'key_kind': 'u64', 'keys_base': 0x8, 'child_index_offset': 0x13C,
        'count_offset': 0x13E, 'edges_base': 0x140, 'key_capacity': 38,
        'layout_note': 'four spare bytes sit between the last key slot '
                       'and the child-index word',
        'pins': {
            0x35BF3C6: '440fb7863e010000', 0x35BF3E5: '483b4cfe10',
            0x35BF42C: '488bb4fe40010000',
        },
    },
    {
        'name': 'family_0x35bf460', 'range': (0x35BF460, 0x35BF4F2),
        'sha256': '10b3b34cb2182f4c9bba0efbb6750ada3ec101615535406c3663df'
                  '2b09f840ca',
        'key_kind': 'u64', 'keys_base': 0x798,
        'child_index_offset': 0x7F0, 'count_offset': 0x7F2,
        'edges_base': 0x7F8, 'key_capacity': 11,
        'pins': {
            0x35BF466: '440fb786f2070000', 0x35BF485: '483b8cfea0070000',
            0x35BF4CC: '488bb4fef8070000',
        },
    },
    {
        'name': 'family_0x35bf500', 'range': (0x35BF500, 0x35BF592),
        'sha256': '90fda960e4f1a5fbffb665662ff5ae5384a64c5c54ac1443f37'
                  '536c1d5400142',
        'key_kind': 'u32', 'keys_base': 0x2C8,
        'child_index_offset': 0x2F4, 'count_offset': 0x2F6,
        'edges_base': 0x2F8, 'key_capacity': 11,
        'pins': {
            0x35BF503: '8b09', 0x35BF505: '440fb786f6020000',
            0x35BF525: '3b8cbecc020000', 0x35BF56C: '488bb4fef8020000',
        },
    },
    {
        'name': 'family_0x1d65b20', 'range': (0x1D65B20, 0x1D65BB2),
        'sha256': 'b1d2c6ba43757c25e56ffeef32b4ee8127289eb49a3361b808cb'
                  '361b5fd8866d',
        'key_kind': 'u64', 'keys_base': 0x8, 'child_index_offset': 0x378,
        'count_offset': 0x37A, 'edges_base': 0x380, 'key_capacity': 110,
        'pins': {
            0x1D65B26: '440fb7867a030000', 0x1D65B45: '483b4cfe10',
            0x1D65B8C: '488bb4fe80030000',
        },
    },
    {
        'name': 'family_0x4d380a0', 'range': (0x4D380A0, 0x4D38132),
        'sha256': 'b1d2c6ba43757c25e56ffeef32b4ee8127289eb49a3361b808cb'
                  '361b5fd8866d',
        'key_kind': 'u64', 'keys_base': 0x8, 'child_index_offset': 0x378,
        'count_offset': 0x37A, 'edges_base': 0x380, 'key_capacity': 110,
        'pins': {
            0x4D380A6: '440fb7867a030000', 0x4D380C5: '483b4cfe10',
            0x4D3810C: '488bb4fe80030000',
        },
    },
]

# One further epilogue instance is inlined into a larger body instead
# of standing alone as a family member.
INLINED_INSTANCE = {
    'fde': (0x4D38C10, 0x4D38E67),
    'sha256': 'f3975f03056f7c4a7022aa75ac016b588e1545a70ffc5d4667c91d6'
              'fec23b5ab',
    'epilogue_store': 0x4D38E48,
    'edges_base': 0x1A38,
}


class PacketError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise PacketError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def hx(value):
    return f'{value:#x}'


def authenticate(data):
    require(sha(data) == ARTIFACT_SHA256,
            'Node 115 artifact hash mismatch')


def section_bytes(data, secs, start, end):
    for section in secs:
        if (section['type'] != 8
                and section['address'] <= start
                and end <= section['address'] + section['size']):
            offset = section['offset'] + (start - section['address'])
            return data[offset:offset + (end - start)]
    raise PacketError(f'range {start:#x}..{end:#x} is not file-backed')


_LINE_RE = re.compile(r'^\s+([0-9a-f]+):\t[0-9a-f ]+\t(.*)$')


def decode_body(data, secs, start, end):
    """objdump-decode one body from a temp copy of the data.

    Returns (rows, texts): rows maps each instruction address to its
    exact bytes (the shared decoder requires the rows to tile the body
    and reproduce its bytes); texts maps each address to objdump's
    AT&T mnemonic text for the textual censuses.
    """
    body = section_bytes(data, secs, start, end)
    with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as tmp:
        tmp.write(body)
        path = tmp.name
    try:
        output = subprocess.check_output(
            ['objdump', '-D', '-b', 'binary', '-m', 'i386:x86-64',
             f'--adjust-vma={start:#x}', path],
            text=True)
    finally:
        os.unlink(path)
    rows = _foundation_decode(output, start, end, body)
    texts = {}
    for line in output.splitlines():
        match = _LINE_RE.match(line)
        if match:
            texts[int(match.group(1), 16)] = match.group(2).strip()
    return rows, texts


def check_pins(name, pins, rows):
    for addr, want in pins.items():
        require(rows.get(addr) == bytes.fromhex(want),
                f'{name} pin bytes changed at {addr:#x}')


def check_calls(name, calls, rows):
    for addr, target in calls.items():
        raw = rows.get(addr)
        require(raw is not None and len(raw) == 5 and raw[0] == 0xE8,
                f'{name} call changed at {addr:#x}')
        actual = addr + 5 + struct.unpack_from('<i', raw, 1)[0]
        require(actual == target,
                f'{name} call target changed at {addr:#x}')


def load_fdes(data):
    _summary, fdes, _gaps = fde_extents(data)
    require(len(fdes) == EXPECTED_FDE_RECORDS, 'FDE record count changed')
    by_start = {}
    for fde in fdes:
        by_start.setdefault(fde['start'], fde['end'])
    require(len(by_start) == EXPECTED_FDE_RECORDS,
            'FDE starts are not unique')
    return by_start


def containing_fde(starts, by_start, va):
    import bisect
    index = bisect.bisect_right(starts, va) - 1
    require(index >= 0, f'no FDE contains {va:#x}')
    start = starts[index]
    require(va < by_start[start], f'no FDE contains {va:#x}')
    return start


def branch_census(data, secs, starts, by_start, opcode, targets):
    """All direct branch sites in .text whose target is in targets."""
    text = next(s for s in secs if s['name'] == '.text')
    blob = data[text['offset']:text['offset'] + text['size']]
    found = {target: {} for target in targets}
    pos = blob.find(bytes([opcode]))
    while pos != -1:
        if pos + 5 <= len(blob):
            va = text['address'] + pos
            target = va + 5 + struct.unpack_from('<i', blob, pos + 1)[0]
            if target in found:
                found[target][va] = containing_fde(starts, by_start, va)
        pos = blob.find(bytes([opcode]), pos + 1)
    return found


_STORE_RE = re.compile(r'^mov\w*\s+[^,]+,\s*0x[0-9a-f]+\(%rsp\)$')


def slot_reads_for(texts, base):
    """Textual read census of the four record slots, the method of the
    cursor-search packet: instructions naming the slot as a source,
    excluding lea (address computation) and pure stores into the slot.
    """
    result = {}
    for slot in (base, base + 8, base + 0x10, base + 0x18):
        needle = f'{slot:#x}(%rsp)'
        reads = []
        for addr in sorted(texts):
            text = texts[addr]
            if needle not in text:
                continue
            if text.startswith('lea'):
                continue
            if _STORE_RE.match(text):
                continue
            reads.append(addr)
        result[slot] = reads
    return result


def rela_census(binary, targets):
    output = subprocess.check_output(
        ['readelf', '-rW', str(binary)], text=True)
    hits = []
    for line in output.splitlines():
        if 'R_X86_64_RELATIVE' not in line:
            continue
        fields = line.split()
        try:
            addend = int(fields[-1], 16)
        except (ValueError, IndexError):
            continue
        if addend in targets:
            hits.append(addend)
    return hits


def analyze(data, binary):
    # No whole-artifact authentication here: generate() authenticates
    # first, so that a mutated byte surfaces as the specific pin, hash
    # or census failure it causes instead of a blanket hash mismatch.
    secs = sections(data)
    by_start = load_fdes(data)
    starts = sorted(by_start)

    # Owners: pins first (so a changed pin reports as a pin), then the
    # whole-body digest, then call-freedom.
    owners = {}
    for name, spec in OWNERS.items():
        start, end = spec['range']
        require(by_start.get(start) == end, f'{name} FDE range changed')
        rows, _texts = decode_body(data, secs, start, end)
        check_pins(name, spec['pins'], rows)
        body = section_bytes(data, secs, start, end)
        require(sha(body) == spec['sha256'],
                f'Owner body hash changed: {name}')
        require(not any(raw[0] == 0xE8 for raw in rows.values()),
                f'{name} unexpectedly contains a direct call')
        owners[name] = {
            'range': [hx(start), hx(end)],
            'size': end - start,
            'sha256': spec['sha256'],
            'layout': spec['layout'],
            'pins': {hx(a): b for a, b in sorted(spec['pins'].items())},
            'calls': {},
        }

    # Boundaries: digest-pinned caller FDEs and the sibling search.
    boundaries = {}
    for name, (start, end, digest) in BOUNDARIES.items():
        require(by_start.get(start) == end, f'{name} FDE range changed')
        body = section_bytes(data, secs, start, end)
        require(sha(body) == digest, f'Boundary body hash changed: {name}')
        boundaries[name] = {
            'range': [hx(start), hx(end)],
            'size': end - start,
            'sha256': digest,
        }

    # Windows inside the digest-pinned callers.
    windows = {}
    for name, spec in WINDOWS.items():
        start, end = spec['range']
        rows, _texts = decode_body(data, secs, start, end)
        check_pins(name, spec['pins'], rows)
        check_calls(name, spec['calls'], rows)
        windows[name] = {
            'range': [hx(start), hx(end)],
            'pins': {hx(a): b for a, b in sorted(spec['pins'].items())},
            'calls': {hx(a): hx(t) for a, t in
                      sorted(spec['calls'].items())},
        }

    # Direct call and tail-call censuses for the whole family.
    family_starts = [member['range'][0] for member in FAMILY]
    call_map = branch_census(
        data, secs, starts, by_start, 0xE8, set(family_starts))
    variant_starts = {
        'variant_search_a': OWNERS['variant_search_a']['range'][0],
        'variant_search_b': OWNERS['variant_search_b']['range'][0],
    }
    call_sites = {}
    for name, start in variant_starts.items():
        derived = call_map[start]
        require(derived == CALL_SITES[name],
                f'direct call census changed for {name}')
        call_sites[name] = {hx(s): hx(c) for s, c in sorted(derived.items())}
    tail_map = branch_census(
        data, secs, starts, by_start, 0xE9, set(variant_starts.values()))
    tail_sites = {}
    for target, sites in tail_map.items():
        if sites:
            tail_sites[hx(target)] = {
                hx(s): hx(c) for s, c in sorted(sites.items())}
    require(not tail_sites, 'unexpected tail call to a variant search')

    # Caller decodes: flag tests, deferred overwrites, slot censuses.
    caller_starts = {}
    for name, (start, _end, _digest) in BOUNDARIES.items():
        if name.startswith('caller_'):
            caller_starts[name] = start
    decoded = {}
    for name, start in caller_starts.items():
        decoded[name] = decode_body(data, secs, start, by_start[start])
    name_by_start = {v: k for k, v in caller_starts.items()}

    flag_tests = {}
    for site, test in FLAG_TESTS.items():
        caller = (CALL_SITES['variant_search_a'].get(site)
                  or CALL_SITES['variant_search_b'].get(site))
        name = name_by_start[caller]
        _rows, texts = decoded[name]
        text = texts.get(test, '')
        base = RECORD_BASES[name]
        require(text.startswith('cmp')
                and f'{base:#x}(%rsp)' in text,
                f'flag test changed at {test:#x}')
        flag_tests[hx(site)] = hx(test)
    require({int(s, 16) for s in flag_tests} == set(FLAG_TESTS),
            'flag test census changed')

    for site, call in DEFERRED_FLAG_SITES.items():
        caller = CALL_SITES['variant_search_b'][site]
        name = name_by_start[caller]
        rows, _texts = decoded[name]
        raw = rows.get(call)
        require(raw is not None and len(raw) == 5 and raw[0] == 0xE8
                and call + 5 + struct.unpack_from('<i', raw, 1)[0]
                == SIBLING,
                f'deferred overwrite call changed at {call:#x}')

    slot_reads = {}
    height_reads = {}
    for name in sorted(caller_starts):
        _rows, texts = decoded[name]
        reads = slot_reads_for(texts, RECORD_BASES[name])
        slot_reads[name] = {
            hx(slot): [hx(a) for a in addrs]
            for slot, addrs in reads.items()
        }
        height = reads[RECORD_BASES[name] + 0x10]
        require(height == HEIGHT_READS[name],
                f'record height-slot read census changed for {name}')
        height_reads[name] = height

    all_sites = set()
    for sites in CALL_SITES.values():
        all_sites |= set(sites)
    require(NODE_POSITION_SITES | FLAG_ONLY_SITES
            | set(DEFERRED_FLAG_SITES) == all_sites
            and not (NODE_POSITION_SITES & FLAG_ONLY_SITES)
            and not (NODE_POSITION_SITES & set(DEFERRED_FLAG_SITES))
            and not (FLAG_ONLY_SITES & set(DEFERRED_FLAG_SITES)),
            'site consumption classes do not partition the call sites')
    flat_classes = [n for names in HEIGHT_CLASSES.values() for n in names]
    require(sorted(flat_classes) == sorted(caller_starts),
            'height classes do not partition the callers')
    for name in HEIGHT_CLASSES['never_read']:
        require(height_reads[name] == [],
                f'{name} unexpectedly reads its record height slot')
    for group in ('scalar_read', 'vector_copy', 'other_phase'):
        for name in HEIGHT_CLASSES[group]:
            require(height_reads[name] != [],
                    f'{name} lost its record height-slot reads')

    # Family census: the epilogue scan must find exactly the thirteen
    # standalone members plus the one inlined instance.
    text = next(s for s in secs if s['name'] == '.text')
    blob = data[text['offset']:text['offset'] + text['size']]
    hit_fdes = set()
    pos = blob.find(EPILOGUE_SEQ)
    while pos != -1:
        hit_fdes.add(containing_fde(
            starts, by_start, text['address'] + pos))
        pos = blob.find(EPILOGUE_SEQ, pos + 1)
    expected_fdes = set(family_starts) | {INLINED_INSTANCE['fde'][0]}
    require(hit_fdes == expected_fdes, 'cursor family census changed')

    members = []
    for member in FAMILY:
        start, end = member['range']
        require(by_start.get(start) == end,
                f"{member['name']} FDE range changed")
        for addr, want in member['pins'].items():
            raw = section_bytes(data, secs, addr,
                                addr + len(bytes.fromhex(want)))
            require(raw == bytes.fromhex(want),
                    f"{member['name']} signature pin bytes changed "
                    f'at {addr:#x}')
        body = section_bytes(data, secs, start, end)
        require(sha(body) == member['sha256'],
                f"family member body hash changed: {member['name']}")
        entry = {
            'name': member['name'],
            'range': [hx(start), hx(end)],
            'size': end - start,
            'sha256': member['sha256'],
            'key_kind': member['key_kind'],
            'keys_base': hx(member['keys_base']),
            'child_index_offset': hx(member['child_index_offset']),
            'count_offset': hx(member['count_offset']),
            'edges_base': hx(member['edges_base']),
            'key_capacity': member['key_capacity'],
            'direct_call_sites': len(call_map[start]),
        }
        if 'owner' in member:
            entry['owner'] = member['owner']
        if 'layout_note' in member:
            entry['layout_note'] = member['layout_note']
        members.append(entry)

    istart, iend = INLINED_INSTANCE['fde']
    require(by_start.get(istart) == iend, 'inlined instance FDE changed')
    ibody = section_bytes(data, secs, istart, iend)
    require(sha(ibody) == INLINED_INSTANCE['sha256'],
            'inlined instance body hash changed')
    store = INLINED_INSTANCE['epilogue_store']
    require(section_bytes(data, secs, store, store + 4)
            == EPILOGUE_SEQ[:4],
            'inlined instance epilogue store changed')

    rela_hits = rela_census(binary, set(variant_starts.values()))
    require(not rela_hits, 'a variant search gained a relocation slot')

    counters = {
        'variant_search_a_call_sites':
            len(CALL_SITES['variant_search_a']),
        'variant_search_b_call_sites':
            len(CALL_SITES['variant_search_b']),
        'variant_search_call_sites': len(all_sites),
        'variant_caller_fdes': len(caller_starts),
        'caller_windows': len(WINDOWS),
        'flag_test_sites': len(FLAG_TESTS),
        'deferred_flag_sites': len(DEFERRED_FLAG_SITES),
        'node_position_sites': len(NODE_POSITION_SITES),
        'flag_only_sites': len(FLAG_ONLY_SITES),
        'family_standalone_bodies': len(FAMILY),
        'family_distinct_bodies':
            len({member['sha256'] for member in FAMILY}),
        'family_inlined_instances': 1,
        'height_never_read_callers': len(HEIGHT_CLASSES['never_read']),
        'height_scalar_read_callers': len(HEIGHT_CLASSES['scalar_read']),
        'height_vector_copy_callers':
            len(HEIGHT_CLASSES['vector_copy']),
        'height_other_phase_callers':
            len(HEIGHT_CLASSES['other_phase']),
    }

    frames = ([[hx(s), hx(e)] for s, e in
               (spec['range'] for spec in OWNERS.values())]
              + [[hx(s), hx(e)] for s, e, _d in BOUNDARIES.values()])

    return {
        'artifact': {
            'sha256': ARTIFACT_SHA256,
            'fde_records': len(by_start),
            'unique_fde_starts': len(by_start),
        },
        'owners': owners,
        'boundaries': boundaries,
        'windows': windows,
        'frames': frames,
        'call_sites': call_sites,
        'tail_call_sites': tail_sites,
        'flag_tests': flag_tests,
        'deferred_flag_sites': {
            hx(s): hx(c) for s, c in sorted(DEFERRED_FLAG_SITES.items())},
        'record_bases': {
            name: hx(base) for name, base in sorted(RECORD_BASES.items())},
        'slot_reads': slot_reads,
        'height_classes': HEIGHT_CLASSES,
        'family': {
            'members': members,
            'inlined_instances': [{
                'fde': [hx(istart), hx(iend)],
                'sha256': INLINED_INSTANCE['sha256'],
                'epilogue_store': hx(store),
                'edges_base': hx(INLINED_INSTANCE['edges_base']),
            }],
        },
        'rela_slots': [hx(a) for a in rela_hits],
        'counters': counters,
    }



def generate(binary, output):
    data = Path(binary).read_bytes()
    authenticate(data)
    report = analyze(data, binary)
    output.mkdir(parents=True, exist_ok=True)
    raw = subprocess.check_output(
        ['readelf', '-wf', str(binary)], text=True)
    ranges = ([spec['range'] for spec in OWNERS.values()]
              + [(start, end) for start, end, _d in BOUNDARIES.values()])
    lines = [
        line.replace(str(binary), '<authenticated-node115>')
        for line in raw.splitlines()
        if any(f'pc={start:016x}..{end:016x}' in line
               for start, end in ranges)
    ]
    require(len(lines) == len(report['frames']),
            'Retained readelf frame changed')
    (output / 'frames.txt').write_text('\n'.join(lines) + '\n')
    exports = {}
    for name, spec in OWNERS.items():
        start, end = spec['range']
        asm = subprocess.check_output([
            'objdump', '-d', '-M', 'intel', '--insn-width=16',
            f'--start-address={start:#x}',
            f'--stop-address={end:#x}',
            str(binary),
        ], text=True)
        safe_name = f'{name}_full_body_{start:x}_{end:x}_objdump.txt'
        rendered = asm.replace(str(binary), '<authenticated-node115>')
        (output / safe_name).write_text(rendered)
        exports[name] = {
            'full_body': {
                'file': safe_name,
                'sha256': sha(rendered.encode()),
                'range': [hx(start), hx(end)],
            },
        }
    report['source_exports'] = exports
    (output / 'records.json').write_text(
        json.dumps(report, indent=2) + '\n')
    return report


def main():
    if len(sys.argv) == 2 and sys.argv[1] == '--generate':
        generate(ARTIFACT, PACKET_DIR)
        print(f'generated {PACKET_DIR}')
        return 0
    if len(sys.argv) == 2 and sys.argv[1] == '--check':
        data = ARTIFACT.read_bytes()
        authenticate(data)
        report = analyze(data, ARTIFACT)
        retained = json.loads((PACKET_DIR / 'records.json').read_text())
        require(report == {k: v for k, v in retained.items()
                           if k != 'source_exports'},
                'retained records drifted from the binary')
        print('packet check ok')
        return 0
    print(__doc__)
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
