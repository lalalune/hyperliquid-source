#!/usr/bin/env python3
"""Authenticated node94 clearinghouse-36fe830 binding (0x36fe830).

Machine-derived static binding: FDE record, body bytes, every branch
destination, every direct and GOT-mediated call site, every panic
Location, and the whole-.text caller census, all checked byte-exactly
against the authenticated node #94 digest. Static checks only; the
captured binary is never executed.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from elf_index import sections

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

START, END = 0x36fe830, 0x36ff3be
FDE_VA = 0xe4b700
FDE = bytes.fromhex(
    '4c000000eca1160028318b028e0b000000410e10420e18420e20420e28420e30'
    '410e38470eb00383078c068d058e048f038602030b0b0e38410e30420e28420e'
    '20420e18420e10410e08410eb0030000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ec780100004c8984248000000048898c24880000'
    '004989d74989f64889bc24f8000000488b767048b94b598638d6c56d344889d0'
    '48f7e148c1ea0b48899424d80000004869c2102700004c89fb4829c34839f30f'
    '83e70a00004c89cd4d8d6e60498b4668488d0c5b48c1e105488b440820488944'
    '24784d8da6f80000004c89e74c89cee82c6fffff4c893424488dbc2458010000'
    '4889c631d2b9010000004c89ac24900000004d89e9ff158d480702488b842460'
    '0100004885c00f88900a00004c8bac24580100004c89e94829c10f80f1080000'
    '4531ed4885c94c0f4fe94c89e74889ac24980000004889eee8c36effff488b28'
    '4889e84c29e80f80f608000048898424b0000000488b8c24980000008b411089'
    '8424d00000000f10010f298424c00000008b411089442430660f1001660f2944'
    '2420488d7424204c89e7e8c17fe9ff4889c5488b40084c8b65204885c04c89a4'
    '24f000000048899c2400010000746a488b4d100fb7b0220300004189f041c1e0'
    '0648c7c2ffffffff31ff660f1f4400004939f8742b4c3bbcd0d0020000410f97'
    'c14180d9004883c74048ffc24180f90174de410fb6f185f67419eb070f1f4000'
    '4889f24883e9017210488b84d028030000eba08b4438c0eb3c488d7c24204c89'
    'fe4c89f2e8b71550004c89f848b94b598638d6c56d3448f7e148c1ea0b493b56'
    '300f85bd070000493b5e100f83b30700008b4424204d8da688010000488d4d08'
    '48898c24b800000031db898424a400000085c00f95c34c8934244c8b2d7f5c07'
    '024889ef4889de4c89fab90200000048896c2410488bac24900000004989e941'
    'ffd531c948898424e00000004885c00f9ec14c89342448898c24a80000008d4c'
    '0901488b7c241048895c24184889de4c89fa4989e9488b6c241041ffd54c8b55'
    '084d85d248898424e80000000f847d000000488b4d1048c74424700000000041'
    '0fb7b2220300004189f041c1e00648c7c2ffffffff31ff660f1f840000000000'
    '4939f8742b4d3bbcd2d0020000410f97c14180d9004883c74048ffc24180f901'
    '74de410fb6f185f67419eb070f1f40004889f24883e901721f4d8b94d2280300'
    '00eb9c498b443ad04889442470eb0948c744247000000000488b8c2498000000'
    '8b4110894424300f10010f29442420488d7424204c89e7e804cac9ff4c89bc24'
    '080100004c8b8c24b8000000498b014885c00f847e000000488b4d100fb7b022'
    '03000089f7c1e70348c7c2ffffffff904885ff742b4c3bbcd0d0020000410f97'
    'c04180d80048ffc24883c7f84180f80174de410fb6f085f6741deb070f1f4000'
    '4889f24883e9010f826b050000488b84d028030000eba5488944242848894c24'
    '3048895424384c894c244048c744242000000000eb134c894c24204c897c2428'
    '48c744243000000000488d7c2420488db424080100004c89f2e8d2e7cbff4889'
    'c54c8b6010448b68040f10000f1048100f1050200f1058300f299c2440010000'
    '0f299424300100000f298c24200100000f298424100100004c89f34c8b742410'
    '4d8b06488b44247848890424488d7c2420488db42410010000488b9424880000'
    '00488b8c24800000004c8b8c24b0000000e80a8d0100837c2420020f84970500'
    '004c89f14883c1204c8d8370010000660f10442420660f104c2430660f105424'
    '400f105c24500f299c2440010000660f29942430010000660f298c2420010000'
    '660f29842410010000488b4424600f115d30660f115520660f114d10660f1145'
    '00498906488b55108b6d044c89ff4c89e648894c2478e80586ffff4139ed4989'
    'de7419498dbe28010000488bb424980000004c89fa89e9e834f90000488b8424'
    'b8000000488b004885c0488b6c2410488b9c24000100007471488b4d100fb7b0'
    '220300004189f041c1e00648c7c2ffffffff31ff6666662e0f1f840000000000'
    '4939f8742b4c3bbcd0d0020000410f97c14180d9004883c74048ffc24180f901'
    '74de410fb6f185f67419eb070f1f40004889f24883e9017211488b84d0280300'
    '00eb9a488b5c38d0eb2e488d7c24204c89fe4c89f2e8c6115000488b8424d800'
    '0000493b46300f85d8030000493b5e100f83ce03000031db4c8bac2488000000'
    '4c8b8424a80000004889d848f7d8480f48c34885c00f880c050000488b542470'
    '4889d148f7d9480f48ca4885c90f88f40400004d85ed0f88450500004829c84c'
    '0fafe80f80380500004500c04180be30020000030f85d30000004c89c5498d86'
    'b8010000498b8eb80100004885c90f8482000000498b96c00100000fb7b9ba00'
    '00004189f841c1e00348c7c6ffffffff4d85c0742b4c3b7cf110410f97c14180'
    'd90048ffc64983c0f84180f90174e1410fb6f985ff7420eb0a0f1f8000000000'
    '4889fe4883ea010f82d5020000488b8cf1c0000000eba448894c242848895424'
    '304889742438488944244048c744242000000000eb1348894424204c897c2428'
    '48c744243000000000488d7c2420e85ddbcbff4c8b204c89e14c01e90f802303'
    '00004889084989e8488b6c24104c8ba424b001000041fec048837c2470000f98'
    'c00f9fc128c10f841c0100000fb6d183fa017507b801000000eb0231c04c8b8c'
    '24800000004d85c9400f98c7400f9fc64028fe741e400fb6febe0100000083ff'
    '01750231f639c60f94c084c9750fe9ce00000031c084c90f84c400000083fa01'
    '7507b901000000eb0231c94885db400f98c60f9fc24028f280faff0f84930000'
    '000fb6d283fa010f859400000031d239ca0f858a000000660f57c0660f57d24d'
    '85c974110f57d2f2480f2ad3f2490f2ac9f20f5ed10f57c9f2490f2accf20f59'
    'ca66480f7ec948b8ffffffffffffff7f4821c148baffffffffffffef7f4839d1'
    '4c8b6c24180f8f3f010000f20f101555bcb0fc660f2ed10f871d010000660f2e'
    '0d7bb7b0fc0f870f010000660f28c1e916010000ba0100000039ca0f8476ffff'
    'ff84c074034531e44c8b6c24184c893424410fb6c84889ef4c89ee4c89fa4c8b'
    '8c2490000000ff15345607024889c14883c1640f8016020000483b8c24e80000'
    '007d594889c14c01e10f80c90100004883c1640f80f60100004883bc24e00000'
    '00007e384885c979334c8934244889ef4c89ee4c89fab9020000004c8b8c2490'
    '000000ff15d755070248b99cffffffffffff7f4839c80f8db3010000488b4424'
    '78488b004883bc24f0000000000f84c20100004885c00f85ec0100004981c658'
    '010000488db424c00000004c89f7e87ddecaffe9d0010000488944243048c744'
    '24380000000048895424404c894c24204c897c2428e9affafffff20f5fd1f20f'
    '10055ab6b0fcf20f5dc2f2480f2cc8660f2e0521b1b0fc480f47c84531e4660f'
    '2ec04c0f4be183bc24a4000000000f84d9feffff31c04d85e44c0f4ee0e9cbfe'
    'ffff48894c243048c744243800000000488974244048894424204c897c2428e9'
    '45fdffff488d3dc52fff01ff156ff206020f99c10fb6c948baffffffffffffff'
    '7f4801ca4929c5488d350a5a01024c0f40ea31ffff15663f07024c89e9e9def6'
    'ffff0f99c00fb6c048b9ffffffffffffff7f4801c14c29ed488d35d959010248'
    '0f40e931ffff15353f07024889ac24b0000000e9dcf6ffff488d3d192bff01ff'
    '15fbf1060248c1f93f48ba00000000000000804831ca4d01ec488d35f85a0102'
    '4c0f40e231ff4989c5ff15f13e07024d896500e9adfcffff48c1f93f48ba0000'
    '0000000000804831ca4c01e0488d3565590102480f40c231ff4889c3ff15be3e'
    '07024889d94883c1640f810afeffff488d354259010231ffff15a23e0702488b'
    '442478488b004883bc24f0000000000f853efeffff4885c0742e4981c6580100'
    '008b8424d000000089442430660f288424c0000000660f29442420488d742420'
    '4c89f7e858c2c9ff488b8424f800000066c70086014881c4780100005b415c41'
    '5d415e415f5dc3488d3d135ee9fc488d0db3f4fe014c8d0514f2fe01488d5424'
    '20be2b000000ff15ccec0602488d152d29ff014889dfff153cec0602488d3dcf'
    'a4ebfc488d0d965b01024c8d056f580102488d542420be2b000000ff1597ec06'
    '02488d3db829ff01ff15b2f00602'
)
BODY_SHA256 = '1d99ea3fb309345395d77b0313025844c4ce78e7bdb4f4129e7f795848fb706d'
BRANCHES = [
    (0x5f, '0f83e70a0000', 2, 6, 0x36ff37c),
    (0xc6, '0f88900a0000', 2, 6, 0x36ff38c),
    (0xda, '0f80f1080000', 2, 6, 0x36ff201),
    (0x106, '0f80f6080000', 2, 6, 0x36ff232),
    (0x16d, '746a', 1, 2, 0x36fea09),
    (0x193, '742b', 1, 2, 0x36fe9f0),
    (0x1b0, '74de', 1, 2, 0x36fe9c0),
    (0x1b8, '7419', 1, 2, 0x36fea03),
    (0x1ba, 'eb07', 1, 2, 0x36fe9f3),
    (0x1c7, '7210', 1, 2, 0x36fea09),
    (0x1d1, 'eba0', 1, 2, 0x36fe9a3),
    (0x1d7, 'eb3c', 1, 2, 0x36fea45),
    (0x201, '0f85bd070000', 2, 6, 0x36ff1f4),
    (0x20b, '0f83b3070000', 2, 6, 0x36ff1f4),
    (0x2ac, '0f847d000000', 2, 6, 0x36feb5f),
    (0x2e3, '742b', 1, 2, 0x36feb40),
    (0x300, '74de', 1, 2, 0x36feb10),
    (0x308, '7419', 1, 2, 0x36feb53),
    (0x30a, 'eb07', 1, 2, 0x36feb43),
    (0x317, '721f', 1, 2, 0x36feb68),
    (0x321, 'eb9c', 1, 2, 0x36feaef),
    (0x32d, 'eb09', 1, 2, 0x36feb68),
    (0x372, '0f847e000000', 2, 6, 0x36fec26),
    (0x393, '742b', 1, 2, 0x36febf0),
    (0x3b0, '74de', 1, 2, 0x36febc0),
    (0x3b8, '741d', 1, 2, 0x36fec07),
    (0x3ba, 'eb07', 1, 2, 0x36febf3),
    (0x3c7, '0f826b050000', 2, 6, 0x36ff168),
    (0x3d5, 'eba5', 1, 2, 0x36febac),
    (0x3f4, 'eb13', 1, 2, 0x36fec39),
    (0x49b, '0f8497050000', 2, 6, 0x36ff268),
    (0x521, '7419', 1, 2, 0x36fed6c),
    (0x557, '7471', 1, 2, 0x36fedfa),
    (0x583, '742b', 1, 2, 0x36fede0),
    (0x5a0, '74de', 1, 2, 0x36fedb0),
    (0x5a8, '7419', 1, 2, 0x36fedf3),
    (0x5aa, 'eb07', 1, 2, 0x36fede3),
    (0x5b7, '7211', 1, 2, 0x36fedfa),
    (0x5c1, 'eb9a', 1, 2, 0x36fed8d),
    (0x5c8, 'eb2e', 1, 2, 0x36fee28),
    (0x5e6, '0f85d8030000', 2, 6, 0x36ff1f4),
    (0x5f0, '0f83ce030000', 2, 6, 0x36ff1f4),
    (0x615, '0f880c050000', 2, 6, 0x36ff357),
    (0x62d, '0f88f4040000', 2, 6, 0x36ff357),
    (0x636, '0f8845050000', 2, 6, 0x36ff3b1),
    (0x643, '0f8038050000', 2, 6, 0x36ff3b1),
    (0x654, '0f85d3000000', 2, 6, 0x36fef5d),
    (0x66e, '0f8482000000', 2, 6, 0x36fef26),
    (0x693, '742b', 1, 2, 0x36feef0),
    (0x6ad, '74e1', 1, 2, 0x36feec0),
    (0x6b5, '7420', 1, 2, 0x36fef07),
    (0x6b7, 'eb0a', 1, 2, 0x36feef3),
    (0x6c7, '0f82d5020000', 2, 6, 0x36ff1d2),
    (0x6d5, 'eba4', 1, 2, 0x36feeab),
    (0x6f4, 'eb13', 1, 2, 0x36fef39),
    (0x71c, '0f8023030000', 2, 6, 0x36ff275),
    (0x746, '0f841c010000', 2, 6, 0x36ff098),
    (0x752, '7507', 1, 2, 0x36fef8b),
    (0x759, 'eb02', 1, 2, 0x36fef8d),
    (0x773, '741e', 1, 2, 0x36fefc3),
    (0x781, '7502', 1, 2, 0x36fefb5),
    (0x78c, '750f', 1, 2, 0x36fefcd),
    (0x78e, 'e9ce000000', 1, 5, 0x36ff091),
    (0x797, '0f84c4000000', 2, 6, 0x36ff091),
    (0x7a0, '7507', 1, 2, 0x36fefd9),
    (0x7a7, 'eb02', 1, 2, 0x36fefdb),
    (0x7bb, '0f8493000000', 2, 6, 0x36ff084),
    (0x7c7, '0f8594000000', 2, 6, 0x36ff091),
    (0x7d1, '0f858a000000', 2, 6, 0x36ff091),
    (0x7e2, '7411', 1, 2, 0x36ff025),
    (0x825, '0f8f3f010000', 2, 6, 0x36ff19a),
    (0x837, '0f871d010000', 2, 6, 0x36ff18a),
    (0x845, '0f870f010000', 2, 6, 0x36ff18a),
    (0x84f, 'e916010000', 1, 5, 0x36ff19a),
    (0x85b, '0f8476ffffff', 2, 6, 0x36ff007),
    (0x863, '7403', 1, 2, 0x36ff098),
    (0x893, '0f8016020000', 2, 6, 0x36ff2df),
    (0x8a1, '7d59', 1, 2, 0x36ff12c),
    (0x8a9, '0f80c9010000', 2, 6, 0x36ff2a8),
    (0x8b3, '0f80f6010000', 2, 6, 0x36ff2df),
    (0x8c2, '7e38', 1, 2, 0x36ff12c),
    (0x8c7, '7933', 1, 2, 0x36ff12c),
    (0x8f6, '0f8db3010000', 2, 6, 0x36ff2df),
    (0x90d, '0f84c2010000', 2, 6, 0x36ff305),
    (0x916, '0f85ec010000', 2, 6, 0x36ff338),
    (0x933, 'e9d0010000', 1, 5, 0x36ff338),
    (0x955, 'e9affaffff', 1, 5, 0x36fec39),
    (0x98e, '0f84d9feffff', 2, 6, 0x36ff09d),
    (0x99d, 'e9cbfeffff', 1, 5, 0x36ff09d),
    (0x9bf, 'e945fdffff', 1, 5, 0x36fef39),
    (0x9fd, 'e9def6ffff', 1, 5, 0x36fe910),
    (0xa33, 'e9dcf6ffff', 1, 5, 0x36fe944),
    (0xa73, 'e9adfcffff', 1, 5, 0x36fef55),
    (0xaa9, '0f810afeffff', 2, 6, 0x36ff0e9),
    (0xacf, '0f853efeffff', 2, 6, 0x36ff143),
    (0xad8, '742e', 1, 2, 0x36ff338),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x36fe8bf, 0x36f57f0),
    (0x36fe928, 0x36f57f0),
    (0x36fe97a, 0x3596940),
    (0x36fea14, 0x3bfffd0),
    (0x36feb87, 0x339b590),
    (0x36fec49, 0x33bd420),
    (0x36fecc1, 0x37179d0),
    (0x36fed46, 0x36f7350),
    (0x36fed67, 0x370e6a0),
    (0x36fee05, 0x3bfffd0),
    (0x36fef3e, 0x33bcaa0),
    (0x36ff15e, 0x33acfe0),
    (0x36ff333, 0x339b590),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x36fe8e5, 0x5773178),
    (0x36ff0b6, 0x57746f0),
    (0x36ff113, 0x57746f0),
    (0x36ff1fb, 0x576e470),
    (0x36ff224, 0x5773190),
    (0x36ff255, 0x5773190),
    (0x36ff26f, 0x576e470),
    (0x36ff299, 0x5773190),
    (0x36ff2cc, 0x5773190),
    (0x36ff2e8, 0x5773190),
    (0x36ff376, 0x576e048),
    (0x36ff386, 0x576dfc8),
    (0x36ff3ab, 0x576e048),
    (0x36ff3b8, 0x576e470),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x36ff1f4, 0x56f21c0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f706572705f6d6574612e7273'), 194, 38),
    (0x36ff268, 0x56f1d88, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f636c656172696e67686f7573652f636c656172696e67686f7573652e7273'), 1500, 109),
    (0x36ff37c, 0x56f1cb0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f636c656172696e67686f7573652f6f7261636c652f6f7261636c652e7273'), 197, 18),
    (0x36ff3b1, 0x56f1d70, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f636c656172696e67686f7573652f636c656172696e67686f7573652e7273'), 1508, 110),
]
CALLERS = [0x36fb178, 0x36fbf0a, 0x36ffa5a, 0x37111d1]
CALLER_FUNCTIONS = {'0x36fb178': ('0x36f7c40', '0x36fe82a'), '0x36fbf0a': ('0x36f7c40', '0x36fe82a'), '0x36ffa5a': ('0x36ff770', '0x36fff02'), '0x37111d1': ('0x3710a70', '0x3711b9f')}
LEA_REFS = 0
OWN_GOT_SLOTS = []
GOT_SITES = {}


def require(condition, message):
    if not condition:
        raise ValueError(message)


class Reader:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)
        self.by_name = {s['name']: s for s in self.sections}

    def read(self, va, size):
        matches = [s for s in self.sections if s['type'] != 8
                   and s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(matches) == 1, f'Ambiguous or unmapped VA {va:#x}')
        s = matches[0]
        off = s['offset'] + va - s['address']
        return self.data[off:off + size]


def relocations(reader):
    raw = reader.read(reader.by_name['.rela.dyn']['address'],
                      reader.by_name['.rela.dyn']['size'])
    rels = {}
    for off in range(0, len(raw), 24):
        address, info, addend = struct.unpack_from('<QQq', raw, off)
        if info == 8:
            require(address not in rels, 'Duplicate relative relocation')
            rels[address] = addend
    return rels


def analyze(data):
    reader = Reader(data)
    body = reader.read(START, END - START)
    require(body == BODY, 'Body bytes changed')
    require(hashlib.sha256(body).hexdigest() == BODY_SHA256, 'Body hash changed')

    eh = reader.by_name['.eh_frame']
    require(eh['address'] <= FDE_VA < eh['address'] + eh['size'],
            'FDE outside .eh_frame')
    record = reader.read(FDE_VA, len(FDE))
    require(record == FDE, 'FDE record changed')
    length = struct.unpack_from('<I', record, 0)[0]
    pc = FDE_VA + 8 + struct.unpack_from('<i', record, 8)[0]
    extent = struct.unpack_from('<I', record, 12)[0]
    require(length == len(FDE) - 4, 'FDE length changed')
    require((pc, pc + extent) == (START, END), 'FDE PC range changed')

    for offset, pattern, rel_pos, insn_len, destination in BRANCHES:
        raw = bytes.fromhex(pattern)
        require(body[offset:offset + len(raw)] == raw,
                f'Branch instruction changed at +{offset:#x}')
        fmt = '<b' if insn_len == 2 else '<i'
        rel = struct.unpack_from(fmt, body, offset + rel_pos)[0]
        require(START + offset + insn_len + rel == destination,
                f'Branch destination changed at +{offset:#x}')
        require(START <= destination < END, 'Branch escapes body')

    for offset, pattern, rel_pos, insn_len, destination in TAIL_CALLS:
        raw = bytes.fromhex(pattern)
        require(body[offset:offset + len(raw)] == raw,
                f'Tail-jump instruction changed at +{offset:#x}')
        fmt = '<b' if insn_len == 2 else '<i'
        rel = struct.unpack_from(fmt, body, offset + rel_pos)[0]
        require(START + offset + insn_len + rel == destination,
                f'Tail-jump destination changed at +{offset:#x}')
        require(not (START <= destination < END), 'Tail jump stayed inside the body')

    for site, target in DIRECT_CALLS:
        off = site - START
        require(body[off] == 0xe8, f'Direct call opcode changed at {site:#x}')
        rel = struct.unpack_from('<i', body, off + 1)[0]
        require(site + 5 + rel == target,
                f'Direct call destination changed at {site:#x}')

    rels = relocations(reader)
    for site, slot in INDIRECT_CALLS:
        off = site - START
        require(body[off:off + 2] == b'\xff\x15',
                f'Indirect call opcode changed at {site:#x}')
        disp = struct.unpack_from('<i', body, off + 2)[0]
        require(site + 6 + disp == slot,
                f'Indirect call slot changed at {site:#x}')

    seen = []
    for site, loc_va, path, line, column in LOCATIONS:
        off = site - START
        require(body[off:off + 3] in (b'\x48\x8d\x3d', b'\x48\x8d\x15',
                                      b'\x4c\x8d\x1d'),
                f'Location lea changed at {site:#x}')
        require(site + 7 + struct.unpack_from('<i', body, off + 3)[0] == loc_va,
                f'Location address changed at {site:#x}')
        path_va = rels.get(loc_va)
        require(path_va is not None, f'Location relocation missing at {loc_va:#x}')
        length_, line_, column_ = struct.unpack('<QII', reader.read(loc_va + 8, 16))
        require((length_, line_, column_) == (len(path), line, column),
                f'Location layout changed at {loc_va:#x}')
        require(reader.read(path_va, length_) == path,
                f'panic path changed at {loc_va:#x}')
        seen.append(dict(location_va=hex(loc_va), line=line, column=column,
                         path=path.decode().rsplit('src/', 1)[-1]))

    text = reader.by_name['.text']
    code = reader.read(text['address'], text['size'])
    direct = []
    pos = 0
    while (pos := code.find(b'\xe8', pos)) >= 0:
        if pos + 5 <= len(code):
            destination = (text['address'] + pos + 5
                           + struct.unpack_from('<i', code, pos + 1)[0])
            if destination == START:
                direct.append(text['address'] + pos)
        pos += 1
    require(direct == CALLERS, f'Direct caller census changed: {[hex(x) for x in direct]}')

    lea_refs = 0
    pos = 0
    while (pos := code.find(b'\x48\x8d', pos)) >= 0:
        if pos + 7 <= len(code) and (code[pos + 2] & 0xC7) == 0x05:
            destination = (text['address'] + pos + 7
                           + struct.unpack_from('<i', code, pos + 3)[0])
            if destination == START:
                lea_refs += 1
        pos += 1
    require(lea_refs == LEA_REFS, f'lea census changed: {lea_refs}')

    from collections import Counter
    return dict(
        target_release='94', target_sha256=SHA256,
        coordinate_system='ELF virtual addresses, no runtime rebase',
        body=dict(start_va=hex(START), end_va_exclusive=hex(END), bytes=len(body),
                  sha256=BODY_SHA256, fde_va=hex(FDE_VA)),
        locations=seen,
        direct_calls={hex(t): n for t, n in Counter(t for _, t in DIRECT_CALLS).items()},
        tail_calls={hex(t): n for t, n in Counter(t for _, _, _, _, t in TAIL_CALLS).items()},
        indirect_got={hex(slot): n for slot, n in
                      Counter(slot for _, slot in INDIRECT_CALLS).items()},
        call_census=dict(direct_e8=[hex(x) for x in CALLERS], lea_references=LEA_REFS,
                         caller_functions=CALLER_FUNCTIONS,
                         own_got_slots=OWN_GOT_SLOTS, got_sites=GOT_SITES,
                         denominator='complete .text scan for e8 and lea encodings'),
        captured_binary_executed=False, progress_gate_requested=False)


def inspect(path):
    data = Path(path).read_bytes()
    require(len(data) == 91774280 and hashlib.sha256(data).hexdigest() == SHA256,
            'Expected exact node #94 size/SHA-256')
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--check', type=Path, help='Compare with retained JSON; fail on drift')
    parser.add_argument('--output', type=Path, help='Write the record JSON to this path')
    args = parser.parse_args()
    result = inspect(args.binary)
    text = json.dumps(result, indent=2, sort_keys=True) + '\n'
    if args.check is not None:
        expected = args.check.read_text()
        require(text == expected, 'Retained evidence record drifted')
        print('Record matches retained evidence.')
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text)
    else:
        print(text)


if __name__ == '__main__':
    main()

