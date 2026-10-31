#!/usr/bin/env python3
"""Authenticated node94 impl-ntl-395a2c0 binding (0x395a2c0).

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

START, END = 0x395a2c0, 0x395af58
FDE_VA = 0x11c77dc
FDE = bytes.fromhex(
    '50000000b49b2000dc2a7902980c000004bb1090ff410e10420e18420e20420e'
    '28420e30410e38470ec00383078c068d058e048f03860203810b0e38410e3042'
    '0e28420e20420e18420e10410e08410ec0030000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ec880100004d89cf4c898424b00000004989d648'
    '897424104989fc4989cd4901d50f80ab0b000031c04d85ed490f4fc54d85f64c'
    '8924240f8eaf02000048894424204c896c241848894c2408498db42484000000'
    '4c89fb4c89ffe855bbffff41833c24020f826f0200004989c74989dc488b0c24'
    '488b4108488b59184885c00f95c14885db0f95c220ca80fa010f854602000048'
    '8b1424488b6a104531ed660f1f440000f6c1010f84780b00004d85ed7422410f'
    'b78de60000004839cd0f83c10000004c89e94889eae9da000000660f1f440000'
    '4885ed74384889e94989c54883e107743131d2666666662e0f1f840000000000'
    '4d8bade800000048ffc24839d175f14889e84829d04883fd087315eb514989c5'
    'eb4c4889e84883fd0872430f1f440000498b8de8000000488b89e8000000488b'
    '89e8000000488b89e8000000488b89e8000000488b89e8000000488b89e80000'
    '004c8ba9e80000004883c0f875c231ed31c0410fb78de60000004839cd0f824c'
    'ffffff666666662e0f1f840000000000498b4d004885c90f84850a000048ffc0'
    '410fb795e40000004989cd663b91e600000073dc4885c00f8493000000488d34'
    'd14881c6f00000004889c74883e7070f84cb0000004531c00f1f840000000000'
    '4c8b2e498db5e800000049ffc04c39c775ee4889c74c29c74883f80872436690'
    '488b06488b80e8000000488b80e8000000488b80e8000000488b80e800000048'
    '8b80e8000000488b80e80000004c8ba8e8000000498db5e80000004883c7f875'
    'bf31edeb1266662e0f1f840000000000488d6a014989cd488d04928b54811889'
    '542470660f10448108660f294424604c89e7488d742460e844b9ffff4c89f948'
    '01c1702a4989cfb101b80000000048ffcb0f8519feffffeb4c0f1f8000000000'
    '4889c74883f8087298e952ffffff48c1f93f48ba00000000000000804831d149'
    '01c74c0f40f931ff488d355934db01ff15fb8be101b101b80000000048ffcb0f'
    '85cbfdffff4c8b2424488b4c24084c8b6c2418488b4424204d85ed7e120f57c0'
    'f2480f2ac0f20f5e0593088bfceb04660f57c0f20f114424200f57c0f2480f2a'
    'c1f20f5e0577088bfcf20f118424e8000000498b442450498b4c245831d24889'
    'c64885c00f95c27405498b742460488994242001000048c78424280100000000'
    '0000488984243001000048898c2438010000488994244001000048c784244801'
    '000000000000488984245001000048898c24580100004889b42460010000488d'
    '8424e800000048898424680100004c8dbc24b8000000488db424200100004c89'
    'ffe86ac59bff488b9c24b80000004885db0f84d80000004c897424184c8bb424'
    'c00000004c8b2ddd3de1010fb7833e01000048894424088d0485000000004c8d'
    '248049f7dc48c7c5ffffffff41bf6000000066666666662e0f1f840000000000'
    '4b8d043c4883f86074364a8d343bba14000000488b7c241041ffd548984885c0'
    '0f98c10f9fc028c848ffc54983c7143c0174cd0fb6c085c0750beb200f1f4000'
    '488b6c24084983ee010f822e070000488b9ceb40010000e96fffffff48895c24'
    '684c8974247048896c2478488d8424b8000000488984248000000048c7442460'
    '000000004c8b24244c8b742418eb2a488b4c24108b411089842490000000660f'
    '1001660f118424800000004c897c246048c744246800000000488d7c2460e82d'
    '07a6ff0f57c0f2490f2ac6f20f5e05ad068bfcf20f5800f20f1100488b8424b8'
    '000000488b8c24c000000031d24889c64885c00f95c27408488bb424c8000000'
    '498d5c2450488954246048c744246800000000488944247048894c2478488994'
    '248000000048c784248800000000000000488984249000000048898c24980000'
    '004889b424a0000000f20f10054f088bfc660f2e44242048895c24084c8d7c24'
    '280f86e9010000660f1f8400000000004c89ff488d742460e8a35fa5ff488b44'
    '24284885c00f84d5030000488b4c2438488d0c89488d14884883c260660f1044'
    '8860660f298424d00000008b448870898424e00000004c8b334d85f60f84ce00'
    '00004889542410498b5c2458450fb7bef6020000428d04bd00000000488d2c80'
    '48f7dd49c7c5ffffffff41bc18020000498d042c483d1802000074444b8d3426'
    'ba14000000488dbc24d0000000ff15953be10148984885c00f98c10f9fc028c8'
    '49ffc54983c4143c0174c50fb6c085c0742e4883eb017315e9d20000000f1f00'
    '4d89fd4883eb010f82c20000004f8bb4eef8020000e972ffffff660f1f440000'
    '4c8974243048895c24384c896c2440488b5c240848895c244848c74424280000'
    '00004c8b24244c8d7c2428eb240f1f008b4210488d4c2448894110660f100266'
    '0f110148895c242848c744243000000000660f57c0660f298424f000000048c7'
    '84240001000000000000488b8c24b00000008b4108488d942408010000894208'
    '488b014889028b4108894214488b014889420c4c89ff488db424f0000000e84d'
    '3fa6ff48c70000000000e961feffff4c8974243048c7442438000000004c896c'
    '2440488b5424108b4210488d4c2448894110660f1002660f1101488b5c240848'
    '895c2428e939ffffff0f1f80000000004c89ff488d742460e8c35da5ff488b44'
    '24284885c00f84f5010000488b542438488d0c92f20f1044d0080f104c88600f'
    '298c24d00000008b548870899424e0000000660f57d2f20f100d7a038bfc660f'
    '2ec8770af20f5e442420660f28d0488d14884883c2604c8b334d85f6f20f1154'
    '24100f84d80000004889542418498b5c2458450fb7bef6020000428d04bd0000'
    '0000488d2c8048f7dd49c7c5ffffffff41bc18020000662e0f1f840000000000'
    '498d042c483d1802000074444b8d3426ba14000000488dbc24d0000000ff1585'
    '39e10148984885c00f98c10f9fc028c849ffc54983c4143c0174c50fb6c085c0'
    '742e4883eb017315e9d50000000f1f004d89fd4883eb010f82c50000004f8bb4'
    'eef8020000e968ffffff660f1f4400004c8974243048895c24384c896c244048'
    '8b5c240848895c244848c7442428000000004c8b24244c8d7c2428eb240f1f00'
    '8b4210488d4c2448894110660f1002660f110148895c242848c7442430000000'
    '00660f57c0660f298424f000000048c784240001000000000000488b8c24b000'
    '00008b4108488d942408010000894208488b014889028b4108894214488b0148'
    '89420c4c89ff488db424f0000000e83d3da6fff20f10442410f20f1100e92efe'
    'ffff4c8974243048c7442438000000004c896c2440488b5424188b4210488d4c'
    '2448894110660f1002660f1101488b5c240848895c2428e936ffffff0f1f4000'
    '488d7c2428488d742460e8b15ba5ff48837c24280075e9498b4c2450498b4424'
    '604885c9410f95c04885c00f95c24420c280fa010f85d1010000498b54245831'
    'f6eb24666666662e0f1f84000000000048ffc241b0014889feb90000000048ff'
    'c80f84a401000041f6c0010f84400200004885f6741a0fb7bef60200004839fa'
    '0f83ba0000004889f7e9d800000066904885d274384889d74889ce4883e70774'
    '314531c06666662e0f1f840000000000488bb6f802000049ffc04c39c775f148'
    '89d14c29c14883fa087315eb514889ceeb4c4889d14883fa0872430f1f440000'
    '488b96f8020000488b92f8020000488b92f8020000488b92f8020000488b92f8'
    '020000488b92f8020000488b92f8020000488bb2f80200004883c1f875c231c9'
    '31d20fb7bef60200004839fa0f8254ffffff66666666662e0f1f840000000000'
    '488bbe100200004885ff0f844301000048ffc10fb796f40200004889fe663b97'
    'f602000073da4885c90f84e1feffff488d14d74881c2000300004889ce4883e6'
    '07747d4531c0662e0f1f840000000000488b3a488d97f802000049ffc04c39c6'
    '75ee4889ce4c29c64883f90872436690488b0a488b89f8020000488b89f80200'
    '00488b89f8020000488b89f8020000488b89f8020000488b89f8020000488bb9'
    'f8020000488d97f80200004883c6f875bf31d2e95bfeffff0f1f840000000000'
    '4889ce4883f90873a7ebe64881c4880100005b415c415d415e415f5dc348895c'
    '246848c74424700000000048896c2478488b442410660f1000660f1184248000'
    '00008b401089842490000000488d8424b80000004889442460e9c6f8ffff49c1'
    'fd3f48b800000000000000804c31e84989cd4d01f5488d35cc2adb014c0f40e8'
    '31ff4889cbff15c582e1014889d9e920f4ffff488d3d0ef1d801ff159035e101'
    'eb0d488d3dfff0d801ff158135e1010f0b488d3d28dcd801ff157235e1014889'
    'c3488dbc24b8000000e80279a9ffeb36ff151232e101eb004889c34c8db42470'
    '0100004c8d7c24600f1f8400000000004c89f74c89fee8c558a5ff4883bc2470'
    '0100000075ea4889dfe8c251d001ff15d431e1010f0b0f0b'
)
BODY_SHA256 = 'ba0e0d2a591c1f9400da82c86432081e961094b0d66b94f579ef8dfae0eff928'
BRANCHES = [
    (0x2d, '0f80ab0b0000', 2, 6, 0x395ae9e),
    (0x43, '0f8eaf020000', 2, 6, 0x395a5b8),
    (0x70, '0f826f020000', 2, 6, 0x395a5a5),
    (0x99, '0f8546020000', 2, 6, 0x395a5a5),
    (0xb3, '0f84780b0000', 2, 6, 0x395aef1),
    (0xbc, '7422', 1, 2, 0x395a3a0),
    (0xc9, '0f83c1000000', 2, 6, 0x395a450),
    (0xd5, 'e9da000000', 1, 5, 0x395a474),
    (0xe3, '7438', 1, 2, 0x395a3dd),
    (0xef, '7431', 1, 2, 0x395a3e2),
    (0x10d, '75f1', 1, 2, 0x395a3c0),
    (0x119, '7315', 1, 2, 0x395a3f0),
    (0x11b, 'eb51', 1, 2, 0x395a42e),
    (0x120, 'eb4c', 1, 2, 0x395a42e),
    (0x129, '7243', 1, 2, 0x395a42e),
    (0x16c, '75c2', 1, 2, 0x395a3f0),
    (0x17d, '0f824cffffff', 2, 6, 0x395a38f),
    (0x197, '0f84850a0000', 2, 6, 0x395aee2),
    (0x1b2, '73dc', 1, 2, 0x395a450),
    (0x1b7, '0f8493000000', 2, 6, 0x395a510),
    (0x1cf, '0f84cb000000', 2, 6, 0x395a560),
    (0x1f0, '75ee', 1, 2, 0x395a4a0),
    (0x1fc, '7243', 1, 2, 0x395a501),
    (0x23f, '75bf', 1, 2, 0x395a4c0),
    (0x243, 'eb12', 1, 2, 0x395a517),
    (0x282, '702a', 1, 2, 0x395a56e),
    (0x291, '0f8519feffff', 2, 6, 0x395a370),
    (0x297, 'eb4c', 1, 2, 0x395a5a5),
    (0x2a7, '7298', 1, 2, 0x395a501),
    (0x2a9, 'e952ffffff', 1, 5, 0x395a4c0),
    (0x2df, '0f85cbfdffff', 2, 6, 0x395a370),
    (0x2fb, '7e12', 1, 2, 0x395a5cf),
    (0x30d, 'eb04', 1, 2, 0x395a5d3),
    (0x347, '7405', 1, 2, 0x395a60e),
    (0x3d1, '0f84d8000000', 2, 6, 0x395a76f),
    (0x428, '7436', 1, 2, 0x395a720),
    (0x451, '74cd', 1, 2, 0x395a6e0),
    (0x458, '750b', 1, 2, 0x395a725),
    (0x45a, 'eb20', 1, 2, 0x395a73c),
    (0x469, '0f822e070000', 2, 6, 0x395ae5d),
    (0x477, 'e96fffffff', 1, 5, 0x395a6ab),
    (0x4ad, 'eb2a', 1, 2, 0x395a799),
    (0x516, '7408', 1, 2, 0x395a7e0),
    (0x581, '0f86e9010000', 2, 6, 0x395aa30),
    (0x5a5, '0f84d5030000', 2, 6, 0x395ac40),
    (0x5dc, '0f84ce000000', 2, 6, 0x395a970),
    (0x61a, '7444', 1, 2, 0x395a920),
    (0x649, '74c5', 1, 2, 0x395a8d0),
    (0x650, '742e', 1, 2, 0x395a940),
    (0x656, '7315', 1, 2, 0x395a92d),
    (0x658, 'e9d2000000', 1, 5, 0x395a9ef),
    (0x667, '0f82c2000000', 2, 6, 0x395a9ef),
    (0x675, 'e972ffffff', 1, 5, 0x395a8ac),
    (0x6ab, 'eb24', 1, 2, 0x395a991),
    (0x72a, 'e961feffff', 1, 5, 0x395a850),
    (0x764, 'e939ffffff', 1, 5, 0x395a962),
    (0x785, '0f84f5010000', 2, 6, 0x395ac40),
    (0x7c2, '770a', 1, 2, 0x395aa8e),
    (0x7e2, '0f84d8000000', 2, 6, 0x395ab80),
    (0x82a, '7444', 1, 2, 0x395ab30),
    (0x859, '74c5', 1, 2, 0x395aae0),
    (0x860, '742e', 1, 2, 0x395ab50),
    (0x866, '7315', 1, 2, 0x395ab3d),
    (0x868, 'e9d5000000', 1, 5, 0x395ac02),
    (0x877, '0f82c5000000', 2, 6, 0x395ac02),
    (0x885, 'e968ffffff', 1, 5, 0x395aab2),
    (0x8bb, 'eb24', 1, 2, 0x395aba1),
    (0x93d, 'e92efeffff', 1, 5, 0x395aa30),
    (0x977, 'e936ffffff', 1, 5, 0x395ab72),
    (0x995, '75e9', 1, 2, 0x395ac40),
    (0x9b4, '0f85d1010000', 2, 6, 0x395ae4b),
    (0x9c1, 'eb24', 1, 2, 0x395aca7),
    (0x9e1, '0f84a4010000', 2, 6, 0x395ae4b),
    (0x9eb, '0f8440020000', 2, 6, 0x395aef1),
    (0x9f4, '741a', 1, 2, 0x395acd0),
    (0xa00, '0f83ba000000', 2, 6, 0x395ad80),
    (0xa09, 'e9d8000000', 1, 5, 0x395ada6),
    (0xa13, '7438', 1, 2, 0x395ad0d),
    (0xa1f, '7431', 1, 2, 0x395ad12),
    (0xa3d, '75f1', 1, 2, 0x395acf0),
    (0xa49, '7315', 1, 2, 0x395ad20),
    (0xa4b, 'eb51', 1, 2, 0x395ad5e),
    (0xa50, 'eb4c', 1, 2, 0x395ad5e),
    (0xa59, '7243', 1, 2, 0x395ad5e),
    (0xa9c, '75c2', 1, 2, 0x395ad20),
    (0xaac, '0f8254ffffff', 2, 6, 0x395acc6),
    (0xaca, '0f8443010000', 2, 6, 0x395aed3),
    (0xae4, '73da', 1, 2, 0x395ad80),
    (0xae9, '0f84e1feffff', 2, 6, 0x395ac90),
    (0xb01, '747d', 1, 2, 0x395ae40),
    (0xb20, '75ee', 1, 2, 0x395add0),
    (0xb2c, '7243', 1, 2, 0x395ae31),
    (0xb6f, '75bf', 1, 2, 0x395adf0),
    (0xb73, 'e95bfeffff', 1, 5, 0x395ac93),
    (0xb87, '73a7', 1, 2, 0x395adf0),
    (0xb89, 'ebe6', 1, 2, 0x395ae31),
    (0xbd9, 'e9c6f8ffff', 1, 5, 0x395a764),
    (0xc0e, 'e920f4ffff', 1, 5, 0x395a2f3),
    (0xc20, 'eb0d', 1, 2, 0x395aeef),
    (0xc4e, 'eb36', 1, 2, 0x395af46),
    (0xc56, 'eb00', 1, 2, 0x395af18),
    (0xc84, '75ea', 1, 2, 0x395af30),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x395a326, 0x3955e80),
    (0x395a537, 0x3955e80),
    (0x395a681, 0x3316bf0),
    (0x395a79e, 0x33baed0),
    (0x395a858, 0x33b0800),
    (0x395a9de, 0x33be930),
    (0x395aa38, 0x33b0800),
    (0x395abee, 0x33be930),
    (0x395ac4a, 0x33b0800),
    (0x395af09, 0x33f2810),
    (0x395af36, 0x33b0800),
    (0x395af49, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x395a58f, 0x5773190),
    (0x395a8ed, 0x576e488),
    (0x395aafd, 0x576e488),
    (0x395aec5, 0x5773190),
    (0x395aeda, 0x576e470),
    (0x395aee9, 0x576e470),
    (0x395aef8, 0x576e470),
    (0x395af10, 0x576e128),
    (0x395af4e, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x395aed3, 0x56e9fe8, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 534, 47),
    (0x395aee2, 0x56e9fe8, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 534, 47),
    (0x395aef1, 0x56e8b20, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 161, 36),
]
CALLERS = [0x395b9e6, 0x395c795]
CALLER_FUNCTIONS = {'0x395b9e6': ('0x395b3a0', '0x395bdc3'), '0x395c795': ('0x395bdd0', '0x395cd78')}
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

