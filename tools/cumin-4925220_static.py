#!/usr/bin/env python3
"""Authenticated node94 cumin-4925220 binding (0x4925220).

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

START, END = 0x4925220, 0x4925f0c
FDE_VA = 0x12a78dc
FDE = bytes.fromhex(
    '50000000b49c2e003cd96703ec0c000004f3ec8dff410e10420e18420e20420e'
    '28420e30410e38470eb00b83078c068d058e048f03860203a50b0e38410e3042'
    '0e28420e20420e18420e10410e08410eb00b0000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ec780500004989d74989f64889fb4c8b228b6a08'
    'bf01000000e8b6e55b004889442450895424584c89a4241803000089ac242003'
    '0000488dbc24b8000000488d742450488d942418030000e8b4e45b0080bc24b8'
    '00000000660f57d2753cf20f108424c00000000f57d2f20f2a9424c80000000f'
    '1405daeb8dfb660f5c05f2db8dfb660f28c8660f15c8f20f58c8f20f5e155e4f'
    '8efbf20f58d1f20f111424bf01000000e82be55b00498907418957084c897424'
    '08488b3b4885ff0f847e000000488b4308f20f1004240fb797821a00004869f2'
    '60020000b96002000049c7c7ffffffff4c8d040e4981f86002000074334e3bb4'
    'ff301a0000410f97c04180d8004881c1a0fdffff49ffc74180f80174d3410fb6'
    'd085d2750eeb1c660f1f8400000000004989d74883e80172144a8bbcff881a00'
    '00eb934829cfe93a02000031ff48895c24504c897424584989fc48897c246048'
    'c7442468000000004c897c2470488d054c598efb488944242048c74424280800'
    '0000488d44242048898424b8000000488d05ba47340048898424c0000000488d'
    '0d1bebe00048898c24c800000048898424d0000000488d44240848898424d800'
    '0000488b05ff0ae50048898424e0000000488d35edb08cfb488dbc2418030000'
    '488d9424b8000000ff15328ce4004c8bb42420030000488b8c2428030000488d'
    'bc24b8000000f20f1005ca4e8efb31f64c89f2ff158f9be400488bb424180300'
    '004885f6740b4c89f731d2ff15bf8be40048c78424b80000000100000048b87b'
    '14ae47e17a843f48898424c0000000488dbc2418030000488db424b8000000ba'
    '60020000ff15568be40048837c24600074594c89a424b800000048c78424c000'
    '0000000000004c89bc24c8000000488b5424584c8d4c2478488d7c2420488db4'
    '24b8000000488d8c24180300004c8d442450e8493c91ff4c8b7c24504c8b7424'
    '204c8b642430e9a70000004c8b7c2450bf881a0000ff15dd8ae4004885c00f84'
    '2b0900004989c648c780201a00000000000066c780821a0000000049890749c7'
    '4708000000004c8b6c2458488dbc24b8000000488db42418030000ba60020000'
    'ff159a8ae400450fb7a6821a00004983fc0b0f83e9080000418d442401664189'
    '86821a00004f89ace6281a00004969c4600200004c89f74801c7488db4241803'
    '0000ba60020000ff15538ae4004c8974242049ff47104969fc600200004c01f7'
    'f20f100424488d150ce9e000be01000000ff15f999e400488d7c2444ff15de92'
    'e4008b432085c00f8483000000f20f104318f20f110424488b4b248b54244c89'
    '942420030000488b5424444889942418030000898424b800000048898c24bc00'
    '000048b8010000001c00000048898424c8000000488d0552198ffb48898424d0'
    '00000048c78424d800000030000000488dbc2418030000488db424b8000000ff'
    '157b92e400660f2e04240f867f070000488d43208b4c244c894808488b4c2444'
    '48890848c74424080000000048c744241800000000488b03488b73104885c00f'
    '95c14885f60f95c220ca80fa010f856c040000488934244531c04885c0410f95'
    'c0488b73084531edeb4f660f1f440000488b142448ffca488b45084889d948c1'
    'e1044c893408488bb424a8000000488974080848ffc348895d10b80000000048'
    '8914244885d24c8b8424b0000000488b7424380f840d0400004489c1f6d14d85'
    'ed0f95c208caf6c201754541b8010000004885f6745c4889f14989c54883e107'
    '745531d26666662e0f1f8400000000004d8bad881a000048ffc24839d175f148'
    '89f04829d04883fe087335eb710f1f0041f6c0010f8487060000410fb78d821a'
    '00004839ce73694d89ee4889f1e9860000004989c5eb474889f04883fe08723e'
    '498b8d881a0000488b89881a0000488b89881a0000488b89881a0000488b8988'
    '1a0000488b89881a0000488b89881a00004c8ba9881a00004883c0f875c231f6'
    '31c0410fb78d821a00004839ce7298904d8bb5201a00004d85f60f8425060000'
    '48ffc0410fb78d801a00004d89f566413b8e821a000073d84885c04c898424b0'
    '0000000f8497000000498d14ce4881c2901a00004889c64883e6070f842f0200'
    '0031ff666666662e0f1f8400000000004c8b2a498d95881a000048ffc74839fe'
    '75ee4889c64829fe4883f80872436690488b02488b80881a0000488b80881a00'
    '00488b80881a0000488b80881a0000488b80881a0000488b80881a00004c8ba8'
    '881a0000498d95881a00004883c6f875bf48c744243800000000eb100f1f4000'
    '488d410148894424384d89f54c69c160020000498b84ce281a000048898424a8'
    '000000438b9c0640020000488b6c24084885ed0f84a70000004c8b6424100fb7'
    '853e0100008d0cc500000000488d1449b91000000049c7c7ffffffff0f1f4000'
    '488d340a4883fe107436423b9cbd14010000400f9cc7400f9fc64028fe4883c1'
    'e849ffc74080fe0174d6400fb6c685c0742e4983ec017315e9ba0100000f1f00'
    '4989c74983ec010f82aa0100004a8bacfd40010000eb87660f1f840000000000'
    '4829cd488d44240848898424a0000000e95c01000066662e0f1f840000000000'
    '31ed4c8984249800000048b800000000ffffffff488b8c24a00000004821c148'
    '09d9488d44240848898424b80000004889ac24c00000004c89a424c80000004c'
    '89bc24d000000048898c24a000000048898c24d800000048c744242000000000'
    '48c74424280800000048c7442430000000004885ed746b4889ac24180300004c'
    '89a424200300004c89bc2428030000488d7c2450488db4241803000089da488d'
    '4c24204c8d8424b80000004c8d8c24dc000000e868bb8fff488b9424b8000000'
    '488b442450488b4c2460eb6d0f1f40004889c64883f8080f8234feffffe9eefd'
    'ffffbf40010000ff156b85e4004885c00f847d03000048c70000000000488944'
    '240848c74424100000000066c7803e010000010089981001000048c740080000'
    '000048c740100800000048c740180000000031c9488d5424084c8b8424980000'
    '0048ff4210488d0c49488d2cc84883c5084d01c64d8bb600020000488b5d1048'
    '3b5d000f85c7fbffff4889efff15c60fe500e9b9fbffff4531e4e983feffff31'
    'c0e99c010000488b4424184883f8030f828d000000488b4c2408488b54241031'
    'f64885c9400f95c6480f44c1488974245048c74424580000000048894c246048'
    '89542468488974247048c74424780000000048898c2480000000488994248800'
    '00004889842490000000488dbc24b8000000488d742450e8746ef5ff488bb424'
    'b80000004885f67414488bbc24c000000048c1e60331d2ff157384e400488b44'
    '24184883f8010f86f60000008b542448b9c5b3a291480fafca48c1e92b6bf13c'
    'b989888888480fafca48c1e9254869d18988880848c1ea216bd23c29d101f181'
    'f9ffff00000f877102000081f9a10500000f831d02000083f9060f82a2000000'
    '488b4c2408488b54241031f64885c9400f95c6480f44c14889b4241803000048'
    'c78424200300000000000048898c242803000048899424300300004889b42438'
    '03000048c78424400300000000000048898c2448030000488994245003000048'
    '89842458030000488dbc24b8000000488db42418030000e8746df5ff488bb424'
    'b80000004885f67414488bbc24c000000048c1e60331d2ff157383e400488b44'
    '2418488b4c2408488b54241031f64885c9400f95c6480f44c14889b424b80000'
    '0048c78424c00000000000000048898c24c800000048899424d00000004889b4'
    '24d800000048c78424e00000000000000048898c24e800000048899424f00000'
    '0048898424f8000000488d5c24204c8db424b80000004c8b3df382e4000f1f00'
    '4889df4c89f6e8e54b0200488b4424204885c07428488b4c2430488d0c49488b'
    '74c8084889f248f7da701273d3488b7cc81048c1e60431d241ffd7ebc3488d7c'
    '2420488db424b8000000e8a14b0200488b4424204885c07456488d5c24204c8d'
    'b424b8000000eb1d0f1f8400000000004889df4c89f6e8754b0200488b442420'
    '4885c0742a488b4c2430488d0c49488b74c8084885f674d8488d04c84883c008'
    '488b780848c1e60431d241ffd7ebc14881c4780500005b415c415d415e415f5d'
    'c3488d3d98d1e000ff158286e400e991000000bf08000000be40010000ff151d'
    '82e400eb7f488d3d44e1e000ff155e86e400eb70488d3dd44f8ffb488d152e6d'
    'd400be1f000000ff15db82e400eb55bf08000000be881a0000ff15e181e400eb'
    '43488d3d186c8efb488d15d165df00be20000000ff15ae82e400eb28488d3d47'
    '3f8ffb488d0dd64dd4004c8d056f4cd400488d9424b8000000be2b000000ff15'
    'c481e4000f0b4889c3488bb424180300004885f674684c89f731d2ff156f81e4'
    '004889dfe867a2d300eb464889c3488dbc24b8000000e875c0fdffeb414889c3'
    '488dbc24b8000000e8d3ed8affeb2fff155382e4004889c3488dbc2418030000'
    'e8db0ffeffeb17ff153b82e4000f0beb004889c3488d7c2408e882b0fdff4889'
    'dfe80aa2d300ff151c82e400'
)
BODY_SHA256 = 'e4fc6c8d65164fab9b900d39929580ecd43e25e1125d6c03e2cfb9c62632da5c'
BRANCHES = [
    (0x68, '753c', 1, 2, 0x49252c6),
    (0xc7, '0f847e000000', 2, 6, 0x492536b),
    (0xfb, '7433', 1, 2, 0x4925350),
    (0x11b, '74d3', 1, 2, 0x4925310),
    (0x123, '750e', 1, 2, 0x4925353),
    (0x125, 'eb1c', 1, 2, 0x4925363),
    (0x137, '7214', 1, 2, 0x492536d),
    (0x141, 'eb93', 1, 2, 0x49252f6),
    (0x146, 'e93a020000', 1, 5, 0x49255a5),
    (0x224, '740b', 1, 2, 0x4925451),
    (0x270, '7459', 1, 2, 0x49254eb),
    (0x2c6, 'e9a7000000', 1, 5, 0x4925592),
    (0x2de, '0f842b090000', 2, 6, 0x4925e2f),
    (0x332, '0f83e9080000', 2, 6, 0x4925e41),
    (0x3a7, '0f8483000000', 2, 6, 0x4925650),
    (0x42a, '0f867f070000', 2, 6, 0x4925dcf),
    (0x46d, '0f856c040000', 2, 6, 0x4925aff),
    (0x488, 'eb4f', 1, 2, 0x49256f9),
    (0x4d3, '0f840d040000', 2, 6, 0x4925b06),
    (0x4e9, '7545', 1, 2, 0x4925750),
    (0x4f4, '745c', 1, 2, 0x4925772),
    (0x500, '7455', 1, 2, 0x4925777),
    (0x51d, '75f1', 1, 2, 0x4925730),
    (0x529, '7335', 1, 2, 0x4925780),
    (0x52b, 'eb71', 1, 2, 0x49257be),
    (0x534, '0f8487060000', 2, 6, 0x4925de1),
    (0x545, '7369', 1, 2, 0x49257d0),
    (0x54d, 'e986000000', 1, 5, 0x49257f8),
    (0x555, 'eb47', 1, 2, 0x49257be),
    (0x55e, '723e', 1, 2, 0x49257be),
    (0x59c, '75c2', 1, 2, 0x4925780),
    (0x5ad, '7298', 1, 2, 0x4925767),
    (0x5ba, '0f8425060000', 2, 6, 0x4925e05),
    (0x5d6, '73d8', 1, 2, 0x49257d0),
    (0x5e3, '0f8497000000', 2, 6, 0x49258a0),
    (0x5fb, '0f842f020000', 2, 6, 0x4925a50),
    (0x620, '75ee', 1, 2, 0x4925830),
    (0x62c, '7243', 1, 2, 0x4925891),
    (0x66f, '75bf', 1, 2, 0x4925850),
    (0x67a, 'eb10', 1, 2, 0x49258ac),
    (0x6b3, '0f84a7000000', 2, 6, 0x4925980),
    (0x6e8, '7436', 1, 2, 0x4925940),
    (0x708, '74d6', 1, 2, 0x4925900),
    (0x710, '742e', 1, 2, 0x4925960),
    (0x716, '7315', 1, 2, 0x492594d),
    (0x718, 'e9ba010000', 1, 5, 0x4925af7),
    (0x727, '0f82aa010000', 2, 6, 0x4925af7),
    (0x735, 'eb87', 1, 2, 0x49258de),
    (0x750, 'e95c010000', 1, 5, 0x4925ad1),
    (0x7d5, '746b', 1, 2, 0x4925a62),
    (0x82a, 'eb6d', 1, 2, 0x4925ab9),
    (0x837, '0f8234feffff', 2, 6, 0x4925891),
    (0x83d, 'e9eefdffff', 1, 5, 0x4925850),
    (0x850, '0f847d030000', 2, 6, 0x4925df3),
    (0x8c3, '0f85c7fbffff', 2, 6, 0x49256b0),
    (0x8d2, 'e9b9fbffff', 1, 5, 0x49256b0),
    (0x8da, 'e983feffff', 1, 5, 0x4925982),
    (0x8e1, 'e99c010000', 1, 5, 0x4925ca2),
    (0x8ef, '0f828d000000', 2, 6, 0x4925ba2),
    (0x967, '7414', 1, 2, 0x4925b9d),
    (0x986, '0f86f6000000', 2, 6, 0x4925ca2),
    (0x9c5, '0f8771020000', 2, 6, 0x4925e5c),
    (0x9d1, '0f831d020000', 2, 6, 0x4925e14),
    (0x9da, '0f82a2000000', 2, 6, 0x4925ca2),
    (0xa67, '7414', 1, 2, 0x4925c9d),
    (0xb13, '7428', 1, 2, 0x4925d5d),
    (0xb29, '7012', 1, 2, 0x4925d5d),
    (0xb2b, '73d3', 1, 2, 0x4925d20),
    (0xb3b, 'ebc3', 1, 2, 0x4925d20),
    (0xb57, '7456', 1, 2, 0x4925dcf),
    (0xb66, 'eb1d', 1, 2, 0x4925da5),
    (0xb83, '742a', 1, 2, 0x4925dcf),
    (0xb96, '74d8', 1, 2, 0x4925d90),
    (0xbad, 'ebc1', 1, 2, 0x4925d90),
    (0xbce, 'e991000000', 1, 5, 0x4925e84),
    (0xbe3, 'eb7f', 1, 2, 0x4925e84),
    (0xbf2, 'eb70', 1, 2, 0x4925e84),
    (0xc0d, 'eb55', 1, 2, 0x4925e84),
    (0xc1f, 'eb43', 1, 2, 0x4925e84),
    (0xc3a, 'eb28', 1, 2, 0x4925e84),
    (0xc74, '7468', 1, 2, 0x4925efe),
    (0xc89, 'eb46', 1, 2, 0x4925ef1),
    (0xc9b, 'eb41', 1, 2, 0x4925efe),
    (0xcad, 'eb2f', 1, 2, 0x4925efe),
    (0xcc5, 'eb17', 1, 2, 0x4925efe),
    (0xccf, 'eb00', 1, 2, 0x4925ef1),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x4925245, 0x4ee3800),
    (0x4925277, 0x4ee3730),
    (0x49252d0, 0x4ee3800),
    (0x49254d2, 0x4239120),
    (0x4925a33, 0x42215a0),
    (0x4925b77, 0x487c9f0),
    (0x4925c77, 0x487c9f0),
    (0x4925d26, 0x494a910),
    (0x4925d6a, 0x494a910),
    (0x4925d96, 0x494a910),
    (0x4925ea4, 0x5660110),
    (0x4925eb6, 0x4901f30),
    (0x4925ec8, 0x41d4ca0),
    (0x4925ee0, 0x4906ec0),
    (0x4925ef9, 0x4900f80),
    (0x4925f01, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x4925408, 0x576e040),
    (0x4925433, 0x576efc8),
    (0x492544b, 0x576e010),
    (0x4925484, 0x576dfe0),
    (0x49254f5, 0x576dfd8),
    (0x4925540, 0x576dfe0),
    (0x4925587, 0x576dfe0),
    (0x49255b1, 0x576efb0),
    (0x49255bc, 0x576e8a0),
    (0x492563f, 0x576e8c0),
    (0x4925a67, 0x576dfd8),
    (0x4925aec, 0x5776ab8),
    (0x4925b97, 0x576e010),
    (0x4925c97, 0x576e010),
    (0x4925de8, 0x576e470),
    (0x4925dfd, 0x576e020),
    (0x4925e0c, 0x576e470),
    (0x4925e27, 0x576e108),
    (0x4925e39, 0x576e020),
    (0x4925e54, 0x576e108),
    (0x4925e7e, 0x576e048),
    (0x4925e9b, 0x576e010),
    (0x4925ecf, 0x576e128),
    (0x4925ee7, 0x576e128),
    (0x4925f06, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x4925de1, 0x5732f80, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 161, 36),
    (0x4925e05, 0x5733f50, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 534, 47),
    (0x4925e1b, 0x566cb50, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f626173652f7372632f63756d696e2e7273'), 21, 13),
    (0x4925e48, 0x571c420, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e6f64652e7273'), 670, 9),
]
CALLERS = [0x4716570, 0x47165b6, 0x4716710, 0x471685a, 0x471697d, 0x47169bf, 0x4716b70, 0x4716bdb, 0x4716c6d, 0x4716caa, 0x4716ce3, 0x4716fa3, 0x47172d9, 0x471731f, 0x4717610, 0x471775d, 0x471778b]
CALLER_FUNCTIONS = {'0x4716570': ('0x47162d0', '0x4717c46'), '0x47165b6': ('0x47162d0', '0x4717c46'), '0x4716710': ('0x47162d0', '0x4717c46'), '0x471685a': ('0x47162d0', '0x4717c46'), '0x471697d': ('0x47162d0', '0x4717c46'), '0x47169bf': ('0x47162d0', '0x4717c46'), '0x4716b70': ('0x47162d0', '0x4717c46'), '0x4716bdb': ('0x47162d0', '0x4717c46'), '0x4716c6d': ('0x47162d0', '0x4717c46'), '0x4716caa': ('0x47162d0', '0x4717c46'), '0x4716ce3': ('0x47162d0', '0x4717c46'), '0x4716fa3': ('0x47162d0', '0x4717c46'), '0x47172d9': ('0x47162d0', '0x4717c46'), '0x471731f': ('0x47162d0', '0x4717c46'), '0x4717610': ('0x47162d0', '0x4717c46'), '0x471775d': ('0x47162d0', '0x4717c46'), '0x471778b': ('0x47162d0', '0x4717c46')}
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

