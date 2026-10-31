#!/usr/bin/env python3
"""Authenticated node94 oracle-3757610 binding (0x3757610).

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

START, END = 0x3757610, 0x375809a
FDE_VA = 0x11a6b14
FDE = bytes.fromhex(
    '50000000ec8e1e00f40a5b028a0a000004277690ff410e10420e18420e20420e'
    '28420e30410e38470ea00283078c068d058e048f0386020303090e38410e3042'
    '0e28420e20420e18420e10410e08410ea0020000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ece800000048894c24684989f448897c24508b42'
    '10898424e00000004889542478660f1002660f298424d0000000488b46088038'
    '000f84ff060000498b442410498b4c24188b1089542434488b400448898424b8'
    '0000004d8b5c2420488b410848898424c00000004c8b511048c7442438000000'
    '0048c74424400800000048c744244800000000488b742468488b46084c8b6618'
    '4885c00f95c14d85e40f95c284d10f84a80700004531ff4885c0410f95c7488b'
    '2e4c8b761048c74424180000000049b9ffffffffffffff7f31db4c895424604c'
    '895c2458eb32662e0f1f840000000000f20f104cd060660f57c0660f2ec80f85'
    'ac0000000f8aa6000000b80000000049ffcc0f84d90600004885db756341f6c7'
    '01745d41bf010000004d85f60f84410100004c89f14889c34883e1070f843601'
    '000031d26666662e0f1f840000000000488b9b2803000048ffc24839d175f14c'
    '89f04829d04983fe080f8321010000e95a0100006666662e0f1f840000000000'
    '41f6c7010f84880800000fb78b220300004939ce0f83560100004889d94c89f2'
    'e97101000066662e0f1f840000000000f20f114c24284c89e848b94b598638d6'
    'c56d3448f7e148c1ea0b4869c2102700004c89ef4829c74c39d70f8368080000'
    '48837c2408000f841effffff488d047f48c1e005488b8c24c0000000488b0401'
    '4885c00f8812080000480faf4424080f800608000048898424c80000000f57c0'
    'f2480f2ac0f20f5944242866480f7ec04c21c8660f57c948b9ffffffffffffef'
    '7f4839c80f8f50020000f20f100d5634abfc660f2ec80f8726020000660f2e05'
    '7c2fabfc0f8718020000660f28c8e9270200004889c3eb564c89f04983fe0872'
    '4d6666666666662e0f1f840000000000488b8b28030000488b8928030000488b'
    '8928030000488b8928030000488b8928030000488b8928030000488b89280300'
    '00488b99280300004883c0f875c24531f631c00fb78b220300004939ce0f82b7'
    'feffff666666662e0f1f840000000000488b8bc00200004885c90f842a070000'
    '48ffc00fb793200300004889cb663b912203000073da4885c00f84a100000048'
    '8d34d14881c6300300004889c74883e7070f84390100004531c0660f1f440000'
    '488b1e488db32803000049ffc04c39c775ee4889c74c29c74883f80872436690'
    '488b06488b8028030000488b8028030000488b8028030000488b802803000048'
    '8b8028030000488b8028030000488b9828030000488db3280300004883c7f875'
    'bf4531f6498b034885c07527e959fdffff6666666666662e0f1f840000000000'
    '4c8d72014889cb498b034885c00f8437fdffff4889d648c1e606488d3c314889'
    '7c24104c8bacd1c8020000488b4c311048894c2408498b4b080fb7b0ba000000'
    '89f7c1e70348c7c2ffffffff0f1f40004885ff743b4c3b6cd010410f97c04180'
    'd80048ffc24883c7f84180f80174e1410fb6f085f60f84b5fcffff4883e90173'
    '1ce9c4fcffff662e0f1f8400000000004889f24883e9010f82adfcffff488b84'
    'd0c0000000eb92660f1f8400000000004889c74883f8080f83e3feffffe91fff'
    'fffff20f10151e32abfcf20f5fd0f20f100d4a2dabfcf20f5dca48896c24204c'
    '897c2470f2480f2cc1660f2e0d0728abfc490f47c1660f2ec9bd00000000480f'
    '4be848b800000000000000804839c50f8464050000837c243400488b4c24100f'
    '841e01000083390175254c8b79084c89f84829e80f809801000048894108488b'
    '41184989c74901ef7133e9c7010000488b4424204829e80f80ef0100004889c2'
    '488b4424684889542420488910488b41184989c74901ef0f8099010000488b44'
    '24104c897818488b40204989c74901ef0f80d0000000488b4424104c89782048'
    '8b40284989c74901ef0f80ed000000488b4424104c8978284c8b7c24484c3b7c'
    '2438750b488d7c2438ff1571db010248f7dd488b4424404b8d0cff4c892cc848'
    '896cc808488b542408488954c810f20f10442428f20f1144c818488b9424c800'
    '0000488954c820660f288424d0000000660f1144c8288b9424e00000008954c8'
    '388b5424348954c83c488b9424b8000000488954c84049ffc74c897c24184c89'
    '7c244849b9ffffffffffffff7f4c8b5424604c8b5c24584c8b7c2470488b6c24'
    '20e9e4faffff488944241831ff488d350ca0f901ff1546b5010249c1ff3f48b8'
    '00000000000000804931c7488b4424184801e84c0f41f8e9fafeffff48894424'
    '1831ff488d35d69ff901ff1510b5010249c1ff3f48b800000000000000804931'
    'c7488b4424184801e84c0f41f8e9ddfeffff31ff488d354da0f901ff15dfb401'
    '0231c04939ef0f99c048b9ffffffffffffff7f4801c84929ef4c0f40f8488b4c'
    '24104c897908488b41184989c74901ef0f8167feffff488944241831ff488d35'
    '5c9ff901ff1596b4010249c1ff3f48b800000000000000804931c7488b442418'
    '4801e84c0f41f8e931feffff31ff488d35d39ff901ff1565b4010231c0488b54'
    '24204839ea0f99c048b9ffffffffffffff7f4801c84829ea480f40d0488b4c24'
    '10e9dafdffff498b0424488b084885c90f84aa0100004c8b70084c8b3d176701'
    '02488d710848894c24080fb781e600000048894424108d048500000000488d2c'
    '8049c7c5ffffffff0f1f8400000000004885ed743b488d5e14ba14000000488b'
    '7c247841ffd748984885c00f98c10f9fc028c849ffc54883c5ec4889de3c0174'
    'cf0fb6c085c00f847bf8ffffeb0766904c8b6c24104983ee01488b4c24080f82'
    '1c0100004a8b8ce9e8000000e970ffffff488b4c24184885c97461488b6c2440'
    '488b550848b8000000000000008048895424084839c20f841d0200004c8b4d00'
    '488b45204889c348f7db480f48d88b453889842490000000660f104528660f29'
    '842480000000be010000004883f9010f85ca0000004c8b442408eb0531f64531'
    'c08b842490000000488b4c24508941600f288424800000000f114150488b4424'
    '4848898424a80000000f104424380f11842498000000488b5424788b42108984'
    '2490000000660f1002660f29842480000000488b8424a000000048894120488b'
    '8424a800000048894128660f11018b842490000000894110488b842494000000'
    '488941148b84249c00000089411c4c894130488971384c89494048895948eb0d'
    '488b44245048c74038020000004881c4e80000005b415c415d415e415f5dc34c'
    '894c242848c1e103488d04c94883c5704883c0b848894424104531f6488d35a5'
    '9df901eb1a66662e0f1f8400000000004983c6484c397424100f849f0000004e'
    '8b6435e048b800000000000000804939c40f84c20000004e8b6c35d84e8b7c35'
    'f849f7dc488b4424084c29e0703948894424084c89f848f7d8490f48c74839c3'
    '73ae498d0c2e8b511089942490000000660f1001660f298424800000004889c3'
    '4c896c2428eb8931ffff15b1b1010231c0488b5424084c39e20f99c048b9ffff'
    'ffffffffff7f4801c84c29e2480f40d04889542408488d35ec9cf901eb95be01'
    '0000004c8b4424084c8b4c2428e94ffeffff488d3d77a3f901eb07488d3d0e9d'
    'f901ff1538640102eb2e488d3d47a3f901ff1529640102eb1f488d3d909cf901'
    'ff15e26a0102eb10488d15c99cf9014c89d6ff15605f01020f0beb04eb020f0b'
    '4889c3488b4424384885c07415488b7c244048c1e003488d34c031d2ff157e5f'
    '01024889dfe87680f001'
)
BODY_SHA256 = 'b8dac0fc9cb74d2acee64b058dfd5be3cfbfadff8c38e4945a0c42f23a66506e'
BRANCHES = [
    (0x41, '0f84ff060000', 2, 6, 0x3757d56),
    (0xae, '0f84a8070000', 2, 6, 0x3757e6c),
    (0xe4, 'eb32', 1, 2, 0x3757728),
    (0xfe, '0f85ac000000', 2, 6, 0x37577c0),
    (0x104, '0f8aa6000000', 2, 6, 0x37577c0),
    (0x112, '0f84d9060000', 2, 6, 0x3757e01),
    (0x11b, '7563', 1, 2, 0x3757790),
    (0x121, '745d', 1, 2, 0x3757790),
    (0x12c, '0f8441010000', 2, 6, 0x3757883),
    (0x13c, '0f8436010000', 2, 6, 0x3757888),
    (0x15d, '75f1', 1, 2, 0x3757760),
    (0x169, '0f8321010000', 2, 6, 0x37578a0),
    (0x16f, 'e95a010000', 1, 5, 0x37578de),
    (0x184, '0f8488080000', 2, 6, 0x3758022),
    (0x194, '0f8356010000', 2, 6, 0x3757900),
    (0x1a0, 'e971010000', 1, 5, 0x3757926),
    (0x1da, '0f8368080000', 2, 6, 0x3758058),
    (0x1e6, '0f841effffff', 2, 6, 0x375771a),
    (0x203, '0f8812080000', 2, 6, 0x375802b),
    (0x20f, '0f8006080000', 2, 6, 0x375802b),
    (0x244, '0f8f50020000', 2, 6, 0x3757aaa),
    (0x256, '0f8726020000', 2, 6, 0x3757a92),
    (0x264, '0f8718020000', 2, 6, 0x3757a92),
    (0x26e, 'e927020000', 1, 5, 0x3757aaa),
    (0x276, 'eb56', 1, 2, 0x37578de),
    (0x27f, '724d', 1, 2, 0x37578de),
    (0x2cc, '75c2', 1, 2, 0x37578a0),
    (0x2dd, '0f82b7feffff', 2, 6, 0x37577aa),
    (0x2fa, '0f842a070000', 2, 6, 0x375803a),
    (0x314, '73da', 1, 2, 0x3757900),
    (0x319, '0f84a1000000', 2, 6, 0x37579d0),
    (0x331, '0f8439010000', 2, 6, 0x3757a80),
    (0x350, '75ee', 1, 2, 0x3757950),
    (0x35c, '7243', 1, 2, 0x37579b1),
    (0x39f, '75bf', 1, 2, 0x3757970),
    (0x3aa, '7527', 1, 2, 0x37579e3),
    (0x3ac, 'e959fdffff', 1, 5, 0x375771a),
    (0x3cd, '0f8437fdffff', 2, 6, 0x375771a),
    (0x413, '743b', 1, 2, 0x3757a60),
    (0x42d, '74e1', 1, 2, 0x3757a20),
    (0x435, '0f84b5fcffff', 2, 6, 0x3757700),
    (0x43f, '731c', 1, 2, 0x3757a6d),
    (0x441, 'e9c4fcffff', 1, 5, 0x375771a),
    (0x457, '0f82adfcffff', 2, 6, 0x375771a),
    (0x465, 'eb92', 1, 2, 0x3757a09),
    (0x477, '0f83e3feffff', 2, 6, 0x3757970),
    (0x47d, 'e91fffffff', 1, 5, 0x37579b1),
    (0x4cf, '0f8464050000', 2, 6, 0x3758049),
    (0x4df, '0f841e010000', 2, 6, 0x3757c13),
    (0x4e8, '7525', 1, 2, 0x3757b1f),
    (0x4f4, '0f8098010000', 2, 6, 0x3757ca2),
    (0x508, '7133', 1, 2, 0x3757b4d),
    (0x50a, 'e9c7010000', 1, 5, 0x3757ce6),
    (0x517, '0f80ef010000', 2, 6, 0x3757d1c),
    (0x537, '0f8099010000', 2, 6, 0x3757ce6),
    (0x550, '0f80d0000000', 2, 6, 0x3757c36),
    (0x569, '0f80ed000000', 2, 6, 0x3757c6c),
    (0x582, '750b', 1, 2, 0x3757b9f),
    (0x621, 'e9e4faffff', 1, 5, 0x375771a),
    (0x657, 'e9fafeffff', 1, 5, 0x3757b66),
    (0x68d, 'e9ddfeffff', 1, 5, 0x3757b7f),
    (0x6d0, '0f8167feffff', 2, 6, 0x3757b4d),
    (0x707, 'e931feffff', 1, 5, 0x3757b4d),
    (0x741, 'e9dafdffff', 1, 5, 0x3757b30),
    (0x750, '0f84aa010000', 2, 6, 0x3757f10),
    (0x793, '743b', 1, 2, 0x3757de0),
    (0x7bf, '74cf', 1, 2, 0x3757da0),
    (0x7c6, '0f847bf8ffff', 2, 6, 0x3757657),
    (0x7cc, 'eb07', 1, 2, 0x3757de5),
    (0x7de, '0f821c010000', 2, 6, 0x3757f10),
    (0x7ec, 'e970ffffff', 1, 5, 0x3757d71),
    (0x7f9, '7461', 1, 2, 0x3757e6c),
    (0x816, '0f841d020000', 2, 6, 0x3758049),
    (0x84f, '0f85ca000000', 2, 6, 0x3757f2f),
    (0x85a, 'eb05', 1, 2, 0x3757e71),
    (0x8fe, 'eb0d', 1, 2, 0x3757f1d),
    (0x943, 'eb1a', 1, 2, 0x3757f6f),
    (0x959, '0f849f000000', 2, 6, 0x375800e),
    (0x971, '0f84c2000000', 2, 6, 0x3758049),
    (0x98c, '7039', 1, 2, 0x3757fd7),
    (0x9a0, '73ae', 1, 2, 0x3757f60),
    (0x9c5, 'eb89', 1, 2, 0x3757f60),
    (0x9fc, 'eb95', 1, 2, 0x3757fa3),
    (0xa0d, 'e94ffeffff', 1, 5, 0x3757e71),
    (0xa19, 'eb07', 1, 2, 0x3758032),
    (0xa28, 'eb2e', 1, 2, 0x3758068),
    (0xa37, 'eb1f', 1, 2, 0x3758068),
    (0xa46, 'eb10', 1, 2, 0x3758068),
    (0xa5a, 'eb04', 1, 2, 0x3758070),
    (0xa5c, 'eb02', 1, 2, 0x3758070),
    (0xa6b, '7415', 1, 2, 0x3758092),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x3758095, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x3757b99, 0x5775710),
    (0x3757c44, 0x5773190),
    (0x3757c7a, 0x5773190),
    (0x3757cab, 0x5773190),
    (0x3757cf4, 0x5773190),
    (0x3757d25, 0x5773190),
    (0x3757fd9, 0x5773190),
    (0x3758032, 0x576e470),
    (0x3758041, 0x576e470),
    (0x3758050, 0x576eb38),
    (0x3758062, 0x576dfc8),
    (0x375808c, 0x576e010),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x3758022, 0x56f23a0, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 173, 36),
    (0x375802b, 0x56f1d40, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f636c656172696e67686f7573652f706f736974696f6e5f6d61702e7273'), 231, 61),
    (0x375803a, 0x56f2388, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 560, 47),
    (0x3758058, 0x56f1d28, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f636c656172696e67686f7573652f6f7261636c652f6f7261636c652e7273'), 202, 18),
]
CALLERS = [0x3766a93]
CALLER_FUNCTIONS = {'0x3766a93': ('0x3766a10', '0x3766ba4')}
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

