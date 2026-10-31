#!/usr/bin/env python3
"""Authenticated node94 clearinghouses-324aeb0 binding (0x324aeb0).

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

START, END = 0x324aeb0, 0x324b9f6
FDE_VA = 0x115a634
FDE = bytes.fromhex(
    '500000000cca190074080f02460b00000417eb91ff410e10420e18420e20420e'
    '28420e30410e38470ed00283078c068d058e048f0386020305010e38410e3042'
    '0e28420e20420e18420e10410e08410ed0020000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ec1801000048898c249800000048895424204889'
    'bc24880000004889b42490000000488b4638488b084885c90f849f0000004c8b'
    '70084c8d2de77633fd488b1d88355202488d710848894c24180fb781e6000000'
    '48894424108d0485000000004c8d3c8049c7c4ffffffff660f1f840000000000'
    '4d85ff743b488d6e14ba140000004c89efffd348984885c00f98c10f9fc028c8'
    '49ffc44983c7ec4889ee3c0174d20fb6c085c0743aeb0e660f1f840000000000'
    '4c8b6424104983ee01488b4c2418720d4a8b8ce1e8000000e973ffffff488b4c'
    '2420488b71104881fed0070000763248b800000000000000804c8bb424880000'
    '00498946100f57c0410f11064c89f04881c4180100005b415c415d415e415f5d'
    'c34889f048c1e005488d2c064881c5e8030000483bac24980000004c8bb42488'
    '000000760c48b80000000000000080ebb0488b7908e8e6b55900a8017449488b'
    '8424900000004c8b78084189d6bb5917b7d1490fafde48c1eb2d49395f10766f'
    '4c69ebf00200004d036f0866c74424284101488d7c24284189d4e841e4120044'
    '89e2e9da000000bf0d000000ff15762f52024885c00f84ae08000048b9696420'
    '696e7075744889480548b9496e76616c69642048890849c746100d0000004989'
    '461849c746200d000000e916ffffff66c744242841010fb744242866898424a0'
    '000000488b44242a48898424a20000008b442432898424aa0000000fb7442436'
    '66898424ae0000000f104424380f104c24480f105424580f105c24680f298424'
    'b00000000f298c24c00000000f299424d00000000f299c24e00000000f104424'
    '780f298424f00000006681bc24a000000086010f85a30000004c8bac24a80000'
    '0069c31027000029c24189d44d3965100f869300000049395f100f86d9070000'
    '4d8b7f084c69f3f002000066c74424284101488d7c2428e824e312004b395c37'
    '300f85620700004d01f74d3967100f8655070000498b5f084f8d346449c1e604'
    '420fb644332a888424900000004e8b6c33084a8b7c33104885ff48897c24100f'
    '84a3000000ff151d2e52024885c00f84930700004889c7e991000000488dbc24'
    'a0000000e8c7fb9c0066c744242860004c89742430488dbc24a0000000488d74'
    '242831d2e8977f5a00488b8424a00000004889442418488bac24a8000000448b'
    'a424b0000000440fb6bc24b4000000440fb6ac24b5000000440fb6b424b60000'
    '000fb69c24b7000000488d7c2428e85dfb9c00488b7c24184489f04c8bb42488'
    '000000e9d5010000bf010000004c01f348897c24184c89ee488b542410ff156d'
    '2d5202448b63180fb64328884424204c8dac24a00000004c89ef4c89fe4489e2'
    'ff154a945202488bb424a0000000488bbc24a80000004889f048f7d84c89e848'
    '0f40c748b90000000000000080488b4018b3034885c04c8bb424880000000f84'
    '880000004839ce4c0f44ef498b4d204885c9746a4889ca4883e207741a4531c0'
    '488b80c801000049ffc04c39c275f14889ca4c29c2eb034889ca4883f908723e'
    '488b80c8010000488b80c8010000488b80c8010000488b80c8010000488b80c8'
    '010000488b80c8010000488b80c8010000488b80c80100004883c2f875c26683'
    'b8c20100000074040fb658184889f048f7d80f808e000000730831d2ff159e2c'
    '5202488b8c24b80000004885c9743d488b9424c0000000488b8424c800000048'
    'c74424300000000048894c2438488954244048c74424500000000048894c2458'
    '4889542460b901000000eb0431c931c048894c242848894c244848894424684c'
    '8dbc24000100004c8d6c24280f1f40004c89ff4c89eee8f53516004883bc2400'
    '0100000075ea807c242000410f95c7488b44241048b900000000000000804839'
    'c8753b89d8488b7c241848bd0000000000000080440fb6ac249000000049897e'
    '1049896e184589662045887e2445886e254188462641885e27e967fbffff4883'
    'f8e10f832d05000044887c240e885c240f4c8d681f4c89e848c1e80548894424'
    '20488d7008488d7c2428e8412100004c8d7c24404c8b7424504c3b7424407509'
    '4c89ffff156f8e5202488b4424484ac704f020000000498d4601488944245048'
    '8b5c2438488b4424484e8b34f0483b5c2428750b488d7c2428ff15912c520249'
    '0fce488b4424304889d948c1e1050f57c00f11040848c7440810000000004c89'
    '74081848ffc348895c2438488b4424504885c0743948817c241020ffffff0f87'
    '53040000488b4c24484c89ea4883e2e04881c2c0000000480354c1f80f824404'
    '0000488954c1f8488b5c2450eb0231db483b5c244075094c89ffff15b88d5202'
    '488b44244848c704d8a0000000488d430148894424504c8b7c2438488b442448'
    '488b1cd84c3b7c2428750b488d7c2428ff15da2b5202480fcb488b4424304c89'
    'f948c1e1050f57c00f11040848c74408100000000048895c081849ffc74c897c'
    '2438488b4424504885c0743748b9ffffffffffffff0748394c24200f84960300'
    '00488b4c24484983e5e04983c5204c036cc1f80f828d0300004c896cc1f84c8b'
    '7c24384c3b7c2428750b488d7c2428ff155b2b5202410fcc488b4424304c89f9'
    '48c1e1050f57c00f1144080c0f110408448964081c498d5f0148895c2438483b'
    '5c2428750b488d7c2428ff15202b5202488b44243048c1e3050f57c00f114418'
    '0f0f1104180fb68c2490000000884c181f498d5f0248895c2438483b5c242875'
    '0b488d7c2428ff15e42a5202488b44243048c1e3050f57c00f1144180f0f1104'
    '180fb64c240f884c181f498d5f0348895c2438483b5c2428750b488d7c2428ff'
    '15ab2a5202488b44243048c1e3050f57c00f1144180f0f1104180fb64c240e88'
    '4c181f498d5f0448895c2438483b5c2428750b488d7c2428ff15722a5202488b'
    '5424104889d0480fc848c1e3054983c705488b4c24300f57c00f11041948c744'
    '19100000000048894419184c897c24384885d2745d488b4424284c29f8483944'
    '24200f87ae010000488b4424204c01f8488944243849c1e7054c037c24304c89'
    'ff488b742418488b5c24104889daff157c2852024883e31f7418ba2000000048'
    '29da4c037c24104c89ff31f6ff15762a5202488b742440488b4424504885c074'
    '274889c148ffc948894c245074094883c0fe4889442450488b5c24284c8b7424'
    '304c8b7c2438eb14488b5c24284c8b7424304c8b7c24384885f67411488b7c24'
    '4848c1e60331d2ff153328520249c1e70548c1e30548899c24000100004c89b4'
    '24080100004c89bc2410010000488d7c2428488db42400010000ff15302a5202'
    '4c8bb424880000000f104424280f104c24380f298c24b00000000f298424a000'
    '0000488b8c24b0000000ba210000004889c848f7e20f80c20000004801c548c7'
    'c0ffffffff480f43c5480f43c5483b842498000000763548b800000000000000'
    '80498946100f57c0410f1106488b8424a0000000488bb424a8000000488dbc24'
    'b80000004889caff5020eb1d0f288424a00000000f288c24b0000000410f114e'
    '10410f110649894620488b7424104885f60f84f5f6ffff488b7c241831d2ff15'
    '3c275202e9e3f6ffff488d3de0684a02ff158a2b5202488d7c2428b901000000'
    '41b8200000004c89fe488b542420e8fdb008004c8b7c2438e92bfeffff48c7c0'
    'ffffffffe932ffffffbf01000000be0d000000ff158f26520266c74424284101'
    '488d3d420734fd488d0dd2e549024c8d059be14902488d542428be2b000000ff'
    '15f3265202eb3bbf01000000488b742410ff1551265202488d3d22384902ff15'
    '3c285202eb1c488d3d2b384902ff1595275202eb0d488d3d34384902ff158627'
    '52020f0beb3b4889c3488d7c2428e8edda1200eb49ff157d2752024889c3488d'
    '7c2428e8e8f39c00eb34ff1568275202eb0f4889c3488d7c2428e8a1b60500eb'
    '034889c348837c2410007412488b7c2418488b74241031d2ff15222652024889'
    'dfe81a474102'
)
BODY_SHA256 = '1d0c42a983698d3981e57e038de375962c92e5d9573f43fdf600422fc3f40e03'
BRANCHES = [
    (0x38, '0f849f000000', 2, 6, 0x324af8d),
    (0x83, '743b', 1, 2, 0x324af70),
    (0xac, '74d2', 1, 2, 0x324af30),
    (0xb3, '743a', 1, 2, 0x324af9f),
    (0xb5, 'eb0e', 1, 2, 0x324af75),
    (0xce, '720d', 1, 2, 0x324af8d),
    (0xd8, 'e973ffffff', 1, 5, 0x324af00),
    (0xed, '7632', 1, 2, 0x324afd1),
    (0x143, '760c', 1, 2, 0x324b001),
    (0x14f, 'ebb0', 1, 2, 0x324afb1),
    (0x15c, '7449', 1, 2, 0x324b057),
    (0x17e, '766f', 1, 2, 0x324b09f),
    (0x1a2, 'e9da000000', 1, 5, 0x324b131),
    (0x1b5, '0f84ae080000', 2, 6, 0x324b919),
    (0x1ea, 'e916ffffff', 1, 5, 0x324afb5),
    (0x273, '0f85a3000000', 2, 6, 0x324b1cc),
    (0x290, '0f8693000000', 2, 6, 0x324b1d9),
    (0x29a, '0f86d9070000', 2, 6, 0x324b929),
    (0x2c1, '0f8562070000', 2, 6, 0x324b8d9),
    (0x2ce, '0f8655070000', 2, 6, 0x324b8d9),
    (0x2ff, '0f84a3000000', 2, 6, 0x324b258),
    (0x30e, '0f8493070000', 2, 6, 0x324b957),
    (0x317, 'e991000000', 1, 5, 0x324b25d),
    (0x3a3, 'e9d5010000', 1, 5, 0x324b42d),
    (0x41e, '0f8488000000', 2, 6, 0x324b35c),
    (0x432, '746a', 1, 2, 0x324b34e),
    (0x43b, '741a', 1, 2, 0x324b307),
    (0x44d, '75f1', 1, 2, 0x324b2f0),
    (0x455, 'eb03', 1, 2, 0x324b30a),
    (0x45e, '723e', 1, 2, 0x324b34e),
    (0x49c, '75c2', 1, 2, 0x324b310),
    (0x4a6, '7404', 1, 2, 0x324b35c),
    (0x4b2, '0f808e000000', 2, 6, 0x324b3f6),
    (0x4b8, '7308', 1, 2, 0x324b372),
    (0x4cd, '743d', 1, 2, 0x324b3bc),
    (0x50a, 'eb04', 1, 2, 0x324b3c0),
    (0x544, '75ea', 1, 2, 0x324b3e0),
    (0x561, '753b', 1, 2, 0x324b44e),
    (0x599, 'e967fbffff', 1, 5, 0x324afb5),
    (0x5a2, '0f832d050000', 2, 6, 0x324b985),
    (0x5de, '7509', 1, 2, 0x324b499),
    (0x612, '750b', 1, 2, 0x324b4cf),
    (0x653, '7439', 1, 2, 0x324b53e),
    (0x65e, '0f8753040000', 2, 6, 0x324b967),
    (0x67c, '0f8244040000', 2, 6, 0x324b976),
    (0x68c, 'eb02', 1, 2, 0x324b540),
    (0x695, '7509', 1, 2, 0x324b550),
    (0x6c9, '750b', 1, 2, 0x324b586),
    (0x70a, '7437', 1, 2, 0x324b5f3),
    (0x71b, '0f8496030000', 2, 6, 0x324b967),
    (0x733, '0f828d030000', 2, 6, 0x324b976),
    (0x748, '750b', 1, 2, 0x324b605),
    (0x783, '750b', 1, 2, 0x324b640),
    (0x7bf, '750b', 1, 2, 0x324b67c),
    (0x7f8, '750b', 1, 2, 0x324b6b5),
    (0x831, '750b', 1, 2, 0x324b6ee),
    (0x873, '745d', 1, 2, 0x324b782),
    (0x882, '0f87ae010000', 2, 6, 0x324b8e6),
    (0x8b8, '7418', 1, 2, 0x324b782),
    (0x8df, '7427', 1, 2, 0x324b7b8),
    (0x8ec, '7409', 1, 2, 0x324b7a7),
    (0x906, 'eb14', 1, 2, 0x324b7cc),
    (0x91a, '7411', 1, 2, 0x324b7dd),
    (0x995, '0f80c2000000', 2, 6, 0x324b90d),
    (0x9b5, '7635', 1, 2, 0x324b89c),
    (0x9ea, 'eb1d', 1, 2, 0x324b8b9),
    (0xa11, '0f84f5f6ffff', 2, 6, 0x324afbc),
    (0xa24, 'e9e3f6ffff', 1, 5, 0x324afbc),
    (0xa58, 'e92bfeffff', 1, 5, 0x324b738),
    (0xa64, 'e932ffffff', 1, 5, 0x324b84b),
    (0xaa5, 'eb3b', 1, 2, 0x324b992),
    (0xac4, 'eb1c', 1, 2, 0x324b992),
    (0xad3, 'eb0d', 1, 2, 0x324b992),
    (0xae4, 'eb3b', 1, 2, 0x324b9d1),
    (0xaf3, 'eb49', 1, 2, 0x324b9ee),
    (0xb08, 'eb34', 1, 2, 0x324b9ee),
    (0xb10, 'eb0f', 1, 2, 0x324b9d1),
    (0xb1f, 'eb03', 1, 2, 0x324b9d4),
    (0xb2a, '7412', 1, 2, 0x324b9ee),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x324b005, 0x37e65f0),
    (0x324b04a, 0x3379490),
    (0x324b167, 0x3379490),
    (0x324b1d4, 0x3c1ada0),
    (0x324b1f4, 0x37f3190),
    (0x324b23e, 0x3c1ada0),
    (0x324b3e6, 0x33ae9e0),
    (0x324b47a, 0x324d5c0),
    (0x324b8fe, 0x32d6a00),
    (0x324b99e, 0x3379490),
    (0x324b9b3, 0x3c1ada0),
    (0x324b9ca, 0x32a7070),
    (0x324b9f1, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x324b05c, 0x576dfd8),
    (0x324b1b5, 0x576dfd8),
    (0x324b26d, 0x576dfe0),
    (0x324b290, 0x57746e0),
    (0x324b36c, 0x576e010),
    (0x324b493, 0x5774308),
    (0x324b4c9, 0x576e160),
    (0x324b54a, 0x5774308),
    (0x324b580, 0x576e160),
    (0x324b5ff, 0x576e160),
    (0x324b63a, 0x576e160),
    (0x324b676, 0x576e160),
    (0x324b6af, 0x576e160),
    (0x324b6e8, 0x576e160),
    (0x324b75e, 0x576dfe0),
    (0x324b77c, 0x576e1f8),
    (0x324b7d7, 0x576e010),
    (0x324b80a, 0x576e240),
    (0x324b8ce, 0x576e010),
    (0x324b8e0, 0x576e470),
    (0x324b923, 0x576dfb8),
    (0x324b94f, 0x576e048),
    (0x324b961, 0x576dfb8),
    (0x324b96e, 0x576e1b0),
    (0x324b97d, 0x576e118),
    (0x324b98c, 0x576e118),
    (0x324b9a5, 0x576e128),
    (0x324b9ba, 0x576e128),
    (0x324b9e8, 0x576e010),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x324b8d9, 0x56f21c0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f706572705f6d6574612e7273'), 194, 38),
    (0x324b976, 0x56df1a8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f68797065722d616c6c6f792d636f72652d666f726b2f6372617465732f736f6c2d74797065732f7372632f6162692f656e636f6465722e7273'), 104, 13),
    (0x324b985, 0x56df1c0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f68797065722d616c6c6f792d636f72652d666f726b2f6372617465732f736f6c2d74797065732f7372632f7574696c732e7273'), 28, 5),
]
CALLERS = []
CALLER_FUNCTIONS = {}
LEA_REFS = 0
OWN_GOT_SLOTS = ['0x56a69f8', '0x56dfa20']
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

