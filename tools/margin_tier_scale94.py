#!/usr/bin/env python3
"""Reproduce the node 94 margin-tier value and serialization evidence, without execution."""

import argparse
import csv
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records

TARGET = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SOURCE_COMMIT = '56c0ec672bd8fdcfaa80f2db700a61e6240b3663'
REFERENCE_COMMIT = '999556f6e0a474b8312db96ec3149e1c44e97c23'
BINARY = ROOT / 'artifacts' / 'node' / '94' / 'hl-node'

# FDEs describe unwind ranges. The expected hashes prevent silently accepting a
# different version or analysing a different instruction sequence in tests.
FUNCTIONS = (
    ('request wrapper', 0x2587110, 0x25872ee, '6ec01e6efbbd5ca5e8820892cdac4a1d2b0ca05e41fc638f6f7e4426b001cac6'),
    ('selector and lookup', 0x27db850, 0x27dbe50, '8d1762774f9054b9111ed24f220916fc5743e4120786aa68f590e14df6606357'),
    ('collection builder', 0x2a0a830, 0x2a0aa58, 'f3d85508c5060545a58375f1d45ca3348a3d9f351c199bb2f6b0415cc529adf3'),
    ('collection walk', 0x2a22900, 0x2a22bb9, '4469387564a6e79c6f1ad8a3f5b380966c032ca7bcb6c5143cec522e0c2db07e'),
    ('tree iterator', 0x2a0a230, 0x2a0a434, '854a46aa373e6945160e655030afbb41737d7c6761b99b9cab4cf208814a7459'),
    ('tier view converter', 0x2a25ed0, 0x2a260d6, '2a5869c374a48b8f8a85e74671aa8903fa6934bf584be011a83190e6d1d8de63'),
    ('owned view wrapper', 0x2a31610, 0x2a3166b, '2418e96c31958eca84028f28be9372e89b8c8222ff706ccb4945e7b2b2d5e492'),
    ('view field builder', 0x2a260e0, 0x2a2622a, '05b0334f98194e6d2a28ccfdde1403b2c877a2fba3b8db3ecfbfff316a494508'),
    ('tier list field builder', 0x29ff1b0, 0x29ff3e1, 'd88eb472428f3324839694218356b0a6ef160ac8ac739cba9c259d3f1c09818f'),
    ('tier list walker', 0x29f4270, 0x29f449e, '07473545e8bd211b5f80814d69dc684f9ba5e4049d55bc9fbca43c47c6b7b850'),
    ('tier field builder', 0x2a26230, 0x2a2637a, '0667074b307205ac39442a76896ca897d6d6078f185b6ee80f480ba971f9eb5b'),
    ('leverage byte builder', 0x2a02870, 0x2a02a18, '85e1743b56f10c92bc910613259d5e47570815a7ffdcbb7ec62117995695e131'),
)

# These are fixed, human-reviewed instruction windows, not disassembler output.
# Their roles are observations about the named byte sequences; they do not make
# claims about unqualified instructions in the surrounding functions.
ANCHORS = (
    ('request forwarding', 0x2587123, '4889fb4881c6c80200000f10020f104a100f294c24200f294424100fb688904b0000890c24488dbc2480000000488d4c24104889c2e8f3462500'),
    ('lookup selector and projection', 0x27db970, '488dbc24800000004c89fe4c89eaff15848df9026681bc248000000086010f859c000000488bb424880000004183fe320f83c10200004c8d6424184c89e74489f2ff15298df90248892c244c8b7c2418488b6c24204c89f848f7d84c0f40e5488dbc24680100004c89e6ff154095f902'),
    ('custom selector search', 0x27dbc67, '488b46386641bc54014885c0747c488b4e400fb7b89e0200004189f841c1e00248c7c2ffffffff66904d85c0742b443bb49074020000410f97c14180d90048ffc24983c0fc4180f90174de410fb6f985ff0f84e8fcffffeb034889fa4883e9017228488b84d0a0020000eba6'),
    ('description allocation and copy', 0x2a25ee4, '4c8b6e08488b5e104885db74174889dfff15de80d4024885c00f846b0100004889c7eb05bf0100000048897c24184c89ee4889daff15c280d402'),
    ('row allocation guard', 0x2a25f1e, '4d8b7424184531ed4c89f54d85f60f95c27405498b6c24284889ee48c1e6044889e848c1e83c0f95c048b9f8ffffffffffff7f4839ce0f97c108c1740f31ff4c8b742418ff155080d4020f0b4d8b6424204885f674278854240f48897424104889f7ff155280d4024885c00f84ed00000048896c24100fb654240feb0eb80800000048c744241000000000'),
    ('iterator numeric conversion and output', 0x2a25fe1, '4c8d68084531f6488d6c24204989c44889efe83842feff4885c0743e0fb64a18f20f10000f140574de7dfd660f5c058cce7dfd660f28c8660f15c8f20f58c8f20f5e0d384e7efdf2410f114df841884d0049ffc64983c510ebb549891f488b4424184989470849895f10488b442410498947184d8967204d897728'),
    ('collection allocation and call', 0x2a0a83e, '4c8b7e404d6bf73848b84a9224499224490248ffc84939c7760b31ff4c89f6ff155537d6024889fb4d85f6741a4989f44c89f7ff156137d6024885c00f848e0100004c89e6eb08b8080000004531ff4c897c24084889442410488d4c241848c744241800000000488944245048894c244048c744244800000000488d4424404889f74889c6e838800100'),
    ('collection element projection', 0x2a22ae7, '486bc238488d34014883c6088bac9170020000488d7c2418ff151b24d50249ffcc896c2410496bc738488b4c244049894c05300f104424200f104c2430410f114c0520410f114405100f10442410410f1144050049ffc7b101b8000000004d85e40f85f2fdffffeb12'),
    ('collection count dispatch', 0x2a0a9e2, '4883fe157334488d4c2440ba01000000e859530100e902ffffffbf08000000be48020000ff151436d6020f0bbf080000004c89f6ff159c35d602488d542440ff15b9a8d602'),
    ('iterator guards', 0x2a0a230, '50488b47404885c00f844501000048ffc848894740833f010f85d701000048837f08000f8596000000'),
    ('iterator key and value addresses', 0x2a0a3e1, '488d04d148056801000048c1e2054801ca4889770848c74710000000004c894f1859c3'),
    ('named view fields', 0x2a2614e, '488d3535999ffd4889e7ba0b0000004c89f1e88b34fdff4885c075204983c618488d3520999ffd4889e7ba0b0000004c89f1e82b90fdff4885c07423'),
    ('named tier fields', 0x2a2629e, '488d35fb979ffd4889e7ba0a0000004c89f1e89bb0fdff4885c075204983c608488d35e5979ffd4889e7ba0b0000004c89f1e89bc5fdff4885c07423'),
    ('array size limit', 0x29f4281, '4c8b6e104a8d0ced00000000488d34c948b9c7711cc7711cc7014939cd760831ffff15109dd702'),
    ('array per-tier loop', 0x29f42f2, '4d85ed0f848c00000049c1e5044c8d7c2420eb56662e0f1f8400000000004983c610488b4424104b8d0ce4488b542460488954c8400f104424200f104c24300f105424400f105c24500f115cc8300f1154c8200f114cc8100f1104c849ffc44c896424184983c5f0742b4c89ff4c89f6e8c91e030048396c2420743c4c8b6424184c3b6424087596'),
    ('owned wrapper and release', 0x2a31610, '415653504889f3e8c44affff488b334885f6740c488b7b0831d2ff15e0c9d302488b73184885f67417488b7b2048c1e60431d24883c4085b415eff25c0c9d3024883c4085b415ec3'),
    ('leverage byte input', 0x2a0291c, '410fb607498d4d0248898c24b800000048c78424c00000000000000048898424c8000000'),
    ('converter result staging', 0x27db9e0, '4c89f848f7d8660f10842468010000660f108c2478010000660f10942488010000660f29942430010000660f298c2420010000660f298424100100006641bc86010f81ac020000'),
    ('getter result helper branch', 0x27dbcd3, '730e4889ef4c89fe31d2ff152d23f902488d7c2430488b2c24e80f020d00'),
    ('success payload staging', 0x27dbcf1, '66448964242044897424240f28842410010000660f288c2420010000660f289424300100000f289c24400100000f11442428660f114c2438660f11542448'),
    ('response temporary copy', 0x27dbb60, '0f104c2418660f105424280f105c24380f106424480f298c2480000000660f299424900000000f299c24a00000000f29a424b0000000'),
    ('response return copy', 0x27dbc23, '0f288424800000000f288c24900000000f289424a00000000f289c24b00000000f115b300f1153200f114b100f1103'),
    ('wrapper result staging', 0x2587184, '0f108424800000000f108c24900000000f109424a00000000f109c24b00000000f295c24400f295424300f294c2420f20f108c24e8000000f20f588c24f00000000f29442410'),
    ('wrapper return copy', 0x2587220, '0f284424100f284c24200f285424300f285c24400f115b300f1153200f114b100f1103'),
)

# The two stack frames are distinct; each row describes 48 payload bytes.
# These interpretations apply to the successful, normally returning path.
FLOW = (
    ('converter result staging', 'lookup stack +0x168', 'lookup stack +0x110'),
    ('success payload staging', 'lookup stack +0x110', 'lookup stack +0x28'),
    ('response temporary copy', 'lookup stack +0x28', 'lookup stack +0x90'),
    ('response return copy', 'lookup stack +0x90', 'lookup output +0x10'),
    ('wrapper result staging', 'wrapper stack +0x90', 'wrapper stack +0x20'),
    ('wrapper return copy', 'wrapper stack +0x20', 'wrapper output +0x10'),
)

# The expected branch form and destination are checked independently of each
# body's hash, and the destination is decoded from the signed displacement.
BRANCHES = (
    (0x27db98e, '0f85', 0x27dba30, 'lookup tag differs from 0x186'),
    (0x27db9a0, '0f83', 0x27dbc67, 'selector is at least 50'),
    (0x27dbc73, '74', 0x27dbcf1, 'custom selector tree is empty'),
    (0x27dbcb8, '0f84', 0x27db9a6, 'custom selector equals a key'),
    (0x27dbcc7, '72', 0x27dbcf1, 'custom selector search ends without a key'),
    (0x27dba21, '0f81', 0x27dbcd3, 'getter first word is not minimum signed 64-bit'),
    (0x27dbcd3, '73', 0x27dbce3, 'getter first word is zero'),
    (0x2a0a856, '76', 0x2a0a863, 'collection count is within its allocation bound'),
    (0x2a0a869, '74', 0x2a0a885, 'collection allocation size is zero'),
    (0x2a0a87a, '0f84', 0x2a0aa0e, 'collection allocation returned null'),
    (0x2a0a8df, '0f84', 0x2a0a9a6, 'collection contains zero projected rows'),
    (0x2a0a8f8, '0f85', 0x2a0a9e2, 'collection has more than one projected row'),
    (0x2a0a91b, '0f84', 0x2a0a9fc, 'collection output allocation returned null'),
    (0x2a0a9e6, '73', 0x2a0aa1c, 'collection has at least 21 projected rows'),
    (0x2a22921, '0f84', 0x2a22b62, 'collection walker has no remaining entries'),
    (0x2a22943, '0f84', 0x2a22b88, 'collection walker state tag is invalid'),
    (0x2a22a26, '0f84', 0x2a22b79, 'collection walker expected parent is null'),
    (0x2a22b48, '0f85', 0x2a22940, 'collection walker has another entry'),
    (0x2a25eef, '74', 0x2a25f08, 'description length is zero'),
    (0x2a25efd, '0f84', 0x2a2606e, 'description allocation returned null'),
    (0x2a25f2f, '74', 0x2a25f36, 'tier tree root is null'),
    (0x2a25f59, '74', 0x2a25f6a, 'tier vector byte length is representable'),
    (0x2a25f72, '74', 0x2a25f9b, 'tier vector byte length is zero'),
    (0x2a25f89, '0f84', 0x2a2607c, 'tier vector allocation returned null'),
    (0x2a25ffb, '74', 0x2a2603b, 'iterator returned no key'),
    (0x2a0a238, '0f84', 0x2a0a383, 'iterator remaining count is zero'),
    (0x2a0a248, '0f85', 0x2a0a425, 'iterator state tag is not one'),
    (0x2a0a253, '0f85', 0x2a0a2ef, 'iterator has current node'),
    (0x2a0a268, '74', 0x2a0a2de, 'initial tree depth is zero'),
    (0x2a0a305, '73', 0x2a0a310, 'local node index is not below count'),
    (0x2a0a31a, '0f84', 0x2a0a416, 'expected parent pointer is null'),
    (0x2a31622, '74', 0x2a31630, 'description capacity is zero'),
    (0x2a31637, '74', 0x2a31650, 'tier vector capacity is zero'),
    (0x2a260fc, '0f84', 0x2a26204, 'view field builder initial helper returned null'),
    (0x2a26168, '75', 0x2a2618a, 'description field helper reports error'),
    (0x2a26188, '74', 0x2a261ad, 'tier list field helper reports success'),
    (0x2a2624c, '0f84', 0x2a26354, 'tier field builder initial helper returned null'),
    (0x2a262b8, '75', 0x2a262da, 'lowerBound field helper reports error'),
    (0x2a262d8, '74', 0x2a262fd, 'maxLeverage field helper reports success'),
    (0x29f429e, '76', 0x29f42a8, 'element count is within the 72-byte allocation bound'),
    (0x29f42b2, '74', 0x29f42ce, 'array allocation size is zero'),
    (0x29f42c3, '0f84', 0x29f4418, 'array allocation returned null'),
    (0x29f42f5, '0f84', 0x29f4387, 'input tier count is zero'),
    (0x29f435a, '74', 0x29f4387, 'the last tier was appended'),
    (0x29f436c, '74', 0x29f43aa, 'tier field builder reported error'),
    (0x29f4378, '75', 0x29f4310, 'array has remaining capacity'),
)

# Only FDEs in FUNCTIONS are subjects; other targets are call edges, not
# recovered helper bodies. rel32 is checked against raw bytes and RELA addends.
CALLS = (
    ('request wrapper', 0x2587158, 'direct', 0x27db850),
    ('name lookup', 0x27db97e, 'indirect', 0x3332270),
    ('tier table getter', 0x27db9b1, 'indirect', 0x3759880),
    ('tier view converter', 0x27db9da, 'indirect', 0x2a25ed0),
    ('getter result helper', 0x27dbcec, 'direct', 0x28abf00),
    ('collection walk', 0x2a0a8c3, 'direct', 0x2a22900),
    ('collection tier projection', 0x2a22aff, 'indirect', 0x2a25ed0),
    ('small collection helper', 0x2a0a9f2, 'direct', 0x2a1fd50),
    ('large collection helper', 0x2a0aa21, 'indirect', 0x2a40780),
    ('tier iterator', 0x2a25ff3, 'direct', 0x2a0a230),
    ('view field builder', 0x2a31617, 'direct', 0x2a260e0),
    ('description field', 0x2a26160, 'direct', 0x29f95f0),
    ('tier list field', 0x2a26180, 'direct', 0x29ff1b0),
    ('tier list walker', 0x29ff263, 'direct', 0x29f4270),
    ('tier field builder', 0x29f4362, 'direct', 0x2a26230),
    ('lowerBound field', 0x2a262b0, 'direct', 0x2a01350),
    ('maxLeverage field', 0x2a262d0, 'direct', 0x2a02870),
)
FIELD_SITES = (
    ('view', 0x2a2614e, b'description'),
    ('view', 0x2a2616e, b'marginTiers'),
    ('tier', 0x2a2629e, b'lowerBound'),
    ('tier', 0x2a262be, b'maxLeverage'),
)


# Additional bridge: the collection inserts 32-bit keys and 48-byte views
# into a tree. A separate writer extracts a key/value pointer pair from the
# same byte offsets and passes its view pointer to the existing field builder.
# Compatibility is a layout fact; it does not prove an actual runtime handoff.
FUNCTIONS += (
    ('tree collection insertion', 0x2a08270, 0x2a08e05, '13f253f540d8b18431989194440cf1c6e3d20e0f42fe6b0d2c557ccb3daaaf94'),
    ('tree pointer collector', 0x2a14370, 0x2a1465e, 'd5b9605c7b74f8a44cf2c95b77a4fcf64da6e66f6df2faf4a1ea457f22c86486'),
    ('tree writer adapter', 0x2a18b90, 0x2a18c53, '7a612a0218a6f95b11fe21decbcecb02ed683fd3a53e30916f148ea946444024'),
    ('pointer pair list writer', 0x29eedf0, 0x29ef02e, '13e2138bf232d0938c2b0df05fa6707352cb9320403469e612bfa67379161698'),
    ('pointer pair field writer', 0x2a30410, 0x2a30584, 'ecf58d8910976b9963c4119c0fc91b6eba52bb2fb086839901c534b846737b9e'),
    ('keyed tree adapter', 0x2a02f50, 0x2a03238, 'cfdba196598ce60adda39c6e1999d87e9dd65ede2c260b166582f2087312e788'),
)
ANCHORS += (
    ('tree capacity guard', 0x2a0860e, '410fb787460200004883f80b48896c24304889742408488954242848897c24200f828cfdffff'),
    ('tree key and payload store', 0x2a083cb, '488b4c241841898c8718020000488d0440c1e0044d892c0749897c07084989540710498974071849896c07204d89740728488b44244048ff00'),
    ('tree row consume', 0x2a08441, '4c8d43384c898424c0000000488b03488b73084883c3104889d94c39ce752a'),
    ('tree entry staged', 0x2a085a0, '4c89a424880000004c89b4248000000048897424484c89ee4889442418488d8424100100004889084c8b6c24484d39cd0f840e030000'),
    ('tree key and value pointers', 0x2a14410, '4c8d52014c89ce48ffc94d8d04914981c018020000488d145248c1e2044c01ca4989c149c1e1044e89040b4a89540b08'),
    ('tree pointer adapter', 0x2a18bea, '4c8d742408488d7424204c89f7e874b7ffff4889df4c89f6e8e961fdff'),
    ('pointer pair list call', 0x29eeedc, '48896c24284c89f74c89fee8241504004c396424307441488b5c2418'),
    ('pointer pair key and view', 0x2a30451, '498b04248b00498d4ffd48890b48c74308000000004889431048c744241001000000498b742408488d7c2418e85e5cffff'),
    ('keyed tree field call', 0x2a03085, '488b43504889442468488b435848894424704c89742460488d7c2478488b742458e8e55a0100'),
    ('keyed special field guard', 0x2a02f67, '49bd0500000000000080498d6dfb48392f75544983fe1e0f8531020000f30f6f06f30f6f4e0e660f740d8b5980fd660f7405733180fd660fdbc1660fd7c03dffff00000f8505020000488d7c24084889cee8a3570100'),
)
BRANCHES += (
    (0x2a0862e, '0f82', 0x2a083c0, 'tree node count is below eleven'),
    (0x2a143a0, '74', 0x2a143ad, 'pointer vector size is representable'),
    (0x2a143b0, '74', 0x2a143e0, 'pointer vector byte count is zero'),
    (0x2a143c4, '0f84', 0x2a14631, 'pointer vector allocation is null'),
    (0x2a143eb, '0f84', 0x2a145fb, 'tree count is zero'),
    (0x2a1445c, '0f84', 0x2a14622, 'tree iterator state tag is invalid'),
    (0x2a1453a, '0f84', 0x2a14613, 'tree iterator parent is missing'),
    (0x2a18ba0, '74', 0x2a18bd7, 'source tree root is null'),
    (0x29eee1e, '76', 0x29eee28, 'pair output allocation count fits'),
    (0x29eee34, '74', 0x29eee50, 'pair output allocation is empty'),
    (0x29eee45, '0f84', 0x29eefa8, 'pair output allocation is null'),
    (0x29eee77, '0f84', 0x29eef0c, 'pointer pair count is zero'),
    (0x29eeef1, '74', 0x29eef34, 'pair writer reports an error'),
    (0x29eeefd, '75', 0x29eee90, 'pair output has spare capacity'),
    (0x2a30431, '0f84', 0x2a3052a, 'pair allocation is null'),
    (0x2a30487, '75', 0x2a304b7, 'view field builder did not return the error tag'),
    (0x2a02f78, '75', 0x2a02fce, 'writer is in its ordinary state'),
    (0x2a02f7e, '0f85', 0x2a031b5, 'special writer state has the wrong field length'),
    (0x2a02faa, '0f85', 0x2a031b5, 'special writer state has the wrong field bytes'),
    (0x2a02ff4, '0f84', 0x2a031cf, 'field name allocation is null'),
    (0x2a030b0, '75', 0x2a030de, 'tree writer did not return the error tag'),
)
CALLS += (
    ('tree construction', 0x2a0a98e, 'direct', 0x2a08270),
    ('keyed tree conversion', 0x2a030a6, 'direct', 0x2a18b90),
    ('tree pointer collection', 0x2a18bf7, 'direct', 0x2a14370),
    ('pointer pair list', 0x2a18c02, 'direct', 0x29eedf0),
    ('pointer pair field', 0x29eeee7, 'direct', 0x2a30410),
    ('pair view fields', 0x2a3047d, 'direct', 0x2a260e0),
    ('special field conversion', 0x2a02fb8, 'direct', 0x2a18760),
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify_digest(data, expected=TARGET):
    actual = hashlib.sha256(data).hexdigest()
    require(actual == expected, 'node 94 input SHA-256 mismatch')
    return actual


class Image:
    def __init__(self, data, expected=TARGET):
        self.sha256 = verify_digest(data, expected)
        self.data = data
        self.secs = sections(data)
        _, fs = eh_frame_records(data, self.secs)
        self.fdes = {}
        for f in fs:
            self.fdes.setdefault(f['start'], []).append(f)
        rela = self.named_section('.rela.dyn')
        require(rela['type'] == 4 and rela['size'] % 24 == 0, 'invalid relocation section')
        self.relocations = {}
        for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, pos)
            self.relocations.setdefault(slot, []).append((info, addend))

    def named_section(self, name):
        found = [s for s in self.secs if s['name'] == name]
        require(len(found) == 1 and found[0]['type'] != 8, 'missing or ambiguous file-backed section')
        return found[0]

    def mapping(self, va, size, executable=False):
        require(isinstance(va, int) and isinstance(size, int) and va >= 0 and size > 0, 'invalid address span')
        found = [s for s in self.secs if s['type'] != 8 and (not executable or s['flags'] & 4)
                 and s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(found) == 1, 'address span is not uniquely file backed')
        s = found[0]
        return s, s['offset'] + va - s['address']

    def read(self, va, size, executable=False):
        _, off = self.mapping(va, size, executable)
        return self.data[off:off + size]

    def one_fde(self, start, end):
        found = self.fdes.get(start, [])
        require(len(found) == 1 and found[0]['end'] == end, 'unexpected FDE extent')
        self.mapping(start, end - start, executable=True)
        return found[0]

    def relocation(self, slot):
        entries = self.relocations.get(slot, [])
        require(len(entries) == 1 and entries[0][0] == 8, 'missing or ambiguous relative relocation')
        return entries[0][1]


def decode_branch(raw, va, opcode):
    expected = bytes.fromhex(opcode)
    require(raw.startswith(expected), 'unexpected branch opcode')
    if len(expected) == 1 and 0x70 <= expected[0] <= 0x7f:
        require(len(raw) >= 2, 'truncated branch')
        size, displacement = 2, struct.unpack_from('<b', raw, 1)[0]
    elif len(expected) == 2 and expected[0] == 0x0f and 0x80 <= expected[1] <= 0x8f:
        require(len(raw) >= 6, 'truncated branch')
        size, displacement = 6, struct.unpack_from('<i', raw, 2)[0]
    else:
        raise ValueError('unsupported branch')
    return size, va + size + displacement


def extract_branch(image, va, opcode, target, role):
    size = 2 if len(opcode) == 2 else 6
    raw = image.read(va, size, executable=True)
    _, actual = decode_branch(raw, va, opcode)
    require(actual == target, 'branch target mismatch')
    return {'site_va': hex(va), 'bytes': raw.hex(), 'taken_va': hex(actual),
            'fallthrough_va': hex(va + size), 'taken_when': role}


def extract_call(image, role, va, kind, target):
    if kind == 'direct':
        raw = image.read(va, 5, executable=True)
        require(raw[0] == 0xe8, 'unexpected direct call')
        actual = va + 5 + struct.unpack_from('<i', raw, 1)[0]
        slot = None
    elif kind == 'indirect':
        raw = image.read(va, 6, executable=True)
        require(raw[:2] == b'\xff\x15', 'unexpected indirect call')
        slot = va + 6 + struct.unpack_from('<i', raw, 2)[0]
        actual = image.relocation(slot)
    else:
        raise ValueError('unsupported call')
    require(actual == target, 'call target mismatch')
    return {'role': role, 'site_va': hex(va), 'kind': kind, 'bytes': raw.hex(),
            'slot_va': '' if slot is None else hex(slot), 'target_va': hex(actual)}


def extract_field(image, scope, va, expected):
    raw = image.read(va, 15, executable=True)
    require(raw[:3] == b'\x48\x8d\x35' and raw[7:11] == b'\x48\x89\xe7\xba', 'unexpected field setup')
    dest = va + 7 + struct.unpack_from('<i', raw, 3)[0]
    length = struct.unpack_from('<I', raw, 11)[0]
    data = image.read(dest, length)
    require(data == expected, 'field name mismatch')
    return {'scope': scope, 'instruction_va': hex(va), 'text_va': hex(dest), 'length': length,
            'name': data.decode('ascii'), 'lea_bytes': raw[:7].hex()}


def float_fraction(bits):
    """Interpret nonnegative finite IEEE-754 binary64 bits exactly."""
    require(isinstance(bits, int) and 0 <= bits < (1 << 63), 'invalid nonnegative binary64')
    exponent = (bits >> 52) & 0x7ff
    significand = bits & ((1 << 52) - 1)
    require(exponent != 0x7ff, 'nonfinite binary64')
    if exponent:
        significand |= 1 << 52
        power = exponent - 1023 - 52
    else:
        power = -1074
    return Fraction(significand << power, 1) if power >= 0 else Fraction(significand, 1 << -power)


def round_even(num, den):
    require(num >= 0 and den > 0, 'invalid rounding ratio')
    quotient, remainder = divmod(num, den)
    twice = 2 * remainder
    return quotient + (twice > den or (twice == den and quotient % 2 == 1))


def round_binary64(value):
    """Round a nonnegative Fraction to binary64, nearest with ties to even."""
    require(isinstance(value, Fraction) and value >= 0, 'expected nonnegative Fraction')
    if not value:
        return 0
    n, d = value.numerator, value.denominator
    e = n.bit_length() - d.bit_length()
    if (n < d << e) if e >= 0 else (n << -e < d):
        e -= 1
    if e < -1022:
        sig = round_even(n << 1074, d)
        require(sig <= 1 << 52, 'subnormal rounding overflow')
        return sig
    require(e <= 1023, 'binary64 overflow outside model')
    shift = 52 - e
    sig = round_even(n << shift, d) if shift >= 0 else round_even(n, d << -shift)
    if sig == 1 << 53:
        sig >>= 1
        e += 1
    require(e <= 1023 and (1 << 52) <= sig < (1 << 53), 'invalid rounded significand')
    return ((e + 1023) << 52) | (sig - (1 << 52))


def simd_conversion(raw, constants):
    """Lift the qualified packed conversion, then the qualified f64 division."""
    require(type(raw) is int and 0 <= raw < 1 << 64, 'raw value outside u64')
    lo = raw & 0xffffffff
    hi = raw >> 32
    lo_bits = (constants['unpack_low'] << 32) | lo
    hi_bits = (constants['unpack_high'] << 32) | hi
    low = float_fraction(lo_bits) - float_fraction(constants['bias_low'])
    high = float_fraction(hi_bits) - float_fraction(constants['bias_high'])
    low = float_fraction(round_binary64(low))
    high = float_fraction(round_binary64(high))
    converted = round_binary64(low + high)
    result = round_binary64(float_fraction(converted) / float_fraction(constants['divisor_bits']))
    return converted, result


def prove_lane_lift(constants):
    """Check the bit-encoding premises for the full-u64 algebraic lift.

    For an exponent e and a 32-bit payload p, the constructed binary64 is
    2**e + p * 2**(e-52).  Subtracting 2**e is exact because p has at most
    32 significant bits.  The two resulting terms sum to the original u64;
    the scalar add performs its one binary64 rounding.  This conditional
    argument uses the already-qualified instruction order and rounding mode.
    """
    lane_facts = []
    for name, expected_exponent in (('low', 52), ('high', 84)):
        prefix = constants['unpack_' + name]
        bias = constants['bias_' + name]
        require(type(prefix) is int and 0 <= prefix < 1 << 32,
                'invalid packed conversion prefix')
        require((prefix << 32) == bias, 'packed prefix and bias disagree')
        exponent = ((bias >> 52) & 0x7ff) - 1023
        require(exponent == expected_exponent and float_fraction(bias) == (1 << exponent),
                'unexpected lane bias')
        variable_mask = (1 << 32) - 1
        require(variable_mask.bit_length() <= 53 and variable_mask < 1 << 52,
                'lane payload does not fit the significand')
        unit = 1 << (exponent - 52)
        require(float_fraction(bias | variable_mask) - float_fraction(bias) == variable_mask * unit,
                'lane endpoint is not exact')
        lane_facts.append({'lane': name, 'binary_exponent': exponent,
                           'payload_bits': variable_mask.bit_length(), 'payload_unit': unit})
    require(lane_facts[0]['payload_unit'] == 1 and lane_facts[1]['payload_unit'] == 1 << 32,
            'lanes do not reconstruct an unsigned 64-bit integer')
    return lane_facts


def exact_ratio_witness(constants):
    """Construct a u64 whose exact integer quotient is lost by two-step rounding."""
    odd = 5**6
    quantum = 1 << 11  # u64 values in [2**63, 2**64) have this f64 ulp.
    lower = ((1 << 63) + odd - 1) // odd
    residue = ((quantum // 2) * pow(odd, -1, quantum)) % quantum
    quotient = lower + (residue - lower) % quantum
    raw = quotient * odd
    require(1 << 63 <= raw < 1 << 64 and raw % quantum == quantum // 2,
            'constructed witness is not an in-range tie')
    require((raw // quantum) % 2 == 0, 'constructed tie does not round down')
    first, result = simd_conversion(raw, constants)
    exact = Fraction(raw, float_fraction(constants['divisor_bits']))
    direct = round_binary64(exact)
    require(float_fraction(direct) == exact and result != direct,
            'constructed input does not lose an exact ratio')
    return {'raw_u64': raw, 'exact_ratio_numerator': exact.numerator,
            'exact_ratio_denominator': exact.denominator,
            'converted_f64_bits': f'{first:016x}', 'view_f64_bits': f'{result:016x}',
            'exact_ratio_f64_bits': f'{direct:016x}'}


def u64_rounding_error_bound(constants):
    """Bound absolute two-stage error for the entire u64 input domain."""
    divisor = float_fraction(constants['divisor_bits'])
    require(divisor == 10**6, 'unexpected divisor for error bound')
    # Every u64 converted to binary64 lies in [0, 2**64]. For integer
    # inputs, half the largest in-domain conversion ulp is 2**10.
    integer_error = 1 << 10
    witness = (1 << 63) + integer_error
    rounded, _ = simd_conversion(witness, constants)
    require(float_fraction(rounded) == 1 << 63, 'integer-rounding bound witness failed')
    require(abs(float_fraction(rounded) - witness) == integer_error, 'integer error is not attained')
    max_dividend = Fraction(1 << 64, 1) / divisor
    e = max_dividend.numerator.bit_length() - max_dividend.denominator.bit_length()
    if e >= 0 and max_dividend.numerator < (max_dividend.denominator << e):
        e -= 1
    require(e == 44 and Fraction(1 << e) <= max_dividend < Fraction(1 << (e + 1)),
            'unexpected quotient binade')
    division_rounding_error = Fraction(1, 1 << (53 - e))
    pre_division_error = Fraction(integer_error, 1) / divisor
    total = pre_division_error + division_rounding_error
    return {'integer_conversion_error_max': integer_error,
            'integer_error_attaining_u64': witness,
            'quotient_upper_bound_binade': e,
            'pre_division_error_numerator': pre_division_error.numerator,
            'pre_division_error_denominator': pre_division_error.denominator,
            'division_rounding_error_numerator': division_rounding_error.numerator,
            'division_rounding_error_denominator': division_rounding_error.denominator,
            'total_error_bound_numerator': total.numerator,
            'total_error_bound_denominator': total.denominator}


def integer_round_u64(value):
    """Independent bitwise lift of u64-to-binary64, with its rounding branch.

    The returned exact integer may equal 2**64 even though the input is u64.
    That boundary must not be narrowed back to u64 before the division.
    """
    require(type(value) is int and 0 <= value < 1 << 64, 'integer input outside u64')
    shift = max(0, value.bit_length() - 53)
    if shift == 0:
        return value, 'exact'
    high, low = divmod(value, 1 << shift)
    if low == 0:
        return value, 'exact'
    halfway = 1 << (shift - 1)
    if low == halfway:
        up = bool(high & 1)
        route = 'tie-even-up' if up else 'tie-even-down'
    else:
        up = low > halfway
        route = 'round-up' if up else 'round-down'
    return (high + int(up)) << shift, route


def integer_conversion_bins(constants):
    """Partition the u64 domain by binary64 integer spacing.

    Each normal binade at exponent e >= 53 has 2**52 floating values
    spaced by 2**(e-52). Every spacing interval contains one exact u64,
    one midpoint tie, and no conversion error greater than half the spacing.
    These are counts of mathematical inputs, not observed node data.
    """
    facts = prove_lane_lift(constants)
    width = sum(fact['payload_bits'] for fact in facts)
    precision = 53  # IEEE binary64 includes its implicit leading bit.
    require(width == 64, 'unexpected integer width for binade partition')
    rows = [{'binade': 'below_2^53', 'lower_u64': 0, 'upper_exclusive': 1 << precision,
             'integer_spacing': 1, 'input_count': 1 << precision,
             'exact_count': 1 << precision, 'midpoint_tie_count': 0, 'max_integer_error': 0}]
    for exponent in range(precision, width):
        lower, upper = 1 << exponent, 1 << (exponent + 1)
        spacing = 1 << (exponent - precision + 1)
        count = upper - lower
        require(count % spacing == 0 and spacing % 2 == 0, 'invalid binary64 binade spacing')
        exact = count // spacing
        rows.append({'binade': f'2^{exponent}..2^{exponent + 1}',
                     'lower_u64': lower, 'upper_exclusive': upper,
                     'integer_spacing': spacing, 'input_count': count,
                     'exact_count': exact, 'midpoint_tie_count': exact,
                     'max_integer_error': spacing // 2})
    require(sum(row['input_count'] for row in rows) == 1 << width,
            'binade partition does not cover u64')
    return rows


def earliest_output_collision(constants):
    """Derive the first adjacent-u64 collision in the projected binary64.

    Before the threshold, all integer conversions are exact. Every binary64
    rounding cell strictly below the threshold has width at most the spacing
    in the previous binade, which is smaller than one input step after division.
    The cell centred on the threshold is checked separately because its two
    neighbouring spacings differ. All comparisons use exact rational values.
    """
    divisor = float_fraction(constants['divisor_bits'])
    require(divisor == 10**6, 'unexpected divisor for collision proof')
    unit = 1 / divisor
    exponent = next(e for e in range(53) if Fraction(1, 1 << (52 - e)) > unit)
    spacing = Fraction(1, 1 << (52 - exponent))
    previous_spacing = spacing / 2
    require(previous_spacing < unit < spacing, 'unexpected quotient spacing')
    threshold_fraction = (1 << exponent) * divisor
    require(threshold_fraction.denominator == 1, 'non-integer collision threshold')
    threshold = threshold_fraction.numerator
    require(threshold + 3 < 1 << 53, 'integer conversion may round before collision')
    # Threshold +/- one input step both lie outside its asymmetric rounding
    # cell. The next two inputs lie within the following, equal-spacing cell.
    require(unit > previous_spacing / 2 and unit > spacing / 2,
            'threshold cell contains an adjacent input')
    require(spacing / 2 < unit and 2 * unit < 3 * spacing / 2,
            'first two inputs above threshold do not share a rounding cell')
    around = {}
    for raw in range(threshold - 1, threshold + 4):
        first, final = simd_conversion(raw, constants)
        require(float_fraction(first) == raw, 'initial conversion was not exact')
        around[raw] = final
    require(around[threshold - 1] != around[threshold]
            and around[threshold] != around[threshold + 1]
            and around[threshold + 1] == around[threshold + 2]
            and around[threshold + 2] != around[threshold + 3],
            'collision boundary model mismatch')
    return {'threshold_quotient_power_of_two': exponent,
            'threshold_raw_u64': threshold,
            'first_raw_u64': threshold + 1, 'second_raw_u64': threshold + 2,
            'shared_result_f64_bits': f'{around[threshold + 1]:016x}',
            'previous_spacing_numerator': previous_spacing.numerator,
            'previous_spacing_denominator': previous_spacing.denominator,
            'input_step_numerator': unit.numerator, 'input_step_denominator': unit.denominator,
            'next_spacing_numerator': spacing.numerator, 'next_spacing_denominator': spacing.denominator}


def selector_route(name_ok, selector, found, boundary=50):
    require(type(name_ok) is bool and type(found) is bool, 'expected boolean lookup flags')
    require(type(selector) is int and 0 <= selector < 1 << 32, 'selector outside u32')
    if not name_ok:
        return 'lookup-error', False
    require(type(boundary) is int and 0 < boundary < 1 << 32, 'selector boundary outside u32')
    if selector >= boundary and not found:
        return 'missing-selector-0x154', False
    return 'call-getter-and-converter', True



def collection_route(declared, emitted, limit, cutoff):
    require(type(declared) is int and 0 <= declared < 1 << 64, 'declared count outside u64')
    require(type(limit) is int and limit >= 0 and type(cutoff) is int and cutoff > 2,
            'invalid collection bounds')
    if declared > limit:
        return 'size-overflow'
    # The caller initializes the output length to zero. On a normal return,
    # the walker increments it exactly once for each decremented input count.
    # Invalid tree states or an unwinding conversion are not normal returns.
    require(type(emitted) is int and emitted == declared, 'inconsistent normal-return count')
    if emitted == 0:
        return 'empty'
    if emitted == 1:
        return 'single-no-preparation-helper'
    if emitted < cutoff:
        return 'direct-preparation-helper'
    return 'indirect-preparation-helper'

def write_tsv(path, columns, rows):
    with path.open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=columns, delimiter='\t', lineterminator='\n', extrasaction='raise')
        w.writeheader()
        w.writerows(rows)


def bridge_layout(image):
    """Decode and cross-check selected collection/consumer addressing bytes."""
    key_store = image.read(0x2a083d0, 8, executable=True)
    key_load = image.read(0x2a1441a, 11, executable=True)
    capacity = image.read(0x2a0860e, 12, executable=True)
    record = image.read(0x2a22b0c, 4, executable=True)
    writer_stride = image.read(0x2a14380, 4, executable=True)
    require(key_store[:4] == bytes.fromhex('41898c87'), 'unexpected key store')
    require(key_load[:7] == bytes.fromhex('4d8d04914981c0'), 'unexpected key address lift')
    require(capacity[:4] == bytes.fromhex('410fb787') and capacity[8:11] == bytes.fromhex('4883f8'),
            'unexpected node capacity guard')
    require(record[:3] == bytes.fromhex('496bc7'), 'unexpected collection record stride')
    require(writer_stride[:3] == bytes.fromhex('49c1e6'), 'unexpected pointer vector stride')
    # Both lifts multiply the index by three then shift it left by four.
    require(image.read(0x2a083d8, 7, True) == bytes.fromhex('488d0440c1e004'),
            'unexpected payload-store stride')
    require(image.read(0x2a14425, 11, True) == bytes.fromhex('488d145248c1e2044c01ca'),
            'unexpected payload-address stride')
    key_at_store = struct.unpack_from('<I', key_store, 4)[0]
    key_at_read = struct.unpack_from('<I', key_load, 7)[0]
    count_offset = struct.unpack_from('<I', capacity, 4)[0]
    slots = capacity[11]
    payload_stride = 3 << 4
    pointer_stride = 1 << writer_stride[3]
    collection_stride = record[3]
    require(key_at_store == key_at_read, 'tree producer and consumer key offsets differ')
    require(slots == 11 and payload_stride == 48 and pointer_stride == 16 and collection_stride == 56,
            'unexpected layout or capacity')
    require(slots * payload_stride <= key_at_store and key_at_store + slots * 4 <= count_offset,
            'tree key and value ranges overlap')
    allocation = image.read(0x2a0a90d, 5, executable=True)
    require(allocation[0] == 0xbf, 'unexpected node allocation instruction')
    node_bytes = struct.unpack_from('<I', allocation, 1)[0]
    require(count_offset + 2 == node_bytes, 'node count and allocation disagree')
    first = image.read(0x206110, 16)
    second = image.read(0x208920, 16)
    require(first[-2:] == second[:2], 'special-key overlap mismatch')
    special_key = first + second[2:]
    require(special_key == b'$serde_json::private::RawValue', 'unexpected special field key')
    margin_key = image.read(0x41fc91, 12)
    require(margin_key == b'marginTables', 'unexpected margin table key')
    return {'key_offset': key_at_store, 'key_stride': 4, 'payload_offset': 0,
            'payload_stride': payload_stride, 'node_count_offset': count_offset,
            'node_slots_on_simple_insert': slots, 'initial_node_allocation_bytes': node_bytes,
            'pointer_pair_stride': pointer_stride, 'collection_entry_stride': collection_stride,
            'special_field_key': special_key.decode('ascii'), 'margin_field_key': margin_key.decode('ascii')}


def keyed_route(is_special_state, length, field_bytes, special_key):
    """Model the byte-qualified adapter gates, stopping at an external call."""
    require(type(is_special_state) is bool, 'state must be boolean')
    require(type(length) is int and 0 <= length < 1 << 64, 'length outside u64')
    require(isinstance(field_bytes, bytes) and isinstance(special_key, bytes), 'field bytes required')
    if is_special_state:
        if length != len(special_key):
            return 'special-wrong-length-error'
        require(len(field_bytes) == length, 'special-key bytes truncated')
        return 'special-value-call' if field_bytes == special_key else 'special-wrong-key-error'
    if length >= 1 << 63:
        return 'field-allocation-size-error'
    return 'ordinary-empty-name-then-tree' if length == 0 else 'ordinary-allocate-then-tree-on-success'


def simulate_bridge(layout, index, key, payload):
    """Model only disjoint node stores/loads for a synthetic node, not x86."""
    require(type(index) is int and 0 <= index < layout['node_slots_on_simple_insert'],
            'node index outside simple-insert range')
    require(type(key) is int and 0 <= key < 1 << 32, 'key outside u32')
    require(isinstance(payload, bytes) and len(payload) == layout['payload_stride'],
            'invalid payload length')
    node = bytearray(layout['initial_node_allocation_bytes'])
    key_offset = layout['key_offset'] + layout['key_stride'] * index
    payload_offset = layout['payload_offset'] + layout['payload_stride'] * index
    struct.pack_into('<I', node, key_offset, key)
    node[payload_offset:payload_offset + len(payload)] = payload
    observed_key = struct.unpack_from('<I', node, key_offset)[0]
    observed_payload = bytes(node[payload_offset:payload_offset + len(payload)])
    return {'key_offset': key_offset, 'payload_offset': payload_offset,
            'observed_key': observed_key, 'payload_equal': observed_payload == payload,
            'payload_sha256': hashlib.sha256(observed_payload).hexdigest()}


def collect(image):
    functions = []
    for role, start, end, digest in FUNCTIONS:
        fde = image.one_fde(start, end)
        sec, offset = image.mapping(start, end - start, executable=True)
        body = image.read(start, end - start, executable=True)
        body_hash = hashlib.sha256(body).hexdigest()
        require(body_hash == digest, 'function byte hash mismatch')
        functions.append({'role': role, 'start_va': hex(start), 'end_va': hex(end),
                          'fde_va': hex(fde['fde']), 'section': sec['name'],
                          'file_offset': hex(offset), 'size': len(body),
                          'body_sha256': body_hash, 'body_hex': body.hex()})

    anchors = []
    for role, va, expected in ANCHORS:
        raw = image.read(va, len(bytes.fromhex(expected)), executable=True)
        require(raw.hex() == expected, 'instruction anchor mismatch')
        _, off = image.mapping(va, len(raw), executable=True)
        anchors.append({'role': role, 'va': hex(va), 'file_offset': hex(off), 'bytes': raw.hex()})

    branches = [extract_branch(image, *row) for row in BRANCHES]
    calls = [extract_call(image, *row) for row in CALLS]
    fields = [extract_field(image, *row) for row in FIELD_SITES]
    unpack_low, unpack_high = struct.unpack('<II', image.read(0x203e80, 8))
    bias_low, bias_high = struct.unpack('<QQ', image.read(0x202ea0, 16))
    divisor_bits = struct.unpack('<Q', image.read(0x20ae60, 8))[0]
    constants = dict(unpack_low=unpack_low, unpack_high=unpack_high, bias_low=bias_low,
                     bias_high=bias_high, divisor_bits=divisor_bits)
    require(constants == {'unpack_low': 0x43300000, 'unpack_high': 0x45300000,
                          'bias_low': 0x4330000000000000, 'bias_high': 0x4530000000000000,
                          'divisor_bits': 0x412e848000000000}, 'unexpected floating constants')
    lane_facts = prove_lane_lift(constants)
    bridge = bridge_layout(image)
    divisor = float_fraction(divisor_bits)
    require(divisor.denominator == 1 and divisor.numerator == 2**6 * 5**6, 'unexpected divisor')
    vector_limit = struct.unpack('<Q', image.read(0x2a25f49, 8, True))[0]
    serial_limit = struct.unpack('<Q', image.read(0x29f4293, 8, True))[0]
    require(vector_limit == (1 << 63) - 8 and serial_limit == ((1 << 63) - 1) // 72,
            'unexpected allocation limits')
    list_stride = image.read(0x2a0a845, 1, True)[0]
    collection_limit = struct.unpack('<Q', image.read(0x2a0a848, 8, True))[0] - 1
    collection_cutoff = image.read(0x2a0a9e5, 1, True)[0]
    require(list_stride == 56 and collection_limit == ((1 << 63) - 1) // list_stride
            and collection_cutoff == 21, 'unexpected collection bounds')
    selector_limit = image.read(0x27db99f, 1, True)[0]
    success_tag = struct.unpack('<H', image.read(0x27db98c, 2, True))[0]
    missing_tag = struct.unpack('<H', image.read(0x27dbc6e, 2, True))[0]
    require(success_tag == 0x186 and missing_tag == 0x154, 'unexpected selector tags')
    require(selector_limit == 50, 'unexpected selector boundary')
    row_stride = image.read(0x2a26038, 1, True)[0]
    require(row_stride == 16, 'unexpected tier row stride')
    return {'functions': functions, 'anchors': anchors, 'branches': branches, 'calls': calls,
            'fields': fields, 'constants': constants, 'lane_facts': lane_facts, 'divisor': divisor.numerator,
            'vector_limit': vector_limit, 'serial_limit': serial_limit,
            'selector_limit': selector_limit, 'success_tag': success_tag, 'missing_tag': missing_tag,
            'bridge': bridge, 'row_stride': row_stride, 'collection_stride': list_stride,
            'collection_limit': collection_limit, 'collection_cutoff': collection_cutoff}


def cases(constants):
    values = {0, 1, 999, 1000, 15624, 15625, 15626, 999999, 1000000, 1000001,
              10**15, 10**15 - 1, 10**15 + 1, (1 << 64) - 1}
    for i in range(65):
        p = 1 << i
        values.update(x for x in (p - 1, p, p + 1) if 0 <= x < 1 << 64)
    for i in range(20):
        p = 10**i
        values.update(x for x in (p - 1, p, p + 1) if 0 <= x < 1 << 64)
    values.add(exact_ratio_witness(constants)['raw_u64'])
    collision_threshold = earliest_output_collision(constants)['threshold_raw_u64']
    values.update(range(collision_threshold - 1, collision_threshold + 4))
    out = []
    d = float_fraction(constants['divisor_bits'])
    for value in sorted(values):
        converted, result = simd_conversion(value, constants)
        integer_value, integer_route = integer_round_u64(value)
        direct = round_binary64(Fraction(value, 1) / d)
        require(converted == round_binary64(Fraction(value, 1)), 'packed conversion model mismatch')
        require(float_fraction(converted) == integer_value, 'integer rounding lift mismatch')
        out.append({'raw_u64': value, 'converted_f64_bits': f'{converted:016x}',
                    'converted_integer': integer_value, 'integer_rounding_route': integer_route,
                    'view_f64_bits': f'{result:016x}', 'exact_ratio_rounded_bits': f'{direct:016x}',
                    'two_step_differs': int(result != direct),
                    'view_equals_exact_ratio': int(float_fraction(result) == Fraction(value, 1) / d)})
    return out


def host_control_inputs():
    values = {0, 1, 999, 1000, 15624, 15625, 15626, (1 << 64) - 1}
    for bit in range(65):
        values.update(v for v in ((1 << bit) - 1, 1 << bit, (1 << bit) + 1)
                      if 0 <= v < 1 << 64)
    values.update((0x9e3779b97f4a7c15 * i + 0x123456789abcdef) & ((1 << 64) - 1)
                  for i in range(2048))
    return sorted(values)


def generate(image, out):
    c = collect(image)
    out.mkdir(parents=True, exist_ok=True)
    fs = c['functions']
    write_tsv(out / 'functions.tsv', ['role', 'start_va', 'end_va', 'fde_va', 'section', 'file_offset', 'size', 'body_sha256'],
              [{k: v for k, v in f.items() if k != 'body_hex'} for f in fs])
    write_tsv(out / 'anchors.tsv', ['role', 'va', 'file_offset', 'bytes'], c['anchors'])
    anchors_by_role = {anchor['role']: anchor for anchor in c['anchors']}
    require(len(anchors_by_role) == len(c['anchors']), 'duplicate instruction anchor role')
    flow = []
    for role, source, destination in FLOW:
        anchor = anchors_by_role[role]
        flow.append({'stage': role, 'site_va': anchor['va'], 'bytes': anchor['bytes'],
                     'source': source, 'destination': destination, 'payload_bytes': 48})
    write_tsv(out / 'response-flow.tsv', ['stage', 'site_va', 'bytes', 'source', 'destination', 'payload_bytes'], flow)
    write_tsv(out / 'branches.tsv', ['site_va', 'bytes', 'taken_va', 'fallthrough_va', 'taken_when'], c['branches'])
    write_tsv(out / 'calls.tsv', ['role', 'site_va', 'kind', 'bytes', 'slot_va', 'target_va'], c['calls'])
    write_tsv(out / 'fields.tsv', ['scope', 'instruction_va', 'text_va', 'length', 'name', 'lea_bytes'], c['fields'])
    bridge = c['bridge']
    layout_rows = [
        {'fact': 'node_key_array_offset', 'value': bridge['key_offset'], 'evidence': 'tree key and payload store; tree key and value pointers'},
        {'fact': 'node_key_width_and_stride', 'value': bridge['key_stride'], 'evidence': '32-bit store and scaled address'},
        {'fact': 'node_view_stride', 'value': bridge['payload_stride'], 'evidence': 'tree key and payload store; tree key and value pointers'},
        {'fact': 'node_count_offset', 'value': bridge['node_count_offset'], 'evidence': 'tree capacity guard'},
        {'fact': 'simple_insert_node_slots', 'value': bridge['node_slots_on_simple_insert'], 'evidence': 'tree capacity guard'},
        {'fact': 'initial_node_allocation_bytes', 'value': bridge['initial_node_allocation_bytes'], 'evidence': 'collection allocation and tree construction'},
        {'fact': 'source_collection_row_stride', 'value': bridge['collection_entry_stride'], 'evidence': 'collection element projection; tree row consume'},
        {'fact': 'pointer_pair_stride', 'value': bridge['pointer_pair_stride'], 'evidence': 'tree key and value pointers; pointer pair list call'},
        {'fact': 'special_field_key', 'value': bridge['special_field_key'], 'evidence': 'keyed special field guard and overlapping constant bytes'},
        {'fact': 'referenced_outer_field_key', 'value': bridge['margin_field_key'], 'evidence': 'file-backed literal; caller attribution supplied by separate research'},
    ]
    write_tsv(out / 'bridge-layout.tsv', ['fact', 'value', 'evidence'], layout_rows)
    special = bridge['special_field_key'].encode('ascii')
    field_cases = []
    for state, length, key in ((True, len(bridge['margin_field_key']), bridge['margin_field_key'].encode('ascii')),
                               (True, len(special), special),
                               (True, len(special), bytes([special[0] ^ 1]) + special[1:]),
                               (False, 0, b''),
                               (False, len(bridge['margin_field_key']), bridge['margin_field_key'].encode('ascii')),
                               (False, (1 << 63) - 1, b''),
                               (False, 1 << 63, b'')):
        route = keyed_route(state, length, key, special)
        field_cases.append({'special_state': int(state), 'declared_length': length,
                            'synthetic_field_hex': key.hex(), 'model_route': route})
    write_tsv(out / 'keyed-cases.tsv', ['special_state', 'declared_length', 'synthetic_field_hex',
                                        'model_route'], field_cases)
    bridge_cases = []
    for index in range(bridge['node_slots_on_simple_insert']):
        for key in (0, c['selector_limit'] - 1, c['selector_limit'], (1 << 32) - 1):
            payload = bytes((index * 13 + key + n) % 256 for n in range(bridge['payload_stride']))
            model = simulate_bridge(bridge, index, key, payload)
            require(model['observed_key'] == key and model['payload_equal'], 'bridge layout model failed')
            bridge_cases.append({'synthetic_index': index, 'synthetic_key_u32': key,
                                 'key_offset': model['key_offset'], 'payload_offset': model['payload_offset'],
                                 'payload_sha256': model['payload_sha256'], 'preserved': 1})
    write_tsv(out / 'bridge-cases.tsv', ['synthetic_index', 'synthetic_key_u32', 'key_offset',
                                        'payload_offset', 'payload_sha256', 'preserved'], bridge_cases)
    vectors = cases(c['constants'])
    write_tsv(out / 'rounding.tsv', ['raw_u64', 'converted_f64_bits', 'converted_integer',
                                     'integer_rounding_route', 'view_f64_bits',
                                     'exact_ratio_rounded_bits', 'two_step_differs', 'view_equals_exact_ratio'], vectors)
    bins = integer_conversion_bins(c['constants'])
    write_tsv(out / 'integer-bins.tsv', ['binade', 'lower_u64', 'upper_exclusive',
                                        'integer_spacing', 'input_count', 'exact_count',
                                        'midpoint_tie_count', 'max_integer_error'], bins)
    exact_inputs = sum(row['exact_count'] for row in bins)
    exact_fraction = Fraction(exact_inputs, 1 << 64)
    selectors = []
    for ok in (False, True):
        for selector in (0, c['selector_limit'] - 1, c['selector_limit'], c['selector_limit'] + 1, (1 << 32) - 1):
            for found in (False, True):
                result, called = selector_route(ok, selector, found, c['selector_limit'])
                selectors.append({'lookup_ok': int(ok), 'selector_u32': selector, 'custom_key_found': int(found),
                                  'model_outcome': result, 'calls_converter': int(called)})
    write_tsv(out / 'selector-cases.tsv', ['lookup_ok', 'selector_u32', 'custom_key_found',
                                            'model_outcome', 'calls_converter'], selectors)
    collection = []
    for declared, emitted in ((0, 0), (1, 1), (2, 2), (c['collection_cutoff'] - 1, c['collection_cutoff'] - 1),
                              (c['collection_cutoff'], c['collection_cutoff']),
                              (c['collection_limit'], c['collection_limit']),
                              (c['collection_limit'] + 1, None), ((1 << 64) - 1, None)):
        route = collection_route(declared, emitted, c['collection_limit'], c['collection_cutoff'])
        collection.append({'declared_count_u64': declared, 'emitted_count_u64': '' if emitted is None else emitted,
                           'input_bytes_if_representable': declared * c['collection_stride']
                           if declared <= c['collection_limit'] else '', 'model_route': route})
    write_tsv(out / 'collection-cases.tsv', ['declared_count_u64', 'emitted_count_u64',
                                              'input_bytes_if_representable', 'model_route'], collection)
    proof = {
        'target_sha256': image.sha256,
        'assumption': 'IEEE 754 binary64 round-to-nearest ties-to-even with masked exceptions',
        'division_constant_bits': f"{c['constants']['divisor_bits']:016x}",
        'division_constant_integer': c['divisor'],
        'factorization': {'power_of_two': 6, 'power_of_five': 6, 'odd_part': 5**6},
        'packed_lane_facts': c['lane_facts'],
        'full_u64_error_bound': u64_rounding_error_bound(c['constants']),
        'tree_layout': bridge,
        'synthetic_bridge_case_count': len(bridge_cases),
        'synthetic_keyed_case_count': len(field_cases),
        'u64_algebra': '(low32 * 1) + (high32 * 2**32) == raw, with exact lane subtractions',
        'exact_integer_conversion_inclusive': 1 << 53,
        'integer_conversion_bins': len(bins),
        'integer_conversion_exact_u64_inputs': exact_inputs,
        'integer_conversion_exact_fraction_numerator': exact_fraction.numerator,
        'integer_conversion_exact_fraction_denominator': exact_fraction.denominator,
        'integer_conversion_midpoint_ties': sum(row['midpoint_tie_count'] for row in bins),
        'maximum_u64_converted_integer': integer_round_u64((1 << 64) - 1)[0],
        'exact_ratio_in_that_range_iff_multiple': 5**6,
        'exact_ratio_any_u64_iff_multiple': 5**6,
        'maximum_u64_divided_by_odd_part': ((1 << 64) - 1) // 5**6,
        'maximum_quotient_significand_bits': (((1 << 64) - 1) // 5**6).bit_length(),
        'exact_ratio_lost_witness': exact_ratio_witness(c['constants']),
        'earliest_adjacent_output_collision': earliest_output_collision(c['constants']),
        'row_stride_bytes': c['row_stride'],
        'collection_stride_bytes': c['collection_stride'],
        'collection_max_count_from_instructions': c['collection_limit'],
        'collection_helper_cutoff_from_instruction': c['collection_cutoff'],
        'vector_byte_limit_from_instruction': c['vector_limit'],
        'maximum_16_byte_row_count': c['vector_limit'] // c['row_stride'],
        'maximum_72_byte_output_count_from_instruction': c['serial_limit'],
        'selector_boundary_from_instruction': c['selector_limit'],
        'lookup_success_tag_from_instruction': c['success_tag'],
        'missing_selector_tag_from_instruction': c['missing_tag'],
        'vector_count': len(vectors),
        'two_step_differences_in_vectors': sum(row['two_step_differs'] for row in vectors),
        'selector_case_count': len(selectors), 'collection_case_count': len(collection),
        'host_control_case_count': len(host_control_inputs()),
        'scope': 'The full-domain integer conversion and factorization arguments depend on the manually qualified instruction lift; the vector cases are not target execution.',
    }
    require(proof['maximum_quotient_significand_bits'] <= 53,
            'u64 quotient does not fit a binary64 significand')
    (out / 'proof.json').write_text(json.dumps(proof, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    evidence = {
        'target_release': 'node 94', 'target_sha256': image.sha256,
        'repository_commit': SOURCE_COMMIT, 'reference_commit': REFERENCE_COMMIT,
        'coordinate_system': 'unrebased ELF virtual addresses; file offsets from file-backed sections',
        'functions': fs, 'floating_constants': {k: hex(v) for k, v in c['constants'].items()},
        'counts': {'functions': len(fs), 'anchors': len(c['anchors']), 'flow_steps': len(flow), 'branches': len(c['branches']),
                   'calls': len(c['calls']), 'fields': len(c['fields']), 'rounding_cases': len(vectors), 'integer_bins': len(bins),
                   'bridge_layout_facts': len(layout_rows), 'synthetic_bridge_cases': len(bridge_cases),
                   'synthetic_keyed_cases': len(field_cases)},
        'limits': 'FDEs are unwind ranges, not a complete function census. The serializer handoff is a matching layout, not an established runtime ownership edge.',
    }
    (out / 'evidence.json').write_text(json.dumps(evidence, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return evidence['counts']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    image = Image(BINARY.read_bytes())
    counts = generate(image, args.out)
    print(json.dumps(counts, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, struct.error) as error:
        print('margin_tier_scale94:', error, file=sys.stderr)
        raise SystemExit(1)
