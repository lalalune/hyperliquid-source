#!/usr/bin/env python3
"""Authenticated node94 mod-42fc790 binding (0x42fc790).

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

START, END = 0x42fc790, 0x42fd525
FDE_VA = 0x122d608
FDE = bytes.fromhex(
    '50000000e0f9260080f10c03950d000004fba88fff410e10420e18420e20420e'
    '28420e30410e38470e900683078c068d058e048f03860203ba0c0e38410e3042'
    '0e28420e20420e18420e10410e08410e90060000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ecd802000085f60f84ab0c00004889fb4889bc24'
    'c8000000488db7800000004c8db424e00000004c89f74889dae8d2b07000488b'
    '8424e0000000488b8c24e800000048898424d000000048898c24d80000004885'
    'c00f94c248ffc94839c10f93c008d00f84730c0000488b7328488b4330488944'
    '24104801f048ffc0660f6f06660fd7c8f7d1488d5610488b7b40488974243048'
    '89b424e000000048899424e800000048898424f000000066898c24f800000048'
    '897c24604889bc24000100004c8d742470488db424e00000004c89f7e81f8657'
    '0048899c24e0000000488db424e00000004c89f7e8e7304700488b83b8000000'
    '48895c2468488b8bc800000048894424084885c00f95c048898c24a800000048'
    '85c90f95c120c180f9010f85220b0000488b4424304883c0f04889442458488b'
    '442468488b90c00000004531c94889542418488b442408eb1f0f1f8000000000'
    'b80000000048ff8c24a8000000488b5424400f84da0a00004d85c97423410fb7'
    '89560400004839ca0f83d20000004c89c9e9f1000000662e0f1f840000000000'
    '4885d2743b4889d14883e10774374889d64989c131d2662e0f1f840000000000'
    '4d8b895804000048ffc24839d175f14889f04829d04889f24883fa087322eb5e'
    '4989c1eb594989c14889d04883fa08724d6666666666662e0f1f840000000000'
    '498b8958040000488b8958040000488b8958040000488b8958040000488b8958'
    '040000488b8958040000488b89580400004c8b89580400004883c0f875c231c0'
    '31d2410fb789560400004839ca0f823bffffff666666662e0f1f840000000000'
    '498b89700300004885c90f84ed0a000048ffc0410fb791540400004989c9663b'
    '915604000073d94885c00f8490000000488d34d14881c6600400004889c74883'
    'e7070f84980900004531c00f1f4400004c8b0e498db15804000049ffc04c39c7'
    '75ee4889c74c29c74883f80872436690488b06488b8058040000488b80580400'
    '00488b8058040000488b8058040000488b8058040000488b80580400004c8b88'
    '58040000498db1580400004883c7f875bf48c744244000000000eb100f1f4000'
    '488d420148894424404989c9488d14928b84918803000089842480000000f30f'
    '6f84917803000048c1e204660f7f442470488b4411384885c00f8401feffff48'
    '01d14c8b51484d85d20f84f1fdffff488b794031f64c898c24b0000000eb2990'
    'b8000000004c8b9424b800000049ffca4c8b8c24b0000000488b742450488b7c'
    '24480f84b8fdffff4885f674230fb78e4a0800004839cf0f83b30000004889f1'
    '4889fae9ca0000000f1f8400000000004885ff747d4889f94889c64883e1070f'
    '844708000031d2660f1f840000000000488bb65008000048ffc24839d175f148'
    '89f84829d04883ff0872430f1f440000488b8e50080000488b8950080000488b'
    '8950080000488b8950080000488b8950080000488b8950080000488b89500800'
    '00488bb1500800004883c0f875c231ffeb0531ff4889c631c00fb78e4a080000'
    '4839cf0f8254ffffff0f1f8000000000488b0e4885c90f845a08000048ffc00f'
    'b796480800004889ce663b914a08000073de4885c04c899424b8000000744148'
    '8d34d14881c6580800004889c74883e707743d4531c0662e0f1f840000000000'
    '4c8b0e498db15008000049ffc04c39c775ee4889c74c29c74883f8087322eb19'
    '488d4201488944244848894c2450eb5f4889c74883f80873074c894c2450eb46'
    '488b06488b8050080000488b8050080000488b8050080000488b805008000048'
    '8b8050080000488b8050080000488b8050080000488db0500800004883c7f875'
    'bf488944245048c7442448000000004869c2b8000000488d14014883c26083bc'
    '01800000000148895424387423837a10010f8438020000488b42404885c00f85'
    '4e040000e9f7fdffff0f1f80000000004c8b42288b842480000000898424f000'
    '0000660f6f442470660f7f8424e0000000488b6c2418488b5c240848837c2460'
    '004c894424200f84b40000004c89c048b9c5a9622eea7a35f1480fafc148c1c0'
    '144889c148c1e939660f6ec1660f60c0f20f70c000660f70c04431c948234424'
    '10488b542430f30f6f0c02660f6fd1660f74d0660fd7d285d27435f30fbcf248'
    '01c6482374241048c1e604488b7c24584829f74c3b070f84640100008d72ff66'
    '21d689f275d5662e0f1f840000000000660f76d2660f74ca660fd7d185d2750d'
    '4801c84883c0104883c110eb8f488b6c2418488b5c2408660f1f840000000000'
    '4c8da3780300000fb7835604000048894424288d0485000000004c8d2c8049c7'
    'c7ffffffff4531f60f1f8400000000004d39f5744b4b8d3434ba14000000488d'
    'bc24e0000000ff152c16470148984885c00f98c10f9fc028c84983c61449ffc7'
    '3c0174cc0fb6c085c074354883ed01731ee9aa000000662e0f1f840000000000'
    '4c8b7c24284883ed010f82910000004a8b9cfb58040000e964ffffff0f1f4000'
    '4a8b44b3e84885c04c8b4c242074714a8b4cb3f00fb7b04a08000089f7c1e703'
    '48c7c2ffffffff660f1f8400000000004885ff742b4c3b4cd010410f97c04180'
    'd80048ffc24883c7f84180f80174e1410fb6f085f674294883e901730ceb2190'
    '4889f24883e9017217488b84d050080000eba1666666662e0f1f840000000000'
    '488b542438837a10010f85c8fdffff4c8b42188b842480000000898424f00000'
    '00660f6f442470660f7f8424e0000000488b6c2418488b5c240848837c246000'
    '4c894424200f84b50000004c89c048b9c5a9622eea7a35f1480fafc148c1c014'
    '4889c148c1e939660f6ec1660f60c0f20f70c000660f70c04431c94823442410'
    '488b542430f30f6f0c02660f6fd1660f74d0660fd7d285d27436f30fbcf24801'
    'c6482374241048c1e604488b7c24584829f74c3b070f84650100008d72ff6621'
    'd689f275d566662e0f1f840000000000660f76d2660f74ca660fd7d185d2750d'
    '4801c84883c0104883c110eb8e488b6c2418488b5c2408660f1f840000000000'
    '4c8da3780300000fb7835604000048894424288d0485000000004c8d2c8049c7'
    'c7ffffffff4531f60f1f8400000000004d39f5744b4b8d3434ba14000000488d'
    'bc24e0000000ff150c14470148984885c00f98c10f9fc028c84983c61449ffc7'
    '3c0174cc0fb6c085c074354883ed01731ee9aa000000662e0f1f840000000000'
    '4c8b7c24284883ed010f82910000004a8b9cfb58040000e964ffffff0f1f4000'
    '4a8b44b3e84885c04c8b4c242074714a8b4cb3f00fb7b04a08000089f7c1e703'
    '48c7c2ffffffff660f1f8400000000004885ff742b4c3b4cd010410f97c04180'
    'd80048ffc24883c7f84180f80174e1410fb6f085f674294883e901730ceb2190'
    '4889f24883e9017217488b84d050080000eba1666666662e0f1f840000000000'
    '488b542438488b42404885c00f84aef9ffff488b4a38488d04c148898424c000'
    '0000e989000000660f1f8400000000004823442410488b542430f30f6f0c0266'
    '0f6fd1660f74d0660fd7d285d27431f30fbcf24801c6482374241048c1e60448'
    '8b7c24584829f74c3b070f84e00100008d72ff6621d689f275d5660f1f440000'
    '660f76d2660f74ca660fd7d185d275104801c84883c0104883c110eb930f1f00'
    '4c8b7c2418488b6c2408e9810000009048894c24284c8b018b84248000000089'
    '8424f0000000660f6f442470660f7f8424e00000004c8b7c2418488b6c240848'
    '837c2460004c8944242074444c89c048b9c5a9622eea7a35f1480fafc148c1c0'
    '144889c148c1e939660f6ec1660f60c0f20f70c000660f70c04431c9e90fffff'
    'ff6666666666662e0f1f840000000000488d9d780300000fb785560400004889'
    '4424388d0485000000004c8d248049c7c6ffffffff4531ed0f1f840000000000'
    '4d39ec744b4a8d342bba14000000488dbc24e0000000ff15bc11470148984885'
    'c00f98c10f9fc028c84983c51449ffc63c0174cc0fb6c085c074354983ef0173'
    '1ee9aa000000662e0f1f8400000000004c8b7424384983ef010f82910000004a'
    '8bacf558040000e964ffffff0f1f40004a8b44ade84885c04c8b4c242074714a'
    '8b4cadf00fb7b04a08000089f7c1e70348c7c2ffffffff660f1f840000000000'
    '4885ff742b4c3b4cd010410f97c04180d80048ffc24883c7f84180f80174e141'
    '0fb6f085f674294883e901730ceb21904889f24883e9017217488b84d0500800'
    '00eba1666666662e0f1f840000000000488b4c24284883c108483b8c24c00000'
    '000f8549feffffe954f7ffff4889f84883ff080f83d7f7ffffe910f8ffff6690'
    '4889c74883f8080f8383f6ffffe9bff6ffff488b442468488b68084c697010f8'
    '0000004901ee4531ff49c7c5ffffffff31c04889c34889e80f1f840000000000'
    '4c39f0743f49ffc70f84de000000488da8f80000008338024889e874e34c8b65'
    'd04c89e04801d873c931ff488d3536f54101ff15485d47014901dc4d0f42e54c'
    '89e0ebae4881c4d80200005b415c415d415e415f5dc3488d3de36a4301ff15fd'
    '0f4701e9820000004c89f74889dee8ed9a7000488d8424c80000004889442470'
    '488d05c97d03004889442478488d8424d00000004889842480000000488d059d'
    '712c0048898424880000004c89b42490000000488d05e6827a00488984249800'
    '0000488d3d4514effb488d15c8f44101488d742470ff15ad0b4701eb0d488d3d'
    '5c6a4301ff15760f47010f0b488d3dad834301ff150f0c47010f0b4889c3488d'
    'bc24e0000000e8f5f703004889dfe8ed2b36010f0b'
)
BODY_SHA256 = 'd8172996f1e6ec7e573d3df5b739feacd72722afcab29df50c78b42549bfd714'
BRANCHES = [
    (0x13, '0f84ab0c0000', 2, 6, 0x42fd454),
    (0x6f, '0f84730c0000', 2, 6, 0x42fd478),
    (0x12a, '0f85220b0000', 2, 6, 0x42fd3e2),
    (0x157, 'eb1f', 1, 2, 0x42fc908),
    (0x172, '0f84da0a0000', 2, 6, 0x42fd3e2),
    (0x17b, '7423', 1, 2, 0x42fc930),
    (0x188, '0f83d2000000', 2, 6, 0x42fc9f0),
    (0x191, 'e9f1000000', 1, 5, 0x42fca17),
    (0x1a3, '743b', 1, 2, 0x42fc970),
    (0x1ac, '7437', 1, 2, 0x42fc975),
    (0x1cd, '75f1', 1, 2, 0x42fc950),
    (0x1dc, '7322', 1, 2, 0x42fc990),
    (0x1de, 'eb5e', 1, 2, 0x42fc9ce),
    (0x1e3, 'eb59', 1, 2, 0x42fc9ce),
    (0x1ef, '724d', 1, 2, 0x42fc9ce),
    (0x23c, '75c2', 1, 2, 0x42fc990),
    (0x24d, '0f823bffffff', 2, 6, 0x42fc91e),
    (0x26a, '0f84ed0a0000', 2, 6, 0x42fd4ed),
    (0x285, '73d9', 1, 2, 0x42fc9f0),
    (0x28a, '0f8490000000', 2, 6, 0x42fcab0),
    (0x2a2, '0f8498090000', 2, 6, 0x42fd3d0),
    (0x2c0, '75ee', 1, 2, 0x42fca40),
    (0x2cc, '7243', 1, 2, 0x42fcaa1),
    (0x30f, '75bf', 1, 2, 0x42fca60),
    (0x31a, 'eb10', 1, 2, 0x42fcabc),
    (0x359, '0f8401feffff', 2, 6, 0x42fc8f0),
    (0x369, '0f84f1fdffff', 2, 6, 0x42fc8f0),
    (0x37d, 'eb29', 1, 2, 0x42fcb38),
    (0x3a2, '0f84b8fdffff', 2, 6, 0x42fc8f0),
    (0x3ab, '7423', 1, 2, 0x42fcb60),
    (0x3b7, '0f83b3000000', 2, 6, 0x42fcc00),
    (0x3c3, 'e9ca000000', 1, 5, 0x42fcc22),
    (0x3d3, '747d', 1, 2, 0x42fcbe2),
    (0x3df, '0f8447080000', 2, 6, 0x42fd3bc),
    (0x3fd, '75f1', 1, 2, 0x42fcb80),
    (0x409, '7243', 1, 2, 0x42fcbde),
    (0x44c, '75c2', 1, 2, 0x42fcba0),
    (0x450, 'eb05', 1, 2, 0x42fcbe7),
    (0x463, '0f8254ffffff', 2, 6, 0x42fcb4d),
    (0x476, '0f845a080000', 2, 6, 0x42fd466),
    (0x490, '73de', 1, 2, 0x42fcc00),
    (0x49d, '7441', 1, 2, 0x42fcc70),
    (0x4b1, '743d', 1, 2, 0x42fcc80),
    (0x4d0, '75ee', 1, 2, 0x42fcc50),
    (0x4dc, '7322', 1, 2, 0x42fcc90),
    (0x4de, 'eb19', 1, 2, 0x42fcc89),
    (0x4ee, 'eb5f', 1, 2, 0x42fccdf),
    (0x4f7, '7307', 1, 2, 0x42fcc90),
    (0x4fe, 'eb46', 1, 2, 0x42fccd6),
    (0x53f, '75bf', 1, 2, 0x42fcc90),
    (0x56b, '7423', 1, 2, 0x42fcd20),
    (0x571, '0f8438020000', 2, 6, 0x42fcf3f),
    (0x57e, '0f854e040000', 2, 6, 0x42fd162),
    (0x584, 'e9f7fdffff', 1, 5, 0x42fcb10),
    (0x5c6, '0f84b4000000', 2, 6, 0x42fce10),
    (0x619, '7435', 1, 2, 0x42fcde0),
    (0x636, '0f8464010000', 2, 6, 0x42fcf30),
    (0x644, '75d5', 1, 2, 0x42fcdab),
    (0x65e, '750d', 1, 2, 0x42fcdfd),
    (0x66b, 'eb8f', 1, 2, 0x42fcd8c),
    (0x6b3, '744b', 1, 2, 0x42fce90),
    (0x6e2, '74cc', 1, 2, 0x42fce40),
    (0x6e9, '7435', 1, 2, 0x42fceb0),
    (0x6ef, '731e', 1, 2, 0x42fce9f),
    (0x6f1, 'e9aa000000', 1, 5, 0x42fcf30),
    (0x709, '0f8291000000', 2, 6, 0x42fcf30),
    (0x717, 'e964ffffff', 1, 5, 0x42fce10),
    (0x72d, '7471', 1, 2, 0x42fcf30),
    (0x753, '742b', 1, 2, 0x42fcf10),
    (0x76d, '74e1', 1, 2, 0x42fcee0),
    (0x775, '7429', 1, 2, 0x42fcf30),
    (0x77b, '730c', 1, 2, 0x42fcf19),
    (0x77d, 'eb21', 1, 2, 0x42fcf30),
    (0x787, '7217', 1, 2, 0x42fcf30),
    (0x791, 'eba1', 1, 2, 0x42fcec4),
    (0x7a9, '0f85c8fdffff', 2, 6, 0x42fcd07),
    (0x7e5, '0f84b5000000', 2, 6, 0x42fd030),
    (0x838, '7436', 1, 2, 0x42fd000),
    (0x855, '0f8465010000', 2, 6, 0x42fd150),
    (0x863, '75d5', 1, 2, 0x42fcfca),
    (0x87e, '750d', 1, 2, 0x42fd01d),
    (0x88b, 'eb8e', 1, 2, 0x42fcfab),
    (0x8d3, '744b', 1, 2, 0x42fd0b0),
    (0x902, '74cc', 1, 2, 0x42fd060),
    (0x909, '7435', 1, 2, 0x42fd0d0),
    (0x90f, '731e', 1, 2, 0x42fd0bf),
    (0x911, 'e9aa000000', 1, 5, 0x42fd150),
    (0x929, '0f8291000000', 2, 6, 0x42fd150),
    (0x937, 'e964ffffff', 1, 5, 0x42fd030),
    (0x94d, '7471', 1, 2, 0x42fd150),
    (0x973, '742b', 1, 2, 0x42fd130),
    (0x98d, '74e1', 1, 2, 0x42fd100),
    (0x995, '7429', 1, 2, 0x42fd150),
    (0x99b, '730c', 1, 2, 0x42fd139),
    (0x99d, 'eb21', 1, 2, 0x42fd150),
    (0x9a7, '7217', 1, 2, 0x42fd150),
    (0x9b1, 'eba1', 1, 2, 0x42fd0e4),
    (0x9cc, '0f84aef9ffff', 2, 6, 0x42fcb10),
    (0x9e2, 'e989000000', 1, 5, 0x42fd200),
    (0xa0d, '7431', 1, 2, 0x42fd1d0),
    (0xa2a, '0f84e0010000', 2, 6, 0x42fd3a0),
    (0xa38, '75d5', 1, 2, 0x42fd19f),
    (0xa4e, '7510', 1, 2, 0x42fd1f0),
    (0xa5b, 'eb93', 1, 2, 0x42fd180),
    (0xa6a, 'e981000000', 1, 5, 0x42fd280),
    (0xaaa, '7444', 1, 2, 0x42fd280),
    (0xadc, 'e90fffffff', 1, 5, 0x42fd180),
    (0xb23, '744b', 1, 2, 0x42fd300),
    (0xb52, '74cc', 1, 2, 0x42fd2b0),
    (0xb59, '7435', 1, 2, 0x42fd320),
    (0xb5f, '731e', 1, 2, 0x42fd30f),
    (0xb61, 'e9aa000000', 1, 5, 0x42fd3a0),
    (0xb79, '0f8291000000', 2, 6, 0x42fd3a0),
    (0xb87, 'e964ffffff', 1, 5, 0x42fd280),
    (0xb9d, '7471', 1, 2, 0x42fd3a0),
    (0xbc3, '742b', 1, 2, 0x42fd380),
    (0xbdd, '74e1', 1, 2, 0x42fd350),
    (0xbe5, '7429', 1, 2, 0x42fd3a0),
    (0xbeb, '730c', 1, 2, 0x42fd389),
    (0xbed, 'eb21', 1, 2, 0x42fd3a0),
    (0xbf7, '7217', 1, 2, 0x42fd3a0),
    (0xc01, 'eba1', 1, 2, 0x42fd334),
    (0xc21, '0f8549feffff', 2, 6, 0x42fd200),
    (0xc27, 'e954f7ffff', 1, 5, 0x42fcb10),
    (0xc33, '0f83d7f7ffff', 2, 6, 0x42fcba0),
    (0xc39, 'e910f8ffff', 1, 5, 0x42fcbde),
    (0xc47, '0f8383f6ffff', 2, 6, 0x42fca60),
    (0xc4d, 'e9bff6ffff', 1, 5, 0x42fcaa1),
    (0xc83, '743f', 1, 2, 0x42fd454),
    (0xc88, '0f84de000000', 2, 6, 0x42fd4fc),
    (0xc9b, '74e3', 1, 2, 0x42fd410),
    (0xca7, '73c9', 1, 2, 0x42fd402),
    (0xcc2, 'ebae', 1, 2, 0x42fd402),
    (0xce3, 'e982000000', 1, 5, 0x42fd4fa),
    (0xd5b, 'eb0d', 1, 2, 0x42fd4fa),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x42fc7c9, 0x4a078a0),
    (0x42fc86c, 0x4874e90),
    (0x42fc884, 0x476f970),
    (0x42fd47e, 0x4a06f70),
    (0x42fd516, 0x433cd10),
    (0x42fd51e, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x42fce56, 0x576e488),
    (0x42fd076, 0x576e488),
    (0x42fd2c6, 0x576e488),
    (0x42fd442, 0x5773190),
    (0x42fd46d, 0x576e470),
    (0x42fd4e5, 0x576e098),
    (0x42fd4f4, 0x576e470),
    (0x42fd503, 0x576e118),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x42fd466, 0x5733f50, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 534, 47),
    (0x42fd4ed, 0x5733f50, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 534, 47),
    (0x42fd4fc, 0x57358b0, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f636f72652f7372632f697465722f61646170746572732f656e756d65726174652e7273'), 82, 9),
]
CALLERS = [0x4d1d07b, 0x4d1eeab]
CALLER_FUNCTIONS = {'0x4d1d07b': ('0x4d1c1c0', '0x4d1dfe3'), '0x4d1eeab': ('0x4d1dff0', '0x4d1fe13')}
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

