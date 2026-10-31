#!/usr/bin/env python3
"""Authenticated node94 vault-rebalance-body binding (0x395bdd0).

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

START, END = 0x395bdd0, 0x395cd78
FDE_VA = 0x11c78d8
FDE = bytes.fromhex(
    '50000000b09c2000f0447902a80f000004471090ff410e10420e18420e20420e'
    '28420e30410e38470e800383078c068d058e048f038602036f050e38410e3042'
    '0e28420e20420e18420e10410e08410e80030000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ec480100004c898424080100004989cf660f2944'
    '241048895424384989f648897c24204d8b21498b4108498b49104c89a4248000'
    '00004889842400010000488984248800000048898c24f800000048898c249000'
    '00004881c684000000488dbc24800000004889742460e835a0ffff41833e024c'
    '897c24684c896424780f827d0200004d8b4e084d8b6e184d85c90f95c14d85ed'
    '0f95c220ca80fa010f855e020000498b6e104531ff4c8d642440660f1f440000'
    'f6c1010f848e0e00004d85ff7422410fb78fe60000004839cd0f83c10000004c'
    '89f94889eae9d9000000660f1f4400004885ed0f848d0000004889e94d89cf48'
    '83e1070f84c501000031d20f1f4400004d8bbfe800000048ffc24839d175f148'
    '89ee4829d64883fd0872430f1f440000498b8fe8000000488b89e8000000488b'
    '89e8000000488b89e8000000488b89e8000000488b89e8000000488b89e80000'
    '004c8bb9e80000004883c6f875c231ed4531c9410fb78fe60000004839cd0f82'
    '5bffffffeb1a31ed4d89cf4531c9410fb78fe60000004839cd0f8240ffffff90'
    '498b0f4885c90f848e04000049ffc1410fb797e40000004989cf663b91e60000'
    '0073dd4889c34d85c90f8491000000488d34d14881c6f00000004c89cf4883e7'
    '070f84d90000004531c0660f1f4400004c8b3e498db7e800000049ffc04c39c7'
    '75ee4c89cf4c29c74983f90872436690488b06488b80e8000000488b80e80000'
    '00488b80e8000000488b80e8000000488b80e8000000488b80e80000004c8bb8'
    'e8000000498db7e80000004883c7f875bf31edeb1266662e0f1f840000000000'
    '488d6a014989cf488d04928b548118895424500f104481080f29442440488dbc'
    '24800000004c89e6e8239effff4889d94801c1704b4889c8b10141b900000000'
    '49ffcd660f284424100f8511feffffeb616666666666662e0f1f840000000000'
    '4c89cf4983f9087288e942ffffff4889ee4883fd080f8355feffffe98efeffff'
    '48c1f93f48be00000000000000804831f14801c3480f40d931ff488d351719db'
    '01ff15b970e1014889d8eb8c660f28442410f2480f2ac8f20f118c24f0000000'
    'f20f59c166480f7ec149bfffffffffffffff7f4c21f9660f57c948baffffffff'
    'ffffef7f4839d17f2ef20f101597eb8afc660f2ed07710660f2e05c1e68afc77'
    '06660f28c8eb10f20f5fd0f20f100dade68afcf20f5dcaf2480f2cc9660f2e0d'
    '74e18afc490f47cf31d2660f2ec9480f4bd14889c34829d348894424700f80e8'
    '0100004889c14829d948895c24280f800f02000048894c24084c897424304d8b'
    '76504d85f60f8426010000488b442430488b6858498db618020000410fb786f6'
    '0200004d8d7ed8488904248d0485000000004c8d248049c7c5ffffffff0f1f00'
    '4d85e4744b488d5e14ba14000000488b7c2438ff159f22e10148984885c00f98'
    'c10f9fc028c84983c73049ffc54983c4ec4889de3c0174c80fb6c085c07515eb'
    '2a6666666666662e0f1f8400000000004c8b2c244883ed010f82930000004f8b'
    'b4eef8020000e969fffffff2410f1047f8f20f110424488b4c24608b41108984'
    '24900000000f10010f29842480000000488db424800000004c8b6c24784c89ef'
    'ff15ea83e1014889c6488b7c24084989fe4929c60f90c30f80410100004d89f4'
    '31d24d85e4490f4fd44989fc4929f4f20f1024247e2cf2480f2ad7f20f5e15ad'
    'eb8afcf20f1005c5ed8afc660f2ec2762a48b819000000000000804c8b742420'
    'eb714889fe4c8b742420660f28442410660f2ec47753e91d020000f2480f2ace'
    'f20f5e0d68eb8afc84db0f85190100004d89f4f20f5eca4c016424284c8b7424'
    '20660f284424100f803f010000f20f59c18b0571e8e10185c00f857101000066'
    '0f2ec40f86cf01000048b819000000000000804989064c89f04881c448010000'
    '5b415c415d415e415f5dc30f99c10fb6c94c01f94889c34829d3488d35b788db'
    '01480f40d931ffff15136ee101488b4424704889c14829d948895c24280f81f1'
    'fdffff0f99c10fb6c94c01f94829d8488d358288db01480f40c1488944240831'
    'ffff15d96de1014c897424304d8b76504d85f60f85d2fdffffe9f3feffff0f99'
    'c00fb6c048b9ffffffffffffff7f4801c84989fc4929f44889f5488d353788db'
    '014c0f40e031ffff15936de1014889ee488b7c2408e986feffff488d3dd7dbd8'
    '01ff155920e1010f0b4989f6488d350588db0131ff4889d3f20f114c2408f20f'
    '119424e8000000ff15536de101f20f109424e8000000f20f104c2408f20f1024'
    '244c89f64889dae9a7feffff4989f4488d352289db0131ff4889d3f20f114c24'
    '08ff15196de101f20f104c2408f20f1024244c89e64889da660f28442410f20f'
    '59c18b0500e7e10185c00f848ffeffff488d05d9e6e1014889442440488d4424'
    '404889842480000000488d3dd8e6e101488d0da1dad0014c8d0582dad0014889'
    'd3488d9424800000004989f4be01000000660f29442410ff15cb23e101f20f10'
    '24244c89e64889da660f28442410660f2ec40f8731feffff660f29442410498b'
    '074885c00f881a080000f20f10055eeb8afc660f2ec40f870dfeffff660f57c0'
    '660f285c2410660f28cbf20fc2c801f20f101501df8afcf20fc2d301660f55d3'
    '660f54d1660f55cb660f56ca660f2ec10f87d3fdfffff20f5ecc0f57c0f2480f'
    '2ac0f20f59c166480f7ec048b9ffffffffffffff7f4821c8660f57c948b9ffff'
    'ffffffffef7f4839c87f2ef20f101515e78afc660f2ed07710660f2e053fe28a'
    'fc7706660f28c8eb10f20f5fd0f20f100d2be28afcf20f5dcaf2480f2cc1660f'
    '2e0df2dc8afc48b9ffffffffffffff7f480f47c131db660f2ec9480f4bd88b05'
    'a4e5e10185c00f851105000049bc19000000000000804885db0f886405000048'
    '89542428488b4c24608b4110894424500f10010f294424404531ff4885f64c0f'
    '4ffe8b4110898424900000000f10010f2984248000000048893424488db42480'
    '0000004c89efff150480e101483904247e1f66c784248000000033004d892648'
    '8dbc2480000000e8f4d00300e9c5fcffff48895c2408488d7424404c89ef4c89'
    'faff154183e101498b9d380200004889d84c29f80f80d1040000488b5c243066'
    '0f2844241049898538020000f20f598424f000000066480f7ec048b9ffffffff'
    'ffffff7f4821c8660f28d0660f57c048b9ffffffffffffef7f4839c87f2cf20f'
    '100dc2e58afc660f2eca660f28c2770a660f2e05e8e08afc7610f20f5fc8f20f'
    '1005dae08afcf20f5dc1f2480f2cc0660f2e05a1db8afc48b9ffffffffffffff'
    '7f480f47c131d2660f2ec0480f4bd0498d4424e74839c20f841c06000048f7da'
    '4c89ac2480000000488b8424000100004889842488000000488b8424f8000000'
    '48898424900000004c8d8c24800000004889df488b742438488b4c24704c8b84'
    '2408010000e826dbffff4c8b73504d85f60f84b5050000488b4424304c8b7858'
    '498db618020000410fb786f6020000498d5ee048894424108d04850000000048'
    '8d2c8049c7c4ffffffff660f1f4400004885ed743c4c8d6e14ba14000000488b'
    '7c2438ff158f1ce10148984885c00f98c10f9fc028c84883c33049ffc44883c5'
    'ec4c89ee3c0174c80fb6c085c07507eb1c4c8b6424104983ef010f822c050000'
    '4f8bb4e6f8020000e973ffffff4c8b73f84c2b742408488b6c247849bfffffff'
    'ffffffff7f7312488d35ba84db014531f631ffff152769e101488b14244c8973'
    'f84989d64c2b7424080f802d030000f2490f2ac6488b4c2430f20f5941686648'
    '0f7ec04c21f8660f57c948beffffffffffffef7f4839f07f2ef20f101507e48a'
    'fc660f2ed07710660f2e0531df8afc7706660f28c8eb10f20f5fd0f20f100d1d'
    'df8afcf20f5dcaf24c0f2ce1660f2e0de4d98afc4d0f47e74531ed660f2ec94d'
    '0f4ae54d85e44d0f4fec7e4f8b81a800000089842490000000660f1081980000'
    '00660f29842480000000488db424800000004889ef4c89eae8c32bdaff4c8bb5'
    '380200004c89f04c01e80f80b803000048898538020000488b14244989d74d29'
    'ef4c896424100f807d0200004531e44d85ff4d0f4fe7488b4c24388b41108984'
    '24900000000f10010f29842480000000488db424800000004889ef4c89e2e85d'
    '2bdaff4c8bb5380200004c89f04c01e00f80640200004c8b642468488b542428'
    '488985380200004c8b334c89f04c29f8488b34240f806f0200004c8b74242048'
    '8903488b4c24608b4110898424200100000f10010f298424100100004c89e348'
    '29f30f807b020000f2490f2aecf20f101d5be48afcf2490f2ae54889d84829d0'
    '0f809302000048be1900000000000080488b4c2410f20f5eebf20f5ee30f57c0'
    'f2480f2ac0f20f5ec30f57c9f2480f2a4c24080f57d2f2490f2ad7f20f5ecbf2'
    '0f5ed34889f04885c97e27488b4c24308b81a800000089842440010000660f10'
    '9998000000660f299c2430010000488d46ee488b5424388b4a1041894e540f10'
    '1a410f115e444883c6ec498936f2410f116e08f2410f116610f2410f114618f2'
    '410f114e20f2410f1156280f28842410010000410f1146308b8c242001000041'
    '894e404d89beb0000000498986b8000000f2410f11a6c00000000f2884243001'
    '0000410f1186c80000008b842440010000418986d8000000e939f8ffff488d05'
    '6ce0e1014889442440488d4424404889842480000000488d3d6be0e101488d0d'
    '34d4d0014c8d0515d4d0014989dc4889d3488d9424800000004989f7be010000'
    '00ff15611de1014c89fe4889da4c89e349bc19000000000000804885db0f899c'
    'faffff4d8926e9cbf7ffff0f99c00fb6c048b9ffffffffffffff7f4801c84c29'
    'fb488d356051d901480f40d831ffff15ec65e1014889d8e9fefaffff0f99c00f'
    'b6c04c01f84989d64c2b742408488d356480db014c0f40f031ffff15c065e101'
    '488b1424e9a6fcffff0f99c00fb6c048b9ffffffffffffff7f4801c84989d74d'
    '29ef488d352f80db014c0f40f831ffff158b65e101e952fdffff48c1f83f48b9'
    '00000000000000804831c14d01e6488d352b50d9014c0f40f131ffff155f65e1'
    '014c89f0e96dfdffff0f99c00fb6c048b9ffffffffffffff7f4801c84d29fe48'
    '8d35d27fdb014c0f40f031ffff152e65e101488b3424488b5424284c89f0e957'
    'fdffff0f99c00fb6c048b9ffffffffffffff7f4801c84c89e34829f3488d3595'
    '7fdb01480f40d831ffff15f164e101488b542428e94ffdffff0f99c00fb6c048'
    'b9ffffffffffffff7f4801c84829d3488d35627fdb01480f40d831fff20f1124'
    '24f20f116c2420ff15b364e101f20f101d7be18afcf20f106c2420f20f102424'
    '4889d8e91efdffff48c1f83f48b900000000000000804831c14d01ee488d353d'
    '4fd9014c0f40f131ffff157164e1014c89f0e919fcffff488d3df2bdd801ff15'
    '3c17e101488d3d27cbc5fc488d0dee81db014c8d05c77edb01488d9424800000'
    '00be2b000000ff15ec12e101488d3de50cdb01ff150717e101488d3de80adb01'
    'ff15c21de1010f0b'
)
BODY_SHA256 = 'e2316aca2ffe6c9c1c221e30a8ce3197fc5f130eb92adfc2ff54280a4d203ee8'
BRANCHES = [
    (0x89, '0f827d020000', 2, 6, 0x395c0dc),
    (0xa8, '0f855e020000', 2, 6, 0x395c0dc),
    (0xc3, '0f848e0e0000', 2, 6, 0x395cd27),
    (0xcc, '7422', 1, 2, 0x395bec0),
    (0xd9, '0f83c1000000', 2, 6, 0x395bf70),
    (0xe5, 'e9d9000000', 1, 5, 0x395bf93),
    (0xf3, '0f848d000000', 2, 6, 0x395bf56),
    (0x103, '0f84c5010000', 2, 6, 0x395c09e),
    (0x11d, '75f1', 1, 2, 0x395bee0),
    (0x129, '7243', 1, 2, 0x395bf3e),
    (0x16c, '75c2', 1, 2, 0x395bf00),
    (0x17e, '0f825bffffff', 2, 6, 0x395beaf),
    (0x184, 'eb1a', 1, 2, 0x395bf70),
    (0x199, '0f8240ffffff', 2, 6, 0x395beaf),
    (0x1a6, '0f848e040000', 2, 6, 0x395c40a),
    (0x1c1, '73dd', 1, 2, 0x395bf70),
    (0x1c9, '0f8491000000', 2, 6, 0x395c030),
    (0x1e1, '0f84d9000000', 2, 6, 0x395c090),
    (0x200, '75ee', 1, 2, 0x395bfc0),
    (0x20c, '7243', 1, 2, 0x395c021),
    (0x24f, '75bf', 1, 2, 0x395bfe0),
    (0x253, 'eb12', 1, 2, 0x395c037),
    (0x293, '704b', 1, 2, 0x395c0b0),
    (0x2a9, '0f8511feffff', 2, 6, 0x395be90),
    (0x2af, 'eb61', 1, 2, 0x395c0e2),
    (0x2c7, '7288', 1, 2, 0x395c021),
    (0x2c9, 'e942ffffff', 1, 5, 0x395bfe0),
    (0x2d5, '0f8355feffff', 2, 6, 0x395bf00),
    (0x2db, 'e98efeffff', 1, 5, 0x395bf3e),
    (0x30a, 'eb8c', 1, 2, 0x395c068),
    (0x347, '7f2e', 1, 2, 0x395c147),
    (0x355, '7710', 1, 2, 0x395c137),
    (0x35f, '7706', 1, 2, 0x395c137),
    (0x365, 'eb10', 1, 2, 0x395c147),
    (0x39d, '0f80e8010000', 2, 6, 0x395c35b),
    (0x3ae, '0f800f020000', 2, 6, 0x395c393),
    (0x3c5, '0f8426010000', 2, 6, 0x395c2c1),
    (0x403, '744b', 1, 2, 0x395c220),
    (0x436, '74c8', 1, 2, 0x395c1d0),
    (0x43d, '7515', 1, 2, 0x395c224),
    (0x43f, 'eb2a', 1, 2, 0x395c23b),
    (0x458, '0f8293000000', 2, 6, 0x395c2c1),
    (0x466, 'e969ffffff', 1, 5, 0x395c1a4),
    (0x4b7, '0f8041010000', 2, 6, 0x395c3ce),
    (0x4d4, '7e2c', 1, 2, 0x395c2d2),
    (0x4ef, '762a', 1, 2, 0x395c2eb),
    (0x500, 'eb71', 1, 2, 0x395c343),
    (0x514, '7753', 1, 2, 0x395c339),
    (0x516, 'e91d020000', 1, 5, 0x395c508),
    (0x52a, '0f8519010000', 2, 6, 0x395c419),
    (0x547, '0f803f010000', 2, 6, 0x395c45c),
    (0x559, '0f8571010000', 2, 6, 0x395c4a0),
    (0x563, '0f86cf010000', 2, 6, 0x395c508),
    (0x5bd, '0f81f1fdffff', 2, 6, 0x395c184),
    (0x5f3, '0f85d2fdffff', 2, 6, 0x395c19b),
    (0x5f9, 'e9f3feffff', 1, 5, 0x395c2c1),
    (0x635, 'e986feffff', 1, 5, 0x395c290),
    (0x687, 'e9a7feffff', 1, 5, 0x395c303),
    (0x6ca, '0f848ffeffff', 2, 6, 0x395c32f),
    (0x732, '0f8731feffff', 2, 6, 0x395c339),
    (0x744, '0f881a080000', 2, 6, 0x395cd34),
    (0x756, '0f870dfeffff', 2, 6, 0x395c339),
    (0x790, '0f87d3fdffff', 2, 6, 0x395c339),
    (0x7c9, '7f2e', 1, 2, 0x395c5c9),
    (0x7d7, '7710', 1, 2, 0x395c5b9),
    (0x7e1, '7706', 1, 2, 0x395c5b9),
    (0x7e7, 'eb10', 1, 2, 0x395c5c9),
    (0x826, '0f8511050000', 2, 6, 0x395cb0d),
    (0x839, '0f8864050000', 2, 6, 0x395cb73),
    (0x890, '7e1f', 1, 2, 0x395c681),
    (0x8ac, 'e9c5fcffff', 1, 5, 0x395c346),
    (0x8d4, '0f80d1040000', 2, 6, 0x395cb7b),
    (0x91c, '7f2c', 1, 2, 0x395c71a),
    (0x92e, '770a', 1, 2, 0x395c70a),
    (0x938, '7610', 1, 2, 0x395c71a),
    (0x977, '0f841c060000', 2, 6, 0x395cd69),
    (0x9d1, '0f84b5050000', 2, 6, 0x395cd5c),
    (0xa13, '743c', 1, 2, 0x395c821),
    (0xa46, '74c8', 1, 2, 0x395c7e0),
    (0xa4d, '7507', 1, 2, 0x395c826),
    (0xa4f, 'eb1c', 1, 2, 0x395c83d),
    (0xa5a, '0f822c050000', 2, 6, 0x395cd5c),
    (0xa68, 'e973ffffff', 1, 5, 0x395c7b0),
    (0xa85, '7312', 1, 2, 0x395c869),
    (0xaa9, '0f802d030000', 2, 6, 0x395cbac),
    (0xad7, '7f2e', 1, 2, 0x395c8d7),
    (0xae5, '7710', 1, 2, 0x395c8c7),
    (0xaef, '7706', 1, 2, 0x395c8c7),
    (0xaf5, 'eb10', 1, 2, 0x395c8d7),
    (0xb2a, '7e4f', 1, 2, 0x395c94b),
    (0xb6a, '0f80b8030000', 2, 6, 0x395ccf8),
    (0xb86, '0f807d020000', 2, 6, 0x395cbd9),
    (0xbd0, '0f8064020000', 2, 6, 0x395cc0a),
    (0xbf4, '0f806f020000', 2, 6, 0x395cc39),
    (0xc22, '0f807b020000', 2, 6, 0x395cc73),
    (0xc40, '0f8093020000', 2, 6, 0x395cca9),
    (0xc89, '7e27', 1, 2, 0x395ca82),
    (0xd38, 'e939f8ffff', 1, 5, 0x395c346),
    (0xd9d, '0f899cfaffff', 2, 6, 0x395c60f),
    (0xda6, 'e9cbf7ffff', 1, 5, 0x395c346),
    (0xdd7, 'e9fefaffff', 1, 5, 0x395c6aa),
    (0xe04, 'e9a6fcffff', 1, 5, 0x395c87f),
    (0xe35, 'e952fdffff', 1, 5, 0x395c95c),
    (0xe64, 'e96dfdffff', 1, 5, 0x395c9a6),
    (0xe9e, 'e957fdffff', 1, 5, 0x395c9ca),
    (0xed4, 'e94ffdffff', 1, 5, 0x395c9f8),
    (0xf23, 'e91efdffff', 1, 5, 0x395ca16),
    (0xf52, 'e919fcffff', 1, 5, 0x395c940),
]
DIRECT_CALLS = [
    (0x395be46, 0x3955e80),
    (0x395c058, 0x3955e80),
    (0x395c677, 0x3999770),
    (0x395c795, 0x395a2c0),
    (0x395c928, 0x36ff4f0),
    (0x395c98e, 0x36ff4f0),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x395c0d1, 0x5773190),
    (0x395c1e3, 0x576e488),
    (0x395c270, 0x5774660),
    (0x395c377, 0x5773190),
    (0x395c3b1, 0x5773190),
    (0x395c3f7, 0x5773190),
    (0x395c411, 0x576e470),
    (0x395c437, 0x5773190),
    (0x395c471, 0x5773190),
    (0x395c4e7, 0x576e8b8),
    (0x395c656, 0x5774660),
    (0x395c691, 0x57749d8),
    (0x395c7f3, 0x576e488),
    (0x395c863, 0x5773190),
    (0x395cb51, 0x576e8b8),
    (0x395cb9e, 0x5773190),
    (0x395cbca, 0x5773190),
    (0x395cbff, 0x5773190),
    (0x395cc2b, 0x5773190),
    (0x395cc5c, 0x5773190),
    (0x395cc99, 0x5773190),
    (0x395ccd7, 0x5773190),
    (0x395cd19, 0x5773190),
    (0x395cd2e, 0x576e470),
    (0x395cd56, 0x576e048),
    (0x395cd63, 0x576e470),
    (0x395cd70, 0x576eb38),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x395c40a, 0x56e9fe8, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 534, 47),
    (0x395cd27, 0x56e8b20, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 161, 36),
    (0x395cd5c, 0x570da48, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f7661756c742f6d6f642e7273'), 742, 58),
]
CALLERS = []
CALLER_FUNCTIONS = {}
LEA_REFS = 0
OWN_GOT_SLOTS = ['0x5774b58']
GOT_SITES = {'0x5774b58': '0x4d469b9'}


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

