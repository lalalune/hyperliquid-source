#!/usr/bin/env python3
"""Node 94: reproduce a per-DEX book hash input from authenticated ELF bytes.

This is static evidence, not execution or a complete x86 disassembler.
Selected byte patterns and unwind extents are explicitly pinned.
"""
import argparse
import csv
import hashlib
import json
import mmap
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import fde_extents, uleb

TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# start: (exclusive FDE end, full unmasked body SHA-256, descriptive role).
FDE_PINS = {
    0x1e5ce30: (0x1e5d036, '90b5b2548a2495680922cf35b047a8eb6a181a2cf8fb7837268441670626b69e', 'low_outer'),
    0x1ddb120: (0x1ddb8cc, '39286beca0c460d4469e26b94bb7b34cda8a109b46c311d6f5d9d1f92813d757', 'low_book_list'),
    0x1e57450: (0x1e57a55, '242d11d09ec47cdeada0bd0409d786f7955ea9f73b48aa1f39f71243cfef6c94', 'low_side_generic'),
    0x1e4d020: (0x1e4d82d, 'f47af7163cbfefce05ca33dcbd49d35f68bbdd0874ae6006b98f56f634b39060', 'low_side_buffered'),
    0x1dfc1f0: (0x1dfc657, 'd634d43eeaaa6ca29f73a80360ff9727d91a2748a95a0bcdd0020e6fd7a13c85', 'low_level_generic'),
    0x1e093c0: (0x1e0983f, 'f54aac001f68df6d3e9f60be7b5dd64bf36bcde207b3a7832d1ce6a3a7661b1d', 'low_level_buffered'),
    0x26b35b0: (0x26b3886, '19d1375ae834ef211f75e65486fb5e2b1b2c284de41f9afb4e58188dbf76a9b8', 'level_capture'),
    0x4446870: (0x4446a76, '84d90e583dbd54f38408c8caf9202948e8c8e61a81e39260f482e2df9de8d753', 'shared_outer'),
    0x43c6690: (0x43c6e3c, '840e6b0d5ab070068d7fba5aeda6019323129635654019c0969dba4df88382ee', 'shared_book_list'),
    0x4439910: (0x4439f15, '24edacb8966c9f577e7a23fa7ac3617513a5edce9fc013908962ee6219d26090', 'shared_side_generic'),
    0x4442100: (0x444290d, 'a1970a62f52f4137391612c1b0b062e3aeb462687506adf8da502872f1e590a6', 'shared_side_buffered'),
    0x43dee00: (0x43df267, '1ab335b850e46e9938a99d0f507fae043349769ac4dd02ffbdb740442cab96ec', 'shared_level_generic'),
    0x43ebe70: (0x43ec2ef, '6f466deea0e0a78737fa0d7f09f1e63de7ff17610431cdd1ac65956c52105ce8', 'shared_level_buffered'),
    0x49e7b60: (0x49e7f4f, 'c4138fb7027ffa77e9d4f5b9e78336952aaf740fe7779ebcda5a4dfab897abc3', 'shared_order_buffered'),
    0x4abb100: (0x4abb1ae, '0208faf4924f404a74160a790ea60f1703051aaee1e575c362351e17d06391a1', 'shared_core_label'),
    0x49e6da0: (0x49e72cd, '837c52326b6ffa781aae2a9261b06626c4ce0b4c6ffddd6eb3087608693393cd', 'shared_core'),
    0x4abb600: (0x4abb951, 'cf0c0b829c59dc57b89c416c4e73252c84d3d1ceb3fbace5c653a9bad781a1b8', 'shared_core_R'),
    0x4aba330: (0x4abab0b, '305cf8b642a018f8940e0dfaae0deb7149dc8ea8ab62381f31777c66506c9ca9', 'shared_core_d'),
    0x4abb380: (0x4abb4c0, 'd86b273f3639e14d9a9bb0f6ba0e531712ef54c9661ddc4d1324c9fb3a5aec46', 'shared_core_c'),
    0x4abc300: (0x4abc4f4, '15c3e8c0fdf5f02bc86875183034a95943e6459b09f033ce7c278bff9f82e455', 'shared_core_side'),
}
PAIRS = {
    'outer': (0x1e5ce30, 0x4446870),
    'book_list': (0x1ddb120, 0x43c6690),
    'side_generic': (0x1e57450, 0x4439910),
    'side_buffer': (0x1e4d020, 0x4442100),
    'level_generic': (0x1dfc1f0, 0x43dee00),
    'level_buffer': (0x1e093c0, 0x43ebe70),
}

# The following byte patterns were selected by bounded instruction inspection;
# the extractor reads and validates them, not a disassembler's text output.
BRANCH_PINS = (
    ('outer', 0x3f, '754a'),
    ('outer', 0x5f, '0f8542010000'),
    ('outer', 0x84, '7550'),
    ('outer', 0x9e, '0f8428010000'),
    ('outer', 0x11d, '754f'),
    ('outer', 0x126, '75d8'),
    ('outer', 0x191, '7424'),
    ('outer', 0x196, '741f'),
    ('book_list', 0x3a, '7546'),
    ('book_list', 0x5f, '746a'),
    ('book_list', 0xa1, '0f844e010000'),
    ('book_list', 0xd1, '0f85b1020000'),
    ('book_list', 0xf5, '0f8554020000'),
    ('book_list', 0x114, '7448'),
    ('book_list', 0x121, '0f8490000000'),
    ('book_list', 0x158, '0f8577050000'),
    ('book_list', 0x164, '7451'),
    ('book_list', 0x1a8, '0f8519050000'),
    ('book_list', 0x1b5, '75c9'),
    ('book_list', 0x1fb, '0f8535030000'),
    ('book_list', 0x21f, '0f8547010000'),
    ('book_list', 0x23e, '7448'),
    ('book_list', 0x24b, '0f8486000000'),
    ('book_list', 0x282, '0f856d040000'),
    ('book_list', 0x28e, '7447'),
    ('book_list', 0x2c8, '0f8500040000'),
    ('book_list', 0x2d5, '75c9'),
    ('book_list', 0x31f, '0f85ea030000'),
    ('book_list', 0x32c, '0f8433040000'),
    ('book_list', 0x39c, '0f84b3030000'),
    ('side_generic', 0x20, '7521'),
    ('side_generic', 0x3d, '0f84e0010000'),
    ('side_generic', 0x4d, '754f'),
    ('side_generic', 0x67, '0f85be000000'),
    ('side_generic', 0xb6, '0f85ac000000'),
    ('side_generic', 0x10f, '747b'),
    ('side_generic', 0x192, '0f85b4000000'),
    ('side_generic', 0x1ae, '0f8550020000'),
    ('side_generic', 0x1dc, '0f84cb000000'),
    ('side_generic', 0x1e5, '0f8409010000'),
    ('side_generic', 0x210, '0f8497000000'),
    ('side_generic', 0x2b7, '743b'),
    ('side_generic', 0x2e5, '0f8560020000'),
    ('side_generic', 0x2f2, '75dc'),
    ('side_generic', 0x331, '0f8565020000'),
    ('side_generic', 0x363, '741a'),
    ('side_generic', 0x385, '0f859c000000'),
    ('side_generic', 0x3a1, '7561'),
    ('side_generic', 0x3cb, '0f84b7000000'),
    ('side_generic', 0x3dc, '0f84f2000000'),
    ('side_generic', 0x3f9, '0f8517feffff'),
    ('side_generic', 0x435, '0f848c010000'),
    ('side_generic', 0x49a, '7438'),
    ('side_generic', 0x4c5, '0f8580000000'),
    ('side_generic', 0x4d2, '75dc'),
    ('side_generic', 0x503, '0f8593000000'),
    ('side_generic', 0x588, '7412'),
    ('side_generic', 0x58d, '740d'),
    ('side_buffer', 0x1b, '7521'),
    ('side_buffer', 0x38, '0f84df010000'),
    ('side_buffer', 0x43, '7568'),
    ('side_buffer', 0x63, '0f857c010000'),
    ('side_buffer', 0xb4, '0f84da060000'),
    ('side_buffer', 0x12e, '741a'),
    ('side_buffer', 0x150, '0f85f0000000'),
    ('side_buffer', 0x16f, '0f85d9030000'),
    ('side_buffer', 0x19d, '0f8403010000'),
    ('side_buffer', 0x1a6, '0f845c010000'),
    ('side_buffer', 0x1d2, '0f84ce000000'),
    ('side_buffer', 0x254, '0f8470050000'),
    ('side_buffer', 0x2b0, '7456'),
    ('side_buffer', 0x2c3, '0f85d5000000'),
    ('level_generic', 0x29, '0f818b000000'),
    ('level_generic', 0x53, '0f8597000000'),
    ('level_generic', 0x72, '757c'),
    ('level_generic', 0x97, '747f'),
    ('level_generic', 0xd3, '7530'),
    ('level_generic', 0xdc, '0f842b030000'),
    ('level_generic', 0x11e, '0f8596000000'),
    ('level_generic', 0x13f, '755a'),
    ('level_generic', 0x15b, '0f84ba000000'),
    ('level_generic', 0x16c, '0f84c9010000'),
    ('level_generic', 0x18b, '0f848a000000'),
    ('level_generic', 0x1c8, '0f845b020000'),
    ('level_generic', 0x22c, '0f8409010000'),
    ('level_generic', 0x26e, '0f8532010000'),
    ('level_generic', 0x27d, '75d1'),
    ('level_generic', 0x293, '7515'),
    ('level_generic', 0x2a8, '7465'),
    ('level_generic', 0x2c1, '7520'),
    ('level_generic', 0x2ca, '0f844a010000'),
    ('level_buffer', 0x20, '751f'),
    ('level_buffer', 0x3d, '741e'),
    ('level_buffer', 0x48, '0f84c3030000'),
    ('level_buffer', 0x76, '7537'),
    ('level_buffer', 0x94, '743d'),
    ('level_buffer', 0xd9, '0f85b4000000'),
    ('level_buffer', 0xf8, '7570'),
    ('level_buffer', 0x11d, '0f84d1000000'),
    ('level_buffer', 0x126, '0f842c010000'),
    ('level_buffer', 0x152, '0f849c000000'),
    ('level_buffer', 0x1a1, '0f849a020000'),
    ('level_buffer', 0x1fe, '7458'),
    ('level_buffer', 0x212, '0f85be000000'),
    ('level_buffer', 0x249, '0f854c010000'),
    ('level_buffer', 0x256, '75d8'),
    ('level_buffer', 0x298, '0f8548010000'),
    ('level_buffer', 0x2ea, '7534'),
    ('level_buffer', 0x30b, '0f858a000000'),
    ('level_buffer', 0x318, '753d'),
    ('level_buffer', 0x335, '7539'),
    ('level_buffer', 0x33e, '0f84ee000000'),
    ('level_buffer', 0x351, '0f8401ffffff'),
    ('level_buffer', 0x369, '75b5'),
    ('level_buffer', 0x395, '0f8476ffffff'),
    ('level_buffer', 0x3d2, '7412'),
    ('level_buffer', 0x3d7, '740d'),
    ('level_buffer', 0x468, '740d'),
    ('single', 0x26b35d0, '0f845c020000'),
    ('single', 0x26b3603, '0f844e020000'),
    ('single', 0x26b360c, '7422'),
    ('single', 0x26b3618, '0f83c2000000'),
    ('single', 0x26b36ea, '0f8458010000'),
    ('single', 0x26b3810, '0f85eafdffff'),
    ('single', 0x49e7b8c, '0f8489020000'),
    ('single', 0x49e7bae, '7539'),
    ('single', 0x49e7bb3, '0f84a7020000'),
    ('single', 0x49e7bcc, '0f86b9020000'),
    ('single', 0x49e7bec, '0f844d020000'),
    ('single', 0x49e7c13, '7543'),
    ('single', 0x49e7c1b, '0f8492020000'),
    ('single', 0x49e7c34, '0f86a4020000'),
    ('single', 0x49e7c7b, '0f85df000000'),
    ('single', 0x49e7c86, '7543'),
    ('single', 0x49e7c92, '0f846e020000'),
    ('single', 0x49e7cae, '0f8676020000'),
    ('single', 0x49e7ce5, '7579'),
    ('single', 0x49e7cec, '751a'),
    ('single', 0x49e7d06, '756e'),
    ('single', 0x49e7d1e, '7569'),
    ('single', 0x49e7d25, '741a'),
    ('single', 0x49e7d3f, '7535'),
    ('single', 0x49e7d48, '7569'),
    ('single', 0x49e7d5c, '752b'),
    ('single', 0x49e7dc5, '75c2'),
    ('single', 0x49e7ddd, '7529'),
    ('single', 0x49e7e01, '7505'),
    ('single', 0x4abb10c, '7535'),
    ('single', 0x4abb118, '7439'),
    ('single', 0x4abb131, '764d'),
    ('single', 0x49e6e26, '741a'),
    ('single', 0x49e6e3b, '741e'),
    ('single', 0x49e6e55, '0f8508010000'),
    ('single', 0x49e6e5e, '7456'),
    ('single', 0x49e6e65, '7533'),
    ('single', 0x49e6e71, '0f84ce020000'),
    ('single', 0x49e6e89, '0f84da020000'),
    ('single', 0x49e6eb0, '0f85ad000000'),
    ('single', 0x49e6ec3, '7457'),
    ('single', 0x49e6eca, '7433'),
    ('single', 0x49e6ed6, '0f84b5020000'),
    ('single', 0x49e6eee, '0f84c1020000'),
    ('single', 0x49e6f1f, '0f848c000000'),
    ('single', 0x49e6f2a, '745f'),
    ('single', 0x49e6f36, '0f84a1020000'),
    ('single', 0x49e6f4f, '0f84af020000'),
    ('single', 0x49e6f92, '0f8489010000'),
    ('single', 0x49e6fb9, '7419'),
    ('single', 0x49e6fce, '0f8513010000'),
    ('single', 0x49e6fd7, '741c'),
    ('single', 0x49e6fef, '0f85f2000000'),
    ('single', 0x49e6ffa, '741c'),
    ('single', 0x49e7012, '0f85cf000000'),
    ('single', 0x49e701d, '744f'),
    ('single', 0x49e7024, '7533'),
    ('single', 0x49e7030, '0f84f3010000'),
    ('single', 0x49e7048, '0f84ff010000'),
    ('single', 0x49e706c, '7579'),
    ('single', 0x49e7085, '7560'),
    ('single', 0x49e7093, '7433'),
    ('single', 0x49e709f, '0f84d0010000'),
    ('single', 0x49e70b7, '0f84e2010000'),
    ('single', 0x49e70db, '752e'),
    ('single', 0x4abb61b, '743a'),
    ('single', 0x4abb627, '0f84d4010000'),
    ('single', 0x4abb63f, '0f84e0010000'),
    ('single', 0x4aba33f, '7445'),
    ('single', 0x4aba34b, '0f84f5020000'),
    ('single', 0x4aba364, '0f841d030000'),
    ('single', 0x4abb393, '7433'),
    ('single', 0x4abb39f, '0f84a2000000'),
    ('single', 0x4abb3b7, '0f84b4000000'),
    ('single', 0x4abc309, '7433'),
    ('single', 0x4abc315, '0f849c000000'),
    ('single', 0x4abc32d, '0f84bb000000'),
    ('single', 0x4abc341, '742e'),
    ('single', 0x4abc34d, '0f84d3000000'),
    ('single', 0x4abc365, '0f84ee000000'),
    ('single', 0x4abc37b, '0f840c010000'),
)

WINDOW_PINS = (
    ('context_dex_vector', 0x2755f9f, '498b8424783300004885c00f8417020000488b8c24080200004c8bb9703300004869c0380100004c01f8'),
    ('context_book_array', 0x2756013, '498b5f104885db0f84a00000004d8b77084889d848c1e0044c8d2c40'),
    ('context_book_capture', 0x2756060, '498db6800000004889ef4c89f2e87e15c4ff660f10842450030000660f108c2460030000660f1094247003000066410f1154242066410f114c241066410f11042449ffc54983c4304981c6d80000004c39eb75ac'),
    ('context_capture_side_first', 0x23976ec, '488d7c2450488d742420e8b5be3100'),
    ('context_capture_side_second', 0x23977ed, '488d7c2450488d742420e8b4bd3100'),
    ('context_second_tree', 0x239771f, '498b4e18498b562031f64889cd4885c9400f95c67404498b6e28'),
    ('context_low_closure', 0x28198ef, '488dbc2408010000488d742420e82f3564ff4c8bb4240801000048b804000000000000804939c60f85f6000000'),
    ('context_shared_closure', 0x4ae4cdf, '488dbc2408010000488d742420e87f1b96ff4c8bb4240801000048b804000000000000804939c60f85f6000000'),
    ('context_low_marker', 0x25a9bde, '81fa000001000f92c034dd83fa100fb6c0bd900000000f43e8'),
    ('context_shared_marker', 0x4aea42e, '81fa000001000f92c034dd83fa100fb6c0bd900000000f43e8'),
    ('context_low_marker_or', 0x25acc63, '4080e60f4080ce'),
    ('context_shared_marker_or', 0x4aed5e3, '4080e60f4080ce'),
    ('capture_input', 0x26b35be, '4c8b6f40488b06488904244c8b66084d85ed0f845c020000488b474848894424084c8b7e100fb60f4c8b7718488b4710488b5f08'),
    ('capture_bad_parent', 0x26b36e0, '488b8b600100004885c90f845801000048ffc00fb793c00100004889cb663b91c201000073da'),
    ('capture_record', 0x26b37a7, '488bacd16801000048c1e2050f1004110f29442410488b4424084889442420488d7c2430488d742410e8fb49ebff49ffcd4889e848f7d8480f48c548894424284c89e048c1e0050f10442438410f114407100f10442428410f11040749ffc4b101'),
    ('outer_size_gate', 0x1e5ce60, '4c8b6a084c8b72104c89f048c1e820754a488d7c24504c8d7c24404c89fe4489f2e84acd7400488b4424504883f8020f8542010000'),
    ('outer_loop', 0x1e5cf06, '49c1e6034b8d2c764531e44c8d7424504c8d7c241048b80000000000000080488d58040f1f80000000004b8b5425084b8b4c25104c89f74c89fee8dbe1f7ff488b4424504839d8754f4983c4184c39e575d8'),
    ('book_list_size', 0x1ddb160, '4889c848c1e004488d2c404889c848c1e8200f94c241807f0c000f95c320d3746a4885c941bc300000004c0f44e14c89f0480f44c148898424b00000004d01f4eb554889c848c1e004488d2c404889c848c1e8200f94c241807f1c000f95c320d30f844e0100004885c941bc300000004c0f44e14c89f0480f44c148898424b00000004d01f4e936010000'),
    ('book_list_loop', 0x1ddb247, '488d15636860fe488dbc2480000000b9070000004c89fee8edc10700488b84248000000048b904000000000000804839c80f85770500004901ee4d39f47451488d1d246860fe4c8d6c246066666666662e0f1f840000000000b9070000004c89ef4c89fe4889da4d89e0e89ac10700488b44246048b904000000000000804839c80f85190500004983c4304d39f475c9'),
    ('side_first_input', 0x1e5753b, '488b8424a80000004c8b78084c8b60104c89e048c1e8200f94c141807e0c000f95c320cb747b4531ed4d85e4410f95c54c89fd490f44ec41c1e5054d01fd'),
    ('side_first_loop', 0x1e576fd, '49c1e4054d01e74d39fd743b4989e4488d6c244848b80000000000000080488d5804904c89e74889ee4c89eae8c24afaff488b04244839d80f85600200004983c5204d39fd75dc'),
    ('side_second_input', 0x1e5778f, '488b8424a8000000488b68204c8b78284c89f848c1e8200f94c141807e0c000f95c320cb741a4531e44d85ff410f95c44989ed4d0f44ef41c1e4054901ec'),
    ('side_second_loop', 0x1e578e0, '49c1e7054c01fd4939ec74384989e74c8d6c24486666662e0f1f8400000000004c89ff4c89ee4c89e2e8e248faff488b04244839d80f85800000004983c4204939ec75dc'),
    ('level_fields', 0x1dfc249, '498b17488d7c24104c89f6e877fe7a00488b4424104883f802757c4d8b6f10498b57184889d048c1e8200f94c141807e0c00410f95c44120cc4889542408'),
    ('level_order_loop', 0x1dfc440, '488dbc24900000004c89fe4c89e2e81d705300488b8424900000004c39e80f85320100004983c7384c3b7c240875d1'),
    ('level_buffered_child', 0x1dfc49a, '488d7c24104c89fe488d542448e8347353004c396424107520'),
    ('shared_record_header', 0x49e7b75, '0fb66a1b4c8b62104080f50140c0e5044080cd874c39220f8489020000498b460842882c2049ffc44d896610410fb66f35'),
    ('shared_bool_marker', 0x49e7be9, '4c39e60f844d0200004080cdc2400fb6fde8a1591000498b4e084288042149ffc44d896610'),
    ('shared_resting_key', 0x49e7c3a, '48b872657374696e675f4a8904216642c7442108737a4983c40a4d896610'),
    ('shared_orig_key', 0x49e7cb4, 'c7443103675f737ac704316f7269674883c60749897610498b5708488d7c24084c89f6e8e4491000488b4424084883f8027579'),
    ('shared_user_field', 0x49e7d08, '498d7720488d7c24084c89f2e837edbbff4c396424087569'),
    ('shared_tif_selector', 0x49e7d41, '498d7734803e057569488d7c24084c89f6e869d9a4ff4c39642408752b'),
    ('shared_core_and_oid', 0x49e7dc7, '498b5718488d7c24084c89f6e828330d004c3964240875294d8b4710488d1535c3d1fb488d7c2408b9030000004c89f6e874320d004c3964240875054c8923'),
    ('core_label', 0x4abb108, '807e1b017535488b0b488b73104839f174394c8b430841c60430a448ffc6488973104829f14883f903764d41c70430636f72654883c604488973104889d64889da5b415e415fe94dbcf2ff'),
    ('core_count_operands', 0x49e6db9, '4c8bae880000004c8b26488b461048837e40000fb6ae900000000f95c1488b5e2008c308cb488b56700fb6b6910000004983fd01b80300000083d8004401e001e848895424304883fa0183d8ff498b5748488954242048897424288d0c320fb6d383e20101ca01c241807e1b00'),
    ('core_t_s_gates', 0x49e6e5b, '4d85ed745641807e1b017533498b06498b76104839f00f84ce020000498b4e08c60431a148ffc6498976104839f00f84da020000c604317448ffc6498976104889e74c89f64c89eae818581000488b04244883f8020f85ad0000004584e449bc0400000000000080'),
    ('core_optional_calls', 0x49e6fb1, 'f6c301488b5c24307419498d57104889e74c89f6e836460d004c3924240f85130100004885db741c498b4f784889e74c89f64889dae845330d004c3924240f85f2000000807c242800741c498d97910000004889e74c89f6e872430d004c3924240f85cf000000807c242000744f'),
    ('core_side_last_fields', 0x49e706e, '410fb697a20000004889e74c89f6e87f520d004c3924247560498b978000000041807e1b007433498b06498b76104839f00f84d0010000498b4e08c60431a148ffc6498976104839f00f84e2010000c604316c48ffc6498976104889e74c89f6e8ed551000488b04244883f802752e'),
    ('core_R_name', 0x4abb617, '807e1b00743a498b06498b76104839f00f84d4010000498b4e08c60431a148ffc6498976104839f00f84e0010000c6043152'),
    ('core_d_name', 0x4aba33b, '807e1b0074454c8b0e488b46104939c10f84f50200004c8b460841c60400a148ffc0488946104939c10f841d03000041c6040064'),
    ('core_c_name', 0x4abb38f, '807e1b007433498b06498b76104839f00f84a2000000498b4e08c60431a148ffc6498976104839f00f84b4000000c6043163'),
    ('core_side_name_and_select', 0x4abc305, '807e1b0074334c8b0e488b46104939c10f849c000000488b4e08c60401a148ffc0488946104939c10f84bb000000c604017348ffc048894610f6c201742e4c8b0e488b46104939c10f84d3000000488b4e08c60401a148ffc0488946104939c10f84ee000000c6040141eb2c'),
    ('core_side_b_value', 0x4abc371, '4c8b0e488b46104939c10f840c010000488b4e08c60401a148ffc0488946104939c10f8427010000c6040142'),
)

TRANSFER_PINS = (
    ('outer', 0x51, 0x25a9bd0, 0x4aea420),
    ('outer', 0x110, 0x1ddb120, 0x43c6690),
    ('outer', 0x167, 0x1dd1db0, 0x43b7430),
    ('book_list', 0xe4, 0x25a9bd0, 0x4aea420),
    ('book_list', 0x13e, 0x1e57450, 0x4439910),
    ('book_list', 0x191, 0x1e57450, 0x4439910),
    ('book_list', 0x1eb, 0x1dd1db0, 0x43b7430),
    ('book_list', 0x20e, 0x25a9aa0, 0x4aea6f0),
    ('book_list', 0x268, 0x1e4d020, 0x4442100),
    ('book_list', 0x2b1, 0x1e4d020, 0x4442100),
    ('book_list', 0x30b, 0x1dd1c70, 0x43b75f0),
    ('side_generic', 0x5a, 0x25a9bd0, 0x4aea420),
    ('side_generic', 0xa9, 0x25a9bd0, 0x4aea420),
    ('side_generic', 0x1a1, 0x25a9bd0, 0x4aea420),
    ('side_generic', 0x1f6, 0x1dfc1f0, 0x43dee00),
    ('side_generic', 0x2d9, 0x1dfc1f0, 0x43dee00),
    ('side_generic', 0x319, 0x1dd1db0, 0x43b7430),
    ('side_generic', 0x394, 0x25a9bd0, 0x4aea420),
    ('side_generic', 0x3ed, 0x1dfc1f0, 0x43dee00),
    ('side_generic', 0x4b9, 0x1dfc1f0, 0x43dee00),
    ('side_generic', 0x4f9, 0x1dd1db0, 0x43b7430),
    ('side_generic', 0x541, 0x1e12bc0, 0x43fa1f0),
    ('side_buffer', 0x55, 0x25a9aa0, 0x4aea6f0),
    ('side_buffer', 0x161, 0x25a9aa0, 0x4aea6f0),
    ('side_buffer', 0x1b7, 0x1e093c0, 0x43ebe70),
    ('side_buffer', 0x2e9, 0x1e093c0, 0x43ebe70),
    ('side_buffer', 0x32f, 0x1dd1c70, 0x43b75f0),
    ('side_buffer', 0x3cb, 0x1e093c0, 0x43ebe70),
    ('side_buffer', 0x3fb, 0x1e093c0, 0x43ebe70),
    ('side_buffer', 0x4df, 0x25a9aa0, 0x4aea6f0),
    ('side_buffer', 0x536, 0x1e093c0, 0x43ebe70),
    ('side_buffer', 0x639, 0x1e093c0, 0x43ebe70),
    ('side_buffer', 0x67f, 0x1dd1c70, 0x43b75f0),
    ('side_buffer', 0x6cd, 0x1e12a80, 0x43fa0b0),
    ('level_generic', 0x45, 0x25a9bd0, 0x4aea420),
    ('level_generic', 0x64, 0x25ac0d0, 0x4aeca50),
    ('level_generic', 0xc5, 0x1e093c0, 0x43ebe70),
    ('level_generic', 0x131, 0x25a9bd0, 0x4aea420),
    ('level_generic', 0x17a, 0x2333470, 0x49e77f0),
    ('level_generic', 0x25e, 0x2333470, 0x49e77f0),
    ('level_generic', 0x2b7, 0x23337e0, 0x49e7b60),
    ('level_generic', 0x31a, 0x2333470, 0x49e77f0),
    ('level_generic', 0x363, 0x1dd1db0, 0x43b7430),
    ('level_generic', 0x39f, 0x1e12bc0, 0x43fa1f0),
    ('level_buffer', 0x2f, 0x25a9aa0, 0x4aea6f0),
    ('level_buffer', 0x68, 0x25abd40, 0x4aec6c0),
    ('level_buffer', 0xea, 0x25a9aa0, 0x4aea6f0),
    ('level_buffer', 0x137, 0x23337e0, 0x49e7b60),
    ('level_buffer', 0x239, 0x23337e0, 0x49e7b60),
    ('level_buffer', 0x280, 0x1dd1c70, 0x43b75f0),
    ('level_buffer', 0x2cc, 0x1e12a80, 0x43fa0b0),
    ('level_buffer', 0x2fb, 0x23337e0, 0x49e7b60),
    ('level_buffer', 0x32b, 0x23337e0, 0x49e7b60),
    ('single', 0x26b37d0, 0x25681d0, None),
    ('single', 0x49e7dd3, 0x4abb100, None),
    ('single', 0x49e7df7, 0x4abb070, None),
    ('single', 0x49e6fc5, 0x4abb600, None),
    ('single', 0x49e6fe6, 0x4aba330, None),
    ('single', 0x49e7009, 0x4abb380, None),
    ('single', 0x49e707c, 0x4abc300, None),
    ('single', 0x4abb14e, 0x49e6da0, None),
    ('single', 0x23976f6, 0x26b35b0, None),
    ('single', 0x23977f7, 0x26b35b0, None),
    ('single', 0x275606d, 0x23975f0, None),
    ('single', 0x28198fc, 0x1e5ce30, None),
    ('single', 0x4ae4cec, 0x4446870, None),
    ('single', 0x24c4784, 0x28198c0, None),
    ('single', 0x47c43f4, 0x4ae4cb0, None),
)

COND = ('o', 'no', 'b', 'ae', 'e', 'ne', 'be', 'a',
        's', 'ns', 'p', 'np', 'l', 'ge', 'le', 'g')
RELATIVE_TYPE = 8
TABLES = (
    ('low', 0x56bda58, 0x24c4780, 0x28198c0),
    ('shared', 0x5744708, 0x47c43f0, 0x4ae4cb0),
)
# Pinned after parsing the selected exception tables. Action bytes remain opaque.
LSDA_HASHES = {
    0x1ddb120: '02884eac1acf53aae08c5eb1df9e0619e748839275fb9849999385ecd6bd4b80',
    0x1dfc1f0: '2f713f026de1674fc2e68b001d45e180690c10595fee9f33231315961bf2f569',
    0x1e093c0: '2ec4e30c111cad1254d12538979fac891ec3b45ba271d53adb3462c835425eb6',
    0x1e4d020: 'f032477f8a40cd6c8afdd27ced474b538fc08232e324ee5c8c1c66630c0342db',
    0x1e57450: '589e0b6e998eb4c0295ed5a3f7dbb8b5ed478d8885b03ec1be249c03e7a0ef95',
    0x1e5ce30: 'cad623f0b1de3316d82686cd033151e7a34f3b9ec7fb85a702f4f58f172b101a',
    0x26b35b0: '85cb2bbd4143613183631e438bf6d4d56aceeff95b6e2d50643ab47049e437f8',
    0x43c6690: '02884eac1acf53aae08c5eb1df9e0619e748839275fb9849999385ecd6bd4b80',
    0x43dee00: '2f713f026de1674fc2e68b001d45e180690c10595fee9f33231315961bf2f569',
    0x43ebe70: '2ec4e30c111cad1254d12538979fac891ec3b45ba271d53adb3462c835425eb6',
    0x4439910: '589e0b6e998eb4c0295ed5a3f7dbb8b5ed478d8885b03ec1be249c03e7a0ef95',
    0x4442100: 'f032477f8a40cd6c8afdd27ced474b538fc08232e324ee5c8c1c66630c0342db',
    0x4446870: 'cad623f0b1de3316d82686cd033151e7a34f3b9ec7fb85a702f4f58f172b101a',
    0x4878b00: 'e840c927a898a5cc0c2408c646eece21305d596641601eb393b3f1dd6435000d',
    0x487a9f0: '1b54abf58c3ea71bca5888977c312f2eee7ed5bf8e615d7a4aa6e0cff80c56db',
    0x4a07530: '0f6db14fac1f9031b32495944a705e4bc30cb456e70607a196ceb7618949fcdf',
}


FDE_PINS.update({
    0x4878b00: (0x4878c19, 'b9e30ebe5fd85157166ff07e139dc992e5aa3a162604149033144dccd708148f', 'shared_book_capture'),
    0x4a07530: (0x4a07675, '61c66a643c6601fab6255ddbea3e25e53e627db0c5a97d3e37e75b6d93113641', 'shared_two_side_capture'),
    0x487a9f0: (0x487aff4, 'e8fad8b4a73beeab70effc5223b3d59596755d10ac92e7ae456cdf602c6793cf', 'shared_side_capture'),
})
WINDOW_PINS += (
    ('context_low_capture_box', 0x2756372, '488b8424b80000004889842460030000660f108424a8000000660f29842450030000bf18000000ff15397c01034885c048894424100f8405110000488b8c246003000048894810660f28842450030000660f1100'),
    ('context_low_vector_insert', 0x2756114, '488b8424b0000000488d0c5b488b942460030000488954c810660f28842450030000660f1104c848ffc348899c24b8000000'),
    ('context_low_descriptor_row1', 0x2756b81, '488b4c241048894b10488d0dc76ef60248894b18'),
    ('context_primary_dex', 0x4d7ea7b, '488b85f83d00004885c00f842a0100004c8ba5f03d00004c69e8380100004981c420010000'),
    ('context_primary_to_capture', 0x4d7ead5, '498bb424e8feffff49699424f0feffffd80000004801f24c89ffe80ca0afff'),
    ('context_primary_box', 0x4d7ecab, '488b4424604889842460030000660f10442450660f29842450030000bf18000000ff1506f39e004885c048894424100f8431110000488b8c246003000048894810660f28842450030000660f1100'),
    ('context_primary_descriptor_row1', 0x4d7f4a6, '488b4c241048894b10488d0d52529c0048894b18'),
    ('context_secondary_dex', 0x4d7cacb, '488b85783300004885c00f842a0100004c8ba5703300004c69e8380100004981c420010000'),
    ('context_secondary_to_capture', 0x4d7cb25, '498bb424e8feffff49699424f0feffffd80000004801f24c89ffe8bcbfafff'),
    ('context_secondary_descriptor_row1', 0x4d7d4f6, '488b4c241048894b10488d0d02729c0048894b18'),
    ('shared_book_loop', 0x4878b70, '498db7800000004c89ef4c89fae8aee918000f104424180f104c24280f10542438410f11542420410f114c2410410f11042448ffc54983c4304981c7d80000004939ee75bb'),
    ('shared_side_one', 0x4a07545, '488b06488b4e0831d24889c64885c00f95c27404498b77104889142448c744240800000000488944241048894c2418488954242048c744242800000000488944243048894c243848897424404c89742448488d7c24504889e6e84d34e7ff'),
    ('shared_side_two', 0x4a075a3, '498b4718498b4f2031d24889c64885c00f95c27404498b77284889142448c744240800000000488944241048894c2418488954242048c744242800000000488944243048894c243848897424404c89742448488d7c24684889e6e8ee33e7ff'),
    ('shared_head_guards', 0x487ac97, '488bb4d16801000048c1e205b808000000833c11010f85fefdffff488b4c1108493b4b100f83effdffff4d8b7b084869c9f800000041833c0f020f84d9fdffff'),
    ('shared_slot_loads', 0x487acf7, '4d8b7710498b47184889442440410fb6aff4000000410f1087c80000000f29442460418b87f0000000898424b0000000410f1087e00000000f298424a0000000450fb6a7f50000004d8bafd8000000'),
    ('shared_record_stores', 0x487ad5a, '4983c7200f284424600f11004c8968104c8978180f288424a00000000f1140208b8c24b0000000894830448860344088683548c744242004000000488944242848c744243001000000'),
    ('shared_next_guards', 0x487ae10, '48837c2460004c8b5c24180f84e3000000488b4c2440493b4b100f83d4000000498b6b084869c9f8000000837c0d00020f84be000000'),
    ('shared_next_loads', 0x487ae46, '4801cd488b4d1048894c2460488b4d1848894c24400fb68df4000000884c240f0f1085c80000000f298424e00000008b8df0000000898c24d00000000f1085e00000000f298424c0000000440fb6bdf50000004c8bb5d80000004c3b642420'),
    ('shared_level_store', 0x487aab0, '4531e431c949ffce4889f248f7da480f48d64c89ce48c1e6054989143249894c320849894432104d8964321849ffc1b101b8000000004d85f60f8449040000'),
    ('context_hash_rate', 0x281998d, '48c78424f000000088000000'),
    ('context_hash_suffix', 0x2819999, '66c78424f80000000100'),
)
BRANCH_PINS += (
    ('single', 0x4878b31, '0f8480000000'),
    ('single', 0x4878b51, '0f849c000000'),
    ('single', 0x4878bb3, '75bb'),
    ('single', 0x4a07557, '7404'),
    ('single', 0x4a075b6, '7404'),
    ('single', 0x487aa28, '740b'),
    ('single', 0x487aa3d, '7426'),
    ('single', 0x487aa51, '0f844c050000'),
    ('single', 0x487aa7f, '0f84b3040000'),
    ('single', 0x487aae9, '0f8449040000'),
    ('single', 0x487aaf2, '0f8485040000'),
    ('single', 0x487aafb, '7423'),
    ('single', 0x487ab07, '0f83c3000000'),
    ('single', 0x487ab23, '7438'),
    ('single', 0x487ab2f, '7431'),
    ('single', 0x487ab4d, '75f1'),
    ('single', 0x487ab59, '7315'),
    ('single', 0x487ab69, '7243'),
    ('single', 0x487abac, '75c2'),
    ('single', 0x487abbc, '0f824bffffff'),
    ('single', 0x487abda, '0f848e030000'),
    ('single', 0x487abf4, '73da'),
    ('single', 0x487abf9, '0f8491000000'),
    ('single', 0x487ac11, '0f84c9020000'),
    ('single', 0x487ac30, '75ee'),
    ('single', 0x487ac3c, '7243'),
    ('single', 0x487ac7f, '75bf'),
    ('single', 0x487acac, '0f85fefdffff'),
    ('single', 0x487acbb, '0f83effdffff'),
    ('single', 0x487acd1, '0f84d9fdffff'),
    ('single', 0x487ad54, '0f8437020000'),
    ('single', 0x487ada6, '0f8446010000'),
    ('single', 0x487ae1b, '0f84e3000000'),
    ('single', 0x487ae2a, '0f83d4000000'),
    ('single', 0x487ae40, '0f84be000000'),
    ('single', 0x487aea5, '0f8515ffffff'),
    ('single', 0x487aee7, '0f8294fdffff'),
    ('single', 0x487afbe, '7416'),
)
TRANSFER_PINS += (
    ('single', 0x4d7eaef, 0x4878b00, None),
    ('single', 0x4d7cb3f, 0x4878b00, None),
    ('single', 0x4878b7d, 0x4a07530, None),
    ('single', 0x4a0759e, 0x487a9f0, None),
    ('single', 0x4a075fd, 0x487a9f0, None),
    ('single', 0x487aec3, 0x454f5d0, None),
)

WINDOW_PINS += (
    ('capture_low_diagnostics', 0x26b3848, '488d3df11c0103ff151bac0b03eb0d488d3d92ff0003ff150cac0b030f0b'),
    ('capture_shared_alloc_failure', 0x487af91, 'bf08000000bee0000000ff151730ef000f0b'),
    ('capture_shared_empty_book_range', 0x4878bb7, '48c704240000000048c7442408080000004c897424104c897310488b0424488903488b442408488943084889d84883c4485b415c415d415e415f5dc3'),
    ('outer_child_failure', 0x1e5cf9e, '0f10442458488b5c24080f114308488903488b74241048b800000000000000804839c674244885f6741f488b7c241831d2ff153b109103eb10488b4c24584c89234889430848894b10'),
)

WINDOW_PINS += (
    ('context_materializer_source_vector', 0x3751ed6, '488d86481800004889442470'),
    ('context_materializer_destination_vector', 0x375224e, '488b4c2470488b4110498986783300000f1001410f118668330000'),
)

FDE_PINS.update({
    0x44356c0: (0x4435722, 'a097498e4ad814f16d842b5214ebdf301f140d8c343a1d75b5cd483691658b3f', 'shared_null_writer'),
    0x45a6a50: (0x45a6ac2, '6b4d55ac5b3b149e6df5d9cef7fca754442b067bc1f0020b658f80463604da03', 'shared_user_writer'),
    0x4abb070: (0x4abb0f5, '5b6bf7ac809b96c82940e93962a1ef71063d475fa53ae9dc6683db9eb9a4f1c8', 'shared_oid_writer'),
})
WINDOW_PINS += (
    ('shared_null_writer', 0x44356c4, '4889f84c8b4e104c390e7425488b4e0842c60409c049ffc14c894e1048b904000000000000804889084883c4085b415ec3'),
    ('shared_user_writer', 0x45a6a59, '4989d64889f24889fb49bf00000000000000800f57c00f1144241a0f294424100f2904244889e7be2a000000b9140000004531c0ff158dc61c014c89f74889c6e8924b54004883f80275064983cf04eb0848894308488953104c893b4889d84883c4305b415e415fc3'),
    ('shared_oid_writer', 0x4abb08b, '807e1b00741a4889f74989f44889d64889cae88e0503004c89e64883f8027533488d7c24084c89f2e808160300488b4424084883f80275094983c7044c893beb1d488b4c24104889430848894b104c893beb0b4c893b48894308488953104883c4185b415c415e415fc3'),
    ('context_shared_u64_small', 0x4aec6c8, '4881fa00010000732e84d20f88d70000004c8b4e104c390e0f845d010000488b4e084288140949ffc14c894e10'),
    ('context_shared_string_short', 0x4aeb63e, '83fb20732389dd4080cda0'),
    ('context_shared_string_long', 0x4aeb680, '498b7e0842c6043fd949ffc74d897e104c39f80f843801000042881c3f'),
    ('context_shared_map_marker', 0x4ae9be0, '81fa000001000f92c034df83fa100fb6c0bd800000000f43e8'),
)
BRANCH_PINS += (
    ('single', 0x44356ce, '7425'),
    ('single', 0x45a6aa2, '7506'),
    ('single', 0x4abb08f, '741a'),
    ('single', 0x4abb0a9, '7533'),
    ('single', 0x4abb0c1, '7509'),
)
TRANSFER_PINS += (
    ('single', 0x49e7d14, 0x45a6a50, None),
    ('single', 0x49e7d52, 0x44356c0, None),
    ('single', 0x45a6a99, 0x4aeb630, None),
    ('single', 0x4435711, 0x454f5d0, None),
    ('single', 0x4abb09d, 0x4aeb630, None),
    ('single', 0x4abb0b3, 0x4aec6c0, None),
    ('single', 0x49e7c6d, 0x4aec6c0, None),
    ('single', 0x49e7cd7, 0x4aec6c0, None),
)

WINDOW_PINS += (
    ('context_marker_identity', 0x4aed5a0, '89f80fb6c88d9140ffffff83fa207301c3'),
    ('context_marker_map_merge', 0x4aed5d4, '85c974f94080e60f4080ce8089f0c3'),
)

def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify_digest(data):
    require(hashlib.sha256(data).hexdigest() == SHA256, 'target SHA-256 mismatch')


def location(secs, data_length, va, size, executable=False):
    require(type(va) is int and type(size) is int and va >= 0 and size > 0,
            'invalid virtual range')
    require(va + size <= 1 << 64, 'virtual range overflow')
    matches = [s for s in secs if s['type'] != 8 and
               (not executable or s['flags'] & 4) and
               s['address'] <= va and va + size <= s['address'] + s['size']]
    require(len(matches) == 1, 'virtual range unmapped or ambiguous')
    sec = matches[0]
    offset = sec['offset'] + va - sec['address']
    require(offset >= 0 and offset + size <= data_length, 'file range outside input')
    return sec, offset


def read(data, secs, va, size, executable=False):
    _, offset = location(secs, len(data), va, size, executable)
    return bytes(data[offset:offset + size])


def check_bytes(data, secs, va, expected, executable=True):
    expected = bytes.fromhex(expected) if isinstance(expected, str) else expected
    require(read(data, secs, va, len(expected), executable) == expected,
            f'changed selected bytes at {va:#x}')
    return expected


def check_body(data, secs, frame, start):
    require(start in FDE_PINS, 'unselected FDE')
    end, digest, _role = FDE_PINS[start]
    require(frame['start'] == start and frame['end'] == end and 'index' in frame,
            f'FDE bounds/index mismatch at {start:#x}')
    raw = read(data, secs, start, end - start, True)
    require(hashlib.sha256(raw).hexdigest() == digest, f'body mismatch at {start:#x}')
    return raw


def selected_frames(data, secs):
    summary, frames, _gaps = fde_extents(data)
    for key in ('unwind_start_differs_from_fde_start', 'duplicate_start',
                'zero_length', 'extent_crosses_section_end',
                'fde_records_not_in_unwind_table', 'lsda_outside_gcc_except_table'):
        require(summary[key] == 0, 'invalid global unwind index: ' + key)
    found = {}
    for frame in frames:
        start = frame['start']
        if start in FDE_PINS:
            require(start not in found, 'duplicate selected FDE start')
            check_body(data, secs, frame, start)
            found[start] = frame
    require(set(found) == set(FDE_PINS), 'missing selected FDE')
    return found


def owner_of(site, size=1):
    owners = [start for start, (end, _digest, _role) in FDE_PINS.items()
              if start <= site and site + size <= end]
    require(len(owners) <= 1, 'ambiguous selected owner')
    return owners[0] if owners else None


def branch_at(data, secs, site, expected, owner):
    raw = check_bytes(data, secs, site, expected)
    if len(raw) == 2 and 0x70 <= raw[0] <= 0x7f:
        disp, code = struct.unpack('<b', raw[1:])[0], raw[0] & 15
    elif len(raw) == 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        disp, code = struct.unpack('<i', raw[2:])[0], raw[1] & 15
    else:
        raise ValueError('unsupported conditional branch')
    dest = site + len(raw) + disp
    require(owner in FDE_PINS and owner <= site and site + len(raw) <= FDE_PINS[owner][0]
            and owner <= dest < FDE_PINS[owner][0], 'branch outside its selected FDE')
    return raw, disp, dest, COND[code]


def transfer_at(data, secs, site, expected_target):
    raw = read(data, secs, site, 5, True)
    require(raw[0] in (0xe8, 0xe9), 'unsupported relative transfer')
    displacement = struct.unpack('<i', raw[1:])[0]
    target = site + 5 + displacement
    require(target == expected_target, 'relative target changed')
    location(secs, len(data), target, 1, True)
    return raw, displacement, target


def selected_branches(data, secs):
    rows = []
    for group, address, expected in BRANCH_PINS:
        if group == 'single':
            owners = [owner_of(address)]
            sites = [address]
        else:
            owners = list(PAIRS[group])
            sites = [start + address for start in owners]
        require(all(owner is not None for owner in owners), 'branch without owner')
        for lane, (owner, site) in enumerate(zip(owners, sites)):
            raw, disp, dest, condition = branch_at(data, secs, site, expected, owner)
            _sec, off = location(secs, len(data), site, len(raw), True)
            rows.append([group, 'single' if group == 'single' else ('low' if lane == 0 else 'shared'),
                         hex(owner), hex(site), hex(off), raw.hex(), condition, disp,
                         hex(site + len(raw)), hex(dest)])
    return sorted(rows, key=lambda r: (int(r[2], 16), int(r[3], 16)))


def selected_transfers(data, secs):
    rows = []
    for group, address, target_low, target_shared in TRANSFER_PINS:
        if group == 'single':
            sites = [(address, target_low, 'single')]
        else:
            low, shared = PAIRS[group]
            sites = [(low + address, target_low, 'low'),
                     (shared + address, target_shared, 'shared')]
        for site, target, lane in sites:
            raw, disp, dest = transfer_at(data, secs, site, target)
            owner = owner_of(site, len(raw))
            _sec, off = location(secs, len(data), site, len(raw), True)
            rows.append([group, lane, 'selected' if owner is not None else 'prior_context',
                         hex(owner) if owner is not None else '', hex(site), hex(off),
                         raw.hex(), 'call' if raw[0] == 0xe8 else 'jump', disp, hex(dest),
                         'selected' if dest in FDE_PINS else 'boundary'])
    return sorted(rows, key=lambda r: int(r[4], 16))


def selected_windows(data, secs):
    rows = []
    for label, va, expected in WINDOW_PINS:
        raw = check_bytes(data, secs, va, expected)
        sec, offset = location(secs, len(data), va, len(raw), True)
        owner = owner_of(va, len(raw))
        rows.append([label, 'selected' if owner is not None else 'prior_context',
                     hex(owner) if owner is not None else '', hex(va),
                     hex(va + len(raw)), hex(offset), sec['name'],
                     hashlib.sha256(raw).hexdigest(), raw.hex()])
    return rows


def relocation_index(data, secs, slots):
    matches = [s for s in secs if s['name'] == '.rela.dyn']
    require(len(matches) == 1 and matches[0]['type'] != 8, 'missing or ambiguous relocation section')
    sec = matches[0]
    require(sec['size'] % 24 == 0, 'misaligned relocation section')
    result = {}
    for pos in range(sec['offset'], sec['offset'] + sec['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, pos)
        if slot in slots:
            require(slot not in result, 'duplicate relocation slot')
            result[slot] = (info & 0xffffffff, info >> 32, addend, pos,
                            bytes(data[pos:pos + 24]))
    require(set(result) == set(slots), 'missing selected relocation')
    return result


def table_rows(data, secs):
    slots = [table + 24 for _lane, table, _thunk, _body in TABLES]
    reloc = relocation_index(data, secs, slots)
    rows = []
    for lane, table, thunk, body in TABLES:
        slot = table + 24
        typ, symbol, addend, pos, raw = reloc[slot]
        require((typ, symbol, addend) == (RELATIVE_TYPE, 0, thunk), 'table relocation mismatch')
        table_bytes = read(data, secs, table, 32)
        size, align = struct.unpack_from('<QQ', table_bytes, 8)
        require((size, align) == (24, 8), 'unexpected table size/alignment')
        _raw, _disp, target = transfer_at(data, secs, thunk + 4, body)
        sec, fileoff = location(secs, len(data), table, 32)
        rows.append([lane, hex(table), hex(fileoff), table_bytes.hex(), size, align,
                     hex(slot), hex(pos), typ, symbol, hex(addend), raw.hex(), hex(thunk), hex(target)])
    return rows


def parse_lsda(data, secs, frame):
    va = frame['lsda']
    if va is None:
        return None, []
    sec, off = location(secs, len(data), va, 3)
    require(sec['name'] == '.gcc_except_table', 'unsupported LSDA section')
    limit = sec['offset'] + sec['size']
    pos = off
    require(data[pos] == 0xff, 'unsupported LSDA base encoding')
    typ = data[pos + 1]
    require(typ in (0xff, 0x9b), 'unsupported LSDA type encoding')
    pos += 2
    if typ == 0x9b:
        dist, pos = uleb(data, pos, limit)
        type_base = pos + dist
        require(type_base <= limit, 'LSDA type table outside section')
    else:
        type_base = limit
    require(pos < limit and data[pos] == 1, 'unsupported call-site encoding')
    length, pos = uleb(data, pos + 1, limit)
    end = pos + length
    require(end <= min(limit, type_base), 'LSDA call-site table outside section')
    rows, previous = [], frame['start']
    while pos < end:
        begin_pos = pos
        vals = []
        for _ in range(4):
            value, pos = uleb(data, pos, end)
            vals.append(value)
        delta, size, landing, action = vals
        start = frame['start'] + delta
        stop = start + size
        land = frame['start'] + landing if landing else None
        require(frame['start'] <= start < stop <= frame['end'] and start >= previous,
                'invalid or overlapping LSDA call range')
        require(land is None or frame['start'] <= land < frame['end'], 'invalid LSDA landing')
        rows.append([hex(frame['start']), hex(va), hex(begin_pos), bytes(data[begin_pos:pos]).hex(),
                     hex(start), hex(stop), '' if land is None else hex(land), action])
        previous = stop
    require(pos == end, 'LSDA row length mismatch')
    raw = bytes(data[off:end])
    digest = hashlib.sha256(raw).hexdigest()
    require(LSDA_HASHES.get(frame['start']) == digest, 'LSDA hash mismatch')
    return [hex(frame['start']), hex(va), hex(off), typ, len(rows), digest, raw.hex()], rows


def lsda_call_links(transfers, lsda_rows):
    # For selected direct calls, the lookup uses return-PC minus one. Jumps
    # have no return PC. Empty landing values and absent rows stay distinct.
    by_owner = {}
    for row in lsda_rows:
        by_owner.setdefault(row[0], []).append(row)
    out = []
    for row in transfers:
        if row[2] != 'selected' or row[7] != 'call':
            continue
        owner, site = row[3], int(row[4], 16)
        lookup_pc = site + 4
        matches = [entry for entry in by_owner.get(owner, [])
                   if int(entry[4], 16) <= lookup_pc < int(entry[5], 16)]
        require(len(matches) <= 1, 'overlapping call-site exception rows')
        entry = matches[0] if matches else None
        out.append([owner, hex(site), row[9], hex(lookup_pc),
                    'covered' if entry is not None else 'no_selected_row',
                    '' if entry is None else entry[4], '' if entry is None else entry[5],
                    '' if entry is None else entry[6], '' if entry is None else entry[7]])
    return out


def twin_comparison(data, secs):
    summary, diffs = [], []
    for name, (left, right) in PAIRS.items():
        left_end = FDE_PINS[left][0]
        right_end = FDE_PINS[right][0]
        require(left_end - left == right_end - right, 'paired FDE length mismatch')
        a = read(data, secs, left, left_end - left, True)
        b = read(data, secs, right, right_end - right, True)
        changed = sum(x != y for x, y in zip(a, b))
        runs = 0
        i = 0
        while i < len(a):
            if a[i] == b[i]:
                i += 1
                continue
            begin = i
            while i < len(a) and a[i] != b[i]:
                i += 1
            runs += 1
            diffs.append([name, hex(begin), hex(left + begin), hex(right + begin),
                          i - begin, a[begin:i].hex(), b[begin:i].hex()])
        summary.append([name, hex(left), hex(right), len(a), changed, runs,
                        hashlib.sha256(a).hexdigest(), hashlib.sha256(b).hexdigest()])
    return summary, diffs


def disp8(data, secs, site, prefix):
    raw = read(data, secs, site, len(prefix) + 1, True)
    require(raw.startswith(prefix), 'unexpected field instruction')
    return raw, raw[-1]


def literal_at_lea(data, secs, site, prefix, expected):
    raw = read(data, secs, site, len(prefix) + 4, True)
    require(raw.startswith(prefix), 'unexpected RIP-relative instruction')
    address = site + len(raw) + struct.unpack('<i', raw[-4:])[0]
    value = read(data, secs, address, len(expected))
    require(value == expected, 'literal changed')
    _sec, off = location(secs, len(data), address, len(value))
    return address, off, value


def field_rows(data, secs):
    # All offsets are extracted from the respective encoded addressing operands.
    specs = [
        ('is_position_tpsl', 0x49e7ba1, bytes.fromhex('410fb66f'), 0x35),
        ('orig_sz', 0x49e7ccb, bytes.fromhex('498b57'), 0x08),
        ('user', 0x49e7d08, bytes.fromhex('498d77'), 0x20),
        ('tif', 0x49e7d41, bytes.fromhex('498d77'), 0x34),
        ('core', 0x49e7dc7, bytes.fromhex('498b57'), 0x18),
        ('oid', 0x49e7ddf, bytes.fromhex('4d8b47'), 0x10),
    ]
    rows = []
    raw = check_bytes(data, secs, 0x49e7c62, '498b17')
    rows.append(['resting_sz', hex(0x49e7c62), '0x0', raw.hex()])
    for name, site, prefix, expected in specs:
        raw, offset = disp8(data, secs, site, prefix)
        require(offset == expected, 'field displacement changed')
        rows.append([name, hex(site), hex(offset), raw.hex()])
    order = ['is_position_tpsl', 'resting_sz', 'orig_sz', 'user', 'tif', 'core', 'oid']
    rows.sort(key=lambda x: order.index(x[0]))

    # Named strings have different encodings: pool bytes, immediate stores, and a child.
    pos_addr, pos_off, pos = literal_at_lea(data, secs, 0x49e7bd2,
                                            bytes.fromhex('0f1005'), b'is_position_tpsl')
    user_addr, user_off, user = literal_at_lea(data, secs, 0x49e7cee,
                                               bytes.fromhex('488d35'), b'user')
    tif_addr, tif_off, tif = literal_at_lea(data, secs, 0x49e7d27,
                                            bytes.fromhex('488d35'), b'tif')
    oid_addr, oid_off, oid = literal_at_lea(data, secs, 0x49e7de3,
                                            bytes.fromhex('488d15'), b'oid')
    a = check_bytes(data, secs, 0x49e7c3a, '48b872657374696e675f')
    b = check_bytes(data, secs, 0x49e7c48, '6642c7442108737a')
    resting = a[2:] + b[-2:]
    c = check_bytes(data, secs, 0x49e7cb4, 'c7443103675f737a')
    d = check_bytes(data, secs, 0x49e7cbc, 'c704316f726967')
    require(d[-1:] == c[4:5], 'overlapping key stores disagree')
    orig = d[3:] + c[5:]
    core = check_bytes(data, secs, 0x4abb133, '41c70430636f7265')[4:]
    require((resting, orig, core) == (b'resting_sz', b'orig_sz', b'core'), 'key bytes changed')
    literals = [
        ['is_position_tpsl', 'rip', hex(0x49e7bd2), hex(pos_addr), hex(pos_off), pos.hex(), pos.decode()],
        ['resting_sz', 'immediate', hex(0x49e7c3a), '', '', resting.hex(), resting.decode()],
        ['orig_sz', 'immediate', hex(0x49e7cb4), '', '', orig.hex(), orig.decode()],
        ['user', 'rip', hex(0x49e7cee), hex(user_addr), hex(user_off), user.hex(), user.decode()],
        ['tif', 'rip', hex(0x49e7d27), hex(tif_addr), hex(tif_off), tif.hex(), tif.decode()],
        ['core', 'immediate_child', hex(0x4abb133), '', '', core.hex(), core.decode()],
        ['oid', 'rip', hex(0x49e7de3), hex(oid_addr), hex(oid_off), oid.hex(), oid.decode()],
    ]
    return rows, literals


def layout_rows(data, secs):
    # Immediate operands from explicitly checked instruction forms.
    # This is a selected layout, not a type recovery or a generic decoder.
    specs = [
        ('low_dex_count_offset', 0x2755f9f, '498b8424', 4, 0x3378),
        ('low_dex_pointer_offset', 0x2755fb8, '4c8bb9', 4, 0x3370),
        ('low_dex_stride', 0x2755fbf, '4869c0', 4, 0x138),
        ('primary_dex_count_offset', 0x4d7ea7b, '488b85', 4, 0x3df8),
        ('primary_dex_pointer_offset', 0x4d7ea8b, '4c8ba5', 4, 0x3df0),
        ('secondary_dex_count_offset', 0x4d7cacb, '488b85', 4, 0x3378),
        ('secondary_dex_pointer_offset', 0x4d7cadb, '4c8ba5', 4, 0x3370),
        ('book_count_offset', 0x2756013, '498b5f', 1, 0x10),
        ('book_pointer_offset', 0x2756020, '4d8b77', 1, 0x08),
        ('book_stride', 0x4878ba9, '4981c7', 4, 0xd8),
        ('side_capture_stride', 0x4878ba5, '4983c4', 1, 0x30),
        ('outer_vector_stride', 0x1e5cf4f, '4983c4', 1, 0x18),
        ('side_map_stride', 0x1ddb2ce, '4983c4', 1, 0x30),
        ('level_stride', 0x1e5773b, '4983c5', 1, 0x20),
        ('order_stride', 0x1dfc464, '4983c7', 1, 0x38),
        ('slot_stride', 0x487acc5, '4869c9', 4, 0xf8),
        ('slot_core_offset', 0x487ad5a, '4983c7', 1, 0x20),
        ('low_descriptor_data_offset', 0x2756b86, '48894b', 1, 0x10),
        ('low_descriptor_table_offset', 0x2756b91, '48894b', 1, 0x18),
    ]
    rows = []
    for label, site, prefix_hex, width, expected in specs:
        prefix = bytes.fromhex(prefix_hex)
        raw = read(data, secs, site, len(prefix) + width, True)
        require(raw.startswith(prefix), 'layout instruction form changed')
        value = int.from_bytes(raw[-width:], 'little')
        require(value == expected, 'layout operand changed')
        owner = owner_of(site, len(raw))
        _sec, offset = location(secs, len(data), site, len(raw), True)
        rows.append([label, 'selected' if owner is not None else 'prior_context',
                     '' if owner is None else hex(owner), hex(site), hex(offset),
                     raw.hex(), hex(value)])
    return rows


def materializer_crosswalk(data, secs):
    # Context only: do not claim the earlier materializer FDE or its calls.
    source = check_bytes(data, secs, 0x3751ed6, '488d86481800004889442470')
    destination = check_bytes(data, secs, 0x375224e,
        '488b4c2470488b4110498986783300000f1001410f118668330000')
    src = struct.unpack_from('<I', source, 3)[0]
    dst_length = struct.unpack_from('<I', destination, 12)[0]
    dst = struct.unpack_from('<I', destination, 23)[0]
    require((src, dst, dst_length) == (0x1848, 0x3368, 0x3378),
            'materializer vector operands changed')
    require(dst_length == dst + 16, 'inconsistent vector triple layout')
    rows = []
    for index, role in enumerate(('first_word', 'pointer_word', 'length_word')):
        rows.append([role, hex(src + 8*index), hex(dst + 8*index),
                     '0x3751ed6', '0x375224e', 'prior_context'])
    return rows


def copy_rows(data, secs):
    # Each source and destination encoding is pinned separately. A label is an
    # inference from the corresponding writer's key, not a recovered type.
    specs = [
        ('sizes', 0x487ad0c, '410f1087', 4, 0xc8, 0x487ad63, '0f1100', 0, 0, 16),
        ('oid', 0x487ad3f, '4d8baf', 4, 0xd8, 0x487ad66, '4c8968', 1, 0x10, 8),
        ('core_address', 0x487ad5a, '4983c7', 1, 0x20, 0x487ad6a, '4c8978', 1, 0x18, 8),
        ('user_prefix', 0x487ad27, '410f1087', 4, 0xe0, 0x487ad76, '0f1140', 1, 0x20, 16),
        ('user_suffix', 0x487ad19, '418b87', 4, 0xf0, 0x487ad81, '8948', 1, 0x30, 4),
        ('tif', 0x487ad37, '450fb6a7', 4, 0xf5, 0x487ad84, '448860', 1, 0x34, 1),
        ('position_flag', 0x487ad04, '410fb6af', 4, 0xf4, 0x487ad88, '408868', 1, 0x35, 1),
    ]
    def operand(site, prefix_hex, width, expected):
        prefix = bytes.fromhex(prefix_hex)
        raw = read(data, secs, site, len(prefix) + width, True)
        require(raw.startswith(prefix), 'copy instruction form changed')
        value = int.from_bytes(raw[-width:], 'little') if width else 0
        require(value == expected, 'copy displacement changed')
        return raw, value
    rows = []
    for name, a, pre_a, wa, expected_a, b, pre_b, wb, expected_b, size in specs:
        src, src_offset = operand(a, pre_a, wa, expected_a)
        dst, dst_offset = operand(b, pre_b, wb, expected_b)
        rows.append([name, hex(a), src.hex(), hex(src_offset), hex(b), dst.hex(),
                     hex(dst_offset), size, 'address' if name == 'core_address' else 'value'])
    return rows


def result_guard_rows(data, secs):
    # Prior closure context: validate the new writer call's downstream guard.
    rows = []
    for lane, site, raw_hex, target in (
        ('low', 0x2819916, '0f85f6000000', 0x2819a12),
        ('shared', 0x4ae4d06, '0f85f6000000', 0x4ae4e02),
    ):
        raw = check_bytes(data, secs, site, raw_hex)
        dest = site + len(raw) + struct.unpack('<i', raw[2:])[0]
        require(dest == target, 'result guard target changed')
        _sec, offset = location(secs, len(data), site, len(raw), True)
        rows.append([lane, 'prior_context', hex(site), hex(offset), raw.hex(), 'ne',
                     hex(site + len(raw)), hex(dest)])
    return rows


def decision_rows(branches):
    # Interpret only these selected branch rows. Labels are not x86 decoding.
    specs = [
        (0x26b35d0, 'level_iterator_exhausted', 'return accumulated count'),
        (0x26b3603, 'level_iterator_flag_clear', 'diagnostic then ud2'),
        (0x26b36ea, 'level_parent_null', 'diagnostic then ud2'),
        (0x4878b31, 'book_range_empty', 'return empty capture vector'),
        (0x4878b51, 'book_capture_allocation_null', 'allocation failure path'),
        (0x487acac, 'head_tag_not_one', 'emit level with empty order vector'),
        (0x487acbb, 'head_index_out_of_range', 'emit level with empty order vector'),
        (0x487acd1, 'head_slot_tag_two', 'emit level with empty order vector'),
        (0x487ad54, 'first_order_allocation_null', 'allocation failure path and ud2'),
        (0x487ada6, 'first_next_word_zero', 'finish one-order vector'),
        (0x487ae1b, 'later_next_word_zero', 'finish collected prefix'),
        (0x487ae2a, 'later_index_out_of_range', 'finish collected prefix'),
        (0x487ae40, 'later_slot_tag_two', 'finish collected prefix'),
        (0x1e5ce6f, 'outer_count_high_half_nonzero', 'use buffered path'),
        (0x1e5ce8f, 'outer_array_header_result_not_two', 'return error payload'),
        (0x1e5cf4d, 'outer_child_result_not_success', 'copy error and release buffer'),
        (0x49e6e55, 'core_header_result_not_two', 'return error payload'),
        (0x49e6e5e, 'core_t_absent', 'omit t'),
        (0x49e6ec3, 'core_S_absent', 'omit S'),
        (0x49e6f1f, 'core_r_absent', 'omit r'),
        (0x49e6fb9, 'core_R_absent', 'omit R'),
        (0x49e6fd7, 'core_d_absent', 'omit d'),
        (0x49e6ffa, 'core_c_absent', 'omit c'),
        (0x49e701d, 'core_b_absent', 'omit b'),
        (0x49e6fce, 'core_R_child_not_success', 'propagate child result'),
        (0x49e7d48, 'tif_tag_not_five', 'select alternative tif writer'),
    ]
    by_site = {int(row[3], 16): row for row in branches}
    result = []
    for site, condition, consequence in specs:
        require(site in by_site, 'decision branch not pinned')
        row = by_site[site]
        result.append([condition, consequence, row[2], row[3], row[4], row[5],
                       row[6], row[8], row[9]])
    return result


def slot_prefix(head_tag, head_index, slots):
    # Conditional, bounded model of the observed guard sequence. This model
    # rejects repeated indices; the target bytes do not establish cycle handling.
    require(type(head_tag) is int and 0 <= head_tag < 1 << 32, 'head tag out of range')
    require(type(head_index) is int and 0 <= head_index < 1 << 64, 'head index out of range')
    for tag, next_word, next_index in slots:
        require(type(tag) is int and 0 <= tag < 1 << 32, 'slot tag out of range')
        require(type(next_word) is int and 0 <= next_word < 1 << 64 and
                type(next_index) is int and 0 <= next_index < 1 << 64, 'slot link out of range')
    if head_tag != 1 or head_index >= len(slots) or slots[head_index][0] == 2:
        return []
    out, seen, index = [], set(), head_index
    while True:
        require(index not in seen, 'synthetic cycle')
        seen.add(index)
        out.append(index)
        _tag, next_word, next_index = slots[index]
        if next_word == 0 or next_index >= len(slots) or slots[next_index][0] == 2:
            return out
        index = next_index


def slot_case_rows():
    cases = [
        ('invalid_head_zero', 0, 0, [(0, 0, 0)]),
        ('invalid_head_two', 2, 0, [(0, 0, 0)]),
        ('head_equal_length', 1, 1, [(0, 0, 0)]),
        ('head_free', 1, 0, [(2, 0, 0)]),
        ('empty_slots', 1, 0, []),
        ('one_slot', 1, 0, [(0, 0, 0)]),
        ('two_slots', 1, 0, [(0, 1, 1), (0, 0, 0)]),
        ('nonzero_link_two', 1, 0, [(0, 2, 1), (0, 0, 0)]),
        ('second_free', 1, 0, [(0, 1, 1), (2, 0, 0)]),
        ('second_out_of_range', 1, 0, [(0, 1, 1)]),
        ('second_word_zero', 1, 0, [(0, 0, 1), (0, 0, 0)]),
    ]
    rows = []
    for label, head_tag, head_index, slots in cases:
        prefix = slot_prefix(head_tag, head_index, slots)
        rows.append([label, head_tag, head_index, json.dumps(slots, separators=(',', ':')),
                     ','.join(str(i) for i in prefix), len(prefix)])
    return rows


def core_count(t, s, r, u10, u20, u40, d, c, b):
    """Selected x86 u32 count expression; inputs are synthetic raw field bits."""
    values = (t, s, u10, u20, u40, d, b)
    require(all(type(v) is int and 0 <= v < 1 << 64 for v in values), 'word out of range')
    require(all(type(v) is int and 0 <= v < 256 for v in (r, c)), 'byte out of range')
    r_gate = ((u10 | u20 | int(u40 != 0)) & 1)
    count = (2 + int(t != 0) + (s & 0xffffffff) + r + r_gate +
             int(d != 0) + c + (b & 0xffffffff)) & 0xffffffff
    present = (2 + int(t != 0) + int((s & 0xff) != 0) + int(r != 0) +
               r_gate + int(d != 0) + int(c != 0) + int((b & 0xff) != 0))
    return count, present


def header_byte(mode):
    require(type(mode) is int and 0 <= mode < 256, 'mode byte out of range')
    return ((((mode ^ 1) << 4) & 0xff) | 0x87)


def small_array_marker(count):
    require(type(count) is int and 0 <= count < 16, 'small-array count out of range')
    return bytes([0x90 | count])


def nested_empty_books(counts):
    require(len(counts) < 16, 'too many synthetic DEX entries')
    result = bytearray(small_array_marker(len(counts)))
    for count in counts:
        result.extend(small_array_marker(count))
        for _ in range(count):
            result.extend((0x92, 0x90, 0x90))
    return bytes(result)


def rol64(x, n):
    mask = (1 << 64) - 1
    return ((x << n) | (x >> ((64 - n) & 63))) & mask


def keccak(message, rounds, rate=136, delimiter=1):
    require(rate == 136 and delimiter in (1, 6) and len(rounds) == 24, 'unsupported Keccak parameters')
    padded = bytearray(message)
    padded.append(delimiter)
    while len(padded) % rate != 0:
        padded.append(0)
    padded[-1] |= 0x80
    state = [0] * 25
    for offset in range(0, len(padded), rate):
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(padded[offset + 8*i:offset + 8*i + 8], 'little')
        for rc in rounds:
            columns = [state[x] ^ state[x+5] ^ state[x+10] ^ state[x+15] ^ state[x+20]
                       for x in range(5)]
            for x in range(5):
                delta = columns[(x - 1) % 5] ^ rol64(columns[(x + 1) % 5], 1)
                for y in range(5):
                    state[x + 5*y] ^= delta
            rotated = [0] * 25
            rotated[0] = state[0]
            x, y = 1, 0
            for turn in range(24):
                dest_x, dest_y = y, (2*x + 3*y) % 5
                rotated[dest_x + 5*dest_y] = rol64(state[x + 5*y], ((turn + 1)*(turn + 2)//2) % 64)
                x, y = dest_x, dest_y
            for y in range(5):
                row = rotated[5*y:5*y+5]
                for x in range(5):
                    state[x + 5*y] = row[x] ^ ((~row[(x+1) % 5]) & row[(x+2) % 5])
            state[0] ^= rc
    return b''.join(v.to_bytes(8, 'little') for v in state)[:32]


def one_order_model(data, secs):
    # Conditional example: selected named buffered path, valid disjoint input,
    # no growth/error, canonical tags, and the prior prefixed-hex primitive.
    _fields, literals = field_rows(data, secs)
    names = {row[0]: row[-1].encode('ascii') for row in literals}
    null = check_bytes(data, secs, 0x44356d4, '42c60409c0')[-1]
    values = check_bytes(data, secs, 0x45a6a80, 'be2a000000b914000000')
    hex_len, user_len = struct.unpack_from('<I', values, 1)[0], struct.unpack_from('<I', values, 6)[0]
    require((null, hex_len, user_len) == (0xc0, 42, 20), 'changed primitive anchors')
    check_bytes(data, secs, 0x4aec6c8, '4881fa00010000732e84d20f88d7000000')
    check_bytes(data, secs, 0x4aeb63e, '83fb20732389dd4080cda0')
    check_bytes(data, secs, 0x4aeb684, '42c6043fd9')
    check_bytes(data, secs, 0x4ae9bf1, 'bd80000000')
    check_bytes(data, secs, 0x4aed5a0, '89f80fb6c88d9140ffffff83fa207301c3')
    check_bytes(data, secs, 0x4aed5d4, '85c974f94080e60f4080ce8089f0c3')
    def text(value):
        require(len(value) < 32, 'short text length')
        return bytes((0xa0 | len(value),)) + value
    encoded_user = b'0x' + bytes(user_len).hex().encode('ascii')
    require(len(encoded_user) == hex_len, 'model user length')
    core = bytes((0x82,)) + text(b's') + text(b'B') + text(b'l') + bytes((1,))
    order = (bytes((header_byte(1),)) + text(names['is_position_tpsl']) + bytes((0xc2,))
             + text(names['resting_sz']) + bytes((1,)) + text(names['orig_sz']) + bytes((1,))
             + text(names['user']) + bytes((0xd9, hex_len)) + encoded_user
             + text(names['tif']) + bytes((null,)) + text(names['core']) + core
             + text(names['oid']) + bytes((1,)))
    # One DEX, one book, first side one (price=1, one order), second side empty.
    wire = bytes((0x91, 0x91, 0x92, 0x91, 0x92, 1, 0x91)) + order + bytes((0x90,))
    return wire


def model_rows(data, secs):
    # These are conditional calculations, not captures or execution of the node.
    w = check_bytes(data, secs, 0x281998d, '48c78424f000000088000000')
    u = check_bytes(data, secs, 0x2819999, '66c78424f80000000100')
    rate = struct.unpack('<I', w[8:12])[0]
    delimiter = struct.unpack('<H', u[8:10])[0]
    require((rate, delimiter) == (136, 1), 'hash parameter operands changed')
    raw = read(data, secs, 0x7d04c8, 24 * 8)
    rounds = list(struct.unpack('<24Q', raw))
    require(keccak(b'', rounds).hex() ==
            'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
            'Keccak empty known answer mismatch')
    require(keccak(b'abc', rounds).hex() ==
            '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45',
            'Keccak abc known answer mismatch')
    require(keccak(b'abc', rounds, delimiter=6) == hashlib.sha3_256(b'abc').digest(),
            'SHA3 delimiter control mismatch')

    examples = [[], [0], [1], [2], [0, 1], [1, 0], [1, 1], [2, 1], [1, 2],
                [0, 0, 0], [1, 1, 1], [0]*15]
    rows = []
    for counts in examples:
        wire = nested_empty_books(counts)
        rows.append([','.join(str(x) for x in counts) if counts else '-',
                     len(counts), sum(counts), len(wire), wire.hex(), keccak(wire, rounds).hex()])
    round_rows = [[i, hex(0x7d04c8 + 8*i), f'{rounds[i]:016x}',
                   raw[8*i:8*i+8].hex()] for i in range(len(rounds))]
    return rows, round_rows


def write_tsv(out, name, columns, rows):
    with (out / name).open('w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f, delimiter='\t', lineterminator='\n')
        writer.writerow(columns)
        writer.writerows(rows)


def extract(data):
    verify_digest(data)
    secs = sections(data)
    frames = selected_frames(data, secs)
    bodies = []
    for start in sorted(frames):
        frame = frames[start]
        end, _digest, label = FDE_PINS[start]
        raw = check_body(data, secs, frame, start)
        sec, off = location(secs, len(data), start, len(raw), True)
        bodies.append([label, hex(start), hex(end), hex(frame['fde']), hex(frame['cie']),
                       '' if frame['lsda'] is None else hex(frame['lsda']),
                       frame['index'], sec['name'], hex(off), len(raw),
                       hashlib.sha256(raw).hexdigest(), raw.hex()])
    windows = selected_windows(data, secs)
    branches = selected_branches(data, secs)
    transfers = selected_transfers(data, secs)
    tables = table_rows(data, secs)
    twin_rows, differences = twin_comparison(data, secs)
    lsda_heads, lsda_rows = [], []
    for start in sorted(frames):
        head, rows = parse_lsda(data, secs, frames[start])
        if head is not None:
            lsda_heads.append(head)
            lsda_rows.extend(rows)
    links = lsda_call_links(transfers, lsda_rows)
    require({int(row[0], 16) for row in lsda_heads} == set(LSDA_HASHES),
            'missing or unexpected selected LSDA')
    fields, literals = field_rows(data, secs)
    layouts = layout_rows(data, secs)
    crosswalk = materializer_crosswalk(data, secs)
    copies = copy_rows(data, secs)
    guards = result_guard_rows(data, secs)
    decisions = decision_rows(branches)
    slot_cases = slot_case_rows()
    examples, round_rows = model_rows(data, secs)
    wire = one_order_model(data, secs)
    rounds = struct.unpack('<24Q', read(data, secs, 0x7d04c8, 24 * 8))
    one_order = [[1, 1, 1, 1, 1, 1, 1, 5, '00' * 20, 'B', 1, len(wire), wire.hex(), keccak(wire, rounds).hex()]]
    side_values = [[v, hex(header_byte(v))] for v in range(256)]
    fixtures = [
        ('all_absent', (0, 0, 0, 0, 0, 0, 0, 0, 0)),
        ('all_present', (1, 1, 1, 1, 0, 0, 1, 1, 1)),
        ('r_byte_two', (0, 0, 2, 0, 0, 0, 0, 0, 0)),
        ('s_word_256', (0, 256, 0, 0, 0, 0, 0, 0, 0)),
        ('b_word_256', (0, 0, 0, 0, 0, 0, 0, 0, 256)),
        ('u10_even', (0, 0, 0, 2, 0, 0, 0, 0, 0)),
        ('u40_nonzero', (0, 0, 0, 0, 0, 1, 0, 0, 0)),
        ('header_wrap', (0, 0xffffffff, 0, 0, 0, 0, 0, 0, 0)),
    ]
    core_cases = []
    for label, values in fixtures:
        count, present = core_count(*values)
        core_cases.append([label] + [hex(x) for x in values] +
                          [count, present, str(count == present).lower()])
    summary = {
        'target_sha256': hashlib.sha256(data).hexdigest(),
        'selected_fde_count': len(bodies),
        'selected_fde_bytes': sum(int(row[9]) for row in bodies),
        'selected_windows': sum(row[1] == 'selected' for row in windows),
        'prior_context_windows': sum(row[1] == 'prior_context' for row in windows),
        'selected_branches': len(branches),
        'relative_transfers': len(transfers),
        'prior_context_transfers': sum(row[2] == 'prior_context' for row in transfers),
        'descriptor_relocations': len(tables),
        'paired_fdes': len(twin_rows),
        'raw_difference_runs': len(differences),
        'lsda_tables': len(lsda_heads),
        'lsda_rows': len(lsda_rows),
        'selected_lsda_call_links': len(links),
        'selected_calls_with_landing': sum(bool(row[7]) for row in links),
        'shared_order_fields': len(fields),
        'layout_operands': len(layouts),
        'materializer_vector_words': len(crosswalk),
        'shared_slot_copies': len(copies),
        'closure_result_guards': len(guards),
        'labelled_decisions': len(decisions),
        'synthetic_slot_cases': len(slot_cases),
        'header_mode_cases': len(side_values),
        'core_count_cases': len(core_cases),
        'conditional_empty_book_examples': len(examples),
        'conditional_one_order_examples': len(one_order),
        'round_constants': len(round_rows),
        'limitations': 'Selected static FDEs and instruction sites, not whole-component coverage. '
                       'No normalization, target execution, Rust implementation, runtime scheduling, '
                       'loader-to-builder object identity, complete exception actions, or final app hash.'
    }
    return {'bodies': bodies, 'windows': windows, 'branches': branches, 'transfers': transfers,
            'tables': tables, 'twins': twin_rows, 'differences': differences, 'lsda_heads': lsda_heads,
            'lsda_rows': lsda_rows, 'lsda_links': links, 'fields': fields, 'literals': literals, 'layouts': layouts, 'crosswalk': crosswalk, 'copies': copies, 'guards': guards, 'decisions': decisions,
            'slot_cases': slot_cases, 'examples': examples, 'one_order': one_order,
            'rounds': round_rows, 'header_cases': side_values, 'core_cases': core_cases,
            'summary': summary}


def generate(data, out):
    result = extract(data)  # Authenticate and validate before creating or writing output.
    out.mkdir(parents=True, exist_ok=True)
    write_tsv(out, 'fdes.tsv', ['role', 'start_va', 'end_va_exclusive', 'fde_va', 'cie_va',
        'lsda_va', 'unwind_index', 'section', 'file_offset', 'size', 'sha256', 'raw_hex'], result['bodies'])
    write_tsv(out, 'windows.tsv', ['label', 'scope', 'owner', 'start_va', 'end_va_exclusive',
        'file_offset', 'section', 'sha256', 'raw_hex'], result['windows'])
    write_tsv(out, 'branches.tsv', ['group', 'lane', 'owner', 'site_va', 'file_offset', 'raw_hex',
        'condition', 'signed_displacement', 'fallthrough_va', 'taken_va'], result['branches'])
    write_tsv(out, 'transfers.tsv', ['group', 'lane', 'scope', 'owner', 'site_va', 'file_offset',
        'raw_hex', 'kind', 'signed_displacement', 'target_va', 'target_scope'], result['transfers'])
    write_tsv(out, 'descriptors.tsv', ['lane', 'table_va', 'file_offset', 'raw_table', 'size',
        'alignment', 'slot_va', 'relocation_file_offset', 'type', 'symbol', 'addend_va',
        'raw_relocation', 'thunk_va', 'closure_va'], result['tables'])
    write_tsv(out, 'paired-fdes.tsv', ['pair', 'low_va', 'shared_va', 'size', 'different_bytes',
        'difference_runs', 'low_sha256', 'shared_sha256'], result['twins'])
    write_tsv(out, 'raw-differences.tsv', ['pair', 'offset', 'low_va', 'shared_va', 'size',
        'low_hex', 'shared_hex'], result['differences'])
    write_tsv(out, 'lsda-headers.tsv', ['owner', 'lsda_va', 'file_offset', 'type_encoding',
        'row_count', 'sha256', 'raw_hex'], result['lsda_heads'])
    write_tsv(out, 'lsda.tsv', ['owner', 'lsda_va', 'entry_file_offset', 'raw_hex',
        'start_va', 'end_va_exclusive', 'landing_va', 'action'], result['lsda_rows'])
    write_tsv(out, 'lsda-call-links.tsv', ['owner', 'call_va', 'target_va', 'lookup_pc',
        'status', 'range_start_va', 'range_end_va_exclusive', 'landing_va', 'action'], result['lsda_links'])
    write_tsv(out, 'layouts.tsv', ['label', 'scope', 'owner', 'instruction_va', 'file_offset',
        'raw_hex', 'operand'], result['layouts'])
    write_tsv(out, 'materializer-crosswalk.tsv', ['role', 'input_offset', 'output_offset',
        'input_instruction_va', 'output_window_va', 'scope'], result['crosswalk'])
    write_tsv(out, 'slot-copies.tsv', ['field_inference', 'source_instruction_va', 'source_raw',
        'slot_offset', 'destination_instruction_va', 'destination_raw', 'record_offset', 'width',
        'copy_kind'], result['copies'])
    write_tsv(out, 'closure-guards.tsv', ['lane', 'scope', 'site_va', 'file_offset', 'raw_hex',
        'condition', 'fallthrough_va', 'taken_va'], result['guards'])
    write_tsv(out, 'decisions.tsv', ['inferred_condition', 'inferred_consequence', 'owner',
        'site_va', 'file_offset', 'raw_hex', 'condition', 'fallthrough_va', 'taken_va'], result['decisions'])
    write_tsv(out, 'synthetic-slot-cases.tsv', ['case', 'head_tag', 'head_index', 'slots_tag_next_index',
        'prefix_indices', 'prefix_length'], result['slot_cases'])
    write_tsv(out, 'order-fields.tsv', ['field', 'instruction_va', 'record_offset', 'raw_hex'], result['fields'])
    write_tsv(out, 'field-literals.tsv', ['field', 'encoding', 'site_va', 'literal_va',
        'file_offset', 'literal_hex', 'ascii'], result['literals'])
    write_tsv(out, 'header-cases.tsv', ['synthetic_mode_byte', 'computed_header_byte'], result['header_cases'])
    write_tsv(out, 'core-count-cases.tsv', ['case', 't', 's', 'r', 'u10', 'u20', 'u40', 'd', 'c',
        'b', 'computed_u32_header', 'present_field_count', 'same'], result['core_cases'])
    write_tsv(out, 'empty-book-examples.tsv', ['synthetic_books_per_dex', 'dex_count', 'book_count',
        'input_length', 'predicted_input_hex', 'predicted_row_keccak256'], result['examples'])
    write_tsv(out, 'one-order-example.tsv', ['dexes', 'books', 'first_side_levels', 'orders',
        'price', 'resting_size', 'original_size', 'tif_tag', 'user_hex', 'core_side', 'core_l',
        'predicted_input_length', 'predicted_input_hex', 'predicted_row_keccak256'], result['one_order'])
    write_tsv(out, 'keccak-rounds.tsv', ['index', 'va', 'word_hex', 'little_endian_hex'], result['rounds'])
    (out / 'summary.json').write_text(json.dumps(result['summary'], sort_keys=True, indent=2) + '\n',
                                      encoding='utf-8')
    return result['summary']


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args(argv)
    with TARGET.open('rb') as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
            result = generate(data, args.out)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, struct.error) as exc:
        print('abci_perp_book_root94:', exc, file=sys.stderr)
        raise SystemExit(1)
