#!/usr/bin/env python3
"""Extract node 94 spot-book row-2 capture and serialization evidence, offline."""
import argparse
import csv
import hashlib
import json
import mmap
from pathlib import Path
import struct

from elf_index import sections
from fde_extents import fde_extents, uleb

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# Actual unwind-described endpoints and unmasked code hashes, not next-index bounds.
FDE_PINS = {
    0x1dd94f0: (0x1dd9957, '4e912295ec8c475dc4bfcaf068056f28c5aa83f927274a64b51787e09ab7e452'),
    0x1e0c5b0: (0x1e0ca2f, 'be52fb764a5b66e31b838cd101696842e8de2df0ef72c5d34f68592a3203e238'),
    0x1e4fe30: (0x1e50435, '2e345ca2fd5b1d6b2fbb1ad53c0e8bcebc77a86c93a97df55e74170c1bdc66b7'),
    0x1e50d30: (0x1e5153d, '3a266fbccbba18b0bffb1cf5d9efd6acef55492a71b3a80f06b57ec08c2db5a0'),
    0x1e5d350: (0x1e5d699, '8feb4197df2b2f994d5dec8e97c2c6cd5ba6ffaf442130f8e30cb6fa91cf1210'),
    0x2332010: (0x2332433, 'dbb86988bbcb950dda028d8cabb38bafcc61a8dcc5fb2e4508f4afadf8a06667'),
    0x23328c0: (0x2332ee7, '1b92c5a3750f41e57873008309d51a0bc58b35e7d7719cd5d44b21e806e7f43a'),
    0x2333470: (0x23337d7, '9f866db34b6a9a1985c11c1e1d0b36d93bdd102a5f47997edb8814936d382326'),
    0x23337e0: (0x2333bcf, '27b7559f2f53d6248b9a3cb75c8ab013c1a2a61fc71b2a8d5db331cff49f1ea5'),
    0x23d36b0: (0x23d370c, 'f81b54efeb04e6e0e0cc3ebf54650ccf8a267332bdcf576581733a19df1fa667'),
    0x23d41c0: (0x23d4511, '59674ba0098d872d072d53ba9dde624015a84e09130b0fb9b6d087caff92a2da'),
    0x23d47a0: (0x23d4994, '28e29fc836a455e6ea4b7a74c2774931fc506a30266ca39ff4a2f1319ecadbe9'),
    0x23d4c70: (0x23d544b, 'b1f5c409a3e406f98040940759c8bc97cc5940232daed208a33882263013a5c1'),
    0x23d59b0: (0x23d5a5e, 'fedc3340a88a0cd2ca1de6ff79c4e1e27905d104a97fac7bbf9f55441e55602d'),
    0x23d86c0: (0x23d8745, 'd82592f91b45c6a8637b5e548d4e4d68ed9dd9dcbb38820d1e8fc66cade8e32f'),
    0x23d8d70: (0x23d8df5, '326519ab5fc05b888b8b46be51aabc6e43912bf228924a84042c527c1d451948'),
    0x25681d0: (0x2568456, 'ca926f54085c49bc6135b161919214f7df9fe3f0b092f65aa13eb51505486dcc'),
    0x26b0930: (0x26b0c06, '8de9c3a7fc3b9b529a6b8c5ed95f353d52b098e6530629ba5684a17522e6966f'),
    0x43c6220: (0x43c6687, '1dd5ce3a2ab96ad7c73120b9611e94c90e51280857375e5e46e5e3cb212e5a4f'),
    0x443b230: (0x443ba3d, '80be950404876936ba6fc1ef264da9c24d6003103bf2a28e20a040cef2cda329'),
    0x4440d60: (0x4441365, '3ad59723f1b724759555dc5d4d86fe5a1670b15d5ca796326684f35045300b5a'),
    0x4446250: (0x4446599, 'fea8dc4984f4b161876ac4e65ac882bc0547e7611ce7e19e1354d3507def594d'),
}

# A few new connector windows inside previously inventoried boundaries. They do
# not include the original state-loader or materializer GOT and call sites.
BOUNDARIES = (
    ('prior_builder', 0x27561cf, 0x2756273, '1832ffd163dca7392db245e4a8b6e893ee4657af114bf93931209a1ea350a558'),
    ('prior_first_side', 0x2397b01, 0x2397c0f, '8ae0028b1c725e6cc988549088b8ddfd294b64d0ff2190e594711a15b623ec0b'),
    ('prior_second_side', 0x2397c0f, 0x2397d45, '3479ee580a7587af15f02f6515f22fda6223bbc4eff56d04d51e3b7782391c4f'),
    ('prior_low_hash_job', 0x2818a10, 0x2818a51, '3c7693bf9efd8e6bc34de10775621dd9062de563133638139faa5ebd3165e5ca'),
    ('prior_shared_hash_job', 0x4ae7970, 0x4ae79b1, '0e9c4ce668e5471d1823d43a5480b89cb3e50c01db7f2d3ef505feadbb405aa0'),
    ('prior_low_result', 0x2818a51, 0x2818a7b, '8f6da3c6d3e60a34bd336a86b80e03ebf0da43a6b4ad7100daecc86573cf3ba8'),
    ('prior_shared_result', 0x4ae79b1, 0x4ae79db, '8f6da3c6d3e60a34bd336a86b80e03ebf0da43a6b4ad7100daecc86573cf3ba8'),
    ('prior_array_marker_select', 0x25a9bde, 0x25a9bf7, '0b1201719aac088f504f0d017f9a48d007b9d4e56e2049ed98587d828e7a02e1'),
    ('prior_array_marker_pack', 0x25acc63, 0x25acc6d, 'f6554d7acdbcd62a3a072ff30d24b1e889c9793fe97023d1ce99d676bb8895a8'),
    ('prior_array_finisher', 0x1dd1dc1, 0x1dd1dec, '589e53b99daf94cf7f767ef2dd59625952aadee1ad60d8b9ecffc10bdfc29c4a'),
    ('prior_pair_finisher', 0x1e12bd1, 0x1e12bf2, '1ea3529f3cf4c409b890a85e92fb768e45cea58a7630f87551383f92778673be'),
    ('prior_hash_parameters', 0x2818add, 0x2818af3, 'e66cf671ce8da10817fdf7a460b1f15e0062abc576a5145c98d2447853ed9fd9'),
    ('prior_round_loop', 0x4f598f0, 0x4f59927, '54bdf255423b1d9f6ee4d1135390f0ed51667ac2db3f158fec79a697bcdd6fa6'),
)

# Exclusive windows were selected by manual instruction-boundary inspection.
# Bodies are hashed separately. These rows are not a complete CFG or disassembly.
WINDOWS = (
    ('tree_admission', 0x26b0930, 0x26b099e),
    ('tree_parent_check', 0x26b0a60, 0x26b0a89),
    ('tree_key_and_row', 0x26b0b20, 0x26b0b96),
    ('tree_return_and_failure', 0x26b0bb2, 0x26b0c06),
    ('slot_head_guards', 0x25681d0, 0x256822f),
    ('slot_first_record', 0x256822f, 0x25682e8),
    ('slot_next_record', 0x2568300, 0x2568401),
    ('slot_return_and_failure', 0x2568401, 0x2568456),
    ('outer_vector_header', 0x1e5d350, 0x1e5d3e2),
    ('outer_loop', 0x1e5d3e2, 0x1e5d431),
    ('outer_buffered_loop', 0x1e5d47d, 0x1e5d590),
    ('outer_error_returns', 0x1e5d590, 0x1e5d64c),
    ('side_header_and_first', 0x1e4fe73, 0x1e4ff5b),
    ('side_first_loop', 0x1e500dd, 0x1e50167),
    ('side_second_header', 0x1e5016f, 0x1e501f9),
    ('side_second_loop', 0x1e502b8, 0x1e50339),
    ('side_errors', 0x1e5037b, 0x1e503e2),
    ('level_header', 0x1dd9514, 0x1dd956c),
    ('level_orders_loop', 0x1dd970b, 0x1dd982b),
    ('level_result', 0x1dd982b, 0x1dd9957),
    ('buffered_level_header', 0x1e0c5cc, 0x1e0c646),
    ('buffered_level_loop', 0x1e0c7a4, 0x1e0c808),
    ('record_generic_header', 0x2333470, 0x23334e6),
    ('record_generic_fields', 0x23334e6, 0x2333663),
    ('record_generic_tails', 0x2333725, 0x23337ad),
    ('record_buffered_header', 0x23337e0, 0x2333869),
    ('record_buffered_values', 0x2333869, 0x23339de),
    ('record_buffered_tails', 0x2333a33, 0x2333a83),
    ('core_generic_count', 0x2332028, 0x2332090),
    ('core_generic_first_fields', 0x23320ea, 0x23321ee),
    ('core_generic_middle_fields', 0x23321ee, 0x2332296),
    ('core_generic_last_fields', 0x2332296, 0x233236d),
    ('core_count_inputs', 0x23328d9, 0x2332941),
    ('core_first_fields', 0x2332981, 0x2332a48),
    ('core_middle_fields', 0x2332a48, 0x2332b37),
    ('core_last_fields', 0x2332b37, 0x2332ca8),
    ('core_R_name', 0x23d41d7, 0x23d4219),
    ('core_d_name', 0x23d4c7b, 0x23d4cb6),
    ('core_s_name', 0x23d47a5, 0x23d47de),
    ('shared_outer_header', 0x4446250, 0x44462e2),
    ('shared_outer_loop', 0x44462e2, 0x4446331),
    ('shared_side_first_loop', 0x444100d, 0x4441097),
    ('shared_side_second_loop', 0x44411e8, 0x4441269),
    ('shared_level_header', 0x43c6244, 0x43c629c),
)
BRANCH_PINS = (
    ('core_generic', 0x23320ed, '7444', 0x2332133),
    ('core_generic', 0x2332140, '7445', 0x2332187),
    ('core_generic', 0x233218a, '7462', 0x23321ee),
    ('core_generic', 0x23321f1, '7421', 0x2332214),
    ('core_generic', 0x233221c, '7421', 0x233223f),
    ('core_generic', 0x2332244, '742c', 0x2332272),
    ('core_generic', 0x2332277, '741d', 0x2332296),
    ('core_generic', 0x23322c6, '743b', 0x2332303),
    ('tree', 0x26b0950, '0f845c020000', 0x26b0bb2),
    ('tree', 0x26b0983, '0f844e020000', 0x26b0bd7),
    ('tree', 0x26b098c, '7422', 0x26b09b0),
    ('tree', 0x26b0998, '0f83c2000000', 0x26b0a60),
    ('tree', 0x26b0a4d, '0f824bffffff', 0x26b099e),
    ('tree', 0x26b0a6a, '0f8458010000', 0x26b0bc8),
    ('tree', 0x26b0a84, '73da', 0x26b0a60),
    ('tree', 0x26b0a89, '0f8491000000', 0x26b0b20),
    ('tree', 0x26b0b90, '0f85eafdffff', 0x26b0980),
    ('slots', 0x25681e4, '7520', 0x2568206),
    ('slots', 0x25681f2, '7312', 0x2568206),
    ('slots', 0x2568204, '7529', 0x256822f),
    ('slots', 0x256828e, '0f848c010000', 0x2568420),
    ('slots', 0x25682e2, '0f8419010000', 0x2568401),
    ('slots', 0x2568353, '0f84a8000000', 0x2568401),
    ('slots', 0x256835d, '0f839e000000', 0x2568401),
    ('slots', 0x2568374, '0f8487000000', 0x2568401),
    ('slots', 0x25683d4, '0f8526ffffff', 0x2568300),
    ('slots', 0x256843b, '7411', 0x256844e),
    ('outer', 0x1e5d392, '0f85e5000000', 0x1e5d47d),
    ('outer', 0x1e5d3c0, '0f8539020000', 0x1e5d5ff),
    ('outer', 0x1e5d3e0, '744f', 0x1e5d431),
    ('outer', 0x1e5d421, '0f85f2010000', 0x1e5d619),
    ('outer', 0x1e5d42f, '75cf', 0x1e5d400),
    ('outer', 0x1e5d490, '0f84c5010000', 0x1e5d65b),
    ('outer', 0x1e5d4e5, '7549', 0x1e5d530),
    ('outer', 0x1e5d518, '0f859d000000', 0x1e5d5bb),
    ('outer', 0x1e5d521, '754a', 0x1e5d56d),
    ('outer', 0x1e5d54f, '753f', 0x1e5d590),
    ('outer', 0x1e5d558, '0f84ee000000', 0x1e5d64c),
    ('outer', 0x1e5d567, '0f84c4feffff', 0x1e5d431),
    ('outer', 0x1e5d57d, '75b1', 0x1e5d530),
    ('outer', 0x1e5d5b5, '0f8463ffffff', 0x1e5d51e),
    ('outer', 0x1e5d5e4, '7454', 0x1e5d63a),
    ('outer', 0x1e5d5e9, '744f', 0x1e5d63a),
    ('side', 0x1e4fe50, '7521', 0x1e4fe73),
    ('side', 0x1e4fe6d, '0f84e0010000', 0x1e50053),
    ('side', 0x1e4fe7d, '754f', 0x1e4fece),
    ('side', 0x1e4fe97, '0f85be000000', 0x1e4ff5b),
    ('side', 0x1e4fee6, '0f85ac000000', 0x1e4ff98),
    ('side', 0x1e4ff3f, '747b', 0x1e4ffbc),
    ('side', 0x1e4ffc2, '0f85b4000000', 0x1e5007c),
    ('side', 0x1e4ffde, '0f8550020000', 0x1e50234),
    ('side', 0x1e5000c, '0f84cb000000', 0x1e500dd),
    ('side', 0x1e50015, '0f8409010000', 0x1e50124),
    ('side', 0x1e50040, '0f8497000000', 0x1e500dd),
    ('side', 0x1e5008a, '0f8467030000', 0x1e503f7),
    ('side', 0x1e500e7, '743b', 0x1e50124),
    ('side', 0x1e50115, '0f8560020000', 0x1e5037b),
    ('side', 0x1e50122, '75dc', 0x1e50100),
    ('side', 0x1e50161, '0f8565020000', 0x1e503cc),
    ('side', 0x1e50193, '741a', 0x1e501af),
    ('side', 0x1e501b5, '0f859c000000', 0x1e50257),
    ('side', 0x1e501d1, '7561', 0x1e50234),
    ('side', 0x1e501fb, '0f84b7000000', 0x1e502b8),
    ('side', 0x1e5020c, '0f84f2000000', 0x1e50304),
    ('side', 0x1e50229, '0f8517feffff', 0x1e50046),
    ('side', 0x1e50265, '0f848c010000', 0x1e503f7),
    ('side', 0x1e502ca, '7438', 0x1e50304),
    ('side', 0x1e502f5, '0f8580000000', 0x1e5037b),
    ('side', 0x1e50302, '75dc', 0x1e502e0),
    ('side', 0x1e50333, '0f8593000000', 0x1e503cc),
    ('level', 0x1dd9519, '0f818b000000', 0x1dd95aa),
    ('level', 0x1dd9543, '0f8597000000', 0x1dd95e0),
    ('level', 0x1dd9562, '757c', 0x1dd95e0),
    ('level', 0x1dd9587, '747f', 0x1dd9608),
    ('level', 0x1dd95c3, '7530', 0x1dd95f5),
    ('level', 0x1dd95cc, '0f842b030000', 0x1dd98fd),
    ('level', 0x1dd962f, '755a', 0x1dd968b),
    ('level', 0x1dd967b, '0f848a000000', 0x1dd970b),
    ('level', 0x1dd971c, '0f8409010000', 0x1dd982b),
    ('level', 0x1dd972a, '7548', 0x1dd9774),
    ('level', 0x1dd975e, '0f8532010000', 0x1dd9896),
    ('record', 0x233380c, '0f8489020000', 0x2333a9b),
    ('record', 0x233382e, '7539', 0x2333869),
    ('record', 0x2333833, '0f84a7020000', 0x2333ae0),
    ('record', 0x233384c, '0f86b9020000', 0x2333b0b),
    ('record', 0x233386c, '0f844d020000', 0x2333abf),
    ('record', 0x2333893, '7543', 0x23338d8),
    ('record', 0x233389b, '0f8492020000', 0x2333b33),
    ('record', 0x23338b4, '0f86a4020000', 0x2333b5e),
    ('record', 0x23338fb, '0f85df000000', 0x23339e0),
    ('record', 0x2333906, '7543', 0x233394b),
    ('record', 0x2333912, '0f846e020000', 0x2333b86),
    ('record', 0x233392e, '0f8676020000', 0x2333baa),
    ('record', 0x2333965, '7579', 0x23339e0),
    ('record', 0x233396c, '751a', 0x2333988),
    ('record', 0x2333986, '756e', 0x23339f6),
    ('record', 0x233399e, '7569', 0x2333a09),
    ('record', 0x23339a5, '741a', 0x23339c1),
    ('record', 0x23339bf, '7535', 0x23339f6),
    ('record', 0x23339c8, '7569', 0x2333a33),
    ('record', 0x23339dc, '752b', 0x2333a09),
    ('record', 0x2333a45, '75c2', 0x2333a09),
    ('record', 0x2333a5d, '7529', 0x2333a88),
    ('record', 0x2333a81, '7505', 0x2333a88),
    ('core', 0x2332946, '741d', 0x2332965),
    ('core', 0x233295e, '7421', 0x2332981),
    ('core', 0x233297b, '0f850e010000', 0x2332a8f),
    ('core', 0x2332984, '7459', 0x23329df),
    ('core', 0x233298b, '7533', 0x23329c0),
    ('core', 0x23329d9, '0f85b0000000', 0x2332a8f),
    ('core', 0x23329ec, '745a', 0x2332a48),
    ('core', 0x23329f3, '7433', 0x2332a28),
    ('core', 0x2332a42, '0f8580020000', 0x2332cc8),
    ('core', 0x2332a4b, '0f8492000000', 0x2332ae3),
    ('core', 0x2332a56, '7465', 0x2332abd),
    ('core', 0x2332aeb, '7421', 0x2332b0e),
    ('core', 0x2332b08, '0f859f010000', 0x2332cad),
    ('core', 0x2332b11, '7424', 0x2332b37),
    ('core', 0x2332b31, '0f8576010000', 0x2332cad),
    ('core', 0x2332b3c, '0f8482000000', 0x2332bc4),
    ('core', 0x2332b47, '7433', 0x2332b7c),
    ('core', 0x2332bbe, '0f8516010000', 0x2332cda),
    ('core', 0x2332bc9, '745b', 0x2332c26),
    ('core', 0x2332bd0, '7533', 0x2332c05),
    ('core', 0x2332c20, '0f8587000000', 0x2332cad),
    ('core', 0x2332c45, '7566', 0x2332cad),
    ('core', 0x2332c53, '7433', 0x2332c88),
    ('core', 0x2332c9e, '7528', 0x2332cc8),
    ('outer_shared', 0x4446292, '0f85e5000000', 0x444637d),
    ('outer_shared', 0x44462c0, '0f8539020000', 0x44464ff),
    ('outer_shared', 0x44462e0, '744f', 0x4446331),
    ('outer_shared', 0x4446321, '0f85f2010000', 0x4446519),
    ('outer_shared', 0x444632f, '75cf', 0x4446300),
    ('outer_shared', 0x4446390, '0f84c5010000', 0x444655b),
    ('outer_shared', 0x44463e5, '7549', 0x4446430),
    ('outer_shared', 0x4446418, '0f859d000000', 0x44464bb),
    ('outer_shared', 0x4446421, '754a', 0x444646d),
    ('outer_shared', 0x444644f, '753f', 0x4446490),
    ('outer_shared', 0x4446458, '0f84ee000000', 0x444654c),
    ('outer_shared', 0x4446467, '0f84c4feffff', 0x4446331),
    ('outer_shared', 0x444647d, '75b1', 0x4446430),
    ('outer_shared', 0x44464b5, '0f8463ffffff', 0x444641e),
    ('outer_shared', 0x44464e4, '7454', 0x444653a),
    ('outer_shared', 0x44464e9, '744f', 0x444653a),
    ('side_shared', 0x4440d80, '7521', 0x4440da3),
    ('side_shared', 0x4440d9d, '0f84e0010000', 0x4440f83),
    ('side_shared', 0x4440dad, '754f', 0x4440dfe),
    ('side_shared', 0x4440dc7, '0f85be000000', 0x4440e8b),
    ('side_shared', 0x4440e16, '0f85ac000000', 0x4440ec8),
    ('side_shared', 0x4440e6f, '747b', 0x4440eec),
    ('side_shared', 0x4440ef2, '0f85b4000000', 0x4440fac),
    ('side_shared', 0x4440f0e, '0f8550020000', 0x4441164),
    ('side_shared', 0x4440f3c, '0f84cb000000', 0x444100d),
    ('side_shared', 0x4440f45, '0f8409010000', 0x4441054),
    ('side_shared', 0x4440f70, '0f8497000000', 0x444100d),
    ('side_shared', 0x4440fba, '0f8467030000', 0x4441327),
    ('side_shared', 0x4441017, '743b', 0x4441054),
    ('side_shared', 0x4441045, '0f8560020000', 0x44412ab),
    ('side_shared', 0x4441052, '75dc', 0x4441030),
    ('side_shared', 0x4441091, '0f8565020000', 0x44412fc),
    ('side_shared', 0x44410c3, '741a', 0x44410df),
    ('side_shared', 0x44410e5, '0f859c000000', 0x4441187),
    ('side_shared', 0x4441101, '7561', 0x4441164),
    ('side_shared', 0x444112b, '0f84b7000000', 0x44411e8),
    ('side_shared', 0x444113c, '0f84f2000000', 0x4441234),
    ('side_shared', 0x4441159, '0f8517feffff', 0x4440f76),
    ('side_shared', 0x4441195, '0f848c010000', 0x4441327),
    ('side_shared', 0x44411fa, '7438', 0x4441234),
    ('side_shared', 0x4441225, '0f8580000000', 0x44412ab),
    ('side_shared', 0x4441232, '75dc', 0x4441210),
    ('side_shared', 0x4441263, '0f8593000000', 0x44412fc),
    ('level_shared', 0x43c6249, '0f818b000000', 0x43c62da),
    ('level_shared', 0x43c6273, '0f8597000000', 0x43c6310),
    ('level_shared', 0x43c6292, '757c', 0x43c6310),
    ('level_shared', 0x43c62b7, '747f', 0x43c6338),
    ('level_shared', 0x43c62f3, '7530', 0x43c6325),
    ('level_shared', 0x43c62fc, '0f842b030000', 0x43c662d),
    ('level_shared', 0x43c635f, '755a', 0x43c63bb),
    ('level_shared', 0x43c63ab, '0f848a000000', 0x43c643b),
    ('level_shared', 0x43c644c, '0f8409010000', 0x43c655b),
    ('level_shared', 0x43c645a, '7548', 0x43c64a4),
    ('level_shared', 0x43c648e, '0f8532010000', 0x43c65c6),
)
CALL_PINS = (
    ('builder_to_constructor', 0x275622d, 'e8ae18c4ff', 0x2397ae0),
    ('constructor_first_tree', 0x2397be6, 'e8458d3100', 0x26b0930),
    ('constructor_second_tree', 0x2397ce7, 'e8448c3100', 0x26b0930),
    ('tree_to_slots', 0x26b0b50, 'e87b76ebff', 0x25681d0),
    ('low_hash_to_outer', 0x2818a4c, 'e8ff4864ff', 0x1e5d350),
    ('outer_array_header', 0x1e5d3b2, 'e819c87400', 0x25a9bd0),
    ('outer_side_direct', 0x1e5d411, 'e81a2affff', 0x1e4fe30),
    ('outer_side_buffered', 0x1e5d545, 'e8e637ffff', 0x1e50d30),
    ('outer_array_finish', 0x1e5d470, 'e83b49f7ff', 0x1dd1db0),
    ('side_pair_header', 0x1e4fed9, 'e8f29c7500', 0x25a9bd0),
    ('first_side_header', 0x1e4ffd1, 'e8fa9b7500', 0x25a9bd0),
    ('first_side_level', 0x1e50109, 'e8e293f8ff', 0x1dd94f0),
    ('first_side_finish', 0x1e50149, 'e8621cf8ff', 0x1dd1db0),
    ('second_side_header', 0x1e501c4, 'e8079a7500', 0x25a9bd0),
    ('second_side_level', 0x1e502e9, 'e80292f8ff', 0x1dd94f0),
    ('second_side_finish', 0x1e50329, 'e8821af8ff', 0x1dd1db0),
    ('side_pair_finish', 0x1e50371, 'e84a28fcff', 0x1e12bc0),
    ('level_buffered', 0x1dd95b5, 'e8f62f0300', 0x1e0c5b0),
    ('level_price', 0x1dd9554, 'e8772b7d00', 0x25ac0d0),
    ('level_orders_header', 0x1dd9621, 'e8aa057d00', 0x25a9bd0),
    ('level_record_direct', 0x1dd974e, 'e81d9d5500', 0x2333470),
    ('level_record_buffered', 0x1dd97a7, 'e834a05500', 0x23337e0),
    ('level_orders_finish', 0x1dd9853, 'e85885ffff', 0x1dd1db0),
    ('level_pair_finish', 0x1dd988f, 'e82c930300', 0x1e12bc0),
    ('buffered_level_record', 0x1e0c7e9, 'e8f26f5200', 0x23337e0),
    ('record_generic_map', 0x23334a4, 'e8d75a2700', 0x25a8f80),
    ('record_generic_resting', 0x2333588, 'e8438b2700', 0x25ac0d0),
    ('record_generic_original', 0x23335d7, 'e8f48a2700', 0x25ac0d0),
    ('record_generic_user', 0x233361c, 'e8bfc1b4ff', 0x1e7f7e0),
    ('record_generic_tif_null', 0x233366b, 'e85093b1ff', 0x1e4c9c0),
    ('record_core_generic', 0x2333745, 'e866ff0900', 0x23d36b0),
    ('record_oid_generic', 0x2333769, 'e8524f0a00', 0x23d86c0),
    ('oid_generic_value', 0x23d8703, 'e8c8391d00', 0x25ac0d0),
    ('record_core_buffered', 0x2333a53, 'e8581f0a00', 0x23d59b0),
    ('record_oid_buffered', 0x2333a77, 'e8f4520a00', 0x23d8d70),
    ('core_buffered_tail', 0x23d59fe, 'e9bdcef5ff', 0x23328c0),
    ('core_generic_tail', 0x23d36ec, 'e91fe9f5ff', 0x2332010),
    ('core_generic_R', 0x23321ff, 'e8ac510a00', 0x23d73b0),
    ('core_generic_d', 0x233222a, 'e8b13c0a00', 0x23d5ee0),
    ('core_generic_c', 0x2332261, 'e8fa340a00', 0x23d5760),
    ('core_generic_b', 0x2332285, 'e8766c0a00', 0x23d8f00),
    ('core_generic_s_value', 0x2332312, 'e8d9842700', 0x25aa7f0),
    ('core_generic_l_value', 0x2332350, 'e87b9d2700', 0x25ac0d0),
    ('core_R_field', 0x2332af9, 'e8c2160a00', 0x23d41c0),
    ('core_d_field', 0x2332b22, 'e849210a00', 0x23d4c70),
    ('core_s_field', 0x2332c36, 'e8651b0a00', 0x23d47a0),
    ('shared_hash_to_outer', 0x4ae79ac, 'e89fe895ff', 0x4446250),
    ('shared_outer_side_direct', 0x4446311, 'e84aaaffff', 0x4440d60),
    ('shared_outer_side_buffered', 0x4446445, 'e8e64dffff', 0x443b230),
    ('shared_first_side_level', 0x4441039, 'e8e251f8ff', 0x43c6220),
    ('shared_second_side_level', 0x4441219, 'e80250f8ff', 0x43c6220),
    ('shared_level_record', 0x43c647e, 'e86d136200', 0x49e77f0),
)

FIELDS = (
    # name, name-LEA, length-instruction, value-instruction, expected value bytes
    ('is_position_tpsl', 0x23334f3, 0x23334fa, 0x23334e6, '450fb67c2435'),
    ('resting_sz', 0x2333559, 0x2333560, 0x233357c, '498b5500'),
    ('orig_sz', 0x23335ad, 0x23335b4, 0x23335cb, '498b5508'),
    ('user', 0x23335f2, 0x23335f9, 0x2333610, '498d7520'),
    ('tif', 0x2333638, 0x233363f, 0x2333656, '498d7534'),
    ('core', 0x23d36c1, 0x23d36c8, 0x2333739, '498b5518'),
    ('oid', 0x2333755, 0x2333761, 0x2333751, '4d8b4510'),
)

CORE_NAMES = (
    ('t', 0x23320f6, 0x23320fd, 't'),
    ('S', 0x2332149, 0x2332150, 'S'),
    ('r', 0x2332193, 0x233219a, 'r'),
    ('R', 0x23d73d7, 0x23d73de, 'R'),
    ('d', 0x23d5efd, 0x23d5f04, 'd'),
    ('c', 0x233224d, 0x2332259, 'c'),
    ('b', 0x23d8f1a, 0x23d8f21, 'b'),
    ('s', 0x23322a5, 0x23322ac, 's'),
    ('l', 0x233232b, 0x2332332, 'l'),
    ('side_bit_zero', 0x2332303, 0x233230a, 'B'),
    ('side_bit_one', 0x23322c8, 0x233230a, 'A'),
)

# Source and destination operands are extracted from the fixed encodings.
LAYOUT = (
    # label, source site, instruction bytes, displacement offset/size,
    # output site, instruction bytes, output displacement offset or None, width
    ('sizes', 0x256824c, '410f1086c8000000', 4, 4, 0x25682ad, '0f1100', None, 16),
    ('oid', 0x2568279, '4d8baed8000000', 3, 4, 0x25682b0, '4c896810', 3, 8),
    ('core_reference', 0x2568294, '4983c620', 3, 1, 0x25682b4, '4c897018', 3, 8),
    ('user_first', 0x2568264, '410f1086e0000000', 4, 4, 0x25682a4, '0f114020', 3, 16),
    ('user_last', 0x2568259, '418b86f0000000', 3, 4, 0x256829c, '894830', 2, 4),
    ('tif', 0x2568271, '450fb6a6f5000000', 4, 4, 0x25682b8, '44886034', 3, 1),
    ('is_position_tpsl', 0x2568244, '410fb6aef4000000', 4, 4, 0x25682bc, '40886835', 3, 1),
)

# These immediate operands are interpreted only after the complete instruction
# forms have matched the authenticated code. Values are read from the ELF.
PREDICATES = (
    ('head_present_tag', 0x25681e1, '833e01', 2, 1),
    ('slab_slot_stride', 0x25681f8, '4869c0f8000000', 3, 4),
    ('vacant_slot_tag', 0x25681ff, '41833c0602', 4, 1),
    ('initial_allocation_bytes', 0x2568280, 'bfe0000000', 1, 4),
    ('initial_capacity', 0x25682c0, '48c744241804000000', 5, 4),
    ('initial_length', 0x25682ce, '48c744242801000000', 5, 4),
    ('order_record_stride', 0x256833f, '4883c538', 3, 1),
    ('growth_element_stride', 0x25683e4, '41b838000000', 2, 4),
    ('tree_level_shift', 0x26b0b2f, '48c1e205', 3, 1),
    ('side_map_stride', 0x1e5d427, '4983c630', 3, 1),
    ('price_level_stride', 0x1e5011b, '4983c520', 3, 1),
    ('named_record_marker_base', 0x2333805, '4080cd87', 3, 1),
    ('price_pair_length', 0x1dd9530, 'ba02000000', 1, 4),
)

# Small byte-checked anchors for synthetic empty-side examples. The first two
# helper ranges are previously studied boundaries, not new FDE ownership.
MODEL_ANCHORS = (
    ('fixarray_threshold', 0x25a9be9, '83fa10', 2, 1),
    ('fixarray_base', 0x25a9bef, 'bd90000000', 1, 4),
    ('fixarray_mask', 0x25acc63, '4080e60f', 3, 1),
    ('fixarray_or', 0x25acc67, '4080ce90', 3, 1),
    ('outer_option_word', 0x1e5d36b, 'c744244800040001c644244c00', 4, 4),
    ('outer_direct_mode', 0x1e5d36b, 'c744244800040001c644244c00', 12, 1),
    ('pair_size', 0x1e4fed4, 'ba02000000', 1, 4),
    ('first_array_finish_sentinel', 0x1dd1dc1, '49be0000000000000080488b1e4889d848f7d871164983c6044d8937', 2, 8),
    ('pair_finish_sentinel', 0x1e12bd1, '49be0000000000000080488b2e4889e848f7d8710c4983c6044c8933', 2, 8),
    ('pair_local_sentinel', 0x1e50339, '48b8000000000000008048890424', 2, 8),
    ('small_price_bound', 0x25ac0e0, '4881fa000100007346', 3, 4),
    ('small_price_sign_test', 0x25ac100, '84d20f8813010000', 0, 2),
    ('small_price_direct_store', 0x25ac111, '498b460888143049ff4610', 4, 3),
    ('small_price_prefix', 0x25ac228, 'c60430cc', 3, 1),
    ('small_price_suffix_store', 0x25ac2bf, '498b460888143049ff4610', 4, 3),
)

ORDER_MODEL_ANCHORS = (
    ('map_marker', 0x25a8f99, '83fa100fb6c0bd800000000f43e8', 7, 4),
    ('map_pack', 0x25acc54, '85c974f94080e60f4080ce8089f0c3', 11, 1),
    ('short_string', 0x25aa803, '488b1f83fa20731440b5a0', 10, 1),
    ('long_string', 0x25aa81f, '81fa00010000731440b5d9', 10, 1),
    ('order_field_count', 0x2333491, '807a0b007432488d7c24084c89f6ba07000000e8d75a2700', 15, 4),
    ('order_bool_base', 0x233352b, '4180cfc2410fb6ffe8e8962700', 3, 1),
    ('tif_null_tag', 0x233365a, '803e050f85c2000000488d7c24084c89f6e85093b1ff', 2, 1),
    ('null_marker', 0x1e4c9f4, 'c60431c048ff43104983c704', 3, 1),
    ('user_hex_lengths', 0x1e7f80d, '4889e7be2a000000b914000000', 4, 4),
    ('user_input_length', 0x1e7f80d, '4889e7be2a000000b914000000', 9, 4),
)

# The selected predicates are read together with their pinned branch and
# surrounding windows. Descriptions state the branch-taken condition only.
DECISIONS = {
    0x23320ed: ('core_generic_t_absent', 'core word at +0x88 is zero', 'omit t'),
    0x2332140: ('core_generic_S_absent', 'low byte of core word at +0 is zero', 'omit S'),
    0x233218a: ('core_generic_r_absent', 'core byte at +0x90 is zero', 'omit r'),
    0x23321f1: ('core_generic_R_absent', 'combined flag low bit is zero', 'omit R'),
    0x233221c: ('core_generic_d_absent', 'core word at +0x70 is zero', 'omit d'),
    0x2332244: ('core_generic_c_absent', 'core byte at +0x91 is zero', 'omit c'),
    0x2332277: ('core_generic_b_absent', 'low byte of core word at +0x48 is zero', 'omit b'),
    0x23322c6: ('core_generic_side_zero', 'bit zero of core byte at +0xa2 is clear', 'emit B rather than A'),
    0x26b0950: ('tree_empty', 'remaining selected tree entries are zero', 'return current output length'),
    0x26b0983: ('tree_invalid_iterator', 'iterator flag bit zero is clear', 'diagnostic then ud2'),
    0x26b0a6a: ('tree_missing_parent', 'parent pointer is zero during ascent', 'diagnostic then ud2'),
    0x26b0b90: ('tree_more', 'remaining entry count is nonzero', 'continue traversal'),
    0x25681e4: ('head_tag', 'head dword is not the present tag', 'return empty record vector'),
    0x25681f2: ('head_bounds', 'head index is at or above slab length', 'return empty record vector'),
    0x2568204: ('head_vacancy', 'slot dword is not the vacant tag', 'enter first record construction'),
    0x256828e: ('first_allocation', 'allocator returns zero', 'allocation failure path'),
    0x25682e2: ('first_next_tag', 'first slot next word is zero', 'return one-record vector'),
    0x2568353: ('next_tag', 'next word is zero', 'return accumulated prefix'),
    0x256835d: ('next_bounds', 'next index is at or above slab length', 'return accumulated prefix'),
    0x2568374: ('next_vacancy', 'next slot dword equals vacant tag', 'return accumulated prefix'),
    0x25683d4: ('vector_capacity', 'record count differs from capacity', 'append without growth'),
    0x1e5d392: ('outer_high_count', 'vector count has a nonzero high 32-bit half', 'enter buffered path'),
    0x1e5d3c0: ('outer_header_error', 'array header result is not 2', 'return header failure payload'),
    0x1e5d3e0: ('outer_empty', 'vector count is zero', 'finish without a side-map call'),
    0x1e5d421: ('outer_child_error', 'side-map result differs from success sentinel', 'return child failure'),
    0x1e5d42f: ('outer_more', 'remaining byte count is nonzero', 'advance to next side-map record'),
    0x1e5d490: ('outer_allocate', 'allocation returns zero', 'allocation failure path'),
    0x1e5d558: ('outer_counter', 'buffered count equals 0xffffffff', 'diagnostic then ud2'),
    0x1e4fe97: ('side_header_error_a', 'two-side header result is not 2', 'return header failure'),
    0x1e4fee6: ('side_header_error_b', 'two-side header result is not 2', 'return header failure'),
    0x1e4ffde: ('first_side_header_error', 'first side header result is not 2', 'return failure'),
    0x1e50115: ('first_side_level_error', 'first-side level result differs from success sentinel', 'return child failure'),
    0x1e50122: ('first_side_more', 'first-side current pointer differs from end', 'visit next level'),
    0x1e50161: ('first_side_finish_error', 'first-side finalizer result differs from success sentinel', 'return failure'),
    0x1e501d1: ('second_side_header_error', 'second side header result is not 2', 'return failure'),
    0x1e502f5: ('second_side_level_error', 'second-side level result differs from success sentinel', 'return child failure'),
    0x1e50302: ('second_side_more', 'second-side current pointer differs from end', 'visit next level'),
    0x1e50333: ('second_side_finish_error', 'second-side finalizer result differs from success sentinel', 'return failure'),
    0x1dd9519: ('level_buffering', 'zero minus buffer word does not set signed overflow', 'delegate to buffered level writer'),
    0x1dd9543: ('level_pair_header_error', 'pair header result is not 2', 'return failure'),
    0x1dd9562: ('level_price_error', 'price result is not 2', 'return failure'),
    0x1dd95cc: ('level_counter', 'buffered count equals 0xffffffff', 'diagnostic then ud2'),
    0x1dd962f: ('level_orders_header_error', 'order-list header result is not 2', 'return failure'),
    0x1dd975e: ('level_order_error', 'order result differs from success sentinel', 'return failure'),
    0x233380c: ('record_no_capacity', 'output length equals capacity', 'request buffer growth'),
    0x233382e: ('record_names_mode', 'name mode byte is not 1', 'skip first field name'),
    0x23338fb: ('resting_size_error', 'size writer result is not 2', 'return failure'),
    0x2333965: ('original_size_error', 'size writer result is not 2', 'return failure'),
    0x233399e: ('user_error', 'user writer result differs from success sentinel', 'return failure'),
    0x23339c8: ('tif_variant', 'tif byte differs from 5', 'call alternate tif writer'),
    0x2333a5d: ('core_error', 'core writer result differs from success sentinel', 'return failure'),
    0x2333a81: ('oid_error', 'oid writer result differs from success sentinel', 'return failure'),
    0x2332984: ('core_t_absent', 'core word at +0x88 is zero', 'omit t'),
    0x23329ec: ('core_S_absent', 'low byte of core word at +0 is zero', 'omit S'),
    0x2332a4b: ('core_r_absent', 'core byte at +0x90 is zero', 'omit r'),
    0x2332aeb: ('core_R_absent', 'combined flag low bit is zero', 'omit R'),
    0x2332b11: ('core_d_absent', 'core word at +0x70 is zero', 'omit d'),
    0x2332b3c: ('core_c_absent', 'core byte at +0x91 is zero', 'omit c'),
    0x2332bc9: ('core_b_absent', 'low byte of core word at +0x48 is zero', 'omit b'),
}

TWINS = (
    ('outer', 0x1e5d350, 0x4446250),
    ('side', 0x1e4fe30, 0x4440d60),
    ('side_buffered', 0x1e50d30, 0x443b230),
    ('level', 0x1dd94f0, 0x43c6220),
)


def require(ok, message):
    if not ok:
        raise ValueError(message)


def verify_digest(data):
    require(hashlib.sha256(data).hexdigest() == SHA256, 'target SHA-256 mismatch')


def location(secs, data_length, va, size, executable=False):
    """Find one wholly file-backed section; never map SHT_NOBITS."""
    require(type(va) is int and type(size) is int and va >= 0 and size > 0,
            'invalid virtual range')
    require(va + size <= 1 << 64, 'virtual range overflow')
    matches = [s for s in secs if s['type'] != 8 and (not executable or s['flags'] & 4)
               and s['address'] <= va and va + size <= s['address'] + s['size']]
    require(len(matches) == 1, 'virtual range is unmapped or ambiguous')
    sec = matches[0]
    off = sec['offset'] + va - sec['address']
    require(off >= 0 and off + size <= data_length, 'file range outside input')
    return sec, off


def read(data, secs, va, size, executable=False):
    _, off = location(secs, len(data), va, size, executable)
    return bytes(data[off:off + size])


def check_bytes(data, secs, va, expected, executable=True):
    expected = bytes.fromhex(expected) if isinstance(expected, str) else expected
    raw = read(data, secs, va, len(expected), executable)
    require(raw == expected, f'changed selected bytes at {va:#x}')
    return raw


def check_frames(data, secs):
    _, frames, _ = fde_extents(data)
    selected = {}
    for frame in frames:
        if frame['start'] in FDE_PINS:
            start = frame['start']
            require(start not in selected and 'index' in frame, 'ambiguous or unindexed FDE')
            end, digest = FDE_PINS[start]
            require(frame['end'] == end, f'changed FDE range at {start:#x}')
            raw = read(data, secs, start, end - start, True)
            require(hashlib.sha256(raw).hexdigest() == digest, f'changed body at {start:#x}')
            selected[start] = frame
    require(set(selected) == set(FDE_PINS), 'selected FDE is missing')
    return selected


def check_boundaries(data, secs):
    for name, start, end, digest in BOUNDARIES:
        raw = read(data, secs, start, end - start, True)
        require(hashlib.sha256(raw).hexdigest() == digest, 'changed boundary ' + name)


def owner_of(va, size=1):
    owners = [start for start, (end, _) in FDE_PINS.items() if start <= va and va + size <= end]
    require(len(owners) == 1, f'site outside selected FDEs: {va:#x}')
    return owners[0]


def branch_at(data, secs, site, expected, target):
    raw = check_bytes(data, secs, site, expected)
    if len(raw) == 2 and 0x70 <= raw[0] <= 0x7f:
        displacement = struct.unpack('<b', raw[1:])[0]
    elif len(raw) == 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        displacement = struct.unpack('<i', raw[2:])[0]
    else:
        raise ValueError('unsupported conditional branch')
    dest = site + len(raw) + displacement
    require(dest == target, 'branch target changed')
    owner = owner_of(site, len(raw))
    require(owner <= dest < FDE_PINS[owner][0], 'branch leaves selected FDE')
    return owner, raw, dest


def transfer_at(data, secs, site, expected, target):
    raw = check_bytes(data, secs, site, expected)
    require(len(raw) == 5 and raw[0] in (0xe8, 0xe9), 'unsupported relative transfer')
    dest = site + len(raw) + struct.unpack('<i', raw[1:])[0]
    require(dest == target, 'transfer target changed')
    location(secs, len(data), dest, 1, True)
    return raw, dest


def decode_lea(data, secs, va):
    raw = read(data, secs, va, 7, True)
    require(raw[:3] in (b'\x48\x8d\x35', b'\x48\x8d\x15', b'\x4c\x8d\x3d'),
            'unsupported selected RIP-relative LEA')
    return raw, va + 7 + struct.unpack('<i', raw[3:])[0]


def decode_length(data, secs, va):
    raw = read(data, secs, va, 5, True)
    require(raw[0] in (0xba, 0xb9), 'unsupported length setup')
    return raw, struct.unpack('<I', raw[1:])[0]


def field_rows(data, secs):
    rows = []
    for order, (name, lea, length_site, value_site, value_hex) in enumerate(FIELDS):
        lea_raw, target = decode_lea(data, secs, lea)
        len_raw, length = decode_length(data, secs, length_site)
        literal = read(data, secs, target, length)
        require(literal == name.encode('ascii'), 'changed field literal')
        value_raw = check_bytes(data, secs, value_site, value_hex)
        source_offset = value_raw[-1]
        _, file_off = location(secs, len(data), target, length)
        rows.append((order, name, hex(lea), lea_raw.hex(), hex(length_site), len_raw.hex(),
                     hex(target), hex(file_off), length, literal.hex(), hex(value_site),
                     value_raw.hex(), hex(source_offset)))
    return rows


def core_name_rows(data, secs):
    rows = []
    for label, lea_site, length_site, text_value in CORE_NAMES:
        lea, literal_va = decode_lea(data, secs, lea_site)
        length_raw, length = decode_length(data, secs, length_site)
        raw = read(data, secs, literal_va, length)
        require(raw == text_value.encode('ascii'), 'changed core literal')
        _, offset = location(secs, len(data), literal_va, length)
        rows.append((label, hex(lea_site), lea.hex(), hex(length_site), length_raw.hex(),
                     hex(literal_va), hex(offset), length, raw.hex(), raw.decode('ascii')))
    return rows


def layout_rows(data, secs):
    rows = []
    for name, source, source_hex, pos, size, dest, dest_hex, dst_pos, width in LAYOUT:
        src = check_bytes(data, secs, source, source_hex)
        dst = check_bytes(data, secs, dest, dest_hex)
        offset = int.from_bytes(src[pos:pos + size], 'little')
        dst_offset = 0 if dst_pos is None else dst[dst_pos]
        rows.append((name, hex(source), src.hex(), hex(offset), hex(dest), dst.hex(),
                     hex(dst_offset), width))
    return rows


def predicate_rows(data, secs):
    rows = []
    for label, site, expected, pos, width in PREDICATES:
        raw = check_bytes(data, secs, site, expected)
        value = int.from_bytes(raw[pos:pos + width], 'little')
        rows.append((label, hex(site), raw.hex(), pos, width, hex(value)))
    check_bytes(data, secs, 0x26b0b5b, '48f7d8480f48c5')
    return rows


def decision_rows(branches):
    by_site = {int(row[2], 16): row for row in branches}
    output = []
    for site in sorted(DECISIONS):
        require(site in by_site, 'decision lacks selected branch')
        label, condition, effect = DECISIONS[site]
        row = by_site[site]
        output.append((label, row[1], row[2], row[4], row[5], row[6], condition, effect))
    return output


def side_names(data, secs):
    rows = []
    for lane, va, length_site in (('low', 0x1e5d3e2, 0x1e5d400),
                                   ('shared', 0x44462e2, 0x4446300)):
        lea, target = decode_lea(data, secs, va)
        length_raw, length = decode_length(data, secs, length_site)
        raw = read(data, secs, target, length)
        require(raw == b'SideMap', 'changed SideMap literal')
        _, off = location(secs, len(data), target, length)
        rows.append((lane, hex(va), lea.hex(), hex(length_site), length_raw.hex(),
                     hex(target), hex(off), length, raw.hex(), raw.decode('ascii')))
    return rows


def closure_results(data, secs):
    """Read the result guards immediately after each pre-existing job call."""
    rows = []
    for lane, site in (('low', 0x2818a51), ('shared', 0x4ae79b1)):
        raw = read(data, secs, site, 0x2a, True)
        require(raw[:10] == bytes.fromhex('4c8bb4240801000048b8'), 'changed result setup')
        require(raw[18:23] == bytes.fromhex('4939c60f85'), 'changed result comparison')
        require(raw[27:] == bytes.fromhex('4c8b7424204c8b7c2428488b542430'),
                'changed result success path')
        sentinel = struct.unpack('<Q', raw[10:18])[0]
        require(sentinel == 0x8000000000000004, 'changed success sentinel')
        branch = site + 21
        target = branch + 6 + struct.unpack('<i', raw[23:27])[0]
        require(target == site + 0x111, 'changed result failure target')
        _, off = location(secs, len(data), site, len(raw), True)
        rows.append((lane, hex(site), hex(off), raw.hex(), hex(sentinel),
                     hex(branch), raw[21:27].hex(), hex(branch + 6), hex(target)))
    return rows


def empty_examples(data, secs):
    """Synthetic valid empty-side shapes, conditional on successful helpers."""
    anchors = []
    values = {}
    for label, site, expected, pos, size in MODEL_ANCHORS:
        raw = check_bytes(data, secs, site, expected)
        value = int.from_bytes(raw[pos:pos + size], 'little')
        values[label] = value
        _, off = location(secs, len(data), site, len(raw), True)
        anchors.append((label, hex(site), hex(off), raw.hex(), pos, size, hex(value)))
    base = values['fixarray_base']
    limit = values['fixarray_threshold']
    mask = values['fixarray_mask']
    pair = values['pair_size']
    require(base == values['fixarray_or'] and mask + 1 == limit and pair == 2,
            'incompatible marker operands')
    require(values['outer_option_word'] == 0x01000400 and values['outer_direct_mode'] == 0,
            'unexpected outer writer options')
    require(values['first_array_finish_sentinel'] == values['pair_finish_sentinel']
            == values['pair_local_sentinel'] == 0x8000000000000000,
            'unexpected direct finisher sentinel')
    # Check the count-zero loop exits and all calls on the direct model path.
    check_bytes(data, secs, 0x1e5d3dd, '4d85ff744f')
    check_bytes(data, secs, 0x1e500e4, '4d39fd743b')
    check_bytes(data, secs, 0x1e502c7, '4939ec7438')
    labels = {'outer_array_header', 'outer_side_direct', 'outer_array_finish',
              'side_pair_header', 'first_side_header', 'first_side_finish',
              'second_side_header', 'second_side_finish', 'side_pair_finish'}
    for label, site, raw, target in CALL_PINS:
        if label in labels:
            transfer_at(data, secs, site, raw, target)
    # Input counts are synthetic; bytes are the direct-path prediction only.
    rows = []
    for n in range(limit):
        wire = bytes((base | (n & mask),)) + bytes((base | pair, base, base)) * n
        rows.append((n, 0, 0, len(wire), wire.hex()))
    # A synthetic level with an empty order list is a corruption control; its
    # reachability in a valid book is deliberately not assumed.
    price_limit, prefix = values['small_price_bound'], values['small_price_prefix']
    require(price_limit == 0x100 and prefix == 0xcc, 'changed small-price encoding')
    for label, site, raw, target in CALL_PINS:
        if label in {'first_side_level', 'level_price', 'level_orders_header',
                     'level_orders_finish', 'level_pair_finish'}:
            transfer_at(data, secs, site, raw, target)
    check_bytes(data, secs, 0x1dd9719, '4d39ef0f8409010000')
    examples = []
    for price in (0, 1, price_limit // 2 - 1, price_limit // 2, price_limit - 1):
        number = bytes((price,)) if price < price_limit // 2 else bytes((prefix, price))
        wire = bytes((base | 1, base | pair, base | 1, base | pair)) + number + bytes((base, base))
        examples.append((price, number.hex(), len(wire), wire.hex()))
    return anchors, rows, examples


def hash_parameters(data, secs):
    """Read the prior closure's hash setup and prior round table as context."""
    setup = check_bytes(data, secs, 0x2818add, '48c78424f00000008800000066c78424f80000000100')
    rate = struct.unpack('<I', setup[8:12])[0]
    delimiter = struct.unpack('<H', setup[20:22])[0]
    output = check_bytes(data, secs, 0x2818b1f, 'ba20000000')
    output_size = struct.unpack('<I', output[1:])[0]
    lea = check_bytes(data, secs, 0x4f598f0, '4c8d05d16b87fb')
    table_va = 0x4f598f0 + len(lea) + struct.unpack('<i', lea[3:])[0]
    loop = check_bytes(data, secs, 0x4f59916, '4883c2084881fac0000000')
    step = loop[3]
    size = struct.unpack('<I', loop[7:11])[0]
    require(step == 8 and size % step == 0 and rate == 136 and delimiter == 1
            and output_size == 32, 'unexpected prior hash parameters')
    raw = read(data, secs, table_va, size)
    require(hashlib.sha256(raw).hexdigest() == 'f8e6964adffc257265537256d21e93496a17b9271dc5d64f40869eeeaaff6fbb',
            'changed prior round table')
    rounds = tuple(struct.unpack('<' + 'Q' * (size // step), raw))
    _, file_off = location(secs, len(data), table_va, size)
    rows = [('closure_setup', hex(0x2818add), '', setup.hex(), hex(rate), hex(delimiter)),
            ('output_length', hex(0x2818b1f), '', output.hex(), hex(output_size), ''),
            ('round_pointer', hex(0x4f598f0), '', lea.hex(), hex(table_va), ''),
            ('round_loop', hex(0x4f59916), '', loop.hex(), hex(step), hex(size)),
            ('round_table', hex(table_va), hex(file_off), raw.hex(), hex(len(rounds)),
             hashlib.sha256(raw).hexdigest())]
    return rows, rate, delimiter, output_size, rounds


def one_order_example(data, secs):
    """Conditional, synthetic named-order example, not captured node output."""
    values, anchors = {}, []
    for label, site, expected, pos, size in ORDER_MODEL_ANCHORS:
        raw = check_bytes(data, secs, site, expected)
        value = int.from_bytes(raw[pos:pos + size], 'little')
        values[label] = value
        _, off = location(secs, len(data), site, len(raw), True)
        anchors.append((label, hex(site), hex(off), raw.hex(), pos, size, hex(value)))
    require(values['map_marker'] == values['map_pack'] == 0x80
            and values['order_field_count'] == 7 and values['short_string'] == 0xa0
            and values['long_string'] == 0xd9 and values['order_bool_base'] == 0xc2
            and values['tif_null_tag'] == 5 and values['null_marker'] == 0xc0,
            'changed named order model')
    user_len = values['user_input_length']
    require(user_len == 20 and values['user_hex_lengths'] == 2 + 2*user_len,
            'changed user hex lengths')
    labels = {'record_generic_map', 'record_generic_resting', 'record_generic_original',
              'record_generic_user', 'record_generic_tif_null', 'record_core_generic',
              'record_oid_generic', 'oid_generic_value', 'core_generic_tail',
              'core_generic_s_value', 'core_generic_l_value'}
    for label, site, raw, target in CALL_PINS:
        if label in labels:
            transfer_at(data, secs, site, raw, target)
    fields = {row[1]: bytes.fromhex(row[9]) for row in field_rows(data, secs)}
    names = {row[0]: bytes.fromhex(row[8]) for row in core_name_rows(data, secs)}
    def short(raw):
        require(len(raw) < 32, 'model string is not short')
        return bytes((values['short_string'] | len(raw),)) + raw
    user = b'0x' + bytes(user_len).hex().encode('ascii')
    require(len(user) == values['user_hex_lengths'], 'bad user encoding length')
    byte_one = bytes((1,))  # Synthetic input amount, price, oid and core l.
    core = (bytes((values['map_marker'] | 2,)) + short(names['s'])
            + short(names['side_bit_zero']) + short(names['l']) + byte_one)
    order = (bytes((values['map_marker'] | values['order_field_count'],))
             + short(fields['is_position_tpsl']) + bytes((values['order_bool_base'],))
             + short(fields['resting_sz']) + byte_one + short(fields['orig_sz']) + byte_one
             + short(fields['user']) + bytes((values['long_string'], len(user))) + user
             + short(fields['tif']) + bytes((values['null_marker'],))
             + short(fields['core']) + core + short(fields['oid']) + byte_one)
    # One book, one first-side level, one order; second side empty. The
    # structural markers come from the previously checked ELF operands.
    structure, _, _ = empty_examples(data, secs)
    array_base = int(next(row[-1] for row in structure if row[0] == 'fixarray_base'), 16)
    pair_size = int(next(row[-1] for row in structure if row[0] == 'pair_size'), 16)
    shape = bytes((array_base | 1, array_base | pair_size, array_base | 1,
                   array_base | pair_size, 1, array_base | 1)) + order + bytes((array_base,))
    return anchors, shape


def keccak_model(message, rate, delimiter, output_size, rounds):
    """Independent Keccak sponge model, used only for synthetic examples."""
    require(rate == 136 and len(rounds) == 24 and 0 < delimiter < 128
            and 0 < output_size <= rate, 'unsupported sponge parameters')
    mask = (1 << 64) - 1
    rotations = [0] * 25
    x, y = 1, 0
    for t in range(24):
        rotations[x + 5*y] = ((t + 1) * (t + 2) // 2) % 64
        x, y = y, (2*x + 3*y) % 5

    def rol(word, count):
        return ((word << count) | (word >> ((64 - count) % 64))) & mask

    padded = bytearray(message)
    padded.append(delimiter)
    padded.extend(b'\0' * ((-len(padded)) % rate))
    padded[-1] |= 0x80
    state = [0] * 25
    for start in range(0, len(padded), rate):
        block = padded[start:start + rate]
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(block[8*i:8*i + 8], 'little')
        for rc in rounds:
            columns = [state[x] ^ state[x+5] ^ state[x+10] ^ state[x+15] ^ state[x+20]
                       for x in range(5)]
            d = [columns[(x-1) % 5] ^ rol(columns[(x+1) % 5], 1) for x in range(5)]
            rotated = [0] * 25
            for y in range(5):
                for x in range(5):
                    rotated[y + 5*((2*x + 3*y) % 5)] = rol(state[x + 5*y] ^ d[x], rotations[x + 5*y])
            for y in range(5):
                for x in range(5):
                    state[x + 5*y] = rotated[x + 5*y] ^ ((~rotated[(x+1) % 5 + 5*y])
                                                          & rotated[(x+2) % 5 + 5*y])
            state[0] ^= rc
    return b''.join(word.to_bytes(8, 'little') for word in state)[:output_size]


def parse_lsda(data, secs, frame):
    """Decode selected call-site tables; action chains and types remain opaque."""
    va = frame['lsda']
    if va is None:
        return None, []
    sec, off = location(secs, len(data), va, 3)
    require(sec['name'] == '.gcc_except_table', 'unexpected LSDA section')
    end_section = sec['offset'] + sec['size']
    pos = off
    require(data[pos] == 0xff, 'unsupported LSDA landing-base encoding')
    type_encoding = data[pos + 1]
    require(type_encoding in (0xff, 0x9b), 'unsupported LSDA type encoding')
    pos += 2
    if type_encoding == 0x9b:
        distance, pos = uleb(data, pos, end_section)
        type_base = pos + distance
        require(type_base <= end_section, 'LSDA type table outside section')
    else:
        type_base = end_section
    require(pos < end_section and data[pos] == 1, 'unsupported LSDA call-site encoding')
    length, pos = uleb(data, pos + 1, end_section)
    end = pos + length
    require(end <= min(end_section, type_base), 'LSDA call-site table out of bounds')
    entries = []
    previous = frame['start']
    while pos < end:
        start_off = pos
        values = []
        for _ in range(4):
            value, pos = uleb(data, pos, end)
            values.append(value)
        delta, size, landing, action = values
        begin = frame['start'] + delta
        limit = begin + size
        land = frame['start'] + landing if landing else None
        require(frame['start'] <= begin < limit <= frame['end'] and begin >= previous,
                'invalid LSDA call-site interval')
        require(land is None or frame['start'] <= land < frame['end'], 'invalid landing pad')
        entries.append({'owner': frame['start'], 'lsda': va, 'begin': begin, 'end': limit,
                        'landing': land, 'action': action, 'entry_offset': start_off,
                        'bytes': bytes(data[start_off:pos]).hex()})
        previous = limit
    require(pos == end, 'LSDA table length mismatch')
    return {'owner': frame['start'], 'va': va, 'offset': off, 'type_encoding': type_encoding,
            'bytes': bytes(data[off:end]).hex(), 'rows': len(entries)}, entries


def twin_rows(data, secs):
    """Report raw byte-difference runs; no bytes are masked or normalized."""
    rows = []
    for label, low, shared in TWINS:
        n = FDE_PINS[low][0] - low
        require(n == FDE_PINS[shared][0] - shared, 'paired FDE lengths differ')
        left, right = read(data, secs, low, n, True), read(data, secs, shared, n, True)
        i = 0
        while i < n:
            if left[i] == right[i]:
                i += 1
                continue
            begin = i
            while i < n and left[i] != right[i]:
                i += 1
            rows.append((label, hex(begin), hex(low + begin), hex(shared + begin),
                         left[begin:i].hex(), right[begin:i].hex(), i - begin))
    return rows


def table(out, name, columns, rows):
    with (out / name).open('w', encoding='utf-8', newline='') as handle:
        writer = csv.writer(handle, delimiter='\t', lineterminator='\n')
        writer.writerow(columns)
        writer.writerows(rows)


def extract(data, out):
    # Authenticate before parsing or creating output.
    verify_digest(data)
    secs = sections(data)
    frames = check_frames(data, secs)
    check_boundaries(data, secs)
    body_rows, extent_rows = [], []
    for start in sorted(frames):
        frame = frames[start]
        end = frame['end']
        _, off = location(secs, len(data), start, end - start, True)
        body = read(data, secs, start, end - start, True)
        extent_rows.append((hex(start), hex(end), end - start, hex(off), hex(frame['fde']),
                            hex(frame['cie']), '' if frame['lsda'] is None else hex(frame['lsda']),
                            frame['index'], hashlib.sha256(body).hexdigest()))
        body_rows.append((hex(start), hex(end), body.hex()))
    window_rows = []
    for name, start, end in WINDOWS:
        owner = owner_of(start, end - start)
        raw = read(data, secs, start, end - start, True)
        _, off = location(secs, len(data), start, len(raw), True)
        window_rows.append((name, 'new', hex(owner), hex(start), hex(end), hex(off), raw.hex()))
    for name, start, end, _ in BOUNDARIES:
        raw = read(data, secs, start, end - start, True)
        _, off = location(secs, len(data), start, len(raw), True)
        window_rows.append((name, 'prior boundary', '', hex(start), hex(end), hex(off), raw.hex()))
    branches = []
    for group, site, expected, target in BRANCH_PINS:
        owner, raw, dest = branch_at(data, secs, site, expected, target)
        _, off = location(secs, len(data), site, len(raw), True)
        branches.append((group, hex(owner), hex(site), hex(off), raw.hex(), hex(site + len(raw)), hex(dest)))
    transfers = []
    for label, site, expected, target in CALL_PINS:
        raw, dest = transfer_at(data, secs, site, expected, target)
        new_owners = [start for start, (end, _) in FDE_PINS.items() if start <= site < end]
        _, off = location(secs, len(data), site, len(raw), True)
        transfers.append((label, 'new' if new_owners else 'prior boundary',
                          hex(new_owners[0]) if new_owners else '', hex(site), hex(off),
                          raw.hex(), 'call' if raw[0] == 0xe8 else 'tail', hex(dest)))
    fields = field_rows(data, secs)
    core_names = core_name_rows(data, secs)
    layout = layout_rows(data, secs)
    predicates = predicate_rows(data, secs)
    decisions = decision_rows(branches)
    names = side_names(data, secs)
    results = closure_results(data, secs)
    model_anchors, examples, level_examples = empty_examples(data, secs)
    hash_rows, rate, delimiter, digest_size, rounds = hash_parameters(data, secs)
    order_model_anchors, order_input = one_order_example(data, secs)
    order_digest = keccak_model(order_input, rate, delimiter, digest_size, rounds)
    digests = [(row[0], row[-1],
                keccak_model(bytes.fromhex(row[-1]), rate, delimiter, digest_size, rounds).hex())
               for row in examples]
    diffs = twin_rows(data, secs)
    headers, lsda_entries = [], []
    for start in sorted(frames):
        header, entries = parse_lsda(data, secs, frames[start])
        if header is not None:
            headers.append(header)
            lsda_entries.extend(entries)
    links = []
    for label, site, expected, target in CALL_PINS:
        if bytes.fromhex(expected)[0] != 0xe8:
            continue  # A tail jump has no call return-PC to look up.
        if not any(start <= site < end for start, (end, _) in FDE_PINS.items()):
            continue
        owner = owner_of(site, len(bytes.fromhex(expected)))
        lookup = site + len(bytes.fromhex(expected)) - 1
        found = [r for r in lsda_entries if r['owner'] == owner and r['begin'] <= lookup < r['end']]
        require(len(found) <= 1, 'overlapping LSDA call-site intervals')
        row = found[0] if found else None
        status = 'no LSDA' if frames[owner]['lsda'] is None else ('uncovered' if row is None else 'covered')
        links.append((label, hex(owner), hex(site), hex(lookup), status,
                      '' if row is None else hex(row['begin']),
                      '' if row is None else hex(row['end']),
                      '' if row is None or row['landing'] is None else hex(row['landing']),
                      '' if row is None else row['action']))
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    table(out, 'extents.tsv', ('start_va','end_va','bytes','file_offset','fde_va','cie_va','lsda_va','index','sha256'), extent_rows)
    table(out, 'bodies.tsv', ('start_va','end_va','bytes_hex'), body_rows)
    table(out, 'windows.tsv', ('label','ownership','owner_va','start_va','end_va','file_offset','bytes_hex'), window_rows)
    table(out, 'branches.tsv', ('group','owner_va','site_va','file_offset','bytes_hex','fallthrough_va','target_va'), branches)
    table(out, 'transfers.tsv', ('label','ownership','owner_va','site_va','file_offset','bytes_hex','kind','target_va'), transfers)
    table(out, 'order-fields.tsv', ('order','name','lea_va','lea_hex','length_va','length_hex','literal_va','file_offset','length','literal_hex','value_va','value_hex','record_offset'), fields)
    table(out, 'core-names.tsv', ('label','lea_va','lea_hex','length_va','length_hex','literal_va','file_offset','length','literal_hex','text'), core_names)
    table(out, 'slot-layout.tsv', ('label','source_va','source_hex','slot_offset','destination_va','destination_hex','record_offset','width'), layout)
    table(out, 'predicates.tsv', ('label','site_va','bytes_hex','immediate_offset','immediate_bytes','value'), predicates)
    table(out, 'decisions.tsv', ('label','owner_va','site_va','bytes_hex','fallthrough_va','target_va','taken_when','taken_effect'), decisions)
    table(out, 'sidemap-names.tsv', ('lane','lea_va','lea_hex','length_va','length_hex','literal_va','file_offset','length','literal_hex','text'), names)
    table(out, 'closure-results.tsv', ('lane','start_va','file_offset','bytes_hex','success_sentinel','branch_va','branch_hex','success_va','failure_va'), results)
    table(out, 'model-anchors.tsv', ('label','site_va','file_offset','bytes_hex','operand_offset','operand_bytes','value'), model_anchors)
    table(out, 'empty-examples.tsv', ('synthetic_books','first_side_levels','second_side_levels','predicted_bytes','predicted_hex'), examples)
    table(out, 'empty-level-examples.tsv', ('synthetic_price','price_hex','predicted_bytes','predicted_hex'), level_examples)
    table(out, 'hash-parameters.tsv', ('label','va','file_offset','bytes_hex','value','additional'), hash_rows)
    table(out, 'empty-example-digests.tsv', ('synthetic_books','predicted_input_hex','predicted_keccak256_hex'), digests)
    table(out, 'order-model-anchors.tsv', ('label','site_va','file_offset','bytes_hex','operand_offset','operand_bytes','value'), order_model_anchors)
    table(out, 'one-order-example.tsv', ('synthetic_books','first_side_levels','orders','price','size','orig_size','oid','tif_tag','user_hex','core_s','core_l','predicted_input_bytes','predicted_input_hex','predicted_keccak256_hex'),
          [(1, 1, 1, 1, 1, 1, 1,
            int(next(r[-1] for r in order_model_anchors if r[0] == 'tif_null_tag'), 16),
            '00' * int(next(r[-1] for r in order_model_anchors if r[0] == 'user_input_length'), 16), 'B', 1,
            len(order_input), order_input.hex(), order_digest.hex())])
    table(out, 'twin-differences.tsv', ('pair','offset','low_va','shared_va','low_hex','shared_hex','different_bytes'), diffs)
    table(out, 'lsda-headers.tsv', ('owner_va','lsda_va','file_offset','type_encoding','table_rows','header_and_table_hex'),
          [(hex(h['owner']), hex(h['va']), hex(h['offset']), hex(h['type_encoding']), h['rows'], h['bytes']) for h in headers])
    table(out, 'lsda-rows.tsv', ('owner_va','lsda_va','start_va','end_va','landing_va','action','file_offset','bytes_hex'),
          [(hex(r['owner']), hex(r['lsda']), hex(r['begin']), hex(r['end']),
            '' if r['landing'] is None else hex(r['landing']), r['action'], hex(r['entry_offset']), r['bytes']) for r in lsda_entries])
    table(out, 'lsda-call-links.tsv', ('label','owner_va','call_va','lookup_va','status','range_start','range_end','landing_va','action'), links)
    summary = {'target_sha256': SHA256, 'selected_fdes': len(extent_rows),
               'selected_fde_bytes': sum(row[2] for row in extent_rows),
               'selected_windows': len(window_rows), 'prior_boundary_windows': len(BOUNDARIES),
               'selected_conditional_branches': len(branches), 'selected_relative_transfers': len(transfers),
               'order_fields': len(fields), 'core_name_literals': len(core_names),
               'slot_layout_rows': len(layout), 'sidemap_names': len(names),
               'closure_result_guards': len(results),
               'synthetic_empty_examples': len(examples), 'synthetic_empty_level_examples': len(level_examples),
               'synthetic_example_digests': len(digests),
               'synthetic_one_order_examples': 1, 'order_model_anchors': len(order_model_anchors),
               'model_anchors': len(model_anchors),
               'selected_predicates': len(predicates), 'labelled_decisions': len(decisions),
               'twin_pairs': len(TWINS), 'raw_difference_runs': len(diffs),
               'raw_different_bytes': sum(row[-1] for row in diffs),
               'lsda_headers': len(headers), 'lsda_rows': len(lsda_entries),
               'lsda_selected_call_links': len(links),
               'lsda_links_with_landing': sum(bool(row[7]) for row in links),
               'normalization_masks': [],
               'scope': 'Selected static ranges and sites; no component coverage denominator or runtime reachability claim.'}
    (out / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    with TARGET.open('rb') as source, mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as data:
        extract(data, args.out)


if __name__ == '__main__':
    main()
