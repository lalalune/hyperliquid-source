"""Reproduce the selected node 115 TWAP cancellation evidence from ELF bytes.

The parser and thirteen execution helpers are selected FDEs. The earlier
dispatcher and wrapper are read only at the sites required for attribution.
All addresses are linked virtual addresses. This tool never runs the target.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections, unwind_index  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402


TARGET = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
BINARY = ROOT / 'artifacts/node/115/hl-node'

# Endpoints and hashes are fail-closed controls, not a function census.
FDE_SPECS = (
    ('payload_parser', 0x39d0f20, 0x39d1b0a, 'b6ea806488931013a127227bca5a8b815b51071ab6b3b23a91cb5013e649ab4b'),
    ('route_core', 0x2c2f020, 0x2c2f7c2, '634ffb41b81654a9c95e981c3b0ea823afd000fc1a3b47d6efc2b4a5c0d4d3d9'),
    ('route0_remove', 0x2d2c6e0, 0x2d2d019, '1d64b62c4c54eea8c604dd80217f513a1a7d1471adfdb73a61624e17d3a4d480'),
    ('route1_remove', 0x2d2d020, 0x2d2d959, 'f8dcdb096f083d52ce2056522652ab6fdac46b37efc7998571aae8c88c65845e'),
    ('route0_first_remove', 0x2d2efa0, 0x2d2f50b, '998af7254c7e741151553fe2fdee2e1e6669df49505b122991311775d687e32e'),
    ('route1_first_remove', 0x2d2f510, 0x2d2fa7b, '06c2c2a6be98ca7895d1a55153e08fb1c172ac81b59a67766acb8c6bf507bb0c'),
    ('route0_tree_remove', 0x243f670, 0x243f8fe, '1f65a8a2a883012b6f57767db90bba1f64d5c2c24a7872a4bf2b93b55258a0f3'),
    ('route1_tree_remove', 0x243f3e0, 0x243f66e, 'cc56ac20cb587e43641d20131bb142b498585f045c00d341d9ce4fa5678485cf'),
    ('route0_record_other', 0x2a81140, 0x2a81545, 'fbe5c8ddda2b225d864127fbfc125f31b76bf871633befe7ececad4cf3fa5c08'),
    ('route0_record_one', 0x2a81a70, 0x2a81f22, '9d86745099f1b6df7498394dcba16262691963873ae53025cf580eaf5625c62d'),
    ('route1_record_other', 0x2a80cb0, 0x2a8113f, '8f8cb37a66180939601c27cda5a3c68b31097f97d53745c8c7e97a18a06db18e'),
    ('route1_record_one', 0x2a81550, 0x2a81a68, '08964ac5d24502675f295c39fa98d821957d2e32abbb2b42928e218105f242c7'),
    ('compact_shift_112', 0x24da590, 0x24da7c6, '2d5a77049d95ba69d1be452211c9d6207eed546634f2d70477ec0f7cdc6f3a55'),
    ('compact_shift_96', 0x24dfef0, 0x24e01e6, '94295e3b0f7076bd7150aa8f79251a6da0276efb0a7df609bfe2076b90d61d58'),
)

# These exact instruction windows support the stated interpretation. The
# selected FDE body hashes above cover the other selected instruction sites.
WINDOWS = (
    ('context_name_length', 0x36616b5, '4889f8488d4afc4883f9240f872c0e0000488d3d437c13fd48630c8f4801f9ffe1'),
    ('context_name_compare', 0x3661e2d, '48b9706572704465706c488db9030bfd0348333e440fb746084981f06f7900004909f80f842d07000048bf7477617043616e6348333e440fb746084981f0656c00004909f80f84ad070000'),
    ('context_name_result', 0x3662625, 'c6400123e9f7000000'),
    ('context_prior_name_result', 0x3662583, 'c640011be999010000'),
    ('context_name_success', 0x3662725, '31c988085b415e415fc3'),
    ('context_bias', 0x2bdbb0c, '498b0424482d86000000b914000000480f43c8488d053ae8a2fd48630c884801c1ffe1'),
    ('context_direct_bias', 0x2bda82a, '498b07482d86000000b914000000480f43c8488d05bdf6a2fd48630c884801c1ffe1'),
    ('context_decoder_switch', 0x36b8d1d, '880c240fb6c0488d0d82160efd486304814801c8ffe0'),
    ('context_decoder', 0x36b9332, '488d15e7a4d9fc4c8d05088cdd02488d7c24204889e6b91000000041b904000000e8c87b3100807c2420000f85830f0000488b4424288b4c2430894b10b9a9000000e9ae1a0000'),
    ('context_decoder_store', 0x36bae27, '4889430848890b4889d84881c4300100005bc3'),
    ('context_wrapper', 0x2a2fb9e, 'ff15945fab030fb704243da20100000f85db0000004d8b0c2448b8cccccccccccccc0c4939c10f8319010000488b4c24084c8b442410488dbc24800000004c89fe4c89f2e839f41f00'),
    ('context_wrapper_core_result_linear', 0x2a2fbe7, '0f288424e00000000f1144246f0f288424d00000000f1144245f0f288424c00000000f1144244f0f288424800000000f288c24900000000f289424a00000000f289c24b00000000f115c243f0f1154242f0f114c241f0f1144240fc60305'),
    ('context_wrapper_core_return_tag', 0x2a2fc3d, '0f1144240fc603050f1004240f104c24100f10'),
    ('context_wrapper_limit_return_tag', 0x2a2fce3, '66c7431054014c894b18c6030f'),
    ('parser_kind', 0x39d0f39, '0fb60683f814898424e40000000f848f05000083f8150f85d9090000'),
    ('parser_kind_switch', 0x39d1072, 'ffc883f80e0f8716040000488bb424f0000000488b9424f8000000488d0d3454ddfc486304814801c8ffe0'),
    ('parser_field_asset', 0x39d10df, '4883fa010f84f90000004883fa050f85370100008b063305488fe0fc0fb64e04320d428fe0fc0fb6c909c10f858c010000e9de000000'),
    ('parser_field_twap_id', 0x39d122a, '4883fa06756c8b0633056990e0fc0fb74e0466330d6290e0fc0fb7c909c17552c644241101'),
    ('parser_duplicate_flags', 0x39d12ee, '807c2410010f84c8010000807c2411000f849c0000004883bc24d8000000000f85c105'),
    ('parser_required_flags', 0x39d1645, 'f68424d0000000017476f68424d8000000010f8479010000488b4424384c8960088b4c247c89481048c700000000'),
    ('route_gate', 0x2c2f03a, '4883f90175184180beac420000000f846401000066c7030801e922060000'),
    ('route_division', 0x2c2f069, '48b94b598638d6c56d344c89c048f7e14989d549c1ed0b4d3baed03a00000f'),
    ('route0_call_and_result', 0x2c2f127, '488d7c2430488d9424a0010000488b4c2428e8a2d50f00837c2430010f8540010000'),
    ('route0_error_copy_to_handoff', 0x2c2f13e, '837c2430010f85400100000f288424a00000000f298424000200000f288424900000000f298424f00100000f288424800000000f298424e00100000f284424400f284c24500f285424600f285c24700f299c24d00100000f299424c00100000f298c24b00100000f298424a0010000e915030000'),
    ('route1_call_and_result', 0x2c2f1fd, '488d7c2430488d9424a00100004d89cf4c89c9e80bde0f00837c2430010f85f6000000'),
    ('route0_handoff', 0x2c2f4c7, '488b44241048894424400f1004240f29442430488d7c24304c89ee4c89f2e826a37eff'),
    ('route1_handoff', 0x2c2f607, '488b44241048894424400f1004240f29442430488d7c24304c89f6e899ad7eff'),
    ('route0_record', 0x2c2f468, '48b801000000000000804889842420020000488b442428488984243802000048c78424a0010000040000004889e7ff158c658b03488b7c2408488db424a0010000bab8020000ff1554008b0348c74424100100000066c78424a0010000a201'),
    ('route1_record', 0x2c2f5ad, '48b8010000000000008048898424200200004c89bc243802000048c78424a0010000040000004889e7ff15ac598b03488b7c2408488db424a0010000bac8020000ff1514ff8a0348c74424100100000066c78424a0010000a201'),
    ('route0_remove_search', 0x2d2c8c5, '488db424e80000004c89efe85b0d7aff4883f8010f84f70300004989d14d8b65184939d4488b5c24180f'),
    ('route0_remove_row', 0x2d2c910, '486bc1700f1004060f104c06100f1054061a0f1194240a0100000f298c24000100000f298424f00000000fb66c062a'),
    ('route0_remove_decrement', 0x2d2c9c3, 'e8c8db7aff49ffcc4d8965180f'),
    ('route0_remove_row_kind', 0x2d2ca4f, '4080fd027507c644244202eb'),
    ('route0_remove_missing', 0x2d2ccd0, '4080fd0275136641c74710d40049c70701000000e905010000'),
    ('route0_first_decrement', 0x2d2f1a1, 'e84a0d7bff49ffcf4d897e184180fc027507c644242002eb4f48'),
    ('route0_tree_decrement', 0x243f79f, '49ff4e10488b8424a001000048898424bd00000080'),
    ('route0_tree_rebalance', 0x243f7b3, '807c240f01753e498b3e4885ff0f8412010000498b46084885c00f8412010000488b8fe004000049890e48ffc84989460848c70100000000be4005000031d2ff15a8fc0904'),
    ('record0_other_group_and_index', 0x2a8119d, '48b94b598638d6c56d344c89f848f7e14989d449c1ec0b498b455048894424604939c40f85cf00000040886c240c4c89f848f7e148c1ea0b4869c2102700004c89fd4829c5493b6d100f83cd000000498b450848c1e505'),
    ('record0_other_fallback', 0x2a81295, '4885f67529660f57c0660f29442420b801000000488944241848c744241000000000eb514885f60fb66c240c74d7b801000000488944241848c744241000000000488d3dcb559f03ff154de5a503'),
    ('record0_one_group_and_index', 0x2a81ac7, '48b94b598638d6c56d344c89f848f7e14989d449c1ec0b498b405048894424584939c40f85f300000044886c240d4c89f848f7e148c1ea0b4869c2102700004d89fd4929c54d3b68100f83fd000000498b400849c1e505'),
    ('record0_one_fallback', 0x2a81be3, '4809f575364c89c5b8010000004889442410660f57c0660f2944243048c744241800000000660f29442420e9960000004809f5440fb66c240d74cab80100000048894424104531e4488d3d764c9f03ff15f8dba503'),
    ('record1_other_index_guard', 0x2a80cc1, '4989f64c8b6610488b72104939f40f831b040000'),
    ('record1_one_index_guard', 0x2a81561, '4989f64c8b26488b72104939f40f83a5040000'),
    ('record1_other_index_stride', 0x2a80d32, '4c89e548c1e505'),
    ('record1_one_index_stride', 0x2a815d5, '4c89e548c1e505'),
    ('record1_other_bounds_failure', 0x2a810f0, '488d15111ea1034c89e7ff1520e5a503488d3d29599f03ff153be7a5030f0b'),
    ('record1_one_bounds_failure', 0x2a81a19, '488d15e814a1034c89e7ff15f7dba503488d3d00509f03ff1512dea5030f0b'),
    ('remove_shift_selection', 0x2d2c980, '4d89c849f7d04d01e04d39c87318488d410131d24839f8480f43d748f7da4801ca48ffc2eb1d488d420131c94839f8480f43cf48f7d94801d148ffc149894d104d89c8e8c8db7aff'),
    ('first_remove_shift_selection', 0x2d2f15e, '4d89c849f7d04d01f84d39c87318488d410131d24839f8480f43d748f7da4801ca48ffc2eb1d488d420131c94839f8480f43cf48f7d94801d148ffc149894e104d89c8e84a0d7bff'),
    ('shift112_branch_entry', 0x24da59b, '4989c94929d10f84930000004d85c00f848a0000004c89c84801f8490f43c14989ff4929d74989fc4929cc4d89c54d29fd767b4c39c00f83c50000004889d54d39e00f863f0100004d29e7'),
    ('shift112_three_copy_first', 0x24da5e6, '496bdf70488d041e496bd5704989fd4889c74989f648890c24ff15634f0004'),
    ('shift112_contiguous_copy', 0x24da6f9, '486bc2704801f0486bf9704801f7496bd0704889c64883c4085b415c415d415e415f5dff25464e0004'),
    ('shift112_noop_return', 0x24da63a, '4883c4085b415c415d415e415f5dc3'),
    ('shift96_branch_entry', 0x24dfefb, '4989c94929d10f84ca0000004d85c00f84c10000004c89c84801f8490f43c14989ff4929d74989fc4929cc4d89c54d29fd0f86ae0000004c39c00f830f0100004889d54d39e00f86b00100004d29e7'),
    ('shift96_three_copy_first', 0x24dff4a, '4c89f848c1e005488d1c40488d041e49c1e5054a8d146d000000004c01ea4989fd4889c74989f648890c24ff15edf5ff03'),
    ('shift96_contiguous_copy', 0x24e00c2, '488d045248c1e0054801f0488d3c4948c1e7054801f749c1e0054b8d14404889c64883c4085b415c415d415e415f5dff2571f4ff03'),
    ('shift96_noop_return', 0x24dffd1, '4883c4085b415c415d415e415f5dc3'),
    ('record1_other_small_selector_math', 0x2a80d4d, '0fb64c24184883f9027346b80a00000048f76424100f807c0300004801c848c7c2ffffffff4889c1480f42ca480f43c84989cc4981ec001f0afa720e4881c100e1f505480f42ca4989cc4c89642438eb36'),
    ('record1_other_large_selector_math', 0x2a80d9e, '4c896424384d85e40f84e60200004981fc00e1f505731f'),
    ('record1_other_multiply_overflow', 0x2a810e4, '48c7c0ffffffffe978fcffff'),
    ('record1_one_small_selector_math', 0x2a815f0, '0fb64c24184883f9027346b80a00000048f76424100f80020400004801c848c7c2ffffffff4889c1480f42ca480f43c84989cc4981ec001f0afa720e4881c100e1f505480f42ca4989cc4c89642448eb36'),
    ('record1_one_large_selector_math', 0x2a81641, '4c896424484d85e40f846c0300004981fc00e1f505731f'),
    ('record1_one_multiply_overflow', 0x2a81a0d, '48c7c0ffffffffe9f2fbffff'),
    ('record1_other_remove_offset', 0x2a80dd4, '4981c4001f0afa'),
    ('record1_one_remove_offset', 0x2a81677, '4981c4001f0afa'),
)

# (label, site, target). These are selected, instruction-aligned control-flow
# sites, not a byte-scan census. Encodings and targets are decoded from ELF.
BRANCHES = (
    ('context_spot_deploy_name', 0x3661e50, 0x3662583),
    ('context_twap_cancel_name', 0x3661e72, 0x3662625),
    ('decoder_error', 0x36b935d, 0x36ba2e6),
    ('wrapper_classifier_error', 0x2a2fbad, 0x2a2fc8e),
    ('wrapper_id_too_large', 0x2a2fbc4, 0x2a2fce3),
    ('parser_sequence', 0x39d0f46, 0x39d14db),
    ('parser_other_input_kind', 0x39d0f4f, 0x39d192e),
    ('parser_one_character', 0x39d10e3, 0x39d11e2),
    ('parser_not_length_five', 0x39d10ed, 0x39d122a),
    ('parser_bad_asset', 0x39d110a, 0x39d129c),
    ('parser_short_t', 0x39d11e8, 0x39d124a),
    ('parser_bad_short_key', 0x39d11ed, 0x39d129c),
    ('parser_not_length_six', 0x39d122e, 0x39d129c),
    ('parser_bad_twap_id', 0x39d1248, 0x39d129c),
    ('parser_asset_arm', 0x39d12fe, 0x39d13a0),
    ('parser_duplicate_t', 0x39d130d, 0x39d18d4),
    ('parser_duplicate_a', 0x39d13a8, 0x39d18dd),
    ('parser_missing_a', 0x39d164d, 0x39d16c5),
    ('parser_missing_t', 0x39d1657, 0x39d17d6),
    ('parser_empty_sequence', 0x39d1515, 0x39d1528),
    ('parser_extra_sequence', 0x39d17c4, 0x39d1957),
    ('route_non_one', 0x2c2f03e, 0x2c2f058),
    ('route_one_gate_zero', 0x2c2f048, 0x2c2f1b2),
    ('route_first_bound', 0x2c2f087, 0x2c2f68f),
    ('route_second_bound', 0x2c2f0d1, 0x2c2f6c3),
    ('route0_remove_value', 0x2c2f143, 0x2c2f289),
    ('route1_remove_value', 0x2c2f21a, 0x2c2f316),
    ('route0_value_variant', 0x2c2f2fb, 0x2c2f3a7),
    ('route1_value_variant', 0x2c2f38f, 0x2c2f4ef),
    ('remove_first_value', 0x2d2c713, 0x2d2c809),
    ('remove_empty_root', 0x2d2c735, 0x2d2ccd6),
    ('remove_key_miss', 0x2d2c85c, 0x2d2ccd6),
    ('remove_index_outside', 0x2d2c866, 0x2d2ccd6),
    ('remove_id_miss', 0x2d2c8d9, 0x2d2ccd6),
    ('remove_index_ge_count', 0x2d2c8ee, 0x2d2ca55),
    ('remove_row_not_two', 0x2d2ca53, 0x2d2ca5c),
    ('remove_rebuild_gate', 0x2d2cae3, 0x2d2cc60),
    ('remove_result_not_two', 0x2d2ccd4, 0x2d2cce9),
    ('remove_parent_empty', 0x2d2cd6e, 0x2d2ce03),
    ('first_remove_no_parent', 0x2d2efd2, 0x2d2f036),
    ('first_remove_found_id', 0x2d2f087, 0x2d2f0db),
    ('first_remove_index_ge_count', 0x2d2f0e5, 0x2d2f1b3),
    ('first_remove_row_not_two', 0x2d2f1b1, 0x2d2f1ba),
    ('first_remove_rebuild_gate', 0x2d2f225, 0x2d2f38a),
    ('tree_remove_empty', 0x243f684, 0x243f86f),
    ('tree_remove_exhausted', 0x243f6e7, 0x243f86f),
    ('tree_remove_root_unchanged', 0x243f7b8, 0x243f7f8),
    ('tree_remove_missing_root', 0x243f7c0, 0x243f8d8),
    ('tree_remove_missing_height', 0x243f7cd, 0x243f8e5),
    ('tree_remove_row_not_two', 0x243f86d, 0x243f875),
    ('record0_other_wrong_group', 0x2a811c0, 0x2a81295),
    ('record0_other_index_outside', 0x2a811e6, 0x2a812b9),
    ('record0_other_wrong_group_nonzero', 0x2a81298, 0x2a812c3),
    ('record0_other_index_outside_zero', 0x2a812c1, 0x2a8129a),
    ('record0_one_wrong_group', 0x2a81aea, 0x2a81be3),
    ('record0_one_index_outside', 0x2a81b10, 0x2a81c13),
    ('record0_one_wrong_group_nonzero', 0x2a81be6, 0x2a81c1e),
    ('record0_one_index_outside_zero', 0x2a81c1c, 0x2a81be8),
    ('record1_other_index_outside', 0x2a80ccf, 0x2a810f0),
    ('record1_one_index_outside', 0x2a8156e, 0x2a81a19),
    ('remove_choose_prefix', 0x2d2c98c, 0x2d2c9a6),
    ('first_remove_choose_prefix', 0x2d2f16a, 0x2d2f184),
    ('shift112_same_position', 0x24da5a1, 0x24da63a),
    ('shift112_zero_count', 0x24da5aa, 0x24da63a),
    ('shift112_source_fits', 0x24da5cc, 0x24da649),
    ('shift112_distance_ge_count', 0x24da5d1, 0x24da69c),
    ('shift112_destination_fits', 0x24da5dd, 0x24da722),
    ('shift112_both_fit', 0x24da64f, 0x24da6f9),
    ('shift112_distance_ge_count_source_fits', 0x24da65f, 0x24da751),
    ('shift112_destination_fits_source_wraps', 0x24da69f, 0x24da77e),
    ('shift96_same_position', 0x24dff01, 0x24dffd1),
    ('shift96_zero_count', 0x24dff0a, 0x24dffd1),
    ('shift96_source_fits', 0x24dff2c, 0x24dffe0),
    ('shift96_distance_ge_count', 0x24dff35, 0x24e004a),
    ('shift96_destination_fits', 0x24dff41, 0x24e00f7),
    ('shift96_both_fit', 0x24dffe6, 0x24e00c2),
    ('shift96_distance_ge_count_source_fits', 0x24dfffa, 0x24e0147),
    ('shift96_destination_fits_source_wraps', 0x24e004d, 0x24e0187),
    ('record1_other_selector_ge_two', 0x2a80d56, 0x2a80d9e),
    ('record1_other_multiply_overflow', 0x2a80d62, 0x2a810e4),
    ('record1_other_offset_no_overflow', 0x2a80d87, 0x2a80d97),
    ('record1_other_selector_ge_two_zero', 0x2a80da6, 0x2a81092),
    ('record1_other_selector_ge_two_large', 0x2a80db3, 0x2a80dd4),
    ('record1_one_selector_ge_two', 0x2a815f9, 0x2a81641),
    ('record1_one_multiply_overflow', 0x2a81605, 0x2a81a0d),
    ('record1_one_offset_no_overflow', 0x2a8162a, 0x2a8163a),
    ('record1_one_selector_ge_two_zero', 0x2a81649, 0x2a819bb),
    ('record1_one_selector_ge_two_large', 0x2a81656, 0x2a81677),
)

# Condition codes whose sense is used by the compact movement decision table.
SHIFT_CONDITIONS = {
    'remove_choose_prefix': 3, 'first_remove_choose_prefix': 3,
    'shift112_same_position': 4, 'shift112_zero_count': 4,
    'shift112_source_fits': 6, 'shift112_distance_ge_count': 3,
    'shift112_destination_fits': 6, 'shift112_both_fit': 6,
    'shift112_distance_ge_count_source_fits': 3, 'shift112_destination_fits_source_wraps': 6,
    'shift96_same_position': 4, 'shift96_zero_count': 4,
    'shift96_source_fits': 6, 'shift96_distance_ge_count': 3,
    'shift96_destination_fits': 6, 'shift96_both_fit': 6,
    'shift96_distance_ge_count_source_fits': 3, 'shift96_destination_fits_source_wraps': 6,
}
ARITH_CONDITIONS = {
    'record1_other_selector_ge_two': 3, 'record1_other_multiply_overflow': 0,
    'record1_other_offset_no_overflow': 2, 'record1_other_selector_ge_two_zero': 4,
    'record1_other_selector_ge_two_large': 3, 'record1_one_selector_ge_two': 3,
    'record1_one_multiply_overflow': 0, 'record1_one_offset_no_overflow': 2,
    'record1_one_selector_ge_two_zero': 4, 'record1_one_selector_ge_two_large': 3,
}

# Relative control-flow targets at manually selected instruction starts.
# Context calls are attributed to previous work; their source FDEs are not
# counted as new selections here.
CALLS = (
    ('context_payload_parser', 0x36b9353, 0x39d0f20),
    ('context_nested_wrapper', 0x2bdbe01, 0x2a2fb70),
    ('context_nested_to_core', 0x2a2fbe2, 0x2c2f020),
    ('context_direct_wrapper', 0x2bdaa2a, 0x2c0a610),
    ('context_direct_to_core', 0x2c0a868, 0x2c2f020),
    ('route0_remove', 0x2c2f139, 0x2d2c6e0),
    ('route1_remove', 0x2c2f210, 0x2d2d020),
    ('route0_variant_one', 0x2c2f30c, 0x2a81a70),
    ('route0_variant_other', 0x2c2f3b2, 0x2a81140),
    ('route1_variant_one', 0x2c2f39d, 0x2a81550),
    ('route1_variant_other', 0x2c2f4f7, 0x2a80cb0),
    ('route0_handoff_context', 0x2c2f4e5, 0x2419810),
    ('route1_handoff_context', 0x2c2f622, 0x241a3c0),
    ('route0_first_remove', 0x2d2c709, 0x2d2efa0),
    ('route1_first_remove', 0x2d2d049, 0x2d2f510),
    ('route0_tree_remove', 0x2d2c8b6, 0x243f670),
    ('route1_tree_remove', 0x2d2d1f6, 0x243f3e0),
    ('route0_compact_shift', 0x2d2c9c3, 0x24da590),
    ('route1_compact_shift', 0x2d2d303, 0x24da590),
    ('first_remove_compact_shift', 0x2d2f1a1, 0x24dfef0),
    ('first_remove_compact_shift_paired', 0x2d2f711, 0x24dfef0),
    ('tree_remove_inner', 0x243f722, 0x1d60b80),
)

JUMPS = (
    ('context_name_success', 0x3662629, 0x3662725),
    ('context_decoder_store', 0x36b9374, 0x36bae27),
    ('route_gate_return', 0x2c2f053, 0x2c2f67a),
    ('route0_error_handoff', 0x2c2f1ad, 0x2c2f4c7),
    ('route1_error_handoff', 0x2c2f284, 0x2c2f607),
    ('remove_kind_two_result', 0x2d2ca5a, 0x2d2cacc),
    ('remove_status_return', 0x2d2cce4, 0x2d2cdee),
    ('first_remove_kind_two', 0x2d2f1b8, 0x2d2f209),
    ('record1_other_overflow_rejoin', 0x2a810eb, 0x2a80d68),
    ('record1_one_overflow_rejoin', 0x2a81a14, 0x2a8160b),
    ('record1_other_small_selector_join', 0x2a80d9c, 0x2a80dd4),
    ('record1_one_small_selector_join', 0x2a8163f, 0x2a81677),
)

# Each entry is an instruction start in the first member of a pair. Its only
# mask is the four-byte PC-relative operand; its opcode must match in both.
PAIRS = (
    ('remove', 0x2d2c6e0, 0x2d2d020, (
        (0x2d2c709, 'e8'), (0x2d2c750, '4c8b35'),
        (0x2d2c855, 'e8'), (0x2d2c8b6, 'e8'), (0x2d2c8d0, 'e8'),
        (0x2d2c9c3, 'e8'), (0x2d2cb71, 'e8'), (0x2d2cc26, 'e8'),
        (0x2d2ce22, 'e8'), (0x2d2ce96, 'e8'), (0x2d2ceb5, 'e8'),
        (0x2d2cefc, 'e8'), (0x2d2cf1d, 'e8'), (0x2d2cf87, 'ff15'),
        (0x2d2cf97, 'e8'), (0x2d2cfe9, 'e8'), (0x2d2cff0, 'ff15'),
        (0x2d2d014, 'e8'),
    )),
    ('first_remove', 0x2d2efa0, 0x2d2f510, (
        (0x2d2efc5, 'e8'), (0x2d2f028, 'e8'), (0x2d2f07e, 'e8'),
        (0x2d2f1a1, 'e8'), (0x2d2f2b1, 'e8'), (0x2d2f356, 'e8'),
        (0x2d2f406, 'e8'), (0x2d2f42d, 'ff15'), (0x2d2f496, 'e8'),
        (0x2d2f4b5, '488d3d'), (0x2d2f4bc, '488d15'),
        (0x2d2f4c8, 'ff15'), (0x2d2f4ce, '488d3d'),
        (0x2d2f4d5, '488d15'), (0x2d2f4e1, 'ff15'), (0x2d2f506, 'e8'),
    )),
    ('tree_remove', 0x243f670, 0x243f3e0, (
        (0x243f722, 'e8'), (0x243f7f2, 'ff15'), (0x243f8d8, '488d3d'),
        (0x243f8df, 'ff15'), (0x243f8e5, '488d3d'),
        (0x243f8ec, '488d15'), (0x243f8f8, 'ff15'),
    )),
)

FIELD_TABLE = 0x6491f48
VARIANT_TABLES = (0x644cc40, 0x6467f98, 0x649bac8)
DECODE_TABLE = 0x79a3ac
INNER_TABLE = 0x60a360
OUTER_TABLE = 0x609f00
INPUT_TABLE = 0x7a64c8
NAME_TABLE = 0x799310
INDEX = 35


def demand(condition, message):
    if not condition:
        raise ValueError(message)


def verify_digest(data, expected=TARGET):
    actual = hashlib.sha256(data).hexdigest()
    demand(actual == expected, 'node 115 SHA-256 mismatch')
    return actual


def file_offset(secs, va, size, data_length):
    """Map a complete VA interval to a unique file-backed section."""
    demand(isinstance(va, int) and isinstance(size, int) and va >= 0 and size > 0,
           'invalid VA interval')
    matches = [s for s in secs if s['type'] != 8 and s['address'] <= va
               and va + size <= s['address'] + s['size']]
    demand(len(matches) == 1, 'VA interval is absent, ambiguous, or NOBITS')
    sec = matches[0]
    offset = sec['offset'] + va - sec['address']
    demand(0 <= offset <= data_length - size, 'section bytes outside file')
    return offset


def relative_relocations(data, sec):
    """Read ELF64 RELA records from a section returned by the shared parser."""
    demand(sec['type'] != 8 and sec['size'] % 24 == 0
           and sec['offset'] >= 0 and sec['offset'] + sec['size'] <= len(data),
           'truncated .rela.dyn')
    result, seen = {}, set()
    for pos in range(sec['offset'], sec['offset'] + sec['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, pos)
        demand(slot not in seen, 'duplicate relocation slot')
        seen.add(slot)
        if info & 0xffffffff != 8:
            continue
        demand(info >> 32 == 0, 'RELATIVE relocation has a symbol')
        result[slot] = (addend, pos, info)
    return result


class Image:
    def __init__(self, data, authenticate=True):
        self.data = data
        if authenticate:
            verify_digest(data)
        self.sections = sections(data)
        _, table = unwind_index(data)
        _, fdes = eh_frame_records(data, self.sections)
        self.fdes = {f['start']: f for f in fdes}
        demand(len(self.fdes) == len(fdes), 'duplicate FDE starts')
        self.index = {row['start']: row['fde'] for row in table}
        self.relocations = self._relocations()

    def offset(self, va, size=1):
        return file_offset(self.sections, va, size, len(self.data))

    def read(self, va, size):
        o = self.offset(va, size)
        return bytes(self.data[o:o + size])

    def containing_fde(self, va):
        hits = [f for f in self.fdes.values() if f['start'] <= va < f['end']]
        demand(len(hits) == 1, 'site does not have one containing FDE')
        return hits[0]

    def _relocations(self):
        rows = [s for s in self.sections if s['name'] == '.rela.dyn']
        demand(len(rows) == 1 and rows[0]['type'] != 8, 'missing or duplicate .rela.dyn')
        return relative_relocations(self.data, rows[0])

    def relative_string(self, slot):
        demand(slot in self.relocations, 'missing RELATIVE string relocation')
        pointer = self.relocations[slot][0]
        length = struct.unpack('<Q', self.read(slot + 8, 8))[0]
        demand(0 < length <= 128, 'invalid descriptor string length')
        raw = self.read(pointer, length)
        try:
            name = raw.decode('ascii')
        except UnicodeDecodeError as exc:
            raise ValueError('non-ASCII descriptor') from exc
        return pointer, length, name

    def table_target(self, base, index, lower, upper):
        demand(isinstance(index, int) and index >= 0, 'invalid table index')
        cell = base + 4 * index
        raw = self.read(cell, 4)
        target = base + struct.unpack('<i', raw)[0]
        demand(lower <= target < upper, 'table target outside selected range')
        return cell, raw, target


def validate_fdes(image):
    result = []
    for role, start, end, body_sha in FDE_SPECS:
        fde = image.fdes.get(start)
        demand(fde is not None and fde['end'] == end, 'unexpected FDE extent: ' + role)
        demand(image.index.get(start) == fde['fde'], 'FDE index mismatch: ' + role)
        executable = [s for s in image.sections if s['type'] != 8 and s['flags'] & 4
                      and s['address'] <= start and end <= s['address'] + s['size']]
        demand(len(executable) == 1, 'FDE extent is not in one file-backed executable section: ' + role)
        body = image.read(start, end - start)
        digest = hashlib.sha256(body).hexdigest()
        demand(digest == body_sha, 'body bytes mismatch: ' + role)
        result.append((role, start, end, fde, body, digest))
    return result


def validate_windows(image):
    rows = []
    for role, va, expected_hex in WINDOWS:
        expected = bytes.fromhex(expected_hex)
        actual = image.read(va, len(expected))
        demand(actual == expected, 'instruction window mismatch: ' + role)
        rows.append((role, va, image.offset(va, len(actual)), actual))
    return rows


def decode_branch(image, va):
    first = image.read(va, 1)[0]
    if 0x70 <= first <= 0x7f:
        raw = image.read(va, 2)
        delta = struct.unpack('<b', raw[1:])[0]
        cc = first & 15
    elif first == 0x0f:
        raw = image.read(va, 6)
        demand(0x80 <= raw[1] <= 0x8f, 'not a supported conditional branch')
        delta = struct.unpack('<i', raw[2:])[0]
        cc = raw[1] & 15
    else:
        raise ValueError('not a supported conditional branch')
    return raw, cc, va + len(raw) + delta


def decode_call(image, va):
    raw = image.read(va, 5)
    demand(raw[0] == 0xe8, 'not a rel32 call')
    return raw, va + 5 + struct.unpack('<i', raw[1:])[0]


def decode_jump(image, va):
    opcode = image.read(va, 1)[0]
    if opcode == 0xeb:
        raw = image.read(va, 2)
        displacement = struct.unpack('<b', raw[1:])[0]
    elif opcode == 0xe9:
        raw = image.read(va, 5)
        displacement = struct.unpack('<i', raw[1:])[0]
    else:
        raise ValueError('not a supported direct jump')
    return raw, va + len(raw) + displacement


def decode_rip_lea(image, va):
    raw = image.read(va, 7)
    demand(raw[0] in (0x48, 0x4c) and raw[1] == 0x8d and (raw[2] & 0xc7) == 0x05,
           'not a supported RIP-relative lea')
    return raw, va + 7 + struct.unpack('<i', raw[3:])[0]


def decode_rip_slot(image, va):
    prefix = image.read(va, 2)
    if prefix in (b'\xff\x15', b'\xff\x25'):
        raw = image.read(va, 6)
        delta = struct.unpack('<i', raw[2:])[0]
    else:
        raw = image.read(va, 7)
        demand(raw[:3] in (b'\x48\x8b\x05', b'\x48\x8b\x2d',
                           b'\x4c\x8b\x25', b'\x4c\x8b\x2d'),
               'not a supported RIP-relative slot reference')
        delta = struct.unpack('<i', raw[3:])[0]
    return raw, va + len(raw) + delta


def dynamic_import(image, slot):
    """Read one ELF64 GLOB_DAT relocation and its dynamic symbol by slot."""
    def one_section(name, expected_type):
        hits = [s for s in image.sections if s['name'] == name and s['type'] == expected_type]
        demand(len(hits) == 1, 'missing or duplicate dynamic section: ' + name)
        s = hits[0]
        demand(0 <= s['offset'] <= len(image.data) - s['size'], 'dynamic section outside file')
        return s

    rela = one_section('.rela.dyn', 4)
    symbols = one_section('.dynsym', 11)
    strings = one_section('.dynstr', 3)
    demand(rela['size'] % 24 == 0 and symbols['size'] % 24 == 0, 'truncated dynamic records')
    matches = []
    for off in range(rela['offset'], rela['offset'] + rela['size'], 24):
        target, info, addend = struct.unpack_from('<QQq', image.data, off)
        if target == slot:
            matches.append((off, info, addend))
    demand(len(matches) == 1, 'missing or duplicate selected import relocation')
    off, info, addend = matches[0]
    symbol_index, kind = info >> 32, info & 0xffffffff
    demand(kind == 6 and symbol_index != 0 and symbol_index < symbols['size'] // 24,
           'invalid GLOB_DAT symbol')
    symbol_off = symbols['offset'] + symbol_index * 24
    name_offset, symbol_info, _, section_index, _, _ = struct.unpack_from('<IBBHQQ', image.data, symbol_off)
    demand(section_index == 0 and symbol_info & 15 == 2, 'dynamic symbol is not an undefined function')
    demand(name_offset < strings['size'], 'dynamic symbol name outside section')
    name_start = strings['offset'] + name_offset
    name_end = image.data.find(b'\0', name_start, strings['offset'] + strings['size'])
    demand(name_end != -1, 'unterminated dynamic symbol')
    name = bytes(image.data[name_start:name_end]).decode('ascii')
    demand(name == 'memmove' and addend == 0, 'unexpected imported symbol')
    return (off, bytes(image.data[off:off + 24]), kind, symbol_index, symbol_off,
            bytes(image.data[symbol_off:symbol_off + 24]), name_start, name)


def checked_branches(image):
    rows = []
    for label, va, expected in BRANCHES:
        raw, condition, target = decode_branch(image, va)
        demand(target == expected, 'branch target mismatch: ' + label)
        expected_condition = SHIFT_CONDITIONS.get(label, ARITH_CONDITIONS.get(label))
        if expected_condition is not None:
            demand(condition == expected_condition, 'branch condition mismatch: ' + label)
        rows.append((label, va, image.offset(va, len(raw)), raw, condition, target))
        for pair_role, first, second, _ in PAIRS:
            fde = image.fdes[first]
            if first <= va < fde['end'] and first <= target < fde['end']:
                other_va = second + va - first
                other_raw, other_condition, other_target = decode_branch(image, other_va)
                demand(other_condition == condition and other_target == second + target - first,
                       'paired branch target mismatch: ' + label)
                rows.append((pair_role + '_paired_' + label, other_va,
                             image.offset(other_va, len(other_raw)), other_raw, other_condition, other_target))
    return rows


def checked_calls(image):
    rows = []
    for role, va, expected in CALLS:
        raw, target = decode_call(image, va)
        demand(target == expected, 'call target mismatch: ' + role)
        rows.append((role, va, image.offset(va, len(raw)), raw, target))
    return rows


def subject_call_target(rows, role):
    matches = [row[-1] for row in rows if row[0] == role]
    demand(len(matches) == 1, 'context call is absent or duplicated')
    return matches[0]


def checked_jumps(image):
    rows = []
    for role, va, expected in JUMPS:
        raw, target = decode_jump(image, va)
        demand(target == expected, 'jump target mismatch: ' + role)
        rows.append((role, va, image.offset(va, len(raw)), raw, target))
    return rows


def pair_records(image, first, second, instructions):
    a = image.fdes[first]
    b = image.fdes[second]
    n = a['end'] - first
    demand(n == b['end'] - second, 'paired FDE lengths differ')
    left = image.read(first, n)
    right = image.read(second, n)
    la, lb = bytearray(left), bytearray(right)
    covered = set()
    operands = []
    for site, prefix_hex in instructions:
        prefix = bytes.fromhex(prefix_hex)
        pos = site - first
        demand(0 <= pos and pos + len(prefix) + 4 <= n, 'mask outside FDE')
        demand(left[pos:pos + len(prefix)] == prefix and right[pos:pos + len(prefix)] == prefix,
               'paired instruction opcode mismatch')
        p = pos + len(prefix)
        demand(not any(i in covered for i in range(p, p + 4)), 'overlapping operand masks')
        covered.update(range(p, p + 4))
        dl = struct.unpack('<i', left[p:p + 4])[0]
        dr = struct.unpack('<i', right[p:p + 4])[0]
        end_left = first + p + 4
        end_right = second + p + 4
        operands.append((pos, prefix_hex, left[p:p + 4], right[p:p + 4],
                         end_left + dl, end_right + dr))
        la[p:p + 4] = b'\0' * 4
        lb[p:p + 4] = b'\0' * 4
    differences = [(i, left[i], right[i]) for i in range(n) if left[i] != right[i]]
    demand(all(i in covered for i, _, _ in differences), 'unmasked body difference')
    demand(la == lb, 'masked pair differs')
    return n, differences, operands, covered, hashlib.sha256(la).hexdigest()


def fixed_division_model(value, multiplier, shift):
    demand(isinstance(value, int) and 0 <= value < 1 << 64, 'value outside u64')
    return (value * multiplier) >> (64 + shift)


def field_key_model(value):
    """Synthetic spelling model for the four pinned comparison paths."""
    if value in (b'a', b'asset'):
        return 0
    if value in (b't', b'twapId'):
        return 1
    return None


def compact_remove_plan(capacity, head, length, index):
    """Synthetic model for the selected callers and 96/112-byte shift helpers.

    A copy is (destination index, source index, element count). This model is
    limited to valid compact-ring removals; it is not a general circular copy.
    """
    demand(all(isinstance(n, int) for n in (capacity, head, length, index))
           and 0 < capacity <= ((1 << 64) - 1) // 112 and 0 <= head < capacity and 0 < length <= capacity
           and 0 <= index < length, 'invalid compact-ring input')
    row = (head + index) % capacity
    suffix = length - index - 1
    if suffix < index:
        source, destination, count, new_head = (row + 1) % capacity, row, suffix, head
    else:
        source, destination, count = head, (head + 1) % capacity, index
        new_head = destination
    if source == destination or count == 0:
        return new_head, []
    distance = (destination - source) % capacity
    source_tail, destination_tail = capacity - source, capacity - destination
    if count <= source_tail:
        if count <= destination_tail:
            copies = [(destination, source, count)]
        elif distance >= count:
            copies = [(destination, source, destination_tail),
                      (0, source + destination_tail, count - destination_tail)]
        else:
            copies = [(0, source + destination_tail, count - destination_tail),
                      (destination, source, destination_tail)]
    elif distance >= count:
        if count <= destination_tail:
            copies = [(destination, source, source_tail),
                      (destination + source_tail, 0, count - source_tail)]
        else:
            copies = [(destination, source, source_tail),
                      (destination + source_tail, 0, destination_tail - source_tail),
                      (0, destination_tail - source_tail, count - destination_tail)]
    elif count <= destination_tail:
        copies = [(destination + source_tail, 0, count - source_tail),
                  (destination, source, source_tail)]
    else:
        copies = [(source_tail - destination_tail, 0, count - source_tail),
                  (0, source + destination_tail, source_tail - destination_tail),
                  (destination, source, destination_tail)]
    return new_head, copies


def record_arithmetic_model(value, selector, multiplier, offset):
    """Synthetic unsigned model for the selected selector-less-than-two path."""
    maximum = (1 << 64) - 1
    demand(isinstance(value, int) and 0 <= value <= maximum and selector in (0, 1)
           and multiplier > 0 and 0 < offset <= maximum, 'invalid record arithmetic input')
    tenfold = min(value * multiplier, maximum)
    combined = min(tenfold + selector, maximum)
    shifted = min(combined + offset, maximum)
    return shifted - offset


def as_hex(value):
    return hex(value)


def write_tsv(path, header, rows):
    with path.open('w', encoding='utf-8', newline='') as handle:
        writer = csv.writer(handle, delimiter='\t', lineterminator='\n')
        writer.writerow(header)
        writer.writerows(rows)


def generate(image, out):
    fdes = validate_fdes(image)
    windows = validate_windows(image)
    branches = checked_branches(image)
    calls = checked_calls(image)
    jumps = checked_jumps(image)
    table_leas = (
        ('name_context', 0x36616c6, NAME_TABLE),
        ('decode_context', 0x36b8d23, DECODE_TABLE),
        ('inner_context', 0x2bdbb1f, INNER_TABLE),
        ('direct_context', 0x2bda83c, OUTER_TABLE),
        ('parser_kind', 0x39d108d, INPUT_TABLE),
        ('context_type_name', 0x36b9332, 0x453820),
        ('context_field_descriptors', 0x36b9339, FIELD_TABLE),
    )
    table_base_rows = []
    for role, site, expected in table_leas:
        raw, target = decode_rip_lea(image, site)
        demand(target == expected, 'RIP-relative table base mismatch: ' + role)
        table_base_rows.append((role, as_hex(site), as_hex(image.offset(site, len(raw))), raw.hex(), as_hex(target)))
    selected_index = image.read(0x3662628, 1)[0]
    action_name = image.read(0x3661e58, 8) + image.read(0x3661e6b, 2)
    demand(action_name == b'twapCancel' and selected_index == INDEX, 'name-to-index mismatch')
    name_bias = -struct.unpack('<b', image.read(0x36616bb, 1))[0]
    field_count = struct.unpack('<I', image.read(0x36b934f, 4))[0]
    input_count = image.read(0x39d1076, 1)[0] + 1
    demand((name_bias, field_count, input_count) == (4, 4, 15), 'selected selector bounds mismatch')
    earlier_base = struct.unpack('<Q', image.read(0x3661e2f, 8))[0]
    adjustment = struct.unpack('<i', image.read(0x3661e3a, 4))[0]
    earlier_name = struct.pack('<Q', (earlier_base + adjustment) & ((1 << 64) - 1)) + image.read(0x3661e49, 2)
    earlier_index = image.read(0x3662586, 1)[0]
    demand(earlier_name == b'spotDeploy' and earlier_index == 27, 'preceding name comparison mismatch')
    demand(image.containing_fde(0x2a2fbe2)['start'] == subject_call_target(calls, 'context_nested_wrapper'),
           'nested context call is outside its wrapper FDE')
    demand(image.containing_fde(0x2c0a868)['start'] == subject_call_target(calls, 'context_direct_wrapper'),
           'direct context call is outside its wrapper FDE')

    # The selected 35th case is constrained independently by four bytes in
    # the decoder, the type descriptor, and the existing router's table entry.
    field_rows = []
    for i, expected in enumerate(('a', 'asset', 't', 'twapId')[:field_count]):
        slot = FIELD_TABLE + 16 * i
        ptr, length, name = image.relative_string(slot)
        demand(name == expected, 'field descriptor mismatch')
        field_rows.append(('field', i, as_hex(slot), as_hex(image.offset(slot, 16)),
                           as_hex(ptr), length, name))
    for i, table in enumerate(VARIANT_TABLES):
        slot = table + 16 * selected_index
        ptr, length, name = image.relative_string(slot)
        demand(name == 'twapCancel', 'variant descriptor mismatch')
        field_rows.append(('variant_copy', i, as_hex(slot), as_hex(image.offset(slot, 16)),
                           as_hex(ptr), length, name))
    demand(image.read(0x453820, 16) == b'TwapCancelAction', 'type-name mismatch')

    switch_rows = []
    name_fde = image.containing_fde(0x3661e2d)
    name_index = len(action_name) - name_bias
    cell, raw, dest = image.table_target(NAME_TABLE, name_index, name_fde['start'], name_fde['end'])
    demand(dest == 0x3661e2d, 'name-length table mismatch')
    switch_rows.append(('name_length_context', len(action_name), name_index, as_hex(NAME_TABLE), as_hex(cell),
                        as_hex(image.offset(cell, 4)), raw.hex(), as_hex(dest)))
    for role, table, idx, anchor in (
        ('decode_context', DECODE_TABLE, selected_index, 0x36b9332),
        ('inner_context', INNER_TABLE, selected_index, 0x2bdbdde),
        ('direct_context', OUTER_TABLE, selected_index, 0x2bdaa19),
    ):
        fde = image.containing_fde(anchor)
        cell, raw, dest = image.table_target(table, idx, fde['start'], fde['end'])
        switch_rows.append((role, idx, idx, as_hex(table), as_hex(cell),
                            as_hex(image.offset(cell, 4)), raw.hex(), as_hex(dest)))
    demand([r[-1] for r in switch_rows[1:]] == ['0x36b9332', '0x2bdbdde', '0x2bdaa19'],
           'selected dispatch arm mismatch')
    for i in range(input_count):
        cell, raw, dest = image.table_target(INPUT_TABLE, i, 0x39d0f20, 0x39d1b0a)
        switch_rows.append(('parser_input_kind', i + 1, i, as_hex(INPUT_TABLE), as_hex(cell),
                            as_hex(image.offset(cell, 4)), raw.hex(), as_hex(dest)))

    # Direct extraction from pinned x86 immediates, followed by a certificate
    # for unsigned division across the entire 64-bit input range.
    bias = struct.unpack('<I', image.read(0x2bdbb12, 4))[0]
    tag = struct.unpack('<I', image.read(0x36b9370, 4))[0]
    threshold = struct.unpack('<Q', image.read(0x2a2fbb9, 8))[0]
    multiplier = struct.unpack('<Q', image.read(0x2c2f06b, 8))[0]
    shift = image.read(0x2c2f07f, 1)[0]
    pass_word = struct.unpack('<H', image.read(0x2a2fba9, 2))[0]
    id_reject = struct.unpack('<H', image.read(0x2a2fce7, 2))[0]
    route_reject = struct.unpack('<H', image.read(0x2c2f051, 2))[0]
    missing_word = struct.unpack('<H', image.read(0x2d2ccdb, 2))[0]
    route0_pass = struct.unpack('<H', image.read(0x2c2f4c5, 2))[0]
    route1_pass = struct.unpack('<H', image.read(0x2c2f605, 2))[0]
    wrapper_core_tag = image.read(0x2a2fc44, 1)[0]
    wrapper_reject_tag = image.read(0x2a2fcef, 1)[0]
    record0_size = struct.unpack('<I', image.read(0x2c2f4aa, 4))[0]
    record1_size = struct.unpack('<I', image.read(0x2c2f5ea, 4))[0]
    scale = 1 << (64 + shift)
    divisor = (scale + multiplier // 2) // multiplier
    error = multiplier * divisor - scale
    demand(tag - bias == INDEX and threshold == 0x0ccccccccccccccc,
           'tag or threshold mismatch')
    demand((pass_word, id_reject, route_reject, missing_word) == (0x1a2, 0x154, 0x108, 0xd4),
           'selected result word mismatch')
    demand((route0_pass, route1_pass, wrapper_core_tag, wrapper_reject_tag, record0_size, record1_size)
           == (pass_word, pass_word, 5, 15, 0x2b8, 0x2c8), 'result or record-shape mismatch')
    demand(multiplier == (scale + divisor - 1) // divisor and error >= 0,
           'reciprocal is not a ceiling')
    demand(((1 << 64) - 1) * error < scale, 'reciprocal proof bound failed')

    # Both route-zero record constructors split the same 64-bit key into a
    # group and a remainder. Route-one constructors use a direct row index.
    # The offsets and immediates below come from the pinned instruction bytes.
    metadata_rows = []
    for role, mul_va, shift_va, divisor_va, group_va, length_va, stride_va in (
        ('route0_other', 0x2a8119f, 0x2a811b3, 0x2a811d8, 0x2a811b7, 0x2a811e5, 0x2a811f3),
        ('route0_one', 0x2a81ac9, 0x2a81add, 0x2a81b02, 0x2a81ae1, 0x2a81b0f, 0x2a81b1d),
    ):
        record_mul = struct.unpack('<Q', image.read(mul_va, 8))[0]
        record_shift = image.read(shift_va, 1)[0]
        record_divisor = struct.unpack('<I', image.read(divisor_va, 4))[0]
        group_offset = image.read(group_va, 1)[0]
        length_offset = image.read(length_va, 1)[0]
        stride_shift = image.read(stride_va, 1)[0]
        demand((record_mul, record_shift, record_divisor, group_offset, length_offset, stride_shift)
               == (multiplier, shift, divisor, 0x50, 0x10, 5), 'record metadata arithmetic mismatch')
        metadata_rows.append((role, 'quotient_remainder', as_hex(mul_va), record_mul,
                              record_shift, record_divisor, as_hex(group_offset),
                              as_hex(length_offset), stride_shift, 1 << stride_shift))
    for role, length_va, stride_va in (('route1_other', 0x2a80ccb, 0x2a80d38),
                                        ('route1_one', 0x2a8156a, 0x2a815db)):
        length_offset = image.read(length_va, 1)[0]
        stride_shift = image.read(stride_va, 1)[0]
        demand((length_offset, stride_shift) == (0x10, 5), 'direct record metadata stride mismatch')
        metadata_rows.append((role, 'direct_index', '', '', '', '', '', as_hex(length_offset),
                              stride_shift, 1 << stride_shift))

    # All selected helper slot references resolve to one GLOB_DAT import.
    # This records the linked symbol, not the runtime binding or its effects.
    import_slot = 0x64df568
    imported = dynamic_import(image, import_slot)
    slot_refs = []
    for role, site in (
        ('shift112_call_a', 0x24da5ff), ('shift112_call_b', 0x24da615),
        ('shift112_load_a', 0x24da62e), ('shift112_load_b', 0x24da671),
        ('shift112_load_c', 0x24da6ba), ('shift112_tail', 0x24da71c),
        ('shift112_load_d', 0x24da735), ('shift112_load_e', 0x24da75c),
        ('shift112_load_f', 0x24da790),
        ('shift96_call_a', 0x24dff75), ('shift96_call_b', 0x24dff96),
        ('shift96_load_a', 0x24dffc5), ('shift96_load_b', 0x24e001b),
        ('shift96_load_c', 0x24e0074), ('shift96_tail', 0x24e00f1),
        ('shift96_load_d', 0x24e011d), ('shift96_load_e', 0x24e015a),
        ('shift96_load_f', 0x24e01a5),
    ):
        raw, target = decode_rip_slot(image, site)
        demand(target == import_slot, 'unexpected shift slot reference: ' + role)
        slot_refs.append((role, as_hex(site), as_hex(image.offset(site, len(raw))), raw.hex(), as_hex(target)))
    stride112 = image.read(0x24da6fc, 1)[0]
    sib = image.read(0x24e00c5, 1)[0]
    stride96 = (1 + (1 << (sib >> 6))) << image.read(0x24e00c9, 1)[0]
    demand((stride112, stride96) == (112, 96), 'shift element stride mismatch')

    arithmetic_rows = []
    for role, slot_site, limit_site, factor_site, negative_site, offset_site, compare_site, overflow_site, remove_site in (
        ('route1_other', 0x2a80d47, 0x2a80d55, 0x2a80d59, 0x2a80d83, 0x2a80d8c, 0x2a80daf, 0x2a80d62, 0x2a80dd7),
        ('route1_one', 0x2a815ea, 0x2a815f8, 0x2a815fc, 0x2a81626, 0x2a8162f, 0x2a81652, 0x2a81605, 0x2a8167a),
    ):
        slot_raw, arithmetic_slot = decode_rip_slot(image, slot_site)
        limit = image.read(limit_site, 1)[0]
        factor = struct.unpack('<I', image.read(factor_site, 4))[0]
        negative_offset = struct.unpack('<i', image.read(negative_site, 4))[0]
        offset = struct.unpack('<I', image.read(offset_site, 4))[0]
        comparison = struct.unpack('<I', image.read(compare_site, 4))[0]
        removal = struct.unpack('<i', image.read(remove_site, 4))[0]
        overflow_raw, overflow_cc, overflow_target = decode_branch(image, overflow_site)
        demand((limit, factor, negative_offset, offset, comparison, removal, overflow_cc)
               == (2, 10, -100000000, 100000000, 100000000, -100000000, 0), 'record arithmetic constants mismatch')
        arithmetic_rows.append((role, as_hex(slot_site), slot_raw.hex(), as_hex(arithmetic_slot),
                                limit, factor, negative_offset, offset, as_hex(overflow_site),
                                overflow_raw.hex(), as_hex(overflow_target)))

    pair_rows, operand_rows, diff_rows = [], [], []
    for role, first, second, sites in PAIRS:
        size, diffs, operands, covered, masked_sha = pair_records(image, first, second, sites)
        pair_rows.append((role, as_hex(first), as_hex(second), size, size - len(diffs),
                          len(diffs), len(covered), len(operands),
                          sum(left_target != right_target for _, _, _, _, left_target, right_target in operands), masked_sha))
        for pos, prefix, left, right, left_target, right_target in operands:
            operand_rows.append((role, as_hex(pos), prefix, left.hex(), right.hex(),
                                 as_hex(left_target), as_hex(right_target),
                                 int(left_target == right_target)))
        for pos, a, b in diffs:
            diff_rows.append((role, as_hex(pos), f'{a:02x}', f'{b:02x}'))

    out.mkdir(parents=True, exist_ok=True)
    write_tsv(out / 'functions.tsv',
              ('role', 'start_va', 'end_va_exclusive', 'file_offset', 'fde_va', 'cie_va',
               'lsda_va', 'body_size', 'body_sha256', 'body_hex'),
              [(role, as_hex(start), as_hex(end), as_hex(image.offset(start, end - start)),
                as_hex(fde['fde']), as_hex(fde['cie']), as_hex(fde['lsda']) if fde['lsda'] is not None else '',
                end - start, digest, body.hex()) for role, start, end, fde, body, digest in fdes])
    write_tsv(out / 'windows.tsv', ('role', 'site_va', 'file_offset', 'bytes'),
              [(role, as_hex(va), as_hex(off), raw.hex()) for role, va, off, raw in windows])
    write_tsv(out / 'branches.tsv', ('role', 'site_va', 'file_offset', 'bytes', 'condition_code', 'target_va'),
              [(role, as_hex(va), as_hex(off), raw.hex(), as_hex(cc), as_hex(target))
               for role, va, off, raw, cc, target in branches])
    write_tsv(out / 'calls.tsv', ('role', 'site_va', 'file_offset', 'bytes', 'target_va'),
              [(role, as_hex(va), as_hex(off), raw.hex(), as_hex(target))
               for role, va, off, raw, target in calls])
    write_tsv(out / 'jumps.tsv', ('role', 'site_va', 'file_offset', 'bytes', 'target_va'),
              [(role, as_hex(va), as_hex(off), raw.hex(), as_hex(target))
               for role, va, off, raw, target in jumps])
    write_tsv(out / 'name-order.tsv', ('order', 'name', 'comparison_site', 'match_site', 'ordinal'),
              [(0, earlier_name.decode('ascii'), as_hex(0x3661e2d), as_hex(0x3662583), earlier_index),
               (1, action_name.decode('ascii'), as_hex(0x3661e56), as_hex(0x3662625), selected_index)])
    write_tsv(out / 'descriptors.tsv', ('kind', 'index', 'slot_va', 'file_offset', 'string_va', 'length', 'text'), field_rows)
    relocation_rows = []
    descriptor_slots = [FIELD_TABLE + 16 * i for i in range(field_count)] + [table + 16 * selected_index for table in VARIANT_TABLES]
    for slot in descriptor_slots + [0x64e5b38]:
        demand(slot in image.relocations, 'selected RELATIVE relocation missing')
        addend, record_off, info = image.relocations[slot]
        raw = bytes(image.data[record_off:record_off + 24])
        relocation_rows.append((as_hex(slot), as_hex(record_off), raw.hex(), as_hex(info & 0xffffffff), as_hex(addend)))
    write_tsv(out / 'relocations.tsv', ('slot_va', 'record_file_offset', 'raw_rela', 'type', 'addend_va'), relocation_rows)
    write_tsv(out / 'rip-references.tsv', ('role', 'site_va', 'file_offset', 'bytes', 'target_va'), table_base_rows)
    write_tsv(out / 'switches.tsv', ('role', 'selector_value', 'table_index', 'table_va', 'slot_va', 'file_offset', 'raw_i32_le', 'target_va'), switch_rows)
    write_tsv(out / 'pairs.tsv', ('role', 'first_va', 'second_va', 'size', 'raw_equal', 'raw_different', 'masked_positions', 'operands', 'different_targets', 'masked_sha256'), pair_rows)
    write_tsv(out / 'pair-operands.tsv', ('pair', 'body_offset', 'opcode', 'first_disp_le', 'second_disp_le', 'first_target', 'second_target', 'target_equal'), operand_rows)
    write_tsv(out / 'pair-diffs.tsv', ('pair', 'body_offset', 'first_byte', 'second_byte'), diff_rows)
    write_tsv(out / 'record-indexing.tsv', ('role', 'index_kind', 'multiplier_va', 'multiplier',
              'post_high_shift', 'divisor', 'group_member_offset', 'length_member_offset',
              'stride_shift', 'stride_bytes'), metadata_rows)
    write_tsv(out / 'shift-slot-references.tsv', ('role', 'site_va', 'file_offset', 'bytes', 'slot_va'), slot_refs)
    off, raw_rela, kind, symbol_index, symbol_off, raw_symbol, name_off, name = imported
    write_tsv(out / 'shift-dynamic-import.tsv', ('slot_va', 'rela_file_offset', 'rela_bytes',
              'relocation_type', 'symbol_index', 'symbol_file_offset', 'symbol_bytes',
              'name_file_offset', 'name'),
              [(as_hex(import_slot), as_hex(off), raw_rela.hex(), kind, symbol_index, as_hex(symbol_off),
                raw_symbol.hex(), as_hex(name_off), name)])
    write_tsv(out / 'shift-strides.tsv', ('role', 'instruction_va', 'stride_bytes'),
              [('compact_shift_112', as_hex(0x24da6f9), stride112),
               ('compact_shift_96', as_hex(0x24e00c2), stride96)])
    write_tsv(out / 'record-arithmetic.tsv', ('role', 'call_site_va', 'call_bytes', 'call_slot_va',
              'selector_limit', 'multiplier', 'negative_immediate', 'offset', 'overflow_branch_va',
              'overflow_branch_bytes', 'overflow_target_va'), arithmetic_rows)
    constants = {'binary_sha256': TARGET, 'index': selected_index, 'tag_bias': bias, 'tag': tag,
                 'name': action_name.decode('ascii'), 'classifier_pass_word': pass_word,
                 'id_reject_word': id_reject, 'route_one_gate_word': route_reject,
                 'remove_missing_word': missing_word, 'wrapper_core_return_tag': wrapper_core_tag,
                 'wrapper_reject_tag': wrapper_reject_tag, 'route0_record_size': record0_size,
                 'route1_record_size': record1_size,
                 'id_limit_exclusive': threshold, 'reciprocal_multiplier': multiplier,
                 'post_high_shift': shift, 'inferred_divisor': divisor,
                 'reciprocal_error': error, 'certificate_max_u64_times_error': ((1 << 64) - 1) * error,
                 'certificate_scale': scale, 'type_name': image.read(0x453820, 16).decode('ascii')}
    (out / 'constants.json').write_text(json.dumps(constants, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    summary = {'binary_sha256': TARGET, 'selected_fdes': len(fdes), 'selected_windows': len(windows),
               'selected_branches': len(branches), 'selected_calls': len(calls),
               'selected_jumps': len(jumps), 'ordered_name_candidates': 2,
               'descriptors': len(field_rows), 'switch_entries': len(switch_rows),
               'rip_references': len(table_base_rows), 'selected_relocations': len(relocation_rows),
               'body_pairs': len(pair_rows), 'masked_operands': len(operand_rows),
               'raw_differing_positions': len(diff_rows), 'record_indexing_paths': len(metadata_rows),
               'shift_slot_references': len(slot_refs), 'shift_dynamic_imports': 1,
               'record_arithmetic_paths': len(arithmetic_rows)}
    (out / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    data = BINARY.read_bytes()
    result = generate(Image(data), args.out)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, struct.error) as exc:
        print('re010_twap_cancel_115:', str(exc), file=sys.stderr)
        raise SystemExit(1)
