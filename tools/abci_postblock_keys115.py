#!/usr/bin/env python3
"""Extract selected #115 post-block key, dispatch, queue and result evidence.

Only the Python standard library and the repository ELF/unwind readers are used.
Addresses identify fixed instruction windows; this is not a general x86 decoder.
"""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
HISTORICAL_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# These are selected unwind extents, not a complete function census.
FUNCTIONS = (
    ('result_row_cleanup', 0x4f33990, 0x4f33bad, 0x130dd64),
    ('expanded_row_wrapper', 0x5601970, 0x5601bdf, 0x135f140),
    ('compact_row_wrapper', 0x5601be0, 0x5601e4f, 0x135f18c),
    ('expanded_postblock', 0x5601e50, 0x5605ed6, 0x135f1d8),
    ('compact_postblock', 0x5605ee0, 0x5609de8, 0x135f230),
    ('append_ring_192', 0x57c3090, 0x57c32cf, 0x13765c0),
)

# Exact hashes anchor instruction-aligned windows without importing a disassembler.
# Context windows are dependencies of earlier proposals, never newly owned bodies.
WINDOWS = (
    ('context', 'compact_engine_cell', 0x5a04f52, 0x5a04f6f, '36220e1edc7e0d1bc3b935208f04690b54822e33f762072eb240167bf2d8cbaa'),
    ('context', 'compact_engine_late', 0x5a05596, 0x5a055b5, '841f0501dd5467136a513a3ca8fc756d6639aebec9b03ffdee3929f36ea63b99'),
    ('context', 'compact_root_capture', 0x269a20b, 0x269a21a, 'b4c1d25e6d4595f51fc9da0c077b0addbed5a944c8d9642e863dead950edde5d'),
    ('context', 'expanded_save_cell', 0x54868f9, 0x548690b, '0dc5e23fbd3ae1721150416610ceff228e0fb3876fc052519b0f694a136d1313'),
    ('context', 'compact_save_cell', 0x54899b9, 0x54899cb, 'ed4b074edc303c6a15d6cda823c2e81285c15df8d105d8e586716c492d394cb9'),
    ('context', 'late_expanded_result_zero', 0x5486d67, 0x5486de7, '5c5fbca725baa1516b35180f810d25ccbd8a2c9a9eb56b9aac710052a297b610'),
    ('context', 'late_expanded_result_growth', 0x5489284, 0x54892cc, '0cb9c7c2730cf2b1dd43267d9b22634612e0666358524b192eab4237e57d6120'),
    ('context', 'prior_root_map_capture', 0x4e3437b, 0x4e3438a, '336ee3a1fe6f15a7971ce4afb431d98db45fb52916f565006b39ef94fa5620b4'),
    ('context', 'prior_keyed_update_gate', 0x55f495c, 0x55f499c, 'e4c47c74dde79dfa80171147b323db6d7648504fda76cce177c5b84f8de76827'),
    ('new', 'expanded_direct_unwind', 0x5605c7a, 0x5605ca3, '392191938596bced75d86a2208fee4e13f2e823c0647a12eefd8ded0b42a9381'),
    ('new', 'compact_direct_unwind', 0x5609ba6, 0x5609bb8, '24559121364650160c6492ee4cc4bf4b7d072edbb0bc65fbe3ccf44b02bf7eaa'),
    ('context', 'prior_adapter_pointer', 0x56186c9, 0x56186d3, '7980c8b665bad82b1250a2f4d458fbc4c4539c9e5ec56ddc0e51993a62401e6d'),
    ('context', 'prior_adapter_call', 0x5618704, 0x5618715, '169b7da1111aa4a100f640afb34a13a2e20bca37512774d97c99ece33cb8894b'),
    ('context', 'prior_key_map_prepare', 0x55f499c, 0x55f4a11, '19c8eee225367809b4cacdaa1686acc556329156149f0e6e34cff9cd4fd431aa'),
    ('context', 'prior_key_map_store', 0x55f4af1, 0x55f4b21, '7e0b58f71f32e87319b806d30152ada4825ce5a78ea6b2dfc93b82f4b413fb91'),
    ('context', 'late_save_rows', 0x5487625, 0x5487647, 'dfa851b31fa560fd37d708ed75f84a49a20298eb27d34ead33349ba94dcedce7'),
    ('context', 'late_prepare_return', 0x5488f03, 0x5488f1d, 'c226afd3e5e67515cefb133ac5f10f1148f6bc77cbb68d5cbd1e102a075391b2'),
    ('context', 'late_copy_return', 0x5489103, 0x5489140, 'b583e68e9f48056c44e07e5129744052ff56022f3501a1ee5261f1cacd45c53b'),
    ('context', 'engine_result_projection', 0x5a07888, 0x5a078c4, 'aeb913fc2bc7548d81c251cf8dd6403a6a6f380e76d85e0cf9207d1600a6a13b'),
    ('context', 'upper_engine_output', 0x4fcb788, 0x4fcb79a, '0df6bbcd46f39fdcf43c7b7bf87d537483f0cb4a9bce779398a7b810c6f683c2'),
    ('context', 'upper_prior_result_cleanup', 0x4fcb79a, 0x4fcb818, '32cfba29d78acfd0a31a3636899361c0a072cfad30423ca6399a04182f87b572'),
    ('context', 'upper_result_cleanup', 0x4fcb818, 0x4fcb825, '49a8d49bd7ef916a2f664fa3d67120154443a450b7e236c858c3550df53154d8'),
    ('new', 'result_cleanup_loop', 0x4f33990, 0x4f339f5, '629717844b2a995420fd944519cf02fd4640452bbfce9d38da0f7467fe8ca6ca'),
    ('new', 'result_cleanup_tail_vectors', 0x4f339f5, 0x4f33a9c, '734cd9588fc95680947fc7b550c82551a98ad0f9727fc11feda57703897cebcc'),
    ('new', 'result_cleanup_tail_unwind', 0x4f33a9c, 0x4f33b27, 'e7fa47a15a15870853968454d6c244f541f006079f7f70b2d27805b7680f1ab2'),
    ('new', 'result_cleanup_unwind', 0x4f33b27, 0x4f33ba1, 'ec22318f2443cb719b825e08dba8ce2c25c09f19ffd000e0a172db49dbc7478b'),
    ('context', 'loader_location', 0x3c1352f, 0x3c13541, '89c07373021f47f27b075f89f0990f68b1fbed732421400f9815c92ba4496ba0'),
    ('context', 'engine_cell', 0x5a0671a, 0x5a06733, 'a025aa7a3f67d53bb37552fa400ac2ef6d1e32f6a46767416097c21e90c9cc75'),
    ('context', 'engine_late', 0x5a06da0, 0x5a06dbb, '88efc987c05ba21b94ed1707abc8835dfa3f818d13971dc4923292cc203ad674'),
    ('context', 'engine_root', 0x5a077d0, 0x5a077ee, '46767584968c15de16d83dc48a7987f9fa33f461d2d1c99dda53220e96235849'),
    ('context', 'late_expanded_entry', 0x548673b, 0x548675d, 'ac4d80124264e9f031dfe8634b351d8e266b5de221ab41904d02c1f7ac6d05dc'),
    ('context', 'late_expanded_zero', 0x5486cf3, 0x5486d67, '9daedaaa75d3ab3bac66cb26f3933049c96739d950920cc4935c67e62e468e65'),
    ('context', 'late_expanded_one', 0x5487208, 0x5487272, '60e9ace5f687b3139384b6901c27c05ea91f65af8e11a6ee992ed94dbad4ba0a'),
    ('context', 'late_compact_entry', 0x54897fb, 0x548981d, 'c786e012f92177cb4f39b12f4042b8308a9b370e2c84f349a027a9080d346083'),
    ('context', 'late_compact_zero', 0x5489e83, 0x5489ed8, 'ec6bb06c9d68052b5ec8a298be746cea4507ac51b03a2327f8f4e54b96b2cbaf'),
    ('context', 'late_compact_one', 0x548a35b, 0x548a3d1, '26c361466ecdd3f034018687944d925fa359b6f3f468ce581acc177a1d0f1406'),
    ('context', 'late_result_copy', 0x54872bd, 0x548730c, '8d69856f8df1191f00e771655988b7d5f2ea090136880a37a2441f414aaeda9b'),
    ('context', 'nested_stack_args', 0x55f4760, 0x55f477d, 'fac6ce55ecb9d0a1fc2817d257e73cdd1234556dbecf62409d6c88da825d83b2'),
    ('context', 'nested_flag_load', 0x55f4870, 0x55f4880, 'de6bb9cc5f8f5936d1f0412dd9f6e0c96a054eccbab187482fd712a39f7ee059'),
    ('context', 'nested_flag_decision', 0x55f4a94, 0x55f4aaf, '127e2c31b68e7c6e50add4c30b6c6259dacddff92ceb0fcad220fc9b19daac97'),
    ('context', 'nested_flag_effect', 0x55f4c60, 0x55f4c96, '3c6091b566ba37ba08897931b2ef5a669e37df8f910d1a3ea8b112b2cf8ab25d'),
    ('new', 'expanded_capture', 0x5601e70, 0x5601f78, 'a8f36a6880d4362f616e47d279a80ba10ac3bed7861f43e13cd19fae48683292'),
    ('new', 'expanded_append_source', 0x5601fba, 0x5602012, 'b572dbd41f7adf594c70517e49e4e5044e3a8ed59dfab03a5fd14792dac4f372'),
    ('new', 'expanded_detach', 0x5602012, 0x5602078, '0f652d3452084c7bf32c645dd9b650d8ee4db8f318bfbf74a3ac828fd8e527ab'),
    ('new', 'expanded_loop_init', 0x56050cc, 0x560517c, 'be973c0b897b42ff755ae4436623d3d5f3e1465c33a4f65b9689e6c6ff4c6782'),
    ('new', 'expanded_key', 0x560517c, 0x5605275, '00be36bee014a3557e08033a3800914e8c668a3f037218ac9b9a56bfc89f6a50'),
    ('new', 'expanded_wrapped', 0x5605275, 0x56052bf, '6a0301ff7e97b5c1c3cd77adce2c758edb2e50cc3739e84703ef91b2a005dd50'),
    ('new', 'expanded_direct', 0x56052c0, 0x5605314, '2fd563ce112de8ff256a185becce6692b6717477e7381871c83258e696233f91'),
    ('new', 'expanded_direct_counter', 0x5605396, 0x56053ea, 'a592df42e435382dc89afa2e9f195a8afe8eec20493ce6995d5acf89311efd71'),
    ('new', 'expanded_second_loop', 0x56055ab, 0x56056ed, 'b41609b2cd2ad3f8a6ff95724c994f8c5b4138f84254fc52ad22938ef7bc41d8'),
    ('new', 'expanded_result_return', 0x56056ed, 0x560571e, 'f0a833f2944b7403c314aab01af9889a39eb16125e5a58b0353f4dd966b3c269'),
    ('new', 'compact_capture', 0x5605f00, 0x5606008, '318e9466cf4a2e71ed05051f70cffe8e55bab9133208d69fe68ea7b738f514da'),
    ('new', 'compact_append_source', 0x560604a, 0x56060a2, '8c5b3ebfc58f7d84044ee7cda1c425550409eac543ab4b0c1a155f57b11e0157'),
    ('new', 'compact_detach', 0x56060a2, 0x560610a, '0a455902196e51fb68526e2d372bcf577e57ce14c54f79a529735a9c7107a64f'),
    ('new', 'compact_loop_init', 0x56090b9, 0x5609149, '14b5c8886983b6fd89c5a45b848ec2be1923d44322eeeacb8908ca92a2b6660f'),
    ('new', 'compact_key', 0x5609149, 0x5609245, '6ec719001bfa9f1b82c5487bb8c9afb5720102c04658e7d954b03fbe75920415'),
    ('new', 'compact_wrapped', 0x5609245, 0x5609294, 'ce03e16d3d10ecef06f7dd18639365a0f5c9243fa78cb603ca4941a91d50f8d3'),
    ('new', 'compact_direct', 0x56092a0, 0x56092e4, '96dd84804a306ebcc4623937d43383a6a8d8e4a7f9ad50d64eb138963caf35ab'),
    ('new', 'compact_direct_counter', 0x56092e4, 0x5609312, '04bf0a13905da99c7374f5871bddb0f43783011329baf4a8376841ebe56c30dc'),
    ('new', 'compact_second_loop', 0x56094cb, 0x5609613, 'ba04e4215668a1a52d22263e86831e0c608e050b958ec8168e865ff62ad26608'),
    ('new', 'compact_result_return', 0x5609613, 0x5609644, '2f941f6b982375873b810e8bf3df9a781b430505cf17431a68b932e3cd464abb'),
    ('new', 'expanded_wrapper_setup', 0x5601970, 0x5601a0b, 'ffefd3581f02bb6d232c8d53f7f6876512ade3984842a73049a984226720e8a0'),
    ('new', 'expanded_wrapper_result', 0x5601a0b, 0x5601acb, '54944843f9b374d9db0c349b62d0a62e30e36ec2ff885f1281db089694afa507'),
    ('new', 'expanded_wrapper_counter', 0x5601acb, 0x5601af9, 'b0a0a9a054aa0abe0c7c60c51b86429ab00647ec07e184a8b387b43e09536eac'),
    ('new', 'expanded_wrapper_output', 0x5601b03, 0x5601b62, '8a58fa86bc80d7a7d2852c410069d009867948fb7c3866fde0bfd6f5a51f6102'),
    ('new', 'expanded_wrapper_unwind', 0x5601ba2, 0x5601bdf, '44725ffc41edc5a09f1389b699a92ff52b6ecb9d04062a94ed6128a19ac4112f'),
    ('new', 'compact_wrapper_setup', 0x5601be0, 0x5601c7b, 'd530f13408d183701e7661fd184a40b955f503edeb5b8cb27e55a008d5b15c92'),
    ('new', 'compact_wrapper_result', 0x5601c7b, 0x5601d3b, '38aba3b7e0e2ef341de1a3ae25b6a45f7ed8a7b042f27e453cef0348c06753fc'),
    ('new', 'compact_wrapper_counter', 0x5601d3b, 0x5601d69, 'b0a0a9a054aa0abe0c7c60c51b86429ab00647ec07e184a8b387b43e09536eac'),
    ('new', 'compact_wrapper_output', 0x5601d73, 0x5601dd2, 'ca69eb6faafce86279e1a2b632778d35a4d99fe1087bda39210ed7d26de9dfef'),
    ('new', 'compact_wrapper_unwind', 0x5601e12, 0x5601e4f, 'fe1f351937c7d96a2fe12acd8e027c6afce9ecc0c84833a337077a225d7c8784'),
    ('new', 'ring_count_guards', 0x57c3090, 0x57c3100, 'de300ef84d630c57f44b6cc133838e49619afc0ebd971f83bcf0c42e49b34ea7'),
    ('new', 'ring_move_and_wrap', 0x57c3100, 0x57c31a9, 'd8d6df5bef795a194db73992e8878b52cce8c54bf41fac7b18fd6eb4f6610caf'),
    ('new', 'ring_copy_return', 0x57c31a9, 0x57c325f, '7d51c73fe5d538c86011271e33024e0ccbf24c917095a00feafc5b635caa7ab2'),
    ('new', 'ring_failure_growth', 0x57c325f, 0x57c32cf, 'daf101b4f3982b0fff95f6770787d98b1ed354d92378881973b129b317782da1'),
)

# Encodings are selected instruction starts verified by bounded human inspection.
# The target is independently calculated from the encoded signed displacement.
EDGES = (
    ('context', 'upper_calls_adapter', 0x4fcb795, 'call', 0x56186c0),
    ('context', 'adapter_calls_engine', 0x5618710, 'call', 0x5a06600),
    ('context', 'upper_calls_row_cleanup', 0x4fcb820, 'call', 0x4f33990),
    ('context', 'upper_prior_row_action_cleanup', 0x4fcb7df, 'call', 0x5b1d0f0),
    ('context', 'upper_prior_row_result_cleanup', 0x4fcb7f2, 'call', 0x5b232a0),
    ('context', 'upper_prior_row_release', 0x4fcb812, 'slot', 0x64df4a0),
    ('context', 'loader_location', 0x3c1352f, 'lea', 0x64767a8),
    ('context', 'expanded_engine_to_late', 0x5a06db6, 'call', 0x5486720),
    ('context', 'compact_engine_to_late', 0x5a055b0, 'call', 0x54897e0),
    ('context', 'expanded_engine_to_root', 0x5a077e1, 'call', 0x5a08720),
    ('context', 'expanded_late_mode_zero', 0x5486d62, 'call', 0x5601e50),
    ('context', 'expanded_late_rows_grow', 0x548929f, 'call', 0x5963a10),
    ('context', 'expanded_late_rows_copy', 0x54892c1, 'slot', 0x64df508),
    ('context', 'expanded_late_mode_one', 0x548726d, 'call', 0x5601e50),
    ('context', 'compact_late_mode_zero', 0x5489ea6, 'call', 0x5605ee0),
    ('context', 'compact_late_mode_one', 0x548a3ad, 'call', 0x5605ee0),
    ('context', 'nested_intermediate_else', 0x55f4a9e, 'branch', 0x55f4c15),
    ('context', 'nested_intermediate_ten', 0x55f4a96, 'branch', 0x55f4b89),
    ('context', 'nested_zero_flag', 0x55f4aa9, 'branch', 0x55f4c60),
    ('context', 'nested_direct_dispatch', 0x55f4c8c, 'call', 0x54a2f90),
    ('context', 'nested_keyed_tag_miss', 0x55f496c, 'branch', 0x55f4a2c),
    ('context', 'nested_keyed_code_miss', 0x55f4980, 'branch', 0x55f4a2c),
    ('new', 'expanded_context_builder', 0x5601f53, 'slot', 0x64e6e10),
    ('new', 'expanded_result_builder', 0x5601f72, 'slot', 0x64e6e18),
    ('new', 'expanded_ring_append', 0x560200d, 'call', 0x57c3090),
    ('new', 'compact_context_builder', 0x5605fe3, 'slot', 0x64e6e10),
    ('new', 'compact_result_builder', 0x5606002, 'slot', 0x64e6e18),
    ('new', 'compact_ring_append', 0x560609d, 'call', 0x57c3090),
    ('new', 'expanded_key_tag_miss', 0x56051be, 'branch', 0x56051f0),
    ('new', 'expanded_key_value_miss', 0x56051c7, 'branch', 0x56051f0),
    ('new', 'expanded_key_special_join', 0x56051e8, 'jump', 0x560520c),
    ('new', 'expanded_direct_gate', 0x5605273, 'branch', 0x56052c0),
    ('new', 'expanded_row_wrapper', 0x560529f, 'call', 0x5601970),
    ('new', 'expanded_direct_dispatch', 0x56052ea, 'call', 0x54a2f90),
    ('new', 'expanded_unwind_join', 0x5605c7d, 'jump', 0x5605c94),
    ('new', 'expanded_unwind_drop', 0x5605c9c, 'call', 0x5632f20),
    ('new', 'expanded_second_stop', 0x560561c, 'branch', 0x56056d8),
    ('new', 'expanded_second_wrapper', 0x56056a7, 'call', 0x5601970),
    ('new', 'compact_key_tag_miss', 0x5609189, 'branch', 0x56091c0),
    ('new', 'compact_key_value_miss', 0x5609193, 'branch', 0x56091c0),
    ('new', 'compact_key_special_join', 0x56091b4, 'jump', 0x56091dc),
    ('new', 'compact_direct_gate', 0x5609243, 'branch', 0x56092a0),
    ('new', 'compact_row_wrapper', 0x5609274, 'call', 0x5601be0),
    ('new', 'compact_direct_dispatch', 0x56092d9, 'call', 0x54a3a00),
    ('new', 'compact_unwind_drop', 0x5609bb1, 'call', 0x5632f20),
    ('new', 'compact_second_stop', 0x5609540, 'branch', 0x56095fe),
    ('new', 'compact_second_wrapper', 0x56095cd, 'call', 0x5601be0),
    ('new', 'expanded_counter_prepare', 0x56019b2, 'call', 0x421dc00),
    ('new', 'expanded_counter_prepare_bypass', 0x5601992, 'branch', 0x56019b9),
    ('new', 'expanded_nested_dispatch', 0x5601a06, 'call', 0x55f4760),
    ('new', 'expanded_result_not_fifteen', 0x5601a13, 'branch', 0x5601ab6),
    ('new', 'expanded_encode_result', 0x5601a8c, 'call', 0x4e4c690),
    ('new', 'expanded_other_result', 0x5601ac5, 'slot', 0x64e6420),
    ('new', 'expanded_counter_tag_other', 0x5601ad0, 'branch', 0x5601ae7),
    ('new', 'compact_counter_prepare', 0x5601c22, 'call', 0x421dc00),
    ('new', 'compact_counter_prepare_bypass', 0x5601c02, 'branch', 0x5601c29),
    ('new', 'compact_nested_dispatch', 0x5601c76, 'call', 0x55f4d60),
    ('new', 'compact_result_not_fifteen', 0x5601c83, 'branch', 0x5601d26),
    ('new', 'compact_encode_result', 0x5601cfc, 'call', 0x4e4c690),
    ('new', 'compact_other_result', 0x5601d35, 'slot', 0x64e6420),
    ('new', 'compact_counter_tag_other', 0x5601d40, 'branch', 0x5601d57),
    ('new', 'ring_length_overflow', 0x57c30cb, 'branch', 0x57c325f),
    ('new', 'ring_fits_capacity', 0x57c30eb, 'branch', 0x57c317e),
    ('new', 'ring_grow', 0x57c30fa, 'branch', 0x57c327a),
    ('new', 'ring_growth_call', 0x57c328e, 'call', 0x5963a10),
    ('new', 'ring_failure_call', 0x57c3272, 'slot', 0x64df770),
    ('new', 'ring_copy_contiguous', 0x57c3231, 'slot', 0x64df508),
    ('new', 'ring_move', 0x57c3167, 'slot', 0x64df568),
    ('new', 'cleanup_rows_done', 0x4f339b7, 'branch', 0x4f339db),
    ('new', 'cleanup_action', 0x4f339bf, 'call', 0x5b1d0f0),
    ('new', 'cleanup_nested_result', 0x4f339d4, 'call', 0x5b232a0),
    ('new', 'cleanup_no_allocation', 0x4f339e1, 'branch', 0x4f339f5),
    ('new', 'cleanup_release', 0x4f339ef, 'slot', 0x64df4a0),
    ('new', 'cleanup_first_tail_done', 0x4f33a14, 'branch', 0x4f33a27),
    ('new', 'cleanup_first_tail_item', 0x4f33a1d, 'call', 0x5b0d830),
    ('new', 'cleanup_first_tail_no_allocation', 0x4f33a2e, 'branch', 0x4f33a3f),
    ('new', 'cleanup_first_tail_release', 0x4f33a39, 'slot', 0x64df4a0),
    ('new', 'cleanup_second_tail_done', 0x4f33a54, 'branch', 0x4f33a67),
    ('new', 'cleanup_second_tail_item', 0x4f33a5d, 'call', 0x5b0d830),
    ('new', 'cleanup_second_tail_no_allocation', 0x4f33a6e, 'branch', 0x4f33a8d),
    ('new', 'cleanup_second_tail_release', 0x4f33a87, 'slot_jump', 0x64df4a0),
    ('new', 'cleanup_unwind_current_result', 0x4f33b32, 'call', 0x5b232a0),
    ('new', 'cleanup_unwind_remaining_rows', 0x4f33b60, 'call', 0x5b1f750),
    ('new', 'cleanup_unwind_row_release', 0x4f33b7e, 'slot', 0x64df4a0),
    ('new', 'cleanup_unwind_first_tail', 0x4f33b88, 'call', 0x4f2eb40),
    ('new', 'cleanup_unwind_second_tail', 0x4f33b94, 'call', 0x4f2f830),
    ('new', 'cleanup_unwind_resume', 0x4f33b9c, 'call', 0x63f0a50),
)

# The selected field bytes below are checked against exact instruction encodings
# before their little-endian immediate/displacement is read. (site, size, offset, width)
FIELDS = (
    ('upper_prior_pointer_stack', 0x4fcb7b6, '4c8bbc24b8000000', 4, 4),
    ('upper_prior_count_stack', 0x4fcb7be, '488b9c24c0000000', 4, 4),
    ('upper_prior_row_stride', 0x4fcb7eb, '4c8dad68010000', 3, 4),
    ('upper_prior_release_stride', 0x4fcb806, '4869f068010000', 3, 4),
    ('late_call_result_stack', 0x5486d56, '488d7c2430', 4, 1),
    ('late_body_result_count', 0x5486d88, '4c8b7c2440', 4, 1),
    ('late_body_result_pointer', 0x5486d83, '4c8b742438', 4, 1),
    ('late_body_row_stride', 0x5486d8d, '4d69e730010000', 3, 4),
    ('late_accum_count', 0x54892a4, '4c8bac2400010000', 4, 4),
    ('late_accum_stride', 0x54892ac, '4969fd30010000', 3, 4),
    ('late_accum_pointer', 0x54892b3, '4803bc24f8000000', 4, 4),
    ('nested_keyed_result_tag', 0x55f496a, '3c10', 1, 1),
    ('nested_keyed_result_code', 0x55f497a, '81f9d0000000', 2, 4),
    ('nested_direct_result_tag', 0x55f4a9c, '3c0f', 1, 1),
    ('compact_engine_state_cell', 0x5a04f5f, '498d842450040000', 4, 4),
    ('compact_engine_saved_cell', 0x5a04f67, '48898424e8000000', 4, 4),
    ('compact_engine_late_cell', 0x5a055a8, '488bb424e8000000', 4, 4),
    ('compact_root_capture_offset', 0x269a20b, '498d8768090000', 3, 4),
    ('engine_state_cell_offset', 0x5a06727, '498d8750040000', 3, 4),
    ('engine_saved_cell_stack', 0x5a0672e, '4889442418', 4, 1),
    ('engine_late_cell_stack', 0x5a06db1, '488b742418', 4, 1),
    ('late_expanded_saved_state', 0x5486900, '4c89642408', 4, 1),
    ('late_expanded_call_state', 0x5486d5b, '488b742408', 4, 1),
    ('late_compact_saved_state', 0x54899c0, '4c89642408', 4, 1),
    ('late_compact_call_state', 0x5489e9f, '488b742408', 4, 1),
    ('root_capture_state_offset', 0x4e3437b, '498d87d8140000', 3, 4),
    ('root_capture_stack_offset', 0x4e34382, '4889842448010000', 4, 4),
    ('expanded_regular_fill4', 0x56051f3, 'c784247703000000000000', 7, 4),
    ('compact_regular_fill4', 0x56091c3, 'c784246703000000000000', 7, 4),
    ('expanded_regular_fill8', 0x56051fe, '48c784247003000000000000', 8, 4),
    ('compact_regular_fill8', 0x56091ce, '48c784246003000000000000', 8, 4),
    ('expanded_tail_store_offset', 0x5605222, '894a07', 2, 1),
    ('compact_tail_store_offset', 0x56091f2, '894a07', 2, 1),
    ('expanded_row_action_bytes', 0x5601b03, 'baf0000000', 1, 4),
    ('compact_row_action_bytes', 0x5601d73, 'baf0000000', 1, 4),
    ('expanded_row_result_first', 0x5601b1e, '410f1187f0000000', 4, 4),
    ('compact_row_result_first', 0x5601d8e, '410f1187f0000000', 4, 4),
    ('expanded_row_result_second', 0x5601b26, '410f118f00010000', 4, 4),
    ('compact_row_result_second', 0x5601d96, '410f118f00010000', 4, 4),
    ('expanded_row_result_last', 0x5601b33, '49898710010000', 3, 4),
    ('compact_row_result_last', 0x5601da3, '49898710010000', 3, 4),
    ('expanded_row_key_first', 0x5601b3e, '410f118718010000', 4, 4),
    ('compact_row_key_first', 0x5601dae, '410f118718010000', 4, 4),
    ('expanded_row_key_last', 0x5601b4a, '41898728010000', 3, 4),
    ('compact_row_key_last', 0x5601dba, '41898728010000', 3, 4),
    ('expanded_zero_flag', 0x56019e0, 'c644245000', 4, 1),
    ('compact_zero_flag', 0x5601c50, 'c644245000', 4, 1),
    ('late_old_count_stack', 0x5487625, '488b842400010000', 4, 4),
    ('late_saved_count_stack', 0x548762d, '4889842400020000', 4, 4),
    ('late_old_pair_stack', 0x5487635, '660f108424f0000000', 5, 4),
    ('late_saved_pair_stack', 0x548763e, '660f298424f0010000', 5, 4),
    ('late_return_saved_count', 0x5488f03, '488b8c2400020000', 4, 4),
    ('late_return_count_local', 0x5488f0b, '48894c2440', 4, 1),
    ('late_return_saved_pair', 0x5488f10, '0f288424f0010000', 4, 4),
    ('late_return_pair_local', 0x5488f18, '0f29442430', 4, 1),
    ('engine_return_field_offset', 0x5a078a8, '0f114030', 3, 1),
    ('upper_engine_result_stack', 0x4fcb788, '488dbc24b0000000', 4, 4),
    ('upper_cleanup_stack', 0x4fcb818, '488dbc24e0000000', 4, 4),
    ('cleanup_row_pointer_offset', 0x4f3399e, '4c8b7f08', 3, 1),
    ('cleanup_row_count_offset', 0x4f339a2, '4c8b7710', 3, 1),
    ('cleanup_row_inner_offset', 0x4f339c4, '498dbc24f0000000', 4, 4),
    ('cleanup_row_stride', 0x4f339cc, '498dac2430010000', 4, 4),
    ('cleanup_free_stride', 0x4f339e3, '4869f030010000', 3, 4),
    ('cleanup_first_tail_pointer', 0x4f339f5, '4c8b7b20', 3, 1),
    ('cleanup_first_tail_count', 0x4f339f9, '4c8b6b28', 3, 1),
    ('cleanup_first_tail_inner', 0x4f339fd, '498d7f08', 3, 1),
    ('cleanup_first_tail_stride', 0x4f33a16, '4c8d6768', 3, 1),
    ('cleanup_first_tail_allocation', 0x4f33a27, '488b4318', 3, 1),
    ('cleanup_first_tail_release_stride', 0x4f33a30, '486bf068', 3, 1),
    ('cleanup_second_tail_pointer', 0x4f33a3f, '4c8b7b38', 3, 1),
    ('cleanup_second_tail_count', 0x4f33a43, '4c8b6b40', 3, 1),
    ('cleanup_second_tail_inner', 0x4f33a47, '498d7f08', 3, 1),
    ('cleanup_second_tail_stride', 0x4f33a56, '4c8d6768', 3, 1),
    ('cleanup_second_tail_allocation', 0x4f33a67, '488b4330', 3, 1),
    ('cleanup_second_tail_release_stride', 0x4f33a70, '486bf068', 3, 1),
    ('ring_divisor_shift', 0x57c30af, '48c1e806', 3, 1),
    ('ring_scale_sib', 0x5601fda, '488d1452', 3, 1),
    ('expanded_input_value_offset', 0x560519d, '488b4520', 3, 1),  # 0x20
    ('compact_input_value_offset', 0x560916a, '488b4520', 3, 1),  # 0x20
    ('expanded_status_offset', 0x56051b7, '83b98000000001', 2, 4),  # 0x80
    ('expanded_status_value', 0x56051b7, '83b98000000001', 6, 1),  # 0x1
    ('compact_status_offset', 0x5609180, '4183bc248000000001', 4, 4),  # 0x80
    ('compact_status_value', 0x5609180, '4183bc248000000001', 8, 1),  # 0x1
    ('expanded_match_value_offset', 0x56051c0, '483b8188000000', 3, 4),  # 0x88
    ('compact_match_value_offset', 0x560918b, '493b842488000000', 4, 4),  # 0x88
    ('expanded_special_fill8', 0x56051c9, '48b82222222222222222', 2, 8),  # 0x2222222222222222
    ('compact_special_fill8', 0x5609195, '48b82222222222222222', 2, 8),  # 0x2222222222222222
    ('expanded_special_fill4', 0x56051db, 'c784247703000022222222', 7, 4),  # 0x22222222
    ('compact_special_fill4', 0x56091a7, 'c784246703000022222222', 7, 4),  # 0x22222222
    ('expanded_special_prefix', 0x56051e6, 'b122', 1, 1),  # 0x22
    ('compact_special_prefix', 0x56091b2, 'b122', 1, 1),  # 0x22
    ('expanded_regular_prefix', 0x560520a, 'b120', 1, 1),  # 0x20
    ('compact_regular_prefix', 0x56091da, 'b120', 1, 1),  # 0x20
    ('expanded_key_stack', 0x560520c, '888c241c020000', 3, 4),  # 0x21c
    ('expanded_key_suffix_stack', 0x5605230, '4889842428020000', 4, 4),  # 0x228
    ('compact_key_stack', 0x56091dc, '888c240c020000', 3, 4),  # 0x20c
    ('compact_key_suffix_stack', 0x5609200, '4889842418020000', 4, 4),  # 0x218
    ('expanded_first_input_stride', 0x560515d, '4883c548', 3, 1),  # 0x48
    ('compact_first_input_stride', 0x5609138, '4883c548', 3, 1),  # 0x48
    ('expanded_second_input_stride', 0x56055b4, '4881c328010000', 3, 4),  # 0x128
    ('compact_second_input_stride', 0x56094d4, '4881c328010000', 3, 4),  # 0x128
    ('expanded_result_stride', 0x5605130, '4969ff30010000', 3, 4),  # 0x130
    ('compact_result_stride', 0x5609110, '4969fc30010000', 3, 4),  # 0x130
    ('expanded_stop_tag', 0x5605616, '483de2000000', 2, 4),  # 0xe2
    ('compact_stop_tag', 0x560953a, '483de2000000', 2, 4),  # 0xe2
    ('expanded_action_tag', 0x560525e, '48c7842400090000bf000000', 8, 4),  # 0xbf
    ('compact_action_tag', 0x560922e, '48c78424e0080000bf000000', 8, 4),  # 0xbf
    ('expanded_action_gate_offset', 0x560526a, '4180bc244b43000000', 4, 4),  # 0x434b
    ('compact_action_gate_offset', 0x560923a, '4180bc24db37000000', 4, 4),  # 0x37db
    ('expanded_ring_offset', 0x5601fd2, '498dbc24d0420000', 4, 4),  # 0x42d0
    ('compact_ring_offset', 0x5606062, '498dbc2460370000', 4, 4),  # 0x3760
    ('expanded_mode_zero_offset', 0x560201a, '4d8db424b83e0000', 4, 4),  # 0x3eb8
    ('expanded_mode_one_offset', 0x5602012, '498d842468420000', 4, 4),  # 0x4268
    ('compact_mode_zero_offset', 0x56060aa, '498d8c2448330000', 4, 4),  # 0x3348
    ('compact_mode_one_offset', 0x56060a2, '498d8424f8360000', 4, 4),  # 0x36f8
    ('expanded_root_group_offset', 0x5601eb1, '4d8d9424d8140000', 4, 4),  # 0x14d8
    ('compact_root_group_offset', 0x5605f41, '4d8d942468090000', 4, 4),  # 0x968
    ('expanded_state_mode_offset', 0x560199e, '410fb6b4240a170000', 5, 4),  # 0x170a
    ('compact_state_mode_offset', 0x5601c0e, '410fb6b4249a0b0000', 5, 4),  # 0xb9a
    ('expanded_flag_counter_offset', 0x56052d3, '4d897c2450', 4, 1),  # 0x50
    ('expanded_active_flag_offset', 0x56052d8, '41c644247801', 4, 1),  # 0x78
    ('compact_flag_counter_offset', 0x56092b3, '4989442450', 4, 1),  # 0x50
    ('compact_active_flag_offset', 0x56092b8, '41c644247801', 4, 1),  # 0x78
    ('expanded_wrapper_status', 0x5601acb, '41833c2401', 4, 1),  # 0x1
    ('compact_wrapper_status', 0x5601d3b, '41833c2401', 4, 1),  # 0x1
    ('expanded_wrapper_counter_offset', 0x5601af4, '4989442408', 4, 1),  # 0x8
    ('compact_wrapper_counter_offset', 0x5601d64, '4989442408', 4, 1),  # 0x8
    ('expanded_stack_argument', 0x56019ea, '4889442408', 4, 1),  # 0x8
    ('compact_stack_argument', 0x5601c5a, '4889442408', 4, 1),  # 0x8
    ('nested_frame_allocation', 0x55f476a, '4881ec68020000', 3, 4),  # 0x268
    ('nested_flag_stack_offset', 0x55f4870, '4c8bac24a8020000', 4, 4),  # 0x2a8
    ('ring_element_bytes', 0x57c327f, '41b8c0000000', 2, 4),  # 0xc0
    ('ring_divisor_inverse', 0x57c30b3, '49bfabaaaaaaaaaaaaaa', 2, 8),  # 0xaaaaaaaaaaaaaaab
    ('expanded_output_count_offset', 0x56056fd, '48894110', 3, 1),  # 0x10
    ('compact_output_count_offset', 0x5609623, '48894110', 3, 1),  # 0x10
)

# Relocations are contextual dynamic-binding boundaries, not new ownership.
RELOCATIONS = (
    ('state_location_path', 0x64767a8, 8, 0x443168),
    ('context_builder', 0x64e6e10, 8, 0x433dc40),
    ('result_builder', 0x64e6e18, 8, 0x434bda0),
    ('result_conversion', 0x64e6420, 8, 0x36aec00),
    ('copy_import', 0x64df508, 0x700000006, 0),
    ('move_import', 0x64df568, 0x800000006, 0),
    ('ring_failure', 0x64df770, 8, 0x1680bd0),
    ('cleanup_deallocator', 0x64df4a0, 8, 0x635de30),
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def authenticate(data, expected=TARGET_SHA256):
    require(hashlib.sha256(data).hexdigest() == expected, 'artifact SHA-256 mismatch')


def named_section(secs, name):
    matches = [s for s in secs if s['name'] == name and s['type'] != 8]
    require(len(matches) == 1, 'missing, duplicate, or NOBITS section: ' + name)
    return matches[0]


def file_offset(data, secs, va, size, executable=False):
    require(isinstance(va, int) and isinstance(size, int) and va >= 0 and size > 0,
            'invalid address or range')
    require(va + size <= 1 << 64, 'address range overflows')
    matches = [s for s in secs if s['type'] != 8 and
               (not executable or s['flags'] & 4) and
               s['address'] <= va and va + size <= s['address'] + s['size']]
    require(len(matches) == 1, 'address is absent, ambiguous, or not file-backed')
    section = matches[0]
    off = section['offset'] + va - section['address']
    require(off >= 0 and off + size <= len(data), 'range outside file')
    return off


def read_va(data, secs, va, size, executable=False):
    off = file_offset(data, secs, va, size, executable)
    return data[off:off + size]


def select_functions(data, secs, index, fdes):
    records = []
    seen = set()
    for label, start, expected_end, expected_fde in FUNCTIONS:
        found = [f for f in fdes if f['start'] == start]
        indexed = [r for r in index if r['start'] == start]
        require(len(found) == len(indexed) == 1, 'selected FDE or header entry missing/duplicate')
        f = found[0]
        require(f['end'] == expected_end and f['fde'] == indexed[0]['fde'] == expected_fde,
                'FDE, extent, and unwind header disagree')
        require(f['fde'] not in seen and f['end'] > f['start'], 'invalid or duplicate FDE')
        seen.add(f['fde'])
        for other in fdes:
            if other is not f and max(start, other['start']) < min(expected_end, other['end']):
                raise ValueError('selected FDE overlaps another FDE')
        raw = read_va(data, secs, start, expected_end - start, True)
        records.append({'label': label, 'start_va': hex(start), 'end_va_exclusive': hex(expected_end),
                        'file_offset': hex(file_offset(data, secs, start, len(raw), True)),
                        'length': len(raw), 'fde_va': hex(f['fde']), 'cie_va': hex(f['cie']),
                        'lsda_va': hex(f['lsda']) if f['lsda'] is not None else '-',
                        'unwind_index': indexed[0]['index'], 'sha256': hashlib.sha256(raw).hexdigest(),
                        'raw_hex': raw.hex()})
    return records


def select_windows(data, secs):
    out = []
    for scope, label, start, end, digest in WINDOWS:
        raw = read_va(data, secs, start, end - start, True)
        require(hashlib.sha256(raw).hexdigest() == digest, 'selected window changed: ' + label)
        out.append({'scope': scope, 'label': label, 'start_va': hex(start),
                    'end_va_exclusive': hex(end),
                    'file_offset': hex(file_offset(data, secs, start, len(raw), True)),
                    'length': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                    'raw_hex': raw.hex()})
    return out


def decode_edge(data, secs, site, kind):
    first = read_va(data, secs, site, 2, True)
    if kind == 'call':
        require(first[0] == 0xe8, 'expected direct call')
        length, disp_offset, width = 5, 1, 4
    elif kind == 'jump':
        require(first[0] in (0xeb, 0xe9), 'expected relative jump')
        length, disp_offset, width = (2, 1, 1) if first[0] == 0xeb else (5, 1, 4)
    elif kind == 'branch':
        if 0x70 <= first[0] <= 0x7f:
            length, disp_offset, width = 2, 1, 1
        else:
            require(first[0] == 0x0f and 0x80 <= first[1] <= 0x8f,
                    'expected conditional branch')
            length, disp_offset, width = 6, 2, 4
    elif kind in ('slot', 'slot_jump'):
        opcode = b'\xff\x15' if kind == 'slot' else b'\xff\x25'
        require(first == opcode, 'expected RIP-relative indirect call or jump')
        length, disp_offset, width = 6, 2, 4
    elif kind == 'lea':
        require(first in (b'\x48\x8d', b'\x4c\x8d'), 'expected RIP-relative LEA')
        length, disp_offset, width = 7, 3, 4
    else:
        raise ValueError('unsupported transfer form')
    raw = read_va(data, secs, site, length, True)
    if kind == 'lea':
        require(raw[2] & 0xc7 == 0x05, 'LEA is not RIP-relative')
    disp = int.from_bytes(raw[disp_offset:disp_offset + width], 'little', signed=True)
    dest = site + length + disp
    require(0 <= dest < 1 << 64, 'relative target overflow')
    return raw, dest


def select_edges(data, secs):
    out = []
    for scope, label, site, kind, expected in EDGES:
        raw, dest = decode_edge(data, secs, site, kind)
        require(dest == expected, 'relative transfer changed: ' + label)
        out.append({'scope': scope, 'label': label, 'kind': kind, 'site_va': hex(site),
                    'file_offset': hex(file_offset(data, secs, site, len(raw), True)),
                    'raw_hex': raw.hex(), 'target_va': hex(dest)})
    return out


def select_fields(data, secs):
    out, values = [], {}
    for label, site, expected_hex, offset, width in FIELDS:
        expected = bytes.fromhex(expected_hex)
        raw = read_va(data, secs, site, len(expected), True)
        require(raw == expected, 'selected operand instruction changed: ' + label)
        require(0 <= offset and width > 0 and offset + width <= len(raw), 'bad field range')
        val = int.from_bytes(raw[offset:offset + width], 'little')
        require(label not in values, 'duplicate field label')
        values[label] = val
        out.append({'label': label, 'site_va': hex(site),
                    'file_offset': hex(file_offset(data, secs, site, len(raw), True)),
                    'instruction_hex': raw.hex(), 'field_offset': offset,
                    'field_width': width, 'field_hex': raw[offset:offset + width].hex(),
                    'value': hex(val)})
    return out, values


def select_relocations(data, secs):
    sec = named_section(secs, '.rela.dyn')
    require(sec['size'] % 24 == 0, 'malformed RELA section')
    wanted = {slot: (label, info, add) for label, slot, info, add in RELOCATIONS}
    require(len(wanted) == len(RELOCATIONS), 'duplicate relocation selection')
    found = {}
    for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
        slot, info, add = struct.unpack_from('<QQq', data, off)
        if slot not in wanted:
            continue
        require(slot not in found, 'duplicate selected relocation')
        label, expected_info, expected_add = wanted[slot]
        if expected_info is not None:
            require(info == expected_info and add == expected_add, 'relocation changed: ' + label)
        found[slot] = {'label': label, 'slot_va': hex(slot), 'entry_file_offset': hex(off),
                       'entry_va': hex(sec['address'] + off - sec['offset']),
                       'raw_hex': data[off:off + 24].hex(), 'type': info & 0xffffffff,
                       'symbol_index': info >> 32, 'addend': hex(add)}
    require(set(found) == set(wanted), 'selected relocation missing')
    return [found[slot] for _, slot, _, _ in RELOCATIONS]


def location_record(data, secs, relocs):
    relocation = next(r for r in relocs if r['label'] == 'state_location_path')
    address, path = 0x64767a8, int(relocation['addend'], 16)
    raw = read_va(data, secs, address, 24)
    length, line, column = struct.unpack_from('<QII', raw, 8)
    require((length, line, column) == (20, 123, 37), 'state Location changed')
    text = read_va(data, secs, path, length)
    require(text == b'l1/src/abci/state.rs', 'state Location path changed')
    return {'record_va': hex(address), 'file_offset': hex(file_offset(data, secs, address, len(raw))),
            'raw_hex': raw.hex(), 'path_va': hex(path), 'path': text.decode('ascii'),
            'length': length, 'line': line, 'column': column}


def location_owner(index, fdes):
    site = 0x3c1352f
    owners = [f for f in fdes if f['start'] <= site < f['end']]
    require(len(owners) == 1 and owners[0]['start'] == 0x3c13520,
            'Location reference has no unique selected FDE')
    owner = owners[0]
    indexed = [entry for entry in index if entry['start'] == owner['start']]
    require(len(indexed) == 1 and indexed[0]['fde'] == owner['fde'],
            'Location FDE and unwind index disagree')
    return {'reference_va': hex(site), 'owner_start_va': hex(owner['start']),
            'owner_end_va_exclusive': hex(owner['end']), 'fde_va': hex(owner['fde']),
            'unwind_index': indexed[0]['index']}


def lsda_rows(data, secs, fde, label):
    if fde['lsda'] is None:
        return []
    sec = named_section(secs, '.gcc_except_table')
    loc = fde['lsda']
    require(sec['address'] <= loc < sec['address'] + sec['size'], 'LSDA outside section')
    pos = file_offset(data, secs, loc, 2)
    end = sec['offset'] + sec['size']
    require(data[pos] == 0xff and data[pos + 1] in (0xff, 0x9b), 'unsupported LSDA header')
    typ = data[pos + 1]
    pos += 2
    type_base = end
    if typ == 0x9b:
        delta, pos = uleb(data, pos, end)
        type_base = pos + delta
    require(type_base <= end and pos < end and data[pos] == 1, 'unsupported LSDA call encoding')
    length, pos = uleb(data, pos + 1, end)
    stop = pos + length
    require(stop <= min(end, type_base), 'truncated LSDA table')
    rows = []
    while pos < stop:
        first = pos
        begin, pos = uleb(data, pos, stop)
        count, pos = uleb(data, pos, stop)
        landing, pos = uleb(data, pos, stop)
        action, pos = uleb(data, pos, stop)
        require(begin + count <= fde['end'] - fde['start'], 'LSDA interval outside FDE')
        require(not landing or landing < fde['end'] - fde['start'], 'LSDA landing outside FDE')
        rows.append({'function': label, 'lsda_va': hex(loc), 'entry_file_offset': hex(first),
                     'start_va': hex(fde['start'] + begin),
                     'end_va_exclusive': hex(fde['start'] + begin + count),
                     'landing_va': hex(fde['start'] + landing) if landing else '-',
                     'action': action, 'raw_hex': data[first:pos].hex()})
    require(pos == stop, 'misaligned LSDA table')
    return rows


def exception_links(edges, exceptions, functions):
    links = []
    for edge in edges:
        if edge['scope'] != 'new' or edge['kind'] not in ('call', 'slot'):
            continue
        site = int(edge['site_va'], 16)
        owners = [f for f in functions if int(f['start_va'], 16) <= site < int(f['end_va_exclusive'], 16)]
        require(len(owners) == 1, 'selected call has no unique FDE')
        owner = owners[0]
        hits = [r for r in exceptions if r['function'] == owner['label'] and
                int(r['start_va'], 16) <= site < int(r['end_va_exclusive'], 16)]
        require(len(hits) <= 1, 'overlapping LSDA intervals')
        if hits:
            row = hits[0]
            require(site + len(bytes.fromhex(edge['raw_hex'])) <= int(row['end_va_exclusive'], 16),
                    'call crosses LSDA interval')
            status, landing, action = 'matched', row['landing_va'], row['action']
        else:
            status, landing, action = 'no-row', '-', '-'
        links.append({'label': edge['label'], 'function': owner['label'], 'site_va': edge['site_va'],
                      'target_va': edge['target_va'], 'status': status,
                      'landing_va': landing, 'action': action})
    return links


def derived(values, nested_prologue):
    # These equalities join independently decoded instructions; they are not a
    # claim that the two layouts are ABI-compatible in general.
    same = ('input_value_offset', 'status_offset', 'status_value', 'match_value_offset',
            'special_fill8', 'special_fill4', 'special_prefix', 'regular_prefix',
            'regular_fill4', 'regular_fill8', 'tail_store_offset',
            'first_input_stride', 'second_input_stride', 'result_stride', 'stop_tag',
            'action_tag', 'flag_counter_offset', 'active_flag_offset', 'wrapper_status',
            'wrapper_counter_offset', 'stack_argument', 'output_count_offset',
            'row_action_bytes', 'row_result_first', 'row_result_second', 'row_result_last',
            'row_key_first', 'row_key_last', 'zero_flag')
    for suffix in same:
        require(values['expanded_' + suffix] == values['compact_' + suffix],
                'layout comparison disagrees: ' + suffix)
    differences = [values['expanded_' + k] - values['compact_' + k] for k in
                   ('action_gate_offset', 'ring_offset', 'mode_zero_offset',
                    'mode_one_offset', 'root_group_offset', 'state_mode_offset')]
    require(len(set(differences)) == 1, 'selected layout offset differences disagree')
    key_prefix_bytes = values['expanded_key_suffix_stack'] - values['expanded_key_stack']
    require(key_prefix_bytes == values['compact_key_suffix_stack'] - values['compact_key_stack'],
            'key prefix and suffix offsets disagree')
    require(nested_prologue == bytes.fromhex('55415741564155415453'),
            'nested saved-register sequence changed')
    saved_register_bytes = sum(0x50 <= b <= 0x57 for b in nested_prologue) * struct.calcsize('<Q')
    call_return_bytes = struct.calcsize('<Q')
    require(values['nested_frame_allocation'] + saved_register_bytes + call_return_bytes +
            values['expanded_stack_argument'] == values['nested_flag_stack_offset'],
            'nested stack argument does not line up')
    require(values['expanded_special_fill8'].to_bytes(8, 'little') ==
            bytes([values['expanded_special_prefix']]) * 8, 'special qword mismatch')
    require(values['expanded_special_fill4'].to_bytes(4, 'little') ==
            bytes([values['expanded_special_prefix']]) * 4, 'special dword mismatch')
    ring_scale = 1 + (1 << ((values['ring_scale_sib'] >> 6) & 3))
    require((values['ring_divisor_inverse'] * ring_scale) % (1 << 64) == 1 and
            values['ring_element_bytes'] == ring_scale * (1 << values['ring_divisor_shift']),
            'ring reciprocal is not the inverse of three')
    require(values['late_old_count_stack'] == values['late_old_pair_stack'] + 16 and
            values['late_saved_count_stack'] == values['late_return_saved_count'] and
            values['late_saved_pair_stack'] == values['late_return_saved_pair'] and
            values['late_return_count_local'] == values['late_return_pair_local'] + 16,
            'late-result descriptor join changed')
    require(values['late_body_result_pointer'] == values['late_call_result_stack'] + 8 and
            values['late_body_result_count'] == values['late_call_result_stack'] + 16 and
            values['late_body_row_stride'] == values['late_accum_stride'] ==
            values['expanded_result_stride'] and
            values['late_accum_pointer'] == values['late_old_pair_stack'] + 8 and
            values['late_accum_count'] == values['late_old_count_stack'],
            'returned row accumulation does not line up')
    require(values['upper_cleanup_stack'] - values['upper_engine_result_stack'] ==
            values['engine_return_field_offset'], 'upper result-to-cleanup offset changed')
    require(values['upper_prior_pointer_stack'] == values['upper_engine_result_stack'] + 8 and
            values['upper_prior_count_stack'] == values['upper_engine_result_stack'] + 16 and
            values['upper_prior_row_stride'] == values['upper_prior_release_stride'] and
            values['upper_prior_row_stride'] != values['cleanup_row_stride'],
            'upper prior result layout changed')
    require(values['engine_saved_cell_stack'] == values['engine_late_cell_stack'] and
            values['compact_engine_state_cell'] == values['engine_state_cell_offset'] and
            values['compact_engine_saved_cell'] == values['compact_engine_late_cell'] and
            values['late_expanded_saved_state'] == values['late_expanded_call_state'] and
            values['late_compact_saved_state'] == values['late_compact_call_state'],
            'state cell handoff offsets changed')
    require(values['root_capture_state_offset'] == values['expanded_root_group_offset'],
            'root capture does not name the selected state group')
    require(values['compact_root_capture_offset'] == values['compact_root_group_offset'],
            'compact root capture does not name the selected state group')
    require(values['nested_keyed_result_tag'] != values['nested_direct_result_tag'],
            'nested result alternatives are not distinct')
    require(values['cleanup_row_stride'] == values['cleanup_free_stride'] ==
            values['expanded_result_stride'] and values['cleanup_row_count_offset'] ==
            values['expanded_output_count_offset'], 'row cleanup layout changed')
    require(values['cleanup_first_tail_pointer'] == values['cleanup_first_tail_allocation'] + 8 and
            values['cleanup_first_tail_count'] == values['cleanup_first_tail_allocation'] + 16 and
            values['cleanup_second_tail_pointer'] == values['cleanup_second_tail_allocation'] + 8 and
            values['cleanup_second_tail_count'] == values['cleanup_second_tail_allocation'] + 16 and
            values['cleanup_first_tail_inner'] == values['cleanup_second_tail_inner'] and
            values['cleanup_first_tail_stride'] == values['cleanup_first_tail_release_stride'] ==
            values['cleanup_second_tail_stride'] == values['cleanup_second_tail_release_stride'],
            'tail cleanup layouts disagree')
    require(values['expanded_row_action_bytes'] == values['expanded_row_result_first'] ==
            values['cleanup_row_inner_offset'] and
            values['expanded_row_result_second'] == values['expanded_row_result_first'] + 16 and
            values['expanded_row_result_last'] == values['expanded_row_result_second'] + 16 and
            values['expanded_row_key_first'] == values['expanded_row_result_last'] + 8 and
            values['expanded_row_key_last'] == values['expanded_row_key_first'] + 16 and
            values['expanded_row_key_last'] + 4 <= values['expanded_result_stride'] and
            values['expanded_row_key_last'] + 4 - values['expanded_row_key_first'] == key_prefix_bytes + 8 and
            1 + values['expanded_tail_store_offset'] + 4 == key_prefix_bytes,
            'row projection layout changed')
    return {'layout_offset_difference': hex(differences[0]),
            'key_prefix_bytes': key_prefix_bytes, 'key_width': key_prefix_bytes + 8,
            'first_input_stride': values['expanded_first_input_stride'],
            'second_input_stride': values['expanded_second_input_stride'],
            'result_stride': values['expanded_result_stride'],
            'engine_result_descriptor_offset': values['engine_return_field_offset'],
            'upper_prior_result_stride': values['upper_prior_row_stride'],
            'cleanup_row_inner_offset': values['cleanup_row_inner_offset'],
            'cleanup_tail_element_bytes': values['cleanup_first_tail_stride'],
            'row_action_bytes': values['expanded_row_action_bytes'],
            'row_result_offset': values['expanded_row_result_first'],
            'row_key_offset': values['expanded_row_key_first'],
            'row_key_last_word_offset': values['expanded_row_key_last'],
            'ring_element_bytes': values['ring_element_bytes'],
            'action_tag': hex(values['expanded_action_tag']),
            'second_loop_stop_tag': hex(values['expanded_stop_tag']),
            'nested_keyed_result_tag': hex(values['nested_keyed_result_tag']),
            'nested_keyed_result_code': hex(values['nested_keyed_result_code']),
            'nested_direct_result_tag': hex(values['nested_direct_result_tag']),
            'regular_key_prefix': hex(values['expanded_regular_prefix']),
            'special_key_byte': hex(values['expanded_special_prefix']),
            'nested_frame_bytes': values['nested_frame_allocation'],
            'nested_saved_register_bytes': saved_register_bytes,
            'nested_call_return_bytes': call_return_bytes,
            'nested_caller_stack_argument': values['expanded_stack_argument'],
            'nested_callee_stack_argument': values['nested_flag_stack_offset']}


def key_model(values, status_word, state_word, input_word):
    """Synthetic model for the fixed selected key-construction windows."""
    require(all(isinstance(x, int) and 0 <= x < 1 << 64 for x in
                (status_word, state_word, input_word)), 'model input outside u64')
    special = ((status_word & 0xffffffff) == values['expanded_status_value'] and
               state_word == input_word)
    prefix_len = values['expanded_key_suffix_stack'] - values['expanded_key_stack']
    result = bytearray(prefix_len + 8)
    result[0] = values['expanded_special_prefix' if special else 'expanded_regular_prefix']
    first = values['expanded_special_fill8' if special else 'expanded_regular_fill8']
    tail = values['expanded_special_fill4' if special else 'expanded_regular_fill4']
    result[1:9] = first.to_bytes(8, 'little')
    tail_start = 1 + values['expanded_tail_store_offset']
    result[tail_start:tail_start + 4] = tail.to_bytes(4, 'little')
    suffix = first if special else int.from_bytes(input_word.to_bytes(8, 'little'), 'big')
    result[prefix_len:prefix_len + 8] = suffix.to_bytes(8, 'little')
    return bytes(result)


def counter_model(tag, counter):
    require(all(isinstance(x, int) and 0 <= x < 1 << 64 for x in (tag, counter)),
            'model input outside u64')
    if tag & 0xffffffff == 1:
        return tag, min(counter + 1, (1 << 64) - 1)
    return 1, 1


def ring_count_model(span, inverse):
    require(isinstance(span, int) and 0 <= span < 1 << 64, 'span outside u64')
    return ((span >> 6) * inverse) & ((1 << 64) - 1)


def verify_historical(data):
    """Validate the retired #94 anchor separately, without generating #115 output from it."""
    authenticate(data, HISTORICAL_SHA256)
    secs, index = unwind_index(data)
    _, fdes = eh_frame_records(data, secs)
    for start, end in ((0x32725d0, 0x3272b3a), (0x3273810, 0x327396c)):
        f = [r for r in fdes if r['start'] == start and r['end'] == end]
        h = [r for r in index if r['start'] == start]
        require(len(f) == len(h) == 1 and f[0]['fde'] == h[0]['fde'], 'historical FDE mismatch')
    rel = named_section(secs, '.rela.dyn')
    wanted, found = {0x57755a8: 0x3273810, 0x56dfbf8: 0x1dd8eb}, {}
    for off in range(rel['offset'], rel['offset'] + rel['size'], 24):
        slot, info, add = struct.unpack_from('<QQq', data, off)
        if slot in wanted:
            require(slot not in found and info == 8 and add == wanted[slot], 'historical relocation changed')
            found[slot] = add
    require(found == wanted, 'historical relocation missing')
    require(decode_edge(data, secs, 0x3272785, 'slot')[1] == 0x57755a8,
            'historical caller changed')
    require(decode_edge(data, secs, 0x3273856, 'lea')[1] == 0x56dfbf8,
            'historical Location reference changed')
    require(read_va(data, secs, 0x3273871, 4, True) == bytes.fromhex('4983fd02'),
            'historical result comparison changed')
    length, line, col = struct.unpack('<QII', read_va(data, secs, 0x56dfc00, 16))
    require((line, col) == (107, 37) and
            read_va(data, secs, found[0x56dfbf8], length).endswith(b'l1/src/abci/state.rs'),
            'historical Location changed')


def tsv(rows):
    require(bool(rows), 'empty table')
    stream = io.StringIO(newline='')
    writer = csv.DictWriter(stream, fieldnames=list(rows[0]), delimiter='\t', lineterminator='\n')
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue().encode('utf-8')


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + '\n').encode('utf-8')


def collect(data):
    authenticate(data)
    secs, index = unwind_index(data)
    _, fdes = eh_frame_records(data, secs)
    functions = select_functions(data, secs, index, fdes)
    windows = select_windows(data, secs)
    edges = select_edges(data, secs)
    fields, values = select_fields(data, secs)
    relocs = select_relocations(data, secs)
    location = location_record(data, secs, relocs)
    location['reference_owner'] = location_owner(index, fdes)
    facts = derived(values, read_va(data, secs, 0x55f4760, 10, True))
    by_start = {f['start']: f for f in fdes}
    exceptions = []
    for label, start, _, _ in FUNCTIONS:
        exceptions.extend(lsda_rows(data, secs, by_start[start], label))
    links = exception_links(edges, exceptions, functions)
    summary = {'target': 'Linux x86-64 node #115', 'binary_sha256': TARGET_SHA256,
               'coordinates': 'linked ELF virtual addresses before load bias',
               'counts': {'selected_new_fdes': len(functions),
                          'selected_new_fde_bytes': sum(f['length'] for f in functions),
                          'new_windows': sum(r['scope'] == 'new' for r in windows),
                          'context_windows': sum(r['scope'] == 'context' for r in windows),
                          'new_edges': sum(r['scope'] == 'new' for r in edges),
                          'context_edges': sum(r['scope'] == 'context' for r in edges),
                          'operand_fields': len(fields), 'relocations': len(relocs),
                          'lsda_rows': len(exceptions), 'selected_new_calls': len(links),
                          'selected_calls_in_lsda_rows': sum(r['status'] == 'matched' for r in links)},
               'limitations': 'Selected static observations; FDEs are unwind ranges, not a complete function census.',
               'derived': facts}
    return {'functions.tsv': tsv(functions), 'windows.tsv': tsv(windows), 'edges.tsv': tsv(edges),
            'fields.tsv': tsv(fields), 'relocations.tsv': tsv(relocs),
            'exceptions.tsv': tsv(exceptions), 'unwind-links.tsv': tsv(links),
            'location.json': json_bytes(location), 'summary.json': json_bytes(summary)}


def generate(binary, out, historical=None):
    data = binary.read_bytes()
    records = collect(data)  # no output is created before all checks pass
    if historical is not None:
        verify_historical(historical.read_bytes())
    out.mkdir(parents=True, exist_ok=True)
    for name, contents in records.items():
        (out / name).write_bytes(contents)
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--historical', type=Path)
    args = parser.parse_args()
    generate(TARGET, args.out, args.historical)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, struct.error) as error:
        print('abci_postblock_keys115:', error, file=sys.stderr)
        raise SystemExit(1)
