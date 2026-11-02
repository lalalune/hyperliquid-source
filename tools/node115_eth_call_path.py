#!/usr/bin/env python3
"""Reproduce selected node 115 eth_call adapter evidence from authenticated ELF bytes."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

# These are explicitly selected FDE starts, not an exhaustive function census.
FUNCTIONS = (
    ('router_init', 0x2e375a0),
    ('limiter_construct', 0x175ceb0),
    ('register_methods', 0x2a05f60),
    ('register_eth_call', 0x2d02f60),
    ('registered_callback', 0x2dd67c0),
    ('rpc_outer_future', 0x2d087e0),
    ('required_parameter', 0x2d10310),
    ('block_id_parameter', 0x2d0f2e0),
    ('state_override_parameter', 0x2d0f5a0),
    ('block_override_deserialize', 0x1d6bfb0),
    ('transaction_deserialize', 0x1d6c480),
    ('transaction_object', 0x1e26230),
    ('field_name_from_bytes', 0x299fd90),
    ('field_name_alternate', 0x299fbc0),
    ('gas_value_parser', 0x29a0530),
    ('quantity_visitor', 0x29ffb40),
    ('call_handler_future', 0x2a2a0e0),
    ('expensive_call_limiter', 0x2a04070),
    ('permit_selector_wrapper', 0x29cc120),
    ('permit_selector_guard', 0x2a353d0),
    ('permit_refresh_and_select', 0x175d250),
    ('worker_spawn', 0x2b3c190),
    ('worker_callback', 0x2b215d0),
    ('context_adapter', 0x29c1ee0),
    ('call_worker', 0x2a4dc20),
    ('request_adapter', 0x2a098b0),
    ('request_preparation', 0x2a04660),
    ('balance_bound_helper', 0x2a2fd10),
    ('downstream_call_boundary', 0x2962aa0),
)

# Each digest pins the exact manually selected instruction window. Raw bytes,
# file offsets, FDE ranges, direct targets and tables are emitted from the ELF.
WINDOWS = (
    ('router_limiter', 0x2e3763f, 14, '050b2dd3066c4021aa558cd037f5a5d959aae3e81825f18750e455dfb68f987e'),
    ('router_registration', 0x2e377a8, 21, 'e8bb2b4f29152970d777d95bdbb3ab439f376b287538b668ccb9807b7df5ad2d'),
    ('method_registration', 0x2a05fab, 25, 'b301637e29ff1736159b567ff4b37d0312b66cde10d04723058c30e59d60744e'),
    ('registration_vtable', 0x2d02fc3, 49, '136b640c53caf2c33dd20fc1bc86d00b1101371cf87cda4ae6f0dd8d8684cddc'),
    ('callback_future', 0x2dd6828, 57, '0e6ccde3105ad1436fc8bbf824b9c2f406660c28e41b318a98ff2bf9c76ba39f'),
    ('request_parse_dispatch', 0x2d08aa1, 77, '225e592da79757a78b6631383b80b05f692c8952c77432a1c215fc5dda8a6cdf'),
    ('request_error_names', 0x2d094be, 38, '2d9c66ba1e20aaffbebb09984f8599b3064715c11780e22fbb4d94c795ac7e47'),
    ('handler_future_dispatch', 0x2d09071, 85, '4bdb2ec5911dd4f627ac219104d183c0a35b7c4bb5128210c7d15b66f85bc92c'),
    ('parameter_empty_and_end', 0x2d10335, 52, '156922466ad4a6b6accca1d8beba2f5b96957bdefbf734fab8991285931956bf'),
    ('parameter_object_call', 0x2d103d3, 50, '657711855d8cd7ca915bed3e6b5b18d0bdb6051cf44859f28db81ca2cc66c1c8'),
    ('parameter_return_copy', 0x2d105e2, 27, '4df9e5aeda2d77f839a106a2aac89d4679e27ffa864d77412464acec4de40f6c'),
    ('parameter_missing_error', 0x2d10634, 130, '96402b6c4d7f6c15c6cc3b2e65692d0059ba7e61e71efda684ddf0ff3e060e35'),
    ('transaction_object_call', 0x1d6c511, 44, 'b387ba70e926ec667b4b35e18e60322fd5c7496490dfc04201153801184faaca'),
    ('transaction_object_copy', 0x1d6c560, 22, 'c57d9d98a7f7f50a6dd8b52f852c909900bfeac644e26c36dac6d0cc1abfbe34'),
    ('transaction_copy_tail', 0x1d6c583, 50, '19a95464b851e19492f104c1aa9282dda676fe13113c57de18543d7cee3f87bc'),
    ('transaction_return', 0x1d6c625, 34, '8244f1cce197cc62e584fc8fcd3454db5c711fdcf6bbead319f0d70ecd872d24'),
    ('object_name_classify', 0x1e2647a, 66, '1150ea670ccfa6691e951265dd792e697c46dedbefeabf72a15aae3b56129f50'),
    ('object_field_dispatch', 0x1e2650c, 52, '56a939620834f130749d99d824b1ffab3669b35f1b60b9f7fabbd7173fa7e6ce'),
    ('name_length_dispatch', 0x299fd9e, 30, '699c5c63eb2de53a60874a2c19bdb735cdb4a724efbbeef29a6e0e7e727eafba'),
    ('name_gas_match', 0x299fe72, 32, '2d90ac29eb3c03ed922166edc298cf0f82e27a7e21be070cf520faa31ba3ca96'),
    ('gas_duplicate_check', 0x1e269fe, 22, 'acccca34a8f3d4a097ddf881376fa0236814a05b9bbea6c88fbe2cf0dbcc9b2b'),
    ('gas_value_parse', 0x1e2717d, 60, '5b6706b07950ce6214bcd05781115992dc0a68e3f1c1bf87e3d772e5785314de'),
    ('gas_absent_sentinel', 0x1e27443, 18, '79d6ac6a12b769538fe11d9880f4c3f1c9a2b7d6faaeb4d758431c48ca4f10a2'),
    ('gas_result_layout', 0x1e27da3, 37, '822712f162137613cfcc19850b4928914edf31d58afb3c2701bc5187660c9034'),
    ('object_final_copy', 0x1e280d3, 27, 'daceed621b3ac29a588bb003bc6336d8449bfc2d931c4e70bc36f647055beb95'),
    ('handler_input_copy', 0x2a2a123, 25, 'b81bf81279e2192426f7dc42f619f1b93e96bfe3368d03f11340a0a2902386c0'),
    ('handler_nested_copy', 0x2a2a181, 109, 'f207f7321ccc41e30f227318d8d541e82d7170775e89ddb20ea3aa91db2e912e'),
    ('handler_method_name', 0x2a2a1ee, 47, 'd906f7fbc08e3b2c709b20b10372a1809a6687b8a28c4e2679a8b79e883624a7'),
    ('handler_permit', 0x2a2a2cf, 45, '71281ab7367d23907cf3eb2b9c169e1528d99c49a497425000f0fe7f77e65391'),
    ('handler_ready', 0x2a2a426, 17, 'd76e2dc50f9f449ee2869787cb5d2dca872d521615ae7a4a32d0f195f7b20037'),
    ('handler_worker_copy', 0x2a2a470, 35, '44b66047b32cdd7bee009cac831d616cebda71fc94c8af24826dcfbe188b1df6'),
    ('handler_spawn', 0x2a2a4ee, 66, '38a50bf7bc76cbeeccee8e3ef1c0f622c64c5d9286e4c104045251355c6aaec1'),
    ('handler_pending', 0x2a2a578, 32, '71f3634ba07328b17e94fdf0f8612be08e52ac04cb5a2af036aa0e1615cae029'),
    ('limiter_entry', 0x2a04070, 49, 'd66e0565acddb89a57d84f5d386efeadf7768f48e532b2918c593064b1ed9195'),
    ('limiter_select', 0x2a04110, 35, 'ac57ae7941df67761adc6d1879fed0f476e244a93813ebc0478e1f3ebb809e2b'),
    ('limiter_poll_pending', 0x2a04351, 63, '69354c6b2a76a546a94174bbd1dce0923f325ad3aeec1460c31f5a9892c671fe'),
    ('limiter_poll_timeout', 0x2a043a0, 17, '39239e798f8b82d10336981a836f7be5e5e9e5a37f197f3e07e23a6a95824235'),
    ('limiter_timeout_object', 0x2a043e9, 54, 'ebd0104e7f126d20f889a5fb8f60b1c60c94da8c507205e505cf52af473f9f3f'),
    ('limiter_result_tags', 0x2a04463, 158, '491698b9e49148975f21ee1766d5b842d2a381d9a7c8a242f3bdc469d198e818'),
    ('limiter_resume_dispatch', 0x2a0441f, 34, '455c7b6f0dc1173c89d4b428c1a8d824209cb1083bce0ffb06d1ac05f2eb34b6'),
    ('limiter_invalid_states', 0x2a04528, 56, '1855d24477f48ac4c37cb8e79512541d6d2207ccb9ec166cc5f62678fb416faa'),
    ('permit_selection_tail', 0x29cc19e, 20, '16f71d3ffb7f84e99c4bda8f1beb8699f68f2df1b50a49ebff45ecf0fe8c5add'),
    ('permit_inner', 0x2a3548c, 29, '17e2849efc2b4e99955a85f68f93e17400c5a716d5eb5f41e49830767ef5bd74'),
    ('permit_cap_refresh', 0x175d2fc, 27, 'd78dd322d1007cc46015e59428548bdab352d6e2b5f58d7a481a7b62770f308b'),
    ('permit_first_replace', 0x175d32e, 67, 'bcc739e6474532695dd8c283e60b725fe6060a9b2e5246cf16f57474e201778d'),
    ('permit_second_replace', 0x175d371, 109, 'bbcde1c9147f965377f61ed8b84d14d3a719190bc63b79b85633875410bc17cd'),
    ('permit_select_ref', 0x175d3de, 23, '724953683397abca534bc6bd6ff38f62ffc3a82cf583b37fa9750b56c279b724'),
    ('permit_return_threshold', 0x175d47f, 10, 'bebebe543f862ec1375c30bb16e95c2fa5fc470c2370a8c5626e23ee38e435ee'),
    ('spawn_payload', 0x2b3c1df, 80, '951cc750e4f6352d6bbe6da48bdabc60ba596242c80188ec54fbbb4d59769c21'),
    ('spawn_vtable', 0x2b3c247, 15, 'd06ffe034d0fbb79fb38fa87c1d455bfebacfecbcdc1a2785c940ff06d21ffb2'),
    ('spawn_heap_copy', 0x2b3c28a, 27, '3463588fd3e47a92f06fd1536aa9057d7e7456ada9cbef091754ebee7145cf3b'),
    ('worker_payload', 0x2b2171d, 23, '0c96930deacc8bc2f3d71301656550137e7e907a611e0c44a427bf0b45c165d1'),
    ('worker_context_call', 0x2b217f6, 33, 'ecf7bc6beeaa8bcec8d4847ed233ec222606249c858264eeefa6d223a2bb9730'),
    ('lock_adapter_call', 0x29c1f65, 16, '43d8a4cbddf879f59528a791ca8fc6f2cef2a3b5101c4242899fec486a945a4a'),
    ('worker_request_copy', 0x2a4dc31, 40, 'e0b936f9eeb78c2addb0812b96850497b95ad1b27db767effea07379a601a0b4'),
    ('worker_run_call', 0x2a4ddb7, 58, '9cbcd2fc40631c74bca35e8f7dc6ce69de827022523049ffc6db6e80dc815138'),
    ('worker_run_alternate', 0x2a4e098, 54, '714c6cf1e247cd006f52fd3b01e2eb5fa95ddae9db494d25b8bf19c0aa52ad6e'),
    ('worker_lock_release', 0x2a4ddf1, 63, 'df06d73e36682e859fb7f36cc638e7a127a5b04d810be116a4ab96ac9445b0a0'),
    ('adapter_input_copy', 0x2a09aee, 18, '5a4eae28f4b5b191b3fd3e10d3cdc779f92aca40297cd73fe7d33cd0f407fbc6'),
    ('adapter_tagged_bound', 0x2a09b43, 60, 'd8c5063ba3df4be1cd5b2c18beb0be7f23e442f9318ad4a80da4191d4ecf2be3'),
    ('adapter_account_gate', 0x2a0a588, 95, 'cbaa616560b0d82370466f860e261ce95cd8c68206c07ae210ac1895b9828259'),
    ('adapter_account_error', 0x2a0a63d, 9, '3c3d292ee17e5f343bc59277bbd7cfdfbb1a9c50005894792264deff70b96af9'),
    ('adapter_final_bound', 0x2a0a744, 54, 'a99be283d8ad2ecd9493331a617b991f44730b45e9abf0976e75d31523a9ca0a'),
    ('adapter_staged_copy', 0x2a0a831, 24, '4faff415a446d1d3dc1d01f14b81ace3842f4859d9a68a349285f008dff70d6b'),
    ('adapter_engine_call', 0x2a0aa2c, 69, '631597411711a39b29ce7bfba6d746690fea000680185340b2a4338042a9fa0d'),
    ('adapter_cleanup', 0x2a0a905, 63, '511577cc55867cd56cfb5461f7d9e0b1c5d44406ed9c50ebbf83355756e8130a'),
    ('balance_subtract', 0x2a2fe3a, 101, '95c0fd39cfca2b8ccc2227ffc2316fdc16e0a86dc0f9274f3cb29cadc00c112d'),
    ('balance_borrow_error', 0x2a2feda, 51, '31316bd9eb161f55dc5ff0ca00b8d891cc660810b12242714fbb23ab735cce4f'),
    ('balance_zero_divisor', 0x2a2ff26, 40, 'cbad410d75b86229db1a4b16ed0929dbe54351f93a9b8d7da0927ddc47256443'),
    ('balance_divisor_and_saturate', 0x2a2ff6d, 84, 'c449ca3d2281a8c96c0f09e0ee1d11e925a4ed7575f771eadd4551b7e0a50dec'),
    ('adapter_normalized_to_prepare', 0x2a0a36e, 64, '1e8eda800eae3fb530b5f9eb0fbb089e818669056b01a06d3fc155ad3c5ef0c0'),
    ('prepare_argument_roles', 0x2a04671, 23, 'f17b9e34e948454031f64d9dcfa5eb9a96a745fb7e7cf5c761845e07de0fb220'),
    ('prepare_request_copy', 0x2a047f8, 22, '6ef74bddaf9c354ae803a507c5b0e37de6f1a284bcd6a919d533711c47d7cb27'),
    ('prepare_gas_local', 0x2a04912, 29, 'eae362a453d9159ad79ee0f57e45b4e59300e726b05e9ff1723e1b34de84fa7e'),
    ('prepare_output_pointer', 0x2a04bbe, 8, 'a80a92329e6458e4cede075b90e2c714a048a2b67536710a00205a32b36781e4'),
    ('prepare_gas_absent_override', 0x2a04c89, 23, 'b7c5ad43f2f4991a72cc6d1d841ee2ac4284dcbcdb9556453176a4139b56d9c4'),
    ('prepare_output_pointer_restore', 0x2a055b8, 14, 'a708e226aa3a0cb33b8130678e1f40aa7aaa5b4e65c8c4566cf0a75f4772d0d6'),
    ('prepare_gas_output', 0x2a0573a, 15, '2fba49b3a092db43d90bc9d1e8bea1755d4b11531447db62b18eec38cd1cfa55'),
    ('adapter_prepared_to_stage', 0x2a0a4c1, 37, '194f5b93ad22c1cc30454738a011a95c06a8674c5be878ec61d5c53d6c1f21a1'),
    ('object_absent_zero_register', 0x1e27381, 9, '86079c921efc7ae57fb58a46b1a6aa2e2e1728c705112b6e82b74dc3a2765f24'),
    ('gas_null_sequence', 0x29a059c, 103, 'ce1e8f257596eec6c252e7359abb7fe3d3b5d0039f8888b5c13939231ce92f63'),
    ('gas_value_tag_results', 0x29a0603, 63, '9f143cd61c3b8000056e4070ed3ec47501bacbfa7e5a3d377f4498d4efebd698'),
    ('gas_null_error', 0x29a0642, 38, '06ec1f7fd829695568f5d9b4cb09d98e430355cb7debd4253da98708ea4e7576'),
    ('quantity_quote_and_minus', 0x29ffbc8, 16, '57450ef1decb39868c618842f2872df481cd48f9838c02b46b968e372c612689'),
    ('quantity_digit_dispatch', 0x29ffd02, 32, 'cf27806035b3f323733bede6adf1a5bc043eb10e49b8fd1d94e91da419a27d81'),
    ('quantity_zero_literal', 0x29ffd37, 40, '49fd210ab4958b586dc5a56993d070cbd46d7359ef627efd84a81e057e2c842d'),
    ('quantity_hex_helper', 0x29ffd5f, 23, 'b4422ff10754f32405b11afed299f28655a7a3e07c95d400d6e82fe4afe95797'),
    ('quantity_success_return', 0x29ffdaa, 11, 'e123aa3005116d3057daad9fbafcfaf3ca98c3acfa2bda08c193abeccc28ea7e'),
    ('quantity_zero_result', 0x29fffdc, 7, '8c22ccc4d07fa9b577afacc7cbb87e693ee2ccaaa663369d78889ebc163696af'),
    ('quantity_error_return', 0x29fffc2, 24, 'b9c23923a5dcfbce6dad5e0a6988141aff46a93109d72dd979f3fff479f50a0c'),
    ('handler_worker_poll', 0x2a2a53f, 57, 'e9405b55accb5e481a7f2bcbb11bfeba3884a77a63dfeaa87dbca247e3fbc53f'),
    ('handler_worker_ready', 0x2a2a6d2, 42, '348d38d509ca855aa4c89607a81a3efc32ebb8846caff7cbf854efb63165eb31'),
    ('handler_worker_error_case', 0x2a2a7d2, 50, 'd8f5244f888f59ab79f911569d6aa363d5d423870d688e783911ff42cb57444e'),
    ('handler_result_variants', 0x2a2a9ad, 43, '030dad12a19aa4a9350ba17583e983a50a2298c9a1ac7eff5fc7d2ea7564a749'),
    ('handler_return_value', 0x2a2b4a6, 76, 'd6ec536c6af39a24d86051348b785f2135f515d50821537f1c5d25f7619a8ced'),
    ('outer_poll_status', 0x2d090c6, 44, 'd036caca8333ecf31655881097d54495c4c737f70779f6404356fc80ef8dd868'),
    ('outer_completed_release', 0x2d09124, 66, '810f321a4f45c62c8e2df7ff4375ea6b1ab5e3d95d8d00e3ba01eb3a39e90ca2'),
    ('outer_completed_tag', 0x2d09188, 30, 'ef2f79327cfdc933191fc2fdd0c4cea61af2afe6516e9401e25343ce55c32298'),
    ('outer_result_state', 0x2d09212, 18, 'e2d0fcf8bcf5b11207856efd2fdc7e7ca710884d77e0d120d7cabcf9eca8547b'),
    ('outer_result_builder', 0x2d09289, 41, '384230e4bb372dab67d24a652c6a72640e9c2bcdb19b7a4d422819b2c35e1e0c'),
    ('outer_return_value', 0x2d0931e, 81, '2326273951a0d2b36ee87410cc0dd3cdfc6a71b9a6537c31e9723da94329aacb'),
    ('outer_request_first_copy', 0x2d08f0a, 27, '3d7cd24440f5deb438e372599f3b47611bd99d06c1be848bd43fd2e6b2261970'),
    ('outer_request_second_copy', 0x2d08f85, 34, '049fb089712443c3ecc146f257927c9276528d9150b57180cf1f59b2e5fb0173'),
    ('outer_request_future_copy', 0x2d0900d, 19, 'd00ca6b10d28d9c014494cacfba353f107df57b4906344b3151fdc2a5eb120ab'),
    ('handler_request_save', 0x2a2a1cd, 33, 'c08e72068868c6654a6c4fd493ad7cfd26551d2f9ebcb7d4966c0b919a4b1484'),
    ('handler_request_to_limiter', 0x2a2a28a, 23, '754364fa61a2c8828a5758c30bc7c8bed80d3f54c8cd558dc9d1221e647f832b'),
    ('spawn_to_heap', 0x2b3c305, 22, 'c279e83a47e9b5ac040c30668ffc3e9b631d681b9bea888ce4a206c8b056b885'),
    ('worker_unpack_first_words', 0x2b216e9, 52, '4e6f83760054098e2c5a4e84fe563e31c257dfe1d6fb631d388e7e4476a7009b'),
    ('worker_rebuild_request', 0x2b21787, 38, 'd491391f529028517d4673609ccf8e59bca7cdcc7888bf28eaa513f9b12a69ba'),
    ('context_input_mapping', 0x29c1ef1, 17, '30e3c06a6a3c87e8f14f6c5c4fac035792c0e54ca8ed97e547763a849b0ce187'),
    ('outer_block_id_parse', 0x2d08aee, 37, 'd890475e84a0bbfb0b07b296a8dc20b1077a5c9dab453e3c2e4304b4025e9d6b'),
    ('outer_state_override_parse', 0x2d08b77, 30, 'dac18de3b6e5b2f40c7b2a407898b395ec58a5fc6bb95aa559a371b717378e04'),
    ('outer_block_override_parse', 0x2d08c94, 35, '9e807e40c22a12b7fbd6d34822fa96e0c897b80820a55d95b1c271645f161047'),
    ('block_id_absent', 0x2d0f30b, 59, '3f1ee00e99122d80147519266983c648adf778cc671af47476f7f0e576959145'),
    ('state_override_absent_test', 0x2d0f5ca, 56, 'f1639a8e72e6a62ed10231a7381c83c8a1c508db54d9d836378e3d63cf095472'),
    ('state_override_absent_result', 0x2d0f84e, 15, '7f2dabf35c99b11e9edf693c18c02c308553a9000ee861c161781af2a106a7cc'),
    ('block_override_input', 0x1d6bfba, 90, '945f10f0838a3ad055a7413ac4e6b14bf28943dc6fcfa1f297be8c44afffa630'),
    ('block_id_error_labels', 0x2d09553, 44, '8e739057ba84a3ec61a528ec052b8f408e41ac76c50d240e228e4e89bb762799'),
    ('state_override_error_labels', 0x2d095e5, 44, 'f84d80fa429c014eaf62f931114c4e9c4d103f3dbd07cea5630cf1de373dffe7'),
    ('block_override_error_labels', 0x2d093f5, 44, '5128ce7df95f21fc4afcec1f976b4f597a819b656c5172ab57a0c5d4b2f31e39'),
    ('duplicate_gas_error_detail', 0x1e28597, 88, 'f5ac312789a8fbd95c68270a689296cfa8b4d69ef424422e6856ff96fffada02'),
)

# opcode and target are independently checked against fixed x86-64 encodings.
DIRECT_EDGES = (
    ('router_to_registration', 0x2e377b8, b'\xe8', 0x2a05f60),
    ('method_to_registration', 0x2a05fbf, b'\xe8', 0x2d02f60),
    ('outer_to_parameter', 0x2d08aae, b'\xe8', 0x2d10310),
    ('outer_to_block_id_parameter', 0x2d08afb, b'\xe8', 0x2d0f2e0),
    ('outer_to_state_overrides', 0x2d08b81, b'\xe8', 0x2d0f5a0),
    ('outer_to_block_overrides', 0x2d08c9c, b'\xe8', 0x1d6bfb0),
    ('parameter_to_transaction', 0x2d103e0, b'\xe8', 0x1d6c480),
    ('transaction_to_object', 0x1d6c51b, b'\xe8', 0x1e26230),
    ('object_to_name_parser', 0x1e26482, b'\xe8', 0x299fd90),
    ('object_to_other_name_parser', 0x1e264a3, b'\xe8', 0x299fbc0),
    ('gas_to_value_parser', 0x1e27188, b'\xe8', 0x29a0530),
    ('duplicate_gas_to_error_helper', 0x1e285e5, b'\xe8', 0x2e31fb0),
    ('gas_value_to_quantity', 0x29a0608, b'\xe8', 0x29ffb40),
    ('quantity_to_hex_helper', 0x29ffd6a, b'\xe8', 0x29fe020),
    ('missing_to_error_builder', 0x2d106a0, b'\xe8', 0x25cd880),
    ('handler_to_limiter', 0x2a2a2dd, b'\xe8', 0x2a04070),
    ('limiter_to_selector', 0x2a04121, b'\xe8', 0x29cc120),
    ('selector_to_guard_tail', 0x29cc1ad, b'\xe9', 0x2a353d0),
    ('selector_to_guard_call', 0x29cc927, b'\xe8', 0x2a353d0),
    ('limiter_to_poll', 0x2a04366, b'\xe8', 0x2b69af0),
    ('handler_to_spawn', 0x2a2a524, b'\xe8', 0x2b3c190),
    ('handler_to_worker_poll', 0x2a2a554, b'\xe8', 0x2e4ac30),
    ('handler_to_result_helper', 0x2a2a73e, b'\xe8', 0x29b0880),
    ('outer_to_cleanup', 0x2d0921f, b'\xe8', 0x2df5e00),
    ('outer_to_result_builder', 0x2d092ad, b'\xe8', 0x22d7030),
    ('worker_to_context', 0x2b21812, b'\xe8', 0x29c1ee0),
    ('context_to_worker', 0x29c1f6b, b'\xe8', 0x2a4dc20),
    ('worker_to_adapter', 0x2a4ddd1, b'\xe8', 0x2a098b0),
    ('worker_to_adapter_alternate', 0x2a4e0af, b'\xe8', 0x2a098b0),
    ('adapter_to_prepare', 0x2a0a3a9, b'\xe8', 0x2a04660),
    ('adapter_to_balance_bound', 0x2a0a5cc, b'\xe8', 0x2a2fd10),
    ('adapter_to_downstream', 0x2a0aa67, b'\xe8', 0x2962aa0),
    ('bound_to_lookup', 0x2a2fd44, b'\xe8', 0x294e890),
)

BRANCHES = (
    ('outer_request_error_if_equal', 0x2d08acd, b'\x0f\x84', 0x2d09488),
    ('missing_if_zero_length', 0x2d10338, b'\x0f\x84', 0x2d10634),
    ('not_closing_bracket', 0x2d1034f, b'\x0f\x85', 0x2d10425),
    ('block_id_absent', 0x2d0f30e, b'\x74', 0x2d0f33a),
    ('state_override_absent', 0x2d0f5cd, b'\x0f\x84', 0x2d0f84e),
    ('block_id_error', 0x2d08b48, b'\x0f\x85', 0x2d0951a),
    ('state_override_error', 0x2d08b8f, b'\x0f\x85', 0x2d095af),
    ('missing_after_closing_bracket', 0x2d10364, b'\xe9', 0x2d10634),
    ('duplicate_gas_if_not_sentinel', 0x1e26a04, b'\x0f\x85', 0x1e28583),
    ('gas_parser_tag_two', 0x1e2719e, b'\x0f\x84', 0x1e27744),
    ('name_not_gas', 0x299fe84, b'\x0f\x85', 0x299ff72),
    ('gas_null_bad_u', 0x29a05ca, b'\x0f\x85', 0x29a065d),
    ('gas_null_bad_l1', 0x29a05e6, b'\x75', 0x29a065d),
    ('gas_null_bad_l2', 0x29a05fd, b'\x75', 0x29a065d),
    ('quantity_zero_literal', 0x29ffd59, b'\x0f\x84', 0x29fffdc),
    ('future_allocation_failed', 0x2d0907f, b'\x0f\x84', 0x2d09470),
    ('registration_allocation_failed', 0x2d02fac, b'\x74', 0x2d03005),
    ('not_pending', 0x2a2a2ee, b'\x75', 0x2a2a2fc),
    ('pending_to_return', 0x2a2a2f7, b'\xe9', 0x2a2a582),
    ('not_permit_ready', 0x2a2a42a, b'\x0f\x85', 0x2a2a598),
    ('worker_poll_not_pending', 0x2a2a572, b'\x0f\x85', 0x2a2a615),
    ('worker_result_other_variant', 0x2a2a6fa, b'\x75', 0x2a2a74b),
    ('worker_result_different_variant', 0x2a2a7f4, b'\x75', 0x2a2a804),
    ('outer_poll_not_pending', 0x2d090d2, b'\x75', 0x2d090f2),
    ('outer_completed_tag_three', 0x2d0918b, b'\x74', 0x2d0919c),
    ('handler_result_variant_two', 0x2a2a9bf, b'\x0f\x84', 0x2a2aa68),
    ('handler_result_not_variant_three', 0x2a2a9d2, b'\x0f\x85', 0x2a2ab85),
    ('poll_not_pending', 0x2a04377, b'\x75', 0x2a04390),
    ('poll_not_tag_one', 0x2a043ab, b'\x0f\x85', 0x2a04463),
    ('first_permit_allocation_failed', 0x175d325, b'\x0f\x84', 0x175d498),
    ('second_permit_allocation_failed', 0x175d393, b'\x0f\x84', 0x175d498),
    ('gas_not_present_tag', 0x2a09b57, b'\x75', 0x2a09b67),
    ('gas_value_at_most_cap', 0x2a09b65, b'\x72', 0x2a09b7f),
    ('prepared_gas_present', 0x2a04c8f, b'\x75', 0x2a04ca0),
    ('fee_fields_both_zero', 0x2a0a598, b'\x0f\x84', 0x2a0a72f),
    ('original_gas_tag_nonzero', 0x2a0a5ae, b'\x0f\x85', 0x2a0a75b),
    ('balance_bound_not_error', 0x2a0a5e1, b'\x0f\x85', 0x2a0a744),
    ('balance_borrow_first', 0x2a2fe91, b'\x72', 0x2a2feda),
    ('balance_borrow_carry', 0x2a2fe9d, b'\x72', 0x2a2feda),
    ('zero_divisor', 0x2a2ff4c, b'\x74', 0x2a2ffb0),
)

LEAS = (
    ('method_name', 0x2a05fab, bytes.fromhex('488d15'), 0x459618),
    ('duplicate_gas_field_name', 0x1e28597, bytes.fromhex('488d05'), 0x5d200e),
    ('registration_vtable', 0x2d02fc8, bytes.fromhex('488d05'), 0x6450998),
    ('outer_future_vtable', 0x2dd684c, bytes.fromhex('488d15'), 0x6450a28),
    ('handler_future_vtable', 0x2d090a2, bytes.fromhex('488d05'), 0x6445868),
    ('error_parameter_name', 0x2d094be, bytes.fromhex('488d3d'), 0x617d83),
    ('error_type_name', 0x2d094c5, bytes.fromhex('488d15'), 0x617f17),
    ('invalid_params_message', 0x2d10687, bytes.fromhex('488d15'), 0x6167a1),
    ('block_id_name', 0x2d09553, bytes.fromhex('488d3d'), 0x459c80),
    ('block_id_type', 0x2d0955a, bytes.fromhex('488d15'), 0x617e94),
    ('state_override_name', 0x2d095e5, bytes.fromhex('488d3d'), 0x617ef0),
    ('state_override_type', 0x2d095ec, bytes.fromhex('488d15'), 0x617eff),
    ('block_override_name', 0x2d093f5, bytes.fromhex('488d3d'), 0x617ec0),
    ('block_override_type', 0x2d093fc, bytes.fromhex('488d15'), 0x617ecf),
    ('spawn_vtable', 0x2b3c247, bytes.fromhex('488d05'), 0x6449ab0),
    ('permit_location', 0x175d263, bytes.fromhex('488d35'), 0x640f7e8),
    ('limiter_location', 0x2a04110, bytes.fromhex('488d0d'), 0x6444e60),
    ('worker_location', 0x2b217f6, bytes.fromhex('4c8d05'), 0x644a990),
)

GOT_CALLS = (
    ('router_limiter_constructor', 0x2e37647, 0x64e22a8, 0x175ceb0),
    ('guard_permit_selection', 0x2a3549a, 0x64e22b0, 0x175d250),
    ('balance_arithmetic_helper', 0x2a2ff7a, 0x64dfb80, 0x144dde0),
)

# Expected relative relocations include vtable slots and Rust location pointers.
RELATIVE_SLOTS = (
    ('limiter_constructor_got', 0x64e22a8, 0x175ceb0),
    ('limiter_select_got', 0x64e22b0, 0x175d250),
    ('register_drop', 0x6450998, 0x2dd6d00),
    ('register_callback', 0x64509b0, 0x2dd67c0),
    ('outer_future_drop', 0x6450a28, 0x2dd6bd0),
    ('outer_future_poll', 0x6450a40, 0x2d087e0),
    ('handler_future_drop', 0x6445868, 0x29ea680),
    ('handler_future_poll', 0x6445880, 0x2a2a0e0),
    ('spawn_callback', 0x6449ab0, 0x2b215d0),
    ('spawn_slot_one', 0x6449ab8, 0x2b2d620),
    ('spawn_slot_two', 0x6449ac0, 0x2b2d080),
    ('spawn_slot_three', 0x6449ac8, 0x2b14fd0),
    ('limiter_source_53', 0x640f7b8, 0x44f487),
    ('limiter_source_46', 0x640f7d0, 0x44f487),
    ('limiter_source_107', 0x640f7e8, 0x44f487),
    ('limiter_source_57', 0x6444e60, 0x44f487),
    ('limiter_source_56', 0x6444e78, 0x44f487),
    ('handler_source', 0x6445888, 0x4349eb),
    ('worker_source', 0x644a990, 0x4349eb),
    ('arithmetic_helper_got', 0x64dfb80, 0x144dde0),
)

TABLES = (
    ('field_name_by_length_minus_two', 0x600974, 19, 0x299fd90),
    ('object_field_enum_minus_base', 0x5cfd88, 15, 0x1e26230),
    ('limiter_outer_resume', 0x601224, 4, 0x2a04070),
    ('limiter_inner_resume', 0x601234, 4, 0x2a04070),
    ('limiter_timeout_resume', 0x601244, 4, 0x2a04070),
    ('handler_outer_resume', 0x6015bc, 4, 0x2a2a0e0),
    ('handler_inner_resume', 0x6015cc, 4, 0x2a2a0e0),
)

FORK_PREFIXES = (
    'z_forks/reth-chainspec/', 'z_forks/reth-ethereum-forks/',
    'z_forks/reth-rpc-eth-types/', 'z_forks/reth-rpc-server-types/',
    'z_forks/revm-precompile/', 'z_vendor/revm-bytecode/',
    'z_vendor/revm-context/', 'z_vendor/revm-context-interface/',
    'z_vendor/revm-handler/', 'z_vendor/revm-inspector/',
    'z_vendor/revm-interpreter/', 'z_vendor/revm-state/',
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def authenticate(data):
    actual = digest(data)
    if actual != TARGET_SHA256:
        raise ValueError('node 115 SHA-256 mismatch')
    return actual


def section_named(sec, name):
    matches = [s for s in sec if s['name'] == name and s['type'] != 8]
    if len(matches) != 1:
        raise ValueError('Missing, duplicate, or non-file-backed section: ' + name)
    return matches[0]


def file_offset(sec, va, size, executable=False):
    if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
        raise ValueError('Invalid address or size')
    matches = [s for s in sec if s['type'] != 8 and s['size'] > 0
               and (not executable or s['flags'] & 4)
               and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('Address does not have one complete file-backed section mapping')
    s = matches[0]
    return s['offset'] + va - s['address']


def read_va(data, sec, va, size, executable=False):
    off = file_offset(sec, va, size, executable)
    result = data[off:off + size]
    if len(result) != size:
        raise ValueError('Truncated address range')
    return result


def decode_branch(data, sec, va, opcode, expected=None):
    if len(opcode) == 1 and opcode[0] in (0xe8, 0xe9):
        displacement_size = 4
    elif len(opcode) == 1 and (opcode[0] == 0xeb or 0x70 <= opcode[0] <= 0x7f):
        displacement_size = 1
    elif len(opcode) == 2 and opcode[0] == 0x0f and 0x80 <= opcode[1] <= 0x8f:
        displacement_size = 4
    else:
        raise ValueError('Unsupported branch opcode')
    raw = read_va(data, sec, va, len(opcode) + displacement_size, True)
    if not raw.startswith(opcode):
        raise ValueError('Unexpected branch opcode')
    delta = int.from_bytes(raw[len(opcode):], 'little', signed=True)
    dest = va + len(raw) + delta
    file_offset(sec, dest, 1, True)
    if expected is not None and dest != expected:
        raise ValueError('Branch target mismatch')
    return dest, raw


def decode_rip(data, sec, va, opcode, expected=None):
    if len(opcode) not in (2, 3):
        raise ValueError('Unsupported RIP-relative encoding')
    raw = read_va(data, sec, va, len(opcode) + 4, True)
    if not raw.startswith(opcode):
        raise ValueError('Unexpected RIP-relative opcode')
    dest = va + len(raw) + int.from_bytes(raw[-4:], 'little', signed=True)
    file_offset(sec, dest, 1)
    if expected is not None and dest != expected:
        raise ValueError('RIP-relative address mismatch')
    return dest, raw


def relocation_index(data, sec):
    rel = section_named(sec, '.rela.dyn')
    if rel['type'] != 4 or rel['size'] % 24:
        raise ValueError('Unexpected RELA section')
    rows = {}
    for pos in range(rel['offset'], rel['offset'] + rel['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, pos)
        if slot in rows:
            raise ValueError('Duplicate relocation destination')
        rows[slot] = (info, addend, pos)
    return rows


def relative_relocation(data, sec, relocs, slot, expected=None):
    file_offset(sec, slot, 8)
    row = relocs.get(slot)
    if row is None or row[0] != 8 or row[1] < 0:
        raise ValueError('Expected x86-64 RELATIVE relocation')
    target = row[1]
    file_offset(sec, target, 1)
    if expected is not None and target != expected:
        raise ValueError('RELATIVE addend mismatch')
    return target, row[2]


def dynamic_symbol_name(data, sec, index):
    syms = section_named(sec, '.dynsym')
    strings = section_named(sec, '.dynstr')
    if syms['type'] != 11 or strings['type'] != 3 or index < 0 or (index + 1) * 24 > syms['size']:
        raise ValueError('Dynamic symbol index outside table')
    pos = syms['offset'] + index * 24
    name_off = struct.unpack_from('<I', data, pos)[0]
    if name_off >= strings['size']:
        raise ValueError('Dynamic symbol name outside table')
    start = strings['offset'] + name_off
    end = data.find(b'\0', start, strings['offset'] + strings['size'])
    if end < 0:
        raise ValueError('Unterminated dynamic symbol name')
    return data[start:end].decode('ascii')


def get_functions(data, sec, index):
    _, fdes = eh_frame_records(data, sec)
    by_start = {}
    for fde in fdes:
        by_start.setdefault(fde['start'], []).append(fde)
    table = {entry['start']: entry for entry in index}
    result = []
    for name, start in FUNCTIONS:
        matches = by_start.get(start, [])
        hdr = table.get(start)
        if len(matches) != 1 or hdr is None or hdr['fde'] != matches[0]['fde']:
            raise ValueError('Selected FDE is not uniquely cross-indexed')
        f = matches[0]
        if f['end'] <= start or f['end'] > hdr['next_index_upper_bound']:
            raise ValueError('Selected FDE range is invalid or crosses the next indexed start')
        raw = read_va(data, sec, start, f['end'] - start, True)
        result.append({'role': name, 'start_va': hex(start), 'end_va_exclusive': hex(f['end']),
                       'file_offset': hex(file_offset(sec, start, len(raw), True)),
                       'fde_va': hex(f['fde']), 'fde_file_offset': hex(file_offset(sec, f['fde'], 4)),
                       'unwind_index': hdr['index'], 'length': len(raw), 'sha256': digest(raw)})
    return result


def get_windows(data, sec, functions):
    ranges = [(int(f['start_va'], 16), int(f['end_va_exclusive'], 16)) for f in functions]
    result = []
    for name, va, size, expected in WINDOWS:
        if sum(lo <= va and va + size <= hi for lo, hi in ranges) != 1:
            raise ValueError('Window outside one selected FDE range')
        raw = read_va(data, sec, va, size, True)
        if digest(raw) != expected:
            raise ValueError('Instruction window fingerprint mismatch: ' + name)
        result.append({'role': name, 'va': hex(va), 'file_offset': hex(file_offset(sec, va, size, True)),
                       'length': size, 'bytes': raw.hex(), 'sha256': digest(raw)})
    return result


def get_edges(data, sec, relocs):
    edges = []
    for name, site, opcode, expected in DIRECT_EDGES + BRANCHES:
        target, raw = decode_branch(data, sec, site, opcode, expected)
        edges.append({'role': name, 'kind': 'relative_control_flow', 'site_va': hex(site),
                      'site_file_offset': hex(file_offset(sec, site, len(raw), True)),
                      'bytes': raw.hex(), 'target_va': hex(target),
                      'target_file_offset': hex(file_offset(sec, target, 1, True))})
    for name, site, prefix, expected in LEAS:
        target, raw = decode_rip(data, sec, site, prefix, expected)
        edges.append({'role': name, 'kind': 'rip_relative_address', 'site_va': hex(site),
                      'site_file_offset': hex(file_offset(sec, site, len(raw), True)),
                      'bytes': raw.hex(), 'target_va': hex(target),
                      'target_file_offset': hex(file_offset(sec, target, 1))})
    for name, site, expected_slot, expected_target in GOT_CALLS:
        slot, raw = decode_rip(data, sec, site, b'\xff\x15', expected_slot)
        target, relocation_off = relative_relocation(data, sec, relocs, slot, expected_target)
        edges.append({'role': name, 'kind': 'rip_indirect_relative_relocation', 'site_va': hex(site),
                      'site_file_offset': hex(file_offset(sec, site, len(raw), True)), 'bytes': raw.hex(),
                      'slot_va': hex(slot), 'slot_file_offset': hex(file_offset(sec, slot, 8)),
                      'rela_file_offset': hex(relocation_off), 'target_va': hex(target),
                      'target_file_offset': hex(file_offset(sec, target, 1))})
    return edges


def get_relocations(data, sec, relocs):
    result = []
    for name, slot, expected in RELATIVE_SLOTS:
        target, rela_off = relative_relocation(data, sec, relocs, slot, expected)
        raw = read_va(data, sec, slot, 8)
        result.append({'role': name, 'slot_va': hex(slot), 'slot_file_offset': hex(file_offset(sec, slot, 8)),
                       'slot_bytes': raw.hex(), 'rela_file_offset': hex(rela_off),
                       'relocation_type': relocs[slot][0], 'addend_va': hex(target),
                       'addend_file_offset': hex(file_offset(sec, target, 1))})
    for role, slot, expected_name in (('copy_symbol_got', 0x64df508, 'memcpy'),
                                      ('move_symbol_got', 0x64df568, 'memmove')):
        row = relocs.get(slot)
        if row is None or row[0] & 0xffffffff != 6:
            raise ValueError('Expected dynamic symbol relocation at memory operation slot')
        index = row[0] >> 32
        symbol = dynamic_symbol_name(data, sec, index)
        if symbol != expected_name:
            raise ValueError('Memory operation dynamic symbol mismatch')
        result.append({'role': role, 'slot_va': hex(slot),
                       'slot_file_offset': hex(file_offset(sec, slot, 8)),
                       'rela_file_offset': hex(row[2]), 'relocation_type': row[0] & 0xffffffff,
                       'symbol_index': index, 'symbol': symbol, 'addend': row[1]})
    return result


def get_vtables(data, sec, relocs):
    result = []
    for role, base, size_expected, align_expected in (
        ('registration_callback', 0x6450998, 8, 8),
        ('outer_future', 0x6450a28, 0x88, 8),
        ('handler_future', 0x6445868, 0x8b0, 16),
    ):
        raw = read_va(data, sec, base, 32)
        size, align = struct.unpack_from('<QQ', raw, 8)
        if (size, align) != (size_expected, align_expected):
            raise ValueError('Vtable size or alignment mismatch')
        drop, _ = relative_relocation(data, sec, relocs, base)
        callback, _ = relative_relocation(data, sec, relocs, base + 24)
        result.append({'role': role, 'va': hex(base), 'file_offset': hex(file_offset(sec, base, 32)),
                       'raw_bytes': raw.hex(), 'size': size, 'alignment': align,
                       'drop_addend_va': hex(drop), 'slot_24_addend_va': hex(callback)})
    return result


def get_locations(data, sec, relocs):
    result = []
    for role, va in (('limiter_constructor_first', 0x640f7d0),
                     ('limiter_constructor_second', 0x640f7b8),
                     ('limiter_selection', 0x640f7e8),
                     ('limiter_poll', 0x6444e60), ('limiter_panic', 0x6444e78),
                     ('handler_panic', 0x6445888), ('worker_context', 0x644a990)):
        raw = read_va(data, sec, va, 24)
        _, length, line, column = struct.unpack('<QQII', raw)
        if length == 0 or length > 200:
            raise ValueError('Invalid location string length')
        pointer, rela_off = relative_relocation(data, sec, relocs, va)
        path = read_va(data, sec, pointer, length).decode('ascii')
        if not (path.startswith('evm_rpc/src/') and path.endswith('.rs')):
            raise ValueError('Unexpected location path')
        result.append({'role': role, 'va': hex(va), 'file_offset': hex(file_offset(sec, va, 24)),
                       'raw_bytes': raw.hex(), 'path': path, 'path_va': hex(pointer),
                       'path_file_offset': hex(file_offset(sec, pointer, length)),
                       'path_length': length, 'line': line, 'column': column,
                       'rela_file_offset': hex(rela_off)})
    return result


def get_tables(data, sec, functions):
    by_start = {int(f['start_va'], 16): f for f in functions}
    result = []
    for role, va, count, owner in TABLES:
        owner_end = int(by_start[owner]['end_va_exclusive'], 16)
        raw = read_va(data, sec, va, count * 4)
        deltas = struct.unpack('<' + 'i' * count, raw)
        entries = []
        for index, delta in enumerate(deltas):
            target = va + delta
            if not owner <= target < owner_end:
                raise ValueError('Jump table target outside selected FDE')
            file_offset(sec, target, 1, True)
            entries.append({'index': index, 'entry_va': hex(va + 4 * index),
                            'relative_signed': delta, 'target_va': hex(target),
                            'target_file_offset': hex(file_offset(sec, target, 1, True))})
        result.append({'role': role, 'va': hex(va), 'file_offset': hex(file_offset(sec, va, len(raw))),
                       'raw_bytes': raw.hex(), 'entries': entries})
    return result


def normalize_gas(tag, value, cap):
    """Evaluate only the observed tag-zero/tag-one branch, with unsigned 64-bit inputs."""
    if type(tag) is not int or tag not in (0, 1):
        raise ValueError('Unsupported request tag')
    if type(value) is not int or not 0 <= value < (1 << 64):
        raise ValueError('Gas word is outside the unsigned 64-bit range')
    if type(cap) is not int or not 0 <= cap < (1 << 64):
        raise ValueError('Cap is outside the unsigned 64-bit range')
    return 1, value if tag == 1 and value <= cap else cap


def fixed_immediate(data, sec, va, prefix, fmt):
    size = struct.calcsize(fmt)
    raw = read_va(data, sec, va, len(prefix) + size, True)
    if not raw.startswith(prefix):
        raise ValueError('Immediate instruction opcode mismatch')
    return struct.unpack_from(fmt, raw, len(prefix))[0]



def trace_gas_copies(data, sec, field_word_offset):
    def imm(va, prefix):
        return fixed_immediate(data, sec, va, bytes.fromhex(prefix), '<I')

    prepare_copy_base = imm(0x2a047f8, '488dbc24')
    prepare_tag = imm(0x2a04912, '4c8b9424')
    prepare_value = imm(0x2a0491f, '4c8b9424')
    temp_store = imm(0x2a04927, '4c899424')
    temp_load = imm(0x2a0573a, '488b8424')
    output_field = imm(0x2a05742, '488983')
    output_base = imm(0x2a0a38e, '488dbc24')
    first_src = imm(0x2a0a4c6, '488db424')
    first_dst = imm(0x2a0a4ce, '488dbc24')
    first_len = imm(0x2a0a4db, 'ba')
    bound_word = imm(0x2a0a75b, '488b8424')
    second_src = imm(0x2a0a839, '488db424')
    second_dst = imm(0x2a0a831, '488dbc24')
    second_len = imm(0x2a0a841, 'ba')
    third_src = imm(0x2a0aa3c, '488db424')
    third_dst = imm(0x2a0aa2c, '4c8dbc24')
    third_len = imm(0x2a0aa34, 'ba')
    if (prepare_tag, prepare_value) != (prepare_copy_base + field_word_offset - 8,
                                        prepare_copy_base + field_word_offset):
        raise ValueError('Preparation local does not read the selected request words')
    if temp_store != temp_load:
        raise ValueError('Preparation temporary gas slot differs')
    if not first_src <= output_base + output_field < first_src + first_len:
        raise ValueError('Prepared gas is outside first staged copy')
    first_result = first_dst + output_base + output_field - first_src
    if first_result != bound_word or not second_src <= bound_word < second_src + second_len:
        raise ValueError('Prepared gas does not reach second bound')
    second_result = second_dst + bound_word - second_src
    if not third_src <= second_result < third_src + third_len:
        raise ValueError('Gas does not reach final copy')
    third_result = third_dst + second_result - third_src
    return {'prepare_input_copy_stack_base': hex(prepare_copy_base),
            'prepare_input_tag_stack_offset': hex(prepare_tag),
            'prepare_input_word_stack_offset': hex(prepare_value),
            'prepare_temporary_stack_offset': hex(temp_store),
            'prepare_output_word_offset': hex(output_field),
            'adapter_prepare_output_stack_base': hex(output_base),
            'staged_copy_source': hex(first_src), 'staged_copy_destination': hex(first_dst),
            'staged_copy_length': first_len, 'adapter_second_bound_stack_word': hex(bound_word),
            'second_copy_source': hex(second_src), 'second_copy_destination': hex(second_dst),
            'second_copy_length': second_len, 'third_copy_source': hex(third_src),
            'third_copy_destination': hex(third_dst), 'third_copy_length': third_len,
            'downstream_argument_stack_base': hex(third_dst),
            'downstream_argument_word_offset': hex(third_result - third_dst)}


def parameter_error_labels(data, sec):
    result = []
    specs = ((0x2d09553, 0x2d0955a, 0x2d09569, 0x2d0956e),
             (0x2d095e5, 0x2d095ec, 0x2d095fb, 0x2d09600),
             (0x2d093f5, 0x2d093fc, 0x2d0940b, 0x2d09410))
    expected = (('block_id', 'Option < BlockId >'),
                ('state_overrides', 'Option < StateOverride >'),
                ('block_overrides', 'Option < Box < BlockOverrides > >'))
    for spec, pair in zip(specs, expected):
        name_va, _ = decode_rip(data, sec, spec[0], bytes.fromhex('488d3d'))
        type_va, _ = decode_rip(data, sec, spec[1], bytes.fromhex('488d15'))
        name_size = fixed_immediate(data, sec, spec[2], b'\xbe', '<I')
        type_size = fixed_immediate(data, sec, spec[3], b'\xb9', '<I')
        name = read_va(data, sec, name_va, name_size).decode('ascii')
        typ = read_va(data, sec, type_va, type_size).decode('ascii')
        if (name, typ) != pair:
            raise ValueError('Optional parameter labels changed')
        result.append({'name': name, 'name_va': hex(name_va), 'name_length': name_size,
                       'type': typ, 'type_va': hex(type_va), 'type_length': type_size})
    return result

def get_decisions(data, sec, tables):
    name_word = fixed_immediate(data, sec, 0x299fe75, b'\x35', '<I')
    name_tail = fixed_immediate(data, sec, 0x299fe7e, b'\x83\xf1', '<B')
    name = name_word.to_bytes(4, 'little')[:2] + bytes([name_tail])
    field_tag = fixed_immediate(data, sec, 0x299fe8a, b'\xc6\x03', '<B')
    enum_base = fixed_immediate(data, sec, 0x1e2650e, b'\x80\xe9', '<B')
    duplicate_va, _ = decode_rip(data, sec, 0x1e28597, bytes.fromhex('488d05'), 0x5d200e)
    duplicate_len = fixed_immediate(data, sec, 0x1e285a6, bytes.fromhex('48c7842428050000'), '<I')
    duplicate_name = read_va(data, sec, duplicate_va, duplicate_len)
    if duplicate_name != name:
        raise ValueError('Duplicate-field label does not match gas classifier')
    if name != b'gas' or field_tag < enum_base:
        raise ValueError('Gas field classifier mismatch')
    name_entries = tables[0]['entries']
    object_entries = tables[1]['entries']
    if int(name_entries[len(name) - 2]['target_va'], 16) != 0x299fe72:
        raise ValueError('Gas name table does not reach classifier')
    field_index = field_tag - enum_base
    if field_index >= len(object_entries) or int(object_entries[field_index]['target_va'], 16) != 0x1e269fe:
        raise ValueError('Gas field table does not reach selected handler')

    cmp_bytes = read_va(data, sec, 0x2a09b59, 12, True)
    store_bytes = read_va(data, sec, 0x2a09b73, 12, True)
    if cmp_bytes[:4] != bytes.fromhex('4881bc24') or store_bytes[:4] != bytes.fromhex('48c78424'):
        raise ValueError('Gas comparison or store encoding mismatch')
    cmp_offset, exclusive_cap = struct.unpack_from('<II', cmp_bytes, 4)
    store_offset, cap = struct.unpack_from('<II', store_bytes, 4)
    second_cap = fixed_immediate(data, sec, 0x2a0a763, bytes.fromhex('483d'), '<I')
    if cmp_offset != store_offset or exclusive_cap != cap + 1 or cap != second_cap:
        raise ValueError('Gas threshold relationship mismatch')
    tag_offset = fixed_immediate(data, sec, 0x2a09b43, bytes.fromhex('488b8424'), '<I')
    copied_base = fixed_immediate(data, sec, 0x2a09aee, bytes.fromhex('488dbc24'), '<I')
    parser_base = fixed_immediate(data, sec, 0x1e280db, bytes.fromhex('488db424'), '<I')
    parser_tag = fixed_immediate(data, sec, 0x1e27db0, bytes.fromhex('48899424'), '<I')
    parser_value = fixed_immediate(data, sec, 0x1e27dc0, bytes.fromhex('48899424'), '<I')
    if (tag_offset - copied_base, cmp_offset - copied_base) != (parser_tag - parser_base, parser_value - parser_base):
        raise ValueError('Parser and adapter field offsets differ')

    detail_first = read_va(data, sec, 0x2d10656, 10, True)
    detail_second = read_va(data, sec, 0x2d10648, 10, True)
    if detail_first[:2] != b'\x48\xb9' or detail_second[:2] != b'\x48\xb9':
        raise ValueError('Missing-parameter message construction changed')
    detail = bytearray(14)
    detail[6:14] = detail_second[2:10]
    detail[0:8] = detail_first[2:10]
    error_code = fixed_immediate(data, sec, 0x2d1069b, b'\xbe', '<i')
    invalid_message = read_va(data, sec, 0x6167a1, 14).decode('ascii')
    request_name = read_va(data, sec, 0x617d83, 7).decode('ascii')
    type_name = read_va(data, sec, 0x617f17, 18).decode('ascii')
    if bytes(detail) != b'No more params' or invalid_message != 'Invalid params' or request_name != 'request' or type_name != 'TransactionRequest':
        raise ValueError('Required parameter error literals mismatch')

    out = []
    for tag, word in ((0, 0), (0, cap + 1), (1, 0), (1, 1), (1, cap - 1),
                      (1, cap), (1, cap + 1), (1, (1 << 64) - 1)):
        new_tag, new_value = normalize_gas(tag, word, cap)
        out.append({'input_tag': tag, 'input_word': word, 'output_tag': new_tag, 'output_word': new_value})
    return {'gas_field': {'name': name.decode('ascii'), 'classifier_tag': field_tag,
                          'object_dispatch_base': enum_base, 'object_dispatch_index': field_index,
                          'name_classifier_va': hex(0x299fe72), 'object_handler_va': hex(0x1e269fe),
                          'duplicate_error_name': duplicate_name.decode('ascii'),
                          'duplicate_error_name_va': hex(duplicate_va),
                          'parser_request_tag_offset': parser_tag - parser_base,
                          'parser_request_word_offset': parser_value - parser_base,
                          'adapter_request_tag_offset': tag_offset - copied_base,
                          'adapter_request_word_offset': cmp_offset - copied_base},
            'optional_parameter_error_labels': parameter_error_labels(data, sec),
            'gas_copy_dataflow': trace_gas_copies(data, sec, parser_value - parser_base),
            'gas_bound': {'cap': cap, 'comparison_exclusive': exclusive_cap,
                          'second_cap': second_cap, 'unsigned_word_bits': 64,
                          'preserve_condition': 'tag equals 1 and unsigned word is below comparison_exclusive',
                          'other_observed_path': 'write tag 1 and cap', 'vectors': out},
            'missing_parameter': {'code': error_code, 'message': invalid_message,
                                  'detail': bytes(detail).decode('ascii'),
                                  'parameter_name': request_name, 'type_name': type_name,
                                  'internal_error_marker_hex': read_va(data, sec, 0x452990, 16).hex()}}


def get_fork_prefixes(data, sec):
    s = section_named(sec, '.rodata')
    block = data[s['offset']:s['offset'] + s['size']]
    result = []
    for prefix in FORK_PREFIXES:
        needle = prefix.encode('ascii')
        positions = []
        pos = 0
        while True:
            found = block.find(needle, pos)
            if found < 0:
                break
            positions.append({'va': hex(s['address'] + found), 'file_offset': hex(s['offset'] + found)})
            pos = found + len(needle)
        if not positions:
            raise ValueError('Expected fork/vendor path prefix missing')
        result.append({'prefix': prefix, 'occurrences': positions})
    return result


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + '\n').encode('ascii')


def tsv_bytes(rows, columns):
    buf = io.StringIO(newline='')
    writer = csv.DictWriter(buf, columns, delimiter='\t', lineterminator='\n', extrasaction='raise')
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue().encode('ascii')


def generate(data, out):
    actual = authenticate(data)
    sec, index = unwind_index(data)
    relocs = relocation_index(data, sec)
    functions = get_functions(data, sec, index)
    windows = get_windows(data, sec, functions)
    tables = get_tables(data, sec, functions)
    metadata = {'target': 'Linux x86-64 node 115', 'target_sha256': actual,
                'coordinate_system': 'link-time ELF virtual addresses and original file offsets',
                'limitations': 'FDE ranges are unwind ranges, not proven complete function boundaries; selected windows and branches are not a whole-program census.',
                'direct_edges_and_branches': get_edges(data, sec, relocs),
                'relocations': get_relocations(data, sec, relocs),
                'vtables': get_vtables(data, sec, relocs), 'locations': get_locations(data, sec, relocs),
                'jump_tables': tables, 'decisions': get_decisions(data, sec, tables),
                'fork_and_vendor_path_prefixes': get_fork_prefixes(data, sec)}
    files = {'functions.tsv': tsv_bytes(functions, ['role', 'start_va', 'end_va_exclusive', 'file_offset',
                                                   'fde_va', 'fde_file_offset', 'unwind_index', 'length', 'sha256']),
             'windows.tsv': tsv_bytes(windows, ['role', 'va', 'file_offset', 'length', 'bytes', 'sha256']),
             'path-evidence.json': json_bytes(metadata)}
    out.mkdir(parents=True, exist_ok=True)
    for name in sorted(files):
        (out / name).write_bytes(files[name])
    return {'files': sorted(files), 'functions': len(functions), 'windows': len(windows),
            'branch_and_reference_records': len(metadata['direct_edges_and_branches']),
            'jump_tables': len(tables), 'sha256': actual}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(generate(TARGET.read_bytes(), args.out), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, struct.error, UnicodeError) as error:
        print('node115_eth_call_path: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
