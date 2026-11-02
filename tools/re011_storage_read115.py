#!/usr/bin/env python3
"""Record a selected node-115 storage-read path from authenticated ELF bytes.

The selected offsets and byte patterns are static analysis witnesses, not a
full x86 decoder or an execution model. This collector executes no target
code and calls no external program.
"""
import argparse
import bisect
import csv
import hashlib
import io
import itertools
import json
from pathlib import Path
import struct

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

WINDOWS = [
    ('constructor_clone_and_refcount', 0x2cff6ad, '4c8b2ef049ff45000f8e9f000000'),
    ('constructor_descriptor_to_insertion', 0x2cff6de, 'bf18000000ff1597fd7d034885c074574983c408488b4c2418488948100f104424080f11004889442410488d0519107503488944241848c7442408000000004c8d4424084889df4c89e64c89fa4c89f1ff15642a7e03'),
    ('constructor_alloc_failure', 0x2cff745, '488d5c2418bf08000000be18000000ff1536fd7d030f0b'),
    ('handler_input_shape', 0x2d018ed, '48b901000000000000804939cf0f84fd0000004885c00f84f4000000488b8c248800000080397b0f85f1000000'),
    ('handler_object_decode', 0x2d01945, '488d7c2420488db42410010000e8c93807ff807c2420020f8536020000488b742428488dbc24a8000000e80cf40000'),
    ('handler_positional_empty', 0x2d019fd, '4939cf750931c0b901000000eb2f488b8c24880000004883f8027521488b9424880000000fb70a31c081f95b5d00000f95c0b901000000480f45ca01c048898c24900000004889842498000000488dbc24a0000000488db42490000000e891de0000'),
    ('handler_address_result', 0x2d01a5f, '4c8bb424a00000004983fe030f85e50700008b8424b8000000898424000200000f108424a80000000f298424f00100004c8bb42490000000488bac24980000004c8974241048896c2418'),
    ('handler_required_next', 0x2d01aa9, '4885ed0f84c5030000410fb60683f82c742b83f85b742683f85d0f85b601000048c78424900000000100000048c784249800000000000000e9910300004883fd01740b41807e01c00f8cbd0800004c8964240848ffcd49ffc6'),
    ('handler_index_value', 0x2d01b4e, '488dbc24a0000000488d742420e890a006ff440fb6a424a00000004180fc030f8556010000488b7424204885f64c8b6424080f84f1020000488b7c242831d2ff150dd97d03'),
    ('handler_missing_index_error', 0x2d01e77, 'bf0e000000ff15fed57d034885c00f841705000048b96520706172616d734889480648b94e6f206d6f72652048890848c74424200e000000488944242848c74424300e000000488d15dd4891fd488dbc24800100004c8d442420b90e000000bea680ffffe8a0b98cff'),
    ('handler_optional_block', 0x2d01ef2, '488b8424a801000048898424e00100000f108424880100000f108c24980100000f298c24d00100000f298424c0010000488d7c2420488db42490000000e8acd300004c8b7424204983fe04750540b502eb360fb66c24280f104424290f298424a00000000f104424390f298424b0000000488b44244848898424bf0000004183fe030f8578030000'),
    ('handler_input_to_adapter', 0x2d01faa, '48898424300100004883c310488d7c2420488d9424f0010000488d8c24c00100004c8d8424100100004889dee8d5d3d1ff4c8b7424204983fe037530'),
    ('handler_result32', 0x2d01fe6, '488d4424280f10000f1048100f298c24600100000f2984245001000040b50148b802000000000000804939c77c5ceb42'),
    ('handler_response_handoff', 0x2d02070, '48c7842420020000000000004c89b424300200004088ac24380200000f288424500100000f288c24600100000f118424390200000f118c2449020000488b442410488b4c2417488984245902000048898c2460020000488b8c2478010000488b411048898424b00000000f10010f298424a0000000488d7c2420488db424a0000000488d942420020000488b8c2418020000e809315dff0f10442438410f114518488b442430498945100fb6442450418845300f10442420410f1145004d896528'),
    ('handler_index_error_annotation', 0x2d021ee, '488d3db15c91fd488d15af5c91fd4c8d442420be05000000b90e0000004531c9ff159cff7d03'),
    ('handler_address_error_annotation', 0x2d0228a, '488d3d285c91fd488d15c45091fd4c8d442420be07000000b9070000004531c9ff1500ff7d03'),
    ('handler_block_error_annotation', 0x2d0232d, '488d3d4c7975fd488d15595b91fd4c8d442420be08000000b91200000041b901000000ff155afe7d03'),
    ('visitor_object_call_and_tail', 0x1d7525d, '66c74424500080488d742408e8b29d1d00803b027453488b442428488b4c24304839c17344488b54242048f7d848ffc148be0026000001000000660f1f8400000000000fb67c0aff4883ff20773b480fa3fe733548894c2430488d3c0848ffc748ffc14883ff0175da'),
    ('visitor_trailing_error', 0x1d752e6, '48c744245816000000488d7c2408488d742458e82201000048894308c60302'),
    ('field_container_choice', 0x1f4f04e, '49bd00260000010000000f1f8400000000000fb67402ff4883fe207735490fa3f5732f49894628488d340148ffc648ffc04883fe0175db48c744241005000000488d7424104c89f7e88563e2ffe9f30a000083fe5b747b83fe7b0f85270b0000'),
    ('field_array_address', 0x1f4f15d, '488d7c2410488db424e0000000e891f5e6ff807c2410010f841f010000807c2411010f85df060000488bb424e0000000488d7c2410e859e1a300807c2410010f84f7000000'),
    ('field_array_index', 0x1f4f1d8, '488d7c2410488db424e0000000e816f5e6ff807c2410010f84a4000000807c2411010f8590070000488bb424e0000000488d7c2410e80e7b71000fb64424108844240f3c02747a'),
    ('field_array_block', 0x1f4f256, '488d7c2410488db424e0000000e898f4e6ff807c241001742a807c2411010f8535090000488bb424e0000000488d7c2410e8649a35000fb64424103c030f8509060000'),
    ('field_name_lengths', 0x1f4f442, '488b4c242083fa014883f9050f84bc0000004883f90874464883f9070f85c4000000'),
    ('field_name_address', 0x1f4f464, '8b08ba6164647231d18b5003be7265737331f209ca0f84e0010000'),
    ('field_name_block_camel', 0x1f4f47f, '8b08ba626c6f6331d18b4003ba636b496431d009c80f858e000000eb13'),
    ('field_name_block_snake', 0x1f4f4a0, '48b9626c6f636b5f69644839087579807c240e030f854d070000'),
    ('field_name_index', 0x1f4f510, '8b08ba696e646531d10fb6400483f07809c80f84e4000000'),
    ('field_unknown_value', 0x1f4f570, '4883fe3a0f854d0600004885c00f84e9060000488945284889efe8d15fe2ff4885c00f8438feffffe9c0010000'),
    ('field_block_object_value', 0x1f4f5b0, '488945284c89e74889eee8319735000fb64424103c030f843cfbffff8844240e'),
    ('field_index_object_value', 0x1f4f6c9, '488945284c89e74889eee8487671000fb64424108844240f3c020f841ffaffff'),
    ('field_address_object_value', 0x1f4f73e, '488945284c89e74889eee8a3dba300807c2410010f8526fcffffe9abf9ffff'),
    ('field_duplicate_index', 0x1f4f60c, '807c240f020f8507060000'),
    ('field_duplicate_address', 0x1f4f65f, 'f6442470010f85cb050000'),
    ('field_missing_order', 0x1f4f773, 'f6442470010f84fb0100000fb66c240f4080fd020f841b020000807c240e037520c644240e02eb4f'),
    ('field_missing_address', 0x1f4f979, '488d05ff2e68fe488944244048c744244807000000eb2d'),
    ('field_missing_index', 0x1f4f9a8, '488d05993568fe488944244048c744244805000000'),
    ('field_duplicate_labels', 0x1f4fc07, '488d0572a050fe488944244048c744244808000000eb2c488d05233368fe488944244048c744244805000000eb15488d05432c68fe488944244048c744244807000000488d4424404889442410488d05f57f55004889442418488d3db3384efee96efdffff'),
    ('slot_value_parse', 0x2666d20, '4156534883ec484889fb4889e7e83e5d70ff0fb604243c167511488b44240848894308c60302e93a010000'),
    ('slot_first_variant', 0x2666d73, '4889e7488d742428e8a08bb6ff803c2401752a'),
    ('slot_first_value', 0x2666db0, '8b4424018b4c2404894b048943014c8b7424080fb64424208843200f104424100f11431031c0eb6a'),
    ('slot_second_variant', 0x2666df1, '4889e7488d742428e81290b6ff4c8b742408833c24017525'),
    ('slot_second_value', 0x2666e2e, '488b442420488943200f104424100f114310b00188034c897308eb31'),
    ('slot_no_variant_error', 0x2666e63, '488d3da1cef8fdbe3e000000e85cb47c0048894308c60302'),
    ('block_null_prefix', 0x22a8d5c, '4183f96e75714883f8010f84d6000000488d78ff48897e284839cf0f839f0000000fb67c02ff488946284080ff750f85a70000004839c80f8383000000488d7801440fb6040248897e284180f86c0f85870000004839cf73670fb64c02014883c0024889462880f96c7570c603024889d84883c4305bc3'),
    ('block_value_parse', 0x22a8dd3, '488d7c2408e8e3a44300807c2408027515488b44241048894308c603034889d84883c4305bc3'),
    ('error_invalid_params_code', 0x2d10e30, '84c07578488b44241848894424300f104424080f29442420488d15525990fd4c8d442420b90e0000004c89f7bea680ffffe81aca8bff'),
    ('adapter_tuple', 0x2a1f3c1, '4889fb4c8ba6d8030000498d442410488d357918a3fd4889b4248801000048c78424900100001000000048c7842480010000000000004d8dac24400100004889842460010000488994246801000048898c2470010000488d84248001000048898424780100004c89ac24c00000004180bc246001000000'),
    ('adapter_direct_path', 0x2a1f42f, '4180bc2460010000007456488d05aa55a1fd488984241001000048c784241801000016000000c7842420010000c601000049c7c680eeffff644c8b3c25000000004d01f764410fb6462083f801743f83f8027524488d3d6648a203ff151815ac03488d7c2430488db42460010000e8dea60100e92f070000'),
    ('adapter_reentry_comparison', 0x2a1f4bd, '48b8ffffffffffffff7f64498b0e4839c10f83ed0400004c89ac24b80000004c89bc24b000000048895c247848898c2400010000488d410164498906644d8b6e1064498b4618486bd8384885c00f84ad0000004d8bbc2458010000418bac2450010000498b84244001000048898424080100004d8ba424480100004531f6eb0c0f1f004983c6384c39f374744f397c351875f043396c351075e94f3964350875e24b8b7c3500488bb424080100004c89e2ff158404ac0385c075c8'),
    ('adapter_shared_result', 0x2a1fbb7, '488d7c2430488db42460010000e8b79f0100488dbc2480000000e83a2accff0f104424300f104c24400f114b180f11430848c70303000000'),
    ('read_context', 0x2a39b96, '4c8b36488b46084889442438488b5e10488b4618488b481048898c24d0000000660f1000660f298424c0000000410fb686200b000088442407'),
    ('read_guard_acquire', 0x2a39bdf, '498daea8060000498b86a806000089c183e108c1e9034883f8f00f93c208ca74124889ef31f6b900ca9a3bff15c873aa03eb0c488d4810f0480fb14d0075e2'),
    ('read_state_and_key_tag', 0x2a39ca0, '498bb6000b0000488b4c24388b411089442450660f1001660f29442440803b010f851d010000488b6c2408488b7b08488b5310488b4b18488b4320e924010000'),
    ('read_byte_key_conversion', 0x2a39de3, '488b6c2408488b4301488b4b09488b5311488b7b19480fcf480fca480fc9480fc84881c6781c000048897c2410488954241848894c24204889442428488d7c2460488d542440488d4c2410ff152cd2aa03'),
    ('read_result_to_big_endian', 0x2a39e34, '488b4c2460488b4424684c8b7c2470488b5c2478480fcb490fcf480fc84889442438480fc948c7c0f0ffffff'),
    ('read_guard_release', 0x2a39e60, '498dbea8060000f0480fc1074883e0f2c7842484000000000000004883f8124989ec4889cd4c8bac24900000000f842f030000'),
    ('read_return', 0x2a3a006, '49891c244d897c2408488b442438498944241049896c2418'),
    ('read_byte_key_conversion_timed', 0x2a3a030, '488b4301488b4b09488b5311488b7b19480fcf480fca480fc9480fc84881c6781c000048897c2410488954241848894c24204889442428488d7c2460488d542440488d4c2410ff15e4cfaa03'),
    ('read_timed_result_and_release', 0x2a3a18a, '488bac24a0000000480fcd488b442438480fc84889442438490fcf48c7c0f0fffffff0480fc107480fcb4883e0f24883f8120f85d1fcffffff15206eaa03'),
    ('read_account_query', 0x43c89ba, '4883c6208b4210894424100f10020f290424488d7c24304889e2e897ff97ff488b4424304883f8027539'),
    ('read_account_failure_cleanup', 0x43c89e4, '488b4424384883f8020f82e3000000488b7424400f84d0000000488b7c24484883f8034885f60f84c600000031d2ff15886a1102e9b9000000'),
    ('read_account_absent_and_storage_setup', 0x43c8a1d, '4885c00f84b00000004981c630120000418b44241089442460410f1004240f29442450410f1007410f104f100f294424300f294c24404889e7488d5424304c89f6e89dfc97ff'),
    ('read_storage_tags', 0x43c8a63, '488b04244883f802752a488b4424084883f802726f488b7424107460488b7c24184883f8034885f6745a31d2ff150b6a1102eb50'),
    ('read_storage_value_select', 0x43c8a97, '488d4c24080f10010f1049100f298c24900000000f29842480000000a80174300f288424800000000f288c24900000000f294c2440eb21'),
    ('read_zero_and_return', 0x43c8ace, '488b064889f7ff100f57c00f114310eb23488b064889f7ff100f57c00f294424400f294424300f284424300f284c24400f114b100f11034889d84881c4a80000005b415c415e415fc3'),
    ('storage_key_build_call', 0x3d48709, '4889fb4c8b7e184989e64c89f7e805f6ffff48c74424180000000048c74424200100000048c744242800000000488d7c2448ba020000004c89f6e8d8600500'),
    ('storage_backend_read', 0x3d4875e, '498b7740488d7c2430488d542448e8ef610100488b4424304889c148f7d97156837c243801756d'),
    ('storage_decode_call', 0x3d48785, '4c8b74244048c70424000000004889e64c89f7ff1512da7902488b14244889e74889c6e8d3f9ffff'),
    ('storage_wrap_decode_tag', 0x3d487ad, '488b04240f104424180f1143180f104424080f11430848ffc04889034c89f7ff15e6d97902eb25'),
    ('storage_wrap_error', 0x3d487d4, '0f1044243848c7430803000000488943100f11431848c70302000000eb07'),
    ('storage_wrap_absent', 0x3d487f2, '48c703000000004889d84883c4605b415e415fc3'),
    ('key_dynamic_prefix', 0x3d47d2e, '488b5e104885db790b31ff4889deff15567779024989d548895c240848897c2410742b4c8b66084889dfff15227779024885c00f8405010000488904244889c74c89e64889daff158e777902eb09b80100000048890424'),
    ('key_buffer_size_and_limbs', 0x3d47d85, '4d8b7d184d8b7510498b6d00498b5d08bf34000000ff15e07679024885c00f84b10000004989c4480fcd480fcb490fce490fcf418b45304189442410410f104520410f1104244d897c24144d8974241c49895c242449896c242c'),
    ('key_join_descriptors', 0x3d47ddf, '488b5c240848895c24184c8b3c244c897c242048895c242848c7442430340000004c8964243848c744244034000000488d742418ba020000004c8b7424104c89f7e8fb690500'),
    ('key_alloc_failure', 0x3d47e5a, 'bf01000000be34000000ff152e7679020f0bbf010000004889deff151e767902'),
    ('join_lengths_overflow', 0x3d9e82e, '4885d2743e4989f648c1e203488d1c5231f631c066666666662e0f1f84000000000049037406100f821e0100004883c0184839c375ec4885f6795631ffff15270c7402'),
    ('join_copy_next', 0x3d9e930, '4a8d3c284c89e64889ea4989c4ff15c50b74024c89e04901ed4c896c24184983c7184c39fb0f8436ffffff4f8b643e084b8b6c3e10488b4c24084c29e94839cd778e4885ed75b9ebcd'),
    ('backend_options_and_sentinel', 0x3d5e976, '49bc0000000000000080488b2a488b5a084c8b6a10ff150f7878024989c748894424704c896424404c896424584885c048895c24100f8485000000'),
    ('backend_read_and_error_pointer', 0x3d5e9b1, '48896c240848c7442420000000004c8d4424204c89f74c89fe4889da4c89e9ff158a857802488b6c24204885ed0f84ae0000004889efff15ab0c7802488d7c24284889ee4889c2ff15420c78024c8b6c2428'),
    ('backend_options_failure', 0x3d5ea36, 'bb98000000bf98000000ff153a0a78024885c00f840f0100004989c6488d35e9eca5fcba980000004889c7ff15a10a7802488b44241848c700980000004c89700848c7401098000000'),
    ('backend_present_or_absent', 0x3d5ea92, '4885c07448488b4c241848894110b801000000488b6c2408488b7c2410eb3f'),
    ('backend_absence_sentinel', 0x3d5eadf, '31c0488b6c2408488b7c2410488b4c24184889410848b800000000000000804889014885ed7535eb3e'),
    ('backend_error_output', 0x3d5eb13, '4889efff15bc357802488b4424184c89284c89700848895810'),
    ('value_decode_call', 0x3d48197, '4889742428488954243048897424384889542440c644244c00c64424480166c744244a20004c8da42480000000488d7424284c89e7ba01000000e8ba9c40ff83bc2480000000010f85ba000000'),
    ('value_empty_marker_check', 0x3151e9f, '0fb64620440fb64621c64620013c017563488b4e184885c9741f4c8b461048ffc9410fb60049ffc04c89461048894e1884c0780e4531c9eb56c6470800e906030000'),
    ('value_empty_parse_error', 0x31521e7, '488d050201310348894710e92d020000'),
    ('value_empty_parse_return', 0x3152424, '48c707010000004889f84881c4b00000005b415c415e415f5dc3'),
    ('value_error_dispatch', 0x3d48278, '0fb604244883f806774b488d0d2b47a7fc486304814801c8ffe0'),
    ('value_empty_error_cleanup', 0x3d48292, '488d7c2408e824fd0000eb2f'),
    ('value_decode_good', 0x3d4829e, '410f10442408410f104c24180f114b180f11430831c0eb24'),
    ('value_decode_bad', 0x3d482cd, '48c7430804000000b8010000004889034881c4a80000005b415c415e415f'),
    ('fixed_variant_dispatch', 0x21cf92b, '0fb606488d0d7f4c41fe486304814801c8ffe0'),
    ('fixed_variant_string', 0x21cf9b7, '488b4610488b5618eb08488b4608488b5610488d7c2430488d4c241041b8200000004889c6ff1566243104837c2430030f85ef000000'),
    ('fixed_variant_bytes_length', 0x21cfa03, '48837e18200f85f3000000488b4610eb0f48837e10200f85e2000000488b46080f10000f104810'),
    ('fixed_variant_success', 0x21cfa2a, '0f114b110f11430131c088034889d84881c4900000005bc3'),
    ('numeric_variant_dispatch', 0x21cfe1c, '0fb606488d0d3e4841fe486304814801c8ffe0'),
    ('numeric_variant_inputs', 0x21cfe5e, '4c8b76104c8b7e184983ff037416eb36488b4608eb634c8b76084c8b7e104983ff037522410fb706663305be1a43fe410fb64e02320db51a43fe0fb6c96609c10f84bf000000488d7c24104c89f64c89fae8fce48200837c2410010f85000100004c897424404c897c2448e9d00100008b4604'),
    ('numeric_variant_u64', 0x21cfed3, '0fb746020f57c00f11431048c74320000000004889430848c70300000000e991010000'),
    ('numeric_variant_special_zero', 0x21cff43, '0fb74c240c66330dfc1943fe3205f81943fe0fb6c06609c841be03000000753c0f57c00f1143100f110348c7432000000000e90d010000'),
    ('numeric_variant_parser_result', 0x21cff9f, '488d7c24104c8d7c240c4c89fe4c89f2e8fce38200837c2410010f84d50000000f104424180f104c24280f114b180f11430831c0488903e9ac000000'),
    ('radix_dispatch', 0x29fe3b0, '4883fa0277047408eb38807e02c07c324c8d4602488d42fe66813e3078742d66813e3058742666813e306f742f66813e304f742866813e3062743166813e3042742ab90a000000e964f7ffffb9100000004c89c64889c2e904f2ffffb9080000004c89c64889c2e9f4f1ffffb9020000004c89c64889c2e9e4f1ffff'),
    ('hex_parity_prefix_and_length', 0x167a9cb, 'f6c2010f85c10000004883fa017613803e30750e807e017875084883c6024883c2fe4889d048d1e84939c00f85a4000000'),
    ('hex_simd_constants', 0x167aa1a, '660f6f055eb3ddfe660f6f0df6afddfe660f6f158e8cddfe660f6f1d8690ddfe660f6f255ebcddfe'),
    ('hex_simd_classification', 0x167aa50, '4d39da7456f3420f6f2c1e660f6ff5660ffcf0660f6ffe660fdaf9660f74fe660fdbea660ffceb660f6ff5660fdaf4660f74f5660fdbf7660fd7ee4983c31085ed74bdeb3f'),
    ('hex_length_errors', 0x167aa95, 'c70701000000e949010000c70702000000e93e010000'),
    ('hex_scalar_table_and_validation', 0x167aaab, '4531d24c8d35572adffe66662e0f1f8400000000004d39d1741f460fb61c1049ffc243803c33ff75ec4889fbe864feffff4889d8e908010000'),
    ('hex_scalar_pair_decoder', 0x167ab30, '440fb64c16ff470fb60c3141c0e104440fb61416470a0c3244880c01440fb64c1601470fb60c3141c0e104440fb6541602470a0c3244884c01014883c0024883c2044839c375b9'),
    ('hex_success_tag', 0x167ab7d, '0fb61446420fb61432c0e2040fb6744601420a1436881401c70703000000eb4c'),
    ('power2_setup_and_empty', 0x29fd618, '0f57c00f294424100f2904244885d20f84570100004889c8f34c0fbcc141b9400000004d29c14801f24531d2'),
    ('power2_loop_bound', 0x29fd64b, '4d01c24839f20f842d0100004889d94981faff0000000f87d100000048ffca'),
    ('power2_digit_classification', 0x29fd670, '440fb61a418d5bd080fb0a7247418d6b9f4080fd1a7222418d6bbf4080fd1a72264180fb5f0f85fe0000004839f2488d52ff75cce9db000000418d5ba94038eb7312e907010000418d5bc94038eb0f82070100000fb6db4839d80f86c9000000'),
    ('power2_limb_insert', 0x29fd6d0, '4d89d349c1eb064489d183e13f4989de49d3e64e0934dc4c39c90f865bfffffff6d94989de49d3ee4981fac00000000f8241ffffff4d85f60f843dffffff48c7470800000000e992000000'),
    ('power2_high_digit_scan', 0x29fd71b, '4180fb5f75786666666666662e0f1f84000000000048ffca4839f2744c440fb65aff458d43d04180f80a7229458d4b9f4180f91a730b458d43a94538c87316eb62458d4bbf4180f91a73b5458d43c94538c8725c904138c073244584c0759431c948ffca4839f275b4'),
    ('power2_result_and_errors', 0x29fd784, '0f2804240f284c24100f114f180f11470831c0eb19410fb6c348c74708030000004889471048894f18b8010000004889074883c4205b415e5dc3'),
    ('decimal_digit_and_underscore', 0x29fdbd0, '4c39dd0f84f50000000fb67500448d76d04180fe0a723c448d669f4180fc1a7217448d66bf4180fc1a721b48ffc583fe5f74cde9e3000000448d76a94538e67312e9e1010000448d76c94538e60f82e1010000450fb6f64c39f10f86bb000000'),
    ('decimal_chunk_overflow', 0x29fdc64, '4889442420488b44240848f7e348895424184889c64c89d048f7e34989d74989c2488b44241048f7e34989d44989c04c89c848f7e3480374242048897424084c135424184d11f84c894424104989c14d11e14883d20048ffc54889ee4885d20f84eafeffffe9da000000'),
    ('decimal_final_success', 0x29fdd6d, '4c896708b92000000041b81800000041bb1000000031c04c89fe4c89ca4e89141f4a8934074889140f4889074883c4285b415c415d415e415f5dc3'),
    ('decimal_overflow_result', 0x29fdda8, 'b801000000b90800000031d2ebdc'),
    ('decimal_radix_chunk_setup', 0x29fdb6e, '4989d34889c8480fafc14531ed0f1f4400004983fd020f842c0200004889c349ffcd48f7e171eb4901f349f7dd'),
    ('decimal_digit_accumulate', 0x29fdc23, '450fb6f64c39f10f86bb00000048f7e10f80b10100004c01f00f829b0100004d89c449ffc40f8482010000488d750149ffc74c89f24d39c54d89e00f855effffff'),
    ('decimal_tail_power', 0x29fdd18, '4889c80f1f44000048f7e10f809a00000049ffcf75f24889c1'),
]

EDGES = [
    ('constructor_refcount_failure', 0x2cff6b5, '0f8e9f000000', 0x2cff75a, 'jcc'),
    ('constructor_allocation', 0x2cff6e3, 'ff1597fd7d03', 0x64df480, 'indirect'),
    ('constructor_no_memory', 0x2cff6ec, '7457', 0x2cff745, 'jcc'),
    ('constructor_insertion', 0x2cff72e, 'ff15642a7e03', 0x64e2198, 'indirect'),
    ('handler_object_visitor', 0x2d01952, 'e8c93807ff', 0x1d75220, 'call'),
    ('handler_object_error', 0x2d0195c, '0f8536020000', 0x2d01b98, 'jcc'),
    ('handler_param_error', 0x2d0196f, 'e80cf40000', 0x2d10d80, 'call'),
    ('handler_positional_address', 0x2d01a5a, 'e891de0000', 0x2d0f8f0, 'call'),
    ('handler_address_error', 0x2d01a6b, '0f85e5070000', 0x2d02256, 'jcc'),
    ('handler_missing_index', 0x2d01aac, '0f84c5030000', 0x2d01e77, 'jcc'),
    ('handler_index_bad_delimiter', 0x2d01ac3, '0f85b6010000', 0x2d01c7f, 'jcc'),
    ('handler_index_visitor', 0x2d01b5b, 'e890a006ff', 0x1d6bbf0, 'call'),
    ('handler_missing_parameter_error', 0x2d01edb, 'e8a0b98cff', 0x25cd880, 'call'),
    ('handler_block_parser_boundary', 0x2d01f2f, 'e8acd30000', 0x2d0f2e0, 'call'),
    ('handler_read_adapter', 0x2d01fd6, 'e8d5d3d1ff', 0x2a1f3b0, 'call'),
    ('handler_result_variant', 0x2d01fe4, '7530', 0x2d02016, 'jcc'),
    ('handler_output_boundary', 0x2d02102, 'e809315dff', 0x22d5210, 'call'),
    ('handler_index_error', 0x2d0220e, 'ff159cff7d03', 0x64e21b0, 'indirect'),
    ('handler_address_error', 0x2d022aa, 'ff1500ff7d03', 0x64e21b0, 'indirect'),
    ('handler_block_error', 0x2d02350, 'ff155afe7d03', 0x64e21b0, 'indirect'),
    ('visitor_fields', 0x1d75269, 'e8b29d1d00', 0x1f4f020, 'call'),
    ('visitor_trailing_error', 0x1d752af, '7335', 0x1d752e6, 'jcc'),
    ('visitor_error_builder', 0x1d752f9, 'e822010000', 0x1d75420, 'call'),
    ('field_array_entry', 0x1f4f0a3, '747b', 0x1f4f120, 'jcc'),
    ('field_reject_non_object', 0x1f4f0a8, '0f85270b0000', 0x1f4fbd5, 'jcc'),
    ('field_address_parser', 0x1f4f192, 'e859e1a300', 0x298d2f0, 'call'),
    ('field_index_parser', 0x1f4f20d, 'e80e7b7100', 0x2666d20, 'call'),
    ('field_block_parser', 0x1f4f287, 'e8649a3500', 0x22a8cf0, 'call'),
    ('field_recognize_address', 0x1f4f479, '0f84e0010000', 0x1f4f65f, 'jcc'),
    ('field_recognize_block_camel', 0x1f4f49a, 'eb13', 0x1f4f4af, 'jmp'),
    ('field_block_snake_mismatch', 0x1f4f4ad, '7579', 0x1f4f528, 'jcc'),
    ('field_duplicate_block', 0x1f4f4b4, '0f854d070000', 0x1f4fc07, 'jcc'),
    ('field_recognize_index', 0x1f4f522, '0f84e4000000', 0x1f4f60c, 'jcc'),
    ('field_unknown_skip_call', 0x1f4f58a, 'e8d15fe2ff', 0x1d75560, 'call'),
    ('field_unknown_value_done', 0x1f4f592, '0f8438feffff', 0x1f4f3d0, 'jcc'),
    ('field_object_block_call', 0x1f4f5ba, 'e831973500', 0x22a8cf0, 'call'),
    ('field_object_block_error', 0x1f4f5c6, '0f843cfbffff', 0x1f4f108, 'jcc'),
    ('field_object_index_call', 0x1f4f6d3, 'e848767100', 0x2666d20, 'call'),
    ('field_object_index_error', 0x1f4f6e3, '0f841ffaffff', 0x1f4f108, 'jcc'),
    ('field_object_address_call', 0x1f4f748, 'e8a3dba300', 0x298d2f0, 'call'),
    ('field_object_address_success', 0x1f4f752, '0f8526fcffff', 0x1f4f37e, 'jcc'),
    ('field_duplicate_index', 0x1f4f611, '0f8507060000', 0x1f4fc1e, 'jcc'),
    ('field_duplicate_address', 0x1f4f664, '0f85cb050000', 0x1f4fc35, 'jcc'),
    ('field_missing_address', 0x1f4f778, '0f84fb010000', 0x1f4f979, 'jcc'),
    ('field_missing_index', 0x1f4f787, '0f841b020000', 0x1f4f9a8, 'jcc'),
    ('field_block_default', 0x1f4f792, '7520', 0x1f4f7b4, 'jcc'),
    ('field_block_duplicate_text', 0x1f4fc1c, 'eb2c', 0x1f4fc4a, 'jmp'),
    ('field_index_duplicate_text', 0x1f4fc33, 'eb15', 0x1f4fc4a, 'jmp'),
    ('slot_parse', 0x2666d2d, 'e83e5d70ff', 0x1d6ca70, 'call'),
    ('slot_first_convert', 0x2666d7b, 'e8a08bb6ff', 0x21cf920, 'call'),
    ('slot_second_convert', 0x2666df9, 'e81290b6ff', 0x21cfe10, 'call'),
    ('slot_error_text', 0x2666e6f, 'e85cb47c00', 0x2e322d0, 'call'),
    ('block_non_null', 0x22a8d60, '7571', 0x22a8dd3, 'jcc'),
    ('block_non_null_parse', 0x22a8dd8, 'e8e3a44300', 0x26e32c0, 'call'),
    ('adapter_direct_branch', 0x2a1f438, '7456', 0x2a1f490, 'jcc'),
    ('adapter_direct_call', 0x2a1f49d, 'e8dea60100', 0x2a39b80, 'call'),
    ('adapter_slow_call', 0x2a1fbc4, 'e8b79f0100', 0x2a39b80, 'call'),
    ('read_guard_fast', 0x2a39bfe, '7412', 0x2a39c12, 'jcc'),
    ('read_guard_slow_acquire', 0x2a39c0a, 'ff15c873aa03', 0x64e0fd8, 'indirect'),
    ('read_guard_cas_mismatch', 0x2a39c1c, '75e2', 0x2a39c00, 'jcc'),
    ('read_key_variant', 0x2a39cc0, '0f851d010000', 0x2a39de3, 'jcc'),
    ('read_first_storage_call', 0x2a39e2e, 'ff152cd2aa03', 0x64e7060, 'indirect'),
    ('read_second_storage_call', 0x2a3a076, 'ff15e4cfaa03', 0x64e7060, 'indirect'),
    ('read_unlock_slow', 0x2a39e8d, '0f842f030000', 0x2a3a1c2, 'jcc'),
    ('read_guard_wake', 0x2a3a1c2, 'ff15206eaa03', 0x64e0fe8, 'indirect'),
    ('read_account_boundary', 0x43c89d4, 'e897ff97ff', 0x3d48970, 'call'),
    ('read_account_not_error', 0x43c89e2, '7539', 0x43c8a1d, 'jcc'),
    ('read_account_absent', 0x43c8a20, '0f84b0000000', 0x43c8ad6, 'jcc'),
    ('read_storage_lookup', 0x43c8a5e, 'e89dfc97ff', 0x3d48700, 'call'),
    ('read_storage_not_error', 0x43c8a6b, '752a', 0x43c8a97, 'jcc'),
    ('read_storage_none', 0x43c8ab5, '7430', 0x43c8ae7, 'jcc'),
    ('read_storage_present', 0x43c8acc, 'eb21', 0x43c8aef, 'jmp'),
    ('storage_key_builder', 0x3d48716, 'e805f6ffff', 0x3d47d20, 'call'),
    ('storage_key_merge', 0x3d48743, 'e8d8600500', 0x3d9e820, 'call'),
    ('storage_get', 0x3d4876c, 'e8ef610100', 0x3d5e960, 'call'),
    ('storage_get_error', 0x3d4877c, '7156', 0x3d487d4, 'jcc'),
    ('storage_no_value', 0x3d48783, '756d', 0x3d487f2, 'jcc'),
    ('storage_decode', 0x3d487a8, 'e8d3f9ffff', 0x3d48180, 'call'),
    ('storage_decoded_cleanup', 0x3d487cc, 'ff15e6d97902', 0x64e61b8, 'indirect'),
    ('key_concat', 0x3d47e20, 'e8fb690500', 0x3d9e820, 'call'),
    ('key_prefix_empty', 0x3d47d4f, '742b', 0x3d47d7c, 'jcc'),
    ('key_prefix_alloc_failure', 0x3d47d61, '0f8405010000', 0x3d47e6c, 'jcc'),
    ('key_prefix_copy', 0x3d47d74, 'ff158e777902', 0x64df508, 'indirect'),
    ('key_null_allocation', 0x3d47da3, '0f84b1000000', 0x3d47e5a, 'jcc'),
    ('join_length_carry', 0x3d9e855, '0f821e010000', 0x3d9e979, 'jcc'),
    ('join_copy', 0x3d9e93d, 'ff15c50b7402', 0x64df508, 'indirect'),
    ('backend_options_create', 0x3d5e98b, 'ff150f787802', 0x64e61a0, 'indirect'),
    ('backend_options_missing', 0x3d5e9ab, '0f8485000000', 0x3d5ea36, 'jcc'),
    ('backend_get', 0x3d5e9d0, 'ff158a857802', 0x64e6f60, 'indirect'),
    ('backend_no_error', 0x3d5e9de, '0f84ae000000', 0x3d5ea92, 'jcc'),
    ('backend_value_absent', 0x3d5ea95, '7448', 0x3d5eadf, 'jcc'),
    ('backend_error_string', 0x3d5e9e7, 'ff15ab0c7802', 0x64df698, 'indirect'),
    ('backend_options_destroy', 0x3d5eb49, 'ff1539707802', 0x64e5b88, 'indirect'),
    ('value_decode', 0x3d481d1, 'e8ba9c40ff', 0x3151e90, 'call'),
    ('value_decode_ok', 0x3d481de, '0f85ba000000', 0x3d4829e, 'jcc'),
    ('value_marker_other', 0x3151eae, '7563', 0x3151f13, 'jcc'),
    ('value_empty_input', 0x3151eb7, '741f', 0x3151ed8, 'jcc'),
    ('value_empty_error', 0x3151edc, 'e906030000', 0x31521e7, 'jmp'),
    ('value_empty_error_return', 0x31521f2, 'e92d020000', 0x3152424, 'jmp'),
    ('value_error_kind_outside_table', 0x3d48280, '774b', 0x3d482cd, 'jcc'),
    ('value_empty_cleanup_call', 0x3d48297, 'e824fd0000', 0x3d57fc0, 'call'),
    ('value_empty_cleanup_to_error', 0x3d4829c, 'eb2f', 0x3d482cd, 'jmp'),
    ('value_bad_done', 0x3d482b4, 'eb24', 0x3d482da, 'jmp'),
    ('fixed_variant_hex_decoder', 0x21cf9dc, 'ff1566243104', 0x64e1e48, 'indirect'),
    ('fixed_variant_hex_error', 0x21cf9e7, '0f85ef000000', 0x21cfadc, 'jcc'),
    ('fixed_variant_length16', 0x21cfa08, '0f85f3000000', 0x21cfb01, 'jcc'),
    ('fixed_variant_length8', 0x21cfa19, '0f85e2000000', 0x21cfb01, 'jcc'),
    ('numeric_variant_special_zero', 0x21cfe9e, '0f84bf000000', 0x21cff63, 'jcc'),
    ('numeric_variant_radix_dispatch', 0x21cfeaf, 'e8fce48200', 0x29fe3b0, 'call'),
    ('numeric_variant_parse_success', 0x21cfeb9, '0f8500010000', 0x21cffbf, 'jcc'),
    ('numeric_variant_fallback_dispatch', 0x21cffaf, 'e8fce38200', 0x29fe3b0, 'call'),
    ('radix_length_greater', 0x29fe3b4, '7704', 0x29fe3ba, 'jcc'),
    ('radix_length_equal', 0x29fe3b6, '7408', 0x29fe3c0, 'jcc'),
    ('radix_short_decimal', 0x29fe3b8, 'eb38', 0x29fe3f2, 'jmp'),
    ('radix_utf8_boundary', 0x29fe3be, '7c32', 0x29fe3f2, 'jcc'),
    ('radix_hex_lower', 0x29fe3cd, '742d', 0x29fe3fc, 'jcc'),
    ('radix_hex_upper', 0x29fe3d4, '7426', 0x29fe3fc, 'jcc'),
    ('radix_oct_lower', 0x29fe3db, '742f', 0x29fe40c, 'jcc'),
    ('radix_oct_upper', 0x29fe3e2, '7428', 0x29fe40c, 'jcc'),
    ('radix_bin_lower', 0x29fe3e9, '7431', 0x29fe41c, 'jcc'),
    ('radix_bin_upper', 0x29fe3f0, '742a', 0x29fe41c, 'jcc'),
    ('radix_decimal_helper', 0x29fe3f7, 'e964f7ffff', 0x29fdb60, 'jmp'),
    ('radix_hex_helper', 0x29fe407, 'e904f2ffff', 0x29fd610, 'jmp'),
    ('radix_oct_helper', 0x29fe417, 'e9f4f1ffff', 0x29fd610, 'jmp'),
    ('radix_bin_helper', 0x29fe427, 'e9e4f1ffff', 0x29fd610, 'jmp'),
    ('hex_odd_length', 0x167a9ce, '0f85c1000000', 0x167aa95, 'jcc'),
    ('hex_not_lower_prefix', 0x167a9e3, '7508', 0x167a9ed, 'jcc'),
    ('hex_decoded_length', 0x167a9f6, '0f85a4000000', 0x167aaa0, 'jcc'),
    ('hex_simd_invalid', 0x167aa91, '74bd', 0x167aa50, 'jcc'),
    ('hex_scalar_invalid', 0x167aad2, '75ec', 0x167aac0, 'jcc'),
    ('hex_pair_loop', 0x167ab75, '75b9', 0x167ab30, 'jcc'),
    ('power2_empty', 0x29fd627, '0f8457010000', 0x29fd784, 'jcc'),
    ('power2_out_of_bits', 0x29fd661, '0f87d1000000', 0x29fd738, 'jcc'),
    ('power2_underscore', 0x29fd695, '0f85fe000000', 0x29fd799, 'jcc'),
    ('power2_digit_outside_base', 0x29fd6ca, '0f86c9000000', 0x29fd799, 'jcc'),
    ('power2_no_cross_limb', 0x29fd6ea, '0f865bffffff', 0x29fd64b, 'jcc'),
    ('power2_high_spill', 0x29fd6ff, '0f8241ffffff', 0x29fd646, 'jcc'),
    ('power2_spill_zero', 0x29fd708, '0f843dffffff', 0x29fd64b, 'jcc'),
    ('power2_high_underscore', 0x29fd71f, '7578', 0x29fd799, 'jcc'),
    ('power2_high_nonzero', 0x29fd778, '7594', 0x29fd70e, 'jcc'),
    ('decimal_underscore', 0x29fdc01, '74cd', 0x29fdbd0, 'jcc'),
    ('decimal_digit_outside_base', 0x29fdc2a, '0f86bb000000', 0x29fdceb, 'jcc'),
    ('decimal_chunk_overflow', 0x29fdcc3, '0f84eafeffff', 0x29fdbb3, 'jcc'),
    ('decimal_final_overflow', 0x29fdd6b, '753b', 0x29fdda8, 'jcc'),
    ('decimal_chunk_64bit_overflow', 0x29fdc33, '0f80b1010000', 0x29fddea, 'jcc'),
    ('decimal_chunk_add_overflow', 0x29fdc3c, '0f829b010000', 0x29fdddd, 'jcc'),
    ('decimal_chunk_boundary', 0x29fdc5e, '0f855effffff', 0x29fdbc2, 'jcc'),
    ('decimal_tail_no_digits', 0x29fdcd1, '7439', 0x29fdd0c, 'jcc'),
    ('decimal_tail_multiply_overflow', 0x29fdd23, '0f809a000000', 0x29fddc3, 'jcc'),
]

# RELA expectations are independent witnesses for descriptor and indirect-call
# targets. Values are checked, then the output is decoded from the ELF records.
RELATIVE = {
    0x6450728: 0x2dd6d00,
    0x6450740: 0x2dd60f0,
    0x6450748: 0x2d018b0,
    0x6450750: 0x2d018b0,
    0x64df480: 0x6355830,
    0x64df4a0: 0x635de30,
    0x64e0fd8: 0x5bb1a60,
    0x64e0fe8: 0x5bb2110,
    0x64e1e48: 0x167a9c0,
    0x64e2198: 0x2f1bce0,
    0x64e21b0: 0x2f1dfe0,
    0x64e5b88: 0x5d34d20,
    0x64e61a0: 0x5d34c90,
    0x64e61b8: 0x5d35010,
    0x64e6f60: 0x5d34e40,
    0x64e7060: 0x43c89a0,
}
IMPORTS = {0x64df508: 'memcpy', 0x64df698: 'strlen'}
LITERALS = [
    ('method', 0x450c50, b'eth_getStorageAt'),
    ('address', 0x5d287f, b'address'),
    ('index', 0x5d2f48, b'index'),
    ('block_id', 0x459c80, b'block_id'),
    ('index_annotation', 0x617ea6, b'index'),
    ('address_annotation', 0x617eb9, b'address'),
    ('address_annotation_type', 0x61735c, b'Address'),
    ('block_annotation_type', 0x617e94, b'Option < BlockId >'),
    ('index_type', 0x617eab, b'JsonStorageKey'),
    ('invalid_params', 0x6167a1, b'Invalid params'),
    ('untagged_error', 0x5f3d0b,
     b'data did not match any variant of untagged enum JsonStorageKey'),
    ('read_options_error', 0x7bd742,
     b'Unable to create RocksDB read options. This is a fairly trivial call, '
     b'and its failure may be indicative of a mis-compiled or mis-loaded RocksDB library.'),
    ('zero_quantity', 0x60194b, b'0x0'),
    ('example_prefix', 0x7bd525, b'Es'),
]

DATA_REFS = [
    ('constructor_descriptor', 0x2cff708, '488d0519107503', 0x6450728, 48),
    ('adapter_method', 0x2a1f3d0, '488d357918a3fd', 0x450c50, 16),
    ('missing_invalid_params', 0x2d01ebd, '488d15dd4891fd', 0x6167a1, 14),
    ('missing_address_label', 0x1f4f979, '488d05ff2e68fe', 0x5d287f, 7),
    ('missing_index_label', 0x1f4f9a8, '488d05993568fe', 0x5d2f48, 5),
    ('index_annotation', 0x2d021ee, '488d3db15c91fd', 0x617ea6, 5),
    ('index_annotation_type', 0x2d021f5, '488d15af5c91fd', 0x617eab, 14),
    ('address_annotation', 0x2d0228a, '488d3d285c91fd', 0x617eb9, 7),
    ('address_annotation_type', 0x2d02291, '488d15c45091fd', 0x61735c, 7),
    ('block_annotation', 0x2d0232d, '488d3d4c7975fd', 0x459c80, 8),
    ('block_annotation_type', 0x2d02334, '488d15595b91fd', 0x617e94, 18),
    ('untagged_error', 0x2666e63, '488d3da1cef8fd', 0x5f3d0b, 62),
    ('read_options_error', 0x3d5ea52, '488d35e9eca5fc', 0x7bd742, 152),
]


class EvidenceError(ValueError):
    """The authenticated image does not match this selected evidence."""


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


def authenticate(data):
    digest = hashlib.sha256(data).hexdigest()
    require(digest == SHA256, 'node 115 digest mismatch')
    return digest


def named_section(secs, name):
    matches = [s for s in secs if s['name'] == name]
    require(len(matches) == 1 and matches[0]['type'] != 8,
            'missing, duplicate or NOBITS section: ' + name)
    return matches[0]


def va_offset(secs, va, size, executable=False):
    require(isinstance(va, int) and isinstance(size, int) and va >= 0 and size > 0,
            'invalid address or size')
    matches = [s for s in secs if s['type'] != 8 and s['flags'] & 2
               and s['address'] <= va and va + size <= s['address'] + s['size']
               and (not executable or s['flags'] & 4)]
    require(len(matches) == 1, 'address lacks one file-backed section')
    s = matches[0]
    return s['offset'] + va - s['address']


def parse_edge(va, raw):
    """Decode only selected rel8/rel32 and RIP-relative call encodings."""
    require(len(raw) >= 2, 'truncated transfer')
    if raw[0] in (0xe8, 0xe9):
        n, pos, fmt = 5, 1, '<i'
        kind = 'call' if raw[0] == 0xe8 else 'jmp'
    elif raw[0] == 0xeb or 0x70 <= raw[0] <= 0x7f:
        n, pos, fmt = 2, 1, '<b'
        kind = 'jmp' if raw[0] == 0xeb else 'jcc'
    elif raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        n, pos, fmt, kind = 6, 2, '<i', 'jcc'
    elif raw[:2] == b'\xff\x15':
        n, pos, fmt, kind = 6, 2, '<i', 'indirect'
    else:
        raise EvidenceError('unsupported transfer opcode')
    require(len(raw) == n, 'transfer length mismatch')
    return kind, va + n + struct.unpack_from(fmt, raw, pos)[0]


def check_window(image, record):
    label, va, expected = record
    raw = bytes.fromhex(expected)
    require(image.read(va, len(raw), executable=True) == raw,
            'changed selected byte window: ' + label)
    return raw


def check_edge(image, record):
    label, va, expected, destination, expected_kind = record
    raw = image.read(va, len(bytes.fromhex(expected)), executable=True)
    require(raw.hex() == expected, 'changed transfer bytes: ' + label)
    kind, target = parse_edge(va, raw)
    require((kind, target) == (expected_kind, destination),
            'changed transfer destination: ' + label)
    if kind == 'jcc':
        require(image.owner(va)['start'] == image.owner(target)['start'],
                'conditional target escaped selected FDE')
    return kind, target


def check_data_ref(image, record):
    """Decode selected RIP-relative LEAs, not arbitrary x86 instructions."""
    label, va, expected, destination, size = record
    raw = image.read(va, len(bytes.fromhex(expected)), executable=True)
    require(raw.hex() == expected, 'changed data reference: ' + label)
    require(len(raw) == 7 and raw[:2] == b'\x48\x8d'
            and raw[2] in (0x05, 0x15, 0x35, 0x3d), 'unsupported data reference')
    target = va + len(raw) + struct.unpack_from('<i', raw, 3)[0]
    require(target == destination, 'changed data reference target: ' + label)
    return target, image.read(target, size)


def check_literal(image, record):
    label, va, literal = record
    require(image.read(va, len(literal)) == literal, 'literal mismatch: ' + label)


class Image:
    def __init__(self, data):
        authenticate(data)
        self.data = data
        self.secs = sections(data)
        for name in ('.text', '.eh_frame', '.eh_frame_hdr', '.rela.dyn', '.dynsym', '.dynstr'):
            named_section(self.secs, name)
        _, entries = unwind_index(data)
        cies, fdes = eh_frame_records(data, self.secs)
        self.cies = cies
        self.fdes = sorted(fdes, key=lambda x: (x['start'], x['end'], x['fde']))
        self.starts = [f['start'] for f in self.fdes]
        require(len(self.starts) == len(set(self.starts)), 'duplicate FDE start')
        self.index = {e['start']: e for e in entries}
        require(len(self.index) == len(entries), 'duplicate unwind index start')
        self._relocs = None

    def read(self, va, n, executable=False):
        offset = va_offset(self.secs, va, n, executable)
        require(offset + n <= len(self.data), 'mapped range outside input')
        return bytes(self.data[offset:offset + n])

    def offset(self, va, n=1, executable=False):
        return va_offset(self.secs, va, n, executable)

    def owner(self, va, size=1):
        pos = bisect.bisect_right(self.starts, va) - 1
        require(pos >= 0, 'address has no FDE')
        f = self.fdes[pos]
        require(f['start'] <= va and va + size <= f['end'], 'address outside FDE')
        require(f['start'] in self.index and self.index[f['start']]['fde'] == f['fde'],
                'FDE not matched by unwind index')
        return f

    def relocations(self):
        if self._relocs is not None:
            return self._relocs
        section = named_section(self.secs, '.rela.dyn')
        require(section['size'] % 24 == 0, 'truncated RELA table')
        wanted = set(RELATIVE) | set(IMPORTS)
        records = {}
        for off in range(section['offset'], section['offset'] + section['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', self.data, off)
            if slot not in wanted:
                continue
            require(slot not in records, 'duplicate selected relocation')
            records[slot] = {'slot': slot, 'kind': info & 0xffffffff,
                             'symbol_index': info >> 32, 'addend': addend,
                             'file_offset': off}
        require(set(records) == wanted, 'missing selected relocation')
        sym = named_section(self.secs, '.dynsym')
        strings = named_section(self.secs, '.dynstr')
        require(sym['size'] % 24 == 0, 'truncated dynamic symbols')
        for slot, row in records.items():
            require(self.read(slot, 8) == bytes(8), 'relocation slot has unexpected file bytes')
            if slot in RELATIVE:
                require(row['kind'] == 8 and row['symbol_index'] == 0
                        and row['addend'] == RELATIVE[slot], 'relative relocation changed')
                row['symbol'] = ''
            else:
                index = row['symbol_index']
                require(row['kind'] == 6 and row['addend'] == 0
                        and index * 24 + 24 <= sym['size'], 'import relocation changed')
                nameoff = struct.unpack_from('<I', self.data, sym['offset'] + index * 24)[0]
                require(nameoff < strings['size'], 'symbol name outside table')
                start = strings['offset'] + nameoff
                end = self.data.find(b'\0', start, strings['offset'] + strings['size'])
                require(end >= 0, 'unterminated symbol')
                name = bytes(self.data[start:end]).decode('ascii')
                require(name == IMPORTS[slot], 'import symbol changed')
                row['symbol'] = name
        self._relocs = records
        return records


def field_names(image):
    """Read field constants from the immediate operands of the visitor."""
    address = image.read(0x1f4f467, 4) + image.read(0x1f4f471, 4)[1:]
    camel = image.read(0x1f4f482, 4) + image.read(0x1f4f48c, 4)[1:]
    snake = image.read(0x1f4f4a2, 8)
    index = image.read(0x1f4f513, 4) + image.read(0x1f4f51f, 1)
    require((address, index, camel, snake) == (b'address', b'index', b'blockId', b'block_id'),
            'field immediate mismatch')
    return address, index, camel, snake


def missing_parameter(image):
    """Recover the selected allocation size, overlapping stores and code."""
    allocation = image.read(0x2d01e77, 5, executable=True)
    first = image.read(0x2d01e8b, 10, executable=True)
    first_store = image.read(0x2d01e95, 4, executable=True)
    second = image.read(0x2d01e99, 10, executable=True)
    second_store = image.read(0x2d01ea3, 3, executable=True)
    error_code = image.read(0x2d01ed6, 5, executable=True)
    require(all((allocation[:1] == b'\xbf', first[:2] == b'\x48\xb9',
                 first_store[:3] == b'\x48\x89\x48', second[:2] == b'\x48\xb9',
                 second_store == b'\x48\x89\x08', error_code[:1] == b'\xbe')),
            'missing-parameter store encoding changed')
    size = struct.unpack_from('<I', allocation, 1)[0]
    offset = first_store[3]
    require(size == 14 and offset + 8 == size, 'missing-parameter size changed')
    require(first[2:4] == second[-2:], 'overlapping parameter stores disagree')
    detail = bytearray(size)
    detail[offset:offset + 8] = first[2:]
    detail[:8] = second[2:]
    code = struct.unpack_from('<i', error_code, 1)[0]
    require((bytes(detail), code) == (b'No more params', -32602),
            'missing-parameter detail changed')
    return size, offset, first[2:], second[2:], bytes(detail), code


def classify_field(key, names):
    """Model only the exact length and little-endian byte comparisons."""
    require(isinstance(key, bytes), 'field must be bytes')
    address, index, camel, snake = names
    if len(key) == len(index) and key[:4] == index[:4] and key[4] == index[4]:
        return 'index'
    if len(key) == len(snake) and key == snake:
        return 'block'
    if len(key) == len(address):
        if key[:4] == address[:4] and key[3:7] == address[3:7]:
            return 'address'
        if key[:4] == camel[:4] and key[3:7] == camel[3:7]:
            return 'block'
    return 'other'


def named_flow(keys, names):
    """Synthetic object-field flow after each supplied value parses normally."""
    seen = set()
    for key in keys:
        field = classify_field(key, names)
        if field != 'other':
            if field in seen:
                return 'duplicate_' + field
            seen.add(field)
    if 'address' not in seen:
        return 'missing_address'
    if 'index' not in seen:
        return 'missing_index'
    return 'complete_block_given' if 'block' in seen else 'complete_block_absent'


def layout(image):
    # The 52-byte allocation and 16-byte offset of the following 4-byte copy
    # are immediates of the selected key-building instructions.
    size = struct.unpack('<I', image.read(0x3d47d96, 4))[0]
    address_size = image.read(0x3d47dc0, 1)[0] + struct.calcsize('<I')
    require((size, address_size, size - address_size) == (52, 20, 32),
            'selected key dimensions changed')
    descriptor_offset = struct.unpack('<I', image.read(0x43c8a29, 4))[0]
    require(descriptor_offset == 0x1230, 'storage descriptor offset changed')
    return {'composite_bytes': size, 'address_bytes': address_size,
            'slot_bytes': size - address_size, 'storage_descriptor_offset': descriptor_offset}


def guard_constants(image):
    """Read the local fast-acquire and release immediates from code bytes."""
    read = lambda va, n: image.read(va, n, executable=True)
    offset = struct.unpack('<I', read(0x2a39be2, 4))[0]
    gate = read(0x2a39bf1, 1)[0]
    signed_bound = struct.unpack('<b', read(0x2a39bf8, 1))[0]
    delta = read(0x2a39c15, 1)[0]
    release_delta = struct.unpack('<i', read(0x2a39e5c, 4))[0]
    signed_mask = struct.unpack('<b', read(0x2a39e6f, 1))[0]
    release_test = read(0x2a39e7e, 1)[0]
    require((offset, gate, signed_bound, delta, release_delta, signed_mask, release_test)
            == (0x6a8, 8, -16, 16, -16, -14, 18), 'guard constants changed')
    return offset, gate, signed_bound % (1 << 64), delta, release_delta, signed_mask % (1 << 64), release_test


def guard_acquire(old, cas_matches, constants):
    """Model only the selected fast gate and comparison-exchange outcome."""
    require(isinstance(old, int) and 0 <= old < 1 << 64 and isinstance(cas_matches, bool),
            'invalid guard input')
    _, gate, bound, delta, _, _, _ = constants
    if old & gate or old >= bound:
        return 'slow_gate', None
    if not cas_matches:
        return 'slow_cas_mismatch', None
    return 'fast', old + delta


def guard_release(old, constants):
    """Model the selected xadd and subsequent wake-helper condition."""
    require(isinstance(old, int) and 0 <= old < 1 << 64, 'invalid guard input')
    _, _, _, _, release_delta, mask, test = constants
    return (old + release_delta) % (1 << 64), bool(old & mask == test)


def key_suffix(address, limbs, sizes):
    """Model the selected 20-byte copy and four reversed, byte-swapped words."""
    require(isinstance(address, bytes) and len(address) == sizes['address_bytes'],
            'address size mismatch')
    require(len(limbs) * 8 == sizes['slot_bytes'], 'limb count mismatch')
    require(all(isinstance(n, int) and 0 <= n < 1 << 64 for n in limbs),
            'limb out of unsigned 64-bit range')
    return address + b''.join(n.to_bytes(8, 'big') for n in reversed(limbs))


def index_limbs(tag, payload):
    """Two selected 32-byte representation arms in the guarded reader."""
    require(tag in (0, 1), 'only the two selected tags are modeled')
    require(isinstance(payload, bytes) and len(payload) == 32, 'slot payload size mismatch')
    if tag == 1:
        return tuple(int.from_bytes(payload[i:i + 8], 'little') for i in range(0, 32, 8))
    integer = int.from_bytes(payload, 'big')
    return tuple((integer >> (64 * i)) & ((1 << 64) - 1) for i in range(4))


def result_word(account_tag, storage_tag, raw):
    """Model the reader only for the observed tags 0, 1 and 2."""
    require(account_tag in (0, 1, 2) and storage_tag in (0, 1, 2), 'unknown result tag')
    require(isinstance(raw, bytes) and len(raw) == 32, 'storage value size mismatch')
    value = raw if account_tag == 1 and storage_tag == 1 else bytes(32)
    return value[::-1]


TABLES = [
    ('fixed_variant', 0x5e45b4, 22, 0x21cf920, 0x21cfc04,
     'd4224e77eecb91ecbf403894b97f6e43f560fadfc55591b2f3eddf8f01ad9e57'),
    ('numeric_variant', 0x5e4664, 22, 0x21cfe10, 0x21d00c8,
     '11d7355e54b67c3b3ef62a99db66ce8089d89c1fe6870e804ef2c3b74a8093d1'),
    ('value_error_kind', 0x7bc9b4, 7, 0x3d48180, 0x3d48321,
     'f208caeae0acdeb9775b4e4ee00c0ca48e06a20ddcc5cd48b79e92d55cf14b91'),
]
NIBBLE_TABLE = 0x46d50c
NIBBLE_HASH = '21244f82b210125632917591768f6bf22eb6861f80c6c25a25bd26dfb580ea7b'
SIMD_CONSTANTS = (0x455d80, 0x455a20, 0x4536c0, 0x453ac0, 0x4566a0)


def jump_tables(image):
    """Decode the explicitly selected table prefixes, without a census claim."""
    out = []
    for label, base, count, lower, upper, digest in TABLES:
        raw = image.read(base, count * 4)
        require(hashlib.sha256(raw).hexdigest() == digest, 'dispatch table changed')
        for index in range(count):
            delta = struct.unpack_from('<i', raw, index * 4)[0]
            target = base + delta
            require(lower <= target < upper, 'dispatch target escaped selected FDE')
            require(image.owner(target)['start'] == lower, 'dispatch target FDE mismatch')
            out.append([label, index, hx(base + index * 4),
                        hx(image.offset(base + index * 4, 4)), raw[index * 4:index * 4 + 4].hex(),
                        delta, hx(target)])
    return out


def empty_value_witness(image):
    """Extract the selected empty-buffer error tags and kind-zero arm."""
    read = lambda va, n: image.read(va, n, executable=True)
    require(read(0x3d481b0, 5) == b'\xc6\x44\x24\x48\x01', 'decoder marker changed')
    require(read(0x3151ed8, 4) == b'\xc6\x47\x08\x00', 'empty error kind changed')
    require(read(0x3152424, 7) == b'\x48\xc7\x07\x01\x00\x00\x00', 'parser error tag changed')
    require(read(0x3d482cd, 13) == b'\x48\xc7\x43\x08\x04\x00\x00\x00\xb8\x01\x00\x00\x00',
            'wrapper error tag changed')
    require(read(0x3d487c3, 3) == b'\x48\xff\xc0', 'storage tag increment changed')
    base = 0x7bc9b4
    cleanup = base + struct.unpack('<i', image.read(base, 4))[0]
    require(cleanup == 0x3d48292, 'empty error cleanup arm changed')
    marker = read(0x3d481b4, 1)[0]
    error_kind = read(0x3151edb, 1)[0]
    parse_tag = struct.unpack('<I', read(0x3152427, 4))[0]
    payload = struct.unpack('<I', read(0x3d482d1, 4))[0]
    wrapper_tag = struct.unpack('<I', read(0x3d482d6, 4))[0]
    return marker, error_kind, parse_tag, cleanup, wrapper_tag, payload, wrapper_tag + 1


def nibble_table(image):
    table = image.read(NIBBLE_TABLE, 256)
    require(hashlib.sha256(table).hexdigest() == NIBBLE_HASH, 'hex lookup table changed')
    require(all(value == 255 or 0 <= value <= 15 for value in table), 'invalid nibble table')
    return table


def simd_constants(image):
    values = [image.read(va, 16) for va in SIMD_CONSTANTS]
    # These five bytes are taken from every repeated lane of the ELF constants.
    require(all(len(set(row)) == 1 for row in values), 'nonuniform SIMD constant')
    constants = tuple(row[0] for row in values)
    require(constants == (0xc6, 0xf5, 0xdf, 0xb9, 0xf9), 'SIMD constant changed')
    return constants


def hex_invalid_simd(byte, constants):
    require(isinstance(byte, int) and 0 <= byte < 256, 'invalid byte')
    c0, c1, c2, c3, c4 = constants
    return ((byte + c0) & 255) <= c1 and (((byte & c2) + c3) & 255) <= c4


def fixed_hex(data, table, expected_size):
    """Model only the length gates and selected scalar byte table."""
    require(isinstance(data, bytes) and len(table) == 256 and expected_size >= 0,
            'bad fixed-hex input')
    if len(data) & 1:
        return 'odd_length', b''
    if data.startswith(b'0x'):
        data = data[2:]
    if len(data) // 2 != expected_size:
        return 'wrong_length', b''
    if any(table[value] == 255 for value in data):
        return 'invalid_character', b''
    return 'ok', bytes((table[data[i]] << 4) | table[data[i + 1]]
                       for i in range(0, len(data), 2))


def radix_prefixes(image):
    """Return only prefix comparisons and base immediates from the dispatcher."""
    pairs = []
    for va, base_va in ((0x29fe3cb, 0x29fe3fd), (0x29fe3d2, 0x29fe3fd),
                        (0x29fe3d9, 0x29fe40d), (0x29fe3e0, 0x29fe40d),
                        (0x29fe3e7, 0x29fe41d), (0x29fe3ee, 0x29fe41d)):
        pairs.append((image.read(va, 2), struct.unpack('<I', image.read(base_va, 4))[0]))
    result = dict(pairs)
    require(result == {b'0x': 16, b'0X': 16, b'0o': 8, b'0O': 8,
                       b'0b': 2, b'0B': 2}, 'numeric radix dispatch changed')
    return result


def radix_route(data, prefixes):
    """Model the selected prefix dispatcher, not its numeric parsing callees."""
    require(isinstance(data, bytes), 'numeric input must be bytes')
    if len(data) < 2 or (len(data) > 2 and 0x80 <= data[2] <= 0xbf):
        return 10, data
    base = prefixes.get(data[:2])
    return (10, data) if base is None else (base, data[2:])


def power2_parse(digits, base, bits):
    """Model the selected reverse digit walk for bases 2, 8 and 16.

    This returns a category and an integer; it does not emulate the error
    object's payload or the separate decimal parser.
    """
    require(isinstance(digits, bytes) and base in (2, 8, 16) and bits == 256,
            'unsupported power-of-two parser input')
    stride = {2: 1, 8: 3, 16: 4}[base]
    value = 0
    bitpos = 0
    for byte in reversed(digits):
        if byte == 0x5f:
            continue
        if 0x30 <= byte <= 0x39:
            digit = byte - 0x30
        elif 0x61 <= byte <= 0x7a:
            digit = byte - 0x61 + 10
        elif 0x41 <= byte <= 0x5a:
            digit = byte - 0x41 + 10
        else:
            return 'invalid_digit', 0
        if digit >= base:
            return 'invalid_digit', 0
        if bitpos >= bits:
            if digit:
                return 'overflow', 0
            bitpos += stride
            continue
        shifted = digit << bitpos
        if shifted >= 1 << bits:
            return 'overflow', 0
        value |= shifted
        bitpos += stride
    return 'ok', value


def decimal_chunk_width(image):
    base = struct.unpack('<I', image.read(0x29fe3f3, 4))[0]
    require(base == 10, 'decimal radix changed')
    width, power = 0, 1
    while power <= ((1 << 64) - 1) // base:
        width += 1
        power *= base
    require(width == 19, 'unexpected 64-bit decimal chunk width')
    return base, width


def decimal_parse(digits, bits, chunk_width):
    """Model selected 19-digit accumulation and 256-bit carry exits."""
    require(isinstance(digits, bytes) and bits == 256 and chunk_width == 19,
            'unsupported decimal parser input')
    result, chunk, count = 0, 0, 0
    for byte in digits:
        if byte == 0x5f:
            continue
        if not 0x30 <= byte <= 0x39:
            return 'invalid_digit', 0
        chunk = chunk * 10 + byte - 0x30
        count += 1
        if count == chunk_width:
            result = result * (10 ** count) + chunk
            if result >= 1 << bits:
                return 'overflow', 0
            chunk, count = 0, 0
    if count:
        result = result * (10 ** count) + chunk
        if result >= 1 << bits:
            return 'overflow', 0
    return 'ok', result


def check_all(image):
    for row in WINDOWS:
        check_window(image, row)
        image.owner(row[1], len(bytes.fromhex(row[2])))
    for row in EDGES:
        check_edge(image, row)
    for row in DATA_REFS:
        check_data_ref(image, row)
        image.owner(row[1], len(bytes.fromhex(row[2])))
    rels = image.relocations()
    for label, va, expected, destination, kind in EDGES:
        if kind == 'indirect':
            require(destination in rels, 'selected indirect transfer lacks relocation')
    for row in LITERALS:
        check_literal(image, row)
    require(struct.unpack('<QQ', image.read(0x6450730, 16)) == (8, 8),
            'descriptor size/alignment changed')
    field_names(image)
    missing_parameter(image)
    layout(image)
    guard_constants(image)
    jump_tables(image)
    empty_value_witness(image)
    nibble = nibble_table(image)
    constants = simd_constants(image)
    require(all(hex_invalid_simd(n, constants) == (nibble[n] == 255) for n in range(256)),
            'SIMD and scalar hex classifiers disagree')
    radix_prefixes(image)
    decimal_chunk_width(image)


def tsv(header, rows):
    out = io.StringIO(newline='')
    writer = csv.writer(out, delimiter='\t', lineterminator='\n')
    writer.writerow(header)
    writer.writerows(rows)
    return out.getvalue().encode('utf-8')


def hx(value):
    return '' if value is None else hex(value)


def records(image):
    check_all(image)
    selected = {}
    for _, va, raw in WINDOWS:
        f = image.owner(va, len(bytes.fromhex(raw)))
        selected[f['start']] = f
    for _, va, raw, _, _ in EDGES:
        f = image.owner(va, len(bytes.fromhex(raw)))
        selected[f['start']] = f
    frame = named_section(image.secs, '.eh_frame')
    header = named_section(image.secs, '.eh_frame_hdr')
    functions = []
    for start in sorted(selected):
        f = selected[start]
        entry = image.index[start]
        n = f['end'] - start
        body = image.read(start, n, executable=True)
        fo = image.offset(f['fde'], 4)
        length = struct.unpack_from('<I', image.data, fo)[0] + 4
        require(fo + length <= frame['offset'] + frame['size'], 'FDE record exceeds frame')
        hdr_off = header['offset'] + 12 + 8 * entry['index']
        cie_off = image.offset(f['cie'], 4)
        cie_length = struct.unpack_from('<I', image.data, cie_off)[0] + 4
        require(cie_off + cie_length <= frame['offset'] + frame['size'], 'CIE exceeds frame')
        functions.append([hx(start), hx(f['end']), hx(image.offset(start, n, True)), n,
                          hx(f['fde']), hx(fo), hx(f['cie']), hx(cie_off),
                          bytes(image.data[cie_off:cie_off + cie_length]).hex(), hx(f['lsda']),
                          entry['index'], hx(hdr_off), bytes(image.data[hdr_off:hdr_off + 8]).hex(),
                          bytes(image.data[fo:fo + length]).hex(), hashlib.sha256(body).hexdigest()])
    windows = [[label, hx(va), hx(image.offset(va, len(bytes.fromhex(raw)), True)),
                hx(image.owner(va)['start']), len(bytes.fromhex(raw)), raw]
               for label, va, raw in WINDOWS]
    rels = image.relocations()
    edges = []
    for label, va, raw, expected_target, expected_kind in EDGES:
        kind, target = check_edge(image, (label, va, raw, expected_target, expected_kind))
        target_addend = rels[target]['addend'] if kind == 'indirect' and target in RELATIVE else None
        symbol = rels[target]['symbol'] if kind == 'indirect' else ''
        edges.append([label, hx(va), hx(image.offset(va, len(bytes.fromhex(raw)), True)),
                      hx(image.owner(va)['start']), raw, kind, hx(target), hx(target_addend), symbol])
    relocations = [[hx(slot), hx(row['file_offset']), row['kind'], row['symbol_index'],
                    hx(row['addend']), row['symbol'], image.read(slot, 8).hex()]
                   for slot, row in sorted(rels.items())]
    data_refs = []
    for row in DATA_REFS:
        label, va, raw, _, size = row
        target, contents = check_data_ref(image, row)
        data_refs.append([label, hx(va), hx(image.offset(va, len(bytes.fromhex(raw)), True)),
                          raw, hx(target), hx(image.offset(target, size)), size, contents.hex()])
    literals = [[name, hx(va), hx(image.offset(va, len(value))), len(value), value.hex(),
                 value.decode('ascii')] for name, va, value in LITERALS]
    names = field_names(image)
    missing_size, missing_offset, missing_first, missing_second, missing_detail, missing_code = missing_parameter(image)
    canonical = [('address', names[0]), ('index', names[1]),
                 ('block_camel', names[2]), ('block_snake', names[3])]
    field_vectors = []
    for name, key in canonical:
        field_vectors.append([name, 'original', '', key.hex(), classify_field(key, names)])
        for i, old in enumerate(key):
            for new in range(256):
                if new == old:
                    continue
                changed = key[:i] + bytes([new]) + key[i + 1:]
                field_vectors.append([name, i, f'{new:02x}', changed.hex(), classify_field(changed, names)])
    universe = (names[0], names[1], names[2], names[3], b'other')
    field_flows = []
    for length in range(5):
        for keys in itertools.product(universe, repeat=length):
            field_flows.append([','.join(key.decode('ascii') for key in keys), named_flow(keys, names)])
    sizes = layout(image)
    guard = guard_constants(image)
    guard_rows = []
    guard_cases = (0, 1, 7, 8, 15, 16, 18, 26, (1 << 64) - 25, (1 << 64) - 17,
                   (1 << 64) - 16, (1 << 64) - 1)
    for old in guard_cases:
        released, wake = guard_release(old, guard)
        for matches in (False, True):
            arm, acquired = guard_acquire(old, matches, guard)
            guard_rows.append([hx(old), int(matches), arm, hx(acquired), hx(released), int(wake)])
    address = bytes(range(sizes['address_bytes']))
    bits = sizes['slot_bytes'] * 8
    integers = [('zero', 0), ('all_ones', (1 << bits) - 1)]
    integers += [('bit_' + str(i), 1 << i) for i in range(bits)]
    key_vectors = []
    for name, value in integers:
        limbs = tuple((value >> (64 * i)) & ((1 << 64) - 1) for i in range(4))
        suffix = key_suffix(address, limbs, sizes)
        key_vectors.append([name, address.hex(), ','.join(f'{n:016x}' for n in limbs),
                            suffix.hex(), (image.read(0x7bd525, 2) + suffix).hex()])
    payloads = (bytes(32), bytes(range(32)))
    lookup_vectors = []
    for account in (0, 1, 2):
        for storage in (0, 1, 2):
            for payload in payloads:
                lookup_vectors.append([account, storage, payload.hex(), int(account == 1),
                                       result_word(account, storage, payload).hex()])
    dispatch = jump_tables(image)
    empty_marker, empty_kind, empty_parse, empty_cleanup, empty_wrapper, empty_payload, empty_storage = empty_value_witness(image)
    nibble = nibble_table(image)
    constants = simd_constants(image)
    hex_classes = [[f'{value:02x}', nibble[value], int(hex_invalid_simd(value, constants))]
                   for value in range(256)]
    expected_hex_bytes = struct.unpack('<I', image.read(0x21cf9d5, 4))[0]
    require(expected_hex_bytes == sizes['slot_bytes'], 'fixed decoder width changed')
    samples = [('empty', b''), ('short_prefix', b'0x'),
               ('fixed_zero', b'0' * 64), ('prefixed_zero', b'0x' + b'0' * 64),
               ('upper_prefix', b'0X' + b'0' * 64), ('odd', b'0' * 63),
               ('too_long', b'0' * 66), ('mixed', b'aF' * 32)]
    samples += [('first_byte_' + f'{value:02x}', bytes([value]) + b'0' * 63)
                for value in range(256)]
    hex_vectors = []
    for label, sample in samples:
        status, result = fixed_hex(sample, nibble, expected_hex_bytes)
        hex_vectors.append([label, sample.hex(), status, result.hex()])
    prefixes = radix_prefixes(image)
    radix_samples = [b'', b'0', b'0x', b'0X1', b'0o7', b'0O7', b'0b1', b'0B1',
                     b'10', b'0q1', b'0x0', b'0x' + bytes([0x7f]),
                     b'0x' + bytes([0x80]), b'0x' + bytes([0xbf]),
                     b'0x' + bytes([0xc0]), b'0x' + bytes([0xff])]
    radix_vectors = []
    for sample in radix_samples:
        base, suffix = radix_route(sample, prefixes)
        radix_vectors.append([sample.hex(), base, suffix.hex()])
    power_vectors = []
    for base, letter in ((2, 'b'), (8, 'o'), (16, 'x')):
        values = (0, 1, (1 << bits) - 1, 1 << bits, (1 << bits) + 1)
        cases = [('value_' + str(i), format(value, letter).encode('ascii'))
                 for i, value in enumerate(values)]
        cases += [('empty', b''), ('underscores', b'___'), ('mixed_underscore', b'0_1_'),
                  ('many_leading_zeroes', b'0' * (bits + 1) + b'1'),
                  ('invalid_symbol', b'1!'), ('invalid_letter', b'g')]
        for label, digits in cases:
            status, value = power2_parse(digits, base, bits)
            power_vectors.append([base, label, digits.hex(), status,
                                  value.to_bytes(sizes['slot_bytes'], 'big').hex() if status == 'ok' else ''])
    decimal_base, chunk_width = decimal_chunk_width(image)
    decimal_cases = [('zero', b'0'), ('empty', b''), ('underscores', b'___'),
                     ('mixed_underscore', b'0_1_'), ('maximum', str((1 << bits) - 1).encode()),
                     ('first_overflow', str(1 << bits).encode()),
                     ('leading_zeroes', b'0' * 100 + b'1'), ('invalid', b'12!'),
                     ('error_before_partial_commit', b'9' * 78 + b'!'),
                     ('overflow_before_error', b'9' * 95 + b'!')]
    decimal_vectors = []
    for label, digits in decimal_cases:
        status, value = decimal_parse(digits, bits, chunk_width)
        decimal_vectors.append([decimal_base, label, digits.hex(), status,
                                value.to_bytes(sizes['slot_bytes'], 'big').hex() if status == 'ok' else ''])
    outputs = {
        'functions.tsv': tsv(['start_va','end_va_exclusive','file_offset','size','fde_va',
                              'fde_file_offset','cie_va','cie_file_offset','cie_bytes',
                              'lsda_va','unwind_index','index_file_offset',
                              'index_bytes','fde_bytes','body_sha256'], functions),
        'windows.tsv': tsv(['label','va','file_offset','fde_start','size','bytes'], windows),
        'edges.tsv': tsv(['label','va','file_offset','fde_start','bytes','kind','target_or_slot_va',
                          'relative_addend_va','import_symbol'], edges),
        'relocations.tsv': tsv(['slot_va','rela_file_offset','type','symbol_index','addend',
                                'symbol','slot_file_bytes'], relocations),
        'data-refs.tsv': tsv(['label','va','file_offset','instruction_bytes','target_va',
                              'target_file_offset','target_size','target_bytes'], data_refs),
        'literals.tsv': tsv(['label','va','file_offset','size','bytes','ascii'], literals),
        'field-vectors.tsv': tsv(['base','mutated_offset','mutated_byte','input_hex','classification'],
                                 field_vectors),
        'field-flows.tsv': tsv(['fields_with_valid_values','synthetic_outcome'], field_flows),
        'parameter-error.tsv': tsv(['allocation_size','first_store_offset','first_immediate_hex',
                                    'second_store_offset','second_immediate_hex','detail_hex',
                                    'detail_ascii','signed_code','message_va'],
                                   [[missing_size, missing_offset, missing_first.hex(), 0,
                                     missing_second.hex(), missing_detail.hex(),
                                     missing_detail.decode('ascii'), missing_code, hx(0x6167a1)]]),
        'key-vectors.tsv': tsv(['case','address_hex','little_endian_limbs_hex','suffix_hex',
                                'conditional_example_key_hex'], key_vectors),
        'guard-vectors.tsv': tsv(['old_word','cas_matches','synthetic_acquire_arm',
                                  'acquired_word_if_fast','synthetic_release_word',
                                  'synthetic_wake_condition'], guard_rows),
        'lookup-vectors.tsv': tsv(['account_tag','storage_tag','storage_payload_hex',
                                   'storage_read_selected','synthetic_return_hex'], lookup_vectors),
        'empty-value.tsv': tsv(['synthetic_input_length','parser_marker','error_kind','parser_error_tag',
                                'cleanup_arm_va','wrapper_error_tag','wrapper_error_payload',
                                'storage_error_tag','synthetic_return_hex'],
                               [[0, empty_marker, empty_kind, empty_parse, hx(empty_cleanup),
                                 empty_wrapper, empty_payload, empty_storage,
                                 result_word(1, empty_storage, bytes(32)).hex()]]),
        'dispatch.tsv': tsv(['variant','tag','entry_va','file_offset','bytes','signed_delta','target_va'],
                            dispatch),
        'hex-classes.tsv': tsv(['byte','scalar_nibble_or_255','simd_invalid'], hex_classes),
        'hex-vectors.tsv': tsv(['case','input_hex','synthetic_status','decoded_hex'], hex_vectors),
        'radix-vectors.tsv': tsv(['input_hex','forwarded_radix','forwarded_suffix_hex'], radix_vectors),
        'power-vectors.tsv': tsv(['radix','case','digits_hex','synthetic_status','value_be_hex'], power_vectors),
        'decimal-vectors.tsv': tsv(['radix','case','digits_hex','synthetic_status','value_be_hex'], decimal_vectors),
    }
    summary = {
        'target_release': '115', 'target_sha256': SHA256,
        'coordinates': 'linked ELF virtual addresses; FDE ends exclusive; file offsets zero based',
        'selected_fdes': len(functions), 'selected_byte_windows': len(windows),
        'selected_transfers': len(edges), 'selected_relocations': len(relocations),
        'selected_data_references': len(data_refs),
        'selected_literals': len(literals), 'field_classification_vectors': len(field_vectors),
        'selected_parameter_errors': 1,
        'field_flow_vectors': len(field_flows), 'key_vectors': len(key_vectors),
        'guard_vectors': len(guard_rows),
        'lookup_vectors': len(lookup_vectors), 'dispatch_entries': len(dispatch),
        'empty_value_cases': 1,
        'hex_classes': len(hex_classes), 'hex_vectors': len(hex_vectors),
        'radix_vectors': len(radix_vectors), 'power_vectors': len(power_vectors),
        'decimal_chunk_digits': chunk_width, 'decimal_vectors': len(decimal_vectors), 'key_layout': sizes,
        'limitations': 'Static selected witnesses and synthetic models only; no target execution, complete function census, block selector behavior, wire serialization, persistent write proof or equivalence.',
    }
    outputs['summary.json'] = (json.dumps(summary, indent=2, sort_keys=True) + '\n').encode('utf-8')
    return outputs


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, help='directory for generated evidence')
    args = parser.parse_args(argv)
    data = TARGET.read_bytes()
    generated = records(Image(data))
    output = Path(args.out)
    output.mkdir(parents=True, exist_ok=True)
    for name in sorted(generated):
        (output / name).write_bytes(generated[name])


if __name__ == '__main__':
    main()
