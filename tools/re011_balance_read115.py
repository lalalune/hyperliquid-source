#!/usr/bin/env python3
"""Regenerate selected static node 115 balance-read evidence without executing it."""

import argparse
import csv
import hashlib
import io
import itertools
import json
from pathlib import Path
import struct
import sys
import tomllib

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/115/hl-node'
NODE_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SYNC_TOML_SHA256 = '8caaf10441c2a38272820f9be1886e76087d94582f107a59157b096d0450796e'
SYNC_LOCK_SHA256 = '631d5b84e901d55bb508e465a236009fc962d961981f0328e812338ebd3f0fae'

# These are selected unwind starts, not a function-census denominator.
FUNCTIONS = (
    ('registration', 0x2cff4e0),
    ('synchronous_wrapper', 0x2dd5c60),
    ('balance_callback', 0x2d009f0),
    ('positional_address', 0x2d0f8f0),
    ('positional_json_address', 0x1d6b370),
    ('object_wrapper', 0x1d734b0),
    ('object_visitor', 0x1f5cc20),
    ('address_value_parser', 0x298d2f0),
    ('address_array_visitor', 0x2694df0),
    ('array_element_wrapper', 0x1dc1b20),
    ('array_length_error', 0x2697370),
    ('balance_handler', 0x2a2b890),
    ('account_read_adapter', 0x2a3e430),
    ('conditional_metric_update', 0x4771f70),
    ('metric_map_lookup', 0x476f260),
)

# Fixed witnesses were inspected at instruction boundaries. Bytes are verified
# before decoding; they are not copied into an implementation or executed.
WINDOWS = (
    ('route_name', 0x2a060b9, '488d1556c3bffd4889e7488d742420b90e000000e80e942f00'),
    ('register_refcount', 0x2cff4ed, '4c8b2ef049ff45000f8e9f0000004989ce4989d74989f44889fb'),
    ('register_alloc', 0x2cff51e, 'bf18000000ff1557ff7d034885c07457'),
    ('register_descriptor', 0x2cff543, '4889442410488d0579117503488944241848c7442408000000004c8d4424084889df4c89e64c89fa4c89f1ff15242c7e03'),
    ('register_fail', 0x2cff585, '488d5c2418bf08000000be18000000ff15f6fe7d030f0b'),
    ('clone_and_callback', 0x2dd5c67, '4889fb4c8b364c89742408488d4424280f10020f11442428488b521048895424380f10010f29442410488b491048894c24204c894424404c894c2448488d742408488d4c24104889c2e83badf2ff'),
    ('callback_drop', 0x2dd5cb5, 'f049ff0e750b488d7c2408ff15f21171034889d84883c4585b415ec3'),
    ('parameter_shape', 0x2d00a14, '488b1e4c8b214c8b6908488b411048b901000000000000804939cc4c898c24a00000000f84cc0000004885c00f84c300000041807d007b0f85c6000000'),
    ('object_call', 0x2d00a7c, '488d7c2440488db424b0000000e8222a07ff807c2440030f85d8020000'),
    ('empty_sequence', 0x2d00b09, '4939cc750931c0b901000000eb244c89e94883f802751b410fb74d0031c081f95b5d00000f95c0b901000000490f45cd01c048898c240001000048898424080100004889e7488db42400010000'),
    ('address_arg', 0x2d00b56, 'e895ed0000488b2c244883fd030f8574020000'),
    ('address_saved', 0x2d00b69, '8b442418898424f00000000f104424080f298424e0000000488d7c2440488db42400010000'),
    ('block_arg', 0x2d00b8e, 'e84de70000488b6c24404883fd047504b002eb2b'),
    ('block_result', 0x2d00ba2, '0fb64424480f104424490f2904240f104424590f29442410488b4c246848894c241f83fd030f8586020000'),
    ('adapter_input', 0x2d00bcd, '888424b00000000f2804240f284c24100f118424b10000000f118c24c1000000488b44241f48898424d00000004883c310488d7c2440488d9424e0000000488d8c24b00000004889dee875acd2ff'),
    ('adapter_output', 0x2d00c1b, '488b6c24404883fd037524488d4424480f10000f1048100f298c24900000000f2984248000000041be01000000eb24'),
    ('response_handoff', 0x2d00c90, '48c7842410010000000000004889ac24200100004c89b424280100000f288424800000000f288c24900000000f118424300100000f118c244001000048899c2450010000488b8c24a8000000488b411048894424100f10010f290424488d7c24404889e6488d942410010000488b8c24f8000000e8c7f55cff'),
    ('response_output_copy', 0x2d00d09, '0f10442458410f114718488b442450498947100fb6442470418847300f10442440410f1107488b8424a0000000498947284c8b742468'),
    ('parameter_cleanup', 0x2d00c6e, '48b802000000000000804939c47c134d85e4740e4c89ef4c89e631d2ff1510e87d03'),
    ('named_copy', 0x2d00d71, '0f104424400f104c24500f105424600f105c24700f2904240f295c24300f295424200f294c2410803c24030f8406fdffff8b442438898424f00000000f104424280f298424e00000000f2804240f284c24100f298424b00000000f298c24c0000000488b442420'),
    ('address_error', 0x2d00e04, '488d3dae7091fd488d154a6591fd4c8d442440be07000000b9070000004531c9ff1586137e03'),
    ('block_error', 0x2d00e83, '488d3df68d75fd488d15037091fd4c8d442440be08000000b91200000041b901000000ff1504137e03'),
    ('visitor_wrapper', 0x1d734d2, '48c74424080000000048c74424100100000048c74424180000000066c74424500080488d742408e822971e00803b037453'),
    ('trailing_whitespace', 0x1d73512, '488b54242048f7d848ffc148be0026000001000000660f1f8400000000000fb67c0aff4883ff20773b480fa3fe733548894c2430488d3c0848ffc748ffc14883ff0175da'),
    ('trailing_error', 0x1d73576, '48c744245816000000488d7c2408488d742458e8921e000048894308c60303'),
    ('field_dispatch', 0x1f5cfd4, '488b0c244c8b6c24084883f9020f8433fdffff488b44241083f9014883f8080f84a70000004883f8070f85ad000000418b4500b96164647231c8418b4d03ba7265737331d109c10f8443010000418b4500b9626c6f6331c8418b4d03ba636b496431d109c17575'),
    ('block_duplicate', 0x1f5d03b, '80fb030f85df040000'),
    ('block_alias', 0x1f5d0a0, '48b8626c6f636b5f696449394500748b'),
    ('block_parse', 0x1f5d12f, '4883fe3a0f85010400004885c00f8441040000488945284889e74889eee89fbb34000fb62c244080fd030f85dffdffff'),
    ('address_duplicate', 0x1f5d164, 'f6442448010f85de030000'),
    ('address_parse', 0x1f5d1cf, '4889e74889eee81601a300803c24010f8431fbffff'),
    ('address_mark', 0x1f5d22b, 'b0018944244889dde93dfdffff'),
    ('missing_and_default', 0x1f5d35e, 'f6442448010f842c0100004080fd03750540b502eb3e'),
    ('missing_address', 0x1f5d495, '488d05e35367fe488944245048c744245807000000488d44245048890424488d0596a754004889442408488d3dfe504dfe4889e6e8e24aed00'),
    ('duplicate_block', 0x1f5d523, '488d0556c74ffe488944245048c744245808000000'),
    ('duplicate_address', 0x1f5d54d, '488d052b5367fe488944245048c744245807000000488d44245048890424488d05dea654004889442408488d3d9c5f4dfe'),
    ('hex_input', 0x298d4c5, '4883f8010f842204000048ffc84989462849c7461000000000488d7c24084c89f2ff150c34b503837c240802488b742410750c48897308c60301e9a6030000488b542418488d7c2440488d4c242041b814000000ff152949b503837c2440030f8513030000'),
    ('hex_output', 0x298d550, '8b4424388b4c243b894b048943014c897b084489631049c1ec204488631431c0e933030000'),
    ('handler_tuple', 0x2a2b8a1, '4889fb4c8ba6d8030000498d442410488d0d2774bdfd48898c247801000048c78424800100000b00000048c7842470010000000000004d8dac244001000048898424580100004889942460010000488d84247001000048898424680100004c89ac24b80000004180bc2460010000007456'),
    ('handler_fast_call', 0x2a2b968, '488d7c2430488db42458010000e8b62a0100e937070000'),
    ('handler_telemetry', 0x2a2b995, '48b8ffffffffffffff7f64498b0e4839c10f83f50400004c89ac24b00000004c89bc24a800000048895c247848898c24f8000000488d410164498906'),
    ('handler_tls_count', 0x2a2bc88, '410f11540f20410f114c0f10410f11040f48ffc56449896e18488d48016449890e'),
    ('handler_slow_call', 0x2a2c097, '488d7c2430488db42458010000e887230100488dbc2480000000e85a65cbff'),
    ('handler_result', 0x2a2c0b6, '0f104424300f104c24400f114b180f11430848c70303000000'),
    ('core_tuple', 0x2a3e441, '4889bc24d80000004c8b364c8b7e08488b4610488b481048898c2400010000660f1000660f298424f0000000'),
    ('core_guard', 0x2a3e488, '4d8da6a8060000498b86a806000089c183e108c1e9034883f8f00f93c208ca74124c89e731f6b900ca9a3bff151f2baa03eb0c488d4810f0490fb10c2475e2'),
    ('account_arg_a', 0x2a3e541, 'be981c00004903b6000b0000418b47108944241066410f1007660f290424488d7c24504889e2e804a43001'),
    ('tag_branch_a', 0x2a3e56c, '488b4424504883f8020f8567010000488b4424584883f8020f82ea010000488b7424600f84d7010000488b7c24684883f8034885f60f84cd01000031d2ff15f10eaa03e9c0010000'),
    ('account_arg_b', 0x2a3e673, 'be981c00004903b6000b0000418b47108944241066410f1007660f290424488d7c24504889e2e8d2a23001'),
    ('tag_branch_b', 0x2a3e69e, '488b4424504883f8027578488b4424584883f8020f82f8000000488b7424600f84e5000000488b7c24684883f8034885f60f84db00000031d2ff15c30daa03e9ce000000'),
    ('tag_success_a', 0x2a3e6e2, '488d4c2458660f1001660f104910660f294c2430660f2944242083f8017573660f28442420660f284c2430660f298c24c0000000660f298424b0000000eb69'),
    ('tag_success_b', 0x2a3e721, '488d4c2458660f1001660f104910660f294c2430660f2944242083f8017570660f28442420660f284c2430660f294c2460660f29442450'),
    ('zero_and_release_a', 0x2a3e76c, '488b064889f7ff10660f57c0660f298424b0000000660f298424c000000048c7c0f0ffffff498dbea8060000f0480fc1074883e0f231dbe91a010000'),
    ('zero_and_release_b', 0x2a3e7a8, '488b064889f7ff10660f57c0660f29442450660f294424604d8bbe180100004d85ff0f95c37498'),
    ('core_release_b', 0x2a3e8ab, '48c7c0f0ffffff498dbea8060000f0480fc1074883e0f24883f8120f8497010000'),
    ('core_final_return', 0x2a3ea32, '0f288424b00000000f288c24c0000000488b8424d80000000f1148100f1100'),
    ('core_wake', 0x2a3ea63, 'ff157f25aa03e95efeffff'),
    ('core_unwind_release', 0x2a3eaee, '488b542440f0480fc10a4889c34883e1f24883f9127531488b7c2440ff15d824aa03eb24'),
    ('address_first_dispatch', 0x298d374, '448d47a54183f820765883ff220f843e01000083ff2d0f85f50000004883f8010f845705000048ffc849894628488d7c24204c89f631d2e8d08f3eff488b4424204883f8030f84f50000004885c00f844804000083f8010f841d040000e929040000488d354331c7fd4e6304864901f041ffe0'),
    ('address_array_call', 0x298d407, '4883f8010f84e004000048ffc849894628488d7c24084c89f6ba01000000e8c679d0ff'),
    ('array_first', 0x2694e0a, '488d7c2410488d742430e8e79872ff807c2410010f84e9010000807c241100742a488b742430488d7c2410e846c675ff807c2410010f84c80100000fb6442411c64424010188442402eb05c644240100807c2401010f8512010000'),
    ('array_sixth', 0x2695001, 'e8fa9672ff807c2410017532488b4424184889442408488b44240848894308c603014889d84883c4485b415c415d415e415f5dc3'),
    ('array_sixth_value', 0x269503f, '807c2411007426488b742430488d7c2410e82bc475ff807c24100174b10fb6442411c64424010188442402eb05c644240100807c2401010f85ea0200000fb64424028844242f4889e7488d742430'),
    ('array_seventh', 0x269508d, 'e88eca72ff803c24000f857bffffff807c2401010f85c90200000fb64424028844242e'),
    ('array_twentieth', 0x26952bc, 'e85fc872ff803c24000f854cfdffff807c2401010f85cd0100000fb644240288442421'),
    ('array_final_probe', 0x26952df, '488d7c2410488d742430e832c872ff0fb644241084c0750b807c2411000f85a801000084c00f84fe000000488b4424184889442440488b004883f8010f84c70000004885c00f85cc000000'),
    ('array_error_cleanup', 0x26953e8, '488b442440488b7808e82a910100be28000000488b7c244031d2ff1598a0e403'),
    ('array_output_stores', 0x2695408, '40886b0144887b024488630344886b04448873050fb644242f8843060fb644242e8843070fb644242d8843080fb644242c8843090fb644242b88430a0fb644242a88430b0fb644242988430c0fb644242888430d0fb644242788430e0fb644242688430f0fb64424258843100fb64424248843110fb64424238843120fb64424228843130fb6442421884314c60300e987fbffff'),
    ('array_length_end', 0x269549c, 'bf12000000eb0cbf13000000eb05bf15000000e8bc1e0000e963fbffff'),
    ('sample_calculation', 0x2a3e813, '4d09ecb800ca9a3b48f76424288b4c24304801c84883d20031f648f7dab9000000004819c94809c14d39e74d0f47e74084ed4d0f45e74c29e1480f42ce807c242000660f57c9752966480f6ec1660f6205a829a1fd660f5c050019a1fd660f28c8660f15c8f20f58c8f20f5e0dcca4a1fd660f298c2410010000'),
    ('metric_call_gate', 0x2a3e996, '4181be2801000000ca9a3b0f95c084c374414983c628488b84240001000048894424600f288424f00000000f29442450488d7424504c89f7660f28842410010000f20f115c2418ff157586aa03f20f105c2418'),
    ('metric_lock_entry', 0x4771f77, 'f20f1104244889f24889fbb10131c0f00fb00f0f85c8010000488db3b8000000488d7c2408e8bfd2ffff'),
    ('metric_lookup', 0x4771fa1, '488b4424084885c00f84a8000000488b4c2410488b7424180f104424200f29442430488b10488b78084989f84921c8f3420f6f0402'),
    ('metric_insert', 0x4772002, '48c1e9394d8d51f04921fa42880c0a42884c121049f7d94b8d3c4948c1e704488d0c3a4180e001450fb6c04c2940104889743ad00f284424300f11443ad80f57c00f11443ae848c7443af80000000048ff4018eb0a'),
    ('metric_sum', 0x4772061, 'f20f1041f0f20f58c366480f7ec248b8ffffffffffffff7f4821d0'),
    ('metric_sum_check', 0x47720ba, '488b71e84885d27943660f28c8eb45'),
    ('metric_count', 0x47720fd, '488b71e84885d278bdf20f100d826fcefb48ffc648c7c2ffffffff480f45d6488951e848ba000000000000f07f4839d07404660f28c8f20f1149f0'),
    ('metric_max_unlock', 0x4772138, 'f20f1041f8f20f5fc3f20f1141f831c9b001f00fb00b7521'),
    ('metric_slow_acquire', 0x4772158, '4889df4989d6ba00ca9a3bff158fe0d6014c89f2e91ffeffff'),
    ('metric_slow_release', 0x4772171, '4889df31f64883c4485b415eff25b5edd601'),
    ('metric_probe', 0x4772183, '41ba100000004d01d04921f8f3420f6f040266440fd7c84983c2104585c90f8542feffffebe0660f6f0266440fd7c0f3450fbcc8460fb6040ae941feffff'),
    ('metric_unwind', 0x47721c1, '4989c631c9b001f00fb00b75084c89f7e87ae8c7014889df31f6ff1557edd601ebebff15d7d2d601'),
    ('element_option_wrapper', 0x1dc1b20, '4156534883ec184989f64889fb488d7c2408e8c9cbffff807c240801750e488b44241048894308c60301eb2f807c2409007423498b36488d7c2408e820f90200807c24080075d70fb644240988430266c7030001eb0566c70300004889d84883c4185b415ec3'),
    ('expected_size_formatter', 0x2697370, '4156534883ec284989fe488d05571adcfd48890424488b053c83e4034889442408488d352394d9fd488d7c24104889e2ff154283e403488b5c2418488b44242048891c244889442408488d1500fed9034889e64c89f7e8359f6500488b7424104885f674114889df31d24889c3ff15bd80e4034889d84883c4285b415ec34989c6488b7424104885f6740b4889df31d2ff159a80e4034c89f7e84296d503'),
    ('map_hash_and_probe', 0x476f26e, '4989d64989f74889fb488d7e204889d6e82df000004889c548c1e839498b17498b7708660f6ec0660f60c0f20f70c000660f70c844498b0648894424284d8b4608458b4e104d8b561031c9660f76d24c8b2d3407d7014989ec4921f4f3420f6f1c22660f6fc3660f74c1660fd7f885ff0f841c010000'),
    ('map_key_status', 0x476f30e, '48837c2428000f94c048897c2448f30fbccf4c01e14821f148f7d9488d2c4948c1e504488b7c2ad04885ff0f94c130c10f858c0000004801d54885ff7444'),
    ('map_key_nonzero', 0x476f34c, '44394de0757e4c3945d87578488b7424284c89c248895c24104c89d341ffd5660f6f5c2450660f76d24989da448b4c240c488b5c2410eb38'),
    ('map_key_zero', 0x476f390, '4c3955e0753a488b7dd84c89c64c89d24c8954241041ffd5660f6f5c2450660f76d24c8b542410448b4c240c4c8b442418660f6f4c2460488b54242085c0744c'),
    ('map_collision_and_empty', 0x476f3d0, '488b4c24488d41ff6621c889c7488b6c2440488b742438488b4c24300f851cffffff66666666662e0f1f840000000000660f74da660fd7c385c075214901cc4983c4104883c110e9abfeffff'),
    ('map_result_existing', 0x476f41c, '48896b084c897b1048c70300000000eb20'),
    ('map_result_missing', 0x476f42d, '49837f1000742b4c893b48896b08f3410f6f06f30f7f4310498b461048894320'),
    ('map_grow', 0x476f45f, 'be010000004c89ff498d5720b901000000ff15c2bcd701ebbc'),
    ('array_cleanup_detail', 0x269530a, '488b4424184889442440488b004883f8010f84c70000004885c00f85cc000000488b442440488b70104885f60f84ba000000488b442440488b780831d2ff1553a1e403e9a4000000'),
    ('positional_cursor', 0x2d0f904, '4c8b264c8b7e084c89a424e00000004c89bc24e80000004d85ff0f844f0200004989f6410fb6042483f82c742283f85b741d83f85d0f85c500000049c7060100000049c7460800000000e9200200004983ff01740c41807c2401c00f8cb9020000'),
    ('positional_nested_setup', 0x2d0f965, '49ffcf49ffc448c74424480000000048c74424500100000048c7442458000000004c896424604c897c24680f57c00f114424704c89a424800000004c89bc248800000066c7842490000000008048c784249800000000000000c68424a000000000488dbc24a8000000488d742448e898b905ff0fb68424a80000003c027568488b742448'),
    ('positional_unexpected_delimiter', 0x2d0fa04, '488d8424e00000004889442448488d05a87d79ff4889442450488d355d1773fd4c8db424f0000000488d5424484c89f7ff15aefc7c03488d7c24104c89f6e8e9140000'),
    ('positional_nested_failure', 0x2d0fa62, '4c8bac24b0000000a801746649c7060100000049c7460800000000488dbc24a80000004c89eee8f3120000'),
    ('positional_cursor_advance', 0x2d0fad4, '488bac24b8000000488b9424980000004885d274264939d7761f41803c14bf7f1a4c8d05b41174034c89e74c89fe4c89f9ff1565fb7c030f0b75e64929d74901d44c89e74c89fee820ad8eff498906'),
    ('positional_no_more_error', 0x2d0fb6b, '48837c2410047576bf0e000000ff1502f97c034885c00f848700000048b96520706172616d734889480648b94e6f206d6f72652048890848c74424480e000000488944245048c74424580e000000488d15e16b90fd4c8d442448b90e0000004889dfbea680ffffe8a9dc8bff'),
    ('positional_allocation_failure', 0x2d0fc0e, 'bf01000000be0e000000ff157af87c034c8d0573107403ba010000004c89e74c89fe4c89f9ff1537fa7c03eb00'),
    ('address_json_prefix', 0x1d6b37c, '488b4e20488b46284839c873374c8d7618488b561849b800260000010000000f1f440000440fb60c024983f92277274d0fa3c8731b48ffc0488946284839c175e34889c848894650c60702e9ee0000004983f922740c4183f95b74064183f97b75084989ff40b501eb054989ff31ed48894650488d7c24184989f4e8f41ec200'),
    ('address_json_result', 0x1d6b3fc, '807c2418017524488b5c2420498b542420498b7424284839d60f87e60000004c89ff4989742420b101eb7b'),
    ('address_json_trailing', 0x1d6b44b, '498b4c242849894c24504084ed4c89ff7526493b4c2420731f498b160fb60c0a8d51f783fa547757488d0d022786fe486314914801caffe2'),
    ('address_json_output', 0x1d6b483, '8b4c24108b5424138954240b894c240848b9ffffffffff0000004821c831c9880f8b4c24088b54240b894f0189570448895f0848894710'),
    ('address_json_error', 0x1d6b4ca, '83f97b74b483f97d74af4889fb4c89f7ff15286d770448c744241816000000488d7c24184889c6ff15115677044889df4889c3b101'),
)

# Each target below is re-derived from the instruction displacement.
TRANSFERS = (
    ('register_name', 0x2a060cd, 'e80e942f00', 0x2cff4e0, 'call'),
    ('register_refcount_guard', 0x2cff4f5, '0f8e9f000000', 0x2cff59a, 'jcc'),
    ('register_null_alloc', 0x2cff52c, '7457', 0x2cff585, 'jcc'),
    ('register_insert', 0x2cff56e, 'ff15242c7e03', 0x64e2198, 'indirect'),
    ('sync_to_callback', 0x2dd5cb0, 'e83badf2ff', 0x2d009f0, 'call'),
    ('sync_drop_guard', 0x2dd5cb9, '750b', 0x2dd5cc6, 'jcc'),
    ('params_sentinel', 0x2d00a37, '0f84cc000000', 0x2d00b09, 'jcc'),
    ('params_empty', 0x2d00a40, '0f84c3000000', 0x2d00b09, 'jcc'),
    ('params_object', 0x2d00a4b, '0f85c6000000', 0x2d00b17, 'jcc'),
    ('params_object_wrapper', 0x2d00a89, 'e8222a07ff', 0x1d734b0, 'call'),
    ('object_failure', 0x2d00a93, '0f85d8020000', 0x2d00d71, 'jcc'),
    ('array_sentinel', 0x2d00b0c, '7509', 0x2d00b17, 'jcc'),
    ('array_empty', 0x2d00b15, 'eb24', 0x2d00b3b, 'jmp'),
    ('array_len_two', 0x2d00b1e, '751b', 0x2d00b3b, 'jcc'),
    ('parse_address', 0x2d00b56, 'e895ed0000', 0x2d0f8f0, 'call'),
    ('address_parse_failure', 0x2d00b63, '0f8574020000', 0x2d00ddd, 'jcc'),
    ('parse_block', 0x2d00b8e, 'e84de70000', 0x2d0f2e0, 'call'),
    ('block_absent', 0x2d00b9c, '7504', 0x2d00ba2, 'jcc'),
    ('block_default', 0x2d00ba0, 'eb2b', 0x2d00bcd, 'jmp'),
    ('block_parse_error', 0x2d00bc7, '0f8586020000', 0x2d00e53, 'jcc'),
    ('invoke_balance', 0x2d00c16, 'e875acd2ff', 0x2a2b890, 'call'),
    ('balance_result', 0x2d00c24, '7524', 0x2d00c4a, 'jcc'),
    ('response_builder_boundary', 0x2d00d04, 'e8c7f55cff', 0x22d02d0, 'call'),
    ('result_join', 0x2d00c48, 'eb24', 0x2d00c6e, 'jmp'),
    ('param_cleanup_signed', 0x2d00c7b, '7c13', 0x2d00c90, 'jcc'),
    ('param_cleanup_zero', 0x2d00c80, '740e', 0x2d00c90, 'jcc'),
    ('param_dealloc', 0x2d00c8a, 'ff1510e87d03', 0x64df4a0, 'indirect'),
    ('object_tag_check', 0x2d00d9c, '0f8406fdffff', 0x2d00aa8, 'jcc'),
    ('named_join', 0x2d00dd8, 'e915feffff', 0x2d00bf2, 'jmp'),
    ('address_annotate', 0x2d00e24, 'ff1586137e03', 0x64e21b0, 'indirect'),
    ('block_annotate', 0x2d00ea6, 'ff1504137e03', 0x64e21b0, 'indirect'),
    ('parse_object', 0x1d734f9, 'e822971e00', 0x1f5cc20, 'call'),
    ('wrapper_error', 0x1d73501, '7453', 0x1d73556, 'jcc'),
    ('trailing_gt_space', 0x1d73539, '773b', 0x1d73576, 'jcc'),
    ('trailing_bitmap_miss', 0x1d7353f, '7335', 0x1d73576, 'jcc'),
    ('trailing_loop', 0x1d73554, '75da', 0x1d73530, 'jcc'),
    ('trailing_error_make', 0x1d73589, 'e8921e0000', 0x1d75420, 'call'),
    ('field_done', 0x1f5cfe1, '0f8433fdffff', 0x1f5cd1a, 'jcc'),
    ('field_len_eight', 0x1f5cff3, '0f84a7000000', 0x1f5d0a0, 'jcc'),
    ('field_len_seven_miss', 0x1f5cffd, '0f85ad000000', 0x1f5d0b0, 'jcc'),
    ('field_address', 0x1f5d01b, '0f8443010000', 0x1f5d164, 'jcc'),
    ('field_block_camel_miss', 0x1f5d039, '7575', 0x1f5d0b0, 'jcc'),
    ('field_block_duplicate', 0x1f5d03e, '0f85df040000', 0x1f5d523, 'jcc'),
    ('field_block_snake', 0x1f5d0ae, '748b', 0x1f5d03b, 'jcc'),
    ('block_value_parse', 0x1f5d14c, 'e89fbb3400', 0x22a8cf0, 'call'),
    ('block_value_failure', 0x1f5d159, '0f85dffdffff', 0x1f5cf3e, 'jcc'),
    ('address_duplicate_guard', 0x1f5d169, '0f85de030000', 0x1f5d54d, 'jcc'),
    ('address_value_parse', 0x1f5d1d5, 'e81601a300', 0x298d2f0, 'call'),
    ('address_value_failure', 0x1f5d1de, '0f8431fbffff', 0x1f5cd15, 'jcc'),
    ('address_required', 0x1f5d363, '0f842c010000', 0x1f5d495, 'jcc'),
    ('block_default_guard', 0x1f5d36d, '7505', 0x1f5d374, 'jcc'),
    ('block_default_join', 0x1f5d372, 'eb3e', 0x1f5d3b2, 'jmp'),
    ('missing_field_error', 0x1f5d4c9, 'e8e24aed00', 0x2e31fb0, 'call'),
    ('duplicate_block_join', 0x1f5d538, 'eb28', 0x1f5d562, 'jmp'),
    ('duplicate_field_error', 0x1f5d57e, 'e943ffffff', 0x1f5d4c6, 'jmp'),
    ('quoted_field_reader', 0x298d4e6, 'ff150c34b503', 0x64e08f8, 'indirect'),
    ('quoted_field_failure', 0x298d4f6, '750c', 0x298d504, 'jcc'),
    ('fixed_width_decoder', 0x298d519, 'ff152949b503', 0x64e1e48, 'indirect'),
    ('fixed_width_failure', 0x298d524, '0f8513030000', 0x298d83d, 'jcc'),
    ('instrumentation_bypass', 0x2a2b910, '7456', 0x2a2b968, 'jcc'),
    ('invoke_core_fast', 0x2a2b975, 'e8b62a0100', 0x2a3e430, 'call'),
    ('fast_return_join', 0x2a2b97a, 'e937070000', 0x2a2c0b6, 'jmp'),
    ('tls_limit', 0x2a2b9a6, '0f83f5040000', 0x2a2bea1, 'jcc'),
    ('invoke_core_traced', 0x2a2c0a4, 'e887230100', 0x2a3e430, 'call'),
    ('trace_cleanup', 0x2a2c0b1, 'e85a65cbff', 0x26e2610, 'call'),
    ('guard_slow_condition', 0x2a3e4a7, '7412', 0x2a3e4bb, 'jcc'),
    ('guard_slow_call', 0x2a3e4b3, 'ff151f2baa03', 0x64e0fd8, 'indirect'),
    ('guard_slow_join', 0x2a3e4b9, 'eb0c', 0x2a3e4c7, 'jmp'),
    ('guard_cas_failure', 0x2a3e4c5, '75e2', 0x2a3e4a9, 'jcc'),
    ('account_lookup_a', 0x2a3e567, 'e804a43001', 0x3d48970, 'call'),
    ('first_tag_not_two', 0x2a3e575, '0f8567010000', 0x2a3e6e2, 'jcc'),
    ('first_subtag_less_two', 0x2a3e584, '0f82ea010000', 0x2a3e774, 'jcc'),
    ('first_subtag_two', 0x2a3e58f, '0f84d7010000', 0x2a3e76c, 'jcc'),
    ('first_cleanup_null', 0x2a3e5a1, '0f84cd010000', 0x2a3e774, 'jcc'),
    ('first_error_cleanup', 0x2a3e5a9, 'ff15f10eaa03', 0x64df4a0, 'indirect'),
    ('first_error_zero', 0x2a3e5af, 'e9c0010000', 0x2a3e774, 'jmp'),
    ('account_lookup_b', 0x2a3e699, 'e8d2a23001', 0x3d48970, 'call'),
    ('second_tag_not_two', 0x2a3e6a7, '7578', 0x2a3e721, 'jcc'),
    ('second_subtag_less_two', 0x2a3e6b2, '0f82f8000000', 0x2a3e7b0, 'jcc'),
    ('second_subtag_two', 0x2a3e6bd, '0f84e5000000', 0x2a3e7a8, 'jcc'),
    ('second_cleanup_null', 0x2a3e6cf, '0f84db000000', 0x2a3e7b0, 'jcc'),
    ('second_error_cleanup', 0x2a3e6d7, 'ff15c30daa03', 0x64df4a0, 'indirect'),
    ('second_error_zero', 0x2a3e6dd, 'e9ce000000', 0x2a3e7b0, 'jmp'),
    ('first_tag_not_one', 0x2a3e6ff, '7573', 0x2a3e774, 'jcc'),
    ('first_success_join', 0x2a3e71f, 'eb69', 0x2a3e78a, 'jmp'),
    ('second_tag_not_one', 0x2a3e73e, '7570', 0x2a3e7b0, 'jcc'),
    ('release_fast_join', 0x2a3e7a3, 'e91a010000', 0x2a3e8c2, 'jmp'),
    ('second_option_none', 0x2a3e7cd, '7498', 0x2a3e767, 'jcc'),
    ('release_slow_branch', 0x2a3e8c6, '0f8497010000', 0x2a3ea63, 'jcc'),
    ('release_wake', 0x2a3ea63, 'ff157f25aa03', 0x64e0fe8, 'indirect'),
    ('release_wake_join', 0x2a3ea69, 'e95efeffff', 0x2a3e8cc, 'jmp'),
    ('unwind_wake_skip', 0x2a3eb03, '7531', 0x2a3eb36, 'jcc'),
    ('unwind_wake', 0x2a3eb0a, 'ff15d824aa03', 0x64e0fe8, 'indirect'),
    ('unwind_join', 0x2a3eb10, 'eb24', 0x2a3eb36, 'jmp'),
    ('register_allocate', 0x2cff523, 'ff1557ff7d03', 0x64df480, 'indirect'),
    ('register_allocate_fail', 0x2cff594, 'ff15f6fe7d03', 0x64df490, 'indirect'),
    ('wrapper_final_drop', 0x2dd5cc0, 'ff15f2117103', 0x64e6eb8, 'indirect'),
    ('metric_gate_skip', 0x2a3e9a6, '7441', 0x2a3e9e9, 'jcc'),
    ('metric_update_call', 0x2a3e9dd, 'ff157586aa03', 0x64e7058, 'indirect'),
    ('metric_lock_slow', 0x4771f8a, '0f85c8010000', 0x4772158, 'jcc'),
    ('metric_lookup_call', 0x4771f9c, 'e8bfd2ffff', 0x476f260, 'call'),
    ('metric_existing_entry', 0x4771fa9, '0f84a8000000', 0x4772057, 'jcc'),
    ('metric_group_probe', 0x4771fe3, '0f849a010000', 0x4772183, 'jcc'),
    ('metric_fallback_probe', 0x4771ffc, '0f89a7010000', 0x47721a9, 'jcc'),
    ('metric_insert_join', 0x4772055, 'eb0a', 0x4772061, 'jmp'),
    ('metric_sum_sign', 0x4772094, '7933', 0x47720c9, 'jcc'),
    ('metric_count_value', 0x4772104, '78bd', 0x47720c3, 'jcc'),
    ('metric_noninf_sum', 0x477212d, '7404', 0x4772133, 'jcc'),
    ('metric_unlock_slow', 0x477214e, '7521', 0x4772171, 'jcc'),
    ('metric_slow_lock_call', 0x4772163, 'ff158fe0d601', 0x64e01f8, 'indirect'),
    ('metric_lock_retry', 0x477216c, 'e91ffeffff', 0x4771f90, 'jmp'),
    ('metric_probe_found', 0x47721a1, '0f8542feffff', 0x4771fe9, 'jcc'),
    ('metric_probe_loop', 0x47721a7, 'ebe0', 0x4772189, 'jmp'),
    ('metric_insert_restart', 0x47721bc, 'e941feffff', 0x4772002, 'jmp'),
    ('metric_unwind_unlock', 0x47721cc, '7508', 0x47721d6, 'jcc'),
    ('metric_unwind_resume', 0x47721d1, 'e87ae8c701', 0x63f0a50, 'call'),
    ('metric_unwind_slow_unlock', 0x47721db, 'ff1557edd601', 0x64e0f38, 'indirect'),
    ('option_probe', 0x1dc1b32, 'e8c9cbffff', 0x1dbe700, 'call'),
    ('option_error', 0x1dc1b3c, '750e', 0x1dc1b4c, 'jcc'),
    ('option_absent', 0x1dc1b51, '7423', 0x1dc1b76, 'jcc'),
    ('option_value_parser', 0x1dc1b5b, 'e820f90200', 0x1df1480, 'call'),
    ('option_value_error', 0x1dc1b65, '75d7', 0x1dc1b3e, 'jcc'),
    ('option_value_join', 0x1dc1b74, 'eb05', 0x1dc1b7b, 'jmp'),
    ('length_error_builder', 0x26973c6, 'e8359f6500', 0x2cf1300, 'call'),
    ('length_error_free_skip', 0x26973d3, '7411', 0x26973e6, 'jcc'),
    ('length_error_unwind', 0x2697409, 'e84296d503', 0x63f0a50, 'call'),
    ('map_hash', 0x476f27e, 'e82df00000', 0x477e2b0, 'call'),
    ('map_probe_empty', 0x476f2de, '0f841c010000', 0x476f400, 'jcc'),
    ('map_null_status', 0x476f33e, '0f858c000000', 0x476f3d0, 'jcc'),
    ('map_zero_key', 0x476f34a, '7444', 0x476f390, 'jcc'),
    ('map_compare_type', 0x476f350, '757e', 0x476f3d0, 'jcc'),
    ('map_compare_length', 0x476f356, '7578', 0x476f3d0, 'jcc'),
    ('map_compare_result', 0x476f3ce, '744c', 0x476f41c, 'jcc'),
    ('map_next_candidate', 0x476f3ec, '0f851cffffff', 0x476f30e, 'jcc'),
    ('map_empty_control', 0x476f40a, '7521', 0x476f42d, 'jcc'),
    ('map_next_group', 0x476f417, 'e9abfeffff', 0x476f2c7, 'jmp'),
    ('map_existing_return', 0x476f42b, 'eb20', 0x476f44d, 'jmp'),
    ('map_grow_check', 0x476f432, '742b', 0x476f45f, 'jcc'),
    ('map_grow_call', 0x476f470, 'ff15c2bcd701', 0x64eb138, 'indirect'),
    ('map_grow_return', 0x476f476, 'ebbc', 0x476f434, 'jmp'),
    ('array_extra_error', 0x26952f5, '750b', 0x2695302, 'jcc'),
    ('array_extra_present', 0x26952fc, '0f85a8010000', 0x26954aa, 'jcc'),
    ('array_probe_absent', 0x2695304, '0f84fe000000', 0x2695408, 'jcc'),
    ('array_drop_subtype', 0x269531b, '0f84c7000000', 0x26953e8, 'jcc'),
    ('array_drop_zero', 0x2695324, '0f85cc000000', 0x26953f6, 'jcc'),
    ('array_drop_empty', 0x2695336, '0f84ba000000', 0x26953f6, 'jcc'),
    ('array_error_release', 0x2695347, 'ff1553a1e403', 0x64df4a0, 'indirect'),
    ('array_error_join', 0x269534d, 'e9a4000000', 0x26953f6, 'jmp'),
    ('positional_empty', 0x2d0f91e, '0f844f020000', 0x2d0fb73, 'jcc'),
    ('positional_comma', 0x2d0f92f, '7422', 0x2d0f953, 'jcc'),
    ('positional_open', 0x2d0f934, '741d', 0x2d0f953, 'jcc'),
    ('positional_bad_delimiter', 0x2d0f939, '0f85c5000000', 0x2d0fa04, 'jcc'),
    ('positional_close', 0x2d0f94e, 'e920020000', 0x2d0fb73, 'jmp'),
    ('positional_one_byte', 0x2d0f957, '740c', 0x2d0f965, 'jcc'),
    ('positional_utf8_boundary', 0x2d0f95f, '0f8cb9020000', 0x2d0fc1e, 'jcc'),
    ('positional_json_address', 0x2d0f9d3, 'e898b905ff', 0x1d6b370, 'call'),
    ('positional_json_not_empty', 0x2d0f9e2, '7568', 0x2d0fa4c, 'jcc'),
    ('positional_empty_no_allocation', 0x2d0f9ec, '0f8481010000', 0x2d0fb73, 'jcc'),
    ('positional_format', 0x2d0fa34, 'ff15aefc7c03', 0x64df6e8, 'indirect'),
    ('positional_error_adapter', 0x2d0fa42, 'e8e9140000', 0x2d10f30, 'call'),
    ('positional_nested_success', 0x2d0fa6c, '7466', 0x2d0fad4, 'jcc'),
    ('positional_nested_error_adapter', 0x2d0fa88, 'e8f3120000', 0x2d10d80, 'call'),
    ('positional_alloc', 0x2d0fb78, 'ff1502f97c03', 0x64df480, 'indirect'),
    ('positional_alloc_fail', 0x2d0fb81, '0f8487000000', 0x2d0fc0e, 'jcc'),
    ('positional_no_more_builder', 0x2d0fbd2, 'e8a9dc8bff', 0x25cd880, 'call'),
    ('address_json_empty', 0x1d6b387, '7337', 0x1d6b3c0, 'jcc'),
    ('address_json_nonspace', 0x1d6b3a9, '7727', 0x1d6b3d2, 'jcc'),
    ('address_json_nonspace_small', 0x1d6b3af, '731b', 0x1d6b3cc, 'jcc'),
    ('address_json_whitespace_loop', 0x1d6b3bb, '75e3', 0x1d6b3a0, 'jcc'),
    ('address_json_quoted', 0x1d6b3d0, '740c', 0x1d6b3de, 'jcc'),
    ('address_json_array', 0x1d6b3d6, '7406', 0x1d6b3de, 'jcc'),
    ('address_json_object', 0x1d6b3dc, '7508', 0x1d6b3e6, 'jcc'),
    ('address_json_parse', 0x1d6b3f7, 'e8f41ec200', 0x298d2f0, 'call'),
    ('address_json_value_ok', 0x1d6b401, '7524', 0x1d6b427, 'jcc'),
    ('address_json_nested_error', 0x1d6b425, 'eb7b', 0x1d6b4a2, 'jmp'),
    ('address_json_composite', 0x1d6b45b, '7526', 0x1d6b483, 'jcc'),
    ('address_json_end', 0x1d6b462, '731f', 0x1d6b483, 'jcc'),
    ('address_json_trailing_outside', 0x1d6b471, '7757', 0x1d6b4ca, 'jcc'),
    ('address_json_error_call', 0x1d6b4f1, 'ff1511567704', 0x64e0b08, 'indirect'),
)

# The i-th pair is the selected next-element call and its presence guard.
ARRAY_ELEMENTS = (
    (0x2694e14, 0x2694e5f), (0x2694e74, 0x2694ebf),
    (0x2694ed5, 0x2694f20), (0x2694f36, 0x2694f88),
    (0x2694f9e, 0x2694feb), (0x2695001, 0x2695076),
    (0x269508d, 0x26950a1), (0x26950b8, 0x26950cc),
    (0x26950e3, 0x26950f7), (0x269510e, 0x2695122),
    (0x2695139, 0x269514d), (0x2695164, 0x2695178),
    (0x269518f, 0x26951a3), (0x26951ba, 0x26951ce),
    (0x26951e5, 0x26951f9), (0x2695210, 0x2695224),
    (0x269523b, 0x269524f), (0x2695266, 0x269527a),
    (0x2695291, 0x26952a5), (0x26952bc, 0x26952d0),
)

RELATIVE_SLOTS = {
    0x64df6c8: 0x1689420,
    0x64df6e8: 0x141e3a0,
    0x64eb138: 0x47642d0,
    0x64506c8: 0x2dd6d00,
    0x64df480: 0x6355830,
    0x64df490: 0x141e251,
    0x64df4a0: 0x635de30,
    0x64df4c0: 0x1680cab,
    0x64e01f8: 0x5bb59d0,
    0x64e08f8: 0x5c56b60,
    0x64e0f38: 0x5bb5650,
    0x64e0fd8: 0x5bb1a60,
    0x64e0fe8: 0x5bb2110,
    0x64e6eb8: 0x5a8d150,
    0x64e7058: 0x4771f70,
    0x64506e0: 0x2dd5c60,
    0x64506e8: 0x2d009f0,
    0x64506f0: 0x2d009f0,
    0x64e1e48: 0x167a9c0,
    0x64e2198: 0x2f1bce0,
    0x64e21b0: 0x2f1dfe0,
}

# Named ranges are exact lengths, not NUL-terminated strings.
REFERENCES = (
    ('method', 0x2a060b9, 0x602416, b'eth_getBalance'),
    ('descriptor', 0x2cff548, 0x64506c8, None),
    ('diagnostic_method', 0x2a2b8b0, 0x602cde, b'eth_balance'),
    ('diagnostic_source', 0x2a2b912, 0x4349eb, b'evm_rpc/src/evm_rpc.rs'),
    ('address_annotation', 0x2d00e04, 0x617eb9, b'address'),
    ('positional_error_title', 0x2d0fbb9, 0x6167a1, b'Invalid params'),
    ('address_type', 0x2d00e0b, 0x61735c, b'Address'),
    ('block_annotation', 0x2d00e83, 0x459c80, b'block_id'),
    ('block_type', 0x2d00e8a, 0x617e94, b'Option < BlockId >'),
    ('missing_address', 0x1f5d495, 0x5d287f, b'address'),
    ('duplicate_block', 0x1f5d523, 0x459c80, b'block_id'),
    ('duplicate_address', 0x1f5d54d, 0x5d287f, b'address'),
)

TOKENS = (
    b'z_forks/reth-chainspec',
    b'z_forks/reth-ethereum-forks',
    b'z_forks/reth-rpc-eth-types',
    b'z_forks/reth-rpc-server-types',
    b'z_forks/revm-precompile',
    b'z_vendor/revm',
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def authenticate(data, expected=NODE_SHA256):
    require(digest(data) == expected, 'input SHA-256 mismatch')


def map_offset(secs, va, size, *, executable=False):
    """Map an entire nonempty VA range uniquely to file-backed section bytes."""
    require(type(va) is int and type(size) is int and va >= 0 and size > 0,
            'invalid virtual address or length')
    require(va + size <= 1 << 64, 'address range overflow')
    matches = [s for s in secs if s['type'] != 8 and s['address'] <= va
               and va + size <= s['address'] + s['size']
               and (not executable or s['flags'] & 4)]
    require(len(matches) == 1, 'range has no unique file-backed section')
    sec = matches[0]
    return sec['offset'] + va - sec['address'], sec['name']


class Image:
    def __init__(self, data):
        self.data = data
        self.secs = sections(data)

    def offset(self, va, size, *, executable=False):
        offset, _ = map_offset(self.secs, va, size, executable=executable)
        require(offset + size <= len(self.data), 'range outside file')
        return offset

    def read(self, va, size, *, executable=False):
        offset = self.offset(va, size, executable=executable)
        return self.data[offset:offset + size]

    def section(self, name):
        found = [s for s in self.secs if s['name'] == name and s['type'] != 8]
        require(len(found) == 1, 'missing or duplicate file-backed section')
        return found[0]


def check_witness(actual, expected):
    require(actual == expected, 'selected byte witness changed')


def decode_transfer(va, raw):
    """Decode only the explicitly frozen rel32, rel8 and RIP-indirect forms."""
    require(bool(raw), 'empty transfer')
    if raw[0] in (0xe8, 0xe9):
        require(len(raw) == 5, 'bad rel32 transfer length')
        displacement = struct.unpack_from('<i', raw, 1)[0]
        kind = 'call' if raw[0] == 0xe8 else 'jmp'
    elif raw[0] == 0xeb or 0x70 <= raw[0] <= 0x7f:
        require(len(raw) == 2, 'bad rel8 transfer length')
        displacement = struct.unpack_from('<b', raw, 1)[0]
        kind = 'jmp' if raw[0] == 0xeb else 'jcc'
    elif len(raw) == 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        displacement = struct.unpack_from('<i', raw, 2)[0]
        kind = 'jcc'
    elif len(raw) == 6 and raw[:2] == b'\xff\x15':
        displacement = struct.unpack_from('<i', raw, 2)[0]
        kind = 'indirect'
    else:
        raise ValueError('unsupported transfer encoding')
    target = va + len(raw) + displacement
    require(0 <= target < 1 << 64, 'transfer target outside u64')
    return kind, target


def checked_transfer(va, raw, expected_raw, expected_target, expected_kind):
    check_witness(raw, bytes.fromhex(expected_raw))
    kind, target = decode_transfer(va, raw)
    require((kind, target) == (expected_kind, expected_target), 'transfer changed')
    return kind, target


def decode_lea(va, raw):
    require(len(raw) == 7 and raw[:2] in (b'\x48\x8d', b'\x4c\x8d')
            and raw[2] & 0xc7 == 0x05, 'unsupported RIP-relative LEA')
    return va + 7 + struct.unpack_from('<i', raw, 3)[0]


def selected_relocations(data, sec, wanted):
    require(sec['type'] == 4 and sec['size'] % 24 == 0, 'invalid RELA section')
    require(sec['offset'] + sec['size'] <= len(data), 'truncated RELA section')
    rows = {}
    for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, off)
        if slot in wanted:
            require(slot not in rows, 'duplicate selected relocation')
            require(info == 8 and addend == wanted[slot], 'selected relocation mismatch')
            rows[slot] = (off, info, addend, data[off:off + 24].hex())
    require(set(rows) == set(wanted), 'missing selected relocation')
    return rows




def dynamic_relocation(data, sec, slot):
    require(sec['type'] == 4 and sec['offset'] >= 0 and sec['size'] >= 0
            and sec['size'] % 24 == 0, 'invalid dynamic RELA section')
    require(sec['offset'] + sec['size'] <= len(data), 'truncated dynamic RELA section')
    found = []
    for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
        address, info, addend = struct.unpack_from('<QQq', data, off)
        if address == slot:
            found.append((off, info, addend, data[off:off + 24].hex()))
    require(len(found) == 1, 'missing or duplicate dynamic relocation')
    off, info, addend, raw = found[0]
    require(info & 0xffffffff == 6 and info >> 32 != 0 and addend == 0,
            'unexpected dynamic symbol relocation')
    return off, info >> 32, addend, raw


def dynamic_symbol(image, index):
    symbols, strings = image.section('.dynsym'), image.section('.dynstr')
    require(symbols['type'] == 11 and strings['type'] == 3 and index > 0, 'invalid dynamic symbol sections')
    entry_offset = symbols['offset'] + index * 24
    require(entry_offset + 24 <= symbols['offset'] + symbols['size'], 'dynamic symbol index outside table')
    name_offset = struct.unpack_from('<I', image.data, entry_offset)[0]
    require(name_offset < strings['size'], 'dynamic symbol name outside table')
    begin = strings['offset'] + name_offset
    end = image.data.find(b'\x00', begin, strings['offset'] + strings['size'])
    require(end >= 0, 'unterminated dynamic symbol name')
    try:
        name = image.data[begin:end].decode('ascii')
    except UnicodeDecodeError as exc:
        raise ValueError('non-ASCII dynamic symbol name') from exc
    return name, entry_offset, name_offset


def selected_bcmp(image):
    slot = 0x64df9f8
    offset, index, addend, record = dynamic_relocation(image.data, image.section('.rela.dyn'), slot)
    name, sym_offset, name_offset = dynamic_symbol(image, index)
    require(name == 'bcmp', 'dynamic symbol name changed')
    # The selected load puts the relocated pointer in r13; both calls use r13.
    load = image.read(0x476f2bd, 7, executable=True)
    check_witness(load[:3], bytes.fromhex('4c8b2d'))
    require(0x476f2bd + 7 + struct.unpack_from('<i', load, 3)[0] == slot,
            'comparison load does not name selected slot')
    calls = []
    for va in (0x476f368, 0x476f3a5):
        raw = image.read(va, 3, executable=True)
        check_witness(raw, bytes.fromhex('41ffd5'))
        calls.append((hex(va), hex(image.offset(va, 3, executable=True)), raw.hex()))
    return {'slot_va': hex(slot), 'slot_file_offset': hex(image.offset(slot, 8)),
            'rela_file_offset': hex(offset), 'rela_record_hex': record, 'symbol_index': index,
            'addend': addend, 'symbol_record_file_offset': hex(sym_offset),
            'symbol_name_offset': name_offset, 'symbol_name': name,
            'symbol_record_hex': image.data[sym_offset:sym_offset + 24].hex(),
            'symbol_name_file_offset': hex(image.section('.dynstr')['offset'] + name_offset),
            'symbol_name_hex': (name.encode('ascii') + b'\x00').hex(),
            'load_va': hex(0x476f2bd), 'load_hex': load.hex(), 'register_calls': calls}


def selected_expected_size(image):
    data = image.read(0x458dd8, 16)
    first, second = struct.unpack('<QQ', data)
    require((first, second) == (20, 40), 'expected-size data changed')
    literal = image.read(0x4307bb, 17)
    check_witness(literal, bytes.fromhex('0865786163746c7920c006206279746573'))
    return {'expected_data_va': hex(0x458dd8), 'expected_data_file_offset': hex(image.offset(0x458dd8, 16)),
            'data_hex': data.hex(), 'first_word': first, 'second_word': second,
            'format_va': hex(0x4307bb), 'format_file_offset': hex(image.offset(0x4307bb, 17)),
            'format_bytes': literal.hex(), 'limit': 'Literal formatting representation; final wire text is not established.'}


def element_wrapper_model(probe_tag, present, value_tag):
    require(probe_tag in (0, 1) and present in (0, 1) and value_tag in (0, 1),
            'invalid abstract wrapper state')
    if probe_tag == 1 or (present == 1 and value_tag == 1):
        return 1, None
    return 0, present


def descriptor_rows(image, relocations):
    """Read the selected data-table header and relocated callable slots."""
    base = decode_lea(0x2cff548, image.read(0x2cff548, 7, executable=True))
    require(base == 0x64506c8, 'descriptor address changed')
    size, alignment = struct.unpack('<QQ', image.read(base + 8, 16))
    require((size, alignment) == (8, 8), 'descriptor metadata changed')
    result = []
    for offset in range(0, 0x30, 8):
        va = base + offset
        raw = image.read(va, 8)
        value = struct.unpack('<Q', raw)[0]
        target = relocations[va][2] if va in relocations else None
        result.append((hex(offset), hex(va), hex(image.offset(va, 8)), raw.hex(),
                       value, '' if target is None else hex(target)))
    return result


def parameter_constants(image):
    sentinel_raw = image.read(0x2d00a22, 10, executable=True)
    check_witness(sentinel_raw[:2], bytes.fromhex('48b9'))
    check_witness(image.read(0x2d00a46, 5, executable=True), bytes.fromhex('41807d007b'))
    check_witness(image.read(0x2d00b27, 6, executable=True), bytes.fromhex('81f95b5d0000'))
    return struct.unpack_from('<Q', sentinel_raw, 2)[0], b'{', b'[]'


def parameter_shape(first_word, data, constants):
    require(type(first_word) is int and 0 <= first_word < 1 << 64, 'invalid input word')
    require(isinstance(data, bytes), 'input must be bytes')
    sentinel, object_first, empty_array = constants
    if first_word == sentinel:
        return 'sentinel_empty'
    if not data:
        return 'positional_empty'
    if data[:1] == object_first:
        return 'object'
    if data == empty_array:
        return 'positional_normalized_empty'
    return 'positional'


def positional_constants(image):
    """Read the positional-address cursor, whitespace and error immediates."""
    cursor = image.read(0x2d0f92c, 13, executable=True)
    check_witness(cursor, bytes.fromhex('83f82c742283f85b741d83f85d'))
    boundary = image.read(0x2d0f953, 18, executable=True)
    check_witness(boundary, bytes.fromhex('4983ff01740c41807c2401c00f8cb9020000'))
    whitespace = image.read(0x1d6b391, 10, executable=True)
    check_witness(whitespace[:2], bytes.fromhex('49b8'))
    mask = struct.unpack_from('<Q', whitespace, 2)[0]
    require(mask == 0x100002600, 'selected whitespace mask changed')
    first = image.read(0x2d0fb87, 10, executable=True)
    second = image.read(0x2d0fb95, 10, executable=True)
    check_witness(first[:2], bytes.fromhex('48b9'))
    check_witness(second[:2], bytes.fromhex('48b9'))
    require(first[2:4] == second[8:10], 'message chunks do not overlap')
    msg = bytearray(14)
    msg[6:14] = first[2:]
    msg[0:8] = second[2:]
    check_witness(bytes(msg), b'No more params')
    raw_code = image.read(0x2d0fbcd, 5, executable=True)
    check_witness(raw_code[:1], b'\xbe')
    code = struct.unpack_from('<i', raw_code, 1)[0]
    require(code == -32602, 'selected error-code immediate changed')
    count = image.read(0x2d0fbc5, 5, executable=True)
    check_witness(count, bytes.fromhex('b90e000000'))
    title = image.read(0x6167a1, 14)
    check_witness(title, b'Invalid params')
    return {
        'comma': cursor[2], 'open': cursor[7], 'close': cursor[12],
        'continuation_upper': boundary[11], 'whitespace_mask': mask,
        'error_title': title.decode('ascii'),
        'error_body': bytes(msg).decode('ascii'), 'error_code_i32': code,
        'title_length': struct.unpack_from('<I', count, 1)[0],
        'message_immediates_hex': [first.hex(), second.hex()],
        'error_code_instruction_hex': raw_code.hex(),
        'whitespace_instruction_hex': whitespace.hex(),
        'cursor_instruction_hex': cursor.hex(),
        'cursor_va': '0x2d0f92c', 'whitespace_va': '0x1d6b391',
        'error_call_va': '0x2d0fbd2', 'error_builder_va': '0x25cd880',
        'limits': 'Helper-local branches only; error builder and wire response are unresolved.',
    }


def positional_model(data, constants):
    """Model selected pre-parser branches for an already selected cursor."""
    require(isinstance(data, bytes), 'cursor input must be bytes')
    if not data:
        return 'no_more_params'
    if data[0] == constants['close']:
        return 'closing_delimiter_no_more_params'
    if data[0] not in (constants['comma'], constants['open']):
        return 'unexpected_delimiter_formatter'
    if len(data) > 1 and 0x80 <= data[1] < constants['continuation_upper']:
        return 'slice_boundary_helper'
    rest = data[1:]
    mask = constants['whitespace_mask']
    i = 0
    while i < len(rest) and rest[i] <= 0x22 and (mask >> rest[i]) & 1:
        i += 1
    if i == len(rest):
        return 'nested_empty_no_more_params'
    if rest[i] in (ord('"'), ord('['), ord('{')):
        return 'nested_address_composite'
    return 'nested_address_other'


def field_names(image):
    """Reconstruct the three compared names from instruction immediates."""
    a = image.read(0x1f5d008, 4, executable=True)
    b = image.read(0x1f5d013, 4, executable=True)
    c = image.read(0x1f5d026, 4, executable=True)
    d = image.read(0x1f5d031, 4, executable=True)
    snake = image.read(0x1f5d0a2, 8, executable=True)
    require(a[-1:] == b[:1] and c[-1:] == d[:1], 'field chunks do not overlap')
    names = (a + b[1:], c + d[1:], snake)
    require(names == (b'address', b'blockId', b'block_id'), 'field literals changed')
    return names


def classify_field(value, names):
    if value == names[0]:
        return 'address'
    if value == names[1] or value == names[2]:
        return 'block'
    return 'other'


def field_flow(fields, names):
    """Model only successful nested values and successful unknown-value skipping."""
    address = block = False
    for value in fields:
        kind = classify_field(value, names)
        if kind == 'address':
            if address:
                return 'duplicate_address'
            address = True
        elif kind == 'block':
            if block:
                return 'duplicate_block'
            block = True
    if not address:
        return 'missing_address'
    return 'address_and_block' if block else 'address_default_block'



def selected_array_elements(image):
    """Decode each selected element-call and presence-failure immediate."""
    rows = []
    for ordinal, (call_va, guard_va) in enumerate(ARRAY_ELEMENTS):
        call = image.read(call_va, 5, executable=True)
        kind, callee = decode_transfer(call_va, call)
        require(kind == 'call' and callee == (0x1dbe700 if ordinal < 6 else 0x1dc1b20),
                'array element call changed')
        check_witness(image.read(guard_va - 5, 5, executable=True), bytes.fromhex('807c240101'))
        guard = image.read(guard_va, 6, executable=True)
        require(guard[:2] == b'\x0f\x85', 'array presence branch changed')
        kind, fail = decode_transfer(guard_va, guard)
        check_witness(image.read(fail, 2 if ordinal == 0 else 1, executable=True),
                      b'\x31\xff' if ordinal == 0 else b'\xbf')
        encoded = 0 if ordinal == 0 else struct.unpack('<I', image.read(fail + 1, 4, executable=True))[0]
        require(encoded == ordinal, 'array missing-index immediate changed')
        rows.append((ordinal, hex(call_va), hex(image.offset(call_va, 5, executable=True)),
                     call.hex(), hex(callee), hex(guard_va), guard.hex(), hex(fail), encoded))
    return rows


def array_output_stores(image):
    """Record five register stores and fifteen stack-byte stores."""
    result = []
    register_writes = ((0x2695408, '40886b01'), (0x269540c, '44887b02'),
                       (0x2695410, '44886303'), (0x2695414, '44886b04'),
                       (0x2695418, '44887305'))
    for ordinal, (va, frozen) in enumerate(register_writes):
        raw = image.read(va, 4, executable=True)
        check_witness(raw, bytes.fromhex(frozen))
        require(raw[-1] == ordinal + 1, 'register output offset changed')
        result.append((ordinal, hex(va), hex(image.offset(va, 4, executable=True)),
                       raw.hex(), 'register', '', raw[-1]))
    for ordinal in range(5, 20):
        load_va = 0x269541c + 8 * (ordinal - 5)
        load = image.read(load_va, 5, executable=True)
        store = image.read(load_va + 5, 3, executable=True)
        require(load[:4] == bytes.fromhex('0fb64424') and load[4] == 0x2f - (ordinal - 5),
                'stack-byte input changed')
        require(store[:2] == bytes.fromhex('8843') and store[2] == ordinal + 1,
                'stack-byte output changed')
        result.append((ordinal, hex(load_va + 5), hex(image.offset(load_va + 5, 3, executable=True)),
                       store.hex(), 'stack', hex(load[4]), store[2]))
    return result


def address_dispatch(image):
    """Read the selected 33-entry relative jump table from file bytes."""
    table_va = 0x600520
    require(digest(image.read(table_va, 33 * 4)) ==
            '66f100f21b9dc8fba2370fa1e3f6b0495a4f8a2aa094d6022a62096deb2da710',
            'address dispatch bytes changed')
    rows = []
    for i in range(33):
        va = table_va + 4 * i
        raw = image.read(va, 4)
        target = table_va + struct.unpack('<i', raw)[0]
        require(0x298d2f0 <= target < 0x298d9a7, 'dispatch target outside selected FDE')
        rows.append((hex(i + 0x5b), hex(va), hex(image.offset(va, 4)), raw.hex(), hex(target)))
    require(dict((int(x[0], 16), int(x[4], 16)) for x in rows)[ord('[')] == 0x298d3e7,
            'array dispatch target changed')
    return rows


def array_model(states, extra):
    """Branch model with normal child/cleanup returns; not a JSON parser."""
    require(len(states) == len(ARRAY_ELEMENTS), 'expected twenty abstract probe states')
    require(all(x in ('present', 'absent', 'error') for x in states), 'invalid element state')
    require(extra in ('present', 'absent', 'error'), 'invalid extra-probe state')
    for i, state in enumerate(states):
        if state == 'error':
            return 'propagate_element_error', i
        if state == 'absent':
            return 'length_argument', i
    if extra == 'present':
        return 'length_argument', len(ARRAY_ELEMENTS) + 1
    return ('success_after_cleanup' if extra == 'error' else 'success'), None


def read_guard_constants(image):
    check_witness(image.read(0x2a3e498, 3, executable=True), bytes.fromhex('83e108'))
    check_witness(image.read(0x2a3e49e, 4, executable=True), bytes.fromhex('4883f8f0'))
    check_witness(image.read(0x2a3e4bb, 4, executable=True), bytes.fromhex('488d4810'))
    check_witness(image.read(0x2a3e8be, 4, executable=True), bytes.fromhex('4883e0f2'))
    check_witness(image.read(0x2a3e8c2, 4, executable=True), bytes.fromhex('4883f812'))
    bit = image.read(0x2a3e49a, 1, executable=True)[0]
    threshold = (1 << 64) + struct.unpack('b', image.read(0x2a3e4a1, 1, executable=True))[0]
    increment = image.read(0x2a3e4be, 1, executable=True)[0]
    mask = ((1 << 64) + struct.unpack('b', image.read(0x2a3e8c1, 1, executable=True))[0])
    wake = image.read(0x2a3e8c5, 1, executable=True)[0]
    return bit, threshold, increment, mask, wake


def acquire_model(old, cas_ok, constants):
    bit, threshold, increment, _, _ = constants
    require(0 <= old < 1 << 64 and type(cas_ok) is bool, 'invalid guard input')
    if old & bit or old >= threshold or not cas_ok:
        return 'slow', None
    return 'fast', old + increment


def release_model(old, constants):
    require(0 <= old < 1 << 64, 'invalid guard input')
    _, _, increment, mask, wake = constants
    return (old - increment) % (1 << 64), (old & mask) == wake




def selected_layout(image):
    """Extract selected structure displacements and scalar immediates."""
    patterns = (
        (0x2a3e488, '4d8da6a8060000'),
        (0x2a3e541, 'be981c0000'),
        (0x2a3e546, '4903b6000b0000'),
        (0x2a3e996, '4181be2801000000ca9a3b'),
        (0x2a3e9a8, '4983c628'),
        (0x4771f86, 'f00fb00f'),
        (0x4772061, 'f20f1041f0'),
        (0x4772066, 'f20f58c3'),
        (0x477211c, '488951e8'),
        (0x4772133, 'f20f1149f0'),
        (0x4772138, 'f20f1041f8'),
        (0x477213d, 'f20f5fc3'),
        (0x4772141, 'f20f1141f8'),
        (0x477214a, 'f00fb00b'),
    )
    for va, expected in patterns:
        check_witness(image.read(va, len(bytes.fromhex(expected)), executable=True), bytes.fromhex(expected))
    dword = lambda va: struct.unpack('<I', image.read(va, 4, executable=True))[0]
    sbyte = lambda va: struct.unpack('<b', image.read(va, 1, executable=True))[0]
    return {
        'account_guard_context_offset': dword(0x2a3e48b),
        'account_state_base_context_offset': dword(0x2a3e549),
        'account_state_inner_offset': dword(0x2a3e542),
        'metric_gate_context_offset': dword(0x2a3e999),
        'metric_gate_constant': dword(0x2a3e99d),
        'metric_object_context_offset': image.read(0x2a3e9ab, 1, executable=True)[0],
        'metric_count_entry_end_offset_signed': sbyte(0x477211f),
        'metric_sum_entry_end_offset_signed': sbyte(0x4772137),
        'metric_max_entry_end_offset_signed': sbyte(0x4772145),
        'metric_lock_bytes': image.read(0x4771f86, 4, executable=True).hex(),
        'metric_unlock_bytes': image.read(0x477214a, 4, executable=True).hex(),
        'metric_sum_add_bytes': image.read(0x4772066, 4, executable=True).hex(),
        'metric_max_instruction_bytes': image.read(0x477213d, 4, executable=True).hex(),
    }


def metric_count_model(old):
    """The selected INC/CMOVNE sequence on one unsigned 64-bit count."""
    require(type(old) is int and 0 <= old < 1 << 64, 'invalid metric count')
    new = (old + 1) % (1 << 64)
    return new if new else (1 << 64) - 1


def outcome_model(tag, subtag, auxiliary_word, payload):
    """Selected caller tag branches only; backend provenance is not inferred."""
    require(tag in (0, 1, 2), 'unsupported tag')
    require(0 <= subtag < 1 << 64 and 0 <= auxiliary_word < 1 << 64,
            'invalid selected result inputs')
    require(len(payload) == 32, 'payload must be 32 bytes')
    if tag == 1:
        return 'copy', 'none', payload
    if tag == 0:
        return 'zero', 'none', bytes(32)
    if subtag == 2:
        require(auxiliary_word != 0, 'indirect cleanup requires a nonzero word')
    cleanup = ('none' if subtag < 2 else
               'indirect_drop' if subtag == 2 else
               'deallocate' if auxiliary_word else 'none')
    return 'zero', cleanup, bytes(32)


def tsv(header, rows):
    out = io.StringIO(newline='')
    writer = csv.writer(out, delimiter='\t', lineterminator='\n')
    writer.writerow(header)
    writer.writerows(rows)
    return out.getvalue().encode('ascii')


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + '\n').encode('ascii')


def table_record_bytes(image, va):
    prefix = image.read(va, 4)
    length = struct.unpack('<I', prefix)[0]
    require(length not in (0, 0xffffffff) and length < 1 << 20, 'unsupported frame length')
    return image.read(va, 4 + length)




def parse_lsda(data, offset, limit, function_start, function_end):
    """Decode only selected LPStart-omitted, ULEB call-site records.

    The type and action tables are not decoded. Coordinates use the FDE start
    because these selected records omit LPStart.
    """
    require(0 <= offset < limit <= len(data) and function_start < function_end,
            'invalid exception-table bounds')
    begin = offset
    require(offset + 2 <= limit, 'truncated exception-table header')
    lp_encoding, type_encoding = data[offset], data[offset + 1]
    offset += 2
    require(lp_encoding == 0xff and type_encoding in (0xff, 0x9b),
            'unsupported exception-table pointer encoding')
    type_base = None
    if type_encoding != 0xff:
        type_delta, offset = uleb(data, offset, limit)
        type_base = offset + type_delta
        require(type_base <= limit, 'exception type table outside section')
    require(offset < limit and data[offset] == 1, 'unsupported call-site encoding')
    offset += 1
    length, offset = uleb(data, offset, limit)
    table_begin, table_end = offset, offset + length
    require(table_end <= limit and (type_base is None or table_end <= type_base),
            'truncated exception call-site table')
    rows = []
    while offset < table_end:
        entry_start = offset
        values = []
        for _ in range(4):
            value, offset = uleb(data, offset, table_end)
            values.append(value)
        first, span, landing, action = values
        require(first + span <= function_end - function_start, 'exception range outside FDE')
        require(not landing or landing < function_end - function_start, 'landing pad outside FDE')
        rows.append((first, span, landing, action, data[entry_start:offset].hex()))
    return {'header_hex': data[begin:table_begin].hex(), 'table_hex': data[table_begin:table_end].hex(),
            'type_encoding': type_encoding, 'type_base_file_offset': type_base,
            'table_file_offset': table_begin, 'table_size': length}, rows


def selected_frame(start, starts, by_fde):
    require(start in starts, 'selected unwind start missing')
    entry = starts[start]
    require(entry['fde'] in by_fde, 'selected FDE missing')
    fde = by_fde[entry['fde']]
    require(fde['start'] == start and fde['end'] > start, 'selected FDE start mismatch')
    return entry, fde


def find_fork_tokens(image):
    ro = image.section('.rodata')
    data = image.data[ro['offset']:ro['offset'] + ro['size']]
    rows = []
    for token in TOKENS:
        start = 0
        while True:
            i = data.find(token, start)
            if i < 0:
                break
            rows.append((token.decode('ascii'), hex(ro['address'] + i),
                         hex(ro['offset'] + i), image.read(ro['address'] + i, len(token)).hex()))
            start = i + 1
    return rows


def public_fork_context():
    manifest = (ROOT / 'upstream/hyper-evm-sync/Cargo.toml').read_bytes()
    lock = (ROOT / 'upstream/hyper-evm-sync/Cargo.lock').read_bytes()
    require(digest(manifest) == SYNC_TOML_SHA256, 'public manifest SHA-256 mismatch')
    require(digest(lock) == SYNC_LOCK_SHA256, 'public lockfile SHA-256 mismatch')
    deps = tomllib.loads(manifest.decode('utf-8'))['dependencies']
    packages = tomllib.loads(lock.decode('utf-8'))['package']
    wanted = ('reth-ethereum-forks', 'reth-primitives', 'revm', 'revm-precompile')
    return {
        'manifest_path': 'upstream/hyper-evm-sync/Cargo.toml',
        'manifest_sha256': digest(manifest),
        'lock_path': 'upstream/hyper-evm-sync/Cargo.lock',
        'lock_sha256': digest(lock),
        'manifest_dependencies': {name: deps[name] for name in ('reth-primitives', 'revm', 'alloy')},
        'selected_lock_packages': sorted(
            ({k: p[k] for k in ('name', 'version', 'source') if k in p}
             for p in packages if p['name'] in wanted),
            key=lambda p: (p['name'], p['version'], p.get('source', ''))),
        'limit': 'These public sync-project dependencies do not identify the private node build.',
    }


def collect(data):
    authenticate(data)
    image = Image(data)
    secs, index = unwind_index(data)
    _, fdes = eh_frame_records(data, secs)
    by_fde = {f['fde']: f for f in fdes}
    starts = {entry['start']: entry for entry in index}
    require(len(by_fde) == len(fdes), 'duplicate FDE address')
    header = image.section('.eh_frame_hdr')
    rows = []
    selected = []
    selected_frames = []
    for role, start in FUNCTIONS:
        entry, fde = selected_frame(start, starts, by_fde)
        length = fde['end'] - start
        body = image.read(start, length, executable=True)
        fde_bytes = table_record_bytes(image, fde['fde'])
        cie_bytes = table_record_bytes(image, fde['cie'])
        hdr_off = header['offset'] + 12 + 8 * entry['index']
        require(hdr_off + 8 <= header['offset'] + header['size'], 'unwind index outside section')
        rows.append((role, hex(start), hex(fde['end']), hex(image.offset(start, length, executable=True)),
                     length, hex(fde['fde']), hex(image.offset(fde['fde'], len(fde_bytes))),
                     hex(fde['cie']), hex(fde['lsda']) if fde['lsda'] is not None else '',
                     entry['index'], hex(hdr_off), data[hdr_off:hdr_off+8].hex(),
                     fde_bytes.hex(), cie_bytes.hex(), digest(body)))
        selected.append((start, fde['end'], role))
        selected_frames.append((role, dict(fde)))
    del fdes, by_fde, index, starts

    except_section = image.section('.gcc_except_table')
    except_limit = except_section['offset'] + except_section['size']
    lsda_headers, lsda_rows = [], []
    for role, fde in selected_frames:
        if fde['lsda'] is None:
            continue
        va = fde['lsda']
        off = image.offset(va, 1)
        require(except_section['offset'] <= off < except_limit, 'LSDA outside exception section')
        header_row, entries = parse_lsda(data, off, except_limit, fde['start'], fde['end'])
        lsda_headers.append((role, hex(va), hex(off), hex(header_row['type_encoding']),
            '' if header_row['type_base_file_offset'] is None else hex(header_row['type_base_file_offset']),
            hex(header_row['table_file_offset']), header_row['table_size'], header_row['header_hex'],
            header_row['table_hex'], len(entries)))
        for index, (first, span, landing, action, raw) in enumerate(entries):
            lsda_rows.append((role, index, hex(fde['start'] + first), hex(fde['start'] + first + span),
                '' if not landing else hex(fde['start'] + landing), action, raw))

    window_rows = []
    for label, va, expected in WINDOWS:
        frozen = bytes.fromhex(expected)
        actual = image.read(va, len(frozen), executable=True)
        check_witness(actual, frozen)
        owner = next((role for a, b, role in selected if a <= va and va + len(actual) <= b), None)
        require(owner is not None or label == 'route_name', 'window outside selected extent')
        window_rows.append((label, hex(va), hex(image.offset(va, len(actual), executable=True)),
                            owner or 'shared_router_boundary', len(actual), actual.hex()))

    transfer_rows = []
    for label, va, expected, target, kind in TRANSFERS:
        actual = image.read(va, len(bytes.fromhex(expected)), executable=True)
        actual_kind, actual_target = checked_transfer(va, actual, expected, target, kind)
        image.offset(actual_target, 1, executable=actual_kind != 'indirect')
        owner = next((role for a, b, role in selected if a <= va and va + len(actual) <= b), None)
        require(owner is not None or label == 'register_name', 'transfer outside selected extent')
        transfer_rows.append((label, hex(va), hex(image.offset(va, len(actual), executable=True)),
                              owner or 'shared_router_boundary', actual.hex(), actual_kind, hex(actual_target)))

    rels = selected_relocations(data, image.section('.rela.dyn'), RELATIVE_SLOTS)
    descriptors = descriptor_rows(image, rels)
    relocation_rows = []
    for slot in sorted(rels):
        off, info, addend, raw = rels[slot]
        image.offset(addend, 1, executable=True)
        relocation_rows.append((hex(slot), hex(image.offset(slot, 8)), image.read(slot, 8).hex(),
                                hex(off), hex(info), hex(addend), raw))

    references = []
    for label, va, target, literal in REFERENCES:
        raw = image.read(va, 7, executable=True)
        found = decode_lea(va, raw)
        require(found == target, 'RIP-relative reference mismatch')
        target_bytes = image.read(found, len(literal) if literal is not None else 8)
        if literal is not None:
            check_witness(target_bytes, literal)
        references.append((label, hex(va), hex(image.offset(va, 7, executable=True)), raw.hex(),
                           hex(found), hex(image.offset(found, len(target_bytes))),
                           target_bytes.hex(), literal.decode('ascii') if literal is not None else ''))
    route_length = image.read(0x2a060c8, 5, executable=True)
    check_witness(route_length, bytes.fromhex('b90e000000'))
    require(struct.unpack_from('<I', route_length, 1)[0] == len(b'eth_getBalance'), 'route length mismatch')

    params_constants = parameter_constants(image)
    parameter_rows = []
    inputs = (b'', b'{}', b'[]', b'[ ]', b'  {}', b'null', b'{', b'[] ', b'\x00')
    for word in (0, params_constants[0]):
        for value in inputs:
            parameter_rows.append((hex(word), value.hex(), len(value),
                                   parameter_shape(word, value, params_constants)))
    positional = positional_constants(image)
    positional_inputs = (b'', b']', b']more', b'[', b',', b'[ ', b'[\t\n\r ',
                         b'["', b'[{', b'[[', b'[0', b'[null', b'x', b' [',
                         b'[\x7f', b'[\x80', b'[\xbf', b'[\xc0', b'[\xff')
    positional_rows = [(value.hex(), len(value), positional_model(value, positional))
                       for value in positional_inputs]
    names = field_names(image)
    mutations = [(name, name, 'original') for name in names]
    for name in names:
        for i, original in enumerate(name):
            for replacement in range(256):
                if replacement != original:
                    mutations.append((name, name[:i] + bytes([replacement]) + name[i+1:], str(i)))
    field_rows = [(source.hex(), candidate.hex(), position, classify_field(candidate, names))
                  for source, candidate, position in mutations]
    variants = names + (b'other',)
    flows = []
    for length in range(5):
        for seq in itertools.product(variants, repeat=length):
            flows.append((','.join(x.decode('ascii') for x in seq), field_flow(seq, names)))

    constants = read_guard_constants(image)
    values = sorted({0, 1, 2, 7, 8, 15, 16, 17, 18, 19, 30, 31, 32,
                     (1 << 63) - 1, 1 << 63, constants[1] - 1,
                     constants[1], constants[1] + 1, (1 << 64) - 1})
    guard_rows = []
    for old in values:
        for cas_ok in (False, True):
            path, new = acquire_model(old, cas_ok, constants)
            released, wake = release_model(old, constants)
            guard_rows.append((hex(old), int(cas_ok), path, '' if new is None else hex(new),
                               hex(released), int(wake)))

    payloads = (bytes(32), bytes(range(32)))
    outcome_rows = []
    for tag, subtag, word, payload in itertools.product((0, 1, 2), (0, 1, 2, 3, 4), (0, 1), payloads):
        if tag == 2 and subtag == 2 and word == 0:
            continue
        result, cleanup, value = outcome_model(tag, subtag, word, payload)
        outcome_rows.append((tag, subtag, word, payload.hex(), result, cleanup, value.hex()))

    array_elements = selected_array_elements(image)
    array_stores = array_output_stores(image)
    dispatch = address_dispatch(image)
    check_witness(image.read(0x26952e9, 5, executable=True), bytes.fromhex('e832c872ff'))
    check_witness(image.read(0x26954aa, 5, executable=True), bytes.fromhex('bf15000000'))
    array_cases = []
    for i in range(len(ARRAY_ELEMENTS)):
        for state in ('absent', 'error'):
            states = ['present'] * len(ARRAY_ELEMENTS)
            states[i] = state
            result, argument = array_model(states, 'absent')
            array_cases.append((i, state, 'absent', result, '' if argument is None else argument))
    for extra_state in ('absent', 'present', 'error'):
        result, argument = array_model(['present'] * len(ARRAY_ELEMENTS), extra_state)
        array_cases.append(('', 'all_present', extra_state, result, '' if argument is None else argument))

    check_witness(image.read(0x477210e, 18, executable=True),
                  bytes.fromhex('48ffc648c7c2ffffffff480f45d6488951e8'))
    bcmp = selected_bcmp(image)
    expected_size = selected_expected_size(image)
    option_rows = []
    for probe_tag, present, value_tag in itertools.product((0, 1), repeat=3):
        result_tag, result_present = element_wrapper_model(probe_tag, present, value_tag)
        option_rows.append((probe_tag, present, value_tag, result_tag,
                            '' if result_present is None else result_present))
    layout = selected_layout(image)
    count_cases = [0, 1, 2, 0x7fffffffffffffff, 0xfffffffffffffffe, 0xffffffffffffffff]
    metric_rows = [(hex(old), hex(metric_count_model(old))) for old in count_cases]

    fork_rows = find_fork_tokens(image)
    public = public_fork_context()
    summary = {
        'target': 'Linux x86-64 node 115', 'binary_sha256': digest(data),
        'binary_size': len(data), 'coordinates': 'linked ELF virtual addresses; zero-based file offsets; exclusive FDE ends',
        'selected_fde_count': len(rows), 'selected_window_count': len(window_rows),
        'selected_transfer_count': len(transfer_rows), 'selected_relative_relocation_count': len(relocation_rows),
        'selected_rip_reference_count': len(references), 'fork_token_occurrences': len(fork_rows),
        'field_name_vectors': len(field_rows), 'field_flow_vectors': len(flows),
        'guard_vectors': len(guard_rows), 'result_tag_vectors': len(outcome_rows),
        'array_element_count': len(array_elements), 'array_output_store_count': len(array_stores),
        'array_case_vectors': len(array_cases), 'address_dispatch_entries': len(dispatch),
        'parameter_shape_vectors': len(parameter_rows), 'descriptor_slots': len(descriptors),
        'positional_cursor_vectors': len(positional_rows),
        'metric_count_vectors': len(metric_rows), 'element_wrapper_vectors': len(option_rows),
        'selected_lsda_headers': len(lsda_headers), 'selected_lsda_call_sites': len(lsda_rows),
        'limits': 'Selected static witnesses and conditional synthetic models; no target execution or whole-node coverage.',
    }
    files = {
        'functions.tsv': tsv(('role','start_va','end_va_exclusive','file_offset','size','fde_va',
            'fde_file_offset','cie_va','lsda_va','unwind_index','unwind_file_offset','unwind_bytes',
            'fde_bytes','cie_bytes','body_sha256'), rows),
        'lsda-headers.tsv': tsv(('role','lsda_va','lsda_file_offset','type_encoding','type_base_file_offset',
            'call_table_file_offset','call_table_size','header_hex','call_table_hex','entries'), lsda_headers),
        'lsda-call-sites.tsv': tsv(('role','index','start_va','end_va_exclusive','landing_va','action','bytes_hex'), lsda_rows),
        'windows.tsv': tsv(('label','va','file_offset','owner','size','bytes_hex'), window_rows),
        'transfers.tsv': tsv(('label','va','file_offset','owner','bytes_hex','kind','target_or_slot_va'), transfer_rows),
        'relocations.tsv': tsv(('slot_va','slot_file_offset','slot_file_bytes','rela_file_offset','info','addend_va','record_hex'), relocation_rows),
        'descriptor.tsv': tsv(('offset','slot_va','file_offset','file_bytes','file_value','rela_addend_va'), descriptors),
        'parameter-cases.tsv': tsv(('first_word','input_hex','input_length','selected_path'), parameter_rows),
        'positional-cases.tsv': tsv(('cursor_hex','cursor_length','selected_helper_path'), positional_rows),
        'positional-error.json': json_bytes(positional),
        'references.tsv': tsv(('label','instruction_va','instruction_file_offset','instruction_bytes','target_va',
            'target_file_offset','target_bytes','literal'), references),
        'field-names.tsv': tsv(('source_hex','candidate_hex','changed_position','selected_class'), field_rows),
        'field-flows.tsv': tsv(('sequence','conditional_result'), flows),
        'guard-vectors.tsv': tsv(('old_word','cas_success','acquire_path','fast_new_word','release_word','wake'), guard_rows),
        'result-vectors.tsv': tsv(('tag','subtag','auxiliary_word','input_payload_hex','path','cleanup','output_hex'), outcome_rows),
        'array-elements.tsv': tsv(('index','call_va','call_file_offset','call_bytes','callee_va',
            'presence_guard_va','guard_bytes','missing_target_va','length_argument'), array_elements),
        'array-stores.tsv': tsv(('index','store_va','store_file_offset','store_bytes','source_kind',
            'stack_offset','output_offset'), array_stores),
        'array-vectors.tsv': tsv(('index','element_state','extra_state','conditional_result','length_argument'), array_cases),
        'address-dispatch.tsv': tsv(('byte','entry_va','file_offset','relative_bytes','target_va'), dispatch),
        'metric-count-vectors.tsv': tsv(('old_count','selected_new_count'), metric_rows),
        'fork-tokens.tsv': tsv(('token','va','file_offset','token_bytes_hex'), fork_rows),
        'public-forks.json': json_bytes(public),
        'selected-layout.json': json_bytes(layout),
        'comparison-symbol.json': json_bytes(bcmp),
        'expected-size.json': json_bytes(expected_size),
        'element-wrapper-vectors.tsv': tsv(('probe_tag','present','value_tag','result_tag','result_present'), option_rows),
        'summary.json': json_bytes(summary),
    }
    return files, summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    data = BINARY.read_bytes()
    files, summary = collect(data)
    args.out.mkdir(parents=True, exist_ok=True)
    for name in sorted(files):
        (args.out / name).write_bytes(files[name])
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, struct.error, KeyError) as exc:
        print('re011_balance_read115:', exc, file=sys.stderr)
        raise SystemExit(1)
