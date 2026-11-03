#!/usr/bin/env python3
"""Extract selected node 115 ABCI keyed-result and root-handoff evidence.

This is a static reader. It never executes the captured ELF or another program.
Selected instructions are byte-for-byte pins, not a general x86 disassembler.
"""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

TARGET = ROOT / 'artifacts/node/115/hl-node'
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
HISTORICAL_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

FDE_SPECS = (
    ('materializer_future', 0x2adce40, 0x2ae00f8, '6804363ad4a709ada550b882a2a82c2dfff253f11864c9e2a75962fd95581072'),
    ('item_loop', 0x2706500, 0x2706847, '46c24f8f2291daa513518c454663138b7fee67a916319835a142c0a93d02b662'),
    ('result_allocator', 0x231b9c0, 0x231bac6, '831c61823e563debca6fadb3c063e01a2e6dc2a9f4204aba58c562fd5a227e7c'),
    ('record_loop', 0x2705280, 0x27058e0, 'e1d200d5959e2e7978c36edfe16da2735b7a0e55b577bf3513189ad2982f7355'),
    ('location_handler', 0x22ec9b0, 0x22ed1ec, '4b5c86979d048ab4416fef11ac1aae00e132d08a1bbcd68f66731b249035acdd'),
    ('tag_dispatch', 0x2c766e0, 0x2c767c9, '60b5a595c5de53b8d6d66c28d973368ece0efaf2d632c151a9c7ec9a12e4e359'),
    ('action_result', 0x2c69220, 0x2c69793, '7d176d11a5646afffc94afa92ff01a259e2a93c2e70c42946b424a17dc5295ee'),
    ('keyed_probe', 0x26fe6d0, 0x26fe80c, '37355f3f2f6df4d1bf03135a19669a4bc5e6e81192a64f89525f4b1a225611ba'),
    ('keyed_insert', 0x26f6bd0, 0x26f6fee, 'be79d36d0450757533a74737aaf5b60141f4e77abd7a11264f1bf8e62a1623c7'),
    ('key_hash', 0x2b6e540, 0x2b6e6ab, '9a965fdd0e713d4e961e730dff4c6ef165a65b2ae29d6be2615db6516c11f15f'),
    ('hash_update', 0x2b41610, 0x2b417e7, '2de0e4e06f65af3f729cc6b2a4d12d7dcbbcb25902272a15c5f238c5096ed8b0'),
    ('root_map_visitor', 0x46a4900, 0x46a4b8f, 'c546af96941f6edd0ada898c2de57d3ea4a999198e8eb9973c941a565d0ee052'),
    ('root_map_constructor', 0x46a0fb0, 0x46a1001, 'fd738852befff5cfdb682785bfb6e093eca602596733ea84538b2ef663709f58'),
    ('root_value_visitor', 0x4307310, 0x430762b, '9c5406abd0eb651233a53116e804015ec356b3486ac0b8110be036a197e1e1d9'),
    ('root_value_constructor', 0x4307290, 0x4307309, 'cd83fee151b51f96a6adf7771b6ecb4b79cb95d08648bc7173cb264f0ceb5003'),
)
WINDOW_SPECS = (
    ('context', 'prior_loader_location', 0x3c1352f, '488d1572328602'),
    ('context', 'prior_loader_materializer', 0x3c135bc, '4889d74889c2ff15d83d8d024889c231c0'),
    ('context', 'wrapper_future', 0x2af4782, '4c8db390000000488dbc24f80200004c89f64c89e2e8a486feff48b80000000000000080488d4804b00348398c24f80200000f844206000066c783890000000101f30f6f8424f8020000f30f7f4358488b84240803000048894368'),
    ('context', 'wrapper_select', 0x2af49a0, '498b074889c148ba00000000000000804831d14885c0b802000000480f48c1488d48fe4883f902734d488b4424184c8b38410fb647104d8d77184d89f58844242084c04c897424080f8553010000498b0689c183e108c1e9034883f8f00f93c208ca747b4c89f731f6b900ca9a3bff15c4c59e03eb784885c07545'),
    ('context', 'wrapper_pointer', 0x2af4a60, 'c6838a000000004c8b7b6049bd0000000000000080e98c070000'),
    ('context', 'wrapper_saved', 0x2af523a, '4c897c2410450fb6bf9a0b0000'),
    ('context', 'wrapper_return', 0x2af5c06, '488db424600a0000ba080300004889efff15ec989e03c6850803000001488b44241048898580030000'),
    ('context', 'parent_copy', 0x2b42442, '488dbc2430040000488d742470bab8030000ff15aed09903'),
    ('context', 'parent_extract', 0x2b4246b, '488b8424b007000048894350'),
    ('context', 'parent_reload', 0x2b42521, '488b43284c8b7b50'),
    ('context', 'parent_base', 0x2b42539, '4c8dab80000000'),
    ('context', 'parent_store', 0x2b42597, '4c89bba0030000'),
    ('context', 'parent_task', 0x2b425ee, '4c8d7c2470ba500300004c89ff4c89eeff1504cf99034c89a3e00300004889abe8030000488d353f4b90034c89ffe87f85ffff'),
    ('context', 'constructor_arg', 0x2b3abef, '4c89f6'),
    ('context', 'constructor_copy', 0x2b3ac28, '488dbc24f40400004c8b35d1489a03ba5003000041ffd6'),
    ('selected', 'future_materializer', 0x2add94d, '488d9424780200004c89f74c89e6ff153f9aa00348898390000000'),
    ('selected', 'future_tag_min', 0x2addded, '49be0000000000000080'),
    ('selected', 'future_result_pointer', 0x2addf6b, 'c683890f0000004c8bbb9000000049ffc6c683890f000000e944f9ffff'),
    ('selected', 'future_output', 0x2add8cc, '488b8424080200004c89304c8978084c897010b001e917240000'),
    ('context', 'collection_entry', 0x22ed71e, '4989d64989f74889fb'),
    ('context', 'root_capture_entry', 0x269a1c1, '4989f74889fb'),
    ('context', 'root_group_builder', 0x2b7f5b7, '48897c2408488d050dbd8c034889442410'),
    ('context', 'collection_state_link', 0x22ed7b1, '488d4c24684c897c24684c896424704989ed49c1e50548baabaaaaaaaaaaaaaa4c89e848f7e24989d7488d7c24484c89f64c89f2e8168d4100'),
    ('context', 'root_capture', 0x269a20b, '498d87680900004889842448010000'),
    ('context', 'root_group_index4', 0x3d2a045, '488b47184889442440488d05a3f374024889442448488b47204889442450488d05b6f374024889442458'),
    ('selected', 'entry_arguments', 0x2706511, '4889d348897424084c8b770848897c2438488b471848894424304939c60f84ba0200004c8b39488b4108'),
    ('selected', 'entry_record_step', 0x2706550, '4c89f0410f1006410f104e10488d8c24880100000f1149100f11014983c620488b4c24384c897108'),
    ('selected', 'entry_gate', 0x27065bf, '498b6d184d8b07498b4810498db8880d0000410fb6b09a0b00004981c0283e00004c89eaff1547fedd038844240684c00f84b9000000'),
    ('selected', 'entry_dispatch', 0x27065f5, '498b378b442450894424200f284424400f29442410894424700f29442460488dbc24d0000000488d5424104c89e14989e8e8b50057006681bc24d0000000a2017477'),
    ('selected', 'entry_gate_clear', 0x27066a1, 'c6442406004c89e7e8e27c07004c89e7488db42490010000e8927abeff'),
    ('selected', 'entry_context', 0x27066be, '488b442460488b4c2468488b542470488d14d248c1e2044801ca48894c246048894c246848894424704889542478488d44240648898424800000004c89bc24880000004c89ac2490000000488b4424284889842498000000488d7c24104c89e6e89d52c1ff'),
    ('selected', 'entry_project', 0x270673a, '4883fd027372488b442410488d0ced000000004801e9498d4ccd004c89ac24d00000004c89ac24d800000048898424e000000048898c24e8000000488dbc2460010000488db424d0000000e89650c1ff488b842470010000488943100f108424600100000f11034883c3184c3b7424300f85a0fdffffeb3c'),
    ('selected', 'entry_sort', 0x27067b2, '4883fd15731dba010000004c89ef4889ee488d8c24d0000000e85028fcffe96bffffff4c89ef4889ee488d9424d0000000ff154ffcdd03e952ffffff'),
    ('selected', 'allocator_entry', 0x231b9cb, '4989f64889fb4c8b6618488b46084929c4742c4d89e749d1ef4c89ffff15933a1c044885c00f849a00000049c1ec0448b9398ee3388ee3388e490fafcceb0731c9b808000000'),
    ('selected', 'allocator_forward', 0x231ba11, '48890c244889442408488d4c241048c744241000000000410f1006410f104e100f294c24600f29442450410f104620410f104e300f114c24400f1144243048894c241848c7442420000000004889442428488d7c2450488d742418e80f983e00488b442410488943100f1004240f1103'),
    ('selected', 'record_source', 0x270537c, '4d89e5ba90000000488dbc24800200004c89e6ff1573a1dd034981c490000000488b4424184c896008'),
    ('selected', 'record_tag', 0x2705413, '6681bc2490010000a20148898424a80000007529418b453389842430010000410f1045230f2984242001000041b501eb0f6666662e0f1f8400000000004531ed488b8424900000000fb61084d28854240f0f84f6000000'),
    ('selected', 'record_call', 0x270546a, '488b4c24488b4110898424c00000000f10010f298424b0000000488dbc24000200004c89f64c89fa488d8c24a00200004989e8e80e75beff410fb6876501000080bc24000200000f0f8598010000'),
    ('selected', 'record_result_fifteen', 0x2705513, '0fb6d0488d7c24504889eee87d22efff488b442460488d8c2470010000488941100f104424500f1101c68424680100000f4889efe8e4116f0041b70fe91e010000'),
    ('selected', 'record_result_other', 0x2705650, '0fb6d0488dbc2468010000488db42400020000ff15b70dde03440fb6bc2468010000'),
    ('selected', 'record_blocked_status', 0x270573b, '66c78424b0000000c600488d7c24504889ee31d2e8dc8cfd01488b442460488d8c2447010000488941100f104424500f11014889ef488b5c2410e8a60b1f014c8b7424784c8ba42480000000'),
    ('selected', 'record_counter', 0x270578d, '498b068338010f852dffffff488b480848ffc148c7c2ffffffff480f44ca0fb654240f48894808'),
    ('selected', 'record_row', 0x2705310, '488d04db488b94248800000044883cc20f288424b00000000f1144c2010f108424bf0000000f1144c210488b8c24a000000048894cc22044886cc2280f284424200f1144c2298b4c2430894cc239488b8c24a800000048894cc24048ffc34c3ba424980000000f849b040000'),
    ('selected', 'handler_tag_key', 0x22ec9c6, '0fb7013da20100000f85b500000048899424c800000048897c2408488d4103488904248b4113898424c00100000f1041030f298424b00100000f10412b0f298424d00100008b413b898424e00100008b4113898424b0000000f30f6f4103660f7f8424a0000000'),
    ('selected', 'handler_single_key', 0x22eca2d, '4c8b2e498b9d780900004885db0f84f70000004883fb010f859b000000498b8570090000f30f6f4048660f6e8c24b0000000660f6e5058660f748424a0000000660f74d1660fdbc2660fd7c03dffff00000f85b3000000e978010000'),
    ('selected', 'handler_passthrough', 0x22eca89, '0fb651020fb6716f4088777f0f10415f0f11476f0f10414f0f11475f0f10413f0f11474f8b71138977230f1041030f1147130f1041170f1147278b7127897737f30f6f412bf30f7f473b8b493b894f4b66894710885712e9df030000'),
    ('selected', 'handler_multi_key', 0x22ecae5, '498bbda0090000498bb5a8090000488b1424e8441a8800498b8d70090000488d9424a0000000488954242048894c242848895c2430498dbd80090000488d5424204889c6e8a21b41004885c00f85ca000000'),
    ('selected', 'handler_alternate_tree', 0x22ecb37, '4d8bbd781000004d85ff0f84990000004c896c24184d8ba580100000488b2df62f1f04498d7708410fb787e600000048898424c00000008d048500000000488d1c8049c7c6ffffffff4885db743b4c8d6e14ba14000000488b7c2410ffd548984885c00f98c10f9fc028c849ffc64883c3ec4c89ee3c0174d00fb6c085c04c8b6c24187445eb0f66904c8bb424c00000004c8b6c24184983ec01720d4f8bbcf7e8000000e97affffff498db5880d0000488d7c2420488b1424ff1522831f04807c2420000f84b8020000'),
    ('selected', 'handler_admitted', 0x22ecc01, '4c8bb424c80000004d8b8648010000488b0c248b4110898424500100000f10010f29842440010000488d7c2420488d942440010000488d8c24d00100004c89eee89a9a980066817c2420a2010f858a010000498d9d6809000041833e010f85cb010000'),
    ('selected', 'handler_clock_compare', 0x22ecc64, '498b4608418b7560418b4d64418b55684189f141c1f90d418d79ff4531c04585c97f2841b8010000004529c84d69c01f85eb5149c1e82741ffc04569c8900100004401cf4569c04fc5fdffc1ee0481e6ff0100004401c64469c7b505000041c1f8024863ff4869ff1f85eb514989f949c1e93f48c1ff254401cf29fec1ff024401c601fe81c6c506f5ff4863f64869f6805101004801ce89d14869c983de1b4348c1e9324869d6e80300004801ca31c94885d2480f4fca4839c80f830b010000'),
    ('selected', 'handler_expired_mul', 0x22ecd29, '4983c6104c89f7ff15ea811f04b90500000048f7e1488b5c24080f804c0400004989c7'),
    ('selected', 'handler_expired_lookup', 0x22ecd50, '498bbda0090000498bb5a8090000488b2c244889eae8d61788004d89ee4989c58b4510898424e00000000f1045000f298424d0000000f3410f6f8670090000488d8424d00000004889842440010000f30f7f8424480100004981c680090000488d9424400100004c89f74c89eee80e1941004885c00f84b70200004c897424384c896c24404531f6e9c4020000'),
    ('selected', 'handler_regular_lookup', 0x22ece2f, '498d7e10ff15e7801f044889c5488b14248b4210898424e00000000f10020f298424d0000000498bbda0090000498bb5a8090000e8d81688004989c7410f108570090000488d8424d000000048898424400100000f118424480100004d8da580090000488d9424400100004c89e74c89fee82b1841004885c074324c896424384c897c24404531e4eb40'),
    ('selected', 'handler_denied', 0x22eceb9, '488b7c240866c747103600c6070f'),
    ('selected', 'handler_regular_mutation', 0x22ecef9, '4c8964242048895c24284889442430488d7c2420e8be9c40004803680848c7c1ffffffff480f43cd480f43cd48894808498b4d60418b556889503848894830'),
    ('selected', 'handler_nested_call', 0x22ecf82, '488d7c2420488d9424d00000004c89ee498d4e104c8d942440010000415250e87ac297004883c4104d8ba5784200004d85e4746f498b9d804200000fb66c2420488dbc24d00000004c89f6ff15557f1f04'),
    ('selected', 'handler_observer', 0x22ecfd3, '6681bc24d0000000a2010f851401000031d24080fd0f0f94c24c8bb424d80000004c8bbc24e0000000488b8c24e8000000488db424b00100004c89e7ff53204d85f6740e4c89ff4c89f631d2ff157b241f04'),
    ('selected', 'handler_output', 0x22ed025, '0f28842490000000488b7c24080f2947700f288424800000000f2947600f284424700f2947500f284424600f294740660f6f442420660f6f4c2430660f6f5424400f285c24500f295f30660f7f5720660f7f4f10660f7f07e945feffff'),
    ('selected', 'handler_expired_mutation', 0x22ed082, '488d4424388b8c24e0000000894810660f6f8424d0000000f30f7f004c89e84c89742420488b4c241048894c24284889442430488d7c2420e8119b40004c03780848c7c1ffffffff490f43cf490f43cf48894808498b0c24418b542408895038488948304889df66c74310d000c6030fe9d0fdffff'),
    ('selected', 'handler_location_failure', 0x22ed16b, '488d3d37dd2ffe488d0d8f0514044c8d0590011404488d942440010000be2b000000ff150d251f040f0b49c7c7ffffffff'),
    ('selected', 'dispatch_counters', 0x2c766fc, '488b86400b000048ffc049c7c5ffffffff490f44c5488986400b0000488dbef03a00004889ceff15c0178703418b4e68894c2408498b4e6048890c24488d7c24104889e24889c64c89e14d89f84531c9ff159e17870366817c2410a201751c498b86480b000048ffc0490f44c5498986480b000066c703a201eb3e'),
    ('selected', 'dispatch_copy', 0x2c76777, '0f284424700f2943600f284424600f2943500f284424500f2943400f284424100f284c24200f285424300f285c24400f295b300f2953200f294b100f2903'),
    ('selected', 'hash_constants', 0x2b6e547, '48b975657370656d6f734831f948ba6d6f646e61726f644831f249b86172656e6567796c4931f849b973657479626465744931f1'),
    ('selected', 'hash_twenty_input', 0x2b6e5a0, '48c7442440000000004889e7ba140000004889c6e85730fdff'),
    ('selected', 'hash_one_round', 0x2b41730, '4a8b1c064931db4c01d049c1c20d4c01d94931c249c1c3104931cb48c1c0204c01d14c01d849c1c2114931ca49c1c31548c1c1204931c34831d84983c0084939d072bd'),
    ('selected', 'probe_key_match', 0x26fe6d4, '4889f048c1e839488b0f4c8b4708660f6ec0660f60c0f20f70c000660f70c044488b42104c8b0a488b52084531d2660f76c94c21c6f30f6f1431660f6fda660f74d8660fd7eb660f1f4400004189eb6685ed7478f3410fbcdb4801f30f82ac0000004c21c3488d3cdd000000004989ce4929fe498b7ef84839c70f839b000000418d6bff4421dd488d3c7f48c1e705f3410f6f19f30f6f643a48660f74e366410f6e5910660f6e6c3a58660f74eb660fdbec660fd7fd81ffffff0000758eeb386666662e0f1f840000000000660f74d1660fd7fa85ff75204983faf0744d4983c2104c01d60f8347ffffff488d3d2a92d303ff15540dde0348c1e3034829d931c0664585db480f45c15b415e5dc3'),
    ('selected', 'insert_header', 0x26f6bd0, '554157415641554154534883ec684989fe4c8b27488b5f084d85e40f84b70100004d8b46104983c618660fefc0660f7f442430660f7f44242048c74424501a40f600c744245800000000660f7f442440'),
    ('selected', 'insert_probe', 0x26f6c20, '4d8b4c2418488b53084c8b7b10498b2c24498b44240831c94d89c50f1f4400004921c5f3420f6f442d00660fd7f085f675204883f9f00f84390300004883c1104901cd73db488d3d840dd403ff15ae88de03f30fbcce4901cd0f82230300004921c5420fb64c2d0084c97814660f6f4500660fd7c8f3440fbce9420fb64c2d00498b7424104885f6400f94c780e1014084f90f85240100000fb6c94829ce0f82eb0200004989742410498d4df04821c14883f9ef0f87e20200004c89c048c1e8394288442d0088440d104c89c84983f9ff0f842c02000048ffc049894424184a8d04ed000000004889e94829c14c8949f8'),
    ('selected', 'insert_record', 0x26f6d11, '4c3b3b0f842401000031c049f7dd84c0740f4889df4d89c4ff1549f5de034d89e0488b43084b8d0c7f48c1e1054c8904080f284424200f284c24300f285424400f114408080f114c08180f115408280f1044244c0f1144083466c74408440002c644084600410f10060f11440848418b56108954085849ffc74c897b10'),
    ('selected', 'insert_return', 0x26f6d8e, '4a8b7cedf84c39ff7225488d15710bd4034c89feff157888de03498b4610488b78f8488b73104839f70f830c020000488d047f48c1e005480343084883c0084883c4685b415c415d415e415f5dc3'),
    ('selected', 'insert_growth', 0x26f6e3e, '4c8904244b8d043f49bc55555555555555014c39e04c0f42e04c89e04c29f84883f8010f86d3000000488b5308488d7c240841b80800000041b9600000004c89fe4c89e1e8096ec2ff'),
    ('selected', 'insert_growth_failure', 0x26f6f23, '488d3d3e0bd403ff15f085de034983ffff0f84ac0000004d8d6701488b5308488d7c240841b80800000041b9600000004c89fe4c89e1e8326dc2ff837c2408017471488b442410488943084c8b04244c89234d89e7488b4b104c39f90f94c04989cf49f7dd84c00f8593fdffff'),
    ('selected', 'nested_key_select', 0x2c69231, '4989cc4989d74989f64889fb8b421089442420f30f6f02660f7f4424104c8baeb03c00004d85ed743f4983fd017540498b86a83c0000f30f6f4008660f6e4c2420660f6e5018660f74d1660f74442410660fdbc2660fd7c831d281f9ffff00000f8590000000eb5b31d2e9870000004c896424084489c54d89cc498bbed83c0000498bb6e03c00004c89fae87fe1aa01488d542410498dbea03c00004889c6e8db922601a80174414c39ea0f837d0400004d89e14189e8498b86a83c00004c8b642408488d0c5248c1e1048b54082c899424c1000000f30f6f44081cf30f7f8424b1000000b201eb0d31d24d89e14189e84c8b642408'),
    ('selected', 'nested_result_gate', 0x2c69416, 'ff157cea87030fb68424b00000003c100f85ba0000000fb78c24c000000081f9d00000000f85a60000004c89e7ff15d7ba87034989c448c1e83e0f85fd02000049c1e402'),
    ('selected', 'nested_penalty_lookup', 0x2c6945a, '498bbea0090000498bb6a80900004c89fae8d050f0ff4989c5418b4710898424a0000000410f10070f29842490000000410f108670090000488d84249000000048898424e80100000f118424f00100004d8dbe80090000488d9424e80100004c89ff4c89eee80c52a9ff498d8e680900004885c00f84aa0000004c897c24284c896c24304531ffe9b5000000'),
    ('selected', 'nested_result_variant', 0x2c6954e, '3c100f84ec0000003c0f0f8573010000807d00010f85b50100004889df4c89f64c89fa4c89e1e84712f7ffe93e010000'),
    ('selected', 'nested_penalty_mutation', 0x2c6957e, '488d4424288b9424a00000008950100f288424900000000f11004c89e84c897c241048894c24184889442420488d7c2410e81cd6a8ff4c03600848c7c1ffffffff490f43cc490f43cc48894808498b4e60418b566889503848894830'),
    ('selected', 'nested_output_and_replay', 0x2c6969d, '0f1143700f114b600f1153500f1173400f116b300f1163200f115b10c6030f4889d84881c4680200005b415c415d415e415f5dc38803410f104500410f104d10410f105520410f105d300f1143010f114b110f1153210f115b31410f1045400f114341410f1045500f114351410f1045600f114361410f10456f0f114370eb9f498b465048ffc048c7c1ffffffff480f45c849894e5041c64678014889df4c89f64c89fa4c89e1e87710f7ff41c6467800e969ffffff49c7c4ffffffffe9fbfcffff488d05caa382034889d74c89ee4889c2ff15ab5e8703'),
    ('selected', 'root_visit_bounds', 0x46a4911, '4c8b6f304d89ef49c1e7044c89e848c1e83c0f95c048b9f8ffffffffffff7f4939cf0f97c108c1740b31ff4c89feff1553abe3014989f44d85ff744b4889fb4c89ffff1527abe3014885c00f84d80100004989c64c892c24488944240848c7442410000000004c89ffff1500abe3014885c04889df7535bf080000004c89feff1502abe3010f0b'),
    ('selected', 'root_visit_entries', 0x46a49d0, '488b4f104885c90f84bb0000004c896c24304c896424384c8b6f0848c1e105488d2c494983c548488b1d4203e4014c8d25f3acde014c8d354ceade01eb2d6690498d45c0488b4c24204c89fa48c1e204488904114c8974110849ffc74c897c24284983c5604883c5a074424c8b7c24104c3b3c2475054889e7ffd3488b4424084c89f948c1e1044c892c084c8964080849ffc74c897c24104c8b7c24284c3b7c2418759c488d7c2418ffd3eb93'),
    ('selected', 'root_visit_handoff', 0x46a4a9d, '4c896c2440488d5424404889542448488d15cdabde0148895424504c8974245848894c246048894424684c897c2470488d442448488944247848c784248000000001000000488d7424584c89e7e88191b0ff'),
    ('selected', 'root_visit_cleanup', 0x46a4aef, '89c3488b7424184885f67411488b7c242048c1e60431d2ff1594a9e301488b34244885f67411488b7c240848c1e60431d2ff157aa9e30189d84881c4880000005b415c415d415e415f5dc3bf080000004c89feff1550a9e301'),
    ('selected', 'root_value_fields', 0x4307321, '48897c2438488d05b3c617024889442440488d47084889442448488d0526b617024889442450488d4f1048894c2458488d0d09d7170248894c2460488d5718488954246848894c2470488d4f3048894c2478488d0d8eb3170248898c2480000000488d4f2048898c24880000004889842490000000488d4f3e48898c2498000000488d0df7b4170248898c24a0000000488d4f2848898c24a800000048898424b0000000488d473c48898424b8000000488d0530c6170248898424c00000004883c73d4889bc24c8000000488d0595d6170248898424d0000000'),
    ('selected', 'root_value_guard', 0x43073fb, 'b00131c9483b0e0f80f7010000b00348837e100a0f85ea010000'),
)
BRANCH_SPECS = (
    ('entry_empty', 0x270652e, '0f84ba020000'),
    ('entry_gate_zero', 0x27065ef, '0f84b9000000'),
    ('entry_initial_tag', 0x2706635, '7477'),
    ('entry_single', 0x270673e, '7372'),
    ('entry_small_sort', 0x27067b6, '731d'),
    ('allocation_empty', 0x231b9dc, '742c'),
    ('allocation_failure', 0x231b9f0, '0f849a000000'),
    ('record_empty', 0x27052ae, '0f845f050000'),
    ('record_initial_tag', 0x2705425, '7529'),
    ('record_gate_zero', 0x2705464, '0f84f6000000'),
    ('record_result_tag', 0x27054b2, '0f8598010000'),
    ('record_tree_match', 0x2705603, '0f8432010000'),
    ('record_counter_state', 0x2705793, '0f852dffffff'),
    ('input_tag', 0x22ec9ce, '0f85b5000000'),
    ('key_count_zero', 0x22eca3a, '0f84f7000000'),
    ('key_count_multiple', 0x22eca44, '0f859b000000'),
    ('key_single_mismatch', 0x22eca7e, '0f85b3000000'),
    ('key_table_found', 0x22ecb31, '0f85ca000000'),
    ('alternate_tree_empty', 0x22ecb41, '0f8499000000'),
    ('alternate_tree_equal', 0x22ecbba, '7445'),
    ('fallback_absent', 0x22ecbfb, '0f84b8020000'),
    ('dispatch_status_other', 0x22ecc4d, '0f858a010000'),
    ('deadline_tag_other', 0x22ecc5e, '0f85cb010000'),
    ('deadline_in_range', 0x22ecd1e, '0f830b010000'),
    ('penalty_mul_overflow', 0x22ecd43, '0f804c040000'),
    ('penalty_key_missing', 0x22ecdc5, '0f84b7020000'),
    ('normal_key_missing', 0x22ecea8, '7432'),
    ('observer_absent', 0x22ecfb4, '746f'),
    ('observer_failure', 0x22ecfdd, '0f8514010000'),
    ('dispatch_status_normal', 0x2c76759, '751c'),
    ('probe_empty_group', 0x26fe726, '7478'),
    ('probe_bad_index', 0x26fe74e, '0f839b000000'),
    ('probe_key_mismatch', 0x26fe790, '758e'),
    ('probe_stop_empty', 0x26fe7aa, '7520'),
    ('insert_existing', 0x26f6beb, '0f84b7010000'),
    ('insert_grow', 0x26f6d14, '0f8424010000'),
    ('insert_bad_index', 0x26f6d96, '7225'),
    ('insert_capacity', 0x26f6e61, '0f86d3000000'),
    ('insert_alloc_failure', 0x26f6f63, '7471'),
    ('nested_status_tag', 0x2c69426, '0f85ba000000'),
    ('nested_status_code', 0x2c6943a, '0f85a6000000'),
    ('nested_quad_overflow', 0x2c69450, '0f85fd020000'),
    ('nested_key_missing', 0x2c694ce, '0f84aa000000'),
    ('nested_result_ten', 0x2c69550, '0f84ec000000'),
    ('nested_result_fifteen', 0x2c69558, '0f8573010000'),
    ('nested_replay_flag', 0x2c69562, '0f85b5010000'),
    ('root_size_ok', 0x46a4938, '740b'),
    ('root_empty', 0x46a494b, '744b'),
    ('root_alloc_failure', 0x46a495c, '0f84d8010000'),
    ('root_second_alloc_success', 0x46a4986, '7535'),
    ('root_no_rows', 0x46a49d7, '0f84bb000000'),
    ('root_row_done', 0x46a4a39, '7442'),
    ('root_keys_capacity', 0x46a4a44, '7505'),
    ('root_values_capacity', 0x46a4a72, '759c'),
    ('value_state_overflow', 0x4307402, '0f80f7010000'),
    ('value_child_count', 0x430740f, '0f85ea010000'),
)
CALL_SPECS = (
    ('materializer_boundary', 0x2add95b, 'ff153f9aa003'),
    ('wrapper_to_future', 0x2af4797, 'e8a486feff'),
    ('parent_to_task', 0x2b4261c, 'e87f85ffff'),
    ('collection_to_loop', 0x22ed7e5, 'e8168d4100'),
    ('entry_gate', 0x27065e3, 'ff1547fedd03'),
    ('entry_initial_dispatch', 0x2706626, 'e8b5005700'),
    ('entry_prepare_records', 0x27066b9, 'e8927abeff'),
    ('entry_to_allocator', 0x270671e, 'e89d52c1ff'),
    ('entry_pack', 0x2706785, 'e89650c1ff'),
    ('entry_small_sort', 0x27067cb, 'e85028fcff'),
    ('entry_large_sort_slot', 0x27067e3, 'ff154ffcdd03'),
    ('allocator_allocate', 0x231b9e7, 'ff15933a1c04'),
    ('allocator_to_record_loop', 0x231ba6c, 'e80f983e00'),
    ('allocator_failure', 0x231ba98, 'ff15fa391c04'),
    ('record_copy', 0x270538f, 'ff1573a1dd03'),
    ('record_to_handler', 0x270549d, 'e80e75beff'),
    ('record_convert', 0x270551e, 'e87d22efff'),
    ('record_other_result', 0x2705663, 'ff15b70dde03'),
    ('record_denied_format', 0x270574f, 'e8dc8cfd01'),
    ('handler_key_hash', 0x22ecaf7, 'e8441a8800'),
    ('handler_key_probe', 0x22ecb29, 'e8a21b4100'),
    ('handler_extra_lookup', 0x22ecbf0, 'ff1522831f04'),
    ('handler_dispatch', 0x22ecc41, 'e89a9a9800'),
    ('handler_expired_amount', 0x22ecd30, 'ff15ea811f04'),
    ('handler_expired_hash', 0x22ecd65, 'e8d6178800'),
    ('handler_expired_probe', 0x22ecdbd, 'e80e194100'),
    ('handler_amount', 0x22ece33, 'ff15e7801f04'),
    ('handler_hash', 0x22ece63, 'e8d8168800'),
    ('handler_probe', 0x22ecea0, 'e82b184100'),
    ('handler_insert', 0x22ecf0d, 'e8be9c4000'),
    ('handler_action', 0x22ecfa1, 'e87ac29700'),
    ('handler_observer_decode', 0x22ecfcd, 'ff15557f1f04'),
    ('handler_observer_callback', 0x22ed00f, 'ff5320'),
    ('handler_expired_insert', 0x22ed0ba, 'e8119b4000'),
    ('handler_location_diagnostic', 0x22ed18d, 'ff150d251f04'),
    ('dispatch_lookup', 0x2c76722, 'ff15c0178703'),
    ('dispatch_call', 0x2c7674c, 'ff159e178703'),
    ('hash_update', 0x2b6e5b4, 'e85730fdff'),
    ('nested_inner_action', 0x2c69416, 'ff157cea8703'),
    ('nested_amount', 0x2c69443, 'ff15d7ba8703'),
    ('nested_hash', 0x2c6946b, 'e8d050f0ff'),
    ('nested_probe', 0x2c694bf, 'e80c52a9ff'),
    ('nested_insert', 0x2c695af, 'e81cd6a8ff'),
    ('nested_replay', 0x2c69744, 'e87710f7ff'),
    ('insert_grow', 0x26f6e82, 'e8096ec2ff'),
    ('insert_failure', 0x26f6fe0, 'ff15b284de03'),
    ('root_key_value_handoff', 0x46a4aea, 'e88191b0ff'),
    ('root_visit_failure', 0x46a4b42, 'ff1550a9e301'),
)

# The selected byte windows above are the authority for these operand slices.
# The coordinates and offsets select bytes; every reported value is decoded from
# the authenticated ELF, including signed x86 displacements.
OPERAND_SPECS = (
    ('future_store_pointer', 0x2add961, 7, 3, 4, False),
    ('future_load_pointer', 0x2addf72, 7, 3, 4, False),
    ('future_output_pointer', 0x2add8d7, 4, 3, 1, False),
    ('wrapper_output_store', 0x2af47cc, 5, 4, 1, False),
    ('wrapper_pointer_load', 0x2af4a67, 4, 3, 1, False),
    ('wrapper_return_pointer', 0x2af5c28, 7, 3, 4, False),
    ('parent_copy_destination', 0x2b42442, 8, 4, 4, False),
    ('parent_extracted_stack', 0x2b4246b, 8, 4, 4, False),
    ('parent_copy_length', 0x2b4244f, 5, 1, 4, False),
    ('parent_task_base', 0x2b42539, 7, 3, 4, False),
    ('parent_task_pointer', 0x2b42597, 7, 3, 4, False),
    ('parent_task_copy_length', 0x2b425f3, 5, 1, 4, False),
    ('constructor_copy_length', 0x2b3ac37, 5, 1, 4, False),
    ('future_sentinel', 0x2addded, 10, 2, 8, False),
    ('wrapper_sentinel', 0x2af49a6, 10, 2, 8, False),
    ('input_tag', 0x22ec9c9, 5, 1, 4, False),
    ('dispatch_tag', 0x2c76752, 7, 5, 2, False),
    ('nested_outer_tag', 0x2c69424, 2, 1, 1, False),
    ('nested_error_code', 0x2c69434, 6, 2, 4, False),
    ('expired_error_code', 0x22ed0e9, 6, 4, 2, False),
    ('denied_error_code', 0x22ecebe, 6, 4, 2, False),
    ('output_tag', 0x22ecec4, 3, 2, 1, False),
    ('expired_multiplier', 0x22ecd36, 5, 1, 4, False),
    ('nested_multiplier_shift', 0x2c69456, 4, 3, 1, False),
    ('handler_map_offset', 0x22ecc53, 7, 3, 4, False),
    ('root_context_map_offset', 0x269a20b, 7, 3, 4, False),
    ('source_stride', 0x2705395, 7, 3, 4, False),
    ('key_bytes', 0x2b6e5ac, 5, 1, 4, False),
    ('insert_element_size', 0x26f6e76, 6, 2, 4, False),
    ('insert_value_pointer', 0x26f6dc9, 4, 3, 1, False),
    ('handler_accumulator_offset', 0x22ecf25, 4, 3, 1, False),
    ('nested_accumulator_offset', 0x2c695c7, 4, 3, 1, False),
    ('root_rows_length_offset', 0x46a49d0, 4, 3, 1, False),
    ('root_rows_pointer_offset', 0x46a49e7, 4, 3, 1, False),
    ('root_key_in_row', 0x46a49f3, 4, 3, 1, False),
    ('root_value_from_key', 0x46a4a10, 4, 3, 1, True),
    ('root_record_stride', 0x46a4a31, 4, 3, 1, False),
    ('root_group_index_bytes', 0x3d2a05a, 4, 3, 1, False),
    ('root_value_accumulator_offset', 0x4307332, 4, 3, 1, False),
    ('root_value_child_count', 0x430740a, 5, 4, 1, False),
    ('root_alloc_shift', 0x46a4918, 4, 3, 1, False),
    ('root_overflow_shift', 0x46a491f, 4, 3, 1, False),
    ('root_alloc_limit', 0x46a4926, 10, 2, 8, False),
    ('sort_lower_limit', 0x270673a, 4, 3, 1, False),
    ('sort_upper_limit', 0x27067b2, 4, 3, 1, False),
)

# Five-word Rust-style dynamic descriptors. Selected callbacks are independent
# FDEs in this packet; previously studied group/scalar callbacks are boundaries.
DESCRIPTOR_SPECS = (
    ('group_context', 0x644b2d0, (0, 0x80, 8, 0x3d2a000, 0x3d29f50)),
    ('keyed_map', 0x6479420, (0x3cedae0, 0x48, 8, 0x46a4900, 0x46a0fb0)),
    ('key', 0x648f6f8, (0, 0x14, 1, 0x41f8050, 0x43025f0)),
    ('value', 0x6493458, (0, 0x40, 8, 0x4307310, 0x4307290)),
    ('scalar_boundary', 0x6482968, (0, 8, 8, 0x14199b0, 0x14196d0)),
)

REFERENCE_SPECS = (
    ('prior_loader_location', 0x3c1352f, 0x64767a8),
    ('context_group_descriptor', 0x2b7f5bc, 0x644b2d0),
    ('context_group_item4_descriptor', 0x3d2a063, 0x6479420),
    ('handler_location', 0x22ed179, 0x642d310),
    ('root_key_descriptor', 0x46a49fe, 0x648f6f8),
    ('root_value_descriptor', 0x46a4a05, 0x6493458),
    ('root_accumulator_descriptor', 0x430733b, 0x6482968),
)


def authenticate(data, expected=TARGET_SHA256):
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise ValueError('input SHA-256 mismatch')
    return actual


def section_by_name(sec_rows, name):
    found = [s for s in sec_rows if s['name'] == name]
    if len(found) != 1 or found[0]['type'] == 8:
        raise ValueError('missing, duplicated, or fileless section: ' + name)
    return found[0]


def file_offset(data, sec_rows, va, size, *, executable=False):
    if type(va) is not int or type(size) is not int or va < 0 or size <= 0:
        raise ValueError('invalid address range')
    found = [s for s in sec_rows if s['type'] != 8 and s['size'] and
             s['address'] <= va and va + size <= s['address'] + s['size'] and
             (not executable or s['flags'] & 4)]
    if len(found) != 1:
        raise ValueError('address does not have one file-backed mapping')
    sec = found[0]
    off = sec['offset'] + va - sec['address']
    if off < 0 or off + size > len(data):
        raise ValueError('address maps outside input')
    return off


def read_va(data, sec_rows, va, size, *, executable=False):
    off = file_offset(data, sec_rows, va, size, executable=executable)
    return bytes(data[off:off + size])


def require_fixed(data, sec_rows, va, expected, *, executable=True):
    expected = bytes.fromhex(expected) if isinstance(expected, str) else bytes(expected)
    actual = read_va(data, sec_rows, va, len(expected), executable=executable)
    if actual != expected:
        raise ValueError(f'changed selected bytes at {va:#x}')
    return actual


def decode_transfer(va, raw):
    """Decode only the fixed call/jump forms selected in the catalog."""
    if not raw:
        raise ValueError('empty transfer')
    if raw[0] == 0xe8 and len(raw) == 5:
        return 'rel32_call', va + 5 + struct.unpack_from('<i', raw, 1)[0]
    if raw[:2] == b'\xff\x15' and len(raw) == 6:
        return 'rip_indirect_call_slot', va + 6 + struct.unpack_from('<i', raw, 2)[0]
    if raw[:2] == b'\xff\x53' and len(raw) == 3:
        return 'register_indirect_call_offset', int.from_bytes(raw[2:], 'little', signed=True)
    if len(raw) == 2 and 0x70 <= raw[0] <= 0x7f:
        return 'short_conditional', va + 2 + int.from_bytes(raw[1:], 'little', signed=True)
    if len(raw) == 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        return 'near_conditional', va + 6 + struct.unpack_from('<i', raw, 2)[0]
    raise ValueError(f'unsupported transfer at {va:#x}')


def selected_fdes(data, sec_rows):
    index_secs, header = unwind_index(data)
    if index_secs != sec_rows:
        raise ValueError('inconsistent section parsing')
    _, records = eh_frame_records(data, sec_rows)
    by_fde = {f['fde']: f for f in records}
    if len(by_fde) != len(records):
        raise ValueError('duplicate FDE address')
    by_start = {row['start']: row for row in header}
    if len(by_start) != len(header):
        raise ValueError('duplicate unwind start')
    selected = []
    for role, start, end, expected_hash in FDE_SPECS:
        row = by_start.get(start)
        record = by_fde.get(row['fde']) if row else None
        if not record or record['start'] != start or record['end'] != end:
            raise ValueError('FDE/header mismatch: ' + role)
        if end > row['next_index_upper_bound']:
            raise ValueError('selected unwind extent overlaps the next start')
        raw = read_va(data, sec_rows, start, end - start, executable=True)
        if hashlib.sha256(raw).hexdigest() != expected_hash:
            raise ValueError('FDE body mismatch: ' + role)
        selected.append(dict(record, role=role, index=row['index'], body=raw))
    ordered = sorted(selected, key=lambda r: r['start'])
    if any(a['end'] > b['start'] for a, b in zip(ordered, ordered[1:])):
        raise ValueError('selected FDEs overlap')
    return selected


def relocations(data, sec_rows):
    sec = section_by_name(sec_rows, '.rela.dyn')
    if sec['size'] % 24:
        raise ValueError('truncated relocation table')
    result = {}
    end = sec['offset'] + sec['size']
    if end > len(data):
        raise ValueError('relocation table outside input')
    for off in range(sec['offset'], end, 24):
        dest, info, addend = struct.unpack_from('<QQq', data, off)
        if dest in result:
            raise ValueError('duplicate relocation destination')
        result[dest] = (info & 0xffffffff, info >> 32, addend, off)
    return result


def descriptor_rows(data, sec_rows, relocs):
    rows = []
    for label, base, expected in DESCRIPTOR_SPECS:
        raw = read_va(data, sec_rows, base, 40)
        values, reloc_offsets = [], []
        for i in range(5):
            va = base + 8 * i
            value = struct.unpack_from('<Q', raw, 8 * i)[0]
            rel = relocs.get(va)
            if rel:
                typ, symbol, addend, off = rel
                if typ != 8 or symbol != 0 or value != 0 or addend < 0:
                    raise ValueError('unexpected descriptor relocation')
                value = addend
                reloc_offsets.append(hex(off))
            else:
                reloc_offsets.append('-')
            values.append(value)
        if tuple(values) != expected:
            raise ValueError('descriptor mismatch: ' + label)
        rows.append((label, hex(base), hex(file_offset(data, sec_rows, base, 40)),
                     *(hex(x) for x in values), ','.join(reloc_offsets), raw.hex()))
    return rows


def materializer_boundary(data, sec_rows, relocs):
    """Check the existing materializer slot as a boundary, without owning it."""
    slot = 0x64e73a0
    raw = read_va(data, sec_rows, slot, 8)
    rel = relocs.get(slot)
    if raw != bytes(8) or not rel or rel[:3] != (8, 0, 0x3c13610):
        raise ValueError('materializer boundary relocation mismatch')
    return ('materializer', hex(slot), hex(file_offset(data, sec_rows, slot, 8)),
            hex(rel[3]), rel[0], rel[1], hex(rel[2]), raw.hex())


def location_row(data, sec_rows, relocs, loc=0x642d310, expected_line=460, expected_col=78):
    raw = read_va(data, sec_rows, loc, 24)
    pointer, length, line, col = struct.unpack('<QQII', raw)
    rel = relocs.get(loc)
    if not rel or rel[0:2] != (8, 0) or pointer != 0:
        raise ValueError('missing Location path relocation')
    path_va = rel[2]
    if length != 20 or (line, col) != (expected_line, expected_col):
        raise ValueError('Location dimensions mismatch')
    path = read_va(data, sec_rows, path_va, length)
    if path != b'l1/src/abci/state.rs':
        raise ValueError('Location suffix mismatch')
    return (hex(loc), hex(file_offset(data, sec_rows, loc, 24)), hex(rel[3]),
            hex(path_va), length, line, col, path.decode('ascii'), raw.hex())


def lsda_rows(data, sec_rows, fde):
    """Decode bounded ULEB call-site rows, retaining uninterpreted action IDs."""
    if fde['lsda'] is None:
        return []
    sec = section_by_name(sec_rows, '.gcc_except_table')
    va = fde['lsda']
    if not sec['address'] <= va < sec['address'] + sec['size']:
        raise ValueError('LSDA outside exception section')
    pos = file_offset(data, sec_rows, va, 1)
    limit = sec['offset'] + sec['size']
    if pos + 2 > limit or data[pos] != 0xff or data[pos + 1] not in (0x9b, 0xff):
        raise ValueError('unsupported LSDA encodings')
    type_encoding = data[pos + 1]
    pos += 2
    if type_encoding == 0x9b:
        type_offset, pos = uleb(data, pos, limit)
        type_base = pos + type_offset
    else:
        type_base = limit
    if type_base > limit or pos >= limit or data[pos] != 1:
        raise ValueError('bad LSDA type or call-site encoding')
    pos += 1
    size, pos = uleb(data, pos, limit)
    end = pos + size
    if end > limit or end > type_base:
        raise ValueError('LSDA call-site table outside bounds')
    rows = []
    while pos < end:
        entry = pos
        start, pos = uleb(data, pos, end)
        length, pos = uleb(data, pos, end)
        landing, pos = uleb(data, pos, end)
        action, pos = uleb(data, pos, end)
        if start + length > fde['end'] - fde['start']:
            raise ValueError('LSDA call site outside FDE')
        if landing and landing >= fde['end'] - fde['start']:
            raise ValueError('LSDA landing outside FDE')
        rows.append((fde['role'], hex(va), hex(entry), hex(fde['start'] + start),
                     hex(fde['start'] + start + length),
                     hex(fde['start'] + landing) if landing else '-', action,
                     bytes(data[entry:pos]).hex()))
    if pos != end:
        raise ValueError('misaligned LSDA table')
    return rows


def operand_rows(data, sec_rows):
    rows, values = [], {}
    for label, va, length, offset, size, signed in OPERAND_SPECS:
        if offset < 0 or size <= 0 or offset + size > length:
            raise ValueError('bad operand specification')
        # Every operand must be covered by a pinned window.
        if not any(start <= va and va + length <= start + len(bytes.fromhex(raw))
                   for _, _, start, raw in WINDOW_SPECS):
            raise ValueError('operand has no fixed-byte window: ' + label)
        raw = read_va(data, sec_rows, va, length, executable=True)
        value = int.from_bytes(raw[offset:offset + size], 'little', signed=signed)
        values[label] = value
        rows.append((label, hex(va), hex(file_offset(data, sec_rows, va, length, executable=True)),
                     raw.hex(), offset, size, int(signed), hex(value) if value >= 0 else str(value)))
    return rows, values


def reference_rows(data, sec_rows):
    rows = []
    for label, va, expected in REFERENCE_SPECS:
        if not any(start <= va and va + 7 <= start + len(bytes.fromhex(raw))
                   for _, _, start, raw in WINDOW_SPECS):
            raise ValueError('reference has no fixed-byte window: ' + label)
        raw = read_va(data, sec_rows, va, 7, executable=True)
        if raw[:2] not in (b'\x48\x8d', b'\x4c\x8d') or raw[2] & 0xc7 != 0x05:
            raise ValueError('unsupported selected RIP-relative LEA')
        target = va + 7 + struct.unpack_from('<i', raw, 3)[0]
        if target != expected:
            raise ValueError('selected reference target changed: ' + label)
        rows.append((label, hex(va), hex(file_offset(data, sec_rows, va, 7, executable=True)),
                     raw.hex(), hex(target)))
    return rows


def verify_joins(values, descriptor_table, starts, references, location, loader_location):
    desc = {row[0]: tuple(int(value, 16) for value in row[3:8]) for row in descriptor_table}
    desc_addresses = {row[0]: int(row[1], 16) for row in descriptor_table}
    targets = {row[0]: int(row[4], 16) for row in references}
    joins = (
        ('future_retained_pointer', values['future_store_pointer'], values['future_load_pointer']),
        ('future_to_wrapper_pointer', values['future_output_pointer'],
         values['wrapper_pointer_load'] - values['wrapper_output_store']),
        ('wrapper_to_parent_pointer', values['wrapper_return_pointer'],
         values['parent_extracted_stack'] - values['parent_copy_destination']),
        ('parent_to_constructor_copy', values['parent_task_copy_length'], values['constructor_copy_length']),
        ('future_wrapper_sentinel', values['future_sentinel'], values['wrapper_sentinel']),
        ('state_map', values['handler_map_offset'], values['root_context_map_offset']),
        ('key_size', values['key_bytes'], desc['key'][1]),
        ('row_stride', values['insert_element_size'], values['root_record_stride']),
        ('value_pointer', values['insert_value_pointer'],
         values['root_key_in_row'] + values['root_value_from_key']),
        ('mutated_root_field', values['handler_accumulator_offset'], values['root_value_accumulator_offset']),
        ('nested_mutation_field', values['handler_accumulator_offset'], values['nested_accumulator_offset']),
        ('dispatch_tag', values['input_tag'], values['dispatch_tag']),
        ('penalty_code', values['expired_error_code'], values['nested_error_code']),
        ('group_descriptor_reference', targets['context_group_descriptor'], desc_addresses['group_context']),
        ('group_item4_descriptor_reference', targets['context_group_item4_descriptor'], desc_addresses['keyed_map']),
        ('key_descriptor_reference', targets['root_key_descriptor'], desc_addresses['key']),
        ('value_descriptor_reference', targets['root_value_descriptor'], desc_addresses['value']),
        ('scalar_descriptor_reference', targets['root_accumulator_descriptor'], desc_addresses['scalar_boundary']),
        ('location_reference', targets['handler_location'], int(location[0], 16)),
        ('loader_location_reference', targets['prior_loader_location'], int(loader_location[0], 16)),
        ('map_visitor_callback', desc['keyed_map'][3], starts['root_map_visitor']),
        ('map_constructor_callback', desc['keyed_map'][4], starts['root_map_constructor']),
        ('value_visitor_callback', desc['value'][3], starts['root_value_visitor']),
        ('value_constructor_callback', desc['value'][4], starts['root_value_constructor']),
    )
    if any(a != b for _, a, b in joins):
        raise ValueError('selected layout, tag, reference, or callback join failed')
    if (values['root_group_index_bytes'] != 4 * 8 or
            values['root_rows_pointer_offset'] != 8 or values['root_rows_length_offset'] != 16 or
            values['root_value_child_count'] != 10 or values['expired_multiplier'] != 5 or
            values['nested_multiplier_shift'] != 2 or values['root_alloc_shift'] != 4 or
            values['root_overflow_shift'] != 60 or values['root_alloc_limit'] != 0x7ffffffffffffff8 or
            values['sort_lower_limit'] != 2 or values['sort_upper_limit'] != 21):
        raise ValueError('selected layout or arithmetic relationship failed')
    if (values['parent_task_pointer'] - values['parent_task_base'] != 0x320 or
            values['parent_task_pointer'] - values['parent_task_base'] + 8 > values['parent_task_copy_length'] or
            values['wrapper_return_pointer'] + 8 > values['parent_copy_length'] or
            ((values['future_sentinel'] + 1) ^ values['wrapper_sentinel']) != 1):
        raise ValueError('selected materializer-to-task relationship failed')
    if len(descriptor_table) != len(DESCRIPTOR_SPECS):
        raise ValueError('missing descriptor rows')
    return [(label, hex(a), hex(b)) for label, a, b in joins]


def tsv(header, rows):
    out = io.StringIO(newline='')
    writer = csv.writer(out, delimiter='\t', lineterminator='\n')
    writer.writerow(header)
    writer.writerows(rows)
    return out.getvalue().encode('utf-8')


def collect(data):
    """Authenticate and derive all records before creating any output files."""
    digest = authenticate(data)
    sec_rows = sections(data)
    chosen = selected_fdes(data, sec_rows)
    relocs = relocations(data, sec_rows)
    descriptors = descriptor_rows(data, sec_rows, relocs)
    materializer = materializer_boundary(data, sec_rows, relocs)
    location = location_row(data, sec_rows, relocs)
    loader_location = location_row(data, sec_rows, relocs, loc=0x64767a8, expected_line=123, expected_col=37)

    function_rows = []
    for f in chosen:
        function_rows.append((f['role'], hex(f['start']), hex(f['end']),
                              hex(file_offset(data, sec_rows, f['start'], len(f['body']), executable=True)),
                              len(f['body']), hex(f['fde']), hex(f['cie']),
                              hex(f['lsda']) if f['lsda'] is not None else '-', f['index'],
                              hashlib.sha256(f['body']).hexdigest(), f['body'].hex()))

    window_rows = []
    for scope, label, va, raw in WINDOW_SPECS:
        actual = require_fixed(data, sec_rows, va, raw)
        if scope == 'selected' and not any(f['start'] <= va and va + len(actual) <= f['end'] for f in chosen):
            raise ValueError('window outside selected FDE: ' + label)
        window_rows.append((scope, label, hex(va),
                            hex(file_offset(data, sec_rows, va, len(actual), executable=True)),
                            len(actual), actual.hex()))

    def transfer_rows(specs, contextual=False):
        result = []
        for label, va, pin in specs:
            raw = require_fixed(data, sec_rows, va, pin)
            form, target = decode_transfer(va, raw)
            owner = next((f for f in chosen if f['start'] <= va and va + len(raw) <= f['end']), None)
            scope = 'selected' if owner else 'context'
            if owner is None and not (contextual and label in
                                      ('collection_to_loop', 'wrapper_to_future', 'parent_to_task')):
                raise ValueError('transfer outside selected FDE: ' + label)
            if form.endswith('conditional') and not (owner['start'] <= target < owner['end']):
                raise ValueError('selected branch leaves FDE: ' + label)
            result.append((scope, label, owner['role'] if owner else '-', hex(va),
                           hex(file_offset(data, sec_rows, va, len(raw), executable=True)),
                           form, hex(target), raw.hex()))
        return result

    branches = transfer_rows(BRANCH_SPECS)
    calls = transfer_rows(CALL_SPECS, contextual=True)
    links = {
        'wrapper_to_future': 'materializer_future',
        'collection_to_loop': 'item_loop', 'entry_initial_dispatch': 'tag_dispatch',
        'entry_to_allocator': 'result_allocator', 'allocator_to_record_loop': 'record_loop',
        'record_to_handler': 'location_handler', 'handler_dispatch': 'tag_dispatch',
        'handler_key_hash': 'key_hash', 'handler_key_probe': 'keyed_probe',
        'handler_insert': 'keyed_insert', 'handler_expired_insert': 'keyed_insert',
        'handler_action': 'action_result', 'hash_update': 'hash_update',
        'nested_hash': 'key_hash', 'nested_probe': 'keyed_probe', 'nested_insert': 'keyed_insert',
    }
    starts = {f['role']: f['start'] for f in chosen}
    by_call = {row[1]: row for row in calls}
    for label, destination in links.items():
        if int(by_call[label][6], 16) != starts[destination]:
            raise ValueError('selected call join failed: ' + label)
    if int(by_call['materializer_boundary'][6], 16) != int(materializer[1], 16):
        raise ValueError('materializer call/relocation join failed')
    old_call = read_va(data, sec_rows, 0x3c135c2, 6, executable=True)
    if decode_transfer(0x3c135c2, old_call)[1] != int(materializer[1], 16):
        raise ValueError('prior Location caller uses a different materializer slot')
    if int(by_call['parent_to_task'][6], 16) != 0x2b3aba0:
        raise ValueError('task constructor boundary changed')
    operands, values = operand_rows(data, sec_rows)
    references = reference_rows(data, sec_rows)
    joins = verify_joins(values, descriptors, starts, references, location, loader_location)
    unwind = [row for f in chosen for row in lsda_rows(data, sec_rows, f)]
    witnesses = []
    for scope, label, role, va, _, _, _, raw in calls:
        if scope != 'selected':
            continue
        start = int(va, 16)
        covered = [r for r in unwind if r[0] == role and int(r[3], 16) <= start and
                   start + len(bytes.fromhex(raw)) <= int(r[4], 16)]
        if len(covered) > 1:
            raise ValueError('ambiguous LSDA witness')
        if covered:
            witnesses.append((label, va, role, *covered[0][1:]))
    summary = {
        'input_sha256': digest,
        'coordinate_system': 'linked ELF virtual addresses; file offsets are separate',
        'selected_fdes': len(function_rows),
        'selected_windows': sum(row[0] == 'selected' for row in window_rows),
        'context_windows': sum(row[0] == 'context' for row in window_rows),
        'selected_conditional_branches': len(branches),
        'selected_and_context_calls': len(calls),
        'decoded_operands': len(operands),
        'decoded_rip_references': len(references),
        'checked_direct_call_joins': len(links),
        'descriptor_records': len(descriptors),
        'materializer_boundary_records': 1,
        'lsda_rows': len(unwind),
        'covered_call_witnesses': len(witnesses),
        'verified_joins': len(joins),
        'limitations': 'Selections are not a function census, complete CFG, execution, or equivalence claim.',
    }
    return {
        'functions.tsv': tsv(('role', 'start_va', 'end_va_exclusive', 'file_offset', 'length',
                              'fde_va', 'cie_va', 'lsda_va', 'unwind_index', 'body_sha256', 'body_hex'), function_rows),
        'windows.tsv': tsv(('scope', 'label', 'va', 'file_offset', 'length', 'raw_hex'), window_rows),
        'branches.tsv': tsv(('scope', 'label', 'fde_role', 'va', 'file_offset', 'form', 'target_va', 'raw_hex'), branches),
        'calls.tsv': tsv(('scope', 'label', 'fde_role', 'va', 'file_offset', 'form', 'target_or_offset', 'raw_hex'), calls),
        'operands.tsv': tsv(('label', 'va', 'file_offset', 'raw_hex', 'operand_offset', 'operand_size', 'signed', 'value'), operands),
        'references.tsv': tsv(('label', 'va', 'file_offset', 'raw_hex', 'target_va'), references),
        'descriptors.tsv': tsv(('label', 'va', 'file_offset', 'drop', 'size', 'alignment', 'visitor', 'constructor', 'relocation_file_offsets', 'raw_hex'), descriptors),
        'boundaries.tsv': tsv(('label', 'slot_va', 'slot_file_offset', 'relocation_file_offset', 'relocation_type', 'symbol', 'addend', 'slot_raw_hex'), [materializer]),
        'locations.tsv': tsv(('va', 'file_offset', 'relocation_file_offset', 'path_va', 'length', 'line', 'column', 'suffix', 'raw_hex'), [location, loader_location]),
        'joins.tsv': tsv(('relationship', 'left_value', 'right_value'), joins),
        'unwind.tsv': tsv(('fde_role', 'lsda_va', 'entry_file_offset', 'range_start_va', 'range_end_va', 'landing_va', 'action', 'raw_hex'), unwind),
        'unwind-witnesses.tsv': tsv(('call_label', 'call_va', 'fde_role', 'lsda_va', 'entry_file_offset', 'range_start_va', 'range_end_va', 'landing_va', 'action', 'raw_hex'), witnesses),
        'summary.json': (json.dumps(summary, sort_keys=True, indent=2) + '\n').encode('utf-8'),
    }


def compare_historical(old, current):
    """Optional release-specific anchors; no historical data enters output files."""
    authenticate(old, HISTORICAL_SHA256)
    authenticate(current)
    old_sec = sections(old)
    new_sec = sections(current)
    old_cmp = require_fixed(old, old_sec, 0x2208594, '0fb7013d86010000')
    new_cmp = require_fixed(current, new_sec, 0x22ec9c6, '0fb7013da2010000')
    old_loader = require_fixed(old, old_sec, 0x3273871, '4983fd02')
    new_loader = require_fixed(current, new_sec, 0x3c1353b, '4883f801')
    old_relocs = relocations(old, old_sec)
    new_relocs = relocations(current, new_sec)

    def old_location(va, line, col):
        raw = read_va(old, old_sec, va, 24)
        ptr, length, got_line, got_col = struct.unpack('<QQII', raw)
        rel = old_relocs.get(va)
        if ptr or length != 49 or (got_line, got_col) != (line, col) or not rel or rel[:2] != (8, 0):
            raise ValueError('historical Location record mismatch')
        if not read_va(old, old_sec, rel[2], length).endswith(b'l1/src/abci/state.rs'):
            raise ValueError('historical Location suffix mismatch')
        return {'va': hex(va), 'line': got_line, 'column': got_col}

    def old_location_reference(site, expected):
        raw = read_va(old, old_sec, site, 7, executable=True)
        if raw[:2] not in (b'\x48\x8d', b'\x4c\x8d') or raw[2] & 0xc7 != 0x05:
            raise ValueError('historical Location reference form')
        if site + 7 + struct.unpack_from('<i', raw, 3)[0] != expected:
            raise ValueError('historical Location reference mismatch')

    old_handler_location = old_location(0x569db28, 398, 78)
    old_loader_location = old_location(0x56dfbf8, 107, 37)
    old_location_reference(0x2208db6, 0x569db28)
    old_location_reference(0x3273856, 0x56dfbf8)
    new_handler_location = location_row(current, new_sec, new_relocs)
    new_loader_location = location_row(current, new_sec, new_relocs,
                                       loc=0x64767a8, expected_line=123, expected_col=37)
    _, old_fdes = eh_frame_records(old, old_sec)
    old_fde = [f for f in old_fdes if f['start'] == 0x2208580]
    if len(old_fde) != 1 or old_fde[0]['end'] != 0x2208e5c:
        raise ValueError('historical FDE mismatch')
    return {'old_sha256': HISTORICAL_SHA256, 'old_handler_start': hex(old_fde[0]['start']),
            'old_handler_end': hex(old_fde[0]['end']), 'old_tag_bytes': old_cmp.hex(),
            'new_handler_start': hex(0x22ec9b0), 'new_tag_bytes': new_cmp.hex(),
            'old_loader_check': old_loader.hex(), 'new_loader_check': new_loader.hex(),
            'old_handler_location': old_handler_location,
            'new_handler_location': {'va': new_handler_location[0], 'line': new_handler_location[5],
                                     'column': new_handler_location[6]},
            'old_loader_location': old_loader_location,
            'new_loader_location': {'va': new_loader_location[0], 'line': new_loader_location[5],
                                    'column': new_loader_location[6]},
            'interpretation': 'separate release-specific anchors, not cross-release behavior equivalence'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--old-elf', type=Path, help='optional authenticated retired capture')
    args = parser.parse_args(argv)
    data = TARGET.read_bytes()
    payloads = collect(data)
    old = compare_historical(args.old_elf.read_bytes(), data) if args.old_elf else None
    args.out.mkdir(parents=True, exist_ok=True)
    for name, payload in payloads.items():
        (args.out / name).write_bytes(payload)
    if old is not None:
        print(json.dumps(old, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, struct.error) as exc:
        print(f'abci_keyed_result115: {exc}', file=sys.stderr)
        raise SystemExit(1)
