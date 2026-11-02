#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reproduce the selected node 115 linked-state serialization and digest handoff."""

import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
OLD_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
U64_MAX = (1 << 64) - 1

# FDE extents are unwind ranges, not a source-function census. Previously
# researched bodies are not included here; the parent windows are contextual.
FUNCTIONS = [
    ('digest_adapter', 0x452aab0, 0x452aeb9),
    ('digest_pair', 0x457cf60, 0x457d46f),
    ('context_writer', 0x4d93030, 0x4d933b5),
    ('capture_snapshot', 0x4e363c0, 0x4e3666e),
    ('capture_adapter', 0x4e45a30, 0x4e45c4a),
    ('snapshot_serializer', 0x4e4b3f0, 0x4e4b85e),
    ('exchange_writer', 0x5481900, 0x548263c),
    ('link_wrapper', 0x5485f80, 0x548649f),
    ('map_writer', 0x57ce100, 0x57ce3df),
    ('string_writer', 0x57cf860, 0x57cfd11),
    ('unsigned_writer', 0x57d00b0, 0x57d0245),
    ('u8_writer', 0x57d0250, 0x57d03cd),
    ('u16_writer', 0x57d0510, 0x57d06a2),
    ('u32_writer', 0x57d0750, 0x57d08dd),
    ('u64_writer', 0x57d08e0, 0x57d0a7a),
    ('marker_pack', 0x57d0b20, 0x57d0b6e),
    ('snapshot_name_adapter', 0x5942870, 0x59429d1),
]
CONTEXT_FUNCTIONS = [(0x5a08720, 0x5a08f7c), (0x5a6bfb0, 0x5a6c8ec)]

# Fixed instruction-aligned windows reviewed against the capture. Raw bytes
# are included in the output, not disassembler text or normalized bytes.
WINDOWS = [
    ('prior_select', 'context', 0x5a08853, '4489e834010fb6c0488d0c4506000000488d051d1ef3fa488d15bf06a5fa4584ed480f45d04889e74c89e6e8fdd6a7ff'),
    ('prior_package', 'context', 0x5a08883, '488b04244889442478488b442408488b542410488b4c241848894c2470488b4c242048894c24600f104424280f298424700100000f108424300100000f108c24400100000f298c24900000000f298424800000004c897c244048894424684889042448899424280100004889542408488dac248000000048896c2410488d4424404889442418488dbc24800100004889e6ba01000000e89221b2fe'),
    ('prior_queue', 'context', 0x5a08a40, '498b04240f1040100f298424500100004c8b68280f1080581c00000f298424600100008b4868894c2430488b40604889442428488d7c2434ff15127fad00660f708424500100004e660f7f4424104c896c24200f288424600100000f290424488d3dcaf4aa00488d15d3f4aa004889e6e88ba0f3ff498dbee0030000488d9424800100004c89fee824bcffff'),
    ('prior_delivery', 'context', 0x5a08b15, '488b44247848898424a8000000488b44246848898424b0000000488b84242801000048898424b8000000488b44247048898424c0000000488b44246048898424c80000000f288424700100000f118424d00000004c89bc24e00000000f108424800100000f108c24900100000f118424e80000000f118c24f80000000f108424300100000f108c24400100000f118424080100000f118c2418010000'),
    ('link_entry', 'owned', 0x5485f80, '554157415641554154534881eca80100004989f64989ff488994246001000048898c2468010000488b06488b70284889b424e8000000488d7c2450ff156fef0501'),
    ('link_construct', 'owned', 0x5485fee, '488d352b420201488d9c24d00000004889dfe86bc84b0048c78424c0000000000000004c89b424100100004c8dac24c00000004c89ac2418010000488d6c24204889ac2420010000488d7c24504c8db424100100004c89f6ba01000000e8e0f99bff'),
    ('link_result_and_check', 'owned', 0x5486050, '488b44245048890424488b4424584889442448488b44246848894424080f104424600f29842470010000488b44247048894424400f104424780f29842480010000488d1598410201488b7c24184c89e6ff153aa905014885c00f857f020000488b7c2428488b742430488b9424d8000000488b8c24e0000000ff1569ee05014885c07408488b084889c7ff11'),
    ('link_return_and_release', 'owned', 0x5486279, '488bb424100100004c39e674154885f67410488bbc241801000031d2ff1505920501488b0424498907488b442448498947080f28842470010000410f114710488b442440498947200f28842480010000410f114728488bb424d00000004885f67410488bbc24d800000031d2ff15b5910501488b7424104885f6740d488b7c241831d2ff159e910501488b7424204885f6740d488b7c242831d2ff15879105014c89f84881c4a80100005b415c415d415e415f5dc3'),
    ('link_result_error', 'owned', 0x548632e, '4889442450488d3df8434afb488d0d1f4a02014c8d05003f0201488d542450be2b000000ff15489305010f0b'),
    ('link_unwind_cleanup', 'owned', 0x5486398, '4889c3488bb424100100004885f67e2c488bbc241801000031d2ff15e8900501eb1a4889c3488bb424d00000004885f67542eb504889c3eb4b4889c34c8b3424488b742408eb164889c3488b7c2450488b07ff104c8b3424488b7424084885f6756a4d85f67577488bb424d00000004885f67410488bbc24d800000031d2ff1584900501488b7424104885f67512488b7424204885f6751f4889dfe818a6f600488b7c241831d2ff155b900501488b7424204885f674e1488b7c242831d2ff15449005014889dfe8eca5f600488b7c244031d2ff152f9005014d85f67489488b7c24484c89f631d2ff151a900501488bb424d00000004885f60f8575ffffffeb83ff1521900501'),
    ('closure_dispatch', 'owned', 0x4e45a30, '55415741564154534883ec304889fb85d2747b4989f7c644240e00c644240f00488d15a9806501488d7c240e488d74240fe8bab5c5004885c07573807c240e0074510fb66c240f49c7c4d0eeffff644c8b3425000000004d01e664410fb644244883f8014c89fe0f849400000083f802757540886c2410c644241100488d3da59d6501ff15efae6901e94c0100004889dfeb064889df4c89fee8f208ffff4889d84883c4305b415c415e415f5dc3'),
    ('closure_tls', 'owned', 0x4e45b31, '64410fb74424446441c64424440040886c2410668944241164410fb66c24464080fd020f84820000006441c64424460240886c24204889dfe85208ffff'),
    ('closure_failure', 'owned', 0x4e45bdc, '488d1595a06501be3d000000488d3d3a3eadfbeb13488d15c8ff6701be45000000488d3d2971b0fbff15ae9a69010f0b488d3dbdfc6701e99bfeffff4889c3488d7c2420ff15b2056a01eb09ff15929869014889c3488d7c2410ff15a4056a014889dfe80cae5a01ff1576986901'),
    ('snapshot_prep', 'owned', 0x4e363c0, '554157415641554154534883ec684989f64889fb4c8b26488b4608498b34244c8b7e284881c6781c0000488b084c8b4008488d7c24304c89faff15d1fd6a014c897c2448498b46104d8b2c244c8b60084c8b7810c644240e00c644240f00488d15db766601488d7c240e488d74240fe80c79c6004885c00f8597000000807c240e00744b'),
    ('snapshot_writer', 'owned', 0x4e3648f, '488d7c24504c89ee4c89e24c89f9e84e4f01000f104424300f104c24400f114b280f1143180f104424500f1103488b442460488943104883c4685b415c415d415e415f5dc3'),
    ('snapshot_tls_writer', 'owned', 0x4e3652e, '640fb7414464c641440040886c24106689442411640fb669464080fd020f849300000064c641460240886c2420488d7c24504c89ee4c89e24c89f9e8824e0100'),
    ('snapshot_error_unwind', 'owned', 0x4e365e4, '488d158d966601be3d000000488d3d3234aefbeb13488d15c0f56801be45000000488d3d2167b1fbff15a6906a010f0b488d3db5f26801e964feffff4889c3488d7c2420ff15aafb6a01eb0eff158a8e6a014889c3eb0e4889c3488d7c2410ff1597fb6a01488b7424304885f6740d488b7c243831d2ff15408e6a014889dfe8e8a35b01ff15528e6a01'),
    ('serializer_setup', 'owned', 0x4e4b3f0, '554157415641554154534881ec080100004889cb4989d64989f44889bc24c8000000bf01000000e8c48ee3004989c589d5498b44242848898424d00000004c89a424d800000048c74424780000000048c78424800000000100000048c784248800000000000000488d4424784889442410c744241800040001c644241c00488d7c2428488db424d8000000488d542410e87b64630048b800000000000000804c8b6424284989c74883c0044939c40f85c4020000488b4424784889442408488bbc24800000004c8ba424880000004c8d056325650148897c24204c89e64c89f24889d9ff150f5569014885c0488b5c24080f8517020000'),
    ('serializer_result', 'owned', 0x4e4b6b5, '488b7424784c39fe74154885f67410488bbc248000000031d2ff15cc3d6901488b8c24c8000000488919488b442420488941084c8961104881c4080100005b415c415d415e415f5dc34889442428488d3d5bd1acfb488d0dc72465014c8d0528236501488d542428be2b000000ff15783f6901e993000000'),
    ('serializer_failure', 'owned', 0x4e4b768, '488b5c24304c8b742438488b7424784885f67410488bbc248000000031d2ff15143d69014c8964242848895c24304c89742438488d3dc3d0acfb488d0d0f2465014c8d0560226501488d542428be2b000000ff15e03e69010f0b'),
    ('serializer_unwind', 'owned', 0x4e4b7c2, '4989c7488b7424784885f67e4b488bbc248000000031d2ff15c13c6901eb394989c7488b5c2408eb504989c7488d7c2428e8a8520000eb56ff15c03c69014989c7488b7424784885f67443488bbc2480000000eb314989c748837c240800742e488b7c2420488b742408eb1a4989c7488b7c2428488b07ff104885db7410488b7c24204889de31d2ff15503c69014c89ffe8f8515a01ff15623c6901'),
    ('outer_to_context', 'owned', 0x5481900, '415741564154534883ec184989d64989f74889fb49bc0400000000000080807a0b0074334889e74c89f6ba01000000e8ccc73400488b04244883f8027433488b4c24084983c4fc4c89234889430848894b10e9ce0c00004889e74c89f6ba01000000e839d23400488b04244883f80275cd4d8b3f41807e0b007441488d354676fdfaba080000004c89f7e8d1de34004883f8020f856f0c000041807e0b00741c4889e74c89f6ba3b000000e850c73400488b04244883f802741ceb604889e74c89f6ba3b000000e8d4d13400488b04244883f802754641807e0b007452488d35a07b4afbba050000004c89f7e86fde34004883f8020f850d0c000041807e0b00742d4889e74c89f6ba11000000e8eec63400488b04244883f802742d488b4c240866480f6ec9660f6ec0e9e30b00004889e74c89f6ba11000000e861d13400488b04244883f80275d341807e0b01751e488d3513794afbba030000004c89f7e8fcdd34004883f8020f859a0b00004889e74c89fe4c89f2e8b41591ff488b04244c39e00f85ab0b0000'),
    ('outer_error_exits', 'owned', 0x5482608, '66480f6ec066480f6eca660f6cc14983c4fc4c89e0488903f30f7f43084889d84883c4185b415c415e415fc3f30f6f442408ebe1'),
    ('context_first_fields', 'owned', 0x4d93030, '4157415641554154534883ec304989d64989f74889fb49bd0400000000000080807a0b007436488d7c24084c89f6ba0d000000e898b0a300488b4424084883f8027436488b4c24104983c5fc4c892b4889430848894b10e9fc020000488d7c24084c89f6ba0d000000e802bba300488b4424084883f80275ca4d8b671041807e0b01751e488d352f30b8fbba0f0000004c89f7e898c7a3004883f8020f8594020000488d7c24084c89f64c89e2e8cecfa300488b4424084883f8020f8570020000498b5718498b4f20488d7c24084c89f6e8aa8c07004c396c24080f85660200004d8b672841807e0b01751e488d35d62fb8fbba060000004c89f7e830c7a3004883f8020f852c020000488d7c24084c89f64c89e2e866cfa300488b4424084883f8020f8508020000'),
    ('context_tx_index', 'owned', 0x4d93159, '41807e0b00741a488d35116b6cfbba080000004c89f7e8ecc6a3004883f802754041833f017526498b5708488d7c24204c89f6e81fcfa300488b4424204883f80275364c896c24084c89e8eb44488d7c24084c89f6e8cdce5500488b442408eb304983c5fc4c896c240848894424104889542418e9c7010000488b4c2428488944241048894c2418498d45fc48894424084c39e80f85a6010000'),
    ('context_remaining_fields', 'owned', 0x4d931f3, '41807e0b01751e488d35fe2eb8fbba050000004c89f7e852c6a3004883f8020f854e010000498b5730488d7c24084c89f6e887cea300488b4424084883f8020f85290100004d8d4760488d15496c6cfb488d7c2408b9040000004c89f6e8eba707004c396c24080f85170100004d8d476c488d15992eb8fb488d7c2408b9090000004c89f6e8c3a707004c396c24080f85ef0000004d8b4738488d15a55b6cfb488d7c2408b9080000004c89f6e85baa07004c396c24080f85c70000004d8b4740488d1575646cfb488d7c2408b9080000004c89f6e833aa07004c396c24080f859f0000004d8b4748488d152a2eb8fb488d7c2408b90c0000004c89f6e80baa07004c396c2408757b498b5750488d7c24084c89f6e8a39707004c396c24087563458b4778488d15a1166cfb488d7c2408b9100000004c89f6e89fbd07004c396c2408753f4d8b4758488d15e22db8fb488d7c2408b9030000004c89f6e8cb8507004c396c2408751b4c892beb27488b5424104983c5fc4c892b4889430848895310eb11488b442418488943100f104424080f11034889d84883c4305b415c415d415e415fc3488b44241848894310488b442408488903488b44241048894308ebd3'),
    ('map_marker_setup', 'owned', 0x57ce100, '554157415641554154534883ec2881fa000001000f92c034df83fa100fb6c0bd800000000f43e84c8b364d8b3e4d8b66104d39e748897c24080f8484010000440fb6ed895424040fb6f24489efe8ce29000089c34d39e70f845e020000498b460842881c20498b4e10488d7101498976104080fddf0f84bb0000004181fdde0000004c8b6c24088b7c24040f8510010000'),
    ('map_wide_store', 'owned', 0x57ce273, '89fb66c1c308498b460866891c30b802000000eb1589fb0fcb4c8b6c2408498b4608891c30b8040000004901461041886d0841887d0949c7450002000000'),
    ('string_marker_setup', 'owned', 0x57cf860, '554157415641554154534883ec384889742430488b0f83fa20895424147304b3a0eb1989d081fa000100007304b3d9eb0b3d000001000f92c380f3db4c8b214c8b69104d39ec48894c24080f845f0300000fb6eb4989d60fb6f289efe85f1200004189c74d39ec4c8b4c24080f84ed030000498b410846883c28498b4910488d79014989791080fbdb0f8480010000'),
    ('string_copy', 'owned', 0x57cfbd3, '4d85ff741b49037908488b7424304c89faff151ef9d0004c8b4c2408498b79104c01ff49897910b80200000031d2'),
    ('marker_combine', 'owned', 0x57d0b20, '89f80fb6c88d9140ffffff83fa207301c381f98f0000007e1b81f990000000742281f9a000000075084080e61f4080cea089f0c385c974f94080e60f4080ce8089f0c34080e60f4080ce9089f0c3'),
    ('uint_dispatch', 'owned', 0x57d00b0, '415741564154534883ec184889fb4881fa00010000734284d20f888e0000004c8b364d8b3e498b76104939f70f84de0000004939f70f8430010000498b460888143049ff4610c643080088530948c70302000000e9a80000004881fa0000010073214889f789d6e8f40300004883f802757e48c7030200000048c74308cd000000eb7e4889d04889f748c1e820754289d6e80a0600004883f802755448c7030200000048c74308ce000000eb540fb6c24889f789c6e8e60000004883f802753048c7030200000048c74308cc000000eb304889d6e8570700004883f802751148c7030200000048c74308cf000000eb1148890348b8030000002600000048894308'),
    ('u8_write_marker', 'owned', 0x57d0276, '488b4b08c60401cc4c8b33488b4b10488d410148894310'),
    ('u8_write_value', 'owned', 0x57d02f2, '4939c60f84aa000000488b4b084088340148ff431041bf02000000'),
    ('u16_write_marker', 'owned', 0x57d0536, '488b4b08c60401cd488b0b488b5310488d4201488943104889cf4829c74883ff020f8396000000'),
    ('u16_swap', 'owned', 0x57d05c2, '89ee66c1c6084983ff017729'),
    ('u16_store', 'owned', 0x57d05f3, '66c1c608488b4b0866893401488343100241be02000000'),
    ('u32_write_marker', 'owned', 0x57d0776, '488b4b08c60401ce488b0b488b5310488d4201488943104889cf4829c74883ff040f8394000000'),
    ('u32_swap', 'owned', 0x57d07ff, '4929c789ee0fce4983ff037727'),
    ('u32_store', 'owned', 0x57d0831, '0fce488b4b08893401488343100441be02000000'),
    ('u64_write_marker', 'owned', 0x57d0907, '488b4b08c60401cf488b0b488b5310488d4201488943104889cf4829c74883ff080f8399000000'),
    ('u64_swap', 'owned', 0x57d098d, '488b43104929c74c89e6480fce4983ff07772a'),
    ('u64_store', 'owned', 0x57d09c7, '480fce488b4b0848893401488343100841be02000000'),
    ('digest_adapter_entry', 'owned', 0x452aab0, '554157415641554154534883ec384989f74889fb85d20f848f01000049c7c4d0eeffff644c8b3425000000004d01e664410fb644244883f801742083f8020f8410010000488d35c5659eff4c89f7ff150c5afb016441c6442448016441807c2446020f84ec000000644d8b6c24284d85ed0f84dd00000041807d00000f84d2000000'),
    ('digest_adapter_fast', 'owned', 0x452ac04, '31ffe8e51a7d014885c00f84040200000fb6404683f802743e85c00f840002000031ed64410fb644244883f8010f84de00000083f8020f85be00000040882c24c644240100488d3d0830f501ff15525dfb01e9bb0100004889df4c89fee8fa2205004889d84883c4385b415c415d415e415f5dc3'),
    ('digest_adapter_guarded', 'owned', 0x452ad15, '64410fb74424446441c64424440040882c24668944240164410fb66c24464080fd020f84830000006441c64424460240886c24204889df4c89fee80c22050031ffe895197d01'),
    ('digest_first', 'owned', 0x457cf60, '554157415641554154534881ece80800004989f64889fbbf01000000e85f73700148894424788954240c4d8b3e4d8b6e08ff15f124f6010f57c00f294424100f294424200f294424300f294424400f10152babedfb0f295424500f100d2fabedfb0f294c24600f299424e00100000f298c24f00100000f298424700100000f298424800100000f298424900100000f298424a00100000f299424b00100000f298c24c0010000c78424d70100000000000048c78424d001000000000000888424db010000c784240002000000000000488b2dda24f6014c8da424700100004c89e74c89fe4c89eaffd54c8b3dc824f601488dbc24300100004c89e641ffd74c89b42480000000498b46100f10000f1048100f118c24600100000f11842450010000'),
    ('digest_second', 'owned', 0x457d081, 'ff150124f6010f57c90f294c24100f294c24200f294c24300f294c24400f10053baaedfb0f29442450660f10153eaaedfb660f295424600f298424e0010000660f299424f00100000f298c24700100000f298c24800100000f298c24900100000f298c24a00100000f298424b0010000660f299424c0010000c78424d70100000000000048c78424d001000000000000888424db010000c7842400020000000000000f108424300100000f108c24400100000f294c24200f294424104c8da424700100004c8d6c2410ba200000004c89e74c89eeffd50f108424500100000f108c24600100000f294c24200f29442410ba200000004c89e74c89eeffd5488d7c24104c89e641ffd7660f10442410660f104c2420660f114b10660f1103'),
    ('capture_probe_error', 'owned', 0x4e45ade, '48894424204889542428488d4424204889442410488d0527087d004889442418488d3d525d5ffb488d15f47f6501488d742410ff15a19b6901488d35f298e9004c89f7ff15e9a969014c89fe6441c644244801'),
    ('snapshot_probe_error', 'owned', 0x4e364d4, '48894424204889542428488d4424204889442410488d0531fe7d004889442418488d3d5c5360fb488d15fe756601488d742410ff15ab916a01e900010000488d35f78eea004c89f7ff15ee9f6a0148c7c1d0eeffff64c6414801'),
    ('map_growth_failure', 'owned', 0x57ce1ea, '837c241001746a'),
    ('map_error_return', 'owned', 0x57ce25b, '49c745000100000048b8030000002600000049894508eb3e'),
    ('string_growth_failure', 'owned', 0x57cfb60, '498b314889f04829f84939c7766548ba0300000026000000b8010000004c01ff727f4889d3488d04364839c7480f47c74883f80941bc080000004c0f43e0498b5108488d7c241841b8010000004d89ce41b9010000004c89e1e8923a1900837c2418010f85b00000004889dab801000000eb2e'),
    ('uint_growth_failure', 'owned', 0x57d01c0, '4989d4488d04364883f80941bf080000004c0f43f8498b56084889e741b80100000041b9010000004c89f9e860341900833c2401750948c70300000000eba4488b442408498946084d893e498b76104c89e24939f70f85d0feffff4989d4ba01000000b90100000041b8010000004c89f74c89fee8d73719004c89e2498b7610e9a6feffff'),
    ('u8_growth_failure', 'owned', 0x57d028d, '4939c675604883c10241bf010000004839c1726c89f5488d14004839d1480f47d14883fa0941be080000004c0f43f2488b53084889e741b80100000041b9010000004889c64c89f1e876331900833c2401742d488b442408488943084c8933488b431089ee'),
    ('u16_growth_failure', 'owned', 0x57d055d, '4883c20341be010000004839c20f829a00000089f5488d04094839c2480f47c24883f80941bf080000004c0f43f8488b53084889e741b80100000041b9010000004889ce4c89f9e8a7301900833c2401745b488b442408488943084c893b488b43104929c7'),
    ('u32_growth_failure', 'owned', 0x57d079d, '4883c20541be010000004839c20f829500000089f5488d04094839c2480f47c24883f80941bf080000004c0f43f8488b53084889e741b80100000041b9010000004889ce4c89f9e8672e1900833c24017456488b442408488943084c893b488b4310'),
    ('u64_growth_failure', 'owned', 0x57d092e, '4883c20941be010000004839c20f829c0000004989f4488d04094839c2480f47c24883f80941bf080000004c0f43f8488b53084889e741b80100000041b9010000004889ce4c89f9e8d52c1900833c2401745c488b442408488943084c893b'),
    ('name_match', 'owned', 0x5942870, '415741564154534883ec484889fb4c8b3d93e0b900418b475085c0754248837e080a7576488b0648b9616263695f7374614833080fb750084881f27465000031c04809ca488d15fe59fffa488d0d9e76b1fa480f44ca0f95c04883c003eb47'),
    ('name_default', 'owned', 0x5942903, '48837e080a748ab804000000488d0d4a76b1fa'),
    ('name_format', 'owned', 0x5942916, '48894c2438488944244048893424488d05f539cdff4889442408488d4c243848894c24104889442418488d35dea6affa4c8b259bcdb9004c8d7424204889e24c89f741ffd44983c7184c893c24488d0546f8f1ff48894424084c897424104889442418488d3595ccb0fa4889e24889df41ffd4488b7424204885f6740d488b7c242831d2ff1500cbb9004889d84883c4485b415c415e415fc3'),
    ('name_unwind', 'owned', 0x59429af, '4889c3488b7424204885f6740d488b7c242831d2ff15d7cab9004889dfe87fe0aa00'),
]

# The successful serializer temporarily reuses its former vector slot, then
# marks it moved before the conditional cleanup and returned triple.
WINDOWS.extend([
    ('serializer_reuse_local', 'owned', 0x4e4b4e7, 'bf01000000e8ef8de3004889442410895424184c896c247889ac2480000000'),
    ('serializer_clear_owner', 'owned', 0x4e4b5aa, '4c897c2478'),
    ('bootstrap_after_copy', 'context', 0x5a6c140, '48c78424a01600001a40f600c78424a816000000000000c68424ad16000000488dbc24b00200004c89f6e8b1c5f9ff'),
])

# Targets of these selected, instruction-aligned control transfers are decoded
# from displacement bytes. Slots already owned by other work are anchor only.
EDGES = [
    ('parent_link', 'context', 0x5a0887e, 'call', 0x5485f80),
    ('parent_digest_adapter', 'context', 0x5a08919, 'call', 0x452aab0),
    ('parent_history', 'context', 0x5a08ac7, 'call', 0x5a046f0),
    ('link_name_builder', 'owned', 0x5486000, 'call', 0x5942870),
    ('link_capture', 'owned', 0x548604b, 'call', 0x4e45a30),
    ('link_check', 'owned', 0x54860a0, 'slot', 0x64e09e0),
    ('link_check_error', 'owned', 0x54860a9, 'jcc', 0x548632e),
    ('link_followup', 'owned', 0x54860c9, 'slot', 0x64e4f38),
    ('capture_probe', 'owned', 0x4e45a61, 'call', 0x5aa1020),
    ('capture_probe_error', 'owned', 0x4e45a69, 'jcc', 0x4e45ade),
    ('capture_simple', 'owned', 0x4e45a70, 'jcc', 0x4e45ac3),
    ('capture_invoke', 'owned', 0x4e45ac9, 'call', 0x4e363c0),
    ('capture_tls_reentry', 'owned', 0x4e45b54, 'jcc', 0x4e45bdc),
    ('capture_invoke_tls', 'owned', 0x4e45b69, 'call', 0x4e363c0),
    ('snapshot_db_save', 'owned', 0x4e363f9, 'slot', 0x64e61d0),
    ('snapshot_probe', 'owned', 0x4e3642f, 'call', 0x5a9dd40),
    ('snapshot_probe_error', 'owned', 0x4e36437, 'jcc', 0x4e364d4),
    ('snapshot_simple', 'owned', 0x4e36442, 'jcc', 0x4e3648f),
    ('snapshot_serialize', 'owned', 0x4e3649d, 'call', 0x4e4b3f0),
    ('snapshot_serialize_tls', 'owned', 0x4e36569, 'call', 0x4e4b3f0),
    ('state_encode', 'owned', 0x4e4b480, 'call', 0x5481900),
    ('state_encode_error', 'owned', 0x4e4b49e, 'jcc', 0x4e4b768),
    ('state_output', 'owned', 0x4e4b4d3, 'slot', 0x64e09e8),
    ('state_output_error', 'owned', 0x4e4b4e1, 'jcc', 0x4e4b6fe),
    ('outer_unnamed', 'owned', 0x5481922, 'jcc', 0x5481957),
    ('outer_map_one', 'owned', 0x548192f, 'call', 0x57ce100),
    ('outer_map_ok', 'owned', 0x548193c, 'jcc', 0x5481971),
    ('outer_exchange_name', 'owned', 0x548198a, 'call', 0x57cf860),
    ('outer_map_59', 'owned', 0x54819ab, 'call', 0x57ce100),
    ('outer_locus_name', 'owned', 0x54819ec, 'call', 0x57cf860),
    ('outer_map_17', 'owned', 0x5481a0d, 'call', 0x57ce100),
    ('outer_ctx_name', 'owned', 0x5481a5f, 'call', 0x57cf860),
    ('outer_ctx_value', 'owned', 0x5481a77, 'call', 0x4d93030),
    ('ctx_map_13', 'owned', 0x4d93063, 'call', 0x57ce100),
    ('ctx_first_name_error', 'owned', 0x4d930cc, 'jcc', 0x4d93366),
    ('ctx_height_name', 'owned', 0x4d9312b, 'call', 0x57cf860),
    ('ctx_height_value', 'owned', 0x4d93145, 'call', 0x57d00b0),
    ('ctx_height_error', 'owned', 0x4d93153, 'jcc', 0x4d93361),
    ('map_marker_pack', 'owned', 0x57ce14d, 'call', 0x57d0b20),
    ('string_marker_pack', 'owned', 0x57cf8bc, 'call', 0x57d0b20),
    ('string_copy', 'owned', 0x57cfbe4, 'slot', 0x64df508),
    ('uint_below_256', 'owned', 0x57d00c5, 'jcc', 0x57d0109),
    ('uint_above_127', 'owned', 0x57d00c9, 'jcc', 0x57d015d),
    ('uint_above_65535', 'owned', 0x57d0110, 'jcc', 0x57d0133),
    ('uint16', 'owned', 0x57d0117, 'call', 0x57d0510),
    ('uint32', 'owned', 0x57d0141, 'call', 0x57d0750),
    ('uint8', 'owned', 0x57d0165, 'call', 0x57d0250),
    ('uint64', 'owned', 0x57d0184, 'call', 0x57d08e0),
    ('digest_adapter_plain', 'owned', 0x452aac6, 'jcc', 0x452ac5b),
    ('digest_pair_plain', 'owned', 0x452ac61, 'call', 0x457cf60),
    ('digest_pair_guarded', 'owned', 0x452ad4f, 'call', 0x457cf60),
    ('digest_platform_a', 'owned', 0x457cf91, 'slot', 0x64df488),
    ('digest_update_load', 'owned', 0x457d02f, 'ripmov', 0x64df510),
    ('digest_finalize_load', 'owned', 0x457d049, 'ripmov', 0x64df518),
    ('digest_platform_b', 'owned', 0x457d081, 'slot', 0x64df488),
    ('name_wrong_length', 'owned', 0x5942892, 'jcc', 0x594290a),
    ('name_second_length', 'owned', 0x5942908, 'jcc', 0x5942894),
    ('bootstrap_end_selector', 'context', 0x5a6c16a, 'call', 0x5a08720),
]

# Offsets in .rela.dyn bind static slots; they do not prove dynamic execution.
RELOCS = {
    0x64df488: (8, 0, 0x160bee0), 0x64df4a0: (8, 0, 0x635de30),
    0x64df508: (6, 7, 0), 0x64df510: (8, 0, 0x160b3a0),
    0x64df518: (8, 0, 0x160bcd0), 0x64df6a0: (8, 0, 0x1680c30),
    0x64e09e0: (8, 0, 0x1505a50), 0x64e09e8: (8, 0, 0x15024a0),
    0x64e4f30: (8, 0, 0x38d8240), 0x64e4f38: (8, 0, 0x38d7f20),
    0x64e61d0: (8, 0, 0x38c2e00),
    0x649da10: (8, 0, 0x443168), 0x649da28: (8, 0, 0x443168),
    0x649da40: (8, 0, 0x443168), 0x64aa230: (8, 0, 0x443168),
    0x64aa248: (8, 0, 0x443168), 0x64aa220: (8, 0, 0x929ae3),
}
LOCATIONS = [
    (0x649da10, 193, 56), (0x649da28, 195, 17),
    (0x649da40, 195, 64), (0x64aa230, 201, 9),
    (0x64aa248, 201, 32),
]
LITERALS = [
    ('source_path', 0x443168, b'l1/src/abci/state.rs'),
    ('snapshot_key', 0x929ae3, b'abci_state'),
    ('binary_suffix', 0x9382b9, b'rmp'), ('text_suffix', 0x459f60, b'json'),
    ('exchange', 0x458fc8, b'exchange'), ('locus', 0x929584, b'locus'),
    ('context', 0x92936a, b'ctx'), ('height', 0x9160f9, b'height'),
    ('hardfork_height', 0x9160ea, b'hardfork_height'),
    ('round', 0x9160ff, b'round'), ('time', 0x459e8c, b'time'),
    ('previous_time', 0x916104, b'prev_time'),
    ('next_order_id', 0x458e38, b'next_oid'),
    ('next_limit_id', 0x459730, b'next_lid'),
    ('next_twap_id', 0x91610d, b'next_twap_id'),
    ('periodic', 0x458f30, b'periodic'), ('freeze', 0x93a687, b'freeze'),
    ('link_message', 0x929b03, b'linked abci state'),
    ('serialized_message', 0x91875b, b'serialized abci state'),
    ('unwrap_message', 0x918865, b'called `Result::unwrap()` on an `Err` value'),
    ('digest_iv_a', 0x457ae0, bytes.fromhex('67e6096a85ae67bb72f36e3c3af54fa5')),
    ('digest_iv_b', 0x457af0, bytes.fromhex('7f520e518c68059babd9831f19cde05b')),
]

# A name reference and input-offset instruction are checked independently.
# 'value_site' is a value writer or a named-field adapter, not a full schema.
FIELDS = [
    ('hardfork_height', 0x4d930b4, 0x4d930a9, 0x10, 0x4d930dd),
    ('height', 0x4d9311c, 0x4d93111, 0x28, 0x4d93145),
    ('round', 0x4d931fa, 0x4d93218, 0x30, 0x4d93224),
    ('time', 0x4d9323c, 0x4d93238, 0x60, 0x4d93250),
    ('prev_time', 0x4d93264, 0x4d93260, 0x6c, 0x4d93278),
    ('next_oid', 0x4d9328c, 0x4d93288, 0x38, 0x4d932a0),
    ('next_lid', 0x4d932b4, 0x4d932b0, 0x40, 0x4d932c8),
    ('next_twap_id', 0x4d932dc, 0x4d932d8, 0x48, 0x4d932f0),
]

# The operand byte slices are part of checked original instructions. These
# records make the selected object/stack relations explicit and reproducible.
OPERANDS = [
    ('bootstrap_tail_qword', 0x5a6c140, '48c78424a01600001a40f600', 4, 4, 0x16a0),
    ('bootstrap_tail_dword', 0x5a6c14c, 'c78424a816000000000000', 3, 4, 0x16a8),
    ('bootstrap_tail_byte', 0x5a6c157, 'c68424ad16000000', 3, 4, 0x16ad),
    ('link_height_offset', 0x5485faa, '488b7028', 3, 1, 0x28),
    ('link_closure_state_slot', 0x5486011, '4c89b42410010000', 4, 4, 0x110),
    ('link_closure_default_slot', 0x5486021, '4c89ac2418010000', 4, 4, 0x118),
    ('link_closure_destination_slot', 0x548602e, '4889ac2420010000', 4, 4, 0x120),
    ('capture_closure_default', 0x4e363d7, '488b4608', 3, 1, 0x08),
    ('capture_height_offset', 0x4e363df, '4c8b7e28', 3, 1, 0x28),
    ('capture_db_object_offset', 0x4e363e3, '4881c6781c0000', 3, 4, 0x1c78),
    ('capture_closure_destination', 0x4e36404, '498b4610', 3, 1, 0x10),
    ('capture_destination_pointer', 0x4e3640c, '4c8b6008', 3, 1, 0x08),
    ('capture_destination_length', 0x4e36410, '4c8b7810', 3, 1, 0x10),
    ('result_second_part', 0x4e364b0, '0f114318', 3, 1, 0x18),
    ('result_second_tail', 0x4e364ac, '0f114b28', 3, 1, 0x28),
    ('result_first_tail', 0x4e364c1, '48894310', 3, 1, 0x10),
    ('serializer_height_offset', 0x4e4b421, '498b442428', 4, 1, 0x28),
    ('serializer_named_configuration', 0x4e4b461, 'c744241800040001', 4, 4, 0x01000400),
    ('context_height_offset', 0x4d93111, '4d8b6728', 3, 1, 0x28),
    ('digest_input_length_slot', 0x457cf8d, '4d8b6e08', 3, 1, 0x08),
    ('digest_root_pointer_slot', 0x457d066, '498b4610', 3, 1, 0x10),
    ('digest_first_component_length', 0x457d14a, 'ba20000000', 1, 4, 0x20),
    ('digest_second_component_length', 0x457d171, 'ba20000000', 1, 4, 0x20),
]

# These call sites are investigated for local exception-table coverage only.
UNWIND_WITNESSES = [
    ('link_capture', 0x5485f80, 0x548604b),
    ('link_check', 0x5485f80, 0x54860a0),
    ('link_followup', 0x5485f80, 0x54860c9),
    ('capture_simple', 0x4e45a30, 0x4e45ac9),
    ('capture_guarded', 0x4e45a30, 0x4e45b69),
    ('snapshot_db_save', 0x4e363c0, 0x4e363f9),
    ('snapshot_encode_simple', 0x4e363c0, 0x4e3649d),
    ('snapshot_encode_guarded', 0x4e363c0, 0x4e36569),
    ('serialize_state', 0x4e4b3f0, 0x4e4b480),
    ('output_state', 0x4e4b3f0, 0x4e4b4d3),
    ('digest_plain', 0x452aab0, 0x452ac61),
    ('digest_guarded', 0x452aab0, 0x452ad4f),
    ('digest_update_input', 0x457cf60, 0x457d047),
    ('digest_finish_input', 0x457cf60, 0x457d05b),
]


def authenticate(data, expected=SHA256):
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected:
        raise ValueError('target SHA-256 mismatch')
    return digest


def unique_section(sec_rows, name, expected_type=None):
    matches = [s for s in sec_rows if s['name'] == name]
    if len(matches) != 1 or matches[0]['type'] == 8:
        raise ValueError('missing, duplicate, or fileless section')
    if expected_type is not None and matches[0]['type'] != expected_type:
        raise ValueError('unexpected section type')
    return matches[0]


def file_mapping(sec_rows, address, size, executable=False):
    if type(address) is not int or type(size) is not int or address < 0 or size <= 0:
        raise ValueError('invalid address or size')
    matches = [s for s in sec_rows if s['type'] != 8 and s['flags'] & 2
               and (not executable or s['flags'] & 4)
               and s['address'] <= address and address + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('address lacks one unambiguous file-backed section')
    s = matches[0]
    return s['offset'] + address - s['address'], s['name']


def read_va(data, sec_rows, address, size, executable=False):
    off, _ = file_mapping(sec_rows, address, size, executable)
    if off + size > len(data):
        raise ValueError('read outside file')
    return bytes(data[off:off + size])


def read_relocations(data, sec_rows, expected):
    section = unique_section(sec_rows, '.rela.dyn', 4)
    if section['size'] % 24 or section['offset'] + section['size'] > len(data):
        raise ValueError('invalid relocation section')
    found = {}
    for off in range(section['offset'], section['offset'] + section['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, off)
        if slot not in expected:
            continue
        if slot in found:
            raise ValueError('duplicate selected relocation')
        found[slot] = (info & 0xffffffff, info >> 32, addend, off)
    for slot, want in expected.items():
        row = found.get(slot)
        if row is None or row[:3] != want:
            raise ValueError('missing or changed selected relocation')
    return found


def symbol_name(data, sec_rows, index):
    sym = unique_section(sec_rows, '.dynsym', 11)
    strings = unique_section(sec_rows, '.dynstr', 3)
    if sym['size'] % 24 or not 0 <= index < sym['size'] // 24:
        raise ValueError('invalid dynamic symbol')
    off = sym['offset'] + index * 24
    name_off, info, other, shndx, value, size = struct.unpack_from('<IBBHQQ', data, off)
    if shndx != 0 or name_off >= strings['size']:
        raise ValueError('symbol is not a valid undefined import')
    begin, end = strings['offset'] + name_off, strings['offset'] + strings['size']
    zero = data.find(b'\0', begin, end)
    if zero < 0:
        raise ValueError('unterminated dynamic symbol')
    return bytes(data[begin:zero]).decode('ascii')


def checked_windows(data, sec_rows):
    rows, names = [], set()
    for label, scope, va, expected_hex in WINDOWS:
        if label in names or scope not in ('owned', 'context'):
            raise ValueError('invalid or duplicate window')
        names.add(label)
        expected = bytes.fromhex(expected_hex)
        actual = read_va(data, sec_rows, va, len(expected), True)
        if actual != expected:
            raise ValueError('changed selected instruction window: ' + label)
        off, _ = file_mapping(sec_rows, va, len(expected), True)
        rows.append((label, scope, hex(va), hex(off), len(actual), actual.hex()))
    return rows


def decode_edge(data, sec_rows, va, form):
    first = read_va(data, sec_rows, va, 2, True)
    if form == 'call' and first[0] == 0xe8:
        length, displacement_offset = 5, 1
    elif form == 'slot' and first == b'\xff\x15':
        length, displacement_offset = 6, 2
    elif form == 'ripmov' and first in (b'\x48\x8b', b'\x4c\x8b'):
        insn = read_va(data, sec_rows, va, 7, True)
        if insn[2] & 0xc7 != 5:
            raise ValueError('not a RIP-relative move')
        length, displacement_offset = 7, 3
    elif form == 'jcc' and 0x70 <= first[0] <= 0x7f:
        raw = read_va(data, sec_rows, va, 2, True)
        return va + 2 + struct.unpack_from('<b', raw, 1)[0], raw
    elif form == 'jcc' and first[0] == 0x0f and 0x80 <= first[1] <= 0x8f:
        length, displacement_offset = 6, 2
    else:
        raise ValueError('unexpected selected transfer opcode')
    raw = read_va(data, sec_rows, va, length, True)
    return va + length + struct.unpack_from('<i', raw, displacement_offset)[0], raw


def decode_lea(data, sec_rows, va):
    raw = read_va(data, sec_rows, va, 7, True)
    if raw[0] not in (0x48, 0x4c) or raw[1] != 0x8d or raw[2] & 0xc7 != 5:
        raise ValueError('unexpected selected LEA')
    return va + 7 + struct.unpack_from('<i', raw, 3)[0]


def checked_edges(data, sec_rows):
    rows = []
    for label, scope, va, form, expected in EDGES:
        actual, raw = decode_edge(data, sec_rows, va, form)
        if actual != expected:
            raise ValueError('changed selected transfer: ' + label)
        off, _ = file_mapping(sec_rows, va, len(raw), True)
        rows.append((label, scope, hex(va), hex(off), form, raw.hex(), hex(actual)))
    return rows


def checked_operands(data, sec_rows):
    rows = []
    for label, va, pin, offset, size, expected in OPERANDS:
        raw = read_va(data, sec_rows, va, len(bytes.fromhex(pin)), True)
        if raw.hex() != pin or offset + size > len(raw):
            raise ValueError('changed selected operand: ' + label)
        value = int.from_bytes(raw[offset:offset + size], 'little')
        if value != expected:
            raise ValueError('unexpected operand value: ' + label)
        rows.append((label, hex(va), raw.hex(), offset, size, hex(value)))
    return rows


def checked_locations(data, sec_rows, relocations):
    path_va = 0x443168
    path = read_va(data, sec_rows, path_va, 20)
    if path != b'l1/src/abci/state.rs':
        raise ValueError('changed Location path')
    rows = []
    for va, expected_line, expected_col in LOCATIONS:
        if relocations[va][:3] != (8, 0, path_va):
            raise ValueError('invalid Location relocation')
        size, line, col = struct.unpack('<QII', read_va(data, sec_rows, va + 8, 16))
        if (size, line, col) != (len(path), expected_line, expected_col):
            raise ValueError('changed Location record')
        off, _ = file_mapping(sec_rows, va, 24)
        rows.append((hex(va), hex(off), path.decode('ascii'), size, line, col))
    return rows


def checked_literals(data, sec_rows):
    rows = []
    for label, va, expected in LITERALS:
        raw = read_va(data, sec_rows, va, len(expected))
        if raw != expected:
            raise ValueError('changed literal: ' + label)
        off, _ = file_mapping(sec_rows, va, len(raw))
        rows.append((label, hex(va), hex(off), len(raw), raw.hex()))
    return rows


def checked_fields(data, sec_rows):
    valid_names = {raw.decode('ascii'): (va, raw) for _, va, raw in LITERALS
                   if all(0x20 <= c < 0x7f for c in raw)}
    rows = []
    for name, name_ref, operand_va, expected_offset, value_site in FIELDS:
        target = decode_lea(data, sec_rows, name_ref)
        if name not in valid_names or target != valid_names[name][0]:
            raise ValueError('wrong field-name reference')
        raw = read_va(data, sec_rows, operand_va, 4, True)
        if raw[:3] not in (b'\x4d\x8b\x67', b'\x49\x8b\x57',
                           b'\x4d\x8d\x47', b'\x4d\x8b\x47') or raw[3] != expected_offset:
            raise ValueError('wrong field operand')
        target_value, call_bytes = decode_edge(data, sec_rows, value_site, 'call')
        rows.append((name, hex(name_ref), hex(target), hex(operand_va), raw.hex(),
                     hex(raw[3]), hex(value_site), call_bytes.hex(), hex(target_value)))
    return rows


def checked_fdes(data, sec_rows):
    _, header = unwind_index(data)
    _, fdes = eh_frame_records(data, sec_rows)
    by_start = {}
    for row in fdes:
        by_start.setdefault(row['start'], []).append(row)
    by_fde = {}
    for row in header:
        if row['fde'] in by_fde:
            raise ValueError('duplicate indexed FDE')
        by_fde[row['fde']] = row
    for start, end in CONTEXT_FUNCTIONS:
        matches = by_start.get(start, [])
        if len(matches) != 1 or matches[0]['end'] != end:
            raise ValueError('missing or changed context FDE')
        indexed = by_fde.get(matches[0]['fde'])
        if indexed is None or indexed['start'] != start:
            raise ValueError('context FDE/header start mismatch')
        if any(other is not matches[0] and other['start'] < end and start < other['end'] for other in fdes):
            raise ValueError('overlapping context FDE')
        file_mapping(sec_rows, start, end - start, True)
    chosen, rows = {}, []
    for label, start, end in FUNCTIONS:
        matches = by_start.get(start, [])
        if len(matches) != 1 or matches[0]['end'] != end:
            raise ValueError('missing or changed FDE extent: ' + label)
        fde = matches[0]
        indexed = by_fde.get(fde['fde'])
        if indexed is None or indexed['start'] != start:
            raise ValueError('FDE/header start mismatch')
        if any(other is not fde and other['start'] < end and start < other['end'] for other in fdes):
            raise ValueError('overlapping selected FDE')
        off, section = file_mapping(sec_rows, start, end - start, True)
        raw = read_va(data, sec_rows, start, end - start, True)
        chosen[start] = fde
        rows.append((label, hex(start), hex(end), hex(off), len(raw), section,
                     hex(fde['fde']), hex(fde['cie']),
                     '' if fde['lsda'] is None else hex(fde['lsda']),
                     indexed['index'], hashlib.sha256(raw).hexdigest(), raw.hex()))
    for label, scope, va, expected_hex in WINDOWS:
        end = va + len(bytes.fromhex(expected_hex))
        choices = [(s, e) for _, s, e in FUNCTIONS] if scope == 'owned' else CONTEXT_FUNCTIONS
        if sum(s <= va and end <= e for s, e in choices) != 1:
            raise ValueError('window is not within its selected FDE: ' + label)
    return chosen, rows


def parse_lsda(data, sec_rows, start, end, lsda):
    section = unique_section(sec_rows, '.gcc_except_table')
    off, name = file_mapping(sec_rows, lsda, 1)
    limit = section['offset'] + section['size']
    if name != '.gcc_except_table' or limit > len(data) or off >= limit:
        raise ValueError('LSDA outside exception table')
    pos = off
    if data[pos] != 0xff:
        raise ValueError('unsupported LSDA base')
    pos += 1
    if pos >= limit:
        raise ValueError('truncated LSDA')
    encoding = data[pos]
    pos += 1
    type_table = None
    if encoding == 0x9b:
        type_offset, pos = uleb(data, pos, limit)
        if type_offset > limit - pos:
            raise ValueError('LSDA type table outside section')
        type_table = pos + type_offset
    elif encoding != 0xff:
        raise ValueError('unsupported LSDA type encoding')
    if pos >= limit or data[pos] != 1:
        raise ValueError('unsupported LSDA call-site encoding')
    pos += 1
    byte_count, pos = uleb(data, pos, limit)
    if byte_count > limit - pos:
        raise ValueError('LSDA call-site table outside section')
    table_end = pos + byte_count
    if type_table is not None and table_end > type_table:
        raise ValueError('LSDA call-site/type table overlap')
    entries, previous_end = [], start
    while pos < table_end:
        entry_off = pos
        begin, pos = uleb(data, pos, table_end)
        length, pos = uleb(data, pos, table_end)
        landing, pos = uleb(data, pos, table_end)
        action, pos = uleb(data, pos, table_end)
        a, z = start + begin, start + begin + length
        dest = start + landing if landing else None
        if a < previous_end or z > end or (dest is not None and not start <= dest < end):
            raise ValueError('invalid LSDA call-site range')
        entries.append((entry_off, a, z, dest, action))
        previous_end = z
    return entries


def checked_unwind(data, sec_rows, fdes):
    tables, rows = {}, []
    for start, fde in fdes.items():
        if fde['lsda'] is not None:
            tables[start] = parse_lsda(data, sec_rows, start, fde['end'], fde['lsda'])
    for label, start, site in UNWIND_WITNESSES:
        matches = [row for row in tables.get(start, []) if row[1] <= site < row[2]]
        if len(matches) > 1:
            raise ValueError('ambiguous LSDA witness')
        if matches:
            off, a, z, dest, action = matches[0]
            rows.append((label, hex(start), hex(site), hex(off), hex(a), hex(z),
                         '' if dest is None else hex(dest), action))
        else:
            rows.append((label, hex(start), hex(site), '', '', '', '', ''))
    return rows, sum(len(v) for v in tables.values())


def all_unwind_records(data, sec_rows, fdes):
    rows = []
    for start, fde in fdes.items():
        lsda = fde['lsda']
        if lsda is None:
            continue
        for off, begin, end, landing, action in parse_lsda(data, sec_rows, start, fde['end'], lsda):
            rows.append((hex(start), hex(lsda), hex(off), hex(begin), hex(end),
                         '' if landing is None else hex(landing), action))
    return rows


def immediate(data, sec_rows, va, opcode, width):
    raw = read_va(data, sec_rows, va, len(opcode) + width, True)
    if not raw.startswith(opcode):
        raise ValueError('changed immediate opcode')
    return int.from_bytes(raw[len(opcode):], 'little')


def encoding_constants(data, sec_rows):
    uint_8 = immediate(data, sec_rows, 0x57d00be, b'\x48\x81\xfa', 4)
    uint_16 = immediate(data, sec_rows, 0x57d0109, b'\x48\x81\xfa', 4)
    if read_va(data, sec_rows, 0x57d00c7, 8, True) != bytes.fromhex('84d20f888e000000'):
        raise ValueError('changed uint small-value sign branch')
    high_word = read_va(data, sec_rows, 0x57d0139, 4, True)
    if high_word != bytes.fromhex('48c1e820'):
        raise ValueError('changed uint high-word test')
    marker_sites = (0x57d027a, 0x57d053a, 0x57d077a, 0x57d090b)
    markers = []
    for site in marker_sites:
        raw = read_va(data, sec_rows, site, 4, True)
        if raw[:3] != bytes.fromhex('c60401'):
            raise ValueError('changed uint marker store')
        markers.append(raw[3])
    if (uint_8, uint_16, markers) != (256, 65536, [0xcc, 0xcd, 0xce, 0xcf]):
        raise ValueError('changed unsigned encoding constants')
    wide_map = read_va(data, sec_rows, 0x57ce117, 2, True)
    if wide_map != bytes.fromhex('34df'):
        raise ValueError('changed map marker selection')
    small_map = immediate(data, sec_rows, 0x57ce11f, b'\xbd', 4)
    map_small_bound = immediate(data, sec_rows, 0x57ce119, b'\x83\xfa', 1)
    string_marker = read_va(data, sec_rows, 0x57cf87f, 2, True)
    if string_marker != bytes.fromhex('b3a0'):
        raise ValueError('changed string marker')
    string_limit = immediate(data, sec_rows, 0x57cf876, b'\x83\xfa', 1)
    if read_va(data, sec_rows, 0x57d0b58, 8, True) != bytes.fromhex('4080e60f4080ce80'):
        raise ValueError('changed map marker packing')
    if read_va(data, sec_rows, 0x57d0b49, 8, True) != bytes.fromhex('4080e61f4080cea0'):
        raise ValueError('changed string marker packing')
    if (small_map, map_small_bound) != (0x80, 16):
        raise ValueError('changed map constants')
    counts = [immediate(data, sec_rows, va, b'\xba', 4)
              for va in (0x548192a, 0x54819a6, 0x5481a08, 0x4d9305e)]
    if counts != [1, 59, 17, 13]:
        raise ValueError('changed selected map counts')
    return {'uint_positive_limit': 1 << 7, 'uint_u8_limit': uint_8,
            'uint_u16_limit': uint_16, 'uint_u32_limit': 1 << high_word[3],
            'uint_markers': markers, 'map_small_base': small_map,
            'map_small_limit': map_small_bound, 'map16_marker': wide_map[1] ^ 1,
            'map32_marker': wide_map[1], 'string_small_base': string_marker[1],
            'string_small_limit': string_limit, 'selected_map_counts': counts}


def encode_uint(value, c):
    if type(value) is not int or not 0 <= value <= U64_MAX:
        raise ValueError('value outside unsigned 64-bit range')
    if value < c['uint_positive_limit']:
        return bytes((value,))
    for limit, marker, width in zip((c['uint_u8_limit'], c['uint_u16_limit'],
                                     c['uint_u32_limit'], 1 << 64),
                                    c['uint_markers'], (1, 2, 4, 8)):
        if value < limit:
            return bytes((marker,)) + value.to_bytes(width, 'big')
    raise ValueError('unreachable integer width')


def map_header(count, c):
    if type(count) is not int or not 0 <= count < (1 << 32):
        raise ValueError('map count outside 32-bit range')
    if count < c['map_small_limit']:
        return bytes((c['map_small_base'] | count,))
    if count < (1 << 16):
        return bytes((c['map16_marker'],)) + count.to_bytes(2, 'big')
    return bytes((c['map32_marker'],)) + count.to_bytes(4, 'big')


def short_string(value, c):
    if not isinstance(value, bytes) or len(value) >= c['string_small_limit']:
        raise ValueError('expected a short byte string')
    return bytes((c['string_small_base'] | len(value),)) + value


def synthetic_models(constants):
    a, b, c, d = constants['selected_map_counts']
    prefix = (map_header(a, constants) + short_string(b'exchange', constants)
              + map_header(b, constants) + short_string(b'locus', constants)
              + map_header(c, constants) + short_string(b'ctx', constants)
              + map_header(d, constants))
    bounds = [0, constants['uint_positive_limit'] - 1, constants['uint_positive_limit'],
              constants['uint_u8_limit'] - 1, constants['uint_u8_limit'],
              constants['uint_u16_limit'] - 1, constants['uint_u16_limit'],
              constants['uint_u32_limit'] - 1, constants['uint_u32_limit'], U64_MAX]
    return {'kind': 'synthetic normal-capacity models; no target execution',
            'conditional_prefix_hex': prefix.hex(),
            'height_key_hex': short_string(b'height', constants).hex(),
            'height_value_cases': [{'value': n, 'encoded_hex': encode_uint(n, constants).hex()} for n in bounds],
            'map_header_cases': [{'count': n, 'encoded_hex': map_header(n, constants).hex()}
                                 for n in (0, 1, 13, 15, 16, 17, 59, 65535, 65536)]}


def location_and_name_refs(data, sec_rows):
    refs = [
        ('link_key_descriptor', 0x5485fee, 0x64aa220),
        ('matched_suffix', 0x59428b4, 0x9382b9),
        ('other_suffix', 0x59428bb, 0x459f60),
        ('link_check_location', 0x5486091, 0x64aa230),
        ('link_error_location', 0x5486341, 0x64aa248),
        ('serializer_write_location', 0x4e4b4be, 0x649da28),
        ('serializer_write_error_location', 0x4e4b711, 0x649da40),
        ('serializer_error_location', 0x4e4b7a9, 0x649da10),
        ('outer_exchange_name', 0x548197b, 0x458fc8),
        ('outer_locus_name', 0x54819dd, 0x929584),
        ('outer_ctx_name', 0x5481a50, 0x92936a),
        ('context_height_name', 0x4d9311c, 0x9160f9),
    ]
    rows = []
    for label, va, expected in refs:
        dest = decode_lea(data, sec_rows, va)
        if dest != expected:
            raise ValueError('changed selected reference')
        raw = read_va(data, sec_rows, va, 7, True)
        rows.append((label, hex(va), raw.hex(), hex(dest)))
    return rows



def checked_selector(data, sec_rows, relocations):
    va = 0x64aa220
    if relocations[va][:3] != (8, 0, 0x929ae3):
        raise ValueError('invalid snapshot-key relocation')
    length = struct.unpack('<Q', read_va(data, sec_rows, va + 8, 8))[0]
    key = read_va(data, sec_rows, relocations[va][2], length)
    if key != b'abci_state':
        raise ValueError('changed snapshot-key descriptor')
    match_length = immediate(data, sec_rows, 0x594288d, bytes.fromhex('48837e08'), 1)
    first = immediate(data, sec_rows, 0x5942897, bytes.fromhex('48b9'), 8).to_bytes(8, 'little')
    last = immediate(data, sec_rows, 0x59428a8, bytes.fromhex('4881f2'), 4).to_bytes(4, 'little')
    if last[2:] != b'\0\0' or match_length != len(first) + 2:
        raise ValueError('changed snapshot-key comparison')
    expected_key = first + last[:2]
    if expected_key != key or decode_lea(data, sec_rows, 0x59428b4) != 0x9382b9:
        raise ValueError('changed snapshot-key match path')
    if decode_lea(data, sec_rows, 0x59428bb) != 0x459f60:
        raise ValueError('changed snapshot-key fallback path')
    matched = read_va(data, sec_rows, 0x9382b9, 3)
    fallback = read_va(data, sec_rows, 0x459f60, 4)
    if (matched, fallback) != (b'rmp', b'json'):
        raise ValueError('changed snapshot suffixes')
    return {'descriptor_va': hex(va), 'key_va': hex(relocations[va][2]),
            'key': key.decode('ascii'), 'key_length': length,
            'key_first_u64': int.from_bytes(first, 'little'),
            'key_last_u16': int.from_bytes(last[:2], 'little'),
            'matched_suffix': matched.decode('ascii'), 'other_suffix': fallback.decode('ascii'),
            'meaning': 'selected input descriptor; formatter and runtime filesystem are boundaries'}


def select_suffix(key, selector):
    if not isinstance(key, bytes):
        raise ValueError('key must be bytes')
    if len(key) != selector['key_length']:
        return selector['other_suffix']
    difference = ((int.from_bytes(key[:8], 'little') ^ selector['key_first_u64']) |
                  (int.from_bytes(key[8:10], 'little') ^ selector['key_last_u16']))
    return selector['matched_suffix'] if difference == 0 else selector['other_suffix']


def render_tsv(head, rows):
    out = io.StringIO(newline='')
    writer = csv.writer(out, delimiter='\t', lineterminator='\n')
    writer.writerow(head)
    writer.writerows(rows)
    return out.getvalue().encode('utf-8')


def render_json(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + '\n').encode('ascii')


def extract(data):
    authenticate(data)
    sec_rows = sections(data)
    windows = checked_windows(data, sec_rows)
    edges = checked_edges(data, sec_rows)
    operands = checked_operands(data, sec_rows)
    relocations = read_relocations(data, sec_rows, RELOCS)
    if symbol_name(data, sec_rows, relocations[0x64df508][1]) != 'memcpy':
        raise ValueError('changed selected import symbol')
    locations = checked_locations(data, sec_rows, relocations)
    literals = checked_literals(data, sec_rows)
    fields = checked_fields(data, sec_rows)
    refs = location_and_name_refs(data, sec_rows)
    selected_fdes, functions = checked_fdes(data, sec_rows)
    unwind, lsda_count = checked_unwind(data, sec_rows, selected_fdes)
    unwind_records = all_unwind_records(data, sec_rows, selected_fdes)
    if len(unwind_records) != lsda_count:
        raise ValueError('inconsistent selected LSDA record count')
    constants = encoding_constants(data, sec_rows)
    selector = checked_selector(data, sec_rows, relocations)
    models = synthetic_models(constants)

    reloc_rows = []
    for slot in sorted(relocations):
        typ, sym, addend, off = relocations[slot]
        reloc_rows.append(('anchor-only', hex(slot), hex(off), typ, sym, hex(addend),
                           bytes(data[off:off + 24]).hex()))
    operand_values = {name: int(value, 16) for name, _va, _raw, _at, _size, value in operands}
    flow = {
        'interpretation': 'selected conditional dataflow only; no observed execution',
        'state_height_offset': hex(operand_values['capture_height_offset']),
        'state_db_subobject_offset': hex(operand_values['capture_db_object_offset']),
        'capture_destination_pointer_offset': hex(operand_values['capture_destination_pointer']),
        'capture_destination_length_offset': hex(operand_values['capture_destination_length']),
        'output_first_tail_offset': hex(operand_values['result_first_tail']),
        'output_second_part_offset': hex(operand_values['result_second_part']),
        'output_second_tail_offset': hex(operand_values['result_second_tail']),
        'digest_input_length_offset': hex(operand_values['digest_input_length_slot']),
        'digest_root_pointer_offset': hex(operand_values['digest_root_pointer_slot']),
        'digest_first_component_length': operand_values['digest_first_component_length'],
        'digest_second_component_length': operand_values['digest_second_component_length'],
        'digest_order': ['serialized_span', 'first_32_byte_result', 'root_32_bytes', 'final_32_byte_result'],
        'dynamic_memcpy_symbol': 'memcpy',
        'bootstrap_post_copy_stack_writes': [
            {'offset': hex(operand_values[name]), 'width': width}
            for name, width in (('bootstrap_tail_qword', 8), ('bootstrap_tail_dword', 4),
                                ('bootstrap_tail_byte', 1))
        ],
        'raw_state_pointer_offsets': ['input->state',
                                      'state+' + hex(operand_values['capture_height_offset']),
                                      'state+' + hex(operand_values['capture_db_object_offset'])],
    }
    summary = {
        'target': 'linux-x86_64-node-115', 'target_sha256': SHA256,
        'scope': 'selected static windows and conditional models; not component coverage',
        'owned_fdes': len(functions), 'selected_windows': len(windows),
        'context_fdes': len(CONTEXT_FUNCTIONS),
        'context_windows': sum(1 for x in windows if x[1] == 'context'),
        'selected_transfers': len(edges), 'selected_operands': len(operands),
        'relocation_anchors': len(reloc_rows), 'locations': len(locations),
        'literals': len(literals), 'field_associations': len(fields),
        'name_selector_sites': 1,
        'location_and_name_references': len(refs),
        'lsda_call_site_records': lsda_count, 'lsda_witnesses': len(unwind),
        'synthetic_height_cases': len(models['height_value_cases']),
        'synthetic_map_cases': len(models['map_header_cases']),
    }
    return {
        'functions.tsv': render_tsv(('label', 'start_va', 'end_va', 'file_offset', 'length',
                                     'section', 'fde_va', 'cie_va', 'lsda_va', 'unwind_index',
                                     'sha256', 'raw_hex'), functions),
        'windows.tsv': render_tsv(('label', 'scope', 'va', 'file_offset', 'length', 'raw_hex'), windows),
        'transfers.tsv': render_tsv(('label', 'scope', 'va', 'file_offset', 'form', 'raw_hex', 'target_va'), edges),
        'operands.tsv': render_tsv(('label', 'va', 'raw_hex', 'operand_offset', 'operand_size', 'value'), operands),
        'relocations.tsv': render_tsv(('scope', 'slot_va', 'file_offset', 'type', 'symbol_index',
                                       'addend', 'raw_hex'), reloc_rows),
        'locations.tsv': render_tsv(('location_va', 'file_offset', 'path_suffix', 'length', 'line', 'column'), locations),
        'references.tsv': render_tsv(('label', 'va', 'raw_hex', 'target_va'), refs),
        'literals.tsv': render_tsv(('label', 'va', 'file_offset', 'length', 'raw_hex'), literals),
        'fields.tsv': render_tsv(('field', 'name_reference_va', 'name_va', 'operand_va', 'operand_hex',
                                  'state_offset', 'value_call_va', 'call_hex', 'callee_va'), fields),
        'unwind.tsv': render_tsv(('label', 'fde_start', 'call_site_va', 'entry_file_offset',
                                  'range_start_va', 'range_end_va', 'landing_va', 'action'), unwind),
        'unwind_records.tsv': render_tsv(('fde_start', 'lsda_va', 'entry_file_offset',
                                          'range_start_va', 'range_end_va', 'landing_va', 'action'),
                                         unwind_records),
        'flow.json': render_json(flow),
        'constants.json': render_json(constants),
        'selector.json': render_json(selector),
        'synthetic.json': render_json(models),
        'summary.json': render_json(summary),
    }


def check_history(data, current=None):
    """Optional independently authenticated old-release byte comparison."""
    authenticate(data, OLD_SHA256)
    sec_rows = sections(data)
    wanted = {0x569db50: (8, 0, 0x1dd8eb), 0x569db80: (8, 0, 0x1dd8eb),
              0x56dfbf8: (8, 0, 0x1dd8eb), 0x57739f8: (8, 0, 0x394b410)}
    reloc = read_relocations(data, sec_rows, wanted)
    old_locations = []
    for va, line, col in ((0x569db50, 196, 9), (0x569db80, 203, 9), (0x56dfbf8, 107, 37)):
        size, got_line, got_col = struct.unpack('<QII', read_va(data, sec_rows, va + 8, 16))
        path = read_va(data, sec_rows, reloc[va][2], size)
        if not path.endswith(b'l1/src/abci/state.rs') or (got_line, got_col) != (line, col):
            raise ValueError('changed historical Location')
        old_locations.append({'va': hex(va), 'line': line, 'column': col,
                              'file_suffix': 'l1/src/abci/state.rs', 'path_length': size})
    old_ranges = [(0x2208e98, '488b7628'), (0x2209015, '488d15344b4903'),
                  (0x2209243, '4c8d0536494903'), (0x220925c, 'ff1596a75603'),
                  (0x3273856, '488d0d9bc34602'), (0x3273871, '4983fd02')]
    for va, pin in old_ranges:
        if read_va(data, sec_rows, va, len(bytes.fromhex(pin)), True).hex() != pin:
            raise ValueError('changed historical witness')
    if decode_lea(data, sec_rows, 0x2209015) != 0x569db50:
        raise ValueError('changed historical first Location reference')
    if decode_lea(data, sec_rows, 0x2209243) != 0x569db80:
        raise ValueError('changed historical second Location reference')
    if decode_lea(data, sec_rows, 0x3273856) != 0x56dfbf8:
        raise ValueError('changed historical loader Location reference')
    dest, _ = decode_edge(data, sec_rows, 0x220925c, 'slot')
    if dest != 0x57739f8:
        raise ValueError('changed historical digest slot')
    _, fdes = eh_frame_records(data, sec_rows)
    found = [f for f in fdes if f['start'] == 0x2208e60]
    if len(found) != 1 or found[0]['end'] != 0x220944c:
        raise ValueError('changed historical FDE')
    old_loader = [f for f in fdes if f['start'] == 0x3273810]
    if len(old_loader) != 1 or old_loader[0]['end'] != 0x327396c:
        raise ValueError('changed historical loader FDE')
    current = TARGET.read_bytes() if current is None else current
    authenticate(current)
    current_sections = sections(current)
    current_location = 0x64767a8
    current_rel = read_relocations(current, current_sections, {current_location: (8, 0, 0x443168)})
    current_path = read_va(current, current_sections, current_rel[current_location][2], 20)
    current_record = struct.unpack('<QII', read_va(current, current_sections, current_location + 8, 16))
    if current_path != b'l1/src/abci/state.rs' or current_record != (20, 123, 37):
        raise ValueError('changed current loader Location')
    return {'release': 94, 'sha256': OLD_SHA256, 'wrapper_start_va': '0x2208e60',
            'wrapper_end_va': hex(found[0]['end']), 'locations': old_locations,
            'height_load_va': '0x2208e98', 'height_load_raw_hex': old_ranges[0][1],
            'historical_digest_site_va': '0x220925c', 'historical_slot_va': hex(dest),
            'historical_slot_addend_va': hex(reloc[dest][2]),
            'historical_loader_start_va': '0x3273810',
            'historical_loader_end_va': hex(old_loader[0]['end']),
            'historical_loader_location_reference_va': '0x3273856',
            'historical_loader_result_compare_va': '0x3273871',
            'historical_loader_result_compare_raw_hex': '4983fd02',
            'node115_loader_location_va': hex(current_location),
            'node115_loader_line': current_record[1],
            'node115_loader_column': current_record[2],
            'comparison_limit': 'separate releases and ABI/layout; no equivalence inferred'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--old-elf', type=Path, help='optional historical ELF for separately authenticated comparison')
    args = parser.parse_args(argv)
    data = TARGET.read_bytes()
    files = extract(data)
    history = check_history(args.old_elf.read_bytes(), data) if args.old_elf else None
    args.out.mkdir(parents=True, exist_ok=True)
    for name, contents in files.items():
        (args.out / name).write_bytes(contents)
    print(json.dumps({'generated_files': len(files), 'historical_check': history}, sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, struct.error, UnicodeDecodeError) as exc:
        print('abci_linked_commit115: ' + str(exc), file=sys.stderr)
        raise SystemExit(1)
