#!/usr/bin/env python3
"""Extract selected #94 call-input byte-decoding evidence without executing it.

All addresses are link-time ELF virtual addresses.  Exact patterns are bounded
observations, not an instruction decoder or an exhaustive control-flow graph.
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

TARGET = ROOT / 'artifacts/node/94/hl-node'
EXPECTED_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# Only these new unwind extents are selected. Caller/callee dependencies are
# identified separately and do not become selected FDE bodies.
FUNCTIONS = (
    ('input-field-collector', 0x26afab0),
    ('field-name-classifier', 0x214d7c0),
    ('optional-value-adapter', 0x209ce20),
    ('value-to-byte-buffer', 0x219c090),
    ('sequence-to-byte-buffer', 0x28096c0),
    ('text-to-byte-buffer', 0x2809db0),
    ('allocated-hex-decoder', 0x156ec60),
    ('hex-vector-converter', 0x156e890),
    ('first-invalid-byte', 0x156e5d0),
    ('value-error-kind-eight', 0x2883640),
    ('value-error-kind-nine', 0x2883f50),
    ('optional-quantity-reader', 0x258cbf0),
    ('quantity-json-reader', 0x28fc450),
    ('radix-u128-accumulator', 0x28f7ae0),
    ('fee-input-selector', 0x4e60140),
    ('fee-u256-computation', 0x4e60470),
    ('odd-buffer-drop', 0x1510a30),
    ('shared-buffer-drop', 0x15102c0),
)

# Whole, fixed byte windows also cover selected error paths. One caller window
# provides the connecting edge; the caller FDE is prior work, not selected.
WINDOWS = (
    ('caller-input-descriptor', 0x1bdb893, '488d15368662fe4c8d0587efaa03488dbc2430010000488d742468b91000000041b902000000e8f241ad00'),
    ('collector-entry-stride', 0x26afac5, '4c8b7608488b46104889c348c1e3064c01f34c89b424c000000048899c24c8000000c68424a0000000164c898424d00000004c898c24d800000048c74424100000000048c7442438000000004885c00f84c1020000'),
    ('collector-iterate', 0x26afb30, '498d6e404889ac24c00000004c89ff4c89f64c89ea4c89e1ff15624b0c0380bc24e000000016750d4989ee4839dd75d0e976020000'),
    ('collector-classify', 0x26afbbc, '488d7c2460488db42480000000e8f2dba9ff807c2460000f85ce0200000fb644246185c00f84d500000083f8010f85a1010000'),
    ('collector-data-duplicate', 0x26afbef, '48837c2438000f85520300000fb68424a0000000c68424a0000000163c160f84b2020000'),
    ('collector-data-convert', 0x26afc38, '4c89ff488db42480000000e8d8d19eff488b8424e800000083bc24e0000000010f848b020000'),
    ('collector-data-mark', 0x26afc99, '48c744243801000000488b4424084889442440488b442470488d4c2458e9c700000048837c2410000f85dd020000'),
    ('collector-input-convert', 0x26afd04, '4c89ff488db42480000000e80cd19eff488b8424e800000083bc24e0000000010f84bf010000'),
    ('collector-input-mark', 0x26afd65, '48c744241001000000488b4424084889442418488b442470488d4c24304889010f284424600f1141f0eb3e'),
    ('collector-loop-end', 0x26afdce, '4983c6404939de0f8555fdffff'),
    ('collector-return-options', 0x26afddb, '807c241000742e488b4424180f104424200f29842480000000488b4c243048898c2490000000488b1c24837c243801741131c9eb2c31c0488b1c24837c24380175ef488b4c24400f104424480f298424e0000000488b54245848899424f0000000488943080f288424800000000f114310488b8424900000004889432048894b280f288424e00000000f114330488b8424f00000004889434048c70300000000'),
    ('collector-error-return', 0x26afee9, '488b1c244889430848c70301000000'),
    ('collector-data-error-name', 0x26aff4d, '488d0538a1b5fd488984248000000048c784248800000004000000'),
    ('collector-input-error-name', 0x26affa4, '488d05b5c1d3fd488984248000000048c784248800000005000000'),
    ('field-dispatch', 0x214d7cc, '440fb636418d46ff83f80e0f8713020000488d0decb927fe486304814801c8ffe0'),
    ('field-input-word', 0x214d803, '488b4608488b4e104883f9040f84330100004883f9050f8535010000b9696e707533080fb6400483f07409c80f851f01000031c0884301e93a010000'),
    ('field-input-bytewise', 0x214d83f, '488b4608488b4e104883f9040f840a0100004883f9050f85190100008038690f85100100008078016e0f8506010000807802700f85fc000000807803750f85f2000000807804740f85e800000031c9e9e3000000'),
    ('field-data-word', 0x214d948, '8138646174610f8495000000b002884301eb1e'),
    ('field-data-bytewise', 0x214d95b, '803864751480780161750e807802747508b101807803617402b102884b01'),
    ('optional-tags', 0x209ce27, '4889fb0fb60683f810740a83f811741883f81275530f57c00f11034889f7e876461200e998000000'),
    ('optional-indirect-parse', 0x209ce4f, '4c8b7608410f1006410f104e100f294c24300f294424204889e7488d742420e81df20f0048833c2400744c0f1004240f104c24100f114b180f11430831c0eb45'),
    ('optional-direct-parse', 0x209ce8f, '4889e7e8f9f10f0048833c240074150f1004240f104c24100f114b180f11430831c0eb0e488b44240848894308b801000000488903eb21'),
    ('value-dispatch', 0x219c09e, '440fb6060fb64e010fb756028b4604488b5e084c8b76104c8b7e18488d35683023fe4e6304864901f041ffe0'),
    ('value-sequence-entry', 0x219c0e9, '49c1e7054d01f74c8934244c8974240848895c24104c897c241848c7442420000000004889e64989fee8a9d5660049833e000f84d3020000'),
    ('value-sequence-cleanup', 0x219c134, '488b04244885c00f84fd030000488d4c24084c8b7c242048894424780f10010f11842480000000488b591048899c24900000004c8ba42480000000488d7c2478e867003c004c29e30f84bc03000048c1eb054c01fb0f82de0300004c897c2478488d1555454f03488d7424784889dfe87880d1ff4989460849c70600000000488d7c2468488b442450488b742458488b542460ff5020e96f030000'),
    ('value-borrowed-or-owned-text', 0x219c287, '4889de4c89f24881c4980000005b415c415e415fe910db66000f10030f104b100f294c24100f2904244889e6e888736e00be200000004889df31d2ff15481d5d03e9710200004c89f64c89fae8d8da66004885db0f845d0200004c89f74889de31d24881c4980000005b415c415e415fff25131d5d03'),
    ('value-raw-bytes-copy', 0x219c1ec, '4d85f60f84740100004989fc4c89f7ff15d71d5d034885c00f84550300004989c74889c74889de4c89f2ff15c41d5d0341f6c7010f85e60100004c89f84883c8014d897c24084d897424104989442418488b05fd1e5d0349890424e9f2020000'),
    ('value-raw-bytes-move', 0x219c24c, '4939df0f85320100004885db0f840b01000041f6c6010f85ec0100004c8977084983ce0148895f104c897718488b05c11e5d03488907e9b7020000'),
    ('value-unicode-text', 0x219c0ca, 'c70424000000003d800000000f83f0020000880424ba01000000e9a8030000'),
    ('value-unicode-output', 0x219c47c, '880424408874240188542402884c2403ba040000004889e6e817d96600e9a0000000'),
    ('value-invalid-tag-error', 0x219c4a4, '48895c2408eb38660f6ec0f30f5ac0f20f11442408c6042403eb594889542408eb1d4889442408eb164898eb2280e101884c2401c6042400eb3a48894c2408c6042401eb2f480fbec1eb04480fbfc24889442408c6042402eb1a48895c2408c6042403eb0f48895c2408c6042402eb04c6042407488d15419652034889e0488d7424504889fb4889c7ff15e5365d034889430848c70300000000'),
    ('sequence-size-init', 0x28096d9, '488b2e488b5e084c8b7e184c897c24284929df49c1ef054885ed4d89fd4c0f44ed4d85ed74174c89efff15d048f6024885c00f843b0200004989c4eb0941bc010000004531ff'),
    ('sequence-loop-start', 0x2809732, '4885ed7421483b5c2428741a4d8b6e204c8d63204d8966080fb6033c16754631dbe911010000'),
    ('sequence-convert-append', 0x28097ff, '488d7c2450488d742460e8a23e84ff807c2450000f85e40000000fb66c2451488b5c2418483b5c2408750b488d7c2408ff159348f602488b44241040882c1848ffc348895c2418'),
    ('sequence-loop-next', 0x2809846, '4c3b642428741c498d4c242049894e08410fb6042449ffc54989cc3c160f8537ffffff4c8b7c24084c8b6424104c39fb4c8b7424200f84e7feffff'),
    ('sequence-empty-result', 0x28098b9, '49c74608010000000f57c0410f114610488d05f070e602eb134d8966084d897e104d896618488b056348f602498906'),
    ('sequence-error-cleanup', 0x28098fd, '488b4424584c8b7424204989460849c70600000000488b7424084885f674cc488b7c241031d2ff15e746f602ebbd'),
    ('adapter-text-call', 0x2809dbb, '4989d74989f44889fb488d7c2408ff15f967f6024c8b7424084c89f048f7d80f80a80000004c8b7c24104c8b6424184d39f47524'),
    ('adapter-bytes-representations', 0x2809def, '4d85f6745741f6c70175694c897b084983cf014c8973104c897b18488b052f43f602eb63bf18000000ff15ba41f6024885c00f84910000004c89384c89700848c74010010000004c897b084c89631048894318488d05bf6be602eb2b48c74308010000000f57c00f114310488d055f6be602eb134c897b084c8973104c897b18488b05d242f602488903'),
    ('adapter-parse-error', 0x2809e88, '4c896424284c897c2430c644242005488d3552aeeb02488d15cbadeb02488d7c2420ff15985df6024889430831c0ebbe'),
    ('adapter-allocation-failure', 0x2809eb8, 'bf08000000be18000000ff155841f6020f0b'),
    ('decoder-parity-prefix', 0x156ec6e, '4989d54889fb41f6c50175364989f441bf01000000b0014983fd01763e41803c2430753c41807c24017875344983c4024983c5fe'),
    ('decoder-odd-error', 0x156ecb0, 'c743080100000048b80000000000000080488903e967010000'),
    ('decoder-buffer-size', 0x156ecce, '4d89ee49d1ee4c89f7ff15fbf21f044885c00f84de0100004989c731c0'),
    ('decoder-simd-constants', 0x156ecfd, '4c21ea498d04144489e983e10f31f6660f6f057c99c9fe660f6f0d2496c9fe660f6f15fc73c9fe660f6f1d3477c9fe660f6f256ca2c9fe6666662e0f1f840000000000'),
    ('decoder-simd-validate', 0x156ed40, '4839f27440f3410f6f2c34660f6ff5660ffcf0660f6ffe660fdaf9660f74fe660fdbea660ffceb660f6ff5660fdaf4660f74f5660fdbf7660fd7fe4883c61085ff74bdeb1d'),
    ('decoder-tail-validation', 0x156ed85, '31d2488d2d062ccefe66904839d174530fb6341048ffc2803c2eff75ee'),
    ('decoder-first-invalid', 0x156eda2, '488d7c24084c89e64c89eae81ef8ffff837c240803746cf30f6f442408f30f7f430848b80000000000000080488903'),
    ('decoder-free-error', 0x156edd1, '807c24040075584c89ff4c89f631d2ff152af21f04eb48'),
    ('decoder-cpu-dispatch', 0x156ede8, '488b0561f51f04488b004885c00f84be0000006685c07814807c240400751e4983fe01753531c0e9810000004c89e74c89ee4c89fa4c89f1e86bfaffff'),
    ('decoder-success', 0x156ee25, '4c89334c897b084c897310'),
    ('decoder-scalar-pairs', 0x156ee42, '4c89f14883e1feba0100000031c0410fb67414ff0fb6342e40c0e604410fb63c14400a342f41883407410fb67414010fb6342e40c0e604410fb67c1402400a342f41887407014883c0024883c2044839c175bb41f6c601748a410fb60c440fb60c29c0e104410fb65444010a0c2a41880c07e96cffffff'),
    ('invalid-byte-and-index', 0x156e5d0, '504889f831ff488d0db733cefe0f1f00440fb6043e48ffc741803c08ff75f14989d04929f84c39c272254889f94883e901721c49ffc04939d077210fb6543eff89500448894808c7000000000058c3'),
    ('vector-block-threshold', 0x156e897, '4883f9200f82b8000000c4e27d7905e430cefec4e27d790ddd30cefec4e27d7915d630cefe'),
    ('vector-32-output', 0x156e8c0, 'c5fe6f1fc5fe6f6720c5e5dbe8c5cd71d308c5dddbf8c5bd71d408c5d571d506c4e25504e9c565dbcac5b5fdedc5c571d706c4e24504f9c55ddbcac5b5fdffc5e571d30ec4e26504d9c5cddbf2c5e5fddec5dd71d40ec4e25d04e1c5bddbf2c5ddfde6c5d571f504c5d5ebdbc5d571f704c5d5ebe4c5e567dcc4e3fd00dbd8c5fe7f1a4883c1e04883c2204883c7404883f91f0f8767ffffff'),
    ('vector-tail-threshold', 0x156e959, '4885c90f84f20200004883f908730731c0e9ad020000'),
    ('value-error-eight', 0x288364d, 'c644241008488d150725e402488d7c2410488d74240fff15afc5ee024989460849c706000000004889dfe844a0fbff'),
    ('value-error-nine', 0x2883f5d, 'c644241009488d15f71be402488d7c2410488d74240fff159fbcee024989460849c706000000004889dfe83497fbff'),
    ('quantity-optional-whitespace', 0x258cbf8, '488b4e20488b46284839c80f83c4000000488b56184883c0044889cf48f7df49b800260000010000006666666666662e0f1f840000000000440fb64c02fc4983f92077204d0fa3c8731a4c8d48fd4c894e284c8d0c0749ffc148ffc04983f90475d6eb71'),
    ('quantity-optional-null', 0x258cc5c, '4183f96e756b4883f8030f84dd000000488d78fd48897e284839cf0f83a6000000488d78fe440fb64402fd48897e284180f8750f85a90000004839cf0f8385000000488d78ff440fb64402fe48897e284180f86c0f85880000004839cf73680fb64c02ff4889462880f96c757531d2eb3c'),
    ('quantity-option-parser-call', 0x258cccd, '488d7c2408e879f73600488b442410837c240801751c4889431048c743080000000048c703020000004889d84883c4205bc3488b4c2418ba0100000031f6488913488973084889431048894b184889d84883c4205bc3'),
    ('quantity-optional-error', 0x258cd23, '48c744240805000000488d4424084889f74889c6e854375affeba548c744240809000000ebe3'),
    ('quantity-dispatch-quote', 0x28fc4d8, '4883ff220f84c60000004883ff2d753a4883f8040f84580400004883c0fc49894628488d7c24284c89f631d2e8772623ff488b4424284883f8030f85fc000000488b442430e9a9030000'),
    ('quantity-quoted-scan-call', 0x28fc5a8, '4883f8040f84980300004883c0fc4989462849c7461000000000488d7c24404c89f2ff15d026e702837c2440024c8b7c2448754b4c897b08e9ea020000'),
    ('quantity-text-special-zero', 0x28fc627, '4c8b6424504983fc037522410fb70766330505ffaefd410fb64f02320dfcfeaefd0fb6c96609c10f8491020000'),
    ('quantity-radix-call', 0x28fc654, '488d7c24284c89fe4c89e2e87cb4ffff837c2428050f85a2020000488b442430488b4c24384889430848894b1031c0e928020000'),
    ('quantity-special-zero-success', 0x28fc8b0, '488903eb2148c744241005000000488d7424104c89f7e8c53b23ff4889430848c703010000004889d84883c4585b415c415e415fc331c031c9e98bfdffff'),
    ('quantity-parse-error', 0x28fc8ee, '48c74424100a000000488d7424104c89f7e87c1223ffeb9348c744241009000000ebad4c897c24184c89642420c644241005488d151900dc02488d7c2410488d74240fff151133e702e95dffffff'),
    ('radix-ascii-prefixes', 0x28f7aee, '4883fa0248893c2441bd0a00000077047408eb50807e02bf7e4a488d5e02488d6afe41bd1000000066813e3078743b66813e3058743441bd0800000066813e306f742766813e304f742041bd0200000066813e3062741366813e3042740c41bd0a0000004889d54889f3'),
    ('radix-iteration-setup', 0x28f7b58, '4c896c242848c7442450050000004801dd48895c240848896c2410488d4c2418488d4424504889442418488d44242848894424204c8d7424304531e44531ff48894c2430eb116690'),
    ('radix-classify-loop', 0x28f7ba0, '48ffc34c89f7e8159cf3ffa80175714839eb0f84a80000000fb6334084f679e0'),
    ('radix-check-multiply-add', 0x28f7c20, '4c39ea0f838f0000004c89f84889d749f7e54889d14989c74c89e049f7e54889d64901ff4989c44911cc4883d600488d4c24180f843effffff4889fa31c9eb5d'),
    ('radix-success', 0x28f7c60, '488b44246048894424400f104424500f294424304c897c24104c8964241848837c24300548c744240805000000488d4424084c0f44f0410f1006488b04240f1100498b4e1048894810'),
    ('radix-error', 0x28f7cb8, 'b902000000488b0424488908488950084c896810ebdb'),
    ('fee-selector-presence', 0x4e60161, '4d85c9400f95c74883bc2470010000000f95c34020fb4c8b11440b12410fb63f4108fa440fb60e41f6c20174154584c97440c640080c48c70002000000e985010000'),
    ('fee-selector-legacy', 0x4e601a3, '4584c90f84090100000f1046080f104e180f298c24b00000000f298424a000000084db0f850401000031c9e91a010000'),
    ('fee-selector-blob-path', 0x4e601d3, '4989c44084ff0f8458010000488d7c24304889d64989ce4889ca4c89c1e87b0200000fb64c243080f9210f859b010000'),
    ('fee-selector-noblob-path', 0x4e60337, '488d7c24304889d64989cf4889ca4c89c1e8230100000fb64c243080f9217547'),
    ('fee-selector-error-forward', 0x4e6039e, '488b442450488944241f0f104424310f104c24410f294c24100f2904240f104424784c89e0410f114424500f10442468410f114424400f10442458410f11442430488b54241f49895424280f2804240f284c2410410f114c2419410f1144240941884c240849c7042402000000e918ffffff'),
    ('fee-selector-blob-aux-error', 0x4e60410, 'c640080dc640101c48c70002000000e904ffffff'),
    ('fee-cap-presence', 0x4e60470, '833e017527530f1046080f104e180f294c24b00f294424a0803a00742d0f1042080f104a180f294c2490eb26833a010f85ed0000004c8b4208488b7210488b4218488b5220e9e10000000f57c00f294424900f29442480'),
    ('fee-zero-cap-tip-test', 0x4e604c7, '488b4424a8480b4424b8488b5424a0480b5424b04809c2751d488b442488480b442498488b542480480b5424904809c20f8405010000'),
    ('fee-cap-versus-base', 0x4e604fd, '488b4424b84c8b41184889c24c39c07529488b5424b04c8b41104c39c2751b488b5424a84c8b41084c39c2750d488b5424a04c8b014c39c2740c41b30d4c39c20f82dd000000'),
    ('fee-cap-versus-tip', 0x4e60543, '4c8b4c24984d89ca4c39c80f85c40000004c8b4424b04c8b5424904d39d00f858e000000488b5424a84c8b5424884c39d20f85af000000488b4424a04c8b5424804c39d00f858b000000e9b1000000'),
    ('fee-without-cap-add', 0x4e60592, '31d231c031f64531c048034110410f92c14c0301481371084883d000410f92c24508ca4c8b59184e8d0c1a410fb6ca83e1014c01c9410f92c14c01da72194584c975144c894708488977104889471848894f20c60721c3'),
    ('fee-add-overflow-error', 0x4e605e9, 'c6070d48c747080b000000c3'),
    ('fee-cap-tip-errors', 0x4e605f5, '4c89c041b30a4c39d07220eb32488b4424b84c8b4c24984d89ca4c39c80f843cffffff41b30a4c39d07314c6070d44885f085bc34889d041b30a4c39d072ec488b442480488b5424884c8b442490'),
    ('fee-sum-with-cap', 0x4e60643, '4c034110410f92c2480301481351084983d000410f92c34508d3488b59184d8d1419410fb6cb83e1014c01d1410f92c24901d90f828c0000004584d20f8583000000'),
    ('fee-min-compare', 0x4e606bd, '0f10060f104e100f294c24f00f294424e0488b4424f84839c17539488b4424f04c89c14939c0752c488b4424e84889d14839c2751f488b4c24c0488b4424e04839c17510488d4424e0eb1ac6070dc647080b5bc34839c1488d4c24c0488d4424e0480f42c10f10000f1048100f114f180f114708c607215bc3'),
    ('odd-buffer-drop', 0x1510a30, '41565350488b1ff6c3017526f048ff4b10753b488b4310488b73084885f67868488b3b31d2ff15b5d52504be18000000eb0a4829de4801d6721c78274889df31d24883c4085b415eff2592d525044883c4085b415ec3'),
    ('odd-buffer-drop-failure', 0x1510a86, '488d3da3ff1504ff1585d62504488d3d94cfd0fe488d0d47ff15044c8d05a0ff1504488d542407be2b000000ff1590d52504488d3d6fcfd0fe488d0d22ff15044c8d058b001604488d542407be2b000000ff156bd525040f0b'),
    ('odd-buffer-drop-unwind', 0x1510adf, '4989c6be180000004889df31d2ff151ed525044c89f7e816f61404'),
    ('shared-buffer-drop', 0x15102c0, '41565350488b1ff048ff4b107532488b4310488b73084885f6782d488b3b4c8b352bdd250431d241ffd6be180000004889df31d24c89f04883c4085b415effe04883c4085b415ec3'),
    ('shared-buffer-drop-failure', 0x1510308, '488d3d1fd7d0fe488d0dd20616044c8d053b081604488d542407be2b000000ff151bdd25040f0b'),
    ('shared-buffer-drop-unwind', 0x151032f, '4989c6be180000004889df31d2ff15cedc25044c89f7e8c6fd1404'),
    ('decoder-allocation-failure', 0x156eec4, 'bf010000004c89f6ff15e6f01f044889c3807c240400750e4c89ff4c89f631d2ff1526f11f044889dfe81e120f04'),
    ('byte-buffer-unwind', 0x2809eca, '4889c34c89ff4c89f6e88863d0fe4889dfe83062e502ff154242f602'),
    ('optional-value-unwind', 0x209cef2, '4889c3be200000004c89f731d2ff150b116d034889dfe803325c03'),
    ('sequence-allocation-unwind', 0x280992b, 'bf08000000be18000000ff15e546f602eb0d488d3d4c7be802ff15ce47f6020f0bbf010000004c89eeff155e46f6024889c3488d7c2430e8594e6affeb09ff15b947f6024889c3488b7424084885f67423488b7c241031d2ff158746f6024889dfe87f67e5024889c34c89e74c89fee8c168d0fe4889dfe86967e502ff157b47f602'),
    ('value-adapter-allocation-unwind', 0x219c54d, 'bf08000000be18000000ff15c31a5d03eb1bbf010000004c89f6ff154b1a5d03488d3d64414f03ff159e1b5d030f0b4989c7488b442450488b742458488d7c2468488b542460ff5020eb764989c74889e7e83d440200eb69ff157d1b5d034989c74885db745b4c89f74889de31d2ff154f1a5d034c89ffe8473b4c03eb004989c7be200000004889df31d2ff15321a5d034c89ffe82a3b4c034989c748833c2400741e4889e7e8e8fb3b00eb14ff15281b5d034989c74c89f74889dee8523c37ff4c89ffe8fa3a4c03ff150c1b5d03'),
)

# name, instruction VA, opcode bytes, expected destination VA. These are a
# bounded human-selected set; signed relative displacements come from the ELF.
TRANSFERS = (
    ('visitor-to-collector', 0x1bdb8b9, 'e8', 0x26afab0),
    ('collector-name', 0x26afbc9, 'e8', 0x214d7c0),
    ('collector-name-error', 0x26afbd3, '0f85', 0x26afea7),
    ('collector-name-input', 0x26afbe0, '0f84', 0x26afcbb),
    ('collector-name-other', 0x26afbe9, '0f85', 0x26afd90),
    ('collector-data-duplicate', 0x26afbf5, '0f85', 0x26aff4d),
    ('collector-data-parser', 0x26afc43, 'e8', 0x209ce20),
    ('collector-data-parser-error', 0x26afc58, '0f84', 0x26afee9),
    ('collector-input-duplicate', 0x26afcc1, '0f85', 0x26affa4),
    ('collector-input-parser', 0x26afd0f, 'e8', 0x209ce20),
    ('collector-input-parser-error', 0x26afd24, '0f84', 0x26afee9),
    ('collector-repeat', 0x26afdd5, '0f85', 0x26afb30),
    ('collector-duplicate-data-format', 0x26aff96, 'e8', 0x1ebaee0),
    ('collector-duplicate-input-format', 0x26affed, 'e8', 0x1ebaee0),
    ('field-tag-range', 0x214d7d7, '0f87', 0x214d9f0),
    ('field-length-four', 0x214d80f, '0f84', 0x214d948),
    ('field-length-five', 0x214d819, '0f85', 0x214d954),
    ('field-input-differs', 0x214d82f, '0f85', 0x214d954),
    ('field-data-equal', 0x214d94e, '0f84', 0x214d9e9),
    ('optional-tag-ten', 0x209ce30, '74', 0x209ce3c),
    ('optional-tag-eleven', 0x209ce35, '74', 0x209ce4f),
    ('optional-tag-twelve', 0x209ce3a, '75', 0x209ce8f),
    ('optional-indirect-adapter', 0x209ce6e, 'e8', 0x219c090),
    ('optional-indirect-error', 0x209ce78, '74', 0x209cec6),
    ('optional-direct-adapter', 0x209ce92, 'e8', 0x219c090),
    ('optional-direct-error', 0x209ce9c, '74', 0x209ceb3),
    ('value-to-sequence', 0x219c112, 'e8', 0x28096c0),
    ('value-to-text-borrowed', 0x219c29b, 'e9', 0x2809db0),
    ('value-to-text-owned', 0x219c2d3, 'e8', 0x2809db0),
    ('value-to-text-codepoint', 0x219c494, 'e8', 0x2809db0),
    ('value-kind-nine', 0x219c1e2, 'e8', 0x2883f50),
    ('value-kind-eight', 0x219c2b3, 'e8', 0x2883640),
    ('sequence-convert-element', 0x2809809, 'e8', 0x204d6b0),
    ('sequence-element-error', 0x2809813, '0f85', 0x28098fd),
    ('sequence-grow', 0x2809828, '75', 0x2809835),
    ('sequence-end', 0x280984b, '74', 0x2809869),
    ('adapter-sentinel-error', 0x2809dda, '0f80', 0x2809e88),
    ('adapter-not-exact', 0x2809ded, '75', 0x2809e13),
    ('adapter-empty', 0x2809df2, '74', 0x2809e4b),
    ('adapter-pointer-bit', 0x2809df8, '75', 0x2809e63),
    ('adapter-alloc-failed', 0x2809e21, '0f84', 0x2809eb8),
    ('decoder-odd', 0x156ec78, '75', 0x156ecb0),
    ('decoder-small', 0x156ec89, '76', 0x156ecc9),
    ('decoder-no-zero-prefix', 0x156ec90, '75', 0x156ecce),
    ('decoder-no-lower-x', 0x156ec98, '75', 0x156ecce),
    ('decoder-nonempty', 0x156ecac, '73', 0x156ecd4),
    ('decoder-alloc-failed', 0x156ece0, '0f84', 0x156eec4),
    ('decoder-vector-finished', 0x156ed43, '74', 0x156ed85),
    ('decoder-vector-repeat', 0x156ed81, '74', 0x156ed40),
    ('decoder-tail-finished', 0x156ed93, '74', 0x156ede8),
    ('decoder-tail-repeat', 0x156eda0, '75', 0x156ed90),
    ('decoder-invalid-details', 0x156edad, 'e8', 0x156e5d0),
    ('decoder-invalid-impossible', 0x156edb7, '74', 0x156ee25),
    ('decoder-init-cpu', 0x156edf5, '0f84', 0x156eeb9),
    ('decoder-vector-branch', 0x156edfe, '78', 0x156ee14),
    ('decoder-vector-call', 0x156ee20, 'e8', 0x156e890),
    ('decoder-scalar-repeat', 0x156ee93, '75', 0x156ee50),
    ('decoder-scalar-done', 0x156ee99, '74', 0x156ee25),
    ('decoder-scalar-return', 0x156eeb4, 'e9', 0x156ee25),
    ('decoder-cpu-retry', 0x156eebf, 'e9', 0x156edfb),
    ('invalid-search', 0x156e5ed, '75', 0x156e5e0),
    ('invalid-sub-bounds', 0x156e5f8, '72', 0x156e61f),
    ('invalid-index-bounds', 0x156e601, '72', 0x156e61f),
    ('invalid-span-bounds', 0x156e609, '77', 0x156e62c),
    ('vector-small', 0x156e89b, '0f82', 0x156e959),
    ('vector-repeat', 0x156e953, '0f87', 0x156e8c0),
    ('vector-done', 0x156e95c, '0f84', 0x156ec54),
    ('vector-eight', 0x156e966, '73', 0x156e96f),
    ('visitor-quantity-one', 0x1bdad1b, 'e8', 0x258cbf0),
    ('visitor-quantity-two', 0x1bdae75, 'e8', 0x258cbf0),
    ('visitor-quantity-three', 0x1bdaef7, 'e8', 0x258cbf0),
    ('visitor-quantity-four', 0x1bdb118, 'e8', 0x258cbf0),
    ('optional-end', 0x258cc03, '0f83', 0x258cccd),
    ('optional-nonspace', 0x258cc3a, '77', 0x258cc5c),
    ('optional-not-null', 0x258cc60, '75', 0x258cccd),
    ('optional-null-truncated', 0x258cc77, '0f83', 0x258cd23),
    ('optional-null-wrong-u', 0x258cc8f, '0f85', 0x258cd3e),
    ('optional-null-wrong-l', 0x258ccb0, '0f85', 0x258cd3e),
    ('optional-null-wrong-end', 0x258ccc7, '75', 0x258cd3e),
    ('optional-to-quantity', 0x258ccd2, 'e8', 0x28fc450),
    ('optional-quantity-error', 0x258cce1, '75', 0x258ccff),
    ('quantity-quoted', 0x28fc4dc, '0f84', 0x28fc5a8),
    ('quantity-negative', 0x28fc4e6, '75', 0x28fc522),
    ('quantity-text-special-zero', 0x28fc64e, '0f84', 0x28fc8e5),
    ('quantity-to-radix', 0x28fc65f, 'e8', 0x28f7ae0),
    ('quantity-radix-error', 0x28fc669, '0f85', 0x28fc911),
    ('radix-length-check', 0x28f7afc, '77', 0x28f7b02),
    ('radix-prefix-x', 0x28f7b1b, '74', 0x28f7b58),
    ('radix-prefix-X', 0x28f7b22, '74', 0x28f7b58),
    ('radix-prefix-o', 0x28f7b2f, '74', 0x28f7b58),
    ('radix-prefix-O', 0x28f7b36, '74', 0x28f7b58),
    ('radix-prefix-b', 0x28f7b43, '74', 0x28f7b58),
    ('radix-prefix-B', 0x28f7b4a, '74', 0x28f7b58),
    ('radix-digit-helper', 0x28f7ba6, 'e8', 0x28317c0),
    ('radix-digit-too-large', 0x28f7c23, '0f83', 0x28f7cb8),
    ('radix-no-overflow', 0x28f7c53, '0f84', 0x28f7b97),
    ('fee-dynamic', 0x4e6018c, '74', 0x4e601a3),
    ('fee-legacy-absent', 0x4e60191, '74', 0x4e601d3),
    ('fee-blob-absent', 0x4e601d9, '0f84', 0x4e60337),
    ('fee-with-blob', 0x4e601f0, 'e8', 0x4e60470),
    ('fee-without-blob', 0x4e60348, 'e8', 0x4e60470),
    ('fee-missing-aux', 0x4e60222, '0f84', 0x4e60410),
    ('fee-cap-absent', 0x4e60473, '75', 0x4e6049c),
    ('fee-tip-absent', 0x4e6048b, '74', 0x4e604ba),
    ('fee-zero-exception', 0x4e604f7, '0f84', 0x4e60602),
    ('fee-cap-below-base', 0x4e6053d, '0f82', 0x4e60620),
    ('fee-uncapped-overflow-a', 0x4e605ce, '72', 0x4e605e9),
    ('fee-uncapped-overflow-b', 0x4e605d3, '75', 0x4e605e9),
    ('fee-cap-below-tip', 0x4e605fe, '72', 0x4e60620),
    ('fee-capped-overflow-a', 0x4e60676, '0f82', 0x4e60708),
    ('fee-capped-overflow-b', 0x4e6067f, '0f85', 0x4e60708),
    ('odd-drop-tagged', 0x1510a3a, '75', 0x1510a62),
    ('odd-drop-shared-still-live', 0x1510a41, '75', 0x1510a7e),
    ('odd-drop-shared-bad-size', 0x1510a4e, '78', 0x1510ab8),
    ('odd-drop-tagged-overflow', 0x1510a68, '72', 0x1510a86),
    ('odd-drop-tagged-bad-size', 0x1510a6a, '78', 0x1510a93),
    ('odd-drop-unwind', 0x1510af5, 'e8', 0x5660110),
    ('shared-drop-still-live', 0x15102cc, '75', 0x1510300),
    ('shared-drop-bad-size', 0x15102d9, '78', 0x1510308),
    ('shared-drop-unwind', 0x1510345, 'e8', 0x5660110),
)

# RIP-relative memory references, not necessarily functions. Size and prefix
# are fixed per site; the displacement is read directly from the ELF.
RIP_REFERENCES = (
    ('caller-type-name', 0x1bdb893, '488d15', 0x203ed0),
    ('caller-field-names', 0x1bdb89a, '4c8d05', 0x568a828),
    ('collector-next-entry', 0x26afb48, 'ff15', 0x57746b0),
    ('field-dispatch-table', 0x214d7dd, '488d0d', 0x3c91d0),
    ('value-dispatch-table', 0x219c0b9, '488d35', 0x3cf128),
    ('adapter-hex-decoder-slot', 0x2809dc9, 'ff15', 0x57705c8),
    ('hex-invalid-map', 0x156ed87, '488d2d', 0x251994),
    ('invalid-byte-map', 0x156e5d6, '488d0d', 0x251994),
    ('hex-cpu-state-slot', 0x156ede8, '488b05', 0x576e350),
    ('hex-cpu-init-slot', 0x156eeb9, 'ff15', 0x576e358),
    ('sequence-resize-slot', 0x280982f, 'ff15', 0x576e0c8),
    ('sequence-allocate-slot', 0x2809702, 'ff15', 0x576dfd8),
    ('sequence-free-slot', 0x2809923, 'ff15', 0x576e010),
    ('value-error-formatter-slot', 0x2883663, 'ff15', 0x576fc18),
    ('quantity-quoted-scanner', 0x28fc5ca, 'ff15', 0x576eca0),
    ('environment-fee-selector-slot', 0x247eb33, 'ff15', 0x5774310),
    ('odd-drop-free-data', 0x1510a55, 'ff15', 0x576e010),
    ('odd-drop-free-owner', 0x1510a78, 'ff25', 0x576e010),
    ('odd-drop-unwind-free', 0x1510aec, 'ff15', 0x576e010),
    ('shared-drop-free-slot', 0x15102de, '4c8b35', 0x576e010),
    ('shared-drop-unwind-free', 0x151033c, 'ff15', 0x576e010),
)

RELA_SLOTS = (
    ('field-name-input', 0x568a828, 0x3b96af),
    ('field-name-data', 0x568a838, 0x20a08c),
    ('hex-decoder', 0x57705c8, 0x156ec60),
    ('collector-iterator', 0x57746b0, 0x4eb8d00),
    ('allocation', 0x576dfd8, 0x54c06b0),
    ('deallocation', 0x576e010, 0x54c8cb0),
    ('sequence-resize', 0x576e0c8, 0x13460a0),
    ('bytes-even-pointer-vtable', 0x576e140, 0x5670ae8),
    ('bytes-odd-pointer-vtable', 0x576e148, 0x5670ac0),
    ('cpu-state-pointer', 0x576e350, 0x57885b8),
    ('cpu-state-init', 0x576e358, 0x4f15250),
    ('error-formatter', 0x576fc18, 0x4ebd240),
    ('quantity-quoted-scanner', 0x576eca0, 0x4ebf970),
    ('fee-input-selector', 0x5774310, 0x4e60140),
    ('empty-bytes-clone-slot', 0x56709c0, 0x1510390),
    ('empty-bytes-drop-slot', 0x56709e0, 0x1510350),
    ('shared-bytes-clone-slot', 0x5670a08, 0x1510360),
    ('shared-bytes-drop-slot', 0x5670a28, 0x15102c0),
    ('odd-pointer-clone-slot', 0x5670ac0, 0x1510c10),
    ('odd-pointer-drop-slot', 0x5670ae0, 0x1510a30),
    ('even-pointer-clone-slot', 0x5670ae8, 0x1510c60),
    ('even-pointer-drop-slot', 0x5670b08, 0x1510b00),
)

# Selected immediates are decoded from fixed instruction encodings, rather
# than copied from an external disassembler's textual output.
OPERANDS = (
    ('seen-data-stack-offset', 0x26afbef, '48837c24', 1, 0x38),
    ('seen-input-stack-offset', 0x26afcbb, '48837c24', 1, 0x10),
    ('result-input-offset', 0x26afe3c, '488943', 1, 0x08),
    ('result-data-offset', 0x26afe58, '48894b', 1, 0x28),
    ('collector-success-tag', 0x26afe74, '48c703', 4, 0),
    ('collector-error-tag', 0x26afef1, '48c703', 4, 1),
    ('hex-odd-mask', 0x156ec74, '41f6c5', 1, 1),
    ('hex-prefix-first-byte', 0x156ec8b, '41803c24', 1, 0x30),
    ('hex-prefix-second-byte', 0x156ec92, '41807c2401', 1, 0x78),
    ('hex-odd-error-code', 0x156ecb0, 'c74308', 4, 1),
    ('first-invalid-error-code', 0x156e617, 'c700', 4, 0),
    ('vector-output-threshold', 0x156e897, '4883f9', 1, 32),
    ('vector-tail-threshold', 0x156e962, '4883f9', 1, 8),
    ('fee-legacy-mixed-error', 0x4e60193, 'c64008', 1, 12),
    ('fee-missing-aux-error-tag', 0x4e60410, 'c64008', 1, 13),
    ('fee-missing-aux-error-code', 0x4e60414, 'c64010', 1, 28),
    ('fee-cap-less-than-base-code', 0x4e60537, '41b3', 1, 13),
    ('fee-cap-less-than-tip-code', 0x4e605f8, '41b3', 1, 10),
    ('fee-overflow-result-tag', 0x4e605e9, 'c607', 1, 13),
    ('fee-overflow-error-code', 0x4e605ec, '48c74708', 4, 11),
    ('fee-success-result-tag', 0x4e605e5, 'c607', 1, 33),
    ('json-whitespace-mask', 0x258cc17, '49b8', 8, 0x100002600),
    ('shared-owner-refcount-offset', 0x15102c7, 'f048ff4b', 1, 16),
    ('shared-owner-free-size', 0x15102ea, 'be', 4, 24),
    ('odd-owner-free-size', 0x1510a5b, 'be', 4, 24),
    ('radix-base-ten', 0x28f7af6, '41bd', 4, 10),
    ('radix-base-sixteen', 0x28f7b10, '41bd', 4, 16),
    ('radix-base-eight', 0x28f7b24, '41bd', 4, 8),
    ('radix-base-two', 0x28f7b38, '41bd', 4, 2),
)

VECTOR_CONSTANTS = (
    ('validate-add', 0x208690), ('validate-maximum-a', 0x208340),
    ('validate-and', 0x206120), ('validate-add-b', 0x206460),
    ('validate-maximum-b', 0x208fa0),
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def authenticate(data):
    digest = hashlib.sha256(data).hexdigest()
    require(digest == EXPECTED_SHA256, 'node #94 SHA-256 mismatch')
    return digest


class View:
    """Resolve only unambiguous, allocated, file-backed ELF section spans."""
    def __init__(self, data, section_rows):
        self.data = data
        self.sections = section_rows

    def offset(self, va, size):
        require(isinstance(va, int) and isinstance(size, int) and va >= 0 and size > 0,
                'invalid address or size')
        candidates = [s for s in self.sections if s['type'] != 8 and s['flags'] & 2
                      and s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(candidates) == 1, 'ambiguous or non-file-backed span')
        off = candidates[0]['offset'] + va - candidates[0]['address']
        require(off >= 0 and off + size <= len(self.data), 'span outside file')
        return off

    def read(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off + size]


def checked_window(view, name, va, expected_hex):
    expected = bytes.fromhex(expected_hex)
    require(expected and view.read(va, len(expected)) == expected,
            'fixed window mismatch: ' + name)
    return {'name': name, 'va': hex(va), 'file_offset': hex(view.offset(va, len(expected))),
            'size': len(expected), 'bytes': expected.hex()}


def direct_transfer(view, name, va, opcode_hex, expected_target):
    opcode = bytes.fromhex(opcode_hex)
    require(opcode, 'missing transfer opcode')
    if len(opcode) == 2 and opcode[0] == 0x0f and 0x80 <= opcode[1] <= 0x8f:
        disp_len, kind = 4, 'conditional'
    elif len(opcode) == 1 and opcode[0] in (0xe8, 0xe9):
        disp_len = 4
        kind = 'call' if opcode[0] == 0xe8 else 'jump'
    elif len(opcode) == 1 and (0x70 <= opcode[0] <= 0x7f or opcode[0] == 0xeb):
        disp_len = 1
        kind = 'jump' if opcode[0] == 0xeb else 'conditional'
    else:
        raise ValueError('unsupported transfer opcode: ' + name)
    raw = view.read(va, len(opcode) + disp_len)
    require(raw.startswith(opcode), 'transfer opcode mismatch: ' + name)
    disp = int.from_bytes(raw[len(opcode):], 'little', signed=True)
    target = va + len(raw) + disp
    require(target == expected_target, 'transfer target mismatch: ' + name)
    return {'name': name, 'site_va': hex(va), 'file_offset': hex(view.offset(va, len(raw))),
            'kind': kind, 'bytes': raw.hex(), 'destination_va': hex(target)}


def rip_reference(view, name, va, prefix_hex, expected_target):
    prefix = bytes.fromhex(prefix_hex)
    require(prefix and len(prefix) in (2, 3), 'unsupported RIP reference')
    raw = view.read(va, len(prefix) + 4)
    require(raw.startswith(prefix), 'RIP opcode mismatch: ' + name)
    disp = int.from_bytes(raw[len(prefix):], 'little', signed=True)
    target = va + len(raw) + disp
    require(target == expected_target, 'RIP target mismatch: ' + name)
    return {'name': name, 'site_va': hex(va), 'file_offset': hex(view.offset(va, len(raw))),
            'bytes': raw.hex(), 'target_va': hex(target)}


def relocation_rows(data, section_rows, slots=RELA_SLOTS):
    relas = [s for s in section_rows if s['name'] == '.rela.dyn' and s['type'] == 4]
    require(len(relas) == 1, 'missing or duplicate RELA section')
    section = relas[0]
    require(section['size'] % 24 == 0, 'bad RELA byte size')
    wanted = {slot: (name, target) for name, slot, target in slots}
    require(len(wanted) == len(slots), 'duplicate requested relocation slot')
    found = {}
    for off in range(section['offset'], section['offset'] + section['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, off)
        if slot in wanted:
            name, target = wanted[slot]
            require(slot not in found and (info & 0xffffffff) == 8 and info >> 32 == 0
                    and addend == target, 'unexpected or duplicate RELA: ' + name)
            found[slot] = {'name': name, 'slot_va': hex(slot), 'rela_file_offset': hex(off),
                           'type': info & 0xffffffff, 'symbol_index': info >> 32,
                           'addend_va': hex(addend), 'rela_bytes': data[off:off + 24].hex()}
    require(set(found) == set(wanted), 'selected RELA slot missing')
    return [found[slot] for _, slot, _ in slots]


def checked_extents(data, view):
    secs, index = unwind_index(data)
    cies, all_fdes = eh_frame_records(data, secs)
    by_start = {}
    for fde in all_fdes:
        if fde['start'] in {start for _, start in FUNCTIONS}:
            require(fde['start'] not in by_start, 'duplicate selected FDE start')
            by_start[fde['start']] = fde
    index_by_start = {row['start']: row for row in index}
    rows, bodies, frame_records = [], [], []
    for name, start in FUNCTIONS:
        require(start in by_start and start in index_by_start, 'selected FDE not indexed')
        fde = by_start[start]
        ref = index_by_start[start]
        require(ref['fde'] == fde['fde'] and fde['end'] > start
                and fde['end'] <= ref['next_index_upper_bound'], 'selected FDE/index disagreement')
        size = fde['end'] - start
        body = view.read(start, size)
        # An executable section alone is not a proof of a function boundary;
        # these are unwind ranges, with instruction paths separately pinned.
        sec = next(s for s in secs if s['name'] == ref['section'])
        require(sec['type'] != 8 and sec['flags'] & 4, 'FDE not file-backed executable')
        rows.append({'name': name, 'start_va': hex(start), 'end_va': hex(fde['end']),
                     'size': size, 'file_offset': hex(view.offset(start, size)),
                     'fde_va': hex(fde['fde']), 'cie_va': hex(fde['cie']),
                     'lsda_va': '' if fde['lsda'] is None else hex(fde['lsda']),
                     'unwind_index': ref['index'], 'body_sha256': hashlib.sha256(body).hexdigest()})
        bodies.append({'name': name, 'start_va': hex(start), 'bytes': body.hex()})
        fde_size = 4 + struct.unpack('<I', view.read(fde['fde'], 4))[0]
        cie_size = 4 + struct.unpack('<I', view.read(fde['cie'], 4))[0]
        require(fde['cie'] in cies, 'missing selected CIE')
        frame_records.append({'name': name, 'fde_va': hex(fde['fde']),
                              'fde_bytes': view.read(fde['fde'], fde_size).hex(),
                              'cie_va': hex(fde['cie']),
                              'cie_bytes': view.read(fde['cie'], cie_size).hex()})
    return rows, bodies, frame_records


def operand_rows(view):
    rows = []
    for name, va, prefix_hex, width, expected in OPERANDS:
        prefix = bytes.fromhex(prefix_hex)
        raw = view.read(va, len(prefix) + width)
        require(raw.startswith(prefix), 'operand opcode mismatch: ' + name)
        value = int.from_bytes(raw[len(prefix):], 'little')
        require(value == expected, 'operand value mismatch: ' + name)
        rows.append({'name': name, 'site_va': hex(va),
                     'file_offset': hex(view.offset(va, len(raw))),
                     'bytes': raw.hex(), 'value': hex(value)})
    return rows


def exception_tables(view, fde_rows):
    """Decode bounded LSDA call-site records, leaving action/type semantics opaque."""
    matches = [s for s in view.sections if s['name'] == '.gcc_except_table' and s['type'] != 8]
    require(len(matches) == 1, 'missing or duplicate exception section')
    section = matches[0]
    section_end = section['offset'] + section['size']
    rows, headers = [], []
    for fde in fde_rows:
        if not fde['lsda_va']:
            continue
        owner, end_va = int(fde['start_va'], 16), int(fde['end_va'], 16)
        va = int(fde['lsda_va'], 16)
        off = view.offset(va, 1)
        require(section['offset'] <= off < section_end, 'LSDA outside exception section')
        data, pos = view.data, off
        require(pos + 2 <= section_end and data[pos] == 0xff, 'unsupported LSDA landing base')
        encoding = data[pos + 1]
        pos += 2
        type_base = None
        if encoding != 0xff:
            require(encoding == 0x9b, 'unsupported LSDA type encoding')
            delta, pos = uleb(data, pos, section_end)
            type_base = pos + delta
            require(type_base <= section_end, 'LSDA type table outside section')
        require(pos < section_end and data[pos] == 1, 'unsupported LSDA call-site encoding')
        pos += 1
        length, pos = uleb(data, pos, section_end)
        table_begin, limit = pos, pos + length
        require(limit <= section_end and (type_base is None or limit <= type_base),
                'invalid LSDA call-site table extent')
        previous = 0
        while pos < limit:
            row_offset = pos
            start, pos = uleb(data, pos, limit)
            size, pos = uleb(data, pos, limit)
            landing, pos = uleb(data, pos, limit)
            action, pos = uleb(data, pos, limit)
            require(start >= previous and owner + start + size <= end_va,
                    'invalid LSDA call-site range')
            require(not landing or owner + landing < end_va, 'invalid LSDA landing')
            previous = start + size
            rows.append({'function': fde['name'], 'owner_va': hex(owner), 'lsda_va': hex(va),
                         'record_file_offset': hex(row_offset), 'start_va': hex(owner + start),
                         'size': size, 'end_va': hex(owner + start + size),
                         'landing_va': hex(owner + landing) if landing else '',
                         'action': action, 'record_bytes': data[row_offset:pos].hex()})
        headers.append({'function': fde['name'], 'owner_va': hex(owner), 'lsda_va': hex(va),
                        'file_offset': hex(off), 'type_encoding': hex(encoding),
                        'header_bytes': data[off:table_begin].hex(), 'table_bytes': length,
                        'call_site_bytes': data[table_begin:limit].hex(),
                        'limits': 'Action records and catch types are not interpreted.'})
    return rows, headers


def jump_table(view, label, base, count):
    rows = []
    for i in range(count):
        raw = view.read(base + 4 * i, 4)
        delta = int.from_bytes(raw, 'little', signed=True)
        rows.append({'table': label, 'index': i, 'entry_va': hex(base + 4 * i),
                     'file_offset': hex(view.offset(base + 4 * i, 4)),
                     'bytes': raw.hex(), 'destination_va': hex(base + delta)})
    return rows


def nibble_rows(view):
    table = view.read(0x251994, 256)
    vector = []
    for _, va in VECTOR_CONSTANTS:
        raw = view.read(va, 16)
        require(len(set(raw)) == 1, 'SIMD constant is not uniform')
        vector.append(raw[0])
    require(vector == [0xc6, 0xf5, 0xdf, 0xb9, 0xf9], 'SIMD constants changed')
    rows = []
    for byte, value in enumerate(table):
        a, b, c, d, e = vector
        invalid = ((byte + a) & 255) <= b and (((byte & c) + d) & 255) <= e
        require(invalid == (value == 0xff), 'SIMD and scalar validity disagree')
        if value != 0xff:
            require(value < 16 and value == (byte & 15) + 9 * (byte >> 6),
                    'vector nibble and table value disagree')
        rows.append({'byte': hex(byte), 'table_va': hex(0x251994 + byte),
                     'file_offset': hex(view.offset(0x251994 + byte, 1)),
                     'table_value': hex(value), 'simd_invalid': int(invalid)})
    return table, vector, rows


def validate_selection(fdes, windows, transfers, rip_references):
    """Keep the explicit old-caller anchors out of selected unwind bodies."""
    external_windows = {'caller-input-descriptor': 0x1bdb893}
    external_edges = {'visitor-to-collector': 0x1bdb8b9,
                      'visitor-quantity-one': 0x1bdad1b,
                      'visitor-quantity-two': 0x1bdae75,
                      'visitor-quantity-three': 0x1bdaef7,
                      'visitor-quantity-four': 0x1bdb118}
    external_rip = {'caller-type-name': 0x1bdb893, 'caller-field-names': 0x1bdb89a,
                    'environment-fee-selector-slot': 0x247eb33}
    for rows, addresses, address_key in ((windows, external_windows, 'va'),
                                         (transfers, external_edges, 'site_va'),
                                         (rip_references, external_rip, 'site_va')):
        require(set(addresses).issubset({row['name'] for row in rows}), 'external anchor missing')
        for row in rows:
            site = int(row[address_key], 16)
            length = len(bytes.fromhex(row['bytes']))
            owners = [fde for fde in fdes if int(fde['start_va'], 16) <= site
                      and site + length <= int(fde['end_va'], 16)]
            if row['name'] in addresses:
                require(site == addresses[row['name']] and not owners, 'invalid external anchor')
            else:
                require(len(owners) == 1, 'selected pattern is outside its selected FDE')


def records_to_tsv(rows, columns):
    stream = io.StringIO(newline='')
    writer = csv.DictWriter(stream, fieldnames=columns, delimiter='\t', lineterminator='\n')
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue().encode('ascii')


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + '\n').encode('ascii')


def records(data):
    digest = authenticate(data)
    sec = sections(data)
    view = View(data, sec)
    fdes, bodies, frame_records = checked_extents(data, view)
    windows = [checked_window(view, *spec) for spec in WINDOWS]
    edges = [direct_transfer(view, *spec) for spec in TRANSFERS]
    rip = [rip_reference(view, *spec) for spec in RIP_REFERENCES]
    validate_selection(fdes, windows, edges, rip)
    relas = relocation_rows(data, sec)
    operands = operand_rows(view)
    exceptions, exception_headers = exception_tables(view, fdes)
    switches = jump_table(view, 'field-kind-minus-one', 0x3c91d0, 15)
    switches += jump_table(view, 'value-kind-bounded', 0x3cf128, 22)
    table, vector, nibbles = nibble_rows(view)
    names = []
    for slot in (0x568a828, 0x568a838):
        length = struct.unpack('<Q', view.read(slot + 8, 8))[0]
        row = next(r for r in relas if int(r['slot_va'], 16) == slot)
        addr = int(row['addend_va'], 16)
        require(length in (4, 5), 'unexpected field-name length')
        raw = view.read(addr, length)
        names.append({'slot_va': hex(slot), 'length': length, 'name_va': hex(addr),
                      'file_offset': hex(view.offset(addr, length)), 'bytes': raw.hex(),
                      'ascii': raw.decode('ascii')})
    require([n['ascii'] for n in names] == ['input', 'data'], 'field-name table changed')
    simd = []
    for name, va in VECTOR_CONSTANTS:
        simd.append({'name': name, 'va': hex(va), 'file_offset': hex(view.offset(va, 16)),
                     'bytes': view.read(va, 16).hex()})
    vector_arithmetic = view.read(0x25198e, 6)
    require(vector_arithmetic == bytes.fromhex('ff0009000f00'), 'vector constants changed')
    type_name = view.read(0x203ed0, 16)
    require(type_name == b'TransactionInput', 'type label changed')
    zero_literal = view.read(0x3ec542, 3)
    require(zero_literal == b'0x0', 'quantity zero literal changed')
    constants = {'field_names': names,
                 'quantity_special_zero': {'va': hex(0x3ec542), 'bytes': zero_literal.hex(), 'ascii': zero_literal.decode('ascii')},
                 'type_name': {'va': hex(0x203ed0), 'bytes': type_name.hex(), 'ascii': type_name.decode('ascii')},
                 'nibble_table': {'va': hex(0x251994), 'length': len(table),
                                  'sha256': hashlib.sha256(table).hexdigest()},
                 'simd_validation_constants': simd,
                 'vector_arithmetic_constants': {'va': hex(0x25198e), 'bytes': vector_arithmetic.hex()}}
    summary = {'target_release': 'node-94', 'binary_sha256': digest,
               'coordinate_system': 'link-time ELF virtual address before load bias',
               'selected_unwind_extents': len(fdes), 'selected_extent_bytes': sum(f['size'] for f in fdes),
               'fixed_windows': len(windows),
               'selected_direct_transfers': len(edges),
               'selected_rip_references': len(rip),
               'selected_relative_relocations': len(relas), 'selected_numeric_operands': len(operands),
               'bounded_switch_entries': len(switches), 'lsda_call_sites': len(exceptions),
               'lsda_landing_pads': sum(bool(row['landing_va']) for row in exceptions),
               'nibble_table_entries': len(nibbles), 'valid_nibble_characters': sum(v != 0xff for v in table),
               'limitations': 'Selected FDEs and fixed byte patterns only; not a complete CFG, ABI proof, runtime trace or function census.'}
    result = {
        'summary.json': json_bytes(summary),
        'functions.tsv': records_to_tsv(fdes, ('name', 'start_va', 'end_va', 'size', 'file_offset', 'fde_va', 'cie_va', 'lsda_va', 'unwind_index', 'body_sha256')),
        'function-bytes.json': json_bytes(bodies),
        'unwind-records.json': json_bytes(frame_records),
        'windows.tsv': records_to_tsv(windows, ('name', 'va', 'file_offset', 'size', 'bytes')),
        'transfers.tsv': records_to_tsv(edges, ('name', 'site_va', 'file_offset', 'kind', 'bytes', 'destination_va')),
        'rip-references.tsv': records_to_tsv(rip, ('name', 'site_va', 'file_offset', 'bytes', 'target_va')),
        'relocations.tsv': records_to_tsv(relas, ('name', 'slot_va', 'rela_file_offset', 'type', 'symbol_index', 'addend_va', 'rela_bytes')),
        'numeric-operands.tsv': records_to_tsv(operands, ('name', 'site_va', 'file_offset', 'bytes', 'value')),
        'exception-sites.tsv': records_to_tsv(exceptions, ('function', 'owner_va', 'lsda_va', 'record_file_offset', 'start_va', 'size', 'end_va', 'landing_va', 'action', 'record_bytes')),
        'exception-headers.json': json_bytes(exception_headers),
        'switch-tables.tsv': records_to_tsv(switches, ('table', 'index', 'entry_va', 'file_offset', 'bytes', 'destination_va')),
        'nibble-map.tsv': records_to_tsv(nibbles, ('byte', 'table_va', 'file_offset', 'table_value', 'simd_invalid')),
        'constants.json': json_bytes(constants),
    }
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    # Complete extraction, including digest authentication, before any output.
    outputs = records(TARGET.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    for name, contents in outputs.items():
        (args.out / name).write_bytes(contents)
    print('wrote ' + str(len(outputs)) + ' deterministic evidence files')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, struct.error) as error:
        print('re21_call_input94: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
