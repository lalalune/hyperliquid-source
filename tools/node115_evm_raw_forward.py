#!/usr/bin/env python3
"""Reproduce selected node 115 raw-transaction forwarding observations from ELF bytes."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
TARGET = ROOT / 'artifacts/node/115/hl-node'

# These are linked virtual addresses, not runtime addresses. The extents are
# independently checked against the repository's .eh_frame parsers.
FUNCTIONS = (
    ('registration_root', 0x17512c0),
    ('registration_context', 0x16b4720),
    ('registration_insert', 0x16b3c40),
    ('callback', 0x16b3d20),
    ('outer_poll', 0x16b3dd0),
    ('named_wrapper', 0x16ffb20),
    ('named_object_parser', 0x1707920),
    ('positional_parser', 0x173f540),
    ('positional_error_adapter', 0x173f9b0),
    ('positional_value_wrapper', 0x16fd060),
    ('shared_value_parser', 0x1702c60),
    ('string_bytes_adapter', 0x16ef310),
    ('array_bytes_adapter', 0x16ef140),
    ('array_item_parser', 0x1705750),
    ('array_delimiter', 0x1705620),
    ('hex_first_invalid', 0x167a940),
    ('hex_vector_decode', 0x167ac00),
    ('hex_decode', 0x167afd0),
    ('hex_vector_encode', 0x144ff90),
    ('hex_encode', 0x14500d0),
    ('forward_poll', 0x17480e0),
    ('forward_error_message', 0x174c7b0),
    ('send_task_boundary', 0x173b210),
    ('body_poll_boundary', 0x16fbea0),
)

# Fixed machine-code windows used to check the transcribed instruction sites.
# They are observations, not substituted code or an executable implementation.
PINNED_WINDOWS = (
    ('register-method', 0x17512ee, 'e82d34f6ff488d15edf3d2fe4889e7b9160000004889dee83629f6ff'),
    ('register-descriptor', 0x16b3ca3, '4889442410488d057154d504488944241848c7442408010000004c8d4424084889df4c89e64c89fa4c89f1ff15c4e4e204'),
    ('callback-construct', 0x16b3d61, 'c684248000000000bf88000000ff150cb7e2044885c074274889e6ba880000004889c74889c3ff157bb7e204488d15bc53d5044889d84881c4900000005b'),
    ('outer-dispatch', 0x16b3df1, '0fb68680000000488d0da183dcfe486304814801c84889bc24c8000000ffe0'),
    ('outer-object-choice', 0x16b3eca, '4d39f5753be9b8000000'),
    ('outer-input-prefix', 0x16b3f0a, '4d85ff747d488b435080387b0f8590000000'),
    ('outer-named-call', 0x16b3f47, '488dbc2410010000488db42490010000e8c4bb04004c8b7c24204883bc2410010000000f847b040000'),
    ('outer-empty-array', 0x16b3fac, '4983ff02751c0fb7084531ff81f95b5d0000410f95c7b901000000480f44c14501ff'),
    ('outer-positional-call', 0x16b3fce, '48898424100100004c89bc2418010000488d7c2430488db42410010000e850b508004c8b6c24304983fd034c8b7c24200f8561040000'),
    ('outer-forward-poll', 0x16b405e, 'bfc8030000ff1517b4e2044885c00f84de0300004989c5488db42490010000bac80300004889c7ff157db4e2044c896b68488d05aaa8d50448894370488dbc24900100004c89ee4c89faff50184c8bac24900100004983fd04751b41c6042403488b8424c800000048c70002000000b103e9ff020000'),
    ('outer-result-tag', 0x16b4190, '4183fd037536'),
    ('outer-result-return', 0x16b439c, '488b8424c80000004c89384c8960080f288424b00000000f134010488b4c2470488948184c896820488b4c24204889482840886830b101888b80000000'),
    ('outer-error-transform', 0x16b4499, '488d3d237fdcfe488d15217fdcfe4c8d842490010000be05000000b9050000004531c9ff15eedce204'),
    ('named-wrapper-call', 0x16ffb60, '66c74424700080488d742428e8af7d000048833b000f8496000000'),
    ('named-wrapper-trailing', 0x16ffb8b, '488b442448488b4c24504839c17377488b54244048f7d848ffc148be0026000001000000900fb67c0aff4883ff20771d480fa3fe731748894c2450488d3c0848ffc748ffc14883ff0175daeb3948c744247816000000488d7c2428488d742478e8900000004889430848c70300000000'),
    ('named-key-test', 0x1707a6d, '833c2402488b4424080f844202000048837c24100575148b08ba6279746531d10fb6400483f07309c874164889efe82079ffff4885c00f8467ffffffe91002000048837c2430000f8569040000'),
    ('named-value-call', 0x1707b02, '4883fe3a0f85680400004885c00f84be040000488945284c89e74889eee83cb1ffff4c8b3c24488b6c24084d85ff0f8491030000'),
    ('named-missing-test', 0x1707ce9, '488b4424304885c0744f'),
    ('named-missing-arm', 0x1707d42, '488d056968d7fe488984248800000048c784249000000005000000488d84248800000048890424488d0530fefbff4889442408488d3d48a8d2fe4889e6488d5c2448e807a30300'),
    ('named-duplicate-arm', 0x1707f23, '488d058866d7fe488984248800000048c784249000000005000000488d84248800000048890424488d054ffcfbff4889442408488d3dbdb5d2fe4889e6488d5c2448e826a10300'),
    ('positional-begin', 0x173f554, '4c8b264c8b7e084c89a424f00000004c89bc24f80000004d85ff0f84840200004989f6410fb6042483f82c742283f85b741d83f85d0f851201000049c7060100000049c7460800000000e9550200004983ff01740c41807c2401c00f8c7b03000049ffcf49ffc4'),
    ('positional-value', 0x173f613, '488d7c2408488d742440e83edafbff837c2408010f85c9000000'),
    ('positional-missing', 0x173f7f8, 'bf0e000000ff157dfcd9044885c00f841401000048b96520706172616d734889480648b94e6f206d6f72652048890848c74424400e000000488944244848c74424500e000000488d15bc09d4fe4c8d442440b90e0000004889dfbea680ffffe8842cfcff'),
    ('value-quote-arm', 0x1702e86, '4883f8010f844104000048ffc84989462849c7461000000000488d7c24104c89f2ff154bdadd04837c241002488b74241875544889730848c70300000000e9c4030000'),
    ('value-string-call', 0x1702f0d, '488b542420488d7c2440e8f4c3feffe94f030000'),
    ('string-decode-slot', 0x16ef31b, '4989d74989f44889fb488d7c2408ff15212bdf044c8b7424084c89f048f7d80f80a8000000'),
    ('hex-parity-prefix', 0x167afde, '4989d54889fb41f6c501753e4989f74983fd01761541803f30750f41807f017875084983c7024983c5fe4c89ef48d1ef48893c24742d'),
    ('hex-odd-arm', 0x167b028, 'c743080100000048b80000000000000080488903'),
    ('hex-vector-validation', 0x167b064, '660f6f0514adddfe660f6f0daca9ddfe660f6f154486ddfe660f6f1d3c8addfe660f6f2514b6ddfe0f1f40004839f27440f3410f6f2c37660f6ff5660ffcf0660f6ffe660fdaf9660f74fe660fdbea660ffceb660f6ff5660fdaf4660f74f5660fdbf7660fd7fe4883c61085ff74bdeb1e'),
    ('hex-table-validation', 0x167b0d5, '31d24c8d352e24dffe66904839d174540fb6341048ffc242803c36ff75ed'),
    ('hex-invalid-path', 0x167b0f3, '488d7c24084c89fe4c89eae83df8ffff837c240803488b34240f84f7000000f30f6f442408f30f7f430848892b'),
    ('hex-first-invalid', 0x167a940, '5031c9488d05c22bdffe660f1f440000440fb6040e48ffc141803c00ff75f14989d04929c84c39c272254889c84883e801721c49ffc04939d077210fb64c0eff894f0448894708c7070000000058c3'),
    ('hex-convert-pairs', 0x167b1a0, '410fb6540fff420fb61432c0e204410fb6340f420a143641881404410fb6540f01420fb61432c0e204410fb6740f02420a143641885404014883c0024883c1044839c575bb4889fe'),
    ('hex-convert-tail', 0x167b1ee, '410fb60c47420fb60c31c0e104410fb6544701420a0c3241880c044889334c89630848897310'),
    ('encoder-size-prefix', 0x14500db, '488d1c124883c3020f8436010000790b31ff4889deff15a2f308054889d54989f44989fe4889dfff1578f308054885c00f841b0100004989c766c70030784989c5'),
    ('encoder-cpu-branch', 0x1450120, '488b0539f90805488b004885c00f84e1000000a90002000075164885ed0f84b40000004883fd01751a31c0e9810000004c89e74889ee4c89eae832feffff'),
    ('encoder-convert-pairs', 0x1450172, '488d15c75b00ff0f1f8000000000410fb6340489f783e70f0fb63c17c1ee040fb63416418874470241887c4703410fb674040189f783e70f0fb63c17c1ee040fb63416418874470441887c47054883c0024839c175b8'),
    ('encoder-convert-tail', 0x14501ce, '4901c4410fb60c2489ca83e20f488d355e5b00ff0fb61432c1e9040fb60c3141884c45004188544501'),
    ('encoder-vector-init', 0x144ffa1, '660f6f05070400ff660f6f0d8f5d00ff'),
    ('encoder-vector-loop', 0x144ffc0, 'f30f6f140f660f6fda660f72d304660fdbd0660f6fe1660f3800e2660fdbd8660f6fd1660f3800d3660f6fda660f60dc660f68d4f30f7f1c4af30f7f544a104883c1104839c875b8'),
    ('chain-selector', 0x1748148, '0fb685c80000008844242783f8020f831b020000'),
    ('chain-testnet', 0x1748377, '0f85b1000000488d051d83d3fe4889442410b827000000e9ac000000'),
    ('chain-mainnet', 0x174842e, '488d059382d3fe4889442410b81f0000004889442418'),
    ('request-jsonrpc-key', 0x17484c4, 'c740036e727063c7006a736f6e'),
    ('request-jsonrpc-value', 0x1748505, 'c640023066c700322e'),
    ('request-method-key', 0x17485d4, '66c740046f64c7006d657468'),
    ('request-method-value', 0x1748614, '0f1005cc80d3fe0f110048b96e73616374696f6e4889480e'),
    ('request-params-key', 0x17486e8, '66c740046d73c70070617261'),
    ('request-encode-call', 0x1748782, '488b442408488b7008488b5010488dbc2470010000e83479d0ff'),
    ('request-singleton', 0x17488bf, '48c7442458010000004c897c246048c74424680100000049bc0000000000000080498d4424044889442450'),
    ('request-id-key', 0x17489a9, '66c7006964'),
    ('request-id-value', 0x17489ce, '498d442402488944245048c74424580000000048c744246001000000'),
    ('request-headers', 0x1748b05, '488d35f17bd3fe488d0d2da5d0fe488d7c2450ba0c00000041b810000000e828c5faff'),
    ('request-header-use', 0x174977c, '488d157670d3fe4c8d05b698d0fe488dbc2470060000488db42470030000b90c00000041b910000000e8b6680000'),
    ('send-task-create', 0x1749b68, '4c8bb424100300004c89f74889dee89516ffff48894424284889d5'),
    ('send-task-setup', 0x1749ba2, '488d0527bcffff4889842478030000488d350676cffe488dbc2470010000488d942470030000ff151a5bd90449bc0000000000000080'),
    ('send-task-poll', 0x1749dda, '498b7670498b4678488dbc2470010000488b942420030000ff50184c8bbc24700100004983ff047537'),
    ('send-task-pending', 0x1749e24, '84c07435c60303488b442438c60003b003e937090000'),
    ('body-read-label', 0x174a48d, '488d053cb3ffff4889842478060000488d352a63cefe488dbc2470030000488d942470060000ff152f52d904'),
    ('body-read-poll', 0x174a74b, '488d7c24504c89e6488b942420030000e84017fbff488b5c24504883fb02752341c60703b004488b8c246801000088014c8b74243049c70604000000b003e9f1080000'),
    ('forward-failure-test', 0x174a99a, '4d39e60f85a6010000'),
    ('forward-failure-log', 0x174aa50, '488d054f94cffe4889842470060000'),
    ('forward-failure-result', 0x174aafb, 'c684247001000001488dbc2448030000488db4247001000031d2e8961c000048b8070000000083ffff488984246003000048c78424300300000200000048c784243803000000000000'),
    ('response-parser-boundary', 0x174ab49, '488dbc24700100004889ee4c89f2e87460fbff488b842470010000498d4c24014839c80f850f020000'),
    ('response-failure-log', 0x174ac27, '488d05ce31cffe48898424f0040000'),
    ('response-failure-result', 0x174acd1, 'c684247003000002488d7c2468488db4247003000031d2e8c31a000048c74424500200000048c7442458000000000f104424600f104c24700f298424400300000f298c245003000048b8070000000083ffff4889842460030000'),
    ('response-success', 0x174ade1, '4c39e00f85e10000000f288424300800000f288c24400800000f118c24480300000f1184243803000048c784243003000003000000e92c010000'),
    ('unsupported-error', 0x174829c, 'c644245000488dbc2488010000488d74245031d2e8fb440000'),
    ('unsupported-error-packed', 0x17482ed, '48b8070000000083ffff4889842460030000'),
    ('forward-complete', 0x174b04b, '488b842460030000498946300f288424300300000f288c24400300000f28942450030000410f115620410f114e10410f1106b001488b4c24088881c1030000'),
    ('error-kind-and-literals', 0x174c7bf, '440fb63e4584ff0f849000000089d548c704240000000048c74424080100000048c74424100000000031c04180ff020f94c04c8d74001b4889e7b90100000041b80100000031f64c89f2e8c244f9ff4180ff02488d058044d3fe488d355e44d3fe480f44f0'),
    ('error-generic-code', 0x174c85c, 'c744241830750000488d44241848890424488b05fc39d9044889442408488d3554d3cffe488d7c24204889e2ff155a2ed904'),
    ('positional-wrapper-call', 0x16fd0d9, '48894650488d7c24204989f7e8765b000048837c2420007437'),
    ('hex-feature-and-vector-call', 0x167b14c, '6685c0781a488b34244885f60f84ab0000004883fe01752431c0e9830000004c89ff4c89ee4c89e24c8b34244c89f1e880faffff4c89f6e981000000'),
    ('hex-vector-init', 0x167ac07, '4883f9200f82b8000000c4e27d7905ec28dffec4e27d790de528dffec4e27d7915de28dffe0f1f4000'),
    ('hex-vector-convert', 0x167ac30, 'c5fe6f1fc5fe6f6720c5e5dbe8c5cd71d308c5dddbf8c5bd71d408c5d571d506c4e25504e9c565dbcac5b5fdedc5c571d706c4e24504f9c55ddbcac5b5fdffc5e571d30ec4e26504d9c5cddbf2c5e5fddec5dd71d40ec4e25d04e1c5bddbf2c5ddfde6c5d571f504c5d5ebdbc5d571f704c5d5ebe4c5e567dcc4e3fd00dbd8c5fe7f1a'),
    ('registration-selector', 0x17512ca, '89fb4c8d7424384c89f731f6ff154c01d904889c2400010000'),
    ('context-input-copy', 0x16b472c, '4889fb48c704240100000048c7442408010000004c8d7c2410bad00000004c89ffff15b5ade204'),
    ('context-heap-copy', 0x16b4763, '4989c64889e6bae00000004889c7ff1591ade204'),
    ('context-return', 0x16b47b0, '4c89334889430848c7431000000000'),
    ('callback-capture', 0x16b3d20, '534881ec90000000488b07f048ff007e7f488b4a1048894c24100f10020f2904244889442430'),
    ('outer-capture', 0x16b3e1e, '4c8b2b488b4b084c8b7b10488b6b3048896c24304c8b6338'),
    ('outer-forward-data', 0x16b4004, '0f104424380f104c24480f298c24e00000000f298424d0000000c6437901488b43604883c010c643790048898424480500000f288424d00000000f288c24e00000000f118424b00100000f118c24c0010000c684245105000000'),
    ('forward-capture', 0x1748109, '0fb686c1030000488d0d9583d3fe486304814801c84889742408ffe0498badb803000041c685c003000000410f104520410f104d30410f114500410f114d100fb685c800000088442427'),
    ('shared-value-type-select', 0x1702ce4, '448d47a54183f820766683ff220f848f010000'),
    ('shared-value-jump-table', 0x1702d54, '488d35d1b3d7fe4e6304864901f041ffe0'),
    ('shared-value-array-visit', 0x1702d85, '4883f8010f844205000048ffc849894628488d7c24604c89f6ba01000000e898c3feff'),
    ('array-visit-loop', 0x16ef190, '488b442410881c2848ffc548896c24184c89f74c89fee8a5650100807c2428017420807c242901754e0fb65c242a488b6c2418483b6c240875c64c89e741ffd5ebbe'),
    ('array-item-classify', 0x170575d, '488d7c2410e8b9feffff807c241001750a488b442418e9c7000000807c241100746e'),
    ('array-item-number-parse', 0x17057f4, '4883ff2d75194885c00f84c700000049894628488d7c24284c89f631d2eb174080c7d04080ff0a7334488d7c24284c89f6ba01000000e811a8ffff488b4c24284883f9037538'),
    ('array-item-number-range', 0x1705872, '488b44243083f901741983f9027526483d0001000072144889442418c644241002eb4c483d00010000733a88430266c7030001eb9f'),
    ('array-item-invalid-kind', 0x17058a7, '4889442418c644241003488d15885dd004488d7c2410488d74240fff1538b0dd04'),
    ('response-classifier-boundary', 0x174aecb, '8bb424d001000048898424180800000f288424300800000f11842420080000488d8c2440080000488dbc2470010000488d942418080000e8a974fbff488b8424a00100004889842460030000'),
    ('outer-named-error-adapter', 0x16b43eb, '488bb42418010000488d7c2430e8b3b508004c8b6c24304983fd030f84f8fbffff'),
    ('error-adapter-result', 0x173fa64, '488b44241848894424300f104424080f29442420488d158207d4fe4c8d442420b90e0000004c89f7bea680ffffe84a2afcff'),
    ('outer-terminal-states', 0x16b4530, '488d3d394cd504ff1523cee204488d3d2c4cd504ff151ecee204488d3d2f4fd504ff1509cee204eb0d488d3d204fd504ff1502cee204'),
    ('forward-terminal-states', 0x174b2bd, '488d3d9c36cc04ff159660d904488d3d8f36cc04ff159160d904'),
    ('array-delimiter-whitespace', 0x1705628, '488b3e4c8b4f20488b47284c39c8733e488b571848ffc04d89ca49f7da49b8002600000100000090440fb65c02ff4983fb2077414d0fa3d8733b488947284d8d1c0249ffc348ffc04983fb0175da'),
    ('array-delimiter-choice', 0x170569d, '4183fb5d7506c6410100eb76807e0800740ac6460800c6410101eb664180fb2c756a'),
    ('array-delimiter-after-comma', 0x17056c4, '4889cb488947284c39c8733048ffc0b9010000004c29c90fb67402ff4883fe20772d490fa3f0732748894728488d340148ffc648ffc04883fe0275db48c744240805000000488d742408e974ffffff83fe5d741f4889d9c6430101'),
    ('array-delimiter-errors', 0x170571f, '31c088014883c4205bc348c744240807000000e948ffffff48c744240815000000ebc7'),
    ('request-format-check', 0x1748ba3, '488d742450ff15ca96d90484c0488b742410488b5424180f85ed250000'),
    ('request-format-failure', 0x174b1ad, '488d3d0e56d3fe488d0d3d3acc044c8d05be39cc04488d542425be37000000ff15ce44d904e9fe010000'),
    ('forward-fatal-sink', 0x174b3d5, '0f0b'),
    ('insert-jsonrpc-field', 0x1748537, '488db42470060000488d942460040000488d4c2450e8bf52feff'),
    ('insert-method-field', 0x1748650, '488db42470060000488d942460040000488d4c2450e8a651feff'),
    ('insert-params-field', 0x17488f2, '488db42470060000488d9424a0090000488d4c2450e8044ffeff'),
    ('insert-id-field', 0x17489f2, '488db42470060000488d942460040000488d4c2450e8044efeff'),
    ('forward-sentinel-load', 0x17480ff, '49bc0000000000000080'),
    ('outer-response-handoff', 0x16b42f9, '488b432848894424400f1043180f29442430488b4b40488dbc2490010000488d742430488d942448010000e8b7d60400'),
    ('string-hex-error-adapter', 0x16ef3e8, '4c896424284c897c2430c644242005488d35b2c2d104488d15bbc2d104488d7c2420ff150015df044889430831c0ebbe'),
    ('shared-value-result-check', 0x1703270, '48837c2440000f849a0000000f284424400f284c24500f114b100f1103'),
    ('array-item-error-return', 0x16ef1d2, '488b442430488b5c24204889430848c70300000000'),
    ('body-dispatch', 0x16fbf12, '0fb683ab000000488d0d1416d8fe486304814801c8ffe0'),
    ('body-first-poll', 0x16fbf8a, '4889e74c89faff156a44de04488b0c244883f9027507b003e9ff030000'),
    ('body-second-poll', 0x16fbff6, '488b00488b304889e74c89faff15f843de04488b0c244883f9027507b004e98d030000'),
    ('body-length-add', 0x16fc064, '488b83e0000000480383800000000f8287010000'),
    ('body-length-overflow-handler', 0x16fc1ff, '488d3d22f7d004ff151433de04e9de000000'),
    ('body-terminal-sink', 0x16fc2ef, '0f0b'),
    ('body-loop-poll', 0x16fc331, '488b00488b304889e74c89faff15bd40de04488b0c244883f9027457'),
    ('body-pending-output', 0x16fc3a4, 'b0054108ed8883ab000000410fb6fd83e7014889de4c89faff15964fde0484c0740c49c70602000000e9f800000049c70601000000e9ec000000'),
    ('body-ready-output', 0x16fc4a5, 'c683a80000000049896e184d897e20c683ab0000000149c706000000004d896e084d896610'),
    ('forward-body-result', 0x174a78e, '488b6c24584c8b7c24600f104424680f298424d00500004c89e7e8233100004883fb017553488b4424084805980100004889442450488d05d6d3f7ff4889442458488d4424254889442460488b059859d9044889442468488d7c24504c8b6c2418e89c68000049bc00000000000000804889c5e995000000'),
)

DIRECT_CALLS = (
    ('construct_registration_context', 0x17512ee, 0x16b4720),
    ('insert_method', 0x1751305, 0x16b3c40),
    ('parse_named', 0x16b3f57, 0x16ffb20),
    ('named_error_adapter', 0x16b43f8, 0x173f9b0),
    ('parse_positional', 0x16b3feb, 0x173f540),
    ('parse_named_object', 0x16ffb6c, 0x1707920),
    ('parse_named_value', 0x1707b1f, 0x1702c60),
    ('parse_positional_value', 0x173f61d, 0x16fd060),
    ('parse_shared_value', 0x16fd0e5, 0x1702c60),
    ('convert_string', 0x1702f17, 0x16ef310),
    ('convert_array', 0x1702da3, 0x16ef140),
    ('parse_array_item', 0x16ef1a6, 0x1705750),
    ('check_array_delimiter', 0x1705762, 0x1705620),
    ('locate_invalid_hex', 0x167b0fe, 0x167a940),
    ('vector_decode', 0x167b17b, 0x167ac00),
    ('vector_encode', 0x1450159, 0x144ff90),
    ('format_forwarded_bytes', 0x1748797, 0x14500d0),
    ('make_send_task', 0x1749b76, 0x173b210),
    ('poll_body', 0x174a75b, 0x16fbea0),
    ('format_unsupported_error', 0x17482b0, 0x174c7b0),
    ('format_forward_error', 0x174ab15, 0x174c7b0),
    ('format_response_error', 0x174ace8, 0x174c7b0),
)

BRANCHES = (
    ('outer_has_input', 0x16b3ecd), ('outer_no_input', 0x16b3ecf),
    ('outer_empty_input', 0x16b3f0d), ('outer_not_object', 0x16b3f16),
    ('named_parse_failed', 0x16b3f6a), ('not_exact_empty_array', 0x16b3fb0),
    ('positional_parse_failed', 0x16b3ffe), ('outer_forward_ready', 0x16b40b7),
    ('outer_forward_pending', 0x16b40cf),
    ('named_other_length', 0x1707a82), ('named_bytes_key', 0x1707a96),
    ('named_duplicate_key', 0x1707ab4), ('named_missing_key', 0x1707cf1),
    ('positional_empty', 0x173f56e), ('positional_comma', 0x173f57f),
    ('positional_open_bracket', 0x173f584), ('positional_not_close', 0x173f589),
    ('positional_closed', 0x173f59e), ('positional_value_error', 0x173f627),
    ('shared_sequence_dispatch', 0x1702cec),
    ('shared_string_dispatch', 0x1702cf1),
    ('array_element_error', 0x16ef1b0),
    ('array_not_end', 0x17056a1),
    ('array_first_item', 0x17056ad),
    ('array_missing_comma', 0x17056bd),
    ('array_trailing_comma', 0x1705716),
    ('array_end', 0x16ef1b7),
    ('item_numeric_kind_one', 0x170587a),
    ('item_numeric_kind_other', 0x170587f),
    ('item_kind_two_in_range', 0x1705887),
    ('item_kind_one_out_of_range', 0x170589b),
    ('hex_decode_error_adapter', 0x16ef33a),
    ('shared_value_error', 0x1703276),
    ('hex_odd_length', 0x167afe8), ('hex_short_input', 0x167aff1),
    ('hex_prefix_first_mismatch', 0x167aff7), ('hex_prefix_second_mismatch', 0x167affe),
    ('hex_vector_valid_block', 0x167b0d1), ('hex_vector_invalid_block', 0x167b0d3),
    ('hex_scalar_invalid', 0x167b0f1), ('hex_vector_feature', 0x167b14f),
    ('hex_encode_vector_feature', 0x1450138),
    ('request_format_failure', 0x1748bba),
    ('request_format_fatal_sink', 0x174b1d2),
    ('chain_supported', 0x1748156), ('chain_not_two', 0x1748377),
    ('send_poll_ready', 0x1749e01), ('send_reschedule', 0x1749e26),
    ('send_pending', 0x1749e35), ('body_poll_ready', 0x174a769),
    ('body_first_poll_ready', 0x16fbf9e),
    ('body_first_poll_pending', 0x16fbfa2),
    ('body_second_poll_ready', 0x16fc010),
    ('body_second_poll_pending', 0x16fc014),
    ('body_combined_length_overflow', 0x16fc072),
    ('body_overflow_terminal', 0x16fc20c),
    ('body_loop_poll_pending', 0x16fc34b),
    ('body_poll_reschedule_failed', 0x16fc3c4),
    ('body_pending_return_inner', 0x16fc3cd),
    ('body_error_return_inner', 0x16fc3d9),
    ('forward_body_non_error_tag', 0x174a7b1),
    ('forward_body_error_cleanup', 0x174a801),
    ('body_pending_return', 0x174a789), ('forward_result_not_sentinel', 0x174a99d),
    ('response_not_parse_error', 0x174ab6c), ('response_other_variant', 0x174ade4),
    ('message_generic_kind', 0x174c7c6),
)

JUMP_TABLES = (
    ('outer_state', 0x16b3df8, 0x47c1a0, 4, 0x16b3dd0),
    ('outer_nested_state', 0x16b3ee0, 0x47c1b0, 4, 0x16b3dd0),
    ('forward_state', 0x1748110, 0x4804ac, 4, 0x17480e0),
    ('forward_nested_state', 0x1748349, 0x4804bc, 5, 0x17480e0),
    ('forward_send_state', 0x17483ae, 0x4804e0, 4, 0x17480e0),
    ('forward_body_state', 0x17483fa, 0x4804d0, 4, 0x17480e0),
    ('forward_aux_state', 0x1748863, 0x4804f0, 4, 0x17480e0),
    ('body_poll_state', 0x16fbf19, 0x47d534, 6, 0x16fbea0),
)

# Target slots are linked addresses. Only local R_X86_64_RELATIVE records are
# accepted; no assumptions about the already-relocated on-disk slot contents.
RELOCATIONS = (
    ('registration_callback_1', 0x6409140, 0x16b3d20),
    ('registration_callback_2', 0x6409148, 0x16b3d20),
    ('outer_future_poll', 0x6409168, 0x16b3dd0),
    ('forward_future_poll', 0x640e958, 0x17480e0),
    ('hex_decoder_slot', 0x64e1e50, 0x167afd0),
    ('outer_diagnostic_descriptor', 0x6409480, 0x44c811),
    ('forward_diagnostic_descriptor', 0x640e960, 0x44c811),
)

LITERALS = (
    ('method', 0x4806e7, b'eth_sendRawTransaction'),
    ('forwarder_source_suffix', 0x44c811, b'evm_rpc/src/evm_write_forwarder.rs'),
    ('testnet_endpoint', 0x4806a1, b'https://rpc.hyperliquid-testnet.xyz/evm'),
    ('mainnet_endpoint', 0x4806c8, b'https://rpc.hyperliquid.xyz/evm'),
    ('header_name', 0x4806fd, b'Content-Type'),
    ('header_name_lowercase', 0x4807f9, b'content-type'),
    ('header_value', 0x453040, b'application/json'),
    ('invalid_params', 0x480201, b'Invalid params'),
    ('named_key', 0x47e5b2, b'bytes'),
    ('missing_field_prefix', 0x4325c5, b'missing field `'),
    ('duplicate_field_prefix', 0x43351b, b'duplicate field `'),
    ('format_failure_diagnostic', 0x4807c2, b'a Display implementation returned an error unexpectedly'),
    ('forward_error', 0x480c7e, b'Unable to send transaction.'),
    ('response_error', 0x480c99, b'Invalid transaction response.'),
    ('generic_format_prefix', 0x449bd5, b'Unexpected error (code='),
    ('unsupported_diagnostic', 0x443e72, b'unsupported chain for evm rpc tx forwarding chain='),
    ('forward_diagnostic', 0x443ea7, b'unable to forward raw transaction: '),
    ('response_diagnostic', 0x43ddfd, b'unable to parse raw transaction response: '),
    ('send_diagnostic', 0x4411bf, b'http_send_request_raw:'),
    ('read_diagnostic', 0x4307ce, b'http_read_body:'),
    ('hex_alphabet', 0x455d40, b'0123456789abcdef'),
)

FORK_TOKENS = (
    b'z_forks/reth-chainspec', b'z_forks/reth-ethereum-forks',
    b'z_forks/reth-rpc-eth-types', b'z_forks/reth-rpc-server-types',
    b'z_forks/revm-precompile', b'z_vendor/revm',
)


class EvidenceError(ValueError):
    """The supplied bytes do not support a requested observation."""


def check_digest(data, expected=TARGET_SHA256):
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise EvidenceError('node 115 SHA-256 mismatch')
    return actual


class Image:
    def __init__(self, data, secs=None):
        self.data = data
        self.sections = sections(data) if secs is None else secs

    def resolve(self, va, length, required_flags=2):
        if (type(va) is not int or type(length) is not int or va < 0 or length <= 0
                or va + length > 1 << 64):
            raise EvidenceError('invalid virtual address range')
        matches = [s for s in self.sections if s['type'] != 8
                   and s['flags'] & required_flags == required_flags
                   and s['address'] <= va and va + length <= s['address'] + s['size']]
        if len(matches) != 1:
            raise EvidenceError('range has no unique file-backed section')
        s = matches[0]
        off = s['offset'] + va - s['address']
        if off < 0 or off + length > len(self.data):
            raise EvidenceError('range extends beyond the file')
        return s, off

    def read(self, va, length, required_flags=2):
        _, off = self.resolve(va, length, required_flags)
        return self.data[off:off + length]


def verify_pin(image, va, expected):
    if not expected or image.read(va, len(expected), 4) != expected:
        raise EvidenceError('instruction window mismatch')


def relative_target(image, site, opcode, length):
    raw = image.read(site, length, 4)
    if raw[:len(opcode)] != opcode or len(opcode) + 4 != length:
        raise EvidenceError('unexpected relative instruction')
    return site + length + struct.unpack_from('<i', raw, len(opcode))[0]


def decode_branch(image, site, lower, upper):
    first = image.read(site, 1, 4)[0]
    if 0x70 <= first <= 0x7f:
        raw = image.read(site, 2, 4)
        cond, disp = first & 15, struct.unpack_from('<b', raw, 1)[0]
    elif first == 0x0f:
        raw = image.read(site, 6, 4)
        if not 0x80 <= raw[1] <= 0x8f:
            raise EvidenceError('not a relative conditional branch')
        cond, disp = raw[1] & 15, struct.unpack_from('<i', raw, 2)[0]
    elif first in (0xe9, 0xeb):
        size = 5 if first == 0xe9 else 2
        raw = image.read(site, size, 4)
        cond = None
        disp = struct.unpack_from('<i' if size == 5 else '<b', raw, 1)[0]
    else:
        raise EvidenceError('not a selected relative branch')
    target = site + len(raw) + disp
    if not (lower <= site and site + len(raw) <= upper and lower <= target < upper):
        raise EvidenceError('branch leaves selected unwind extent')
    names = ('o', 'no', 'b', 'ae', 'e', 'ne', 'be', 'a',
             's', 'ns', 'p', 'np', 'l', 'ge', 'le', 'g')
    return ('jmp' if cond is None else 'j' + names[cond]), target, raw


def read_jump_table(image, lea_site, table_va, count, owner, opcode=b'\x48\x8d\x0d'):
    if relative_target(image, lea_site, opcode, 7) != table_va:
        raise EvidenceError('jump table reference mismatch')
    if count <= 0 or count > 256:
        raise EvidenceError('invalid jump table size')
    raw = image.read(table_va, 4 * count)
    targets = [table_va + n for n in struct.unpack('<' + 'i' * count, raw)]
    if any(not owner['start'] <= v < owner['end'] for v in targets):
        raise EvidenceError('jump table target outside selected unwind extent')
    return targets


def find_relocations(image, specifications=RELOCATIONS):
    secs = [s for s in image.sections if s['name'] == '.rela.dyn']
    if len(secs) != 1 or secs[0]['type'] != 4 or secs[0]['size'] % 24:
        raise EvidenceError('unsupported dynamic relocation section')
    sec = secs[0]
    want = {address: (name, expected) for name, address, expected in specifications}
    if len(want) != len(specifications):
        raise EvidenceError('duplicate requested relocation')
    found = {}
    for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
        address, info, addend = struct.unpack_from('<QQq', image.data, off)
        if address in want:
            if address in found:
                raise EvidenceError('duplicate relocation for requested slot')
            if info != 8 or addend != want[address][1]:
                raise EvidenceError('unexpected relocation type or addend')
            found[address] = (off, info, addend, image.data[off:off + 24].hex())
    if set(found) != set(want):
        raise EvidenceError('missing relocation for requested slot')
    return found


def hex_lookup():
    table = bytearray([255] * 256)
    for base in (ord('0'), ord('A'), ord('a')):
        size, value = (10, 0) if base == ord('0') else (6, 10)
        for n in range(size):
            table[base + n] = value + n
    return bytes(table)


def require_hex_table(table):
    if table != hex_lookup():
        raise EvidenceError('unexpected hex lookup table')
    return table


def decode_hex(data, table):
    require_hex_table(table)
    if len(data) & 1:
        return ('odd', None, None)
    if data.startswith(b'0x'):
        data = data[2:]
    for i, byte in enumerate(data):
        if table[byte] == 255:
            return ('invalid', i, byte)
    return ('ok', bytes((table[data[i]] << 4) | table[data[i + 1]]
                        for i in range(0, len(data), 2)), None)


def encode_hex(data, alphabet):
    if alphabet != b'0123456789abcdef':
        raise EvidenceError('unexpected hex alphabet')
    out = bytearray(b'0x')
    for b in data:
        out.extend((alphabet[b >> 4], alphabet[b & 15]))
    return bytes(out)


def vector_invalid(byte, lane, constants):
    if (not 0 <= byte <= 255 or not 0 <= lane < 16 or len(constants) != 5
            or any(len(item) != 16 for item in constants)):
        raise EvidenceError('invalid vector classifier argument')
    a, b, mask, add, limit = (c[lane] for c in constants)
    return ((byte + a) & 255) <= b and (((byte & mask) + add) & 255) <= limit


def chain_case(selector):
    if type(selector) is not int or not 0 <= selector <= 255:
        raise EvidenceError('chain selector is not one byte')
    if selector < 2:
        return 'unsupported'
    return 'testnet_endpoint' if selector == 2 else 'mainnet_endpoint'




def array_delimiter_case(first, data, whitespace_mask):
    """Model the sequence-access delimiter; payload parsing happens elsewhere."""
    if type(first) is not bool or not isinstance(data, bytes) or whitespace_mask != 0x100002600:
        raise EvidenceError('invalid sequence delimiter arguments')
    pos = 0
    while pos < len(data) and data[pos] <= 32 and (whitespace_mask >> data[pos]) & 1:
        pos += 1
    if pos == len(data):
        return ('error', pos, 2)
    if data[pos] == ord(']'):
        return ('end', pos, None)
    if first:
        return ('item', pos, None)
    if data[pos] != ord(','):
        return ('error', pos, 7)
    pos += 1
    while pos < len(data) and data[pos] <= 32 and (whitespace_mask >> data[pos]) & 1:
        pos += 1
    if pos == len(data):
        return ('error', pos, 5)
    if data[pos] == ord(']'):
        return ('error', pos, 21)
    return ('item', pos, None)


def numeric_item_case(kind, payload):
    """Model only the numeric parser result kinds compared by the byte-item visitor."""
    if type(kind) is not int or type(payload) is not int or not 0 <= payload < 1 << 64:
        raise EvidenceError('invalid numeric parser result')
    if kind not in (1, 2) or payload >= 256:
        return ('error', None)
    return ('byte', payload)



def response_markers(image):
    """Expose only the caller's observed discriminants, leaving decoder ownership open."""
    sentinel = struct.unpack('<Q', image.read(0x1748101, 8, 4))[0]
    result_tag = struct.unpack('<I', image.read(0x174ae12, 4, 4))[0]
    if sentinel != 0x8000000000000000 or result_tag != 3:
        raise EvidenceError('response boundary marker mismatch')
    return [
        ('forward_error_equal', hex(0x174a99a), hex(sentinel)),
        ('decode_error_equal', hex(0x174ab69), hex(sentinel + 1)),
        ('decoded_copy_equal', hex(0x174ade1), hex(sentinel)),
        ('decoded_copy_output_tag', hex(0x174ae0a), str(result_tag)),
    ]



def checked_sum_u64(left, right):
    if any(type(x) is not int or not 0 <= x < 1 << 64 for x in (left, right)):
        raise EvidenceError('invalid unsigned body length')
    total = left + right
    return (total & ((1 << 64) - 1), int(total >= 1 << 64))


def selected_body_writes(image):
    byte = lambda va: image.read(va, 1, 4)[0]
    dword = lambda va: struct.unpack('<I', image.read(va, 4, 4))[0]
    rows = [
        ('first_poll_pending', 0x16fbfa0, 'body_state', byte(0x16fbfa1)),
        ('second_poll_pending', 0x16fc012, 'body_state', byte(0x16fc013)),
        ('later_poll_pending', 0x16fc3a4, 'body_state', byte(0x16fc3a5)),
        ('pending_rescheduled', 0x16fc3c6, 'output_tag', dword(0x16fc3c9)),
        ('pending_reschedule_failed', 0x16fc3d2, 'output_tag', dword(0x16fc3d5)),
        ('ready', 0x16fc4b4, 'body_state', byte(0x16fc4ba)),
        ('ready', 0x16fc4bb, 'output_tag', dword(0x16fc4be)),
    ]
    if tuple(r[3] for r in rows) != (3, 4, 5, 2, 1, 1, 0):
        raise EvidenceError('body-poll state marker mismatch')
    return [(path, hex(site), field, value) for path, site, field, value in rows]


def selected_state_writes(image):
    """Return immediates from checked poll-state stores; names are interpretations."""
    byte = lambda va: image.read(va, 1, 4)[0]
    dword = lambda va: struct.unpack('<I', image.read(va, 4, 4))[0]
    rows = [
        ('outer_pending', 0x16b40b9, 'nested_state', byte(0x16b40bd)),
        ('outer_pending', 0x16b40c6, 'output_tag', dword(0x16b40c9)),
        ('outer_pending', 0x16b40cd, 'outer_state', byte(0x16b40ce)),
        ('outer_ready', 0x16b43d1, 'outer_state', byte(0x16b43d2)),
        ('send_pending', 0x1749e28, 'inner_state', byte(0x1749e2a)),
        ('send_pending', 0x1749e30, 'intermediate_state', byte(0x1749e32)),
        ('send_pending', 0x1749e33, 'nested_state', byte(0x1749e34)),
        ('body_pending', 0x174a76b, 'body_state', byte(0x174a76e)),
        ('body_pending', 0x174a76f, 'nested_state', byte(0x174a770)),
        ('body_pending', 0x174a780, 'output_tag', dword(0x174a783)),
        ('body_pending', 0x174a787, 'forward_state', byte(0x174a788)),
        ('forward_ready', 0x174b07d, 'forward_state', byte(0x174b07e)),
    ]
    if tuple(x[3] for x in rows) != (3, 2, 3, 1, 3, 3, 3, 3, 4, 4, 3, 1):
        raise EvidenceError('poll-state immediate mismatch')
    if dword(0x16b43d5) != 0x80 or dword(0x174b086) != 0x3c1:
        raise EvidenceError('poll-state offset mismatch')
    return [(path, hex(site), field, value) for path, site, field, value in rows]


def selector_layout(image):
    u32 = lambda va: struct.unpack('<I', image.read(va, 4, 4))[0]
    stack_base = image.read(0x17512d0, 1, 4)[0]
    stack_store = u32(0x17512df)
    copied_bytes = u32(0x16b4746)
    context_add = image.read(0x16b4029, 1, 4)[0]
    future_dest = u32(0x16b4032)
    future_base = u32(0x16b4079)
    future_read = u32(0x1748128)
    selector_read = u32(0x174814b)
    if (stack_base, stack_store, copied_bytes, context_add, future_dest, future_base,
            future_read, selector_read) != (0x38, 0x100, 0xd0, 0x10, 0x548, 0x190, 0x3b8, 0xc8):
        raise EvidenceError('selector capture layout mismatch')
    if stack_store - stack_base != selector_read or future_dest - future_base != future_read:
        raise EvidenceError('selector capture offsets do not join')
    return [
        ('registration_argument_low_byte', hex(0x17512dc), 'stack_displacement', hex(stack_store)),
        ('registration_context_pointer', hex(0x17512cc), 'stack_displacement', hex(stack_base)),
        ('registration_context_copy', hex(0x16b4745), 'copy_size', hex(copied_bytes)),
        ('outer_context_pointer_adjust', hex(0x16b4026), 'heap_displacement', hex(context_add)),
        ('forward_object_copy_source', hex(0x16b4075), 'stack_displacement', hex(future_base)),
        ('forward_context_pointer_store', hex(0x16b402e), 'stack_displacement', hex(future_dest)),
        ('forward_context_pointer_load', hex(0x1748125), 'forward_object_displacement', hex(future_read)),
        ('selector_load', hex(0x1748148), 'context_displacement', hex(selector_read)),
    ]


def tsv(path, headings, rows):
    with path.open('w', encoding='utf-8', newline='') as f:
        w = csv.writer(f, delimiter='\t', lineterminator='\n')
        w.writerow(headings)
        w.writerows(rows)


def within_pinned(site, length):
    return any(start <= site and site + length <= start + len(bytes.fromhex(raw))
               for _, start, raw in PINNED_WINDOWS)


def selected_extents(image):
    secs, index = unwind_index(image.data)
    _, fdes = eh_frame_records(image.data, secs)
    by_fde = {f['fde']: f for f in fdes}
    if len(by_fde) != len(fdes):
        raise EvidenceError('duplicate unwind record')
    by_start = {item['start']: item for item in index}
    selected = {}
    for name, start in FUNCTIONS:
        if start not in by_start:
            raise EvidenceError('selected unwind start absent')
        record = by_start[start]
        fde = by_fde.get(record['fde'])
        if fde is None or fde['start'] != start or fde['end'] <= start:
            raise EvidenceError('unwind index and FDE disagree')
        image.resolve(start, fde['end'] - start, 4)
        selected[start] = dict(fde, name=name, index=record['index'], section=record['section'])
    return selected


def owner_for(extents, start, length=1):
    matches = [f for f in extents.values() if f['start'] <= start and start + length <= f['end']]
    if len(matches) != 1:
        raise EvidenceError('site does not belong to exactly one selected unwind extent')
    return matches[0]


def instruction_stores(image):
    # Reconstruct overlapping immediate stores only after checking their full pinned windows.
    jsonrpc = bytearray(7)
    jsonrpc[3:7] = image.read(0x17484c7, 4, 4)
    jsonrpc[0:4] = image.read(0x17484cd, 4, 4)
    version = image.read(0x174850c, 2, 4) + image.read(0x1748508, 1, 4)
    method = image.read(0x17485dc, 4, 4) + image.read(0x17485d8, 2, 4)
    params = image.read(0x17486f0, 4, 4) + image.read(0x17486ec, 2, 4)
    request_id = image.read(0x17489ac, 2, 4)
    items = (('jsonrpc_key', bytes(jsonrpc)), ('jsonrpc_value', version),
             ('method_key', method), ('params_key', params), ('id_key', request_id))
    expected = (b'jsonrpc', b'2.0', b'method', b'params', b'id')
    if tuple(value for _, value in items) != expected:
        raise EvidenceError('unexpected request immediate stores')
    return items


def generate(data, out):
    digest = check_digest(data)
    image = Image(data)
    extents = selected_extents(image)
    window_rows = []
    for name, va, encoded in PINNED_WINDOWS:
        expected = bytes.fromhex(encoded)
        verify_pin(image, va, expected)
        fde = owner_for(extents, va, len(expected))
        _, offset = image.resolve(va, len(expected), 4)
        window_rows.append((name, fde['name'], hex(va), hex(offset), len(expected),
                            image.read(va, len(expected), 4).hex()))

    literal_rows, literal_values = [], {}
    for name, va, expected in LITERALS:
        actual = image.read(va, len(expected))
        if actual != expected:
            raise EvidenceError('literal mismatch: ' + name)
        sec, offset = image.resolve(va, len(actual))
        literal_values[name] = actual
        literal_rows.append((name, hex(va), hex(offset), sec['name'], len(actual), actual.hex(), actual.decode('ascii')))

    for site, destination in ((0x16b3ca8, 0x6409120), (0x16b3d8d, 0x6409150),
                              (0x16b408f, 0x640e940)):
        if relative_target(image, site, image.read(site, 3, 4), 7) != destination:
            raise EvidenceError('descriptor reference mismatch')
    if image.read(0x16b40a8, 3, 4) != b'\xff\x50\x18':
        raise EvidenceError('future poll slot mismatch')
    if relative_target(image, 0x16ef329, b'\xff\x15', 6) != 0x64e1e50:
        raise EvidenceError('hex decoder call slot mismatch')
    relocations = find_relocations(image)
    source_sites = []
    for site, descriptor in ((0x16b454a, 0x6409480), (0x16b4559, 0x6409480),
                             (0x174b2bd, 0x640e960), (0x174b2ca, 0x640e960)):
        if relative_target(image, site, b'\x48\x8d\x3d', 7) != descriptor:
            raise EvidenceError('diagnostic descriptor reference mismatch')
        source_sites.append((owner_for(extents, site)['name'], hex(site), hex(descriptor),
                             hex(relocations[descriptor][2]), image.read(site, 7, 4).hex()))

    request_calls = []
    for field, site in (('jsonrpc', 0x174854c), ('method', 0x1748665),
                        ('params', 0x1748907), ('id', 0x1748a07)):
        destination = relative_target(image, site, b'\xe8', 5)
        if destination != 0x172d810 or not within_pinned(site, 5):
            raise EvidenceError('request construction helper mismatch')
        request_calls.append((field, hex(site), hex(destination), image.read(site, 5, 4).hex()))
    counts = [struct.unpack('<I', image.read(site + 5, 4, 4))[0]
              for site in (0x17488bf, 0x17488cd, 0x17489e1)]
    if counts != [1, 1, 1]:
        raise EvidenceError('request singleton or identifier immediate mismatch')
    request_values = [('params_slot_58', hex(0x17488bf), counts[0]),
                      ('params_slot_68', hex(0x17488cd), counts[1]),
                      ('id_payload', hex(0x17489e1), counts[2])]

    flows = []
    for name, site, target in DIRECT_CALLS:
        if not within_pinned(site, 5):
            raise EvidenceError('direct call not covered by a checked window')
        actual = relative_target(image, site, b'\xe8', 5)
        if actual != target or target not in extents:
            raise EvidenceError('direct call destination mismatch')
        source = owner_for(extents, site, 5)
        flows.append((name, source['name'], hex(site), 'call-rel32', hex(actual), image.read(site, 5, 4).hex()))
    for name, site in BRANCHES:
        source = owner_for(extents, site)
        op, target, raw = decode_branch(image, site, source['start'], source['end'])
        if not within_pinned(site, len(raw)):
            raise EvidenceError('branch not covered by a checked window')
        flows.append((name, source['name'], hex(site), op, hex(target), raw.hex()))
    flows.sort(key=lambda row: (int(row[2], 16), row[0]))

    tables = []
    for name, site, table, count, start in JUMP_TABLES:
        owner = extents[start]
        for selector, target in enumerate(read_jump_table(image, site, table, count, owner)):
            raw = image.read(table + 4 * selector, 4)
            tables.append((name, hex(site), hex(table), selector, raw.hex(), hex(target), owner['name']))

    # The selector is an input byte minus 0x5b after an unsigned range test.
    value_table_va = 0x47e12c
    targets = read_jump_table(image, 0x1702d54, value_table_va, 33, extents[0x1702c60], b'\x48\x8d\x35')
    for selector, target in enumerate(targets):
        raw = image.read(value_table_va + 4 * selector, 4)
        tables.append(('shared_value_type', hex(0x1702d54), hex(value_table_va), selector,
                       raw.hex(), hex(target), 'shared_value_parser'))
    if targets[0] != 0x1702d65:
        raise EvidenceError('array value dispatch mismatch')

    table = require_hex_table(image.read(0x46d50c, 256))
    constants = [image.read(x, 16) for x in (0x455d80, 0x455a20, 0x4536c0, 0x453ac0, 0x4566a0)]
    character_rows = []
    for byte in range(256):
        flags = [vector_invalid(byte, lane, constants) for lane in range(16)]
        if any(flag != (table[byte] == 255) for flag in flags):
            raise EvidenceError('vector classifier disagrees with binary lookup table')
        character_rows.append((f'{byte:02x}', '-' if table[byte] == 255 else table[byte],
                               int(table[byte] != 255), ''.join('1' if f else '0' for f in flags)))
    # The vector decode's per-character arithmetic is checked for all accepted pairs.
    valid = [v for v in range(256) if table[v] != 255]
    arithmetic_pairs = 0
    word_constants = tuple(struct.unpack('<H', image.read(x, 2))[0] for x in (0x46d506, 0x46d508, 0x46d50a))
    if word_constants != (0xff, 9, 15):
        raise EvidenceError('unexpected vector decode constants')
    for high in valid:
        for low in valid:
            h = (high & word_constants[2]) + ((high & word_constants[0]) >> 6) * word_constants[1]
            l = (low & word_constants[2]) + ((low & word_constants[0]) >> 6) * word_constants[1]
            if (h << 4) | l != (table[high] << 4) | table[low]:
                raise EvidenceError('vector arithmetic differs from lookup decoding')
            arithmetic_pairs += 1

    cases = (
        ('empty', b''), ('prefix_only', b'0x'), ('one_digit', b'0'),
        ('odd_invalid_precedes_character', b'z'), ('odd_after_prefix', b'0x0'),
        ('zero', b'00'), ('mixed_case', b'aBcD'), ('prefix_mixed_case', b'0xA0bF'),
        ('uppercase_prefix', b'0X'), ('invalid_after_prefix', b'0xzz'),
        ('invalid_second_digit', b'0g'), ('invalid_first_digit', b'g0'),
        ('spaces', b'  '), ('non_ascii', bytes([0xff, 0x30])),
        ('second_bad_in_block', b'00' * 8 + b'0g'),
        ('valid_vector_boundary', b'0123456789abcdef' * 4),
        ('invalid_vector_boundary', b'0' * 16 + b'g0'),
    )
    case_rows = []
    for label, value in cases:
        status, result, bad = decode_hex(value, table)
        case_rows.append((label, value.hex(), len(value), status,
                          result.hex() if status == 'ok' else ('' if result is None else result),
                          '' if bad is None else f'{bad:02x}'))

    whitespace_mask = struct.unpack('<Q', image.read(0x1705647, 8, 4))[0]
    delimiter_inputs = ((True, b''), (True, b' ]'), (True, b'1'), (True, b' ,'),
                        (True, b'\t\n\r '), (False, b''), (False, b']'),
                        (False, b','), (False, b',  '), (False, b',]'),
                        (False, b', \t]'), (False, b', 255'), (False, b' 1'),
                        (False, b'\x0b]'))
    delimiter_rows = [(int(first), raw.hex(), *array_delimiter_case(first, raw, whitespace_mask))
                      for first, raw in delimiter_inputs]

    range1 = struct.unpack('<I', image.read(0x1705883, 4, 4))[0]
    range2 = struct.unpack('<I', image.read(0x1705897, 4, 4))[0]
    if (range1, range2) != (256, 256):
        raise EvidenceError('array numeric range mismatch')
    item_inputs = ((1, 0), (1, 1), (1, 255), (1, 256), (1, (1 << 64) - 1),
                   (2, 0), (2, 255), (2, 256), (2, (1 << 64) - 1),
                   (0, 0), (3, 0), (255, 0))
    item_rows = [(kind, payload, *numeric_item_case(kind, payload)) for kind, payload in item_inputs]
    state_rows = selected_state_writes(image)
    body_state_rows = selected_body_writes(image)
    upper = (1 << 64) - 1
    sum_inputs = ((0, 0), (upper, 0), (upper, 1), (upper - 7, 7), (upper - 7, 8))
    sum_rows = [(left, right, *checked_sum_u64(left, right)) for left, right in sum_inputs]
    response_rows = response_markers(image)
    layout_rows = selector_layout(image)

    fork_rows = []
    rodata = [s for s in image.sections if s['name'] == '.rodata' and s['type'] != 8]
    if len(rodata) != 1:
        raise EvidenceError('missing or duplicate file-backed rodata')
    sec = rodata[0]
    raw_rodata = data[sec['offset']:sec['offset'] + sec['size']]
    for token in FORK_TOKENS:
        pos = 0
        while True:
            pos = raw_rodata.find(token, pos)
            if pos < 0:
                break
            fork_rows.append((token.decode('ascii'), hex(sec['address'] + pos), hex(sec['offset'] + pos), len(token)))
            pos += len(token)
    fork_rows.sort(key=lambda x: (x[0], int(x[1], 16)))

    code_sites = (0x17482ed, 0x174ab1a, 0x174ad19)
    packed = [struct.unpack('<Q', image.read(site + 2, 8, 4))[0] for site in code_sites]
    if len(set(packed)) != 1 or packed[0] != 0xffff830000000007:
        raise EvidenceError('error result immediate differs')
    error_code = struct.unpack('<i', struct.pack('<I', packed[0] >> 32))[0]
    positional_code = struct.unpack('<i', image.read(0x173f853, 4, 4))[0]
    named_code = struct.unpack('<i', image.read(0x173fa8d, 4, 4))[0]
    if named_code != positional_code:
        raise EvidenceError('named and positional error code mismatch')
    unexpected_code = struct.unpack('<I', image.read(0x174c860, 4, 4))[0]
    tags = (image.read(0x17482a0, 1, 4)[0], image.read(0x174ab02, 1, 4)[0],
            image.read(0x174acd8, 1, 4)[0])
    if (error_code, positional_code, unexpected_code, tags) != (-32000, -32602, 30000, (0, 1, 2)):
        raise EvidenceError('error tags or constants differ')

    function_rows = []
    for name, start in FUNCTIONS:
        f = extents[start]
        sec, offset = image.resolve(start, f['end'] - start, 4)
        body = image.read(start, f['end'] - start, 4)
        function_rows.append((name, hex(start), hex(f['end']), hex(offset), sec['name'], f['index'],
                              hex(f['fde']), hex(f['cie']), '' if f['lsda'] is None else hex(f['lsda']),
                              len(body), hashlib.sha256(body).hexdigest()))

    reloc_rows = [(name, hex(addr), hex(relocations[addr][0]), hex(relocations[addr][1]),
                   hex(relocations[addr][2]), relocations[addr][3]) for name, addr, _ in RELOCATIONS]
    store_rows = [(name, value.hex(), value.decode('ascii')) for name, value in instruction_stores(image)]
    no_more = bytearray(14)
    no_more[6:14] = image.read(0x173f80e, 8, 4)
    no_more[0:8] = image.read(0x173f81c, 8, 4)
    if no_more != b'No more params':
        raise EvidenceError('missing positional parameter message mismatch')
    outcomes = [
        ('missing_positional_input', 'positional_parser', '', positional_code,
         literal_values['invalid_params'].decode('ascii'), no_more.decode('ascii')),
        ('missing_named_key', 'named_object_parser', '', named_code, 'missing_field_prefix',
         literal_values['named_key'].decode('ascii')),
        ('duplicate_named_key', 'named_object_parser', '', named_code, 'duplicate_field_prefix',
         literal_values['named_key'].decode('ascii')),
        ('unsupported_chain', 'forward_poll', tags[0], error_code, 'generic_format_prefix', unexpected_code),
        ('forward_error', 'forward_poll', tags[1], error_code, literal_values['forward_error'].decode('ascii'), ''),
        ('response_decode_error', 'forward_poll', tags[2], error_code, literal_values['response_error'].decode('ascii'), ''),
    ]
    selector_rows = [(i, chain_case(i)) for i in range(256)]
    summary = {
        'target_sha256': digest,
        'coordinate_system': 'linked virtual addresses and ELF file offsets, without ASLR rebasing',
        'selected_fde_count': len(function_rows),
        'checked_instruction_windows': len(window_rows),
        'direct_calls_and_conditional_branches': len(flows),
        'relative_relocations': len(reloc_rows),
        'source_diagnostic_references': len(source_sites),
        'jump_table_entries': len(tables),
        'literal_count': len(literal_rows),
        'fork_token_occurrences': len(fork_rows),
        'hex_character_cases': len(character_rows),
        'vector_classifier_lane_cases': len(character_rows) * 16,
        'valid_vector_arithmetic_pairs': arithmetic_pairs,
        'hex_example_cases': len(case_rows),
        'array_numeric_result_cases': len(item_rows),
        'array_delimiter_cases': len(delimiter_rows),
        'state_write_observations': len(state_rows),
        'body_state_write_observations': len(body_state_rows),
        'body_length_addition_cases': len(sum_rows),
        'response_boundary_markers': len(response_rows),
        'selector_capture_observations': len(layout_rows),
        'request_helper_calls': len(request_calls),
        'request_value_immediates': len(request_values),
        'chain_selector_cases': len(selector_rows),
        'error_outcomes': len(outcomes),
        'notes': ['FDEs are unwind extents, not proven complete function boundaries.',
                  'Case tables are static models of selected byte-pinned predicates, not binary execution.',
                  'Response-parser, HTTP transport and node state transitions remain outside this packet.'],
    }

    out.mkdir(parents=True, exist_ok=True)
    tsv(out / 'functions.tsv', ('role', 'start_va', 'end_va_exclusive', 'file_offset', 'section',
        'unwind_index', 'fde_va', 'cie_va', 'lsda_va', 'byte_count', 'sha256'), function_rows)
    tsv(out / 'windows.tsv', ('name', 'owner', 'start_va', 'file_offset', 'byte_count', 'bytes_hex'), window_rows)
    tsv(out / 'control-flow.tsv', ('name', 'owner', 'site_va', 'opcode', 'target_va', 'bytes_hex'), flows)
    tsv(out / 'jump-tables.tsv', ('table', 'reference_va', 'table_va', 'selector', 'entry_le_hex', 'target_va', 'owner'), tables)
    tsv(out / 'source-sites.tsv', ('owner', 'site_va', 'descriptor_va', 'suffix_va', 'instruction_hex'), source_sites)
    tsv(out / 'relocations.tsv', ('name', 'slot_va', 'rela_file_offset', 'info', 'addend', 'rela_bytes_hex'), reloc_rows)
    tsv(out / 'literals.tsv', ('name', 'va', 'file_offset', 'section', 'length', 'bytes_hex', 'ascii'), literal_rows)
    tsv(out / 'request-helper-calls.tsv', ('field', 'site_va', 'target_va', 'bytes_hex'), request_calls)
    tsv(out / 'request-values.tsv', ('observation', 'site_va', 'immediate'), request_values)
    tsv(out / 'request-stores.tsv', ('field', 'bytes_hex', 'ascii'), store_rows)
    tsv(out / 'selector-layout.tsv', ('observation', 'site_va', 'field', 'value'), layout_rows)
    tsv(out / 'body-states.tsv', ('path', 'site_va', 'field', 'stored_value'), body_state_rows)
    tsv(out / 'body-length-cases.tsv', ('left_u64', 'right_u64', 'wrapped_sum_u64', 'carry'), sum_rows)
    tsv(out / 'response-markers.tsv', ('observation', 'site_va', 'value'), response_rows)
    tsv(out / 'state-writes.tsv', ('path', 'site_va', 'field', 'stored_value'), state_rows)
    tsv(out / 'array-delimiters.tsv', ('first_element', 'remaining_hex', 'model_status', 'consumed', 'error_tag'), delimiter_rows)
    tsv(out / 'array-item-cases.tsv', ('numeric_kind', 'payload_u64', 'model_status', 'output_byte'), item_rows)
    tsv(out / 'fork-tokens.tsv', ('token', 'va', 'file_offset', 'length'), fork_rows)
    tsv(out / 'hex-characters.tsv', ('byte_hex', 'table_nibble', 'valid', 'vector_invalid_by_lane'), character_rows)
    tsv(out / 'hex-cases.tsv', ('case', 'input_hex', 'input_length', 'model_status', 'output_hex_or_invalid_index', 'invalid_byte_hex'), case_rows)
    tsv(out / 'chain-selectors.tsv', ('selector_byte', 'selected_case'), selector_rows)
    tsv(out / 'outcomes.tsv', ('path', 'owner', 'kind_byte', 'signed_code', 'literal_or_format', 'detail'), outcomes)
    (out / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    result = generate(TARGET.read_bytes(), args.out)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, struct.error) as error:
        print('evidence generation failed: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
