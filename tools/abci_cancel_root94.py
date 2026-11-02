#!/usr/bin/env python3
"""Recover bounded node #94 scheduled-cancel load and hash-writer paths.

Only file-backed ELF bytes are read. No captured program or external tool runs.
"""
import argparse
import csv
import hashlib
import io
import json
import mmap
from pathlib import Path
import struct
import sys

from elf_index import unwind_index
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/94/hl-node'
TARGET_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
TARGET_SIZE = 91774280

# These are the newly analyzed functions. Upstream functions are boundaries only.
FUNCTIONS = (
    ('shared_direct_key_writer', 0x43f56b0),
    ('rmp_map_key_fixed', 0x2a72b70),
    ('json_pair_key_helper', 0x3093d90),
    ('shared_direct_time_writer', 0x43e35d0),
    ('rmp_exchange', 0x2bfe6c0),
    ('rmp_cancel_map', 0x2de8130),
    ('rmp_map_entries', 0x3679c50),
    ('rmp_sequence_entries', 0x36af9e0),
    ('rmp_entry_pair', 0x2d3afe0),
    ('rmp_cancel_value', 0x2c710c0),
    ('rmp_nullable_time', 0x2a6e990),
    ('json_map', 0x363eef0),
    ('json_map_value', 0x3022400),
    ('json_map_key', 0x301d7f0),
    ('json_sequence_key', 0x30485b0),
    ('json_fixed_key', 0x324f600),
    ('json_unsigned_value', 0x2fe4ce0),
    ('json_sequence_map', 0x36c4290),
    ('json_sequence_pair', 0x3030830),
    ('json_cancel_value', 0x30b8fe0),
    ('json_nullable_time', 0x3b81700),
    ('type_formatter', 0x3432030),
    ('low_field_wrapper', 0x27b3660),
    ('shared_field_wrapper', 0x4df6370),
    ('low_map_writer', 0x25edcb0),
    ('shared_map_writer', 0x46042b0),
    ('low_sequence_writer', 0x1e33450),
    ('shared_sequence_writer', 0x4409880),
    ('low_pair_writer', 0x1debef0),
    ('shared_pair_writer', 0x43c8990),
    ('low_generic_value_writer', 0x28e49c0),
    ('low_direct_value_writer', 0x28e4b20),
    ('shared_generic_value_writer', 0x4c64730),
    ('shared_direct_value_writer', 0x4c64890),
)

# Selected raw evidence windows. Some endpoints cut instructions; bytes are exact and
# unmasked; the whole artifact digest is verified before these windows are read.
WINDOWS = (
    ('shared_key_header', 0x43f56b0, '554157415641554154534883ec584989f74889fb49bc00000000000000804c8b2e4c89e848f7d871094d8b7718e9a200000048895424184d8b7718418b5720488d7c24204c89f6e8f44f6f00488b4424204883f8020f85ca0000004c896c241048895c24084d8b6f08498b'),
    ('shared_key_flush', 0x43f571b, '5f104885db74364531e4488d6c2420660f1f440000430fb65425004889ef4c89f6e87f6f6f00488b4424204883f8020f859700000049ffc44c39e375d8488b7424104885f6740b4c89ef31d2ff15a3883701'),
    ('shared_key_hex', 0x43f5777, '4d8927488b542418488b5c24080f57c00f1144243a0f294424300f29442420488d7c2420be2a000000b9140000004531c0ff1572d937014c89f74889c6e8775e6f004883f8027509'),
    ('shared_key_error', 0x43f57c8, '48894308488953104c8923eb31488b4c24284c89234889430848894b10eb1f488b4c2428488b54240848be00000000000000804889324889420848894a10'),
    ('rmp_key_name', 0x2a72b70, '534881ec900000004889fb4883f90a752148b85f457874537472754833020fb74a084881f1637400004809c10f840c010000'),
    ('rmp_key_buffer', 0x2a72ba2, '0f57c00f29442420c74424300000000048c744244000000000488d442420488944244848c744245014000000488d7c2460488d542440b901000000e8bee215000fb64424603c097544'),
    ('json_seq_key_helper', 0x3093d90, '4156534883ec384889fb488b4f20488b47284839c873454989f6488d7318488b531848ffc048f7d948bf0026000001000000440fb64402ff4983f8220f87ad0000004c0fa3c7732c488943284c8d040149ffc048ffc04983f80175d648c70424050000004889e64889dfe8d1f4f4ff4889c2eb394983f82275754885c00f84910000004889432848c7431000000000488d7c24204889daff1573ae6d02488b4c2420488b5424284883f902750db8010000004883c4385b415ec3488b442430f6c101498b4e1048894c2410410f10060f2904244889e74889d64889c2e81fe76400a801751f31c04883c4385b415ec3488d153a8664024889df4c89f6e8af04f5ff4889c24889d74889dee811c62700e95bffffff'),
    ('shared_time_writer', 0x43e35fc, '48c744243020000060488d4424084889442420488d059abe33014889442428488b024c8b38488d7424204c89ffff1531bf380184c00f8591000000488b7c2420488b442428be54000000ff502084c0757b4983c704488d7424204c89ffff1509bf380184c075654c8b7c24084c8b642410488b5424184c89f74c89e6e8b37f700048b900000000000000804883f802750e4883c90448890b4d85ff7512eb1e488943084889531048890b4d85ff'),
    ('shared_time_failure', 0x43e36c8, '488d3deae430fc488d0d22be33014c8d0503be3301488d542407be37000000ff155ba938010f0b'),
    ('rmp_value_result_copy', 0x2c717cf, 'c6442450090fb746226683f8ff0f8406020000ffc0668946220f104424500f104c24600f114f100f1107'),
    ('rmp_marker_read', 0x2de82f7, '4c8b46184d85c00f848e010000488b461049ffc80fb60848ffc0488946104c89461884c90f88970100004531c9e935feffff'),
    ('rmp_value_marker_dispatch', 0x2c7145a, '41b0e03cdf0f878efcffff3c900f83ba010000240f0fb6e8'),
    ('rmp_value_staging', 0x2c714e7, '31d231c048894424788994248000000048898c2484000000488b842488000000488b4c247848898c24f00000008b8c2480000000898c24f80000008b8c2484000000898c24fc0000004889842400010000488b84240001000048898424d8000000488b8424f000000048898424c80000008b8424f8000000898424d00000008b8424fc000000898424d4000000c68424c00000000940b501'),
    ('boundary_rmp_loader', 0x2e0e684, '807c2401000f8557fcffff83bc2490200000020f85df060000488dbc24c80000004c89f631d2e81100dfff'),
    ('rmp_exchange_call', 0x2bfeaa6, '4989fe48899c24289b000089ac24309b0000488dbc24f8370000488db424289b0000e8935febff4c8bbc24f83700000f108424003800000f29842470590000'),
    ('boundary_rmp_field', 0x2abb843, '4c8bac24800000004d85ed0f851b2f00000fb6532448c784248000000000000000488dbc24700600004889dee8bcc832000fb68424700600003c090f854f180000488d8c2478060000488b4110488d9424c81800004889420f0f10010f1142ff48c784246016000001000000488b420f488d8c2468160000488941100f1042ff0f1101b8010000004889842480000000e96e070000'),
    ('boundary_rmp_label', 0x2abe76f, '488d055ca5abfd48898424d026000048c78424d826000018000000'),
    ('rmp_map_dispatch', 0x2de84b8, '41b1e080f9df0f879afcffff80f9900f833b01000080e10f0fb6d90fb746226685c00f844003000066ffc8668946220f84c80200004989fe4989f74889742460895c2468488d7c2420488d742460e8451789000fb64424203c090f8578010000'),
    ('rmp_seq_dispatch', 0x2de8608, '80f9a00f833e01000080e10f0fb6d90fb746226685c00f840902000066ffc8668946220f84840100004989fe4989f74889742460895c2468488d7c2420488d742460e891738c000fb64424203c097538'),
    ('rmp_map_entries_key', 0x3679cb0, '418d5eff488b8424b8000000895808b904000000488d7c2410488b742478488d154b03b9fce8968e3fff'),
    ('rmp_map_entries_value', 0x3679d54, '488d7c2410488b74247831d2e85b735fff0fb64424103c090f8535020000'),
    ('rmp_map_insert', 0x3679e90, '00488d54243c488d8c24f0000000e8cd44d2ff48837c24100075434189de48'),
    ('rmp_map_dup', 0x3679eee, 'bf0d000000ff15df400f024885c00f844701000048b963617465206b65794889480548b96475706c6963617448890848c78424980000000d00000048898424a000000048c78424a80000000d000000488d7c2410488db42498000000e8810a47ff'),
    ('rmp_seq_entries', 0x36afa07, '448b66084585e40f84d20000004989f64c8b3e488d6c246041ffcc4c8d6c2458488d5c24400f1f4000458966084c89ef4c89fe31d2e89fb568ff807c2458000f85c1000000'),
    ('rmp_seq_insert', 0x36afabc, '4c89ef488d7424084889da488d8c24d8000000e89ce8ceff48837c24580075494183c4ff0f824affffff'),
    ('rmp_seq_duplicate', 0x36afb25, 'bf0d000000ff15a8e40b024885c00f848100000048b963617465206b65794889480548b96475706c6963617448890848c78424f00000000d00000048898424f800000048c78424000100000d000000488d7c2458488db424f0000000e84aae43ff'),
    ('rmp_pair_fixed_key', 0x2d3b540, 'c78424d000000000000000488d8424f000000048898424d800000048c78424e000000014000000488d7c2450488d9424d00000004889b42408010000b901000000e81a59e9ff0fb64424503c09754a'),
    ('rmp_pair_child', 0x2d3b6b5, '488d7c24504c89c631d2e8fc59f3ff0fb64424504883f8090f858f010000'),
    ('rmp_value_seq', 0x2c71627, '3ca00f83ad020000240f440fb6f00fb746226685c00f84560f000066ffc8668946220f84330300004585f674364989fc488d7c24084889f3e82cd3dfff0fb64424083c0975298b6c240c4c8b6c24104183fe010f859e0000004531ff31c0e9b70000004531ff31ed31c0'),
    ('rmp_value_seq_n', 0x2c7171e, '488d7c24084889dee80546dfff0fb64424083c090f85c6000000458d7efe488b4424104c89e74889de4889442430896c24384c896c243c488b442440488b4c243048898c24c00000008b4c2438898c24c80000008b4c243c898c24cc00000048898424d0000000'),
    ('rmp_value_seq_remainder', 0x2c71785, '4585ff74154529fe0f8264020000c6442450044489742454eb35488b8424d00000004889442468488b8424c000000048894424588b8424c8000000894424608b8424cc00000089442464c644245009'),
    ('rmp_value_map_keys', 0x2c71dbe, '4883fa010f85d30300000fb6013c6e0f94c13c747506895c2404eb18b00228c8e95c03000048b80300000025000000e9e80600004889fb833c24017470488d7c24084989f6e888cbdfff0fb64424083c0975238b44240c4889842410010000488b4424104889842420010000bf010000004c89f6eb46'),
    ('rmp_value_map_n', 0x2c720f0, '410fb6063c6e0f94c1b20228ca31c93c740fb6c20f44c1eb2ab00248837c2418014c89ff8b5c24047519488b4424100fb60831c080f974740a80f96e0f94c1b00228c8884424314c89ee0fb64424313c0274580fb6c083f801895c24040f859ffcffff4889fb4883bc24e8000000010f84cd030000488d7c24084989f6e8be3bdfff0fb64424083c090f8584030000488b4424104889842418010000b80100000048898424e8000000'),
    ('rmp_value_defaults', 0x2c71a53, '31c0f68424e800000001488b8c2418010000480f44c840f6c701488b9424100100000f44d04889df4889c8488b8c2420010000'),
    ('rmp_value_duplicate_n', 0x2c72532, '4989f6488d052e4190fd488944245048c744245801000000488d4424504889442408488d05d5a6b7004889442410488d356eea56fd488d7c2470488d542408e80a88e7ff'),
    ('rmp_value_duplicate_t', 0x2c71e6b, '4989f6488d05bb4990fde9c2060000'),
    ('rmp_time_nil', 0x2a6e998, '0fb646200fb64e21c64620013dc0000000747883f8010f8582000000'),
    ('rmp_time_nil_return', 0x2a6ea09, '3ca07308240f89c1b090eb213cc07308241f89c1b0a0eb157513c7430400000000c603094889d84883c4405bc3884620884e21488d1549b479fd488d7c2420b904000000e8be460200'),
    ('low_pair_entry', 0x1debef0, '554157415641554154534881ecb80000004989cd4989f44889fb49be0000000000000080488b364889f048f7d871154d8b7c242841807f0c02751c4c896c244831c0eb48'),
    ('shared_pair_entry', 0x43c8990, '554157415641554154534881ecb80000004989cd4989f44889fb49be0000000000000080488b364889f048f7d871154d8b7c242841807f0c02751c4c896c244831c0eb48'),
    ('low_pair_key', 0x1debf7c, '488944247848c78424800000000100000048c7842488000000000000004c89bc2490000000c784249800000002000000488d7c2410488d742478e8e51002004d8d66044c396424100f8589020000'),
    ('shared_pair_key', 0x43c8a1c, '488944247848c78424800000000100000048c7842488000000000000004c89bc2490000000c784249800000002000000488d7c2410488d742478e855c102004d8d66044c396424100f8589020000'),
    ('boundary_exchange_child', 0x2fe80e4, '4883fe3a0f85cd9100004885c00f843dac00004989462848c78424f800000000000000488dbc24800700004c89f6e8d96d6500488b84248807000083bc2480070000010f848b4a0000488d8c24900700000f1001488d8c24280700000f11410848c7842420070000010000004889842428070000b80100000048898424f8000000'),
    ('boundary_field_pointer', 0x275b2aa, '498d96a83900004889e74c89fee8a48305004c3924240f851a050000'),
    ('boundary_hash_low', 0x2816885, 'c744240800040001c644240c00488b36488dbc24080100004889e2e80b74ddff4c8bb4240801000048b804000000000000804939c60f85f6000000'),
    ('boundary_hash_shared', 0x4ae4ac5, 'c744240800040001c644240c00488b36488dbc24080100004889e2e8cbf7b1ff4c8bb4240801000048b804000000000000804939c60f85f6000000'),
    ('reader_dispatch', 0x363ef81, '448d47a54183f8200f87b2000000488d35b632f5fc4e6304864901f041ffe0'),
    ('reader_seq_entry', 0x363efa0, '410fb64e4884c90f84dd060000fec941884e480f84aa0600004883f8040f84ba0600004883c0fc49894628488dbc24d00000004c89f6ba01000000e8b0520800'),
    ('reader_map_entry', 0x363f0a6, '410fb64e4884c90f84e4050000fec941884e480f84a40500004883f8040f84b40500004883c0fc49894628'),
    ('reader_map_loop', 0x363f120, '488dbc24b80000004c89eee8c0e69dff80bc24b8000000010f845e010000f68424b9000000010f845a010000488d7c24604c89eee8a7329eff837c2460010f8470010000'),
    ('reader_map_insert', 0x363f1d1, '4889e7488db424a0000000488d942410010000488d4c2440e882f1d5ff48833c24000f8427ffffffbf0d000000ff15d4ed12024885c00f84b504000048b963617465206b65794889480548b96475706c6963617448890848c704240d000000488944240848c74424100d0000004889e7e85aead9ffe9'),
    ('reader_map_error', 0x363f287, '488b4c24284889410848c70101000000e9d8000000488b8424c0000000eb330f108424a00000000f11842488000000488b8424b0000000488984249800000048c784248000000000000000eb26488b442468488984248800000048c784248000000001000000488dbc24a0000000e8a69edbff'),
    ('reader_map_result', 0x363f342, '488b8424880000000f108424900000000f298424f0000000488b4c2428488941080f288424f00000000f11411031c04889014889c84881c4280100005b415c415d415e415f5dc3'),
    ('reader_colon', 0x302247f, '4983f83a751a4885c07420488946284889dfe84a6b09004889d84883c4205bc348c744240806000000eb'),
    ('reader_map_key', 0x301d8d1, '4183f97d7506c6430100eb5c807808000f8484000000c64008004180f9227555488d7c2408e8051d2300807c240800740d488b44241048894308b001eb2c8b4424098b4c240c894b05894302488b4424108b4c24180fb654241c48894309885315894b11c643010131c088034889d84883c4205bc3'),
    ('reader_pair_key', 0x3048682, '4183fa5d7509c6430100e986000000807e08000f8489000000c6460800eb0a4183f85d0f84870000000f57c00f29442420c74424300000000048c744240800000000488d442420488944241048c744241814000000488d742408e8afb60400a801740848895308b001eb2c8b4424208b4c2423894b05894302488b4424278b4c242f0fb654243348894309885315894b11c643010131c088034889d84883c4405bc3'),
    ('reader_key_fixed_buffer', 0x324f600, '534883ec500f57c00f29442420c744243000000000488b46284883f8ff0f849a0000004889f24889fb4883c61848ffc04889422848c7421000000000488d7c2438ff1559f65102488b4c2438488b5424404883f902751db801000000a801754c8b4424308943110f284424200f11430131c0eb3e488b442448f6c10148c744240800000000488d4c242048894c241048c744241814000000488d7c24084889d64889c2e8e82e4900a80174b448895308b00188034889d84883c4505bc3'),
    ('reader_unsigned_dispatch', 0x2fe4d59, '4883ff2d75374885c00f84f000000048894328488d7c24204889de31d2e855efffff488b4424204883f8037537488b542428b8010000004883c4305bc34080c7d04080ff0a736e488d7c24204889deba01000000e81eefffff488b4424204883f80374c9488b54242883f801740a83f80275134885d2786431c0a801754e31c04883c4305bc3'),
    ('reader_unsigned_error', 0x2fe4ddf, '4889542410c644240803488d15d88e7002488d7c2408488d742407ff1518ae78024889c2b801000000a80174cbeb17488d1533456f02488d7424074889dfe81ef5ffff4889c24889d74889dee880b63200e916ffffff4889542410c644240802488d1502456f02488d7c2408488d742407ff15f2ad7802eba8'),
    ('reader_sequence_loop', 0x36c42f0, '4c89ff4c89e6e835c596ff488b4c2438488b4424404883f9020f84b6000000'),
    ('reader_sequence_insert', 0x36c4350, '4c89ff4c89ee4889ea488d8c2480000000e80aa0cdff48837c2438007482bf0d000000ff155f9c0a024885c00f84'),
    ('reader_sequence_duplicate', 0x36c4382, '48b963617465206b65794889480548b96475706c6963617448890848c74424380d000000488944244048c74424480d000000488d7c2438e8e298d1ff'),
    ('reader_pair_open', 0x303094a, '83fe5b0f8561020000410fb64e4884c90f84e7020000fec941884e480f845e0200004885c00f84c5020000498946284c89742430c644243801488d7c2410488d742430e81e7c0100807c241001750a'),
    ('reader_pair_value', 0x3030abd, '488d7c2410e8198508004c8b7c2418807c241000745a41bc01000000410fb646483cff7479fec0418846484c89f7e80045fbff4d85e47575'),
    ('value_open', 0x30b905c, '83ff5b0f845103000083ff7b0f8564050000'),
    ('value_map_flags', 0x30b909d, 'b20148c74424380000000048c744244000000000'),
    ('value_key_dispatch', 0x30b91a6, '48837c24180175720fb6450083f86e0f84e200000083f8747560837c2438010f8445040000'),
    ('value_unknown_and_dup_n', 0x30b9287, '4c89f7e801a1f2ff4885c00f84f8000000e97f02000048837c2440010f845e030000'),
    ('value_field_reads', 0x30b9308, '4883fe3a0f85e70200004885c00f843603000049894628488d7c24284c89f6e8d483ac00837c2428010f8461020000448b6c242c488b4424304889442448b8010000004889442438eb3e4883fe3a75504885c00f84f0020000498946284c89f7e873b9f2ffa8010f850b0200004889542450b8010000004889442440'),
    ('value_sequence', 0x30b93b6, '410fb64e4884c90f84a8020000fec941884e480f84d00100004885c00f8479020000498946284c89742428c644243001488d7c2408488d742428e84b8cf5ff8b6c240883fd027428448b6c240c4c8b642410488d7c2408488d742428e8690af5ff488b4424084883f8020f85b3000000'),
    ('value_defaults', 0x30b946a, '4531fff644243801450f44eff644244001488b6c2450490f44ef4c8b642448'),
    ('value_output', 0x30b94ad, '4885c00f85b100000048896b0844896b104c89631431c0488903'),
    ('value_invalid_type', 0x30b95d2, '488d15773a6202488d7424274c89f7e85aadf2ffe97cffffff'),
    ('value_duplicate_errors', 0x30b9607, '488d05db394cfdeb07488d05983b4cfd488944242848c744243001000000488d4424284889442408488d05fa3573004889442410488d3d937912fd488d742408e8e4443200e9cbfeffff'),
    ('value_type_formatter', 0x3432030, '488b3e488b4608488b4018488d353bb215fdba16000000ffe0'),
    ('nullable_time', 0x3b8176c, '4183f96e75684883f8030f84c2000000488d78fd48897e284839cf0f838b000000488d78fe440fb64402fd48897e284180f8750f858e0000004839cf736e488d78ff440fb64402fe48897e284180f86c75754839cf73550fb64c02ff4889462880f96c7562c7430400000000eb31488d7c2408e8dc2651ff837c2408017510488b44241048894308b801000000eb128b44240c488b4c241089430448894b0831c08903'),
    ('nullable_time_errors', 0x3b81818, '48c744240805000000488d4424084889f74889c6e83f3646ffebbd48c744240809000000ebe3'),
    ('low_field_wrapper', 0x27b366b, '807e0b007420488d3595bdc3fdba180000004989ff4889dfe86871dfff4c89ff4883f80275104c89f64889da5b415e415fe90fa6e3ff48b9000000000000008048890f48894708488957105b415e415fc3'),
    ('shared_field_wrapper', 0x4df637b, '807e0b007420488d35cee491fbba180000004989ff4889dfe8d84dcfff4c89ff4883f80275104c89f64889da5b415e415fe9ffde80ff48b9000000000000008048890f48894708488957105b415e415fc3'),
    ('low_map_adapter', 0x25edcbf, '488b0e4885c97435488b5608488b461048c74424200000000048894c2428488954243048c74424400000000048894c24484889542450b901000000eb0431c931c048894c241848894c243848894424584989e7488d7424184c89ffe84153f7ff4889df4c89f64c89fae8235784ff488b34244885f67411488b7c240848c1e60431d2ff15c90218034889d84883c4605b415e415fc3'),
    ('shared_map_adapter', 0x46042bf, '488b0e4885c97435488b5608488b461048c74424200000000048894c2428488954243048c74424400000000048894c24484889542450b901000000eb0431c931c048894c241848894c243848894424584989e7488d7424184c89ffe8517226004889df4c89f64c89fae85355e0ff488b34244885f67411488b7c240848c1e60431d2ff15c99c16014889d84883c4605b415e415fc3'),
    ('low_sequence_prefix', 0x1e33469, '4c8b6a084c8b72104c89f048c1e8200f94c1807e0c00410f95c44120cc741831ed4d85f6400f95c54c89eb490f44dec1e5044c01edeb0c4c89ed4885c00f85f6000000488d7c24404c89fe4489f2e814677700488b4424404883f8020f85b3000000'),
    ('low_sequence_first', 0x1e334fe, '488b13488b4b08488d7c2440488d742410e8dc89fbff488b44244048b900000000000000804883c1044839c80f84d3000000'),
    ('low_sequence_loop', 0x1e33630, '488b5500488b4d084c89f74c89fee8ad88fbff488b4424404839d80f85dffeffff4883c5104c39ed75d6'),
    ('shared_sequence_prefix', 0x4409899, '4c8b6a084c8b72104c89f048c1e8200f94c1807e0c00410f95c44120cc741831ed4d85f6400f95c54c89eb490f44dec1e5044c01edeb0c4c89ed4885c00f85f6000000488d7c24404c89fe4489f2e8340b6e00488b4424404883f8020f85b3000000'),
    ('shared_sequence_first', 0x440992e, '488b13488b4b08488d7c2440488d742410e84cf0fbff488b44244048b900000000000000804883c1044839c80f84d3000000'),
    ('shared_sequence_loop', 0x4409a60, '488b5500488b4d084c89f74c89fee81deffbff488b4424404839d80f85dffeffff4883c5104c39ed75d6'),
    ('low_pair_generic', 0x1dec073, '4c89742478488d7c2410488b7424484c89eae83689af004c396424100f85bd020000488d7424784889dfe81e6b0200e9e5020000498b4424104839c60f84e9020000498b4c2408c604019248ffc04989442410'),
    ('low_pair_direct', 0x1dec1cb, '488d7c24104c89ee4889eae84589af004c397c24100f85ee000000'),
    ('shared_pair_generic', 0x43c8b13, '4c89742478488d7c2410488b7424484c89eae806bc89004c396424100f85bd020000488d7424784889dfe8ae160300e9e5020000498b4424104839c60f84e9020000498b4c2408c604019248ffc04989442410'),
    ('shared_pair_direct', 0x43c8c6b, '488d7c24104c89ee4889eae815bc89004c397c24100f85ee000000'),
    ('low_generic_presence', 0x28e49e1, '8b6e084c8b3e31d24d85ff0f95c283fd0183daff41807e0b00742a4889e74c89f6e87945ccff488b04244883f802742a'),
    ('low_generic_fields', 0x28e4a3b, '85ed744941807e0b01751a488d35721bb1fdba010000004c89f7e8965dccff4883f802756f4983c408488d15215492fd4889e7b9040000004c89f64d89e0e892b156ff498d45044839042475554d85ff743941807e0b01751a488d35cb1ab1fdba010000004c89f7e8485dccff4883f802754f4889e74c89f64c89fae81476ccff488b04244883f80275324983c5044c892beb39'),
    ('low_generic_error', 0x28e4acf, '4c892c2448894424084889542410488b44241048894310488b0424488903488b44240848894308eb10488b5424084c892b4889430848895310'),
    ('low_direct_presence', 0x28e4b41, '8b6e084c8b3e31d24d85ff0f95c283fd0183daff41807e1b00741a4889e74c89f6e8e946ccff488b04244883f802741ee9df0000004889e74c89f6e81f4fccff488b04244883f8020f85c6000000'),
    ('low_direct_t', 0x28e4b8f, '85ed74624983c40841807e1b017533498b06498b76104839f00f84db000000498b4e08c60431a148ffc6498976104839f00f84e7000000c604317448ffc649897610488d15b45292fd4889e7b9040000004c89f64d89e0e895b156ff498d4504483904247572'),
    ('low_direct_n', 0x28e4bf5, '4d85ff745241807e1b017533498b06498b76104839f00f84c4000000498b4e08c60431a148ffc6498976104839f00f84d0000000c604316e48ffc6498976104889e74c89f64c89fae8fe70ccff488b04244883f80275094983c5044c892beb22'),
    ('low_direct_error', 0x28e4c55, '488b4c24084c892b4889430848894b10eb10488b442410488943100f1004240f1103'),
    ('shared_generic_presence', 0x4c64751, '8b6e084c8b3e31d24d85ff0f95c283fd0183daff41807e0b00742a4889e74c89f6e88951e8ff488b04244883f802742a'),
    ('shared_generic_fields', 0x4c647ab, '85ed744e41807e0b01751a488d354b8eaafbba010000004c89f7e8a669e8ff4883f80275744983c4084c89642418488d44241848894424204889e7488d5424204c89f6e87dec77ff498d45044839042475554d85ff743941807e0b01751a488d35f790aafbba010000004c89f7e85369e8ff4883f802754f4889e74c89f64c89fae81f82e8ff488b04244883f80275324983c5044c892beb39'),
    ('shared_generic_error', 0x4c64844, '4c892c2448894424084889542410488b44241048894310488b0424488903488b44240848894308eb10488b5424084c892b4889430848895310'),
    ('shared_direct_presence', 0x4c648b1, '8b6e084c8b3e31d24d85ff0f95c283fd0183daff41807e1b00741a4889e74c89f6e8f952e8ff488b04244883f802741ee9e40000004889e74c89f6e8ff5de8ff488b04244883f8020f85cb000000'),
    ('shared_direct_t', 0x4c648ff, '85ed74674983c40841807e1b017533498b06498b76104839f00f84e0000000498b4e08c60431a148ffc6498976104839f00f84ec000000c604317448ffc6498976104c89642418488d44241848894424204889e7488d5424204c89f6e870ec77ff498d4504483904247572'),
    ('shared_direct_n', 0x4c6496a, '4d85ff745241807e1b017533498b06498b76104839f00f84c4000000498b4e08c60431a148ffc6498976104839f00f84d0000000c604316e48ffc6498976104889e74c89f64c89fae8097de8ff488b04244883f80275094983c5044c892beb22'),
    ('shared_direct_error', 0x4c649ca, '488b4c24084c892b4889430848894b10eb10488b442410488943100f1004240f1103'),
)

# Each edge is a selected rel32 instruction, not a census of all calls.
# The first four originate in previously researched functions and are solely
# boundary connections; none of those functions is claimed by this packet.
EDGES = (
    ('shared_key_buffer_header', 0x43f56f7, 0xe8, 0x4aea6f0, 'new-to-helper'),
    ('shared_key_buffer_byte', 0x43f573c, 0xe8, 0x4aec6c0, 'new-to-helper'),
    ('shared_key_hex_string', 0x43f57b4, 0xe8, 0x4aeb630, 'new-to-helper'),
    ('rmp_key_buffer_decode', 0x2a72bdd, 0xe8, 0x2bd0ea0, 'new-to-helper'),
    ('rmp_pair_key_decode', 0x2d3b581, 0xe8, 0x2bd0ea0, 'new-to-helper'),
    ('json_pair_key_decode', 0x3093e6c, 0xe8, 0x36e2590, 'new-to-helper'),
    ('shared_time_write_string', 0x43e3678, 0xe8, 0x4aeb630, 'new-to-helper'),
    ('prior_rmp_to_exchange', 0x2e0e6aa, 0xe8, 0x2bfe6c0, 'prior-boundary'),
    ('rmp_exchange_fields', 0x2bfeac8, 0xe8, 0x2ab4a60, 'new-to-helper'),
    ('prior_rmp_field_to_map', 0x2abb86f, 0xe8, 0x2de8130, 'prior-boundary'),
    ('rmp_map_dispatch', 0x2de8506, 0xe8, 0x3679c50, 'new'),
    ('rmp_seq_dispatch', 0x2de864a, 0xe8, 0x36af9e0, 'new'),
    ('rmp_map_key', 0x3679cd5, 0xe8, 0x2a72b70, 'new-to-helper'),
    ('rmp_map_value', 0x3679d60, 0xe8, 0x2c710c0, 'new'),
    ('rmp_map_insert', 0x3679e9e, 0xe8, 0x339e370, 'new-to-helper'),
    ('rmp_array_pair', 0x36afa3c, 0xe8, 0x2d3afe0, 'new'),
    ('rmp_array_insert', 0x36afacf, 0xe8, 0x339e370, 'new-to-helper'),
    ('rmp_pair_value', 0x2d3b6bf, 0xe8, 0x2c710c0, 'new'),
    ('rmp_value_seq_time', 0x2c7165f, 0xe8, 0x2a6e990, 'new'),
    ('rmp_value_seq_n', 0x2c71726, 0xe8, 0x2a65d30, 'new-to-helper'),
    ('rmp_value_map_time', 0x2c71e03, 0xe8, 0x2a6e990, 'new'),
    ('rmp_value_map_n', 0x2c7216d, 0xe8, 0x2a65d30, 'new-to-helper'),
    ('rmp_value_unknown', 0x2c721af, 0xe8, 0x2ddabf0, 'new-to-helper'),
    ('rmp_time_non_nil', 0x2a6ea4d, 0xe8, 0x2a93110, 'new-to-helper'),
    ('prior_exchange_to_map', 0x2fe8112, 0xe8, 0x363eef0, 'prior-boundary'),
    ('prior_field_to_wrapper', 0x275b2b7, 0xe8, 0x27b3660, 'prior-boundary'),
    ('prior_low_hash_to_map', 0x28168a0, 0xe8, 0x25edcb0, 'prior-boundary'),
    ('prior_shared_hash_to_map', 0x4ae4ae0, 0xe8, 0x46042b0, 'prior-boundary'),
    ('map_to_array', 0x363efdb, 0xe8, 0x36c4290, 'new'),
    ('map_read_key', 0x363f12b, 0xe8, 0x301d7f0, 'new'),
    ('map_read_value', 0x363f154, 0xe8, 0x3022400, 'new'),
    ('map_insert', 0x363f1e9, 0xe8, 0x339e370, 'new-to-helper'),
    ('map_duplicate_error', 0x363f241, 0xe8, 0x33ddca0, 'new-to-helper'),
    ('map_value_to_cancel', 0x3022491, 0xe8, 0x30b8fe0, 'new'),
    ('array_to_pair', 0x36c42f6, 0xe8, 0x3030830, 'new'),
    ('array_insert', 0x36c4361, 0xe8, 0x339e370, 'new-to-helper'),
    ('array_duplicate_error', 0x36c43b9, 0xe8, 0x33ddca0, 'new-to-helper'),
    ('pair_read_key', 0x303098d, 0xe8, 0x30485b0, 'new'),
    ('pair_read_cancel', 0x3030ac2, 0xe8, 0x30b8fe0, 'new'),
    ('map_key_to_fixed', 0x301d8f6, 0xe8, 0x324f600, 'new'),
    ('fixed_key_to_decoder', 0x324f6a3, 0xe8, 0x36e2590, 'new-to-helper'),
    ('sequence_key_to_decoder', 0x30486dc, 0xe8, 0x3093d90, 'new-to-helper'),
    ('unsigned_negative_number', 0x2fe4d76, 0xe8, 0x2fe3cd0, 'new-to-helper'),
    ('unsigned_positive_number', 0x2fe4dad, 0xe8, 0x2fe3cd0, 'new-to-helper'),
    ('value_unknown', 0x30b928a, 0xe8, 0x2fe3390, 'new-to-helper'),
    ('value_read_t', 0x30b9327, 0xe8, 0x3b81700, 'new'),
    ('value_read_n', 0x30b9368, 0xe8, 0x2fe4ce0, 'new'),
    ('value_seq_first', 0x30b93f0, 0xe8, 0x3012040, 'new-to-helper'),
    ('value_seq_second', 0x30b9412, 0xe8, 0x3009e80, 'new-to-helper'),
    ('value_duplicate_error', 0x30b9647, 0xe8, 0x33ddb30, 'new-to-helper'),
    ('time_non_null', 0x3b817df, 0xe8, 0x3093ec0, 'new-to-helper'),
    ('low_wrapper_label', 0x27b3683, 0xe8, 0x25aa7f0, 'new-to-helper'),
    ('low_wrapper_map', 0x27b369c, 0xe9, 0x25edcb0, 'new'),
    ('shared_wrapper_label', 0x4df6393, 0xe8, 0x4aeb170, 'new-to-helper'),
    ('shared_wrapper_map', 0x4df63ac, 0xe9, 0x46042b0, 'new'),
    ('low_collect', 0x25edd1a, 0xe8, 0x2563060, 'new-to-helper'),
    ('low_map_sequence', 0x25edd28, 0xe8, 0x1e33450, 'new'),
    ('shared_collect', 0x460431a, 0xe8, 0x486b570, 'new-to-helper'),
    ('shared_map_sequence', 0x4604328, 0xe8, 0x4409880, 'new'),
    ('low_sequence_header', 0x1e334b7, 0xe8, 0x25a9bd0, 'new-to-helper'),
    ('low_sequence_first', 0x1e3350f, 0xe8, 0x1debef0, 'new'),
    ('low_sequence_loop', 0x1e3363e, 0xe8, 0x1debef0, 'new'),
    ('shared_sequence_header', 0x44098e7, 0xe8, 0x4aea420, 'new-to-helper'),
    ('shared_sequence_first', 0x440993f, 0xe8, 0x43c8990, 'new'),
    ('shared_sequence_loop', 0x4409a6e, 0xe8, 0x43c8990, 'new'),
    ('low_pair_generic_key', 0x1debfb6, 0xe8, 0x1e0d0a0, 'new-to-helper'),
    ('low_pair_direct_key', 0x1dec0f7, 0xe8, 0x1e0d6c0, 'new-to-helper'),
    ('shared_pair_generic_key', 0x43c8a56, 0xe8, 0x43f4bb0, 'new-to-helper'),
    ('shared_pair_direct_key', 0x43c8b97, 0xe8, 0x43f56b0, 'new-to-helper'),
    ('low_pair_generic', 0x1dec085, 0xe8, 0x28e49c0, 'new'),
    ('low_pair_direct', 0x1dec1d6, 0xe8, 0x28e4b20, 'new'),
    ('shared_pair_generic', 0x43c8b25, 0xe8, 0x4c64730, 'new'),
    ('shared_pair_direct', 0x43c8c76, 0xe8, 0x4c64890, 'new'),
    ('low_generic_time', 0x28e4a79, 0xe8, 0x1e4fc10, 'new-to-helper'),
    ('low_generic_n', 0x28e4ab7, 0xe8, 0x25ac0d0, 'new-to-helper'),
    ('low_direct_time', 0x28e4be6, 0xe8, 0x1e4fd80, 'new-to-helper'),
    ('low_direct_n', 0x28e4c3d, 0xe8, 0x25abd40, 'new-to-helper'),
    ('shared_generic_time', 0x4c647ee, 0xe8, 0x43e3470, 'new-to-helper'),
    ('shared_generic_n', 0x4c6482c, 0xe8, 0x4aeca50, 'new-to-helper'),
    ('shared_direct_time', 0x4c6495b, 0xe8, 0x43e35d0, 'new-to-helper'),
    ('shared_direct_n', 0x4c649b2, 0xe8, 0x4aec6c0, 'new-to-helper'),
)

# Jcc condition codes use the x86 low nibble. Both targets are reported; only
# the indicated checks are included, not all control flow in each extent.
BRANCHES = (
    ('key_unbuffered', 0x43f56d7, 0x1, 0x43f56e2, 'new'),
    ('key_header_failure', 0x43f5705, 0x5, 0x43f57d5, 'new'),
    ('key_empty_buffer', 0x43f5720, 0x4, 0x43f5758, 'new'),
    ('key_byte_failure', 0x43f574a, 0x5, 0x43f57e7, 'new'),
    ('key_buffer_loop', 0x43f5756, 0x5, 0x43f5730, 'new'),
    ('key_hex_write_failure', 0x43f57bd, 0x5, 0x43f57c8, 'new'),
    ('rmp_key_nonspecial_name', 0x2a72b7f, 0x5, 0x2a72ba2, 'new'),
    ('rmp_key_special_name', 0x2a72b9c, 0x4, 0x2a72cae, 'new'),
    ('rmp_key_decode_error', 0x2a72be9, 0x5, 0x2a72c2f, 'new'),
    ('json_pair_key_eof', 0x3093da5, 0x3, 0x3093dec, 'new'),
    ('json_pair_key_quote', 0x3093e08, 0x5, 0x3093e7f, 'new'),
    ('json_pair_key_decode_error', 0x3093e73, 0x5, 0x3093e94, 'new'),
    ('time_date_format_error', 0x43e3631, 0x5, 0x43e36c8, 'new'),
    ('time_separator_error', 0x43e364b, 0x5, 0x43e36c8, 'new'),
    ('time_clock_format_error', 0x43e3661, 0x5, 0x43e36c8, 'new'),
    ('time_string_result', 0x43e368b, 0x5, 0x43e369b, 'new'),
    ('time_no_buffer_free', 0x43e36a9, 0x4, 0x43e36b9, 'new'),
    ('rmp_value_depth_overflow', 0x2c717dc, 4, 0x2c719e8, 'new'),
    ('rmp_marker_signed', 0x2de831b, 8, 0x2de84b8, 'new'),
    ('rmp_value_marker_array', 0x2c71467, 3, 0x2c71627, 'new'),
    ('rmp_value_marker_other', 0x2c71629, 3, 0x2c718dc, 'new'),
    ('prior_rmp_field_duplicate', 0x2abb84e, 0x5, 0x2abe76f, 'prior-boundary'),
    ('rmp_fixmap_to_seq', 0x2de84c7, 0x3, 0x2de8608, 'new'),
    ('rmp_seq_to_other', 0x2de860b, 0x3, 0x2de874f, 'new'),
    ('rmp_map_read_error', 0x3679d6c, 0x5, 0x3679fa7, 'new'),
    ('rmp_map_duplicate', 0x3679ea9, 0x5, 0x3679eee, 'new'),
    ('rmp_sequence_pair_error', 0x36afa46, 0x5, 0x36afb0d, 'new'),
    ('rmp_sequence_duplicate', 0x36afada, 0x5, 0x36afb25, 'new'),
    ('rmp_pair_value_error', 0x2d3b6cd, 0x5, 0x2d3b862, 'new'),
    ('rmp_value_array_empty', 0x2c71652, 0x4, 0x2c7168a, 'new'),
    ('rmp_value_t_error', 0x2c7166b, 0x5, 0x2c71696, 'new'),
    ('rmp_value_has_n', 0x2c7167a, 0x5, 0x2c7171e, 'new'),
    ('rmp_value_n_error', 0x2c71732, 0x5, 0x2c717fe, 'new'),
    ('rmp_value_no_extra', 0x2c71788, 0x4, 0x2c7179f, 'new'),
    ('rmp_key_size', 0x2c71dc2, 0x5, 0x2c7219b, 'new'),
    ('rmp_key_not_t', 0x2c71dd2, 0x5, 0x2c71dda, 'new'),
    ('rmp_duplicate_t', 0x2c71df9, 0x4, 0x2c71e6b, 'new'),
    ('rmp_time_error', 0x2c71e0f, 0x5, 0x2c71e34, 'new'),
    ('rmp_key_unknown', 0x2c72141, 0x4, 0x2c7219b, 'new'),
    ('rmp_key_t', 0x2c7214d, 0x5, 0x2c71df2, 'new'),
    ('rmp_duplicate_n', 0x2c7215f, 0x4, 0x2c72532, 'new'),
    ('rmp_n_error', 0x2c72179, 0x5, 0x2c72503, 'new'),
    ('rmp_nil', 0x2a6e9a9, 0x4, 0x2a6ea23, 'new'),
    ('prior_field_child_error', 0x2fe8127, 4, 0x2fecbb8, 'prior-boundary'),
    ('map_dispatch_outside_table', 0x363ef89, 7, 0x363f041, 'new'),
    ('map_key_error', 0x363f138, 4, 0x363f29c, 'new'),
    ('map_key_done', 0x363f146, 4, 0x363f2a6, 'new'),
    ('map_value_error', 0x363f15e, 4, 0x363f2d4, 'new'),
    ('map_insert_continue', 0x363f1f3, 4, 0x363f120, 'new'),
    ('map_duplicate_alloc_failure', 0x363f207, 4, 0x363f6c2, 'new'),
    ('array_entry_error', 0x36c4309, 4, 0x36c43c5, 'new'),
    ('array_entries_done', 0x36c4332, 4, 0x36c43e1, 'new'),
    ('array_insert_continue', 0x36c436c, 4, 0x36c42f0, 'new'),
    ('pair_requires_array', 0x303094d, 5, 0x3030bb4, 'new'),
    ('pair_first_nonerror', 0x3030997, 5, 0x30309a3, 'new'),
    ('pair_missing_first', 0x30309a8, 4, 0x3030be6, 'new'),
    ('pair_value_success', 0x3030ad1, 4, 0x3030b2d, 'new'),
    ('map_key_requires_quote', 0x301d8ef, 5, 0x301d946, 'new'),
    ('map_key_success', 0x301d900, 4, 0x301d90f, 'new'),
    ('sequence_key_success', 0x30486e3, 4, 0x30486ed, 'new'),
    ('fixed_key_string_success', 0x324f655, 5, 0x324f674, 'new'),
    ('fixed_key_decode_success', 0x324f6aa, 4, 0x324f660, 'new'),
    ('unsigned_sign_dispatch', 0x2fe4d5d, 5, 0x2fe4d96, 'new'),
    ('unsigned_number_result', 0x2fe4d84, 5, 0x2fe4dbd, 'new'),
    ('unsigned_non_digit', 0x2fe4d9e, 3, 0x2fe4e0e, 'new'),
    ('unsigned_parse_error', 0x2fe4dbb, 4, 0x2fe4d86, 'new'),
    ('unsigned_tag_one', 0x2fe4dc5, 4, 0x2fe4dd1, 'new'),
    ('unsigned_other_tag', 0x2fe4dca, 5, 0x2fe4ddf, 'new'),
    ('unsigned_negative_reject', 0x2fe4dcf, 8, 0x2fe4e35, 'new'),
    ('value_open_array', 0x30b905f, 4, 0x30b93b6, 'new'),
    ('value_invalid_type', 0x30b9068, 5, 0x30b95d2, 'new'),
    ('value_close_map', 0x30b9153, 4, 0x30b946a, 'new'),
    ('value_unknown_length', 0x30b91ac, 5, 0x30b9220, 'new'),
    ('value_key_n', 0x30b91b5, 4, 0x30b929d, 'new'),
    ('value_unknown_key', 0x30b91be, 5, 0x30b9220, 'new'),
    ('value_duplicate_t', 0x30b91c5, 4, 0x30b9610, 'new'),
    ('value_duplicate_n', 0x30b92a3, 4, 0x30b9607, 'new'),
    ('value_unknown_success', 0x30b9292, 4, 0x30b9390, 'new'),
    ('value_t_error', 0x30b9331, 4, 0x30b9598, 'new'),
    ('value_n_error', 0x30b936f, 5, 0x30b9580, 'new'),
    ('value_array_t_error', 0x30b93fc, 4, 0x30b9426, 'new'),
    ('value_array_n_non_error', 0x30b9420, 5, 0x30b94d9, 'new'),
    ('value_closing_error', 0x30b94b0, 5, 0x30b9567, 'new'),
    ('time_non_null_route', 0x3b81770, 5, 0x3b817da, 'new'),
    ('time_invalid_u', 0x3b8179f, 5, 0x3b81833, 'new'),
    ('time_invalid_first_l', 0x3b817bc, 5, 0x3b81833, 'new'),
    ('time_invalid_second_l', 0x3b817cf, 5, 0x3b81833, 'new'),
    ('low_wrapper_unnamed', 0x27b366f, 4, 0x27b3691, 'new'),
    ('low_wrapper_label_error', 0x27b368f, 5, 0x27b36a1, 'new'),
    ('shared_wrapper_unnamed', 0x4df637f, 4, 0x4df63a1, 'new'),
    ('shared_wrapper_label_error', 0x4df639f, 5, 0x4df63b1, 'new'),
    ('low_map_empty', 0x25edcc5, 4, 0x25edcfc, 'new'),
    ('shared_map_empty', 0x46042c5, 4, 0x46042fc, 'new'),
    ('low_sequence_header_error', 0x1e334c5, 5, 0x1e3357e, 'new'),
    ('shared_sequence_header_error', 0x44098f5, 5, 0x44099ae, 'new'),
    ('low_pair_generic_key_error', 0x1debfc4, 5, 0x1dec253, 'new'),
    ('low_pair_direct_key_error', 0x1dec105, 5, 0x1dec201, 'new'),
    ('shared_pair_generic_key_error', 0x43c8a64, 5, 0x43c8cf3, 'new'),
    ('shared_pair_direct_key_error', 0x43c8ba5, 5, 0x43c8ca1, 'new'),
    ('low_pair_generic_value_error', 0x1dec08f, 5, 0x1dec352, 'new'),
    ('low_pair_direct_value_error', 0x1dec1e0, 5, 0x1dec2d4, 'new'),
    ('shared_pair_generic_value_error', 0x43c8b2f, 5, 0x43c8df2, 'new'),
    ('shared_pair_direct_value_error', 0x43c8c80, 5, 0x43c8d74, 'new'),
    ('low_generic_t_absent', 0x28e4a3d, 4, 0x28e4a88, 'new'),
    ('low_generic_n_absent', 0x28e4a8b, 4, 0x28e4ac6, 'new'),
    ('low_direct_t_absent', 0x28e4b91, 4, 0x28e4bf5, 'new'),
    ('low_direct_t_error', 0x28e4bf3, 5, 0x28e4c67, 'new'),
    ('low_direct_n_absent', 0x28e4bf8, 4, 0x28e4c4c, 'new'),
    ('low_direct_n_error', 0x28e4c4a, 5, 0x28e4c55, 'new'),
    ('shared_generic_t_absent', 0x4c647ad, 4, 0x4c647fd, 'new'),
    ('shared_generic_n_absent', 0x4c64800, 4, 0x4c6483b, 'new'),
    ('shared_direct_t_absent', 0x4c64901, 4, 0x4c6496a, 'new'),
    ('shared_direct_t_error', 0x4c64968, 5, 0x4c649dc, 'new'),
    ('shared_direct_n_absent', 0x4c6496d, 4, 0x4c649c1, 'new'),
    ('shared_direct_n_error', 0x4c649bf, 5, 0x4c649ca, 'new'),
)

# Fixed RIP-relative LEA instructions linking the selected names and vtable.
LEAS = (
    ('rmp_key_type_name', 0x3679cce, 0x20a020),
    ('shared_time_error_text', 0x43e36c8, 0x6f1bb9),
    ('rmp_outer_field_boundary', 0x2abe76f, 0x578cd2),
    ('rmp_duplicate_t', 0x2c71e6e, 0x576830),
    ('rmp_duplicate_n', 0x2c72535, 0x57666a),
    ('rmp_time_name', 0x2a6ea3c, 0x209e8c),
    ('low_outer_name', 0x27b3671, 0x3ef40d),
    ('shared_outer_name', 0x4df6381, 0x714856),
    ('reader_expected_type_vtable', 0x30b95d2, 0x56dd050),
    ('expected_type_text', 0x343203b, 0x58d27d),
    ('duplicate_n', 0x30b9607, 0x57cfe9),
    ('duplicate_t', 0x30b9610, 0x57d1af),
    ('duplicate_template', 0x30b963b, 0x1e0fd5),
    ('low_generic_t', 0x28e4a46, 0x3f65bf),
    ('low_generic_time', 0x28e4a64, 0x209e8c),
    ('low_generic_n', 0x28e4a94, 0x3f6566),
    ('shared_generic_t', 0x4c647b6, 0x70d608),
    ('shared_generic_n', 0x4c64809, 0x70d907),
    ('map_dispatch_table', 0x363ef8f, 0x59224c),
)
LITERALS = (
    ('rmp_key_type_name', 0x20a020, b'User'),
    ('time_format_error', 0x6f1bb9, b'a Display implementation returned an error unexpectedly'),
    ('rmp_outer_name', 0x578cd2, b'user_to_scheduled_cancel'),
    ('rmp_reader_t', 0x576830, b't'),
    ('rmp_reader_n', 0x57666a, b'n'),
    ('low_outer_name', 0x3ef40d, b'user_to_scheduled_cancel'),
    ('shared_outer_name', 0x714856, b'user_to_scheduled_cancel'),
    ('reader_n', 0x57cfe9, b'n'),
    ('reader_t', 0x57d1af, b't'),
    ('expected_type', 0x58d27d, b'struct ScheduledCancel'),
    ('duplicate_template', 0x1e0fd5, b'\x11duplicate field `\xc0'),
    ('low_writer_t', 0x3f65bf, b't'),
    ('low_writer_n', 0x3f6566, b'n'),
    ('shared_writer_t', 0x70d608, b't'),
    ('shared_writer_n', 0x70d907, b'n'),
    ('time_name', 0x209e8c, b'Time'),
)


def verify_digest(data):
    if len(data) != TARGET_SIZE or hashlib.sha256(data).hexdigest() != TARGET_SHA256:
        raise ValueError('node 94 artifact size or SHA-256 mismatch')


def file_offset(data, secs, va, size, executable=False):
    """Resolve one complete range through exactly one file-backed section."""
    if va < 0 or size <= 0:
        raise ValueError('invalid address range')
    candidates = [s for s in secs if s['type'] != 8
                  and (not executable or s['flags'] & 4)
                  and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(candidates) != 1:
        raise ValueError(f'unmapped or ambiguous range {va:#x}+{size:#x}')
    section = candidates[0]
    offset = section['offset'] + va - section['address']
    if offset < 0 or offset + size > len(data):
        raise ValueError('resolved range outside file')
    return section, offset


def take(data, secs, va, size, executable=False):
    _, offset = file_offset(data, secs, va, size, executable)
    return bytes(data[offset:offset + size])


def bind_extents(data, secs, entries, records):
    table = {row['start']: row for row in entries}
    if len(table) != len(entries):
        raise ValueError('ambiguous unwind index start')
    wanted = {start for _, start in FUNCTIONS}
    matches = [row for row in records if row['start'] in wanted]
    selected = {row['start']: row for row in matches}
    if len(matches) != len(FUNCTIONS) or len(selected) != len(FUNCTIONS):
        raise ValueError('missing or duplicate selected FDE')
    result = []
    for name, start in FUNCTIONS:
        row, entry = selected[start], table.get(start)
        if entry is None or row['fde'] != entry['fde'] or row['end'] <= start:
            raise ValueError('FDE does not match unwind index')
        if row['end'] > entry['next_index_upper_bound']:
            raise ValueError('FDE exceeds following indexed start')
        sec, off = file_offset(data, secs, start, row['end'] - start, executable=True)
        result.append({
            'name': name, 'start': start, 'end': row['end'],
            'fde': row['fde'], 'cie': row['cie'], 'lsda': row['lsda'],
            'section': sec['name'], 'offset': off,
            'sha256': hashlib.sha256(data[off:off + row['end'] - start]).hexdigest(),
        })
    return result


def own_at(ranges, site, length):
    owners = [row for row in ranges if row['start'] <= site and site + length <= row['end']]
    if len(owners) != 1:
        raise ValueError(f'site {site:#x} is not in one selected FDE')
    return owners[0]['name']


def check_windows(data, secs, ranges):
    rows = []
    for name, va, expected_hex in WINDOWS:
        expected = bytes.fromhex(expected_hex)
        section, offset = file_offset(data, secs, va, len(expected), executable=True)
        observed = bytes(data[offset:offset + len(expected)])
        if observed != expected:
            raise ValueError(f'changed window {name} at {va:#x}')
        owner = 'prior-boundary' if name.startswith('boundary_') else own_at(ranges, va, len(expected))
        rows.append((name, owner, hex(va), hex(offset), section['name'], observed.hex()))
    return rows


def rel32(data, secs, site, opcode):
    raw = take(data, secs, site, 5, executable=True)
    if raw[0] != opcode or opcode not in (0xe8, 0xe9):
        raise ValueError(f'unexpected relative transfer at {site:#x}')
    return raw, site + 5 + struct.unpack_from('<i', raw, 1)[0]


def conditional(data, secs, site, condition):
    prefix = take(data, secs, site, 2, executable=True)
    if 0x70 <= prefix[0] <= 0x7f:
        raw = prefix
        found = prefix[0] & 15
        length = 2
        displacement = struct.unpack_from('<b', raw, 1)[0]
    elif prefix[0] == 0x0f and 0x80 <= prefix[1] <= 0x8f:
        raw = take(data, secs, site, 6, executable=True)
        found = prefix[1] & 15
        length = 6
        displacement = struct.unpack_from('<i', raw, 2)[0]
    else:
        raise ValueError(f'not a selected conditional branch at {site:#x}')
    if found != condition:
        raise ValueError(f'changed branch condition at {site:#x}')
    return raw, site + length + displacement, site + length


def collect_edges(data, secs, ranges):
    rows = []
    for label, site, op, expected, scope in EDGES:
        raw, dest = rel32(data, secs, site, op)
        if dest != expected:
            raise ValueError(f'changed call destination at {site:#x}')
        owner = 'prior-boundary' if scope == 'prior-boundary' else own_at(ranges, site, 5)
        _, off = file_offset(data, secs, site, 5, executable=True)
        rows.append((label, scope, owner, hex(site), hex(off), raw.hex(), hex(dest)))
    return rows


def collect_branches(data, secs, ranges):
    rows = []
    for label, site, condition, expected, scope in BRANCHES:
        raw, dest, fallthrough = conditional(data, secs, site, condition)
        if dest != expected:
            raise ValueError(f'changed branch destination at {site:#x}')
        owner = 'prior-boundary' if scope == 'prior-boundary' else own_at(ranges, site, len(raw))
        if scope != 'prior-boundary' and own_at(ranges, dest, 1) != owner:
            raise ValueError(f'branch target leaves selected FDE at {site:#x}')
        _, off = file_offset(data, secs, site, len(raw), executable=True)
        rows.append((label, scope, owner, hex(site), hex(off), raw.hex(), hex(dest), hex(fallthrough)))
    return rows


def collect_leas(data, secs, ranges):
    rows = []
    for name, site, expected in LEAS:
        raw = take(data, secs, site, 7, executable=True)
        if raw[0] & 0xf0 != 0x40 or raw[1] != 0x8d or raw[2] & 0xc7 != 0x05:
            raise ValueError(f'changed RIP-relative LEA at {site:#x}')
        dest = site + 7 + struct.unpack_from('<i', raw, 3)[0]
        if dest != expected:
            raise ValueError(f'changed LEA destination at {site:#x}')
        _, off = file_offset(data, secs, site, 7, executable=True)
        owner = 'prior-boundary' if name == 'rmp_outer_field_boundary' else own_at(ranges, site, 7)
        rows.append((name, owner, hex(site), hex(off), raw.hex(), hex(dest)))
    return rows


def collect_literals(data, secs):
    rows = []
    for name, va, expected in LITERALS:
        sec, off = file_offset(data, secs, va, len(expected))
        raw = bytes(data[off:off + len(expected)])
        if raw != expected:
            raise ValueError(f'changed literal {name}')
        rows.append((name, hex(va), hex(off), sec['name'], len(raw), raw.hex()))
    return rows


def inline_duplicate_keys(data, secs, ranges):
    """Reconstruct overlapping immediate stores in each duplicate-key arm."""
    rows = []
    for name, length_site, suffix_site, prefix_site in (
        ('rmp_map_duplicate_key', 0x3679eee, 0x3679f02, 0x3679f10),
        ('rmp_sequence_duplicate_key', 0x36afb25, 0x36afb39, 0x36afb47),
        ('map_duplicate_key', 0x363f1f9, 0x363f20d, 0x363f21b),
        ('sequence_duplicate_key', 0x36c436e, 0x36c4382, 0x36c4390),
    ):
        length_op = take(data, secs, length_site, 5, executable=True)
        suffix = take(data, secs, suffix_site, 10, executable=True)
        prefix = take(data, secs, prefix_site, 10, executable=True)
        if length_op[0] != 0xbf or suffix[:2] != b'\x48\xb9' or prefix[:2] != b'\x48\xb9':
            raise ValueError('changed duplicate-key instruction form')
        length = struct.unpack_from('<I', length_op, 1)[0]
        if length != 13 or suffix[2:5] != prefix[7:10]:
            raise ValueError('inconsistent overlapping duplicate-key stores')
        value = bytearray(length)
        value[5:13] = suffix[2:10]
        value[0:8] = prefix[2:10]
        if value != b'duplicate key':
            raise ValueError('changed duplicate-key text')
        owner = own_at(ranges, length_site, 5)
        rows.append((name, owner, hex(length_site), hex(suffix_site), hex(prefix_site),
                     length, bytes(value).hex(), bytes(value).decode('ascii')))
    return rows


def relative_relocation(data, secs, slot, expected):
    sections = [s for s in secs if s['name'] == '.rela.dyn' and s['type'] != 8]
    if len(sections) != 1 or sections[0]['size'] % 24:
        raise ValueError('invalid relocation section')
    section = sections[0]
    found = []
    for pos in range(section['offset'], section['offset'] + section['size'], 24):
        offset, info, addend = struct.unpack_from('<QQq', data, pos)
        if offset == slot:
            found.append((offset, info, addend, pos))
    if len(found) != 1 or found[0][1] != 8 or found[0][2] != expected:
        raise ValueError('changed or ambiguous relative relocation')
    return found[0]


def collect_helper_relocations(data, secs, ranges):
    """Resolve the selected formatter and prefixed-hex indirect calls."""
    rows = []
    relocs = []
    for name, site, slot, target in (
        ('time_date_format', 0x43e3629, 0x576f560, 0x151f240),
        ('time_clock_format', 0x43e3659, 0x576f568, 0x15204a0),
        ('key_prefixed_hex', 0x43f57a8, 0x5773120, 0x29ed380),
    ):
        raw = take(data, secs, site, 6, executable=True)
        if raw[:2] != b'\xff\x15':
            raise ValueError(f'changed indirect call at {site:#x}')
        actual_slot = site + 6 + struct.unpack_from('<i', raw, 2)[0]
        if actual_slot != slot:
            raise ValueError(f'changed indirect slot at {site:#x}')
        reloc = relative_relocation(data, secs, slot, target)
        _, off = file_offset(data, secs, site, 6, executable=True)
        rows.append((name, own_at(ranges, site, 6), hex(site), hex(off),
                     raw.hex(), hex(slot), hex(target), hex(reloc[3])))
        relocs.append(reloc)
    return rows, relocs


def entry_table(data, secs, ranges):
    base = 0x59224c
    raw = take(data, secs, base, 33 * 4)
    rows = []
    for index in range(33):
        displacement = struct.unpack_from('<i', raw, index * 4)[0]
        dest = base + displacement
        if own_at(ranges, dest, 1) != 'json_map':
            raise ValueError('dispatch target outside JSON map FDE')
        character = 0x5b + index
        if character == 0x5b and dest != 0x363efa0:
            raise ValueError('changed array dispatch')
        if character == 0x7b and dest != 0x363f0a6:
            raise ValueError('changed map dispatch')
        _, off = file_offset(data, secs, base + index * 4, 4)
        rows.append((hex(character), hex(base + index * 4), hex(off), raw[index * 4:index * 4 + 4].hex(), hex(dest)))
    return rows


def field_count(count, tag):
    if not 0 <= count < (1 << 64) or not 0 <= tag < (1 << 32):
        raise ValueError('count or tag outside unsigned storage width')
    # setne(count) + 1 - carry(tag < 1), modulo 32 bits.
    carry = int(tag < 1)
    return (int(count != 0) - 0xffffffff - carry) & 0xffffffff


def fields(count, tag):
    number = field_count(count, tag)
    names = (['t'] if tag else []) + (['n'] if count else [])
    if number != len(names):
        raise ValueError('field-count model inconsistency')
    return names


def event_model(events):
    """Model only already-decoded key events, not the JSON grammar."""
    seen = set()
    tag = count = 0
    for event in events:
        if event == 'unknown':
            return ('delegate-unknown', tag, count)
        if event not in ('t-null', 't-present', 'n-zero', 'n-nonzero'):
            raise ValueError('unsupported event')
        key = event[0]
        if key in seen:
            return ('duplicate-' + key, tag, count)
        seen.add(key)
        if event == 't-present':
            tag = 1
        elif event == 'n-nonzero':
            count = 1
    return ('accepted', tag, count)


def fixarray_model(length):
    """Model the fixarray branch assuming child reads succeed, not a decoder."""
    if not isinstance(length, int) or not 0 <= length <= 15:
        raise ValueError('fixarray length outside marker width')
    time_action = 'default' if length == 0 else 'delegate'
    count_action = 'default' if length < 2 else 'delegate'
    remainder = max(length - 2, 0)
    result_tag = 4 if remainder else 9
    return time_action, count_action, remainder, result_tag


def tsv(header, rows):
    stream = io.StringIO(newline='')
    writer = csv.writer(stream, delimiter='\t', lineterminator='\n')
    writer.writerow(header)
    writer.writerows(rows)
    return stream.getvalue().encode('utf-8')


def generate(data):
    verify_digest(data)
    secs, entries = unwind_index(data)
    _, records = eh_frame_records(data, secs)
    ranges = bind_extents(data, secs, entries, records)
    windows = check_windows(data, secs, ranges)
    edges = collect_edges(data, secs, ranges)
    branches = collect_branches(data, secs, ranges)
    refs = collect_leas(data, secs, ranges)
    literals = collect_literals(data, secs)
    inline_text = inline_duplicate_keys(data, secs, ranges)
    jump = entry_table(data, secs, ranges)
    relocation = relative_relocation(data, secs, 0x56dd068, 0x3432030)
    indirect, helper_relocations = collect_helper_relocations(data, secs, ranges)
    function_rows = [(r['name'], hex(r['start']), hex(r['end']), r['end'] - r['start'],
                      hex(r['fde']), hex(r['cie']), '-' if r['lsda'] is None else hex(r['lsda']),
                      r['section'], hex(r['offset']), r['sha256']) for r in ranges]
    cases = []
    for tag in (0, 1, 0xffffffff):
        for count in (0, 1, 0xffffffffffffffff):
            keys = fields(count, tag)
            cases.append((hex(tag), hex(count), field_count(count, tag), ','.join(keys) or '-',
                          'fields-present' if keys else 'empty', 'static-model'))
    event_cases = [(), ('t-null',), ('t-null', 't-null'), ('t-present', 't-null'),
                   ('n-zero',), ('n-zero', 'n-nonzero'), ('t-null', 'n-zero'),
                   ('n-nonzero', 't-present'), ('unknown',)]
    events = []
    for seq in event_cases:
        result, tag, count = event_model(seq)
        events.append((','.join(seq) or '-', result, hex(tag), hex(count),
                       ','.join(fields(count, tag)) or '-', 'static-model'))
    fixarrays = []
    for length in range(16):
        time_action, count_action, remainder, result = fixarray_model(length)
        fixarrays.append((hex(0x90 + length), length, time_action, count_action,
                          remainder, result, 'static-model'))
    summary = {
        'artifact_sha256': TARGET_SHA256,
        'artifact_size': len(data),
        'coordinates': 'linked ELF virtual address and file offset',
        'scope': 'selected JSON and MessagePack scheduled-cancel read and state-hash writer branches',
        'functions': len(function_rows), 'windows': len(windows),
        'relative_edges': len(edges), 'conditional_branches': len(branches),
        'rip_leas': len(refs), 'literals': len(literals),
        'dispatch_table_entries': len(jump), 'writer_model_cases': len(cases),
        'reader_model_cases': len(events), 'fixarray_model_cases': len(fixarrays),
        'vtable_relocations': 1, 'helper_relocations': len(helper_relocations),
        'fde_warning': 'FDEs are unwind extents, not complete function boundaries or coverage.',
        'model_warning': 'Model cases are inferred from selected code bytes; they are not target executions.',
    }
    output = {
        'functions.tsv': tsv(('role','start_va','end_va_exclusive','size','fde_va','cie_va','lsda_va','section','file_offset','sha256'), function_rows),
        'windows.tsv': tsv(('name','owner','va','file_offset','section','bytes_hex'), windows),
        'edges.tsv': tsv(('name','scope','source_owner','site_va','file_offset','bytes_hex','target_va'), edges),
        'branches.tsv': tsv(('name','scope','source_owner','site_va','file_offset','bytes_hex','taken_va','fallthrough_va'), branches),
        'references.tsv': tsv(('name','source_owner','site_va','file_offset','bytes_hex','target_va'), refs),
        'literals.tsv': tsv(('name','va','file_offset','section','length','bytes_hex'), literals),
        'inline-text.tsv': tsv(('name','source_owner','length_site_va','suffix_site_va','prefix_site_va','length','bytes_hex','ascii'), inline_text),
        'dispatch.tsv': tsv(('input_byte','entry_va','file_offset','bytes_hex','target_va'), jump),
        'relocation.tsv': tsv(('slot_va','info','addend_va','record_file_offset'),
                              [(hex(row[0]), hex(row[1]), hex(row[2]), hex(row[3])) for row in [relocation] + helper_relocations]),
        'indirect.tsv': tsv(('name','source_owner','site_va','file_offset','bytes_hex','slot_va','relocation_addend_va','relocation_file_offset'), indirect),
        'writer-cases.tsv': tsv(('option_tag','count','field_count','field_order','shape','kind'), cases),
        'reader-cases.tsv': tsv(('events','result','option_tag','count','would_write_fields','kind'), events),
        'fixarray-cases.tsv': tsv(('marker','length','time_action','count_action','remaining','result_tag','kind'), fixarrays),
        'summary.json': (json.dumps(summary, indent=2, sort_keys=True) + '\n').encode(),
    }
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    with BINARY.open('rb') as source:
        with mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as data:
            outputs = generate(data)
    args.out.mkdir(parents=True, exist_ok=True)
    for name in sorted(outputs):
        (args.out / name).write_bytes(outputs[name])
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, struct.error) as error:
        print(f'abci_cancel_root94: {error}', file=sys.stderr)
        raise SystemExit(1)
