"""Static, digest-bound analysis of the configuration-name field path in node 94.

This is a closed set of byte-pattern readers, not a general x86 decoder. It
reads the captured ELF but never invokes or executes the captured program.
"""
import argparse
import copy
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records

DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
ENTRIES = {
    0x13d28e0: 'configuration_initializer',
    0x144b150: 'path_and_format_selector',
    0x149e710: 'document_reader',
    0x14889f0: 'unknown_fields_collector',
    0x13bd490: 'binary_marker_reader',
    0x13abf40: 'binary_field_visitor',
    0x13aa6e0: 'binary_optional_field_reader',
    0x13c75e0: 'binary_key_classifier',
    0x14baf90: 'object_reader',
    0x14a2870: 'field_visitor',
    0x13c71c0: 'borrowed_key_classifier',
    0x13c84c0: 'owned_key_classifier',
}

class EvidenceError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


def verify_digest(data):
    require(hashlib.sha256(data).hexdigest() == DIGEST, 'target digest mismatch')


def file_offset(secs, va, size, data_size):
    require(va >= 0 and size > 0 and va + size >= va, 'invalid byte range')
    candidates = [s for s in secs if s['type'] != 8 and s['flags'] & 2
                  and s['address'] <= va and va + size <= s['address'] + s['size']]
    require(len(candidates) == 1, 'range is not uniquely file backed')
    s = candidates[0]
    offset = s['offset'] + va - s['address']
    require(offset >= 0 and offset + size <= data_size, 'range outside file')
    return offset


class Image:
    def __init__(self, data):
        verify_digest(data)
        self.data = data
        self.secs = sections(data)
        _, self.fdes = eh_frame_records(data, self.secs)
        self.patches = {}
        self.relas = {}
        for sec in self.secs:
            if sec['type'] != 4:
                continue
            require(sec['size'] % 24 == 0, 'unaligned RELA section')
            for pos in range(sec['offset'], sec['offset'] + sec['size'], 24):
                slot, info, addend = struct.unpack_from('<QQq', data, pos)
                if slot in self.relas:
                    raise EvidenceError('duplicate relocation slot')
                self.relas[slot] = (info, addend)

    def offset(self, va, size):
        return file_offset(self.secs, va, size, len(self.data))

    def read(self, va, size):
        pos = self.offset(va, size)
        result = bytearray(self.data[pos:pos + size])
        for patch_va, replacement in self.patches.items():
            start = max(va, patch_va)
            end = min(va + size, patch_va + len(replacement))
            if start < end:
                result[start - va:end - va] = replacement[start - patch_va:end - patch_va]
        return bytes(result)

    def with_patch(self, va, replacement):
        out = copy.copy(self)
        out.patches = dict(self.patches)
        out.patches[va] = replacement
        return out

    def fde(self, start):
        rows = [f for f in self.fdes if f['start'] == start]
        require(len(rows) == 1 and rows[0]['end'] > start, 'missing, duplicate or empty FDE')
        return rows[0]

    def relative(self, slot):
        entry = self.relas.get(slot)
        require(entry is not None and entry[0] == 8, 'missing or invalid RELATIVE relocation')
        return entry[1]

    def dynamic_symbol(self, slot):
        entry = self.relas.get(slot)
        require(entry is not None and entry[0] & 0xffffffff == 6, 'missing GLOB_DAT relocation')
        ds = [s for s in self.secs if s['name'] == '.dynsym' and s['type'] != 8]
        st = [s for s in self.secs if s['name'] == '.dynstr' and s['type'] != 8]
        require(len(ds) == len(st) == 1, 'missing or duplicate dynamic symbol sections')
        index = entry[0] >> 32
        require(index * 24 + 24 <= ds[0]['size'], 'symbol outside dynamic table')
        name_off = struct.unpack_from('<I', self.data, ds[0]['offset'] + index * 24)[0]
        require(name_off < st[0]['size'], 'dynamic symbol name outside table')
        start = st[0]['offset'] + name_off
        end = self.data.find(b'\0', start, st[0]['offset'] + st[0]['size'])
        require(end >= 0, 'unterminated dynamic symbol name')
        return self.data[start:end].decode('ascii')


def signed(raw):
    return int.from_bytes(raw, 'little', signed=True)


def hexva(value):
    return hex(value)


def exact(image, va, pattern):
    expected = bytes.fromhex(pattern)
    actual = image.read(va, len(expected))
    require(actual == expected, 'changed byte pattern at ' + hex(va))
    return actual


def rel32(image, site, prefix):
    prefix = bytes.fromhex(prefix)
    raw = image.read(site, len(prefix) + 4)
    require(raw.startswith(prefix), 'unexpected relative operand at ' + hex(site))
    return site + len(raw) + signed(raw[-4:])


def branch(image, label, site, expected):
    raw = exact(image, site, expected)
    require((len(raw) == 2 and (0x70 <= raw[0] <= 0x7f or raw[0] == 0xeb)) or
            (len(raw) == 5 and raw[0] == 0xe9) or
            (len(raw) == 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f),
            'unsupported branch pattern')
    delta = signed(raw[-1:] if len(raw) == 2 else raw[-4:])
    return dict(label=label, site=site, file_offset=image.offset(site, len(raw)),
                bytes=raw.hex(), fallthrough=site + len(raw), target=site + len(raw) + delta)


def call(image, label, site, expected, indirect=False):
    raw = exact(image, site, expected)
    require(raw[:2] == b'\xff\x15' if indirect else raw[:1] == b'\xe8', 'unsupported call')
    target = site + len(raw) + signed(raw[-4:])
    result = dict(label=label, site=site, file_offset=image.offset(site, len(raw)),
                  bytes=raw.hex(), target=target, kind='indirect-slot' if indirect else 'direct')
    if indirect and target in image.relas and image.relas[target][0] == 8:
        result['relative_addend'] = image.relative(target)
    elif indirect and target in image.relas and image.relas[target][0] & 0xffffffff == 6:
        result['symbol'] = image.dynamic_symbol(target)
    return result


# These selected windows are the local evidence for the documented flow. Each
# starts at a manually inspected instruction boundary; no scan resynchronizes.
WINDOWS = {
    'initializer_config_slot': (0x13d28ef, '488b1d32c039048b435085c00f85e40100004883c318'),
    'initializer_field_argument': (0x13d2901, '4883c31848895c2418488d057f7700004889442420'),
    'initializer_template': (0x13d2916, '488d35e8aae0fe4889e7488d542418ff1515b73904'),
    'initializer_result_dispatch': (0x13d2935, '488d0dfc412904488d7c24184889dee8078807004c8b7c24184983ff030f84c9010000488d742420488dbc2480020000ba6002'),
    'initializer_default_name_slot': (0x13d2a7c, '49c7462000000000'),
    'initializer_default_result': (0x13d2a96, '4531ff4d893e'),
    'initializer_result_copy': (0x13d2aa7, '498d7e08488db42480020000ba60020000ff1522b53904'),
    'initializer_error': (0x13d2b21, '488b4424204889842480020000488d3d6844e4fe488d0d1c4429044c8d050d402904488d942480020000be2b000000ff15f2b439040f0b'),
    'selector_initial_predicate': (0x144b169, '4889f74889d6ff157338320484c0743f'),
    'selector_transformed_predicate': (0x144b179, '4c8d7424584c89f74c89e64c89faff159b443204488b7c2460488b742468ff154b38320484c07440'),
    'selector_absent_tag': (0x144b1b8, '41bd020000004c892b4c897308'),
    'selector_error_result': (0x144b63c, '4c89730848c70303000000'),
    'selector_binary_read': (0x144b32f, '488b742460488b542468488d7c2420ff15fc4232044c8b7c24204c89f848f7d80f8106030000'),
    'selector_extension_length': (0x144b2c4, '4883c2fc4839ca0f854c010000'),
    'selector_extension_r': (0x144b2d1, '0fb65408018d72bf4080fe1a400f92c640c0e6054008d64080fe720f852b010000'),
    'selector_extension_m': (0x144b2f2, '0fb65408028d72bf4080fe1a400f92c640c0e6054008d64080fe6d0f850a010000'),
    'selector_extension_p': (0x144b313, '0fb64408038d48bf80f91a0f92c1c0e10508c180f9700f85ee000000'),
    'selector_non_rmp_read': (0x144b41d, '488b742460488b542468488d7c2420ff15164232044c8b7c24204c89f848f7d80f81f6000000'),
    'selector_document_call': (0x144b539, '4c8b642428488b4424304c8964242048894424280f57c00f114424304c896424404889442448488dbc2410010000488d742420e89f3105004c8bac24100100004983fd020f85d6010000'),
    'selector_binary_call': (0x144b68a, '488dbc2410010000488d742420ba01000000e8ef1df7ff4c8bac24100100004983fd020f85a6000000'),
    'selector_success_copy': (0x144b759, '4c8bb42418010000488db42420010000488dbc2478030000ba58020000ff1564283204'),
    'binary_marker_to_visitor': (0x13bd823, '0fb746226685c00f840704000066ffc8668946220f847b0300004889fb4989f64889742420896c2428488dbc2498020000488d742420e8e2e6feff4c8bbc24980200000f108424a00200000f290424'),
    'binary_visitor_counted_key': (0x13ac2c0, '488b45184885c00f845d05000048ffc80fb60e48ffc6488975104889451889ca4829d00f8276020000488d0c1648894d1048894518488d7c2470e8e1b20100e9d2060000'),
    'binary_visitor_validated_key': (0x13ac5d4, '488dbc24f00200004c89fe4889dae8f9af010080bc24f0020000007469'),
    'binary_visitor_optional_sentinels': (0x13abfb0, '48c78424700600000200000048c784249006000002000000'),
    'binary_field_dispatch': (0x13aca29, '8d42ea80fa160fb6c0b9180000000f43c80fb6c1488d0d5c30e6fe486304814801c848b90100000000000080488b6c2468ffe0'),
    'binary_selected_field': (0x13ad678, '83bc2490060000020f85dd410000498b2c24488dbc24f00200004889eee846d0ffff8b8424f0020000410f1006410f104e100f298424400800000f298c245008000083f8010f84bc3200000f288424400800000f288c24500800000f298c24a00600000f29842490060000'),
    'binary_absent_default': (0x13ada2c, '48c784241003000000000000'),
    'binary_default_select': (0x13adee0, '488b84249006000048898424980200004883f8020f94442403488d842490060000488d8c2410030000480f44c10f10000f1048100f294424700f298c2480000000'),
    'binary_unknown_field_collection': (0x13adf56, '488dbc2400010000488db42410020000e865a70d000fb68424000100003c090f8575040000'),
    'binary_publish_field': (0x13ae0cf, '0f284424700f288c24800000000f298c24300100000f29842420010000488db42400010000bab80000004c89f7ff15defe3b04'),
    'binary_collector_failure': (0x13ae3f0, '0f108424010100000f108c24100100000f118c24ff0100000f298424f00100000f108424ff010000'),
    'binary_duplicate_name': (0x13b1863, '488d05d350e6fe488944247048c744247806000000'),
    'binary_duplicate_template': (0x13b189a, '488d3534f7e2fe'),
    'binary_option_entry': (0x13aa6e8, '0fb646200fb64e21c64620013dc00000000f848000000083f8010f8586000000'),
    'binary_option_end_of_input': (0x13aa730, 'c6430800488d05bdc12b044889431048c70301000000'),
    'binary_option_input_marker': (0x13aa771, '3cc07308241f89c1b0a0eb11750f0f57c00f1103'),
    'binary_option_null': (0x13aa77f, '0f57c00f11034889d84883c4205bc3'),
    'binary_option_result': (0x13aa78e, '884620884e214889e7ba01000000e8af440100803c2409751e488b442418488943200f104424080f11431048c743080100000031c0eb160f1004240f104c24100f114b180f114308b8010000004889034889d84883c4205bc3'),
    'binary_key_dispatch': (0x13c75e0, '4889f8488d4afa4883f91b0f87b20e0000488d3db8f4e4fe48630c8f4801f9ffe1'),
    'binary_key_unknown': (0x13c84a3, 'c640080f488970104889501848c70000000000c3'),
    'document_reader_entry': (0x149e74f, 'c6442448804889e6e834c80100833b020f848e000000'),
    'document_trailing_loop': (0x149e778, '488b442420488b4c24284839c1736c488b54241848f7d848ffc148be00260000010000000f1f40000fb67c0aff4883ff20771d480fa3fe731748894c2428488d3c0848ffc748ffc14883ff0175daeb2b'),
    'document_trailing_error': (0x149e7c8, '48c7442450160000004889e7488d742450e8d20500004889430848c70302000000488d7c2468e8cd090100'),
    'object_reader_brace_depth': (0x14bb005, '83ff7b0f854c010000410fb64e4884c90f8466010000fec941884e480f844c0100004885c00f845e01000049894628488dbc24780200004c89f6e82c78feff410fb646483cff0f844a010000fec041884648'),
    'object_result_success': (0x14bb0ad, '4c8b742410488db42488020000488d7b10ba58020000ff15172f2b044c89234c897308'),
    'object_result_choice': (0x14bb09d, '4c8b6424084983fc02743a4d85ff75674c8b742410'),
    'object_both_errors': (0x14bb0e2, '488b7c24104d85ff74564989fc498b074883f801742b4885c07532'),
    'object_closing_error_drop': (0x14bb114, '488d7c2408e8a240ffff4c89ff'),
    'object_result_error': (0x14bb142, '4c89f6e886bff8ff4889430848c70302000000'),
    'visitor_optional_sentinels': (0x14a28e6, '48c78424f00500000200000048c784241006000002000000'),
    'visitor_key_representation': (0x14a2aa4, '488b9424f0000000f6c1017412'),
    'visitor_key_calls': (0x14a2ab1, '488dbc24c00200004889c6e8ff59f2ffeb10488dbc24c00200004889c6e8ed46f2ff'),
    'visitor_special_tag_first': (0x14a2ad3, '0fb68c24c002000080f92e0f842f350000'),
    'visitor_special_tag_second': (0x14a2b13, '80f92f0f84f0340000'),
    'visitor_tag_dispatch': (0x14a2b40, '8d51ea80f9160fb6d2be180000000f42d60f298424e00700000fb6d2488d35798cd7fe486314964801f2ffe2'),
    'visitor_unknown_key_staged': (0x14a2e1e, '8b9424a00100008bb424a3010000488dbc245105000089770389170f288424e00700000f11470f888c2450050000'),
    'visitor_unknown_value': (0x14a3505, '4883fe3a0f85cd5800004885c00f84ab6a000049894528488dbc24e00000004c89eee8245f01000fb68424e00000003c160f84813f0000'),
    'visitor_unknown_append': (0x14a35a6, '4c3bbc24a8010000750e488dbc24a8010000ff15aab12c04488b8424b00100004c89f948c1e1060f288424c00200000f288c24d00200000f289424e00200000f289c24f00200000f115c08300f115408200f114c08100f11040849ffc74c89bc24b8010000'),
    'visitor_unknown_collect': (0x14a538c, '488dbc24e0000000488db424a80100004c89642440e84a36feff4c8bac24e800000083bc24e0000000010f8593000000'),
    'unknown_collector_loop': (0x1488a40, '4983c6404883c5c04885ed0f84db00000041803e1674e94c89ff4c89f6e8ce5001004c8b642448488b5c24504c3b6424280f84f1000000498d7620'),
    'unknown_collector_value': (0x1488a83, 'e81842010048b8050000000000008048394424480f84b0000000'),
    'unknown_collector_insert': (0x1488b05, 'e85616040048b8050000000000008048394424480f8421ffffff4c89ffe8d960ffff'),
    'unknown_collector_success': (0x1488b2c, '488b4424204c8b742408498946180f10442410410f11460849c70600000000'),
    'unknown_collector_failure': (0x1488b4d, '4c8b7424504d85e4740e4889df4c89e631d2ff15ab542e044c89f34c8b74240849895e0849c70601000000488d7c2410e83e150500'),
    'visitor_selected_precheck': (0x14a33ed, '83bc2410060000020f85a54f0000498b4d20498b45284839c80f831b3c0000488b1348ffc048f7d90fb67402ff4883fe3a0f8707660000490fa3f60f83e50b000049894528488d340148ffc648ffc04883fe0175d3e9e03b0000'),
    'visitor_selected_parse': (0x14a4013, '4883fe3a0f850e5a00004885c00f84b05d000049894528488dbc24c00200004c89eee8d6dcf9ff488b8c24c0020000488b8424c80200004883f9020f847a350000488d9424c10200000f10420f488d9424200600000f110248898c24100600004889842418060000e9e0000000'),
    'visitor_absent_default': (0x14a4d51, '48c78424e002000000000000'),
    'visitor_default_select': (0x14a5313, '488b8c24100600004989ce4883f902410f94c0488d8c2410060000480f44c80f10010f1049100f298424500500000f298c2460050000'),
    'visitor_publish_copy': (0x14a558b, '0f288424500500000f288c24600500000f298c24100100000f29842400010000488db424e0000000bab80000004c89e7ff151f8a2c04'),
    'visitor_selected_error': (0x14a75ce, '4c896424404c8b6c2460488b6c2458e9f3faffff'),
    'visitor_duplicate_literal': (0x14a83a0, '4c89fb4c89642440488d05ae38d7fe48898424e000000048c78424e800000006000000'),
    'visitor_duplicate_template_arg': (0x14a83e8, '488d3de68bd3fe'),
    'visitor_duplicate_error_jump': (0x14a8478, 'e8e3e2faffe929060000'),
    'visitor_wrong_colon_error': (0x14a9a2b, '4c89fb4c8964244048c78424e000000006000000'),
    'object_depth_error': (0x14bb173, '48c744240818000000e972feffff'),
    'visitor_error_return': (0x14a8aab, '4889430848c70302000000e934d6ffff'),
    'visitor_map_cleanup_gate': (0x14a4394, '0fb644241322842410060000a8010f84fa000000'),
    'visitor_close_failure_result': (0x14a53bc, '488b8424b80200004c89680848c70002000000'),
    'visitor_close_failure_cleanup': (0x14a53ef, '4883bc2450050000004c8b6c2460740d488dbc2458050000e894450300'),
    'borrowed_key_entry': (0x13c71c0, '4889f8488d4afa4883f91b0f87d1030000488d3d68f8e4fe48630c8f4801f9ffe1'),
    'borrowed_key_six': (0x13c71e1, 'b9625f6b65330e0fb77e0481f77973000009cf0f84c4030000b963675f6b330e0fb77e0481f76579000009cf0f858f030000c6002dc3'),
    'borrowed_key_unknown': (0x13c75a2, 'c6000d4889700848895010c3'),
    'owned_key_unknown': (0x13c88df, 'c6030c4c8973084c897b104c897318'),
    'owned_key_entry': (0x13c84c0, '41574156415453504989d64889fb488d42fa4883f81b0f8721040000488d0d3de6e4fe486304814801c8ffe0'),
    'owned_key_six': (0x13c84ec, 'b8625f6b6533060fb74e0481f17973000009c10f841c040000b863675f6b33060fb74e0481f16579000009c10f859e030000c6032de9c8030000'),
}

BRANCHES = [
    ('config_once_pending', 0x13d28fb, '0f85e4010000'),
    ('initializer_loader_error', 0x13d2952, '0f84c9010000'),
    ('initializer_has_value', 0x13d2974, '0f852d010000'),
    ('selector_path_predicate_false', 0x144b177, '743f'),
    ('selector_transformed_predicate_false', 0x144b19f, '7440'),
    ('selector_extension_not_p', 0x144b329, '0f85ee000000'),
    ('selector_binary_read_non_error', 0x144b34f, '0f8106030000'),
    ('selector_binary_parse_non_error', 0x144b6ad, '0f85a6000000'),
    ('selector_read_non_error', 0x144b43d, '0f81f6000000'),
    ('selector_document_non_error', 0x144b57d, '0f85d6010000'),
    ('document_parse_error', 0x149e75f, '0f848e000000'),
    ('document_at_end', 0x149e785, '736c'),
    ('document_byte_above_space', 0x149e7a9, '771d'),
    ('document_byte_not_whitespace', 0x149e7af, '7317'),
    ('document_more_bytes', 0x149e7c4, '75da'),
    ('object_input_exhausted', 0x14bafaf, '7339'),
    ('object_not_open_brace', 0x14bb008, '0f854c010000'),
    ('object_zero_depth', 0x14bb015, '0f8466010000'),
    ('object_depth_decrement_zero', 0x14bb021, '0f844c010000'),
    ('object_depth_increment_overflow', 0x14bb04b, '0f844a010000'),
    ('object_visitor_error', 0x14bb0a6, '743a'),
    ('object_closing_error', 0x14bb0ab, '7567'),
    ('object_no_secondary_error', 0x14bb0ea, '7456'),
    ('binary_zero_depth', 0x13bd82a, '0f8407040000'),
    ('binary_decrement_to_zero', 0x13bd837, '0f847b030000'),
    ('binary_visitor_non_error', 0x13bd883, '7520'),
    ('binary_key_header_exhausted', 0x13ac2c7, '0f845d050000'),
    ('binary_key_body_short', 0x13ac2e3, '0f8276020000'),
    ('binary_key_utf8_ready', 0x13ac5ef, '7469'),
    ('binary_selected_duplicate', 0x13ad680, '0f85dd410000'),
    ('binary_selected_value_error', 0x13ad6bd, '0f84bc320000'),
    ('binary_collector_failure', 0x13adf75, '0f8575040000'),
    ('binary_option_cached_null', 0x13aa6f9, '0f8480000000'),
    ('binary_option_end_of_input', 0x13aa70f, '741f'),
    ('binary_option_raw_nonnull', 0x13aa77d, '750f'),
    ('binary_option_read_error', 0x13aa7a5, '751e'),
    ('visitor_borrowed_key', 0x14a2aaf, '7412'),
    ('visitor_key_not_quote', 0x14a2a57, '0f855d4c0000'),
    ('visitor_field_tag_46', 0x14a2ade, '0f842f350000'),
    ('visitor_field_tag_47', 0x14a2b16, '0f84f0340000'),
    ('unknown_value_error', 0x14a3536, '0f84813f0000'),
    ('unknown_buffer_has_capacity', 0x14a35ae, '750e'),
    ('unknown_collector_done', 0x1488a4b, '0f84db000000'),
    ('unknown_collector_skip_tag', 0x1488a55, '74e9'),
    ('unknown_key_error', 0x1488a71, '0f84f1000000'),
    ('unknown_value_decode_error', 0x1488a97, '0f84b0000000'),
    ('unknown_insert_no_drop', 0x1488b19, '0f8421ffffff'),
    ('unknown_collector_non_error', 0x14a53b6, '0f8593000000'),
    ('selected_duplicate', 0x14a33f5, '0f85a54f0000'),
    ('selected_colon_exhausted', 0x14a3406, '0f831b3c0000'),
    ('selected_colon_above_range', 0x14a341e, '0f8707660000'),
    ('selected_first_non_whitespace', 0x14a3428, '0f83e50b0000'),
    ('selected_not_colon', 0x14a4017, '0f850e5a0000'),
    ('selected_cursor_overflow', 0x14a4020, '0f84b05d0000'),
    ('selected_value_error', 0x14a404e, '0f847a350000'),
    ('selected_value_stored', 0x14a407b, 'e9e0000000'),
    ('close_failure_no_map_to_drop', 0x14a53fd, '740d'),
]

CALLS = [
    ('initializer_to_selector', 0x13d2944, 'e807880700', False),
    ('selector_to_document', 0x144b56c, 'e89f310500', False),
    ('selector_to_binary_marker', 0x144b69c, 'e8ef1df7ff', False),
    ('binary_marker_to_visitor', 0x13bd859, 'e8e2e6feff', False),
    ('binary_visitor_counted_key', 0x13ac2fa, 'e8e1b20100', False),
    ('binary_visitor_validated_key', 0x13ac5e2, 'e8f9af0100', False),
    ('binary_visitor_optional_field', 0x13ad695, 'e846d0ffff', False),
    ('binary_optional_value_boundary', 0x13aa79c, 'e8af440100', False),
    ('binary_unknown_collector_boundary', 0x13adf66, 'e865a70d00', False),
    ('binary_publish_copy_slot', 0x13ae0fc, 'ff15defe3b04', True),
    ('document_to_object', 0x149e757, 'e834c80100', False),
    ('object_to_visitor', 0x14bb03f, 'e82c78feff', False),
    ('visitor_owned_classifier', 0x14a2abc, 'e8ff59f2ff', False),
    ('visitor_borrowed_classifier', 0x14a2ace, 'e8ed46f2ff', False),
    ('visitor_unknown_value_boundary', 0x14a3527, 'e8245f0100', False),
    ('visitor_unknown_collector', 0x14a53a1, 'e84a36feff', False),
    ('unknown_collector_key_boundary', 0x1488a5d, 'e8ce500100', False),
    ('unknown_collector_value_boundary', 0x1488a83, 'e818420100', False),
    ('unknown_collector_insert_boundary', 0x1488b05, 'e856160400', False),
    ('unknown_collector_drop_boundary', 0x1488b22, 'e8d960ffff', False),
    ('visitor_optional_map_boundary', 0x14a4035, 'e8d6dcf9ff', False),
    ('document_error_constructor_boundary', 0x149e7d9, 'e8d2050000', False),
    ('object_close_checker_boundary', 0x14bb075, 'e87651feff', False),
    ('object_drop_success_boundary', 0x14bb119, 'e8a240ffff', False),
    ('visitor_duplicate_error_boundary', 0x14a8478, 'e8e3e2faff', False),
    ('visitor_drop_map_boundary', 0x14a5407, 'e894450300', False),
    ('initializer_formatter_slot', 0x13d2925, 'ff1515b73904', True),
    ('selector_path_predicate_slot', 0x144b16f, 'ff1573383204', True),
    ('selector_path_transform_slot', 0x144b187, 'ff159b443204', True),
    ('selector_transformed_predicate_slot', 0x144b197, 'ff154b383204', True),
    ('selector_binary_read_slot', 0x144b33e, 'ff15fc423204', True),
    ('selector_non_rmp_read_slot', 0x144b42c, 'ff1516423204', True),
    ('visitor_publish_copy_slot', 0x14a55bb, 'ff151f8a2c04', True),
]


def prefix_length(code):
    sentinel = bytes.fromhex('48b80100000000000080')
    if code.startswith(sentinel + bytes.fromhex('48398424')):
        return 18
    if code.startswith(sentinel + bytes.fromhex('48394424')):
        return 15
    if code.startswith(sentinel + bytes.fromhex('488b4c24584839c1')):
        return 18
    if code.startswith(bytes.fromhex('488b44246848398424')):
        return 13
    if code.startswith(bytes.fromhex('4c89642440488b8c24')) and code[13:16] == bytes.fromhex('4885c9'):
        return 16
    if code.startswith(bytes.fromhex('488b4c24604885c9')):
        return 8
    if code.startswith(bytes.fromhex('4d85e4')):
        return 3
    if code.startswith(bytes.fromhex('83bc24')) and code[7] == 2:
        return 8
    raise EvidenceError('unsupported duplicate guard pattern')


def fields(image, base, count, bias, owner):
    rows = []
    for index in range(count):
        slot = base + 4 * index
        entry = base + signed(image.read(slot, 4))
        require(owner['start'] <= entry < owner['end'], 'field arm outside visitor')
        body = image.read(entry, 130)
        guard_len = prefix_length(body)
        require(body[guard_len:guard_len + 2] == b'\x0f\x85', 'expected duplicate branch')
        dupe_site = entry + guard_len
        dupe = dupe_site + 6 + signed(body[guard_len + 2:guard_len + 6])
        require(owner['start'] <= dupe < owner['end'], 'duplicate arm outside visitor')
        d = image.read(dupe, 36)
        prefix = bytes.fromhex('4c89fb4c89642440')
        short_prefix = bytes.fromhex('4c89fb')
        if d.startswith(prefix):
            n = len(prefix)
        elif d.startswith(short_prefix):
            n = len(short_prefix)
        else:
            raise EvidenceError('unsupported duplicate entry')
        require(d[n:n + 3] == bytes.fromhex('488d05') and
                d[n + 7:n + 15] == bytes.fromhex('48898424e0000000') and
                d[n + 15:n + 23] == bytes.fromhex('48c78424e8000000'), 'duplicate literal pattern')
        literal = dupe + n + 7 + signed(d[n + 3:n + 7])
        length = int.from_bytes(d[n + 23:n + 27], 'little')
        require(0 < length <= 128, 'invalid field literal length')
        value = image.read(literal, length)
        require(all(0x20 <= c < 0x7f for c in value), 'non-ascii field diagnostic')
        # Restrict the search to the distinctive load/compare/BT sequence.
        marker = bytes.fromhex('0fb67402ff4883fe3a0f87')
        positions = [p for p in range(len(body)) if body.startswith(marker, p)]
        require(len(positions) == 1, 'missing or ambiguous colon-scanner pattern')
        p = positions[0]
        require(body[p + 15:p + 21] == bytes.fromhex('490fa3f60f83'), 'missing whitespace branch')
        upper_site = entry + p + 9
        bad_upper = upper_site + 6 + signed(body[p + 11:p + 15])
        colon_site = entry + p + 19
        colon = colon_site + 6 + signed(body[p + 21:p + 25])
        require(owner['start'] <= colon < owner['end'] and owner['start'] <= bad_upper < owner['end'],
                'colon branch outside visitor')
        handler = image.read(colon, 120)
        require(handler[:6] == bytes.fromhex('4883fe3a0f85') and
                handler[10:15] == bytes.fromhex('4885c00f84') and
                handler[19:23] == bytes.fromhex('49894528'), 'unsupported colon-handler pattern')
        wrong_colon = colon + 10 + signed(handler[6:10])
        overflow = colon + 19 + signed(handler[15:19])
        pattern = bytes.fromhex('4c89eee8')
        calls = [p for p in range(len(handler)) if handler.startswith(pattern, p)]
        require(len(calls) == 1, 'missing or ambiguous value-parser call')
        cs = colon + calls[0] + 3
        target = rel32(image, cs, 'e8')
        rows.append(dict(index=index, field_tag=index + bias, slot=slot, arm=entry,
                         duplicate_branch=dupe_site, duplicate_arm=dupe,
                         literal_va=literal, literal_length=length, literal=value.decode('ascii'),
                         colon_above=bad_upper, colon_branch=colon_site, colon_arm=colon,
                         wrong_colon=wrong_colon, cursor_overflow=overflow,
                         value_call=cs, value_target=target))
    require(len({r['arm'] for r in rows}) == count, 'duplicate field arms')
    require(len({r['literal'] for r in rows}) == count, 'duplicate field diagnostics')
    raw_names = b''.join(struct.pack('<Q', r['literal_length']) + r['literal'].encode('ascii') for r in rows)
    require(hashlib.sha256(raw_names).hexdigest() ==
            '8f90c7ba41f44683ac5b7edcb46f68aca284524dd0f8db67be82e7f4440d1220',
            'field diagnostic sequence changed')
    return rows


def matcher(image, entry, six, table_site, leaf_branch, leaf_prefix, fallback_branch, fall_tag_site):
    table = rel32(image, table_site, '488d3d' if entry == 0x13c71c0 else '488d0d')
    six_target = table + signed(image.read(table, 4))
    require(six_target == six, 'length-six table target changed')
    leaf = rel32(image, leaf_branch, '0f84')
    leaf_bytes = image.read(leaf, 4 if entry == 0x13c71c0 else 3)
    require(leaf_bytes.startswith(bytes.fromhex(leaf_prefix)), 'success leaf changed')
    tag = leaf_bytes[2]
    require(tag == image.read(fall_tag_site, 3)[2] - 1, 'adjacent tag mismatch')
    fall = rel32(image, fallback_branch, '0f85')
    if entry == 0x13c71c0:
        first = image.read(six + 1, 4) + image.read(six + 13, 2)
        second = image.read(six + 26, 4) + image.read(six + 38, 2)
    else:
        first = image.read(six + 1, 4) + image.read(six + 13, 2)
        second = image.read(six + 26, 4) + image.read(six + 38, 2)
    require(first == b'b_keys' and second == b'cg_key', 'six-byte comparisons changed')
    return dict(entry=entry, table=table, length_six_target=six, first_name=first.decode(),
                first_tag=tag, first_leaf=leaf, second_name=second.decode(),
                second_tag=image.read(fall_tag_site, 3)[2], mismatch_target=fall)


def symbolic_field_paths(image, fde):
    """Extract equality constraints without executing target instructions.

    Only exact encodings in this one switch are admitted. Every successful
    leaf must constrain every byte of its length bucket; contradictory paths
    are discarded. The error/fallback leaf is accounted for separately.
    """
    table = rel32(image, 0x13c75f1, '488d3d')
    minimum = -signed(image.read(0x13c75e6, 1))
    last_index = image.read(0x13c75ea, 1)[0]
    fallback = rel32(image, 0x13c75eb, '0f87')
    paths, failure_paths, visits = [], 0, 0
    for length in range(minimum, minimum + last_index + 1):
        slot = table + 4 * (length - minimum)
        entry = table + signed(image.read(slot, 4))
        require(fde['start'] <= entry < fde['end'], 'binary length entry outside FDE')
        stack = [(entry, None, None, {}, {}, ())]
        while stack:
            pc, reg_index, pending, equal, unequal, trace = stack.pop()
            visits += 1
            require(visits <= 10000, 'binary classifier traversal exceeded bound')
            if pc == fallback:
                failure_paths += 1
                continue
            require(fde['start'] <= pc and pc + 12 <= fde['end'], 'binary predicate outside FDE')
            raw = image.read(pc, 12)
            if raw[:3] == bytes.fromhex('0fb60e'):
                stack.append((pc + 3, 0, None, equal, unequal, trace))
                continue
            if raw[:3] == bytes.fromhex('0fb64e'):
                require(raw[3] < length, 'binary load outside field length')
                stack.append((pc + 4, raw[3], None, equal, unequal, trace))
                continue
            if raw[:2] == bytes.fromhex('83f9'):
                require(reg_index is not None and reg_index < length, 'unbound compared register')
                stack.append((pc + 3, reg_index, (reg_index, raw[2]), equal, unequal, trace))
                continue
            if raw[:2] == bytes.fromhex('803e'):
                stack.append((pc + 3, reg_index, (0, raw[2]), equal, unequal, trace))
                continue
            if raw[:2] == bytes.fromhex('807e'):
                require(raw[2] < length, 'binary comparison outside field length')
                stack.append((pc + 4, reg_index, (raw[2], raw[3]), equal, unequal, trace))
                continue
            if raw[:2] in (bytes.fromhex('0f84'), bytes.fromhex('0f85')) or raw[0] in (0x74, 0x75):
                require(pending is not None, 'binary branch without a comparison')
                if raw[0] == 0x0f:
                    width, taken_equal = 6, raw[1] == 0x84
                    target = pc + width + signed(raw[2:6])
                else:
                    width, taken_equal = 2, raw[0] == 0x74
                    target = pc + width + signed(raw[1:2])
                index, value = pending
                for dst, want_equal in ((target, taken_equal), (pc + width, not taken_equal)):
                    eq, ne = dict(equal), dict(unequal)
                    if want_equal:
                        if (index in eq and eq[index] != value) or value in ne.get(index, ()):
                            continue
                        eq[index] = value
                    else:
                        if eq.get(index) == value:
                            continue
                        ne[index] = ne.get(index, frozenset()) | {value}
                        if len(ne[index]) == 256:
                            continue
                    item = (pc, index, value, want_equal)
                    stack.append((dst, reg_index, None, eq, ne, trace + (item,)))
                continue
            if raw[:3] == bytes.fromhex('c64008'):
                require(raw[4:] == bytes.fromhex('48c70000000000c3'), 'binary success leaf changed')
                require(set(equal) == set(range(length)), 'success leaf does not constrain whole field')
                name = bytes(equal[i] for i in range(length))
                require(all(0x20 <= c < 0x7f for c in name), 'non-ascii binary field predicate')
                paths.append(dict(name=name.decode('ascii'), tag=raw[3], length=length,
                                  table_slot=slot, entry=entry, success=pc,
                                  branch_count=len(trace),
                                  comparisons=','.join(hexva(a) + ':' + str(i) + ':' +
                                                       format(v, '02x') + ':' + ('eq' if yes else 'ne')
                                                       for a, i, v, yes in trace)))
                continue
            raise EvidenceError('unsupported binary predicate at ' + hex(pc))
    paths.sort(key=lambda row: (row['tag'], row['name']))
    require(len({r['tag'] for r in paths}) == len(paths), 'duplicate binary success tag')
    require(len({r['name'] for r in paths}) == len(paths), 'duplicate binary field name')
    return paths, dict(length_minimum=minimum, length_maximum=minimum + last_index,
                       table=table, fallback=fallback, failure_paths=failure_paths, visits=visits)


def json_key_probe(image, key, fde=None, owned=False):
    """Evaluate admitted comparison patterns on a byte string, never machine code.

    This closed reader uses two fixed register-encoding forms, not a general
    emulator. Unsupported encodings, reads or paths fail closed. The external
    bcmp edge is modeled only as zero/nonzero byte equality. For the owned
    form, fallback models the normal-return outcome of the external allocator.
    """
    require(isinstance(key, bytes), 'key probe requires bytes')
    fde = fde if fde is not None else image.fde(0x13c84c0 if owned else 0x13c71c0)
    if owned:
        table = rel32(image, 0x13c84dc, '488d0d')
        minimum = -signed(image.read(0x13c84d1, 1))
        last_index = image.read(0x13c84d5, 1)[0]
        out_of_range = rel32(image, 0x13c84d6, '0f87')
        fallback = rel32(image, 0x13c8518, '0f85')
        exact(image, 0x13c88df, 'c6030c4c8973084c897b104c897318')
        exact(image, out_of_range, '4d85f6795031ff4c89f6ff15ab563a04')
        exact(image, 0x13c8952, '0f8564ffffff41bf01000000e970ffffff')
        fallback_tag, fallback_leaf = 12, 0x13c88df
    else:
        table = rel32(image, 0x13c71d1, '488d3d')
        minimum = -signed(image.read(0x13c71c6, 1))
        last_index = image.read(0x13c71ca, 1)[0]
        out_of_range = fallback = rel32(image, 0x13c71cb, '0f87')
        fallback_tag, fallback_leaf = 13, fallback
    if not minimum <= len(key) <= minimum + last_index:
        return dict(tag=fallback_tag, entry=out_of_range, leaf=fallback_leaf,
                    branches='', steps=0, bcmp=False)
    slot = table + 4 * (len(key) - minimum)
    entry = table + signed(image.read(slot, 4))
    pc, zf, steps, trace, used_bcmp = entry, None, 0, [], False
    regs, vectors = {}, {}
    mask64 = (1 << 64) - 1

    def keypart(offset, width):
        require(0 <= offset and offset + width <= len(key), 'JSON key probe read outside input')
        return key[offset:offset + width]

    def integer(offset, width):
        return int.from_bytes(keypart(offset, width), 'little')

    while True:
        steps += 1
        require(steps <= 500, 'JSON key probe exceeded bound')
        require(fde['start'] <= pc < fde['end'], 'JSON key probe left FDE')
        raw = image.read(pc, min(24, fde['end'] - pc))
        if pc == fallback or (owned and pc == out_of_range):
            if owned:
                exact(image, fallback, '4989f44c89f7ff1510573a044885c074774989c74c89e64c89ff4c89f2ff1501573a04c6030c4c8973084c897b104c897318')
            else:
                exact(image, pc, 'c6000d4889700848895010c3')
            return dict(tag=fallback_tag, entry=entry, leaf=fallback_leaf, branches=','.join(trace),
                        steps=steps, bcmp=used_bcmp)
        if pc == 0x13c7217:
            exact(image, pc, '4157415653488d0d21fbe4fe4889d3ba210000004889f74989f74889ce4989c6ff153b713a044c89fe4889da89c14c89f085c95b415e415f0f854d030000c6001dc3')
            data_va = rel32(image, 0x13c721c, '488d0d')
            count = int.from_bytes(image.read(0x13c7227, 4), 'little')
            slot_va = rel32(image, 0x13c7237, 'ff15')
            require(image.dynamic_symbol(slot_va) == 'bcmp' and len(key) == count, 'unexpected bcmp boundary')
            zf = key == image.read(data_va, count)
            used_bcmp = True
            trace.append(hexva(0x13c724f) + (':fallthrough' if zf else ':taken'))
            pc = 0x13c7255 if zf else fallback
            continue
        if owned and pc == 0x13c8526:
            exact(image, pc, '488d0517e8e4feba210000004889f74989f74889c6ff15375e3a044c89fe85c00f8570030000c6031de99a030000')
            data_va = rel32(image, 0x13c8526, '488d05')
            count = int.from_bytes(image.read(0x13c852e, 4), 'little')
            slot_va = rel32(image, 0x13c853b, 'ff15')
            require(image.dynamic_symbol(slot_va) == 'bcmp' and len(key) == count, 'unexpected bcmp boundary')
            zf = key == image.read(data_va, count)
            used_bcmp = True
            trace.append(hexva(0x13c8546) + (':fallthrough' if zf else ':taken'))
            pc = 0x13c854c if zf else fallback
            continue
        if owned and raw[:2] == b'\xc6\x03':
            require(22 <= raw[2] <= 45, 'unexpected owned JSON key leaf')
            jump_width = 5 if raw[3:4] == b'\xe9' else 2
            require(raw[3:4] in (b'\xe9', b'\xeb'), 'unexpected owned key leaf jump')
            jump_end = pc + 3 + jump_width
            require(jump_end + signed(raw[4:3 + jump_width]) == 0x13c88ee, 'owned key leaf target changed')
            return dict(tag=raw[2], entry=entry, leaf=pc, branches=','.join(trace),
                        steps=steps, bcmp=used_bcmp)
        if raw[:2] == b'\xc6\x00':
            require(raw[3:4] == b'\xc3' and 22 <= raw[2] <= 45, 'unexpected JSON key leaf')
            return dict(tag=raw[2], entry=entry, leaf=pc, branches=','.join(trace),
                        steps=steps, bcmp=used_bcmp)
        if raw[:2] in (b'\x0f\x84', b'\x0f\x85') or raw[:1] in (b'\x74', b'\x75'):
            require(zf is not None, 'JSON key branch has no condition')
            if raw[0] == 0x0f:
                width, take_on_zero = 6, raw[1] == 0x84
            else:
                width, take_on_zero = 2, raw[0] == 0x74
            take = zf == take_on_zero
            target = pc + width + signed(raw[width - (1 if width == 2 else 4):width])
            trace.append(hexva(pc) + (':taken' if take else ':fallthrough'))
            pc = target if take else pc + width
            continue

        # Normalize only the exact owned-register forms seen in this pair of
        # FDEs. The two longer canonical forms have their actual widths fixed.
        adjustment = 0
        if owned:
            aliases = (
                ('66480f6ed1','66480f6ed7'), ('66480f6ed8','66480f6ed9'),
                ('660fd7c0','660fd7c8'), ('660fd7c1','660fd7c9'), ('660f6ec8','660f6ec9'),
                ('4881f1','4881f7'), ('4883f1','4883f7'), ('4881c1','4881c7'),
                ('483306','48330e'), ('48330e','48333e'), ('48334e','48337e'),
                ('483346','48334e'), ('488b56','4c8b46'), ('4831c2','4931c8'),
                ('4809ca','4909f8'), ('4809c1','4809cf'), ('4809c8','4809f9'),
                ('0fb74e','0fb77e'), ('0fb64e','0fb67e'), ('0fb646','0fb64e'),
                ('483906','48390e'), ('48b8','48b9'), ('48b9','48bf'),
                ('3306','330e'), ('09c1','09cf'), ('8b4e','8b7e'), ('81f1','81f7'),
                ('4805','4881c1'), ('3d','81f9'), ('b8','b9'),
            )
            for actual, canonical in aliases:
                a, b = bytes.fromhex(actual), bytes.fromhex(canonical)
                if raw.startswith(a):
                    raw, adjustment = b + raw[len(a):], len(a) - len(b)
                    break

        # Exact register/memory encodings found in these FDEs only.
        if raw[:2] == b'\x48\xb9':
            regs['rcx'], width = int.from_bytes(raw[2:10], 'little'), 10
        elif raw[:2] == b'\x48\xbf':
            regs['rdi'], width = int.from_bytes(raw[2:10], 'little'), 10
        elif raw[:1] == b'\xb9':
            regs['rcx'], width = int.from_bytes(raw[1:5], 'little'), 5
        elif raw[:3] == bytes.fromhex('48330e'):
            regs['rcx'] ^= integer(0, 8); width = 3
        elif raw[:3] == bytes.fromhex('48333e'):
            regs['rdi'] ^= integer(0, 8); width = 3
        elif raw[:3] == bytes.fromhex('48337e'):
            regs['rdi'] ^= integer(raw[3], 8); width = 4
        elif raw[:3] == bytes.fromhex('48334e'):
            regs['rcx'] ^= integer(raw[3], 8); width = 4
        elif raw[:2] == bytes.fromhex('330e'):
            regs['rcx'] = (regs['rcx'] ^ integer(0, 4)) & 0xffffffff; width = 2
        elif raw[:3] == bytes.fromhex('4c8b46'):
            regs['r8'], width = integer(raw[3], 8), 4
        elif raw[:3] == bytes.fromhex('4931c8'):
            regs['r8'] ^= regs['rcx']; width = 3
        elif raw[:3] == bytes.fromhex('4909f8'):
            regs['r8'] |= regs['rdi']; zf, width = regs['r8'] == 0, 3
        elif raw[:3] == bytes.fromhex('4809cf'):
            regs['rdi'] |= regs['rcx']; zf, width = regs['rdi'] == 0, 3
        elif raw[:3] == bytes.fromhex('4809f9'):
            regs['rcx'] |= regs['rdi']; zf, width = regs['rcx'] == 0, 3
        elif raw[:2] == bytes.fromhex('09cf'):
            regs['rdi'] = (regs['rdi'] | regs['rcx']) & 0xffffffff; zf, width = regs['rdi'] == 0, 2
        elif raw[:3] in (bytes.fromhex('0fb77e'), bytes.fromhex('0fb67e')):
            regs['rdi'] = integer(raw[3], 2 if raw[1] == 0xb7 else 1); width = 4
        elif raw[:3] == bytes.fromhex('0fb64e'):
            regs['rcx'], width = integer(raw[3], 1), 4
        elif raw[:2] == bytes.fromhex('8b7e'):
            regs['rdi'], width = integer(raw[2], 4), 3
        elif raw[:2] == bytes.fromhex('81f7'):
            regs['rdi'] = (regs['rdi'] ^ int.from_bytes(raw[2:6], 'little')) & 0xffffffff; width = 6
        elif raw[:3] == bytes.fromhex('4881f7'):
            regs['rdi'] ^= signed(raw[3:7]) & mask64; width = 7
        elif raw[:3] == bytes.fromhex('4883f7'):
            regs['rdi'] ^= signed(raw[3:4]) & mask64; width = 4
        elif raw[:3] in (bytes.fromhex('4881c7'), bytes.fromhex('4881c1')):
            reg = 'rdi' if raw[2] == 0xc7 else 'rcx'
            regs[reg] = (regs[reg] + signed(raw[3:7])) & mask64; width = 7
        elif raw[:3] == bytes.fromhex('48390e'):
            zf, width = integer(0, 8) == regs['rcx'], 3
        elif raw[:4] == bytes.fromhex('f30f6f06'):
            vectors[0], width = keypart(0, 16), 4
        elif raw[:4] == bytes.fromhex('f30f6f4e'):
            vectors[1], width = keypart(raw[4], 16), 5
        elif raw[:4] in (bytes.fromhex('660f7405'), bytes.fromhex('660f740d')):
            reg = 0 if raw[3] == 5 else 1
            constant = image.read(rel32(image, pc, raw[:4].hex()), 16)
            vectors[reg] = bytes(255 if a == b else 0 for a, b in zip(vectors[reg], constant))
            width = 8
        elif raw[:5] == bytes.fromhex('66480f6ed7'):
            vectors[2], width = regs['rdi'].to_bytes(8, 'little') + bytes(8), 5
        elif raw[:5] == bytes.fromhex('66480f6ed9'):
            vectors[3], width = regs['rcx'].to_bytes(8, 'little') + bytes(8), 5
        elif raw[:4] == bytes.fromhex('660f6cd3'):
            vectors[2], width = vectors[2][:8] + vectors[3][:8], 4
        elif raw[:4] == bytes.fromhex('660f74d1'):
            vectors[2] = bytes(255 if a == b else 0 for a, b in zip(vectors[2], vectors[1])); width = 4
        elif raw[:4] == bytes.fromhex('660f6ec9'):
            vectors[1], width = (regs['rcx'] & 0xffffffff).to_bytes(4, 'little') + bytes(12), 4
        elif raw[:4] in (bytes.fromhex('660fdbc1'), bytes.fromhex('660fdbc2'), bytes.fromhex('660fdbc8')):
            dest, src = {0xc1: (0, 1), 0xc2: (0, 2), 0xc8: (1, 0)}[raw[3]]
            vectors[dest] = bytes(a & b for a, b in zip(vectors[dest], vectors[src])); width = 4
        elif raw[:4] in (bytes.fromhex('660fd7c8'), bytes.fromhex('660fd7c9')):
            vector = vectors[0 if raw[3] == 0xc8 else 1]
            regs['rcx'] = sum(((byte >> 7) & 1) << i for i, byte in enumerate(vector)); width = 4
        elif raw[:2] == bytes.fromhex('81f9'):
            zf, width = regs['rcx'] == int.from_bytes(raw[2:6], 'little'), 6
        else:
            raise EvidenceError('unsupported JSON key probe encoding at ' + hexva(pc))
        pc += width + adjustment


def ashex(value):
    if isinstance(value, int):
        return hexva(value)
    return value


def tsv(rows, columns, hexadecimal=()):
    output = io.StringIO(newline='')
    writer = csv.writer(output, delimiter='\t', lineterminator='\n')
    writer.writerow(columns)
    for row in rows:
        writer.writerow([ashex(row.get(c, '')) if c in hexadecimal else row.get(c, '') for c in columns])
    return output.getvalue().encode('utf-8')


def collect(image):
    fdes = {start: image.fde(start) for start in ENTRIES}
    for f in fdes.values():
        matches = [sec for sec in image.secs if sec['type'] != 8 and sec['flags'] & 4 and
                   sec['address'] <= f['start'] and f['end'] <= sec['address'] + sec['size']]
        require(len(matches) == 1, 'FDE is not in a unique executable section')
    for name, (va, pattern) in WINDOWS.items():
        raw = exact(image, va, pattern)
        require(sum(f['start'] <= va and va + len(raw) <= f['end'] for f in fdes.values()) == 1,
                'selected window not in exactly one selected FDE: ' + name)
    branches = [branch(image, *x) for x in BRANCHES]
    calls = [call(image, *x) for x in CALLS]
    for row in branches + calls:
        require(any(f['start'] <= row['site'] < f['end'] for f in fdes.values()), 'site outside selection')
    visitor = fdes[0x14a2870]
    mask = int.from_bytes(image.read(0x149e794, 8), 'little')
    whitespace_limit = image.read(0x149e7a8, 1)[0]
    whitespace = [i for i in range(whitespace_limit + 1) if mask & (1 << i)]
    require(mask == int.from_bytes(image.read(0x14bafbd, 8), 'little'), 'whitespace masks differ')
    dispatch_base = rel32(image, 0x14a2b5c, '488d35')
    dispatch = fields(image, dispatch_base, int.from_bytes(image.read(0x14a2b4a, 4), 'little'),
                      -signed(image.read(0x14a2b42, 1)), visitor)
    fallback_slot = dispatch_base + len(dispatch) * 4
    fallback_arm = dispatch_base + signed(image.read(fallback_slot, 4))
    require(fallback_arm == 0x14a2e1e, 'unknown field arm changed')
    stride = 1 << image.read(0x14a35cc, 1)[0]
    require(stride == image.read(0x1488a43, 1)[0], 'unknown record strides differ')
    binary_paths, binary_summary = symbolic_field_paths(image, fdes[0x13c75e0])
    require([(r['name'], r['tag']) for r in binary_paths] ==
            [(r['literal'], r['field_tag']) for r in dispatch],
            'binary field predicates and diagnostic dispatch disagree')
    json_probes = []
    for owned in (False, True):
        classifier = 'owned' if owned else 'borrowed'
        fde = fdes[0x13c84c0 if owned else 0x13c71c0]
        for row in binary_paths:
            key = row['name'].encode('ascii')
            probe = json_key_probe(image, key, fde, owned)
            require(probe['tag'] == row['tag'], 'JSON key and binary predicate disagree')
            json_probes.append(dict(classifier=classifier, case='known', key_hex=key.hex(), **probe))
        for key in (b'b_key', b'b_keyx', b'B_keys', b'b_keys_', b'b_key\x00', b'cg_keY',
                    b'NvTestnet', b'', b'X' * 34, b'testnet_slack_channeL'):
            probe = json_key_probe(image, key, fde, owned)
            require(probe['tag'] == (12 if owned else 13), 'unexpected JSON key acceptance')
            json_probes.append(dict(classifier=classifier, case='negative', key_hex=key.hex(), **probe))
    borrowed = matcher(image, 0x13c71c0, 0x13c71e1, 0x13c71d1, 0x13c71f4,
                       'c600', 0x13c720d, 0x13c7213)
    owned = matcher(image, 0x13c84c0, 0x13c84ec, 0x13c84dc, 0x13c84ff,
                    'c603', 0x13c8518, 0x13c851e)
    require(borrowed['first_name'] == owned['first_name'] == dispatch[22]['literal'], 'key mismatch')
    require(borrowed['first_tag'] == owned['first_tag'] == dispatch[22]['field_tag'], 'tag mismatch')
    require(borrowed['second_name'] == owned['second_name'] == dispatch[23]['literal'], 'second key mismatch')
    require(borrowed['second_tag'] == owned['second_tag'] == dispatch[23]['field_tag'], 'second tag mismatch')
    require(dispatch[22]['value_target'] == 0x1441d10, 'selected map call changed')
    bin_dispatch = rel32(image, 0x13aca3d, '488d0d')
    bin_bias = -signed(image.read(0x13aca2b, 1))
    bin_count = int.from_bytes(image.read(0x13aca33, 4), 'little')
    bin_index = borrowed['first_tag'] - bin_bias
    require(0 <= bin_index < bin_count, 'selected binary field outside dispatch')
    bin_slot = bin_dispatch + 4 * bin_index
    bin_arm = bin_dispatch + signed(image.read(bin_slot, 4))
    require(bin_arm == 0x13ad678 and fdes[0x13abf40]['start'] <= bin_arm < fdes[0x13abf40]['end'],
            'selected binary field arm changed')
    bin_duplicate = rel32(image, 0x13ad680, '0f85')
    bin_duplicate_name = rel32(image, bin_duplicate, '488d05')
    require(image.read(bin_duplicate_name, len(borrowed['first_name'])) == borrowed['first_name'].encode(),
            'binary duplicate diagnostic changed')
    require(rel32(image, 0x13b189a, '488d35') == 0x1e0fd5, 'binary duplicate template changed')
    require(rel32(image, 0x13ad695, 'e8') == 0x13aa6e0, 'binary option reader changed')
    require(rel32(image, 0x13aa79c, 'e8') == 0x13bec50, 'binary value boundary changed')
    null_marker = int.from_bytes(image.read(0x13aa6f5, 4), 'little')
    require(null_marker == 0xc0, 'binary option null marker changed')
    format_callback = rel32(image, 0x13d290a, '488d05')
    require(format_callback == 0x13da090, 'format callback changed')
    require(image.relative(0x576e928) == 0x577b288, 'configuration slot changed')
    require(image.relative(0x577a898) == 0x13d28e0, 'initializer slot changed')
    require(image.relative(0x5668488) == 0x2180ff, 'name slice pointer changed')
    require(image.read(0x5668490, 8) == struct.pack('<Q', 9), 'name slice length changed')
    require(image.read(0x2180ff, 9) == b'NvTestnet', 'name slice bytes changed')
    require(image.dynamic_symbol(0x576dfe0) == 'memcpy', 'copy symbol changed')
    tmpl = rel32(image, 0x13d2916, '488d35')
    prefix = image.read(tmpl, 2)
    require(prefix[0] == 0xc0 and prefix[1] < 0x80, 'unsupported template')
    template = image.read(tmpl, prefix[1] + 3)
    duplicate_va = rel32(image, 0x14a83e8, '488d3d')
    duplicate_len = image.read(duplicate_va, 1)[0]
    duplicate = image.read(duplicate_va, duplicate_len + 5)
    require(duplicate[1:1 + duplicate_len] == b'duplicate field `' and
            duplicate[-4:] == bytes.fromhex('c0016000'), 'duplicate template changed')
    require(template[-1] == 0 and template[2:-1] == b'/api_secrets.json', 'template changed')
    function_rows = []
    for start, label in ENTRIES.items():
        f = fdes[start]
        raw = image.read(start, f['end'] - start)
        function_rows.append(dict(role=label, start=start, end=f['end'], fde=f['fde'],
                                  lsda=f['lsda'], file_offset=image.offset(start, len(raw)),
                                  byte_count=len(raw), sha256=hashlib.sha256(raw).hexdigest()))
    function_rows.sort(key=lambda r: r['start'])
    window_rows = [dict(label=name, va=va, file_offset=image.offset(va, len(bytes.fromhex(pattern))),
                        byte_count=len(bytes.fromhex(pattern)), bytes=image.read(va, len(bytes.fromhex(pattern))).hex())
                   for name, (va, pattern) in WINDOWS.items()]
    window_rows.sort(key=lambda r: r['va'])
    evidence = {
        'artifact': {'release': 'node94', 'sha256': DIGEST, 'size': len(image.data)},
        'coordinate_system': 'ELF linked virtual addresses; file offsets are section-mapped',
        'source_commit': '56c0ec672bd8fdcfaa80f2db700a61e6240b3663',
        'reference_commit': '999556f6e0a474b8312db96ec3149e1c44e97c23',
        'counts': {'selected_fdes': len(function_rows), 'field_arms': len(dispatch),
                   'selected_branches': len(branches), 'selected_calls': len(calls),
                   'selected_windows': len(window_rows)},
        'initializer': {'display_callback': hexva(format_callback),
                        'configuration_field_offset': image.read(0x13d2904, 1)[0],
                        'default_output_offset': image.read(0x13d2a7f, 1)[0],
                        'default_word': int.from_bytes(image.read(0x13d2a80, 4), 'little')},
        'path_selector': {'predicate_slot': hexva(rel32(image, 0x144b16f, 'ff15')),
                          'predicate': hexva(image.relative(rel32(image, 0x144b16f, 'ff15'))),
                          'transformer': hexva(image.relative(rel32(image, 0x144b187, 'ff15'))),
                          'initial_false_tag': int.from_bytes(image.read(0x144b1ba, 4), 'little'),
                          'error_tag': int.from_bytes(image.read(0x144b643, 4), 'little')},
        'duplicate_template': {'va': hexva(duplicate_va), 'bytes': duplicate.hex(),
                               'prefix': duplicate[1:1 + duplicate_len].decode('ascii')},
        'document_whitespace': {'mask': hexva(mask), 'limit': whitespace_limit, 'accepted_bytes': whitespace},
        'template': {'va': hexva(tmpl), 'file_offset': hexva(image.offset(tmpl, len(template))),
                     'bytes': template.hex(), 'literal': template[2:-1].decode('ascii')},
        'relocation_context': [
            {'slot': hexva(slot), 'relative_addend': hexva(image.relative(slot))}
            for slot in (0x5668488, 0x576e928, 0x577a898)],
        'binary_field_classifier': {**binary_summary, 'table': hexva(binary_summary['table']),
                                    'fallback': hexva(binary_summary['fallback']),
                                    'success_paths': len(binary_paths)},
        'json_key_probes': {'classifiers': 2,
                            'known_inputs_per_classifier': sum(r['case'] == 'known' and r['classifier'] == 'borrowed' for r in json_probes),
                            'negative_inputs_per_classifier': sum(r['case'] == 'negative' and r['classifier'] == 'borrowed' for r in json_probes),
                            'single_byte_mutations_per_classifier': sum(r['length'] for r in binary_paths),
                            'known_bcmp_paths': sum(r['case'] == 'known' and r['bcmp'] for r in json_probes),
                            'bcmp_symbol': image.dynamic_symbol(rel32(image, 0x13c7237, 'ff15'))},
        'binary_selected_field': {'dispatch_table': hexva(bin_dispatch), 'dispatch_index': bin_index,
                                  'dispatch_slot': hexva(bin_slot), 'arm': hexva(bin_arm),
                                  'duplicate_arm': hexva(bin_duplicate),
                                  'duplicate_name_va': hexva(bin_duplicate_name),
                                  'null_marker': hexva(null_marker),
                                  'option_reader': hexva(rel32(image, 0x13ad695, 'e8')),
                                  'value_boundary': hexva(rel32(image, 0x13aa79c, 'e8'))},
        'json_selected_field': {'field_tag': hexva(borrowed['first_tag']),
                                'slot_offset': hexva(int.from_bytes(image.read(0x14a33f0, 4), 'little')),
                                'unset_sentinel': image.read(0x14a33f4, 1)[0],
                                'default_word': int.from_bytes(image.read(0x14a4d59, 4), 'little'),
                                'value_boundary': hexva(dispatch[22]['value_target'])},
        'json_special_tags': [{'tag': hexva(image.read(0x14a2add, 1)[0]),
                               'branch': hexva(0x14a2ade), 'target': hexva(rel32(image, 0x14a2ade, '0f84'))},
                              {'tag': hexva(image.read(0x14a2b15, 1)[0]),
                               'branch': hexva(0x14a2b16), 'target': hexva(rel32(image, 0x14a2b16, '0f84'))}],
        'discriminator_context': {'name_slice_va': hexva(image.relative(0x5668488)),
                                  'name_length': int.from_bytes(image.read(0x5668490, 8), 'little'),
                                  'name': image.read(0x2180ff, 9).decode('ascii'),
                                  'field_dispatch_base': hexva(dispatch_base),
                                  'field_dispatch_first_tag': dispatch[0]['field_tag'],
                                  'field_dispatch_last_tag': dispatch[-1]['field_tag'],
                                  'fallback_slot': hexva(fallback_slot), 'fallback_arm': hexva(fallback_arm),
                                  'unknown_record_stride': stride},
        'limitations': 'Selected byte patterns and unwind ranges only; no complete x86 CFG, native execution, Rust implementation, whole-component coverage, file-system behavior, or progress gate is claimed.'
    }
    return {
        'evidence.json': (json.dumps(evidence, indent=2, sort_keys=True) + '\n').encode(),
        'functions.tsv': tsv(function_rows, ['role','start','end','fde','lsda','file_offset','byte_count','sha256'],
                             ('start','end','fde','lsda','file_offset')),
        'field-dispatch.tsv': tsv(dispatch, ['index','field_tag','slot','arm','duplicate_branch','duplicate_arm',
            'literal_va','literal_length','literal','colon_above','colon_branch','colon_arm','wrong_colon',
            'cursor_overflow','value_call','value_target'],
            ('field_tag','slot','arm','duplicate_branch','duplicate_arm','literal_va','colon_above',
             'colon_branch','colon_arm','wrong_colon','cursor_overflow','value_call','value_target')),
        'binary-field-paths.tsv': tsv(binary_paths, ['name','tag','length','table_slot','entry','success',
            'branch_count','comparisons'], ('tag','table_slot','entry','success')),
        'json-field-probes.tsv': tsv(json_probes, ['classifier','case','key_hex','tag','entry','leaf','branches','steps','bcmp'],
                                     ('tag','entry','leaf')),
        'key-matchers.tsv': tsv([borrowed, owned], ['entry','table','length_six_target','first_name','first_tag',
            'first_leaf','second_name','second_tag','mismatch_target'],
            ('entry','table','length_six_target','first_tag','first_leaf','second_tag','mismatch_target')),
        'branches.tsv': tsv(branches, ['label','site','file_offset','bytes','fallthrough','target'],
                            ('site','file_offset','fallthrough','target')),
        'calls.tsv': tsv(calls, ['label','site','file_offset','bytes','kind','target','relative_addend','symbol'],
                         ('site','file_offset','target','relative_addend')),
        'windows.tsv': tsv(window_rows, ['label','va','file_offset','byte_count','bytes'], ('va','file_offset')),
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', required=True, type=Path)
    args = p.parse_args()
    image = Image((ROOT / 'artifacts/node/94/hl-node').read_bytes())
    outputs = collect(image)
    args.out.mkdir(parents=True, exist_ok=True)
    for name, data in outputs.items():
        (args.out / name).write_bytes(data)
    print('generated ' + str(len(outputs)) + ' evidence files')


if __name__ == '__main__':
    try:
        main()
    except (EvidenceError, ValueError, OSError, struct.error) as exc:
        print('config_name_field94: ' + str(exc), file=sys.stderr)
        raise SystemExit(1)
