#!/usr/bin/env python3
"""Extract the node 94 configuration-rooted database home path, without execution.

The selected instruction starts were checked by bounded human disassembly. This
is a fixed-pattern collector, not a general x86 decoder or a function census.
"""
import argparse
import csv
import hashlib
import io
import json
import struct
from pathlib import Path

from elf_index import sections
from fde_extents import eh_frame_records, uleb

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = Path('artifacts/node/94/hl-node')
EXPECTED_SIZE = 91774280
EXPECTED_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# FDE extent and body hashes admit only the bytes reviewed for this path.
FUNCTIONS = (
    ('global_string_adapter', 0x15861b0, 0x15861c4, 'd3ada1d32fee8528e241f03d78787a39ac32177348cfe168613fb878d66f8a16'),
    ('home_selector', 0x15861d0, 0x1586308, '0708e4510d25b8d4b5fde39b85aefb822df85b4431644bb13c6e4b40a1b39dc3'),
    ('input_string_adapter', 0x1589f60, 0x1589f77, '5c9765457b6278d68eb9d3231f077fbe38e585fafae5d700148861fac9977eff'),
    ('sorted_record_insert', 0x428f680, 0x428fd68, '6038d4141aff10e100ade32103243c1b984c04c0ce31431c25cd00ac3ef09230'),
    ('remaining_iterator_drop', 0x44c8670, 0x44c8730, 'c8ed078d8dc5d05ae25aea732bbf815cd67e13225d4affffe39baad40f9db825'),
    ('record_map_builder', 0x489d9c0, 0x489db89, 'd82677c6818118727dda6fdc00edc09f204f37da4d2390f181907053d8eb063d'),
    ('record_vector_drop', 0x4900d10, 0x4900e00, '9afbbd5967d598f709a85900726ab89744103f653885127c70f89311d1e694e7'),
    ('home_map_entry', 0x4adda00, 0x4addb60, '7f58ae56d67f3b103029be3031158bd3c9cbd16aa3f0bc8907480df1024deafc'),
)

# These are bounded instruction windows, independently checked against their
# expected bytes. Some windows contain several instructions.
PINS = (
    ('load_discriminator', 0x15861d7, '488b07'),
    ('negate_for_overflow', 0x15861dd, '48f7d9'),
    ('no_hub_marker', 0x15861e2, '48b90100000000000080'),
    ('compare_no_hub_marker', 0x15861ec, '4839c8'),
    ('global_once_word', 0x15861f8, '8b435085c0'),
    ('global_prefix_1', 0x1586203, '4883c318'),
    ('global_prefix_2', 0x1586239, '4883c318'),
    ('global_format_adapter', 0x15861b0, '4889f0488b7708488b57104889c7ff253c7e1e04'),
    ('input_format_adapter', 0x1589f60, '4889f0488b0f488b7108488b51104889c7ff2589401e04'),
    ('init_temp_empty', 0x4adda0d, '48c74424180000000048c74424200100000048c744242800000000'),
    ('format_error_test', 0x4adda55, '84c0'),
    ('range_begin', 0x4adda70, '48c744243800000000'),
    ('range_end', 0x4adda79, '48c744244002000000'),
    ('two_key_bytes', 0x4adda82, '66c74424480001'),
    ('copy_input_and_map', 0x4addaa0, '488b4310498946100f1003410f1106488b442460498946280f10442450410f114618'),
    ('free_temporary_test', 0x4addac2, '488b34244885f6'),
    ('panic_message_length', 0x4addafb, 'be37000000'),
    ('panic_trap', 0x4addb06, '0f0b'),
    ('cleanup_signed_limit', 0x4addb38, '48b80200000000000080'),
    ('cleanup_signed_test', 0x4addb42, '4839c6'),
    ('cleanup_zero_test', 0x4addb47, '4885f6'),
    ('length_test', 0x489d9d8, '488b7424184885f6'),
    ('one_item_test', 0x489d9f5, '4883fe01'),
    ('leaf_alloc_size', 0x489da0e, 'bf70000000'),
    ('root_init', 0x489da22, '48c7000000000066c740620000'),
    ('map_count_init', 0x489da3d, '48c744242000000000'),
    ('record_stride', 0x489da46, '49c1e704'),
    ('iterator_tag', 0x489da4d, 'c644243804'),
    ('iterator_range', 0x489da52, '4c896424484c896424504c897424584c897c2460'),
    ('map_publish', 0x489da7a, '0f10442428488b4424200f110348894310'),
    ('empty_map_root', 0x489da8d, '48c7030000000048c7431000000000'),
    ('sort_threshold', 0x489dac6, '4883fe15'),
    ('sort_key_compare', 0x489db02, '410fb65010413a10'),
    ('sort_shift_record', 0x489db13, '420f104417f0420f110417'),
    ('drop_buffer_test', 0x4900d73, '498b364885f6'),
    ('atomic_drop', 0x4900d61, '4a8b0423f048ff0875e5'),
    ('iterator_drop_check', 0x44c867c, '4c8b77084c8b67184d29f4'),
    ('iterator_ref_drop', 0x44c86aa, '498b46f0f048ff0875ec'),
    ('bulk_initial_height', 0x428f694, '4c8b3f488b4f084885c9'),
    ('bulk_read_tag', 0x428f740, '440fb66c2410488b5c2418c644241004'),
    ('bulk_next_record', 0x428f7b0, '488b542428488b4c24384839ca0f843e020000488d42104889442428440fb62a488b5a08'),
    ('bulk_advance_compare', 0x428f779, '488d481048894c24280fb608488b4008884c241048894424184138cd7551'),
    ('bulk_capacity_check', 0x428f7ed, '410fb747624883f80b'),
    ('bulk_key_and_ptr_stores', 0x428f7f8, '8d48016641894f6245886c076449895cc70849ff06'),
    ('bulk_duplicate_dec', 0x428f797, 'f048ff0b75a3'),
    ('bulk_height_check', 0x428fa2e, '4c8b65084d85e4'),
)

# Only the listed reviewed transfer sites are decoded. A code or section scan
# for all x86 instructions is deliberately not attempted.
TRANSFERS = (
    ('neg_overflow',0x15861e0,'70',0x1586227),
    ('other_input',0x15861ef,'75',0x158625d),
    ('once_first',0x15861fd,'0f85',0x1586296),
    ('first_format_join',0x1586225,'eb',0x1586285),
    ('once_second',0x1586233,'0f85',0x15862cf),
    ('second_format_join',0x158625b,'eb',0x1586285),
    ('once_first_return',0x15862ca,'e9',0x1586203),
    ('once_second_return',0x1586303,'e9',0x1586239),
    ('formatter_failure',0x4adda57,'0f85',0x4addae3),
    ('build_map',0x4adda9b,'e8',0x489d9c0),
    ('empty_temp',0x4addac9,'74',0x4addad8),
    ('cleanup_first_empty',0x4addb12,'74',0x4addb35),
    ('cleanup_second_empty',0x4addb26,'74',0x4addb35),
    ('cleanup_marker_exclusion',0x4addb45,'7c',0x4addb58),
    ('cleanup_zero_exclusion',0x4addb4a,'74',0x4addb58),
    ('collect_records_boundary',0x489d9d3,'e8',0x4872470),
    ('empty_records',0x489d9e0,'0f84',0x489da8d),
    ('multiple_records',0x489d9f9,'0f85',0x489dac6),
    ('root_alloc_failure',0x489da1c,'0f84',0x489db37),
    ('large_sort',0x489daca,'73',0x489db49),
    ('sort_already_ordered',0x489db0a,'73',0x489daeb),
    ('sort_shift',0x489db30,'72',0x489db13),
    ('sort_finish',0x489daf9,'0f84',0x489d9ff),
    ('insert_records',0x489da75,'e8',0x428f680),
    ('drop_records_a',0x489db61,'e8',0x4900d10),
    ('drop_records_b',0x489db76,'e8',0x4900d10),
    ('no_existing_height',0x428f69e,'74',0x428f71f),
    ('iterator_unprimed',0x428f754,'74',0x428f7b0),
    ('iterator_finished',0x428f75a,'0f84',0x428fa01),
    ('empty_iterator',0x428f7bd,'0f84',0x428fa01),
    ('has_next',0x428f7e1,'75',0x428f779),
    ('distinct_key',0x428f795,'75',0x428f7e8),
    ('last_key',0x428f777,'74',0x428f7e3),
    ('split_leaf',0x428f7f6,'73',0x428f812),
    ('insert_next',0x428f80d,'e9',0x428f740),
    ('drop_iterator',0x428fa06,'e8',0x44c8670),
    ('zero_tree_height',0x428fa35,'0f84',0x428fc21),
    ('vector_empty',0x4900d29,'74',0x4900d73),
    ('vector_ref_nonzero',0x4900d69,'75',0x4900d50),
    ('iterator_no_remaining',0x44c8687,'74',0x44c86bd),
    ('iterator_ref_nonzero',0x44c86b2,'75',0x44c86a0),
    ('iterator_no_allocation',0x44c86c4,'74',0x44c86de),
    ('iterator_resume',0x44c870b,'e8',0x5660110),
)

# rel32 RIP operands, including external boundaries, are resolved from bytes.
RIP_REFS = (
    ('global_slot_first',0x15861f1,'488b1d',0x576e928),
    ('global_slot_second',0x1586227,'488b1d',0x576e928),
    ('global_adapter_first',0x158620b,'488d05',0x15861b0),
    ('global_adapter_second',0x1586241,'488d05',0x15861b0),
    ('no_hub_template',0x158621e,'488d15',0x1ea808),
    ('hub_template',0x1586254,'488d15',0x1f3db9),
    ('input_adapter',0x158626b,'488d05',0x1589f60),
    ('identity_template',0x158627e,'488d15',0x1ea44d),
    ('format_output',0x1586288,'ff15',0x576e008),
    ('once_first_call',0x15862c1,'ff15',0x576e8b8),
    ('once_second_call',0x15862fa,'ff15',0x576e8b8),
    ('global_adapter_tail',0x15861be,'ff25',0x576e000),
    ('input_adapter_tail',0x1589f71,'ff25',0x576e000),
    ('display_context',0x4adda3b,'488d05',0x5738168),
    ('home_selector_slot',0x4adda4f,'ff15',0x57707e8),
    ('entry_free',0x4addad2,'ff15',0x576e010),
    ('format_failure_text',0x4addae3,'488d3d',0x706a56),
    ('format_failure_call',0x4addb00,'ff15',0x576e048),
    ('cleanup_free_a',0x4addb2f,'ff15',0x576e010),
    ('cleanup_free_b',0x4addb52,'ff15',0x576e010),
    ('root_allocate',0x489da13,'ff15',0x576dfd8),
    ('empty_free',0x489dab1,'ff15',0x576e010),
    ('root_alloc_error',0x489db41,'ff15',0x576e020),
    ('large_sort_slot',0x489db4e,'ff15',0x5776768),
    ('vector_drop_slot',0x4900d41,'488b2d',0x5770800),
    ('iterator_free',0x44c86d8,'ff25',0x576e010),
)

RELOCATIONS = {
    0x576dfd8: 0x54c06b0,
    0x576e000: 0x1573450,
    0x576e008: 0x1571d90,
    0x576e010: 0x54c8cb0,
    0x576e020: 0x1345e2a,
    0x576e048: 0x157aa10,
    0x576e8b8: 0x4ee3b20,
    0x576e928: 0x577b288,
    0x57707e8: 0x15861d0,
    0x5776768: 0x4488e90,
    0x577b288: 0x164ff00,
}


def verify_digest(data):
    if len(data) != EXPECTED_SIZE or hashlib.sha256(data).hexdigest() != EXPECTED_SHA256:
        raise ValueError('node 94 input size or SHA-256 mismatch')


class Image:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)

    def offset(self, address, length):
        if address < 0 or length <= 0 or address + length > (1 << 64):
            raise ValueError('invalid virtual address range')
        matches = [s for s in self.sections if s['type'] != 8 and s['flags'] & 2
                   and s['address'] <= address and address + length <= s['address'] + s['size']]
        if len(matches) != 1:
            raise ValueError('virtual range has no unique file-backed allocated section')
        sec = matches[0]
        return sec['offset'] + address - sec['address']

    def read(self, address, length):
        pos = self.offset(address, length)
        return bytes(self.data[pos:pos + length])

    def expect(self, address, expected):
        actual = self.read(address, len(expected))
        if actual != expected:
            raise ValueError('selected instruction bytes changed at %#x' % address)
        return actual


def checked_rel32(image, address, opcode, target):
    prefix = bytes.fromhex(opcode)
    raw = image.read(address, len(prefix) + 4)
    if not raw.startswith(prefix):
        raise ValueError('unexpected rel32 opcode at %#x' % address)
    result = address + len(raw) + struct.unpack_from('<i', raw, len(prefix))[0]
    if result != target:
        raise ValueError('unexpected relative target at %#x' % address)
    return raw, result


def checked_transfer(image, address, opcode, target):
    prefix = bytes.fromhex(opcode)
    if prefix[0] in (0xe8, 0xe9) or prefix[0] == 0x0f:
        return checked_rel32(image, address, opcode, target)
    raw = image.read(address, 2)
    if len(prefix) != 1 or raw[0] != prefix[0]:
        raise ValueError('unexpected short transfer at %#x' % address)
    result = address + 2 + struct.unpack_from('<b', raw, 1)[0]
    if result != target:
        raise ValueError('unexpected short transfer target at %#x' % address)
    return raw, result


def checked_body(image, start, end, expected_sha256):
    if end <= start:
        raise ValueError('invalid selected FDE extent')
    body = image.read(start, end - start)
    if hashlib.sha256(body).hexdigest() != expected_sha256:
        raise ValueError('selected FDE byte hash mismatch')
    return body


def parse_relocations(image, expected):
    matches = [s for s in image.sections if s['name'] == '.rela.dyn' and s['type'] == 4]
    if len(matches) != 1:
        raise ValueError('missing or ambiguous dynamic RELA section')
    sec = matches[0]
    if sec['size'] % 24:
        raise ValueError('truncated dynamic RELA section')
    found = {}
    for pos in range(sec['offset'], sec['offset'] + sec['size'], 24):
        address, info, addend = struct.unpack_from('<QQq', image.data, pos)
        if address in expected:
            if address in found or info != 8 or addend != expected[address]:
                raise ValueError('selected relative relocation changed or duplicated')
            found[address] = {'slot_va': hex(address), 'type': info,
                              'addend_va': hex(addend), 'record_file_offset': hex(pos),
                              'record_bytes': bytes(image.data[pos:pos + 24]).hex()}
    if set(found) != set(expected):
        raise ValueError('selected relative relocation missing')
    return [found[k] for k in sorted(found)]


def parse_template(image, address, expected_suffix):
    head = image.read(address, 2)
    if head[0] != 0xc0:
        raise ValueError('template does not begin with selected argument token')
    length = head[1]
    # c0 00 is an argument followed directly by the terminator; the second
    # byte is not a zero-length literal token requiring another terminator.
    raw = image.read(address, length + 3 if length else 2)
    literal = raw[2:-1] if length else b''
    if raw[-1] != 0 or literal != expected_suffix:
        raise ValueError('selected template literal or terminator changed')
    return {'entry_va': hex(address), 'entry_file_offset': hex(image.offset(address, len(raw))),
            'raw_hex': raw.hex(), 'literal_length': length,
            'literal': literal.decode('ascii')}


def exception_table(image, fde):
    address = fde['lsda']
    if address is None:
        return None, []
    found = [s for s in image.sections if s['name'] == '.gcc_except_table' and s['type'] != 8
             and s['address'] <= address < s['address'] + s['size']]
    if len(found) != 1:
        raise ValueError('exception table is not uniquely file-backed')
    sec = found[0]
    pos = image.offset(address, 2)
    origin = pos
    end = sec['offset'] + sec['size']
    lp, type_enc = image.data[pos], image.data[pos + 1]
    pos += 2
    if lp != 0xff or type_enc not in (0xff, 0x9b):
        raise ValueError('unsupported exception table header')
    type_base = None
    if type_enc != 0xff:
        delta, pos = uleb(image.data, pos, end)
        type_base = pos + delta
        if type_base > end:
            raise ValueError('exception type table outside section')
    if pos >= end or image.data[pos] != 1:
        raise ValueError('unsupported exception call-site encoding')
    length, pos = uleb(image.data, pos + 1, end)
    stop = pos + length
    if stop > end or (type_base is not None and stop > type_base):
        raise ValueError('exception call-site table outside bounds')
    records, previous_end = [], 0
    while pos < stop:
        entry = pos
        values = []
        for _ in range(4):
            value, pos = uleb(image.data, pos, stop)
            values.append(value)
        start, size, landing, action = values
        if not size or start < previous_end or start + size > fde['end'] - fde['start']:
            raise ValueError('invalid exception range')
        if landing and landing >= fde['end'] - fde['start']:
            raise ValueError('landing pad outside selected FDE')
        previous_end = start + size
        records.append({'function_va': hex(fde['start']), 'entry_file_offset': hex(entry),
                        'start_va': hex(fde['start'] + start), 'end_va': hex(fde['start'] + start + size),
                        'landing_va': hex(fde['start'] + landing) if landing else '',
                        'action_index': action, 'raw_hex': bytes(image.data[entry:pos]).hex()})
    header = {'function_va': hex(fde['start']), 'lsda_va': hex(address),
              'header_file_offset': hex(origin), 'header_and_sites_hex': bytes(image.data[origin:stop]).hex(),
              'lpstart_encoding': hex(lp), 'type_encoding': hex(type_enc), 'callsite_encoding': '0x1',
              'entry_count': len(records)}
    return header, records


def selector_case(word, second_marker):
    if not 0 <= word < (1 << 64):
        raise ValueError('selector must be an unsigned 64-bit word')
    if word == 1 << 63:
        return 'global_db_hub'
    if word == second_marker:
        return 'global_no_db_hub'
    return 'input_string'


def signed_cleanup_eligible(word, signed_floor):
    if not 0 <= word < (1 << 64):
        raise ValueError('word out of range')
    signed = word if word < (1 << 63) else word - (1 << 64)
    return word != 0 and signed >= signed_floor


def model_pair_insert(keys):
    """Abstract two-record normal-flow model; source values identify original positions."""
    if len(keys) != 2 or any(not 0 <= key <= 255 for key in keys):
        raise ValueError('model requires two byte keys')
    records = [(keys[0], 0), (keys[1], 1)]
    if records[1][0] < records[0][0]:
        records[0], records[1] = records[1], records[0]
    if records[0][0] == records[1][0]:
        return [records[1]]
    return records


def tsv(fieldnames, rows):
    stream = io.StringIO(newline='')
    writer = csv.DictWriter(stream, fieldnames=fieldnames, delimiter='\t', lineterminator='\n')
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue().encode('utf-8')


def collect(data):
    verify_digest(data)
    image = Image(data)
    _, fdes = eh_frame_records(data, image.sections)
    fde_map = {}
    for fde in fdes:
        fde_map.setdefault(fde['start'], []).append(fde)
    functions, exceptions, lsda_headers = [], [], []
    for name, start, end, digest in FUNCTIONS:
        candidates = fde_map.get(start, [])
        if len(candidates) != 1 or candidates[0]['end'] != end:
            raise ValueError('selected FDE changed')
        body = checked_body(image, start, end, digest)
        fde = candidates[0]
        functions.append({'name': name, 'start_va': hex(start), 'end_va': hex(end),
                          'start_file_offset': hex(image.offset(start, 1)),
                          'size': len(body), 'body_sha256': digest, 'body_hex': body.hex(),
                          'fde_va': hex(fde['fde']),
                          'lsda_va': hex(fde['lsda']) if fde['lsda'] is not None else None})
        header, entries = exception_table(image, fde)
        if header is not None:
            lsda_headers.append(header)
            exceptions.extend(entries)
    windows = []
    for label, address, hexbytes in PINS:
        raw = image.expect(address, bytes.fromhex(hexbytes))
        if not any(start <= address and address + len(raw) <= end for _, start, end, _ in FUNCTIONS):
            raise ValueError('selected window lies outside selected FDEs')
        windows.append({'label': label, 'va': hex(address), 'file_offset': hex(image.offset(address, len(raw))),
                        'size': len(raw), 'raw_hex': raw.hex()})
    transfers = []
    for label, address, opcode, target in TRANSFERS:
        raw, resolved = checked_transfer(image, address, opcode, target)
        transfers.append({'label': label, 'va': hex(address), 'file_offset': hex(image.offset(address, len(raw))),
                          'raw_hex': raw.hex(), 'target_va': hex(resolved)})
    refs = []
    for label, address, opcode, target in RIP_REFS:
        raw, resolved = checked_rel32(image, address, opcode, target)
        refs.append({'label': label, 'va': hex(address), 'file_offset': hex(image.offset(address, len(raw))),
                     'raw_hex': raw.hex(), 'target_va': hex(resolved)})
    relocations = parse_relocations(image, RELOCATIONS)
    templates = [parse_template(image, 0x1f3db9, b'/hyperliquid_data/db_hub'),
                 parse_template(image, 0x1ea808, b'/hyperliquid_data/no_db_hub'),
                 parse_template(image, 0x1ea44d, b'')]
    diagnostic_length = struct.unpack_from('<I', image.read(0x4addafb, 5), 1)[0]
    diagnostic = image.read(0x706a56, diagnostic_length)
    if diagnostic != b'a Display implementation returned an error unexpectedly':
        raise ValueError('selected format-failure diagnostic changed')
    marker = struct.unpack_from('<Q', image.read(0x15861e2, 10), 2)[0]
    floor = struct.unpack_from('<q', image.read(0x4addb38, 10), 2)[0]
    start = struct.unpack_from('<i', image.read(0x4adda70, 9), 5)[0]
    stop = struct.unpack_from('<i', image.read(0x4adda79, 9), 5)[0]
    keybytes = image.read(0x4adda82, 7)[5:]
    if marker != (1 << 63) + 1 or floor != -(1 << 63) + 2 or (start, stop, keybytes) != (0, 2, b'\x00\x01'):
        raise ValueError('selector or two-key setup differs')
    inputs = [0, 1, (1 << 63) - 1, 1 << 63, marker, marker + 1, (1 << 64) - 1]
    scenarios = [{'word': hex(value), 'route': selector_case(value, marker),
                  'cleanup_eligible': signed_cleanup_eligible(value, floor)} for value in inputs]
    pairs = [list(keybytes), list(reversed(keybytes)), [keybytes[0], keybytes[0]]]
    models = [{'input_keys': list(pair), 'output_key_source_pairs': model_pair_insert(pair)} for pair in pairs]
    # This is a conditional transfer model for the two distinct records. All
    # offsets and the stride below come from the already validated instructions.
    insert = image.read(0x428f7f8, 21)
    key_base, pointer_base, pointer_scale = insert[12], insert[17], 1 << (insert[16] >> 6)
    count_offset = insert[7]
    root_init = image.read(0x489da22, 13)
    initial_count = struct.unpack_from('<H', root_init, 11)[0]
    root_size = struct.unpack_from('<I', image.read(0x489da0e, 5), 1)[0]
    writes = []
    for index, (key, source_index) in enumerate(model_pair_insert(keybytes)):
        writes.append({'step': index, 'key': key, 'source_record': source_index,
                       'leaf_count_before': initial_count + index,
                       'leaf_count_after': initial_count + index + 1,
                       'key_byte_offset': hex(key_base + index),
                       'pointer_word_offset': hex(pointer_base + index * pointer_scale)})
    summary = {'artifact': ARTIFACT.as_posix(), 'artifact_size': len(data), 'artifact_sha256': EXPECTED_SHA256,
               'coordinate_system': 'linked ELF virtual addresses and file offsets',
               'function_count': len(functions), 'pin_count': len(windows),
               'transfer_count': len(transfers), 'rip_reference_count': len(refs),
               'relocation_count': len(relocations), 'template_count': len(templates),
               'exception_table_count': len(lsda_headers), 'exception_site_count': len(exceptions),
               'scope': 'Selected static path and conditional models; no target execution or whole-function equivalence.'}
    evidence = {'summary': summary, 'functions': functions, 'relocations': relocations,
                'templates': templates,
                'format_failure_diagnostic': {'va': hex(0x706a56),
                                              'file_offset': hex(image.offset(0x706a56, diagnostic_length)),
                                              'length': diagnostic_length, 'raw_hex': diagnostic.hex(),
                                              'text': diagnostic.decode('ascii')},
                'lsda_headers': lsda_headers,
                'selector_scenarios_are_inferences': scenarios, 'two_record_models_are_inferences': models,
                'two_record_leaf_model_is_inference': {'root_allocation_size': root_size,
                    'count_word_offset': hex(count_offset), 'initial_count': initial_count,
                    'pointer_stride': pointer_scale, 'writes': writes}}
    output = {
        'evidence.json': (json.dumps(evidence, indent=2, ensure_ascii=True) + '\n').encode('utf-8'),
        'windows.tsv': tsv(('label','va','file_offset','size','raw_hex'), windows),
        'transfers.tsv': tsv(('label','va','file_offset','raw_hex','target_va'), transfers),
        'rip-references.tsv': tsv(('label','va','file_offset','raw_hex','target_va'), refs),
        'exceptions.tsv': tsv(('function_va','entry_file_offset','start_va','end_va','landing_va','action_index','raw_hex'), exceptions),
    }
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    results = collect((ROOT / ARTIFACT).read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    for name in sorted(results):
        (args.out / name).write_bytes(results[name])
    print('Generated %d deterministic evidence files.' % len(results))


if __name__ == '__main__':
    main()
