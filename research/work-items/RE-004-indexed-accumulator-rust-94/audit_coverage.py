"""Reproduce post-freeze coverage counts without changing oracle expectations."""
import json
import struct

from oracle import corpus, expected, MOD, MASK, PACKET
from verify_static import encoded, require


def audit():
    coverage = {key: 0 for key in ['success', 'default_index', 'negative_index', 'minimum_i32',
        'maximum_i32', 'entry_high_bit', 'wrapped_index_field', 'wrapped_entry_addition',
        'wrapped_update_address', 'counter_overflow', 'sum_overflow', 'selector_slot_output_alias',
        'index_field_output_alias', 'base_slot_output_alias']}
    coverage.update(addend_counter_deltas=set(), addend_sum_deltas=set())
    for row in corpus():
        image_base, selector_slot, addend_address, base_slot, _, image = row
        tag, entry = struct.unpack_from('<BQ', expected(row))
        if tag:
            continue
        coverage['success'] += 1
        def read(address, width):
            return int.from_bytes(image[address - image_base:address - image_base + width], 'little')
        pointer = read(selector_slot, 8)
        unsigned = read((pointer + 32) % MOD, 4) if pointer else 13
        index = (unsigned if unsigned < 2 ** 31 else unsigned - 2 ** 32) if pointer else 13
        base, addend = read(base_slot, 8), read(addend_address, 8)
        counter, total = (entry + 176) % MOD, (entry + 64) % MOD
        coverage['default_index'] += pointer == 0
        coverage['negative_index'] += index < 0
        coverage['minimum_i32'] += index == -2 ** 31
        coverage['maximum_i32'] += index == 2 ** 31 - 1
        coverage['entry_high_bit'] += entry >= 2 ** 63
        coverage['wrapped_index_field'] += pointer + 32 >= MOD
        coverage['wrapped_entry_addition'] += not (0 <= base + 8 * index < MOD)
        coverage['wrapped_update_address'] += entry + 176 >= MOD or entry + 64 >= MOD
        coverage['counter_overflow'] += read(counter, 8) == MASK
        coverage['sum_overflow'] += read(total, 8) + addend >= MOD
        for name, address in [('addend_counter_deltas', counter), ('addend_sum_deltas', total)]:
            if abs(addend_address - address) < 8:
                coverage[name].add(addend_address - address)
        def overlaps(address, width):
            return any(address < other + 8 and other < address + width for other in [counter, total])
        coverage['selector_slot_output_alias'] += overlaps(selector_slot, 8)
        coverage['index_field_output_alias'] += bool(pointer) and overlaps((pointer + 32) % MOD, 4)
        coverage['base_slot_output_alias'] += overlaps(base_slot, 8)
    for name in ['addend_counter_deltas', 'addend_sum_deltas']:
        coverage[name] = sorted(coverage[name])
        require(coverage[name] == list(range(-7, 8)), 'partial addend alias coverage')
    coverage['frozen_inputs_sha256'] = json.loads((PACKET / 'frozen.json').read_text())['inputs_sha256']
    coverage['derivation'] = 'read-only coverage audit of frozen admitted inputs; not additional oracle expectations'
    return coverage


if __name__ == '__main__':
    coverage = audit()
    require(encoded(coverage) == (PACKET / 'coverage.json').read_bytes(), 'coverage record drift')
    print(json.dumps({'admitted': coverage['success'], 'negative_index': coverage['negative_index'],
                      'all_addend_overlap_displacements': True}))
