#!/usr/bin/env python3
"""Extract a bounded AgentTracker snapshot read/write path from node 94 ELF bytes."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import fde_extents

BINARY = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
FUNCTIONS = {
    0x1deb090: ('nonce_pair_writer', 0x1debeea, '16b78435bbf18d88411e72365df1c1e51fd75788f0656ae22ac4d55e55bb2ce5'),
    0x1e2e9b0: ('nonce_pairs_writer', 0x1e2ec3b, '2d8846e09c257f79f31978490e1409616650967ddcdfd7451ee2b6cd8f76b08b'),
    0x1fe1cf0: ('nonce_pair_orderer', 0x1fe2505, '3a3cfb4165b4a0d76f412c0dd002628a0962b76929bbeb89b0340b3316951998'),
    0x2028520: ('nonce_field_writer', 0x202860b, '86dd4e9975abae795d0af92d3817754be1b4eccf491158c2e499c2c9b1870c02'),
    0x256e240: ('nonce_pairs_collect', 0x256e476, '507eb52aac3050677533e081624412143ae565a88d6c23bf3923a325b8c746f8'),
    0x230d1b0: ('generic_writer', 0x230d3a6, '42307b51c300bb7527756c71d71d51b252c172039b6eb8c76339b1e65ae6ae25'),
    0x230d3b0: ('text_writer', 0x230d6b7, '02ded28fe6513392dd13e59e6571a0fc782771a152040388e3e624bd41c7442e'),
    0x23d1f80: ('last_text_field', 0x23d2049, 'cf31d7d14ac6357162212882358b8d6749400276d25b7cc35ad8ee00f134c09e'),
    0x2d9e1e0: ('binary_reader', 0x2da0caf, 'b4f27f05d777cb9c72f5852d7063c72d70ce90f030a823168662042978067410'),
    0x31b0240: ('json_reader', 0x31b2e55, '14096e519fdf201649baa579a4763bb8d217a69714153009278b169de3be915a'),
    0x341e2f0: ('binary_key_classifier', 0x341e416, 'a29386e455ceb8a9466672980bf74d662beeac2ea319b752f70d85f5b40229f8'),
    0x341e420: ('json_key_classifier', 0x341e546, 'a9fff3bc3fd3c3302cce224723bc5d15fcc15f3e3bab17b5f04c753e2d54f56f'),
}
# Sites are manually inspected instruction starts, not results of an opcode scan.
# Row order is the serializer's order and the classifier's tag order.
FIELDS = (
    (0x230d22c, 0x230d255, 0x230d264, 0x2da0388, 0x2da039e, 0x2da0a67, 0x31b04af, 0x31b2437),
    (0x230d271, 0x230d29b, 0x230d2a5, 0x2da0660, 0x2da0676, 0x2da0b94, 0x31b060c, 0x31b22ed),
    (0x230d2b2, 0x230d2dc, 0x230d2e6, 0x2da04f4, 0x2da050a, 0x2da0a15, 0x31b0560, 0x31b2248),
    (0x230d2f3, 0x230d31c, 0x230d326, 0x2da05aa, 0x2da05c0, 0x2da0ab9, 0x31b05b6, 0x31b2392),
    (0x230d32f, 0x230d35b, 0x230d365, 0x2da043b, 0x2da0451, 0x2da0b0b, 0x31b050a, 0x31b24d7),
)
OFFSETS = ((0x230d24f, '4c89fe'), (0x230d28f, '498d7730'),
           (0x230d2d0, '498d7760'), (0x230d30d, '498db790000000'),
           (0x230d349, '4981c7c0000000'))
NAMES = ('user_to_main_agent', 'user_to_extra_agents', 'agent_to_user',
         'address_to_nonce_set', 'user_to_pending_agent_removals')
EXPECTED_CHILDREN = (0x202b5e0, 0x202c300, 0x2029f60, 0x2028520, 0x202ab90)
EXPECTED_READERS = (0x2ccfd70, 0x2d30e60, 0x2c67360, 0x2b92ce0, 0x2b2a910)
BINARY_DIAG = (0x577213, 0x577225, 0x577239, 0x577246, 0x57725a)
JSON_DIAG = (0x57db77, 0x57db89, 0x57db9d, 0x57dbaa, 0x57dbbe)
DEBUG_NAME_LEAS = (0x230d402, 0x230d46a, 0x230d4d3, 0x230d53c, 0x23d1f94)
DEBUG_CALLS = (0x230d457, 0x230d4c0, 0x230d529, 0x230d591, 0x23d1fda)
DEBUG_CHILDREN = (0x202b400, 0x202b8b0, 0x202bc70, 0x2028610, 0x202a8c0)
NAME_CALLS = (0x230d23b, 0x230d280, 0x230d2c1, 0x230d302, 0x230d33e)
NAME_FAILURES = (0x230d244, 0x230d289, 0x230d2ca, 0x230d30b, 0x230d347)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify_digest(data):
    require(hashlib.sha256(data).hexdigest() == DIGEST, 'node 94 SHA-256 mismatch')


def at(data, secs, va, size):
    require(isinstance(va, int) and isinstance(size, int) and va >= 0 and size > 0,
            'invalid VA or length')
    matches = [s for s in secs if s['type'] != 8 and s['address'] <= va
               and va + size <= s['address'] + s['size']]
    require(len(matches) == 1, 'VA is not uniquely file-backed')
    sec = matches[0]
    off = sec['offset'] + va - sec['address']
    require(off >= 0 and off + size <= len(data), 'file mapping outside input')
    return bytes(data[off:off + size])


def pin(data, secs, va, expected):
    raw = at(data, secs, va, len(bytes.fromhex(expected)))
    require(raw == bytes.fromhex(expected), f'instruction window changed at {va:#x}: {raw.hex()}')
    return raw


def call(data, secs, va, target):
    raw = at(data, secs, va, 5)
    require(raw[0] == 0xe8, 'expected direct call opcode')
    actual = va + 5 + struct.unpack_from('<i', raw, 1)[0]
    require(actual == target, 'direct call destination changed')
    return {'site': hex(va), 'target': hex(actual), 'bytes': raw.hex()}


def lea(data, secs, va, expected_target=None):
    raw = at(data, secs, va, 7)
    require(raw[0] in (0x48, 0x4c) and raw[1] == 0x8d and raw[2] & 0xc7 == 5,
            'expected RIP-relative LEA')
    target = va + 7 + struct.unpack_from('<i', raw, 3)[0]
    if expected_target is not None:
        require(target == expected_target, 'RIP-relative destination changed')
    return target


def branch(data, secs, va, expected_target, op):
    raw = at(data, secs, va, 6 if len(op) == 2 else 2)
    require(raw.startswith(op), 'conditional opcode changed')
    displacement = struct.unpack_from('<i' if len(op) == 2 else '<b', raw, len(op))[0]
    dest = va + len(raw) + displacement
    require(dest == expected_target, 'conditional branch destination changed')
    return {'site': hex(va), 'target': hex(dest), 'bytes': raw.hex()}


def table(data, secs, va, count, expected):
    raw = at(data, secs, va, count * 4)
    targets = [va + struct.unpack_from('<i', raw, i * 4)[0] for i in range(count)]
    require(targets == list(expected), 'relative dispatch table changed')
    return {'base': hex(va), 'entry_bytes': raw.hex(), 'targets': [hex(x) for x in targets]}


def check_function(data, secs, start, end, expected_hash):
    raw = at(data, secs, start, end - start)
    digest = hashlib.sha256(raw).hexdigest()
    require(digest == expected_hash, 'selected FDE body changed')
    return raw, digest


def load_functions(data, secs, fdes):
    selected = {}
    for start, (role, end, digest) in FUNCTIONS.items():
        found = [f for f in fdes if f['start'] == start]
        require(len(found) == 1 and found[0]['end'] == end, 'missing, duplicate or changed FDE')
        raw, actual = check_function(data, secs, start, end, digest)
        sec = next(s for s in secs if s['type'] != 8 and s['address'] <= start
                   and end <= s['address'] + s['size'])
        selected[role] = {'start': hex(start), 'end_exclusive': hex(end),
                          'fde_va': hex(found[0]['fde']),
                          'file_offset': hex(sec['offset'] + start - sec['address']),
                          'size': len(raw), 'sha256': actual, 'bytes': raw.hex()}
    return selected


def classifier_keys(data, secs):
    # These constants are operands of the fixed, hashed classifier bodies.
    # Agent-to-user is two overlapping immediate qwords; pending has two
    # overlapping vector operands. Verify overlap before joining them.
    first = at(data, secs, 0x341e313, 8)
    last = at(data, secs, 0x341e320, 8)
    require(first[5:] == last[:3], 'overlapping immediate differs')
    pairs = ((0x2048b0, 0x2073c0, 2), (0x2068b0, 0x207a30, 4),
             (0x203f60, 0x205250, 4))
    words = [at(data, secs, a, 16) + at(data, secs, b, n) for a, b, n in pairs]
    x, y = at(data, secs, 0x2048a0, 16), at(data, secs, 0x207060, 16)
    require(x[14:] == y[:2], 'overlapping vector operands differ')
    keys = [words[0], words[1], first + last[3:], words[2], x + y[2:]]
    require([x.decode('ascii') for x in keys] == list(NAMES), 'classifier constants changed')
    return keys


def classify(key, keys):
    return next((i for i, expected in enumerate(keys) if key == expected), len(keys))



def imported_symbol(data, secs, slot, expected):
    """Resolve a selected ELF64 GLOB_DAT relocation through dynsym and dynstr."""
    chosen = {}
    for name, typ in (('.rela.dyn', 4), ('.dynsym', 11), ('.dynstr', 3)):
        rows = [s for s in secs if s['name'] == name and s['type'] == typ]
        require(len(rows) == 1, 'missing or duplicate dynamic section')
        chosen[name] = rows[0]
    rela, syms, strings = (chosen['.rela.dyn'], chosen['.dynsym'], chosen['.dynstr'])
    require(rela['size'] % 24 == 0 and syms['size'] % 24 == 0, 'invalid dynamic entry size')
    found = []
    for offset in range(rela['offset'], rela['offset'] + rela['size'], 24):
        address, info, addend = struct.unpack_from('<QQq', data, offset)
        if address == slot:
            found.append((offset, info, addend))
    require(len(found) == 1, 'relocation slot missing or duplicated')
    offset, info, addend = found[0]
    symbol_index, kind = info >> 32, info & 0xffffffff
    require(kind == 6 and addend == 0 and symbol_index * 24 + 24 <= syms['size'],
            'unexpected relocation kind, addend or symbol index')
    symbol_offset = syms['offset'] + symbol_index * 24
    name_offset = struct.unpack_from('<I', data, symbol_offset)[0]
    require(name_offset < strings['size'], 'dynamic symbol name out of range')
    begin = strings['offset'] + name_offset
    limit = strings['offset'] + strings['size']
    end = data.find(b'\0', begin, limit)
    require(end >= 0, 'unterminated dynamic symbol')
    name = bytes(data[begin:end]).decode('ascii')
    require(name == expected, 'dynamic symbol changed')
    return {'slot': hex(slot), 'kind': kind, 'symbol_index': symbol_index, 'name': name,
            'rela_file_offset': hex(offset), 'symbol_file_offset': hex(symbol_offset),
            'name_file_offset': hex(begin), 'rela_bytes': bytes(data[offset:offset + 24]).hex()}


def indirect_call(data, secs, va, slot):
    raw = at(data, secs, va, 6)
    require(raw[:2] == b'\xff\x15', 'expected indirect RIP-relative call')
    target = va + 6 + struct.unpack_from('<i', raw, 2)[0]
    require(target == slot, 'indirect slot changed')
    return {'site': hex(va), 'slot': hex(target), 'bytes': raw.hex()}


def extract(data):
    verify_digest(data)
    secs = sections(data)
    _, fdes, _ = fde_extents(data)
    functions = load_functions(data, secs, fdes)
    classifier_keys(data, secs)
    binary_dispatch = table(data, secs, 0x51b254, 6,
                            (0x2da0382, 0x2da065a, 0x2da04ee, 0x2da05a4, 0x2da0438, 0x2da070d))
    json_dispatch = table(data, secs, 0x57cbd4, 6,
                          (0x31b04ac, 0x31b0609, 0x31b055d, 0x31b05b3, 0x31b0502, 0x31b065f))
    classifier_dispatch = table(data, secs, 0x58c3c4, 18,
        (0x341e311, 0x341e3fb, 0x341e3fb, 0x341e3fb, 0x341e3fb, 0x341e39d,
         0x341e3fb, 0x341e33e, 0x341e3fb, 0x341e3fb, 0x341e3fb, 0x341e3fb,
         0x341e3fb, 0x341e3fb, 0x341e3fb, 0x341e3fb, 0x341e3fb, 0x341e3d2))
    json_key_dispatch = table(data, secs, 0x58c40c, 18,
                               tuple(int(x, 16) + 0x130 for x in classifier_dispatch['targets']))
    fields = []
    for i, (name_lea, writer_call, writer_guard, binary_guard, binary_call,
            binary_duplicate, json_guard, json_diag_lea) in enumerate(FIELDS):
        literal = lea(data, secs, name_lea)
        length_raw = at(data, secs, name_lea + 7, 5)
        require(length_raw[0] == 0xba, 'field length is not MOV edx, imm32')
        length = struct.unpack_from('<I', length_raw, 1)[0]
        name = at(data, secs, literal, length).decode('ascii')
        require(name == NAMES[i], 'writer field name changed')
        offset_va, offset_bytes = OFFSETS[i]
        offset_raw = pin(data, secs, offset_va, offset_bytes)
        offset = 0 if i == 0 else (offset_raw[-1] if i < 3 else struct.unpack_from('<I', offset_raw, 3)[0])
        require(offset == 0x30 * i, 'writer field offset changed')
        writer_edge = call(data, secs, writer_call, EXPECTED_CHILDREN[i])
        writer_failure = branch(data, secs, writer_guard, 0x230d37b,
                                b'\x75' if i >= 3 else b'\x0f\x85')
        reader_duplicate = branch(data, secs, binary_guard, binary_duplicate, b'\x0f\x85')
        reader_edge = call(data, secs, binary_call, EXPECTED_READERS[i])
        json_dup = branch(data, secs, json_guard, (0x31b23e5, 0x31b229b, 0x31b21f6,
                                                  0x31b2340, 0x31b248a)[i], b'\x0f\x85')
        require(lea(data, secs, binary_duplicate, BINARY_DIAG[i]) == BINARY_DIAG[i], 'binary diagnostic name')
        require(lea(data, secs, json_diag_lea, JSON_DIAG[i]) == JSON_DIAG[i], 'JSON diagnostic name')
        require(at(data, secs, BINARY_DIAG[i], length).decode('ascii') == name and
                at(data, secs, JSON_DIAG[i], length).decode('ascii') == name, 'reader name differs')
        debug_name = lea(data, secs, DEBUG_NAME_LEAS[i])
        require(at(data, secs, debug_name, length).decode('ascii') == name, 'text writer field name differs')
        fields.append({'tag': i, 'name': name, 'name_va': hex(literal), 'name_length': length,
                       'writer_offset': offset, 'offset_instruction': {'va': hex(offset_va), 'bytes': offset_raw.hex()},
                       'writer_call': writer_edge, 'writer_child_failure': writer_failure,
                       'writer_name_call': call(data, secs, NAME_CALLS[i], 0x25aa7f0),
                       'writer_name_failure': branch(data, secs, NAME_FAILURES[i], 0x230d36c,
                                                     b'\x0f\x85' if i < 3 else b'\x75'),
                       'binary_reader_call': reader_edge, 'binary_duplicate_branch': reader_duplicate,
                       'binary_duplicate_name_va': hex(BINARY_DIAG[i]), 'json_duplicate_branch': json_dup,
                       'json_duplicate_name_va': hex(JSON_DIAG[i]), 'text_name_site': hex(DEBUG_NAME_LEAS[i]),
                       'text_child_call': call(data, secs, DEBUG_CALLS[i], DEBUG_CHILDREN[i])})
    # Parent-context edge is a previously published hash-closure call site;
    # it is a byte check, not an additional newly claimed function.
    context = call(data, secs, 0x2816250, 0x230d1b0)
    connections = [call(data, secs, 0x275b9fc, 0x230d3b0),
                   call(data, secs, 0x2abaf62, 0x2d9e1e0),
                   call(data, secs, 0x3183643, 0x31b0240),
                   call(data, secs, 0x2d9f857, 0x385c730),
                   call(data, secs, 0x2d9f988, 0x385c730),
                   call(data, secs, 0x2d9f9f3, 0x385c730),
                   call(data, secs, 0x31b1237, 0x385c730),
                   call(data, secs, 0x31b142a, 0x385c730),
                   call(data, secs, 0x31b1491, 0x385c730),
                   call(data, secs, 0x2028570, 0x256e240),
                   call(data, secs, 0x2028585, 0x1fe1cf0),
                   call(data, secs, 0x20285a8, 0x1e2e9b0),
                   call(data, secs, 0x1e2eb9e, 0x1deb090),
                   call(data, secs, 0x230d1e3, 0x25a8f80),
                   call(data, secs, 0x230d215, 0x25a9bd0),
                   call(data, secs, 0x2da0232, 0x341e2f0),
                   call(data, secs, 0x31b0468, 0x341e420),
                   call(data, secs, 0x230d5af, 0x23d1f80)]
    require(at(data, secs, 0x1df8f3, 15) == b'\x0fmissing field ', 'missing-field template changed')
    require(at(data, secs, 0x1e0fd5, 18) == b'\x11duplicate field `', 'duplicate-field template changed')
    # Full body hashes above bind all surrounding instruction bytes. These
    # selected windows additionally make each reported condition explicit.
    window_specs = (
        ('context_state_offset', 0x275b9c4, '488dbbd0360000'),
        ('nonce_control_group', 0x202853b, '660f6f00660fd7d0f7d2'),
        ('nonce_pair_allocation_stride', 0x256e2b8, '4989df49c1e704'),
        ('nonce_bucket_pair', 0x256e31d, 'f3410fbccc48f7d9488d0c4948c1e1044a8d14294883c2d0498d4c0de848891048894808'),
        ('nonce_small_order_cutoff', 0x1fe1d0c, '4883fe1548897c24080f83f90000004883fd020f82a6060000'),
        ('nonce_small_key_compare', 0x1fe1d75, '4a8b7c2810ba140000004889deff1500c7780385c079c6'),
        ('nonce_writer_map_count', 0x1e2ea0c, '488d7c24404c89fe4489f2e8b4b17700'),
        ('nonce_entry_stride_loop', 0x1e2eb90, '488b5500488b4d084c89f74c89fee8edc4fbff488b4424404839d80f85dffeffff4883c5104c39ed75d6'),
        ('nonce_pair_sequence_marker', 0x1deb284, '488b4c2420488b4908c6040192'),
        ('writer_container_modes', 0x230d1d0, '807a0b007432'),
        ('writer_first_container_count', 0x230d1de, 'ba05000000'),
        ('writer_second_container_count', 0x230d210, 'ba05000000'),
        ('writer_result_sentinel', 0x230d1c6, '49bc0000000000000080'),
        ('writer_success_sentinel', 0x230d25a, '4d8d6c2404'),
        ('writer_named_mode', 0x230d225, '41807e0b01751e'),
        ('writer_success', 0x230d367, '4c892beb29'),
        ('map_missing_first', 0x2d9f7d7, '48837c2448000f8465eeffff'),
        ('map_default_second', 0x2d9f80f, '48837c2408007436'),
        ('map_missing_third', 0x2d9f88f, '48837c2410000f944424107448'),
        ('map_default_fourth', 0x2d9f89c, '48837c2418000f944424080f84d4000000'),
        ('map_default_fifth', 0x2d9f9bd, '4d85ff742a'),
        ('sequence_count_zero', 0x2d9e7a5, '4585ed0f84e5020000'),
        ('sequence_count_one', 0x2d9e828, '4183fd017566'),
        ('sequence_count_two', 0x2d9e912, '4183fd020f85ae000000'),
        ('sequence_count_three', 0x2d9ea48, '4183fd030f85af000000'),
        ('sequence_count_four', 0x2d9eb7f, '4183fd040f850f040000'),
        ('sequence_remainder', 0x2d9efe3, '418d45fb4889442408'),
        ('sequence_tail_check', 0x2d9ed4e, '488b44240885c00f84020200004129c5'),
        ('json_missing_first', 0x31b1028, '4d85c90f84a6010000'),
        ('json_default_second', 0x31b1031, '4d85db0f84f0010000'),
        ('json_missing_third', 0x31b1272, '4d85e40f944424207442'),
        ('json_default_fourth', 0x31b127c, '4d85ff0f944424080f8499010000'),
        ('json_default_fifth', 0x31b145f, '4d85ed7426'),
        ('json_input_forms', 0x31b02d1, '83ff5b0f847c06000083ff7b0f85df180000'),
        ('binary_short_input', 0x2d9e282, '4883f8020f82db010000'),
    )
    windows = [{'name': name, 'va': hex(va), 'bytes': pin(data, secs, va, code).hex()}
               for name, va, code in window_specs]
    # The two named missing routes and five duplicate routes refer to the
    # same diagnostic templates; resolve their actual RIP displacements.
    diagnostic_refs = []
    for site, target in ((0x2d9e650, 0x577213), (0x2d9e681, 0x1df8f3),
                         (0x2d9f8ec, 0x577239), (0x2d9f920, 0x1df8f3),
                         (0x31b11d7, 0x57db77), (0x31b1211, 0x1df8f3),
                         (0x31b12be, 0x57db9d), (0x31b12f8, 0x1df8f3),
                         (0x2da0a46, 0x1e0fd5), (0x2da0a98, 0x1e0fd5),
                         (0x2da0aea, 0x1e0fd5), (0x2da0b3c, 0x1e0fd5),
                         (0x2da0bc5, 0x1e0fd5), (0x31b2282, 0x1e0fd5),
                         (0x31b2327, 0x1e0fd5), (0x31b23cc, 0x1e0fd5),
                         (0x31b2471, 0x1e0fd5), (0x31b2511, 0x1e0fd5)):
        diagnostic_refs.append({'site': hex(site), 'target': hex(lea(data, secs, site, target)),
                                'bytes': at(data, secs, site, 7).hex()})
    imported = imported_symbol(data, secs, 0x576e488, 'memcmp')
    comparator_calls = [indirect_call(data, secs, site, 0x576e488) for site in
                        (0x1fe1d82, 0x1fe1dc2, 0x1fe1e05, 0x1fe205a, 0x1fe2100)]
    return {'target_sha256': hashlib.sha256(data).hexdigest(),
            'coordinates': 'linked ELF virtual addresses; FDE ends exclusive',
            'functions': functions, 'fields': fields, 'binary_dispatch': binary_dispatch,
            'json_dispatch': json_dispatch, 'binary_classifier_length_dispatch': classifier_dispatch,
            'json_classifier_length_dispatch': json_key_dispatch, 'context_call': context,
            'connections': connections, 'windows': windows, 'diagnostic_references': diagnostic_refs,
            'nonce_comparator_import': imported, 'nonce_comparator_calls': comparator_calls,
            'limitations': 'Selected static paths only; FDEs are unwind extents, no execution or full codec claim.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = extract(BINARY.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'evidence.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
