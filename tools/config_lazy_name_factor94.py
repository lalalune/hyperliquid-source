#!/usr/bin/env python3
"""Extract the #94 lazy-name cell handoff and its name-indexed float selector.

All addresses are linked ELF VAs.  This tool reads captured bytes only; it
never executes the captured program or invokes a disassembler.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records

SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SIZE = 91774280
BINARY = ROOT / 'artifacts/node/94/hl-node'
TABLE = 0x218640
DOMAIN = 76  # established valid discriminant domain, not an observed bounds check
TABLE_SHA256 = '360b7dfc5dda096fc2591ce5b6067d8ecb239d2776f00a6549f965477452f47c'
CONFIG_GOT = 0x576e928
CONFIG_CELL = 0x577b288
ONCE_WORD = CONFIG_CELL + 0x50
VTABLE = 0x567b210
DESCRIPTORS = 0x5668288
NAME_CONTEXT = (
    (32, 0x2180ff, b'NvTestnet'),
    (33, 0x218108, b'NvTestnet2'),
    (34, 0x218112, b'NvMainnet'),
    (35, 0x21811b, b'NvMainnet2'),
)

FUNCTIONS = (
    ('factor_reader', 0x1402750, 0x14027a9, '45071242c24504d99f97d021bdfff1a85dd5ba33169fda29785689d53f7a0a0f'),
    ('once_callback_slot_20', 0x164c560, 0x164c5c6, '7463761f9d515bf0769be9a6f7f9bf7bdfce2fd25166eec441a016e8286cb440'),
    ('once_callback_slot_18', 0x164c5d0, 0x164c636, 'be2286191d2f05781f602d159df5a6aa73f29eaf68a1baf5f93283a863b32e67'),
)

# Fully specified encodings at known starts; branch and RIP targets are also
# decoded independently below.  These are not a general x86 instruction parser.
READER_FACTS = (
    ('global_got', 0x1402755, '488b1dccc13604'),
    ('once_word_load', 0x140275c, '8b4350'),
    ('once_word_test', 0x140275f, '85c0'),
    ('once_word_nonzero_branch', 0x1402761, '7516'),
    ('name_byte_load', 0x1402763, '0fb64348'),
    ('factor_table_address', 0x1402767, '488d0dd25ee1fe'),
    ('factor_indexed_load', 0x140276e, 'f20f1004c1'),
    ('reader_return', 0x1402773, '4883c4105bc3'),
    ('context_setup', 0x1402779, '48891c244889e04889442408'),
    ('once_word_address', 0x1402785, '488d7b50'),
    ('callback_vtable_address', 0x1402789, '488d0d808a2704'),
    ('once_location_address', 0x1402790, '4c8d05a18a2704'),
    ('context_and_force_argument', 0x1402797, '488d542408be01000000'),
    ('once_call', 0x14027a1, 'ff1511c13604'),
    ('resume_name_load', 0x14027a7, 'ebba'),
)
CALLBACK_FACTS = (
    ('context_address_load', 0x05, '488b07'),
    ('cell_pointer_take', 0x08, '488b18'),
    ('clear_context_slot', 0x0b, '48c70000000000'),
    ('cell_pointer_test', 0x12, '4885db'),
    ('null_branch', 0x15, '743c'),
    ('state_byte_compare', 0x17, '807e0401'),
    ('state_byte_branch', 0x1b, '7443'),
    ('initializer_result_address', 0x1d, '4889e7'),
    ('initializer_indirect_call', 0x20, 'ff13'),
    ('copy_64_through_79', 0x22, '0f104424400f114340'),
    ('load_other_chunks', 0x2b, '0f1004240f104c24100f105424200f105c2430'),
    ('store_48_through_63', 0x3e, '0f115b30'),
    ('store_32_through_47', 0x42, '0f115320'),
    ('store_16_through_31', 0x46, '0f114b10'),
    ('store_0_through_15', 0x4a, '0f1103'),
    ('callback_return', 0x4d, '4883c4505bc3'),
)
SLOTS = (
    ('slot_18_callback', 0x567b228, 0x164c5d0),
    ('slot_20_callback', 0x567b230, 0x164c560),
    ('null_failure_target', 0x576e470, 0x157a9f0),
    ('state_failure_target', 0x576e868, 0x4eeb4c0),
    ('once_target', 0x576e8b8, 0x4ee3b20),
    ('config_cell', 0x576e928, 0x577b288),
    ('factor_reader', 0x576efa8, 0x1402750),
    ('config_initializer', 0x577b288, 0x164ff00),
)


def verify_identity(data):
    if len(data) != SIZE or hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError('node #94 size or SHA-256 mismatch')


def va_offset(data, secs, va, size=1):
    if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
        raise ValueError('invalid VA or size')
    hits = [s for s in secs if s['type'] != 8 and s['address'] <= va
            and va + size <= s['address'] + s['size']]
    if len(hits) != 1:
        raise ValueError('address lacks one file-backed section')
    s = hits[0]
    off = s['offset'] + va - s['address']
    if off < 0 or off + size > len(data):
        raise ValueError('file-backed range exceeds input')
    return off


def read_va(data, secs, va, size):
    off = va_offset(data, secs, va, size)
    return bytes(data[off:off + size])


def unique_section(secs, name):
    rows = [s for s in secs if s['name'] == name and s['type'] != 8]
    if len(rows) != 1:
        raise ValueError('missing or ambiguous file-backed section')
    return rows[0]


def selected_relocations(data, secs, wanted):
    sec = unique_section(secs, '.rela.dyn')
    if sec['size'] % 24 or sec['offset'] + sec['size'] > len(data):
        raise ValueError('malformed relocation section')
    found = {}
    for p in range(sec['offset'], sec['offset'] + sec['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, p)
        if slot not in wanted:
            continue
        if slot in found or info != 8:
            raise ValueError('ambiguous or non-relative selected relocation')
        found[slot] = {'slot': slot, 'type': info, 'addend': addend,
                       'rela_file_offset': p}
    if set(found) != set(wanted):
        raise ValueError('missing selected relocation')
    return found


def check_slot_targets(rels):
    for label, slot, addend in SLOTS:
        if slot not in rels or rels[slot]['addend'] != addend:
            raise ValueError('relocation target mismatch: ' + label)


def short_target(va, ins):
    if len(ins) != 2 or ins[0] not in (0x74, 0x75, 0xeb):
        raise ValueError('unsupported short branch')
    return va + 2 + struct.unpack('<b', ins[1:])[0]


def rip_target(va, ins):
    if not ((len(ins) == 7 and ins[:2] in (b'\x48\x8b', b'\x48\x8d', b'\x4c\x8d'))
            or (len(ins) == 6 and ins[:2] == b'\xff\x15')):
        raise ValueError('unsupported RIP-relative instruction')
    return va + len(ins) + struct.unpack('<i', ins[-4:])[0]


def check_fact(data, secs, label, va, expected_hex):
    expected = bytes.fromhex(expected_hex)
    observed = read_va(data, secs, va, len(expected))
    if observed != expected:
        raise ValueError('instruction contract mismatch: ' + label)
    return {'label': label, 'va': va, 'offset': va_offset(data, secs, va, len(expected)),
            'bytes': observed.hex()}


def check_code(data, secs):
    rows = [check_fact(data, secs, name, va, hx) for name, va, hx in READER_FACTS]
    for label, base in (('slot20', 0x164c560), ('slot18', 0x164c5d0)):
        for name, delta, hx in CALLBACK_FACTS:
            rows.append(check_fact(data, secs, label + '_' + name, base + delta, hx))
    return rows


def branches(data, secs):
    specs = (
        ('reader_state_nonzero', 0x1402761, 0x1402779),
        ('reader_resume', 0x14027a7, 0x1402763),
        ('slot20_null', 0x164c575, 0x164c5b3),
        ('slot20_state_byte_one', 0x164c57b, 0x164c5c0),
        ('slot18_null', 0x164c5e5, 0x164c623),
        ('slot18_state_byte_one', 0x164c5eb, 0x164c630),
    )
    rows = []
    for label, site, expected in specs:
        ins = read_va(data, secs, site, 2)
        dest = short_target(site, ins)
        if dest != expected:
            raise ValueError('branch target mismatch: ' + label)
        rows.append({'label': label, 'site': site, 'target': dest, 'bytes': ins.hex()})
    return rows


def failure_returns(data, secs):
    # These are conditional on an indirect helper returning normally; they do
    # not assert either helper's runtime return or exception behavior.
    specs = (
        ('slot20_null_helper', 0x164c5ba, 0x164c5c0, 0x576e470, 'ff15a2221204'),
        ('slot20_state_helper', 0x164c5c0, 0x164c5c6, 0x576e868, 'cc'),
        ('slot18_null_helper', 0x164c62a, 0x164c630, 0x576e470, 'ff1532221204'),
        ('slot18_state_helper', 0x164c630, 0x164c636, 0x576e868, 'cc'),
    )
    rows = []
    for label, site, continuation, target, following_hex in specs:
        call = read_va(data, secs, site, 6)
        following = read_va(data, secs, continuation, len(bytes.fromhex(following_hex)))
        if (site + len(call) != continuation or rip_target(site, call) != target
                or following.hex() != following_hex):
            raise ValueError('failure helper continuation mismatch: ' + label)
        rows.append({'label': label, 'call': site, 'target_slot': target,
                     'continuation': continuation, 'following': following.hex()})
    return rows


def factor_bits(data, secs):
    raw = read_va(data, secs, TABLE, 8 * DOMAIN)
    if hashlib.sha256(raw).hexdigest() != TABLE_SHA256:
        raise ValueError('factor table hash mismatch')
    words = [struct.unpack_from('<Q', raw, i * 8)[0] for i in range(DOMAIN)]
    allowed = {0x3ff0000000000000, 0x4014000000000000}
    if set(words) != allowed or words[32] != 0x4014000000000000:
        raise ValueError('unexpected factor table')
    return words


def factor_at(words, index):
    # This is a research-domain guard, not an assertion that machine code checks it.
    if type(index) is not int or not 0 <= index < DOMAIN or len(words) != DOMAIN:
        raise ValueError('index outside established valid domain')
    return struct.unpack('<d', struct.pack('<Q', words[index]))[0]


def factor_runs(words):
    out = []
    start = 0
    for i in range(1, len(words) + 1):
        if i == len(words) or words[i] != words[start]:
            out.append({'first': start, 'end_exclusive': i,
                        'factor': int(factor_at(words, start)), 'bits': words[start]})
            start = i
    return out


def fde_rows(data, secs):
    _, fdes = eh_frame_records(data, secs)
    rows = []
    for label, start, end, expected_hash in FUNCTIONS:
        matched = [f for f in fdes if f['start'] == start]
        if len(matched) != 1 or matched[0]['end'] != end:
            raise ValueError('selected FDE missing, duplicated or changed')
        f = matched[0]
        code = read_va(data, secs, start, end - start)
        section = next(s for s in secs if s['type'] != 8 and s['address'] <= start
                       and end <= s['address'] + s['size'])
        if not section['flags'] & 4 or hashlib.sha256(code).hexdigest() != expected_hash:
            raise ValueError('selected executable body mismatch')
        rows.append({'label': label, 'start': start, 'end': end,
                     'file_offset': va_offset(data, secs, start, end - start),
                     'fde': f['fde'], 'cie': f['cie'], 'lsda': f['lsda'],
                     'size': len(code), 'sha256': expected_hash, 'body': code.hex()})
    return rows


def cell_context(data, secs):
    # A RELATIVE relocation supplies the initial function pointer at load time.
    if read_va(data, secs, CONFIG_CELL, 8) != bytes(8):
        raise ValueError('unexpected pre-relocation cell bytes')
    initial_word = struct.unpack('<I', read_va(data, secs, ONCE_WORD, 4))[0]
    if initial_word != 3:
        raise ValueError('unexpected initial once word')
    head = struct.unpack('<QQQ', read_va(data, secs, VTABLE, 24))
    if head != (0, 8, 8):
        raise ValueError('unexpected callback vtable head')
    return initial_word, head


def name_contexts(data, secs, rels, words):
    contexts = []
    for index, expected_pointer, expected_name in NAME_CONTEXT:
        slot = DESCRIPTORS + 16 * index
        if slot not in rels:
            raise ValueError('name descriptor relocation missing')
        pointer = rels[slot]['addend']
        name_length = struct.unpack('<Q', read_va(data, secs, slot + 8, 8))[0]
        name = read_va(data, secs, pointer, name_length)
        if pointer != expected_pointer or name != expected_name:
            raise ValueError('name context mismatch')
        contexts.append({'index': index, 'descriptor': slot, 'name_va': pointer,
                         'name_length': name_length, 'name': name.decode('ascii'),
                         'factor': factor_at(words, index)})
    return contexts


def build(data):
    verify_identity(data)
    secs = sections(data)
    funcs = fde_rows(data, secs)
    facts = check_code(data, secs)
    edges = branches(data, secs)
    failure_continuations = failure_returns(data, secs)
    descriptor_slots = {DESCRIPTORS + 16 * index for index, _, _ in NAME_CONTEXT}
    rels = selected_relocations(data, secs, {slot for _, slot, _ in SLOTS} | descriptor_slots)
    check_slot_targets(rels)
    initial_word, vtable_head = cell_context(data, secs)
    rip_sites = ((0x1402755, 7, CONFIG_GOT), (0x1402767, 7, TABLE),
                 (0x1402789, 7, VTABLE), (0x1402790, 7, 0x567b238),
                 (0x14027a1, 6, 0x576e8b8),
                 (0x164c5b3, 7, 0x567b250), (0x164c5ba, 6, 0x576e470),
                 (0x164c5c0, 6, 0x576e868),
                 (0x164c623, 7, 0x567b250), (0x164c62a, 6, 0x576e470),
                 (0x164c630, 6, 0x576e868))
    refs = []
    for site, n, expected in rip_sites:
        ins = read_va(data, secs, site, n)
        dest = rip_target(site, ins)
        if dest != expected:
            raise ValueError('RIP target mismatch')
        refs.append({'site': site, 'target': dest, 'bytes': ins.hex()})
    words = factor_bits(data, secs)
    contexts = name_contexts(data, secs, rels, words)
    one = sum(w == 0x3ff0000000000000 for w in words)
    five = sum(w == 0x4014000000000000 for w in words)
    result = {
        'target': {'release': 94, 'size': len(data), 'sha256': SHA256},
        'domain': {'first': 0, 'end_exclusive': len(words),
                   'basis': 'prior discriminant inventory; selector has no local bounds check'},
        'table': {'va': TABLE, 'byte_count': len(words) * 8,
                  'sha256': hashlib.sha256(read_va(data, secs, TABLE, len(words) * 8)).hexdigest(),
                  'factor_1_count': one, 'factor_5_count': five,
                  'factor_at_0': factor_at(words, 0), 'factor_at_32': factor_at(words, 32),
                  'factor_at_34': factor_at(words, 34), 'factor_at_75': factor_at(words, 75)},
        'context': {'config_got': CONFIG_GOT, 'config_cell': CONFIG_CELL,
                    'initial_once_word_va': ONCE_WORD, 'initial_once_word': initial_word,
                    'callback_vtable': VTABLE, 'callback_vtable_head': list(vtable_head),
                    'default_descriptor_va': contexts[0]['descriptor'],
                    'default_name_va': contexts[0]['name_va'],
                    'default_name_length': contexts[0]['name_length'],
                    'default_name': contexts[0]['name'], 'default_discriminant': contexts[0]['index']},
        'selected': {'functions': len(funcs), 'fact_windows': len(facts),
                     'short_branches': len(edges), 'rip_references': len(refs),
                     'relocations': len(rels),
                     'failure_return_sites': len(failure_continuations)},
        'limitations': ['FDE ranges are not a function census',
                        'the prior Once and configuration initializer bodies are external boundaries',
                        'no target instructions are executed',
                        'table bytes outside the established 76-value domain are not interpreted'],
    }
    return funcs, facts, edges, refs, rels, factor_runs(words), failure_continuations, contexts, result


def save_tsv(path, header, rows):
    with path.open('w', encoding='utf-8', newline='') as out:
        writer = csv.writer(out, delimiter='\t', lineterminator='\n')
        writer.writerow(header)
        writer.writerows(rows)


def generate(data, out):
    funcs, facts, edges, refs, rels, runs, failure_continuations, contexts, summary = build(data)
    out.mkdir(parents=True, exist_ok=True)
    hx = lambda value: '' if value is None else hex(value)
    save_tsv(out / 'functions.tsv',
             ('label', 'start_va', 'end_exclusive_va', 'file_offset', 'fde_va', 'cie_va', 'lsda_va', 'size', 'sha256', 'body_hex'),
             ((x['label'], hx(x['start']), hx(x['end']), hx(x['file_offset']), hx(x['fde']),
               hx(x['cie']), hx(x['lsda']), x['size'], x['sha256'], x['body']) for x in funcs))
    save_tsv(out / 'instructions.tsv', ('label', 'va', 'file_offset', 'bytes'),
             ((x['label'], hx(x['va']), hx(x['offset']), x['bytes']) for x in facts))
    save_tsv(out / 'branches.tsv', ('label', 'site_va', 'target_va', 'bytes'),
             ((x['label'], hx(x['site']), hx(x['target']), x['bytes']) for x in edges))
    save_tsv(out / 'rip-references.tsv', ('site_va', 'target_va', 'bytes'),
             ((hx(x['site']), hx(x['target']), x['bytes']) for x in refs))
    save_tsv(out / 'relocations.tsv', ('slot_va', 'type', 'addend_va', 'record_file_offset'),
             ((hx(k), v['type'], hx(v['addend']), hx(v['rela_file_offset'])) for k, v in sorted(rels.items())))
    save_tsv(out / 'factor-runs.tsv', ('first_index', 'end_exclusive', 'factor', 'binary64_bits'),
             ((x['first'], x['end_exclusive'], x['factor'], hx(x['bits'])) for x in runs))
    save_tsv(out / 'failure-returns.tsv',
             ('label', 'call_va', 'target_slot_va', 'return_va', 'following_bytes'),
             ((x['label'], hx(x['call']), hx(x['target_slot']),
               hx(x['continuation']), x['following']) for x in failure_continuations))
    save_tsv(out / 'name-context.tsv', ('index', 'descriptor_va', 'name_va', 'length', 'name', 'factor'),
             ((x['index'], hx(x['descriptor']), hx(x['name_va']), x['name_length'],
               x['name'], int(x['factor'])) for x in contexts))
    (out / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return summary


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, required=True)
    args = p.parse_args()
    summary = generate(BINARY.read_bytes(), args.out)
    print('ok functions={} facts={} branches={} factors={}'.format(
        summary['selected']['functions'], summary['selected']['fact_windows'],
        summary['selected']['short_branches'], summary['domain']['end_exclusive']))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, struct.error) as exc:
        print('config_lazy_name_factor94: ' + str(exc), file=sys.stderr)
        raise SystemExit(1)
