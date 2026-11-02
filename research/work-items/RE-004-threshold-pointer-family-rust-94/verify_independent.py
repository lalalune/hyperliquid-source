"""Portable independent value/ELF review; no imports from the packet, no native execution."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import struct

TARGET = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
STARTS = [0x54d76e0, 0x54d7700, 0x54d7740]
BODIES = [
    'f30f1efa4883f93fba00000000488d05cc2f2900480f47c2c3',
    'f30f1efa488d053b444c008038007420488d15b9844c00803a0175144883f923770e488d05774c2900c3660f1f44000031c0c3',
    'f30f1efa488d05fb434c008038007420488d1579844c00803a0175144881f9c3000000770b488d05944b2900c30f1f0031c0c3',
]
FLAGS = [0x599bb46, 0x599fbd0]
BASES = [0x576a6c0, 0x576c3a0, 0x576c300]
MOD = 1 << 64


def need(condition, message):
    if not condition:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def inspect(repo):
    packet = repo / 'research/work-items/RE-004-threshold-pointer-family-rust-94'
    inputs = gzip.decompress((packet / 'inputs.bin.gz').read_bytes())
    outputs = gzip.decompress((packet / 'expected.bin.gz').read_bytes())
    frozen = json.loads((packet / 'frozen.json').read_text())
    need(len(inputs) % 48 == 0 and len(outputs) * 2 == len(inputs), 'fixture framing')
    # Availability/byte classes are represented by a literal action matrix,
    # independently of the source branch chain and oracle interval membership.
    actions = (('refuse', 'refuse', 'refuse'),
               ('preserve', 'preserve', 'preserve'),
               ('refuse', 'selected', 'zero'))
    pairs = [set(), set(), set()]
    counts = {'cases': 0, 'refusals': 0, 'preserved_rdx': 0, 'selected_nonzero': 0}
    selected_zero = required_after_large_index = 0
    expected_rows = struct.iter_unpack('<QQQ', outputs)
    for number, (row, stored) in enumerate(zip(struct.iter_unpack('<6Q', inputs), expected_rows)):
        member, index, bias, incoming, first, second = row
        need(member < 3 and first <= 256 and second <= 256, 'descriptor domain')
        if first < 256 and second < 256:
            pairs[member].add((first, second))
        a = 0 if first == 256 else 1 if first == 0 else 2
        b = 0 if second == 256 else 1 if second == 1 else 2
        action = 'plain' if member == 0 else actions[a][b]
        # Unsigned comparison via carry out of unbounded addition, avoiding
        # either <= or range membership used in the implementations under review.
        inside = (index + MOD - [64, 36, 196][member]) // MOD == 0
        if action == 'refuse':
            want = (0, 0, 0)
        else:
            selected = action in ('plain', 'selected') and inside
            rax = (bias + BASES[member]) % MOD if selected else 0
            rdx = {'plain': 0, 'preserve': incoming,
                   'selected': (bias + FLAGS[1]) % MOD,
                   'zero': (bias + FLAGS[1]) % MOD}[action]
            want = (1, rax, rdx)
            selected_zero += selected and rax == 0
        need(stored == want, f'independent fixture mismatch {number}')
        counts['cases'] += 1
        counts['refusals'] += action == 'refuse'
        counts['preserved_rdx'] += action == 'preserve'
        counts['selected_nonzero'] += want[1] != 0
        required_after_large_index += member != 0 and a == 2 and b == 0 and not inside
    need(all(len(x) == 65536 for x in pairs), 'complete flag products')
    need(all(frozen[key] == value for key, value in counts.items()), 'frozen counts')
    need(digest(inputs) == frozen['inputs_sha256'] and digest(outputs) == frozen['expected_sha256'], 'frozen hashes')
    need(selected_zero > 0 and required_after_large_index > 0, 'zero-address/read-order witnesses')

    binary = (repo / 'artifacts/node/94/hl-node').read_bytes()
    need(len(binary) == 91774280 and digest(binary) == TARGET, 'complete target')
    shoff = struct.unpack_from('<Q', binary, 40)[0]
    shsize, shnum, strindex = struct.unpack_from('<HHH', binary, 58)
    need(shsize == 64, 'ELF64 section size')
    sections = [struct.unpack_from('<IIQQQQIIQQ', binary, shoff + i * 64) for i in range(shnum)]
    names_section = sections[strindex]
    names = binary[names_section[4]:names_section[4] + names_section[5]]
    def section_name(section):
        return names[section[0]:].split(b'\0', 1)[0].decode()
    def mapped(address, length):
        found = [s for s in sections if s[1] != 8 and s[3] <= address and address + length <= s[3] + s[5]]
        need(len(found) == 1, 'unique file-backed range')
        s = found[0]
        offset = s[4] + address - s[3]
        return binary[offset:offset + length], s
    phoff = struct.unpack_from('<Q', binary, 32)[0]
    phsize, phnum = struct.unpack_from('<HH', binary, 54)
    need(phsize == 56, 'ELF64 segment size')
    loads = [struct.unpack_from('<IIQQQQQQ', binary, phoff + i * 56) for i in range(phnum)]
    body_records = []
    for number, (start, body_hex, padding) in enumerate(zip(STARTS, BODIES, [7, 13, 13])):
        expected = bytes.fromhex(body_hex)
        actual, section = mapped(start, len(expected))
        need(actual == expected and section_name(section) == '.text', 'complete original body')
        need(mapped(start + len(expected), padding)[0] == b'\xcc' * padding, 'exact following padding')
        refs = [(13, BASES[0])] if number == 0 else [(4, FLAGS[0]), (16, FLAGS[1]), (34 if number == 1 else 37, BASES[number])]
        for offset, target in refs:
            displacement = struct.unpack_from('<i', actual, offset + 3)[0]
            need(start + offset + 7 + displacement == target, 'actual RIP displacement')
        body_records.append({'start': start, 'bytes': len(actual), 'sha256': digest(actual), 'hex': actual.hex()})
    need(sum(r['bytes'] for r in body_records) == 127, 'full family extent')
    contexts = []
    for address in FLAGS:
        ss = [s for s in sections if s[2] & 2 and s[3] <= address < s[3] + s[5]]
        ps = [s for s in loads if s[0] == 1 and s[3] <= address < s[3] + s[6]]
        need(len(ss) == len(ps) == 1, 'unique global mappings')
        s, program = ss[0], ps[0]
        need(s[1] == 8 and section_name(s) == '.bss' and s[2] & 1, 'writable NOBITS flag')
        need(program[1] & 2 and program[3] + program[5] <= address, 'writable zero-fill tail')
        contexts.append({'address': address, 'section': list(s), 'load': list(program),
                         'has_file_byte': False, 'initial_zero_is_not_runtime_value': True})
    for address in BASES:
        _, s = mapped(address, 1)
        need(section_name(s) == '.data.rel.ro', 'address-only result context')
        need(any(x[0] == 1 and x[3] <= address < x[3] + x[6] for x in loads), 'result load mapping')
    relocations = []
    for s in sections:
        need(s[1] != 9, 'unexpected REL')
        if s[1] == 4:
            need(s[9] == 24 and s[5] % 24 == 0, 'RELA shape')
            for offset in range(s[4], s[4] + s[5], 24):
                record = (offset, *struct.unpack_from('<QQq', binary, offset))
                need(record[2] & 0xffffffff in (1, 6, 7, 8, 18), 'known relocation width')
                relocations.append(record)
    need(len(relocations) == 80300, 'full RELA census')
    naming = [r for r in relocations if r[3] in STARTS]
    need(len(naming) == 3 and sorted(r[3] for r in naming) == STARTS, 'one entry slot per member')
    need(len({r[1] for r in naming}) == 3, 'distinct slots')
    for r in naming:
        offset, address, info, addend = r
        raw, s = mapped(address, 8)
        need(info == 8 and raw == bytes(8) and section_name(s) == '.data.rel.ro', 'RELATIVE raw-zero slot')
        need([q for q in relocations if q[1] < address + 8 and address < q[1] + 8] == [r], 'unique complete slot writer')
    for flag in FLAGS:
        need(not any(r[1] <= flag < r[1] + 8 for r in relocations), 'flag byte writer')
    for r in body_records:
        end = r['start'] + r['bytes'] + [7, 13, 13][STARTS.index(r['start'])]
        need(not any(q[1] < end and r['start'] < q[1] + 8 for q in relocations), 'code/padding writer')

    paths = [repo / 'src/node94-threshold-pointer-family/lib.rs',
             repo / 'src/node94-threshold-pointer-family/input_only_driver.rs',
             packet / 'PROOF.md', packet / 'oracle.py', packet / 'frozen.json',
             packet / 'verify_static.py', packet / 'static.json']
    return {'target_sha256': TARGET, 'reviewed_hashes': {str(x.relative_to(repo)): digest(x.read_bytes()) for x in paths},
            'independent_method': 'Literal availability/byte-class action matrix plus unsigned interval carry-out; struct-only ELF64 section/program/RELA parsing; no packet imports.',
            'fixture_mismatches': 0, **counts, 'flag_pairs_per_member': [len(x) for x in pairs],
            'selected_address_zero_cases': selected_zero, 'missing_second_even_over_bound_cases': required_after_large_index,
            'body_records': body_records, 'bss_contexts': contexts, 'entry_slots': naming,
            'rela_records': len(relocations), 'all_slots_unique_writer': True,
            'native_replay': False, 'captured_execution': False, 'instruction_emulation': False,
            'assessment': 'No blocker: full-width RAX/RDX partition, first-before-second admission, index test after required observations, numeric wrap, and BSS runtime-value distinction are consistent.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path.cwd())
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    result = inspect(args.repo.resolve())
    result['review_script_sha256'] = digest(Path(__file__).read_bytes())
    raw = json.dumps(result, indent=2, sort_keys=True) + '\n'
    if args.out:
        args.out.write_text(raw)
    else:
        print(raw, end='')


if __name__ == '__main__':
    main()
