#!/usr/bin/env python3
"""Regenerate static node94 IP-translation evidence; never execute the capture."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records

TARGET = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BODIES = {
    'translation': (0x45c3ae0, 0x45c3d19, 0xee8448,
                    'ff60ec0b1efb2ad914a907a31dbfc67be412340669113cee0edcdc5fcebd9106'),
    'table_initializer': (0x45be020, 0x45be0cf, 0xee72a0,
                          '8fe05167c738bff15969ad81188359ed58f09e8227152e178f612b66e5421a01'),
    'caller': (0x487dcc0, 0x487e2f8, 0x12a0acc,
               '9635b7582b9f8f254ad6b35c9a06d9f3aaf84294c9abd4735af4d7210512e335'),
}

# These are instruction obligations, not a replacement copy of executable code.
# Every line is also independently bound to a complete retained disassembly.
PINS = {
    'low_40_bits': (0x45c3ae9, '48bbffffffffff0000004821fb'),
    'split_octets': (0x45c3af6, '4989de49c1ee0848c1eb10'),
    'odd_tag_bypass': (0x45c3b01, '40f6c701741f'),
    'return_reassembly': (0x45c3b07, '48c1e310410fb6cec1e1084809d9400fb6c74809c8'),
    'mode_split': (0x45c3b26, '4084f6741f'),
    'reverse_10': (0x45c3b2b, '4180fe0a74d6'),
    'reverse_172_192': (0x45c3b31, '410fb6c63dac00000074343dc0000000753f'),
    'reverse_192_168': (0x45c3b43, '80fba87423eb38'),
    'forward_10': (0x45c3b4a, '4180fe0a0f8492000000'),
    'forward_172_192': (0x45c3b54, '410fb6c63dac00000074793dc000000075a1'),
    'forward_192_168': (0x45c3b66, '80fba8747b41b6c0eb97'),
    'reverse_172_mask': (0x45c3b70, '89f8250000f0003d000010000f84b1000000'),
    'reverse_state_gate': (0x45c3b82, '8b05002a1c0185c00f8533010000'),
    'reverse_table_load': (0x45c3b90, '488b0de9291c014885c90f8467ffffff488b05d1291c0148c1e103'),
    'reverse_key': (0x45c3bab, '89dac1e208410fb6f609d631d2'),
    'reverse_loop': (0x45c3bc0, '3b7410040f84880000004883c2084839d175ede92fffffff'),
    'forward_172_mask': (0x45c3bd8, '89f8250000f0003d00001000754d'),
    'forward_state_gate': (0x45c3be6, '8b059c291c0185c00f8579000000'),
    'forward_table_load': (0x45c3bf4, '488b0d85291c014885c90f8403ffffff488b056d291c0148c1e103'),
    'forward_key': (0x45c3c0f, '89dac1e208410fb6f609d631d2'),
    'forward_loop': (0x45c3c20, '3b341074164883c2084839d175f2e9d4feffff'),
    'restore_172': (0x45c3c33, '41b6ace9ccfeffff'),
    'forward_value': (0x45c3c3b, '0fb74c10050fb65c1007c1e31009cb440fb6741004eb14'),
    'reverse_value': (0x45c3c52, '0fb74c10010fb65c1003c1e31009cb440fb63410'),
    'clear_tag_on_match': (0x45c3c66, '31ffe99afeffff'),
    'forward_after_init': (0x45c3cab, '4c89ff488b0dcb281c014885c90f8546ffffffe944feffff'),
    'reverse_after_init': (0x45c3d01, '4c89ff488b0d75281c014885c90f858cfeffffe9eefdffff'),
    'allocate_64': (0x45be024, 'bf40000000ff15a9ff1a014885c00f8487000000'),
    'publish_eight_rows': (0x45be0a7, '48c703080000004889430848c74310080000004889d85bc3'),
    'caller_first_input': (0x487dddf, '8b4a4c8b7a5048c1e7204809cf0fb630e8ec5cd4ff'),
    'caller_first_result': (0x487ddf4, '4989c44180fc027521'),
    'caller_first_store': (0x487de44, '4489601449c1ec2044886018'),
    'caller_later_input': (0x487e1eb, '8b414c8b795048c1e7204809c7488b4424580fb630e8db58d4ff'),
    'caller_later_store': (0x487dec4, '4c89e948c1e920884c101844896c1014'),
}

TABLE = (
    (0x45be038, 'ac1f08942bce2fef', '488908'),
    (0x45be045, 'ac1f080b03735280', '48894808'),
    (0x45be053, 'ac1f008f36fac69f', '48894810'),
    (0x45be061, 'ac1f051e36407387', '48894818'),
    (0x45be06f, 'ac1f03fa12b12ff8', '48894820'),
    (0x45be07d, 'ac1f018e12b62e0c', '48894828'),
    (0x45be08b, 'ac1f0ea72bce9d74', '48894830'),
    (0x45be099, 'ac1f0c232bcf88dc', '48894838'),
)


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Image:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)
        names = [s['name'] for s in self.sections]
        require(len(names) == len(set(names)), 'duplicate section names')

    def off(self, va, size=1):
        found = [s for s in self.sections if s['type'] != 8 and
                 s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(found) == 1, 'ambiguous/unbacked address')
        return found[0]['offset'] + va - found[0]['address']

    def get(self, va, size):
        off = self.off(va, size)
        return self.data[off:off + size]

    def pin(self, va, expected, label):
        raw = bytes.fromhex(expected)
        require(self.get(va, len(raw)) == raw, 'instruction obligation: ' + label)
        return {'va': hex(va), 'file_offset': hex(self.off(va)), 'bytes': expected}

    def relocations(self):
        sec, = [s for s in self.sections if s['name'] == '.rela.dyn']
        require(sec['size'] % 24 == 0, 'partial RELA record')
        records = {}
        for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', self.data, off)
            require(slot not in records, 'duplicate relocation slot')
            records[slot] = (info, addend, off)
        return records


def observe(data, *, body_hashes=True):
    image = Image(data)
    _, fdes = eh_frame_records(data, image.sections)
    ranges = []
    for name, (start, end, fde, digest) in BODIES.items():
        matches = [f for f in fdes if f['start'] == start]
        require(len(matches) == 1 and matches[0]['end'] == end and matches[0]['fde'] == fde,
                'FDE binding: ' + name)
        raw = image.get(start, end - start)
        if body_hashes:
            require(sha(raw) == digest, 'body digest: ' + name)
        ranges.append({'role': name, 'start': hex(start), 'end': hex(end),
                       'file_offset': hex(image.off(start)), 'bytes': len(raw),
                       'sha256': sha(raw), 'fde': hex(fde), 'cie': hex(matches[0]['cie'])})
    obligations = {name: image.pin(va, raw, name) for name, (va, raw) in PINS.items()}
    table = []
    for i, (va, raw, store) in enumerate(TABLE):
        image.pin(va, '48b9' + raw + store, f'initializer row {i}')
        octets = bytes.fromhex(raw)
        table.append({'index': i, 'immediate_instruction': hex(va), 'bytes': raw,
                      'private': '.'.join(map(str, octets[:4])),
                      'public': '.'.join(map(str, octets[4:]))})
    relocs = image.relocations()
    require(not any(target == 0x45c3ae0 for _, target, _ in relocs.values()),
            'unexpected relocation targeting translation helper')
    bindings = []
    for slot, target in [(0x5786570, 0x45be020), (0x576e8b8, 0x4ee3b20),
                         (0x572b048, 0x45bdfd0), (0x572b050, 0x45ac680),
                         (0x572b058, 0x1f87cf)]:
        require(slot in relocs and relocs[slot][:2] == (8, target), 'RELATIVE binding: ' + hex(slot))
        bindings.append({'slot': hex(slot), 'type': 'R_X86_64_RELATIVE', 'addend': hex(target),
                         'record_file_offset': hex(relocs[slot][2])})
    # Both deferred-initialization arms pass these same state/vtable/Location addresses.
    lazy = []
    for site, target, prefix in [(0x45c3c6d, 0x5786570, '488d05'), (0x45c3c80, 0x5786588, '488d05'),
                                (0x45c3c87, 0x572b030, '488d0d'), (0x45c3c8e, 0x572b058, '4c8d05'),
                                (0x45c3cc3, 0x5786570, '488d05'), (0x45c3cd6, 0x5786588, '488d05'),
                                (0x45c3cdd, 0x572b030, '488d0d'), (0x45c3ce4, 0x572b058, '4c8d05'),
                                (0x45c3ca5, 0x576e8b8, 'ff15'), (0x45c3cfb, 0x576e8b8, 'ff15')]:
        opcode = bytes.fromhex(prefix)
        raw = image.get(site, len(opcode) + 4)
        require(raw.startswith(opcode), 'RIP opcode')
        require(site + len(raw) + struct.unpack_from('<i', raw, len(opcode))[0] == target, 'RIP target')
        lazy.append({'site': hex(site), 'target': hex(target), 'bytes': raw.hex()})
    require(image.get(0x5786578, 20) == bytes(16) + b'\x03\x00\x00\x00', 'initial table/state words')
    path = b'/rustc/e408947bfd200af42db322daf0fadfe7e26d3bd1/library/std/src/sync/once.rs'
    require(image.get(0x1f87cf, len(path)) == path, 'Once source path')
    require(struct.unpack('<QII', image.get(0x572b060, 16)) == (len(path), 219, 20), 'Once Location')
    # All byte-pattern E8 candidates are recorded; complete caller disassembly
    # is separately checked for instruction boundaries. This is not an indirect xref census.
    text, = [s for s in image.sections if s['name'] == '.text']
    raw = data[text['offset']:text['offset'] + text['size']]
    calls, pos = [], 0
    while True:
        pos = raw.find(b'\xe8', pos)
        if pos < 0 or pos + 5 > len(raw):
            break
        va = text['address'] + pos
        if va + 5 + struct.unpack_from('<i', raw, pos + 1)[0] == 0x45c3ae0:
            calls.append(va)
        pos += 1
    require(calls == [0x487ddef, 0x487e200], 'direct-call candidate census')
    return {'schema_version': 1, 'target_sha256': DIGEST, 'coordinates': 'ELF virtual addresses; end exclusive',
            'bodies': ranges, 'instruction_obligations': obligations, 'ordered_table': table,
            'relative_bindings': bindings, 'initialization_edges': lazy,
            'source_location': {'path': path.decode(), 'line': 219, 'column': 20, 'record': '0x572b058'},
            'direct_calls': [hex(x) for x in calls], 'captured_binaries_executed': False}


def build(data):
    require(sha(data) == DIGEST, 'wrong node94 SHA-256')
    return observe(data)


def verify_exports(data):
    image = Image(data)
    counts = {}
    for name, (start, end, _, _) in BODIES.items():
        providers = []
        for provider in ('objdump', 'llvm'):
            cursor, starts = start, set()
            for line in (PACKET / (name + '.' + provider + '.txt')).read_text().splitlines():
                match = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}[ \t]+)+)(.*)$', line)
                if not match:
                    continue
                va, raw = int(match[1], 16), bytes.fromhex(match[2])
                require(va == cursor and image.get(va, len(raw)) == raw,
                        'disassembly byte coverage: ' + name + '/' + provider)
                if match[3].strip():
                    starts.add(va)
                cursor += len(raw)
            require(cursor == end, 'incomplete disassembly: ' + name + '/' + provider)
            providers.append(starts)
        require(providers[0] == providers[1], 'decoder instruction boundaries differ: ' + name)
        if name == 'caller':
            require({0x487ddef, 0x487e200} <= providers[0], 'call not at decoded boundary')
        counts[name] = len(providers[0])
    return counts


def controls(data):
    image = Image(data)
    mutations = [(0x45c3b04, 'odd-tag mask'), (0x45c3b29, 'mode branch'),
                 (0x45c3b2e, '10-prefix'), (0x45c3b75, '172 mask'),
                 (0x45c3b68, '192 second octet'), (0x45c3bc3, 'reverse column'),
                 (0x45c3bc4, 'first-match branch'), (0x45c3bcD, 'row stride'),
                 (0x45c3c3f, 'forward value column'), (0x45c3c67, 'matched tag clear'),
                 (0x45be03a, 'captured table byte'), (0x45be0b6, 'table length'),
                 (0x45c3ca7, 'initialization call target')]
    offsets = [(image.off(va), label) for va, label in mutations]
    offsets.append((image.relocations()[0x5786570][2] + 16, 'initializer relocation'))
    rejected = []
    for off, label in offsets:
        changed = bytearray(data)
        changed[off] ^= 1
        try:
            observe(changed, body_hashes=False)  # bypass both digest guards, not structural checks
        except ValueError as exc:
            rejected.append({'control': label, 'rejection': str(exc)})
        else:
            raise ValueError('accepted mutation: ' + label)
    return rejected


def manifest():
    for line in (PACKET / 'MANIFEST.sha256').read_text().splitlines():
        digest, name = line.split('  ', 1)
        path = (ROOT / name).resolve()
        require(path.is_relative_to(ROOT), 'manifest outside repository')
        require(sha(path.read_bytes()) == digest, 'manifest mismatch: ' + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    parser.add_argument('--controls', action='store_true')
    args = parser.parse_args()
    data = TARGET.read_bytes()
    records = build(data)
    records['retained_instructions'] = verify_exports(data)
    rendered = json.dumps(records, indent=2) + '\n'
    if args.write:
        (PACKET / 'records.json').write_text(rendered)
    else:
        require((PACKET / 'records.json').read_text() == rendered, 'records differ')
        manifest()
    if args.controls:
        print(json.dumps(controls(data), indent=2))
    print('PASS: 3 authenticated FDE bodies; 8 initialized pairs; direction, ordered lookup, tag and caller bindings.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError) as error:
        sys.exit(str(error))
