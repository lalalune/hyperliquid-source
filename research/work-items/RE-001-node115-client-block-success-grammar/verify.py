#!/usr/bin/env python3
"""Authenticate node115 client-block-success-grammar; static reads only, no capture execution."""
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
TARGET = ROOT / 'artifacts/node/115/hl-node'
DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
BODIES = {'response_context': (95078336, 95079458, 16539836, '3e0159ca16b60928de905e585f823776c42d39b592da8d78895ba5644a335668'), 'client_vector': (92426016, 92426642, 20443080, 'b5062c7e55d91bdee8d2b908894ac96e19d88748a7ad01db3fbe908fd2c7187f'), 'client_callback': (95125264, 95125338, 16544496, '43ac297470e8c9994d5f10a8798a2a168dd9dc0ca3c31ac274001979515c5f0a'), 'unverified_client': (83602832, 83603464, 20003028, '4a5b944abd869caae825297d31713122eb729fb397707c4f5b447178f3a3a2b9'), 'block': (83588960, 83589974, 20002284, 'a1a71052c4d5d9aee6d9a0c3c4c255b40c7ab9e063eda032a1b541ee8bb33548'), 'header': (94199456, 94201110, 20570492, '4c6f3e2f6947db2261d6f992490fbd51d443dad9869418cbdcd13ecea6d9b7f9'), 'optional_qc': (81809792, 81810146, 15881660, '63b893b251cb1c201296b425526fbb66dabda317360aedd98a328c3ffc8f7ad8'), 'commit_proof': (83603472, 83604215, 20003104, '3d94ef9d02e96f92d8d81f820a0fe0c834c5c4ccbd7569f47c8469617e826aba'), 'qc': (93752608, 93753102, 16497760, '9d897eea60b573b602895ec73ca2901f4aaf3711f7b3bafd61bd72b057a6cf01'), 'tc': (93753104, 93753990, 20519248, 'c22429f921f404c50c0c2542cd7ddfed75f599edede981456800c306eb7204e8'), 'qc_map_context': (81683568, 81684021, 19903380, '2d78cdf4bcdc8f5fc380beb504e408d77f15dceab565c2a3e76b0f65e77f8ce1'), 'tc_map_context': (81525072, 81525361, 19890780, '28c865e8380a6b31cb618f090877cb72564a449dc9295ff73d286df7d29d6e6e'), 'qc_vector': (92429920, 92430607, 20443584, '37d1dc2880e502a72d3891647e4dbca47ae0cd6d0e7c82a515b7e8fe56c1c571'), 'tc_vector': (92428528, 92429221, 20443416, '424d2c6ed90e021a21b0597b89cc5ab6e49de895816dd89f83148ae5ba784aca'), 'qc_row': (92409424, 92409887, 16368512, '65210f207e9d1eda6299ccd0b74a9c3a5ae6aa35828d185525a67607251ee9fa'), 'tc_row': (92408944, 92409413, 16368428, '271dde684385a20a8d6462402aa95b0f05b0c814574dcc03ac919c40d97b3bf5'), 'qc_value': (88272864, 88273346, 16242412, 'e9a83a9b435fad30dd53f52250f95cba97bee48ed7062278b120ac62071a1fbc'), 'tc_value': (88261264, 88261881, 16242116, 'c0c1562b52470443cc60a212cdbdf451e0eefdf3dfe199a8b16a6def21c8f5e0'), 'signature': (92409888, 92410179, 16368596, 'f6dc75f95bfa101af2781803212885c9ed7b936d1c1f76e1f37cd638ea132bb1'), 'u256': (92411200, 92411679, 16368852, '250473b823e51704e56dab2308d4d03b85c8188c62869bd726e42135a1f5e7c8'), 'address': (92405440, 92405581, 16368160, '43099d683c7763c8202646662ad21741c7b9a77a7a6f039ddfb94d7e3195dddd'), 'hash': (92410928, 92411043, 16368804, '14f7a11f50bba370abd61ae08c76346b828217584ce9a296bcce3df0040cd7a5'), 'hash_callback': (81887968, 81888083, 15896036, '3042e3d11c3ff987168d6e546d330459bab2be50cc7a228218844c8a92388e2c'), 'hash_vector': (92422976, 92423531, 20442748, '3fecb4908df7c3081467b86090ff3c6ea2afa11cb7366935232ac7c7b9621b69'), 'attachment_vector': (92424256, 92425051, 20442916, 'b6e022d43edcdff560d395a9eff26aae32df752863550d674cfdb449abfb4f4f'), 'attachment_row': (81809040, 81809336, 19925084, 'db38152d3e3aa6d9f9336364fd59c52beca5396809a91f1cf5b8a6857172cb95'), 'blob': (92425056, 92425305, 16369664, 'c633c938aeeb979c077c0cdc1f71ff53f842115044503ac870eb030b2d7e43fe'), 'u64_context': (92410448, 92410677, 16368700, '12341e48e3f53f92ed9caa50ddc8c09b3716795758360fd10e6a869eccd150a2'), 'u32_context': (92410192, 92410435, 16368644, 'd9cbd093b853222eb99cc7f535e1ba275ee2ed6d0fb20cd42ab1d09226c31f10'), 'timestamp_context': (82634880, 82635459, 15940280, '965d32059ea1c5d738917cb43054ca765acffb72cc671a9f83ded8ca61bc13f2')}
SLOTS = {105772160: 104159280, 105795616: 93726240, 105772192: 104193584, 105582576: 4409424, 105773128: 23600704, 105772184: 21095012, 105772224: 23596203, 105795480: 94951360, 105772176: 21094993, 105810136: 83071296, 105810144: 83078560, 105795600: 93725008, 105795576: 93727024, 105582344: 4422467, 105773104: 23596048, 105795560: 93727584, 105795624: 93726576, 105794744: 94955456, 105772440: 104159488, 105802808: 92415424, 105807736: 92415744, 105807728: 92415120, 105775088: 23236432, 105778120: 23631248, 105775728: 23628320, 105772776: 21095328}
SUPPORT = {}
LITERALS = {'source_0x434850': (4409424, b'z_forks/bincode-fork/src/de/decoder.rs'), 'location_0x64b0ff0': (105582584, b'&\x00\x00\x00\x00\x00\x00\x00]\x00\x00\x00\r\x00\x00\x00'), 'source_0x437b43': (4422467, b'z_forks/bincode-fork/src/de/impls.rs'), 'location_0x64b0f08': (105582352, b'$\x00\x00\x00\x00\x00\x00\x00\xf3\x01\x00\x00\x14\x00\x00\x00'), 'option_commit_proof': (9532433, b'core::option::Option<node::consensus::client_block::CommitProof>'), 'option_qc': (9532497, b'core::option::Option<node::consensus::types::Qc>'), 'block_parent': (9668198, b'BlockParent'), 'literal_context_0x93c571': (9684337, b'GossipRpcResponseTcpClient not connectedip not v4tcp_bytestcp read bytes over li'), 'literal_context_0x93c428': (9684008, b'core::result::Result<alloc::vec::Vec<node::consensus::verified::Unverified<node:'), 'literal_context_0x917481': (9532545, b'core::option::Option<node::gossip_rpc::GossipStatus>core::option::Option<alloc::'), 'literal_context_0x93c560': (9684320, b'ClientBlocksErrorGossipRpcResponseTcpClient not connectedip not v4tcp_bytestcp r'), 'literal_context_0x917411': (9532433, b'core::option::Option<node::consensus::client_block::CommitProof>core::option::Op'), 'literal_context_0x917451': (9532497, b'core::option::Option<node::consensus::types::Qc>core::option::Option<node::gossi')}
IMPORTS = {105772296: (7, 'memcpy')}
INCOMING = {'response_context': [], 'client_vector': [], 'client_callback': [], 'unverified_client': [], 'block': [], 'header': [], 'optional_qc': [], 'commit_proof': [], 'qc': [], 'tc': [], 'qc_map_context': [], 'tc_map_context': [], 'qc_vector': [], 'tc_vector': [], 'qc_row': [], 'tc_row': [], 'qc_value': [], 'tc_value': [], 'signature': [], 'u256': [], 'address': [], 'hash': [], 'hash_callback': [], 'hash_vector': [], 'attachment_vector': [], 'attachment_row': [], 'blob': [], 'u64_context': [], 'u32_context': [], 'timestamp_context': []}
# Image/export helpers adapted from MIT-authored packets #2111, #2141, #2154 and #2184/#2200.
# All target spans, constants and semantic deductions below are newly measured.
def require(value, message):
    if not value:
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
        matches = [s for s in self.sections if s['type'] != 8 and
                   s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(matches) == 1, 'ambiguous or unbacked VA')
        return matches[0]['offset'] + va - matches[0]['address']

    def get(self, va, size):
        offset = self.off(va, size)
        raw = self.data[offset:offset + size]
        require(len(raw) == size, 'truncated VA bytes')
        return raw

    def relocs(self):
        sec, = [s for s in self.sections if s['name'] == '.rela.dyn']
        require(sec['size'] % 24 == 0, 'partial RELA record')
        result = {}
        for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', self.data, off)
            require(slot not in result, 'duplicate relocation slot')
            result[slot] = (info, addend, off)
        return result


def export_rows(image, name, start, end):
    """Require byte-complete independent exports with equal instruction starts."""
    providers = []
    for provider in ('gnu', 'llvm'):
        cursor, rows = start, []
        for line in (PACKET / f'{name}.{provider}.txt').read_text().splitlines():
            match = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}[ \t]+)+)(.*)$', line)
            if not match:
                continue
            va, raw, asm = int(match[1], 16), bytes.fromhex(match[2]), match[3].strip()
            require(va == cursor and va + len(raw) <= end, 'export range: ' + name)
            require(image.get(va, len(raw)) == raw, 'export bytes: ' + name)
            if asm:
                # LLVM 18 prints LOCK as a separate one-byte pseudo-instruction.
                # Join only a literal F0/lock row to its immediately adjacent opcode.
                if rows and rows[-1][1] == b'\xf0' and rows[-1][2] == 'lock':
                    prefix_va, prefix, _ = rows.pop()
                    require(prefix_va + 1 == va, 'noncontiguous LOCK prefix')
                    rows.append((prefix_va, prefix + raw, 'lock ' + asm))
                else:
                    rows.append((va, raw, asm))
            else:
                require(bool(rows), 'orphan export continuation')
                a, previous, text = rows[-1]
                rows[-1] = (a, previous + raw, text)
            cursor += len(raw)
        require(cursor == end, 'incomplete export: ' + name)
        providers.append(rows)
    require([(a, b) for a, b, _ in providers[0]] == [(a, b) for a, b, _ in providers[1]],
            'independent decoder boundaries differ: ' + name)
    return providers[0]


def call_candidates(image, target, prefix):
    text, = [s for s in image.sections if s['name'] == '.text']
    raw = image.data[text['offset']:text['offset'] + text['size']]
    pos, found = 0, []
    while True:
        pos = raw.find(prefix, pos)
        if pos < 0 or pos + len(prefix) + 4 > len(raw):
            return found
        va = text['address'] + pos
        to = va + len(prefix) + 4 + struct.unpack_from('<i', raw, pos + len(prefix))[0]
        if to == target:
            found.append(va)
        pos += 1


def dynamic_symbol(image, info):
    sym, = [s for s in image.sections if s['name'] == '.dynsym']
    strings, = [s for s in image.sections if s['name'] == '.dynstr']
    index = info >> 32
    require((index + 1) * 24 <= sym['size'], 'dynamic symbol index')
    off = sym['offset'] + index * 24
    name, flags, other, shndx, value, size = struct.unpack_from('<IBBHQQ', image.data, off)
    require(name < strings['size'], 'dynamic string index')
    start = strings['offset'] + name
    end = image.data.find(b'\0', start, strings['offset'] + strings['size'])
    require(end >= start, 'unterminated dynamic symbol')
    return {'name': image.data[start:end].decode('ascii'), 'symbol_index': index,
            'symbol_file_offset': hex(off), 'name_file_offset': hex(start),
            'info': flags, 'other': other, 'section_index': shndx,
            'value': hex(value), 'size': size}



def incoming(image, fdes):
    """Qualified .text encoded-form census; not arbitrary dynamic dispatch."""
    import capstone
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    cache, result, bindings = {}, [], []
    for name in INCOMING:
        target = BODIES[name][0]
        slots = [s for s, (info, value, _) in image.relocs().items() if info == 8 and value == target]
        expected = INCOMING[name]
        require(slots == expected, 'incoming RELATIVE census: ' + name)
        bindings.append({'role': name, 'target': hex(target), 'slots': [hex(s) for s in slots]})
        forms = [(target, b'\xe8')] + [(s, pre) for s in slots for pre in (b'\xff\x15', b'\xff\x25')]
        for address, prefix in forms:
            for site in call_candidates(image, address, prefix):
                owners = [f for f in fdes if f['start'] <= site < f['end']]
                require(len(owners) == 1, 'incoming FDE ownership')
                f, = owners
                if f['start'] not in cache:
                    raw = image.get(f['start'], f['end'] - f['start'])
                    rows = list(decoder.disasm_lite(raw, f['start']))
                    require(sum(row[1] for row in rows) == len(raw), 'incoming complete decode')
                    cache[f['start']] = {row[0]: row for row in rows}
                row = cache[f['start']].get(site)
                require(row and row[1] == len(prefix) + 4 and row[2] in ('call', 'jmp'), 'incoming instruction boundary')
                result.append({'role': name, 'site': hex(site), 'target_or_slot': hex(address),
                               'instruction': row[2] + ' ' + row[3], 'bytes': image.get(site, row[1]).hex(), 'owner': f})
    return {'qualified_candidates': result, 'relative_bindings': bindings,
            'limits': 'Only E8 and RIP-relative FF15/FF25 forms in .text; no arbitrary register/vtable caller or runtime-reachability claim.'}


def observe(data, *, body_hashes=True, exports=True):
    image = Image(data)
    _, fdes = eh_frame_records(data, image.sections)
    relocs = image.relocs()
    bodies, boundaries, ends = [], set(), set()
    for name, (start, end, fde_va, digest) in BODIES.items():
        fs = [f for f in fdes if f['start'] == start]
        require(len(fs) == 1 and fs[0]['end'] == end and fs[0]['fde'] == fde_va,
                'FDE binding: ' + name)
        raw = image.get(start, end - start)
        if body_hashes:
            require(sha(raw) == digest, 'body digest: ' + name)
        row = {'role': name, 'start': hex(start), 'end': hex(end), 'bytes': len(raw),
               'sha256': sha(raw), 'file_offset': hex(image.off(start)), 'enclosing_fde': fs[0]}
        if exports:
            decoded = export_rows(image, name, start, end)
            starts = {a for a, _, _ in decoded}
            boundaries.update(starts)
            ends.update(a + len(b) for a, b, _ in decoded)
            row['instructions'], row['calls_and_tail_jumps'], row['returns'] = len(decoded), [], []
            row['scope'] = 'The complete nested successful ClientBlocks payload consists of unverified block/attachment pairs: block signature, header, optional commit proof; header address/hash vector/timestamp/QC-or-TC parent; QC five u64 fields and hash/votes; TC leading u64/QC/votes; attachment Hash32 plus raw length-prefixed bytes. Signature limbs use varints rather than raw65-byte wire copies. This is a structural successful-wire contract, not cryptographic verification, full malformed-input ABI/budget equivalence, or a claimed transaction interpretation of opaque blobs.'
            for va, raw, asm in decoded:
                branch = re.match(r'j\w+\s+([0-9a-f]+)\s', asm)
                if branch:
                    require(int(branch[1], 16) in starts or asm.startswith('jmp'), 'conditional branch outside decoded FDE')
                if asm == 'ret':
                    row['returns'].append(hex(va))
                if not re.match(r'call\s', asm) and raw[:2] != b'\xff\x25':
                    continue
                call = {'site': hex(va), 'bytes': raw.hex(), 'disassembly': asm}
                if raw[:1] == b'\xe8':
                    to = va + 5 + struct.unpack_from('<i', raw, 1)[0]
                    call['direct_target'] = hex(to)
                    call['target_fde'] = next((f for f in fdes if f['start'] == to), None)
                elif raw[:2] in (b'\xff\x15', b'\xff\x25'):
                    slot = va + 6 + struct.unpack_from('<i', raw, 2)[0]
                    require(slot in relocs, 'unbound call slot')
                    info, target, off = relocs[slot]
                    call.update(slot=hex(slot), relocation_info=hex(info), addend=hex(target),
                                relocation_file_offset=hex(off))
                    if info & 0xffffffff != 8:
                        call['symbol'] = dynamic_symbol(image, info)
                else:
                    call['qualification'] = 'Register-indirect call; concrete target remains unresolved'
                row['calls_and_tail_jumps'].append(call)
        bodies.append(row)
    obligations = json.loads((PACKET / 'obligations.json').read_text())
    for name, r in obligations.items():
        start, end, raw = int(r['va'], 16), int(r['end'], 16), bytes.fromhex(r['bytes'])
        require(len(raw) == end - start and image.get(start, len(raw)) == raw,
                'instruction obligation: ' + name)
        if exports:
            require(start in boundaries and end in ends, 'instruction span boundary: ' + name)
    bindings = []
    for slot, target in SLOTS.items():
        require(relocs.get(slot, ())[:2] == (8, target), 'RELATIVE binding: ' + hex(slot))
        bindings.append({'slot': hex(slot), 'target': hex(target),
                         'relocation_file_offset': hex(relocs[slot][2])})
    imports = []
    for slot, (index, name) in IMPORTS.items():
        require(relocs.get(slot, ())[:2] == ((index << 32) | 6, 0), 'GLOB_DAT binding: ' + name)
        symbol = dynamic_symbol(image, relocs[slot][0])
        require(symbol['name'] == name and symbol['info'] == 18 and symbol['other'] == 0 and
                symbol['section_index'] == 0 and symbol['value'] == '0x0' and symbol['size'] == 0,
                'undefined dynamic function: ' + name)
        imports.append({'slot': hex(slot), 'relocation_info': hex(relocs[slot][0]), 'symbol': symbol})
    literals = []
    for name, (va, expected) in LITERALS.items():
        require(image.get(va, len(expected)) == expected, 'literal binding: ' + name)
        literals.append({'role': name, 'va': hex(va), 'file_offset': hex(image.off(va)),
                         'bytes': expected.hex(), 'length': len(expected)})
    if exports:
        frame, = [s for s in image.sections if s['name'] == '.eh_frame']
        headers = re.findall(r'^([0-9a-f]+) .*FDE cie=([0-9a-f]+) pc=([0-9a-f]+)\.\.([0-9a-f]+)$',
                             (PACKET / 'fdes.readelf.txt').read_text(), re.MULTILINE)
        actual = sorted(tuple(int(x, 16) for x in row) for row in headers)
        expected = sorted((r['enclosing_fde']['fde'] - frame['address'],
                           r['enclosing_fde']['cie'] - frame['address'],
                           int(r['start'], 16), int(r['end'], 16)) for r in bodies)
        require(actual == expected, 'independent readelf FDE headers')
    return {'schema': 1, 'target_sha256': sha(data), 'coordinates': 'ELF VA; exclusive ends',
            'bodies': bodies, 'measured_bytes': sum(r['bytes'] for r in bodies),
            'obligations': len(obligations), 'relative_bindings': bindings,
            'literals': literals, 'dynamic_imports': imports,
            'incoming': incoming(image, fdes) if exports else None,
            'captured_code_executed_or_emulated': False}


def build(data):
    require(len(data) == 105896032 and sha(data) == DIGEST, 'wrong node115 SHA-256 or size')
    return observe(data)


def controls(data):
    image, offsets = Image(data), []
    relocs = image.relocs()
    for name, r in json.loads((PACKET / 'obligations.json').read_text()).items():
        offsets.append((image.off(int(r['end'], 16) - 1), 'instruction ' + name))
    offsets += [(relocs[s][2] + 16, 'relative ' + hex(s)) for s in SLOTS]
    offsets += [(image.off(a), 'literal ' + name) for name, (a, _) in LITERALS.items()]
    offsets += [(image.off(b[2]) + 12, 'FDE range ' + name) for name, b in BODIES.items()]
    for slot, (index, name) in IMPORTS.items():
        symbol = dynamic_symbol(image, relocs[slot][0])
        offsets += [(relocs[slot][2] + 8, 'import relocation kind ' + name),
                    (relocs[slot][2] + 12, 'import symbol index ' + name),
                    (int(symbol['symbol_file_offset'], 16), 'import symbol name offset ' + name),
                    (int(symbol['name_file_offset'], 16), 'import symbol text ' + name)]
    result = []
    for off, label in offsets:
        changed = bytearray(data)
        changed[off] ^= 1
        try:
            observe(changed, body_hashes=False, exports=False)
        except ValueError as error:
            result.append({'control': label, 'file_offset': hex(off), 'rejection': str(error)})
        else:
            raise ValueError('corruption survived: ' + label)
    return {'whole_image_body_and_export_guards_bypassed': True, 'rejected': result, 'survived': []}


def encoded(value):
    return json.dumps(value, indent=2, sort_keys=True) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    parser.add_argument('--controls', action='store_true')
    args = parser.parse_args()
    data = TARGET.read_bytes()
    result = build(data)
    outputs = {'records.json': result}
    if args.controls:
        outputs['controls.json'] = controls(data)
    for name, value in outputs.items():
        text = encoded(value)
        if args.write:
            (PACKET / name).write_text(text)
        else:
            require((PACKET / name).read_text() == text, 'regeneration mismatch: ' + name)
    print(f"PASS: {len(result['bodies'])} complete FDEs / {result['measured_bytes']} bytes")
    if args.controls:
        print(f"PASS: {len(outputs['controls.json']['rejected'])} deep corruption controls")


if __name__ == '__main__':
    main()
