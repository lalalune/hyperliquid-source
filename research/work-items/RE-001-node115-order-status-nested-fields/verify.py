#!/usr/bin/env python3
"""Authenticate node115 order-status-nested-fields; static reads only, no capture execution."""
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
BODIES = {'status_projection': (85495584, 85496594, 16095812, 'e7fa428402c333f3368e34fe2f5d5350e2b016ad21975615d5debe697b7acb79'), 'quantity_string_field': (86441824, 86442100, 20156020, '6dc26b40129783be13eaa88227d2315638fe8f5be145fa0f2868cfd381c321ec'), 'cloid_string_field': (86436784, 86437128, 16142064, 'a0bc4ee4d52d78319eaf5eadd1999927583f78d81f5f01be733b6e5dc1921c0e'), 'decimal_normalization': (71983568, 71983890, 19554732, '5755053649d020f6910130a3c8545f3ea7be8487550b0344e144816e504a75d0'), 'hex_context': (48937808, 48938206, 14282292, 'a4ade37e9aec972480063da782bee7d212fa6a8aeac7a864ef3c36e1439fadf7'), 'unsigned_integer_context': (92078256, 92078661, 16332268, '670d2c2c065027115cde30623f01649150037c55c346d3672c08eb7924f4be66'), 'map_context': (92070144, 92070879, 16331480, 'cecbd66ced0d55e5289361ba57d8fabf9b9f97c6daef2c786ce166383020cd38'), 'array_context': (92072864, 92073599, 16331696, '7a7c55ebf4eaa015fc8f6541163ba665be721633b0415814fd93793a82ef3f2b'), 'string_context': (92076128, 92077329, 16332108, '27ffc606d1606ba84fff1619d494309645c747711e39d79bcc5ad202ab7bb3f3')}
SLOTS = {105798616: 71983568, 105772192: 104193584, 105794824: 48937808, 105777784: 23627584, 105772776: 21095328, 105772160: 104159280, 105772184: 21095012, 105253656: 4451363, 105772400: 23599072, 105253584: 4451363, 105772848: 23596640, 105253680: 4451363, 105772576: 23596223, 105253704: 4451363, 105253608: 4451363, 105253632: 4451363}
SUPPORT = {}
LITERALS = {'source_0x43ec23': (4451363, b'/home/ubuntu/hl/code_Mainnet/z_vendor/impl-serde/src/serialize.rs'), 'location_0x6460b18': (105253664, b'A\x00\x00\x00\x00\x00\x00\x00>\x00\x00\x00/\x00\x00\x00'), 'location_0x6460ad0': (105253592, b'A\x00\x00\x00\x00\x00\x00\x00)\x00\x00\x00\x05\x00\x00\x00'), 'location_0x6460b30': (105253688, b'A\x00\x00\x00\x00\x00\x00\x008\x00\x00\x00\t\x00\x00\x00'), 'location_0x6460b48': (105253712, b'A\x00\x00\x00\x00\x00\x00\x009\x00\x00\x00\t\x00\x00\x00'), 'location_0x6460ae8': (105253616, b'A\x00\x00\x00\x00\x00\x00\x00/\x00\x00\x00\x18\x00\x00\x00'), 'location_0x6460b00': (105253640, b'A\x00\x00\x00\x00\x00\x00\x004\x00\x00\x00\x05\x00\x00\x00'), 'status_dispatch': (9556500, b'6\xbd\x86\x04\x8a\xbe\x86\x04&\xbe\x86\x04V\xbe\x86\x04\xb7\xbd\x86\x04'), 'filled': (9564881, b'filled'), 'resting': (9564899, b'resting'), 'totalSz': (9564887, b'totalSz'), 'avgPx': (9564894, b'avgPx'), 'oid': (9561144, b'oid'), 'cloid': (9561170, b'cloid'), 'hex_digits': (4545856, b'0123456789abcdef'), 'float_format_descriptor_context': (4561048, b'\xc5 \x00\x00p\n\x00\x00'), 'literal_context_0x91f2d1': (9564881, b'filledtotalSzavgPxrestingwaitingForFillwaitingForTriggerMultiSigSignersauthorize'), 'literal_context_0x91f277': (9564791, b'errorsuccessstatushyperliquidity_ensure_orderspointsspot_to_rangeensure_order_bu'), 'literal_context_0x91f2ea': (9564906, b'waitingForFillwaitingForTriggerMultiSigSignersauthorizedUsersthresholduser_to_mu'), 'literal_context_0x91f2f8': (9564920, b'waitingForTriggerMultiSigSignersauthorizedUsersthresholduser_to_multi_sig_signer'), 'literal_context_0x91f2e3': (9564899, b'restingwaitingForFillwaitingForTriggerMultiSigSignersauthorizedUsersthresholduse'), 'literal_context_0x91f2d7': (9564887, b'totalSzavgPxrestingwaitingForFillwaitingForTriggerMultiSigSignersauthorizedUsers'), 'literal_context_0x91f2de': (9564894, b'avgPxrestingwaitingForFillwaitingForTriggerMultiSigSignersauthorizedUsersthresho'), 'literal_context_0x91e438': (9561144, b'oidcrossedfeebuilderFeetidcloidliquidationfeeTrialEscrowbuildertwapIddeployerFee'), 'literal_context_0x91e452': (9561170, b'cloidliquidationfeeTrialEscrowbuildertwapIddeployerFeepriorityGasszientryPxposit'), 'literal_context_0x6408a6': (6555814, b'assertion failed: v.len() > 1 + bytes.len() * 20x prefix is missingthere should ')}
IMPORTS = {105772296: (7, 'memcpy')}
INCOMING = {'status_projection': [], 'quantity_string_field': [], 'cloid_string_field': [], 'decimal_normalization': [105798616], 'hex_context': [105794824], 'unsigned_integer_context': [], 'map_context': [], 'array_context': [], 'string_context': []}
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
            row['scope'] = 'Filled and resting order-status MessagePack payloads project their nested fields in fixed order with mode-dependent map or array containers; quantity fields are normalized strings, oid is unsigned integer and absent cloid is omitted. Valid option flags and serializer modes only. Outer dispatch and generic encoders are credited context; initial Rust float rendering, allocation failure, full post-block responses and target execution remain outside the claim.'
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
