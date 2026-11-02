#!/usr/bin/env python3
"""Check two complete scalar leaves without executing captured instructions."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from fde_extents import eh_frame_records
from libcore_fmt_correspondence import Elf

TARGET = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SIGN, FRACTION = 1 << 63, (1 << 52) - 1
LEAVES = {
    'trunc': (0x565f490, 0x565f4e5, 0x5775dd8,
              '9c7e83a0ac9c57aa9f4c69fdcd94712018a675493adcdbc56b58521fd79c4ead'),
    'floor': (0x565f6f0, 0x565f784, 0x5774e18,
              'e0d611c8ba63673199effd82914ecb4020d08f683441be0339b9d34115567cb0'),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def listing(path, image, begin, end):
    rows, cursor = [], begin
    for line in path.read_text().splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(\S.*)$', line)
        if match:
            address, raw = int(match[1], 16), bytes.fromhex(match[2])
            require(address == cursor and address + len(raw) <= end, 'listing extent')
            require(image.va_bytes(address, len(raw), executable=True)[0] == raw, 'listing bytes')
            rows.append((address, raw))
            cursor += len(raw)
    require(cursor == end, 'incomplete listing')
    return rows


def inspect(data):
    image = Elf(data, 3)
    _, frames = eh_frame_records(data)
    leaves, protected = {}, []
    for name, (begin, end, slot, expected_hash) in LEAVES.items():
        raw, location = image.va_bytes(begin, end - begin, executable=True)
        require(sha(raw) == expected_hash, name + ' body hash')
        matches = [f for f in frames if f['start'] < end and begin < f['end']]
        require(len(matches) == 1 and matches[0]['start'] == begin and matches[0]['end'] == end,
                name + ' unique complete FDE')
        frame = matches[0]
        records = {}
        for kind in ('fde', 'cie'):
            address = frame[kind]
            size = int.from_bytes(image.va_bytes(address, 4)[0], 'little') + 4
            record, mapping = image.va_bytes(address, size)
            records[kind] = {'va': address, 'file_offset': mapping['file_offset'],
                             'hex': record.hex(), 'sha256': sha(record)}
        rows = listing(PACKET / (name + '.gnu.txt'), image, begin, end)
        require(rows == listing(PACKET / (name + '.llvm.txt'), image, begin, end),
                name + ' decoder instruction-boundary disagreement')
        starts = {address for address, _ in rows}
        branches, returns = [], []
        for address, opcode in rows:
            if len(opcode) == 2 and 0x70 <= opcode[0] <= 0x7f:
                target = address + 2 + struct.unpack('b', opcode[1:])[0]
                require(target in starts, 'branch leaves instruction boundaries')
                branches.append({'from': address, 'to': target, 'opcode': opcode.hex()})
            if opcode == b'\xc3':
                returns.append(address)
        require(len(branches) == (2 if name == 'trunc' else 4), 'branch count')
        require(len(returns) == (1 if name == 'trunc' else 4), 'return count')
        relocation = image.relative(slot)
        require(relocation['addend'] == begin, name + ' slot target')
        leaves[name] = {'begin': begin, 'end': end, 'bytes': len(raw), 'hex': raw.hex(),
                        'sha256': sha(raw), 'file_offset': location['file_offset'],
                        'instructions': len(rows), 'branches': branches, 'returns': returns,
                        'frame': frame, 'frame_records': records, 'relocation': relocation}
        protected.extend([(begin, end), (slot, slot + 8)])
    constant, location = image.va_bytes(0x20a278, 8)
    require(constant == bytes.fromhex('000000000000f0bf'), 'negative one constant')
    load, _ = image.va_bytes(0x565f76f, 8, executable=True)
    require(load[:4] == bytes.fromhex('f20f1015') and
            0x565f777 + struct.unpack('<i', load[4:])[0] == 0x20a278, 'constant load edge')
    protected.append((0x20a278, 0x20a280))
    writes, count = [], 0
    for section in image.sections:
        require(section['type'] != 9, 'unsupported REL table')
        if section['type'] != 4:
            continue
        require(section['entsize'] == 24 and section['size'] % 24 == 0, 'invalid RELA table')
        for offset in range(section['offset'], section['offset'] + section['size'], 24):
            dest, info, addend = struct.unpack_from('<QQq', data, offset)
            count += 1
            if any(dest < hi and lo < dest + 8 for lo, hi in protected):
                require(any(dest == v[2] and info == 8 and addend == v[0] for v in LEAVES.values()),
                        'unexpected protected relocation')
                writes.append(offset)
    require(sorted(writes) == sorted(x['relocation']['record_file_offset'] for x in leaves.values()),
            'nonunique slot writes')
    return {'target_sha256': sha(data), 'target_bytes': len(data), 'leaves': leaves,
            'constant': {'va': 0x20a278, 'file_offset': location['file_offset'], 'hex': constant.hex()},
            'rela_records_checked': count, 'captured_code_executed': False,
            'instruction_emulation': False}


def corpus():
    values = set()
    for exponent in range(2048):
        fractions = {0, 1, 2, (1 << 51) - 1, 1 << 51, FRACTION - 1, FRACTION}
        if 1023 <= exponent <= 1074:
            unit = 1 << (1075 - exponent)
            fractions.update(x for x in (unit - 1, unit, unit + 1) if x <= FRACTION)
        values.update(sign | exponent << 52 | fraction
                      for sign in (0, SIGN) for fraction in fractions)
    values.update(int.from_bytes(hashlib.sha256(f'floor-trunc94:{i}'.encode()).digest()[:8], 'little')
                  for i in range(4096))
    return sorted(values)


def oracle(bits, daz):
    """Exact rational rounding; the comparison-specific DAZ exception is from PROOF.md."""
    exponent, fraction = (bits >> 52) & 2047, bits & FRACTION
    sign = bits & SIGN
    if exponent == 2047:
        return bits, bits
    significand = fraction if exponent == 0 else (1 << 52) + fraction
    power = -1074 if exponent == 0 else exponent - 1075
    numerator, denominator = (significand << power, 1) if power >= 0 else (significand, 1 << -power)
    quotient, remainder = divmod(numerator, denominator)

    def encode(integer):
        if integer == 0:
            return sign
        top = integer.bit_length() - 1
        mantissa = integer << (52 - top) if top <= 52 else integer >> (top - 52)
        require(top <= 52 or integer == mantissa << (top - 52), 'integer not exact binary64')
        return sign | ((top + 1023) << 52) | (mantissa - (1 << 52))

    trunc = encode(quotient)
    floor = encode(quotient + int(bool(sign and remainder)))
    if daz and sign and exponent == 0 and fraction:
        floor = bits
    return trunc, floor


def controls(data, record):
    locations = {'trunc body': record['leaves']['trunc']['file_offset'] + 0x14,
                 'floor body': record['leaves']['floor']['file_offset'] + 0x14,
                 'constant': record['constant']['file_offset'] + 7}
    for name, leaf in record['leaves'].items():
        locations[name + ' FDE'] = leaf['frame_records']['fde']['file_offset'] + 12
        locations[name + ' slot'] = leaf['relocation']['record_file_offset'] + 16
    rejected = {}
    for name, offset in locations.items():
        changed = bytearray(data)
        changed[offset] ^= 1
        try:
            inspect(bytes(changed))
        except ValueError as error:
            rejected[name] = str(error)
        else:
            raise ValueError('accepted corruption: ' + name)
    return rejected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', type=Path)
    args = parser.parse_args()
    data = (ROOT / 'artifacts/node/94/hl-node').read_bytes()
    require(sha(data) == TARGET, 'target identity')
    result = inspect(data)
    result['corruption_controls'] = controls(data, result)
    cases = [(bits, daz) for bits in corpus() for daz in (False, True)]
    inputs = b''.join(struct.pack('<QB', bits, daz) for bits, daz in cases)
    expected = b''.join(struct.pack('<QQ', *oracle(bits, daz)) for bits, daz in cases)
    result['frozen_oracle'] = {'cases': len(cases), 'exponents': 2048, 'daz_modes': 2,
                               'inputs_sha256': sha(inputs), 'expected_sha256': sha(expected)}
    text = json.dumps(result, indent=2, sort_keys=True) + '\n'
    if args.write:
        with args.write.open('x') as output:
            output.write(text)
    else:
        require((PACKET / 'static.json').read_text() == text, 'retained static record drift')
    print(json.dumps({'frozen_oracle': result['frozen_oracle'],
                      'corruption_controls': result['corruption_controls']}, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
