#!/usr/bin/env python3
"""Recheck one static ceil packet; never execute or emulate captured code."""
import argparse
import csv
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
BODY = '305266cf1728cbf73813d37f53ff4f144253a377fc9258c8732b1f4b3bf5eaeb'
BEGIN, END = 0x565f670, 0x565f6e7
CALLER_BEGIN, CALLER_END, CALL = 0x3261c40, 0x3262583, 0x3262024
SLOT = 0x57747c8
SIGN, FRACTION, WORD = 1 << 63, (1 << 52) - 1, (1 << 64) - 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


# The manifest pins every packet file except MANIFEST.sha256 itself.
PACKET_FILES = frozenset({
    'PROOF.md', 'README.md', 'VALIDATION.md', 'caller.objdump.txt',
    'ceil.llvm.txt', 'ceil.objdump.txt', 'evidence.json', 'samples.tsv',
    'verify.py',
})


def check_manifest():
    # Nothing in this verifier read MANIFEST.sha256 before: the packet
    # carried a full-pin manifest that no check enforced, so a tampered
    # or co-deleted evidence file was invisible as long as the two
    # files the verifier happens to read (evidence.json, samples.tsv)
    # stayed consistent with the binary. Enforce the admission check
    # the RE-001 sibling packet verifiers spell out: strict parse, no
    # duplicate rows, no symlinked or subdirectory entries (tolerating
    # only a __pycache__ of plain bytecode files), and the listed set
    # equal to both the pinned packet files and the files present.
    manifest = PACKET / 'MANIFEST.sha256'
    require(manifest.is_file(), 'MANIFEST.sha256 missing')
    listed = {}
    for line in manifest.read_text(encoding='utf-8').splitlines():
        if not line.strip():
            continue
        parts = line.split()
        require(len(parts) == 2, 'malformed manifest line: %r' % line.strip())
        digest_hex, name = parts
        require(name not in listed, 'manifest lists %s twice' % name)
        listed[name] = digest_hex
    present = set()
    for entry in sorted(PACKET.iterdir()):
        if entry.is_symlink():
            raise ValueError('packet entry is a symlink: %s' % entry.name)
        if entry.is_dir():
            if entry.name != '__pycache__' or not all(
                    child.name.endswith('.pyc') and not child.is_symlink()
                    for child in entry.iterdir()):
                raise ValueError('unexpected directory in packet: %s' % entry.name)
            continue
        present.add(entry.name)
    present.discard('MANIFEST.sha256')
    require(set(listed) == PACKET_FILES,
            'manifest file set differs from the pinned packet files: '
            'missing rows %s, unexpected rows %s'
            % (sorted(PACKET_FILES - set(listed)),
               sorted(set(listed) - PACKET_FILES)))
    require(set(listed) == present,
            'manifest file set differs from packet contents: '
            'unlisted %s, missing %s'
            % (sorted(present - set(listed)),
               sorted(set(listed) - present)))
    for name, digest_hex in sorted(listed.items()):
        if name in present:
            require(digest((PACKET / name).read_bytes()) == digest_hex,
                    'manifest hash mismatch: %s' % name)


def listing_rows(path, image, begin, end):
    """Validate retained row bytes and contiguous coverage, not their mnemonics."""
    rows, cursor = [], begin
    for line in path.read_text(encoding='utf-8').splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(\S.*)$', line)
        if not match:
            continue
        address, raw = int(match[1], 16), bytes.fromhex(match[2])
        require(address == cursor and raw, 'disassembly rows are not contiguous')
        require(address + len(raw) <= end, 'disassembly exceeds admitted extent')
        actual, _ = image.va_bytes(address, len(raw), executable=True)
        require(raw == actual, 'retained disassembly bytes differ')
        rows.append((address, raw))
        cursor += len(raw)
    require(cursor == end, 'disassembly does not cover the complete extent')
    return rows


def inspect(data):
    """Structural control seam. Only main admits the full target SHA-256."""
    image = Elf(data, 3)
    body, mapping = image.va_bytes(BEGIN, END - BEGIN, executable=True)
    require(digest(body) == BODY, 'ceil body digest differs')
    cies, fdes = eh_frame_records(data)
    frames = []
    for begin, end in ((BEGIN, END), (CALLER_BEGIN, CALLER_END)):
        matches = [f for f in fdes if f['start'] < end and begin < f['end']]
        require(len(matches) == 1 and matches[0]['start'] == begin and
                matches[0]['end'] == end, 'FDE extent differs or overlaps')
        f = matches[0]
        records = {}
        for label, address in (('fde', f['fde']), ('cie', f['cie'])):
            size = int.from_bytes(image.va_bytes(address, 4)[0], 'little') + 4
            raw, location = image.va_bytes(address, size)
            records[label] = {'va': address, 'file_offset': location['file_offset'],
                              'hex': raw.hex(), 'sha256': digest(raw)}
        frames.append({'range': f, 'cie': cies[f['cie']], 'records': records})
    rows = listing_rows(PACKET / 'ceil.objdump.txt', image, BEGIN, END)
    require(rows == listing_rows(PACKET / 'ceil.llvm.txt', image, BEGIN, END),
            'GNU/LLVM instruction boundaries differ')
    caller_rows = listing_rows(PACKET / 'caller.objdump.txt', image, CALLER_BEGIN, CALLER_END)
    starts = {a for a, _ in rows}
    branches, returns = [], []
    for address, raw in rows:
        if len(raw) == 2 and raw[0] in (0x77, 0x76, 0x74, 0x78):
            target = address + 2 + struct.unpack('b', raw[1:])[0]
            require(target in starts, 'conditional branch leaves instruction boundaries')
            branches.append({'from': address, 'to': target, 'opcode': raw[0]})
        if raw == b'\xc3':
            returns.append(address)
    require(len(branches) == 5 and returns == [0x565f6cd, 0x565f6dd, 0x565f6e6],
            'branch/return structure differs')
    constants = []
    for instruction, address, bits in ((0x565f6d5, 0x20a730, 0x3ff0000000000000),
                                      (0x565f6de, 0x20a910, SIGN)):
        raw, _ = image.va_bytes(instruction, 8, executable=True)
        require(raw[:4] == bytes.fromhex('f20f1005'), 'constant load opcode differs')
        require(instruction + 8 + struct.unpack('<i', raw[4:])[0] == address,
                'constant RIP-relative edge differs')
        value, location = image.va_bytes(address, 8)
        require(int.from_bytes(value, 'little') == bits, 'constant bits differ')
        constants.append({'load_va': instruction, 'va': address,
                          'file_offset': location['file_offset'], 'hex': value.hex()})
    call_bytes, call_mapping = image.va_bytes(CALL, 6, executable=True)
    require((CALL, call_bytes) in caller_rows, 'caller edge is not an instruction boundary')
    require(call_bytes[:2] == b'\xff\x15' and
            CALL + 6 + struct.unpack('<i', call_bytes[2:])[0] == SLOT,
            'caller RIP-relative slot differs')
    relocation = image.relative(SLOT)
    require(relocation['addend'] == BEGIN, 'slot relocation resolves elsewhere')
    protected = [(BEGIN, END), (SLOT, SLOT + 8)] + [(c['va'], c['va'] + 8) for c in constants]
    slot_writes, total = [], 0
    for section in image.sections:
        require(section['type'] != 9, 'unsupported REL table')
        if section['type'] != 4:
            continue
        require(section['entsize'] == 24 and section['size'] % 24 == 0, 'invalid RELA table')
        for offset in range(section['offset'], section['offset'] + section['size'], 24):
            destination, info, addend = struct.unpack_from('<QQq', data, offset)
            total += 1
            # Conservative eight-byte overlap guard for this captured table.
            if any(destination < hi and lo < destination + 8 for lo, hi in protected):
                require(destination == SLOT and info == 8 and addend == BEGIN,
                        'unexpected relocation overlaps protected bytes')
                slot_writes.append(offset)
    require(slot_writes == [relocation['record_file_offset']], 'slot write is not globally unique')
    caller_body, _ = image.va_bytes(CALLER_BEGIN, CALLER_END - CALLER_BEGIN, executable=True)
    return {'target_sha256': digest(data), 'target_bytes': len(data),
            'body': {'start': BEGIN, 'end': END, 'bytes': len(body), 'sha256': digest(body),
                     'hex': body.hex(), 'file_offset': mapping['file_offset'],
                     'section': mapping['section']['name'], 'pt_load': mapping['PT_LOAD'],
                     'instructions': len(rows), 'branches': branches, 'returns': returns},
            'frames': frames, 'constants': constants,
            'caller': {'start': CALLER_BEGIN, 'end': CALLER_END, 'sha256': digest(caller_body),
                       'instructions': len(caller_rows), 'call_va': CALL,
                       'call_file_offset': call_mapping['file_offset'], 'call_hex': call_bytes.hex()},
            'relocation': relocation, 'rela_records_checked': total,
            'target_execution': False, 'instruction_emulation': False}


def ceiling_rule(bits):
    """Integer equation derived in PROOF.md; not an instruction evaluator."""
    exponent = (bits >> 52) & 0x7ff
    if exponent >= 1075:
        return bits
    if exponent <= 1022:
        return SIGN if bits & SIGN else (0 if bits == 0 else 0x3ff0000000000000)
    mask = FRACTION >> (exponent - 1023)
    return ((bits + (mask if not bits & SIGN else 0)) & ~mask) & WORD


def rational_ceiling(bits):
    """Independent exact rational ceiling, then exact integer-to-binary64 encoding."""
    exponent, fraction = (bits >> 52) & 0x7ff, bits & FRACTION
    negative = bool(bits & SIGN)
    if exponent == 0x7ff:
        return bits  # Exceptional-bit contract is established by the static early return.
    significand = fraction if exponent == 0 else (1 << 52) + fraction
    power = -1074 if exponent == 0 else exponent - 1075
    if power >= 0:
        integer = significand << power
    else:
        denominator = 1 << -power
        integer = significand // denominator if negative else -(-significand // denominator)
    if integer == 0:
        return SIGN if negative else 0
    highest = integer.bit_length() - 1
    mantissa = integer << (52 - highest) if highest <= 52 else integer >> (highest - 52)
    require(highest <= 52 or integer == mantissa << (highest - 52), 'integer result is not exact binary64')
    return (SIGN if negative else 0) | ((highest + 1023) << 52) | (mantissa - (1 << 52))


def numerical_controls():
    corpus = set()
    for exponent in range(2048):
        fractions = {0, 1, 2, (1 << 51) - 1, 1 << 51, FRACTION - 1, FRACTION}
        if 1023 <= exponent <= 1074:
            boundary = 1 << (1075 - exponent)
            fractions.update(v for v in (boundary - 1, boundary, boundary + 1) if v <= FRACTION)
        corpus.update(sign | exponent << 52 | fraction
                      for sign in (0, SIGN) for fraction in fractions)
    corpus.update(int.from_bytes(hashlib.sha256(f'ceil94:{i}'.encode()).digest()[:8], 'little')
                  for i in range(4096))
    cases = sorted(corpus)
    expectations = [rational_ceiling(b) for b in cases]
    actual = [ceiling_rule(b) for b in cases]
    require(actual == expectations, 'integer rule differs from rational oracle')
    mutants = {'truncate_positive_fraction': 0, 'lose_negative_zero': 0,
               'quiet_signaling_nan': 0, 'early_large_exponent_return': 0}
    for bits, expected in zip(cases, expectations):
        e = (bits >> 52) & 0x7ff
        truncated = bits & ~(FRACTION >> (e - 1023)) if 1023 <= e <= 1074 else ceiling_rule(bits)
        mutants['truncate_positive_fraction'] += truncated != expected
        mutants['lose_negative_zero'] += (0 if expected == SIGN else expected) != expected
        quieted = bits | (1 << 51) if e == 0x7ff and bits & FRACTION else ceiling_rule(bits)
        mutants['quiet_signaling_nan'] += quieted != expected
        early = bits if e == 1074 else ceiling_rule(bits)
        mutants['early_large_exponent_return'] += early != expected
    require(all(mutants.values()), 'a semantic control survived the corpus')
    return {'cases': len(cases), 'exponent_fields': 2048, 'mismatches': 0,
            'inputs_sha256': digest(b''.join(struct.pack('<Q', b) for b in cases)),
            'expected_sha256': digest(b''.join(struct.pack('<Q', b) for b in expectations)),
            'semantic_control_mismatches': mutants,
            'meaning': 'integer rule versus exact rational oracle; no target execution'}


def corruption_controls(data, record):
    locations = {'body immediate': record['body']['file_offset'] + 0x14,
                 'negative zero constant': record['constants'][1]['file_offset'] + 7,
                 'slot addend': record['relocation']['record_file_offset'] + 16,
                 'FDE range': record['frames'][0]['records']['fde']['file_offset'] + 12}
    rejected = {}
    for name, offset in locations.items():
        changed = bytearray(data)
        changed[offset] ^= 1
        try:
            inspect(bytes(changed))
        except ValueError as error:
            rejected[name] = str(error)
        else:
            raise ValueError('corrupted structure accepted: ' + name)
    return rejected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', type=Path, help='write a new evidence record instead of comparing')
    args = parser.parse_args()
    check_manifest()
    data = (ROOT / 'artifacts/node/94/hl-node').read_bytes()
    require(digest(data) == TARGET, 'full target SHA-256 differs')
    result = inspect(data)
    result['numerical_controls'] = numerical_controls()
    result['corruption_controls'] = corruption_controls(data, result)
    with (PACKET / 'samples.tsv').open(encoding='utf-8') as source:
        samples = list(csv.DictReader(source, delimiter='\t'))
    require(len(samples) == 16, 'sample table is incomplete')
    for sample in samples:
        bits, expected = int(sample['input_bits'], 16), int(sample['expected_output_bits'], 16)
        require(ceiling_rule(bits) == rational_ceiling(bits) == expected,
                'sample differs: ' + sample['case'])
    result['samples'] = {'rows': len(samples), 'sha256': digest((PACKET / 'samples.tsv').read_bytes())}
    serialized = json.dumps(result, indent=2, sort_keys=True) + '\n'
    if args.write:
        with args.write.open('x', encoding='utf-8') as destination:
            destination.write(serialized)
    else:
        require((PACKET / 'evidence.json').read_text(encoding='utf-8') == serialized,
                'retained evidence differs from rederived record')
    print(json.dumps({'bytes': result['body']['bytes'], 'instructions': result['body']['instructions'],
                      'numerical_controls': result['numerical_controls'],
                      'corruption_controls': result['corruption_controls']}, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError) as error:
        print('ceil packet: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
