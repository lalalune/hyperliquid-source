#!/usr/bin/env python3
"""Bind node #115 EVM JSON byte serialization to its exact hex/JSON helpers."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records

TARGET = ROOT / 'artifacts/node/115/hl-node'
TARGET_SIZE = 105_896_032
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
EXPECTED_FDES = {
    0x25ce7e0: 0x25ce8cb,
    0x2a315b0: 0x2a31733,
    0x2a31790: 0x2a318cf,
}
TEXT_WITNESSES = {
    # Existing EVM JSON entry passes the input slice and serializer to this writer.
    0x2591faf: '488b7b08488b73104c89f2e821c80300',
    # The writer formats the input slice into a temporary String before escaping it.
    0x25ce7e0: '41574156534883ec204889f04889fe4c8b32488d7c24084889c2e8b12d4600',
    # Open quote, grow if needed, append it, then call the shared JSON string escaper.
    0x25ce809: '498b7610493936745d498b4608c604302248ffc6498976',
    0x25ce821: '4c89f74889de4c89fae8010bffff498b',
    # Close quote; conditionally free the temporary String allocation.
    0x25ce838: '498b4608c604302248ffc64989761048',
    0x25ce847: '488b7424084885f67414',
    0x25ce851: '4889df31d24883c4205b415e415fff253b0cf103',
    0x25ce86f: 'ba01000000b90100000041b8010000004c89f7e8c9f7d4ff498b7610eb85',
    0x25ce88d: 'ba01000000b90100000041b8010000004c89f7e8abf7d4ff498b7610eb8d',
    0x25ce8ab: '4989c6488b7424084885f6740b4889df31d2ff15dd0bf1034c89f7e8',
    # The hex formatter writes "0x", then chooses scalar or vector nibble conversion.
    0x2a315f4: '66c70030784989c54983c502488b0559e4aa03488b004885c0',
    0x2a31613: 'a90002000075164885ed0f84b40000004883fd01751a31c0e9810000004c89e74889ee4c',
    0x2a31660: '410fb6340489f783e70f0fb63c17c1ee040fb63416418874470241887c4703410fb674040189f7',
    0x2a316ae: '4901c4410fb60c2489ca83e20f488d357e46a2fd0fb61432c1e9040fb60c3141884c4500418854450149',
    # The vectorized branch uses the same 16-byte hex alphabet as the scalar loop.
    0x2a317a1: '660f6f0507eca1fd660f6f0d8f45a2fd6666666666662e0f1f840000000000f30f6f140f660f6fda660f72d304660fdb',
    0x2a317c0: 'f30f6f140f660f6fda660f72d304660fdbd0660f6fe1660f3800e2660fdbd8660f6fd1660f3800d3660f6fda660f60dc660f68d4f30f7f1c',
}
RODATA_WITNESSES = {0x455d40: b'0123456789abcdef'}
SLOT_TARGETS = {
    0x64df480: 0x6355830,  # allocation used by the hex String formatter
    0x64df498: 0x141e264,  # allocation failure path
    0x64df4a0: 0x635de30,  # String buffer deallocation
    0x64dfa60: 0x6500098,  # formatter configuration word
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_at(data, section, va, size):
    require(section['address'] <= va and va + size <= section['address'] + section['size'],
            f'{va:#x}: span is outside {section["name"]}')
    offset = section['offset'] + va - section['address']
    require(offset + size <= len(data), f'{va:#x}: span is outside file')
    return data[offset:offset + size]


def relocation_targets(data, secs):
    matches = [s for s in secs if s['name'] == '.rela.dyn' and s['type'] == 4]
    require(len(matches) == 1, 'expected one file-backed .rela.dyn')
    section = matches[0]
    require(section['size'] % 24 == 0, '.rela.dyn size is not a multiple of Elf64_Rela')
    found = {}
    for pos in range(section['offset'], section['offset'] + section['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, pos)
        if slot not in SLOT_TARGETS:
            continue
        require(slot not in found, f'duplicate relocation at {slot:#x}')
        require((info & 0xffffffff) == 8 and (info >> 32) == 0,
                f'{slot:#x}: expected symbol-free R_X86_64_RELATIVE')
        found[slot] = addend
    require(found == SLOT_TARGETS, f'relocation target mismatch: {found!r}')
    return [{'slot': hex(slot), 'type': 'R_X86_64_RELATIVE', 'addend': hex(target)}
            for slot, target in sorted(found.items())]


def extract(data, *, expected_digest=TARGET_SHA256):
    digest = hashlib.sha256(data).hexdigest()
    if expected_digest is not None:
        require(len(data) == TARGET_SIZE and digest == expected_digest,
                f'target size/SHA-256 mismatch: size={len(data)}, sha256={digest}')
    secs = sections(data)
    text = next(s for s in secs if s['name'] == '.text' and s['type'] != 8)
    rodata = next(s for s in secs if s['name'] == '.rodata' and s['type'] != 8)
    fdes = {row['start']: row['end'] for _, rows in [eh_frame_records(data, secs)] for row in rows}
    for start, end in EXPECTED_FDES.items():
        require(fdes.get(start) == end,
                f'FDE mismatch at {start:#x}: observed {fdes.get(start)!r}, expected {end:#x}')
    instructions = {}
    for va, expected in TEXT_WITNESSES.items():
        raw = read_at(data, text, va, len(bytes.fromhex(expected)))
        require(raw.hex() == expected, f'instruction witness mismatch at {va:#x}: {raw.hex()}')
        instructions[hex(va)] = raw.hex()
    literals = {}
    for va, expected in RODATA_WITNESSES.items():
        raw = read_at(data, rodata, va, len(expected))
        require(raw == expected, f'rodata witness mismatch at {va:#x}: {raw!r}')
        literals[hex(va)] = raw.decode('ascii')
    return {
        'target': {'release': 115, 'size': len(data), 'sha256': digest,
                   'coordinate': 'ELF virtual address'},
        'scope': 'static trace of the node #115 EVM JSON bytes writer and its existing hex formatter',
        'fdes': [{'start': hex(start), 'end': hex(end), 'bytes': end - start,
                  'sha256': hashlib.sha256(read_at(data, text, start, end - start)).hexdigest()}
                 for start, end in sorted(EXPECTED_FDES.items())],
        'observations': [
            {'address': '0x2591fb7', 'fact': 'the existing send_to_evm_data JSON entry calls 0x25ce7e0 with its data pointer, length, and serializer'},
            {'address': '0x25ce7e0', 'fact': 'the writer calls 0x2a315b0 to create a temporary formatted String from the input byte slice'},
            {'address': '0x25ce812', 'fact': 'the writer appends an opening quote to the serializer Vec, passes the temporary String pointer and length to JSON escape helper 0x25bf330, and appends a closing quote'},
            {'address': '0x25ce86f', 'fact': 'when the serializer Vec has no spare byte, the writer calls reserve with additional=1, alignment=1, element_size=1, then retries the quote append'},
            {'address': '0x25ce8ab', 'fact': 'the unwind cleanup checks temporary String capacity and calls the relocated deallocator when nonzero'},
            {'address': '0x2a315f4', 'fact': 'the helper allocates a buffer of 2*input_length+2 bytes and writes the two-byte prefix 0x'},
            {'address': '0x2a31613', 'fact': 'a configuration bit at mask 0x200 selects a vectorized helper; the other path uses a scalar nibble loop'},
            {'address': '0x2a31660', 'fact': 'the scalar path maps both nibbles of each input byte through the digit table at 0x455d40'},
            {'address': '0x2a317a1', 'fact': 'the vectorized path loads the same digit table at 0x455d40 before nibble lookup'},
            {'address': '0x455d40', 'fact': 'the 16-byte digit table is 0123456789abcdef'},
            {'address': '0x64dfa60', 'fact': 'the formatter configuration GOT slot is a symbol-free relative relocation to 0x6500098'},
        ],
        'inference': [
            'For successful formatting, the helper produces 0x followed by two lowercase hexadecimal digits per input byte; the empty slice therefore formats as 0x. Both scalar and vectorized paths use the same lowercase digit table.',
            'The byte writer surrounds that formatted ASCII string with JSON quotes and passes it through the shared string escaper. Because its output alphabet contains no JSON-escapable byte, successful output is the quoted 0x-prefixed lowercase hex string.',
            'The generic writer result and successful-allocation assumptions are limited to this observed static path; this packet does not establish all error, allocation-failure, or dynamic configuration behavior.',
        ],
        'unresolved': [
            'source-level identity and intended meaning of configuration bit 0x200',
            'the complete allocator failure and serialization Result/error contract',
            'runtime use of the global configuration and behavior under live node conditions',
        ],
        'instruction_witnesses': instructions,
        'literal_witnesses': literals,
        'relocations': relocation_targets(data, secs),
        'limitations': [
            'The node artifact was read statically and was not executed or emulated.',
            'The existing 0x25bf330 escape helper is reused by reference; its behavior was separately covered by evm-send-to-evm-data-json-115.',
            'FDE extents are unwind ranges, not proof of source-level function boundaries.',
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--binary', type=Path, default=TARGET)
    args = parser.parse_args(argv)
    report = extract(args.binary.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'records.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('verified node115 EVM JSON bytes writer: 0x-prefixed lowercase hex through JSON string escaping; error paths remain partial')


if __name__ == '__main__':
    main()
