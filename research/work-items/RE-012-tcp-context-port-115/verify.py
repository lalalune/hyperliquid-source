#!/usr/bin/env python3
"""Evidence-corruption controls and scalar worksheets, not target execution."""
import argparse
import copy
import json
from pathlib import Path
import re

import collect as evidence


def run(native, out):
    data = (evidence.ROOT / 'artifacts/node/115/hl-node').read_bytes()
    evidence.authenticate(data)
    image = evidence.Image(data)
    anchors = json.loads((evidence.PACKET / 'anchors.json').read_text())
    evidence.bindings(image, anchors)
    rejected = []

    def reject(name, fn):
        try:
            fn()
        except ValueError:
            rejected.append(name)
        else:
            raise ValueError('Accepted corrupt evidence: '+name)

    # Deliberately bypass the outer digest guard only in these in-memory controls.
    # This challenges the selected evidence, rather than merely its file hash.
    def mutated_read(va):
        altered = copy.copy(image)
        def read(start, count):
            raw = bytearray(image.read(start, count))
            if start <= va < start+count:
                raw[va-start] ^= 1
            return bytes(raw)
        altered.read = read
        return altered

    for anchor in anchors:
        va = int(anchor['va'], 16)+len(bytes.fromhex(anchor['bytes_hex']))-1
        reject('anchor:'+anchor['name'], lambda va=va: evidence.bindings(mutated_read(va), anchors))
    for va in [0x607018, 0x607024, 0x604ac4, 0x604c10, 0x604cbc]:
        reject('data:'+hex(va), lambda va=va: evidence.bindings(mutated_read(va), anchors))
    for slot in [*evidence.RELATIVE, *evidence.IMPORTS]:
        altered = copy.copy(image)
        altered.relocs = dict(image.relocs)
        altered.relocs[slot] = image.relocs[slot]*2
        reject('duplicate-relocation:'+hex(slot), lambda: evidence.bindings(altered, anchors))
        info, addend = image.relocs[slot][0]
        altered.relocs[slot] = [(info, addend+1)]
        reject('changed-relocation:'+hex(slot), lambda: evidence.bindings(altered, anchors))
    reject('truncated-artifact', lambda: evidence.authenticate(data[:-1]))
    reject('same-size-wrong-artifact', lambda: evidence.authenticate(bytes([data[0]^1])+data[1:]))
    raw = (native / 'constructor.gnu.objdump').read_bytes()
    lines = raw.splitlines(keepends=True)
    instruction = re.compile(rb'^\s*[0-9a-f]+:\s+(?:[0-9a-f]{2}[ \t]+)+')
    last = max(i for i, line in enumerate(lines) if instruction.match(line))
    truncated = b''.join(lines[:last]+lines[last+1:])
    start, end = evidence.RANGES['constructor']
    evidence.native_rows(raw, image, start, end)
    reject('truncated-native-export', lambda: evidence.native_rows(truncated, image, start, end))

    # Independent arithmetic statement for the observed widths. No target
    # instructions, decoder-produced IR, sockets or CPU emulator are executed.
    cases = 0
    for port in range(1 << 16):
        network_bytes = bytes([port >> 8, port & 255])
        rotate16 = ((port << 8) | (port >> 8)) & 0xffff
        evidence.require(rotate16.to_bytes(2, 'little') == network_bytes, 'Port byte-order worksheet')
        for high in [0, 1, 0x8000, 0xffff]:
            word = port | (high << 16)
            selected = ((word - 4000) & 0xffffffff) & 0xffff
            evidence.require((selected < 65534) == (port not in (3998, 3999)), 'Low-word worksheet')
            for length in [0, 1024, 1025, (1 << 64)-1]:
                observed = length >= 1025 and selected < 65534
                expected = length > 1024 and port not in (3998, 3999)
                evidence.require(observed == expected, 'Eligibility worksheet')
                cases += 1
    boundaries = [{'length': n, 'port': p, 'compression_eligible': n >= 1025 and p not in (3998,3999)}
                  for n in [1024,1025] for p in [3997,3998,3999,4000,4001,65535]]
    report = {
        'target_sha256': evidence.TARGET,
        'captured_code_executed_or_emulated': False,
        'authentic_binding_check': 'pass',
        'negative_controls_rejected': rejected,
        'negative_control_count': len(rejected),
        'byte_order_worksheet_values': 65536,
        'eligibility_worksheet_cases': cases,
        'upper_word_samples': [0,1,32768,65535],
        'general_padding_argument': 'For any u32 x, low16(x - 4000 mod 2^32) = (low16(x) - 4000) mod 2^16. Thus high16 cannot affect the subsequent u16 comparison.',
        'boundary_examples': boundaries,
        'comparison_scope': 'Static evidence integrity and arithmetic corroboration only; no Rust or target behavioral equivalence claim.',
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8', newline='\n')
    print(json.dumps({'negative_controls': len(rejected), 'worksheet_cases': cases}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', type=Path, default=evidence.PACKET / 'native')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    run(args.native, args.out)
