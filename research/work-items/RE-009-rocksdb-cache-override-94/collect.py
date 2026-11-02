#!/usr/bin/env python3
"""Static, digest-bound cache-argument provenance evidence; never executes target."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import fde_extents

DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
STARTS = [0x37d4e30, 0x3315c30, 0x3be4b40, 0x3421980,
          0x459a4c0, 0x489d280, 0x4875ba0, 0x42c70c0]
# Independently read from the authenticated target, not inferred reference Rust.
PINS = {
    'state_entry_pair_stores': (0x37d4e41, '48897424684889542470'),
    'state_bundle_2': (0x37d4ed6, 'c644241802'),
    'state_capture_pair_address': (0x37d4ee0, '488d4424684889442410'),
    'state_capture_input': (0x3315c3b, '4989f6'),
    'state_capture_forward': (0x3315c99, '4c89f7'),
    'state_capture_load_pair': (0x3be4b69, '488b4708488b084c8b4008'),
    'state_saved_override': (0x342199b, '4d89c64989cf'),
    'state_selection': (0x3421a56, '41f6c701bf02000000490f45fe4889f848c1e822'),
    'checkpoint_entry_pair_stores': (0x459a4d1, '48897424684889542470'),
    'checkpoint_bundle_range': (0x459a55a, '48c74424300000000048c74424380200000066c74424400001'),
    'checkpoint_capture_pair_address': (0x459a578, '488d4424684889442428'),
    'checkpoint_capture_copy': (0x489d28e, '488b462048894424500f10060f104e100f294c24400f29442430'),
    'checkpoint_capture_base': (0x489d2ab, '488d742430'),
    'checkpoint_pair_pointer': (0x4875c4f, '488b5e08'),
    'checkpoint_pair_words': (0x4875cad, '488b0b4c8b4308'),
    'checkpoint_saved_override': (0x42c70dd, '4d89c64989cf'),
    'checkpoint_selection': (0x42c71b1, '41f6c701bf10000000490f45fe4889f848c1e822'),
}
CALLS = [(0x37d4ef4, 0x3315c30), (0x3315c9c, 0x3be4b40),
         (0x3be4b7c, 0x3421980), (0x459a58c, 0x489d280),
         (0x489d2b0, 0x4875ba0), (0x4875cc8, 0x42c70c0)]


def mapped(secs, address, size):
    matches = [s for s in secs if s['type'] != 8 and
               s['address'] <= address and address + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('Non-unique address mapping')
    return matches[0]['offset'] + address - matches[0]['address']


def check_pins(data, secs):
    for name, (address, encoded) in PINS.items():
        expected = bytes.fromhex(encoded)
        offset = mapped(secs, address, len(expected))
        if data[offset:offset + len(expected)] != expected:
            raise ValueError(name)
    for site, target in CALLS:
        offset = mapped(secs, site, 5)
        if data[offset] != 0xe8 or site + 5 + struct.unpack_from('<i', data, offset + 1)[0] != target:
            raise ValueError(f'Call mismatch {site:#x}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--objdump', default=shutil.which('llvm-objdump'))
    args = parser.parse_args()
    if not args.objdump:
        parser.error('Supply an installed llvm-objdump path')
    binary = ROOT / 'artifacts/node/94/hl-node'
    data = binary.read_bytes()
    if hashlib.sha256(data).hexdigest() != DIGEST:
        raise ValueError('Target SHA-256 mismatch')
    secs = sections(data)
    check_pins(data, secs)
    _, fdes, _ = fde_extents(data)
    chosen = []
    for start in STARTS:
        rows = [f for f in fdes if f['start'] == start]
        if len(rows) != 1:
            raise ValueError('Missing or duplicate selected FDE start')
        chosen.append(rows[0])
    controls = []
    # Bypass digest deliberately: each claimed provenance instruction and each
    # call must independently reject a one-byte corruption, not only fail hash.
    for name, (address, encoded) in PINS.items():
        changed = bytearray(data)
        changed[mapped(secs, address, len(bytes.fromhex(encoded)))] ^= 1
        try:
            check_pins(changed, secs)
        except ValueError:
            controls.append({'control': name, 'result': 'rejected'})
        else:
            raise ValueError('Corruption accepted: ' + name)
    for site, target in CALLS:
        changed = bytearray(data)
        changed[mapped(secs, site, 5) + 1] ^= 1
        try:
            check_pins(changed, secs)
        except ValueError:
            controls.append({'control': f'call-displacement-{site:#x}', 'result': 'rejected'})
        else:
            raise ValueError('Call corruption accepted')
    out = Path(__file__).resolve().parent
    version = subprocess.run([args.objdump, '--version'], check=True, capture_output=True, text=True).stdout
    (out / 'llvm-version.txt').write_text(version)
    decoded = {}
    for f in chosen:
        cmd = [args.objdump, '-d', '--x86-asm-syntax=intel',
               f"--start-address={f['start']:#x}", f"--stop-address={f['end']:#x}",
               'artifacts/node/94/hl-node']
        result = subprocess.run(cmd, cwd=ROOT, check=True, capture_output=True, text=True)
        (out / f"{f['start']:x}.llvm.txt").write_text(result.stdout)
        for line in result.stdout.splitlines():
            match = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} )+)\s*(.*)$', line)
            if match:
                decoded[int(match[1], 16)] = match[3]
    for _, (address, _) in PINS.items():
        if address not in decoded:
            raise ValueError(f'Pinned address is not a decoded instruction start: {address:#x}')
    for site, target in CALLS:
        if not re.search(rf'\bcall\s+{target:#x}\b', decoded.get(site, '')):
            raise ValueError(f'Disassembler did not confirm direct call: {site:#x}')
    records = {
        'target_sha256': DIGEST, 'target_size': len(data),
        'source_revision': 'e5c9b6436876b2a4a39daef813171f9879317699',
        'reference_revision': '999556f6e0a474b8312db96ec3149e1c44e97c23',
        'reference_use': 'Only prior question/labels; no inferred Rust copied',
        'coordinate_system': 'ELF virtual addresses; end exclusive',
        'fde_ranges': [{**{k: hex(v) if isinstance(v, int) else v for k, v in f.items()},
                        'raw_sha256': hashlib.sha256(data[mapped(secs, f['start'], f['end'] - f['start']):
                                                              mapped(secs, f['start'], f['end'] - f['start']) + f['end'] - f['start']]).hexdigest()}
                       for f in chosen],
        'pins': {name: {'va': hex(address), 'bytes': encoded} for name, (address, encoded) in PINS.items()},
        'decoded_direct_calls': [{'site': hex(s), 'target': hex(t)} for s, t in CALLS],
        'negative_controls': controls,
        'counts': {'fde_ranges': len(chosen), 'provenance_pins': len(PINS), 'direct_calls': len(CALLS),
                   'rejected_corruptions': len(controls)},
        'limitations': ['FDEs describe unwind extents, not a complete function census.',
                        'No target execution, Rust reconstruction, equivalence or full gate claim.',
                        'Entry RSI/RDX concrete values and earlier producers remain unknown.',
                        'Pins validate recorded instructions, not arbitrary control-flow/dataflow proofs.'],
    }
    (out / 'records.json').write_text(json.dumps(records, indent=2) + '\n')
    print(json.dumps(records['counts'], sort_keys=True))


if __name__ == '__main__':
    main()
