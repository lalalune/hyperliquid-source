#!/usr/bin/env python3
"""Retained-row and exact finite-integer challenge; no instruction evaluator."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import re


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def need(ok, message):
    if not ok:
        raise ValueError(message)


def main():
    out = Path(__file__).resolve().parent
    native = Path('/tmp/hl-resume-20261101/root-parts-next')
    body = (native / '1572b20.raw').read_bytes()
    need(len(body) == 649 and sha(body) == '8a8da4e2ea89dea2c9687bd9936c9a5e44d2396480dced263337ffa47658cea3', 'Native body identity')
    rows = []
    for line in (native / '1572b20.objdump').read_text().splitlines():
        match = re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)\s*(.*)', line)
        if match:
            rows.append((int(match[1], 16), bytes.fromhex(match[2]), match[3]))
    need(len(rows) == 169 and b''.join(raw for _, raw, _ in rows) == body, 'Complete169-row byte tiling')
    cursor = 0x1572b20
    for address, raw, _ in rows:
        need(address == cursor, 'Noncontiguous native rows')
        cursor += len(raw)
    need(cursor == 0x1572da9, 'Native endpoint')
    calls = [address for address, _, text in rows if text.startswith('call')]
    need(calls == [0x1572b49, 0x1572b87, 0x1572c2f, 0x1572c5d, 0x1572c8a], 'Complete five-callback closure')
    need(all(not (raw[:1] == b'\xe8' or raw[:2] == b'\xff\x15') for _, raw, _ in rows), 'Unexpected fixed callee/GOT edge')
    by_address = {address: raw for address, raw, _ in rows}
    for address in [0x1572c28, 0x1572c80]:
        raw = by_address[address]
        need(len(raw) == 7 and raw[:3] == b'\x48\x8d\x35', 'Expected actual zero-literal LEA')
        need(address + 7 + int.from_bytes(raw[3:], 'little', signed=True) == 0x252cb8, 'Actual literal target')
    admission_raw = (native / 'ADMISSION.json').read_bytes()
    need(sha(admission_raw) == '9cfc39596eb319bb0aaf7a81250089b1dc550ab175611216f46d5e745f4061f3', 'Root actual intake changed')
    admission = json.loads(admission_raw)
    need(admission['protected_overlaps'] == [] and sum(admission['all_RELA_counts'].values()) == 80300, 'Recorded literal/code write closure')
    need(admission['literal']['sha256'] == sha(b'0' * 64), 'Actual64-zero literal')

    # These are fixed mathematical integer expressions, derived from the
    # complete listing. They have no PC, register file or simulated memory.
    # The independent reference is direct decimal threshold/divmod arithmetic.
    widths, output_rows = Counter(), []
    maximum_products = [0, 0, 0, 0, 0]
    for n in range(65536):
        length = 1 if n == 0 else (((n + 0x5fff6) & (n + 0x7ff9c)) ^
                                 ((n + 0xdfc18) & (n + 0x7d8f0))) // 131072 + 1
        wanted_length = 1 + sum(n >= power for power in (10, 100, 1000, 10000))
        need(length == wanted_length, 'Decimal length expression')
        products = (n * 52429, (n // 4) * 5243, (n // 8) * 8389, (n // 16) * 839)
        quotients = (products[0] // 524288, products[1] // 131072,
                     products[2] // 1048576, products[3] // 524288)
        need(quotients == tuple(n // power for power in (10, 100, 1000, 10000)), 'Native reciprocal quotient')
        for index, value in enumerate(products):
            maximum_products[index] = max(maximum_products[index], value)
            need(value < 1 << 32, 'Native u32 product would wrap')
        digits = [n - 10 * quotients[0]]
        for value in quotients[:3]:
            maximum_products[4] = max(maximum_products[4], value * 6554)
            even_scaled = (value * 6554 // 32768) & ~1
            need(even_scaled == 2 * (value // 10), 'Native even quotient')
            digits.append(value - 5 * even_scaled)
        digits.append(quotients[3])
        need(all(0 <= d <= 9 for d in digits), 'Nondecimal digit')
        encoded = bytes((digits[k] | 48) for k in range(length - 1, -1, -1))
        wanted = str(n).encode('ascii')
        need(encoded == wanted, 'Full decimal numeral differs')
        widths[length] += 1
        output_rows.append(str(n).encode() + b'\t' + wanted.hex().encode() + b'\n')
    expected_bytes = b''.join(output_rows)
    root_decimal = json.loads((native / 'DECIMAL-PROOF.json').read_bytes())
    need(sha(expected_bytes) == root_decimal['authority']['sha256'] == 'c9042b15746d27dee7e02acb3884d0f0482ab2427bcaf83b0213870c81f467af', 'Separate root decimal authority differs')
    need(sha((native / 'u16-decimal-output.tsv').read_bytes()) == sha(expected_bytes), 'Actual retained decimal rows differ')
    report = {'schema': 'writer649-independent-pre-source-native-challenge/1', 'status': 'PASS',
              'new_Rust_seen_or_executed': False, 'captured_execution_or_instruction_evaluator': False,
              'native_body_sha256': sha(body), 'native_bytes': len(body), 'native_rows': len(rows),
              'all_callback_call_sites': [hex(address) for address in calls],
              'root_actual_intake_sha256': sha(admission_raw),
              'root_theorem_sha256': sha((native / 'WRITER-649-PROOF.md').read_bytes()),
              'root_decimal_proof_sha256': sha((native / 'DECIMAL-PROOF.json').read_bytes()),
              'decimal_domain': 65536, 'complete_length_and_numeral_mismatches': 0,
              'decimal_width_distribution': dict(widths), 'maximum_native_products': maximum_products,
              'every_product_fits_u32': all(value < 1 << 32 for value in maximum_products),
              'direct_decimal_authority_sha256': sha(expected_bytes),
              'native_proof_sha256': sha((out / 'PROOF.md').read_bytes()),
              'challenge_script_sha256': sha(Path(__file__).read_bytes()),
              'limits': ['Root full-target/code/literal/RELA admission was checked as a frozen record; no new target read was made.',
                         'Fixed exact-integer formulas and retained row bytes are checked; no target code, PC/register/memory evaluator or compiler runs.',
                         'Full request/effect theorem is conditional on immutable inputs, valid mapped byte views and supplied normal callbacks.']}
    path = out / 'NATIVE-CHALLENGE.json'
    need(not path.exists(), 'Preserve prior challenge')
    path.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'path': str(path), 'sha256': sha(path.read_bytes()), 'status': report['status'],
                      'proof_sha256': report['native_proof_sha256']}, sort_keys=True))


if __name__ == '__main__':
    main()
