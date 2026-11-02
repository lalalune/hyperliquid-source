"""All-u16 arithmetic proof of the actual fixed decimal writer's expressions.

No target or instruction evaluation: evaluate mathematical integer expressions
and compare them to the independent decimal numeral definition over a complete
finite domain. No registers, machine memory, PC, instruction dispatch or native
code are modeled or executed.
"""
from pathlib import Path
import hashlib
import json

OUT = Path(__file__).resolve().parent
rows = []
for n in range(65536):
    width = 1 if n == 0 else (
        (((n + 0x5fff6) & (n + 0x7ff9c)) ^
         ((n + 0xdfc18) & (n + 0x7d8f0))) // (1 << 17) + 1)
    q10 = n * 0xcccd // (1 << 19)
    q100 = (n // 4) * 0x147b // (1 << 17)
    q1000 = (n // 8) * 0x20c5 // (1 << 20)
    q10000 = (n // 16) * 0x347 // (1 << 19)
    assert q10 == n // 10
    assert q100 == n // 100
    assert q1000 == n // 1000
    assert q10000 == n // 10000
    decimal_digits = [n - 10 * q10]
    for quotient in (q10, q100, q1000):
        assert quotient * 0x199a < (1 << 32)
        scaled_even = (quotient * 0x199a // (1 << 15)) & ~1
        digit = quotient - 5 * scaled_even
        assert digit == quotient % 10
        decimal_digits.append(digit)
    decimal_digits.append(q10000)
    assert all(0 <= digit <= 9 for digit in decimal_digits)
    encoded = bytes(0x30 | decimal_digits[index] for index in range(width - 1, -1, -1))
    assert encoded == str(n).encode('ascii')
    rows.append(f'{n}\t{encoded.hex()}\n')
raw = ''.join(rows).encode()
(OUT / 'u16-decimal-output.tsv').write_bytes(raw)
report = dict(schema='root-u16-decimal-fixed-writer-arithmetic-proof-v1',
              target_sha256='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f',
              helper_range=['0x1572b20', '0x1572da9'],
              helper_sha256='8a8da4e2ea89dea2c9687bd9936c9a5e44d2396480dced263337ffa47658cea3',
              decimal_block=['0x1572ca0', '0x1572d94'],
              domain=65536, quotient_mismatches=0, complete_numeral_mismatches=0,
              maximum_width=5,
              facts=['All integer multiplications fit u32 on the finite u16 domain.',
                     'Every emitted byte lies in ASCII0..9; OR0x30 equals addition0x30.',
                     'Selected1..5 output bytes have all been initialized.',
                     'Width6..8 branches are unreachable for admitted u16 payload.',
                     'Frozen before any new Rust for this emitter was authored.'],
              authority=dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()),
              generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              captured_binary_or_instruction_execution=False,
              limitations=['Only the arithmetic decimal payload relation is closed here.',
                           'Callback sequencing/state/failure effects require a separate complete proof.',
                           'No original ABI, runtime or whole-node identity is established.'])
(OUT / 'DECIMAL-PROOF.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
print(json.dumps(report, indent=2, sort_keys=True))
