#!/usr/bin/env python3
"""Pre-source value corpus: unbounded prefix mathematics and exact rational RN.

No host float arithmetic, production imports, captured execution or instruction
evaluation. Book cases generate impact results; no injected floating operands.
"""
import argparse
from collections import Counter
from fractions import Fraction
from functools import lru_cache
import hashlib
import gzip
import json
from pathlib import Path

U = (1 << 64) - 1
M = (1 << 63) - 2
SIGN = 1 << 63


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


@lru_cache(maxsize=None)
def value(word):
    exponent = (word >> 52) & 2047
    require(exponent != 2047, 'oracle does not admit nonfinite operands')
    fraction = word & ((1 << 52) - 1)
    mantissa = fraction if exponent == 0 else fraction + (1 << 52)
    power = -1074 if exponent == 0 else exponent - 1075
    result = Fraction(mantissa) * Fraction(2) ** power
    return -result if word & SIGN else result


@lru_cache(maxsize=None)
def rn(exact):
    """Find adjacent representables by bisection, then compare exact distances.

    This unbounded rational oracle is intentionally separate from the planned
    fixed-width integer significand implementation. The admitted operation's
    proof excludes nonzero subnormals and overflow; reject either here.
    """
    exact = Fraction(exact)
    if exact == 0:
        return 0  # nearest-even exact cancellation; XOR is represented separately
    sign = SIGN if exact < 0 else 0
    absolute = abs(exact)
    exponent = absolute.numerator.bit_length() - absolute.denominator.bit_length()
    if absolute < Fraction(2) ** exponent:
        exponent -= 1
    require(-1022 <= exponent <= 1023, 'outside proved normal rounding domain')
    unit = Fraction(2) ** (exponent - 52)
    low, high = 1 << 52, 1 << 53
    # Locate the lower adjacent significand without integer quotient/remainder
    # rounding, native floating operations, or an expected-output lookup table.
    while low + 1 < high:
        middle = (low + high) // 2
        if middle * unit <= absolute:
            low = middle
        else:
            high = middle
    lower, upper = low * unit, (low + 1) * unit
    down, up = absolute - lower, upper - absolute
    nearest = low + int(up < down or (up == down and low & 1))
    if nearest == 1 << 53:
        nearest >>= 1
        exponent += 1
    require(exponent <= 1023, 'rounding overflow outside proved domain')
    word = sign | ((exponent + 1023) << 52) | (nearest - (1 << 52))
    require(value(word) == (-nearest * Fraction(2) ** (exponent - 52)
                            if sign else nearest * Fraction(2) ** (exponent - 52)),
            'adjacent encoding mismatch')
    return word


def scaled(raw, divisor, fault):
    if fault == 'single-round-scale':
        return rn(Fraction(raw, divisor))
    return rn(value(rn(Fraction(raw))) / divisor)


def chain(book, head, fault):
    entries, slots = book
    if head >= len(slots):
        return None
    visited, quantities = set(), []
    while True:
        if head in visited:
            return 'cycle'
        visited.add(head)
        tag, quantity, continuation, after = slots[head]
        if (tag & 255 if fault == 'byte-tag' else tag) == 2:
            break
        quantities.append(quantity)
        if (continuation & 255 if fault == 'byte-continuation' else continuation) == 0:
            break
        if after >= len(slots):
            if fault == 'later-invalid-zero':
                return None
            break
        head = after
    total = sum(quantities)
    return total & U if fault == 'wrap-chain-quantity' else min(U, total)


def impact(book, target, fault=None):
    """First exact prefix crossing, not a register/PC or saturation interpreter."""
    entries, _ = book
    if fault == 'sort-levels':
        entries = sorted(entries, key=lambda e: min(e[0], (1 << 64) - e[0]))
    costs, quantities = [], []
    for raw_key, active, head in entries:
        if not active & 1 and fault != 'ignore-active-bit':
            return 0
        q = chain(book, head, fault)
        if q == 'cycle':
            return q
        if q is None:
            if fault == 'skip-invalid-initial':
                continue
            return 0
        if q == 0:
            return 0
        price = raw_key if raw_key < SIGN else (1 << 64) - raw_key
        if fault == 'unsigned-key':
            price = raw_key
        if fault == 'discard-zero-price' and price == 0:
            continue
        whole = price * q
        before = sum(costs)
        crosses = before + whole >= target
        if whole > M and not (fault == 'partial-cap-only' and crosses):
            return 0
        if not crosses:
            costs.append(whole)
            quantities.append(q)
            continue
        require(price > 0, 'positive-target crossing price')
        numerator = target - before
        n = (numerator + price - 1) // price if fault == 'ceil-partial' else numerator // price
        if fault == 'partial-cap-only' and price * n > M:
            return 0
        final_cost = before + price * n
        final_quantity = min(U, (0 if fault == 'forget-previous-quantity' else sum(quantities)) + n)
        if not 1 <= final_quantity <= final_cost:
            return 0
        return final_cost // final_quantity
    return 0


def evaluate(case, fault=None):
    asset, oracle, target, scale, mode, member, first_book, second_book = case
    require(first_book[1] is second_book[1], 'one shared native slab/count required')
    if fault == 'scale-after-oracle' and oracle == 0:
        return ('N', asset, 1, oracle)
    if scale > 6:
        return ('E', 'SCALE')
    if oracle == 0:
        return ('N', asset, 1, oracle)
    if target == 0:
        return ('E', 'TARGET')
    first = impact(first_book, target, fault)
    if first == 'cycle':
        return ('E', 'CYCLE1')
    if fault == 'short-circuit-zero' and first == 0:
        return ('N', asset, 1, oracle)
    second = impact(second_book, target, fault)
    if second == 'cycle':
        return ('E', 'CYCLE2')
    if first == 0 or second == 0:
        payload = rn(Fraction(oracle)) if fault == 'converted-fallback' else oracle
        return ('N', asset, 1, payload)
    if fault == 'swap-books':
        first, second = second, first
    divisor = 1 if fault == 'no-scale' else 10 ** (6 - scale)
    o, a, b = (scaled(x, divisor, fault) for x in (oracle, first, second))
    gap_mode = mode != 0 if fault != 'mode-one-only' else mode == 1
    if gap_mode:
        negative_b_minus_o = rn(value(b) - value(o)) ^ SIGN
        a_minus_o = rn(value(a) - value(o))
        x = a_minus_o if value(a_minus_o) > 0 else 0
        y = negative_b_minus_o if value(negative_b_minus_o) > 0 else 0
        v = rn(value(rn(value(x) - value(y))) / value(o))
    else:
        total = rn(value(a) + value(b))
        midpoint = total if fault == 'omit-half' else rn(value(total) / 2)
        v = rn(value(rn(value(midpoint) / value(o))) - 1)
    def clamp(word):
        return rn(max(Fraction(-1, 2), min(Fraction(1, 2), value(word))))
    if fault == 'divide-after-clamp':
        v = clamp(v)
        if member:
            v = rn(value(v) / 100)
    else:
        if member:
            v = rn(value(v) / 100)
        if fault != 'omit-clamp':
            v = clamp(v)
    if fault is None:
        require((v >> 52) & 2047 != 2047 and v != SIGN, 'active finite/+zero theorem')
        require(abs(value(v)) <= Fraction(1, 2), 'active clamp theorem')
    return ('V', v, first, second, asset, 0, v)


def book(levels):
    return ([(p & U, 1, i) for i, (p, _) in enumerate(levels)],
            [(0, q, 0, U) for _, q in levels])


def cases():
    out = []
    def add(label, a, b, oracle=100, target=100, scale=6, mode=0, member=False, asset=123456789):
        # Input construction only: embed two disjoint chain descriptions into
        # one real shared slab. The actual oracle/API has no per-side count.
        # Every previously invalid initial/later index maps to U, which remains
        # outside the small common slab. Never let concatenation admit it.
        shared, sequences = [], []
        for entries, slots in (a, b):
            base, count = len(shared), len(slots)
            def index(old):
                return base + old if old < count else U
            sequences.append([(key, active, index(head)) for key, active, head in entries])
            shared.extend((tag, quantity, continuation, index(after))
                          for tag, quantity, continuation, after in slots)
        out.append((label, (asset, oracle, target, scale, mode, member,
                            (sequences[0], shared), (sequences[1], shared))))
    empty = ([], [])
    ordinary = book([(100, 1)])
    cyclic = ([(100, 1, 0)], [(0, 1, 1, 0)])
    pairs = [(1, 1), (1, 2), (2, 1), (3, 7), (99, 101), (1000, 1001),
             ((1 << 32)-1, (1 << 32)+1), (1 << 53, (1 << 53)+1),
             (M, M), ((1 << 52)+1, (1 << 52)+3)]
    oracles = [0, 1, 2, 3, 99, 100, 101, (1 << 32)+1, (1 << 53)-1,
               (1 << 53)+1, (1 << 63)+1, U]
    for a, b in pairs:
        target = max(a, b)
        ba, bb = book([(a, (target+a-1)//a)]), book([(b, (target+b-1)//b)])
        for oracle in oracles:
            for scale in range(7):
                for mode in (0, 1, 255):
                    for member in (False, True):
                        add('value-matrix', ba, bb, oracle, target, scale, mode, member,
                            (oracle ^ a ^ (b << 1)) & U)
    special = [
        ('empty-first', empty, ordinary, 100),
        ('empty-second', ordinary, empty, 100),
        ('signed-price', book([(-100, 1)]), ordinary, 100),
        ('minimum-key', book([(-(1 << 63), 1)]), ordinary, 100),
        ('cap-before-partial', book([(M+1, 1)]), book([(M+1, 1)]), M+1),
        ('cap-valid-boundary', book([(M, 1)]), book([(M, 1)]), M),
        ('wide-product', book([(1 << 62, 4)]), ordinary, 100),
        ('terminal-floor-zero', book([(3, 2), (7, 2)]), book([(3, 4)]), 10),
        ('actual-order', book([(7, 2), (3, 2)]), book([(3, 4)]), 10),
        ('exhaustion', book([(1, 99)]), ordinary, 100),
        ('zero-price-quantity', book([(0, U), (1, 2)]), book([(1, 1)]), 1),
        ('zero-price-before-fill', book([(0, 1), (100, 2)]), ordinary, 100),
        ('zero-quantity', book([(100, 0)]), ordinary, 100),
        ('inactive-level', ([(100, 2, 0)], [(0, 1, 0, U)]), ordinary, 100),
        ('high-active-byte', ([(100, 255, 0)], [(0, 1, 0, U)]), ordinary, 100),
        ('invalid-initial', ([(100, 1, 9), (100, 1, 0)], [(0, 1, 0, U)]), ordinary, 100),
        ('invalid-later', ([(100, 1, 0)], [(0, 1, 1, U)]), ordinary, 100),
        ('tag2-before-quantity', ([(100, 1, 0)], [(2, U, 1, 0)]), ordinary, 100),
        ('dword-tag-not-byte', ([(100, 1, 0)], [(258, 1, 0, U)]), ordinary, 100),
        ('full-width-continuation', ([(50, 1, 0)], [(0, 1, 256, 1), (0, 1, 0, U)]), ordinary, 100),
        ('tag2-after-quantity', ([(100, 1, 0)], [(0, 1, U, 1), (2, U, U, 0)]), ordinary, 100),
        ('chain-saturation', ([(1, 1, 0)], [(0, U, 1, 1), (0, 2, 0, U)]), book([(1, 1)]), 1),
        ('unused-cycle-entry', ([(100, 1, 0), (1, 1, 1)], [(0, 1, 0, 0), (0, 1, 1, 1)]), ordinary, 100),
        ('same-slot-reused', ([(1, 1, 0), (2, 1, 0)], [(0, 1, 0, U)]), book([(3, 1)]), 3),
        ('ignored-next-cycle', ([(100, 1, 0)], [(0, 1, 0, 0)]), ordinary, 100),
    ]
    for label, a, b, target in special:
        for mode in (0, 255):
            for scale in (0, 6):
                for member in (False, True):
                    add(label, a, b, 100, target, scale, mode, member, U)
    for scale in (7, 8, 127, 255):
        for oracle in (0, 1):
            for target in (0, 1):
                add('policy-invalid-scale', cyclic, cyclic, oracle, target, scale)
    for target in (0, 1, U):
        add('oracle-zero-bypasses-books-target', cyclic, cyclic, 0, target)
    add('policy-zero-target', ordinary, ordinary, 1, 0)
    add('policy-cycle-first', cyclic, ordinary)
    add('policy-cycle-second', ordinary, cyclic)
    add('policy-first-zero-second-cycle', empty, cyclic)
    add('oracle-zero-invalid-initial', ([(1, 1, U)], []), empty, 0, 0)
    shared = [(0, 1, 0, U)]
    out.append(('same-slot-both-trees', (U, 100, 100, 6, 255, False,
                                       ([(100, 1, 0)], shared), ([(100, 1, 0)], shared))))
    shared = [(0, 1, 1, 1), (0, 1, 0, U)]
    out.append(('shared-chain-two-heads', (U, 100, 100, 6, 255, False,
                                         ([(50, 1, 0)], shared), ([(100, 1, 1)], shared))))
    # Deterministic PRNG supplies diverse finite, acyclic logical books; no
    # platform random module or floating distribution enters the oracle.
    state = 0x14223750ce03c027d
    def next_word():
        nonlocal state
        state = (state * 6364136223846793005 + 1442695040888963407) & U
        return state
    for index in range(768):
        books = []
        for side in range(2):
            entries, slots = [], []
            for _ in range(1 + next_word() % 6):
                price = next_word() % 1000000
                if next_word() & 1:
                    price = -price
                head = len(slots)
                count = 1 + next_word() % 4
                entries.append((price & U, 1, head))
                for j in range(count):
                    quantity = next_word() % 1000
                    slots.append((0, quantity, (1 << (next_word() % 64)) if j+1 < count else 0,
                                  head+j+1 if j+1 < count else U))
            books.append((entries, slots))
        oracle = next_word() % 1000000 + 1 if index % 3 else next_word()
        target = next_word() % 1000000000 + 1
        add('deterministic-multilevel', *books, oracle, target, next_word() % 7,
            next_word() % 256, bool(next_word() & 1), next_word())
    return out


def encode_input(index, case):
    asset, oracle, target, scale, mode, member, a, b = case
    require(a[1] is b[1], 'protocol common slab')
    words = [index, asset, oracle, target, scale, mode, int(member),
             len(a[0]), len(b[0]), len(a[1])]
    for entries in (a[0], b[0]):
        for row in entries:
            words.extend(row)
    for row in a[1]:
        words.extend(row)
    return ' '.join(f'{x:016x}' for x in words) + '\n'


def encode_output(index, result):
    return f'{index:016x} ' + ' '.join(x if isinstance(x, str) else f'{x:016x}' for x in result) + '\n'


FAULTS = ['sort-levels', 'unsigned-key', 'partial-cap-only', 'ceil-partial',
          'forget-previous-quantity', 'discard-zero-price', 'wrap-chain-quantity',
          'skip-invalid-initial', 'later-invalid-zero', 'byte-tag', 'byte-continuation',
          'ignore-active-bit', 'swap-books', 'mode-one-only', 'no-scale',
          'single-round-scale', 'omit-half', 'divide-after-clamp', 'omit-clamp',
          'converted-fallback', 'scale-after-oracle', 'short-circuit-zero']


def generate(out):
    require(not out.exists(), 'existing output refused')
    inputs, outputs, labels = [], [], ['case\tcategory\tresult']
    counts, witnesses = Counter(), {}
    all_cases = cases()
    for index, (category, case) in enumerate(all_cases):
        expected = evaluate(case)
        inputs.append(encode_input(index, case))
        outputs.append(encode_output(index, expected))
        labels.append(f'{index:016x}\t{category}\t{expected[0]}')
        counts[expected[0]] += 1
        for fault in FAULTS:
            if fault in witnesses:
                continue
            wrong = evaluate(case, fault)
            if wrong != expected:
                witnesses[fault] = {'case': f'{index:016x}', 'category': category,
                                    'expected': encode_output(index, expected).strip(),
                                    'false_model': encode_output(index, wrong).strip(),
                                    'scope': 'safe policy only, outside native ordinary theorem'
                                    if fault in ('scale-after-oracle', 'short-circuit-zero') else 'ordinary value relation'}
    require(set(witnesses) == set(FAULTS), 'unwitnessed false models: ' + str(set(FAULTS)-set(witnesses)))
    out.mkdir(parents=True)
    streams = {}
    for name, lines in [('inputs.txt', inputs), ('expected.txt', outputs)]:
        raw = ''.join(lines).encode('ascii')
        stored = gzip.compress(raw, mtime=0)
        (out / (name + '.gz')).write_bytes(stored)
        streams[name] = {'file': name + '.gz', 'raw_sha256': hashlib.sha256(raw).hexdigest(),
                         'raw_bytes': len(raw), 'stored_sha256': hashlib.sha256(stored).hexdigest(),
                         'stored_bytes': len(stored)}
    (out / 'cases.tsv').write_text('\n'.join(labels) + '\n')
    report = {'case_count': len(all_cases), 'result_counts': dict(sorted(counts.items())),
              'category_counts': dict(sorted(Counter(x[0] for x in all_cases).items())),
              'false_model_witnesses': witnesses,
              'streams': streams,
              'files': {n: hashlib.sha256((out/n).read_bytes()).hexdigest()
                        for n in ('inputs.txt.gz', 'expected.txt.gz', 'cases.tsv')},
              'independence': 'Pre-source Python Fraction/adjacent-representable rounding and exact prefix sums; no host FP, production imports, captured evaluation or injected impacts.',
              'limit': 'Finite mathematical witnesses, not native execution or universal semantic proof. Two witnesses concern new safe policy only; both-impact ordinary order remains a source-review invariant.'}
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    return {'case_count': len(all_cases), 'result_counts': dict(counts), 'false_models': len(witnesses)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(generate(args.out)))
