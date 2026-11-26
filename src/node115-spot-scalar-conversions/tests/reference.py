"""Branch oracle using unbounded integers, including native u64 refusal points."""
from random import Random

max_word = (1 << 64) - 1
rng = Random(115)
for exp in range(20):
    factor = 10 ** exp
    near = {0, 1, 2, 7, factor, factor-1, factor+1, 1 << 32,
            max_word // factor, max_word // factor + 1, max_word - 1, max_word}
    valid = sorted(n for n in near if 0 <= n <= max_word)
    pairs = [(a,b) for a in valid for b in valid]
    pairs += [(rng.getrandbits(64),rng.getrandbits(64)) for _ in range(48)]
    for a,b in pairs:
        if b == 0:
            first = 0
        else:
            first = (a * factor // b if a * factor <= max_word else (a // b) * factor)
            first = max(1,first) if first <= max_word else 0
        second = a*b // factor
        if a*b > max_word:
            if a % factor == 0 or b % factor == 0:
                pass  # One exact cancellation preserves the quotient.
            else:
                second = min(a,b)*(max(a,b)//factor)
            if second > max_word:
                second = 0
        print(exp, a, b, first, second)
