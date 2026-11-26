"""Emit deterministic expected values, using arbitrary-precision integer arithmetic."""
import random

rng = random.Random(434910)
limit = (1 << 60) * 4 // 5  # floor(2**62 / 5), the native strict bound
maximum = (1 << 256) - 1
for exponent in range(-128, 128):
    factor = 10 ** abs(exponent)
    inputs = {0, 1, limit - 1, limit, limit + 1, maximum}
    for boundary in (factor, limit * factor, limit // factor, maximum // factor,
                     1 << 64, 1 << 128, 1 << 192):
        inputs.update(boundary + delta for delta in (-1, 0, 1))
    inputs.update(rng.getrandbits(bits) for bits in (32, 58, 60, 64, 96, 128, 192, 256))
    for original in sorted(x for x in inputs if 0 <= x <= maximum):
        after = original
        accepted = -1
        if factor < 1 << 64:
            if exponent < 0:
                scaled = original * factor
            else:
                after = scaled = original // factor
            if scaled < limit:
                accepted = scaled
        print(exponent, format(original, "064x"), format(after, "064x"), accepted)
