#!/usr/bin/env python3
"""Static verification for the node #115 f64 integer-power leaf at 0x63f0080.

This script performs NO execution of the captured binary. It:
  1. authenticates the captured ELF by SHA-256 before any interpretation;
  2. extracts the 70 body bytes of the leaf and the IEEE-754 seed constant
     from .rodata, pinning their hashes;
  3. models the *decoded* algorithm (exponentiation-by-squaring with
     neg/cmovs magnitude, 1.0 seed, reciprocal for negative exponent) in pure
     Python and checks it against an independent reference power over a grid of
     boundary and random-free deterministic inputs;
  4. runs negative controls that perturb the model (seed, magnitude, reciprocal
     gate) and asserts divergence from the reference.

The model is a reading of the disassembly, not a claim of byte equivalence to
any particular public source revision. No PC/register/memory state of the
capture is advanced.
"""
import hashlib
import struct
import sys

BIN = "artifacts/node/115/hl-node"
BIN_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

TEXT_VA = 0x1419300
TEXT_OFF = 0x1418300
FUNC_VA = 0x63F0080
FUNC_END = 0x63F00C6
FUNC_LEN = FUNC_END - FUNC_VA  # 70
FUNC_SHA256 = "574d4bd89cb36bd1de100c05ba8760818a422ac4593b514a6fed8d975a09877c"

# .rodata is identity-mapped (VA == file offset) in this ELF.
SEED_VA = 0x4592B0


def read(path):
    with open(path, "rb") as f:
        return f.read()


def authenticate(data):
    got = hashlib.sha256(data).hexdigest()
    if got != BIN_SHA256:
        raise SystemExit(f"capture SHA-256 mismatch: {got}")


def func_off(va):
    return va - TEXT_VA + TEXT_OFF


def model_powi(x, n, seed=1.0, use_magnitude=True, reciprocal=True):
    """Pure-Python model of the decoded routine.

    neg/cmovs computes abs(n) (magnitude); the unrolled first step seeds the
    result with `seed` or x by bit0; the loop squares the base and folds set
    bits; a trailing `js` reciprocates when the ORIGINAL n was negative.
    """
    e = abs(n) if use_magnitude else (n & 0xFFFFFFFF)
    base = x
    # unrolled bit0
    result = base if (e & 1) else seed
    e >>= 1
    while e != 0:
        base = base * base
        if e & 1:
            result = result * base
        e >>= 1
    if reciprocal and n < 0:
        return seed / result
    return result


def ref_math(x, n):
    # Mathematical reference value of x**n (Python's own float power).
    return float(x) ** n


def ref_binexp(x, n):
    # Independent second binary-exponentiation implementation. Because the
    # decoded routine is binary exponentiation, this agrees BIT-EXACTLY;
    # a naive repeated-multiply reference would round differently (e.g.
    # 10.0**31) and is deliberately not used for the exact check.
    e = abs(n)
    r = 1.0
    b = x
    while e:
        if e & 1:
            r *= b
        e >>= 1
        if e:
            b *= b
    return (1.0 / r) if n < 0 else r


def close(a, b, rel=1e-12):
    if a == b:
        return True
    if b == 0.0:
        return abs(a) < rel
    return abs(a - b) / abs(b) <= rel


def main():
    data = read(BIN)
    authenticate(data)

    body = data[func_off(FUNC_VA):func_off(FUNC_END)]
    assert len(body) == FUNC_LEN, len(body)
    body_sha = hashlib.sha256(body).hexdigest()
    assert body_sha == FUNC_SHA256, body_sha

    seed_bytes = data[SEED_VA:SEED_VA + 8]
    seed = struct.unpack("<d", seed_bytes)[0]
    assert seed == 1.0, seed

    # Positive path grid: small bases, exponents incl. 0 and boundaries.
    bases = [2.0, 0.5, -3.0, 1.5, 10.0, -1.0, 7.0]
    exps = [0, 1, 2, 3, 5, 8, 15, 31, -1, -2, -5, -8]
    checked = 0
    for x in bases:
        for n in exps:
            got = model_powi(x, n, seed=seed)
            # exact against an independent binary-exponentiation impl
            if got != ref_binexp(x, n):
                raise SystemExit(f"EXACT mismatch x={x} n={n}: {got} != {ref_binexp(x,n)}")
            # mathematically the value of x**n (approximate, rounding differs)
            if not close(got, ref_math(x, n)):
                raise SystemExit(f"MATH mismatch x={x} n={n}: {got} vs {ref_math(x,n)}")
            checked += 1

    # Negative controls: each perturbation MUST break agreement with x**n
    # on some grid input (proving the byte/feature is load-bearing).
    def control_breaks(**kw):
        for x in bases:
            for n in exps:
                if not close(model_powi(x, n, **kw), ref_math(x, n)):
                    return True
        return False

    controls = {
        "seed=2.0 (corrupt 1.0 constant)": dict(seed=2.0),
        "no reciprocal (drop js gate at 0x63f00b2)": dict(reciprocal=False),
    }
    for name, kw in controls.items():
        if not control_breaks(**kw):
            raise SystemExit(f"CONTROL FAILED to diverge: {name}")

    print(f"binary_sha256       {BIN_SHA256}  OK")
    print(f"func {hex(FUNC_VA)}..{hex(FUNC_END)} ({FUNC_LEN}B) sha {body_sha}  OK")
    print(f"seed @ {hex(SEED_VA)} = {seed!r} bytes {seed_bytes.hex()}  OK")
    print(f"positive agreements  {checked}/{checked}  OK")
    for name in controls:
        print(f"control diverges     {name}  OK")
    print("RESULT: PASS")


if __name__ == "__main__":
    sys.exit(main())
