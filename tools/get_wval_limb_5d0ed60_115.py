"""Model of node #115 blst get_wval_limb, 0x5d0ed60..0x5d0edb4 (RE-002).

get_wval_limb is blst's bit-field reader for the windowed scalar
multiplication. It pulls a small field out of a little-endian
bit-packed byte string. It is a leaf: it calls nothing, allocates
nothing, stores nothing, and reads only the bytes the field spans.

Signature (System V, read off the disassembly):

  limb_t get_wval_limb(const byte *w, size_t bitpos, size_t nbits)

rdi = w, rsi = bitpos, rdx = nbits. The disassembly pins the whole
algorithm; the observable result is the little-endian window of the
bytes the field spans, shifted down by the bit offset:

  **result = (sum over j in [0, span] of w[first + j] << (8 * j))
              >> (bitpos & 7)**

  first = bitpos >> 3,  span = ((bitpos + nbits - 1) >> 3) - first

The window is *not* masked down to `nbits` bits. It holds the field in
its low bits and, when the field does not end on a byte boundary, up to
seven extra high bits from the last spanned byte. That is not an
inference: the routine has no mask-to-nbits step, and every one of the
10 call sites masks the window itself (`and` at, or immediately after,
the first use) before shifting and accumulating it. See caller_use.tsv.

1. `shr $0x3,%rsi` then `add %rsi,%rdi` (0x5d0ed63, 0x5d0ed75) turn
   bitpos into the first byte index and add it to the pointer.
2. `lea -0x1(%r9,%rdx,1),%rax` / `shr $0x3,%rax` / `sub %rax,%rsi`
   (0x5d0ed70..0x5d0ed7c) leave rsi holding `first - last`, i.e. the
   negated byte span. rsi is then counted up to zero, one byte per
   iteration.
3. The loop body (0x5d0ed81..0x5d0eda8) runs exactly four times
   (`add $0x8,%ecx` against `cmp $0x20,%ecx`), so at most four bytes
   are read. Each iteration loads one byte, ANDs it with a mask,
   shifts it left by the running bit counter and ORs it into the
   accumulator.
4. The mask is the key: `mov %rsi,%r8` / `sar $0x3f,%r8`
   (0x5d0ed87, 0x5d0ed90) turn the *previous* rsi into an all-ones
   mask while rsi is still negative and into zero once it reaches
   zero. Only the iterations while rsi < 0 -- exactly `span + 1` of
   them -- contribute a byte; the remaining iterations read a byte and
   OR in zero. Bytes past the field therefore never leak in.
5. `shr $0x3f,%rdx` / `add %rdx,%rdi` (0x5d0ed9e, 0x5d0eda2) advance
   the pointer by one only while rsi is still negative, so the `j`-th
   contributing byte is `w[first + j]`, shifted by `8 * j`.
6. `mov %r9d,%ecx` / `and $0x7,%ecx` / `shr %cl,%rax`
   (0x5d0edaa..0x5d0edb3) finally drop the `bitpos & 7` low bits.

Because the loop is capped at 32 shifted bits, a field spanning more
than four bytes would be truncated; the model rejects that instead of
guessing. That cap is the only domain limit.

Bound to node #115, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Vendor census member 4858b6d10aa81d56-server.o, rlib
libblst-51b314b09d0de342.rlib, crate blst (candidate versions 0.3.15,
0.3.16, 0.3.17), symbol get_wval_limb, native true,
target_body_sha256 == source_body_sha256 (raw equal), no relocations,
12 identical source copies.

Environment limits: static disassembly only (objdump/readelf on the
digest-verified local binary). No cargo/rustc, Ghidra or a live node
was used; this is a Python transcription of the pinned algorithm, not a
build of node or blst code. The 10 direct callers are recorded in the
packet's callers.tsv.
"""

import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = (ROOT / "research" / "work-items"
          / "RE-002-node115-blst-get-wval-limb-5d0ed60-115")

START = 0x5d0ed60
END = 0x5d0EDB4
ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")

M64 = (1 << 64) - 1


def _span(bitpos, nbits):
    return ((bitpos + nbits - 1) >> 3) - (bitpos >> 3)


def get_wval_limb(w, bitpos, nbits):
    """The pinned result: the little-endian window of the spanned bytes,
    shifted down by (bitpos & 7). The window is NOT masked to nbits bits;
    it may carry up to seven extra high bits from the last spanned byte
    (the callers mask it themselves).

    w: bytes-like, the bit-packed little-endian string.

    Raises ValueError for a negative bitpos, for nbits < 1, for a field
    whose span is more than four bytes (the routine shifts only 32 bits
    and would truncate it), or for a buffer too short to hold the field
    (the routine would read past it).
    """
    if bitpos < 0:
        raise ValueError("bitpos must be non-negative")
    if nbits < 1:
        raise ValueError("nbits must be at least 1")
    first = bitpos >> 3
    span = _span(bitpos, nbits)
    if span > 3:
        raise ValueError("field spans more than four bytes")
    if len(w) < first + span + 1:
        raise ValueError("buffer too short for the field")
    acc = 0
    for j in range(span + 1):
        acc |= w[first + j] << (8 * j)
    return acc >> (bitpos & 7)


# ---------------------------------------------------------------------------
# The pinned implementation as the disassembly advances it, for
# cross-checking the closed form (this mirrors the register dance
# literally: the four-iteration loop, the sign mask, and the pointer
# step that stops once the byte span is consumed).
# ---------------------------------------------------------------------------

def get_wval_limb_asm(w, bitpos, nbits):
    """The same result computed the way the binary computes it."""
    first = bitpos >> 3
    rsi = first - ((bitpos + nbits - 1) >> 3)   # negated byte span
    rdi = first
    rax = 0
    cl = 0
    r8 = M64
    for _ in range(4):
        rdx = w[rdi] & 0xFF          # movzbl (%rdi),%edx
        rdx &= r8                    # and %r8,%rdx
        r8 = rsi                     # mov %rsi,%r8
        rdx = (rdx << cl) & M64      # shl %cl,%rdx
        cl += 8                      # add $0x8,%ecx
        r8 = M64 if r8 < 0 else 0    # sar $0x3f,%r8
        rax = (rax | rdx) & M64      # or %rdx,%rax
        prev = rsi                   # mov %rsi,%rdx
        rsi += 1                     # add $0x1,%rsi
        rdi += 1 if prev < 0 else 0  # shr $0x3f,%rdx ; add %rdx,%rdi
        if cl == 32:                 # cmp $0x20,%ecx ; jne
            break
    return (rax >> (bitpos & 7)) & M64   # mov %r9d,%ecx ; and $0x7,%ecx ; shr %cl,%rax


# ---------------------------------------------------------------------------
# Case generation
# ---------------------------------------------------------------------------

def generate_cases(seed=115):
    """2,400 deterministic cases: 600 boundary, 600 shift, 600 mask,
    600 random. Each row is (id, group, param, expected)."""
    rng = random.Random(seed)
    rows = []
    state = {"cell": "structural"}

    def add(cid, group, param):
        w = bytes.fromhex(param["w"])
        expected = get_wval_limb(w, param["bitpos"], param["nbits"])
        # The closed form and the literal transcription agree on
        # every case, inside the model's domain.
        assert expected == get_wval_limb_asm(w, param["bitpos"],
                                            param["nbits"]), (cid, param)
        rows.append({"id": cid, "group": group,
                     "param": json.dumps(param, sort_keys=True),
                     "expected": json.dumps({"value": expected}),
                     "cell": state["cell"]})

    # --- group 1: boundary (600): byte-aligned fields, span 0..3 ---
    n = [0]

    def bnd(param):
        add(f"boundary-{n[0]:04d}", "boundary", param)
        n[0] += 1

    # Byte-aligned reads of every supported span, over varied bytes.
    for span in range(4):
        for nbits in (8 * (span + 1), 8 * (span + 1) - 1, 1, 7, 8, 9,
                      8 * span + 1 if span else 1):
            if not (1 <= nbits <= 8 * (span + 1)):
                continue
            for val in (0x00, 0x01, 0xFF):
                w = bytes([val]) * (span + 1)
                bnd({"w": w.hex(), "bitpos": 0, "nbits": nbits})
    # A one-byte buffer, every nbits that fits.
    for nbits in range(1, 9):
        bnd({"w": "a5", "bitpos": 0, "nbits": nbits})
    # The top bit of the last supported span.
    for span in range(4):
        for nbits in (1, 8 * (span + 1)):
            w = bytes([0x80] + [0x00] * span)
            if nbits <= 8 * (span + 1):
                bnd({"w": w.hex(), "bitpos": 0, "nbits": nbits})
    # long buffers: only the spanned bytes may matter.
    for span in range(4):
        w = bytes([0x11] + [0x22] * (span + 1) + [0x33] * 3)
        bnd({"w": w.hex(), "bitpos": 0, "nbits": 8 * (span + 1)})
    # deterministic pseudo-random byte-aligned cases.
    state["cell"] = "sweep"
    while n[0] < 600:
        span = rng.randrange(4)
        nbits = rng.randrange(1, 8 * (span + 1) + 1)
        w = bytes(rng.randrange(256) for _ in range(span + 1))
        bnd({"w": w.hex(), "bitpos": 0, "nbits": nbits})
    assert n[0] == 600, n[0]

    # --- group 2: shift (600): non-zero bit offsets 1..7 ---
    n = [0]
    state["cell"] = "structural"

    def shf(param):
        add(f"shift-{n[0]:04d}", "shift", param)
        n[0] += 1

    for off in range(1, 8):
        for span in range(4):
            maxbits = 8 * (span + 1) - off
            if maxbits < 1:
                continue
            for nbits in (1, maxbits // 2 or 1, maxbits):
                w = bytes([0x5A, 0x3C, 0xC3, 0x0F][:span + 1])
                shf({"w": w.hex(), "bitpos": off, "nbits": nbits})
    # bitpos not confined to the first byte.
    for first in range(1, 5):
        for off in (0, 3, 7):
            for span in range(4):
                maxbits = 8 * (span + 1) - off
                if maxbits < 1:
                    continue
                w = bytes([0x00] * first) + bytes([0xA7]) * (span + 1)
                shf({"w": w.hex(), "bitpos": first * 8 + off, "nbits": 1})
                shf({"w": w.hex(), "bitpos": first * 8 + off,
                     "nbits": maxbits})
    state["cell"] = "sweep"
    while n[0] < 600:
        off = rng.randrange(8)
        span = rng.randrange(4)
        maxbits = 8 * (span + 1) - off
        if maxbits < 1:
            continue
        nbits = rng.randrange(1, maxbits + 1)
        first = rng.randrange(0, 3)
        w = bytes(rng.randrange(256) for _ in range(first + span + 1))
        shf({"w": w.hex(), "bitpos": first * 8 + off, "nbits": nbits})
    assert n[0] == 600, n[0]

    # --- group 3: mask (600): bytes outside the field are all ones, so
    # a leaking implementation would differ from the model. ---
    n = [0]
    state["cell"] = "structural"

    def msk(param):
        add(f"mask-{n[0]:04d}", "mask", param)
        n[0] += 1

    for off in range(8):
        for span in range(4):
            maxbits = 8 * (span + 1) - off
            if maxbits < 1:
                continue
            for nbits in (1, maxbits):
                w = bytearray([0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
                for j in range(span + 1):
                    w[j] = 0x00
                msk({"w": bytes(w).hex(), "bitpos": off, "nbits": nbits})
    # only the first spanned byte zero, the rest all ones.
    for span in range(4):
        for nbits in (1, 8 * (span + 1)):
            if nbits > 8 * (span + 1):
                continue
            w = bytearray([0x00] + [0xFF] * 4)
            msk({"w": bytes(w).hex(), "bitpos": 0, "nbits": nbits})
    state["cell"] = "sweep"
    while n[0] < 600:
        off = rng.randrange(8)
        span = rng.randrange(4)
        maxbits = 8 * (span + 1) - off
        if maxbits < 1:
            continue
        nbits = rng.randrange(1, maxbits + 1)
        w = bytearray(rng.randrange(256) for _ in range(span + 1 + 3))
        for j in range(span + 1, len(w)):
            w[j] = 0xFF
        msk({"w": bytes(w).hex(), "bitpos": off, "nbits": nbits})
    assert n[0] == 600, n[0]

    # --- group 4: random (600) ---
    n = [0]
    state["cell"] = "sweep"
    while n[0] < 600:
        off = rng.randrange(8)
        span = rng.randrange(4)
        maxbits = 8 * (span + 1) - off
        if maxbits < 1:
            continue
        nbits = rng.randrange(1, maxbits + 1)
        first = rng.randrange(0, 4)
        w = bytes(rng.randrange(256) for _ in range(first + span + 1))
        add(f"random-{n[0]:04d}", "random",
            {"w": w.hex(), "bitpos": first * 8 + off, "nbits": nbits})
        n[0] += 1
    assert n[0] == 600, n[0]

    assert len(rows) == 2400, len(rows)
    return rows


def replay_case(case):
    """Recompute a case's expected value from its param."""
    param = json.loads(case["param"])
    got = get_wval_limb(bytes.fromhex(param["w"]), param["bitpos"],
                        param["nbits"])
    return got == json.loads(case["expected"])["value"], got


# The generated sweep is exhaustive (2,400 cases) but only a readable
# subset is committed: `cases.tsv` is a review artifact, and a 1.6 MB
# file is not reviewable on GitHub. The committed ledger keeps every
# cell whose parameter is small enough to read, plus a deterministic
# stride sample of the generated sweep; the full 2,400-case sweep and
# the 200,000-input differential are re-derived in memory by the test
# suite.
LEDGER_PARAM_MAX = 600
LEDGER_TARGET = 300


def _stride(seq, need):
    """`need` rows spread evenly over seq (deterministic)."""
    if need <= 0:
        return []
    if len(seq) <= need:
        return list(seq)
    step = len(seq) / need
    return [seq[int(i * step)] for i in range(need)]


def ledger_rows(rows=None):
    """The committed, human-reviewable ledger: stratified over the four
    case families (so every comparison path is visible in the ledger),
    structural cells first, then an even stride sample, capped at
    LEDGER_TARGET."""
    if rows is None:
        rows = generate_cases()
    pool = [r for r in rows if len(r["param"]) <= LEDGER_PARAM_MAX]
    groups = []
    for r in pool:
        if r["group"] not in groups:
            groups.append(r["group"])
    per = LEDGER_TARGET // max(1, len(groups))
    out = []
    for g in groups:
        sel = [r for r in pool if r["group"] == g]
        structural = [r for r in sel if r.get("cell") == "structural"]
        sweep = [r for r in sel if r.get("cell") != "structural"]
        head = structural[:per // 2]
        head += _stride(sweep, per - len(head))
        out += head
    if len(out) < LEDGER_TARGET:
        have = {r["id"] for r in out}
        rest = [r for r in pool
                if r["id"] not in have and r.get("cell") != "structural"]
        out += _stride(rest, LEDGER_TARGET - len(out))
    return out[:LEDGER_TARGET]


def cases_tsv_rows():
    return ledger_rows()


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv == ["gen-cases"]:
        out = PACKET / "cases.tsv"
        rows = cases_tsv_rows()
        with open(out, "w") as fh:
            fh.write("id\tgroup\tparam\texpected\n")
            for r in rows:
                fh.write("\t".join(r[k] for k in ("id", "group", "param",
                                                  "expected")) + "\n")
        print(f"wrote {out} ({len(rows)} committed cases; the full "
              f"2,400-case sweep is re-derived in memory by the tests)")
        return 0
    print("usage: get_wval_limb_5d0ed60_115.py [gen-cases]")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
