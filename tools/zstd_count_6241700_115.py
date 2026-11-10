"""Model of node #115 zstd-sys ZSTD_count, 0x6241700..0x62417d3 (RE-002).

The routine is the zstd match-length counter. It is a leaf: it
calls nothing, allocates nothing and reads only the two byte
ranges it is given. Signature (System V, from the disassembly):

  size_t ZSTD_count(const BYTE* pIn, const BYTE* pMatch, const BYTE* pInLimit)

rdi = pIn, rsi = pMatch, rdx = pInLimit. It returns the number of
leading bytes that pIn and pMatch share, never exceeding the bytes
available before pInLimit, i.e. min(lcp(pIn, pMatch), pInLimit -
pIn). The disassembly pins the comparison widths and the cap:

1. 8-byte tier: while pIn <= pInLimit - 8, read one qword from
   pIn and one from pMatch and compare them. Equal qwords advance
   both pointers by 8; the first unequal qword returns the count of
   matching low-order bytes inside that qword (xor, tzcnt >> 3).
2. 4-byte tier: while pIn <= pInLimit - 4, compare one dword; a
   match advances by 4, a mismatch falls through to the 2-byte tier.
3. 2-byte tier: while pIn <= pInLimit - 2, compare one word; a
   match advances by 2.
4. 1-byte tier: while pIn < pInLimit, compare one byte; a match
   advances by 1.
5. The result is always (current pIn - pIn_start), so it can never
   exceed pInLimit - pIn_start: the routine stops before the limit.

The mismatch index inside a partially equal qword/dword is computed
with tzcnt on the XOR of the two little-endian words, shifted right
by 3, which is the number of equal low-order bytes; because x86 is
little-endian this is exactly the leading equal-byte count of the
two ranges at that offset.

What is modelled is the routine's observable result on two byte
ranges and a limit: the count of leading equal bytes, capped at the
limit. It is a pure function of (pIn bytes, pMatch bytes, limit);
no state is read or written.

Bound to node #115, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Vendor census member 7c9960efb53c0b35-zstd_lazy.o, rlib
libzstd_sys-c8c5b6f4c7c3aee0.rlib, crate zstd-sys, symbol
ZSTD_count, target_body_sha256 == source_body_sha256 (raw equal),
0 relocations.

Environment limits: static disassembly only (objdump/readelf on the
digest-verified local binary). No cargo/rustc, Ghidra or a live node
was used; this is a Python transcription of the pinned algorithm,
not a build of node or zstd code. The 25 direct callers are recorded
in the packet's callers.tsv.
"""

import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-002-node115-zstd-count-6241700-115"

START = 0x6241700
END = 0x62417D3
ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")


def zstd_count(p_in, p_match, limit):
    """min(lcp(p_in, p_match), limit), the pinned ZSTD_count result.

    p_in, p_match: bytes-like ranges; p_match must supply at least as
    many readable bytes as p_in does up to the limit (the binary reads
    qwords from both, so a shorter p_match is out of the characterized
    domain). limit: int >= 0, the cap pInLimit - pIn.

    Raises ValueError for a negative limit, or for ranges that do not
    supply `limit` readable bytes -- the binary would read past them,
    which this model does not characterize (the routine's own callers
    always pass a limit inside both buffers).
    """
    if limit < 0:
        raise ValueError("limit must be non-negative")
    if len(p_in) < limit or len(p_match) < limit:
        raise ValueError("ranges must supply `limit` readable bytes")
    n = 0
    while n < limit and p_in[n] == p_match[n]:
        n += 1
    return n


# ---------------------------------------------------------------------------
# The pinned implementation in tiers, for cross-checking the closed form
# (mirrors the four comparison widths the disassembly uses).
# ---------------------------------------------------------------------------

def zstd_count_tiers(p_in, p_match, limit):
    """The same result advanced the way the binary does: 8-, then 4-,
    then 2-, then 1-byte comparison widths, capped at `limit`."""
    ip = 0
    while ip <= limit - 8:
        word_in = int.from_bytes(p_in[ip:ip + 8], "little")
        word_match = int.from_bytes(p_match[ip:ip + 8], "little")
        if word_in != word_match:
            x = word_in ^ word_match
            return ip + ((x & -x).bit_length() - 1) // 8
        ip += 8
    if ip <= limit - 4:
        if p_in[ip:ip + 4] == p_match[ip:ip + 4]:
            ip += 4
    if ip <= limit - 2:
        if p_in[ip:ip + 2] == p_match[ip:ip + 2]:
            ip += 2
    if ip < limit:
        if p_in[ip:ip + 1] == p_match[ip:ip + 1]:
            ip += 1
    return ip


# ---------------------------------------------------------------------------
# Case generation
# ---------------------------------------------------------------------------

def _repeat(byte, n):
    return bytes([byte & 0xFF]) * n


def generate_cases(seed=115):
    """2,400 deterministic cases: 600 boundary, 600 tiers, 600 random,
    600 mixed. Each row is (id, group, param, expected)."""
    rng = random.Random(seed)
    rows = []
    state = {"cell": "structural"}

    def add(cid, group, param):
        ip = bytes.fromhex(param["in"])
        match = bytes.fromhex(param["match"])
        limit = param["limit"]
        expected = zstd_count(ip, match, limit)
        # The closed form and the tier walk must agree for every case.
        assert expected == zstd_count_tiers(ip, match, limit), (cid, param)
        rows.append({"id": cid, "group": group,
                     "param": json.dumps(param, sort_keys=True),
                     "expected": json.dumps({"count": expected}),
                     "cell": state["cell"]})

    # --- group 1: boundary (600) ---
    n = [0]

    def bnd(param):
        add(f"boundary-{n[0]:04d}", "boundary", param)
        n[0] += 1

    # limit 0: nothing compared, always 0 (even for equal ranges).
    bnd({"in": "00", "match": "00", "limit": 0})
    bnd({"in": "", "match": "", "limit": 0})
    # mismatch at index 0 .. 8, at each tier edge, with exact-bounded limits.
    for idx in range(0, 9):
        lim = idx + 3
        bnd({"in": _repeat(0x41, lim).hex(),
             "match": (_repeat(0x41, idx) + b"\x42" + _repeat(0x41, lim)).hex()[: (lim) * 2],
             "limit": lim})
    # Equal up to the limit, mismatch just beyond: count == limit.
    for lim in (0, 1, 2, 3, 4, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65):
        long_in = _repeat(0x5A, lim + 4)
        long_match = _repeat(0x5A, lim) + b"\x00" + _repeat(0x5A, 3)
        bnd({"in": long_in.hex(), "match": long_match.hex(), "limit": lim})
    # All-equal ranges of each tier length: count == limit.
    for lim in (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 15, 16, 24, 32):
        bnd({"in": _repeat(0xC3, lim).hex(),
             "match": _repeat(0xC3, lim).hex(), "limit": lim})
    # The 8-byte tier boundary: limit 7 (dword/word/byte tiers only),
    # limit 8 and 9; mismatch located inside the first qword.
    for lim in (7, 8, 9, 16, 17):
        for idx in (0, 1, 2, 3, 4, 5, 6, 7, 8):
            if idx >= lim:
                continue
            bnd({"in": _repeat(0x11, lim).hex(),
                 "match": (_repeat(0x11, idx) + b"\x99" + _repeat(0x11, lim))[:lim].hex(),
                 "limit": lim})
    # Equal through a full qword then mismatch in the next qword: the
    # 8-byte loop's second iteration reports the inner offset.
    for off in range(0, 9):
        lim = 16
        match = _repeat(0x21, 8) + _repeat(0x21, off) + b"\x77" + _repeat(0x21, 7)
        bnd({"in": _repeat(0x21, lim).hex(), "match": match[:lim].hex(),
             "limit": lim})
    # Deterministic pseudo-random boundary rows up to limit 40.
    state["cell"] = "sweep"
    while n[0] < 600:
        lim = rng.randrange(0, 41)
        inb = bytes(rng.randrange(4) for _ in range(lim))
        match = bytearray(inb)
        if lim and rng.random() < 0.7:
            match[rng.randrange(lim)] ^= 0xFF
        bnd({"in": inb.hex(), "match": bytes(match).hex(), "limit": lim})
    assert n[0] == 600, n[0]

    # --- group 2: tiers (600) ---
    n = [0]

    def tier(param):
        add(f"tiers-{n[0]:04d}", "tiers", param)
        n[0] += 1

    # Each width exercised with a mismatch at its last byte.
    for lim, width in ((8, 8), (4, 4), (2, 2), (1, 1)):
        for last in range(width):
            inb = _repeat(0x33, lim)
            m = bytearray(inb)
            m[last] ^= 0x80
            tier({"in": inb.hex(), "match": bytes(m).hex(), "limit": lim})
    # limit 8 with mismatch in bytes 0..7 uses the qword tzcnt path.
    for last in range(8):
        inb = _repeat(0x44, 8)
        m = bytearray(inb)
        m[last] ^= 0x01
        tier({"in": inb.hex(), "match": bytes(m).hex(), "limit": 8})
    # limit 12: qword misses, dword tier decides.
    for last in range(8, 12):
        inb = _repeat(0x55, 12)
        m = bytearray(inb)
        m[last] ^= 0x40
        tier({"in": inb.hex(), "match": bytes(m).hex(), "limit": 12})
    # limit 10: qword misses, dword matches, word tier decides.
    for last in (8, 9):
        inb = _repeat(0x66, 10)
        m = bytearray(inb)
        m[last] ^= 0x02
        tier({"in": inb.hex(), "match": bytes(m).hex(), "limit": 10})
    # limit 9: qword, dword match, byte tier decides.
    inb = _repeat(0x77, 9)
    m = bytearray(inb)
    m[8] ^= 0x08
    tier({"in": inb.hex(), "match": bytes(m).hex(), "limit": 9})
    state["cell"] = "sweep"
    while n[0] < 600:
        lim = rng.choice((1, 2, 3, 4, 5, 8, 9, 10, 12, 16, 17, 24))
        inb = _repeat(rng.randrange(256), lim)
        m = bytearray(inb)
        if rng.random() < 0.8:
            m[rng.randrange(lim)] ^= 1 << rng.randrange(8)
        tier({"in": inb.hex(), "match": bytes(m).hex(), "limit": lim})
    assert n[0] == 600, n[0]

    # --- group 3: random (600) ---
    n = [0]

    def rnd(param):
        add(f"random-{n[0]:04d}", "random", param)
        n[0] += 1

    state["cell"] = "sweep"
    while n[0] < 600:
        lim = rng.choice((0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 16, 20, 32, 33, 40, 64, 128))
        inb = bytes(rng.randrange(256) for _ in range(lim))
        m = bytearray(inb)
        if lim:
            lcp = rng.randrange(lim + 1)
            if lcp < lim:
                m[lcp] = (inb[lcp] + 1 + rng.randrange(255)) & 0xFF
            for i in range(lcp):
                m[i] = inb[i]
            if rng.random() < 0.3:
                for i in range(lcp + 1, lim):
                    m[i] = rng.randrange(256)
        rnd({"in": inb.hex(), "match": bytes(m).hex(), "limit": lim})
    assert n[0] == 600, n[0]

    # --- group 4: mixed (600) ---
    n = [0]

    def mix(param):
        add(f"mixed-{n[0]:04d}", "mixed", param)
        n[0] += 1

    # Large limits comparable to the 8-byte loop's several iterations.
    for lim in (64, 100, 255, 256, 257, 512, 1000, 4096):
        for frac in (0.0, 0.25, 0.5, 0.999, 1.0):
            lcp = int(lim * frac)
            inb = bytes(((i * 31 + 7) & 0xFF) for i in range(lim))
            m = bytearray(inb)
            if lcp < lim:
                m[lcp] = (inb[lcp] ^ 0xFF) & 0xFF
            mix({"in": inb.hex(), "match": bytes(m).hex(), "limit": lim})
    state["cell"] = "sweep"
    while n[0] < 600:
        lim = rng.choice((50, 100, 129, 200, 300, 511, 512, 513, 1000, 2048))
        inb = bytes(rng.randrange(256) for _ in range(lim))
        m = bytearray(inb)
        lcp = rng.choice((0, 1, 7, 8, 15, 16, 31, 63, 64, 127, lim - 1 if lim else 0, lim))
        lcp = max(0, min(lcp, lim))
        if lcp < lim:
            m[lcp] = (inb[lcp] + 1) & 0xFF
        for i in range(lcp):
            m[i] = inb[i]
        mix({"in": inb.hex(), "match": bytes(m).hex(), "limit": lim})
    assert n[0] == 600, n[0]

    assert len(rows) == 2400, len(rows)
    return rows


def replay_case(case):
    """Recompute a case's expected value from its param."""
    param = json.loads(case["param"])
    got = zstd_count(bytes.fromhex(param["in"]),
                     bytes.fromhex(param["match"]), param["limit"])
    return got == json.loads(case["expected"])["count"], got


# The generated sweep is exhaustive (2,400 cases) but only a readable
# subset is committed: `cases.tsv` is a review artifact, and a 1.6 MB file
# is not reviewable on GitHub. The committed ledger keeps every cell whose
# parameter is small enough to read, plus a deterministic stride sample of
# the generated sweep; the full 2,400-case sweep and the 200,000-input
# differential are re-derived in memory by the test suite.
LEDGER_PARAM_MAX = 600
LEDGER_TARGET = 300


def ledger_rows(rows=None):
    """The committed, human-reviewable ledger: structural cases first,
    then an even stride sample of the sweep, capped at LEDGER_TARGET."""
    if rows is None:
        rows = generate_cases()
    structural = [r for r in rows
                  if r.get("cell") == "structural"
                  and len(r["param"]) <= LEDGER_PARAM_MAX]
    sweep = [r for r in rows
             if r.get("cell") != "structural"
             and len(r["param"]) <= LEDGER_PARAM_MAX]
    if len(structural) >= LEDGER_TARGET:
        step = len(structural) // LEDGER_TARGET
        return structural[::step][:LEDGER_TARGET]
    need = LEDGER_TARGET - len(structural)
    step = max(1, len(sweep) // need)
    return structural + sweep[::step][:need]


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
    print("usage: zstd_count_6241700_115.py [gen-cases]")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
