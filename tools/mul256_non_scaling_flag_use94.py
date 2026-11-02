"""Deterministic generator for the RE-004 mul256 non-scaling flag-use packet.

Maps how the five non-scaling callers of the #160 256-bit multiply helpers
consume the helpers' overflow signals, and models the caller outcomes.
Reads the pinned node #94 binary and disassembles nothing: it checks the
node SHA-256 first, verifies unwind FDE starts, anchor bytes, and the full
14-site E8 caller census via the repository shared ELF parser, then emits
evidence.json, sites.tsv, cases.tsv and windows.txt. Writes only to --out.
Static analysis only: the node binary is never executed.
"""

import argparse
import bisect
import hashlib
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import elf_index  # noqa: E402  (repository shared ELF section parser)

SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
DEFAULT_BINARY = Path("artifacts/node/94/hl-node")
H1 = 0x27A1150
H2 = 0x4DE5500
MASK = (1 << 64) - 1
ALL1 = (MASK, MASK, MASK, MASK)
ZERO = (0, 0, 0, 0)

# (va, hex bytes) anchors: calls, flag tests, sentinel stores, branches,
# the helper-2 al test, the helper-2 al-discard point, out zeroing, flag bit.
ANCHORS = [
    (0x279D1FC, "e84f3f0000"),
    (0x279D201, "807c242000"),
    (0x279D206, "49c7c7ffffffff"),
    (0x279D222, "7513"),
    (0x279D2AB, "e8a03e0000"),
    (0x279D2B0, "807c242000"),
    (0x279D2B5, "48c7c7ffffffff"),
    (0x279D2D1, "7513"),
    (0x279D51A, "e8313c0000"),
    (0x279D51F, "807c242800"),
    (0x279D524, "48c7c6ffffffff"),
    (0x279D540, "7514"),
    (0x4C90193, "e868531500"),
    (0x4C90198, "4889e2"),
    (0x4C994FF, "e8fcbf1400"),
    (0x4C99504, "84c0"),
    (0x4C99506, "7526"),
    (0x4C90159, "0f298424b0000000"),
    (0x279D39D, "808bb000000004"),
    (0x279D5BF, "808bb000000004"),
]

# Full 14-site census from the #160 packet, re-derived here by E8 scan.
CENSUS = [
    (0x2715834, 0x2715320, 0x2716BC0, "helper-1", "scaling"),
    (0x271589B, 0x2715320, 0x2716BC0, "helper-1", "scaling"),
    (0x27159E0, 0x2715320, 0x2716BC0, "helper-1", "scaling"),
    (0x279D1FC, 0x279D0C0, 0x279D3E0, "helper-1", "other"),
    (0x279D2AB, 0x279D0C0, 0x279D3E0, "helper-1", "other"),
    (0x279D51A, 0x279D3E0, 0x279D5E0, "helper-1", "other"),
    (0x4C90193, 0x4C900A0, 0x4C901E0, "helper-2", "other"),
    (0x4C994FF, 0x4C99440, 0x4C995C0, "helper-2", "other"),
    (0x4D0ABFB, 0x4D0A6D0, 0x4D0BFA0, "helper-2", "scaling"),
    (0x4D0AC78, 0x4D0A6D0, 0x4D0BFA0, "helper-2", "scaling"),
    (0x4D0ADD6, 0x4D0A6D0, 0x4D0BFA0, "helper-2", "scaling"),
    (0x4D0C4CB, 0x4D0BFA0, 0x4D0D870, "helper-2", "scaling"),
    (0x4D0C548, 0x4D0BFA0, 0x4D0D870, "helper-2", "scaling"),
    (0x4D0C6A6, 0x4D0BFA0, 0x4D0D870, "helper-2", "scaling"),
]

CALLERS = [
    (0x279D0C0, 0x279D3E0, "caller-A"),
    (0x279D3E0, 0x279D5E0, "caller-B"),
    (0x4C900A0, 0x4C901E0, "caller-C"),
    (0x4C99440, 0x4C995C0, "caller-D"),
]

# Helper-behavior rows reused from the #160 packet's loop_cases.tsv:
# (name, helper1_product, helper1_flag, helper1_flag_exact, helper2_al).
# helper1_flag_exact 0 means the flag is a #160 false positive.
HELPER_ROWS = [
    ("single_limb", (35, 0, 0, 0), 0, 1, 0),
    ("b_low_zero", (0, 35, 0, 0), 1, 0, 0),
    ("b_zero", (0, 0, 0, 0), 1, 0, 0),
    ("two_limb_fit", (3, 10, 8, 0), 1, 0, 0),
    ("limb_max_squared", (1, MASK - 1, 0, 0), 0, 1, 0),
    ("max_times_two", (MASK - 1, MASK, MASK, MASK), 1, 1, 1),
    ("four_limb_overflow", (5, 16, 34, 60), 1, 1, 1),
    ("top_limb_product", (0, 0, 0, 0), 1, 1, 1),
]
HELPER = {r[0]: r for r in HELPER_ROWS}


def va_to_offset(sections, va):
    for s in sections:
        if s["type"] == 8:
            continue
        if s["address"] <= va < s["address"] + s["size"]:
            return s["offset"] + (va - s["address"])
    raise ValueError(f"VA {va:#x} has no file mapping")


def read_bytes(data, sections, va, length):
    off = va_to_offset(sections, va)
    return data[off:off + length]


def check_anchor(data, sections, va, hex_bytes):
    want = bytes.fromhex(hex_bytes)
    got = read_bytes(data, sections, va, len(want))
    if got != want:
        raise ValueError(f"anchor mismatch at {va:#x}: got {got.hex()}, want {hex_bytes}")


def derive_census(data, sections, entries):
    text = next(s for s in sections if s["name"] == ".text")
    base, off, size = text["address"], text["offset"], text["size"]
    starts = [e["start"] for e in entries]
    found = {}
    for target in (H1, H2):
        sites = []
        for i in range(size - 5):
            if data[off + i] == 0xE8:
                rel = struct.unpack_from("<i", data, off + i + 1)[0]
                if base + i + 5 + rel == target:
                    sites.append(base + i)
        found[target] = sites
    for site, fde_start, fde_end, helper, _role in CENSUS:
        target = H1 if helper == "helper-1" else H2
        if site not in found[target]:
            raise ValueError(f"census site {site:#x} not found by E8 scan")
        j = bisect.bisect_right(starts, site) - 1
        e = entries[j]
        if e["start"] != fde_start or e["next_index_upper_bound"] != fde_end:
            raise ValueError(f"enclosing FDE mismatch for {site:#x}")
    for target in (H1, H2):
        want = sorted(s for s, _, _, h, _ in CENSUS if (H1 if h == "helper-1" else H2) == target)
        if sorted(found[target]) != want:
            raise ValueError(f"E8 scan found extra/missing sites for {target:#x}")
    return found


def add4(a, b):
    out = []
    carry = 0
    for x, y in zip(a, b):
        s = x + y + carry
        out.append(s & MASK)
        carry = s >> 64
    return tuple(out), carry


def sub4(a, b):
    out = []
    borrow = 0
    for x, y in zip(a, b):
        d = x - y - borrow
        out.append(d & MASK)
        borrow = 1 if d < 0 else 0
    return tuple(out), borrow


def limbs_str(v):
    return ",".join(str(x) for x in v)


def caller_a(p1, flag1, p2, flag2, stored):
    """FDE 0x279d0c0: D = stored - (P1' + P2'), sentinel rules applied."""
    p1p = ALL1 if flag1 else p1
    p2p = ALL1 if flag2 else p2
    s, carry = add4(p1p, p2p)
    if carry:
        s = ALL1
    d, borrow = sub4(stored, s)
    if stored[3] < s[3] or borrow:
        d = ZERO
    return {"p1_effective": p1p, "p2_effective": p2p, "sum": s, "result": d}


def caller_b(p, flag, stored):
    """FDE 0x279d3e0: D = stored - P', sentinel rules applied."""
    pp = ALL1 if flag else p
    d, borrow = sub4(stored, pp)
    if stored[3] < pp[3] or borrow:
        d = ZERO
    return {"p_effective": pp, "result": d}


def caller_d(p, al):
    """FDE 0x4c99440: al=1 -> return 0; else T = P + 10, carry -> return 0."""
    if al:
        return {"outcome": "return-0", "sum": None}
    t, carry = add4(p, (10, 0, 0, 0))
    if carry:
        return {"outcome": "return-0", "sum": t}
    return {"outcome": "continue", "sum": t}


S_NORMAL = (1000, 100, 100, 0)
S_TOPMAX = (0, 0, 0, MASK)
S_MAX = (MASK, MASK, MASK, MASK)


def build_cases():
    rows = []
    # Caller A rows: (case, p1 scenario, p2 scenario, stored).
    for case, s1, s2, stored in [
        ("A1-normal", "single_limb", "single_limb", S_NORMAL),
        ("A2-falsepos-call1", "b_low_zero", "single_limb", S_NORMAL),
        ("A3-falsepos-call2", "single_limb", "two_limb_fit", S_NORMAL),
        ("A4-falsepos-top-corner", "b_low_zero", "single_limb", S_TOPMAX),
        ("A5-falsepos-stored-max", "b_low_zero", "single_limb", S_MAX),
        ("A6-true-overflow", "max_times_two", "single_limb", S_NORMAL),
    ]:
        h1 = HELPER[s1]
        h2 = HELPER[s2]
        r = caller_a(h1[1], h1[2], h2[1], h2[2], stored)
        # True (flag-free) result for contrast.
        true_sum, true_carry = add4(h1[1], h2[1])
        true_sum = ALL1 if true_carry else true_sum
        true_d, true_b = sub4(stored, true_sum)
        if stored[3] < true_sum[3] or true_b:
            true_d = ZERO
        false_pos = 1 if (h1[3] == 0 or h2[3] == 0) else 0
        rows.append(("caller-A", case, s1, s2, limbs_str(stored),
                     limbs_str(r["sum"]), limbs_str(r["result"]), limbs_str(true_d),
                     str(false_pos)))
    # Caller B rows: (case, p scenario, stored).
    for case, s1, stored in [
        ("B1-normal", "single_limb", S_NORMAL),
        ("B2-falsepos", "b_low_zero", S_NORMAL),
        ("B3-falsepos-top-corner", "b_low_zero", S_TOPMAX),
        ("B4-falsepos-stored-max", "b_low_zero", S_MAX),
        ("B5-true-overflow", "top_limb_product", S_NORMAL),
    ]:
        h1 = HELPER[s1]
        r = caller_b(h1[1], h1[2], stored)
        true_d, true_b = sub4(stored, h1[1])
        if stored[3] < h1[1][3] or true_b:
            true_d = ZERO
        rows.append(("caller-B", case, s1, "", limbs_str(stored),
                     limbs_str(r["p_effective"]), limbs_str(r["result"]), limbs_str(true_d),
                     str(1 - h1[3])))
    # Caller D rows: (case, helper scenario or raw product, al override).
    d_cases = [
        ("D1-fit", "single_limb", None),
        ("D2-exact-overflow", "top_limb_product", None),
        ("D3-plus10-carry", None, (MASK, MASK, MASK, MASK)),
        ("D4-plus10-boundary", None, (MASK - 10, 0, 0, 0)),
        ("D5-plus10-wrap-low", None, (MASK - 9, 0, 0, 0)),
    ]
    for case, s1, raw in d_cases:
        if s1 is not None:
            h = HELPER[s1]
            p, al = h[1], h[4]
        else:
            p, al = raw, 0
        r = caller_d(p, al)
        rows.append(("caller-D", case, s1 or "raw", "", limbs_str(p),
                     limbs_str(r["sum"]) if r["sum"] is not None else "",
                     r["outcome"], "", ""))
    # Caller C rows: al is never consumed.
    for case, al in [("C1-al-0", 0), ("C2-al-1", 1)]:
        rows.append(("caller-C", case, "", "", "", "", "al-not-consumed", "", ""))
    return rows


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    p.add_argument("--allow-digest-mismatch", action="store_true")
    args = p.parse_args()
    data = args.binary.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != SHA256 and not args.allow_digest_mismatch:
        raise ValueError(f"node digest mismatch: {digest}")
    sections, entries = elf_index.unwind_index(data)
    starts = {e["start"]: e for e in entries}
    for addr, label in ((H1, "helper-1"), (H2, "helper-2")):
        if addr not in starts:
            raise ValueError(f"{label} {addr:#x} is not an unwind start")
    for start, _end, _label in CALLERS:
        if start not in starts:
            raise ValueError(f"caller FDE {start:#x} is not an unwind start")
    for va, hex_bytes in ANCHORS:
        check_anchor(data, sections, va, hex_bytes)
    # E8 targets of the five non-scaling call sites.
    for site, helper in ((0x279D1FC, H1), (0x279D2AB, H1), (0x279D51A, H1),
                         (0x4C90193, H2), (0x4C994FF, H2)):
        raw = read_bytes(data, sections, site, 5)
        if raw[0] != 0xE8:
            raise ValueError(f"not an E8 call at {site:#x}")
        rel = struct.unpack_from("<i", raw, 1)[0]
        if site + 5 + rel != helper:
            raise ValueError(f"call at {site:#x} targets {site + 5 + rel:#x}, want {helper:#x}")
    derive_census(data, sections, entries)
    windows = []
    for start, end, label in CALLERS:
        w = read_bytes(data, sections, start, end - start)
        windows.append((label, start, end, len(w), hashlib.sha256(w).hexdigest()))
    cases = build_cases()
    sites = [(f"{s:#x}", f"{fs:#x}", f"{fe:#x}", h, r)
             for s, fs, fe, h, r in CENSUS if r == "other"]
    out = args.out
    out.mkdir(parents=True, exist_ok=True)
    evidence = {
        "target": "node #94",
        "sha256": SHA256,
        "worktree_baseline": "2993e46",
        "helpers": {
            "helper-1": {"address": "0x27a1150", "overflow_signal": "byte at out+0x20, conservative"},
            "helper-2": {"address": "0x4de5500", "overflow_signal": "al return, exact"},
        },
        "callers": [{"label": label, "fde": f"{s:#x}..{e:#x}", "length": ln, "sha256": sha}
                    for label, s, e, ln, sha in windows],
        "sites": len(sites),
        "census_total": len(CENSUS),
        "anchors": len(ANCHORS),
        "cases": len(cases),
    }
    (out / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
    (out / "sites.tsv").write_text(
        "call_site\tenclosing_fde_start\tenclosing_fde_end\thelper\trole\n" +
        "".join("\t".join(r) + "\n" for r in sites))
    (out / "cases.tsv").write_text(
        "caller\tcase\tp1_scenario\tp2_scenario\tstored\tsum_or_effective\tresult\ttrue_result\tfalse_positive\n" +
        "".join("\t".join(r) + "\n" for r in cases))
    (out / "windows.txt").write_text(
        "".join(f"{label} {s:#x}..{e:#x} length={ln} sha256={sha}\n"
                for label, s, e, ln, sha in windows))
    print(f"{len(cases)} cases; {len(sites)} non-scaling sites; "
          f"{len(CENSUS)} census sites; {len(ANCHORS)} anchors; node94 SHA-256 {SHA256}")


if __name__ == "__main__":
    main()
