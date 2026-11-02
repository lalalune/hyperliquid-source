"""Deterministic generator for the RE-004 mul256 helper-operand-shapes packet.

Answers the second open question of the #161 packet: can multi-limb helper
inputs actually reach the helper-1 sites? The answer is yes at the sites'
own input-selection layer, and the packet shows exactly how.

The three non-scaling helper-1 sites (caller-A call 1 at 0x279d1fc,
caller-A call 2 at 0x279d2ab, caller-B at 0x279d51a) select their operands
in small prologue/setup regions that the #161 packet did not map (it mapped
flag consumption after the calls, not operand selection before them):

- Sites A1 and B share one prologue idiom: the `a` operand is forced to a
  single limb (V,0,0,0) because the stack slots after the [rsp+0x78] slot
  are zeroed at entry, while the `b` operand is a full 4-limb value:
  R = [ctx+0x240] when the flag at [ctx+0x178] != 1, else
  min(P + Q, R) with P = [ctx+0x180], Q = [ctx+0x90] (4-limb add, mod 2^256).
  The prologue performs no limb-count reduction, so a low-zero multi-limb
  `b` such as (0,7,0,0) passes through unchanged -- exactly the #160
  b_low_zero false-positive shape (a=(5,0,0,0), b=(0,7,0,0), fitting
  product (0,35,0,0), helper-1 flag 1). The #161 collapse is therefore
  live at A1 and B, not merely latent.
- Site A2 is gated on [ctx] bit 0 (panic path otherwise) and builds
  a = (X,Y,0,0) from [ctx+0x10]/[ctx+0x18] and b = (W<<17,0,0,0) from
  [ctx+0x210], with W < 2^47 enforced by a panic guard (shr 0x2f + jne).
  A two-limb `a` is directly reachable, but it does NOT flag: #160's own
  simulation returns flag 0 for every multi-limb-a x single-limb-b shape
  (2/3/4-limb a tested), because the flag follows `b`'s shape, not `a`'s.
  This corrects the mapping of #161's A3 scenario: its two_limb_fit row
  has a two-limb `b`, which call 2's single-limb `b` can never be, so
  A3 does not describe call 2's reachable behavior (the #161 packet
  itself is not modified here). Call 2's only flag path is W = 0 with
  X != 0 (b = 0 short-circuits to flag 1 in #160's simulation, even
  though the product is genuinely 0, so the sentinel still destroys
  the sum); X = Y = 0 gives flag 0, and X = 0, Y != 0 with W = 0 falls
  in #160's out-of-scope region (a_skip + b_skip > 4). Call 2 can
  never truly overflow: a2 < 2^128 and b2 < 2^64, so the product is
  always below 2^192.

The generator verifies the node SHA-256 first, checks unwind FDE starts
and every prologue/setup anchor byte via the repository shared ELF parser,
re-derives the helper-1 census inside the caller-A/B FDEs by E8 scan, and
models the operand selection with independent big-integer arithmetic.
Flag outcomes are taken from the #160 loop_cases.tsv rows or from runs of
#160's own block-level simulation on the exact site shapes (cited as an
oracle, not re-derived here); collapse outcomes follow the #161 proof
(any flag = 1 collapses the caller result to exactly 0). Writes only to
--out. Static analysis only: the node binary is never executed.
"""

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import elf_index  # noqa: E402  (repository shared ELF section parser)

SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
DEFAULT_BINARY = Path("artifacts/node/94/hl-node")
CALLER_A = 0x279D0C0
CALLER_B = 0x279D3E0
HELPER_1 = 0x27A1150
MASK = (1 << 64) - 1
MASK256 = (1 << 256) - 1

# Prologue/setup anchor bytes, keyed by address. All verified against
# objdump -d -M intel output for node #94.
ANCHORS = {
    # Caller-A entry: V load, zeroing, V slot store.
    0x279D0D7: "488b8638020000", 0x279D0DE: "0f57c0",
    0x279D0E1: "0f11842480000000", 0x279D0E9: "48c784249000000000000000",
    0x279D0F5: "4889442478",
    # Caller-A flag test and fast/slow split.
    0x279D0FA: "83be7801000001", 0x279D101: "0f85b6000000",
    # Caller-A P loads, R loads, sum adds.
    0x279D107: "498b8680010000", 0x279D10E: "498b8e88010000",
    0x279D115: "498b9690010000", 0x279D11C: "498bbe98010000",
    0x279D123: "410f108640020000", 0x279D12B: "410f108e50020000",
    0x279D13D: "490396a0000000", 0x279D144: "400f92c6",
    0x279D148: "49038690000000", 0x279D14F: "49138e98000000",
    0x279D156: "4883d200", 0x279D15A: "410f92c0", 0x279D15E: "4108f0",
    0x279D161: "4903bea8000000", 0x279D168: "410fb6f0",
    0x279D16C: "83e601", 0x279D16F: "4801fe",
    # Caller-A top-down compare chain and min select.
    0x279D18A: "4839fe", 0x279D18D: "7540",
    0x279D1CF: "4839fe", 0x279D1D2: "4889e1",
    0x279D1D5: "488d442430", 0x279D1DA: "480f42c1",
    # Caller-A slow path (R directly).
    0x279D1BD: "410f108640020000", 0x279D1C5: "410f108e50020000",
    0x279D1CD: "eb16",
    # Caller-A call 1 setup and call.
    0x279D1EF: "4889e7", 0x279D1F2: "488d742478",
    0x279D1F7: "488d542450", 0x279D1FC: "e84f3f0000",
    # Caller-A call 2 gate, a2 construction, b2 construction, call.
    0x279D237: "41f60601", 0x279D23B: "0f8475010000",
    0x279D241: "498b4610", 0x279D245: "498b4e18", 0x279D24C: "4885c9",
    0x279D25D: "4889442450", 0x279D262: "48894c2458",
    0x279D267: "0f280424", 0x279D26B: "0f11442460",
    0x279D270: "498b8610020000", 0x279D277: "4889c1",
    0x279D27A: "48c1e92f", 0x279D27E: "0f854b010000",
    0x279D284: "48c1e011", 0x279D28B: "0f11442438",
    0x279D290: "48c7442448000000", 0x279D299: "4889442430",
    0x279D29E: "4889e7", 0x279D2A1: "488d742450",
    0x279D2A6: "488d542430", 0x279D2AB: "e8a03e0000",
    # Caller-B entry: V load, zeroing, V slot store.
    0x279D3F0: "488b8638020000", 0x279D3F7: "0f57c0",
    0x279D3FA: "0f11842480000000", 0x279D402: "48c784249000000000000000",
    0x279D40E: "4889442478",
    # Caller-B flag test and fast/slow split.
    0x279D413: "83be7801000001", 0x279D41A: "0f85b7000000",
    # Caller-B P loads, R loads, sum adds (same instruction shapes as A).
    0x279D420: "498b8680010000", 0x279D43C: "410f108640020000",
    0x279D44C: "0f294c2440", 0x279D451: "0f29442430",
    0x279D456: "490396a0000000", 0x279D461: "49038690000000",
    0x279D468: "49138e98000000", 0x279D46F: "4883d200",
    0x279D47A: "4903bea8000000",
    # Caller-B min select and slow path.
    0x279D4E9: "4839fe", 0x279D4EC: "488d4c2408",
    0x279D4F1: "488d442430", 0x279D4F6: "480f42c1",
    0x279D4D7: "410f108640020000", 0x279D4E7: "eb18",
    # Caller-B call setup and call.
    0x279D50B: "488d7c2408", 0x279D510: "488d742478",
    0x279D515: "488d542450", 0x279D51A: "e8313c0000",
}

# Claimed windows: prologue/setup regions only. They sit inside the #161
# FDE windows but are byte-disjoint from #161's anchored regions (flag
# tests at 0x279d201/0x279d2b0/0x279d51f, sentinel presets, add/sub
# chains), which all lie after the call sites or after the call-2 gate.
WINDOWS = [
    ("caller-A-prologue", 0x279D0C0, 0x279D1FC),
    ("caller-A-call2-setup", 0x279D237, 0x279D2AB),
    ("caller-B-prologue", 0x279D3E0, 0x279D51A),
]

# #161 anchored ranges (flag tests, sentinel presets, add/sub chains,
# counter/flag tails) -- the generator asserts no claimed window overlaps
# any of them.
PRIOR_161_RANGES = [
    (0x279D201, 0x279D237), (0x279D2B0, 0x279D3B6),
    (0x279D51F, 0x279D5E0),
]


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


def limbs_to_int(limbs):
    v = 0
    for i, x in enumerate(limbs):
        v |= (x & MASK) << (64 * i)
    return v


def int_to_limbs(v):
    return tuple((v >> (64 * i)) & MASK for i in range(4))


def limbs_str(v):
    return ",".join(str(x) for x in v)


def select_b(flag178, p, q, r):
    """Caller-A/B prologue selection: R when flag != 1, else min(P+Q, R)."""
    if flag178 != 1:
        return r
    s = (limbs_to_int(p) + limbs_to_int(q)) & MASK256
    return int_to_limbs(min(s, limbs_to_int(r)))


def mul4(a, b):
    return int_to_limbs((limbs_to_int(a) * limbs_to_int(b)) & MASK256)


def fits4(a, b):
    return limbs_to_int(a) * limbs_to_int(b) <= MASK256


# (site, case, flag178, gate_bit, V, P, Q, R, X, Y, W)
# V: [ctx+0x238] for A1/B. P/Q/R: context quads for the min path.
# X/Y/W: call-2 context values (X=[ctx+0x10], Y=[ctx+0x18], W=[ctx+0x210]).
CASE_SPECS = [
    ("A1", "C1-slow-b-low-zero", 0, None, 5, None, None, (0, 7, 0, 0), None, None, None),
    ("A1", "C2-fast-min-R-low-zero", 1, None, 5, (0, 8, 0, 0), (0, 0, 0, 0), (0, 7, 0, 0), None, None, None),
    ("A1", "C3-fast-min-S-low-zero", 1, None, 5, (0, 7, 0, 0), (0, 0, 0, 0), (0, 8, 0, 0), None, None, None),
    ("A1", "C4-slow-single-no-flag", 0, None, 5, None, None, (7, 0, 0, 0), None, None, None),
    ("A1", "C5-fast-min-equal", 1, None, 5, (0, 7, 0, 0), (0, 0, 0, 0), (0, 7, 0, 0), None, None, None),
    ("B", "C6-slow-b-low-zero", 0, None, 5, None, None, (0, 7, 0, 0), None, None, None),
    ("B", "C7-fast-min-R-low-zero", 1, None, 5, (0, 8, 0, 0), (0, 0, 0, 0), (0, 7, 0, 0), None, None, None),
    ("A2", "C8-two-limb-a-no-flag", None, 1, None, None, None, None, 1, 2, 3),
    ("A2", "C9-single-a-no-flag", None, 1, None, None, None, None, 3, 0, 1),
    ("A2", "C10-b-zero", None, 1, None, None, None, None, 1, 2, 0),
    ("A2", "C10b-b-zero-X0-out-of-scope", None, 1, None, None, None, None, 0, 2, 0),
    ("A2", "C10c-a-zero-b-zero", None, 1, None, None, None, None, 0, 0, 0),
    ("A2", "C11-gate-clear-panic", None, 0, None, None, None, None, 1, 2, 3),
    ("A2", "C12-W-too-large-panic", None, 1, None, None, None, None, 1, 2, 1 << 47),
    ("A2", "C13-call2-never-overflows", None, 1, None, None, None, None, (1 << 64) - 1, (1 << 64) - 1, (1 << 47) - 1),
]

# (case, helper1_flag, flag_basis, collapse)
# flag_basis: 'row' = exact #160 loop_cases.tsv row; 'rule' = #160 flag rule
# as labeled inference; 'none' = no product computed (panic path).
CASE_OUTCOMES = {
    "C1-slow-b-low-zero": (1, "row:b_low_zero", 1),
    "C2-fast-min-R-low-zero": (1, "row:b_low_zero", 1),
    "C3-fast-min-S-low-zero": (1, "row:b_low_zero", 1),
    "C4-slow-single-no-flag": (0, "row:single_limb", 0),
    "C5-fast-min-equal": (1, "row:b_low_zero", 1),
    "C6-slow-b-low-zero": (1, "row:b_low_zero", 1),
    "C7-fast-min-R-low-zero": (1, "row:b_low_zero", 1),
    "C8-two-limb-a-no-flag": (0, "sim:2x1-no-flag", 0),
    "C9-single-a-no-flag": (0, "row:single_limb", 0),
    "C10-b-zero": (1, "sim:b-zero-X-nonzero", 1),
    "C10b-b-zero-X0-out-of-scope": (None, "none:160-out-of-scope", None),
    "C10c-a-zero-b-zero": (0, "sim:a-zero", 0),
    "C13-call2-never-overflows": (0, "sim:2x1-no-flag", 0),
    "C11-gate-clear-panic": (None, "none:panic-path", None),
    "C12-W-too-large-panic": (None, "none:panic-path", None),
}


def build_cases():
    rows = []
    for site, case, flag178, gate, v, p, q, r, x, y, w in CASE_SPECS:
        flag, basis, collapse = CASE_OUTCOMES[case]
        if site in ("A1", "B"):
            a = (v, 0, 0, 0)
            b = select_b(flag178, p, q, r)
            prod = mul4(a, b)
            assert fits4(a, b), case
            rows.append((site, case, str(flag178), "", limbs_str(a), limbs_str(b),
                         limbs_str(prod), str(flag), basis,
                         str(collapse) if collapse is not None else ""))
        else:
            if gate == 0 or (w is not None and w >= (1 << 47)):
                rows.append((site, case, "", str(gate), "", "", "", "", basis, ""))
            elif case.endswith("out-of-scope"):
                # Shape computed, flag unknown: #160's sim refuses this
                # region (a_skip + b_skip > 4); no flag claim is made.
                a = (x, y, 0, 0)
                b = (0, 0, 0, 0)
                rows.append((site, case, "", str(gate), limbs_str(a), limbs_str(b),
                             limbs_str(mul4(a, b)), "", basis, ""))
            else:
                a = (x, y, 0, 0)
                b = ((w << 17) & MASK, 0, 0, 0)
                prod = mul4(a, b)
                assert fits4(a, b), case
                # Call-2 bound: a2 < 2^128, b2 < 2^64, so the product is
                # always below 2^192 and can never truly overflow.
                assert limbs_to_int(a) < (1 << 128) and limbs_to_int(b) < (1 << 64), case
                rows.append((site, case, "", str(gate), limbs_str(a), limbs_str(b),
                             limbs_str(prod), str(flag), basis,
                             str(collapse) if collapse is not None else ""))
    return rows


def derive_census(data, sections, entries):
    """Exactly the 3 non-scaling helper-1 sites inside caller-A/B FDEs."""
    text = next(s for s in sections if s["name"] == ".text")
    base, off, size = text["address"], text["offset"], text["size"]
    starts = [e["start"] for e in entries]
    import bisect
    found = []
    for i in range(size - 5):
        if data[off + i] == 0xE8:
            rel = struct.unpack_from("<i", data, off + i + 1)[0]
            if base + i + 5 + rel == HELPER_1:
                site = base + i
                j = bisect.bisect_right(starts, site) - 1
                if entries[j]["start"] in (CALLER_A, CALLER_B):
                    found.append(site)
    want = [0x279D1FC, 0x279D2AB, 0x279D51A]
    if sorted(found) != want:
        raise ValueError(f"helper-1 sites in caller-A/B FDEs: {[hex(s) for s in found]}")
    return found


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
    for addr in (CALLER_A, CALLER_B, HELPER_1):
        if addr not in starts:
            raise ValueError(f"{addr:#x} is not an unwind start")
    for va, hx in ANCHORS.items():
        check_anchor(data, sections, va, hx)
    # Claimed windows must not overlap #161's anchored ranges.
    for label, ws, we in WINDOWS:
        for ps, pe in PRIOR_161_RANGES:
            if not (we <= ps or ws >= pe):
                raise ValueError(f"window {label} overlaps #161 range {ps:#x}..{pe:#x}")
    derive_census(data, sections, entries)
    windows = []
    for label, ws, we in WINDOWS:
        w = read_bytes(data, sections, ws, we - ws)
        windows.append((label, ws, we, len(w), hashlib.sha256(w).hexdigest()))
    cases = build_cases()
    out = args.out
    out.mkdir(parents=True, exist_ok=True)
    evidence = {
        "target": "node #94",
        "sha256": SHA256,
        "worktree_baseline": "2993e46",
        "sites": {
            "A1": {"call": "0x279d1fc", "fde": "0x279d0c0..0x279d3e0",
                   "a": "[rsp+0x78] slot (V,0,0,0)", "b": "min(P+Q,R) or R at [rsp+0x50]"},
            "A2": {"call": "0x279d2ab", "fde": "0x279d0c0..0x279d3e0",
                   "a": "(X,Y,0,0) at [rsp+0x50]", "b": "(W<<17,0,0,0) at [rsp+0x30]"},
            "B": {"call": "0x279d51a", "fde": "0x279d3e0..0x279d5e0",
                  "a": "[rsp+0x78] slot (V,0,0,0)", "b": "min(P+Q,R) or R at [rsp+0x50]"},
        },
        "context_fields": {
            "V": "[ctx+0x238]", "flag178": "[ctx+0x178] dword",
            "P": "[ctx+0x180..0x198]", "Q": "[ctx+0x90..0xa8]",
            "R": "[ctx+0x240..0x250]", "X": "[ctx+0x10]", "Y": "[ctx+0x18]",
            "W": "[ctx+0x210]", "gate": "[ctx] bit 0",
        },
        "flag_oracle": "#160 loop_cases.tsv rows b_low_zero/single_limb; "
                        "#160 flag rule for C8/C10 (labeled inference)",
        "collapse_rule": "#161 proof: any helper-1 flag = 1 collapses the "
                         "caller result to exactly 0",
        "cases": len(cases),
        "windows": [{"label": l, "range": f"{s:#x}..{e:#x}", "length": ln, "sha256": sha}
                    for l, s, e, ln, sha in windows],
    }
    (out / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
    (out / "sites.tsv").write_text(
        "site\tcall\tfde\tout\ta_shape\tb_shape\n" +
        "A1\t0x279d1fc\t0x279d0c0..0x279d3e0\t[rsp]\t(V,0,0,0)\tmin(P+Q,R) or R\n" +
        "A2\t0x279d2ab\t0x279d0c0..0x279d3e0\t[rsp]\t(X,Y,0,0)\t(W<<17,0,0,0)\n" +
        "B\t0x279d51a\t0x279d3e0..0x279d5e0\t[rsp+0x8]\t(V,0,0,0)\tmin(P+Q,R) or R\n")
    (out / "cases.tsv").write_text(
        "site\tcase\tflag178\tgate_bit\ta\tb\tproduct\tfits\thelper1_flag\tflag_basis\tcollapse_to_zero\n" +
        "".join("\t".join((site, case, f178, gate, a, b, prod, "1" if prod else "",
                           fl, basis, col)) + "\n"
                for site, case, f178, gate, a, b, prod, fl, basis, col in cases))
    (out / "windows.txt").write_text(
        "".join(f"{label} {s:#x}..{e:#x} length={ln} sha256={sha}\n"
                for label, s, e, ln, sha in windows))
    print(f"{len(cases)} cases; 3 helper-1 sites; node94 SHA-256 {SHA256}")


if __name__ == "__main__":
    main()
