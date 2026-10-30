#!/usr/bin/env python3
"""RE-007: static margin-tier, requirement, and liquidation-admission evidence.

The tool authenticates node #94, checks selected instructions and relocation-backed
edges, and writes a deterministic evidence packet.  It never maps or executes the
captured program.  The arithmetic models are deliberately small: their constants,
branch order, integer widths, and saturation points are admitted only after the
corresponding instruction controls have matched.
"""

import argparse
import csv
import hashlib
import json
import struct
import sys
from pathlib import Path

TOOL_DIR = Path(__file__).resolve().parent
if str(TOOL_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_DIR))
from elf_index import sections
from fde_extents import fde_extents

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "artifacts/node/94/hl-node"
SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
U64_MAX = (1 << 64) - 1
I64_MIN = -(1 << 63)
I64_MAX = (1 << 63) - 1
WIRE_NTL_LIMIT = 0x0CCCCCCCCCCCCCCC
TIER_LOWER_LIMIT = 1_000_000_000_000_000
MAX_LEVERAGE = 50

# FDE extents are unwind-described ranges, not a complete function census.
FUNCTIONS = {
    "tier_lookup": (0x33331A0, 0x3333276),
    "maintenance_requirement": (0x3333670, 0x33337F9),
    "initial_requirement": (0x3333800, 0x3333915),
    "tier_admission": (0x3335590, 0x3335C40),
    "position_margin_by_mode": (0x3717480, 0x37179C5),
    "liquidation_candidate_collection": (0x37D7360, 0x37D77D8),
    "single_or_cross_surplus": (0x37D77E0, 0x37D79E0),
    "aggregate_margin": (0x37D79E0, 0x37D7F0C),
}

# name: (VA, exact bytes). These controls cover every semantic claim emitted below.
CONTROLS = {
    "description_len_lt_251": (0x33355B7, "4881fdfb0000007251"),
    "tier_count_lt_4": (0x333561A, "4983fd047234"),
    "tier_count_nonzero": (0x3335654, "4d85ed7435"),
    "wire_limit": (0x3335659, "48b9cccccccccccccc0c"),
    "first_lower_is_zero": (0x333566B, "4885c0744b"),
    "first_leverage_at_most_50": (0x33356BB, "410fb6470848894424084883f8320f87ac000000"),
    "later_lower_limit": (0x3335806, "48b80080c6a47e8d0300"),
    "later_leverage_decreases": (0x333591A, "3a4c24080f83ff010000"),
    "later_lower_increases": (0x33359E2, "483b5424180f8345010000"),
    "prior_current_divisor_2l": (0x3335933, "8d3400488b4424184889c148c1e920"),
    "prior_previous_divisor_2l": (0x3335954, "0fb674240801f64885c9740c"),
    "prior_saturating_add_sub": (0x333597A, "488b74242848037424200f8254010000482b7424307311"),
    "maintenance_double_sat": (0x3333733, "4885db787e4801db"),
    "maintenance_prior_mul_4l": (0x333373B, "410fb64ef88d048d0000000049f766f00f8091000000"),
    "maintenance_sub_sat": (0x3333751, "4829c37316"),
    "maintenance_divisor_6l": (0x333376C, "01c9488d0c49"),
    "initial_divisor_2l": (0x33338B3, "0fb67410f801f6"),
    "initial_sub_sat": (0x33338CB, "482b41f07311"),
    "price_nonnegative": (0x3717491, "4885d20f888b040000"),
    "signed_notional_checked_mul": (0x371749A, "4989d64989f44c0faf76100f807a040000"),
    "notional_unsigned_abs": (0x37174AE, "4d89f749f7df4d0f48fe"),
    "mode_jump": (0x37174B8, "0fb6c1488d0d6affe7fc486314814801caff e2".replace(" ", "")),
    "cross_isolated_test": (0x37174E0, "41803c24000f85a4030000"),
    "initial_got_call": (0x3717755, "4c89ef4c89feff1587cf0502"),
    "maintenance_got_call": (0x37177DB, "4c89ef4c89feff15b9e10502"),
    "isolated_margin_add_checked": (0x371788F, "4d8b6424084c89f14c01e10f8092000000"),
    "mode_three_concrete_caller": (0x36FFF7E, "b9030000004c898c24c0010000e8d0730d00"),
    "cross_surplus_negative_only": (0x37D73BD, "4c8b7424504d85f60f88b60300004c8b7c24484c89fb4c29f30f804b0300004885db794d"),
    "isolated_surplus_negative_only": (0x37D76B9, "ff1531d0f9014989c44885c00f89e7fdffff"),
    "aggregate_call_mode_forward": (0x37D7CAC, "0fb64c2430440fb6442434488d7c2450488db424800000004c8b8c2400010000ff1506caf901"),
}

GOT_EDGES = (
    (0x57759A0, 0x3333670, 0x37177E1, "maintenance requirement"),
    (0x57746E8, 0x3333800, 0x371775B, "initial requirement"),
    (0x57746D8, 0x3717480, 0x37D7CCC, "aggregate to position margin"),
    (0x57746D8, 0x3717480, 0x37D793A, "single position to position margin"),
    (0x5773178, 0x37D79E0, 0x37D73B7, "candidate collector cross aggregate"),
    (0x57746F0, 0x37D77E0, 0x37D76B9, "candidate collector isolated surplus"),
    (0x5773190, 0x358DCD0, 0x3333761, "maintenance unsigned-underflow recorder"),
    (0x5773190, 0x358DCD0, 0x33338DA, "initial unsigned-underflow recorder"),
    (0x5773190, 0x358DCD0, 0x3717956, "isolated signed-overflow recorder"),
    (0x5773190, 0x358DCD0, 0x37D7730, "candidate signed-overflow recorder"),
    (0x57757B8, 0x32D5860, 0x37D73F2, "cross candidate vector growth"),
    (0x57757B8, 0x32D5860, 0x37D76E0, "isolated candidate vector growth"),
)

DIRECT_EDGES = (
    (0x33336AC, 0x2FE1670, "maintenance tier-tree range lookup"),
    (0x3333838, 0x2FE1670, "initial tier-tree range lookup"),
    (0x3335735, 0x3398F50, "single-tier tree construction"),
    (0x3335A45, 0x3398F50, "admitted-tier tree construction"),
    (0x3717573, 0x3398F50, "mode-2 built-in table construction"),
    (0x371760A, 0x3398F50, "mode-3 built-in table construction"),
    (0x36FFF8B, 0x37D7360, "concrete mode 3 to candidate collector"),
)

LOCATIONS = {
    0x56E9B40: ("l1/src/clearinghouse/margin_table.rs", 107, 105),
    0x56E9B70: ("l1/src/qtys/impl_ntl.rs", 26, 1),
    0x56F1FA8: ("l1/src/clearinghouse/position.rs", 204, 57),
    0x56F3A48: ("l1/src/clearinghouse/user_state.rs", 87, 60),
    0x56F3A78: ("l1/src/qtys/impl_ntl.rs", 62, 1),
    0x56F3A90: ("l1/src/qtys/mod.rs", 830, 1),
    0x56F3AA8: ("l1/src/qtys/mod.rs", 829, 1),
}

LITERALS = {
    0x58B826: b"lower bound should increase for each tier",
    0x58B84F: b"lower bound should start at 0",
    0x58B86C: b"empty tiers",
    0x58B892: b"ntl bound too large",
    0x5B66D3: b"max leverage should decrease for each tier",
}


class EvidenceError(ValueError):
    pass


class Image:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)

    def off(self, va, size=1):
        hits = [s for s in self.sections if s["type"] != 8 and
                s["address"] <= va and va + size <= s["address"] + s["size"]]
        if len(hits) != 1:
            raise EvidenceError("VA %s has %d file mappings" % (hex(va), len(hits)))
        return hits[0]["offset"] + va - hits[0]["address"]

    def read(self, va, size):
        off = self.off(va, size)
        return self.data[off:off + size]

    def relative_relocs(self):
        out = {}
        for sec in self.sections:
            if sec["type"] != 4:
                continue
            if sec["size"] % 24:
                raise EvidenceError("truncated RELA section")
            raw = self.data[sec["offset"]:sec["offset"] + sec["size"]]
            for where, info, addend in struct.iter_unpack("<QQq", raw):
                if info & 0xFFFFFFFF == 8:
                    if where in out:
                        raise EvidenceError("duplicate relative relocation")
                    out[where] = addend
        return out


def authenticate(data):
    digest = hashlib.sha256(data).hexdigest()
    if digest != SHA256:
        raise EvidenceError("target SHA-256 mismatch: %s" % digest)
    return digest


def sat_add_u64(a, b):
    return min(U64_MAX, a + b)


def sat_sub_u64(a, b):
    return max(0, a - b)


def sat_mul_u64(a, b):
    return min(U64_MAX, a * b)


def sat_add_i64(a, b):
    return min(I64_MAX, max(I64_MIN, a + b))


def sat_sub_i64(a, b):
    return min(I64_MAX, max(I64_MIN, a - b))


def checked_signed_notional(size, price):
    if price < 0:
        raise ArithmeticError("negative raw price")
    value = size * price
    if value < I64_MIN or value > I64_MAX:
        raise OverflowError("signed i64 notional overflow")
    return value


def uabs_i64(value):
    return -value if value < 0 else value


def admit_tiers(description_bytes, raw_tiers):
    """Model only the ordered checks and record arithmetic visible at 0x3335590."""
    if description_bytes > 250:
        return "description-too-long", None
    if len(raw_tiers) > 3:
        return "too-many-tiers", None
    if not raw_tiers:
        return "empty-tiers", None
    lower, leverage = raw_tiers[0]
    if lower >= WIRE_NTL_LIMIT:
        return "wire-ntl-too-large", None
    if lower != 0:
        return "first-lower-not-zero", None
    if leverage > MAX_LEVERAGE:
        return "leverage-too-large", None
    built = [(lower, 0, leverage)]
    previous_lower, previous_leverage, prior = lower, leverage, 0
    if len(raw_tiers) > 1:
        lower = raw_tiers[1][0]
        if lower >= WIRE_NTL_LIMIT:
            return "wire-ntl-too-large", None
        if lower > TIER_LOWER_LIMIT:
            return "tier-lower-too-large", None
    for index, (lower, leverage) in enumerate(raw_tiers[1:], 1):
        if leverage > MAX_LEVERAGE:
            return "leverage-too-large", None
        if leverage >= previous_leverage:
            return "leverage-not-decreasing", None
        if leverage == 0 or previous_leverage == 0:
            return "zero-divisor-before-result", None
        current = lower // (2 * leverage)
        previous = lower // (2 * previous_leverage)
        prior = sat_sub_u64(sat_add_u64(prior, current), previous)
        # The binary validates the next lower bound before comparing the current
        # lower bound with its predecessor.
        if index + 1 < len(raw_tiers):
            next_lower = raw_tiers[index + 1][0]
            if next_lower >= WIRE_NTL_LIMIT:
                return "wire-ntl-too-large", None
            if next_lower > TIER_LOWER_LIMIT:
                return "tier-lower-too-large", None
        if previous_lower >= lower:
            return "lower-not-increasing", None
        built.append((lower, prior, leverage))
        previous_lower, previous_leverage = lower, leverage
    return "ok", built


def tier_for(tiers, notional):
    selected = tiers[0]
    for tier in tiers[1:]:
        if tier[0] > notional:
            break
        selected = tier
    return selected


def initial_requirement(tiers, notional):
    _lower, prior, leverage = tier_for(tiers, notional)
    if leverage == 0:
        raise ZeroDivisionError("zero tier leverage")
    return sat_sub_u64(notional // (2 * leverage), prior)


def maintenance_requirement(tiers, notional):
    _lower, prior, leverage = tier_for(tiers, notional)
    if leverage == 0:
        raise ZeroDivisionError("zero tier leverage")
    numerator = sat_sub_u64(sat_mul_u64(notional, 2),
                            sat_mul_u64(prior, 4 * leverage))
    return numerator // (6 * leverage)


def position_summary(position, price, mode, cap, tiers):
    """Model the proved fields read/written by 0x3717480, not the full Rust type."""
    signed = checked_signed_notional(position["size"], price)
    notional = uabs_i64(signed)
    if mode == 0:
        required = 0
    elif mode == 1:
        leverage = position["leverage"]
        if leverage == 0:
            raise ZeroDivisionError("zero position leverage")
        required = notional // leverage
    elif mode == 2:
        required = initial_requirement(tiers, notional)
    elif mode == 3:
        required = maintenance_requirement(tiers, notional)
    elif mode == 4:
        leverage = min(position["leverage"], cap)
        if leverage == 0:
            raise ZeroDivisionError("zero capped leverage")
        required = notional // leverage
    else:
        raise IndexError("mode jump-table index is outside the five proved entries")
    if not position["isolated"]:
        return {"isolated": False, "signed": signed, "effective": required,
                "notional": notional, "previous_margin": 0, "computed": 0}
    after = sat_add_i64(position["margin"], signed)
    return {"isolated": True, "signed": after, "effective": max(after, 0),
            "notional": notional, "previous_margin": position["margin"],
            "computed": required}


def liquidation_surplus(summary):
    requirement = summary["computed"] if summary["isolated"] else summary["effective"]
    if requirement > I64_MAX:
        raise OverflowError("requirement does not fit signed i64 comparison path")
    return sat_sub_i64(summary["signed"], requirement)


def direct_target(img, site):
    raw = img.read(site, 5)
    if raw[0] != 0xE8:
        raise EvidenceError("expected direct call at %s" % hex(site))
    return site + 5 + struct.unpack_from("<i", raw, 1)[0]


def got_slot(img, site):
    raw = img.read(site, 6)
    if raw[:2] != b"\xff\x15":
        raise EvidenceError("expected RIP-relative indirect call at %s" % hex(site))
    return site + 6 + struct.unpack_from("<i", raw, 2)[0]


def location(img, relocs, va):
    pointer = relocs.get(va)
    if pointer is None:
        raise EvidenceError("Location lacks path relocation at %s" % hex(va))
    length, line, column = struct.unpack("<QII", img.read(va + 8, 16))
    raw = img.read(pointer, length)
    prefix = b"/home/ubuntu/hl/code_Mainnet/"
    if not raw.startswith(prefix):
        raise EvidenceError("unexpected source prefix")
    return raw[len(prefix):].decode("utf-8"), line, column


def instruction_rows(img):
    rows = []
    for name, (va, expected) in CONTROLS.items():
        want = bytes.fromhex(expected)
        got = img.read(va, len(want))
        if got != want:
            raise EvidenceError("instruction control changed: %s at %s" % (name, hex(va)))
        rows.append((name, va, got.hex()))
    return rows


def boundary_rows():
    status, tiers = admit_tiers(250, [(0, 50), (1_000, 20), (1_000_000, 10)])
    if status != "ok":
        raise EvidenceError("internal boundary fixture rejected")
    rows = []
    for n in [0, 1, 999, 1_000, 999_999, 1_000_000, I64_MAX, 1 << 63, U64_MAX]:
        rows.append({"kind": "requirement", "input": str(n),
                     "initial": str(initial_requirement(tiers, n)),
                     "maintenance": str(maintenance_requirement(tiers, n)),
                     "result": "ok"})
    admission = [
        ("empty", 0, []),
        ("first-nonzero", 0, [(1, 50)]),
        ("wire-limit", 0, [(WIRE_NTL_LIMIT, 50)]),
        ("too-many", 0, [(0, 50), (1, 40), (2, 30), (3, 20)]),
        ("description-251-precedes-too-many", 251, [(0, 50)] * 4),
        ("leverage-51", 0, [(0, 51)]),
        ("equal-leverage", 0, [(0, 50), (1, 50)]),
        ("decreasing-lower", 0, [(0, 50), (2, 40), (1, 30)]),
        ("single-zero-leverage", 0, [(0, 0)]),
        ("multi-zero-leverage", 0, [(0, 1), (1, 0)]),
    ]
    for name, desc, raw in admission:
        result, _ = admit_tiers(desc, raw)
        rows.append({"kind": "admission:" + name, "input": repr(raw),
                     "initial": "", "maintenance": "", "result": result})
    for surplus in [I64_MIN, -1, 0, 1, I64_MAX]:
        rows.append({"kind": "eligibility", "input": str(surplus), "initial": "",
                     "maintenance": "", "result": "eligible" if surplus < 0 else "ineligible"})
    return tiers, rows


def analyse(data, verify_digest=True):
    if verify_digest:
        authenticate(data)
    img = Image(data)
    relocs = img.relative_relocs()
    controls = instruction_rows(img)
    fdes = {row["start"]: row for row in fde_extents(data)[1]}
    function_rows = []
    for name, (start, end) in FUNCTIONS.items():
        row = fdes.get(start)
        if row is None or row["end"] != end:
            raise EvidenceError("FDE extent changed for %s" % name)
        function_rows.append((name, start, end, end - start, row["fde"]))

    edge_rows = []
    for slot, target, site, meaning in GOT_EDGES:
        if relocs.get(slot) != target:
            raise EvidenceError("GOT relocation changed at %s" % hex(slot))
        if got_slot(img, site) != slot:
            raise EvidenceError("indirect call changed at %s" % hex(site))
        edge_rows.append((site, "got-call", slot, target, meaning))
    for site, target, meaning in DIRECT_EDGES:
        if direct_target(img, site) != target:
            raise EvidenceError("direct call changed at %s" % hex(site))
        edge_rows.append((site, "direct-call", 0, target, meaning))

    location_rows = []
    for va, expected in LOCATIONS.items():
        got = location(img, relocs, va)
        if got != expected:
            raise EvidenceError("source Location changed at %s" % hex(va))
        location_rows.append((va,) + got)
    for va, text in LITERALS.items():
        if img.read(va, len(text)) != text:
            raise EvidenceError("literal changed at %s" % hex(va))

    table = 0x59742C
    mode_destinations = [table + struct.unpack("<i", img.read(table + i * 4, 4))[0]
                         for i in range(5)]
    expected_modes = [0x3717888, 0x37174CB, 0x371751F, 0x37175B6, 0x37174F0]
    if mode_destinations != expected_modes:
        raise EvidenceError("five-entry mode jump table changed")

    tiers, boundaries = boundary_rows()
    result = {
        "target": {"path": "artifacts/node/94/hl-node", "sha256": SHA256,
                   "bytes": len(data), "captured_binary_executed": False},
        "scope": {
            "proved_transition": "admitted tier records -> mode-3 maintenance requirement -> cross/isolated surplus < 0 candidate admission",
            "mode_jump_destinations": [hex(x) for x in mode_destinations],
            "tier_record_fixture": [{"lower": x[0], "prior": x[1], "leverage": x[2]} for x in tiers],
            "state_mutation": "candidate-vector append only; the bounded path does not write position records",
        },
        "formulas": {
            "initial_u64": "sat_sub(floor(notional / (2 * leverage)), prior_contribution)",
            "maintenance_u64": "floor(sat_sub(sat_mul(notional, 2), sat_mul(prior_contribution, 4 * leverage)) / (6 * leverage))",
            "signed_notional_i64": "checked(position_size_i64 * nonnegative_price_i64)",
            "eligibility": "signed surplus < 0; zero is ineligible",
        },
        "counts": {"functions": len(function_rows), "instruction_controls": len(controls),
                   "dependency_edges": len(edge_rows), "locations": len(location_rows),
                   "boundary_rows": len(boundaries)},
        "limits": [
            "Raw price, size and notional widths and operations are proved; decimal scaling is not.",
            "FDE ranges are unwind extents, not a complete function census.",
            "The tier tree implementation, recorder body, all callers, and complete liquidation execution are not closed.",
            "A zero leverage is not rejected by the shown single-tier admission branch, but requirement division would have a zero divisor.",
            "No independently authored Rust component is claimed because surrounding layouts and unit scales remain incomplete.",
        ],
    }
    return result, function_rows, edge_rows, location_rows, controls, boundaries


def write_packet(out, analysed):
    result, functions, edges, locations, controls, boundaries = analysed
    out.mkdir(parents=True, exist_ok=True)
    (out / "evidence.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    with (out / "functions.tsv").open("w", newline="") as handle:
        w = csv.writer(handle, delimiter="\t", lineterminator="\n")
        w.writerow(["name", "start", "end", "bytes", "fde"])
        for name, start, end, size, fde in functions:
            w.writerow([name, hex(start), hex(end), size, hex(fde)])
    with (out / "dependencies.tsv").open("w", newline="") as handle:
        w = csv.writer(handle, delimiter="\t", lineterminator="\n")
        w.writerow(["site", "kind", "slot", "target", "meaning"])
        for site, kind, slot, target, meaning in edges:
            w.writerow([hex(site), kind, hex(slot) if slot else "", hex(target), meaning])
    with (out / "locations.tsv").open("w", newline="") as handle:
        w = csv.writer(handle, delimiter="\t", lineterminator="\n")
        w.writerow(["record", "repository_path", "line", "column"])
        for va, path, line, column in locations:
            w.writerow([hex(va), path, line, column])
    with (out / "boundaries.tsv").open("w", newline="") as handle:
        w = csv.DictWriter(handle, ["kind", "input", "initial", "maintenance", "result"],
                           delimiter="\t", lineterminator="\n")
        w.writeheader()
        w.writerows(boundaries)
    with (out / "instruction-bytes.txt").open("w") as handle:
        for name, va, raw in controls:
            handle.write("%s\t%s\t%s\n" % (name, hex(va), raw))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path,
                        default=ROOT / "research/work-items/RE-007-margin-path-94")
    args = parser.parse_args()
    data = BINARY.read_bytes()
    analysed = analyse(data)
    write_packet(args.out, analysed)
    print(json.dumps(analysed[0]["counts"], sort_keys=True))


if __name__ == "__main__":
    main()
