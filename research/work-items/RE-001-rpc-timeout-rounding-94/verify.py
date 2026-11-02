#!/usr/bin/env python3
"""Digest-bound static evidence; does not execute captured instructions."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import random
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
from gossip_rpc_timeouts_static import Image

TARGET = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
START, END = 0x565F410, 0x565F481
TRUNC_START, TRUNC_END = 0x565F490, 0x565F4E5
MASK, BIAS, SLOT = 0x2082F0, 0x203AE0, 0x576F6D8
BODY = bytes.fromhex(
    "660f28c8660f2805d48ebafa660f54c1660f5605b846bafaf20f58c1"
    "66480f7ec04889c248c1ea3481e2ff07000081fa32040000773a"
    "8d8a01fcffff48be000000000000f0ff48d3fe81faff030000"
    "48b90000000000000080480f43ce4889ca48f7d24885c27408"
    "4821c166480f6ec1c3"
)
CALLERS = ((0x1FD475E, 0x1FD4570), (0x1FD500C, 0x1FD4570),
           (0x226BCD0, 0x226BB20), (0x435CCC6, 0x435CB20))
FILES = {"README.md", "RESULT.md", "verify.py", "records.json", "disassembly.txt"}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def bits(value):
    return struct.unpack("<Q", struct.pack("<d", value))[0]


def number(value):
    return struct.unpack("<d", struct.pack("<Q", value))[0]


def biased_truncation(value, bias):
    # Static model of ADDSD under round-to-nearest-even, then the observed mask.
    result = value + math.copysign(bias, value)
    word = bits(result)
    exponent = (word >> 52) & 0x7FF
    if exponent > 0x432:
        return result
    mask = (1 << 63) if exponent < 0x3FF else (
        (-0x10000000000000 >> ((exponent - 0x3FF) & 63)) & ((1 << 64) - 1)
    )
    return number(word & mask)


def nearest_away(value):
    # Independent exact rational reference, not Python's ties-to-even round().
    if not math.isfinite(value):
        return value
    numerator, denominator = value.as_integer_ratio()
    whole, remainder = divmod(abs(numerator), denominator)
    if 2 * remainder >= denominator:
        whole += 1
    return math.copysign(float(whole), value)


def inspect_image(img):
    require(img.fde(START) == (START, END), "helper FDE changed")
    require(img.fde(TRUNC_START) == (TRUNC_START, TRUNC_END), "neighbor FDE changed")
    body = img.read(START, END - START)
    require(body == BODY, "helper instructions changed")
    require(body[28:] == img.read(TRUNC_START, TRUNC_END - TRUNC_START),
            "truncation suffix no longer equals neighboring body")
    require(img.read(MASK, 16) == struct.pack("<QQ", 1 << 63, 1 << 63),
            "sign mask changed")
    require(img.read(BIAS, 16) == struct.pack("<QQ", 0x3FDFFFFFFFFFFFFF,
                                            0x3FDFFFFFFFFFFFFF), "bias changed")
    require(img.rip(START + 4, 8) == MASK, "sign-mask RIP changed")
    require(img.rip(START + 16, 8) == BIAS, "bias RIP changed")
    require(img.relative.get(SLOT) == START, "relocation target changed")
    callers = []
    for mul, fde in CALLERS:
        lo, hi = img.fde(fde)
        require(lo <= mul and mul + 14 <= hi, "caller outside owning FDE")
        require(img.read(mul, 4) == bytes.fromhex("f20f5905"), "multiply changed")
        require(img.rip(mul, 8) == 0x20AE60 and img.f64(0x20AE60) == 1e6,
                "seconds multiplier changed")
        require(img.read(mul + 8, 2) == b"\xff\x15", "indirect call changed")
        require(img.rip(mul + 8, 6) == SLOT, "caller slot changed")
        callers.append({"fde_start": hex(lo), "fde_end": hex(hi),
                        "multiply_va": hex(mul), "call_va": hex(mul + 8),
                        "file_offset": img.offset(mul, 14),
                        "bytes": img.read(mul, 14).hex()})
    return {"helper": {"start": hex(START), "end_exclusive": hex(END),
                       "file_offset": img.offset(START, len(body)),
                       "bytes": len(body), "sha256": hashlib.sha256(body).hexdigest(),
                       "hex": body.hex()},
            "neighbor_truncation": {"start": hex(TRUNC_START),
                                   "end_exclusive": hex(TRUNC_END),
                                   "same_suffix_bytes": 85},
            "constants": [{"va": hex(v), "file_offset": img.offset(v, 16),
                           "hex": img.read(v, 16).hex()} for v in (MASK, BIAS)],
            "relative_slot": hex(SLOT), "relative_target": hex(START),
            "callers": callers}


def evidence(data):
    require(len(data) == 91774280 and hashlib.sha256(data).hexdigest() == TARGET,
            "not the authenticated Node94 artifact")
    img = Image(data)
    result = inspect_image(img)
    bias = img.f64(BIAS)
    values = [0.0, -0.0, number(1), -number(1), 0.25, -0.25,
              math.nextafter(0.5, 0), -math.nextafter(0.5, 0),
              0.5, -0.5, math.nextafter(0.5, 1), -math.nextafter(0.5, 1),
              1.5, -1.5, 2.5, -2.5,
              2.0**51 - 0.5, -(2.0**51 - 0.5),
              2.0**51 + 0.5, -(2.0**51 + 0.5),
              2.0**52, -(2.0**52), 2.0**52 + 1, -(2.0**52 + 1),
              math.inf, -math.inf, math.nan]
    rng = random.Random(94)
    for _ in range(256):
        values.append(number((rng.getrandbits(1) << 63)
                             | ((1023 + rng.randrange(-10, 55)) << 52)
                             | rng.getrandbits(52)))
    cases = []
    for value in values:
        actual, expected = biased_truncation(value, bias), nearest_away(value)
        require((math.isnan(actual) and math.isnan(expected))
                or bits(actual) == bits(expected), "static model differs from rational reference")
        cases.append({"input_bits": f"{bits(value):016x}",
                      "model_bits": f"{bits(actual):016x}",
                      "reference_bits": f"{bits(expected):016x}"})
    below = math.nextafter(0.5, 0)
    require(biased_truncation(below, 0.5) != nearest_away(below),
            "exact-half bias control no longer discriminates")
    require(round(0.5) != nearest_away(0.5), "ties-even control does not discriminate")
    require(math.trunc(0.5) != nearest_away(0.5), "truncation control does not discriminate")
    mutations = [(START + 26, b"\x5c", "ADDSD-to-SUBSD"),
                 (START + 52, b"\x76", "exponent-branch"),
                 (MASK, b"\0" * 16, "lost-sign-mask"),
                 (BIAS, struct.pack("<dd", 0.5, 0.5), "exact-half-bias"),
                 (TRUNC_END - 1, b"\xcc", "truncation-return"),
                 (CALLERS[0][0] + 8, b"\x90", "caller-opcode")]
    rejected = []
    for va, replacement, name in mutations:
        altered = bytearray(data)
        off = img.offset(va, len(replacement))
        altered[off:off + len(replacement)] = replacement
        try:
            inspect_image(Image(altered))
        except ValueError:
            rejected.append(name)
        else:
            raise ValueError("corruption accepted: " + name)
    dependencies = ["tools/gossip_rpc_timeouts_static.py", "tools/fde_extents.py",
                    "tools/elf_index.py"]
    result.update(target_sha256=TARGET, target_executed=False,
                  model_assumption="binary64 ADDSD round-to-nearest-even; no target execution",
                  modeled_cases=cases, corrupted_inputs_rejected=rejected,
                  semantic_controls=["exact-half-bias", "ties-even", "truncation-only"],
                  dependencies={p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest()
                                for p in dependencies})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "artifacts/node/94/hl-node")
    parser.add_argument("--write-records", type=Path)
    args = parser.parse_args()
    output = (json.dumps(evidence(args.binary.read_bytes()), indent=2, sort_keys=True,
                         allow_nan=False) + "\n").encode()
    if args.write_records:
        args.write_records.write_bytes(output)
        print("Wrote authenticated static records; no target execution.")
        return
    packet = Path(__file__).resolve().parent
    require((packet / "records.json").read_bytes() == output, "records differ")
    entries = {}
    for line in (packet / "MANIFEST.sha256").read_text().splitlines():
        digest, name = line.split("  ", 1)
        require(name in FILES and name not in entries, "foreign or duplicate manifest path")
        require(hashlib.sha256((packet / name).read_bytes()).hexdigest() == digest,
                "manifest digest mismatch: " + name)
        entries[name] = digest
    require(set(entries) == FILES, "incomplete packet manifest")
    print("Verified helper113B, neighbor85B, four calls,283 modeled inputs,"
          " six instruction/data controls and three semantic controls."
          " Static evidence only; no component gate or runtime equivalence.")


if __name__ == "__main__":
    main()
