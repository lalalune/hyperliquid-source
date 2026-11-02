#!/usr/bin/env python3
"""RE-004: core-to-EVM scaling for non-negative evm_extra_wei_decimals in node #94 (static).

Three handler copies (0x2715320, 0x4d0a6d0, 0x4d0bfa0) load the record byte at
+0xd1 (evm_extra_wei_decimals, stride 0xe8, flag +0xbc == 1) and, when the byte
is non-negative as i8, run a square-and-multiply loop over 256-bit values to
compute 10^d, then multiply the core amount by 10^d with a checked 256-bit
multiply:

    d == 0      : pow10 = 1 via a .rodata constant (shortcut, no loop)
    0 < d <= 77 : pow10 = 10^d exactly; final product = amount * 10^d
    d >= 78     : the loop overflows (10^78 > 2^256) and takes the fallback
    final overflow (amount * 10^d >= 2^256) also takes the fallback

The loop keeps a 32-byte accumulator (starts at 1) and a 32-byte base (starts
at 10). Each iteration: if the current bit of d is set, acc = mul(acc, base);
then base = mul(base, base); d >>= 1. Overflow flags accumulate into bl
(copy-1 folds the helper's out+0x20 byte; copies 2/3 fold the helper's al
return). The one subtlety the model reproduces exactly: a square overflow on
the final iteration is dropped (its flag register is never folded into bl
after the loop exits), but that cannot change any verdict, because for
d <= 77 no square overflows before the last iteration in a way that matters,
and for d >= 78 the accumulator multiply itself overflows first.

Two helper variants implement the checked 256-bit multiply: 0x27a1150
(copy-1) writes the value to out and the overflow byte to out+0x20, while
0x4de5500 (copies 2/3) takes (out, count=4, a, b) and returns the overflow
flag in al. Their inner schoolbook loops are not decoded here; only the
call-site contract is mapped.

This tool never executes the node and never calls a disassembler. It verifies
the target SHA-256, reads FDE bounds from the repository unwind index, checks
anchor byte strings at fixed virtual addresses, transcribes the positive-path
windows, and computes the loop/final tables arithmetically. It writes only
to the directory given by --out.

    python3 tools/core_evm_positive_scale94.py --out <dir>
    python3 tools/core_evm_positive_scale94.py --out <dir> --binary <path>

--allow-digest-mismatch is test-only: it lets the tamper controls prove the
anchor checks fail on their own, instead of failing at the digest check.
Production runs must never use it.

writes evidence.json, sites.tsv, loop_cases.tsv, final_cases.tsv and
windows.txt. Only the Python standard library is used.
"""

import argparse
import bisect
import csv
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import elf_index  # noqa: E402  (repository shared ELF section parser)

DEFAULT_BINARY = ROOT / "artifacts" / "node" / "94" / "hl-node"
SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
U256 = 1 << 256
RODATA_ONE = 0x20A720

HELPER1 = 0x27A1150
HELPER2 = 0x4DE5500

# Per-copy anchor addresses. Every anchor is verified byte-for-byte; the
# tamper controls in the tests flip one byte of each anchor class and must
# make this tool fail.
COPIES = [
    {
        "id": "copy-1",
        "fde": (0x2715320, 0x2716BC0),
        "positive": 0x2715756,
        "fallback": 0x271628D,
        "square_block": 0x271586D,
        "helper": HELPER1,
        "helper_fde": (0x27A1150, 0x27A1630),
        "amount_slot": 0x58,
        "flag_slot": 0x50,
        "result_slot": 0x1F0,
        "entry": (0x2715756, 0x2715800),
        "loop": (0x2715800, 0x271595A),
        "shortcut": (0x271595A, 0x2715977),
        "final": (0x2715977, 0x27159FC),
        "anchors": {
            "base10": (0x271576F, "48c78424d00200000a000000"),
            "movzx": (0x271577B, "440fb6fa"),
            "preloop_mov": (0x27157BD, "488b842400010000"),
            "preloop_or1": (0x27157C5, "4c09f8"),
            "preloop_or2": (0x27157C8, "480b8424f8000000"),
            "preloop_je": (0x27157D0, "0f8484010000"),
            "loop_test": (0x2715800, "41f6c701"),
            "loop_je": (0x2715804, "7467"),
            "acc_call": (0x2715834, "e817b90800"),
            "acc_fold_or": (0x2715854, "0a9c2450010000"),
            "acc_fold_set": (0x2715864, "0f95c34408e380e301"),
            "sq_call": (0x271589B, "e8b0b80800"),
            "sq_fold": (0x27158BB, "440aa42450010000"),
            "shr": (0x27158CC, "49d1ef"),
            "exit_test": (0x271593B, "f6c301"),
            "exit_je": (0x271594E, "7427"),
            "exit_jmp": (0x2715955, "e933090000"),
            "shortcut_movq": (0x271596F, "f30f7e05a94daffd"),
            "final_call": (0x27159E0, "e86bb70800"),
            "final_cmp": (0x27159EA, "80bc245001000000"),
            "final_jne": (0x27159F2, "0f8595080000"),
            "flag_flip": (0x27159F8, "4180f501"),
        },
    },
    {
        "id": "copy-2",
        "fde": (0x4D0A6D0, 0x4D0BFA0),
        "positive": 0x4D0AB0C,
        "fallback": 0x4D0B690,
        "square_block": 0x4D0AC33,
        "helper": HELPER2,
        "helper_fde": (0x4DE5500, 0x4DE59D0),
        "amount_slot": 0x48,
        "flag_slot": 0xE8,
        "result_slot": 0x210,
        "entry": (0x4D0AB0C, 0x4D0ABB0),
        "loop": (0x4D0ABB0, 0x4D0AD39),
        "shortcut": (0x4D0AD39, 0x4D0AD56),
        "final": (0x4D0AD56, 0x4D0AE18),
        "anchors": {
            "base10": (0x4D0AB25, "48c78424d00200000a000000"),
            "movzx": (0x4D0AB31, "440fb6fa"),
            "preloop_or2": (0x4D0AB7E, "480b8424f8000000"),
            "preloop_je": (0x4D0AB86, "0f84ad010000"),
            "loop_test": (0x4D0ABB0, "41f6c701"),
            "loop_je": (0x4D0ABB4, "747d"),
            "esi4a": (0x4D0ABE8, "be04000000"),
            "acc_call": (0x4D0ABFB, "e800a90d00"),
            "acc_fold": (0x4D0AC24, "08c30f95c34008eb80e301"),
            "esi4b": (0x4D0AC65, "be04000000"),
            "sq_call": (0x4D0AC78, "e883a80d00"),
            "shr": (0x4D0ACA1, "49d1ef"),
            "sq_fold": (0x4D0ACA4, "4008c5"),
            "exit_test": (0x4D0AD17, "f6c301"),
            "exit_je": (0x4D0AD2D, "7427"),
            "exit_jmp": (0x4D0AD34, "e957090000"),
            "shortcut_movq": (0x4D0AD4E, "f30f7e05caf94ffb"),
            "final_call": (0x4D0ADD6, "e825a70d00"),
            "final_test": (0x4D0AE0D, "84c0"),
            "final_jne": (0x4D0AE0F, "0f857b080000"),
            "flag_flip": (0x4D0AE15, "80f201"),
        },
    },
    {
        "id": "copy-3",
        "fde": (0x4D0BFA0, 0x4D0D870),
        "positive": 0x4D0C3DC,
        "fallback": 0x4D0CF60,
        "square_block": 0x4D0C503,
        "helper": HELPER2,
        "helper_fde": (0x4DE5500, 0x4DE59D0),
        "amount_slot": 0x48,
        "flag_slot": 0xE8,
        "result_slot": 0x210,
        "entry": (0x4D0C3DC, 0x4D0C480),
        "loop": (0x4D0C480, 0x4D0C609),
        "shortcut": (0x4D0C609, 0x4D0C626),
        "final": (0x4D0C626, 0x4D0C6E8),
        "anchors": {
            "base10": (0x4D0C3F5, "48c78424d00200000a000000"),
            "movzx": (0x4D0C401, "440fb6fa"),
            "preloop_or2": (0x4D0C44E, "480b8424f8000000"),
            "preloop_je": (0x4D0C456, "0f84ad010000"),
            "loop_test": (0x4D0C480, "41f6c701"),
            "loop_je": (0x4D0C484, "747d"),
            "esi4a": (0x4D0C4B8, "be04000000"),
            "acc_call": (0x4D0C4CB, "e830900d00"),
            "acc_fold": (0x4D0C4F4, "08c30f95c34008eb80e301"),
            "esi4b": (0x4D0C535, "be04000000"),
            "sq_call": (0x4D0C548, "e8b38f0d00"),
            "shr": (0x4D0C571, "49d1ef"),
            "sq_fold": (0x4D0C574, "4008c5"),
            "exit_test": (0x4D0C5E7, "f6c301"),
            "exit_je": (0x4D0C5FD, "7427"),
            "exit_jmp": (0x4D0C604, "e957090000"),
            "shortcut_movq": (0x4D0C61E, "f30f7e05fae04ffb"),
            "final_call": (0x4D0C6A6, "e8558e0d00"),
            "final_test": (0x4D0C6DD, "84c0"),
            "final_jne": (0x4D0C6DF, "0f857b080000"),
            "flag_flip": (0x4D0C6E5, "80f201"),
        },
    },
]

# (name, VA, expected bytes) for the shared helpers and the .rodata constant.
SHARED_ANCHORS = [
    ("helper1_overflow_store", 0x27A12ED, "884720"),
    ("helper2_overflow_one", 0x4DE55A3, "b001"),
    ("helper2_zero", 0x4DE551A, "31c0"),
    ("rodata_one", RODATA_ONE, "0100000000000000"),
]

# E8 call sites of each helper found by a plain .text scan, with the
# enclosing FDE from the unwind index. The nine positive-path sites are
# mapped here; the remaining five belong to other callers and are listed
# only to close the census.
CENSUS = {
    HELPER1: {
        "mapped": [0x2715834, 0x271589B, 0x27159E0],
        "other": [(0x279D1FC, 0x279D0C0), (0x279D2AB, 0x279D0C0),
                  (0x279D51A, 0x279D3E0)],
    },
    HELPER2: {
        "mapped": [0x4D0ABFB, 0x4D0AC78, 0x4D0ADD6,
                   0x4D0C4CB, 0x4D0C548, 0x4D0C6A6],
        "other": [(0x4C90193, 0x4C900A0), (0x4C994FF, 0x4C99440)],
    },
}


class CheckError(Exception):
    pass


def fail(message):
    raise CheckError(message)


def va_to_offset(data, sections, va):
    for section in sections:
        if section["type"] == 8:
            continue
        start = section["address"]
        end = start + section["size"]
        if start <= va < end:
            return section["offset"] + (va - start)
    fail(f"VA {va:#x} has no file mapping")


def read_at(data, sections, va, size):
    offset = va_to_offset(data, sections, va)
    chunk = data[offset:offset + size]
    if len(chunk) != size:
        fail(f"short read at VA {va:#x}")
    return chunk


def check_anchor(data, sections, va, expected_hex, name):
    actual = read_at(data, sections, va, len(expected_hex) // 2).hex()
    if actual != expected_hex:
        fail(f"anchor {name} at {va:#x}: expected {expected_hex}, got {actual}")


def call_target(data, sections, va):
    insn = read_at(data, sections, va, 5)
    if insn[0] != 0xE8:
        fail(f"not a call at {va:#x}")
    return va + 5 + struct.unpack_from("<i", insn, 1)[0]


def load_unwind_index(root):
    for candidate in ("work/node-94-unwind.tsv", "work/index/node-94-unwind.tsv"):
        path = root / candidate
        if path.exists():
            bounds = {}
            with open(path, newline="") as handle:
                for row in csv.DictReader(handle, delimiter="\t"):
                    bounds[int(row["start_va"], 16)] = int(
                        row["next_index_upper_bound_va"], 16
                    )
            return bounds
    fail("node #94 unwind index not found under work/")


def enclosing_fde(bounds, starts, va):
    i = bisect.bisect_right(starts, va) - 1
    if i < 0:
        fail(f"no enclosing FDE for {va:#x}")
    start = starts[i]
    return start, bounds[start]


def mul256(a, b):
    """Return (low 256 bits, overflow flag) of a * b."""
    prod = a * b
    return prod % U256, 1 if prod >= U256 else 0


def loop_model(d):
    """Simulate the square-and-multiply loop for decimals byte d.

    Returns (pow10, loop_overflow): pow10 is the accumulator value at loop
    exit (exact 10^d when loop_overflow is 0); loop_overflow is the bl flag
    at loop exit, with the exact fold order of the three copies (a square
    overflow is folded into bl only at a later bit-set iteration, so a
    square overflow on the final iteration is dropped).
    """
    acc, base, bl, sq_acc, remaining = 1, 10, 0, 0, d
    while remaining:
        if remaining & 1:
            acc, ov = mul256(acc, base)
            bl = 1 if (bl or ov or sq_acc) else 0
        base, ov2 = mul256(base, base)
        sq_acc = sq_acc or ov2
        remaining >>= 1
    return acc, bl


def build(binary_path, out_dir, allow_digest_mismatch=False):
    data = Path(binary_path).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != SHA256 and not allow_digest_mismatch:
        fail(f"target digest mismatch: {digest}")
    sections = elf_index.sections(data)
    bounds = load_unwind_index(ROOT)
    starts = sorted(bounds)

    for copy in COPIES:
        fde_start, fde_end = copy["fde"]
        got = enclosing_fde(bounds, starts, fde_start)
        if got != (fde_start, fde_end):
            fail(f"FDE bound mismatch for {copy['id']}: {got}")
        h_start, h_end = copy["helper_fde"]
        got = enclosing_fde(bounds, starts, h_start)
        if got != (h_start, h_end):
            fail(f"helper FDE bound mismatch for {copy['id']}: {got}")
        for name, (va, expected) in copy["anchors"].items():
            check_anchor(data, sections, va, expected, f"{copy['id']}:{name}")
        for call_name in ("acc_call", "sq_call", "final_call"):
            va, _ = copy["anchors"][call_name]
            if call_target(data, sections, va) != copy["helper"]:
                fail(f"{copy['id']}:{call_name} does not target the helper")
        for jmp_name, expect in (("exit_jmp", copy["fallback"]),
                                 ("final_jne", copy["fallback"])):
            va, raw = copy["anchors"][jmp_name]
            insn = bytes.fromhex(raw)
            if jmp_name == "exit_jmp":
                target = va + 5 + struct.unpack_from("<i", insn, 1)[0]
            else:
                target = va + 6 + struct.unpack_from("<i", insn, 2)[0]
            if target != expect:
                fail(f"{copy['id']}:{jmp_name} targets {target:#x}, not fallback")
        va, raw = copy["anchors"]["shortcut_movq"]
        insn = bytes.fromhex(raw)
        disp = struct.unpack_from("<i", insn, 4)[0]
        if va + 8 + disp != RODATA_ONE:
            fail(f"{copy['id']}: shortcut constant is not 0x20a720")
        va, raw = copy["anchors"]["preloop_je"]
        insn = bytes.fromhex(raw)
        target = va + 6 + struct.unpack_from("<i", insn, 2)[0]
        if target != copy["shortcut"][0]:
            fail(f"{copy['id']}: preloop je does not target the shortcut")
        va, raw = copy["anchors"]["loop_je"]
        insn = bytes.fromhex(raw)
        target = va + 2 + (insn[1] if insn[1] < 128 else insn[1] - 256)
        if target != copy["square_block"]:
            fail(f"{copy['id']}: loop je does not target the square block")

    for name, va, expected in SHARED_ANCHORS:
        check_anchor(data, sections, va, expected, name)

    # Census: plain .text scan for E8 calls to either helper.
    text = None
    for section in sections:
        if section.get("name") == ".text":
            text = section
            break
    if text is None:
        fail(".text section not found")
    text_bytes = data[text["offset"]:text["offset"] + text["size"]]
    text_va = text["address"]
    found = {HELPER1: [], HELPER2: []}
    for i in range(len(text_bytes) - 5):
        if text_bytes[i] != 0xE8:
            continue
        rel = struct.unpack_from("<i", text_bytes, i + 1)[0]
        target = text_va + i + 5 + rel
        if target in found:
            found[target].append(text_va + i)
    for helper, spec in CENSUS.items():
        expected = sorted(spec["mapped"] + [va for va, _ in spec["other"]])
        if sorted(found[helper]) != expected:
            fail(f"helper {helper:#x} census mismatch: {found[helper]}")
        for va, fde_start in spec["other"]:
            got_start, _ = enclosing_fde(bounds, starts, va)
            if got_start != fde_start:
                fail(f"other-caller FDE mismatch at {va:#x}: {got_start:#x}")

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    def write_text(name, text_content):
        (out_dir / name).write_text(text_content)

    def write_tsv(name, rows, columns):
        with open(out_dir / name, "w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns,
                                    delimiter="\t", lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)

    # Window transcription, byte-for-byte with per-window digests.
    windows = {}
    window_lines = []
    for copy in COPIES:
        for kind in ("entry", "loop", "shortcut", "final"):
            start, end = copy[kind]
            chunk = read_at(data, sections, start, end - start)
            key = f"{copy['id']}:{kind}"
            windows[key] = {
                "start": hex(start),
                "end": hex(end),
                "bytes": len(chunk),
                "sha256": hashlib.sha256(chunk).hexdigest(),
            }
            window_lines.append(f"{key} {start:#x}..{end:#x} {chunk.hex()}")

    sites_rows = []
    for copy in COPIES:
        sites_rows.append({
            "copy": copy["id"],
            "fde_start": hex(copy["fde"][0]),
            "fde_end": hex(copy["fde"][1]),
            "positive_va": hex(copy["positive"]),
            "helper": hex(copy["helper"]),
            "helper_fde_start": hex(copy["helper_fde"][0]),
            "helper_fde_end": hex(copy["helper_fde"][1]),
            "acc_call": hex(copy["anchors"]["acc_call"][0]),
            "sq_call": hex(copy["anchors"]["sq_call"][0]),
            "final_call": hex(copy["anchors"]["final_call"][0]),
            "fallback": hex(copy["fallback"]),
            "amount_slot": hex(copy["amount_slot"]),
            "flag_slot": hex(copy["flag_slot"]),
            "result_slot": hex(copy["result_slot"]),
            "entry_window": f"{copy['entry'][0]:#x}..{copy['entry'][1]:#x}",
            "loop_window": f"{copy['loop'][0]:#x}..{copy['loop'][1]:#x}",
            "shortcut_window": f"{copy['shortcut'][0]:#x}..{copy['shortcut'][1]:#x}",
            "final_window": f"{copy['final'][0]:#x}..{copy['final'][1]:#x}",
        })

    loop_rows = []
    for d in range(256):
        pow10, overflow = loop_model(d)
        loop_rows.append({
            "d": d,
            "loop_overflow": overflow,
            "outcome": "fallback" if overflow else "success",
            "pow10_hex": "" if overflow else f"{pow10:#x}",
            "pow10_dec": "" if overflow else str(pow10),
        })

    final_rows = []
    amounts = [0, 1, 2, (1 << 64) - 1]
    for d in (0, 1, 2, 18, 19, 77, 78):
        pow10, loop_overflow = loop_model(d)
        if loop_overflow:
            final_rows.append({
                "d": d, "amount": "", "pow10": "",
                "product": "", "final_overflow": "",
                "outcome": "fallback (loop overflow)",
            })
            continue
        threshold = (U256 + pow10 - 1) // pow10
        grid = sorted(set(amounts + [threshold - 1, threshold]))
        for amount in grid:
            if amount < 0:
                continue
            prod, ov = mul256(amount, pow10)
            final_rows.append({
                "d": d, "amount": amount, "pow10": pow10,
                "product": prod, "final_overflow": ov,
                "outcome": "fallback" if ov else "success",
            })

    evidence = {
        "target": "node #94",
        "sha256": SHA256,
        "worktree_baseline": "2993e46",
        "rodata_one_va": hex(RODATA_ONE),
        "rodata_one_value": 1,
        "helpers": {
            "copy-1": {"va": hex(HELPER1), "fde": [hex(0x27A1150), hex(0x27A1630)],
                       "overflow_signal": "byte at out+0x20"},
            "copies-2-3": {"va": hex(HELPER2), "fde": [hex(0x4DE5500), hex(0x4DE59D0)],
                           "overflow_signal": "al return (0 exact, 1 overflow)"},
        },
        "census": {
            hex(HELPER1): {"mapped": [hex(v) for v in CENSUS[HELPER1]["mapped"]],
                           "other": [(hex(v), hex(f))
                                     for v, f in CENSUS[HELPER1]["other"]]},
            hex(HELPER2): {"mapped": [hex(v) for v in CENSUS[HELPER2]["mapped"]],
                           "other": [(hex(v), hex(f))
                                     for v, f in CENSUS[HELPER2]["other"]]},
        },
        "loop_boundary": {
            "largest_exact_d": 77,
            "smallest_fallback_d": 78,
            "note": "10^77 < 2^256 < 10^78; verified by simulating all d in 0..255",
        },
        "windows": windows,
    }

    write_tsv("sites.tsv", sites_rows,
              ["copy", "fde_start", "fde_end", "positive_va", "helper",
               "helper_fde_start", "helper_fde_end", "acc_call", "sq_call",
               "final_call", "fallback", "amount_slot", "flag_slot",
               "result_slot", "entry_window", "loop_window",
               "shortcut_window", "final_window"])
    write_tsv("loop_cases.tsv", loop_rows,
              ["d", "loop_overflow", "outcome", "pow10_hex", "pow10_dec"])
    write_tsv("final_cases.tsv", final_rows,
              ["d", "amount", "pow10", "product", "final_overflow", "outcome"])
    write_text("windows.txt", "\n".join(window_lines) + "\n")
    (out_dir / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
    return evidence


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    parser.add_argument("--binary", default=str(DEFAULT_BINARY))
    parser.add_argument("--allow-digest-mismatch", action="store_true")
    args = parser.parse_args(argv)
    try:
        build(args.binary, args.out, args.allow_digest_mismatch)
    except CheckError as exc:
        print(f"CHECK FAILED: {exc}", file=sys.stderr)
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
