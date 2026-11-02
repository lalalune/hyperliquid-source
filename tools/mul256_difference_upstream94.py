"""Deterministic generator for the RE-004 mul256 difference-upstream packet.

Maps the direct upstream callers of the #161 mul256 difference writers
(caller-A 0x279d0c0, caller-B 0x279d3e0) and answers #161's open question:
does any direct upstream caller distinguish the collapsed 0 from a genuine
0 difference? All twelve direct call sites live in small tag-dispatch
wrappers that decode a value, call caller-A/B only when the tag byte is 5,
and otherwise copy the decoded fields. The generator verifies the wrapper
idiom byte by byte (tag compare, branch, argument setup, call, post-call
jump to the tag store, and the tag-store/return tail), re-derives the full
direct-caller census by E8 scan, confirms no E9 tail-jump caller exists,
and models the wrapper-observable outcomes. Reads the pinned node #94
binary and disassembles nothing: it checks the node SHA-256 first, verifies
unwind FDE starts and anchors via the repository shared ELF parser, then
emits evidence.json, sites.tsv, cases.tsv and windows.txt. Writes only
to --out. Static analysis only: the node binary is never executed.
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
CALLER_A = 0x279D0C0
CALLER_B = 0x279D3E0
DEC_A = 0x2787460
DEC_B = 0x2786DD0
MASK = (1 << 64) - 1
ZERO = (0, 0, 0, 0)

# (call site, wrapper FDE start, wrapper FDE end, callee, decoder, decoder site, call bytes)
SITES = [
    (0x276E398, 0x276E340, 0x276E3E0, "caller-A", DEC_A, 0x276E37D, "e823ed0200"),
    (0x276E508, 0x276E4B0, 0x276E550, "caller-A", DEC_B, 0x276E4ED, "e8b3eb0200"),
    (0x2771B58, 0x2771B00, 0x2771BA0, "caller-A", DEC_A, 0x2771B3D, "e863b50200"),
    (0x2772838, 0x27727E0, 0x2772880, "caller-A", DEC_B, 0x277281D, "e883a80200"),
    (0x2777878, 0x2777820, 0x27778C0, "caller-A", DEC_B, 0x277785D, "e843580200"),
    (0x2778768, 0x2778710, 0x27787B0, "caller-A", DEC_A, 0x277874D, "e853490200"),
    (0x276D638, 0x276D5E0, 0x276D680, "caller-B", DEC_B, 0x276D61D, "e8a3fd0200"),
    (0x276DA58, 0x276DA00, 0x276DAA0, "caller-B", DEC_A, 0x276DA3D, "e883f90200"),
    (0x2770CE8, 0x2770C90, 0x2770D30, "caller-B", DEC_B, 0x2770CCD, "e8f3c60200"),
    (0x2770DD8, 0x2770D80, 0x2770E20, "caller-B", DEC_A, 0x2770DBD, "e803c60200"),
    (0x2776908, 0x27768B0, 0x2776950, "caller-B", DEC_A, 0x27768ED, "e8d36a0200"),
    (0x2776E78, 0x2776E20, 0x2776EC0, "caller-B", DEC_B, 0x2776E5D, "e863650200"),
]

# Decoder call bytes per site, keyed by decoder site.
DEC_CALLS = {
    0x276E37D: "e8de900100", 0x276E4ED: "e8de880100", 0x2771B3D: "e81e590100",
    0x277281D: "e8ae450100", 0x277785D: "e86ef50000", 0x277874D: "e80eed0000",
    0x276D61D: "e8ae970100", 0x276DA3D: "e81e9a0100", 0x2770CCD: "e8fe600100",
    0x2770DBD: "e89e660100", 0x27768ED: "e86e0b0100", 0x2776E5D: "e86eff0000",
}

# #157-#161 FDE ranges, for the non-overlap check (unwind-described ranges).
PRIOR_FDES = [
    (0x2715320, 0x2716BC0), (0x4D0A6D0, 0x4D0BFA0), (0x4D0BFA0, 0x4D0D870),
    (0x27A1150, 0x27A13F0), (0x4DE5500, 0x4DE58C0),
    (0x279D0C0, 0x279D3E0), (0x279D3E0, 0x279D5E0),
    (0x4C900A0, 0x4C901E0), (0x4C99440, 0x4C995C0),
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


def derive_census(data, sections, entries):
    text = next(s for s in sections if s["name"] == ".text")
    base, off, size = text["address"], text["offset"], text["size"]
    starts = [e["start"] for e in entries]
    found = {}
    for target in (CALLER_A, CALLER_B):
        sites = []
        for i in range(size - 5):
            if data[off + i] == 0xE8:
                rel = struct.unpack_from("<i", data, off + i + 1)[0]
                if base + i + 5 + rel == target:
                    sites.append(base + i)
        found[target] = sites
        # No E9 tail-jump caller for either target.
        for i in range(size - 5):
            if data[off + i] == 0xE9:
                rel = struct.unpack_from("<i", data, off + i + 1)[0]
                if base + i + 5 + rel == target:
                    raise ValueError(f"E9 tail-jump caller at {base + i:#x} for {target:#x}")
    for site, fs, fe, callee, _dec, _ds, _cb in SITES:
        target = CALLER_A if callee == "caller-A" else CALLER_B
        if site not in found[target]:
            raise ValueError(f"census site {site:#x} not found by E8 scan")
        j = bisect.bisect_right(starts, site) - 1
        e = entries[j]
        if e["start"] != fs or e["next_index_upper_bound"] != fe:
            raise ValueError(f"enclosing FDE mismatch for {site:#x}")
    for target, callee in ((CALLER_A, "caller-A"), (CALLER_B, "caller-B")):
        want = sorted(s for s, _, _, c, _, _, _ in SITES if c == callee)
        if sorted(found[target]) != want:
            raise ValueError(f"E8 scan found extra/missing sites for {target:#x}")
    return found


def limbs_str(v):
    return ",".join(str(x) for x in v)


def wrapper_outcome(tag, difference, collapsed, state_byte, counter):
    """Model one wrapper's observable outputs.

    tag: decoder tag byte. difference: caller-A/B difference (4 limbs) when
    tag == 5 and no collapse. collapsed: True when the #161 sentinel path
    replaced the difference by 0. state_byte: the [r14+0x294] byte caller-A/B
    test before bumping the counter. counter: pre-call [rbx+0x60] value.
    Returns (return_object, mutated_stored, counter_out, flag_set).
    """
    if tag != 5:
        return ("copied-fields", None, counter, False)
    stored = ZERO if collapsed else difference
    if state_byte == 1:
        counter_out = MASK if counter == MASK else counter + 1
    else:
        counter_out = counter
    return ("tag-only", stored, counter_out, True)


S_NORMAL = (1000, 100, 100, 0)
DIFF_A = (930, 100, 100, 0)
DIFF_B = (1000, 65, 100, 0)


def build_cases():
    rows = []
    # (case, callee, tag, difference, collapsed, state_byte, counter)
    specs = [
        ("W1-copy-tag3", "caller-A", 3, None, False, 0, 7),
        ("W2-copy-tag4", "caller-B", 4, None, False, 0, 7),
        ("W3-copy-tag6", "caller-A", 6, None, False, 0, 7),
        ("W4-A-genuine-nonzero", "caller-A", 5, DIFF_A, False, 1, 7),
        ("W5-A-genuine-zero", "caller-A", 5, ZERO, False, 1, 7),
        ("W6-A-collapsed-zero", "caller-A", 5, DIFF_A, True, 1, 7),
        ("W7-B-genuine-nonzero", "caller-B", 5, DIFF_B, False, 1, 7),
        ("W8-B-genuine-zero", "caller-B", 5, ZERO, False, 1, 7),
        ("W9-B-collapsed-zero", "caller-B", 5, DIFF_B, True, 1, 7),
        ("W10-A-counter-wrap", "caller-A", 5, DIFF_A, False, 1, MASK),
        ("W11-B-state-zero", "caller-B", 5, DIFF_B, False, 0, 7),
    ]
    for case, callee, tag, diff, collapsed, state, counter in specs:
        ret, stored, counter_out, flag = wrapper_outcome(
            tag, diff, collapsed, state, counter)
        rows.append((callee, case, str(tag),
                     limbs_str(diff) if diff is not None else "",
                     "1" if collapsed else "0", str(state), str(counter),
                     ret, limbs_str(stored) if stored is not None else "",
                     str(counter_out), "1" if flag else "0"))
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
    for addr, label in ((CALLER_A, "caller-A"), (CALLER_B, "caller-B")):
        if addr not in starts:
            raise ValueError(f"{label} {addr:#x} is not an unwind start")
    for site, fs, fe, callee, dec, ds, cb in SITES:
        if fs not in starts:
            raise ValueError(f"wrapper FDE {fs:#x} is not an unwind start")
        # Wrapper idiom anchors, relative to the call site.
        check_anchor(data, sections, site - 0x16, "0fb62c24")   # movzx ebp,[rsp]
        check_anchor(data, sections, site - 0x12, "4080fd05")   # cmp bpl,5
        check_anchor(data, sections, site - 0x0E, "7513")       # jne copy-path
        check_anchor(data, sections, site - 0x0C, "488b7c2408")  # mov rdi,[rsp+8]
        check_anchor(data, sections, site - 0x07, "498bb6d8000000")  # mov rsi,[r14+0xd8]
        check_anchor(data, sections, site, cb)                  # call caller-A/B
        check_anchor(data, sections, site + 5, "eb31")          # jmp tag-store
        check_anchor(data, sections, site + 0x38, "40882b")     # mov [rbx],bpl
        check_anchor(data, sections, site + 0x3B, "4889d8")     # mov rax,rbx
        check_anchor(data, sections, site + 0x3E, "4883c440")   # add rsp,0x40
        check_anchor(data, sections, site + 0x42, "5b415e5dc3")  # pops + ret
        check_anchor(data, sections, site + 7, "8b442401")      # copy-path head
        check_anchor(data, sections, site + 0x0F, "894b04")     # mov [rbx+4],ecx
        check_anchor(data, sections, site + 0x12, "894301")     # mov [rbx+1],eax
        check_anchor(data, sections, ds, DEC_CALLS[ds])         # decoder call
        raw = read_bytes(data, sections, ds, 5)
        rel = struct.unpack_from("<i", raw, 1)[0]
        if ds + 5 + rel != dec:
            raise ValueError(f"decoder call at {ds:#x} targets {ds + 5 + rel:#x}, want {dec:#x}")
        raw = read_bytes(data, sections, site, 5)
        rel = struct.unpack_from("<i", raw, 1)[0]
        want = CALLER_A if callee == "caller-A" else CALLER_B
        if site + 5 + rel != want:
            raise ValueError(f"call at {site:#x} targets {site + 5 + rel:#x}, want {want:#x}")
        for ps, pe in PRIOR_FDES:
            if not (fe <= ps or fs >= pe):
                raise ValueError(f"wrapper FDE {fs:#x}..{fe:#x} overlaps prior {ps:#x}..{pe:#x}")
    derive_census(data, sections, entries)
    windows = []
    for site, fs, fe, callee, dec, _ds, _cb in SITES:
        w = read_bytes(data, sections, fs, fe - fs)
        windows.append((f"{callee}-wrapper-{site:#x}", fs, fe, len(w),
                        hashlib.sha256(w).hexdigest()))
    cases = build_cases()
    out = args.out
    out.mkdir(parents=True, exist_ok=True)
    evidence = {
        "target": "node #94",
        "sha256": SHA256,
        "worktree_baseline": "2993e46",
        "callees": {
            "caller-A": {"address": "0x279d0c0", "fde": "0x279d0c0..0x279d3e0"},
            "caller-B": {"address": "0x279d3e0", "fde": "0x279d3e0..0x279d5e0"},
        },
        "decoders": {"0x2787460": 6, "0x2786dd0": 6},
        "sites": len(SITES),
        "e9_tail_jump_callers": 0,
        "tag": 5,
        "post_call_bytes": "eb31",
        "cases": len(cases),
        "windows": [{"label": l, "fde": f"{s:#x}..{e:#x}", "length": ln, "sha256": sha}
                    for l, s, e, ln, sha in windows],
    }
    (out / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
    (out / "sites.tsv").write_text(
        "call_site\twrapper_fde_start\twrapper_fde_end\tcallee\tdecoder\tdecoder_site\n" +
        "".join(f"{s:#x}\t{fs:#x}\t{fe:#x}\t{c}\t{d:#x}\t{ds:#x}\n"
                for s, fs, fe, c, d, ds, _cb in SITES))
    (out / "cases.tsv").write_text(
        "callee\tcase\ttag\tdifference\tcollapsed\tstate_byte\tcounter_in\treturn_object\tmutated_stored\tcounter_out\tflag_set\n" +
        "".join("\t".join(r) + "\n" for r in cases))
    (out / "windows.txt").write_text(
        "".join(f"{label} {s:#x}..{e:#x} length={ln} sha256={sha}\n"
                for label, s, e, ln, sha in windows))
    print(f"{len(cases)} cases; {len(SITES)} wrapper sites; "
          f"node94 SHA-256 {SHA256}")


if __name__ == "__main__":
    main()
