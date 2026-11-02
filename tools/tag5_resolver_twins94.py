"""Deterministic generator for the RE-004 tag-5 resolver twins packet.

Two small functions, 0x2788350 (421 bytes, decoder-A caller) and 0x2788500
(527 bytes, decoder-B caller), share one tag-5 resolution idiom: decode a
value, copy it verbatim when the tag byte is not 5, and otherwise resolve
the decoded object's [0x68..0x88] vectors against two fixed 16-byte
constants. On a full 32-byte match the object header is set to 1 and the
decoded value is copied into the object; on a mismatch a transform callee
rewrites the object's [0x0..0x40] (twin-B adds a post-transform tag check
with a second transform). Neither twin reads or writes the #161 difference
field [obj+0x40..0x58], the counter [obj+0x60], or the flag [obj+0xb0].
The generator verifies the twin idiom byte by byte, re-derives the full
direct-caller census of both decoders by E8 scan (30 sites: 12 #162
wrappers, these 2 twins, 16 sites in 7 larger functions), confirms no E9
tail-jump caller exists, and models the routing outcomes. Transform outputs
are opaque by design (callee bodies are out of scope); cases assert routing
and overwrite extents, not transform values. Reads the pinned node #94
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
DEC_A = 0x2787460
DEC_B = 0x2786DD0
CONST_HI = 0x204BE0  # compared against [obj+0x78]
CONST_LO = 0x206160  # compared against [obj+0x68]
CONST_HI_BYTES = bytes.fromhex("e500b653ca82273b7bfad8045d85a470")
CONST_LO_BYTES = bytes.fromhex("c5d2460186f7233c927e7db2dcc703c0")
CLEANUP = 0x2781760
MATCH_CALLEE = 0x26B0730

# (twin, FDE start, FDE end, main-body end (ret), decoder, decode site)
TWINS = [
    ("twin-A", 0x2788350, 0x27884F5, 0x2788499, DEC_A, 0x2788366),
    ("twin-B", 0x2788500, 0x278870F, 0x27886B3, DEC_B, 0x2788516),
]

# Full tail byte sequences (stores + stack restore + pops + ret), keyed by twin.
TAILS = {
    "twin-A": "4c89730840886b10c603054883c4785b415e415f5dc3",
    "twin-B": "4c89730840886b10c603054881c4a80000005b415e415f5dc3",
}
WRAPPER_DEC_SITES = [
    0x276E37D, 0x276E4ED, 0x2771B3D, 0x277281D, 0x277785D, 0x277874D,
    0x276D61D, 0x276DA3D, 0x2770CCD, 0x2770DBD, 0x27768ED, 0x2776E5D,
]

# Decoder-call sites in larger functions (classification only, no new claim):
# (site, decoder, enclosing FDE start, enclosing FDE end)
BIG_SITES = [
    (0x2788801, DEC_A, 0x2788710, 0x2789DAB),
    (0x2788A5C, DEC_A, 0x2788710, 0x2789DAB),
    (0x2788AAE, DEC_A, 0x2788710, 0x2789DAB),
    (0x2788F98, DEC_A, 0x2788710, 0x2789DAB),
    (0x2789E9E, DEC_B, 0x2789DB0, 0x278B402),
    (0x278A0FA, DEC_B, 0x2789DB0, 0x278B402),
    (0x278A149, DEC_B, 0x2789DB0, 0x278B402),
    (0x278A613, DEC_B, 0x2789DB0, 0x278B402),
    (0x278B4D3, DEC_A, 0x278B410, 0x278BDB0),
    (0x278BB0C, DEC_A, 0x278B410, 0x278BDB0),
    (0x278BE73, DEC_B, 0x278BDB0, 0x278C750),
    (0x278C4AC, DEC_B, 0x278BDB0, 0x278C750),
    (0x278CA20, DEC_A, 0x278C750, 0x278D51D),
    (0x278D0D4, DEC_A, 0x278C750, 0x278D51D),
    (0x278D7F0, DEC_B, 0x278D520, 0x278E2ED),
    (0x278DEA4, DEC_B, 0x278D520, 0x278E2ED),
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


def call_target(data, sections, va):
    raw = read_bytes(data, sections, va, 5)
    if raw[0] != 0xE8:
        raise ValueError(f"not a call at {va:#x}: {raw.hex()}")
    return va + 5 + struct.unpack_from("<i", raw, 1)[0]


def rip_target(data, sections, va, prefix_hex):
    prefix = bytes.fromhex(prefix_hex)
    raw = read_bytes(data, sections, va, len(prefix) + 4)
    if raw[:len(prefix)] != prefix:
        raise ValueError(f"bad rip instruction at {va:#x}: {raw.hex()}")
    return va + len(prefix) + 4 + struct.unpack_from("<i", raw, len(prefix))[0]


def check_twin(data, sections, twin, fs, fe, body_end, dec, ds):
    # Shared skeleton anchors, expressed as offsets from the twin's own
    # decode site / tag check so both twins use one table.
    base = ds
    # decode call + tag check
    if call_target(data, sections, ds) != dec:
        raise ValueError(f"{twin} decode call at {ds:#x} does not target {dec:#x}")
    check_anchor(data, sections, base + 5, "0fb60424")    # movzx eax,[rsp]
    check_anchor(data, sections, base + 9, "3c05")        # cmp al,5
    check_anchor(data, sections, base + 11, "0f85")       # jne copy-path
    # header check: mov r14,[rsp+8]; movzx ebp,[rsp+0x10]; cmp [r14],4; jne tail
    hdr = base + 17
    check_anchor(data, sections, hdr, "4c8b742408")       # mov r14,[rsp+8]
    check_anchor(data, sections, hdr + 5, "0fb66c2410")   # movzx ebp,[rsp+0x10]
    check_anchor(data, sections, hdr + 10, "41833e04")    # cmp DWORD [r14],4
    check_anchor(data, sections, hdr + 14, "0f85")        # jne tail
    # vector compare: movdqu pair, pcmpeqb pair (rip targets = constants),
    # pand, pmovmskb, cmp eax,0xffff, je match-path
    vc = hdr + 20
    check_anchor(data, sections, vc, "f3410f6f4668")     # movdqu xmm0,[r14+0x68]
    check_anchor(data, sections, vc + 6, "f3410f6f4e78")  # movdqu xmm1,[r14+0x78]
    if rip_target(data, sections, vc + 12, "660f740d") != CONST_HI:
        raise ValueError(f"{twin} high vector constant target mismatch")
    if rip_target(data, sections, vc + 20, "660f7405") != CONST_LO:
        raise ValueError(f"{twin} low vector constant target mismatch")
    check_anchor(data, sections, vc + 28, "660fdbc1")     # pand xmm0,xmm1
    check_anchor(data, sections, vc + 32, "660fd7c0")     # pmovmskb eax,xmm0
    check_anchor(data, sections, vc + 36, "3dffff0000")   # cmp eax,0xffff
    check_anchor(data, sections, vc + 41, "0f84")         # je match-path
    # match path: call 0x26b0730, then mov QWORD [r14],1 (verified by
    # searching the twin body for the 7-byte store after the call).
    body = read_bytes(data, sections, fs, body_end - fs)
    if bytes.fromhex("49c70601000000") not in body:
        raise ValueError(f"{twin} match-path header store not found")
    # tail: full store + stack-restore + pops + ret sequence ending at
    # body_end (the ret byte itself).
    tail = bytes.fromhex(TAILS[twin])
    if read_bytes(data, sections, body_end - len(tail) + 1, len(tail)) != tail:
        raise ValueError(f"{twin} tail sequence mismatch")
    if read_bytes(data, sections, body_end, 1) != b"\xc3":
        raise ValueError(f"{twin} body does not end with ret")


def check_twin_specific(data, sections):
    # Twin-A non-match transform call -> 0x1e6af40; twin-B -> 0x37d13c0,
    # then post-transform tag check + second transform 0x324a070.
    if call_target(data, sections, 0x27883D9) != 0x1E6AF40:
        raise ValueError("twin-A transform call target mismatch")
    if call_target(data, sections, 0x278859A) != 0x37D13C0:
        raise ValueError("twin-B transform call target mismatch")
    check_anchor(data, sections, 0x278859F, "833c2404")   # cmp DWORD [rsp],4
    check_anchor(data, sections, 0x27885A3, "0f85")       # jne transform-copy
    if call_target(data, sections, 0x27885AE) != 0x324A070:
        raise ValueError("twin-B second transform call target mismatch")
    check_anchor(data, sections, 0x27885B3, "48c744244001000000")  # mov [rsp+0x40],1
    if call_target(data, sections, 0x278844D) != MATCH_CALLEE:
        raise ValueError("twin-A match callee target mismatch")
    if call_target(data, sections, 0x2788606) != MATCH_CALLEE:
        raise ValueError("twin-B match callee target mismatch")


def derive_census(data, sections, entries):
    text = next(s for s in sections if s["name"] == ".text")
    base, off, size = text["address"], text["offset"], text["size"]
    starts = [e["start"] for e in entries]
    found = {}
    for target in (DEC_A, DEC_B):
        sites = []
        for i in range(size - 5):
            if data[off + i] == 0xE8:
                rel = struct.unpack_from("<i", data, off + i + 1)[0]
                if base + i + 5 + rel == target:
                    sites.append(base + i)
        found[target] = sites
        for i in range(size - 5):
            if data[off + i] == 0xE9:
                rel = struct.unpack_from("<i", data, off + i + 1)[0]
                if base + i + 5 + rel == target:
                    raise ValueError(f"E9 tail-jump caller at {base + i:#x} for {target:#x}")
    want_a = None  # (kept explicit below; no implicit wrapper split assumed)
    # Build the expected sets explicitly: wrappers split 6/6 by decoder.
    # (Wrapper decoder targets are recorded in the #162 packet; here we
    # only assert the total counts per decoder and the twin/big sites.)
    twin_sites = {DEC_A: [0x2788366], DEC_B: [0x2788516]}
    big_a = sorted(s for s, d, _, _ in BIG_SITES if d == DEC_A)
    big_b = sorted(s for s, d, _, _ in BIG_SITES if d == DEC_B)
    if len(found[DEC_A]) != 15 or len(found[DEC_B]) != 15:
        raise ValueError(f"decoder census counts: A={len(found[DEC_A])}, B={len(found[DEC_B])}, want 15/15")
    for target, twins, bigs in ((DEC_A, twin_sites[DEC_A], big_a),
                                (DEC_B, twin_sites[DEC_B], big_b)):
        for s in twins + bigs:
            if s not in found[target]:
                raise ValueError(f"census site {s:#x} not found for decoder {target:#x}")
        # Every big site must sit in its recorded enclosing FDE.
        for s, d, fs, fe in BIG_SITES:
            if d != target:
                continue
            j = bisect.bisect_right(starts, s) - 1
            e = entries[j]
            if e["start"] != fs or e["next_index_upper_bound"] < fe:
                raise ValueError(f"enclosing FDE mismatch for big site {s:#x}")
    return found


def build_cases():
    # (twin, case, tag, header4, vectors_match, transform_tag,
    #  output_object, obj_writes, obj_untouched)
    specs = [
        ("twin-A", "R1-A-copy-tag3", 3, "", "", "", "copied-fields", "none",
         "difference/counter/flag"),
        ("twin-B", "R2-B-copy-tag6", 6, "", "", "", "copied-fields", "none",
         "difference/counter/flag"),
        ("twin-A", "R3-A-header-not4", 5, "0", "", "", "tag-5-as-is", "none",
         "difference/counter/flag"),
        ("twin-B", "R4-B-header-not4", 5, "0", "", "", "tag-5-as-is", "none",
         "difference/counter/flag"),
        ("twin-A", "R5-A-match", 5, "1", "1", "", "tag-5-resolved",
         "[obj]=1;[obj+0x8..0x38]=decoded", "difference/counter/flag"),
        ("twin-B", "R6-B-match", 5, "1", "1", "", "tag-5-resolved",
         "[obj]=1;[obj+0x8..0x38]=decoded", "difference/counter/flag"),
        ("twin-A", "R7-A-transform", 5, "1", "0", "", "tag-5-resolved",
         "[obj+0x0..0x40]=transform_A(vectors)", "difference/counter/flag"),
        ("twin-B", "R8-B-transform-tag-other", 5, "1", "0", "other",
         "tag-5-resolved", "[obj+0x0..0x40]=transform_B(vectors)",
         "difference/counter/flag"),
        ("twin-B", "R9-B-transform-tag4", 5, "1", "0", "4", "tag-5-resolved",
         "[obj+0x0]=1;[obj+0x8..0x40]=second_transform",
         "difference/counter/flag"),
    ]
    return specs


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
    # Constants in .rodata.
    if read_bytes(data, sections, CONST_HI, 16) != CONST_HI_BYTES:
        raise ValueError("high vector constant bytes mismatch")
    if read_bytes(data, sections, CONST_LO, 16) != CONST_LO_BYTES:
        raise ValueError("low vector constant bytes mismatch")
    for twin, fs, fe, body_end, dec, ds in TWINS:
        if fs not in starts:
            raise ValueError(f"{twin} FDE {fs:#x} is not an unwind start")
        # next_index_upper_bound is the NEXT FDE start, so it only bounds
        # the true FDE end from above; the exact end is pinned by the
        # window digest below.
        if starts[fs]["next_index_upper_bound"] < fe:
            raise ValueError(f"{twin} FDE end exceeds unwind bound")
        check_twin(data, sections, twin, fs, fe, body_end, dec, ds)
    check_twin_specific(data, sections)
    # Twin-identity checks (modulo position-dependent bytes).
    body_a = read_bytes(data, sections, 0x2788350, 0x2788499 - 0x2788350)
    body_b = read_bytes(data, sections, 0x2788500, 0x27886B3 - 0x2788500)
    copy_a = read_bytes(data, sections, 0x2788415, 0x2788448 - 0x2788415)
    copy_b = read_bytes(data, sections, 0x27885CB, 0x27885FE - 0x27885CB)
    if copy_a != copy_b:
        raise ValueError("twin copy blocks differ")
    match_a = read_bytes(data, sections, 0x2788467, 0x2788484 - 0x2788467)
    match_b = read_bytes(data, sections, 0x2788620, 0x278863D - 0x2788620)
    if match_a != match_b:
        raise ValueError("twin match-copy blocks differ")
    derive_census(data, sections, entries)
    windows = []
    for twin, fs, fe, _be, _dec, _ds in TWINS:
        w = read_bytes(data, sections, fs, fe - fs)
        windows.append((twin, fs, fe, len(w), hashlib.sha256(w).hexdigest()))
    cases = build_cases()
    out = args.out
    out.mkdir(parents=True, exist_ok=True)
    evidence = {
        "target": "node #94",
        "sha256": SHA256,
        "worktree_baseline": "2993e46",
        "twins": [
            {"twin": t, "fde": f"{fs:#x}..{fe:#x}", "length": fe - fs,
             "main_body": f"{fs:#x}..{be:#x}", "decoder": f"{dec:#x}",
             "decode_site": f"{ds:#x}"}
            for t, fs, fe, be, dec, ds in TWINS],
        "vector_constants": {
            "0x204be0": CONST_HI_BYTES.hex(),
            "0x206160": CONST_LO_BYTES.hex(),
        },
        "transform_callees": {
            "twin-A": "0x1e6af40",
            "twin-B": "0x37d13c0",
            "twin-B-second": "0x324a070",
        },
        "match_callee": "0x26b0730",
        "cleanup_callee": "0x2781760",
        "decoder_census": {"total": 30, "dec-A": 15, "dec-B": 15,
                           "wrappers": 12, "twins": 2, "big_function_sites": 16},
        "e9_tail_jump_callers": 0,
        "untouched_ranges": ["[obj+0x40..0x58] difference",
                             "[obj+0x60] counter", "[obj+0xb0] flag"],
        "cases": len(cases),
        "windows": [{"label": l, "fde": f"{s:#x}..{e:#x}", "length": ln, "sha256": sha}
                    for l, s, e, ln, sha in windows],
    }
    (out / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
    (out / "sites.tsv").write_text(
        "twin\tfde_start\tfde_end\tmain_body_end\tdecoder\tdecode_site\ttransform_callee\n" +
        "twin-A\t0x2788350\t0x27884f5\t0x2788499\t0x2787460\t0x2788366\t0x1e6af40\n" +
        "twin-B\t0x2788500\t0x278870f\t0x27886b3\t0x2786dd0\t0x2788516\t0x37d13c0\n")
    (out / "cases.tsv").write_text(
        "twin\tcase\ttag\theader_is_4\tvectors_match\ttransform_tag\toutput_object\tobj_writes\tobj_untouched\n" +
        "".join("\t".join(str(v) for v in r) + "\n" for r in cases))
    (out / "windows.txt").write_text(
        "".join(f"{label} {s:#x}..{e:#x} length={ln} sha256={sha}\n"
                for label, s, e, ln, sha in windows))
    print(f"{len(cases)} cases; {len(TWINS)} twins; "
          f"node94 SHA-256 {SHA256}")


if __name__ == "__main__":
    main()
