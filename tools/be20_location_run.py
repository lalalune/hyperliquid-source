#!/usr/bin/env python3
"""Deterministic generator for RE-004 be20 location run (node #94).

Verifies the node digest/size first, then checks every recorded byte
against the binary: the 26 Location records (.data.rel.ro, VA-0x2000),
their RELATIVE relocations (.rela.dyn entries are 24 bytes at file
offset 0x6bc0), the .rodata file-path strings, the 35 lea site
instruction bytes (.text, VA-0x1000, disp32 resolving to the entry),
and the 6 GOT slot resolutions. Writes only to --out. No node
execution, no disassembler, no network.
"""

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

NODE_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
NODE_SIZE = 91774280
ROOT = Path(__file__).resolve().parents[1]
NODE = ROOT / "artifacts" / "node" / "94" / "hl-node"

PREFIX = "/home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/"
# (entry, va, file_suffix, line, col, reloc_index, reloc_addend)
LOCATIONS = [
    (0, 0x574BF38, "revm-19.2.0/src/handler/mainnet/pre_execution.rs", 65, 44, 61887, 0x1E3EC3),
    (1, 0x574BF50, "revm-19.2.0/src/handler/mainnet/pre_execution.rs", 178, 9, 61888, 0x1E3EC3),
    (2, 0x574BF68, "revm-19.2.0/src/handler/mainnet/pre_execution.rs", 157, 13, 61889, 0x1E3EC3),
    (3, 0x574BF80, "ruint-1.12.3/src/algorithms/mul.rs", 113, 23, 61890, 0x1EF49B),
    (4, 0x574BF98, "revm-19.2.0/src/journaled_state.rs", 332, 45, 61891, 0x1E3A8C),
    (5, 0x574BFB0, "revm-19.2.0/src/journaled_state.rs", 347, 59, 61892, 0x1E3A8C),
    (6, 0x574BFC8, "revm-19.2.0/src/journaled_state.rs", 360, 61, 61893, 0x1E3A8C),
    (7, 0x574BFE0, "revm-19.2.0/src/journaled_state.rs", 339, 45, 61894, 0x1E3A8C),
    (8, 0x574BFF8, "revm-19.2.0/src/journaled_state.rs", 366, 53, 61895, 0x1E3A8C),
    (9, 0x574C010, "revm-19.2.0/src/journaled_state.rs", 368, 49, 61896, 0x1E3A8C),
    (10, 0x574C028, "revm-19.2.0/src/journaled_state.rs", 372, 45, 61897, 0x1E3A8C),
    (11, 0x574C040, "revm-19.2.0/src/journaled_state.rs", 372, 21, 61898, 0x1E3A8C),
    (12, 0x574C058, "revm-19.2.0/src/journaled_state.rs", 375, 64, 61899, 0x1E3A8C),
    (13, 0x574C070, "revm-19.2.0/src/journaled_state.rs", 399, 26, 61900, 0x1E3A8C),
    (14, 0x574C088, "revm-19.2.0/src/journaled_state.rs", 402, 26, 61901, 0x1E3A8C),
    (15, 0x574C0A0, "revm-19.2.0/src/journaled_state.rs", 386, 26, 61902, 0x1E3A8C),
    (16, 0x574C0B8, "revm-19.2.0/src/journaled_state.rs", 389, 26, 61903, 0x1E3A8C),
    (17, 0x574C0D0, "revm-19.2.0/src/journaled_state.rs", 420, 55, 61904, 0x1E3A8C),
    (18, 0x574C0E8, "ruint-1.12.3/src/bits.rs", 296, 42, 61905, 0x1EB6F4),
    (19, 0x574C100, "revm-interpreter-15.0.0/src/interpreter/shared_memory.rs", 268, 28, 61906, 0x200B23),
    (20, 0x574C118, "revm-interpreter-15.0.0/src/interpreter/shared_memory.rs", 277, 50, 61907, 0x200B23),
    (21, 0x574C130, "revm-interpreter-15.0.0/src/interpreter/shared_memory.rs", 171, 19, 61908, 0x200B23),
    (22, 0x574C148, "revm-interpreter-15.0.0/src/interpreter/shared_memory.rs", 117, 9, 61909, 0x200B23),
    (23, 0x574C160, "revm-interpreter-15.0.0/src/instructions/system.rs", 175, 59, 61910, 0x1FD479),
    (24, 0x574C178, "revm-interpreter-15.0.0/src/instructions/system.rs", 175, 44, 61911, 0x1FD479),
    (25, 0x574C190, "revm-interpreter-15.0.0/src/interpreter/shared_memory.rs", 146, 34, 61912, 0x200B23),
]
# (site, entry, reg, follow, got_or_cont)
SITES = [
    (0x4E77E70, 0, "rdx", "indirect", 0x576E468),
    (0x4E7851F, 1, "rdi", "indirect", 0x576E1B0),
    (0x4E7852C, 2, "rdi", "indirect", 0x576E118),
    (0x4E78A87, 3, "rcx", "indirect", 0x576E2E0),
    (0x4E7A441, 4, "rdi", "jmp-cont", 0x4E7A4BD),
    (0x4E7A44A, 5, "rdi", "jmp-cont", 0x4E7A4BD),
    (0x4E7A4B6, 6, "rdi", "fallthrough-cont", 0x4E7A4BD),
    (0x4E7A4AD, 7, "rdi", "jmp-cont", 0x4E7A4BD),
    (0x4E7A453, 8, "rdi", "jmp-cont", 0x4E7A4BD),
    (0x4E7A492, 9, "rdi", "jmp-cont", 0x4E7A4BD),
    (0x4E7A489, 10, "rdi", "jmp-cont", 0x4E7A4BD),
    (0x4E7A4CE, 11, "rdi", "indirect", 0x576E150),
    (0x4E7A46E, 12, "rdi", "jmp-cont", 0x4E7A4BD),
    (0x4E7A477, 13, "rdi", "jmp-cont", 0x4E7A4BD),
    (0x4E7A49B, 14, "rdi", "jmp-cont", 0x4E7A4BD),
    (0x4E7A480, 15, "rdi", "jmp-cont", 0x4E7A4BD),
    (0x4E7A4A4, 16, "rdi", "jmp-cont", 0x4E7A4BD),
    (0x4E7A465, 17, "rdi", "jmp-cont", 0x4E7A4C6),
    (0x4E79AEE, 18, "rdi", "indirect", 0x576E150),
    (0x4E7A5EA, 19, "rdi", "indirect", 0x576E118),
    (0x4E7A819, 19, "rdi", "indirect", 0x576E118),
    (0x4E7B0AE, 19, "rdi", "indirect", 0x576E118),
    (0x4E7A5F7, 20, "rdi", "indirect", 0x576E150),
    (0x4E7A826, 20, "rdi", "indirect", 0x576E150),
    (0x4E7B0BB, 20, "rdi", "indirect", 0x576E150),
    (0x4E7A5DD, 21, "rdi", "indirect", 0x576E118),
    (0x4E7A7FF, 21, "rdi", "indirect", 0x576E118),
    (0x4E7B094, 21, "rdi", "indirect", 0x576E118),
    (0x4E7A80C, 22, "rdi", "indirect", 0x576E150),
    (0x4E7AB2E, 22, "rdi", "indirect", 0x576E150),
    (0x4E7B0A1, 22, "rdi", "indirect", 0x576E150),
    (0x4E7B475, 22, "rdi", "indirect", 0x576E150),
    (0x4E7AC5E, 23, "rdi", "indirect", 0x576E118),
    (0x4E7AC4B, 24, "rcx", "indirect", 0x576E2E0),
    (0x4E7B482, 25, "rdi", "indirect", 0x576E118),
]
# GOT slot -> resolved runtime address (RELATIVE reloc addend)
GOT = {
    0x576E118: 0x157B480,
    0x576E150: 0x157B520,
    0x576E1B0: 0x157B4A0,
    0x576E2E0: 0x157A6F0,
    0x576E468: 0x157A9B0,
    0x576E470: 0x157A9F0,
}
# runtime helper -> (message .rodata ptr, recorded length, exact prefix bytes)
MSG = {
    0x157B480: (0x252CF8, 57, b"attempt to add with overflow"),
    0x157B520: (0x252D9B, 67, b"attempt to subtract with overflow"),
    0x157B4A0: (0x252D14, 67, b"attempt to multiply with overflow"),
    0x157A9F0: (0x256638, 43, b"called `Option::unwrap()` on a `None` value"),
}
RELA_OFF = 0x6BC0
MODRM = {"rdi": 0x3D, "rdx": 0x15, "rcx": 0x0D}


def fail(msg):
    print(f"be20_location_run: FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    data = NODE.read_bytes()
    if len(data) != NODE_SIZE:
        fail(f"node size {len(data)} != {NODE_SIZE}")
    if hashlib.sha256(data).hexdigest() != NODE_SHA256:
        fail("node digest mismatch")

    def datarelro(va, n):
        return data[va - 0x2000: va - 0x2000 + n]

    def text(va, n):
        return data[va - 0x1000: va - 0x1000 + n]

    def rela(idx):
        off, info, add = struct.unpack_from("<QQq", data, RELA_OFF + idx * 24)
        return off, info, add

    loc_rows = []
    seg_rows = []
    for (idx, va, suffix, line, col, ridx, addend) in LOCATIONS:
        raw = datarelro(va, 24)
        slot, flen, fline, fcol = struct.unpack("<QQII", raw)
        full = PREFIX + suffix
        if slot != 0:
            fail(f"entry {idx}: reloc slot file value {slot} != 0")
        if flen != len(full):
            fail(f"entry {idx}: length {flen} != {len(full)}")
        if (fline, fcol) != (line, col):
            fail(f"entry {idx}: line/col {(fline, fcol)} != {(line, col)}")
        if data[addend: addend + len(full)].decode() != full:
            fail(f"entry {idx}: .rodata string mismatch")
        roff, rinfo, radd = rela(ridx)
        if roff != va or (rinfo & 0xFFFFFFFF) != 8 or radd != addend:
            fail(f"entry {idx}: reloc {ridx} mismatch")
        loc_rows.append(
            f"{idx}\t{va:#x}\t{full}\t{line}\t{col}\t{len(full)}\t{ridx}\t{addend:#x}"
        )
        seg_rows.append(
            f"loc{idx}\t{va:#x}\t{va + 0x18:#x}\t24\t{va - 0x2000:#x}\t"
            f"{hashlib.sha256(raw).hexdigest()}\tclaim"
        )
        if va != LOCATIONS[0][1] + idx * 0x18:
            fail(f"entry {idx}: not contiguous at 0x18 stride")

    site_rows = []
    entry_va = {idx: va for (idx, va, *_rest) in LOCATIONS}
    for (site, entry, reg, follow, target) in SITES:
        raw = text(site, 7)
        if raw[0:2] != b"\x48\x8d" or raw[2] != MODRM[reg]:
            fail(f"site {site:#x}: lea bytes {raw.hex()} do not match reg {reg}")
        disp = struct.unpack("<i", raw[3:7])[0]
        if site + 7 + disp != entry_va[entry]:
            fail(f"site {site:#x}: disp32 resolves to {site + 7 + disp:#x}")
        site_rows.append(f"{site:#x}\t{entry}\t{reg}\t{follow}\t{target:#x}")

    # GOT resolutions: find each slot's RELATIVE reloc by scanning .rela.dyn
    # offsets (bounded scan; entries are 24 bytes).
    got_found = {}
    n_rela = 0x1D4E10 // 24
    for i in range(n_rela):
        off, info, add = rela(i)
        if off in GOT and (info & 0xFFFFFFFF) == 8:
            got_found[off] = add
    for slot, want in GOT.items():
        if got_found.get(slot) != want:
            fail(f"GOT {slot:#x} resolves to {got_found.get(slot)} != {want:#x}")

    for helper, (ptr, ln, prefix) in MSG.items():
        span = data[ptr: ptr + ln]
        if not span.startswith(prefix):
            fail(f"helper {helper:#x}: message span mismatch")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "locations.tsv").write_text(
        "entry\tva\tfile\tline\tcol\tfile_len\treloc_index\treloc_addend\n"
        + "\n".join(loc_rows) + "\n"
    )
    (out / "sites.tsv").write_text(
        "site\tentry\treg\tfollow\ttarget\n" + "\n".join(site_rows) + "\n"
    )
    (out / "segments.txt").write_text("\n".join(seg_rows) + "\n")
    evidence = {
        "node": {"id": 94, "size": NODE_SIZE, "sha256": NODE_SHA256},
        "run": {"start": f"{LOCATIONS[0][1]:#x}", "end": f"{LOCATIONS[-1][1] + 0x18:#x}",
                "entries": len(LOCATIONS), "stride": 0x18, "claim_bytes": len(LOCATIONS) * 24,
                "reloc_indices": [LOCATIONS[0][5], LOCATIONS[-1][5]]},
        "sites": {"total": len(SITES),
                  "registers": {"rdi": 32, "rdx": 1, "rcx": 2},
                  "indirect": 22, "continuation": 13},
        "got": {f"{k:#x}": f"{v:#x}" for k, v in GOT.items()},
        "segments": {"claim": len(seg_rows), "claim_bytes": len(seg_rows) * 24, "anchors": 0},
    }
    (out / "evidence.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print(f"be20_location_run: OK ({len(seg_rows)} segments)")


if __name__ == "__main__":
    main()
