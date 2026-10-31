#!/usr/bin/env python3
"""RE-020: 0x22ae8a0 path-field layout + 0x4546ba0 GOT thunk census (node #94).

Standalone. From the pinned node #94 binary only, it recovers:
  * FDE 0x22ae8a0..0x22b1080 and the four ff15 sites through GOT 0x5773c70;
  * the DIFFERENT path-pointer source at each site (+0xd0, +0x140, +0x220, r15);
  * GOT slot 0x5773c70 RELATIVE addend 0x4546ba0 (thin thunk);
  * thunk FDE 0x4546ba0..0x4546c60: preserves rsi/rdx, injects Location into rcx,
    redirects rdi to a local out buffer, then e8 to 0x3c155a0;
  * call census: exactly 4 ff15 through 0x5773c70 across .text/.init/.fini/.plt;
    exactly 0 direct e8 to 0x4546ba0.
Does NOT claim which filename or format each path field holds.
Output is sorted, deterministic JSON. Every expected value is pinned exactly.
Imports only the Python standard library (no objdump, no pyelftools).
"""
import argparse
import bisect
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "artifacts" / "node" / "94" / "hl-node"
BINARY_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"

FDE_A = 0x22ae8a0
FDE_A_END = 0x22b1080
FDE_B = 0x4546ba0
FDE_B_END = 0x4546c60
GOT_SLOT = 0x5773c70
LOADER = 0x3c155a0
LOCATION = 0x56dfc28
SCAN_SECTIONS = (".fini", ".init", ".plt", ".text")

# Four ff15 sites inside FDE A through GOT_SLOT, with path-pointer sources.
FF15_SITES = (0x22aec0f, 0x22aee86, 0x22aef33, 0x22afc2c)

KEY_INSNS = [
    # site1: path ptr from [rbp+0xd0]
    (0x22aebc6, "488bb5d0000000", "site1 mov rsi,[rbp+0xd0] path ptr"),
    (0x22aebcd, "488b95d8000000", "site1 mov rdx,[rbp+0xd8] path len"),
    (0x22aec02, "488dbc24f0010000", "site1 lea rdi,[rsp+0x1f0] out"),
    (0x22aec0f, "ff155b504c03", "site1 ff15 [0x5773c70]"),
    # site2: path ptr from [rbp+0x140]
    (0x22aee6e, "488bb540010000", "site2 mov rsi,[rbp+0x140] path ptr"),
    (0x22aee75, "488b9548010000", "site2 mov rdx,[rbp+0x148] path len"),
    (0x22aee7c, "488d9d50020000", "site2 lea rbx,[rbp+0x250]"),
    (0x22aee83, "4889df", "site2 mov rdi,rbx out"),
    (0x22aee86, "ff15e44d4c03", "site2 ff15 [0x5773c70]"),
    # site3: path ptr from [rbp+0x220]
    (0x22aef22, "488bb520020000", "site3 mov rsi,[rbp+0x220] path ptr"),
    (0x22aef29, "488d9d30020000", "site3 lea rbx,[rbp+0x230]"),
    (0x22aef30, "4889df", "site3 mov rdi,rbx out"),
    (0x22aef33, "ff15374d4c03", "site3 ff15 [0x5773c70]"),
    # site4: path ptr from r15
    (0x22afbf5, "4c8bbdd0000000", "site4 mov r15,[rbp+0xd0] (r15 source filled)"),
    (0x22afbfc, "488b95d8000000", "site4 mov rdx,[rbp+0xd8] path len"),
    (0x22afc21, "488dbc24f0010000", "site4 lea rdi,[rsp+0x1f0] out"),
    (0x22afc29, "4c89fe", "site4 mov rsi,r15 path ptr"),
    (0x22afc2c, "ff153e404c03", "site4 ff15 [0x5773c70]"),
    # thunk 0x4546ba0
    (0x4546ba0, "4157415653", "thunk push r15,r14,rbx"),
    (0x4546ba5, "4881ec00100000", "thunk sub rsp,0x1000"),
    (0x4546bac, "48c7042400000000", "thunk mov qword [rsp],0"),
    (0x4546bb4, "4881ecd00f0000", "thunk sub rsp,0xfd0"),
    (0x4546bbb, "4889fb", "thunk mov rbx,rdi save caller out"),
    (0x4546bbe, "488d0d63901901", "thunk lea rcx, Location 0x56dfc28"),
    (0x4546bc5, "488d7c2408", "thunk lea rdi,[rsp+8] local out"),
    (0x4546bca, "e8d1e96cff", "thunk e8 0x3c155a0 (rsi/rdx preserved)"),
]

PATH_SOURCES = {
    "0x22aec0f": {"path_ptr_source": "[rbp+0xd0]", "path_ptr_load_va": "0x22aebc6",
                 "path_len_source": "[rbp+0xd8]", "path_len_load_va": "0x22aebcd"},
    "0x22aee86": {"path_ptr_source": "[rbp+0x140]", "path_ptr_load_va": "0x22aee6e",
                 "path_len_source": "[rbp+0x148]", "path_len_load_va": "0x22aee75"},
    "0x22aef33": {"path_ptr_source": "[rbp+0x220]", "path_ptr_load_va": "0x22aef22",
                 "path_len_source": "rdx (held from earlier [rbp+0xd8] copy into [rbp+0x228])",
                 "path_len_note": "rdx not reloaded immediately before call; pin is path-ptr only"},
    "0x22afc2c": {"path_ptr_source": "r15", "path_ptr_load_va": "0x22afc29",
                 "path_len_source": "[rbp+0xd8]", "path_len_load_va": "0x22afbfc",
                 "r15_filled_from": "[rbp+0xd0]", "r15_fill_va": "0x22afbf5"},
}

LOCATIONS = {
    "0x56dfc28": {
        "file": "/home/ubuntu/hl/code_Mainnet/l1/src/abci/state.rs",
        "file_ptr": "0x1dd8eb",
        "length": 49,
        "line": 86,
        "column": 40,
    },
}

THUNK_ABI = {
    "preserves": ["rsi", "rdx"],
    "injects_rcx": "Location 0x56dfc28",
    "redirects_rdi": "lea rdi,[rsp+8] local out; caller rdi saved in rbx",
    "forwards_to": "0x3c155a0",
}

EXTENT_A_SHA256 = "50478e148269fa470c6dd5aae4856b72c729cf49f0c9f3b38cc755ed62fcb9c4"
EXTENT_B_SHA256 = "a70030129ce619628e734791f5c998483c7b9f622bbf973432cf60253351add4"

TARGETS = {
    "0x22aec0f": "0x5773c70",
    "0x22aee86": "0x5773c70",
    "0x22aef33": "0x5773c70",
    "0x22afc2c": "0x5773c70",
    "0x4546bbe": "0x56dfc28",
    "0x4546bca": "0x3c155a0",
}

EXPECT = {
    "binary_sha256": BINARY_SHA256,
    "fde_a": hex(FDE_A),
    "fde_a_end": hex(FDE_A_END),
    "fde_a_extent_sha256": EXTENT_A_SHA256,
    "fde_a_extent_len": FDE_A_END - FDE_A,
    "fde_b": hex(FDE_B),
    "fde_b_end": hex(FDE_B_END),
    "fde_b_extent_sha256": EXTENT_B_SHA256,
    "fde_b_extent_len": FDE_B_END - FDE_B,
    "got_slot": hex(GOT_SLOT),
    "got_addend": hex(FDE_B),
    "ff15_sites": [hex(s) for s in FF15_SITES],
    "ff15_count": len(FF15_SITES),
    "e8_direct_to_thunk_count": 0,
    "key_insns": len(KEY_INSNS),
    "locations": LOCATIONS,
    "path_sources": PATH_SOURCES,
    "thunk_abi": THUNK_ABI,
}


def segments(data):
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise ValueError("not an ELF64 little-endian file")
    phoff, = struct.unpack_from("<Q", data, 0x20)
    phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
    out = []
    for i in range(phnum):
        t, _f, off, va, _p, fs, _m, _a = struct.unpack_from("<IIQQQQQQ", data, phoff + i * phentsize)
        if t == 1:
            out.append((va, off, fs))
    return out


def at(data, segs, va, n):
    for base, off, size in segs:
        if base <= va and va + n <= base + size:
            return bytes(data[off + va - base: off + va - base + n])
    raise KeyError(hex(va))


def shdrs(data):
    shoff, = struct.unpack_from("<Q", data, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3a)
    sh = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize) for i in range(shnum)]
    stroff = sh[shstrndx][4]
    for h in sh:
        name = bytes(data[stroff + h[0]: stroff + h[0] + 24]).split(b"\0", 1)[0]
        yield name, h


def section_map(data):
    return {name: h for name, h in shdrs(data)}


def fde_next_start(data, segs, va):
    secs = section_map(data)
    h = secs[b".eh_frame_hdr"]
    o, a = h[4], h[3]
    if tuple(data[o + 1:o + 4]) != (0x1b, 0x03, 0x3b):
        raise ValueError("eh_frame_hdr encodings")
    n, = struct.unpack_from("<I", data, o + 8)
    tab = [struct.unpack_from("<ii", data, o + 12 + 8 * i) for i in range(n)]
    starts = [a + x for x, _ in tab]
    i = starts.index(va)
    return starts[i + 1]


def decode_target(va, hx):
    b = bytes.fromhex(hx)
    if b[0] == 0xe8 and len(b) == 5:
        disp, = struct.unpack_from("<i", b, 1)
        return va + 5 + disp
    if b[0] == 0xff and b[1] == 0x15 and len(b) == 6:
        disp, = struct.unpack_from("<i", b, 2)
        return va + 6 + disp
    if b[:3] in (b"\x48\x8d\x05", b"\x48\x8d\x35", b"\x48\x8d\x0d"):
        disp, = struct.unpack_from("<i", b, 3)
        return va + len(b) + disp
    return None


def read_location(data, segs, loc_va):
    secs = section_map(data)
    h = secs[b".rela.dyn"]
    n = h[5] // 24
    addend = None
    for i in range(n):
        o = h[4] + i * 24
        r_offset, r_info, r_addend = struct.unpack_from("<QQq", data, o)
        if r_offset == loc_va and (r_info & 0xffffffff) == 8:
            addend = r_addend
            break
    if addend is None:
        raise KeyError("no RELATIVE for " + hex(loc_va))
    length, = struct.unpack_from("<Q", at(data, segs, loc_va, 24), 8)
    line, col = struct.unpack_from("<II", at(data, segs, loc_va, 24), 16)
    path = at(data, segs, addend, length).decode()
    return {
        "file": path,
        "file_ptr": hex(addend),
        "length": length,
        "line": line,
        "column": col,
    }


def got_relative_addend(data, got_va):
    secs = section_map(data)
    h = secs[b".rela.dyn"]
    n = h[5] // 24
    for i in range(n):
        o = h[4] + i * 24
        r_offset, r_info, r_addend = struct.unpack_from("<QQq", data, o)
        if r_offset == got_va and (r_info & 0xffffffff) == 8:
            return r_addend
    raise KeyError("no RELATIVE for GOT " + hex(got_va))


def ff15_scan(data, slot):
    secs = section_map(data)
    found = []
    for name in SCAN_SECTIONS:
        h = secs[name.encode()]
        va, off, size = h[3], h[4], h[5]
        blob = data[off:off + size]
        for i in range(len(blob) - 5):
            if blob[i] != 0xff or blob[i + 1] != 0x15:
                continue
            disp, = struct.unpack_from("<i", blob, i + 2)
            site = va + i
            if site + 6 + disp == slot:
                found.append(site)
    return sorted(found)


def e8_scan(data, target):
    secs = section_map(data)
    found = []
    for name in SCAN_SECTIONS:
        h = secs[name.encode()]
        va, off, size = h[3], h[4], h[5]
        blob = data[off:off + size]
        for i in range(len(blob) - 4):
            if blob[i] != 0xe8:
                continue
            disp, = struct.unpack_from("<i", blob, i + 1)
            site = va + i
            if site + 5 + disp == target:
                found.append(site)
    return sorted(found)


def analyse(data, check_sha=True):
    if check_sha and hashlib.sha256(data).hexdigest() != BINARY_SHA256:
        raise ValueError("binary sha256 mismatch")
    segs = segments(data)
    end_a = fde_next_start(data, segs, FDE_A)
    if end_a != FDE_A_END:
        raise ValueError("FDE A end %s != %s" % (hex(end_a), hex(FDE_A_END)))
    end_b = fde_next_start(data, segs, FDE_B)
    if end_b != FDE_B_END:
        raise ValueError("FDE B end %s != %s" % (hex(end_b), hex(FDE_B_END)))
    ext_a = at(data, segs, FDE_A, FDE_A_END - FDE_A)
    ext_b = at(data, segs, FDE_B, FDE_B_END - FDE_B)
    sha_a = hashlib.sha256(ext_a).hexdigest()
    sha_b = hashlib.sha256(ext_b).hexdigest()
    keys = {}
    for va, hx, role in KEY_INSNS:
        got = at(data, segs, va, len(hx) // 2)
        if got.hex() != hx:
            raise ValueError("key mismatch at %s: %s != %s" % (hex(va), got.hex(), hx))
        keys[hex(va)] = {"bytes": hx, "role": role}
    targets = {}
    for va, hx, _role in KEY_INSNS:
        t = decode_target(va, hx)
        if t is not None:
            targets[hex(va)] = hex(t)
    locs = {k: read_location(data, segs, int(k, 16)) for k in LOCATIONS}
    got_addend = got_relative_addend(data, GOT_SLOT)
    if got_addend != FDE_B:
        raise ValueError("GOT addend %s != %s" % (hex(got_addend), hex(FDE_B)))
    ff15 = ff15_scan(data, GOT_SLOT)
    e8s = e8_scan(data, FDE_B)
    # Confirm each ff15 site is inside FDE A
    for s in ff15:
        if not (FDE_A <= s < FDE_A_END):
            raise ValueError("ff15 site %s outside FDE A" % hex(s))
    return {
        "binary_sha256": BINARY_SHA256,
        "fde_a": hex(FDE_A),
        "fde_a_end": hex(FDE_A_END),
        "fde_a_extent_sha256": sha_a,
        "fde_a_extent_len": FDE_A_END - FDE_A,
        "fde_b": hex(FDE_B),
        "fde_b_end": hex(FDE_B_END),
        "fde_b_extent_sha256": sha_b,
        "fde_b_extent_len": FDE_B_END - FDE_B,
        "got_slot": hex(GOT_SLOT),
        "got_addend": hex(got_addend),
        "ff15_sites": [hex(s) for s in ff15],
        "ff15_count": len(ff15),
        "e8_direct_to_thunk": [hex(s) for s in e8s],
        "e8_direct_to_thunk_count": len(e8s),
        "key_bytes": keys,
        "targets": targets,
        "locations": locs,
        "path_sources": PATH_SOURCES,
        "thunk_abi": THUNK_ABI,
        "key_insns": len(KEY_INSNS),
        "non_claims": [
            "which filename or format string each path field (+0xd0/+0x140/+0x220/r15) holds",
            "who writes the path fields at +0xd0/+0x140/+0x220",
            "runtime behaviour of the loader at 0x3c155a0 (see RE-019)",
            "the meaning of other GOT slots near 0x5773c70",
        ],
    }


def expectation_errors(result):
    errs = []
    for k, v in EXPECT.items():
        if k == "locations":
            if result.get("locations") != v:
                errs.append("locations mismatch")
            continue
        if k == "path_sources":
            if result.get("path_sources") != v:
                errs.append("path_sources mismatch")
            continue
        if k == "thunk_abi":
            if result.get("thunk_abi") != v:
                errs.append("thunk_abi mismatch")
            continue
        if result.get(k) != v:
            errs.append("%s: got %r want %r" % (k, result.get(k), v))
    if result.get("targets") != TARGETS:
        # only require the pinned TARGETS keys
        for tk, tv in TARGETS.items():
            if result.get("targets", {}).get(tk) != tv:
                errs.append("target %s: got %r want %r" % (tk, result.get("targets", {}).get(tk), tv))
    if len(result.get("key_bytes", {})) != len(KEY_INSNS):
        errs.append("key_bytes count")
    return errs


def render(result):
    # Deterministic sorted JSON
    return json.dumps(result, sort_keys=True, indent=2) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args(argv)
    data = TARGET.read_bytes()
    result = analyse(data)
    errs = expectation_errors(result)
    if errs:
        for e in errs:
            print("FAIL", e, file=sys.stderr)
        return 1
    text = render(result)
    if args.out:
        args.out.write_text(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
