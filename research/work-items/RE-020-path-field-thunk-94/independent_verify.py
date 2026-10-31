#!/usr/bin/env python3
"""RE-020 independent verifier. Imports nothing from tools/.

Checks every key VA byte by byte against the pinned node #94 binary, re-derives
each ff15/e8/LEA target, re-runs the ff15 census over .text/.init/.fini/.plt with
its own code, checks the GOT RELATIVE addend and Location record, and checks the
packet JSON against MANIFEST.sha256. Prints PASS, FAIL or INCONCLUSIVE; exit 0, 1 or 2.
"""
import hashlib
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BINARY = ROOT / "artifacts" / "node" / "94" / "hl-node"
SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
PACKET_JSON = HERE / "path-field-thunk.json"
FDE_A = 0x22ae8a0
FDE_A_END = 0x22b1080
FDE_B = 0x4546ba0
FDE_B_END = 0x4546c60
EXTENT_A_SHA256 = "50478e148269fa470c6dd5aae4856b72c729cf49f0c9f3b38cc755ed62fcb9c4"
EXTENT_B_SHA256 = "a70030129ce619628e734791f5c998483c7b9f622bbf973432cf60253351add4"
GOT_SLOT = 0x5773c70
FF15_SITES = [0x22aec0f, 0x22aee86, 0x22aef33, 0x22afc2c]
SCAN = (b".text\0", b".init\0", b".fini\0", b".plt\0")

KEYS = [
    (0x22aebc6, "488bb5d0000000"),
    (0x22aebcd, "488b95d8000000"),
    (0x22aec02, "488dbc24f0010000"),
    (0x22aec0f, "ff155b504c03"),
    (0x22aee6e, "488bb540010000"),
    (0x22aee75, "488b9548010000"),
    (0x22aee7c, "488d9d50020000"),
    (0x22aee83, "4889df"),
    (0x22aee86, "ff15e44d4c03"),
    (0x22aef22, "488bb520020000"),
    (0x22aef29, "488d9d30020000"),
    (0x22aef30, "4889df"),
    (0x22aef33, "ff15374d4c03"),
    (0x22afbf5, "4c8bbdd0000000"),
    (0x22afbfc, "488b95d8000000"),
    (0x22afc21, "488dbc24f0010000"),
    (0x22afc29, "4c89fe"),
    (0x22afc2c, "ff153e404c03"),
    (0x4546ba0, "4157415653"),
    (0x4546ba5, "4881ec00100000"),
    (0x4546bac, "48c7042400000000"),
    (0x4546bb4, "4881ecd00f0000"),
    (0x4546bbb, "4889fb"),
    (0x4546bbe, "488d0d63901901"),
    (0x4546bc5, "488d7c2408"),
    (0x4546bca, "e8d1e96cff"),
]

TARGETS = {
    0x22aec0f: 0x5773c70,
    0x22aee86: 0x5773c70,
    0x22aef33: 0x5773c70,
    0x22afc2c: 0x5773c70,
    0x4546bbe: 0x56dfc28,
    0x4546bca: 0x3c155a0,
}


def segments(data):
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


def section_blobs(data):
    shoff, = struct.unpack_from("<Q", data, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3a)
    sh = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize) for i in range(shnum)]
    stroff = sh[shstrndx][4]
    out = {}
    for h in sh:
        name = bytes(data[stroff + h[0]: stroff + h[0] + 24]).split(b"\0", 1)[0] + b"\0"
        out[name] = (h[3], h[4], h[5])
    return out


def fde_next(data, segs, va):
    secs = section_blobs(data)
    h = secs[b".eh_frame_hdr\0"]
    # need section header fields: reuse via raw
    shoff, = struct.unpack_from("<Q", data, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3a)
    sh = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize) for i in range(shnum)]
    stroff = sh[shstrndx][4]
    hdr = None
    for h in sh:
        name = bytes(data[stroff + h[0]: stroff + h[0] + 24]).split(b"\0", 1)[0]
        if name == b".eh_frame_hdr":
            hdr = h
            break
    o, a = hdr[4], hdr[3]
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
    if b[:3] == b"\x48\x8d\x0d":
        disp, = struct.unpack_from("<i", b, 3)
        return va + 7 + disp
    return None


def check_keys(data, check_sha=True, census=True, locations=True, extent=True):
    errs = []
    if check_sha and hashlib.sha256(data).hexdigest() != SHA256:
        errs.append("binary sha256")
        return errs
    segs = segments(data)
    for va, hx in KEYS:
        got = at(data, segs, va, len(hx) // 2)
        if got.hex() != hx:
            errs.append("key %s" % hex(va))
        t = decode_target(va, hx)
        if va in TARGETS and t != TARGETS[va]:
            errs.append("target %s" % hex(va))
    if extent:
        end_a = fde_next(data, segs, FDE_A)
        end_b = fde_next(data, segs, FDE_B)
        if end_a != FDE_A_END:
            errs.append("fde_a_end")
        if end_b != FDE_B_END:
            errs.append("fde_b_end")
        if hashlib.sha256(at(data, segs, FDE_A, FDE_A_END - FDE_A)).hexdigest() != EXTENT_A_SHA256:
            errs.append("extent_a")
        if hashlib.sha256(at(data, segs, FDE_B, FDE_B_END - FDE_B)).hexdigest() != EXTENT_B_SHA256:
            errs.append("extent_b")
    if census:
        secs = section_blobs(data)
        found = []
        for name in SCAN:
            if name not in secs:
                continue
            va, off, size = secs[name]
            blob = data[off:off + size]
            for i in range(len(blob) - 5):
                if blob[i] != 0xff or blob[i + 1] != 0x15:
                    continue
                disp, = struct.unpack_from("<i", blob, i + 2)
                site = va + i
                if site + 6 + disp == GOT_SLOT:
                    found.append(site)
        if found != FF15_SITES:
            errs.append("ff15_census")
        # e8 direct to thunk must be 0
        e8s = []
        for name in SCAN:
            if name not in secs:
                continue
            va, off, size = secs[name]
            blob = data[off:off + size]
            for i in range(len(blob) - 4):
                if blob[i] != 0xe8:
                    continue
                disp, = struct.unpack_from("<i", blob, i + 1)
                site = va + i
                if site + 5 + disp == FDE_B:
                    e8s.append(site)
        if e8s:
            errs.append("e8_direct")
    if locations:
        # GOT reloc
        shoff, = struct.unpack_from("<Q", data, 0x28)
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3a)
        sh = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize) for i in range(shnum)]
        stroff = sh[shstrndx][4]
        rela = None
        for h in sh:
            name = bytes(data[stroff + h[0]: stroff + h[0] + 24]).split(b"\0", 1)[0]
            if name == b".rela.dyn":
                rela = h
                break
        addend = None
        n = rela[5] // 24
        for i in range(n):
            o = rela[4] + i * 24
            r_offset, r_info, r_addend = struct.unpack_from("<QQq", data, o)
            if r_offset == GOT_SLOT and (r_info & 0xffffffff) == 8:
                addend = r_addend
                break
        if addend != FDE_B:
            errs.append("got_addend")
        # Location 0x56dfc28
        loc_va = 0x56dfc28
        loc_addend = None
        for i in range(n):
            o = rela[4] + i * 24
            r_offset, r_info, r_addend = struct.unpack_from("<QQq", data, o)
            if r_offset == loc_va and (r_info & 0xffffffff) == 8:
                loc_addend = r_addend
                break
        if loc_addend != 0x1dd8eb:
            errs.append("loc_addend")
        blob = at(data, segs, loc_va, 24)
        length, = struct.unpack_from("<Q", blob, 8)
        line, col = struct.unpack_from("<II", blob, 16)
        if (length, line, col) != (49, 86, 40):
            errs.append("loc_fields")
        path = at(data, segs, loc_addend, length)
        if path != b"/home/ubuntu/hl/code_Mainnet/l1/src/abci/state.rs":
            errs.append("loc_path")
    return errs


def check_packet():
    errs = []
    man = HERE / "MANIFEST.sha256"
    if not man.exists():
        return ["no MANIFEST"]
    for line in man.read_text().splitlines():
        if not line.strip():
            continue
        hx, name = line.split(None, 1)
        p = HERE / name
        if not p.exists():
            # allow ../../../ relative
            p2 = (HERE / name).resolve()
            if not p2.exists():
                errs.append("missing " + name)
                continue
            p = p2
        if hashlib.sha256(p.read_bytes()).hexdigest() != hx:
            errs.append("manifest " + name)
    return errs


def main():
    if not BINARY.exists():
        print("INCONCLUSIVE binary missing")
        return 2
    data = BINARY.read_bytes()
    errs = check_keys(data) + check_packet()
    if errs:
        for e in errs:
            print("FAIL", e)
        print("FAIL")
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
