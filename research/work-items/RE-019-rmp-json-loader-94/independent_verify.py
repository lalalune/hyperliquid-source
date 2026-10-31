#!/usr/bin/env python3
"""RE-019 independent verifier. Imports nothing from tools/.

Checks every key VA byte by byte against the pinned node #94 binary, re-derives
each call/LEA target, re-runs the e8 caller pass over .text/.init/.fini/.plt with
its own code, checks label bytes and Location records, and checks the packet JSON
against MANIFEST.sha256. Prints PASS, FAIL or INCONCLUSIVE; exit 0, 1 or 2.
"""
import bisect
import hashlib
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BINARY = ROOT / "artifacts" / "node" / "94" / "hl-node"
SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
PACKET_JSON = HERE / "rmp-json-loader.json"
FN = 0x3c155a0
FN_END = 0x3c15c70
EXTENT_SHA256 = "b9475c6190243bb4674d50321121a69fe42b87751dfcbea6acf3455738b08f8e"
CALLERS = [0x22aefea, 0x3273862, 0x4546bca]
SCAN = (b".text\0", b".init\0", b".fini\0", b".plt\0")
FDES = {0x22aefea: 0x22ae8a0, 0x3273862: 0x3273810, 0x4546bca: 0x4546ba0}

KEYS = [
    (0x3c155a0, "4157415641545348"),
    (0x3c155a7, "4881ec00100000"),
    (0x3c155cc, "4889fb"),
    (0x3c155cf, "4c8d742458"),
    (0x3c155d7, "ff154ba0b501"),
    (0x3c155ed, "ff15f593b501"),
    (0x3c155fc, "41803f2f"),
    (0x3c15600, "0f94c0"),
    (0x3c1561c, "488d35f91e5efc"),
    (0x3c1564a, "48c70302000000"),
    (0x3c15668, "c684242001000006"),
    (0x3c15670, "8884244a010000"),
    (0x3c1568e, "ff15bc91b501"),
    (0x3c15696, "807c242009"),
    (0x3c156af, "4883fa02"),
    (0x3c156b5, "66813e2e2e"),
    (0x3c156ba, "0f8495010000"),
    (0x3c156e1, "807c3eff2e"),
    (0x3c15701, "0fb6540801"),
    (0x3c15718, "4080fe72"),
    (0x3c15722, "0fb6540802"),
    (0x3c15739, "4080fe6d"),
    (0x3c15743, "0fb6440803"),
    (0x3c15756, "80f970"),
    (0x3c1576e, "ff15cc9eb501"),
    (0x3c1579f, "488d05a80c5efc"),
    (0x3c15864, "ff15de9db501"),
    (0x3c15895, "488d059f905cfc"),
    (0x3c159ae, "e82dd63cff"),
    (0x3c159de, "488d05e9765efc"),
    (0x3c15a81, "c644244001"),
    (0x3c15a86, "66c74424420004"),
    (0x3c15a9c, "e89f801fff"),
    (0x3c15add, "488d05b8e15dfc"),
    (0x3c15b62, "bac81f0000"),
    (0x3c15b6a, "ff157084b501"),
    (0x3c15b9a, "4889d8"),
    (0x3c15bab, "c3"),
    (0x144a60b, "4989d6"),
    (0x144a624, "66813e7e2f"),
    (0x144a629, "7441"),
    (0x22aefdb, "488d0d460c4303"),
    (0x22aefea, "e8b1659601"),
    (0x3273856, "488d0d9bc34602"),
    (0x3273862, "e8391d9a00"),
    (0x4546bbe, "488d0d63901901"),
    (0x4546bca, "e8d1e96cff"),
]

TARGETS = {
    0x3c155d7: 0x576f628,
    0x3c155ed: 0x576e9e8,
    0x3c1561c: 0x1f751c,
    0x3c1568e: 0x576e850,
    0x3c1576e: 0x576f640,
    0x3c1579f: 0x1f644e,
    0x3c15864: 0x576f648,
    0x3c15895: 0x1de93b,
    0x3c159ae: 0x2fe2fe0,
    0x3c159de: 0x1fd0ce,
    0x3c15a9c: 0x2e0db40,
    0x3c15add: 0x1f3c9c,
    0x3c15b6a: 0x576dfe0,
    0x22aefdb: 0x56dfc28,
    0x22aefea: 0x3c155a0,
    0x3273856: 0x56dfbf8,
    0x3273862: 0x3c155a0,
    0x4546bbe: 0x56dfc28,
    0x4546bca: 0x3c155a0,
}

LABEL_BYTES = {
    0x1f751c: "0e6d697373696e672066696c653a20c0",
    0x1f644e: "06726561643a20c0",
    0x1de93b: "10726561645f746f5f737472696e673a20c0",
    0x1fd0ce: "1673657264655f6a736f6e3a3a66726f6d5f7374723a20c0",
    0x1f3c9c: "17726d705f73657264653a3a66726f6d5f736c6963653a20c0",
}

LOCATIONS = {
    0x56dfc28: {
        "file": "/home/ubuntu/hl/code_Mainnet/l1/src/abci/state.rs",
        "file_ptr": 0x1dd8eb,
        "length": 49,
        "line": 86,
        "column": 40,
    },
    0x56dfbf8: {
        "file": "/home/ubuntu/hl/code_Mainnet/l1/src/abci/state.rs",
        "file_ptr": 0x1dd8eb,
        "length": 49,
        "line": 107,
        "column": 37,
    },
}


def load_segments(data):
    phoff, = struct.unpack_from("<Q", data, 0x20)
    phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
    segs = []
    for i in range(phnum):
        t, _f, off, va, _p, fs, _m, _a = struct.unpack_from("<IIQQQQQQ", data, phoff + i * phentsize)
        if t == 1:
            segs.append((va, off, fs))
    return segs


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
        name = bytes(data[stroff + h[0]: stroff + h[0] + 16]).split(b"\0", 1)[0] + b"\0"
        yield name, h


def fde_start(data, segs, va):
    for name, h in shdrs(data):
        if name == b".eh_frame_hdr\0":
            o, a = h[4], h[3]
            if tuple(data[o + 1:o + 4]) != (0x1b, 0x03, 0x3b):
                raise ValueError("eh_frame_hdr encodings")
            n, = struct.unpack_from("<I", data, o + 8)
            tab = [struct.unpack_from("<ii", data, o + 12 + 8 * i) for i in range(n)]
            starts = [a + x for x, _ in tab]
            i = bisect.bisect_right(starts, va) - 1
            fva = a + tab[i][1]
            b = at(data, segs, fva, 16)
            pc, = struct.unpack_from("<i", b, 8)
            return fva + 8 + pc
    raise KeyError(".eh_frame_hdr")


def fde_next_start(data, segs, va):
    for name, h in shdrs(data):
        if name == b".eh_frame_hdr\0":
            o, a = h[4], h[3]
            n, = struct.unpack_from("<I", data, o + 8)
            tab = [struct.unpack_from("<ii", data, o + 12 + 8 * i) for i in range(n)]
            starts = [a + x for x, _ in tab]
            i = starts.index(va)
            return starts[i + 1]
    raise KeyError(".eh_frame_hdr")


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


def check_callers(data):
    found = []
    n_sec = 0
    for name, h in shdrs(data):
        if name not in SCAN:
            continue
        n_sec += 1
        addr, b = h[3], bytes(data[h[4]:h[4] + h[5]])
        for i in range(len(b) - 4):
            if b[i] != 0xe8:
                continue
            disp, = struct.unpack_from("<i", b, i + 1)
            site = addr + i
            if site + 5 + disp == FN:
                found.append(site)
    fails = [] if n_sec == len(SCAN) else ["scanned %d sections != %d" % (n_sec, len(SCAN))]
    if found != CALLERS:
        fails.append("e8 -> %#x: %s != %s" % (FN, [hex(x) for x in found], [hex(x) for x in CALLERS]))
    return fails


def read_location(data, segs, loc_va):
    for name, h in shdrs(data):
        if name != b".rela.dyn\0":
            continue
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
            "file_ptr": addend,
            "length": length,
            "line": line,
            "column": col,
        }
    raise KeyError(".rela.dyn")



def got_relative_addend(data, got_va):
    for name, h in shdrs(data):
        if name != b".rela.dyn\0":
            continue
        n = h[5] // 24
        for i in range(n):
            o = h[4] + i * 24
            r_offset, r_info, r_addend = struct.unpack_from("<QQq", data, o)
            if r_offset == got_va and (r_info & 0xffffffff) == 8:
                return r_addend
    raise KeyError("no RELATIVE for GOT " + hex(got_va))

def check_keys(data, check_sha=True, callers=True, labels=True, locations=True, extent=True):
    if check_sha and hashlib.sha256(data).hexdigest() != SHA256:
        return ["binary sha256 mismatch"]
    fails = []
    segs = load_segments(data)
    if extent:
        if fde_next_start(data, segs, FN) != FN_END:
            fails.append("extent end mismatch")
        ext = at(data, segs, FN, FN_END - FN)
        if hashlib.sha256(ext).hexdigest() != EXTENT_SHA256:
            fails.append("extent sha256 mismatch")
    try:
        if got_relative_addend(data, 0x576f628) != 0x144a600:
            fails.append("tilde GOT addend mismatch")
    except KeyError as e:
        fails.append(str(e))
    for va, hx in KEYS:
        got = at(data, segs, va, len(hx) // 2).hex()
        if got != hx:
            fails.append("%#x: %s != %s" % (va, got, hx))
        exp = TARGETS.get(va)
        if exp is not None:
            t = decode_target(va, hx)
            if t != exp:
                fails.append("%#x: target %#x != %#x" % (va, t if t is not None else -1, exp))
    for site, fde in FDES.items():
        if fde_start(data, segs, site) != fde:
            fails.append("%#x: fde %#x != %#x" % (site, fde_start(data, segs, site), fde))
    if labels:
        for va, hx in LABEL_BYTES.items():
            got = at(data, segs, va, len(hx) // 2).hex()
            if got != hx:
                fails.append("label %#x: %s != %s" % (va, got, hx))
    if locations:
        for va, exp in LOCATIONS.items():
            got = read_location(data, segs, va)
            if got != exp:
                fails.append("location %#x mismatch" % va)
    if callers:
        fails += check_callers(data)
    return fails


def check_packet():
    manifest = HERE / "MANIFEST.sha256"
    if not manifest.exists() or not PACKET_JSON.exists():
        return ["packet json or MANIFEST.sha256 missing"]
    pins = dict(reversed(line.split("  ", 1)) for line in manifest.read_text().splitlines() if line)
    if hashlib.sha256(PACKET_JSON.read_bytes()).hexdigest() != pins.get("rmp-json-loader.json"):
        return ["rmp-json-loader.json does not match MANIFEST.sha256"]
    return []


def main():
    if not BINARY.exists():
        print("INCONCLUSIVE: binary not present at", BINARY)
        return 2
    try:
        fails = check_keys(BINARY.read_bytes()) + check_packet()
    except (KeyError, ValueError, struct.error) as e:
        print("INCONCLUSIVE:", e)
        return 2
    for f in fails:
        print("FAIL", f)
    print("%s: key_insns=%d callers=%d labels=%d locations=%d failures=%d" % (
        "FAIL" if fails else "PASS", len(KEYS), len(CALLERS), len(LABEL_BYTES),
        len(LOCATIONS), len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
