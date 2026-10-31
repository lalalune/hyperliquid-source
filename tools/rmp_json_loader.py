#!/usr/bin/env python3
"""RE-019: 0x3c155a0 path-selected MessagePack/JSON loader (node #94).

Standalone. From the pinned node #94 binary only, it recovers:
  * path ABI (rdi=out, rsi=path_ptr, rdx=path_len, rcx=Location);
  * first call [0x576f628] -> 0x144a600 ~/ expander (cmpw $0x2f7e);
  * absolute-/ is sete-flag (not reject); exact-.. (len==2, cmpw $0x2e2e) -> non-rmp arm;
  * the FDE extent 0x3c155a0..0x3c15c70 (sha256-pinned);
  * a whole-section e8 caller pass: exactly three sites call 0x3c155a0;
  * the .rmp case-insensitive extension gate;
  * the two format arms: .rmp -> call 0x2e0db40 + LEA rmp_serde::from_slice;
    else -> call 0x2fe2fe0 + LEA serde_json::from_str;
  * Ok payload length 0x1fc8 (memcpy) and Err tag movq $2;
  * Location records at the three callers (state.rs:86 and state.rs:107).
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

FN = 0x3c155a0
FN_END = 0x3c15c70
SCAN_SECTIONS = (".fini", ".init", ".plt", ".text")
CALLERS = (0x22aefea, 0x3273862, 0x4546bca)

KEY_INSNS = [
    (0x3c155a0, "4157415641545348", "prologue push r15,r14,r12,rbx"),
    (0x3c155a7, "4881ec00100000", "sub rsp,0x1000 stack probe"),
    (0x3c155cc, "4889fb", "mov rbx,rdi out Result (path ABI rdi)"),
    (0x3c155cf, "4c8d742458", "lea r14,[rsp+0x58]"),
    (0x3c155d7, "ff154ba0b501", "call [0x576f628] ~/ expander GOT (rsi/rdx path)"),
    (0x3c155ed, "ff15f593b501", "call [0x576e9e8] path probe"),
    (0x3c155fc, "41803f2f", "cmpb $0x2f,(r15) detect absolute slash"),
    (0x3c15600, "0f94c0", "sete al is_absolute flag (not a reject)"),
    (0x3c1561c, "488d35f91e5efc", "lea rsi, missing file:"),
    (0x3c1564a, "48c70302000000", "movq $2,(rbx) early Err tag"),
    (0x3c15668, "c684242001000006", "movb $6,[rsp+0x120]"),
    (0x3c15670, "8884244a010000", "movb al,[rsp+0x14a] store is_absolute"),
    (0x3c1568e, "ff15bc91b501", "call [0x576e850] Path construct"),
    (0x3c15696, "807c242009", "cmpb $9,[rsp+0x20]"),
    (0x3c156af, "4883fa02", "cmp $2,rdx before exact-.. check"),
    (0x3c156b5, "66813e2e2e", "cmpw $0x2e2e,(rsi) exact-.. path"),
    (0x3c156ba, "0f8495010000", "je non-rmp arm when path is exact .."),
    (0x3c156e1, "807c3eff2e", "cmpb $0x2e,-1(rsi,rdi) trailing-dot scan"),
    (0x3c15701, "0fb6540801", "movzbl 1(rax,rcx),edx ext0"),
    (0x3c15718, "4080fe72", "cmp $0x72,sil folded r"),
    (0x3c15722, "0fb6540802", "movzbl 2(rax,rcx),edx ext1"),
    (0x3c15739, "4080fe6d", "cmp $0x6d,sil folded m"),
    (0x3c15743, "0fb6440803", "movzbl 3(rax,rcx),eax ext2"),
    (0x3c15756, "80f970", "cmp $0x70,cl folded p"),
    (0x3c1576e, "ff15cc9eb501", "call [0x576f640] rmp-side open/read"),
    (0x3c1579f, "488d05a80c5efc", "lea rax, read:"),
    (0x3c15864, "ff15de9db501", "call [0x576f648] non-rmp open/read"),
    (0x3c15895, "488d059f905cfc", "lea rax, read_to_string:"),
    (0x3c159ae, "e82dd63cff", "call 0x2fe2fe0 json decode helper"),
    (0x3c159de, "488d05e9765efc", "lea rax, serde_json::from_str"),
    (0x3c15a81, "c644244001", "movb $1,[rsp+0x40]"),
    (0x3c15a86, "66c74424420004", "movw $0x400,[rsp+0x42]"),
    (0x3c15a9c, "e89f801fff", "call 0x2e0db40 rmp decode helper"),
    (0x3c15add, "488d05b8e15dfc", "lea rax, rmp_serde::from_slice"),
    (0x3c15b62, "bac81f0000", "mov edx,0x1fc8 Ok payload length"),
    (0x3c15b6a, "ff157084b501", "call [0x576dfe0] memcpy Ok payload"),
    (0x3c15b9a, "4889d8", "mov rax,rbx"),
    (0x3c15bab, "c3", "ret"),
    (0x144a60b, "4989d6", "tilde expander: mov r14,rdx path_len"),
    (0x144a624, "66813e7e2f", "tilde expander: cmpw $0x2f7e,(rsi) ~/"),
    (0x144a629, "7441", "tilde expander: je home-expand"),
]

CALLER_KEYS = [
    (0x22aefdb, "488d0d460c4303", "caller 0x22aefea: lea rcx, Location state.rs:86"),
    (0x22aefea, "e8b1659601", "caller 0x22aefea: call 0x3c155a0"),
    (0x3273856, "488d0d9bc34602", "caller 0x3273862: lea rcx, Location state.rs:107"),
    (0x3273862, "e8391d9a00", "caller 0x3273862: call 0x3c155a0"),
    (0x4546bbe, "488d0d63901901", "caller 0x4546bca: lea rcx, Location state.rs:86"),
    (0x4546bca, "e8d1e96cff", "caller 0x4546bca: call 0x3c155a0"),
]

LABELS = {
    "0x1f751c": "missing file: ",
    "0x1f644e": "read: ",
    "0x1de93b": "read_to_string: ",
    "0x1fd0ce": "serde_json::from_str: ",
    "0x1f3c9c": "rmp_serde::from_slice: ",
}
LABEL_BYTES = {
    "0x1f751c": "0e6d697373696e672066696c653a20c0",
    "0x1f644e": "06726561643a20c0",
    "0x1de93b": "10726561645f746f5f737472696e673a20c0",
    "0x1fd0ce": "1673657264655f6a736f6e3a3a66726f6d5f7374723a20c0",
    "0x1f3c9c": "17726d705f73657264653a3a66726f6d5f736c6963653a20c0",
}

LOCATIONS = {
    "0x56dfc28": {
        "file": "/home/ubuntu/hl/code_Mainnet/l1/src/abci/state.rs",
        "file_ptr": "0x1dd8eb",
        "length": 49,
        "line": 86,
        "column": 40,
    },
    "0x56dfbf8": {
        "file": "/home/ubuntu/hl/code_Mainnet/l1/src/abci/state.rs",
        "file_ptr": "0x1dd8eb",
        "length": 49,
        "line": 107,
        "column": 37,
    },
}

PATH_ABI = {
    "rdi": "out Result pointer",
    "rsi": "path pointer",
    "rdx": "path length",
    "rcx": "Location pointer",
}
TILDE_EXPANDER = {
    "va": "0x144a600",
    "got": "0x576f628",
    "got_addend": "0x144a600",
    "cmpw_imm": "0x2f7e",
    "cmpw_va": "0x144a624",
    "cmpw_bytes": "66813e7e2f",
}
EXTENT_SHA256 = "b9475c6190243bb4674d50321121a69fe42b87751dfcbea6acf3455738b08f8e"
CALLER_FDES = {
    "0x22aefea": "0x22ae8a0",
    "0x3273862": "0x3273810",
    "0x4546bca": "0x4546ba0",
}
TARGETS = {
    "0x3c155d7": "0x576f628",
    "0x3c155ed": "0x576e9e8",
    "0x3c1561c": "0x1f751c",
    "0x3c1568e": "0x576e850",
    "0x3c1576e": "0x576f640",
    "0x3c1579f": "0x1f644e",
    "0x3c15864": "0x576f648",
    "0x3c15895": "0x1de93b",
    "0x3c159ae": "0x2fe2fe0",
    "0x3c159de": "0x1fd0ce",
    "0x3c15a9c": "0x2e0db40",
    "0x3c15add": "0x1f3c9c",
    "0x3c15b6a": "0x576dfe0",
    "0x22aefdb": "0x56dfc28",
    "0x22aefea": "0x3c155a0",
    "0x3273856": "0x56dfbf8",
    "0x3273862": "0x3c155a0",
    "0x4546bbe": "0x56dfc28",
    "0x4546bca": "0x3c155a0",
}

EXPECT = {
    "binary_sha256": BINARY_SHA256,
    "function": hex(FN),
    "function_end": hex(FN_END),
    "extent_sha256": EXTENT_SHA256,
    "extent_len": FN_END - FN,
    "callers": [hex(c) for c in CALLERS],
    "caller_fdes": CALLER_FDES,
    "ok_payload_len": 0x1fc8,
    "err_tag": 2,
    "key_insns": len(KEY_INSNS) + len(CALLER_KEYS),
    "labels": LABELS,
    "locations": LOCATIONS,
    "path_abi": PATH_ABI,
    "tilde_expander": TILDE_EXPANDER,
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


def fde_start(data, segs, va):
    secs = section_map(data)
    h = secs[b".eh_frame_hdr"]
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


def fde_next_start(data, segs, va):
    secs = section_map(data)
    h = secs[b".eh_frame_hdr"]
    o, a = h[4], h[3]
    n, = struct.unpack_from("<I", data, o + 8)
    tab = [struct.unpack_from("<ii", data, o + 12 + 8 * i) for i in range(n)]
    starts = [a + x for x, _ in tab]
    i = starts.index(va)
    return starts[i + 1]


def caller_scan(data):
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
            if site + 5 + disp == FN:
                found.append(site)
    return sorted(found)


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


def analyse(data, check_sha=True):
    if check_sha and hashlib.sha256(data).hexdigest() != BINARY_SHA256:
        raise ValueError("binary sha256 mismatch")
    segs = segments(data)
    end = fde_next_start(data, segs, FN)
    if end != FN_END:
        raise ValueError("extent end %s != %s" % (hex(end), hex(FN_END)))
    extent = at(data, segs, FN, FN_END - FN)
    extent_sha = hashlib.sha256(extent).hexdigest()
    keys = {}
    for va, hx, role in KEY_INSNS + CALLER_KEYS:
        got = at(data, segs, va, len(hx) // 2)
        if got.hex() != hx:
            raise ValueError("key mismatch at %s: %s != %s" % (hex(va), got.hex(), hx))
        keys[hex(va)] = {"bytes": hx, "role": role}
    targets = {}
    for va, hx, _role in KEY_INSNS + CALLER_KEYS:
        t = decode_target(va, hx)
        if t is not None:
            targets[hex(va)] = hex(t)
    labels = {}
    for va_s, hx in LABEL_BYTES.items():
        va = int(va_s, 16)
        got = at(data, segs, va, len(hx) // 2)
        if got.hex() != hx:
            raise ValueError("label mismatch at " + va_s)
        labels[va_s] = LABELS[va_s]
    locs = {k: read_location(data, segs, int(k, 16)) for k in LOCATIONS}
    callers = caller_scan(data)
    caller_fdes = {hex(c): hex(fde_start(data, segs, c)) for c in callers}
    got_addend = got_relative_addend(data, 0x576f628)
    if got_addend != 0x144a600:
        raise ValueError("tilde GOT addend %s != 0x144a600" % hex(got_addend))
    tilde = dict(TILDE_EXPANDER)
    return {
        "binary_sha256": BINARY_SHA256,
        "function": hex(FN),
        "function_end": hex(FN_END),
        "extent_sha256": extent_sha,
        "extent_len": FN_END - FN,
        "callers": [hex(c) for c in callers],
        "caller_fdes": {k: caller_fdes[k] for k in sorted(caller_fdes)},
        "ok_payload_len": 0x1fc8,
        "err_tag": 2,
        "path_abi": dict(PATH_ABI),
        "tilde_expander": tilde,
        "key_bytes": keys,
        "targets": {k: targets[k] for k in sorted(targets)},
        "labels": labels,
        "locations": locs,
        "caller_scan": {
            "e8_sites": [hex(c) for c in callers],
            "sections": list(SCAN_SECTIONS),
        },
    }


def expectation_errors(result):
    errs = []
    for k, v in EXPECT.items():
        if k in ("key_insns", "labels", "locations", "caller_fdes", "callers",
                 "path_abi", "tilde_expander"):
            continue
        if result.get(k) != v:
            errs.append("%s: %r != %r" % (k, result.get(k), v))
    if result["callers"] != EXPECT["callers"]:
        errs.append("callers: %s != %s" % (result["callers"], EXPECT["callers"]))
    if result["caller_fdes"] != EXPECT["caller_fdes"]:
        errs.append("caller_fdes mismatch")
    if len(result["key_bytes"]) != EXPECT["key_insns"]:
        errs.append("key_insns: %d != %d" % (len(result["key_bytes"]), EXPECT["key_insns"]))
    if result["labels"] != EXPECT["labels"]:
        errs.append("labels mismatch")
    if result["locations"] != EXPECT["locations"]:
        errs.append("locations mismatch")
    if result.get("path_abi") != EXPECT["path_abi"]:
        errs.append("path_abi mismatch")
    if result.get("tilde_expander") != EXPECT["tilde_expander"]:
        errs.append("tilde_expander mismatch")
    for va, exp in TARGETS.items():
        got = result["targets"].get(va)
        if got != exp:
            errs.append("target %s: %s != %s" % (va, got, exp))
    return errs


def render(result):
    payload = {
        "binary_sha256": result["binary_sha256"],
        "caller_fdes": result["caller_fdes"],
        "caller_scan": result["caller_scan"],
        "callers": result["callers"],
        "err_tag": result["err_tag"],
        "extent_len": result["extent_len"],
        "extent_sha256": result["extent_sha256"],
        "function": result["function"],
        "function_end": result["function_end"],
        "key_bytes": result["key_bytes"],
        "labels": result["labels"],
        "locations": result["locations"],
        "ok_payload_len": result["ok_payload_len"],
        "path_abi": result["path_abi"],
        "targets": result["targets"],
        "tilde_expander": result["tilde_expander"],
    }
    return json.dumps(payload, sort_keys=True, indent=1) + "\n"


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, default=None)
    args = p.parse_args(argv)
    data = TARGET.read_bytes()
    result = analyse(data)
    errs = expectation_errors(result)
    if errs:
        for e in errs:
            print("EXPECT", e, file=sys.stderr)
        return 1
    text = render(result)
    if args.out:
        args.out.write_text(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
