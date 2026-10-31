#!/usr/bin/env python3
"""RE-024 independent verifier. Imports only hashlib, pathlib, struct.

Checks every key VA byte against the pinned node #94 binary, re-derives the
finalize GOT slot and Location lea target, checks the ripemd Location pin
(VA/len/sha256/suffix only), recomputes RIPEMD-160 digests via hashlib, and
checks the packet JSON hash. Prints PASS or FAIL; exit 0 or 1.
"""
import hashlib
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BINARY = ROOT / "artifacts" / "node" / "94" / "hl-node"
SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
PACKET_JSON = HERE / "ripemd160-compress.json"
JSON_SHA256 = "6167af924de2bbdb68943119ea66c3866448fa024b20992a10cd9bdd7ecefb43"
FN = 0x4EA55F0
FN_RET = 0x4EA6C7F
CARVED_SHA256 = "9da4dd9d6f7ad3288ba0fafbc8323f441ff24d39bef6e9deb5922fa7c5e9303c"
FINALIZE = 0x4EA0200
GOT_SLOT = 0x5776FB0
FINALIZE_MOV = 0x4EA043A
FINALIZE_FF15 = 0x4EA049B
LOCATION_PATH_VA = 0x1F1474
LOCATION_PATH_LEN = 89
LOCATION_PATH_SHA256 = "36b681955d65e83df460197ed445c5afd9833b222b962608ca53fe2ae2349d35"
LOCATION_PATH_SUFFIX = "ripemd-0.1.3/src/lib.rs"
LOCATION_RELA_SLOT = 0x574F610
LOCATION_LEA = 0x4EA0541
R_X86_64_RELATIVE = 8

KEY_INSNS = [
    (0x4EA55F0, "554157415641554154534883ec18"),
    (0x4EA6C7F, "c3"),
    (0x4EA0200, "554157415641554154534881ec680100"),
    (0x4EA043A, "488b1d6f6b8d00"),
    (0x4EA044A, "ffd3"),
    (0x4EA0486, "ffd3"),
    (0x4EA049B, "ff150f6b8d00"),
    (0x4EA0541, "488d3dc8f08a00"),
]

EXPECTED_DIGESTS = {
    "empty": hashlib.new("ripemd160", b"").hexdigest(),
    "abc": hashlib.new("ripemd160", b"abc").hexdigest(),
    "message_digest": hashlib.new("ripemd160", b"message digest").hexdigest(),
    "az": hashlib.new("ripemd160", bytes(range(ord("a"), ord("z") + 1))).hexdigest(),
    "alphanum": hashlib.new(
        "ripemd160",
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    ).hexdigest(),
}


def segments(data):
    e_phoff = struct.unpack_from("<Q", data, 32)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 54)
    out = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        if struct.unpack_from("<I", data, o)[0] != 1:
            continue
        p_offset, p_vaddr = struct.unpack_from("<QQ", data, o + 8)
        p_filesz, p_memsz = struct.unpack_from("<QQ", data, o + 32)
        out.append((p_vaddr, p_offset, p_filesz, p_memsz))
    return out


def read_va(data, segs, va, n):
    for base, off, filesz, _m in segs:
        if base <= va < base + filesz:
            o = off + va - base
            return data[o : o + n]
    raise KeyError(hex(va))


def main():
    failures = []
    data = BINARY.read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA256:
        failures.append("binary sha256")
    segs = segments(data)
    carved = read_va(data, segs, FN, FN_RET - FN + 1)
    if hashlib.sha256(carved).hexdigest() != CARVED_SHA256:
        failures.append("carved sha256")
    for va, hx in KEY_INSNS:
        raw = read_va(data, segs, va, len(hx) // 2)
        if raw.hex() != hx:
            failures.append("insn " + hex(va))
    mov = read_va(data, segs, FINALIZE_MOV, 7)
    if FINALIZE_MOV + 7 + struct.unpack_from("<i", mov, 3)[0] != GOT_SLOT:
        failures.append("finalize mov got")
    ff15 = read_va(data, segs, FINALIZE_FF15, 6)
    if FINALIZE_FF15 + 6 + struct.unpack_from("<i", ff15, 2)[0] != GOT_SLOT:
        failures.append("finalize ff15 got")
    lea = read_va(data, segs, LOCATION_LEA, 7)
    if LOCATION_LEA + 7 + struct.unpack_from("<i", lea, 3)[0] != LOCATION_RELA_SLOT:
        failures.append("location lea")
    loc_raw = read_va(data, segs, LOCATION_PATH_VA, LOCATION_PATH_LEN)
    if len(loc_raw) != LOCATION_PATH_LEN:
        failures.append("location len")
    if hashlib.sha256(loc_raw).hexdigest() != LOCATION_PATH_SHA256:
        failures.append("location sha256")
    if not loc_raw.decode("ascii", errors="replace").endswith(LOCATION_PATH_SUFFIX):
        failures.append("location suffix")
    e_shoff = struct.unpack_from("<Q", data, 40)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
    shstr_hdr = e_shoff + e_shstrndx * e_shentsize
    shstr_off = struct.unpack_from("<Q", data, shstr_hdr + 24)[0]
    shstr_sz = struct.unpack_from("<Q", data, shstr_hdr + 32)[0]
    shstr = data[shstr_off : shstr_off + shstr_sz]
    found_got = False
    found_loc = False
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        name_off = struct.unpack_from("<I", data, o)[0]
        name = shstr[name_off : shstr.find(bytes([0]), name_off)]
        if name == b".rela.dyn":
            off = struct.unpack_from("<Q", data, o + 24)[0]
            size = struct.unpack_from("<Q", data, o + 32)[0]
            for k in range(size // 24):
                r_offset, r_info, r_addend = struct.unpack_from(
                    "<QQq", data, off + k * 24
                )
                if (
                    r_offset == GOT_SLOT
                    and (r_info & 0xFFFFFFFF) == R_X86_64_RELATIVE
                    and r_addend == FN
                ):
                    found_got = True
                if (
                    r_offset == LOCATION_RELA_SLOT
                    and (r_info & 0xFFFFFFFF) == R_X86_64_RELATIVE
                    and r_addend == LOCATION_PATH_VA
                ):
                    found_loc = True
            break
    if not found_got:
        failures.append("rela got")
    if not found_loc:
        failures.append("rela location")
    pkt = PACKET_JSON.read_text()
    for name, hx in EXPECTED_DIGESTS.items():
        needle = "\"expected_digest_hex\": \"" + hx + "\""
        if needle not in pkt:
            failures.append("packet digest " + name)
    if hashlib.sha256(PACKET_JSON.read_bytes()).hexdigest() != JSON_SHA256:
        failures.append("json sha256")
    for line in (HERE / "MANIFEST.sha256").read_text().splitlines():
        if not line.strip():
            continue
        digest, rel = line.split("  ", 1)
        path = (HERE / rel).resolve()
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            failures.append("manifest " + rel)
    if failures:
        print("FAIL:", ", ".join(failures))
        return 1
    print(
        "PASS: key_insns=%d vectors=%d failures=0"
        % (len(KEY_INSNS), len(EXPECTED_DIGESTS))
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
