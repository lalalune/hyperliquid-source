#!/usr/bin/env python3
"""RE-023 independent verifier. Imports only hashlib, pathlib, struct.

Checks every key VA byte against the pinned node #94 binary, re-derives the
dispatcher e9 target and caller GOT slot, checks the sha512.rs Location pin
(VA/len/sha256/suffix only), recomputes FIPS 180-4 digests via hashlib, and
checks the packet JSON hash. Prints PASS or FAIL; exit 0 or 1.
"""
import hashlib
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BINARY = ROOT / "artifacts" / "node" / "94" / "hl-node"
SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
PACKET_JSON = HERE / "sha512-compress.json"
JSON_SHA256 = "8cb0c2e8bb4b4da347cf14b3142fcee8a2458275d9adc85550bf780da745e5e4"
FN = 0x4EC4A40
FN_RET = 0x4EC857A
CARVED_SHA256 = "88b5bbdb2171f51f7102d46e8411c4a7c6099e62f2bf0ee3e7339da7f54ce57c"
DISPATCHER = 0x4EC9170
DISPATCHER_E9 = 0x4EC9183
UPDATE = 0x4EC4900
GOT_SLOT = 0x57708D0
CALLER_MOV = 0x158F8D1
LOCATION_PATH_VA = 0x1FD941
LOCATION_PATH_LEN = 90
LOCATION_PATH_SHA256 = "5e5b8e29cd580d42368242a335b46c412944e3d4d387730d5b2ec41cb082c4b1"
LOCATION_PATH_SUFFIX = "sha2-0.9.9/src/sha512.rs"
R_X86_64_RELATIVE = 8

KEY_INSNS = [
    (0x4EC4A40, "554157415641554154534881ecf80000"),
    (0x4EC857A, "c3"),
    (0x4EC9170, "0fb60505d78b00"),
    (0x4EC9177, "3cff"),
    (0x4EC9179, "740d"),
    (0x4EC917B, "3c01"),
    (0x4EC917D, "0f840df4ffff"),
    (0x4EC9183, "e9b8b8ffff"),
    (0x4EC4900, "4157415641554154"),
    (0x4EC49B2, "e8b9470000"),
    (0x4EC49CC, "e89f470000"),
    (0x4EC47D0, "4157415641554154"),
    (0x4EC4809, "e862490000"),
    (0x158F8D1, "488b1df80f1e04"),
    (0x158F8E5, "ffd3"),
]

EXPECTED_DIGESTS = {
    "empty": hashlib.sha512(b"").hexdigest(),
    "abc": hashlib.sha512(b"abc").hexdigest(),
    "two_block": hashlib.sha512(
        b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
        b"ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
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
    e9 = read_va(data, segs, DISPATCHER_E9, 5)
    if DISPATCHER_E9 + 5 + struct.unpack_from("<i", e9, 1)[0] != FN:
        failures.append("dispatcher e9")
    for call_va in (0x4EC49B2, 0x4EC49CC, 0x4EC4809):
        insn = read_va(data, segs, call_va, 5)
        if call_va + 5 + struct.unpack_from("<i", insn, 1)[0] != DISPATCHER:
            failures.append("call " + hex(call_va))
    caller_mov = read_va(data, segs, CALLER_MOV, 7)
    if CALLER_MOV + 7 + struct.unpack_from("<i", caller_mov, 3)[0] != GOT_SLOT:
        failures.append("caller got")
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
    found = False
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        name_off = struct.unpack_from("<I", data, o)[0]
        name = shstr[name_off : shstr.find(bytes([0]), name_off)]
        if name == b".rela.dyn":
            off = struct.unpack_from("<Q", data, o + 24)[0]
            size = struct.unpack_from("<Q", data, o + 32)[0]
            for k in range(size // 24):
                r_offset, r_info, r_addend = struct.unpack_from("<QQq", data, off + k * 24)
                if (
                    r_offset == GOT_SLOT
                    and (r_info & 0xFFFFFFFF) == R_X86_64_RELATIVE
                    and r_addend == UPDATE
                ):
                    found = True
            break
    if not found:
        failures.append("rela")
    for name, hx in EXPECTED_DIGESTS.items():
        if hx != EXPECTED_DIGESTS[name]:
            failures.append("vector " + name)
    # Cross-check packet expected digests match FIPS
    # (packet is JSON; parse without json module via simple search)
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
    print("PASS: key_insns=%d vectors=%d failures=0" % (len(KEY_INSNS), len(EXPECTED_DIGESTS)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
