#!/usr/bin/env python3
"""RE-028 independent verifier. Imports only hashlib, pathlib, struct.

Re-derives from the pinned node #94 binary: the modexp entry carve hash, key
instruction bytes, GOT/table RELAs, ff15 refs to GOT 0x576e530, gas immediates
0x3 / 0xc8 / 0x14, Address 0x05 table objects, and the three jemalloc stub
addresses plus memcpy/memset GLOB_DAT. Recomputes expected modexp outputs and
EIP-2565 / EIP-198 gas for the published vectors and checks them against the
packet JSON. Does not emulate. Prints PASS or FAIL; exit 0 or 1.
"""
import hashlib
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BINARY = ROOT / "artifacts" / "node" / "94" / "hl-node"
SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
PACKET_JSON = HERE / "modexp.json"
JSON_SHA256 = "20d1c278107e8688d04bd79ca27139606a4bcb88a942a5d288fd4d47dc843360"
FN = 0x136BDD0
FN_END = 0x136BF34
FN_RET = 0x136BEAA
CARVED_SHA256 = "ee1f99abba09a6804f55da289130166de868f339c6294ea29a3e81bc7e4c3252"
GOT_SLOT = 0x576E530
BERLIN = 0x4E91F20
BYZ = 0x4E92810
BERLIN_CALL = 0x4E92664
BYZ_CALL = 0x4E92F6D
BERLIN_TABLE = 0x574EE70
BYZ_TABLE = 0x574F170
BERLIN_DIV3 = 0x4E931BD
BERLIN_FLOOR = 0x4E93257
BYZ_DIV20 = 0x4E933B5
MALLOC = 0x54C06B0
MALLOC_SLOT = 0x576DFD8
REALLOC = 0x54C0780
REALLOC_SLOT = 0x576E298
FREE = 0x54C8CB0
FREE_SLOT = 0x576E010
MEMCPY_SLOT = 0x576DFE0
MEMSET_SLOT = 0x576E1F8
ALLOC_ERR = 0x1346068
PANIC = 0x157B810

KEY_INSNS = [
    (0x136BDD0, "4157415641554154534883ec50"),
    (0x136BEAA, "c3"),
    (0x136BEAB, "48c70300000000"),
    (0x4E92664, "ff15c6be8d00"),
    (0x4E92F6D, "ff15bdb58d00"),
    (0x4E931BD, "48c744244803000000"),
    (0x4E93257, "b8c8000000"),
    (0x4E933B5, "48c744244014000000"),
]

RELAS = [
    (GOT_SLOT, 8, FN),
    (BERLIN_TABLE, 8, BERLIN),
    (BYZ_TABLE, 8, BYZ),
    (MALLOC_SLOT, 8, MALLOC),
    (REALLOC_SLOT, 8, REALLOC),
    (FREE_SLOT, 8, FREE),
]


def segments(data):
    e_phoff = struct.unpack_from("<Q", data, 32)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 54)
    out = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        if struct.unpack_from("<I", data, o)[0] != 1:
            continue
        p_offset, p_vaddr = struct.unpack_from("<QQ", data, o + 8)
        p_filesz = struct.unpack_from("<Q", data, o + 32)[0]
        out.append((p_vaddr, p_offset, p_filesz))
    return out


def read_va(data, segs, va, n):
    for base, off, filesz in segs:
        if base <= va < base + filesz:
            return data[off + va - base : off + va - base + n]
    raise KeyError(hex(va))


def rela_dyn(data):
    e_shoff = struct.unpack_from("<Q", data, 40)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
    shstr_off, shstr_sz = struct.unpack_from(
        "<QQ", data, e_shoff + e_shstrndx * e_shentsize + 24
    )
    shstr = data[shstr_off : shstr_off + shstr_sz]
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        name_off, sh_type = struct.unpack_from("<II", data, o)
        name = shstr[name_off : shstr.find(b"\x00", name_off)]
        if name == b".rela.dyn" and sh_type != 8:
            off, size = struct.unpack_from("<QQ", data, o + 24)
            return [
                struct.unpack_from("<QQq", data, off + k * 24)
                for k in range(size // 24)
            ]
    return []


def slot_refs(data, segs, slot):
    refs = []
    for base, off, filesz in segs:
        code = data[off : off + filesz]
        i = 0
        while i <= len(code) - 6:
            va = base + i
            if code[i] == 0xFF and code[i + 1] in (0x15, 0x25):
                tgt = va + 6 + struct.unpack_from("<i", code, i + 2)[0]
                if tgt == slot:
                    refs.append(va)
                i += 6
                continue
            i += 1
    return refs


def iteration_count(exp_bytes):
    elen = len(exp_bytes)
    if elen == 0:
        return 0
    v = int.from_bytes(exp_bytes[:32], "big")
    msb = v.bit_length() if v else 0
    if elen <= 32:
        return max(msb - 1, 0)
    return 8 * (elen - 32) + max(msb - 1, 0)


def gas_eip2565(base, exp, mod):
    words = (max(len(mod), len(base)) + 7) // 8
    return max(200, words * words * max(iteration_count(exp), 1) // 3)


def gas_eip198(base, exp, mod):
    x = max(len(mod), len(base))
    if x <= 64:
        mc = x * x
    elif x <= 1024:
        mc = x * x // 4 + 96 * x - 3072
    else:
        mc = x * x // 16 + 480 * x - 199680
    return mc * max(iteration_count(exp), 1) // 20


def ref_modexp(base, exp, mod):
    if len(mod) == 0:
        return b""
    m = int.from_bytes(mod, "big")
    if m == 0:
        return bytes(len(mod))
    r = pow(
        int.from_bytes(base or b"\x00", "big"),
        int.from_bytes(exp or b"\x00", "big"),
        m,
    )
    return r.to_bytes(len(mod), "big")


# The manifest pins the packet's own files plus the
# ../..-relative tool and test files the packet binds.
PACKET_FILES = frozenset({
    "../../../tests/test_crypto_emulation_guard.py",
    "../../../tests/test_modexp.py",
    "../../../tests/test_modexp_review.py",
    "../../../tools/crypto_emulation_guard.py",
    "../../../tools/modexp.py",
    "README.md",
    "REVIEW.md",
    "independent_verify.py",
    "modexp.json",
    "pr-body.md",
    "review-static.json",
    "verify.py",
})


def main():
    errors = []
    data = BINARY.read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA256:
        errors.append("binary sha256 mismatch")
    segs = segments(data)
    carved = read_va(data, segs, FN, FN_END - FN)
    if hashlib.sha256(carved).hexdigest() != CARVED_SHA256:
        errors.append("carve sha256 mismatch")
    if read_va(data, segs, FN_RET, 1) != b"\xc3":
        errors.append("primary ret not c3")
    pad = read_va(data, segs, FN_END, 0x136BF40 - FN_END)
    if pad != b"\xcc" * len(pad):
        errors.append("padding not int3")
    for va, hx in KEY_INSNS:
        raw = read_va(data, segs, va, len(hx) // 2)
        if raw.hex() != hx:
            errors.append("key_insn at " + hex(va))
    rela = {r[0]: r for r in rela_dyn(data)}
    for slot, rtype, addend in RELAS:
        r = rela.get(slot)
        if r is None or (r[1] & 0xFFFFFFFF) != rtype or r[2] != addend:
            errors.append("RELA mismatch at " + hex(slot))
    for slot in (MEMCPY_SLOT, MEMSET_SLOT):
        r = rela.get(slot)
        if r is None or (r[1] & 0xFFFFFFFF) != 6:
            errors.append("GLOB_DAT expected at " + hex(slot))
    refs = slot_refs(data, segs, GOT_SLOT)
    if sorted(refs) != [BERLIN_CALL, BYZ_CALL]:
        errors.append("ff15 refs mismatch: " + ",".join(hex(x) for x in refs))
    for table, plus28 in ((BERLIN_TABLE, 0x01), (BYZ_TABLE, 0x00)):
        addr = read_va(data, segs, table + 0x10, 20)
        if addr != bytes(19) + b"\x05":
            errors.append("Address 0x05 mismatch at " + hex(table))
        if read_va(data, segs, table + 0x28, 1)[0] != plus28:
            errors.append("+0x28 mismatch at " + hex(table))
    # stubs exist as code
    for va in (MALLOC, REALLOC, FREE, ALLOC_ERR, PANIC):
        read_va(data, segs, va, 1)

    pkt = PACKET_JSON.read_bytes()
    if hashlib.sha256(pkt).hexdigest() != JSON_SHA256:
        errors.append("packet json sha256 mismatch")
    import json

    disk = json.loads(pkt)
    # vector gas + output recomputed independently
    vectors = {
        "eip198_ex1": (
            b"\x03",
            bytes.fromhex(
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e"
            ),
            bytes.fromhex(
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
            ),
        ),
        "large": (
            bytes.fromhex("01" * 48),
            bytes.fromhex("02" * 40),
            bytes.fromhex("ff" * 63 + "01"),
        ),
        "even_modulus": (b"\x02", b"\x03", b"\x08"),
        "zero_modulus": (b"\x03", b"\x05", b""),
        "small_3_5_7": (b"\x03", b"\x05", b"\x07"),
        "neg_wrong_base": (b"\x05", b"\x05", b"\x07"),
    }
    for name, (b, e, m) in vectors.items():
        expect = ref_modexp(b, e, m).hex()
        g2565 = gas_eip2565(b, e, m)
        g198 = gas_eip198(b, e, m)
        v = disk["vectors"][name]
        if v["expected_output_hex"] != expect:
            errors.append(name + " expected output drift")
        if v["expected_gas_eip2565"] != g2565:
            errors.append(name + " eip2565 gas drift")
        if v["expected_gas_eip198"] != g198:
            errors.append(name + " eip198 gas drift")
        if v["berlin"]["output_hex"] != expect or v["berlin"]["gas_used"] != g2565:
            errors.append(name + " berlin packet mismatch")
        if v["byzantium"]["output_hex"] != expect or v["byzantium"]["gas_used"] != g198:
            errors.append(name + " byzantium packet mismatch")
    if disk["vectors"]["small_3_5_7"]["berlin"]["output_hex"] == disk["vectors"][
        "neg_wrong_base"
    ]["berlin"]["output_hex"]:
        errors.append("wrong-base negative control collapsed")
    if disk["vectors"]["zero_modulus"]["berlin"]["output_hex"] != "":
        errors.append("zero-modulus not empty")
    for label, m in disk["mutations"].items():
        if not m["broke_expectation"]:
            errors.append(label + " mutation did not break")

    # MANIFEST. Admission first: hashing each listed row is not
    # enough. It cannot see a duplicated row, a listed file replaced
    # by a symlink (read_bytes follows it, so the evidence can point
    # outside the packet), an unlisted file in the packet directory,
    # or an evidence file deleted together with its row. Pin the
    # listed set and compare it against the packet contents,
    # mirroring the RE-005 verifier and the node-inventory verifiers.
    listed = {}
    for line in (HERE / "MANIFEST.sha256").read_text().splitlines():
        if not line.strip():
            continue
        digest, sep, name = line.partition("  ")
        if not sep or len(digest) != 64:
            errors.append("MANIFEST malformed line: " + line.strip())
            continue
        if name in listed:
            errors.append("MANIFEST lists " + name + " twice")
            continue
        listed[name] = digest
    if set(listed) != PACKET_FILES:
        errors.append("MANIFEST file set differs from pinned packet files")
    present = set()
    for entry in sorted(HERE.iterdir()):
        if entry.is_symlink():
            errors.append("packet entry is a symlink: " + entry.name)
        elif entry.is_dir():
            if entry.name != "__pycache__" or not all(
                    child.name.endswith(".pyc") and not child.is_symlink()
                    for child in entry.iterdir()):
                errors.append("unexpected directory in packet: " + entry.name)
        else:
            present.add(entry.name)
    in_packet = {name for name in listed if not name.startswith("..")}
    if present - {"MANIFEST.sha256"} != in_packet:
        errors.append("packet contents differ from MANIFEST")
    for name, digest in listed.items():
        path = HERE / name
        if path.is_symlink() or not path.is_file():
            errors.append("MANIFEST entry is a symlink or not a file: " + name)
            continue
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            errors.append("MANIFEST mismatch " + name)

    # path string must not appear in committed packet files (needles assembled)
    needle_path = "home/" + "ubuntu"
    needle_name = "Lan" + "tern"
    for name in ("README.md", "pr-body.md", "modexp.json", "verify.py", "independent_verify.py"):
        body = (HERE / name).read_text()
        if needle_path in body:
            errors.append(name + " contains absolute build path fragment")
        if needle_name in body:
            errors.append(name + " contains forbidden word")

    if errors:
        for e in errors:
            print("FAIL", e)
        print("FAIL")
        return 1
    print(
        "PASS carve=%s refs=%d vectors=%d mutations=%d"
        % (CARVED_SHA256[:16], len(refs), len(vectors), len(disk["mutations"]))
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
