#!/usr/bin/env python3
"""RE-026 independent verifier. Imports only hashlib, pathlib, struct.

Re-derives from the pinned node #94 binary: the run_add carve hash, key
instruction bytes, call/slot targets, the bn254 field constants (p computed
here from the BN parameter u, the Montgomery inverse, R and R^2) as imm64 in
run_add and the point decoder, the GOT and precompile-table RELAs, an exact
scan of rip-relative ff15/ff25/mov references to GOT 0x5776f00 and of direct
e8/e9 calls to run_add, and the bn128.rs Location. Recomputes every ok vector
with its own affine addition and checks the emulated outputs recorded in the
packet, then the packet JSON hash and MANIFEST.sha256. Does not emulate.
Prints PASS or FAIL; exit 0 or 1.
"""
import hashlib
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BINARY = ROOT / "artifacts" / "node" / "94" / "hl-node"
SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
PACKET_JSON = HERE / "bn254-ecadd.json"
JSON_SHA256 = "0ece19222a62722e80d336bca990ba1113a9e3765a26aa0f858b46c7af335581"
FN = 0x4E96610
FN_END = 0x4E96CEE
CARVED_SHA256 = "89f39d1b63955c1db57a998837ca6f826d190682a1c6ad8db722e37f707bad39"
DECODER, DECODER_END = 0x4E961E0, 0x4E9660F
TEXT_LOAD_VA = 0x1343C80
GOT_SLOT = 0x5776F00
U = 4965661367192848881
LOCATION = 0x574F258
LOCATION_PATH_VA = 0x1FEB5E
LOCATION_PATH_LEN = 101
LOCATION_PATH_SHA256 = "a36d5efeadaf197094d34d1742918772b052f93db555af81e21e1369194c874d"
LOCATION_PATH_SUFFIX = b"revm-precompile-16.0.0/src/bn128.rs"
LOCATION_LEAS = [0x4E989A3, 0x4E989B0]

KEY_INSNS = [
    (0x4E96610, "554157415641554154534881eca8020000"),
    (0x4E96621, "4889fb4c39c17613"),
    (0x4E96629, "48b80000000000000080"),
    (0x4E9663C, "4883fa7f"),
    (0x4E96686, "ff1554798d00"),
    (0x4E9671E, "e8bdfaffff"),
    (0x4E967A4, "e837faffff"),
    (0x4E967EB, "c3"),
    (0x4E968CD, "e81e480800"),
    (0x4E968D8, "e8e3f70700"),
    (0x4E9694E, "48b88dca7168916a8197"),
    (0x4E9695D, "48b847fd7cd8168c203c"),
    (0x4E9696B, "49bd29a031e1724e6430"),
    (0x4E9697A, "48bd5d588181b64550b8"),
    (0x4E96989, "4c8b2568058e00"),
    (0x4E969A3, "49be896386e48207d287"),
    (0x4E969AD, "49bfc96aca1e657dde9e"),
    (0x4E969BD, "41ffd4"),
    (0x4E96C57, "bf40000000"),
    (0x4E96C5C, "ff1576738d00"),
    (0x4E96CBE, "48c7431040000000"),
    (0x4E96CCD, "488b8424e8000000"),
    (0x4E96CD5, "48894320"),
    (0x4E96CE8, "ff15ca728d00"),
    (0x4E98A4F, "b996000000"),
    (0x4E98A57, "ff15a3e48d00"),
    (0x4E98ADF, "b9f4010000"),
    (0x4E98AE7, "ff1513e48d00"),
    (0x54C06B0, "f30f1efa4881ff00100000"),
]
# (insn VA, len, displacement offset, expected target)
BRANCHES = [
    (0x4E9671E, 5, 1, DECODER),
    (0x4E967A4, 5, 1, DECODER),
    (0x4E968CD, 5, 1, 0x4F1B0F0),
    (0x4E968D8, 5, 1, 0x4F160C0),
    (0x4E96989, 7, 3, 0x5776EF8),
    (0x4E96686, 6, 2, 0x576DFE0),
    (0x4E96C5C, 6, 2, 0x576DFD8),
    (0x4E96CE8, 6, 2, 0x576DFB8),
    (0x4E98A57, 6, 2, GOT_SLOT),
    (0x4E98AE7, 6, 2, GOT_SLOT),
]
# (slot, r_type, addend)
RELAS = [
    (GOT_SLOT, 8, FN),
    (0x574F020, 8, 0x4E98A40),
    (0x574F0E0, 8, 0x4E98AD0),
    (0x576DFD8, 8, 0x54C06B0),
    (0x5776EF8, 8, 0x4F1F9C0),
    (LOCATION, 8, LOCATION_PATH_VA),
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
            o = off + va - base
            return data[o : o + n]
    raise KeyError(hex(va))


def rela_dyn(data):
    e_shoff = struct.unpack_from("<Q", data, 40)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
    shstr_off, shstr_sz = struct.unpack_from("<QQ", data, e_shoff + e_shstrndx * e_shentsize + 24)
    shstr = data[shstr_off : shstr_off + shstr_sz]
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        name_off, sh_type = struct.unpack_from("<II", data, o)
        if shstr[name_off : shstr.find(bytes([0]), name_off)] == b".rela.dyn" and sh_type != 8:
            off, size = struct.unpack_from("<QQ", data, o + 24)
            return {struct.unpack_from("<Q", data, off + k * 24)[0]:
                    struct.unpack_from("<QQq", data, off + k * 24) for k in range(size // 24)}
    return {}


def ec_add(p, a, b):
    if a == (0, 0):
        return b
    if b == (0, 0):
        return a
    if a[0] == b[0] and (a[1] + b[1]) % p == 0:
        return (0, 0)
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], p - 2, p) % p
    else:
        lam = (b[1] - a[1]) * pow((b[0] - a[0]) % p, p - 2, p) % p
    x = (lam * lam - a[0] - b[0]) % p
    return (x, (lam * (a[0] - x) - a[1]) % p)


def json_str(text, key, after):
    i = text.index('"' + key + '": "', after) + len(key) + 5
    return text[i : text.index('"', i)]


# The manifest pins the packet's own files plus the
# ../..-relative tool and test files the packet binds.
PACKET_FILES = frozenset({
    "README.md",
    "bn254-ecadd.json",
    "independent_verify.py",
    "pr-body.md",
    "verify.py",
})


def main():
    failures = []
    data = BINARY.read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA256:
        failures.append("binary sha256")
    segs = segments(data)
    carved = read_va(data, segs, FN, FN_END - FN)
    if len(carved) != 1758 or hashlib.sha256(carved).hexdigest() != CARVED_SHA256:
        failures.append("carved sha256")
    for va, hx in KEY_INSNS:
        if read_va(data, segs, va, len(hx) // 2).hex() != hx:
            failures.append("insn " + hex(va))
    for va, ilen, at, want in BRANCHES:
        insn = read_va(data, segs, va, ilen)
        if va + ilen + struct.unpack_from("<i", insn, at)[0] != want:
            failures.append("branch " + hex(va))

    p = 36 * U**4 + 36 * U**3 + 24 * U**2 + 6 * U + 1
    if pow(2, p - 1, p) != 1 or p.bit_length() != 254:  # Fermat base-2 sanity only
        failures.append("p shape")
    m64 = 2**64 - 1
    inv = (-pow(p, -1, 2**128)) % 2**128
    r1, r2 = 2**256 % p, 2**512 % p
    decoder = read_va(data, segs, DECODER, DECODER_END - DECODER)

    def counts(code, v, n):
        return [code.count(struct.pack("<Q", (v >> (64 * i)) & m64)) for i in range(n)]

    if counts(carved, p, 4) != [4, 4, 1, 3]:
        failures.append("p limbs in run_add")
    if counts(carved, inv, 2) != [1, 1]:
        failures.append("Montgomery inverse in run_add")
    if counts(carved, r1, 4) != [2, 2, 2, 2]:
        failures.append("R mod p in run_add")
    if counts(decoder, r2, 4) != [2, 2, 2, 2] or counts(decoder, p, 4) != [1, 1, 1, 1]:
        failures.append("decoder constants")

    rela = rela_dyn(data)
    for slot, rtype, addend in RELAS:
        r = rela.get(slot)
        if r is None or (r[1] & 0xFFFFFFFF) != rtype or r[2] != addend:
            failures.append("rela " + hex(slot))
    for obj in (0x574F020, 0x574F0E0):  # Address field at +0x10 (#550 layout)
        if read_va(data, segs, obj + 0x10, 20) != bytes(19) + b"\x06":
            failures.append("table address " + hex(obj))
    r = rela.get(0x576DFE0)
    if r is None or (r[1] & 0xFFFFFFFF) != 6:
        failures.append("memcpy GLOB_DAT")

    for base, off, filesz in segs:
        if base == TEXT_LOAD_VA:
            text = data[off : off + filesz]
    refs, direct = [], 0
    for i in range(len(text)):
        b0 = text[i]
        b1 = text[i + 1] if i + 1 < len(text) else None
        if b0 == 0xFF and b1 in (0x15, 0x25) and i + 6 <= len(text):
            if TEXT_LOAD_VA + i + 6 + struct.unpack_from("<i", text, i + 2)[0] == GOT_SLOT:
                refs.append((b1, TEXT_LOAD_VA + i))
        elif b0 in (0x48, 0x4C) and b1 == 0x8B and i + 7 <= len(text) and (text[i + 2] & 0xC7) == 0x05:
            if TEXT_LOAD_VA + i + 7 + struct.unpack_from("<i", text, i + 3)[0] == GOT_SLOT:
                refs.append((0x8B, TEXT_LOAD_VA + i))
        if b0 in (0xE8, 0xE9) and i + 5 <= len(text) and TEXT_LOAD_VA + i + 5 + struct.unpack_from("<i", text, i + 1)[0] == FN:
            direct += 1
    if refs != [(0x15, 0x4E98A57), (0x15, 0x4E98AE7)]:
        failures.append("GOT slot refs")
    if direct != 0:
        failures.append("direct calls")
    for pat in (bytes([0x0F, 0xA2]), bytes([0x0F, 0x01, 0xD0]), bytes([0x66, 0x0F, 0x38, 0xF6]),
                bytes([0xF3, 0x0F, 0x38, 0xF6])):
        if pat in carved:
            failures.append("feature pattern " + pat.hex())

    plen, l_line, l_col = struct.unpack_from("<QII", read_va(data, segs, LOCATION, 24), 8)
    path = read_va(data, segs, LOCATION_PATH_VA, LOCATION_PATH_LEN)
    if (plen, l_line, l_col) != (LOCATION_PATH_LEN, 169, 20):
        failures.append("location fields")
    if hashlib.sha256(path).hexdigest() != LOCATION_PATH_SHA256 or not path.endswith(LOCATION_PATH_SUFFIX):
        failures.append("location path")
    for lea in LOCATION_LEAS:
        insn = read_va(data, segs, lea, 7)
        if lea + 7 + struct.unpack_from("<i", insn, 3)[0] != LOCATION or FN <= lea < FN_END:
            failures.append("location lea " + hex(lea))

    pkt = PACKET_JSON.read_text()
    oks = 0
    pos = pkt.index('"vectors"')
    while True:
        k = pkt.find('"expected_kind": "ok"', pos)
        if k < 0:
            break
        start = pkt.rfind('"emu": {', 0, k)
        inp = bytes.fromhex(json_str(pkt, "input_hex", start))
        pts = [tuple(int.from_bytes(inp[o + j : o + j + 32], "big") for j in (0, 32)) for o in (0, 64)]
        x, y = ec_add(p, *pts)
        want = (x.to_bytes(32, "big") + y.to_bytes(32, "big")).hex()
        if json_str(pkt, "output_hex", start) != want or json_str(pkt, "expected", start) != want:
            failures.append("vector at %d" % start)
        oks += 1
        pos = k + 1
    if oks != 3:
        failures.append("ok vector count %d" % oks)
    if hashlib.sha256(PACKET_JSON.read_bytes()).hexdigest() != JSON_SHA256:
        failures.append("json sha256")
    # Admission: hashing each listed row is not enough. It cannot see
    # a duplicated row, a listed file replaced by a symlink
    # (read_bytes follows it, so the evidence can point outside the
    # packet), an unlisted file in the packet directory, or an
    # evidence file deleted together with its row. Pin the listed set
    # and compare it against the packet contents, mirroring the RE-005
    # verifier and the node-inventory verifiers.
    listed = {}
    for line in (HERE / "MANIFEST.sha256").read_text().splitlines():
        if not line.strip():
            continue
        digest, sep, rel = line.partition("  ")
        if not sep or len(digest) != 64:
            failures.append("malformed manifest line: " + line.strip())
            continue
        if rel in listed:
            failures.append("manifest lists " + rel + " twice")
            continue
        listed[rel] = digest
    if set(listed) != PACKET_FILES:
        failures.append("manifest file set differs from pinned packet files")
    present = set()
    for entry in sorted(HERE.iterdir()):
        if entry.is_symlink():
            failures.append("packet entry is a symlink: " + entry.name)
        elif entry.is_dir():
            if entry.name != "__pycache__" or not all(
                    child.name.endswith(".pyc") and not child.is_symlink()
                    for child in entry.iterdir()):
                failures.append("unexpected directory in packet: " + entry.name)
        else:
            present.add(entry.name)
    in_packet = {rel for rel in listed if not rel.startswith("..")}
    if present - {"MANIFEST.sha256"} != in_packet:
        failures.append("packet contents differ from manifest")
    for rel, digest in listed.items():
        path = HERE / rel
        if path.is_symlink() or not path.is_file():
            failures.append("manifest entry is a symlink or not a file: " + rel)
            continue
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            failures.append("manifest " + rel)
    if failures:
        print("FAIL:", ", ".join(failures))
        return 1
    print("PASS: key_insns=%d branches=%d relas=%d ok_vectors=%d failures=0"
          % (len(KEY_INSNS), len(BRANCHES), len(RELAS), oks))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
