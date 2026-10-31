#!/usr/bin/env python3
"""RE-021 independent verifier. Imports nothing from tools/.

Checks every key VA byte against the pinned node #94 binary, re-derives the
SIGMA lea target, re-counts rol immediates with its own scanner, checks the
blake2.rs Location path bytes, recomputes EIP-152 vector outputs with an
independent portable Blake2b F, and checks the packet JSON against
MANIFEST.sha256. Prints PASS, FAIL or INCONCLUSIVE; exit 0, 1 or 2.
"""
import hashlib
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BINARY = ROOT / "artifacts" / "node" / "94" / "hl-node"
SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
PACKET_JSON = HERE / "blake2b-compress.json"
JSON_SHA256 = "dc2420392ce8f7ad5f63dbc313b8ddb8095143a91a25eef1e9a2a7663ad78f92"
FN = 0x4E9A8A0
FN_END = 0x4E9B02C
CARVED_SHA256 = "df9b7ff03af68d61cb6e574cadb5fc0081e4a38a7fd35cefd030fbebea1a8788"
SIGMA_VA = 0x7C4A90
SIGMA_LEA = 0x4E9A99E
SIGMA_LEA_TARGET = 0x7C4AD0
LOCATION_PATH_VA = 0x1E9DCB
LOCATION_PATH = (
    b"/home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/"
    b"revm-precompile-16.0.0/src/blake2.rs"
)
WRAP = 0x4E9D2A0
ADDR09_VA = 0x574F0C0
ADDR09_BYTES = b"\x00" * 19 + b"\x09"
PRECOMPILE_SLOT = 0x574F0B0
F_GOT_SLOT = 0x5776F28
R_X86_64_RELATIVE = 8

KEYS = [
    (0x4E9A8A0, "554157415641554154534881ec38010000"),
    (0x4E9A8B1, "48899424f0000000"),
    (0x4E9A8B9, "48b83ba7ca8485ae67bb"),
    (0x4E9A8C8, "48b808c9bcf367e6096a"),
    (0x4E9A8D7, "49bd79217e1319cde05b"),
    (0x4E9A8E1, "48b82bf894fe72f36e3c"),
    (0x4E9A8F0, "4c8b36"),
    (0x4E9A8F3, "49bcd182e6ad7f520e51"),
    (0x4E9A8FD, "4c3321"),
    (0x4E9A904, "49bf1f6c3e2b8c68059b"),
    (0x4E9A90E, "4c337908"),
    (0x4E9A916, "4585c0"),
    (0x4E9A919, "48b89442be0454267ce0"),
    (0x4E9A923, "49ba6bbd41fbabd9831f"),
    (0x4E9A92D, "4c0f45d0"),
    (0x4E9A94D, "4889bc24e8000000"),
    (0x4E9A955, "4885ff"),
    (0x4E9A998, "0f845d040000"),
    (0x4E9A99E, "488d352ba192fb"),
    (0x4E9A9A8, "48b8f1361d5f3af54fa5"),
    (0x4E9A9D0, "48bacdcccccccccccccc"),
    (0x4E9AC22, "49c1c420"),
    (0x4E9AC36, "49c1c028"),
    (0x4E9AC59, "49c1c730"),
    (0x4E9AC68, "48d1c5"),
    (0x4E9AEAF, "c3"),
    (0x4E9D2A0, "4156534881ec18010000"),
    (0x4E9D2AA, "48817e10d5000000"),
    (0x4E9D2B2, "7519"),
    (0x4E9D2B8, "8b18"),
    (0x4E9D2BA, "0fcb"),
    (0x4E9D2BC, "4839da"),
    (0x4E9D2F2, "0fb688d4000000"),
    (0x4E9D2F9, "80f902"),
    (0x4E9D2FC, "0f8356010000"),
    (0x4E9D3BA, "4889df"),
    (0x4E9D3BD, "ff15659b8d00"),
]

ROL_COUNTS = {"0x20": 8, "0x28": 8, "0x30": 8, "1": 8}

IV = [
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
    0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
]
SIGMA = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
]

VECTORS = {
    "vector_4_rounds0": {
        "rounds": 0, "f": 1,
        "input_hex": "0000000048c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001",
        "output_hex": "08c9bcf367e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d282e6ad7f520e511f6c3e2b8c68059b9442be0454267ce079217e1319cde05b",
    },
    "vector_5_rounds12": {
        "rounds": 12, "f": 1,
        "input_hex": "0000000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001",
        "output_hex": "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
    },
    "vector_6_rounds12_f0": {
        "rounds": 12, "f": 0,
        "input_hex": "0000000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000",
        "output_hex": "75ab69d3190a562c51aef8d88f1c2775876944407270c42c9844252c26d2875298743e7f6d5ea2f2d3e8d226039cd31b4e426ac4f2d3d666a610c2116fde4735",
    },
    "vector_7_rounds1": {
        "rounds": 1, "f": 1,
        "input_hex": "0000000148c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001",
        "output_hex": "b63a380cb2897d521994a85234ee2c181b5f844d2c624c002677e9703449d2fba551b3a8333bcdf5f2f7e08993d53923de3d64fcc68c034e717b9293fed7a421",
    },
}


def segments(data: bytes):
    e_phoff = struct.unpack_from("<Q", data, 32)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 54)
    out = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", data, o)[0]
        p_offset, p_vaddr, _, p_filesz, _, _ = struct.unpack_from("<QQQQQQ", data, o + 8)
        if p_type == 1 and p_filesz:
            out.append((p_vaddr, p_offset, p_filesz))
    return sorted(out)


def va_to_off(segs, va):
    for base, off, size in segs:
        if base <= va < base + size:
            return off + (va - base)
    raise KeyError(hex(va))


def read_va(data, segs, va, n):
    o = va_to_off(segs, va)
    return data[o:o + n]


def ror64(x, n):
    return ((x >> n) | (x << (64 - n))) & 0xFFFFFFFFFFFFFFFF


def G(v, a, b, c, d, x, y):
    v[a] = (v[a] + v[b] + x) & 0xFFFFFFFFFFFFFFFF
    v[d] = ror64(v[d] ^ v[a], 32)
    v[c] = (v[c] + v[d]) & 0xFFFFFFFFFFFFFFFF
    v[b] = ror64(v[b] ^ v[c], 24)
    v[a] = (v[a] + v[b] + y) & 0xFFFFFFFFFFFFFFFF
    v[d] = ror64(v[d] ^ v[a], 16)
    v[c] = (v[c] + v[d]) & 0xFFFFFFFFFFFFFFFF
    v[b] = ror64(v[b] ^ v[c], 63)


def blake2b_f(rounds, h, m, t, f):
    """Independent portable Blake2b F (RFC 7693 / EIP-152)."""
    v = list(h) + list(IV)
    v[12] ^= t[0]
    v[13] ^= t[1]
    if f:
        v[14] ^= 0xFFFFFFFFFFFFFFFF
    for r in range(rounds):
        s = SIGMA[r % 10]
        G(v, 0, 4, 8, 12, m[s[0]], m[s[1]])
        G(v, 1, 5, 9, 13, m[s[2]], m[s[3]])
        G(v, 2, 6, 10, 14, m[s[4]], m[s[5]])
        G(v, 3, 7, 11, 15, m[s[6]], m[s[7]])
        G(v, 0, 5, 10, 15, m[s[8]], m[s[9]])
        G(v, 1, 6, 11, 12, m[s[10]], m[s[11]])
        G(v, 2, 7, 8, 13, m[s[12]], m[s[13]])
        G(v, 3, 4, 9, 14, m[s[14]], m[s[15]])
    out = [(h[i] ^ v[i] ^ v[i + 8]) & 0xFFFFFFFFFFFFFFFF for i in range(8)]
    return b"".join(struct.pack("<Q", w) for w in out)


def count_rol(data, segs):
    blob = read_va(data, segs, FN, FN_END - FN)
    counts = {"0x20": 0, "0x28": 0, "0x30": 0, "1": 0}
    i = 0
    while i + 3 < len(blob):
        b0, b1, b2 = blob[i], blob[i + 1], blob[i + 2]
        if b0 in (0x48, 0x49) and b1 == 0xC1 and (b2 & 0xF8) == 0xC0:
            imm = blob[i + 3]
            if imm in (0x20, 0x28, 0x30):
                counts[hex(imm)] += 1
            i += 4
            continue
        if b0 in (0x48, 0x49) and b1 == 0xD1 and (b2 & 0xF8) == 0xC0:
            counts["1"] += 1
            i += 3
            continue
        i += 1
    return counts


def check_keys(data):
    failures = []
    if hashlib.sha256(data).hexdigest() != SHA256:
        return ["binary sha256 mismatch"]
    segs = segments(data)
    carved = read_va(data, segs, FN, FN_END - FN)
    if hashlib.sha256(carved).hexdigest() != CARVED_SHA256:
        failures.append("carved sha256")
    if len(carved) != 1932:
        failures.append("carved len")
    for va, hx in KEYS:
        raw = read_va(data, segs, va, len(hx) // 2)
        if raw.hex() != hx:
            failures.append(f"key_insn {hex(va)}")
    lea = read_va(data, segs, SIGMA_LEA, 7)
    disp = struct.unpack_from("<i", lea, 3)[0]
    if SIGMA_LEA + 7 + disp != SIGMA_LEA_TARGET:
        failures.append("sigma lea target")
    sigma0 = [struct.unpack_from("<Q", read_va(data, segs, SIGMA_VA, 128), i * 8)[0] for i in range(16)]
    if sigma0 != list(range(16)):
        failures.append("sigma0")
    if read_va(data, segs, LOCATION_PATH_VA, len(LOCATION_PATH)) != LOCATION_PATH:
        failures.append("location path")
    if count_rol(data, segs) != ROL_COUNTS:
        failures.append("rol_counts")
    for name, spec in VECTORS.items():
        inp = bytes.fromhex(spec["input_hex"])
        if len(inp) != 213:
            failures.append(f"{name} input len")
            continue
        rounds = int.from_bytes(inp[0:4], "big")
        h = [struct.unpack_from("<Q", inp, 4 + i * 8)[0] for i in range(8)]
        m = [struct.unpack_from("<Q", inp, 68 + i * 8)[0] for i in range(16)]
        t = [struct.unpack_from("<Q", inp, 196 + i * 8)[0] for i in range(2)]
        f = inp[212]
        if rounds != spec["rounds"] or f != spec["f"]:
            failures.append(f"{name} parse")
            continue
        out = blake2b_f(rounds, h, m, t, bool(f))
        if out.hex() != spec["output_hex"]:
            failures.append(f"{name} ref mismatch")
    # HyperEVM 0x09 wiring pins
    if read_va(data, segs, ADDR09_VA, 20) != ADDR09_BYTES:
        failures.append("address_0x09")
    call = read_va(data, segs, 0x4E9D3BD, 6)
    if call.hex() != "ff15659b8d00":
        failures.append("call_indirect")
    disp = struct.unpack_from("<i", call, 2)[0]
    if 0x4E9D3BD + 6 + disp != F_GOT_SLOT:
        failures.append("call_indirect_slot")
    if read_va(data, segs, 0x4E9D2AA, 8).hex() != "48817e10d5000000":
        failures.append("input_len_0xd5")
    if read_va(data, segs, 0x4E9D2BA, 2).hex() != "0fcb":
        failures.append("rounds_bswap")
    if read_va(data, segs, 0x4E9D2F9, 3).hex() != "80f902":
        failures.append("final_flag_cmp")
    if read_va(data, segs, 0x4E9D2BC, 3).hex() != "4839da":
        failures.append("gas_cmp")
    # RELA pins
    e_shoff = struct.unpack_from("<Q", data, 40)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
    shstr_hdr = e_shoff + e_shstrndx * e_shentsize
    shstr_off = struct.unpack_from("<Q", data, shstr_hdr + 24)[0]
    shstr_sz = struct.unpack_from("<Q", data, shstr_hdr + 32)[0]
    shstr = data[shstr_off:shstr_off + shstr_sz]
    found_wrap = found_f = False
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        name_off = struct.unpack_from("<I", data, o)[0]
        name = shstr[name_off:shstr.find(b"\x00", name_off)]
        if name != b".rela.dyn":
            continue
        off = struct.unpack_from("<Q", data, o + 24)[0]
        size = struct.unpack_from("<Q", data, o + 32)[0]
        for k in range(size // 24):
            r_offset, r_info, r_addend = struct.unpack_from("<QQq", data, off + k * 24)
            if (r_offset == PRECOMPILE_SLOT and r_addend == WRAP
                    and (r_info & 0xFFFFFFFF) == R_X86_64_RELATIVE):
                found_wrap = True
            if (r_offset == F_GOT_SLOT and r_addend == FN
                    and (r_info & 0xFFFFFFFF) == R_X86_64_RELATIVE):
                found_f = True
    if not found_wrap:
        failures.append("wrap_rela")
    if not found_f:
        failures.append("f_rela")
    return failures


def check_packet():
    failures = []
    if not PACKET_JSON.is_file():
        return ["missing packet json"]
    raw = PACKET_JSON.read_bytes()
    if hashlib.sha256(raw).hexdigest() != JSON_SHA256:
        failures.append("json sha256")
    try:
        obj = __import__("json").loads(raw)
    except Exception:
        return ["json parse"]
    if obj.get("key_insns_count") != len(KEYS):
        failures.append("key_insns_count")
    if obj.get("carved_sha256") != CARVED_SHA256:
        failures.append("json carved")
    if obj.get("behavioural_proof") != "unicorn_emulation_of_carved_function_bytes":
        failures.append("behavioural_proof field")
    w = obj.get("hyperevm_precompile_wiring") or {}
    if w.get("status") != "statically_shown":
        failures.append("wiring_status")
    if w.get("gas_per_round") != 1:
        failures.append("wiring_gas")
    if w.get("address_0x09_bytes") != ADDR09_BYTES.hex():
        failures.append("wiring_addr09_json")
    for name, spec in VECTORS.items():
        v = obj.get("eip152_vectors", {}).get(name)
        if not v or v.get("expected_output_hex") != spec["output_hex"]:
            failures.append(f"json {name}")
        elif not v.get("byte_identical"):
            failures.append(f"json {name} not identical")
    man = HERE / "MANIFEST.sha256"
    if man.is_file():
        for line in man.read_text().splitlines():
            if not line.strip():
                continue
            digest, rel = line.split(None, 1)
            target = HERE / rel if not rel.startswith("../") else (HERE / rel).resolve()
            # MANIFEST paths are relative to packet dir
            path = (HERE / rel).resolve()
            if not path.is_file():
                # try from ROOT-relative via packet-relative ../
                path = (HERE / rel)
            if not path.is_file():
                failures.append(f"manifest missing {rel}")
                continue
            if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                failures.append(f"manifest {rel}")
    return failures


def main():
    if not BINARY.is_file():
        print("INCONCLUSIVE: binary missing")
        return 2
    data = BINARY.read_bytes()
    failures = check_keys(data) + check_packet()
    status = "PASS" if not failures else "FAIL"
    print("%s: key_insns=%d vectors=%d failures=%d" % (
        status, len(KEYS), len(VECTORS), len(failures)))
    for f in failures:
        print("FAIL", f)
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
