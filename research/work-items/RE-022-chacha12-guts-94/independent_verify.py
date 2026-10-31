#!/usr/bin/env python3
"""RE-022 independent verifier. Imports only hashlib, pathlib, struct.

Checks every key VA byte against the pinned node #94 binary, re-derives the
expand rip target and caller GOT slot, checks the guts.rs Location pin (VA/len/sha256/suffix),
recomputes ChaCha20/12/8 4x reference outputs, and checks the packet JSON
hash. Prints PASS or FAIL; exit 0 or 1.
"""
import hashlib
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BINARY = ROOT / "artifacts" / "node" / "94" / "hl-node"
SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
PACKET_JSON = HERE / "chacha12-guts.json"
JSON_SHA256 = "146a164a1fbc9be96ede3696385ee093560a303539b890fc68707f6770d9c3ab"
FN = 0x4E13780
FN_RET = 0x4E13E59
CARVED_SHA256 = "1bea6b14e546e8037c041345946203e3994be41e7b83d5c75eca60d40da59eae"
EXPAND_VA = 0x204670
LOCATION_PATH_VA = 0x1E6959
LOCATION_PATH_LEN = 95
LOCATION_PATH_SHA256 = "79cee213bb7bba7155a035070bbc1abed8bd176a9839bdb674df8816801602b7"
LOCATION_PATH_SUFFIX = "rand_chacha-0.3.1/src/guts.rs"
WRAP = 0x4E14560
WRAP_E9 = 0x4E14DB7
GOT_SLOT = 0x576E900
CALLER = 0x13C9ED2
R_X86_64_RELATIVE = 8

KEY_INSNS = [
    (0x4E13780, "4883ec28"),
    (0x4E13784, "660f6f1f"),
    (0x4E13788, "66440f6f6f10"),
    (0x4E1378E, "660f6f7f20"),
    (0x4E13800, "85f6"),
    (0x4E13815, "0f840a050000"),
    (0x4E1381B, "66440f6f0d4c0e3ffb"),
    (0x4E13CDE, "ffce"),
    (0x4E13CE0, "0f859afbffff"),
    (0x4E13E55, "4883c428"),
    (0x4E13E59, "c3"),
    (0x4E14560, "55"),
    (0x4E1456D, "488b1ddc9d9500"),
    (0x4E14DB7, "e9c4e9ffff"),
    (0x13C9E99, "498dbe20010000"),
    (0x13C9EBC, "4881c100ffffff"),
    (0x13C9EC3, "49898e58010000"),
    (0x13C9ECA, "be06000000"),
    (0x13C9ECF, "4889c2"),
    (0x13C9ED2, "ff15284a3a04"),
]

EXPECTED_VECTORS = {
    "chacha20_ndr10_ctr0_nonce0": "39fd2b7dd9c5196a8dbd0377b8dc4a498a35d86fbcde6accb2cc7d4cd8ea24922b23cce7a26023ab3f0eef693ac87f64258235eab1f7a32dc22762a0485b410c18b84231ade6a6d113615c61af434e27f8b1f3f5e1ad5b5cecf8fc122a35755c7208086dd1ee3c5d9d815824640e003c9ba0f65ede5d59ce0d2a4a7f31955acd42f22ddca74a92d56ca78aef298e723b60237f3647eabeb7f3e09c30ce80e3e284a8021b8a5c0b2494cd3c8d5b13507ec7e7a0784df4a3e2ea8162d261c59d23e7ab11c0f73c3b7eb0983950b3e2c4a08f843da95fb7fcb3f13456816b51b7824df2f9bd5613d4b4ed952fd858cd1b984acbf8ff1fd1a7c806d81ca8e4ae3b2c",
    "chacha12_ndr6_ctr0_nonce0": "f231f9ffd17ac65e4405f325d7e940aa4913601fc2be46bce9c3cac3d91a1a365940b308c2857c9f29d6e2548528d49a612b1b0ae6765d16e585aefb463688796cfa9aa0833b72e0db5c15523dd18346358e0ceb2e1b6448049d30327eee851622c65ea358aab7d50d49d2d9151bebc0d9d4261f48cc6c657f8a2b3ce7e08f88fe769153ca48a6f44c778ee379c8783d035da5d9969d22db0209962b74d41715b335ddd9bc9c6d374448c3be176d97871118fef03017bf1702201e35cccdf04145678a22ab58e907ab41780ba4675d0750688c7c3b06579e180c27629b33827be633b89bd5039035393a9866cbb09f00135c36fa5794f5457938255a2166624b",
    "chacha8_ndr4_ctr0_nonce0": "4015b28f6e12ab6ad9e8667b31c51233f78f172790b2d94f326b2ed7ffbcbecbff9ead365f89ce3b6f4055bc759d90fd8f831d27c7b0df93b3b9ed8238a256d6761a6e0fc8b2b859f5a9f3ae170a7599b0b023ce79d7659b32ee79373e727289712ff289f30f641fcd822ff8e656ffd8725691f839a7b433a5b61053d99baee042777fee89b729f64c36f0da14fe6b486409d7023b34b22d364a2a718f4f888e27b18e0f0ad18a245b6f39720c7083ef7fe327c8768a762d647830246daef63959b423fcd539ddad10690d9285404106a864e35bcb83afa33009c07ae094e222f9bcf75b1d656dce4cbed17b3e6e8721a8bf09fda8ffd986da2022263cecb493",
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
            return data[o:o + n]
    raise KeyError(hex(va))


def rotl32(v, n):
    return ((v << n) | (v >> (32 - n))) & 0xffffffff


def qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xffffffff; s[d] ^= s[a]; s[d] = rotl32(s[d], 16)
    s[c] = (s[c] + s[d]) & 0xffffffff; s[b] ^= s[c]; s[b] = rotl32(s[b], 12)
    s[a] = (s[a] + s[b]) & 0xffffffff; s[d] ^= s[a]; s[d] = rotl32(s[d], 8)
    s[c] = (s[c] + s[d]) & 0xffffffff; s[b] ^= s[c]; s[b] = rotl32(s[b], 7)


def double_round(w):
    qr(w, 0, 4, 8, 12); qr(w, 1, 5, 9, 13); qr(w, 2, 6, 10, 14); qr(w, 3, 7, 11, 15)
    qr(w, 0, 5, 10, 15); qr(w, 1, 6, 11, 12); qr(w, 2, 7, 8, 13); qr(w, 3, 4, 9, 14)


def block(key, ctr, n64, ndr):
    st = list(struct.unpack("<16I", b"expand 32-byte k" + key + struct.pack("<QQ", ctr, n64)))
    w = st[:]
    for _ in range(ndr):
        double_round(w)
    return struct.pack("<16I", *[(w[i] + st[i]) & 0xffffffff for i in range(16)])


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
    if read_va(data, segs, EXPAND_VA, 16) != b"expand 32-byte k":
        failures.append("expand")
    exp = read_va(data, segs, 0x4E1381B, 9)
    if 0x4E1381B + 9 + struct.unpack_from("<i", exp, 5)[0] != EXPAND_VA:
        failures.append("expand rip")
    loc_raw = read_va(data, segs, LOCATION_PATH_VA, LOCATION_PATH_LEN)
    if len(loc_raw) != LOCATION_PATH_LEN:
        failures.append("location len")
    if hashlib.sha256(loc_raw).hexdigest() != LOCATION_PATH_SHA256:
        failures.append("location sha256")
    if not loc_raw.decode("ascii", errors="replace").endswith(LOCATION_PATH_SUFFIX):
        failures.append("location suffix")
    e9 = read_va(data, segs, WRAP_E9, 5)
    if WRAP_E9 + 5 + struct.unpack_from("<i", e9, 1)[0] != FN:
        failures.append("wrapper e9")
    call = read_va(data, segs, CALLER, 6)
    if CALLER + 6 + struct.unpack_from("<i", call, 2)[0] != GOT_SLOT:
        failures.append("caller got")
    e_shoff = struct.unpack_from("<Q", data, 40)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
    shstr_hdr = e_shoff + e_shstrndx * e_shentsize
    shstr_off = struct.unpack_from("<Q", data, shstr_hdr + 24)[0]
    shstr_sz = struct.unpack_from("<Q", data, shstr_hdr + 32)[0]
    shstr = data[shstr_off:shstr_off + shstr_sz]
    found = False
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        name_off = struct.unpack_from("<I", data, o)[0]
        name = shstr[name_off:shstr.find(bytes([0]), name_off)]
        if name == b".rela.dyn":
            off = struct.unpack_from("<Q", data, o + 24)[0]
            size = struct.unpack_from("<Q", data, o + 32)[0]
            for k in range(size // 24):
                r_offset, r_info, r_addend = struct.unpack_from("<QQq", data, off + k * 24)
                if (r_offset == GOT_SLOT and (r_info & 0xFFFFFFFF) == R_X86_64_RELATIVE
                        and r_addend == WRAP):
                    found = True
            break
    if not found:
        failures.append("rela")
    key = bytes(range(32))
    for name, ndr in (("chacha20_ndr10_ctr0_nonce0", 10),
                      ("chacha12_ndr6_ctr0_nonce0", 6),
                      ("chacha8_ndr4_ctr0_nonce0", 4)):
        out = b"".join(block(key, i, 0, ndr) for i in range(4))
        if out.hex() != EXPECTED_VECTORS[name]:
            failures.append("vector " + name)
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
    print("PASS: key_insns=%d vectors=%d failures=0" % (len(KEY_INSNS), len(EXPECTED_VECTORS)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
