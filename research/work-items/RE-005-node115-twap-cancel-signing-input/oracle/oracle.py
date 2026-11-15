#!/usr/bin/env python3
"""Independent oracle for the node #115 twapCancel signing input (RE-005).

Standard library only. Nothing here imports or copies the Rust crate, the
`node115-sponge-permutation` source, or `node115-twap-action-wire`.

Specifications used (all public):
  * MessagePack specification, "Formats" section: positive fixint (0x00-0x7f),
    uint 8/16/32/64 (0xcc/0xcd/0xce/0xcf, big-endian), fixstr (0xa0|len, len<=31),
    fixmap (0x80|len, len<=15). Smallest-width integers are what the target
    writer selects (observed in the binary, see the packet README).
  * FIPS 202 section 3 for Keccak-f[1600]. The round constants are generated
    from the rc(t) LFSR of Algorithm 5 and the rho offsets from the (t+1)(t+2)/2
    walk of Algorithm 2, so no table is shared with any Rust source.
  * Keccak submission padding pad10*1 with domain byte 0x01 (original Keccak,
    capacity 512, rate 136) -- "Keccak-256". FIPS 202 SHA3-256 differs only in
    the domain byte (0x06).

Keccak-256 is validated before any row is written:
  * public vectors: Keccak-256("") = c5d24601...a470,
    Keccak-256("abc") = 4e03657a...6c45 (Ethereum/Keccak team test vectors),
    Keccak-256("The quick brown fox jumps over the lazy dog") = 4d741b6f...aa15;
  * the permutation and sponge are cross-checked against the standard library
    `hashlib.sha3_256` (domain byte 0x06) for lengths 0..400, which exercises
    single and multi-block absorption.

Usage: oracle.py --outdir NEW_DIR              (writes corpus.tsv)
       oracle.py --outdir NEW_DIR --selftest   (guard controls, see selftest())
NEW_DIR must not exist and, after resolving symlinks and "..", must not lie
inside the packet or the crate directory (exit 4, nothing is written).
Exit codes: 0 ok; 1 failed check or selftest; 2 usage; 4 --outdir refused.
"""
import argparse
import hashlib
import os
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.realpath(__file__))
PACKET = os.path.dirname(HERE)
CRATE = os.path.realpath(os.path.join(PACKET, "..", "..", "..", "src", "node115-twap-cancel-signing-input"))
SHIPPED_CORPUS = os.path.join(CRATE, "tests", "oracle", "corpus.tsv")

# ---------------------------------------------------------------- Keccak ----
MASK = (1 << 64) - 1


def _rc_bit(t):
    # FIPS 202 Algorithm 5: rc(t) over GF(2)[x]/(x^8+x^6+x^5+x^4+1)
    if t % 255 == 0:
        return 1
    r = 1
    for _ in range(t % 255):
        r <<= 1
        if r & 0x100:
            r ^= 0x171
    return r & 1


def _round_constants():
    out = []
    for ir in range(24):
        c = 0
        for j in range(7):
            if _rc_bit(j + 7 * ir):
                c |= 1 << ((1 << j) - 1)
        out.append(c)
    return out


def _rho_offsets():
    r = [[0] * 5 for _ in range(5)]
    x, y = 1, 0
    for t in range(24):
        r[x][y] = ((t + 1) * (t + 2) // 2) % 64
        x, y = y, (2 * x + 3 * y) % 5
    return r


RC = _round_constants()
RHO = _rho_offsets()


def _rol(v, n):
    n %= 64
    return ((v << n) | (v >> (64 - n))) & MASK if n else v


def keccak_f(a):
    """a[x][y] lanes; FIPS 202 theta, rho, pi, chi, iota."""
    for ir in range(24):
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol(a[x][y], RHO[x][y])
        a = [[b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y] & MASK) for y in range(5)]
             for x in range(5)]
        a[0][0] ^= RC[ir]
    return a


def sponge(data, domain, outlen=32, rate=136):
    state = [[0] * 5 for _ in range(5)]
    padded = bytearray(data)
    padded.append(domain)
    while len(padded) % rate:
        padded.append(0)
    padded[-1] |= 0x80
    for off in range(0, len(padded), rate):
        block = padded[off:off + rate]
        for i in range(rate // 8):
            lane = int.from_bytes(block[8 * i:8 * i + 8], "little")
            state[i % 5][i // 5] ^= lane
        state = keccak_f(state)
    out = b"".join(state[i % 5][i // 5].to_bytes(8, "little") for i in range(25))
    return out[:outlen]


def keccak256(data):
    return sponge(data, 0x01)


PUBLIC_VECTORS = [
    (b"", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
    (b"abc", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"),
    (b"The quick brown fox jumps over the lazy dog",
     "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15"),
]


def selfcheck_keccak():
    for msg, want in PUBLIC_VECTORS:
        got = keccak256(msg).hex()
        if got != want:
            sys.exit("oracle: Keccak-256 public vector mismatch for %r: %s" % (msg, got))
    for n in range(0, 401):
        msg = bytes((i * 7 + n) & 0xFF for i in range(n))
        if sponge(msg, 0x06) != hashlib.sha3_256(msg).digest():
            sys.exit("oracle: sponge disagrees with hashlib.sha3_256 at length %d" % n)


# -------------------------------------------------------------- MessagePack --
def mp_uint(n):
    assert 0 <= n < 1 << 64
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return b"\xcc" + n.to_bytes(1, "big")
    if n < 0x10000:
        return b"\xcd" + n.to_bytes(2, "big")
    if n < 0x100000000:
        return b"\xce" + n.to_bytes(4, "big")
    return b"\xcf" + n.to_bytes(8, "big")


def mp_fixstr(s):
    b = s.encode("ascii")
    assert len(b) <= 31
    return bytes([0xA0 | len(b)]) + b


def mp_fixmap(n):
    assert 0 <= n <= 15
    return bytes([0x80 | n])


def cancel_map(a, t):
    return (mp_fixmap(3) + mp_fixstr("type") + mp_fixstr("twapCancel")
            + mp_fixstr("a") + mp_uint(a) + mp_fixstr("t") + mp_uint(t))


def suffix(nonce, vault, expiry):
    out = struct.pack(">Q", nonce)
    out += (b"\x01" + vault) if vault is not None else b"\x00"
    if expiry is not None:
        out += b"\x00" + struct.pack(">Q", expiry)
    return out


def signing_input(a, t, nonce, vault, expiry):
    return cancel_map(a, t) + suffix(nonce, vault, expiry)


def chain_tag(selector):
    return 0x61 if (selector & 0xFF) == 3 else 0x62


def record_image(tag, digest):
    """88-byte returned record with the tag-string pointer word left zero."""
    return struct.pack("<QQQ", 1, 0, 1) + digest + struct.pack("<Q", 0x539) + bytes(24)


# ------------------------------------------------------------------ corpus --
U32 = 0xFFFFFFFF
U64 = 0xFFFFFFFFFFFFFFFF
A_VALUES = [0, 1, 127, 128, 255, 256, 65535, 65536, 0x7FFFFFFF, 0x80000000, U32]
T_VALUES = [0, 1, 2, 127, 128, 255, 256, 65535, 65536, U32, U32 + 1, 1 << 63, U64 - 1, U64]
NONCE0 = 0x0102030405060708
VAULT0 = bytes(range(0xA0, 0xB4))
EXPIRY0 = 0x1122334455667788
SELECTORS = [0, 1, 2, 3, 4, 5, 0x61, 0x62, 0x80, 0xFF, 0x100, 0x103, 0x203, 0xFFFFFF03, 0x7FFFFFFF, U32]
COMBOS = [(None, None), (None, EXPIRY0), (VAULT0, None), (VAULT0, EXPIRY0)]


class SplitMix:
    def __init__(self, seed):
        self.s = seed & MASK

    def next(self):
        self.s = (self.s + 0x9E3779B97F4A7C15) & MASK
        z = self.s
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK
        return z ^ (z >> 31)


def rows():
    out = []

    def add(cls, a, t, nonce, vault, expiry, selector):
        out.append((cls, a, t, nonce, vault, expiry, selector))

    add("anchor", 1, 2, NONCE0, None, None, 3)
    for a in A_VALUES:
        for t in T_VALUES:
            add("int-grid", a, t, NONCE0, None, None, 3)
    for vault, expiry in COMBOS:
        for a, t in [(1, 2), (127, 128), (255, 256), (65535, 65536), (U32, U32 + 1), (U32, U64), (0, 0)]:
            for sel in (3, 4):
                add("suffix-combo", a, t, NONCE0, vault, expiry, sel)
    for sel in SELECTORS:
        for vault, expiry in COMBOS:
            add("selector", 7, 300, NONCE0, vault, expiry, sel)
    for nonce in (0, 1, 255, 256, U32, U32 + 1, 1 << 63, U64):
        for vault, expiry in COMBOS:
            add("nonce", 7, 300, nonce, vault, expiry, 3)
    for i in range(8):
        add("nonce-byte", 7, 300, 0xFF << (8 * i), None, None, 3)
    for i in range(20):
        v = bytearray(20)
        v[i] = 0xFF
        add("vault-byte", 7, 300, NONCE0, bytes(v), None, 3)
    add("vault-zero", 7, 300, NONCE0, bytes(20), None, 3)
    add("vault-zero", 7, 300, NONCE0, bytes(20), 0, 3)
    for expiry in (0, 1, 127, 128, 255, 256, 65535, 65536, U32, U32 + 1, U64):
        for vault in (None, VAULT0):
            add("expiry", 7, 300, NONCE0, vault, expiry, 3)
    # field changes one at a time against the anchor
    add("single-change", 2, 2, NONCE0, None, None, 3)
    add("single-change", 1, 3, NONCE0, None, None, 3)
    add("single-change", 1, 2, NONCE0 + 1, None, None, 3)
    add("single-change", 1, 2, NONCE0, bytes(20), None, 3)
    add("single-change", 1, 2, NONCE0, None, 0, 3)
    add("single-change", 1, 2, NONCE0, None, None, 2)
    rng = SplitMix(0x1337)
    for _ in range(300):
        r = rng.next()
        a = rng.next() & (U32 >> (r & 31))
        t = rng.next() >> ((r >> 8) % 64)
        nonce = rng.next()
        vault = None
        if r & 0x10000:
            vault = b"".join(rng.next().to_bytes(8, "little") for _ in range(3))[:20]
        expiry = rng.next() >> ((r >> 20) % 64) if r & 0x20000 else None
        add("random", a, t, nonce, vault, expiry, (r >> 40) & U32)
    return out


def render(row):
    cls, a, t, nonce, vault, expiry, selector = row
    data = signing_input(a, t, nonce, vault, expiry)
    digest = keccak256(data)
    tag = chain_tag(selector)
    return [cls, str(a), str(t), "%016x" % nonce, vault.hex() if vault is not None else "-",
            str(expiry) if expiry is not None else "-", str(selector), data.hex(), digest.hex(),
            "%02x" % tag, record_image(tag, digest).hex()]


HEADER = ("#class\ta\tt\tnonce_hex\tvault_hex\texpiry\tselector\tinput_hex\tdigest_hex\ttag_hex\trecord_hex")


def refuse_outdir(outdir):
    """Reason to refuse, or None. Works on the resolved path (symlinks, "..")."""
    real = os.path.realpath(outdir)
    if os.path.exists(real):
        return "--outdir already exists; give a new directory"
    for name, root in (("packet", PACKET), ("crate", CRATE)):
        if real == root or real.startswith(root + os.sep):
            return "--outdir lies inside the %s" % name
    return None


def snapshot(*roots):
    seen = set()
    for root in roots:
        for base, dirs, files in os.walk(root):
            seen.update(os.path.join(base, n) for n in dirs + files)
    return seen


def selftest(args):
    """Guard controls. A baseline run must succeed first; every refusal must exit 4
    and leave the packet and crate directories exactly as they were."""
    os.makedirs(args.outdir)
    me = os.path.abspath(__file__)
    work = args.outdir
    results = []

    def run(*extra):
        return subprocess.run([sys.executable, "-I", me] + list(extra), capture_output=True, text=True, timeout=600)

    def record(name, ok):
        results.append((name, ok))
        print("selftest %-58s %s" % (name, "ok" if ok else "FAIL"))

    before = snapshot(PACKET, CRATE)
    ok_dir = os.path.join(work, "baseline")
    r = run("--outdir", ok_dir)
    record("baseline: fresh outdir, exit 0", r.returncode == 0)
    try:
        with open(os.path.join(ok_dir, "corpus.tsv"), "rb") as a, open(SHIPPED_CORPUS, "rb") as b:
            same = a.read() == b.read()
    except OSError:
        same = False
    record("baseline: corpus byte-identical to the shipped corpus", same)
    if not all(ok for _n, ok in results):
        print("selftest: baseline failed; the refusal controls would prove nothing")
        return 1

    def refused(name, outdir, leftover=None):
        r = run("--outdir", outdir)
        gone = leftover is None or not os.path.exists(leftover)
        record(name, r.returncode == 4 and gone)

    refused("existing outdir refused (exit 4)", ok_dir)
    refused("new path inside the packet refused (exit 4)", os.path.join(PACKET, "selftest-new-out"),
            os.path.join(PACKET, "selftest-new-out"))
    refused("new path inside the crate refused (exit 4)", os.path.join(CRATE, "tests", "selftest-new-out"),
            os.path.join(CRATE, "tests", "selftest-new-out"))
    refused("packet path spelled with .. refused (exit 4)", os.path.join(PACKET, "oracle", "..", "selftest-new-out"),
            os.path.join(PACKET, "selftest-new-out"))
    for name, root in (("packet", PACKET), ("crate", CRATE)):
        link = os.path.join(work, "link-" + name)
        os.symlink(root, link)
        refused("new path below a symlink to the %s refused (exit 4)" % name,
                os.path.join(link, "selftest-new-out"), os.path.join(root, "selftest-new-out"))
    dangling = os.path.join(work, "dangling")
    os.symlink(os.path.join(PACKET, "selftest-dangling"), dangling)
    refused("dangling symlink into the packet refused (exit 4)", dangling,
            os.path.join(PACKET, "selftest-dangling"))
    r = run()
    record("missing --outdir refused (exit 2)", r.returncode == 2)
    record("packet and crate directories unchanged", snapshot(PACKET, CRATE) == before)
    failed = [n for n, ok in results if not ok]
    print("selftest: %d/%d controls passed" % (len(results) - len(failed), len(results)))
    return 1 if failed else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--outdir", required=True, help="new directory; not existing, not inside the packet or crate")
    ap.add_argument("--selftest", action="store_true", help="run the --outdir guard controls instead")
    args = ap.parse_args()
    why = refuse_outdir(args.outdir)
    if why:
        sys.stderr.write("oracle: %s\n" % why)
        return 4
    if args.selftest:
        return selftest(args)
    selfcheck_keccak()
    anchor = signing_input(1, 2, NONCE0, None, None).hex()
    if anchor != "83a474797065aa7477617043616e63656ca16101a17402010203040506070800":
        sys.exit("oracle: scout anchor input bytes mismatch: " + anchor)
    os.makedirs(os.path.realpath(args.outdir))
    lines = ["# RE-005 twapCancel signing-input oracle corpus. Generated by oracle.py; see ORACLE_FROZEN.txt.",
             HEADER]
    for row in rows():
        lines.append("\t".join(render(row)))
    with open(os.path.join(os.path.realpath(args.outdir), "corpus.tsv"), "w", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")
    print("oracle: wrote %d rows; Keccak public vectors and hashlib cross-check passed" % (len(lines) - 2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
