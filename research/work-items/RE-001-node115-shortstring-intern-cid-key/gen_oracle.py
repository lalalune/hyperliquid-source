#!/usr/bin/env python3
"""Oracle corpus for the node #115 long-name key path (entry 0x1546aa0), written before the Rust.

Hand-coded SipHash-1-3 (zero key) after the SipHash paper (Aumasson/Bernstein),
checked three ways before any corpus line is trusted:
  1. the paper's published SipHash-2-4 vector (key 00..0f, message 00..0e -> a129ca6149be45e5)
     through the same (c, d)-round code;
  2. CPython's own C siphash13 (`hash(bytes)` with PYTHONHASHSEED=0, zero key, cutoff 0) in a
     child interpreter, on every message the corpus uses (a hash of -1 is reported as -2 by
     CPython, so a value of 2**64-2 is skipped, not compared);
  3. the three scouting values from SCOUT.md (also CPython-derived).
The cache model is a plain dict. Nothing here is imported from, or shares code with, the crate.

What the corpus says is what the #115 bytes do (see README.md), not what a standard says:
the message is name || 0xff || i32 little-endian index (4 bytes, not 8), i = 0..9, the
character is 'A' + (hash % 26), the ten characters are packed little-endian into a u128,
names of 16 bytes or fewer skip all of it, and a new long name is cached only while the cache
holds at most 99,999 entries.

usage: gen_oracle.py --outdir NEW_DIR
NEW_DIR must not exist (its parent must) and must not be inside this packet or the crate
directory. Writes corpus.txt only.
"""
import argparse
import os
import random
import subprocess
import sys

HERE = os.path.dirname(os.path.realpath(__file__))
CRATE = os.path.realpath(os.path.join(HERE, "..", "..", "..", "src", "node115-shortstring-intern"))
M64 = (1 << 64) - 1


def rotl(x, b):
    return ((x << b) | (x >> (64 - b))) & M64


def siphash(msg, c, d, k0=0, k1=0):
    v = [k0 ^ 0x736F6D6570736575, k1 ^ 0x646F72616E646F6D, k0 ^ 0x6C7967656E657261, k1 ^ 0x7465646279746573]

    def rounds(n):
        for _ in range(n):
            v[0] = (v[0] + v[1]) & M64
            v[1] = rotl(v[1], 13) ^ v[0]
            v[0] = rotl(v[0], 32)
            v[2] = (v[2] + v[3]) & M64
            v[3] = rotl(v[3], 16) ^ v[2]
            v[0] = (v[0] + v[3]) & M64
            v[3] = rotl(v[3], 21) ^ v[0]
            v[2] = (v[2] + v[1]) & M64
            v[1] = rotl(v[1], 17) ^ v[2]
            v[2] = rotl(v[2], 32)

    full = len(msg) - len(msg) % 8
    for i in range(0, full, 8):
        m = int.from_bytes(msg[i:i + 8], "little")
        v[3] ^= m
        rounds(c)
        v[0] ^= m
    b = ((len(msg) & 0xFF) << 56) | int.from_bytes(msg[full:], "little")
    v[3] ^= b
    rounds(c)
    v[0] ^= b
    v[2] ^= 0xFF
    rounds(d)
    return v[0] ^ v[1] ^ v[2] ^ v[3]


def sip13(msg):
    return siphash(msg, 1, 3)


def index_msg(name, i):
    return name + b"\xff" + i.to_bytes(4, "little")


def chars_of(name):
    return bytes(0x41 + sip13(index_msg(name, i)) % 26 for i in range(10))


def key_of(name):
    if len(name) <= 16:
        return int.from_bytes(name, "little")
    return int.from_bytes(chars_of(name), "little")


class Cache:
    """dict; a new long name is stored only while len(d) <= 99_999."""

    def __init__(self):
        self.d = {}

    def intern(self, name):
        if len(name) <= 16:
            return key_of(name), "short"
        if name in self.d:
            return key_of(name), "hit"      # the stored value is the same function of the name
        k = key_of(name)
        if len(self.d) <= 99999:
            self.d[name] = None
            return k, "miss_inserted"
        return k, "miss_not_inserted"

    def fill(self, n):
        """n cache-fill names through the same rule, without hashing them (only membership matters)."""
        for i in range(n):
            if len(self.d) <= 99999:
                self.d[fill_name(i)] = None


def fill_name(n):
    return b"cache-fill-%08d" % n


def check_outdir(path):
    p = os.path.realpath(path)
    if os.path.lexists(path):
        sys.exit("refusing: %s already exists" % path)
    if not os.path.isdir(os.path.dirname(p)):
        sys.exit("refusing: parent directory of --outdir must exist")
    for guard in (HERE, CRATE):
        if p == guard or p.startswith(guard + os.sep):
            sys.exit("refusing: --outdir is inside the packet or the crate")


def cpython_crosscheck(msgs):
    """hash() of each message in a child CPython with PYTHONHASHSEED=0; returns (compared, skipped)."""
    code = ("import sys\nfor l in sys.stdin:\n    print(hash(bytes.fromhex(l.strip())) & (2**64-1))\n")
    env = {"PATH": os.environ.get("PATH", ""), "PYTHONHASHSEED": "0"}
    r = subprocess.run([sys.executable, "-c", code], input="".join(m.hex() + "\n" for m in msgs),
                       capture_output=True, text=True, env=env)
    if r.returncode != 0:
        sys.exit("tool error: child CPython failed: " + r.stderr[-500:])
    got = [int(x) for x in r.stdout.split()]
    if len(got) != len(msgs):
        sys.exit("tool error: child CPython returned %d of %d" % (len(got), len(msgs)))
    compared = skipped = 0
    for m, g in zip(msgs, got):
        want = sip13(m)
        if not m:  # CPython defines hash(b"") as 0 without hashing
            skipped += 1
            continue
        if g == M64 - 1:  # CPython maps a hash of -1 to -2: cannot tell the two apart
            skipped += 1
            continue
        if g != want:
            sys.exit("ORACLE DISAGREES with CPython siphash13 on %s: %016x vs %016x" % (m.hex(), want, g))
        compared += 1
    return compared, skipped


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--outdir", required=True)
    a = ap.parse_args()
    check_outdir(a.outdir)

    # 1. paper vector through the (c, d) code
    k0, k1 = int.from_bytes(bytes(range(8)), "little"), int.from_bytes(bytes(range(8, 16)), "little")
    if siphash(bytes(range(15)), 2, 4, k0, k1) != 0xA129CA6149BE45E5:
        sys.exit("hand SipHash fails the published SipHash-2-4 vector")

    # 3. scouting values
    for name, chars, val in ((b"abcdefghijklmnopq", b"XGOKOCQCLX", 0x584C4351434F4B4F4758),
                             (b"HyperliquidShortString", b"SPHUYUDMKY", 0x594B4D44555955485053)):
        if chars_of(name) != chars or key_of(name) != val:
            sys.exit("scouting value mismatch for %r" % name)
    if key_of(b"abcdefghijklmnop") != 0x706F6E6D6C6B6A696867666564636261:
        sys.exit("scouting short value mismatch")

    rng = random.Random(115)
    lines = ["# oracle corpus for node115-shortstring-intern; see gen_oracle.py. Fields are space separated, hex lowercase.",
             "# SIP <msg|-> <u64>            hand SipHash-1-3, zero key",
             "# KEY <name|-> <chars|-> <u128> key for a name; chars is the 10-byte generated name or - for the short path",
             "# COLLIDE <long name> <short name> <u128>   two different names with the same key (the short one is the long one's generated letters)",
             "# CACHE <id> <fill> <name:path:len>...   fill = cache-fill-%08d names 0..fill-1 interned first, then the probes",
             "# ROWS <id> <fill> <name/text,...> => OK <key:value,...> <len> | ERR <index> <len>   (stand-in parser: 40 chars [0-9a-f])"]

    # raw SipHash lines: every length 0..40 (tail and block edges), plus longer ones
    sip_msgs = [bytes((i * 7 + 3 + n) & 0xFF for i in range(n)) for n in range(0, 41)]
    sip_msgs += [bytes(rng.randrange(256) for _ in range(n)) for n in (47, 48, 49, 63, 64, 65, 100)]

    # names for KEY lines
    names = [b"", b"a", b"\x00", b"abcdefghijklmno", b"abcdefghijklmnop", b"abcdefghijklmnopq", b"XGOKOCQCLX",
             b"HyperliquidShortString", b"\x00" * 16, b"\x00" * 17, b"A" * 16, b"A" * 17,
             "é".encode() * 8, "é".encode() * 9, "日本語日本".encode(), "日本語日本語".encode(),
             b"a" * 14 + "é".encode(), b"a" * 15 + "é".encode(), "😀".encode() * 4, "😀".encode() * 4 + b"a",
             "é".encode() * 7 + b"x" * 3, b"a" * 15, b"a" * 16, b"a" * 17, b"a" * 18, b"line1\nline2-is-long\x00z"]
    names += [b"a" * n for n in range(17, 72)]
    base = bytearray(b"HyperliquidTokenName0123")
    one_byte = []
    for p in range(len(base)):          # one byte changed at a time: 24 pairs against `base`
        v = bytearray(base)
        v[p] = ord("z") if v[p] != ord("z") else ord("y")
        one_byte.append(bytes(v))
    names += one_byte
    names += [bytes(base), bytes(base) + b"\x00", b"\x00" + bytes(base), bytes(base)[:-1], bytes(base)[:17], bytes(base)[:16]]
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.é日語😀"
    for _ in range(160):
        names.append("".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 41))).encode())

    # collect every message that the hash will see and cross-check against CPython
    msgs = list(sip_msgs)
    for nm in names:
        if len(nm) > 16:
            msgs += [index_msg(nm, i) for i in range(10)]
    msgs += [index_msg(fill_name(n), i) for n in range(0, 2000) for i in range(10)]
    compared, skipped = cpython_crosscheck(msgs)

    for m in sip_msgs:
        lines.append("SIP %s %016x" % (m.hex() or "-", sip13(m)))
    seen = set()
    for nm in names:
        if nm in seen:
            continue
        seen.add(nm)
        ch = chars_of(nm) if len(nm) > 16 else None
        lines.append("KEY %s %s %032x" % (nm.hex() or "-", ch.decode() if ch else "-", key_of(nm)))
    # single-byte changes must give different keys (a property of this sample, not a claim about the node)
    if len({key_of(b) for b in one_byte} | {key_of(bytes(base))}) != 25:
        sys.exit("a one-byte change left a key unchanged")

    # collision: the key space is ten capital letters (26**10 values), so two different names can share a key.
    # A 17-byte name and a 10-byte name made of its generated letters do (the scouting pair).
    long_nm, short_nm = b"abcdefghijklmnopq", chars_of(b"abcdefghijklmnopq")
    if long_nm == short_nm or key_of(long_nm) != key_of(short_nm):
        sys.exit("collision pair does not collide")
    lines.append("COLLIDE %s %s %032x" % (long_nm.hex(), short_nm.hex(), key_of(long_nm)))

    # distinct-key observation on the first 20,000 fill names
    keys = {key_of(fill_name(n)) for n in range(20000)}
    lines.append("DISTINCT cache-fill 20000 %d" % len(keys))

    # cache scenarios
    def probes(c, specs):
        out = []
        for nm in specs:
            _, path = c.intern(nm)
            out.append("%s:%s:%d" % (nm.hex() or "-", path, len(c.d)))
        return " ".join(out)

    def run_cache(cid, fill, specs):
        c = Cache()
        c.fill(fill)
        lines.append("CACHE %s %d %s" % (cid, fill, probes(c, specs)))

    A, B, C = b"A-long-name-for-the-cache-0001", b"B-long-name-for-the-cache-0002", b"C" * 17
    run_cache("empty-start", 0, [A, A, b"short", A, B, A, b"D" * 16, C, C, b"", B])
    run_cache("one-entry", 1, [fill_name(0), fill_name(1), fill_name(1), A])
    run_cache("fill-99997", 99997, [A, B, C, A, C, b"E" * 20])
    run_cache("fill-99998", 99998, [A, B, C, A, B, C])
    run_cache("fill-99999", 99999, [A, B, A, B, fill_name(99998), fill_name(0)])
    run_cache("fill-100000", 100000, [A, A, fill_name(99999), fill_name(0), b"short-ok"])
    run_cache("fill-100003", 100003, [fill_name(99999), fill_name(100000), fill_name(100002), fill_name(100002), A])
    run_cache("short-never-cached", 99999, [b"x" * 16, b"y" * 16, b"z" * 16, A])

    # consumer scenarios, stand-in parser
    def valid(t):
        return len(t) == 40 and all(ch in b"0123456789abcdef" for ch in t)

    def run_rows(rid, fill, items):
        c = Cache()
        c.fill(fill)
        rows, err = [], None
        for idx, (nm, tx) in enumerate(items):
            k, _ = c.intern(nm)            # the bytes call the key function first ...
            if not valid(tx):              # ... then the 20-byte parser; Err is an unwrap panic
                err = idx
                break
            rows.append("%032x:%s" % (k, tx.decode()))
        enc = ",".join("%s/%s" % (nm.hex() or "-", tx.hex() or "-") for nm, tx in items) or "-"
        res = "ERR %d %d" % (err, len(c.d)) if err is not None else "OK %s %d" % (",".join(rows) or "-", len(c.d))
        lines.append("ROWS %s %d %s => %s" % (rid, fill, enc, res))

    v1, v2, v3 = b"00" * 20, b"ab" * 20, b"0123456789abcdef0123456789abcdef01234567"
    run_rows("empty", 0, [])
    run_rows("mixed-ok", 0, [(A, v1), (b"short", v2), (A, v3), (B, v1), (b"", v2), (b"q" * 16, v3), (b"q" * 17, v1)])
    run_rows("fail-first-long", 0, [(A, b"0" * 39), (B, v1)])
    run_rows("fail-first-short", 0, [(b"short", b"0" * 39), (B, v1)])
    run_rows("fail-middle", 0, [(A, v1), (B, v2), (C, b"zz" * 20), (b"never-reached-long-name", v3)])
    run_rows("fail-uppercase", 0, [(A, b"AB" * 20)])
    run_rows("fail-41", 0, [(A, v1 + b"0")])
    run_rows("cap-full", 100000, [(A, v1), (A, v2), (b"short", v3)])
    run_rows("cap-one-left", 99999, [(A, v1), (B, v2), (A, v3)])
    run_rows("cap-last-slot-then-fail", 99999, [(A, v1), (B, b"bad")])

    os.mkdir(a.outdir)
    with open(os.path.join(a.outdir, "corpus.txt"), "w", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    print("lines %d, cpython siphash13 compared %d messages (skipped %d), distinct keys %d" %
          (len(lines), compared, skipped, len(keys)))


if __name__ == "__main__":
    main()
