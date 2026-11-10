#!/usr/bin/env python3
"""Oracle corpus generator for node115-peers-response-set (RE-012).

Standard library only. Writes only into a new directory given by --outdir.
It refuses an existing directory and any directory inside this packet or the
Rust crate, and it never reads or changes any other file.

The expected values come from a different representation than the Rust crate:
a hand-written wire encoder, a spec-based LZ4 block encoder, and an overwrite
ledger that records the input index of the row that survives for every key
(a dict keyed by the four wire bytes, ordered by Python bytes comparison).
It uses no sorting-by-tuple shortcut shared with the crate and no code from it.
"""
import argparse
import hashlib
import os
import struct
import sys

LIMIT = 10_000          # selected Peers request: raw tag 1, low32 == 1
SMALL_MAX = 64          # <= 64 kept rows -> small set, > 64 -> tree


class Rng:
    """splitmix64, so the corpus does not depend on the Python version."""

    def __init__(self, seed):
        self.s = seed & (2**64 - 1)

    def u64(self):
        self.s = (self.s + 0x9E3779B97F4A7C15) & (2**64 - 1)
        z = self.s
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & (2**64 - 1)
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & (2**64 - 1)
        return z ^ (z >> 31)

    def below(self, n):
        return self.u64() % n

    def shuffle(self, items):
        for i in range(len(items) - 1, 0, -1):
            j = self.below(i + 1)
            items[i], items[j] = items[j], items[i]


# ---------------------------------------------------------------- wire form
def varint(v, wide=None):
    """Node scalar: <251 one byte; 251 + u16; 252 + u32; 253 + u64 (LE)."""
    if wide is None:
        wide = 0 if v < 251 else 1 if v < 1 << 16 else 2 if v < 1 << 32 else 3
    if wide == 0:
        assert v < 251
        return bytes([v])
    if wide == 1:
        return bytes([251]) + v.to_bytes(2, "little")
    if wide == 2:
        return bytes([252]) + v.to_bytes(4, "little")
    return bytes([253]) + v.to_bytes(8, "little")


def row_bytes(key, flag, value, wide=None):
    assert len(key) == 4
    return varint(0) + key + bytes([flag]) + varint(value, wide)


def peers_payload(rows, count=None, outer=1, wides=None):
    out = varint(outer) + varint(len(rows) if count is None else count)
    for i, (k, f, v) in enumerate(rows):
        out += row_bytes(k, f, v, None if wides is None else wides.get(i))
    return out


def frame(payload, flag=0):
    return struct.pack(">I", len(payload)) + bytes([flag]) + payload


# ---------------------------------------------------------------------- LZ4
def _ext(n):
    out = b""
    while n >= 255:
        out += b"\xff"
        n -= 255
    return out + bytes([n])


def lz4_sequence(lits, match=None):
    lit_nib = min(len(lits), 15)
    token = lit_nib << 4
    body = b""
    if len(lits) >= 15:
        body += _ext(len(lits) - 15)
    body += lits
    if match is not None:
        off, mlen = match
        assert 1 <= off <= 65535 and mlen >= 4
        token |= min(mlen - 4, 15)
        body += off.to_bytes(2, "little")
        if mlen - 4 >= 15:
            body += _ext(mlen - 4 - 15)
    return bytes([token]) + body


def lz4_block(data, greedy):
    """LZ4 block per the public block-format description."""
    n = len(data)
    if not greedy or n < 16:
        return lz4_sequence(data)
    out = b""
    table = {}
    anchor = 0
    i = 0
    while i + 12 <= n:                    # last match starts >= 12 from the end
        key = data[i:i + 4]
        cand = table.get(key)
        table[key] = i
        if cand is not None and i - cand <= 65535:
            m = 4
            while i + m < n - 5 and data[cand + m] == data[i + m]:
                m += 1
            if i + m <= n - 5:            # last 5 bytes stay literals
                out += lz4_sequence(data[anchor:i], (i - cand, m))
                i += m
                anchor = i
                continue
        i += 1
    return out + lz4_sequence(data[anchor:])


def lz4_ref_decode(block):
    """Spec decoder used only to self-check this generator's encoder."""
    out = bytearray()
    p = 0
    while p < len(block):
        tok = block[p]
        p += 1
        lit = tok >> 4
        if lit == 15:
            while True:
                b = block[p]
                p += 1
                lit += b
                if b != 255:
                    break
        out += block[p:p + lit]
        p += lit
        if p >= len(block):
            break
        off = block[p] | block[p + 1] << 8
        p += 2
        m = (tok & 15) + 4
        if (tok & 15) == 15:
            while True:
                b = block[p]
                p += 1
                m += b
                if b != 255:
                    break
        assert 0 < off <= len(out)
        for _ in range(m):
            out.append(out[-off])
    return bytes(out)


def lz4_payload(data, greedy, capacity=None):
    block = lz4_block(data, greedy)
    assert lz4_ref_decode(block) == data
    cap = len(data) if capacity is None else capacity
    return struct.pack("<I", cap) + block


# ------------------------------------------------------------------- ledger
def ledger(rows):
    """key -> (input index, flag, value); the later input row overwrites."""
    last = {}
    for idx, (k, f, v) in enumerate(rows):
        last[k] = (idx, f, v)
    return [(k, last[k]) for k in sorted(last)]


def expect_ok(rows, payload, compressed, stream_rest=0, consumed=None):
    # 4 + 8 + 24 * n must stay within the 10,000 limit, so at most 416 rows
    assert 4 + 8 + 24 * len(rows) <= LIMIT, "case would hit the limit; expect an error"
    kept = ledger(rows)
    if consumed is None:
        consumed = len(payload)
    charged = 4 + 8 + 13 * len(rows)       # outer tag, count, 13 per element
    fields = [
        "ok",
        f"compressed={int(compressed)}",
        f"storage={'small' if len(kept) <= SMALL_MAX else 'tree'}",
        f"wire={len(rows)}",
        f"kept={len(kept)}",
        f"charged={charged}",
        f"remaining={len(payload) - consumed}",
        f"stream_rest={stream_rest}",
        "rows=" + ",".join(f"{k.hex()}:{f}:{v}" for k, (_, f, v) in kept),
        "winners=" + ",".join(str(i) for _, (i, _, _) in kept),
    ]
    return ";".join(fields)


def exact_len(rows):
    return len(peers_payload(rows))


# -------------------------------------------------------------------- cases
VALUES = [0, 1, 250, 251, 65535, 65536, 2**32 - 1, 2**32, 2**64 - 1]


def rand_keys(rng, count):
    keys = set()
    while len(keys) < count:
        keys.add(bytes(rng.below(256) for _ in range(4)))
    return sorted(keys)


def build(cases):
    rng = Rng(0x5EED115)
    add = cases.append

    def ok_plain(cid, rows, flag=0, extra_tail=b"", rest=b""):
        payload = peers_payload(rows)
        full = payload + extra_tail
        fr = frame(full, flag) + rest
        add((cid, fr.hex(), expect_ok(rows, full, False, len(rest), len(payload))))

    def ok_lz4(cid, rows, greedy, capacity=None, extra_tail=b"", rest=b""):
        payload = peers_payload(rows)
        full = payload + extra_tail
        lz = lz4_payload(full, greedy, capacity)
        fr = frame(lz, 1) + rest
        add((cid, fr.hex(), expect_ok(rows, full, True, len(rest), len(payload))))

    def err(cid, frame_bytes, cls):
        add((cid, frame_bytes.hex(), f"err;class={cls}"))

    # 1. the SCOUT example, reproduced byte for byte by the hand encoder
    scout_rows = [(bytes([1, 2, 3, 4]), 0, 1), (bytes([0, 0, 0, 1]), 1, 2), (bytes([1, 2, 3, 4]), 1, 3)]
    scout = frame(peers_payload(scout_rows), 0)
    assert scout.hex() == "00000017000103000102030400010000000001010200010203040103"
    ok_plain("scout-28-plain", scout_rows)
    ok_lz4("scout-28-lz4-literal", scout_rows, greedy=False)
    ok_plain("empty-vector", [])
    ok_plain("single-row", [(bytes([9, 9, 9, 9]), 1, 7)])

    # 2. count sweeps, unique keys, three input orders
    sizes = [2, 3, 8, 16, 19, 20, 21, 22, 32, 33, 63, 64, 65, 66, 100, 200, 416]
    for n in sizes:
        keys = rand_keys(rng, n)
        for order in ("rand", "asc", "desc"):
            ks = list(keys)
            if order == "rand":
                rng.shuffle(ks)
            elif order == "desc":
                ks.reverse()
            rows = [(k, rng.below(2), VALUES[(i + n) % len(VALUES)]) for i, k in enumerate(ks)]
            ok_plain(f"unique-n{n}-{order}", rows)

    # 3. duplicate-heavy inputs; every row distinct so the winner is visible
    for n in [2, 3, 10, 19, 20, 21, 22, 33, 64, 65, 200, 416]:
        for variant, pool_size in enumerate((1, 2, 3, max(2, n // 3), max(2, n // 2))):
            pool = rand_keys(rng, pool_size)
            rows = []
            for i in range(n):
                rows.append((pool[rng.below(pool_size)], rng.below(2), VALUES[i % len(VALUES)] ^ (i + 1)))
            ok_plain(f"dups-n{n}-v{variant}-pool{pool_size}", rows)

    # 4. kept-count boundary after de-duplication: 64 vs 65 and 63/64
    for kept in (63, 64, 65, 66):
        pool = rand_keys(rng, kept)
        rows = [(k, 0, i) for i, k in enumerate(pool)] + [(k, 1, 1000 + i) for i, k in enumerate(pool)]
        rng.shuffle(rows)
        ok_plain(f"twice-each-kept{kept}", rows)
    pool = rand_keys(rng, 64)
    rows = [(k, 0, i) for i, k in enumerate(pool)] + [(pool[0], 1, 777)]
    ok_plain("n65-one-dup-kept64", rows)
    pool = rand_keys(rng, 65)
    rows = [(k, 0, i) for i, k in enumerate(pool)] + [(pool[0], 1, 777)]
    ok_plain("n66-one-dup-kept65", rows)

    # 5. byte order of the four key bytes (not little-endian numeric order)
    ks = [bytes.fromhex(h) for h in ("00000001", "01000000", "00010000", "ff000000", "000000ff", "80000000", "7fffffff", "00000100")]
    rows = [(k, i & 1, i) for i, k in enumerate(ks)]
    ok_plain("key-byte-order", rows)
    ok_plain("key-byte-order-twice", rows + [(k, 1, 100 + i) for i, k in enumerate(reversed(ks))])

    # 6. shapes that steer the long-sort run detector and the partition path
    def shape(cid, n, keyfn, pool):
        rows = [(pool[keyfn(i) % len(pool)], i & 1, i + 1) for i in range(n)]
        ok_plain(cid, rows)

    pool = rand_keys(rng, 416)
    for n in (21, 33, 65, 200, 416):
        shape(f"shape-ascending-n{n}", n, lambda i: i, pool)
        shape(f"shape-descending-n{n}", n, lambda i, n=n: n - 1 - i, pool)
        shape(f"shape-desc-with-ties-n{n}", n, lambda i, n=n: (n - 1 - i) // 2, pool)
        shape(f"shape-asc-with-ties-n{n}", n, lambda i: i // 3, pool)
        shape(f"shape-organ-pipe-n{n}", n, lambda i, n=n: min(i, n - 1 - i), pool)
        shape(f"shape-sawtooth-n{n}", n, lambda i: i % 7, pool)
        shape(f"shape-all-equal-n{n}", n, lambda i: 0, pool)
        shape(f"shape-two-keys-alternating-n{n}", n, lambda i: i % 2, pool)
    for n in (150, 300, 416):
        for distinct in (4, 5, 9):
            ks = rand_keys(rng, distinct)
            rows = [(ks[rng.below(distinct)], rng.below(2), i + 1) for i in range(n)]
            ok_plain(f"shape-few-distinct-n{n}-d{distinct}", rows)

    # 7. the 10,000 request limit and the 24-byte pre-charge: 416 passes, 417 fails
    rows416 = [(k, 0, i) for i, k in enumerate(rand_keys(rng, 416))]
    ok_plain("limit-n416", rows416)
    rows417 = [(k, 0, i) for i, k in enumerate(rand_keys(rng, 417))]
    err("limit-n417", frame(peers_payload(rows417), 0), "limit")
    err("limit-n417-lz4", frame(lz4_payload(peers_payload(rows417), True), 1), "limit")
    err("limit-count-only-417", frame(varint(1) + varint(417), 0), "limit")
    err("limit-count-huge", frame(varint(1) + varint(2**40, 3), 0), "limit")
    ok_lz4("limit-n416-lz4-greedy", rows416, greedy=True)

    # 8. response/row errors reached after a good frame
    two = [(bytes([1, 1, 1, 1]), 0, 1), (bytes([2, 2, 2, 2]), 1, 2)]
    good = peers_payload(two)
    err("count-exceeds-data", frame(peers_payload(two, count=3), 0), "short_input")
    err("truncated-key", frame(good[:-5], 0), "short_input")
    err("missing-flag", frame(varint(1) + varint(1) + varint(0) + b"\x01\x02\x03\x04", 0), "short_input")
    err("missing-scalar", frame(varint(1) + varint(1) + varint(0) + b"\x01\x02\x03\x04\x00", 0), "short_input")
    err("bad-bool-2", frame(varint(1) + varint(1) + varint(0) + b"\x01\x02\x03\x04\x02" + varint(5), 0), "bad_bool")
    err("bad-node-tag-1", frame(varint(1) + varint(1) + varint(1) + b"\x01\x02\x03\x04\x00" + varint(5), 0), "bad_node_tag")
    err("bad-scalar-marker-254", frame(varint(1) + varint(1) + varint(0) + b"\x01\x02\x03\x04\x00\xfe\x00", 0), "bad_scalar")
    err("outer-tag-3", frame(varint(3) + varint(0), 0), "outer_tag")
    err("not-peers-nested-success", frame(varint(0) + varint(0), 0), "not_peers")
    err("empty-payload", frame(b"", 0), "short_input")
    wide = peers_payload(two, wides={0: 1, 1: 3})
    add(("nonminimal-scalars", frame(wide, 0).hex(), expect_ok(two, wide, False)))
    ok_plain("trailing-bytes-kept-as-remaining", two, extra_tail=b"\xde\xad\xbe\xef")
    ok_plain("two-frames-stream-rest", two, rest=frame(good, 0))
    ok_plain("flag-2-is-plain", two, flag=2)
    ok_plain("flag-255-is-plain", two, flag=255)

    # 9. frame-level errors
    err("eof-clean", b"", "eof")
    err("header-truncated-1", b"\x00", "frame_header")
    err("header-truncated-4", b"\x00\x00\x00\x17", "frame_header")
    err("payload-truncated", scout[:-1], "frame_payload")
    err("payload-truncated-header-only", scout[:5], "frame_payload")
    big = bytes(10_000)
    # exactly 10,000 payload bytes pass the gate; the payload itself is a valid
    # response followed by padding, so the padding is reported as remaining.
    pad = 10_000 - len(good)
    ok_plain("frame-exactly-10000", two, extra_tail=bytes(pad))
    err("frame-10001-over-limit", struct.pack(">I", 10_001) + b"\x00" + bytes(10_001), "over_limit")
    err("frame-huge-over-limit", struct.pack(">I", 0xFFFFFFFF) + b"\x00", "over_limit")
    err("frame-10001-lz4-over-limit", struct.pack(">I", 10_001) + b"\x01" + bytes(10_001), "over_limit")

    # 10. LZ4 frames
    for n in (5, 21, 65, 200, 415):
        keys = rand_keys(rng, n)
        rows = [(k, 0, i) for i, k in enumerate(keys)] + [(keys[0], 1, 999)]
        ok_lz4(f"lz4-literal-n{n}", rows, greedy=False)
        ok_lz4(f"lz4-greedy-n{n}", rows, greedy=True)
    ok_lz4("lz4-capacity-larger-than-data", two, greedy=False, capacity=len(good) + 77)
    ok_lz4("lz4-capacity-10000", two, greedy=False, capacity=10_000)
    ok_lz4("lz4-decoded-exactly-10000", two, greedy=True, extra_tail=bytes(10_000 - len(good)))
    ok_lz4("lz4-two-frames-stream-rest", two, greedy=False, rest=frame(good, 0))
    # long literal / long match extension bytes
    rep = [(bytes([5, 5, 5, 5]), 0, i) for i in range(30)] + [(bytes([6, 6, 6, 6]), 1, 1)]
    ok_lz4("lz4-long-repeat-extension", rep, greedy=True)
    sc = lz4_payload(peers_payload(two), False)
    err("lz4-capacity-10001", frame(struct.pack("<I", 10_001) + sc[4:], 1), "lz4")
    err("lz4-capacity-too-small", frame(struct.pack("<I", 3) + sc[4:], 1), "lz4")
    err("lz4-no-capacity-bytes", frame(b"\x05\x00", 1), "lz4")
    err("lz4-empty-block", frame(struct.pack("<I", 0), 1), "lz4")
    err("lz4-literal-overrun", frame(struct.pack("<I", 9) + b"\x50ab", 1), "lz4")
    err("lz4-zero-offset", frame(struct.pack("<I", 8) + b"\x13A\x00\x00\x00", 1), "lz4")
    err("lz4-offset-beyond-history", frame(struct.pack("<I", 12) + b"\x13A\x05\x00\x00", 1), "lz4")
    err("lz4-match-needs-terminal-token", frame(struct.pack("<I", 8) + b"\x13A\x01\x00", 1), "lz4")
    err("lz4-truncated-extension", frame(struct.pack("<I", 40) + b"\xf0", 1), "lz4")
    err("lz4-output-over-capacity", frame(struct.pack("<I", 2) + b"\x40abcd", 1), "lz4")
    # a valid block whose decoded bytes are not a Peers response
    err("lz4-decodes-to-bad-tag", frame(lz4_payload(varint(3) + varint(0), False), 1), "outer_tag")
    err("lz4-decodes-to-short-row", frame(lz4_payload(good[:-5], True), 1), "short_input")
    return cases


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--outdir", required=True, help="new directory to create; must not exist")
    args = ap.parse_args(argv)

    here = os.path.dirname(os.path.realpath(__file__))
    root = os.path.realpath(os.path.join(here, "..", "..", "..", ".."))
    forbidden = [
        os.path.join(root, "research", "work-items", "RE-012-node115-peers-response-set"),
        os.path.join(root, "src", "node115-peers-response-set"),
    ]
    out = os.path.abspath(args.outdir)
    parent = os.path.realpath(os.path.dirname(out))
    real_out = os.path.join(parent, os.path.basename(out))
    if os.path.lexists(out):
        print("refusing: outdir already exists", file=sys.stderr)
        return 2
    if not os.path.isdir(parent):
        print("refusing: parent of outdir does not exist", file=sys.stderr)
        return 2
    for f in forbidden:
        if real_out == f or real_out.startswith(f + os.sep):
            print("refusing: outdir is inside the packet or the crate", file=sys.stderr)
            return 2

    cases = build([])
    ids = [c[0] for c in cases]
    assert len(ids) == len(set(ids)), "duplicate case id"
    lines = ["# id\tframe_hex\texpect"] + ["\t".join(c) for c in cases]
    data = ("\n".join(lines) + "\n").encode()
    os.mkdir(out)
    with open(os.path.join(out, "corpus.tsv"), "wb") as fh:
        fh.write(data)
    digest = hashlib.sha256(data).hexdigest()
    with open(os.path.join(out, "corpus.sha256"), "w") as fh:
        fh.write(f"{digest}  corpus.tsv\n")
    print(f"{len(cases)} cases, sha256 {digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
