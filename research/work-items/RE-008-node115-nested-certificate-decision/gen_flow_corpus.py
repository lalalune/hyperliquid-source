#!/usr/bin/env python3
"""Generate the expected-value corpora for the #115 nested certificate flow (no Rust involved).

Usage: python3 -I gen_flow_corpus.py <output directory>

Every expected value below comes from the rule list in relations.tsv (read from the disassembly,
function by function), applied to explicit inputs. The signature primitives are replaced by the
test-only toy defined here (`toy_digest`, `toy_recover`); the Rust tests implement the same toy. Whether
a signature "recovers" is therefore decided by toy arithmetic, never by real cryptography.

Outputs: cases-equal.tsv (0x4e08870 + 0x4e550e0), cases-collect.tsv (0x4e00160), cases-signer.tsv
(0x57e8bd0), cases-quorum.tsv (0x595bc40 + 0x4d3e1a0), cases-flow.tsv (0x595f880 and 0x595fd20 with the
real collaborators; the call log lists every boundary call in order), cases-tree.tsv (same columns as
cases-flow.tsv: the verifier over certificates of more than 64 signatures, which the native code stores as a
multi-leaf tree, plus empty certificates; added in round 3, own random stream, no other file moves).
"""
import os
import struct
import sys

M = (1 << 64) - 1


class Rng:
    def __init__(self, seed):
        self.x = seed & M

    def u64(self):
        self.x = (self.x * 6364136223846793005 + 1442695040888963407) & M
        return self.x ^ (self.x >> 31)

    def below(self, n):
        return self.u64() % n

    def pick(self, seq):
        return seq[self.below(len(seq))]

    def bytes(self, n):
        return bytes(self.below(256) for _ in range(n))


def pool_key(i):
    return bytes([i]) + bytes([(i * 37 + 11 * n) & 0xFF for n in range(18)]) + bytes([0])


def kt(k):
    """Key token: K<first byte> for the generator's pool keys (pool_key), else 40 hex digits."""
    return "K%02x" % k[0] if k == pool_key(k[0]) else k.hex()


def unkt(s):
    return pool_key(int(s[1:], 16)) if s[0] == "K" else bytes.fromhex(s)


# ---- toy primitives (test only) -------------------------------------------------------------

def fnv(seed, data):
    h = (0xCBF29CE484222325 ^ ((seed * 0x9E3779B97F4A7C15) & M)) & M
    for b in data:
        h = ((h ^ b) * 0x100000001B3) & M
    return h


def frame_bytes(hash32, a, b, c, d, e, signer):
    return hash32 + b"".join(x.to_bytes(8, "little") for x in (a, b, c, d, e)) + signer


def toy_digest(variant, frame):
    data = variant.to_bytes(8, "little") + frame
    return b"".join(fnv(k, data).to_bytes(8, "little") for k in range(4))


def toy_recover(sig, dg):
    if sig[64] >= 4:
        return None
    return bytes(sig[i] ^ dg[i] for i in range(20))


def make_sig(spec, key, dg):
    """spec: V valid for key, R<hex40> valid for that address, E recovery error, F<hex byte>[:pos] fill."""
    if spec[0] == "F":
        byte, _, pos = spec[1:].partition(":")
        s = bytearray([int(byte, 16)] * 65)
        if pos:
            s[int(pos)] ^= 1
        return bytes(s)
    s = bytearray(65)
    for i in range(20, 64):
        s[i] = (key[0] * 3 + i * 5) & 0xFF
    if spec == "E":
        s[64] = 7
        return bytes(s)
    target = key if spec == "V" else unkt(spec[1:])
    for i in range(20):
        s[i] = target[i] ^ dg[i]
    return bytes(s)


# ---- containers ------------------------------------------------------------------------------

class Coll:
    """Signature collection: tree (sorted by key) or ring (cap, head, rows in logical order)."""

    def __init__(self, form, rows, cap=0, head=0):
        self.form, self.rows, self.cap, self.head = form, rows, cap, head
        if form == "T":
            assert len({k for k, _ in rows}) == len(rows)
            self.rows = sorted(rows, key=lambda r: r[0])
        else:
            assert len(rows) <= cap and (head < cap or (cap == 0 and head == 0))

    def text(self):
        body = ",".join("%s~%s" % (kt(k), s) for k, s in self.rows)
        return ("T=" if self.form == "T" else "R%d.%d=" % (self.cap, self.head)) + body


class Stakes:
    """Stake map (tree or sorted ring), validator set and validator count."""

    def __init__(self, form, entries, vals, vcount, cap=0, head=0):
        self.form, self.entries, self.vals, self.vcount = form, sorted(entries), sorted(set(vals)), vcount
        self.cap, self.head = cap, head
        assert len({k for k, _ in self.entries}) == len(self.entries)
        if form == "R":
            assert len(self.entries) <= cap and (head < cap or (cap == 0 and head == 0))

    def map_text(self):
        body = ",".join("%s:%x" % (kt(k), w) for k, w in self.entries)
        return ("T=" if self.form == "T" else "R%d.%d=" % (self.cap, self.head)) + body

    def member(self, key):
        return any(k == key for k, _ in self.entries)

    def text(self):
        return "S/%s/%s/%x" % (self.map_text(), ",".join(kt(v) for v in self.vals) or "-", self.vcount)


# ---- reference rules (written from relations.tsv) ----------------------------------------------

def sat_sum(ws):
    t = 0
    for w in ws:
        t = min(M, t + w)
    return t


def clamp_fraction(bits):
    """0x595bc67..0x595bccc. Returns the fraction; zero means 'true at once'."""
    if (bits & 0x7FFFFFFFFFFFFFFF) > 0x7FEFFFFFFFFFFFFF:
        return 1.0
    x = struct.unpack("<d", struct.pack("<Q", bits))[0]
    t = 0.0 if 0.0 > x else x  # maxsd %xmm0,%xmm2 (dest 0.0, source x)
    return 0.7 if 0.7 < t else t  # minsd %xmm2,%xmm0 (dest 0.7, source t)


def ref_quorum(st, signers, bits):
    """signers: sorted unique keys. 0x4d3e1a0 then 0x595bc40."""
    weights = dict(st.entries)
    signed = sat_sum(weights[k] for k in signers if k in weights)
    total = sat_sum(w for _, w in st.entries)
    if not 3 * signed > 2 * total:
        return False
    frac = clamp_fraction(bits)
    if frac == 0.0:
        return True
    count = sum(1 for k in signers if k in st.vals)
    return float(count) > frac * float(st.vcount)


def ref_signer(st, variant, frame, addr, sig, log):
    if not st.member(addr):
        return False
    dg = toy_digest(variant, frame)
    log.append("D:%d:%s" % (variant, kt(addr)))
    log.append("R:%s" % kt(addr))
    return toy_recover(sig, dg) == addr


def ref_equal(a, b):
    if len(a.rows) != len(b.rows):
        return False
    return all(ka == kb and sa == sb for (ka, sa), (kb, sb) in zip(a.rows, b.rows))


def ref_collect(coll, st):
    for k, _ in coll.rows:
        if not st.member(k):
            return "2c", kt(k)
    return "2e", ",".join(kt(k) for k in sorted({k for k, _ in coll.rows}))


def ref_verify(c, log):
    """0x595f880. c: dict with sigs, hash, a..e, fraction, stakes (None = provider has no set)."""
    log.append("P:%x" % c["e"])
    st = c["stakes"]
    if st is None:
        return "28", "%x" % c["e"]
    tag, payload = ref_collect(c["sigs"], st)
    if tag != "2e":
        return tag, payload
    signers = sorted({k for k, _ in c["sigs"].rows})
    if not ref_quorum(st, signers, c["fraction"]):
        return "07", "-"
    for key, spec in c["sigs"].rows:
        frame = frame_bytes(c["hash"], c["a"], c["b"], c["c"], c["d"], c["e"], key)
        dg = toy_digest(1, frame)
        sig = make_sig(spec, key, dg)
        if not ref_signer(st, 1, frame, key, sig, log):
            return "02", "-"
    return "2e", "-"


def ref_decision(c, log):
    """0x595fd20 on top of ref_verify and ref_equal."""
    a, b, f30, f38, f40 = c["a"], c["b"], c["c"], c["d"], c["e"]
    cc, dd = c["ctx_c"], c["ctx_d"]
    if (a, b) == (cc, dd):
        if f30 < b:
            return "05", "-"
        if f30 == b:
            if f38 != b or f40 != b or c["hash"] != bytes(32):
                return "06", "-"
            return ("2e" if ref_equal(c["sigs"], Coll("R", [], 0, 0)) else "06"), "-"
        if not (f38 < f30 and b <= f40 and f40 <= f38):
            return "2d", "%x:%x:%x" % (f30, f38, f40)
        return ref_verify(c, log)
    if a <= cc:
        return "00", "%x:%x:%x:%x" % (a, b, cc, dd)
    tag, _ = ref_verify(c, log)
    if tag == "2e":
        return "DIVERGE", "%x:%x:%x:%x" % (cc, dd, a, b)
    return "00", "%x:%x:%x:%x" % (a, b, cc, dd)


# ---- case builders -----------------------------------------------------------------------------

def key(i, j=0):
    return bytes([i]) + bytes([(i * 37 + 11 * n) & 0xFF for n in range(18)]) + bytes([j])


POOL = [key(0x10 + 3 * i) for i in range(80)]  # strictly increasing first byte, so pool order is key order
FILL = bytes([0xFF]) * 20
FRACTIONS = [0x0, 0x8000000000000000, 0x3FB999999999999A, 0x3FE0000000000000, 0x3FE6666666666666,
             0x3FE6666666666667, 0x3FE6666666666665, 0x3FF0000000000000, 0x4000000000000000,
             0xBFF0000000000000, 0x7FF0000000000000, 0xFFF0000000000000, 0x7FF8000000000000,
             0xFFF8000000000001, 0x7FF0000000000001, 0x0000000000000001, 0x7FEFFFFFFFFFFFFF,
             0x3FD5555555555555, 0x3FE55555555554FA, 0x8000000000000001, 0xBFE0000000000000]


def lines_header(cols):
    return ["\t".join(cols)]


def build_equal(rng):
    out = []

    def sigs(form, keys, fills, cap=0, head=0):
        rows = [(k, "F%02x" % f) for k, f in zip(keys, fills)]
        return Coll(form, rows, cap, head)

    n = 0
    for form_a in "TR":
        for form_b in "TR":
            for size in (0, 1, 2, 5, 12, 30):
                keys = POOL[:size]
                fills = [(7 * i + 3) & 0xFF for i in range(size)]
                variants = ["same", "key", "sig_first", "sig_last", "sig_mid", "len_plus", "len_minus", "order"]
                for v in variants:
                    k2, f2, spec2 = list(keys), list(fills), None
                    if v == "key" and size:
                        k2[size // 2] = key(0xE0)
                    if v == "len_plus":
                        k2 = keys + [key(0xE1)]
                        f2 = fills + [1]
                    if v == "len_minus":
                        if not size:
                            continue
                        k2, f2 = keys[:-1], fills[:-1]
                    if v == "order":
                        if size < 2:
                            continue
                        k2[0], k2[1] = k2[1], k2[0]
                    ca, cb = (None, None)
                    cap_a = size + rng.below(4)
                    cap_b = len(k2) + rng.below(4)
                    ca = sigs(form_a, keys, fills, cap_a, rng.below(cap_a) if cap_a else 0)
                    cb = sigs(form_b, k2, f2, cap_b, rng.below(cap_b) if cap_b else 0)
                    if form_b == "T" and v == "order":
                        continue
                    if form_a == "T" and form_b == "T" and v == "order":
                        continue
                    if v.startswith("sig") and size:
                        pos = {"sig_first": 0, "sig_last": size - 1, "sig_mid": size // 2}[v]
                        cb.rows[pos] = (cb.rows[pos][0], "F%02x:%d" % (f2[pos], rng.below(65)))
                    if v == "sig_first" or v == "sig_mid" or v == "sig_last":
                        if not size:
                            continue
                    # tree order is key order; recompute the expectation on the stored order
                    out.append(("e%04d" % n, "%s%s-%s" % (form_a, form_b, v), ca.text(), cb.text(),
                                "T" if ref_equal(ca, cb) else "F"))
                    n += 1
    # signature byte flips at every tail position of a one-row collection
    for pos in range(65):
        ca = Coll("T", [(POOL[0], "F5a")], 0, 0)
        cb = Coll("R", [(POOL[0], "F5a:%d" % pos)], 3, 2)
        out.append(("e%04d" % n, "flip-byte", ca.text(), cb.text(), "T" if ref_equal(ca, cb) else "F"))
        n += 1
    return out


def stakes_for(rng, form, keys, weights, vals, vcount, extra_cap=2):
    entries = list(zip(keys, weights))
    cap = len(entries) + rng.below(extra_cap + 1)
    head = rng.below(cap) if cap else 0
    return Stakes(form, entries, vals, vcount, cap, head)


def build_collect(rng):
    out = []
    n = 0
    for set_form in "TR":
        for sig_form in "TR":
            for size in (0, 1, 3, 7):
                for miss in (None, 0, "mid", "last"):
                    if miss is not None and size == 0:
                        continue
                    keys = POOL[:size]
                    st = stakes_for(rng, set_form, POOL[:12] if size else [], [5] * (12 if size else 0), [], 1)
                    members = list(keys)
                    if miss is not None:
                        idx = {0: 0, "mid": size // 2, "last": size - 1}[miss]
                        members[idx] = key(0xE0 + idx)
                    cap = size + rng.below(3)
                    order = list(members)
                    if sig_form == "R":
                        # ring order is arbitrary: rotate/shuffle by the generator's rng
                        for i in range(size - 1, 0, -1):
                            j = rng.below(i + 1)
                            order[i], order[j] = order[j], order[i]
                        if size and rng.below(3) == 0:
                            order.append(order[0])  # a repeated key
                            cap += 1
                    coll = Coll(sig_form, [(k, "F00") for k in order], cap, rng.below(cap) if cap else 0)
                    tag, payload = ref_collect(coll, st)
                    out.append(("c%04d" % n, "%s%s-%s" % (set_form, sig_form, miss), coll.text(),
                                st.map_text(), "%s:%s" % (tag, payload)))
                    n += 1
    # a stake map with no rows at all against one key (null tree root)
    for set_form in "TR":
        st = Stakes(set_form, [], [], 0, 0, 0)
        coll = Coll("T", [(POOL[3], "F00")], 0, 0)
        tag, payload = ref_collect(coll, st)
        out.append(("c%04d" % n, "empty-set-" + set_form, coll.text(), st.map_text(), "%s:%s" % (tag, payload)))
        n += 1
    return out


def build_signer(rng):
    out = []
    n = 0
    for set_form in "TR":
        for in_set in (True, False):
            for spec_kind in ("V", "other", "E", "bitflip"):
                for variant in (0, 1, 2):
                    for size in (1, 4, 13):
                        keys = POOL[:size]
                        st = stakes_for(rng, set_form, keys, [3] * size, [], 1)
                        addr = keys[rng.below(size)] if in_set else key(0xE5)
                        hashb = bytes([rng.below(256)]) * 32
                        a, b, c, d, e = (rng.u64() & 0xFFFF for _ in range(5))
                        frame = frame_bytes(hashb, a, b, c, d, e, addr)
                        dg = toy_digest(variant, frame)
                        if spec_kind == "V":
                            spec = "V"
                        elif spec_kind == "other":
                            spec = "R" + kt(key(0x77))
                        elif spec_kind == "E":
                            spec = "E"
                        else:
                            spec = "R" + kt(addr[:19] + bytes([addr[19] ^ 1]))
                        sig = make_sig(spec, addr, dg)
                        log = []
                        res = ref_signer(st, variant, frame, addr, sig, log)
                        out.append(("s%04d" % n, "%s-%s-%s" % (set_form, "in" if in_set else "out", spec_kind),
                                    st.map_text(), hashb[:1].hex(), "%x" % a, "%x" % b, "%x" % c, "%x" % d, "%x" % e,
                                    str(variant), kt(addr), spec, "T" if res else "F", " ".join(log) or "-"))
                        n += 1
    return out


def quorum_row(n, group, st, signers, bits):
    sg = sorted(set(signers))
    return ("q%04d" % n, group, st.map_text(), ",".join(kt(v) for v in st.vals) or "-",
            "%x" % st.vcount, ",".join(kt(k) for k in sg) or "-", "%016x" % bits,
            "T" if ref_quorum(st, sg, bits) else "F")


def build_quorum_band(rng, start):
    """Added after a mutant (upper clamp 0.8 instead of 0.7) survived the first corpus: validator counts
    that put count/validators between 0.7 and 0.8, so the clamp value decides. Own rng: no other case moves."""
    out = []
    for bits in FRACTIONS:
        for vcount in (4, 7, 14):
            for have in (0, 1, 3, 5):
                keys = POOL[:6]
                st = stakes_for(rng, "TR"[rng.below(2)], keys, [4] * 6, keys[:have], vcount)
                out.append(quorum_row(start + len(out), "fraction-band", st, keys[:5], bits))
    return out


def build_quorum(rng):
    out = []
    n = 0

    def add(group, st, signers, bits):
        nonlocal n
        out.append(quorum_row(n, group, st, signers, bits))
        n += 1

    # 3*signed > 2*total boundary, tree and ring stake maps
    for form in "TR":
        for weights, take in (([1, 1, 1], 2), ([1, 1, 1], 3), ([2, 1, 1], 2), ([2, 1, 1], 1), ([3, 3, 3], 2),
                              ([1], 1), ([0, 0], 2), ([5, 4, 3, 2, 1], 4), ([5, 4, 3, 2, 1], 3),
                              ([M, M, M], 3), ([M, M, M], 2), ([M, 1, 1], 1), ([M, M, 5], 2), ([M - 1, 1], 1)):
            keys = POOL[:len(weights)]
            st = stakes_for(rng, form, keys, weights, keys, 7)
            add("stake-%s" % form, st, keys[:take], 0)
            add("stake-%s-last" % form, st, keys[len(weights) - take:], 0)
    # count stage: fraction patterns against validator counts
    for bits in FRACTIONS:
        for vcount in (0, 1, 3, 10, (1 << 53) + 1, M):
            for have in (0, 1, 3, 5):
                keys = POOL[:6]
                st = stakes_for(rng, "TR"[rng.below(2)], keys, [4] * 6, keys[:have], vcount)
                add("fraction", st, keys[:5], bits)
    # random stake and validator layouts, including signers missing from the stake map
    for _ in range(120):
        form = "TR"[rng.below(2)]
        k = 1 + rng.below(9)
        keys = POOL[:k]
        weights = [rng.pick([0, 1, 2, 3, 10, M // 4, M // 2, M]) for _ in keys]
        vals = [x for x in POOL[:12] if rng.below(2)]
        st = stakes_for(rng, form, keys, weights, vals, rng.pick([0, 1, 2, 5, 12, 1 << 60]))
        signers = [x for x in POOL[:12] if rng.below(2)]
        add("random-" + form, st, signers, rng.pick(FRACTIONS))
    # empty stake map and empty signer set
    add("empty-stakes", Stakes("T", [], [], 3, 0, 0), [], 0)
    add("empty-ring", Stakes("R", [], [], 3, 0, 0), POOL[:2], 0x3FE0000000000000)
    return out


def hash_text(h):
    """Z: all zero; one byte: that byte repeated 32 times; otherwise all 32 bytes in hex."""
    if h == bytes(32):
        return "Z"
    return h[:1].hex() if len(set(h)) == 1 else h.hex()


def build_flow(rng):
    out = []
    n = 0

    def add(group, entry, c):
        nonlocal n
        log = []
        if entry == "V":
            tag, payload = ref_verify(c, log)
        else:
            tag, payload = ref_decision(c, log)
        out.append(("f%04d" % n, group, entry, c["sigs"].text(), hash_text(c["hash"]), "%x" % c["a"], "%x" % c["b"],
                    "%x" % c["c"], "%x" % c["d"], "%x" % c["e"], "%x" % c["ctx_c"], "%x" % c["ctx_d"],
                    "%016x" % c["fraction"], "N" if c["stakes"] is None else c["stakes"].text(),
                    tag, payload, " ".join(log) or "-"))
        n += 1

    def base(**kw):
        c = dict(a=0x77, b=5, c=9, d=8, e=6, ctx_c=0x77, ctx_d=5, hash=bytes([0x42]) * 32, fraction=0,
                 stakes=None, sigs=Coll("T", []))
        c.update(kw)
        return c

    def scenario(form_set, form_sig, size, wrong=None, miss=None, skew=False, vals_n=None):
        keys = POOL[:size]
        n_keys = max(size, 1) + (2 if skew else 0)
        weights = ([1] * size + [1000, 1000]) if skew else [10] * n_keys
        st = stakes_for(rng, form_set, POOL[:n_keys], weights,
                        POOL[:vals_n if vals_n is not None else n_keys], n_keys)
        members = list(keys)
        if miss is not None and size:
            members[miss % size] = key(0xE0)
        order = list(members)
        if form_sig == "R" and size > 1:
            for i in range(size - 1, 0, -1):
                j = rng.below(i + 1)
                order[i], order[j] = order[j], order[i]
        specs = ["V"] * len(order)
        if wrong is not None and order:
            specs[wrong % len(order)] = rng.pick(["E", "R" + kt(key(0x77))])
        cap = len(order) + rng.below(3)
        coll = Coll(form_sig, list(zip(order, specs)), cap, rng.below(cap) if cap else 0)
        return st, coll

    # provider has no stake set for the round
    for e in (0, 1, 6, M):
        add("provider-none", "V", base(e=e))
    # every outcome of the verifier, tree and ring on both sides
    for form_set in "TR":
        for form_sig in "TR":
            for size in (1, 2, 3, 5):
                st, coll = scenario(form_set, form_sig, size)
                add("accepted", "V", base(stakes=st, sigs=coll))
                st, coll = scenario(form_set, form_sig, size, miss=rng.below(size))
                add("unknown-signer", "V", base(stakes=st, sigs=coll))
                st, coll = scenario(form_set, form_sig, size, skew=True)
                add("quorum-stake", "V", base(stakes=st, sigs=coll))
                st, coll = scenario(form_set, form_sig, size, vals_n=0)
                add("quorum-count", "V", base(stakes=st, sigs=coll, fraction=0x3FE0000000000000))
                for wrong in range(size):
                    st, coll = scenario(form_set, form_sig, size, wrong=wrong)
                    add("bad-signature", "V", base(stakes=st, sigs=coll))
    # empty certificate: the stake test can never pass with zero signers
    for form_set in "TR":
        st, coll = scenario(form_set, "T", 0)
        add("empty-certificate", "V", base(stakes=st, sigs=coll))
    # repeated key in a ring: checked twice, counted once
    st = stakes_for(rng, "T", POOL[:2], [10] * 2, POOL[:2], 2)
    add("duplicate-key", "V", base(stakes=st, sigs=Coll("R", [(POOL[0], "V"), (POOL[1], "V"), (POOL[0], "V")], 4, 2)))
    add("duplicate-key-bad", "V", base(stakes=st, sigs=Coll("R", [(POOL[0], "V"), (POOL[1], "E"), (POOL[0], "V")], 3, 1)))
    # the signed frame carries every certificate field: random field values, signatures made for them
    for _ in range(24):
        st, coll = scenario("TR"[rng.below(2)], "TR"[rng.below(2)], 1 + rng.below(4))
        add("frame-fields", "V", base(stakes=st, sigs=coll, a=rng.u64(), b=rng.u64(), c=rng.u64(), d=rng.u64(),
                                      e=rng.u64(), hash=bytes([1 + rng.below(255)]) * 32))
    # fraction patterns through the whole verifier
    for bits in FRACTIONS:
        st, coll = scenario("T", "T", 3, vals_n=2)
        add("fraction", "V", base(stakes=st, sigs=coll, fraction=bits))
    # decision entry: pair relation, ordered chain, empty route, divergence
    pairs = [(0, 0), (1, 5), (5, 1), (M, 0), (0, M), (1 << 63, 1 << 63)]
    for (a, b) in pairs:
        for (cc, dd) in pairs:
            for kind in ("empty", "chain", "behind"):
                if kind == "chain":
                    f30, f38, f40 = (b + 3) & M, (b + 2) & M, (b + 1) & M
                    if not (b < f30 and f38 < f30 and b <= f40 <= f38):
                        continue
                elif kind == "empty":
                    f30 = f38 = f40 = b
                else:
                    f30, f38, f40 = (b - 1) & M, b, b
                for sigkind in ("good", "none", "bad"):
                    st, coll = scenario("T" if (a + b) % 2 else "R", "R", 2, wrong=0 if sigkind == "bad" else None)
                    if sigkind == "none":
                        coll = Coll("R", [], 0, 0)
                    c = base(a=a, b=b, c=f30, d=f38, e=f40, ctx_c=cc, ctx_d=dd, stakes=st, sigs=coll,
                             hash=bytes(32) if kind == "empty" else bytes([0x42]) * 32)
                    add("decision-" + kind + "-" + sigkind, "D", c)
    # decision: the empty route with a tail byte set, a provider without set, a tree-form certificate
    for pos in (0, 31):
        t = bytearray(32)
        t[pos] = 1
        add("decision-tail", "D", base(a=3, b=4, c=4, d=4, e=4, ctx_c=3, ctx_d=4, hash=bytes(t)))
    add("decision-no-set", "D", base(a=3, b=4, c=6, d=5, e=4, ctx_c=3, ctx_d=4))
    st, coll = scenario("R", "T", 70)
    add("decision-tree-certificate", "D", base(a=3, b=4, c=6, d=5, e=4, ctx_c=3, ctx_d=4, stakes=st, sigs=coll))
    return out


def flow_row(n, group, entry, c):
    """One cases-tree.tsv row, same columns as cases-flow.tsv (id prefix t)."""
    log = []
    tag, payload = ref_verify(c, log) if entry == "V" else ref_decision(c, log)
    return ("t%04d" % n, group, entry, c["sigs"].text(), hash_text(c["hash"]), "%x" % c["a"], "%x" % c["b"],
            "%x" % c["c"], "%x" % c["d"], "%x" % c["e"], "%x" % c["ctx_c"], "%x" % c["ctx_d"],
            "%016x" % c["fraction"], "N" if c["stakes"] is None else c["stakes"].text(),
            tag, payload, " ".join(log) or "-")


TREE_SIZES = (65, 72, 80)


def build_tree_flow(rng):
    """Certificates of more than 64 signatures (native tree storage, several leaves of at most 11 entries),
    and empty certificates. Added in round 3 after an independent trace found that relations.tsv V5 gave
    the wrong signature pointer for tree entries (the value slot node+8+72*i, not key address+0x18). The
    rule list says each entry's own signature goes to the check, in key order; here a signature valid for
    the neighbouring key (what a shifted slot would hand over) must be refused at the entry where it sits,
    and the call log must stop there. Positions are in key order (the pool is sorted by first byte)."""
    out = []

    def add(group, entry, c):
        out.append(flow_row(len(out), group, entry, c))

    def base(**kw):
        c = dict(a=0x77, b=5, c=9, d=8, e=6, ctx_c=0x77, ctx_d=5, hash=bytes([0x42]) * 32, fraction=0,
                 stakes=None, sigs=Coll("T", []))
        c.update(kw)
        return c

    def tree_case(size, specs=None, absent=(), skew=False, vals=True, form=None):
        keys = POOL[:size]
        spec_list = ["V"] * size
        for p, s in (specs or {}).items():
            spec_list[p] = s
        holders = [k for i, k in enumerate(keys) if i not in absent]
        extra = [key(0xFE), key(0xFF)] if skew else []  # first bytes 0xFE/0xFF are not in POOL (0x10..0xFD step 3)
        entries = holders + extra
        weights = ([1] * len(holders) + [1000] * len(extra)) if skew else [10] * len(entries)
        st = stakes_for(rng, form or "TR"[rng.below(2)], entries, weights, holders if vals else [], len(entries))
        return st, Coll("T", list(zip(keys, spec_list)))

    def neighbour(keys, p):
        return "R" + kt(keys[(p + 1) % len(keys)])

    for size in TREE_SIZES:
        keys = POOL[:size]
        st, coll = tree_case(size)
        add("tree-accepted", "V", base(stakes=st, sigs=coll))
        if size == 72:
            for p in (size // 2,):
                st, coll = tree_case(size, {p: "E"})
                add("tree-bad-signature", "V", base(stakes=st, sigs=coll))
                st, coll = tree_case(size, {p: neighbour(keys, p)})
                add("tree-swapped-signature", "V", base(stakes=st, sigs=coll))
            continue
        # every entry carries the signature made for the next key: refused at entry 0, one digest only
        st, coll = tree_case(size, {p: neighbour(keys, p) for p in range(size)})
        add("tree-shifted-slot", "V", base(stakes=st, sigs=coll))
        for p in sorted({0, 10, 11, 32, size // 2, 63, 64, size - 1}):
            st, coll = tree_case(size, {p: "E"})
            add("tree-bad-signature", "V", base(stakes=st, sigs=coll))
        for p in (5, 33, size - 2):
            st, coll = tree_case(size, {p: neighbour(keys, p)})
            add("tree-swapped-signature", "V", base(stakes=st, sigs=coll))
        st, coll = tree_case(size, absent={size // 3})
        add("tree-unknown-signer", "V", base(stakes=st, sigs=coll))
        st, coll = tree_case(size, absent={size // 2, size - 3})
        add("tree-two-unknown", "V", base(stakes=st, sigs=coll))
        st, coll = tree_case(size, skew=True)
        add("tree-quorum-stake", "V", base(stakes=st, sigs=coll))
        st, coll = tree_case(size, vals=False)
        add("tree-quorum-count", "V", base(stakes=st, sigs=coll, fraction=0x3FE0000000000000))
    add("tree-provider-none", "V", base(sigs=tree_case(65)[1]))

    # the ring form at its largest (64 rows), logical order shuffled: the same rule, different visiting order
    keys = POOL[:64]
    for bad_last in (False, True):
        order = list(keys)
        for i in range(63, 0, -1):
            j = rng.below(i + 1)
            order[i], order[j] = order[j], order[i]
        specs = ["V"] * 64
        if bad_last:
            specs[-1] = "E"
        cap = 64 + rng.below(3)
        st = stakes_for(rng, "T", keys, [10] * 64, keys, 64)
        coll = Coll("R", list(zip(order, specs)), cap, rng.below(cap))
        add("ring-64-control-bad-last" if bad_last else "ring-64-control-accepted", "V", base(stakes=st, sigs=coll))

    # the same tree through the whole decision (ordered path: pair equal, 5 <= f40 <= f38 < f30 in the base case)
    for bad in (None, 40):
        st, coll = tree_case(70, None if bad is None else {bad: "E"})
        add("tree-decision-bad" if bad else "tree-decision-accepted", "D",
            base(a=3, b=4, c=6, d=5, e=4, ctx_c=3, ctx_d=4, stakes=st, sigs=coll))

    # empty certificate: no signer can reach 3*signed > 2*total, whatever the total (even zero); a missing
    # stake set wins over everything
    add("empty-zero-stake-tree", "V", base(stakes=Stakes("T", [], [], 0, 0, 0), sigs=Coll("T", [])))
    add("empty-zero-stake-ring", "V", base(stakes=Stakes("R", [], [], 0, 0, 0), sigs=Coll("R", [], 0, 0)))
    add("empty-provider-none", "V", base(sigs=Coll("T", [])))
    return out


def write(path, cols, rows):
    with open(path, "w", newline="\n") as f:
        f.write("\n".join(["\t".join(cols)] + ["\t".join(r) for r in rows]) + "\n")
    print("%s\t%d" % (os.path.basename(path), len(rows)))


def main():
    out = sys.argv[1]
    rng = Rng(0x115AB1E5)
    write(os.path.join(out, "cases-equal.tsv"), ["id", "group", "first", "second", "equal"], build_equal(rng))
    write(os.path.join(out, "cases-collect.tsv"), ["id", "group", "sigs", "stakes", "result"], build_collect(rng))
    write(os.path.join(out, "cases-signer.tsv"),
          ["id", "group", "stakes", "hash", "a", "b", "c", "d", "e", "variant", "address", "sig", "valid", "log"],
          build_signer(rng))
    quorum = build_quorum(rng)
    quorum += build_quorum_band(Rng(0x2F3), len(quorum))
    write(os.path.join(out, "cases-quorum.tsv"),
          ["id", "group", "stake_map", "validators", "validator_count", "signers", "fraction_bits", "quorum"],
          quorum)
    write(os.path.join(out, "cases-flow.tsv"),
          ["id", "group", "entry", "sigs", "hash", "a", "b", "c", "d", "e", "ctx_c", "ctx_d", "fraction",
           "provider", "tag", "payload", "log"], build_flow(rng))
    write(os.path.join(out, "cases-tree.tsv"),
          ["id", "group", "entry", "sigs", "hash", "a", "b", "c", "d", "e", "ctx_c", "ctx_d", "fraction",
           "provider", "tag", "payload", "log"], build_tree_flow(Rng(0x7EE5)))


main()
