#!/usr/bin/env python3
"""Generate cases.tsv for the node #115 nested certificate decision 0x595fd20.

The expected columns come from the relation table in relations.tsv, which was
read from the disassembly. This file does not import or call any Rust code.
Usage: python3 -I gen_corpus.py <output cases.tsv>
"""
import sys

M = (1 << 64) - 1
H63 = 1 << 63
HEAD = (0x1111111111111111, 0x2222222222222222, 0x3333333333333333, 0x4444444444444444)
V4 = [0, 1, H63, M]
V5 = [0, 1, 2, H63, M]
ZERO_TAIL = bytes(32)
VALIDATORS = [None, (0x02, 0), (0x10, 0), (0x13, 0), (0x20, 0), (0x2D, 0), (0x00, 0), (0x05, 0)]


def expect(k):
    """Return (tag, payload words, helper_calls, validator_calls, ref, path) per relations.tsv."""
    a, b, cc, dd = k["a"], k["b"], k["ctx_c"], k["ctx_d"]
    c, d, e, tail = k["c"], k["d"], k["e"], k["tail"]
    ref = [0, 8, 0, 0, a, b, b, b, b, 0, 0, 0, 0]
    if (a, b) == (cc, dd):
        if c < b:  # P1
            return "05", [], 0, 0, None, "P1"
        if c == b:
            if d != b:  # P2
                return "06", [], 0, 0, None, "P2"
            if e != b:  # P3
                return "06", [], 0, 0, None, "P3"
            if tail != ZERO_TAIL:  # P4
                return "06", [], 0, 0, None, "P4"
            if k["helper"]:  # P6
                return "2e", [], 1, 0, ref, "P6"
            return "06", [], 1, 0, ref, "P5"
        if d >= c:  # P7
            return "2d", [c, d, e], 0, 0, None, "P7"
        if b > e:  # P8
            return "2d", [c, d, e], 0, 0, None, "P8"
        if e > d:  # P9
            return "2d", [c, d, e], 0, 0, None, "P9"
        v = k["validator"]  # P10
        if v is None:
            return "2e", [], 0, 1, None, "P10"
        return "%02x" % v[0], [v[1]], 0, 1, None, "P10"
    if a <= cc:  # P11
        return "00", [a, b, cc, dd], 0, 0, None, "P11"
    v = k["validator"]
    if v is None:  # P12
        return "DIVERGE", [cc, dd, a, b], 0, 1, None, "P12"
    return "00", [a, b, cc, dd], 0, 1, None, "P13"


def case(group, **kw):
    k = dict(head=HEAD, a=0x77, b=0, c=0, d=0, e=0, tail=ZERO_TAIL, ctx_c=0x77, ctx_d=0,
             helper=True, validator=None)
    k.update(kw)
    k["group"] = group
    return k


def build():
    out = []
    # G1: pair relation over V4^4, downstream fields chosen to reach the empty route for equal pairs.
    i = 0
    for a in V4:
        for b in V4:
            for cc in V4:
                for dd in V4:
                    v = VALIDATORS[i % len(VALIDATORS)]
                    out.append(case("pair", a=a, b=b, c=b, d=b, e=b, ctx_c=cc, ctx_d=dd,
                                    helper=(i % 3 != 0), validator=v))
                    i += 1
    # G2: c against B with equal pairs, d=e chosen so the ordered chain passes when c > B.
    for b in V5:
        for c in V5:
            de = b if c <= b else c - 1
            out.append(case("c-vs-b", b=b, c=c, d=de, e=de, ctx_d=b, validator=(0x13, 0)))
    # G3: c == B, one downstream deviation at a time.
    for b in V5:
        for d in sorted({(b + 1) & M, (b - 1) & M, 0, M} - {b}):
            out.append(case("empty-d", b=b, c=b, d=d, e=b, ctx_d=b))
            out.append(case("empty-e", b=b, c=b, d=b, e=d, ctx_d=b))
            out.append(case("empty-de", b=b, c=b, d=d, e=d, ctx_d=b))
        for hv in (True, False):
            out.append(case("empty-helper", b=b, c=b, d=b, e=b, ctx_d=b, helper=hv))
    for pos in range(32):
        t = bytearray(32)
        t[pos] = 1
        out.append(case("tail-byte", b=1, c=1, d=1, e=1, ctx_d=1, tail=bytes(t)))
    for t in (bytes([0xFF] * 32), bytes([0x80] + [0] * 31), bytes([0] * 31 + [0x80])):
        out.append(case("tail-pattern", b=1, c=1, d=1, e=1, ctx_d=1, tail=t))
    # G4: c > B, every (d, e) over V5.
    j = 0
    for b in V5:
        for c in V5:
            if c <= b:
                continue
            for d in V5:
                for e in V5:
                    v = VALIDATORS[j % len(VALIDATORS)]
                    out.append(case("chain", b=b, c=c, d=d, e=e, ctx_d=b, validator=v))
                    j += 1
    return out


def hx(x):
    return "%x" % x


def main():
    cases = build()
    marker = 0xC0DE0000
    lines = []
    cols = ["id", "group", "head", "a", "b", "c", "d", "e", "tail", "ctx_c", "ctx_d", "helper",
            "validator", "out_tag", "out_words", "helper_calls", "validator_calls", "ref"]
    lines.append("\t".join(cols))
    stats = {}
    for n, k in enumerate(cases):
        v = k["validator"]
        if v is not None:
            marker += 1
            v = (v[0], marker)
            k["validator"] = v
        tag, words, hc, vc, ref, path = expect(k)
        stats[path] = stats.get(path, 0) + 1
        vtxt = "A" if v is None else "R:%02x:%x" % v
        lines.append("\t".join([
            "c%04d" % n, k["group"], ":".join(hx(x) for x in k["head"]),
            hx(k["a"]), hx(k["b"]), hx(k["c"]), hx(k["d"]), hx(k["e"]), k["tail"].hex(),
            hx(k["ctx_c"]), hx(k["ctx_d"]), "T" if k["helper"] else "F", vtxt,
            tag, ":".join(hx(x) for x in words) if words else "-", str(hc), str(vc),
            ":".join(hx(x) for x in ref) if ref else "-"]))
    with open(sys.argv[1], "w", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    for key in sorted(stats, key=lambda p: int(p[1:])):
        print("%s\t%d" % (key, stats[key]))
    print("total\t%d" % len(cases))


main()
