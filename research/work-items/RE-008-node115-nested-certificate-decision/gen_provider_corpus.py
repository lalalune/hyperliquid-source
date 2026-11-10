#!/usr/bin/env python3
"""Generate cases-provider.tsv: expected results of the stake-set provider 0x595e5c0 (no Rust involved).

Usage: python3 -I gen_provider_corpus.py <output directory>

Rule list (relations-provider.tsv PR3..PR6, with the history search of RE-008-proposer-selection-115):
  base = state+0x20, exec = state+0x60, counter = state+0x68, r = query round (all u64)
  limit   = max(min(base + 2000, MAX), min(exec + 201, MAX))
  warning = r >= limit                     counter' = (counter + warning) mod 2^64
  q       = base                           if r < min(base + 2000, MAX)
            max(base, (r - 200) mod 2^64)  otherwise
  result  = the greatest stored round <= q (tag 0x2e), none gives tag 0x28 with r.
"""
import os
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


def provider(rounds, base, exec_, counter, r):
    sat = lambda x: min(x, M)
    limit = max(sat(base + 2000), sat(exec_ + 201))
    warning = r >= limit
    q = base if r < sat(base + 2000) else max(base, (r - 200) & M)
    below = [x for x in rounds if x <= q]
    return (max(below) if below else None), (counter + warning) & M


V = [0, 1, 199, 200, 201, 1999, 2000, 2001, 2199, 2200, 2201, 4000, 1 << 63, M - 2000, M - 1999, M - 1998, M - 401,
     M - 201, M - 200, M - 1, M]
HISTORIES = [[], [0], [5], [3, 9, 27], [100, 2000, 2200, 4000], list(range(1, 14)), [M - 1, M], [0, M],
             [1, 200, 201, 2000, 2001, 4001], [7, (1 << 63) - 1, 1 << 63], [M - 2000, M - 1999, M - 200]]


def text(form, rounds, cap, head):
    body = ",".join("%x" % x for x in rounds)
    return ("T=" if form == "T" else "R%d.%d=" % (cap, head)) + body


def main():
    rng = Rng(0x595E5C0)
    rows = []

    def add(group, rounds, form, base, exec_, counter, r):
        cap = len(rounds) + rng.below(3)
        head = rng.below(cap) if (form == "R" and cap) else 0
        sel, after = provider(rounds, base, exec_, counter, r)
        rows.append(("p%04d" % len(rows), group, text(form, rounds, cap, head), "%x" % base, "%x" % exec_,
                     "%x" % counter, "%x" % r, "-" if sel is None else "%x" % sel, "%x" % after))

    hist = HISTORIES[8]
    for i, base in enumerate([0, 5, M - 1999, M]):
        for j, exec_ in enumerate([0, 1500, M - 200]):
            for k, r in enumerate(V):
                add("boundary", hist, "TR"[(i + j + k) % 2], base, exec_, [0, 7, M][(i + k) % 3], r)
    for _ in range(220):
        add("random", rng.pick(HISTORIES), rng.pick("TR"), rng.pick(V), rng.pick(V), rng.pick([0, 1, M]), rng.pick(V))
    for rounds in HISTORIES:
        for form in "TR":
            add("history", rounds, form, 0, 0, 0, M)
            add("history", rounds, form, 4000, 5000, 3, 4200)
    # Added after mutant H04 (lookup round without the max against the base) survived the first 516 rows:
    # the max only matters when base > MAX - 200, so the history needs rounds in that range.
    high = [M - 2000, M - 1999, M - 200, M - 1, M]
    for base in (M - 1999, M - 1, M):
        for r in (M - 1, M):
            add("boundary-high", high, "TR"[len(rows) % 2], base, 0, 0, r)
    cols = ["id", "group", "history", "base", "exec", "counter", "round", "selected", "counter_after"]
    with open(os.path.join(sys.argv[1], "cases-provider.tsv"), "w", newline="\n") as f:
        f.write("\n".join(["\t".join(cols)] + ["\t".join(r) for r in rows]) + "\n")
    print("cases-provider.tsv\t%d" % len(rows))


main()
