"""How many string literals in a reconstructed source tree occur verbatim in a binary.

Only literals of at least MIN_LEN characters count; simple escapes are undone.
Prints overall and per-top-level-dir rates plus sample misses.

usage: python3 -I grounding.py SRC_DIR BINARY [MIN_LEN]
"""
import collections
import os
import re
import sys

src, binary = sys.argv[1], sys.argv[2]
min_len = int(sys.argv[3]) if len(sys.argv) > 3 else 8
data = open(binary, "rb").read()
lit = re.compile(r'(?<![A-Za-z0-9_\'])"((?:[^"\\\n]|\\.)*)"')
esc = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"', "'": "'", "0": "\0"}


def unescape(s):
    return re.sub(r"\\(.)", lambda m: esc.get(m.group(1), m.group(0)), s)


per_dir = collections.defaultdict(lambda: [0, 0])
misses, seen = collections.defaultdict(list), set()
for root, _, files in os.walk(src):
    if ".git" in root.split(os.sep):
        continue
    for f in files:
        if not f.endswith(".rs"):
            continue
        p = os.path.join(root, f)
        top = os.path.relpath(p, src).split(os.sep)[0]
        text = open(p, encoding="utf-8", errors="replace").read()
        for m in lit.finditer(text):
            s = unescape(m.group(1))
            if len(s) < min_len or "{" in s or (top, s) in seen:
                continue  # skip short and format-template literals
            seen.add((top, s))
            hit = s.encode() in data
            per_dir[top][0] += hit
            per_dir[top][1] += 1
            if not hit:
                misses[top].append(s)

tot_hit = sum(h for h, _ in per_dir.values())
tot = sum(n for _, n in per_dir.values())
print(f"overall: {tot_hit}/{tot} = {100 * tot_hit / max(tot, 1):.1f}% of distinct literals (len>={min_len}, no '{{') found verbatim")
for top, (h, n) in sorted(per_dir.items(), key=lambda kv: -kv[1][1]):
    print(f"  {top:18s} {h:5d}/{n:<5d} {100 * h / max(n, 1):5.1f}%")
print("sample misses:")
for top in sorted(misses, key=lambda t: -len(misses[t]))[:4]:
    print(f"  [{top}]", " | ".join(repr(s[:60]) for s in misses[top][:6]))
