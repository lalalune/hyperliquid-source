"""Split a reconstruction's string literals into grounded / drift / notes / partial / unanchored.

grounded   - verbatim in the source binary (#94) and still in the newer one (#115)
drift      - verbatim in #94 but gone from #115
late       - absent from #94 but present in #115 (should be rare; coincidences)
notes      - absent from both, and looks like an analyst/agent annotation
partial    - absent verbatim, but some 3-word window (>=10 chars) occurs in #94
unanchored - absent, with no 3-word window in #94 (paraphrased or invented)

usage: python3 -I drift.py SRC_DIR BIN_SOURCE BIN_NEWER OUT_JSON [MIN_LEN]
"""
import collections
import json
import os
import re
import subprocess
import sys
import tempfile

src, bin_a, bin_b, out_json = sys.argv[1:5]
min_len = int(sys.argv[5]) if len(sys.argv) > 5 else 8
a, b = open(bin_a, "rb").read(), open(bin_b, "rb").read()
lit = re.compile(r'(?<![A-Za-z0-9_\'])"((?:[^"\\\n]|\\.)*)"')
esc = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"', "'": "'", "0": "\0"}
note_re = re.compile(r"sub_[0-9A-Fa-f]{4,}|\b0x[0-9A-Fa-f]{5,}\b|\bsee\b|—|TODO|FIXME|reconstruct|placeholder|\bstub\b|\bEA\b", re.I)


def unescape(s):
    return re.sub(r"\\(.)", lambda m: esc.get(m.group(1), m.group(0)), s)


# Attribute arguments that only exist at compile time (paths, case conventions, cfgs, docs).
attr_key = re.compile(r"\b(rename_all|rename_all_fields|skip_serializing_if|default|with|serialize_with|"
                      r"deserialize_with|bound|from|into|try_from|remote|crate|path|doc|cfg|cfg_attr|"
                      r"allow|deny|warn|must_use|deprecated|note|since|link_name|export_name|target_feature)"
                      r"\s*=\s*$")
items, attr_only = {}, set()  # (top, literal) -> first file
for root, _, files in os.walk(src):
    if "/.git" in root:
        continue
    for f in files:
        if f.endswith(".rs"):
            p = os.path.join(root, f)
            rel = os.path.relpath(p, src)
            top = rel.split(os.sep)[0]
            text = open(p, encoding="utf-8", errors="replace").read()
            for m in lit.finditer(text):
                s = unescape(m.group(1))
                if len(s) < min_len or "{" in s:
                    continue
                line_start = text.rfind("\n", 0, m.start()) + 1
                before = text[line_start:m.start()]
                if before.lstrip().startswith("#[") and attr_key.search(before):
                    attr_only.add((top, s))
                    continue
                items.setdefault((top, s), rel)
for key in attr_only & items.keys():
    attr_only.discard(key)  # also used as a runtime literal elsewhere

cls, windows = {}, {}
for key in items:
    s = key[1].encode()
    in_a, in_b = s in a, s in b
    if in_a:
        cls[key] = "grounded" if in_b else "drift"
    elif in_b:
        cls[key] = "late"
    elif note_re.search(key[1]):
        cls[key] = "notes"
    else:
        words = key[1].split()
        wins = {" ".join(words[i:i + 3]) for i in range(len(words) - 2)}
        windows[key] = {w for w in wins if len(w) >= 10 and "\n" not in w}

pats = sorted({w for ws in windows.values() for w in ws})
found = set()
if pats:
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        fh.write("\n".join(pats) + "\n")
    r = subprocess.run(["rg", "-a", "-o", "-F", "-N", "--no-filename", "-f", fh.name, bin_a], capture_output=True)
    found = {l.decode("utf-8", "replace") for l in r.stdout.splitlines()}
    os.unlink(fh.name)
a_lower = a.lower()
for key, ws in windows.items():
    if ws & found:
        cls[key] = "partial"
    elif key[1].lower().encode() in a_lower:
        cls[key] = "case"
    else:
        cls[key] = "unanchored"
print(f"excluded {len(attr_only)} compile-time attribute literals (e.g. {sorted(s for _, s in attr_only)[:5]})")

order = ["grounded", "drift", "late", "notes", "partial", "case", "unanchored"]
tot = collections.Counter(cls.values())
per = collections.defaultdict(collections.Counter)
for (top, _), c in cls.items():
    per[top][c] += 1
n = len(cls)
print(f"{n} distinct literals (len>={min_len}, no '{{')")
print("overall: " + "  ".join(f"{c} {tot[c]} ({100 * tot[c] / n:.1f}%)" for c in order))
print(f"verbatim in source binary #94: {tot['grounded'] + tot['drift']} ({100 * (tot['grounded'] + tot['drift']) / n:.1f}%)")
print(f"{'crate':18s}" + "".join(f"{c:>11s}" for c in order) + "   in#94%")
for top, cnt in sorted(per.items(), key=lambda kv: -sum(kv[1].values())):
    m = sum(cnt.values())
    print(f"{top:18s}" + "".join(f"{cnt[c]:>11d}" for c in order) + f"   {100 * (cnt['grounded'] + cnt['drift']) / m:5.1f}%")
examples = {c: [f"{items[k]}: {k[1][:70]!r}" for k, v in cls.items() if v == c][:8] for c in order}
for c in ("drift", "partial", "unanchored", "notes"):
    print(f"-- {c} examples:")
    for e in examples[c]:
        print("   ", e)
json.dump({"counts": dict(tot), "per_crate": {k: dict(v) for k, v in per.items()},
           "items": [{"crate": k[0], "file": items[k], "literal": k[1], "class": v} for k, v in cls.items()]},
          open(out_json, "w"), indent=1)
