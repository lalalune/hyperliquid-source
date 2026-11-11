#!/usr/bin/env python3
from pathlib import Path

out = Path(__file__).resolve().parent / "cursor-vectors.tsv"
sets = [[], [0], [65535], [0, 127, 65535], [0, 1, 2, 3, 4]]
rows = []
for keys in sets:
    for query in range(256):
        pos = next((i for i, key in enumerate(keys) if key >= query), len(keys))
        found = pos < len(keys) and keys[pos] == query
        rows.append((len(keys), ",".join(map(str, keys)), query, int(found), pos))
lines = ["length\tkeys\tquery\tfound\tposition"]
lines.extend("\t".join(map(str, row)) for row in rows)
out.write_text("\n".join(lines) + "\n", encoding="ascii", newline="\n")
print(f"wrote {len(rows)} cases")
