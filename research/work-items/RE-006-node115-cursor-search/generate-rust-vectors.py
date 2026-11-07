#!/usr/bin/env python3
from pathlib import Path

out = Path(__file__).resolve().parent / "cursor-vectors.tsv"
rows = []
sets = [[], [0], [255], [0, 127, 128, 255], [0, 1, 2, 3, 4]]
for keys in sets:
    for key in range(256):
        pos = next((i for i, item in enumerate(keys) if item >= key), len(keys))
        found = pos < len(keys) and keys[pos] == key
        rows.append((len(keys), ",".join(map(str, keys)), key, int(found), pos))
lines = ["length\tkeys\tquery\tfound\tposition"]
lines.extend("\t".join(map(str, row)) for row in rows)
out.write_text("\n".join(lines) + "\n", encoding="ascii", newline="\n")
print(f"wrote {len(rows)} cases")
