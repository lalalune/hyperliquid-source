#!/usr/bin/env python3
from pathlib import Path

out = Path(__file__).resolve().parent / "ring-vectors.tsv"
rows = []
for capacity in range(1, 17):
    for head in range(capacity):
        for length in range(capacity):
            rows.append((capacity, head, length, (head + length) % capacity, length + 1))
lines = ["capacity\thead\tlength\tindex\tnext_length"]
lines.extend("\t".join(map(str, row)) for row in rows)
out.write_text("\n".join(lines) + "\n", encoding="ascii", newline="\n")
print(f"wrote {len(rows)} cases")
