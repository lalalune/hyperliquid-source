# RE-010 · Node #115 digest-vote execution handoff to separate trackers

- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.
- Scope: selected direct and nested Action dispatch, ABCI digest vote authentication/height admission, and the point where the two vote families feed distinct state subobjects.

The prior display-name packet enumerates the router and nested dispatcher tables, but follows a different Action. The prior hash-signature record packet qualifies the tracker helpers without identifying these call sites. #4113 maps the corresponding formatter tags. The new evidence joins the selected execution arms to their tracker calls.

| Internal tag | Direct router arm and wrapper | Nested dispatcher arm and shared core | Tracker offset and call |
| --- | --- | --- | --- |
| `0xdc` L1 hash | `0x2bdaf18` → `0x2c16eb0` | `0x2bdc615` → `0x283ad10` | state `+0x3d98`, call `0x283ae93` → `0x27606d0` |
| `0xdd` ABCI digest | `0x2bdb0c8` → `0x2c19610` | `0x2bdc896` → `0x294fdd0` | state `+0x3e50`, call `0x294ff53` → `0x2760bc0` |

Both dispatchers add 8 to the Action pointer on these arms. The direct ABCI wrapper calls two existing gates and checks each result word against `0x1a2` before invoking the same core used by the nested arm. The L1 wrapper also reaches its nested core on its selected success path.

In the ABCI core, height comes from payload `+0x20`, the two digest lanes come from payload base, and the pointer to signature storage is payload `+0x28`. The core prepares a digest/signature-check input, calls slot `0x64e0ad8`, then compares the selected 20-byte result against the third argument. A result byte of 1 from the slot takes error `0x7e`. A mismatch takes `0x12e`. After the selected matching branch, an unsigned height at least `0x0ccccccccccccccc` takes error `0x154`. Those paths bypass the tracker call. The accepted branch assembles the signature pointer, height, digest and compared identity into the message passed to the tracker. Tracker return word `0x1a2` maps to outer byte `0x0a` here.

The offset and call separation identifies where to look for the two vote families. It does not establish a quorum for a real height, the digest's source algorithm or equivalence to an independently sourced root. All joins are static, with normal helper returns and ordinary binding as applicable. No completion gate is requested.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agreed on the 59 retained spans. Re-run either from the start and exclusive end listed in [instructions.tsv](instructions.tsv). This check verifies the pinned ELF, matched unwind bounds, selected table cells and relative call operands:

```sh
PYTHONPATH=tools python3 -B - <<'PY'
import csv
import hashlib
from pathlib import Path
from elf_index import unwind_index
from fde_extents import eh_frame_records

data = Path("artifacts/node/115/hl-node").read_bytes()
assert hashlib.sha256(data).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
sections, header = unwind_index(data)
_, fdes = eh_frame_records(data, sections)
indexed = {(row["start"], row["fde"]) for row in header}
bounds = {(row["start"], row["end"]) for row in fdes if (row["start"], row["fde"]) in indexed}

def raw(section_name, va, size):
    section = next(row for row in sections if row["name"] == section_name)
    relative = va - section["address"]
    assert 0 <= relative <= section["size"] - size
    start = section["offset"] + relative
    return data[start:start + size]

path = Path("research/work-items/RE-010-node115-digest-vote-handler-tracker/instructions.tsv")
with path.open() as handle:
    rows = list(csv.DictReader(handle, delimiter="\t"))
for row in rows:
    start, end, va = (int(row[key], 16) for key in ("fde_start", "fde_end", "va"))
    expected = bytes.fromhex(row["bytes"])
    assert (start, end) in bounds and start <= va < va + len(expected) <= end
    assert raw(".text", va, len(expected)) == expected
for table, targets in ((0x609f00, (0x2bdaf18, 0x2bdb0c8)), (0x60a360, (0x2bdc615, 0x2bdc896))):
    for index, target in enumerate(targets, 86):
        assert table + int.from_bytes(raw(".rodata", table + 4 * index, 4), "little", signed=True) == target
for va, target in {
    0x2bdaf28: 0x2c16eb0, 0x2bdb0d8: 0x2c19610, 0x2bdc627: 0x283ad10,
    0x2bdc8a8: 0x294fdd0, 0x2c1718c: 0x283ad10, 0x2c198ec: 0x294fdd0,
    0x283ae93: 0x27606d0, 0x294ff53: 0x2760bc0,
}.items():
    code = raw(".text", va, 5)
    assert code[0] == 0xe8 and va + 5 + int.from_bytes(code[1:], "little", signed=True) == target
print(f"{len(rows)} byte spans, four table cells and eight call targets match")
PY
```
