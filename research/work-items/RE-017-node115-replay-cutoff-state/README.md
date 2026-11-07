# RE-017 · Node #115 replay admission tracks two independent keys

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

[PR #4011](https://github.com/lalalune/hyperliquid-source/pull/4011) locates the startup word in the restored consensus-round field. [PR #4135](https://github.com/lalalune/hyperliquid-source/pull/4135) recovers the converter's empty-input test. This packet follows the worker's two copies of the initial word across consecutive iterations, which affects where a real replay can first execute.

| Worker lane | Initial source | Payload record before conversion | Converter sentinel | Selected completed conversion |
| --- | --- | --- | --- | --- |
| Identity expectation at stack +0x168 | Entry R8 | Checked against the incoming identity, then assigned the saturated successor of the record's selected +0x60 or +0xb0 | Remains advanced | Remains advanced |
| Empty-input cutoff basis in R15 | Entry R8 | Forwarded to the converter as RDX | Carried unchanged along the retry edge | Reloaded from converted output +0x18, which carries the successor |

The two writes at 0x5a6e2d3 and 0x5a6e2d6 share the saved entry word. The earlier identity advance at 0x5a6e46f updates only the stack slot before the converter at 0x5a6e48d. After a sentinel the selected cleanup edges at 0x5a6e5b9 and 0x5a6e5cd rejoin 0x5a6e300 with R15 preserved. The null payload also loops without changing either lane. On the selected non-sentinel path the converter's success store at 0x4fad67e supplies output +0x18. The SIMD copy at 0x5a6e609 and 0x5a6e636 places that word in stack +0x338. The tail reload at 0x5a6fd24 and its rejoin at 0x5a6e4cb make it the basis for the next converter call.

For example, start with identity and cutoff basis both 100 and an empty record whose identity and selected basis are both 100. Its successor is 101, so it skips and leaves expectation 101 with cutoff basis 100. With contiguous empty records through identity 109, the successor reaches 110 and meets the unchanged threshold. Recalculating the cutoff from the advancing expectation on each skip would miss that transition. This is a scalar boundary example. Real record fields need to be read from the captured stream, and the trace supplies no mapping between round and checkpoint height.

## Reproduce

GNU and LLVM agree on the selected [instruction spans](instructions.tsv).
```sh
PYTHONPATH=tools python3 -B - <<'PY'
import csv
import hashlib
from pathlib import Path
import struct
from elf_index import unwind_index
from fde_extents import eh_frame_records

data = Path("artifacts/node/115/hl-node").read_bytes()
assert hashlib.sha256(data).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
sections, header = unwind_index(data)
_, fdes = eh_frame_records(data, sections)
indexed = {(row["start"], row["fde"]) for row in header}
bounds = {(row["start"], row["end"]) for row in fdes if (row["start"], row["fde"]) in indexed}

def elf_bytes(section_name, address, size):
    section = next(row for row in sections if row["name"] == section_name)
    displacement = address - section["address"]
    assert 0 <= displacement <= displacement + size <= section["size"]
    offset = section["offset"] + displacement
    return data[offset:offset + size]

with Path("research/work-items/RE-017-node115-replay-cutoff-state/instructions.tsv").open() as handle:
    rows = list(csv.DictReader(handle, delimiter="\t"))
spans = {}
for row in rows:
    start, end, address = (int(row[key], 16) for key in ("fde_start", "fde_end", "va"))
    raw = bytes.fromhex(row["bytes"])
    assert address not in spans
    assert (start, end) in bounds and start <= address < address + len(raw) <= end
    assert elf_bytes(".text", address, len(raw)) == raw
    spans[address] = raw

def rip_target(address):
    raw = spans[address]
    return address + len(raw) + struct.unpack_from("<i", raw, len(raw) - 4)[0]

section = next(row for row in sections if row["name"] == ".rela.dyn")
relocations = {slot: (info, addend) for slot, info, addend in struct.iter_unpack(
    "<QQq", data[section["offset"]:section["offset"] + section["size"]]
)}
assert relocations[rip_target(0x5a6e48d)] == (8, 0x4fad300)
assert rip_target(0x5a6e5b9) == rip_target(0x5a6e5cd) == 0x5a6e300
assert all(rip_target(site) == 0x5a6e4cb for site in (0x5a6ff8f, 0x5a6ffa5, 0x5a6ffb9))
assert spans[0x5a6e48a] == bytes.fromhex("4c 89 fa")
limit = (1 << 64) - 1
expected = basis = 100
for record in range(100, 110):
    assert record == expected
    expected = min(record + 1, limit)
    accepted = expected >= min(basis + 10, limit)
    assert accepted == (record == 109)
    if accepted:
        basis = expected
assert (expected, basis) == (110, 110)
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```
