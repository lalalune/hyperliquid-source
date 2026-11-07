# RE-017 · Node #115 replay callback collection reorder

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

[PR #4172](https://github.com/lalalune/hyperliquid-source/pull/4172) identifies the mode-selected collection and leaves its downstream ordering open. The callback hands that collection to `0x4e36fb0`, which forwards its pointer and count to `0x5a8a610`. That helper immediately returns for counts below two. For larger counts, the selected path draws indexed 32-bit or 64-bit words from state, multiplies them by the current remaining count, and uses the high product part as an index after a rejection check. It decrements the remaining count, bounds-checks both indices and swaps the corresponding 16-byte entries, repeating until one remains. Thus collector encounter order cannot in general be assumed at the callback consumer; counts zero and one cannot be reordered by this helper.

The wrapper obtains state through thread-local storage and passes a pointer to it. This packet does not establish seed provenance, the generator's quality, a concrete runtime permutation, or a relationship to checkpoint height. It proves a static reorder boundary only; it does not demonstrate real block replay.

## Reproduce

GNU and LLVM agree on the selected instruction spans.
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

with Path("research/work-items/RE-017-node115-replay-collection-reorder/instructions.tsv").open() as handle:
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
assert rip_target(0x5a635a7) == 0x5b74af0
assert rip_target(0x5a635bc) == 0x4e36fb0
assert rip_target(0x4e36ff6) == 0x5a8a610
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```
