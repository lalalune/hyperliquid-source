# RE-017 · Node #115 capture writer retains the unwritten suffix

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

[PR #4155](https://github.com/lalalune/hyperliquid-source/pull/4155) ties the raw ABCI digest to its named writer. The existing [context result packet](../RE-017-abci-context-result-115/README.md) tracks the buffered replica writer. This packet follows the common native flush boundary past the existing call sites to recover behavior after a partial filesystem write.

Both the optional digest flush and the replica buffer's fallback reach 0x1533e80. It reads length at writer +0x10, source pointer at +0x8 and fd at +0x1c. An empty buffer returns zero before issuing an import call. Otherwise the routine calls the GLIBC `write` slot for the current suffix. A positive return advances a separate cursor; errno 4 after a -1 return retries without advancing that cursor. A zero write on a nonempty request exits the loop with a nonzero result instead of treating it as successful drain.

After progress followed by a non-retry error or zero write, the selected ordinary cleanup uses `memmove` to bring the unwritten suffix to the start and stores its length. If the routine completed the write, it stores zero length. An error before any positive write leaves the previous length intact. For example, with ten bytes pending and a successful four-byte prefix followed by a terminal error, six bytes remain. This is a buffered write contract. No filesystem persistence, atomicity across processes or state-root correctness follows from a successful return.

## Reproduce

Selected instruction spans agree between GNU and LLVM.
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

with Path("research/work-items/RE-017-node115-capture-short-write/instructions.tsv").open() as handle:
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
assert rip_target(0x4e3a91e) == rip_target(0x14c3854) == 0x1533e80
assert relocations[rip_target(0x1533ea8)] == (0x1300000006, 0)
assert relocations[rip_target(0x1533eaf)] == (0x1400000006, 0)
assert relocations[rip_target(0x1533f6c)] == (0x800000006, 0)
assert 0x1533f2d + struct.unpack("<b", spans[0x1533f2b][-1:])[0] == 0x1533ecf
assert 0x1533ec9 + struct.unpack("<b", spans[0x1533ec7][-1:])[0] == 0x1533f3a
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```
