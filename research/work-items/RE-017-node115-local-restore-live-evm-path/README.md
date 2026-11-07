# RE-017 · Node #115 local restore live EVM path input

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

The [local-state restore packet](../RE-017-local-state-restore-115/README.md) identifies the accepted checkpoint row, the auxiliary preparation call at `0x2cc19af` and the materializer, and treats the preparation as a boundary. This packet resolves the two distinct path inputs at that call site. It does not reconstruct the materializer studied separately in #3939 and #3940.

1. On the selected non-sentinel branch the caller preserves the selected row's words at stack `+0x148` and `+0x150..+0x15f`. It then calls `0x16929b0` to overwrite a temporary at stack `+0x140`. On the selected initialized-global path this new triple uses a global-based root and format fragments `/hyperliquid_data` then `/evm_db_hub_slow`.
2. The auxiliary helper `0x2bacad0` receives that new path triple. Its callback forwards the pointer and length, and `0x23b0180` receives selector 2. Its normal builder passes the path and selector to the format record `c0 01 2f c0 00`. The relocated type callback routes selector 2 to `EvmState` of length 8. The resulting path `<configured-base>/hyperliquid_data/evm_db_hub_slow/EvmState` reaches constructor slot `0x64e20c0`, and its returned object is paired with selector 2.
3. The auxiliary result retains the input triple in its first 24 bytes and the typed descriptor in the next 24. Before calling the materializer, the caller separately rebuilds its earlier checkpoint-row temporary and supplies the auxiliary result as the next argument. Therefore the typed path just constructed is relative to the configured live base on this path. The selected checkpoint row is a separate argument.

An offline fixture that provides a historical checkpoint directory still needs to account for this second path input. The selected constructor does not by itself establish an open, persistence, copying from the historical path, or successful restoration.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on [instructions.tsv](instructions.tsv).

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

with Path("research/work-items/RE-017-node115-local-restore-live-evm-path/instructions.tsv").open() as handle:
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
for address, target in ((0x2cc199a, 0x16929b0), (0x2cc19af, 0x2bacad0),
                        (0x2bacb58, 0x23b0180), (0x23b0193, 0x23702c0)):
    assert rip_target(address) == target
for address, literal in ((0x16929e6, b"\xc0\x11/hyperliquid_data\x00"),
                         (0x1692a0e, b"\xc0\x10/evm_db_hub_slow\x00"),
                         (0x2370342, b"\xc0\x01/\xc0\x00"),
                         (0x1696de9, b"EvmState")):
    assert elf_bytes(".rodata", rip_target(address), len(literal)) == literal
for address, slot, target in ((0x2370336, 0x64e2078, 0x1696db0),
                              (0x237035e, 0x64e20c0, 0x16961b0),
                              (0x2cc19ea, 0x64e73a0, 0x3c13610)):
    assert rip_target(address) == slot
    assert relocations[slot] == (8, target)
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```
