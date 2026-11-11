# RE-017 · Node #115 startup checkpoint compression and retries

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

[PR #4148](https://github.com/lalalune/hyperliquid-source/pull/4148) recovers the archive name and the raw checkpoint argument. The [sibling ownership packet](../RE-005-node115-sibling-join-ownership/README.md) recovers thread creation and handle disposal. This packet follows the detached worker's local compression stage so an offline fixture can distinguish its MessagePack input from its compressed archive member.

The startup spawner installs closure descriptor 0x64aa7a8. The thread entry invokes descriptor +0x18, whose relocation names 0x561fed0. That body calls the state-independent setup boundary and then copies closure +0x28 through +0x4f into a worker argument. The second call resolves to 0x4d98f80. Its selected compressor receives closure-derived pointer/length fields at worker argument +0x18/+0x20. They are copied from startup's second path slice in the incoming staging record, where [PR #4148](https://github.com/lalalune/hyperliquid-source/pull/4148) pins `/tmp/abci_checkpoint.rmp`.

The compressor retry wrapper calls 0x1505f90 with the source slice, flags read from bytes 0 and 1 of little-endian 0x0100, and a default retry array because R8 is zero. The selected path formatter appends `.lz4`. A source that already has that suffix goes to an error constructor before the command path. The compression command format has literal prefix `lz4 -q -9 `, two path operands and the conditional option `--rm`. Worker flag byte 1 is one, selecting the four option bytes. The arguments use quoting helpers, so this is a description of the selected options and file operands. The local source is intended to be removed by the compressor on success. The result on that path carries the generated path and its length.

The first compression attempt is immediate. A sentinel result selects up to three delayed retries, with default binary64 values 0.001, 0.05 and 1.0 seconds before conversion by the duration helper. A later non-sentinel returns early. If all fail, the wrapper returns the sentinel with an aggregated error and the worker branches away before its next stage. The static trace does not establish that a compressor is installed, that files were created or removed, or that a remote object exists.

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

with Path("research/work-items/RE-017-node115-checkpoint-compression/instructions.tsv").open() as handle:
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
assert rip_target(0x5614ccf) == 0x64aa7a8
assert relocations[0x64aa7a8 + 0x18] == (8, 0x561fed0)
assert relocations[rip_target(0x561ff28)] == (8, 0x4d98f80)
assert rip_target(0x4d98fd9) == 0x1560ff0
assert rip_target(0x1561046) == rip_target(0x1561160) == 0x1505f90
assert elf_bytes(".rodata", rip_target(0x4d98fbd), 15) == b"zip_inner_retry"
assert elf_bytes(".rodata", rip_target(0x150621f), 19) == bytes.fromhex("0a 6c 7a 34 20 2d 71 20 2d 39 20 c0 01 20 c0 01 20 c0 00")
assert elf_bytes(".rodata", rip_target(0x1506042), 4) == b"--rm"
assert b".lz4" in spans[0x1505fbd]
assert struct.unpack("<3d", elf_bytes(".rodata", rip_target(0x1561082), 24)) == (0.001, 0.05, 1.0)
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```
