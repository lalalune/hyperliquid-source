# RE-017 · Node #115 startup checkpoint archive name

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

The [loader checkpoint result packet](../RE-017-loader-checkpoint-result-115/README.md) maps the startup writer, including its mode gate and later opaque helper. This packet follows that writer's local and archive locators. It distinguishes an operator-captured startup artifact from a periodic state dump whose catalog keys contain block heights.

On the selected startup path, `0x5a6dd5b` samples the time provider. The formatter at `0x5a6de00` uses `%Y-%m-%dT%H:%M:%SZ`; the selected output pointer and length are saved for later. Mode 2 and the configuration sentinel each bypass the new path. Otherwise the compact writer receives the two path slices `/tmp/abci_checkpoint_evm_db` and `/tmp/abci_checkpoint.rmp`.

After the compact writer returns, `0x5a6df4d` builds a name from three arguments. The first is the configuration byte string returned by the previously documented `0x154abf0` route. Callback `0x59dbfb0` forwards its pointer and length. The second is global byte `+0x48` rendered through slot `0x64e2408 -> 0x1774e60`; the [configuration path packet](../RE-015-config-path-115/README.md) maps that renderer's name table. The third is the saved timestamp string. The format bytes specify `<configured-prefix>/hyperliquid/abci_checkpoints/<rendered-name>/<timestamp>.lz4`.

The call at `0x5a6dfa7` receives a staging record whose path slots hold this formatted name and the literal `/tmp/abci_checkpoint.rmp`. A zero leading return goes to the earlier error path. This is a configuration-dependent locator and an argument association. Neither a named object nor a compressed body was acquired from this path, and successful transfer and a timestamp-to-height identity remain unverified. An archive manifest should carry the original key, capture time, explicit sequential height and binary identity separately.

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

with Path("research/work-items/RE-017-node115-native-checkpoint-object-key/instructions.tsv").open() as handle:
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
for address, literal in (
    (0x5a6dd8f, b"%Y-%m-%dT%H:%M:%SZ"),
    (0x5a6de75, b"/tmp/abci_checkpoint_evm_db"),
    (0x5a6de94, b"/tmp/abci_checkpoint.rmp"),
    (0x5a6df36, b"\xc0\x1e/hyperliquid/abci_checkpoints/\xc0\x01/\xc0\x04.lz4\x00"),
):
    assert elf_bytes(".rodata", rip_target(address), len(literal)) == literal
assert rip_target(0x5a6defb) == 0x59dbfb0
assert rip_target(0x5a6df11) == 0x64e2408
assert relocations[0x64e2408] == (8, 0x1774e60)
assert rip_target(0x5a6dfa7) == 0x5614960
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```
