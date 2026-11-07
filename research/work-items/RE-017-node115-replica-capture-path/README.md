# RE-017 · Node #115 replica command capture path arguments

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

The [loader checkpoint packet](../RE-017-loader-checkpoint-result-115/README.md) identifies the result builder and its height and flag stores. This packet follows the builder's file-path operands, distinguishing the native capture locator from a public explorer block identifier.

At `0x5a6e055` the builder receives the 12 bytes `replica_cmds` and a fresh load of state `+0x28`. The first format record at `0x44af09` takes the configured base, that name and a separate pointer-length input. Its embedded literal spans are `/data/` and `/`. The callback `0x5616320` forwards each of the two pointer-length inputs unchanged to its output boundary. The builder copies this first formatted path triple into its result prefix.

The second format record at `0x440e47` takes the first path, a date-like dword and the saved height word. The dword comes from a fresh time-provider call followed by the conversion slot at `0x595ae31`. A zero returned dword takes the failure arm before this formatter. Its date callback uses six bytes `%Y%m%d`. Its height callback resolves to `0x1689420`, the unsigned decimal formatter. It supplies the resulting path triple to the sink constructor at `0x595ae97`, then copies the sink state at output `+0x18`. Thus the local path has the selected shape `<base>/data/replica_cmds/<separate-prefix>/<date>/<height>`. The path date and separate prefix should be retained as capture provenance. A block timestamp and block hash do not establish the producer's prefix or date, and construction does not prove file persistence.

For a real-data negative control, Hyperliquid's explorer returned public block details at heights 1199000000 and 1199000001 on 2026-10-27 UTC. Both responses contain block height, time, hash, proposer and transactions. Every transaction in each response reported the corresponding height. Neither envelope carries the native path or a field named `abci_digest`. This is an observation of those two responses only. It does not prove the explorer or archives never return other fields. The block IDs are independently queryable in the [official explorer](https://app.hyperliquid.xyz/explorer). The [operator README](https://github.com/hyperliquid-dex/node/blob/405cc08b17a727ee51b0f9128918955a84439915/README.md) describes the local replica output path. No full explorer response is committed.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on [instructions.tsv](instructions.tsv). Static verification from repository root:

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

with Path("research/work-items/RE-017-node115-replica-capture-path/instructions.tsv").open() as handle:
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
for address, literal in ((0x5a6e03f, b"replica_cmds"),
                         (0x595acbb, b"\xc0\x06/data/\xc0\x01/\xc0\x00"),
                         (0x595ae76, b"\xc0\x01/\xc0\x01/\xc0\x00"),
                         (0x150ceb2, b"%Y%m%d")):
    assert elf_bytes(".rodata", rip_target(address), len(literal)) == literal
for address, slot, target in ((0x5a6e055, 0x64ebf70, 0x595ac30),
                              (0x595ae31, 0x64e0ab8, 0x1629fb0),
                              (0x595ae59, 0x64e0b68, 0x150ce90),
                              (0x595ae6a, 0x64e0a98, 0x1689420),
                              (0x595ae97, 0x64e0020, 0x14c3b30)):
    assert rip_target(address) == slot
    assert relocations[slot] == (8, target)
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```
