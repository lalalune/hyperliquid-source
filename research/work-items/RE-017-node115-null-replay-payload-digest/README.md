# RE-017 · Node #115 null replay payload digest path

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

The existing [replay override trimming packet](../RE-017-node115-replay-override-trim/README.md) starts at `0x5a6383f`; [#5881](https://github.com/lalalune/hyperliquid-source/pull/5881) joins the worker's null-first pair `(0, P)` to the callback. This packet traces the data supplied to the earlier digest slots and the 32-byte buffer passed to the trimming helper on a selected callback continuation.

On the selected null-first branch the callback loads P from its input pair `+8`, then loads RSI from P `+0x18` and RDX from P `+0x20` at `0x5a6333f/0x5a63343`. No intervening instruction changes those argument registers before the call at `0x5a633f0`, whose relocation resolves slot `0x64e0148` to `0x5cda910`. The callback then copies 0xe0 bytes of the local state to stack `+0x130` and calls slot `0x64e0150` (relocated to `0x5cdad40`) with a 0x20-byte output at stack `+0xa0`. It moves those 32 output bytes to stack `+0x340`. Under the selected nonzero-selector, null-first continuation and no intervening changes, `0x5a6383f` passes that buffer to `0x57e6750`. Existing digest evidence identifies these slots as an update/final pair; this packet does not independently establish their algorithm or that a real payload is valid.

The observation depends on valid P and memory, selected path reachability, normal helper returns, helper semantics from the cited evidence, and absence of intervening changes to the digest buffer. It does not identify P's values, prove the pointer/length describe real replay bytes, or compare a state root. No captured binary is executed.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 39 selected instruction spans. Python 3 verifies the target digest, FDE bounds, slot relocations, direct edge and negative byte controls.

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

with Path("research/work-items/RE-017-node115-null-replay-payload-digest/instructions.tsv").open() as handle:
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

assert rip_target(0x5a633f0)==0x64e0148
assert rip_target(0x5a63424)==0x64e0150
assert rip_target(0x5a6340e)==0x64df508
assert relocations[0x64e0148][1]==0x5cda910
assert relocations[0x64e0150][1]==0x5cdad40
assert rip_target(0x5a63688)==0x5a63832
assert rip_target(0x5a6383f)==0x57e6750
assert spans[0x5a6333f]==bytes.fromhex('488b7018')
assert spans[0x5a63343]==bytes.fromhex('488b5020')
assert spans[0x5a6341c]==bytes.fromhex('ba20000000')
for addr in (0x5a6333f,0x5a63424):
    changed=bytearray(spans[addr]);changed[-1]^=1
    assert changed != elf_bytes('.text',addr,len(changed))
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```
