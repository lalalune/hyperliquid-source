# RE-017 · Node #115 replay producer payload source and gate

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

[PR #5040](https://github.com/lalalune/hyperliquid-source/pull/5040) identifies a selected producer capture and a queue publication of `(0, P)` but does not identify the source of P or the preceding gate. This packet traces the direct zero-first-word route within FDE `0x5a82670` to that selected publication.

At `0x5a8706c/0x5a87074`, the code loads two qwords from stack `+0x2318/+0x2320` into RCX/RAX. When `r12d != 1`, the selected branch transfers them to future fields `+0x190/+0x198`, then to `+0x2d60/+0x2d68`. The code tests the first qword at `+0x2d60`; if zero it branches to `0x5a8869d` and reloads P from `+0x2d68` into R15. On the selected continuation it increments `[P]`, passes P to `0x57e69b0`, then stages `(0, P)` for the queue publish call at `0x5a889db`. The alternate nonzero gate arm is not reconstructed.

Thus P is conditionally the second qword of that stack pair, not a demonstrated block height or decoded record. The chain assumes the cited control transfers, same future object, valid pointers, normal returns, and no intervening alias writes or mutation. The stack pair's upstream writer, lifetime semantics of helpers, runtime scheduling, and real replay record remain unresolved. No target binary is executed.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 44 selected instruction spans; LLVM prints lock prefixes separately. Python 3 verifies the pinned target, FDE, branch and call displacements, negative mutation, and synthetic gate/dataflow offsets. Synthetic values are not target runtime observations.

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

with Path("research/work-items/RE-017-node115-replay-enqueued-payload-source/instructions.tsv").open() as handle:
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

assert rip_target(0x5a87080)==0x5a8724f
assert rip_target(0x5a8729e)==0x5a8869d
assert rip_target(0x5a88977)==0x57e69b0
assert rip_target(0x5a889db)==0x581b0c0
for first,payload in ((0,1),(0,0x123456789abcdef0),(7,9)):
    future=bytearray(0x2d70)
    struct.pack_into('<QQ',future,0x190,first,payload)
    struct.pack_into('<QQ',future,0x2d60,*struct.unpack_from('<QQ',future,0x190))
    gate,loaded=struct.unpack_from('<QQ',future,0x2d60)
    assert (gate==0)==(first==0)
    if gate==0: assert (0,loaded)==(0,payload)
changed=bytearray(spans[0x5a8729e]);changed[-1]^=1
assert changed!=elf_bytes('.text',0x5a8729e,len(changed))
print(f"{len(spans)} authenticated instruction spans and selected branches match")
PY
```
