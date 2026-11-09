# RE-017 · Node #115 replay small-sort capacity gate

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

[#5912](https://github.com/lalalune/hyperliquid-source/pull/5912) follows a selected replay-digest preparation path to helper `0x5408900`; this packet checks its entry and failure condition. For count R below two, the helper returns immediately. For `2 <= R <= 31` with incoming capacity C, it forms `R+16` and compares C unsigned with that value; C below `R+16` branches to `ud2`, while C at least `R+16` enters subsequent work. The helper branches separately at R=7/8. Here R+16 cannot wrap. On the selected N=21..64 wrapper path in [#5901](https://github.com/lalalune/hyperliquid-source/pull/5901), the scratch capacity passed to the worker is 128; #5912 maps that capacity to the helper and has R < ceil(N/2) <= 32. Subject to those call-chain assumptions, 2 <= R <= 31 implies R+16 <= 47 < 128, so the capacity trap is unreachable on this selected path. Actual runtime reachability and pointer validity are not established. The later sort, its side effects, and real replay state roots are not established. No captured binary executes.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 23 selected instruction spans. Python 3 checks the target identity, FDE, bytes, branch destinations, synthetic boundaries, and corruption controls.

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

with Path("research/work-items/RE-017-node115-replay-digest-small-sort-capacity/instructions.tsv").open() as handle:
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

assert rip_target(0x5408917)==0x5408f45
assert rip_target(0x5408924)==0x5408fa3
assert rip_target(0x5408943)==0x5408b97
assert spans[0x5408fa3]==bytes.fromhex('0f0b')
def route(r, c):
    if r<2: return 'return'
    if c<r+16: return 'trap'
    return 'work'
for r in (2,7,8,15,31):
    assert route(r,r+15)=='trap'
    assert route(r,r+16)=='work'
assert route(1,0)=='return'
assert route(2,17)=='trap' and route(2,18)=='work'
for n in range(21,65):
    m=(n+1)//2
    for r in range(2,m):
        assert r+16<=47 and route(r,128)=='work'
for a in (0x5408917,0x5408924):
    bad=bytearray(spans[a]);bad[-1]^=1
    assert bad!=elf_bytes('.text',a,len(bad))
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```
