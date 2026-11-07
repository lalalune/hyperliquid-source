# RE-017 · Node #115 checkpoint transfer consumes the compressed path

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

[PR #4148](https://github.com/lalalune/hyperliquid-source/pull/4148) identifies the configured checkpoint archive locator. [PR #4151](https://github.com/lalalune/hyperliquid-source/pull/4151) follows the detached worker through its compression stage. This packet identifies the subsequent transport and the outcome boundary. That matters when deciding whether a file should remain locally and whether the startup process can vouch for its remote availability.

The compression failure test at 0x4d98fe9 branches away before transfer. On its normal continuation, 0x4d98fef and 0x4d98ff4 read the compression result pointer and length. Those form the third and fourth inputs at the transport boundary. The first two inputs are the archive path slice from worker argument +0x8/+0x10. The worker resolves slot 0x64e1048 to 0x154a8a0, which separately checks the optional archive configuration. Its absent path returns zero before command construction. On the present path, three fixed slices are copied with lengths 3, 2 and 2. They are the byte tokens `aws`, `s3`, and `mv`. The next two slices are the compressed local source and the configured archive destination, in that order. The vector reaches the command assembly helper 0x15b0450 and the returned command reaches 0x1561970.

The transport is the AWS CLI move operation. Its intent is to remove the compressed local artifact after transfer. The transport wrapper invokes the command immediately, and after a non-null error follows the default three-delay schedule unless a subsequent invocation returns zero. At the worker boundary a nonzero transport result takes the unwrap diagnostic. A zero result can also arise from absent optional configuration in the helper, so it does not by itself certify remote persistence. The initial startup process detaches the selected worker, as independently shown by the [sibling ownership packet](../RE-005-node115-sibling-join-ownership/README.md), and has no join-based delivery proof on this path.

These are static observations. No CLI command, transfer or access to private infrastructure was performed.

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

with Path("research/work-items/RE-017-node115-checkpoint-upload/instructions.tsv").open() as handle:
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
assert relocations[rip_target(0x4d99007)] == (8, 0x154a8a0)
assert relocations[rip_target(0x154a8c1)] == (8, 0x154abf0)
assert rip_target(0x154a963) == 0x15b0450
assert rip_target(0x154a9a3) == 0x1561970
assert relocations[rip_target(0x156199d)] == relocations[rip_target(0x1561a99)] == (8, 0x1535fd0)
assert [elf_bytes(".rodata", rip_target(site), length) for site, length in ((0x154a8f4, 3), (0x154a909, 2), (0x154a91e, 2))] == [b"aws", b"s3", b"mv"]
assert elf_bytes(".rodata", rip_target(0x4d99055), 43) == b"called `Result::unwrap()` on an `Err` value"
assert struct.unpack("<3d", elf_bytes(".rodata", rip_target(0x15619d5), 24)) == (0.001, 0.05, 1.0)
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```
