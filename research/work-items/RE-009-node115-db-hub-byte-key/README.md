# RE-009: node115 DB-hub byte-key lookup and failure boundary

Question: which key width, comparison, node offsets and missing-key route select
the database-associated value before this `db_hub` path operation?

Target: node115, 105,896,032 bytes; SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
Task: bounded RE-009/RE-001 storage map. All four storage component gates remain
false. This is not a Rust reconstruction or a recovered persistent key/value
schema. The observed lookup is an in-memory byte-key tree, not a proved RocksDB
key encoding or complete database-hub API.

## Measured owner

The complete FDE-backed extent is **`0x1692ca0..0x1692fe9`**, half-open:
841 bytes, 199 native instructions. The retained export covers every byte.
The producer independently validates Capstone 5.0.7 decoding against GNU
objdump's raw bytes. `records.json` retains the body digest and file offset,
actual FDE/CIE/LSDA coordinates, every call/branch and RIP-relative binding,
including the relocation info/addends. These are unwind-backed extents, not a
complete validated function inventory. No normalization or source/binary match
percentage is asserted.

Three actual Location LEAs refer to `db/src/db_hub.rs`: line62:41 at
`0x1692ee7`, line68:14 at `0x1692f13`, and line66:14 at `0x1692f6c`.
This establishes source association; the original function and field names are
not recovered from the stripped target.

## Raw lookup relation

The body saves incoming ECX, then zero-extends its **low byte** at `0x1692d20`.
The high 24 bits of the original word do not enter the measured comparison.
It loads the root-like pointer from incoming context+`0x18` and height-like word
from context+`0x20`. A null root branches directly to `0x1692f6c`.

| Observed field | Offset / width | Evidence |
| --- | --- | --- |
| node key count | `+0x62`, u16 | `MOVZX ESI,word [RAX+0x62]` at `0x1692d24` |
| first byte key | `+0x64`, u8 | index starts at -1; `[RAX+RDX+0x65]` at `0x1692d4a` |
| child pointer array | `+0x70`, 8-byte stride | `[RAX+RDX*8+0x70]` at `0x1692d8d` |
| selected value pointer array | `+8`, 8-byte stride | `[RAX+RDX*8+8]` at `0x1692d97` |
| selected object adjustment | `+0x10` | ADD RBP,0x10 at `0x1692d9c` |

At each node, the loop negates the zero-extended count and starts index RDX=-1.
The equality at `0x1692d44` detects exhaustion before loading a key. Otherwise
both query and loaded key are zero-extended bytes. CMP / SETL / SETG / SUB
constructs the comparison byte -1, 0 or +1. Though the condition mnemonics use
signed ordering, both compared 64-bit values lie in 0..255, so this is also
unsigned byte ordering.

After incrementing the index, the loop continues only when comparison byte is
exactly **1** (`0x1692d61..0x1692d65`): query greater than key. Equality chooses
the value pointer; a smaller query selects a child at the current index.
Exhaustion chooses child index=count. For valid sorted keys, this is the local
first-key-greater-or-equal scan relation. The count cannot independently prove
node capacity or valid allocation; no arbitrary count is claimed safe.

A non-equal result decrements RCX by 1 and tests unsigned borrow at
`0x1692d83..0x1692d87`. Borrow goes to the same missing-key path; otherwise it
loads the selected child and repeats. Under ordinary valid tree invariants this
corresponds to descending a level until a match or terminal miss. The packet
does not establish all tree constructors, ordering invariants, corruption
handling, aliasing, concurrent access or ownership.

## Selected-value use and failure

The equal route loads a value pointer from `[node+8+8*index]`, adds `0x10`,
prepares a path from the input pointer/length and the original low key byte,
then calls `0x1698c00` at `0x1692e02`. Nonzero RAX goes to the line68:14
failure arm (`0x1692f00`). The target helper, object layout and filesystem
operation remain unclosed; a selected pointer is not proof of successful
database access or persistence.

Before tree lookup, the body tests the input path through indirect slot
`0x64e0928`, then conditionally calls slot `0x64e0940` with an observed 0x1ff
mode word and byte1. Nonzero RAX follows the line62:41 failure arm. Those
slots' RELATIVE addends are retained, but their complete helper semantics are
outside this packet.

The null-root/depth-borrow miss route loads Location `0x64089e0` (line66:14)
and calls indirect slot `0x64df830` at `0x1692f73`. It does not synthesize a
default database or return an ordinary not-found result in the measured
normal route. The call's complete unwind/panic behavior is not independently
closed; the retained export preserves landing pads and `_Unwind_Resume` calls.
No security defect is claimed.

## Reproduce and controls

Python3.12.3, Capstone5.0.7, GNU objdump2.42; Linux x86-64 analysis host.

```sh
python3 tools/db_hub_key_static.py --output work/db-hub-byte-key
python3 -m unittest discover -s tests -p test_db_hub_key_static.py -v
python3 tools/verify_packets.py
git diff --check
```

The full target size/SHA check precedes output creation and any native tool.
GNU objdump reads a private byte-identical capture copy. Native exported
trailing whitespace is trimmed; instruction/address/raw-byte contents are not
normalized. No captured code, emulator, database, process adapter, socket,
chain action, production key or paid dataset is run.

Five focused tests pass. All 256 possible query bytes are checked against empty,
singleton and edge-containing sorted scalar arrays. These are local comparison
relations, **not allocated target node fixtures**, and do not establish node
capacity or full tree behavior. Counterfactuals mutate the actual loop
continuation immediate, field displacements, height decrement, descent-branch
destination, selected-value call target and a relocated source line; the
corresponding recovered relations or records change. Truncated, wrong and
same-size modified targets are rejected before output creation.

No Rust build or differential execution is claimed. Project-wide catalog
regeneration and full repository gates belong to integration; this packet does
not change a component completion gate or whole-node denominator.
