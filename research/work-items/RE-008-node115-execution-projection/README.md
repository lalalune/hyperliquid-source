# RE-008: node115 execution-state selection and compact projection boundary

- Component: consensus execution-state processing; static data ownership and update mapping.
- Target: Linux x86-64 node #115, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/source revision: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; no inferred reference source used.
- Question: which result rows update the two adjacent execution-state words, and which input bytes feed the separate compact projection passed downstream?
- Status: bounded local native observations. Producer, comparator, event and observer helper semantics are not closed; no Rust, full state-transition or component-gate claim.

## Native scope and source attribution

The complete FDE `0x2af7150..0x2af77ee` contains **1,694 raw bytes / 336 instructions**. `native.asm` retains the full GNU export. `records.json` retains the raw body and hash, unique file mapping, FDE/CIE, every call/branch, source Location records/relocations, imported-slot records and direct-helper FDE leads. FDE bounds describe unwind coverage, not semantic closure or proof that no cold implementation exists elsewhere.

Six actual `R_X86_64_RELATIVE` source Locations bind the body to `node/src/consensus/execution_state.rs`: `0x6448148` (128:34), `0x6448160` (138:29), `0x6448178` (139:30), `0x6448190` (153:30), `0x64481a8` (154:21) and `0x64481c0` (155:30). These are validated raw metadata, not recovered function symbols. The line-153/154 bindings distinguish the compact-projection argument and the later full-result argument described below.

The first native argument is retained as object RBX; the second is a context pointer, later dereferenced to another object. Valid native objects, collection extents and ABI-preserving normally returning helpers are preconditions. No stable external ABI or source field names are assigned.

## Result selection and adjacent state writes

The initial byte at object `+0x260` controls an optional preparation path. It does **not** return from the function: both paths reach the producer call `0x2af7435 -> 0x2af6580`, with a 24-byte tagged argument derived from object `+0x2d0..+0x2e0` and a second optional identity-like argument. That producer writes a result at stack `+0x158`; its behavior and original result type are unmeasured.

The local result handling is precise even though its producer is opaque:

| Result fields relative to stack `+0x158` | Native traversal | State word updated |
| --- | --- | --- |
| base pointer `+8`, count `+0x10` | 32-byte rows; first unsigned eight-byte field, then helper on the row suffix for ties | object `+0x2d0` gets the chosen row's first eight bytes |
| base pointer `+0x20`, count `+0x28` | 64-byte rows; helper `0x26a7880` returns a comparison byte | object `+0x2d8` gets the chosen row's first eight bytes |

For **either zero count**, the respective state store is skipped. This preserves the previous local word; zero rows do not locally write zero to it. One row is selected directly.

For multiple 32-byte rows, `0x2af756d` compares the current and candidate first words as unsigned. If unequal, `seta`/`sbb` produces the signed comparison byte. If equal, `0x23316c0` compares suffixes. A signed byte **greater than zero** retains the current row; otherwise the candidate replaces it. Thus unequal first words locally prefer the larger unsigned first word, and a zero tie result prefers the later candidate. The suffix ordering and its helper validity are unmeasured. A whole-row maximum or global ordering trait is not claimed.

For multiple 64-byte rows, `0x26a7880` receives addresses of the current/candidate row pointers. `test al,al` followed by signed `cmovle` replaces the current pointer on **AL <= 0**, including equality, and advances by 64 bytes. The helper's sign contract, meaning and call closure remain unknown. This packet records the actual selection condition instead of calling it a proven maximum.

## Separate 80-byte to 5-byte projection

After the local state writes, the context-derived object supplies fields at `+0x38e0`, `+0x38e8`, `+0x38f0` and `+0x38f8`. An overflow-flag branch on `0 - field(+0x38e0)` bypasses the ordinary allocation path for the exact min-i64 encoding. The original collection variant name and nonordinary path invariants are unknown.

On the ordinary nonempty path, count is `+0x38f0`, row base is `+0x38e8`, and allocation size is `count*5`. Valid count/extent invariants are assumed; this is not a proof that arbitrary hostile native objects are safe. The loops copy **exactly the five contiguous bytes at offsets `+0x45..+0x4a` of each 80-byte source row**, in source order, into packed five-byte output rows. The half-open notation includes offsets 0x45 through 0x49.

- The scalar tail loads four bytes at source offset 0x45 and one byte at 0x49, advances source by **0x50**, output by **5**.
- The four-row unrolled path starts from source base `+0x135`, loads at displacements `-0xf0`, `-0xa0`, `-0x50`, `0` (the same 0x45 offset in consecutive rows), then advances source by **0x140**, output by **20**.
- Zero count uses an empty dangling pointer value of 1 with no row read or allocation. The special encoding path is only mapped, not assigned the ordinary vector invariants.

The projection descriptor is built at stack `+0x138`: count at `+0`, allocated pointer at `+8`, count again at `+0x10`, and the copied context word from `+0x38f8` at `+0x18`. At `0x2af76af`, call `0x2502370` receives that descriptor, an object-derived pointer and the line-153 Location. Whether it stores, serializes, transmits or discards those bytes is **not established**.

Next, a **separate 176-byte** copy of the original producer result is passed to `0x2cedc50` with object `+0x2a0` and the line-154 Location. The five-byte projection is therefore not a replacement for the complete result argument. The later timing/observer suffix and the earlier preparation helpers are retained in the raw export but not assigned clock, publication, persistence or event semantics.

## Reproduction and controls

From the repository root with Python **3.12.3**, Capstone **5.0.7**, GNU objdump **2.42**:

```sh
python3 tools/node115_execution_projection.py --write
python3 tools/node115_execution_projection.py
python3 -m unittest discover -s tests -p test_node115_execution_projection.py -v
```

The default command checks exact evidence replay; `--write` regenerates it. Only static file reading and disassembly occur. No captured target, emulator, live protocol, key, signing or chain action is used. **11 focused tests pass**: retained evidence, wrong artifact, truncated decode, both zero-count branches, both zero-comparison tie choices, the projection's fifth-byte offset, scalar input/output strides and unrolled input stride. Mutations are rejected after independent instruction decoding as well as the normal full-artifact identity gate.

No compiled source/target comparisons have been measured: raw-equal, normalized-only and unmatched fields remain unset. The raw export denominator is one FDE / 1,694 bytes / 336 instructions, not whole-component coverage. Gates remain false and the shared catalogue is untouched. Complete callers, producer rows' semantic types, comparator closure, exceptional exits, source-level ownership and downstream effects remain open.

Next: close the result producer and comparator contracts, then trace the two downstream arguments separately. This prevents a reconstruction from erasing old state on empty output or replacing the full result with the compact five-byte projection.

Native text exports trim trailing whitespace only; instruction bytes, operands and addresses are unchanged.
