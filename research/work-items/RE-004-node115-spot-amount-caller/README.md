# RE-004: node 115 spot-amount conversion at a real caller

Partial progress for [#3908](https://github.com/lalalune/hyperliquid-source/issues/3908).
This binds the existing spot-decimal leaf to the fields supplied by one caller
and to the accepted quotient's output field. It leaves all component gates false.

## Target and existing boundary

Base: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. Node #115 Linux x86-64
ELF: 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Addresses below are ELF virtual addresses.

`RE-004-spot-decimal-115` and prior [#2289](https://github.com/lalalune/hyperliquid-source/pull/2289)
and [#2832](https://github.com/lalalune/hyperliquid-source/pull/2832) own the
`0x29aea00..0x29aeaf2` metadata/divisibility leaf. They leave its caller,
economic units and consumer unproved. This packet supplies a selected caller
relation; it does not repeat the divisor implementation or resolve those units.
Open [#4262](https://github.com/lalalune/hyperliquid-source/pull/4262) concerns
different floating price-band gates at `0x4488300` / `0x3c0f840`.

## Source fields and result handoff

The owner is `0x22e5090..0x22e537d`. On entry, RSI is the source object and
R8 supplies the metadata owner; these are positional observations, not a
complete original type definition.

| Boundary | Static observation |
|---|---|
| Source index | `0x22e50ba` loads source+0x38 into RDX. |
| Source amount | `0x22e50be` loads source+0x40 into RSI. |
| Metadata | `0x22e50e1` forms R8+0x10; `0x22e50ef` passes it in RCX. |
| Actual call | `0x22e50f2` calls the existing leaf `0x29aea00`, with a stack result slot. |
| Leaf result | The existing leaf writes the accepted quotient at result+8 and tag 0x1a2 at result+0. |
| Rejection | `0x22e5101` sends any other tag to the error-copy block, which writes that tag at `0x22e51ca`. |
| Selected branch | A zero source byte at +0x51 reaches `0x22e51d6`. The nonzero branch has a separate path and is outside this result-handoff contract. |
| Retention | `0x22e51da` retains the accepted quotient in R15, before the result slot can be reused. |
| Accepted output | `0x22e527e` writes the original index to output+0x18; `0x22e5282` writes R15 unchanged to output+0x20; `0x22e529f` publishes tag 0x1a2. |

The retained leaf entry confirms the two-stage metadata lookup: the pair index
selects a 32-byte record, its token index selects a 0x158-byte record, and the
byte at token-record+0x48 controls the existing conversion. The leaf's arithmetic
and exceptional bounds checks remain credited to the earlier packet.

The selected caller has another condition before publishing the accepted
record. If its first qword is the sentinel `0x8000000000000001`, it bypasses
the extra helper and chooses a local tag 2. Otherwise it calls `0x292a0c0`
at `0x22e5219` with the original source/index, additional context, the same
metadata base and an inverted source byte from +0x50. That helper must return
tag 0x1a2; another result takes the second error-copy block. The quotient in
callee-saved R15 is not recomputed on this path and is published only after
this additional check. Normal helper return and the native calling convention
are premises; this packet does not reconstruct that helper's transitive logic.

Other output fields and inactive enum storage are not assigned economic
meaning. This establishes a source-field → metadata leaf → accepted-record
connection. Original wire decoding, token aliases, amount units, the nonzero
+0x51 branch, downstream ledger mutation and persistence remain open.

## Evidence and reproduction

`records.json` retains **5 windows / 608 bytes / 144 instructions** with exact
bytes, hashes and enclosing FDE bounds. The verifier checks 37 facts and rejects
11 in-memory corruptions of source fields, metadata base, call target, result
tags/branches, retained quotient slot and output fields. Controls run the fact
checks with global digest/window rejection bypassed, so a whole-file hash
mismatch alone is not counted as detecting the wrong relation.

Use an existing Python environment with Capstone **5.0.7** and the hydrated
artifact (observed Python **3.14.7**):

```sh
python3 research/work-items/RE-004-node115-spot-amount-caller/verify.py
```

Expected: 5 windows, 608 bytes, 144 instructions, 37 facts and 11 rejected
corruptions. `verification.json` records the observed output. `--target PATH`
accepts only the pinned ELF. The existing registry-row-labels helper supplies
ELF/FDE parsing; no dependencies or inputs are downloaded.

No target instructions were executed or emulated. Static checks authenticate
the selected evidence; they do not establish runtime equivalence or the whole
assets component. Interpretation and tooling are independently authored, and
imported rights remain unchanged.
