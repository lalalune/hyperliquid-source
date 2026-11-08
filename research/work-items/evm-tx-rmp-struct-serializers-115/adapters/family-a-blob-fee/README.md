# Family-a blob fee key adapter

Component `evm`; subordinate to the existing evm-tx-rmp-struct-serializers-115 evidence.
Target node #115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`;
base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.
Actual FDE `0x233a4f0..0x233a5a2`: 178 bytes / 51 instructions.

## Observed local contract

Resolve the inline blob payload +0x60 delegate. Mode exactly 1 emits b0 plus the pinned 16-byte maxFeePerBlobGas key. Continuation remaps original RDX value storage to RSI, buffer to RDX and preserves output RDI, then tails to the numeric encoder recorded in the exports. There is no local result repackaging or numeric conversion. Concrete numeric type, units and downstream wire representation remain open.

Buffer capacity/storage/length are +0/+8/+0x10. Local growth paths call the
recorded family-specific helper with marker/name lengths, reload descriptor
fields and rejoin the pending stores. All direct external edges are explicitly
pinned to actual FDE starts. Callees are boundaries, not newly recovered by
this adapter. No byte normalization or runtime type-name equivalence is used.

```sh
python3 research/work-items/evm-tx-rmp-struct-serializers-115/adapters/family-a-blob-fee/verify.py
```

Python, Capstone 5.0.6, pyelftools 0.32. Full target digest/FDE, complete
decoding, instruction/data pins and branch destinations checked. 8 operative
mutations must reject below the image SHA guard. Independent finite controls
are recorded in records.json; they are not captured-instruction execution or
interpretation. Complete bytes, FDE/CIE, calls, branches and pool context retained.

Valid stable nonaliasing storage, buffer invariants and normal helper returns
are assumptions. Nested wire schemas, allocation failure, unwind behavior and
full native GNU/Rust/Ghidra/source reproduction remain unqualified. No progress
gate changes. Next: recover the named tail encoder rather than infer its body.
