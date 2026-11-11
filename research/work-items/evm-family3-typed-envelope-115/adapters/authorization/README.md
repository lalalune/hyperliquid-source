# Authorization-list key adapter

Component `evm`; subordinate to the existing evm-family3-typed-envelope-115 evidence.
Target node #115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`;
base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.
Actual FDE `0x5b69550..0x5b69618`: 200 bytes / 55 instructions.

## Observed local contract

Close the extra +0x90 delegate in the Eip7702-shaped payload. Entry RDI=output, RSI=buffer, RDX=collection. A mode other than 1 directly branches to 0x52a6c00 before any local frame or key store. Mode 1 writes b1 plus authorizationList: 16 pinned pool bytes and a final t byte. It then restores registers and tails to the same 0x52a6c00, preserving the original collection argument. The literal establishes the field name; collection schema/signature rules remain outside this adapter.

Buffer capacity/storage/length are +0/+8/+0x10. Local growth paths call the
recorded family-specific helper with marker/name lengths, reload descriptor
fields and rejoin the pending stores. All direct external edges are explicitly
pinned to actual FDE starts. Callees are boundaries, not newly recovered by
this adapter. No byte normalization or runtime type-name equivalence is used.

```sh
python3 research/work-items/evm-family3-typed-envelope-115/adapters/authorization/verify.py
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
