# RE-011: Where are the #94 EVM RPC method strings and router-associated FDEs?

- Component ID: `evm-rpc` (with static `evm` dependency/fork comparison).
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. The comparison target is node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Visor is a different artifact and is not analyzed here.
- Source commit / reference commit: hyperliquid-source `1f8c67c63ca4794c9689235471c60297f8a5c985`; `provenance/sources.json` records can1357 revision `999556f6e0a474b8312db96ec3149e1c44e97c23`. The specific reference file is separately SHA-256 pinned in the JSON. This unlicensed inferred reference supplies the 26 names, not authoritative original source or implementation.
- Claim status: observations, inference, and unresolved questions are separated below.
- Scope included and excluded: static method-string anchors, panic Locations, three direct calls, and #94/#115 revm/reth/evm_rpc path evidence. No target execution, network, full-chain download, EVM execution, complete request-to-handler proof, build or equivalence claim.

## Reproduce

From the repository root, on Linux x86-64, Python 3.13.5 and GNU objdump 2.44 were used; the generator uses Python's standard library plus the existing repository `tools/info_request_path.py` ELF helpers. It authenticates both binary inputs and all five reference/inventory/provenance files before producing output. Input digests are recorded in the JSON; artifact identities are also in `provenance/artifacts.json`. No captured binary is executed. Output JSON SHA-256: `764927b79762198ac15842cc918e492c0175af6c790bfb61a4f78dddcfa07958`.

```sh
python3 tools/evm_rpc_method_path.py --out research/work-items/RE-011-evm-rpc-method-path/
python3 research/work-items/RE-011-evm-rpc-method-path/verify.py
python3 -m unittest tests.test_evm_rpc_method_path -v
make verify
```

The raw excerpts were made with the following static disassembly options (start included, stop excluded), using exactly the authenticated #94 input:

```sh
objdump -d --start-address=0x27ab650 --stop-address=0x27abc18 artifacts/node/94/hl-node > research/work-items/RE-011-evm-rpc-method-path/excerpts/method-table.objdump.txt
objdump -d --start-address=0x20266a0 --stop-address=0x2027608 artifacts/node/94/hl-node > research/work-items/RE-011-evm-rpc-method-path/excerpts/router-init.objdump.txt
objdump -d --start-address=0x202ec80 --stop-address=0x20312c2 artifacts/node/94/hl-node > research/work-items/RE-011-evm-rpc-method-path/excerpts/router-request.objdump.txt
objdump -d --start-address=0x2027610 --stop-address=0x2028519 artifacts/node/94/hl-node > research/work-items/RE-011-evm-rpc-method-path/excerpts/router-callee.objdump.txt
```

`MANIFEST.sha256` covers every packet file except itself. The verifier checks it and regenerates JSON byte-for-byte. It does not regenerate the objdump excerpts; their tool version and options are above. A fresh exported tree may be missing imported evidence; see `RESULT.md` for this run's actual check outcomes.

## Evidence

All addresses below are ELF virtual addresses; FDE ends are exclusive. The JSON records every anchor, file offset, instruction byte sequence, Location slot, line/column, candidate LEA site and FDE bounds. All four disassembly files cover complete selected FDE ranges. `objdump` prints offsets from an unrelated nearest exported dynamic symbol: those labels are not recovered function names.

**Observed, #94.**

- The reference `build_route_table()` contains 26 distinct `eth_*` names. All **26/26** have an exact start-pointer LEA in FDE `0x27ab650..0x27abc18`. For example `eth_blockNumber` bytes begin at VA/file offset `0x3f05a2`; instruction `0x27ab667` is `48 8d 15 34 4f c4 fd`, pointing there, and `0x27ab671` loads length 15. `eth_call` starts at `0x20aad0`, referenced by LEA at `0x27ab69b`, with length 8 at `0x27ab6aa`. The 26 names, matching anchors, length-load bytes, and following call targets, not just these samples, are in JSON. All 26 following rel32 calls land at FDE starts; their destination roles remain unverified. Exact means pointer to the first byte; Rust strings need not be NUL-terminated. The linear objdump cross-check confirms all 26 table LEAs as instructions. A matching name and length do not establish request semantics or coverage of other method names.
- Of 1,186 first-party candidate Location records, **42** have the binary path prefix `evm_rpc/`: method_router 7, evm_rpc 15, evm_store 15, write_forwarder 2, reth_rpc_helpers_copied 2, reth_eth_tx_builder_copied 1. Their LEA sites attribute to **38** FDE ranges. These are scoped record and candidate-site counts, not a census of functions or RPC methods.
- The router-associated initialization FDE `0x20266a0..0x2027608` references `method_router.rs` Locations 37, 39 and 42. At `0x20267ad` it calls the string-bearing FDE `0x27ab650` with bytes `e8 9e 4e 78 00`. The Location slot for line 37 is `0x5696ea0`, referenced at `0x2027292`.
- A separate router-associated FDE `0x202ec80..0x20312c2` references `method_router.rs` Locations 51, 97 and 116. Its calls at `0x202f4d9` (`e8 32 81 ff ff`) and `0x2030034` (`e8 d7 75 ff ff`) land at `0x2027610`, the start of FDE `0x2027610..0x2028519`, which references `method_router.rs` Location 151. This establishes call edges between Location-bearing ranges, not the callee's method-handler identity.
- No single FDE in this scan owns both router and `evm_rpc.rs` Locations. For example `0x27b6540..0x27b840b` references `evm_rpc.rs` lines 423 and 517 and `reth_rpc_helpers_copied.rs` lines 33 and 141. The remaining `evm_rpc.rs` Location owners, including 13 FDEs sharing line 86, are recorded in JSON. Source line numbers are the binary's Location values, not verified line correspondence with the inferred reference.

The Location walk uses `.rela.dyn` `R_X86_64_RELATIVE` slots in `.data.rel.ro`, the `/home/ubuntu/hl/code_Mainnet/` first-party path prefix in `.rodata`, and the following length/line/column fields. It attributes RIP LEA byte-pattern hits to `.eh_frame_hdr` FDE bounds. The complete selected-range objdump exports validate the selected router Location instructions and direct calls; other scan hits remain candidates until independently decoded. FDE bounds describe unwind entries and do not by themselves establish source-function boundaries or ownership. Scans do not resolve register-indirect calls (for example `0x2027d3d`) or establish a complete call graph.

**Dependency/fork matrix: observed path facts.** The complete selected inventory and RE-002 provenance facts, including original offsets/occurrence counts, are in `fork_matrix` in JSON. These are surviving paths, not a complete dependency graph.

| Evidence | #94 | #115 |
| --- | --- | --- |
| `evm_rpc` diagnostic file inventory | six files, including `reth_eth_tx_builder_copied.rs` | six files, including `expensive_call_limiter.rs` instead of that file |
| revm | registry paths `revm 19.2.0`, `revm-interpreter 15.0.0`, `revm-precompile 16.0.0`, `revm-primitives 15.1.0` | `z_forks/revm-precompile` (12 path occurrences); `z_vendor` paths for bytecode, context, context-interface, handler, inspector, interpreter and state; version not encoded in these paths |
| reth | Cargo git checkout path `reth-e231042ee7db3fb7/3212af2` (10 occurrences) | `z_forks` paths `reth-chainspec`, `reth-ethereum-forks`, `reth-rpc-eth-types`, `reth-rpc-server-types` |

**Inference.** The method-string FDE is a route-table construction candidate: it repeatedly passes the 26 string pointers and lengths to calls and is called from the router Location FDE. The path change is consistent with differing dependency sourcing/fork layout between these builds. Neither observation establishes exact upstream revisions, fork patches, runtime reachability, handler identities or equivalence across releases. The short reth checkout token is not a complete commit SHA. A missing diagnostic path is not proof that a crate or file was absent from a build.

**Unresolved.** Which request branch reads a method, selects an entry, and reaches a particular EVM RPC handler? No call from a router-associated FDE to a *verified* dispatcher or handler was established. Calls between the router Location FDEs and to the table builder are real, but naming their callees as dispatchers would overstate the evidence. Register-indirect calls, vtables, async state and helper/data closure require further analysis; no direct runtime behavior is established. We do not transfer #94 addresses to #115.

## Implementation and comparison

No Rust implementation, Cargo.lock, build flags, two-build comparison, normalized/raw binary comparison, masks, helper/relocation/vtable/data closure, fixtures or runtime boundary behavior have been established. There is no byte transplantation. Generator tests compare the regenerated JSON byte-for-byte and independently decode the three call displacements and selected table LEAs with objdump. They reject altered #94 and #115 binaries and altered pinned inputs, reject a CLI non-ELF/digest mismatch without output, check an absent method literal, and test the exclusive FDE boundary. These are evidence/tool controls, not target behavior tests.

## Results and limitations

The bounded metrics are 26/26 reference names with a table-FDE LEA, 42 scoped Location records and 38 containing FDEs; denominators are as stated and are not function or binary coverage. The `.eh_frame_hdr` contains 121,299 entries, not a verified function census. There is no complete EVM RPC mapping, exact dependency lock or full-chain execution claim. **No gate change**: this partial static packet does not satisfy the full-component mapped, built, behavior or identity gates.

Next question: trace a concrete method lookup through the `0x2027610` range and its indirect calls, identify the target using relocation/vtable/dataflow evidence, and independently validate a handler FDE and its parameters without executing the target.
