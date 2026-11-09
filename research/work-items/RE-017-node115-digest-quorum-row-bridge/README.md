# RE-017 · Node #115 digest-quorum descriptor receives compact replay rows

- Component ID: `abci` / replay comparison boundary.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit: `0781ce04826eeefd89fe336cb8ea073be0c1de30`.
- Claim status: static observations with conditional data-flow inference; indirect runtime binding unresolved.
- Scope: the selected first call from the compact row loop to the object at context `+0x280`, its row arguments and the subsequent insertion boundary. No root value or state semantics are claimed.

This closes a narrow join left open by [the descriptor-owner packet](../RE-017-node115-digest-quorum-owner/README.md) and [the compact reference lookup](../RE-017-node115-compact-digest-reference-lookup/README.md). The former places the constructor's `abci_digest_quorum` descriptor at owner body `+0x930` (returned allocation `+0x940`). The [raw-reference packet](../RE-017-node115-raw-reference-origin/README.md) places the replay context at owner body `+0x6b0`; `0x930 - 0x6b0 = 0x280`. On the selected same-owner path, the comparator's `context+0x280` therefore addresses that constructed descriptor. The compact reference lookup stops at the call to `0x4e3a020`; this packet traces its row arguments through the first downstream builder boundary.

## Evidence

At `0x5a05c14`, the compact loop computes `RBX = R12 + 0x280`. For each row, `R13` advances by `0x68`; the loop copies the two 16-byte lanes at row offsets `+0x48` and `+0x58` into stack `R12`, and copies the qword at row offset `+0` to `R12+0x20`. It calls `0x4e3a020` with:

- `RDI = context + 0x280`;
- `RSI =` a temporary at `RSP+0x98`, initialized through an indirect call immediately before the row loop;
- `RDX =` a stack record containing the incoming row key and 32-byte candidate.

The callee retains those pointers in `R14`, `R15` and `R12`. It copies the first two qwords of the initialized temporary and calls through slot `0x64e0f80` with `RSI=R14` (the `+0x280` descriptor) and `RDX` pointing to the copied temporary fields. This indirect call is not passed the row bytes. On the selected normal continuation, the callee then calls `0x50e6fe0` with `RDI=descriptor+0x48`, `RSI` pointing to those temporary fields and `RDX` still pointing to the row record. `0x50e6fe0` allocates a 0x80-byte intermediate and forwards the row-record pointer to `0x537d7b0`. This proves the descriptor-associated path receives each row and reaches that boundary, while leaving both dynamic dispatch effects and the builder's semantics unresolved.

After the helper returns, the caller advances `R13` and the existing comparison path reads the candidate lanes again from the original row and searches the separate history context at `+0x400`. The selected instructions therefore show row data passed through the descriptor-associated path and independently reused for comparison. They do not show that this path produces the reference digest, changes the incoming row, or supplies the `+0x400` history. The address join is conditional on the same selected owner construction and normal returns.

The selected helper also stores intermediate fields relative to the descriptor. Dynamic call bindings, aliasing writes outside the selected instructions, the meaning of the object fields, quorum rules, persistence and runtime scheduling remain unresolved. This is not evidence of a canonical root, successful replay, or a full component gate.

## Reproduce

The recorded instruction rows were obtained with Apple LLVM `llvm-objdump` 21.0.0. From repository root:

```sh
python3 research/work-items/RE-017-node115-digest-quorum-row-bridge/verify.py
```

The verifier checks the authenticated #115 digest, selected instruction bytes, their file-backed `.text` mappings and FDE membership, the direct call target and the recorded row-field/argument instructions. It has corruption controls for an altered call displacement and descriptor offset. An FDE extent is an unwind range, not a validated function boundary.

## Results and limits

The bounded result is a call/data-flow join: the constructor's `abci_digest_quorum` descriptor is the object at replay-context `+0x280` on the selected same-owner path. Each selected row is routed through a descriptor-associated helper before the comparator looks up a reference through context `+0x400`; the candidate is read directly from the row for that comparison. No progress gate is requested. Next question: resolve the `0x64e0f80` binding and trace the descriptor-associated state without assuming it is a root source.
