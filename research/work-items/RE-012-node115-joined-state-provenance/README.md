# Source of the joined startup state's result word

On a selected normal return from node 115 startup, the qword at outer result offset `+0x30` is the pointer returned by the state builder at VA `0x3c13610`. Startup receives it through the thread-join helper's `0x44` result at **offset +8**. The same join result also contains a separate allocation at offset `+0x30`. Those offsets belong to different result layouts. Confusing them would connect the startup consumer to a 176-byte auxiliary record instead of the builder's 17,096-byte state allocation.

**Target.** Linux x86-64 `artifacts/node/115/hl-node`, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Addresses below are ELF virtual addresses before rebasing. The scope is a conditional static pointer identity under ordinary ABI, valid, non-aliasing live buffers and normally returning helpers.

| Boundary | Observation on the selected route |
| --- | --- |
| Build the state | The join helper at `0x56467d0` saves its output pointer in R13 and calls `pthread_join`. Its selected builder call at `0x5646ba2` goes through slot `0x64e73a0` to `0x3c13610`. That previously reconstructed builder copies `0x42c8` bytes into fresh storage and returns its address. The join helper compares byte `[rax+0xb9a]` to R15B, then saves RAX at `[rsp+0x48]` on equality. |
| Select the join variant | At `0x5646c7d..0x5646cad`, two 16-byte comparisons are ANDed. A full `0xffff` mask selects `0x5646df7`. The unequal branch writes tag `0x3c`. The comparison establishes equality of the two byte sequences on the selected branch. Their domain meaning remains unresolved here. |
| Distinguish the two allocations | After a second allocation of `0xb0` bytes, the helper stores that pointer from RBX to `[r13+0x30]`. It separately reloads the saved builder return and stores it to `[r13+8]` at `0x5646ef0`, then writes tag `0x44`. |
| Map into the outer record | At `0x2ad9fcc`, the caller supplies `rsp+0x220` as output. On the direct tag-`0x44` edge it reads `rsp+0x228`. The live word passes through stack `+0x18`, R14, RCX, stack `+0x28`, then RCX again. The caller sets R13 to 2. The selected branch writes R13 at `rsp+0x350` and RCX at `rsp+0x380`, a difference of `0x30`. |
| Return the record | At `0x2adaae6..0x2adaaf9`, the byte produced by `r13 == 2` is XORed with `[rbx+0x54]`. The direct return arm therefore requires that context byte to be exactly 1. On its ordinary housekeeping path (global test at `0x2adb480` falls through), two `memcpy` calls each carry `0x98` bytes, first to `rsp+0x1860`, then to the original output pointer kept in `rsp+0x1b8`. Both copies include the whole selected qword. |

## Prior work and consumer

The [state load chain](../RE-016-state-load-chain-115/README.md) establishes the builder's allocation protocol and lists `0x5646ba2` as a separate, unanalysed caller. The [sibling join study](../RE-005-node115-sibling-join-ownership/README.md) includes the join helper among the users of shared ownership machinery. The [keyed block result](../RE-017-abci-keyed-result-115/README.md) follows a different caller of the same materializer. The new evidence is the field identity across this particular join helper and outer return.

[PR #7064](https://github.com/lalalune/hyperliquid-source/pull/7064) picks up the outer result's `+0x30` qword and follows it into the startup constructor. Its downstream analysis is independently reviewable. Assigning this producer to a specific invocation of another checkpoint loader, establishing its input file or height, and proving replay or root correctness all require additional evidence.

## Reproduction

From the repository root, with Python 3, pyelftools and Capstone 5.0.7 available:

```sh
python3 research/work-items/RE-012-node115-joined-state-provenance/verify.py --target artifacts/node/115/hl-node
(cd research/work-items/RE-012-node115-joined-state-provenance && shasum -a 256 -c MANIFEST.sha256)
```

The verifier reads the artifact as ELF data. It checks the target digest, unwind ranges, instruction transcripts and relocation destinations, then derives the field displacement and checks both copy sizes. Six negative controls alter individual instruction encodings in memory and send them through disassembly and the field checks again. Examples include selecting the auxiliary pointer, taking the unequal comparison branch, and shortening the final copy until the selected word is excluded.
