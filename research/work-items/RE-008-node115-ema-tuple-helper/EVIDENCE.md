# RE-008: selected node-link maintenance in EMA tuple helper

- Component ID: `consensus` / RE-008.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: upstream `main` `a8616af9432b8d8517b2af677880e117b7c28ef3`; no reference-source semantics imported.
- Claim status: instruction and edge observations; node and allocator semantics unresolved.
- Scope: one actual FDE, selected child backlink/index stores, count updates and removal cleanup; no full CFG, runtime execution, Rust implementation or gate advancement.

## Reproduce

From repository root: `python3 research/work-items/RE-008-node115-ema-tuple-helper/verify.py`. Input is the pinned `artifacts/node/115/hl-node`; Python standard library plus repository ELF/FDE readers. No target execution, networking or signing. The FDE body is `[0x4d2ec40,0x4d2f8bb)` and hashes to `cdf565ff24380bd6d5f1bcb456ba828dd2b8d0bdf2279f51b221c82ae1bad691`.

## Evidence

- `0x4d2ec64` loads the root object from the descriptor; `0x4d2ec6b` reads its 16-bit count at `+0x272`; `0x4d2ec72` forms a selected slot address using `+0x218`.
- `0x4d2ed02..0x4d2ed05` decrements and stores the count before the selected path continues. `0x4d2ed59` loads a child through an indexed `+0x270` path.
- In a child propagation loop, `0x4d2ef8c` writes the current parent pointer at child `+0x210`; the following instructions store the child index at `+0x270`. The loop repeats across up to four children per block.
- In the selected removal path, `0x4d2f7b5..0x4d2f7c2` moves the first child into the removed node slot and decrements the remaining count; `0x4d2f7c6` clears the moved child's parent pointer at `+0x210` before resuming the update path.

The indirect helper at relocation slot `0x64df568`, balancing behavior, and all path reachability remain open.

## Implementation and comparison

No Rust implementation or binary-equivalence comparison. The verifier checks the original body hash, 13 complete instruction witnesses, three direct edges and one mutation control per witness.

## Results and limitations

The verifier passes all 13 witnesses, three edges and 13 mutation controls against the pinned target. No component gate changes. Next question: resolve the indirect helper targets and determine the tuple fields that accompany the node-link updates.
