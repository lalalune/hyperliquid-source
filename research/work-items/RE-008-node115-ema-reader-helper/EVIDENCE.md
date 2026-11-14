# RE-008: selected `+0x4e0` reader helper dataflow

- Component ID: `consensus` / RE-008.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: upstream `main` `a8616af9432b8d8517b2af677880e117b7c28ef3`; no reference-source semantics imported.
- Claim status: instruction and edge observations; tuple semantics and ownership unresolved.
- Scope: one actual FDE, selected count/slot handling, descendant descriptor construction and common output stores; no full CFG, runtime execution, Rust implementation or gate advancement.

## Reproduce

From repository root: `python3 research/work-items/RE-008-node115-ema-reader-helper/verify.py`. Input is the pinned `artifacts/node/115/hl-node`; Python standard library plus repository ELF/FDE readers. No target execution, networking or signing. The FDE body is `[0x4d256e0,0x4d25fd8)` and hashes to `f872fc8a63299d0e5d3f450cb54d40ceb07e876151aa155c10d6c6bc9ae0277e`.

## Evidence

- `0x4d256fe` loads the root object; `0x4d25705` reads its count at `+0x4da`; `0x4d2570c` forms the selected entry address at `+0x08`.
- `0x4d25752..0x4d257c7` preserves fields rooted at `+0x60` and `+0xc0`, while `0x4d257d1..0x4d257d4` decrements and stores the count.
- The helper separates empty, capacity, and descendant paths at the observed direct branches. The selected descendant path assembles a stack descriptor and reaches the internal recursive call at `0x4d25906`.
- The common return path writes the assembled record through output `+0x80`; selected witnesses cover the scalar, vector stores, and tail qwords.

The recursive helper's semantics, indirect memory-copy target, and full path reachability remain open. The packet does not assign source-level types from offsets alone.

## Implementation and comparison

No Rust implementation or binary-equivalence comparison. The verifier checks the original body hash, 18 complete instruction witnesses, four direct edges and one mutation control per witness.

## Results and limitations

The verifier passes all 18 witnesses, four edges and 18 mutation controls against the pinned target. No component gate changes. Next question: resolve the recursive helper and distinguish the slot copy from the record allocator path.
