# RE-008: selected `+0x4e0` reader and output layout

- Component ID: `consensus` / RE-008.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: upstream `main` `a8616af9432b8d8517b2af677880e117b7c28ef3`; no reference-source semantics imported.
- Claim status: instruction and edge observations; tuple semantics and ownership unresolved.
- Scope: one actual FDE, `+0x4e0` table traversal, selected entry replacement, record copy and common output stores; no full CFG, runtime execution, Rust implementation or gate advancement.

## Reproduce

From repository root: `python3 research/work-items/RE-008-node115-ema-reader-4e0/verify.py`. Input is the pinned `artifacts/node/115/hl-node`; Python standard library plus repository ELF/FDE readers. No target execution, networking or signing. The FDE body is `[0x4d30c80,0x4d31061)` and hashes to `fbc21b2a3e4c1b659195550a0f0c84de35ef88c5b7e063aa727b812ab1f22167`.

## Evidence

- `0x4d30c9f` loads the selected table entry through node offset `+0x4e0`; `0x4d30c99` sends the empty count path to `0x4d30f75`.
- `0x4d30da4..0x4d30daf` builds a stack descriptor and calls `0x4d256e0`.
- `0x4d30e5f` replaces the selected table entry pointer. The selected record copies preserve and restore fields rooted at `+0x60` and `+0xc0`.
- `0x4d31001..0x4d3104e` writes the common output layout through `+0x80`, including a cleared qword at `+0x78`.

The helper call's returned fields, table invariant, and all indirect data relationships remain open. The packet does not assign a source-level type from offsets alone.

## Implementation and comparison

No Rust implementation or binary-equivalence comparison. The verifier checks the original body hash, 20 complete instruction witnesses, three direct edges and one mutation control per witness.

## Results and limitations

The verifier passes all 20 witnesses, three edges and 20 mutation controls against the pinned target. No component gate changes. Next question: resolve `0x4d256e0` and determine the descriptor fields consumed by the `+0x4e0` reader.
