# RE-008: selected EMA result helper layout

- Component ID: `consensus` / RE-008.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: upstream `main` `a8616af9432b8d8517b2af677880e117b7c28ef3`; no reference-source semantics imported.
- Claim status: instruction and edge observations; tuple semantics and ownership unresolved.
- Scope: one actual FDE, selected tree traversal, slot replacement, output-copy path and empty-path call; no full CFG, runtime execution, Rust implementation or gate advancement.

## Reproduce

From repository root: `python3 research/work-items/RE-008-node115-ema-result-helper/verify.py`. Input is the pinned `artifacts/node/115/hl-node`; Python standard library plus repository ELF/FDE readers. No target execution, networking or signing. The FDE body is `[0x4d30990,0x4d30c7a)` and hashes to `a0f4eda395fa738e185a3f08641d0320731a6f318d17f580584b0ccc09af9139`.

## Evidence

- `0x4d30998` preserves the caller's result pointer in `RBX`; `0x4d309a6` tests the count loaded from the descriptor.
- `0x4d30aae..0x4d30ab3` forms a stack descriptor and calls `0x4d2ec40`. The empty path at `0x4d30bdd` calls the same helper with a three-qword descriptor.
- `0x4d30b2a` stores the returned pointer at `base + index*8 + 0x218`; instructions `0x4d30b32..0x4d30b74` preserve and restore the selected 48-byte entry around that replacement.
- The return path at `0x4d30c41..0x4d30c6a` copies the tuple to output `+0x00..+0x37`, clears `+0x40`, and stores a qword at `+0x48`.

The helper call's result fields, parent-path meaning and all indirect data relationships remain open. The packet avoids naming the container or tuple type from disassembly alone.

## Implementation and comparison

No Rust implementation or binary-equivalence comparison. The verifier checks the original body hash, 13 complete instruction witnesses, three direct edges and one mutation control per witness.

## Results and limitations

The verifier passes all 13 witnesses, three edges and 13 mutation controls against the pinned target. No component gate changes. Next question: resolve the `0x4d2ec40` tuple construction and the descriptor fields consumed by the parent-path update.
