# RE-008: selected context forwarding inside the first EMA helper

- Component: consensus, bounded static continuation of the #115 latency-EMA query path.
- Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base: `a8616af9432b8d8517b2af677880e117b7c28ef3`; no reference source copied.
- Coordinates: linked ELF VAs, exclusive end. Actual FDE `0x12fae40` covers `[0x4de2150,0x4de2556)` (1,030 bytes); full body SHA-256 `7e6a95742e5b547a797dcbe13598164012c9e05d7ba4b2b296bda612dbfa51fb`.
- Claim: one sentinel-conditioned entry and one later context-forwarding arm. This is not a complete helper reconstruction or component gate.

## Gap and observation

Open PR #6783 establishes that wrapper `0x5a722f0` passes a five-word context to `0x4de2150`. No integrated work item or current open PR explains how this callee first treats those words; the existing skiplist records cite it only as a containing FDE for a different call. This packet inspects two instruction-aligned excerpts, `[0x4de216e,0x4de21a0)` and `[0x4de2321,0x4de236f)`, while authenticating the complete FDE body.

At `0x4de216e..0x4de2179`, the callee compares zero against the first qword of its RDI object and branches on **no signed overflow**. For 64-bit subtraction `0 - n`, overflow occurs only when `n` is `0x8000000000000000`; that value selects the fall-through arm. In the arm, `0x4de217d..0x4de21a0` copies five qwords from the incoming RSI context into local `rsp+0xc0..0xe7`. The later selected block at `0x4de2321..0x4de236f` places a pointer to that local copy in a descriptor at `rsp+0x90`, then calls `0x514ef40`. This proves the original context, including its input-pointer word, is forwarded as data to a nested helper on that path. It does not prove the nested helper's read/write behavior or that every path reaches it.

The wrapper's own source labels and the sentinel's high-level container meaning remain inferred. The body contains further traversal, construction, cleanup and unwind paths that are not analysed here. No normalization or compiled-code equality claim is made.

## Reproduce and controls

Run from repository root with the pinned artifact:

```sh
python3 research/work-items/RE-008-node115-ema-context-forward/verify.py
```

The standard-library verifier authenticates the whole target digest, resolves the actual FDE, checks the 1,030-byte body SHA-256 and all 128 selected bytes, and decodes the direct call to `0x514ef40`. Five changed-byte controls in the branch, context loads/stores, descriptor and call must fail after the whole-image guard is bypassed. `result.json` stores the output. GNU objdump 2.47.20260726 was used to select aligned instruction windows. No captured binary is executed or emulated. Imported bytes retain upstream rights; new text and verifier use the repository MIT license.

Local checks on macOS arm64, Python 3.14.3: `verify.py` passed (1,030-byte body hash, 128/128 selected bytes, 5/5 controls). `make doctor` passed with installed GNU binutils exposed through ignored `work/bin`; `make verify` passed after pinned submodules were materialized (3,728 manifests, 29,756 entries); `make reproduce` and `make catalogue-check` passed. `make test` was stopped after 25 seconds at file 10/1397. No full-suite or hosted-CI pass is claimed.

## Limits and next question

No Rust implementation, full callee semantics, target-equivalence result, validated function denominator, gate or network effect is claimed. Next: inspect the `0x514ef40` branch that consumes the descriptor and determine whether it dereferences the forwarded input pointer or mutates its pointee. The preceding path's complete reachability and object invariants remain open.
