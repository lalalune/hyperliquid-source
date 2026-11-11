# RE-001: trace the BOLE conditional input at `0x54b29ea`

- Component: `exchange`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`.
- Scope: trace the value tested at the branch already recorded in [the call-edge packet](../RE-001-node115-loc-edge-54b2a0a/README.md), ending at the static helper that populates the caller's temporary result. No source-level type or behavior is assigned to the result.

## Observation

The branch at `0x54b29ea` is controlled by `test rax, rax` at `0x54b29e7`. The preceding instruction loads `rax` from `[rbp+8]` (`488b4508` at `0x54b29e3`), so the branch is taken exactly when that eight-byte field is zero.

Within the recorded FDE `[0x54a9c70,0x54b66a2)`, this base address `rbp` is assembled from the eight bytes returned in the temporary at `[rsp+0x68..0x70)`. The instructions at `0x54b272f`, `0x54b2754`, `0x54b275c`, and `0x54b2763` load those bytes, and shifts/or operations at `0x54b2767..0x54b2772` reconstruct the little-endian 64-bit value. This establishes the data dependency; it does not establish what the value represents.

The temporary is populated through an indirect call at `0x54b2724`. Its RIP-relative slot resolves to `0x64e71b0`; the `.rela.dyn` entry at that address is `R_X86_64_RELATIVE` with addend `0x3699410`. The call setup passes `&[rsp+0x60]` in `rdi` and the value saved at `[rsp+0x30]` in `rsi`. That saved value came from `r12` at `0x54b25d1`, where `r12` had been formed as `r15+0x670` at `0x54b259f`.

The helper's FDE covers `[0x3699410,0x3699613)`. Its entry retains the two arguments in `r13` and `rbp`, reads fields at offsets `0x88`, `0x90`, and `0x98` from the second argument, and returns the output-buffer address in `rax`. The downstream helper calls and the semantic type of the output remain unresolved. The evidence therefore stops at the helper-populated bytes and the exact qword tested by the branch.

## Reproduce

From the repository root with the pinned LFS target materialized:

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
objdump -d -M intel --start-address=0x54b259f --stop-address=0x54b2a16 "$target"
objdump -d -M intel --start-address=0x3699410 --stop-address=0x369946c "$target"
python3 research/work-items/RE-001-node115-bole-null-check-54b2a0a/verify.py
```

`verify.py` uses the repository's static ELF/FDE parsers. It checks the artifact digest, the two unwind extents, the branch and call instruction bytes, the call-slot relocation, and a one-byte displacement-corruption control. It reads the captured ELF as data and does not execute it.

## Results and limits

The zero/nonzero predicate and its dataflow through one caller temporary to a digest-bound helper are established. The helper's own callee semantics, the output layout's source-level type, the reason for the zero case, branch reachability, and the eventual runtime effect remain unknown. This packet advances one RE-001 question only; it claims no component gate, function denominator, or reconstruction completeness.
