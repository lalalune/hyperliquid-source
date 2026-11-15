# RE-017: flat pending-map ring wrap (#115)

## Question and scope

PR #6678 traces selected flat-map compaction but leaves the ring address calculation implicit. Under what conditions does its single subtraction visit the intended 24-byte entries across the wrap boundary? Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; ELF virtual addresses. Main reference `a8616af9432b8d8517b2af677880e117b7c28ef3`; helper FDE `[0x57f1690,0x57f1874)`.

## Observation and deduction

The helper loads four qwords at map offsets `0`, `+8`, `+0x10`, `+0x18`. On the nonempty selected path, label them capacity `N`, data pointer `P`, head `H` and logical count `C` respectively as a structural inference. At `0x57f16d0..0x57f16f7` the first scan computes `H+j`, compares it unsigned with `N`, subtracts `N` once when greater or equal, scales the result by 24 and passes `P+24*index` to the predicate. The later scan and retained-prefix swap use the corresponding single-subtraction expression at `0x57f1760..0x57f17d7`; the swap moves 24 bytes (`0x57f17dc..0x57f180e`).

If `N>0`, `H<N`, `C<=N`, `0<=j<C`, and the address arithmetic does not overflow, then `H+j<2N`; one subtraction is sufficient, so the selected physical index equals `(H+j) mod N`. The first scan and later scan thus address the same logical ring indexing convention, including a crossing of the capacity boundary. These are conditional arithmetic deductions, not proof that all runtime descriptors satisfy the assumptions. Invalid capacity/head/count, allocation bounds, callback mutations, other representations and exception paths remain open. No native execution, checkpoint or state-root equivalence is claimed.

## Reproduction

Run `python3 research/work-items/RE-017-node115-flat-ring-wrap/verify.py` to authenticate the target, check four instruction anchors and two predicate direct calls, and reject four independent one-byte mutations. `windows.txt` is Apple LLVM objdump 21.0.0 `-d --x86-asm-syntax=intel` output; Python 3.11.15 was used. No completion gate is advanced.
