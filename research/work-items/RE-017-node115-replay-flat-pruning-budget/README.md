# RE-017: flat pending-map secondary pruning and compaction (#115)

## Question and scope

PR #6677 traces the flat pending-map primary digest path and leaves the alternative timer branch and compaction open. What happens when that callback's second threshold is reached, and how does its return value affect the flat map? Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Addresses are ELF virtual addresses; main reference `a8616af9432b8d8517b2af677880e117b7c28ef3`. FDEs `[0x57f1690,0x57f1874)` and `[0x57d44d0,0x57d4aea)`.

## Observations

When the first threshold comparison is earlier, the callback starts a second threshold construction using f64 `60.0` (`0x57d4784..0x57d47a6`). At `0x57d4890..0x57d48e5` it compares three words with signed ordering for the first and unsigned ordering for the remaining two. Earlier-than returns low byte 1. For a greater-or-equal second comparison, it loads the qwords through context pointers `+0x28` and `+0x30`; if the former is unsigned-less than the latter, it increments the former and returns low byte 0; otherwise it returns 1 (`0x57d48eb..0x57d490c`, `0x57d4a48..0x57d4a5b`). The 0 result occurs without calling digest extraction on this selected secondary path.

The caller `0x57f1690` first scans a prefix of entries whose callback result is nonzero, then scans later 24-byte entries. Each later nonzero result is swapped into the next prefix position. When at least one zero result was found, it writes the retained prefix length to map `+0x18` (`0x57f16a6..0x57f1706`, `0x57f1760..0x57f1848`). Inference: the selected valid ring case stably retains nonzero-result entries and removes zero-result entries from its logical length. This counter update occurs at compaction, not at each callback invocation.

Under #6626's normal-call context assumptions, the secondary increment is bounded by the initial `max(0,C-1000)` budget. This does not imply the final length is at least 1000: primary extraction callbacks can also return zero. Valid ring bounds, no alias/interference, successful calls and sufficient memory are assumptions; no real execution, full timer arithmetic, returned digest validity, checkpoint or state-root equivalence is proven. No completion gate changes.

## Reproduction

Run `python3 research/work-items/RE-017-node115-replay-flat-pruning-budget/verify.py` to authenticate the artifact, verify seven instruction anchors and both callback direct calls, and reject seven independent one-byte mutations. `windows.txt` is Apple LLVM objdump 21.0.0 `-d --x86-asm-syntax=intel` output; Python 3.11.15 was used. The captured target is not executed.
