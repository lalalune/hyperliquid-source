# RE-017: replay leaf low-count repair dispatch (#115)

Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Addresses are ELF virtual addresses. This extends #6625's leaf compaction and #6628's nonzero-depth caller, both of which leave low-count continuation open. This is a bounded static branch map, not a reconstruction of the three called helper bodies or proof of complete balancing.

## Dispatch after selected compaction

Let `c` be the 16-bit count loaded before compaction, with `1 <= c`, and let `c' = c-1`. `0x4d2c0f8..0x4d2c10c` stores `c'` and skips the low-count dispatch when `c'>4`. For `c'<=4`, a null parent bypasses the sibling cases. Otherwise the code reads the 16-bit child index at node `+0xe4`.

For a nonzero child index `j`, it loads the qword at `parent+0xe0+8*j` (equivalently the previous child slot in the `+0xe8` array). For `j=0`, it first requires a nonzero parent count and loads `parent+0xf0` (the next child slot). A zero parent count enters the separate `0x4d2c306` exceptional path. In either selected sibling case, it reads that sibling's 16-bit count `s` and compares **the original count** `c+s` against 12; this is equivalent to comparing `c'+s` against 11 under the stated count assumption.

- If `c+s<12`, both sides call `0x4c9fa80`, with side argument 1 for the previous slot and 0 for the next slot.
- If `c+s>=12`, the previous-slot side calls `0x4c92630` with argument 1; the next-slot side calls `0x4c98390` with argument 1. The previous-slot case increments the returned index afterward.
- The subsequent parent check calls `0x4c35400` where a parent is present; its behavior and the called repair helpers' full effects are not established here.

These branches are conditional on valid node, sibling and parent descriptors and normal helper returns. Labels such as sibling and repair are structural inferences. The packet does not show that any particular runtime input reaches these branches, that invariants hold, or that recovered checkpoint replay or roots match.

## Reproduction

Run `python3 research/work-items/RE-017-node115-replay-underfull-dispatch/verify.py`. It authenticates the target, checks five instruction anchors and four direct calls, and rejects five one-byte anchor mutations. `windows.txt` is an `/usr/bin/objdump -d --x86-asm-syntax=intel` excerpt. No captured node code is executed and no project completion gate is changed.
