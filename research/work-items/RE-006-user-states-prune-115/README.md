# RE-006: per-book user_states prune closures of node #115, recovered and re-run from bytes

- Component ID: orderbook (RE-006 book transitions)
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository main at packet time; no reference source is copied. An earlier release was used only as a clue for the shape of the rule and was re-derived on #115 bytes (different strides, offsets and addresses).
- Claim status: observation (byte patterns, layouts, run results), inference (the written rule), unresolved (ring buffer form, host loops)
- Scope included and excluded: the two per-book closures `0x2425d20` and `0x2425870` of the block step `prune_book_empty_user_states` and their whole callee tree for the B-tree form of `user_states`. Excluded: the ring buffer form, the inlined step loops in the three hosts, thread pool split arms.

With this packet the effect of the step on one book can be reconstructed as an executable rule: an entry of `user_states` goes exactly when its `b` and `u` length words are both zero and no occupied slab slot of the book holds that user; `r` plays no part. The rule is checked against the real bytes of both closures (10,730 cases, 0 mismatches), and 39 deliberately wrong rules, byte flips and out-of-range inputs are all detected.

## Reproduce

```
python3 tools/artifacts.py verify
python3 tools/prune_user_states_115.py --out research/work-items/RE-006-user-states-prune-115
python3 -m unittest tests.test_prune_user_states_115
(cd research/work-items/RE-006-user-states-prune-115 && sha256sum -c MANIFEST.sha256)
```

The tool reads the ELF with the shared parsers (`tools/elf_index.py`, `tools/fde_extents.py`), checks the SHA-256 first, never runs the binary and calls no external program. Regenerating twice into different folders gives identical bytes. Peak memory about 630 MB, about 220 s.

## Evidence

All addresses are virtual addresses of #115; bytes are read with struct.

- Step name: the text `prune_book_empty_user_states` (28 bytes) is at `0x60e21e` and `0x929e38`; three `lea` sites load it, in the host functions `0x2bdf8f0` (`0x2be191a`), `0x54a9c70` (`0x54abd99`) and `0x54b66b0` (`0x54b8710`); each is followed by the length word `0x1c`. The step is inlined in the hosts, so the per-book work is in two closures.
- Closures: `0x2425d20` (rows) and `0x2425870` (list) are byte-identical after masking call and rip displacements (same masked SHA-256 in `evidence.json`), and differ only in callees: collector `0x231e650` / `0x231e420`, remove loop `0x2dcf030` / `0x2dcf3d0`. Shared callees: reference list builder `0x234bec0`, set remove `0x1d5d520`, drop walk `0x2447f90`.
- Filter: `0x29fa380` / `0x29fbe00` contain `mov rsi,[rdx+0x38]; or rsi,[rdx+0x50]` over (key, value) reference pairs; a pair passes only when both length words are zero, and the 20 key bytes are appended to a key vector.
- Layouts (see `evidence.json`, `layout`): book stride `0x120`, slab pointer/length `+0x88/+0x90`, slab slot stride `0x110` with state dword at `+0` (2 = vacant) and the 20 byte user at `+0xf8`; `user_states` at book `+0xe8` is an enum with niche word `0x8000000000000000` for the B-tree (root `+0xf0`, height `+0xf8`, length `+0x100`) and a sorted ring otherwise. B-tree node: parent at 0, 11 values of 0x58 bytes from `+8`, 11 keys of 20 bytes at `+0x3d0`, parent index `+0x4ac`, length `+0x4ae`, edges `+0x4b0`. The set node is the 20 byte key B-tree node: keys `+8`, length `+0xe6`, edges `+0xe8`, size `0x148`.
- Flow of a closure (observed in the bytes, confirmed by the run): collect the candidate users into a B-tree set; for each slab slot of the first `slab_len` with state dword other than 2, remove that slot's user from the set; remove every user still in the set from `user_states`, dropping the stored value.
- Files: `evidence.json` (functions, anchors, layout, rule table, counts), `cases.tsv` (first 600 cases), `controls.tsv` (39 controls), `mutations_not_killed.tsv`, `measure.json`.

## Implementation and comparison

`tools/prune_user_states_115.py` contains a small x86-64 evaluator (decoder, memory, machine) that runs the real function bytes of both closures and their entire callee tree. Stubbed edges only: allocator (malloc/free/growth), memcmp/memcpy/memmove, the thread-pool registry and thread word, and panic slots. A separately written rule (`removed`, `spec_run`) predicts the final key list, length, untouched bytes (slab, rest of the book, values of kept users) and the absence of leaked allocations. The tool builds B-tree books of height 0 to 3, with kept, dropped and held users, near-identical 20 byte keys, state dwords such as 3, 0x102, 0x200000000 and 0x500000002, slab lengths shorter than the slab, empty maps, vectors with capacity but no length, and 5,200 random books per closure.

- Cases: 10,730 (330 structured, 2 x 5,200 random), mismatches 0, about 49.7 million instructions executed.
- Negative controls: 39 of 39 detected: 19 wrong rules (ignore `u`, ignore `b`, require `r` empty, `or` for `and`, vacant counted as held, slab length ignored or off by one, state compared as 64 bits, nothing/everything removed, one removal skipped, stale length, ...), 12 single-byte flips of the anchored instructions, 3 digest damages, 4 out-of-range address checks (FDE and file offset).
- Mutation pass (flip every branch, immediate and field offset in 13 functions of the callee tree, run only cases that reach it): 683 mutants, 350 killed, 85 survived, 248 unreached. Survivors are listed without a classification in `mutations_not_killed.tsv`; they are not counted as controls.
- Unit tests: `tests/test_prune_user_states_115.py`, 12 tests, no skips.

## Results and limitations

- The rule above holds on every case for both closures; the closures are the same code with different callees.
- Not modelled: the ring buffer form of `user_states` (its collector enters the rayon join with a work-stealing deque and atomics, which the evaluator does not model); the inlined loops of the three hosts around the closures (which books are visited, and the gate on the step); thread pool split arms (all runs are the sequential path of a worker thread); allocator failure.
- 248 mutants are unreached for these reasons, 85 survive; this is a limit of the case list, not proof that those bytes are irrelevant.
- No component gate is requested.

Next question: model the rayon join of `0x2e41e50` / `0x2e41cf0` to run the ring form, then recover the host loop that decides which books reach these closures.
