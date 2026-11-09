# RE-011: reconstruct the node #115 EVM journal checkpoint revert (0x29710e0 x3) and the account-slot journal write (0x29712c0)

With this packet the journal half of the `evm` journaled state can be rebuilt as a pure function: the checkpoint-revert body (depth saturating decrement, log truncation with the capacity<<5 free and the vtable +0x20 drop, watermark lowering, newest-first journal replay through the GOT applier with the tag-0xc stop and the spec >= 3 flag) and the 20-byte-key slot write (hashbrown probe over 0xa8-byte buckets, panic on empty or absent, tag-2 first-touch entry, tag-0xb entry, journal growth through a GOT helper, value and reference replacement with the lock-decrement slow-path free) are re-implemented in Python, and 14,400 bytes-driven cases agree with the real machine code with 0 mismatches.

- Component ID: evm (RE-011, EVM fork / RPC adapter)
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: main at the time of the run (no reference source copied; the #94 notes were not used for any address or layout)
- Claim status: observation (byte-verified behaviour of the listed bodies) with inference only where marked below
- Scope included and excluded: revert bodies 0x29710e0, 0x4322f30, 0x5463410 (0x1e0 bytes each, identical but for two GOT displacements) and write body 0x29712c0 (0x230 bytes). Excluded: the applier behind GOT slot 0x64e6d68 (stubbed, arguments recorded), the heap-free helper behind 0x64df4a0, the vtable drop, the journal grow helper behind 0x64e6cf0, the reference slow-path free behind 0x64e4fa8 and the panic helper behind 0x64df830 (all boundaries, arguments recorded); the non-copy siblings 0x4323110 and 0x5463860 of the write body (they call the separate lookup 0x3ed7e80 and are not byte copies); unwind landing pads. No component gate is requested.

## Reproduce

Working directory: repository root; Python 3 standard library plus `tools/elf_index.py`, `tools/fde_extents.py` and the evaluator of `tools/re11_transient_storage115.py`; no external program is run and the binary is never executed.

```
python3 tools/re11_journal115.py --out research/work-items/RE-011-journal-revert-write-115
python3 -m unittest tests.test_re11_journal115
(cd research/work-items/RE-011-journal-revert-write-115 && sha256sum -c MANIFEST.sha256)
```

The tool refuses to run when the input SHA-256 differs from the one above, writes every evidence file deterministically (no time, no randomness, no absolute path) and was run twice with identical bytes. Case inputs come from a SHA-512 counter stream labelled per body, so the case lists are reproduced from the tool alone.

## Evidence

All addresses are virtual addresses of node #115. Every number below is read from ELF bytes by the tool (`constants.json`, `decoded-instructions.tsv`).

State object (the executing journaled state, argument 1 of both bodies): logs pointer +0x8 and length +0x10 (0x50-byte entries: capacity +0x0, buffer +0x8, vtable +0x18, bytes pointer +0x20, bytes length +0x28), journal capacity +0x18, pointer +0x20, length +0x28 (0x58-byte entries, tag in byte 0), watermark +0x40, state maps +0xc8 and +0xf0, item count +0xe0, secret +0xe8, depth +0x118, spec byte +0x126.

Revert (0x29710e0, copies 0x4322f30 and 0x5463410 differ only in the displacements at +0xb8..+0xbb and +0x14e..+0x151, i.e. the GOT slots of the applier 0x64e6d68 and of the heap free 0x64df4a0, see `constants.json`):

1. depth +0x118 = depth - 1, saturating at zero (`cmp $1; adc $-1`).
2. If the checkpoint log length (checkpoint +0x0) is not above the current log length, the length becomes the checkpoint value and every log from there up is dropped in order: a heap free of `capacity << 5` bytes with alignment 0 when the capacity is non-zero, then a call through vtable slot +0x20 with (entry +0x30, bytes pointer, bytes length). A larger checkpoint leaves the logs alone.
3. watermark +0x40 = min(watermark, checkpoint +0x10) (store when checkpoint <= watermark).
4. If the checkpoint journal length (checkpoint +0x8) is below the current one, the journal length becomes the checkpoint value and the removed entries are walked newest first: an entry whose tag is 0xc stops the walk (the entry is not applied); any other entry is copied to the stack and handed to the applier with (entry copy, state +0xc8, state +0xf0, flag = spec >= 3).

Write (0x29712c0): with the map item count (+0xe0) zero, or after a probe that meets a group with an EMPTY control byte and no match, the body calls the panic helper with the message at 0x6441ca8. Otherwise it finds the bucket (hash: folded two-multiply of the 20-byte key with the secret +0xe8 and the process seed behind slot 0x64dfa78; control byte h>>57; triangular 16-byte group probing; bucket i ends at ctrl - i*0xa8, key at -0xa8, flags at -4, value at -0x48, reference word at -0x20). A bucket without flag bit 4 gets a tag-2 journal entry (key bytes at +0x1..+0x14) and the flag; a tag-0xb entry is always pushed; each push calls the grow helper first when capacity == length. The 32-byte value replaces the bucket value, a non-zero old reference word has its count decremented (the `lock` prefix at +0x1c4 is run as a nop: single thread) and the slow-path free runs when it reaches zero, and the new reference word is stored.

Executed instruction coverage (from `decoded-instructions.tsv`): 104/121 of each revert copy and 127/141 of the write body; the unexecuted rows are unwind landing pads, nop padding and the `ud2` after the panic call.

## Implementation and comparison

`tools/re11_journal115.py` evaluates the real machine code of every body with the concrete x86-64 evaluator of `tools/re11_transient_storage115.py` and compares each case with `model_revert` / `model_write`, which are pure Python reconstructions (including the hash, the probe and both journal pushes). Boundaries are stubbed with recorded arguments (offsets relative to the case memories) and compared as ordered event lists, together with return, callee-saved registers, stack pointer and the final bytes of every region.

- Cases: 14,400 = 3 x 3,600 revert cases (one stream per copy) + 3,600 write cases; sampled rows in `cases-revert.tsv` (every 2nd) and `cases-write.tsv` (every 2nd), class counts in `outcome-classes.tsv`. Revert cases vary log and journal lengths, checkpoint positions (below, equal, above), watermark relations, depth (0, 1, 2^63, 2^64-1), spec byte, capacities including 2^59, 2^63 and 2^64-1 (shift wrap) and a tag-0xc sentinel at random positions. Write cases vary bucket count 16/32/64, decoys that differ in one key bit, tombstones, a full first probe group, empty maps, first-touch versus already-touched buckets, journal full at the first or second push, old reference counts 0/1/2/5/2^64-1.
- Result: 0 mismatches in 14,400 cases.
- Negative controls (57, all detected): 18 wrong revert reconstructions (depth wrap, depth floor, missing free, free size, drop order, kept log length, watermark rules, spec thresholds, kept journal length, forward walk, one extra entry, sentinel handling, swapped applier arguments), 10 wrong write reconstructions (control shift, tail ignored, single-group probe, ignored item count, missing secret, forced first touch, wrong tag, dropped value, no slow-path free, kept reference), one inverted condition byte at every conditional jump of 0x29710e0 and of 0x29712c0 and at the first five of each sibling revert copy, a flipped `.text` byte (digest check) and an address past `.text`. Equivalent mutants (a model change with no observable effect, e.g. strict versus non-strict compare when the two lengths are equal) were removed rather than counted.
- Unit tests: `tests/test_re11_journal115.py` (9 tests, 0 skipped).

## Results and limitations

Metrics: `summary.json` and `measure.json` (cases 14,400; mismatches 0; negative controls 57 of 57). The applier behind slot 0x64e6d68 and the other GOT helpers are boundaries, so what each replayed journal entry does to the state maps is not reconstructed here (the applier arguments, tag and 0x57 payload bytes are verified). The wrong-sibling check (`write_slots` refusing 0x4323110) records that two other write bodies exist with a separate lookup; they are not covered. The tag meanings (2 = first touch of a bucket, 0xb = value write, 0xc = an already-taken entry that ends the replay) are inferences from the stores and the stop test, not observations of the applier. No component gate is requested.

Next question: the applier behind GOT slot 0x64e6d68 (the per-tag undo of the journal) and the lookup-calling write bodies 0x4323110 and 0x5463860 with the lookup 0x3ed7e80.
