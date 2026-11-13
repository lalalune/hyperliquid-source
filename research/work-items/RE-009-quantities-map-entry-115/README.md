# RE-009: reconstruct the node #115 hybrid quantity map entry 0x3cd7640, its four ring searches and the balance debit 0x42258d0

- Component ID: RE-009 / quantities (upstream labels `base/l1_map/entry.rs`, `l1/qtys/impl_wei.rs`, `l1/qtys/mod.rs`)
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit: repository commit `a8616af9432b8d8517b2af677880e117b7c28ef3` (origin/main when the tool was written); the reference tree under `references/can1357-hl` was not used and nothing was copied from it
- Claim status: observation for every table; the rule lists are reconstructions that the bytes confirm on the generated cases below; the root handler 0x3c34fd0 is *not* reconstructed (unresolved, see limits)
- Scope included: the hybrid map entry 0x3cd7640 (ring and tree paths, promotion and the entry of the demotion), the four ring binary searches 0x4554cb0 / 0x4555050 / 0x4556850 / 0x4557ad0 and the balance debit 0x42258d0, all as real code; scope excluded: the bodies of the promotion and demotion host calls, the two phase callees 0x4221510 / 0x4221f40, the second debit 0x4225a30 and the root handler 0x3c34fd0

The quantity maps of the exchange state are a two-shape container behind one capacity niche: a sorted `VecDeque` of rows with 20-byte keys, or a B-tree of 11-key nodes when the first word is `0x8000000000000000`; the entry call promotes a ring to a tree on a *missing* key once the ring holds at least `0x40` rows, demotes a tree with fewer than `0x20` rows on every entry (hysteresis, not a single cutoff), and the balance debit `0x42258d0` is `total -= amount` (panic on underflow) followed by `limit = min(limit, total)`, which makes the first and third steps of the root handler 0x3c34fd0 reconstructible as plain functions. The original bytes of all six bodies run in a small x86-64 evaluator on 17,000 generated cases (10,000 ring searches, 4,000 entry calls, 3,000 debits) and a separately written rule list matches every one (0 mismatches). 206 deliberate corruptions were tried: 190 are caught and 16 are proved equivalent edit by edit (`equivalent-mutants.tsv`).

## Reproduce

Run from the repository root with the target binary linked at `artifacts/node/115/hl-node` (the tool checks its SHA-256 first and fails otherwise; it never executes the binary and calls no external program):

```
python3 tools/qty_map_entry_115.py --out research/work-items/RE-009-quantities-map-entry-115
python3 -m unittest tests.test_qty_map_entry_115
```

ELF sections and FDEs come from the shared parsers `tools/elf_index.py` and `tools/fde_extents.py`; the evaluator in the tool is the shared offline x86-64 one (decoder, memory, machine), extended in the tool by the host-call table below. Measured here: one `--out` run takes well under two minutes, the test file runs 23 tests in under a second without the binary. Two runs into different directories compare equal with `diff -r`. `MANIFEST.sha256` lists every file of the folder except itself.

| file | content |
| --- | --- |
| `measure.json` | counts read by the verifier: cases, negative controls, detected, equivalent |
| `functions.tsv` | FDE start and size of the eight target bodies plus the second 0x30-stride copy |
| `calls.tsv` | every direct call, tail jump and indirect call of the eight target bodies |
| `ring-searches.tsv` | every 6th of 2,500 search cases per body with its result; digest of all in `digests.tsv` |
| `entry-cases.tsv`, `entry-outcomes.tsv` | every 3rd of 4,000 entry cases and the outcome counts per map shape |
| `entry-unexecuted.tsv` | the runs of entry instructions that no case executes (the demotion and unwind tails) |
| `debit-cases.tsv`, `debit-outcomes.tsv` | every 4th of 3,000 debit cases and the outcome counts |
| `controls.tsv`, `equivalent-mutants.tsv` | all 206 corruptions with detection, and the 16 equivalent edits with the reason |
| `digests.tsv` | SHA-256 of the full per-case result stream of each of the six runs |

## Evidence

Observations (bytes read by the tool, re-read with objdump for this README):

- `0x4557ad0` (492 bytes) takes `rdi` = ring header `{cap, ptr, head, len}` and `rsi` = 20-byte key; it normalises `head` (`head >= cap` subtracts `cap`), splits the window into a front slice of `min(len, cap - head)` rows and a back slice, compares the first row of the back slice first (`mov edx,0x14` then the imported compare through the GOT slot `0x64dfb50`), then runs a halving search in whichever slice can hold the key. It returns `rax` = 0 for found and 1 for missing, and `rdx` = the logical row index or insertion point. Row stride is `lea rax,[r13+r13*4]` then `*8` = 0x28.
- `0x4555050` and `0x4556850` (509 bytes each) are the same code with row stride 0x30 (`lea x,[r13*2]; add x,r13; shl x,4`); `0x4554cb0` (455 bytes) is the same code with stride 0x70 (`imul reg,reg,0x70`). The decoded instruction sequences differ only in the stride arithmetic and register allocation.
- `0x3cd7640` (1,119 bytes, `rdi` = 0x40-byte result, `rsi` = map, `rdx` = key): `neg [map]` with overflow detects the niche; `cmp [map+0x18],0x20; setb` plus the niche decides the demotion branch, whose first call is `0x3dd3f30` (tree into an owning iterator, 9 words at `rsp+0x80`) and the loop around `0x3904b80`; the ring path calls `0x4556850`, then `cmp [map+0x18],0x3f; jbe` decides the promotion, whose host call is `0x387cdd0` with the ring moved by value at `rsi` and the map reset to `{0, 8, 0, 0}` first (then the buffer is released only when its capacity is non-zero, which it is not at that moment). The tree walk compares 20-byte keys at node offset `0x110`, reads the key count as a `u16` at `0x1ee` and the child pointers at `0x1f0`.
- Result layout of the entry: occupied is `{1, node-or-0, height-or-map, index-or-index}`: for a tree `{1, node, height, index, &root_slot}`, for a ring `{1, 0, map, index}`; vacant is `{0, 0, map, index, key[0..20]}` for a ring at offset 0x20, and `{0, &root_slot, leaf, 0, index, key}` for a tree with the key at 0x28. A tree whose root pointer is null yields leaf 0 and the stale niche value `0x8000000000000000` where the index belongs (observed, probably the register that still held the niche).
- `0x42258d0` (348 bytes, `rdi` = state, `rsi` = key, `rdx` = amount) looks the key up in the map at `state+0x10`: ring rows are 0x28 bytes with the value pair at `+0x18`/`+0x20`; tree nodes keep 16-byte values from node offset 0 (`lea r15,[rax-0x10]` then `add r15,0x10` per key), keys at `0xb8`, key count at `0x196`, children at `0x198`. On a hit it computes `total - amount` with a borrow test; a borrow calls the panic slot `0x64e4ea8` with the location at `0x6487478`; otherwise it stores the new total and `min(limit, total)` into the first word.
- Root `0x3c34fd0` (2,622 bytes) calls `0x4557ad0` on `state+0x10` (key present or error code `0x95`), a hash lookup `0x3be6f50` (error `0x9b`), `0x3cd7640` on `state+0x228` twice, `0x4221510` and `0x4221f40`, `0x42258d0` and `0x4225a30`; it reads maps at `state+0xd0` (stride 0x70), `+0x228` (0x30), `+0x268` (0x28) and `+0x288` (0x30); its result tag word is `0x1a2` for success and `0x95`, `0x9b`, `0x10c` for the three early errors. See `calls.tsv` for every site.

Inferences (not proved by the bytes alone): the capacity niche means "tree" because `0x8000000000000000` can never be a `VecDeque` capacity; the 0x40/0x20 pair is a hysteresis that keeps small maps as sorted rings; the first word of the debit value is a limit that follows the total down.

## Implementation and comparison

`tools/qty_map_entry_115.py` builds a memory image per case from the layouts above (random noise outside the live rows, wrapped ring windows, real multi-level node images with a uniform height), runs the real bytes, and compares the result words, the final map header and the host-call arguments with a separately written specification (`spec_search`, `spec_tree_walk`, `spec_entry`, `spec_debit`). Host calls are recorded stubs: the imported compare (unsigned bytewise, length from `rdx`), the promotion (returns a staged tree and records the by-value ring and the map header), the demotion (records the iterator words and the map header, then stops), the panic slot and the dealloc slot.

Controls: every *executed* conditional jump has its condition inverted and every executed immediate operand has its low bit flipped, one edit per run, against a battery of cases; plus deliberately wrong specifications (`right`, `next`, `limit`, `no_demote`, `saturate`, `no_clamp`). Sixteen immediate edits survive and are listed with a structural reason: a compare against 1 that only skips a halving round with step zero, a `mov eax,0` or `mov eax,1` whose bit 0 is overwritten by the following `setne al`, and the "front slice empty" error flag that no valid ring can reach.

## Results and limitations

- 17,000 cases, 0 mismatches. Controls: 206 made, 190 detected, 16 equivalent, 0 undetected (`measure.json`).
- Entry outcomes by shape are in `entry-outcomes.tsv`; both thresholds are exercised on both sides (ring lengths 62..65, tree lengths 31/32), the wrapped ring window, the null-root tree and the empty-root demotion.
- Not covered (unresolved): the demotion body after its first host call and the unwind tails (`entry-unexecuted.tsv`, 6 runs, 79 instructions); the bulk-build host call `0x387cdd0` is replaced by a staged tree, so the shape of the tree it builds from a ring is not shown; `0x4221510`, `0x4221f40`, `0x4225a30` and the root handler are not reconstructed, so which request fields feed the key and amount of the debit is an observation of register moves only.
- The mutation battery is a sample of the generated cases, so "detected" means detected by that sample; the full run of each body is the digest in `digests.tsv`.

Next question: what do `0x4221510` and `0x4221f40` write between the two entry calls on `state+0x228`, and what is the unit of the debited total?
