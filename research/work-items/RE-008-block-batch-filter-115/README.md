# RE-008: node #115 consensus block batch filter 0x2705af0, from the into-iter of received blocks to the in-place emitted records

This packet lets an implementer write, as one flow, how node #115 filters a batch of received signed blocks before they reach the consensus state: each 0x1b0 byte item is looked up by its 32 byte block hash in a known-hash set (B-tree or ring), an already known hash keeps its certificates and loses its block, a block whose round plus one is below a floor word is dropped silently, every other block goes through the signed block wrapper `0x2786870`, and the result is either the moved block or a dropped item whose error record, Arc handles and certificate vector are released in a fixed order. The batch function `0x2705af0`, the ring search `0x24c5ba0` and (as dependencies) the wrapper `0x2786870`, the signer check `0x57e8bd0` and the stake ring search `0x57f54e0` run as the real bytes in a Python x86-64 interpreter against a separately written rule list: 15,000 cases (12,000 batch runs and 3,000 direct ring searches), 0 mismatches, 222 negative controls all detected.

- Component ID: consensus (task RE-008)
- Target release and full SHA-256: node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository base `0781ce04826eeefd89fe336cb8ea073be0c1de30`; no reference source was read or copied; no #94 result is used
- Claim status: observation for every row run or pinned; inference where marked below; unresolved items are listed under Results and limitations
- Scope included: `0x2705af0` (batch function, first byte to return, 438 rows) and `0x24c5ba0` (ring search with 0x198 byte rows, 137 rows), both from their first byte to return; `0x2786870`, `0x57e8bd0` and `0x57f54e0` run as bytes because the batch function calls them, without their own case tables here
- Scope excluded: the stake set provider `0x595e5c0`, the block rules `0x59d6b80`, the digest builder `0x57e8d40`, signature recovery, the certificate drop `0x2780350`, the Arc slow drop behind GOT `0x64e4cb8`, the caller `0x231b71c` and the two closure owners, the timeout side `0x2786a20` and its caller `0x2e08b90`
- Related work: the front ends `0x57e8970`, `0x57e8bd0`, `0x57f54e0`, `0x2786870` and `0x2786a20` are the subject of the earlier #115 signed message admission packet of this series; this packet starts at the first unowned caller of `0x2786870`. `RE-001-*` caller lists mention `0x2705af0` and `0x24c5ba0` only as inventory rows

## Reproduce

Run from the repository root. Python 3 standard library plus `tools/elf_index.py` and `tools/fde_extents.py`. No external program runs, the binary is never executed, nothing touches a network. The tool refuses any other digest. One run takes about two minutes on four cores and peaks at about 350 MB resident (measured with `/usr/bin/time -v`).

```
python3 tools/consensus_block_batch_115.py --out research/work-items/RE-008-block-batch-filter-115
python3 -m unittest tests.test_consensus_block_batch_115
```

The generated files are byte-identical on two runs with different hash seeds and time zones (checked with `diff -r`).

## Evidence

Coordinates are ELF virtual addresses in `.text` and `.data.rel.ro`/`.got` slots. Function bounds are FDE bounds from the shared parser. Every table is produced by the tool from file bytes or from a run of the real rows.

### Observations: how the functions are reached

`callers.tsv` is a byte scan of every `e8`/`e9` rel32 to the two scope functions with the containing FDE: `0x2705af0` has one direct caller (`0x231b71c`, in the 0x12f byte function at `0x231b6f0`), `0x24c5ba0` has 15 (two inside the batch function, the rest in `0x294acb0`, `0x2e07a00`, `0x2e098e0` and four more bodies). The batch function receives four pointers: an into-iter (`+8` current, `+0x18` end), an accumulator word returned unchanged, the write pointer of the output, and a two word closure (`+0` the state that owns the known-hash set, `+8` the state handed on to the wrapper). It returns the accumulator in `rax` and the new write pointer in `rdx`.

### Observations: the rule list

`gates.tsv` pins 17 rows (call targets, GOT slots, immediates, operations) to the sites below; each is decoded from the bytes and checked with a wrong-site and a wrong-expectation negative. `layouts.tsv` lists every displacement the two functions read off a pointer register, `coverage.tsv` the number of cases that reach each of the 575 rows.

1. Item size. Each step copies 0x1b0 bytes of the item to the frame, advances the iterator current pointer by 0x1b0 and stores it back before anything else (so a later stub can tell which item is being handled). Item fields: block `+0` (0x178 bytes), certificate vector capacity/pointer/length at `+0x178/+0x180/+0x188`, 32 byte block hash at `+0x190`.
2. Known-hash lookup. If the word at state `+0x208` equals `0x8000000000000000` the set is a B-tree: root `+0x210`, height `+0x218`, a node keeps up to 11 keys of 32 bytes from `+0`, a `u16` key count at `+0x1192` and edges from `+0x1198`; keys are compared left to right with `memcmp(hash, key, 32)`, equal is found, greater moves on, smaller descends through the edge of that index, a leaf that ends the walk or a root pointer of 0 is a miss. Otherwise the set is a ring (capacity, buffer, head, length at `+0x208 +0x210 +0x218 +0x220`) of 0x198 byte rows whose first 32 bytes are the key, searched by `0x24c5ba0` (back slice first, size-halving search per slice, result 0 for found and 1 for absent plus an index).
3. A known hash. The block hash vector is freed (`capacity << 5` bytes, only if the capacity is not 0), the block certificates are dropped through `0x2780350`, and the item is emitted without its block unless the certificate capacity word equals `0x8000000000000000` (then nothing is emitted). The emitted record is `{certificate capacity, pointer, length}` at `+0`, `0x8000000000000000` at `+0x18` (no block), 0x170 bytes of leftover frame at `+0x20`, the hash at `+0x190`.
4. The round floor. For an unknown hash the round is the word at block `+0x50` when the tag word at block `+0x18` equals `0x8000000000000001`, else the word at block `+0xa0`; one is added and a wrap to 0 saturates to `0xffffffffffffffff`. If that value is below the floor word at state `+0x2c8` the item is dropped silently: one Arc strong count per certificate (element stride 0x28, the Arc pointer at element `+0x20`) is decremented and the slow drop runs when it reaches zero, the certificate vector is freed (`capacity * 40` bytes if the capacity is not 0), the block hash vector is freed and the block certificates are dropped.
5. Otherwise the lookup runs a second time (same set, same hash, so its found arm is unreachable) and the block is passed to `0x2786870` with the closure's second word. A first output word other than `0x8000000000000000` is success: the 0x170 bytes after it are copied and the item is emitted with the block (`+0x18` holds the first block word, `+0x20` the next 0x170 bytes), again unless the certificate capacity word is `0x8000000000000000`.
6. Error. The 0x48 byte record the wrapper leaves at output `+8` is released by its tag byte: `0x10` frees the buffer `(ptr +0x10, size +8)` and then `(ptr +0x28, size +0x20)` when the sizes are not 0, `0x20` and `0x13` free `(ptr +0x10, size +8)`, any other tag frees nothing. Then the Arc counts are decremented and the certificate vector freed exactly as in rule 4 (the wrapper has already freed the block hash vector and dropped the block certificates). Nothing is emitted. A block whose first word is itself `0x8000000000000000` is a success for the wrapper and an error for this function (15 items in the cases, label `niche_collision`): the record is read from block bytes `+8..+0x50`.

`functions.tsv` lists bounds and reached rows, `stubs.tsv` every contract, `outcomes.tsv` the case classes and item outcomes.

### Inferences, kept apart

- Calling the iterator items received blocks with their certificates, the keyed set a known-block set and the `+0x2c8` word a minimum round is inferred from the layout and from the neighbouring wrapper; the bytes show only words, tags and walks.
- Reading the 0x1b0 to 0x1b0 move as an in-place `Vec` collect (accumulator and write pointer returned) is inferred from the call shape.
- Reading `0x24c5ba0` as `VecDeque::binary_search_by` is inferred from the model matching on 3,000 direct cases including damaged (unsorted) rings.

## Implementation and comparison

Rust implementation: not yet implemented. `tools/consensus_block_batch_115.py` holds an x86-64 row evaluator (head of the earlier signed message admission tool, decoder unchanged), the fixture and a rule list written from the observations above. Per case it writes the iterator, the items, the Arc objects, the certificate vectors, the known-hash set (B-tree or ring), the stake set and the contract plans into emulated memory, runs the real bytes, and compares the return pair, the 0x1000 byte output region (the 0x170 bytes of frame leftovers in no-block records are masked), every Arc counter and the ordered list of stub calls with every argument.

Cases: 15,000 (12,000 batch runs with 0 to 6 items, B-tree sets of 0 to 200 keys and rings of 1 to 33 rows, 3,000 direct ring searches), 0 mismatches. Item outcomes: known_kept 14,359, known_niche 2,518, stale 4,195, admitted 325, admitted_niche 54, stakes_error 6,208, set_miss 3,223, recover_error 271, other_address 236, verify_error 1,031, niche_collision 15 (see `outcomes.tsv`).

Negative controls (222, all detected): 17 flawed rule lists (known set unchecked, selector swapped, no increment, wrap to zero, strict floor, block kept for a known hash, Arc counts kept, error record not freed, tag 0x13 ignored, niche emitted, unshifted hash free, 8 byte certificate free, reversed tree order, first key only, ring moves on equal, error box not dropped, recovery compare skipped), 119 one-bit edits of conditions and immediates in the real rows (each run on up to 64 picked cases; 15 edits survived and are listed in `mutations.tsv`, not counted), 48 corrupted fixture bytes (hash byte of a known item, matching ring row key byte, floor word, tag word, certificate length, iterator end, signature byte, signer address byte) and 38 range and pin controls.

## Results and limitations

- 495 of 575 rows of the two own functions are reached. The 80 rows that are not are listed in `coverage.tsv`: 70 exception landing pads after `0x27061e7`, eight alignment `nop`s, one `xchg ax,ax` and one `jmp` at `0x24c5cf4` (the arm of the ring search for an empty remainder).
- The 15 surviving edits are not counted as detected and not claimed equivalent. By reading they look dead or unwitnessed: the second lookup (`0x2705f1d`..`0x2705fd7`) can only differ if its found arm fires, which a deterministic set cannot make; `mov bpl,1` at `0x2705ce0` is an unwind flag; the `rbp` immediates at `0x2705d77`/`0x2705d90` and `0x2706160`/`0x2706170` feed an index the drop loops do not use; four ring search immediates at `0x24c5c0b`, `0x24c5c4f`, `0x24c5ce6`, `0x24c5d60` act only for sizes and signs the case shapes do not separate.
- Contract stubs are not run: stake provider `0x595e5c0`, block rules `0x59d6b80`, recovery slot `0x64e0ad8`, digest builder `0x57e8d40` (modelled as SHA-256 over the variant word and the 0x178 block bytes, which is not the real digest), certificate drop `0x2780350`, the Arc slow drop and libc. Any rule here that depends on their real behaviour is out of scope.
- The 0x170 bytes of leftover frame in no-block records come from earlier iterations and are masked, not modelled.
- Cases cover at most six items per run and trees of at most 200 keys; larger batches only repeat the per-item steps.
- The timeout side (`0x2786a20` from `0x2e08b90`) and the closure owners are not covered. This does not raise any component gate.

Next question: the caller `0x231b71c` that builds the iterator and closure, and `0x2e08b90` for the timeout message batch.
