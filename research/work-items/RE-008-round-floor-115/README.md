# RE-008: node #115 round-floor scan 0x294acb0 and the in-place collect driver 0x231b6f0 around the block batch filter

This packet lets an implementer write two more pieces of how node #115 handles a batch of received signed blocks: the driver `0x231b6f0` that builds the iterator and closure for the batch filter `0x2705af0`, collects its output in place over the input buffer, resets the iterator and drops the closure, and the scan `0x294acb0` that takes the minimum round over a vector of the same 0x1b0 byte items, reading the round straight from an inline block or, for an item whose block was elided (word `0x8000000000000000` at item `+0x18`), from the block stored under its 32 byte hash in the known B-tree or ring. Both functions run as the real bytes in a Python x86-64 interpreter, together with the batch filter, the ring search and the signed block wrapper chain as real dependencies, against a separately written rule list: 13,500 cases, 0 mismatches, 192 negative controls with 192 detected.

- Component ID: consensus (task RE-008)
- Target release and full SHA-256: node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository base `0781ce04826eeefd89fe336cb8ea073be0c1de30`; no reference source was read or copied; no #94 result is used
- Claim status: observation for every row run or pinned; inference where marked below; unresolved items are listed under Results and limitations
- Scope included: `0x294acb0` (round-floor scan, first byte to return) and `0x231b6f0` (collect driver, first byte to return); `0x2705af0`, `0x24c5ba0`, `0x2786870`, `0x57e8bd0` and `0x57f54e0` run as bytes because the two functions call them, without their own case tables here
- Scope excluded: the stake set provider `0x595e5c0`, the block rules `0x59d6b80`, the digest builder `0x57e8d40`, signature recovery, the certificate drop `0x2780350`, the Arc slow drop behind GOT `0x64e4cb8`, the closure drop `0x2824570`, the unread-item drop `0x277ff30`, the unwind cleanup `0x23020f0`, the owners of the collected vector and of the floor scan's result, the sibling collector `0x2e20b00` and the timeout side
- Related work: the batch filter `0x2705af0` and the ring search `0x24c5ba0` are the subject of the earlier #115 block batch filter packet of this series (this packet starts at its caller and at the next direct caller of the ring search); the front ends above them belong to the signed message admission packet. No `RE-001-*` row reconstructs either function

## Reproduce

Run from the repository root. Python 3 standard library plus `tools/elf_index.py` and `tools/fde_extents.py`. No external program runs, the binary is never executed, nothing touches a network. The tool refuses any other digest.

```
python3 tools/consensus_round_floor_115.py --out research/work-items/RE-008-round-floor-115
python3 -m unittest tests.test_consensus_round_floor_115
```

The generated files are byte-identical across runs with different hash seeds and time zones (checked with `diff -r` on two full runs; a third run in another time zone, made after `coverage.tsv` was extended to the dependency rows, matches the first two on every file and on the own-function rows of that table).

## Evidence

Coordinates are ELF virtual addresses in `.text` and `.data.rel.ro`/`.got` slots. Function bounds are FDE bounds from the shared parser. Every table is produced by the tool from file bytes or from a run of the real rows.

### Observations: how the functions are reached

`callers.tsv` is a byte scan of every `e8`/`e9` rel32 to the two scope functions with the containing FDE: call 0x2e0a56e -> 0x231b6f0 in 0x2e098e0..0x2e11140; call 0x2e0c2bd -> 0x294acb0 in 0x2e098e0..0x2e11140. The driver `0x231b6f0` (0x12f bytes, FDE `0x231b6f0..0x231b81f`) takes an output pointer and an iterator block: `+0` buffer start, `+8` current, `+0x10` capacity, `+0x18` end, and the filter closure from `+0x20` (`+0x20` the state that owns the known-hash set, `+0x28` the state handed to the wrapper). The scan takes a vector header (`+0` begin, `+8` end, `+0x10` pointer to the known set) and a start value and returns the minimum in `rax`.

### Observations: the rule list

`gates.tsv` pins 16 rows (call targets, GOT slots, immediates, operations) to the sites below; each is decoded from the bytes and checked with a wrong-site and a wrong-expectation negative. `layouts.tsv` lists every displacement the two functions read off a pointer register, `coverage.tsv` the number of cases that reach each row.

1. Driver. It calls the batch filter with the iterator block as its first argument, the buffer start as both the accumulator and the write pointer and the closure `iterator + 0x20`. The collected count is `(write pointer - buffer start) / 0x1b0` computed as `(span >> 4) * 0x84bda12f684bda13` (exact for multiples of 0x1b0 = 16 * 27). It returns, through the output pointer, the triple `{capacity word of the iterator, buffer start, count}`. The iterator is then reset to its dangling state (`+0` = 8, `+8` = 8, `+0x10` = 0, `+0x18` = 8) after a drop loop for unread items (one `0x277ff30` call per item; it runs zero times because the filter drains the iterator, so the loop is covered only by the call-site pin), and the closure is dropped through `0x2824570` with the iterator pointer. Because the writes trail the reads, the in-place collect never overwrites an unread item.
2. Scan: item count. The count comes from the byte span the same way (`(end - begin) >> 4` times the inverse of 27); an empty vector returns the start value unchanged.
3. Scan: inline block. When the word at item `+0x18` is not `0x8000000000000000` the item holds its block there. The round is read from the block by a three way choice on two tags: if block `+0x18` equals `0x8000000000000001` the word at block `+0x50`, else if block `+0xa8` equals `0x8000000000000001` the word at block `+0x48`, else the word at block `+0xd8`. The result is the unsigned minimum of the running value and that round.
4. Scan: elided block. The 32 byte hash at item `+0x190` is looked up in the known set the vector points to. If set word 0 equals `0x8000000000000000` it is a B-tree (root `+8`, height `+0x10`; a node keeps up to 11 keys of 32 bytes from `+0`, a `u16` key count at `+0x1192`, edges from `+0x1198`; keys compared left to right with `memcmp(hash, key, 32)`, equal is found, greater moves on, smaller descends); the value of key `i` is the block at node `+0x168 + 0x178 * i`, which is 8 bytes into its 0x178 byte value slot (value array at node `+0x160`). Otherwise it is a ring of 0x198 byte rows searched by `0x24c5ba0`; a found index is made physical (`index + head`, minus the capacity when not below it) and the block starts at row `+0x20`. A miss (root 0, a leaf that ends the walk, or ring search result 1) leaves the running minimum unchanged. A found block is read with the same three way choice as in rule 3.

`functions.tsv` lists bounds and reached rows, `stubs.tsv` every contract, `outcomes.tsv` the case classes and item outcomes.

### Inferences, kept apart

- Calling the items received blocks with their certificates, the keyed set a known-block set and the minimum a lowest pending round is inferred from the layout and from the neighbouring wrapper; the bytes show only words, tags and walks.
- Reading the driver as `Vec::from_iter` over an in-place `IntoIter` map (accumulator and write pointer returned, source allocation reused) is inferred from the call shape.
- The 8 byte offset of the block inside a tree value is observed through the floor result on 13,500 cases; whether those 8 bytes hold a discriminant is not shown.

## Implementation and comparison

Rust implementation: not yet implemented. `tools/consensus_round_floor_115.py` holds an x86-64 row evaluator (head of the earlier block batch filter tool, decoder unchanged), the fixture and a rule list written from the observations above. Per driver case it writes the iterator, the items, the Arc objects, the certificate vectors, the known-hash set (B-tree or ring), the stake set and the contract plans into emulated memory, runs the real bytes from `0x231b6f0`, and compares the returned pointer, the result triple, the collected bytes (the 0x170 bytes of frame leftovers in no-block records are masked), the iterator reset words, every Arc counter and the ordered list of stub calls. Per floor case it writes the vector, items (inline and elided blocks) and the known set with a block under every key, runs `0x294acb0` and compares the returned minimum and a digest of the fixture memory (nothing may be written).

Cases: 13,500 (6,000 driver runs with 0 to 6 items, B-tree sets of 0 to 200 keys and rings of 1 to 33 rows; 7,500 floor runs with 0 to 6 items), 0 mismatches. Driver item outcomes: admitted 159, admitted_niche 24, known_kept 7175, known_niche 1211, niche_collision 7, other_address 123, recover_error 128, set_miss 1611, stakes_error 3095, stale 2123, verify_error 530. Floor item outcomes: inline 12129, niche_hit 4188, niche_miss 3877 (see `outcomes.tsv`).

Negative controls (192, 192 detected): 26 flawed rule lists (the 17 filter flaws, four driver flaws: closure kept, capacity dropped, iterator not reset, count off by one, and five floor flaws: maximum instead of minimum, signed compare, swapped selector, no elided lookup, start value ignored), 51 killed one-bit edits of conditions and immediates in the real rows (each run on up to 128 picked cases; 2 edits survived and are listed in `mutations.tsv`, not counted), 78 corrupted fixture bytes and 37 range and pin controls.

## Results and limitations

- 188 of 217 rows of the two own functions are reached. Unreached rows (`coverage.tsv`): 0x231b6f0: 24 rows (0x231b796, 0x231b79d, 0x231b7a0, 0x231b7a5, 0x231b7a8, 0x231b7d4, 0x231b7d7, 0x231b7d9, 0x231b7dc, 0x231b7e0, 0x231b7e3, 0x231b7e5 ...); 0x294acb0: 5 rows (0x294ad06, 0x294ae31, 0x294ae83, 0x294aee0, 0x294aeea).
- Surviving edits: 0x231b6f0 0x231b758 (immediate), 0x294acb0 0x294ae9e (immediate). They are not counted as detected and not claimed equivalent. By reading, the immediate at `0x231b758` is the shift that turns the unread span into an item count, which is 0 in every reachable run, and the one at `0x294ae9e` is the bit test on the ring search's found flag.
- Contract stubs are not run: stake provider `0x595e5c0`, block rules `0x59d6b80`, recovery slot `0x64e0ad8`, digest builder `0x57e8d40` (modelled as SHA-256 over the variant word and the 0x178 block bytes, which is not the real digest), certificate drop `0x2780350`, the Arc slow drop, the closure and item drops and libc. Any rule here that depends on their real behaviour is out of scope.
- The 0x170 bytes of leftover frame in no-block records come from earlier iterations and are masked, not modelled.
- Cases cover at most six items per run and trees of at most 200 keys; larger batches only repeat the per-item steps. The ring row `index >= length` skip in the scan is unreachable for a found result and not exercised.
- The owners of both functions' results and the sibling collector `0x2e20b00` (a B-tree collect with insert `0x1c89780`) are not covered. This does not raise any component gate.

Next question: the sibling collector `0x2e20b00` with the B-tree insert `0x1c89780`, and the caller of `0x294acb0`.
