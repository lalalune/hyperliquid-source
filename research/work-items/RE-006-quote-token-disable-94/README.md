# RE-006: what does the quote token disable do to the books and TWAP orders of node #94?

- Component ID: RE-006 (book transitions)
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / reference `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23`, used as a lead only
- Claim status: observation for bytes, routes, offsets and the evaluated behaviour; inference where marked; unresolved where marked
- Scope included and excluded: included are the disable `0x4d63950` with its copies `0x4d636c0` and `0x2747d90`, the pair scans `0x48839e0` and `0x2570a50`, the whole-book walks `0x4308160` and `0x4307b60`, the queue sweeps `0x42f3360`, `0x42f39b0` and `0x26dd540`, and the two routes into the first copy. The heap pop and push run real but are not this packet's claim. Excluded, as stubs only, are the user cancels `0x43038b0`, `0x4303b30` and `0x26e4240`, the map clones and drops, the order and user removals, the state row helpers, the flushes, the status write `0x339d350` and the tree slot `0x5774c28`. These functions appear in the merged or open packets only as stubs or callers; the question here is what the disable path does with them.

## Reproduce

Run from the repository root on Linux with Python 3 and the connected `artifacts/node/94/hl-node`. No network, no key, and the binary is never executed.

```sh
python3 tools/quote_token_disable.py --out research/work-items/RE-006-quote-token-disable-94
python3 -m unittest tests.test_quote_token_disable
cd research/work-items/RE-006-quote-token-disable-94 && sha256sum -c MANIFEST.sha256
```

The tool refuses any other binary digest. It reads ELF bytes through `tools/elf_index.py` and `tools/fde_extents.py`, parses no objdump or readelf output, calls no external program, and takes about 180 s on a loaded server. Its three generated files (`evidence.json`, `call_sites.tsv`, `mutations.tsv`) are byte-identical between runs.

## Evidence

Coordinates are virtual addresses. Bounds are FDE extents. File offset is VA minus 0x1000 in `.text`.

### Routes

| Route | Table and entry | Arm | Call site |
| --- | --- | --- | --- |
| Spot deploy, nested case 14 | `0x703ff8`, entry 14 | `0x4ad7afe`: token against exchange `+0x218`, then the call | `0x4ad7b17` |
| Global vote | `0x711064`, entry 62 | `0x4cacde3`: token against `+0x218`; `cmp byte [r15+0x10], 0` and `je 0x4caf273` at `0x4cacdfc` | `0x4caf27b` |

The second copy has the same two kinds of caller at `0x4ad8447` and `0x4cb7c0b`, the third at `0x235a965` and `0x23e7f77`. All six are in `call_sites.tsv`.

### Disable, first copy `0x4d63950`

Arguments: `rdi` result, `rsi` exchange, `rdx` token.

1. Token 0 gives word `0xef`.
2. The token is looked up in the tree at exchange `+0x2e0` (u64 key, one value byte). An empty tree, a missing key, or value byte 1 gives word `0xdf`.
3. Both arms store the text at `0x5998a9`, length 0x24: `quote token is not currently enabled`.
4. Any other value byte passes, including 2 and 255. `0x339d350` then writes 1 for the token.
5. The scan collects every pair index whose quote word equals the token.
6. For each index, in order: remove it from the tree at `+0x3a00`, panic at `l1/src/books.rs:19:47` if it is past the book count at `+0x3390`, run the whole-book walk, run the queue sweep, flush the one row vector.
7. The index list is freed and the word is `0x186`.

The status byte is written before the scan, so a panic in step 6 follows the write. A spot's rows are flushed before the next spot starts.

### Pair scan `0x48839e0`

The range is 0 to exchange `+0x200` at pair stride 0x20 from `+0x1f8`. Only the word at pair `+0x08` is compared. The result is an index vector of capacity 4, then doubled.

### Whole book `0x4308160`

| Book offset | Meaning |
| --- | --- |
| `+0xb8` | user map root; 0 with a nonzero length panics at the map unwrap, `library/alloc/src/collections/btree/map.rs:306:46` |
| `+0xc0` | user map height |
| `+0xc8` | user map length; 0 skips the clone and the walk |

With a nonzero length the map is cloned through `0x499c210`. The clone is walked in key order, and each key goes to `0x43038b0` with flag 1 and `r9d` 0xc, the reason that the status table names `delistedCanceled` in `RE-006-user-book-cancel-94`. The count comes from the clone. A count above the keys panics at `navigate.rs:534:47` after the last user, and a count below them stops early. The drop `0x49ad040` always runs. Key slot and node offsets are in `book_user_node`.

### Queue sweep `0x42f3360`

Arguments: `rdi` queue, `rsi` spot, `rdx` exchange, `rcx` row vector. The queue at exchange `+0x34e0` is a heap of 0x28-byte entries at `+0x00` and a map from user to order id at `+0x18`. Maps are in `queue_map`, `entry_map` and `value_map`.

Each pop:

1. The entry is kept if the user is absent, the order tree is empty, the id is absent, or the value's first word is not this spot.
2. A match goes to the removal `0x4944230`. Byte `+0x22` equal to 2 means no value: `0x4344430` drops a word `0xce`, and the entry is neither kept nor reported.
3. If the order map is now empty, `0x49463e0` removes the user and `0x49b7ad0` drains what it returns.
4. `0x46ca2b0` makes 0x58 bytes from the value and exchange `+0x90`.
5. One row goes on the vector.

| Row offset | Size | Value |
| --- | --- | --- |
| `+0x00` | 8 | 4 |
| `+0x08` | 0x58 | output of `0x46ca2b0` |
| `+0x60` | 8 | `0x8000000000000001` |
| `+0x78` | 8 | order id |
| `+0x80` | 12 | block time from exchange `+0x60` |
| `+0x8c` | 20 | user |

After the last pop, kept entries go back through `0x44c1900` in pop order, and their buffer is freed at 0x28 bytes per capacity. A map order with no queue entry is not touched: the sweep walks the queue, not the map. A case shows it (`map order with no entry stays`).

`RE-006-halt-book-sweep-94` (open) has the same keep test for its perp sweep `0x42f2400`. The spot form has no dex or market lookup, its row is 0x268 bytes instead of 0x278, and it has its own removal and state row helpers.

### Three copies

| Copy | Entry | Whole book | Sweep | Tree, queue, books at exchange |
| --- | --- | --- | --- | --- |
| first | `0x4d63950` | `0x4308160` | `0x42f3360` | `+0x3a00`, `+0x34e0`, `+0x3388` |
| second | `0x4d636c0` | `0x4307b60` | `0x42f39b0` | `+0x4480`, `+0x3f60`, `+0x3e08` |
| third | `0x2747d90` | inlined | `0x26dd540` | `+0x3a00`, `+0x34e0`, `+0x3388` |

The second copy's field offsets differ from the first only in those eight displacement rows, each `0xa80` higher (`copy_offsets`). The first two sweeps have 336 instructions each and 0 pairs differ in shape (`sweep_pair`). The third copy has its own callees, and its entry inlines the whole-book walk. `check_edges` proves each named callee is a direct call inside the function the table says.

### Worked example

From `evidence.json` `worked_example`, through the real bytes of the first copy. Token 7 quotes spots 0 and 2. Spot 1 is quoted in token 8. Book rows come first in each flush. The order on spot 1 stays, in both the map and the queue.

### Reference comparison

`evidence.json` key `reference_claims` holds three rows.

- `l1/exchange/handlers/26_spot_deploy.rs` lists nested case 14 as `DisableQuoteToken` and leaves `disable_quote_token` abstract. Table entry 14 agrees, and this packet is that missing body.
- `l1/action/vote_global.rs:132` labels `EnableQuoteToken` as raw 0x52, case 0x40. The arm with the same shape is at index 0x3e, which the reference labels `SetActionDelayerEnabled`. The arms at 0x3f and 0x3a store a single byte into the exchange, and I did not name them.
- `l1/spot_meta.rs` gives `QuoteTokenStatus` Active 0, Disabled 1 and an unknown form. The gate treats 1 as stop and every other value as pass, which fits.

### Inferences

- The queue is the spot TWAP schedule. `RE-006-twap-slice-94` (open) names the structure, and the state row helper bound-checks the value's first word against the pair count.
- The row word is the state that the TWAP status serializer `0x42e9000` prints as `"terminated"`. That serializer is not run here.
- The tree at `+0x3a00` is the one `lea rdi, [rbx+0x3a00]` at `0x26ff0db` hands to the block step's `0xfe` user spot buy cycle, so a disabled quote also leaves that cycle. This rests on the offset alone.
- `0x339d350` and the slot `0x5774c28` (target `0x333a700`) behave as map insert and map remove. Both are stubs.
- The three copies look like one source with different type parameters. Which runs live is not shown.

## Implementation and comparison

Rust implementation: not yet implemented.

The comparison is a Python specification against the real bytes. `spec_run()` predicts the ordered edge calls with their arguments, the result word and text, panics by Location, every row, the final map and the queue in real pop order. It was written from the disassembly before any run. The evaluator steps the real instructions and stubs only the listed edges. Trees are built with the real node shapes, with tempting keys in unused slots and an unmapped pointer in leaf edges.

Controls: 257 cases on each of the three copies. Every condition, immediate and non-stack field offset of `0x4d63950`, `0x48839e0`, `0x4308160` and `0x42f3360` is flipped one at a time. Unit tests add a wrong digest, an address inside a function, a NOBITS address, a wrong callee, a wrong pin, a wrong table entry and a wrong expected reason, each of which must be refused.

## Results and limitations

| Metric | Value |
| --- | --- |
| Cases, each run on all three copies | 257 |
| Mismatches, all runs | 0 |
| Outcomes | done, TWAP orders ended 73, done, book users cancelled 69, done, no spot quoted in the token 34, done, spots with nothing on them 38, panic books 3, panic root 1, panic walk 2, refused 0xdf 35, refused 0xef 2 |
| Instructions stepped | 2,896,742 |
| Stepped / total, disable, three copies | 128 / 149, 128 / 149, 270 / 308 |
| Stepped / total, pair scan, shared and third | 83 / 104, 84 / 105 |
| Stepped / total, whole book, two functions | 158 / 173, 158 / 173 |
| Stepped / total, queue sweep, three copies | 308 / 336, 308 / 336, 318 / 346 |
| Mutants killed / survived / unreached | 275 / 6 / 9 |
| Byte pins | 36 |

275 mutants are killed. All 6 survivors and 9 unreached rows have a reason in `mutations.tsv`:

- 2 survivors are the `cmp height, 8` tests of the unrolled descent, reached only with the low three bits nonzero.
- 2 are height steps in the sweep's second user walk, which repeats a walk that just found the same key.
- 1 is a shift of the start index, which every caller passes as 0.
- 1 is the dangling pointer of an empty vector, which nothing reads.
- The 9 unreached rows are unwind landing pads and the allocation failure tail.

The first mutation pass had 9 survivors. Three were real case gaps, closed by adding a user above every map key and a zero word beside the pair count.

Limits:

- All states are harness-built. No live quote token, book or queue state is known, and no statement here says when the action occurs on the chain.
- The stubs' arguments are pinned, their insides are not. In particular, the cancel of each user belongs to `RE-006-user-book-cancel-94`.
- Mutants cover the first copy. The other two run every case but are not mutated.
- The word `0xce` arm is reached only by a stub reporting a missed removal. On a consistent map the same key was found just before, so it should not run.
- Whether the Display of word `0xef` uses the stored text is not traced. The reference maps 239 to `invalid quote token`.
- The second user walk's failure exit is not reached, for the same reason as the `0xce` arm.
- The vote table label difference is unresolved.

No progress gate is requested.

Next question: what does `0x333a700` remove from the tree at exchange `+0x3a00`, and which handler writes that tree?
