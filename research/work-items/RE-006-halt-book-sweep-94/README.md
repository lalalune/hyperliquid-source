# RE-006: perp halt transition of one asset on node #94

- Component ID: `orderbook` (task RE-006, book transitions)
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23` (labels used as leads only, nothing copied)
- Claim status: observation for every offset, branch, constant and count below; inference where the section says so; unresolved items are listed at the end
- Scope included and excluded: included are the delay gates `0x4cf3550` and `0x4cf36a0`, the halt transitions `0x4cf0850` and `0x4cf0d10`, the queue sweeps `0x42f2400` and `0x42f2bb0`, and the set removal `0x4cf0530`. The dispatch arm and the book sweep's single call site are pinned as bytes. Excluded, as stubs only, are the book sweep bodies `0x4307e60` and `0x4307860`, the row producer `0x36ff770`, the apply call `0x4cd84f0`, the finishing calls `0x4329870` and `0x432a100`, and the B-tree and heap helpers.

## Reproduce

Run from the repository root. The tool starts no external program and never runs the binary.
The tool takes about 20 s, including the mutation pass.
Author environment: Python 3.12.3, Linux x86-64. It reads only `artifacts/node/94/hl-node`, and uses the repository's
`tools/elf_index.py` and `tools/fde_extents.py` for section and FDE parsing.

```sh
python3 tools/artifacts.py verify
python3 tools/halt_book_sweep.py --out work/halt-book-sweep-check
diff -r work/halt-book-sweep-check research/work-items/RE-006-halt-book-sweep-94 -x README.md -x MANIFEST.sha256
python3 -m unittest tests.test_halt_book_sweep
```

Generated files: `evidence.json`, `call_sites.tsv`, `copy_differences.tsv`, `mutations.tsv`. Every number there comes from
`struct` reads of the ELF or from the evaluator in the tool.

## Evidence

Coordinates are virtual addresses. Offsets marked `+` are from the named structure's start. Each function was decoded to
its exact FDE end. `outer` is the object in `rdi` of the halt transition, and `market` one 0x2f0-byte row of the vector at
outer `+0x5c0` (first copy) or `+0x1040` (second copy).

### Call path

```text
0x4caa870 / 0x4cb3200 table entry 0x22 (0x711064 / 0x711244), arms 0x4cab563 / 0x4cb3ef3
  word +8 resolved through slot 0x5773950, byte +0xc is the flag
  flag set:   0x4cf0850 / 0x4cf0d10
  flag clear: 0x4cf0530
0x4d50130 / 0x4d55b50, byte flag in bpl
  flag set:   delay gate 0x4cf3550 / 0x4cf36a0, then 0x4cf0850 / 0x4cf0d10
  flag clear: 0x4cf0530
0x49fee90 / 0x49fe410
  market +0x230 set to 2, then 0x4cf0850 / 0x4cf0d10 for each u64 in the list from 0x47c0d80
  (flag clear: market +0x230 set to 0)

0x4cf0850 / 0x4cf0d10 (outer, asset)
  asset already in the market set: stop
  0x493ac40                  insert into the set at market +0x270
  0x4307e60 / 0x4307860      book sweep, user cancel with reason 0xc
  0x42f2400 / 0x42f2bb0      queue sweep
  0x4329870 / 0x432a100      finish the first vector
  slot 0x5774970 = 0x36ff770 position rows, 0x238 bytes each
  0x3987cb0                  only when the u32 at outer +0 is 1
  0x4cd84f0 (r8 0, r9d 0x30003)
  0x4329870 / 0x432a100      finish the second vector
```

The two halts differ only in the field set and the three callee pairs (`copy_differences.tsv`, 12 rows), and the two queue
sweeps only in the two market vector fields (2 rows). The two gates differ in the market fields, the byte field and the call target (4 rows).

| Field | First copy | Second copy |
| --- | --- | --- |
| Market vector | outer `+0x5c0` | outer `+0x1040` |
| Market count | outer `+0x5c8` | outer `+0x1048` |
| Collection vector | outer `+0x3370` | outer `+0x3df0` |
| Collection count | outer `+0x3378` | outer `+0x3df8` |
| Byte for the delay and record | outer `+0x8f2` | outer `+0x1372` |

### Halt `0x4cf0850`

1. Asset is split as `asset / 10000` (dex) and `asset % 10000` (local), by the multiply-shift `0x346dc5d63886594b >> 75` and
   `imul 0x2710`.
2. A dex at or past the market count panics at `l1/src/dex_registry/clearinghouses.rs:17:33`, through `Result::unwrap` on
   the error word 0x141. The word is built and dropped through `0x3379490` on success too.
3. The set at market `+0x270` is a `BTreeSet` of u64: keys `+0x08`, parent `+0x00`, parent index `+0x60`, length `+0x62`,
   edges `+0x68`. If the asset is present, the function goes to its last check and returns. **A second halt of the same
   asset cancels nothing and calls nothing.**
4. The insert happens first. Only then are the collection and book bounds tested, at `l1/src/dex_registry/perp_dex.rs:30:33`
   and `l1/src/books.rs:19:47`. So an asset with no book reaches the insert and then panics.
5. The book is collection `+0x08` plus local times 0xd8, and the queue is collection `+0x18`.
6. The first vector starts as (0, 8, 0), goes to the book sweep and then the queue sweep, and is moved to the finishing call.
7. The rows from `0x36ff770` go to `0x4cd84f0` with a 33-byte argument: byte 1, then 32 bytes from `0x3987cb0` when the u32 at
   outer `+0` is 1, or 32 zero bytes otherwise. The record call gets the byte field, outer `+0x28`, outer `+0x08` and 0.
8. The second vector goes to the finishing call, and the rows' buffer is freed at 0x238 bytes per capacity.

The lazy gate at `0x577ab98` is read twice, after the first finish and before the return. The function has no store outside
its stack (`stores_outside_stack` in `evidence.json`), and all three callers ignore `rax`.

The book sweeps were not evaluated, because `0x4307e60` is already a caller row in open packet #161. What this packet pins is
that each holds one call of the user cancel, with `edx` 1 and `r9d` 0xc, and that value 0xc of the status table `0x7038dc`
is `delistedCanceled` (`book_sweep_sites`).

### Delay gate `0x4cf3550`

1. A dex at or past the market count panics at `l1/src/dex_registry/clearinghouses.rs:11:29`.
2. If market `+0x230` is 3, the date is skipped and the halt runs.
3. Otherwise the delay is 300.0 when the byte field is 1 or 2, and 3600.0 for any other value (table `0x207af0`).
4. Slot `0x576efb8` (`0x1459ca0`) adds the delay to the 12 bytes at market `+0x218`. The result compares with outer `+0x60` as
   a signed i32, then u32, then u32. Later than now returns word 0x79 with no halt.
5. Equal or earlier runs the halt and returns word 0x186.

The tie case passes: a deadline equal to the time at outer `+0x60` runs the halt.

### Queue sweep `0x42f2400`

The queue has two parts: a vector (capacity, pointer, length) of 0x28-byte entries at `+0x00`, and a map at `+0x18`.

- Entry: u64 key `+0x00`, nonzero u32 `+0x08`, 8 bytes `+0x0c`, user `+0x14`. `0x44c0fe0` pops one, and a zero u32 at `+0x08`
  in the result ends the loop.
- Map: 20-byte user to an inner map, node keys `+0x110`, values `+0x08` (stride 0x18), length `+0x1ee`, edges `+0x1f0`,
  compared with `memcmp` of 20 bytes.
- Inner map: u64 to a 0x60-byte value, node values `+0x00`, parent `+0x420`, keys `+0x428`, length `+0x482`, edges `+0x488`.

For each entry:

1. If the user or the key is absent, or the value's first u64 differs from the asset, the entry is kept for later.
2. If it matches, `0x49432c0` removes the value. A result with byte `+0x22` equal to 2 means nothing came out: `0x4344430` drops
   a word 0xce, and **that entry is neither kept nor emitted**.
3. If the inner map's length is now 0, `0x4944610` removes the user and `0x494b020` drains the map it returns.
4. A dex at or past the market count panics at `l1/src/dex_registry/clearinghouses.rs:11:29`. The market count is read at
   entry, and the test is reached only by a match.
5. `0x46ca710` turns the value into 0x58 bytes, using the market row.
6. A 0x278-byte record goes on the caller's vector, the same vector the book sweep filled.

| Record offset | Size | Value |
| --- | --- | --- |
| `+0x00` | 8 | 4 |
| `+0x08` | 0x58 | output of `0x46ca710` |
| `+0x60` | 8 | `0x8000000000000001` |
| `+0x78` | 8 | queue key |
| `+0x80` | 12 | outer `+0x60` time |
| `+0x8c` | 20 | user |

After the last pop, kept entries go back through `0x44c1900` in pop order, and their buffer is freed at 0x28 bytes per capacity.

### Set removal `0x4cf0530`

This function is shared: both dispatchers and both `0x4d50130`-style callers reach it, each passing its own market vector.

1. A dex at or past the count panics at `l1/src/dex_registry/clearinghouses.rs:17:33`.
2. If market `+0x230` is neither 0 nor 3, it returns word 0x162 and leaves the set alone.
3. Otherwise `0x4942d10` removes the asset, and the word is 0x186 whether the asset was present or not.

Nothing else is touched, so **clearing the flag does not bring back any canceled order**.

### Inferences

- The asset set is the set of halted perps. `l1/action/vote_global.rs:102` labels raw 0x34, case 0x22, as `HaltPerpTrading` with
  `asset` and `is_halted`. Table entry 0x22 reads a word at `+8` and a byte at `+0xc`, which fits. So 0x34 being the raw tag is a
  label, and the shape agrees with it.
- By hand reading, `0x36ff770` walks a user table, takes each user's position in that asset, and writes two-sided 0x238 rows at
  one price, so this path closes positions. The name of the price is not shown here.
- The gate is a rate limit. `0x36ff770` stamps market `+0x218` from outer `+0x60` unless market `+0x230` is 3 (`byte_pins`), and
  the gate reads the same field. Status 3 skips both. So a market that just halted an asset has to wait 3600 s, or 300 s when the
  byte field is 1 or 2.
- Market `+0x230` is a status byte with 0 and 2 written by `0x49fee90` when a whole market changes. `l1/asset/pdi.rs:790` ties
  disabling a dex to all its assets being halted, and the reference's `TradingStatus` calls 2 `Delisted`, but which enum this
  byte belongs to is not shown.
- The queue holds a user's orders that are not on the book, given its 0x60-byte values with an asset field and its shared output
  vector. Whether these are trigger orders is unresolved.

## Implementation and comparison

Rust implementation: not yet implemented.

The comparison here is the original bytes against a specification written from the claim above. `spec_gate()`, `spec_halt()`,
`spec_queue()` and `spec_unhalt()` predict the ordered list of edge calls with their arguments, panics with their Location,
the word returned, and the written bytes of each output record. Both copies run against the same specification, with only
the field set changed.

Stubs replace every callee named in the scope line, plus `0x3379490`, `0x1459ca0`, `0x493ac40`, `0x4942d10`, `0x44c0fe0`,
`0x44c1900`, `0x49432c0`, `0x4944610`, `0x494b020`, `0x46ca710`, `0x4344430`, `memcmp`, `memcpy`, vector growth, free, the
`Once` call and the panic entries. Stubs poison volatile registers and all xmm registers, and callee-saved registers are
checked on exit. All three B-trees are real memory with uniform depth. Bytes where a real leaf would end are filled with an
unmapped pointer, so a stray edge read stops the run instead of acting as a null root.

Controls: every condition was inverted, bit 0 of every immediate flipped, and bit 3 of every non-stack field displacement
flipped, one at a time, in `0x4cf3550`, `0x4cf0850`, `0x42f2400` and `0x4cf0530`. A mutant that spins stops at a step limit
and counts as detected. Separate tests change the delay index, apply constant, market stride, reason byte, dispatch entry and
pinned bytes, invert branches, corrupt the digest, and pass a NOBITS address. The second copies have no mutation pass;
`copy_differences.tsv` ties them to the first.

The reference file `l1/books.rs` differs from the bytes as follows:

| Point | Reference lead | Bytes |
| --- | --- | --- |
| `0x4CF0850` | `ensure_main_perp_book_registered`: set the book's `registered` flag, reset caches, return the book | no return value, no store outside the stack; the first insert cancels the book, sweeps the queue and handles the positions |
| Set meaning | `registered_main_perp_assets`, only grows | removed again by `0x4cf0530` |
| Missing book | `Option`, returns `None` | panics at `books.rs:19:47`, after the insert |
| `0x4CF0D10` | perp-dex mirror | same 1207 bytes with the second field set |
| Selector | `asset / 10000`, `asset % 10000`, strides 0x138 and 0xd8 | the same, confirmed |

The reference's `HaltPerpTrading` label in `l1/action/vote_global.rs:102` agrees with the arm shape.

## Results and limitations

| Metric | Value |
| --- | --- |
| Gate cases, each of 2 copies | 218 |
| Halt cases, each of 2 copies | 107 |
| Queue cases, each of 2 copies | 83 |
| Set removal cases, 1 copy | 32 |
| Mismatches, all runs | 0 |
| Gate outcomes | pass 238, too soon 194, panic 4 |
| Halt outcomes | full path 96, already present 82, panic 36 |
| Queue rows, both copies | removed 90, put back 762, failed removal 16 |
| Set removal outcomes | ok 13, blocked 16, panic 3 |
| Instructions stepped | 191,005 |
| Stepped / total, halt | 206 / 247 |
| Stepped / total, gate | 71 / 78 |
| Stepped / total, queue | 355 / 393 |
| Stepped / total, set removal | 61 / 68 |
| Mutants killed / survived / unreached | 252 / 2 / 5 |

Both 2 survivors are height steps in the queue sweep's second user walk: it repeats a walk that just found the same key,
so the height never runs out. The first passes had real gaps, and they are closed: value bytes and user bytes were periodic, which
hid 4 field offset mutants, and leaf edges read as null hid one height step. The 5 unreached rows are unwind cleanup.

No progress gate is requested. Limits:

- Stubs are contracts. The book sweep bodies, `0x36ff770`, `0x4cd84f0` and both finishing calls are not evaluated here, and their
  effects are not claimed beyond the arguments they receive.
- The heap order of `0x44c0fe0` and `0x44c1900` is not modelled. Entries come from a list in the case, so order among entries is
  tested only as "kept entries return in pop order".
- The `0x46ca710` conversion is stubbed, so which record fields hold which order fields is not shown.
- `0x1459ca0` is stubbed. By hand reading it scales seconds by 1e9 and adds through two imported `chrono` helpers.
- Byte field outer `+0x8f2` is unresolved. It also selects notional limits elsewhere, and 3 means something to `0x49fee90`.
- The `Once` state is modelled as a plain word. Both reads were reached, including a state that stays set, which does not happen
  after a real `Once` completes.
- Which clearinghouse each copy belongs to is not settled, so the copies are named first and second only.
- Callers came from `E8`/`E9` byte patterns. A pointer built at run time would not appear.

Next question: `0x42f3360` and `0x42f39b0` pop and push the same queue. By what test do they keep entries, and do they share this
sweep's removal shape?
