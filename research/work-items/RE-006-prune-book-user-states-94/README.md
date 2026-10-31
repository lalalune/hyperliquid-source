# RE-006: block step prune_book_empty_user_states: which user_states entries of a book are removed

- Component ID: RE-006 (book state transitions), one removal path from the block step to the book's user map
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is used as a list of labels to check.
- Claim status: observation for everything in Evidence, which comes from ELF bytes and an evaluator of those bytes. Inferences and unresolved items are marked.
- Scope included and excluded: included with mutants are the first copy of the step `0x222bab0` from entry to its timing tail at `+0xca`, the walks `0x228e8d0`, `0x21e1110`, `0x21e1d80`, the closure `0x2773720`, and its helpers `0x2577530`, `0x287c9b0`, `0x255d140`, `0x228d390`, `0x24c2420`, `0x27e8490`, `0x2865710`. Real bytes without mutants: closures `0x2773290`, `0x4336700`, `0x43361b0`, steps `0x4717c50`, `0x4710ec0` with their walks, the B-tree insert and remove code, and the value drops `0x2785030`, `0x2784f00`. Stubbed: allocator, memcmp, list growth, the thread word, the registry and the clock. Excluded: the thread pool split arms, the timing tail of the step, what writes the `b`, `r` and `u` fields, and the value of the period word.

## Reproduce

From the repository root:

```
python3 tools/prune_book_user_states.py --out research/work-items/RE-006-prune-book-user-states-94
python3 -m unittest tests.test_prune_book_user_states
```

The tool takes about 450 s. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It does not start objdump or readelf, so the binutils version cannot change the output. The binary is never executed. It only reads bytes.

Generated files: `evidence.json`, `call_sites.tsv`, `cases.tsv`, `mutations.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

All addresses are virtual addresses in the ELF. Function ends come from FDEs (`functions` in `evidence.json`).

### The step

Each of `0x22297c0`, `0x470e9a0`, `0x47162d0` builds an argument block just before the call (`step_sites`):

| Offset | Value |
| --- | --- |
| `+0x00/+0x08` | pointer and length `0x1c` of the text `prune_book_empty_user_states` (`0x3efa87`, and `0x714e88` for the other two) |
| `+0x10/+0x18` | doubles `0.05`, `0.05`, read only after the state change |
| `+0x20` | byte: new bucket above the stored bucket |

The bucket is block time in ms divided by state `+0x38c0` (`+0x4340` in the third copy). The stored bucket at `+0x38c8` (`+0x4348`) is raised at the same place. The step does nothing, and reads no clock, unless the byte is exactly 1.

The step then walks the rows at state `+0x3368` (`+0x3de8`), stride `0x138`, and for each row its books at row `+0x08/+0x10`, stride `0xd8`, through closure `0x2773290`. After that it walks the books of the vector at state `+0x3380` (`+0x3e00`) through closure `0x2773720`. The second copy of each pair is `0x43361b0`, `0x4336700`. All four closures have equal bytes once call and rip displacements are masked (`closure_copies`), and all are 1163 bytes.

### The rule

For one book:

```
candidates = users of user_states whose b length word is 0 and whose u length word is 0
for each of the first slab-length slots whose state dword is not 2:
    remove the slot's 20 byte user from candidates
remove every candidate from user_states, dropping the 0x50 byte value
```

| Entry | Occupied slot | Removed |
| --- | --- | --- |
| `b` empty, `u` empty, any `r` | no | yes |
| `b` empty, `u` empty, any `r` | yes | no |
| `b` or `u` not empty | either | no |

The filter is one test at `0x228d438`: `mov rsi, [rdx+0x48]; or rsi, [rdx+0x30]; jne skip`. A byte search over `.text` finds these 8 bytes four times, one for each fold copy (`filter_sites`). The rule therefore reads the length words only: an empty map with a live root node is a candidate, and its node is freed.

`r` is not tested. An entry with a filled `r` vector and no slot is removed, and the vector is freed. The rule table with all 16 forms is `rule_table` in `evidence.json`, and each form runs on real bytes.

The state word compare is a dword, so state `0x500000002` counts as vacant, and `0x200000000` counts as occupied. Slots past the slab length are not read.

### Names and layout

The serializer `0x431e6f0` writes the name `user_states` for book `+0xb8` through `0x4382c50`. The value writer `0x43206c0` shows three fields, in the writing order below, and the panic text `field index 0 <= i < 3` sits beside the names:

| Value offset | Name written | Name beside it in the strings | Form |
| --- | --- | --- | --- |
| `+0x20` | `b` (`0x6effee`) | `book_order_keys` (`0x6effef`) | map, length at `+0x30` |
| `+0x00` | `r` (`0x6efffe`) | none | vector of 8 byte items |
| `+0x38` | `u` (`0x6effff`) | `untriggered_orders` (`0x6f0000`) | map, length at `+0x48`, inner value `0xb8` bytes |

Value `+0x18` is not read on this path. The user tree node has 11 values at `+0x000`, parent `+0x370`, 11 keys at `+0x378`, parent index `+0x454`, length `+0x456`, edges `+0x458` (`fields`).

The book accessor `0x2755c70` picks row `asset / 10000` against the count at state `+0x3378`, stride `0x138`, then book `asset % 10000`, stride `0xd8` (`anchors`). So the `+0x3368` rows are per dex.

### Against the reference

| Reference | Claim | Observed | Verdict |
| --- | --- | --- | --- |
| `l1/` (whole tree) | no text `prune_book_empty_user_states`, `user_states`, `book_order_keys` or `untriggered_orders` | the step name is at `0x3efa87`, and the serializers write the field names | missing in the reference |
| `l1/book/book/mod.rs:208` | `user_orders: BTreeMap<User, BTreeMap<Oid, usize>>` | the value is `0x50` bytes with one vector and two maps | shape differs |

### Inferences

- Field `u` holds the user's untriggered orders, and `b` holds keys of the user's book orders, from the adjacent strings. The rule then says a user with an untriggered order keeps the entry.
- The slot walk looks like a guard: if `b` always lists every slab order of the user, no candidate is ever taken out by it. Nothing here shows that it never fires.
- The second list at state `+0x3380` is the spot books. The accessor ties `+0x3368` to dex and asset, and no reader of `+0x3380` was checked.

### Unresolved

- What `r` holds, and whether dropping it loses anything.
- The value of the period word, so how often the step runs.

## Implementation and comparison

Rust implementation: not yet implemented.

The comparison here is the real bytes against a separately written Python specification (`removed`, `spec_book`), with real tree insert, remove, merge and drop code. Each run checks the kept users in order, the length word, the value bytes of every kept entry, parent links of the tree, an unchanged slab and book head, and a leak check over all allocations.

The thread word is 0 in most cases, which takes the plain loops. Cases with one or eight threads hold one item per list, so no split happens.

## Results and limitations

| Metric | Value |
| --- | --- |
| Cases | 458 |
| Mismatches | 0 |
| Instructions stepped | 1,503,221 |
| Stepped / total: step up to its timing tail | 56 / 56 |
| Stepped / total: row walk | 37 / 107 |
| Stepped / total: books of one row | 48 / 97 |
| Stepped / total: book list walk | 48 / 97 |
| Stepped / total: per-book closure | 207 / 239 |
| Stepped / total: collect entry references | 130 / 185 |
| Stepped / total: build the set | 180 / 254 |
| Stepped / total: parallel collect entry | 67 / 85 |
| Stepped / total: filter on b and u lengths | 79 / 184 |
| Stepped / total: append the filtered keys | 44 / 66 |
| Stepped / total: remove loop | 159 / 179 |
| Stepped / total: remove a held user from the set | 88 / 96 |
| Mutants killed / survived / unreached | 325 / 58 / 142 |

Mutation scope: each mutant ran the small cases that reach its instruction, then at most the three smallest large cases. The large trees therefore ran only in the baseline, not against every mutant.

The 58 survivors were read by class, not probed one by one, and the reason column in `mutations.tsv` gives the class per function. 29 sit in the thread count words, the collect entry and the single-node list link, which the plain loop path does not depend on. The others are capacity limits, iterator back handle words, the slab counter guard, and search start or position words. One such row needs a plain note: `0x27738bd`, the search start word of the held-user lookup, survived because the cases that give the set a second level were outside the three smallest large cases. The baseline does cover those shapes (`all held height 1`, `set grows past one leaf`), so the rule stands on them, but this mutant does not separate them. The same limit applies to the search start `0x287cb7d`. The 142 unreached rows are thread pool split arms, descent arms for height 8 or more, allocator failure arms, panic arms and unwind pads.

Limits:

- The thread pool split arms need a thread local read that the evaluator refuses. Rows or books of length 2 or more with a thread count above 0 are not run. The result of the fold is a set, so the split can change only the order of inserts.
- Trees of height 8 or more are not built, so the 8 step descent loops are not stepped. The closure, the collector and the remove loop each hold one of those loops.
- The closures `0x2773290`, `0x4336700`, `0x43361b0` run 83 of the book rows, with no mutants. Masked bytes are equal, and their callees differ in address only as listed.
- `0x2755c70` is stubbed in #131 and appears here only as three anchors. `0x22297c0`, `0x470e9a0`, `0x47162d0` hold rows in other packets, and only their bytes before the call are read here. `0x2785030`, `0x2784f00`, `0x286d260`, `0x28aa700` are value and tree drops with rows in other packets, so they run with no mutants.

No progress gate is requested.

Next question: who writes field `r` at value `+0x00`, and what reads it?
