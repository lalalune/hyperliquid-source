# RE-006: two-insert remainder, result merge, and guarded book update

The reconstruction can now preserve the original input quantity across a second insertion, reconcile the two result records, and update a resting slot only under the observed tag, lookup, and occupancy guards.

- Component ID: RE-006, order-book state transitions.
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663` / `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23`. The unlicensed reference supplies leads only; no reference code is copied.
- Claim status: the byte sequences, FDE ranges, call targets, branch destinations and relocations below are observations; semantic names are inferences explicitly marked below. Synthetic projections are not executions of the target.
- Scope included and excluded: five selected FDEs, the specified windows in two calling hosts, and selected call and unwind edges. Insert bodies, the prior record's complete construction, fill-total helper body, row-rewrite drivers, opaque helper effects, and unrelated host paths are outside this packet. The earlier `RE-006-queued-row-rewrite-94` packet covers the row-rewrite drivers and treats these hosts as context; the five selected FDEs here are distinct from its subjects.

## Reproduce

From the repository root, with node #94 in the repository's artifact location:

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/book_two_insert94.py --out work/re006-two-insert-a
PYTHONHASHSEED=98765 TZ=Pacific/Honolulu python3 tools/book_two_insert94.py --out work/re006-two-insert-b
diff -r work/re006-two-insert-a work/re006-two-insert-b
python3 -m unittest tests.test_book_two_insert94 -v
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

The collector was run with CPython 3.12.3 on Linux x86-64. It authenticates the entire input first, uses `tools/elf_index.py` and `tools/fde_extents.py` for ELF sections and CIE/FDE records, and interprets only selected fixed byte patterns. It calls no external program and does not execute the node. Human inspection used GNU objdump 2.42; no objdump output is an input to any generated file or test. The two generation commands have no time or hash-seed dependence. To compare a generated file with the retained packet, compare the corresponding file in `work/re006-two-insert-a` with the one beside this README. `MANIFEST.sha256` records the hashes of this README and the retained generated files.

Generated files are `functions.tsv`, `witnesses.tsv`, `sites.tsv`, `branches.tsv`, `calls.tsv`, `constants.tsv`, `relocations.tsv`, `merge-cases.tsv`, `twins.tsv`, and `summary.json`. All addresses are original ELF virtual addresses; file offsets are zero based. FDE ends and mask ranges are exclusive. The tables preserve raw bytes and unmasked hashes; addresses and counts are taken from the authenticated ELF, not a disassembler's output.

## Evidence

### Boundaries and context

| Selected role | FDE start | Exclusive end | FDE record VA | Bytes |
| --- | --- | --- | --- | ---: |
| Guarded slot-word writer | `0x4302290` | `0x430237e` | `0xec2cf8` | 238 |
| Pending-row clear | `0x432bef0` | `0x432bf67` | `0x122ea1c` | 119 |
| Two-result merge | `0x4471d80` | `0x447254b` | `0x1247c58` | 1995 |
| Result cleanup | `0x447b7f0` | `0x447b918` | `0xed3ef0` | 296 |
| Fill-vector concatenation | `0x4888840` | `0x4888b82` | `0x12a1a48` | 834 |

These are decoded FDE extents, not a claim that all code in the node has been located. Full body bytes and file offsets are in `functions.tsv`. Context windows in the caller at `0x4d12e80` and its sibling at `0x4d15710` are pinned separately. The first host calls the first insert at `0x4d13b41`, the second insert at `0x4d14617`, and the merge at `0x4d14654`. The sibling's corresponding calls are also in `calls.tsv`; the insert targets differ between the two hosts. The first result's first word is saved at stack offset `+0x160`. The merge receives A at stack offset `+0x4a0`, the new insert result, and B at `+0x1e0`, a record assembled by preceding code. The saved first word and B's current tag are separate observations; their equality is not assumed.

Ten corresponding host windows are compared in `twins.tsv`: four are raw-equal, and six are equal after masking only the four displacement bytes of selected direct calls or RIP-relative indirect calls. The exact half-open mask ranges and raw differences are retained; every masked call's opcode and actual destination are checked separately in `calls.tsv`. This is a window comparison, not a whole-function or whole-binary match.

### From first result to second-insert quantity

On the selected host path, the sixth argument is retained and its word at `+8` is saved, then reloaded into `r15` (`sites.tsv`, `host-quantity-source`, `host-quantity-reload`). The first insert's result tag is saved separately. At `0x4d143fb`, a local byte gate may bypass the second insert and proceed to the saved-tag check; the gate's wider meaning remains unresolved.

If that gate permits the path, `0x4d14426` calls the previously studied fill-total helper. The caller examines the first returned word. If zero, the next quantity is the saved word; if nonzero, the caller computes `max(saved_word - second_return_word, 0)` with an unsigned borrow test. A zero result takes `0x4d14453` to `0x4d144aa`, sets the later class to 2, and skips the second insert. A nonzero result is stored at `+8` of the second-insert input at `0x4d14554` and the second insert is called. This preserves the full saved word in `r15`; the smaller computed word is not substituted at the later slot writer.

The helper's body is not reanalyzed here. `RE-006-queued-row-rewrite-94` identifies its result as an optional fill summary, with the subtracted word representing the first total. That meaning is an inference used to call the computed word a remaining quantity; the zero test and saturating subtraction themselves are byte observations.

### Result-selection and finalization branches

Let E be the exact word `0x8000000000000000`, loaded at `0x4471d94`. The first test at `0x4471e2e` uses overflow from `0 - A.tag`, which is set for E only. The following B tests compare for equality to E. `merge-cases.tsv` projects the four cases through the decoded branch destinations:

| A tag | B tag | Selected output |
| --- | --- | --- |
| E | E | A's tagged record, first 32 bytes |
| E | other | B record |
| other | E | A record |
| other | other | Combine contents |

The test uses zero as the synthetic non-E tag; E-adjacent values are additional negative controls. This table is a static projection over the pinned byte tests, not observed target execution. Prior spot-insert evidence identifies E as the error form; that semantic label is an inference here.

For two non-E records, the merger iterates B's map, searches A using a 20-byte comparison, and appends B's 8-byte elements after A's existing elements for each matching key. An absent key is inserted with an empty vector first. A B entry whose vector's first word is E takes the branch at `0x4471fe1` out of the merge iteration; later entries are handled by the cleanup walk, not merged. The map key's interpretation as a user is inherited from the prior spot-insert result layout. The sequence is bounded by the iterator and allocation helpers; their complete contracts are not established here.

The merger passes A's fill range first and B's second to `0x4888840`. Its two copy loops use the `memmove` relocation and stride `0x228`, preserving each range's order. For aligned, non-wrapping ranges, the emitted count multiplier is the modular inverse used after dividing byte extents by 8. A total above `0x3b5cc0ed7303b5` goes to the failure edge; this is `floor((2^63 - 1) / 0x228)`. A null allocation has a failure edge as well. The empty case produces capacity 0, pointer 8 and length 0. The sum can wrap for malformed ranges before the limit check; no corruption resilience or successful allocation is claimed. The combined result retains A's word at `+0x30`, 17 bytes at `+0x38`, and byte at `+0x49`.

The host derives a class from A: E gives class 2, otherwise it uses A's byte at `+0x49`. After the common helper at `0x4d146e7`:

| Class and saved first tag | Observed local action |
| --- | --- |
| Class 2; saved tag is E | Skip row clear and rewrite |
| Class 2; saved tag is not E | Clear pending rows, then call the row-rewrite driver |
| Class is not 2 | Call the indirect helper; if the class low bit is set, call the slot writer; call the row-rewrite driver only if the saved tag is not E |

The zero-remainder arm also reaches class 2 without a second insert. A non-E flag byte of 2 follows class 2 as well; bytes such as 3 follow the low-bit test. The latter values are synthetic controls and are not claimed to occur in valid node states. The earlier local-gate bypass reaches the saved-tag check without passing through the common helper.

### Guarded slab write and cleanup

The slot writer's book index uses the control pointer at `+0x28`, mask at `+0x30`, and nonempty count at `+0x40`. It hashes the key with multiplication by `0xf1357aea2e62a9c5`, a 20-bit left rotation and the top seven bits as fingerprint, probing control groups in steps of 16. An all-ones control byte terminates an unsuccessful lookup. On an equal key it reads a slab index, rejects indices at or beyond the length at book `+0x10`, loads the slab base at `+0x08`, and uses stride `0xf8`. If the slot's low 32-bit discriminator is 2, it does nothing; otherwise it writes the supplied word at slot `+0xd0`. Missing key, empty index, out-of-range index and vacant slot all leave that field alone.

The pending-row clear stores length zero at vector `+0x10` before walking elements at stride `0x268`. Its normal and unwind paths call the same per-row helper; the unwind path attempts the remaining rows and resumes unwinding if those calls return. Result cleanup tests the E tag and checks its following signed word: only a positive value passes the word at `+0x10` and the positive value to the indirect cleanup target. Normal and unwind edges, including the fill allocation limit and null-allocation edges, are listed in `branches.tsv` and `calls.tsv`; they do not establish rollback of opaque helpers.

### Inferences and unresolved points

Prior spot-insert evidence identifies result `+0x30` as an order id, the 17 bytes at `+0x38` as client-id data, and `+0x49` as a fresh resting-id flag. Prior perp-insert evidence identifies the `+0xd0` word in the same-sized resting slot as original size. Together with the host's quantity flow, these support the opening reconstruction statement; the present packet independently establishes the stores and offsets, not those names across every order variant.

The host's gate meaning, the entire construction and ownership of B, the effects of the indirect transition helper, the complete iterator and allocator contracts, and recovery after exceptions remain unresolved. The byte coverage does not establish reachability for every combination of these synthetic inputs.

## Implementation and comparison

Independent Rust implementation: not yet implemented. No Cargo lock, Rust compiler flags, build, target execution, runtime fixture, or raw/normalized compiled-code comparison exists for this packet. The Python projections are bounded models of selected observations, not a Rust implementation or a target differential test.

Helper closure remains incomplete: the two insert bodies, fill-total helper, row rewrite, map helpers and opaque indirect target are external boundaries. Call-target closure is limited to the selected direct transfers and seven selected relocation records in the output; loader resolution is not exercised. Relocation and data closure beyond those records, vtable closure, and whole-ELF identity remain unmeasured. The only normalization is the explicit call-displacement masking in `twins.tsv`; no other bytes are masked.

## Results and limitations

| Measure | Result |
| --- | ---: |
| Selected decoded FDEs | 5 |
| Pinned byte windows | 36 |
| Selected conditional and unconditional branches | 69 |
| Selected calls, indirect jump and RIP-relative loads | 46 |
| Selected instruction sequences and constants | 44 and 25 |
| Selected relocation records | 7 |
| Compared host windows: raw equal / normalized only / unmatched | 4 / 6 / 0 of 10 |
| Static tag-selection cases | 4 |
| Focused unit tests | 14 passed; 0 skipped |

The tests cover altered target hashes, opcodes, branch displacements, fixed windows, relocation records, NOBITS and out-of-range mappings, zero and saturated remainders, exact-tag decisions, map ordering, slot lookup collisions and vacancy, and vector-size boundaries. They exercise the collector and projections only. No progress gate is requested, and no whole-function coverage or binary-equivalence denominator is implied.

Next question: what exact input and earlier fill-summary conditions make the host's local gate true, and what mutations does the indirect transition helper perform before the slot write?
